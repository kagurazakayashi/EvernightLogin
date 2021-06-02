package profile

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// AuditRecorder 是安全审计写入契约；实现必须 fail-closed。
type AuditRecorder interface {
	Record(ctx context.Context, event audit.Event) error
	RecordFailure(ctx context.Context, event audit.Event) error
	ExecuteCritical(ctx context.Context, request audit.CriticalRequest, change audit.Change) error
}

// Options 是资料服务依赖。
type Options struct {
	Store Store
	Audit AuditRecorder
	// Authorizer 判定读写权限；nil 时使用仅允许本人与受信 system/local_admin 的
	// 默认口径（普通用户修改他人 fail-closed）。
	Authorizer Authorizer
	// ReauthVerifier 是更名再次验证契约；RequireReauth 且普通用户更名时未注入
	// 一律拒绝。
	ReauthVerifier ReauthVerifier
	// Policy 是更名/电话策略；零值使用 DefaultPolicy。
	Policy Policy
	Now    func() time.Time
	Logger *slog.Logger
}

// Service 是资料领域服务。构造后不可变，不启动协程、不发会话。
type Service struct {
	opts   Options
	policy resolvedPolicy
}

// New 校验依赖并构造服务。Policy 逐字段合并安全默认值（再次验证默认开启）。
func New(options Options) (*Service, error) {
	if isNil(options.Store) {
		return nil, fmt.Errorf("%w: 资料存储为空", ErrOptionsInvalid)
	}
	if isNil(options.Audit) {
		return nil, fmt.Errorf("%w: 安全审计写入器为空", ErrOptionsInvalid)
	}
	resolved, err := options.Policy.resolve()
	if err != nil {
		return nil, err
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Logger == nil {
		options.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Service{opts: options, policy: resolved}, nil
}

// GetProfile 读取目标资料：本人或受信管理通道；未注入 Authorizer 时其他用户一律
// 拒绝（fail-closed）。
func (s *Service) GetProfile(ctx context.Context, caller Caller, targetUserID string) (UserProfile, error) {
	ctx = normalizeContext(ctx)
	if !account.ValidUserID(targetUserID) {
		return UserProfile{}, fmt.Errorf("%w: 用户 ID 格式无效", ErrInvalidRequest)
	}
	// 先判权再读目标，避免向无权调用者泄露用户是否存在。
	if err := s.preAuthorize(ctx, caller, targetUserID, false); err != nil {
		return UserProfile{}, err
	}
	record, found, err := s.opts.Store.GetProfile(ctx, targetUserID)
	if err != nil {
		return UserProfile{}, ErrStoreUnavailable
	}
	if !found {
		return UserProfile{}, ErrUserNotFound
	}
	if err := s.authorize(ctx, caller, record, false); err != nil {
		return UserProfile{}, err
	}
	return record, nil
}

// UpdateSelf 由本人修改自己的非敏感资料。
func (s *Service) UpdateSelf(ctx context.Context, caller Caller, change ProfileChange, expectedRowVersion int64, requestID string) (UserProfile, error) {
	if !caller.IsUser() {
		return UserProfile{}, ErrAccessDenied
	}
	return s.update(ctx, caller, caller.actor.ID, change, expectedRowVersion, requestID)
}

// UpdateUser 由获授权管理员/受信通道修改目标用户资料；权限由 Authorizer 判定，
// 未注入时普通用户不能修改他人。
func (s *Service) UpdateUser(ctx context.Context, caller Caller, request UpdateRequest) (UserProfile, error) {
	if !account.ValidUserID(request.TargetUserID) {
		return UserProfile{}, fmt.Errorf("%w: 用户 ID 格式无效", ErrInvalidRequest)
	}
	return s.update(ctx, caller, request.TargetUserID, request.Change, request.ExpectedRowVersion, request.RequestID)
}

// update 是资料更新共同实现：版本条件更新 + 审计同事务。
func (s *Service) update(ctx context.Context, caller Caller, targetUserID string, change ProfileChange,
	expectedRowVersion int64, requestID string) (UserProfile, error) {
	ctx = normalizeContext(ctx)
	if err := account.ValidateRequestID(requestID); err != nil {
		return UserProfile{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if caller.requestID != "" && requestID == "" {
		requestID = caller.requestID
	}
	if !change.HasChanges() {
		return UserProfile{}, fmt.Errorf("%w: 没有需要修改的字段", ErrInvalidRequest)
	}
	if expectedRowVersion < 1 {
		return UserProfile{}, fmt.Errorf("%w: 资料版本无效", ErrInvalidRequest)
	}
	if err := s.preAuthorize(ctx, caller, targetUserID, true); err != nil {
		return UserProfile{}, err
	}
	current, found, err := s.opts.Store.GetProfile(ctx, targetUserID)
	if err != nil {
		return UserProfile{}, ErrStoreUnavailable
	}
	if !found {
		return UserProfile{}, ErrUserNotFound
	}
	if current.RowVersion != expectedRowVersion {
		return UserProfile{}, ErrVersionConflict
	}
	if err := s.authorize(ctx, caller, current, true); err != nil {
		return UserProfile{}, err
	}
	next, changes, err := applyChange(current, change, s.policy.phoneRegion)
	if err != nil {
		return UserProfile{}, err
	}
	now := s.now()
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:     caller.actor,
			Action:    "profile.update",
			Target:    audit.Target{Type: "user", ID: targetUserID},
			RequestID: requestID,
			Changes:   changes,
		},
		FailureReasonCode: "profile.update_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	changed := false
	err = s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		ok, err := s.opts.Store.UpdateProfile(txCtx, tx, UpdateRecord{
			UserID:             targetUserID,
			Nickname:           next.Nickname,
			Biography:          next.Biography,
			Language:           next.Language,
			Timezone:           next.Timezone,
			Phone:              next.Phone,
			PhoneChanged:       change.Phone != nil && next.Phone != current.Phone,
			ExpectedRowVersion: expectedRowVersion,
			Now:                now,
		})
		if err != nil {
			return err
		}
		changed = ok
		if !ok {
			return ErrVersionConflict
		}
		return nil
	})
	if err != nil {
		return UserProfile{}, mapCriticalError(err)
	}
	if !changed {
		return UserProfile{}, ErrVersionConflict
	}
	return s.readAfterWrite(ctx, targetUserID)
}

// ChangeUsername 是受控更名：规范化/保留名/唯一性/冷却/再次验证/版本条件。
func (s *Service) ChangeUsername(ctx context.Context, caller Caller, request ChangeUsernameRequest) (UserProfile, error) {
	ctx = normalizeContext(ctx)
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		return UserProfile{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if !account.ValidUserID(request.TargetUserID) {
		return UserProfile{}, fmt.Errorf("%w: 用户 ID 格式无效", ErrInvalidRequest)
	}
	if request.ExpectedRowVersion < 1 {
		return UserProfile{}, fmt.Errorf("%w: 资料版本无效", ErrInvalidRequest)
	}
	if caller.requestID != "" && request.RequestID == "" {
		request.RequestID = caller.requestID
	}
	if err := s.preAuthorize(ctx, caller, request.TargetUserID, true); err != nil {
		return UserProfile{}, err
	}
	current, found, err := s.opts.Store.GetProfile(ctx, request.TargetUserID)
	if err != nil {
		return UserProfile{}, ErrStoreUnavailable
	}
	if !found {
		return UserProfile{}, ErrUserNotFound
	}
	if current.RowVersion != request.ExpectedRowVersion {
		return UserProfile{}, ErrVersionConflict
	}
	if err := s.authorize(ctx, caller, current, true); err != nil {
		return UserProfile{}, err
	}
	// root 受保护：更名只能走后续受控应急流程，普通资料 API 不修改 root 用户名。
	if current.IsRoot {
		return UserProfile{}, ErrAccessDenied
	}
	username, normalized, err := account.NormalizeUsernameWithReserved(request.NewUsername, s.policy.reserved)
	if err != nil {
		return UserProfile{}, err
	}
	if normalized == current.UsernameNormalized && username == current.Username {
		return UserProfile{}, fmt.Errorf("%w: 新用户名与当前用户名相同", ErrInvalidRequest)
	}
	now := s.now()
	if s.policy.renameCooldown > 0 && !current.UsernameChangedAt.IsZero() {
		allowed := current.UsernameChangedAt.Add(s.policy.renameCooldown)
		if now.Before(allowed) {
			return UserProfile{}, fmt.Errorf("%w: 请在 %s 后再试", ErrRenameTooSoon,
				allowed.UTC().Format(time.RFC3339))
		}
	}
	if s.policy.requireReauth && caller.IsUser() {
		if s.opts.ReauthVerifier == nil {
			return UserProfile{}, ErrRenameReauthRequired
		}
		if err := s.opts.ReauthVerifier.VerifyReauth(ctx, caller, request.TargetUserID); err != nil {
			return UserProfile{}, ErrRenameReauthRequired
		}
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:     caller.actor,
			Action:    "profile.username_change",
			Target:    audit.Target{Type: "user", ID: request.TargetUserID},
			RequestID: request.RequestID,
			Changes: []audit.FieldChange{
				{Field: "username", Before: current.Username, After: username},
			},
		},
		FailureReasonCode: "profile.username_change_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	changed := false
	err = s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		ok, err := s.opts.Store.UpdateUsername(txCtx, tx, UsernameUpdate{
			UserID:             request.TargetUserID,
			Username:           username,
			UsernameNormalized: normalized,
			ExpectedRowVersion: request.ExpectedRowVersion,
			Now:                now,
		})
		if err != nil {
			return err
		}
		changed = ok
		if !ok {
			return ErrVersionConflict
		}
		return nil
	})
	if err != nil {
		return UserProfile{}, mapCriticalError(err)
	}
	if !changed {
		return UserProfile{}, ErrVersionConflict
	}
	return s.readAfterWrite(ctx, request.TargetUserID)
}

// authorize 使用注入 Authorizer 或默认口径判定读写权限。
func (s *Service) authorize(ctx context.Context, caller Caller, target UserProfile, write bool) error {
	if err := caller.actor.Validate(); err != nil {
		return ErrAccessDenied
	}
	if s.opts.Authorizer != nil {
		if err := s.opts.Authorizer.AuthorizeProfile(ctx, caller, target, write); err != nil {
			return ErrAccessDenied
		}
		return nil
	}
	switch caller.actor.Type {
	case audit.ActorUser:
		if caller.actor.ID != target.UserID {
			return ErrAccessDenied
		}
		return nil
	case audit.ActorSystem, audit.ActorLocalAdmin:
		return nil
	default:
		return ErrAccessDenied
	}
}

// readAfterWrite 重新读取提交后的资料；失败返回存储不可用而不是伪造成功。
func (s *Service) readAfterWrite(ctx context.Context, userID string) (UserProfile, error) {
	record, found, err := s.opts.Store.GetProfile(ctx, userID)
	if err != nil || !found {
		return UserProfile{}, ErrStoreUnavailable
	}
	return record, nil
}

// applyChange 校验字段并计算更新后的资料与审计差异；错误只描述规则，不回显敏感值。
func applyChange(current UserProfile, change ProfileChange, region string) (UserProfile, []audit.FieldChange, error) {
	next := current
	changes := make([]audit.FieldChange, 0, 5)
	if change.Nickname != nil {
		value, err := account.NormalizeNickname(*change.Nickname)
		if err != nil {
			return UserProfile{}, nil, err
		}
		if value != current.Nickname {
			changes = append(changes, audit.FieldChange{Field: "nickname", Before: current.Nickname, After: value})
		}
		next.Nickname = value
	}
	if change.Biography != nil {
		value, err := normalizeBiography(*change.Biography)
		if err != nil {
			return UserProfile{}, nil, err
		}
		if value != current.Biography {
			// 简介允许换行且长度较大，审计差异不能保存原文（换行/控制字符会被审计
			// 拒绝并误报存储故障）；只记录脱敏标记与长度摘要。
			changes = append(changes, audit.FieldChange{Field: "biography",
				After: fmt.Sprintf("[REDACTED] %d bytes", len(value))})
		}
		next.Biography = value
	}
	if change.Language != nil {
		value, err := account.NormalizeLanguage(*change.Language)
		if err != nil {
			return UserProfile{}, nil, err
		}
		if value != current.Language {
			changes = append(changes, audit.FieldChange{Field: "language", After: value})
		}
		next.Language = value
	}
	if change.Timezone != nil {
		value, err := account.NormalizeTimezone(*change.Timezone)
		if err != nil {
			return UserProfile{}, nil, err
		}
		if value != current.Timezone {
			changes = append(changes, audit.FieldChange{Field: "timezone", After: value})
		}
		next.Timezone = value
	}
	if change.Phone != nil {
		value, err := NormalizePhone(*change.Phone, region)
		if err != nil {
			return UserProfile{}, nil, err
		}
		if value != current.Phone {
			changes = append(changes, audit.FieldChange{
				Field: "phone", Before: MaskPhone(current.Phone), After: MaskPhone(value)})
		}
		next.Phone = value
	}
	return next, changes, nil
}

// normalizeBiography 校验简介长度与控制字符（与 account 创建口径一致，最多 1000
// 码点，允许换行）。
func normalizeBiography(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if len([]rune(value)) > 1000 {
		return "", fmt.Errorf("%w: 简介不能超过 1000 个字符", ErrInvalidRequest)
	}
	for _, character := range value {
		if character == '\n' || character == '\t' {
			continue
		}
		if character < 0x20 || character == 0x7f {
			return "", fmt.Errorf("%w: 简介包含不允许的控制字符", ErrInvalidRequest)
		}
	}
	return value, nil
}

func (s *Service) now() time.Time { return s.opts.Now().UTC().Truncate(time.Millisecond) }

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func mapCriticalError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, audit.ErrAuditUnavailable):
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	case errors.Is(err, audit.ErrInvalidEvent):
		// 审计事件字段非法是内部/配置错误，不能伪装成存储不可用。
		return fmt.Errorf("%w: 审计事件无效", ErrOptionsInvalid)
	case errors.Is(err, ErrVersionConflict), errors.Is(err, ErrUsernameTaken),
		errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrAccessDenied),
		errors.Is(err, ErrUserNotFound), errors.Is(err, ErrOptionsInvalid):
		return err
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, ErrStoreUnavailable):
		return err
	default:
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

// preAuthorize 在读取目标之前做保守判权：本人或受信管理通道直接判定；注入
// Authorizer 且调用者不是本人时，先用最小目标快照预判，避免先查库泄露存在性。
// 读取成功后仍会用真实目标快照再次授权。
func (s *Service) preAuthorize(ctx context.Context, caller Caller, targetUserID string, write bool) error {
	if err := caller.actor.Validate(); err != nil {
		return ErrAccessDenied
	}
	callerIsSelf := caller.IsUser() && caller.actor.ID == targetUserID
	if s.opts.Authorizer != nil {
		if callerIsSelf {
			return nil
		}
		if err := s.opts.Authorizer.AuthorizeProfile(ctx, caller,
			UserProfile{UserID: targetUserID}, write); err != nil {
			return ErrAccessDenied
		}
		return nil
	}
	switch caller.actor.Type {
	case audit.ActorUser:
		if caller.actor.ID != targetUserID {
			return ErrAccessDenied
		}
		return nil
	case audit.ActorSystem, audit.ActorLocalAdmin:
		return nil
	default:
		return ErrAccessDenied
	}
}
