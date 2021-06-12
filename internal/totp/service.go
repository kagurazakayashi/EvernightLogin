package totp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// Policy 是宿主的 MFA 强制策略。
type Policy interface {
	MFARequired(ctx context.Context, userID string) (bool, error)
}

// PolicyFunc 是 Policy 的函数适配器。
type PolicyFunc func(ctx context.Context, userID string) (bool, error)

// MFARequired 实现 Policy。
func (f PolicyFunc) MFARequired(ctx context.Context, userID string) (bool, error) {
	if f == nil {
		return false, nil
	}
	return f(ctx, userID)
}

// OtherFactors 是其他 MFA 因素查询（用于解除绑定时判断是否最后一个强因素）。
// 当前 TOTP 是唯一实现的强因素；未来 Passkey/FIDO2 接入后由宿主实现返回其他
// 强因素是否存在。nil 视为没有其他强因素。
type OtherFactors interface {
	HasOtherStrongFactor(ctx context.Context, userID string) (bool, error)
}

// Options 是 TOTP 服务依赖。
type Options struct {
	Store  Store
	Audit  AuditRecorder
	Sealer *secrets.Sealer
	// Reauth 是首次绑定/解除的近期认证收敛入口（步骤 39）；nil 时 fail-closed。
	Reauth reauth.OperationRunner
	// Policy 是强制 MFA 策略；nil 表示没有外部强制策略。
	Policy Policy
	// OtherFactors 报告是否存在其他强因素；nil 视为没有。
	OtherFactors OtherFactors
	// SessionInvalidator 在解除 TOTP 后撤销该用户既有会话；nil 时仍会在同事务
	// 递增 security_version 使会话失效。
	SessionInvalidator SessionInvalidator
	// IssuerName 是 otpauth 导入 URI 的签发者名称。
	IssuerName    string
	PeriodSeconds int
	Digits        int
	WindowSteps   int
	BindingTTL    time.Duration
	MaxAttempts   int
	Now           func() time.Time
	Random        io.Reader
	Logger        *slog.Logger
}

// AuditRecorder 是安全审计写入契约。
type AuditRecorder interface {
	Record(ctx context.Context, event audit.Event) error
	RecordFailure(ctx context.Context, event audit.Event) error
	ExecuteCritical(ctx context.Context, request audit.CriticalRequest, change audit.Change) error
}

var _ SessionInvalidator = (*session.Service)(nil)

// Service 是 TOTP 绑定与验证服务。构造后不可变，不启动协程，不做二维码 UI。
type Service struct {
	opts Options
}

// New 校验依赖并构造服务。
func New(options Options) (*Service, error) {
	if isNil(options.Store) {
		return nil, fmt.Errorf("%w: TOTP 存储为空", ErrOptionsInvalid)
	}
	if isNil(options.Audit) {
		return nil, fmt.Errorf("%w: 审计写入器为空", ErrOptionsInvalid)
	}
	if isNil(options.Sealer) {
		return nil, fmt.Errorf("%w: 种子加密器为空", ErrOptionsInvalid)
	}
	if options.PeriodSeconds == 0 {
		options.PeriodSeconds = DefaultPeriodSeconds
	}
	if options.PeriodSeconds < MinPeriodSeconds || options.PeriodSeconds > MaxPeriodSeconds {
		return nil, fmt.Errorf("%w: 时间步长必须在 %d～%d 秒之间", ErrOptionsInvalid, MinPeriodSeconds, MaxPeriodSeconds)
	}
	if options.Digits == 0 {
		options.Digits = DefaultDigits
	}
	if options.Digits < MinDigits || options.Digits > MaxDigits {
		return nil, fmt.Errorf("%w: 验证码位数必须在 %d～%d 之间", ErrOptionsInvalid, MinDigits, MaxDigits)
	}
	if options.WindowSteps == 0 {
		options.WindowSteps = DefaultWindowSteps
	}
	if options.WindowSteps < 0 || options.WindowSteps > MaxWindowSteps {
		return nil, fmt.Errorf("%w: 窗口步数必须在 0～%d 之间", ErrOptionsInvalid, MaxWindowSteps)
	}
	if options.BindingTTL == 0 {
		options.BindingTTL = DefaultBindingTTL
	}
	if options.BindingTTL < MinBindingTTL || options.BindingTTL > MaxBindingTTL {
		return nil, fmt.Errorf("%w: 绑定有效期必须在 %s～%s 之间", ErrOptionsInvalid, MinBindingTTL, MaxBindingTTL)
	}
	if options.MaxAttempts == 0 {
		options.MaxAttempts = DefaultMaxAttempts
	}
	if options.MaxAttempts < 1 || options.MaxAttempts > 10 {
		return nil, fmt.Errorf("%w: 尝试上限必须在 1～10 之间", ErrOptionsInvalid)
	}
	if options.IssuerName == "" {
		options.IssuerName = "EvernightLogin"
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.Logger == nil {
		options.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Service{opts: options}, nil
}

// BindingStart 是开始绑定 TOTP 的结果。Secret/URI 只在此返回一次，调用方必须只
// 展示给当前用户（二维码数据就是 URI 字符串），不得写入日志或普通存储。
type BindingStart struct {
	BindingID     string
	Secret        string
	URI           string
	ExpiresAt     time.Time
	PeriodSeconds int
	Digits        int
}

// BeginBinding 开始 TOTP 绑定：要求近期认证（步骤 39 收敛入口）、生成随机种子、
// 加密保存为 pending 绑定并返回一次性种子/URI。重绑允许已有 active 绑定存在，
// 新绑定验证成功后才替换旧绑定。
//
// 装配约束（必须由宿主保证）：本方法只允许从**完整（非受限）已认证会话**调用，
// 不得接受待第二因素/待改密/受限初始化等受限会话；高权限账户绑定或更换强因素
// 必须在完成强认证后进行。mfa.add 目录默认只要求近期密码认证，服务层不额外判断
// 会话是否完整，因此宿主若把受限会话误接到此入口，会退化为主密码即可绑定新因素。
func (s *Service) BeginBinding(ctx context.Context, caller Caller, requestID string) (BindingStart, error) {
	ctx = normalizeContext(ctx)
	if err := caller.actor.Validate(); err != nil || !caller.IsUser() {
		return BindingStart{}, ErrAccessDenied
	}
	if err := account.ValidateRequestID(requestID); err != nil {
		s.recordFailure(ctx, caller.actor, "mfa.totp_bind_begin_denied", "invalid_request",
			string(CodeReqInvalid))
		return BindingStart{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if err := s.requireRecentAuth(ctx, caller, "mfa.add"); err != nil {
		return BindingStart{}, err
	}
	now := s.now()
	// 惰性清理过期 pending，避免过期记录永久占用绑定名额。
	if _, cleanupErr := s.opts.Store.DeleteExpiredPending(ctx, caller.actor.ID, now); cleanupErr != nil {
		s.opts.Logger.Warn("TOTP 过期 pending 清理失败", "error", cleanupErr)
	}
	pendingCount, err := s.opts.Store.CountPending(ctx, caller.actor.ID, now)
	if err != nil {
		return BindingStart{}, ErrStoreUnavailable
	}
	if pendingCount >= MaxPendingBindings {
		s.recordFailure(ctx, caller.actor, "mfa.totp_bind_begin_denied", "pending_limit",
			string(CodeRateLimited))
		return BindingStart{}, ErrRateLimited
	}
	username, found, err := s.opts.Store.Username(ctx, caller.actor.ID)
	if err != nil {
		return BindingStart{}, ErrStoreUnavailable
	}
	if !found || username == "" {
		return BindingStart{}, ErrAccessDenied
	}
	secret, err := GenerateSecret(s.opts.Random)
	if err != nil {
		return BindingStart{}, err
	}
	bindingID, err := newBindingID(s.opts.Random)
	if err != nil {
		return BindingStart{}, err
	}
	sealed, err := s.opts.Sealer.Seal(secrets.Binding{
		Purpose: "mfa.totp", ObjectID: bindingID, ScopeID: secrets.ScopeSystem,
	}, secret)
	if err != nil {
		return BindingStart{}, fmt.Errorf("%w: %v", ErrSealFailed, err)
	}
	record := Binding{
		ID: bindingID, UserID: caller.actor.ID, Status: "pending",
		Algorithm: AlgorithmSHA1, Digits: s.opts.Digits, PeriodSeconds: s.opts.PeriodSeconds,
		WindowSteps: s.opts.WindowSteps, LastAcceptedStep: -1, Attempts: 0,
		MaxAttempts: s.opts.MaxAttempts, ExpiresAt: now.Add(s.opts.BindingTTL),
		CreatedAt: now, UpdatedAt: now, sealedSecret: sealed,
	}
	critical := s.critical("mfa.totp_bind_begin", caller.actor, bindingID, requestID,
		[]audit.FieldChange{{Field: "status", After: "pending"},
			{Field: "period_seconds", After: fmt.Sprint(s.opts.PeriodSeconds)},
			{Field: "digits", After: fmt.Sprint(s.opts.Digits)}})
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.opts.Store.CreatePendingTx(txCtx, tx, record)
	}); err != nil {
		return BindingStart{}, mapCriticalError(err)
	}
	uri, err := BuildURI(secret, s.opts.IssuerName, username, s.opts.PeriodSeconds, s.opts.Digits)
	if err != nil {
		return BindingStart{}, err
	}
	return BindingStart{BindingID: bindingID, Secret: EncodeSecret(secret), URI: uri,
		ExpiresAt: record.ExpiresAt, PeriodSeconds: s.opts.PeriodSeconds, Digits: s.opts.Digits}, nil
}

// BindConfirm 是确认绑定的请求；Code 是当前验证器显示的一次性验证码。
type BindConfirm struct {
	BindingID string
	Code      string
	RequestID string
}

// BindingMetadata 是可查询的绑定元数据（不含种子或加密信封）。
type BindingMetadata struct {
	ID            string
	Status        string
	Algorithm     Algorithm
	Digits        int
	PeriodSeconds int
	WindowSteps   int
	CreatedAt     time.Time
	ActivatedAt   time.Time
}

// ConfirmBinding 验证 pending 绑定的验证码；成功后在审计事务内激活新绑定并停用
// 旧 active（重绑先验证新因素再替换旧因素），失败递增尝试次数并写失败审计。
func (s *Service) ConfirmBinding(ctx context.Context, caller Caller, request BindConfirm) (BindingMetadata, error) {
	ctx = normalizeContext(ctx)
	if err := caller.actor.Validate(); err != nil || !caller.IsUser() {
		return BindingMetadata{}, ErrAccessDenied
	}
	if !validBindingID(request.BindingID) || request.Code == "" || len(request.Code) > 16 {
		s.recordFailure(ctx, caller.actor, "mfa.totp_bind_confirm_denied", "invalid_params",
			string(CodeReqInvalid))
		return BindingMetadata{}, ErrInvalidRequest
	}
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		s.recordFailure(ctx, caller.actor, "mfa.totp_bind_confirm_denied", "invalid_request",
			string(CodeReqInvalid))
		return BindingMetadata{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	binding, found, err := s.opts.Store.GetPending(ctx, caller.actor.ID, request.BindingID)
	if err != nil {
		return BindingMetadata{}, ErrStoreUnavailable
	}
	if !found {
		s.recordFailure(ctx, caller.actor, "mfa.totp_bind_confirm_denied", "not_found",
			string(CodeReqInvalid))
		return BindingMetadata{}, ErrBindingNotFound
	}
	now := s.now()
	if !now.Before(binding.ExpiresAt) {
		s.recordFailure(ctx, caller.actor, "mfa.totp_bind_confirm_denied", "expired",
			string(CodeReqInvalid))
		return BindingMetadata{}, ErrBindingExpired
	}
	if binding.Attempts >= binding.MaxAttempts {
		s.recordFailure(ctx, caller.actor, "mfa.totp_bind_confirm_denied", "attempts_exceeded",
			string(CodeChallengeInvalid))
		return BindingMetadata{}, ErrAttemptsExceeded
	}
	secret, err := s.openSecret(binding)
	if err != nil {
		return BindingMetadata{}, err
	}
	matchedStep, ok := verifyWindow(secret, request.Code, now, binding.PeriodSeconds,
		binding.WindowSteps, binding.Digits)
	if !ok {
		// 失败确认只写独立失败审计，绝不伪造 ExecuteCritical 成功事件；尝试计数
		// 用非事务条件更新（并发仍不超上限），不涉及业务状态成功。
		s.recordFailure(ctx, caller.actor, "mfa.totp_bind_confirm_failed", "code_invalid",
			string(CodeChallengeInvalid))
		if _, _, incrementErr := s.opts.Store.IncrementAttempts(ctx, caller.actor.ID, binding.ID, now); incrementErr != nil {
			s.opts.Logger.Warn("TOTP 绑定失败计数写入失败", "error", incrementErr)
		}
		return BindingMetadata{}, ErrCodeInvalid
	}
	critical := s.critical("mfa.totp_bind_activated", caller.actor, binding.ID, request.RequestID,
		[]audit.FieldChange{{Field: "status", Before: "pending", After: "active"}})
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		ok, activateErr := s.opts.Store.ActivateTx(txCtx, tx, caller.actor.ID, binding.ID, matchedStep, now)
		if activateErr != nil {
			return activateErr
		}
		if !ok {
			return ErrBindingNotFound
		}
		return nil
	}); err != nil {
		return BindingMetadata{}, mapCriticalError(err)
	}
	metadata := BindingMetadata{ID: binding.ID, Status: "active", Algorithm: binding.Algorithm,
		Digits: binding.Digits, PeriodSeconds: binding.PeriodSeconds,
		WindowSteps: binding.WindowSteps, CreatedAt: binding.CreatedAt, ActivatedAt: now}
	return metadata, nil
}

// VerifyLoginCode 验证当前用户 active TOTP 绑定的一次性验证码，并原子推进已接受
// 时间步：只接受严格更大的时间步，同一步并发/重放只有一方成功。
func (s *Service) VerifyLoginCode(ctx context.Context, userID, code string) error {
	ctx = normalizeContext(ctx)
	if !account.ValidUserID(userID) || code == "" || len(code) > 16 {
		return ErrInvalidRequest
	}
	binding, found, err := s.opts.Store.GetActive(ctx, userID)
	if err != nil {
		return ErrStoreUnavailable
	}
	if !found {
		return ErrBindingNotFound
	}
	secret, err := s.openSecret(binding)
	if err != nil {
		return err
	}
	now := s.now()
	matchedStep, ok := verifyWindow(secret, code, now, binding.PeriodSeconds, binding.WindowSteps, binding.Digits)
	if !ok {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: userID}, "mfa.totp_verify_failed",
			"code_invalid", string(CodeChallengeInvalid))
		return ErrCodeInvalid
	}
	if matchedStep <= binding.LastAcceptedStep {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: userID}, "mfa.totp_verify_failed",
			"step_replay", string(CodeChallengeInvalid))
		return ErrReplay
	}
	advanced := false
	critical := s.critical("mfa.totp_verified", audit.Actor{Type: audit.ActorUser, ID: userID},
		binding.ID, "", []audit.FieldChange{{Field: "step", After: fmt.Sprint(matchedStep)}})
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		ok, advanceErr := s.opts.Store.AdvanceAcceptedStepTx(txCtx, tx, userID, binding.ID, matchedStep, now)
		if advanceErr != nil {
			return advanceErr
		}
		if !ok {
			return ErrReplay
		}
		advanced = true
		return nil
	}); err != nil {
		if errors.Is(err, ErrReplay) {
			return ErrReplay
		}
		return mapCriticalError(err)
	}
	if !advanced {
		return ErrReplay
	}
	return nil
}

// HasActive 报告用户是否已激活 TOTP（供步骤 40 登录状态机选择因素）。
func (s *Service) HasActive(ctx context.Context, userID string) (bool, error) {
	ctx = normalizeContext(ctx)
	if !account.ValidUserID(userID) {
		return false, ErrInvalidRequest
	}
	active, err := s.opts.Store.HasActive(ctx, userID)
	if err != nil {
		return false, ErrStoreUnavailable
	}
	return active, nil
}

// RemoveRequest 是解除 TOTP 绑定请求；Code 必须验证当前绑定（证明持有）。
type RemoveRequest struct {
	Code      string
	RequestID string
}

// RemoveBinding 先验证当前 TOTP 验证码，再检查强制 MFA 与其他强因素：强制 MFA 下
// 若没有其他强因素则拒绝移除最后一个可用因素。
func (s *Service) RemoveBinding(ctx context.Context, caller Caller, request RemoveRequest) error {
	ctx = normalizeContext(ctx)
	if err := caller.actor.Validate(); err != nil || !caller.IsUser() {
		return ErrAccessDenied
	}
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		return fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	active, found, err := s.opts.Store.GetActive(ctx, caller.actor.ID)
	if err != nil {
		return ErrStoreUnavailable
	}
	if !found {
		return ErrBindingNotFound
	}
	if err := s.VerifyLoginCode(ctx, caller.actor.ID, request.Code); err != nil {
		return err
	}
	if !isNil(s.opts.Policy) {
		forced, policyErr := s.opts.Policy.MFARequired(ctx, caller.actor.ID)
		if policyErr != nil {
			return ErrPolicyUnavailable
		}
		if forced {
			hasOther := false
			if !isNil(s.opts.OtherFactors) {
				hasOther, err = s.opts.OtherFactors.HasOtherStrongFactor(ctx, caller.actor.ID)
				if err != nil {
					return ErrPolicyUnavailable
				}
			}
			if !hasOther {
				s.recordFailure(ctx, caller.actor, "mfa.totp_remove_denied", "last_strong_factor",
					string(CodeMFARequired))
				return ErrFactorRequired
			}
		}
	}
	now := s.now()
	critical := s.critical("mfa.totp_removed", caller.actor, active.ID, request.RequestID,
		[]audit.FieldChange{{Field: "status", Before: "active", After: "disabled"}})
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		removed, disableErr := s.opts.Store.DisableActiveTx(txCtx, tx, caller.actor.ID, now)
		if disableErr != nil {
			return disableErr
		}
		if !removed {
			return ErrBindingNotFound
		}
		// 解除强因素改变认证面：同事务递增 security_version 让解除前建立的所有
		// 会话（含记住我）立即失效，不能继续凭旧强认证访问管理接口。
		return s.opts.Store.IncrementUserSecurityVersionTx(txCtx, tx, caller.Actor().ID, now)
	}); err != nil {
		return mapCriticalError(err)
	}
	if !isNil(s.opts.SessionInvalidator) {
		if _, err := s.opts.SessionInvalidator.RevokeAllForUser(ctx, caller.Actor().ID,
			"totp_removed"); err != nil {
			s.opts.Logger.Warn("TOTP 解除后撤销会话失败", "error", err)
		}
	}
	return nil
}

// Bindings 返回调用者当前绑定元数据（不含种子/密文）。
func (s *Service) Bindings(ctx context.Context, caller Caller) ([]BindingMetadata, error) {
	ctx = normalizeContext(ctx)
	if err := caller.actor.Validate(); err != nil || !caller.IsUser() {
		return nil, ErrAccessDenied
	}
	bindings, err := s.opts.Store.List(ctx, caller.actor.ID)
	if err != nil {
		return nil, ErrStoreUnavailable
	}
	metadata := make([]BindingMetadata, 0, len(bindings))
	for _, binding := range bindings {
		metadata = append(metadata, BindingMetadata{ID: binding.ID, Status: binding.Status,
			Algorithm: binding.Algorithm, Digits: binding.Digits,
			PeriodSeconds: binding.PeriodSeconds, WindowSteps: binding.WindowSteps,
			CreatedAt: binding.CreatedAt, ActivatedAt: binding.ActivatedAt})
	}
	return metadata, nil
}

// ===== 内部辅助 =====

// requireRecentAuth 复用步骤 39 的敏感操作收敛入口做绑定前近期认证判定。
func (s *Service) requireRecentAuth(ctx context.Context, caller Caller, operationID string) error {
	if isNil(s.opts.Reauth) {
		return ErrReauthRequired
	}
	reauthCaller, err := reauth.CallerFromActor(caller.actor)
	if err != nil {
		return ErrAccessDenied
	}
	if _, err := s.opts.Reauth.Authorize(ctx, reauthCaller, reauth.Request{
		ScopeID: "system", OperationID: operationID, TargetType: "user",
		TargetID: caller.actor.ID, Params: map[string]string{"factor": "totp"},
		Description: "绑定 TOTP 验证器",
	}); err != nil {
		switch {
		case errors.Is(err, reauth.ErrAccessDenied):
			return ErrAccessDenied
		case errors.Is(err, reauth.ErrMFARequired):
			return ErrMFARequired
		default:
			return ErrReauthRequired
		}
	}
	return nil
}

// openSecret 用绑定 ID 与固定用途解密种子；失败 fail-closed，不返回种子。
func (s *Service) openSecret(binding Binding) ([]byte, error) {
	if len(binding.sealedSecret) == 0 {
		return nil, ErrSealFailed
	}
	secret, err := s.opts.Sealer.Open(secrets.Binding{
		Purpose: "mfa.totp", ObjectID: binding.ID, ScopeID: secrets.ScopeSystem,
	}, binding.sealedSecret)
	if err != nil || len(secret) < 10 {
		return nil, ErrSealFailed
	}
	return secret, nil
}

func (s *Service) critical(action string, actor audit.Actor, bindingID, requestID string,
	changes []audit.FieldChange) audit.CriticalRequest {
	return audit.CriticalRequest{
		Event: audit.Event{
			Actor: actor, Action: action,
			Target:    audit.Target{Type: "totp_binding", ID: safeValue(bindingID)},
			RequestID: validRequestID(requestID), Changes: changes,
		},
		FailureReasonCode:   action + "_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapCriticalError(err))) },
	}
}

// recordFailure 写独立失败审计；失败只记录日志。
func (s *Service) recordFailure(ctx context.Context, actor audit.Actor, action, reason, code string) {
	if err := actor.Validate(); err != nil {
		return
	}
	event := audit.Event{Actor: actor, Action: action, Target: audit.Target{Type: "totp_binding"},
		Outcome: audit.OutcomeFailure, ErrorCode: code, ReasonCode: safeReason(reason)}
	if err := s.opts.Audit.RecordFailure(ctx, event); err != nil {
		s.opts.Logger.Warn("TOTP 失败审计写入失败", "error", err)
	}
}

func (s *Service) now() time.Time { return s.opts.Now().UTC().Truncate(time.Millisecond) }

func newBindingID(random io.Reader) (string, error) {
	buffer := make([]byte, 16)
	if _, err := io.ReadFull(random, buffer); err != nil {
		return "", ErrSealFailed
	}
	return "tfb_" + hex.EncodeToString(buffer), nil
}

func validBindingID(value string) bool {
	if len(value) != 4+32 || value[:4] != "tfb_" {
		return false
	}
	for index := 4; index < len(value); index++ {
		character := value[index]
		if (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') {
			continue
		}
		return false
	}
	return true
}

func mapCriticalError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, audit.ErrAuditUnavailable):
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	case errors.Is(err, audit.ErrInvalidEvent):
		return fmt.Errorf("%w: 审计事件无效", ErrOptionsInvalid)
	case errors.Is(err, ErrBindingNotFound), errors.Is(err, ErrBindingExpired),
		errors.Is(err, ErrCodeInvalid), errors.Is(err, ErrReplay),
		errors.Is(err, ErrAttemptsExceeded), errors.Is(err, ErrAccessDenied),
		errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrFactorRequired),
		errors.Is(err, ErrMFARequired), errors.Is(err, ErrOptionsInvalid):
		return err
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, ErrStoreUnavailable), errors.Is(err, ErrPolicyUnavailable),
		errors.Is(err, ErrSealFailed), errors.Is(err, ErrRateLimited):
		return err
	default:
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
}

func validRequestID(value string) string {
	if account.ValidateRequestID(value) != nil {
		return ""
	}
	return value
}

func safeValue(value string) string {
	if len(value) == 0 || len(value) > 128 {
		return ""
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '_' ||
			character == '-' {
			continue
		}
		return ""
	}
	return value
}

func safeReason(value string) string {
	if len(value) == 0 || len(value) > 64 {
		return ""
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '_' {
			continue
		}
		return ""
	}
	return value
}

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
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
