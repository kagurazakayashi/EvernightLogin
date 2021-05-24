package session

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
)

// MaxCleanupRetention 是过期会话清理允许保留的最长时间。
const MaxCleanupRetention = 30 * 24 * time.Hour

// 服务端撤销原因码。它们写入 sessions.revoked_reason 与审计差异，供排障区分；
// 不参与授权判断，也不代表客户端可见的原因。
const (
	// RevokeReasonLogout 表示用户主动退出。
	RevokeReasonLogout = "logout"
	// RevokeReasonRotated 表示登录成功轮换撤销了旧会话（防会话固定）。
	RevokeReasonRotated = "rotated"
	// RevokeReasonUserSessions 表示按账户批量撤销（禁用、改密后的服务端撤销）。
	RevokeReasonUserSessions = "user_sessions_revoked"
)

// AuditRecorder 是会话服务使用的安全审计接口；生产实现为 *audit.Recorder。
type AuditRecorder interface {
	Record(ctx context.Context, event audit.Event) error
	RecordFailure(ctx context.Context, event audit.Event) error
	ExecuteCritical(ctx context.Context, request audit.CriticalRequest, change audit.Change) error
}

// Options 是构造会话服务的显式依赖。
type Options struct {
	// Store 是会话持久化；必填。
	Store Store
	// Audit 是安全审计写入器；必填。会话签发、退出与批量撤销都写审计，签发与
	// 撤销必须与成功审计一致提交才能返回成功。
	Audit AuditRecorder
	// Keyring 提供会话秘密与 CSRF 令牌摘要所需的密钥材料；必填，必须包含当前
	// 写密钥。本包不保存会话秘密原文。
	Keyring *secrets.Keyring
	// IdleTimeout 是空闲到期期限；0 使用 DefaultIdleTimeout。
	IdleTimeout time.Duration
	// AbsoluteTimeout 是绝对到期期限；0 使用 DefaultAbsoluteTimeout，且不得小于
	// IdleTimeout。
	AbsoluteTimeout time.Duration
	// CookieName 是浏览器会话 Cookie 名；空使用 DefaultCookieName。CSRF 中间件
	// 必须使用同一名字，否则无法识别 Cookie 会话请求。
	CookieName string
	// CookiePolicy 是会话 Cookie 安全属性；nil 使用 DefaultCookiePolicy。
	CookiePolicy *CookiePolicy
	// Logger 是结构化运行日志；nil 使用丢弃输出。日志只记录会话/用户稳定 ID、类
	// 别、原因与到期时间，绝不记录会话秘密、CSRF 令牌或摘要。
	Logger *slog.Logger
	// Now 是可注入时钟；nil 使用 time.Now。服务内部统一截断到 UTC 毫秒。
	Now func() time.Time
	// Random 是安全随机源；nil 使用 crypto/rand.Reader。生产不得替换为弱随机源。
	Random io.Reader
}

// Service 是会话服务。构造后不可变，可被多个 goroutine 并发使用；它不拥有
// 数据库连接、不启动后台协程、也不自动清理过期会话（由维护任务调用 Cleanup）。
type Service struct {
	store           Store
	audit           AuditRecorder
	ring            *secrets.Keyring
	idleTimeout     time.Duration
	absoluteTimeout time.Duration
	cookieName      string
	cookiePolicy    CookiePolicy
	logger          *slog.Logger
	now             func() time.Time
	random          io.Reader
}

// New 创建会话服务。存储、审计或密钥环为空、缺少当前写密钥、期限/策略不合法时
// 返回 ErrOptionsInvalid；不会创建默认密钥、默认审计或替身存储。
func New(store Store, options Options) (*Service, error) {
	if isNilInterface(store) {
		return nil, fmt.Errorf("%w: 会话存储为空", ErrOptionsInvalid)
	}
	if isNilInterface(options.Audit) {
		return nil, fmt.Errorf("%w: 审计写入器为空", ErrOptionsInvalid)
	}
	if options.Keyring == nil {
		return nil, fmt.Errorf("%w: 主密钥环为空", ErrOptionsInvalid)
	}
	currentKeyID := options.Keyring.CurrentKeyID()
	if currentKeyID == "" || !options.Keyring.HasKey(currentKeyID) {
		return nil, fmt.Errorf("%w: 密钥环缺少当前写密钥", ErrOptionsInvalid)
	}
	idleTimeout := options.IdleTimeout
	if idleTimeout == 0 {
		idleTimeout = DefaultIdleTimeout
	}
	if idleTimeout < MinIdleTimeout || idleTimeout > MaxIdleTimeout {
		return nil, fmt.Errorf("%w: 空闲期限必须在 %s 到 %s 之间", ErrOptionsInvalid, MinIdleTimeout, MaxIdleTimeout)
	}
	absoluteTimeout := options.AbsoluteTimeout
	if absoluteTimeout == 0 {
		absoluteTimeout = DefaultAbsoluteTimeout
	}
	if absoluteTimeout < MinAbsoluteTimeout || absoluteTimeout > MaxAbsoluteTimeout {
		return nil, fmt.Errorf("%w: 绝对期限必须在 %s 到 %s 之间", ErrOptionsInvalid, MinAbsoluteTimeout, MaxAbsoluteTimeout)
	}
	if absoluteTimeout < idleTimeout {
		return nil, fmt.Errorf("%w: 绝对期限不能小于空闲期限", ErrOptionsInvalid)
	}
	cookieName := options.CookieName
	if cookieName == "" {
		cookieName = DefaultCookieName
	}
	if !isCookieToken(cookieName) {
		return nil, fmt.Errorf("%w: 会话 Cookie 名无效", ErrOptionsInvalid)
	}
	cookiePolicy := DefaultCookiePolicy()
	if options.CookiePolicy != nil {
		cookiePolicy = *options.CookiePolicy
	}
	if err := cookiePolicy.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrOptionsInvalid, err)
	}
	if _, err := cookiePolicy.NewCookie(cookieName, "probe-value"); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrOptionsInvalid, err)
	}
	logger := options.Logger
	if logger == nil {
		logger = discardLogger()
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	random := options.Random
	if random == nil {
		random = rand.Reader
	}
	return &Service{
		store:           store,
		audit:           options.Audit,
		ring:            options.Keyring,
		idleTimeout:     idleTimeout,
		absoluteTimeout: absoluteTimeout,
		cookieName:      cookieName,
		cookiePolicy:    cookiePolicy,
		logger:          logger,
		now:             now,
		random:          random,
	}, nil
}

// isNilInterface 检测 nil 接口与 typed nil 指针，避免把 typed nil 当成可用依赖。
func isNilInterface(value any) bool {
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

// discardLogger 返回写入丢弃输出的日志器。
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

// normalizeContext 把 nil ctx 当成 Background，避免调用方漏传时 panic。
func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// clockNow 返回统一截断到 UTC 毫秒的当前时间，与数据库毫秒列表示一致。
func (s *Service) clockNow() time.Time {
	return s.now().UTC().Truncate(time.Millisecond)
}

// authnSpec 是从认证结果提取的签发参数。
type authnSpec struct {
	userID          string
	securityVersion int64
	kind            Kind
	reason          Reason
	steps           []authn.Step
}

// sessionSpecFromAuth 校验认证结果并映射为会话类别。它绝不把不完整认证当完整
// 登录：只有 complete 且 unrestricted 且无剩余步骤才允许普通会话；受限/待补
// 步骤只能得到受限会话；凭客户端标记伪造的组合一律拒绝。
func sessionSpecFromAuth(result authn.AuthenticateResult) (authnSpec, error) {
	if !account.ValidUserID(result.UserID) {
		return authnSpec{}, fmt.Errorf("%w: 认证结果的用户 ID 无效", ErrInvalidRequest)
	}
	if result.SecurityVersion <= 0 {
		return authnSpec{}, fmt.Errorf("%w: 认证结果缺少账户安全版本", ErrInvalidRequest)
	}
	if !result.Outcome.Valid() {
		return authnSpec{}, fmt.Errorf("%w: 认证结论类别未知", ErrInvalidRequest)
	}
	if len(result.CompletedMethods) == 0 {
		return authnSpec{}, fmt.Errorf("%w: 认证结果没有已完成方法", ErrInvalidRequest)
	}
	for _, method := range result.CompletedMethods {
		if !method.Valid() {
			return authnSpec{}, fmt.Errorf("%w: 认证方法标识未知", ErrInvalidRequest)
		}
	}
	reason, err := reasonFromAuthn(result)
	if err != nil {
		return authnSpec{}, err
	}
	restricted := reason != ReasonNone
	// 组合一致性：complete 必须 unrestricted 且无剩余步骤；受限结论必须标记
	// Restricted 且带原因。
	if result.Outcome == authn.OutcomeComplete {
		if result.Restricted || len(result.RequiredSteps) != 0 {
			return authnSpec{}, fmt.Errorf("%w: 完整认证结果不得标记受限或带剩余步骤", ErrInvalidRequest)
		}
	} else if !result.Restricted || reason == ReasonNone {
		return authnSpec{}, fmt.Errorf("%w: 不完整认证结果必须标记受限并带受限原因", ErrInvalidRequest)
	}
	for _, step := range result.RequiredSteps {
		if !step.Valid() {
			return authnSpec{}, fmt.Errorf("%w: 剩余认证步骤标识未知", ErrInvalidRequest)
		}
	}
	kind := KindNormal
	if restricted {
		kind = KindRestricted
	}
	return authnSpec{
		userID:          result.UserID,
		securityVersion: result.SecurityVersion,
		kind:            kind,
		reason:          reason,
		steps:           append([]authn.Step(nil), result.RequiredSteps...),
	}, nil
}

// Login 把密码认证结果接入会话，签发普通或受限会话。
//
// 签发前会重读账户状态与安全版本（必须 active 且与认证结果一致）以及应用/成员
// 状态，绝不信任认证结果里的快照。若请求携带仍有效的旧会话秘密，它会在同一审计
// 事务中被撤销，并签发新的会话 ID 与秘密（防会话固定）。成功审计与写入必须一致
// 提交，审计不可用时拒绝签发。
func (s *Service) Login(ctx context.Context, request LoginRequest) (IssuedSession, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return IssuedSession{}, err
	}
	spec, err := sessionSpecFromAuth(request.Result)
	if err != nil {
		return IssuedSession{}, err
	}
	if request.AppID != "" && !validAppID(request.AppID) {
		return IssuedSession{}, fmt.Errorf("%w: 应用 ID 格式无效", ErrInvalidRequest)
	}
	if request.RequestID != "" && !validRequestID(request.RequestID) {
		return IssuedSession{}, fmt.Errorf("%w: 请求编号格式无效", ErrInvalidRequest)
	}
	now := s.clockNow()
	if err := s.checkEligibility(ctx, spec, request.AppID); err != nil {
		return IssuedSession{}, err
	}
	existing, err := s.loadRevocableSession(ctx, request.ExistingSession)
	if err != nil {
		return IssuedSession{}, err
	}
	material, err := s.newSessionMaterial()
	if err != nil {
		return IssuedSession{}, err
	}
	keyID := s.ring.CurrentKeyID()
	secretDigest, err := s.ring.HMACDigest(keyID, secretDigestDomain, digestMessage(material.id, material.secret))
	if err != nil {
		s.logger.Error("无法生成会话秘密摘要", "reason", "key_unavailable")
		return IssuedSession{}, fmt.Errorf("%w: 无法生成会话秘密摘要", ErrOptionsInvalid)
	}
	csrfDigest, err := s.ring.HMACDigest(keyID, csrfDigestDomain, digestMessage(material.id, material.csrf))
	if err != nil {
		s.logger.Error("无法生成 CSRF 令牌摘要", "reason", "key_unavailable")
		return IssuedSession{}, fmt.Errorf("%w: 无法生成 CSRF 令牌摘要", ErrOptionsInvalid)
	}
	absoluteExpiresAt := now.Add(s.absoluteTimeout)
	idleExpiresAt := now.Add(s.idleTimeout)
	if idleExpiresAt.After(absoluteExpiresAt) {
		idleExpiresAt = absoluteExpiresAt
	}
	record := Record{
		ID:                material.id,
		UserID:            spec.userID,
		AppID:             request.AppID,
		Kind:              spec.kind,
		Reason:            spec.reason,
		RequiredSteps:     spec.steps,
		SecurityVersion:   spec.securityVersion,
		SecretDigest:      secretDigest,
		CSRFDigest:        csrfDigest,
		KeyID:             keyID,
		RowVersion:        1,
		CreatedAt:         now,
		LastSeenAt:        now,
		IdleExpiresAt:     idleExpiresAt,
		AbsoluteExpiresAt: absoluteExpiresAt,
		RequestID:         request.RequestID,
	}
	changes := []audit.FieldChange{
		{Field: "session_kind", After: string(record.Kind)},
		{Field: "restricted_reason", After: string(record.Reason)},
		{Field: "security_version", After: strconv.FormatInt(record.SecurityVersion, 10)},
		{Field: "idle_expires_at", After: idleExpiresAt.UTC().Format(time.RFC3339)},
		{Field: "absolute_expires_at", After: absoluteExpiresAt.UTC().Format(time.RFC3339)},
	}
	if record.AppID != "" {
		changes = append(changes, audit.FieldChange{Field: "app_id", After: record.AppID})
	}
	if existing != nil {
		changes = append(changes, audit.FieldChange{Field: "session_rotation", After: "previous_session_revoked"})
	}
	event := audit.Event{
		Actor:     audit.Actor{Type: audit.ActorUser, ID: spec.userID},
		AppID:     request.AppID,
		Action:    string(ActionSessionIssue),
		Target:    audit.Target{Type: "session", ID: record.ID},
		RequestID: request.RequestID,
		Changes:   changes,
	}
	critical := audit.CriticalRequest{
		Event:             event,
		FailureReasonCode: "session_issue_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(s.mapCriticalError(ctx, err)))
		},
	}
	insertErr := s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		if existing != nil {
			revoked, err := s.store.Revoke(txCtx, tx, RevokeCondition{
				ID:     existing.ID,
				Now:    now,
				Reason: RevokeReasonRotated,
			})
			if err != nil {
				return err
			}
			// 撤销未生效（旧会话已被并发撤销/状态竞争）时不能断言轮换成功，更
			// 不能在未确认旧会话失效时签发新会话：整体回滚并 fail-closed 拒绝。
			if !revoked {
				return ErrRotationFailed
			}
		}
		return s.store.Insert(txCtx, tx, record)
	})
	if insertErr != nil {
		return IssuedSession{}, s.mapCriticalError(ctx, insertErr)
	}
	issued := IssuedSession{
		Session:    record.session(),
		Secret:     newSecret(material.id + secretSeparator + material.secret),
		CSRFSecret: newSecret(material.csrf),
	}
	if existing != nil {
		issued.RotatedSessionID = existing.ID
	}
	s.logger.Info("会话已签发",
		"session_id", record.ID,
		"user_id", record.UserID,
		"app_id", record.AppID,
		"kind", string(record.Kind),
		"reason", string(record.Reason),
		"idle_expires_at", idleExpiresAt,
		"absolute_expires_at", absoluteExpiresAt,
		"rotated", existing != nil,
	)
	return issued, nil
}

// checkEligibility 在签发前重读账户与应用/成员状态。任何不一致都拒绝签发；对外
// 统一 ErrAccountNotEligible（与登录失败一致），内部原因只写失败审计与日志。
func (s *Service) checkEligibility(ctx context.Context, spec authnSpec, appID string) error {
	state, found, err := s.store.LoadUserState(ctx, spec.userID)
	if err != nil {
		return s.storeFailure(ctx, "读取账户状态", err)
	}
	if !found || state.Status != account.StatusActive || state.SecurityVersion != spec.securityVersion {
		s.recordIssuanceRejection(ctx, spec, appID, "account_not_eligible")
		return ErrAccountNotEligible
	}
	// root 在 MFA/管理强认证完成前只能持有受限会话：即使调用方给出“完整认证”
	// 结果，也不得签发普通会话（防御认证结果被误用或未来 MFA 状态机接线错误）。
	if state.IsRoot && spec.kind == KindNormal {
		s.recordIssuanceRejection(ctx, spec, appID, "root_requires_restricted_session")
		return ErrAccountNotEligible
	}
	if appID != "" {
		membership, found, err := s.store.LoadMembership(ctx, appID, spec.userID)
		if err != nil {
			return s.storeFailure(ctx, "读取应用成员状态", err)
		}
		if !found || !membership.ApplicationActive || !membership.MemberActive {
			s.recordIssuanceRejection(ctx, spec, appID, "application_membership_inactive")
			return ErrAccountNotEligible
		}
	}
	return nil
}

// recordIssuanceRejection 记录签发被拒绝的失败审计。审计失败时仍返回统一失败，
// 只把审计错误写入运行日志（不改变“拒绝签发”的结论）。
func (s *Service) recordIssuanceRejection(ctx context.Context, spec authnSpec, appID, reason string) {
	event := audit.Event{
		Actor:      audit.Actor{Type: audit.ActorAnonymous},
		AppID:      appID,
		Action:     string(ActionSessionIssue),
		Target:     audit.Target{Type: "user", ID: spec.userID},
		Outcome:    audit.OutcomeFailure,
		ErrorCode:  string(CodeAuthFailed),
		ReasonCode: reason,
	}
	if err := s.audit.RecordFailure(ctx, event); err != nil {
		s.logger.Warn("会话签发拒绝的失败审计写入失败", "reason", reason, "error_category", "audit_unavailable")
	}
	s.logger.Info("会话签发被拒绝", "user_id", spec.userID, "app_id", appID, "reason", reason)
}

// loadRevocableSession 读取并验证客户端出示的旧会话秘密，用于登录轮换。
//
// 只验证秘密摘要与非撤销状态，不要求账户仍可用（旧会话可能属于即将失效的账户，
// 仍需被撤销）。秘密格式非法、会话不存在、摘要不匹配或已撤销时返回 nil，表示
// 没有需要轮换的旧会话；存储错误时返回错误（fail-closed，不签发新会话）。
func (s *Service) loadRevocableSession(ctx context.Context, secret string) (*Record, error) {
	if secret == "" {
		return nil, nil
	}
	record, err := s.loadVerifiedRecord(ctx, secret, "session_rotation")
	if err != nil {
		if errors.Is(err, ErrSessionInvalid) {
			return nil, nil
		}
		return nil, err
	}
	if !record.RevokedAt.IsZero() {
		return nil, nil
	}
	return &record, nil
}

// Validate 校验会话秘密并返回当前会话快照。未知、撤销、空闲/绝对到期、摘要不
// 匹配、账户禁用/安全版本变化、应用停用或成员失效都返回统一的 ErrSessionInvalid，
// 不泄露具体原因。校验不延长空闲到期（续期必须显式调用 Renew）。
func (s *Service) Validate(ctx context.Context, secret string) (Session, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return Session{}, err
	}
	record, err := s.loadVerifiedRecord(ctx, secret, "validate")
	if err != nil {
		return Session{}, err
	}
	if reason := invalidReason(record, s.clockNow()); reason != "" {
		s.logger.Info("会话校验未通过", "session_id", record.ID, "user_id", record.UserID, "reason", reason)
		return Session{}, ErrSessionInvalid
	}
	if err := s.checkCurrentState(ctx, record); err != nil {
		return Session{}, err
	}
	return record.session(), nil
}

// Renew 续期：延长空闲到期并返回更新后的会话。续期绝不越过绝对到期；并发续期
// 安全（以最后一次为准），与撤销竞争时撤销优先。账户/应用/成员状态不满足时拒绝
// 续期并视为会话失效。
func (s *Service) Renew(ctx context.Context, secret string) (Session, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return Session{}, err
	}
	record, err := s.loadVerifiedRecord(ctx, secret, "renew")
	if err != nil {
		return Session{}, err
	}
	now := s.clockNow()
	if reason := invalidReason(record, now); reason != "" {
		s.logger.Info("会话续期未通过", "session_id", record.ID, "user_id", record.UserID, "reason", reason)
		return Session{}, ErrSessionInvalid
	}
	if err := s.checkCurrentState(ctx, record); err != nil {
		return Session{}, err
	}
	idleExpiresAt := now.Add(s.idleTimeout)
	if idleExpiresAt.After(record.AbsoluteExpiresAt) {
		idleExpiresAt = record.AbsoluteExpiresAt
	}
	updated, changed, err := s.store.Touch(ctx, TouchCondition{
		ID:            record.ID,
		Now:           now,
		IdleExpiresAt: idleExpiresAt,
	})
	if err != nil {
		return Session{}, s.storeFailure(ctx, "续期会话", err)
	}
	if !changed {
		s.logger.Info("会话续期冲突", "session_id", record.ID, "user_id", record.UserID, "reason", "revoked_or_expired")
		return Session{}, ErrSessionInvalid
	}
	s.logger.Info("会话已续期",
		"session_id", updated.ID,
		"user_id", updated.UserID,
		"idle_expires_at", updated.IdleExpiresAt,
		"absolute_expires_at", updated.AbsoluteExpiresAt,
	)
	return updated.session(), nil
}

// Logout 撤销当前会话（退出）。已失效/未知会话按幂等成功处理，不泄露会话是否
// 存在；已知会话的撤销与成功审计一致提交。退出后立即无法再通过 Validate/Renew。
func (s *Service) Logout(ctx context.Context, secret string) error {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	record, err := s.loadVerifiedRecord(ctx, secret, "logout")
	if err != nil {
		if errors.Is(err, ErrSessionInvalid) {
			return nil
		}
		return err
	}
	if !record.RevokedAt.IsZero() {
		return nil
	}
	now := s.clockNow()
	event := audit.Event{
		Actor:   audit.Actor{Type: audit.ActorUser, ID: record.UserID},
		AppID:   record.AppID,
		Action:  string(ActionSessionRevoke),
		Target:  audit.Target{Type: "session", ID: record.ID},
		Changes: []audit.FieldChange{{Field: "revoke_reason", After: RevokeReasonLogout}},
	}
	critical := audit.CriticalRequest{
		Event:             event,
		FailureReasonCode: "session_logout_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(s.mapCriticalError(ctx, err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		_, revokeErr := s.store.Revoke(txCtx, tx, RevokeCondition{ID: record.ID, Now: now, Reason: RevokeReasonLogout})
		return revokeErr
	})
	if err != nil {
		return s.mapCriticalError(ctx, err)
	}
	s.logger.Info("会话已撤销", "session_id", record.ID, "user_id", record.UserID, "reason", RevokeReasonLogout)
	return nil
}

// RevokeAllForUser 撤销某账户的全部活动会话，返回实际撤销数量。它用于服务端
// 失效（例如管理员禁用账户、改密后的全面撤销）；调用方必须已通过可信管理授权，
// 本方法本身不做授权判断。撤销与成功审计一致提交。
func (s *Service) RevokeAllForUser(ctx context.Context, userID, reason string) (int64, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if !account.ValidUserID(userID) {
		return 0, fmt.Errorf("%w: 用户 ID 格式无效", ErrInvalidRequest)
	}
	if !validRevokeReason(reason) {
		return 0, fmt.Errorf("%w: 撤销原因码无效", ErrInvalidRequest)
	}
	now := s.clockNow()
	var revoked int64
	event := audit.Event{
		Actor:   audit.Actor{Type: audit.ActorSystem, ID: "session-service"},
		Action:  string(ActionSessionRevoke),
		Target:  audit.Target{Type: "user", ID: userID},
		Changes: []audit.FieldChange{{Field: "revoke_reason", After: reason}},
	}
	critical := audit.CriticalRequest{
		Event:             event,
		FailureReasonCode: "session_bulk_revoke_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(s.mapCriticalError(ctx, err)))
		},
	}
	err := s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		count, revokeErr := s.store.RevokeUser(txCtx, tx, RevokeUserCondition{
			UserID: userID,
			Now:    now,
			Reason: reason,
		})
		if revokeErr != nil {
			return revokeErr
		}
		revoked = count
		return nil
	})
	if err != nil {
		return 0, s.mapCriticalError(ctx, err)
	}
	s.logger.Info("账户会话已批量撤销", "user_id", userID, "reason", reason, "revoked", revoked)
	return revoked, nil
}

// AuthorizeBusiness 校验会话并要求其可访问普通业务接口。受限会话一律拒绝；
// 这是 Go API 层的统一守卫，HTTP 宿主应在业务处理器最前面调用。
func (s *Service) AuthorizeBusiness(ctx context.Context, secret string) (Session, error) {
	current, err := s.Validate(ctx, secret)
	if err != nil {
		return Session{}, err
	}
	if !current.CanAccessBusiness() {
		s.logger.Info("受限会话被拒绝访问业务接口",
			"session_id", current.ID,
			"user_id", current.UserID,
			"reason", string(current.Reason),
		)
		return Session{}, ErrRestrictedSession
	}
	return current, nil
}

// AuthorizeManagement 校验会话并要求其可访问管理接口：必须是普通会话且已完成
// 强认证。MFA 尚未实现，本步没有任何会话能通过该检查，管理访问保持拒绝。
func (s *Service) AuthorizeManagement(ctx context.Context, secret string) (Session, error) {
	current, err := s.Validate(ctx, secret)
	if err != nil {
		return Session{}, err
	}
	if !current.IsNormal() {
		s.logger.Info("受限会话被拒绝访问管理接口",
			"session_id", current.ID,
			"user_id", current.UserID,
			"reason", string(current.Reason),
		)
		return Session{}, ErrRestrictedSession
	}
	if current.StrongAuthVerifiedAt.IsZero() {
		s.logger.Info("会话缺少强认证，拒绝管理访问",
			"session_id", current.ID,
			"user_id", current.UserID,
		)
		return Session{}, ErrStrongAuthRequired
	}
	return current, nil
}

// ValidateCSRFToken 校验与会话绑定的 CSRF 令牌，签名与 internal/transport 的
// CSRFConfig.ValidateToken / 根包 CSRFValidator 一致，可直接接既有 CSRF 中间件。
//
// 它只从请求 Cookie 或 Authorization: Bearer 读取会话秘密（绝不读取 URL/查询
// 参数），验证会话秘密摘要、会话仍活动且 CSRF 令牌摘要匹配；来源（Origin/
// Referer）允许列表仍由既有 HTTP 防护中间件负责，两者不可互相替代。
func (s *Service) ValidateCSRFToken(ctx context.Context, request *http.Request, token string) error {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	secret, ok := s.SessionSecretFromRequest(request)
	if !ok {
		return ErrSessionInvalid
	}
	record, err := s.loadVerifiedRecord(ctx, secret, "csrf")
	if err != nil {
		return err
	}
	if reason := invalidReason(record, s.clockNow()); reason != "" {
		s.logger.Info("CSRF 令牌校验未通过", "session_id", record.ID, "reason", reason)
		return ErrSessionInvalid
	}
	// 与 Validate 保持同一状态语义：账户禁用/安全版本变化/应用成员失效后，
	// 未撤销的旧会话也不能继续通过 CSRF 中间件（否则中间件会放行到后续处理器）。
	if err := s.checkCurrentState(ctx, record); err != nil {
		return err
	}
	trimmed := strings.TrimSpace(token)
	if trimmed == "" || len(trimmed) > 512 {
		return ErrSessionInvalid
	}
	expected, err := s.ring.HMACDigest(record.KeyID, csrfDigestDomain, digestMessage(record.ID, trimmed))
	if err != nil {
		s.logger.Error("CSRF 令牌校验密钥不可用", "session_id", record.ID)
		return ErrSessionInvalid
	}
	if subtle.ConstantTimeCompare(expected, record.CSRFDigest) != 1 {
		s.logger.Info("CSRF 令牌不匹配", "session_id", record.ID)
		return ErrSessionInvalid
	}
	return nil
}

// Cleanup 删除过期或撤销时间早于 retention 的会话记录，返回删除数量。只应在维护
// 任务或受控管理操作中调用；retention 为 0 表示立即清理。
func (s *Service) Cleanup(ctx context.Context, retention time.Duration) (int64, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if retention < 0 || retention > MaxCleanupRetention {
		return 0, fmt.Errorf("%w: 清理保留时长必须在 0 到 %s 之间", ErrInvalidRequest, MaxCleanupRetention)
	}
	cutoff := s.clockNow().Add(-retention)
	deleted, err := s.store.DeleteExpired(ctx, cutoff)
	if err != nil {
		return 0, s.storeFailure(ctx, "清理过期会话", err)
	}
	s.logger.Info("会话过期清理完成", "deleted", deleted, "cutoff", cutoff)
	return deleted, nil
}

// loadVerifiedRecord 解析并加载会话秘密，验证 HMAC 摘要。未知会话、格式非法和
// 摘要不匹配都返回统一 ErrSessionInvalid（内部原因只写日志）；存储/密钥故障按
// fail-closed 处理。
func (s *Service) loadVerifiedRecord(ctx context.Context, secret, operation string) (Record, error) {
	id, value, ok := parseSessionSecret(secret)
	if !ok {
		s.logger.Info("会话秘密格式无效", "operation", operation)
		return Record{}, ErrSessionInvalid
	}
	record, found, err := s.store.Load(ctx, id)
	if err != nil {
		return Record{}, s.storeFailure(ctx, "读取会话", err)
	}
	if !found {
		s.logger.Info("会话不存在", "session_id", id, "operation", operation)
		return Record{}, ErrSessionInvalid
	}
	expected, err := s.ring.HMACDigest(record.KeyID, secretDigestDomain, digestMessage(record.ID, value))
	if err != nil {
		// 密钥缺失是服务内部故障，但对调用方仍必须表现为会话无效，避免暴露
		// 会话是否存在或密钥轮换细节。
		s.logger.Error("会话秘密摘要密钥不可用", "session_id", record.ID, "key_id", record.KeyID)
		return Record{}, ErrSessionInvalid
	}
	if subtle.ConstantTimeCompare(expected, record.SecretDigest) != 1 {
		s.logger.Info("会话秘密不匹配", "session_id", record.ID, "operation", operation)
		return Record{}, ErrSessionInvalid
	}
	return record, nil
}

// checkCurrentState 重新读取账户状态/安全版本与（可选）应用/成员状态，任何不一致
// 都让会话失效。它不使用任何缓存，保证禁用、改密、成员移除立即生效。
func (s *Service) checkCurrentState(ctx context.Context, record Record) error {
	state, found, err := s.store.LoadUserState(ctx, record.UserID)
	if err != nil {
		return s.storeFailure(ctx, "读取账户状态", err)
	}
	if !found || state.Status != account.StatusActive || state.SecurityVersion != record.SecurityVersion {
		s.logger.Info("会话因账户状态变化失效",
			"session_id", record.ID,
			"user_id", record.UserID,
			"reason", "account_state_changed",
		)
		return ErrSessionInvalid
	}
	if record.AppID == "" {
		return nil
	}
	membership, found, err := s.store.LoadMembership(ctx, record.AppID, record.UserID)
	if err != nil {
		return s.storeFailure(ctx, "读取应用成员状态", err)
	}
	if !found || !membership.ApplicationActive || !membership.MemberActive {
		s.logger.Info("会话因应用或成员状态变化失效",
			"session_id", record.ID,
			"user_id", record.UserID,
			"app_id", record.AppID,
			"reason", "application_membership_changed",
		)
		return ErrSessionInvalid
	}
	return nil
}

// storeFailure 把存储错误映射为对外安全的 ErrStoreUnavailable，同时保留 context
// 取消/超时语义；原始错误只写入结构化日志供内部诊断，绝不把失败包装成成功。
func (s *Service) storeFailure(ctx context.Context, operation string, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	s.logger.Warn("会话存储操作失败", "operation", operation, "error_category", "store_unavailable")
	return fmt.Errorf("%w: %s", ErrStoreUnavailable, operation)
}

// mapCriticalError 把关键事务错误映射为对外安全错误：审计不可用优先映射
// AUDIT_WRITE_FAILED，存储不可用映射 DB_UNAVAILABLE，其余按内部错误处理。
func (s *Service) mapCriticalError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, audit.ErrAuditUnavailable) {
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	}
	// 轮换失败是明确的登录失败（旧会话未确认失效），不映射为存储故障。
	if errors.Is(err, ErrRotationFailed) {
		s.logger.Info("登录轮换旧会话未生效，拒绝签发新会话", "reason", "rotation_conflict")
		return ErrRotationFailed
	}
	if errors.Is(err, ErrStoreUnavailable) {
		return err
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	s.logger.Warn("会话关键操作失败", "error_category", "session_critical_failure")
	return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
}

// invalidReason 返回会话失效原因；空字符串表示仍有效。
func invalidReason(record Record, now time.Time) string {
	switch {
	case !record.RevokedAt.IsZero():
		return "revoked"
	case !record.IdleExpiresAt.After(now):
		return "idle_expired"
	case !record.AbsoluteExpiresAt.After(now):
		return "absolute_expired"
	default:
		return ""
	}
}

// session 把持久化记录转换为对外会话快照。
func (r Record) session() Session {
	return Session{
		ID:                   r.ID,
		UserID:               r.UserID,
		AppID:                r.AppID,
		Kind:                 r.Kind,
		Reason:               r.Reason,
		SecurityVersion:      r.SecurityVersion,
		RequiredSteps:        append([]authn.Step(nil), r.RequiredSteps...),
		StrongAuthVerifiedAt: r.StrongAuthAt,
		CreatedAt:            r.CreatedAt,
		LastSeenAt:           r.LastSeenAt,
		IdleExpiresAt:        r.IdleExpiresAt,
		AbsoluteExpiresAt:    r.AbsoluteExpiresAt,
		RowVersion:           r.RowVersion,
	}
}

// sessionMaterial 是新生会话的随机材料。
type sessionMaterial struct {
	id     string
	secret string
	csrf   string
}

// newSessionMaterial 生成不可预测的会话 ID、会话秘密与 CSRF 令牌。ID 是 128 位
// 随机值，秘密与 CSRF 令牌各 256 位；全部来自注入的安全随机源。
func (s *Service) newSessionMaterial() (sessionMaterial, error) {
	idText, err := randomToken(s.random, sessionIDRandomBytes, true)
	if err != nil {
		s.logger.Error("无法生成会话 ID", "error_category", "random_source")
		return sessionMaterial{}, fmt.Errorf("%w: 无法生成会话 ID", ErrOptionsInvalid)
	}
	secret, err := randomToken(s.random, SecretSize, false)
	if err != nil {
		s.logger.Error("无法生成会话秘密", "error_category", "random_source")
		return sessionMaterial{}, fmt.Errorf("%w: 无法生成会话秘密", ErrOptionsInvalid)
	}
	csrf, err := randomToken(s.random, CSRFSecretSize, false)
	if err != nil {
		s.logger.Error("无法生成 CSRF 令牌", "error_category", "random_source")
		return sessionMaterial{}, fmt.Errorf("%w: 无法生成 CSRF 令牌", ErrOptionsInvalid)
	}
	return sessionMaterial{id: SessionIDPrefix + idText, secret: secret, csrf: csrf}, nil
}

// randomToken 从随机源读取 size 字节。hexEncoded 为 true 时输出小写十六进制（用于
// 会话 ID），否则输出 base64url 无填充文本（用于秘密）。
func randomToken(random io.Reader, size int, hexEncoded bool) (string, error) {
	buffer := make([]byte, size)
	if _, err := io.ReadFull(random, buffer); err != nil {
		return "", err
	}
	if hexEncoded {
		return hex.EncodeToString(buffer), nil
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

// digestMessage 构造摘要输入：会话 ID 与会话秘密/CSRF 令牌用 0 字节分隔并绑定，
// 防止跨会话摘要重放。
func digestMessage(id, value string) []byte {
	message := make([]byte, 0, len(id)+1+len(value))
	message = append(message, id...)
	message = append(message, 0)
	message = append(message, value...)
	return message
}

// parseSessionSecret 解析 "会话ID.秘密" 形式的 Cookie/API 值。格式非法返回 false，
// 不做任何提示，避免把格式错误和秘密不匹配做成可区分响应。
func parseSessionSecret(value string) (id, secret string, ok bool) {
	if value == "" || len(value) > maxSecretInputBytes {
		return "", "", false
	}
	id, secret, found := strings.Cut(value, secretSeparator)
	if !found || !validSessionID(id) || len(secret) != SecretTextLength {
		return "", "", false
	}
	for index := 0; index < len(secret); index++ {
		character := secret[index]
		allowed := (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_'
		if !allowed {
			return "", "", false
		}
	}
	return id, secret, true
}

// validSessionID 校验会话 ID 格式：固定前缀加 32 个十六进制字符。
func validSessionID(id string) bool {
	if len(id) != sessionIDLength || !strings.HasPrefix(id, SessionIDPrefix) {
		return false
	}
	for index := len(SessionIDPrefix); index < len(id); index++ {
		character := id[index]
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

// validAppID 校验应用 ID 的保守格式（非空、长度受限、可见 ASCII）。应用是否存在
// 与启用由存储状态检查负责。
func validAppID(appID string) bool {
	if appID == "" || len(appID) > maxAppIDBytes {
		return false
	}
	for index := 0; index < len(appID); index++ {
		if appID[index] < 0x21 || appID[index] > 0x7e {
			return false
		}
	}
	return true
}

// validRequestID 校验请求编号的保守格式（可见 ASCII、长度受限）。
func validRequestID(requestID string) bool {
	if requestID == "" || len(requestID) > maxRequestIDBytes {
		return false
	}
	for index := 0; index < len(requestID); index++ {
		if requestID[index] < 0x21 || requestID[index] > 0x7e {
			return false
		}
	}
	return true
}

// validRevokeReason 校验撤销原因码：非空、长度受限、只含可见 ASCII。
func validRevokeReason(reason string) bool {
	if reason == "" || len(reason) > maxRevokeReasonBytes {
		return false
	}
	for index := 0; index < len(reason); index++ {
		if reason[index] < 0x21 || reason[index] > 0x7e {
			return false
		}
	}
	return true
}
