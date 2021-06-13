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
	"unicode"
	"unicode/utf8"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
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
	// RevokeReasonUserRevoke 表示用户指定退出自己的其他会话或全部自己的会话。
	RevokeReasonUserRevoke = "user_revoke"
	// RevokeReasonAdminRevoke 表示管理员按授权范围强制下线。
	RevokeReasonAdminRevoke = "admin_revoke"
	// RevokeReasonAccountDisabled 表示账户禁用流程触发的服务端批量退出。
	RevokeReasonAccountDisabled = "account_disabled"
	// RevokeReasonReplacedSingleDevice 表示单设备策略下被新登录替换。
	RevokeReasonReplacedSingleDevice = "replaced_single_device"
	// RevokeReasonMaxActiveSessions 表示超过最大在线数被自动淘汰（最久未活动优先）。
	RevokeReasonMaxActiveSessions = "max_active_sessions"
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
	// StrongAuthMaxAge 是强认证事实的有效期（管理访问的强认证新鲜度窗口）；
	// 0 使用 DefaultStrongAuthMaxAge（15 分钟），允许 1 分钟～24 小时。超过窗口后
	// 既有会话的管理访问要求重新完成强认证（不是一次验证永久有效）。
	StrongAuthMaxAge time.Duration
	// RememberMeTimeout 是“记住我”登录的绝对到期期限；0 使用
	// DefaultRememberMeTimeout，必须不小于 AbsoluteTimeout 且不超过
	// MaxAbsoluteTimeout。
	RememberMeTimeout time.Duration
	// MaxActiveSessions 是同一账户允许并存的活动会话上限；0 表示不限制（默认）。
	// 数量约束在登录审计事务内用单条条件更新原子维护，不在事务外先查后写。
	MaxActiveSessions int
	// DevicePolicy 是同一账户的并发登录设备策略；空使用 DevicePolicyMultiple。
	// 单设备策略会在签发事务中先撤销该账户此前全部活动会话，再签发新会话。
	DevicePolicy DevicePolicy
	// RecoveryGate 授权签发受限恢复会话（步骤 44）。nil 表示未装配恢复代码流程，
	// 所有受限恢复会话签发一律拒绝（fail-closed）。
	RecoveryGate RecoverySessionGate
	// RecoverySessionTTL 是受限恢复会话的绝对到期期限；0 使用
	// DefaultRecoverySessionTTL，允许 MinRecoverySessionTTL～MaxRecoverySessionTTL。
	RecoverySessionTTL time.Duration
	// AllowRootRecoverySessions 允许为 root 签发受限恢复会话；默认 false。root
	// 应急恢复必须由受控本地通道处理，普通恢复代码流程不能作用于 root。
	AllowRootRecoverySessions bool
	// Authorizer 判定管理员能否在给定范围强制下线；nil 时管理强制下线一律拒绝
	// （fail-closed）。用户本人退出自己的会话不依赖它。
	Authorizer ScopeAuthorizer
	// Sensitive 是敏感操作收敛入口（步骤 39）。默认 nil 时管理访问由既有强认证
	// 闸门 fail-closed（MFA 未实现前始终拒绝）；显式 AllowLegacyWithoutSensitive
	// 才允许仅靠旧闸门。接线后管理访问额外经敏感策略判定，要求强认证而未实现时
	// 继续拒绝，不放宽。
	Sensitive SensitiveRunner
	// AllowLegacyWithoutSensitive 显式允许未接线敏感策略时仅使用旧强认证闸门。
	AllowLegacyWithoutSensitive bool
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
	store             Store
	audit             AuditRecorder
	ring              *secrets.Keyring
	idleTimeout       time.Duration
	absoluteTimeout   time.Duration
	rememberTimeout   time.Duration
	maxActive         int
	devicePolicy      DevicePolicy
	strongAuthAge     time.Duration
	authorizer        ScopeAuthorizer
	sensitive         SensitiveRunner
	allowLegacy       bool
	recoveryGate      RecoverySessionGate
	recoveryTTL       time.Duration
	allowRootRecovery bool
	cookieName        string
	cookiePolicy      CookiePolicy
	logger            *slog.Logger
	now               func() time.Time
	random            io.Reader
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
	rememberTimeout := options.RememberMeTimeout
	if rememberTimeout == 0 {
		rememberTimeout = DefaultRememberMeTimeout
	}
	// “记住我”是独立的绝对到期策略，不强制长于普通绝对期限（宿主可配置更短或
	// 更长），但必须落在与绝对期限相同的合理上下界内，避免无界或近零期限。
	if rememberTimeout < MinAbsoluteTimeout || rememberTimeout > MaxAbsoluteTimeout {
		return nil, fmt.Errorf("%w: 记住我期限必须在 %s 到 %s 之间",
			ErrOptionsInvalid, MinAbsoluteTimeout, MaxAbsoluteTimeout)
	}
	if options.MaxActiveSessions < 0 || options.MaxActiveSessions > MaxActiveSessionsLimit {
		return nil, fmt.Errorf("%w: 最大在线数必须在 0 到 %d 之间", ErrOptionsInvalid, MaxActiveSessionsLimit)
	}
	devicePolicy := options.DevicePolicy
	if devicePolicy == "" {
		devicePolicy = DevicePolicyMultiple
	}
	if !devicePolicy.Valid() {
		return nil, fmt.Errorf("%w: 设备策略未定义", ErrOptionsInvalid)
	}
	if devicePolicy == DevicePolicySingle && options.MaxActiveSessions > 1 {
		return nil, fmt.Errorf("%w: 单设备策略下最大在线数只能为 0 或 1", ErrOptionsInvalid)
	}
	strongAuthAge := options.StrongAuthMaxAge
	if strongAuthAge == 0 {
		strongAuthAge = DefaultStrongAuthMaxAge
	}
	if strongAuthAge < MinStrongAuthMaxAge || strongAuthAge > MaxStrongAuthMaxAge {
		return nil, fmt.Errorf("%w: 强认证有效期必须在 %s～%s 之间",
			ErrOptionsInvalid, MinStrongAuthMaxAge, MaxStrongAuthMaxAge)
	}
	recoveryTTL := options.RecoverySessionTTL
	if recoveryTTL == 0 {
		recoveryTTL = DefaultRecoverySessionTTL
	}
	if recoveryTTL < MinRecoverySessionTTL || recoveryTTL > MaxRecoverySessionTTL {
		return nil, fmt.Errorf("%w: 受限恢复会话期限必须在 %s～%s 之间",
			ErrOptionsInvalid, MinRecoverySessionTTL, MaxRecoverySessionTTL)
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
		store:             store,
		audit:             options.Audit,
		ring:              options.Keyring,
		idleTimeout:       idleTimeout,
		absoluteTimeout:   absoluteTimeout,
		rememberTimeout:   rememberTimeout,
		maxActive:         options.MaxActiveSessions,
		devicePolicy:      devicePolicy,
		strongAuthAge:     strongAuthAge,
		authorizer:        options.Authorizer,
		sensitive:         options.Sensitive,
		allowLegacy:       options.AllowLegacyWithoutSensitive,
		recoveryGate:      options.RecoveryGate,
		recoveryTTL:       recoveryTTL,
		allowRootRecovery: options.AllowRootRecoverySessions,
		cookieName:        cookieName,
		cookiePolicy:      cookiePolicy,
		logger:            logger,
		now:               now,
		random:            random,
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
	strongAuthAt    time.Time
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
	if !result.StrongAuthCompletedAt.IsZero() {
		// 强认证时间只能出现在完整、非受限认证结果中；受限结果携带该时间意味着
		// 调用方试图用未完成认证获得管理访问，直接拒绝。
		if result.Outcome != authn.OutcomeComplete || result.Restricted || len(result.RequiredSteps) != 0 {
			return authnSpec{}, fmt.Errorf("%w: 受限认证结果不得携带强认证时间", ErrInvalidRequest)
		}
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
		strongAuthAt:    result.StrongAuthCompletedAt,
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
	client := sanitizeClientInfo(request.Client)
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
	// “记住我”只延长本次会话的绝对到期，且受服务端配置上限约束；空闲到期与
	// 续期规则不变（续期永不超过绝对到期）。
	absoluteTimeout := s.absoluteTimeout
	if request.RememberMe {
		absoluteTimeout = s.rememberTimeout
	}
	absoluteExpiresAt := now.Add(absoluteTimeout)
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
		StrongAuthAt:      spec.strongAuthAt,
		RowVersion:        1,
		CreatedAt:         now,
		LastSeenAt:        now,
		IdleExpiresAt:     idleExpiresAt,
		AbsoluteExpiresAt: absoluteExpiresAt,
		RequestID:         request.RequestID,
		RememberMe:        request.RememberMe,
		ClientUserAgent:   client.UserAgent,
		ClientAddress:     client.Address,
	}
	changes := []audit.FieldChange{
		{Field: "session_kind", After: string(record.Kind)},
		{Field: "restricted_reason", After: string(record.Reason)},
		{Field: "security_version", After: strconv.FormatInt(record.SecurityVersion, 10)},
		{Field: "idle_expires_at", After: idleExpiresAt.UTC().Format(time.RFC3339)},
		{Field: "absolute_expires_at", After: absoluteExpiresAt.UTC().Format(time.RFC3339)},
		{Field: "remember_me", After: strconv.FormatBool(record.RememberMe)},
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
		// 并发数量约束在同一 IMMEDIATE 审计事务内以单条条件更新原子维护：先按
		// 策略淘汰旧会话（自动淘汰写独立审计事件），再插入新会话；任何一步失败
		// 都整体回滚，绝不出现“计数通过但实际超限”或“先签发后淘汰失败”。
		if err := s.enforceConcurrencyPolicy(txCtx, tx, record, now); err != nil {
			return err
		}
		if err := s.store.Insert(txCtx, tx, record); err != nil {
			return err
		}
		// 插入后在事务内复核数量约束：正常路径由前置淘汰保证不超限；若存储实现
		// 偏离契约（并发/策略状态异常），fail-closed 返回 ErrConcurrentLimit 并
		// 整体回滚，绝不留下超限会话。
		return s.verifyActiveQuota(txCtx, tx, record, now)
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

// IssueRecoverySession 在恢复代码被原子消费成功后签发短时受限恢复会话。
//
// 该会话的受限原因是 recovery：internal/session 自身与所有 AuthorizeBusiness /
// AuthorizeManagement 调用都会拒绝它访问普通业务与管理接口。恢复流程只允许通过
// internal/recovery 的专门接口核对状态、绑定新安全方式与取消退出。
//
// 安全约束（缺一不可）：
//   - 必须注入 RecoverySessionGate 且其对本次尝试返回 nil；未装配恢复流程时拒绝。
//   - 账户必须 active 且安全版本与第一步认证结果一致；root 默认拒绝（受控本地
//     通道未接入前不得用普通恢复代码流程恢复 root）。
//   - 期限固定为短时 RecoverySessionTTL，空闲到期不超过该期限；不绑定应用、
//     不携带强认证时间、不使用记住我；恢复流程结束后必须以正常登录重新获得完整
//     会话，本方法绝不签发普通会话。
//   - 签发与成功审计一致提交；失败审计不携带恢复代码或会话秘密。
func (s *Service) IssueRecoverySession(ctx context.Context, request RecoverySessionRequest) (IssuedSession, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return IssuedSession{}, err
	}
	if !account.ValidUserID(request.UserID) {
		return IssuedSession{}, fmt.Errorf("%w: 用户 ID 格式无效", ErrInvalidRequest)
	}
	if request.SecurityVersion <= 0 {
		return IssuedSession{}, fmt.Errorf("%w: 缺少账户安全版本", ErrInvalidRequest)
	}
	if !validRecoveryAttemptID(request.AttemptID) {
		return IssuedSession{}, fmt.Errorf("%w: 恢复尝试 ID 格式无效", ErrInvalidRequest)
	}
	if request.RequestID != "" && !validRequestID(request.RequestID) {
		return IssuedSession{}, fmt.Errorf("%w: 请求编号格式无效", ErrInvalidRequest)
	}
	if isNilInterface(s.recoveryGate) {
		s.recordRecoveryRejection(ctx, request, "recovery_gate_not_configured")
		return IssuedSession{}, ErrRecoveryNotAllowed
	}
	if err := s.recoveryGate.AuthorizeRecoverySession(ctx, request); err != nil {
		s.recordRecoveryRejection(ctx, request, "recovery_attempt_not_authorized")
		return IssuedSession{}, ErrRecoveryNotAllowed
	}
	now := s.clockNow()
	state, found, err := s.store.LoadUserState(ctx, request.UserID)
	if err != nil {
		return IssuedSession{}, s.storeFailure(ctx, "读取账户状态", err)
	}
	if !found || state.Status != account.StatusActive {
		s.recordRecoveryRejection(ctx, request, "account_not_eligible")
		return IssuedSession{}, ErrAccountNotEligible
	}
	if state.SecurityVersion != request.SecurityVersion {
		s.recordRecoveryRejection(ctx, request, "security_version_changed")
		return IssuedSession{}, ErrAccountNotEligible
	}
	if state.IsRoot && !s.allowRootRecovery {
		s.recordRecoveryRejection(ctx, request, "root_recovery_not_supported")
		return IssuedSession{}, ErrRecoveryNotAllowed
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
		s.logger.Error("无法生成恢复会话秘密摘要", "reason", "key_unavailable")
		return IssuedSession{}, fmt.Errorf("%w: 无法生成会话秘密摘要", ErrOptionsInvalid)
	}
	csrfDigest, err := s.ring.HMACDigest(keyID, csrfDigestDomain, digestMessage(material.id, material.csrf))
	if err != nil {
		s.logger.Error("无法生成恢复会话 CSRF 摘要", "reason", "key_unavailable")
		return IssuedSession{}, fmt.Errorf("%w: 无法生成 CSRF 令牌摘要", ErrOptionsInvalid)
	}
	absoluteExpiresAt := now.Add(s.recoveryTTL)
	idleExpiresAt := now.Add(s.idleTimeout)
	if idleExpiresAt.After(absoluteExpiresAt) {
		idleExpiresAt = absoluteExpiresAt
	}
	record := Record{
		ID:                material.id,
		UserID:            request.UserID,
		Kind:              KindRestricted,
		Reason:            ReasonRecovery,
		SecurityVersion:   request.SecurityVersion,
		SecretDigest:      secretDigest,
		CSRFDigest:        csrfDigest,
		KeyID:             keyID,
		RowVersion:        1,
		CreatedAt:         now,
		LastSeenAt:        now,
		IdleExpiresAt:     idleExpiresAt,
		AbsoluteExpiresAt: absoluteExpiresAt,
		RequestID:         request.RequestID,
		ClientUserAgent:   sanitizeClientInfo(request.Client).UserAgent,
		ClientAddress:     sanitizeClientInfo(request.Client).Address,
	}
	event := audit.Event{
		Actor:     audit.Actor{Type: audit.ActorUser, ID: request.UserID},
		Action:    string(ActionSessionIssue),
		Target:    audit.Target{Type: "session", ID: record.ID},
		RequestID: request.RequestID,
		Changes: []audit.FieldChange{
			{Field: "session_kind", After: string(record.Kind)},
			{Field: "restricted_reason", After: string(record.Reason)},
			{Field: "recovery_attempt_id", After: request.AttemptID},
			{Field: "security_version", After: strconv.FormatInt(record.SecurityVersion, 10)},
			{Field: "idle_expires_at", After: idleExpiresAt.UTC().Format(time.RFC3339)},
			{Field: "absolute_expires_at", After: absoluteExpiresAt.UTC().Format(time.RFC3339)},
			{Field: "short_lived", After: "true"},
		},
	}
	if existing != nil {
		event.Changes = append(event.Changes, audit.FieldChange{Field: "session_rotation", After: "previous_session_revoked"})
	}
	critical := audit.CriticalRequest{
		Event:             event,
		FailureReasonCode: "recovery_session_issue_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(s.mapCriticalError(ctx, err)))
		},
	}
	insertErr := s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		if existing != nil {
			revoked, revokeErr := s.store.Revoke(txCtx, tx, RevokeCondition{
				ID:     existing.ID,
				Now:    now,
				Reason: RevokeReasonRotated,
			})
			if revokeErr != nil {
				return revokeErr
			}
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
	s.logger.Info("受限恢复会话已签发",
		"session_id", record.ID,
		"user_id", record.UserID,
		"reason", string(record.Reason),
		"absolute_expires_at", absoluteExpiresAt,
	)
	return issued, nil
}

// recordRecoveryRejection 记录恢复会话签发被拒绝的失败审计；审计不可用只写运行
// 日志，不改变“拒绝签发”的结论，也不泄露恢复代码/尝试内容。
func (s *Service) recordRecoveryRejection(ctx context.Context, request RecoverySessionRequest, reason string) {
	event := audit.Event{
		Actor:      audit.Actor{Type: audit.ActorAnonymous},
		Action:     string(ActionSessionIssue),
		Target:     audit.Target{Type: "user", ID: request.UserID},
		Outcome:    audit.OutcomeFailure,
		ErrorCode:  string(CodeAccessDenied),
		ReasonCode: reason,
	}
	if err := s.audit.RecordFailure(ctx, event); err != nil {
		s.logger.Warn("恢复会话签发拒绝的失败审计写入失败", "reason", reason, "error_category", "audit_unavailable")
	}
	s.logger.Info("受限恢复会话签发被拒绝", "user_id", request.UserID, "reason", reason)
}

// validRecoveryAttemptID 校验恢复尝试 ID 格式：rca_ 前缀加 32 位小写十六进制。
// 该格式由 internal/recovery 固定，客户端不可构造；session 只作为装配契约校验。
func validRecoveryAttemptID(id string) bool {
	const prefix = "rca_"
	if len(id) != len(prefix)+32 || !strings.HasPrefix(id, prefix) {
		return false
	}
	for _, r := range id[len(prefix):] {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
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
// 续期并视为会话失效。受限恢复会话（ReasonRecovery）不允许续期，返回受限拒绝，
// 以保持“核对/绑定/退出”的短时边界。
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
	// 受限恢复会话是短时一次性流程会话（只允许核对/绑定/退出），不允许续期延长其
	// 生命周期；越权续期返回统一受限拒绝，恢复流程结束后必须重新正常登录。
	if record.Kind == KindRestricted && record.Reason == ReasonRecovery {
		s.logger.Info("受限恢复会话不允许续期",
			"session_id", record.ID,
			"user_id", record.UserID,
		)
		return Session{}, ErrRestrictedSession
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
	return s.revokeAllForUser(ctx, userID, reason, ActionSessionRevoke, audit.Actor{Type: audit.ActorSystem, ID: "session-service"}, "session_bulk_revoke_failed")
}

// RevokeOnAccountDisabled 是账户禁用流程触发的服务端批量退出：撤销该账户全部
// 活动会话并写独立的 account_disabled_revoke 审计动作，与管理员强制下线、用户
// 自行退出、自动淘汰互相区分。调用方必须是已授权的账户禁用流程（本方法不做
// 授权判断）；审计不可用时整体回滚、拒绝变更。
func (s *Service) RevokeOnAccountDisabled(ctx context.Context, userID string) (int64, error) {
	return s.revokeAllForUser(ctx, userID, RevokeReasonAccountDisabled, ActionSessionAccountDisabledRevoke,
		audit.Actor{Type: audit.ActorSystem, ID: "session-service"}, "session_account_disabled_revoke_failed")
}

// revokeAllForUser 是服务端批量撤销的公共实现：审计事件动作与实际操作者由调用
// 场景给出，撤销用户范围固定为全部活动会话。
func (s *Service) revokeAllForUser(ctx context.Context, userID, reason string, action Action, actor audit.Actor, failureReason string) (int64, error) {
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
		Actor:   actor,
		Action:  string(action),
		Target:  audit.Target{Type: "user", ID: userID},
		Changes: []audit.FieldChange{{Field: "revoke_reason", After: reason}},
	}
	critical := audit.CriticalRequest{
		Event:             event,
		FailureReasonCode: failureReason,
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
	s.logger.Info("账户会话已批量撤销", "user_id", userID, "reason", reason, "revoked", revoked, "action", string(action))
	return revoked, nil
}

// ListSessions 列出调用方本人当前活动会话（含当前会话），用于设备列表。它必须
// 出示仍然有效且可访问普通业务的会话秘密；列表只返回展示所需字段，不含会话
// 秘密、CSRF 令牌、验证摘要或 Cookie；Client 字段只是参考描述（UserAgent 由
// 客户端自称、Address 来自可信边界），不是可信设备身份或地理位置。
func (s *Service) ListSessions(ctx context.Context, secret string, options ListOptions) (SessionPage, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return SessionPage{}, err
	}
	current, err := s.Validate(ctx, secret)
	if err != nil {
		return SessionPage{}, err
	}
	if !current.CanAccessBusiness() {
		return SessionPage{}, ErrRestrictedSession
	}
	currentID, _, parsed := parseSessionSecret(secret)
	if !parsed {
		return SessionPage{}, ErrSessionInvalid
	}
	page, pageSize, err := normalizeListOptions(options)
	if err != nil {
		return SessionPage{}, err
	}
	result, err := s.store.ListUserSessions(ctx, UserSessionQuery{
		UserID:   current.UserID,
		Now:      s.clockNow(),
		Offset:   (page - 1) * pageSize,
		PageSize: pageSize,
	})
	if err != nil {
		return SessionPage{}, s.storeFailure(ctx, "读取设备列表", err)
	}
	summaries := make([]SessionSummary, 0, len(result.Records))
	for _, record := range result.Records {
		summaries = append(summaries, record.summary(record.ID == currentID))
	}
	consumed := int64((page-1)*pageSize + len(summaries))
	return SessionPage{
		Sessions: summaries,
		Page:     page,
		PageSize: pageSize,
		Total:    result.Total,
		HasMore:  consumed < result.Total,
	}, nil
}

// RevokeSession 让调用方退出自己名下的指定会话。目标不存在、已失效或不属于
// 调用方时按幂等成功返回 false（不泄露他人会话是否存在，也不区分“不存在”与
// “已撤销”）；只有实际撤销才返回 true 并写 session.revoke_own 审计。
func (s *Service) RevokeSession(ctx context.Context, secret, targetSessionID string) (bool, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return false, err
	}
	targetSessionID = strings.TrimSpace(targetSessionID)
	if !validSessionID(targetSessionID) {
		return false, fmt.Errorf("%w: 目标会话 ID 格式无效", ErrInvalidRequest)
	}
	current, err := s.Validate(ctx, secret)
	if err != nil {
		return false, err
	}
	if !current.CanAccessBusiness() {
		return false, ErrRestrictedSession
	}
	record, found, err := s.store.Load(ctx, targetSessionID)
	if err != nil {
		return false, s.storeFailure(ctx, "读取目标会话", err)
	}
	if !found || invalidReason(record, s.clockNow()) != "" {
		return false, nil
	}
	// 越权目标按幂等成功处理：不能通过结果差异探测其他用户的会话是否存在。
	if record.UserID != current.UserID {
		s.logger.Info("用户尝试退出非本人会话，按幂等无操作处理", "user_id", current.UserID)
		return false, nil
	}
	now := s.clockNow()
	var revoked bool
	event := audit.Event{
		Actor:   audit.Actor{Type: audit.ActorUser, ID: current.UserID},
		AppID:   record.AppID,
		Action:  string(ActionSessionRevokeOwn),
		Target:  audit.Target{Type: "session", ID: record.ID},
		Changes: []audit.FieldChange{{Field: "revoke_reason", After: RevokeReasonUserRevoke}},
	}
	critical := audit.CriticalRequest{
		Event:             event,
		FailureReasonCode: "session_revoke_own_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(s.mapCriticalError(ctx, err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		changed, revokeErr := s.store.Revoke(txCtx, tx, RevokeCondition{ID: record.ID, Now: now, Reason: RevokeReasonUserRevoke})
		if revokeErr != nil {
			return revokeErr
		}
		revoked = changed
		return nil
	})
	if err != nil {
		return false, s.mapCriticalError(ctx, err)
	}
	s.logger.Info("用户指定退出会话", "session_id", record.ID, "user_id", current.UserID, "revoked", revoked)
	return revoked, nil
}

// RevokeAllOwnSessions 让调用方退出自己的全部会话。keepCurrent 为 true 时保留
// 当前会话（“退出其他设备”），为 false 时连当前会话一起退出（“退出全部设备”）。
// 之后所有被撤销会话立即无法再通过 Validate/Renew；没有可撤销会话时幂等返回 0。
func (s *Service) RevokeAllOwnSessions(ctx context.Context, secret string, keepCurrent bool) (int64, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	current, err := s.Validate(ctx, secret)
	if err != nil {
		return 0, err
	}
	if !current.CanAccessBusiness() {
		return 0, ErrRestrictedSession
	}
	currentID, _, parsed := parseSessionSecret(secret)
	if !parsed {
		return 0, ErrSessionInvalid
	}
	now := s.clockNow()
	condition := RevokeUserCondition{
		UserID: current.UserID,
		Now:    now,
		Reason: RevokeReasonUserRevoke,
	}
	if keepCurrent {
		condition.ExceptSessionID = currentID
	}
	changes := []audit.FieldChange{
		{Field: "revoke_reason", After: RevokeReasonUserRevoke},
		{Field: "keep_current", After: strconv.FormatBool(keepCurrent)},
	}
	var revoked int64
	event := audit.Event{
		Actor:   audit.Actor{Type: audit.ActorUser, ID: current.UserID},
		Action:  string(ActionSessionRevokeOwn),
		Target:  audit.Target{Type: "user", ID: current.UserID},
		Changes: changes,
	}
	critical := audit.CriticalRequest{
		Event:             event,
		FailureReasonCode: "session_revoke_all_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(s.mapCriticalError(ctx, err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		count, revokeErr := s.store.RevokeUser(txCtx, tx, condition)
		if revokeErr != nil {
			return revokeErr
		}
		revoked = count
		return nil
	})
	if err != nil {
		return 0, s.mapCriticalError(ctx, err)
	}
	s.logger.Info("用户退出自己的会话", "user_id", current.UserID, "keep_current", keepCurrent, "revoked", revoked)
	return revoked, nil
}

// AdminRevoke 由管理员按授权范围强制下线。它要求调用方出示普通（非受限）会话，
// 再通过注入的 ScopeAuthorizer 走既有授权语义（internal/authz 的 sessions.revoke
// 权限与作用范围），不采用客户端自称的额外范围：
//   - ScopeAppID 非空时只能作用于绑定该应用的会话；其他应用或全局会话按幂等
//     无操作处理，绝不跨范围撤销。
//   - root 账户的会话与受保护目标由授权实现与服务端共同拒绝。
//   - 目标不存在、已失效或越界时返回 Revoked=0 的成功结果，不泄露他人会话是否存在。
//
// 安全顺序：先完成强认证闸门与范围级授权（此时尚未读取任何目标状态），再读取目标
// 做存在/root/范围判断；因此缺少强认证、缺少授权实现或授权拒绝时，对不存在、普通
// 与 root 目标一律返回同一个 ErrAccessDenied，不产生存在性探测差异。授权通过后
// 目标不存在按幂等成功返回 0。
//
// 审计动作固定为 session.admin_revoke 并记录真实操作者（管理员用户）；审计不可用
// 时整体回滚拒绝。本方法不宣称已撤销 OAuth 令牌或第三方业务会话，只联动身份
// 服务的当前会话。
func (s *Service) AdminRevoke(ctx context.Context, adminSecret string, request AdminRevokeRequest) (result AdminRevokeResult, returnErr error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return AdminRevokeResult{}, err
	}
	scopeAppID := strings.TrimSpace(request.ScopeAppID)
	targetUserID := strings.TrimSpace(request.TargetUserID)
	targetSessionID := strings.TrimSpace(request.TargetSessionID)
	if scopeAppID != "" && !validAppID(scopeAppID) {
		return AdminRevokeResult{}, fmt.Errorf("%w: 作用范围应用 ID 格式无效", ErrInvalidRequest)
	}
	if (targetUserID == "") == (targetSessionID == "") {
		return AdminRevokeResult{}, fmt.Errorf("%w: 必须且只能指定目标用户或目标会话之一", ErrInvalidRequest)
	}
	if targetUserID != "" && !account.ValidUserID(targetUserID) {
		return AdminRevokeResult{}, fmt.Errorf("%w: 目标用户 ID 格式无效", ErrInvalidRequest)
	}
	if targetSessionID != "" && !validSessionID(targetSessionID) {
		return AdminRevokeResult{}, fmt.Errorf("%w: 目标会话 ID 格式无效", ErrInvalidRequest)
	}
	if request.RequestID != "" && !validRequestID(request.RequestID) {
		return AdminRevokeResult{}, fmt.Errorf("%w: 请求编号格式无效", ErrInvalidRequest)
	}
	admin, err := s.Validate(ctx, adminSecret)
	if err != nil {
		return AdminRevokeResult{}, err
	}
	// 管理强制下线属于管理操作：必须完成强认证（strong_auth_verified_at_ms 非空）。
	// MFA 尚未实现，本包没有写入该字段的通道，因此默认 fail-closed 拒绝；后续管理
	// 强认证步骤接入后才会放行。先过闸门再做任何目标读取，避免存在性探测。
	if !admin.CanAccessManagement() {
		return AdminRevokeResult{}, s.denyAdminRevoke(ctx, admin, scopeAppID, targetUserID, targetSessionID, request.RequestID, "strong_auth_required")
	}
	if s.sensitive == nil && !s.allowLegacy {
		// 未装配敏感策略时默认拒绝管理操作，不静默跳过步骤 38 策略。
		return AdminRevokeResult{}, s.denyAdminRevoke(ctx, admin, scopeAppID, targetUserID, targetSessionID, request.RequestID, "sensitive_guard_missing")
	}
	var sensitiveResult reauth.Result
	if s.sensitive != nil {
		// 管理访问的敏感策略要求强认证；MFA 未实现时策略层同样 fail-closed，
		// 不因接线而放宽既有强认证要求。
		guardCaller, callerErr := reauth.CallerFromActor(audit.Actor{Type: audit.ActorUser, ID: admin.UserID})
		if callerErr != nil {
			return AdminRevokeResult{}, s.denyAdminRevoke(ctx, admin, scopeAppID, targetUserID, targetSessionID, request.RequestID, "sensitive_guard_denied")
		}
		targetType, targetID := "user", targetUserID
		if targetSessionID != "" {
			targetType, targetID = "session", targetSessionID
		}
		guarded, guardErr := s.sensitive.Authorize(ctx, guardCaller, reauth.Request{
			ScopeID: "system", OperationID: "session.management.access",
			TargetType: targetType, TargetID: targetID,
			Params:      map[string]string{"scope_app_id": scopeAppID},
			Description: "管理强制下线", RequestID: request.RequestID,
		})
		if guardErr != nil {
			return AdminRevokeResult{}, s.denyAdminRevoke(ctx, admin, scopeAppID, targetUserID, targetSessionID, request.RequestID, "sensitive_guard_denied")
		}
		sensitiveResult = guarded
		defer func() {
			if returnErr == nil && s.sensitive != nil {
				// 告知失败只记录日志，不回滚已经完成的强制下线。
				if notifyErr := s.sensitive.NotifyOutcome(ctx, sensitiveResult, reauth.OutcomeSuccess); notifyErr != nil {
					s.logger.Warn("管理强制下线安全告知未完成", "error", notifyErr)
				}
			}
		}()
	}
	if s.authorizer == nil {
		// 没有授权实现时 fail-closed：绝不把“未接线”当成管理员已获授权。
		return AdminRevokeResult{}, s.denyAdminRevoke(ctx, admin, scopeAppID, targetUserID, targetSessionID, request.RequestID, "authorizer_missing")
	}
	actor := audit.Actor{Type: audit.ActorUser, ID: admin.UserID}
	if targetSessionID != "" {
		// 目标会话所属用户未知：先做范围级授权（target 可空），授权通过后才读取
		// 目标会话，避免未授权调用方通过结果差异探测会话/用户是否存在。
		if err := s.authorizeAdmin(ctx, actor, scopeAppID, ""); err != nil {
			return AdminRevokeResult{}, s.denyAdminRevoke(ctx, admin, scopeAppID, "", targetSessionID, request.RequestID, "authorization_denied")
		}
		return s.adminRevokeSession(ctx, admin, actor, scopeAppID, targetSessionID, request.RequestID)
	}
	if err := s.authorizeAdmin(ctx, actor, scopeAppID, targetUserID); err != nil {
		return AdminRevokeResult{}, s.denyAdminRevoke(ctx, admin, scopeAppID, targetUserID, "", request.RequestID, "authorization_denied")
	}
	return s.adminRevokeUser(ctx, admin, actor, scopeAppID, targetUserID, request.RequestID)
}

// adminRevokeSession 按会话 ID 执行管理员强制下线。调用方必须已完成范围级授权与
// 强认证闸门；本函数先读取目标，再做范围/root/目标级授权判断。
func (s *Service) adminRevokeSession(ctx context.Context, admin Session, actor audit.Actor, scopeAppID, targetSessionID, requestID string) (AdminRevokeResult, error) {
	record, found, err := s.store.Load(ctx, targetSessionID)
	if err != nil {
		return AdminRevokeResult{}, s.storeFailure(ctx, "读取目标会话", err)
	}
	if !found || invalidReason(record, s.clockNow()) != "" {
		return AdminRevokeResult{}, nil
	}
	// 应用范围管理员绝不能跨应用撤销：越界按幂等无操作处理，不泄露会话存在性。
	if scopeAppID != "" && record.AppID != scopeAppID {
		return AdminRevokeResult{}, nil
	}
	state, found, err := s.store.LoadUserState(ctx, record.UserID)
	if err != nil {
		return AdminRevokeResult{}, s.storeFailure(ctx, "读取目标账户状态", err)
	}
	if !found {
		return AdminRevokeResult{}, nil
	}
	if state.IsRoot {
		return AdminRevokeResult{}, s.denyAdminRevoke(ctx, admin, scopeAppID, record.UserID, targetSessionID, requestID, "root_protected")
	}
	// 目标级授权：应用范围需要按实际目标用户追加受保护目标检查。
	if err := s.authorizeAdmin(ctx, actor, scopeAppID, record.UserID); err != nil {
		return AdminRevokeResult{}, s.denyAdminRevoke(ctx, admin, scopeAppID, record.UserID, targetSessionID, requestID, "target_authorization_denied")
	}
	now := s.clockNow()
	var revoked int64
	event := audit.Event{
		Actor:     actor,
		AppID:     scopeAppID,
		Action:    string(ActionSessionAdminRevoke),
		Target:    audit.Target{Type: "session", ID: record.ID},
		RequestID: requestID,
		Changes: []audit.FieldChange{
			{Field: "revoke_reason", After: RevokeReasonAdminRevoke},
			{Field: "scope_app_id", After: scopeAppID},
			{Field: "target_user_id", After: record.UserID},
		},
	}
	critical := audit.CriticalRequest{
		Event:             event,
		FailureReasonCode: "session_admin_revoke_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(s.mapCriticalError(ctx, err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		changed, revokeErr := s.store.Revoke(txCtx, tx, RevokeCondition{ID: record.ID, Now: now, Reason: RevokeReasonAdminRevoke})
		if revokeErr != nil {
			return revokeErr
		}
		if changed {
			revoked = 1
		}
		return nil
	})
	if err != nil {
		return AdminRevokeResult{}, s.mapCriticalError(ctx, err)
	}
	s.logger.Info("管理员强制下线会话",
		"admin_user_id", admin.UserID,
		"target_user_id", record.UserID,
		"session_id", record.ID,
		"scope_app_id", scopeAppID,
		"revoked", revoked,
	)
	return AdminRevokeResult{Revoked: revoked}, nil
}

// adminRevokeUser 按目标用户执行管理员强制下线（可限定应用范围）。调用方必须已
// 完成强认证闸门与针对该目标用户的授权检查。
func (s *Service) adminRevokeUser(ctx context.Context, admin Session, actor audit.Actor, scopeAppID, targetUserID, requestID string) (AdminRevokeResult, error) {
	state, found, err := s.store.LoadUserState(ctx, targetUserID)
	if err != nil {
		return AdminRevokeResult{}, s.storeFailure(ctx, "读取目标账户状态", err)
	}
	if !found {
		// 账户不存在时其会话随外键级联删除：按幂等成功返回。
		return AdminRevokeResult{}, nil
	}
	if state.IsRoot {
		return AdminRevokeResult{}, s.denyAdminRevoke(ctx, admin, scopeAppID, targetUserID, "", requestID, "root_protected")
	}
	now := s.clockNow()
	var revoked int64
	event := audit.Event{
		Actor:     actor,
		AppID:     scopeAppID,
		Action:    string(ActionSessionAdminRevoke),
		Target:    audit.Target{Type: "user", ID: targetUserID},
		RequestID: requestID,
		Changes: []audit.FieldChange{
			{Field: "revoke_reason", After: RevokeReasonAdminRevoke},
			{Field: "scope_app_id", After: scopeAppID},
		},
	}
	critical := audit.CriticalRequest{
		Event:             event,
		FailureReasonCode: "session_admin_revoke_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(s.mapCriticalError(ctx, err)))
		},
	}
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		count, revokeErr := s.store.RevokeUser(txCtx, tx, RevokeUserCondition{
			UserID: targetUserID,
			AppID:  scopeAppID,
			Now:    now,
			Reason: RevokeReasonAdminRevoke,
		})
		if revokeErr != nil {
			return revokeErr
		}
		revoked = count
		return nil
	})
	if err != nil {
		return AdminRevokeResult{}, s.mapCriticalError(ctx, err)
	}
	s.logger.Info("管理员强制下线用户会话",
		"admin_user_id", admin.UserID,
		"target_user_id", targetUserID,
		"scope_app_id", scopeAppID,
		"revoked", revoked,
	)
	return AdminRevokeResult{Revoked: revoked}, nil
}

// authorizeAdmin 调用注入的授权实现判定管理员范围；任何错误都按拒绝处理，不把
// 授权依赖故障解释为放行。
func (s *Service) authorizeAdmin(ctx context.Context, actor audit.Actor, scopeAppID, targetUserID string) error {
	if s.authorizer == nil {
		return ErrAccessDenied
	}
	if err := s.authorizer.AuthorizeSessionRevoke(ctx, actor, scopeAppID, targetUserID); err != nil {
		return ErrAccessDenied
	}
	return nil
}

// denyAdminRevoke 记录被拒绝的管理强制下线尝试并返回统一无权错误；失败审计写入
// 失败只写日志，不改变“拒绝”的结论。
func (s *Service) denyAdminRevoke(ctx context.Context, admin Session, scopeAppID, targetUserID, targetSessionID, requestID, reason string) error {
	event := audit.Event{
		Actor:      audit.Actor{Type: audit.ActorUser, ID: admin.UserID},
		AppID:      scopeAppID,
		Action:     string(ActionSessionAdminRevoke),
		Target:     audit.Target{Type: "user", ID: targetUserID},
		Outcome:    audit.OutcomeDenied,
		ErrorCode:  string(CodeAccessDenied),
		ReasonCode: reason,
		RequestID:  requestID,
	}
	if targetSessionID != "" {
		event.Target = audit.Target{Type: "session", ID: targetSessionID}
	}
	if err := s.audit.RecordFailure(ctx, event); err != nil {
		s.logger.Warn("管理强制下线被拒绝的失败审计写入失败", "reason", reason, "error_category", "audit_unavailable")
	}
	s.logger.Info("管理强制下线被拒绝", "admin_user_id", admin.UserID, "scope_app_id", scopeAppID, "reason", reason)
	return ErrAccessDenied
}

// verifyActiveQuota 在登录事务内复核数量约束：单设备策略上限 1，最大在线数上限
// 为配置值（0 表示不限制）。超限说明前置淘汰未按契约生效，返回 ErrConcurrentLimit
// 让整个事务回滚（fail-closed），不会出现“计数通过但实际超限”的成功登录。
func (s *Service) verifyActiveQuota(ctx context.Context, tx audit.Tx, record Record, now time.Time) error {
	limit := 0
	switch {
	case s.devicePolicy == DevicePolicySingle:
		limit = 1
	case s.maxActive > 0:
		limit = s.maxActive
	default:
		return nil
	}
	count, err := s.store.CountActiveSessions(ctx, tx, record.UserID, now)
	if err != nil {
		return err
	}
	if count > int64(limit) {
		s.logger.Warn("并发会话数量约束复核失败，拒绝签发",
			"user_id", record.UserID,
			"policy_limit", limit,
			"active_count", count,
		)
		return fmt.Errorf("%w: 活动会话 %d 超过上限 %d", ErrConcurrentLimit, count, limit)
	}
	return nil
}

// enforceConcurrencyPolicy 在登录审计事务内维护“单设备策略 / 最大在线数”约束。
//
// 原子性：调用方的审计事务是 SQLite IMMEDIATE 写事务（存储层 _txlock=immediate），
// 淘汰使用单条条件 UPDATE（RevokeUser/RevokeOldest），再插入新会话；并发登录被
// 写锁串行化，不存在“两个请求都读到未超限再各自插入”的竞态窗口。淘汰与签发在
// 同一事务提交：任何一步失败（含自动淘汰审计写入失败）都会整体回滚，不会出现
// “新会话已签发但旧会话未淘汰”或“旧会话已撤销但新会话未签发”。
func (s *Service) enforceConcurrencyPolicy(ctx context.Context, tx audit.Tx, record Record, now time.Time) error {
	var (
		revoked int64
		err     error
		reason  string
		policy  string
	)
	switch {
	case s.devicePolicy == DevicePolicySingle:
		// 单设备策略的明确替换规则：新登录胜出，先撤销该账户此前全部活动会话
		// （所有应用），再签发新会话；撤销原因标记 replaced_single_device。
		policy = string(DevicePolicySingle)
		reason = RevokeReasonReplacedSingleDevice
		revoked, err = s.store.RevokeUser(ctx, tx, RevokeUserCondition{
			UserID: record.UserID,
			Now:    now,
			Reason: reason,
		})
	case s.maxActive > 0:
		// 最大在线数：保留最近活动的 MaxActiveSessions-1 条，其余按最久未活动
		// 优先淘汰，为新会话腾出位置（插入后总数不超过上限）。
		policy = "max_active_sessions"
		reason = RevokeReasonMaxActiveSessions
		keep := s.maxActive - 1
		if keep < 0 {
			keep = 0
		}
		revoked, err = s.store.RevokeOldest(ctx, tx, RevokeOldestCondition{
			UserID: record.UserID,
			Now:    now,
			Keep:   keep,
			Reason: reason,
		})
	default:
		return nil
	}
	if err != nil {
		return err
	}
	if revoked == 0 {
		return nil
	}
	// 自动淘汰与签发同事务写独立审计动作 session.eviction，与用户主动退出、
	// 管理员强制下线、账户禁用退出互相区分。
	eviction, prepareErr := audit.PrepareEvent(audit.Event{
		Actor:     audit.Actor{Type: audit.ActorUser, ID: record.UserID},
		AppID:     record.AppID,
		Action:    string(ActionSessionEviction),
		Target:    audit.Target{Type: "user", ID: record.UserID},
		Outcome:   audit.OutcomeSuccess,
		RequestID: record.RequestID,
		Changes: []audit.FieldChange{
			{Field: "policy", After: policy},
			{Field: "revoke_reason", After: reason},
			{Field: "evicted_count", After: strconv.FormatInt(revoked, 10)},
			{Field: "trigger", After: "login"},
		},
	}, now)
	if prepareErr != nil {
		return fmt.Errorf("%w: 自动淘汰审计事件无效", ErrOptionsInvalid)
	}
	if appendErr := tx.AppendEvent(ctx, eviction); appendErr != nil {
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, appendErr)
	}
	s.logger.Info("并发登录策略自动淘汰旧会话",
		"user_id", record.UserID,
		"policy", policy,
		"revoked", revoked,
		"new_session_id", record.ID,
	)
	return nil
}

// recordRestrictedDenial 为受限**恢复**会话的越权访问写失败审计（步骤 44 要求：
// 越权必须拒绝并审计）。其他受限原因（待第二因素/待改密/初始化）是正常登录中间
// 状态，频繁访问拒绝不逐条写审计以避免噪声；恢复会话是安全敏感状态，必须留痕。
// 审计写入失败只写运行日志，绝不改变“拒绝访问”的结论。
func (s *Service) recordRestrictedDenial(ctx context.Context, current Session, operation string) {
	if current.Reason != ReasonRecovery {
		return
	}
	event := audit.Event{
		Actor:      audit.Actor{Type: audit.ActorUser, ID: current.UserID},
		Action:     string(ActionSessionRestrictedDenied),
		Target:     audit.Target{Type: "session", ID: current.ID},
		Outcome:    audit.OutcomeFailure,
		ErrorCode:  string(CodeAccessDenied),
		ReasonCode: operation,
	}
	if err := s.audit.RecordFailure(ctx, event); err != nil {
		s.logger.Warn("恢复会话越权拒绝的失败审计写入失败", "operation", operation, "error_category", "audit_unavailable")
	}
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
		s.recordRestrictedDenial(ctx, current, "business_api")
		return Session{}, ErrRestrictedSession
	}
	return current, nil
}

// AuthorizeManagement 校验会话并要求其可访问管理接口：必须是普通会话且已完成
// 强认证且在有效期内（Options.StrongAuthMaxAge，默认 15 分钟）。强认证不是一次
// 验证永久有效；过期后必须重新完成强认证（如 Passkey/安全密钥 UV 或密码+TOTP，
// 取决于策略）。
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
		s.recordRestrictedDenial(ctx, current, "management_api")
		return Session{}, ErrRestrictedSession
	}
	now := s.clockNow()
	if current.StrongAuthVerifiedAt.IsZero() ||
		current.StrongAuthVerifiedAt.After(now) ||
		now.Sub(current.StrongAuthVerifiedAt) > s.strongAuthAge {
		s.logger.Info("会话缺少有效强认证，拒绝管理访问",
			"session_id", current.ID,
			"user_id", current.UserID,
			"strong_auth_max_age", s.strongAuthAge.String(),
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
	// 数量约束复核失败是拒绝签发（登录失败），不是存储不可用。
	if errors.Is(err, ErrConcurrentLimit) {
		return err
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

// summary 把持久化记录转换为设备列表摘要；它只复制展示字段，绝不携带秘密或
// 验证摘要。
func (r Record) summary(current bool) SessionSummary {
	return SessionSummary{
		ID:                r.ID,
		AppID:             r.AppID,
		Kind:              r.Kind,
		Reason:            r.Reason,
		CreatedAt:         r.CreatedAt,
		LastSeenAt:        r.LastSeenAt,
		IdleExpiresAt:     r.IdleExpiresAt,
		AbsoluteExpiresAt: r.AbsoluteExpiresAt,
		RememberMe:        r.RememberMe,
		Current:           current,
		Client: ClientInfo{
			UserAgent: r.ClientUserAgent,
			Address:   r.ClientAddress,
		},
	}
}

// sanitizeClientInfo 清理展示用客户端描述：截断到列上限并去除控制字符；它不做
// 任何可信度提升，也不会把 User-Agent 派生为设备身份。
func sanitizeClientInfo(client ClientInfo) ClientInfo {
	return ClientInfo{
		UserAgent: sanitizeDisplayText(client.UserAgent, maxClientUserAgentBytes),
		Address:   sanitizeDisplayText(client.Address, maxClientAddressBytes),
	}
}

// sanitizeDisplayText 去除控制/格式字符，压缩连续空白，并按 UTF-8 边界截断到
// maxBytes。仅用于展示字段，不改变授权判断。
func sanitizeDisplayText(value string, maxBytes int) string {
	if value == "" || maxBytes <= 0 {
		return ""
	}
	var builder strings.Builder
	builder.Grow(min(len(value), maxBytes))
	written := 0
	pendingSpace := false
	for _, character := range value {
		if unicode.IsControl(character) || character == '\uFEFF' {
			continue
		}
		if unicode.IsSpace(character) {
			pendingSpace = written > 0
			continue
		}
		if pendingSpace {
			if written+1 > maxBytes {
				break
			}
			builder.WriteByte(' ')
			written++
			pendingSpace = false
		}
		size := utf8.RuneLen(character)
		if size < 0 {
			continue
		}
		if written+size > maxBytes {
			break
		}
		builder.WriteRune(character)
		written += size
	}
	return builder.String()
}

// normalizeListOptions 规范化分页参数：页从 1 开始、页大小在默认值与上限之间；
// 非法值回退到安全默认或拒绝，不允许构造超大偏移。
func normalizeListOptions(options ListOptions) (page, pageSize int, err error) {
	page = options.Page
	if page < 1 {
		page = 1
	}
	if page > 1_000_000 {
		return 0, 0, fmt.Errorf("%w: 页码超出允许范围", ErrInvalidRequest)
	}
	pageSize = options.PageSize
	if pageSize <= 0 {
		pageSize = DefaultListPageSize
	}
	if pageSize > MaxListPageSize {
		pageSize = MaxListPageSize
	}
	return page, pageSize, nil
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
