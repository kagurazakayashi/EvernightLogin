package recovery

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"strconv"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/ratelimit"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// AuditRecorder 是恢复服务使用的安全审计契约；生产实现为 *audit.Recorder。
type AuditRecorder interface {
	Record(ctx context.Context, event audit.Event) error
	RecordFailure(ctx context.Context, event audit.Event) error
	ExecuteCritical(ctx context.Context, request audit.CriticalRequest, change audit.Change) error
}

// Sessions 是恢复服务依赖的会话契约；生产实现为 *session.Service（含步骤 44 新增
// 的受限恢复会话签发入口）。
type Sessions interface {
	IssueRecoverySession(ctx context.Context, request session.RecoverySessionRequest) (session.IssuedSession, error)
	Validate(ctx context.Context, secret string) (session.Session, error)
	Logout(ctx context.Context, secret string) error
	RevokeAllForUser(ctx context.Context, userID, reason string) (int64, error)
}

// Requirements 按账户真实权限返回恢复完成后必须达到的最低强度。
//
//   - root 与高权限（持有管理/敏感系统权限）账户必须返回 StrengthStrong；普通用户
//     可返回 StrengthSecondFactor。
//   - 实现必须使用可信授权数据实时计算，不能信任客户端参数。
//   - 错误视为要求不可用并 fail-closed（拒绝完成恢复）。
type Requirements interface {
	RecoveryStrength(ctx context.Context, userID string) (Strength, error)
}

// RequirementsFunc 是 Requirements 的函数适配器。
type RequirementsFunc func(ctx context.Context, userID string) (Strength, error)

// RecoveryStrength 实现 Requirements。nil 函数按 fail-closed 返回 StrengthStrong。
func (f RequirementsFunc) RecoveryStrength(ctx context.Context, userID string) (Strength, error) {
	if f == nil {
		return "", ErrRequirementsUnavail
	}
	return f(ctx, userID)
}

// FactorBindRequest 是开始绑定新安全方式的请求；AttemptID/UserID 来自可信会话。
type FactorBindRequest struct {
	UserID    string
	AttemptID string
	Method    FactorMethod
	RequestID string
}

// FactorBindStart 是新安全方式绑定开始结果。PublicData 是仅展示给当前用户的一次性
// 绑定数据（TOTP URI 或 WebAuthn publicKey 选项 JSON），不是长期秘密；它不得进入
// 日志或审计，也不应被缓存。
type FactorBindStart struct {
	Method     FactorMethod
	BindingID  string
	PublicData []byte
	ExpiresAt  time.Time
}

// FactorVerifyRequest 是完成新安全方式真实验证的请求；Response 是认证器/验证器
// 返回的原始响应（服务端必须校验，不能信任客户端“已验证”标记）。
type FactorVerifyRequest struct {
	UserID    string
	AttemptID string
	Method    FactorMethod
	BindingID string
	Response  []byte
	RequestID string
}

// FactorProof 是新因素真实验证成功后由宿主适配器返回的可信证明。适配器必须调用
// internal/totp / internal/passkey 等真实因素服务验证成功后才能构造本结构。
type FactorProof struct {
	Method       FactorMethod
	FactorRef    string
	UserVerified bool
	VerifiedAt   time.Time
}

// Valid 报告证明字段是否有界且合法；时间是否新鲜由服务判断。
func (p FactorProof) Valid() bool {
	if !p.Method.Valid() || p.FactorRef == "" || len(p.FactorRef) > MaxFactorRefBytes {
		return false
	}
	return !p.VerifiedAt.IsZero()
}

// FactorBinder 是宿主提供的真实新安全方式绑定/验证适配器。
//
// 装配约束：实现必须调用真实因素服务（TOTP 绑定确认、WebAuthn 注册验证）完成
// 验证；不得把客户端“验证成功”参数当作证明，也不得在失败/未验证时返回 FactorProof。
// 恢复流程只会把受限恢复会话对应的尝试 ID 传给本适配器，宿主必须只接受该恢复态。
type FactorBinder interface {
	BeginRebind(ctx context.Context, request FactorBindRequest) (FactorBindStart, error)
	VerifyRebind(ctx context.Context, request FactorVerifyRequest) (FactorProof, error)
}

// LegacyFactorRevocation 是恢复完成后的旧因素撤销请求：保留刚验证的新因素，撤销
// 其余旧 MFA 因素（丢失的认证器/旧 Passkey 等），由宿主按策略实现。
type LegacyFactorRevocation struct {
	UserID        string
	AttemptID     string
	KeepMethod    FactorMethod
	KeepFactorRef string
}

// FactorRevoker 是旧因素撤销适配器；nil 时恢复完成不自动撤销旧因素（装配文档必须
// 写明宿主需按策略处理），完成结果中的 LegacyFactorsRevoked=false。
type FactorRevoker interface {
	RevokeLegacyFactors(ctx context.Context, request LegacyFactorRevocation) error
}

// NotificationKind 是恢复流程安全告知类别。
type NotificationKind string

const (
	// NotificationCodesGenerated 表示恢复代码已生成/重新生成（旧组作废）。
	NotificationCodesGenerated NotificationKind = "recovery_codes_generated"
	// NotificationRecoveryStarted 表示恢复代码已被使用，进入受限恢复。
	NotificationRecoveryStarted NotificationKind = "recovery_started"
	// NotificationRecoveryCompleted 表示恢复完成、旧因素/会话撤销并需重新登录。
	NotificationRecoveryCompleted NotificationKind = "recovery_completed"
	// NotificationRecoveryCancelled 表示恢复流程被取消。
	NotificationRecoveryCancelled NotificationKind = "recovery_cancelled"
	// NotificationRecoveryFailed 表示恢复尝试因验证失败次数用尽而作废。
	NotificationRecoveryFailed NotificationKind = "recovery_failed"
)

// Notification 是一条安全告知（不含恢复代码、验证摘要或会话秘密）。
type Notification struct {
	Kind       NotificationKind
	UserID     string
	Username   string
	Event      string
	OccurredAt time.Time
}

// Notifier 发送恢复相关安全告知。生产实现见 NewMailNotifier（复用 internal/mailer
// 的告知模板，只发送到已验证邮箱）；nil 表示未装配，服务跳过告知但仍写审计。
type Notifier interface {
	Notify(ctx context.Context, notification Notification) error
}

// Options 是恢复服务的显式依赖。
type Options struct {
	// Store 是恢复持久化；必填。
	Store Store
	// Audit 是安全审计写入器；必填。恢复代码生成、使用、完成、取消的审计不可用时
	// 拒绝关键变更。
	Audit AuditRecorder
	// Keyring 提供恢复代码验证摘要密钥；必填且必须包含当前写密钥。
	Keyring *secrets.Keyring
	// Sessions 是会话契约；必填。恢复代码成功后只签发短时受限恢复会话。
	Sessions Sessions
	// Reauth 是“更新恢复代码”的近期认证收敛入口；nil 时该操作 fail-closed
	// REAUTH_REQUIRED。
	Reauth reauth.OperationRunner
	// Requirements 是恢复强度要求；nil 时按 StrengthStrong（最强要求）处理。
	Requirements Requirements
	// AuthLevels 按账户真实权限返回“更新恢复代码”所需的最低认证级别；nil 时按
	// AuthLevelStrong（fail-closed）处理。已绑定强因素/高权限账户必须返回
	// AuthLevelStrong：持有“完整会话 + 密码”不能静默重新生成恢复代码绕过 MFA。
	AuthLevels AuthLevelRequirements
	// StrongAuthMaxAge 是“近期强认证”的新鲜度窗口；0 使用 DefaultStrongAuthMaxAge，
	// 允许 MinStrongAuthMaxAge～MaxStrongAuthMaxAge。
	StrongAuthMaxAge time.Duration
	// Binder 是新安全方式绑定/验证适配器；nil 时无法完成恢复（fail-closed）。
	Binder FactorBinder
	// FactorRevoker 是完成后旧因素撤销适配器；nil 时不自动撤销旧因素。
	FactorRevoker FactorRevoker
	// Notifier 是安全告知适配器；nil 时跳过告知（审计仍完整）。
	Notifier Notifier
	// CodeCount 是每组代码数量；0 使用 DefaultCodeCount，允许 6～20。
	CodeCount int
	// AttemptTTL 是一次恢复尝试的短时有效期；0 使用 DefaultAttemptTTL，允许 5～30 分钟。
	AttemptTTL time.Duration
	// MaxAttempts 是新因素验证失败次数上限；0 使用 DefaultMaxAttempts，允许 3～10。
	MaxAttempts int
	// BeginRatePolicy 是恢复代码尝试的账户维度限流策略；零值使用
	// DefaultBeginFailureLimit/DefaultBeginFailureWindow（10 次/10 分钟）。
	// 80 位熵下不可爆破，限流主要用于降噪与防滥用；容量有硬上限。
	BeginRatePolicy ratelimit.Policy
	// Now 是可注入时钟；nil 使用 time.Now，统一截断到 UTC 毫秒。
	Now func() time.Time
	// Random 是安全随机源；nil 使用 crypto/rand.Reader。生产不得替换弱随机源。
	Random io.Reader
	// Logger 是结构化运行日志；nil 使用丢弃输出。日志不含代码/摘要/会话秘密。
	Logger *slog.Logger
}

// Service 是恢复代码与受限恢复流程服务。构造后不可变、可并发使用；它不拥有数据库
// 连接、不启动后台协程，也不自动清理过期记录（过期在读取时惰性判定并迁移状态）。
type Service struct {
	opts          Options
	codeCount     int
	attemptTTL    time.Duration
	maxAttempts   int
	strongAuthAge time.Duration
	beginLimiter  *ratelimit.Limiter
	now           func() time.Time
	random        io.Reader
	logger        *slog.Logger
}

// New 校验并构造恢复服务。缺少存储/审计/密钥环/会话或参数越界时返回 ErrOptionsInvalid；
// 不创建默认密钥、默认审计或生产替身。
func New(options Options) (*Service, error) {
	if isNilInterface(options.Store) {
		return nil, fmt.Errorf("%w: 恢复存储为空", ErrOptionsInvalid)
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
	if isNilInterface(options.Sessions) {
		return nil, fmt.Errorf("%w: 会话服务为空", ErrOptionsInvalid)
	}
	codeCount, err := validateCodeCount(options.CodeCount)
	if err != nil {
		return nil, err
	}
	attemptTTL, err := validateAttemptTTL(options.AttemptTTL)
	if err != nil {
		return nil, err
	}
	maxAttempts, err := validateMaxAttempts(options.MaxAttempts)
	if err != nil {
		return nil, err
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	random := options.Random
	if random == nil {
		random = rand.Reader
	}
	strongAuthAge := options.StrongAuthMaxAge
	if strongAuthAge == 0 {
		strongAuthAge = DefaultStrongAuthMaxAge
	}
	if strongAuthAge < MinStrongAuthMaxAge || strongAuthAge > MaxStrongAuthMaxAge {
		return nil, fmt.Errorf("%w: 强认证新鲜度窗口必须在 %s～%s 之间",
			ErrOptionsInvalid, MinStrongAuthMaxAge, MaxStrongAuthMaxAge)
	}
	beginPolicy := options.BeginRatePolicy
	if !beginPolicy.Enabled() {
		beginPolicy = ratelimit.Policy{Limit: DefaultBeginFailureLimit, Window: DefaultBeginFailureWindow}
	}
	if beginPolicy.Limit < MinBeginFailureLimit || beginPolicy.Limit > MaxBeginFailureLimit {
		return nil, fmt.Errorf("%w: 恢复尝试限流次数必须在 %d～%d 之间",
			ErrOptionsInvalid, MinBeginFailureLimit, MaxBeginFailureLimit)
	}
	if beginPolicy.Window < MinBeginFailureWindow || beginPolicy.Window > MaxBeginFailureWindow {
		return nil, fmt.Errorf("%w: 恢复尝试限流窗口必须在 %s～%s 之间",
			ErrOptionsInvalid, MinBeginFailureWindow, MaxBeginFailureWindow)
	}
	beginLimiter, err := ratelimit.New(ratelimit.Options{Policy: beginPolicy, Now: now})
	if err != nil {
		return nil, fmt.Errorf("%w: 恢复尝试限流器构造失败", ErrOptionsInvalid)
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Service{
		opts:          options,
		codeCount:     codeCount,
		attemptTTL:    attemptTTL,
		maxAttempts:   maxAttempts,
		strongAuthAge: strongAuthAge,
		beginLimiter:  beginLimiter,
		now:           now,
		random:        random,
		logger:        logger,
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

// clockNow 返回统一截断到 UTC 毫秒的当前时间。
func (s *Service) clockNow() time.Time { return s.now().UTC().Truncate(time.Millisecond) }

// requiredStrength 读取账户恢复强度要求；未注入实现时 fail-closed 为 StrengthStrong。
func (s *Service) requiredStrength(ctx context.Context, userID string) (Strength, error) {
	requirements := s.opts.Requirements
	if isNilInterface(requirements) {
		return StrengthStrong, nil
	}
	strength, err := requirements.RecoveryStrength(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrRequirementsUnavail, err)
	}
	if !strength.Valid() {
		return "", ErrRequirementsUnavail
	}
	return strength, nil
}

// requiredAuthLevel 读取“更新恢复代码”所需的最低认证级别；未注入实现时
// fail-closed 为 AuthLevelStrong（已绑定强因素/高权限部署必须注入适配器）。
func (s *Service) requiredAuthLevel(ctx context.Context, userID string) (AuthLevel, error) {
	requirements := s.opts.AuthLevels
	if isNilInterface(requirements) {
		return AuthLevelStrong, nil
	}
	level, err := requirements.RequiredLevel(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrRequirementsUnavail, err)
	}
	if !level.Valid() {
		return "", ErrRequirementsUnavail
	}
	return level, nil
}

// strongAuthRejectionReason 检查可信上下文中的近期强认证事实，返回空字符串表示
// 满足，否则返回稳定内部原因码。宿主 HTTP/会话中间件必须用 reauth.WithSignals
// 传入经服务端验证的会话事实（例如把 session.Session.StrongAuthVerifiedAt 映射为
// VerifiedAt、按会话强认证标记设置 Strength=strong、Complete=true）；未提供或
// 过旧/未来时间一律 fail-closed，绝不因“完整会话+密码”放行更新恢复代码。
func (s *Service) strongAuthRejectionReason(ctx context.Context) string {
	signals := reauth.SignalsFromContext(ctx)
	if !signals.Complete {
		return "strong_auth_incomplete"
	}
	if signals.Strength != policy.StrengthStrong {
		return "strong_auth_level_insufficient"
	}
	if signals.VerifiedAt.IsZero() {
		return "strong_auth_missing"
	}
	now := s.clockNow()
	if signals.VerifiedAt.After(now.Add(time.Minute)) {
		return "strong_auth_from_future"
	}
	if now.Sub(signals.VerifiedAt) > s.strongAuthAge {
		return "strong_auth_stale"
	}
	return ""
}

// allowedMethods 返回指定强度允许绑定的新因素方法（强认证只允许 Passkey）。
func allowedMethods(strength Strength) []FactorMethod {
	methods := make([]FactorMethod, 0, 2)
	for _, method := range []FactorMethod{MethodPasskey, MethodTOTP} {
		if strength.Allows(method) {
			methods = append(methods, method)
		}
	}
	return methods
}

// accountState 读取账户状态并对 root 做恢复流程保护：root 恢复必须走受控本地通道，
// 普通恢复代码流程不能作用于 root。
func (s *Service) accountState(ctx context.Context, userID string) (UserState, error) {
	state, found, err := s.opts.Store.UserState(ctx, userID)
	if err != nil {
		return UserState{}, ErrStoreUnavailable
	}
	if !found {
		return UserState{}, ErrAccessDenied
	}
	if state.IsRoot {
		return UserState{}, ErrRootProtected
	}
	return state, nil
}

// recordFailure 写失败审计（独立事务）；审计不可用只写运行日志，不改变拒绝结论。
func (s *Service) recordFailure(ctx context.Context, actor audit.Actor, action, targetType, targetID string,
	errorCode ErrorCode, reason string) {
	event := audit.Event{
		Actor:      actor,
		Action:     action,
		Target:     audit.Target{Type: targetType, ID: targetID},
		Outcome:    audit.OutcomeFailure,
		ErrorCode:  string(errorCode),
		ReasonCode: reason,
	}
	if err := s.opts.Audit.RecordFailure(ctx, event); err != nil {
		s.logger.Warn("恢复流程失败审计写入失败",
			"action", action, "reason", reason, "error_category", "audit_unavailable")
	}
}

// recordSuccess 写普通成功审计（不参与关键事务的辅助事件，例如会话/旧因素撤销失败）。
func (s *Service) recordSuccess(ctx context.Context, actor audit.Actor, action, targetType, targetID string,
	changes []audit.FieldChange) {
	event := audit.Event{
		Actor:   actor,
		Action:  action,
		Target:  audit.Target{Type: targetType, ID: targetID},
		Outcome: audit.OutcomeSuccess,
		Changes: changes,
	}
	if err := s.opts.Audit.Record(ctx, event); err != nil {
		s.logger.Warn("恢复流程辅助审计写入失败", "action", action, "error_category", "audit_unavailable")
	}
}

// notify 尽力发送安全告知：失败只记录日志与失败审计，不回滚已成功的关键变更。
func (s *Service) notify(ctx context.Context, notification Notification) {
	if isNilInterface(s.opts.Notifier) {
		return
	}
	notification.OccurredAt = notification.OccurredAt.UTC().Truncate(time.Millisecond)
	if err := s.opts.Notifier.Notify(ctx, notification); err != nil {
		s.logger.Warn("恢复安全告知发送失败", "kind", string(notification.Kind), "user_id", notification.UserID)
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorSystem, ID: "recovery.notifier"},
			"recovery.notification_failed", "user", notification.UserID,
			CodeMailDeliveryFailed, "delivery_failed")
	}
}

// databaseUsername 读取展示用用户名；读取失败时返回空（告知仍可发送）。
func (s *Service) databaseUsername(ctx context.Context, userID string) string {
	username, found, err := s.opts.Store.Username(ctx, userID)
	if err != nil || !found {
		return ""
	}
	return username
}

// GenerateRequest 是生成/重新生成恢复代码的请求（要求近期认证 + 敏感策略）。
type GenerateRequest struct {
	RequestID string
}

// GeneratedCodes 是新一组恢复代码的一次性结果：Codes 只在此返回一次，调用方必须
// 立即展示给当前用户，不得写入日志、URL 或普通存储。
type GeneratedCodes struct {
	Codes      []Code
	GroupID    string
	Generation int64
	CreatedAt  time.Time
}

// Generate 生成新一组恢复代码并使旧组立即失效。
//
// 要求：调用者为账户本人、账户 active 且非 root，并通过 internal/reauth 的
// “更新恢复代码”（recovery.codes.rotate）近期认证与敏感策略；未装配 reauth 时
// fail-closed REAUTH_REQUIRED。旧组作废、新组写入与成功审计在同一事务提交，并发
// 重新生成只有一个成功，旧组不会静默继续有效。
func (s *Service) Generate(ctx context.Context, caller Caller, request GenerateRequest) (GeneratedCodes, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return GeneratedCodes{}, err
	}
	if err := caller.actor.Validate(); err != nil || !caller.IsUser() {
		return GeneratedCodes{}, ErrAccessDenied
	}
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		s.recordFailure(ctx, anonymousActor(), ActionCodesGenerated, "user", caller.actor.ID,
			CodeReqInvalid, "invalid_request")
		return GeneratedCodes{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	userID := caller.actor.ID
	if _, err := s.accountState(ctx, userID); err != nil {
		s.recordFailure(ctx, caller.actor, ActionCodesGenerated, "user", userID,
			CodeOf(err), "account_not_eligible")
		return GeneratedCodes{}, err
	}
	// 已绑定强因素/高权限账户更新恢复代码必须要求近期强认证：否则“完整会话+密码”
	// 可静默重新生成恢复代码，再用“密码+新码”替代第二因素绕过 MFA。
	requiredLevel, err := s.requiredAuthLevel(ctx, userID)
	if err != nil {
		s.recordFailure(ctx, caller.actor, ActionCodesGenerated, "user", userID,
			CodeOf(err), "auth_level_unavailable")
		return GeneratedCodes{}, err
	}
	if requiredLevel == AuthLevelStrong {
		if reason := s.strongAuthRejectionReason(ctx); reason != "" {
			s.recordFailure(ctx, caller.actor, ActionCodesGenerated, "user", userID,
				CodeMFARequired, reason)
			return GeneratedCodes{}, fmt.Errorf(
				"%w: 该账户更新恢复代码需要近期强认证", ErrStrongAuthRequired)
		}
	}
	reauthResult, err := s.authorizeRotate(ctx, caller, request.RequestID)
	if err != nil {
		return GeneratedCodes{}, err
	}
	now := s.clockNow()
	oldGroup, found, err := s.opts.Store.ActiveGroup(ctx, userID)
	if err != nil {
		return GeneratedCodes{}, ErrStoreUnavailable
	}
	generation := int64(1)
	var oldGroupID string
	if found {
		generation = oldGroup.Generation + 1
		oldGroupID = oldGroup.ID
	}
	groupID, err := newDomainID(s.random, groupIDPrefix)
	if err != nil {
		return GeneratedCodes{}, err
	}
	group := Group{
		ID: groupID, UserID: userID, Generation: generation, Status: GroupActive,
		CodeCount: s.codeCount, CreatedAt: now,
	}
	codes, records, err := s.buildCodes(userID, groupID, now)
	if err != nil {
		return GeneratedCodes{}, err
	}
	keyID := s.opts.Keyring.CurrentKeyID()
	event := audit.Event{
		Actor:     caller.actor,
		Action:    ActionCodesGenerated,
		Target:    audit.Target{Type: "user", ID: userID},
		RequestID: request.RequestID,
		Changes: []audit.FieldChange{
			{Field: "group_generation", After: strconv.FormatInt(generation, 10)},
			{Field: "code_count", After: strconv.Itoa(s.codeCount)},
			{Field: "required_auth_level", After: string(requiredLevel)},
			{Field: "key_id", After: keyID},
		},
	}
	if oldGroupID != "" {
		event.Changes = append(event.Changes, audit.FieldChange{Field: "previous_group_invalidated", After: "true"})
	}
	critical := audit.CriticalRequest{
		Event:             event,
		FailureReasonCode: "recovery_codes_generate_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(s.mapStoreError(err)))
		},
	}
	committed := false
	criticalErr := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		if oldGroupID != "" {
			invalidated, invalidateErr := s.opts.Store.InvalidateGroupTx(txCtx, tx, oldGroupID, GroupSuperseded, now)
			if invalidateErr != nil {
				return invalidateErr
			}
			if !invalidated {
				// 并发重新生成已使旧组失效：本次不覆盖对方结果，整体回滚。
				return ErrConcurrentRotation
			}
		}
		if insertErr := s.opts.Store.InsertGroupTx(txCtx, tx, group); insertErr != nil {
			return insertErr
		}
		if insertErr := s.opts.Store.InsertCodesTx(txCtx, tx, records); insertErr != nil {
			return insertErr
		}
		committed = true
		return nil
	})
	if criticalErr != nil || !committed {
		if errors.Is(criticalErr, ErrConcurrentRotation) {
			return GeneratedCodes{}, ErrConcurrentRotation
		}
		return GeneratedCodes{}, s.mapStoreError(criticalErr)
	}
	s.logger.Info("恢复代码已生成", "user_id", userID, "generation", generation, "count", s.codeCount)
	if reauthResult != nil && !isNilInterface(s.opts.Reauth) {
		if notifyErr := s.opts.Reauth.NotifyOutcome(ctx, *reauthResult, reauth.OutcomeSuccess); notifyErr != nil {
			s.logger.Warn("恢复代码更新告知未完成", "error", notifyErr)
		}
	}
	s.notify(ctx, Notification{
		Kind: NotificationCodesGenerated, UserID: userID,
		Username:   s.databaseUsername(ctx, userID),
		Event:      "恢复代码已重新生成，旧的一组恢复代码已立即失效。",
		OccurredAt: now,
	})
	return GeneratedCodes{Codes: codes, GroupID: groupID, Generation: generation, CreatedAt: now}, nil
}

// buildCodes 生成一组恢复代码明文与对应摘要记录（摘要绑定用户 ID；明文只用于返回）。
func (s *Service) buildCodes(userID, groupID string, now time.Time) ([]Code, []CodeRecord, error) {
	keyID := s.opts.Keyring.CurrentKeyID()
	codes := make([]Code, 0, s.codeCount)
	records := make([]CodeRecord, 0, s.codeCount)
	seen := make(map[string]struct{}, s.codeCount)
	for len(codes) < s.codeCount {
		code, err := newCode(s.random)
		if err != nil {
			return nil, nil, err
		}
		normalized, ok := normalizeCode(code.Reveal())
		if !ok {
			return nil, nil, fmt.Errorf("%w: 生成的代码格式异常", ErrOptionsInvalid)
		}
		if _, duplicate := seen[normalized]; duplicate {
			continue
		}
		seen[normalized] = struct{}{}
		codeID, err := newDomainID(s.random, codeIDPrefix)
		if err != nil {
			return nil, nil, err
		}
		digest, err := codeDigest(s.opts.Keyring, keyID, userID, normalized)
		if err != nil {
			return nil, nil, err
		}
		codes = append(codes, code)
		records = append(records, CodeRecord{
			ID: codeID, GroupID: groupID, UserID: userID,
			Digest: digest, KeyID: keyID, CreatedAt: now,
		})
	}
	return codes, records, nil
}

// authorizeRotate 执行“更新恢复代码”的近期认证与敏感策略判定；未装配 reauth 时
// fail-closed 返回 ErrReauthRequired。返回的 Result 供执行后告知使用。
func (s *Service) authorizeRotate(ctx context.Context, caller Caller, requestID string) (*reauth.Result, error) {
	if isNilInterface(s.opts.Reauth) {
		s.recordFailure(ctx, anonymousActor(), ActionCodesGenerated, "user", caller.actor.ID,
			CodeReauthRequired, "reauth_not_configured")
		return nil, ErrReauthRequired
	}
	reauthCaller, err := reauth.CallerFromActor(caller.actor)
	if err != nil {
		s.recordFailure(ctx, anonymousActor(), ActionCodesGenerated, "user", caller.actor.ID,
			CodeAccessDenied, "reauth_caller_invalid")
		return nil, ErrAccessDenied
	}
	result, err := s.opts.Reauth.Authorize(ctx, reauthCaller, reauth.Request{
		ScopeID:     scopeSystem,
		OperationID: OperationCodesRotate,
		TargetType:  "user",
		TargetID:    caller.actor.ID,
		Params: map[string]string{
			"code_count": strconv.Itoa(s.codeCount),
			"rotate":     "true",
		},
		Description: "更新恢复代码",
		RequestID:   requestID,
	})
	if err != nil {
		mapped := s.mapReauthError(err)
		s.recordFailure(ctx, anonymousActor(), ActionCodesGenerated, "user", caller.actor.ID,
			CodeOf(mapped), "reauth_denied")
		return nil, mapped
	}
	return &result, nil
}

// mapReauthError 把再次认证领域错误映射为恢复领域错误（保留 REAUTH_REQUIRED /
// MFA_REQUIRED / ACCESS_DENIED 等稳定语义，不泄露内部文本）。
func (s *Service) mapReauthError(err error) error {
	switch {
	case errors.Is(err, reauth.ErrAccessDenied):
		return ErrAccessDenied
	case errors.Is(err, reauth.ErrMFARequired):
		return ErrMFARequired
	case errors.Is(err, reauth.ErrPolicyUnavailable):
		return ErrPolicyUnavailable
	case errors.Is(err, reauth.ErrStoreUnavailable):
		return ErrStoreUnavailable
	case errors.Is(err, reauth.ErrAuditUnavailable):
		return ErrAuditUnavailable
	case errors.Is(err, reauth.ErrRateLimited):
		return ErrRateLimited
	default:
		return ErrReauthRequired
	}
}

// mapStoreError 把存储/审计事务错误映射为稳定领域错误。
func (s *Service) mapStoreError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrAuditUnavailable), errors.Is(err, audit.ErrAuditUnavailable):
		return ErrAuditUnavailable
	case errors.Is(err, ErrConcurrentRotation), errors.Is(err, ErrAttemptInProgress):
		return err
	case errors.Is(err, ErrStoreUnavailable):
		return ErrStoreUnavailable
	default:
		return ErrStoreUnavailable
	}
}

// anonymousActor 返回匿名审计身份（拒绝路径不能伪造用户身份）。
func anonymousActor() audit.Actor { return audit.Actor{Type: audit.ActorAnonymous} }

// Inventory 是账户恢复代码的只读概览（不含代码、摘要或秘密）。
type Inventory struct {
	HasActiveGroup bool
	GroupID        string
	Generation     int64
	CodesRemaining int
	CreatedAt      time.Time
}

// Inventory 返回当前账户恢复代码组的只读概览；需要完整（非受限）会话的宿主先行
// 校验，本方法只校验调用者身份，不签发/不消费任何东西。
func (s *Service) Inventory(ctx context.Context, caller Caller) (Inventory, error) {
	ctx = normalizeContext(ctx)
	if err := caller.actor.Validate(); err != nil || !caller.IsUser() {
		return Inventory{}, ErrAccessDenied
	}
	group, found, err := s.opts.Store.ActiveGroup(ctx, caller.actor.ID)
	if err != nil {
		return Inventory{}, ErrStoreUnavailable
	}
	if !found {
		return Inventory{}, nil
	}
	unused, err := s.opts.Store.ListUnusedCodes(ctx, caller.actor.ID)
	if err != nil {
		return Inventory{}, ErrStoreUnavailable
	}
	return Inventory{
		HasActiveGroup: true,
		GroupID:        group.ID,
		Generation:     group.Generation,
		CodesRemaining: len(unused),
		CreatedAt:      group.CreatedAt,
	}, nil
}

// normalizeContext 把 nil ctx 当成 Background，避免调用方漏传时 panic。
func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// 编译期断言：*session.Service 满足 Sessions 契约（步骤 44 的恢复会话入口）。
var _ Sessions = (*session.Service)(nil)

// 编译期断言：*reauth.Service 满足 reauth.OperationRunner。
var _ reauth.OperationRunner = (*reauth.Service)(nil)
