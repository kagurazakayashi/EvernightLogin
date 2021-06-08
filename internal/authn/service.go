package authn

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/bootstrap"
	"github.com/kagurazakayashi/EvernightLogin/internal/ratelimit"
)

// 内部诊断原因码。它们只写安全审计，不返回给匿名调用者。
const (
	reasonUnknownUser          = "unknown_user"
	reasonBadPassword          = "bad_password"
	reasonAccountDisabled      = "account_disabled"
	reasonAccountPending       = "account_pending"
	reasonAccountPendingDelete = "account_pending_delete"
	reasonPasswordNotSet       = "password_not_set"
	reasonIdentifierInvalid    = "identifier_invalid"
	reasonEmailLoginDisabled   = "email_login_disabled"
	reasonCredentialCorrupted  = "credential_corrupted"
	reasonIpLimited            = "ip_limit"
	reasonOperationLimited     = "operation_limit"
	reasonIdentifierLocked     = "identifier_locked"
	reasonLockCapacity         = "lock_capacity"
	reasonIdentifierSweep      = "identifier_sweep"
	reasonPasswordWorkBusy     = "password_work_busy"
	reasonStrongAuthUnknown    = "strong_auth_policy_unavailable"
	reasonReauthFailed         = "reauth_failed"
	reasonWeakPassword         = "weak_password"
	reasonPasswordReused       = "password_reused"
	reasonRootStateRejected    = "root_setup_state_rejected"
)

const (
	// DefaultMaxConcurrentPasswordWork 是同时执行 Argon2 派生/校验的默认并发数。
	// Argon2 按参数分配大量内存（默认 19 MiB/次，配置上限 256 MiB），HTTP 暴露后
	// 必须有硬并发上限，避免少量并发请求耗尽进程内存。
	DefaultMaxConcurrentPasswordWork = 2
	// MinMaxConcurrentPasswordWork/MaxMaxConcurrentPasswordWork 是并发上限范围。
	MinMaxConcurrentPasswordWork = 1
	MaxMaxConcurrentPasswordWork = 8
	// DefaultPasswordWorkQueueTimeout 是等待 Argon2 工作槽位的默认排队超时；超时
	// 按 fail-closed 拒绝（RATE_LIMITED），不无界排队。
	DefaultPasswordWorkQueueTimeout = 3 * time.Second
	// MinPasswordWorkQueueTimeout/MaxPasswordWorkQueueTimeout 是排队超时范围。
	MinPasswordWorkQueueTimeout = 10 * time.Millisecond
	MaxPasswordWorkQueueTimeout = 30 * time.Second
	// operationPasswordAuthenticate/operationPasswordChangeReauth 是操作维度失败预算键。
	operationPasswordAuthenticate = "password.authenticate"
	operationPasswordChangeReauth = "password.change_reauth"
)

// errPasswordWorkBusy 表示 Argon2 工作槽位排队超时；对外按 RATE_LIMITED 拒绝。
var errPasswordWorkBusy = errors.New("密码计算工作槽位繁忙")

// AuditRecorder 是认证依赖的安全审计写入契约；生产实现为 *audit.Recorder。
// 返回错误时调用方必须把操作视为失败（fail-closed），不能静默丢弃审计。
type AuditRecorder interface {
	Record(ctx context.Context, event audit.Event) error
	RecordFailure(ctx context.Context, event audit.Event) error
	ExecuteCritical(ctx context.Context, request audit.CriticalRequest, change audit.Change) error
}

// Options 是构造认证服务的显式依赖。
type Options struct {
	// Store 是认证持久化；必填。
	Store Store
	// Audit 是安全审计写入器；必填。认证成功/失败、密码写入与哈希升级都写审计，
	// 成功路径必须与审计一致提交才能返回。
	Audit AuditRecorder
	// RootInitialization 是 root 受限初始化状态存储（bootstrap.Store 的子集）；
	// 必填。设置 root 正式密码必须复用 0008 状态机，不能绕过。
	RootInitialization RootInitializationStore
	// Params 是当前 Argon2id 参数；零值使用 DefaultParams。
	Params Params
	// PasswordPolicy 是密码长度/弱密码/历史策略；零值使用默认策略。
	PasswordPolicy PasswordPolicy
	// FailurePolicy 是失败限制策略；零值使用默认策略。
	FailurePolicy FailurePolicy
	// RateLimitPolicy 是地址/操作维度失败预算策略；零值使用默认策略。
	RateLimitPolicy RateLimitPolicy
	// RateLimitCapacity 是单个限流器最大键数；0 使用 ratelimit.DefaultMaxEntries。
	RateLimitCapacity int
	// MaxConcurrentPasswordWork 是同时执行 Argon2 派生/校验的上限；0 使用
	// DefaultMaxConcurrentPasswordWork（2），允许 1～8。
	MaxConcurrentPasswordWork int
	// PasswordWorkQueueTimeout 是等待 Argon2 工作槽位的排队超时；0 使用
	// DefaultPasswordWorkQueueTimeout（3 秒），超时按 RATE_LIMITED fail-closed。
	PasswordWorkQueueTimeout time.Duration
	// EmailLoginEnabled 是“配置允许的已验证邮箱登录”开关；默认关闭，关闭时
	// 邮箱形式标识一律按认证失败处理（不暴露开关状态）。
	EmailLoginEnabled bool
	// Now 是可注入时钟；nil 使用 time.Now。所有时间统一 UTC 毫秒。
	Now func() time.Time
	// Random 是安全随机源；nil 使用 crypto/rand.Reader。用于生成盐与 dummy 哈希。
	Random io.Reader
	// Sensitive 是敏感操作收敛入口（步骤 39）；默认 nil 时设置密码直接拒绝
	// （fail-closed）。密码修改属敏感操作，必须经步骤 38 策略判定再执行。
	Sensitive SensitiveRunner
	// AllowLegacyWithoutSensitive 显式允许未接线敏感策略时仅用当前密码复核
	// （仅供旧装配/测试过渡，默认 false）。
	AllowLegacyWithoutSensitive bool
	// Logger 是运行日志器；nil 使用丢弃输出。日志不记录密码/哈希/盐/标识明文。
	Logger *slog.Logger
	// Sleep 是渐进延迟注入点；nil 使用带 context 的 time.Sleep。测试可注入记录器
	// 验证延迟策略而不真实等待。
	Sleep func(ctx context.Context, duration time.Duration) error
}

// Service 是认证领域服务。构造后不可变（除内部并发安全的失败跟踪/限流/工作槽位
// 状态），可被多个 goroutine 并发使用；不启动后台协程、不提供 HTTP 端点、不签发
// 会话或 Token，也不缓存密码材料。
type Service struct {
	store  Store
	audit  AuditRecorder
	root   RootInitializationStore
	params Params
	policy PasswordPolicy

	delays           *delayTracker
	locks            *failureTracker
	sweep            *sweepGuard
	ipLimiter        *ratelimit.Limiter
	operationLimiter *ratelimit.Limiter

	emailLoginEnabled bool
	sensitive         SensitiveRunner
	allowLegacy       bool
	now               func() time.Time
	random            io.Reader
	logger            *slog.Logger
	sleep             func(ctx context.Context, duration time.Duration) error
	dummyHash         string
	// kdfSlots 是有界 Argon2 工作槽位信号量；nil 表示不限制（仅内部测试构造）。
	kdfSlots        chan struct{}
	kdfQueueTimeout time.Duration

	rootMu sync.Mutex
}

// New 校验依赖并构造认证服务。缺少 Store/Audit/RootInitialization 或参数越界时
// 返回 ErrOptionsInvalid，不会创建默认放行实现、默认密码或测试替身。
func New(options Options) (*Service, error) {
	if isNilInterface(options.Store) {
		return nil, fmt.Errorf("%w: 认证存储为空", ErrOptionsInvalid)
	}
	if isNilInterface(options.Audit) {
		return nil, fmt.Errorf("%w: 安全审计写入器为空", ErrOptionsInvalid)
	}
	if isNilInterface(options.RootInitialization) {
		return nil, fmt.Errorf("%w: root 初始化状态存储为空", ErrOptionsInvalid)
	}
	params := options.Params
	if params == (Params{}) {
		params = DefaultParams()
	}
	if err := params.Validate(); err != nil {
		return nil, err
	}
	policy := options.PasswordPolicy
	if policy.MinRunes == 0 && policy.MaxRunes == 0 && policy.HistoryLimit == 0 &&
		len(policy.WeakExtraWords) == 0 {
		policy = DefaultPasswordPolicy()
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	failurePolicy := options.FailurePolicy
	if failurePolicy == (FailurePolicy{}) {
		failurePolicy = DefaultFailurePolicy()
	}
	failurePolicy = failurePolicy.normalize()
	if err := failurePolicy.Validate(); err != nil {
		return nil, err
	}
	ratePolicy := options.RateLimitPolicy
	if ratePolicy == (RateLimitPolicy{}) {
		ratePolicy = DefaultRateLimitPolicy()
	}
	if err := ratePolicy.Validate(); err != nil {
		return nil, err
	}
	maxConcurrentWork := options.MaxConcurrentPasswordWork
	if maxConcurrentWork == 0 {
		maxConcurrentWork = DefaultMaxConcurrentPasswordWork
	}
	if maxConcurrentWork < MinMaxConcurrentPasswordWork || maxConcurrentWork > MaxMaxConcurrentPasswordWork {
		return nil, fmt.Errorf("%w: 密码计算并发上限必须在 %d～%d 之间",
			ErrOptionsInvalid, MinMaxConcurrentPasswordWork, MaxMaxConcurrentPasswordWork)
	}
	queueTimeout := options.PasswordWorkQueueTimeout
	if queueTimeout == 0 {
		queueTimeout = DefaultPasswordWorkQueueTimeout
	}
	if queueTimeout < MinPasswordWorkQueueTimeout || queueTimeout > MaxPasswordWorkQueueTimeout {
		return nil, fmt.Errorf("%w: 密码计算排队超时必须在 %s～%s 之间",
			ErrOptionsInvalid, MinPasswordWorkQueueTimeout, MaxPasswordWorkQueueTimeout)
	}
	capacity := options.RateLimitCapacity
	if capacity == 0 {
		capacity = ratelimit.DefaultMaxEntries
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	random := options.Random
	if random == nil {
		random = rand.Reader
	}
	logger := options.Logger
	if logger == nil {
		logger = discardLogger()
	}
	sleep := options.Sleep
	if sleep == nil {
		sleep = sleepWithContext
	}
	service := &Service{
		store:             options.Store,
		audit:             options.Audit,
		root:              options.RootInitialization,
		params:            params,
		policy:            policy,
		delays:            newDelayTracker(failurePolicy, now),
		locks:             newFailureTracker(failurePolicy, now),
		sweep:             newSweepGuard(failurePolicy, now),
		emailLoginEnabled: options.EmailLoginEnabled,
		sensitive:         options.Sensitive,
		allowLegacy:       options.AllowLegacyWithoutSensitive,
		now:               now,
		random:            random,
		logger:            logger,
		sleep:             sleep,
		kdfSlots:          make(chan struct{}, maxConcurrentWork),
		kdfQueueTimeout:   queueTimeout,
	}
	// dummy 哈希用于账户不存在/未设置密码时执行与真实校验等价的计算，减小基于
	// 响应时间的账户存在性差异。它在构造时一次性计算，参数与当前参数一致。
	dummyPlain := make([]byte, 16)
	if _, err := io.ReadFull(random, dummyPlain); err != nil {
		return nil, fmt.Errorf("%w: 无法生成 dummy 哈希材料", ErrOptionsInvalid)
	}
	dummyHash, err := HashPassword(hex.EncodeToString(dummyPlain), params, random)
	if err != nil {
		return nil, err
	}
	service.dummyHash = dummyHash
	if ratePolicy.IP.Enabled() {
		limiter, err := ratelimit.New(ratelimit.Options{Policy: ratePolicy.IP, MaxEntries: capacity})
		if err != nil {
			return nil, fmt.Errorf("%w: 地址维度限流器构造失败", ErrOptionsInvalid)
		}
		service.ipLimiter = limiter
	}
	if ratePolicy.Operation.Enabled() {
		limiter, err := ratelimit.New(ratelimit.Options{Policy: ratePolicy.Operation, MaxEntries: capacity})
		if err != nil {
			return nil, fmt.Errorf("%w: 操作维度限流器构造失败", ErrOptionsInvalid)
		}
		service.operationLimiter = limiter
	}
	return service, nil
}

// Authenticate 执行一次正式密码认证。
//
// 行为与安全不变量：
//   - Argon2 派生/校验受有界并发槽位限制，排队超时 fail-closed 返回 RATE_LIMITED，
//     避免 HTTP 暴露后并发请求耗尽内存。
//   - 地址/操作维度按失败预算限流：认证开始前用 Peek 只读判断，成功认证不消耗
//     配额；失败时才计一次失败。来源地址按 IPv4 地址或 IPv6 /64 前缀聚合。
//   - 账户维度使用渐进延迟；临时锁定按“账户 + 来源前缀”组合生效，单个来源无法
//     锁死其他来源或 root 账户的登录；单一来源对不同标识的失败数还有上限。
//   - 账户不存在、密码错误、账户不可用、未设置密码、邮箱未验证、标识格式错误的
//     公开结果完全相同（ErrAuthenticationFailed），内部审计记录原因；未知账户
//     执行等价 dummy 校验以减小时间差。
//   - 密码正确但账户要求强认证时返回 OutcomePendingSecondFactor、Restricted=true，
//     RequiredSteps 为 [StepStrongAuthSetup, StepSecondFactor]（MFA 尚未实现，需先
//     绑定强因素再完成第二因素）；要求首次改密时返回 OutcomePendingPasswordChange。
//     二者都不是完整登录，本方法绝不返回会话或 Token。
//   - 密码正确但审计写入失败时拒绝认证（fail-closed）。
//   - 登录成功且旧哈希参数弱于当前策略时，在审计事务中条件升级哈希；升级失败
//     只记录告警，不影响本次认证结论。
func (s *Service) Authenticate(ctx context.Context, request AuthenticateRequest) (AuthenticateResult, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return AuthenticateResult{}, err
	}
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		return AuthenticateResult{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if len(request.Identifier) == 0 || len(request.Identifier) > MaxIdentifierBytes {
		return AuthenticateResult{}, fmt.Errorf("%w: 登录标识长度无效", ErrInvalidRequest)
	}
	if len(request.Password) == 0 || len(request.Password) > MaxPasswordBytes {
		return AuthenticateResult{}, fmt.Errorf("%w: 密码输入长度无效", ErrInvalidRequest)
	}
	ipClass := aggregateClientAddress(request.ClientIP)
	if retryAfter, reason, limited := s.peekThrottle(ipClass, operationPasswordAuthenticate); limited {
		return AuthenticateResult{}, s.rejectRateLimited(ctx, request, "", reason, retryAfter)
	}

	identifier, identifierErr := ParseIdentifier(request.Identifier)
	var (
		user       UserRecord
		found      bool
		accountKey string
	)
	if identifierErr != nil {
		// 格式错误与“不存在账户”统一公开失败，但仍按原始标识计入失败状态。
		accountKey = "raw:" + boundedFailureKey(request.Identifier)
	} else {
		var lookupErr error
		switch identifier.Kind {
		case IdentifierUsername:
			user, found, lookupErr = s.store.FindUserByUsernameNormalized(ctx, identifier.Normalized)
		case IdentifierEmail:
			if s.emailLoginEnabled {
				user, found, lookupErr = s.store.FindUserByVerifiedEmail(ctx, identifier.Normalized)
			}
		}
		if lookupErr != nil {
			return AuthenticateResult{}, s.storeFailure(ctx, "查询登录账户", lookupErr)
		}
		if found {
			// 同一账户的用户名与邮箱失败归并到同一账户键，避免用两种标识翻倍尝试。
			accountKey = "acct:" + user.UserID
		} else {
			accountKey = "id:" + string(identifier.Kind) + ":" + identifier.Normalized
		}
	}
	lockKey := s.lockKey(accountKey, ipClass)
	if locked, retryAfter := s.locks.check(lockKey); locked {
		userID := ""
		if found {
			userID = user.UserID
		}
		return AuthenticateResult{}, s.rejectRateLimited(ctx, request, userID, reasonIdentifierLocked, retryAfter)
	}

	if identifierErr != nil {
		if err := s.verifyDummyPassword(ctx, request.Password); err != nil {
			if contextFailure(err) {
				return AuthenticateResult{}, err
			}
			return AuthenticateResult{}, s.rejectPasswordWorkBusy(ctx, request, "", err)
		}
		return AuthenticateResult{}, s.recordAuthFailure(ctx, request, ipClass, accountKey, lockKey,
			"", reasonIdentifierInvalid)
	}
	if !found {
		if err := s.verifyDummyPassword(ctx, request.Password); err != nil {
			if contextFailure(err) {
				return AuthenticateResult{}, err
			}
			return AuthenticateResult{}, s.rejectPasswordWorkBusy(ctx, request, "", err)
		}
		reason := reasonUnknownUser
		if identifier.Kind == IdentifierEmail && !s.emailLoginEnabled {
			reason = reasonEmailLoginDisabled
		}
		return AuthenticateResult{}, s.recordAuthFailure(ctx, request, ipClass, accountKey, lockKey, "", reason)
	}

	credential, credentialFound, err := s.store.GetPasswordCredential(ctx, user.UserID)
	if err != nil {
		return AuthenticateResult{}, s.storeFailure(ctx, "读取密码凭证", err)
	}
	if !credentialFound {
		if err := s.verifyDummyPassword(ctx, request.Password); err != nil {
			if contextFailure(err) {
				return AuthenticateResult{}, err
			}
			return AuthenticateResult{}, s.rejectPasswordWorkBusy(ctx, request, user.UserID, err)
		}
		return AuthenticateResult{}, s.recordAuthFailure(ctx, request, ipClass, accountKey, lockKey,
			user.UserID, reasonPasswordNotSet)
	}
	verified, err := s.verifyPassword(ctx, credential.PasswordHash, request.Password)
	if err != nil {
		if contextFailure(err) {
			return AuthenticateResult{}, err
		}
		if errors.Is(err, errPasswordWorkBusy) {
			return AuthenticateResult{}, s.rejectPasswordWorkBusy(ctx, request, user.UserID, err)
		}
		s.logger.Error("密码凭证数据损坏，拒绝登录", "user_id", user.UserID, "error", err)
		return AuthenticateResult{}, s.recordAuthFailure(ctx, request, ipClass, accountKey, lockKey,
			user.UserID, reasonCredentialCorrupted)
	}
	if !verified.Matched {
		return AuthenticateResult{}, s.recordAuthFailure(ctx, request, ipClass, accountKey, lockKey,
			user.UserID, reasonBadPassword)
	}

	// 密码正确后才判断账户状态；公开结果仍是统一失败，内部审计记录真实原因。
	if user.Status != account.StatusActive {
		reason := reasonAccountDisabled
		switch user.Status {
		case account.StatusPending:
			reason = reasonAccountPending
		case account.StatusPendingDelete:
			reason = reasonAccountPendingDelete
		}
		s.logger.Warn("密码正确但账户状态不允许登录", "user_id", user.UserID, "status", string(user.Status))
		return AuthenticateResult{}, s.recordAuthFailure(ctx, request, ipClass, accountKey, lockKey,
			user.UserID, reason)
	}

	strongAuthRequired, err := s.store.StrongAuthRequired(ctx, user.UserID)
	if err != nil {
		if auditErr := s.recordVerifyFailure(ctx, request, user.UserID, reasonStrongAuthUnknown, CodeDBUnavailable); auditErr != nil {
			return AuthenticateResult{}, errors.Join(fmt.Errorf("%w: %s", ErrStoreUnavailable, "判定强认证要求"),
				auditErr)
		}
		return AuthenticateResult{}, fmt.Errorf("%w: %s", ErrStoreUnavailable, "判定强认证要求")
	}

	// 密码验证成功：清除该账户的延迟与当前来源组合的锁定状态。
	s.delays.reset(accountKey)
	s.locks.reset(lockKey)

	upgradeApplied := s.maybeUpgradePasswordHash(ctx, user, credential, request.Password, verified.Params)

	completedAt := s.clockNow()
	result := AuthenticateResult{
		UserID:                 user.UserID,
		Username:               user.Username,
		CompletedMethods:       []Method{MethodPassword},
		CompletedAt:            completedAt,
		Restricted:             false,
		PasswordUpgradeApplied: upgradeApplied,
		SecurityVersion:        user.SecurityVersion,
	}
	switch {
	case strongAuthRequired:
		// 管理强认证（root/高权限权限持有者）要求第二因素；MFA 尚未实现，密码
		// 正确只能得到受限的“已完成第一因素”结果，绝不能当作完整登录。
		result.Outcome = OutcomePendingSecondFactor
		result.RequiredSteps = strongAuthSteps()
		result.Restricted = true
	case credential.MustChange:
		result.Outcome = OutcomePendingPasswordChange
		result.RequiredSteps = []Step{StepPasswordChange}
		result.Restricted = true
	default:
		result.Outcome = OutcomeComplete
	}
	if err := s.recordVerifySuccess(ctx, request, result); err != nil {
		return AuthenticateResult{}, err
	}
	s.logger.Info("密码认证完成",
		"user_id", user.UserID,
		"outcome", string(result.Outcome),
		"restricted", result.Restricted,
		"password_upgraded", result.PasswordUpgradeApplied,
	)
	return result, nil
}

// SetPassword 由可信管理员/系统通道，或已认证用户本人（必须提供当前密码）设置
// 或重置某个普通账户的正式密码。
//
// 边界：
//   - 普通用户只能改自己，且必须提供正确的当前密码作为再次验证；再次验证与登录
//     共用地址/操作维度失败预算、账户维度渐进延迟与“账户 + 来源”临时锁定，避免
//     接 HTTP 后成为不限速的密码校验器。目标不是自己一律 ACCESS_DENIED。
//   - root 始终拒绝：root 正式密码只能通过 SetRootPassword 的受限本地流程设置。
//   - 新密码走统一长度/弱密码/标识信息检查；当前密码与可选历史密码不能被重复
//     使用。写入与成功审计在同一事务提交，并递增 users.security_version。
//   - 不强制没有依据的定期改密；RequireChange 只用于管理员创建账户后要求首次
//     登录改密（一次性标记，成功改密后清除）。
func (s *Service) SetPassword(ctx context.Context, caller Caller, request SetPasswordRequest) (SetPasswordResult, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return SetPasswordResult{}, err
	}
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		return SetPasswordResult{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if !account.ValidUserID(request.TargetUserID) {
		return SetPasswordResult{}, fmt.Errorf("%w: 目标用户 ID 格式无效", ErrInvalidRequest)
	}
	if len(request.NewPassword) == 0 || len(request.NewPassword) > MaxPasswordBytes {
		return SetPasswordResult{}, fmt.Errorf("%w: 新密码长度无效", ErrInvalidRequest)
	}
	if err := caller.actor.Validate(); err != nil {
		return SetPasswordResult{}, ErrAccessDenied
	}
	switch caller.actorKind() {
	case audit.ActorLocalAdmin, audit.ActorSystem:
		// 受信管理/系统通道允许设置普通账户密码。
	case audit.ActorUser:
		if caller.actorID() != request.TargetUserID {
			return SetPasswordResult{}, fmt.Errorf("%w: 普通用户只能修改自己的密码", ErrAccessDenied)
		}
	default:
		return SetPasswordResult{}, ErrAccessDenied
	}

	user, found, err := s.store.FindUserByID(ctx, request.TargetUserID)
	if err != nil {
		return SetPasswordResult{}, s.storeFailure(ctx, "查询目标账户", err)
	}
	if !found {
		return SetPasswordResult{}, ErrUserNotFound
	}
	if user.IsRoot {
		return SetPasswordResult{}, fmt.Errorf("%w: root 密码只能通过本地受控初始化流程设置", ErrAccessDenied)
	}
	credential, credentialFound, err := s.store.GetPasswordCredential(ctx, user.UserID)
	if err != nil {
		return SetPasswordResult{}, s.storeFailure(ctx, "读取目标密码凭证", err)
	}

	// 普通用户自助改密必须复核当前密码（再次验证）；复核失败与登录共用限流。
	if caller.actorKind() == audit.ActorUser {
		if !credentialFound || request.CurrentPassword == "" {
			return SetPasswordResult{}, fmt.Errorf("%w: 修改密码需要提供当前密码", ErrAccessDenied)
		}
		if err := s.reauthenticatePasswordChange(ctx, caller, user, credential, request); err != nil {
			return SetPasswordResult{}, err
		}
	}

	if err := s.checkPasswordPolicy(request.NewPassword, user); err != nil {
		return SetPasswordResult{}, s.rejectedPasswordChange(ctx, caller, ActionPasswordSet,
			user.UserID, reasonWeakPassword, CodeOf(err), err)
	}
	if credentialFound {
		if err := s.checkPasswordReuse(ctx, user.UserID, credential, request.NewPassword); err != nil {
			if contextFailure(err) {
				return SetPasswordResult{}, err
			}
			if errors.Is(err, errPasswordWorkBusy) {
				return SetPasswordResult{}, s.passwordWorkFailure(ctx, caller, ActionPasswordSet, user.UserID, err)
			}
			return SetPasswordResult{}, s.rejectedPasswordChange(ctx, caller, ActionPasswordSet,
				user.UserID, reasonPasswordReused, CodeOf(err), err)
		}
	}
	sensitiveResult, guardErr := s.authorizeSensitive(ctx, caller, user.UserID, request.RequestID)
	if guardErr != nil {
		return SetPasswordResult{}, guardErr
	}
	newHash, err := s.hashPassword(ctx, request.NewPassword)
	if err != nil {
		if contextFailure(err) {
			return SetPasswordResult{}, err
		}
		if errors.Is(err, errPasswordWorkBusy) {
			return SetPasswordResult{}, s.passwordWorkFailure(ctx, caller, ActionPasswordSet, user.UserID, err)
		}
		return SetPasswordResult{}, fmt.Errorf("%w: %w", ErrOptionsInvalid, err)
	}
	now := s.clockNow()
	event := audit.Event{
		Actor:     caller.actor,
		Action:    string(ActionPasswordSet),
		Target:    audit.Target{Type: "user", ID: user.UserID},
		Outcome:   audit.OutcomeSuccess,
		RequestID: caller.requestID,
		Changes: []audit.FieldChange{
			{Field: "security_version_change", After: "password_changed"},
			{Field: "must_change", After: strconv.FormatBool(request.RequireChange)},
			{Field: "argon2_params", After: s.params.String()},
			{Field: "history_limit", After: strconv.Itoa(s.policy.HistoryLimit)},
		},
	}
	critical := audit.CriticalRequest{
		Event:             event,
		FailureReasonCode: "password_set_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	var changeResult PasswordChangeResult
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		result, setErr := s.store.SetPassword(txCtx, tx, PasswordChange{
			UserID:       user.UserID,
			PasswordHash: newHash,
			MustChange:   request.RequireChange,
			HistoryLimit: s.policy.HistoryLimit,
			Now:          now,
		})
		if setErr != nil {
			return setErr
		}
		changeResult = result
		return nil
	})
	if err != nil {
		return SetPasswordResult{}, mapCriticalError(err)
	}
	s.logger.Info("正式密码已设置",
		"user_id", user.UserID,
		"must_change", request.RequireChange,
		"argon2_params", s.params.String(),
		"security_version", changeResult.SecurityVersion,
	)
	s.notifySensitive(ctx, sensitiveResult)
	return SetPasswordResult{
		UserID:            user.UserID,
		SecurityVersion:   changeResult.SecurityVersion,
		PasswordChangedAt: changeResult.ChangedAt,
		HistoryLimit:      s.policy.HistoryLimit,
	}, nil
}

// reauthenticatePasswordChange 对普通用户自助改密的当前密码复核施加与登录相同的
// 失败限制：地址/操作维度失败预算、账户维度渐进延迟、账户+来源临时锁定与来源
// 标识扫描阈值；复核成功不消耗预算并清除失败状态。
func (s *Service) reauthenticatePasswordChange(ctx context.Context, caller Caller, user UserRecord,
	credential CredentialRecord, request SetPasswordRequest) error {
	ipClass := aggregateClientAddress(request.ClientIP)
	accountKey := "acct:" + user.UserID
	lockKey := s.lockKey(accountKey, ipClass)
	if retryAfter, reason, limited := s.peekThrottle(ipClass, operationPasswordChangeReauth); limited {
		return s.rejectedRateLimited(ctx, caller, ActionPasswordSet, user.UserID, reason, retryAfter)
	}
	if locked, retryAfter := s.locks.check(lockKey); locked {
		return s.rejectedRateLimited(ctx, caller, ActionPasswordSet, user.UserID, reasonIdentifierLocked, retryAfter)
	}
	verified, err := s.verifyPassword(ctx, credential.PasswordHash, request.CurrentPassword)
	if err != nil {
		if contextFailure(err) {
			return err
		}
		if errors.Is(err, errPasswordWorkBusy) {
			return s.passwordWorkFailure(ctx, caller, ActionPasswordSet, user.UserID, err)
		}
		return s.rejectedPasswordChange(ctx, caller, ActionPasswordSet, user.UserID,
			reasonReauthFailed, CodeAuthFailed, ErrAuthenticationFailed)
	}
	if !verified.Matched {
		failureErr := s.recordPasswordChangeFailure(ctx, caller, ipClass, accountKey, lockKey, user.UserID)
		if failureErr != nil {
			return failureErr
		}
		return s.rejectedPasswordChange(ctx, caller, ActionPasswordSet, user.UserID,
			reasonReauthFailed, CodeAuthFailed, ErrAuthenticationFailed)
	}
	s.delays.reset(accountKey)
	s.locks.reset(lockKey)
	return nil
}

// recordPasswordChangeFailure 记录一次自助改密复核失败并应用失败限制；返回的
// 错误可能已是限流错误（调用方必须原样返回，不再写重复审计）。
func (s *Service) recordPasswordChangeFailure(ctx context.Context, caller Caller, ipClass, accountKey,
	lockKey, userID string) error {
	if !s.sweep.record(ipClass, accountKey) {
		return s.rejectedRateLimited(ctx, caller, ActionPasswordSet, userID, reasonIdentifierSweep,
			s.locks.policy.Window)
	}
	if budgetErr := s.consumeFailureBudget(ipClass, operationPasswordChangeReauth); budgetErr != nil {
		var limitErr *RateLimitError
		if errors.As(budgetErr, &limitErr) {
			return s.rejectedRateLimited(ctx, caller, ActionPasswordSet, userID, limitErr.Reason, limitErr.RetryAfter)
		}
		return budgetErr
	}
	delay := s.delays.record(accountKey)
	if allowed, retryAfter, capacity := s.locks.recordFailure(lockKey); !allowed {
		reason := reasonIdentifierLocked
		if capacity {
			reason = reasonLockCapacity
		}
		return s.rejectedRateLimited(ctx, caller, ActionPasswordSet, userID, reason, retryAfter)
	}
	if delay > 0 {
		if err := s.sleep(ctx, delay); err != nil {
			return err
		}
	}
	return nil
}

// SetRootPassword 由本地受控操作者为唯一 root 设置正式密码。
//
// 它复用 0008 受限状态机与正式密码服务的同一实现：
//   - 只接受可信本地管理员 Caller；调用前必须已通过 PurposeRootSetup 一次性凭证
//     兑换进入 setup_verified（pending_setup 直接拒绝，不存在默认密码旁路）。
//   - 只在 root_initializations.state=setup_verified 时写入；ready 后配置入口关闭。
//   - 密码写入、users.security_version 递增、审计与“是否进入 ready”的条件状态
//     更新在同一审计事务提交；MarkReady 还会在事务内确认正式密码凭证确实存在。
//   - 只有“正式密码已落库且必需强认证已配置”才推进 ready。MFA 尚未实现，root
//     要求强认证，因此本步成功后状态保持 setup_verified，RequiredSteps 含强因素
//     绑定与第二因素；不签发会话、不伪造已完成的强认证。
func (s *Service) SetRootPassword(ctx context.Context, caller Caller, request SetRootPasswordRequest) (RootPasswordResult, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return RootPasswordResult{}, err
	}
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		return RootPasswordResult{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if err := caller.actor.Validate(); err != nil || caller.actorKind() != audit.ActorLocalAdmin {
		return RootPasswordResult{}, ErrAccessDenied
	}
	if len(request.NewPassword) == 0 || len(request.NewPassword) > MaxPasswordBytes {
		return RootPasswordResult{}, fmt.Errorf("%w: 新密码长度无效", ErrInvalidRequest)
	}
	if request.RootUserID != "" && !account.ValidUserID(request.RootUserID) {
		return RootPasswordResult{}, fmt.Errorf("%w: root 用户 ID 格式无效", ErrInvalidRequest)
	}

	// 与 SetRootPassword 并发执行串行化；跨进程由 MarkReady 条件更新兜底。
	s.rootMu.Lock()
	defer s.rootMu.Unlock()

	record, found, err := s.root.GetInitialization(ctx)
	if err != nil {
		return RootPasswordResult{}, s.storeFailure(ctx, "读取 root 初始化状态", err)
	}
	if !found {
		return RootPasswordResult{}, s.rejectedPasswordChange(ctx, caller, ActionRootPasswordSet,
			"", reasonRootStateRejected, CodeReqInvalid, ErrNotInitialized)
	}
	if request.RootUserID != "" && request.RootUserID != record.RootUserID {
		return RootPasswordResult{}, s.rejectedPasswordChange(ctx, caller, ActionRootPasswordSet,
			record.RootUserID, reasonRootStateRejected, CodeConflict, ErrSetupStateConflict)
	}
	switch record.State {
	case bootstrap.StateSetupVerified:
		// 允许继续配置。
	case bootstrap.StatePendingSetup:
		return RootPasswordResult{}, s.rejectedPasswordChange(ctx, caller, ActionRootPasswordSet,
			record.RootUserID, reasonRootStateRejected, CodeConflict, ErrSetupVerificationRequired)
	case bootstrap.StateReady:
		return RootPasswordResult{}, s.rejectedPasswordChange(ctx, caller, ActionRootPasswordSet,
			record.RootUserID, reasonRootStateRejected, CodeConflict, ErrSetupCompleted)
	default:
		return RootPasswordResult{}, fmt.Errorf("%w: root 初始化状态数据无效", ErrStoreUnavailable)
	}

	user, found, err := s.store.FindUserByID(ctx, record.RootUserID)
	if err != nil {
		return RootPasswordResult{}, s.storeFailure(ctx, "读取 root 账户", err)
	}
	if !found || !user.IsRoot || user.Status != account.StatusActive {
		return RootPasswordResult{}, fmt.Errorf("%w: root 账户数据无效", ErrStoreUnavailable)
	}
	credential, credentialFound, err := s.store.GetPasswordCredential(ctx, user.UserID)
	if err != nil {
		return RootPasswordResult{}, s.storeFailure(ctx, "读取 root 密码凭证", err)
	}
	if err := s.checkPasswordPolicy(request.NewPassword, user); err != nil {
		return RootPasswordResult{}, s.rejectedPasswordChange(ctx, caller, ActionRootPasswordSet,
			user.UserID, reasonWeakPassword, CodeOf(err), err)
	}
	if credentialFound {
		if err := s.checkPasswordReuse(ctx, user.UserID, credential, request.NewPassword); err != nil {
			if contextFailure(err) {
				return RootPasswordResult{}, err
			}
			if errors.Is(err, errPasswordWorkBusy) {
				return RootPasswordResult{}, s.passwordWorkFailure(ctx, caller, ActionRootPasswordSet, user.UserID, err)
			}
			return RootPasswordResult{}, s.rejectedPasswordChange(ctx, caller, ActionRootPasswordSet,
				user.UserID, reasonPasswordReused, CodeOf(err), err)
		}
	}
	newHash, err := s.hashPassword(ctx, request.NewPassword)
	if err != nil {
		if contextFailure(err) {
			return RootPasswordResult{}, err
		}
		if errors.Is(err, errPasswordWorkBusy) {
			return RootPasswordResult{}, s.passwordWorkFailure(ctx, caller, ActionRootPasswordSet, user.UserID, err)
		}
		return RootPasswordResult{}, fmt.Errorf("%w: %w", ErrOptionsInvalid, err)
	}
	strongAuthRequired, err := s.store.StrongAuthRequired(ctx, user.UserID)
	if err != nil {
		return RootPasswordResult{}, s.storeFailure(ctx, "判定 root 强认证要求", err)
	}
	readyEligible := !strongAuthRequired
	finalState := bootstrap.StateSetupVerified
	if readyEligible {
		finalState = bootstrap.StateReady
	}
	now := s.clockNow()
	event := audit.Event{
		Actor:     caller.actor,
		Action:    string(ActionRootPasswordSet),
		Target:    audit.Target{Type: "user", ID: user.UserID},
		Outcome:   audit.OutcomeSuccess,
		RequestID: caller.requestID,
		Changes: []audit.FieldChange{
			{Field: "root_state", Before: string(record.State), After: string(finalState)},
			{Field: "security_version_change", After: "password_changed"},
			{Field: "argon2_params", After: s.params.String()},
			{Field: "strong_auth_required", After: strconv.FormatBool(strongAuthRequired)},
		},
	}
	critical := audit.CriticalRequest{
		Event:             event,
		FailureReasonCode: "root_password_set_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	var changeResult PasswordChangeResult
	err = s.audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		result, setErr := s.store.SetPassword(txCtx, tx, PasswordChange{
			UserID:       user.UserID,
			PasswordHash: newHash,
			MustChange:   false,
			HistoryLimit: s.policy.HistoryLimit,
			Now:          now,
		})
		if setErr != nil {
			return setErr
		}
		changeResult = result
		if readyEligible {
			return s.root.MarkReady(txCtx, tx, bootstrap.RootReadyChange{
				RootUserID: user.UserID,
				Now:        now,
			})
		}
		return nil
	})
	if err != nil {
		return RootPasswordResult{}, mapCriticalError(err)
	}
	result := RootPasswordResult{
		RootUserID:         user.UserID,
		State:              finalState,
		StrongAuthRequired: strongAuthRequired,
		SecurityVersion:    changeResult.SecurityVersion,
		PasswordChangedAt:  changeResult.ChangedAt,
	}
	if strongAuthRequired {
		result.RequiredSteps = strongAuthSteps()
	}
	s.logger.Info("root 正式密码已设置",
		"root_user_id", user.UserID,
		"root_state", string(finalState),
		"strong_auth_required", strongAuthRequired,
		"security_version", changeResult.SecurityVersion,
	)
	return result, nil
}

// SetPasswordRequest 是设置/重置普通账户密码的参数。
type SetPasswordRequest struct {
	// TargetUserID 是目标普通账户稳定 ID；不能是 root。
	TargetUserID string
	// NewPassword 是新明文密码；只用于本次处理，不保存、不记录。
	NewPassword string
	// CurrentPassword 是普通用户自助改密时的当前密码（再次验证）；管理员/系统
	// 重置时忽略。
	CurrentPassword string
	// ClientIP 是可信客户端地址（IPv4/IPv6 文本），仅用于普通用户自助改密的
	// 再次验证限流；必须由传输层从可信边界解析后传入，不能用请求参数自称。
	ClientIP string
	// RequireChange 表示要求目标账户下次成功登录后先修改密码。
	RequireChange bool
	// RequestID 可选，写入审计用于关联查询。
	RequestID string
}

// SetPasswordResult 是密码设置结果（不含密码/哈希）。
type SetPasswordResult struct {
	// UserID 是目标用户 ID。
	UserID string
	// SecurityVersion 是递增后的安全版本；会话模块必须拒绝旧版本会话。
	SecurityVersion int64
	// PasswordChangedAt 是密码变更时间。
	PasswordChangedAt time.Time
	// HistoryLimit 是本次生效的历史限制条数（0 表示未启用）。
	HistoryLimit int
}

// SetRootPasswordRequest 是本地受控 root 正式密码设置参数。
type SetRootPasswordRequest struct {
	// RootUserID 可选；非空时必须与 0008 初始化记录绑定的 root 用户 ID 一致。
	RootUserID string
	// NewPassword 是新明文密码；只用于本次处理，不保存、不记录。
	NewPassword string
	// RequestID 可选，写入审计用于关联查询。
	RequestID string
}

// RootPasswordResult 是 root 正式密码设置结果。
type RootPasswordResult struct {
	// RootUserID 是唯一 root 账户 ID。
	RootUserID string
	// State 是写入后的受限初始化状态：正常为 setup_verified（等待强认证配置），
	// 仅当强认证要求已满足时才为 ready。
	State bootstrap.State
	// StrongAuthRequired 表示 root 仍要求强认证（MFA 实现前恒为 true）。
	StrongAuthRequired bool
	// RequiredSteps 是进入 ready 前仍必须完成的步骤。
	RequiredSteps []Step
	// SecurityVersion 是递增后的安全版本。
	SecurityVersion int64
	// PasswordChangedAt 是密码变更时间。
	PasswordChangedAt time.Time
}

// strongAuthSteps 返回“密码已正确但强认证尚未满足”时仍需完成的步骤。MFA 尚未
// 实现，账户既没有已绑定强因素（需 StrongAuthSetup），也不能完成第二因素验证，
// 因此两步都列出；会话步骤只能据此签发受限会话。
func strongAuthSteps() []Step {
	return []Step{StepStrongAuthSetup, StepSecondFactor}
}

// checkPasswordPolicy 用统一策略校验密码，并把账户展示信息作为弱密码检查标识。
func (s *Service) checkPasswordPolicy(password string, user UserRecord) error {
	return s.policy.Check(password, []string{user.Username, user.Nickname})
}

// checkPasswordReuse 检查新密码是否等于当前密码或近期历史密码。每个 Argon2
// 校验都经过有界工作槽位；槽位繁忙返回 errPasswordWorkBusy 由调用方处理。
func (s *Service) checkPasswordReuse(ctx context.Context, userID string, credential CredentialRecord, password string) error {
	current, err := s.verifyPassword(ctx, credential.PasswordHash, password)
	if err != nil {
		if errors.Is(err, errPasswordWorkBusy) {
			return err
		}
		return fmt.Errorf("%w: 当前密码凭证损坏", ErrStoreUnavailable)
	}
	if current.Matched {
		return ErrPasswordReused
	}
	if s.policy.HistoryLimit <= 0 {
		return nil
	}
	hashes, err := s.store.ListPasswordHistoryHashes(ctx, userID, s.policy.HistoryLimit)
	if err != nil {
		return err
	}
	for _, hash := range hashes {
		verified, verifyErr := s.verifyPassword(ctx, hash, password)
		if verifyErr != nil {
			if errors.Is(verifyErr, errPasswordWorkBusy) {
				return verifyErr
			}
			continue
		}
		if verified.Matched {
			return ErrPasswordReused
		}
	}
	return nil
}

// maybeUpgradePasswordHash 在密码验证成功后按当前参数条件升级旧哈希。升级是
// 尽力而为：槽位繁忙或事务失败只记告警，不改变本次认证结论。
func (s *Service) maybeUpgradePasswordHash(ctx context.Context, user UserRecord, credential CredentialRecord,
	password string, storedParams Params) bool {
	if !storedParams.WeakerThan(s.params) {
		return false
	}
	newHash, err := s.hashPassword(context.WithoutCancel(ctx), password)
	if err != nil {
		s.logger.Warn("密码哈希升级失败：无法派生新哈希", "user_id", user.UserID, "error", err)
		return false
	}
	now := s.clockNow()
	upgradeCtx := context.WithoutCancel(ctx)
	event := audit.Event{
		Actor:   audit.Actor{Type: audit.ActorUser, ID: user.UserID},
		Action:  string(ActionPasswordUpgrade),
		Target:  audit.Target{Type: "user", ID: user.UserID},
		Outcome: audit.OutcomeSuccess,
		Changes: []audit.FieldChange{
			{Field: "argon2_params_before", After: storedParams.String()},
			{Field: "argon2_params_after", After: s.params.String()},
		},
	}
	critical := audit.CriticalRequest{
		Event:             event,
		FailureReasonCode: "password_hash_upgrade_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.audit.ExecuteCritical(upgradeCtx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.store.UpgradePasswordHash(txCtx, tx, HashUpgrade{
			UserID:  user.UserID,
			OldHash: credential.PasswordHash,
			NewHash: newHash,
			Now:     now,
		})
	})
	if err != nil {
		s.logger.Warn("密码哈希升级未生效", "user_id", user.UserID, "error", err)
		return false
	}
	return true
}

// contextFailure 返回 err 是否属于 context 取消/超时。密码计算排队、校验与派生
// 路径必须原样传播上下文错误，不能把调用方主动取消伪装成 RATE_LIMITED 或凭据损坏。
func contextFailure(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// acquirePasswordWork 获取一个有界 Argon2 工作槽位；排队超过上限返回
// errPasswordWorkBusy（fail-closed），不无界排队。
func (s *Service) acquirePasswordWork(ctx context.Context) error {
	if s.kdfSlots == nil {
		return nil
	}
	select {
	case s.kdfSlots <- struct{}{}:
		return nil
	default:
	}
	timer := time.NewTimer(s.kdfQueueTimeout)
	defer timer.Stop()
	select {
	case s.kdfSlots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return errPasswordWorkBusy
	}
}

// releasePasswordWork 释放 Argon2 工作槽位。
func (s *Service) releasePasswordWork() {
	if s.kdfSlots != nil {
		<-s.kdfSlots
	}
}

// verifyPassword 在有界并发槽位内执行密码校验。
func (s *Service) verifyPassword(ctx context.Context, encoded, plain string) (VerifyResult, error) {
	if err := s.acquirePasswordWork(ctx); err != nil {
		return VerifyResult{}, err
	}
	defer s.releasePasswordWork()
	return VerifyPassword(encoded, plain)
}

// hashPassword 在有界并发槽位内派生新密码哈希。
func (s *Service) hashPassword(ctx context.Context, plain string) (string, error) {
	if err := s.acquirePasswordWork(ctx); err != nil {
		return "", err
	}
	defer s.releasePasswordWork()
	return HashPassword(plain, s.params, s.random)
}

// lockKey 组合账户键与来源前缀，形成按“账户 + 来源”的临时锁定键。
func (s *Service) lockKey(accountKey, ipClass string) string {
	return accountKey + "|" + ipClass
}

// peekThrottle 只读判断地址/操作维度失败预算是否已用尽（成功请求不消耗配额）。
func (s *Service) peekThrottle(ipClass, operationKey string) (time.Duration, string, bool) {
	if decision := s.ipLimiter.Peek("ip:" + ipClass); !decision.Allowed {
		return nonZeroRetry(decision.RetryAfter), reasonIpLimited, true
	}
	if decision := s.operationLimiter.Peek(operationKey); !decision.Allowed {
		return nonZeroRetry(decision.RetryAfter), reasonOperationLimited, true
	}
	return 0, "", false
}

// consumeFailureBudget 在失败时消耗一次地址/操作维度失败预算；超限返回限流错误。
func (s *Service) consumeFailureBudget(ipClass, operationKey string) error {
	if decision := s.ipLimiter.Allow("ip:" + ipClass); !decision.Allowed {
		return &RateLimitError{RetryAfter: nonZeroRetry(decision.RetryAfter), Reason: reasonIpLimited}
	}
	if decision := s.operationLimiter.Allow(operationKey); !decision.Allowed {
		return &RateLimitError{RetryAfter: nonZeroRetry(decision.RetryAfter), Reason: reasonOperationLimited}
	}
	return nil
}

// verifyDummyPassword 对账户不存在/未设置密码的请求执行等价 Argon2 计算，减小
// 基于响应时间的账户存在性差异。结果被丢弃，永远不放行。
func (s *Service) verifyDummyPassword(ctx context.Context, password string) error {
	if s.dummyHash == "" {
		return nil
	}
	_, err := s.verifyPassword(ctx, s.dummyHash, password)
	return err
}

// recordAuthFailure 统一处理登录失败：来源标识扫描、地址/操作失败预算、账户
// 维度渐进延迟、账户+来源临时锁定、失败审计与统一公开错误。
func (s *Service) recordAuthFailure(ctx context.Context, request AuthenticateRequest, ipClass, accountKey,
	lockKey, userID, reason string) error {
	if !s.sweep.record(ipClass, accountKey) {
		return s.rejectRateLimited(ctx, request, userID, reasonIdentifierSweep, s.locks.policy.Window)
	}
	if budgetErr := s.consumeFailureBudget(ipClass, operationPasswordAuthenticate); budgetErr != nil {
		var limitErr *RateLimitError
		if errors.As(budgetErr, &limitErr) {
			return s.rejectRateLimited(ctx, request, userID, limitErr.Reason, limitErr.RetryAfter)
		}
		return budgetErr
	}
	delay := s.delays.record(accountKey)
	if allowed, retryAfter, capacity := s.locks.recordFailure(lockKey); !allowed {
		reasonCode := reasonIdentifierLocked
		if capacity {
			reasonCode = reasonLockCapacity
		}
		return s.rejectRateLimited(ctx, request, userID, reasonCode, retryAfter)
	}
	if delay > 0 {
		if err := s.sleep(ctx, delay); err != nil {
			return err
		}
	}
	if err := s.recordVerifyFailure(ctx, request, userID, reason, CodeAuthFailed); err != nil {
		return errors.Join(ErrAuthenticationFailed, err)
	}
	return ErrAuthenticationFailed
}

// rejectPasswordWorkBusy 把 Argon2 排队超时统一记录并返回 RATE_LIMITED。
func (s *Service) rejectPasswordWorkBusy(ctx context.Context, request AuthenticateRequest, userID string, cause error) error {
	retryAfter := nonZeroRetry(s.kdfQueueTimeout)
	if retryAfter <= 0 {
		retryAfter = time.Second
	}
	event := audit.Event{
		Actor:      audit.Actor{Type: audit.ActorAnonymous},
		Action:     string(ActionPasswordVerify),
		Target:     audit.Target{Type: "user", ID: userID},
		Outcome:    audit.OutcomeFailure,
		ErrorCode:  string(CodeRateLimited),
		ReasonCode: reasonPasswordWorkBusy,
		RequestID:  request.RequestID,
	}
	limitErr := &RateLimitError{RetryAfter: retryAfter, Reason: reasonPasswordWorkBusy}
	auditErr := s.audit.RecordFailure(ctx, event)
	if auditErr != nil {
		return errors.Join(limitErr, fmt.Errorf("%w: %w", ErrAuditUnavailable, auditErr))
	}
	if cause != nil && !errors.Is(cause, errPasswordWorkBusy) {
		s.logger.Warn("密码计算排队失败", "error", cause)
	}
	return limitErr
}

// rejectedRateLimited 为密码设置类操作写限流拒绝审计（调用者身份可信）。
func (s *Service) rejectedRateLimited(ctx context.Context, caller Caller, action Action, userID, reason string,
	retryAfter time.Duration) error {
	retryAfter = nonZeroRetry(retryAfter)
	event := audit.Event{
		Actor:      caller.actor,
		Action:     string(action),
		Target:     audit.Target{Type: "user", ID: userID},
		Outcome:    audit.OutcomeFailure,
		ErrorCode:  string(CodeRateLimited),
		ReasonCode: reason,
		RequestID:  caller.requestID,
	}
	limitErr := &RateLimitError{RetryAfter: retryAfter, Reason: reason}
	if err := s.audit.RecordFailure(ctx, event); err != nil {
		return errors.Join(limitErr, fmt.Errorf("%w: %w", ErrAuditUnavailable, err))
	}
	return limitErr
}

// passwordWorkFailure 为密码设置路径的 Argon2 排队超时写审计并返回限流错误。
func (s *Service) passwordWorkFailure(ctx context.Context, caller Caller, action Action, userID string,
	cause error) error {
	retryAfter := nonZeroRetry(s.kdfQueueTimeout)
	event := audit.Event{
		Actor:      caller.actor,
		Action:     string(action),
		Target:     audit.Target{Type: "user", ID: userID},
		Outcome:    audit.OutcomeFailure,
		ErrorCode:  string(CodeRateLimited),
		ReasonCode: reasonPasswordWorkBusy,
		RequestID:  caller.requestID,
	}
	limitErr := &RateLimitError{RetryAfter: retryAfter, Reason: reasonPasswordWorkBusy}
	if err := s.audit.RecordFailure(ctx, event); err != nil {
		return errors.Join(limitErr, fmt.Errorf("%w: %w", ErrAuditUnavailable, err))
	}
	if cause != nil && !errors.Is(cause, errPasswordWorkBusy) {
		s.logger.Warn("密码计算排队失败", "error", cause)
	}
	return limitErr
}

// rejectRateLimited 写匿名限流拒绝审计并返回带等待时间的限流错误。
func (s *Service) rejectRateLimited(ctx context.Context, request AuthenticateRequest, userID, reason string,
	retryAfter time.Duration) error {
	retryAfter = nonZeroRetry(retryAfter)
	event := audit.Event{
		Actor:      audit.Actor{Type: audit.ActorAnonymous},
		Action:     string(ActionPasswordVerify),
		Target:     audit.Target{Type: "user", ID: userID},
		Outcome:    audit.OutcomeFailure,
		ErrorCode:  string(CodeRateLimited),
		ReasonCode: reason,
		RequestID:  request.RequestID,
	}
	if err := s.audit.RecordFailure(ctx, event); err != nil {
		return errors.Join(&RateLimitError{RetryAfter: retryAfter, Reason: reason},
			fmt.Errorf("%w: %w", ErrAuditUnavailable, err))
	}
	return &RateLimitError{RetryAfter: retryAfter, Reason: reason}
}

// recordVerifyFailure 写认证失败审计。审计失败时把认证失败与审计错误合并返回，
// 不静默丢弃证据。
func (s *Service) recordVerifyFailure(ctx context.Context, request AuthenticateRequest, userID, reason string,
	code ErrorCode) error {
	event := audit.Event{
		Actor:      audit.Actor{Type: audit.ActorAnonymous},
		Action:     string(ActionPasswordVerify),
		Target:     audit.Target{Type: "user", ID: userID},
		Outcome:    audit.OutcomeFailure,
		ErrorCode:  string(code),
		ReasonCode: reason,
		RequestID:  request.RequestID,
	}
	if err := s.audit.RecordFailure(ctx, event); err != nil {
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	}
	return nil
}

// recordVerifySuccess 写认证成功审计；审计不可用时拒绝返回认证结果（fail-closed）。
func (s *Service) recordVerifySuccess(ctx context.Context, request AuthenticateRequest, result AuthenticateResult) error {
	steps := make([]string, 0, len(result.RequiredSteps))
	for _, step := range result.RequiredSteps {
		steps = append(steps, string(step))
	}
	event := audit.Event{
		Actor:     audit.Actor{Type: audit.ActorUser, ID: result.UserID},
		Action:    string(ActionPasswordVerify),
		Target:    audit.Target{Type: "user", ID: result.UserID},
		Outcome:   audit.OutcomeSuccess,
		RequestID: request.RequestID,
		Changes: []audit.FieldChange{
			{Field: "auth_method", After: string(MethodPassword)},
			{Field: "authentication_outcome", After: string(result.Outcome)},
			{Field: "required_steps", After: strings.Join(steps, ",")},
			{Field: "restricted", After: strconv.FormatBool(result.Restricted)},
			{Field: "security_version", After: strconv.FormatInt(result.SecurityVersion, 10)},
		},
	}
	if err := s.audit.Record(ctx, event); err != nil {
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	}
	return nil
}

// rejectedPasswordChange 写密码设置类操作的失败审计（不伪造成功记录）；审计
// 失败时与原拒绝错误合并返回。
func (s *Service) rejectedPasswordChange(ctx context.Context, caller Caller, action Action, userID, reason string,
	code ErrorCode, cause error) error {
	event := audit.Event{
		Actor:      caller.actor,
		Action:     string(action),
		Target:     audit.Target{Type: "user", ID: userID},
		Outcome:    audit.OutcomeFailure,
		ErrorCode:  string(code),
		ReasonCode: reason,
		RequestID:  caller.requestID,
	}
	if err := s.audit.RecordFailure(ctx, event); err != nil {
		return errors.Join(cause, fmt.Errorf("%w: %w", ErrAuditUnavailable, err))
	}
	return cause
}

// storeFailure 把存储错误映射为对外安全的 ErrStoreUnavailable；保留 context
// 取消/超时语义，原始错误只写运行日志。
func (s *Service) storeFailure(ctx context.Context, operation string, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, ErrStoreUnavailable) {
		return err
	}
	s.logger.Warn("认证存储操作失败", "operation", operation, "error", err)
	return fmt.Errorf("%w: %s", ErrStoreUnavailable, operation)
}

// clockNow 返回统一截断到 UTC 毫秒的当前时间，与数据库毫秒列一致。
func (s *Service) clockNow() time.Time {
	return s.now().UTC().Truncate(time.Millisecond)
}

// mapCriticalError 把审计事务错误映射为认证领域错误；审计失败优先判定。
func mapCriticalError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, audit.ErrAuditUnavailable):
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	case errors.Is(err, ErrSetupStateConflict), errors.Is(err, ErrInvalidRequest),
		errors.Is(err, ErrPasswordReused), errors.Is(err, ErrWeakPassword):
		return err
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, audit.ErrInvalidEvent):
		return fmt.Errorf("%w: 审计事件无效", ErrOptionsInvalid)
	case errors.Is(err, ErrStoreUnavailable):
		return err
	default:
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
}

// normalizeContext 把 nil ctx 当成 Background，避免调用方漏传导致 panic。
func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// sleepWithContext 执行可取消的渐进延迟。
func sleepWithContext(ctx context.Context, duration time.Duration) error {
	if duration <= 0 {
		return nil
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// discardLogger 返回写入丢弃输出的日志器。
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

// nonZeroRetry 保证对外给出的等待时间为正数（避免提示立即重试）。
func nonZeroRetry(duration time.Duration) time.Duration {
	if duration <= 0 {
		return time.Second
	}
	return duration
}

// aggregateClientAddress 把可信客户端地址归一为限流/锁定使用的来源前缀：
// IPv4 使用完整地址，IPv6 聚合到 /64 前缀（同一 /64 内的地址变体不再提供额外
// 尝试空间，避免用 IPv6 地址轮换绕过限流）。
func aggregateClientAddress(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "unknown"
	}
	parsed := net.ParseIP(trimmed)
	if parsed == nil {
		return "invalid"
	}
	if ipv4 := parsed.To4(); ipv4 != nil {
		return "ipv4:" + ipv4.String()
	}
	ipv6 := parsed.To16()
	if ipv6 == nil {
		return "invalid"
	}
	var prefix [8]byte
	copy(prefix[:], ipv6[:8])
	return fmt.Sprintf("ipv6:%x", prefix)
}

// boundedFailureKey 把任意登录标识输入限制为有界失败跟踪键；超长输入用其长度与
// 前 64 字节表示，避免以超长标识消耗内存。
func boundedFailureKey(raw string) string {
	if len(raw) <= 64 {
		return strings.ToLower(raw)
	}
	return fmt.Sprintf("%d:%s", len(raw), strings.ToLower(raw[:64]))
}

// isNilInterface 检测 nil 接口与 typed nil 指针，避免服务调用时 panic。
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
