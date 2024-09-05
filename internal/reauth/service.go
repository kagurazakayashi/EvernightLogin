package reauth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"sync"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
)

const (
	// DefaultChallengeTTL 是认证挑战默认有效期。
	DefaultChallengeTTL = 5 * time.Minute
	// DefaultApprovalTTL 是一次性批准默认有效期。
	DefaultApprovalTTL = 2 * time.Minute
	// DefaultProofMaxAge 是目标绑定操作证明“准备→最终提交”的默认最大间隔。
	DefaultProofMaxAge = 5 * time.Second
	// MinProofMaxAge 是允许的最小间隔（更低会让正常请求频繁失败）。
	MinProofMaxAge = 500 * time.Millisecond
	// MaxProofMaxAge 是允许的最大间隔（硬上限 5 秒；不允许放宽到分钟级，否则会把
	// 权限/会话复核结果的有效期拉长成不可接受的窗口）。
	MaxProofMaxAge = 5 * time.Second
	// DefaultMaxAttempts 是挑战允许的密码尝试次数。
	DefaultMaxAttempts = 5
	// DefaultFailureNotifyLimit 是失败高风险告知的窗口内频次上限。
	DefaultFailureNotifyLimit = 3
	// DefaultFailureNotifyWindow 是失败告知限频窗口。
	DefaultFailureNotifyWindow = time.Hour
	// maxParamsFields 是操作参数数量上限。
	maxParamsFields = 16
	// maxParamKeyBytes 是参数名长度上限。
	maxParamKeyBytes = 64
	// maxParamValueBytes 是参数值长度上限。
	maxParamValueBytes = 512
)

// PasswordVerifyRequest 是对已登录用户进行再次密码验证的请求。
type PasswordVerifyRequest struct {
	UserID    string
	Username  string
	Password  string
	RequestID string
}

// PasswordVerifyResult 是密码验证成功的客观事实。Complete 表示该认证是完整认证
// （没有待完成第二因素/强制改密等步骤）；不同方法不机械相加，调用方只使用实际
// 完成的方式与强度。
type PasswordVerifyResult struct {
	UserID      string
	CompletedAt time.Time
	Complete    bool
}

// PasswordVerifier 是密码再次验证契约；生产适配在 internal/authn（真实密码校验、
// 失败限流与审计），测试可使用受控替身并断言调用参数。
type PasswordVerifier interface {
	VerifyPassword(ctx context.Context, request PasswordVerifyRequest) (PasswordVerifyResult, error)
}

// PolicyEvaluator 是步骤 38 敏感操作目录的评估接口；生产实现为
// *policy.Service。
type PolicyEvaluator interface {
	Evaluate(ctx context.Context, caller policy.Caller, request policy.EvaluateRequest) (policy.Decision, error)
}

// AuditRecorder 是安全审计写入契约；实现必须 fail-closed。
type AuditRecorder interface {
	Record(ctx context.Context, event audit.Event) error
	RecordFailure(ctx context.Context, event audit.Event) error
	ExecuteCritical(ctx context.Context, request audit.CriticalRequest, change audit.Change) error
}

// Options 是再次认证服务依赖。
type Options struct {
	Store     Store
	Audit     AuditRecorder
	Policy    PolicyEvaluator
	Passwords PasswordVerifier
	// StrongFactors 是第二条强因素验证器；nil 时 strong 要求 fail-closed。
	StrongFactors StrongFactorVerifier
	Mailer        mailer.Sender
	// Deliveries 是可靠投递入队服务（步骤 197）：非空时安全告知改走 mailer 队列，
	// 由任务有限重试/重启恢复承担；nil 时回退直接 Mailer（单测/嵌入兼容）。
	Deliveries  mailer.DeliveryEnqueuer
	FromAddress string
	AppName     string
	SupportURL  string
	Templates   *mailer.TemplateSet
	// AvailableStrengths 是当前环境已实现的认证强度；nil 时只认为 none/password
	// 可用（MFA/Passkey 未实现），要求强认证的操作 fail-closed。
	AvailableStrengths []policy.Strength
	// IntentSealer 密封直接管理操作的新值意图（步骤 255）；nil 时直接管理证明
	// fail-closed。生产实现为 *internal/secrets.Sealer。
	IntentSealer IntentSealer
	ChallengeTTL time.Duration
	ApprovalTTL  time.Duration
	// ProofMaxAge 是目标绑定操作证明的准备→提交最大间隔（步骤 255 修复）；零值使用
	// DefaultProofMaxAge，允许 500ms～5s，绝不允许放宽到分钟级。
	ProofMaxAge         time.Duration
	MaxAttempts         int
	FailureNotifyLimit  int
	FailureNotifyWindow time.Duration
	Now                 func() time.Time
	Random              io.Reader
	Logger              *slog.Logger
}

// Service 是再次认证与安全告知执行侧服务。构造后不可变，不启动协程，不实现 MFA。
// 步骤 255 起额外承载目标绑定操作证明所需的晚期接线依赖（会话校验、权限复核、
// WebAuthn 第二步验证器），由宿主在相应服务构造完成后注入；未注入时对直接管理
// 操作 fail-closed。
type Service struct {
	opts           Options
	available      map[policy.Strength]bool
	failureLimiter *failureLimiter
	// proofMu 保护步骤 255 的晚期接线依赖（构造后由宿主一次性 Set）。
	proofMu           sync.RWMutex
	intentSealer      IntentSealer
	sessionVerifier   SessionVerifier
	permissionChecker PermissionChecker
	strongWebAuthn    StrongWebAuthnVerifier
	// proofMaxAge 是目标绑定操作证明的准备→提交最大间隔（≤5s）。
	proofMaxAge time.Duration
}

// New 校验依赖并构造服务。
func New(options Options) (*Service, error) {
	if isNil(options.Store) {
		return nil, fmt.Errorf("%w: 再次认证存储为空", ErrOptionsInvalid)
	}
	if isNil(options.Audit) {
		return nil, fmt.Errorf("%w: 审计写入器为空", ErrOptionsInvalid)
	}
	if isNil(options.Policy) {
		return nil, fmt.Errorf("%w: 敏感策略评估器为空", ErrOptionsInvalid)
	}
	if options.ChallengeTTL == 0 {
		options.ChallengeTTL = DefaultChallengeTTL
	}
	if options.ChallengeTTL < time.Minute || options.ChallengeTTL > 15*time.Minute {
		return nil, fmt.Errorf("%w: 挑战有效期必须在 1～15 分钟之间", ErrOptionsInvalid)
	}
	if options.ApprovalTTL == 0 {
		options.ApprovalTTL = DefaultApprovalTTL
	}
	if options.ApprovalTTL < 30*time.Second || options.ApprovalTTL > 10*time.Minute {
		return nil, fmt.Errorf("%w: 批准有效期必须在 30 秒～10 分钟之间", ErrOptionsInvalid)
	}
	if options.ProofMaxAge == 0 {
		options.ProofMaxAge = DefaultProofMaxAge
	}
	if options.ProofMaxAge < MinProofMaxAge || options.ProofMaxAge > MaxProofMaxAge {
		return nil, fmt.Errorf("%w: 操作证明最大准备间隔必须在 %s～%s 之间",
			ErrOptionsInvalid, MinProofMaxAge, MaxProofMaxAge)
	}
	if options.MaxAttempts == 0 {
		options.MaxAttempts = DefaultMaxAttempts
	}
	if options.MaxAttempts < 1 || options.MaxAttempts > 10 {
		return nil, fmt.Errorf("%w: 挑战尝试上限必须在 1～10 之间", ErrOptionsInvalid)
	}
	if options.FailureNotifyLimit == 0 {
		options.FailureNotifyLimit = DefaultFailureNotifyLimit
	}
	if options.FailureNotifyLimit < 0 || options.FailureNotifyLimit > 10 {
		return nil, fmt.Errorf("%w: 失败告知频次上限必须在 0～10 之间", ErrOptionsInvalid)
	}
	if options.FailureNotifyWindow == 0 {
		options.FailureNotifyWindow = DefaultFailureNotifyWindow
	}
	if options.FailureNotifyWindow < time.Minute || options.FailureNotifyWindow > 24*time.Hour {
		return nil, fmt.Errorf("%w: 失败告知窗口必须在 1 分钟～24 小时之间", ErrOptionsInvalid)
	}
	available := make(map[policy.Strength]bool)
	if len(options.AvailableStrengths) == 0 {
		available[policy.StrengthNone] = true
		available[policy.StrengthPassword] = true
	} else {
		for _, strength := range options.AvailableStrengths {
			if !strength.Known() {
				return nil, fmt.Errorf("%w: 可用认证强度 %q 未知", ErrOptionsInvalid, strength)
			}
			available[strength] = true
		}
	}
	if !available[policy.StrengthPassword] {
		return nil, fmt.Errorf("%w: 可用认证强度必须包含 password", ErrOptionsInvalid)
	}
	if options.FromAddress != "" {
		if _, err := mailer.ParseAddress(options.FromAddress); err != nil {
			return nil, fmt.Errorf("%w: 发件地址无效", ErrOptionsInvalid)
		}
	}
	if options.Templates == nil {
		templates, err := mailer.DefaultTemplateSet()
		if err != nil {
			return nil, fmt.Errorf("%w: 默认邮件模板不可用", ErrOptionsInvalid)
		}
		options.Templates = templates
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
	service := &Service{
		opts:         options,
		available:    available,
		proofMaxAge:  options.ProofMaxAge,
		intentSealer: options.IntentSealer,
		failureLimiter: &failureLimiter{
			limit: options.FailureNotifyLimit, window: options.FailureNotifyWindow,
			entries: make(map[string][]time.Time),
		},
	}
	return service, nil
}

// proofMaxAgeLimit 返回证明准备→提交允许的最大间隔（构造时已校验不超过 5 秒）。
func (s *Service) proofMaxAgeLimit() time.Duration {
	if s == nil || s.proofMaxAge <= 0 {
		return DefaultProofMaxAge
	}
	return s.proofMaxAge
}

// SupportedStrengths 返回当前可满足的认证强度（用于诊断与装配校验）。
func (s *Service) SupportedStrengths() []policy.Strength {
	strengths := make([]policy.Strength, 0, len(s.available))
	for _, candidate := range []policy.Strength{policy.StrengthNone, policy.StrengthPassword, policy.StrengthStrong} {
		if s.available[candidate] {
			strengths = append(strengths, candidate)
		}
	}
	return strengths
}

// OperationRunner 是业务模块使用的执行前/执行后收敛接口；*Service 实现它。
// 模块在关键写入前调用 Authorize，在成功后调用 NotifyOutcome（失败只记录日志）。
type OperationRunner interface {
	Authorize(ctx context.Context, caller Caller, request Request) (Result, error)
	NotifyOutcome(ctx context.Context, result Result, outcome Outcome) error
}

// CallerFromActor 把可信审计身份转换为再次认证调用者；匿名身份拒绝。
func CallerFromActor(actor audit.Actor) (Caller, error) {
	switch actor.Type {
	case audit.ActorUser:
		return UserCaller(actor.ID)
	case audit.ActorSystem:
		return SystemCaller(actor.ID)
	case audit.ActorLocalAdmin:
		return LocalAdminCaller(actor.ID)
	default:
		return Caller{}, ErrAccessDenied
	}
}

// Authorize 是执行前校验的收敛入口：按策略评估近期认证事实；不满足时优先使用
// 上下文中的一次性批准，批准必须绑定调用者、作用域、操作、目标与服务端计算的
// 参数摘要，且只能消费一次。返回 Result 供执行后告知使用。
func (s *Service) Authorize(ctx context.Context, caller Caller, request Request) (Result, error) {
	ctx = normalizeContext(ctx)
	if err := caller.actor.Validate(); err != nil {
		return Result{}, ErrAccessDenied
	}
	if err := s.validateRequest(request); err != nil {
		s.recordRejection(ctx, caller, request, err)
		return Result{}, err
	}
	// 步骤 255：直接管理操作（操作者与目标不同）不允许走“上下文信号/旧一次性批准”
	// 路径，必须使用会话+目标+意图绑定的 ConsumeProofTx；否则伪造 context 信号或
	// 参数摘要不能代替会话/意图绑定。
	if isDirectManagementOperation(request.OperationID) {
		s.recordRejection(ctx, caller, request, errDirectOperationRequiresProof)
		return Result{}, errDirectOperationRequiresProof
	}
	policyCaller, err := toPolicyCaller(caller.actor)
	if err != nil {
		return Result{}, ErrAccessDenied
	}
	digest := ParamsDigest(request.Params)
	signals := SignalsFromContext(ctx)
	verification := policy.Verification{
		VerifiedAt: signals.VerifiedAt, Strength: signals.Strength, Confirmed: signals.Confirmed,
	}
	decision, evaluateErr := s.opts.Policy.Evaluate(ctx, policyCaller, policy.EvaluateRequest{
		ScopeID: request.ScopeID, OperationID: request.OperationID, Verification: verification,
	})
	if evaluateErr == nil {
		if err := s.checkComplete(decision, signals.Complete); err != nil {
			s.recordRejection(ctx, caller, request, err)
			return Result{}, err
		}
		return s.newResult(caller, request, decision, "direct", "", signals), nil
	}
	// 需要额外认证/确认时尝试消费一次性批准。
	if signals.ApprovalToken != "" {
		result, approvalErr := s.consumeApproval(ctx, caller, request, digest, signals, policyCaller)
		if approvalErr != nil {
			s.recordRejection(ctx, caller, request, approvalErr)
			return Result{}, approvalErr
		}
		return result, nil
	}
	mapped := s.mapEvaluateError(evaluateErr, decision)
	s.recordRejection(ctx, caller, request, mapped)
	return Result{}, mapped
}

// Run 是“执行前校验 + 业务动作 + 执行后告知”的闭环封装。业务模块也可分别调用
// Authorize/NotifyOutcome，以便把动作放入自身的审计事务。
func (s *Service) Run(ctx context.Context, caller Caller, request Request,
	action func(context.Context) error) (Result, error) {
	if action == nil {
		return Result{}, fmt.Errorf("%w: 业务动作不能为空", ErrInvalidRequest)
	}
	result, err := s.Authorize(ctx, caller, request)
	if err != nil {
		return Result{}, err
	}
	if actionErr := action(ctx); actionErr != nil {
		s.notifyOutcomeBestEffort(ctx, result, OutcomeFailure)
		return result, actionErr
	}
	s.notifyOutcomeBestEffort(ctx, result, OutcomeSuccess)
	return result, nil
}

// NotifyOutcome 执行操作后安全告知；返回错误只说明告知未完成，调用方不得据此回滚
// 已成功的业务变更。成功告知遵守策略 NotificationRequired，失败告知按敏感操作
// 触发并受频次限制。
func (s *Service) NotifyOutcome(ctx context.Context, result Result, outcome Outcome) error {
	return s.notifyOutcome(ctx, result, outcome)
}

// notifyOutcomeBestEffort 在 Run 内部使用：告知失败只记录日志，不影响业务结果。
func (s *Service) notifyOutcomeBestEffort(ctx context.Context, result Result, outcome Outcome) {
	if err := s.notifyOutcome(ctx, result, outcome); err != nil {
		s.opts.Logger.Warn("安全告知未完成", "error", err)
	}
}

// ChallengeRequest 是创建认证挑战的请求。
type ChallengeRequest struct {
	ScopeID     string
	OperationID string
	TargetType  string
	TargetID    string
	Params      map[string]string
	Description string
	RequestID   string
	// MinimumStrength 是可信页面适配层要求的更强认证下限；只能提高、不能降低
	// 策略要求的强度。为空表示只按策略。
	MinimumStrength policy.Strength
	// SessionID 是操作者本次管理会话的服务器端 ID（步骤 255，可直接管理操作使用）；
	// 由可信会话解析写入，不能来自普通请求参数自称。非直接管理操作必须为空。
	SessionID string
	// Intent 是本次操作将应用的新值意图（步骤 255，直接管理操作使用）；非直接管理
	// 操作必须为空。服务端只保存其密封密文，不保存明文或无密钥摘要。
	Intent *Intent
}

// Challenge 是操作绑定认证挑战。Required=false 表示当前策略不需要额外认证。
type Challenge struct {
	ID               string
	OperationID      string
	RequiredStrength policy.Strength
	ExpiresAt        time.Time
	MaxAttempts      int
	Required         bool
}

// BeginChallenge 为需要再次认证的操作创建挑战；要求强认证但环境未实现时
// fail-closed 返回 MFA_REQUIRED，不创建可用密码满足的降级挑战。
func (s *Service) BeginChallenge(ctx context.Context, caller Caller, request ChallengeRequest) (Challenge, error) {
	ctx = normalizeContext(ctx)
	if err := caller.actor.Validate(); err != nil {
		return Challenge{}, ErrAccessDenied
	}
	if !caller.IsUser() {
		return Challenge{}, fmt.Errorf("%w: 只有用户本人可以发起再次认证", ErrAccessDenied)
	}
	policyRequest := Request{ScopeID: request.ScopeID, OperationID: request.OperationID,
		TargetType: request.TargetType, TargetID: request.TargetID, Params: request.Params,
		Description: request.Description, RequestID: request.RequestID}
	if err := s.validateRequest(policyRequest); err != nil {
		s.recordRejection(ctx, caller, policyRequest, err)
		return Challenge{}, err
	}
	// 步骤 255：直接管理操作必须显式绑定操作者会话与本次新值意图；普通敏感操作
	// 不允许混用这两项，避免把“操作者即目标”的旧语义与目标绑定证明混淆。
	directOperation := isDirectManagementOperation(request.OperationID)
	if directOperation {
		if request.ScopeID != "system" || request.TargetType != "user" ||
			!account.ValidUserID(request.TargetID) {
			mapped := fmt.Errorf("%w: 直接管理操作的目标/范围非法", ErrInvalidRequest)
			s.recordRejection(ctx, caller, policyRequest, mapped)
			return Challenge{}, mapped
		}
		if !validSessionBinding(request.SessionID) {
			mapped := fmt.Errorf("%w: 缺少可信会话绑定", ErrSessionMismatch)
			s.recordRejection(ctx, caller, policyRequest, mapped)
			return Challenge{}, mapped
		}
		requiredKind, _ := requiredIntentKind(request.OperationID)
		if request.Intent == nil || request.Intent.Kind != requiredKind {
			mapped := fmt.Errorf("%w: 缺少本次新值意图", ErrIntentInvalid)
			s.recordRejection(ctx, caller, policyRequest, mapped)
			return Challenge{}, mapped
		}
		if err := request.Intent.Validate(); err != nil {
			s.recordRejection(ctx, caller, policyRequest, err)
			return Challenge{}, err
		}
	} else if request.SessionID != "" || request.Intent != nil {
		mapped := fmt.Errorf("%w: 非直接管理操作不支持会话/意图绑定", ErrInvalidRequest)
		s.recordRejection(ctx, caller, policyRequest, mapped)
		return Challenge{}, mapped
	}
	policyCaller, err := toPolicyCaller(caller.actor)
	if err != nil {
		return Challenge{}, ErrAccessDenied
	}
	decision, evaluateErr := s.opts.Policy.Evaluate(ctx, policyCaller, policy.EvaluateRequest{
		ScopeID: request.ScopeID, OperationID: request.OperationID,
	})
	if evaluateErr == nil {
		// 目录判定该操作当前不要求额外认证：不保存挑战。
		return Challenge{OperationID: request.OperationID, Required: false}, nil
	}
	mappedEvaluate := s.mapEvaluateError(evaluateErr, decision)
	requiredStrength := decision.RequiredStrength
	if request.MinimumStrength.Known() && strengthRank(request.MinimumStrength) > strengthRank(requiredStrength) {
		requiredStrength = request.MinimumStrength
	}
	if !decision.Sensitive || !decision.ReauthRequired {
		// 未知操作/作用域、策略不可用等非“需要验证”类错误必须拒绝，不得 fail-open
		// 返回 Required=false。
		s.recordRejection(ctx, caller, policyRequest, mappedEvaluate)
		return Challenge{}, mappedEvaluate
	}
	if !s.available[requiredStrength] {
		mapped := fmt.Errorf("%w: 要求 %q 强度认证", ErrMFARequired, requiredStrength)
		s.recordRejection(ctx, caller, policyRequest, mapped)
		return Challenge{}, mapped
	}
	now := s.now()
	challengeID, err := newDatabaseID(s.opts.Random, "chl_")
	if err != nil {
		return Challenge{}, err
	}
	paramsDigest := ParamsDigest(request.Params)
	var sealedIntent []byte
	if directOperation {
		// 密封绑定以挑战 ID 为对象、作用域为范围；密文跨挑战/跨范围复制无法解密。
		sealedIntent, err = s.sealIntent(challengeID, request.ScopeID, *request.Intent)
		if err != nil {
			s.recordRejection(ctx, caller, policyRequest, err)
			return Challenge{}, err
		}
	}
	record := ChallengeRecord{
		ID: challengeID, UserID: caller.actor.ID, ScopeID: request.ScopeID,
		OperationID: request.OperationID, TargetType: request.TargetType, TargetID: request.TargetID,
		ParamsSHA256: paramsDigest[:], RequiredStrength: requiredStrength,
		State: ChallengePending, Attempts: 0, MaxAttempts: s.opts.MaxAttempts,
		ExpiresAt: now.Add(s.opts.ChallengeTTL), CreatedAt: now, UpdatedAt: now,
		SessionID: request.SessionID, IntentSealed: sealedIntent,
	}
	changes := []audit.FieldChange{
		{Field: "operation_id", After: request.OperationID},
		{Field: "target_type", After: request.TargetType},
		{Field: "target_id", After: safeValue(request.TargetID)},
		{Field: "required_strength", After: string(requiredStrength)},
	}
	if directOperation {
		changes = append(changes,
			audit.FieldChange{Field: "session_bound", After: "true"},
			audit.FieldChange{Field: "intent_bound", After: "true"})
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: caller.actor, Action: "reauth.challenge",
			Target:    audit.Target{Type: "reauth_challenge", ID: challengeID},
			RequestID: validRequestID(request.RequestID),
			Changes:   changes,
		},
		FailureReasonCode:   "reauth.challenge_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapCriticalError(err))) },
	}
	if directOperation {
		// 发起证明前复核操作者当前权限（事务外只读；权限内核使用独立连接，不能与
		// 审计写事务同时读取）。消费前的最终复核在 PrepareProof 再做一次。
		permissionKey, _ := directPermissionKey(request.OperationID)
		if err := s.checkDirectProofPermission(ctx, caller.actor.ID, permissionKey); err != nil {
			s.recordRejection(ctx, caller, policyRequest, err)
			return Challenge{}, err
		}
	}
	err = s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.opts.Store.CreateChallengeTx(txCtx, tx, record)
	})
	if err != nil {
		return Challenge{}, mapCriticalError(err)
	}
	// 有界擦除过期/已消费批准上的意图密文（失败不影响本次签发，安全由消费校验保证）。
	s.purgeExpiredIntents(ctx)
	return Challenge{ID: challengeID, OperationID: request.OperationID,
		RequiredStrength: requiredStrength, ExpiresAt: record.ExpiresAt,
		MaxAttempts: s.opts.MaxAttempts, Required: true}, nil
}

// VerifyChallengeRequest 是校验认证挑战的请求。
type VerifyChallengeRequest struct {
	ChallengeID string
	Password    string
	// TOTPCode 是策略要求 strong 时的第二条因素动态码；password-only 不得满足
	// strong 要求。
	TOTPCode string
	// SessionID 是操作者当前管理会话 ID（步骤 255）；挑战绑定了会话时必须完全一致，
	// 用于把一次性批准限制在完成验证的同一会话上。
	SessionID string
	RequestID string
}

// ApprovalGrant 是验证成功后的短时一次性批准（明文令牌只在此返回一次）。
type ApprovalGrant struct {
	Token           string
	ExpiresAt       time.Time
	GrantedStrength policy.Strength
	OperationID     string
	TargetType      string
	TargetID        string
	// SessionID 是本次批准绑定的操作者会话 ID（直接管理证明非空）。
	SessionID string
}

// VerifyChallenge 校验挑战绑定的用户密码；成功返回一次操作批准令牌，失败递增
// 尝试次数并写失败审计。挑战不是批准，密码验证后才产生一次性批准。
func (s *Service) VerifyChallenge(ctx context.Context, caller Caller, request VerifyChallengeRequest) (ApprovalGrant, error) {
	ctx = normalizeContext(ctx)
	if err := caller.actor.Validate(); err != nil {
		return ApprovalGrant{}, ErrAccessDenied
	}
	if !caller.IsUser() {
		return ApprovalGrant{}, fmt.Errorf("%w: 只有用户本人可以完成再次认证", ErrAccessDenied)
	}
	if !validDatabaseID(request.ChallengeID, "chl_") {
		return ApprovalGrant{}, fmt.Errorf("%w: 挑战标识格式非法", ErrInvalidRequest)
	}
	requestID := validRequestID(request.RequestID)
	if request.Password == "" || len(request.Password) > 1024 {
		return ApprovalGrant{}, fmt.Errorf("%w: 密码不能为空且长度受限", ErrAuthenticationFailed)
	}
	record, found, err := s.opts.Store.GetChallenge(ctx, request.ChallengeID)
	if err != nil {
		return ApprovalGrant{}, ErrStoreUnavailable
	}
	if !found || record.UserID != caller.actor.ID {
		// 不泄露他人挑战是否存在。
		s.recordVerifyFailure(ctx, caller, request.ChallengeID, "challenge_not_found")
		return ApprovalGrant{}, ErrChallengeInvalid
	}
	now := s.now()
	if record.State != ChallengePending {
		return ApprovalGrant{}, ErrChallengeInvalid
	}
	if !now.Before(record.ExpiresAt) {
		return ApprovalGrant{}, ErrChallengeExpired
	}
	// 步骤 255：挑战绑定了会话时，完成验证的调用必须来自同一会话；否则拒绝，
	// 防止把一步验证能力挪用到其他会话。
	if record.SessionID != "" &&
		(!validSessionBinding(request.SessionID) || request.SessionID != record.SessionID) {
		s.recordVerifyFailure(ctx, caller, record.ID, "session_mismatch")
		return ApprovalGrant{}, ErrSessionMismatch
	}
	if record.Attempts >= record.MaxAttempts {
		s.recordVerifyFailure(ctx, caller, request.ChallengeID, "attempts_exceeded")
		return ApprovalGrant{}, ErrAttemptsExceeded
	}
	username, found, err := s.opts.Store.Username(ctx, caller.actor.ID)
	if err != nil {
		return ApprovalGrant{}, ErrStoreUnavailable
	}
	if !found {
		return ApprovalGrant{}, ErrAccessDenied
	}
	if isNil(s.opts.Passwords) {
		// 未接线（含 typed-nil）密码验证实现时不得把挑战当已通过，fail-closed。
		return ApprovalGrant{}, fmt.Errorf("%w: 未配置密码验证实现", ErrMFARequired)
	}
	verified, verifyErr := s.opts.Passwords.VerifyPassword(ctx, PasswordVerifyRequest{
		UserID: caller.actor.ID, Username: username, Password: request.Password, RequestID: requestID,
	})
	if verifyErr != nil {
		attempts, increaseErr := s.opts.Store.IncreaseAttempts(ctx, record.ID, now)
		if increaseErr != nil {
			s.opts.Logger.Warn("再次认证失败后递增尝试次数失败", "error", increaseErr)
		}
		if attempts >= record.MaxAttempts {
			s.recordVerifyFailure(ctx, caller, record.ID, "attempts_exceeded")
			return ApprovalGrant{}, ErrAttemptsExceeded
		}
		s.recordVerifyFailure(ctx, caller, record.ID, "invalid_password")
		return ApprovalGrant{}, ErrAuthenticationFailed
	}
	if verified.UserID != caller.actor.ID {
		// 验证器返回了其他账户：拒绝，不消耗为批准。
		s.recordVerifyFailure(ctx, caller, record.ID, "verifier_subject_mismatch")
		return ApprovalGrant{}, ErrAuthenticationFailed
	}
	completedAt := verified.CompletedAt
	if completedAt.IsZero() {
		completedAt = now
	}
	if completedAt.After(now) {
		// 验证器报告的完成时间略晚于本服务截断后的时钟时按当前时间处理。
		completedAt = now
	}
	// 强认证要求：必须再完成真实第二因素（TOTP/Passkey），密码本身不得满足。
	grantedStrength := policy.StrengthPassword
	verificationComplete := verified.Complete
	if record.RequiredStrength == policy.StrengthStrong {
		if isNil(s.opts.StrongFactors) {
			s.recordVerifyFailure(ctx, caller, record.ID, "strong_verifier_not_configured")
			return ApprovalGrant{}, fmt.Errorf("%w: 未配置强因素验证实现", ErrMFARequired)
		}
		if request.TOTPCode == "" {
			s.recordVerifyFailure(ctx, caller, record.ID, "strong_factor_required")
			return ApprovalGrant{}, fmt.Errorf("%w: 需要第二因素动态码", ErrMFARequired)
		}
		strong, strongErr := s.opts.StrongFactors.VerifyStrongFactor(ctx,
			StrongFactorVerifyRequest{UserID: caller.actor.ID, TOTPCode: request.TOTPCode,
				RequestID: requestID})
		if strongErr != nil || strong.UserID != caller.actor.ID || !strong.UserVerified {
			attempts, increaseErr := s.opts.Store.IncreaseAttempts(ctx, record.ID, now)
			if increaseErr != nil {
				s.opts.Logger.Warn("再次认证强因素失败后递增尝试次数失败", "error", increaseErr)
			}
			if attempts >= record.MaxAttempts {
				s.recordVerifyFailure(ctx, caller, record.ID, "attempts_exceeded")
				return ApprovalGrant{}, ErrAttemptsExceeded
			}
			s.recordVerifyFailure(ctx, caller, record.ID, "invalid_strong_factor")
			return ApprovalGrant{}, ErrAuthenticationFailed
		}
		completedAt = strong.CompletedAt
		if completedAt.IsZero() {
			completedAt = now
		}
		if completedAt.After(now) {
			completedAt = now
		}
		grantedStrength = policy.StrengthStrong
		verificationComplete = true
	}
	// 以刚完成的真实认证事实重新评估策略并签发一次性批准（步骤 255 抽出的共用
	// 签发路径，WebAuthn 路径复用同一逻辑）。
	return s.issueApproval(ctx, caller, record, grantedStrength, completedAt,
		verificationComplete, requestID)
}

// issueApproval 在审计事务内把已核实的真实认证事实固化为一次性批准：
//   - 以批准授予的事实重新评估策略；不满足/需要更强时不出具批准；
//   - 高权限操作必须有完整强认证；
//   - 挑战上绑定的会话与密封意图原样复制到批准（步骤 255 的直接管理证明消费时
//     再次核对），批准本身不保存意图明文；
//   - 挑战状态与批准行在同一事务提交，并发只有一个赢家。
func (s *Service) issueApproval(ctx context.Context, caller Caller, record ChallengeRecord,
	grantedStrength policy.Strength, completedAt time.Time, verificationComplete bool,
	requestID string) (ApprovalGrant, error) {
	now := s.now()
	policyCaller, policyErr := toPolicyCaller(caller.actor)
	if policyErr != nil {
		return ApprovalGrant{}, ErrAccessDenied
	}
	decision, evaluateErr := s.opts.Policy.Evaluate(ctx, policyCaller, policy.EvaluateRequest{
		ScopeID: record.ScopeID, OperationID: record.OperationID,
		Verification: policy.Verification{VerifiedAt: completedAt,
			Strength: grantedStrength, Confirmed: true},
	})
	if evaluateErr != nil {
		mapped := s.mapEvaluateError(evaluateErr, decision)
		s.recordVerifyFailure(ctx, caller, record.ID, "policy_not_satisfied")
		return ApprovalGrant{}, mapped
	}
	if decision.RootOnly && !verificationComplete {
		mapped := fmt.Errorf("%w: 高权限操作需要完整强认证", ErrMFARequired)
		s.recordVerifyFailure(ctx, caller, record.ID, "strong_auth_incomplete")
		return ApprovalGrant{}, mapped
	}
	// 直接管理操作的安全下限：必须两步验证达成 strong，否则不出具可消费证明。
	if isDirectManagementOperation(record.OperationID) &&
		(grantedStrength != policy.StrengthStrong || !verificationComplete) {
		s.recordVerifyFailure(ctx, caller, record.ID, "direct_operation_strong_required")
		return ApprovalGrant{}, fmt.Errorf("%w: 直接管理操作需要完整两步验证", ErrMFARequired)
	}
	token, tokenDigest, err := newApprovalToken(s.opts.Random)
	if err != nil {
		return ApprovalGrant{}, err
	}
	approvalID, err := newDatabaseID(s.opts.Random, "apr_")
	if err != nil {
		return ApprovalGrant{}, err
	}
	approval := ApprovalRecord{
		ID: approvalID, ChallengeID: record.ID, TokenSHA256: tokenDigest,
		UserID: caller.actor.ID, ScopeID: record.ScopeID, OperationID: record.OperationID,
		TargetType: record.TargetType, TargetID: record.TargetID,
		ParamsSHA256: record.ParamsSHA256, GrantedStrength: grantedStrength,
		Complete: verificationComplete, GrantedAt: completedAt,
		ExpiresAt: now.Add(s.opts.ApprovalTTL), CreatedAt: now,
		SessionID: record.SessionID, IntentSealed: record.IntentSealed,
	}
	changes := []audit.FieldChange{
		{Field: "operation_id", After: record.OperationID},
		{Field: "target_type", After: record.TargetType},
		{Field: "target_id", After: safeValue(record.TargetID)},
		{Field: "granted_strength", After: string(grantedStrength)},
		{Field: "authentication_complete", After: boolText(verificationComplete)},
	}
	if record.SessionID != "" {
		changes = append(changes, audit.FieldChange{Field: "session_bound", After: "true"})
	}
	if len(record.IntentSealed) > 0 {
		changes = append(changes, audit.FieldChange{Field: "intent_bound", After: "true"})
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: caller.actor, Action: "reauth.approved",
			Target:    audit.Target{Type: "reauth_approval", ID: approvalID},
			RequestID: requestID,
			Changes:   changes,
		},
		FailureReasonCode:   "reauth.approval_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapCriticalError(err))) },
	}
	err = s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		ok, approveErr := s.opts.Store.ApproveTx(txCtx, tx, record.ID, now, approval)
		if approveErr != nil {
			return approveErr
		}
		if !ok {
			return ErrChallengeInvalid
		}
		return nil
	})
	if err != nil {
		return ApprovalGrant{}, mapCriticalError(err)
	}
	return ApprovalGrant{Token: token, ExpiresAt: approval.ExpiresAt,
		GrantedStrength: grantedStrength, OperationID: record.OperationID,
		TargetType: record.TargetType, TargetID: record.TargetID,
		SessionID: record.SessionID}, nil
}

// CancelChallenge 取消用户本人尚未完成的再次认证挑战：pending 条件迁移为
// cancelled 并写审计。取消不产生批准、不签发任何令牌，之后 VerifyChallenge 一律
// 返回 CHALLENGE_INVALID；已经 verified/cancelled/expired 的挑战不可再取消。
//
// 取消是降低风险的动作，但仍需身份绑定：调用者必须是对应挑战的用户本人，不能
// 由他人或普通请求参数代取消。
func (s *Service) CancelChallenge(ctx context.Context, caller Caller, challengeID string) error {
	ctx = normalizeContext(ctx)
	if err := caller.actor.Validate(); err != nil {
		return ErrAccessDenied
	}
	if !caller.IsUser() {
		return fmt.Errorf("%w: 只有用户本人可以取消再次认证", ErrAccessDenied)
	}
	if !validDatabaseID(challengeID, "chl_") {
		return fmt.Errorf("%w: 挑战标识格式非法", ErrInvalidRequest)
	}
	challenge, found, err := s.opts.Store.GetChallenge(ctx, challengeID)
	if err != nil {
		return ErrStoreUnavailable
	}
	if !found || challenge.UserID != caller.actor.ID {
		// 不泄露他人挑战是否存在。
		return ErrChallengeInvalid
	}
	now := s.now()
	if challenge.State != ChallengePending || !now.Before(challenge.ExpiresAt) {
		return ErrChallengeInvalid
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: caller.actor, Action: "reauth.challenge_cancelled",
			Target:    audit.Target{Type: "reauth_challenge", ID: challenge.ID},
			RequestID: caller.requestID,
			Changes: []audit.FieldChange{
				{Field: "operation_id", After: challenge.OperationID},
				{Field: "target_type", After: challenge.TargetType},
				{Field: "target_id", After: safeValue(challenge.TargetID)},
			},
		},
		FailureReasonCode: "reauth.challenge_cancel_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		ok, cancelErr := s.opts.Store.CancelChallengeTx(txCtx, tx, challenge.ID, now)
		if cancelErr != nil {
			return cancelErr
		}
		if !ok {
			return ErrChallengeInvalid
		}
		return nil
	})
	if err != nil {
		return mapCriticalError(err)
	}
	return nil
}

// Notifications 读取用户最近的安全告知记录：本人或受信系统/本地通道/root 可读。
func (s *Service) Notifications(ctx context.Context, caller Caller, userID string, limit int) ([]NotificationRecord, error) {
	ctx = normalizeContext(ctx)
	if err := caller.actor.Validate(); err != nil {
		return nil, ErrAccessDenied
	}
	if !account.ValidUserID(userID) {
		return nil, fmt.Errorf("%w: 用户 ID 格式无效", ErrInvalidRequest)
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	self := caller.IsUser() && caller.actor.ID == userID
	if !self {
		allowed := caller.actor.Type == audit.ActorSystem || caller.actor.Type == audit.ActorLocalAdmin
		if !allowed && caller.IsUser() {
			isRoot, rootErr := s.opts.Store.IsRoot(ctx, caller.actor.ID)
			if rootErr != nil {
				return nil, ErrStoreUnavailable
			}
			allowed = isRoot
		}
		if !allowed {
			return nil, ErrAccessDenied
		}
	}
	records, err := s.opts.Store.ListNotifications(ctx, userID, limit)
	if err != nil {
		return nil, ErrStoreUnavailable
	}
	return records, nil
}

// consumeApproval 原子消费一次性批准并重新评估策略；绑定不符/过期/重放一律拒绝。
func (s *Service) consumeApproval(ctx context.Context, caller Caller, request Request,
	digest [32]byte, signals Signals, policyCaller policy.Caller) (Result, error) {
	rawToken, decodeErr := hexToken(signals.ApprovalToken)
	if decodeErr != nil {
		return Result{}, ErrApprovalInvalid
	}
	approval, found, err := s.opts.Store.GetApprovalByTokenDigest(ctx, secretDigest(rawToken))
	if err != nil {
		return Result{}, ErrStoreUnavailable
	}
	if !found {
		return Result{}, ErrApprovalInvalid
	}
	if !caller.IsUser() || approval.UserID != caller.actor.ID {
		return Result{}, ErrApprovalInvalid
	}
	if approval.ScopeID != request.ScopeID || approval.OperationID != request.OperationID ||
		approval.TargetType != request.TargetType || approval.TargetID != request.TargetID {
		return Result{}, ErrApprovalInvalid
	}
	if !equalBytes(approval.ParamsSHA256, digest[:]) {
		return Result{}, ErrApprovalInvalid
	}
	now := s.now()
	if !approval.ConsumedAt.IsZero() {
		return Result{}, ErrApprovalConsumed
	}
	if !now.Before(approval.ExpiresAt) {
		return Result{}, ErrApprovalExpired
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: caller.actor, Action: "reauth.approval_consumed",
			Target:    audit.Target{Type: "reauth_approval", ID: approval.ID},
			RequestID: validRequestID(request.RequestID),
			Changes: []audit.FieldChange{
				{Field: "operation_id", After: approval.OperationID},
				{Field: "target_type", After: approval.TargetType},
				{Field: "target_id", After: safeValue(approval.TargetID)},
			},
		},
		FailureReasonCode:   "reauth.approval_consumed_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapCriticalError(err))) },
	}
	err = s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		ok, consumeErr := s.opts.Store.ConsumeApprovalTx(txCtx, tx, approval.ID, now)
		if consumeErr != nil {
			return consumeErr
		}
		if !ok {
			return ErrApprovalConsumed
		}
		return nil
	})
	if err != nil {
		return Result{}, mapCriticalError(err)
	}
	// 用批准授予的事实重新评估；已过期/要求提升时必须重新认证。
	decision, evaluateErr := s.opts.Policy.Evaluate(ctx, policyCaller, policy.EvaluateRequest{
		ScopeID: request.ScopeID, OperationID: request.OperationID,
		Verification: policy.Verification{VerifiedAt: approval.GrantedAt,
			Strength: approval.GrantedStrength, Confirmed: signals.Confirmed},
	})
	if evaluateErr != nil {
		return Result{}, s.mapEvaluateError(evaluateErr, decision)
	}
	if err := s.checkComplete(decision, approval.Complete); err != nil {
		return Result{}, err
	}
	return s.newResult(caller, request, decision, "approval", approval.ID, signals), nil
}

// newResult 构造执行后告知需要的操作上下文。
func (s *Service) newResult(caller Caller, request Request, decision policy.Decision,
	method, approvalID string, signals Signals) Result {
	result := Result{
		OperationID: request.OperationID, TargetType: request.TargetType,
		TargetID: request.TargetID, Description: request.Description,
		Decision: decision, Method: method, ApprovalID: approvalID,
		RequestID: request.RequestID,
	}
	if caller.IsUser() {
		result.UserID = caller.actor.ID
	} else if request.TargetType == "user" && account.ValidUserID(request.TargetID) {
		result.UserID = request.TargetID
	}
	return result
}

// checkComplete 拒绝“高权限操作 + 未完成强认证”的组合，不为演示放宽。
func (s *Service) checkComplete(decision policy.Decision, complete bool) error {
	if decision.Sensitive && decision.RootOnly && !complete {
		return fmt.Errorf("%w: 高权限操作需要完整强认证", ErrMFARequired)
	}
	return nil
}

// mapEvaluateError 把策略评估错误映射为再次认证错误；未实现强度一律 fail-closed。
func (s *Service) mapEvaluateError(err error, decision policy.Decision) error {
	switch {
	case errors.Is(err, policy.ErrVerificationUnavailable):
		return fmt.Errorf("%w: 要求 %q 强度认证", ErrMFARequired, decision.RequiredStrength)
	case errors.Is(err, policy.ErrReauthRequired):
		return ErrReauthRequired
	case errors.Is(err, policy.ErrConfirmationRequired):
		return ErrConfirmationRequired
	case errors.Is(err, policy.ErrOperationUnknown), errors.Is(err, policy.ErrScopeUnknown),
		errors.Is(err, policy.ErrInvalidRequest):
		return fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	case errors.Is(err, policy.ErrStoreUnavailable):
		return ErrPolicyUnavailable
	default:
		return fmt.Errorf("%w: %w", ErrPolicyUnavailable, err)
	}
}

// validateRequest 校验操作上下文，限制参数规模与字符集，避免绑定摘要被滥用。
func (s *Service) validateRequest(request Request) error {
	if request.ScopeID == "" || len(request.ScopeID) > 128 {
		return fmt.Errorf("%w: 作用域非法", ErrInvalidRequest)
	}
	if len(request.OperationID) < 3 || len(request.OperationID) > 128 {
		return fmt.Errorf("%w: 操作标识非法", ErrInvalidRequest)
	}
	if !validTargetType(request.TargetType) {
		return fmt.Errorf("%w: 目标类型非法", ErrInvalidRequest)
	}
	if !validTargetID(request.TargetID) {
		return fmt.Errorf("%w: 目标标识非法", ErrInvalidRequest)
	}
	if len(request.Description) > 256 {
		return fmt.Errorf("%w: 操作说明过长", ErrInvalidRequest)
	}
	if account.ValidateRequestID(request.RequestID) != nil {
		return fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if len(request.Params) > maxParamsFields {
		return fmt.Errorf("%w: 操作参数过多", ErrInvalidRequest)
	}
	for key, value := range request.Params {
		if len(key) == 0 || len(key) > maxParamKeyBytes || len(value) > maxParamValueBytes {
			return fmt.Errorf("%w: 操作参数长度非法", ErrInvalidRequest)
		}
		if !validParamKey(key) {
			return fmt.Errorf("%w: 操作参数名非法", ErrInvalidRequest)
		}
	}
	return nil
}

// recordRejection 为执行前拒绝写失败审计；审计失败不改变拒绝结果。
func (s *Service) recordRejection(ctx context.Context, caller Caller, request Request, cause error) {
	if cause == nil {
		return
	}
	if err := caller.actor.Validate(); err != nil {
		return
	}
	outcome := audit.OutcomeFailure
	if CodeOf(mapCriticalError(cause)) == CodeAccessDenied {
		outcome = audit.OutcomeDenied
	}
	event := audit.Event{
		Actor: caller.actor, Action: "reauth.authorize",
		Target:  audit.Target{Type: "sensitive_operation", ID: safeValue(request.OperationID)},
		Outcome: outcome, ErrorCode: string(CodeOf(mapCriticalError(cause))),
		ReasonCode: "reauth_rejected", RequestID: validRequestID(request.RequestID),
	}
	if err := s.opts.Audit.RecordFailure(ctx, event); err != nil {
		s.opts.Logger.Warn("再次认证拒绝失败审计写入失败", "error", err)
	}
}

// recordVerifyFailure 为密码验证失败写失败审计（不改变拒绝结果）。
func (s *Service) recordVerifyFailure(ctx context.Context, caller Caller, challengeID, reason string) {
	event := audit.Event{
		Actor: caller.actor, Action: "reauth.verify_failed",
		Target:  audit.Target{Type: "reauth_challenge", ID: safeValue(challengeID)},
		Outcome: audit.OutcomeFailure, ErrorCode: string(CodeAuthenticationFailed),
		ReasonCode: safeReason(reason),
	}
	if err := s.opts.Audit.RecordFailure(ctx, event); err != nil {
		s.opts.Logger.Warn("再次认证失败审计写入失败", "error", err)
	}
}

// CodeAuthenticationFailed 是密码验证失败的公开错误码（不细分账户/密码）。
const CodeAuthenticationFailed = CodeAuthFailed

func (s *Service) now() time.Time { return s.opts.Now().UTC().Truncate(time.Millisecond) }

// mapCriticalError 把审计事务错误映射为领域错误，不伪装成功。
func mapCriticalError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, audit.ErrAuditUnavailable):
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	case errors.Is(err, audit.ErrInvalidEvent):
		return fmt.Errorf("%w: 审计事件无效", ErrOptionsInvalid)
	case errors.Is(err, ErrChallengeInvalid), errors.Is(err, ErrApprovalConsumed),
		errors.Is(err, ErrApprovalExpired), errors.Is(err, ErrApprovalInvalid),
		errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrAccessDenied),
		errors.Is(err, ErrMFARequired), errors.Is(err, ErrOptionsInvalid),
		errors.Is(err, ErrIntentInvalid), errors.Is(err, ErrProofBindingMismatch),
		errors.Is(err, ErrSessionMismatch), errors.Is(err, ErrProofUnavailable):
		return err
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, ErrStoreUnavailable), errors.Is(err, ErrPolicyUnavailable):
		return err
	default:
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
}

func toPolicyCaller(actor audit.Actor) (policy.Caller, error) {
	switch actor.Type {
	case audit.ActorUser:
		return policy.UserCaller(actor.ID)
	case audit.ActorSystem:
		return policy.SystemCaller(actor.ID)
	case audit.ActorLocalAdmin:
		return policy.LocalAdminCaller(actor.ID)
	default:
		return policy.Caller{}, ErrAccessDenied
	}
}

func validParamKey(key string) bool {
	for index := 0; index < len(key); index++ {
		character := key[index]
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
			character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return len(key) > 0
}

func validDatabaseID(value, prefix string) bool {
	if len(value) != len(prefix)+32 || value[:len(prefix)] != prefix {
		return false
	}
	for index := len(prefix); index < len(value); index++ {
		character := value[index]
		if (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') {
			continue
		}
		return false
	}
	return true
}

func hexToken(token string) ([]byte, error) {
	if len(token) != 64 {
		return nil, ErrApprovalInvalid
	}
	buffer := make([]byte, 32)
	for index := 0; index < 32; index++ {
		high, ok := hexNibble(token[index*2])
		if !ok {
			return nil, ErrApprovalInvalid
		}
		low, ok := hexNibble(token[index*2+1])
		if !ok {
			return nil, ErrApprovalInvalid
		}
		buffer[index] = high<<4 | low
	}
	return buffer, nil
}

func hexNibble(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	default:
		return 0, false
	}
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	result := byte(0)
	for index := range left {
		result |= left[index] ^ right[index]
	}
	return result == 0
}

func validRequestID(requestID string) string {
	if account.ValidateRequestID(requestID) != nil {
		return ""
	}
	return requestID
}

// safeValue 把目标/操作标识限制为审计可接受的可见 ASCII，非法值替换为空。
func safeValue(value string) string {
	if len(value) == 0 || len(value) > 128 {
		return ""
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '_' ||
			character == '-' || character == ':' || character == '/' {
			continue
		}
		return ""
	}
	return value
}

func safeReason(reason string) string {
	if len(reason) == 0 || len(reason) > 64 {
		return ""
	}
	for index := 0; index < len(reason); index++ {
		character := reason[index]
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '_' {
			continue
		}
		return ""
	}
	return reason
}

func boolText(value bool) string {
	if value {
		return "true"
	}
	return "false"
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

// failureLimiter 是有界进程内失败告知限频器；单实例语义，多实例时可能各自发送一次，
// 但不会无限轰炸（窗口内有限）。
type failureLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	entries map[string][]time.Time
}

// allow 判断某键在本窗口内是否仍可发送，并记录本次时间。
func (l *failureLimiter) allow(key string, now time.Time) bool {
	if l == nil || l.limit <= 0 {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := now.Add(-l.window)
	existing := l.entries[key]
	kept := existing[:0]
	for _, timestamp := range existing {
		if timestamp.After(cutoff) {
			kept = append(kept, timestamp)
		}
	}
	if len(kept) >= l.limit {
		l.entries[key] = kept
		return false
	}
	l.entries[key] = append(kept, now)
	if len(l.entries) > 10000 {
		for candidate, timestamps := range l.entries {
			if len(timestamps) == 0 || !timestamps[len(timestamps)-1].After(cutoff) {
				delete(l.entries, candidate)
			}
		}
	}
	return true
}

// strengthRank 返回认证强度的单调排序，用于“只能提高”的下限比较。
func strengthRank(strength policy.Strength) int {
	switch strength {
	case policy.StrengthStrong:
		return 2
	case policy.StrengthPassword:
		return 1
	default:
		return 0
	}
}
