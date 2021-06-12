package mfa

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authfact"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/credential"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	"github.com/kagurazakayashi/EvernightLogin/internal/passkey"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

const (
	// DefaultCodeTTL 是邮件验证码默认有效期。
	DefaultCodeTTL = 10 * time.Minute
	// MinCodeTTL/MaxCodeTTL 是验证码有效期边界。
	MinCodeTTL = 2 * time.Minute
	MaxCodeTTL = 15 * time.Minute
	// DefaultResendCooldown 是重发验证码冷却。
	DefaultResendCooldown = 60 * time.Second
	// DefaultMaxAttempts 是验证码尝试上限。
	DefaultMaxAttempts = 5
	// DefaultChallengeTTL 是挑战默认有效期。
	DefaultChallengeTTL = 10 * time.Minute
)

// Options 是 MFA 服务依赖。
type Options struct {
	Store       Store
	Audit       AuditRecorder
	Credentials *credential.Service
	// Sessions 是会话签发/校验契约；生产传入 *internal/session.Service。
	Sessions SessionIssuer
	// Mailer 是受控邮件发送接口（复用 internal/mailer）；nil 时发送失败 fail-closed。
	Mailer      mailer.Sender
	Templates   *mailer.TemplateSet
	FromAddress string
	AppName     string
	SupportURL  string
	// TOTP 是 TOTP 第二步因素适配器（步骤 41）；nil 表示未接入，存在 TOTP 因素的
	// 账户按“没有可用因素”处理（强制 MFA 时 fail-closed）。
	TOTP SecondFactorTOTP
	// FactorPreference 是第二步因素优先顺序；默认 Passkey/安全密钥 > TOTP > 邮件
	// （强因素优先）。选择器只会返回用户实际启用且满足策略的因素；未列出的因素
	// 不会被选择。
	FactorPreference []FactorType
	// Passkeys 是 FIDO2 安全密钥第二步适配器；nil 时“安全密钥”因素视为不可用。
	Passkeys SecondFactorPasskey
	// StrongFactorSource 报告账户是否已有强认证因素，用于强认证初始化闭环判定；
	// nil 时视为未就绪（不允许完成初始化）。
	StrongFactorSource StrongFactorSource
	// StrongSetupAuthorizer 授权进入强认证初始化（受控初始化/受邀状态/管理员一次性
	// 凭证或审批）；AllowStrongAuthSetup=true 时必填，nil 或拒绝时初始化 fail-closed。
	StrongSetupAuthorizer StrongSetupAuthorizer
	// Revoker 撤销受限会话；AllowStrongAuthSetup=true 时必须注入。
	Revoker SessionRevoker
	// AllowTOTPForStrongAuth 允许“密码+TOTP”满足管理强认证（受控备用）；默认
	// false，即强认证默认要求 Passkey/安全密钥的用户验证（UV）。显式设为 true
	// 时才接受 TOTP 作为强认证备用方式，并在 README/装配文档说明风险。
	AllowTOTPForStrongAuth bool
	// AllowStrongAuthSetup 允许对“要求强认证但未绑定强因素”的管理账户走受限
	// 初始化闭环（只签发受限会话、绑定允许方式后撤销并要求重新登录）；默认 false
	// 保守拒绝，宿主显式装配后启用。
	AllowStrongAuthSetup bool
	// StrongSetupMethods 是允许在初始化流程中绑定的强因素方法；默认
	// [MethodPasskey]（邮件永远不允许）。宿主必须保证对应绑定入口已限制为受限会话。
	StrongSetupMethods []authfact.Method
	// Policy 是宿主的 MFA 强制策略；nil 表示没有外部强制策略。
	Policy         Policy
	CodeTTL        time.Duration
	ChallengeTTL   time.Duration
	ResendCooldown time.Duration
	MaxAttempts    int
	// RatePolicy 是账户维度有界限流（挑战/验证/重发）；零值使用 DefaultRatePolicy。
	RatePolicy RatePolicy
	Now        func() time.Time
	Random     io.Reader
	Logger     *slog.Logger
}

// Service 是 MFA 状态机服务。构造后不可变，不启动协程，不实现 TOTP/Passkey。
type Service struct {
	opts             Options
	ratePolicy       RatePolicy
	challengeLimiter *counterLimiter
	verifyLimiter    *counterLimiter
	resendLimiter    *counterLimiter
	factorPreference []FactorType
}

// New 校验依赖并构造服务；缺少存储/审计/凭证/会话或邮件配置时拒绝构造（邮件在
// 登录与因素新增时必须可用，不能静默跳过验证码投递）。
func New(options Options) (*Service, error) {
	if isNil(options.Store) {
		return nil, fmt.Errorf("%w: MFA 存储为空", ErrOptionsInvalid)
	}
	if isNil(options.Audit) {
		return nil, fmt.Errorf("%w: 审计写入器为空", ErrOptionsInvalid)
	}
	if options.Credentials == nil {
		return nil, fmt.Errorf("%w: 一次性凭证服务为空", ErrOptionsInvalid)
	}
	if isNil(options.Sessions) {
		return nil, fmt.Errorf("%w: 会话服务为空", ErrOptionsInvalid)
	}
	if isNil(options.TOTP) {
		// 装配契约：mfa 必须与 TOTP 适配器配对注入，否则已绑定 TOTP 的账户可能
		// 被当作“没有因素”而只凭密码登录；宁可拒绝启动也不放行。
		return nil, fmt.Errorf("%w: 必须配对注入 TOTP 适配器", ErrOptionsInvalid)
	}
	if isNil(options.Mailer) {
		return nil, fmt.Errorf("%w: 邮件发送接口为空", ErrOptionsInvalid)
	}
	if _, err := mailer.ParseAddress(options.FromAddress); err != nil {
		return nil, fmt.Errorf("%w: 发件地址无效", ErrOptionsInvalid)
	}
	if options.CodeTTL == 0 {
		options.CodeTTL = DefaultCodeTTL
	}
	if options.CodeTTL < MinCodeTTL || options.CodeTTL > MaxCodeTTL {
		return nil, fmt.Errorf("%w: 验证码有效期必须在 %s～%s 之间", ErrOptionsInvalid, MinCodeTTL, MaxCodeTTL)
	}
	if options.ChallengeTTL == 0 {
		options.ChallengeTTL = DefaultChallengeTTL
	}
	if options.ChallengeTTL < MinCodeTTL || options.ChallengeTTL > MaxCodeTTL+5*time.Minute {
		return nil, fmt.Errorf("%w: 挑战有效期非法", ErrOptionsInvalid)
	}
	if options.ResendCooldown == 0 {
		options.ResendCooldown = DefaultResendCooldown
	}
	if options.ResendCooldown < 10*time.Second || options.ResendCooldown > 10*time.Minute {
		return nil, fmt.Errorf("%w: 重发冷却必须在 10 秒～10 分钟之间", ErrOptionsInvalid)
	}
	if options.MaxAttempts == 0 {
		options.MaxAttempts = DefaultMaxAttempts
	}
	if options.MaxAttempts < 1 || options.MaxAttempts > 10 {
		return nil, fmt.Errorf("%w: 尝试上限必须在 1～10 之间", ErrOptionsInvalid)
	}
	if options.Templates == nil {
		templates, err := mailer.DefaultTemplateSet()
		if err != nil {
			return nil, fmt.Errorf("%w: 默认邮件模板不可用", ErrOptionsInvalid)
		}
		options.Templates = templates
	}
	ratePolicy, err := options.RatePolicy.resolve()
	if err != nil {
		return nil, fmt.Errorf("%w: 限流策略非法", ErrOptionsInvalid)
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
	factorPreference, err := resolveFactorPreference(options.FactorPreference)
	if err != nil {
		return nil, err
	}
	// 认证方式选择策略与强认证初始化闭环的装配约束：缺依赖时 fail-closed。
	if options.AllowStrongAuthSetup {
		if isNil(options.Revoker) || isNil(options.StrongFactorSource) ||
			isNil(options.StrongSetupAuthorizer) {
			return nil, fmt.Errorf(
				"%w: 启用强认证初始化必须注入会话撤销器、强因素来源与受控初始化授权器", ErrOptionsInvalid)
		}
	}
	if options.Passkeys != nil && isNil(options.Passkeys) {
		return nil, fmt.Errorf("%w: 安全密钥适配器为空", ErrOptionsInvalid)
	}
	setupMethods := options.StrongSetupMethods
	if len(setupMethods) == 0 {
		setupMethods = []authfact.Method{authfact.MethodPasskey}
	}
	seenMethod := make(map[authfact.Method]bool, len(setupMethods))
	for _, method := range setupMethods {
		if !method.Valid() || method == authfact.MethodEmailOTP ||
			method == authfact.MethodPassword || method == authfact.MethodRecoveryCode {
			return nil, fmt.Errorf("%w: 强认证初始化只允许 Passkey/安全密钥/TOTP 方法", ErrOptionsInvalid)
		}
		if seenMethod[method] {
			return nil, fmt.Errorf("%w: 强认证初始化方法重复", ErrOptionsInvalid)
		}
		seenMethod[method] = true
	}
	options.StrongSetupMethods = setupMethods
	return &Service{
		opts: options, ratePolicy: ratePolicy, factorPreference: factorPreference,
		challengeLimiter: newCounterLimiter(ratePolicy.ChallengeLimit, ratePolicy.ChallengeWindow),
		verifyLimiter:    newCounterLimiter(ratePolicy.VerifyLimit, ratePolicy.VerifyWindow),
		resendLimiter:    newCounterLimiter(ratePolicy.ResendLimit, ratePolicy.ResendWindow),
	}, nil
}

// BeginLoginRequest 是第一步密码认证成功后的第二步启动请求。
type BeginLoginRequest struct {
	// Result 是 internal/authn 的可信密码认证结果。
	Result authn.AuthenticateResult
	// AppID/ExistingSession/RequestID/RememberMe/Client 传给会话服务签发受限会话。
	AppID           string
	ExistingSession string
	RequestID       string
	RememberMe      bool
	Client          session.ClientInfo
}

// LoginStart 是第二步启动结果。
type LoginStart struct {
	// RequiresSecondFactor=false 表示账户未启用邮件因素，调用方按既有流程登录。
	RequiresSecondFactor bool
	ChallengeID          string
	// AttemptToken 只返回一次；客户端用于验证、重发与取消，不落库明文。
	AttemptToken string
	MaskedEmail  string
	ExpiresAt    time.Time
	FactorType   FactorType
	// RestrictedSession 是限制用途的受限会话；第二步成功后才换成完整会话。
	RestrictedSession session.IssuedSession
	// PasskeyCeremonyID/PasskeyOptions 是安全密钥第二步的 WebAuthn ceremony 与
	// publicKey 选项 JSON（FactorType=passkey 时存在）；Options 不含秘密。
	PasskeyCeremonyID string
	PasskeyOptions    []byte
	// SetupRequired 表示账户要求强认证但尚未绑定强因素，当前处于受限初始化闭环：
	// 只能绑定 AllowedSetupMethods 中的方式，完成后调用 CompleteStrongSetup 并要求
	// 重新登录；绝不会在本流程签发完整会话。
	SetupRequired       bool
	AllowedSetupMethods []authfact.Method
}

// BeginLogin 在密码认证成功后按认证方式选择策略启动第二步：优先 Passkey/安全密钥，
// 其次 TOTP，最后邮件；只选择用户实际启用且满足策略的因素，高权限账户不会降级到
// 邮件。要求强认证但未绑定强因素的管理账户在宿主显式启用时进入受限初始化闭环，
// 只签发受限会话并返回允许绑定的强因素方法，绝不签发完整会话。
func (s *Service) BeginLogin(ctx context.Context, request BeginLoginRequest) (LoginStart, error) {
	ctx = normalizeContext(ctx)
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		return LoginStart{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	base := request.Result
	if !account.ValidUserID(base.UserID) || len(base.CompletedMethods) == 0 {
		return LoginStart{}, fmt.Errorf("%w: 认证结果不完整", ErrInvalidRequest)
	}
	hasPassword := false
	for _, method := range base.CompletedMethods {
		if method == authn.MethodPassword {
			hasPassword = true
		}
	}
	if !hasPassword {
		return LoginStart{}, fmt.Errorf("%w: 缺少密码认证方法", ErrInvalidRequest)
	}
	// 认证结论分析：受限/不完整只能通过“强认证初始化”或强因素第二步继续；
	// 待改密等其余受限原因仍然 fail-closed，不能被第二因素流程绕过。
	requiresStrong := base.Restricted || base.Outcome != authn.OutcomeComplete ||
		len(base.RequiredSteps) > 0
	strongSetupStep := false
	for _, step := range base.RequiredSteps {
		switch step {
		case authn.StepStrongAuthSetup:
			strongSetupStep = true
		case authn.StepPasswordChange:
			s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: base.UserID}, "mfa.begin_denied",
				"password_change_required", string(CodeMFARequired), request.RequestID)
			return LoginStart{}, ErrStrongAuthRequired
		}
	}
	if requiresStrong && !strongSetupStep {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: base.UserID}, "mfa.begin_denied",
			"strong_auth_required", string(CodeMFARequired), request.RequestID)
		return LoginStart{}, ErrStrongAuthRequired
	}
	if !s.challengeLimiter.allow(base.UserID, s.now()) {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: base.UserID}, "mfa.begin_denied",
			"challenge_rate_limited", string(CodeRateLimited), request.RequestID)
		return LoginStart{}, ErrRateLimited
	}
	emailCount, err := s.activeEmailFactor(ctx, base.UserID)
	if err != nil {
		return LoginStart{}, err
	}
	totpActive := false
	if !isNil(s.opts.TOTP) {
		totpActive, err = s.opts.TOTP.HasActive(ctx, base.UserID)
		if err != nil {
			return LoginStart{}, ErrStoreUnavailable
		}
	}
	passkeyActive := false
	if !isNil(s.opts.Passkeys) {
		passkeyActive, err = s.opts.Passkeys.HasSecondFactor(ctx, base.UserID)
		if err != nil {
			return LoginStart{}, ErrStoreUnavailable
		}
	}
	forced := false
	if !isNil(s.opts.Policy) {
		forced, err = s.opts.Policy.MFARequired(ctx, base.UserID)
		if err != nil {
			return LoginStart{}, ErrPolicyUnavailable
		}
	}
	// 认证事实：只把真实完成的密码写入；未完成强认证时不会伪造事实。
	facts := authfact.MustSet(authfact.Fact{Method: authfact.MethodPassword,
		VerifiedAt: base.CompletedAt})
	requirement := authfact.Requirement{Minimum: authfact.StrengthSingle}
	if forced {
		requirement.Minimum = authfact.StrengthMFA
	}
	if requiresStrong {
		// 管理账户要求强认证：默认要求 Passkey/安全密钥完成 UV（RequireUserVerification），
		// 邮件明确不是合格方式；只有在宿主显式 AllowTOTPForStrongAuth 时才允许
		// 密码+TOTP 作为受控备用。
		requirement.Minimum = authfact.StrengthStrong
		requirement.RequireUserVerification = !s.opts.AllowTOTPForStrongAuth
	}
	available := make([]authfact.Available, 0, 3)
	for _, factor := range s.factorPreference {
		switch factor {
		case FactorPasskey:
			if !isNil(s.opts.Passkeys) && passkeyActive {
				available = append(available, authfact.Available{Method: authfact.MethodSecurityKey,
					Enabled: true, SupportsUserVerification: true})
			}
		case FactorTOTP:
			if totpActive {
				available = append(available, authfact.Available{Method: authfact.MethodTOTP, Enabled: true})
			}
		case FactorEmail:
			if emailCount > 0 {
				available = append(available, authfact.Available{Method: authfact.MethodEmailOTP, Enabled: true})
			}
		}
	}
	chosen, selectErr := authfact.Select(facts, available, requirement)
	if selectErr != nil {
		if requiresStrong {
			if s.opts.AllowStrongAuthSetup {
				return s.beginStrongSetup(ctx, base, request)
			}
			s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: base.UserID}, "mfa.begin_denied",
				"strong_factor_missing", string(CodeMFARequired), request.RequestID)
			return LoginStart{}, ErrStrongAuthRequired
		}
		if forced {
			s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: base.UserID}, "mfa.begin_denied",
				"mfa_required_without_factor", string(CodeMFARequired), request.RequestID)
			return LoginStart{}, ErrSecondFactorRequired
		}
		// 非强制、无可用因素：无需第二步，调用方按既有密码流程继续。
		return LoginStart{RequiresSecondFactor: false}, nil
	}
	factor := factorTypeOf(chosen.Method)
	email := ""
	if factor == FactorEmail {
		var found bool
		email, found, err = s.opts.Store.VerifiedEmail(ctx, base.UserID)
		if err != nil {
			return LoginStart{}, ErrStoreUnavailable
		}
		if !found || email == "" {
			s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: base.UserID}, "mfa.begin_denied",
				"no_verified_email", string(CodeMFARequired), request.RequestID)
			return LoginStart{}, ErrNoVerifiedEmail
		}
	}
	username := base.Username
	if username == "" {
		username, _, err = s.opts.Store.Username(ctx, base.UserID)
		if err != nil {
			return LoginStart{}, ErrStoreUnavailable
		}
	}
	now := s.now()
	challengeID, err := newID(s.opts.Random, "mfc_")
	if err != nil {
		return LoginStart{}, err
	}
	attemptToken, attemptDigest, err := newAttemptToken(s.opts.Random)
	if err != nil {
		return LoginStart{}, err
	}
	credentialID := ""
	issuedSecret := ""
	factorRef := ""
	passkeyOptions := []byte(nil)
	passkeyCeremonyID := ""
	if factor == FactorEmail {
		issued, issueErr := s.opts.Credentials.Issue(ctx, credential.IssueRequest{
			Purpose: purposeLoginCode, Target: challengeID, Kind: credential.KindCode,
			TTL: s.opts.CodeTTL, MaxAttempts: s.opts.MaxAttempts,
		})
		if issueErr != nil {
			return LoginStart{}, fmt.Errorf("%w: 无法签发验证码", ErrStoreUnavailable)
		}
		credentialID = issued.ID
		issuedSecret = issued.Secret.Reveal()
	}
	if factor == FactorPasskey {
		// 安全密钥第二步：ceremony 绑定本 MFA 挑战 ID，验证时强制同一上下文。
		if isNil(s.opts.Passkeys) {
			s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: base.UserID}, "mfa.begin_denied",
				"passkey_unavailable", string(CodeMFARequired), request.RequestID)
			return LoginStart{}, ErrNoAvailableMethod
		}
		start, startErr := s.opts.Passkeys.BeginSecondFactor(ctx, base.UserID, challengeID, request.RequestID)
		if startErr != nil {
			s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: base.UserID}, "mfa.begin_denied",
				"passkey_ceremony_failed", string(CodeMFARequired), request.RequestID)
			return LoginStart{}, ErrNoAvailableMethod
		}
		passkeyCeremonyID = start.CeremonyID
		passkeyOptions = start.PublicKey
		factorRef = start.CeremonyID
	}
	challenge := Challenge{
		ID: challengeID, UserID: base.UserID, FactorType: factor, Purpose: PurposeLogin,
		AttemptSHA256: attemptDigest, CredentialID: credentialID, FactorRef: factorRef, Generation: 1,
		State: StatePending, Username: username, AppID: request.AppID,
		RememberMe: request.RememberMe, ClientUserAgent: request.Client.UserAgent,
		ClientAddress: request.Client.Address, Attempts: 0, MaxAttempts: s.opts.MaxAttempts,
		RequireStrong:   requiresStrong,
		SecurityVersion: base.SecurityVersion, CompletedAt: base.CompletedAt,
		ExpiresAt: now.Add(s.opts.CodeTTL), CreatedAt: now, UpdatedAt: now,
	}
	if err := s.createChallenge(ctx, challenge); err != nil {
		if factor == FactorEmail {
			s.cancelCredential(ctx, credentialID, challengeID, purposeLoginCode)
		}
		return LoginStart{}, err
	}
	if factor == FactorEmail {
		if err := s.sendCode(ctx, audit.Actor{Type: audit.ActorUser, ID: base.UserID},
			email, username, issuedSecret, request.RequestID); err != nil {
			s.cancelCredential(ctx, credentialID, challengeID, purposeLoginCode)
			s.failChallenge(ctx, challengeID, attemptDigest, 1, "mail_delivery_failed", request.RequestID)
			return LoginStart{}, err
		}
	}
	maskedEmail := ""
	if factor == FactorEmail {
		maskedEmail = maskAddress(email)
	}
	// 受限会话只在第二步挑战准备好后签发；第一步绝不给完整会话。
	restricted, err := s.opts.Sessions.Login(ctx, session.LoginRequest{
		Result: pendingSecondFactorResult(base), AppID: request.AppID,
		ExistingSession: request.ExistingSession, RequestID: request.RequestID,
		RememberMe: request.RememberMe, Client: request.Client,
	})
	if err != nil {
		s.cancelCredential(ctx, challenge.CredentialID, challengeID, purposeLoginCode)
		s.failChallenge(ctx, challengeID, attemptDigest, 1, "restricted_session_failed", request.RequestID)
		return LoginStart{}, fmt.Errorf("%w: %v", ErrSessionUnavailable, err)
	}
	if restricted.Session.Kind != session.KindRestricted ||
		restricted.Session.Reason != session.ReasonPendingSecondFactor ||
		restricted.Session.AppID != request.AppID {
		s.cancelCredential(ctx, challenge.CredentialID, challengeID, purposeLoginCode)
		s.failChallenge(ctx, challengeID, attemptDigest, 1, "restricted_session_mismatch", request.RequestID)
		return LoginStart{}, fmt.Errorf("%w: 受限会话不符", ErrSessionUnavailable)
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:     audit.Actor{Type: audit.ActorUser, ID: base.UserID},
			Action:    "mfa.challenge_bind",
			Target:    audit.Target{Type: "mfa_challenge", ID: challengeID},
			RequestID: validRequestID(request.RequestID),
			Changes:   []audit.FieldChange{{Field: "restricted_session", After: restricted.Session.ID}},
		},
		FailureReasonCode:   "mfa.challenge_bind_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapCriticalError(err))) },
	}
	err = s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		ok, bindErr := s.opts.Store.BindRestrictedSessionTx(txCtx, tx, challengeID, attemptDigest, 1,
			restricted.Session.ID, now)
		if bindErr != nil {
			return bindErr
		}
		if !ok {
			return ErrChallengeInvalid
		}
		return nil
	})
	if err != nil {
		s.cancelCredential(ctx, challenge.CredentialID, challengeID, purposeLoginCode)
		return LoginStart{}, mapCriticalError(err)
	}
	event := audit.Event{
		Actor:  audit.Actor{Type: audit.ActorUser, ID: base.UserID},
		Action: "mfa.login_challenge", Target: audit.Target{Type: "mfa_challenge", ID: challengeID},
		Outcome: audit.OutcomeSuccess, RequestID: validRequestID(request.RequestID),
		Changes: []audit.FieldChange{
			{Field: "purpose", After: string(PurposeLogin)},
			{Field: "factor_type", After: string(challenge.FactorType)},
			{Field: "recipient", After: maskedEmail},
			{Field: "expires_at_ms", After: fmt.Sprint(challenge.ExpiresAt.UnixMilli())},
		},
	}
	if err := s.opts.Audit.Record(ctx, event); err != nil {
		s.cancelCredential(ctx, challenge.CredentialID, challengeID, purposeLoginCode)
		return LoginStart{}, fmt.Errorf("%w: %v", ErrAuditUnavailable, err)
	}
	start := LoginStart{
		RequiresSecondFactor: true, ChallengeID: challengeID, AttemptToken: attemptToken,
		MaskedEmail: maskedEmail, ExpiresAt: challenge.ExpiresAt, FactorType: challenge.FactorType,
		RestrictedSession: restricted,
	}
	if factor == FactorPasskey {
		start.PasskeyCeremonyID = passkeyCeremonyID
		start.PasskeyOptions = passkeyOptions
	}
	return start, nil
}

// beginStrongSetup 为“要求强认证但尚未绑定强因素”的管理账户创建受限初始化挑战：
// 只签发受限会话、返回允许绑定的强因素方法；绑定成功后必须调用 CompleteStrongSetup
// 撤销受限会话并要求重新登录，绝不在此流程中签发完整会话。
func (s *Service) beginStrongSetup(ctx context.Context, base authn.AuthenticateResult,
	request BeginLoginRequest) (LoginStart, error) {
	// 受控初始化状态校验：普通受限会话不能自助绑定强因素；授权失败 fail-closed，
	// 不创建初始化挑战、不签发受限会话。
	if isNil(s.opts.StrongSetupAuthorizer) {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: base.UserID},
			"mfa.strong_setup_denied", "initialization_not_authorized", string(CodeMFARequired), request.RequestID)
		return LoginStart{}, ErrStrongAuthRequired
	}
	if err := s.opts.StrongSetupAuthorizer.AuthorizeStrongSetup(ctx, base.UserID, request.RequestID); err != nil {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: base.UserID},
			"mfa.strong_setup_denied", "initialization_denied", string(CodeMFARequired), request.RequestID)
		return LoginStart{}, ErrStrongAuthRequired
	}
	methods := s.opts.StrongSetupMethods
	if len(methods) == 0 {
		methods = []authfact.Method{authfact.MethodPasskey}
	}
	now := s.now()
	challengeID, err := newID(s.opts.Random, "mfc_")
	if err != nil {
		return LoginStart{}, err
	}
	attemptToken, attemptDigest, err := newAttemptToken(s.opts.Random)
	if err != nil {
		return LoginStart{}, err
	}
	challenge := Challenge{
		ID: challengeID, UserID: base.UserID, FactorType: FactorPasskey,
		Purpose: PurposeStrongSetup, AttemptSHA256: attemptDigest, Generation: 1,
		State: StatePending, Username: base.Username, AppID: request.AppID,
		RememberMe: request.RememberMe, ClientUserAgent: request.Client.UserAgent,
		ClientAddress: request.Client.Address, Attempts: 0, MaxAttempts: s.opts.MaxAttempts,
		RequireStrong:   true,
		SecurityVersion: base.SecurityVersion, CompletedAt: base.CompletedAt,
		ExpiresAt: now.Add(s.opts.CodeTTL), CreatedAt: now, UpdatedAt: now,
	}
	if err := s.createChallenge(ctx, challenge); err != nil {
		return LoginStart{}, err
	}
	restricted, err := s.opts.Sessions.Login(ctx, session.LoginRequest{
		Result: strongSetupResult(base), AppID: request.AppID,
		ExistingSession: request.ExistingSession, RequestID: request.RequestID,
		RememberMe: request.RememberMe, Client: request.Client,
	})
	if err != nil {
		s.failChallenge(ctx, challengeID, attemptDigest, 1, "restricted_session_failed", request.RequestID)
		return LoginStart{}, fmt.Errorf("%w: %v", ErrSessionUnavailable, err)
	}
	if restricted.Session.Kind != session.KindRestricted ||
		restricted.Session.Reason != session.ReasonPendingSecondFactor ||
		restricted.Session.AppID != request.AppID {
		s.failChallenge(ctx, challengeID, attemptDigest, 1, "restricted_session_mismatch", request.RequestID)
		return LoginStart{}, fmt.Errorf("%w: 受限会话不符", ErrSessionUnavailable)
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:     audit.Actor{Type: audit.ActorUser, ID: base.UserID},
			Action:    "mfa.strong_setup_challenge",
			Target:    audit.Target{Type: "mfa_challenge", ID: challengeID},
			RequestID: validRequestID(request.RequestID),
			Changes: []audit.FieldChange{
				{Field: "purpose", After: string(PurposeStrongSetup)},
				{Field: "restricted_session", After: restricted.Session.ID},
			},
		},
		FailureReasonCode:   "mfa.strong_setup_bind_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapCriticalError(err))) },
	}
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		ok, bindErr := s.opts.Store.BindRestrictedSessionTx(txCtx, tx, challengeID, attemptDigest, 1,
			restricted.Session.ID, now)
		if bindErr != nil {
			return bindErr
		}
		if !ok {
			return ErrChallengeInvalid
		}
		return nil
	}); err != nil {
		return LoginStart{}, mapCriticalError(err)
	}
	return LoginStart{
		RequiresSecondFactor: true, SetupRequired: true, ChallengeID: challengeID,
		AttemptToken: attemptToken, ExpiresAt: challenge.ExpiresAt,
		FactorType: FactorPasskey, AllowedSetupMethods: methods, RestrictedSession: restricted,
	}, nil
}

// StrongSetupCompleteRequest 是强认证初始化完成请求；ExistingSession 必须是初始化
// 挑战绑定的那个受限会话。
type StrongSetupCompleteRequest struct {
	ChallengeID     string
	AttemptToken    string
	ExistingSession string
	RequestID       string
}

// StrongSetupCompleteResult 是初始化完成结果；调用方必须要求用户重新登录，不得
// 据此签发完整会话。
type StrongSetupCompleteResult struct {
	UserID             string
	Methods            []authfact.Method
	MustReauthenticate bool
}

// CompleteStrongSetup 完成强认证初始化闭环：校验受限会话/尝试令牌/挑战状态，确认
// 账户已真实绑定强因素（由 StrongFactorSource 报告），撤销受限会话并标记挑战已完成。
// 本方法不签发会话；邮箱不是允许的初始化方式。
func (s *Service) CompleteStrongSetup(ctx context.Context, request StrongSetupCompleteRequest) (StrongSetupCompleteResult, error) {
	ctx = normalizeContext(ctx)
	attemptDigest, err := hexAttemptToken(request.AttemptToken)
	if err != nil {
		return StrongSetupCompleteResult{}, ErrChallengeInvalid
	}
	challenge, err := s.loadChallenge(ctx, request.ChallengeID)
	if err != nil {
		return StrongSetupCompleteResult{}, err
	}
	if challenge.Purpose != PurposeStrongSetup || challenge.FactorType != FactorPasskey {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: challenge.UserID},
			"mfa.strong_setup_denied", "purpose_mismatch", string(CodeChallengeInvalid), request.RequestID)
		return StrongSetupCompleteResult{}, ErrChallengeInvalid
	}
	if !equalDigest(challenge.AttemptSHA256, attemptDigest) || challenge.State != StatePending {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: challenge.UserID},
			"mfa.strong_setup_denied", "invalid_challenge", string(CodeChallengeInvalid), request.RequestID)
		return StrongSetupCompleteResult{}, ErrChallengeInvalid
	}
	if !s.verifyLimiter.allow(challenge.UserID, s.now()) {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: challenge.UserID},
			"mfa.strong_setup_denied", "verify_rate_limited", string(CodeRateLimited), request.RequestID)
		return StrongSetupCompleteResult{}, ErrRateLimited
	}
	now := s.now()
	if !now.Before(challenge.ExpiresAt) {
		s.transition(ctx, challenge, attemptDigest, challenge.Generation, StateExpired, request.RequestID)
		return StrongSetupCompleteResult{}, ErrChallengeExpired
	}
	sessionRecord, err := s.opts.Sessions.Validate(ctx, request.ExistingSession)
	if err != nil || sessionRecord.UserID != challenge.UserID ||
		!sessionRecord.IsRestricted() || sessionRecord.Kind != session.KindRestricted ||
		sessionRecord.Reason != session.ReasonPendingSecondFactor ||
		sessionRecord.AppID != challenge.AppID ||
		sessionRecord.ID != challenge.RestrictedSessionID || challenge.RestrictedSessionID == "" {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: challenge.UserID},
			"mfa.strong_setup_denied", "restricted_session_invalid", string(CodeChallengeInvalid), request.RequestID)
		return StrongSetupCompleteResult{}, ErrChallengeInvalid
	}
	if isNil(s.opts.StrongFactorSource) || isNil(s.opts.Revoker) {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: challenge.UserID},
			"mfa.strong_setup_denied", "strong_source_unavailable", string(CodeMFARequired), request.RequestID)
		return StrongSetupCompleteResult{}, ErrStrongSetupIncomplete
	}
	hasStrong, err := s.opts.StrongFactorSource.HasStrongFactor(ctx, challenge.UserID)
	if err != nil {
		return StrongSetupCompleteResult{}, ErrPolicyUnavailable
	}
	if !hasStrong {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: challenge.UserID},
			"mfa.strong_setup_denied", "strong_factor_missing", string(CodeMFARequired), request.RequestID)
		return StrongSetupCompleteResult{}, ErrStrongSetupIncomplete
	}
	// 先撤销受限会话，避免留下临时受限通道；撤销失败则 fail-closed 不标记完成。
	if err := s.opts.Revoker.Logout(ctx, request.ExistingSession); err != nil {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: challenge.UserID},
			"mfa.strong_setup_denied", "restricted_session_revoke_failed", string(CodeDBUnavailable), request.RequestID)
		return StrongSetupCompleteResult{}, fmt.Errorf("%w: 撤销受限会话失败", ErrSessionUnavailable)
	}
	if err := s.markVerified(ctx, challenge, attemptDigest, now, request.RequestID); err != nil {
		return StrongSetupCompleteResult{}, err
	}
	methods := s.opts.StrongSetupMethods
	if len(methods) == 0 {
		methods = []authfact.Method{authfact.MethodPasskey}
	}
	event := audit.Event{
		Actor:   audit.Actor{Type: audit.ActorUser, ID: challenge.UserID},
		Action:  "mfa.strong_setup_completed",
		Target:  audit.Target{Type: "mfa_challenge", ID: challenge.ID},
		Outcome: audit.OutcomeSuccess, RequestID: validRequestID(request.RequestID),
		Changes: []audit.FieldChange{{Field: "restricted_session", Before: challenge.RestrictedSessionID,
			After: "revoked"}, {Field: "must_reauthenticate", After: "true"}},
	}
	if err := s.opts.Audit.Record(ctx, event); err != nil {
		return StrongSetupCompleteResult{}, fmt.Errorf("%w: %v", ErrAuditUnavailable, err)
	}
	return StrongSetupCompleteResult{UserID: challenge.UserID, Methods: methods,
		MustReauthenticate: true}, nil
}

// AvailableSecondFactorMethods 返回用户当前实际启用且满足策略的第二因素方法
// （按 FactorPreference 顺序；强制 MFA 时邮件仍可作为 MFA 的第二步，但满足强认证
// 时不接受邮件，见 BeginLogin 选择器）。空列表表示没有可用方式，不泄露其他账户。
func (s *Service) AvailableSecondFactorMethods(ctx context.Context, caller Caller,
	userID string) ([]authfact.Method, error) {
	ctx = normalizeContext(ctx)
	if err := caller.actor.Validate(); err != nil {
		return nil, ErrAccessDenied
	}
	// 只允许本人查询；系统组件（可信装配层）可代为查询，普通用户不能枚举他人。
	if caller.actor.Type == audit.ActorUser && caller.actor.ID != userID {
		return nil, ErrAccessDenied
	}
	if !account.ValidUserID(userID) {
		return nil, ErrInvalidRequest
	}
	emailCount, err := s.activeEmailFactor(ctx, userID)
	if err != nil {
		return nil, err
	}
	totpActive := false
	if !isNil(s.opts.TOTP) {
		totpActive, err = s.opts.TOTP.HasActive(ctx, userID)
		if err != nil {
			return nil, ErrStoreUnavailable
		}
	}
	passkeyActive := false
	if !isNil(s.opts.Passkeys) {
		passkeyActive, err = s.opts.Passkeys.HasSecondFactor(ctx, userID)
		if err != nil {
			return nil, ErrStoreUnavailable
		}
	}
	forced := false
	if !isNil(s.opts.Policy) {
		forced, err = s.opts.Policy.MFARequired(ctx, userID)
		if err != nil {
			return nil, ErrPolicyUnavailable
		}
	}
	requirement := authfact.Requirement{Minimum: authfact.StrengthSingle}
	if forced {
		requirement.Minimum = authfact.StrengthMFA
	}
	// 第一因素已完成密码；列表语义是“密码之后可用的第二因素”。
	facts := authfact.MustSet(authfact.Fact{Method: authfact.MethodPassword,
		VerifiedAt: s.now()})
	available := make([]authfact.Available, 0, 3)
	for _, factor := range s.factorPreference {
		switch factor {
		case FactorPasskey:
			if !isNil(s.opts.Passkeys) && passkeyActive {
				available = append(available, authfact.Available{Method: authfact.MethodSecurityKey,
					Enabled: true, SupportsUserVerification: true})
			}
		case FactorTOTP:
			if totpActive {
				available = append(available, authfact.Available{Method: authfact.MethodTOTP, Enabled: true})
			}
		case FactorEmail:
			if emailCount > 0 {
				available = append(available, authfact.Available{Method: authfact.MethodEmailOTP, Enabled: true})
			}
		}
	}
	eligible := authfact.Eligible(facts, available, requirement)
	methods := make([]authfact.Method, 0, len(eligible))
	for _, candidate := range eligible {
		methods = append(methods, candidate.Method)
	}
	return methods, nil
}

// Verify 校验邮件验证码并原子消费挑战；成功后用受限会话秘密轮换签发完整普通会话。
func (s *Service) Verify(ctx context.Context, request VerifyRequest) (VerifyResult, error) {
	ctx = normalizeContext(ctx)
	attemptDigest, err := hexAttemptToken(request.AttemptToken)
	if err != nil {
		return VerifyResult{}, ErrChallengeInvalid
	}
	challenge, err := s.loadChallenge(ctx, request.ChallengeID)
	if err != nil {
		return VerifyResult{}, err
	}
	if !equalDigest(challenge.AttemptSHA256, attemptDigest) {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: challenge.UserID},
			"mfa.verify_failed", "attempt_mismatch", string(CodeChallengeInvalid), request.RequestID)
		return VerifyResult{}, ErrChallengeInvalid
	}
	if challenge.Purpose != PurposeLogin {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: challenge.UserID},
			"mfa.verify_failed", "purpose_mismatch", string(CodeChallengeInvalid), request.RequestID)
		return VerifyResult{}, ErrChallengeInvalid
	}
	if challenge.State != StatePending {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: challenge.UserID},
			"mfa.verify_failed", "state_not_pending", string(CodeChallengeInvalid), request.RequestID)
		return VerifyResult{}, ErrChallengeInvalid
	}
	if !s.verifyLimiter.allow(challenge.UserID, s.now()) {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: challenge.UserID},
			"mfa.verify_failed", "verify_rate_limited", string(CodeRateLimited), request.RequestID)
		return VerifyResult{}, ErrRateLimited
	}
	now := s.now()
	if !now.Before(challenge.ExpiresAt) {
		s.transition(ctx, challenge, attemptDigest, challenge.Generation, StateExpired, request.RequestID)
		return VerifyResult{}, ErrChallengeExpired
	}
	// 受限会话必须正是第一步为本挑战签发的那一个：同用户、同应用作用域、受限
	// 原因为待第二因素且会话 ID 与挑战绑定值一致；其他受限会话不能完成本挑战。
	sessionRecord, err := s.opts.Sessions.Validate(ctx, request.ExistingSession)
	if err != nil || sessionRecord.UserID != challenge.UserID ||
		!sessionRecord.IsRestricted() || sessionRecord.Kind != session.KindRestricted ||
		sessionRecord.Reason != session.ReasonPendingSecondFactor ||
		sessionRecord.AppID != challenge.AppID ||
		sessionRecord.ID != challenge.RestrictedSessionID || challenge.RestrictedSessionID == "" {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: challenge.UserID},
			"mfa.verify_failed", "restricted_session_invalid", string(CodeChallengeInvalid), request.RequestID)
		return VerifyResult{}, ErrChallengeInvalid
	}
	if challenge.Purpose != PurposeLogin {
		// 强认证初始化挑战只能通过 CompleteStrongSetup 完成，不能当作登录第二步。
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: challenge.UserID},
			"mfa.verify_failed", "purpose_mismatch", string(CodeChallengeInvalid), request.RequestID)
		return VerifyResult{}, ErrChallengeInvalid
	}
	factorMethod := authfact.MethodEmailOTP
	strongAuthAt := time.Time{}
	userVerified := false
	authenticatorRef := ""
	switch challenge.FactorType {
	case FactorPasskey:
		if isNil(s.opts.Passkeys) || request.PasskeyCeremonyID == "" || len(request.PasskeyResponse) == 0 ||
			request.PasskeyCeremonyID != challenge.FactorRef {
			s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: challenge.UserID},
				"mfa.verify_failed", "passkey_ceremony_invalid", string(CodeChallengeInvalid), request.RequestID)
			return VerifyResult{}, ErrChallengeInvalid
		}
		result, passkeyErr := s.opts.Passkeys.FinishSecondFactor(ctx, passkey.SecondFactorFinishRequest{
			CeremonyID: request.PasskeyCeremonyID, ContextID: challenge.ID,
			Response: request.PasskeyResponse, RequestID: request.RequestID,
		})
		if passkeyErr != nil {
			s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: challenge.UserID},
				"mfa.verify_failed", "passkey_invalid", string(CodeChallengeInvalid), request.RequestID)
			if s.recordFailedAttempt(ctx, challenge, attemptDigest, now, request.RequestID) {
				return VerifyResult{}, ErrAttemptsExceeded
			}
			return VerifyResult{}, ErrCodeInvalid
		}
		if result.UserID != challenge.UserID {
			s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: challenge.UserID},
				"mfa.verify_failed", "passkey_user_mismatch", string(CodeChallengeInvalid), request.RequestID)
			return VerifyResult{}, ErrChallengeInvalid
		}
		if challenge.RequireStrong && !result.UserVerified {
			// 策略要求强认证时，未完成用户验证的安全密钥断言不能算强认证，也不
			// 能降级为普通第二步；计入尝试次数并明确拒绝。
			s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: challenge.UserID},
				"mfa.verify_failed", "strong_auth_uv_missing", string(CodeMFARequired), request.RequestID)
			if s.recordFailedAttempt(ctx, challenge, attemptDigest, now, request.RequestID) {
				return VerifyResult{}, ErrAttemptsExceeded
			}
			return VerifyResult{}, ErrStrongAuthRequired
		}
		if err := s.markVerified(ctx, challenge, attemptDigest, now, request.RequestID); err != nil {
			return VerifyResult{}, err
		}
		challenge.State = StateVerified
		challenge.VerifiedAt = result.VerifiedAt
		factorMethod = authfact.MethodSecurityKey
		userVerified = result.UserVerified
		authenticatorRef = result.AuthenticatorID
		if result.UserVerified {
			strongAuthAt = now
		}
	case FactorTOTP:
		if request.Code == "" || len(request.Code) > 64 {
			return VerifyResult{}, ErrCodeInvalid
		}
		factorMethod = authfact.MethodTOTP
		// 门控：只有挑战明确要求强认证且宿主显式允许“密码+TOTP”满足强认证时才
		// 记录强认证时间；普通 MFA 的 TOTP 只完成登录，不授予管理访问强认证。
		if challenge.RequireStrong && s.opts.AllowTOTPForStrongAuth {
			strongAuthAt = now
		}
		if isNil(s.opts.TOTP) {
			s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: challenge.UserID},
				"mfa.verify_failed", "totp_unavailable", string(CodeChallengeInvalid), request.RequestID)
			return VerifyResult{}, ErrChallengeInvalid
		}
		if err := s.opts.TOTP.VerifyLoginCode(ctx, challenge.UserID, request.Code); err != nil {
			s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: challenge.UserID},
				"mfa.verify_failed", "totp_invalid", string(CodeChallengeInvalid), request.RequestID)
			if s.recordFailedAttempt(ctx, challenge, attemptDigest, now, request.RequestID) {
				return VerifyResult{}, ErrAttemptsExceeded
			}
			return VerifyResult{}, ErrCodeInvalid
		}
		if err := s.markVerified(ctx, challenge, attemptDigest, now, request.RequestID); err != nil {
			return VerifyResult{}, err
		}
		challenge.State = StateVerified
		challenge.VerifiedAt = now
	case FactorEmail:
		if request.Code == "" || len(request.Code) > 64 {
			return VerifyResult{}, ErrCodeInvalid
		}
		if _, err := s.opts.Credentials.VerifyAndConsume(ctx, credential.VerifyRequest{
			Kind: credential.KindCode, ID: challenge.CredentialID, Purpose: purposeLoginCode,
			Target: challenge.ID, Secret: request.Code,
		}); err != nil {
			// 验证码错误/过期/重放：凭证服务保证尝试上限与原子消费；挑战自身也记录
			// 尝试计数并在达到上限时迁移 failed（状态机完整性）。
			if errors.Is(err, credential.ErrStoreUnavailable) {
				return VerifyResult{}, ErrStoreUnavailable
			}
			if s.recordFailedAttempt(ctx, challenge, attemptDigest, now, request.RequestID) {
				return VerifyResult{}, ErrAttemptsExceeded
			}
			return VerifyResult{}, ErrCodeInvalid
		}
		if err := s.markVerified(ctx, challenge, attemptDigest, now, request.RequestID); err != nil {
			return VerifyResult{}, err
		}
		challenge.State = StateVerified
		challenge.VerifiedAt = now
	default:
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: challenge.UserID},
			"mfa.verify_failed", "unsupported_factor", string(CodeMFARequired), request.RequestID)
		return VerifyResult{}, fmt.Errorf("%w: 不支持的第二步方式", ErrNoAvailableMethod)
	}
	completedAt := now
	authenticated := completeResult(challenge, completedAt, factorMethod, strongAuthAt)
	issued, err := s.opts.Sessions.Login(ctx, session.LoginRequest{
		Result: authenticated, AppID: challenge.AppID, ExistingSession: request.ExistingSession,
		RequestID: request.RequestID, RememberMe: challenge.RememberMe,
		Client: session.ClientInfo{UserAgent: challenge.ClientUserAgent,
			Address: challenge.ClientAddress},
	})
	if err != nil {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: challenge.UserID},
			"mfa.verify_failed", "complete_session_failed", string(CodeDBUnavailable), request.RequestID)
		return VerifyResult{}, fmt.Errorf("%w: %v", ErrSessionUnavailable, err)
	}
	// 防御性复验：完整会话不得改变应用作用域，也不能仍是受限会话。
	if issued.Session.IsRestricted() || issued.Session.AppID != challenge.AppID {
		return VerifyResult{}, fmt.Errorf("%w: 完整会话作用域不符", ErrSessionUnavailable)
	}
	facts := authfact.MustSet(
		authfact.Fact{Method: authfact.MethodPassword, VerifiedAt: challenge.CompletedAt},
		authfact.Fact{Method: factorMethod, VerifiedAt: completedAt,
			UserVerified: userVerified, AuthenticatorID: authenticatorRef},
	)
	return VerifyResult{Session: issued, Authenticated: authenticated, ChallengeID: challenge.ID,
		Method: string(factorMethod), AMR: authfact.AMR(facts), ACR: authfact.ACR(facts),
		Strength: facts.Strength().String()}, nil
}

// ResendRequest 是重发验证码请求。
type ResendRequest struct {
	ChallengeID  string
	AttemptToken string
	RequestID    string
}

// Resend 在冷却后重发验证码，并使旧验证码失效（ReplaceActive + 代数递增）。
func (s *Service) Resend(ctx context.Context, request ResendRequest) (LoginStart, error) {
	ctx = normalizeContext(ctx)
	attemptDigest, err := hexAttemptToken(request.AttemptToken)
	if err != nil {
		return LoginStart{}, ErrChallengeInvalid
	}
	challenge, err := s.loadChallenge(ctx, request.ChallengeID)
	if err != nil {
		return LoginStart{}, err
	}
	if challenge.FactorType != FactorEmail {
		// TOTP 没有“重发验证码”；重发接口只服务邮件因素，避免对 TOTP 挑战发邮件。
		return LoginStart{}, fmt.Errorf("%w: 该因素不支持重发", ErrInvalidRequest)
	}
	if challenge.Purpose != PurposeLogin || !equalDigest(challenge.AttemptSHA256, attemptDigest) ||
		challenge.State != StatePending {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: challenge.UserID},
			"mfa.resend_denied", "invalid_challenge", string(CodeChallengeInvalid), request.RequestID)
		return LoginStart{}, ErrChallengeInvalid
	}
	if !s.resendLimiter.allow(challenge.UserID, s.now()) {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: challenge.UserID},
			"mfa.resend_denied", "resend_rate_limited", string(CodeRateLimited), request.RequestID)
		return LoginStart{}, ErrRateLimited
	}
	now := s.now()
	if !now.Before(challenge.ExpiresAt) {
		return LoginStart{}, ErrChallengeExpired
	}
	if now.Sub(challenge.UpdatedAt) < s.opts.ResendCooldown {
		s.recordFailure(ctx, audit.Actor{Type: audit.ActorUser, ID: challenge.UserID},
			"mfa.resend_denied", "cooldown", string(CodeRateLimited), request.RequestID)
		return LoginStart{}, ErrRateLimited
	}
	email, found, err := s.opts.Store.VerifiedEmail(ctx, challenge.UserID)
	if err != nil {
		return LoginStart{}, ErrStoreUnavailable
	}
	if !found || email == "" {
		return LoginStart{}, ErrNoVerifiedEmail
	}
	issued, err := s.opts.Credentials.Issue(ctx, credential.IssueRequest{
		Purpose: purposeLoginCode, Target: challenge.ID, Kind: credential.KindCode,
		TTL: s.opts.CodeTTL, MaxAttempts: s.opts.MaxAttempts, ReplaceActive: true,
	})
	if err != nil {
		return LoginStart{}, ErrStoreUnavailable
	}
	expiresAt := challenge.ExpiresAt
	if candidate := now.Add(s.opts.CodeTTL); candidate.Before(expiresAt) || challenge.ExpiresAt.Before(now) {
		expiresAt = candidate
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:  audit.Actor{Type: audit.ActorUser, ID: challenge.UserID},
			Action: "mfa.resend", Target: audit.Target{Type: "mfa_challenge", ID: challenge.ID},
			RequestID: validRequestID(request.RequestID),
			Changes: []audit.FieldChange{
				{Field: "generation", After: "incremented"},
				{Field: "recipient", After: maskAddress(email)},
			},
		},
		FailureReasonCode:   "mfa.resend_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapCriticalError(err))) },
	}
	err = s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		generation, ok, rotateErr := s.opts.Store.RotateChallengeTx(txCtx, tx, challenge.ID,
			attemptDigest, challenge.Generation, issued.ID, expiresAt, now)
		if rotateErr != nil {
			return rotateErr
		}
		if !ok {
			return ErrChallengeInvalid
		}
		_ = generation
		return nil
	})
	if err != nil {
		s.cancelCredential(ctx, issued.ID, challenge.ID, purposeLoginCode)
		return LoginStart{}, mapCriticalError(err)
	}
	if err := s.sendCode(ctx, audit.Actor{Type: audit.ActorUser, ID: challenge.UserID}, email, challenge.Username, issued.Secret.Reveal(), request.RequestID); err != nil {
		s.cancelCredential(ctx, issued.ID, challenge.ID, purposeLoginCode)
		return LoginStart{}, err
	}
	return LoginStart{RequiresSecondFactor: true, ChallengeID: challenge.ID,
		MaskedEmail: maskAddress(email), ExpiresAt: expiresAt, FactorType: challenge.FactorType,
		AttemptToken: request.AttemptToken}, nil
}

// CancelRequest 是取消未完成 MFA 登录挑战的请求；ExistingSession 用于同时撤销
// 第一步已签发的受限会话，避免取消后残留半登录会话。
type CancelRequest struct {
	ChallengeID     string
	AttemptToken    string
	ExistingSession string
	RequestID       string
}

// CancelLogin 取消未完成的 MFA 登录挑战并撤销其绑定的受限会话。
func (s *Service) CancelLogin(ctx context.Context, request CancelRequest) error {
	ctx = normalizeContext(ctx)
	attemptDigest, err := hexAttemptToken(request.AttemptToken)
	if err != nil {
		return ErrChallengeInvalid
	}
	challenge, err := s.loadChallenge(ctx, request.ChallengeID)
	if err != nil {
		return err
	}
	if challenge.Purpose != PurposeLogin || !equalDigest(challenge.AttemptSHA256, attemptDigest) {
		return ErrChallengeInvalid
	}
	if challenge.State != StatePending {
		return ErrChallengeInvalid
	}
	if err := s.transition(ctx, challenge, attemptDigest, challenge.Generation, StateCancelled, request.RequestID); err != nil {
		return err
	}
	s.cancelCredential(ctx, challenge.CredentialID, challenge.ID, challengePurpose(challenge.Purpose))
	// 受限会话不能通过普通用户撤销 API 撤销（受限会话无业务访问权），本方法只
	// 取消挑战与验证码；已签发受限会话由宿主会话管理/到期回收，不作为已认证状态。
	return nil
}

// FactorEnrollmentRequest 是新增邮箱因素请求（仅需要请求编号）。
type FactorEnrollmentRequest struct {
	RequestID string
}

// FactorEnrollment 是新增因素验证码投递结果。
type FactorEnrollment struct {
	ChallengeID  string
	AttemptToken string
	MaskedEmail  string
	ExpiresAt    time.Time
}

// BeginEmailFactorEnrollment 向已验证邮箱发送验证码以证明渠道控制权；已启用邮件
// 因素时返回 CONFLICT，不允许静默覆盖。
func (s *Service) BeginEmailFactorEnrollment(ctx context.Context, caller Caller,
	request FactorEnrollmentRequest) (FactorEnrollment, error) {
	ctx = normalizeContext(ctx)
	if err := caller.actor.Validate(); err != nil || !caller.IsUser() {
		return FactorEnrollment{}, ErrAccessDenied
	}
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		return FactorEnrollment{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if !s.challengeLimiter.allow(caller.actor.ID, s.now()) {
		s.recordFailure(ctx, caller.actor, "mfa.factor_add_denied", "challenge_rate_limited",
			string(CodeRateLimited), request.RequestID)
		return FactorEnrollment{}, ErrRateLimited
	}
	active, err := s.activeEmailFactor(ctx, caller.actor.ID)
	if err != nil {
		return FactorEnrollment{}, err
	}
	if active > 0 {
		return FactorEnrollment{}, ErrFactorExists
	}
	email, found, err := s.opts.Store.VerifiedEmail(ctx, caller.actor.ID)
	if err != nil {
		return FactorEnrollment{}, ErrStoreUnavailable
	}
	if !found || email == "" {
		s.recordFailure(ctx, caller.actor, "mfa.factor_add_denied", "no_verified_email",
			string(CodeMFARequired), request.RequestID)
		return FactorEnrollment{}, ErrNoVerifiedEmail
	}
	username, _, err := s.opts.Store.Username(ctx, caller.actor.ID)
	if err != nil {
		return FactorEnrollment{}, ErrStoreUnavailable
	}
	now := s.now()
	challengeID, err := newID(s.opts.Random, "mfc_")
	if err != nil {
		return FactorEnrollment{}, err
	}
	attemptToken, attemptDigest, err := newAttemptToken(s.opts.Random)
	if err != nil {
		return FactorEnrollment{}, err
	}
	issued, err := s.opts.Credentials.Issue(ctx, credential.IssueRequest{
		Purpose: purposeFactorEnrollCode, Target: challengeID, Kind: credential.KindCode,
		TTL: s.opts.CodeTTL, MaxAttempts: s.opts.MaxAttempts,
	})
	if err != nil {
		return FactorEnrollment{}, ErrStoreUnavailable
	}
	challenge := Challenge{
		ID: challengeID, UserID: caller.actor.ID, FactorType: FactorEmail, Purpose: PurposeFactorEnroll,
		AttemptSHA256: attemptDigest, CredentialID: issued.ID, Generation: 1,
		State: StatePending, Username: username, Attempts: 0, MaxAttempts: s.opts.MaxAttempts,
		ExpiresAt: now.Add(s.opts.CodeTTL), CreatedAt: now, UpdatedAt: now,
	}
	if err := s.createChallenge(ctx, challenge); err != nil {
		s.cancelCredential(ctx, issued.ID, challengeID, purposeFactorEnrollCode)
		return FactorEnrollment{}, err
	}
	if err := s.sendCode(ctx, caller.actor, email, username, issued.Secret.Reveal(), request.RequestID); err != nil {
		s.cancelCredential(ctx, issued.ID, challengeID, purposeFactorEnrollCode)
		s.failChallenge(ctx, challengeID, attemptDigest, 1, "mail_delivery_failed", request.RequestID)
		return FactorEnrollment{}, err
	}
	return FactorEnrollment{ChallengeID: challengeID, AttemptToken: attemptToken,
		MaskedEmail: maskAddress(email), ExpiresAt: challenge.ExpiresAt}, nil
}

// FactorVerifyRequest 是新增因素验证请求。
type FactorVerifyRequest struct {
	ChallengeID  string
	AttemptToken string
	Code         string
	RequestID    string
}

// ConfirmEmailFactorEnrollment 验证渠道控制权后启用邮件因素；验证码错误/过期/重放
// 均不启用因素。
func (s *Service) ConfirmEmailFactorEnrollment(ctx context.Context, caller Caller,
	request FactorVerifyRequest) (Factor, error) {
	ctx = normalizeContext(ctx)
	if err := caller.actor.Validate(); err != nil || !caller.IsUser() {
		return Factor{}, ErrAccessDenied
	}
	attemptDigest, err := hexAttemptToken(request.AttemptToken)
	if err != nil {
		return Factor{}, ErrChallengeInvalid
	}
	challenge, err := s.loadChallenge(ctx, request.ChallengeID)
	if err != nil {
		return Factor{}, err
	}
	if challenge.UserID != caller.actor.ID || challenge.Purpose != PurposeFactorEnroll ||
		!equalDigest(challenge.AttemptSHA256, attemptDigest) {
		return Factor{}, ErrChallengeInvalid
	}
	if challenge.State != StatePending {
		s.recordFailure(ctx, caller.actor, "mfa.factor_verify_failed", "state_not_pending",
			string(CodeChallengeInvalid), request.RequestID)
		return Factor{}, ErrChallengeInvalid
	}
	now := s.now()
	if !now.Before(challenge.ExpiresAt) {
		s.transition(ctx, challenge, attemptDigest, challenge.Generation, StateExpired, request.RequestID)
		return Factor{}, ErrChallengeExpired
	}
	if _, err := s.opts.Credentials.VerifyAndConsume(ctx, credential.VerifyRequest{
		Kind: credential.KindCode, ID: challenge.CredentialID, Purpose: purposeFactorEnrollCode,
		Target: challenge.ID, Secret: request.Code,
	}); err != nil {
		s.recordFailure(ctx, caller.actor, "mfa.factor_verify_failed", "code_invalid",
			string(CodeChallengeInvalid), request.RequestID)
		return Factor{}, ErrCodeInvalid
	}
	factor := Factor{ID: "", UserID: challenge.UserID, Type: FactorEmail, State: "active",
		CreatedAt: now}
	factorID, err := newID(s.opts.Random, "mft_")
	if err != nil {
		return Factor{}, err
	}
	factor.ID = factorID
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: caller.actor, Action: "mfa.factor_added",
			Target:    audit.Target{Type: "user", ID: challenge.UserID},
			RequestID: validRequestID(request.RequestID),
			Changes:   []audit.FieldChange{{Field: "factor_type", After: string(FactorEmail)}},
		},
		FailureReasonCode:   "mfa.factor_add_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapCriticalError(err))) },
	}
	err = s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		ok, updateErr := s.opts.Store.UpdateChallengeStateTx(txCtx, tx, challenge.ID, attemptDigest,
			challenge.Generation, StatePending, StateVerified, now)
		if updateErr != nil {
			return updateErr
		}
		if !ok {
			return ErrChallengeInvalid
		}
		if insertErr := s.opts.Store.InsertFactorTx(txCtx, tx, factor); insertErr != nil {
			return fmt.Errorf("%w: %v", ErrFactorExists, insertErr)
		}
		return nil
	})
	if err != nil {
		return Factor{}, mapCriticalError(err)
	}
	return factor, nil
}

// RemoveEmailFactor 停用当前用户的邮件因素。被 Policy 强制要求 MFA 时，不能移除
// 最后一个可用因素（当前只实现 email 类型）。
func (s *Service) RemoveEmailFactor(ctx context.Context, caller Caller, requestID string) error {
	ctx = normalizeContext(ctx)
	if err := caller.actor.Validate(); err != nil || !caller.IsUser() {
		return ErrAccessDenied
	}
	if err := account.ValidateRequestID(requestID); err != nil {
		return fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	active, err := s.activeEmailFactor(ctx, caller.actor.ID)
	if err != nil {
		return err
	}
	if active == 0 {
		return ErrFactorNotFound
	}
	if !isNil(s.opts.Policy) {
		forced, policyErr := s.opts.Policy.MFARequired(ctx, caller.actor.ID)
		if policyErr != nil {
			return ErrPolicyUnavailable
		}
		if forced {
			// 当前只有 email 一种因素：强制 MFA 的用户移除它就是移除最后一个可用
			// 因素，必须拒绝；后续因素类型接入后这里按“其他因素数量”判断。
			s.recordFailure(ctx, caller.actor, "mfa.factor_remove_denied", "last_factor",
				string(CodeConflict), requestID)
			return ErrFactorRequired
		}
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor: caller.actor, Action: "mfa.factor_removed",
			Target:    audit.Target{Type: "user", ID: caller.actor.ID},
			RequestID: validRequestID(requestID),
			Changes:   []audit.FieldChange{{Field: "factor_type", Before: string(FactorEmail)}},
		},
		FailureReasonCode:   "mfa.factor_remove_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapCriticalError(err))) },
	}
	err = s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		removed, removeErr := s.opts.Store.RemoveFactorTx(txCtx, tx, caller.actor.ID, FactorEmail)
		if removeErr != nil {
			return removeErr
		}
		if !removed {
			return ErrFactorNotFound
		}
		return nil
	})
	if err != nil {
		return mapCriticalError(err)
	}
	return nil
}

// Factors 返回调用者自己的因素列表；普通用户只能读自己。
func (s *Service) Factors(ctx context.Context, caller Caller) ([]Factor, error) {
	ctx = normalizeContext(ctx)
	if err := caller.actor.Validate(); err != nil || !caller.IsUser() {
		return nil, ErrAccessDenied
	}
	factors, err := s.opts.Store.GetFactors(ctx, caller.actor.ID)
	if err != nil {
		return nil, ErrStoreUnavailable
	}
	return factors, nil
}

// 生产适配器编译期契约固化：安全密钥第二步使用真实 *passkey.Service，会话撤销
// 使用真实 *session.Service（测试替身只允许出现在测试路径）。
var (
	_ SecondFactorPasskey = (*passkey.Service)(nil)
	_ SessionRevoker      = (*session.Service)(nil)
)

// ===== 内部辅助 =====

func (s *Service) activeEmailFactor(ctx context.Context, userID string) (int, error) {
	count, err := s.opts.Store.CountActiveFactors(ctx, userID, FactorEmail)
	if err != nil {
		return 0, ErrStoreUnavailable
	}
	return count, nil
}

func (s *Service) createChallenge(ctx context.Context, challenge Challenge) error {
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:  audit.Actor{Type: audit.ActorUser, ID: challenge.UserID},
			Action: "mfa.challenge_created",
			Target: audit.Target{Type: "mfa_challenge", ID: challenge.ID},
			Changes: []audit.FieldChange{
				{Field: "purpose", After: string(challenge.Purpose)},
				{Field: "factor_type", After: string(challenge.FactorType)},
			},
		},
		FailureReasonCode:   "mfa.challenge_create_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapCriticalError(err))) },
	}
	err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		return s.opts.Store.CreateChallengeTx(txCtx, tx, challenge)
	})
	if err != nil {
		return mapCriticalError(err)
	}
	return nil
}

// loadChallenge 读取挑战并统一映射存储错误。
func (s *Service) loadChallenge(ctx context.Context, challengeID string) (Challenge, error) {
	if !validChallengeID(challengeID) {
		return Challenge{}, ErrChallengeInvalid
	}
	challenge, found, err := s.opts.Store.GetChallenge(ctx, challengeID)
	if err != nil {
		return Challenge{}, ErrStoreUnavailable
	}
	if !found {
		return Challenge{}, ErrChallengeInvalid
	}
	return challenge, nil
}

// transition 条件迁移挑战状态并写审计；失败只记录日志（拒绝结果仍由调用方返回）。
func (s *Service) transition(ctx context.Context, challenge Challenge, attemptDigest []byte,
	generation int, to ChallengeState, requestID string) error {
	now := s.now()
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:     audit.Actor{Type: audit.ActorUser, ID: challenge.UserID},
			Action:    "mfa.challenge_" + string(to),
			Target:    audit.Target{Type: "mfa_challenge", ID: challenge.ID},
			RequestID: validRequestID(requestID),
		},
		FailureReasonCode:   "mfa.challenge_state_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapCriticalError(err))) },
	}
	err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		ok, updateErr := s.opts.Store.UpdateChallengeStateTx(txCtx, tx, challenge.ID, attemptDigest,
			generation, challenge.State, to, now)
		if updateErr != nil {
			return updateErr
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

// sendCode 渲染并发送验证码邮件。明文验证码只进入邮件正文；错误/日志/审计不含它。
func (s *Service) sendCode(ctx context.Context, actor audit.Actor, email, username, code, requestID string) error {
	content, err := s.opts.Templates.Render(mailer.RenderRequest{
		Kind: mailer.KindVerification,
		Verification: &mailer.VerificationData{
			DisplayName: username, Code: code,
			ExpiresIn: formatDuration(s.opts.CodeTTL), AppName: s.opts.AppName,
		},
	})
	if err != nil {
		s.recordFailure(ctx, actor, "mfa.mail_failed", "template_invalid", string(CodeMailDeliveryFailed), requestID)
		return fmt.Errorf("%w: 模板渲染失败", ErrMailFailed)
	}
	from, fromErr := mailer.ParseAddress(s.opts.FromAddress)
	to, toErr := mailer.ParseAddress(email)
	if fromErr != nil || toErr != nil {
		return fmt.Errorf("%w: 地址无效", ErrMailFailed)
	}
	if err := s.opts.Mailer.Send(ctx, mailer.Message{From: from, To: []mailer.Address{to},
		Subject: content.Subject, TextBody: content.TextBody}); err != nil {
		s.recordFailure(ctx, actor, "mfa.mail_failed", "delivery_failed", string(CodeMailDeliveryFailed), requestID)
		return fmt.Errorf("%w: 投递失败", ErrMailFailed)
	}
	return nil
}

func challengePurpose(purpose Purpose) string {
	if purpose == PurposeFactorEnroll {
		return purposeFactorEnrollCode
	}
	return purposeLoginCode
}

func (s *Service) cancelCredential(ctx context.Context, credentialID, challengeID, purpose string) {
	if credentialID == "" {
		return
	}
	if err := s.opts.Credentials.Cancel(context.WithoutCancel(ctx), credential.CancelRequest{
		ID: credentialID, Purpose: purpose, Target: challengeID,
	}); err != nil {
		s.opts.Logger.Warn("MFA 验证码取消失败", "error", err)
	}
}

// failChallenge 尽力把挑战置为 failed 并写失败审计（不掩盖原始拒绝原因）。
func (s *Service) failChallenge(ctx context.Context, challengeID string, attemptDigest []byte,
	generation int, reason, requestID string) {
	now := s.now()
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:      audit.Actor{Type: audit.ActorSystem, ID: "mfa.failure"},
			Action:     "mfa.challenge_failed",
			Target:     audit.Target{Type: "mfa_challenge", ID: challengeID},
			RequestID:  validRequestID(requestID),
			ReasonCode: reason,
			Outcome:    audit.OutcomeFailure,
		},
		FailureReasonCode:   "mfa.challenge_state_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapCriticalError(err))) },
	}
	err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		ok, updateErr := s.opts.Store.UpdateChallengeStateTx(txCtx, tx, challengeID, attemptDigest,
			generation, StatePending, StateFailed, now)
		if updateErr != nil {
			return updateErr
		}
		if !ok {
			return ErrChallengeInvalid
		}
		return nil
	})
	if err != nil {
		s.opts.Logger.Warn("MFA 挑战失败状态写入失败", "error", err)
	}
}

// recordFailure 写独立失败审计；失败只记录日志，不改变原始拒绝结果。
func (s *Service) recordFailure(ctx context.Context, actor audit.Actor, action, reason, code, requestID string) {
	if err := actor.Validate(); err != nil {
		return
	}
	event := audit.Event{
		Actor: actor, Action: action, Target: audit.Target{Type: "mfa"},
		Outcome: audit.OutcomeFailure, ErrorCode: code, ReasonCode: reason,
		RequestID: validRequestID(requestID),
	}
	if err := s.opts.Audit.RecordFailure(ctx, event); err != nil {
		s.opts.Logger.Warn("MFA 失败审计写入失败", "error", err)
	}
}

func (s *Service) now() time.Time { return s.opts.Now().UTC().Truncate(time.Millisecond) }

func mapCriticalError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, audit.ErrAuditUnavailable):
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	case errors.Is(err, audit.ErrInvalidEvent):
		return fmt.Errorf("%w: 审计事件无效", ErrOptionsInvalid)
	case errors.Is(err, ErrChallengeInvalid), errors.Is(err, ErrCodeInvalid),
		errors.Is(err, ErrFactorExists), errors.Is(err, ErrFactorNotFound),
		errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrAccessDenied),
		errors.Is(err, ErrFactorRequired), errors.Is(err, ErrStrongAuthRequired),
		errors.Is(err, ErrOptionsInvalid):
		return err
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, ErrStoreUnavailable), errors.Is(err, ErrPolicyUnavailable),
		errors.Is(err, ErrSessionUnavailable):
		return err
	default:
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
}

func validChallengeID(value string) bool {
	if len(value) != 4+32 || value[:4] != "mfc_" {
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

func validRequestID(requestID string) string {
	if account.ValidateRequestID(requestID) != nil {
		return ""
	}
	return requestID
}

func formatDuration(value time.Duration) string {
	minutes := int(value / time.Minute)
	if minutes <= 0 {
		return "数分钟"
	}
	return fmt.Sprintf("%d 分钟", minutes)
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

// resolveFactorPreference 校验因素优先顺序；默认 TOTP 优先于邮件（更符合“强因素
// 优先”的安全默认），步骤 43 的完整认证方式选择策略之前不做更复杂决策。
func resolveFactorPreference(value []FactorType) ([]FactorType, error) {
	if len(value) == 0 {
		return []FactorType{FactorPasskey, FactorTOTP, FactorEmail}, nil
	}
	seen := make(map[FactorType]bool, len(value))
	result := make([]FactorType, 0, len(value))
	for _, factor := range value {
		if factor != FactorTOTP && factor != FactorEmail {
			return nil, fmt.Errorf("%w: 未知因素优先项", ErrOptionsInvalid)
		}
		if seen[factor] {
			return nil, fmt.Errorf("%w: 因素优先项重复", ErrOptionsInvalid)
		}
		seen[factor] = true
		result = append(result, factor)
	}
	return result, nil
}

// chooseFactor 按配置顺序选择第一个可用因素。
func (s *Service) chooseFactor(emailActive, totpActive bool) (FactorType, bool) {
	for _, factor := range s.factorPreference {
		switch factor {
		case FactorTOTP:
			if totpActive {
				return FactorTOTP, true
			}
		case FactorEmail:
			if emailActive {
				return FactorEmail, true
			}
		}
	}
	return "", false
}

// recordFailedAttempt 记录挑战自身尝试计数；达到上限时迁移 pending→failed。
// 返回是否已用尽。
func (s *Service) recordFailedAttempt(ctx context.Context, challenge Challenge,
	attemptDigest []byte, now time.Time, requestID string) bool {
	exhausted := false
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:     audit.Actor{Type: audit.ActorUser, ID: challenge.UserID},
			Action:    "mfa.attempt_recorded",
			Target:    audit.Target{Type: "mfa_challenge", ID: challenge.ID},
			RequestID: validRequestID(requestID),
		},
		FailureReasonCode:   "mfa.attempt_record_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapCriticalError(err))) },
	}
	err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		attempts, ok, attemptErr := s.opts.Store.RecordAttemptTx(txCtx, tx, challenge.ID,
			attemptDigest, challenge.Generation, now)
		if attemptErr != nil {
			return attemptErr
		}
		if !ok {
			return ErrChallengeInvalid
		}
		if attempts >= challenge.MaxAttempts {
			exhausted = true
			okTransition, transitionErr := s.opts.Store.UpdateChallengeStateTx(txCtx, tx,
				challenge.ID, attemptDigest, challenge.Generation, StatePending, StateFailed, now)
			if transitionErr != nil {
				return transitionErr
			}
			if !okTransition {
				return ErrChallengeInvalid
			}
		}
		return nil
	})
	if err != nil {
		s.opts.Logger.Warn("MFA 尝试计数写入失败", "error", err)
	}
	return exhausted
}

// markVerified 在审计事务内把挑战 pending→verified（单赢家）。
func (s *Service) markVerified(ctx context.Context, challenge Challenge,
	attemptDigest []byte, now time.Time, requestID string) error {
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:  audit.Actor{Type: audit.ActorUser, ID: challenge.UserID},
			Action: "mfa.verified", Target: audit.Target{Type: "mfa_challenge", ID: challenge.ID},
			RequestID: validRequestID(requestID),
			Changes: []audit.FieldChange{
				{Field: "purpose", After: string(challenge.Purpose)},
				{Field: "factor_type", After: string(challenge.FactorType)},
			},
		},
		FailureReasonCode:   "mfa.verify_failed",
		FailureErrorCodeFor: func(err error) string { return string(CodeOf(mapCriticalError(err))) },
	}
	err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		ok, updateErr := s.opts.Store.UpdateChallengeStateTx(txCtx, tx, challenge.ID, attemptDigest,
			challenge.Generation, StatePending, StateVerified, now)
		if updateErr != nil {
			return updateErr
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
