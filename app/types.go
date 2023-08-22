package app

import (
	"context"
	"net"
	"time"
)

// RootRequest 是首次 root 初始化请求。Password 只用于本次受限初始化，不保存、
// 不返回、不记录；调用方应尽快清空自己的副本。
type RootRequest struct {
	Username    string
	DisplayName string
	Password    string
	RequestID   string
}

// RootResult 是首次初始化结果（不含密码、密钥或会话）。
type RootResult struct {
	UserID             string
	State              string
	StrongAuthRequired bool
	SecurityVersion    int64
}

// CreateUserRequest 是宿主受信创建用户请求。
type CreateUserRequest struct {
	Username  string
	Password  string
	Email     string
	Nickname  string
	Language  string
	Timezone  string
	RequestID string
}

// User 是脱敏用户视图。
type User struct {
	ID        string
	Username  string
	Nickname  string
	Email     string
	Status    string
	CreatedAt time.Time
}

// LoginRequest 是一次密码登录请求（口令只用于本次验证）。
type LoginRequest struct {
	Username  string
	Password  string
	AppID     string
	ClientIP  string
	RequestID string
	// RememberMe 由宿主决定是否请求记住登录状态；是否生效由会话策略决定。
	RememberMe bool
	// UserAgent 是客户端自称的 UA 摘要（仅记录用途，不能作为身份）。
	UserAgent string
}

// LoginResult 是登录结果；SessionSecret/CSRFSecret 只在本结果出现一次。
//
// 当账户启用了第二因素或被策略要求强认证时，Login 返回受限会话与
// SecondFactor 挑战：Restricted=true，SessionSecret 是只能完成第二步的受限会话
// 秘密，宿主必须调用 AuthService.VerifySecondFactor 才能得到完整会话。
type LoginResult struct {
	UserID        string
	Username      string
	SessionID     string
	SessionSecret []byte
	CSRFSecret    []byte
	ExpiresAt     time.Time
	Restricted    bool
	RequiredSteps []string
	// SecondFactor 非 nil 表示必须完成第二步验证；挑战数据只返回一次。
	SecondFactor *SecondFactorChallenge
}

// SecondFactorChallenge 是第二步因素挑战（TOTP/Passkey/邮件或强认证初始化）。
// AttemptToken/PasskeyOptions 只在本结果出现一次，不得写入日志或普通存储。
type SecondFactorChallenge struct {
	ChallengeID       string
	AttemptToken      []byte
	FactorType        string
	MaskedEmail       string
	ExpiresAt         time.Time
	PasskeyCeremonyID string
	PasskeyOptions    []byte
	// SetupRequired 表示账户被要求强认证但尚未绑定强因素：当前只能完成受控
	// 强认证初始化（AllowedSetupMethods），完成后需要重新登录，不会签发完整会话。
	SetupRequired       bool
	AllowedSetupMethods []string
}

// VerifySecondFactorRequest 是完成第二步验证的请求。
type VerifySecondFactorRequest struct {
	// SessionSecret 是第一步签发的受限会话秘密。
	SessionSecret []byte
	ChallengeID   string
	AttemptToken  []byte
	// Code 是 TOTP/邮件验证码；Passkey 第二步使用 PasskeyCeremonyID/PasskeyResponse。
	Code              string
	PasskeyCeremonyID string
	PasskeyResponse   []byte
	RequestID         string
}

// VerifiedSession 是第二步通过后签发的完整会话；秘密只返回一次。
type VerifiedSession struct {
	UserID        string
	SessionID     string
	SessionSecret []byte
	CSRFSecret    []byte
	ExpiresAt     time.Time
	// Method/Strength 是本次第二步因素与达到的认证强度（"totp"/"passkey"/"email"）。
	Method   string
	Strength string
}

// BeginRecoveryRequest 使用恢复代码替代第二步，进入受限恢复会话。
type BeginRecoveryRequest struct {
	// SessionSecret 是第一步签发的受限会话秘密（待第二因素）。
	SessionSecret []byte
	ChallengeID   string
	AttemptToken  []byte
	RecoveryCode  string
	RequestID     string
}

// RecoverySession 是受限恢复会话：不能访问业务，只能检查状态并完成新因素绑定。
type RecoverySession struct {
	UserID           string
	SessionID        string
	SessionSecret    []byte
	ExpiresAt        time.Time
	CodesRemaining   int
	RequiredStrength string
	AllowedMethods   []string
}

// RecoveryStatusRequest 查询受限恢复会话状态。
type RecoveryStatusRequest struct {
	SessionSecret []byte
}

// RecoveryStatus 是受限恢复会话的只读状态（不含恢复代码或秘密）。
type RecoveryStatus struct {
	HasActiveGroup   bool
	CodesRemaining   int
	ExpiresAt        time.Time
	RequiredStrength string
	AllowedMethods   []string
}

// TOTPBindingBeginRequest 开始绑定 TOTP（敏感操作 mfa.add，需要近期密码验证）。
type TOTPBindingBeginRequest struct {
	SessionSecret []byte
	// Password 是本次敏感操作再次认证的密码；服务端不会保存它。
	Password  string
	RequestID string
}

// TOTPBindingStart 是 TOTP 绑定开始结果；Secret/OTPAuthURL 只返回一次。
type TOTPBindingStart struct {
	BindingID     string
	Secret        string
	OTPAuthURL    string
	ExpiresAt     time.Time
	PeriodSeconds int
	Digits        int
}

// TOTPBindingConfirmRequest 用一次性验证码确认 TOTP 绑定。
type TOTPBindingConfirmRequest struct {
	SessionSecret []byte
	BindingID     string
	Code          string
	RequestID     string
}

// TOTPBinding 是已激活 TOTP 绑定的脱敏元数据。
type TOTPBinding struct {
	BindingID   string
	Status      string
	CreatedAt   time.Time
	ActivatedAt time.Time
}

// RecoveryCodesRequest 生成新一组恢复代码（敏感操作 recovery.codes.rotate，
// 已绑定强因素的账户需要近期强认证：密码 + TOTP 动态码）。
type RecoveryCodesRequest struct {
	SessionSecret []byte
	Password      string
	TOTPCode      string
	RequestID     string
}

// RecoveryCodes 是新一组恢复代码的一次性结果；Codes 只返回一次。
type RecoveryCodes struct {
	Codes      []string
	Generation int64
	CreatedAt  time.Time
}

// SecurityStatusRequest 查询当前账户的认证/恢复能力概览。
type SecurityStatusRequest struct {
	SessionSecret []byte
}

// SecurityStatus 是认证/恢复能力概览（不含秘密或代码）。
type SecurityStatus struct {
	TOTPActive             bool
	EmailFactorActive      bool
	PasskeyEnabled         bool
	PasskeyCount           int
	RecoveryCodesRemaining int
	StrongFactorBound      bool
}

// AccessRequest 是联合权限检查请求（权限由业务服务端确定）。
type AccessRequest struct {
	UserID     string
	AppID      string
	Permission string
	Mode       string
	ResourceID string
	RequestID  string
}

// AccessDecision 是权限检查结果；Reason/Code 为稳定公开值。
type AccessDecision struct {
	Allowed     bool
	Code        string
	Reason      string
	RequestID   string
	Application string
}

// GrantRoleRequest 是宿主受信角色分配请求（Phase A 暂未开放，返回明确错误）。
type GrantRoleRequest struct {
	UserID string
	AppID  string
	RoleID string
}

// BootstrapService 是首次初始化门面。
type BootstrapService interface {
	EnsureRoot(ctx context.Context, req RootRequest) (RootResult, error)
}

// UserService 是宿主受信用户门面。
type UserService interface {
	Create(ctx context.Context, req CreateUserRequest) (User, error)
}

// AuthService 是认证门面：密码第一步 + 第二因素/受限恢复验证。
type AuthService interface {
	// Login 完成密码第一步。账户启用第二因素时返回受限会话与 SecondFactor 挑战；
	// 未启用时直接返回完整会话。
	Login(ctx context.Context, req LoginRequest) (LoginResult, error)
	// VerifySecondFactor 用受限会话 + 挑战数据完成第二步，返回完整会话。
	VerifySecondFactor(ctx context.Context, req VerifySecondFactorRequest) (VerifiedSession, error)
	// BeginRecovery 用恢复代码替代第二步，进入受限恢复会话。
	BeginRecovery(ctx context.Context, req BeginRecoveryRequest) (RecoverySession, error)
	// RecoveryStatus 查询受限恢复会话状态。
	RecoveryStatus(ctx context.Context, req RecoveryStatusRequest) (RecoveryStatus, error)
}

// SecurityService 是认证/安全设置门面：敏感操作经真实再次认证后执行。
type SecurityService interface {
	// Status 返回当前账户的认证/恢复能力概览。
	Status(ctx context.Context, req SecurityStatusRequest) (SecurityStatus, error)
	// BeginTOTPBinding 开始绑定 TOTP（敏感操作 mfa.add，需要近期密码验证）。
	BeginTOTPBinding(ctx context.Context, req TOTPBindingBeginRequest) (TOTPBindingStart, error)
	// ConfirmTOTPBinding 用一次性验证码确认 TOTP 绑定。
	ConfirmTOTPBinding(ctx context.Context, req TOTPBindingConfirmRequest) (TOTPBinding, error)
	// GenerateRecoveryCodes 生成新一组恢复代码（敏感操作，需要近期认证）。
	GenerateRecoveryCodes(ctx context.Context, req RecoveryCodesRequest) (RecoveryCodes, error)
}

// AccessService 是联合权限检查门面。
type AccessService interface {
	Check(ctx context.Context, req AccessRequest) (AccessDecision, error)
}

// SessionService 会话语义有限：撤销当前会话。
type SessionService interface {
	Revoke(ctx context.Context, sessionSecret []byte) error
}

// AdminService 是受信管理门面；Phase A 不提供角色分配（留 146-149）。
type AdminService interface {
	GrantApplicationRole(ctx context.Context, req GrantRoleRequest) error
}

var _ = net.IP{}
