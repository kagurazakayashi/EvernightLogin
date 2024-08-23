package app

import (
	"context"
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
	RequestID     string
}

// RecoveryStatus 是受限恢复会话的只读状态（不含恢复代码或秘密）。
type RecoveryStatus struct {
	HasActiveGroup   bool
	CodesRemaining   int
	ExpiresAt        time.Time
	RequiredStrength string
	AllowedMethods   []string
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

// BootstrapService 是首次初始化门面。
type BootstrapService interface {
	EnsureRoot(ctx context.Context, req RootRequest) (RootResult, error)
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
