package serverapp

// 步骤 258：直接修改他人用户名的 HTTP/CLI 桥接契约。
//
// 职责边界：授权、两步验证证明、目标/行版本校验、证明消费、事务一致提交与审计
// 全部由宿主（根包 app 的直接管理门面与 255 操作证明门面）执行；本包只定义管理
// JSON API 与宿主实现之间的最小协议，不复制第二套安全判定、不保存证明/密码。
//
// 桥接实现由宿主在 OpenBase 之后、HTTP 组装之前注入 Deps.DirectManagement；
// 未注入时不挂载相关路由（fail-closed 404，不返回占位成功）。

import (
	"context"
	"time"
)

// DirectProofChallenge 是目标绑定两步验证挑战的公开投影（不含密封意图/秘密）。
type DirectProofChallenge struct {
	ChallengeID       string
	Operation         string
	TargetUserID      string
	RequiredStrength  string
	ExpiresAt         time.Time
	MaxAttempts       int
	WebAuthnAvailable bool
}

// DirectProofGrant 是一次性操作证明；ProofToken 只返回一次，调用方不持久化到日志。
type DirectProofGrant struct {
	ProofToken      string
	ExpiresAt       time.Time
	Operation       string
	TargetUserID    string
	GrantedStrength string
}

// DirectWebAuthnStart 是浏览器 WebAuthn get() 所需的公开参数（不含秘密）。
type DirectWebAuthnStart struct {
	ChallengeID string
	CeremonyID  string
	PublicKey   []byte
	RPID        string
	ExpiresAt   time.Time
}

// DirectUsernameChangeRequest 是直接改名提交请求（操作者身份来自可信会话，不来自
// 请求体；证明令牌用于消费本次两步验证）。
type DirectUsernameChangeRequest struct {
	OperatorUserID     string
	TargetUserID       string
	NewUsername        string
	ExpectedRowVersion int64
	Reason             string
	ProofToken         string
	RequestID          string
}

// DirectUsernameChangeResult 是直接改名的脱敏结果（稳定用户 ID 不变）。
type DirectUsernameChangeResult struct {
	UserID     string
	Username   string
	RowVersion int64
	UpdatedAt  time.Time
}

// DirectUsernameBridge 是宿主必须实现的直接改名桥接能力。所有方法都必须使用
// ctx 中由管理 API 中间件注入的真实管理会话秘密构造可信 AdminCaller；不得信任
// 请求体中的操作者字段。
type DirectUsernameBridge interface {
	BeginUsernameVerification(ctx context.Context, operatorUserID, targetUserID,
		newUsername, requestID string) (DirectProofChallenge, error)
	ConfirmUsernameVerification(ctx context.Context, operatorUserID, challengeID,
		password, totpCode, requestID string) (DirectProofGrant, error)
	BeginUsernameWebAuthnVerification(ctx context.Context, operatorUserID, challengeID,
		requestID string) (DirectWebAuthnStart, error)
	ConfirmUsernameWebAuthnVerification(ctx context.Context, operatorUserID, challengeID,
		ceremonyID string, response []byte, requestID string) (DirectProofGrant, error)
	CancelUsernameVerification(ctx context.Context, operatorUserID, challengeID,
		requestID string) error
	ChangeUsername(ctx context.Context,
		request DirectUsernameChangeRequest) (DirectUsernameChangeResult, error)
}

// DirectManagementError 是宿主桥接返回的稳定错误：Code 必须是管理 API 错误码
// 投影中的码；Cause 只用于服务端日志，不投影给调用方。
type DirectManagementError struct {
	Code string
	Err  error
}

// Error 实现 error；不包含内部细节。
func (e *DirectManagementError) Error() string {
	if e == nil {
		return "直接管理操作失败"
	}
	return "直接管理操作失败：" + e.Code
}

// Unwrap 返回原始错误供服务端诊断/错误归属判断。
func (e *DirectManagementError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// NewDirectManagementError 构造带稳定码的直接管理错误；code 为空按 INTERNAL_ERROR。
func NewDirectManagementError(code string, err error) error {
	if code == "" {
		code = "INTERNAL_ERROR"
	}
	return &DirectManagementError{Code: code, Err: err}
}

// managementSessionSecretKey 是管理 API 中间件注入真实管理会话秘密的 context key。
// 秘密只在本进程请求链路内传递，不写入日志、响应或页面。
type managementSessionSecretKey struct{}

// WithManagementSessionSecret 把管理会话秘密放进 context（仅限 serverapp 管理路由
// 使用；调用方负责不记录/不回显该值）。
func WithManagementSessionSecret(ctx context.Context, secret string) context.Context {
	if ctx == nil || secret == "" {
		return ctx
	}
	return context.WithValue(ctx, managementSessionSecretKey{}, secret)
}

// ManagementSessionSecret 读取 context 中的管理会话秘密；不存在时返回空串，
// 宿主桥接必须据此 fail-closed。
func ManagementSessionSecret(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	secret, _ := ctx.Value(managementSessionSecretKey{}).(string)
	return secret
}
