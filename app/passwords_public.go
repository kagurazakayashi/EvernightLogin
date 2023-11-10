// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package app

// 受控改密公开 Go 接口（步骤 223）。
//
// 边界（Lead 已批准）：
//   - 只暴露“本人改密”：调用方必须提供完整（非受限）登录会话与当前密码，目标
//     用户从会话解析，请求里没有目标用户 ID，因此不存在“管理员改他人密码”旁路；
//   - 复用 internal/passwordreset.ChangePassword 的真实实现：当前密码复核、密码
//     策略/历史复用、security_version 递增、撤销全部会话、作废 pending 找回入口、
//     写 OAuth 撤销 outbox；失败不半改；
//   - 管理员强制改密/客服恢复改密不在本接口（分别归 229 客服恢复与 CLI root 应急）；
//   - 访问器 Runtime.Passwords() 定义在本文件，不编辑 app/runtime.go。

import (
	"context"

	"github.com/kagurazakayashi/EvernightLogin/internal/passwordreset"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
)

// PasswordChangeService 是本人受控改密门面。
type PasswordChangeService interface {
	// ChangeOwnPassword 本人改密：需要完整会话 + 当前密码；成功后要求重新登录，
	// 旧会话（含当前会话）按撤销 + security_version 失效。
	ChangeOwnPassword(ctx context.Context,
		req ChangeOwnPasswordRequest) (PasswordChangeResult, error)
}

// ChangeOwnPasswordRequest 是本人改密请求；没有目标用户字段。
type ChangeOwnPasswordRequest struct {
	// SessionSecret 是完整登录会话秘密（受限会话拒绝）。
	SessionSecret []byte
	// CurrentPassword/NewPassword 不保存、不记录、不进入审计。
	CurrentPassword string
	NewPassword     string
	// ClientIP 是可信边界解析出的客户端地址，仅用于失败限流。
	ClientIP string
	// TOTPCode 是再次认证可能要求的强因素动态码（仅在策略要求时使用，不保存）。
	TOTPCode  string
	RequestID string
}

// PasswordChangeResult 是改密结果；不包含密码或哈希。
type PasswordChangeResult struct {
	UserID          string
	SecurityVersion int64
	// RequiresRelogin 恒为 true：默认安全策略撤销全部会话并要求重新登录。
	RequiresRelogin bool
	SessionsRevoked int64
}

// Passwords 返回本人受控改密门面。
func (r *Runtime) Passwords() PasswordChangeService {
	return &passwordChangeFacade{r: r}
}

type passwordChangeFacade struct {
	r *Runtime
}

// ChangeOwnPassword 复用密码找回域的真实本人改密实现。
func (f *passwordChangeFacade) ChangeOwnPassword(ctx context.Context,
	req ChangeOwnPasswordRequest) (PasswordChangeResult, error) {
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return PasswordChangeResult{}, err
	}
	record, err := f.r.requireSession(ctx, req.SessionSecret, true, requestID)
	if err != nil {
		return PasswordChangeResult{}, err
	}
	security := f.r.securityDomains()
	if security == nil || security.PasswordReset == nil {
		return PasswordChangeResult{}, configError("密码服务未装配", requestID)
	}
	caller, err := passwordreset.UserCaller(record.UserID)
	if err != nil {
		return PasswordChangeResult{}, mapDomainError("会话主体无效", "ACCESS_DENIED", requestID)
	}
	// 真实再次认证：password.change 敏感操作需要绑定目标与操作的近期验证；策略
	// 要求强因素时使用请求中携带的动态码，绝不伪造批准信号。
	approved, err := f.r.approveSensitive(ctx, record.UserID, "password.change",
		"修改密码", req.CurrentPassword, req.TOTPCode, requestID, policy.StrengthPassword)
	if err != nil {
		return PasswordChangeResult{}, err
	}
	result, err := security.PasswordReset.ChangePassword(approved, caller,
		passwordreset.ChangeRequest{CurrentPassword: req.CurrentPassword,
			NewPassword: req.NewPassword, ClientIP: req.ClientIP, RequestID: requestID})
	if err != nil {
		return PasswordChangeResult{}, mapDomainError("修改密码失败",
			string(passwordreset.CodeOf(err)), requestID)
	}
	return PasswordChangeResult{UserID: result.UserID,
		SecurityVersion: result.SecurityVersion, RequiresRelogin: result.RequiresRelogin,
		SessionsRevoked: result.SessionsRevoked}, nil
}
