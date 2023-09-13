package app

// 找回密码公开门面（嵌入宿主用）。
//
// 目标：让宿主在自己的“忘记密码”页面发起 Evernight 的邮件找回流程，并用邮件
// 中的一次性 token 完成密码重置；不暴露 internal/ 类型，也不返回重置 token。
// 为防账号枚举，Request 对“账户不存在/已禁用/无密码/邮件发送失败”保持与成功
// 相同的外部结果；只有邮件能力未配置时才返回明确配置错误。

import (
	"context"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/passwordreset"
)

// RequestPasswordResetRequest 是发起找回密码的请求。
type RequestPasswordResetRequest struct {
	// Identifier 是邮箱地址（Evernight 通过邮箱匹配账户）。
	Identifier string
	// ClientIP 是可信边界解析的客户端地址，用于来源维度限流。
	ClientIP  string
	RequestID string
}

// CompletePasswordResetRequest 是用邮件 token 设置新密码的请求。
type CompletePasswordResetRequest struct {
	Token       string
	NewPassword string
	RequestID   string
}

// PasswordResetResult 是完成找回的结果；不签发业务会话。
type PasswordResetResult struct {
	UserID          string
	SecurityVersion int64
	RequiresRelogin bool
	SessionsRevoked int64
	ResetAt         time.Time
}

// PasswordResetService 是找回密码公开门面。
type PasswordResetService interface {
	// Request 发起找回；成功/未找到/禁用等统一返回 nil，避免账号枚举。
	Request(ctx context.Context, req RequestPasswordResetRequest) error
	// ValidateToken 检查邮件 token 当前是否仍可用：核对请求状态、一次性凭证状态/
	// 绑定与账户可找回状态，但不消费、不改状态；所有失败统一返回 CHALLENGE_INVALID。
	ValidateToken(ctx context.Context, token string) error
	// Complete 用 token 设置新强密码，并撤销旧会话。
	Complete(ctx context.Context, req CompletePasswordResetRequest) (PasswordResetResult, error)
}

type passwordResetFacade struct{ r *Runtime }

func (f *passwordResetFacade) Request(ctx context.Context, req RequestPasswordResetRequest) error {
	r := f.r
	if r == nil || r.base == nil {
		return login.NewAppError(login.CodeConfigInvalid, "找回密码服务未装配",
			login.WithRequestID(login.NewRequestID()))
	}
	if !r.base.Config.Mail.Enabled {
		return login.NewAppError(login.CodeConfigInvalid, "找回密码邮件未配置",
			login.WithRequestID(login.NewRequestID()))
	}
	security := r.securityDomains()
	if security == nil || security.PasswordReset == nil {
		return login.NewAppError(login.CodeConfigInvalid, "找回密码服务未装配",
			login.WithRequestID(login.NewRequestID()))
	}
	requestID := req.RequestID
	if requestID == "" {
		requestID = login.NewRequestID()
	}
	// BeginReset 对账户不存在/禁用/邮件失败统一返回 nil，差异只进审计。
	if _, err := security.PasswordReset.BeginReset(ctx, passwordreset.BeginResetRequest{
		Identifier: req.Identifier, ClientIP: req.ClientIP, RequestID: requestID,
	}); err != nil {
		return mapDomainError("发起找回密码失败", string(passwordreset.CodeOf(err)))
	}
	return nil
}

func (f *passwordResetFacade) ValidateToken(ctx context.Context, token string) error {
	r := f.r
	security := r.securityDomains()
	if security == nil || security.PasswordReset == nil {
		return login.NewAppError(login.CodeConfigInvalid, "找回密码服务未装配",
			login.WithRequestID(login.NewRequestID()))
	}
	// 预检查与内置找回页面走同一个领域判断（ValidateResetToken 会核对请求状态、
	// 一次性凭证状态/绑定与账户可找回状态），但公开错误统一为 CHALLENGE_INVALID：
	// 不区分 token 不存在/过期/已使用/已撤销/账户禁用/无密码，避免公开入口泄露
	// 账户状态。服务层对底层存储故障仍按默认拒绝处理，不会当作有效 token。
	if err := security.PasswordReset.ValidateResetToken(ctx, token); err != nil {
		return login.NewAppError(login.CodeChallengeInvalid, "找回 token 无效或已失效")
	}
	return nil
}

func (f *passwordResetFacade) Complete(ctx context.Context, req CompletePasswordResetRequest) (PasswordResetResult, error) {
	r := f.r
	security := r.securityDomains()
	if security == nil || security.PasswordReset == nil {
		return PasswordResetResult{}, login.NewAppError(login.CodeConfigInvalid, "找回密码服务未装配",
			login.WithRequestID(login.NewRequestID()))
	}
	requestID := req.RequestID
	if requestID == "" {
		requestID = login.NewRequestID()
	}
	result, err := security.PasswordReset.CompleteReset(ctx, passwordreset.CompleteRequest{
		Token: req.Token, NewPassword: req.NewPassword, RequestID: requestID,
	})
	if err != nil {
		return PasswordResetResult{}, mapDomainError("重置密码失败", string(passwordreset.CodeOf(err)))
	}
	return PasswordResetResult{
		UserID: result.UserID, SecurityVersion: result.SecurityVersion,
		RequiresRelogin: result.RequiresRelogin, SessionsRevoked: result.SessionsRevoked,
		ResetAt: result.ResetAt,
	}, nil
}

var _ PasswordResetService = (*passwordResetFacade)(nil)
