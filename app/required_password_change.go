package app

// 步骤 257：MustChange 受限会话完成本人改密。
//
// D-257-1（安全审计 INFO-1，Lead 裁决为产品语义，第 11 轮 260 登记）：直接重置口令后
// 目标凭据带 must_change=true，用新口令登录只得到“仅能改密、无业务访问”的受限会话
// （kind=restricted / reason=pending_password_change / required_steps=[password_change]）；
// 该入口仍执行真实密码策略与再次认证（reauth 强度策略），**不会因“仅改密”自动跳过第二
// 因素**；MFA/Passkey 保留、改密不解除 MFA，完成后必须用新口令重新登录，完整登录仍需
// 第二因素（目标已绑定 MFA 时改密是否额外要求 TOTP 取决于 reauth 策略；目标绑定 MFA 的
// 独立闭环用例计划在 274 补测）。
//
// 管理员直接重置口令后目标凭证带 must_change=true：目标用新口令登录时认证只走到
// “密码已通过、必须先改密”，得到受限会话（kind=restricted,
// reason=pending_password_change, required_steps=[password_change]），不能直接访问
// 业务/管理接口。本门面提供该受限会话完成本人改密的唯一入口：
//   - 只接受 reason=pending_password_change 且 required_steps 含 password_change 的
//     受限会话；完整会话、其他受限原因（如待 MFA/待强认证初始化）一律拒绝；
//   - 仍执行真实密码策略/历史复用、当前密码复核（复用 passwordreset.ChangePassword）；
//     不允许把受限会话当成任意改密捷径（目标来自会话主体，没有用户 ID 参数）；
//   - 成功后 security_version 递增、旧会话/下载/刷新凭证失效、pending 找回入口作废、
//     OAuth 撤销 outbox 与关键审计按既有改密域一致提交；之后必须用新口令重新登录。

import (
	"context"

	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/passwordreset"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// RequiredPasswordChangeRequest 是强制改密受限会话完成本人改密的请求。
type RequiredPasswordChangeRequest struct {
	// SessionSecret 是 must_change 受限会话秘密（不接受完整会话走此入口）。
	SessionSecret []byte
	// CurrentPassword/NewPassword 不保存、不记录。
	CurrentPassword string
	NewPassword     string
	// ClientIP 是可信边界解析的客户端地址，仅用于失败限流。
	ClientIP string
	// TOTPCode 是再次认证可能要求的强因素动态码（不保存）。
	TOTPCode  string
	RequestID string
}

// RequiredPasswordChangeService 是强制改密受限会话完成本人改密的门面。
type RequiredPasswordChangeService interface {
	// Complete 用受限会话 + 当前新口令完成强制改密；成功后要求重新登录。
	Complete(ctx context.Context,
		request RequiredPasswordChangeRequest) (PasswordChangeResult, error)
}

// RequiredPasswordChanges 返回强制改密门面（与本人受控改密门面区分：后者要求完整会话）。
func (r *Runtime) RequiredPasswordChanges() RequiredPasswordChangeService {
	return &requiredPasswordChangeFacade{r: r}
}

type requiredPasswordChangeFacade struct{ r *Runtime }

// Complete 实现受限会话强制改密（详见文件头安全边界）。
func (f *requiredPasswordChangeFacade) Complete(ctx context.Context,
	request RequiredPasswordChangeRequest) (PasswordChangeResult, error) {
	requestID, err := resolveRequestID(ctx, request.RequestID)
	if err != nil {
		return PasswordChangeResult{}, err
	}
	r := f.r
	services := r.coreServices()
	security := r.securityDomains()
	if services == nil || services.Sessions == nil || security == nil ||
		security.PasswordReset == nil {
		return PasswordChangeResult{}, configError("改密服务未装配", requestID)
	}
	if len(request.SessionSecret) == 0 {
		return PasswordChangeResult{}, mapDomainError("缺少会话秘密",
			"ACCESS_DENIED", requestID)
	}
	record, err := services.Sessions.Validate(ctx, string(request.SessionSecret))
	if err != nil {
		return PasswordChangeResult{}, mapDomainError("会话无效或已失效",
			string(session.CodeOf(err)), requestID)
	}
	if !requiresPasswordChange(record) {
		return PasswordChangeResult{}, mapDomainError(
			"该会话不需要或不允许通过强制改密入口修改密码", "ACCESS_DENIED", requestID)
	}
	caller, callerErr := passwordreset.UserCaller(record.UserID)
	if callerErr != nil {
		return PasswordChangeResult{}, mapDomainError("会话主体无效",
			"ACCESS_DENIED", requestID)
	}
	approved, approveErr := r.approveSensitive(ctx, record.UserID, "password.change",
		"修改密码", request.CurrentPassword, request.TOTPCode, requestID,
		policy.StrengthPassword)
	if approveErr != nil {
		return PasswordChangeResult{}, approveErr
	}
	result, changeErr := security.PasswordReset.ChangePassword(approved, caller,
		passwordreset.ChangeRequest{CurrentPassword: request.CurrentPassword,
			NewPassword: request.NewPassword, ClientIP: request.ClientIP,
			RequestID: requestID})
	if changeErr != nil {
		return PasswordChangeResult{}, mapDomainError("修改密码失败",
			string(passwordreset.CodeOf(changeErr)), requestID)
	}
	return PasswordChangeResult{UserID: result.UserID,
		SecurityVersion: result.SecurityVersion, RequiresRelogin: result.RequiresRelogin,
		SessionsRevoked: result.SessionsRevoked}, nil
}

// requiresPasswordChange 判断会话是否恰为本步允许的 must_change 受限会话。
func requiresPasswordChange(record session.Session) bool {
	if !record.IsRestricted() || record.Reason != session.ReasonPendingPasswordChange {
		return false
	}
	for _, step := range record.RequiredSteps {
		if step == authn.StepPasswordChange {
			return true
		}
	}
	return false
}

var _ RequiredPasswordChangeService = (*requiredPasswordChangeFacade)(nil)
