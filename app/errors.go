package app

import (
	"errors"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin"
)

// configError 返回稳定的 CONFIG_INVALID AppError。
func configError(message string) error {
	return login.NewAppError(login.CodeConfigInvalid, message)
}

// wrapInternal 把内部错误包装为不泄露内部细节的公开错误：只返回 INTERNAL_ERROR
// 与固定摘要，不保留原始错误链（避免宿主通过 errors.Is/As 或 %v 看到内部路径、
// SQL、密钥材料等信息）。内部错误需要诊断时由内部装配层按脱敏字段记录日志。
func wrapInternal(message string, err error) error {
	if err == nil {
		return login.NewAppError(login.CodeInternalError, message)
	}
	if appErr, ok := err.(*login.AppError); ok {
		return appErr
	}
	return login.NewAppError(login.CodeInternalError, message)
}

// mapAuthError 把认证错误映射为公开稳定错误；不返回账户存在性细节。
func mapAuthError(err error) error {
	if err == nil {
		return nil
	}
	message := "登录失败"
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "disabled") || strings.Contains(lower, "禁用") {
		return login.NewAppError(login.CodeUserDisabled, "账户当前不可使用")
	}
	return login.NewAppError(login.CodeAuthFailed, message)
}

// mapServiceError 是通用内部错误映射；只返回稳定公开码与直白说明。
func mapServiceError(err error) error {
	if err == nil {
		return nil
	}
	if appErr, ok := err.(*login.AppError); ok {
		return appErr
	}
	return login.NewAppError(login.CodeInternalError, "操作未完成")
}

// domainCodeToPublic 把各领域模块的稳定错误码投影到根包已登记错误码。领域码只
// 复用根包注册表，不新增、不改语义；未知码回退为 INTERNAL_ERROR。
var domainCodeToPublic = map[string]login.ErrorCode{
	"REQ_INVALID":          login.CodeReqInvalid,
	"AUTH_FAILED":          login.CodeAuthFailed,
	"ACCESS_DENIED":        login.CodeAccessDenied,
	"REAUTH_REQUIRED":      login.CodeReauthRequired,
	"MFA_REQUIRED":         login.CodeMFARequired,
	"MFA_REBIND_REQUIRED":  login.CodeMFARebindRequired,
	"CHALLENGE_INVALID":    login.CodeChallengeInvalid,
	"RATE_LIMITED":         login.CodeRateLimited,
	"CONFLICT":             login.CodeConflict,
	"AUTHZ_UNAVAILABLE":    login.CodeAuthzUnavailable,
	"DB_UNAVAILABLE":       login.CodeDBUnavailable,
	"AUDIT_WRITE_FAILED":   login.CodeAuditWriteFailed,
	"MAIL_DELIVERY_FAILED": login.CodeMailDeliveryFailed,
	"INTERNAL_ERROR":       login.CodeInternalError,
	"USER_DISABLED":        login.CodeUserDisabled,
	// 委派/权限引擎的稳定码（只复用根包已登记错误码）：
	"PERMISSION_REQUIRED":     login.CodePermissionRequired,
	"APP_SCOPE_MISMATCH":      login.CodeAppScopeMismatch,
	"CLIENT_DISABLED":         login.CodeClientDisabled,
	"RESOURCE_FORBIDDEN":      login.CodeResourceForbidden,
	"APP_MEMBERSHIP_REQUIRED": login.CodeAppMembershipRequired,
}

// mapDomainError 把领域错误码映射为稳定公开错误；message 是面向调用者的直白
// 摘要，不包含内部细节、秘密或账户存在性信息。
func mapDomainError(message string, code string) error {
	if public, ok := domainCodeToPublic[code]; ok {
		return login.NewAppError(public, message)
	}
	return login.NewAppError(login.CodeInternalError, message)
}

var _ = errors.Is
