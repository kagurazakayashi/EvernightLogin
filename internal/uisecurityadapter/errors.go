package uisecurityadapter

import (
	"errors"
	"github.com/kagurazakayashi/EvernightLogin/internal/mfa"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
	"github.com/kagurazakayashi/EvernightLogin/internal/passkey"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/recovery"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	"github.com/kagurazakayashi/EvernightLogin/internal/totp"
	ui "github.com/kagurazakayashi/EvernightLogin/ui"
)

// publicCodes 是页面可呈现的稳定错误码集合（不新增码）。
var publicCodes = map[string]bool{
	"REQ_INVALID": true, "ACCESS_DENIED": true, "REAUTH_REQUIRED": true,
	"MFA_REQUIRED": true, "MFA_REBIND_REQUIRED": true, "CHALLENGE_INVALID": true,
	"CONFLICT": true, "RATE_LIMITED": true, "AUTHZ_UNAVAILABLE": true,
	"DB_UNAVAILABLE": true, "AUDIT_WRITE_FAILED": true, "MAIL_DELIVERY_FAILED": true,
	"AUTH_FAILED": true, "INTERNAL_ERROR": true,
	"FEATURE_NOT_ENABLED": true,
}

func mapped(code string) error {
	if !publicCodes[code] {
		code = "INTERNAL_ERROR"
	}
	return &ui.UIAccountError{Code: code}
}

// domainError 优先透传已映射公开错误，否则用领域 CodeOf 归一化。
func domainError(err error, codeOf func(error) string) error {
	if err == nil {
		return nil
	}
	var publicErr *ui.UIAccountError
	if errors.As(err, &publicErr) {
		return publicErr
	}
	return mapped(codeOf(err))
}

func mapMFAError(err error) error {
	return domainError(err, func(value error) string { return string(mfa.CodeOf(value)) })
}

func mapTOTPError(err error) error {
	return domainError(err, func(value error) string { return string(totp.CodeOf(value)) })
}

func mapPasskeyError(err error) error {
	return domainError(err, func(value error) string { return string(passkey.CodeOf(value)) })
}

func mapRecoveryError(err error) error {
	return domainError(err, func(value error) string { return string(recovery.CodeOf(value)) })
}

func mapSessionError(err error) error {
	return domainError(err, func(value error) string { return string(session.CodeOf(value)) })
}

// mapOAuthError 映射 oauthflow 协议/领域错误到页面稳定码。
func mapOAuthError(err error) error {
	if err == nil {
		return nil
	}
	var publicErr *ui.UIAccountError
	if errors.As(err, &publicErr) {
		return publicErr
	}
	var oauthErr *oauthflow.OAuthError
	if errors.As(err, &oauthErr) {
		switch oauthErr.Code {
		case "access_denied":
			return mapped("ACCESS_DENIED")
		case "invalid_grant":
			return mapped("CHALLENGE_INVALID")
		case "temporarily_unavailable", "server_error":
			return mapped("DB_UNAVAILABLE")
		case "slow_down":
			return mapped("RATE_LIMITED")
		case "invalid_client", "unauthorized_client":
			return mapped("AUTH_FAILED")
		default:
			return mapped("REQ_INVALID")
		}
	}
	return domainError(err, func(value error) string { return string(oauthflow.CodeOf(value)) })
}

// mapReauthError 映射再次认证错误。
func mapReauthError(err error) error {
	return domainError(err, func(value error) string { return string(reauth.CodeOf(value)) })
}

// mapReauthVerifyError 映射挑战校验失败：错误凭据/过期/尝试超限都是“需要重新
// 完成再次认证”，统一 fail-closed 为 REAUTH_REQUIRED，不降级为普通无权限。
func mapReauthVerifyError(err error) error {
	if err == nil {
		return nil
	}
	var publicErr *ui.UIAccountError
	if errors.As(err, &publicErr) {
		return publicErr
	}
	if errors.Is(err, reauth.ErrAccessDenied) || errors.Is(err, reauth.ErrAuthenticationFailed) ||
		errors.Is(err, reauth.ErrChallengeInvalid) || errors.Is(err, reauth.ErrAttemptsExceeded) {
		return mapped("REAUTH_REQUIRED")
	}
	return mapReauthError(err)
}
