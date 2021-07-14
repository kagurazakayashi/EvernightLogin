package uiauthadapter

import (
	"errors"
	"fmt"
	"testing"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/mfa"
	"github.com/kagurazakayashi/EvernightLogin/internal/passkey"
	"github.com/kagurazakayashi/EvernightLogin/internal/passwordreset"
	"github.com/kagurazakayashi/EvernightLogin/internal/recovery"
)

// TestPublicMFAErrorDomainMapping 验证各领域错误按真实哨兵映射，不会因某领域
// CodeOf 的默认 INTERNAL_ERROR 抢先命中而退化；INTERNAL 只用于无领域匹配/真内部。
func TestPublicMFAErrorDomainMapping(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"MFA 无效验证码", mfa.ErrCodeInvalid, "CHALLENGE_INVALID"},
		{"MFA 挑战过期", fmt.Errorf("wrap: %w", mfa.ErrChallengeExpired), "CHALLENGE_INVALID"},
		{"MFA 尝试用尽", mfa.ErrAttemptsExceeded, "CHALLENGE_INVALID"},
		{"MFA 邮件失败", mfa.ErrMailFailed, "MAIL_DELIVERY_FAILED"},
		{"MFA 拒绝", mfa.ErrAccessDenied, "ACCESS_DENIED"},
		{"MFA 限流", mfa.ErrRateLimited, "RATE_LIMITED"},
		{"MFA 存储", mfa.ErrStoreUnavailable, "DB_UNAVAILABLE"},

		{"恢复代码无效", recovery.ErrCodeInvalid, "CHALLENGE_INVALID"},
		{"恢复代码过期", recovery.ErrAttemptExpired, "CHALLENGE_INVALID"},
		{"恢复代码用尽", recovery.ErrCodeExhausted, "CHALLENGE_INVALID"},
		{"恢复尝试次数用尽", recovery.ErrAttemptsExceeded, "CHALLENGE_INVALID"},
		{"恢复强度不足", recovery.ErrStrengthNotMet, "MFA_REBIND_REQUIRED"},
		{"恢复方法不允许", recovery.ErrMethodNotAllowed, "MFA_REBIND_REQUIRED"},
		{"恢复 root 保护", recovery.ErrRootProtected, "ACCESS_DENIED"},
		{"恢复限流", recovery.ErrRateLimited, "RATE_LIMITED"},
		{"恢复并发", recovery.ErrConcurrentRotation, "CONFLICT"},
		{"恢复要求不可用", recovery.ErrRequirementsUnavail, "AUTHZ_UNAVAILABLE"},

		{"Passkey ceremony 无效", passkey.ErrCeremonyInvalid, "CHALLENGE_INVALID"},
		{"Passkey ceremony 过期", passkey.ErrCeremonyExpired, "CHALLENGE_INVALID"},
		{"Passkey 认证失败", passkey.ErrAuthenticationFailed, "AUTH_FAILED"},
		{"Passkey 疑似复制", passkey.ErrCloneDetected, "AUTH_FAILED"},
		{"Passkey 需要再次认证", passkey.ErrReauthRequired, "REAUTH_REQUIRED"},
		{"Passkey 需要强认证", passkey.ErrMFARequired, "MFA_REQUIRED"},
		{"Passkey 拒绝", passkey.ErrAccessDenied, "ACCESS_DENIED"},
		{"Passkey 存储", passkey.ErrStoreUnavailable, "DB_UNAVAILABLE"},

		{"重置 token 无效", passwordreset.ErrTokenInvalid, "CHALLENGE_INVALID"},
		{"重置 token 过期", passwordreset.ErrTokenExpired, "CHALLENGE_INVALID"},
		{"重置账户禁用", passwordreset.ErrAccountDisabled, "USER_DISABLED"},
		{"重置无密码", passwordreset.ErrNoPassword, "ACCESS_DENIED"},
		{"重置限流", passwordreset.ErrRateLimited, "RATE_LIMITED"},
		{"重置存储", passwordreset.ErrStoreUnavailable, "DB_UNAVAILABLE"},

		{"无领域错误", errors.New("boom"), "INTERNAL_ERROR"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			mapped := publicMFAError(test.err)
			var publicErr *login.UIPageAuthError
			if !errors.As(mapped, &publicErr) {
				t.Fatalf("期望 *UIPageAuthError，实际 %T", mapped)
			}
			if publicErr.Code != test.want {
				t.Fatalf("错误码 = %q，期望 %q（err=%v）", publicErr.Code, test.want, test.err)
			}
		})
	}
}
