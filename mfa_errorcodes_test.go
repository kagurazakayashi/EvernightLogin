package login

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/mfa"
)

// TestMFAErrorCodesRegistered 验证 MFA 领域只复用根包已登记错误码（46 个），
// 高权限邮件因素不满足映射 MFA_REQUIRED，验证码/挑战问题映射 CHALLENGE_INVALID。
func TestMFAErrorCodesRegistered(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode mfa.ErrorCode
		wantHTTP int
	}{
		{name: "非法请求", err: fmt.Errorf("%w: bad", mfa.ErrInvalidRequest), wantCode: mfa.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "因素已存在", err: mfa.ErrFactorExists, wantCode: mfa.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "因素不存在", err: mfa.ErrFactorNotFound, wantCode: mfa.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "越权", err: mfa.ErrAccessDenied, wantCode: mfa.CodeAccessDenied, wantHTTP: http.StatusForbidden},
		{name: "高权限需强认证", err: mfa.ErrStrongAuthRequired, wantCode: mfa.CodeMFARequired, wantHTTP: http.StatusForbidden},
		{name: "需要第二因素", err: mfa.ErrSecondFactorRequired, wantCode: mfa.CodeMFARequired, wantHTTP: http.StatusForbidden},
		{name: "无已验证邮箱", err: mfa.ErrNoVerifiedEmail, wantCode: mfa.CodeMFARequired, wantHTTP: http.StatusForbidden},
		{name: "挑战无效", err: mfa.ErrChallengeInvalid, wantCode: mfa.CodeChallengeInvalid, wantHTTP: http.StatusBadRequest},
		{name: "挑战过期", err: mfa.ErrChallengeExpired, wantCode: mfa.CodeChallengeInvalid, wantHTTP: http.StatusBadRequest},
		{name: "验证码无效", err: mfa.ErrCodeInvalid, wantCode: mfa.CodeChallengeInvalid, wantHTTP: http.StatusBadRequest},
		{name: "尝试用尽", err: mfa.ErrAttemptsExceeded, wantCode: mfa.CodeChallengeInvalid, wantHTTP: http.StatusBadRequest},
		{name: "限流", err: mfa.ErrRateLimited, wantCode: mfa.CodeRateLimited, wantHTTP: http.StatusTooManyRequests},
		{name: "强制策略禁止移除", err: mfa.ErrFactorRequired, wantCode: mfa.CodeConflict, wantHTTP: http.StatusConflict},
		{name: "策略不可用", err: mfa.ErrPolicyUnavailable, wantCode: mfa.CodeAuthzUnavailable, wantHTTP: http.StatusServiceUnavailable},
		{name: "存储不可用", err: mfa.ErrStoreUnavailable, wantCode: mfa.CodeDBUnavailable, wantHTTP: http.StatusServiceUnavailable},
		{name: "会话不可用", err: mfa.ErrSessionUnavailable, wantCode: mfa.CodeDBUnavailable, wantHTTP: http.StatusServiceUnavailable},
		{name: "审计不可用", err: mfa.ErrAuditUnavailable, wantCode: mfa.CodeAuditWriteFailed, wantHTTP: http.StatusServiceUnavailable},
		{name: "邮件失败", err: mfa.ErrMailFailed, wantCode: mfa.CodeMailDeliveryFailed, wantHTTP: 0},
		{name: "选项无效", err: mfa.ErrOptionsInvalid, wantCode: mfa.CodeInternalError, wantHTTP: http.StatusInternalServerError},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := mfa.CodeOf(test.err)
			if got != test.wantCode {
				t.Fatalf("CodeOf(%v) = %q，期望 %q", test.err, got, test.wantCode)
			}
			definition, ok := LookupErrorCode(ErrorCode(got))
			if !ok {
				t.Fatalf("错误码 %q 未在根包注册表登记", got)
			}
			if definition.HTTPStatus != test.wantHTTP {
				t.Errorf("错误码 %q HTTP 状态 = %d，期望 %d", got, definition.HTTPStatus, test.wantHTTP)
			}
		})
	}
	if len(RegisteredErrorCodes()) != 46 {
		t.Errorf("错误码注册表数量 = %d，期望 46（MFA 模块不新增错误码）", len(RegisteredErrorCodes()))
	}
}
