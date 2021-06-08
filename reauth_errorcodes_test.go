package login

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
)

// TestReauthErrorCodesRegistered 验证再次认证领域只复用根包已登记错误码（46 个）。
func TestReauthErrorCodesRegistered(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode reauth.ErrorCode
		wantHTTP int
	}{
		{name: "非法请求", err: fmt.Errorf("%w: bad", reauth.ErrInvalidRequest), wantCode: reauth.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "认证失败", err: reauth.ErrAuthenticationFailed, wantCode: reauth.CodeAuthFailed, wantHTTP: http.StatusUnauthorized},
		{name: "批准无效", err: reauth.ErrApprovalInvalid, wantCode: reauth.CodeTokenInvalid, wantHTTP: http.StatusUnauthorized},
		{name: "批准过期", err: reauth.ErrApprovalExpired, wantCode: reauth.CodeTokenInvalid, wantHTTP: http.StatusUnauthorized},
		{name: "批准重放", err: reauth.ErrApprovalConsumed, wantCode: reauth.CodeTokenInvalid, wantHTTP: http.StatusUnauthorized},
		{name: "越权", err: reauth.ErrAccessDenied, wantCode: reauth.CodeAccessDenied, wantHTTP: http.StatusForbidden},
		{name: "需要再次认证", err: reauth.ErrReauthRequired, wantCode: reauth.CodeReauthRequired, wantHTTP: http.StatusForbidden},
		{name: "需要确认", err: reauth.ErrConfirmationRequired, wantCode: reauth.CodeReauthRequired, wantHTTP: http.StatusForbidden},
		{name: "需要强认证", err: reauth.ErrMFARequired, wantCode: reauth.CodeMFARequired, wantHTTP: http.StatusForbidden},
		{name: "挑战无效", err: reauth.ErrChallengeInvalid, wantCode: reauth.CodeChallengeInvalid, wantHTTP: http.StatusBadRequest},
		{name: "挑战过期", err: reauth.ErrChallengeExpired, wantCode: reauth.CodeChallengeInvalid, wantHTTP: http.StatusBadRequest},
		{name: "尝试用尽", err: reauth.ErrAttemptsExceeded, wantCode: reauth.CodeChallengeInvalid, wantHTTP: http.StatusBadRequest},
		{name: "限流", err: reauth.ErrRateLimited, wantCode: reauth.CodeRateLimited, wantHTTP: http.StatusTooManyRequests},
		{name: "策略不可用", err: reauth.ErrPolicyUnavailable, wantCode: reauth.CodeAuthzUnavailable, wantHTTP: http.StatusServiceUnavailable},
		{name: "存储不可用", err: reauth.ErrStoreUnavailable, wantCode: reauth.CodeDBUnavailable, wantHTTP: http.StatusServiceUnavailable},
		{name: "审计不可用", err: reauth.ErrAuditUnavailable, wantCode: reauth.CodeAuditWriteFailed, wantHTTP: http.StatusServiceUnavailable},
		{name: "告知失败", err: reauth.ErrNotificationFailed, wantCode: reauth.CodeMailDeliveryFailed, wantHTTP: 0},
		{name: "选项无效", err: reauth.ErrOptionsInvalid, wantCode: reauth.CodeInternalError, wantHTTP: http.StatusInternalServerError},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := reauth.CodeOf(test.err)
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
		t.Errorf("错误码注册表数量 = %d，期望 46（再次认证模块不新增错误码）", len(RegisteredErrorCodes()))
	}
}
