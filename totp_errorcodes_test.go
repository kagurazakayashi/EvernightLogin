package login

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/totp"
)

// TestTOTPErrorCodesRegistered 验证 TOTP 领域只复用根包已登记错误码（46 个）。
func TestTOTPErrorCodesRegistered(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode totp.ErrorCode
		wantHTTP int
	}{
		{name: "非法请求", err: fmt.Errorf("%w: bad", totp.ErrInvalidRequest), wantCode: totp.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "绑定不存在", err: totp.ErrBindingNotFound, wantCode: totp.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "绑定过期", err: totp.ErrBindingExpired, wantCode: totp.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "越权", err: totp.ErrAccessDenied, wantCode: totp.CodeAccessDenied, wantHTTP: http.StatusForbidden},
		{name: "需要近期认证", err: totp.ErrReauthRequired, wantCode: totp.CodeReauthRequired, wantHTTP: http.StatusForbidden},
		{name: "移除最后强因素", err: totp.ErrFactorRequired, wantCode: totp.CodeMFARequired, wantHTTP: http.StatusForbidden},
		{name: "需要强因素", err: totp.ErrMFARequired, wantCode: totp.CodeMFARequired, wantHTTP: http.StatusForbidden},
		{name: "验证码无效", err: totp.ErrCodeInvalid, wantCode: totp.CodeChallengeInvalid, wantHTTP: http.StatusBadRequest},
		{name: "时间步重放", err: totp.ErrReplay, wantCode: totp.CodeChallengeInvalid, wantHTTP: http.StatusBadRequest},
		{name: "尝试用尽", err: totp.ErrAttemptsExceeded, wantCode: totp.CodeChallengeInvalid, wantHTTP: http.StatusBadRequest},
		{name: "限流", err: totp.ErrRateLimited, wantCode: totp.CodeRateLimited, wantHTTP: http.StatusTooManyRequests},
		{name: "策略不可用", err: totp.ErrPolicyUnavailable, wantCode: totp.CodeAuthzUnavailable, wantHTTP: http.StatusServiceUnavailable},
		{name: "存储不可用", err: totp.ErrStoreUnavailable, wantCode: totp.CodeDBUnavailable, wantHTTP: http.StatusServiceUnavailable},
		{name: "加密不可用", err: totp.ErrSealFailed, wantCode: totp.CodeDBUnavailable, wantHTTP: http.StatusServiceUnavailable},
		{name: "审计不可用", err: totp.ErrAuditUnavailable, wantCode: totp.CodeAuditWriteFailed, wantHTTP: http.StatusServiceUnavailable},
		{name: "选项无效", err: totp.ErrOptionsInvalid, wantCode: totp.CodeInternalError, wantHTTP: http.StatusInternalServerError},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := totp.CodeOf(test.err)
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
		t.Errorf("错误码注册表数量 = %d，期望 46（TOTP 模块不新增错误码）", len(RegisteredErrorCodes()))
	}
}
