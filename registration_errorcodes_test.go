package login

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/registration"
)

// TestRegistrationErrorCodesRegistered 验证注册领域只复用根包已登记错误码，并
// 核对 HTTP 状态映射；不新增注册码（注册表仍 46 个）。
func TestRegistrationErrorCodesRegistered(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode registration.ErrorCode
		wantHTTP int
	}{
		{name: "非法请求", err: fmt.Errorf("%w: bad", registration.ErrInvalidRequest), wantCode: registration.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "弱密码", err: fmt.Errorf("%w: weak", registration.ErrWeakPassword), wantCode: registration.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "注册冲突", err: registration.ErrRegistrationConflict, wantCode: registration.CodeConflict, wantHTTP: http.StatusConflict},
		{name: "验证入口失效", err: registration.ErrVerificationInvalid, wantCode: registration.CodeChallengeInvalid, wantHTTP: http.StatusBadRequest},
		{name: "重发过于频繁", err: registration.ErrResendTooSoon, wantCode: registration.CodeRateLimited, wantHTTP: http.StatusTooManyRequests},
		{name: "注册关闭", err: registration.ErrRegistrationClosed, wantCode: registration.CodeAuthFailed, wantHTTP: http.StatusUnauthorized},
		{name: "邮件发送不可用", err: registration.ErrMailUnavailable, wantCode: registration.CodeMailDeliveryFailed, wantHTTP: 0},
		{name: "无权操作", err: registration.ErrAccessDenied, wantCode: registration.CodeAccessDenied, wantHTTP: http.StatusForbidden},
		{name: "存储不可用", err: registration.ErrStoreUnavailable, wantCode: registration.CodeDBUnavailable, wantHTTP: http.StatusServiceUnavailable},
		{name: "审计不可用", err: registration.ErrAuditUnavailable, wantCode: registration.CodeAuditWriteFailed, wantHTTP: http.StatusServiceUnavailable},
		{name: "选项无效", err: registration.ErrOptionsInvalid, wantCode: registration.CodeInternalError, wantHTTP: http.StatusInternalServerError},
		{name: "未知错误", err: fmt.Errorf("boom"), wantCode: registration.CodeInternalError, wantHTTP: http.StatusInternalServerError},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := registration.CodeOf(test.err)
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
		t.Errorf("错误码注册表数量 = %d，期望 46（注册模块不新增错误码）", len(RegisteredErrorCodes()))
	}
}
