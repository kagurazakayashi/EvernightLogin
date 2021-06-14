package login

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/passwordreset"
)

// TestPasswordResetErrorCodesRegistered 验证密码找回领域只复用根包已登记错误码。
func TestPasswordResetErrorCodesRegistered(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode passwordreset.ErrorCode
		wantHTTP int
	}{
		{name: "非法请求", err: fmt.Errorf("%w: bad", passwordreset.ErrInvalidRequest), wantCode: passwordreset.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "越权", err: passwordreset.ErrAccessDenied, wantCode: passwordreset.CodeAccessDenied, wantHTTP: http.StatusForbidden},
		{name: "无密码账户", err: passwordreset.ErrNoPassword, wantCode: passwordreset.CodeAccessDenied, wantHTTP: http.StatusForbidden},
		{name: "入口无效", err: passwordreset.ErrTokenInvalid, wantCode: passwordreset.CodeChallengeInvalid, wantHTTP: http.StatusBadRequest},
		{name: "入口过期", err: passwordreset.ErrTokenExpired, wantCode: passwordreset.CodeChallengeInvalid, wantHTTP: http.StatusBadRequest},
		{name: "账户禁用", err: passwordreset.ErrAccountDisabled, wantCode: passwordreset.CodeUserDisabled, wantHTTP: http.StatusForbidden},
		{name: "邮件失败", err: passwordreset.ErrMailFailed, wantCode: passwordreset.CodeMailDeliveryFailed, wantHTTP: 0},
		{name: "会话撤销失败", err: passwordreset.ErrSessionRevoke, wantCode: passwordreset.CodeDBUnavailable, wantHTTP: http.StatusServiceUnavailable},
		{name: "存储不可用", err: passwordreset.ErrStoreUnavailable, wantCode: passwordreset.CodeDBUnavailable, wantHTTP: http.StatusServiceUnavailable},
		{name: "审计不可用", err: passwordreset.ErrAuditUnavailable, wantCode: passwordreset.CodeAuditWriteFailed, wantHTTP: http.StatusServiceUnavailable},
		{name: "选项无效", err: passwordreset.ErrOptionsInvalid, wantCode: passwordreset.CodeInternalError, wantHTTP: http.StatusInternalServerError},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := passwordreset.CodeOf(test.err)
			if got != test.wantCode {
				t.Fatalf("CodeOf(%v) = %q，期望 %q", test.err, got, test.wantCode)
			}
			definition, ok := LookupErrorCode(ErrorCode(got))
			if !ok {
				t.Fatalf("错误码 %q 未登记", got)
			}
			if definition.HTTPStatus != test.wantHTTP {
				t.Errorf("错误码 %q HTTP 状态 = %d，期望 %d", got, definition.HTTPStatus, test.wantHTTP)
			}
		})
	}
	if len(RegisteredErrorCodes()) != 46 {
		t.Errorf("错误码数量 = %d，期望 46", len(RegisteredErrorCodes()))
	}
}
