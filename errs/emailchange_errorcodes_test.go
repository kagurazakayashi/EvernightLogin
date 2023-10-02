package errs

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/emailchange"
)

// TestEmailChangeErrorCodesRegistered 验证邮箱变更领域只复用根包已登记错误码（46 个）。
func TestEmailChangeErrorCodesRegistered(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode emailchange.ErrorCode
		wantHTTP int
	}{
		{name: "非法请求", err: fmt.Errorf("%w: bad", emailchange.ErrInvalidRequest), wantCode: emailchange.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "无权变更", err: emailchange.ErrAccessDenied, wantCode: emailchange.CodeAccessDenied, wantHTTP: http.StatusForbidden},
		{name: "邮箱占用", err: emailchange.ErrEmailInUse, wantCode: emailchange.CodeConflict, wantHTTP: http.StatusConflict},
		{name: "需要再次验证", err: emailchange.ErrReauthRequired, wantCode: emailchange.CodeReauthRequired, wantHTTP: http.StatusForbidden},
		{name: "申请失效", err: emailchange.ErrRequestNotFound, wantCode: emailchange.CodeChallengeInvalid, wantHTTP: http.StatusBadRequest},
		{name: "申请过期", err: emailchange.ErrRequestExpired, wantCode: emailchange.CodeChallengeInvalid, wantHTTP: http.StatusBadRequest},
		{name: "存储不可用", err: emailchange.ErrStoreUnavailable, wantCode: emailchange.CodeDBUnavailable, wantHTTP: http.StatusServiceUnavailable},
		{name: "审计不可用", err: emailchange.ErrAuditUnavailable, wantCode: emailchange.CodeAuditWriteFailed, wantHTTP: http.StatusServiceUnavailable},
		{name: "选项无效", err: emailchange.ErrOptionsInvalid, wantCode: emailchange.CodeInternalError, wantHTTP: http.StatusInternalServerError},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := emailchange.CodeOf(test.err)
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
	if len(RegisteredErrorCodes()) != 48 {
		t.Errorf("错误码注册表数量 = %d，期望 48", len(RegisteredErrorCodes()))
	}
}
