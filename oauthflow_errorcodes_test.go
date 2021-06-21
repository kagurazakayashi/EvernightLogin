package login

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
)

// TestOAuthFlowErrorCodesRegistered 验证 OAuth 授权码流程只复用根包已登记错误码
// （46 个，不新增设计码）；协议错误使用标准 OAuth error 字段而非这些业务码。
func TestOAuthFlowErrorCodesRegistered(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode oauthflow.ErrorCode
		wantHTTP int
	}{
		{name: "选项无效", err: oauthflow.ErrOptionsInvalid, wantCode: oauthflow.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "请求无效", err: fmt.Errorf("%w: bad", oauthflow.ErrInvalidRequest), wantCode: oauthflow.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "确认请求不存在", err: oauthflow.ErrConsentNotFound, wantCode: oauthflow.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "存储不可用", err: oauthflow.ErrStoreUnavailable, wantCode: oauthflow.CodeDBUnavailable, wantHTTP: http.StatusServiceUnavailable},
		{name: "审计不可用", err: oauthflow.ErrAuditUnavailable, wantCode: oauthflow.CodeAuditWriteFailed, wantHTTP: http.StatusServiceUnavailable},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := oauthflow.CodeOf(test.err)
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
		t.Errorf("错误码注册表数量 = %d，期望 46（OAuth 授权码流程不新增错误码）",
			len(RegisteredErrorCodes()))
	}
}
