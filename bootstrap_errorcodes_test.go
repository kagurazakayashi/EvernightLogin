package login

import (
	"errors"
	"fmt"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/bootstrap"
)

// TestBootstrapErrorCodesRegistered 验证首次初始化领域复用根包已登记错误码：
// 非法请求/未初始化映射 REQ_INVALID，已初始化/状态冲突/root 保留名占用映射
// CONFLICT，一次性配置凭证无效映射 TOKEN_INVALID，未授权映射 ACCESS_DENIED，
// 存储不可用映射 DB_UNAVAILABLE，审计失败映射 AUDIT_WRITE_FAILED；不新增注册码。
func TestBootstrapErrorCodesRegistered(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode bootstrap.ErrorCode
		wantHTTP int
	}{
		{name: "非法请求", err: fmt.Errorf("%w: bad", bootstrap.ErrInvalidRequest), wantCode: bootstrap.CodeReqInvalid, wantHTTP: 400},
		{name: "尚未初始化", err: bootstrap.ErrNotInitialized, wantCode: bootstrap.CodeReqInvalid, wantHTTP: 400},
		{name: "已完成初始化", err: bootstrap.ErrAlreadyInitialized, wantCode: bootstrap.CodeConflict, wantHTTP: 409},
		{name: "初始化状态冲突", err: bootstrap.ErrSetupStateConflict, wantCode: bootstrap.CodeConflict, wantHTTP: 409},
		{name: "root 保留名占用", err: bootstrap.ErrRootUsernameTaken, wantCode: bootstrap.CodeConflict, wantHTTP: 409},
		{name: "配置凭证无效", err: bootstrap.ErrSetupCredentialInvalid, wantCode: bootstrap.CodeTokenInvalid, wantHTTP: 401},
		{name: "未获准操作", err: bootstrap.ErrAccessDenied, wantCode: bootstrap.CodeAccessDenied, wantHTTP: 403},
		{name: "存储不可用", err: bootstrap.ErrStoreUnavailable, wantCode: bootstrap.CodeDBUnavailable, wantHTTP: 503},
		{name: "审计不可用", err: bootstrap.ErrAuditUnavailable, wantCode: bootstrap.CodeAuditWriteFailed, wantHTTP: 503},
		{name: "服务选项无效", err: bootstrap.ErrOptionsInvalid, wantCode: bootstrap.CodeInternalError, wantHTTP: 500},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := bootstrap.CodeOf(test.err)
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
	// 未分类内部错误映射为 INTERNAL_ERROR（不进入任何具体错误码）；该码已登记。
	if got := bootstrap.CodeOf(errors.New("unclassified")); got != bootstrap.CodeInternalError {
		t.Fatalf("CodeOf(未分类错误) = %q，期望 INTERNAL_ERROR", got)
	}
}
