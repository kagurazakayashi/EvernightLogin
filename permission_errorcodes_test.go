package login

import (
	"errors"
	"fmt"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/permission"
)

// TestPermissionErrorCodesRegistered 验证权限目录错误映射到已登记错误码。
func TestPermissionErrorCodesRegistered(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode permission.ErrorCode
		wantHTTP int
	}{
		{name: "非法请求", err: fmt.Errorf("%w: bad", permission.ErrInvalidRequest), wantCode: permission.CodeReqInvalid, wantHTTP: 400},
		{name: "权限不存在", err: permission.ErrPermissionNotFound, wantCode: permission.CodeReqInvalid, wantHTTP: 400},
		{name: "scope 无效", err: permission.ErrScopeInvalid, wantCode: permission.CodeReqInvalid, wantHTTP: 400},
		{name: "标识冲突", err: permission.ErrPermissionKeyTaken, wantCode: permission.CodeConflict, wantHTTP: 409},
		{name: "引用冲突", err: permission.ErrPermissionInUse, wantCode: permission.CodeConflict, wantHTTP: 409},
		{name: "状态冲突", err: permission.ErrStateConflict, wantCode: permission.CodeConflict, wantHTTP: 409},
		{name: "未获准", err: permission.ErrAccessDenied, wantCode: permission.CodeAccessDenied, wantHTTP: 403},
		{name: "内置保护", err: permission.ErrBuiltinProtected, wantCode: permission.CodeAccessDenied, wantHTTP: 403},
		{name: "应用停用", err: permission.ErrApplicationInactive, wantCode: permission.CodeClientDisabled, wantHTTP: 403},
		{name: "存储不可用", err: permission.ErrStoreUnavailable, wantCode: permission.CodeDBUnavailable, wantHTTP: 503},
		{name: "审计不可用", err: permission.ErrAuditUnavailable, wantCode: permission.CodeAuditWriteFailed, wantHTTP: 503},
		{name: "未知错误", err: errors.New("unclassified"), wantCode: permission.CodeInternalError, wantHTTP: 500},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := permission.CodeOf(test.err)
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
	if string(permission.CodeReqInvalid) != string(CodeReqInvalid) ||
		string(permission.CodeConflict) != string(CodeConflict) ||
		string(permission.CodeAccessDenied) != string(CodeAccessDenied) ||
		string(permission.CodeClientDisabled) != string(CodeClientDisabled) ||
		string(permission.CodeDBUnavailable) != string(CodeDBUnavailable) ||
		string(permission.CodeAuditWriteFailed) != string(CodeAuditWriteFailed) ||
		string(permission.CodeInternalError) != string(CodeInternalError) {
		t.Fatal("internal/permission 错误码字面值与根包注册表不一致")
	}
}
