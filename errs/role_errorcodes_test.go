package errs

import (
	"errors"
	"fmt"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/role"
)

// TestRoleErrorCodesRegistered 验证角色领域（含角色权限组合与分配）错误映射到已登记
// 错误码，且内部字面值与根包注册表一致。
func TestRoleErrorCodesRegistered(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode role.ErrorCode
		wantHTTP int
	}{
		{name: "非法请求", err: fmt.Errorf("%w: bad", role.ErrInvalidRequest), wantCode: role.CodeReqInvalid, wantHTTP: 400},
		{name: "角色不存在", err: role.ErrRoleNotFound, wantCode: role.CodeReqInvalid, wantHTTP: 400},
		{name: "作用范围无效", err: role.ErrScopeInvalid, wantCode: role.CodeReqInvalid, wantHTTP: 400},
		{name: "权限不存在", err: role.ErrPermissionNotFound, wantCode: role.CodeReqInvalid, wantHTTP: 400},
		{name: "权限已停用", err: role.ErrPermissionInactive, wantCode: role.CodeReqInvalid, wantHTTP: 400},
		{name: "用户不存在", err: role.ErrUserNotFound, wantCode: role.CodeReqInvalid, wantHTTP: 400},
		{name: "用户组不存在", err: role.ErrGroupNotFound, wantCode: role.CodeReqInvalid, wantHTTP: 400},
		{name: "角色键冲突", err: role.ErrRoleKeyTaken, wantCode: role.CodeConflict, wantHTTP: 409},
		{name: "角色被引用", err: role.ErrRoleInUse, wantCode: role.CodeConflict, wantHTTP: 409},
		{name: "角色已停用", err: role.ErrRoleDisabled, wantCode: role.CodeConflict, wantHTTP: 409},
		{name: "状态冲突", err: role.ErrStateConflict, wantCode: role.CodeConflict, wantHTTP: 409},
		{name: "未获准", err: role.ErrAccessDenied, wantCode: role.CodeAccessDenied, wantHTTP: 403},
		{name: "内置角色受保护", err: role.ErrBuiltinProtected, wantCode: role.CodeAccessDenied, wantHTTP: 403},
		{name: "root_only 权限", err: role.ErrRootOnlyPermission, wantCode: role.CodeAccessDenied, wantHTTP: 403},
		{name: "root 账户保护", err: role.ErrRootProtected, wantCode: role.CodeAccessDenied, wantHTTP: 403},
		{name: "权限跨范围", err: role.ErrPermissionScope, wantCode: role.CodeAppScopeMismatch, wantHTTP: 403},
		{name: "用户组跨范围", err: role.ErrGroupScope, wantCode: role.CodeAppScopeMismatch, wantHTTP: 403},
		{name: "非应用成员", err: role.ErrUserNotMember, wantCode: role.CodeAppMembershipRequired, wantHTTP: 403},
		{name: "应用已停用", err: role.ErrApplicationInactive, wantCode: role.CodeClientDisabled, wantHTTP: 403},
		{name: "账户不可用", err: role.ErrUserNotEligible, wantCode: role.CodeUserDisabled, wantHTTP: 403},
		{name: "存储不可用", err: role.ErrStoreUnavailable, wantCode: role.CodeDBUnavailable, wantHTTP: 503},
		{name: "审计不可用", err: role.ErrAuditUnavailable, wantCode: role.CodeAuditWriteFailed, wantHTTP: 503},
		{name: "未知错误", err: errors.New("unclassified"), wantCode: role.CodeInternalError, wantHTTP: 500},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := role.CodeOf(test.err)
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
	if string(role.CodeReqInvalid) != string(CodeReqInvalid) ||
		string(role.CodeConflict) != string(CodeConflict) ||
		string(role.CodeAccessDenied) != string(CodeAccessDenied) ||
		string(role.CodeAppScopeMismatch) != string(CodeAppScopeMismatch) ||
		string(role.CodeAppMembershipRequired) != string(CodeAppMembershipRequired) ||
		string(role.CodeClientDisabled) != string(CodeClientDisabled) ||
		string(role.CodeUserDisabled) != string(CodeUserDisabled) ||
		string(role.CodeDBUnavailable) != string(CodeDBUnavailable) ||
		string(role.CodeAuditWriteFailed) != string(CodeAuditWriteFailed) ||
		string(role.CodeInternalError) != string(CodeInternalError) {
		t.Fatal("internal/role 错误码字面值与根包注册表不一致")
	}
}
