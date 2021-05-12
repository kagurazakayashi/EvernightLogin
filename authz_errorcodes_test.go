package login

import (
	"errors"
	"fmt"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
)

// TestAuthorizationErrorCodesRegistered 验证授权计算引擎错误与判定码都使用已登记
// 错误码，并核对 HTTP 映射与字面值。
func TestAuthorizationErrorCodesRegistered(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode authz.ErrorCode
		wantHTTP int
	}{
		{name: "非法请求", err: fmt.Errorf("%w: bad", authz.ErrInvalidRequest), wantCode: authz.CodeReqInvalid, wantHTTP: 400},
		{name: "主体不存在", err: authz.ErrSubjectNotFound, wantCode: authz.CodeReqInvalid, wantHTTP: 400},
		{name: "未获准查询", err: authz.ErrAccessDenied, wantCode: authz.CodeAccessDenied, wantHTTP: 403},
		{name: "root 保护", err: authz.ErrRootProtected, wantCode: authz.CodeAccessDenied, wantHTTP: 403},
		{name: "存储不可用", err: authz.ErrStoreUnavailable, wantCode: authz.CodeDBUnavailable, wantHTTP: 503},
		{name: "未知错误", err: errors.New("unclassified"), wantCode: authz.CodeInternalError, wantHTTP: 500},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := authz.CodeOf(test.err)
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

	// 判定结果中的全部错误码都必须已登记，且字面值一致。
	decisionCodes := []struct {
		code     authz.ErrorCode
		wantHTTP int
	}{
		{authz.CodeReqInvalid, 400},
		{authz.CodeAccessDenied, 403},
		{authz.CodeUserDisabled, 403},
		{authz.CodeClientDisabled, 403},
		{authz.CodeAppMembershipRequired, 403},
		{authz.CodePermissionRequired, 403},
		{authz.CodePermissionDisabled, 403},
		{authz.CodePermissionUnknown, 400},
		{authz.CodeAppScopeMismatch, 403},
		{authz.CodeResourceForbidden, 403},
		{authz.CodeAuthzUnavailable, 503},
		{authz.CodeDBUnavailable, 503},
		{authz.CodeInternalError, 500},
	}
	for _, test := range decisionCodes {
		definition, ok := LookupErrorCode(ErrorCode(test.code))
		if !ok {
			t.Errorf("判定错误码 %q 未登记", test.code)
			continue
		}
		if definition.HTTPStatus != test.wantHTTP {
			t.Errorf("判定错误码 %q HTTP 状态 = %d，期望 %d", test.code, definition.HTTPStatus, test.wantHTTP)
		}
	}
	if string(authz.CodeReqInvalid) != string(CodeReqInvalid) ||
		string(authz.CodeAccessDenied) != string(CodeAccessDenied) ||
		string(authz.CodeUserDisabled) != string(CodeUserDisabled) ||
		string(authz.CodeClientDisabled) != string(CodeClientDisabled) ||
		string(authz.CodeAppMembershipRequired) != string(CodeAppMembershipRequired) ||
		string(authz.CodePermissionRequired) != string(CodePermissionRequired) ||
		string(authz.CodePermissionDisabled) != string(CodePermissionDisabled) ||
		string(authz.CodePermissionUnknown) != string(CodePermissionUnknown) ||
		string(authz.CodeAppScopeMismatch) != string(CodeAppScopeMismatch) ||
		string(authz.CodeResourceForbidden) != string(CodeResourceForbidden) ||
		string(authz.CodeAuthzUnavailable) != string(CodeAuthzUnavailable) ||
		string(authz.CodeDBUnavailable) != string(CodeDBUnavailable) ||
		string(authz.CodeInternalError) != string(CodeInternalError) {
		t.Fatal("internal/authz 错误码字面值与根包注册表不一致")
	}
}
