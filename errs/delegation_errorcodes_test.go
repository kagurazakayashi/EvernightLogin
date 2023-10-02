package errs

import (
	"errors"
	"fmt"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
)

// TestDelegationErrorCodesRegistered 验证可转授权限/委派限制领域复用根包已登记
// 错误码：缺少转授资格/资格过期/资格撤回/不再持有映射为 PERMISSION_REQUIRED，
// 自我转授/目标越界/数据范围过宽等转授限制映射为 ACCESS_DENIED，作用范围串用
// 映射为 APP_SCOPE_MISMATCH，并核对根包注册表登记与字面值一致。
func TestDelegationErrorCodesRegistered(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode delegation.ErrorCode
		wantHTTP int
	}{
		{name: "非法请求", err: fmt.Errorf("%w: bad", delegation.ErrInvalidRequest), wantCode: delegation.CodeReqInvalid, wantHTTP: 400},
		{name: "委派资格不存在", err: delegation.ErrGrantNotFound, wantCode: delegation.CodeReqInvalid, wantHTTP: 400},
		{name: "权限不存在", err: delegation.ErrPermissionNotFound, wantCode: delegation.CodeReqInvalid, wantHTTP: 400},
		{name: "缺少转授资格", err: delegation.ErrTransferNotGranted, wantCode: delegation.CodePermissionRequired, wantHTTP: 403},
		{name: "委派已过期", err: delegation.ErrTransferExpired, wantCode: delegation.CodePermissionRequired, wantHTTP: 403},
		{name: "委派已撤回", err: delegation.ErrTransferRevoked, wantCode: delegation.CodePermissionRequired, wantHTTP: 403},
		{name: "已不持有该权限", err: delegation.ErrPermissionNotHeld, wantCode: delegation.CodePermissionRequired, wantHTTP: 403},
		{name: "自我转授", err: delegation.ErrSelfTransferDenied, wantCode: delegation.CodeAccessDenied, wantHTTP: 403},
		{name: "目标不在白名单", err: delegation.ErrTargetNotAllowed, wantCode: delegation.CodeAccessDenied, wantHTTP: 403},
		{name: "数据范围过宽", err: delegation.ErrDataScopeTooBroad, wantCode: delegation.CodeAccessDenied, wantHTTP: 403},
		{name: "未获准操作", err: delegation.ErrAccessDenied, wantCode: delegation.CodeAccessDenied, wantHTTP: 403},
		{name: "权限不可转授", err: delegation.ErrPermissionUnavailable, wantCode: delegation.CodeAccessDenied, wantHTTP: 403},
		{name: "未配置转授检查", err: delegation.ErrDelegationNotSupported, wantCode: delegation.CodeAccessDenied, wantHTTP: 403},
		{name: "权限与作用范围不一致", err: delegation.ErrScopeMismatch, wantCode: delegation.CodeAppScopeMismatch, wantHTTP: 403},
		{name: "应用已停用", err: delegation.ErrApplicationInactive, wantCode: delegation.CodeClientDisabled, wantHTTP: 403},
		{name: "委派对象账户不可用", err: delegation.ErrDelegatorInvalid, wantCode: delegation.CodeUserDisabled, wantHTTP: 403},
		{name: "存储不可用", err: delegation.ErrStoreUnavailable, wantCode: delegation.CodeDBUnavailable, wantHTTP: 503},
		{name: "审计不可用", err: delegation.ErrAuditUnavailable, wantCode: delegation.CodeAuditWriteFailed, wantHTTP: 503},
		{name: "服务选项无效", err: delegation.ErrOptionsInvalid, wantCode: delegation.CodeInternalError, wantHTTP: 500},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := delegation.CodeOf(test.err)
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

	// 非本包错误返回空字符串，由调用方继续映射；空字符串不得被当作已登记代码。
	if got := delegation.CodeOf(errors.New("unclassified")); got != "" {
		t.Fatalf("CodeOf(非本包错误) = %q，期望空字符串", got)
	}
	if _, ok := LookupErrorCode(ErrorCode("")); ok {
		t.Error("空字符串不应登记为可诊断错误码")
	}

	if string(delegation.CodeReqInvalid) != string(CodeReqInvalid) ||
		string(delegation.CodePermissionRequired) != string(CodePermissionRequired) ||
		string(delegation.CodeAccessDenied) != string(CodeAccessDenied) ||
		string(delegation.CodeAppScopeMismatch) != string(CodeAppScopeMismatch) ||
		string(delegation.CodeClientDisabled) != string(CodeClientDisabled) ||
		string(delegation.CodeUserDisabled) != string(CodeUserDisabled) ||
		string(delegation.CodeDBUnavailable) != string(CodeDBUnavailable) ||
		string(delegation.CodeAuditWriteFailed) != string(CodeAuditWriteFailed) ||
		string(delegation.CodeInternalError) != string(CodeInternalError) {
		t.Fatal("internal/delegation 错误码字面值与根包注册表不一致")
	}
}
