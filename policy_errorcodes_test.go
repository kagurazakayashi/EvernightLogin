package login

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
)

// TestPolicyErrorCodesRegistered 验证敏感策略领域只复用根包已登记错误码（46 个），
// 不新增错误码；未实现验证方式 fail-closed 映射 MFA_REQUIRED，非 root 修改映射
// ACCESS_DENIED，版本冲突映射 CONFLICT。
func TestPolicyErrorCodesRegistered(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode policy.ErrorCode
		wantHTTP int
	}{
		{name: "非法请求", err: fmt.Errorf("%w: bad", policy.ErrInvalidRequest), wantCode: policy.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "非法组合", err: policy.ErrInvalidChange, wantCode: policy.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "未知操作", err: policy.ErrOperationUnknown, wantCode: policy.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "未知作用域", err: policy.ErrScopeUnknown, wantCode: policy.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "无默认值", err: policy.ErrDefaultUnavailable, wantCode: policy.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "无权访问", err: policy.ErrAccessDenied, wantCode: policy.CodeAccessDenied, wantHTTP: http.StatusForbidden},
		{name: "非 root 修改", err: policy.ErrRootRequired, wantCode: policy.CodeAccessDenied, wantHTTP: http.StatusForbidden},
		{name: "需要再次验证", err: policy.ErrReauthRequired, wantCode: policy.CodeReauthRequired, wantHTTP: http.StatusForbidden},
		{name: "需要确认", err: policy.ErrConfirmationRequired, wantCode: policy.CodeReauthRequired, wantHTTP: http.StatusForbidden},
		{name: "验证强度不可满足", err: policy.ErrVerificationUnavailable, wantCode: policy.CodeMFARequired, wantHTTP: http.StatusForbidden},
		{name: "版本冲突", err: policy.ErrVersionConflict, wantCode: policy.CodeConflict, wantHTTP: http.StatusConflict},
		{name: "存储不可用", err: policy.ErrStoreUnavailable, wantCode: policy.CodeDBUnavailable, wantHTTP: http.StatusServiceUnavailable},
		{name: "审计不可用", err: policy.ErrAuditUnavailable, wantCode: policy.CodeAuditWriteFailed, wantHTTP: http.StatusServiceUnavailable},
		{name: "选项无效", err: policy.ErrOptionsInvalid, wantCode: policy.CodeInternalError, wantHTTP: http.StatusInternalServerError},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := policy.CodeOf(test.err)
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
		t.Errorf("错误码注册表数量 = %d，期望 46（敏感策略模块不新增错误码）", len(RegisteredErrorCodes()))
	}
}
