package errs

import (
	"errors"
	"fmt"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/managedapi"
)

// TestManagedAPIErrorCodesRegistered 验证托管管理 API 使用的错误码全部复用既有
// 已登记码（本步不新增错误码），并核对 HTTP 映射与字面值。
func TestManagedAPIErrorCodesRegistered(t *testing.T) {
	codes := []struct {
		code     managedapi.ErrorCode
		wantHTTP int
	}{
		{managedapi.CodeReqInvalid, 400},
		{managedapi.CodeAccessDenied, 403},
		{managedapi.CodePermissionRequired, 403},
		{managedapi.CodeAppMembershipRequired, 403},
		{managedapi.CodeAppScopeMismatch, 403},
		{managedapi.CodeUserDisabled, 403},
		{managedapi.CodeClientDisabled, 403},
		{managedapi.CodeResourceForbidden, 403},
		{managedapi.CodeConflict, 409},
		{managedapi.CodeRateLimited, 429},
		{managedapi.CodeDBUnavailable, 503},
		{managedapi.CodeAuditWriteFailed, 503},
		{managedapi.CodeInternalError, 500},
	}
	for _, test := range codes {
		definition, ok := LookupErrorCode(ErrorCode(test.code))
		if !ok {
			t.Errorf("托管管理 API 错误码 %q 未在根包注册表登记", test.code)
			continue
		}
		if definition.HTTPStatus != test.wantHTTP {
			t.Errorf("错误码 %q HTTP 状态 = %d，期望 %d", test.code, definition.HTTPStatus, test.wantHTTP)
		}
	}

	cases := []struct {
		name     string
		err      error
		wantCode managedapi.ErrorCode
	}{
		{"非法请求", fmt.Errorf("%w: bad", managedapi.ErrInvalidRequest), managedapi.CodeReqInvalid},
		{"未授权", managedapi.ErrAccessDenied, managedapi.CodeAccessDenied},
		{"未启用", managedapi.ErrPolicyDisabled, managedapi.CodeAccessDenied},
		{"对象越界", managedapi.ErrObjectForbidden, managedapi.CodeResourceForbidden},
		{"版本冲突", managedapi.ErrVersionConflict, managedapi.CodeConflict},
		{"存储不可用", managedapi.ErrStoreUnavailable, managedapi.CodeDBUnavailable},
		{"审计不可用", managedapi.ErrAuditUnavailable, managedapi.CodeAuditWriteFailed},
		{"未分类", errors.New("unclassified"), managedapi.CodeInternalError},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := managedapi.CodeOf(test.err)
			if got != test.wantCode {
				t.Fatalf("CodeOf(%v) = %q，期望 %q", test.err, got, test.wantCode)
			}
			if _, ok := LookupErrorCode(ErrorCode(got)); !ok {
				t.Fatalf("错误码 %q 未登记", got)
			}
		})
	}

	literals := []struct {
		internal managedapi.ErrorCode
		root     ErrorCode
	}{
		{managedapi.CodeReqInvalid, CodeReqInvalid},
		{managedapi.CodeAccessDenied, CodeAccessDenied},
		{managedapi.CodePermissionRequired, CodePermissionRequired},
		{managedapi.CodeAppMembershipRequired, CodeAppMembershipRequired},
		{managedapi.CodeAppScopeMismatch, CodeAppScopeMismatch},
		{managedapi.CodeUserDisabled, CodeUserDisabled},
		{managedapi.CodeClientDisabled, CodeClientDisabled},
		{managedapi.CodeResourceForbidden, CodeResourceForbidden},
		{managedapi.CodeConflict, CodeConflict},
		{managedapi.CodeRateLimited, CodeRateLimited},
		{managedapi.CodeDBUnavailable, CodeDBUnavailable},
		{managedapi.CodeAuditWriteFailed, CodeAuditWriteFailed},
		{managedapi.CodeInternalError, CodeInternalError},
	}
	for _, literal := range literals {
		if string(literal.internal) != string(literal.root) {
			t.Errorf("错误码字面值不一致：internal=%q root=%q", literal.internal, literal.root)
		}
	}
}
