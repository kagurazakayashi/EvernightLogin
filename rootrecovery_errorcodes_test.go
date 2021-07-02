package login

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/rootrecovery"
)

// TestRootRecoveryErrorCodesRegistered 验证 root 本地应急恢复领域只复用根包已登记
// 错误码（46 个，不新增设计码）。
func TestRootRecoveryErrorCodesRegistered(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode rootrecovery.ErrorCode
		wantHTTP int
	}{
		{name: "非法请求", err: fmt.Errorf("%w: bad", rootrecovery.ErrInvalidRequest), wantCode: rootrecovery.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "选项无效", err: rootrecovery.ErrOptionsInvalid, wantCode: rootrecovery.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "密码策略", err: rootrecovery.ErrPasswordPolicy, wantCode: rootrecovery.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "未选择操作", err: rootrecovery.ErrNoAction, wantCode: rootrecovery.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "需要维护停机", err: rootrecovery.ErrMaintenanceRequired, wantCode: rootrecovery.CodeRestoreMaintenanceRequired, wantHTTP: http.StatusConflict},
		{name: "恢复锁被占用", err: rootrecovery.ErrLocked, wantCode: rootrecovery.CodeConflict, wantHTTP: http.StatusConflict},
		{name: "确认取消", err: rootrecovery.ErrConfirmationDeclined, wantCode: rootrecovery.CodeAccessDenied, wantHTTP: http.StatusForbidden},
		{name: "root 不存在", err: rootrecovery.ErrRootNotFound, wantCode: rootrecovery.CodeAccessDenied, wantHTTP: http.StatusForbidden},
		{name: "root 状态不允许", err: rootrecovery.ErrRootNotEligible, wantCode: rootrecovery.CodeAccessDenied, wantHTTP: http.StatusForbidden},
		{name: "错误数据库", err: rootrecovery.ErrInvalidDatabase, wantCode: rootrecovery.CodeDBUnavailable, wantHTTP: http.StatusServiceUnavailable},
		{name: "存储不可用", err: rootrecovery.ErrStoreUnavailable, wantCode: rootrecovery.CodeDBUnavailable, wantHTTP: http.StatusServiceUnavailable},
		{name: "审计不可用", err: rootrecovery.ErrAuditUnavailable, wantCode: rootrecovery.CodeAuditWriteFailed, wantHTTP: http.StatusServiceUnavailable},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := rootrecovery.CodeOf(test.err)
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
		t.Errorf("错误码注册表数量 = %d，期望 48（root 应急恢复不新增错误码）",
			len(RegisteredErrorCodes()))
	}
}
