package login

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/manualrecovery"
)

// TestManualRecoveryErrorCodesRegistered 验证人工恢复领域只复用根包已登记错误码
// （46 个），root/高权限目标投影 SUPPORT_TARGET_PROTECTED，自批/越权 ACCESS_DENIED。
func TestManualRecoveryErrorCodesRegistered(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode manualrecovery.ErrorCode
		wantHTTP int
	}{
		{name: "默认关闭/非法请求", err: manualrecovery.ErrDisabled, wantCode: manualrecovery.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "非法参数", err: fmt.Errorf("%w: bad", manualrecovery.ErrInvalidRequest), wantCode: manualrecovery.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "目标受保护", err: manualrecovery.ErrTargetProtected, wantCode: manualrecovery.CodeSupportTargetProtected, wantHTTP: http.StatusForbidden},
		{name: "目标不可用", err: manualrecovery.ErrTargetUnavailable, wantCode: manualrecovery.CodeUserDisabled, wantHTTP: http.StatusForbidden},
		{name: "越权", err: manualrecovery.ErrAccessDenied, wantCode: manualrecovery.CodeAccessDenied, wantHTTP: http.StatusForbidden},
		{name: "自批", err: manualrecovery.ErrSelfApproval, wantCode: manualrecovery.CodeAccessDenied, wantHTTP: http.StatusForbidden},
		{name: "需要再次认证", err: manualrecovery.ErrReauthRequired, wantCode: manualrecovery.CodeReauthRequired, wantHTTP: http.StatusForbidden},
		{name: "需要强认证", err: manualrecovery.ErrMFARequired, wantCode: manualrecovery.CodeMFARequired, wantHTTP: http.StatusForbidden},
		{name: "内容变化", err: manualrecovery.ErrContentChanged, wantCode: manualrecovery.CodeConflict, wantHTTP: http.StatusConflict},
		{name: "等待期未满", err: manualrecovery.ErrApprovalNotYetValid, wantCode: manualrecovery.CodeConflict, wantHTTP: http.StatusConflict},
		{name: "批准过期", err: manualrecovery.ErrApprovalExpired, wantCode: manualrecovery.CodeChallengeInvalid, wantHTTP: http.StatusBadRequest},
		{name: "申请不存在", err: manualrecovery.ErrRequestNotFound, wantCode: manualrecovery.CodeChallengeInvalid, wantHTTP: http.StatusBadRequest},
		{name: "策略不可用", err: manualrecovery.ErrAuthzUnavailable, wantCode: manualrecovery.CodeAuthzUnavailable, wantHTTP: http.StatusServiceUnavailable},
		{name: "存储不可用", err: manualrecovery.ErrStoreUnavailable, wantCode: manualrecovery.CodeDBUnavailable, wantHTTP: http.StatusServiceUnavailable},
		{name: "审计不可用", err: manualrecovery.ErrAuditUnavailable, wantCode: manualrecovery.CodeAuditWriteFailed, wantHTTP: http.StatusServiceUnavailable},
		{name: "通知失败", err: manualrecovery.ErrNotificationFailed, wantCode: manualrecovery.CodeMailDeliveryFailed, wantHTTP: 0},
		{name: "选项无效", err: manualrecovery.ErrOptionsInvalid, wantCode: manualrecovery.CodeInternalError, wantHTTP: http.StatusInternalServerError},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := manualrecovery.CodeOf(test.err)
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
		t.Errorf("错误码注册表数量 = %d，期望 48（人工恢复模块不新增错误码）", len(RegisteredErrorCodes()))
	}
}
