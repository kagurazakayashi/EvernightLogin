package errs

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/recovery"
)

// TestRecoveryErrorCodesRegistered 验证恢复领域只复用根包已登记错误码（46 个），
// 恢复代码/尝试问题投影 CHALLENGE_INVALID，受限恢复会话要求重新绑定投影
// MFA_REBIND_REQUIRED，root 与越权投影 ACCESS_DENIED。
func TestRecoveryErrorCodesRegistered(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode recovery.ErrorCode
		wantHTTP int
	}{
		{name: "非法请求", err: fmt.Errorf("%w: bad", recovery.ErrInvalidRequest), wantCode: recovery.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "越权", err: recovery.ErrAccessDenied, wantCode: recovery.CodeAccessDenied, wantHTTP: http.StatusForbidden},
		{name: "root 保护", err: recovery.ErrRootProtected, wantCode: recovery.CodeAccessDenied, wantHTTP: http.StatusForbidden},
		{name: "需要再次认证", err: recovery.ErrReauthRequired, wantCode: recovery.CodeReauthRequired, wantHTTP: http.StatusForbidden},
		{name: "需要重新绑定", err: recovery.ErrSessionRequired, wantCode: recovery.CodeMFARebindRequired, wantHTTP: http.StatusForbidden},
		{name: "需要近期强认证", err: recovery.ErrStrongAuthRequired, wantCode: recovery.CodeMFARequired, wantHTTP: http.StatusForbidden},
		{name: "强度不足", err: recovery.ErrStrengthNotMet, wantCode: recovery.CodeMFARebindRequired, wantHTTP: http.StatusForbidden},
		{name: "方法不允许", err: recovery.ErrMethodNotAllowed, wantCode: recovery.CodeMFARebindRequired, wantHTTP: http.StatusForbidden},
		{name: "代码无效", err: recovery.ErrCodeInvalid, wantCode: recovery.CodeChallengeInvalid, wantHTTP: http.StatusBadRequest},
		{name: "代码组不存在", err: recovery.ErrNoActiveGroup, wantCode: recovery.CodeChallengeInvalid, wantHTTP: http.StatusBadRequest},
		{name: "尝试过期", err: recovery.ErrAttemptExpired, wantCode: recovery.CodeChallengeInvalid, wantHTTP: http.StatusBadRequest},
		{name: "尝试用尽", err: recovery.ErrAttemptsExceeded, wantCode: recovery.CodeChallengeInvalid, wantHTTP: http.StatusBadRequest},
		{name: "并发更新", err: recovery.ErrConcurrentRotation, wantCode: recovery.CodeConflict, wantHTTP: http.StatusConflict},
		{name: "进行中尝试", err: recovery.ErrAttemptInProgress, wantCode: recovery.CodeConflict, wantHTTP: http.StatusConflict},
		{name: "限流", err: recovery.ErrRateLimited, wantCode: recovery.CodeRateLimited, wantHTTP: http.StatusTooManyRequests},
		{name: "策略不可用", err: recovery.ErrRequirementsUnavail, wantCode: recovery.CodeAuthzUnavailable, wantHTTP: http.StatusServiceUnavailable},
		{name: "存储不可用", err: recovery.ErrStoreUnavailable, wantCode: recovery.CodeDBUnavailable, wantHTTP: http.StatusServiceUnavailable},
		{name: "审计不可用", err: recovery.ErrAuditUnavailable, wantCode: recovery.CodeAuditWriteFailed, wantHTTP: http.StatusServiceUnavailable},
		{name: "告知失败", err: recovery.ErrNotificationFailed, wantCode: recovery.CodeMailDeliveryFailed, wantHTTP: 0},
		{name: "选项无效", err: recovery.ErrOptionsInvalid, wantCode: recovery.CodeInternalError, wantHTTP: http.StatusInternalServerError},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := recovery.CodeOf(test.err)
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
		t.Errorf("错误码注册表数量 = %d，期望 48（恢复模块不新增错误码）", len(RegisteredErrorCodes()))
	}
}
