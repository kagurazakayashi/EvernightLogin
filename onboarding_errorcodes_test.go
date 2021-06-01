package login

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/onboarding"
)

// TestOnboardingErrorCodesRegistered 验证入驻领域只复用根包已登记错误码（46 个），
// 不新增注册码并核对 HTTP 状态映射。
func TestOnboardingErrorCodesRegistered(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode onboarding.ErrorCode
		wantHTTP int
	}{
		{name: "非法请求", err: fmt.Errorf("%w: bad", onboarding.ErrInvalidRequest), wantCode: onboarding.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "邀请失效", err: onboarding.ErrInvitationNotFound, wantCode: onboarding.CodeChallengeInvalid, wantHTTP: http.StatusBadRequest},
		{name: "邀请过期", err: onboarding.ErrInvitationExpired, wantCode: onboarding.CodeChallengeInvalid, wantHTTP: http.StatusBadRequest},
		{name: "状态冲突", err: onboarding.ErrInvitationConflict, wantCode: onboarding.CodeConflict, wantHTTP: http.StatusConflict},
		{name: "审核状态冲突", err: onboarding.ErrReviewStateConflict, wantCode: onboarding.CodeConflict, wantHTTP: http.StatusConflict},
		{name: "身份不匹配", err: onboarding.ErrInvitationIdentityMismatch, wantCode: onboarding.CodeAccessDenied, wantHTTP: http.StatusForbidden},
		{name: "自行批准", err: onboarding.ErrSelfApproval, wantCode: onboarding.CodeAccessDenied, wantHTTP: http.StatusForbidden},
		{name: "管理强认证", err: onboarding.ErrManagementAuthRequired, wantCode: onboarding.CodeReauthRequired, wantHTTP: http.StatusForbidden},
		{name: "存储不可用", err: onboarding.ErrStoreUnavailable, wantCode: onboarding.CodeDBUnavailable, wantHTTP: http.StatusServiceUnavailable},
		{name: "审计不可用", err: onboarding.ErrAuditUnavailable, wantCode: onboarding.CodeAuditWriteFailed, wantHTTP: http.StatusServiceUnavailable},
		{name: "选项无效", err: onboarding.ErrOptionsInvalid, wantCode: onboarding.CodeInternalError, wantHTTP: http.StatusInternalServerError},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := onboarding.CodeOf(test.err)
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
		t.Errorf("错误码注册表数量 = %d，期望 46（入驻模块不新增错误码）", len(RegisteredErrorCodes()))
	}
}
