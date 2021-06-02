package login

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/profile"
)

// TestProfileErrorCodesRegistered 验证资料领域只复用根包已登记错误码（46 个）。
func TestProfileErrorCodesRegistered(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode profile.ErrorCode
		wantHTTP int
	}{
		{name: "非法请求", err: fmt.Errorf("%w: bad", profile.ErrInvalidRequest), wantCode: profile.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "电话非法", err: profile.ErrPhoneInvalid, wantCode: profile.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "无权修改", err: profile.ErrAccessDenied, wantCode: profile.CodeAccessDenied, wantHTTP: http.StatusForbidden},
		{name: "版本冲突", err: profile.ErrVersionConflict, wantCode: profile.CodeConflict, wantHTTP: http.StatusConflict},
		{name: "用户名占用", err: profile.ErrUsernameTaken, wantCode: profile.CodeConflict, wantHTTP: http.StatusConflict},
		{name: "更名冷却", err: profile.ErrRenameTooSoon, wantCode: profile.CodeRateLimited, wantHTTP: http.StatusTooManyRequests},
		{name: "更名再次验证", err: profile.ErrRenameReauthRequired, wantCode: profile.CodeReauthRequired, wantHTTP: http.StatusForbidden},
		{name: "用户不存在", err: profile.ErrUserNotFound, wantCode: profile.CodeChallengeInvalid, wantHTTP: http.StatusBadRequest},
		{name: "存储不可用", err: profile.ErrStoreUnavailable, wantCode: profile.CodeDBUnavailable, wantHTTP: http.StatusServiceUnavailable},
		{name: "审计不可用", err: profile.ErrAuditUnavailable, wantCode: profile.CodeAuditWriteFailed, wantHTTP: http.StatusServiceUnavailable},
		{name: "选项无效", err: profile.ErrOptionsInvalid, wantCode: profile.CodeInternalError, wantHTTP: http.StatusInternalServerError},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := profile.CodeOf(test.err)
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
		t.Errorf("错误码注册表数量 = %d，期望 46（资料模块不新增错误码）", len(RegisteredErrorCodes()))
	}
}
