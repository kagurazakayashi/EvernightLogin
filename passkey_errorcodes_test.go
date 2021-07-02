package login

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/passkey"
)

// TestPasskeyErrorCodesRegistered 验证 Passkey 领域只复用根包已登记错误码（46 个）。
func TestPasskeyErrorCodesRegistered(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode passkey.ErrorCode
		wantHTTP int
	}{
		{name: "非法请求", err: fmt.Errorf("%w: bad", passkey.ErrInvalidRequest), wantCode: passkey.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "凭证不存在", err: passkey.ErrCredentialNotFound, wantCode: passkey.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "越权", err: passkey.ErrAccessDenied, wantCode: passkey.CodeAccessDenied, wantHTTP: http.StatusForbidden},
		{name: "需要近期认证", err: passkey.ErrReauthRequired, wantCode: passkey.CodeReauthRequired, wantHTTP: http.StatusForbidden},
		{name: "需要强认证", err: passkey.ErrMFARequired, wantCode: passkey.CodeMFARequired, wantHTTP: http.StatusForbidden},
		{name: "认证失败", err: passkey.ErrAuthenticationFailed, wantCode: passkey.CodeAuthFailed, wantHTTP: http.StatusUnauthorized},
		{name: "可能被复制", err: passkey.ErrCloneDetected, wantCode: passkey.CodeAuthFailed, wantHTTP: http.StatusUnauthorized},
		{name: "挑战无效", err: passkey.ErrCeremonyInvalid, wantCode: passkey.CodeChallengeInvalid, wantHTTP: http.StatusBadRequest},
		{name: "挑战过期", err: passkey.ErrCeremonyExpired, wantCode: passkey.CodeChallengeInvalid, wantHTTP: http.StatusBadRequest},
		{name: "凭证冲突", err: passkey.ErrCredentialConflict, wantCode: passkey.CodeConflict, wantHTTP: http.StatusConflict},
		{name: "凭证上限", err: passkey.ErrCredentialLimit, wantCode: passkey.CodeConflict, wantHTTP: http.StatusConflict},
		{name: "最后登录方式", err: passkey.ErrLastLoginMethod, wantCode: passkey.CodeConflict, wantHTTP: http.StatusConflict},
		{name: "会话签发不可用", err: passkey.ErrSessionUnavailable, wantCode: passkey.CodeDBUnavailable, wantHTTP: http.StatusServiceUnavailable},
		{name: "存储不可用", err: passkey.ErrStoreUnavailable, wantCode: passkey.CodeDBUnavailable, wantHTTP: http.StatusServiceUnavailable},
		{name: "审计不可用", err: passkey.ErrAuditUnavailable, wantCode: passkey.CodeAuditWriteFailed, wantHTTP: http.StatusServiceUnavailable},
		{name: "选项无效", err: passkey.ErrOptionsInvalid, wantCode: passkey.CodeInternalError, wantHTTP: http.StatusInternalServerError},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := passkey.CodeOf(test.err)
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
		t.Errorf("错误码注册表数量 = %d，期望 48（Passkey 模块不新增错误码）", len(RegisteredErrorCodes()))
	}
}
