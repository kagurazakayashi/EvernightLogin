package login

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/token"
)

// TestTokenErrorCodesRegistered 验证令牌领域只复用根包已登记错误码（46 个）：
// 签名/格式/未知密钥/恶意密钥引用投影 TOKEN_INVALID，过期 TOKEN_EXPIRED，撤销密钥
// TOKEN_REVOKED，接收方不匹配 TOKEN_AUDIENCE_MISMATCH，越权 ACCESS_DENIED。
func TestTokenErrorCodesRegistered(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode token.ErrorCode
		wantHTTP int
	}{
		{name: "非法请求", err: fmt.Errorf("%w: bad", token.ErrInvalidRequest), wantCode: token.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "越权", err: token.ErrAccessDenied, wantCode: token.CodeAccessDenied, wantHTTP: http.StatusForbidden},
		{name: "令牌格式", err: token.ErrMalformedToken, wantCode: token.CodeTokenInvalid, wantHTTP: http.StatusUnauthorized},
		{name: "错误算法", err: token.ErrWrongAlgorithm, wantCode: token.CodeTokenInvalid, wantHTTP: http.StatusUnauthorized},
		{name: "未知密钥", err: token.ErrUnknownKey, wantCode: token.CodeTokenInvalid, wantHTTP: http.StatusUnauthorized},
		{name: "恶意密钥引用", err: token.ErrMaliciousKeyRef, wantCode: token.CodeTokenInvalid, wantHTTP: http.StatusUnauthorized},
		{name: "签名无效", err: token.ErrSignatureInvalid, wantCode: token.CodeTokenInvalid, wantHTTP: http.StatusUnauthorized},
		{name: "缺少声明", err: token.ErrMissingClaims, wantCode: token.CodeTokenInvalid, wantHTTP: http.StatusUnauthorized},
		{name: "错误签发方", err: token.ErrWrongIssuer, wantCode: token.CodeTokenInvalid, wantHTTP: http.StatusUnauthorized},
		{name: "错误类型", err: token.ErrWrongType, wantCode: token.CodeTokenInvalid, wantHTTP: http.StatusUnauthorized},
		{name: "尚未生效", err: token.ErrTokenNotYetValid, wantCode: token.CodeTokenInvalid, wantHTTP: http.StatusUnauthorized},
		{name: "已过期", err: token.ErrTokenExpired, wantCode: token.CodeTokenExpired, wantHTTP: http.StatusUnauthorized},
		{name: "密钥撤销", err: token.ErrKeyRevoked, wantCode: token.CodeTokenRevoked, wantHTTP: http.StatusUnauthorized},
		{name: "接收方不匹配", err: token.ErrAudienceMismatch, wantCode: token.CodeTokenAudienceMismatch, wantHTTP: http.StatusForbidden},
		{name: "客户端停用", err: token.ErrClientInactive, wantCode: token.CodeClientDisabled, wantHTTP: http.StatusForbidden},
		{name: "存储不可用", err: token.ErrStoreUnavailable, wantCode: token.CodeDBUnavailable, wantHTTP: http.StatusServiceUnavailable},
		{name: "审计不可用", err: token.ErrAuditUnavailable, wantCode: token.CodeAuditWriteFailed, wantHTTP: http.StatusServiceUnavailable},
		{name: "选项无效", err: token.ErrOptionsInvalid, wantCode: token.CodeInternalError, wantHTTP: http.StatusInternalServerError},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := token.CodeOf(test.err)
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
		t.Errorf("错误码注册表数量 = %d，期望 48（令牌模块不新增错误码）", len(RegisteredErrorCodes()))
	}
}
