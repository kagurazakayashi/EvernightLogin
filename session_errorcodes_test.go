package login

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	"github.com/kagurazakayashi/EvernightLogin/internal/transport"
)

// TestSessionErrorCodesRegistered 验证会话领域复用根包已登记错误码：统一会话无效
// 与签发不可用映射 AUTH_FAILED，受限会话/强认证要求映射 ACCESS_DENIED，非法请求
// 映射 REQ_INVALID，存储不可用映射 DB_UNAVAILABLE，审计失败映射
// AUDIT_WRITE_FAILED，选项无效映射 INTERNAL_ERROR；不新增注册码。
func TestSessionErrorCodesRegistered(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode session.ErrorCode
		wantHTTP int
	}{
		{name: "会话无效", err: session.ErrSessionInvalid, wantCode: session.CodeAuthFailed, wantHTTP: http.StatusUnauthorized},
		{name: "签发账户不可用", err: session.ErrAccountNotEligible, wantCode: session.CodeAuthFailed, wantHTTP: http.StatusUnauthorized},
		{name: "轮换旧会话失败", err: session.ErrRotationFailed, wantCode: session.CodeAuthFailed, wantHTTP: http.StatusUnauthorized},
		{name: "并发上限复核失败", err: session.ErrConcurrentLimit, wantCode: session.CodeAuthFailed, wantHTTP: http.StatusUnauthorized},
		{name: "会话管理无权", err: session.ErrAccessDenied, wantCode: session.CodeAccessDenied, wantHTTP: http.StatusForbidden},
		{name: "受限会话", err: session.ErrRestrictedSession, wantCode: session.CodeAccessDenied, wantHTTP: http.StatusForbidden},
		{name: "需要强认证", err: session.ErrStrongAuthRequired, wantCode: session.CodeAccessDenied, wantHTTP: http.StatusForbidden},
		{name: "非法请求", err: fmt.Errorf("%w: bad", session.ErrInvalidRequest), wantCode: session.CodeReqInvalid, wantHTTP: http.StatusBadRequest},
		{name: "存储不可用", err: session.ErrStoreUnavailable, wantCode: session.CodeDBUnavailable, wantHTTP: http.StatusServiceUnavailable},
		{name: "审计不可用", err: session.ErrAuditUnavailable, wantCode: session.CodeAuditWriteFailed, wantHTTP: http.StatusServiceUnavailable},
		{name: "服务选项无效", err: session.ErrOptionsInvalid, wantCode: session.CodeInternalError, wantHTTP: http.StatusInternalServerError},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := session.CodeOf(test.err)
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
	// 不新增注册码：会话模块只复用既有注册表。
	if len(RegisteredErrorCodes()) != 46 {
		t.Errorf("错误码注册表数量 = %d，期望 46（会话模块不新增错误码）", len(RegisteredErrorCodes()))
	}
}

// TestSessionCookieAndCSRFContract 验证会话 Cookie 与会话 CSRF 校验器与既有 HTTP
// 防护契约一致：Cookie 名与 CSRF 中间件默认会话 Cookie 名相同，默认 Cookie 安全
// 属性与根包 DefaultCookiePolicy 相同，会话服务可直接作为 CSRFValidator 使用。
func TestSessionCookieAndCSRFContract(t *testing.T) {
	if session.DefaultCookieName != transport.DefaultCSRFCookieName {
		t.Errorf("会话 Cookie 名 = %q，CSRF 中间件会话 Cookie 名 = %q，两者必须一致",
			session.DefaultCookieName, transport.DefaultCSRFCookieName)
	}
	internalPolicy := session.DefaultCookiePolicy()
	publicPolicy := DefaultCookiePolicy()
	if internalPolicy.Secure != publicPolicy.Secure {
		t.Error("会话 Cookie Secure 与根包 CookiePolicy 默认值不一致")
	}
	if internalPolicy.HttpOnly != publicPolicy.HttpOnly {
		t.Error("会话 Cookie HttpOnly 与根包 CookiePolicy 默认值不一致")
	}
	if internalPolicy.SameSite != publicPolicy.SameSite {
		t.Error("会话 Cookie SameSite 与根包 CookiePolicy 默认值不一致")
	}
	if internalPolicy.Path != publicPolicy.Path {
		t.Error("会话 Cookie Path 与根包 CookiePolicy 默认值不一致")
	}
	if internalPolicy.Domain != publicPolicy.Domain {
		t.Error("会话 Cookie Domain 与根包 CookiePolicy 默认值不一致")
	}
	if internalPolicy.MaxAge != publicPolicy.MaxAge {
		t.Error("会话 Cookie MaxAge 与根包 CookiePolicy 默认值不一致")
	}
	// 会话服务实现 CSRFValidator，可直接接 HTTPProtectionOptions.CSRF.TokenValidator；
	// 来源（Origin/Referer）规则仍由同一 CSRF 中间件负责。
	var _ CSRFValidator = (*session.Service)(nil)
}
