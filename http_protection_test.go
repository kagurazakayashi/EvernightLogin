package login_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

// decodeResponseMap 解析响应 JSON。
func decodeResponseMap(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("响应不是合法 JSON: %v（%q）", err, recorder.Body.String())
	}
	return payload
}

// TestHTTPProtectionOptionsValidation 验证防护配置错误映射为 CONFIG_INVALID。
func TestHTTPProtectionOptionsValidation(t *testing.T) {
	validCSRF := login.CSRFPolicy{
		Enabled:        true,
		AllowedOrigins: []string{"https://app.example.com"},
		TokenValidator: login.CSRFValidatorFunc(func(_ context.Context, _ *http.Request, _ string) error {
			return nil
		}),
	}
	invalidSameSite := login.CookiePolicy{SameSite: http.SameSiteNoneMode, Path: "/"}
	invalidZeroSameSite := login.CookiePolicy{Path: "/"}
	cases := []struct {
		name       string
		protection *login.HTTPProtectionOptions
	}{
		{"非法可信代理", &login.HTTPProtectionOptions{TrustedProxies: []string{"not-an-ip"}}},
		{"显式限流无维度", &login.HTTPProtectionOptions{RateLimit: login.RateLimitOptions{Capacity: 16}}},
		{"限流缺窗口", &login.HTTPProtectionOptions{RateLimit: login.RateLimitOptions{ClientIP: login.RateLimitPolicy{Limit: 1}}}},
		{"CORS 通配来源", &login.HTTPProtectionOptions{CORS: login.CORSOptions{AllowedOrigins: []string{"*"}}}},
		{"CSRF 缺校验器", &login.HTTPProtectionOptions{CSRF: login.CSRFPolicy{Enabled: true, AllowedOrigins: []string{"https://app.example.com"}}}},
		{"CSRF 缺来源", &login.HTTPProtectionOptions{CSRF: login.CSRFPolicy{Enabled: true, TokenValidator: validCSRF.TokenValidator}}},
		{"Cookie SameSite None 未 Secure", &login.HTTPProtectionOptions{CookiePolicy: &invalidSameSite}},
		{"Cookie SameSite 未明确", &login.HTTPProtectionOptions{CookiePolicy: &invalidZeroSameSite}},
		{"请求期限过短", &login.HTTPProtectionOptions{RequestTimeout: time.Millisecond}},
		{"并发上限为负", &login.HTTPProtectionOptions{MaxConcurrentRequests: -1}},
		{"并发超上限", &login.HTTPProtectionOptions{MaxConcurrentRequests: login.MaxHTTPMaxConcurrentRequests + 1}},
		{"昂贵路径非绝对", &login.HTTPProtectionOptions{ExpensivePaths: []string{"healthz"}}},
		{"昂贵路径无预算", &login.HTTPProtectionOptions{RateLimit: login.RateLimitOptions{Disabled: true}, ExpensivePaths: []string{"/healthz"}}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			handler, err := login.NewHTTPHandler(login.HTTPOptions{Protection: testCase.protection})
			if err == nil || handler != nil {
				t.Fatalf("非法防护配置 %+v 应返回错误", testCase.protection)
			}
			if !login.IsErrorCode(err, login.CodeConfigInvalid) {
				t.Fatalf("错误码 = %v，期望 CONFIG_INVALID", err)
			}
		})
	}

	// 零值保护配置使用安全默认值，必须可构造。
	handler, err := login.NewHTTPHandler(login.HTTPOptions{Protection: &login.HTTPProtectionOptions{}})
	if err != nil || handler == nil {
		t.Fatalf("默认防护配置应有效: %v", err)
	}
	// 显式关闭限流，但 CSRF 配置合法，也允许构造。
	validHandler, err := login.NewHTTPHandler(login.HTTPOptions{Protection: &login.HTTPProtectionOptions{
		RateLimit: login.RateLimitOptions{Disabled: true},
		CSRF:      validCSRF,
	}})
	if err != nil || validHandler == nil {
		t.Fatalf("合法 CSRF 配置应有效: %v", err)
	}
}

// TestHTTPProtectionDefaultSecurityHeaders 验证默认安全响应头覆盖成功与错误响应。
func TestHTTPProtectionDefaultSecurityHeaders(t *testing.T) {
	handler, err := login.NewHTTPHandler(login.HTTPOptions{Protection: &login.HTTPProtectionOptions{}})
	if err != nil {
		t.Fatalf("构造 Handler 失败: %v", err)
	}
	for _, path := range []string{"/healthz", "/missing"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.RemoteAddr = "203.0.113.9:1234"
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		header := recorder.Header()
		for name, want := range map[string]string{
			"X-Content-Type-Options":       "nosniff",
			"X-Frame-Options":              "DENY",
			"Referrer-Policy":              "no-referrer",
			"Cross-Origin-Opener-Policy":   "same-origin",
			"Cross-Origin-Resource-Policy": "same-origin",
		} {
			if got := header.Get(name); got != want {
				t.Fatalf("%s 的 %s = %q，期望 %q", path, name, got, want)
			}
		}
		if csp := header.Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Fatalf("%s 默认 CSP = %q", path, csp)
		}
		if header.Get("Strict-Transport-Security") != "" {
			t.Fatalf("%s 默认不应输出 HSTS", path)
		}
		if header.Get("X-Request-ID") == "" {
			t.Fatalf("%s 缺少 X-Request-ID", path)
		}
	}
}

// TestHTTPProtectionRateLimitAndRetryAdvice 验证公开 Handler 的 429 与等待建议。
func TestHTTPProtectionRateLimitAndRetryAdvice(t *testing.T) {
	handler, err := login.NewHTTPHandler(login.HTTPOptions{Protection: &login.HTTPProtectionOptions{
		RateLimit: login.RateLimitOptions{
			ClientIP: login.RateLimitPolicy{Limit: 1, Window: time.Minute},
		},
	}})
	if err != nil {
		t.Fatalf("构造 Handler 失败: %v", err)
	}
	request := func() *http.Request {
		request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		request.RemoteAddr = "203.0.113.9:1234"
		return request
	}
	first := httptest.NewRecorder()
	handler.ServeHTTP(first, request())
	if first.Code != http.StatusOK {
		t.Fatalf("首个请求状态 = %d", first.Code)
	}
	second := httptest.NewRecorder()
	handler.ServeHTTP(second, request())
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("第二个请求状态 = %d（%s）", second.Code, second.Body.String())
	}
	if header := second.Header().Get("Retry-After"); header == "" {
		t.Fatal("限流响应缺少 Retry-After")
	} else if seconds, err := strconv.Atoi(header); err != nil || seconds < 1 {
		t.Fatalf("Retry-After = %q", header)
	}
	payload := decodeResponseMap(t, second)
	if payload["code"] != "RATE_LIMITED" {
		t.Fatalf("限流错误码 = %v", payload["code"])
	}
	seconds, ok := payload["retry_after_seconds"].(float64)
	if !ok || seconds < 1 {
		t.Fatalf("retry_after_seconds = %v", payload["retry_after_seconds"])
	}
	if second.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("限流响应缺少安全头")
	}
}

// TestHTTPProtectionCORSExactOrigin 验证公开 Handler 的精确来源与预检。
func TestHTTPProtectionCORSExactOrigin(t *testing.T) {
	handler, err := login.NewHTTPHandler(login.HTTPOptions{Protection: &login.HTTPProtectionOptions{
		RateLimit: login.RateLimitOptions{Disabled: true},
		CORS: login.CORSOptions{
			AllowedOrigins:   []string{"https://app.example.com"},
			AllowCredentials: true,
		},
	}})
	if err != nil {
		t.Fatalf("构造 Handler 失败: %v", err)
	}
	get := func(origin string) *http.Request {
		request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		request.RemoteAddr = "203.0.113.9:1234"
		if origin != "" {
			request.Header.Set("Origin", origin)
		}
		return request
	}
	allowed := httptest.NewRecorder()
	handler.ServeHTTP(allowed, get("https://app.example.com"))
	if allowed.Code != http.StatusOK {
		t.Fatalf("允许来源状态 = %d", allowed.Code)
	}
	if got := allowed.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Fatalf("ACAO = %q", got)
	}
	if got := allowed.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("Allow-Credentials = %q", got)
	}

	rejected := httptest.NewRecorder()
	handler.ServeHTTP(rejected, get("https://evil.example.com"))
	if rejected.Code != http.StatusForbidden {
		t.Fatalf("拒绝来源状态 = %d", rejected.Code)
	}
	if rejected.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("拒绝来源不应回显 ACAO")
	}
	if payload := decodeResponseMap(t, rejected); payload["code"] != "ACCESS_DENIED" {
		t.Fatalf("来源拒绝错误码 = %v", payload["code"])
	}

	preflight := httptest.NewRequest(http.MethodOptions, "/healthz", nil)
	preflight.RemoteAddr = "203.0.113.9:1234"
	preflight.Header.Set("Origin", "https://app.example.com")
	preflight.Header.Set("Access-Control-Request-Method", http.MethodGet)
	preflightRecorder := httptest.NewRecorder()
	handler.ServeHTTP(preflightRecorder, preflight)
	if preflightRecorder.Code != http.StatusNoContent {
		t.Fatalf("预检状态 = %d", preflightRecorder.Code)
	}
	if got := preflightRecorder.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Fatalf("预检 ACAO = %q", got)
	}
}

// TestCookiePolicyContract 验证 Cookie 安全属性与 __Host- 前缀规则。
func TestCookiePolicyContract(t *testing.T) {
	policy := login.DefaultCookiePolicy()
	if err := policy.Validate(); err != nil {
		t.Fatalf("默认 Cookie 策略无效: %v", err)
	}
	cookie, err := policy.NewCookie("__Host-login_session", "session-value")
	if err != nil {
		t.Fatalf("构造 __Host- Cookie 失败: %v", err)
	}
	if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("Cookie 安全属性 = %+v", cookie)
	}
	if cookie.Path != "/" || cookie.Domain != "" {
		t.Fatalf("Cookie Path/Domain = %q/%q", cookie.Path, cookie.Domain)
	}
	if _, err := (login.CookiePolicy{SameSite: http.SameSiteLaxMode, Path: "/"}).NewCookie("wordpress_sec", "x"); err != nil {
		t.Fatalf("普通 Cookie 名应允许: %v", err)
	}
	if err := (login.CookiePolicy{SameSite: http.SameSiteNoneMode, Path: "/"}).Validate(); err == nil {
		t.Fatal("SameSite=None 未启用 Secure 应被拒绝")
	}
	if err := (login.CookiePolicy{SameSite: http.SameSiteDefaultMode, Path: "/"}).Validate(); err == nil {
		t.Fatal("SameSite 未明确应被拒绝")
	}
	if err := (login.CookiePolicy{SameSite: http.SameSiteLaxMode, Path: "relative"}).Validate(); err == nil {
		t.Fatal("相对 Path 应被拒绝")
	}
	insecureHost := login.DefaultCookiePolicy()
	insecureHost.Secure = false
	if _, err := insecureHost.NewCookie("__Host-login_session", "x"); err == nil {
		t.Fatal("__Host- Cookie 未 Secure 应被拒绝")
	}
	if _, err := (login.CookiePolicy{SameSite: http.SameSiteLaxMode, Path: "/", Domain: ".example.com"}).NewCookie("__Host-login_session", "x"); err == nil {
		t.Fatal("__Host- Cookie 带 Domain 应被拒绝")
	}
}

// TestDefaultRateLimitOptionsContract 验证默认限流配置是启用且有限的。
func TestDefaultRateLimitOptionsContract(t *testing.T) {
	options := login.DefaultRateLimitOptions()
	if options.Disabled {
		t.Fatal("默认限流不应关闭")
	}
	if options.ClientIP.Limit <= 0 || options.User.Limit <= 0 || options.Application.Limit <= 0 ||
		options.Endpoint.Limit <= 0 || options.Expensive.Limit <= 0 {
		t.Fatalf("默认限流维度不完整: %+v", options)
	}
	if options.Capacity <= 0 || options.CleanupInterval <= 0 {
		t.Fatalf("默认容量/清理间隔无效: %+v", options)
	}
}

// TestOpenAPIDocumentsRateLimitContract 验证 OpenAPI 记录 429 与等待建议字段。
func TestOpenAPIDocumentsRateLimitContract(t *testing.T) {
	document, err := login.OpenAPIDocument("/api")
	if err != nil {
		t.Fatalf("生成 OpenAPI 失败: %v", err)
	}
	var decoded struct {
		Components struct {
			Schemas struct {
				Error struct {
					Properties map[string]json.RawMessage `json:"properties"`
				} `json:"Error"`
			} `json:"schemas"`
		} `json:"components"`
		CommonResponses map[string]json.RawMessage `json:"x-login-common-error-responses"`
	}
	if err := json.Unmarshal(document, &decoded); err != nil {
		t.Fatalf("OpenAPI 解析失败: %v", err)
	}
	if _, ok := decoded.Components.Schemas.Error.Properties["retry_after_seconds"]; !ok {
		t.Fatal("OpenAPI Error 缺少 retry_after_seconds")
	}
	if _, ok := decoded.CommonResponses["429"]; !ok {
		t.Fatal("OpenAPI 缺少 429 限流响应")
	}
}
