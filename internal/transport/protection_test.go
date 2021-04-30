package transport

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// protectionClock 是可手动推进的并发安全测试时钟。
type protectionClock struct {
	mu  sync.Mutex
	now time.Time
}

// Now 返回当前测试时间。
func (c *protectionClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance 推进测试时间。
func (c *protectionClock) Advance(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(duration)
}

// testProtection 返回默认关闭限流、保留安全默认值的基础防护配置。
func testProtection() *ProtectionOptions {
	return &ProtectionOptions{
		RequestTimeout:        2 * time.Second,
		MaxConcurrentRequests: 16,
		RateLimit:             RateLimitConfig{Disabled: true},
	}
}

// testIdentityResolver 只在测试中按请求头返回可控身份，绝不用于生产。
func testIdentityResolver(_ context.Context, request *http.Request) (Identity, error) {
	value := request.Header.Get("X-Test-Identity")
	switch value {
	case "":
		return Identity{}, errors.New("测试身份缺失")
	case "user-1", "user-2":
		return Identity{Kind: "user", SubjectID: value}, nil
	case "app-1":
		return Identity{Kind: "application", SubjectID: "client-1", AppID: "app-1"}, nil
	case "app-2":
		return Identity{Kind: "application", SubjectID: "client-2", AppID: "app-2"}, nil
	default:
		return Identity{}, errors.New("测试身份未知")
	}
}

// cheapGetRoute 返回固定成功响应。
func cheapGetRoute() route {
	return route{
		method: http.MethodGet,
		path:   "/test/cheap",
		handle: func(_ context.Context, w *responseWriter, _ *http.Request) error {
			return jsonResponse(w, http.StatusOK, map[string]string{"ok": "yes"})
		},
	}
}

// cheapPostRoute 返回固定成功响应，供 CSRF 测试使用。
func cheapPostRoute() route {
	return route{
		method: http.MethodPost,
		path:   "/test/cheap",
		handle: func(_ context.Context, w *responseWriter, _ *http.Request) error {
			return jsonResponse(w, http.StatusOK, map[string]string{"ok": "yes"})
		},
	}
}

// otherGetRoute 是另一个接口，用于验证接口维度隔离。
func otherGetRoute() route {
	return route{
		method: http.MethodGet,
		path:   "/test/other",
		handle: func(_ context.Context, w *responseWriter, _ *http.Request) error {
			return jsonResponse(w, http.StatusOK, map[string]string{"ok": "yes"})
		},
	}
}

// testProtectionHandler 构造带测试路由与防护配置的 Handler。
func testProtectionHandler(t *testing.T, protection *ProtectionOptions, routes []route, resolver ResolveIdentityFunc) *handler {
	t.Helper()
	options := testOptions(nil)
	options.Protection = protection
	options.extraRoutes = routes
	options.ResolveIdentity = resolver
	return buildHandler(t, options)
}

// protectionRequest 构造指定方法、路径与远端地址的请求。
func protectionRequest(method, path, remoteAddr string) *http.Request {
	request := httptest.NewRequest(method, path, nil)
	request.RemoteAddr = remoteAddr
	return request
}

// serveProtection 执行请求并返回记录器。
func serveProtection(handler *handler, request *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

// assertRateLimited 断言 429 响应包含 RATE_LIMITED、Retry-After 与 JSON 等待建议。
func assertRateLimited(t *testing.T, recorder *httptest.ResponseRecorder) {
	t.Helper()
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("状态 = %d，期望 429（%s）", recorder.Code, recorder.Body.String())
	}
	if header := recorder.Header().Get("Retry-After"); header == "" {
		t.Fatal("限流响应缺少 Retry-After")
	} else if seconds, err := strconv.Atoi(header); err != nil || seconds < 1 {
		t.Fatalf("Retry-After = %q，期望正整数", header)
	}
	payload := decodeJSONMap(t, recorder.Body.Bytes())
	if payload["code"] != "RATE_LIMITED" {
		t.Fatalf("错误码 = %v，期望 RATE_LIMITED", payload["code"])
	}
	seconds, ok := payload["retry_after_seconds"].(float64)
	if !ok || seconds < 1 {
		t.Fatalf("retry_after_seconds = %v，期望 >=1", payload["retry_after_seconds"])
	}
	if !strings.Contains(recorder.Body.String(), "request_id") {
		t.Fatalf("限流响应缺少 request_id: %s", recorder.Body.String())
	}
}

// TestSecurityHeadersAppliedToAllResponses 验证默认安全头、错误响应与自定义头。
func TestSecurityHeadersAppliedToAllResponses(t *testing.T) {
	handler := testProtectionHandler(t, testProtection(), nil, nil)
	for _, path := range []string{"/healthz", "/missing"} {
		recorder := serveProtection(handler, protectionRequest(http.MethodGet, path, "203.0.113.9:1234"))
		header := recorder.Header()
		checks := map[string]string{
			"X-Content-Type-Options":       "nosniff",
			"X-Frame-Options":              "DENY",
			"Referrer-Policy":              "no-referrer",
			"Cross-Origin-Opener-Policy":   "same-origin",
			"Cross-Origin-Resource-Policy": "same-origin",
		}
		for name, want := range checks {
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
	}

	custom := testProtection()
	custom.SecurityHeaders = SecurityHeaderConfig{
		ContentSecurityPolicy: "default-src 'self'; frame-ancestors 'self'",
		AllowFraming:          true,
		EnableHSTS:            true,
	}
	customHandler := testProtectionHandler(t, custom, nil, nil)
	recorder := serveProtection(customHandler, protectionRequest(http.MethodGet, "/healthz", "203.0.113.9:1234"))
	if got := recorder.Header().Get("X-Frame-Options"); got != "SAMEORIGIN" {
		t.Fatalf("允许同源嵌入时 X-Frame-Options = %q", got)
	}
	if got := recorder.Header().Get("Content-Security-Policy"); got != "default-src 'self'; frame-ancestors 'self'" {
		t.Fatalf("自定义 CSP = %q", got)
	}
	if got := recorder.Header().Get("Strict-Transport-Security"); got == "" {
		t.Fatal("启用 HSTS 后缺少响应头")
	}

	framing := testProtection()
	framing.SecurityHeaders = SecurityHeaderConfig{AllowFraming: true}
	framingHandler := testProtectionHandler(t, framing, nil, nil)
	framingRecorder := serveProtection(framingHandler, protectionRequest(http.MethodGet, "/healthz", "203.0.113.9:1234"))
	if got := framingRecorder.Header().Get("X-Frame-Options"); got != "SAMEORIGIN" {
		t.Fatalf("默认 CSP 允许同源嵌入时 X-Frame-Options = %q", got)
	}
	if csp := framingRecorder.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'self'") {
		t.Fatalf("默认 CSP 允许同源嵌入时仍禁止被嵌入: %q", csp)
	}
}

// TestClientIPRateLimitIgnoresForgedForwardedFor 验证未配置可信代理时忽略伪造的
// X-Forwarded-For，只按直连地址限流。
func TestClientIPRateLimitIgnoresForgedForwardedFor(t *testing.T) {
	protection := testProtection()
	protection.RateLimit = RateLimitConfig{ClientIP: RateLimitRule{Limit: 1, Window: time.Minute}}
	handler := testProtectionHandler(t, protection, []route{cheapGetRoute()}, nil)

	first := protectionRequest(http.MethodGet, "/test/cheap", "203.0.113.9:1111")
	first.Header.Set("X-Forwarded-For", "198.51.100.7")
	if recorder := serveProtection(handler, first); recorder.Code != http.StatusOK {
		t.Fatalf("首个请求状态 = %d", recorder.Code)
	}
	second := protectionRequest(http.MethodGet, "/test/cheap", "203.0.113.9:2222")
	second.Header.Set("X-Forwarded-For", "198.51.100.7")
	assertRateLimited(t, serveProtection(handler, second))

	third := protectionRequest(http.MethodGet, "/test/cheap", "203.0.113.9:3333")
	third.Header.Set("X-Forwarded-For", "198.51.100.8")
	assertRateLimited(t, serveProtection(handler, third))

	other := protectionRequest(http.MethodGet, "/test/cheap", "203.0.113.10:4444")
	if recorder := serveProtection(handler, other); recorder.Code != http.StatusOK {
		t.Fatalf("不同直连地址状态 = %d", recorder.Code)
	}
}

// TestTrustedProxyClientIPResolution 验证只有显式可信代理的 X-Forwarded-For 生效。
func TestTrustedProxyClientIPResolution(t *testing.T) {
	protection := testProtection()
	protection.TrustedProxies = []string{"10.0.0.1"}
	protection.RateLimit = RateLimitConfig{ClientIP: RateLimitRule{Limit: 1, Window: time.Minute}}
	handler := testProtectionHandler(t, protection, []route{cheapGetRoute()}, nil)

	request := func(client string) *http.Request {
		r := protectionRequest(http.MethodGet, "/test/cheap", "10.0.0.1:1234")
		r.Header.Set("X-Forwarded-For", client)
		return r
	}
	if recorder := serveProtection(handler, request("198.51.100.7")); recorder.Code != http.StatusOK {
		t.Fatalf("可信代理首个客户端请求状态 = %d", recorder.Code)
	}
	assertRateLimited(t, serveProtection(handler, request("198.51.100.7")))
	if recorder := serveProtection(handler, request("198.51.100.8")); recorder.Code != http.StatusOK {
		t.Fatalf("不同客户端地址应独立限流，状态 = %d", recorder.Code)
	}

	malformedProtection := testProtection()
	malformedProtection.TrustedProxies = []string{"10.0.0.1"}
	malformedProtection.RateLimit = RateLimitConfig{ClientIP: RateLimitRule{Limit: 1, Window: time.Minute}}
	malformedHandler := testProtectionHandler(t, malformedProtection, []route{cheapGetRoute()}, nil)
	malformed := protectionRequest(http.MethodGet, "/test/cheap", "10.0.0.1:1234")
	malformed.Header.Set("X-Forwarded-For", "not-an-ip")
	if recorder := serveProtection(malformedHandler, malformed); recorder.Code != http.StatusOK {
		t.Fatalf("畸形转发头首个请求状态 = %d", recorder.Code)
	}
	malformedAgain := protectionRequest(http.MethodGet, "/test/cheap", "10.0.0.1:5678")
	malformedAgain.Header.Set("X-Forwarded-For", "not-an-ip")
	assertRateLimited(t, serveProtection(malformedHandler, malformedAgain))
}

// TestRateLimitByEndpoint 验证接口维度独立计数。
func TestRateLimitByEndpoint(t *testing.T) {
	protection := testProtection()
	protection.RateLimit = RateLimitConfig{Endpoint: RateLimitRule{Limit: 1, Window: time.Minute}}
	handler := testProtectionHandler(t, protection, []route{cheapGetRoute(), otherGetRoute()}, nil)

	if recorder := serveProtection(handler, protectionRequest(http.MethodGet, "/test/cheap", "203.0.113.9:1111")); recorder.Code != http.StatusOK {
		t.Fatalf("首个接口请求状态 = %d", recorder.Code)
	}
	assertRateLimited(t, serveProtection(handler, protectionRequest(http.MethodGet, "/test/cheap", "203.0.113.9:1111")))
	if recorder := serveProtection(handler, protectionRequest(http.MethodGet, "/test/other", "203.0.113.9:1111")); recorder.Code != http.StatusOK {
		t.Fatalf("另一个接口不应受同一维度影响，状态 = %d", recorder.Code)
	}
}

// TestRateLimitByAuthenticatedUserAndApplication 验证用户/应用维度只使用可信
// 身份，客户端自填 user_id 不参与分桶。
func TestRateLimitByAuthenticatedUserAndApplication(t *testing.T) {
	protection := testProtection()
	protection.RateLimit = RateLimitConfig{
		User:        RateLimitRule{Limit: 1, Window: time.Minute},
		Application: RateLimitRule{Limit: 1, Window: time.Minute},
	}
	handler := testProtectionHandler(t, protection, []route{identityRoute(), cheapGetRoute()}, testIdentityResolver)

	protected := func(who string) *http.Request {
		request := protectionRequest(http.MethodGet, "/test/identity", "203.0.113.9:1111")
		request.Header.Set("X-Test-Identity", who)
		return request
	}
	if recorder := serveProtection(handler, protected("user-1")); recorder.Code != http.StatusOK {
		t.Fatalf("user-1 首个请求状态 = %d", recorder.Code)
	}
	assertRateLimited(t, serveProtection(handler, protected("user-1")))
	if recorder := serveProtection(handler, protected("user-2")); recorder.Code != http.StatusOK {
		t.Fatalf("user-2 应独立限流，状态 = %d", recorder.Code)
	}
	if recorder := serveProtection(handler, protected("app-1")); recorder.Code != http.StatusOK {
		t.Fatalf("app-1 首个请求状态 = %d", recorder.Code)
	}
	assertRateLimited(t, serveProtection(handler, protected("app-1")))
	if recorder := serveProtection(handler, protected("app-2")); recorder.Code != http.StatusOK {
		t.Fatalf("app-2 应独立限流，状态 = %d", recorder.Code)
	}

	// 匿名请求不受用户/应用维度约束；伪造 X-User-ID 不能制造用户桶。
	forgedProtection := testProtection()
	forgedProtection.RateLimit = RateLimitConfig{User: RateLimitRule{Limit: 1, Window: time.Minute}}
	forgedHandler := testProtectionHandler(t, forgedProtection, []route{cheapGetRoute()}, nil)
	for index := 0; index < 2; index++ {
		request := protectionRequest(http.MethodGet, "/test/cheap", "203.0.113.20:1111")
		request.Header.Set("X-User-ID", "user-1")
		if recorder := serveProtection(forgedHandler, request); recorder.Code != http.StatusOK {
			t.Fatalf("匿名请求 %d 状态 = %d，伪造 user_id 不应参与限流", index+1, recorder.Code)
		}
	}
}

// TestExpensiveRequestBudget 验证昂贵接口独立预算，普通接口不受影响。
func TestExpensiveRequestBudget(t *testing.T) {
	protection := testProtection()
	protection.RateLimit = RateLimitConfig{Expensive: RateLimitRule{Limit: 1, Window: time.Minute}}
	protection.ExpensivePaths = []string{"/test/cheap"}
	handler := testProtectionHandler(t, protection, []route{cheapGetRoute(), otherGetRoute()}, nil)

	if recorder := serveProtection(handler, protectionRequest(http.MethodGet, "/test/cheap", "203.0.113.9:1111")); recorder.Code != http.StatusOK {
		t.Fatalf("昂贵接口首个请求状态 = %d", recorder.Code)
	}
	assertRateLimited(t, serveProtection(handler, protectionRequest(http.MethodGet, "/test/cheap", "203.0.113.9:1111")))
	if recorder := serveProtection(handler, protectionRequest(http.MethodGet, "/test/other", "203.0.113.9:1111")); recorder.Code != http.StatusOK {
		t.Fatalf("普通接口不应消耗昂贵预算，状态 = %d", recorder.Code)
	}
}

// TestRateLimitCapacityAndCleanup 验证容量上限 fail-closed 与过期清理。
func TestRateLimitCapacityAndCleanup(t *testing.T) {
	clock := &protectionClock{now: time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)}
	protection := testProtection()
	protection.RateLimit = RateLimitConfig{
		ClientIP:        RateLimitRule{Limit: 10, Window: time.Minute},
		Capacity:        2,
		CleanupInterval: 30 * time.Second,
	}
	options := testOptions(nil)
	options.Protection = protection
	options.extraRoutes = []route{cheapGetRoute()}
	options.Now = clock.Now
	handler := buildHandler(t, options)

	for _, address := range []string{"203.0.113.1:1111", "203.0.113.2:1111"} {
		if recorder := serveProtection(handler, protectionRequest(http.MethodGet, "/test/cheap", address)); recorder.Code != http.StatusOK {
			t.Fatalf("容量未满时 %s 状态 = %d", address, recorder.Code)
		}
	}
	assertRateLimited(t, serveProtection(handler, protectionRequest(http.MethodGet, "/test/cheap", "203.0.113.3:1111")))
	// 已有键仍可计数。
	if recorder := serveProtection(handler, protectionRequest(http.MethodGet, "/test/cheap", "203.0.113.1:1111")); recorder.Code != http.StatusOK {
		t.Fatalf("容量耗尽后已有键应继续允许，状态 = %d", recorder.Code)
	}
	clock.Advance(time.Minute)
	if recorder := serveProtection(handler, protectionRequest(http.MethodGet, "/test/cheap", "203.0.113.4:1111")); recorder.Code != http.StatusOK {
		t.Fatalf("窗口过期清理后新键应允许，状态 = %d", recorder.Code)
	}
}

// TestRateLimitConcurrentRace 验证 6 路并发下计数准确、无竞态。
func TestRateLimitConcurrentRace(t *testing.T) {
	clock := &protectionClock{now: time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)}
	protection := testProtection()
	protection.RateLimit = RateLimitConfig{ClientIP: RateLimitRule{Limit: 3, Window: time.Minute}}
	options := testOptions(nil)
	options.Protection = protection
	options.extraRoutes = []route{cheapGetRoute()}
	options.Now = clock.Now
	handler := buildHandler(t, options)

	const goroutines = 6
	var waitGroup sync.WaitGroup
	var allowed atomic.Int32
	var denied atomic.Int32
	for index := 0; index < goroutines; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			recorder := serveProtection(handler, protectionRequest(http.MethodGet, "/test/cheap", "203.0.113.30:1111"))
			switch recorder.Code {
			case http.StatusOK:
				allowed.Add(1)
			case http.StatusTooManyRequests:
				denied.Add(1)
			default:
				t.Errorf("并发请求状态 = %d", recorder.Code)
			}
		}()
	}
	waitGroup.Wait()
	if allowed.Load() != 3 || denied.Load() != 3 {
		t.Fatalf("并发限流结果 allowed=%d denied=%d，期望 3/3", allowed.Load(), denied.Load())
	}
}

// TestCORSExactOriginsPreflightAndRejection 验证精确来源、预检与拒绝。
func TestCORSExactOriginsPreflightAndRejection(t *testing.T) {
	protection := testProtection()
	protection.CORS = CORSConfig{
		AllowedOrigins:   []string{"https://app.example.com"},
		AllowCredentials: true,
	}
	handler := testProtectionHandler(t, protection, []route{cheapGetRoute(), cheapPostRoute()}, nil)

	allowed := protectionRequest(http.MethodGet, "/test/cheap", "203.0.113.9:1111")
	allowed.Header.Set("Origin", "https://app.example.com")
	recorder := serveProtection(handler, allowed)
	if recorder.Code != http.StatusOK {
		t.Fatalf("允许来源状态 = %d", recorder.Code)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Fatalf("ACAO = %q", got)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("Allow-Credentials = %q", got)
	}
	if !strings.Contains(recorder.Header().Get("Vary"), "Origin") {
		t.Fatalf("缺少 Vary: Origin")
	}

	disallowed := protectionRequest(http.MethodGet, "/test/cheap", "203.0.113.9:1111")
	disallowed.Header.Set("Origin", "https://evil.example.com")
	recorder = serveProtection(handler, disallowed)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("不允许来源状态 = %d", recorder.Code)
	}
	if recorder.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("不允许来源不应回显 ACAO")
	}
	if payload := decodeJSONMap(t, recorder.Body.Bytes()); payload["code"] != "ACCESS_DENIED" {
		t.Fatalf("来源拒绝错误码 = %v", payload["code"])
	}

	preflight := protectionRequest(http.MethodOptions, "/test/cheap", "203.0.113.9:1111")
	preflight.Header.Set("Origin", "https://app.example.com")
	preflight.Header.Set("Access-Control-Request-Method", http.MethodGet)
	preflight.Header.Set("Access-Control-Request-Headers", "content-type, x-csrf-token")
	recorder = serveProtection(handler, preflight)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("预检状态 = %d（%s）", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Fatalf("预检 ACAO = %q", got)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Methods"); !strings.Contains(got, http.MethodGet) {
		t.Fatalf("预检允许方法 = %q", got)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(strings.ToLower(got), "x-csrf-token") {
		t.Fatalf("预检允许头 = %q", got)
	}
	if got := recorder.Header().Get("Access-Control-Max-Age"); got == "" {
		t.Fatal("预检缺少 Max-Age")
	}

	badOrigin := protectionRequest(http.MethodOptions, "/test/cheap", "203.0.113.9:1111")
	badOrigin.Header.Set("Origin", "https://evil.example.com")
	badOrigin.Header.Set("Access-Control-Request-Method", http.MethodGet)
	if recorder := serveProtection(handler, badOrigin); recorder.Code != http.StatusForbidden {
		t.Fatalf("不允许来源预检状态 = %d", recorder.Code)
	}

	badMethod := protectionRequest(http.MethodOptions, "/test/cheap", "203.0.113.9:1111")
	badMethod.Header.Set("Origin", "https://app.example.com")
	badMethod.Header.Set("Access-Control-Request-Method", "TRACE")
	if recorder := serveProtection(handler, badMethod); recorder.Code != http.StatusForbidden {
		t.Fatalf("不允许方法预检状态 = %d", recorder.Code)
	}

	badHeader := protectionRequest(http.MethodOptions, "/test/cheap", "203.0.113.9:1111")
	badHeader.Header.Set("Origin", "https://app.example.com")
	badHeader.Header.Set("Access-Control-Request-Method", http.MethodGet)
	badHeader.Header.Set("Access-Control-Request-Headers", "x-evil")
	if recorder := serveProtection(handler, badHeader); recorder.Code != http.StatusForbidden {
		t.Fatalf("不允许请求头预检状态 = %d", recorder.Code)
	}

	if _, err := newProtection(&ProtectionOptions{CORS: CORSConfig{AllowedOrigins: []string{"*"}}}, nil); err == nil {
		t.Fatal("通配符 CORS 来源应在构造时被拒绝")
	}
	if _, err := newProtection(&ProtectionOptions{CORS: CORSConfig{AllowCredentials: true}}, nil); err == nil {
		t.Fatal("只有 AllowCredentials 而无来源应在构造时被拒绝")
	}
}

// TestCSRFCookieSessionContract 验证来源与令牌双校验、安全方法豁免，以及 CORS
// 不能替代 CSRF。
func TestCSRFCookieSessionContract(t *testing.T) {
	validator := CSRFConfig{
		Enabled:        true,
		AllowedOrigins: []string{"https://app.example.com"},
		ValidateToken: func(_ context.Context, _ *http.Request, token string) error {
			if token == "good-token" {
				return nil
			}
			return errors.New("bad token")
		},
	}
	protection := testProtection()
	protection.CSRF = validator
	protection.CORS = CORSConfig{AllowedOrigins: []string{"https://app.example.com"}}
	handler := testProtectionHandler(t, protection, []route{cheapGetRoute(), cheapPostRoute()}, nil)

	sessionCookie := &http.Cookie{Name: DefaultCSRFCookieName, Value: "session-1", Path: "/"}
	base := func(method string) *http.Request {
		return protectionRequest(method, "/test/cheap", "203.0.113.9:1111")
	}

	// 安全方法：有会话 Cookie 也不要求 CSRF 令牌，兼容顶层跨站授权跳转。
	safe := base(http.MethodGet)
	safe.AddCookie(sessionCookie)
	safe.Header.Set("Origin", "https://app.example.com")
	if recorder := serveProtection(handler, safe); recorder.Code != http.StatusOK {
		t.Fatalf("安全方法状态 = %d", recorder.Code)
	}

	// 无会话 Cookie 的令牌认证接口不要求 CSRF。
	tokenAuth := base(http.MethodPost)
	if recorder := serveProtection(handler, tokenAuth); recorder.Code != http.StatusOK {
		t.Fatalf("无 Cookie 的不安全方法状态 = %d", recorder.Code)
	}

	missing := base(http.MethodPost)
	missing.AddCookie(sessionCookie)
	missing.Header.Set("Origin", "https://app.example.com")
	if recorder := serveProtection(handler, missing); recorder.Code != http.StatusForbidden {
		t.Fatalf("缺少 CSRF 令牌状态 = %d", recorder.Code)
	} else if payload := decodeJSONMap(t, recorder.Body.Bytes()); payload["code"] != "ACCESS_DENIED" {
		t.Fatalf("CSRF 失败错误码 = %v", payload["code"])
	}

	badToken := base(http.MethodPost)
	badToken.AddCookie(sessionCookie)
	badToken.Header.Set("Origin", "https://app.example.com")
	badToken.Header.Set(DefaultCSRFTokenHeader, "bad-token")
	if recorder := serveProtection(handler, badToken); recorder.Code != http.StatusForbidden {
		t.Fatalf("错误 CSRF 令牌状态 = %d", recorder.Code)
	}

	good := base(http.MethodPost)
	good.AddCookie(sessionCookie)
	good.Header.Set("Origin", "https://app.example.com")
	good.Header.Set(DefaultCSRFTokenHeader, "good-token")
	if recorder := serveProtection(handler, good); recorder.Code != http.StatusOK {
		t.Fatalf("合法 CSRF 请求状态 = %d", recorder.Code)
	}

	badOrigin := base(http.MethodPost)
	badOrigin.AddCookie(sessionCookie)
	badOrigin.Header.Set("Origin", "https://evil.example.com")
	badOrigin.Header.Set(DefaultCSRFTokenHeader, "good-token")
	if recorder := serveProtection(handler, badOrigin); recorder.Code != http.StatusForbidden {
		t.Fatalf("错误来源 CSRF 状态 = %d", recorder.Code)
	}

	noOrigin := base(http.MethodPost)
	noOrigin.AddCookie(sessionCookie)
	noOrigin.Header.Set(DefaultCSRFTokenHeader, "good-token")
	if recorder := serveProtection(handler, noOrigin); recorder.Code != http.StatusForbidden {
		t.Fatalf("缺少来源 CSRF 状态 = %d", recorder.Code)
	}

	referer := base(http.MethodPost)
	referer.AddCookie(sessionCookie)
	referer.Header.Set("Referer", "https://app.example.com/scan?state=1")
	referer.Header.Set(DefaultCSRFTokenHeader, "good-token")
	if recorder := serveProtection(handler, referer); recorder.Code != http.StatusOK {
		t.Fatalf("允许 Referer 来源状态 = %d", recorder.Code)
	}

	// CORS 允许来源但没有 CSRF 令牌：仍必须拒绝。
	corsOnly := base(http.MethodPost)
	corsOnly.AddCookie(sessionCookie)
	corsOnly.Header.Set("Origin", "https://app.example.com")
	if recorder := serveProtection(handler, corsOnly); recorder.Code != http.StatusForbidden {
		t.Fatalf("CORS 允许但缺 CSRF 令牌状态 = %d", recorder.Code)
	}

	if _, err := newProtection(&ProtectionOptions{CSRF: CSRFConfig{Enabled: true}}, nil); err == nil {
		t.Fatal("启用 CSRF 但缺校验器/来源应在构造时被拒绝")
	}
}

// TestConcurrencyLimitRejectsWithoutQueueing 验证并发上限立即拒绝并返回等待建议。
func TestConcurrencyLimitRejectsWithoutQueueing(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan struct{})
	var startOnce sync.Once
	blocking := route{
		method: http.MethodGet,
		path:   "/test/block",
		handle: func(_ context.Context, w *responseWriter, _ *http.Request) error {
			startOnce.Do(func() { close(started) })
			<-release
			close(finished)
			return jsonResponse(w, http.StatusOK, map[string]string{"ok": "done"})
		},
	}
	protection := testProtection()
	protection.MaxConcurrentRequests = 1
	handler := testProtectionHandler(t, protection, []route{blocking}, nil)

	firstDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		firstDone <- serveProtection(handler, protectionRequest(http.MethodGet, "/test/block", "203.0.113.9:1111"))
	}()
	<-started
	second := serveProtection(handler, protectionRequest(http.MethodGet, "/test/block", "203.0.113.9:1111"))
	assertRateLimited(t, second)
	close(release)
	first := <-firstDone
	<-finished
	if first.Code != http.StatusOK {
		t.Fatalf("第一个并发请求状态 = %d", first.Code)
	}
}

// TestResponseTimeoutForcesGatewayTimeout 验证不响应 context 的处理器也能在墙钟
// 期限后得到 504，并且其后续写入不会污染已发送响应。
func TestResponseTimeoutForcesGatewayTimeout(t *testing.T) {
	release := make(chan struct{})
	handlerDone := make(chan struct{})
	blocking := route{
		method: http.MethodGet,
		path:   "/test/slow",
		handle: func(_ context.Context, w *responseWriter, _ *http.Request) error {
			<-release
			defer close(handlerDone)
			return jsonResponse(w, http.StatusOK, map[string]string{"ok": "late"})
		},
	}
	protection := testProtection()
	protection.RequestTimeout = 50 * time.Millisecond
	handler := testProtectionHandler(t, protection, []route{blocking}, nil)

	start := time.Now()
	recorder := serveProtection(handler, protectionRequest(http.MethodGet, "/test/slow", "203.0.113.9:1111"))
	elapsed := time.Since(start)
	if elapsed < 40*time.Millisecond {
		t.Fatalf("超时响应过早返回：%s", elapsed)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("超时响应过晚返回：%s", elapsed)
	}
	if recorder.Code != http.StatusGatewayTimeout {
		t.Fatalf("超时状态 = %d（%s）", recorder.Code, recorder.Body.String())
	}
	payload := decodeJSONMap(t, recorder.Body.Bytes())
	if payload["code"] != "INTERNAL_ERROR" {
		t.Fatalf("超时错误码 = %v", payload["code"])
	}
	close(release)
	<-handlerDone
}

// TestResponseTimeoutPropagatesContext 验证处理器通过 context 感知期限并返回 504。
func TestResponseTimeoutPropagatesContext(t *testing.T) {
	cooperative := route{
		method: http.MethodGet,
		path:   "/test/slow",
		handle: func(ctx context.Context, _ *responseWriter, _ *http.Request) error {
			<-ctx.Done()
			return ctx.Err()
		},
	}
	protection := testProtection()
	protection.RequestTimeout = 50 * time.Millisecond
	handler := testProtectionHandler(t, protection, []route{cooperative}, nil)
	start := time.Now()
	recorder := serveProtection(handler, protectionRequest(http.MethodGet, "/test/slow", "203.0.113.9:1111"))
	if recorder.Code != http.StatusGatewayTimeout {
		t.Fatalf("协作取消超时状态 = %d", recorder.Code)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("协作取消超时过久：%s", elapsed)
	}
}

// TestRateLimitErrorContainsWaitAdvice 验证 429 的等待建议与响应头一致。
func TestRateLimitErrorContainsWaitAdvice(t *testing.T) {
	protection := testProtection()
	protection.RateLimit = RateLimitConfig{ClientIP: RateLimitRule{Limit: 1, Window: 10 * time.Minute}}
	handler := testProtectionHandler(t, protection, []route{cheapGetRoute()}, nil)
	serveProtection(handler, protectionRequest(http.MethodGet, "/test/cheap", "203.0.113.40:1111"))
	recorder := serveProtection(handler, protectionRequest(http.MethodGet, "/test/cheap", "203.0.113.40:1111"))
	assertRateLimited(t, recorder)
	payload := decodeJSONMap(t, recorder.Body.Bytes())
	seconds, _ := payload["retry_after_seconds"].(float64)
	header, err := strconv.Atoi(recorder.Header().Get("Retry-After"))
	if err != nil {
		t.Fatalf("Retry-After 解析失败: %v", err)
	}
	if int(seconds) != header {
		t.Fatalf("JSON retry_after_seconds=%v 与 Retry-After=%d 不一致", seconds, header)
	}
}

// TestRateLimitByApplicationIdentity 补充应用身份独立于用户身份的限流键。
func TestRateLimitByApplicationIdentity(t *testing.T) {
	protection := testProtection()
	protection.RateLimit = RateLimitConfig{Application: RateLimitRule{Limit: 1, Window: time.Minute}}
	handler := testProtectionHandler(t, protection, []route{identityRoute()}, testIdentityResolver)
	for index := 0; index < 2; index++ {
		request := protectionRequest(http.MethodGet, "/test/identity", "203.0.113.50:1111")
		request.Header.Set("X-Test-Identity", "app-1")
		recorder := serveProtection(handler, request)
		if index == 0 && recorder.Code != http.StatusOK {
			t.Fatalf("应用身份首个请求状态 = %d", recorder.Code)
		}
		if index == 1 {
			assertRateLimited(t, recorder)
		}
	}
}
