package adminapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// addTestRoute 在构造后的服务上追加一条测试路由（仅同包测试使用），用于验证
// 传输契约而不依赖具体领域服务。
func addTestRoute(server *Server, method, pattern string, handler func(*callContext) error) {
	server.routes = append(server.routes, route{method: method, pattern: pattern,
		segments: parseRoutePattern(pattern), handler: handler})
}

// TestNewValidatesOptions 验证 fail-closed 的构造校验：缺会话、缺错误码投影、
// 前缀/上限越界都不允许构造成功。
func TestNewValidatesOptions(t *testing.T) {
	stub := &stubSession{secret: "s", userID: "usr_00000000000000000000000000000001"}
	if _, err := New(Options{ErrorCodes: testCodes()}); err == nil {
		t.Fatal("缺少会话边界时不应构造成功")
	}
	if _, err := New(Options{Session: stub}); err == nil {
		t.Fatal("缺少错误码投影时不应构造成功")
	}
	if _, err := New(Options{Session: stub, ErrorCodes: []ErrorCodeInfo{
		{Code: "ACCESS_DENIED", Message: "x", HTTPStatus: 403}}}); err == nil {
		t.Fatal("错误码投影缺少传输必需码时不应构造成功")
	}
	for _, basePath := range []string{"/", "/admin/", "admin", "/admin//v1", "/admin/%76"} {
		_, err := New(Options{Session: stub, ErrorCodes: testCodes(), BasePath: basePath})
		if err == nil {
			t.Fatalf("非法挂载前缀 %q 不应构造成功", basePath)
		}
	}
	if _, err := New(Options{Session: stub, ErrorCodes: testCodes(),
		MaxBodyBytes: MaxMaxBodyBytes + 1}); err == nil {
		t.Fatal("请求体上限越界不应构造成功")
	}
	if _, err := New(Options{Session: stub, ErrorCodes: testCodes(),
		RequestTimeout: MinRequestTimeout / 2}); err == nil {
		t.Fatal("请求期限越界不应构造成功")
	}
	server, err := New(Options{Session: stub, ErrorCodes: testCodes()})
	if err != nil {
		t.Fatalf("合法配置构造失败: %v", err)
	}
	if server.BasePath() != DefaultBasePath || server.Version() != "v1" {
		t.Fatalf("默认前缀/版本不符合预期: %q %q", server.BasePath(), server.Version())
	}
}

// TestAuthenticationContract 验证认证失败与强认证缺失的 fail-closed 行为。
func TestAuthenticationContract(t *testing.T) {
	stub := &stubSession{secret: "s3cret", userID: "usr_00000000000000000000000000000001"}
	server := newStubServer(t, stub)

	reply := callAPI(t, server, http.MethodGet, "/admin/v1/meta", "", "", nil)
	requireErrorCode(t, reply, http.StatusUnauthorized, "AUTH_FAILED")

	reply = callAPI(t, server, http.MethodGet, "/admin/v1/meta", "", "Bearer wrong", nil)
	requireErrorCode(t, reply, http.StatusUnauthorized, "AUTH_FAILED")

	stub.authErr = session.ErrStrongAuthRequired
	reply = callAPI(t, server, http.MethodGet, "/admin/v1/meta", "", "Bearer s3cret", nil)
	requireErrorCode(t, reply, http.StatusForbidden, "REAUTH_REQUIRED")
	stub.authErr = nil

	// 防御性检查：即使会话服务返回了未完成强认证的会话，也必须拒绝。
	stub.session = session.Session{UserID: stub.userID, Kind: session.KindNormal}
	reply = callAPI(t, server, http.MethodGet, "/admin/v1/meta", "", "Bearer s3cret", nil)
	requireErrorCode(t, reply, http.StatusForbidden, "ACCESS_DENIED")
	stub.session = session.Session{}
}

// TestCSRFContract 验证 Cookie 会话的非安全方法必须携带有效 CSRF 令牌，而
// Bearer 会话秘密不受浏览器 CSRF 影响。
func TestCSRFContract(t *testing.T) {
	stub := &stubSession{secret: "s3cret", csrf: "csrf-token-value",
		userID: "usr_00000000000000000000000000000001"}
	server := newStubServer(t, stub)
	addTestRoute(server, http.MethodPost, "test/write", func(c *callContext) error {
		c.server.writeSuccess(c.writer, c.requestID, map[string]any{"done": true})
		return nil
	})

	cookie := session.DefaultCookieName + "=s3cret"
	reply := callAPI(t, server, http.MethodPost, "/admin/v1/test/write", `{}`, "",
		map[string]string{"Cookie": cookie})
	requireErrorCode(t, reply, http.StatusForbidden, "ACCESS_DENIED")

	reply = callAPI(t, server, http.MethodPost, "/admin/v1/test/write", `{}`, "",
		map[string]string{"Cookie": cookie, CSRFHeaderName: "wrong"})
	requireErrorCode(t, reply, http.StatusForbidden, "ACCESS_DENIED")

	reply = callAPI(t, server, http.MethodPost, "/admin/v1/test/write", `{}`, "",
		map[string]string{"Cookie": cookie, CSRFHeaderName: "csrf-token-value"})
	requireSuccess(t, reply)

	// Bearer 会话不要求 CSRF 头；scheme 大小写不敏感（与 internal/session 一致）。
	for _, scheme := range []string{"Bearer", "bearer", "BEARER", "bEaReR"} {
		reply = callAPI(t, server, http.MethodPost, "/admin/v1/test/write", `{}`,
			scheme+" s3cret", nil)
		requireSuccess(t, reply)
	}

	// 只有 scheme 没有令牌时不认定为 Bearer，仍按 Cookie 会话要求 CSRF。
	reply = callAPI(t, server, http.MethodPost, "/admin/v1/test/write", `{}`, "Bearer ", nil)
	requireErrorCode(t, reply, http.StatusUnauthorized, "AUTH_FAILED")

	// Cookie 与服务端优先级一致：Cookie 存在时即使带 Bearer 头也按 Cookie 会话
	// 要求 CSRF，避免“Bearer 免 CSRF、实际 Cookie 认证”的绕过。
	reply = callAPI(t, server, http.MethodPost, "/admin/v1/test/write", `{}`, "Bearer s3cret",
		map[string]string{"Cookie": cookie})
	requireErrorCode(t, reply, http.StatusForbidden, "ACCESS_DENIED")

	// Cookie+Bearer 组合携带有效 CSRF 令牌时放行（CSRF 校验与 Cookie 会话一致）。
	reply = callAPI(t, server, http.MethodPost, "/admin/v1/test/write", `{}`, "Bearer s3cret",
		map[string]string{"Cookie": cookie, CSRFHeaderName: "csrf-token-value"})
	requireSuccess(t, reply)

	// 任何 Cookie（含无关 Cookie）存在时都不免 CSRF，防止自定义/未知 Cookie 名漏检。
	reply = callAPI(t, server, http.MethodPost, "/admin/v1/test/write", `{}`, "Bearer s3cret",
		map[string]string{"Cookie": "unrelated=1"})
	requireErrorCode(t, reply, http.StatusForbidden, "ACCESS_DENIED")

	// 仅 Bearer、无任何 Cookie 时才免 CSRF。
	reply = callAPI(t, server, http.MethodPost, "/admin/v1/test/write", `{}`, "Bearer s3cret", nil)
	requireSuccess(t, reply)
}

// TestChunkedBodyTooLarge 验证 chunked（无 Content-Length）超限请求体返回 413，
// 而不是被笼统归为参数错误 400。
func TestChunkedBodyTooLarge(t *testing.T) {
	stub := &stubSession{secret: "s3cret", userID: "usr_00000000000000000000000000000001"}
	server, err := New(Options{Session: stub, ErrorCodes: testCodes(), MaxBodyBytes: 1024})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	addTestRoute(server, http.MethodPost, "test/write", func(c *callContext) error {
		var input map[string]any
		if err := c.decodeJSON(&input); err != nil {
			return err
		}
		c.server.writeSuccess(c.writer, c.requestID, map[string]any{"done": true})
		return nil
	})
	request := httptest.NewRequest(http.MethodPost, "/admin/v1/test/write",
		strings.NewReader(`{"padding":"`+strings.Repeat("x", 4096)+`"}`))
	request.ContentLength = -1
	request.TransferEncoding = []string{"chunked"}
	request.Header.Set("Authorization", "Bearer s3cret")
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("chunked 超限状态 = %d，期望 413，响应=%s",
			recorder.Code, recorder.Body.String())
	}
}

// TestRoutingContract 验证严格路径匹配：不做“清理后仍然命中”的归一化。
func TestRoutingContract(t *testing.T) {
	stub := &stubSession{secret: "s3cret", userID: "usr_00000000000000000000000000000001"}
	server := newStubServer(t, stub)
	authz := "Bearer s3cret"

	// 未知路径与不在挂载前缀下的路径返回 404。
	for _, path := range []string{
		"/admin/v1/unknown", "/admin/v2/meta", "/admin", "/admin/v1",
	} {
		reply := callAPI(t, server, http.MethodGet, path, "", authz, nil)
		requireErrorCode(t, reply, http.StatusNotFound, "REQ_INVALID")
	}
	// 路径归一化/编码规避一律拒绝（400），不做“清理后仍然命中”。
	for _, path := range []string{
		"/admin/v1/../meta", "/admin/v1/%2e%2e/meta", "/admin/v1/meta%2fextra",
		"/admin/v1/meta/", "/admin/v1//meta",
	} {
		reply := callAPI(t, server, http.MethodGet, path, "", authz, nil)
		requireErrorCode(t, reply, http.StatusBadRequest, "REQ_INVALID")
	}

	// 已知路径的错误方法返回 405 并带 Allow。
	reply := callAPI(t, server, http.MethodPost, "/admin/v1/meta", `{}`, authz,
		map[string]string{CSRFHeaderName: "x"})
	if reply.status != http.StatusMethodNotAllowed {
		t.Fatalf("错误方法状态 = %d，期望 405，响应=%s", reply.status, string(reply.body))
	}
	if allow := reply.header.Get("Allow"); allow != http.MethodGet {
		t.Fatalf("Allow = %q，期望 GET", allow)
	}
}

// TestSuccessEnvelopeAndSecurityHeaders 验证统一成功 envelope、请求编号回显与
// 缓存/嗅探防护响应头。
func TestSuccessEnvelopeAndSecurityHeaders(t *testing.T) {
	stub := &stubSession{secret: "s3cret", userID: "usr_00000000000000000000000000000001"}
	server := newStubServer(t, stub)
	reply := callAPI(t, server, http.MethodGet, "/admin/v1/meta", "", "Bearer s3cret", nil)
	data := requireSuccess(t, reply)
	if data["api_version"] != "v1" {
		t.Fatalf("api_version = %v", data["api_version"])
	}
	if got := reply.header.Get("X-Request-ID"); got == "" || got != reply.parsed["request_id"] {
		t.Fatalf("响应头 X-Request-ID 与正文不一致: %q vs %v", got, reply.parsed["request_id"])
	}
	if got := reply.header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if got := reply.header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q", got)
	}
	if got := reply.header.Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Fatalf("Content-Type = %q", got)
	}
}

// TestErrorCodeSearch 验证错误码检索端点按码过滤且结果有序。
func TestErrorCodeSearch(t *testing.T) {
	stub := &stubSession{secret: "s3cret", userID: "usr_00000000000000000000000000000001"}
	server := newStubServer(t, stub)
	authz := "Bearer s3cret"

	data := requireSuccess(t, callAPI(t, server, http.MethodGet, "/admin/v1/error-codes", "", authz, nil))
	codes, ok := data["error_codes"].([]any)
	if !ok || len(codes) != len(testCodes()) {
		t.Fatalf("错误码列表长度不符: %v", data["error_codes"])
	}
	filtered := requireSuccess(t, callAPI(t, server, http.MethodGet,
		"/admin/v1/error-codes?code=access_denied", "", authz, nil))
	items, ok := filtered["error_codes"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("按码过滤失败: %v", filtered)
	}
	first := items[0].(map[string]any)
	if first["code"] != "ACCESS_DENIED" || first["http_status"].(float64) != 403 {
		t.Fatalf("错误码条目不符: %v", first)
	}
}

// TestConfirmAndBodyContract 验证写操作的确认语义、严格 JSON 解码与请求体上限。
func TestConfirmAndBodyContract(t *testing.T) {
	stub := &stubSession{secret: "s3cret", userID: "usr_00000000000000000000000000000001"}
	server, err := New(Options{Session: stub, ErrorCodes: testCodes(), MaxBodyBytes: 1024})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	addTestRoute(server, http.MethodPost, "test/write", func(c *callContext) error {
		var input struct {
			Confirm bool `json:"confirm"`
		}
		if err := c.decodeJSON(&input); err != nil {
			return err
		}
		if err := requireConfirm(input.Confirm); err != nil {
			return err
		}
		c.server.writeSuccess(c.writer, c.requestID, map[string]any{"done": true})
		return nil
	})
	authz := "Bearer s3cret"

	reply := callAPI(t, server, http.MethodPost, "/admin/v1/test/write", ``, authz, nil)
	requireErrorCode(t, reply, http.StatusBadRequest, "REQ_INVALID")
	reply = callAPI(t, server, http.MethodPost, "/admin/v1/test/write", `{"confirm":false}`, authz, nil)
	requireErrorCode(t, reply, http.StatusBadRequest, "REQ_INVALID")
	reply = callAPI(t, server, http.MethodPost, "/admin/v1/test/write",
		`{"confirm":true,"unknown":1}`, authz, nil)
	requireErrorCode(t, reply, http.StatusBadRequest, "REQ_INVALID")
	reply = callAPI(t, server, http.MethodPost, "/admin/v1/test/write",
		`{"confirm":true}{"confirm":true}`, authz, nil)
	requireErrorCode(t, reply, http.StatusBadRequest, "REQ_INVALID")
	requireSuccess(t, callAPI(t, server, http.MethodPost, "/admin/v1/test/write",
		`{"confirm":true}`, authz, nil))

	oversized := `{"confirm":true,"padding":"` + strings.Repeat("x", 2048) + `"}`
	reply = callAPI(t, server, http.MethodPost, "/admin/v1/test/write", oversized, authz, nil)
	if reply.status != http.StatusRequestEntityTooLarge {
		t.Fatalf("超大请求体状态 = %d，期望 413，响应=%s", reply.status, string(reply.body))
	}
}

// TestPanicRecovery 验证处理程序 panic 被恢复为统一 500，不泄露 panic 值。
func TestPanicRecovery(t *testing.T) {
	stub := &stubSession{secret: "s3cret", userID: "usr_00000000000000000000000000000001"}
	server := newStubServer(t, stub)
	addTestRoute(server, http.MethodGet, "test/panic", func(*callContext) error {
		panic("secret internal detail")
	})
	reply := callAPI(t, server, http.MethodGet, "/admin/v1/test/panic", "", "Bearer s3cret", nil)
	payload := requireErrorCode(t, reply, http.StatusInternalServerError, "INTERNAL_ERROR")
	if message, _ := payload["message"].(string); message == "" || message == "secret internal detail" {
		t.Fatalf("panic 响应消息不合法: %q", message)
	}
}

// TestMount 验证 Mount 注册前缀且可通过 ServeMux 访问。
func TestMount(t *testing.T) {
	stub := &stubSession{secret: "s3cret", userID: "usr_00000000000000000000000000000001"}
	server := newStubServer(t, stub)
	mux := http.NewServeMux()
	patterns, err := server.Mount(mux)
	if err != nil {
		t.Fatalf("Mount 失败: %v", err)
	}
	if len(patterns) != 1 || patterns[0] != "/admin/v1/" {
		t.Fatalf("Mount 返回模式不符: %v", patterns)
	}
	request := httptest.NewRequest(http.MethodGet, "/admin/v1/meta", nil)
	request.Header.Set("Authorization", "Bearer s3cret")
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("经由 ServeMux 访问状态 = %d，响应=%s", recorder.Code, recorder.Body.String())
	}
	if _, err := server.Mount(nil); err == nil {
		t.Fatal("空 ServeMux 应返回错误")
	}
}
