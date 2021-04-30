package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testErrorCodes 是传输层测试用的注册表投影，覆盖固定使用的错误码。
var testErrorCodes = []ErrorCodeInfo{
	{Code: "REQ_INVALID", Category: "参数", Message: "请求内容不符合要求", HTTPStatus: 400},
	{Code: "AUTH_FAILED", Category: "认证", Message: "无法完成登录", HTTPStatus: 401},
	{Code: "ACCESS_DENIED", Category: "权限", Message: "请求未获准", HTTPStatus: 403},
	{Code: "TOKEN_INVALID", Category: "令牌", Message: "访问凭证无效", HTTPStatus: 401},
	{Code: "RATE_LIMITED", Category: "限流", Message: "请求过于频繁", HTTPStatus: 429},
	{Code: "INTERNAL_ERROR", Category: "内部故障", Message: "服务发生未预期错误", HTTPStatus: 500},
}

// syncBuffer 是并发安全的日志缓冲，避免测试读取访问日志时与请求 goroutine
// 竞争。
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

// Write 实现 io.Writer。
func (b *syncBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(data)
}

// String 返回当前日志内容。
func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// testRequestIDCounter 为测试 Handler 生成递增请求编号。
var testRequestIDCounter atomic.Uint64

// testOptions 构造传输层测试选项；日志写入由调用方通过 setter 注入。
func testOptions(logWriter io.Writer) Options {
	return Options{
		ErrorCodes:        testErrorCodes,
		NewRequestID:      func() string { return fmt.Sprintf("req_test_%08d", testRequestIDCounter.Add(1)) },
		ValidateRequestID: validateCorrelationFallback,
		Now:               func() time.Time { return time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC) },
		Version:           "test",
		AccessLogWriter:   logWriter,
	}
}

// buildHandler 规范化选项并构造 Handler。
func buildHandler(t *testing.T, options Options) *handler {
	t.Helper()
	normalized, err := normalizeOptions(options)
	if err != nil {
		t.Fatalf("规范化选项失败: %v", err)
	}
	built, err := newHandler(normalized)
	if err != nil {
		t.Fatalf("构造 Handler 失败: %v", err)
	}
	return built
}

// jsonResponse 构造并写出一条 JSON 响应。
func jsonResponse(w *responseWriter, status int, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, err = w.Write(body)
	return err
}

// identityRoute 返回回显可信身份的测试路由。
func identityRoute() route {
	return route{
		method:           http.MethodGet,
		path:             "/test/identity",
		requiresIdentity: true,
		handle: func(ctx context.Context, w *responseWriter, _ *http.Request) error {
			identity, ok := IdentityFromContext(ctx)
			payload := map[string]any{
				"resolved": ok,
				"kind":     identity.Kind,
				"subject":  identity.SubjectID,
				"app":      identity.AppID,
				"request":  RequestIDFromContext(ctx),
			}
			return jsonResponse(w, http.StatusOK, payload)
		},
	}
}

// jsonBodyRoute 解析请求体并回显规范化后的 name。
func jsonBodyRoute() route {
	return route{
		method: http.MethodPost,
		path:   "/test/body",
		handle: func(_ context.Context, w *responseWriter, r *http.Request) error {
			var input struct {
				Name string `json:"name"`
			}
			if problem := decodeJSONBody(r, &input); problem != nil {
				return problem
			}
			normalized, problem := normalizeTextParam("name", input.Name, 64, true)
			if problem != nil {
				return problem
			}
			return jsonResponse(w, http.StatusOK, map[string]string{"name": normalized})
		},
	}
}

// queryParamRoute 读取并规范化唯一查询参数 name。
func queryParamRoute() route {
	return route{
		method: http.MethodGet,
		path:   "/test/param",
		handle: func(_ context.Context, w *responseWriter, r *http.Request) error {
			name, problem := singleQueryValue(r, "name", 64, true)
			if problem != nil {
				return problem
			}
			return jsonResponse(w, http.StatusOK, map[string]string{"name": name})
		},
	}
}

// newRecorderRequest 构造直接交给 Handler 的请求；URL 由路径与查询串显式提供，
// 便于测试重复斜杠、点段和百分号编码等非规范路径。
func newRecorderRequest(method, path, rawQuery string) *http.Request {
	request := httptest.NewRequest(method, "/", nil)
	request.URL = &url.URL{Path: path, RawQuery: rawQuery}
	request.RequestURI = path
	if rawQuery != "" {
		request.RequestURI = path + "?" + rawQuery
	}
	return request
}

// decodeJSONMap 解析响应 JSON。
func decodeJSONMap(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("响应不是合法 JSON: %v（%q）", err, string(body))
	}
	return decoded
}

// TestProductionRoutesOnly 验证公开构造函数只注册健康与 OpenAPI 路由。
func TestProductionRoutesOnly(t *testing.T) {
	logBuffer := &syncBuffer{}
	options := testOptions(logBuffer)
	options.extraRoutes = []route{identityRoute(), jsonBodyRoute()}
	handler := buildHandler(t, options)

	if len(handler.routes) != 4 {
		t.Fatalf("测试构造器路由数 = %d，期望 4", len(handler.routes))
	}
	// 公开 New 不接收测试路由，只能看到健康与 OpenAPI。
	normalized, err := normalizeOptions(testOptions(logBuffer))
	if err != nil {
		t.Fatalf("规范化失败: %v", err)
	}
	production, err := New(normalized)
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	for _, path := range []string{"/test/identity", "/test/body", "/test/param"} {
		recorder := httptest.NewRecorder()
		production.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("生产 Handler 不应注册测试路由 %s，状态 = %d", path, recorder.Code)
		}
	}
}

// TestHealthEndpointMinimal 验证健康端点只返回固定状态，不泄露配置/数据库/密钥。
func TestHealthEndpointMinimal(t *testing.T) {
	handler := buildHandler(t, testOptions(nil))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("健康状态 = %d，期望 200", recorder.Code)
	}
	if got := recorder.Body.String(); got != `{"status":"ok"}` {
		t.Fatalf("健康响应 = %q，期望最小固定响应", got)
	}
	if contentType := recorder.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "application/json") {
		t.Fatalf("健康响应 Content-Type = %q", contentType)
	}
	requestID := recorder.Header().Get("X-Request-ID")
	if requestID == "" || validateCorrelationFallback(requestID) != nil {
		t.Fatalf("健康响应缺少合法 X-Request-ID: %q", requestID)
	}
	lowerBody := strings.ToLower(recorder.Body.String())
	for _, forbidden := range []string{"database", "secret", "password", "config", "path", "version"} {
		if strings.Contains(lowerBody, forbidden) {
			t.Fatalf("健康响应泄露了 %q: %s", forbidden, recorder.Body.String())
		}
	}
}

// TestRequestIDHandling 验证客户端请求编号只在合法唯一时复用，否则生成新编号。
func TestRequestIDHandling(t *testing.T) {
	handler := buildHandler(t, testOptions(nil))
	validCases := []struct {
		name   string
		header []string
		want   string
	}{
		{"合法编号复用", []string{"client-request-1"}, "client-request-1"},
		{"非法字符不复用", []string{"bad id"}, ""},
		{"换行注入不复用", []string{"bad\nid"}, ""},
		{"Unicode 不复用", []string{"请求编号"}, ""},
		{"过长不复用", []string{strings.Repeat("a", 65)}, ""},
		{"重复头不复用", []string{"one", "two"}, ""},
	}
	for _, testCase := range validCases {
		t.Run(testCase.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
			for _, value := range testCase.header {
				request.Header.Add("X-Request-ID", value)
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			got := recorder.Header().Get("X-Request-ID")
			if testCase.want != "" {
				if got != testCase.want {
					t.Fatalf("复用的请求编号 = %q，期望 %q", got, testCase.want)
				}
				return
			}
			if got == "" || validateCorrelationFallback(got) != nil {
				t.Fatalf("应生成合法新请求编号，实际 %q", got)
			}
			for _, value := range testCase.header {
				if got == value {
					t.Fatalf("非法客户端请求编号 %q 不应被复用", value)
				}
			}
		})
	}
}

// TestErrorEnvelopeContainsRequestID 验证统一错误响应包含同一请求编号。
func TestErrorEnvelopeContainsRequestID(t *testing.T) {
	handler := buildHandler(t, testOptions(nil))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/missing", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("未知路由状态 = %d，期望 404", recorder.Code)
	}
	payload := decodeJSONMap(t, recorder.Body.Bytes())
	if payload["code"] != "REQ_INVALID" {
		t.Fatalf("错误码 = %v，期望 REQ_INVALID", payload["code"])
	}
	if payload["request_id"] != recorder.Header().Get("X-Request-ID") {
		t.Fatalf("错误响应 request_id 与响应头不一致: %v vs %q", payload["request_id"], recorder.Header().Get("X-Request-ID"))
	}
	if message, _ := payload["message"].(string); message == "" || strings.ContainsAny(message, "\r\n") {
		t.Fatalf("公开错误消息无效: %q", message)
	}
}

// TestUnknownRouteAndMethodResponses 验证未知路由 404、方法不允许 405 与 Allow 头。
func TestUnknownRouteAndMethodResponses(t *testing.T) {
	handler := buildHandler(t, testOptions(nil))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/healthz", nil))
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("错误方法状态 = %d，期望 405", recorder.Code)
	}
	if allow := recorder.Header().Get("Allow"); allow != http.MethodGet {
		t.Fatalf("Allow = %q，期望 GET", allow)
	}
	if payload := decodeJSONMap(t, recorder.Body.Bytes()); payload["code"] != "REQ_INVALID" {
		t.Fatalf("405 错误码 = %v", payload["code"])
	}
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/nope", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("未知路由状态 = %d", recorder.Code)
	}
	if payload := decodeJSONMap(t, recorder.Body.Bytes()); payload["code"] != "REQ_INVALID" {
		t.Fatalf("404 错误码 = %v", payload["code"])
	}
}

// TestOAuthReservedPathNotWrapped 验证 /oauth2 保留空间不使用统一错误信封。
func TestOAuthReservedPathNotWrapped(t *testing.T) {
	handler := buildHandler(t, testOptions(nil))
	for _, path := range []string{"/oauth2", "/oauth2/token", "/oauth2/.well-known/openid-configuration"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, path, nil))
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("%s 状态 = %d，期望 404（尚未实现协议端点）", path, recorder.Code)
		}
		body := recorder.Body.String()
		if strings.Contains(body, `"code"`) || strings.Contains(body, "request_id") {
			t.Fatalf("OAuth 保留路径不应返回统一业务错误信封: %s", body)
		}
		if contentType := recorder.Header().Get("Content-Type"); strings.HasPrefix(contentType, "application/json") {
			t.Fatalf("OAuth 保留路径不应使用统一 JSON 响应: %q", contentType)
		}
	}
}

// TestPathSafetyRejectsNonCanonicalPaths 验证不清理、不重写、不绕过路由。
func TestPathSafetyRejectsNonCanonicalPaths(t *testing.T) {
	handler := buildHandler(t, testOptions(nil))
	cases := []struct {
		name  string
		build func() *http.Request
		want  int
	}{
		{"重复斜杠", func() *http.Request { return newRecorderRequest(http.MethodGet, "//healthz", "") }, http.StatusNotFound},
		{"尾斜杠", func() *http.Request { return newRecorderRequest(http.MethodGet, "/healthz/", "") }, http.StatusNotFound},
		{"点段", func() *http.Request { return newRecorderRequest(http.MethodGet, "/./healthz", "") }, http.StatusNotFound},
		{"父段", func() *http.Request { return newRecorderRequest(http.MethodGet, "/healthz/..", "") }, http.StatusNotFound},
		{"反斜杠", func() *http.Request { return newRecorderRequest(http.MethodGet, `/healthz\..\x`, "") }, http.StatusNotFound},
		{"编码斜杠", func() *http.Request { return encodedPathRequest("/healthz/..", "/healthz/%2e%2e") }, http.StatusNotFound},
		{"编码字母", func() *http.Request { return encodedPathRequest("/healthz", "/%68ealthz") }, http.StatusNotFound},
		{"空路径", func() *http.Request { return newRecorderRequest(http.MethodGet, "", "") }, http.StatusBadRequest},
		{"查询串过长", func() *http.Request {
			return newRecorderRequest(http.MethodGet, "/healthz", strings.Repeat("a", MaxQueryBytes+1))
		}, http.StatusRequestURITooLong},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, testCase.build())
			if recorder.Code != testCase.want {
				t.Fatalf("状态 = %d，期望 %d（响应：%s）", recorder.Code, testCase.want, recorder.Body.String())
			}
			if testCase.want == http.StatusNotFound && strings.Contains(recorder.Body.String(), "ok") {
				t.Fatalf("非规范路径不得命中健康端点: %s", recorder.Body.String())
			}
		})
	}
}

// encodedPathRequest 构造带 RawPath 的请求，模拟百分号编码路径。
func encodedPathRequest(decodedPath, rawPath string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.URL = &url.URL{Path: decodedPath, RawPath: rawPath}
	request.RequestURI = rawPath
	return request
}

// TestPrefixIsolation 验证固定路径前缀不会因清理/重写而绕过。
func TestPrefixIsolation(t *testing.T) {
	options := testOptions(nil)
	options.Prefix = "/login"
	handler := buildHandler(t, options)
	cases := []struct {
		path string
		want int
	}{
		{"/login/healthz", http.StatusOK},
		{"/healthz", http.StatusNotFound},
		{"/login//healthz", http.StatusNotFound},
		{"/login/healthz/", http.StatusNotFound},
		{"/login/../healthz", http.StatusNotFound},
		{"/loginx/healthz", http.StatusNotFound},
	}
	for _, testCase := range cases {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, testCase.path, nil))
		if recorder.Code != testCase.want {
			t.Fatalf("%s 状态 = %d，期望 %d", testCase.path, recorder.Code, testCase.want)
		}
	}
}

// TestBodyLimitByContentLength 验证超大 Content-Length 在进入处理程序前被拒绝。
func TestBodyLimitByContentLength(t *testing.T) {
	options := testOptions(nil)
	options.MaxBodyBytes = MinMaxBodyBytes
	handler := buildHandler(t, options)
	request := httptest.NewRequest(http.MethodGet, "/healthz", strings.NewReader(strings.Repeat("x", int(MinMaxBodyBytes)+1)))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("超大请求状态 = %d，期望 413", recorder.Code)
	}
	if payload := decodeJSONMap(t, recorder.Body.Bytes()); payload["code"] != "REQ_INVALID" {
		t.Fatalf("413 错误码 = %v", payload["code"])
	}
}

// TestGETRoutesRejectRequestBody 验证只读端点不接受小请求体。
func TestGETRoutesRejectRequestBody(t *testing.T) {
	handler := buildHandler(t, testOptions(nil))
	request := httptest.NewRequest(http.MethodGet, "/healthz", strings.NewReader("hello"))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("带请求体的 GET 状态 = %d，期望 400", recorder.Code)
	}
	if payload := decodeJSONMap(t, recorder.Body.Bytes()); payload["code"] != "REQ_INVALID" {
		t.Fatalf("错误码 = %v", payload["code"])
	}
}

// TestPanicRecoveryKeepsServerUsable 验证 panic 被隔离为 500 且后续请求正常。
func TestPanicRecoveryKeepsServerUsable(t *testing.T) {
	panicRoute := route{
		method: http.MethodGet,
		path:   "/test/panic",
		handle: func(context.Context, *responseWriter, *http.Request) error {
			panic("panic-secret-value")
		},
	}
	logBuffer := &syncBuffer{}
	options := testOptions(nil)
	options.extraRoutes = []route{panicRoute}
	options.Logger = slog.New(slog.NewTextHandler(logBuffer, &slog.HandlerOptions{Level: slog.LevelDebug}))
	handler := buildHandler(t, options)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/test/panic", nil))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("panic 状态 = %d，期望 500", recorder.Code)
	}
	body := recorder.Body.String()
	if strings.Contains(body, "panic-secret-value") || strings.Contains(body, "goroutine") {
		t.Fatalf("panic 细节泄露到响应: %s", body)
	}
	payload := decodeJSONMap(t, recorder.Body.Bytes())
	if payload["code"] != "INTERNAL_ERROR" {
		t.Fatalf("panic 错误码 = %v，期望 INTERNAL_ERROR", payload["code"])
	}
	if strings.Contains(logBuffer.String(), "panic-secret-value") {
		t.Fatalf("panic 细节泄露到运行日志: %s", logBuffer.String())
	}
	// 服务仍可用。
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("panic 后健康请求状态 = %d", recorder.Code)
	}
}

// TestInternalErrorDoesNotLeak 验证处理程序内部错误不泄露原始文本。
func TestInternalErrorDoesNotLeak(t *testing.T) {
	errorRoute := route{
		method: http.MethodGet,
		path:   "/test/error",
		handle: func(context.Context, *responseWriter, *http.Request) error {
			return errors.New("secret-internal-value")
		},
	}
	logBuffer := &syncBuffer{}
	options := testOptions(nil)
	options.extraRoutes = []route{errorRoute}
	options.Logger = slog.New(slog.NewTextHandler(logBuffer, &slog.HandlerOptions{Level: slog.LevelDebug}))
	handler := buildHandler(t, options)
	tracker := httptest.NewRecorder()
	handler.ServeHTTP(tracker, httptest.NewRequest(http.MethodGet, "/test/error", nil))
	if tracker.Code != http.StatusInternalServerError {
		t.Fatalf("内部错误状态 = %d，期望 500", tracker.Code)
	}
	if strings.Contains(tracker.Body.String(), "secret-internal-value") || strings.Contains(logBuffer.String(), "secret-internal-value") {
		t.Fatalf("内部错误原文泄露: body=%s log=%s", tracker.Body.String(), logBuffer.String())
	}
}

// TestJSONBodyBoundaries 验证请求体类型、大小与单值边界。
func TestJSONBodyBoundaries(t *testing.T) {
	options := testOptions(nil)
	options.MaxBodyBytes = MinMaxBodyBytes
	options.extraRoutes = []route{jsonBodyRoute()}
	handler := buildHandler(t, options)

	post := func(contentType, body string, contentLength int64) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/test/body", strings.NewReader(body))
		request.ContentLength = contentLength
		request.Header.Set("Content-Type", contentType)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder
	}

	valid := post("application/json; charset=utf-8", `{"name":"  alice  "}`, -1)
	if valid.Code != http.StatusOK {
		t.Fatalf("合法 JSON 状态 = %d（%s）", valid.Code, valid.Body.String())
	}
	if payload := decodeJSONMap(t, valid.Body.Bytes()); payload["name"] != "alice" {
		t.Fatalf("参数未规范化: %v", payload["name"])
	}
	cases := []struct {
		name        string
		contentType string
		body        string
		length      int64
		want        int
	}{
		{"错误内容类型", "text/plain", `{"name":"a"}`, -1, http.StatusUnsupportedMediaType},
		{"缺少内容类型", "", `{"name":"a"}`, -1, http.StatusUnsupportedMediaType},
		{"非法 JSON", "application/json", `{"name":`, -1, http.StatusBadRequest},
		{"未知字段", "application/json", `{"name":"a","extra":1}`, -1, http.StatusBadRequest},
		{"尾随内容", "application/json", `{"name":"a"}{"name":"b"}`, -1, http.StatusBadRequest},
		{"空请求体", "application/json", ``, -1, http.StatusBadRequest},
		{"chunked 超大请求体", "application/json", `{"name":"` + strings.Repeat("x", int(MinMaxBodyBytes)) + `"}`, -1, http.StatusRequestEntityTooLarge},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			recorder := post(testCase.contentType, testCase.body, testCase.length)
			if recorder.Code != testCase.want {
				t.Fatalf("状态 = %d，期望 %d（响应：%s）", recorder.Code, testCase.want, recorder.Body.String())
			}
			if recorder.Code >= 400 {
				if payload := decodeJSONMap(t, recorder.Body.Bytes()); payload["code"] != "REQ_INVALID" {
					t.Fatalf("错误码 = %v，期望 REQ_INVALID", payload["code"])
				}
			}
		})
	}
}

// TestParameterNormalization 验证查询参数规范化与重复参数拒绝。
func TestParameterNormalization(t *testing.T) {
	options := testOptions(nil)
	options.extraRoutes = []route{queryParamRoute()}
	handler := buildHandler(t, options)
	cases := []struct {
		name  string
		query string
		want  int
		value string
	}{
		{"正常值去空白", "name=%20%20alice%20%20", http.StatusOK, "alice"},
		{"缺省参数为空", "", http.StatusOK, ""},
		{"重复参数拒绝", "name=a&name=b", http.StatusBadRequest, ""},
		{"控制字符拒绝", "name=a%0Ab", http.StatusBadRequest, ""},
		{"非法 UTF-8 拒绝", "name=%ff", http.StatusBadRequest, ""},
		{"超长参数拒绝", "name=" + strings.Repeat("a", 128), http.StatusBadRequest, ""},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, newRecorderRequest(http.MethodGet, "/test/param", testCase.query))
			if recorder.Code != testCase.want {
				t.Fatalf("状态 = %d，期望 %d（%s）", recorder.Code, testCase.want, recorder.Body.String())
			}
			if testCase.want == http.StatusOK {
				if payload := decodeJSONMap(t, recorder.Body.Bytes()); payload["name"] != testCase.value {
					t.Fatalf("规范化参数 = %v，期望 %q", payload["name"], testCase.value)
				}
			}
		})
	}
}

// TestIdentityResolutionIgnoresClientSuppliedIDs 验证身份只来自可信解析函数。
func TestIdentityResolutionIgnoresClientSuppliedIDs(t *testing.T) {
	resolved := Identity{Kind: "user", SubjectID: "user-123", AppID: "app-1"}
	options := testOptions(nil)
	options.extraRoutes = []route{identityRoute()}
	options.ResolveIdentity = func(context.Context, *http.Request) (Identity, error) {
		return resolved, nil
	}
	handler := buildHandler(t, options)
	request := httptest.NewRequest(http.MethodGet, "/test/identity?user_id=evil&actor_id=evil", nil)
	request.Header.Set("X-User-ID", "evil")
	request.Header.Set("X-Actor-ID", "evil")
	request.Header.Set("X-Is-Root", "true")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("身份路由状态 = %d（%s）", recorder.Code, recorder.Body.String())
	}
	payload := decodeJSONMap(t, recorder.Body.Bytes())
	if payload["subject"] != resolved.SubjectID {
		t.Fatalf("身份主体 = %v，期望可信解析值 %q", payload["subject"], resolved.SubjectID)
	}
	if payload["kind"] != resolved.Kind || payload["app"] != resolved.AppID {
		t.Fatalf("身份内容 = %v", payload)
	}
	if payload["request"] == "" {
		t.Fatal("上下文缺少请求编号")
	}
}

// TestIdentityFailuresFailClosed 验证解析失败、缺少解析器与无效身份都拒绝。
func TestIdentityFailuresFailClosed(t *testing.T) {
	cases := []struct {
		name     string
		resolver ResolveIdentityFunc
		want     int
		code     string
	}{
		{"未配置解析器", nil, http.StatusForbidden, "ACCESS_DENIED"},
		{"解析返回普通错误", func(context.Context, *http.Request) (Identity, error) {
			return Identity{}, errors.New("session expired")
		}, http.StatusUnauthorized, "AUTH_FAILED"},
		{"解析返回身份错误", func(context.Context, *http.Request) (Identity, error) {
			return Identity{}, &IdentityError{Code: "TOKEN_INVALID", Status: http.StatusUnauthorized, Message: "访问凭证无效"}
		}, http.StatusUnauthorized, "TOKEN_INVALID"},
		{"解析返回无效身份", func(context.Context, *http.Request) (Identity, error) {
			return Identity{Kind: "root", SubjectID: ""}, nil
		}, http.StatusUnauthorized, "AUTH_FAILED"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			options := testOptions(nil)
			options.extraRoutes = []route{identityRoute()}
			options.ResolveIdentity = testCase.resolver
			handler := buildHandler(t, options)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/test/identity", nil))
			if recorder.Code != testCase.want {
				t.Fatalf("状态 = %d，期望 %d（%s）", recorder.Code, testCase.want, recorder.Body.String())
			}
			payload := decodeJSONMap(t, recorder.Body.Bytes())
			if payload["code"] != testCase.code {
				t.Fatalf("错误码 = %v，期望 %s", payload["code"], testCase.code)
			}
			if payload["resolved"] != nil {
				t.Fatalf("身份建立失败时不应执行受保护处理程序: %v", payload)
			}
		})
	}
}

// TestContextCancellation 验证客户端取消能传递到处理程序，访问日志记录 499。
func TestContextCancellation(t *testing.T) {
	started := make(chan struct{})
	var sawCancellation atomic.Bool
	cancelRoute := route{
		method: http.MethodGet,
		path:   "/test/cancel",
		handle: func(ctx context.Context, w *responseWriter, _ *http.Request) error {
			close(started)
			<-ctx.Done()
			sawCancellation.Store(true)
			return ctx.Err()
		},
	}
	logBuffer := &syncBuffer{}
	options := testOptions(logBuffer)
	options.extraRoutes = []route{cancelRoute}
	handler := buildHandler(t, options)
	server := httptest.NewServer(handler)
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/test/cancel", nil)
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	result := make(chan error, 1)
	go func() {
		response, err := server.Client().Do(request)
		if err == nil {
			_ = response.Body.Close()
		}
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("处理程序未启动")
	}
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("客户端取消后请求应返回错误")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("客户端取消后请求未结束")
	}
	waitFor(t, "处理程序观察到上下文取消", func() bool {
		return sawCancellation.Load()
	})
	waitFor(t, "访问日志记录取消", func() bool {
		return strings.Contains(logBuffer.String(), " 499 ")
	})
}

// waitFor 在超时内等待条件成立。
func waitFor(t *testing.T, description string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("等待超时: %s", description)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestConcurrentRequests 验证 Handler 可并发使用且访问日志按行完整写出。
func TestConcurrentRequests(t *testing.T) {
	logBuffer := &syncBuffer{}
	options := testOptions(logBuffer)
	handler := buildHandler(t, options)
	const workers = 6
	const perWorker = 10
	var waitGroup sync.WaitGroup
	failures := make(chan string, workers*perWorker)
	for workerIndex := 0; workerIndex < workers; workerIndex++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for requestIndex := 0; requestIndex < perWorker; requestIndex++ {
				recorder := httptest.NewRecorder()
				handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/healthz", nil))
				if recorder.Code != http.StatusOK {
					failures <- fmt.Sprintf("状态 %d", recorder.Code)
					return
				}
			}
		}()
	}
	waitGroup.Wait()
	close(failures)
	for failure := range failures {
		t.Fatalf("并发请求失败: %s", failure)
	}
	lines := strings.Split(strings.TrimSpace(logBuffer.String()), "\n")
	// 两行头 + 每条请求一行。
	if len(lines) != workers*perWorker+2 {
		t.Fatalf("访问日志行数 = %d，期望 %d", len(lines), workers*perWorker+2)
	}
	for _, line := range lines[2:] {
		if fields := strings.Fields(line); len(fields) != len(strings.Fields(accessLogFields)) {
			t.Fatalf("访问日志字段数 = %d，期望 %d：%q", len(fields), len(strings.Fields(accessLogFields)), line)
		}
	}
}
