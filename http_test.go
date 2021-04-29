package login_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin"
)

// lockedBuffer 是并发安全的日志缓冲。
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

// Write 实现 io.Writer。
func (b *lockedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(data)
}

// String 返回当前内容。
func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestNewHTTPHandlerValidatesOptions 验证非法 Handler 选项返回 CONFIG_INVALID。
func TestNewHTTPHandlerValidatesOptions(t *testing.T) {
	cases := []login.HTTPOptions{
		{Prefix: "/api/"},
		{Prefix: "api"},
		{Prefix: "//api"},
		{Prefix: "/a/../b"},
		{MaxBodyBytes: 1},
		{MaxBodyBytes: login.MaxHTTPMaxBodyBytes + 1},
	}
	for _, options := range cases {
		handler, err := login.NewHTTPHandler(options)
		if err == nil || handler != nil {
			t.Fatalf("非法选项 %+v 应返回错误", options)
		}
		if !login.IsErrorCode(err, login.CodeConfigInvalid) {
			t.Fatalf("错误码 = %v，期望 CONFIG_INVALID", err)
		}
	}
	handler, err := login.NewHTTPHandler(login.HTTPOptions{})
	if err != nil || handler == nil {
		t.Fatalf("默认选项应有效: %v", err)
	}
}

// TestHTTPHandlerProductionEndpoints 验证公开 Handler 只暴露健康与 OpenAPI。
func TestHTTPHandlerProductionEndpoints(t *testing.T) {
	logBuffer := &lockedBuffer{}
	handler, err := login.NewHTTPHandler(login.HTTPOptions{
		Prefix:          "/api",
		AccessLogWriter: logBuffer,
		MaxBodyBytes:    login.MinHTTPMaxBodyBytes,
	})
	if err != nil {
		t.Fatalf("构造 Handler 失败: %v", err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	response, err := server.Client().Get(server.URL + "/api/healthz")
	if err != nil {
		t.Fatalf("健康请求失败: %v", err)
	}
	body := readBody(t, response)
	if response.StatusCode != http.StatusOK || body != `{"status":"ok"}` {
		t.Fatalf("健康响应 = %d %q", response.StatusCode, body)
	}
	if requestID := response.Header.Get("X-Request-ID"); !strings.HasPrefix(requestID, "req_") {
		t.Fatalf("响应缺少合法请求编号: %q", requestID)
	}

	for _, path := range []string{"/healthz", "/api//healthz", "/api/healthz/", "/api/test/echo", "/api/debug/pprof"} {
		response, err := server.Client().Get(server.URL + path)
		if err != nil {
			t.Fatalf("请求 %s 失败: %v", path, err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusNotFound {
			t.Fatalf("%s 状态 = %d，期望 404", path, response.StatusCode)
		}
	}
	// /oauth2 保留路径不使用统一业务错误信封。
	response, err = server.Client().Post(server.URL+"/api/oauth2/token", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("OAuth 保留路径请求失败: %v", err)
	}
	oauthBody := readBody(t, response)
	if strings.Contains(oauthBody, `"code"`) {
		t.Fatalf("OAuth 保留路径不应返回统一错误信封: %s", oauthBody)
	}
	if !strings.Contains(logBuffer.String(), "#Version: 1.0") {
		t.Fatalf("访问日志未写入 W3C 头: %s", logBuffer.String())
	}
	if strings.Contains(logBuffer.String(), "?") {
		t.Fatalf("访问日志不应记录查询串: %s", logBuffer.String())
	}
}

// TestOpenAPIDocumentRegistrySync 验证公开 OpenAPI 文档与 46 码注册表一致。
func TestOpenAPIDocumentRegistrySync(t *testing.T) {
	document, err := login.OpenAPIDocument("/api")
	if err != nil {
		t.Fatalf("生成 OpenAPI 失败: %v", err)
	}
	var decoded struct {
		OpenAPI string `json:"openapi"`
		Paths   map[string]struct {
			Get *struct {
				Responses map[string]json.RawMessage `json:"responses"`
			} `json:"get"`
		} `json:"paths"`
		Components struct {
			Schemas struct {
				Error struct {
					Properties struct {
						Code struct {
							Enum []string `json:"enum"`
						} `json:"code"`
					} `json:"properties"`
				} `json:"Error"`
			} `json:"schemas"`
		} `json:"components"`
		Registry map[string]struct {
			Category   string `json:"category"`
			Message    string `json:"message"`
			HTTPStatus int    `json:"http_status"`
		} `json:"x-login-error-registry"`
		OAuthReserved string `json:"x-login-oauth-reserved-prefix"`
	}
	if err := json.Unmarshal(document, &decoded); err != nil {
		t.Fatalf("OpenAPI 文档解析失败: %v", err)
	}
	if decoded.OpenAPI != "3.0.3" {
		t.Fatalf("openapi = %q", decoded.OpenAPI)
	}
	for _, path := range []string{"/api/healthz", "/api/openapi.json"} {
		if _, ok := decoded.Paths[path]; !ok {
			t.Fatalf("OpenAPI 缺少路径 %s", path)
		}
	}
	if decoded.OAuthReserved == "" || !strings.HasPrefix(decoded.OAuthReserved, "/") {
		t.Fatalf("OAuth 保留前缀扩展缺失: %q", decoded.OAuthReserved)
	}
	definitions := login.RegisteredErrorCodes()
	enum := decoded.Components.Schemas.Error.Properties.Code.Enum
	if len(enum) != len(definitions) {
		t.Fatalf("错误码 enum 数量 = %d，期望 %d", len(enum), len(definitions))
	}
	enumSet := make(map[string]bool, len(enum))
	for _, code := range enum {
		enumSet[code] = true
	}
	for _, definition := range definitions {
		code := string(definition.Code)
		if !enumSet[code] {
			t.Fatalf("OpenAPI enum 缺少错误码 %s", code)
		}
		entry, ok := decoded.Registry[code]
		if !ok {
			t.Fatalf("OpenAPI 注册表投影缺少 %s", code)
		}
		if entry.Category != string(definition.Category) || entry.Message != definition.DefaultMessage || entry.HTTPStatus != definition.HTTPStatus {
			t.Fatalf("错误码 %s 的 OpenAPI 投影与注册表不一致: %+v", code, entry)
		}
	}
}

// TestIdentityPublicContract 验证身份结构校验与上下文传递接口。
func TestIdentityPublicContract(t *testing.T) {
	valid := login.Identity{Kind: login.IdentityKindUser, SubjectID: "user-123", AppID: "app-1"}
	if err := valid.Validate(); err != nil {
		t.Fatalf("合法身份被拒绝: %v", err)
	}
	application := login.Identity{Kind: login.IdentityKindApplication, SubjectID: "client-1"}
	if err := application.Validate(); err == nil {
		t.Fatal("应用身份缺少 AppID 应被拒绝")
	}
	invalid := []login.Identity{
		{Kind: "root", SubjectID: "user-1"},
		{Kind: login.IdentityKindUser, SubjectID: ""},
		{Kind: login.IdentityKindUser, SubjectID: "bad id"},
		{Kind: login.IdentityKindUser, SubjectID: "user-1", AppID: "bad/app"},
	}
	for _, identity := range invalid {
		if err := identity.Validate(); err == nil {
			t.Fatalf("非法身份 %+v 应被拒绝", identity)
		}
	}
	ctx, err := login.WithIdentity(context.Background(), valid)
	if err != nil {
		t.Fatalf("WithIdentity 失败: %v", err)
	}
	got, ok := login.IdentityFromContext(ctx)
	if !ok || got != valid {
		t.Fatalf("身份上下文往返 = %+v, %v", got, ok)
	}
	if _, ok := login.IdentityFromContext(context.Background()); ok {
		t.Fatal("空上下文不应含身份")
	}
	if requestID := login.RequestIDFromContext(context.Background()); requestID != "" {
		t.Fatalf("空上下文请求编号 = %q", requestID)
	}
}

// TestHTTPHandlerRejectsOversizedBody 验证公开 Handler 的请求体上限。
func TestHTTPHandlerRejectsOversizedBody(t *testing.T) {
	handler, err := login.NewHTTPHandler(login.HTTPOptions{MaxBodyBytes: login.MinHTTPMaxBodyBytes})
	if err != nil {
		t.Fatalf("构造 Handler 失败: %v", err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	request, err := http.NewRequest(http.MethodGet, server.URL+"/healthz",
		strings.NewReader(strings.Repeat("x", int(login.MinHTTPMaxBodyBytes)+1)))
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	body := readBody(t, response)
	if response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("超大请求状态 = %d（%s）", response.StatusCode, body)
	}
	if !strings.Contains(body, "REQ_INVALID") {
		t.Fatalf("超大请求错误码缺失: %s", body)
	}
}

// readBody 读取并关闭响应体。
func readBody(t *testing.T, response *http.Response) string {
	t.Helper()
	defer response.Body.Close()
	var buffer bytes.Buffer
	if _, err := buffer.ReadFrom(response.Body); err != nil {
		t.Fatalf("读取响应失败: %v", err)
	}
	return buffer.String()
}
