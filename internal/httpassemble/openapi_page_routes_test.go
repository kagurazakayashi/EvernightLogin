package httpassemble

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/httpapi"
)

// pageRoutesHandler 是测试用页面处理器：实现 http.Handler 与
// httpapi.UIPageRouteLister，模拟 *ui.WebUI 向 OpenAPI 提供实际注册的命名路由。
type pageRoutesHandler struct {
	routes []httpapi.UIPageRouteInfo
}

// ServeHTTP 实现 http.Handler（本测试不经过页面处理器）。
func (h pageRoutesHandler) ServeHTTP(http.ResponseWriter, *http.Request) {}

// OpenAPIPageRoutes 返回已注册页面路由投影（与 *ui.WebUI 的方法签名一致）。
func (h pageRoutesHandler) OpenAPIPageRoutes() []httpapi.UIPageRouteInfo { return h.routes }

// testPageCSP 是合法的页面 CSP 基线（装配层要求显式提供）。
const testPageCSP = "default-src 'none'; script-src 'self'; style-src 'self'; " +
	"img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self'; " +
	"frame-ancestors 'none'; base-uri 'none'; object-src 'none'"

// TestOpenAPIDocumentIncludesRegisteredPageRoutes 验证装配层从页面处理器提取
// 路由投影后，服务端 /openapi.json 包含页面/表单操作（页面与 JSON API 分开标识），
// 且请求字段/响应来自同源契约表。
func TestOpenAPIDocumentIncludesRegisteredPageRoutes(t *testing.T) {
	pageHandler := pageRoutesHandler{routes: []httpapi.UIPageRouteInfo{
		{Name: "auth.login", Method: http.MethodGet, Path: "/login", Access: "public"},
		{Name: "auth.login.submit", Method: http.MethodPost, Path: "/login", Access: "public"},
		{Name: "account.password.submit", Method: http.MethodPost, Path: "/account/password",
			Access: "user"},
	}}
	handler, err := NewHTTPHandler(httpapi.HTTPOptions{
		Prefix: "/api",
		UI: &httpapi.UIHTTPOptions{
			Handler:                   pageHandler,
			PageContentSecurityPolicy: testPageCSP,
		},
	}, "test-version")
	if err != nil {
		t.Fatalf("NewHTTPHandler: %v", err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet,
		"http://example.test/api/openapi.json", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("OpenAPI 状态 = %d，body=%.200s", recorder.Code, recorder.Body.String())
	}
	var document map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &document); err != nil {
		t.Fatalf("OpenAPI 不是合法 JSON: %v", err)
	}
	paths, _ := document["paths"].(map[string]any)
	loginItem, ok := paths["/api/login"].(map[string]any)
	if !ok {
		t.Fatalf("OpenAPI 缺少装配后的登录页路径：%v", paths)
	}
	loginGET, ok := loginItem["get"].(map[string]any)
	if !ok {
		t.Fatal("登录页缺少 GET 操作")
	}
	if loginGET["x-login-route-kind"] != "html-page" {
		t.Fatalf("登录页 route-kind = %v", loginGET["x-login-route-kind"])
	}
	if loginGET["x-login-route-name"] != "auth.login" {
		t.Fatalf("登录页命名路由 = %v", loginGET["x-login-route-name"])
	}
	loginPOST, ok := loginItem["post"].(map[string]any)
	if !ok {
		t.Fatal("登录页缺少 POST 操作")
	}
	if _, ok := loginPOST["requestBody"].(map[string]any); !ok {
		t.Fatal("登录提交缺少 requestBody")
	}
	// JSON API 端点仍保持统一错误信封语义。
	healthItem, ok := paths["/api/healthz"].(map[string]any)
	if !ok {
		t.Fatal("OpenAPI 缺少健康检查路径")
	}
	healthGET, _ := healthItem["get"].(map[string]any)
	if healthGET["x-login-route-kind"] != "json-api" {
		t.Fatalf("健康检查 route-kind = %v", healthGET["x-login-route-kind"])
	}
	// 契约计数来自真实注入的路由，不是手写清单。
	contract, _ := document["x-login-page-contract"].(map[string]any)
	if documented, _ := contract["documented"].(float64); int(documented) != 3 {
		t.Fatalf("已登记页面操作数 = %v，期望 3", contract["documented"])
	}
}
