// 命令 ui-pages 演示内置页面框架的最小可运行替换契约（步骤 62）：
//   - 同一命名路由的宿主模板替换；
//   - 品牌与 BasePath 覆盖；
//   - 整体禁用内置页面后核心 API（健康/OpenAPI）仍可用。
//
// 示例只使用公开包 login 与标准库（不依赖 internal），可由外部宿主照抄模式。
// 它不启动监听端口，请求全部经 httptest 在内存中驱动，可安全重复运行。
package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing/fstest"

	"github.com/kagurazakayashi/EvernightLogin"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "ui-pages 示例失败:", err)
		os.Exit(1)
	}
	fmt.Println("ui-pages 示例通过：宿主模板替换、品牌与 BasePath、禁用内置页面后 API 可用")
}

// run 构造三种页面模式并断言可观察行为。
func run() error {
	// 1) 内置页面 + 宿主模板替换同一路由 + 品牌/BasePath 覆盖。
	hostTemplates := fstest.MapFS{
		"host/forbidden.html": &fstest.MapFile{Data: []byte(
			`{{define "page-title"}}Host page{{end}}{{define "content"}}<p id="host-template">宿主模板替换</p>{{end}}`)},
	}
	web, err := login.NewWebUI(login.WebUIOptions{
		ContractVersion: login.UIContractVersion,
		Prefix:          "/login",
		Brand:           login.UIBrand{Name: "示例品牌", Theme: "auto"},
		HostTemplates: &login.UIHostTemplates{FS: hostTemplates,
			Overrides: []login.UITemplateOverride{{RouteName: "system.forbidden",
				TemplatePath: "host/forbidden.html"}}},
	})
	if err != nil {
		return fmt.Errorf("构造内置页面失败: %w", err)
	}
	handler, err := login.NewHTTPHandler(login.HTTPOptions{Prefix: "/login",
		UI: &login.UIHTTPOptions{Handler: web,
			PageContentSecurityPolicy: login.DefaultUIPageContentSecurityPolicy}})
	if err != nil {
		return fmt.Errorf("构造 HTTP Handler 失败: %w", err)
	}
	page := request(handler, http.MethodGet, "/login/403", "")
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "宿主模板替换") {
		return fmt.Errorf("宿主模板替换未生效: %d", page.Code)
	}
	if !strings.Contains(page.Body.String(), "示例品牌") {
		return fmt.Errorf("品牌名称未生效")
	}
	// 内置未覆盖页面仍由内置模板渲染（宿主模板按路由覆盖，不做全局替换）。
	if builtinPage := request(handler, http.MethodGet, "/login/404", ""); builtinPage.Code != http.StatusOK ||
		!strings.Contains(builtinPage.Body.String(), "页面不存在") {
		return fmt.Errorf("未覆盖路由应回退内置模板: %d", builtinPage.Code)
	}

	// 2) 宿主渲染器优先于所有模板。
	rendererWeb, err := login.NewWebUI(login.WebUIOptions{Prefix: "/login",
		Brand:        login.UIBrand{Name: "示例品牌"},
		HostRenderer: &staticRenderer{body: `<html><body><p id="host-renderer">宿主渲染器</p></body></html>`}})
	if err != nil {
		return fmt.Errorf("构造宿主渲染器页面失败: %w", err)
	}
	rendererHandler, err := login.NewHTTPHandler(login.HTTPOptions{Prefix: "/login",
		UI: &login.UIHTTPOptions{Handler: rendererWeb,
			PageContentSecurityPolicy: login.DefaultUIPageContentSecurityPolicy}})
	if err != nil {
		return fmt.Errorf("构造渲染器 Handler 失败: %w", err)
	}
	rendered := request(rendererHandler, http.MethodGet, "/login/403", "")
	if rendered.Code != http.StatusOK || !strings.Contains(rendered.Body.String(), "宿主渲染器") {
		return fmt.Errorf("宿主渲染器优先级未生效: %d", rendered.Code)
	}

	// 3) 整体禁用内置页面：内置 HTML 路由关闭，健康/OpenAPI 仍可用。
	disabledWeb, err := login.NewWebUI(login.WebUIOptions{Prefix: "/login",
		DisableBuiltinPages: true})
	if err != nil {
		return fmt.Errorf("构造禁用内置页面失败: %w", err)
	}
	disabledHandler, err := login.NewHTTPHandler(login.HTTPOptions{Prefix: "/login",
		UI: &login.UIHTTPOptions{Handler: disabledWeb,
			PageContentSecurityPolicy: login.DefaultUIPageContentSecurityPolicy}})
	if err != nil {
		return fmt.Errorf("构造禁用页面 Handler 失败: %w", err)
	}
	if disabled := request(disabledHandler, http.MethodGet, "/login/403", ""); disabled.Code != http.StatusNotFound {
		return fmt.Errorf("禁用内置页面后 HTML 路由应 404: %d", disabled.Code)
	}
	for _, apiPath := range []string{"/login/healthz", "/login/openapi.json"} {
		if api := request(disabledHandler, http.MethodGet, apiPath, ""); api.Code != http.StatusOK {
			return fmt.Errorf("禁用内置页面后 %s 应可用: %d", apiPath, api.Code)
		}
	}
	return nil
}

// staticRenderer 是宿主页面渲染器示例：固定输出一段本地 HTML。
type staticRenderer struct{ body string }

// RenderPage 实现 login.UIPageRenderer。
func (r *staticRenderer) RenderPage(_ context.Context,
	_ login.UIPageContext) (login.UIPageResponse, bool, error) {
	return login.UIPageResponse{StatusCode: http.StatusOK,
		ContentType: "text/html; charset=utf-8", Body: []byte(r.body)}, true, nil
}

// request 在内存中驱动 HTTP Handler。
func request(handler http.Handler, method, target, body string) *httptest.ResponseRecorder {
	httpRequest := httptest.NewRequest(method, target, strings.NewReader(body))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httpRequest)
	return recorder
}
