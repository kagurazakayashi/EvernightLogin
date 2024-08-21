package ui

import (
	"context"
	"encoding/json"
	"errors"
	httpapi "github.com/kagurazakayashi/EvernightLogin/httpapi"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/kagurazakayashi/EvernightLogin/internal/transport"
)

// fakePageSessions 是页面会话契约的测试替身（仅单测；真实会话见集成测试）。
type fakePageSessions struct {
	session UISession
	err     error
	token   string
}

func (f *fakePageSessions) ResolvePageSession(context.Context, *http.Request) (UISession, error) {
	if f.err != nil {
		return UISession{}, f.err
	}
	return f.session, nil
}

func (f *fakePageSessions) IssueCSRFToken(context.Context, *http.Request) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.token, nil
}

// testWebUI 构造内置页面处理器。
func testWebUI(t *testing.T, mutate func(*WebUIOptions)) *WebUI {
	t.Helper()
	options := WebUIOptions{Prefix: "/login", Logger: slog.New(slog.NewTextHandler(
		io.Discard, nil))}
	if mutate != nil {
		mutate(&options)
	}
	ui, err := NewWebUI(options)
	if err != nil {
		t.Fatalf("构造页面处理器失败: %v", err)
	}
	return ui
}

// serveUI 用请求路径驱动 WebUI 并返回记录器。
func serveUI(ui *WebUI, method, target, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request = request.WithContext(transport.WithRequestID(request.Context(), "req_test_0001"))
	recorder := httptest.NewRecorder()
	ui.ServeHTTP(recorder, request)
	return recorder
}

// TestWebUIRenderBuiltinPages 验证内置系统页渲染、语言与可访问结构。
func TestWebUIRenderBuiltinPages(t *testing.T) {
	ui := testWebUI(t, nil)
	cases := []struct {
		path string
		want string
	}{
		{"/login/403", "请求未获准"},
		{"/login/404", "页面不存在"},
		{"/login/401", "会话已过期"},
		{"/login/500", "页面暂时不可用"},
	}
	for _, test := range cases {
		recorder := serveUI(ui, http.MethodGet, test.path, "")
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s 状态 = %d，期望 200", test.path, recorder.Code)
		}
		body := recorder.Body.String()
		if !strings.Contains(body, `lang="zh-CN"`) {
			t.Fatalf("%s 缺少 lang 属性", test.path)
		}
		if !strings.Contains(body, test.want) {
			t.Fatalf("%s 缺少中文文案 %q", test.path, test.want)
		}
		if strings.Count(body, "<h1") > 1 {
			t.Fatalf("%s 出现多个 h1", test.path)
		}
		if !strings.Contains(body, `class="ln-skip-link"`) {
			t.Fatalf("%s 缺少跳到主要内容链接", test.path)
		}
		if !strings.Contains(body, "req_test_0001") {
			t.Fatalf("%s 缺少 request_id", test.path)
		}
		if strings.Contains(body, "<style") || regexp.MustCompile(`<script(?:\s[^>]*)?>(?s:.)*</script>`).MatchString(body) {
			t.Fatalf("%s 不允许内联脚本/样式", test.path)
		}
	}
	// 未知路径渲染 404 页面。
	recorder := serveUI(ui, http.MethodGet, "/login/no-such-page", "")
	if recorder.Code != http.StatusNotFound || !strings.Contains(recorder.Body.String(), "页面不存在") {
		t.Fatalf("未知页面应渲染 404 页面，实际 %d", recorder.Code)
	}
}

// TestWebUISessionStates 验证受保护页面的无会话/未知会话状态。
func TestWebUISessionStates(t *testing.T) {
	sessions := &fakePageSessions{session: UISession{Authenticated: true, UserID: "usr_1",
		Kind: "normal"}, token: "csrf-token-example"}
	ui := testWebUI(t, func(options *WebUIOptions) {
		options.EnableComponentPreview = true
		options.Session = sessions
	})
	if recorder := serveUI(ui, http.MethodGet, "/login/_ui/preview", ""); recorder.Code != http.StatusOK {
		t.Fatalf("有会话的受保护页面应 200，实际 %d", recorder.Code)
	} else if !strings.Contains(recorder.Body.String(), `name="csrf_token"`) {
		t.Fatal("受保护页面应包含 CSRF 隐藏字段")
	}
	if recorder := serveUI(ui, http.MethodPost, "/login/_ui/preview",
		"display_name=example&csrf_token=csrf-token-example"); recorder.Code != http.StatusOK ||
		!strings.Contains(recorder.Body.String(), "操作已完成") {
		t.Fatalf("组件预览 POST 应渲染成功状态，实际 %d", recorder.Code)
	}
	// 无会话服务 → fail-closed 为 401 过期页。
	uiNoSession := testWebUI(t, func(options *WebUIOptions) {
		options.EnableComponentPreview = true
	})
	if recorder := serveUI(uiNoSession, http.MethodGet, "/login/_ui/preview", ""); recorder.Code != http.StatusUnauthorized ||
		!strings.Contains(recorder.Body.String(), "会话已过期") {
		t.Fatalf("无会话应 401 过期页，实际 %d", recorder.Code)
	}
	// 会话过期错误。
	expired := &fakePageSessions{err: ErrUISessionExpired}
	uiExpired := testWebUI(t, func(options *WebUIOptions) {
		options.EnableComponentPreview = true
		options.Session = expired
	})
	if recorder := serveUI(uiExpired, http.MethodGet, "/login/_ui/preview", ""); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("会话过期应 401，实际 %d", recorder.Code)
	}
	// 无权限错误。
	forbidden := &fakePageSessions{err: ErrUIForbidden}
	uiForbidden := testWebUI(t, func(options *WebUIOptions) {
		options.EnableComponentPreview = true
		options.Session = forbidden
	})
	if recorder := serveUI(uiForbidden, http.MethodGet, "/login/_ui/preview", ""); recorder.Code != http.StatusForbidden {
		t.Fatalf("无权限应 403，实际 %d", recorder.Code)
	}
}

// TestWebUIReplacementPriority 验证宿主渲染器 > 宿主模板 > 内置模板与禁用内置。
func TestWebUIReplacementPriority(t *testing.T) {
	renderer := &fakePageRenderer{body: "<html><body>host-renderer</body></html>"}
	ui := testWebUI(t, func(options *WebUIOptions) {
		options.HostRenderer = renderer
	})
	if recorder := serveUI(ui, http.MethodGet, "/login/403", ""); !strings.Contains(recorder.Body.String(), "host-renderer") {
		t.Fatal("宿主渲染器应优先于内置模板")
	}
	// 宿主模板覆盖同一路由。
	hostTemplate := fstest.MapFS{
		"host/forbidden.html": &fstest.MapFile{Data: []byte(
			`{{define "page-title"}}HOST{{end}}{{define "content"}}<p>host-template</p>{{end}}`)},
	}
	uiTemplates := testWebUI(t, func(options *WebUIOptions) {
		options.HostTemplates = &UIHostTemplates{FS: hostTemplate,
			Overrides: []UITemplateOverride{{RouteName: "system.forbidden",
				TemplatePath: "host/forbidden.html"}}}
	})
	if recorder := serveUI(uiTemplates, http.MethodGet, "/login/403", ""); !strings.Contains(recorder.Body.String(), "host-template") {
		t.Fatal("宿主模板应覆盖内置页面模板")
	}
	// 宿主模板语法错误必须启动失败，不静默回退。
	broken := fstest.MapFS{"host/forbidden.html": &fstest.MapFile{Data: []byte(
		`{{define "content"}}{{if}}{{end}}`)}}
	if _, err := NewWebUI(WebUIOptions{Prefix: "/login", HostTemplates: &UIHostTemplates{
		FS: broken, Overrides: []UITemplateOverride{{RouteName: "system.forbidden",
			TemplatePath: "host/forbidden.html"}}}}); err == nil {
		t.Fatal("宿主模板语法错误应导致构造失败")
	}
	// 整体禁用内置 UI：内置页面关闭，宿主渲染器仍可提供页面。
	disabled := testWebUI(t, func(options *WebUIOptions) {
		options.DisableBuiltinPages = true
		options.HostRenderer = renderer
		options.Routes = []UIRoute{{Name: "host.home", Method: http.MethodGet,
			Path: "/home", Access: UIAccessPublic, Layout: "layout/auth", Template: "host/home"}}
	})
	if recorder := serveUI(disabled, http.MethodGet, "/login/403", ""); recorder.Code != http.StatusNotFound {
		t.Fatalf("禁用内置页面后系统页应 404，实际 %d", recorder.Code)
	}
	if recorder := serveUI(disabled, http.MethodGet, "/login/home", ""); !strings.Contains(recorder.Body.String(), "host-renderer") {
		t.Fatal("禁用内置页面后宿主路由仍应可渲染")
	}
	// 禁用内置且无渲染器/模板 → 构造失败，避免“空页面伪装完成”。
	if _, err := NewWebUI(WebUIOptions{Prefix: "/login", DisableBuiltinPages: true,
		Routes: []UIRoute{{Name: "host.home", Method: http.MethodGet, Path: "/home",
			Access: UIAccessPublic, Layout: "layout/auth", Template: "host/home"}}}); err == nil {
		t.Fatal("禁用内置页面且无宿主模板/渲染器应构造失败")
	}
	// 宿主渲染器运行错误 → 明确 500，不静默回退。
	failing := &fakePageRenderer{err: errors.New("render failed")}
	uiFailing := testWebUI(t, func(options *WebUIOptions) { options.HostRenderer = failing })
	if recorder := serveUI(uiFailing, http.MethodGet, "/login/403", ""); recorder.Code != http.StatusInternalServerError {
		t.Fatalf("宿主渲染器错误应 500，实际 %d", recorder.Code)
	}
}

// fakePageRenderer 是宿主页面渲染器测试替身。
type fakePageRenderer struct {
	body string
	err  error
}

func (f *fakePageRenderer) RenderPage(context.Context, UIPageContext) (UIPageResponse, bool, error) {
	if f.err != nil {
		return UIPageResponse{}, false, f.err
	}
	return UIPageResponse{StatusCode: http.StatusOK, ContentType: "text/html; charset=utf-8",
		Body: []byte(f.body)}, true, nil
}

// TestWebUIAssetsAndI18n 验证资源指纹/缓存/路径安全与语言回退/键覆盖。
func TestWebUIAssetsAndI18n(t *testing.T) {
	ui := testWebUI(t, nil)
	assetURL := ui.assetURL("css/base.css")
	if !strings.HasPrefix(assetURL, "/login/assets/") ||
		!strings.HasSuffix(assetURL, "/css/base.css") {
		t.Fatalf("资源 URL 形态不正确: %s", assetURL)
	}
	recorder := serveUI(ui, http.MethodGet, assetURL, "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("资源请求失败: %d", recorder.Code)
	}
	if recorder.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
		t.Fatalf("指纹资源缓存头不正确: %q", recorder.Header().Get("Cache-Control"))
	}
	if !strings.HasPrefix(recorder.Header().Get("Content-Type"), "text/css") {
		t.Fatalf("资源 MIME 不正确: %q", recorder.Header().Get("Content-Type"))
	}
	// ES 模块必须使用 JavaScript MIME（否则 nosniff 下无法执行）。
	moduleURL := ui.assetURL("js/app.mjs")
	moduleRecorder := serveUI(ui, http.MethodGet, moduleURL, "")
	if moduleRecorder.Code != http.StatusOK ||
		!strings.HasPrefix(moduleRecorder.Header().Get("Content-Type"), "text/javascript") {
		t.Fatalf("ES 模块 MIME 不正确: %d %q", moduleRecorder.Code,
			moduleRecorder.Header().Get("Content-Type"))
	}
	// 页面引用不得出现 missing 资源。
	if recorder := serveUI(ui, http.MethodGet, "/login/403", ""); strings.Contains(recorder.Body.String(), "assets/missing") {
		t.Fatal("页面引用了缺失资源")
	}
	// 错误指纹、路径穿越与未知扩展名拒绝。
	for _, path := range []string{"/login/assets/deadbeefdeadbeef/css/base.css",
		"/login/assets/../../../etc/passwd", "/login/assets/%2e%2e/secret.txt",
		"/login/assets/hash/../../x.css"} {
		if recorder := serveUI(ui, http.MethodGet, path, ""); recorder.Code == http.StatusOK {
			t.Fatalf("危险资源路径 %s 不应返回 200", path)
		}
	}
	// 未提供翻译语言回退 zh-CN；未知键返回键名（不伪造翻译）。
	request := httptest.NewRequest(http.MethodGet, "/login/403", nil)
	request.Header.Set("Accept-Language", "en-US,en;q=0.9")
	page := ui.pageContext(request, &ui.routes[0], UISession{}, "", http.StatusOK, "", "", nil)
	if page.Locale != "zh-CN" {
		t.Fatalf("未翻译语言应回退 zh-CN，实际 %s", page.Locale)
	}
	if got := ui.translate("zh-CN", "missing.key", nil); got != "missing.key" {
		t.Fatalf("未知键应回退键名，实际 %q", got)
	}
	if got := ui.translate("zh-CN", "common.state.empty", nil); got == "" || got == "common.state.empty" {
		t.Fatal("zh-CN 基线键应有真实文案")
	}
	// 模板使用的所有 i18n 键必须存在于 zh-CN 目录。
	used := map[string]struct{}{}
	pattern := regexp.MustCompile(`\b(?:t|t_fmt|label)\s+"([^"]+)"`)
	err := walkEmbeddedTemplates(func(data []byte) {
		for _, match := range pattern.FindAllSubmatch(data, -1) {
			used[string(match[1])] = struct{}{}
		}
	})
	if err != nil {
		t.Fatalf("遍历模板失败: %v", err)
	}
	jsonData, err := webEmbedded.ReadFile("web/i18n/zh-CN.json")
	if err != nil {
		t.Fatalf("读取 zh-CN 文案失败: %v", err)
	}
	catalog := map[string]string{}
	if err := json.Unmarshal(jsonData, &catalog); err != nil {
		t.Fatalf("解析 zh-CN 文案失败: %v", err)
	}
	for key := range used {
		if _, ok := catalog[key]; !ok {
			t.Errorf("模板使用的键 %q 未在 zh-CN 目录定义", key)
		}
	}
}

// walkEmbeddedTemplates 遍历内置模板文件内容（全部 layout/component/page）。
func walkEmbeddedTemplates(visit func([]byte)) error {
	return fs.WalkDir(webEmbedded, "web/templates", func(logicalPath string, entry fs.DirEntry,
		walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(logicalPath, ".html") {
			return nil
		}
		data, readErr := webEmbedded.ReadFile(logicalPath)
		if readErr != nil {
			return readErr
		}
		visit(data)
		return nil
	})
}

// TestWebUIConstantsAndValidation 验证契约版本、前缀与路由唯一性。
func TestWebUIConstantsAndValidation(t *testing.T) {
	if UIContractVersion != "ui.v1" {
		t.Fatalf("契约版本 = %q", UIContractVersion)
	}
	if _, err := NewWebUI(WebUIOptions{ContractVersion: "ui.v2"}); err == nil {
		t.Fatal("未知契约版本应拒绝")
	}
	if _, err := NewWebUI(WebUIOptions{Prefix: "/trailing/"}); err == nil {
		t.Fatal("非法前缀应拒绝")
	}
	names := map[string]struct{}{}
	for _, route := range BuiltinUIRoutes() {
		if _, exists := names[route.Name]; exists {
			t.Fatalf("内置路由重名: %s", route.Name)
		}
		names[route.Name] = struct{}{}
	}
	if _, err := NewWebUI(WebUIOptions{Prefix: "/login", Routes: []UIRoute{
		{Name: "system.forbidden", Method: http.MethodGet, Path: "/dup",
			Access: UIAccessPublic, Layout: "layout/auth", Template: "page/system/error"}}}); err == nil {
		t.Fatal("宿主覆盖内置路由名应拒绝")
	}
	if _, err := NewWebUI(WebUIOptions{Prefix: "/login", Routes: []UIRoute{
		{Name: "host.x", Method: http.MethodGet, Path: "/403",
			Access: UIAccessPublic, Layout: "layout/auth", Template: "page/system/error"}}}); err == nil {
		t.Fatal("宿主覆盖内置路由路径应拒绝")
	}
}

// TestUIHTTPOptionsValidation 验证页面挂载配置的失败关闭（空处理器/过宽或缺失 CSP）。
func TestUIHTTPOptionsValidation(t *testing.T) {
	if _, err := newUIHTTPHandler(httpapi.HTTPOptions{UI: &httpapi.UIHTTPOptions{}}); err == nil {
		t.Fatal("UI 处理器为空应拒绝构造 HTTP Handler")
	}
	if _, err := newUIHTTPHandler(httpapi.HTTPOptions{UI: &httpapi.UIHTTPOptions{
		Handler: http.NotFoundHandler()}}); err == nil {
		t.Fatal("缺少页面 CSP 应拒绝构造 HTTP Handler")
	}
	if _, err := newUIHTTPHandler(httpapi.HTTPOptions{UI: &httpapi.UIHTTPOptions{
		Handler:                   http.NotFoundHandler(),
		PageContentSecurityPolicy: "default-src *; script-src * 'unsafe-inline'",
	}}); err == nil {
		t.Fatal("过宽页面 CSP 应拒绝构造 HTTP Handler")
	}
	if _, err := newUIHTTPHandler(httpapi.HTTPOptions{UI: &httpapi.UIHTTPOptions{
		Handler:                   http.NotFoundHandler(),
		PageContentSecurityPolicy: DefaultUIPageContentSecurityPolicy,
	}}); err != nil {
		t.Fatalf("合法页面 CSP 应允许构造: %v", err)
	}
}
