package app

// 嵌入式 HTTP/页面挂载测试（步骤 183）：与独立服务共用同一装配链（协议域/页面/
// 管理 API/HTTP 防护），宿主用自己的 http.ServeMux 挂载。所有页面请求走真实
// handler 与真实临时 SQLite，不使用测试替身页面。

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

// csrfTokenPattern 匹配页面隐藏 CSRF 字段（字段名由公开页面契约固定为 csrf_token）。
var csrfTokenPattern = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

// httpTestOrigin 是测试配置的公开来源；POST 表单必须带匹配的 Origin 头。
const httpTestOrigin = "http://127.0.0.1:18080"

// fetchStatus 发起 GET 并返回状态码与响应体。
func fetchStatus(client *http.Client, target string) (int, string, error) {
	response, err := client.Get(target)
	if err != nil {
		return 0, "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return 0, "", err
	}
	return response.StatusCode, string(body), nil
}
func hiddenField(t *testing.T, body, name string) string {
	t.Helper()
	pattern := regexp.MustCompile(`name="` + regexp.QuoteMeta(name) + `" value="([^"]+)"`)
	match := pattern.FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatalf("页面未渲染隐藏字段 %s", name)
	}
	return match[1]
}
func postFormOrigin(t *testing.T, client *http.Client, target string,
	form url.Values, origin string) (*http.Response, error) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("构造表单 POST 失败: %v", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", origin)
	return client.Do(request)
}

// openHTTPRuntime 打开带 HTTP 装配的真实运行时。
func openHTTPRuntime(t *testing.T, ctx context.Context, cfg login.Config,
	dir string, clock *testClock, httpOptions *HTTPOptions) *Runtime {
	t.Helper()
	runtime, err := Open(ctx, Options{
		Config: &cfg, DatabasePath: filepath.Join(dir, "login.db"),
		MasterKeyFile: filepath.Join(dir, "master.key"), CreateMasterKey: true,
		Migrate: true, OperatorID: "http-host-operator", Now: clock.Now,
		HTTP: httpOptions,
	})
	if err != nil {
		for walked := err; walked != nil; walked = errors.Unwrap(walked) {
			t.Logf("HTTP 装配失败链路: %v", walked)
		}
		t.Fatalf("Open（含 HTTP）: %v", err)
	}
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	return runtime
}

// httpClientWithJar 返回保留 Cookie 的 HTTP 客户端。
func httpClientWithJar(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("创建 Cookie jar 失败: %v", err)
	}
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

// getCSRFPair 读取指定页面并返回表单 token 与保留 Cookie 的客户端。
func getCSRFPair(t *testing.T, client *http.Client, pageURL string) string {
	t.Helper()
	response, err := client.Get(pageURL)
	if err != nil {
		t.Fatalf("打开页面 %s 失败: %v", pageURL, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("页面 %s 状态码 = %d，期望 200", pageURL, response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatalf("读取页面失败: %v", err)
	}
	match := csrfTokenPattern.FindSubmatch(body)
	if len(match) != 2 {
		t.Fatalf("页面 %s 未找到 CSRF 隐藏字段", pageURL)
	}
	return string(match[1])
}

// TestEmbeddedHTTPPagesMountAndSecurity 覆盖 183 主链：前缀、登录/注册/找回入口、
// CSRF（缺 token/跨来源拒绝）、认证后管理读取、无权限拒绝、宿主 mux 挂载、健康检查。
func TestEmbeddedHTTPPagesMountAndSecurity(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 23, 8, 0, 0, 0, time.UTC))
	dir := t.TempDir()
	cfg := testConfig()
	cfg.Server.PublicBaseURL = httpTestOrigin + "/idp"
	runtime := openHTTPRuntime(t, ctx, cfg, dir, clock, &HTTPOptions{Prefix: "/idp"})
	if runtime.Handler() == nil {
		t.Fatal("配置 HTTP 后 Handler 不能为空")
	}
	if runtime.HTTPPrefix() != "/idp" {
		t.Fatalf("HTTPPrefix = %q，期望 /idp", runtime.HTTPPrefix())
	}
	if _, err := runtime.Bootstrap().EnsureRoot(ctx, RootRequest{
		DisplayName: "Root", Password: "V7!qZ2#Lm9@Tp4$x",
		RequestID: login.NewRequestID(),
	}); err != nil {
		t.Fatalf("EnsureRoot: %v", err)
	}
	// 准备一个持有系统 users.read 的管理员用户（真实角色+委派），以及一个普通用户。
	adminUser, err := runtime.Users().Create(ctx, CreateUserRequest{
		Username: "page-admin", Password: "A7$dK3!mQ9@xR2#v",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建管理员用户失败: %v", err)
	}
	if _, err := runtime.Users().Create(ctx, CreateUserRequest{
		Username: "page-normal", Password: "N4!rT8#xW2@qL6$z",
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("创建普通用户失败: %v", err)
	}
	local := runtime.LocalAdmin()
	adminAPI := runtime.Admin()
	readPermission, err := adminAPI.CreatePermission(ctx, AdminCreatePermissionRequest{
		Caller: local, ScopeID: "system", Key: "users.read", Name: "读取用户",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建 users.read 权限失败: %v", err)
	}
	readRole, err := adminAPI.CreateRole(ctx, AdminCreateRoleRequest{
		Caller: local, ScopeID: "system", Key: "page-reader", Name: "页面读取管理员",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建读取角色失败: %v", err)
	}
	if err := adminAPI.AddRolePermission(ctx, AdminRolePermissionRequest{
		Caller: local, RoleID: readRole.ID, PermissionID: readPermission.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("角色添加权限失败: %v", err)
	}
	if err := adminAPI.GrantApplicationRole(ctx, GrantRoleRequest{
		Caller: local, UserID: adminUser.ID, RoleID: readRole.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("分配读取角色失败: %v", err)
	}

	// 给 page-admin 绑定 TOTP：管理页面需要强认证会话（真实第二因素，不用测试旁路）。
	adminLogin, err := runtime.Auth().Login(ctx, LoginRequest{
		Username: "page-admin", Password: "A7$dK3!mQ9@xR2#v",
		ClientIP: "127.0.0.1", RequestID: login.NewRequestID()})
	if err != nil || adminLogin.Restricted {
		t.Fatalf("管理员首次登录异常: %+v err=%v", adminLogin, err)
	}
	totpStart, err := runtime.Security().BeginTOTPBinding(ctx, TOTPBindingBeginRequest{
		SessionSecret: adminLogin.SessionSecret, Password: "A7$dK3!mQ9@xR2#v",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("开始绑定 TOTP 失败: %v", err)
	}
	if _, err := runtime.Security().ConfirmTOTPBinding(ctx, TOTPBindingConfirmRequest{
		SessionSecret: adminLogin.SessionSecret, BindingID: totpStart.BindingID,
		Code: currentTOTP(t, clock, totpStart.Secret), RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("确认 TOTP 绑定失败: %v", err)
	}
	clock.Advance(30 * time.Second)

	// 宿主自己的 mux：健康检查 + 嵌入式处理器挂载。
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("ok"))
	})
	if err := runtime.Mount(mux); err != nil {
		t.Fatalf("Mount: %v", err)
	}
	server := httptest.NewServer(mux)
	defer server.Close()

	// 健康检查由宿主提供；页面由嵌入式处理器提供。
	if status := httpStatus(t, server.URL+"/healthz"); status != http.StatusOK {
		t.Fatalf("健康检查状态码 = %d", status)
	}
	// 固定前缀：无前缀路径 404，前缀路径 200。
	if status := httpStatus(t, server.URL+"/login"); status != http.StatusNotFound {
		t.Fatalf("无前缀 /login 应 404，实际 %d", status)
	}
	loginPage := server.URL + "/idp/login"
	if status := httpStatus(t, loginPage); status != http.StatusOK {
		t.Fatalf("登录页状态码 = %d", status)
	}
	if status := httpStatus(t, server.URL+"/idp/register"); status != http.StatusOK {
		t.Fatalf("注册页状态码 = %d", status)
	}
	if status := httpStatus(t, server.URL+"/idp/login/forgot-password"); status != http.StatusOK {
		t.Fatalf("找回密码页状态码 = %d", status)
	}
	// 未认证访问管理页：页面会话过期 -> 401（HTTP 层拒绝，不返回管理内容）。
	client := httpClientWithJar(t)
	response, err := client.Get(server.URL + "/idp/admin/users")
	if err != nil {
		t.Fatalf("未认证管理页请求失败: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("未认证管理页应 401，实际 %d", response.StatusCode)
	}
	// CSRF：缺少 token 的登录 POST 必须 403。
	missingToken, err := http.PostForm(server.URL+"/idp/login",
		url.Values{"identifier": {"page-admin"}, "password": {"A7$dK3!mQ9@xR2#v"}})
	if err != nil {
		t.Fatalf("缺 token POST 失败: %v", err)
	}
	missingToken.Body.Close()
	if missingToken.StatusCode != http.StatusForbidden {
		t.Fatalf("缺 CSRF token 的登录 POST 应 403，实际 %d", missingToken.StatusCode)
	}
	// CSRF：跨来源（Origin 不匹配）+ 有效 token 也必须 403。
	token := getCSRFPair(t, client, loginPage)
	crossOriginForm := url.Values{"identifier": {"page-admin"},
		"password": {"A7$dK3!mQ9@xR2#v"}, "csrf_token": {token}}
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/idp/login",
		strings.NewReader(crossOriginForm.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://evil.example")
	crossResponse, err := client.Do(request)
	if err != nil {
		t.Fatalf("跨来源 POST 失败: %v", err)
	}
	crossResponse.Body.Close()
	if crossResponse.StatusCode != http.StatusForbidden {
		t.Fatalf("跨来源登录 POST 应 403，实际 %d", crossResponse.StatusCode)
	}
	// 正常登录：密码 -> 受限会话 -> 第二因素页 -> 真实 TOTP -> 强认证会话，
	// 之后凭真实 users.read 权限读取管理页。
	token = getCSRFPair(t, client, loginPage)
	loginForm := url.Values{"identifier": {"page-admin"},
		"password": {"A7$dK3!mQ9@xR2#v"}, "csrf_token": {token}}
	loginResponse, err := postFormOrigin(t, client, server.URL+"/idp/login", loginForm, httpTestOrigin)
	if err != nil {
		t.Fatalf("登录 POST 失败: %v", err)
	}
	loginResponse.Body.Close()
	if loginResponse.StatusCode != http.StatusSeeOther && loginResponse.StatusCode != http.StatusFound {
		t.Fatalf("正确密码登录应重定向，实际 %d", loginResponse.StatusCode)
	}
	mfaPage := server.URL + "/idp/login/second-factor"
	mfaStatus, mfaBody, err := fetchStatus(client, mfaPage)
	if err != nil || mfaStatus != http.StatusOK {
		t.Fatalf("第二因素页应 200: status=%d err=%v", mfaStatus, err)
	}
	mfaForm := url.Values{
		"challenge_id":  {hiddenField(t, mfaBody, "challenge_id")},
		"attempt_token": {hiddenField(t, mfaBody, "attempt_token")},
		"csrf_token":    {hiddenField(t, mfaBody, "csrf_token")},
		"code":          {currentTOTP(t, clock, totpStart.Secret)},
	}
	mfaResponse, err := postFormOrigin(t, client, mfaPage, mfaForm, httpTestOrigin)
	if err != nil {
		t.Fatalf("第二因素 POST 失败: %v", err)
	}
	mfaResponse.Body.Close()
	if mfaResponse.StatusCode != http.StatusSeeOther && mfaResponse.StatusCode != http.StatusFound {
		t.Fatalf("正确 TOTP 验证应重定向，实际 %d", mfaResponse.StatusCode)
	}
	// 管理页除权限外还要求“近期强认证”的会话事实；生产只有 Passkey 强认证会写入
	// 该事实（本步不做 WebAuthn ceremony）。这里用测试数据库夹具标记强认证新鲜度
	// （与 internal/serverapp 的管理页测试同一做法），身份/第二因素/权限仍全部走
	// 真实链路，不伪造账户或权限。
	jarURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("解析测试地址失败: %v", err)
	}
	sessionSecret := ""
	for _, cookie := range client.Jar.Cookies(jarURL) {
		if strings.Contains(strings.ToLower(cookie.Name), "session") {
			sessionSecret = cookie.Value
		}
	}
	if sessionSecret == "" {
		t.Fatal("登录后缺少会话 Cookie")
	}
	record, err := runtime.base.Services.Sessions.Validate(ctx, sessionSecret)
	if err != nil {
		t.Fatalf("登录后会话无效: %v", err)
	}
	if _, err := runtime.base.Store.DB().ExecContext(ctx,
		`UPDATE sessions SET strong_auth_verified_at_ms=? WHERE id=?`,
		clock.Now().UnixMilli(), record.ID); err != nil {
		t.Fatalf("标记强认证新鲜度失败: %v", err)
	}
	adminPage, err := client.Get(server.URL + "/idp/admin/users")
	if err != nil {
		t.Fatalf("管理员读取管理页失败: %v", err)
	}
	adminBody, _ := io.ReadAll(io.LimitReader(adminPage.Body, 1<<20))
	adminPage.Body.Close()
	if adminPage.StatusCode != http.StatusOK {
		t.Fatalf("有 users.read 权限应能读取管理页，状态 %d body=%s", adminPage.StatusCode, string(adminBody))
	}
	if !strings.Contains(string(adminBody), "用户") {
		t.Fatal("管理页缺少用户相关渲染内容")
	}
	// 无权限：普通用户登录后访问管理页返回 403 页面。
	normalClient := httpClientWithJar(t)
	normalToken := getCSRFPair(t, normalClient, loginPage)
	normalResponse, err := postFormOrigin(t, normalClient, server.URL+"/idp/login", url.Values{
		"identifier": {"page-normal"}, "password": {"N4!rT8#xW2@qL6$z"},
		"csrf_token": {normalToken}}, httpTestOrigin)
	if err != nil {
		t.Fatalf("普通用户登录失败: %v", err)
	}
	normalResponse.Body.Close()
	if normalResponse.StatusCode != http.StatusSeeOther && normalResponse.StatusCode != http.StatusFound {
		t.Fatalf("普通用户登录应重定向，实际 %d", normalResponse.StatusCode)
	}
	forbidden, err := normalClient.Get(server.URL + "/idp/admin/users")
	if err != nil {
		t.Fatalf("普通用户访问管理页失败: %v", err)
	}
	forbidden.Body.Close()
	if forbidden.StatusCode != http.StatusForbidden {
		t.Fatalf("无权限访问管理页应 403，实际 %d", forbidden.StatusCode)
	}
}

// httpStatus 发起 GET 并返回状态码。
func httpStatus(t *testing.T, target string) int {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	response, err := client.Get(target)
	if err != nil {
		t.Fatalf("GET %s 失败: %v", target, err)
	}
	response.Body.Close()
	return response.StatusCode
}

// TestEmbeddedHTTPMissingDependenciesFailStartup 验证缺依赖/非法配置在 Open 阶段
// 失败，而不是悄悄只提供健康页。
func TestEmbeddedHTTPMissingDependenciesFailStartup(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 23, 9, 0, 0, 0, time.UTC))
	cfg := testConfig()
	t.Run("非法前缀", func(t *testing.T) {
		dir := t.TempDir()
		config := cfg
		_, err := Open(ctx, Options{Config: &config,
			DatabasePath:  filepath.Join(dir, "login.db"),
			MasterKeyFile: filepath.Join(dir, "master.key"), CreateMasterKey: true,
			Migrate: true, OperatorID: "http-host-operator", Now: clock.Now,
			HTTP: &HTTPOptions{Prefix: "/bad/prefix/"}})
		if err == nil {
			t.Fatal("非法 HTTP 前缀必须使 Open 失败")
		}
	})
	t.Run("启用协议但配置不合法", func(t *testing.T) {
		dir := t.TempDir()
		config := cfg
		_, err := Open(ctx, Options{Config: &config,
			DatabasePath:  filepath.Join(dir, "login.db"),
			MasterKeyFile: filepath.Join(dir, "master.key"), CreateMasterKey: true,
			Migrate: true, OperatorID: "http-host-operator", Now: clock.Now,
			HTTP: &HTTPOptions{EnableProtocol: true}})
		if err == nil {
			t.Fatal("启用协议端点但缺少合法签发方配置时必须失败")
		}
	})
}

// TestEmbeddedHTTPPageOverrides 验证宿主页面/品牌/静态资源覆盖与关闭内置页面的
// 正向行为：替换内容生效，但路由访问级别、会话与 CSRF 校验仍由服务端真实执行。
func TestEmbeddedHTTPPageOverrides(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC))
	hostTemplatesFS := fstest.MapFS{
		"pages/host-login.html": &fstest.MapFile{Data: []byte(
			`{{define "page-title"}}Host Login{{end}}` +
				`{{define "content"}}<p id="host-template-marker">HOST-TEMPLATE-MARKER</p>{{end}}`)},
	}
	hostAssetsFS := fstest.MapFS{
		"css/base.css": &fstest.MapFile{Data: []byte("/* HOST-ASSET-MARKER */")},
	}
	t.Run("模板/品牌/静态资源覆盖", func(t *testing.T) {
		dir := t.TempDir()
		cfg := testConfig()
		cfg.Server.PublicBaseURL = httpTestOrigin + "/idp"
		runtime := openHTTPRuntime(t, ctx, cfg, dir, clock, &HTTPOptions{
			Prefix: "/idp",
			PageOverrides: &PageOverrides{
				Brand: &login.UIBrand{Name: "HostBrand"},
				HostTemplates: &login.UIHostTemplates{FS: hostTemplatesFS,
					Overrides: []login.UITemplateOverride{{RouteName: "auth.login",
						TemplatePath: "pages/host-login.html"}}},
				AssetOverlays: []fs.FS{hostAssetsFS},
			},
		})
		server := httptest.NewServer(runtime.Handler())
		defer server.Close()
		status, body, err := fetchStatus(server.Client(), server.URL+"/idp/login")
		if err != nil || status != http.StatusOK {
			t.Fatalf("宿主模板覆盖后登录页应 200: status=%d err=%v", status, err)
		}
		if !strings.Contains(body, "HOST-TEMPLATE-MARKER") {
			t.Fatal("宿主模板覆盖未生效（缺少宿主标记）")
		}
		if !strings.Contains(body, "HostBrand") {
			t.Fatal("宿主品牌未生效")
		}
		assetStatus, assetBody, err := fetchStatus(server.Client(),
			server.URL+"/idp/assets/css/base.css")
		if err != nil || assetStatus != http.StatusOK {
			t.Fatalf("宿主静态资源覆盖后应 200: status=%d err=%v", assetStatus, err)
		}
		if !strings.Contains(assetBody, "HOST-ASSET-MARKER") {
			t.Fatal("宿主静态资源覆盖未生效")
		}
	})
	t.Run("宿主渲染器优先", func(t *testing.T) {
		dir := t.TempDir()
		cfg := testConfig()
		cfg.Server.PublicBaseURL = httpTestOrigin + "/idp"
		runtime := openHTTPRuntime(t, ctx, cfg, dir, clock, &HTTPOptions{
			Prefix:        "/idp",
			PageOverrides: &PageOverrides{HostRenderer: hostLoginRenderer{}},
		})
		server := httptest.NewServer(runtime.Handler())
		defer server.Close()
		status, body, err := fetchStatus(server.Client(), server.URL+"/idp/login")
		if err != nil || status != http.StatusOK {
			t.Fatalf("宿主渲染器页面应 200: status=%d err=%v", status, err)
		}
		if !strings.Contains(body, "HOST-RENDERER-MARKER") {
			t.Fatal("宿主单页渲染器未生效")
		}
	})
	t.Run("关闭内置页面", func(t *testing.T) {
		dir := t.TempDir()
		cfg := testConfig()
		cfg.Server.PublicBaseURL = httpTestOrigin + "/idp"
		runtime := openHTTPRuntime(t, ctx, cfg, dir, clock, &HTTPOptions{
			Prefix:        "/idp",
			PageOverrides: &PageOverrides{DisableBuiltinPages: true},
		})
		server := httptest.NewServer(runtime.Handler())
		defer server.Close()
		// DisableBuiltinPages 关闭内置系统页（403/404/401/500）；账号等业务页面由
		// PageAuth 等选项提供，仍按真实会话/权限工作。
		if status := httpStatus(t, server.URL+"/idp/403"); status != http.StatusNotFound {
			t.Fatalf("关闭内置页面后 /403 应 404，实际 %d", status)
		}
		if status := httpStatus(t, server.URL+"/idp/login"); status != http.StatusOK {
			t.Fatalf("关闭内置系统页后登录页仍应由 PageAuth 提供 200，实际 %d", status)
		}
		// 静态资源与安全链仍由同一 handler 提供（关闭内置页面不等于关闭服务）。
		if status := httpStatus(t, server.URL+"/idp/assets/css/base.css"); status != http.StatusOK {
			t.Fatalf("关闭内置页面后静态资源应仍可取，实际 %d", status)
		}
	})
}

// hostLoginRenderer 是测试用宿主单页渲染器：只接管登录页，其余页面回退内置模板。
type hostLoginRenderer struct{}

func (hostLoginRenderer) RenderPage(_ context.Context,
	page login.UIPageContext) (login.UIPageResponse, bool, error) {
	if page.RouteName != "auth.login" {
		return login.UIPageResponse{}, false, nil
	}
	return login.UIPageResponse{StatusCode: http.StatusOK,
		ContentType: "text/html; charset=utf-8",
		Body:        []byte("<html>HOST-RENDERER-MARKER</html>")}, true, nil
}

// TestEmbeddedHTTPAdminAPIMount 验证管理 JSON API 与页面共用同一 HTTP 装配与
// 挂载语义：启用后挂载点真实存在且要求真实管理会话（未认证不是 404）。
func TestEmbeddedHTTPAdminAPIMount(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 23, 11, 0, 0, 0, time.UTC))
	dir := t.TempDir()
	cfg := testConfig()
	cfg.Server.PublicBaseURL = httpTestOrigin + "/idp"
	runtime := openHTTPRuntime(t, ctx, cfg, dir, clock, &HTTPOptions{
		Prefix: "/idp", EnableAdminAPI: true, AdminAPIPrefix: "/api/admin"})
	mounts := runtime.HTTPMounts()
	found := false
	for _, mount := range mounts {
		if mount == "/idp/api/admin" {
			found = true
		}
	}
	if !found {
		t.Fatalf("HTTPMounts 未包含管理 API 挂载点: %v", mounts)
	}
	server := httptest.NewServer(runtime.Handler())
	defer server.Close()
	status := httpStatus(t, server.URL+"/idp/api/admin/users")
	if status == http.StatusNotFound {
		t.Fatal("已启用的管理 API 挂载点不应是 404")
	}
	if status != http.StatusUnauthorized && status != http.StatusForbidden {
		t.Fatalf("未认证管理 API 应 401/403，实际 %d", status)
	}
}

func TestHTTPHandlerAbsentWithoutOptions(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC))
	dir := t.TempDir()
	cfg := testConfig()
	runtime, err := Open(ctx, Options{Config: &cfg,
		DatabasePath:  filepath.Join(dir, "login.db"),
		MasterKeyFile: filepath.Join(dir, "master.key"), CreateMasterKey: true,
		Migrate: true, OperatorID: "http-host-operator", Now: clock.Now})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	if runtime.Handler() != nil {
		t.Fatal("未配置 HTTP 时 Handler 应为 nil")
	}
	mux := http.NewServeMux()
	if err := runtime.Mount(mux); !login.IsErrorCode(err, login.CodeConfigInvalid) {
		t.Fatalf("未配置 HTTP 时 Mount 应返回 CONFIG_INVALID，实际 %v", err)
	}
	if err := runtime.Mount(nil); !login.IsErrorCode(err, login.CodeConfigInvalid) {
		t.Fatalf("nil mux 应返回 CONFIG_INVALID，实际 %v", err)
	}
	_ = errors.Is
}
