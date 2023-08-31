package main

// 嵌入式 HTTP 与页面挂载验收（步骤 183，外部 module 只使用公开 app 包）：
//   - 把 Runtime.Handler/Mount 挂到宿主自己的 http.Server；
//   - 真实前缀、登录/注册/找回页面、CSRF 拒绝、登录后页面、无权限拒绝、健康检查；
//   - 缺依赖/非法配置在 Open 阶段失败，而不是只提供健康页。

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/app"
)

// hostLoginTemplate 是示例宿主模板覆盖：登录页渲染宿主标记，并保留真实 CSRF
// 隐藏字段与登录表单，证明“替换模板不跳过服务端 CSRF/认证”。
const hostLoginTemplate = `{{define "page-title"}}Host Login{{end}}{{define "content"}}` +
	`<p id="host-template-marker">HOST-TEMPLATE-MARKER</p>` +
	`<form method="post" action="{{route "auth.login.submit"}}">{{csrf_field}}` +
	`<input name="identifier" autocomplete="username"><input name="password" type="password" autocomplete="current-password">` +
	`<button type="submit">login</button></form>{{end}}`

// httpExampleOrigin 是示例配置的宿主机来源；表单 POST 必须带匹配的 Origin 头。
const httpExampleOrigin = "http://127.0.0.1:18080"

// httpCSRFTokenPattern 匹配公开页面契约固定的 CSRF 隐藏字段。
var httpCSRFTokenPattern = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

// postFormOriginExample 发送带同源 Origin 头的表单 POST。
func postFormOriginExample(client *http.Client, target string,
	form url.Values, origin string) (*http.Response, error) {
	request, err := http.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", origin)
	return client.Do(request)
}

// noRedirectClient 返回保留 Cookie 且不自动跟随重定向的客户端。
func noRedirectClient() (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("创建 Cookie jar 失败: %w", err)
	}
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}, nil
}

// fetchStatus 发起 GET 并返回状态码与响应体（最多 1 MiB）。
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

// csrfPair 打开页面并返回 CSRF 表单 token（Cookie 已保存在 client 中）。
func csrfPair(client *http.Client, target string) (string, error) {
	status, body, err := fetchStatus(client, target)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("页面 %s 状态码 = %d", target, status)
	}
	match := httpCSRFTokenPattern.FindStringSubmatch(body)
	if len(match) != 2 {
		return "", fmt.Errorf("页面 %s 未找到 CSRF 隐藏字段", target)
	}
	return match[1], nil
}

// runHTTPChecks 用真实监听器验证嵌入模式 HTTP 与页面挂载主链。
func runHTTPChecks(ctx context.Context, runtime *app.Runtime) error {
	if runtime.Handler() == nil {
		return fmt.Errorf("配置 HTTP 后 Handler 不能为空")
	}
	if runtime.HTTPPrefix() != "/idp" {
		return fmt.Errorf("HTTPPrefix = %q，期望 /idp", runtime.HTTPPrefix())
	}
	if _, err := runtime.Users().Create(ctx, app.CreateUserRequest{
		Username: "http-user", Password: "H7!pQ3@wE9#rT2$y", Nickname: "HTTP 用户",
		RequestID: login.NewRequestID()}); err != nil {
		return fmt.Errorf("创建 HTTP 测试用户失败: %w", err)
	}
	if err := runtime.Mount(nil); !login.IsErrorCode(err, login.CodeConfigInvalid) {
		return fmt.Errorf("nil mux 应返回 CONFIG_INVALID，实际 %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("ok"))
	})
	if err := runtime.Mount(mux); err != nil {
		return fmt.Errorf("Mount: %w", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("监听临时端口失败: %w", err)
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		<-serveDone
	}()
	baseURL := "http://" + listener.Addr().String()
	client, err := noRedirectClient()
	if err != nil {
		return err
	}
	// 健康检查由宿主提供；页面由嵌入式处理器提供。
	if status, _, err := fetchStatus(client, baseURL+"/healthz"); err != nil || status != http.StatusOK {
		return fmt.Errorf("健康检查异常: status=%d err=%v", status, err)
	}
	// 固定前缀：无前缀路径 404，前缀登录/注册/找回入口 200；登录页应用宿主模板
	// 覆盖（真实文件系统来源）并渲染宿主品牌。
	if status, _, err := fetchStatus(client, baseURL+"/login"); err != nil || status != http.StatusNotFound {
		return fmt.Errorf("无前缀 /login 应 404: status=%d err=%v", status, err)
	}
	loginStatus, loginBody, err := fetchStatus(client, baseURL+"/idp/login")
	if err != nil || loginStatus != http.StatusOK {
		return fmt.Errorf("登录页应 200: status=%d err=%v", loginStatus, err)
	}
	if !strings.Contains(loginBody, "HOST-TEMPLATE-MARKER") {
		return fmt.Errorf("宿主模板覆盖未生效")
	}
	if !strings.Contains(loginBody, "EmbeddedHostBrand") {
		return fmt.Errorf("宿主品牌未生效")
	}
	for _, path := range []string{"/idp/register", "/idp/login/forgot-password"} {
		status, _, err := fetchStatus(client, baseURL+path)
		if err != nil || status != http.StatusOK {
			return fmt.Errorf("页面 %s 应 200: status=%d err=%v", path, status, err)
		}
	}
	// 宿主静态资源覆盖：无哈希 URL 返回覆盖后的内容。
	assetStatus, assetBody, err := fetchStatus(client, baseURL+"/idp/assets/css/base.css")
	if err != nil || assetStatus != http.StatusOK || !strings.Contains(assetBody, "HOST-ASSET-MARKER") {
		return fmt.Errorf("宿主静态资源覆盖未生效: status=%d err=%v", assetStatus, err)
	}
	// 未认证访问管理页：页面会话过期 -> 401（HTTP 层拒绝）。
	response, err := client.Get(baseURL + "/idp/admin/users")
	if err != nil {
		return fmt.Errorf("未认证管理页请求失败: %w", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("未认证管理页应 401，实际 %d", response.StatusCode)
	}
	// CSRF：缺少 token 的登录 POST 必须 403。
	missing, err := http.PostForm(baseURL+"/idp/login", url.Values{
		"identifier": {"http-user"}, "password": {"H7!pQ3@wE9#rT2$y"}})
	if err != nil {
		return fmt.Errorf("缺 token POST 失败: %w", err)
	}
	missing.Body.Close()
	if missing.StatusCode != http.StatusForbidden {
		return fmt.Errorf("缺 CSRF token 的登录 POST 应 403，实际 %d", missing.StatusCode)
	}
	// CSRF：跨来源 Origin + 有效 token 必须 403。
	token, err := csrfPair(client, baseURL+"/idp/login")
	if err != nil {
		return err
	}
	form := url.Values{"identifier": {"http-user"},
		"password": {"H7!pQ3@wE9#rT2$y"}, "csrf_token": {token}}
	crossRequest, _ := http.NewRequest(http.MethodPost, baseURL+"/idp/login",
		strings.NewReader(form.Encode()))
	crossRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	crossRequest.Header.Set("Origin", "http://evil.example")
	crossResponse, err := client.Do(crossRequest)
	if err != nil {
		return fmt.Errorf("跨来源 POST 失败: %w", err)
	}
	crossResponse.Body.Close()
	if crossResponse.StatusCode != http.StatusForbidden {
		return fmt.Errorf("跨来源登录 POST 应 403，实际 %d", crossResponse.StatusCode)
	}
	// 正常登录：同源表单 + token；之后页面可访问，管理页因无权限 403。
	token, err = csrfPair(client, baseURL+"/idp/login")
	if err != nil {
		return err
	}
	loginResponse, err := postFormOriginExample(client, baseURL+"/idp/login", url.Values{
		"identifier": {"http-user"}, "password": {"H7!pQ3@wE9#rT2$y"},
		"csrf_token": {token}}, httpExampleOrigin)
	if err != nil {
		return fmt.Errorf("登录 POST 失败: %w", err)
	}
	loginResponse.Body.Close()
	if loginResponse.StatusCode != http.StatusSeeOther && loginResponse.StatusCode != http.StatusFound {
		return fmt.Errorf("正确登录应重定向，实际 %d", loginResponse.StatusCode)
	}
	if status, _, err := fetchStatus(client, baseURL+"/idp/home"); err != nil || status != http.StatusOK {
		return fmt.Errorf("登录后首页应 200: status=%d err=%v", status, err)
	}
	if status, _, err := fetchStatus(client, baseURL+"/idp/admin/users"); err != nil || status != http.StatusForbidden {
		return fmt.Errorf("普通用户访问管理页应 403: status=%d err=%v", status, err)
	}
	// 优雅关闭统一由上面的 defer 完成（Shutdown 后只等待一次 serveDone，
	// 避免二次接收造成示例挂起）。
	return nil
}

// runHTTPFailStartChecks 验证缺依赖/非法配置在 Open 阶段失败（不是只提供健康页）。
func runHTTPFailStartChecks(ctx context.Context, databasePath, masterKeyPath string) error {
	cfg := exampleHTTPConfig()
	invalidPrefix, err := app.Open(ctx, app.Options{
		Config: &cfg, DatabasePath: databasePath, MasterKeyFile: masterKeyPath,
		CreateMasterKey: false, Migrate: true, OperatorID: "embedded-example",
		HTTP: &app.HTTPOptions{Prefix: "/bad/prefix/"}})
	if err == nil {
		_ = invalidPrefix.Close(context.Background())
		return fmt.Errorf("非法 HTTP 前缀必须使 Open 失败")
	}
	protocolCfg := exampleHTTPConfig()
	protocol, err := app.Open(ctx, app.Options{
		Config: &protocolCfg, DatabasePath: databasePath, MasterKeyFile: masterKeyPath,
		CreateMasterKey: false, Migrate: true, OperatorID: "embedded-example",
		HTTP: &app.HTTPOptions{EnableProtocol: true}})
	if err == nil {
		_ = protocol.Close(context.Background())
		return fmt.Errorf("启用协议端点但缺少合法签发方配置时必须失败")
	}
	// 页面模板覆盖引用未知路由/非法模板路径时必须在 Open 阶段失败（不静默忽略）。
	overrideCfg := exampleHTTPConfig()
	overridden, err := app.Open(ctx, app.Options{
		Config: &overrideCfg, DatabasePath: databasePath, MasterKeyFile: masterKeyPath,
		CreateMasterKey: false, Migrate: true, OperatorID: "embedded-example",
		HTTP: &app.HTTPOptions{PageOverrides: &app.PageOverrides{
			HostTemplates: &login.UIHostTemplates{FS: os.DirFS(filepath.Dir(databasePath)),
				Overrides: []login.UITemplateOverride{{RouteName: "no.such.route",
					TemplatePath: "missing.html"}}}}}})
	if err == nil {
		_ = overridden.Close(context.Background())
		return fmt.Errorf("未知路由的宿主模板覆盖必须使 Open 失败")
	}
	return nil
}

// exampleHTTPConfig 返回与示例主流程一致的配置（仅用于失败路径场景）。
func exampleHTTPConfig() login.Config {
	cfg := login.Default()
	cfg.Registration.Enabled = true
	cfg.Registration.RequireReview = false
	cfg.Registration.RequireEmailVerification = false
	return cfg
}
