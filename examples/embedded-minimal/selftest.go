package main

// selftest.go 是隐藏在示例里的有界自检：全部步骤只使用公开包与真实临时资源，
// 同时覆盖成功路径与拒绝路径，并把每一步证据写入结构化结果 JSON。
//
// 自检不是产品能力证明的替代品：它只证明“外部 Module 通过公开入口能完成最小
// 嵌入生命周期”，不覆盖 MFA/Passkey、真实邮件、多实例、非 Windows 平台等能力。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/app"
)

// selfTestCheck 是一条可审计的自检检查项。
type selfTestCheck struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// selfTestReport 是自检输出（JSON 或人类摘要共用）；不含密码、会话秘密或 CSRF 令牌。
type selfTestReport struct {
	Schema         string          `json:"schema"`
	Status         string          `json:"status"`
	Mode           string          `json:"mode"`
	ListenAddr     string          `json:"listen_addr,omitempty"`
	Port           int             `json:"port,omitempty"`
	HTTPPrefix     string          `json:"http_prefix,omitempty"`
	DataDir        string          `json:"data_dir,omitempty"`
	DataDirRemoved bool            `json:"data_dir_removed"`
	Checks         []selfTestCheck `json:"checks"`
	DurationMS     int64           `json:"duration_ms"`
	Error          string          `json:"error,omitempty"`
}

// csrfTokenPattern 匹配公开页面契约的 CSRF 隐藏字段（与 examples/embedded-runtime 一致）。
var csrfTokenPattern = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

// executeSelfTest 执行完整自检并返回结构化结果。它总是自己清理临时资源。
func executeSelfTest(ctx context.Context) (report selfTestReport) {
	startedAt := time.Now()
	report = selfTestReport{Schema: selfTestResultSchema, Status: "PASS", Mode: "self-test"}
	defer func() {
		report.DurationMS = time.Since(startedAt).Milliseconds()
		if report.DataDir != "" {
			report.DataDirRemoved = !pathExists(report.DataDir)
		}
		if report.Status == "PASS" && report.DataDir != "" && !report.DataDirRemoved {
			report.Status = "FAIL"
			if report.Error == "" {
				report.Error = "临时数据目录未清理"
			}
		}
	}()

	h, err := openHost(ctx, "embedded-user", false)
	if err != nil {
		report.Status = "FAIL"
		report.Error = "host.open: " + err.Error()
		report.Checks = append(report.Checks,
			selfTestCheck{ID: "host.open", Status: "FAIL", Detail: err.Error()})
		return report
	}
	report.ListenAddr = h.listener.Addr().String()
	report.Port = h.port()
	report.HTTPPrefix = h.runtime.HTTPPrefix()
	report.DataDir = h.dataDir
	// 清理 defer 比下面的 report 收尾 defer 后注册、先执行：先清理再汇总清理证据。
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		shutdownErr := h.shutdown(cleanupCtx)
		removed := !pathExists(h.dataDir)
		report.DataDirRemoved = removed
		switch {
		case shutdownErr != nil:
			report.Status = "FAIL"
			if report.Error == "" {
				report.Error = "清理失败: " + shutdownErr.Error()
			}
			report.Checks = append(report.Checks, selfTestCheck{
				ID: "cleanup.shutdown", Status: "FAIL", Detail: shutdownErr.Error()})
		case !removed:
			report.Status = "FAIL"
			if report.Error == "" {
				report.Error = "临时数据目录未删除: " + h.dataDir
			}
			report.Checks = append(report.Checks, selfTestCheck{
				ID: "cleanup.temp_data_removed", Status: "FAIL",
				Detail: "临时数据目录仍存在: " + h.dataDir})
		default:
			report.Checks = append(report.Checks, selfTestCheck{
				ID: "cleanup.temp_data_removed", Status: "PASS",
				Detail: "HTTP 服务已关闭、运行时已关闭、临时数据目录已删除: " + h.dataDir})
		}
	}()

	// markFailed 记录失败并中断后续步骤（失败后的证据已足够定位，不继续伪造通过）。
	markFailed := func(id string, checkErr error) {
		report.Status = "FAIL"
		if report.Error == "" {
			report.Error = id + ": " + checkErr.Error()
		}
		report.Checks = append(report.Checks,
			selfTestCheck{ID: id, Status: "FAIL", Detail: checkErr.Error()})
	}
	// runCheck 执行一项检查；detail 只放脱敏证据（ID、状态码、计数）。
	runCheck := func(id string, fn func() (string, error)) bool {
		detail, checkErr := fn()
		if checkErr != nil {
			markFailed(id, checkErr)
			return false
		}
		report.Checks = append(report.Checks,
			selfTestCheck{ID: id, Status: "PASS", Detail: detail})
		return true
	}

	// 1) Open 只构造运行时：状态 new、HTTP 处理器已装配、尚未启动后台任务。
	if !runCheck("runtime.opened", func() (string, error) {
		if h.runtime.State() != login.StateNew {
			return "", fmt.Errorf("Open 后状态应为 new（未启动），实际 %q", h.runtime.State())
		}
		if h.runtime.Handler() == nil {
			return "", errors.New("配置 Options.HTTP 后 Handler() 不能为空")
		}
		if h.runtime.HTTPPrefix() != httpPrefix {
			return "", fmt.Errorf("HTTPPrefix = %q，期望 %q", h.runtime.HTTPPrefix(), httpPrefix)
		}
		if h.rootUserID == "" || h.user.ID == "" {
			return "", errors.New("受控初始化 root 或注册合成用户未返回 ID")
		}
		return fmt.Sprintf("state=new; http_prefix=%s; listen=%s", h.runtime.HTTPPrefix(),
			h.listener.Addr().String()), nil
	}) {
		return report
	}
	// 2) 受控本地初始化只由本进程启动流程完成（root 已创建，不经 HTTP）。
	if !runCheck("bootstrap.root", func() (string, error) {
		if h.rootUserID == "" {
			return "", errors.New("受控初始化未建立 root")
		}
		return "root_user_id=" + h.rootUserID, nil
	}) {
		return report
	}
	// 3) 合成用户来自公开注册流程，返回脱敏视图。
	if !runCheck("registration.user_created", func() (string, error) {
		if h.user.ID == "" || h.user.Username != "embedded-user" {
			return "", fmt.Errorf("注册结果异常: id=%q username=%q", h.user.ID, h.user.Username)
		}
		if h.user.Status == "" {
			return "", errors.New("注册结果缺少账户状态")
		}
		return fmt.Sprintf("user_id=%s username=%s status=%s", h.user.ID, h.user.Username,
			h.user.Status), nil
	}) {
		return report
	}
	// 4) 拒绝路径：错误密码与不存在账户返回同一个稳定码，不签发会话。
	const wrongPassword = "not-the-right-password-240"
	var sessionSecret []byte
	if !runCheck("login.bad_password_rejected", func() (string, error) {
		for _, username := range []string{h.user.Username, "no-such-account-240"} {
			result, loginErr := h.runtime.Auth().Login(ctx, app.LoginRequest{
				Username: username, Password: wrongPassword, ClientIP: "127.0.0.1",
				RequestID: login.NewRequestID(),
			})
			if loginErr == nil {
				return "", fmt.Errorf("账户 %q 的错误凭据不应登录成功", username)
			}
			if !login.IsErrorCode(loginErr, login.CodeAuthFailed) {
				return "", fmt.Errorf("账户 %q 应返回稳定 AUTH_FAILED，实际 %v", username, loginErr)
			}
			if len(result.SessionSecret) != 0 {
				return "", fmt.Errorf("账户 %q 登录失败仍返回了会话秘密", username)
			}
		}
		return "错误密码与不存在账户均返回 AUTH_FAILED 且无会话", nil
	}) {
		return report
	}
	// 5) 成功路径：正确密码签发完整会话（本例未启用第二因素）。
	if !runCheck("login.success", func() (string, error) {
		result, loginErr := h.runtime.Auth().Login(ctx, app.LoginRequest{
			Username: h.user.Username, Password: h.userPassword, ClientIP: "127.0.0.1",
			RequestID: login.NewRequestID(),
		})
		if loginErr != nil {
			return "", fmt.Errorf("正确密码登录失败: %w", loginErr)
		}
		if result.Restricted || result.SecondFactor != nil {
			return "", fmt.Errorf("未启用第二因素的账户不应返回受限会话: restricted=%t", result.Restricted)
		}
		if len(result.SessionSecret) == 0 {
			return "", errors.New("登录成功未返回会话秘密")
		}
		sessionSecret = result.SessionSecret
		return fmt.Sprintf("user_id=%s restricted=%t", result.UserID, result.Restricted), nil
	}) {
		return report
	}
	// 6) 会话校验走公开门面，且不返回秘密。
	if !runCheck("session.validate", func() (string, error) {
		info, validateErr := h.runtime.Sessions().Validate(ctx, sessionSecret)
		if validateErr != nil {
			return "", fmt.Errorf("Sessions.Validate 失败: %w", validateErr)
		}
		if info.UserID != h.user.ID || info.SessionID == "" {
			return "", fmt.Errorf("会话快照与登录用户不一致: user_id=%q session_id=%q",
				info.UserID, info.SessionID)
		}
		return fmt.Sprintf("user_id=%s session_id=%s", info.UserID, info.SessionID), nil
	}) {
		return report
	}

	// 7) HTTP/UI：登录页与注册页真实可访问，页面含 CSRF 与表单字段。
	pageClient, err := newHTTPClient()
	if err != nil {
		markFailed("http.ui.page", err)
		return report
	}
	if !runCheck("http.ui.page", func() (string, error) {
		status, body, fetchErr := getURL(ctx, pageClient, h.url(httpPrefix+"/login"))
		if fetchErr != nil {
			return "", fmt.Errorf("读取登录页失败: %w", fetchErr)
		}
		if status != http.StatusOK {
			return "", fmt.Errorf("登录页状态码 = %d，期望 200", status)
		}
		if !strings.Contains(body, `name="identifier"`) || !strings.Contains(body, `name="password"`) {
			return "", errors.New("登录页缺少 identifier/password 表单字段")
		}
		if _, tokenErr := csrfTokenFromPage(body); tokenErr != nil {
			return "", tokenErr
		}
		registerStatus, _, fetchErr := getURL(ctx, pageClient, h.url(httpPrefix+"/register"))
		if fetchErr != nil {
			return "", fmt.Errorf("读取注册页失败: %w", fetchErr)
		}
		if registerStatus != http.StatusOK {
			return "", fmt.Errorf("注册页状态码 = %d，期望 200", registerStatus)
		}
		return fmt.Sprintf("login=%d register=%d; 表单与 CSRF 字段存在", status, registerStatus), nil
	}) {
		return report
	}
	// 8) 拒绝路径：缺 CSRF 令牌与跨来源表单提交都必须 403。
	if !runCheck("http.ui.csrf_reject", func() (string, error) {
		postClient, clientErr := newHTTPClient()
		if clientErr != nil {
			return "", clientErr
		}
		form := url.Values{"identifier": {h.user.Username}, "password": {h.userPassword}}
		missingStatus, _, postErr := postForm(ctx, postClient, h.url(httpPrefix+"/login"),
			form, h.origin())
		if postErr != nil {
			return "", fmt.Errorf("缺少 CSRF 令牌的登录 POST 失败: %w", postErr)
		}
		if missingStatus != http.StatusForbidden {
			return "", fmt.Errorf("缺少 CSRF 令牌的登录 POST 应 403，实际 %d", missingStatus)
		}
		_, pageBody, fetchErr := getURL(ctx, postClient, h.url(httpPrefix+"/login"))
		if fetchErr != nil {
			return "", fmt.Errorf("读取登录页 CSRF 令牌失败: %w", fetchErr)
		}
		token, tokenErr := csrfTokenFromPage(pageBody)
		if tokenErr != nil {
			return "", tokenErr
		}
		crossForm := url.Values{"identifier": {h.user.Username},
			"password": {h.userPassword}, "csrf_token": {token}}
		crossStatus, _, postErr := postForm(ctx, postClient, h.url(httpPrefix+"/login"),
			crossForm, "http://evil.example")
		if postErr != nil {
			return "", fmt.Errorf("跨来源登录 POST 失败: %w", postErr)
		}
		if crossStatus != http.StatusForbidden {
			return "", fmt.Errorf("跨来源登录 POST 应 403，实际 %d", crossStatus)
		}
		return "缺 token=403; 跨来源=403", nil
	}) {
		return report
	}
	// 9) HTTP/UI 成功链：同源表单 + 有效 CSRF 登录，登录后页面可访问；普通用户管理页 403。
	if !runCheck("http.ui.login_submit", func() (string, error) {
		loginClient, clientErr := newHTTPClient()
		if clientErr != nil {
			return "", clientErr
		}
		_, pageBody, fetchErr := getURL(ctx, loginClient, h.url(httpPrefix+"/login"))
		if fetchErr != nil {
			return "", fmt.Errorf("读取登录页失败: %w", fetchErr)
		}
		token, tokenErr := csrfTokenFromPage(pageBody)
		if tokenErr != nil {
			return "", tokenErr
		}
		loginForm := url.Values{"identifier": {h.user.Username},
			"password": {h.userPassword}, "csrf_token": {token}}
		loginStatus, _, postErr := postForm(ctx, loginClient, h.url(httpPrefix+"/login"),
			loginForm, h.origin())
		if postErr != nil {
			return "", fmt.Errorf("同源登录 POST 失败: %w", postErr)
		}
		if loginStatus != http.StatusSeeOther && loginStatus != http.StatusFound {
			return "", fmt.Errorf("正确登录应重定向（303/302），实际 %d", loginStatus)
		}
		homeStatus, _, fetchErr := getURL(ctx, loginClient, h.url(httpPrefix+"/home"))
		if fetchErr != nil {
			return "", fmt.Errorf("登录后首页请求失败: %w", fetchErr)
		}
		if homeStatus != http.StatusOK {
			return "", fmt.Errorf("登录后首页状态码 = %d，期望 200", homeStatus)
		}
		adminStatus, _, fetchErr := getURL(ctx, loginClient, h.url(httpPrefix+"/admin/users"))
		if fetchErr != nil {
			return "", fmt.Errorf("普通用户管理页请求失败: %w", fetchErr)
		}
		if adminStatus != http.StatusForbidden {
			return "", fmt.Errorf("普通用户访问管理页应 403，实际 %d", adminStatus)
		}
		return fmt.Sprintf("login=%d home=200 admin=403", loginStatus), nil
	}) {
		return report
	}
	// 10) 拒绝路径：未认证访问管理页在 HTTP 层 401。
	if !runCheck("http.ui.admin_unauthorized", func() (string, error) {
		anonymous, clientErr := newHTTPClient()
		if clientErr != nil {
			return "", clientErr
		}
		status, _, fetchErr := getURL(ctx, anonymous, h.url(httpPrefix+"/admin/users"))
		if fetchErr != nil {
			return "", fmt.Errorf("未认证管理页请求失败: %w", fetchErr)
		}
		if status != http.StatusUnauthorized {
			return "", fmt.Errorf("未认证管理页应 401，实际 %d", status)
		}
		return "未认证管理页=401", nil
	}) {
		return report
	}
	// 11) 宿主受保护业务路由：公开 Sessions.Validate 在宿主 HTTP 边界校验会话。
	if !runCheck("host.protected_route", func() (string, error) {
		anonymous, clientErr := newHTTPClient()
		if clientErr != nil {
			return "", clientErr
		}
		healthStatus, healthBody, fetchErr := getURL(ctx, anonymous, h.url("/healthz"))
		if fetchErr != nil {
			return "", fmt.Errorf("宿主健康检查失败: %w", fetchErr)
		}
		if healthStatus != http.StatusOK || strings.TrimSpace(healthBody) != "ok" {
			return "", fmt.Errorf("宿主健康检查异常: status=%d body=%q", healthStatus, healthBody)
		}
		unauthorized, _, fetchErr := getURL(ctx, anonymous, h.url("/api/whoami"))
		if fetchErr != nil {
			return "", fmt.Errorf("未认证受保护路由请求失败: %w", fetchErr)
		}
		if unauthorized != http.StatusUnauthorized {
			return "", fmt.Errorf("未认证受保护路由应 401，实际 %d", unauthorized)
		}
		request, requestErr := http.NewRequestWithContext(ctx, http.MethodGet,
			h.url("/api/whoami"), nil)
		if requestErr != nil {
			return "", requestErr
		}
		request.AddCookie(h.sessionCookie(sessionSecret))
		response, doErr := anonymous.Do(request)
		if doErr != nil {
			return "", fmt.Errorf("携带会话的受保护路由请求失败: %w", doErr)
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		response.Body.Close()
		if readErr != nil {
			return "", fmt.Errorf("读取受保护路由响应失败: %w", readErr)
		}
		if response.StatusCode != http.StatusOK {
			return "", fmt.Errorf("有效会话访问受保护路由应 200，实际 %d", response.StatusCode)
		}
		var payload struct {
			UserID string `json:"user_id"`
		}
		if decodeErr := json.Unmarshal(body, &payload); decodeErr != nil {
			return "", fmt.Errorf("受保护路由响应不是合法 JSON: %w", decodeErr)
		}
		if payload.UserID != h.user.ID {
			return "", fmt.Errorf("受保护路由返回的 user_id=%q 与登录用户不一致", payload.UserID)
		}
		return fmt.Sprintf("healthz=200; whoami(无会话)=401; whoami(有会话)=200 user_id=%s",
			payload.UserID), nil
	}) {
		return report
	}
	// 12) 显式生命周期：Start 启动后台任务、Ready 通过、重复 Start 返回稳定错误。
	if !runCheck("lifecycle.start_ready", func() (string, error) {
		if startErr := h.runtime.Start(ctx); startErr != nil {
			return "", fmt.Errorf("显式 Start 失败: %w", startErr)
		}
		if h.runtime.State() != login.StateRunning {
			return "", fmt.Errorf("Start 后状态应为 running，实际 %q", h.runtime.State())
		}
		if startErr := h.runtime.Start(ctx); !errors.Is(startErr, login.ErrAlreadyStarted) {
			return "", fmt.Errorf("重复 Start 应返回 ErrAlreadyStarted，实际 %v", startErr)
		}
		if readyErr := h.runtime.Ready(ctx); readyErr != nil {
			return "", fmt.Errorf("Ready 失败: %w", readyErr)
		}
		return "state=running; 重复 Start=ErrAlreadyStarted; Ready=OK", nil
	}) {
		return report
	}
	// 13) 撤销后旧会话立即失效：公开 Validate 失败，宿主受保护路由 401。
	if !runCheck("session.revoke", func() (string, error) {
		if revokeErr := h.runtime.Sessions().Revoke(ctx, sessionSecret); revokeErr != nil {
			return "", fmt.Errorf("Sessions.Revoke 失败: %w", revokeErr)
		}
		if _, validateErr := h.runtime.Sessions().Validate(ctx, sessionSecret); validateErr == nil {
			return "", errors.New("撤销后 Sessions.Validate 不应继续通过")
		}
		request, requestErr := http.NewRequestWithContext(ctx, http.MethodGet,
			h.url("/api/whoami"), nil)
		if requestErr != nil {
			return "", requestErr
		}
		request.AddCookie(h.sessionCookie(sessionSecret))
		client, clientErr := newHTTPClient()
		if clientErr != nil {
			return "", clientErr
		}
		response, doErr := client.Do(request)
		if doErr != nil {
			return "", fmt.Errorf("撤销后受保护路由请求失败: %w", doErr)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized {
			return "", fmt.Errorf("撤销后受保护路由应 401，实际 %d", response.StatusCode)
		}
		return "撤销后 Validate 失败; 受保护路由=401", nil
	}) {
		return report
	}
	// 14) 幂等关闭：重复 Close 安全，状态最终为 closed。
	if !runCheck("lifecycle.close_idempotent", func() (string, error) {
		if closeErr := h.runtime.Close(ctx); closeErr != nil {
			return "", fmt.Errorf("第一次 Close 失败: %w", closeErr)
		}
		if closeErr := h.runtime.Close(ctx); closeErr != nil {
			return "", fmt.Errorf("重复 Close 应安全，实际 %v", closeErr)
		}
		if h.runtime.State() != login.StateClosed {
			return "", fmt.Errorf("Close 后状态应为 closed，实际 %q", h.runtime.State())
		}
		return "重复 Close 均成功; state=closed", nil
	}) {
		return report
	}
	return report
}

// writeSelfTestJSON 把自检结果写成单行 JSON（stdout 只允许这一行）。
func writeSelfTestJSON(writer io.Writer, report selfTestReport) error {
	payload, err := json.Marshal(report)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "%s\n", payload); err != nil {
		return err
	}
	return nil
}

// printSelfTestSummary 输出人类可读的自检摘要。
func printSelfTestSummary(writer io.Writer, report selfTestReport) {
	_, _ = fmt.Fprintf(writer, "最小嵌入示例自检：%s（%d 项检查，耗时 %dms）\n",
		report.Status, len(report.Checks), report.DurationMS)
	for _, check := range report.Checks {
		_, _ = fmt.Fprintf(writer, "  [%s] %s", check.Status, check.ID)
		if check.Detail != "" {
			_, _ = fmt.Fprintf(writer, "：%s", check.Detail)
		}
		_, _ = fmt.Fprintln(writer)
	}
	_, _ = fmt.Fprintf(writer, "监听：%s；HTTP 前缀：%s；临时数据目录已删除：%t\n",
		report.ListenAddr, report.HTTPPrefix, report.DataDirRemoved)
	if report.Error != "" {
		_, _ = fmt.Fprintln(writer, "错误：", report.Error)
	}
}

// newHTTPClient 返回保留 Cookie 且不自动跟随重定向的客户端（便于断言 303/302）。
func newHTTPClient() (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("创建 Cookie jar 失败: %w", err)
	}
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

// getURL 发起 GET 并返回状态码与响应体（最多 1 MiB）。
func getURL(ctx context.Context, client *http.Client, target string) (int, string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, "", err
	}
	response, err := client.Do(request)
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

// postForm 以同源/跨来源 Origin 提交表单 POST，返回状态码与响应体（最多 1 MiB）。
func postForm(ctx context.Context, client *http.Client, target string,
	form url.Values, origin string) (int, string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target,
		strings.NewReader(form.Encode()))
	if err != nil {
		return 0, "", err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	response, err := client.Do(request)
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

// csrfTokenFromPage 从公开页面提取 CSRF 隐藏字段值（页面契约的一部分）。
func csrfTokenFromPage(body string) (string, error) {
	match := csrfTokenPattern.FindStringSubmatch(body)
	if len(match) != 2 {
		return "", errors.New("页面未找到 CSRF 隐藏字段")
	}
	return match[1], nil
}

// pathExists 报告路径是否存在（用于清理验证）。
func pathExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}
