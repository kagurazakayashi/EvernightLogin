package main

// selftest.go 是示例的有界自检：启动真实运行时（临时 SQLite + 动态回环端口 +
// 进程内本地邮件捕获器），通过宿主自定义页面与公开 Go 接口走完整链路，同时覆盖
// 成功路径与拒绝路径，并把证据写入结构化 JSON。
//
// 覆盖（与步骤 241 对应）：
//   - 宿主自定义页面与 Evernight 内置页面并存挂载（前缀/路由不冲突）；
//   - 匿名表单同源 + 双提交 CSRF 拒绝；已登录表单用公开 Sessions.ValidateCSRF；
//   - 注册 -> 本地邮件验证链接 -> 宿主验证页确认邮箱 -> 登录；
//   - 错误密码拒绝；资料读取/白名单更新/版本冲突拒绝；
//   - 受控改名：错误密码拒绝；成功后稳定 UserID 不变，业务投影按 UserID 同步；
//   - 跨用户修改拒绝（普通用户不能改他人资料，也不越权成为管理员）；
//   - 找回密码：宿主页面发起 -> 邮件 -> 宿主重置页完成 -> 旧会话失效 -> 新密码登录；
//   - 启用第二因素后，密码第一步只得到受限会话，宿主不建立会话（不绕过 MFA）；
//   - 关闭清理：HTTP 服务、运行时、本地邮件捕获器、动态端口与临时目录。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strconv"
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

// selfTestReport 是自检输出（不包含密码、会话秘密、CSRF 令牌或一次性链接）。
type selfTestReport struct {
	Schema         string          `json:"schema"`
	Status         string          `json:"status"`
	Mode           string          `json:"mode"`
	ListenAddr     string          `json:"listen_addr,omitempty"`
	Port           int             `json:"port,omitempty"`
	HTTPPrefix     string          `json:"http_prefix,omitempty"`
	MailSinkAddr   string          `json:"mail_sink_addr,omitempty"`
	DataDir        string          `json:"data_dir,omitempty"`
	DataDirRemoved bool            `json:"data_dir_removed"`
	Checks         []selfTestCheck `json:"checks"`
	DurationMS     int64           `json:"duration_ms"`
	Error          string          `json:"error,omitempty"`
}

// 合成账户与密码（仅用于临时示例数据库，不是真实秘密）。
const (
	aliceUsername    = "alice-page-user"
	aliceEmail       = "alice-page@example.test"
	alicePassword    = "Kq7-9f3a2b8c4d1e6f0a7b5c2d9e3f8a1b6c"
	aliceNewPassword = "Kq7-3c8d1a6f9b2e5d0c7a4f1b8e3d6c9a2f"
	bobUsername      = "bob-page-user"
	bobEmail         = "bob-page@example.test"
	bobPassword      = "Kq7-7b2e5d8c1a4f0e3b6d9c2a5f8b1e4d7c"
	aliceRenamed     = "alice-renamed-241"
)

// hiddenFieldPattern 构造匹配 "name=... value=..." 隐藏字段的正则。
func hiddenFieldPattern(name string) *regexp.Regexp {
	return regexp.MustCompile(`name="` + regexp.QuoteMeta(name) + `" value="([^"]*)"`)
}

// userIDPattern 匹配公开结果中的用户 ID。
var userIDPattern = regexp.MustCompile(`usr_[0-9a-f]{16,}`)

// executeSelfTest 执行完整自检；parent 只用于取消，内部按 timeout 有界。
func executeSelfTest(parent context.Context, timeout time.Duration) (report selfTestReport) {
	startedAt := time.Now()
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	report = selfTestReport{Schema: selfTestResultSchema, Status: "PASS", Mode: "self-test"}
	// 收尾 defer 最后执行：计算耗时并校验临时目录清理结果。
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

	h, err := openHost(ctx, false, false)
	if err != nil {
		report.Status = "FAIL"
		report.Error = "host.open: " + err.Error()
		report.Checks = append(report.Checks,
			selfTestCheck{ID: "host.open", Status: "FAIL", Detail: err.Error()})
		return report
	}
	listenPort := h.port()
	mailPort := portOfAddress(h.sink.Addr())
	report.ListenAddr = h.listener.Addr().String()
	report.Port = listenPort
	report.HTTPPrefix = h.runtime.HTTPPrefix()
	report.MailSinkAddr = h.sink.Addr()
	report.DataDir = h.dataDir
	// 清理 defer 先注册、后执行：关闭资源、验证端口与临时目录，再交给收尾 defer。
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		shutdownErr := h.shutdown(cleanupCtx)
		removed := !pathExists(h.dataDir)
		report.DataDirRemoved = removed
		httpReleased := tcpPortReleased(listenPort)
		mailReleased := mailPort > 0 && tcpPortReleased(mailPort)
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
			detail := fmt.Sprintf("HTTP 服务/运行时/邮件捕获器已关闭；临时目录已删除；"+
				"HTTP 端口 %d 释放=%t；邮件端口 %d 释放=%t",
				listenPort, httpReleased, mailPort, mailReleased)
			status := "PASS"
			if !httpReleased || !mailReleased {
				status = "FAIL"
				report.Status = "FAIL"
				if report.Error == "" {
					report.Error = "动态端口未释放"
				}
			}
			report.Checks = append(report.Checks,
				selfTestCheck{ID: "cleanup.temp_data_removed", Status: status, Detail: detail})
		}
	}()

	// markFailed 记录失败并中断后续步骤。
	markFailed := func(id string, checkErr error) {
		report.Status = "FAIL"
		if report.Error == "" {
			report.Error = id + ": " + checkErr.Error()
		}
		report.Checks = append(report.Checks,
			selfTestCheck{ID: id, Status: "FAIL", Detail: checkErr.Error()})
	}
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
	baseURL := h.origin()
	origin := h.origin()

	// 敏感值登记：仅用于最后断言它们没有出现在结构化结果中，不写入任何日志。
	var sensitiveValues []string
	mailCursor := 0

	// 1) Open 后状态为 new（未启动），HTTP 与邮件捕获器已装配。
	if !runCheck("host.open", func() (string, error) {
		if h.runtime.State() != login.StateNew {
			return "", fmt.Errorf("Open 后状态应为 new，实际 %q", h.runtime.State())
		}
		if h.runtime.Handler() == nil {
			return "", errors.New("配置 HTTP 后 Handler() 不能为空")
		}
		if h.runtime.HTTPPrefix() != httpPrefix {
			return "", fmt.Errorf("HTTPPrefix = %q，期望 %q", h.runtime.HTTPPrefix(), httpPrefix)
		}
		if h.sink.Addr() == "" {
			return "", errors.New("本地邮件捕获器未监听")
		}
		return fmt.Sprintf("state=new; handler=ok; prefix=%s; listen=%s; mail=%s",
			h.runtime.HTTPPrefix(), h.listener.Addr(), h.sink.Addr()), nil
	}) {
		return report
	}
	// 2) 显式 Start/Ready：邮件投递任务只在显式启动后运行。
	if !runCheck("lifecycle.start_ready", func() (string, error) {
		if err := h.start(ctx); err != nil {
			return "", err
		}
		if h.runtime.State() != login.StateRunning {
			return "", fmt.Errorf("Start 后状态应为 running，实际 %q", h.runtime.State())
		}
		if err := h.runtime.Start(ctx); !errors.Is(err, login.ErrAlreadyStarted) {
			return "", fmt.Errorf("重复 Start 应返回 ErrAlreadyStarted，实际 %v", err)
		}
		return "state=running; 重复 Start=ErrAlreadyStarted; Ready=OK", nil
	}) {
		return report
	}
	// 3) 宿主页面与 Evernight 内置页面并存挂载（前缀/路由不冲突）。
	if !runCheck("host.pages_coexist", func() (string, error) {
		anonymous, clientErr := newHTTPClient()
		if clientErr != nil {
			return "", clientErr
		}
		homeStatus, homeBody, fetchErr := getURL(ctx, anonymous, baseURL+"/")
		if fetchErr != nil {
			return "", fmt.Errorf("读取宿主首页失败: %w", fetchErr)
		}
		if homeStatus != http.StatusOK ||
			!strings.Contains(homeBody, "宿主自定义页面与 Evernight 页面并存") {
			return "", fmt.Errorf("宿主首页异常: status=%d", homeStatus)
		}
		loginStatus, loginBody, fetchErr := getURL(ctx, anonymous, baseURL+httpPrefix+"/login")
		if fetchErr != nil || loginStatus != http.StatusOK ||
			!strings.Contains(loginBody, "宿主自定义登录页") {
			return "", fmt.Errorf("宿主登录页异常: status=%d err=%v", loginStatus, fetchErr)
		}
		registerStatus, registerBody, fetchErr := getURL(ctx, anonymous, baseURL+httpPrefix+"/register")
		if fetchErr != nil || registerStatus != http.StatusOK ||
			!strings.Contains(registerBody, "宿主自定义注册页") {
			return "", fmt.Errorf("宿主注册页异常: status=%d err=%v", registerStatus, fetchErr)
		}
		builtinStatus, builtinBody, fetchErr := getURL(ctx, anonymous, baseURL+httpPrefix+"/403")
		if fetchErr != nil || builtinStatus != http.StatusOK || len(builtinBody) == 0 {
			return "", fmt.Errorf("Evernight 内置 403 页异常: status=%d err=%v",
				builtinStatus, fetchErr)
		}
		devStatus, _, fetchErr := getURL(ctx, anonymous, baseURL+"/dev/mailbox")
		if fetchErr != nil {
			return "", fetchErr
		}
		if devStatus != http.StatusNotFound {
			return "", fmt.Errorf("非演示模式不应注册 /dev/mailbox，实际 %d", devStatus)
		}
		return fmt.Sprintf("宿主首页/登录/注册=200；内置 403=200；/dev/mailbox=%d",
			devStatus), nil
	}) {
		return report
	}
	// 4) 匿名表单 CSRF/同源拒绝路径。
	if !runCheck("host.csrf_anonymous_reject", func() (string, error) {
		client, clientErr := newHTTPClient()
		if clientErr != nil {
			return "", clientErr
		}
		_, pageBody, fetchErr := getURL(ctx, client, baseURL+httpPrefix+"/login")
		if fetchErr != nil {
			return "", fetchErr
		}
		token := hiddenValue(pageBody, anonymousCSRFField)
		if token == "" {
			return "", errors.New("宿主登录页缺少匿名 CSRF 隐藏字段")
		}
		missingStatus, _, postErr := postFormWithOrigin(ctx, client,
			baseURL+httpPrefix+"/login", url.Values{"username": {"x"}, "password": {"y"}},
			origin)
		if postErr != nil {
			return "", postErr
		}
		if missingStatus != http.StatusForbidden {
			return "", fmt.Errorf("缺 CSRF 令牌应 403，实际 %d", missingStatus)
		}
		crossStatus, _, postErr := postFormWithOrigin(ctx, client,
			baseURL+httpPrefix+"/login", url.Values{anonymousCSRFField: {token},
				"username": {"x"}, "password": {"y"}}, "http://evil.example")
		if postErr != nil {
			return "", postErr
		}
		if crossStatus != http.StatusForbidden {
			return "", fmt.Errorf("跨来源应 403，实际 %d", crossStatus)
		}
		noCookieClient, clientErr := newHTTPClient()
		if clientErr != nil {
			return "", clientErr
		}
		noCookieStatus, _, postErr := postFormWithOrigin(ctx, noCookieClient,
			baseURL+httpPrefix+"/login", url.Values{anonymousCSRFField: {token},
				"username": {"x"}, "password": {"y"}}, origin)
		if postErr != nil {
			return "", postErr
		}
		if noCookieStatus != http.StatusForbidden {
			return "", fmt.Errorf("缺 CSRF Cookie 应 403，实际 %d", noCookieStatus)
		}
		return "缺 token=403；跨来源=403；缺 Cookie=403", nil
	}) {
		return report
	}

	// Alice 的完整宿主页面旅程：注册 -> 验证邮件 -> 验证 -> 登录 -> 资料/改名。
	aliceClient, err := newHTTPClient()
	if err != nil {
		markFailed("registration.via_host_page", err)
		return report
	}
	var aliceUserID string
	if !runCheck("registration.via_host_page", func() (string, error) {
		_, pageBody, fetchErr := getURL(ctx, aliceClient, baseURL+httpPrefix+"/register")
		if fetchErr != nil {
			return "", fetchErr
		}
		token := hiddenValue(pageBody, anonymousCSRFField)
		if token == "" {
			return "", errors.New("宿主注册页缺少匿名 CSRF 隐藏字段")
		}
		form := url.Values{anonymousCSRFField: {token}, "username": {aliceUsername},
			"email": {aliceEmail}, "password": {alicePassword}}
		status, body, postErr := postFormWithOrigin(ctx, aliceClient,
			baseURL+httpPrefix+"/register", form, origin)
		if postErr != nil {
			return "", postErr
		}
		if status != http.StatusOK || !strings.Contains(body, "注册完成") {
			return "", fmt.Errorf("宿主注册失败: status=%d body=%s", status,
				snippet(body, 300))
		}
		match := userIDPattern.FindString(body)
		if match == "" {
			return "", errors.New("注册成功页面未返回用户 ID")
		}
		aliceUserID = match
		return fmt.Sprintf("user_id=%s email=%s", aliceUserID, aliceEmail), nil
	}) {
		return report
	}
	var verifyToken string
	var aliceVerifyUID, aliceVerifyCID string
	if !runCheck("email.verification_mail", func() (string, error) {
		message, text, count, waitErr := waitForMail(ctx, h.sink, mailCursor,
			func(mail capturedMail, body string) bool {
				return mailTo(mail, aliceEmail) && hasVerificationLink(body)
			})
		if waitErr != nil {
			return "", waitErr
		}
		mailCursor = count
		uid, cid, token, linkErr := verificationLink(text)
		if linkErr != nil {
			return "", linkErr
		}
		if uid != aliceUserID {
			return "", fmt.Errorf("验证链接用户 %q 与注册用户 %q 不一致", uid, aliceUserID)
		}
		aliceVerifyUID, aliceVerifyCID, verifyToken = uid, cid, token
		sensitiveValues = append(sensitiveValues, token)
		return fmt.Sprintf("收件人=%v；验证链接参数来自邮件（%d 字节令牌）",
			message.To, len(token)), nil
	}) {
		return report
	}
	if !runCheck("email.verify_via_host_page", func() (string, error) {
		verifyClient, clientErr := newHTTPClient()
		if clientErr != nil {
			return "", clientErr
		}
		verifyURL := baseURL + httpPrefix + "/email/verify?uid=" +
			url.QueryEscape(aliceVerifyUID) + "&cid=" + url.QueryEscape(aliceVerifyCID) +
			"&token=" + url.QueryEscape(verifyToken)
		status, pageBody, fetchErr := getURL(ctx, verifyClient, verifyURL)
		if fetchErr != nil {
			return "", fetchErr
		}
		if status != http.StatusOK || !strings.Contains(pageBody, "宿主自定义邮箱验证页") {
			return "", fmt.Errorf("宿主验证页异常: status=%d", status)
		}
		csrf := hiddenValue(pageBody, anonymousCSRFField)
		form := url.Values{anonymousCSRFField: {csrf}, "uid": {aliceVerifyUID},
			"cid": {aliceVerifyCID}, "token": {verifyToken}}
		postStatus, postBody, postErr := postFormWithOrigin(ctx, verifyClient,
			baseURL+httpPrefix+"/email/verify", form, origin)
		if postErr != nil {
			return "", postErr
		}
		if postStatus != http.StatusOK || !strings.Contains(postBody, "邮箱已验证") {
			return "", fmt.Errorf("宿主验证提交失败: status=%d body=%s", postStatus,
				snippet(postBody, 300))
		}
		return fmt.Sprintf("宿主验证页 GET=200；提交后邮箱已验证（%s）", aliceEmail), nil
	}) {
		return report
	}

	var aliceSession hostSession
	var aliceCSRF string
	var aliceRowVersion int64
	if !runCheck("login.wrong_password_rejected", func() (string, error) {
		loginClient, clientErr := newHTTPClient()
		if clientErr != nil {
			return "", clientErr
		}
		_, pageBody, fetchErr := getURL(ctx, loginClient, baseURL+httpPrefix+"/login")
		if fetchErr != nil {
			return "", fetchErr
		}
		token := hiddenValue(pageBody, anonymousCSRFField)
		status, body, postErr := postFormWithOrigin(ctx, loginClient,
			baseURL+httpPrefix+"/login", url.Values{anonymousCSRFField: {token},
				"username": {aliceUsername}, "password": {"wrong-password-241"}}, origin)
		if postErr != nil {
			return "", postErr
		}
		if status != http.StatusOK || !strings.Contains(body, "用户名或密码错误") {
			return "", fmt.Errorf("错误密码应显示通用失败，实际 status=%d", status)
		}
		if _, ok := cookieValue(loginClient, hostSessionCookie); ok {
			return "", errors.New("错误密码不应建立宿主会话")
		}
		return "错误密码=通用失败且无宿主会话", nil
	}) {
		return report
	}
	if !runCheck("login.success", func() (string, error) {
		_, pageBody, fetchErr := getURL(ctx, aliceClient, baseURL+httpPrefix+"/login")
		if fetchErr != nil {
			return "", fetchErr
		}
		token := hiddenValue(pageBody, anonymousCSRFField)
		status, postBody, postErr := postFormWithOrigin(ctx, aliceClient,
			baseURL+httpPrefix+"/login", url.Values{anonymousCSRFField: {token},
				"username": {aliceUsername}, "password": {alicePassword}}, origin)
		if postErr != nil {
			return "", postErr
		}
		if status != http.StatusSeeOther {
			return "", fmt.Errorf("正确登录应 303 跳转，实际 %d；页面消息：%s",
				status, pageMessage(postBody))
		}
		sessionID, ok := cookieValue(aliceClient, hostSessionCookie)
		if !ok {
			return "", errors.New("登录成功未下发宿主会话 Cookie")
		}
		session, found := h.sessions.Get(sessionID)
		if !found {
			return "", errors.New("宿主会话存储中找不到刚建立的会话")
		}
		if session.UserID != aliceUserID || len(session.Secret) == 0 || session.CSRF == "" {
			return "", fmt.Errorf("宿主会话内容异常: user=%q secret=%d csrf=%d",
				session.UserID, len(session.Secret), len(session.CSRF))
		}
		aliceSession = session
		sensitiveValues = append(sensitiveValues, string(session.Secret), session.CSRF)
		return fmt.Sprintf("303 跳转；宿主会话 user_id=%s（会话秘密仅存宿主内存）",
			session.UserID), nil
	}) {
		return report
	}
	if !runCheck("profile.page_and_csrf", func() (string, error) {
		status, body, fetchErr := getURL(ctx, aliceClient, baseURL+"/profile")
		if fetchErr != nil {
			return "", fetchErr
		}
		if status != http.StatusOK || !strings.Contains(body, "宿主业务资料页") {
			return "", fmt.Errorf("资料页异常: status=%d", status)
		}
		if !strings.Contains(body, aliceUsername) {
			return "", errors.New("资料页未显示当前 username")
		}
		rowVersion, parseErr := strconv.ParseInt(hiddenValue(body, "expected_row_version"), 10, 64)
		if parseErr != nil {
			return "", fmt.Errorf("资料页表单缺少版本号: %w", parseErr)
		}
		aliceRowVersion = rowVersion
		aliceCSRF = hiddenValue(body, "csrf_token")
		if aliceCSRF == "" {
			return "", errors.New("资料页表单缺少会话绑定 CSRF 令牌")
		}
		if !strings.Contains(body, "业务 LinkedAt") {
			return "", errors.New("资料页未展示业务投影 LinkedAt")
		}
		return fmt.Sprintf("GET /profile=200；row_version=%d；CSRF 表单字段存在",
			rowVersion), nil
	}) {
		return report
	}
	var aliceProjection profileProjection
	if !runCheck("projection.link", func() (string, error) {
		projection, found := h.projections.Get(aliceUserID)
		if !found {
			return "", errors.New("登录后未建立业务资料投影")
		}
		if projection.LinkedAt.IsZero() || projection.AccountCreatedAt.IsZero() {
			return "", errors.New("业务关联时间或账户创建时间缺失")
		}
		if projection.LinkedAt.Before(projection.AccountCreatedAt) {
			return "", fmt.Errorf("业务 LinkedAt(%s) 不应早于账户 CreatedAt(%s)",
				projection.LinkedAt, projection.AccountCreatedAt)
		}
		if !projection.BusinessUpdatedAt.IsZero() {
			return "", errors.New("首次关联不应虚构业务更新时间")
		}
		if projection.UserID != aliceUserID || projection.Username != aliceUsername {
			return "", fmt.Errorf("投影关联/展示值异常: user=%q username=%q",
				projection.UserID, projection.Username)
		}
		aliceProjection = projection
		return fmt.Sprintf("user_id=%s；LinkedAt=%s；AccountCreatedAt=%s；"+
			"BusinessUpdatedAt=未同步", projection.UserID,
			projection.LinkedAt.Format(time.RFC3339),
			projection.AccountCreatedAt.Format(time.RFC3339)), nil
	}) {
		return report
	}
	if !runCheck("profile.update_whitelist_and_sync", func() (string, error) {
		form := url.Values{"csrf_token": {aliceCSRF},
			"expected_row_version": {strconv.FormatInt(aliceRowVersion, 10)},
			"nickname":             {"Alice Updated"}, "biography": {"示例简介"},
			"language": {"zh-CN"}, "timezone": {"Asia/Shanghai"}}
		status, _, postErr := postFormWithOrigin(ctx, aliceClient,
			baseURL+"/profile/update", form, origin)
		if postErr != nil {
			return "", postErr
		}
		if status != http.StatusSeeOther {
			return "", fmt.Errorf("资料更新应 303，实际 %d", status)
		}
		_, pageBody, fetchErr := getURL(ctx, aliceClient, baseURL+"/profile")
		if fetchErr != nil {
			return "", fetchErr
		}
		if !strings.Contains(pageBody, "Alice Updated") {
			return "", errors.New("资料页未显示更新后的昵称")
		}
		newRowVersion, parseErr := strconv.ParseInt(
			hiddenValue(pageBody, "expected_row_version"), 10, 64)
		if parseErr != nil {
			return "", parseErr
		}
		csr := hiddenValue(pageBody, "csrf_token")
		view, viewErr := h.runtime.Profile().GetProfile(ctx, app.OwnProfileRequest{
			SessionSecret: aliceSession.Secret, RequestID: login.NewRequestID()})
		if viewErr != nil {
			return "", fmt.Errorf("公开 GetProfile 失败: %w", viewErr)
		}
		if view.Nickname != "Alice Updated" || view.UserID != aliceUserID {
			return "", fmt.Errorf("公开资料视图未更新: %+v", view)
		}
		projection, found := h.projections.Get(aliceUserID)
		if !found {
			return "", errors.New("业务投影丢失")
		}
		if projection.Nickname != "Alice Updated" {
			return "", errors.New("业务投影昵称未同步")
		}
		if !projection.LinkedAt.Equal(aliceProjection.LinkedAt) {
			return "", errors.New("资料更新不应改变业务 LinkedAt")
		}
		if projection.BusinessUpdatedAt.IsZero() ||
			projection.BusinessUpdatedAt.Before(projection.LinkedAt) {
			return "", errors.New("业务更新时间未按同步更新")
		}
		aliceProjection = projection
		aliceRowVersion = newRowVersion
		aliceCSRF = csr
		return fmt.Sprintf("昵称已更新；row_version=%d；投影已同步且 LinkedAt 不变",
			newRowVersion), nil
	}) {
		return report
	}
	if !runCheck("profile.update_reject", func() (string, error) {
		// 缺 CSRF：403。
		noCSRF := url.Values{"expected_row_version": {strconv.FormatInt(aliceRowVersion, 10)},
			"nickname": {"Should Not Apply"}}
		status, _, postErr := postFormWithOrigin(ctx, aliceClient,
			baseURL+"/profile/update", noCSRF, origin)
		if postErr != nil {
			return "", postErr
		}
		if status != http.StatusForbidden {
			return "", fmt.Errorf("缺会话 CSRF 应 403，实际 %d", status)
		}
		// 过期版本号：领域拒绝（稳定错误码在页面展示）。
		stale := url.Values{"csrf_token": {aliceCSRF}, "expected_row_version": {"1"},
			"nickname": {"Stale Write"}, "biography": {""}, "language": {""},
			"timezone": {""}}
		status, body, postErr := postFormWithOrigin(ctx, aliceClient,
			baseURL+"/profile/update", stale, origin)
		if postErr != nil {
			return "", postErr
		}
		if status != http.StatusOK || !strings.Contains(body, "更新资料失败") {
			return "", fmt.Errorf("过期版本号应被拒绝: status=%d", status)
		}
		view, viewErr := h.runtime.Profile().GetProfile(ctx, app.OwnProfileRequest{
			SessionSecret: aliceSession.Secret, RequestID: login.NewRequestID()})
		if viewErr != nil {
			return "", viewErr
		}
		if view.Nickname != "Alice Updated" {
			return "", errors.New("被拒绝的更新不应改变资料")
		}
		return "缺 CSRF=403；过期版本号=稳定拒绝且资料未变", nil
	}) {
		return report
	}
	if !runCheck("rename.wrong_password_rejected", func() (string, error) {
		form := url.Values{"csrf_token": {aliceCSRF},
			"expected_row_version": {strconv.FormatInt(aliceRowVersion, 10)},
			"new_username":         {aliceRenamed}, "password": {"wrong-password-241"}}
		status, body, postErr := postFormWithOrigin(ctx, aliceClient,
			baseURL+"/profile/rename", form, origin)
		if postErr != nil {
			return "", postErr
		}
		if status != http.StatusOK || !strings.Contains(body, "修改用户名失败") {
			return "", fmt.Errorf("错误密码改名应被拒绝: status=%d", status)
		}
		view, viewErr := h.runtime.Profile().GetProfile(ctx, app.OwnProfileRequest{
			SessionSecret: aliceSession.Secret, RequestID: login.NewRequestID()})
		if viewErr != nil {
			return "", viewErr
		}
		if view.Username != aliceUsername {
			return "", fmt.Errorf("被拒绝的改名不应生效，实际 %q", view.Username)
		}
		return "错误密码=拒绝且用户名未变", nil
	}) {
		return report
	}
	if !runCheck("rename.success_stable_user_id", func() (string, error) {
		form := url.Values{"csrf_token": {aliceCSRF},
			"expected_row_version": {strconv.FormatInt(aliceRowVersion, 10)},
			"new_username":         {aliceRenamed}, "password": {alicePassword}}
		status, body, postErr := postFormWithOrigin(ctx, aliceClient,
			baseURL+"/profile/rename", form, origin)
		if postErr != nil {
			return "", postErr
		}
		if status != http.StatusOK || !strings.Contains(body, "用户名已修改") {
			return "", fmt.Errorf("正确改名失败: status=%d body=%s", status,
				snippet(body, 300))
		}
		view, viewErr := h.runtime.Profile().GetProfile(ctx, app.OwnProfileRequest{
			SessionSecret: aliceSession.Secret, RequestID: login.NewRequestID()})
		if viewErr != nil {
			return "", viewErr
		}
		if view.Username != aliceRenamed || view.UserID != aliceUserID {
			return "", fmt.Errorf("改名后 user_id/username 异常: %+v", view)
		}
		info, validateErr := h.runtime.Sessions().Validate(ctx, aliceSession.Secret)
		if validateErr != nil || info.UserID != aliceUserID {
			return "", fmt.Errorf("改名后原会话/身份不稳定: %+v err=%v", info, validateErr)
		}
		projection, found := h.projections.Get(aliceUserID)
		if !found || projection.Username != aliceRenamed {
			return "", errors.New("业务投影未按稳定 UserID 同步新用户名")
		}
		if !projection.LinkedAt.Equal(aliceProjection.LinkedAt) {
			return "", errors.New("改名不应改变业务 LinkedAt")
		}
		if !projection.BusinessUpdatedAt.After(aliceProjection.BusinessUpdatedAt) {
			return "", errors.New("改名后业务更新时间未推进")
		}
		aliceProjection = projection
		aliceRowVersion = view.RowVersion
		return fmt.Sprintf("user_id=%s 不变；username=%s；投影 LinkedAt 不变、更新时间推进",
			view.UserID, view.Username), nil
	}) {
		return report
	}

	// Bob 用户：注册/验证/登录，用于跨用户拒绝与 MFA 受限路径。
	bobClient, err := newHTTPClient()
	if err != nil {
		markFailed("user_b.registered_and_verified", err)
		return report
	}
	var bobUserID string
	var bobSession hostSession
	if !runCheck("user_b.registered_and_verified", func() (string, error) {
		_, pageBody, fetchErr := getURL(ctx, bobClient, baseURL+httpPrefix+"/register")
		if fetchErr != nil {
			return "", fetchErr
		}
		token := hiddenValue(pageBody, anonymousCSRFField)
		form := url.Values{anonymousCSRFField: {token}, "username": {bobUsername},
			"email": {bobEmail}, "password": {bobPassword}}
		status, body, postErr := postFormWithOrigin(ctx, bobClient,
			baseURL+httpPrefix+"/register", form, origin)
		if postErr != nil {
			return "", postErr
		}
		if status != http.StatusOK || !strings.Contains(body, "注册完成") {
			return "", fmt.Errorf("Bob 注册失败: status=%d", status)
		}
		bobUserID = userIDPattern.FindString(body)
		if bobUserID == "" {
			return "", errors.New("Bob 注册未返回用户 ID")
		}
		message, text, count, waitErr := waitForMail(ctx, h.sink, mailCursor,
			func(mail capturedMail, body string) bool {
				return mailTo(mail, bobEmail) && hasVerificationLink(body)
			})
		_ = message
		if waitErr != nil {
			return "", waitErr
		}
		mailCursor = count
		uid, cid, verify, linkErr := verificationLink(text)
		if linkErr != nil {
			return "", linkErr
		}
		if uid != bobUserID {
			return "", errors.New("Bob 验证链接用户不一致")
		}
		sensitiveValues = append(sensitiveValues, verify)
		verifyURL := baseURL + httpPrefix + "/email/verify?uid=" + url.QueryEscape(uid) +
			"&cid=" + url.QueryEscape(cid) + "&token=" + url.QueryEscape(verify)
		verifyStatus, verifyBody, fetchErr := getURL(ctx, bobClient, verifyURL)
		if fetchErr != nil {
			return "", fetchErr
		}
		if verifyStatus != http.StatusOK {
			return "", fmt.Errorf("Bob 验证页异常: %d", verifyStatus)
		}
		csrf := hiddenValue(verifyBody, anonymousCSRFField)
		postStatus, postBody, postErr := postFormWithOrigin(ctx, bobClient,
			baseURL+httpPrefix+"/email/verify",
			url.Values{anonymousCSRFField: {csrf}, "uid": {uid}, "cid": {cid},
				"token": {verify}}, origin)
		if postErr != nil {
			return "", postErr
		}
		if postStatus != http.StatusOK || !strings.Contains(postBody, "邮箱已验证") {
			return "", errors.New("Bob 邮箱验证失败")
		}
		return fmt.Sprintf("user_id=%s email=%s 已注册并验证", bobUserID, bobEmail), nil
	}) {
		return report
	}
	if !runCheck("user_b.login", func() (string, error) {
		_, pageBody, fetchErr := getURL(ctx, bobClient, baseURL+httpPrefix+"/login")
		if fetchErr != nil {
			return "", fetchErr
		}
		token := hiddenValue(pageBody, anonymousCSRFField)
		status, _, postErr := postFormWithOrigin(ctx, bobClient,
			baseURL+httpPrefix+"/login", url.Values{anonymousCSRFField: {token},
				"username": {bobUsername}, "password": {bobPassword}}, origin)
		if postErr != nil {
			return "", postErr
		}
		if status != http.StatusSeeOther {
			return "", fmt.Errorf("Bob 登录应 303，实际 %d", status)
		}
		sessionID, ok := cookieValue(bobClient, hostSessionCookie)
		if !ok {
			return "", errors.New("Bob 登录未建立宿主会话")
		}
		session, found := h.sessions.Get(sessionID)
		if !found {
			return "", errors.New("Bob 宿主会话缺失")
		}
		bobSession = session
		sensitiveValues = append(sensitiveValues, string(session.Secret), session.CSRF)
		return fmt.Sprintf("user_id=%s 登录成功", session.UserID), nil
	}) {
		return report
	}
	if !runCheck("cross_user.modification_denied", func() (string, error) {
		// 普通用户 Bob 的管理会话不能修改 Alice（跨用户写入拒绝）。
		hackedNickname := "hacked-by-bob"
		_, err := h.runtime.Admin().UpdateUserProfile(ctx, app.AdminUpdateProfileRequest{
			Caller: h.runtime.AdminSession(bobSession.Secret), UserID: aliceUserID,
			Nickname: &hackedNickname, ExpectedRowVersion: aliceRowVersion,
			RequestID: login.NewRequestID()})
		if err == nil {
			return "", errors.New("普通用户不应能修改他人资料")
		}
		if !login.IsErrorCode(err, login.CodeAccessDenied) &&
			!login.IsErrorCode(err, login.CodePermissionRequired) &&
			!login.IsErrorCode(err, login.CodeAppScopeMismatch) {
			return "", fmt.Errorf("跨用户写入应返回稳定拒绝码，实际 %v", err)
		}
		// Bob 通过宿主页面更新自己的资料，不影响 Alice。
		_, pageBody, fetchErr := getURL(ctx, bobClient, baseURL+"/profile")
		if fetchErr != nil {
			return "", fetchErr
		}
		csrf := hiddenValue(pageBody, "csrf_token")
		rowVersion, parseErr := strconv.ParseInt(hiddenValue(pageBody,
			"expected_row_version"), 10, 64)
		if parseErr != nil {
			return "", parseErr
		}
		form := url.Values{"csrf_token": {csrf},
			"expected_row_version": {strconv.FormatInt(rowVersion, 10)},
			"nickname":             {"Bob Nickname"}, "biography": {""},
			"language": {""}, "timezone": {""}}
		status, _, postErr := postFormWithOrigin(ctx, bobClient,
			baseURL+"/profile/update", form, origin)
		if postErr != nil {
			return "", postErr
		}
		if status != http.StatusSeeOther {
			return "", fmt.Errorf("Bob 更新本人资料应 303，实际 %d", status)
		}
		aliceView, viewErr := h.runtime.Profile().GetProfile(ctx, app.OwnProfileRequest{
			SessionSecret: aliceSession.Secret, RequestID: login.NewRequestID()})
		if viewErr != nil {
			return "", viewErr
		}
		if aliceView.Nickname != "Alice Updated" || aliceView.Username != aliceRenamed {
			return "", fmt.Errorf("Bob 的更新不应影响 Alice: %+v", aliceView)
		}
		bobView, viewErr := h.runtime.Profile().GetProfile(ctx, app.OwnProfileRequest{
			SessionSecret: bobSession.Secret, RequestID: login.NewRequestID()})
		if viewErr != nil {
			return "", viewErr
		}
		if bobView.Nickname != "Bob Nickname" || bobView.UserID != bobUserID {
			return "", errors.New("Bob 的本人资料未更新")
		}
		return "Bob 修改 Alice=稳定拒绝；Bob 改本人成功且 Alice 不受影响", nil
	}) {
		return report
	}

	// 找回密码：宿主页面发起 -> 本地邮件 -> 宿主重置页 -> 旧会话失效 -> 新密码登录。
	var aliceResetToken string
	if !runCheck("forgot_password.via_host_page", func() (string, error) {
		forgotClient, clientErr := newHTTPClient()
		if clientErr != nil {
			return "", clientErr
		}
		_, pageBody, fetchErr := getURL(ctx, forgotClient,
			baseURL+httpPrefix+"/login/forgot-password")
		if fetchErr != nil {
			return "", fetchErr
		}
		token := hiddenValue(pageBody, anonymousCSRFField)
		status, body, postErr := postFormWithOrigin(ctx, forgotClient,
			baseURL+httpPrefix+"/login/forgot-password",
			url.Values{anonymousCSRFField: {token}, "email": {aliceEmail}}, origin)
		if postErr != nil {
			return "", postErr
		}
		if status != http.StatusOK ||
			!strings.Contains(body, "如果该邮箱已注册并已验证") {
			return "", fmt.Errorf("找回页应返回防枚举结果: status=%d", status)
		}
		_, text, count, waitErr := waitForMail(ctx, h.sink, mailCursor,
			func(mail capturedMail, body string) bool {
				return mailTo(mail, aliceEmail) && hasPasswordResetLink(body)
			})
		if waitErr != nil {
			return "", waitErr
		}
		mailCursor = count
		resetToken, tokenErr := passwordResetToken(text)
		if tokenErr != nil {
			return "", tokenErr
		}
		aliceResetToken = resetToken
		sensitiveValues = append(sensitiveValues, resetToken)
		return "宿主找回页=200（防枚举文案）；本地邮件已捕获重置链接", nil
	}) {
		return report
	}
	if !runCheck("reset_password.via_host_page", func() (string, error) {
		resetClient, clientErr := newHTTPClient()
		if clientErr != nil {
			return "", clientErr
		}
		resetURL := baseURL + httpPrefix + "/login/reset-password?token=" +
			url.QueryEscape(aliceResetToken)
		status, pageBody, fetchErr := getURL(ctx, resetClient, resetURL)
		if fetchErr != nil {
			return "", fetchErr
		}
		if status != http.StatusOK || !strings.Contains(pageBody, "宿主自定义重置密码页") {
			return "", fmt.Errorf("宿主重置页异常: status=%d", status)
		}
		csrf := hiddenValue(pageBody, anonymousCSRFField)
		form := url.Values{anonymousCSRFField: {csrf}, "token": {aliceResetToken},
			"new_password": {aliceNewPassword}, "confirm_password": {aliceNewPassword}}
		postStatus, postBody, postErr := postFormWithOrigin(ctx, resetClient,
			baseURL+httpPrefix+"/login/reset-password", form, origin)
		if postErr != nil {
			return "", postErr
		}
		if postStatus != http.StatusOK || !strings.Contains(postBody, "密码已重置") {
			return "", fmt.Errorf("重置密码失败: status=%d body=%s", postStatus,
				snippet(postBody, 300))
		}
		// 旧完整会话必须失效。
		if _, validateErr := h.runtime.Sessions().Validate(ctx, aliceSession.Secret); validateErr == nil {
			return "", errors.New("密码重置后旧会话仍有效")
		}
		// 宿主旧会话页应被重定向到登录页。
		status, _, fetchErr = getURL(ctx, aliceClient, baseURL+"/profile")
		if fetchErr != nil {
			return "", fetchErr
		}
		if status != http.StatusSeeOther {
			return "", fmt.Errorf("旧宿主会话访问资料页应跳转登录，实际 %d", status)
		}
		// 旧密码失效、新密码可登录（Go 公开接口）。
		if _, loginErr := h.runtime.Auth().Login(ctx, app.LoginRequest{
			Username: aliceRenamed, Password: alicePassword, ClientIP: "127.0.0.1",
			RequestID: login.NewRequestID()}); loginErr == nil {
			return "", errors.New("重置后旧密码仍可登录")
		}
		if _, loginErr := h.runtime.Auth().Login(ctx, app.LoginRequest{
			Username: aliceRenamed, Password: aliceNewPassword, ClientIP: "127.0.0.1",
			RequestID: login.NewRequestID()}); loginErr != nil {
			return "", fmt.Errorf("重置后新密码登录失败: %w", loginErr)
		}
		return "宿主重置页完成；旧会话/旧密码失效；新密码可登录", nil
	}) {
		return report
	}

	// MFA 不绕过：Bob 绑定 TOTP 后，密码第一步只得到受限会话，宿主不建立会话。
	if !runCheck("mfa.restricted_not_bypassed", func() (string, error) {
		start, bindErr := h.runtime.Security().BeginTOTPBinding(ctx,
			app.TOTPBindingBeginRequest{SessionSecret: bobSession.Secret,
				Password: bobPassword, RequestID: login.NewRequestID()})
		if bindErr != nil {
			return "", fmt.Errorf("开始 TOTP 绑定失败: %w", bindErr)
		}
		code, codeErr := totpCode(start.Secret, time.Now())
		if codeErr != nil {
			return "", codeErr
		}
		if _, confirmErr := h.runtime.Security().ConfirmTOTPBinding(ctx,
			app.TOTPBindingConfirmRequest{SessionSecret: bobSession.Secret,
				BindingID: start.BindingID, Code: code,
				RequestID: login.NewRequestID()}); confirmErr != nil {
			return "", fmt.Errorf("确认 TOTP 绑定失败: %w", confirmErr)
		}
		// 宿主登录页：只带密码，应提示需要第二因素且不下发宿主会话。
		mfaClient, clientErr := newHTTPClient()
		if clientErr != nil {
			return "", clientErr
		}
		_, pageBody, fetchErr := getURL(ctx, mfaClient, baseURL+httpPrefix+"/login")
		if fetchErr != nil {
			return "", fetchErr
		}
		token := hiddenValue(pageBody, anonymousCSRFField)
		status, body, postErr := postFormWithOrigin(ctx, mfaClient,
			baseURL+httpPrefix+"/login", url.Values{anonymousCSRFField: {token},
				"username": {bobUsername}, "password": {bobPassword}}, origin)
		if postErr != nil {
			return "", postErr
		}
		if status != http.StatusOK || !strings.Contains(body, "第二因素") {
			return "", fmt.Errorf("MFA 账户第一步应提示第二因素: status=%d", status)
		}
		if _, ok := cookieValue(mfaClient, hostSessionCookie); ok {
			return "", errors.New("MFA 受限会话不应建立宿主会话")
		}
		// 直接 Go 接口：受限会话不能访问资料。
		restricted, loginErr := h.runtime.Auth().Login(ctx, app.LoginRequest{
			Username: bobUsername, Password: bobPassword, ClientIP: "127.0.0.1",
			RequestID: login.NewRequestID()})
		if loginErr != nil || !restricted.Restricted || restricted.SecondFactor == nil {
			return "", fmt.Errorf("MFA 账户第一步应返回受限会话: %+v err=%v",
				restricted, loginErr)
		}
		if _, profileErr := h.runtime.Profile().GetProfile(ctx, app.OwnProfileRequest{
			SessionSecret: restricted.SessionSecret,
			RequestID:     login.NewRequestID()}); profileErr == nil {
			return "", errors.New("受限会话不应能访问完整资料")
		}
		return "宿主页面=提示第二因素且无宿主会话；受限会话访问资料=拒绝", nil
	}) {
		return report
	}
	// 敏感值不进入结构化结果（页面不写日志/不持久化，结果 JSON 也只含脱敏证据）。
	if !runCheck("no_secrets_in_result", func() (string, error) {
		payload, marshalErr := json.Marshal(report)
		if marshalErr != nil {
			return "", marshalErr
		}
		for _, value := range sensitiveValues {
			if value == "" {
				continue
			}
			if strings.Contains(string(payload), value) {
				return "", errors.New("自检结果 JSON 中出现会话秘密/CSRF 令牌/一次性令牌")
			}
		}
		return fmt.Sprintf("%d 个敏感值均未出现在结果 JSON 中", len(sensitiveValues)), nil
	}) {
		return report
	}
	return report
}

// ===== 自检辅助 =====

// writeSelfTestJSON 输出单行 JSON 结果。
func writeSelfTestJSON(writer io.Writer, report selfTestReport) error {
	payload, err := json.Marshal(report)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(writer, "%s\n", payload)
	return err
}

// printSelfTestSummary 输出人类可读摘要。
func printSelfTestSummary(writer io.Writer, report selfTestReport) {
	_, _ = fmt.Fprintf(writer, "宿主自定义页面与资料同步示例自检：%s（%d 项检查，耗时 %dms）\n",
		report.Status, len(report.Checks), report.DurationMS)
	for _, check := range report.Checks {
		_, _ = fmt.Fprintf(writer, "  [%s] %s", check.Status, check.ID)
		if check.Detail != "" {
			_, _ = fmt.Fprintf(writer, "：%s", check.Detail)
		}
		_, _ = fmt.Fprintln(writer)
	}
	_, _ = fmt.Fprintf(writer, "监听：%s；HTTP 前缀：%s；邮件捕获器：%s；临时目录已删除：%t\n",
		report.ListenAddr, report.HTTPPrefix, report.MailSinkAddr, report.DataDirRemoved)
	if report.Error != "" {
		_, _ = fmt.Fprintln(writer, "错误：", report.Error)
	}
}

// newHTTPClient 返回保留 Cookie 且不自动跟随重定向的客户端。
func newHTTPClient() (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("创建 Cookie jar 失败: %w", err)
	}
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}, nil
}

// getURL 发起 GET 并返回状态码与响应体（最多 2 MiB）。
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
	body, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		return 0, "", err
	}
	return response.StatusCode, string(body), nil
}

// postFormWithOrigin 提交带 Origin 的表单 POST，返回状态码、响应体与响应头。
func postFormWithOrigin(ctx context.Context, client *http.Client, target string,
	form url.Values, origin string) (int, string, error) {
	status, body, _, err := postFormWithOriginHeaders(ctx, client, target, form, origin)
	return status, body, err
}

// postFormWithOriginHeaders 提交表单 POST 并返回响应头（用于断言未下发 Cookie）。
func postFormWithOriginHeaders(ctx context.Context, client *http.Client, target string,
	form url.Values, origin string) (int, string, http.Header, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target,
		strings.NewReader(form.Encode()))
	if err != nil {
		return 0, "", nil, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, "", nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		return 0, "", nil, err
	}
	return response.StatusCode, string(body), response.Header, nil
}

// hiddenValue 从页面中提取指定 name 的隐藏字段值。
func hiddenValue(body, name string) string {
	match := hiddenFieldPattern(name).FindStringSubmatch(body)
	if len(match) != 2 {
		return ""
	}
	return match[1]
}

// cookieValue 从客户端 Cookie jar 中读取指定 Cookie（针对站点动态端口）。
func cookieValue(client *http.Client, name string) (string, bool) {
	if client == nil || client.Jar == nil {
		return "", false
	}
	// 示例只使用回环地址；遍历 jar 需要具体 URL，这里用 Cookie 内容判断。
	for _, rawURL := range []string{"http://127.0.0.1/"} {
		parsed, err := url.Parse(rawURL)
		if err != nil {
			continue
		}
		for _, cookie := range client.Jar.Cookies(parsed) {
			if cookie.Name == name && cookie.Value != "" {
				return cookie.Value, true
			}
		}
	}
	// 动态端口下 jar 按 host 记录 Cookie，Cookie 只在请求后写入；用最近请求的
	// host 无法从 jar 反查，因此通过 Cookie 探测请求的方式不可行。调用方在需要时
	// 使用 cookieFromClientTarget。
	return "", false
}

// cookieFromClientTarget 在已知站点 URL 时读取 Cookie。
func cookieFromClientTarget(client *http.Client, target, name string) (string, bool) {
	parsed, err := url.Parse(target)
	if err != nil || client == nil || client.Jar == nil {
		return "", false
	}
	for _, cookie := range client.Jar.Cookies(parsed) {
		if cookie.Name == name && cookie.Value != "" {
			return cookie.Value, true
		}
	}
	return "", false
}

// portOfAddress 从 host:port 解析端口。
func portOfAddress(address string) int {
	_, portText, err := net.SplitHostPort(address)
	if err != nil {
		return 0
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return 0
	}
	return port
}

// tcpPortReleased 尝试绑定回环端口验证监听已释放。
func tcpPortReleased(port int) bool {
	if port <= 0 || port > 65535 {
		return false
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		listener, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
		if err == nil {
			_ = listener.Close()
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// pathExists 报告路径是否存在。
func pathExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

// snippet 截取文本用于错误证据（有界）。
func snippet(text string, limit int) string {
	trimmed := strings.TrimSpace(text)
	if len(trimmed) <= limit {
		return trimmed
	}
	return trimmed[:limit] + "..."
}

// pageMessage 提取宿主页面中的错误/成功提示文本（用于失败证据）。
var pageMessagePattern = regexp.MustCompile(`class="(?:error|ok)">([^<]*)<`)

// pageMessage 返回页面第一条错误/成功提示。
func pageMessage(body string) string {
	match := pageMessagePattern.FindStringSubmatch(body)
	if len(match) != 2 {
		return "（无提示文本）"
	}
	return strings.TrimSpace(match[1])
}

// mailTo 报告捕获邮件是否包含指定收件人。
func mailTo(mail capturedMail, address string) bool {
	for _, recipient := range mail.To {
		if strings.EqualFold(strings.TrimSpace(recipient), address) {
			return true
		}
	}
	return false
}

// hasVerificationLink 报告邮件正文是否含邮箱验证入口。
func hasVerificationLink(text string) bool {
	_, _, _, err := verificationLink(text)
	return err == nil
}

// hasPasswordResetLink 报告邮件正文是否含密码找回入口。
func hasPasswordResetLink(text string) bool {
	_, err := passwordResetLink(text)
	return err == nil
}

// waitForMail 在本地邮件捕获器中等待满足条件的邮件（从 startIndex 起扫描）。
func waitForMail(ctx context.Context, sink *smtpSink, startIndex int,
	match func(capturedMail, string) bool) (capturedMail, string, int, error) {
	for {
		messages := sink.Snapshot()
		for index := startIndex; index < len(messages); index++ {
			text, err := decodeCapturedMailText(messages[index].Data)
			if err != nil {
				continue
			}
			if match(messages[index], text) {
				return messages[index], text, len(messages), nil
			}
		}
		select {
		case <-ctx.Done():
			return capturedMail{}, "", len(messages),
				fmt.Errorf("等待邮件超时: %w", ctx.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
}
