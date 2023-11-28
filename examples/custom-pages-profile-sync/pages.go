package main

// pages.go 是宿主自定义页面（服务端渲染，html/template）与它们的处理逻辑。
//
// 这些页面是“第二套 UI 的示范”，不是产品前端：它们：
//   - 精确覆盖 Evernight 内置的登录/注册/邮箱验证/找回/重置页面路径，
//     因此邮件链接直接落到宿主页面；其余 Evernight 页面仍在内置前缀下并存；
//   - 只调用公开 Go 接口（Auth/Registration/PasswordReset/Profile/Sessions）；
//   - 自行实现同源校验 + 匿名表单双提交 CSRF；已登录表单用公开
//     Sessions.ValidateCSRF 校验与会话绑定的令牌；
//   - 不把会话秘密、CSRF 令牌或一次性链接写入日志/文件/localStorage；页面只
//     渲染服务端视图，没有任何前端脚本与客户端存储。

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/app"
)

// pageData 是所有宿主页面共用的视图模型（只含脱敏数据）。
type pageData struct {
	Title         string
	Error         string
	Message       string
	IsLoggedIn    bool
	UserID        string
	Username      string
	AnonymousCSRF string
	CSRFToken     string
	UsernameInput string
	RowVersion    int64
	Profile       app.ProfileView
	Projection    profileProjection
	HasProjection bool

	AccountCreatedAtText   string
	AccountUpdatedAtText   string
	LinkedAtText           string
	BusinessUpdatedAtText  string
	LastUsernameChangedAt  string
	VerifyUserID           string
	VerifyCredentialID     string
	VerifyToken            string
	ResetToken             string
	DemoMails              []demoMailView
	LoginPath              string
	RegisterPath           string
	ForgotPath             string
	ProfilePath            string
	LogoutPath             string
	HomePath               string
	EvernightHomePath      string
	EvernightForbiddenPath string
}

// demoMailView 是演示模式本地信报页的一封邮件视图（仅本地演示使用）。
type demoMailView struct {
	To             string
	ReceivedAtText string
	Text           string
}

// pageTemplateText 是页面模板集合（head/各页面共享）。
const pageTemplateText = `{{define "head"}}<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<style>
body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;max-width:58rem;margin:2rem auto;padding:0 1rem;color:#222;line-height:1.55}
nav a{margin-right:.9rem}
.card{border:1px solid #ddd;border-radius:8px;padding:1rem;margin:1rem 0}
.muted{color:#666}
.error{color:#b00020;font-weight:600;white-space:pre-wrap}
.ok{color:#0a7a2f;font-weight:600;white-space:pre-wrap}
table{border-collapse:collapse;margin:.5rem 0}
td,th{border:1px solid #ddd;padding:.25rem .6rem;text-align:left;vertical-align:top}
label{display:block;margin:.45rem 0}
input,textarea{width:100%;max-width:34rem;padding:.3rem;box-sizing:border-box}
button{margin-top:.6rem;padding:.35rem .9rem}
pre{background:#f6f6f6;padding:.8rem;overflow:auto;max-height:24rem}
.warn{background:#fff4e5;border:1px solid #e0a040;padding:.6rem;border-radius:6px}
</style></head><body>
<nav>
<a href="/">业务首页</a>
<a href="{{.LoginPath}}">宿主登录</a>
<a href="{{.RegisterPath}}">宿主注册</a>
<a href="{{.ForgotPath}}">找回密码</a>
<a href="{{.ProfilePath}}">资料同步</a>
<a href="{{.LogoutPath}}">退出</a>
<span class="muted">Evernight 内置页面仍在：<a href="{{.EvernightHomePath}}">首页</a> / <a href="{{.EvernightForbiddenPath}}">403 页</a></span>
</nav>
<h1>{{.Title}}</h1>
{{end}}
{{define "foot"}}<hr>
<p class="muted">示例边界：本页面由宿主实现，只调用公开 Go 接口；Evernight 会话秘密只保存在宿主内存，页面不写日志、不使用 localStorage；生产部署请使用 HTTPS + Secure Cookie。</p>
</body></html>{{end}}

{{define "home"}}{{template "head" .}}
{{if .Error}}<p class="error">{{.Error}}</p>{{end}}
<div class="card">
<h2>宿主自定义页面与 Evernight 页面并存</h2>
<p>本页、登录/注册/验证/找回/资料页都是宿主自己实现的路由与模板；Evernight 内置页面
继续在固定前缀 <code>/idp/</code> 下提供服务（例如 <a href="{{.EvernightHomePath}}">/idp/home</a>、
<a href="{{.EvernightForbiddenPath}}">/idp/403</a>），两者路由不冲突。</p>
{{if .IsLoggedIn}}<p class="ok">已登录：{{.Username}}（稳定 UserID：{{.UserID}}）</p>
{{else}}<p class="muted">当前未登录；可先注册（会向本地邮件捕获器投递验证邮件）再登录。</p>{{end}}
</div>
{{if .HasProjection}}
<div class="card">
<h2>业务资料投影（按稳定 UserID 关联）</h2>
<table>
<tr><th>关联键（稳定 UserID）</th><td>{{.Projection.UserID}}</td></tr>
<tr><th>同步展示 username</th><td>{{.Projection.Username}}（只读展示值，更名不换身份）</td></tr>
<tr><th>同步展示 nickname</th><td>{{.Projection.Nickname}}</td></tr>
<tr><th>业务 LinkedAt</th><td>{{.LinkedAtText}}</td></tr>
<tr><th>账户 CreatedAt（来自 Login）</th><td>{{.AccountCreatedAtText}}</td></tr>
<tr><th>业务 BusinessUpdatedAt</th><td>{{.BusinessUpdatedAtText}}</td></tr>
</table>
<p class="muted">业务 LinkedAt / BusinessUpdatedAt 是业务自建时间；账户 CreatedAt 来自
公开资料视图。业务更新时间不是账户字段，也不读取不存在的业务字段。</p>
</div>
{{end}}
{{template "foot" .}}{{end}}

{{define "login"}}{{template "head" .}}
{{if .Error}}<p class="error">{{.Error}}</p>{{end}}
{{if .Message}}<p class="ok">{{.Message}}</p>{{end}}
<div class="card">
<h2>宿主自定义登录页（公开 <code>Auth().Login</code>）</h2>
<form method="post" action="{{.LoginPath}}">
<input type="hidden" name="host_csrf_token" value="{{.AnonymousCSRF}}">
<label>用户名 <input name="username" value="{{.UsernameInput}}" autocomplete="username"></label>
<label>密码 <input name="password" type="password" autocomplete="current-password"></label>
<button type="submit">登录</button>
</form>
<p class="muted">同源校验与匿名表单 CSRF 由宿主页面完成；密码校验、失败限制与审计由
EvernightLogin 领域层执行。启用第二因素的账户会返回受限会话，本页面不会建立宿主会话
（不绕过 MFA），需按 Evernight 约定完成第二步。</p>
</div>
{{template "foot" .}}{{end}}

{{define "register"}}{{template "head" .}}
{{if .Error}}<p class="error">{{.Error}}</p>{{end}}
{{if .Message}}<p class="ok">{{.Message}}</p>{{end}}
<div class="card">
<h2>宿主自定义注册页（公开 <code>Registration().RegisterAccount</code>）</h2>
<form method="post" action="{{.RegisterPath}}">
<input type="hidden" name="host_csrf_token" value="{{.AnonymousCSRF}}">
<label>用户名 <input name="username" value="{{.UsernameInput}}" autocomplete="username"></label>
<label>邮箱（本地邮件捕获器会收到验证邮件） <input name="email" type="email" autocomplete="email"></label>
<label>密码 <input name="password" type="password" autocomplete="new-password"></label>
<button type="submit">注册</button>
</form>
</div>
{{template "foot" .}}{{end}}

{{define "verify"}}{{template "head" .}}
{{if .Error}}<p class="error">{{.Error}}</p>{{end}}
{{if .Message}}<p class="ok">{{.Message}}</p>{{end}}
<div class="card">
<h2>宿主自定义邮箱验证页（公开 <code>Registration().VerifyEmail</code>）</h2>
<p class="muted">一次性令牌只放在本表单隐藏字段中，页面不写日志、不使用 localStorage。</p>
<form method="post" action="/idp/email/verify">
<input type="hidden" name="host_csrf_token" value="{{.AnonymousCSRF}}">
<input type="hidden" name="uid" value="{{.VerifyUserID}}">
<input type="hidden" name="cid" value="{{.VerifyCredentialID}}">
<input type="hidden" name="token" value="{{.VerifyToken}}">
<button type="submit">确认验证邮箱</button>
</form>
</div>
{{template "foot" .}}{{end}}

{{define "forgot"}}{{template "head" .}}
{{if .Error}}<p class="error">{{.Error}}</p>{{end}}
{{if .Message}}<p class="ok">{{.Message}}</p>{{end}}
<div class="card">
<h2>宿主自定义找回密码页（公开 <code>PasswordReset().Request</code>）</h2>
<form method="post" action="{{.ForgotPath}}">
<input type="hidden" name="host_csrf_token" value="{{.AnonymousCSRF}}">
<label>邮箱 <input name="email" type="email" autocomplete="email"></label>
<button type="submit">发送找回链接</button>
</form>
<p class="muted">无论邮箱是否存在，页面显示同一结果（防枚举）；邮件由本地捕获器接收。</p>
</div>
{{template "foot" .}}{{end}}

{{define "reset"}}{{template "head" .}}
{{if .Error}}<p class="error">{{.Error}}</p>{{end}}
{{if .Message}}<p class="ok">{{.Message}}</p>{{end}}
<div class="card">
<h2>宿主自定义重置密码页（公开 <code>PasswordReset().Complete</code>）</h2>
<form method="post" action="/idp/login/reset-password">
<input type="hidden" name="host_csrf_token" value="{{.AnonymousCSRF}}">
<input type="hidden" name="token" value="{{.ResetToken}}">
<label>新密码 <input name="new_password" type="password" autocomplete="new-password"></label>
<label>确认新密码 <input name="confirm_password" type="password" autocomplete="new-password"></label>
<button type="submit">重置密码</button>
</form>
</div>
{{template "foot" .}}{{end}}

{{define "profile"}}{{template "head" .}}
{{if .Error}}<p class="error">{{.Error}}</p>{{end}}
{{if .Message}}<p class="ok">{{.Message}}</p>{{end}}
{{if not .IsLoggedIn}}
<div class="card"><p>请先<a href="{{.LoginPath}}">登录</a>后查看资料。</p></div>
{{else}}
<div class="card">
<h2>账户资料（公开 <code>Profile().GetProfile/UpdateProfile</code>）</h2>
<table>
<tr><th>稳定 UserID</th><td>{{.Profile.UserID}}</td></tr>
<tr><th>Username</th><td>{{.Profile.Username}}</td></tr>
<tr><th>Nickname</th><td>{{.Profile.Nickname}}</td></tr>
<tr><th>Biography</th><td>{{.Profile.Biography}}</td></tr>
<tr><th>RowVersion</th><td>{{.Profile.RowVersion}}</td></tr>
<tr><th>账户 CreatedAt</th><td>{{.AccountCreatedAtText}}</td></tr>
<tr><th>账户 UpdatedAt</th><td>{{.AccountUpdatedAtText}}</td></tr>
<tr><th>最近改名时间</th><td>{{.LastUsernameChangedAt}}</td></tr>
</table>
<h3>更新白名单字段（公开 <code>Profile().UpdateProfile</code>）</h3>
<form method="post" action="/profile/update">
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
<input type="hidden" name="expected_row_version" value="{{.RowVersion}}">
<label>昵称 <input name="nickname" value="{{.Profile.Nickname}}"></label>
<label>简介 <input name="biography" value="{{.Profile.Biography}}"></label>
<label>语言 <input name="language" value="{{.Profile.Language}}"></label>
<label>时区 <input name="timezone" value="{{.Profile.Timezone}}"></label>
<button type="submit">保存白名单资料</button>
</form>
<h3>受控改名（公开 <code>Profile().ChangeUsername</code>，需要当前密码）</h3>
<form method="post" action="/profile/rename">
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
<input type="hidden" name="expected_row_version" value="{{.RowVersion}}">
<label>新用户名 <input name="new_username" autocomplete="username"></label>
<label>当前密码（真实再次认证） <input name="password" type="password" autocomplete="current-password"></label>
<button type="submit">修改用户名</button>
</form>
<p class="muted">更名不改变 UserID；业务投影按 UserID 关联，username 只是同步展示值。</p>
</div>
<div class="card">
<h2>业务资料投影（业务侧存储，按稳定 UserID 关联）</h2>
{{if .HasProjection}}
<table>
<tr><th>关联键（稳定 UserID）</th><td>{{.Projection.UserID}}</td></tr>
<tr><th>同步展示 username</th><td>{{.Projection.Username}}</td></tr>
<tr><th>同步展示 nickname</th><td>{{.Projection.Nickname}}</td></tr>
<tr><th>业务 LinkedAt</th><td>{{.LinkedAtText}}</td></tr>
<tr><th>账户 CreatedAt（来自公开资料视图）</th><td>{{.AccountCreatedAtText}}</td></tr>
<tr><th>业务 BusinessUpdatedAt</th><td>{{.BusinessUpdatedAtText}}</td></tr>
</table>
<p class="muted">账户 CreatedAt、业务 LinkedAt、业务更新时间是三个不同事实：CreatedAt
来自 Login；LinkedAt 是业务首次关联时间；BusinessUpdatedAt 是业务最近一次同步时间
（未同步显示“未同步”），不会读取账户上不存在的业务字段。</p>
{{else}}<p class="muted">尚未建立业务投影。</p>{{end}}
</div>
{{end}}
{{template "foot" .}}{{end}}

{{define "mailbox"}}{{template "head" .}}
<div class="warn">仅演示模式的本地开发信报页：内容包含一次性验证/找回链接，仅用于本机
手动演示，生产环境不会注册该路由，也不应把令牌写入日志或持久存储。</div>
{{range .DemoMails}}
<div class="card"><h3>收件人：{{.To}}（{{.ReceivedAtText}}）</h3><pre>{{.Text}}</pre></div>
{{else}}<p class="muted">尚未捕获到邮件。</p>{{end}}
{{template "foot" .}}{{end}}
`

// pageTemplates 是编译后的页面模板集合。
var pageTemplates = template.Must(template.New("pages").Parse(pageTemplateText))

// renderPage 渲染宿主页面；错误时直接返回 500，不把内部细节写入页面。
func (h *host) renderPage(writer http.ResponseWriter, status int, name string, data pageData) {
	data.LoginPath = httpPrefix + "/login"
	data.RegisterPath = httpPrefix + "/register"
	data.ForgotPath = httpPrefix + "/login/forgot-password"
	data.ProfilePath = "/profile"
	data.LogoutPath = "/logout"
	data.HomePath = "/"
	data.EvernightHomePath = httpPrefix + "/home"
	data.EvernightForbiddenPath = httpPrefix + "/403"
	var buffer bytes.Buffer
	if err := pageTemplates.ExecuteTemplate(&buffer, name, data); err != nil {
		http.Error(writer, "页面渲染失败", http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(status)
	_, _ = writer.Write(buffer.Bytes())
}

// redirect 返回 303 跳转（表单提交后统一用 303）。
func redirect(writer http.ResponseWriter, target string) {
	writer.Header().Set("Location", target)
	writer.WriteHeader(http.StatusSeeOther)
}

// clientIP 从连接地址解析客户端 IP（示例只监听回环地址，不信任转发头）。
func clientIP(request *http.Request) string {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return "127.0.0.1"
	}
	return host
}

// requestContext 返回 5 秒有界请求上下文。
func requestContext(request *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(request.Context(), 5*time.Second)
}

// formatTimeOrNever 把时间格式化为 UTC RFC3339；零值显示占位文本，不虚构时间。
func formatTimeOrNever(value time.Time, zeroText string) string {
	if value.IsZero() {
		return zeroText
	}
	return value.UTC().Format(time.RFC3339)
}

// handleHome 渲染宿主业务首页。
func (h *host) handleHome(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path != "/" {
		http.NotFound(writer, request)
		return
	}
	if request.Method != http.MethodGet {
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	data := pageData{Title: "宿主业务首页（自定义页面）"}
	if session, info, ok := h.authenticated(request); ok {
		data.IsLoggedIn = true
		data.UserID = info.UserID
		ctx, cancel := requestContext(request)
		defer cancel()
		if view, err := h.runtime.Profile().GetProfile(ctx, app.OwnProfileRequest{
			SessionSecret: session.Secret, RequestID: login.NewRequestID()}); err == nil {
			data.Username = view.Username
			if projection, found := h.projections.Get(info.UserID); found {
				h.fillProjection(&data, projection, view)
			}
		}
	}
	h.renderPage(writer, http.StatusOK, "home", data)
}

// fillProjection 把业务投影与时间文本填入页面数据。
func (h *host) fillProjection(data *pageData, projection profileProjection,
	view app.ProfileView) {
	data.HasProjection = true
	data.Projection = projection
	data.LinkedAtText = formatTimeOrNever(projection.LinkedAt, "未关联")
	data.AccountCreatedAtText = formatTimeOrNever(projection.AccountCreatedAt, "未知")
	data.BusinessUpdatedAtText = formatTimeOrNever(projection.BusinessUpdatedAt, "未同步")
	data.AccountUpdatedAtText = view.UpdatedAt
	if view.UsernameChangedAt == "" {
		data.LastUsernameChangedAt = "无"
	} else {
		data.LastUsernameChangedAt = view.UsernameChangedAt
	}
}

// handleLogin 是宿主自定义登录页（GET 渲染 / POST 调用公开 Auth().Login）。
func (h *host) handleLogin(writer http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodGet:
		if _, _, ok := h.authenticated(request); ok {
			redirect(writer, "/profile")
			return
		}
		token, err := h.issueAnonymousCSRF(writer, request)
		if err != nil {
			http.Error(writer, "生成表单令牌失败", http.StatusInternalServerError)
			return
		}
		h.renderPage(writer, http.StatusOK, "login", pageData{
			Title: "宿主自定义登录页", AnonymousCSRF: token})
	case http.MethodPost:
		h.submitLogin(writer, request)
	default:
		writer.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// submitLogin 处理宿主登录表单：同源 + 匿名 CSRF -> 公开 Login -> 宿主会话。
func (h *host) submitLogin(writer http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	token, tokenErr := h.issueAnonymousCSRF(writer, request)
	if tokenErr != nil {
		http.Error(writer, "生成表单令牌失败", http.StatusInternalServerError)
		return
	}
	if err := h.verifyAnonymousCSRF(request, request.PostFormValue(anonymousCSRFField)); err != nil {
		h.renderPage(writer, http.StatusForbidden, "login", pageData{
			Title: "宿主自定义登录页", AnonymousCSRF: token,
			Error: "表单校验失败：" + err.Error()})
		return
	}
	username := strings.TrimSpace(request.PostFormValue("username"))
	password := request.PostFormValue("password")
	ctx, cancel := requestContext(request)
	defer cancel()
	result, err := h.runtime.Auth().Login(ctx, app.LoginRequest{
		Username: username, Password: password, ClientIP: clientIP(request),
		UserAgent: request.UserAgent(), RequestID: login.NewRequestID(),
	})
	if err != nil {
		message := "登录失败"
		switch {
		case login.IsErrorCode(err, login.CodeAuthFailed):
			message = "用户名或密码错误"
		case login.IsErrorCode(err, login.CodeRateLimited):
			message = "尝试过于频繁，请稍后再试"
		case login.IsErrorCode(err, login.CodeUserDisabled):
			message = "账户当前不可使用"
		}
		h.renderPage(writer, http.StatusOK, "login", pageData{
			Title: "宿主自定义登录页", AnonymousCSRF: token,
			UsernameInput: username, Error: message})
		return
	}
	if result.Restricted {
		// 第二因素/受限状态：宿主不建立会话、不把受限会话当成登录成功。
		h.renderPage(writer, http.StatusOK, "login", pageData{
			Title: "宿主自定义登录页", AnonymousCSRF: token, UsernameInput: username,
			Message: "该账户需要第二因素或额外验证（受限会话）。本宿主页面不建立会话，" +
				"请按 Evernight 约定完成第二步；宿主页面不绕过 MFA。"})
		return
	}
	view, err := h.runtime.Profile().GetProfile(ctx, app.OwnProfileRequest{
		SessionSecret: result.SessionSecret, RequestID: login.NewRequestID()})
	if err != nil {
		_ = h.runtime.Sessions().Revoke(ctx, result.SessionSecret)
		h.renderPage(writer, http.StatusOK, "login", pageData{
			Title: "宿主自定义登录页", AnonymousCSRF: token, UsernameInput: username,
			Error: "登录后读取资料失败，已撤销本次会话（" + publicCode(err) + "）"})
		return
	}
	if _, err := h.projections.Link(view, time.Now()); err != nil {
		h.renderPage(writer, http.StatusOK, "login", pageData{
			Title: "宿主自定义登录页", AnonymousCSRF: token, UsernameInput: username,
			Error: "建立业务资料投影失败"})
		return
	}
	sessionID, err := h.sessions.Put(result.UserID, result.SessionSecret,
		string(result.CSRFSecret))
	if err != nil {
		http.Error(writer, "建立宿主会话失败", http.StatusInternalServerError)
		return
	}
	h.setHostSessionCookie(writer, sessionID)
	redirect(writer, "/profile")
}

// handleRegister 是宿主自定义注册页（公开 Registration().RegisterAccount）。
func (h *host) handleRegister(writer http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodGet:
		token, err := h.issueAnonymousCSRF(writer, request)
		if err != nil {
			http.Error(writer, "生成表单令牌失败", http.StatusInternalServerError)
			return
		}
		h.renderPage(writer, http.StatusOK, "register", pageData{
			Title: "宿主自定义注册页", AnonymousCSRF: token})
	case http.MethodPost:
		h.submitRegister(writer, request)
	default:
		writer.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// submitRegister 处理宿主注册表单（注册后由邮件投递通道发送验证邮件）。
func (h *host) submitRegister(writer http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	token, tokenErr := h.issueAnonymousCSRF(writer, request)
	if tokenErr != nil {
		http.Error(writer, "生成表单令牌失败", http.StatusInternalServerError)
		return
	}
	username := strings.TrimSpace(request.PostFormValue("username"))
	if err := h.verifyAnonymousCSRF(request, request.PostFormValue(anonymousCSRFField)); err != nil {
		h.renderPage(writer, http.StatusForbidden, "register", pageData{
			Title: "宿主自定义注册页", AnonymousCSRF: token, UsernameInput: username,
			Error: "表单校验失败：" + err.Error()})
		return
	}
	email := strings.TrimSpace(request.PostFormValue("email"))
	password := request.PostFormValue("password")
	ctx, cancel := requestContext(request)
	defer cancel()
	registered, err := h.runtime.Registration().RegisterAccount(ctx,
		app.RegisterAccountRequest{Username: username, Password: password, Email: email,
			RequestID: login.NewRequestID()})
	if err != nil {
		message := "注册失败"
		switch {
		case login.IsErrorCode(err, login.CodeConfigInvalid):
			message = "当前未开放注册"
		case login.IsErrorCode(err, login.CodeRateLimited):
			message = "请求过于频繁，请稍后再试"
		case login.IsErrorCode(err, login.CodeReqInvalid):
			message = "注册信息不合法（用户名、邮箱或密码不符合策略）"
		}
		h.renderPage(writer, http.StatusOK, "register", pageData{
			Title: "宿主自定义注册页", AnonymousCSRF: token, UsernameInput: username,
			Error: message})
		return
	}
	// 示例受控本地初始化：把示例自助权限角色分配给新用户（真实部署走产品管理流程）。
	if err := h.assignSelfServiceRole(ctx, registered.UserID); err != nil {
		h.renderPage(writer, http.StatusOK, "register", pageData{
			Title: "宿主自定义注册页", AnonymousCSRF: token, UsernameInput: username,
			Error: "注册成功但示例权限初始化失败：" + publicCode(err)})
		return
	}
	message := fmt.Sprintf("注册完成（用户 %s，状态 %s）。", registered.UserID, registered.Status)
	if registered.VerificationSent {
		message += "验证邮件已交给本地邮件投递通道，请从邮件链接完成邮箱验证。"
	} else {
		message += fmt.Sprintf("验证邮件未发送（%s），请稍后重试。",
			registered.VerificationErrorCode)
	}
	h.renderPage(writer, http.StatusOK, "register", pageData{
		Title: "宿主自定义注册页", Message: message, AnonymousCSRF: token})
}

// handleVerifyEmail 是宿主自定义邮箱验证页（公开 Registration().VerifyEmail）。
func (h *host) handleVerifyEmail(writer http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodGet:
		token, err := h.issueAnonymousCSRF(writer, request)
		if err != nil {
			http.Error(writer, "生成表单令牌失败", http.StatusInternalServerError)
			return
		}
		h.renderPage(writer, http.StatusOK, "verify", pageData{
			Title: "宿主自定义邮箱验证页", AnonymousCSRF: token,
			VerifyUserID:       request.URL.Query().Get("uid"),
			VerifyCredentialID: request.URL.Query().Get("cid"),
			VerifyToken:        request.URL.Query().Get("token")})
	case http.MethodPost:
		h.submitVerifyEmail(writer, request)
	default:
		writer.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// submitVerifyEmail 消费一次性验证令牌（匿名操作，但仍有同源 + CSRF 防护）。
func (h *host) submitVerifyEmail(writer http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	token, tokenErr := h.issueAnonymousCSRF(writer, request)
	if tokenErr != nil {
		http.Error(writer, "生成表单令牌失败", http.StatusInternalServerError)
		return
	}
	data := pageData{Title: "宿主自定义邮箱验证页", AnonymousCSRF: token,
		VerifyUserID:       request.PostFormValue("uid"),
		VerifyCredentialID: request.PostFormValue("cid"),
		VerifyToken:        request.PostFormValue("token")}
	if err := h.verifyAnonymousCSRF(request, request.PostFormValue(anonymousCSRFField)); err != nil {
		data.Error = "表单校验失败：" + err.Error()
		h.renderPage(writer, http.StatusForbidden, "verify", data)
		return
	}
	ctx, cancel := requestContext(request)
	defer cancel()
	verified, err := h.runtime.Registration().VerifyEmail(ctx, app.VerifyEmailRequest{
		UserID: data.VerifyUserID, CredentialID: data.VerifyCredentialID,
		Token: data.VerifyToken, RequestID: login.NewRequestID()})
	if err != nil {
		// 统一失败文案，不回显令牌或内部状态细节。
		data.Error = "验证链接无效或已过期，请重新发送验证邮件"
		h.renderPage(writer, http.StatusOK, "verify", data)
		return
	}
	data.Message = fmt.Sprintf("邮箱已验证：%s（用户 %s，时间 %s）",
		verified.Email, verified.UserID, verified.VerifiedAt)
	h.renderPage(writer, http.StatusOK, "verify", data)
}

// handleForgotPassword 是宿主自定义找回密码页（公开 PasswordReset().Request）。
func (h *host) handleForgotPassword(writer http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodGet:
		token, err := h.issueAnonymousCSRF(writer, request)
		if err != nil {
			http.Error(writer, "生成表单令牌失败", http.StatusInternalServerError)
			return
		}
		h.renderPage(writer, http.StatusOK, "forgot", pageData{
			Title: "宿主自定义找回密码页", AnonymousCSRF: token})
	case http.MethodPost:
		h.submitForgotPassword(writer, request)
	default:
		writer.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// submitForgotPassword 发起找回；对账户存在性与内部失败返回同一防枚举结果。
func (h *host) submitForgotPassword(writer http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	token, tokenErr := h.issueAnonymousCSRF(writer, request)
	if tokenErr != nil {
		http.Error(writer, "生成表单令牌失败", http.StatusInternalServerError)
		return
	}
	if err := h.verifyAnonymousCSRF(request, request.PostFormValue(anonymousCSRFField)); err != nil {
		h.renderPage(writer, http.StatusForbidden, "forgot", pageData{
			Title: "宿主自定义找回密码页", AnonymousCSRF: token,
			Error: "表单校验失败：" + err.Error()})
		return
	}
	email := strings.TrimSpace(request.PostFormValue("email"))
	ctx, cancel := requestContext(request)
	defer cancel()
	err := h.runtime.PasswordReset().Request(ctx, app.RequestPasswordResetRequest{
		Identifier: email, ClientIP: clientIP(request), RequestID: login.NewRequestID()})
	message := "如果该邮箱已注册并已验证，找回链接会发送到邮箱。"
	if err != nil && login.IsErrorCode(err, login.CodeRateLimited) {
		// 来源限流与账户是否存在无关，可安全提示等待。
		message = "请求过于频繁，请稍后再试。"
	} else if err != nil && login.IsErrorCode(err, login.CodeConfigInvalid) {
		message = "找回入口当前不可用（邮件未配置或服务未装配）。"
	}
	h.renderPage(writer, http.StatusOK, "forgot", pageData{
		Title: "宿主自定义找回密码页", AnonymousCSRF: token, Message: message})
}

// handleResetPassword 是宿主自定义重置密码页（公开 PasswordReset().Complete）。
func (h *host) handleResetPassword(writer http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodGet:
		token, err := h.issueAnonymousCSRF(writer, request)
		if err != nil {
			http.Error(writer, "生成表单令牌失败", http.StatusInternalServerError)
			return
		}
		h.renderPage(writer, http.StatusOK, "reset", pageData{
			Title: "宿主自定义重置密码页", AnonymousCSRF: token,
			ResetToken: request.URL.Query().Get("token")})
	case http.MethodPost:
		h.submitResetPassword(writer, request)
	default:
		writer.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// submitResetPassword 校验一次性令牌并完成重置；成功后宿主侧旧会话全部失效。
func (h *host) submitResetPassword(writer http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	token, tokenErr := h.issueAnonymousCSRF(writer, request)
	if tokenErr != nil {
		http.Error(writer, "生成表单令牌失败", http.StatusInternalServerError)
		return
	}
	data := pageData{Title: "宿主自定义重置密码页", AnonymousCSRF: token,
		ResetToken: request.PostFormValue("token")}
	if err := h.verifyAnonymousCSRF(request, request.PostFormValue(anonymousCSRFField)); err != nil {
		data.Error = "表单校验失败：" + err.Error()
		h.renderPage(writer, http.StatusForbidden, "reset", data)
		return
	}
	newPassword := request.PostFormValue("new_password")
	if newPassword != request.PostFormValue("confirm_password") {
		data.Error = "两次输入的新密码不一致"
		h.renderPage(writer, http.StatusOK, "reset", data)
		return
	}
	ctx, cancel := requestContext(request)
	defer cancel()
	if err := h.runtime.PasswordReset().ValidateTokenWithSource(ctx,
		app.ValidatePasswordResetTokenRequest{Token: data.ResetToken,
			ClientIP: clientIP(request), RequestID: login.NewRequestID()}); err != nil {
		data.Error = "找回链接无效或已过期，请重新发起找回"
		h.renderPage(writer, http.StatusOK, "reset", data)
		return
	}
	result, err := h.runtime.PasswordReset().Complete(ctx,
		app.CompletePasswordResetRequest{Token: data.ResetToken, NewPassword: newPassword,
			ClientIP: clientIP(request), RequestID: login.NewRequestID()})
	if err != nil {
		data.Error = "重置未完成：链接可能已失效或新密码不符合策略"
		h.renderPage(writer, http.StatusOK, "reset", data)
		return
	}
	// 密码重置会撤销 Evernight 旧会话；宿主侧同一用户的会话也必须立刻失效。
	h.sessions.DeleteUser(result.UserID)
	data.Message = fmt.Sprintf("密码已重置（用户 %s）。旧会话已失效，请重新登录。", result.UserID)
	h.renderPage(writer, http.StatusOK, "reset", data)
}

// handleProfilePage 渲染宿主业务资料页（GET）。
func (h *host) handleProfilePage(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	session, info, ok := h.authenticated(request)
	if !ok {
		redirect(writer, httpPrefix+"/login")
		return
	}
	h.renderProfile(writer, request, session, info, http.StatusOK, "", "")
}

// renderProfile 重新读取公开资料与业务投影并渲染资料页。
func (h *host) renderProfile(writer http.ResponseWriter, request *http.Request,
	session hostSession, info app.SessionInfo, status int, errorMessage, okMessage string) {
	ctx, cancel := requestContext(request)
	defer cancel()
	view, err := h.runtime.Profile().GetProfile(ctx, app.OwnProfileRequest{
		SessionSecret: session.Secret, RequestID: login.NewRequestID()})
	if err != nil {
		h.sessions.Delete(session.ID)
		h.clearHostSessionCookie(writer)
		redirect(writer, httpPrefix+"/login")
		return
	}
	data := pageData{Title: "宿主业务资料页（公开 Profile 接口）", IsLoggedIn: true,
		Profile: view, RowVersion: view.RowVersion, CSRFToken: session.CSRF,
		Error: errorMessage, Message: okMessage}
	projection, found := h.projections.Get(info.UserID)
	if !found {
		if linked, linkErr := h.projections.Link(view, time.Now()); linkErr == nil {
			projection, found = linked, true
		}
	}
	if found {
		h.fillProjection(&data, projection, view)
	}
	h.renderPage(writer, status, "profile", data)
}

// handleProfileUpdate 处理白名单资料更新（公开 Profile().UpdateProfile）。
func (h *host) handleProfileUpdate(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	session, info, ok := h.authenticated(request)
	if !ok {
		redirect(writer, httpPrefix+"/login")
		return
	}
	if err := request.ParseForm(); err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	ctx, cancel := requestContext(request)
	defer cancel()
	if err := h.verifySameOrigin(request); err != nil {
		h.renderProfile(writer, request, session, info, http.StatusForbidden, err.Error(), "")
		return
	}
	if err := h.runtime.Sessions().ValidateCSRF(ctx, session.Secret,
		request.PostFormValue(authenticatedCSRFField)); err != nil {
		h.renderProfile(writer, request, session, info, http.StatusForbidden,
			"会话绑定的 CSRF 校验失败，请刷新页面重试", "")
		return
	}
	rowVersion, err := strconv.ParseInt(request.PostFormValue("expected_row_version"), 10, 64)
	if err != nil {
		h.renderProfile(writer, request, session, info, http.StatusBadRequest,
			"缺少或非法的资料版本号", "")
		return
	}
	nickname := request.PostFormValue("nickname")
	biography := request.PostFormValue("biography")
	language := request.PostFormValue("language")
	timezone := request.PostFormValue("timezone")
	view, err := h.runtime.Profile().UpdateProfile(ctx, app.UpdateOwnProfileRequest{
		SessionSecret: session.Secret, Nickname: &nickname, Biography: &biography,
		Language: &language, Timezone: &timezone, ExpectedRowVersion: rowVersion,
		RequestID: login.NewRequestID()})
	if err != nil {
		h.renderProfile(writer, request, session, info, http.StatusOK,
			"更新资料失败："+publicCode(err), "")
		return
	}
	if _, err := h.projections.SyncProfile(view, time.Now()); err != nil {
		h.renderProfile(writer, request, session, info, http.StatusOK,
			"资料已更新，但业务投影同步失败", "")
		return
	}
	redirect(writer, "/profile")
}

// handleProfileRename 处理受控改名（公开 Profile().ChangeUsername）。
func (h *host) handleProfileRename(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	session, info, ok := h.authenticated(request)
	if !ok {
		redirect(writer, httpPrefix+"/login")
		return
	}
	if err := request.ParseForm(); err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	ctx, cancel := requestContext(request)
	defer cancel()
	if err := h.verifySameOrigin(request); err != nil {
		h.renderProfile(writer, request, session, info, http.StatusForbidden, err.Error(), "")
		return
	}
	if err := h.runtime.Sessions().ValidateCSRF(ctx, session.Secret,
		request.PostFormValue(authenticatedCSRFField)); err != nil {
		h.renderProfile(writer, request, session, info, http.StatusForbidden,
			"会话绑定的 CSRF 校验失败，请刷新页面重试", "")
		return
	}
	rowVersion, err := strconv.ParseInt(request.PostFormValue("expected_row_version"), 10, 64)
	if err != nil {
		h.renderProfile(writer, request, session, info, http.StatusBadRequest,
			"缺少或非法的资料版本号", "")
		return
	}
	newUsername := strings.TrimSpace(request.PostFormValue("new_username"))
	view, err := h.runtime.Profile().ChangeUsername(ctx, app.ChangeOwnUsernameRequest{
		SessionSecret: session.Secret, NewUsername: newUsername,
		Password: request.PostFormValue("password"), ExpectedRowVersion: rowVersion,
		RequestID: login.NewRequestID()})
	if err != nil {
		h.renderProfile(writer, request, session, info, http.StatusOK,
			"修改用户名失败："+publicCode(err), "")
		return
	}
	if _, err := h.projections.SyncProfile(view, time.Now()); err != nil {
		h.renderProfile(writer, request, session, info, http.StatusOK,
			"用户名已修改，但业务投影同步失败", "")
		return
	}
	h.renderProfile(writer, request, session, info, http.StatusOK, "",
		"用户名已修改；稳定 UserID 不变，业务投影已按 UserID 同步 username 展示值")
}

// handleLogout 撤销 Evernight 会话并清除宿主会话。
func (h *host) handleLogout(writer http.ResponseWriter, request *http.Request) {
	if session, ok := h.currentHostSession(request); ok {
		ctx, cancel := requestContext(request)
		_ = h.runtime.Sessions().Revoke(ctx, session.Secret)
		cancel()
		h.sessions.Delete(session.ID)
	}
	h.clearHostSessionCookie(writer)
	redirect(writer, "/")
}

// handleDevMailbox 是仅演示模式可用的本地信报页（不进入自检，也不进入生产路径）。
func (h *host) handleDevMailbox(writer http.ResponseWriter, request *http.Request) {
	if !h.demoMode {
		http.NotFound(writer, request)
		return
	}
	mails := h.sink.Snapshot()
	views := make([]demoMailView, 0, len(mails))
	for _, mail := range mails {
		text, err := decodeCapturedMailText(mail.Data)
		if err != nil {
			continue
		}
		views = append(views, demoMailView{To: strings.Join(mail.To, ", "),
			ReceivedAtText: mail.ReceivedAt.UTC().Format(time.RFC3339), Text: text})
	}
	h.renderPage(writer, http.StatusOK, "mailbox", pageData{
		Title: "本地演示信报（仅演示模式）", DemoMails: views})
}

// publicCode 返回稳定公开错误码文本；未知错误不暴露内部细节。
func publicCode(err error) string {
	if err == nil {
		return ""
	}
	if code, ok := login.ErrorCodeOf(err); ok {
		return string(code)
	}
	return "操作未完成"
}

// DeleteUser 删除某用户的所有宿主会话（密码重置后调用）。
func (s *hostSessionStore) DeleteUser(userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, session := range s.byID {
		if session.UserID == userID {
			delete(s.byID, id)
		}
	}
}
