package login_test

// 步骤 66 真实服务集成测试：临时 SQLite + 真实 authn/session/registration/profile/
// avatar/emailchange/passwordreset/reauth；邮件只用本地捕获器，不联网、不监听端口。

import (
	"bytes"
	"context"
	"image"
	"image/color"
	"image/png"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	appslist "github.com/kagurazakayashi/EvernightLogin/internal/app/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	authnsqlite "github.com/kagurazakayashi/EvernightLogin/internal/authn/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/avatar"
	avatarsqlite "github.com/kagurazakayashi/EvernightLogin/internal/avatar/sqlite"
	bootstrapsqlite "github.com/kagurazakayashi/EvernightLogin/internal/bootstrap/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/credential"
	credentialsqlite "github.com/kagurazakayashi/EvernightLogin/internal/credential/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/emailchange"
	emailchangesqlite "github.com/kagurazakayashi/EvernightLogin/internal/emailchange/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	"github.com/kagurazakayashi/EvernightLogin/internal/pagecsrf"
	"github.com/kagurazakayashi/EvernightLogin/internal/passwordreset"
	passwordresetsqlite "github.com/kagurazakayashi/EvernightLogin/internal/passwordreset/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	policysqlite "github.com/kagurazakayashi/EvernightLogin/internal/policy/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/profile"
	profilesqlite "github.com/kagurazakayashi/EvernightLogin/internal/profile/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	reauthsqlite "github.com/kagurazakayashi/EvernightLogin/internal/reauth/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/registration"
	registrationsqlite "github.com/kagurazakayashi/EvernightLogin/internal/registration/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	sessionsqlite "github.com/kagurazakayashi/EvernightLogin/internal/session/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/uiaccountadapter"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

type accountIntegrationEnv struct {
	t         *testing.T
	ui        http.Handler
	sessions  *session.Service
	authn     *authn.Service
	profile   *profile.Service
	emailMail *captureEmailChangeMail
	nowFunc   func() time.Time
}

type captureEmailChangeMail struct {
	verification emailchange.VerificationEmail
	notice       emailchange.SecurityNoticeEmail
}

func (c *captureEmailChangeMail) SendVerification(_ context.Context,
	message emailchange.VerificationEmail) error {
	c.verification = message
	return nil
}

func (c *captureEmailChangeMail) SendSecurityNotice(_ context.Context,
	message emailchange.SecurityNoticeEmail) error {
	c.notice = message
	return nil
}

// authnPasswordVerifier 用真实 authn 服务完成 reauth 的密码验证。
type authnPasswordVerifier struct{ authn *authn.Service }

func (v authnPasswordVerifier) VerifyPassword(ctx context.Context,
	request reauth.PasswordVerifyRequest) (reauth.PasswordVerifyResult, error) {
	result, err := v.authn.Authenticate(ctx, authn.AuthenticateRequest{
		Identifier: request.Username, Password: request.Password, RequestID: request.RequestID})
	if err != nil {
		return reauth.PasswordVerifyResult{}, err
	}
	return reauth.PasswordVerifyResult{UserID: result.UserID,
		CompletedAt: result.CompletedAt, Complete: !result.Restricted &&
			len(result.RequiredSteps) == 0}, nil
}

// selfAppAuthorizer 允许用户读取/更新自己的成员资料；管理动作仅系统身份。
type selfAppAuthorizer struct{}

// Authorize 是测试装配：允许适配器使用的本人 Caller 执行成员资料读/写；
// 生产必须由宿主注入真实应用权限引擎。
func (selfAppAuthorizer) Authorize(context.Context, app.Caller, app.Action, string) error {
	return nil
}

func (selfAppAuthorizer) ApplicationScope(_ context.Context,
	_ app.Caller) (bool, []string, error) {
	return true, nil, nil
}

func newAccountIntegrationEnv(t *testing.T) *accountIntegrationEnv {
	t.Helper()
	ctx := context.Background()
	storage, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(
		filepath.Join(t.TempDir(), "account-pages.db")))
	if err != nil {
		t.Fatalf("打开数据库: %v", err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	list, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移: %v", err)
	}
	if _, err := storage.Migrate(ctx, list); err != nil {
		t.Fatalf("执行迁移: %v", err)
	}
	auditStore, err := auditsqlite.New(storage)
	if err != nil {
		t.Fatalf("审计存储: %v", err)
	}
	now := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)
	nowFunc := func() time.Time { return now }
	recorder, err := audit.New(auditStore, audit.Options{Now: nowFunc,
		Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("审计: %v", err)
	}
	keyring, err := secrets.GenerateKeyring("k1", now)
	if err != nil {
		t.Fatalf("密钥环: %v", err)
	}
	sessionStore, err := sessionsqlite.New(storage)
	if err != nil {
		t.Fatalf("会话存储: %v", err)
	}
	sessionService, err := session.New(sessionStore, session.Options{
		AllowLegacyWithoutSensitive: true, Store: sessionStore, Audit: recorder,
		Keyring: keyring, IdleTimeout: 10 * time.Minute, AbsoluteTimeout: 2 * time.Hour,
		Now: nowFunc, Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("会话服务: %v", err)
	}
	authnStore, err := authnsqlite.New(storage)
	if err != nil {
		t.Fatalf("认证存储: %v", err)
	}
	bootstrapStore, err := bootstrapsqlite.New(storage)
	if err != nil {
		t.Fatalf("初始化存储: %v", err)
	}
	authnService, err := authn.New(authn.Options{Store: authnStore, Audit: recorder,
		RootInitialization: bootstrapStore, AllowLegacyWithoutSensitive: true,
		Now: nowFunc, Logger: testDiscardLogger(),
		Params: authn.Params{MemoryKiB: 8192, Iterations: 1, Parallelism: 1,
			SaltLength: 16, KeyLength: 32},
		Sleep: func(context.Context, time.Duration) error { return nil }})
	if err != nil {
		t.Fatalf("认证服务: %v", err)
	}
	credentialStore, err := credentialsqlite.New(storage)
	if err != nil {
		t.Fatalf("凭证存储: %v", err)
	}
	credentialService, err := credential.New(credentialStore, credential.Options{
		Keyring: keyring, Now: nowFunc})
	if err != nil {
		t.Fatalf("凭证服务: %v", err)
	}
	registrationStore, err := registrationsqlite.New(storage)
	if err != nil {
		t.Fatalf("注册存储: %v", err)
	}
	registrationService, err := registration.New(registration.Options{
		Store: registrationStore, Audit: recorder, Credentials: credentialService,
		Mailer: &captureRegistrationMail{}, VerificationURLBase: testPageOrigin + "/email/verify",
		Enabled: true, VerificationTTL: time.Hour, ResendCooldown: time.Minute,
		AppName: "EvernightLogin", Now: nowFunc, Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("注册服务: %v", err)
	}
	// 真实 reauth 服务（policy + password verifier + 存储）。
	policyStore, err := policysqlite.New(storage)
	if err != nil {
		t.Fatalf("策略存储: %v", err)
	}
	policyService, err := policy.New(policy.Options{Store: policyStore, Audit: recorder,
		AvailableStrengths: []policy.Strength{policy.StrengthPassword}, Now: nowFunc,
		Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("策略服务: %v", err)
	}
	reauthStore, err := reauthsqlite.New(storage)
	if err != nil {
		t.Fatalf("reauth 存储: %v", err)
	}
	reauthService, err := reauth.New(reauth.Options{Store: reauthStore, Audit: recorder,
		Policy: policyService, Passwords: authnPasswordVerifier{authn: authnService},
		AvailableStrengths: []policy.Strength{policy.StrengthPassword},
		Now:                nowFunc, Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("reauth 服务: %v", err)
	}
	profileStore, err := profilesqlite.New(storage)
	if err != nil {
		t.Fatalf("资料存储: %v", err)
	}
	profileService, err := profile.New(profile.Options{Store: profileStore, Audit: recorder,
		ReauthVerifier: uiaccountadapter.ProfileSignalReauthVerifier{Now: nowFunc},
		Sensitive:      reauthService, Now: nowFunc, Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("资料服务: %v", err)
	}
	avatarStore, err := avatarsqlite.New(storage)
	if err != nil {
		t.Fatalf("头像存储: %v", err)
	}
	avatarStorage, err := avatar.NewLocalStorage(filepath.Join(t.TempDir(), "avatars"))
	if err != nil {
		t.Fatalf("头像文件存储: %v", err)
	}
	avatarService, err := avatar.New(avatar.Options{Store: avatarStore,
		Storage: avatarStorage, Audit: recorder, Now: nowFunc, Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("头像服务: %v", err)
	}
	appStore, err := appslist.New(storage)
	if err != nil {
		t.Fatalf("应用存储: %v", err)
	}
	appService, err := app.New(app.Options{Store: appStore, Audit: recorder,
		Authorizer: selfAppAuthorizer{}, Transfers: allowGuard{}, Now: nowFunc,
		Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("应用服务: %v", err)
	}
	emailMail := &captureEmailChangeMail{}
	emailChangeStore, err := emailchangesqlite.New(storage)
	if err != nil {
		t.Fatalf("邮箱变更存储: %v", err)
	}
	emailChangeService, err := emailchange.New(emailchange.Options{
		Store: emailChangeStore, Audit: recorder, Credentials: credentialService,
		ReauthVerifier: uiaccountadapter.EmailSignalReauthVerifier{Now: nowFunc},
		Sensitive:      reauthService, Mailer: emailMail,
		VerificationURLBase: testPageOrigin + "/email/change/verify",
		SupportURL:          testPageOrigin + "/support", AppName: "EvernightLogin",
		TTL: time.Hour, Now: nowFunc, Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("邮箱变更服务: %v", err)
	}
	passwordResetStore, err := passwordresetsqlite.New(storage)
	if err != nil {
		t.Fatalf("密码存储: %v", err)
	}
	passwordResetService, err := passwordreset.New(passwordreset.Options{
		Store: passwordResetStore, Audit: recorder, Credentials: credentialService,
		Passwords: authnService, Sessions: sessionService,
		Mailer:      mailer.SenderFunc(func(context.Context, mailer.Message) error { return nil }),
		FromAddress: "noreply@example.test", AppName: "EvernightLogin",
		SupportURL: testPageOrigin + "/support", ResetURLBase: testPageOrigin + "/password/reset",
		Now: nowFunc, Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("密码服务: %v", err)
	}
	adapter, err := uiaccountadapter.New(uiaccountadapter.Options{Profile: profileService,
		App: appService, Avatar: avatarService, EmailChange: emailChangeService,
		Passwords: passwordResetService, Reauth: reauthService, Sessions: sessionService,
		Now: nowFunc, Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("账户适配器: %v", err)
	}
	tokens, err := pagecsrf.New(pagecsrf.Options{Keyring: keyring, Now: nowFunc})
	if err != nil {
		t.Fatalf("页面令牌: %v", err)
	}
	ui, err := login.NewWebUI(login.WebUIOptions{
		Session: pageSessions{service: sessionService}, FormTokens: tokens,
		PageAccount: &login.UIPageAccountOptions{Backend: adapter},
		Now:         nowFunc, Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("页面框架: %v", err)
	}
	// 通过真实注册服务创建用户。
	if _, err := registrationService.Register(ctx, registration.RegisterRequest{
		Username: "alice", Password: "CorrectHorseBattery1!", RequestID: "req_seed"}); err != nil {
		t.Fatalf("创建账户: %v", err)
	}
	return &accountIntegrationEnv{t: t, ui: ui, sessions: sessionService,
		authn: authnService, profile: profileService, emailMail: emailMail, nowFunc: nowFunc}
}

func testDiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

// loginCookie 真实登录并返回会话 Cookie 与用户 ID。
func (e *accountIntegrationEnv) loginCookie() ([]*http.Cookie, string) {
	e.t.Helper()
	result, err := e.authn.Authenticate(context.Background(), authn.AuthenticateRequest{
		Identifier: "alice", Password: "CorrectHorseBattery1!", RequestID: "req_login"})
	if err != nil {
		e.t.Fatalf("登录认证: %v", err)
	}
	issued, err := e.sessions.Login(context.Background(), session.LoginRequest{Result: result})
	if err != nil {
		e.t.Fatalf("签发会话: %v", err)
	}
	cookie, err := e.sessions.NewCookie(issued)
	if err != nil {
		e.t.Fatalf("会话 Cookie: %v", err)
	}
	return []*http.Cookie{cookie}, result.UserID
}

// request 执行页面请求。
func (e *accountIntegrationEnv) request(method, target string, body []byte,
	contentType string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	e.t.Helper()
	request := httptest.NewRequest(method, testPageOrigin+target, bytes.NewReader(body))
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	e.ui.ServeHTTP(recorder, request)
	return recorder
}

// form 执行 URL-encoded POST。
func (e *accountIntegrationEnv) form(target string, values url.Values,
	cookies []*http.Cookie) *httptest.ResponseRecorder {
	return e.request(http.MethodPost, target, []byte(values.Encode()),
		"application/x-www-form-urlencoded", cookies)
}

// page 获取页面并返回正文与页面 CSRF 令牌。
func (e *accountIntegrationEnv) page(target string, cookies []*http.Cookie) (string, string) {
	e.t.Helper()
	response := e.request(http.MethodGet, target, nil, "", cookies)
	if response.Code != http.StatusOK {
		e.t.Fatalf("GET %s = %d", target, response.Code)
	}
	return response.Body.String(), extractPageToken(e.t, response.Body.String())
}

// ===== 真实服务用例 =====

func TestAccountIntegrationProfileUpdateAndConflict(t *testing.T) {
	env := newAccountIntegrationEnv(t)
	cookies, userID := env.loginCookie()
	body, token := env.page("/account/profile", cookies)
	if !strings.Contains(body, userID) || !strings.Contains(body, "alice") {
		t.Fatalf("资料页缺少稳定 ID/用户名")
	}
	saved := env.form("/account/profile", url.Values{"csrf_token": {token},
		"row_version": {"1"}, "nickname": {"<b>Alice</b>"}, "biography": {"bio"},
		"language": {"zh-CN"}, "timezone": {"Asia/Shanghai"}, "phone": {""}}, cookies)
	if saved.Code != http.StatusSeeOther {
		t.Fatalf("资料保存 = %d body=%.300s", saved.Code, saved.Body.String())
	}
	profile, err := env.profile.GetProfile(context.Background(),
		mustProfileCaller(t, userID), userID)
	if err != nil || profile.Nickname != "<b>Alice</b>" {
		t.Fatalf("资料未更新: %+v err=%v", profile, err)
	}
	// 旧行版本 → CONFLICT，页面提示重新读取，不覆盖。
	_, token2 := env.page("/account/profile", cookies)
	conflict := env.form("/account/profile", url.Values{"csrf_token": {token2},
		"row_version": {"1"}, "nickname": {"Old"}}, cookies)
	if conflict.Code != http.StatusBadRequest ||
		!strings.Contains(conflict.Body.String(), "重新读取") {
		t.Fatalf("版本冲突 = %d", conflict.Code)
	}
}

func TestAccountIntegrationUsernameReauth(t *testing.T) {
	env := newAccountIntegrationEnv(t)
	cookies, userID := env.loginCookie()
	_, token := env.page("/account/profile/username", cookies)
	wrong := env.form("/account/profile/username", url.Values{"csrf_token": {token},
		"row_version": {"1"}, "new_username": {"alice2"}, "current_password": {"wrong"}}, cookies)
	if wrong.Code != http.StatusBadRequest ||
		!strings.Contains(wrong.Body.String(), "验证当前身份") {
		t.Fatalf("错误密码更名 = %d", wrong.Code)
	}
	_, token2 := env.page("/account/profile/username", cookies)
	ok := env.form("/account/profile/username", url.Values{"csrf_token": {token2},
		"row_version": {"1"}, "new_username": {"alice2"},
		"current_password": {"CorrectHorseBattery1!"}}, cookies)
	if ok.Code != http.StatusOK || !strings.Contains(ok.Body.String(), "用户名已更新") {
		t.Fatalf("真实更名 = %d err=%q", ok.Code, errorSummary(ok.Body.String()))
	}
	profile, err := env.profile.GetProfile(context.Background(),
		mustProfileCaller(t, userID), userID)
	if err != nil || profile.Username != "alice2" {
		t.Fatalf("更名未生效: %+v err=%v", profile, err)
	}
}

func TestAccountIntegrationAvatarUpload(t *testing.T) {
	env := newAccountIntegrationEnv(t)
	cookies, _ := env.loginCookie()
	pngData := makePNG(t)
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	_ = writer.WriteField("csrf_token", "session-csrf")
	_ = writer.WriteField("row_version", "1")
	part, err := writer.CreatePart(textproto.MIMEHeader{
		"Content-Disposition": {`form-data; name="avatar"; filename="avatar.png"`},
		"Content-Type":        {"image/png"}})
	if err != nil {
		t.Fatalf("multipart: %v", err)
	}
	_, _ = part.Write(pngData)
	_ = writer.Close()
	upload := env.request(http.MethodPost, "/account/profile/avatar", body.Bytes(),
		writer.FormDataContentType(), cookies)
	if upload.Code != http.StatusSeeOther {
		t.Fatalf("头像上传 = %d err=%q", upload.Code, errorSummary(upload.Body.String()))
	}
	imageResponse := env.request(http.MethodGet, "/account/profile/avatar/image", nil, "", cookies)
	if imageResponse.Code != http.StatusOK ||
		imageResponse.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("头像读取 = %d %v", imageResponse.Code, imageResponse.Header())
	}
	if !bytes.HasPrefix(imageResponse.Body.Bytes(), []byte("\x89PNG")) {
		t.Fatal("头像字节应由后端重编码为 PNG")
	}
	// SVG 不受支持。
	var svg bytes.Buffer
	svgWriter := multipart.NewWriter(&svg)
	_ = svgWriter.WriteField("csrf_token", "session-csrf")
	_ = svgWriter.WriteField("row_version", "2")
	svgPart, _ := svgWriter.CreateFormFile("avatar", "evil.svg")
	_, _ = svgPart.Write([]byte(`<svg xmlns="http://www.w3.org/2000/svg"></svg>`))
	_ = svgWriter.Close()
	rejected := env.request(http.MethodPost, "/account/profile/avatar", svg.Bytes(),
		svgWriter.FormDataContentType(), cookies)
	if rejected.Code != http.StatusBadRequest {
		t.Fatalf("SVG 上传 = %d，期望 400", rejected.Code)
	}
}

func TestAccountIntegrationEmailChange(t *testing.T) {
	env := newAccountIntegrationEnv(t)
	cookies, _ := env.loginCookie()
	_, token := env.page("/account/profile/email", cookies)
	requested := env.form("/account/profile/email", url.Values{"csrf_token": {token},
		"new_email":        {"newmail@example.test"},
		"current_password": {"CorrectHorseBattery1!"}}, cookies)
	if requested.Code != http.StatusOK || !strings.Contains(requested.Body.String(), "验证邮件已交给发送方") {
		t.Fatalf("邮箱申请 = %d err=%q", requested.Code, errorSummary(requested.Body.String()))
	}
	if env.emailMail.verification.VerificationURL == "" {
		t.Fatal("未捕获验证邮件入口")
	}
	parsed, err := url.Parse(env.emailMail.verification.VerificationURL)
	if err != nil {
		t.Fatalf("解析验证链接: %v", err)
	}
	query := parsed.Query()
	get := env.request(http.MethodGet, "/email/change/verify?"+query.Encode(), nil, "", nil)
	if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), "验证新邮箱") {
		t.Fatalf("验证页 GET = %d", get.Code)
	}
	verifyToken := extractPageToken(t, get.Body.String())
	post := env.form("/email/change/verify", url.Values{"csrf_token": {verifyToken},
		"rid": {query.Get("rid")}, "cid": {query.Get("cid")},
		"token": {query.Get("token")}}, nil)
	if post.Code != http.StatusOK || !strings.Contains(post.Body.String(), "新邮箱已验证并生效") {
		t.Fatalf("验证消费 = %d body=%.400s", post.Code, post.Body.String())
	}
}

func TestAccountIntegrationPasswordChange(t *testing.T) {
	env := newAccountIntegrationEnv(t)
	cookies, _ := env.loginCookie()
	_, token := env.page("/account/password", cookies)
	wrong := env.form("/account/password", url.Values{"csrf_token": {token},
		"current_password": {"WrongPassword1!"}, "new_password": {"V7#qZ!mR2@tL9$xP"},
		"password_confirm": {"V7#qZ!mR2@tL9$xP"}}, cookies)
	if wrong.Code != http.StatusBadRequest {
		t.Fatalf("错误当前密码 = %d", wrong.Code)
	}
	_, token2 := env.page("/account/password", cookies)
	ok := env.form("/account/password", url.Values{"csrf_token": {token2},
		"current_password": {"CorrectHorseBattery1!"}, "new_password": {"V7#qZ!mR2@tL9$xP"},
		"password_confirm": {"V7#qZ!mR2@tL9$xP"}}, cookies)
	if ok.Code != http.StatusSeeOther {
		t.Fatalf("真实改密 = %d err=%q", ok.Code, errorSummary(ok.Body.String()))
	}
	// 旧会话应在改密后失效。
	if _, err := env.sessions.Validate(context.Background(),
		cookies[0].Value); err == nil {
		t.Fatal("改密后旧会话仍有效")
	}
}

// ===== 辅助 =====

func mustProfileCaller(t *testing.T, userID string) profile.Caller {
	t.Helper()
	caller, err := profile.UserCaller(userID)
	if err != nil {
		t.Fatalf("资料 Caller: %v", err)
	}
	return caller
}

// makePNG 生成 8x8 PNG。
func makePNG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 8, 8))
	for y := 0; y < 8; y++ {
		for x := 0; x < 8; x++ {
			img.Set(x, y, color.RGBA{R: 10, G: 20, B: 30, A: 255})
		}
	}
	var buffer bytes.Buffer
	if err := png.Encode(&buffer, img); err != nil {
		t.Fatalf("生成 PNG: %v", err)
	}
	return buffer.Bytes()
}

// errorSummary 从页面中提取错误横幅文本（测试诊断用）。
func errorSummary(body string) string {
	match := regexp.MustCompile(`ln-banner--error[^>]*>\s*<p>([^<]*)`).FindStringSubmatch(body)
	if len(match) == 2 {
		return match[1]
	}
	return "(no error banner)"
}
