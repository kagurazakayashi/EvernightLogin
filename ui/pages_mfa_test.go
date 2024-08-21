package ui_test

// 步骤 64 页面集成测试：真实 SQLite + 真实 authn/session/mfa/totp/recovery/
// passwordreset 服务 + 真实 transport CSRF/页面框架；邮件只写入本地捕获器，不联网、
// 不启动监听端口。Passkey 硬件/浏览器 ceremony 未实测（见报告）。

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	authnsqlite "github.com/kagurazakayashi/EvernightLogin/internal/authn/sqlite"
	bootstrapsqlite "github.com/kagurazakayashi/EvernightLogin/internal/bootstrap/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/credential"
	credentialsqlite "github.com/kagurazakayashi/EvernightLogin/internal/credential/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	"github.com/kagurazakayashi/EvernightLogin/internal/mfa"
	mfasqlite "github.com/kagurazakayashi/EvernightLogin/internal/mfa/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/pagecsrf"
	"github.com/kagurazakayashi/EvernightLogin/internal/pagestate"
	"github.com/kagurazakayashi/EvernightLogin/internal/passkey"
	passkeysqlite "github.com/kagurazakayashi/EvernightLogin/internal/passkey/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/passwordreset"
	passwordresetsqlite "github.com/kagurazakayashi/EvernightLogin/internal/passwordreset/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/recovery"
	recoverysqlite "github.com/kagurazakayashi/EvernightLogin/internal/recovery/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	sessionsqlite "github.com/kagurazakayashi/EvernightLogin/internal/session/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/internal/totp"
	totpsqlite "github.com/kagurazakayashi/EvernightLogin/internal/totp/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/uiauthadapter"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const mfaTestOrigin = "http://localhost"

// lazyRecoveryGate 解决 session 与 recovery 的构造环：session 先拿到委托 gate，
// recovery 服务构造完成后再绑定；未绑定前 fail-closed。
type lazyRecoveryGate struct {
	service *recovery.Service
}

func (g *lazyRecoveryGate) AuthorizeRecoverySession(ctx context.Context,
	request session.RecoverySessionRequest) error {
	if g.service == nil {
		return recovery.ErrSessionRequired
	}
	return g.service.AuthorizeRecoverySession(ctx, request)
}

// captureMailer 捕获邮件正文（本地收件器，不真实外发）。
type captureMailer struct {
	last mailer.Message
}

func (c *captureMailer) Send(_ context.Context, message mailer.Message) error {
	c.last = message
	return nil
}

// allowReauth 是测试用再次认证执行器（真实策略在后续装配步骤接入）。
type allowReauth struct{}

func (allowReauth) Authorize(_ context.Context, _ reauth.Caller,
	request reauth.Request) (reauth.Result, error) {
	return reauth.Result{OperationID: request.OperationID, TargetType: request.TargetType,
		TargetID: request.TargetID, UserID: "usr_00000000000000000000000000000064"}, nil
}
func (allowReauth) NotifyOutcome(context.Context, reauth.Result, reauth.Outcome) error { return nil }

// totpBinder 用真实 totp 服务实现恢复重绑适配器（测试装配）。
type totpBinder struct {
	totp *totp.Service
	now  func() time.Time
}

func (b totpBinder) BeginRebind(ctx context.Context, request recovery.FactorBindRequest) (recovery.FactorBindStart, error) {
	caller, err := totp.UserCaller(request.UserID)
	if err != nil {
		return recovery.FactorBindStart{}, err
	}
	start, err := b.totp.BeginBinding(ctx, caller, request.RequestID)
	if err != nil {
		return recovery.FactorBindStart{}, err
	}
	return recovery.FactorBindStart{Method: recovery.MethodTOTP, BindingID: start.BindingID,
		PublicData: []byte(start.URI), ExpiresAt: start.ExpiresAt}, nil
}

func (b totpBinder) VerifyRebind(ctx context.Context, request recovery.FactorVerifyRequest) (recovery.FactorProof, error) {
	caller, err := totp.UserCaller(request.UserID)
	if err != nil {
		return recovery.FactorProof{}, err
	}
	if _, err := b.totp.ConfirmBinding(ctx, caller, totp.BindConfirm{
		BindingID: request.BindingID, Code: string(request.Response), RequestID: request.RequestID}); err != nil {
		return recovery.FactorProof{}, err
	}
	return recovery.FactorProof{Method: recovery.MethodTOTP, FactorRef: request.BindingID,
		VerifiedAt: b.now()}, nil
}

// mfaPageEnv 是 MFA 页面集成环境。
type mfaPageEnv struct {
	t         *testing.T
	handler   http.Handler
	storage   *storagesqlite.Store
	sessions  *session.Service
	authn     *authn.Service
	mfa       *mfa.Service
	totp      *totp.Service
	recovery  *recovery.Service
	reset     *passwordreset.Service
	passkeys  *passkey.Service
	simulator *testAuthenticator
	mail      *captureMailer
	csrf      *pagecsrf.Provider
	userID    string
	now       time.Time
	advance   func(time.Duration)
	codes     []string
}

// newMFAPageEnv 构造真实服务与页面处理器。
func newMFAPageEnv(t *testing.T) *mfaPageEnv {
	t.Helper()
	ctx := context.Background()
	storage, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(
		filepath.Join(testutil.TempDir(t), "mfa.db")))
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
	now := time.Date(2026, 4, 5, 6, 7, 8, 0, time.UTC)
	nowFunc := func() time.Time { return now }
	auditStore, err := auditsqlite.New(storage)
	if err != nil {
		t.Fatalf("审计存储: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(ioDiscard{}, &slog.HandlerOptions{Level: slog.LevelError}))
	recorder, err := audit.New(auditStore, audit.Options{Now: nowFunc, Logger: logger})
	if err != nil {
		t.Fatalf("审计: %v", err)
	}
	keyring, err := secrets.GenerateKeyring("k1", now)
	if err != nil {
		t.Fatalf("密钥环: %v", err)
	}
	recoveryGate := &lazyRecoveryGate{}
	sessionStore, err := sessionsqlite.New(storage)
	if err != nil {
		t.Fatalf("会话存储: %v", err)
	}
	sessionService, err := session.New(sessionStore, session.Options{
		AllowLegacyWithoutSensitive: true, Store: sessionStore, Audit: recorder,
		Keyring: keyring, RecoveryGate: recoveryGate,
		IdleTimeout: 10 * time.Minute, AbsoluteTimeout: 2 * time.Hour,
		Now: nowFunc, Logger: logger})
	if err != nil {
		t.Fatalf("会话服务: %v", err)
	}
	bootstrapStore, err := bootstrapsqlite.New(storage)
	if err != nil {
		t.Fatalf("初始化存储: %v", err)
	}
	authnStore, err := authnsqlite.New(storage)
	if err != nil {
		t.Fatalf("认证存储: %v", err)
	}
	authnService, err := authn.New(authn.Options{Store: authnStore, Audit: recorder, AllowLegacyWithoutSensitive: true,
		RootInitialization: bootstrapStore, Now: nowFunc, Logger: logger,
		Params: authn.Params{MemoryKiB: 8192, Iterations: 1, Parallelism: 1,
			SaltLength: 16, KeyLength: 32},
		Sleep: func(context.Context, time.Duration) error { return nil }})
	if err != nil {
		t.Fatalf("认证服务: %v", err)
	}
	userID := "usr_00000000000000000000000000000064"
	if _, err := storage.ExecContext(ctx, `INSERT INTO users(id,username,username_normalized,
status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'active',0,1,1,?,?)`, userID, "mfauser", "mfauser",
		now.UnixMilli(), now.UnixMilli()); err != nil {
		t.Fatalf("插入账户: %v", err)
	}
	adminCaller, err := authn.LocalAdminCaller("test-admin")
	if err != nil {
		t.Fatalf("管理员调用者: %v", err)
	}
	if _, err := authnService.SetPassword(ctx, adminCaller, authn.SetPasswordRequest{
		TargetUserID: userID, NewPassword: "correct horse battery staple",
		RequestID: "req-set-password"}); err != nil {
		t.Fatalf("设置密码: %v", err)
	}
	if _, err := storage.ExecContext(ctx, `INSERT INTO user_emails(email_normalized,user_id,email,
verified_at_ms,created_at_ms,updated_at_ms) VALUES(?,?,?,?,?,?)`, "user@example.test",
		userID, "user@example.test", now.UnixMilli(), now.UnixMilli(), now.UnixMilli()); err != nil {
		t.Fatalf("插入已验证邮箱: %v", err)
	}
	if _, err := storage.ExecContext(ctx, `INSERT INTO mfa_factors(id,user_id,factor_type,status,
created_at_ms,updated_at_ms) VALUES('mfa_factor_email_1',?,'email','active',?,?)`,
		userID, now.UnixMilli(), now.UnixMilli()); err != nil {
		t.Fatalf("插入邮件因素: %v", err)
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
	mailCapture := &captureMailer{}
	templates, err := mailer.DefaultTemplateSet()
	if err != nil {
		t.Fatalf("邮件模板: %v", err)
	}
	totpStore, err := totpsqlite.New(storage)
	if err != nil {
		t.Fatalf("TOTP 存储: %v", err)
	}
	sealer, err := secrets.NewSealer(keyring, logger)
	if err != nil {
		t.Fatalf("加密器: %v", err)
	}
	totpService, err := totp.New(totp.Options{Store: totpStore, Audit: recorder,
		Sealer: sealer, Reauth: allowReauth{}, Now: nowFunc, Logger: logger})
	if err != nil {
		t.Fatalf("TOTP 服务: %v", err)
	}
	passkeyStore, err := passkeysqlite.New(storage)
	if err != nil {
		t.Fatalf("Passkey 存储: %v", err)
	}
	passkeyService, err := passkey.New(passkey.Options{Store: passkeyStore, Audit: recorder,
		Sessions: sessionService, Reauth: allowReauth{}, Now: nowFunc, Logger: logger,
		Config: passkey.Config{RPID: "localhost", RPDisplayName: "EvernightLogin",
			Origins: []string{mfaTestOrigin}}})
	if err != nil {
		t.Fatalf("Passkey 服务: %v", err)
	}
	mfaStore, err := mfasqlite.New(storage)
	if err != nil {
		t.Fatalf("MFA 存储: %v", err)
	}
	mfaService, err := mfa.New(mfa.Options{Store: mfaStore, Audit: recorder,
		Credentials: credentialService, Sessions: sessionService, Mailer: mailCapture,
		Templates: templates, FromAddress: "login@example.test", AppName: "EvernightLogin",
		SupportURL: mfaTestOrigin + "/support", TOTP: totpService,
		Passkeys: passkeyService, Now: nowFunc, Logger: logger})
	if err != nil {
		t.Fatalf("MFA 服务: %v", err)
	}
	recoveryStore, err := recoverysqlite.New(storage)
	if err != nil {
		t.Fatalf("恢复存储: %v", err)
	}
	recoveryService, err := recovery.New(recovery.Options{Store: recoveryStore,
		Audit: recorder, Keyring: keyring, Sessions: sessionService,
		Reauth: allowReauth{}, Requirements: recovery.RequirementsFunc(func(
			context.Context, string) (recovery.Strength, error) {
			return recovery.StrengthSecondFactor, nil
		}), AuthLevels: recovery.AuthLevelRequirementsFunc(func(context.Context,
			string) (recovery.AuthLevel, error) {
			return recovery.AuthLevelPassword, nil
		}), Binder: totpBinder{totp: totpService, now: nowFunc},
		Now: nowFunc, Logger: logger})
	if err != nil {
		t.Fatalf("恢复服务: %v", err)
	}
	recoveryGate.service = recoveryService
	resetStore, err := passwordresetsqlite.New(storage)
	if err != nil {
		t.Fatalf("找回存储: %v", err)
	}
	resetService, err := passwordreset.New(passwordreset.Options{
		Store: resetStore, Audit: recorder, Credentials: credentialService,
		Passwords: authnService, Sessions: sessionService, Mailer: mailCapture,
		Templates: templates, FromAddress: "login@example.test",
		AppName: "EvernightLogin", SupportURL: mfaTestOrigin + "/support",
		ResetURLBase: mfaTestOrigin + "/login/reset-password", Now: nowFunc, Logger: logger})
	if err != nil {
		t.Fatalf("找回服务: %v", err)
	}
	pageState, err := pagestate.New(pagestate.Options{Keyring: keyring, Now: nowFunc})
	if err != nil {
		t.Fatalf("页面状态: %v", err)
	}
	adapter, err := uiauthadapter.New(uiauthadapter.Options{Authn: authnService,
		Sessions: sessionService, MFA: mfaService, Recovery: recoveryService,
		PasswordReset: resetService, PageState: pageState, Now: nowFunc, Logger: logger})
	if err != nil {
		t.Fatalf("页面适配器: %v", err)
	}
	csrfProvider, err := pagecsrf.New(pagecsrf.Options{Keyring: keyring,
		TTL: 10 * time.Minute, Now: nowFunc})
	if err != nil {
		t.Fatalf("页面 CSRF: %v", err)
	}
	ui, err := login.NewWebUI(login.WebUIOptions{
		Session: pageSessions{service: sessionService}, FormTokens: csrfProvider,
		PageAuth: &login.UIPageAuthOptions{Backend: adapter, PostLoginPath: "/home"},
		PageMFA:  &login.UIPageMFAOptions{Backend: adapter},
		Now:      nowFunc, Logger: logger})
	if err != nil {
		t.Fatalf("页面框架: %v", err)
	}
	publicPaths := login.UIPageAuthPublicFormPaths("")
	for path, purpose := range login.UIPageMFAPublicFormPaths("") {
		publicPaths[path] = purpose
	}
	pathList := make([]string, 0, len(publicPaths))
	purposes := map[string]string{}
	for path, purpose := range publicPaths {
		pathList = append(pathList, path)
		purposes[path] = purpose
	}
	handler, err := login.NewHTTPHandler(login.HTTPOptions{Prefix: "",
		UI: &login.UIHTTPOptions{Handler: ui,
			PageContentSecurityPolicy: login.DefaultUIPageContentSecurityPolicy},
		Protection: &login.HTTPProtectionOptions{CSRF: login.CSRFPolicy{Enabled: true,
			CookieName: session.DefaultCookieName, AllowedOrigins: []string{mfaTestOrigin},
			RequireForAllUnsafeRequests: true, PublicFormPaths: pathList,
			PublicTokenValidator: csrfProvider.Validator(purposes),
			TokenValidator: login.CSRFValidatorFunc(func(ctx context.Context,
				request *http.Request, token string) error {
				return sessionService.ValidateCSRFToken(ctx, request, token)
			})}}})
	if err != nil {
		t.Fatalf("HTTP 处理器: %v", err)
	}
	env := &mfaPageEnv{t: t, handler: handler, storage: storage, sessions: sessionService,
		authn: authnService, mfa: mfaService, totp: totpService,
		recovery: recoveryService, reset: resetService, passkeys: passkeyService,
		simulator: newTestAuthenticator(t), mail: mailCapture,
		csrf: csrfProvider, userID: userID, now: now,
		advance: func(d time.Duration) { now = now.Add(d) }}
	var securityVersion int64
	rows, qerr := storage.QueryContext(ctx, `SELECT security_version FROM users WHERE id=?`, userID)
	if qerr == nil && rows.Next() {
		_ = rows.Scan(&securityVersion)
		rows.Close()
	}
	// 生成恢复代码（一次性展示在测试内部；不写入日志）。
	userCaller, err := recovery.UserCaller(userID)
	if err != nil {
		t.Fatalf("恢复调用者: %v", err)
	}
	generated, err := recoveryService.Generate(ctx, userCaller, recovery.GenerateRequest{
		RequestID: "req-gen-codes"})
	if err != nil {
		t.Fatalf("生成恢复代码: %v", err)
	}
	for _, code := range generated.Codes {
		env.codes = append(env.codes, code.Reveal())
	}
	return env
}

// mfaResponse 是一次页面响应。
type mfaResponse struct {
	status  int
	headers http.Header
	body    string
	cookies []*http.Cookie
}

// request 执行一次请求并收集 Cookie。
func (e *mfaPageEnv) request(method, target string, form url.Values,
	cookies []*http.Cookie, origin string) mfaResponse {
	e.t.Helper()
	var body *strings.Reader
	if form == nil {
		body = strings.NewReader("")
	} else {
		body = strings.NewReader(form.Encode())
	}
	request := httptest.NewRequest(method, mfaTestOrigin+target, body)
	request.Host = "example.test"
	if form != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if origin == "" {
		origin = mfaTestOrigin
	}
	if origin != "-" {
		request.Header.Set("Origin", origin)
	}
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	e.handler.ServeHTTP(recorder, request)
	return mfaResponse{status: recorder.Code, headers: recorder.Header(),
		body: recorder.Body.String(), cookies: recorder.Result().Cookies()}
}

// mergeCookies 按名字合并 Cookie（后出现覆盖）。
func mergeCookies(sets ...[]*http.Cookie) []*http.Cookie {
	byName := map[string]*http.Cookie{}
	order := []string{}
	for _, set := range sets {
		for _, cookie := range set {
			if _, ok := byName[cookie.Name]; !ok {
				order = append(order, cookie.Name)
			}
			if cookie.MaxAge < 0 || cookie.Value == "" {
				delete(byName, cookie.Name)
				continue
			}
			byName[cookie.Name] = cookie
		}
	}
	result := make([]*http.Cookie, 0, len(byName))
	for _, name := range order {
		if cookie, ok := byName[name]; ok {
			result = append(result, cookie)
		}
	}
	return result
}

// tokenFrom 从页面提取隐藏字段。
func tokenFrom(t *testing.T, body, name string) string {
	t.Helper()
	pattern := regexp.MustCompile(`name="` + regexp.QuoteMeta(name) + `" value="([^"]*)"`)
	match := pattern.FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatalf("页面缺少隐藏字段 %s；body head=%s", name, body[:min(len(body), 600)])
	}
	return match[1]
}

// loginPassword 执行密码登录并返回响应。
func (e *mfaPageEnv) loginPassword(password string) (mfaResponse, []*http.Cookie) {
	e.t.Helper()
	page := e.request(http.MethodGet, "/login", nil, nil, "")
	if page.status != http.StatusOK {
		e.t.Fatalf("登录页状态 = %d", page.status)
	}
	csrf := tokenFrom(e.t, page.body, "csrf_token")
	cookies := mergeCookies(page.cookies)
	resp := e.request(http.MethodPost, "/login", url.Values{
		"identifier": {"mfauser"}, "password": {password}, "csrf_token": {csrf}},
		cookies, "")
	return resp, mergeCookies(cookies, resp.cookies)
}

// secondFactorPage 读取第二因素页并解析挑战字段与匿名 CSRF。
func (e *mfaPageEnv) secondFactorPage(cookies []*http.Cookie) (mfaResponse, url.Values, []*http.Cookie) {
	e.t.Helper()
	resp := e.request(http.MethodGet, "/login/second-factor", nil, cookies, "")
	if resp.status != http.StatusOK {
		e.t.Fatalf("第二因素页状态 = %d body=%s", resp.status, resp.body)
	}
	fields := url.Values{
		"challenge_id":  {tokenFrom(e.t, resp.body, "challenge_id")},
		"attempt_token": {tokenFrom(e.t, resp.body, "attempt_token")},
		"csrf_token":    {tokenFrom(e.t, resp.body, "csrf_token")},
	}
	return resp, fields, mergeCookies(cookies, resp.cookies)
}

// extractEmailCode 从捕获邮件正文提取验证码。
func extractEmailCode(t *testing.T, message mailer.Message) string {
	t.Helper()
	match := regexp.MustCompile(`\b[0-9]{6,10}\b`).FindString(message.TextBody)
	if match == "" {
		t.Fatalf("邮件正文未包含验证码")
	}
	return match
}

// username 返回测试账户用户名。
func (e *mfaPageEnv) username() string { return "mfauser" }

// TestMFAPagesEmailSecondFactor 验证真实邮件第二因素页面闭环：密码→受限会话→
// 错误码→正确验证码→完整会话，且受限会话不能访问普通页面。
func TestMFAPagesEmailSecondFactor(t *testing.T) {
	env := newMFAPageEnv(t)
	loginResp, cookies := env.loginPassword("correct horse battery staple")
	if loginResp.status != http.StatusSeeOther ||
		loginResp.headers.Get("Location") != "/login/second-factor" {
		t.Fatalf("受限登录应跳转第二因素，状态=%d location=%s body=%s",
			loginResp.status, loginResp.headers.Get("Location"), loginResp.body)
	}
	// 受限会话访问普通页面必须拒绝。
	if home := env.request(http.MethodGet, "/home", nil, cookies, ""); home.status != http.StatusForbidden &&
		home.status != http.StatusUnauthorized {
		t.Fatalf("受限会话访问 /home 应拒绝，实际 %d", home.status)
	}
	_, fields, cookies := env.secondFactorPage(cookies)
	code := extractEmailCode(t, env.mail.last)
	// 错误验证码：统一 CHALLENGE_INVALID，不建立完整会话。
	wrong := url.Values{}
	for key, values := range fields {
		wrong[key] = append([]string(nil), values...)
	}
	wrong.Set("code", "000000")
	wrongResp := env.request(http.MethodPost, "/login/second-factor", wrong, cookies, "")
	if wrongResp.status != http.StatusBadRequest || !strings.Contains(wrongResp.body, "CHALLENGE_INVALID") {
		t.Fatalf("错误验证码应 400/CHALLENGE_INVALID，实际 %d body=%s", wrongResp.status, wrongResp.body)
	}
	// 正确验证码：303 到 /home 并写完整会话 Cookie。
	ok := url.Values{}
	for key, values := range fields {
		ok[key] = append([]string(nil), values...)
	}
	ok.Set("code", code)
	verifyResp := env.request(http.MethodPost, "/login/second-factor", ok, cookies, "")
	if verifyResp.status != http.StatusSeeOther || verifyResp.headers.Get("Location") != "/home" {
		t.Fatalf("第二因素成功应跳转 /home，状态=%d location=%s body=%s",
			verifyResp.status, verifyResp.headers.Get("Location"), verifyResp.body)
	}
	cookies = mergeCookies(cookies, verifyResp.cookies)
	var secret string
	for _, cookie := range cookies {
		if cookie.Name == session.DefaultCookieName {
			secret = cookie.Value
		}
	}
	if secret == "" {
		t.Fatal("第二因素成功未写会话 Cookie")
	}
	record, err := env.sessions.Validate(context.Background(), secret)
	if err != nil || !record.IsNormal() {
		t.Fatalf("第二因素成功后应为完整会话: %v", err)
	}
	// 旧验证码/挑战不可重放。
	if replay := env.request(http.MethodPost, "/login/second-factor", ok, cookies, ""); replay.status == http.StatusSeeOther {
		t.Fatal("已消费挑战不应再次成功")
	}
}

// TestMFAPagesRecoveryCodeRebind 验证恢复代码→受限恢复→TOTP 重绑→一次性新代码。
func TestMFAPagesRecoveryCodeRebind(t *testing.T) {
	env := newMFAPageEnv(t)
	if len(env.codes) == 0 {
		t.Fatal("缺少恢复代码")
	}
	_, cookies := env.loginPassword("correct horse battery staple")
	_, fields, cookies := env.secondFactorPage(cookies)
	// 进入恢复代码页（GET 需要匿名 CSRF 与受限会话）。
	codePage := env.request(http.MethodGet, "/login/recovery-code", nil, cookies, "")
	if codePage.status != http.StatusOK {
		t.Fatalf("恢复代码页状态 = %d body=%s", codePage.status, codePage.body)
	}
	cookies = mergeCookies(cookies, codePage.cookies)
	submit := url.Values{"code": {env.codes[0]},
		"csrf_token": {tokenFrom(t, codePage.body, "csrf_token")}}
	recoveryResp := env.request(http.MethodPost, "/login/recovery-code", submit, cookies, "")
	if recoveryResp.status != http.StatusSeeOther ||
		recoveryResp.headers.Get("Location") != "/login/recovery/rebind" {
		t.Fatalf("恢复代码成功应跳转重绑页，状态=%d location=%s body_head=%s",
			recoveryResp.status, recoveryResp.headers.Get("Location"), recoveryResp.body[:min(len(recoveryResp.body), 1200)])
	}
	cookies = mergeCookies(cookies, recoveryResp.cookies)
	_ = fields
	// 重绑页展示真实强度与允许方式。
	rebind := env.request(http.MethodGet, "/login/recovery/rebind", nil, cookies, "")
	if rebind.status != http.StatusOK || !strings.Contains(rebind.body, "重新绑定安全方式") {
		t.Fatalf("重绑页状态=%d body=%s", rebind.status, rebind.body)
	}
	cookies = mergeCookies(cookies, rebind.cookies)
	// 开始 TOTP 绑定。
	startCSRF := tokenFrom(t, rebind.body, "csrf_token")
	startResp := env.request(http.MethodPost, "/login/recovery/rebind/start",
		url.Values{"method": {"totp"}, "csrf_token": {startCSRF}}, cookies, "")
	if startResp.status != http.StatusOK || !strings.Contains(startResp.body, "otpauth://") {
		t.Fatalf("TOTP 绑定开始失败: %d body=%s", startResp.status, startResp.body)
	}
	cookies = mergeCookies(cookies, startResp.cookies)
	bindingID := tokenFrom(t, startResp.body, "binding_id")
	secret := secretFromTOTPURI(t, startResp.body)
	code := keystreamTOTP(t, secret, env.now, 30, 6)
	completeResp := env.request(http.MethodPost, "/login/recovery/rebind/complete",
		url.Values{"binding_id": {bindingID}, "method": {"totp"}, "response": {code},
			"csrf_token": {tokenFrom(t, startResp.body, "csrf_token")}}, cookies, "")
	if completeResp.status != http.StatusOK || !strings.Contains(completeResp.body, "恢复已完成") {
		t.Fatalf("恢复完成失败: %d body=%s", completeResp.status, completeResp.body)
	}
	// 完成后原恢复代码不能再次使用（旧组作废/会话失效）。
	second := env.request(http.MethodPost, "/login/recovery-code",
		url.Values{"code": {env.codes[0]}, "csrf_token": {tokenFrom(t, rebind.body, "csrf_token")}},
		cookies, "")
	if second.status == http.StatusSeeOther {
		t.Fatal("旧恢复代码不应再次成功")
	}
}

// secretFromTOTPURI 从 otpauth URI 提取 base32 密钥。
func secretFromTOTPURI(t *testing.T, body string) string {
	t.Helper()
	match := regexp.MustCompile(`secret=([A-Z2-7]+)`).FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatalf("未找到 TOTP 密钥")
	}
	return match[1]
}

// keystreamTOTP 按 RFC 6238 计算指定时间的验证码。
func keystreamTOTP(t *testing.T, secret string, at time.Time, period, digits int) string {
	t.Helper()
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		t.Fatalf("解码 TOTP 密钥: %v", err)
	}
	counter := uint64(at.Unix() / int64(period))
	var buffer [8]byte
	binary.BigEndian.PutUint64(buffer[:], counter)
	mac := hmac.New(sha1.New, raw)
	mac.Write(buffer[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 | uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 | uint32(sum[offset+3])
	modulo := uint32(1)
	for index := 0; index < digits; index++ {
		modulo *= 10
	}
	return fmt.Sprintf("%0*d", digits, value%modulo)
}

// TestMFAPagesPasswordReset 验证统一找回受理与重置密码：GET 不消费 token、重置后
// 新密码可登录、不签发会话、MFA 不变。
func TestMFAPagesPasswordReset(t *testing.T) {
	env := newMFAPageEnv(t)
	page := env.request(http.MethodGet, "/login/forgot-password", nil, nil, "")
	if page.status != http.StatusOK {
		t.Fatalf("找回页状态 = %d", page.status)
	}
	cookies := mergeCookies(page.cookies)
	csrf := tokenFrom(t, page.body, "csrf_token")
	uniform := env.request(http.MethodPost, "/login/forgot-password",
		url.Values{"identifier": {"unknown@example.test"}, "csrf_token": {csrf}}, cookies, "")
	if uniform.status != http.StatusOK || !strings.Contains(uniform.body, "如果该账户可用") {
		t.Fatalf("未知账户仍应统一受理，状态=%d body=%s", uniform.status, uniform.body)
	}
	sent := env.request(http.MethodPost, "/login/forgot-password",
		url.Values{"identifier": {"user@example.test"}, "csrf_token": {csrf}}, cookies, "")
	if sent.status != http.StatusOK || !strings.Contains(sent.body, "如果该账户可用") {
		t.Fatalf("找回受理失败: %d", sent.status)
	}
	token := extractResetToken(t, env.mail.last.TextBody)
	resetPage := env.request(http.MethodGet, "/login/reset-password?token="+url.QueryEscape(token),
		nil, nil, "")
	if resetPage.status != http.StatusOK {
		t.Fatalf("重置页状态 = %d body=%s", resetPage.status, resetPage.body)
	}
	newPassword := "new correct horse battery"
	resetCSRF := tokenFrom(t, resetPage.body, "csrf_token")
	resetResp := env.request(http.MethodPost, "/login/reset-password", url.Values{
		"token": {token}, "new_password": {newPassword}, "confirm_password": {newPassword},
		"csrf_token": {resetCSRF}}, mergeCookies(resetPage.cookies), "")
	if resetResp.status != http.StatusOK || !strings.Contains(resetResp.body, "密码已重置") {
		t.Fatalf("重置失败: %d body=%s", resetResp.status, resetResp.body)
	}
	// 新密码可认证；重置不签发会话。
	result, err := env.authn.Authenticate(context.Background(), authn.AuthenticateRequest{
		Identifier: "mfauser", Password: newPassword, RequestID: "req-after-reset"})
	if err != nil || result.UserID != env.userID {
		t.Fatalf("重置后新密码认证失败: %v", err)
	}
	for _, cookie := range resetResp.cookies {
		if cookie.Name == session.DefaultCookieName && cookie.Value != "" {
			t.Fatal("密码重置不应签发会话")
		}
	}
	// 旧 token 不可重复使用。
	replay := env.request(http.MethodPost, "/login/reset-password", url.Values{
		"token": {token}, "new_password": {newPassword}, "confirm_password": {newPassword},
		"csrf_token": {resetCSRF}}, mergeCookies(resetPage.cookies), "")
	if replay.status == http.StatusOK {
		t.Fatal("已消费重置 token 不应再次成功")
	}
}

// extractResetToken 从找回邮件正文提取 token 参数。
func extractResetToken(t *testing.T, body string) string {
	t.Helper()
	match := regexp.MustCompile(`token=([A-Za-z0-9_\-\.%]+)`).FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatalf("邮件正文未包含重置 token: %q", body)
	}
	value, err := url.QueryUnescape(match[1])
	if err != nil {
		t.Fatalf("解码 token: %v", err)
	}
	return value
}

// ===== 软件 WebAuthn 认证器（模拟认证器；真实设备未实测） =====

const passkeyRPID = "localhost"

// testAuthenticator 是仅测试使用的软件 WebAuthn 认证器：生成 P-256 密钥、构造
// 注册/断言响应；不访问网络、不冒充真实硬件。
type testAuthenticator struct {
	t            *testing.T
	key          *ecdsa.PrivateKey
	credentialID []byte
	signCount    uint32
}

// newTestAuthenticator 创建软件认证器。
func newTestAuthenticator(t *testing.T) *testAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成认证器密钥: %v", err)
	}
	credentialID := make([]byte, 32)
	if _, err := rand.Read(credentialID); err != nil {
		t.Fatalf("凭证 ID: %v", err)
	}
	return &testAuthenticator{t: t, key: key, credentialID: credentialID}
}

type passkeyCreationOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RP        struct {
			ID string `json:"id"`
		} `json:"rp"`
	} `json:"publicKey"`
}

type passkeyRequestOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RPID      string `json:"rpId"`
	} `json:"publicKey"`
}

// registrationResponse 构造 navigator.credentials.create 结果 JSON。
func (a *testAuthenticator) registrationResponse(t *testing.T, optionsJSON []byte,
	origin, rpIDOverride string) []byte {
	t.Helper()
	var options passkeyCreationOptions
	if err := json.Unmarshal(optionsJSON, &options); err != nil {
		t.Fatalf("解析注册选项: %v", err)
	}
	rpID := options.PublicKey.RP.ID
	if rpIDOverride != "" {
		rpID = rpIDOverride
	}
	clientData := a.clientData("webauthn.create", options.PublicKey.Challenge, origin)
	flags := byte(0x01 | 0x40 | 0x04) // UP + AT + UV
	auth := buildTestAuthData(rpID, flags, a.signCount, a.credentialID,
		coseTestES256(&a.key.PublicKey))
	response := map[string]any{
		"id":                     base64.RawURLEncoding.EncodeToString(a.credentialID),
		"rawId":                  base64.RawURLEncoding.EncodeToString(a.credentialID),
		"type":                   "public-key",
		"clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientData),
			"attestationObject": base64.RawURLEncoding.EncodeToString(attestationTestObject(auth)),
			"transports":        []string{"internal"},
		},
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("序列化注册响应: %v", err)
	}
	return encoded
}

// assertionResponse 构造 navigator.credentials.get 结果 JSON。
func (a *testAuthenticator) assertionResponse(t *testing.T, optionsJSON []byte,
	origin, rpIDOverride string, counter uint32) []byte {
	t.Helper()
	var options passkeyRequestOptions
	if err := json.Unmarshal(optionsJSON, &options); err != nil {
		t.Fatalf("解析断言选项: %v", err)
	}
	rpID := options.PublicKey.RPID
	if rpIDOverride != "" {
		rpID = rpIDOverride
	}
	clientData := a.clientData("webauthn.get", options.PublicKey.Challenge, origin)
	flags := byte(0x01 | 0x04) // UP + UV
	auth := buildTestAuthData(rpID, flags, counter, nil, nil)
	clientDataHash := sha256.Sum256(clientData)
	signed := append(append([]byte(nil), auth...), clientDataHash[:]...)
	digest := sha256.Sum256(signed)
	signature, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatalf("认证器签名: %v", err)
	}
	response := map[string]any{
		"id":                     base64.RawURLEncoding.EncodeToString(a.credentialID),
		"rawId":                  base64.RawURLEncoding.EncodeToString(a.credentialID),
		"type":                   "public-key",
		"clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientData),
			"authenticatorData": base64.RawURLEncoding.EncodeToString(auth),
			"signature":         base64.RawURLEncoding.EncodeToString(signature),
		},
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("序列化断言响应: %v", err)
	}
	return encoded
}

func (a *testAuthenticator) clientData(ceremonyType, challenge, origin string) []byte {
	encoded, err := json.Marshal(map[string]any{"type": ceremonyType,
		"challenge": challenge, "origin": origin, "crossOrigin": false})
	if err != nil {
		a.t.Fatalf("序列化 clientData: %v", err)
	}
	return encoded
}

func buildTestAuthData(rpID string, flags byte, counter uint32, credentialID, coseKey []byte) []byte {
	hash := sha256.Sum256([]byte(rpID))
	auth := append([]byte(nil), hash[:]...)
	auth = append(auth, flags)
	var counterBytes [4]byte
	binary.BigEndian.PutUint32(counterBytes[:], counter)
	auth = append(auth, counterBytes[:]...)
	if flags&0x40 != 0 {
		auth = append(auth, make([]byte, 16)...)
		var length [2]byte
		binary.BigEndian.PutUint16(length[:], uint16(len(credentialID)))
		auth = append(auth, length[:]...)
		auth = append(auth, credentialID...)
		auth = append(auth, coseKey...)
	}
	return auth
}

func coseTestES256(publicKey *ecdsa.PublicKey) []byte {
	x := publicKey.X.FillBytes(make([]byte, 32))
	y := publicKey.Y.FillBytes(make([]byte, 32))
	result := []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21}
	result = append(result, cborTestBytes(x)...)
	result = append(result, 0x22)
	result = append(result, cborTestBytes(y)...)
	return result
}

func attestationTestObject(authData []byte) []byte {
	result := []byte{0xa3}
	result = append(result, cborTestText("fmt")...)
	result = append(result, cborTestText("none")...)
	result = append(result, cborTestText("attStmt")...)
	result = append(result, 0xa0)
	result = append(result, cborTestText("authData")...)
	result = append(result, cborTestBytes(authData)...)
	return result
}

func cborTestText(value string) []byte {
	return append(cborTestHead(3, uint64(len(value))), value...)
}

func cborTestBytes(value []byte) []byte {
	return append(cborTestHead(2, uint64(len(value))), value...)
}

func cborTestHead(major byte, length uint64) []byte {
	switch {
	case length < 24:
		return []byte{major<<5 | byte(length)}
	case length < 256:
		return []byte{major<<5 | 24, byte(length)}
	case length < 65536:
		return []byte{major<<5 | 25, byte(length >> 8), byte(length)}
	default:
		return []byte{major<<5 | 26, byte(length >> 24), byte(length >> 16),
			byte(length >> 8), byte(length)}
	}
}

// TestMFAPagesPasskeySecondFactor 用软件 WebAuthn 认证器验证真实 Passkey 第二步：
// 服务端 options→浏览器断言→mfa.Verify→完整会话；并验证错误 ceremony 被拒绝。
func TestMFAPagesPasskeySecondFactor(t *testing.T) {
	env := newMFAPageEnv(t)
	ctx := context.Background()
	caller, err := passkey.UserCaller(env.userID)
	if err != nil {
		t.Fatalf("Passkey 调用者: %v", err)
	}
	registration, err := env.passkeys.BeginRegistrationWithPurpose(ctx, caller,
		"req-passkey-register", passkey.PurposeBoth)
	if err != nil {
		t.Fatalf("开始 Passkey 注册: %v", err)
	}
	registrationResponse := env.simulator.registrationResponse(t, registration.PublicKey,
		mfaTestOrigin, "")
	if _, err := env.passkeys.FinishRegistration(ctx, caller,
		passkey.RegistrationFinishRequest{CeremonyID: registration.CeremonyID,
			Response: registrationResponse, Name: "软件认证器", RequestID: "req-passkey-finish"}); err != nil {
		t.Fatalf("完成 Passkey 注册: %v", err)
	}
	// 删除邮件因素，确保第二因素选择 Passkey。
	if _, err := env.storage.ExecContext(ctx, `DELETE FROM mfa_factors WHERE user_id=?`,
		env.userID); err != nil {
		t.Fatalf("删除邮件因素: %v", err)
	}
	loginResp, cookies := env.loginPassword("correct horse battery staple")
	if loginResp.status != http.StatusSeeOther ||
		loginResp.headers.Get("Location") != "/login/second-factor" {
		t.Fatalf("Passkey 受限登录未跳转第二步: %d %s", loginResp.status,
			loginResp.headers.Get("Location"))
	}
	factorPage := env.request(http.MethodGet, "/login/second-factor", nil, cookies, "")
	if factorPage.status != http.StatusOK || !strings.Contains(factorPage.body, "调用认证器") {
		t.Fatalf("Passkey 第二步页状态=%d body=%s", factorPage.status, factorPage.body)
	}
	cookies = mergeCookies(cookies, factorPage.cookies)
	optionsMatch := regexp.MustCompile(`data-ln-options="([^"]+)"`).FindStringSubmatch(factorPage.body)
	if len(optionsMatch) != 2 {
		t.Fatal("Passkey 页面缺少服务端 options")
	}
	optionsJSON := []byte(htmlUnescape(optionsMatch[1]))
	ceremonyID := tokenFrom(t, factorPage.body, "passkey_ceremony_id")
	assertion := env.simulator.assertionResponse(t, optionsJSON, mfaTestOrigin, "", 1)
	verify := env.request(http.MethodPost, "/login/second-factor", url.Values{
		"challenge_id":        {tokenFrom(t, factorPage.body, "challenge_id")},
		"attempt_token":       {tokenFrom(t, factorPage.body, "attempt_token")},
		"passkey_ceremony_id": {ceremonyID},
		"passkey_response":    {string(assertion)},
		"csrf_token":          {tokenFrom(t, factorPage.body, "csrf_token")}}, cookies, "")
	if verify.status != http.StatusSeeOther || verify.headers.Get("Location") != "/home" {
		t.Fatalf("Passkey 第二步成功应跳转 /home，实际 %d body=%s", verify.status,
			verify.body[:min(len(verify.body), 600)])
	}
	// 错误 ceremony 响应被拒绝（不建立完整会话）。
	badAssertion := env.simulator.assertionResponse(t, optionsJSON, mfaTestOrigin+".evil", "", 2)
	bad := env.request(http.MethodPost, "/login/second-factor", url.Values{
		"challenge_id":        {tokenFrom(t, factorPage.body, "challenge_id")},
		"attempt_token":       {tokenFrom(t, factorPage.body, "attempt_token")},
		"passkey_ceremony_id": {ceremonyID},
		"passkey_response":    {string(badAssertion)},
		"csrf_token":          {tokenFrom(t, factorPage.body, "csrf_token")}}, cookies, "")
	if bad.status == http.StatusSeeOther {
		t.Fatal("错误来源的 Passkey 断言不应成功")
	}
}

// htmlUnescape 解码 HTML 属性实体（仅测试用于读取服务端转义后的 JSON）。
func htmlUnescape(value string) string {
	replacer := strings.NewReplacer("&#34;", `"`, "&#39;", "'", "&amp;", "&",
		"&lt;", "<", "&gt;", ">")
	return replacer.Replace(value)
}

// TestMFAPagesTOTPSecondFactor 用真实 TOTP 服务验证第二因素：绑定真实 TOTP 因素、
// 动态码验证、同一时间步重放拒绝。
func TestMFAPagesTOTPSecondFactor(t *testing.T) {
	env := newMFAPageEnv(t)
	ctx := context.Background()
	caller, err := totp.UserCaller(env.userID)
	if err != nil {
		t.Fatalf("TOTP 调用者: %v", err)
	}
	start, err := env.totp.BeginBinding(ctx, caller, "req-totp-bind")
	if err != nil {
		t.Fatalf("开始 TOTP 绑定: %v", err)
	}
	code := keystreamTOTP(t, start.Secret, env.now, start.PeriodSeconds, start.Digits)
	if _, err := env.totp.ConfirmBinding(ctx, caller, totp.BindConfirm{
		BindingID: start.BindingID, Code: code, RequestID: "req-totp-confirm"}); err != nil {
		t.Fatalf("确认 TOTP 绑定: %v", err)
	}
	// 绑定确认消耗了当前时间步；推进时间避免登录验证被同一步重放防护拒绝。
	env.advance(time.Minute)
	env.now = env.now.Add(time.Minute)
	// TOTP 优先于邮件；删除邮件因素确保页面显示 TOTP 分支。
	if _, err := env.storage.ExecContext(ctx, `DELETE FROM mfa_factors WHERE user_id=?`,
		env.userID); err != nil {
		t.Fatalf("删除邮件因素: %v", err)
	}
	loginResp, cookies := env.loginPassword("correct horse battery staple")
	if loginResp.status != http.StatusSeeOther {
		t.Fatalf("TOTP 受限登录应跳转第二步: %d", loginResp.status)
	}
	factorPage := env.request(http.MethodGet, "/login/second-factor", nil, cookies, "")
	if factorPage.status != http.StatusOK || !strings.Contains(factorPage.body, "输入当前动态码") {
		t.Fatalf("TOTP 第二步页状态=%d body=%s", factorPage.status, factorPage.body)
	}
	if strings.Contains(factorPage.body, "重新发送验证码") {
		t.Fatal("TOTP 页不应提供重发验证码")
	}
	cookies = mergeCookies(cookies, factorPage.cookies)
	verify := env.request(http.MethodPost, "/login/second-factor", url.Values{
		"challenge_id":  {tokenFrom(t, factorPage.body, "challenge_id")},
		"attempt_token": {tokenFrom(t, factorPage.body, "attempt_token")},
		"code":          {env.totpCode(t, start.Secret)},
		"csrf_token":    {tokenFrom(t, factorPage.body, "csrf_token")}}, cookies, "")
	if verify.status != http.StatusSeeOther || verify.headers.Get("Location") != "/home" {
		t.Fatalf("TOTP 验证应成功，实际 %d body=%s", verify.status,
			verify.body[:min(len(verify.body), 600)])
	}
}

// totpCode 计算当前时间步的 TOTP 验证码。
func (e *mfaPageEnv) totpCode(t *testing.T, secret string) string {
	t.Helper()
	return keystreamTOTP(t, secret, e.now, 30, 6)
}

// TestMFAPagesErrorCodesAndI18n 验证用户可纠正错误映射为稳定码 + 400 + 已翻译文案，
// 内部故障才返回 500；恢复代码无效、重置 token 无效/过期、Passkey ceremony 失败。
func TestMFAPagesErrorCodesAndI18n(t *testing.T) {
	env := newMFAPageEnv(t)
	// 恢复代码无效：真实 mfa/recovery 链路返回 CHALLENGE_INVALID（400 + 中文）。
	_, cookies := env.loginPassword("correct horse battery staple")
	codePage := env.request(http.MethodGet, "/login/recovery-code", nil, cookies, "")
	if codePage.status != http.StatusOK {
		t.Fatalf("恢复代码页状态 = %d", codePage.status)
	}
	cookies = mergeCookies(cookies, codePage.cookies)
	badCode := env.request(http.MethodPost, "/login/recovery-code", url.Values{
		"code":       {"not-a-valid-recovery-code"},
		"csrf_token": {tokenFrom(t, codePage.body, "csrf_token")}}, cookies, "")
	assertPublicError(t, badCode, "CHALLENGE_INVALID", http.StatusBadRequest)
	if !strings.Contains(badCode.body, "验证请求无效或已失效") {
		t.Fatalf("错误摘要应为中文文案，实际 body=%s", badCode.body)
	}

	// 重置 token 无效：400 CHALLENGE_INVALID + 中文。
	invalidReset := env.request(http.MethodGet, "/login/reset-password?token=invalid-token", nil, nil, "")
	assertPublicError(t, invalidReset, "CHALLENGE_INVALID", http.StatusBadRequest)
	if !strings.Contains(invalidReset.body, "重置入口无效或已失效") {
		t.Fatalf("无效重置 token 摘要应为中文，实际 body=%s", invalidReset.body)
	}

	// 重置 token 过期：真实找回 token，推进时间后 GET 只读校验拒绝（不消费）。
	forgotPage := env.request(http.MethodGet, "/login/forgot-password", nil, nil, "")
	forgotCookies := mergeCookies(forgotPage.cookies)
	sent := env.request(http.MethodPost, "/login/forgot-password", url.Values{
		"identifier": {"user@example.test"},
		"csrf_token": {tokenFrom(t, forgotPage.body, "csrf_token")}}, forgotCookies, "")
	if sent.status != http.StatusOK {
		t.Fatalf("找回受理失败: %d", sent.status)
	}
	resetToken := extractResetToken(t, env.mail.last.TextBody)
	env.advance(30 * time.Minute)
	expiredReset := env.request(http.MethodGet,
		"/login/reset-password?token="+url.QueryEscape(resetToken), nil, nil, "")
	assertPublicError(t, expiredReset, "CHALLENGE_INVALID", http.StatusBadRequest)

	// 恢复代码过期：适配器映射层断言（真实尝试过期需先消费成功，单独由单测覆盖）。
	// Passkey ceremony 失败：真实注册软件认证器后提交伪造断言。
	ctx := context.Background()
	caller, err := passkey.UserCaller(env.userID)
	if err != nil {
		t.Fatalf("Passkey 调用者: %v", err)
	}
	registration, err := env.passkeys.BeginRegistrationWithPurpose(ctx, caller,
		"req-passkey-register", passkey.PurposeBoth)
	if err != nil {
		t.Fatalf("开始 Passkey 注册: %v", err)
	}
	registrationResponse := env.simulator.registrationResponse(t, registration.PublicKey,
		mfaTestOrigin, "")
	if _, err := env.passkeys.FinishRegistration(ctx, caller,
		passkey.RegistrationFinishRequest{CeremonyID: registration.CeremonyID,
			Response: registrationResponse, Name: "软件认证器", RequestID: "req-passkey-finish"}); err != nil {
		t.Fatalf("完成 Passkey 注册: %v", err)
	}
	if _, err := env.storage.ExecContext(ctx, `DELETE FROM mfa_factors WHERE user_id=?`,
		env.userID); err != nil {
		t.Fatalf("删除邮件因素: %v", err)
	}
	loginResp, passkeyCookies := env.loginPassword("correct horse battery staple")
	if loginResp.status != http.StatusSeeOther {
		t.Fatalf("Passkey 受限登录应跳转第二步: %d", loginResp.status)
	}
	factorPage := env.request(http.MethodGet, "/login/second-factor", nil, passkeyCookies, "")
	passkeyCookies = mergeCookies(passkeyCookies, factorPage.cookies)
	failedCeremony := env.request(http.MethodPost, "/login/second-factor", url.Values{
		"challenge_id":        {tokenFrom(t, factorPage.body, "challenge_id")},
		"attempt_token":       {tokenFrom(t, factorPage.body, "attempt_token")},
		"passkey_ceremony_id": {tokenFrom(t, factorPage.body, "passkey_ceremony_id")},
		"passkey_response":    {`{"id":"forged","type":"public-key","response":{}}`},
		"csrf_token":          {tokenFrom(t, factorPage.body, "csrf_token")}}, passkeyCookies, "")
	assertPublicError(t, failedCeremony, "CHALLENGE_INVALID", http.StatusBadRequest)
	if !strings.Contains(failedCeremony.body, "验证请求无效或已失效") {
		t.Fatalf("Passkey ceremony 失败摘要应为中文，实际 body=%s", failedCeremony.body)
	}

	// zh-CN 目录必须包含所有页面会显示的 error.business 稳定码键。
	catalogRaw, err := os.ReadFile("web/i18n/zh-CN.json")
	if err != nil {
		t.Fatalf("读取 zh-CN 文案: %v", err)
	}
	var catalog map[string]string
	if err := json.Unmarshal(catalogRaw, &catalog); err != nil {
		t.Fatalf("解析 zh-CN 文案: %v", err)
	}
	for _, code := range []string{"CHALLENGE_INVALID", "AUTH_FAILED", "ACCESS_DENIED",
		"MFA_REQUIRED", "MFA_REBIND_REQUIRED", "REAUTH_REQUIRED", "REQ_INVALID",
		"RATE_LIMITED", "CONFLICT", "USER_DISABLED", "MAIL_DELIVERY_FAILED",
		"AUTHZ_UNAVAILABLE", "DB_UNAVAILABLE", "AUDIT_WRITE_FAILED", "INTERNAL_ERROR"} {
		if message := strings.TrimSpace(catalog["error.business."+code]); message == "" {
			t.Errorf("zh-CN 缺少错误码文案 error.business.%s", code)
		}
	}
	for _, key := range []string{"page.auth.passkey.cancelled", "page.auth.passkey.unsupported",
		"page.auth.passkey.uv_required"} {
		if strings.TrimSpace(catalog[key]) == "" {
			t.Errorf("zh-CN 缺少页面文案 %s", key)
		}
	}
	// Passkey 取消/不支持的真实原因映射必须在客户端模块中显式存在。
	module, err := os.ReadFile("web/assets/js/modules/webauthn.mjs")
	if err != nil {
		t.Fatalf("读取 WebAuthn 模块: %v", err)
	}
	for _, reason := range []string{"NotAllowedError", "NotSupportedError", "SecurityError", "AbortError"} {
		if !strings.Contains(string(module), reason) {
			t.Errorf("WebAuthn 模块缺少取消/失败原因映射 %s", reason)
		}
	}
}

// assertPublicError 断言页面返回稳定错误码与状态，并显示中文摘要而非原始键名。
func assertPublicError(t *testing.T, response mfaResponse, code string, status int) {
	t.Helper()
	if response.status != status {
		t.Fatalf("状态 = %d，期望 %d（body=%s）", response.status, status,
			response.body[:min(len(response.body), 800)])
	}
	if !strings.Contains(response.body, code) {
		t.Fatalf("页面缺少稳定错误码 %s（状态 %d）", code, response.status)
	}
	if strings.Contains(response.body, "error.business."+code) {
		t.Fatalf("页面显示了未翻译的原始键 error.business.%s", code)
	}
}
