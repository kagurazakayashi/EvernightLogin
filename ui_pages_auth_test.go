package login_test

// 步骤 63 账户入口页集成测试：真实 SQLite + 真实 authn/session/registration/
// onboarding/credential 服务 + 真实 transport CSRF 与页面框架；邮件只写入本地
// 捕获器，不联网、不启动监听端口。

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
	"github.com/kagurazakayashi/EvernightLogin/internal/onboarding"
	onboardingsqlite "github.com/kagurazakayashi/EvernightLogin/internal/onboarding/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/pagecsrf"
	"github.com/kagurazakayashi/EvernightLogin/internal/registration"
	registrationsqlite "github.com/kagurazakayashi/EvernightLogin/internal/registration/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	sessionsqlite "github.com/kagurazakayashi/EvernightLogin/internal/session/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/uiauthadapter"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const testPageOrigin = "http://example.test"

type captureRegistrationMail struct {
	last  registration.EmailMessage
	count int
}

func (c *captureRegistrationMail) SendEmailVerification(_ context.Context,
	message registration.EmailMessage) error {
	c.last = message
	c.count++
	return nil
}

type captureInvitationMail struct {
	last onboarding.InvitationEmail
}

func (c *captureInvitationMail) SendInvitation(_ context.Context,
	message onboarding.InvitationEmail) error {
	c.last = message
	return nil
}

func (c *captureInvitationMail) SendReviewDecision(_ context.Context,
	_ onboarding.ReviewEmail) error {
	return nil
}

// allowGuard 是入域委派检查的测试替身：只用于邀请创建路径；页面鉴权仍由真实
// onboarding 服务与真实 Caller 校验。
type allowGuard struct{}

func (allowGuard) CheckPermissionAccess(context.Context, audit.Tx, audit.Actor, string,
	[]delegation.PermissionRef, []delegation.Target) error {
	return nil
}

func (allowGuard) CheckAssignment(context.Context, audit.Tx, audit.Actor, string,
	[]delegation.PermissionRef, delegation.Target) error {
	return nil
}

func (allowGuard) CheckPermissionActivation(context.Context, audit.Tx, audit.Actor, string,
	[]delegation.PermissionRef, []delegation.Target) error {
	return nil
}

func (allowGuard) CheckScopeRestoration(context.Context, audit.Tx, audit.Actor, string) error {
	return nil
}

// pageSessions 用真实会话服务实现公开页面会话契约。
type pageSessions struct{ service *session.Service }

func (p pageSessions) ResolvePageSession(ctx context.Context,
	request *http.Request) (login.UISession, error) {
	secret, ok := p.service.SessionSecretFromRequest(request)
	if !ok {
		return login.UISession{}, login.ErrUISessionExpired
	}
	record, err := p.service.Validate(ctx, secret)
	if err != nil {
		return login.UISession{}, login.ErrUISessionExpired
	}
	kind := "normal"
	if record.IsRestricted() {
		kind = "restricted"
	}
	return login.UISession{Authenticated: true, UserID: record.UserID,
		AppID: record.AppID, Kind: kind, ExpiresAt: record.AbsoluteExpiresAt}, nil
}

func (p pageSessions) IssueCSRFToken(ctx context.Context,
	request *http.Request) (string, error) {
	secret, ok := p.service.SessionSecretFromRequest(request)
	if !ok {
		return "", login.ErrUISessionExpired
	}
	token, err := p.service.IssuePageCSRFToken(ctx, secret)
	if err != nil {
		return "", login.ErrUISessionExpired
	}
	return token.Reveal(), nil
}

type pageAuthEnv struct {
	t          *testing.T
	handler    http.Handler
	authn      *authn.Service
	sessions   *session.Service
	reg        *registration.Service
	onboarding *onboarding.Service
	regMail    *captureRegistrationMail
	inviteMail *captureInvitationMail
	csrf       *pagecsrf.Provider
	adapter    *uiauthadapter.Adapter
	advance    func(time.Duration)
}

// newPageAuthEnv 构造真实服务与页面处理器。
func newPageAuthEnv(t *testing.T, registrationMutate func(*registration.Options)) *pageAuthEnv {
	t.Helper()
	ctx := context.Background()
	storage, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(
		filepath.Join(t.TempDir(), "pages.db")))
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
	logger := slog.New(slog.NewTextHandler(ioDiscard{}, &slog.HandlerOptions{Level: slog.LevelError}))
	now := time.Date(2026, 4, 5, 6, 7, 8, 0, time.UTC)
	nowFunc := func() time.Time { return now }
	recorder, err := audit.New(auditStore, audit.Options{Now: nowFunc, Logger: logger})
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
		Now: nowFunc, Logger: logger})
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
		RootInitialization: bootstrapStore, Now: nowFunc, Logger: logger,
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
	regMail := &captureRegistrationMail{}
	regOptions := registration.Options{Store: registrationStore, Audit: recorder,
		Credentials: credentialService, Mailer: regMail,
		VerificationURLBase: testPageOrigin + "/email/verify", Enabled: true,
		VerificationTTL: time.Hour, ResendCooldown: time.Minute,
		AppName: "EvernightLogin", Now: nowFunc, Logger: logger}
	if registrationMutate != nil {
		registrationMutate(&regOptions)
	}
	registrationService, err := registration.New(regOptions)
	if err != nil {
		t.Fatalf("注册服务: %v", err)
	}
	onboardingStore, err := onboardingsqlite.New(storage)
	if err != nil {
		t.Fatalf("入域存储: %v", err)
	}
	inviteMail := &captureInvitationMail{}
	onboardingService, err := onboarding.New(onboarding.Options{Store: onboardingStore,
		Audit: recorder, Guard: allowGuard{}, Credentials: credentialService,
		InviteAuthorizer: onboarding.InviteAuthorizerFunc(func(context.Context,
			onboarding.Caller, onboarding.CreateRequest) error {
			return nil
		}),
		Mailer: inviteMail, SupportURL: testPageOrigin + "/support",
		AcceptanceURLBase: testPageOrigin + "/invitation/accept",
		AppName:           "EvernightLogin", PasswordPolicy: authn.DefaultPasswordPolicy(),
		HashParams: authn.Params{MemoryKiB: 8192, Iterations: 1, Parallelism: 1,
			SaltLength: 16, KeyLength: 32},
		InvitationTTL: time.Hour, Now: nowFunc, Logger: logger})
	if err != nil {
		t.Fatalf("入域服务: %v", err)
	}
	adapter, err := uiauthadapter.New(uiauthadapter.Options{Authn: authnService,
		Sessions: sessionService, Registration: registrationService,
		Onboarding: onboardingService, RegistrationStore: registrationStore,
		Credential: credentialService, Now: nowFunc, Logger: logger})
	if err != nil {
		t.Fatalf("页面账户适配器: %v", err)
	}
	csrfProvider, err := pagecsrf.New(pagecsrf.Options{Keyring: keyring,
		TTL: 10 * time.Minute, Now: nowFunc})
	if err != nil {
		t.Fatalf("页面 CSRF: %v", err)
	}
	ui, err := login.NewWebUI(login.WebUIOptions{
		Session:    pageSessions{service: sessionService},
		FormTokens: csrfProvider,
		PageAuth:   &login.UIPageAuthOptions{Backend: adapter, PostLoginPath: "/home"},
		Now:        nowFunc,
		Logger:     logger,
	})
	if err != nil {
		t.Fatalf("页面框架: %v", err)
	}
	publicPaths := login.UIPageAuthPublicFormPaths("")
	pathList := make([]string, 0, len(publicPaths))
	purposes := map[string]string{}
	for path, purpose := range publicPaths {
		pathList = append(pathList, path)
		purposes[path] = purpose
	}
	handler, err := login.NewHTTPHandler(login.HTTPOptions{UI: &login.UIHTTPOptions{
		Handler: ui, PageContentSecurityPolicy: login.DefaultUIPageContentSecurityPolicy},
		Protection: &login.HTTPProtectionOptions{
			CSRF: login.CSRFPolicy{Enabled: true,
				CookieName: session.DefaultCookieName, AllowedOrigins: []string{testPageOrigin},
				RequireForAllUnsafeRequests: true, PublicFormPaths: pathList,
				PublicTokenValidator: csrfProvider.Validator(purposes),
				TokenValidator: login.CSRFValidatorFunc(func(ctx context.Context,
					request *http.Request, token string) error {
					return sessionService.ValidateCSRFToken(ctx, request, token)
				})},
			SecurityHeaders: &login.SecurityHeaderOptions{
				ContentSecurityPolicy: login.DefaultUIPageContentSecurityPolicy},
		}})
	if err != nil {
		t.Fatalf("HTTP 处理器: %v", err)
	}
	return &pageAuthEnv{t: t, handler: handler, authn: authnService,
		sessions: sessionService, reg: registrationService,
		onboarding: onboardingService, regMail: regMail, inviteMail: inviteMail,
		csrf: csrfProvider, adapter: adapter,
		advance: func(d time.Duration) { now = now.Add(d) }}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }

// ===== 请求辅助 =====

var csrfValuePattern = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

type pageResponse struct {
	status  int
	headers http.Header
	body    string
	cookies []*http.Cookie
}

// request 执行一次请求；origin 为空时使用默认同源。
func (e *pageAuthEnv) request(method, target string, form url.Values,
	cookies []*http.Cookie, origin string) pageResponse {
	e.t.Helper()
	var body *strings.Reader
	if form == nil {
		body = strings.NewReader("")
	} else {
		body = strings.NewReader(form.Encode())
	}
	request := httptest.NewRequest(method, testPageOrigin+target, body)
	request.Host = "example.test"
	if form != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if origin == "" {
		origin = testPageOrigin
	}
	if origin != "-" {
		request.Header.Set("Origin", origin)
	}
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	e.handler.ServeHTTP(recorder, request)
	result := recorder.Result()
	return pageResponse{status: result.StatusCode, headers: result.Header,
		body: recorder.Body.String(), cookies: result.Cookies()}
}

// csrfPair 返回匿名 CSRF 令牌与 Cookie（从登录页 GET 提取）。
func (e *pageAuthEnv) csrfPair(target string) (string, []*http.Cookie) {
	e.t.Helper()
	response := e.request(http.MethodGet, target, nil, nil, "")
	if response.status != http.StatusOK {
		e.t.Fatalf("GET %s = %d", target, response.status)
	}
	match := csrfValuePattern.FindStringSubmatch(response.body)
	if len(match) != 2 {
		e.t.Fatalf("GET %s 未渲染 CSRF 隐藏字段", target)
	}
	var cookies []*http.Cookie
	for _, cookie := range response.cookies {
		if cookie.Name == pagecsrf.CookieName {
			cookies = append(cookies, cookie)
		}
	}
	if len(cookies) == 0 {
		e.t.Fatalf("GET %s 未下发匿名 CSRF Cookie", target)
	}
	return match[1], cookies
}

// sessionCookies 从响应提取会话 Cookie。
func sessionCookies(response pageResponse) []*http.Cookie {
	for _, cookie := range response.cookies {
		if cookie.Name == session.DefaultCookieName {
			return []*http.Cookie{cookie}
		}
	}
	return nil
}

// createUser 通过真实注册服务创建账户并返回稳定用户 ID。
func (e *pageAuthEnv) createUser(username, password string) string {
	e.t.Helper()
	result, err := e.reg.Register(context.Background(), registration.RegisterRequest{
		Username: username, Password: password, RequestID: "req_create_" + username})
	if err != nil {
		e.t.Fatalf("创建账户: %v", err)
	}
	return result.UserID
}

// ===== 测试 =====

func TestAuthPagesRenderWithRealServices(t *testing.T) {
	env := newPageAuthEnv(t, nil)
	response := env.request(http.MethodGet, "/login", nil, nil, "")
	if response.status != http.StatusOK || !strings.Contains(response.body, "登录") ||
		!strings.Contains(response.body, `name="csrf_token"`) {
		t.Fatalf("登录页渲染异常: status=%d body=%.600s", response.status, response.body)
	}
	if response.headers.Get("Cache-Control") != "no-store" ||
		!strings.Contains(response.headers.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatalf("页面安全头缺失: %v", response.headers)
	}
	register := env.request(http.MethodGet, "/register", nil, nil, "")
	if register.status != http.StatusOK || !strings.Contains(register.body, "注册") {
		t.Fatalf("注册页渲染异常: %d", register.status)
	}
	status := env.request(http.MethodGet, "/register/status", nil, nil, "")
	if status.status != http.StatusOK || !strings.Contains(status.body, "审核状态") {
		t.Fatalf("审核状态页渲染异常: %d", status.status)
	}
	unknown := env.request(http.MethodGet, "/nonexistent-page", nil, nil, "")
	if unknown.status != http.StatusNotFound {
		t.Fatalf("未知页面状态 = %d，期望 404", unknown.status)
	}
}

func TestLoginRealBackendAndRedirectWhitelist(t *testing.T) {
	env := newPageAuthEnv(t, nil)
	env.createUser("alice", "CorrectHorseBattery1!")
	token, cookies := env.csrfPair("/login")
	// 错误密码：统一公开错误，不签发会话。
	wrong := env.request(http.MethodPost, "/login", url.Values{
		"csrf_token": {token}, "identifier": {"alice"},
		"password": {"WrongPassword1!"}}, cookies, "")
	if wrong.status != http.StatusBadRequest || !strings.Contains(wrong.body, "无法完成登录") {
		t.Fatalf("错误密码响应 = %d/%q", wrong.status, wrong.body)
	}
	if len(sessionCookies(wrong)) != 0 {
		t.Fatal("错误密码不应签发会话 Cookie")
	}
	// 正确密码：303 到站内默认落地页并签发会话。
	ok := env.request(http.MethodPost, "/login", url.Values{
		"csrf_token": {token}, "identifier": {"alice"},
		"password": {"CorrectHorseBattery1!"}}, cookies, "")
	if ok.status != http.StatusSeeOther || ok.headers.Get("Location") != "/home" {
		t.Fatalf("登录成功响应 = %d Location=%q", ok.status, ok.headers.Get("Location"))
	}
	activeCookies := sessionCookies(ok)
	if len(activeCookies) == 0 {
		t.Fatal("登录成功应签发会话 Cookie")
	}
	landing := env.request(http.MethodGet, "/home", nil, activeCookies, "")
	if landing.status != http.StatusOK || !strings.Contains(landing.body, "已登录") {
		t.Fatalf("落地页 = %d", landing.status)
	}
	// 开放重定向：非站内 return 回退默认落地页。
	token2, cookies2 := env.csrfPair("/login")
	redirect := env.request(http.MethodPost, "/login", url.Values{
		"csrf_token": {token2}, "identifier": {"alice"},
		"password": {"CorrectHorseBattery1!"}, "return": {"//evil.example"}}, cookies2, "")
	if redirect.status != http.StatusSeeOther || redirect.headers.Get("Location") != "/home" {
		t.Fatalf("非法 return 未被拒绝: %d %q", redirect.status,
			redirect.headers.Get("Location"))
	}
	// 合法站内 return 保留。
	token3, cookies3 := env.csrfPair("/login")
	allowed := env.request(http.MethodPost, "/login", url.Values{
		"csrf_token": {token3}, "identifier": {"alice"},
		"password": {"CorrectHorseBattery1!"}, "return": {"/register"}}, cookies3, "")
	if allowed.status != http.StatusSeeOther || allowed.headers.Get("Location") != "/register" {
		t.Fatalf("合法 return 被拒绝: %d %q", allowed.status, allowed.headers.Get("Location"))
	}
}

func TestRegisterClosedAndNoEmailFlow(t *testing.T) {
	closed := newPageAuthEnv(t, func(options *registration.Options) {
		options.Enabled = false
	})
	page := closed.request(http.MethodGet, "/register", nil, nil, "")
	if page.status != http.StatusForbidden || !strings.Contains(page.body, "当前未开放注册") {
		t.Fatalf("关闭注册页 = %d", page.status)
	}
	open := newPageAuthEnv(t, nil)
	token, cookies := open.csrfPair("/register")
	// 保留字段/未知字段整单拒绝。
	invalid := open.request(http.MethodPost, "/register", url.Values{
		"csrf_token": {token}, "username": {"carol"}, "password": {"CorrectHorseBattery1!"},
		"password_confirm": {"CorrectHorseBattery1!"}, "is_root": {"true"}}, cookies, "")
	if invalid.status != http.StatusBadRequest {
		t.Fatalf("含保留字段的注册 = %d，期望 400", invalid.status)
	}
	// 无邮箱注册成功，且不自动登录。
	token2, cookies2 := open.csrfPair("/register")
	created := open.request(http.MethodPost, "/register", url.Values{
		"csrf_token": {token2}, "username": {"dave"}, "password": {"CorrectHorseBattery1!"},
		"password_confirm": {"CorrectHorseBattery1!"}}, cookies2, "")
	if created.status != http.StatusOK || !strings.Contains(created.body, "账户已创建") {
		t.Fatalf("无邮箱注册 = %d/%q", created.status, created.body)
	}
	if len(sessionCookies(created)) != 0 {
		t.Fatal("注册不应自动签发会话")
	}
	// 新账户可真实登录。
	token3, cookies3 := open.csrfPair("/login")
	loginResponse := open.request(http.MethodPost, "/login", url.Values{
		"csrf_token": {token3}, "identifier": {"dave"},
		"password": {"CorrectHorseBattery1!"}}, cookies3, "")
	if loginResponse.status != http.StatusSeeOther {
		t.Fatalf("新账户登录 = %d", loginResponse.status)
	}
}

func TestEmailVerificationRealFlow(t *testing.T) {
	env := newPageAuthEnv(t, nil)
	_, err := env.reg.Register(context.Background(), registration.RegisterRequest{
		Username: "erin", Password: "CorrectHorseBattery1!", Email: "erin@example.test",
		RequestID: "req_verify"})
	if err != nil {
		t.Fatalf("带邮箱注册: %v", err)
	}
	verificationURL := env.regMail.last.VerificationURL
	if verificationURL == "" {
		t.Fatal("注册未生成验证链接（捕获器为空）")
	}
	parsed, err := url.Parse(verificationURL)
	if err != nil {
		t.Fatalf("解析验证链接: %v", err)
	}
	query := parsed.Query()
	// GET 不消费：确认表单渲染且数据库票据仍可直接验证。
	page := env.request(http.MethodGet, "/email/verify?"+query.Encode(), nil, nil, "")
	if page.status != http.StatusOK || !strings.Contains(page.body, "验证邮箱") {
		t.Fatalf("邮箱验证 GET = %d", page.status)
	}
	token, cookies := env.csrfPair("/email/verify?" + query.Encode())
	post := env.request(http.MethodPost, "/email/verify", url.Values{
		"csrf_token": {token}, "uid": {query.Get("uid")}, "cid": {query.Get("cid")},
		"token": {query.Get("token")}}, cookies, "")
	if post.status != http.StatusOK || !strings.Contains(post.body, "邮箱已验证") {
		t.Fatalf("邮箱验证 POST = %d/%q", post.status, post.body)
	}
	// 重复提交同一一次性入口：拒绝且不显示成功。
	token2, cookies2 := env.csrfPair("/email/verify?" + query.Encode())
	replay := env.request(http.MethodPost, "/email/verify", url.Values{
		"csrf_token": {token2}, "uid": {query.Get("uid")}, "cid": {query.Get("cid")},
		"token": {query.Get("token")}}, cookies2, "")
	if replay.status != http.StatusBadRequest {
		t.Fatalf("重复验证入口 = %d，期望 400", replay.status)
	}
}

func TestInvitationAcceptRealFlow(t *testing.T) {
	env := newPageAuthEnv(t, nil)
	inviterID := env.createUser("frank", "CorrectHorseBattery1!")
	inviterCaller, err := onboarding.UserCaller(inviterID)
	if err != nil {
		t.Fatalf("邀请者 Caller: %v", err)
	}
	if _, err := env.onboarding.CreateInvitation(context.Background(), inviterCaller,
		onboarding.CreateRequest{TargetEmail: "invitee@example.test", TTL: time.Hour,
			RequestID: "req_invite"}); err != nil {
		t.Fatalf("创建邀请: %v", err)
	}
	acceptance := env.inviteMail.last.AcceptanceURL
	if acceptance == "" {
		t.Fatal("邀请邮件捕获器为空")
	}
	parsed, err := url.Parse(acceptance)
	if err != nil {
		t.Fatalf("解析邀请链接: %v", err)
	}
	query := parsed.Query()
	page := env.request(http.MethodGet, "/invitation/accept?"+query.Encode(), nil, nil, "")
	if page.status != http.StatusOK || !strings.Contains(page.body, "接受邀请") {
		t.Fatalf("邀请页 GET = %d", page.status)
	}
	if strings.Contains(page.body, `href="`+query.Get("token")) {
		t.Fatal("邀请令牌不得出现在链接地址中")
	}
	if !strings.Contains(page.body, `name="token"`) {
		t.Fatal("邀请令牌应只放在 POST 隐藏字段")
	}
	token, cookies := env.csrfPair("/invitation/accept?" + query.Encode())
	accepted := env.request(http.MethodPost, "/invitation/accept", url.Values{
		"csrf_token": {token}, "iid": {query.Get("iid")}, "cid": {query.Get("cid")},
		"token": {query.Get("token")}, "username": {"invitee"},
		"password":         {"CorrectHorseBattery1!"},
		"password_confirm": {"CorrectHorseBattery1!"}}, cookies, "")
	if accepted.status != http.StatusOK || !strings.Contains(accepted.body, "邀请已接受") {
		t.Fatalf("邀请接受 = %d/%q", accepted.status, accepted.body)
	}
	// 一次性凭证重复接受：拒绝。
	reuseToken, reuseCookies := env.csrfPair("/invitation/accept?" + query.Encode())
	reuse := env.request(http.MethodPost, "/invitation/accept", url.Values{
		"csrf_token": {reuseToken}, "iid": {query.Get("iid")}, "cid": {query.Get("cid")},
		"token": {query.Get("token")}, "username": {"invitee2"},
		"password":         {"CorrectHorseBattery1!"},
		"password_confirm": {"CorrectHorseBattery1!"}}, reuseCookies, "")
	if reuse.status != http.StatusBadRequest {
		t.Fatalf("重复接受邀请 = %d，期望 400", reuse.status)
	}
}

func TestAnonymousCSRFProtection(t *testing.T) {
	env := newPageAuthEnv(t, nil)
	// 缺失令牌：拒绝。
	missing := env.request(http.MethodPost, "/login", url.Values{
		"identifier": {"alice"}, "password": {"x"}}, nil, "")
	if missing.status != http.StatusForbidden {
		t.Fatalf("缺失 CSRF = %d，期望 403", missing.status)
	}
	// 跨源：拒绝。
	token, cookies := env.csrfPair("/login")
	crossOrigin := env.request(http.MethodPost, "/login", url.Values{
		"csrf_token": {token}, "identifier": {"alice"}, "password": {"x"}},
		cookies, "http://evil.example")
	if crossOrigin.status != http.StatusForbidden {
		t.Fatalf("跨源 CSRF = %d，期望 403", crossOrigin.status)
	}
	// 用途错配：登录令牌用于注册路径，拒绝。
	mismatch := env.request(http.MethodPost, "/register", url.Values{
		"csrf_token": {token}, "username": {"zoe"}, "password": {"CorrectHorseBattery1!"},
		"password_confirm": {"CorrectHorseBattery1!"}}, cookies, "")
	if mismatch.status != http.StatusForbidden {
		t.Fatalf("用途错配令牌 = %d，期望 403", mismatch.status)
	}
	// Cookie 与隐藏字段不一致：拒绝。
	otherToken, otherCookies := env.csrfPair("/login")
	tampered := env.request(http.MethodPost, "/login", url.Values{
		"csrf_token": {otherToken}, "identifier": {"alice"}, "password": {"x"}},
		cookies, "")
	if tampered.status != http.StatusForbidden {
		t.Fatalf("Cookie/字段不一致 = %d，期望 403", tampered.status)
	}
	_ = otherCookies
}

// ===== 断言辅助编译期占位（避免未用变量） =====

// TestEmailResendGenericAndBinding 验证重发验证邮件：CSRF 同页用途可用、对外统一
// “已受理”，且仅当 uid/cid/token 与 pending 票据/一次性凭证绑定时才真实发送。
func TestEmailResendGenericAndBinding(t *testing.T) {
	env := newPageAuthEnv(t, nil)
	if _, err := env.reg.Register(context.Background(), registration.RegisterRequest{
		Username: "gina", Password: "CorrectHorseBattery1!", Email: "gina@example.test",
		RequestID: "req_resend"}); err != nil {
		t.Fatalf("带邮箱注册: %v", err)
	}
	parsed, err := url.Parse(env.regMail.last.VerificationURL)
	if err != nil {
		t.Fatalf("解析验证链接: %v", err)
	}
	query := parsed.Query()
	resendForm := func(uid, cid, token string) url.Values {
		return url.Values{"csrf_token": {""}, "uid": {uid}, "cid": {cid}, "token": {token}}
	}
	// GET 后使用同页 CSRF 令牌重发：应被受理（B1 修复点；旧实现恒 403）。
	checked := func() (string, []*http.Cookie) { return env.csrfPair("/email/verify?" + query.Encode()) }
	token, cookies := checked()
	form := resendForm(query.Get("uid"), query.Get("cid"), query.Get("token"))
	form.Set("csrf_token", token)
	env.advance(2 * time.Minute) // 越过注册初始发送冷却
	before := env.regMail.count
	first := env.request(http.MethodPost, "/email/verify/resend", form, cookies, "")
	if first.status != http.StatusOK || !strings.Contains(first.body, "重发请求已受理") {
		t.Fatalf("重发受理响应 = %d/%q", first.status, first.body)
	}
	if env.regMail.count != before+1 {
		t.Fatalf("有效票据重发应真实发送，count=%d->%d", before, env.regMail.count)
	}
	// 重发会替换待验证票据/一次性凭证，后续步骤使用最新邮件链接。
	latest, err := url.Parse(env.regMail.last.VerificationURL)
	if err != nil {
		t.Fatalf("解析最新验证链接: %v", err)
	}
	query = latest.Query()
	// 立即再次重发：后端冷却，对外仍统一受理且不发送。
	token2, cookies2 := checked()
	form2 := resendForm(query.Get("uid"), query.Get("cid"), query.Get("token"))
	form2.Set("csrf_token", token2)
	before = env.regMail.count
	cooldown := env.request(http.MethodPost, "/email/verify/resend", form2, cookies2, "")
	if cooldown.status != http.StatusOK || !strings.Contains(cooldown.body, "重发请求已受理") {
		t.Fatalf("冷却期响应 = %d", cooldown.status)
	}
	if env.regMail.count != before {
		t.Fatalf("冷却期内不应发送，count=%d->%d", before, env.regMail.count)
	}
	// 伪造 token：统一受理但不发送。
	env.advance(2 * time.Minute)
	token3, cookies3 := checked()
	form3 := resendForm(query.Get("uid"), query.Get("cid"), query.Get("token")+"x")
	form3.Set("csrf_token", token3)
	before = env.regMail.count
	forged := env.request(http.MethodPost, "/email/verify/resend", form3, cookies3, "")
	if forged.status != http.StatusOK || !strings.Contains(forged.body, "重发请求已受理") ||
		env.regMail.count != before {
		t.Fatalf("伪造 token 应为统一受理且不发送: status=%d count=%d->%d",
			forged.status, before, env.regMail.count)
	}
	// 不存在用户：统一受理但不发送。
	token4, cookies4 := checked()
	form4 := resendForm("usr_doesnotexist000000000000000000", query.Get("cid"), query.Get("token"))
	form4.Set("csrf_token", token4)
	before = env.regMail.count
	unknown := env.request(http.MethodPost, "/email/verify/resend", form4, cookies4, "")
	if unknown.status != http.StatusOK || env.regMail.count != before {
		t.Fatalf("不存在用户应统一受理且不发送: status=%d", unknown.status)
	}
	// 已消费票据：统一受理但不发送。
	token5, cookies5 := checked()
	form5 := resendForm(query.Get("uid"), query.Get("cid"), query.Get("token"))
	form5.Set("csrf_token", token5)
	if consumed := env.request(http.MethodPost, "/email/verify", form5, cookies5, ""); consumed.status != http.StatusOK {
		t.Fatalf("验证消费 = %d", consumed.status)
	}
	token6, cookies6 := checked()
	form6 := resendForm(query.Get("uid"), query.Get("cid"), query.Get("token"))
	form6.Set("csrf_token", token6)
	before = env.regMail.count
	consumedResend := env.request(http.MethodPost, "/email/verify/resend", form6, cookies6, "")
	if consumedResend.status != http.StatusOK || env.regMail.count != before {
		t.Fatalf("已消费票据应统一受理且不发送: status=%d", consumedResend.status)
	}
}
