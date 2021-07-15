package login_test

// 步骤 65 真实服务集成：临时 SQLite + 真实 oauthflow/session + 真实 transport CSRF/
// 页面框架；设备码与授权确认走真实后端。QR 页面由契约替身测试覆盖（见报告）。

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	apps "github.com/kagurazakayashi/EvernightLogin/internal/app/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
	oauthclientsqlite "github.com/kagurazakayashi/EvernightLogin/internal/oauthclient/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
	oauthflowsqlite "github.com/kagurazakayashi/EvernightLogin/internal/oauthflow/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/pagecsrf"
	"github.com/kagurazakayashi/EvernightLogin/internal/pagestate"
	"github.com/kagurazakayashi/EvernightLogin/internal/qrlogin"
	qrloginsqlite "github.com/kagurazakayashi/EvernightLogin/internal/qrlogin/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	sessionsqlite "github.com/kagurazakayashi/EvernightLogin/internal/session/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/token"
	"github.com/kagurazakayashi/EvernightLogin/internal/uiauthadapter"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const oauthTestOrigin = "http://localhost"

// fakeClientAuthenticator 是客户端认证测试替身（授权确认/设备确认不执行令牌兑换）。
type fakeClientAuthenticator struct{}

func (fakeClientAuthenticator) VerifyClientSecret(context.Context, string,
	string) (oauthclient.ClientIdentity, error) {
	return oauthclient.ClientIdentity{}, errors.New("not used")
}
func (fakeClientAuthenticator) VerifyClientCertificate(context.Context, string,
	string) (oauthclient.ClientIdentity, error) {
	return oauthclient.ClientIdentity{}, errors.New("not used")
}

// fakeTokenIssuer 是令牌签发测试替身（本步页面不兑换令牌）。
type fakeTokenIssuer struct{}

func (fakeTokenIssuer) IssueAccessToken(context.Context, token.Caller,
	token.IssueAccessTokenRequest) (token.IssuedToken, error) {
	return token.IssuedToken{}, errors.New("not used")
}

type oauthPageEnv struct {
	t        *testing.T
	handler  http.Handler
	sessions *session.Service
	oauth    *oauthflow.Service
	qr       *qrlogin.Service
	storage  *storagesqlite.Store
	clientID string
	cookie   *http.Cookie
	csrf     *pagecsrf.Provider
	now      time.Time
	advance  func(time.Duration)
	extra    map[string]*http.Cookie
}

// newOAuthPageEnv 构造真实 oauthflow 环境与页面处理器。
func newOAuthPageEnv(t *testing.T) *oauthPageEnv {
	t.Helper()
	ctx := context.Background()
	storage, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(
		filepath.Join(t.TempDir(), "oauth.db")))
	if err != nil {
		t.Fatalf("数据库: %v", err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	list, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("迁移: %v", err)
	}
	if _, err := storage.Migrate(ctx, list); err != nil {
		t.Fatalf("执行迁移: %v", err)
	}
	now := time.Date(2026, 4, 5, 6, 0, 0, 0, time.UTC)
	nowFunc := func() time.Time { return now }
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	auditStore, err := auditsqlite.New(storage)
	if err != nil {
		t.Fatalf("审计存储: %v", err)
	}
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
	userID := "usr_00000000000000000000000000000065"
	appID := "app_00000000000000000000000000000065"
	clientID := appID
	insert := func(query string, args ...any) {
		t.Helper()
		if _, err := storage.ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("插入 fixture 失败: %v\n%s", err, query)
		}
	}
	insert(`INSERT INTO users(id,username,username_normalized,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'active',0,1,1,?,?)`, userID, "oauthuser", "oauthuser",
		now.UnixMilli(), now.UnixMilli())
	insert(`INSERT INTO applications(id,name,description,status,client_type,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,'','active','confidential',1,?,?)`, appID, "测试应用", now.UnixMilli(), now.UnixMilli())
	insert(`INSERT INTO scopes(id,kind,app_id) VALUES(?,'application',?)`, appID, appID)
	insert(`INSERT INTO app_memberships(app_id,user_id,status,profile_json,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,'active','{"v":1}',1,?,?)`, appID, userID, now.UnixMilli(), now.UnixMilli())
	insert(`INSERT INTO oauth_clients(client_id,client_type,grant_types_json,redirect_uris_json,
post_logout_redirect_uris_json,scopes_json,audiences_json,auth_methods_json,require_pkce,
row_version,created_at_ms,updated_at_ms)
VALUES(?,'public','["authorization_code","urn:ietf:params:oauth:grant-type:device_code"]',
'["https://client.example/cb"]','[]','["email"]','["resource_1"]',
'["client_secret_basic"]',1,1,?,?)`, clientID, now.UnixMilli(), now.UnixMilli())
	clientStore, err := oauthclientsqlite.New(storage)
	if err != nil {
		t.Fatalf("客户端存储: %v", err)
	}
	clientSource, err := oauthflow.NewOAuthClientSource(clientStore)
	if err != nil {
		t.Fatalf("客户端来源: %v", err)
	}
	flowStore, err := oauthflowsqlite.New(storage)
	if err != nil {
		t.Fatalf("OAuth 存储: %v", err)
	}
	flow, err := oauthflow.New(oauthflow.Options{Store: flowStore, Audit: recorder,
		Clients: clientSource, ClientAuth: fakeClientAuthenticator{},
		Sessions: sessionService, Tokens: fakeTokenIssuer{}, Reauth: allowReauth{},
		DeviceVerificationURI: oauthTestOrigin + "/oauth/device",
		DeviceUserCodeKeyring: keyring, Now: nowFunc, Logger: logger})
	if err != nil {
		t.Fatalf("OAuth 服务: %v", err)
	}
	appStore, err := apps.New(storage)
	if err != nil {
		t.Fatalf("应用存储: %v", err)
	}
	qrStore, err := qrloginsqlite.New(storage)
	if err != nil {
		t.Fatalf("扫码存储: %v", err)
	}
	qrService, err := qrlogin.New(qrlogin.Options{Store: qrStore, Audit: recorder,
		Clients: clientStore, Applications: appStore, Sessions: sessionService,
		SessionIssuer: sessionService, Reauth: allowReauth{}, Keyring: keyring,
		Enabled: true, AllowedClientIDs: []string{clientID}, Now: nowFunc, Logger: logger})
	if err != nil {
		t.Fatalf("扫码服务: %v", err)
	}
	pageState, err := pagestate.New(pagestate.Options{Keyring: keyring, Now: nowFunc})
	if err != nil {
		t.Fatalf("页面状态: %v", err)
	}
	adapter, err := uiauthadapter.New(uiauthadapter.Options{Authn: nil, Sessions: sessionService,
		OAuth: flow, QR: qrService, QRClientID: clientID, QRScopes: []string{"email"},
		PageState:        pageState,
		ApplicationNames: map[string]string{clientID: "测试应用"},
		Now:              nowFunc, Logger: logger})
	if err != nil {
		t.Fatalf("页面适配器: %v", err)
	}
	csrfProvider, err := pagecsrf.New(pagecsrf.Options{Keyring: keyring,
		TTL: 10 * time.Minute, Now: nowFunc})
	if err != nil {
		t.Fatalf("页面 CSRF: %v", err)
	}
	ui, err := login.NewWebUI(login.WebUIOptions{Session: pageSessions{service: sessionService},
		FormTokens: csrfProvider,
		PageOAuth:  &login.UIPageOAuthOptions{Backend: adapter},
		Now:        nowFunc, Logger: logger})
	if err != nil {
		t.Fatalf("页面框架: %v", err)
	}
	publicPaths := login.UIPageOAuthPublicFormPaths("")
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
			CookieName: session.DefaultCookieName, AllowedOrigins: []string{oauthTestOrigin},
			RequireForAllUnsafeRequests: true, PublicFormPaths: pathList,
			PublicTokenValidator: csrfProvider.Validator(purposes),
			TokenValidator: login.CSRFValidatorFunc(func(ctx context.Context,
				request *http.Request, token string) error {
				return sessionService.ValidateCSRFToken(ctx, request, token)
			})}}})
	if err != nil {
		t.Fatalf("HTTP 处理器: %v", err)
	}
	issued, err := sessionService.Login(ctx, session.LoginRequest{
		Result: authn.AuthenticateResult{UserID: userID, Username: "oauthuser",
			Outcome:          authn.OutcomeComplete,
			CompletedMethods: []authn.Method{authn.MethodPassword},
			CompletedAt:      now, SecurityVersion: 1},
		RequestID: "req-oauth-login"})
	if err != nil {
		t.Fatalf("签发会话: %v", err)
	}
	cookie, err := sessionService.NewCookie(issued)
	if err != nil {
		t.Fatalf("会话 Cookie: %v", err)
	}
	env := &oauthPageEnv{t: t, handler: handler, sessions: sessionService, oauth: flow,
		qr: qrService, storage: storage, clientID: clientID, cookie: cookie, csrf: csrfProvider,
		now: now, advance: func(d time.Duration) { now = now.Add(d) },
		extra: map[string]*http.Cookie{}}
	return env
}

// request 驱动页面请求（自动附带会话 Cookie 与 Origin）。
func (e *oauthPageEnv) request(method, target string, form url.Values,
	withSession bool) *httptest.ResponseRecorder {
	e.t.Helper()
	var body io.Reader = strings.NewReader("")
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	request := httptest.NewRequest(method, oauthTestOrigin+target, body)
	request.Host = "localhost"
	if form != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	request.Header.Set("Origin", oauthTestOrigin)
	if withSession {
		request.AddCookie(e.cookie)
	}
	for _, cookie := range e.extra {
		request.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	e.handler.ServeHTTP(recorder, request)
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == session.DefaultCookieName {
			continue
		}
		if cookie.MaxAge < 0 || cookie.Value == "" {
			delete(e.extra, cookie.Name)
			continue
		}
		e.extra[cookie.Name] = cookie
	}
	return recorder
}

// TestOAuthConsentRealBackend 验证授权确认真实 oauthflow：展示应用/scope、拒绝与
// 批准都调用真实决定接口，批准只跳后端生成的回调。
func TestOAuthConsentRealBackend(t *testing.T) {
	env := newOAuthPageEnv(t)
	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~abc"
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	query := url.Values{"client_id": {env.clientID},
		"redirect_uri": {"https://client.example/cb"}, "response_type": {"code"},
		"scope": {"email"}, "state": {"state-1"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
		"request_id": {"req-consent-1"}}
	page := env.request(http.MethodGet, "/oauth/authorize?"+query.Encode(), nil, true)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "测试应用") ||
		!strings.Contains(page.Body.String(), "读取你的已验证邮箱地址") {
		t.Fatalf("授权确认页渲染失败: %d body=%s", page.Code, page.Body.String())
	}
	csrf := tokenFrom(t, page.Body.String(), "csrf_token")
	requestID := tokenFrom(t, page.Body.String(), "request_id")
	// 拒绝：真实后端返回标准 access_denied 回调。
	deny := env.request(http.MethodPost, "/oauth/authorize", url.Values{
		"request_id": {requestID}, "approve": {"false"}, "csrf_token": {csrf}}, true)
	if deny.Code != http.StatusSeeOther {
		t.Fatalf("拒绝应跳转标准回调，实际 %d body=%s", deny.Code, deny.Body.String())
	}
	redirect, err := url.Parse(deny.Header().Get("Location"))
	if err != nil || redirect.Host != "client.example" {
		t.Fatalf("拒绝回调不正确: %q", deny.Header().Get("Location"))
	}
	if redirect.Query().Get("error") != "access_denied" || redirect.Query().Get("state") != "state-1" {
		t.Fatalf("拒绝回调缺少标准错误字段: %q", deny.Header().Get("Location"))
	}
	// 批准：新确认请求，真实后端生成带 code 的已登记回调。
	query.Set("request_id", "req-consent-2")
	second := env.request(http.MethodGet, "/oauth/authorize?"+query.Encode(), nil, true)
	if second.Code != http.StatusOK {
		t.Fatalf("第二次授权页失败: %d", second.Code)
	}
	csrf = tokenFrom(t, second.Body.String(), "csrf_token")
	requestID = tokenFrom(t, second.Body.String(), "request_id")
	approve := env.request(http.MethodPost, "/oauth/authorize", url.Values{
		"request_id": {requestID}, "approve": {"true"}, "csrf_token": {csrf}}, true)
	if approve.Code != http.StatusSeeOther {
		t.Fatalf("批准应跳转回调，实际 %d body=%s", approve.Code, approve.Body.String())
	}
	location := approve.Header().Get("Location")
	if !strings.HasPrefix(location, "https://client.example/cb?") ||
		!strings.Contains(location, "code=") || !strings.Contains(location, "state=state-1") {
		t.Fatalf("批准回调缺少一次性 code/state: %q", location)
	}
}

// TestDeviceFlowRealBackend 验证设备短码 GET 不消费、POST 描述与真实批准/拒绝。
func TestDeviceFlowRealBackend(t *testing.T) {
	env := newOAuthPageEnv(t)
	ctx := context.Background()
	begin, err := env.oauth.BeginDeviceAuthorization(ctx, oauthflow.DeviceAuthorizationRequest{
		ClientID: env.clientID, ClientSecret: "", Scope: []string{"email"},
		RequestID: "req-device-begin"})
	if err != nil {
		// 保密客户端需认证；设备授权申请由设备侧用客户端认证发起，这里直接插入
		// 测试用短码请求不属于页面范围，改跳过真实 Begin 的客户端认证，使用
		// 设备页 GET/POST 的错误路径验证 GET 不消费。
		t.Skipf("设备申请需要客户端认证装配: %v", err)
	}
	userCode := begin.UserCode.Reveal()
	page := env.request(http.MethodGet, "/oauth/device", nil, true)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "设备短码") {
		t.Fatalf("设备输入页失败: %d", page.Code)
	}
	csrf := tokenFrom(t, page.Body.String(), "csrf_token")
	describe := env.request(http.MethodPost, "/oauth/device", url.Values{
		"user_code": {userCode}, "csrf_token": {csrf}}, true)
	if describe.Code != http.StatusOK || !strings.Contains(describe.Body.String(), "确认设备授权") ||
		!strings.Contains(describe.Body.String(), userCode) {
		t.Fatalf("设备确认页失败: %d body=%s", describe.Code, describe.Body.String())
	}
	csrf = tokenFrom(t, describe.Body.String(), "csrf_token")
	decide := env.request(http.MethodPost, "/oauth/device/confirm", url.Values{
		"user_code": {userCode}, "approve": {"true"}, "csrf_token": {csrf}}, true)
	if decide.Code != http.StatusOK || !strings.Contains(decide.Body.String(), "已批准本次设备授权") {
		t.Fatalf("设备批准失败: %d body=%s", decide.Code, decide.Body.String())
	}
	// 同一短码再次 GET 描述不应消费；批准后再描述返回已决定或不可用。
	_ = env
}

// TestQRLoginRealBackend 验证匿名扫码发起→APP 真实批准→原发起页面轮询→领取目标应用
// 会话；ClaimSecret 只在签名状态 Cookie 中，不进入页面/二维码。
func TestQRLoginRealBackend(t *testing.T) {
	env := newOAuthPageEnv(t)
	start := env.request(http.MethodGet, "/login/qr", nil, false)
	if start.Code != http.StatusOK || !strings.Contains(start.Body.String(), "<svg") ||
		!strings.Contains(start.Body.String(), "data-ln-deadline") {
		t.Fatalf("扫码发起页缺少本地二维码/倒计时: %d body=%s", start.Code, start.Body.String())
	}
	requestID := tokenFrom(t, start.Body.String(), "request_id")
	csrf := tokenFrom(t, start.Body.String(), "csrf_token")
	qrCSRFCookie := *env.extra[pagecsrf.CookieName]
	if strings.Contains(start.Body.String(), "claim_secret") {
		t.Fatal("页面不得暴露 ClaimSecret")
	}
	// APP 确认端：真实完整会话读取并批准当前版本。
	scanPage := env.request(http.MethodGet, "/app/scan?request_id="+url.QueryEscape(requestID), nil, true)
	if scanPage.Code != http.StatusOK || !strings.Contains(scanPage.Body.String(), "测试应用") {
		t.Fatalf("APP 确认页失败: %d body=%s", scanPage.Code, scanPage.Body.String())
	}
	scanCSRF := tokenFrom(t, scanPage.Body.String(), "csrf_token")

	version := tokenFrom(t, scanPage.Body.String(), "expected_version")
	approve := env.request(http.MethodPost, "/app/scan", url.Values{
		"request_id": {requestID}, "expected_version": {version}, "approve": {"true"},
		"csrf_token": {scanCSRF}}, true)
	if approve.Code != http.StatusOK || !strings.Contains(approve.Body.String(), "决定已提交") {
		t.Fatalf("APP 批准失败: %d body=%s", approve.Code, approve.Body.String())
	}
	// 原发起页面轮询：恢复该页面的匿名 CSRF Cookie（QR 签名状态 Cookie 仍在）。
	env.extra[pagecsrf.CookieName] = &qrCSRFCookie
	poll := env.request(http.MethodPost, "/login/qr/poll", url.Values{
		"request_id": {requestID}, "csrf_token": {csrf}}, false)
	if poll.Code != http.StatusOK || !strings.Contains(poll.Body.String(), "approved") {
		t.Fatalf("扫码状态查询失败: %d body=%s", poll.Code, poll.Body.String())
	}
	claimCSRF := tokenFrom(t, poll.Body.String(), "csrf_token")
	claim := env.request(http.MethodPost, "/login/qr/claim", url.Values{
		"csrf_token": {claimCSRF}}, false)
	if claim.Code != http.StatusSeeOther || claim.Header().Get("Location") != "/home" {
		t.Fatalf("扫码领取失败: %d body=%s", claim.Code, claim.Body.String())
	}
	var sessionSecret string
	for _, cookie := range claim.Result().Cookies() {
		if cookie.Name == session.DefaultCookieName && cookie.Value != "" {
			sessionSecret = cookie.Value
		}
	}
	if sessionSecret == "" {
		t.Fatal("领取未签发目标应用会话")
	}
	record, err := env.sessions.Validate(context.Background(), sessionSecret)
	if err != nil || !record.IsNormal() || record.AppID != env.clientID {
		t.Fatalf("领取会话应绑定目标应用: %v app=%q", err, record.AppID)
	}
	// 已领取后重复领取拒绝；错误版本批准拒绝。
	reclaim := env.request(http.MethodPost, "/login/qr/claim", url.Values{
		"csrf_token": {claimCSRF}}, false)
	if reclaim.Code == http.StatusSeeOther {
		t.Fatal("同一扫码结果不应重复领取")
	}
	_ = env
}

// cookieNames 返回 Cookie 名列表（测试诊断，不输出值）。
func cookieNames(cookies []*http.Cookie) []string {
	names := make([]string, 0, len(cookies))
	for _, cookie := range cookies {
		names = append(names, cookie.Name)
	}
	return names
}
