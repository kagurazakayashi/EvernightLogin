package protocolapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	appsqlite "github.com/kagurazakayashi/EvernightLogin/internal/app/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
	oauthclientsqlite "github.com/kagurazakayashi/EvernightLogin/internal/oauthclient/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
	oauthflowsqlite "github.com/kagurazakayashi/EvernightLogin/internal/oauthflow/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/oidc"
	oidcsqlite "github.com/kagurazakayashi/EvernightLogin/internal/oidc/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/protocolapi"
	"github.com/kagurazakayashi/EvernightLogin/internal/qrlogin"
	qrsqlite "github.com/kagurazakayashi/EvernightLogin/internal/qrlogin/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	sessionsqlite "github.com/kagurazakayashi/EvernightLogin/internal/session/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/internal/token"
	tokensqlite "github.com/kagurazakayashi/EvernightLogin/internal/token/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// 测试固定配置。issuer 使用 https 公网形式；httptest 只提供本机 http 回环地址，
// 但协议逻辑中的 issuer/origin 校验按配置值进行，测试请求显式带同源 Origin。
const (
	testIssuer = "https://issuer.example.test"

	testUserAlice = "usr_00000000000000000000000000000001"
	testUserBob   = "usr_00000000000000000000000000000002"
	testUserCarol = "usr_00000000000000000000000000000003"

	testClientPublic  = "app_00000000000000000000000000000001" // 授权码 + 刷新
	testClientDevice  = "app_00000000000000000000000000000002" // 纯设备码
	testClientService = "app_00000000000000000000000000000003" // 保密客户端 client_credentials
	testClientDevice2 = "app_00000000000000000000000000000004" // 第二个设备码公开客户端
	testClientPublic2 = "app_00000000000000000000000000000005" // 第二个授权码公开客户端（跨客户端测试）
	testRedirectURI2  = "https://client2.example.test/callback"

	testRedirectURI = "https://client.example.test/callback"
	testAudience    = "https://api.example.test"
	testResourceAPI = "https://api.example.test"

	// RFC 7636 附录 B 的 S256 测试向量。
	testPKCEVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	testPKCEChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

// testClock 是可推进的确定性时钟。
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(duration)
}

// fakeSensitive 是步骤 38/39 敏感策略的测试替身：测试聚焦协议传输层，敏感策略
// 服务本身由既有步骤的测试覆盖；这里始终允许以隔离协议行为。
type fakeSensitive struct {
	mu    sync.Mutex
	allow bool
	calls int
}

func (f *fakeSensitive) Authorize(_ context.Context, _ reauth.Caller,
	request reauth.Request) (reauth.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if !f.allow {
		return reauth.Result{}, reauth.ErrAccessDenied
	}
	return reauth.Result{OperationID: request.OperationID, TargetType: request.TargetType,
		TargetID: request.TargetID, Description: request.Description,
		RequestID: request.RequestID}, nil
}

func (f *fakeSensitive) NotifyOutcome(context.Context, reauth.Result, reauth.Outcome) error {
	return nil
}

// allowAuthorizer 是客户端管理授权测试替身（测试聚焦协议层）。
type allowAuthorizer struct{}

func (allowAuthorizer) AuthorizeClient(context.Context, oauthclient.Caller,
	string, oauthclient.Action) error {
	return nil
}

// allowInspectAuthorizer 是令牌状态查询资源服务授权测试替身。
type allowInspectAuthorizer struct{}

func (allowInspectAuthorizer) AuthorizeInspection(context.Context, string, string) (
	oauthflow.InspectPermission, error) {
	return oauthflow.InspectPermission{Allowed: true, ShowSubject: true}, nil
}

// allowInspectClientAuthorizer 是刷新令牌元数据查询关系授权测试替身。
type allowInspectClientAuthorizer struct{}

func (allowInspectClientAuthorizer) AuthorizeClientInspection(context.Context, string,
	string, string) error {
	return nil
}

// revocationLinker 解决 oidc.Service 需要 oauthflow.Service 做在线撤销检查、而
// oauthflow.Service 又需要 oidc.Service 签发 ID Token 的构造循环：先注入链接器，
// 两个服务构造完成后回填真实实现。
type revocationLinker struct {
	service *oauthflow.Service
}

func (l *revocationLinker) AccessTokenRevoked(ctx context.Context,
	claims token.AccessClaims) (bool, error) {
	if l.service == nil {
		return false, errors.New("撤销检查尚未接线")
	}
	return l.service.AccessTokenRevoked(ctx, claims)
}

// testEnv 是真实临时 SQLite（44 迁移）+ 真实服务 + httptest HTTP 服务的测试环境。
type testEnv struct {
	t             *testing.T
	ctx           context.Context
	clock         *testClock
	raw           *storagesqlite.Store
	audit         *audit.Recorder
	sessions      *session.Service
	tokens        *token.Service
	oidc          *oidc.Service
	flow          *oauthflow.Service
	clientAuth    *oauthclient.Service
	qr            *qrlogin.Service
	server        *protocolapi.Server
	httpServer    *httptest.Server
	logs          *bytes.Buffer
	sensitive     *fakeSensitive
	clientSecrets map[string]string
	client        *http.Client
	// tokenStore/sealer 暴露给验收测试：用于构造“签发方不同但签名密钥相同的真实
	// 令牌”，验证 UserInfo 对错误签发方的拒绝不是靠签名错误冒充的。
	tokenStore *tokensqlite.Store
	sealer     *secrets.Sealer
}

// newTestEnv 装配真实服务与 HTTP 端点。测试失败会影响协议层行为，因此任何装配
// 失败都 t.Fatalf。
func newTestEnv(t *testing.T, mutate func(*protocolapi.Options)) *testEnv {
	t.Helper()
	ctx := context.Background()
	clock := &testClock{now: time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)}
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo}))

	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(
		filepath.Join(testutil.TempDir(t), "protocolapi.db")))
	if err != nil {
		t.Fatalf("打开临时数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	migrationSet, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移失败: %v", err)
	}
	if _, err := raw.Migrate(ctx, migrationSet); err != nil {
		t.Fatalf("执行迁移失败: %v", err)
	}
	auditStore, err := auditsqlite.New(raw)
	if err != nil {
		t.Fatalf("审计存储失败: %v", err)
	}
	recorder, err := audit.New(auditStore, audit.Options{Logger: logger, Now: clock.Now})
	if err != nil {
		t.Fatalf("审计服务失败: %v", err)
	}
	env := &testEnv{t: t, ctx: ctx, clock: clock, raw: raw, audit: recorder, logs: logs}
	env.seedIdentity()

	sessionKeyring, err := secrets.GenerateKeyring("session-k1", clock.Now())
	if err != nil {
		t.Fatalf("会话密钥环失败: %v", err)
	}
	tokenKeyring, err := secrets.GenerateKeyring("token-k1", clock.Now())
	if err != nil {
		t.Fatalf("令牌密钥环失败: %v", err)
	}
	sealer, err := secrets.NewSealer(tokenKeyring, nil)
	if err != nil {
		t.Fatalf("密文封装器失败: %v", err)
	}
	deviceKeyring, err := secrets.GenerateKeyring("device-k1", clock.Now())
	if err != nil {
		t.Fatalf("设备短码密钥环失败: %v", err)
	}
	qrKeyring, err := secrets.GenerateKeyring("qr-k1", clock.Now())
	if err != nil {
		t.Fatalf("扫码密钥环失败: %v", err)
	}

	sessionStore, err := sessionsqlite.New(raw)
	if err != nil {
		t.Fatalf("会话存储失败: %v", err)
	}
	env.sessions, err = session.New(sessionStore, session.Options{
		Store: sessionStore, Audit: recorder, Keyring: sessionKeyring,
		IdleTimeout: 30 * time.Minute, AbsoluteTimeout: 12 * time.Hour,
		AllowLegacyWithoutSensitive: true, Logger: logger, Now: clock.Now,
	})
	if err != nil {
		t.Fatalf("会话服务失败: %v", err)
	}

	clientStore, err := oauthclientsqlite.New(raw)
	if err != nil {
		t.Fatalf("OAuth 客户端存储失败: %v", err)
	}
	env.sensitive = &fakeSensitive{allow: true}
	env.clientAuth, err = oauthclient.New(oauthclient.Options{
		Store: clientStore, Audit: recorder, Authorizer: allowAuthorizer{},
		Sensitive: env.sensitive, Now: clock.Now, Logger: logger,
	})
	if err != nil {
		t.Fatalf("OAuth 客户端服务失败: %v", err)
	}
	env.registerClients(clientStore)

	tokenStore, err := tokensqlite.New(raw)
	if err != nil {
		t.Fatalf("令牌存储失败: %v", err)
	}
	env.tokenStore = tokenStore
	env.sealer = sealer
	tokenClients, err := token.NewOAuthClientSource(clientStore)
	if err != nil {
		t.Fatalf("令牌客户端来源失败: %v", err)
	}
	env.tokens, err = token.New(token.Options{
		Store: tokenStore, Audit: recorder, Sealer: sealer, Issuer: testIssuer,
		Clients: tokenClients,
		Authorizer: token.IssuanceAuthorizerFunc(func(_ context.Context, _ token.Caller,
			request token.IssuanceRequest) error {
			if request.TokenKind == token.TokenUseAccess &&
				(request.GrantType == token.GrantAuthorizationCode ||
					request.GrantType == token.GrantDeviceCode ||
					request.GrantType == token.GrantClientCredentials) {
				return nil
			}
			if request.TokenKind == token.TokenUseID &&
				request.GrantType == token.GrantAuthorizationCode {
				return nil
			}
			return token.ErrAccessDenied
		}),
		KeyRetention: 24 * time.Hour, Now: clock.Now, Logger: logger,
	})
	if err != nil {
		t.Fatalf("令牌服务失败: %v", err)
	}
	oidcStore, err := oidcsqlite.New(raw)
	if err != nil {
		t.Fatalf("OIDC 用户存储失败: %v", err)
	}
	linker := &revocationLinker{}
	env.oidc, err = oidc.New(oidc.Options{
		Issuer: testIssuer, AuthorizationEndpoint: testIssuer + protocolapi.PathAuthorize,
		TokenEndpoint:    testIssuer + protocolapi.PathToken,
		UserInfoEndpoint: testIssuer + protocolapi.PathUserInfo,
		JWKSURI:          testIssuer + protocolapi.PathJWKS,
		Tokens:           env.tokens, Users: oidcStore, RevocationChecker: linker,
		SubjectSecret: []byte("protocolapi-test-subject-secret-32b"),
		Now:           clock.Now,
	})
	if err != nil {
		t.Fatalf("OIDC 服务失败: %v", err)
	}
	flowStore, err := oauthflowsqlite.New(raw)
	if err != nil {
		t.Fatalf("授权流程存储失败: %v", err)
	}
	flowClients, err := oauthflow.NewOAuthClientSource(clientStore)
	if err != nil {
		t.Fatalf("授权客户端来源失败: %v", err)
	}
	env.flow, err = oauthflow.New(oauthflow.Options{
		Store: flowStore, Audit: recorder, Clients: flowClients,
		ClientAuth: env.clientAuth, Sessions: env.sessions,
		SessionRevoker: env.sessions, Tokens: env.tokens, Reauth: env.sensitive,
		OIDC: env.oidc, TokenVerifier: env.tokens,
		InspectAuthorizer:       allowInspectAuthorizer{},
		InspectClientAuthorizer: allowInspectClientAuthorizer{},
		DeviceVerificationURI:   testIssuer + "/device",
		DeviceUserCodeKeyring:   deviceKeyring,
		Now:                     clock.Now, Logger: logger,
	})
	if err != nil {
		t.Fatalf("授权流程服务失败: %v", err)
	}
	linker.service = env.flow

	appStore, err := appsqlite.New(raw)
	if err != nil {
		t.Fatalf("应用存储失败: %v", err)
	}
	qrStore, err := qrsqlite.New(raw)
	if err != nil {
		t.Fatalf("扫码登录存储失败: %v", err)
	}
	env.qr, err = qrlogin.New(qrlogin.Options{
		Store: qrStore, Audit: recorder, Clients: clientStore, Applications: appStore,
		Sessions: env.sessions, SessionIssuer: env.sessions, Reauth: env.sensitive,
		Keyring: qrKeyring, Enabled: true, AllowedClientIDs: []string{testClientPublic},
		RequestTTL: 2 * time.Minute, ClaimInterval: time.Second,
		Now: clock.Now, Logger: logger,
	})
	if err != nil {
		t.Fatalf("扫码登录服务失败: %v", err)
	}

	options := protocolapi.Options{
		OAuth: env.flow, OIDC: env.oidc, Tokens: env.tokens, Sessions: env.sessions,
		ClientAuth: env.clientAuth, QRLogin: env.qr, QRClientID: testClientPublic,
		QRScopes: []string{"profile"}, EnableDeviceFlow: true, EnableIntrospection: true,
		Logger: logger, Now: clock.Now,
	}
	if mutate != nil {
		mutate(&options)
	}
	env.server, err = protocolapi.New(options)
	if err != nil {
		t.Fatalf("构造协议端点失败: %v", err)
	}
	env.httpServer = httptest.NewServer(env.server.Handler())
	t.Cleanup(env.httpServer.Close)
	// 不自动跟随重定向：协议断言需要检查 303 与 Location。
	env.client = &http.Client{
		Transport: env.httpServer.Client().Transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return env
}

// seedIdentity 写入用户（含已验证邮箱）、应用、成员关系与应用 scope。
func (e *testEnv) seedIdentity() {
	e.t.Helper()
	now := e.clock.Now().UnixMilli()
	exec := func(query string, args ...any) {
		e.t.Helper()
		if _, err := e.raw.ExecContext(e.ctx, query, args...); err != nil {
			e.t.Fatalf("插入测试数据失败: %v\nSQL: %s", err, query)
		}
	}
	insertUser := func(userID, username, nickname string) {
		exec(`INSERT INTO users(id,username,username_normalized,nickname,biography,avatar_ref,
language,timezone,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,?, '',NULL,'zh-CN','Asia/Shanghai','active',0,1,1,?,?)`,
			userID, username, username, nickname, now, now)
	}
	insertUser(testUserAlice, "alice", "Alice")
	insertUser(testUserBob, "bob", "Bob")
	insertUser(testUserCarol, "carol", "Carol")
	exec(`INSERT INTO user_emails(email_normalized,user_id,email,verified_at_ms,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?)`, "alice@example.test", testUserAlice, "alice@example.test", now, now, now)
	insertApplication := func(applicationID, name, clientType string) {
		exec(`INSERT INTO applications(id,name,description,status,client_type,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,'', 'active', ?,1,?,?)`, applicationID, name, clientType, now, now)
		exec(`INSERT INTO scopes(id,kind,app_id) VALUES(?,'application',?)`, applicationID, applicationID)
	}
	insertApplication(testClientPublic, "协议演示应用", "public")
	insertApplication(testClientDevice, "设备码应用", "public")
	insertApplication(testClientService, "服务身份应用", "confidential")
	insertApplication(testClientDevice2, "第二设备码应用", "public")
	insertApplication(testClientPublic2, "第二授权码应用", "public")
	for _, applicationID := range []string{testClientPublic, testClientDevice,
		testClientService, testClientDevice2, testClientPublic2} {
		for _, userID := range []string{testUserAlice, testUserBob, testUserCarol} {
			exec(`INSERT INTO app_memberships(app_id,user_id,status,profile_json,row_version,
created_at_ms,updated_at_ms) VALUES(?,?,'active','{"v":1}',1,?,?)`,
				applicationID, userID, now, now)
		}
	}
}

// registerClients 用真实 oauthclient 服务登记三个客户端（公开授权的公开客户端、
// 纯设备码公开客户端、client_credentials 保密客户端）。
func (e *testEnv) registerClients(store *oauthclientsqlite.Store) {
	e.t.Helper()
	_ = store
	caller, err := oauthclient.SystemCaller("protocolapi-test")
	if err != nil {
		e.t.Fatalf("构造客户端管理调用者失败: %v", err)
	}
	requirePKCE := true
	register := func(request oauthclient.RegisterRequest) {
		e.t.Helper()
		request.RequestID = "req_register_" + request.ClientID
		request.RequirePKCE = &requirePKCE
		result, registerErr := e.clientAuth.RegisterClient(e.ctx, caller, request)
		if registerErr != nil {
			e.t.Fatalf("登记客户端 %s 失败: %v", request.ClientID, registerErr)
		}
		if result.Secret != nil {
			e.seedClientSecret(request.ClientID, result.Secret.Secret)
		}
	}
	register(oauthclient.RegisterRequest{
		ClientID: testClientPublic, ClientType: oauthclient.ClientTypePublic,
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		RedirectURIs: []string{testRedirectURI},
		Scopes:       []string{"openid", "profile", "email", "offline_access"},
		Audiences:    []string{testIssuer, testResourceAPI},
	})
	register(oauthclient.RegisterRequest{
		ClientID: testClientDevice, ClientType: oauthclient.ClientTypePublic,
		GrantTypes: []string{string(oauthclient.GrantDeviceCode)},
		Scopes:     []string{"profile", "email"},
		Audiences:  []string{testResourceAPI},
	})
	register(oauthclient.RegisterRequest{
		ClientID: testClientDevice2, ClientType: oauthclient.ClientTypePublic,
		GrantTypes: []string{string(oauthclient.GrantDeviceCode)},
		Scopes:     []string{"profile"},
		Audiences:  []string{testResourceAPI},
	})
	register(oauthclient.RegisterRequest{
		ClientID: testClientPublic2, ClientType: oauthclient.ClientTypePublic,
		GrantTypes:   []string{"authorization_code"},
		RedirectURIs: []string{testRedirectURI2},
		Scopes:       []string{"openid"},
		Audiences:    []string{testIssuer},
	})
	register(oauthclient.RegisterRequest{
		ClientID: testClientService, ClientType: oauthclient.ClientTypeConfidential,
		GrantTypes:  []string{"client_credentials"},
		Scopes:      []string{"service.read"},
		Audiences:   []string{testResourceAPI},
		AuthMethods: []string{"client_secret_post"},
	})
}

// clientSecrets 保存登记返回的客户端密钥明文（仅测试内存）。
func (e *testEnv) seedClientSecret(clientID, secret string) {
	if e.clientSecrets == nil {
		e.clientSecrets = make(map[string]string)
	}
	e.clientSecrets[clientID] = secret
}

// login 以给定用户签发普通会话，返回会话秘密与 Cookie。
func (e *testEnv) login(userID string) (session.IssuedSession, *http.Cookie) {
	e.t.Helper()
	issued, err := e.sessions.Login(e.ctx, session.LoginRequest{
		Result: authn.AuthenticateResult{
			UserID: userID, Username: userNames[userID], Outcome: authn.OutcomeComplete,
			CompletedMethods: []authn.Method{authn.MethodPassword},
			CompletedAt:      e.clock.Now(), SecurityVersion: 1,
		},
		RequestID: "req_login_" + userID,
	})
	if err != nil {
		e.t.Fatalf("签发测试会话失败: %v", err)
	}
	cookie, err := e.sessions.NewCookie(issued)
	if err != nil {
		e.t.Fatalf("构造会话 Cookie 失败: %v", err)
	}
	return issued, cookie
}

// issueDirectToken 用真实令牌服务签发一个访问令牌（用于激活签名密钥等装配性
// 测试；它不经过协议端点，不对应任何“客户端可自行铸造令牌”的通道）。
func (e *testEnv) issueDirectToken(scopes []string) string {
	e.t.Helper()
	caller, err := token.SystemCaller("protocolapi-test")
	if err != nil {
		e.t.Fatalf("构造系统签发身份失败: %v", err)
	}
	issued, err := e.tokens.IssueAccessToken(e.ctx, caller, token.IssueAccessTokenRequest{
		ClientID: testClientPublic, SubjectUserID: testUserAlice,
		GrantType: token.GrantAuthorizationCode, Scopes: scopes,
		Audiences: []string{testResourceAPI}, RequestID: "req_direct_token"})
	if err != nil {
		e.t.Fatalf("签发测试访问令牌失败: %v", err)
	}
	return issued.Token.Reveal()
}

// url 返回 httptest 服务地址 + 路径。
func (e *testEnv) url(path string) string { return e.httpServer.URL + path }

// do 执行一次 HTTP 请求；cookie 非 nil 时附加 Cookie 头，body 非 nil 时作为 JSON
// 编码（Content-Type: application/json），否则按 values 编码为表单。
type requestOptions struct {
	cookie *http.Cookie
	form   url.Values
	json   any
	header map[string]string
}

// doRequest 执行请求并返回响应与完整正文。
func (e *testEnv) doRequest(method, path string, options requestOptions) (*http.Response, []byte) {
	e.t.Helper()
	var body io.Reader
	contentType := ""
	switch {
	case options.json != nil:
		encoded, err := json.Marshal(options.json)
		if err != nil {
			e.t.Fatalf("编码 JSON 请求失败: %v", err)
		}
		body = bytes.NewReader(encoded)
		contentType = "application/json"
	case options.form != nil:
		body = strings.NewReader(options.form.Encode())
		contentType = "application/x-www-form-urlencoded"
	}
	request, err := http.NewRequestWithContext(e.ctx, method, e.url(path), body)
	if err != nil {
		e.t.Fatalf("构造请求失败: %v", err)
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	if options.cookie != nil {
		request.AddCookie(options.cookie)
	}
	for name, value := range options.header {
		request.Header.Set(name, value)
	}
	response, err := e.client.Do(request)
	if err != nil {
		e.t.Fatalf("执行请求失败: %v", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		e.t.Fatalf("读取响应失败: %v", err)
	}
	return response, responseBody
}

// decodeJSON 解码响应 JSON 为 map，失败时输出正文便于排障。
func (e *testEnv) decodeJSON(body []byte) map[string]any {
	e.t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		e.t.Fatalf("响应不是合法 JSON: %v\n%s", err, body)
	}
	return decoded
}

// countAudit 统计指定动作的审计事件数（真实审计表）。
func (e *testEnv) countAudit(action string) int64 {
	e.t.Helper()
	rows, err := e.raw.QueryContext(e.ctx,
		`SELECT COUNT(*) FROM audit_events WHERE action=?`, action)
	if err != nil {
		e.t.Fatalf("查询审计失败: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return 0
	}
	var count int64
	if err := rows.Scan(&count); err != nil {
		e.t.Fatalf("扫描审计失败: %v", err)
	}
	return count
}

// queryString 读取单行单列字符串（测试断言用）。
func (e *testEnv) queryString(query string, args ...any) string {
	e.t.Helper()
	rows, err := e.raw.QueryContext(e.ctx, query, args...)
	if err != nil {
		e.t.Fatalf("查询失败: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return ""
	}
	var value string
	if err := rows.Scan(&value); err != nil {
		e.t.Fatalf("扫描失败: %v", err)
	}
	return value
}

// queryInt 读取单行单列整数。
func (e *testEnv) queryInt(query string, args ...any) int64 {
	e.t.Helper()
	value := e.queryString(query, args...)
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0
	}
	return parsed
}

// userNames 是测试用户的显示用户名（会话签发要求真实用户名）。
var userNames = map[string]string{
	testUserAlice: "alice", testUserBob: "bob", testUserCarol: "carol",
}
