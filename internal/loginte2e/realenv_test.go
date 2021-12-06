package loginte2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
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

// 本文件用真实 SQLite + 真实领域服务 + 真实 internal/protocolapi HTTP 处理程序
// 做端到端验收：这是“用 httptest + 真实 protocolapi 服务”的库测试证据。
// 它证明工具能对真实协议实现跑通全流程，但不等于真实浏览器/真机互操作验收。

const (
	realTestIssuer = "https://issuer.example.test"

	realUserAlice = "usr_00000000000000000000000000000001"

	realClientPublic = "app_00000000000000000000000000000001"
	realClientDevice = "app_00000000000000000000000000000002"

	realRedirectURI = "https://client.example.test/callback"
	realAudience    = "https://api.example.test"
)

// realClock 是“固定起点 + 真实流逝”的测试时钟：起点确定便于断言，时间会随墙钟
// 前进，使设备码/扫码轮询的间隔与过期语义在真实服务里可推进（固定时钟会让服务端
// 认为轮询永远过快）。
type realClock struct {
	base    time.Time
	started time.Time
}

// Now 返回当前测试时间（单调前进）。
func (c *realClock) Now() time.Time {
	return c.base.Add(time.Since(c.started).Truncate(time.Millisecond))
}

// allowSensitive 是敏感策略测试替身（始终允许）；生产敏感策略由既有步骤测试。
type allowSensitive struct{}

// Authorize 实现 reauth.OperationRunner（与协议包测试的允许替身一致：回填真实
// 操作标识，不伪造授权结论的来源）。
func (allowSensitive) Authorize(_ context.Context, _ reauth.Caller,
	request reauth.Request) (reauth.Result, error) {
	return reauth.Result{OperationID: request.OperationID, TargetType: request.TargetType,
		TargetID: request.TargetID, Description: request.Description,
		RequestID: request.RequestID}, nil
}

// NotifyOutcome 实现 reauth.OperationRunner。
func (allowSensitive) NotifyOutcome(context.Context, reauth.Result, reauth.Outcome) error {
	return nil
}

// allowClientAuthorizer 是客户端管理授权测试替身。
type allowClientAuthorizer struct{}

// AuthorizeClient 实现 oauthclient.Authorizer。
func (allowClientAuthorizer) AuthorizeClient(context.Context, oauthclient.Caller,
	string, oauthclient.Action) error {
	return nil
}

// allowInspectAuthorizer 是状态查询授权测试替身。
type allowInspectAuthorizer struct{}

// AuthorizeInspection 实现 oauthflow.InspectAuthorizer。
func (allowInspectAuthorizer) AuthorizeInspection(context.Context, string, string) (
	oauthflow.InspectPermission, error) {
	return oauthflow.InspectPermission{Allowed: true, ShowSubject: true}, nil
}

// allowInspectClientAuthorizer 是刷新族关系授权测试替身。
type allowInspectClientAuthorizer struct{}

// AuthorizeClientInspection 实现 oauthflow.ClientInspectAuthorizer。
func (allowInspectClientAuthorizer) AuthorizeClientInspection(context.Context, string,
	string, string) error {
	return nil
}

// revocationLinker 解决 oidc ↔ oauthflow 的构造循环。
type revocationLinker struct{ service *oauthflow.Service }

// AccessTokenRevoked 实现 oidc 在线撤销检查契约。
func (l *revocationLinker) AccessTokenRevoked(ctx context.Context,
	claims token.AccessClaims) (bool, error) {
	if l.service == nil {
		return false, errors.New("撤销检查尚未接线")
	}
	return l.service.AccessTokenRevoked(ctx, claims)
}

// realEnv 是真实协议服务测试环境。
type realEnv struct {
	clock      *realClock
	sessions   *session.Service
	flow       *oauthflow.Service
	tokens     *token.Service
	httpServer *httptest.Server
	secret     string
	logs       *bytes.Buffer
}

// newRealEnv 装配真实 SQLite（全量迁移）+ 真实服务 + httptest 协议端点。
func newRealEnv(t *testing.T) *realEnv {
	t.Helper()
	ctx := context.Background()
	clock := &realClock{base: time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC),
		started: time.Now()}
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo}))

	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(
		filepath.Join(testutil.TempDir(t), "loginte2e.db")))
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
	seedRealIdentity(t, raw, clock)

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
	sessionService, err := session.New(sessionStore, session.Options{
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
	clientAuth, err := oauthclient.New(oauthclient.Options{
		Store: clientStore, Audit: recorder, Authorizer: allowClientAuthorizer{},
		Sensitive: allowSensitive{}, Now: clock.Now, Logger: logger,
	})
	if err != nil {
		t.Fatalf("OAuth 客户端服务失败: %v", err)
	}
	registerRealClients(t, ctx, clientAuth)
	tokenStore, err := tokensqlite.New(raw)
	if err != nil {
		t.Fatalf("令牌存储失败: %v", err)
	}
	tokenClients, err := token.NewOAuthClientSource(clientStore)
	if err != nil {
		t.Fatalf("令牌客户端来源失败: %v", err)
	}
	tokens, err := token.New(token.Options{
		Store: tokenStore, Audit: recorder, Sealer: sealer, Issuer: realTestIssuer,
		Clients: tokenClients,
		Authorizer: token.IssuanceAuthorizerFunc(func(_ context.Context, _ token.Caller,
			request token.IssuanceRequest) error {
			if request.TokenKind == token.TokenUseAccess &&
				(request.GrantType == token.GrantAuthorizationCode ||
					request.GrantType == token.GrantDeviceCode) {
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
	oidcService, err := oidc.New(oidc.Options{
		Issuer: realTestIssuer, AuthorizationEndpoint: realTestIssuer + protocolapi.PathAuthorize,
		TokenEndpoint:    realTestIssuer + protocolapi.PathToken,
		UserInfoEndpoint: realTestIssuer + protocolapi.PathUserInfo,
		JWKSURI:          realTestIssuer + protocolapi.PathJWKS,
		Tokens:           tokens, Users: oidcStore, RevocationChecker: linker,
		SubjectSecret: []byte("loginte2e-test-subject-secret-32"),
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
	flow, err := oauthflow.New(oauthflow.Options{
		Store: flowStore, Audit: recorder, Clients: flowClients,
		ClientAuth: clientAuth, Sessions: sessionService,
		SessionRevoker: sessionService, Tokens: tokens, Reauth: allowSensitive{},
		OIDC: oidcService, TokenVerifier: tokens,
		InspectAuthorizer:       allowInspectAuthorizer{},
		InspectClientAuthorizer: allowInspectClientAuthorizer{},
		DeviceVerificationURI:   realTestIssuer + "/device",
		DeviceUserCodeKeyring:   deviceKeyring,
		Now:                     clock.Now, Logger: logger,
	})
	if err != nil {
		t.Fatalf("授权流程服务失败: %v", err)
	}
	linker.service = flow
	appStore, err := appsqlite.New(raw)
	if err != nil {
		t.Fatalf("应用存储失败: %v", err)
	}
	qrStore, err := qrsqlite.New(raw)
	if err != nil {
		t.Fatalf("扫码存储失败: %v", err)
	}
	qrService, err := qrlogin.New(qrlogin.Options{
		Store: qrStore, Audit: recorder, Clients: clientStore, Applications: appStore,
		Sessions: sessionService, SessionIssuer: sessionService, Reauth: allowSensitive{},
		Keyring: qrKeyring, Enabled: true, AllowedClientIDs: []string{realClientPublic},
		RequestTTL: 2 * time.Minute, ClaimInterval: time.Second,
		Now: clock.Now, Logger: logger,
	})
	if err != nil {
		t.Fatalf("扫码登录服务失败: %v", err)
	}
	server, err := protocolapi.New(protocolapi.Options{
		OAuth: flow, OIDC: oidcService, Tokens: tokens, Sessions: sessionService,
		ClientAuth: clientAuth, QRLogin: qrService, QRClientID: realClientPublic,
		QRScopes: []string{"profile"}, EnableDeviceFlow: true, EnableIntrospection: true,
		Logger: logger, Now: clock.Now,
	})
	if err != nil {
		t.Fatalf("构造协议端点失败: %v", err)
	}
	httpServer := httptest.NewServer(server.Handler())
	t.Cleanup(httpServer.Close)

	// 以真实会话服务签发 alice 的完整普通会话（模拟已登录用户）。
	issued, err := sessionService.Login(ctx, session.LoginRequest{
		Result: authn.AuthenticateResult{
			UserID: realUserAlice, Username: "alice", Outcome: authn.OutcomeComplete,
			CompletedMethods: []authn.Method{authn.MethodPassword},
			CompletedAt:      clock.Now(), SecurityVersion: 1,
		},
		RequestID: "req_loginte2e_login",
	})
	if err != nil {
		t.Fatalf("签发测试会话失败: %v", err)
	}
	env := &realEnv{clock: clock, sessions: sessionService, flow: flow, tokens: tokens,
		httpServer: httpServer, secret: issued.Secret.Reveal(), logs: logs}
	// 令牌服务的签名密钥在首次签发时激活：先签发一个测试令牌，保证 JWKS 有公钥
	// （与 protocolapi 测试环境的装配步骤一致；探针令牌不经过协议端点）。
	if err := env.activateSigningKey(); err != nil {
		t.Fatalf("激活签名密钥失败: %v", err)
	}
	return env
}

// seedRealIdentity 写入合成用户、应用、成员关系与应用 scope。
func seedRealIdentity(t *testing.T, raw *storagesqlite.Store, clock *realClock) {
	t.Helper()
	now := clock.Now().UnixMilli()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := raw.ExecContext(context.Background(), query, args...); err != nil {
			t.Fatalf("插入测试数据失败: %v\nSQL: %s", err, query)
		}
	}
	exec(`INSERT INTO users(id,username,username_normalized,nickname,biography,avatar_ref,
language,timezone,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,'alice','Alice','',NULL,'zh-CN','Asia/Shanghai','active',0,1,1,?,?)`,
		realUserAlice, "alice", now, now)
	for _, applicationID := range []string{realClientPublic, realClientDevice} {
		exec(`INSERT INTO applications(id,name,description,status,client_type,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,'', 'active','public',1,?,?)`, applicationID, "loginte2e 应用", now, now)
		exec(`INSERT INTO scopes(id,kind,app_id) VALUES(?,'application',?)`,
			applicationID, applicationID)
		exec(`INSERT INTO app_memberships(app_id,user_id,status,profile_json,row_version,
created_at_ms,updated_at_ms) VALUES(?,?,'active','{"v":1}',1,?,?)`,
			applicationID, realUserAlice, now, now)
	}
}

// registerRealClients 用真实客户端服务登记公开授权码客户端与设备码客户端。
func registerRealClients(t *testing.T, ctx context.Context, clientAuth *oauthclient.Service) {
	t.Helper()
	caller, err := oauthclient.SystemCaller("loginte2e-test")
	if err != nil {
		t.Fatalf("构造客户端管理调用者失败: %v", err)
	}
	requirePKCE := true
	register := func(request oauthclient.RegisterRequest) {
		t.Helper()
		request.RequestID = "req_register_" + request.ClientID
		request.RequirePKCE = &requirePKCE
		if _, registerErr := clientAuth.RegisterClient(ctx, caller, request); registerErr != nil {
			t.Fatalf("登记客户端 %s 失败: %v", request.ClientID, registerErr)
		}
	}
	register(oauthclient.RegisterRequest{
		ClientID: realClientPublic, ClientType: oauthclient.ClientTypePublic,
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		RedirectURIs: []string{realRedirectURI},
		Scopes:       []string{"openid", "profile", "email", "offline_access"},
		Audiences:    []string{realTestIssuer, realAudience},
	})
	register(oauthclient.RegisterRequest{
		ClientID: realClientDevice, ClientType: oauthclient.ClientTypePublic,
		GrantTypes: []string{string(oauthclient.GrantDeviceCode)},
		Scopes:     []string{"profile", "email"},
		Audiences:  []string{realAudience},
	})
}

// activateSigningKey 通过真实令牌服务签发一个测试访问令牌以激活签名密钥/JWKS。
func (e *realEnv) activateSigningKey() error {
	caller, err := token.SystemCaller("loginte2e-test")
	if err != nil {
		return err
	}
	_, err = e.tokens.IssueAccessToken(context.Background(), caller,
		token.IssueAccessTokenRequest{ClientID: realClientPublic, SubjectUserID: realUserAlice,
			GrantType: token.GrantAuthorizationCode, Scopes: []string{"openid", "profile"},
			Audiences: []string{realTestIssuer}, RequestID: "req_loginte2e_activate"})
	return err
}

// deviceConfirmer 用真实 oauthflow 服务完成“已登录用户确认设备码”。
func (e *realEnv) deviceConfirmer() DeviceConfirmFunc {
	return func(ctx context.Context, userCode string) error {
		_, err := e.flow.DecideDeviceAuthorization(ctx, e.secret,
			oauthflow.DeviceDecisionRequest{UserCode: userCode, Approve: true,
				RequestID: "req_loginte2e_device_confirm"})
		return err
	}
}

// assertReportNoSecret 断言报告不包含会话秘密或 JWT。
func assertReportNoSecret(t *testing.T, report *Report, secretsToHide ...string) {
	t.Helper()
	payload, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("编码报告失败: %v", err)
	}
	text := string(payload)
	for _, secret := range secretsToHide {
		if secret == "" {
			continue
		}
		if bytes.Contains(payload, []byte(secret)) || containsStringFold(text, secret) {
			t.Fatalf("报告泄露了会话秘密/令牌")
		}
	}
	if containsStringFold(text, "eyJ") {
		t.Fatalf("报告出现了 JWT 片段（令牌不应写入报告）")
	}
}

// reportFailureDetails 在失败时输出每条失败用例，便于定位。
func reportFailureDetails(t *testing.T, report *Report) {
	t.Helper()
	if report.Summary.Fail == 0 {
		return
	}
	for _, result := range report.Results {
		if result.Status == StatusFail {
			t.Logf("[FAIL] %s/%s: %s", result.Suite, result.Case, result.Detail)
		}
	}
}

// TestRealProtocolAPIAuthCodeFamily 对真实 protocolapi 服务运行 discovery/jwks/
// authcode/token/qr 套件（共用公开授权码客户端与真实登录会话）。
func TestRealProtocolAPIAuthCodeFamily(t *testing.T) {
	env := newRealEnv(t)
	client, err := New(Config{
		Server: env.httpServer.URL, ExpectedIssuer: realTestIssuer,
		ClientID: realClientPublic, RedirectURI: realRedirectURI,
		Scopes:        []string{"openid", "profile", "email", "offline_access"},
		SessionSecret: env.secret,
		PollTimeout:   30 * time.Second,
		Now:           env.clock.Now,
	})
	if err != nil {
		t.Fatalf("构造测试客户端失败: %v", err)
	}
	defer client.Close()
	for _, suite := range []string{SuiteDiscovery, SuiteJWKS, SuiteAuthCode, SuiteToken, SuiteQR} {
		t.Run(suite, func(t *testing.T) {
			report, runErr := client.Run(context.Background(), suite)
			if runErr != nil {
				t.Fatalf("套件 %s 无法继续: %v", suite, runErr)
			}
			reportFailureDetails(t, report)
			if report.Summary.Fail > 0 {
				t.Fatalf("套件 %s 有 %d 条失败", suite, report.Summary.Fail)
			}
			if report.Summary.Pass == 0 {
				t.Fatalf("套件 %s 没有通过任何用例", suite)
			}
			assertReportNoSecret(t, report, env.secret)
			if report.ExitCode() != ExitPass {
				t.Fatalf("套件 %s 退出码 = %d，期望 0", suite, report.ExitCode())
			}
		})
	}
}

// TestRealProtocolAPIDeviceFlow 对真实服务运行设备码套件（真实领域服务完成确认）。
func TestRealProtocolAPIDeviceFlow(t *testing.T) {
	env := newRealEnv(t)
	client, err := New(Config{
		Server: env.httpServer.URL, ExpectedIssuer: realTestIssuer,
		ClientID: realClientDevice, Scopes: []string{"profile", "email"},
		SessionSecret: env.secret, PollTimeout: 60 * time.Second,
		DeviceConfirm: env.deviceConfirmer(), Now: env.clock.Now,
	})
	if err != nil {
		t.Fatalf("构造测试客户端失败: %v", err)
	}
	defer client.Close()
	report, runErr := client.Run(context.Background(), SuiteDevice)
	if runErr != nil {
		t.Fatalf("设备码套件无法继续: %v", runErr)
	}
	reportFailureDetails(t, report)
	if report.Summary.Fail > 0 {
		t.Fatalf("设备码套件有 %d 条失败", report.Summary.Fail)
	}
	if report.Summary.Pass == 0 {
		t.Fatal("设备码套件没有通过任何用例")
	}
	assertReportNoSecret(t, report, env.secret)
}

// TestRealProtocolAPIAllSuite 验证 all 套件能给出一条汇总报告（协议部分）。
func TestRealProtocolAPIAllSuite(t *testing.T) {
	env := newRealEnv(t)
	client, err := New(Config{
		Server: env.httpServer.URL, ExpectedIssuer: realTestIssuer,
		ClientID: realClientPublic, RedirectURI: realRedirectURI,
		Scopes:        []string{"openid", "profile", "email", "offline_access"},
		SessionSecret: env.secret, PollTimeout: 20 * time.Second,
		DeviceConfirm: env.deviceConfirmer(), Now: env.clock.Now,
	})
	if err != nil {
		t.Fatalf("构造测试客户端失败: %v", err)
	}
	defer client.Close()
	report, runErr := client.Run(context.Background(), SuiteAll)
	if runErr != nil {
		t.Fatalf("all 套件无法继续: %v", runErr)
	}
	if len(report.Results) == 0 {
		t.Fatal("all 套件没有产生任何结果")
	}
	// 设备码用授权码客户端会被服务端拒绝（未登记设备码 grant）：相关用例失败是
	// 预期的客户端配置问题，因此这里只断言报告结构与非协议套件的结果。
	if report.Summary.Pass == 0 {
		t.Fatal("all 套件没有通过任何用例")
	}
	seen := map[string]bool{}
	for _, result := range report.Results {
		seen[result.Suite] = true
	}
	for _, suite := range []string{SuiteDiscovery, SuiteJWKS, SuiteAuthCode, SuiteToken, SuiteQR} {
		if !seen[suite] {
			t.Fatalf("all 套件报告缺少 %s 的结果", suite)
		}
	}
	assertReportNoSecret(t, report, env.secret)
}
