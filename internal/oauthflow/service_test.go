package oauthflow_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
	oauthclientsqlite "github.com/kagurazakayashi/EvernightLogin/internal/oauthclient/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
	oauthflowsqlite "github.com/kagurazakayashi/EvernightLogin/internal/oauthflow/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	sessionsqlite "github.com/kagurazakayashi/EvernightLogin/internal/session/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/token"
	tokensqlite "github.com/kagurazakayashi/EvernightLogin/internal/token/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const (
	testUserID    = "usr_00000000000000000000000000000001"
	testAppID     = "app_00000000000000000000000000000001"
	testAppID2    = "app_00000000000000000000000000000002"
	testAudience  = "https://api.example.test"
	testRedirect  = "https://client.example.test/callback"
	testRedirect2 = "https://client2.example.test/callback"
	// RFC 7636 附录 B 的 S256 测试向量。
	pkceVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	pkceChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

// fakeReauth 是步骤 39 收敛入口的测试替身；allow=false 模拟近期认证不足。
type fakeReauth struct {
	mu             sync.Mutex
	allow          bool
	authorizeCalls int
	notifyCalls    int
	lastRequest    reauth.Request
}

func (f *fakeReauth) Authorize(_ context.Context, _ reauth.Caller,
	request reauth.Request) (reauth.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.authorizeCalls++
	f.lastRequest = request
	if !f.allow {
		return reauth.Result{}, reauth.ErrAccessDenied
	}
	return reauth.Result{OperationID: request.OperationID, TargetType: request.TargetType,
		TargetID: request.TargetID, Description: request.Description, RequestID: request.RequestID}, nil
}

func (f *fakeReauth) NotifyOutcome(_ context.Context, _ reauth.Result, _ reauth.Outcome) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.notifyCalls++
	return nil
}

// fakeClientAuth 只用于保密客户端的客户端认证测试；生产适配器已由步骤 49 实测。
type fakeClientAuth struct {
	secrets map[string]string
}

func (f *fakeClientAuth) VerifyClientSecret(_ context.Context, clientID,
	secret string) (oauthclient.ClientIdentity, error) {
	if f.secrets[clientID] != "" && f.secrets[clientID] == secret {
		return oauthclient.ClientIdentity{ClientID: clientID,
			ClientType: oauthclient.ClientTypeConfidential,
			AuthMethod: oauthclient.AuthMethodSecretBasic}, nil
	}
	return oauthclient.ClientIdentity{}, oauthclient.ErrClientAuthFailed
}

func (f *fakeClientAuth) VerifyClientCertificate(_ context.Context, clientID,
	certificatePEM string) (oauthclient.ClientIdentity, error) {
	if certificatePEM == "valid-client-certificate-pem" {
		return oauthclient.ClientIdentity{ClientID: clientID,
			ClientType: oauthclient.ClientTypeConfidential,
			AuthMethod: oauthclient.AuthMethodTLSClientAuth}, nil
	}
	return oauthclient.ClientIdentity{}, oauthclient.ErrClientAuthFailed
}

type testEnv struct {
	t             *testing.T
	ctx           context.Context
	raw           *storagesqlite.Store
	audit         *audit.Recorder
	reAuth        *fakeReauth
	clientAuth    *fakeClientAuth
	session       *session.Service
	tokens        *token.Service
	flow          *oauthflow.Service
	oauthStore    *oauthclientsqlite.Store
	now           time.Time
	userID        string
	sessionSecret string
	appID         string
	clientType    oauthclient.ClientType
}

func newTestEnv(t *testing.T, clientType oauthclient.ClientType) *testEnv {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(filepath.Join(t.TempDir(), "oauthflow-test.db")))
	if err != nil {
		t.Fatalf("打开数据库: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	list, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移: %v", err)
	}
	if _, err := raw.Migrate(ctx, list); err != nil {
		t.Fatalf("执行迁移: %v", err)
	}
	auditStore, err := auditsqlite.New(raw)
	if err != nil {
		t.Fatalf("审计存储: %v", err)
	}
	environment := &testEnv{t: t, ctx: ctx, raw: raw, now: now, userID: testUserID,
		appID: testAppID, clientType: clientType}
	environment.audit, err = audit.New(auditStore, audit.Options{
		Now: func() time.Time { return environment.now }})
	if err != nil {
		t.Fatalf("审计: %v", err)
	}
	environment.reAuth = &fakeReauth{allow: true}
	environment.clientAuth = &fakeClientAuth{secrets: map[string]string{testAppID: "confidential-secret"}}
	environment.seedIdentity()
	oauthStore, err := oauthclientsqlite.New(raw)
	if err != nil {
		t.Fatalf("OAuth 客户端存储: %v", err)
	}
	environment.oauthStore = oauthStore
	environment.seedClients()
	sessionKeyring, err := secrets.GenerateKeyring("session-k1", now)
	if err != nil {
		t.Fatalf("会话密钥环: %v", err)
	}
	sessionStore, err := sessionsqlite.New(raw)
	if err != nil {
		t.Fatalf("会话存储: %v", err)
	}
	environment.session, err = session.New(sessionStore, session.Options{
		Audit: environment.audit, Keyring: sessionKeyring,
		Now: func() time.Time { return environment.now },
	})
	if err != nil {
		t.Fatalf("会话服务: %v", err)
	}
	issued, err := environment.session.Login(ctx, session.LoginRequest{Result: authn.AuthenticateResult{
		UserID: testUserID, Username: "alice", Outcome: authn.OutcomeComplete,
		CompletedMethods: []authn.Method{authn.MethodPassword}, CompletedAt: now,
		SecurityVersion: 1,
	}})
	if err != nil {
		t.Fatalf("签发测试会话: %v", err)
	}
	environment.sessionSecret = issued.Secret.Reveal()

	tokenKeyring, err := secrets.GenerateKeyring("token-k1", now)
	if err != nil {
		t.Fatalf("令牌密钥环: %v", err)
	}
	sealer, err := secrets.NewSealer(tokenKeyring, nil)
	if err != nil {
		t.Fatalf("Sealer: %v", err)
	}
	tokenStore, err := tokensqlite.New(raw)
	if err != nil {
		t.Fatalf("令牌存储: %v", err)
	}
	tokenClients, err := token.NewOAuthClientSource(oauthStore)
	if err != nil {
		t.Fatalf("令牌客户端来源: %v", err)
	}
	environment.tokens, err = token.New(token.Options{
		Store: tokenStore, Audit: environment.audit, Sealer: sealer,
		Issuer: "https://issuer.example.test", Clients: tokenClients,
		Authorizer: token.IssuanceAuthorizerFunc(func(_ context.Context, _ token.Caller,
			request token.IssuanceRequest) error {
			if request.GrantType == token.GrantAuthorizationCode && request.TokenKind == "access" {
				return nil
			}
			return token.ErrAccessDenied
		}),
		KeyRetention: 24 * time.Hour,
		Now:          func() time.Time { return environment.now },
	})
	if err != nil {
		t.Fatalf("令牌服务: %v", err)
	}
	flowStore, err := oauthflowsqlite.New(raw)
	if err != nil {
		t.Fatalf("授权流程存储: %v", err)
	}
	source, err := oauthflow.NewOAuthClientSource(oauthStore)
	if err != nil {
		t.Fatalf("授权客户端来源: %v", err)
	}
	environment.flow, err = oauthflow.New(oauthflow.Options{
		Store: flowStore, Audit: environment.audit, Clients: source,
		ClientAuth: environment.clientAuth, Sessions: environment.session,
		Tokens: environment.tokens, Reauth: environment.reAuth,
		Now: func() time.Time { return environment.now },
	})
	if err != nil {
		t.Fatalf("授权流程服务: %v", err)
	}
	return environment
}

// seedIdentity 写入 active 用户、应用与 active 成员关系。
func (e *testEnv) seedIdentity() {
	e.exec(`INSERT INTO users(id,username,username_normalized,nickname,status,is_root,
security_version,row_version,created_at_ms,updated_at_ms) VALUES(?,?,?,?, 'active',0,1,1,?,?)`,
		testUserID, "alice", "alice", "Alice", e.now.UnixMilli(), e.now.UnixMilli())
	e.exec(`INSERT INTO applications(id,name,status,client_type,row_version,created_at_ms,updated_at_ms)
VALUES(?,?, 'active', ?,1,?,?)`, testAppID, "Demo App", string(e.clientType),
		e.now.UnixMilli(), e.now.UnixMilli())
	e.exec(`INSERT INTO app_memberships(app_id,user_id,status,row_version,created_at_ms,updated_at_ms)
VALUES(?,?, 'active',1,?,?)`, testAppID, testUserID, e.now.UnixMilli(), e.now.UnixMilli())
}

// seedClients 直接写入 oauth_clients 登记配置（auth 端点只读登记；生产登记由步骤 49
// 服务完成，本步验证协议读取真实登记配置）。
func (e *testEnv) seedClients() {
	authMethods := `[]`
	if e.clientType == oauthclient.ClientTypeConfidential {
		authMethods = `["client_secret_basic"]`
	}
	e.exec(`INSERT INTO oauth_clients(client_id,client_type,grant_types_json,redirect_uris_json,
post_logout_redirect_uris_json,scopes_json,audiences_json,auth_methods_json,require_pkce,
row_version,created_at_ms,updated_at_ms) VALUES(?,?,?,?,?,?,?,?,1,1,?,?)`,
		testAppID, string(e.clientType),
		`["authorization_code"]`, `["`+testRedirect+`"]`, `[]`,
		`["profile.read","email.read"]`, `["`+testAudience+`"]`, authMethods,
		e.now.UnixMilli(), e.now.UnixMilli())
}

// registerSecondClient 登记第二个公开客户端（用于跨客户端兑换测试）。
func (e *testEnv) registerSecondClient() {
	e.exec(`INSERT INTO applications(id,name,status,client_type,row_version,created_at_ms,updated_at_ms)
VALUES(?,?, 'active','public',1,?,?)`, testAppID2, "Second App",
		e.now.UnixMilli(), e.now.UnixMilli())
	e.exec(`INSERT INTO app_memberships(app_id,user_id,status,row_version,created_at_ms,updated_at_ms)
VALUES(?,?, 'active',1,?,?)`, testAppID2, testUserID,
		e.now.UnixMilli(), e.now.UnixMilli())
	e.exec(`INSERT INTO oauth_clients(client_id,client_type,grant_types_json,redirect_uris_json,
post_logout_redirect_uris_json,scopes_json,audiences_json,auth_methods_json,require_pkce,
row_version,created_at_ms,updated_at_ms) VALUES('`+testAppID2+`','public',
'["authorization_code"]','["`+testRedirect2+`"]','[]','["profile.read"]',
'["`+testAudience+`"]','[]',1,1,?,?)`, e.now.UnixMilli(), e.now.UnixMilli())
}

func (e *testEnv) exec(query string, args ...any) {
	e.t.Helper()
	if _, err := e.raw.ExecContext(e.ctx, query, args...); err != nil {
		e.t.Fatalf("执行测试 SQL 失败: %v", err)
	}
}

func (e *testEnv) queryInt(query string, args ...any) int64 {
	e.t.Helper()
	rows, err := e.raw.QueryContext(e.ctx, query, args...)
	if err != nil {
		e.t.Fatalf("查询测试 SQL 失败: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return 0
	}
	var value int64
	if err := rows.Scan(&value); err != nil {
		e.t.Fatalf("扫描测试 SQL 失败: %v", err)
	}
	return value
}

func (e *testEnv) queryString(query string, args ...any) string {
	e.t.Helper()
	rows, err := e.raw.QueryContext(e.ctx, query, args...)
	if err != nil {
		e.t.Fatalf("查询测试 SQL 失败: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return ""
	}
	var value string
	if err := rows.Scan(&value); err != nil {
		e.t.Fatalf("扫描测试 SQL 失败: %v", err)
	}
	return value
}

func (e *testEnv) authorizeRequest() oauthflow.AuthorizeRequest {
	return oauthflow.AuthorizeRequest{
		ClientID: testAppID, RedirectURI: testRedirect, ResponseType: "code",
		Scope: []string{"profile.read", "email.read"}, Resource: []string{testAudience},
		State: "opaque-state-123", Nonce: "nonce-abc",
		CodeChallenge: pkceChallenge, CodeChallengeMethod: "S256", RequestID: "req_begin_1",
	}
}

func (e *testEnv) begin() oauthflow.ConsentPrompt {
	e.t.Helper()
	prompt, err := e.flow.BeginAuthorization(e.ctx, e.sessionSecret, e.authorizeRequest())
	if err != nil {
		e.t.Fatalf("发起授权请求: %v", err)
	}
	return prompt
}

func (e *testEnv) approve(prompt oauthflow.ConsentPrompt) oauthflow.AuthorizationResult {
	e.t.Helper()
	result, err := e.flow.DecideAuthorization(e.ctx, e.sessionSecret, oauthflow.DecideRequest{
		RequestID: prompt.RequestID, Approve: true, DecisionRequestID: "req_decide_1"})
	if err != nil {
		e.t.Fatalf("批准授权: %v", err)
	}
	return result
}

func (e *testEnv) exchangeAccess(code string) (oauthflow.TokenResponse, error) {
	return e.flow.Exchange(e.ctx, oauthflow.ExchangeRequest{
		GrantType: "authorization_code", Code: code, RedirectURI: testRedirect,
		ClientID: testAppID, CodeVerifier: pkceVerifier, RequestID: "req_exchange_1"})
}

// ===== 正常流程 =====

func TestAuthorizationCodeHappyPath(t *testing.T) {
	env := newTestEnv(t, oauthclient.ClientTypePublic)
	prompt := env.begin()
	if prompt.RequestID == "" || prompt.ClientID != testAppID ||
		strings.Join(prompt.Scopes, " ") != "email.read profile.read" {
		t.Fatalf("确认页数据不正确: %+v", prompt)
	}
	// 发起授权不等于批准：此时不得存在授权码。
	if got := env.queryInt(`SELECT COUNT(*) FROM oauth_authorization_codes`); got != 0 {
		t.Fatalf("未确认前不应签发授权码: %d", got)
	}
	if status := env.queryString(`SELECT status FROM oauth_authorization_requests WHERE id=?`,
		prompt.RequestID); status != "pending" {
		t.Fatalf("确认请求状态 = %q，期望 pending", status)
	}
	result := env.approve(prompt)
	if !result.Approved || result.Code == "" {
		t.Fatalf("批准后应返回授权码: %+v", result)
	}
	redirect, err := url.Parse(result.RedirectURL)
	if err != nil || redirect.Query().Get("code") != result.Code ||
		redirect.Query().Get("state") != "opaque-state-123" {
		t.Fatalf("授权成功重定向不正确: %s err=%v", result.RedirectURL, err)
	}
	// 数据库/审计不得保存授权码明文，只保存摘要。
	digest := sha256.Sum256([]byte(result.Code))
	if got := env.queryInt(`SELECT COUNT(*) FROM oauth_authorization_codes WHERE code_sha256=?`,
		digest[:]); got != 1 {
		t.Fatalf("缺少授权码摘要记录")
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE detail_json LIKE ?`,
		"%"+result.Code+"%"); got != 0 {
		t.Fatalf("审计泄露授权码明文")
	}
	// nonce 保存供后续 OIDC 使用。
	if nonce := env.queryString(`SELECT nonce FROM oauth_authorization_codes`); nonce != "nonce-abc" {
		t.Fatalf("授权码未保存 nonce: %q", nonce)
	}
	response, err := env.exchangeAccess(result.Code)
	if err != nil {
		t.Fatalf("兑换授权码: %v", err)
	}
	if response.TokenType != "Bearer" || response.ExpiresIn <= 0 ||
		response.Scope != "email.read profile.read" {
		t.Fatalf("Token 响应不正确: %+v", response)
	}
	claims, err := env.tokens.VerifyAccessToken(env.ctx, response.AccessToken.Reveal(), testAudience)
	if err != nil {
		t.Fatalf("验证 Access Token: %v", err)
	}
	if claims.Subject != testUserID || claims.ClientID != testAppID ||
		strings.Join(claims.Scopes, " ") != "email.read profile.read" ||
		len(claims.Audience) != 1 || claims.Audience[0] != testAudience {
		t.Fatalf("Access Token 声明不正确: %+v", claims)
	}
	// 兑换成功事件存在且不含令牌原文。
	if got := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action='oauth.token.exchanged'`); got != 1 {
		t.Fatalf("缺少兑换成功审计")
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE detail_json LIKE ?`,
		"%"+response.AccessToken.Reveal()+"%"); got != 0 {
		t.Fatalf("审计泄露 Access Token")
	}
	// 重复兑换：拒绝且记录重放。
	if _, err := env.exchangeAccess(result.Code); !isOAuthCode(err, "invalid_grant") {
		t.Fatalf("重复兑换应 invalid_grant，实际 %v", err)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM oauth_authorization_codes WHERE replayed_at_ms IS NOT NULL`); got != 1 {
		t.Fatalf("重复兑换未记录重放")
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM oauth_authorization_codes WHERE consumed_at_ms IS NOT NULL`); got != 1 {
		t.Fatalf("授权码应只消费一次")
	}
}

func TestAuthorizationDenied(t *testing.T) {
	env := newTestEnv(t, oauthclient.ClientTypePublic)
	prompt := env.begin()
	result, err := env.flow.DecideAuthorization(env.ctx, env.sessionSecret,
		oauthflow.DecideRequest{RequestID: prompt.RequestID, Approve: false,
			DecisionRequestID: "req_deny_1"})
	if err != nil {
		t.Fatalf("拒绝授权不应返回内部错误: %v", err)
	}
	if result.Approved || result.Code != "" {
		t.Fatalf("拒绝不应签发授权码: %+v", result)
	}
	redirect, parseErr := url.Parse(result.RedirectURL)
	if parseErr != nil || redirect.Query().Get("error") != "access_denied" ||
		redirect.Query().Get("state") != "opaque-state-123" {
		t.Fatalf("拒绝重定向不正确: %s err=%v", result.RedirectURL, parseErr)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM oauth_authorization_codes`); got != 0 {
		t.Fatalf("拒绝后不应存在授权码")
	}
	if status := env.queryString(`SELECT status FROM oauth_authorization_requests WHERE id=?`,
		prompt.RequestID); status != "denied" {
		t.Fatalf("确认请求状态 = %q，期望 denied", status)
	}
	// 拒绝后再次尝试批准不能成功（条件迁移只允许一次决定）。
	if _, err := env.flow.DecideAuthorization(env.ctx, env.sessionSecret,
		oauthflow.DecideRequest{RequestID: prompt.RequestID, Approve: true,
			DecisionRequestID: "req_deny_2"}); err == nil {
		t.Fatal("已拒绝的确认请求不能再次批准")
	}
}

// ===== 请求校验与回调安全 =====

func TestAuthorizationRequestValidation(t *testing.T) {
	env := newTestEnv(t, oauthclient.ClientTypePublic)
	cases := []struct {
		name         string
		mutate       func(*oauthflow.AuthorizeRequest)
		wantCode     string
		wantRedirect bool
	}{
		{"未知客户端", func(r *oauthflow.AuthorizeRequest) {
			r.ClientID = "app_00000000000000000000000000000009"
		}, "invalid_client", false},
		{"未登记回调", func(r *oauthflow.AuthorizeRequest) {
			r.RedirectURI = "https://evil.example.test/callback"
		}, "invalid_request", false},
		{"隐式授权", func(r *oauthflow.AuthorizeRequest) {
			r.ResponseType = "token"
		}, "unsupported_response_type", true},
		{"密码授权", func(r *oauthflow.AuthorizeRequest) {
			r.ResponseType = "password"
		}, "unsupported_response_type", true},
		{"缺少 PKCE", func(r *oauthflow.AuthorizeRequest) {
			r.CodeChallenge = ""
			r.CodeChallengeMethod = ""
		}, "invalid_request", true},
		{"PKCE plain", func(r *oauthflow.AuthorizeRequest) {
			r.CodeChallengeMethod = "plain"
		}, "invalid_request", true},
		{"PKCE 格式非法", func(r *oauthflow.AuthorizeRequest) {
			r.CodeChallenge = "short"
		}, "invalid_request", true},
		{"未登记 scope", func(r *oauthflow.AuthorizeRequest) {
			r.Scope = []string{"admin.write"}
		}, "invalid_scope", true},
		{"未登记 audience", func(r *oauthflow.AuthorizeRequest) {
			r.Resource = []string{"https://other.example.test"}
		}, "invalid_request", true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			request := env.authorizeRequest()
			testCase.mutate(&request)
			_, err := env.flow.BeginAuthorization(env.ctx, env.sessionSecret, request)
			if !isOAuthCode(err, testCase.wantCode) {
				t.Fatalf("错误 = %v，期望 %s", err, testCase.wantCode)
			}
			var protocolError *oauthflow.OAuthError
			if !errors.As(err, &protocolError) {
				t.Fatalf("错误不是 OAuthError: %v", err)
			}
			if _, redirectable := protocolError.RedirectLocation(); redirectable != testCase.wantRedirect {
				t.Fatalf("重定向安全判定 = %v，期望 %v", redirectable, testCase.wantRedirect)
			}
			if testCase.wantRedirect {
				location, _ := protocolError.RedirectLocation()
				parsed, parseErr := url.Parse(location)
				if parseErr != nil || parsed.Query().Get("error") != testCase.wantCode ||
					parsed.Query().Get("state") != "opaque-state-123" {
					t.Fatalf("错误重定向不正确: %s err=%v", location, parseErr)
				}
			}
		})
	}
	// 客户端停用：拒绝且不重定向。
	env.exec(`UPDATE applications SET status='disabled' WHERE id=?`, testAppID)
	_, err := env.flow.BeginAuthorization(env.ctx, env.sessionSecret, env.authorizeRequest())
	if !isOAuthCode(err, "unauthorized_client") {
		t.Fatalf("停用客户端错误 = %v", err)
	}
	var protocolError *oauthflow.OAuthError
	if errors.As(err, &protocolError) {
		if _, redirectable := protocolError.RedirectLocation(); redirectable {
			t.Fatal("停用客户端不应重定向")
		}
	}
}

func TestAuthorizationSessionAndReauth(t *testing.T) {
	env := newTestEnv(t, oauthclient.ClientTypePublic)
	prompt := env.begin()
	// 会话被撤销后不能批准。
	if _, err := env.session.RevokeAllForUser(env.ctx, testUserID,
		session.RevokeReasonUserSessions); err != nil {
		t.Fatalf("撤销会话: %v", err)
	}
	_, err := env.flow.DecideAuthorization(env.ctx, env.sessionSecret, oauthflow.DecideRequest{
		RequestID: prompt.RequestID, Approve: true, DecisionRequestID: "req_after_revoke"})
	if !isOAuthCode(err, "access_denied") {
		t.Fatalf("会话失效应拒绝批准，实际 %v", err)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM oauth_authorization_codes`); got != 0 {
		t.Fatalf("会话失效后不应签发授权码")
	}

	// 重新登录后，近期认证不足（Reauth 拒绝）必须失败且不发码。
	env.relogin(t)
	prompt = env.begin()
	env.reAuth.mu.Lock()
	env.reAuth.allow = false
	env.reAuth.mu.Unlock()
	_, err = env.flow.DecideAuthorization(env.ctx, env.sessionSecret, oauthflow.DecideRequest{
		RequestID: prompt.RequestID, Approve: true, DecisionRequestID: "req_reauth_denied"})
	if !isOAuthCode(err, "access_denied") {
		t.Fatalf("近期认证不足应拒绝批准，实际 %v", err)
	}
	env.reAuth.mu.Lock()
	env.reAuth.allow = true
	env.reAuth.mu.Unlock()
	if got := env.queryInt(`SELECT COUNT(*) FROM oauth_authorization_codes`); got != 0 {
		t.Fatalf("近期认证不足时不应签发授权码")
	}
}

// relogin 在会话撤销后重新签发完整测试会话。
func (e *testEnv) relogin(t *testing.T) {
	t.Helper()
	issued, err := e.session.Login(e.ctx, session.LoginRequest{Result: authn.AuthenticateResult{
		UserID: testUserID, Username: "alice", Outcome: authn.OutcomeComplete,
		CompletedMethods: []authn.Method{authn.MethodPassword}, CompletedAt: e.now,
		SecurityVersion: 1,
	}})
	if err != nil {
		t.Fatalf("重新登录: %v", err)
	}
	e.sessionSecret = issued.Secret.Reveal()
}

// ===== Token 端点校验 =====

func TestTokenExchangeValidation(t *testing.T) {
	env := newTestEnv(t, oauthclient.ClientTypePublic)
	prompt := env.begin()
	result := env.approve(prompt)

	// 错误 verifier 不消费授权码；修正后可成功。
	_, err := env.flow.Exchange(env.ctx, oauthflow.ExchangeRequest{
		GrantType: "authorization_code", Code: result.Code, RedirectURI: testRedirect,
		ClientID: testAppID, CodeVerifier: strings.Repeat("A", 43), RequestID: "req_bad_verifier"})
	if !isOAuthCode(err, "invalid_grant") {
		t.Fatalf("PKCE 不符应 invalid_grant，实际 %v", err)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM oauth_authorization_codes WHERE consumed_at_ms IS NULL`); got != 1 {
		t.Fatalf("PKCE 失败不应消费授权码")
	}
	// redirect_uri 替换。
	_, err = env.flow.Exchange(env.ctx, oauthflow.ExchangeRequest{
		GrantType: "authorization_code", Code: result.Code, RedirectURI: testRedirect2,
		ClientID: testAppID, CodeVerifier: pkceVerifier, RequestID: "req_bad_redirect"})
	if !isOAuthCode(err, "invalid_grant") {
		t.Fatalf("回调替换应 invalid_grant，实际 %v", err)
	}
	// 错误 grant type。
	_, err = env.flow.Exchange(env.ctx, oauthflow.ExchangeRequest{
		GrantType: "password", Code: result.Code, RedirectURI: testRedirect,
		ClientID: testAppID, CodeVerifier: pkceVerifier})
	if !isOAuthCode(err, "unsupported_grant_type") {
		t.Fatalf("password 授权应 unsupported_grant_type，实际 %v", err)
	}
	// 未获准/不存在的授权码。
	_, err = env.flow.Exchange(env.ctx, oauthflow.ExchangeRequest{
		GrantType: "authorization_code", Code: "unknown-code", RedirectURI: testRedirect,
		ClientID: testAppID, CodeVerifier: pkceVerifier})
	if !isOAuthCode(err, "invalid_grant") {
		t.Fatalf("未知授权码应 invalid_grant，实际 %v", err)
	}
	// 标准 OAuth 错误体字段。
	var protocolError *oauthflow.OAuthError
	if !errors.As(err, &protocolError) || protocolError.Body()["error"] != "invalid_grant" {
		t.Fatalf("错误不是标准 OAuth 格式: %v", err)
	}
	// 正确的兑换仍成功。
	response, err := env.exchangeAccess(result.Code)
	if err != nil {
		t.Fatalf("正确兑换失败: %v", err)
	}
	_ = response
}

func TestExchangeCrossClientAndClientState(t *testing.T) {
	env := newTestEnv(t, oauthclient.ClientTypePublic)
	env.registerSecondClient()
	prompt := env.begin()
	result := env.approve(prompt)
	// 跨客户端兑换：使用另一个已登记公开客户端的 client_id。
	_, err := env.flow.Exchange(env.ctx, oauthflow.ExchangeRequest{
		GrantType: "authorization_code", Code: result.Code, RedirectURI: testRedirect,
		ClientID: testAppID2, CodeVerifier: pkceVerifier})
	if !isOAuthCode(err, "invalid_grant") {
		t.Fatalf("跨客户端兑换应 invalid_grant，实际 %v", err)
	}
	// 应用停用后兑换：客户端配置不可用，按 invalid_client 拒绝。
	env.exec(`UPDATE applications SET status='disabled' WHERE id=?`, testAppID)
	_, err = env.exchangeAccess(result.Code)
	if !isOAuthCode(err, "invalid_client") {
		t.Fatalf("客户端停用后兑换应 invalid_client，实际 %v", err)
	}
}

func TestExchangeSessionInvalidated(t *testing.T) {
	env := newTestEnv(t, oauthclient.ClientTypePublic)
	prompt := env.begin()
	result := env.approve(prompt)
	// 授权码签发后撤销用户全部会话：兑换必须拒绝。
	if _, err := env.session.RevokeAllForUser(env.ctx, testUserID,
		session.RevokeReasonUserSessions); err != nil {
		t.Fatalf("撤销会话: %v", err)
	}
	_, err := env.exchangeAccess(result.Code)
	if !isOAuthCode(err, "invalid_grant") {
		t.Fatalf("会话失效后兑换应 invalid_grant，实际 %v", err)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM oauth_authorization_codes WHERE consumed_at_ms IS NOT NULL`); got != 0 {
		t.Fatalf("会话失效的兑换不应消费授权码")
	}
}

func TestExchangeConcurrentSingleWinner(t *testing.T) {
	env := newTestEnv(t, oauthclient.ClientTypePublic)
	prompt := env.begin()
	result := env.approve(prompt)
	const workers = 4
	var wg sync.WaitGroup
	results := make(chan error, workers)
	for index := 0; index < workers; index++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := env.exchangeAccess(result.Code)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	success := 0
	failures := 0
	for err := range results {
		if err == nil {
			success++
			continue
		}
		if isOAuthCode(err, "invalid_grant") {
			failures++
			continue
		}
		t.Fatalf("并发兑换出现非预期错误: %v", err)
	}
	if success != 1 || failures != workers-1 {
		t.Fatalf("并发兑换结果 success=%d failures=%d", success, failures)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM oauth_authorization_codes WHERE consumed_at_ms IS NOT NULL`); got != 1 {
		t.Fatalf("授权码应恰好消费一次")
	}
}

func TestExchangeExpiredCode(t *testing.T) {
	env := newTestEnv(t, oauthclient.ClientTypePublic)
	prompt := env.begin()
	result := env.approve(prompt)
	env.now = env.now.Add(oauthflow.DefaultCodeTTL + time.Minute)
	_, err := env.exchangeAccess(result.Code)
	if !isOAuthCode(err, "invalid_grant") {
		t.Fatalf("过期授权码应 invalid_grant，实际 %v", err)
	}
}

// ===== 保密客户端 =====

func TestConfidentialClientAuthentication(t *testing.T) {
	env := newTestEnv(t, oauthclient.ClientTypeConfidential)
	prompt := env.begin()
	result := env.approve(prompt)
	// 缺少客户端认证。
	_, err := env.flow.Exchange(env.ctx, oauthflow.ExchangeRequest{
		GrantType: "authorization_code", Code: result.Code, RedirectURI: testRedirect,
		ClientID: testAppID, CodeVerifier: pkceVerifier})
	if !isOAuthCode(err, "invalid_client") {
		t.Fatalf("缺少客户端认证应 invalid_client，实际 %v", err)
	}
	// 错误 secret。
	_, err = env.flow.Exchange(env.ctx, oauthflow.ExchangeRequest{
		GrantType: "authorization_code", Code: result.Code, RedirectURI: testRedirect,
		ClientID: testAppID, ClientSecret: "wrong", CodeVerifier: pkceVerifier})
	if !isOAuthCode(err, "invalid_client") {
		t.Fatalf("错误客户端 secret 应 invalid_client，实际 %v", err)
	}
	// 正确 secret 成功。
	response, err := env.flow.Exchange(env.ctx, oauthflow.ExchangeRequest{
		GrantType: "authorization_code", Code: result.Code, RedirectURI: testRedirect,
		ClientID: testAppID, ClientSecret: "confidential-secret", CodeVerifier: pkceVerifier})
	if err != nil {
		t.Fatalf("保密客户端兑换失败: %v", err)
	}
	if !response.AccessToken.IsSet() {
		t.Fatal("缺少 Access Token")
	}
	// TLS 客户端证书身份兑换：另一条授权码路径。
	prompt = env.begin()
	result = env.approve(prompt)
	response, err = env.flow.Exchange(env.ctx, oauthflow.ExchangeRequest{
		GrantType: "authorization_code", Code: result.Code, RedirectURI: testRedirect,
		ClientID: testAppID, ClientCertificatePEM: "valid-client-certificate-pem",
		CodeVerifier: pkceVerifier})
	if err != nil {
		t.Fatalf("TLS 客户端证书兑换失败: %v", err)
	}
	if !response.AccessToken.IsSet() {
		t.Fatal("缺少证书身份兑换的 Access Token")
	}
}

// ===== 辅助 =====

func isOAuthCode(err error, code string) bool {
	var protocolError *oauthflow.OAuthError
	if !errors.As(err, &protocolError) {
		return false
	}
	return protocolError.Code == code
}
