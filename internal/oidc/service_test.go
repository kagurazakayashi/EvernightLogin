package oidc_test

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/oidc"
	oidcsqlite "github.com/kagurazakayashi/EvernightLogin/internal/oidc/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/internal/token"
	tokensqlite "github.com/kagurazakayashi/EvernightLogin/internal/token/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const (
	testIssuer      = "https://issuer.example.test"
	testClient      = "app_00000000000000000000000000000001"
	testClientB     = "app_00000000000000000000000000000002"
	testUser        = "usr_00000000000000000000000000000001"
	testUserNoEmail = "usr_00000000000000000000000000000002"
	testAudience    = "https://api.example.test"
)

// fakeTokenClients 是令牌服务的客户端登记测试替身。
type fakeTokenClients struct{ clients map[string]token.ClientInfo }

func (f *fakeTokenClients) LoadClient(_ context.Context, clientID string) (token.ClientInfo, error) {
	client, found := f.clients[clientID]
	if !found {
		return token.ClientInfo{}, token.ErrClientNotFound
	}
	return client, nil
}

// fakeRevocationChecker 是步骤 55 在线撤销检查测试替身。
type fakeRevocationChecker struct {
	revoked bool
	err     error
}

func (f *fakeRevocationChecker) AccessTokenRevoked(context.Context, token.AccessClaims) (bool, error) {
	return f.revoked, f.err
}

type testEnv struct {
	t       *testing.T
	ctx     context.Context
	now     time.Time
	tokens  *token.Service
	service *oidc.Service
	raw     *storagesqlite.Store
	checker *fakeRevocationChecker
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(filepath.Join(testutil.TempDir(t), "oidc.db")))
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
	env := &testEnv{t: t, ctx: ctx, now: now, raw: raw,
		checker: &fakeRevocationChecker{}}
	recorder, err := audit.New(auditStore, audit.Options{Now: func() time.Time { return env.now }})
	if err != nil {
		t.Fatalf("审计: %v", err)
	}
	// 种子用户与邮箱（UserInfo 只读这些字段）。
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := raw.ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("测试 SQL: %v", err)
		}
	}
	exec(`INSERT INTO users(id,username,username_normalized,nickname,biography,avatar_ref,language,
timezone,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,?, '',NULL,'zh-CN','Asia/Shanghai','active',0,1,1,?,?)`,
		testUser, "alice", "alice", "Alice", now.UnixMilli(), now.UnixMilli())
	exec(`INSERT INTO users(id,username,username_normalized,nickname,biography,avatar_ref,language,
timezone,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,?, '',NULL,'en-US','UTC','active',0,1,1,?,?)`,
		testUserNoEmail, "bob", "bob", "Bob", now.UnixMilli(), now.UnixMilli())
	exec(`INSERT INTO user_emails(email_normalized,user_id,email,verified_at_ms,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?)`, "alice@example.test", testUser, "alice@example.test",
		now.UnixMilli(), now.UnixMilli(), now.UnixMilli())
	keyring, err := secrets.GenerateKeyring("k1", now)
	if err != nil {
		t.Fatalf("密钥环: %v", err)
	}
	sealer, err := secrets.NewSealer(keyring, nil)
	if err != nil {
		t.Fatalf("Sealer: %v", err)
	}
	tokenStore, err := tokensqlite.New(raw)
	if err != nil {
		t.Fatalf("令牌存储: %v", err)
	}
	clients := &fakeTokenClients{clients: map[string]token.ClientInfo{
		testClient: {
			ClientID: testClient, ApplicationID: testClient, ClientType: "public",
			AppActive: true, GrantTypes: []string{"authorization_code"},
			Scopes:    []string{"openid", "profile", "email"},
			Audiences: []string{testIssuer, testAudience},
		},
		testClientB: {
			ClientID: testClientB, ApplicationID: testClientB, ClientType: "public",
			AppActive: true, GrantTypes: []string{"authorization_code"},
			Scopes: []string{"openid"}, Audiences: []string{testIssuer},
		},
	}}
	tokens, err := token.New(token.Options{
		Store: tokenStore, Audit: recorder, Sealer: sealer, Issuer: testIssuer,
		Clients: clients,
		Authorizer: token.IssuanceAuthorizerFunc(func(_ context.Context, _ token.Caller,
			request token.IssuanceRequest) error {
			if request.GrantType == token.GrantAuthorizationCode {
				return nil
			}
			return token.ErrAccessDenied
		}),
		KeyRetention: 24 * time.Hour,
		Now:          func() time.Time { return env.now },
	})
	if err != nil {
		t.Fatalf("令牌服务: %v", err)
	}
	userStore, err := oidcsqlite.New(raw)
	if err != nil {
		t.Fatalf("OIDC 用户存储: %v", err)
	}
	service, err := oidc.New(oidc.Options{
		Issuer:                testIssuer,
		AuthorizationEndpoint: testIssuer + "/oauth/authorize",
		TokenEndpoint:         testIssuer + "/oauth/token",
		UserInfoEndpoint:      testIssuer + "/oidc/userinfo",
		JWKSURI:               testIssuer + "/oidc/jwks",
		Tokens:                tokens,
		Users:                 userStore,
		RevocationChecker:     env.checker,
		SubjectSecret:         bytesOf('s', 32),
		Now:                   func() time.Time { return env.now },
	})
	if err != nil {
		t.Fatalf("OIDC 服务: %v", err)
	}
	env.tokens = tokens
	env.service = service
	return env
}

func bytesOf(character byte, count int) []byte {
	value := make([]byte, count)
	for index := range value {
		value[index] = character
	}
	return value
}

// issueAccessToken 以用户身份签发 Access Token。
func (e *testEnv) issueAccessToken(clientID, userID string, scopes, audiences []string) string {
	e.t.Helper()
	caller, err := token.UserCaller(userID)
	if err != nil {
		e.t.Fatalf("用户调用者: %v", err)
	}
	issued, err := e.tokens.IssueAccessToken(e.ctx, caller, token.IssueAccessTokenRequest{
		ClientID: clientID, SubjectUserID: userID, GrantType: token.GrantAuthorizationCode,
		Scopes: scopes, Audiences: audiences, RequestID: "req_access",
	})
	if err != nil {
		e.t.Fatalf("签发 Access Token: %v", err)
	}
	return issued.Token.Reveal()
}

// seedSessionAuth 直接以真实会话认证事实签发 ID Token（等效 oauthflow 兑换路径）。
func (e *testEnv) issueIDToken(clientID, userID, nonce string, methods []string) string {
	e.t.Helper()
	issued, err := e.service.IssueLoginIDToken(e.ctx, oidc.LoginIDTokenRequest{
		ClientID: clientID, UserID: userID, Nonce: nonce,
		AuthTime: e.now, AuthMethods: methods, Scopes: []string{"openid", "profile", "email"},
		RequestID: "req_id",
	})
	if err != nil {
		e.t.Fatalf("签发 ID Token: %v", err)
	}
	return issued.Token.Reveal()
}

// ===== 测试用例 =====

// TestDiscoveryDocumentOnlyImplemented 覆盖发现文档一致性、issuer 路径与“只声明真实
// 能力”：只声明授权码 + PKCE S256 + ES256 + pairwise，不声明撤销/设备码/结束会话。
func TestDiscoveryDocumentOnlyImplemented(t *testing.T) {
	env := newTestEnv(t)
	document := env.service.Discovery()
	if document.Issuer != testIssuer {
		t.Errorf("issuer = %q", document.Issuer)
	}
	for _, endpoint := range []string{document.AuthorizationEndpoint, document.TokenEndpoint,
		document.UserInfoEndpoint, document.JWKSURI} {
		if !strings.HasPrefix(endpoint, testIssuer+"/") {
			t.Errorf("端点不在 issuer 路径前缀下: %q", endpoint)
		}
	}
	if len(document.ResponseTypesSupported) != 1 || document.ResponseTypesSupported[0] != "code" {
		t.Errorf("response_types_supported = %v", document.ResponseTypesSupported)
	}
	if len(document.GrantTypesSupported) != 1 || document.GrantTypesSupported[0] != "authorization_code" {
		t.Errorf("grant_types_supported = %v", document.GrantTypesSupported)
	}
	if len(document.SubjectTypesSupported) != 1 || document.SubjectTypesSupported[0] != "pairwise" {
		t.Errorf("subject_types_supported = %v", document.SubjectTypesSupported)
	}
	if len(document.IDTokenSigningAlgValuesSupported) != 1 ||
		document.IDTokenSigningAlgValuesSupported[0] != "ES256" {
		t.Errorf("签名算法 = %v", document.IDTokenSigningAlgValuesSupported)
	}
	if len(document.CodeChallengeMethodsSupported) != 1 ||
		document.CodeChallengeMethodsSupported[0] != "S256" {
		t.Errorf("PKCE 方法 = %v", document.CodeChallengeMethodsSupported)
	}
	if !contains(document.ScopesSupported, "openid") {
		t.Errorf("缺少 openid scope: %v", document.ScopesSupported)
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("序列化发现文档: %v", err)
	}
	// 未实现的端点/能力不得出现在文档中。
	for _, forbidden := range []string{"device_authorization_endpoint", "revocation_endpoint",
		"end_session_endpoint", "introspection_endpoint", "refresh_token", "implicit",
		"client_credentials", "HS256", "none"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Errorf("发现文档声明了未实现能力 %q: %s", forbidden, encoded)
		}
	}
}

// TestIDTokenClaimsPairwiseAndInterop 覆盖 ID Token 必需声明、nonce 往返、aud/azp、
// auth_time、真实 amr/acr 与按客户端配对 subject；并用 go-jose（独立 JOSE 校验流程）
// 验证签名与声明，而不是只用本项目验证器自签自验。
func TestIDTokenClaimsPairwiseAndInterop(t *testing.T) {
	env := newTestEnv(t)
	raw := env.issueIDToken(testClient, testUser, "nonce-roundtrip-1",
		[]string{"password", "totp"})

	// 本项目验证路径：类型/issuer/aud/nonce/auth_time/amr/acr。
	claims, err := env.tokens.VerifyIDToken(env.ctx, raw, testClient)
	if err != nil {
		t.Fatalf("验证 ID Token: %v", err)
	}
	if claims.Issuer != testIssuer || claims.Audience != testClient ||
		claims.ClientID != testClient || claims.AuthorizedParty != testClient {
		t.Errorf("ID Token 声明异常: %+v", claims)
	}
	if claims.Nonce != "nonce-roundtrip-1" {
		t.Errorf("nonce 未原样回传: %q", claims.Nonce)
	}
	if !claims.AuthTime.Equal(env.now) || claims.TokenUse != token.TokenUseID {
		t.Errorf("auth_time/token_use 异常: %+v", claims)
	}
	if !contains(claims.AMR, "pwd") || !contains(claims.AMR, "otp") || !contains(claims.AMR, "totp") {
		t.Errorf("amr 未反映真实认证方法: %v", claims.AMR)
	}
	if claims.ACR != "urn:evernight:acr:strong" {
		t.Errorf("acr = %q，期望强认证映射", claims.ACR)
	}
	// pairwise：同一用户对不同客户端 sub 不同，且不等于真实用户 ID；同一客户端稳定。
	other := env.issueIDToken(testClientB, testUser, "nonce-2", []string{"password"})
	otherClaims, err := env.tokens.VerifyIDToken(env.ctx, other, testClientB)
	if err != nil {
		t.Fatalf("验证第二客户端 ID Token: %v", err)
	}
	if claims.Subject == otherClaims.Subject || claims.Subject == testUser {
		t.Errorf("subject 未按客户端配对: %q vs %q", claims.Subject, otherClaims.Subject)
	}
	repeated := env.issueIDToken(testClient, testUser, "nonce-3", []string{"password"})
	repeatedClaims, err := env.tokens.VerifyIDToken(env.ctx, repeated, testClient)
	if err != nil || repeatedClaims.Subject != claims.Subject {
		t.Fatalf("同一客户端 subject 不稳定: %v", err)
	}

	// 独立 JOSE 互操作校验：从 JWKS 取公钥、解析紧凑 JWS、验证 ES256 签名并读取声明。
	jwks, err := env.tokens.PublishedJWKS(env.ctx)
	if err != nil {
		t.Fatalf("读取 JWKS: %v", err)
	}
	var keySet jose.JSONWebKeySet
	if err := json.Unmarshal(jwks, &keySet); err != nil {
		t.Fatalf("解析 JWKS: %v", err)
	}
	signature, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("标准 JOSE 解析: %v", err)
	}
	if len(signature.Signatures) != 1 {
		t.Fatalf("JWS 签名数量 = %d", len(signature.Signatures))
	}
	kid := signature.Signatures[0].Header.KeyID
	keys := keySet.Key(kid)
	if len(keys) != 1 {
		t.Fatalf("JWKS 未找到 kid %q", kid)
	}
	payload, err := signature.Verify(keys[0])
	if err != nil {
		t.Fatalf("标准 JOSE 验签失败: %v", err)
	}
	var independent map[string]any
	if err := json.Unmarshal(payload, &independent); err != nil {
		t.Fatalf("解析独立校验声明: %v", err)
	}
	if independent["iss"] != testIssuer || independent["aud"] != testClient ||
		independent["nonce"] != "nonce-roundtrip-1" || independent["sub"] != claims.Subject {
		t.Errorf("独立校验声明不一致: %v", independent)
	}
	exp, expOK := independent["exp"].(float64)
	iat, iatOK := independent["iat"].(float64)
	authTime, authOK := independent["auth_time"].(float64)
	if !expOK || !iatOK || !authOK || exp <= iat || int64(authTime) != env.now.Unix() {
		t.Errorf("时间声明异常: %v", independent)
	}
}

// TestUserInfoScopeTrimmingAndValidation 覆盖 UserInfo：Access Token 验证、scope 字段
// 裁剪、email_verified 真实状态、sub 与 ID Token 一致、错误类型/过期/错误 audience/
// 缺 scope 拒绝。
func TestUserInfoScopeTrimmingAndValidation(t *testing.T) {
	env := newTestEnv(t)
	// openid+email：只返回 sub/email/email_verified，不返回 profile 字段。
	emailToken := env.issueAccessToken(testClient, testUser, []string{"openid", "email"},
		[]string{testIssuer})
	response, err := env.service.UserInfo(env.ctx, emailToken)
	if err != nil {
		t.Fatalf("UserInfo(email): %v", err)
	}
	idClaims, err := env.tokens.VerifyIDToken(env.ctx,
		env.issueIDToken(testClient, testUser, "", []string{"password"}), testClient)
	if err != nil || response.Subject != idClaims.Subject {
		t.Fatalf("UserInfo sub 与 ID Token 不一致: %v %q vs %q", err, response.Subject, idClaims.Subject)
	}
	if response.Email != "alice@example.test" || response.EmailVerified == nil || !*response.EmailVerified {
		t.Errorf("email/email_verified 异常: %+v", response)
	}
	if response.Name != "" || response.PreferredUsername != "" {
		t.Errorf("未授权 profile 字段被返回: %+v", response)
	}
	// openid+profile：返回资料字段，不返回 email。
	profileToken := env.issueAccessToken(testClient, testUser, []string{"openid", "profile"},
		[]string{testIssuer})
	profile, err := env.service.UserInfo(env.ctx, profileToken)
	if err != nil {
		t.Fatalf("UserInfo(profile): %v", err)
	}
	if profile.Name != "Alice" || profile.PreferredUsername != "alice" ||
		profile.Locale != "zh-CN" || profile.ZoneInfo != "Asia/Shanghai" {
		t.Errorf("profile 字段异常: %+v", profile)
	}
	if profile.Email != "" || profile.EmailVerified != nil {
		t.Errorf("未授权 email 字段被返回: %+v", profile)
	}
	// 无已验证邮箱：即使请求 email scope 也不返回 email/email_verified。
	noEmailToken := env.issueAccessToken(testClient, testUserNoEmail, []string{"openid", "email"},
		[]string{testIssuer})
	noEmail, err := env.service.UserInfo(env.ctx, noEmailToken)
	if err != nil {
		t.Fatalf("UserInfo(无邮箱): %v", err)
	}
	if noEmail.Email != "" || noEmail.EmailVerified != nil {
		t.Errorf("无已验证邮箱不应返回 email: %+v", noEmail)
	}
	// 缺 openid scope。
	noScope := env.issueAccessToken(testClient, testUser, []string{"profile"}, []string{testIssuer})
	if _, err := env.service.UserInfo(env.ctx, noScope); oidc.CodeOf(err) != oidc.CodeAccessDenied {
		t.Fatalf("缺 openid scope 错误 = %v", err)
	}
	// 错误 audience（未包含 issuer）。
	wrongAudience := env.issueAccessToken(testClient, testUser, []string{"openid"},
		[]string{testAudience})
	if _, err := env.service.UserInfo(env.ctx, wrongAudience); oidc.CodeOf(err) != oidc.CodeTokenInvalid {
		t.Fatalf("错误 audience 错误 = %v", err)
	}
	// ID Token 不能当 Access Token 使用。
	idToken := env.issueIDToken(testClient, testUser, "", []string{"password"})
	var protocolErr *oidc.ProtocolError
	if _, err := env.service.UserInfo(env.ctx, idToken); !errors.As(err, &protocolErr) ||
		protocolErr.Code != "invalid_token" {
		t.Fatalf("ID Token 用作 UserInfo 错误 = %v", err)
	}
	// 过期 Access Token（可注入时钟 + 短 TTL 的新服务）。
	expiredEnv := newTestEnv(t)
	expired := expiredEnv.issueAccessToken(testClient, testUser, []string{"openid"}, []string{testIssuer})
	expiredEnv.now = expiredEnv.now.Add(2 * time.Hour)
	if _, err := expiredEnv.service.UserInfo(expiredEnv.ctx, expired); oidc.CodeOf(err) != oidc.CodeTokenInvalid {
		t.Fatalf("过期 Access Token 错误 = %v", err)
	}
}

// TestConfigurationValidation 覆盖 issuer 路径/尾斜杠、端点同源与前缀、subject 秘密、
// 未实现 Scope 与缺失依赖的 fail-closed 构造。
func TestConfigurationValidation(t *testing.T) {
	env := newTestEnv(t)
	base := oidc.Options{
		Issuer: testIssuer, AuthorizationEndpoint: testIssuer + "/oauth/authorize",
		TokenEndpoint: testIssuer + "/oauth/token", UserInfoEndpoint: testIssuer + "/oidc/userinfo",
		JWKSURI: testIssuer + "/oidc/jwks", Tokens: env.tokens,
		Users: &fakeUsers{}, SubjectSecret: bytesOf('k', 32),
		RevocationChecker: &fakeRevocationChecker{},
	}
	if _, err := oidc.New(base); err != nil {
		t.Fatalf("合法配置构造失败: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*oidc.Options)
	}{
		{"issuer 尾斜杠", func(o *oidc.Options) { o.Issuer = testIssuer + "/" }},
		{"issuer 明文非回环", func(o *oidc.Options) { o.Issuer = "http://example.test" }},
		{"端点跨源", func(o *oidc.Options) { o.TokenEndpoint = "https://other.example.test/token" }},
		{"端点越出 issuer 前缀", func(o *oidc.Options) { o.UserInfoEndpoint = testIssuer + "/../userinfo" }},
		{"subject 秘密过短", func(o *oidc.Options) { o.SubjectSecret = bytesOf('x', 8) }},
		{"未实现 Scope", func(o *oidc.Options) { o.SupportedScopes = []string{"openid", "admin"} }},
		{"无令牌服务", func(o *oidc.Options) { o.Tokens = nil }},
		{"无用户来源", func(o *oidc.Options) { o.Users = nil }},
		{"无在线撤销检查器", func(o *oidc.Options) { o.RevocationChecker = nil }},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			options := base
			testCase.mutate(&options)
			if _, err := oidc.New(options); !errors.Is(err, oidc.ErrOptionsInvalid) {
				t.Fatalf("非法配置构造错误 = %v，期望 ErrOptionsInvalid", err)
			}
		})
	}
	// 发现文档 must not 声明未实现的 OpenID Provider 元数据。
	document := env.service.Discovery()
	if document.ClaimsParameterSupported || document.RequestParameterSupported ||
		document.RequestURIParameterSupported {
		t.Error("不应声明未实现的 claims/request 参数支持")
	}
}

// fakeUsers 是 UserInfoSource 的最小替身（仅供配置校验用例）。
type fakeUsers struct{}

func (f *fakeUsers) LoadUserInfo(context.Context, string) (oidc.UserInfoRecord, bool, error) {
	return oidc.UserInfoRecord{}, false, nil
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
