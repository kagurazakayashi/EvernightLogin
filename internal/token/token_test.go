package token_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	. "github.com/kagurazakayashi/EvernightLogin/internal/token"
	tokensqlite "github.com/kagurazakayashi/EvernightLogin/internal/token/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const (
	testIssuer   = "https://issuer.example.test"
	testClient   = "app_00000000000000000000000000000001"
	testClientB  = "app_00000000000000000000000000000002"
	testUserA    = "usr_00000000000000000000000000000001"
	testUserB    = "usr_00000000000000000000000000000002"
	testAudience = "https://api.example.test"
	testScope    = "profile.read"
)

// fakeClients 是 ClientSource 测试替身：按登记配置返回，缺失/故障 fail-closed。
type fakeClients struct {
	clients map[string]ClientInfo
	err     error
}

func (f *fakeClients) LoadClient(_ context.Context, clientID string) (ClientInfo, error) {
	if f.err != nil {
		return ClientInfo{}, f.err
	}
	client, found := f.clients[clientID]
	if !found {
		return ClientInfo{}, ErrClientNotFound
	}
	return client, nil
}

// fakeAuthorizer 记录签发授权判定并可注入拒绝。
type fakeAuthorizer struct {
	mu       sync.Mutex
	allow    bool
	err      error
	requests []IssuanceRequest
}

func (f *fakeAuthorizer) AuthorizeIssuance(_ context.Context, _ Caller, request IssuanceRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, request)
	if f.err != nil {
		return f.err
	}
	if !f.allow {
		return ErrAccessDenied
	}
	return nil
}

type testEnv struct {
	t          *testing.T
	ctx        context.Context
	raw        *storagesqlite.Store
	store      *tokensqlite.Store
	service    *Service
	audit      *audit.Recorder
	keyring    *secrets.Keyring
	clients    *fakeClients
	authorizer *fakeAuthorizer
	now        time.Time
}

func newTestEnv(t *testing.T, mutate func(*Options)) *testEnv {
	t.Helper()
	ctx := context.Background()
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(filepath.Join(testutil.TempDir(t), "token-test.db")))
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
	env := &testEnv{t: t, ctx: ctx, raw: raw, now: time.Now().UTC().Truncate(time.Millisecond)}
	env.audit, err = audit.New(auditStore, audit.Options{Now: func() time.Time { return env.now }})
	if err != nil {
		t.Fatalf("审计: %v", err)
	}
	keyring, err := secrets.GenerateKeyring("k1", env.now)
	if err != nil {
		t.Fatalf("密钥环: %v", err)
	}
	env.keyring = keyring
	sealer, err := secrets.NewSealer(keyring, nil)
	if err != nil {
		t.Fatalf("Sealer: %v", err)
	}
	store, err := tokensqlite.New(raw)
	if err != nil {
		t.Fatalf("令牌存储: %v", err)
	}
	env.store = store
	env.clients = &fakeClients{clients: map[string]ClientInfo{
		testClient: {
			ClientID: testClient, ApplicationID: testClient, ClientType: "public",
			AppActive:  true,
			GrantTypes: []string{string(GrantAuthorizationCode), string(GrantDeviceCode)},
			Scopes:     []string{testScope, "profile.write"}, Audiences: []string{testAudience},
		},
		testClientB: {
			ClientID: testClientB, ApplicationID: testClientB, ClientType: "confidential",
			AppActive:  true,
			GrantTypes: []string{string(GrantClientCredentials)},
			Scopes:     []string{"service.read"}, Audiences: []string{testAudience},
		},
	}}
	env.authorizer = &fakeAuthorizer{allow: true}
	options := Options{
		Store: store, Audit: env.audit, Sealer: sealer,
		Issuer: testIssuer, Clients: env.clients, Authorizer: env.authorizer,
		AccessTTL: 15 * time.Minute, IDTokenTTL: 10 * time.Minute,
		KeyRetention: 24 * time.Hour, ClockSkew: time.Minute,
		Now: func() time.Time { return env.now },
	}
	if mutate != nil {
		mutate(&options)
	}
	env.service, err = New(options)
	if err != nil {
		t.Fatalf("令牌服务: %v", err)
	}
	return env
}

// caller 构造用户调用者。
func (env *testEnv) caller(userID string) Caller {
	env.t.Helper()
	caller, err := UserCaller(userID)
	if err != nil {
		env.t.Fatalf("调用者: %v", err)
	}
	return caller
}

// systemCaller 构造受信系统调用者。
func (env *testEnv) systemCaller() Caller {
	env.t.Helper()
	caller, err := SystemCaller("oauth-orchestrator")
	if err != nil {
		env.t.Fatalf("系统调用者: %v", err)
	}
	return caller
}

// accessRequest 返回一条合法的用户 Access Token 签发请求。
func accessRequest() IssueAccessTokenRequest {
	return IssueAccessTokenRequest{
		ClientID: testClient, SubjectUserID: testUserA, GrantType: GrantAuthorizationCode,
		Scopes: []string{testScope}, Audiences: []string{testAudience}, RequestID: "req-issue-1",
	}
}

// issueAccess 签发一条 Access Token。
func (env *testEnv) issueAccess() IssuedToken {
	env.t.Helper()
	issued, err := env.service.IssueAccessToken(env.ctx, env.caller(testUserA), accessRequest())
	if err != nil {
		env.t.Fatalf("签发 Access Token: %v", err)
	}
	return issued
}

// activeKey 读取当前 active 密钥并解密为签名密钥（测试构造任意声明用）。
func (env *testEnv) activeKey() KeyRecord {
	env.t.Helper()
	record, found, err := env.store.GetActiveKey(env.ctx)
	if err == nil && !found {
		record, err = env.service.EnsureActiveKeyForTest(env.ctx)
	}
	if err != nil || record.Kid == "" {
		env.t.Fatalf("读取 active 密钥: %v", err)
	}
	return record
}

// signClaimsForTest 用当前 active 密钥对任意声明签名（生成负向测试令牌）。
func (env *testEnv) signClaimsForTest(claims any, typ string) string {
	env.t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		env.t.Fatalf("编码声明: %v", err)
	}
	compact, err := env.service.SignClaimsForTest(env.activeKey(), payload, typ)
	if err != nil {
		env.t.Fatalf("签名: %v", err)
	}
	return compact
}

// testAccessClaims 是与 Access Token 声明等价的外部测试结构（JSON 标签一致）。
type testAccessClaims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  []string `json:"aud"`
	ClientID  string   `json:"client_id"`
	Scope     string   `json:"scope,omitempty"`
	TokenUse  string   `json:"token_use"`
	IssuedAt  int64    `json:"iat"`
	NotBefore int64    `json:"nbf,omitempty"`
	ExpiresAt int64    `json:"exp"`
	TokenID   string   `json:"jti"`
}

// validAccessClaims 返回一份合法声明（测试按需篡改）。
func validAccessClaims(now time.Time) testAccessClaims {
	return testAccessClaims{
		Issuer: testIssuer, Subject: testUserA, Audience: []string{testAudience},
		ClientID: testClient, Scope: testScope, TokenUse: TokenUseAccess,
		IssuedAt: now.Unix(), NotBefore: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
		TokenID: "jti_test_1",
	}
}

// count 统计计数查询。
func (env *testEnv) count(query string, args ...any) int {
	env.t.Helper()
	rows, err := env.raw.QueryContext(env.ctx, query, args...)
	if err != nil {
		env.t.Fatalf("计数查询: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		env.t.Fatalf("计数查询无结果")
	}
	var value int
	if err := rows.Scan(&value); err != nil {
		env.t.Fatalf("扫描计数: %v", err)
	}
	return value
}

// auditDump 拼接审计动作与差异，用于断言不泄密。
func (env *testEnv) auditDump() string {
	env.t.Helper()
	rows, err := env.raw.QueryContext(env.ctx,
		`SELECT action||'|'||COALESCE(detail_json,'')||'|'||COALESCE(reason_code,'') FROM audit_events`)
	if err != nil {
		env.t.Fatalf("读取审计: %v", err)
	}
	defer rows.Close()
	var builder strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			env.t.Fatalf("扫描审计: %v", err)
		}
		builder.WriteString(line + "\n")
	}
	return builder.String()
}

// TestIssueAndVerifyAccessToken 覆盖签发验签主路径、错误 audience、篡改与类型混用。
func TestIssueAndVerifyAccessToken(t *testing.T) {
	env := newTestEnv(t, nil)
	issued := env.issueAccess()
	if issued.Subject != testUserA || issued.KeyID == "" || issued.TokenID == "" {
		t.Fatalf("签发结果异常: %+v", issued)
	}
	claims, err := env.service.VerifyAccessToken(env.ctx, issued.Token.Reveal(), testAudience)
	if err != nil {
		t.Fatalf("验证 Access Token: %v", err)
	}
	if claims.Subject != testUserA || claims.ClientID != testClient ||
		claims.TokenUse != TokenUseAccess || claims.KeyID != issued.KeyID ||
		len(claims.Scopes) != 1 || claims.Scopes[0] != testScope {
		t.Fatalf("声明异常: %+v", claims)
	}
	if claims.Issuer != testIssuer {
		t.Fatalf("issuer = %q", claims.Issuer)
	}
	if _, err := env.service.VerifyAccessToken(env.ctx, issued.Token.Reveal(), "https://other.example.test"); !errors.Is(err, ErrAudienceMismatch) {
		t.Fatalf("错误 audience 应拒绝，得到 %v", err)
	}
	// 篡改 payload：签名验证必须失败。
	parts := strings.Split(issued.Token.Reveal(), ".")
	tamperedPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"x"}`))
	tampered := parts[0] + "." + tamperedPayload + "." + parts[2]
	if _, err := env.service.VerifyAccessToken(env.ctx, tampered, testAudience); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("篡改令牌应签名失败，得到 %v", err)
	}
	// Access Token 不能当 ID Token 用。
	if _, err := env.service.VerifyIDToken(env.ctx, issued.Token.Reveal(), testClient); !errors.Is(err, ErrWrongType) {
		t.Fatalf("Access Token 当 ID Token 应拒绝，得到 %v", err)
	}
}

// TestWrongAlgorithmAndMaliciousKeyReferences 覆盖错误算法与不受控密钥引用拒绝。
func TestWrongAlgorithmAndMaliciousKeyReferences(t *testing.T) {
	env := newTestEnv(t, nil)
	env.issueAccess()
	env.authorizer.allow = true
	key := env.activeKey()
	claims := validAccessClaims(env.now)
	payload, _ := json.Marshal(claims)
	// HS256 token（相同 kid）：固定允许算法必须拒绝。
	hmacKey := []byte("0123456789abcdef0123456789abcdef")
	hmacSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: hmacKey},
		(&jose.SignerOptions{}).WithType(jose.ContentType(AccessTokenType)).
			WithHeader(jose.HeaderKey("kid"), key.Kid))
	if err != nil {
		t.Fatalf("构造 HS256 签名器: %v", err)
	}
	hmacObject, err := hmacSigner.Sign(payload)
	if err != nil {
		t.Fatalf("HS256 签名: %v", err)
	}
	hmacToken, _ := hmacObject.CompactSerialize()
	if _, err := env.service.VerifyAccessToken(env.ctx, hmacToken, testAudience); !errors.Is(err, ErrWrongAlgorithm) {
		t.Fatalf("错误算法应拒绝，得到 %v", err)
	}
	// 将受控签名密钥签出的令牌头部加入 jku 远程密钥引用：必须拒绝。
	privateKey, err := env.service.OpenPrivateKeyForTest(key)
	if err != nil {
		t.Fatalf("解密私钥: %v", err)
	}
	signerOptions := (&jose.SignerOptions{}).WithType(jose.ContentType(AccessTokenType)).
		WithHeader(jose.HeaderKey("kid"), key.Kid).
		WithHeader(jose.HeaderKey("jku"), "https://attacker.example.test/keys")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: privateKey}, signerOptions)
	if err != nil {
		t.Fatalf("构造 jku 签名器: %v", err)
	}
	object, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("jku 签名: %v", err)
	}
	jkuToken, _ := object.CompactSerialize()
	if _, err := env.service.VerifyAccessToken(env.ctx, jkuToken, testAudience); !errors.Is(err, ErrMaliciousKeyRef) {
		t.Fatalf("jku 引用应拒绝，得到 %v", err)
	}
	// 内嵌 jwk 头（EmbedJWK）同样拒绝。
	embedOptions := (&jose.SignerOptions{EmbedJWK: true}).WithType(jose.ContentType(AccessTokenType)).
		WithHeader(jose.HeaderKey("kid"), key.Kid)
	embedSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: privateKey}, embedOptions)
	if err != nil {
		t.Fatalf("构造 jwk 签名器: %v", err)
	}
	embedded, err := embedSigner.Sign(payload)
	if err != nil {
		t.Fatalf("jwk 签名: %v", err)
	}
	embedToken, _ := embedded.CompactSerialize()
	if _, err := env.service.VerifyAccessToken(env.ctx, embedToken, testAudience); !errors.Is(err, ErrMaliciousKeyRef) {
		t.Fatalf("内嵌 jwk 应拒绝，得到 %v", err)
	}
	// "alg=none" 粗糙令牌直接拒绝。
	noneHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"at+jwt","kid":"` + key.Kid + `"}`))
	noneToken := noneHeader + "." + base64.RawURLEncoding.EncodeToString(payload) + "."
	if _, err := env.service.VerifyAccessToken(env.ctx, noneToken, testAudience); !errors.Is(err, ErrWrongAlgorithm) {
		t.Fatalf("none 算法应拒绝，得到 %v", err)
	}
}

// TestClaimValidation 覆盖 issuer/类型/必需声明/时间容差与过期。
func TestClaimValidation(t *testing.T) {
	env := newTestEnv(t, nil)
	key := env.activeKey()
	_ = key
	base := validAccessClaims(env.now)
	cases := []struct {
		name   string
		mutate func(*testAccessClaims)
		want   error
	}{
		{name: "错误签发方", mutate: func(c *testAccessClaims) { c.Issuer = "https://evil.example.test" }, want: ErrWrongIssuer},
		{name: "错误类型", mutate: func(c *testAccessClaims) { c.TokenUse = TokenUseID }, want: ErrWrongType},
		{name: "缺少主体", mutate: func(c *testAccessClaims) { c.Subject = "" }, want: ErrMissingClaims},
		{name: "缺少 jti", mutate: func(c *testAccessClaims) { c.TokenID = "" }, want: ErrMissingClaims},
		{name: "过期", mutate: func(c *testAccessClaims) { c.ExpiresAt = env.now.Add(-2 * time.Minute).Unix() }, want: ErrTokenExpired},
		{name: "尚未生效", mutate: func(c *testAccessClaims) { c.NotBefore = env.now.Add(time.Hour).Unix() }, want: ErrTokenNotYetValid},
		{name: "签发时间在未来", mutate: func(c *testAccessClaims) { c.IssuedAt = env.now.Add(time.Hour).Unix() }, want: ErrTokenNotYetValid},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			claims := base
			claims.Audience = append([]string(nil), base.Audience...)
			test.mutate(&claims)
			token := env.signClaimsForTest(claims, AccessTokenType)
			if _, err := env.service.VerifyAccessToken(env.ctx, token, testAudience); !errors.Is(err, test.want) {
				t.Fatalf("期望 %v，得到 %v", test.want, err)
			}
		})
	}
	// 恰在容差内仍接受：过期 30 秒 + 容差 1 分钟。
	withinSkew := base
	withinSkew.ExpiresAt = env.now.Add(-30 * time.Second).Unix()
	token := env.signClaimsForTest(withinSkew, AccessTokenType)
	if _, err := env.service.VerifyAccessToken(env.ctx, token, testAudience); err != nil {
		t.Fatalf("容差内过期令牌应接受: %v", err)
	}
	// 超过容差拒绝。
	beyond := base
	beyond.ExpiresAt = env.now.Add(-2 * time.Minute).Unix()
	if _, err := env.service.VerifyAccessToken(env.ctx, env.signClaimsForTest(beyond, AccessTokenType), testAudience); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("超过容差应过期，得到 %v", err)
	}
}

// TestUnknownKeyAndForgedSignature 覆盖未知 kid 与伪造签名。
func TestUnknownKeyAndForgedSignature(t *testing.T) {
	env := newTestEnv(t, nil)
	base := validAccessClaims(env.now)
	// 未知 kid（格式合法）：即使签名有效也拒绝。
	unknown := base
	token := env.signClaimsForTestWithKid(unknown, "kid_0000000000000000000000000000dead")
	if _, err := env.service.VerifyAccessToken(env.ctx, token, testAudience); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("未知 kid 应拒绝，得到 %v", err)
	}
	// 使用 active kid 但随机私钥签名：签名验证失败。
	record := env.activeKey()
	randomKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成随机密钥: %v", err)
	}
	payload, _ := json.Marshal(base)
	options := (&jose.SignerOptions{}).WithType(jose.ContentType(AccessTokenType)).
		WithHeader(jose.HeaderKey("kid"), record.Kid)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: randomKey}, options)
	if err != nil {
		t.Fatalf("构造伪造签名器: %v", err)
	}
	object, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("伪造签名: %v", err)
	}
	forged, _ := object.CompactSerialize()
	if _, err := env.service.VerifyAccessToken(env.ctx, forged, testAudience); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("伪造签名应拒绝，得到 %v", err)
	}
}

// signClaimsForTestWithKid 用临时随机密钥按指定 kid 签名（构造未知 kid 令牌）。
func (env *testEnv) signClaimsForTestWithKid(claims any, kid string) string {
	env.t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		env.t.Fatalf("生成临时密钥: %v", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		env.t.Fatalf("编码声明: %v", err)
	}
	options := (&jose.SignerOptions{}).WithType(jose.ContentType(AccessTokenType)).
		WithHeader(jose.HeaderKey("kid"), kid)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, options)
	if err != nil {
		env.t.Fatalf("构造临时签名器: %v", err)
	}
	object, err := signer.Sign(payload)
	if err != nil {
		env.t.Fatalf("临时签名: %v", err)
	}
	compact, _ := object.CompactSerialize()
	return compact
}

// TestKeyRotationGraceAndRetirement 覆盖轮换期间旧令牌可用、退役后拒绝、JWKS 发布集合。
func TestKeyRotationGraceAndRetirement(t *testing.T) {
	env := newTestEnv(t, nil)
	firstToken := env.issueAccess()
	oldKid := env.activeKey().Kid
	rotated, err := env.service.RotateSigningKey(env.ctx, env.systemCaller(), "req-rotate-1")
	if err != nil {
		t.Fatalf("轮换密钥: %v", err)
	}
	if rotated.Status != KeyActive || rotated.Kid == oldKid {
		t.Fatalf("轮换结果异常: %+v", rotated)
	}
	// 轮换后旧令牌仍在保留期内可验证。
	if _, err := env.service.VerifyAccessToken(env.ctx, firstToken.Token.Reveal(), testAudience); err != nil {
		t.Fatalf("轮换保留期内旧令牌应可验证: %v", err)
	}
	// JWKS 同时发布旧（retired）与新（active）公钥。
	jwks, err := env.service.PublishedJWKS(env.ctx)
	if err != nil {
		t.Fatalf("读取 JWKS: %v", err)
	}
	var keySet jose.JSONWebKeySet
	if err := json.Unmarshal(jwks, &keySet); err != nil {
		t.Fatalf("解析 JWKS: %v", err)
	}
	if len(keySet.Keys) != 2 {
		t.Fatalf("JWKS 公钥数量 = %d，期望 2", len(keySet.Keys))
	}
	// 新签发令牌使用新 kid。
	newToken := env.issueAccess()
	if newToken.KeyID != rotated.Kid {
		t.Fatalf("新令牌 kid = %q，期望 %q", newToken.KeyID, rotated.Kid)
	}
	// 超过保留期后旧令牌拒绝、旧公钥不再发布。
	env.now = env.now.Add(25 * time.Hour)
	if _, err := env.service.VerifyAccessToken(env.ctx, firstToken.Token.Reveal(), testAudience); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("保留期后旧令牌应拒绝，得到 %v", err)
	}
	jwks, err = env.service.PublishedJWKS(env.ctx)
	if err != nil {
		t.Fatalf("读取 JWKS: %v", err)
	}
	keySet = jose.JSONWebKeySet{}
	if err := json.Unmarshal(jwks, &keySet); err != nil {
		t.Fatalf("解析 JWKS: %v", err)
	}
	for _, key := range keySet.Keys {
		if key.KeyID == oldKid {
			t.Fatal("退役保留期后旧公钥仍被发布")
		}
	}
}

// TestKeyRevocation 覆盖紧急撤销：旧令牌立即拒绝、公钥停止发布、审计留痕。
func TestKeyRevocation(t *testing.T) {
	env := newTestEnv(t, nil)
	issued := env.issueAccess()
	kid := env.activeKey().Kid
	if err := env.service.RevokeSigningKey(env.ctx, env.systemCaller(), "req-revoke-1", kid, "疑似泄露"); err != nil {
		t.Fatalf("撤销密钥: %v", err)
	}
	if _, err := env.service.VerifyAccessToken(env.ctx, issued.Token.Reveal(), testAudience); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("撤销密钥后令牌应拒绝，得到 %v", err)
	}
	jwks, err := env.service.PublishedJWKS(env.ctx)
	if err != nil {
		t.Fatalf("读取 JWKS: %v", err)
	}
	if strings.Contains(string(jwks), kid) {
		t.Fatal("撤销密钥仍出现在 JWKS")
	}
	if !strings.Contains(env.auditDump(), "token.key.revoked") {
		t.Fatal("撤销密钥缺少审计")
	}
	// 撤销 active 后没有可签密钥：下一次签发引导创建新密钥（系统主体审计）。
	issued2 := env.issueAccess()
	if issued2.KeyID == kid {
		t.Fatal("撤销后不应复用旧密钥")
	}
	if _, err := env.service.VerifyAccessToken(env.ctx, issued2.Token.Reveal(), testAudience); err != nil {
		t.Fatalf("新签发令牌验证: %v", err)
	}
}

// TestIssuanceCannotForgeAuthorization 覆盖签发不能伪造调用者/主体身份。
func TestIssuanceCannotForgeAuthorization(t *testing.T) {
	// 未注入授权器拒绝构造。
	if _, err := New(Options{}); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatalf("缺少授权器应拒绝构造，得到 %v", err)
	}
	env := newTestEnv(t, nil)
	// 普通用户不能为其他主体签发。
	if _, err := env.service.IssueAccessToken(env.ctx, env.caller(testUserA),
		IssueAccessTokenRequest{ClientID: testClient, SubjectUserID: testUserB,
			GrantType: GrantAuthorizationCode, Scopes: []string{testScope},
			Audiences: []string{testAudience}, RequestID: "req-forge"}); !errors.Is(err, ErrSubjectNotAllowed) {
		t.Fatalf("为他人签发应拒绝，得到 %v", err)
	}
	// 授权器拒绝时 fail-closed 并写失败审计。
	env.authorizer.allow = false
	if _, err := env.service.IssueAccessToken(env.ctx, env.caller(testUserA), accessRequest()); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("授权器拒绝应 fail-closed，得到 %v", err)
	}
	if !strings.Contains(env.auditDump(), "token.issuance_denied") {
		t.Fatal("签发拒绝缺少失败审计")
	}
	// 受信系统调用者在授权器允许时可以代表用户签发（受控编排服务）。
	env.authorizer.allow = true
	issued, err := env.service.IssueAccessToken(env.ctx, env.systemCaller(), accessRequest())
	if err != nil {
		t.Fatalf("受信系统调用者签发: %v", err)
	}
	claims, err := env.service.VerifyAccessToken(env.ctx, issued.Token.Reveal(), testAudience)
	if err != nil || claims.Subject != testUserA {
		t.Fatalf("系统调用者签发结果异常: %v %+v", err, claims)
	}
}

// TestClientScopeAudienceValidation 覆盖客户端/授权类型/Scope/audience 校验。
func TestClientScopeAudienceValidation(t *testing.T) {
	env := newTestEnv(t, nil)
	cases := []struct {
		name   string
		mutate func(*IssueAccessTokenRequest)
		want   error
	}{
		{name: "未知客户端", mutate: func(r *IssueAccessTokenRequest) { r.ClientID = "app_0000000000000000000000000000000f" }, want: ErrClientNotFound},
		{name: "未登记 Scope", mutate: func(r *IssueAccessTokenRequest) { r.Scopes = []string{"admin.all"} }, want: ErrScopeNotAllowed},
		{name: "未登记 audience", mutate: func(r *IssueAccessTokenRequest) { r.Audiences = []string{"https://other.example.test"} }, want: ErrAudienceNotAllowed},
		{name: "客户端不支持授权类型", mutate: func(r *IssueAccessTokenRequest) { r.GrantType = GrantClientCredentials; r.SubjectUserID = "" }, want: ErrGrantNotAllowed},
		{name: "刷新令牌不支持", mutate: func(r *IssueAccessTokenRequest) { r.GrantType = "refresh_token" }, want: ErrRefreshNotSupported},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			request := accessRequest()
			test.mutate(&request)
			if _, err := env.service.IssueAccessToken(env.ctx, env.caller(testUserA), request); !errors.Is(err, test.want) {
				t.Fatalf("期望 %v，得到 %v", test.want, err)
			}
		})
	}
	// 应用停用：CLIENT_DISABLED。
	inactive := env.clients.clients[testClient]
	inactive.AppActive = false
	env.clients.clients[testClient] = inactive
	if _, err := env.service.IssueAccessToken(env.ctx, env.caller(testUserA), accessRequest()); !errors.Is(err, ErrClientInactive) {
		t.Fatalf("应用停用应拒绝，得到 %v", err)
	}
}

// TestIDTokenIssueAndVerify 覆盖 ID Token 签发验签与类型隔离。
func TestIDTokenIssueAndVerify(t *testing.T) {
	env := newTestEnv(t, nil)
	env.authorizer.allow = true
	request := IssueIDTokenRequest{
		ClientID: testClient, SubjectUserID: testUserA, Nonce: "nonce-1",
		AuthTime: env.now.Add(-5 * time.Minute), RequestID: "req-idtoken",
	}
	issued, err := env.service.IssueIDToken(env.ctx, env.caller(testUserA), request)
	if err != nil {
		t.Fatalf("签发 ID Token: %v", err)
	}
	claims, err := env.service.VerifyIDToken(env.ctx, issued.Token.Reveal(), testClient)
	if err != nil {
		t.Fatalf("验证 ID Token: %v", err)
	}
	if claims.Subject != testUserA || claims.Audience != testClient ||
		claims.TokenUse != TokenUseID || claims.Nonce != "nonce-1" || claims.AuthTime.IsZero() {
		t.Fatalf("ID Token 声明异常: %+v", claims)
	}
	// 不能当 Access Token 使用；错误 clientID 拒绝。
	if _, err := env.service.VerifyAccessToken(env.ctx, issued.Token.Reveal(), testAudience); !errors.Is(err, ErrWrongType) {
		t.Fatalf("ID Token 当 Access Token 应拒绝，得到 %v", err)
	}
	if _, err := env.service.VerifyIDToken(env.ctx, issued.Token.Reveal(), testClientB); !errors.Is(err, ErrAudienceMismatch) {
		t.Fatalf("错误 clientID 应拒绝，得到 %v", err)
	}
	// 普通用户不能为他人签发 ID Token。
	if _, err := env.service.IssueIDToken(env.ctx, env.caller(testUserA), IssueIDTokenRequest{
		ClientID: testClient, SubjectUserID: testUserB, RequestID: "req-id-forge"}); !errors.Is(err, ErrSubjectNotAllowed) {
		t.Fatalf("为他人签发 ID Token 应拒绝，得到 %v", err)
	}
}

// TestJWKSContainsOnlyPublicMaterial 验证 JWKS 只含公钥、数据库私钥只存密文。
func TestJWKSContainsOnlyPublicMaterial(t *testing.T) {
	env := newTestEnv(t, nil)
	env.issueAccess()
	jwks, err := env.service.PublishedJWKS(env.ctx)
	if err != nil {
		t.Fatalf("读取 JWKS: %v", err)
	}
	var keySet jose.JSONWebKeySet
	if err := json.Unmarshal(jwks, &keySet); err != nil {
		t.Fatalf("解析 JWKS: %v", err)
	}
	if len(keySet.Keys) != 1 {
		t.Fatalf("JWKS 公钥数量 = %d", len(keySet.Keys))
	}
	key := keySet.Keys[0]
	if !key.IsPublic() || key.KeyID == "" || key.Algorithm != AlgorithmES256 ||
		key.Use != KeyUseSignature || strings.Contains(string(jwks), `"d"`) {
		t.Fatalf("JWKS 公钥内容异常: %s", string(jwks))
	}
	if key.Valid() == false {
		t.Fatal("JWKS 公钥无法被 JOSE 库识别")
	}
	// 数据库只保存密文：不出现私有 JWK 字段或 PEM/DER 明文标记。
	rows, err := env.raw.QueryContext(env.ctx, `SELECT public_jwk,sealed_private FROM token_signing_keys`)
	if err != nil {
		t.Fatalf("读取密钥行: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var publicJWK, sealed []byte
		if err := rows.Scan(&publicJWK, &sealed); err != nil {
			t.Fatalf("扫描密钥行: %v", err)
		}
		if strings.Contains(string(publicJWK), `"d"`) {
			t.Fatal("公开 JWK 含私有字段")
		}
		if len(sealed) == 0 || strings.Contains(string(sealed), "PRIVATE KEY") {
			t.Fatal("私钥不是密文保存")
		}
	}
	// 审计不含令牌原文或私钥材料。
	dump := env.auditDump()
	if strings.Contains(dump, `"d"`) || strings.Contains(dump, "PRIVATE KEY") {
		t.Fatal("审计泄露私钥材料")
	}
}

// TestKeyRetentionOptionValidation 验证保留期/时钟容差/签发方配置边界。
func TestKeyRetentionOptionValidation(t *testing.T) {
	base := func() Options {
		env := newTestEnv(t, nil)
		return Options{
			Store: env.store, Audit: env.audit, Sealer: env.service.OptionsForTest().Sealer,
			Issuer: testIssuer, Clients: env.clients, Authorizer: env.authorizer,
			AccessTTL: 15 * time.Minute, IDTokenTTL: 10 * time.Minute,
			KeyRetention: 20 * time.Minute, ClockSkew: time.Minute,
			Now: func() time.Time { return env.now },
		}
	}
	if _, err := New(base()); err == nil {
		t.Fatal("保留期小于最长令牌有效期+容差应拒绝构造")
	}
	invalidIssuers := []string{"", "issuer", "http://evil.example.test", "https://issuer.example.test/?x=1", "https://user:pass@issuer.example.test"}
	for _, issuer := range invalidIssuers {
		options := base()
		options.Issuer = issuer
		options.KeyRetention = 24 * time.Hour
		if _, err := New(options); !errors.Is(err, ErrOptionsInvalid) {
			t.Fatalf("签发方 %q 应拒绝构造，得到 %v", issuer, err)
		}
	}
	options := base()
	options.KeyRetention = 24 * time.Hour
	options.ClockSkew = time.Hour
	if _, err := New(options); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatalf("时钟容差越界应拒绝构造，得到 %v", err)
	}
}

// TestClientCredentialsSubject 验证 client_credentials 只允许保密客户端且主体为客户端。
func TestClientCredentialsSubject(t *testing.T) {
	env := newTestEnv(t, nil)
	request := IssueAccessTokenRequest{
		ClientID: testClientB, GrantType: GrantClientCredentials,
		Scopes: []string{"service.read"}, Audiences: []string{testAudience}, RequestID: "req-cc",
	}
	issued, err := env.service.IssueAccessToken(env.ctx, env.systemCaller(), request)
	if err != nil {
		t.Fatalf("client_credentials 签发: %v", err)
	}
	claims, err := env.service.VerifyAccessToken(env.ctx, issued.Token.Reveal(), testAudience)
	if err != nil || claims.Subject != testClientB {
		t.Fatalf("服务主体声明异常: %v %+v", err, claims)
	}
	// 公开客户端不能使用 client_credentials。
	publicRequest := request
	publicRequest.ClientID = testClient
	if _, err := env.service.IssueAccessToken(env.ctx, env.systemCaller(), publicRequest); !errors.Is(err, ErrGrantNotAllowed) {
		t.Fatalf("公开客户端 client_credentials 应拒绝，得到 %v", err)
	}
	// client_credentials 不允许用户主体。
	withUser := request
	withUser.SubjectUserID = testUserA
	if _, err := env.service.IssueAccessToken(env.ctx, env.systemCaller(), withUser); !errors.Is(err, ErrSubjectNotAllowed) {
		t.Fatalf("client_credentials 用户主体应拒绝，得到 %v", err)
	}
}

// TestAuditedWithoutTokenMaterial 验证签发/轮换成功审计存在且不含令牌原文。
func TestAuditedWithoutTokenMaterial(t *testing.T) {
	env := newTestEnv(t, nil)
	issued := env.issueAccess()
	if _, err := env.service.RotateSigningKey(env.ctx, env.systemCaller(), "req-rotate-audit"); err != nil {
		t.Fatalf("轮换: %v", err)
	}
	dump := env.auditDump()
	for _, action := range []string{"token.access.issued", "token.key.rotated"} {
		if !strings.Contains(dump, action) {
			t.Errorf("缺少审计动作 %q", action)
		}
	}
	if strings.Contains(dump, issued.Token.Reveal()) {
		t.Fatal("审计泄露令牌原文")
	}
}

// fakeOAuthReader 是 OAuthClientReader 测试替身（模拟 oauthclient.Store.GetClient）。
type fakeOAuthReader struct {
	record oauthclient.ClientRecord
	found  bool
	err    error
}

func (f *fakeOAuthReader) GetClient(context.Context, string) (oauthclient.ClientRecord, bool, error) {
	return f.record, f.found, f.err
}

// TestOAuthClientSourceAdapter 验证生产适配器只读取客户端安全设置并映射应用状态。
func TestOAuthClientSourceAdapter(t *testing.T) {
	reader := &fakeOAuthReader{
		found: true,
		record: oauthclient.ClientRecord{
			Client: oauthclient.Client{
				ClientID: testClient, ClientType: oauthclient.ClientTypePublic,
				GrantTypes: []oauthclient.GrantType{oauthclient.GrantAuthorizationCode},
				Scopes:     []string{testScope}, Audiences: []string{testAudience},
			},
			AppStatus: "active",
		},
	}
	source, err := NewOAuthClientSource(reader)
	if err != nil {
		t.Fatalf("构造适配器: %v", err)
	}
	info, err := source.LoadClient(context.Background(), testClient)
	if err != nil {
		t.Fatalf("读取客户端: %v", err)
	}
	if !info.AppActive || info.ClientType != "public" || len(info.GrantTypes) != 1 ||
		info.GrantTypes[0] != string(GrantAuthorizationCode) ||
		len(info.Scopes) != 1 || len(info.Audiences) != 1 {
		t.Fatalf("客户端映射异常: %+v", info)
	}
	// 应用停用映射为 AppActive=false；不存在映射为 ErrClientNotFound。
	reader.record.AppStatus = "disabled"
	if info, _ := source.LoadClient(context.Background(), testClient); info.AppActive {
		t.Fatal("停用应用不应映射为可用")
	}
	reader.found = false
	if _, err := source.LoadClient(context.Background(), testClient); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("未登记客户端应 ErrClientNotFound，得到 %v", err)
	}
	if _, err := NewOAuthClientSource(nil); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatalf("空读取器应拒绝构造，得到 %v", err)
	}
}
