package oauthclient_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
	oauthclientsqlite "github.com/kagurazakayashi/EvernightLogin/internal/oauthclient/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const (
	appPublic       = "app_00000000000000000000000000000001"
	appConfidential = "app_00000000000000000000000000000002"
	appDisabled     = "app_00000000000000000000000000000003"
	appTLSCert      = "app_00000000000000000000000000000004"
	appMisMatching  = "app_00000000000000000000000000000005"
	seedMillis      = int64(1_700_000_000_000)
)

var fixedNow = time.UnixMilli(seedMillis).UTC()

// ===== 测试替身 =====

type fakeAuthorizer struct {
	deny  bool
	err   error
	calls int
}

func (f *fakeAuthorizer) AuthorizeClient(ctx context.Context, caller oauthclient.Caller, applicationID string, action oauthclient.Action) error {
	f.calls++
	if f.err != nil {
		return f.err
	}
	if f.deny {
		return oauthclient.ErrAccessDenied
	}
	return nil
}

type stubSensitive struct {
	denyErr        error
	authorizeCalls int
	notifyCalls    int
	lastRequest    reauth.Request
}

func (s *stubSensitive) Authorize(ctx context.Context, caller reauth.Caller, request reauth.Request) (reauth.Result, error) {
	s.authorizeCalls++
	s.lastRequest = request
	if s.denyErr != nil {
		return reauth.Result{}, s.denyErr
	}
	return reauth.Result{OperationID: request.OperationID, TargetType: request.TargetType,
		TargetID: request.TargetID, UserID: caller.Actor().ID,
		Decision: policy.Decision{Sensitive: true}}, nil
}

func (s *stubSensitive) NotifyOutcome(ctx context.Context, result reauth.Result, outcome reauth.Outcome) error {
	s.notifyCalls++
	return nil
}

// ===== 测试环境 =====

type testEnv struct {
	t     *testing.T
	ctx   context.Context
	raw   *storagesqlite.Store
	authz *fakeAuthorizer
	sens  *stubSensitive
	svc   *oauthclient.Service
	now   time.Time
}

func newTestEnv(t *testing.T, mutate func(*oauthclient.Options)) *testEnv {
	t.Helper()
	ctx := context.Background()
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(t.TempDir()+"/oauth.db"))
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
	recorder, err := audit.New(auditStore, audit.Options{Now: func() time.Time { return fixedNow }})
	if err != nil {
		t.Fatalf("审计: %v", err)
	}
	store, err := oauthclientsqlite.New(raw)
	if err != nil {
		t.Fatalf("客户端存储: %v", err)
	}
	env := &testEnv{t: t, ctx: ctx, raw: raw, authz: &fakeAuthorizer{}, sens: &stubSensitive{}, now: fixedNow}
	options := oauthclient.Options{
		Store: store, Audit: recorder, Authorizer: env.authz, Sensitive: env.sens,
		Now: func() time.Time { return env.now },
	}
	if mutate != nil {
		mutate(&options)
	}
	svc, err := oauthclient.New(options)
	if err != nil {
		t.Fatalf("客户端服务: %v", err)
	}
	env.svc = svc
	env.seedApplication(appPublic, "public", "active")
	env.seedApplication(appConfidential, "confidential", "active")
	env.seedApplication(appDisabled, "confidential", "disabled")
	env.seedApplication(appTLSCert, "confidential", "active")
	env.seedApplication(appMisMatching, "confidential", "active")
	return env
}

func (e *testEnv) seedApplication(id, clientType, status string) {
	e.t.Helper()
	if _, err := e.raw.DB().ExecContext(e.ctx, `INSERT INTO applications(
id,name,description,icon_ref,homepage,owner_user_id,contact_info,status,client_type,
row_version,created_at_ms,updated_at_ms
) VALUES(?,?,'',NULL,NULL,NULL,NULL,?,?,1,?,?)`,
		id, "应用-"+clientType, status, clientType, seedMillis, seedMillis); err != nil {
		e.t.Fatalf("应用: %v", err)
	}
}

func (e *testEnv) caller(t *testing.T) oauthclient.Caller {
	t.Helper()
	caller, err := oauthclient.UserCaller("usr_00000000000000000000000000000001")
	if err != nil {
		t.Fatalf("调用者: %v", err)
	}
	return caller
}

func (e *testEnv) count(query string, args ...any) int {
	e.t.Helper()
	var value int
	if err := e.raw.DB().QueryRowContext(e.ctx, query, args...).Scan(&value); err != nil {
		e.t.Fatalf("计数: %v", err)
	}
	return value
}

// makeCertificate 生成自签客户端证书 PEM；isCA 控制是否为 CA 证书。
func makeCertificate(t *testing.T, notBefore, notAfter time.Time, isCA bool) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥: %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("序列号: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "client-" + time.Now().Format("150405.000000")},
		NotBefore:    notBefore, NotAfter: notAfter,
		IsCA: isCA, BasicConstraintsValid: isCA,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("签发证书: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func validPublicRegister() oauthclient.RegisterRequest {
	return oauthclient.RegisterRequest{
		ClientID: appPublic, ClientType: oauthclient.ClientTypePublic,
		GrantTypes:   []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
		RedirectURIs: []string{"https://app.example.com/callback"},
		Scopes:       []string{"openid", "profile"},
		Audiences:    []string{"https://api.example.com"},
		RequestID:    "req-register",
	}
}

func validConfidentialRegister(clientID string) oauthclient.RegisterRequest {
	return oauthclient.RegisterRequest{
		ClientID: clientID, ClientType: oauthclient.ClientTypeConfidential,
		GrantTypes:   []string{"authorization_code", "refresh_token", "client_credentials"},
		RedirectURIs: []string{"https://app.example.com/callback"},
		Scopes:       []string{"openid"},
		Audiences:    []string{"https://api.example.com"},
		AuthMethods:  []string{"client_secret_basic"},
		RequestID:    "req-register",
	}
}

// ===== 测试用例 =====

// TestRegisterPublicClient 覆盖公开客户端登记：无 secret、强制 PKCE、拒绝 secret/
// 证书与 client_credentials，客户端类型必须与应用一致，返回不含任何凭证。
func TestRegisterPublicClient(t *testing.T) {
	env := newTestEnv(t, nil)
	result, err := env.svc.RegisterClient(env.ctx, env.caller(t), validPublicRegister())
	if err != nil {
		t.Fatalf("登记公开客户端: %v", err)
	}
	if result.Secret != nil || result.Certificate != nil {
		t.Error("公开客户端不应返回凭证")
	}
	if !result.Client.RequirePKCE || result.Client.ClientType != oauthclient.ClientTypePublic ||
		len(result.Client.AuthMethods) != 0 {
		t.Errorf("公开客户端设置异常: %+v", result.Client)
	}
	secrets, err := env.svc.ListClientSecrets(env.ctx, env.caller(t), appPublic)
	if err != nil || len(secrets) != 0 {
		t.Fatalf("公开客户端密钥列表 = %+v %v，期望为空", secrets, err)
	}
	// 重复登记冲突。
	if _, err := env.svc.RegisterClient(env.ctx, env.caller(t), validPublicRegister()); !errors.Is(err, oauthclient.ErrCredentialConflict) {
		t.Fatalf("重复登记错误 = %v，期望 ErrCredentialConflict", err)
	}
	// 非法组合：公开客户端配 secret 方式、client_credentials、PKCE=false、证书。
	badSecret := validPublicRegister()
	badSecret.AuthMethods = []string{"client_secret_basic"}
	badSecret.ClientID = appMisMatching
	if _, err := env.svc.RegisterClient(env.ctx, env.caller(t), badSecret); !errors.Is(err, oauthclient.ErrInvalidConfiguration) {
		t.Fatalf("公开客户端配 secret 错误 = %v", err)
	}
	badGrant := validPublicRegister()
	badGrant.ClientID = appMisMatching
	badGrant.GrantTypes = []string{"client_credentials"}
	if _, err := env.svc.RegisterClient(env.ctx, env.caller(t), badGrant); !errors.Is(err, oauthclient.ErrInvalidConfiguration) {
		t.Fatalf("公开客户端 client_credentials 错误 = %v", err)
	}
	noPKCE := false
	badPKCE := validPublicRegister()
	badPKCE.ClientID = appMisMatching
	badPKCE.RequirePKCE = &noPKCE
	if _, err := env.svc.RegisterClient(env.ctx, env.caller(t), badPKCE); !errors.Is(err, oauthclient.ErrInvalidConfiguration) {
		t.Fatalf("公开客户端关闭 PKCE 错误 = %v", err)
	}
	badCert := validPublicRegister()
	badCert.ClientID = appMisMatching
	badCert.CertificatePEM = makeCertificate(t, env.now.Add(-time.Hour), env.now.Add(time.Hour), false)
	if _, err := env.svc.RegisterClient(env.ctx, env.caller(t), badCert); !errors.Is(err, oauthclient.ErrInvalidConfiguration) {
		t.Fatalf("公开客户端配证书错误 = %v", err)
	}
	// 客户端类型与应用不一致。
	mismatch := validConfidentialRegister(appPublic)
	mismatch.AuthMethods = []string{"client_secret_basic"}
	if _, err := env.svc.RegisterClient(env.ctx, env.caller(t), mismatch); !errors.Is(err, oauthclient.ErrClientTypeMismatch) {
		t.Fatalf("客户端类型不一致错误 = %v，期望 ErrClientTypeMismatch", err)
	}
	// 不支持的授权类型。
	for _, grant := range []string{"password", "implicit"} {
		request := validPublicRegister()
		request.ClientID = appMisMatching
		request.GrantTypes = []string{grant}
		if _, err := env.svc.RegisterClient(env.ctx, env.caller(t), request); !errors.Is(err, oauthclient.ErrUnsupportedGrantType) {
			t.Fatalf("%s 授权错误 = %v，期望 ErrUnsupportedGrantType", grant, err)
		}
	}
	if env.count(`SELECT COUNT(*) FROM audit_events WHERE action='oauth.client.denied' AND outcome='denied'`) < 1 {
		t.Error("拒绝路径缺少失败审计")
	}
}

// TestConfidentialSecretLifecycle 覆盖保密客户端密钥：一次性展示、只存摘要、验证、
// 轮换过渡期、过期、撤销、最后凭证保护与停用/未知客户端拒绝。
func TestConfidentialSecretLifecycle(t *testing.T) {
	env := newTestEnv(t, nil)
	result, err := env.svc.RegisterClient(env.ctx, env.caller(t), validConfidentialRegister(appConfidential))
	if err != nil {
		t.Fatalf("登记保密客户端: %v", err)
	}
	if result.Secret == nil || result.Secret.Secret == "" || result.Secret.Info.Prefix == "" {
		t.Fatal("保密客户端登记必须一次性返回密钥")
	}
	firstSecret := result.Secret.Secret
	firstID := result.Secret.Info.ID
	// 库中只保存前缀与摘要，不含明文。
	var digestLength int
	if err := env.raw.DB().QueryRowContext(env.ctx,
		`SELECT length(secret_digest) FROM oauth_client_secrets WHERE id=?`, firstID).Scan(&digestLength); err != nil {
		t.Fatalf("读取摘要: %v", err)
	}
	if digestLength != 32 {
		t.Errorf("密钥摘要长度 = %d，期望 32", digestLength)
	}
	if env.count(`SELECT COUNT(*) FROM oauth_client_secrets WHERE secret_prefix=? AND id=?`,
		result.Secret.Info.Prefix, firstID) != 1 {
		t.Error("前缀未保存")
	}
	// 列表只返回前缀，不返回明文/摘要。
	infos, err := env.svc.ListClientSecrets(env.ctx, env.caller(t), appConfidential)
	if err != nil || len(infos) != 1 || infos[0].Prefix != result.Secret.Info.Prefix {
		t.Fatalf("密钥列表 = %+v %v", infos, err)
	}
	ListJSON, _ := json.Marshal(infos)
	if strings.Contains(string(ListJSON), firstSecret) {
		t.Error("密钥列表泄露明文")
	}
	// 审计不得包含密钥明文。
	rows, err := env.raw.DB().QueryContext(env.ctx, `SELECT COALESCE(detail_json,'') FROM audit_events`)
	if err != nil {
		t.Fatalf("读取审计: %v", err)
	}
	for rows.Next() {
		var detail string
		if err := rows.Scan(&detail); err != nil {
			rows.Close()
			t.Fatalf("扫描审计: %v", err)
		}
		if strings.Contains(detail, firstSecret) {
			rows.Close()
			t.Error("审计泄露客户端密钥明文")
		}
	}
	rows.Close()
	// 验证：正确密钥通过，错误密钥失败。
	identity, err := env.svc.VerifyClientSecret(env.ctx, appConfidential, firstSecret)
	if err != nil || identity.ClientID != appConfidential || identity.AuthMethod != oauthclient.AuthMethodSecretBasic {
		t.Fatalf("验证密钥: %v %+v", err, identity)
	}
	if _, err := env.svc.VerifyClientSecret(env.ctx, appConfidential, firstSecret+"x"); !errors.Is(err, oauthclient.ErrClientAuthFailed) {
		t.Fatalf("错误密钥 = %v，期望 ErrClientAuthFailed", err)
	}
	// 轮换：新密钥生效，旧密钥在过渡期内仍可用。
	rotated, err := env.svc.RotateClientSecret(env.ctx, env.caller(t), oauthclient.RotateSecretRequest{
		ClientID: appConfidential, RequestID: "req-rotate"})
	if err != nil {
		t.Fatalf("轮换密钥: %v", err)
	}
	if rotated.Secret == firstSecret {
		t.Fatal("轮换必须生成新密钥")
	}
	if _, err := env.svc.VerifyClientSecret(env.ctx, appConfidential, rotated.Secret); err != nil {
		t.Fatalf("新密钥验证: %v", err)
	}
	env.now = env.now.Add(2 * time.Hour)
	if _, err := env.svc.VerifyClientSecret(env.ctx, appConfidential, firstSecret); err != nil {
		t.Fatalf("过渡期内旧密钥应仍可用: %v", err)
	}
	// 撤销新密钥（此时旧密钥仍在过渡期，可用密钥数 > 1，允许撤销）；撤销后不可再用。
	infos, err = env.svc.ListClientSecrets(env.ctx, env.caller(t), appConfidential)
	if err != nil || len(infos) != 2 {
		t.Fatalf("轮换后密钥数 = %d", len(infos))
	}
	if err := env.svc.RevokeClientSecret(env.ctx, env.caller(t), oauthclient.RevokeSecretRequest{
		ClientID: appConfidential, SecretID: rotated.Info.ID, RequestID: "req-revoke"}); err != nil {
		t.Fatalf("撤销新密钥: %v", err)
	}
	if _, err := env.svc.VerifyClientSecret(env.ctx, appConfidential, rotated.Secret); !errors.Is(err, oauthclient.ErrClientAuthFailed) {
		t.Fatalf("撤销后密钥 = %v，期望 ErrClientAuthFailed", err)
	}
	// 幂等撤销。
	if err := env.svc.RevokeClientSecret(env.ctx, env.caller(t), oauthclient.RevokeSecretRequest{
		ClientID: appConfidential, SecretID: rotated.Info.ID, RequestID: "req-revoke2"}); err != nil {
		t.Fatalf("重复撤销应幂等: %v", err)
	}
	// 过渡期结束（默认 24 小时）后旧密钥失效。
	env.now = env.now.Add(25 * time.Hour)
	if _, err := env.svc.VerifyClientSecret(env.ctx, appConfidential, firstSecret); !errors.Is(err, oauthclient.ErrClientAuthFailed) {
		t.Fatalf("过渡期后旧密钥 = %v，期望 ErrClientAuthFailed", err)
	}
	// 停用应用后验证返回 CLIENT_DISABLED。
	if _, err := env.raw.DB().ExecContext(env.ctx, `UPDATE applications SET status='disabled' WHERE id=?`, appConfidential); err != nil {
		t.Fatalf("停用应用: %v", err)
	}
	if _, err := env.svc.VerifyClientSecret(env.ctx, appConfidential, rotated.Secret); !errors.Is(err, oauthclient.ErrClientDisabled) {
		t.Fatalf("停用应用验证 = %v，期望 ErrClientDisabled", err)
	}
	// 未知客户端与公开客户端都不能用密钥验证。
	if _, err := env.svc.VerifyClientSecret(env.ctx, "app_0000000000000000000000000000000f", "secret"); !errors.Is(err, oauthclient.ErrClientAuthFailed) {
		t.Fatalf("未知客户端 = %v", err)
	}
}

// TestSecretExpiryAndLastCredential 覆盖密钥过期与最后凭证保护。
func TestSecretExpiryAndLastCredential(t *testing.T) {
	env := newTestEnv(t, func(options *oauthclient.Options) {
		options.SecretTTL = 24 * time.Hour
		options.RotationGracePeriod = time.Minute
	})
	registered, err := env.svc.RegisterClient(env.ctx, env.caller(t), validConfidentialRegister(appTLSCert))
	if err != nil {
		t.Fatalf("登记: %v", err)
	}
	// 唯一密钥：撤销被拒（避免自锁）。
	if err := env.svc.RevokeClientSecret(env.ctx, env.caller(t), oauthclient.RevokeSecretRequest{
		ClientID: appTLSCert, SecretID: registered.Secret.Info.ID, RequestID: "req-last"}); !errors.Is(err, oauthclient.ErrLastCredential) {
		t.Fatalf("最后密钥撤销错误 = %v，期望 ErrLastCredential", err)
	}
	// 超过有效期后密钥失效。
	env.now = env.now.Add(25 * time.Hour)
	if _, err := env.svc.VerifyClientSecret(env.ctx, appTLSCert, registered.Secret.Secret); !errors.Is(err, oauthclient.ErrClientAuthFailed) {
		t.Fatalf("过期密钥 = %v，期望 ErrClientAuthFailed", err)
	}
}

// TestRedirectMatching 覆盖回调精确匹配与 RFC 8252 回环例外：大小写、编码、片段、
// 子域、查询串与自定义 scheme 边界，以及非法回调/非法组合拒绝。
func TestRedirectMatching(t *testing.T) {
	registered := []string{"https://app.example.com/cb?tenant=a"}
	for _, requested := range []string{
		"https://app.example.com/cb?tenant=b",
		"https://app.example.com/CB?tenant=a",
		"https://app.example.com/cb%2F?tenant=a",
		"https://app.example.com/cb?tenant=a&extra=1",
		"https://sub.app.example.com/cb?tenant=a",
		"https://app.example.com.evil.test/cb?tenant=a",
		"https://app.example.com/cb/../cb?tenant=a",
	} {
		if _, err := oauthclient.MatchRedirectURI(registered, requested, oauthclient.ClientTypeConfidential); !errors.Is(err, oauthclient.ErrRedirectMismatch) && !errors.Is(err, oauthclient.ErrInvalidRequest) {
			t.Errorf("回调 %q 错误 = %v，期望不匹配", requested, err)
		}
	}
	if _, err := oauthclient.MatchRedirectURI(registered, "https://app.example.com/cb?tenant=a", oauthclient.ClientTypeConfidential); err != nil {
		t.Fatalf("精确回调应匹配: %v", err)
	}
	// 片段一律拒绝。
	if _, err := oauthclient.MatchRedirectURI(registered, "https://app.example.com/cb#frag", oauthclient.ClientTypeConfidential); !errors.Is(err, oauthclient.ErrInvalidRequest) {
		t.Fatalf("片段回调 = %v，期望 ErrInvalidRequest", err)
	}
	// 通配符与开放重定向前缀不匹配。
	if _, err := oauthclient.MatchRedirectURI([]string{"https://app.example.com/*"}, "https://app.example.com/cb", oauthclient.ClientTypeConfidential); err == nil {
		t.Fatal("通配符登记不应匹配具体回调")
	}
	// RFC 8252 回环动态端口：路径/查询一致时忽略端口。
	loopback := []string{"http://127.0.0.1:8080/cb?x=1"}
	if _, err := oauthclient.MatchRedirectURI(loopback, "http://127.0.0.1:5000/cb?x=1", oauthclient.ClientTypePublic); err != nil {
		t.Fatalf("回环动态端口应匹配: %v", err)
	}
	if _, err := oauthclient.MatchRedirectURI(loopback, "http://127.0.0.1:5000/other?x=1", oauthclient.ClientTypePublic); !errors.Is(err, oauthclient.ErrRedirectMismatch) {
		t.Fatalf("回环换路径 = %v，期望不匹配", err)
	}
	if _, err := oauthclient.MatchRedirectURI(loopback, "http://localhost:5000/cb?x=1", oauthclient.ClientTypePublic); err == nil {
		t.Fatal("localhost 主机名不应按回环 IP 处理")
	}
	// 保密客户端不允许 http 回环与私有 scheme。
	if err := oauthclient.ValidateRedirectURI("http://127.0.0.1:8080/cb", oauthclient.ClientTypeConfidential); err == nil {
		t.Fatal("保密客户端不应允许 http 回环")
	}
	if err := oauthclient.ValidateRedirectURI("com.example.app:/cb", oauthclient.ClientTypeConfidential); err == nil {
		t.Fatal("保密客户端不应允许自定义 scheme")
	}
	if err := oauthclient.ValidateRedirectURI("com.example.app:/cb", oauthclient.ClientTypePublic); err != nil {
		t.Fatalf("公开客户端自定义 scheme 应允许: %v", err)
	}
	// 非回环 http 与 userinfo 拒绝。
	if err := oauthclient.ValidateRedirectURI("http://example.com/cb", oauthclient.ClientTypePublic); err == nil {
		t.Fatal("非回环 http 不应允许")
	}
	if err := oauthclient.ValidateRedirectURI("https://user:pass@app.example.com/cb", oauthclient.ClientTypeConfidential); err == nil {
		t.Fatal("userinfo 不应允许")
	}
}

// TestAuthorizationFailureAndSettingsChange 覆盖未经授权修改安全设置与管理/敏感
// 验证拒绝：拒绝时不产生配置变更并写失败审计；成功更新受行版本保护。
func TestAuthorizationFailureAndSettingsChange(t *testing.T) {
	env := newTestEnv(t, nil)
	// 管理权限拒绝：登记失败且无记录。
	env.authz.deny = true
	if _, err := env.svc.RegisterClient(env.ctx, env.caller(t), validConfidentialRegister(appConfidential)); !errors.Is(err, oauthclient.ErrAccessDenied) {
		t.Fatalf("未授权登记错误 = %v，期望 ErrAccessDenied", err)
	}
	if env.count(`SELECT COUNT(*) FROM oauth_clients`) != 0 {
		t.Error("未授权时不应创建客户端")
	}
	env.authz.deny = false
	// 敏感策略拒绝：登记失败且无记录。
	env.sens.denyErr = reauth.ErrReauthRequired
	if _, err := env.svc.RegisterClient(env.ctx, env.caller(t), validConfidentialRegister(appConfidential)); !errors.Is(err, oauthclient.ErrReauthRequired) {
		t.Fatalf("敏感策略拒绝错误 = %v，期望 ErrReauthRequired", err)
	}
	if env.count(`SELECT COUNT(*) FROM oauth_clients`) != 0 {
		t.Error("敏感策略拒绝时不应创建客户端")
	}
	env.sens.denyErr = nil
	// 正常登记后，未授权修改设置被拒且配置不变。
	if _, err := env.svc.RegisterClient(env.ctx, env.caller(t), validConfidentialRegister(appConfidential)); err != nil {
		t.Fatalf("登记: %v", err)
	}
	before, err := env.svc.GetClient(env.ctx, env.caller(t), appConfidential)
	if err != nil {
		t.Fatalf("读取客户端: %v", err)
	}
	env.authz.deny = true
	update := oauthclient.UpdateSettingsRequest{
		ClientID: appConfidential, GrantTypes: []string{"authorization_code"},
		RedirectURIs: []string{"https://other.example.com/cb"}, Scopes: []string{"openid"},
		Audiences: []string{"https://api.example.com"}, ExpectedRowVersion: before.RowVersion,
		RequestID: "req-update-denied",
	}
	if _, err := env.svc.UpdateClientSettings(env.ctx, env.caller(t), update); !errors.Is(err, oauthclient.ErrAccessDenied) {
		t.Fatalf("未授权修改错误 = %v，期望 ErrAccessDenied", err)
	}
	env.authz.deny = false
	after, err := env.svc.GetClient(env.ctx, env.caller(t), appConfidential)
	if err != nil || after.RowVersion != before.RowVersion ||
		after.RedirectURIs[0] != "https://app.example.com/callback" {
		t.Fatalf("未授权修改不应改变配置: %v %+v", err, after)
	}
	// 行版本过期导致冲突。
	update.ExpectedRowVersion = 99
	update.RequestID = "req-update-stale"
	if _, err := env.svc.UpdateClientSettings(env.ctx, env.caller(t), update); !errors.Is(err, oauthclient.ErrVersionConflict) {
		t.Fatalf("过期版本修改错误 = %v，期望 ErrVersionConflict", err)
	}
	if env.count(`SELECT COUNT(*) FROM audit_events WHERE action='oauth.client.denied' AND outcome='denied'`) < 2 {
		t.Error("拒绝路径缺少失败审计")
	}
	// 敏感策略调用绑定操作/目标/配置摘要。
	if env.sens.authorizeCalls < 2 || env.sens.lastRequest.OperationID == "" ||
		env.sens.lastRequest.Params["client_id"] != appConfidential {
		t.Errorf("敏感策略绑定异常: calls=%d %+v", env.sens.authorizeCalls, env.sens.lastRequest)
	}
}

// TestCertificateIdentityLifecycle 覆盖 TLS 客户端证书身份：登记、验证、错误证书、
// 撤销、最后凭证保护与非法证书拒绝。
func TestCertificateIdentityLifecycle(t *testing.T) {
	env := newTestEnv(t, nil)
	firstPEM := makeCertificate(t, env.now.Add(-time.Hour), env.now.Add(24*time.Hour), false)
	register := oauthclient.RegisterRequest{
		ClientID: appTLSCert, ClientType: oauthclient.ClientTypePublic,
		GrantTypes: []string{"authorization_code"}, RedirectURIs: []string{"com.example.app:/cb"},
		Scopes: []string{"openid"}, Audiences: []string{"https://api.example.com"},
		RequestID: "req-register",
	}
	// 公开客户端不能配置证书。
	register.ClientType = oauthclient.ClientTypePublic
	register.AuthMethods = []string{"tls_client_auth"}
	register.CertificatePEM = firstPEM
	if _, err := env.svc.RegisterClient(env.ctx, env.caller(t), register); !errors.Is(err, oauthclient.ErrInvalidConfiguration) {
		t.Fatalf("公开客户端证书错误 = %v", err)
	}
	// 保密客户端 tls_client_auth 必须带证书。
	confidential := oauthclient.RegisterRequest{
		ClientID: appTLSCert, ClientType: oauthclient.ClientTypeConfidential,
		GrantTypes: []string{"authorization_code"}, RedirectURIs: []string{"https://app.example.com/cb"},
		Scopes: []string{"openid"}, Audiences: []string{"https://api.example.com"},
		AuthMethods: []string{"tls_client_auth"}, RequestID: "req-register",
	}
	if _, err := env.svc.RegisterClient(env.ctx, env.caller(t), confidential); !errors.Is(err, oauthclient.ErrInvalidConfiguration) {
		t.Fatalf("缺少证书的 tls 客户端错误 = %v，期望 ErrInvalidConfiguration", err)
	}
	confidential.CertificatePEM = firstPEM
	result, err := env.svc.RegisterClient(env.ctx, env.caller(t), confidential)
	if err != nil {
		t.Fatalf("登记证书客户端: %v", err)
	}
	if result.Secret != nil || result.Certificate == nil || result.Certificate.FingerprintSHA256 == "" {
		t.Fatalf("证书身份结果异常: %+v", result)
	}
	identity, err := env.svc.VerifyClientCertificate(env.ctx, appTLSCert, firstPEM)
	if err != nil || identity.AuthMethod != oauthclient.AuthMethodTLSClientAuth {
		t.Fatalf("证书验证: %v %+v", err, identity)
	}
	// 另一张证书不匹配。
	wrongPEM := makeCertificate(t, env.now.Add(-time.Hour), env.now.Add(24*time.Hour), false)
	if _, err := env.svc.VerifyClientCertificate(env.ctx, appTLSCert, wrongPEM); !errors.Is(err, oauthclient.ErrClientAuthFailed) {
		t.Fatalf("错误证书 = %v，期望 ErrClientAuthFailed", err)
	}
	// 唯一证书不能撤销（避免自锁）；登记第二张后可撤销第一张。
	infos, err := env.svc.ListClientCertificates(env.ctx, env.caller(t), appTLSCert)
	if err != nil || len(infos) != 1 {
		t.Fatalf("证书列表 = %+v %v", infos, err)
	}
	if err := env.svc.RevokeClientCertificate(env.ctx, env.caller(t), oauthclient.CertificateRequest{
		ClientID: appTLSCert, CertificateID: infos[0].ID, RequestID: "req-revoke-last"}); !errors.Is(err, oauthclient.ErrLastCredential) {
		t.Fatalf("最后证书撤销错误 = %v，期望 ErrLastCredential", err)
	}
	second, err := env.svc.RegisterClientCertificate(env.ctx, env.caller(t), oauthclient.CertificateRequest{
		ClientID: appTLSCert, CertificatePEM: wrongPEM, RequestID: "req-cert2"})
	if err != nil {
		t.Fatalf("登记第二张证书: %v", err)
	}
	if err := env.svc.RevokeClientCertificate(env.ctx, env.caller(t), oauthclient.CertificateRequest{
		ClientID: appTLSCert, CertificateID: infos[0].ID, RequestID: "req-revoke1"}); err != nil {
		t.Fatalf("撤销第一张证书: %v", err)
	}
	if _, err := env.svc.VerifyClientCertificate(env.ctx, appTLSCert, firstPEM); !errors.Is(err, oauthclient.ErrClientAuthFailed) {
		t.Fatalf("撤销后旧证书 = %v，期望 ErrClientAuthFailed", err)
	}
	if _, err := env.svc.VerifyClientCertificate(env.ctx, appTLSCert, wrongPEM); err != nil {
		t.Fatalf("第二张证书应可用: %v", err)
	}
	if second.FingerprintSHA256 == "" {
		t.Error("证书指纹缺失")
	}
	// 过期证书、CA 证书与含私钥内容拒绝登记。
	expired := makeCertificate(t, env.now.Add(-48*time.Hour), env.now.Add(-time.Hour), false)
	if _, err := env.svc.RegisterClientCertificate(env.ctx, env.caller(t), oauthclient.CertificateRequest{
		ClientID: appTLSCert, CertificatePEM: expired, RequestID: "req-expired"}); !errors.Is(err, oauthclient.ErrInvalidRequest) {
		t.Fatalf("过期证书错误 = %v", err)
	}
	caPEM := makeCertificate(t, env.now.Add(-time.Hour), env.now.Add(time.Hour), true)
	if _, err := env.svc.RegisterClientCertificate(env.ctx, env.caller(t), oauthclient.CertificateRequest{
		ClientID: appTLSCert, CertificatePEM: caPEM, RequestID: "req-ca"}); !errors.Is(err, oauthclient.ErrInvalidRequest) {
		t.Fatalf("CA 证书错误 = %v", err)
	}
	privateKeyPEM := "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
	if _, err := env.svc.RegisterClientCertificate(env.ctx, env.caller(t), oauthclient.CertificateRequest{
		ClientID: appTLSCert, CertificatePEM: privateKeyPEM, RequestID: "req-private"}); !errors.Is(err, oauthclient.ErrInvalidRequest) {
		t.Fatalf("私钥内容错误 = %v", err)
	}
}

// TestInvalidClientCombinationsAndOptions 覆盖非法客户端类型组合、缺依赖构造失败
// 与不支持的授权类型。
func TestInvalidClientCombinationsAndOptions(t *testing.T) {
	env := newTestEnv(t, nil)
	// 保密客户端没有身份验证方式。
	noAuth := validConfidentialRegister(appMisMatching)
	noAuth.AuthMethods = nil
	if _, err := env.svc.RegisterClient(env.ctx, env.caller(t), noAuth); !errors.Is(err, oauthclient.ErrInvalidConfiguration) {
		t.Fatalf("保密客户端无验证方式错误 = %v", err)
	}
	// 不支持的身份验证方式。
	badMethod := validConfidentialRegister(appMisMatching)
	badMethod.AuthMethods = []string{"private_key_jwt"}
	if _, err := env.svc.RegisterClient(env.ctx, env.caller(t), badMethod); !errors.Is(err, oauthclient.ErrUnsupportedAuthMethod) {
		t.Fatalf("不支持的身份验证方式错误 = %v", err)
	}
	// refresh_token 缺授权码类型。
	badRefresh := validConfidentialRegister(appMisMatching)
	badRefresh.GrantTypes = []string{"refresh_token"}
	if _, err := env.svc.RegisterClient(env.ctx, env.caller(t), badRefresh); !errors.Is(err, oauthclient.ErrInvalidConfiguration) {
		t.Fatalf("非法 refresh 组合错误 = %v", err)
	}
	// 含片段/通配符的回调登记整体拒绝。
	badRedirect := validConfidentialRegister(appMisMatching)
	badRedirect.RedirectURIs = []string{"https://app.example.com/cb#frag"}
	if _, err := env.svc.RegisterClient(env.ctx, env.caller(t), badRedirect); !errors.Is(err, oauthclient.ErrInvalidRequest) {
		t.Fatalf("含片段回调登记错误 = %v", err)
	}
	// 无 target audience。
	noAudience := validConfidentialRegister(appMisMatching)
	noAudience.Audiences = nil
	if _, err := env.svc.RegisterClient(env.ctx, env.caller(t), noAudience); !errors.Is(err, oauthclient.ErrInvalidRequest) {
		t.Fatalf("缺少 audience 错误 = %v", err)
	}
	if _, err := oauthclient.New(oauthclient.Options{}); !errors.Is(err, oauthclient.ErrOptionsInvalid) {
		t.Fatalf("缺依赖构造错误 = %v，期望 ErrOptionsInvalid", err)
	}
}
