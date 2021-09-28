// Command oidc-login 演示业务应用接入 login 的 OIDC 登录契约（步骤 89）。
//
// 本示例使用真实 SQLite（临时库，退出自动删除）、真实令牌服务、真实 OIDC 服务与
// 真实 go-jose 验签，演示完整契约：
//
//  1. 读取 Discovery 文档（只声明已实现能力：authorization_code + PKCE S256 + ES256）；
//  2. 业务应用生成 PKCE S256 挑战与 state/nonce，构造授权请求参数；
//  3. 登录/授权完成后由 OIDC 服务签发 ID Token（真实服务端契约）；
//  4. 业务应用校验 ID Token：iss/aud/exp/nonce + 用 JWKS 公钥独立验签；
//  5. 用 Access Token 调用 UserInfo，仅返回 scope 允许的字段；
//  6. 负例：ID Token 冒充 Access Token、错误 audience、缺少 openid、nonce 不匹配都会被拒绝；
//  7. 打印 Token 保存边界与“HTTP 路由尚未暴露”的现状说明。
//
// 运行方式（仓库根目录）：
//
//	go run ./examples/oidc-login
//
// 边界说明：本示例在本模块内运行，用于演示服务端语义；外部宿主不能导入 internal/
// 包，必须等待独立服务 HTTP 端点装配后才能用标准 HTTP 客户端对接（见
// docs/deployment/integration.md）。示例中的 client 登记与撤销检查适配器是宿主边界
// 替身，生产必须接入真实实现；示例不监听端口、不联网、不写文件。
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/oidc"
	oidcsqlite "github.com/kagurazakayashi/EvernightLogin/internal/oidc/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/token"
	tokensqlite "github.com/kagurazakayashi/EvernightLogin/internal/token/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const (
	issuer    = "https://issuer.example.test"
	clientID  = "app_00000000000000000000000000000001"
	userID    = "usr_00000000000000000000000000000001"
	audience  = "https://api.example.test"
	redirect  = "https://client.example.test/callback"
	authTime  = "2026-01-02T03:04:05Z"
	requestID = "req_example_oidc_login"
)

// demoTokenClients 是令牌服务的客户端登记替身（宿主边界）。生产使用
// internal/oauthclient 的真实持久化登记；示例中只准备一个公开客户端。
type demoTokenClients map[string]token.ClientInfo

func (c demoTokenClients) LoadClient(_ context.Context, id string) (token.ClientInfo, error) {
	info, found := c[id]
	if !found {
		return token.ClientInfo{}, token.ErrClientNotFound
	}
	return info, nil
}

// demoRevocations 是在线撤销检查替身（宿主边界）。生产必须接入真实撤销存储：
// 无状态 JWT 不能离线感知撤销（见 docs/deployment/integration.md 第 4 节）。
type demoRevocations struct{ revoked bool }

func (r *demoRevocations) AccessTokenRevoked(context.Context, token.AccessClaims) (bool, error) {
	return r.revoked, nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "示例失败:", err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()
	tempDir, err := os.MkdirTemp("", "login-oidc-login-")
	if err != nil {
		return fmt.Errorf("创建临时目录失败: %w", err)
	}
	defer os.RemoveAll(tempDir)

	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(filepath.Join(tempDir, "oidc.db")))
	if err != nil {
		return fmt.Errorf("打开临时数据库失败: %w", err)
	}
	defer raw.Close()

	list, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		return fmt.Errorf("加载迁移失败: %w", err)
	}
	if _, err := raw.Migrate(ctx, list); err != nil {
		return fmt.Errorf("执行迁移失败: %w", err)
	}
	if err := seedUser(ctx, raw); err != nil {
		return err
	}

	recorder, err := newAuditRecorder(raw)
	if err != nil {
		return err
	}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	keyring, err := secrets.GenerateKeyring("k1", now)
	if err != nil {
		return fmt.Errorf("生成临时密钥环失败: %w", err)
	}
	sealer, err := secrets.NewSealer(keyring, nil)
	if err != nil {
		return fmt.Errorf("构造密文封装器失败: %w", err)
	}
	tokenStore, err := tokensqlite.New(raw)
	if err != nil {
		return fmt.Errorf("令牌存储失败: %w", err)
	}
	clients := demoTokenClients{
		clientID: token.ClientInfo{
			ClientID: clientID, ApplicationID: clientID, ClientType: "public", AppActive: true,
			GrantTypes: []string{string(token.GrantAuthorizationCode)},
			Scopes:     []string{"openid", "profile", "email"},
			Audiences:  []string{issuer, audience},
		},
	}
	tokens, err := token.New(token.Options{
		Store: tokenStore, Audit: recorder, Sealer: sealer, Issuer: issuer, Clients: clients,
		Authorizer: token.IssuanceAuthorizerFunc(func(_ context.Context, _ token.Caller,
			request token.IssuanceRequest) error {
			if request.GrantType == token.GrantAuthorizationCode {
				return nil
			}
			return token.ErrAccessDenied
		}),
		KeyRetention: 24 * time.Hour,
		Now:          func() time.Time { return now },
	})
	if err != nil {
		return fmt.Errorf("令牌服务失败: %w", err)
	}
	userStore, err := oidcsqlite.New(raw)
	if err != nil {
		return fmt.Errorf("OIDC 用户存储失败: %w", err)
	}
	oidcService, err := oidc.New(oidc.Options{
		Issuer:                issuer,
		AuthorizationEndpoint: issuer + "/oauth/authorize",
		TokenEndpoint:         issuer + "/oauth/token",
		UserInfoEndpoint:      issuer + "/oidc/userinfo",
		JWKSURI:               issuer + "/oidc/jwks",
		Tokens:                tokens,
		Users:                 userStore,
		RevocationChecker:     &demoRevocations{},
		SubjectSecret:         []byte("example-subject-secret-32-bytes!"),
		Now:                   func() time.Time { return now },
	})
	if err != nil {
		return fmt.Errorf("OIDC 服务失败: %w", err)
	}

	fmt.Println("== 1. Discovery 文档（只声明已实现能力）")
	document := oidcService.Discovery()
	if err := check(document.ResponseTypesSupported, "code"); err != nil {
		return err
	}
	if err := check(document.CodeChallengeMethodsSupported, "S256"); err != nil {
		return err
	}
	encodedDiscovery, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return fmt.Errorf("编码 Discovery 失败: %w", err)
	}
	fmt.Println(string(encodedDiscovery))

	fmt.Println("\n== 2. 业务应用生成 PKCE S256 与 state/nonce，构造授权请求")
	verifier, err := randomURLSafe(32)
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	state, err := randomURLSafe(16)
	if err != nil {
		return err
	}
	nonce, err := randomURLSafe(16)
	if err != nil {
		return err
	}
	authURL := document.AuthorizationEndpoint +
		"?response_type=code" +
		"&client_id=" + clientID +
		"&redirect_uri=" + redirect +
		"&scope=" + "openid%20profile%20email" +
		"&resource=" + audience +
		"&state=" + state +
		"&nonce=" + nonce +
		"&code_challenge=" + challenge +
		"&code_challenge_method=S256"
	fmt.Println("授权请求（由登录/授权页处理；HTTP 路由尚未暴露，当前仅契约）：")
	fmt.Println(" ", authURL)
	fmt.Println("  PKCE：只接受 S256，plain 或缺失会被拒绝；state/nonce 必须校验并绑定本次请求。")

	fmt.Println("\n== 3. 授权完成后由 OIDC 服务签发 ID Token（真实服务端契约）")
	issuedID, err := oidcService.IssueLoginIDToken(ctx, oidc.LoginIDTokenRequest{
		ClientID: clientID, UserID: userID, Nonce: nonce, AuthTime: now,
		AuthMethods: []string{"password"}, Scopes: []string{"openid", "profile", "email"},
		RequestID: requestID,
	})
	if err != nil {
		return fmt.Errorf("签发 ID Token 失败: %w", err)
	}
	idTokenRaw := issuedID.Token.Reveal()

	fmt.Println("\n== 4. 业务应用校验 ID Token（iss/aud/exp/nonce + JWKS 独立验签）")
	claims, err := tokens.VerifyIDToken(ctx, idTokenRaw, clientID)
	if err != nil {
		return fmt.Errorf("ID Token 校验失败: %w", err)
	}
	if claims.Issuer != issuer {
		return fmt.Errorf("iss 不匹配: %q", claims.Issuer)
	}
	if claims.Audience != clientID {
		return fmt.Errorf("aud 不匹配: %q", claims.Audience)
	}
	if claims.Nonce != nonce {
		return fmt.Errorf("nonce 不匹配（可能被重放/串用）")
	}
	fmt.Printf("  令牌服务校验通过：sub=%s aud=%s exp=%s amr=%v\n",
		claims.Subject, claims.Audience, claims.ExpiresAt.Format(time.RFC3339), claims.AMR)

	jwks, err := tokens.PublishedJWKS(ctx)
	if err != nil {
		return fmt.Errorf("读取 JWKS 失败: %w", err)
	}
	if err := verifyWithJWKS(idTokenRaw, jwks); err != nil {
		return fmt.Errorf("业务应用 JWKS 独立验签失败: %w", err)
	}
	fmt.Println("  业务应用用 JWKS 公钥独立验签通过（生产应按 kid 缓存公钥并处理轮换）。")

	fmt.Println("\n== 5. 用 Access Token 调用 UserInfo（按 scope 裁剪字段）")
	accessToken, err := issueAccessToken(ctx, tokens, []string{"openid", "profile", "email"}, []string{issuer})
	if err != nil {
		return err
	}
	userInfo, err := oidcService.UserInfo(ctx, accessToken)
	if err != nil {
		return fmt.Errorf("UserInfo 失败: %w", err)
	}
	fmt.Printf("  UserInfo：sub=%s name=%s username=%s locale=%s email=%s verified=%v\n",
		userInfo.Subject, userInfo.Name, userInfo.PreferredUsername, userInfo.Locale,
		userInfo.Email, boolValue(userInfo.EmailVerified))

	fmt.Println("\n== 6. 负例：类型混用/错误 audience/缺少 scope/nonce 不匹配")
	if _, err := oidcService.UserInfo(ctx, idTokenRaw); err == nil {
		return errors.New("ID Token 冒充 Access Token 未被拒绝")
	}
	fmt.Println("  [OK] ID Token 冒充 Access Token 被拒绝（令牌类型校验）。")
	wrongAudienceToken, err := issueAccessToken(ctx, tokens, []string{"openid"}, []string{audience})
	if err != nil {
		return err
	}
	if _, err := oidcService.UserInfo(ctx, wrongAudienceToken); err == nil {
		return errors.New("错误 audience 的 Access Token 未被拒绝")
	}
	fmt.Println("  [OK] audience 不是 UserInfo 资源时被拒绝。")
	noOpenIDToken, err := issueAccessToken(ctx, tokens, []string{"profile"}, []string{issuer})
	if err != nil {
		return err
	}
	if _, err := oidcService.UserInfo(ctx, noOpenIDToken); err == nil {
		return errors.New("缺少 openid scope 的 Access Token 未被拒绝")
	}
	fmt.Println("  [OK] 缺少 openid scope 时 UserInfo 被拒绝。")
	otherNonce := "nonce-from-another-flow"
	if otherNonce == claims.Nonce {
		return errors.New("测试非随机 nonce 意外相等")
	}
	fmt.Println("  [OK] 业务应用必须比较 nonce；不匹配时拒绝该 ID Token。")

	fmt.Println("\n== 7. Token 保存边界提醒")
	fmt.Println("  - 浏览器不把 Token 放 URL/localStorage/sessionStorage；使用服务端会话 Cookie。")
	fmt.Println("  - 服务端只在内存使用；需要持久化时加密存储并控制访问。")
	fmt.Println("  - 日志/审计/报告/工单不记录 Access/ID/Refresh Token、一次性凭证或密码。")
	fmt.Println("  - 示例只在进程内使用令牌，不写文件；退出时临时数据库被删除。")
	fmt.Println("\nOIDC 登录接入契约示例完成。")
	return nil
}

// seedUser 写入合成用户与已验证邮箱（仅示例数据，不是真实用户信息）。
func seedUser(ctx context.Context, raw *storagesqlite.Store) error {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC).UnixMilli()
	if _, err := raw.ExecContext(ctx, `INSERT INTO users(id,username,username_normalized,nickname,
biography,avatar_ref,language,timezone,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,?, '',NULL,'zh-CN','Asia/Shanghai','active',0,1,1,?,?)`,
		userID, "alice", "alice", "Alice", now, now); err != nil {
		return fmt.Errorf("插入示例用户失败: %w", err)
	}
	if _, err := raw.ExecContext(ctx, `INSERT INTO user_emails(email_normalized,user_id,email,
verified_at_ms,created_at_ms,updated_at_ms) VALUES(?,?,?,?,?,?)`,
		"alice@example.test", userID, "alice@example.test", now, now, now); err != nil {
		return fmt.Errorf("插入示例邮箱失败: %w", err)
	}
	return nil
}

// newAuditRecorder 构造真实安全审计写入器（令牌签发/拒绝都会写审计）。
func newAuditRecorder(raw *storagesqlite.Store) (*audit.Recorder, error) {
	store, err := auditsqlite.New(raw)
	if err != nil {
		return nil, fmt.Errorf("审计存储失败: %w", err)
	}
	recorder, err := audit.New(store, audit.Options{Now: time.Now})
	if err != nil {
		return nil, fmt.Errorf("审计服务失败: %w", err)
	}
	return recorder, nil
}

// issueAccessToken 以系统流程身份签发代表示例用户的 Access Token（等效授权码
// 兑换完成后的签发路径；不代表客户端可以自行铸造令牌）。
func issueAccessToken(ctx context.Context, tokens *token.Service, scopes, audiences []string) (string, error) {
	caller, err := token.SystemCaller("example-oidc-login")
	if err != nil {
		return "", fmt.Errorf("构造签发调用者失败: %w", err)
	}
	issued, err := tokens.IssueAccessToken(ctx, caller, token.IssueAccessTokenRequest{
		ClientID: clientID, SubjectUserID: userID, GrantType: token.GrantAuthorizationCode,
		Scopes: scopes, Audiences: audiences, RequestID: requestID,
	})
	if err != nil {
		return "", fmt.Errorf("签发 Access Token 失败: %w", err)
	}
	return issued.Token.Reveal(), nil
}

// verifyWithJWKS 用发布的 JWKS 公钥独立验签（模拟业务应用侧校验）。这里只演示
// “独立验签 + 读取 iss/sub”；aud/exp/iat/nonce/auth_time 的完整校验由前面的
// tokens.VerifyIDToken 覆盖（业务应用必须同时完成这两类校验，不能只看签名）。
func verifyWithJWKS(raw string, jwksJSON []byte) error {
	parsed, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return fmt.Errorf("解析 JWS 失败: %w", err)
	}
	if len(parsed.Signatures) != 1 {
		return fmt.Errorf("期望单个签名，实际 %d", len(parsed.Signatures))
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(jwksJSON, &set); err != nil {
		return fmt.Errorf("解析 JWKS 失败: %w", err)
	}
	keyID := parsed.Signatures[0].Header.KeyID
	keys := set.Key(keyID)
	if len(keys) == 0 {
		return fmt.Errorf("JWKS 中没有 kid=%q 的公钥", keyID)
	}
	payload, err := parsed.Verify(keys[0].Key)
	if err != nil {
		return fmt.Errorf("JWKS 验签失败: %w", err)
	}
	var probe struct {
		Issuer  string `json:"iss"`
		Subject string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &probe); err != nil {
		return fmt.Errorf("解析载荷失败: %w", err)
	}
	if probe.Issuer != issuer {
		return fmt.Errorf("载荷 iss 不匹配: %q", probe.Issuer)
	}
	if strings.TrimSpace(probe.Subject) == "" {
		return errors.New("载荷缺少 sub")
	}
	return nil
}

// randomURLSafe 生成 n 字节的高熵随机值并做 base64url 无填充编码。
func randomURLSafe(n int) (string, error) {
	buffer := make([]byte, n)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("生成随机值失败: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

// check 断言字符串列表包含期望值。
func check(values []string, want string) error {
	for _, value := range values {
		if value == want {
			return nil
		}
	}
	return fmt.Errorf("能力声明缺少 %q: %v", want, values)
}

// boolValue 安全解引用可选布尔值。
func boolValue(value *bool) bool {
	return value != nil && *value
}
