// Command oidc-login 是步骤 191 的可运行外部客户端示例：用授权码 + PKCE(S256)
// 走真实 HTTP 协议流程取得 Token 并调用 OIDC UserInfo。
//
// 示例分两段：
//
//  1. 服务端夹具：在本模块内用临时 SQLite、真实领域服务与 internal/protocolapi
//     处理器启动一个只监听 127.0.0.1 随机端口的真实 HTTP 服务（退出即关闭并删除
//     临时库）。它代替“已经部署好的 login-server”，因为示例不应占用固定端口。
//  2. 外部客户端：只用标准库 net/http + go-jose 做 Discovery、授权码 + PKCE、
//     令牌兑换、JWKS 独立验签与 UserInfo 调用；业务应用照这一段接入即可，不需要
//     import 本模块 internal/ 包。
//
// 覆盖的验收判据（全部通过真实协议流程，未直接构造令牌冒充正向证据）：
//
//	UserInfo 成功；UserInfo 的 sub 与 ID Token 的 sub 一致；scope 字段裁剪
//	（openid-only 只返回 sub）；错误 audience（资源服务器 audience）被拒绝；
//	ID Token 冒充 Access Token 被拒绝；授权码重放被拒绝；
//	错误签发方与撤销后的令牌在 internal/protocolapi 的验收测试中覆盖
//	（外部示例无法安全地伪造另一签发方的真实签名，故作说明而不伪造）。
//
// 运行方式（仓库根目录，Windows/Linux/macOS 均可）：
//
//	go run ./examples/oidc-login
//
// 安全边界：临时数据库/密钥只用于本进程；不联网、不写仓库、不打印令牌原文；
// 程序退出时关闭回环 HTTP 服务并删除临时目录。示例中的“已登录用户”由真实会话
// 服务在进程内签发（生产环境由登录页完成），宿主边界适配器（授权判定/近期认证）
// 是演示替身，生产必须接入真实实现。
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"

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

// 示例固定数据（合成用户/应用，不是真实账户）。
const (
	demoUserID         = "usr_00000000000000000000000000000001"
	demoClientID       = "app_00000000000000000000000000000001"
	demoRedirectURI    = "https://client.example.test/callback"
	resourceAudience   = "https://api.example.test"
	subjectSecretText  = "example-oidc-login-subject-secret-32b"
	demoRequestTimeout = 20 * time.Second
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "示例失败:", err)
		os.Exit(1)
	}
}

// serviceFixture 是示例内置的真实 OIDC 服务端夹具。
type serviceFixture struct {
	issuer   string
	sessions *session.Service
	cookie   *http.Cookie
	server   *http.Server
	listener net.Listener
	db       *storagesqlite.Store
	tempDir  string
}

// Close 停止回环 HTTP 服务、关闭临时数据库并删除临时目录。
func (f *serviceFixture) Close() {
	if f == nil {
		return
	}
	if f.server != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = f.server.Shutdown(shutdownCtx)
		cancel()
	}
	if f.listener != nil {
		_ = f.listener.Close()
	}
	if f.db != nil {
		_ = f.db.Close()
	}
	if f.tempDir != "" {
		_ = os.RemoveAll(f.tempDir)
	}
}

// allowAuthorizer 是客户端管理授权测试替身（聚焦协议演示，生产接真实授权）。
type allowAuthorizer struct{}

// AuthorizeClient 实现 oauthclient.Authorizer。
func (allowAuthorizer) AuthorizeClient(context.Context, oauthclient.Caller, string, oauthclient.Action) error {
	return nil
}

// allowSensitive 是敏感操作策略测试替身（生产由 reauth.Service 判定近期强认证）。
type allowSensitive struct{}

// Authorize 实现 reauth.OperationRunner：回填真实操作标识，不伪造授权来源。
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

// revocationLinker 解决 oidc 与 oauthflow 的构造循环：先注入链接器，两个服务
// 构造完成后回填真实在线撤销检查实现。
type revocationLinker struct{ flow *oauthflow.Service }

// AccessTokenRevoked 实现 oidc.RevocationChecker。
func (l *revocationLinker) AccessTokenRevoked(ctx context.Context,
	claims token.AccessClaims) (bool, error) {
	if l.flow == nil {
		return false, errors.New("撤销检查尚未接线")
	}
	return l.flow.AccessTokenRevoked(ctx, claims)
}

// startFixture 装配真实服务并启动回环 HTTP 端点。
func startFixture(ctx context.Context) (*serviceFixture, error) {
	fixture := &serviceFixture{}
	fail := func(err error) (*serviceFixture, error) {
		fixture.Close()
		return nil, err
	}

	tempDir, err := os.MkdirTemp("", "login-oidc-login-")
	if err != nil {
		return nil, fmt.Errorf("创建临时目录失败: %w", err)
	}
	fixture.tempDir = tempDir
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(
		filepath.Join(tempDir, "oidc-example.db")))
	if err != nil {
		return fail(fmt.Errorf("打开临时数据库失败: %w", err))
	}
	fixture.db = raw
	migrationSet, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		return fail(fmt.Errorf("加载迁移失败: %w", err))
	}
	if _, err := raw.Migrate(ctx, migrationSet); err != nil {
		return fail(fmt.Errorf("执行迁移失败: %w", err))
	}

	// 先监听回环随机端口，再按实际端口生成 issuer（issuer 必须与端点同源）。
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fail(fmt.Errorf("监听回环端口失败: %w", err))
	}
	fixture.listener = listener
	issuer := "http://" + listener.Addr().String()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	now := time.Now
	if err := seedDemoIdentity(ctx, raw, now); err != nil {
		return fail(err)
	}
	auditStore, err := auditsqlite.New(raw)
	if err != nil {
		return fail(fmt.Errorf("审计存储失败: %w", err))
	}
	recorder, err := audit.New(auditStore, audit.Options{Logger: logger, Now: now})
	if err != nil {
		return fail(fmt.Errorf("审计服务失败: %w", err))
	}
	sessionKeyring, err := secrets.GenerateKeyring("session-k1", now())
	if err != nil {
		return fail(fmt.Errorf("会话密钥环失败: %w", err))
	}
	tokenKeyring, err := secrets.GenerateKeyring("token-k1", now())
	if err != nil {
		return fail(fmt.Errorf("令牌密钥环失败: %w", err))
	}
	sealer, err := secrets.NewSealer(tokenKeyring, nil)
	if err != nil {
		return fail(fmt.Errorf("密文封装器失败: %w", err))
	}

	sessionStore, err := sessionsqlite.New(raw)
	if err != nil {
		return fail(fmt.Errorf("会话存储失败: %w", err))
	}
	sessions, err := session.New(sessionStore, session.Options{
		Store: sessionStore, Audit: recorder, Keyring: sessionKeyring,
		IdleTimeout: 30 * time.Minute, AbsoluteTimeout: 12 * time.Hour,
		AllowLegacyWithoutSensitive: true, Logger: logger, Now: now,
	})
	if err != nil {
		return fail(fmt.Errorf("会话服务失败: %w", err))
	}
	fixture.sessions = sessions

	clientStore, err := oauthclientsqlite.New(raw)
	if err != nil {
		return fail(fmt.Errorf("OAuth 客户端存储失败: %w", err))
	}
	clientAuth, err := oauthclient.New(oauthclient.Options{
		Store: clientStore, Audit: recorder, Authorizer: allowAuthorizer{},
		Sensitive: allowSensitive{}, Now: now, Logger: logger,
	})
	if err != nil {
		return fail(fmt.Errorf("OAuth 客户端服务失败: %w", err))
	}
	if err := registerDemoClient(ctx, clientAuth, issuer); err != nil {
		return fail(err)
	}

	tokenStore, err := tokensqlite.New(raw)
	if err != nil {
		return fail(fmt.Errorf("令牌存储失败: %w", err))
	}
	tokenClients, err := token.NewOAuthClientSource(clientStore)
	if err != nil {
		return fail(fmt.Errorf("令牌客户端来源失败: %w", err))
	}
	tokens, err := token.New(token.Options{
		Store: tokenStore, Audit: recorder, Sealer: sealer, Issuer: issuer,
		Clients: tokenClients,
		Authorizer: token.IssuanceAuthorizerFunc(func(_ context.Context, _ token.Caller,
			request token.IssuanceRequest) error {
			if request.TokenKind == token.TokenUseAccess &&
				request.GrantType == token.GrantAuthorizationCode {
				return nil
			}
			if request.TokenKind == token.TokenUseID &&
				request.GrantType == token.GrantAuthorizationCode {
				return nil
			}
			return token.ErrAccessDenied
		}),
		KeyRetention: 24 * time.Hour, Now: now, Logger: logger,
	})
	if err != nil {
		return fail(fmt.Errorf("令牌服务失败: %w", err))
	}
	oidcStore, err := oidcsqlite.New(raw)
	if err != nil {
		return fail(fmt.Errorf("OIDC 用户存储失败: %w", err))
	}
	linker := &revocationLinker{}
	oidcService, err := oidc.New(oidc.Options{
		Issuer:                issuer,
		AuthorizationEndpoint: issuer + protocolapi.PathAuthorize,
		TokenEndpoint:         issuer + protocolapi.PathToken,
		UserInfoEndpoint:      issuer + protocolapi.PathUserInfo,
		JWKSURI:               issuer + protocolapi.PathJWKS,
		Tokens:                tokens, Users: oidcStore, RevocationChecker: linker,
		SubjectSecret: []byte(subjectSecretText), Now: now,
	})
	if err != nil {
		return fail(fmt.Errorf("OIDC 服务失败: %w", err))
	}
	flowStore, err := oauthflowsqlite.New(raw)
	if err != nil {
		return fail(fmt.Errorf("授权流程存储失败: %w", err))
	}
	flowClients, err := oauthflow.NewOAuthClientSource(clientStore)
	if err != nil {
		return fail(fmt.Errorf("授权客户端来源失败: %w", err))
	}
	flow, err := oauthflow.New(oauthflow.Options{
		Store: flowStore, Audit: recorder, Clients: flowClients,
		ClientAuth: clientAuth, Sessions: sessions, SessionRevoker: sessions,
		Tokens: tokens, Reauth: allowSensitive{}, OIDC: oidcService, TokenVerifier: tokens,
		Now: now, Logger: logger,
	})
	if err != nil {
		return fail(fmt.Errorf("授权流程服务失败: %w", err))
	}
	linker.flow = flow

	server, err := protocolapi.New(protocolapi.Options{
		OAuth: flow, OIDC: oidcService, Tokens: tokens, Sessions: sessions,
		ClientAuth: clientAuth, Logger: logger, Now: now,
	})
	if err != nil {
		return fail(fmt.Errorf("构造协议端点失败: %w", err))
	}
	fixture.issuer = issuer
	fixture.server = &http.Server{Handler: server.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if serveErr := fixture.server.Serve(listener); serveErr != nil &&
			!errors.Is(serveErr, http.ErrServerClosed) {
			fmt.Fprintln(os.Stderr, "回环 HTTP 服务意外退出:", serveErr)
		}
	}()

	// 示例模拟“用户已通过登录页登录”：用真实会话服务签发普通会话并取 Cookie。
	issued, err := sessions.Login(ctx, session.LoginRequest{
		Result: authn.AuthenticateResult{
			UserID: demoUserID, Username: "alice", Outcome: authn.OutcomeComplete,
			CompletedMethods: []authn.Method{authn.MethodPassword},
			CompletedAt:      now(), SecurityVersion: 1,
		},
		RequestID: "req_example_login",
	})
	if err != nil {
		return fail(fmt.Errorf("签发示例会话失败: %w", err))
	}
	cookie, err := sessions.NewCookie(issued)
	if err != nil {
		return fail(fmt.Errorf("构造示例会话 Cookie 失败: %w", err))
	}
	fixture.cookie = cookie
	return fixture, nil
}

// seedDemoIdentity 写入合成用户、应用、成员关系与应用 scope。
func seedDemoIdentity(ctx context.Context, raw *storagesqlite.Store, now func() time.Time) error {
	nowMS := now().UnixMilli()
	exec := func(query string, args ...any) error {
		if _, err := raw.ExecContext(ctx, query, args...); err != nil {
			return fmt.Errorf("插入示例数据失败: %w", err)
		}
		return nil
	}
	if err := exec(`INSERT INTO users(id,username,username_normalized,nickname,biography,
avatar_ref,language,timezone,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,'alice','Alice','',NULL,'zh-CN','Asia/Shanghai','active',0,1,1,?,?)`,
		demoUserID, "alice", nowMS, nowMS); err != nil {
		return err
	}
	if err := exec(`INSERT INTO user_emails(email_normalized,user_id,email,verified_at_ms,
created_at_ms,updated_at_ms) VALUES(?,?,?,?,?,?)`,
		"alice@example.test", demoUserID, "alice@example.test", nowMS, nowMS, nowMS); err != nil {
		return err
	}
	if err := exec(`INSERT INTO applications(id,name,description,status,client_type,row_version,
created_at_ms,updated_at_ms) VALUES(?,?,'','active','public',1,?,?)`,
		demoClientID, "示例 OIDC 客户端", nowMS, nowMS); err != nil {
		return err
	}
	if err := exec(`INSERT INTO scopes(id,kind,app_id) VALUES(?,'application',?)`,
		demoClientID, demoClientID); err != nil {
		return err
	}
	return exec(`INSERT INTO app_memberships(app_id,user_id,status,profile_json,row_version,
created_at_ms,updated_at_ms) VALUES(?,?,'active','{"v":1}',1,?,?)`,
		demoClientID, demoUserID, nowMS, nowMS)
}

// registerDemoClient 用真实客户端服务登记公开授权码客户端。issuer 必须登记为
// 允许 audience：UserInfo 把 issuer 当作自己的资源受众，缺它就无法取得可用于
// UserInfo 的 Access Token（这是步骤 160 发现失败的真实原因，不是校验缺陷）。
func registerDemoClient(ctx context.Context, clientAuth *oauthclient.Service, issuer string) error {
	caller, err := oauthclient.SystemCaller("oidc-login-example")
	if err != nil {
		return fmt.Errorf("构造客户端管理调用者失败: %w", err)
	}
	requirePKCE := true
	if _, err := clientAuth.RegisterClient(ctx, caller, oauthclient.RegisterRequest{
		ClientID: demoClientID, ClientType: oauthclient.ClientTypePublic,
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		RedirectURIs: []string{demoRedirectURI},
		Scopes:       []string{"openid", "profile", "email", "offline_access"},
		Audiences:    []string{issuer, resourceAudience},
		RequirePKCE:  &requirePKCE,
		RequestID:    "req_example_register_client",
	}); err != nil {
		return fmt.Errorf("登记示例客户端失败: %w", err)
	}
	return nil
}

// externalClient 是“外部业务应用”的客户端：只使用标准 HTTP + go-jose。
type externalClient struct {
	issuer      string
	clientID    string
	redirectURI string
	cookie      *http.Cookie
	http        *http.Client
}

// newExternalClient 构造外部客户端；不自动跟随重定向（需检查 303 回调参数）。
func newExternalClient(fixture *serviceFixture) *externalClient {
	return &externalClient{
		issuer: fixture.issuer, clientID: demoClientID, redirectURI: demoRedirectURI,
		cookie: fixture.cookie,
		http: &http.Client{
			Timeout: demoRequestTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// discovery 读取 OIDC Discovery 文档，只信任服务端声明。
func (c *externalClient) discovery(ctx context.Context) (map[string]any, error) {
	response, body, err := c.get(ctx, "/.well-known/openid-configuration", false)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Discovery 状态 = %d", response.StatusCode)
	}
	var document map[string]any
	if err := json.Unmarshal(body, &document); err != nil {
		return nil, fmt.Errorf("Discovery 不是合法 JSON: %w", err)
	}
	if document["issuer"] != c.issuer {
		return nil, fmt.Errorf("Discovery issuer = %v，期望 %q", document["issuer"], c.issuer)
	}
	return document, nil
}

// get 发送 GET 请求；withSession 为 true 时带已登录会话 Cookie。
func (c *externalClient) get(ctx context.Context, target string, withSession bool) (
	*http.Response, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.issuer+target, nil)
	if err != nil {
		return nil, nil, err
	}
	return c.do(request, withSession)
}

// postForm 发送表单 POST 请求；withSession 为 true 时带会话 Cookie 与同源 Origin。
func (c *externalClient) postForm(ctx context.Context, target string,
	form url.Values, withSession bool) (*http.Response, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.issuer+target,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, nil, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if withSession {
		request.Header.Set("Origin", c.issuer)
	}
	return c.do(request, withSession)
}

// do 执行请求并读取有界响应。
func (c *externalClient) do(request *http.Request, withSession bool) (
	*http.Response, []byte, error) {
	if withSession && c.cookie != nil {
		request.AddCookie(c.cookie)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, nil, fmt.Errorf("HTTP 请求失败: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, nil, fmt.Errorf("读取响应失败: %w", err)
	}
	return response, body, nil
}

// pkcePair 返回 PKCE S256 的 verifier 与 challenge。
func pkcePair() (verifier, challenge string, err error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(buffer)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// randomToken 生成 state/nonce 这类不可预测值。
func randomToken(n int) (string, error) {
	buffer := make([]byte, n)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

var (
	requestIDPattern = regexp.MustCompile(`name="request_id" value="([^"]+)"`)
	csrfTokenPattern = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)
)

// authorize 走一次完整授权码流程（同意页 → 批准 → 回调授权码），返回授权码与
// 本次 state/nonce/verifier。resource 为空时省略 resource 参数。
func (c *externalClient) authorize(ctx context.Context, endpoints map[string]any,
	scope, resource, state, nonce, challenge string) (code string, err error) {
	authorizationEndpoint, _ := endpoints["authorization_endpoint"].(string)
	if authorizationEndpoint == "" {
		return "", errors.New("Discovery 缺少 authorization_endpoint")
	}
	query := url.Values{
		"client_id": {c.clientID}, "redirect_uri": {c.redirectURI},
		"response_type": {"code"}, "scope": {scope}, "state": {state}, "nonce": {nonce},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	if resource != "" {
		query.Set("resource", resource)
	}
	consentURL := authorizationEndpoint + "?" + query.Encode()
	response, body, err := c.get(ctx, strings.TrimPrefix(consentURL, c.issuer), true)
	if err != nil {
		return "", err
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("同意页状态 = %d（需要有效登录会话）", response.StatusCode)
	}
	if strings.Contains(string(body), "access_token") || strings.Contains(string(body), "id_token") {
		return "", errors.New("同意页不应包含任何令牌")
	}
	requestID := firstGroup(requestIDPattern, body)
	csrfToken := firstGroup(csrfTokenPattern, body)
	if requestID == "" || csrfToken == "" {
		return "", errors.New("同意页缺少 request_id/csrf_token 隐藏字段")
	}
	approved, _, err := c.postForm(ctx, protocolapi.PathAuthorize, url.Values{
		"request_id": {requestID}, "csrf_token": {csrfToken}, "decision": {"approve"},
	}, true)
	if err != nil {
		return "", err
	}
	if approved.StatusCode != http.StatusSeeOther {
		return "", fmt.Errorf("批准后状态 = %d，期望 303", approved.StatusCode)
	}
	location := approved.Header.Get("Location")
	if !strings.HasPrefix(location, c.redirectURI) {
		return "", errors.New("服务端重定向到未登记回调")
	}
	parsed, err := url.Parse(location)
	if err != nil {
		return "", fmt.Errorf("回调地址无法解析: %w", err)
	}
	callback := parsed.Query()
	if protocolError := callback.Get("error"); protocolError != "" {
		return "", fmt.Errorf("授权被拒绝: %s", protocolError)
	}
	if returnedState := callback.Get("state"); returnedState != state {
		return "", errors.New("回调 state 与请求不一致")
	}
	code = callback.Get("code")
	if code == "" {
		return "", errors.New("回调缺少授权码")
	}
	return code, nil
}

// tokenResponse 是令牌端点成功响应投影（令牌只在内存使用，不打印）。
type tokenResponse struct {
	AccessToken  string
	IDToken      string
	RefreshToken string
	TokenType    string
	ExpiresIn    int64
}

// exchangeCode 用授权码 + PKCE verifier 兑换令牌。
func (c *externalClient) exchangeCode(ctx context.Context, endpoints map[string]any,
	code, verifier string) (*tokenResponse, error) {
	tokenEndpoint, _ := endpoints["token_endpoint"].(string)
	if tokenEndpoint == "" {
		return nil, errors.New("Discovery 缺少 token_endpoint")
	}
	response, body, err := c.postForm(ctx, strings.TrimPrefix(tokenEndpoint, c.issuer),
		url.Values{
			"grant_type": {"authorization_code"}, "code": {code},
			"redirect_uri": {c.redirectURI}, "client_id": {c.clientID},
			"code_verifier": {verifier},
		}, false)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("令牌端点状态 = %d: %s", response.StatusCode,
			oauthErrorOf(body))
	}
	var payload struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("令牌响应不是合法 JSON: %w", err)
	}
	if payload.AccessToken == "" || payload.IDToken == "" {
		return nil, errors.New("令牌响应缺少 access_token/id_token")
	}
	return &tokenResponse{AccessToken: payload.AccessToken, IDToken: payload.IDToken,
		RefreshToken: payload.RefreshToken, TokenType: payload.TokenType,
		ExpiresIn: payload.ExpiresIn}, nil
}

// fetchJWKS 拉取签名公钥集合（外部客户端自行验签，不信任令牌自述密钥地址）。
func (c *externalClient) fetchJWKS(ctx context.Context, endpoints map[string]any) ([]byte, error) {
	jwksURI, _ := endpoints["jwks_uri"].(string)
	if jwksURI == "" {
		return nil, errors.New("Discovery 缺少 jwks_uri")
	}
	response, body, err := c.get(ctx, strings.TrimPrefix(jwksURI, c.issuer), false)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS 状态 = %d", response.StatusCode)
	}
	return body, nil
}

// verifyIDToken 用 JWKS 公钥独立验证 ID Token 的签名与 iss/aud/nonce/exp，
// 返回 sub 供与 UserInfo 比对。
func (c *externalClient) verifyIDToken(jwksJSON []byte, raw, nonce string) (string, error) {
	parsed, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return "", fmt.Errorf("解析 ID Token 失败: %w", err)
	}
	if len(parsed.Signatures) != 1 {
		return "", errors.New("ID Token 必须只有一个签名")
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(jwksJSON, &set); err != nil {
		return "", fmt.Errorf("解析 JWKS 失败: %w", err)
	}
	keys := set.Key(parsed.Signatures[0].Header.KeyID)
	if len(keys) == 0 {
		return "", errors.New("JWKS 中没有 ID Token 的 kid 公钥")
	}
	payload, err := parsed.Verify(keys[0].Key)
	if err != nil {
		return "", fmt.Errorf("ID Token 验签失败: %w", err)
	}
	var claims struct {
		Issuer   string  `json:"iss"`
		Subject  string  `json:"sub"`
		Audience string  `json:"aud"`
		Nonce    string  `json:"nonce"`
		Expires  float64 `json:"exp"`
		IssuedAt float64 `json:"iat"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("解析 ID Token 载荷失败: %w", err)
	}
	if claims.Issuer != c.issuer {
		return "", fmt.Errorf("ID Token iss = %q", claims.Issuer)
	}
	if claims.Audience != c.clientID {
		return "", fmt.Errorf("ID Token aud = %q，期望客户端自己", claims.Audience)
	}
	if claims.Nonce != nonce {
		return "", errors.New("ID Token nonce 不匹配（重放/串用）")
	}
	if claims.Expires <= float64(time.Now().Add(-time.Minute).Unix()) {
		return "", errors.New("ID Token 已过期")
	}
	if claims.Subject == "" {
		return "", errors.New("ID Token 缺少 sub")
	}
	return claims.Subject, nil
}

// userInfo 用 Bearer 访问令牌调用 UserInfo，返回状态码与 JSON 正文。
func (c *externalClient) userInfo(ctx context.Context, endpoints map[string]any,
	accessToken string) (int, map[string]any, error) {
	userInfoEndpoint, _ := endpoints["userinfo_endpoint"].(string)
	if userInfoEndpoint == "" {
		return 0, nil, errors.New("Discovery 缺少 userinfo_endpoint")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.issuer+strings.TrimPrefix(userInfoEndpoint, c.issuer), nil)
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	response, body, err := c.do(request, false)
	if err != nil {
		return 0, nil, err
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		return response.StatusCode, nil, fmt.Errorf("UserInfo 响应不是合法 JSON: %w", err)
	}
	return response.StatusCode, decoded, nil
}

// oauthErrorOf 从错误响应里取稳定 error 值用于诊断（不输出令牌/秘密）。
func oauthErrorOf(body []byte) string {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return "非 JSON 错误响应"
	}
	if code, _ := payload["error"].(string); code != "" {
		return code
	}
	return "未知错误"
}

// firstGroup 返回正则第一个捕获组。
func firstGroup(pattern *regexp.Regexp, body []byte) string {
	match := pattern.FindSubmatch(body)
	if len(match) < 2 {
		return ""
	}
	return string(match[1])
}

// run 启动真实服务，然后以外部客户端身份完成 OIDC UserInfo 正向与拒绝验收。
func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	fixture, err := startFixture(ctx)
	if err != nil {
		return err
	}
	defer fixture.Close()
	client := newExternalClient(fixture)

	fmt.Println("== 1. 启动真实 OIDC 服务（临时 SQLite + 回环 HTTP 端口）")
	fmt.Println("  issuer:", fixture.issuer)
	endpoints, err := client.discovery(ctx)
	if err != nil {
		return fmt.Errorf("Discovery 失败: %w", err)
	}
	fmt.Printf("  discovery: token_endpoint=%v userinfo_endpoint=%v jwks_uri=%v\n",
		endpoints["token_endpoint"], endpoints["userinfo_endpoint"], endpoints["jwks_uri"])

	fmt.Println("\n== 2. 授权码 + PKCE(S256)：同意页 → 批准 → 回调授权码")
	verifier, challenge, err := pkcePair()
	if err != nil {
		return fmt.Errorf("生成 PKCE 失败: %w", err)
	}
	state, err := randomToken(16)
	if err != nil {
		return err
	}
	nonce, err := randomToken(16)
	if err != nil {
		return err
	}
	// UserInfo 的受众是 issuer：客户端必须把 issuer 登记为允许 audience，并在
	// 授权请求里显式 resource=<issuer>（多 audience 客户端不允许隐式选择）。
	code, err := client.authorize(ctx, endpoints, "openid profile email",
		fixture.issuer, state, nonce, challenge)
	if err != nil {
		return fmt.Errorf("授权码流程失败: %w", err)
	}
	fmt.Println("  [OK] 授权码已取得（PKCE S256、state 已校验）")

	fmt.Println("\n== 3. 令牌端点：code + verifier 兑换 Access/ID Token")
	tokens, err := client.exchangeCode(ctx, endpoints, code, verifier)
	if err != nil {
		return fmt.Errorf("兑换令牌失败: %w", err)
	}
	fmt.Printf("  [OK] token_type=%s expires_in=%d（令牌原文不打印）\n",
		tokens.TokenType, tokens.ExpiresIn)

	fmt.Println("\n== 4. 拉取 JWKS 并独立验证 ID Token")
	jwksJSON, err := client.fetchJWKS(ctx, endpoints)
	if err != nil {
		return fmt.Errorf("拉取 JWKS 失败: %w", err)
	}
	idTokenSubject, err := client.verifyIDToken(jwksJSON, tokens.IDToken, nonce)
	if err != nil {
		return fmt.Errorf("ID Token 校验失败: %w", err)
	}
	fmt.Println("  [OK] ID Token 签名/iss/aud/nonce/exp 校验通过")

	fmt.Println("\n== 5. 用 Access Token 调用 UserInfo（sub 必须与 ID Token 一致）")
	status, info, err := client.userInfo(ctx, endpoints, tokens.AccessToken)
	if err != nil {
		return fmt.Errorf("UserInfo 调用失败: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("UserInfo 状态 = %d: %v", status, info)
	}
	userInfoSubject, _ := info["sub"].(string)
	if userInfoSubject == "" || userInfoSubject != idTokenSubject {
		return fmt.Errorf("UserInfo sub(%q) 与 ID Token sub(%q) 不一致",
			userInfoSubject, idTokenSubject)
	}
	if info["name"] != "Alice" || info["preferred_username"] != "alice" ||
		info["email"] != "alice@example.test" || info["email_verified"] != true {
		return fmt.Errorf("UserInfo 字段异常: %v", info)
	}
	fmt.Printf("  [OK] UserInfo: sub=%s name=%v email=%v email_verified=%v\n",
		userInfoSubject, info["name"], info["email"], info["email_verified"])

	fmt.Println("\n== 6. scope 字段裁剪：只申请 openid 时只返回 sub")
	trimVerifier, trimChallenge, err := pkcePair()
	if err != nil {
		return err
	}
	trimState, err := randomToken(16)
	if err != nil {
		return err
	}
	trimNonce, err := randomToken(16)
	if err != nil {
		return err
	}
	trimCode, err := client.authorize(ctx, endpoints, "openid", fixture.issuer,
		trimState, trimNonce, trimChallenge)
	if err != nil {
		return fmt.Errorf("openid-only 授权失败: %w", err)
	}
	trimTokens, err := client.exchangeCode(ctx, endpoints, trimCode, trimVerifier)
	if err != nil {
		return fmt.Errorf("openid-only 兑换失败: %w", err)
	}
	status, trimInfo, err := client.userInfo(ctx, endpoints, trimTokens.AccessToken)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("openid-only UserInfo 状态 = %d: %v", status, trimInfo)
	}
	if _, exists := trimInfo["name"]; exists {
		return fmt.Errorf("缺少 profile scope 却返回 name: %v", trimInfo)
	}
	if _, exists := trimInfo["email"]; exists {
		return fmt.Errorf("缺少 email scope 却返回 email: %v", trimInfo)
	}
	if trimSubject, _ := trimInfo["sub"].(string); trimSubject != idTokenSubject {
		return fmt.Errorf("openid-only sub 与 ID Token 不一致: %v", trimInfo["sub"])
	}
	fmt.Println("  [OK] 只返回 sub，profile/email 字段已裁剪")

	fmt.Println("\n== 7. 拒绝路径：错误 audience / ID Token 误用 / 授权码重放")
	resourceVerifier, resourceChallenge, err := pkcePair()
	if err != nil {
		return err
	}
	resourceState, err := randomToken(16)
	if err != nil {
		return err
	}
	resourceNonce, err := randomToken(16)
	if err != nil {
		return err
	}
	// 资源服务器 audience 的令牌可以访问业务 API，但不能访问 UserInfo。
	resourceCode, err := client.authorize(ctx, endpoints, "openid profile",
		resourceAudience, resourceState, resourceNonce, resourceChallenge)
	if err != nil {
		return fmt.Errorf("资源 audience 授权失败: %w", err)
	}
	resourceTokens, err := client.exchangeCode(ctx, endpoints, resourceCode, resourceVerifier)
	if err != nil {
		return fmt.Errorf("资源 audience 兑换失败: %w", err)
	}
	status, wrongAudienceInfo, err := client.userInfo(ctx, endpoints, resourceTokens.AccessToken)
	if err != nil {
		return err
	}
	if status != http.StatusUnauthorized || wrongAudienceInfo["error"] != "invalid_token" {
		return fmt.Errorf("错误 audience 未被拒绝: %d %v", status, wrongAudienceInfo)
	}
	fmt.Println("  [OK] 资源服务器 audience 令牌访问 UserInfo 被 401 invalid_token 拒绝")

	status, misuseInfo, err := client.userInfo(ctx, endpoints, tokens.IDToken)
	if err != nil {
		return err
	}
	if status != http.StatusUnauthorized || misuseInfo["error"] != "invalid_token" {
		return fmt.Errorf("ID Token 误用未被拒绝: %d %v", status, misuseInfo)
	}
	fmt.Println("  [OK] ID Token 冒充 Access Token 被拒绝")

	replayResponse, replayBody, err := client.postForm(ctx,
		strings.TrimPrefix(fmt.Sprint(endpoints["token_endpoint"]), fixture.issuer),
		url.Values{
			"grant_type": {"authorization_code"}, "code": {code},
			"redirect_uri": {demoRedirectURI}, "client_id": {demoClientID},
			"code_verifier": {verifier},
		}, false)
	if err != nil {
		return err
	}
	if replayResponse.StatusCode != http.StatusBadRequest ||
		oauthErrorOf(replayBody) != "invalid_grant" {
		return fmt.Errorf("授权码重放未被拒绝: %d %s", replayResponse.StatusCode,
			oauthErrorOf(replayBody))
	}
	fmt.Println("  [OK] 授权码重放被 400 invalid_grant 拒绝")

	fmt.Println("\n== 8. 说明")
	fmt.Println("  - UserInfo 的 Access Token audience 必须包含 issuer；资源服务器 audience")
	fmt.Println("    的令牌只能访问业务 API（这是受众隔离，不是校验缺陷）。")
	fmt.Println("  - 错误签发方、撤销与过期令牌的拒绝由 internal/protocolapi 的验收测试")
	fmt.Println("    用真实服务覆盖（外部示例无法安全伪造其他签发方的真实签名）。")
	fmt.Println("  - 生产应用不导入本模块 internal/ 包；照本示例的客户端部分（Discovery、")
	fmt.Println("    PKCE、令牌兑换、JWKS 验签、UserInfo）用标准库实现即可。")
	fmt.Println("\nOIDC UserInfo 正向接入与受众校验示例完成。")
	return nil
}
