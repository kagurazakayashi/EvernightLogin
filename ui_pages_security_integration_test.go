package login_test

// 步骤 67 真实服务集成：临时 SQLite + 真实 mfa/totp/passkey/recovery/session/
// oauthflow + 真实页面框架；再次认证使用测试执行器（真实策略/强认证装配另记）。

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	oauthclientsqlite "github.com/kagurazakayashi/EvernightLogin/internal/oauthclient/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
	oauthflowsqlite "github.com/kagurazakayashi/EvernightLogin/internal/oauthflow/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	policysqlite "github.com/kagurazakayashi/EvernightLogin/internal/policy/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	reauthsqlite "github.com/kagurazakayashi/EvernightLogin/internal/reauth/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	"github.com/kagurazakayashi/EvernightLogin/internal/uisecurityadapter"
)

// allowSecurityReauth 是测试用再次认证执行器：真实策略/强认证另案装配。
type allowSecurityReauth struct{}

func (allowSecurityReauth) BeginChallenge(_ context.Context, _ reauth.Caller,
	request reauth.ChallengeRequest) (reauth.Challenge, error) {
	return reauth.Challenge{ID: "chl_test", OperationID: request.OperationID,
		Required: true, ExpiresAt: time.Now().Add(5 * time.Minute)}, nil
}
func (allowSecurityReauth) VerifyChallenge(_ context.Context, _ reauth.Caller,
	request reauth.VerifyChallengeRequest) (reauth.ApprovalGrant, error) {
	return reauth.ApprovalGrant{Token: "grant-test", OperationID: "test"}, nil
}
func (allowSecurityReauth) NotifyOutcome(context.Context, reauth.Result, reauth.Outcome) error {
	return nil
}

// allowOperationRunner 供 oauthflow 授权确认使用（测试执行器）。
type allowOperationRunner struct{}

func (allowOperationRunner) Authorize(_ context.Context, _ reauth.Caller,
	_ reauth.Request) (reauth.Result, error) {
	return reauth.Result{}, nil
}
func (allowOperationRunner) NotifyOutcome(context.Context, reauth.Result, reauth.Outcome) error {
	return nil
}

type securityIntegrationEnv struct {
	t       *testing.T
	ui      *login.WebUI
	cookie  *http.Cookie
	env     *mfaPageEnv
	adapter *uisecurityadapter.Adapter
	flow    *oauthflow.Service
	client  string
}

func newSecurityIntegrationEnv(t *testing.T) *securityIntegrationEnv {
	t.Helper()
	env := newMFAPageEnv(t)
	ctx := context.Background()
	nowFunc := func() time.Time { return env.now }
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	auditStore, err := auditsqlite.New(env.storage)
	if err != nil {
		t.Fatalf("审计存储: %v", err)
	}
	recorder, err := audit.New(auditStore, audit.Options{Now: nowFunc, Logger: logger})
	if err != nil {
		t.Fatalf("审计: %v", err)
	}
	keyring, err := secrets.GenerateKeyring("oauth-sec-k1", env.now)
	if err != nil {
		t.Fatalf("密钥环: %v", err)
	}
	clientID := "app_sec_00000000000000000000000000067"
	insert := func(query string, args ...any) {
		t.Helper()
		if _, err := env.storage.ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("fixture 插入失败: %v\n%s", err, query)
		}
	}
	insert(`INSERT INTO applications(id,name,description,status,client_type,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,'','active','public',1,?,?)`, clientID, "安全测试应用", env.now.UnixMilli(), env.now.UnixMilli())
	insert(`INSERT INTO scopes(id,kind,app_id) VALUES(?,'application',?)`, clientID, clientID)
	insert(`INSERT INTO app_memberships(app_id,user_id,status,profile_json,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,'active','{"v":1}',1,?,?)`, clientID, env.userID, env.now.UnixMilli(), env.now.UnixMilli())
	insert(`INSERT INTO oauth_clients(client_id,client_type,grant_types_json,redirect_uris_json,
post_logout_redirect_uris_json,scopes_json,audiences_json,auth_methods_json,require_pkce,
row_version,created_at_ms,updated_at_ms)
VALUES(?,'public','["authorization_code"]','["https://client.example/cb"]','[]',
'["email"]','["resource_sec"]','[]',1,1,?,?)`, clientID, env.now.UnixMilli(), env.now.UnixMilli())
	clientStore, err := oauthclientsqlite.New(env.storage)
	if err != nil {
		t.Fatalf("OAuth 客户端存储: %v", err)
	}
	source, err := oauthflow.NewOAuthClientSource(clientStore)
	if err != nil {
		t.Fatalf("客户端来源: %v", err)
	}
	flowStore, err := oauthflowsqlite.New(env.storage)
	if err != nil {
		t.Fatalf("OAuth 存储: %v", err)
	}
	flow, err := oauthflow.New(oauthflow.Options{Store: flowStore, Audit: recorder,
		Clients: source, ClientAuth: fakeClientAuthenticator{},
		Sessions: env.sessions, Tokens: fakeTokenIssuer{}, Reauth: allowOperationRunner{},
		DeviceVerificationURI: mfaTestOrigin + "/oauth/device",
		DeviceUserCodeKeyring: keyring, Now: nowFunc, Logger: logger})
	if err != nil {
		t.Fatalf("OAuth 服务: %v", err)
	}
	policyStore, err := policysqlite.New(env.storage)
	if err != nil {
		t.Fatalf("策略存储: %v", err)
	}
	policyService, err := policy.New(policy.Options{Store: policyStore, Audit: recorder,
		AvailableStrengths: []policy.Strength{policy.StrengthPassword},
		Now:                nowFunc, Logger: logger})
	if err != nil {
		t.Fatalf("策略服务: %v", err)
	}
	reauthStore, err := reauthsqlite.New(env.storage)
	if err != nil {
		t.Fatalf("再次认证存储: %v", err)
	}
	reauthService, err := reauth.New(reauth.Options{Store: reauthStore, Audit: recorder,
		Policy: policyService, Passwords: authnPasswordVerifier{authn: env.authn},
		AvailableStrengths: []policy.Strength{policy.StrengthPassword},
		Now:                nowFunc, Logger: logger})
	if err != nil {
		t.Fatalf("再次认证服务: %v", err)
	}
	adapter, err := uisecurityadapter.New(uisecurityadapter.Options{
		MFA: env.mfa, TOTP: env.totp, Passkeys: env.passkeys, Recovery: env.recovery,
		Sessions: env.sessions, OAuth: flow, Reauth: reauthService,
		ApplicationNames: map[string]string{clientID: "安全测试应用"},
		Now:              nowFunc, Logger: logger})
	if err != nil {
		t.Fatalf("安全中心适配器: %v", err)
	}
	ui, err := login.NewWebUI(login.WebUIOptions{
		Session: pageSessions{service: env.sessions}, FormTokens: env.csrf,
		PageSecurity: &login.UIPageSecurityOptions{Backend: adapter},
		Now:          nowFunc, Logger: logger})
	if err != nil {
		t.Fatalf("页面框架: %v", err)
	}
	securityVersion := int64(1)
	rows, queryErr := env.storage.QueryContext(ctx,
		`SELECT security_version FROM users WHERE id=?`, env.userID)
	if queryErr == nil && rows.Next() {
		_ = rows.Scan(&securityVersion)
		rows.Close()
	}
	issued, err := env.sessions.Login(ctx, session.LoginRequest{
		Result: authn.AuthenticateResult{UserID: env.userID, Username: "mfauser",
			Outcome:          authn.OutcomeComplete,
			CompletedMethods: []authn.Method{authn.MethodPassword},
			CompletedAt:      env.now, SecurityVersion: securityVersion},
		RequestID: "req_security_login"})
	if err != nil {
		t.Fatalf("签发会话: %v", err)
	}
	cookie, err := env.sessions.NewCookie(issued)
	if err != nil {
		t.Fatalf("会话 Cookie: %v", err)
	}
	return &securityIntegrationEnv{t: t, ui: ui, cookie: cookie, env: env,
		adapter: adapter, flow: flow, client: clientID}
}

func (e *securityIntegrationEnv) request(method, target string, form url.Values) *httptest.ResponseRecorder {
	e.t.Helper()
	body := strings.NewReader("")
	if form != nil {
		form.Set("csrf_token", "test-csrf-token")
		body = strings.NewReader(form.Encode())
	}
	request := httptest.NewRequest(method, mfaTestOrigin+target, body)
	request.Host = "example.test"
	request.Header.Set("Origin", mfaTestOrigin)
	request.AddCookie(e.cookie)
	if form != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	recorder := httptest.NewRecorder()
	e.ui.ServeHTTP(recorder, request)
	return recorder
}

var hiddenFieldPattern = regexp.MustCompile(`name="([a-z_]+)" value="([^"]*)"`)

func hiddenFields(body string) map[string]string {
	fields := map[string]string{}
	for _, match := range hiddenFieldPattern.FindAllStringSubmatch(body, -1) {
		fields[match[1]] = match[2]
	}
	return fields
}

// TestSecurityBackendRealServices 验证真实 MFA 移除/添加、会话退出与授权撤回。
func TestSecurityBackendRealServices(t *testing.T) {
	env := newSecurityIntegrationEnv(t)
	// 各区域真实渲染。
	for path, expected := range map[string]string{
		"/account/security":                "安全设置",
		"/account/security/mfa":            "移除邮件验证码",
		"/account/security/totp":           "开始绑定验证器",
		"/account/security/recovery-codes": "重新生成恢复代码",
		"/account/sessions":                "当前会话",
	} {
		response := env.request(http.MethodGet, path, nil)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), expected) {
			t.Fatalf("%s 真实渲染失败: %d", path, response.Code)
		}
	}
	// 邮件因素：错误密码 fail-closed，不改变真实状态。
	wrongRemove := env.request(http.MethodPost, "/account/security/mfa/remove",
		url.Values{"current_password": {"wrong password"}})
	if wrongRemove.Code < http.StatusBadRequest || strings.Contains(wrongRemove.Body.String(), "邮件两步验证已更新") ||
		!strings.Contains(wrongRemove.Body.String(), "需要先验证当前身份") {
		t.Fatalf("错误密码移除因素应失败: %d", wrongRemove.Code)
	}
	// 真实移除后再通过真实邮件验证码添加。
	remove := env.request(http.MethodPost, "/account/security/mfa/remove",
		url.Values{"current_password": {"correct horse battery staple"}})
	if remove.Code != http.StatusOK || !strings.Contains(remove.Body.String(), "邮件两步验证已更新") {
		t.Fatalf("移除邮件因素失败: %d body=%s", remove.Code, remove.Body.String())
	}
	addStart := env.request(http.MethodPost, "/account/security/mfa", url.Values{})
	if addStart.Code != http.StatusOK || !strings.Contains(addStart.Body.String(), `name="attempt_token"`) {
		t.Fatalf("开始添加邮件因素失败: %d", addStart.Code)
	}
	fields := hiddenFields(addStart.Body.String())
	code := regexp.MustCompile(`\d{8}`).FindString(env.env.mail.last.TextBody)
	if fields["challenge_id"] == "" || fields["attempt_token"] == "" || code == "" {
		t.Fatalf("缺少挑战/验证码: fields=%v", fields["challenge_id"])
	}
	confirm := env.request(http.MethodPost, "/account/security/mfa/confirm", url.Values{
		"challenge_id": {fields["challenge_id"]}, "attempt_token": {fields["attempt_token"]},
		"code": {code}})
	if confirm.Code != http.StatusOK || !strings.Contains(confirm.Body.String(), "邮件两步验证已更新") {
		t.Fatalf("确认邮件因素失败: %d body=%s", confirm.Code, confirm.Body.String())
	}
	// 会话：真实列表与退出其他（当前账户只有会话；保留当前）。
	list := env.request(http.MethodGet, "/account/sessions", nil)
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), "当前会话") {
		t.Fatalf("会话列表失败: %d", list.Code)
	}
	wrongOthers := env.request(http.MethodPost, "/account/sessions/revoke-others",
		url.Values{"current_password": {"wrong password"}})
	if wrongOthers.Code < http.StatusBadRequest || !strings.Contains(wrongOthers.Body.String(), "需要先验证当前身份") {
		t.Fatalf("错误密码退出其他会话应失败: %d", wrongOthers.Code)
	}
	others := env.request(http.MethodPost, "/account/sessions/revoke-others",
		url.Values{"current_password": {"correct horse battery staple"}})
	if others.Code != http.StatusOK {
		t.Fatalf("退出其他会话失败: %d body=%s", others.Code, others.Body.String())
	}
	// 授权：真实 oauthflow 授权后列表可见、撤回后消失。
	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~abc"
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	prompt, err := env.flow.BeginAuthorization(context.Background(), env.cookie.Value,
		oauthflow.AuthorizeRequest{ClientID: env.client, RedirectURI: "https://client.example/cb",
			ResponseType: "code", Scope: []string{"email"}, State: "state-sec",
			CodeChallenge: challenge, CodeChallengeMethod: "S256", RequestID: "req-sec-grant"})
	if err != nil {
		t.Fatalf("创建授权请求失败: %v", err)
	}
	if _, err := env.flow.DecideAuthorization(context.Background(), env.cookie.Value,
		oauthflow.DecideRequest{RequestID: prompt.RequestID, Approve: true,
			DecisionRequestID: "req-sec-decide"}); err != nil {
		t.Fatalf("批准授权失败: %v", err)
	}
	grants := env.request(http.MethodGet, "/account/grants", nil)
	if grants.Code != http.StatusOK || !strings.Contains(grants.Body.String(), "安全测试应用") ||
		!strings.Contains(grants.Body.String(), "name=\"authorization_id\" value=\"") {
		t.Fatalf("授权列表失败: %d body=%s", grants.Code, grants.Body.String())
	}
	wrongRevoke := env.request(http.MethodPost, "/account/grants/revoke", url.Values{
		"authorization_id": {prompt.RequestID},
		"current_password": {"wrong password"}})
	if wrongRevoke.Code < http.StatusBadRequest || !strings.Contains(wrongRevoke.Body.String(), "需要先验证当前身份") {
		t.Fatalf("错误密码撤回授权应失败: %d", wrongRevoke.Code)
	}
	stillListed := env.request(http.MethodGet, "/account/grants", nil)
	if !strings.Contains(stillListed.Body.String(), "安全测试应用") {
		t.Fatal("失败撤回不应改变真实授权")
	}
	revoke := env.request(http.MethodPost, "/account/grants/revoke", url.Values{
		"authorization_id": {prompt.RequestID},
		"current_password": {"correct horse battery staple"}})
	if revoke.Code != http.StatusOK || !strings.Contains(revoke.Body.String(), "授权已撤回") {
		t.Fatalf("撤回授权失败: %d body=%s", revoke.Code, revoke.Body.String())
	}
	grantsAgain := env.request(http.MethodGet, "/account/grants", nil)
	if strings.Contains(grantsAgain.Body.String(), "安全测试应用") {
		t.Fatal("已撤销授权不应再出现在列表")
	}
	// 退出全部：清除 Cookie 并跳登录。
	all := env.request(http.MethodPost, "/account/sessions/revoke-all",
		url.Values{"current_password": {"correct horse battery staple"}})
	if all.Code != http.StatusSeeOther || all.Header().Get("Location") != "/login" {
		t.Fatalf("退出全部会话失败: %d", all.Code)
	}
}
