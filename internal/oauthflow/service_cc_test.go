package oauthflow_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
)

// serviceExchange 发起 client_credentials Token 端点请求。
func (e *testEnv) serviceExchange(clientID, secret string, scope, resource []string,
	requestID string) (oauthflow.TokenResponse, error) {
	e.t.Helper()
	return e.flow.Exchange(e.ctx, oauthflow.ExchangeRequest{
		GrantType: "client_credentials", ClientID: clientID, ClientSecret: secret,
		Scope: scope, Resource: resource, RequestID: requestID,
	})
}

// registerClient 直接登记额外应用与 OAuth 客户端安全设置（协议层只读真实登记配置）。
func (e *testEnv) registerClient(applicationID, redirectURI string,
	clientType oauthclient.ClientType, grants []string, secret string) {
	e.t.Helper()
	if _, err := e.raw.ExecContext(e.ctx, `INSERT INTO applications(id,name,status,client_type,row_version,created_at_ms,updated_at_ms)
VALUES(?,?, 'active', ?,1,?,?)`, applicationID, "Extra App", string(clientType),
		e.now.UnixMilli(), e.now.UnixMilli()); err != nil {
		e.t.Fatalf("插入额外应用失败: %v", err)
	}
	authMethods := `[]`
	if clientType == oauthclient.ClientTypeConfidential {
		authMethods = `["client_secret_basic"]`
	}
	if _, err := e.raw.DB().ExecContext(e.ctx, `INSERT INTO oauth_clients(client_id,client_type,grant_types_json,redirect_uris_json,
post_logout_redirect_uris_json,scopes_json,audiences_json,auth_methods_json,require_pkce,
row_version,created_at_ms,updated_at_ms) VALUES(?,?,?,?,?,'["profile.read"]','["`+
		testAudience+`"]',?,1,1,?,?)`,
		applicationID, string(clientType), `["`+strings.Join(grants, `","`)+`"]`,
		`["`+redirectURI+`"]`, `[]`, authMethods, e.now.UnixMilli(), e.now.UnixMilli()); err != nil {
		e.t.Fatalf("插入额外 OAuth 客户端失败: %v", err)
	}
	if secret != "" {
		e.clientAuth.secrets[applicationID] = secret
	}
}

// TestClientCredentialsServiceToken 验证合法保密客户端获取服务身份令牌：主体为
// client_id、subject_type=service、Scope/audience 缩减、无 ID/Refresh Token，且
// 审计以系统主体记录、不含 token/secret。
func TestClientCredentialsServiceToken(t *testing.T) {
	env := newTestEnv(t, oauthclient.ClientTypeConfidential)
	response, err := env.serviceExchange(testAppID, "confidential-secret",
		[]string{"profile.read"}, []string{testAudience}, "req_cc_happy")
	if err != nil {
		t.Fatalf("服务身份令牌签发失败: %v", err)
	}
	if !response.AccessToken.IsSet() || response.TokenType != "Bearer" ||
		response.ExpiresIn <= 0 || response.Scope != "profile.read" {
		t.Fatalf("标准 Token 响应不正确: %+v", response)
	}
	if response.IDToken.IsSet() {
		t.Fatal("client_credentials 默认不得签发 ID Token")
	}
	claims, err := env.tokens.VerifyAccessToken(env.ctx, response.AccessToken.Reveal(), testAudience)
	if err != nil {
		t.Fatalf("验证服务身份令牌: %v", err)
	}
	if claims.Subject != testAppID || claims.ClientID != testAppID {
		t.Fatalf("服务身份主体必须是 client_id 自身: sub=%q client=%q",
			claims.Subject, claims.ClientID)
	}
	if claims.SubjectType != "service" || claims.TokenUse != "access" {
		t.Fatalf("服务身份令牌声明不正确: subject_type=%q token_use=%q",
			claims.SubjectType, claims.TokenUse)
	}
	if strings.Join(claims.Scopes, " ") != "profile.read" ||
		strings.Join(claims.Audience, " ") != testAudience {
		t.Fatalf("Scope/audience 不正确: %+v", claims)
	}
	// 服务主体审计：actor_type=system / actor_id=oauthflow；不含 token/secret 原文。
	if got := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action='oauth.service_token.issued'
AND actor_type='system' AND actor_id='oauthflow' AND outcome='success'`); got != 1 {
		t.Fatalf("缺少服务主体签发审计: %d", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE detail_json LIKE ? OR detail_json LIKE ?`,
		"%"+response.AccessToken.Reveal()+"%", "%confidential-secret%"); got != 0 {
		t.Fatalf("审计泄露服务令牌或客户端 secret")
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action='oauth.service_token.issued'
AND actor_type='user'`); got != 0 {
		t.Fatalf("服务身份签发不得冒用用户主体审计")
	}
	// Token 服务自身的签发审计也应是系统主体。
	if got := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action='token.access.issued'
AND actor_type='system' AND actor_id='oauthflow'`); got != 1 {
		t.Fatalf("缺少令牌服务系统主体签发审计: %d", got)
	}
}

// TestClientCredentialsRejections 覆盖错误凭证、公开客户端、未登记 grant、应用停用、
// 越界 Scope/audience；全部标准 OAuth 错误且不签发令牌。
func TestClientCredentialsRejections(t *testing.T) {
	env := newTestEnv(t, oauthclient.ClientTypeConfidential)
	// 公开客户端即使配置了 client_credentials 也必须拒绝。
	env.registerSecondClient()
	env.exec(`UPDATE oauth_clients SET grant_types_json='["authorization_code","client_credentials"]'
WHERE client_id=?`, testAppID2)
	caseList := []struct {
		name    string
		request func() (oauthflow.TokenResponse, error)
		code    string
		status  int
	}{
		{"错误凭证", func() (oauthflow.TokenResponse, error) {
			return env.serviceExchange(testAppID, "wrong-secret", []string{"profile.read"},
				[]string{testAudience}, "req_cc_bad_secret")
		}, "invalid_client", 401},
		{"缺少客户端认证", func() (oauthflow.TokenResponse, error) {
			return env.serviceExchange(testAppID, "", []string{"profile.read"},
				[]string{testAudience}, "req_cc_missing_auth")
		}, "invalid_client", 401},
		{"公开客户端拒绝", func() (oauthflow.TokenResponse, error) {
			return env.serviceExchange(testAppID2, "", []string{"profile.read"},
				[]string{testAudience}, "req_cc_public")
		}, "unauthorized_client", 400},
		{"越界 Scope", func() (oauthflow.TokenResponse, error) {
			return env.serviceExchange(testAppID, "confidential-secret",
				[]string{"admin.write"}, []string{testAudience}, "req_cc_bad_scope")
		}, "invalid_scope", 400},
		{"越界 audience", func() (oauthflow.TokenResponse, error) {
			return env.serviceExchange(testAppID, "confidential-secret",
				[]string{"profile.read"}, []string{"https://other.example.test"}, "req_cc_bad_aud")
		}, "invalid_request", 400},
	}
	for _, testCase := range caseList {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := testCase.request()
			var protocolError *oauthflow.OAuthError
			if !errors.As(err, &protocolError) || protocolError.Code != testCase.code {
				t.Fatalf("错误 = %v，期望 %s", err, testCase.code)
			}
			if protocolError.HTTPStatus != testCase.status {
				t.Fatalf("HTTP 状态 = %d，期望 %d", protocolError.HTTPStatus, testCase.status)
			}
			if body := protocolError.Body(); body["error"] != testCase.code {
				t.Fatalf("标准错误体不正确: %+v", body)
			}
		})
	}
	// 未登记 client_credentials 的保密客户端拒绝（即使 secret 正确）。
	const appNoGrant = "app_00000000000000000000000000000003"
	env.registerClient(appNoGrant, "https://no-grant.example.test/cb",
		oauthclient.ClientTypeConfidential, []string{"authorization_code"}, "no-grant-secret")
	if _, err := env.serviceExchange(appNoGrant, "no-grant-secret", []string{"profile.read"},
		[]string{testAudience}, "req_cc_no_grant"); !isOAuthCode(err, "unauthorized_client") {
		t.Fatalf("未登记 client_credentials 应 unauthorized_client，实际 %v", err)
	}
	// 应用停用后拒绝后续签发。
	env.exec(`UPDATE applications SET status='disabled' WHERE id=?`, testAppID)
	if _, err := env.serviceExchange(testAppID, "confidential-secret", []string{"profile.read"},
		[]string{testAudience}, "req_cc_disabled"); !isOAuthCode(err, "invalid_client") {
		t.Fatalf("应用停用后应 invalid_client，实际 %v", err)
	}
	// 失败路径应写服务主体失败审计。
	if got := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action='oauth.service_token.denied'`); got < 4 {
		t.Fatalf("缺少服务身份拒绝审计: %d", got)
	}
	// 所有失败都不产生成功签发审计。
	if got := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action='oauth.service_token.issued'`); got != 0 {
		t.Fatalf("失败路径不应产生成功签发审计: %d", got)
	}
}

// TestClientCredentialsScopeNarrowingAndRotation 验证 Scope/audience 可在登记范围内
// 缩减，以及客户端凭证轮换后旧 secret 立即失效、新 secret 生效。
func TestClientCredentialsScopeNarrowingAndRotation(t *testing.T) {
	env := newTestEnv(t, oauthclient.ClientTypeConfidential)
	// 只请求登记集合的子集。
	response, err := env.serviceExchange(testAppID, "confidential-secret",
		[]string{"profile.read"}, []string{testAudience}, "req_cc_narrow")
	if err != nil {
		t.Fatalf("缩减 Scope 签发失败: %v", err)
	}
	claims, err := env.tokens.VerifyAccessToken(env.ctx, response.AccessToken.Reveal(), testAudience)
	if err != nil {
		t.Fatalf("验证缩减 Scope 令牌: %v", err)
	}
	if strings.Join(claims.Scopes, " ") != "profile.read" {
		t.Fatalf("Scope 未按请求缩减: %v", claims.Scopes)
	}
	// 模拟客户端凭证轮换：旧 secret 失效，新 secret 生效。
	env.clientAuth.secrets[testAppID] = "rotated-confidential-secret"
	if _, err := env.serviceExchange(testAppID, "confidential-secret", []string{"profile.read"},
		[]string{testAudience}, "req_cc_old_secret"); !isOAuthCode(err, "invalid_client") {
		t.Fatalf("轮换后旧 secret 应 invalid_client，实际 %v", err)
	}
	if _, err := env.serviceExchange(testAppID, "rotated-confidential-secret",
		[]string{"profile.read"}, []string{testAudience}, "req_cc_new_secret"); err != nil {
		t.Fatalf("轮换后新 secret 应成功: %v", err)
	}
}

// TestServiceAndUserTokensDistinct 验证同一客户端签发的用户令牌与服务身份令牌在
// subject/subject_type 上清晰区分，服务令牌不借用用户或 root 身份。
func TestServiceAndUserTokensDistinct(t *testing.T) {
	env := newTestEnv(t, oauthclient.ClientTypeConfidential)
	// 用户授权码流程。
	prompt := env.begin()
	result := env.approve(prompt)
	userResponse, err := env.flow.Exchange(env.ctx, oauthflow.ExchangeRequest{
		GrantType: "authorization_code", Code: result.Code.Reveal(), RedirectURI: testRedirect,
		ClientID: testAppID, ClientSecret: "confidential-secret", CodeVerifier: pkceVerifier,
		RequestID: "req_cc_user_token"})
	if err != nil {
		t.Fatalf("用户令牌兑换失败: %v", err)
	}
	userClaims, err := env.tokens.VerifyAccessToken(env.ctx, userResponse.AccessToken.Reveal(),
		testAudience)
	if err != nil {
		t.Fatalf("验证用户令牌: %v", err)
	}
	serviceResponse, err := env.serviceExchange(testAppID, "confidential-secret",
		[]string{"profile.read"}, []string{testAudience}, "req_cc_service_token")
	if err != nil {
		t.Fatalf("服务令牌签发失败: %v", err)
	}
	serviceClaims, err := env.tokens.VerifyAccessToken(env.ctx, serviceResponse.AccessToken.Reveal(),
		testAudience)
	if err != nil {
		t.Fatalf("验证服务令牌: %v", err)
	}
	if userClaims.SubjectType != "user" || userClaims.Subject != testUserID {
		t.Fatalf("用户令牌主体不正确: %+v", userClaims)
	}
	if serviceClaims.SubjectType != "service" || serviceClaims.Subject != testAppID {
		t.Fatalf("服务令牌主体不正确: %+v", serviceClaims)
	}
	if serviceClaims.Subject == userClaims.Subject {
		t.Fatal("服务令牌不得复用用户主体")
	}
	if serviceClaims.Subject == "" || strings.HasPrefix(serviceClaims.Subject, "usr_") {
		t.Fatalf("服务主体不应是用户 ID: %q", serviceClaims.Subject)
	}
}
