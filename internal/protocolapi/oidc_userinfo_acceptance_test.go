package protocolapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/protocolapi"
	"github.com/kagurazakayashi/EvernightLogin/internal/token"
)

// 本文件是步骤 191 的 OIDC UserInfo 正向接入与受众校验验收。
//
// 正向证据全部来自真实 HTTP 协议流程：临时 SQLite + 真实领域服务 + httptest 回环
// HTTP 服务，客户端只通过 HTTP 端点完成 授权码 + PKCE(S256) → Token → UserInfo；
// 不使用“直接签发 Access Token 再调用 UserInfo”冒充正向证据。直接签发的令牌只用于
// 两个无法通过本服务协议流程构造的拒绝用例：错误签发方（需要另一签发方真实签名）
// 与撤销后/过期后的负例准备。

// step191OtherIssuer 是“错误签发方”用例使用的第二个签发方标识。
const step191OtherIssuer = "https://other-issuer.example.test"

// step191OtherIssuerClients 是第二个令牌服务的客户端来源：只登记与真实客户端相同的
// Scope/audience 范围，确保签发失败时不会掩盖“错误签发方”这一唯一变量。
type step191OtherIssuerClients struct{}

// LoadClient 实现 token.ClientSource。
func (step191OtherIssuerClients) LoadClient(_ context.Context, clientID string) (token.ClientInfo, error) {
	if clientID != testClientPublic {
		return token.ClientInfo{}, token.ErrClientNotFound
	}
	return token.ClientInfo{
		ClientID: testClientPublic, ApplicationID: testClientPublic, ClientType: "public",
		AppActive:  true,
		GrantTypes: []string{"authorization_code", "refresh_token"},
		Scopes:     []string{"openid", "profile", "email", "offline_access"},
		Audiences:  []string{testIssuer, testResourceAPI},
	}, nil
}

// issueWrongIssuerAccessToken 用第二个真实令牌服务签发一个“签名密钥相同、签发方不同”
// 的 Access Token：它与真实令牌共用同一签名私钥（同一 active key 记录）与同一
// audience（testIssuer），唯一差异是 iss；因此 UserInfo 若接受它，就说明签发方校验
// 缺失。该令牌不是手工拼装的 JWT，而是真实令牌服务的签发结果。
func (e *testEnv) issueWrongIssuerAccessToken() string {
	e.t.Helper()
	other, err := token.New(token.Options{
		Store: e.tokenStore, Audit: e.audit, Sealer: e.sealer, Issuer: step191OtherIssuer,
		Clients: step191OtherIssuerClients{},
		Authorizer: token.IssuanceAuthorizerFunc(func(_ context.Context, _ token.Caller,
			request token.IssuanceRequest) error {
			if request.GrantType == token.GrantAuthorizationCode {
				return nil
			}
			return token.ErrAccessDenied
		}),
		KeyRetention: 24 * time.Hour, Now: e.clock.Now,
	})
	if err != nil {
		e.t.Fatalf("构造第二签发方令牌服务失败: %v", err)
	}
	caller, err := token.SystemCaller("step191-other-issuer")
	if err != nil {
		e.t.Fatalf("构造第二签发方调用者失败: %v", err)
	}
	issued, err := other.IssueAccessToken(e.ctx, caller, token.IssueAccessTokenRequest{
		ClientID: testClientPublic, SubjectUserID: testUserAlice,
		GrantType: token.GrantAuthorizationCode, Scopes: []string{"openid", "profile"},
		Audiences: []string{testIssuer}, RequestID: "req_step191_other_issuer"})
	if err != nil {
		e.t.Fatalf("签发错误签发方令牌失败: %v", err)
	}
	return issued.Token.Reveal()
}

// oidcUserInfoHTTP 用 Bearer 调用真实 UserInfo HTTP 端点并解码 JSON 正文。
func (e *testEnv) oidcUserInfoHTTP(accessToken string) (*http.Response, map[string]any) {
	e.t.Helper()
	response, body := e.doRequest(http.MethodGet, protocolapi.PathUserInfo,
		requestOptions{header: map[string]string{"Authorization": "Bearer " + accessToken}})
	var decoded map[string]any
	_ = json.Unmarshal(body, &decoded)
	return response, decoded
}

// revokeAccessTokenHTTP 用真实撤销端点（RFC 7009）撤销访问令牌。
func (e *testEnv) revokeAccessTokenHTTP(accessToken string) {
	e.t.Helper()
	response, body := e.doRequest(http.MethodPost, protocolapi.PathRevoke,
		requestOptions{form: url.Values{"token": {accessToken}, "client_id": {testClientPublic}}})
	if response.StatusCode != http.StatusOK {
		e.t.Fatalf("撤销访问令牌状态 = %d: %s", response.StatusCode, body)
	}
}

// TestOIDCUserInfoAcceptance 按步骤 191 判据验收 UserInfo：
//   - 成功路径来自真实授权码 + PKCE → Token → UserInfo；
//   - sub 与 ID Token 一致、scope 字段裁剪、缺少 openid 拒绝；
//   - 错误 audience、错误签发方、ID Token 误用、授权码重放、撤销与过期令牌全部拒绝。
func TestOIDCUserInfoAcceptance(t *testing.T) {
	env := newTestEnv(t, nil)
	_, cookie := env.login(testUserAlice)

	// Discovery 必须声明真实挂载的 UserInfo 端点，客户端据此拼请求。
	discoveryResponse, discoveryBody := env.doRequest(http.MethodGet,
		protocolapi.PathDiscovery, requestOptions{})
	if discoveryResponse.StatusCode != http.StatusOK {
		t.Fatalf("Discovery 状态 = %d: %s", discoveryResponse.StatusCode, discoveryBody)
	}
	discovery := env.decodeJSON(discoveryBody)
	if endpoint, _ := discovery["userinfo_endpoint"].(string); endpoint != testIssuer+protocolapi.PathUserInfo {
		t.Fatalf("Discovery userinfo_endpoint = %v", discovery["userinfo_endpoint"])
	}

	// ===== 正向：真实授权码 + PKCE S256 兑换令牌后调用 UserInfo =====
	payload := env.issueCodeTokens(cookie, "openid profile email", testIssuer, "nonce-step191")
	accessToken, _ := payload["access_token"].(string)
	idTokenRaw, _ := payload["id_token"].(string)
	if accessToken == "" || idTokenRaw == "" {
		t.Fatalf("授权码流程未取得 access_token/id_token: %v", payload)
	}
	// 用真实令牌服务验证 ID Token（iss/aud/exp），并取 sub 与 UserInfo 比对。
	idClaims, err := env.tokens.VerifyIDToken(env.ctx, idTokenRaw, testClientPublic)
	if err != nil {
		t.Fatalf("ID Token 校验失败: %v", err)
	}
	response, info := env.oidcUserInfoHTTP(accessToken)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("UserInfo 状态 = %d: %v", response.StatusCode, info)
	}
	subject, _ := info["sub"].(string)
	if subject == "" || subject != idClaims.Subject {
		t.Fatalf("UserInfo sub = %q，ID Token sub = %q（必须一致）", subject, idClaims.Subject)
	}
	if info["name"] != "Alice" || info["preferred_username"] != "alice" ||
		info["locale"] != "zh-CN" || info["zoneinfo"] != "Asia/Shanghai" {
		t.Fatalf("profile 字段异常: %v", info)
	}
	if info["email"] != "alice@example.test" || info["email_verified"] != true {
		t.Fatalf("email/email_verified 异常: %v", info)
	}
	for _, forbidden := range []string{"password", "mfa", "session", "recovery", "security_version"} {
		if _, exists := info[forbidden]; exists {
			t.Fatalf("UserInfo 泄露字段 %q", forbidden)
		}
	}

	// ===== scope 裁剪：只申请 openid 时只返回 sub =====
	trimmed := env.issueCodeTokens(cookie, "openid", testIssuer, "nonce-step191-trim")
	trimmedToken, _ := trimmed["access_token"].(string)
	response, trimmedInfo := env.oidcUserInfoHTTP(trimmedToken)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("openid-only UserInfo 状态 = %d: %v", response.StatusCode, trimmedInfo)
	}
	if trimmedSubject, _ := trimmedInfo["sub"].(string); trimmedSubject == "" ||
		trimmedSubject != idClaims.Subject {
		t.Fatalf("openid-only UserInfo sub = %v", trimmedInfo["sub"])
	}
	for _, trimmedField := range []string{"name", "preferred_username", "locale", "zoneinfo",
		"updated_at", "email", "email_verified"} {
		if _, exists := trimmedInfo[trimmedField]; exists {
			t.Fatalf("缺少 profile/email scope 却返回 %q: %v", trimmedField, trimmedInfo)
		}
	}

	// ===== 缺少 openid scope：真实流程签发的令牌被拒绝（403 insufficient_scope） =====
	noOpenID := env.issueCodeTokens(cookie, "profile email", testIssuer, "nonce-step191-no-openid")
	noOpenIDToken, _ := noOpenID["access_token"].(string)
	response, noOpenIDInfo := env.oidcUserInfoHTTP(noOpenIDToken)
	if response.StatusCode != http.StatusForbidden || noOpenIDInfo["error"] != "insufficient_scope" {
		t.Fatalf("缺少 openid scope 未被拒绝: %d %v", response.StatusCode, noOpenIDInfo)
	}

	// ===== 错误 audience：资源服务器 audience 的令牌不能访问 UserInfo =====
	wrongAudience := env.issueCodeTokens(cookie, "openid profile", testResourceAPI,
		"nonce-step191-wrong-audience")
	wrongAudienceToken, _ := wrongAudience["access_token"].(string)
	response, wrongAudienceInfo := env.oidcUserInfoHTTP(wrongAudienceToken)
	if response.StatusCode != http.StatusUnauthorized || wrongAudienceInfo["error"] != "invalid_token" {
		t.Fatalf("错误 audience 的令牌未被拒绝: %d %v", response.StatusCode, wrongAudienceInfo)
	}

	// ===== 错误签发方：同一签名密钥、不同 iss 的真实令牌被拒绝 =====
	wrongIssuerToken := env.issueWrongIssuerAccessToken()
	response, wrongIssuerInfo := env.oidcUserInfoHTTP(wrongIssuerToken)
	if response.StatusCode != http.StatusUnauthorized || wrongIssuerInfo["error"] != "invalid_token" {
		t.Fatalf("错误签发方的令牌未被拒绝: %d %v", response.StatusCode, wrongIssuerInfo)
	}

	// ===== ID Token 误用：不能冒充 Access Token 访问 UserInfo =====
	response, idTokenMisuse := env.oidcUserInfoHTTP(idTokenRaw)
	if response.StatusCode != http.StatusUnauthorized || idTokenMisuse["error"] != "invalid_token" {
		t.Fatalf("ID Token 冒充 Access Token 未被拒绝: %d %v", response.StatusCode, idTokenMisuse)
	}

	// ===== 授权码重放：同一授权码第二次兑换必须 invalid_grant =====
	code, _ := env.obtainAuthorizationCode(cookie, "openid profile", testIssuer,
		"state-step191-replay", "nonce-step191-replay")
	exchange, exchangePayload := env.exchangeCode(code, testPKCEVerifier)
	if exchange.StatusCode != http.StatusOK {
		t.Fatalf("首次兑换授权码失败: %d %v", exchange.StatusCode, exchangePayload)
	}
	replay, replayPayload := env.exchangeCode(code, testPKCEVerifier)
	if replay.StatusCode != http.StatusBadRequest || replayPayload["error"] != "invalid_grant" {
		t.Fatalf("授权码重放未被拒绝: %d %v", replay.StatusCode, replayPayload)
	}

	// ===== 撤销后：真实撤销端点撤销访问令牌，UserInfo 必须立即拒绝 =====
	env.revokeAccessTokenHTTP(accessToken)
	response, revokedInfo := env.oidcUserInfoHTTP(accessToken)
	if response.StatusCode != http.StatusUnauthorized || revokedInfo["error"] != "invalid_token" {
		t.Fatalf("撤销后的访问令牌仍可访问 UserInfo: %d %v", response.StatusCode, revokedInfo)
	}

	// ===== 过期：推进真实服务时钟越过 Access Token 有效期后必须拒绝 =====
	// 先通过真实协议流程取得新令牌，再推进测试时钟（该环境时钟注入到真实令牌/
	// OIDC 服务，等价于墙钟前进；不再用固定夹具伪造过期结论）。
	expiring := env.issueCodeTokens(cookie, "openid", testIssuer, "nonce-step191-expired")
	expiringToken, _ := expiring["access_token"].(string)
	env.clock.Advance(2 * time.Hour)
	response, expiredInfo := env.oidcUserInfoHTTP(expiringToken)
	if response.StatusCode != http.StatusUnauthorized || expiredInfo["error"] != "invalid_token" {
		t.Fatalf("过期后的访问令牌仍可访问 UserInfo: %d %v", response.StatusCode, expiredInfo)
	}

	// 全部拒绝响应都必须是标准 RFC 6750 Bearer 挑战，不得是 5xx 或静默放行。
	if challenge := response.Header.Get("WWW-Authenticate"); !strings.HasPrefix(challenge, "Bearer") {
		t.Fatalf("UserInfo 错误响应缺少 Bearer 挑战: %q", challenge)
	}
}
