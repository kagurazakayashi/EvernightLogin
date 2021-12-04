package protocolapi_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/kagurazakayashi/EvernightLogin/internal/protocolapi"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// consentPage 是从最小同意页解析出的服务端值（隐藏字段，由 html/template 转义）。
type consentPage struct {
	requestID string
	csrfToken string
}

var (
	requestIDPattern = regexp.MustCompile(`name="request_id" value="([^"]+)"`)
	csrfTokenPattern = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)
)

// authorizeValues 构造标准授权请求参数。
func authorizeValues(scope, resource, state, nonce string) url.Values {
	return url.Values{
		"client_id":             {testClientPublic},
		"redirect_uri":          {testRedirectURI},
		"response_type":         {"code"},
		"scope":                 {scope},
		"resource":              {resource},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {testPKCEChallenge},
		"code_challenge_method": {"S256"},
	}
}

// beginConsent GET 授权端点并解析同意页隐藏字段。
func (e *testEnv) beginConsent(cookie *http.Cookie, values url.Values) consentPage {
	e.t.Helper()
	response, body := e.doRequest(http.MethodGet,
		protocolapi.PathAuthorize+"?"+values.Encode(), requestOptions{cookie: cookie})
	if response.StatusCode != http.StatusOK {
		e.t.Fatalf("同意页状态 = %d: %s", response.StatusCode, body)
	}
	if contentType := response.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "text/html") {
		e.t.Fatalf("同意页 Content-Type = %q", contentType)
	}
	requestID := firstMatch(requestIDPattern, body)
	csrfToken := firstMatch(csrfTokenPattern, body)
	if requestID == "" || csrfToken == "" {
		e.t.Fatalf("同意页缺少隐藏字段: %s", body)
	}
	return consentPage{requestID: requestID, csrfToken: csrfToken}
}

// submitConsent 提交同意/拒绝决定（带同源 Origin）。
func (e *testEnv) submitConsent(cookie *http.Cookie, page consentPage,
	decision string) *http.Response {
	e.t.Helper()
	form := url.Values{
		"request_id": {page.requestID},
		"csrf_token": {page.csrfToken},
		"decision":   {decision},
	}
	response, body := e.doRequest(http.MethodPost, protocolapi.PathAuthorize,
		requestOptions{cookie: cookie, form: form,
			header: map[string]string{"Origin": testIssuer}})
	if response.StatusCode != http.StatusSeeOther {
		e.t.Fatalf("同意提交状态 = %d，期望 303: %s", response.StatusCode, body)
	}
	return response
}

// redirectValues 解析 303 重定向地址的查询参数并校验回调前缀。
func redirectValues(t *testing.T, response *http.Response) url.Values {
	t.Helper()
	location := response.Header.Get("Location")
	if location == "" {
		t.Fatal("重定向响应缺少 Location")
	}
	if !strings.HasPrefix(location, testRedirectURI) {
		t.Fatalf("重定向到未登记回调: %s", location)
	}
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("解析重定向地址失败: %v", err)
	}
	return parsed.Query()
}

// exchangeForm 构造授权码兑换表单。
func exchangeForm(code, verifier string) url.Values {
	return url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {testRedirectURI},
		"client_id":     {testClientPublic},
		"code_verifier": {verifier},
	}
}

// exchangeCode 兑换授权码并返回响应与解码正文。
func (e *testEnv) exchangeCode(code, verifier string) (*http.Response, map[string]any) {
	e.t.Helper()
	response, body := e.doRequest(http.MethodPost, protocolapi.PathToken,
		requestOptions{form: exchangeForm(code, verifier)})
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		e.t.Fatalf("令牌响应不是合法 JSON: %v\n%s", err, body)
	}
	return response, payload
}

// obtainAuthorizationCode 完成“GET 同意页 + POST 批准”并返回授权码与 state。
func (e *testEnv) obtainAuthorizationCode(cookie *http.Cookie, scope, resource, state,
	nonce string) (string, url.Values) {
	e.t.Helper()
	page := e.beginConsent(cookie, authorizeValues(scope, resource, state, nonce))
	response := e.submitConsent(cookie, page, "approve")
	query := redirectValues(e.t, response)
	code := query.Get("code")
	if code == "" {
		e.t.Fatalf("批准后重定向缺少 code: %v", query)
	}
	if got := query.Get("state"); got != state {
		e.t.Fatalf("state = %q，期望 %q", got, state)
	}
	return code, query
}

// issueCodeTokens 完成授权码流程并返回令牌响应载荷。
func (e *testEnv) issueCodeTokens(cookie *http.Cookie, scope, resource, nonce string) map[string]any {
	e.t.Helper()
	code, _ := e.obtainAuthorizationCode(cookie, scope, resource, "state-"+nonce, nonce)
	response, payload := e.exchangeCode(code, testPKCEVerifier)
	if response.StatusCode != http.StatusOK {
		e.t.Fatalf("授权码兑换状态 = %d: %v", response.StatusCode, payload)
	}
	return payload
}

// firstMatch 返回正则第一个捕获组。
func firstMatch(pattern *regexp.Regexp, body []byte) string {
	match := pattern.FindSubmatch(body)
	if len(match) < 2 {
		return ""
	}
	return string(match[1])
}

// TestAuthorizeRequiresLogin 验证未登录时返回受控错误，不创建待确认请求，也不
// 自动批准。
func TestAuthorizeRequiresLogin(t *testing.T) {
	env := newTestEnv(t, nil)
	values := authorizeValues("openid profile", testIssuer, "state-1", "nonce-1")
	response, body := env.doRequest(http.MethodGet,
		protocolapi.PathAuthorize+"?"+values.Encode(), requestOptions{})
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("未登录授权状态 = %d: %s", response.StatusCode, body)
	}
	payload := env.decodeJSON(body)
	if payload["error"] != "access_denied" {
		t.Fatalf("error = %v", payload["error"])
	}
	if location := response.Header.Get("Location"); location != "" {
		t.Fatalf("未登录时不得重定向到任何地址: %s", location)
	}
	if count := env.queryInt(`SELECT COUNT(*) FROM oauth_authorization_requests`); count != 0 {
		t.Fatalf("未登录时不应创建待确认请求，实际 %d", count)
	}
}

// TestAuthorizeLoginPathRedirect 验证配置 LoginPath 后未登录跳转登录页并携带
// 站内相对 return_to（不产生开放重定向）。
func TestAuthorizeLoginPathRedirect(t *testing.T) {
	env := newTestEnv(t, func(options *protocolapi.Options) {
		options.LoginPath = "/login"
	})
	values := authorizeValues("openid", testIssuer, "state-2", "nonce-2")
	response, body := env.doRequest(http.MethodGet,
		protocolapi.PathAuthorize+"?"+values.Encode(), requestOptions{})
	if response.StatusCode != http.StatusSeeOther {
		t.Fatalf("状态 = %d: %s", response.StatusCode, body)
	}
	location := response.Header.Get("Location")
	if !strings.HasPrefix(location, "/login?return_to=") {
		t.Fatalf("Location = %q", location)
	}
	returnTo, err := url.QueryUnescape(strings.TrimPrefix(location, "/login?return_to="))
	if err != nil {
		t.Fatalf("return_to 编码无效: %v", err)
	}
	if !strings.HasPrefix(returnTo, protocolapi.PathAuthorize+"?") ||
		strings.Contains(returnTo, "https://") {
		t.Fatalf("return_to 必须是自己站内相对路径: %q", returnTo)
	}
}

// TestAuthorizeConsentAndTokenExchange 覆盖授权码 + PKCE 成功闭环，并用第三方
// JOSE 库从 /jwks 独立验证 ID Token 签名与声明（不是自签自验）。
func TestAuthorizeConsentAndTokenExchange(t *testing.T) {
	env := newTestEnv(t, nil)
	_, cookie := env.login(testUserAlice)
	scope := "openid profile email offline_access"
	resource := testIssuer
	nonce := "nonce-interop-1"

	values := authorizeValues(scope, resource, "opaque-state-123", nonce)
	// 同意页不得包含授权码或令牌；只包含服务端会话绑定的 CSRF 与确认编号。
	response, body := env.doRequest(http.MethodGet,
		protocolapi.PathAuthorize+"?"+values.Encode(), requestOptions{cookie: cookie})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("同意页状态 = %d", response.StatusCode)
	}
	if strings.Contains(string(body), "access_token") || strings.Contains(string(body), "id_token") {
		t.Fatal("同意页不得包含令牌字段")
	}
	if !strings.Contains(string(body), testClientPublic) {
		t.Fatal("同意页未展示受控 client_id")
	}
	page := consentPage{requestID: firstMatch(requestIDPattern, body),
		csrfToken: firstMatch(csrfTokenPattern, body)}
	if page.requestID == "" || page.csrfToken == "" {
		t.Fatalf("同意页缺少隐藏字段: %s", body)
	}
	if count := env.queryInt(`SELECT COUNT(*) FROM oauth_authorization_codes`); count != 0 {
		t.Fatalf("仅展示同意页就签发了授权码（自动批准）: %d", count)
	}

	approved := env.submitConsent(cookie, page, "approve")
	query := redirectValues(t, approved)
	code := query.Get("code")
	if code == "" || query.Get("state") != "opaque-state-123" {
		t.Fatalf("授权重定向参数异常: %v", query)
	}
	tokenResponse, tokenPayload := env.exchangeCode(code, testPKCEVerifier)
	if tokenResponse.StatusCode != http.StatusOK {
		t.Fatalf("兑换状态 = %d: %v", tokenResponse.StatusCode, tokenPayload)
	}
	if cache := tokenResponse.Header.Get("Cache-Control"); !strings.Contains(cache, "no-store") {
		t.Fatalf("令牌响应 Cache-Control = %q", cache)
	}
	accessToken, _ := tokenPayload["access_token"].(string)
	idTokenRaw, _ := tokenPayload["id_token"].(string)
	refreshToken, _ := tokenPayload["refresh_token"].(string)
	if accessToken == "" || idTokenRaw == "" || refreshToken == "" {
		t.Fatalf("令牌响应缺少字段: %v", tokenPayload)
	}
	if tokenPayload["token_type"] != "Bearer" {
		t.Fatalf("token_type = %v", tokenPayload["token_type"])
	}
	if expiresIn, _ := tokenPayload["expires_in"].(float64); expiresIn <= 0 {
		t.Fatalf("expires_in = %v", tokenPayload["expires_in"])
	}
	if scopeText, _ := tokenPayload["scope"].(string); !strings.Contains(scopeText, "openid") {
		t.Fatalf("scope = %v", tokenPayload["scope"])
	}

	// 第三方 JOSE 库从本进程发布的 JWKS 独立验签并核对声明。
	claims := verifyIDTokenWithJWKS(t, env, idTokenRaw, testClientPublic)
	if claims.Issuer != testIssuer || claims.Audience != testClientPublic {
		t.Fatalf("ID Token iss/aud = %q/%q", claims.Issuer, claims.Audience)
	}
	if claims.Nonce != nonce || claims.Subject == "" || claims.AuthTime == 0 {
		t.Fatalf("ID Token 声明异常: %+v", claims)
	}
	if len(claims.AMR) == 0 || claims.ACR == "" {
		t.Fatalf("ID Token 缺少 amr/acr: %+v", claims)
	}
	expectedSubject, err := env.oidc.Subject(testClientPublic, testUserAlice)
	if err != nil {
		t.Fatalf("计算 pairwise subject 失败: %v", err)
	}
	if claims.Subject != expectedSubject {
		t.Fatalf("ID Token sub 不是按客户端配对假名: %q", claims.Subject)
	}

	// 授权码一次性：重放必须被拒绝。
	replay, replayPayload := env.exchangeCode(code, testPKCEVerifier)
	if replay.StatusCode != http.StatusBadRequest || replayPayload["error"] != "invalid_grant" {
		t.Fatalf("授权码重放未被拒绝: %d %v", replay.StatusCode, replayPayload)
	}
	if env.countAudit("oauth.token.exchanged") < 1 {
		t.Fatal("缺少令牌兑换成功审计")
	}
	if env.countAudit("oauth.token.exchange_denied") < 1 {
		t.Fatal("缺少令牌兑换拒绝审计")
	}
}

// idTokenClaims 是测试侧独立解析的 ID Token 声明（不从服务端内部类型断言）。
type idTokenClaims struct {
	Issuer   string   `json:"iss"`
	Audience string   `json:"aud"`
	Subject  string   `json:"sub"`
	Nonce    string   `json:"nonce"`
	AuthTime int64    `json:"auth_time"`
	AMR      []string `json:"amr"`
	ACR      string   `json:"acr"`
}

// verifyIDTokenWithJWKS 通过 HTTP 获取 /jwks 并用 go-jose 独立验签（模拟标准
// 客户端行为；不调用本模块的 VerifyIDToken，避免自签自验）。
func verifyIDTokenWithJWKS(t *testing.T, env *testEnv, rawToken, clientID string) idTokenClaims {
	t.Helper()
	response, body := env.doRequest(http.MethodGet, protocolapi.PathJWKS, requestOptions{})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("JWKS 状态 = %d", response.StatusCode)
	}
	var keySet jose.JSONWebKeySet
	if err := json.Unmarshal(body, &keySet); err != nil {
		t.Fatalf("解析 JWKS 失败: %v", err)
	}
	parsed, err := jose.ParseSigned(rawToken, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("解析 ID Token JWS 失败: %v", err)
	}
	if len(parsed.Signatures) != 1 {
		t.Fatalf("ID Token 签名数量 = %d", len(parsed.Signatures))
	}
	keys := keySet.Key(parsed.Signatures[0].Header.KeyID)
	if len(keys) == 0 {
		t.Fatalf("JWKS 缺少 kid=%q", parsed.Signatures[0].Header.KeyID)
	}
	claimsBody, err := parsed.Verify(keys[0].Key)
	if err != nil {
		t.Fatalf("ID Token JWKS 验签失败: %v", err)
	}
	var claims idTokenClaims
	if err := json.Unmarshal(claimsBody, &claims); err != nil {
		t.Fatalf("解析 ID Token 声明失败: %v", err)
	}
	if claims.Audience != clientID {
		t.Fatalf("ID Token aud = %q", claims.Audience)
	}
	return claims
}

// TestWrongPKCEVerifierRejected 验证错误 code_verifier 被拒绝且不破坏已签发的码。
func TestWrongPKCEVerifierRejected(t *testing.T) {
	env := newTestEnv(t, nil)
	_, cookie := env.login(testUserAlice)
	code, _ := env.obtainAuthorizationCode(cookie, "openid", testIssuer, "state-pkce", "nonce-pkce")
	wrongVerifier := strings.Repeat("A", 43)
	response, payload := env.exchangeCode(code, wrongVerifier)
	if response.StatusCode != http.StatusBadRequest || payload["error"] != "invalid_grant" {
		t.Fatalf("错误 verifier 未被拒绝: %d %v", response.StatusCode, payload)
	}
	if env.countAudit("oauth.token.exchange_denied") < 1 {
		t.Fatal("缺少 PKCE 失败审计")
	}

	// 授权码绑定精确 redirect_uri：换成另一个（即使同客户端登记的）地址也必须拒绝。
	boundCode, _ := env.obtainAuthorizationCode(cookie, "openid", testIssuer,
		"state-binding", "nonce-binding")
	wrongRedirect := exchangeForm(boundCode, testPKCEVerifier)
	wrongRedirect.Set("redirect_uri", "https://client.example.test/other-callback")
	response, body := env.doRequest(http.MethodPost, protocolapi.PathToken,
		requestOptions{form: wrongRedirect})
	if response.StatusCode != http.StatusBadRequest || env.decodeJSON(body)["error"] != "invalid_grant" {
		t.Fatalf("回调绑定不匹配未被拒绝: %d %s", response.StatusCode, body)
	}

	// 授权码绑定 client：换另一个客户端兑换同样拒绝。
	clientBoundCode, _ := env.obtainAuthorizationCode(cookie, "openid", testIssuer,
		"state-client-binding", "nonce-client-binding")
	otherClient := exchangeForm(clientBoundCode, testPKCEVerifier)
	otherClient.Set("client_id", testClientPublic2)
	response, body = env.doRequest(http.MethodPost, protocolapi.PathToken,
		requestOptions{form: otherClient})
	if response.StatusCode != http.StatusBadRequest || env.decodeJSON(body)["error"] != "invalid_grant" {
		t.Fatalf("客户端绑定不匹配未被拒绝: %d %s", response.StatusCode, body)
	}

	// 不支持的 grant_type（password/implicit 在项目范围内被禁止）。
	response, body = env.doRequest(http.MethodPost, protocolapi.PathToken,
		requestOptions{form: url.Values{"grant_type": {"password"},
			"client_id": {testClientPublic}, "username": {"alice"}, "password": {"secret"}}})
	if response.StatusCode != http.StatusBadRequest ||
		env.decodeJSON(body)["error"] != "unsupported_grant_type" {
		t.Fatalf("password grant 未被拒绝: %d %s", response.StatusCode, body)
	}
}

// TestAuthorizeProtocolErrors 覆盖开放重定向防护、PKCE 强制、CSRF 与拒绝路径。
func TestAuthorizeProtocolErrors(t *testing.T) {
	env := newTestEnv(t, nil)
	_, cookie := env.login(testUserAlice)
	base := authorizeValues("openid", testIssuer, "state-err", "nonce-err")

	t.Run("无效 redirect_uri 不重定向", func(t *testing.T) {
		values := cloneValues(base)
		values.Set("redirect_uri", "https://evil.example.test/callback")
		response, body := env.doRequest(http.MethodGet,
			protocolapi.PathAuthorize+"?"+values.Encode(), requestOptions{cookie: cookie})
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("状态 = %d: %s", response.StatusCode, body)
		}
		if location := response.Header.Get("Location"); location != "" {
			t.Fatalf("无效回调不得重定向: %s", location)
		}
		payload := env.decodeJSON(body)
		if payload["error"] != "invalid_request" {
			t.Fatalf("error = %v", payload["error"])
		}
	})

	t.Run("未知 client 不重定向", func(t *testing.T) {
		values := cloneValues(base)
		values.Set("client_id", "app_00000000000000000000000000000099")
		response, body := env.doRequest(http.MethodGet,
			protocolapi.PathAuthorize+"?"+values.Encode(), requestOptions{cookie: cookie})
		if response.StatusCode != http.StatusUnauthorized ||
			env.decodeJSON(body)["error"] != "invalid_client" {
			t.Fatalf("未知 client 未被拒绝: %d %s", response.StatusCode, body)
		}
		if location := response.Header.Get("Location"); location != "" {
			t.Fatalf("未知 client 不得重定向: %s", location)
		}
	})

	t.Run("response_type 只支持 code", func(t *testing.T) {
		values := cloneValues(base)
		values.Set("response_type", "token")
		response, _ := env.doRequest(http.MethodGet,
			protocolapi.PathAuthorize+"?"+values.Encode(), requestOptions{cookie: cookie})
		query := redirectValues(t, response)
		if query.Get("error") != "unsupported_response_type" {
			t.Fatalf("error = %v", query)
		}
		if query.Get("state") != "state-err" {
			t.Fatalf("state 未原样回传: %v", query)
		}
	})

	t.Run("拒绝 PKCE plain", func(t *testing.T) {
		values := cloneValues(base)
		values.Set("code_challenge_method", "plain")
		response, _ := env.doRequest(http.MethodGet,
			protocolapi.PathAuthorize+"?"+values.Encode(), requestOptions{cookie: cookie})
		query := redirectValues(t, response)
		if query.Get("error") != "invalid_request" {
			t.Fatalf("error = %v", query)
		}
		if !strings.Contains(query.Get("error_description"), "PKCE") {
			t.Fatalf("error_description = %q", query.Get("error_description"))
		}
	})

	t.Run("缺失 PKCE 拒绝", func(t *testing.T) {
		values := cloneValues(base)
		values.Del("code_challenge")
		values.Del("code_challenge_method")
		response, _ := env.doRequest(http.MethodGet,
			protocolapi.PathAuthorize+"?"+values.Encode(), requestOptions{cookie: cookie})
		query := redirectValues(t, response)
		if query.Get("error") != "invalid_request" {
			t.Fatalf("error = %v", query)
		}
	})

	t.Run("重复参数拒绝", func(t *testing.T) {
		target := protocolapi.PathAuthorize + "?" + base.Encode() + "&client_id=" + testClientPublic
		response, body := env.doRequest(http.MethodGet, target, requestOptions{cookie: cookie})
		if response.StatusCode != http.StatusBadRequest ||
			env.decodeJSON(body)["error"] != "invalid_request" {
			t.Fatalf("重复 client_id 未拒绝: %d %s", response.StatusCode, body)
		}
	})

	t.Run("缺少 CSRF 拒绝", func(t *testing.T) {
		page := env.beginConsent(cookie, base)
		response, body := env.doRequest(http.MethodPost, protocolapi.PathAuthorize,
			requestOptions{cookie: cookie, form: url.Values{
				"request_id": {page.requestID}, "decision": {"approve"},
			}, header: map[string]string{"Origin": testIssuer}})
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("状态 = %d: %s", response.StatusCode, body)
		}
	})

	t.Run("跨源提交拒绝", func(t *testing.T) {
		page := env.beginConsent(cookie, base)
		response, body := env.doRequest(http.MethodPost, protocolapi.PathAuthorize,
			requestOptions{cookie: cookie, form: url.Values{
				"request_id": {page.requestID}, "csrf_token": {page.csrfToken},
				"decision": {"approve"},
			}, header: map[string]string{"Origin": "https://evil.example.test"}})
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("跨源提交状态 = %d: %s", response.StatusCode, body)
		}
	})

	t.Run("缺少来源头拒绝（状态修改 fail-closed）", func(t *testing.T) {
		page := env.beginConsent(cookie, base)
		response, body := env.doRequest(http.MethodPost, protocolapi.PathAuthorize,
			requestOptions{cookie: cookie, form: url.Values{
				"request_id": {page.requestID}, "csrf_token": {page.csrfToken},
				"decision": {"approve"},
			}})
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("缺少来源头的状态修改状态 = %d: %s", response.StatusCode, body)
		}
	})

	t.Run("拒绝授权返回 access_denied", func(t *testing.T) {
		page := env.beginConsent(cookie, base)
		response := env.submitConsent(cookie, page, "deny")
		query := redirectValues(t, response)
		if query.Get("error") != "access_denied" || query.Get("state") != "state-err" {
			t.Fatalf("拒绝授权参数 = %v", query)
		}
	})
}

// TestTokenEndpointClientAuthentication 覆盖 client_credentials 的 Basic/Post 认证、
// 错误密钥与公开客户端越权。
func TestTokenEndpointClientAuthentication(t *testing.T) {
	env := newTestEnv(t, nil)
	secret := env.clientSecrets[testClientService]
	if secret == "" {
		t.Fatal("缺少保密客户端密钥")
	}
	credentials := func() url.Values {
		return url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {testClientService},
			"client_secret": {secret},
			"scope":         {"service.read"},
			"resource":      {testResourceAPI},
		}
	}
	response, body := env.doRequest(http.MethodPost, protocolapi.PathToken,
		requestOptions{form: credentials()})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("client_credentials 状态 = %d: %s", response.StatusCode, body)
	}
	payload := env.decodeJSON(body)
	if tokenValue, _ := payload["access_token"].(string); tokenValue == "" {
		t.Fatalf("缺少 access_token: %v", payload)
	}
	if _, exists := payload["refresh_token"]; exists {
		t.Fatal("client_credentials 不得签发刷新令牌")
	}
	if _, exists := payload["id_token"]; exists {
		t.Fatal("client_credentials 不得签发 ID Token")
	}

	// Basic 认证（RFC 6749 要求 form-urlencoding 后再 base64）。
	basic := base64.StdEncoding.EncodeToString([]byte(
		url.QueryEscape(testClientService) + ":" + url.QueryEscape(secret)))
	basicForm := url.Values{"grant_type": {"client_credentials"},
		"scope": {"service.read"}, "resource": {testResourceAPI}}
	response, body = env.doRequest(http.MethodPost, protocolapi.PathToken,
		requestOptions{form: basicForm,
			header: map[string]string{"Authorization": "Basic " + basic}})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Basic 认证状态 = %d: %s", response.StatusCode, body)
	}

	// 错误密钥。
	wrong := credentials()
	wrong.Set("client_secret", "wrong-secret")
	response, body = env.doRequest(http.MethodPost, protocolapi.PathToken,
		requestOptions{form: wrong})
	if response.StatusCode != http.StatusUnauthorized ||
		env.decodeJSON(body)["error"] != "invalid_client" {
		t.Fatalf("错误密钥未被拒绝: %d %s", response.StatusCode, body)
	}
	if challenge := response.Header.Get("WWW-Authenticate"); challenge == "" {
		t.Log("错误密钥响应未附带 WWW-Authenticate（表单认证时非必须）")
	}

	// 公开客户端不能使用 client_credentials。
	response, body = env.doRequest(http.MethodPost, protocolapi.PathToken,
		requestOptions{form: url.Values{
			"grant_type": {"client_credentials"}, "client_id": {testClientPublic},
			"scope": {"openid"}, "resource": {testResourceAPI},
		}})
	if response.StatusCode != http.StatusBadRequest ||
		env.decodeJSON(body)["error"] != "unauthorized_client" {
		t.Fatalf("公开客户端 client_credentials 未被拒绝: %d %s", response.StatusCode, body)
	}

	// 同时使用 Basic 与表单密钥：重复认证方式拒绝。
	mixed := credentials()
	response, body = env.doRequest(http.MethodPost, protocolapi.PathToken,
		requestOptions{form: mixed,
			header: map[string]string{"Authorization": "Basic " + basic}})
	if response.StatusCode != http.StatusBadRequest ||
		env.decodeJSON(body)["error"] != "invalid_request" {
		t.Fatalf("混合认证方式未被拒绝: %d %s", response.StatusCode, body)
	}

	// 非表单 Content-Type 拒绝。
	response, body = env.doRequest(http.MethodPost, protocolapi.PathToken,
		requestOptions{json: map[string]string{"grant_type": "client_credentials"}})
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("JSON 令牌请求状态 = %d: %s", response.StatusCode, body)
	}
}

// TestRefreshRotationAndReplay 覆盖刷新令牌轮换与重放撤销整族。
func TestRefreshRotationAndReplay(t *testing.T) {
	env := newTestEnv(t, nil)
	_, cookie := env.login(testUserAlice)
	payload := env.issueCodeTokens(cookie, "openid offline_access", testResourceAPI, "nonce-refresh")
	firstRefresh, _ := payload["refresh_token"].(string)
	if firstRefresh == "" {
		t.Fatalf("授权码流程未签发刷新令牌: %v", payload)
	}
	refreshForm := func(refreshToken string) url.Values {
		return url.Values{"grant_type": {"refresh_token"},
			"refresh_token": {refreshToken}, "client_id": {testClientPublic}}
	}
	response, body := env.doRequest(http.MethodPost, protocolapi.PathToken,
		requestOptions{form: refreshForm(firstRefresh)})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("刷新状态 = %d: %s", response.StatusCode, body)
	}
	refreshed := env.decodeJSON(body)
	secondRefresh, _ := refreshed["refresh_token"].(string)
	if secondRefresh == "" || secondRefresh == firstRefresh {
		t.Fatalf("刷新令牌未轮换: %v", refreshed)
	}
	if accessToken, _ := refreshed["access_token"].(string); accessToken == "" {
		t.Fatalf("刷新未返回访问令牌: %v", refreshed)
	}
	// 旧刷新令牌重放：拒绝并撤销整族。
	replay, body := env.doRequest(http.MethodPost, protocolapi.PathToken,
		requestOptions{form: refreshForm(firstRefresh)})
	if replay.StatusCode != http.StatusBadRequest || env.decodeJSON(body)["error"] != "invalid_grant" {
		t.Fatalf("刷新令牌重放未被拒绝: %d %s", replay.StatusCode, body)
	}
	// 重放后新刷新令牌也必须失效（整族撤销）。
	afterReplay, body := env.doRequest(http.MethodPost, protocolapi.PathToken,
		requestOptions{form: refreshForm(secondRefresh)})
	if afterReplay.StatusCode != http.StatusBadRequest ||
		env.decodeJSON(body)["error"] != "invalid_grant" {
		t.Fatalf("重放后整族未撤销: %d %s", afterReplay.StatusCode, body)
	}
	if env.countAudit("oauth.refresh.family_revoked") < 1 {
		t.Fatal("缺少刷新族撤销审计")
	}
}

// TestUserInfoScopeAndRevocation 覆盖 UserInfo 作用域裁剪、令牌类型混用与在线撤销。
func TestUserInfoScopeAndRevocation(t *testing.T) {
	env := newTestEnv(t, nil)
	_, cookie := env.login(testUserAlice)
	payload := env.issueCodeTokens(cookie, "openid profile email", testIssuer, "nonce-userinfo")
	accessToken, _ := payload["access_token"].(string)
	idToken, _ := payload["id_token"].(string)
	if accessToken == "" || idToken == "" {
		t.Fatalf("令牌缺失: %v", payload)
	}
	userInfo := func(tokenValue string) (*http.Response, map[string]any) {
		response, body := env.doRequest(http.MethodGet, protocolapi.PathUserInfo,
			requestOptions{header: map[string]string{"Authorization": "Bearer " + tokenValue}})
		var decoded map[string]any
		_ = json.Unmarshal(body, &decoded)
		return response, decoded
	}
	response, info := userInfo(accessToken)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("UserInfo 状态 = %d: %v", response.StatusCode, info)
	}
	expectedSubject, err := env.oidc.Subject(testClientPublic, testUserAlice)
	if err != nil {
		t.Fatalf("计算 subject 失败: %v", err)
	}
	if info["sub"] != expectedSubject {
		t.Fatalf("UserInfo sub = %v", info["sub"])
	}
	if info["name"] != "Alice" || info["preferred_username"] != "alice" {
		t.Fatalf("profile 字段异常: %v", info)
	}
	if info["email"] != "alice@example.test" || info["email_verified"] != true {
		t.Fatalf("email 字段异常: %v", info)
	}
	for _, forbidden := range []string{"password", "mfa", "session", "recovery"} {
		if _, exists := info[forbidden]; exists {
			t.Fatalf("UserInfo 泄露字段 %q", forbidden)
		}
	}

	// ID Token 不能冒充 Access Token。
	response, info = userInfo(idToken)
	if response.StatusCode != http.StatusUnauthorized || info["error"] != "invalid_token" {
		t.Fatalf("ID Token 冒充访问令牌未被拒绝: %d %v", response.StatusCode, info)
	}
	// 缺少令牌。
	response, _ = env.doRequest(http.MethodGet, protocolapi.PathUserInfo, requestOptions{})
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("缺少令牌状态 = %d", response.StatusCode)
	}
	if !strings.HasPrefix(response.Header.Get("WWW-Authenticate"), "Bearer") {
		t.Fatalf("WWW-Authenticate = %q", response.Header.Get("WWW-Authenticate"))
	}
	// 令牌放查询串：明确拒绝，避免进入 URL/日志。
	response, body := env.doRequest(http.MethodGet,
		protocolapi.PathUserInfo+"?access_token="+url.QueryEscape(accessToken), requestOptions{})
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("查询串令牌未被拒绝: %d %s", response.StatusCode, body)
	}

	// 只声明 openid scope 的令牌只能拿到 sub，profile/email 字段被裁剪。
	trimmed := env.issueCodeTokens(cookie, "openid", testIssuer, "nonce-trimmed")
	trimmedToken, _ := trimmed["access_token"].(string)
	response, trimmedInfo := userInfo(trimmedToken)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("openid-only UserInfo 状态 = %d: %v", response.StatusCode, trimmedInfo)
	}
	if _, exists := trimmedInfo["name"]; exists {
		t.Fatalf("缺少 profile scope 却返回 name: %v", trimmedInfo)
	}
	if _, exists := trimmedInfo["email"]; exists {
		t.Fatalf("缺少 email scope 却返回 email: %v", trimmedInfo)
	}
	if trimmedInfo["sub"] == nil || trimmedInfo["sub"] == "" {
		t.Fatalf("openid-only UserInfo 缺少 sub: %v", trimmedInfo)
	}
	// audience 不是 UserInfo 资源的访问令牌被拒绝（令牌接收方校验）。
	wrongAudience := env.issueCodeTokens(cookie, "openid profile", testResourceAPI,
		"nonce-wrong-audience")
	wrongAudienceToken, _ := wrongAudience["access_token"].(string)
	response, wrongInfo := userInfo(wrongAudienceToken)
	if response.StatusCode != http.StatusUnauthorized || wrongInfo["error"] != "invalid_token" {
		t.Fatalf("错误 audience 的令牌未拒绝: %d %v", response.StatusCode, wrongInfo)
	}

	// 撤销访问令牌后 UserInfo 立即拒绝（在线撤销检查）。
	response, body = env.doRequest(http.MethodPost, protocolapi.PathRevoke,
		requestOptions{form: url.Values{"token": {accessToken},
			"client_id": {testClientPublic}}})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("撤销状态 = %d: %s", response.StatusCode, body)
	}
	response, info = userInfo(accessToken)
	if response.StatusCode != http.StatusUnauthorized || info["error"] != "invalid_token" {
		t.Fatalf("撤销后 UserInfo 未拒绝: %d %v", response.StatusCode, info)
	}
	if env.countAudit("oauth.access_token.revoked") < 1 {
		t.Fatal("缺少访问令牌撤销审计")
	}
}

// TestIntrospection 覆盖 RFC 7662 状态查询的认证、披露裁剪与不枚举语义。
func TestIntrospection(t *testing.T) {
	env := newTestEnv(t, nil)
	_, cookie := env.login(testUserAlice)
	payload := env.issueCodeTokens(cookie, "openid profile offline_access",
		testResourceAPI, "nonce-introspect")
	accessToken, _ := payload["access_token"].(string)
	refreshToken, _ := payload["refresh_token"].(string)
	if accessToken == "" || refreshToken == "" {
		t.Fatalf("令牌缺失: %v", payload)
	}
	secret := env.clientSecrets[testClientService]
	introspect := func(form url.Values) (*http.Response, map[string]any) {
		response, body := env.doRequest(http.MethodPost, protocolapi.PathIntrospect,
			requestOptions{form: form})
		var decoded map[string]any
		_ = json.Unmarshal(body, &decoded)
		return response, decoded
	}
	form := func(tokenValue string) url.Values {
		return url.Values{"token": {tokenValue}, "audience": {testResourceAPI},
			"client_id": {testClientService}, "client_secret": {secret}}
	}
	response, inspection := introspect(form(accessToken))
	if response.StatusCode != http.StatusOK || inspection["active"] != true {
		t.Fatalf("状态查询失败: %d %v", response.StatusCode, inspection)
	}
	if inspection["client_id"] != testClientPublic ||
		!strings.Contains(fmt.Sprint(inspection["scope"]), "openid") {
		t.Fatalf("状态查询披露异常: %v", inspection)
	}
	if inspection["token_type"] != "access_token" {
		t.Fatalf("token_type = %v", inspection["token_type"])
	}
	// 未知令牌 active=false 且不泄露原因。
	response, inspection = introspect(form("not-a-real-token"))
	if response.StatusCode != http.StatusOK || inspection["active"] != false {
		t.Fatalf("未知令牌状态 = %d %v", response.StatusCode, inspection)
	}
	// 未完成客户端认证。
	unauthenticated := url.Values{"token": {accessToken},
		"client_id": {testClientService}, "audience": {testResourceAPI}}
	response, body := env.doRequest(http.MethodPost, protocolapi.PathIntrospect,
		requestOptions{form: unauthenticated})
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("未认证状态查询状态 = %d: %s", response.StatusCode, body)
	}
	// 刷新令牌元数据查询（只返回族信息，不泄露用户主体以外的秘密）。
	refreshInspection, inspection := introspect(url.Values{"token": {refreshToken},
		"token_type_hint": {"refresh_token"}, "audience": {testResourceAPI},
		"client_id": {testClientService}, "client_secret": {secret}})
	if refreshInspection.StatusCode != http.StatusOK || inspection["active"] != true {
		t.Fatalf("刷新令牌状态查询 = %d %v", refreshInspection.StatusCode, inspection)
	}
	if inspection["token_type"] != "refresh_token" {
		t.Fatalf("刷新令牌 token_type = %v", inspection["token_type"])
	}
	// 撤销刷新令牌后状态查询 active=false。
	response, body = env.doRequest(http.MethodPost, protocolapi.PathRevoke,
		requestOptions{form: url.Values{"token": {refreshToken},
			"token_type_hint": {"refresh_token"}, "client_id": {testClientPublic}}})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("撤销刷新令牌状态 = %d: %s", response.StatusCode, body)
	}
	_, inspection = introspect(url.Values{"token": {refreshToken},
		"token_type_hint": {"refresh_token"}, "audience": {testResourceAPI},
		"client_id": {testClientService}, "client_secret": {secret}})
	if inspection["active"] != false {
		t.Fatalf("撤销后刷新令牌仍 active: %v", inspection)
	}
}

// TestResponseAndAuditDoNotLeakSecrets 验证运行日志与审计明细不含令牌/授权码/
// 设备码/客户端密钥等秘密。
func TestResponseAndAuditDoNotLeakSecrets(t *testing.T) {
	env := newTestEnv(t, nil)
	_, cookie := env.login(testUserAlice)
	code, _ := env.obtainAuthorizationCode(cookie, "openid offline_access",
		testIssuer, "state-leak", "nonce-leak")
	response, payload := env.exchangeCode(code, testPKCEVerifier)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("兑换失败: %v", payload)
	}
	accessToken, _ := payload["access_token"].(string)
	refreshToken, _ := payload["refresh_token"].(string)
	idToken, _ := payload["id_token"].(string)
	if accessToken == "" || refreshToken == "" || idToken == "" {
		t.Fatalf("令牌缺失: %v", payload)
	}
	clientSecret := env.clientSecrets[testClientService]
	logs := env.logs.String()
	secrets := []string{accessToken, refreshToken, idToken, code, clientSecret}
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		if strings.Contains(logs, secret) {
			t.Fatal("运行日志泄露了协议秘密")
		}
		for _, column := range []string{"detail_json", "error_code", "reason_code"} {
			query := fmt.Sprintf(
				`SELECT COUNT(*) FROM audit_events WHERE instr(%s, ?) > 0`, column)
			if env.queryInt(query, secret) != 0 {
				t.Fatalf("审计列 %s 泄露了协议秘密", column)
			}
		}
	}
}

// cloneValues 复制 url.Values（避免子测试互相影响）。
func cloneValues(values url.Values) url.Values {
	cloned := make(url.Values, len(values))
	for name, items := range values {
		cloned[name] = append([]string(nil), items...)
	}
	return cloned
}

// 编译期确认 session 包在测试中使用（会话 Cookie 类型断言）。
var _ = session.IssuedSession{}
