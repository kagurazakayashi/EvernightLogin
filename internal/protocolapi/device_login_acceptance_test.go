package protocolapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
	"github.com/kagurazakayashi/EvernightLogin/internal/protocolapi"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	"github.com/kagurazakayashi/EvernightLogin/internal/token"
	"github.com/kagurazakayashi/EvernightLogin/internal/uiauthadapter"
)

// 本文件是步骤 192 的设备码登录边界与重放验收。
//
// 证据来源：临时 SQLite（全量迁移）+ 真实会话/审计/OAuth 客户端/令牌/授权流程服务 +
// httptest 回环真实 HTTP 服务；设备端只通过 HTTP 端点申请/轮询/取消，不接触领域
// 服务内部状态。用户确认走**真实内置确认页面**（login.NewWebUI + 生产页面适配器
// uiauthadapter + 真实登录会话）：页面 HTML 由真实模板渲染真实应用名与 scope 说明，
// 批准/拒绝经页面处理器调用真实 oauthflow 决定接口。页面 POST 的传输层 CSRF/Origin
// 中间件由 serverapp 装配（步骤 160 已有真实页面证据），本测试聚焦页面数据与业务
// 决定路径；测试请求带真实会话 Cookie，不伪造身份。

// devicePageSessions 用真实会话服务实现内置页面框架的会话契约（只读服务端会话，
// 不接受任何客户端自报身份）。
type devicePageSessions struct{ service *session.Service }

// ResolvePageSession 实现 login.UISessionService。
func (p devicePageSessions) ResolvePageSession(ctx context.Context,
	request *http.Request) (login.UISession, error) {
	secret, ok := p.service.SessionSecretFromRequest(request)
	if !ok {
		return login.UISession{}, login.ErrUISessionExpired
	}
	record, err := p.service.Validate(ctx, secret)
	if err != nil {
		return login.UISession{}, login.ErrUISessionExpired
	}
	kind := "normal"
	if record.IsRestricted() {
		kind = "restricted"
	}
	return login.UISession{Authenticated: true, UserID: record.UserID, AppID: record.AppID,
		Kind: kind, ExpiresAt: record.AbsoluteExpiresAt}, nil
}

// IssueCSRFToken 实现 login.UISessionService：令牌只在服务端会话绑定下签发。
func (p devicePageSessions) IssueCSRFToken(ctx context.Context,
	request *http.Request) (string, error) {
	secret, ok := p.service.SessionSecretFromRequest(request)
	if !ok {
		return "", login.ErrUISessionExpired
	}
	token, err := p.service.IssuePageCSRFToken(ctx, secret)
	if err != nil {
		return "", login.ErrUISessionExpired
	}
	return token.Reveal(), nil
}

// loginWithRecentStrongAuth 以真实认证事实签发“已登录 + 近期强认证”会话，等价于
// 用户经登录页/两步验证完成登录后的浏览器会话。
func (e *testEnv) loginWithRecentStrongAuth(userID string) *http.Cookie {
	e.t.Helper()
	issued, err := e.sessions.Login(e.ctx, session.LoginRequest{
		Result: authn.AuthenticateResult{
			UserID: userID, Username: userNames[userID], Outcome: authn.OutcomeComplete,
			CompletedMethods: []authn.Method{authn.MethodPassword},
			CompletedAt:      e.clock.Now(), StrongAuthCompletedAt: e.clock.Now(),
			SecurityVersion: 1,
		},
		RequestID: "req_device_page_login_" + userID,
	})
	if err != nil {
		e.t.Fatalf("签发设备确认页会话失败: %v", err)
	}
	cookie, err := e.sessions.NewCookie(issued)
	if err != nil {
		e.t.Fatalf("构造设备确认页 Cookie 失败: %v", err)
	}
	return cookie
}

// devicePageServer 装配真实内置页面（真实模板 + 生产页面适配器 + 真实会话）。
func (e *testEnv) devicePageServer() *httptest.Server {
	e.t.Helper()
	backend, err := uiauthadapter.New(uiauthadapter.Options{
		Sessions: e.sessions, OAuth: e.flow,
		ApplicationNames: map[string]string{
			testClientDevice:  "设备码应用",
			testClientDevice2: "第二设备码应用",
		},
		Now: e.clock.Now,
	})
	if err != nil {
		e.t.Fatalf("构造设备确认页适配器失败: %v", err)
	}
	ui, err := login.NewWebUI(login.WebUIOptions{
		Prefix: "", Session: devicePageSessions{service: e.sessions},
		PageOAuth: &login.UIPageOAuthOptions{Backend: backend},
		Now:       e.clock.Now,
	})
	if err != nil {
		e.t.Fatalf("构造内置确认页面失败: %v", err)
	}
	server := httptest.NewServer(ui)
	e.t.Cleanup(server.Close)
	return server
}

// deviceBeginHTTP 以指定公开客户端申请设备授权（公开客户端只用 client_id，不带 secret）。
func (e *testEnv) deviceBeginHTTP(clientID string) map[string]any {
	e.t.Helper()
	response, body := e.doRequest(http.MethodPost, protocolapi.PathDeviceAuthorization,
		requestOptions{form: url.Values{"client_id": {clientID}, "scope": {"profile"}}})
	if response.StatusCode != http.StatusOK {
		e.t.Fatalf("设备授权申请状态 = %d: %s", response.StatusCode, body)
	}
	return e.decodeJSON(body)
}

// devicePollAs 以指定客户端轮询设备码。
func (e *testEnv) devicePollAs(clientID, deviceCode string) (*http.Response, map[string]any) {
	e.t.Helper()
	response, body := e.doRequest(http.MethodPost, protocolapi.PathToken,
		requestOptions{form: url.Values{
			"grant_type":  {protocolapi.DeviceCodeGrantType},
			"device_code": {deviceCode}, "client_id": {clientID},
		}})
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		e.t.Fatalf("设备码轮询响应不是 JSON: %v\n%s", err, body)
	}
	return response, payload
}

// pageRequest 向确认页面发送请求（带真实会话 Cookie 与表单）。
func pageRequest(t *testing.T, page *httptest.Server, method, path string,
	cookie *http.Cookie, form url.Values) (int, string) {
	t.Helper()
	var bodyReader *strings.Reader
	if form != nil {
		bodyReader = strings.NewReader(form.Encode())
	} else {
		bodyReader = strings.NewReader("")
	}
	request, err := http.NewRequest(method, page.URL+path, bodyReader)
	if err != nil {
		t.Fatalf("构造页面请求失败: %v", err)
	}
	if form != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	response, err := page.Client().Do(request)
	if err != nil {
		t.Fatalf("页面请求 %s %s 失败: %v", method, path, err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatalf("读取页面响应失败: %v", err)
	}
	return response.StatusCode, string(payload)
}

// TestDeviceCodeLoginAcceptance 覆盖步骤 192 判据：公共客户端全流程、pending、
// slow_down（含间隔递增）、确认页显示正确应用与 scope、批准领取、一次性消费、
// 错误客户端、用户拒绝、过期、取消与 Discovery 一致性。
func TestDeviceCodeLoginAcceptance(t *testing.T) {
	env := newTestEnv(t, nil)
	// 协议包与领域包的设备码 grant_type 必须同源，避免声明与实际不一致。
	if oauthflow.AccessTokenGrantDeviceCode != protocolapi.DeviceCodeGrantType {
		t.Fatalf("设备码 grant_type 常量不一致: %q vs %q",
			oauthflow.AccessTokenGrantDeviceCode, protocolapi.DeviceCodeGrantType)
	}

	// ===== Discovery 与实现一致：启用时声明真实设备授权端点与 grant_type =====
	discoveryResponse, discoveryBody := env.doRequest(http.MethodGet,
		protocolapi.PathDiscovery, requestOptions{})
	if discoveryResponse.StatusCode != http.StatusOK {
		t.Fatalf("Discovery 状态 = %d", discoveryResponse.StatusCode)
	}
	discovery := env.decodeJSON(discoveryBody)
	if endpoint, _ := discovery["device_authorization_endpoint"].(string); endpoint !=
		testIssuer+protocolapi.PathDeviceAuthorization {
		t.Fatalf("Discovery device_authorization_endpoint = %v", discovery["device_authorization_endpoint"])
	}
	if !containsText(discovery["grant_types_supported"], protocolapi.DeviceCodeGrantType) {
		t.Fatalf("Discovery grant_types_supported 缺少设备码: %v", discovery["grant_types_supported"])
	}

	// ===== 真实公开客户端申请（client_id 即可，不携带伪 secret） =====
	start := env.deviceBeginHTTP(testClientDevice)
	deviceCode, _ := start["device_code"].(string)
	userCode, _ := start["user_code"].(string)
	verificationURI, _ := start["verification_uri"].(string)
	verificationComplete, _ := start["verification_uri_complete"].(string)
	expiresIn, _ := start["expires_in"].(float64)
	interval, _ := start["interval"].(float64)
	if deviceCode == "" || userCode == "" {
		t.Fatalf("设备授权响应缺少 device_code/user_code: 字段缺失")
	}
	if verificationURI != testIssuer+"/device" {
		t.Fatalf("verification_uri = %q（应为配置的设备确认页）", verificationURI)
	}
	if !strings.Contains(verificationComplete, "user_code=") {
		t.Fatalf("verification_uri_complete 未携带短码: %q", verificationComplete)
	}
	if expiresIn <= 0 || interval < 1 {
		t.Fatalf("expires_in/interval 异常: %v/%v", start["expires_in"], start["interval"])
	}
	if env.countAudit("oauth.device.requested") < 1 {
		t.Fatal("缺少设备授权申请审计")
	}

	// ===== 授权待定：未确认前轮询 authorization_pending =====
	response, payload := env.devicePollAs(testClientDevice, deviceCode)
	if response.StatusCode != http.StatusBadRequest || payload["error"] != "authorization_pending" {
		t.Fatalf("未确认轮询 = %d %v", response.StatusCode, payload)
	}

	// ===== 过快轮询：slow_down + Retry-After，服务端强制增大间隔 =====
	response, payload = env.devicePollAs(testClientDevice, deviceCode)
	if response.StatusCode != http.StatusBadRequest || payload["error"] != "slow_down" {
		t.Fatalf("过快轮询 = %d %v", response.StatusCode, payload)
	}
	firstRetry, err := retryAfterSeconds(response)
	if err != nil {
		t.Fatalf("slow_down 响应缺少合法 Retry-After: %v", err)
	}
	// 间隔已增大：原间隔（>=5s）内再次轮询仍然 slow_down，且 Retry-After 不小于上次。
	env.clock.Advance(time.Duration(interval) * time.Second)
	response, payload = env.devicePollAs(testClientDevice, deviceCode)
	if response.StatusCode != http.StatusBadRequest || payload["error"] != "slow_down" {
		t.Fatalf("间隔增大后过早轮询 = %d %v", response.StatusCode, payload)
	}
	secondRetry, err := retryAfterSeconds(response)
	if err != nil {
		t.Fatalf("第二次 slow_down 缺少合法 Retry-After: %v", err)
	}
	if secondRetry <= firstRetry {
		t.Fatalf("slow_down 未增大轮询间隔: %d -> %d 秒", firstRetry, secondRetry)
	}

	// ===== 错误客户端不能领取（批准前后都拒绝，且不泄露归属） =====
	response, payload = env.devicePollAs(testClientDevice2, deviceCode)
	if response.StatusCode != http.StatusBadRequest || payload["error"] != "invalid_grant" {
		t.Fatalf("其他客户端提交设备码 = %d %v", response.StatusCode, payload)
	}

	// ===== 确认页显示正确应用与请求范围（真实模板 + 真实适配器 + 真实会话） =====
	cookie := env.loginWithRecentStrongAuth(testUserAlice)
	page := env.devicePageServer()
	status, verifyHTML := pageRequest(t, page, http.MethodGet,
		"/oauth/device?user_code="+url.QueryEscape(userCode), cookie, nil)
	if status != http.StatusOK || !strings.Contains(verifyHTML, `name="user_code"`) {
		t.Fatalf("设备确认入口页异常: %d", status)
	}
	status, confirmHTML := pageRequest(t, page, http.MethodPost, "/oauth/device", cookie,
		url.Values{"user_code": {userCode}})
	if status != http.StatusOK {
		t.Fatalf("设备确认页读取状态 = %d", status)
	}
	if !strings.Contains(confirmHTML, "设备码应用") ||
		!strings.Contains(confirmHTML, testClientDevice) {
		t.Fatal("确认页未显示正确的应用名称/应用标识")
	}
	if !strings.Contains(confirmHTML, "profile") ||
		!strings.Contains(confirmHTML, "读取你的公开资料") {
		t.Fatal("确认页未显示正确的请求范围（scope + 中文说明）")
	}
	if !strings.Contains(confirmHTML, userCode) {
		t.Fatal("确认页未显示用户输入的短码")
	}

	// ===== 批准（页面 POST 调用真实决定接口）后按新间隔领取令牌 =====
	status, approveHTML := pageRequest(t, page, http.MethodPost, "/oauth/device/confirm",
		cookie, url.Values{"user_code": {userCode}, "approve": {"true"}})
	if status != http.StatusOK {
		t.Fatalf("批准提交状态 = %d", status)
	}
	if strings.Contains(approveHTML, "ACCESS_DENIED") || strings.Contains(approveHTML, "REAUTH") {
		t.Fatalf("批准被拒绝: %s", truncateDetail(approveHTML))
	}
	// 轮询间隔已被 slow_down 增大，等待足够时间后领取（注入时钟，不长等）。
	env.clock.Advance(60 * time.Second)
	response, payload = env.devicePollAs(testClientDevice, deviceCode)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("批准后领取令牌 = %d %v", response.StatusCode, payload)
	}
	accessToken, _ := payload["access_token"].(string)
	if accessToken == "" || payload["token_type"] != "Bearer" {
		t.Fatalf("设备令牌响应异常")
	}
	if _, exists := payload["id_token"]; exists {
		t.Fatal("设备客户端未申请 openid，不应签发 ID Token")
	}
	if _, exists := payload["refresh_token"]; exists {
		t.Fatal("设备客户端未登记 refresh_token，不应签发刷新令牌")
	}
	claims, err := env.tokens.VerifyAccessToken(env.ctx, accessToken, testResourceAPI)
	if err != nil {
		t.Fatalf("设备令牌校验失败: %v", err)
	}
	if claims.TokenUse != token.TokenUseAccess || claims.ClientID != testClientDevice ||
		claims.Subject != testUserAlice || !strings.Contains(strings.Join(claims.Scopes, " "), "profile") {
		t.Fatalf("设备令牌声明异常: %+v", claims)
	}
	if env.countAudit("oauth.device.token_issued") < 1 {
		t.Fatal("缺少设备令牌签发审计")
	}

	// ===== 一次性消费：同一设备码重复兑换 invalid_grant =====
	response, payload = env.devicePollAs(testClientDevice, deviceCode)
	if response.StatusCode != http.StatusBadRequest || payload["error"] != "invalid_grant" {
		t.Fatalf("设备码重复兑换 = %d %v", response.StatusCode, payload)
	}

	// ===== 用户拒绝：确认为拒绝后轮询 access_denied =====
	deniedStart := env.deviceBeginHTTP(testClientDevice)
	deniedCode, _ := deniedStart["device_code"].(string)
	deniedUserCode, _ := deniedStart["user_code"].(string)
	status, _ = pageRequest(t, page, http.MethodPost, "/oauth/device/confirm", cookie,
		url.Values{"user_code": {deniedUserCode}, "approve": {"false"}})
	if status != http.StatusOK {
		t.Fatalf("拒绝提交状态 = %d", status)
	}
	response, payload = env.devicePollAs(testClientDevice, deniedCode)
	if response.StatusCode != http.StatusBadRequest || payload["error"] != "access_denied" {
		t.Fatalf("用户拒绝后轮询 = %d %v", response.StatusCode, payload)
	}

	// ===== 发起端取消：204，随后轮询 access_denied =====
	cancelStart := env.deviceBeginHTTP(testClientDevice)
	cancelCode, _ := cancelStart["device_code"].(string)
	cancelResponse, cancelBody := env.doRequest(http.MethodPost, protocolapi.PathDeviceCancel,
		requestOptions{form: url.Values{"device_code": {cancelCode},
			"client_id": {testClientDevice}}})
	if cancelResponse.StatusCode != http.StatusNoContent {
		t.Fatalf("设备取消状态 = %d: %s", cancelResponse.StatusCode, cancelBody)
	}
	response, payload = env.devicePollAs(testClientDevice, cancelCode)
	if response.StatusCode != http.StatusBadRequest || payload["error"] != "access_denied" {
		t.Fatalf("取消后轮询 = %d %v", response.StatusCode, payload)
	}

	// ===== 到期：设备码过期后轮询 expired_token（注入时钟，不长等） =====
	expiredStart := env.deviceBeginHTTP(testClientDevice)
	expiredCode, _ := expiredStart["device_code"].(string)
	env.clock.Advance(11 * time.Minute)
	response, payload = env.devicePollAs(testClientDevice, expiredCode)
	if response.StatusCode != http.StatusBadRequest || payload["error"] != "expired_token" {
		t.Fatalf("过期设备码轮询 = %d %v", response.StatusCode, payload)
	}

	// ===== Discovery 与实现一致：未启用设备码时不声明、端点 404 =====
	disabled := newTestEnv(t, func(options *protocolapi.Options) {
		options.EnableDeviceFlow = false
	})
	disabledDiscoveryResponse, disabledBody := disabled.doRequest(http.MethodGet,
		protocolapi.PathDiscovery, requestOptions{})
	if disabledDiscoveryResponse.StatusCode != http.StatusOK {
		t.Fatalf("禁用设备码时 Discovery 状态 = %d", disabledDiscoveryResponse.StatusCode)
	}
	disabledDocument := disabled.decodeJSON(disabledBody)
	if _, exists := disabledDocument["device_authorization_endpoint"]; exists {
		t.Fatalf("未启用设备码却声明 device_authorization_endpoint: %v",
			disabledDocument["device_authorization_endpoint"])
	}
	if containsText(disabledDocument["grant_types_supported"], protocolapi.DeviceCodeGrantType) {
		t.Fatal("未启用设备码却声明 device_code grant_type")
	}
	disabledResponse, disabledDeviceBody := disabled.doRequest(http.MethodPost,
		protocolapi.PathDeviceAuthorization,
		requestOptions{form: url.Values{"client_id": {testClientDevice}, "scope": {"profile"}}})
	if disabledResponse.StatusCode != http.StatusNotFound {
		t.Fatalf("未启用设备码时端点应 404，实际 %d: %s",
			disabledResponse.StatusCode, disabledDeviceBody)
	}

	// 错误响应必须是标准 OAuth 错误字段，不得是 5xx 或静默成功。
	if response.StatusCode >= 500 {
		t.Fatalf("设备码拒绝路径出现服务端错误: %d", response.StatusCode)
	}
}

// retryAfterSeconds 解析 Retry-After 秒数。
func retryAfterSeconds(response *http.Response) (int, error) {
	raw := strings.TrimSpace(response.Header.Get("Retry-After"))
	if raw == "" {
		return 0, fmt.Errorf("响应缺少 Retry-After")
	}
	seconds, err := strconv.Atoi(raw)
	if err != nil || seconds <= 0 || seconds > 3600 {
		return 0, fmt.Errorf("Retry-After 非法: %q", raw)
	}
	return seconds, nil
}

// containsText 判断 JSON 数组值中是否包含期望字符串。
func containsText(value any, want string) bool {
	items, ok := value.([]any)
	if !ok {
		return false
	}
	for _, item := range items {
		if text, ok := item.(string); ok && text == want {
			return true
		}
	}
	return false
}

// truncateDetail 截断页面正文用于失败诊断（页面不含令牌/秘密）。
func truncateDetail(body string) string {
	if len(body) <= 200 {
		return body
	}
	return body[:200]
}
