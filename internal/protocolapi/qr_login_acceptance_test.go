package protocolapi_test

import (
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/pagestate"
	"github.com/kagurazakayashi/EvernightLogin/internal/protocolapi"
	"github.com/kagurazakayashi/EvernightLogin/internal/qrlogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	"github.com/kagurazakayashi/EvernightLogin/internal/uiauthadapter"
	ui "github.com/kagurazakayashi/EvernightLogin/ui"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

// 本文件是步骤 193 的“已登录 APP 扫码确认与网页领取闭环”验收。
//
// 证据来源：临时 SQLite（全量迁移）+ 真实会话/审计应用/扫码/会话签发服务 +
// httptest 回环真实 HTTP 服务 + 真实内置网页（ui.NewWebUI + 生产页面适配器
// uiauthadapter + 真实登录会话）：
//   - 发起端是企业内网页匿名会话（只持有服务端签发的状态 Cookie，不登录）；
//   - 确认端是另一个独立的已登录 APP 会话（真实普通会话 + 近期强认证事实）；
//   - 二维码载荷只含一次性 request_id；领取绑定只保存在发起端签名状态 Cookie；
//   - 领取出的目标应用会话由真实 session 服务签发，归属确认者而不是发起端。
// 页面 POST 的传输层 CSRF/Origin 中间件由 serverapp 装配（步骤 160 已有真实页面
// 证据），本测试聚焦双会话分离、页面数据与业务决定/领取路径；协议直连则同时验证
// “Bearer 会话 + 同源 Origin”的合法调用方式（Cookie 会话必须额外通过 CSRF）。

var (
	qrRequestIDField = regexp.MustCompile(`name="request_id" value="([^"]+)"`)
	qrVersionField   = regexp.MustCompile(`name="expected_version" value="([^"]+)"`)
)

// qrPageServer 装配真实内置扫码页面（匿名发起页 + APP 确认页）与其生产适配器。
func (e *testEnv) qrPageServer() *httptest.Server {
	e.t.Helper()
	pageKeyring, err := secrets.GenerateKeyring("qr-page-k1", e.clock.Now())
	if err != nil {
		e.t.Fatalf("生成页面状态密钥环失败: %v", err)
	}
	pageState, err := pagestate.New(pagestate.Options{
		Keyring: pageKeyring, TTL: 15 * time.Minute, Now: e.clock.Now})
	if err != nil {
		e.t.Fatalf("构造页面状态编解码器失败: %v", err)
	}
	backend, err := uiauthadapter.New(uiauthadapter.Options{
		Sessions: e.sessions, QR: e.qr, QRClientID: testClientPublic,
		QRScopes: []string{"profile"}, PageState: pageState, Now: e.clock.Now,
	})
	if err != nil {
		e.t.Fatalf("构造扫码页面适配器失败: %v", err)
	}
	ui, err := ui.NewWebUI(ui.WebUIOptions{
		Prefix: "", Session: devicePageSessions{service: e.sessions},
		PageOAuth: &ui.UIPageOAuthOptions{Backend: backend},
		Now:       e.clock.Now,
	})
	if err != nil {
		e.t.Fatalf("构造内置扫码页面失败: %v", err)
	}
	server := httptest.NewServer(ui)
	e.t.Cleanup(server.Close)
	return server
}

// qrPageClient 是只做页面请求的 HTTP 客户端：不跟随重定向（需要检查 303 与
// Set-Cookie），Cookie 由调用方显式携带（状态 Cookie 带 Secure，本机 http 回环
// 测试需要手工回传，等价于浏览器在 https 下的行为）。
type qrPageClient struct {
	t    *testing.T
	base string
	http *http.Client
}

// newQRPageClient 构造页面客户端。
func newQRPageClient(t *testing.T, server *httptest.Server) *qrPageClient {
	t.Helper()
	return &qrPageClient{t: t, base: server.URL, http: &http.Client{
		Transport: server.Client().Transport, Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

// do 发送页面请求，返回状态码、正文与响应 Cookie。
func (c *qrPageClient) do(method, path string, cookie *http.Cookie,
	form url.Values) (int, string, []*http.Cookie) {
	c.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	request, err := http.NewRequest(method, c.base+path, body)
	if err != nil {
		c.t.Fatalf("构造页面请求失败: %v", err)
	}
	if form != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	response, err := c.http.Do(request)
	if err != nil {
		c.t.Fatalf("页面请求 %s %s 失败: %v", method, path, err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		c.t.Fatalf("读取页面响应失败: %v", err)
	}
	return response.StatusCode, string(payload), response.Cookies()
}

// loginWithStrongAuthSession 以真实认证事实签发普通会话（近期强认证），返回会话
// 秘密与浏览器 Cookie。
func (e *testEnv) loginWithStrongAuthSession(userID string) (session.IssuedSession, *http.Cookie) {
	e.t.Helper()
	issued, err := e.sessions.Login(e.ctx, session.LoginRequest{
		Result: authn.AuthenticateResult{
			UserID: userID, Username: userNames[userID], Outcome: authn.OutcomeComplete,
			CompletedMethods: []authn.Method{authn.MethodPassword},
			CompletedAt:      e.clock.Now(), StrongAuthCompletedAt: e.clock.Now(),
			SecurityVersion: 1,
		},
		RequestID: "req_qr_confirm_login_" + userID,
	})
	if err != nil {
		e.t.Fatalf("签发扫码确认端会话失败: %v", err)
	}
	cookie, err := e.sessions.NewCookie(issued)
	if err != nil {
		e.t.Fatalf("构造扫码确认端 Cookie 失败: %v", err)
	}
	return issued, cookie
}

// findStateCookie 从响应 Cookie 中取发起端签名状态 Cookie（ln_qr_state）。
func findStateCookie(cookies []*http.Cookie) *http.Cookie {
	for _, cookie := range cookies {
		if cookie != nil && cookie.Name == "ln_qr_state" && cookie.Value != "" {
			return cookie
		}
	}
	return nil
}

// findSessionCookie 从响应 Cookie 中找出可被真实会话服务校验的目标应用会话 Cookie。
func (e *testEnv) findSessionCookie(cookies []*http.Cookie) (*http.Cookie, session.Session) {
	e.t.Helper()
	for _, cookie := range cookies {
		if cookie == nil || cookie.Value == "" || cookie.Name == "ln_qr_state" {
			continue
		}
		if record, err := e.sessions.Validate(e.ctx, cookie.Value); err == nil {
			return cookie, record
		}
	}
	return nil, session.Session{}
}

// qrFieldValue 从页面隐藏字段取唯一值。
func qrFieldValue(pattern *regexp.Regexp, body string) string {
	match := pattern.FindStringSubmatch(body)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

// TestQRLoginPageAcceptance 覆盖步骤 193 判据：双会话网页扫码、确认前展示应用/
// 范围、仅原发起端领取、重复确认/领取、错误端抢领、拒绝/取消/过期语义、二维码
// 不含长期 Token，以及协议直连的合法调用方式。
func TestQRLoginPageAcceptance(t *testing.T) {
	env := newTestEnv(t, nil)
	page := env.qrPageServer()
	initiator := newQRPageClient(t, page)
	anonymous := newQRPageClient(t, page)
	confirmIssued, confirmCookie := env.loginWithStrongAuthSession(testUserBob)

	// ===== 1. 匿名发起端打开网页：创建请求、渲染二维码、只把领取绑定写入签名 Cookie =====
	status, initiatorHTML, initiatorCookies := initiator.do(http.MethodGet, "/login/qr", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("发起端页面状态 = %d", status)
	}
	requestID := qrFieldValue(qrRequestIDField, initiatorHTML)
	if requestID == "" {
		t.Fatal("发起端页面缺少 request_id")
	}
	if !strings.Contains(initiatorHTML, "ln-qr-wrap") {
		t.Fatal("发起端页面未渲染二维码区域")
	}
	stateCookie := findStateCookie(initiatorCookies)
	if stateCookie == nil {
		t.Fatal("发起端页面未下发签名状态 Cookie")
	}
	// 二维码/发起页不得包含领取绑定、会话秘密或任何长期 Token 字段。
	for _, forbidden := range []string{"claim_secret", "access_token", "refresh_token",
		"id_token", stateCookie.Value, confirmIssued.Secret.Reveal()} {
		if forbidden != "" && strings.Contains(initiatorHTML, forbidden) {
			t.Fatalf("发起端页面泄露秘密片段: %q", forbidden)
		}
	}

	// ===== 2. 未登录的另一个网页不能读取确认上下文（双会话分离） =====
	status, _, _ = anonymous.do(http.MethodGet, "/app/scan?request_id="+url.QueryEscape(requestID),
		nil, nil)
	if status < 400 {
		t.Fatalf("匿名确认端读取待确认请求未被拒绝: %d", status)
	}
	// 其它网页即使知道 request_id 也不能领取（无签名状态 Cookie）。
	status, _, stolenCookies := anonymous.do(http.MethodPost, "/login/qr/claim", nil, url.Values{})
	if status < 400 {
		t.Fatalf("其它网页抢领未被拒绝: %d", status)
	}
	if _, record := env.findSessionCookie(stolenCookies); record.UserID != "" {
		t.Fatal("其它网页抢领竟然取得有效会话")
	}

	// ===== 3. 已登录 APP 读取确认页：展示正确应用与请求范围 =====
	status, confirmHTML, _ := initiator.do(http.MethodGet,
		"/app/scan?request_id="+url.QueryEscape(requestID), confirmCookie, nil)
	if status != http.StatusOK {
		t.Fatalf("APP 确认页状态 = %d", status)
	}
	if !strings.Contains(confirmHTML, "协议演示应用") ||
		!strings.Contains(confirmHTML, testClientPublic) {
		t.Fatal("确认页未展示正确的应用名称/应用标识")
	}
	if !strings.Contains(confirmHTML, "profile") ||
		!strings.Contains(confirmHTML, "读取你的公开资料") {
		t.Fatal("确认页未展示正确的请求范围（scope + 中文说明）")
	}
	expectedVersion := qrFieldValue(qrVersionField, confirmHTML)
	if expectedVersion == "" {
		t.Fatal("确认页缺少请求版本号")
	}

	// ===== 4. 批准后同一请求不能被重复确认 =====
	status, _, _ = initiator.do(http.MethodPost, "/app/scan", confirmCookie,
		url.Values{"request_id": {requestID}, "expected_version": {expectedVersion},
			"approve": {"true"}})
	if status != http.StatusOK {
		t.Fatalf("APP 批准状态 = %d", status)
	}
	status, _, _ = initiator.do(http.MethodPost, "/app/scan", confirmCookie,
		url.Values{"request_id": {requestID}, "expected_version": {expectedVersion},
			"approve": {"true"}})
	if status < 400 {
		t.Fatalf("重复确认未被拒绝: %d", status)
	}

	// ===== 5. 原发起端轮询到 approved 并领取：签发确认者的目标应用会话 =====
	status, pollHTML, _ := initiator.do(http.MethodPost, "/login/qr/poll", stateCookie,
		url.Values{"request_id": {requestID}})
	if status != http.StatusOK || !strings.Contains(pollHTML, qrlogin.StatusApproved) {
		t.Fatalf("发起端轮询未看到 approved: %d", status)
	}
	status, _, claimCookies := initiator.do(http.MethodPost, "/login/qr/claim", stateCookie,
		url.Values{})
	if status != http.StatusSeeOther {
		t.Fatalf("发起端领取状态 = %d，期望 303", status)
	}
	claimedCookie, claimedSession := env.findSessionCookie(claimCookies)
	if claimedCookie == nil {
		t.Fatal("领取成功未签发目标应用会话 Cookie")
	}
	if claimedSession.UserID != testUserBob || claimedSession.AppID != testClientPublic {
		t.Fatalf("领取会话归属异常: user=%q app=%q", claimedSession.UserID, claimedSession.AppID)
	}
	if claimedCookie.Value == confirmCookie.Value {
		t.Fatal("领取出的目标应用会话不能复用确认端自己的会话 Cookie")
	}

	// ===== 6. 重复领取拒绝（同一发起端也不能二次领取） =====
	status, _, replayCookies := initiator.do(http.MethodPost, "/login/qr/claim", stateCookie,
		url.Values{})
	if status < 400 {
		t.Fatalf("重复领取未被拒绝: %d", status)
	}
	if _, record := env.findSessionCookie(replayCookies); record.UserID != "" {
		t.Fatal("重复领取竟然再次签发有效会话")
	}

	// ===== 7. 用户拒绝：确认页拒绝后发起端不能领取 =====
	status, denyHTML, denyCookies := initiator.do(http.MethodGet, "/login/qr", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("二次发起页状态 = %d", status)
	}
	denyRequestID := qrFieldValue(qrRequestIDField, denyHTML)
	denyState := findStateCookie(denyCookies)
	if denyRequestID == "" || denyState == nil {
		t.Fatal("二次发起缺少请求标识/状态 Cookie")
	}
	_, denyConfirmHTML, _ := initiator.do(http.MethodGet,
		"/app/scan?request_id="+url.QueryEscape(denyRequestID), confirmCookie, nil)
	denyVersion := qrFieldValue(qrVersionField, denyConfirmHTML)
	status, _, _ = initiator.do(http.MethodPost, "/app/scan", confirmCookie,
		url.Values{"request_id": {denyRequestID}, "expected_version": {denyVersion},
			"approve": {"false"}})
	if status != http.StatusOK {
		t.Fatalf("APP 拒绝状态 = %d", status)
	}
	status, denyPollHTML, _ := initiator.do(http.MethodPost, "/login/qr/poll", denyState,
		url.Values{})
	if status != http.StatusOK || !strings.Contains(denyPollHTML, qrlogin.StatusDenied) {
		t.Fatalf("拒绝后发起端状态 = %d（期望 denied）", status)
	}
	status, _, _ = initiator.do(http.MethodPost, "/login/qr/claim", denyState, url.Values{})
	if status < 400 {
		t.Fatalf("用户拒绝后仍能领取: %d", status)
	}

	// ===== 8. 发起端取消：状态 cancelled，领取被拒绝 =====
	status, cancelHTML, cancelCookies := initiator.do(http.MethodGet, "/login/qr", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("三次发起页状态 = %d", status)
	}
	cancelState := findStateCookie(cancelCookies)
	if cancelState == nil {
		t.Fatal("三次发起缺少状态 Cookie")
	}
	status, cancelPage, _ := initiator.do(http.MethodPost, "/login/qr/cancel", cancelState,
		url.Values{})
	if status != http.StatusOK || !strings.Contains(cancelPage, qrlogin.StatusCancelled) {
		t.Fatalf("取消后状态 = %d（期望 cancelled）", status)
	}
	status, _, _ = initiator.do(http.MethodPost, "/login/qr/claim", cancelState, url.Values{})
	if status < 400 {
		t.Fatalf("取消后仍能领取: %d", status)
	}
	_ = cancelHTML

	// ===== 9. 过期：超过请求有效期后轮询为 expired，领取被拒绝（注入时钟，不长等） =====
	status, expireHTML, expireCookies := initiator.do(http.MethodGet, "/login/qr", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("过期用例发起页状态 = %d", status)
	}
	_ = expireHTML
	expireState := findStateCookie(expireCookies)
	if expireState == nil {
		t.Fatal("过期用例缺少状态 Cookie")
	}
	env.clock.Advance(3 * time.Minute)
	status, expiredPage, _ := initiator.do(http.MethodPost, "/login/qr/poll", expireState,
		url.Values{})
	if status != http.StatusOK || !strings.Contains(expiredPage, qrlogin.QueryExpired) {
		t.Fatalf("过期后轮询状态 = %d（期望 expired）", status)
	}
	status, _, _ = initiator.do(http.MethodPost, "/login/qr/claim", expireState, url.Values{})
	if status < 400 {
		t.Fatalf("过期后仍能领取: %d", status)
	}

	// ===== 10. 错误应用：固定目标应用时不得为其他应用创建扫码请求 =====
	response, wrongAppBody := env.doRequest(http.MethodPost, protocolapi.PathQRRequest,
		requestOptions{json: map[string]any{"client_id": testClientDevice}})
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("跨应用扫码创建 = %d: %s", response.StatusCode, wrongAppBody)
	}

	// ===== 11. 协议直连合法调用：Bearer 会话 + 同源 Origin（不关闭校验） =====
	// 发起端（匿名 JSON）创建请求；确认端用真实会话秘密作为 Bearer；Cookie 会话才
	// 需要 CSRF，这里用 Bearer 是协议端点的合法调用方式，仍需同源 Origin。
	beginResponse, beginBody := env.doRequest(http.MethodPost, protocolapi.PathQRRequest,
		requestOptions{json: map[string]any{}})
	if beginResponse.StatusCode != http.StatusOK {
		t.Fatalf("协议直连创建扫码请求 = %d", beginResponse.StatusCode)
	}
	begin := env.decodeJSON(beginBody)
	apiRequestID, _ := begin["request_id"].(string)
	claimSecret, _ := begin["claim_secret"].(string)
	if apiRequestID == "" || claimSecret == "" {
		t.Fatal("协议直连创建响应缺少请求标识/领取绑定")
	}
	bearer := confirmIssued.Secret.Reveal()
	promptResponse, promptBody := env.doRequest(http.MethodGet,
		protocolapi.PathQRPrompt+"?request_id="+url.QueryEscape(apiRequestID),
		requestOptions{header: map[string]string{"Authorization": "Bearer " + bearer}})
	if promptResponse.StatusCode != http.StatusOK {
		t.Fatalf("协议直连确认上下文 = %d: %s", promptResponse.StatusCode, promptBody)
	}
	prompt := env.decodeJSON(promptBody)
	if prompt["client_id"] != testClientPublic || prompt["application_name"] != "协议演示应用" {
		t.Fatalf("确认上下文应用信息异常: %v", prompt)
	}
	if scopes, _ := prompt["scopes"].([]any); len(scopes) != 1 || scopes[0] != "profile" {
		t.Fatalf("确认上下文 scope 异常: %v", prompt["scopes"])
	}
	if warning, _ := prompt["warning"].(string); warning == "" {
		t.Fatal("确认上下文缺少风险提示")
	}
	// 缺少同源 Origin 的状态修改请求必须被拒绝（纵深防御，不是 CSRF 替代）。
	response, _ = env.doRequest(http.MethodPost, protocolapi.PathQRDecision,
		requestOptions{json: map[string]any{"request_id": apiRequestID,
			"expected_version": prompt["version"], "approve": true},
			header: map[string]string{"Authorization": "Bearer " + bearer}})
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("缺 Origin 的协议直连决定 = %d，期望 403", response.StatusCode)
	}
	response, decisionBody := env.doRequest(http.MethodPost, protocolapi.PathQRDecision,
		requestOptions{json: map[string]any{"request_id": apiRequestID,
			"expected_version": prompt["version"], "approve": true},
			header: map[string]string{"Authorization": "Bearer " + bearer,
				"Origin": testIssuer}})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("协议直连批准 = %d: %s", response.StatusCode, decisionBody)
	}
	claimResponse, claimBody := env.doRequest(http.MethodPost, protocolapi.PathQRClaim,
		requestOptions{json: map[string]any{"request_id": apiRequestID,
			"claim_secret": claimSecret}})
	if claimResponse.StatusCode != http.StatusOK {
		t.Fatalf("协议直连领取 = %d: %s", claimResponse.StatusCode, claimBody)
	}
	apiClaimedCookie, apiClaimedSession := env.findSessionCookie(claimResponse.Cookies())
	if apiClaimedCookie == nil || apiClaimedSession.UserID != testUserBob ||
		apiClaimedSession.AppID != testClientPublic {
		t.Fatalf("协议直连接领取会话异常: %+v", apiClaimedSession)
	}
	// 错误领取绑定与重复领取都必须拒绝。
	replayResponse, _ := env.doRequest(http.MethodPost, protocolapi.PathQRClaim,
		requestOptions{json: map[string]any{"request_id": apiRequestID,
			"claim_secret": claimSecret}})
	if replayResponse.StatusCode < 400 {
		t.Fatalf("协议直连重复领取未被拒绝: %d", replayResponse.StatusCode)
	}
	wrongSecretResponse, _ := env.doRequest(http.MethodPost, protocolapi.PathQRClaim,
		requestOptions{json: map[string]any{"request_id": apiRequestID,
			"claim_secret": strings.Repeat("A", 43)}})
	if wrongSecretResponse.StatusCode < 400 {
		t.Fatalf("错误领取绑定未被拒绝: %d", wrongSecretResponse.StatusCode)
	}
}
