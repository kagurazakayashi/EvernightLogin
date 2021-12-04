package protocolapi_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
	"github.com/kagurazakayashi/EvernightLogin/internal/protocolapi"
	"github.com/kagurazakayashi/EvernightLogin/internal/qrlogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// deviceStart 发起一次设备授权申请并返回服务端响应。
func (e *testEnv) deviceStart() map[string]any {
	e.t.Helper()
	response, body := e.doRequest(http.MethodPost, protocolapi.PathDeviceAuthorization,
		requestOptions{form: url.Values{
			"client_id": {testClientDevice}, "scope": {"profile"},
			"resource": {testResourceAPI},
		}})
	if response.StatusCode != http.StatusOK {
		e.t.Fatalf("设备授权申请状态 = %d: %s", response.StatusCode, body)
	}
	if cache := response.Header.Get("Cache-Control"); !strings.Contains(cache, "no-store") {
		e.t.Fatalf("设备授权响应 Cache-Control = %q", cache)
	}
	return e.decodeJSON(body)
}

// devicePoll 用设备码轮询令牌端点。
func (e *testEnv) devicePoll(deviceCode string) (*http.Response, map[string]any) {
	e.t.Helper()
	response, body := e.doRequest(http.MethodPost, protocolapi.PathToken,
		requestOptions{form: url.Values{
			"grant_type":  {protocolapi.DeviceCodeGrantType},
			"device_code": {deviceCode}, "client_id": {testClientDevice},
		}})
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		e.t.Fatalf("设备码轮询响应不是 JSON: %v\n%s", err, body)
	}
	return response, payload
}

// approveDevice 用真实授权确认服务（宿主页面层契约）完成用户批准。
func (e *testEnv) approveDevice(userCode string, approve bool) {
	e.t.Helper()
	issued, _ := e.login(testUserAlice)
	sessionSecret := issued.Secret.Reveal()
	requestID := "req_device_approve"
	if _, err := e.flow.DescribeDeviceAuthorization(e.ctx, sessionSecret, userCode,
		requestID); err != nil {
		e.t.Fatalf("设备授权确认页读取失败: %v", err)
	}
	if _, err := e.flow.DecideDeviceAuthorization(e.ctx, sessionSecret,
		oauthflow.DeviceDecisionRequest{UserCode: userCode, Approve: approve,
			RequestID: requestID}); err != nil {
		e.t.Fatalf("设备授权决定失败: %v", err)
	}
}

// TestDeviceAuthorizationFlow 覆盖 RFC 8628 设备码完整流程与轮询状态机。
func TestDeviceAuthorizationFlow(t *testing.T) {
	env := newTestEnv(t, nil)
	start := env.deviceStart()
	deviceCode, _ := start["device_code"].(string)
	userCode, _ := start["user_code"].(string)
	if deviceCode == "" || userCode == "" {
		t.Fatalf("设备授权响应缺少设备码/短码: %v", start)
	}
	if _, exists := start["verification_uri"]; !exists {
		t.Fatalf("缺少 verification_uri: %v", start)
	}
	if complete, _ := start["verification_uri_complete"].(string); !strings.Contains(complete,
		url.QueryEscape(userCode)) && !strings.Contains(complete, strings.ToLower(
		strings.ReplaceAll(userCode, "-", ""))) {
		t.Fatalf("verification_uri_complete 未携带短码: %q", complete)
	}
	if interval, _ := start["interval"].(float64); interval < 1 {
		t.Fatalf("interval = %v", start["interval"])
	}
	if env.countAudit("oauth.device.requested") < 1 {
		t.Fatal("缺少设备授权申请审计")
	}

	// 未批准：authorization_pending。
	response, payload := env.devicePoll(deviceCode)
	if response.StatusCode != http.StatusBadRequest || payload["error"] != "authorization_pending" {
		t.Fatalf("未批准轮询 = %d %v", response.StatusCode, payload)
	}
	// 过快轮询：slow_down，并附带 Retry-After。
	response, payload = env.devicePoll(deviceCode)
	if response.StatusCode != http.StatusBadRequest || payload["error"] != "slow_down" {
		t.Fatalf("过快轮询 = %d %v", response.StatusCode, payload)
	}
	if retryAfter := response.Header.Get("Retry-After"); retryAfter == "" {
		t.Fatal("slow_down 响应缺少 Retry-After")
	}

	// 用户在另一设备批准（真实授权确认服务），再等过轮询间隔领取令牌。
	env.approveDevice(userCode, true)
	// 之前触发过 slow_down，服务端已把强制间隔提高到 10 秒，这里越过新间隔。
	env.clock.Advance(11 * time.Second)
	response, payload = env.devicePoll(deviceCode)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("批准后轮询 = %d %v", response.StatusCode, payload)
	}
	accessToken, _ := payload["access_token"].(string)
	if accessToken == "" || payload["token_type"] != "Bearer" {
		t.Fatalf("设备令牌响应异常: %v", payload)
	}
	if _, exists := payload["refresh_token"]; exists {
		t.Fatal("设备客户端未登记 refresh_token，不应签发刷新令牌")
	}
	if env.countAudit("oauth.device.token_issued") < 1 {
		t.Fatal("缺少设备令牌签发审计")
	}

	// 设备码一次性：重放 invalid_grant。
	response, payload = env.devicePoll(deviceCode)
	if response.StatusCode != http.StatusBadRequest || payload["error"] != "invalid_grant" {
		t.Fatalf("设备码重放 = %d %v", response.StatusCode, payload)
	}

	// 过期设备码：expired_token。
	expiredStart := env.deviceStart()
	env.clock.Advance(11 * time.Minute)
	response, payload = env.devicePoll(expiredStart["device_code"].(string))
	if response.StatusCode != http.StatusBadRequest || payload["error"] != "expired_token" {
		t.Fatalf("过期设备码 = %d %v", response.StatusCode, payload)
	}
}

// TestDeviceAuthorizationRejections 覆盖设备码跨客户端绑定、用户拒绝与发起端取消。
func TestDeviceAuthorizationRejections(t *testing.T) {
	env := newTestEnv(t, nil)
	start := env.deviceStart()
	deviceCode, _ := start["device_code"].(string)

	// 其他同样登记设备码的客户端提交同一设备码：拒绝且不泄露归属。
	response, body := env.doRequest(http.MethodPost, protocolapi.PathToken,
		requestOptions{form: url.Values{
			"grant_type":  {protocolapi.DeviceCodeGrantType},
			"device_code": {deviceCode}, "client_id": {testClientDevice2},
		}})
	if response.StatusCode != http.StatusBadRequest ||
		env.decodeJSON(body)["error"] != "invalid_grant" {
		t.Fatalf("跨客户端设备码未被拒绝: %d %s", response.StatusCode, body)
	}

	// 用户明确拒绝：access_denied。
	env.approveDevice(start["user_code"].(string), false)
	env.clock.Advance(6 * time.Second)
	response, polled := env.devicePoll(deviceCode)
	if response.StatusCode != http.StatusBadRequest || polled["error"] != "access_denied" {
		t.Fatalf("用户拒绝后的轮询 = %d %v", response.StatusCode, polled)
	}

	// 发起端取消：204，随后轮询 access_denied。
	cancelStart := env.deviceStart()
	cancelCode := cancelStart["device_code"].(string)
	cancelResponse, cancelBody := env.doRequest(http.MethodPost, protocolapi.PathDeviceCancel,
		requestOptions{form: url.Values{"device_code": {cancelCode},
			"client_id": {testClientDevice}}})
	if cancelResponse.StatusCode != http.StatusNoContent {
		t.Fatalf("设备取消状态 = %d: %s", cancelResponse.StatusCode, cancelBody)
	}
	env.clock.Advance(6 * time.Second)
	response, body = env.doRequest(http.MethodPost, protocolapi.PathToken,
		requestOptions{form: url.Values{
			"grant_type":  {protocolapi.DeviceCodeGrantType},
			"device_code": {cancelCode}, "client_id": {testClientDevice},
		}})
	if response.StatusCode != http.StatusBadRequest ||
		env.decodeJSON(body)["error"] != "access_denied" {
		t.Fatalf("取消后的轮询 = %d %s", response.StatusCode, body)
	}
}

// qrBegin 创建一次扫码登录请求。
func (e *testEnv) qrBegin() map[string]any {
	e.t.Helper()
	response, body := e.doRequest(http.MethodPost, protocolapi.PathQRRequest,
		requestOptions{json: map[string]any{}})
	if response.StatusCode != http.StatusOK {
		e.t.Fatalf("扫码创建状态 = %d: %s", response.StatusCode, body)
	}
	return e.decodeJSON(body)
}

// qrClaimBody 构造领取绑定请求体。
func qrClaimBody(begin map[string]any) map[string]any {
	return map[string]any{
		"request_id":   begin["request_id"],
		"claim_secret": begin["claim_secret"],
	}
}

// TestQRLoginFlow 覆盖扫码登录创建/轮询/批准/领取闭环与一次性领取。
func TestQRLoginFlow(t *testing.T) {
	env := newTestEnv(t, nil)
	begin := env.qrBegin()
	requestID, _ := begin["request_id"].(string)
	claimSecret, _ := begin["claim_secret"].(string)
	qrPayload, _ := begin["qr_payload"].(string)
	if requestID == "" || claimSecret == "" || qrPayload == "" {
		t.Fatalf("扫码创建响应缺少字段: %v", begin)
	}
	// 二维码载荷只含一次性请求标识，不含领取绑定/令牌/会话秘密。
	if strings.Contains(qrPayload, claimSecret) {
		t.Fatal("二维码载荷泄露领取绑定")
	}
	if !strings.Contains(qrPayload, requestID) {
		t.Fatalf("二维码载荷缺少请求标识: %q", qrPayload)
	}
	if _, err := qrlogin.ParseQRPayload(qrPayload); err != nil {
		t.Fatalf("二维码载荷不是受支持结构: %v", err)
	}
	if env.countAudit("app_qr_login.request_created") < 1 {
		t.Fatal("缺少扫码请求创建审计")
	}

	// 原发起端轮询状态：pending。
	response, body := env.doRequest(http.MethodPost, protocolapi.PathQRStatus,
		requestOptions{json: qrClaimBody(begin)})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("扫码状态 = %d: %s", response.StatusCode, body)
	}
	status := env.decodeJSON(body)
	if status["status"] != qrlogin.StatusPending {
		t.Fatalf("扫码状态 = %v", status["status"])
	}
	version := status["version"]

	// 没有领取绑定的第三方不能查询（400），错误绑定不能查询（410）。
	response, body = env.doRequest(http.MethodPost, protocolapi.PathQRStatus,
		requestOptions{json: map[string]any{"request_id": requestID}})
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("缺少领取绑定状态 = %d: %s", response.StatusCode, body)
	}
	response, body = env.doRequest(http.MethodPost, protocolapi.PathQRStatus,
		requestOptions{json: map[string]any{"request_id": requestID,
			"claim_secret": strings.Repeat("A", 43)}})
	if response.StatusCode != http.StatusGone {
		t.Fatalf("错误领取绑定状态 = %d: %s", response.StatusCode, body)
	}

	// 确认端：未登录不能读取；登录后（bob）读取受控上下文。
	response, body = env.doRequest(http.MethodGet,
		protocolapi.PathQRPrompt+"?request_id="+url.QueryEscape(requestID), requestOptions{})
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("未登录读取确认上下文 = %d: %s", response.StatusCode, body)
	}
	bobIssued, bobCookie := env.login(testUserBob)
	response, body = env.doRequest(http.MethodGet,
		protocolapi.PathQRPrompt+"?request_id="+url.QueryEscape(requestID),
		requestOptions{cookie: bobCookie})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("确认上下文状态 = %d: %s", response.StatusCode, body)
	}
	prompt := env.decodeJSON(body)
	if prompt["request_id"] != requestID || prompt["client_id"] != testClientPublic {
		t.Fatalf("确认上下文异常: %v", prompt)
	}
	if warning, _ := prompt["warning"].(string); warning == "" {
		t.Fatal("确认上下文缺少风险提醒")
	}

	// 浏览器 Cookie 会话提交决定必须带 CSRF。
	decisionBody := map[string]any{"request_id": requestID,
		"expected_version": version, "approve": true}
	response, body = env.doRequest(http.MethodPost, protocolapi.PathQRDecision,
		requestOptions{cookie: bobCookie, json: decisionBody,
			header: map[string]string{"Origin": testIssuer}})
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("缺少 CSRF 决定状态 = %d: %s", response.StatusCode, body)
	}
	csrfSecret, err := env.sessions.IssuePageCSRFToken(env.ctx, bobIssued.Secret.Reveal())
	if err != nil {
		t.Fatalf("签发 CSRF 令牌失败: %v", err)
	}
	decisionBody["csrf_token"] = csrfSecret.Reveal()
	// 纵深防御：状态修改端点缺少 Origin/Referer 时直接拒绝（即使 CSRF 令牌正确）。
	response, body = env.doRequest(http.MethodPost, protocolapi.PathQRDecision,
		requestOptions{cookie: bobCookie, json: decisionBody})
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("缺少来源头的扫码决定状态 = %d: %s", response.StatusCode, body)
	}
	response, body = env.doRequest(http.MethodPost, protocolapi.PathQRDecision,
		requestOptions{cookie: bobCookie, json: decisionBody,
			header: map[string]string{"Origin": testIssuer}})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("扫码批准状态 = %d: %s", response.StatusCode, body)
	}
	if env.countAudit("app_qr_login.approved") < 1 {
		t.Fatal("缺少扫码批准审计")
	}

	// 第三方（carol）持有错误领取绑定不能领取。
	_, carolCookie := env.login(testUserCarol)
	_ = carolCookie
	response, body = env.doRequest(http.MethodPost, protocolapi.PathQRClaim,
		requestOptions{json: map[string]any{"request_id": requestID,
			"claim_secret": strings.Repeat("A", 43)}})
	if response.StatusCode != http.StatusGone {
		t.Fatalf("错误领取绑定领取 = %d: %s", response.StatusCode, body)
	}

	// 原发起端领取：签发的是确认者（bob）的目标应用会话。
	claimResponse, claimBody := env.doRequest(http.MethodPost, protocolapi.PathQRClaim,
		requestOptions{json: qrClaimBody(begin)})
	if claimResponse.StatusCode != http.StatusOK {
		t.Fatalf("领取状态 = %d: %s", claimResponse.StatusCode, claimBody)
	}
	claim := env.decodeJSON(claimBody)
	if claim["status"] != qrlogin.StatusClaimed || claim["user_id"] != testUserBob {
		t.Fatalf("领取结果异常（应绑定确认者）: %v", claim)
	}
	if claim["app_id"] != testClientPublic {
		t.Fatalf("领取会话应用范围 = %v", claim["app_id"])
	}
	cookies := claimResponse.Cookies()
	if len(cookies) == 0 {
		t.Fatal("领取成功未投递目标应用会话 Cookie")
	}
	claimedSession, err := env.sessions.Validate(env.ctx, cookies[0].Value)
	if err != nil {
		t.Fatalf("领取的会话 Cookie 校验失败: %v", err)
	}
	if claimedSession.UserID != testUserBob || claimedSession.AppID != testClientPublic {
		t.Fatalf("领取会话主体异常: %+v", claimedSession)
	}
	if !strings.Contains(claimedSession.ID, session.SessionIDPrefix) {
		t.Fatalf("会话 ID 前缀异常: %q", claimedSession.ID)
	}
	if env.countAudit("app_qr_login.claimed") < 1 {
		t.Fatal("缺少扫码领取审计")
	}

	// 结果只能领取一次。
	response, body = env.doRequest(http.MethodPost, protocolapi.PathQRClaim,
		requestOptions{json: qrClaimBody(begin)})
	if response.StatusCode != http.StatusGone {
		t.Fatalf("重复领取状态 = %d: %s", response.StatusCode, body)
	}
	// 已领取的请求不能被再次批准/拒绝。
	response, body = env.doRequest(http.MethodPost, protocolapi.PathQRDecision,
		requestOptions{cookie: bobCookie, json: decisionBody,
			header: map[string]string{"Origin": testIssuer}})
	if response.StatusCode != http.StatusGone {
		t.Fatalf("重复决定状态 = %d: %s", response.StatusCode, body)
	}
}

// TestQRLoginRejections 覆盖目标应用固定、拒绝、过期与重新生成。
func TestQRLoginRejections(t *testing.T) {
	env := newTestEnv(t, nil)
	// 固定 QRClientID 时不得为其他应用创建扫码请求。
	response, body := env.doRequest(http.MethodPost, protocolapi.PathQRRequest,
		requestOptions{json: map[string]any{"client_id": testClientDevice}})
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("跨应用扫码创建 = %d: %s", response.StatusCode, body)
	}

	// 用户拒绝。
	begin := env.qrBegin()
	requestID, _ := begin["request_id"].(string)
	bobIssued, bobCookie := env.login(testUserBob)
	csrfSecret, err := env.sessions.IssuePageCSRFToken(env.ctx, bobIssued.Secret.Reveal())
	if err != nil {
		t.Fatalf("签发 CSRF 令牌失败: %v", err)
	}
	response, body = env.doRequest(http.MethodPost, protocolapi.PathQRDecision,
		requestOptions{cookie: bobCookie, json: map[string]any{
			"request_id": requestID, "expected_version": begin["version"],
			"approve": false, "csrf_token": csrfSecret.Reveal(),
		}, header: map[string]string{"Origin": testIssuer}})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("拒绝扫码状态 = %d: %s", response.StatusCode, body)
	}
	if env.countAudit("app_qr_login.denied") < 1 {
		t.Fatal("缺少扫码拒绝审计")
	}
	response, body = env.doRequest(http.MethodPost, protocolapi.PathQRClaim,
		requestOptions{json: qrClaimBody(begin)})
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("拒绝后领取状态 = %d: %s", response.StatusCode, body)
	}

	// 过期：超过请求有效期后状态为 expired，领取失败。
	expiring := env.qrBegin()
	env.clock.Advance(3 * time.Minute)
	response, body = env.doRequest(http.MethodPost, protocolapi.PathQRStatus,
		requestOptions{json: qrClaimBody(expiring)})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("过期状态查询 = %d: %s", response.StatusCode, body)
	}
	if status := env.decodeJSON(body); status["status"] != qrlogin.QueryExpired {
		t.Fatalf("过期状态 = %v", status["status"])
	}
	response, body = env.doRequest(http.MethodPost, protocolapi.PathQRClaim,
		requestOptions{json: qrClaimBody(expiring)})
	if response.StatusCode != http.StatusGone {
		t.Fatalf("过期领取状态 = %d: %s", response.StatusCode, body)
	}

	// 重新生成：旧请求失效，新请求使用新领取绑定。
	regenerating := env.qrBegin()
	response, body = env.doRequest(http.MethodPost, protocolapi.PathQRRegenerate,
		requestOptions{json: qrClaimBody(regenerating)})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("重新生成状态 = %d: %s", response.StatusCode, body)
	}
	regenerated := env.decodeJSON(body)
	newSecret, _ := regenerated["claim_secret"].(string)
	if newSecret == "" || newSecret == regenerating["claim_secret"] {
		t.Fatalf("重新生成未更换领取绑定: %v", regenerated)
	}
	response, body = env.doRequest(http.MethodPost, protocolapi.PathQRStatus,
		requestOptions{json: qrClaimBody(regenerating)})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("旧请求状态查询 = %d: %s", response.StatusCode, body)
	}
	if status := env.decodeJSON(body); status["status"] != qrlogin.StatusCancelled {
		t.Fatalf("旧请求重新生成后状态 = %v，期望 cancelled", status["status"])
	}
	response, body = env.doRequest(http.MethodPost, protocolapi.PathQRStatus,
		requestOptions{json: qrClaimBody(regenerated)})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("新请求状态 = %d: %s", response.StatusCode, body)
	}
	// 发起端取消。
	response, body = env.doRequest(http.MethodPost, protocolapi.PathQRCancel,
		requestOptions{json: qrClaimBody(regenerated)})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("取消状态 = %d: %s", response.StatusCode, body)
	}
	if status := env.decodeJSON(body); status["status"] != qrlogin.StatusCancelled {
		t.Fatalf("取消后状态 = %v", status["status"])
	}
}
