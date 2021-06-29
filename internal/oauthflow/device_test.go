package oauthflow_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
)

// 本文件验证步骤 57 设备授权（RFC 8628）：申请 → 另一会话确认 → 轮询领取闭环，
// 以及猜码限流、过快轮询、客户端替换、过期/拒绝/取消、并发领取与确认后状态变化。

// deviceProtocolCode 断言错误是标准 OAuth 协议错误并返回其 error 值。
func deviceProtocolCode(t *testing.T, err error) string {
	t.Helper()
	var protocolErr *oauthflow.OAuthError
	if !errors.As(err, &protocolErr) {
		t.Fatalf("期望标准 OAuth 协议错误，实际 = %v", err)
	}
	return protocolErr.Code
}

// newDeviceEnv 构造启用设备码授权的测试环境（真实临时 SQLite 与真实会话/令牌服务）。
func newDeviceEnv(t *testing.T, clientType oauthclient.ClientType) *testEnv {
	t.Helper()
	environment := newTestEnv(t, clientType)
	environment.exec(`UPDATE oauth_clients SET grant_types_json=? WHERE client_id=?`,
		`["authorization_code","urn:ietf:params:oauth:grant-type:device_code"]`, testAppID)
	return environment
}

// beginDevice 发起一次设备授权申请；失败直接结束测试。
func (e *testEnv) beginDevice(t *testing.T,
	request oauthflow.DeviceAuthorizationRequest) oauthflow.DeviceAuthorizationResponse {
	t.Helper()
	if request.ClientID == "" {
		request.ClientID = testAppID
	}
	if request.Scope == nil {
		request.Scope = []string{"profile.read", "email.read"}
	}
	if request.Resource == nil {
		request.Resource = []string{testAudience}
	}
	if request.RequestID == "" {
		request.RequestID = "req_dev_begin"
	}
	if e.clientType == oauthclient.ClientTypeConfidential && request.ClientSecret == "" {
		request.ClientSecret = "confidential-secret"
	}
	response, err := e.flow.BeginDeviceAuthorization(e.ctx, request)
	if err != nil {
		t.Fatalf("设备授权申请失败：%v", err)
	}
	return response
}

// approveDevice 用测试会话查询并批准设备授权请求。
func (e *testEnv) approveDevice(t *testing.T, userCode string) {
	t.Helper()
	if _, err := e.flow.DescribeDeviceAuthorization(e.ctx, e.sessionSecret, userCode,
		"req_dev_describe"); err != nil {
		t.Fatalf("查询设备授权请求失败：%v", err)
	}
	if _, err := e.flow.DecideDeviceAuthorization(e.ctx, e.sessionSecret,
		oauthflow.DeviceDecisionRequest{UserCode: userCode, Approve: true,
			RequestID: "req_dev_decide"}); err != nil {
		t.Fatalf("批准设备授权请求失败：%v", err)
	}
}

// pollDevice 轮询 Token 端点领取令牌。
func (e *testEnv) pollDevice(t *testing.T,
	response oauthflow.DeviceAuthorizationResponse) (oauthflow.TokenResponse, error) {
	t.Helper()
	request := oauthflow.ExchangeRequest{
		GrantType:  oauthflow.AccessTokenGrantDeviceCode,
		DeviceCode: response.DeviceCode.Reveal(), ClientID: testAppID,
		RequestID: "req_dev_poll",
	}
	if e.clientType == oauthclient.ClientTypeConfidential {
		request.ClientSecret = "confidential-secret"
	}
	return e.flow.Exchange(e.ctx, request)
}

// TestDeviceAuthorizationFullFlow 验证申请→另一会话确认→领取闭环与一次性。
func TestDeviceAuthorizationFullFlow(t *testing.T) {
	env := newDeviceEnv(t, oauthclient.ClientTypePublic)
	start := env.beginDevice(t, oauthflow.DeviceAuthorizationRequest{})
	if !start.DeviceCode.IsSet() || !start.UserCode.IsSet() {
		t.Fatal("申请响应缺少设备码或短码")
	}
	display := start.UserCode.Reveal()
	if len(display) != 9 || display[4] != '-' {
		t.Fatalf("短码显示格式 = %q，期望 XXXX-XXXX", display)
	}
	if !strings.HasPrefix(start.VerificationURIComplete, start.VerificationURI) ||
		!strings.Contains(start.VerificationURIComplete, "user_code=") {
		t.Fatalf("验证链接 = %q，未包含验证地址或短码", start.VerificationURIComplete)
	}
	if start.ExpiresIn != 600 || start.Interval != 5 {
		t.Fatalf("有效期/间隔 = %d/%d，期望 600/5", start.ExpiresIn, start.Interval)
	}
	// 库里只保存摘要，不保存设备码/短码明文。
	if got := env.queryInt(`SELECT COUNT(*) FROM oauth_device_authorizations
WHERE status='pending' AND length(device_code_sha256)=32 AND length(user_code_digest)=32
AND length(user_code_key_id)>0`); got != 1 {
		t.Fatalf("设备授权记录数 = %d，期望 1 条 pending 摘要记录", got)
	}
	// 用户输入允许小写/无连字符（规范化后一致）。
	prompt, err := env.flow.DescribeDeviceAuthorization(env.ctx, env.sessionSecret,
		strings.ToLower(strings.ReplaceAll(display, "-", "")), "req_dev_describe")
	if err != nil {
		t.Fatalf("查询设备授权请求失败：%v", err)
	}
	if prompt.ClientID != testAppID || len(prompt.Scopes) != 2 || len(prompt.Audiences) != 1 {
		t.Fatalf("确认页信息不完整：%+v", prompt)
	}
	if _, err := env.flow.DecideDeviceAuthorization(env.ctx, env.sessionSecret,
		oauthflow.DeviceDecisionRequest{UserCode: display, Approve: true,
			RequestID: "req_dev_decide"}); err != nil {
		t.Fatalf("批准设备授权请求失败：%v", err)
	}
	response, err := env.pollDevice(t, start)
	if err != nil {
		t.Fatalf("设备码领取令牌失败：%v", err)
	}
	claims, err := env.tokens.VerifyAccessToken(env.ctx, response.AccessToken.Reveal(), testAudience)
	if err != nil {
		t.Fatalf("领取的 Access Token 验证失败：%v", err)
	}
	if claims.Subject != testUserID || claims.ClientID != testAppID {
		t.Fatalf("令牌主体 = %q/%q，期望 %q/%q", claims.Subject, claims.ClientID,
			testUserID, testAppID)
	}
	if !containsString(claims.Scopes, "profile.read") {
		t.Fatalf("令牌 scope = %v，缺少 profile.read", claims.Scopes)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM oauth_device_authorizations WHERE status='consumed'`); got != 1 {
		t.Fatalf("consumed 记录数 = %d，期望 1", got)
	}
	// 重复领取必须失败且不再签发令牌。
	_, err = env.pollDevice(t, start)
	if code := deviceProtocolCode(t, err); code != "invalid_grant" {
		t.Fatalf("重复领取 error = %q，期望 invalid_grant", code)
	}
}

// TestDeviceAuthorizationPendingAndSlowDown 验证等待状态与过快轮询的标准 slow_down。
func TestDeviceAuthorizationPendingAndSlowDown(t *testing.T) {
	env := newDeviceEnv(t, oauthclient.ClientTypePublic)
	start := env.beginDevice(t, oauthflow.DeviceAuthorizationRequest{})
	if _, err := env.pollDevice(t, start); deviceProtocolCode(t, err) != "authorization_pending" {
		t.Fatalf("未批准时轮询 error = %v，期望 authorization_pending", err)
	}
	// 间隔内再次轮询：slow_down，且服务端增大间隔。
	_, err := env.pollDevice(t, start)
	if code := deviceProtocolCode(t, err); code != "slow_down" {
		t.Fatalf("过快轮询 error = %q，期望 slow_down", code)
	}
	interval := env.queryInt(`SELECT interval_seconds FROM oauth_device_authorizations`)
	if interval != 10 {
		t.Fatalf("slow_down 后间隔 = %d，期望 10", interval)
	}
	env.now = env.now.Add(time.Duration(interval+1) * time.Second)
	if _, err := env.pollDevice(t, start); deviceProtocolCode(t, err) != "authorization_pending" {
		t.Fatalf("等待间隔后轮询 error = %v，期望 authorization_pending", err)
	}
	// 用户确认后等满间隔即可领取。
	env.approveDevice(t, start.UserCode.Reveal())
	env.now = env.now.Add(11 * time.Second)
	if _, err := env.pollDevice(t, start); err != nil {
		t.Fatalf("确认后领取失败：%v", err)
	}
}

// TestDeviceAuthorizationUserCodeGuessRateLimited 验证按用户维度猜码限流。
func TestDeviceAuthorizationUserCodeGuessRateLimited(t *testing.T) {
	env := newDeviceEnv(t, oauthclient.ClientTypePublic)
	_ = env.beginDevice(t, oauthflow.DeviceAuthorizationRequest{})
	var lastErr error
	for attempt := 0; attempt < 12; attempt++ {
		_, lastErr = env.flow.DescribeDeviceAuthorization(env.ctx, env.sessionSecret,
			"BCDF-GHJK", "req_dev_guess")
		if errors.Is(lastErr, oauthflow.ErrDeviceAuthorizationRateLimited) {
			break
		}
		if !errors.Is(lastErr, oauthflow.ErrDeviceAuthorizationNotFound) {
			t.Fatalf("第 %d 次错误短码 error = %v，期望不存在或限流", attempt+1, lastErr)
		}
	}
	if !errors.Is(lastErr, oauthflow.ErrDeviceAuthorizationRateLimited) {
		t.Fatalf("连续猜码未被限流，最后 error = %v", lastErr)
	}
	if got := oauthflow.CodeOf(lastErr); got != oauthflow.CodeRateLimited {
		t.Fatalf("限流错误码 = %q，期望 RATE_LIMITED", got)
	}
}

// TestDeviceAuthorizationClientSubstitution 验证设备码只能由申请时的客户端领取。
func TestDeviceAuthorizationClientSubstitution(t *testing.T) {
	env := newDeviceEnv(t, oauthclient.ClientTypePublic)
	start := env.beginDevice(t, oauthflow.DeviceAuthorizationRequest{})
	env.registerSecondClient()
	env.exec(`UPDATE oauth_clients SET grant_types_json=? WHERE client_id=?`,
		`["urn:ietf:params:oauth:grant-type:device_code"]`, testAppID2)
	_, err := env.flow.Exchange(env.ctx, oauthflow.ExchangeRequest{
		GrantType:  oauthflow.AccessTokenGrantDeviceCode,
		DeviceCode: start.DeviceCode.Reveal(), ClientID: testAppID2,
		RequestID: "req_dev_substitute",
	})
	if code := deviceProtocolCode(t, err); code != "invalid_grant" {
		t.Fatalf("换客户端领取 error = %q，期望 invalid_grant", code)
	}
	env.exec(`UPDATE applications SET status='disabled' WHERE id=?`, testAppID)
	if _, err := env.pollDevice(t, start); deviceProtocolCode(t, err) != "invalid_client" {
		t.Fatalf("应用停用后轮询 error = %v，期望 invalid_client", err)
	}
}

// TestDeviceAuthorizationExpired 验证过期后的标准 expired_token 与确认失效。
func TestDeviceAuthorizationExpired(t *testing.T) {
	env := newDeviceEnv(t, oauthclient.ClientTypePublic)
	start := env.beginDevice(t, oauthflow.DeviceAuthorizationRequest{})
	env.now = env.now.Add(11 * time.Minute)
	if _, err := env.pollDevice(t, start); deviceProtocolCode(t, err) != "expired_token" {
		t.Fatalf("过期轮询 error = %v，期望 expired_token", err)
	}
	if _, err := env.flow.DescribeDeviceAuthorization(env.ctx, env.sessionSecret,
		start.UserCode.Reveal(), "req_dev_describe"); !errors.Is(err,
		oauthflow.ErrDeviceAuthorizationNotFound) {
		t.Fatalf("过期短码查询 error = %v，期望不存在/失效", err)
	}
	if _, err := env.flow.DecideDeviceAuthorization(env.ctx, env.sessionSecret,
		oauthflow.DeviceDecisionRequest{UserCode: start.UserCode.Reveal(), Approve: true,
			RequestID: "req_dev_decide"}); !errors.Is(err,
		oauthflow.ErrDeviceAuthorizationNotFound) {
		t.Fatalf("过期短码批准 error = %v，期望不存在/失效", err)
	}
}

// TestDeviceAuthorizationDenyAndCancel 验证用户拒绝与设备取消都按 access_denied 收敛。
func TestDeviceAuthorizationDenyAndCancel(t *testing.T) {
	env := newDeviceEnv(t, oauthclient.ClientTypePublic)
	start := env.beginDevice(t, oauthflow.DeviceAuthorizationRequest{})
	if _, err := env.flow.DecideDeviceAuthorization(env.ctx, env.sessionSecret,
		oauthflow.DeviceDecisionRequest{UserCode: start.UserCode.Reveal(), Approve: false,
			RequestID: "req_dev_deny"}); err != nil {
		t.Fatalf("拒绝设备授权失败：%v", err)
	}
	if _, err := env.pollDevice(t, start); deviceProtocolCode(t, err) != "access_denied" {
		t.Fatalf("拒绝后轮询 error = %v，期望 access_denied", err)
	}

	second := env.beginDevice(t, oauthflow.DeviceAuthorizationRequest{})
	if err := env.flow.CancelDeviceAuthorization(env.ctx, oauthflow.DeviceCancelRequest{
		DeviceCode: second.DeviceCode.Reveal(), ClientID: testAppID,
		RequestID: "req_dev_cancel"}); err != nil {
		t.Fatalf("设备取消失败：%v", err)
	}
	if _, err := env.pollDevice(t, second); deviceProtocolCode(t, err) != "access_denied" {
		t.Fatalf("取消后轮询 error = %v，期望 access_denied", err)
	}
	if err := env.flow.CancelDeviceAuthorization(env.ctx, oauthflow.DeviceCancelRequest{
		DeviceCode: second.DeviceCode.Reveal(), ClientID: testAppID,
		RequestID: "req_dev_cancel_again"}); !errors.Is(err,
		oauthflow.ErrDeviceAuthorizationConflict) {
		t.Fatalf("重复取消 error = %v，期望状态冲突", err)
	}
	// 换客户端取消必须被拒绝。
	env.registerSecondClient()
	env.exec(`UPDATE oauth_clients SET grant_types_json=? WHERE client_id=?`,
		`["urn:ietf:params:oauth:grant-type:device_code"]`, testAppID2)
	third := env.beginDevice(t, oauthflow.DeviceAuthorizationRequest{})
	if err := env.flow.CancelDeviceAuthorization(env.ctx, oauthflow.DeviceCancelRequest{
		DeviceCode: third.DeviceCode.Reveal(), ClientID: testAppID2,
		RequestID: "req_dev_cancel_substitute"}); !errors.Is(err,
		oauthflow.ErrDeviceAuthorizationNotFound) {
		t.Fatalf("换客户端取消 error = %v，期望不存在", err)
	}
}

// TestDeviceAuthorizationConfidentialClient 验证保密客户端在申请与轮询两端都必须认证。
func TestDeviceAuthorizationConfidentialClient(t *testing.T) {
	env := newDeviceEnv(t, oauthclient.ClientTypeConfidential)
	if _, err := env.flow.BeginDeviceAuthorization(env.ctx, oauthflow.DeviceAuthorizationRequest{
		ClientID: testAppID, Scope: []string{"profile.read"},
		Resource: []string{testAudience}, RequestID: "req_dev_noauth"}); deviceProtocolCode(t, err) !=
		"invalid_client" {
		t.Fatalf("保密客户端未认证申请 error = %v，期望 invalid_client", err)
	}
	start := env.beginDevice(t, oauthflow.DeviceAuthorizationRequest{})
	env.approveDevice(t, start.UserCode.Reveal())
	if _, err := env.flow.Exchange(env.ctx, oauthflow.ExchangeRequest{
		GrantType:  oauthflow.AccessTokenGrantDeviceCode,
		DeviceCode: start.DeviceCode.Reveal(), ClientID: testAppID,
		RequestID: "req_dev_poll_noauth",
	}); deviceProtocolCode(t, err) != "invalid_client" {
		t.Fatalf("保密客户端未认证轮询 error = %v，期望 invalid_client", err)
	}
	if _, err := env.pollDevice(t, start); err != nil {
		t.Fatalf("保密客户端认证后领取失败：%v", err)
	}
}

// TestDeviceAuthorizationStateChangedBeforeClaim 验证确认后状态变化一律 fail-closed。
func TestDeviceAuthorizationStateChangedBeforeClaim(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(env *testEnv)
	}{
		{name: "用户被禁用", mutate: func(env *testEnv) {
			env.exec(`UPDATE users SET status='disabled' WHERE id=?`, testUserID)
		}},
		{name: "安全版本递增", mutate: func(env *testEnv) {
			env.exec(`UPDATE users SET security_version=security_version+1 WHERE id=?`, testUserID)
		}},
		{name: "成员关系移除", mutate: func(env *testEnv) {
			env.exec(`UPDATE app_memberships SET status='disabled' WHERE user_id=? AND app_id=?`,
				testUserID, testAppID)
		}},
		{name: "确认会话被撤销", mutate: func(env *testEnv) {
			env.exec(`UPDATE sessions SET revoked_at_ms=?`, env.now.Add(time.Second).UnixMilli())
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			env := newDeviceEnv(t, oauthclient.ClientTypePublic)
			start := env.beginDevice(t, oauthflow.DeviceAuthorizationRequest{})
			env.approveDevice(t, start.UserCode.Reveal())
			test.mutate(env)
			env.now = env.now.Add(6 * time.Second)
			_, err := env.pollDevice(t, start)
			if code := deviceProtocolCode(t, err); code != "invalid_grant" {
				t.Fatalf("状态变化后轮询 error = %q，期望 invalid_grant", code)
			}
			if got := env.queryInt(`SELECT COUNT(*) FROM oauth_device_authorizations
WHERE status='consumed'`); got != 0 {
				t.Fatalf("状态变化后不应消费设备码（consumed=%d）", got)
			}
		})
	}
}

// TestDeviceAuthorizationConcurrentClaim 验证并发领取单赢家与并发决定单赢家。
func TestDeviceAuthorizationConcurrentClaim(t *testing.T) {
	env := newDeviceEnv(t, oauthclient.ClientTypePublic)
	start := env.beginDevice(t, oauthflow.DeviceAuthorizationRequest{})

	// 并发决定：只有一方成功批准。
	var decideWait sync.WaitGroup
	decideErrs := make([]error, 2)
	for index := 0; index < 2; index++ {
		decideWait.Add(1)
		go func(slot int) {
			defer decideWait.Done()
			_, decideErrs[slot] = env.flow.DecideDeviceAuthorization(env.ctx, env.sessionSecret,
				oauthflow.DeviceDecisionRequest{UserCode: start.UserCode.Reveal(), Approve: true,
					RequestID: "req_dev_concurrent_decide"})
		}(index)
	}
	decideWait.Wait()
	succeeded := 0
	for _, err := range decideErrs {
		if err == nil {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Fatalf("并发批准成功数 = %d，期望 1", succeeded)
	}

	// 并发领取：只有一方拿到令牌。
	env.now = env.now.Add(6 * time.Second)
	var pollWait sync.WaitGroup
	pollErrs := make([]error, 4)
	for index := 0; index < 4; index++ {
		pollWait.Add(1)
		go func(slot int) {
			defer pollWait.Done()
			_, pollErrs[slot] = env.pollDevice(t, start)
		}(index)
	}
	pollWait.Wait()
	succeeded = 0
	for _, err := range pollErrs {
		if err == nil {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Fatalf("并发领取成功数 = %d，期望 1", succeeded)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM oauth_device_authorizations
WHERE status='consumed'`); got != 1 {
		t.Fatalf("consumed 记录数 = %d，期望 1", got)
	}
}

// TestDeviceAuthorizationScopeAndOptionsValidation 验证 openid scope 拒绝与配置校验。
func TestDeviceAuthorizationScopeAndOptionsValidation(t *testing.T) {
	env := newDeviceEnv(t, oauthclient.ClientTypePublic)
	env.exec(`UPDATE oauth_clients SET scopes_json='["openid","profile.read"]' WHERE client_id=?`,
		testAppID)
	if _, err := env.flow.BeginDeviceAuthorization(env.ctx, oauthflow.DeviceAuthorizationRequest{
		ClientID: testAppID, Scope: []string{"openid"}, Resource: []string{testAudience},
		RequestID: "req_dev_openid"}); deviceProtocolCode(t, err) != "invalid_scope" {
		t.Fatalf("openid scope 申请 error = %v，期望 invalid_scope", err)
	}
	if _, err := env.flow.BeginDeviceAuthorization(env.ctx, oauthflow.DeviceAuthorizationRequest{
		ClientID: testAppID, Scope: []string{"profile.write"}, Resource: []string{testAudience},
		RequestID: "req_dev_bad_scope"}); deviceProtocolCode(t, err) != "invalid_scope" {
		t.Fatalf("未登记 scope 申请 error = %v，期望 invalid_scope", err)
	}
	// 宿主配置校验：非法验证地址与非回环 http 在 New 阶段拒绝。
	base := env.flowOptionsForTest()
	base.DeviceVerificationURI = "http://example.test/device"
	if _, err := oauthflow.New(base); !errors.Is(err, oauthflow.ErrOptionsInvalid) {
		t.Fatalf("非回环 http 验证地址 error = %v，期望 ErrOptionsInvalid", err)
	}
	base.DeviceVerificationURI = ""
	unconfigured, err := oauthflow.New(base)
	if err != nil {
		t.Fatalf("构造未配置验证地址的服务失败：%v", err)
	}
	if _, err := unconfigured.BeginDeviceAuthorization(env.ctx,
		oauthflow.DeviceAuthorizationRequest{ClientID: testAppID,
			Scope: []string{"profile.read"}, Resource: []string{testAudience},
			RequestID: "req_dev_unconfigured"}); deviceProtocolCode(t, err) !=
		"temporarily_unavailable" {
		t.Fatalf("未配置验证地址申请 error = %v，期望 temporarily_unavailable", err)
	}
	// 启用设备流但缺少短码 HMAC 密钥环：拒绝构造（低熵短码不允许无密钥摘要）。
	noKeyring := env.flowOptionsForTest()
	noKeyring.DeviceUserCodeKeyring = nil
	if _, err := oauthflow.New(noKeyring); !errors.Is(err, oauthflow.ErrOptionsInvalid) {
		t.Fatalf("缺少设备短码密钥环 error = %v，期望 ErrOptionsInvalid", err)
	}
}

// TestDeviceUserCodeDigestKeyed 验证低熵短码以带密钥 HMAC 摘要落库（不是明文、
// 也不是无密钥 SHA-256），并记录 key_id 支持轮换。
func TestDeviceUserCodeDigestKeyed(t *testing.T) {
	env := newDeviceEnv(t, oauthclient.ClientTypePublic)
	start := env.beginDevice(t, oauthflow.DeviceAuthorizationRequest{})
	normalized := strings.ReplaceAll(start.UserCode.Reveal(), "-", "")
	unkeyed := sha256.Sum256([]byte(normalized))
	digestHex := env.queryString(`SELECT hex(user_code_digest) FROM oauth_device_authorizations`)
	keyID := env.queryString(`SELECT user_code_key_id FROM oauth_device_authorizations`)
	if digestHex == "" || len(digestHex) != 64 {
		t.Fatalf("user_code_digest 长度异常：%q", digestHex)
	}
	if digestHex == hex.EncodeToString(unkeyed[:]) {
		t.Fatal("短码摘要等于无密钥 SHA-256（违反低熵验证码约束）")
	}
	if digestHex == hex.EncodeToString([]byte(normalized)) {
		t.Fatal("短码摘要保存了明文")
	}
	if keyID == "" || keyID != env.deviceKeyring.CurrentKeyID() {
		t.Fatalf("user_code_key_id = %q，期望当前密钥 %q", keyID, env.deviceKeyring.CurrentKeyID())
	}
	// 正确短码仍可定位到请求；另一个格式合法但错误的短码必须拒绝。
	if _, err := env.flow.DescribeDeviceAuthorization(env.ctx, env.sessionSecret,
		start.UserCode.Reveal(), "req_dev_keyed_ok"); err != nil {
		t.Fatalf("正确短码查询失败：%v", err)
	}
	// 使用不同密钥环的服务无法命中同一库中的记录（证明密钥参与摘要）。
	otherKeyring, err := secrets.GenerateKeyring("device-code-other", env.now)
	if err != nil {
		t.Fatalf("生成其它密钥环失败：%v", err)
	}
	otherOptions := env.flowOptionsForTest()
	otherOptions.DeviceUserCodeKeyring = otherKeyring
	otherService, err := oauthflow.New(otherOptions)
	if err != nil {
		t.Fatalf("构造其它密钥服务失败：%v", err)
	}
	if _, err := otherService.DescribeDeviceAuthorization(env.ctx, env.sessionSecret,
		start.UserCode.Reveal(), "req_dev_keyed_other"); !errors.Is(err,
		oauthflow.ErrDeviceAuthorizationNotFound) {
		t.Fatalf("不同密钥环命中记录 error = %v，期望 NotFound（fail-closed）", err)
	}
}

// TestDeviceUserCodeKeyringRotation 验证密钥轮换：旧记录在旧密钥仍在密钥环时可
// 核对，旧密钥移除后 fail-closed 不再命中；新请求使用新当前密钥。
func TestDeviceUserCodeKeyringRotation(t *testing.T) {
	env := newDeviceEnv(t, oauthclient.ClientTypePublic)
	old := env.beginDevice(t, oauthflow.DeviceAuthorizationRequest{})
	oldKeyID := env.queryString(`SELECT user_code_key_id FROM oauth_device_authorizations`)

	// 轮换：新密钥成为当前写密钥，旧密钥保留为历史读密钥。
	material, err := secrets.GenerateKeyMaterial()
	if err != nil {
		t.Fatalf("生成轮换密钥材料失败：%v", err)
	}
	rotated, err := env.deviceKeyring.RotateTo("device-code-k2", material, env.now)
	if err != nil {
		t.Fatalf("轮换密钥环失败：%v", err)
	}
	rotatedOptions := env.flowOptionsForTest()
	rotatedOptions.DeviceUserCodeKeyring = rotated
	rotatedService, err := oauthflow.New(rotatedOptions)
	if err != nil {
		t.Fatalf("构造轮换后服务失败：%v", err)
	}
	// 旧 pending 请求仍可用旧短码核对（key_id 随行支持历史验证）。
	if _, err := rotatedService.DescribeDeviceAuthorization(env.ctx, env.sessionSecret,
		old.UserCode.Reveal(), "req_dev_rotate_old"); err != nil {
		t.Fatalf("轮换后旧短码查询失败：%v", err)
	}
	// 新请求使用新当前密钥。
	if _, err := rotatedService.BeginDeviceAuthorization(env.ctx,
		oauthflow.DeviceAuthorizationRequest{ClientID: testAppID,
			Scope: []string{"profile.read"}, Resource: []string{testAudience},
			RequestID: "req_dev_rotate_new"}); err != nil {
		t.Fatalf("轮换后新申请失败：%v", err)
	}
	if got := env.queryString(`SELECT user_code_key_id FROM oauth_device_authorizations
WHERE id<>?`, old.RequestID); got != "device-code-k2" {
		t.Fatalf("新记录 key_id = %q，期望 device-code-k2（旧记录 key_id=%q）", got, oldKeyID)
	}
	// 移除旧密钥后，旧记录不再命中（fail-closed：短码失效，不误放行）。
	withoutOld, err := rotated.WithoutKey("device-code-k1")
	if err != nil {
		t.Fatalf("移除旧密钥失败：%v", err)
	}
	withoutOptions := env.flowOptionsForTest()
	withoutOptions.DeviceUserCodeKeyring = withoutOld
	withoutService, err := oauthflow.New(withoutOptions)
	if err != nil {
		t.Fatalf("构造移除旧密钥服务失败：%v", err)
	}
	if _, err := withoutService.DescribeDeviceAuthorization(env.ctx, env.sessionSecret,
		old.UserCode.Reveal(), "req_dev_rotate_removed"); !errors.Is(err,
		oauthflow.ErrDeviceAuthorizationNotFound) {
		t.Fatalf("旧密钥移除后查询 error = %v，期望 NotFound（fail-closed）", err)
	}
}

// ---------- 测试辅助 ----------

// flowOptionsForTest 返回与当前测试环境一致、可修改的 oauthflow.Options。
func (e *testEnv) flowOptionsForTest() oauthflow.Options {
	return oauthflow.Options{
		Store: e.flowStore, Audit: e.audit, Clients: e.source,
		ClientAuth: e.clientAuth, Sessions: e.session, Tokens: e.tokens,
		Reauth: e.reAuth, DeviceVerificationURI: "https://login.example.test/device",
		DeviceUserCodeKeyring: e.deviceKeyring,
		Now:                   func() time.Time { return e.now },
	}
}

// containsString 报告切片是否包含指定值（测试辅助）。
func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
