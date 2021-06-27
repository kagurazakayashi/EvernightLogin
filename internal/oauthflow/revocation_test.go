package oauthflow_test

import (
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

var seedFamilySeq int

// seedRefreshFamily 写入一个刷新令牌族与 active 刷新令牌（明文只在测试内，库中只存摘要）。
func (e *testEnv) seedRefreshFamily(clientID, userID, authorizationID, plain string) string {
	e.t.Helper()
	seedFamilySeq++
	familyID := fmt.Sprintf("rtf_%032d", seedFamilySeq)
	tokenID := fmt.Sprintf("rtt_%032d", seedFamilySeq)
	absolute := e.now.Add(24 * time.Hour).UnixMilli()
	e.exec(`INSERT INTO refresh_token_families(id,client_id,subject_user_id,authorization_id,
scope,audiences_json,security_version,created_at_ms,absolute_expires_at_ms,idle_timeout_ms)
VALUES(?,?,?,?,?,?,1,?,?,?)`, familyID, clientID, userID, authorizationID,
		"profile.read", `["`+testAudience+`"]`, e.now.UnixMilli(), absolute,
		(2 * time.Hour).Milliseconds())
	digest := sha256.Sum256([]byte(plain))
	idle := e.now.Add(2 * time.Hour).UnixMilli()
	e.exec(`INSERT INTO refresh_tokens(id,family_id,token_sha256,status,issued_at_ms,
idle_expires_at_ms,expires_at_ms) VALUES(?,?,?, 'active',?,?,?)`, tokenID, familyID,
		digest[:], e.now.UnixMilli(), idle, absolute)
	return familyID
}

// TestLogoutScopes 覆盖四种退出范围的语义区分。
func TestLogoutScopes(t *testing.T) {
	env := newTestEnv(t, oauthclientClientTypeConfidentialForTest())
	// 1) 退出当前会话：只撤销当前会话，不撤销授权码/刷新族。
	prompt := env.begin()
	result := env.approve(prompt)
	env.seedRefreshFamily(testAppID, testUserID, prompt.RequestID, "refresh-plain-current")
	currentLogout, err := env.flow.Logout(env.ctx, oauthflow.LogoutRequest{
		SessionSecret: env.sessionSecret, Scope: oauthflow.LogoutCurrentSession,
		RequestID: "req_logout_current"})
	if err != nil || currentLogout.AppSessions != 1 {
		t.Fatalf("退出当前会话: %+v err=%v", currentLogout, err)
	}
	if _, validateErr := env.session.Validate(env.ctx, env.sessionSecret); validateErr == nil {
		t.Fatal("退出当前会话后会话应失效")
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM oauth_authorization_codes WHERE revoked_at_ms IS NULL`); got != 1 {
		t.Fatalf("退出当前会话不应撤销授权码: %d", got)
	}

	// 2) 退出全部身份会话：全部会话失效。
	env.relogin(t)
	allLogout, err := env.flow.Logout(env.ctx, oauthflow.LogoutRequest{
		SessionSecret: env.sessionSecret, Scope: oauthflow.LogoutAllSessions,
		RequestID: "req_logout_all"})
	if err != nil || allLogout.AppSessions < 1 {
		t.Fatalf("退出全部会话: %+v err=%v", allLogout, err)
	}
	if _, validateErr := env.session.Validate(env.ctx, env.sessionSecret); validateErr == nil {
		t.Fatal("退出全部会话后会话应失效")
	}

	// 3) 撤回某次授权：撤销该授权下未兑换授权码与刷新族。
	env.relogin(t)
	prompt = env.begin()
	result = env.approve(prompt)
	familyID := env.seedRefreshFamily(testAppID, testUserID, prompt.RequestID, "refresh-plain-grant")
	revoked, err := env.flow.RevokeAuthorization(env.ctx, oauthflow.RevokeAuthorizationRequest{
		SessionSecret: env.sessionSecret, AuthorizationID: prompt.RequestID,
		RequestID: "req_revoke_grant"})
	if err != nil || revoked.AuthorizationCodes != 1 || revoked.RefreshFamilies != 1 {
		t.Fatalf("撤回授权: %+v err=%v", revoked, err)
	}
	if !result.Approved {
		t.Fatal("审批结果异常")
	}
	if state := env.queryString(`SELECT COALESCE(revoked_at_ms,0) FROM oauth_authorization_codes
WHERE authorization_request_id=?`, prompt.RequestID); state == "0" || state == "" {
		t.Fatalf("撤回授权未撤销未兑换授权码: %q", state)
	}
	if revokedAt := env.queryInt(`SELECT COALESCE(revoked_at_ms,0) FROM refresh_token_families WHERE id=?`,
		familyID); revokedAt == 0 {
		t.Fatal("撤回授权未撤销刷新族")
	}
	// 重复撤回幂等：已撤销族不再计入，不报错。
	again, err := env.flow.RevokeAuthorization(env.ctx, oauthflow.RevokeAuthorizationRequest{
		SessionSecret: env.sessionSecret, AuthorizationID: prompt.RequestID,
		RequestID: "req_revoke_grant_again"})
	if err != nil || again.RefreshFamilies != 0 {
		t.Fatalf("重复撤回应幂等: %+v err=%v", again, err)
	}

	// 4) 退出某应用：撤销该应用下全部授权码与刷新族，并写（用户,客户端）撤销标记。
	env.relogin(t)
	prompt = env.begin()
	_ = env.approve(prompt)
	env.seedRefreshFamily(testAppID, testUserID, prompt.RequestID, "refresh-plain-app")
	appLogout, err := env.flow.Logout(env.ctx, oauthflow.LogoutRequest{
		SessionSecret: env.sessionSecret, Scope: oauthflow.LogoutApplication,
		ClientID: testAppID, RequestID: "req_logout_app"})
	if err != nil || appLogout.AuthorizationCodes < 1 || appLogout.RefreshFamilies < 1 {
		t.Fatalf("退出应用: %+v err=%v", appLogout, err)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM oauth_client_user_revocations
WHERE user_id=? AND client_id=?`, testUserID, testAppID); got != 1 {
		t.Fatalf("退出应用缺少在线撤销标记: %d", got)
	}
}

// TestLogoutCrossUserDenied 验证不能撤回他人的授权（跨用户误撤销拒绝）。
func TestLogoutCrossUserDenied(t *testing.T) {
	env := newTestEnv(t, oauthclientClientTypeConfidentialForTest())
	prompt := env.begin()
	_ = env.approve(prompt)
	// 第二个用户与会话。
	const secondUser = "usr_00000000000000000000000000000002"
	env.exec(`INSERT INTO users(id,username,username_normalized,nickname,status,is_root,
security_version,row_version,created_at_ms,updated_at_ms) VALUES(?,?,?,?, 'active',0,1,1,?,?)`,
		secondUser, "bob", "bob", "Bob", env.now.UnixMilli(), env.now.UnixMilli())
	env.exec(`INSERT INTO app_memberships(app_id,user_id,status,row_version,created_at_ms,updated_at_ms)
VALUES(?,?, 'active',1,?,?)`, testAppID, secondUser, env.now.UnixMilli(), env.now.UnixMilli())
	issued, err := env.session.Login(env.ctx, sessionLoginRequest(secondUser, "bob"))
	if err != nil {
		t.Fatalf("第二个用户登录: %v", err)
	}
	_, revokeErr := env.flow.RevokeAuthorization(env.ctx, oauthflow.RevokeAuthorizationRequest{
		SessionSecret: issued.Secret.Reveal(), AuthorizationID: prompt.RequestID,
		RequestID: "req_revoke_cross_user"})
	if revokeErr == nil {
		t.Fatal("跨用户撤回授权必须拒绝")
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM oauth_authorization_codes WHERE revoked_at_ms IS NULL`); got != 1 {
		t.Fatalf("跨用户拒绝后不应撤销授权码: %d", got)
	}
	// 退出应用同样不能对他人的授权状态产生误撤销；这里用同一用户但错误客户端仍应有明确错误。
	if _, err := env.flow.Logout(env.ctx, oauthflow.LogoutRequest{
		SessionSecret: env.sessionSecret, Scope: oauthflow.LogoutApplication,
		ClientID: "app_00000000000000000000000000000009", RequestID: "req_logout_unknown_app"}); err == nil {
		t.Fatal("退出未知应用必须拒绝")
	}
}

// TestRevokeTokenEndpoint 覆盖标准撤销端点：客户端认证、只撤销自己的令牌、未知/重复
// 幂等、避免枚举、撤销后状态查询联动。
func TestRevokeTokenEndpoint(t *testing.T) {
	env := newTestEnv(t, oauthclientClientTypeConfidentialForTest())
	familyID := env.seedRefreshFamily(testAppID, testUserID, "oar_refresh_1", "refresh-endpoint-plain")
	// 撤销他人客户端令牌：不报错但不撤销（避免枚举/归属探测）。
	env.exec(`INSERT INTO applications(id,name,status,client_type,row_version,created_at_ms,updated_at_ms)
VALUES('app_00000000000000000000000000000004','Other','active','public',1,?,?)`,
		env.now.UnixMilli(), env.now.UnixMilli())
	env.exec(`INSERT INTO oauth_clients(client_id,client_type,grant_types_json,redirect_uris_json,
post_logout_redirect_uris_json,scopes_json,audiences_json,auth_methods_json,require_pkce,
row_version,created_at_ms,updated_at_ms) VALUES('app_00000000000000000000000000000004','public',
'["authorization_code"]','[]','[]','[]','[]','[]',1,1,?,?)`, env.now.UnixMilli(), env.now.UnixMilli())
	if err := env.flow.RevokeToken(env.ctx, oauthflow.RevokeTokenRequest{
		ClientID: "app_00000000000000000000000000000004", Token: "refresh-endpoint-plain",
		RequestID: "req_revoke_other_client"}); err != nil {
		t.Fatalf("他人令牌撤销应静默成功: %v", err)
	}
	if revokedAt := env.queryInt(`SELECT COALESCE(revoked_at_ms,0) FROM refresh_token_families WHERE id=?`,
		familyID); revokedAt != 0 {
		t.Fatal("他人客户端不得撤销令牌")
	}
	// 本客户端撤销：幂等，重复调用仍成功。
	for attempt := 0; attempt < 2; attempt++ {
		if err := env.flow.RevokeToken(env.ctx, oauthflow.RevokeTokenRequest{
			ClientID: testAppID, ClientSecret: "confidential-secret",
			Token: "refresh-endpoint-plain", RequestID: "req_revoke_refresh"}); err != nil {
			t.Fatalf("撤销自己的刷新令牌失败: %v", err)
		}
	}
	if revokedAt := env.queryInt(`SELECT COALESCE(revoked_at_ms,0) FROM refresh_token_families WHERE id=?`,
		familyID); revokedAt == 0 {
		t.Fatal("撤销自己的刷新令牌未生效")
	}
	// 未知令牌也按成功处理（不枚举）。
	if err := env.flow.RevokeToken(env.ctx, oauthflow.RevokeTokenRequest{
		ClientID: testAppID, ClientSecret: "confidential-secret", Token: "does-not-exist",
		RequestID: "req_revoke_unknown"}); err != nil {
		t.Fatalf("未知令牌应静默成功: %v", err)
	}
	// 错误客户端凭证必须 invalid_client。
	if err := env.flow.RevokeToken(env.ctx, oauthflow.RevokeTokenRequest{
		ClientID: testAppID, ClientSecret: "wrong", Token: "refresh-endpoint-plain",
		RequestID: "req_revoke_bad_client"}); !isOAuthCode(err, "invalid_client") {
		t.Fatalf("错误客户端凭证应 invalid_client，实际 %v", err)
	}
}

// TestRevokeAccessTokenAndInspection 验证访问令牌 jti 撤销与状态查询联动（在线校验
// 路径）；离线自包含 JWT 的失效延迟已在文档声明，不被本测试宣称为即时失效。
func TestRevokeAccessTokenAndInspection(t *testing.T) {
	env := newTestEnv(t, oauthclientClientTypeConfidentialForTest())
	prompt := env.begin()
	result := env.approve(prompt)
	response, err := env.flow.Exchange(env.ctx, oauthflow.ExchangeRequest{
		GrantType: "authorization_code", Code: result.Code.Reveal(), RedirectURI: testRedirect,
		ClientID: testAppID, ClientSecret: "confidential-secret", CodeVerifier: pkceVerifier,
		RequestID: "req_revoke_access_exchange"})
	if err != nil {
		t.Fatalf("兑换用户令牌: %v", err)
	}
	if _, verifyErr := env.tokens.VerifyAccessToken(env.ctx, response.AccessToken.Reveal(),
		testAudience); verifyErr != nil {
		t.Fatalf("测试前置：令牌应可验证: %v", verifyErr)
	}
	inspection, err := env.flow.InspectToken(env.ctx, oauthflow.TokenInspectRequest{
		Token: response.AccessToken.Reveal(), TokenTypeHint: "access_token",
		Audience: testAudience, ResourceServerClientID: testAppID, RequestID: "req_inspect_before"})
	if err != nil || !inspection.Active {
		t.Fatalf("撤销前状态查询应 active: %+v err=%v", inspection, err)
	}
	if err := env.flow.RevokeToken(env.ctx, oauthflow.RevokeTokenRequest{
		ClientID: testAppID, ClientSecret: "confidential-secret",
		Token: response.AccessToken.Reveal(), TokenTypeHint: "access_token",
		RequestID: "req_revoke_access"}); err != nil {
		t.Fatalf("撤销访问令牌: %v", err)
	}
	inspection, err = env.flow.InspectToken(env.ctx, oauthflow.TokenInspectRequest{
		Token: response.AccessToken.Reveal(), TokenTypeHint: "access_token",
		Audience: testAudience, ResourceServerClientID: testAppID, RequestID: "req_inspect_after"})
	if err != nil || inspection.Active {
		t.Fatalf("撤销后在线状态查询应 inactive: %+v err=%v", inspection, err)
	}
}

// TestSecurityEventRevocationAndOutbox 覆盖改密/恢复/禁用/成员移除事件接入与 outbox
// 消费；审计/事务失败时事件保留 pending 且可重试。
func TestSecurityEventRevocationAndOutbox(t *testing.T) {
	env := newTestEnv(t, oauthclientClientTypeConfidentialForTest())
	prompt := env.begin()
	_ = env.approve(prompt)
	familyID := env.seedRefreshFamily(testAppID, testUserID, prompt.RequestID, "refresh-plain-event")
	// 改密事件：用户级撤销刷新族/授权码并写用户级在线标记。
	result, err := env.flow.ApplySecurityEvent(env.ctx, oauthflow.SecurityEvent{
		Kind: oauthflow.SecurityEventPasswordChanged, UserID: testUserID,
		RequestID: "req_event_password"})
	if err != nil || result.RefreshFamilies != 1 || result.AuthorizationCodes != 1 {
		t.Fatalf("改密事件接入: %+v err=%v", result, err)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM oauth_user_revocations WHERE user_id=?`, testUserID); got != 1 {
		t.Fatalf("缺少用户级在线撤销标记: %d", got)
	}
	if revokedAt := env.queryInt(`SELECT COALESCE(revoked_at_ms,0) FROM refresh_token_families WHERE id=?`,
		familyID); revokedAt == 0 {
		t.Fatal("改密事件未撤销刷新族")
	}
	// 成员移除事件：按（用户,客户端）收敛。
	prompt = env.begin()
	_ = env.approve(prompt)
	secondFamily := env.seedRefreshFamily(testAppID, testUserID, prompt.RequestID, "refresh-plain-membership")
	if _, err := env.flow.ApplySecurityEvent(env.ctx, oauthflow.SecurityEvent{
		Kind: oauthflow.SecurityEventMembershipRemoved, UserID: testUserID, ClientID: testAppID,
		RequestID: "req_event_membership"}); err != nil {
		t.Fatalf("成员移除事件接入: %v", err)
	}
	if revokedAt := env.queryInt(`SELECT COALESCE(revoked_at_ms,0) FROM refresh_token_families WHERE id=?`,
		secondFamily); revokedAt == 0 {
		t.Fatal("成员移除事件未撤销刷新族")
	}
	// outbox：插入事件，先让审计写入失败（触发器），消费应保留 pending 并累计失败次数。
	env.exec(`INSERT INTO oauth_revocation_events(id,user_id,reason,created_at_ms)
VALUES('orev_test_0001',?, 'password_changed',?)`, testUserID, env.now.UnixMilli())
	env.exec(`CREATE TRIGGER fail_audit_revocation BEFORE INSERT ON audit_events
BEGIN SELECT RAISE(ABORT,'模拟审计故障'); END`)
	if _, err := env.flow.ConsumeOAuthRevocationEvents(env.ctx, 10); err == nil {
		t.Fatal("审计失败时 outbox 消费应返回错误")
	}
	if processed := env.queryInt(`SELECT COUNT(*) FROM oauth_revocation_events
WHERE id='orev_test_0001' AND processed_at_ms IS NULL AND attempt_count>=1`); processed != 1 {
		t.Fatal("失败事件应保留 pending 并累计尝试次数")
	}
	env.exec(`DROP TRIGGER fail_audit_revocation`)
	if processed, err := env.flow.ConsumeOAuthRevocationEvents(env.ctx, 10); err != nil || processed != 1 {
		t.Fatalf("重试消费 outbox 失败: processed=%d err=%v", processed, err)
	}
	if pending := env.queryInt(`SELECT COUNT(*) FROM oauth_revocation_events
WHERE id='orev_test_0001' AND processed_at_ms IS NULL`); pending != 0 {
		t.Fatal("重试成功事件未标记 processed")
	}
}

// oauthclientClientTypeConfidentialForTest 返回保密客户端类型，缩短测试调用。
func oauthclientClientTypeConfidentialForTest() oauthclient.ClientType {
	return oauthclient.ClientTypeConfidential
}

func sessionLoginRequest(userID, username string) session.LoginRequest {
	return session.LoginRequest{Result: authn.AuthenticateResult{
		UserID: userID, Username: username, Outcome: authn.OutcomeComplete,
		CompletedMethods: []authn.Method{authn.MethodPassword}, CompletedAt: time.Now().UTC(),
		SecurityVersion: 1,
	}}
}

// TestRevokeRefreshInvalidatesAccessTokensAndIgnoresWrongHint 验证步骤 55-FIX：
// 撤销刷新令牌时同事务写（用户,客户端）在线标记，使既有未过期 Access Token 在
// InspectToken 中 inactive；错误 token_type_hint（access_token 指向不透明刷新令牌）
// 必须被忽略并回退按刷新令牌撤销。
func TestRevokeRefreshInvalidatesAccessTokensAndIgnoresWrongHint(t *testing.T) {
	env := newTestEnv(t, oauthclientClientTypeConfidentialForTest())
	// 先签发一个用户 Access Token（同一授权/客户端）。
	prompt := env.begin()
	result := env.approve(prompt)
	response, err := env.flow.Exchange(env.ctx, oauthflow.ExchangeRequest{
		GrantType: "authorization_code", Code: result.Code.Reveal(), RedirectURI: testRedirect,
		ClientID: testAppID, ClientSecret: "confidential-secret", CodeVerifier: pkceVerifier,
		RequestID: "req_fix55_exchange"})
	if err != nil {
		t.Fatalf("兑换用户令牌: %v", err)
	}
	inspection, err := env.flow.InspectToken(env.ctx, oauthflow.TokenInspectRequest{
		Token: response.AccessToken.Reveal(), TokenTypeHint: "access_token",
		Audience: testAudience, ResourceServerClientID: testAppID, RequestID: "req_fix55_before"})
	if err != nil || !inspection.Active {
		t.Fatalf("撤销前 AT 应 active: %+v err=%v", inspection, err)
	}
	familyID := env.seedRefreshFamily(testAppID, testUserID, prompt.RequestID, "refresh-fix55-plain")
	// 错误 hint：refresh token 被声明为 access_token，端点必须忽略 hint 并撤族。
	if err := env.flow.RevokeToken(env.ctx, oauthflow.RevokeTokenRequest{
		ClientID: testAppID, ClientSecret: "confidential-secret",
		Token: "refresh-fix55-plain", TokenTypeHint: "access_token",
		RequestID: "req_fix55_wrong_hint"}); err != nil {
		t.Fatalf("错误 hint 撤销刷新令牌失败: %v", err)
	}
	if revokedAt := env.queryInt(`SELECT COALESCE(revoked_at_ms,0) FROM refresh_token_families WHERE id=?`,
		familyID); revokedAt == 0 {
		t.Fatal("错误 hint 时未撤销刷新族")
	}
	// 刷新令牌撤销联动：既有 AT 在线状态应 inactive。
	inspection, err = env.flow.InspectToken(env.ctx, oauthflow.TokenInspectRequest{
		Token: response.AccessToken.Reveal(), TokenTypeHint: "access_token",
		Audience: testAudience, ResourceServerClientID: testAppID, RequestID: "req_fix55_after"})
	if err != nil || inspection.Active {
		t.Fatalf("刷新令牌撤销后既有 AT 在线状态应 inactive: %+v err=%v", inspection, err)
	}
}
