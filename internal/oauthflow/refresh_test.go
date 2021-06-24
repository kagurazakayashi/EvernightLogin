package oauthflow_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
)

// enableRefreshClient 把测试客户端登记为授权码 + refresh_token 且允许
// offline_access/profile.read/email.read（模拟生产登记）。
func (e *testEnv) enableRefreshClient() {
	e.exec(`UPDATE oauth_clients SET grant_types_json='["authorization_code","refresh_token"]',
scopes_json='["profile.read","email.read","offline_access"]' WHERE client_id=?`, testAppID)
}

// beginWithRefreshScopes 发起含 offline_access 的授权请求并批准，返回授权码。
func (e *testEnv) exchangeWithRefresh() oauthflow.TokenResponse {
	e.t.Helper()
	request := e.authorizeRequest()
	request.Scope = []string{"profile.read", "email.read", "offline_access"}
	request.RequestID = "req_refresh_begin"
	prompt, err := e.flow.BeginAuthorization(e.ctx, e.sessionSecret, request)
	if err != nil {
		e.t.Fatalf("发起刷新授权: %v", err)
	}
	result := e.approve(prompt)
	response, err := e.flow.Exchange(e.ctx, oauthflow.ExchangeRequest{
		GrantType: "authorization_code", Code: result.Code.Reveal(), RedirectURI: testRedirect,
		ClientID: testAppID, CodeVerifier: pkceVerifier, RequestID: "req_refresh_exchange"})
	if err != nil {
		e.t.Fatalf("授权码兑换: %v", err)
	}
	return response
}

// refresh 用给定刷新令牌请求轮换。
func (e *testEnv) refresh(refreshToken, requestID string, scope, resource []string) (oauthflow.TokenResponse, error) {
	return e.flow.Exchange(e.ctx, oauthflow.ExchangeRequest{
		GrantType: "refresh_token", ClientID: testAppID, RefreshToken: refreshToken,
		Scope: scope, Resource: resource, RequestID: requestID})
}

// inspectAuthorizer 是令牌状态查询授权器测试替身。
type inspectAuthorizer struct {
	allow        bool
	showSubject  bool
	err          error
	lastAudience string
}

func (f *inspectAuthorizer) AuthorizeInspection(_ context.Context, _, audience string) (oauthflow.InspectPermission, error) {
	f.lastAudience = audience
	if f.err != nil {
		return oauthflow.InspectPermission{}, f.err
	}
	return oauthflow.InspectPermission{Allowed: f.allow, ShowSubject: f.showSubject}, nil
}

// inspectClientAuthorizer 是资源服务→客户端关系授权器测试替身。
type inspectClientAuthorizer struct {
	allow map[string]bool
	err   error
}

func (f *inspectClientAuthorizer) AuthorizeClientInspection(_ context.Context,
	resourceServerClientID, clientID, audience string) error {
	if f.err != nil {
		return f.err
	}
	if f.allow == nil || !f.allow[resourceServerClientID+"|"+clientID] {
		return errors.New("关系未获准")
	}
	return nil
}

// buildInspectFlow 构造带令牌验证与状态查询授权器的流程服务（复用同一存储/依赖）。
func (e *testEnv) buildInspectFlow(authorizer oauthflow.InspectAuthorizer,
	relationship oauthflow.InspectClientAuthorizer) *oauthflow.Service {
	e.t.Helper()
	service, err := oauthflow.New(oauthflow.Options{
		Store: e.flowStore, Audit: e.audit, Clients: e.source,
		ClientAuth: e.clientAuth, Sessions: e.session, Tokens: e.tokens,
		Reauth: e.reAuth, TokenVerifier: e.tokens, InspectAuthorizer: authorizer,
		InspectClientAuthorizer: relationship,
		Now:                     func() time.Time { return e.now },
	})
	if err != nil {
		e.t.Fatalf("状态查询流程服务: %v", err)
	}
	return service
}

// TestRefreshTokenRotationAndReplay 验证轮换、旧值重放撤销整族、库只存摘要。
func TestRefreshTokenRotationAndReplay(t *testing.T) {
	env := newTestEnv(t, oauthclient.ClientTypePublic)
	env.enableRefreshClient()
	first := env.exchangeWithRefresh()
	if !first.RefreshToken.IsSet() {
		t.Fatal("授权码兑换应签发刷新令牌")
	}
	oldSecret := first.RefreshToken.Reveal()
	if env.queryInt(`SELECT COUNT(*) FROM refresh_tokens WHERE status='active'`) != 1 {
		t.Fatal("应存在一个 active 刷新令牌")
	}
	// 数据库只保存摘要，不出现明文。
	if env.queryString(`SELECT hex(token_sha256) FROM refresh_tokens LIMIT 1`) == "" ||
		strings.Contains(env.queryString(`SELECT hex(token_sha256) FROM refresh_tokens LIMIT 1`), oldSecret) {
		t.Fatal("刷新令牌摘要异常或疑似存明文")
	}
	rotated, err := env.refresh(oldSecret, "req_rotate_1", nil, nil)
	if err != nil {
		t.Fatalf("刷新轮换: %v", err)
	}
	if !rotated.RefreshToken.IsSet() || rotated.RefreshToken.Reveal() == oldSecret {
		t.Fatal("轮换必须返回新的刷新令牌")
	}
	if env.queryInt(`SELECT COUNT(*) FROM refresh_tokens WHERE status='used'`) != 1 ||
		env.queryInt(`SELECT COUNT(*) FROM refresh_tokens WHERE status='active'`) != 1 {
		t.Fatal("旧令牌应 used、新令牌应 active")
	}
	// 旧值再次使用：重放检测撤销整族。
	if _, err := env.refresh(oldSecret, "req_replay_1", nil, nil); !isOAuthCode(err, "invalid_grant") {
		t.Fatalf("旧刷新令牌重用应 invalid_grant，得到 %v", err)
	}
	if env.queryInt(`SELECT COUNT(*) FROM refresh_token_families WHERE revoked_at_ms IS NOT NULL`) != 1 {
		t.Fatal("重放后令牌族应被撤销")
	}
	if env.queryInt(`SELECT COUNT(*) FROM refresh_tokens WHERE status='active'`) != 0 {
		t.Fatal("重放后不得存在 active 刷新令牌")
	}
	// 新令牌也随族撤销而失效。
	if _, err := env.refresh(rotated.RefreshToken.Reveal(), "req_after_replay", nil, nil); !isOAuthCode(err, "invalid_grant") {
		t.Fatalf("族撤销后新令牌应失效，得到 %v", err)
	}
	if !strings.Contains(env.auditDump(), "oauth.refresh.replayed") {
		t.Fatal("重放缺少审计")
	}
}

// TestRefreshConcurrentSingleWinner 验证并发刷新同一令牌只有一方成功；失败方按
// 重放处理撤销整族（无无限宽限）。
func TestRefreshConcurrentSingleWinner(t *testing.T) {
	env := newTestEnv(t, oauthclient.ClientTypePublic)
	env.enableRefreshClient()
	first := env.exchangeWithRefresh()
	secret := first.RefreshToken.Reveal()
	const workers = 4
	var wait sync.WaitGroup
	results := make([]error, workers)
	responses := make([]oauthflow.TokenResponse, workers)
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			responses[index], results[index] = env.refresh(secret, "req_concurrent_"+string(rune('a'+index)), nil, nil)
		}(index)
	}
	wait.Wait()
	successes := 0
	for _, err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("并发刷新成功次数 = %d，期望 1（%v）", successes, results)
	}
	if env.queryInt(`SELECT COUNT(*) FROM refresh_token_families WHERE revoked_at_ms IS NOT NULL`) != 1 {
		t.Fatal("并发失败方应触发族撤销")
	}
	if env.queryInt(`SELECT COUNT(*) FROM refresh_tokens WHERE status='active'`) != 0 {
		t.Fatal("并发冲突后不得残留 active 刷新令牌")
	}
}

// TestRefreshScopeExpansionAndClientMismatch 验证 scope 不得扩大、客户端错配拒绝。
func TestRefreshScopeExpansionAndClientMismatch(t *testing.T) {
	env := newTestEnv(t, oauthclient.ClientTypePublic)
	env.enableRefreshClient()
	first := env.exchangeWithRefresh()
	// 扩大 scope：invalid_scope，且不撤销族（旧令牌仍可用）。
	if _, err := env.refresh(first.RefreshToken.Reveal(), "req_expand_1",
		[]string{"profile.read", "admin.write"}, nil); !isOAuthCode(err, "invalid_scope") {
		t.Fatalf("扩大 scope 应 invalid_scope，得到 %v", err)
	}
	// 客户端错配：另一公开客户端使用同一刷新令牌。
	env.registerSecondClient()
	_, err := env.flow.Exchange(env.ctx, oauthflow.ExchangeRequest{
		GrantType: "refresh_token", ClientID: testAppID2,
		RefreshToken: first.RefreshToken.Reveal(), RequestID: "req_mismatch_1"})
	if !isOAuthCode(err, "invalid_grant") && !isOAuthCode(err, "unauthorized_client") {
		t.Fatalf("客户端错配应拒绝，得到 %v", err)
	}
	// 原客户端仍可正常缩减 scope 刷新（证明错配未误撤销）。
	if _, err := env.refresh(first.RefreshToken.Reveal(), "req_shrink_1",
		[]string{"profile.read"}, nil); err != nil {
		t.Fatalf("缩减 scope 刷新应成功: %v", err)
	}
}

// TestRefreshServiceTokenRejected 验证服务身份（client_credentials）不能刷新，且
// 授权码兑换才会创建刷新令牌族。
func TestRefreshServiceTokenRejected(t *testing.T) {
	env := newTestEnv(t, oauthclient.ClientTypeConfidential)
	// 服务客户端没有 refresh_token 登记：任何刷新请求都拒绝。
	serviceResponse, err := env.flow.Exchange(env.ctx, oauthflow.ExchangeRequest{
		GrantType: "client_credentials", ClientID: testAppID,
		ClientSecret: "confidential-secret", Scope: []string{"profile.read"},
		RequestID: "req_service_1"})
	if err != nil {
		t.Fatalf("client_credentials 签发服务令牌: %v", err)
	}
	if !serviceResponse.AccessToken.IsSet() {
		t.Fatal("服务令牌应签发")
	}
	if env.queryInt(`SELECT COUNT(*) FROM refresh_token_families`) != 0 {
		t.Fatal("client_credentials 不应创建刷新令牌族")
	}
	if _, err := env.refresh(serviceResponse.AccessToken.Reveal(), "req_service_refresh", nil, nil); !isOAuthCode(err, "unauthorized_client") {
		t.Fatalf("服务客户端刷新应拒绝，得到 %v", err)
	}
}

// TestRefreshIdleExpiry 验证刷新令牌空闲过期，且族绝对有效期不被突破。
func TestRefreshIdleExpiry(t *testing.T) {
	env := newTestEnv(t, oauthclient.ClientTypePublic)
	env.enableRefreshClient()
	first := env.exchangeWithRefresh()
	env.now = env.now.Add(8 * 24 * time.Hour) // 默认空闲 7 天
	if _, err := env.refresh(first.RefreshToken.Reveal(), "req_idle_expired", nil, nil); !isOAuthCode(err, "invalid_grant") {
		t.Fatalf("空闲过期应拒绝，得到 %v", err)
	}
	if env.queryInt(`SELECT COUNT(*) FROM refresh_tokens WHERE status='expired'`) != 1 {
		t.Fatal("空闲过期令牌应标记 expired")
	}
}

// TestRefreshUserDisabled 验证用户/成员状态变化撤销族并使令牌 inactive。
func TestRefreshUserDisabled(t *testing.T) {
	env := newTestEnv(t, oauthclient.ClientTypePublic)
	env.enableRefreshClient()
	first := env.exchangeWithRefresh()
	env.exec(`UPDATE users SET status='disabled' WHERE id=?`, testUserID)
	if _, err := env.refresh(first.RefreshToken.Reveal(), "req_disabled", nil, nil); !isOAuthCode(err, "invalid_grant") {
		t.Fatalf("用户停用后刷新应拒绝，得到 %v", err)
	}
	if env.queryInt(`SELECT COUNT(*) FROM refresh_token_families WHERE revoked_at_ms IS NOT NULL`) != 1 {
		t.Fatal("用户停用后令牌族应撤销（真实业务状态影响 active）")
	}
}

// TestRefreshTransactionFailureKeepsToken 验证审计/事务失败不消费旧令牌（可安全重试）。
func TestRefreshTransactionFailureKeepsToken(t *testing.T) {
	env := newTestEnv(t, oauthclient.ClientTypePublic)
	env.enableRefreshClient()
	first := env.exchangeWithRefresh()
	inject := &failingAudit{inner: env.audit, failCritical: 1}
	flow, err := oauthflow.New(oauthflow.Options{
		Store: env.flowStore, Audit: inject, Clients: env.source,
		ClientAuth: env.clientAuth, Sessions: env.session, Tokens: env.tokens,
		Reauth: env.reAuth, Now: func() time.Time { return env.now },
	})
	if err != nil {
		t.Fatalf("构造注入审计流程: %v", err)
	}
	if _, err := flow.Exchange(env.ctx, oauthflow.ExchangeRequest{
		GrantType: "refresh_token", ClientID: testAppID,
		RefreshToken: first.RefreshToken.Reveal(), RequestID: "req_tx_fail"}); !isOAuthCode(err, "temporarily_unavailable") {
		t.Fatalf("事务失败应 temporarily_unavailable，得到 %v", err)
	}
	// 旧令牌未被消费，故障后仍可正常刷新。
	if env.queryInt(`SELECT COUNT(*) FROM refresh_tokens WHERE status='active'`) != 1 {
		t.Fatal("事务失败后旧令牌应保持 active")
	}
	if _, err := env.refresh(first.RefreshToken.Reveal(), "req_tx_retry", nil, nil); err != nil {
		t.Fatalf("事务失败后重试应成功: %v", err)
	}
}

// failingAudit 在指定次数后注入审计事务失败。
type failingAudit struct {
	inner        oauthflow.AuditRecorder
	mu           sync.Mutex
	failCritical int
}

func (f *failingAudit) Record(ctx context.Context, event audit.Event) error {
	return f.inner.Record(ctx, event)
}

func (f *failingAudit) RecordFailure(ctx context.Context, event audit.Event) error {
	return f.inner.RecordFailure(ctx, event)
}

func (f *failingAudit) ExecuteCritical(ctx context.Context, request audit.CriticalRequest, change audit.Change) error {
	f.mu.Lock()
	if f.failCritical > 0 {
		f.failCritical--
		f.mu.Unlock()
		return oauthflow.ErrStoreUnavailable
	}
	f.mu.Unlock()
	return f.inner.ExecuteCritical(ctx, request, change)
}

// TestInspectTokenPrivacyAndActivity 验证状态查询的授权/披露裁剪与 active 变化。
func TestInspectTokenPrivacyAndActivity(t *testing.T) {
	env := newTestEnv(t, oauthclient.ClientTypePublic)
	env.enableRefreshClient()
	authorizer := &inspectAuthorizer{allow: true, showSubject: false}
	inspectFlow := env.buildInspectFlow(authorizer, nil)
	first := env.exchangeWithRefresh()
	// Access Token 查询：默认不披露用户主体。
	inspection, err := inspectFlow.InspectToken(env.ctx, oauthflow.TokenInspectRequest{
		Token: first.AccessToken.Reveal(), Audience: testAudience,
		ResourceServerClientID: "app_000000000000000000000000000000aa",
		RequestID:              "req_inspect_1"})
	if err != nil {
		t.Fatalf("状态查询: %v", err)
	}
	if !inspection.Active || inspection.ClientID != testAppID || inspection.Subject != "" {
		t.Fatalf("状态查询结果/隐私裁剪异常: %+v", inspection)
	}
	// 授权器允许披露时才返回用户主体。
	authorizer.showSubject = true
	inspection, err = inspectFlow.InspectToken(env.ctx, oauthflow.TokenInspectRequest{
		Token: first.AccessToken.Reveal(), Audience: testAudience,
		ResourceServerClientID: "app_000000000000000000000000000000aa",
		RequestID:              "req_inspect_2"})
	if err != nil || inspection.Subject != testUserID {
		t.Fatalf("允许披露时应返回主体: %v %+v", err, inspection)
	}
	// 刷新令牌状态查询（不透明）：需资源服务与该客户端关系授权；默认不披露主体。
	refreshFlow := env.buildInspectFlow(authorizer, &inspectClientAuthorizer{
		allow: map[string]bool{"app_000000000000000000000000000000aa|" + testAppID: true},
	})
	refreshInspection, err := refreshFlow.InspectToken(env.ctx, oauthflow.TokenInspectRequest{
		Token: first.RefreshToken.Reveal(), TokenTypeHint: "refresh_token",
		Audience:               testAudience,
		ResourceServerClientID: "app_000000000000000000000000000000aa",
		RequestID:              "req_inspect_refresh"})
	if err != nil || !refreshInspection.Active || refreshInspection.TokenType != "refresh_token" {
		t.Fatalf("刷新令牌状态查询异常: %v %+v", err, refreshInspection)
	}
	// 未授权调用者拒绝。
	denied := &inspectAuthorizer{allow: false}
	deniedFlow := env.buildInspectFlow(denied, nil)
	if _, err := deniedFlow.InspectToken(env.ctx, oauthflow.TokenInspectRequest{
		Token: first.AccessToken.Reveal(), Audience: testAudience,
		ResourceServerClientID: "app_000000000000000000000000000000aa",
		RequestID:              "req_inspect_denied"}); !isOAuthCode(err, "access_denied") {
		t.Fatalf("未授权查询应拒绝，得到 %v", err)
	}
	// 无效/过期令牌统一 active=false（不提供区别化细节）。
	invalid, err := inspectFlow.InspectToken(env.ctx, oauthflow.TokenInspectRequest{
		Token: "invalid-token", Audience: testAudience,
		ResourceServerClientID: "app_000000000000000000000000000000aa",
		RequestID:              "req_inspect_invalid"})
	if err != nil || invalid.Active {
		t.Fatalf("无效令牌应 active=false，得到 %v %+v", err, invalid)
	}
	// 撤销族后 Access Token 查询仍遵循令牌自身有效性（JWT 无状态），但刷新令牌查询
	// inactive；用户停用等业务变化影响后续 active（文档声明 active 不等于可执行）。
	env.exec(`UPDATE refresh_token_families SET revoked_at_ms=?,revoke_reason='test'`, env.now.UnixMilli())
	refreshInspection, err = refreshFlow.InspectToken(env.ctx, oauthflow.TokenInspectRequest{
		Token: first.RefreshToken.Reveal(), TokenTypeHint: "refresh_token",
		Audience:               testAudience,
		ResourceServerClientID: "app_000000000000000000000000000000aa",
		RequestID:              "req_inspect_revoked"})
	if err != nil || refreshInspection.Active {
		t.Fatalf("族撤销后刷新令牌应 inactive: %v %+v", err, refreshInspection)
	}
}

// TestInspectRefreshTokenPrivacyBoundary 验证 54-FIX：刷新令牌元数据查询必须
// 声明属于令牌族的 audience 且资源服务与所属客户端存在可信关系；否则不披露任何
// 元数据（跨应用探测拒绝）。
func TestInspectRefreshTokenPrivacyBoundary(t *testing.T) {
	env := newTestEnv(t, oauthclient.ClientTypePublic)
	env.enableRefreshClient()
	authorizer := &inspectAuthorizer{allow: true, showSubject: true}
	first := env.exchangeWithRefresh()
	resourceServer := "app_000000000000000000000000000000aa"
	relationship := &inspectClientAuthorizer{allow: map[string]bool{
		resourceServer + "|" + testAppID: true,
	}}
	flow := env.buildInspectFlow(authorizer, relationship)
	query := func(token, audience, server string) oauthflow.TokenInspection {
		t.Helper()
		inspection, err := flow.InspectToken(env.ctx, oauthflow.TokenInspectRequest{
			Token: token, TokenTypeHint: "refresh_token", Audience: audience,
			ResourceServerClientID: server, RequestID: "req_inspect_boundary"})
		if err != nil {
			t.Fatalf("状态查询不应返回协议错误（统一 inactive）: %v", err)
		}
		return inspection
	}
	// 合法资源服务 + 匹配 audience：返回元数据与主体。
	valid := query(first.RefreshToken.Reveal(), testAudience, resourceServer)
	if !valid.Active || valid.ClientID != testAppID || valid.Subject != testUserID {
		t.Fatalf("合法查询结果异常: %+v", valid)
	}
	// audience 不属于该族：inactive 且不披露元数据。
	mismatch := query(first.RefreshToken.Reveal(), "https://other.example.test", resourceServer)
	if mismatch.Active || mismatch.ClientID != "" || mismatch.Scope != "" || mismatch.Subject != "" {
		t.Fatalf("audience 不匹配不得披露元数据: %+v", mismatch)
	}
	// 缺少 audience：inactive。
	missing := query(first.RefreshToken.Reveal(), "", resourceServer)
	if missing.Active || missing.ClientID != "" {
		t.Fatalf("缺少 audience 不得披露元数据: %+v", missing)
	}
	// 跨应用资源服务（关系未获准）：inactive 且不披露元数据/用户身份。
	cross := query(first.RefreshToken.Reveal(), testAudience, "app_000000000000000000000000000000bb")
	if cross.Active || cross.ClientID != "" || cross.Subject != "" {
		t.Fatalf("跨应用查询不得披露元数据: %+v", cross)
	}
	// 未注入关系授权器：fail-closed，不披露元数据。
	noRelationship := env.buildInspectFlow(authorizer, nil)
	inspection, err := noRelationship.InspectToken(env.ctx, oauthflow.TokenInspectRequest{
		Token: first.RefreshToken.Reveal(), TokenTypeHint: "refresh_token",
		Audience: testAudience, ResourceServerClientID: resourceServer,
		RequestID: "req_inspect_no_rel"})
	if err != nil || inspection.Active || inspection.ClientID != "" {
		t.Fatalf("未注入关系授权器应 fail-closed: %v %+v", err, inspection)
	}
	if !strings.Contains(env.auditDump(), "resource_server_client_relationship_denied") {
		t.Fatal("跨应用拒绝缺少失败审计")
	}
}

// auditDump 读取审计动作+原因码（用于断言拒绝留痕）。
func (e *testEnv) auditDump() string {
	e.t.Helper()
	rows, err := e.raw.QueryContext(e.ctx,
		`SELECT action||'|'||COALESCE(reason_code,'') FROM audit_events`)
	if err != nil {
		e.t.Fatalf("读取审计: %v", err)
	}
	defer rows.Close()
	var builder strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			e.t.Fatalf("扫描审计: %v", err)
		}
		builder.WriteString(line + "\n")
	}
	return builder.String()
}
