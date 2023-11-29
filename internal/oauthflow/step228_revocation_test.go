package oauthflow_test

// 步骤 228：RFC 7009 撤销的审计失败与刷新/撤销短并发边界。
//   - 关键审计不可用时撤销必须失败且不撤销刷新族（无虚假成功），修复后可重试；
//   - 刷新轮换与撤销并发时最终收敛为族撤销，不残留可用刷新令牌。

import (
	"errors"
	"sync"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
)

func TestRevokeTokenAuditFailureNoFalseSuccess(t *testing.T) {
	env := newTestEnv(t, oauthclient.ClientTypeConfidential)
	familyID := env.seedRefreshFamily(testAppID, testUserID, "oar_audit_revoke",
		"refresh-audit-failure")
	env.exec(`CREATE TRIGGER fail_audit_revoke BEFORE INSERT ON audit_events
BEGIN SELECT RAISE(ABORT,'模拟审计故障'); END`)
	err := env.flow.RevokeToken(env.ctx, oauthflow.RevokeTokenRequest{
		ClientID: testAppID, ClientSecret: "confidential-secret",
		Token: "refresh-audit-failure", RequestID: "req_revoke_audit_fail"})
	if err == nil {
		t.Fatal("审计失败时撤销不得报告成功")
	}
	var oauthErr *oauthflow.OAuthError
	if !errors.As(err, &oauthErr) || oauthErr.Code != "server_error" {
		t.Fatalf("审计失败撤销错误 = %T %v，期望 OAuth server_error", err, err)
	}
	if revokedAt := env.queryInt(`SELECT COALESCE(revoked_at_ms,0)
FROM refresh_token_families WHERE id=?`, familyID); revokedAt != 0 {
		t.Fatal("审计失败时不得撤销刷新族（事务应回滚）")
	}
	// 审计恢复后重试幂等成功，证明失败没有制造“已撤销”的假状态。
	env.exec(`DROP TRIGGER fail_audit_revoke`)
	if err := env.flow.RevokeToken(env.ctx, oauthflow.RevokeTokenRequest{
		ClientID: testAppID, ClientSecret: "confidential-secret",
		Token: "refresh-audit-failure", RequestID: "req_revoke_audit_retry"}); err != nil {
		t.Fatalf("审计恢复后重试撤销: %v", err)
	}
	if revokedAt := env.queryInt(`SELECT COALESCE(revoked_at_ms,0)
FROM refresh_token_families WHERE id=?`, familyID); revokedAt == 0 {
		t.Fatal("重试后刷新族仍未撤销")
	}
}

func TestRevokeRefreshConcurrentWithRotationConverges(t *testing.T) {
	env := newTestEnv(t, oauthclient.ClientTypePublic)
	env.enableRefreshClient()
	first := env.exchangeWithRefresh()
	if !first.RefreshToken.IsSet() {
		t.Fatal("测试前置：缺少刷新令牌")
	}
	oldSecret := first.RefreshToken.Reveal()
	var wait sync.WaitGroup
	var refreshResponse oauthflow.TokenResponse
	var refreshErr error
	var revokeErr error
	start := make(chan struct{})
	wait.Add(2)
	go func() {
		defer wait.Done()
		<-start
		refreshResponse, refreshErr = env.refresh(oldSecret, "req_race_refresh", nil, nil)
	}()
	go func() {
		defer wait.Done()
		<-start
		revokeErr = env.flow.RevokeToken(env.ctx, oauthflow.RevokeTokenRequest{
			ClientID: testAppID, Token: oldSecret,
			TokenTypeHint: "refresh_token", RequestID: "req_race_revoke"})
	}()
	close(start)
	wait.Wait()
	if revokeErr != nil {
		t.Fatalf("并发撤销返回错误: %v", revokeErr)
	}
	// 无论刷新先赢还是撤销先赢，最终刷新族必须已撤销；刷新成功产生的新令牌也不可用。
	if revoked := env.queryInt(`SELECT COUNT(*) FROM refresh_token_families
WHERE revoked_at_ms IS NOT NULL`); revoked < 1 {
		t.Fatal("并发刷新/撤销后刷新族未撤销")
	}
	if refreshErr == nil {
		if !refreshResponse.RefreshToken.IsSet() {
			t.Fatal("刷新成功但未返回新刷新令牌")
		}
		if _, err := env.refresh(refreshResponse.RefreshToken.Reveal(),
			"req_race_after", nil, nil); err == nil {
			t.Fatal("并发撤销后新刷新令牌仍可用")
		}
	}
	// 旧值也不得再可刷新。
	if _, err := env.refresh(oldSecret, "req_race_old", nil, nil); err == nil {
		t.Fatal("并发撤销后旧刷新令牌仍可用")
	}
}
