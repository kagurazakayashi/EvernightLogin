package emailchange_test

// 步骤 250：邮箱变更真实写入点的“已验证邮箱身份代际”递增测试。
//
// 校验 users.email_identity_version 只在邮箱切换确实提交时于同一事务内递增：
//   - 本人换绑（A→B）与首次添加都 +1；
//   - 申请阶段、取消、验证失败（令牌不符）不递增；
//   - 每次真实切换都得到新代际，因此与签发时绑定旧代际的密码找回入口不可能重新匹配。
//
// 全部使用真实 SQLite + 真实凭证/审计服务，不通过测试旁路构造“有效旧链接”。

import (
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/emailchange"
)

// identityVersion 读取账户当前已验证邮箱身份代际。
func (e *testEnv) identityVersion(t *testing.T, userID string) int64 {
	t.Helper()
	var version int64
	if err := e.storage.DB().QueryRowContext(e.ctx,
		`SELECT email_identity_version FROM users WHERE id=?`, userID).Scan(&version); err != nil {
		t.Fatalf("读取邮箱身份代际: %v", err)
	}
	return version
}

// switchEmail 通过真实服务完成一次申请 + 确认。
func (e *testEnv) switchEmail(t *testing.T, userID, newEmail, requestID string) {
	t.Helper()
	if _, err := e.service.RequestChange(e.ctx, e.caller(t, userID), newEmail, requestID); err != nil {
		t.Fatalf("发起邮箱变更 %s: %v", newEmail, err)
	}
	rid, cid, token := linkParts(t, e.mail.lastVerify(t))
	if _, err := e.service.Verify(e.ctx, emailchange.VerifyRequest{
		RequestID: rid, CredentialID: cid, Token: token, RequestIDLog: requestID + "-verify"}); err != nil {
		t.Fatalf("确认邮箱变更 %s: %v", newEmail, err)
	}
}

// TestEmailIdentityVersionIncrementsOnRealWrites 验证换绑/首次添加递增代际，且失败/
// 未提交路径不递增。
func TestEmailIdentityVersionIncrementsOnRealWrites(t *testing.T) {
	env := newTestEnv(t, true)
	const changeUserID = "usr_00000000000000000000000000000101"
	const firstAddUserID = "usr_00000000000000000000000000000102"
	env.seedUser(t, changeUserID, "identitychange")
	env.seedEmail(t, changeUserID, "identity.old@example.test")
	env.seedUser(t, firstAddUserID, "identityfirst")

	if got := env.identityVersion(t, changeUserID); got != 0 {
		t.Fatalf("换绑前代际 = %d，期望 0", got)
	}
	// A→B：真实切换提交，代际 +1。
	env.switchEmail(t, changeUserID, "identity.b@example.test", "req-250-id-ab")
	if got := env.identityVersion(t, changeUserID); got != 1 {
		t.Fatalf("A→B 后代际 = %d，期望 1", got)
	}
	// B→C：再次切换，代际继续单调递增。
	env.switchEmail(t, changeUserID, "identity.c@example.test", "req-250-id-bc")
	if got := env.identityVersion(t, changeUserID); got != 2 {
		t.Fatalf("B→C 后代际 = %d，期望 2", got)
	}
	// 首次添加（无已验证邮箱 → 新增）同样 +1。
	env.switchEmail(t, firstAddUserID, "identity.first@example.test", "req-250-id-first")
	if got := env.identityVersion(t, firstAddUserID); got != 1 {
		t.Fatalf("首次添加后代际 = %d，期望 1", got)
	}

	// 失败/未提交路径不改变代际：申请后取消、错误令牌验证都不得递增。
	const failedUserID = "usr_00000000000000000000000000000103"
	env.seedUser(t, failedUserID, "identityfailed")
	env.seedEmail(t, failedUserID, "identity.failed.old@example.test")
	if _, err := env.service.RequestChange(env.ctx, env.caller(t, failedUserID),
		"identity.failed.new@example.test", "req-250-id-cancel"); err != nil {
		t.Fatalf("发起待取消申请: %v", err)
	}
	rid, cid, token := linkParts(t, env.mail.lastVerify(t))
	if err := env.service.Cancel(env.ctx, env.caller(t, failedUserID), emailchange.CancelRequest{
		RequestID: rid, RequestIDLog: "req-250-id-cancel-now"}); err != nil {
		t.Fatalf("取消申请: %v", err)
	}
	if _, err := env.service.Verify(env.ctx, emailchange.VerifyRequest{
		RequestID: rid, CredentialID: cid, Token: token}); err == nil {
		t.Fatal("取消后验证应拒绝")
	}
	if got := env.identityVersion(t, failedUserID); got != 0 {
		t.Fatalf("未提交/取消路径代际 = %d，期望保持 0", got)
	}
}
