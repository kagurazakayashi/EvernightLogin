package qrlogin_test

// 步骤 92 验收探针：APP 扫码登录的跨用户绑定与一次性领取验收。
// 复用既有真实测试环境（临时 SQLite、迁移、真实会话/应用/客户端登记/审计服务），
// 补充步骤 92 能力矩阵中的「扫码绑定、确认、领取、跨用户」项：
//   - 不同用户 APP 确认后，领取到的会话主体必须是确认者本人，不得混淆为其他用户；
//   - 同一请求只允许成功领取一次；
//   - 领取时才校验账户当前状态，确认后被停用的用户不得领到可用会话。
//
// 边界：进程内真实服务验收，不是部署后的 HTTP 端点，也无真实手机 APP/浏览器实测。

import (
	"errors"
	"testing"

	. "github.com/kagurazakayashi/EvernightLogin/internal/qrlogin"
)

// TestStep92QRAcrossUserAndSingleClaim 覆盖跨用户确认与一次性领取。
func TestStep92QRAcrossUserAndSingleClaim(t *testing.T) {
	env := newTestEnv(t)
	// 合成数据默认只给 testUser 建立应用成员关系；跨用户确认需要第二用户也是本应用
	// 成员（真实登录语义要求成员关系有效）。
	now := testStart.UnixMilli()
	if _, err := env.raw.ExecContext(env.ctx, `INSERT INTO app_memberships(
app_id,user_id,status,profile_json,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,'active','{"v":1}',1,?,?)`, testAppOne, testOtherUser, now, now); err != nil {
		t.Fatalf("建立第二用户应用成员关系失败: %v", err)
	}
	// 两个不同用户都持有本应用作用域的已登录 APP 会话。
	sessionA := env.loginApp(testUser, testAppOne)
	_ = sessionA
	sessionB := env.loginApp(testOtherUser, testAppOne)

	begin := env.begin()
	env.approve(begin, sessionB.Secret.Reveal())
	issued, err := env.service.Claim(env.ctx, claimRequest(begin))
	if err != nil {
		t.Fatalf("跨用户确认后领取失败: %v", err)
	}
	if issued.Session.UserID != testOtherUser {
		t.Fatalf("领取的会话主体 = %q，期望确认者 %q", issued.Session.UserID, testOtherUser)
	}
	if issued.Session.AppID != testAppOne {
		t.Fatalf("领取的会话应用 = %q，期望 %q", issued.Session.AppID, testAppOne)
	}
	if _, err := env.service.Claim(env.ctx, claimRequest(begin)); !errors.Is(err, ErrAlreadyClaimed) {
		t.Fatalf("重复领取应返回 ErrAlreadyClaimed，实际 %v", err)
	}
	// 领取到的会话可访问业务接口，且主体就是确认用户。
	validated, err := env.sessions.AuthorizeBusiness(env.ctx, issued.Secret.Reveal())
	if err != nil || validated.UserID != testOtherUser {
		t.Fatalf("领取会话应可访问业务接口且主体为确认者: %+v err=%v", validated, err)
	}

	// 确认后被停用的用户不得领到可用会话（领取时重新检查当前账户状态）。
	disabledBegin := env.begin()
	env.approve(disabledBegin, sessionB.Secret.Reveal())
	if _, err := env.raw.ExecContext(env.ctx,
		`UPDATE users SET status='disabled', security_version=security_version+1 WHERE id=?`,
		testOtherUser); err != nil {
		t.Fatalf("停用确认用户失败: %v", err)
	}
	if _, err := env.service.Claim(env.ctx, claimRequest(disabledBegin)); err == nil {
		t.Fatal("确认用户已停用，领取不应成功签发可用会话")
	}

	// 用户 A 并未参与上述请求：A 的独立请求仍可由 A 确认并领取 A 自己的会话。
	finalBegin := env.begin()
	env.approve(finalBegin, sessionA.Secret.Reveal())
	final, err := env.service.Claim(env.ctx, claimRequest(finalBegin))
	if err != nil || final.Session.UserID != testUser {
		t.Fatalf("用户 A 自身请求应领取到 A 的会话: %+v err=%v", final, err)
	}
}
