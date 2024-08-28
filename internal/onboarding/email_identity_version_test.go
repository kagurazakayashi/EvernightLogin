package onboarding_test

// 步骤 250：邀请接受（新账户预验证邮箱）写入点的“已验证邮箱身份代际”递增测试。
//
// 邀请创建新账户时会在同一事务内写入已验证邮箱行；本步要求该“已验证邮箱身份”
// 建立时也单调递增 users.email_identity_version：
//   - 接受成功代际从 0 变为 1，且只递增一次；
//   - 验证失败/重复接受不创建账户、不产生代际变化；
//   - 邀请为既有用户加入应用（不写邮箱行）时不改变该用户代际。
//
// 邀请新账户在支持路径上先于任何密码找回入口存在，因此不存在可复活的旧链接；
// 代际前进保证身份建立前残留的旧绑定（迁移前旧行/恢复数据）不会因邮箱文本相同
// 而重新匹配（密码找回侧拒绝逻辑由 passwordreset 测试覆盖）。

import (
	"net/url"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/onboarding"
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

// acceptRequestFromMail 从邀请邮件解析接受参数并附加新账户字段。
func acceptRequestFromMail(t *testing.T, mail onboarding.InvitationEmail,
	username string) onboarding.AcceptRequest {
	t.Helper()
	parsed, err := url.Parse(mail.AcceptanceURL)
	if err != nil {
		t.Fatalf("解析接受入口: %v", err)
	}
	query := parsed.Query()
	return onboarding.AcceptRequest{
		InvitationID: query.Get("iid"), CredentialID: query.Get("cid"),
		Token: query.Get("token"),
		NewUser: &onboarding.NewUserRequest{
			Username: username, Password: "correct-horse-battery-9",
		},
	}
}

// TestInvitationAcceptanceAdvancesEmailIdentityVersion 验证邀请新账户接受成功使代际
// 从 0 递增到 1，失败/重复接受不递增。
func TestInvitationAcceptanceAdvancesEmailIdentityVersion(t *testing.T) {
	env := newTestEnv(t)
	const invitedEmail = "identity.invited@example.test"
	created, err := env.service.CreateInvitation(env.ctx, env.caller(t, inviterID),
		onboarding.CreateRequest{
			TargetEmail: invitedEmail,
			Roles:       []onboarding.Role{{RoleID: "role_system_member", ScopeID: "system"}},
		})
	if err != nil {
		t.Fatalf("创建邀请: %v", err)
	}
	mail := env.mail.lastInvitation(t)
	request := acceptRequestFromMail(t, mail, "identityinvited")

	// 错误令牌：拒绝且不创建账户（不产生代际）。
	tampered := request
	tampered.Token = mutateOnboardingToken(t, request.Token)
	if _, err := env.service.AcceptInvitation(env.ctx, onboarding.Caller{}, tampered); err == nil {
		t.Fatal("错误令牌接受邀请应拒绝")
	}
	if got := env.count(`SELECT COUNT(*) FROM user_emails WHERE email_normalized=?`, invitedEmail); got != 0 {
		t.Fatalf("失败接受不应写入邮箱行，实际 %d", got)
	}

	// 正确令牌：接受成功，新账户建立已验证邮箱身份，代际 = 1。
	accepted, err := env.service.AcceptInvitation(env.ctx, onboarding.Caller{}, request)
	if err != nil {
		t.Fatalf("接受邀请: %v", err)
	}
	if !accepted.NewUser || accepted.UserID == "" {
		t.Fatalf("接受结果异常: %+v", accepted)
	}
	if got := env.identityVersion(t, accepted.UserID); got != 1 {
		t.Fatalf("邀请接受后代际 = %d，期望 1", got)
	}
	if got := env.count(`SELECT COUNT(*) FROM user_emails
WHERE user_id=? AND email_normalized=? AND verified_at_ms IS NOT NULL`,
		accepted.UserID, invitedEmail); got != 1 {
		t.Fatalf("邀请接受后已验证邮箱行数 = %d，期望 1", got)
	}
	// 重复接受：令牌已消费，拒绝且不重复递增（账户未被二次创建）。
	if _, err := env.service.AcceptInvitation(env.ctx, onboarding.Caller{}, request); err == nil {
		t.Fatal("重复接受应拒绝")
	}
	if got := env.identityVersion(t, accepted.UserID); got != 1 {
		t.Fatalf("重复接受后代际 = %d，期望保持 1", got)
	}
	invitation, err := env.service.GetInvitation(env.ctx, env.caller(t, inviterID), created.Invitation.ID)
	if err != nil {
		t.Fatalf("查询邀请: %v", err)
	}
	if invitation.UsedCount != 1 {
		t.Fatalf("邀请使用次数 = %d，期望 1", invitation.UsedCount)
	}
}

// mutateOnboardingToken 翻转令牌首字符，构造“格式合法但内容不符”的错误令牌。
func mutateOnboardingToken(t *testing.T, token string) string {
	t.Helper()
	if strings.TrimSpace(token) == "" {
		t.Fatal("邀请令牌为空")
	}
	buffer := []byte(token)
	if buffer[0] == 'A' {
		buffer[0] = 'B'
	} else {
		buffer[0] = 'A'
	}
	return string(buffer)
}
