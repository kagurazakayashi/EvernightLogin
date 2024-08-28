package registration_test

// 步骤 250：注册首次邮箱验证写入点的“已验证邮箱身份代际”递增测试。
//
// 注册验证只处理“尚未验证 → 首次验证”的第一绑定，不会替换既有已验证邮箱，
// 因此在支持路径上不可能先存在绑定该身份的密码找回入口。这里直接断言：
//   - 验证成功在同一审计事务内把 users.email_identity_version 从 0 递增到 1；
//   - 失败/重放/取消路径不递增；
//   - 代际单调前进使任何在身份建立前残留的旧绑定（迁移前旧行/恢复数据）不可能
//     因“邮箱文本相同”而重新匹配（密码找回侧拒绝逻辑由 passwordreset 测试覆盖）。

import (
	"errors"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/registration"
)

// identityVersion 读取账户当前已验证邮箱身份代际。
func (e *testEnv) identityVersion(t *testing.T, id string) int64 {
	t.Helper()
	var version int64
	if err := e.storage.DB().QueryRowContext(e.ctx,
		`SELECT email_identity_version FROM users WHERE id=?`, id).Scan(&version); err != nil {
		t.Fatalf("读取邮箱身份代际: %v", err)
	}
	return version
}

// TestEmailVerificationAdvancesEmailIdentityVersion 验证注册首次验证成功后代际 +1，
// 失败与重放不改变代际。
func TestEmailVerificationAdvancesEmailIdentityVersion(t *testing.T) {
	env := newTestEnv(t, nil)
	registered := env.mustRegister(registration.RegisterRequest{
		Username: "identityverify", Email: "identity.verify@example.test",
		RequestID: "req-250-register",
	})
	if registered.UserID == "" {
		t.Fatal("注册未返回用户 ID")
	}
	if got := env.identityVersion(t, registered.UserID); got != 0 {
		t.Fatalf("验证前代际 = %d，期望 0（注册只写入未验证行）", got)
	}
	// 邮箱行在验证前确实未验证：代际递增与“已验证身份建立”严格同事务。
	if got := env.count(`SELECT COUNT(*) FROM user_emails
WHERE user_id=? AND email_normalized='identity.verify@example.test' AND verified_at_ms IS NULL`,
		registered.UserID); got != 1 {
		t.Fatalf("验证前未验证邮箱行数 = %d，期望 1", got)
	}
	request, _ := env.link(t)
	// 错误令牌：拒绝且不递增。
	tampered := request
	tampered.Token = mutateRegistrationToken(t, request.Token)
	if _, err := env.reg.VerifyEmail(env.ctx, tampered); !errors.Is(err, registration.ErrVerificationInvalid) {
		t.Fatalf("错误令牌验证错误 = %v，期望 ErrVerificationInvalid", err)
	}
	if got := env.identityVersion(t, registered.UserID); got != 0 {
		t.Fatalf("错误令牌后代际 = %d，期望保持 0", got)
	}
	// 正确令牌：首次验证成功，代际 +1。
	if _, err := env.reg.VerifyEmail(env.ctx, request); err != nil {
		t.Fatalf("首次邮箱验证: %v", err)
	}
	if got := env.identityVersion(t, registered.UserID); got != 1 {
		t.Fatalf("首次验证后代际 = %d，期望 1", got)
	}
	if got := env.count(`SELECT COUNT(*) FROM user_emails
WHERE user_id=? AND verified_at_ms IS NOT NULL`, registered.UserID); got != 1 {
		t.Fatalf("验证后已验证邮箱行数 = %d，期望 1", got)
	}
	// 重放同一入口：拒绝且不重复递增（代际仍为 1）。
	if _, err := env.reg.VerifyEmail(env.ctx, request); !errors.Is(err, registration.ErrVerificationInvalid) {
		t.Fatalf("重放验证错误 = %v，期望 ErrVerificationInvalid", err)
	}
	if got := env.identityVersion(t, registered.UserID); got != 1 {
		t.Fatalf("重放后代际 = %d，期望保持 1", got)
	}
}

// mutateRegistrationToken 翻转令牌首字符，构造“格式合法但内容不符”的错误令牌。
func mutateRegistrationToken(t *testing.T, token string) string {
	t.Helper()
	if token == "" {
		t.Fatal("验证令牌为空")
	}
	buffer := []byte(token)
	if buffer[0] == 'A' {
		buffer[0] = 'B'
	} else {
		buffer[0] = 'A'
	}
	return string(buffer)
}
