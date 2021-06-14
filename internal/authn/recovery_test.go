package authn_test

import (
	"context"
	"errors"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
)

// TestResetPasswordForRecoveryRealPath 使用真实 authn 服务覆盖找回重置：仅 system
// 调用者、密码策略/历史检查、安全版本递增、旧密码失效、新密码可登录、禁用账户拒绝。
func TestResetPasswordForRecoveryRealPath(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	userID := env.insertUser("resetuser", account.StatusActive, false)
	env.setPassword(userID, "OldPass!Tr9x", false)
	before := int64(env.queryInt(`SELECT security_version FROM users WHERE id=?`, userID))

	// 普通用户身份不能调用找回重置（必须走 SetPassword 的完整敏感策略）。
	userCaller, err := authn.UserCaller(userID)
	if err != nil {
		t.Fatalf("用户调用者: %v", err)
	}
	if _, err := env.service.ResetPasswordForRecovery(ctx, userCaller, authn.RecoveryResetRequest{
		UserID: userID, NewPassword: "NewPass!Kq7v", RequestID: "req-reset-denied"}); !errors.Is(err, authn.ErrAccessDenied) {
		t.Fatalf("普通用户找回重置错误 = %v，期望 ErrAccessDenied", err)
	}
	// system 调用者：弱密码拒绝。
	if _, err := env.service.ResetPasswordForRecovery(ctx, env.systemCaller, authn.RecoveryResetRequest{
		UserID: userID, NewPassword: "123456", RequestID: "req-reset-weak"}); !errors.Is(err, authn.ErrWeakPassword) {
		t.Fatalf("弱密码错误 = %v，期望 ErrWeakPassword", err)
	}
	// 正常重置：安全版本递增，旧密码失效，新密码可登录。
	result, err := env.service.ResetPasswordForRecovery(ctx, env.systemCaller, authn.RecoveryResetRequest{
		UserID: userID, NewPassword: "NewPass!Kq7v", RequestID: "req-reset-ok"})
	if err != nil {
		t.Fatalf("找回重置: %v", err)
	}
	if result.SecurityVersion <= before {
		t.Errorf("安全版本未递增: %d → %d", before, result.SecurityVersion)
	}
	if _, err := env.authenticate("resetuser", "OldPass!Tr9x", "203.0.113.8"); err == nil {
		t.Error("旧密码重置后仍可登录")
	}
	if _, err := env.authenticate("resetuser", "NewPass!Kq7v", "203.0.113.8"); err != nil {
		t.Fatalf("新密码登录失败: %v", err)
	}
	// 禁用账户拒绝。
	disabledID := env.insertUser("disableduser", account.StatusDisabled, false)
	env.setPassword(disabledID, "SomePass!Wm4z", false)
	if _, err := env.service.ResetPasswordForRecovery(ctx, env.systemCaller, authn.RecoveryResetRequest{
		UserID: disabledID, NewPassword: "Another!Pz8w", RequestID: "req-reset-disabled"}); err == nil {
		t.Error("禁用账户找回重置不应成功")
	}
}
