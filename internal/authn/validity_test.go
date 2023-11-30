package authn_test

// 步骤 234：认证入口的账户有效期即时校验测试。
//
// 覆盖 valid_from 未到、valid_until 到期（半开区间右端）、无期限成功，以及失败
// 不依赖定时扫描；使用真实临时 SQLite、真实密码校验与可注入时钟。

import (
	"context"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
)

// setUserValidity 直接写库模拟管理员已设置的有效期（便于精确边界测试）。
func setUserValidity(t *testing.T, env *testEnv, userID string,
	validFrom, validUntil *time.Time) {
	t.Helper()
	var fromMS, untilMS any
	if validFrom != nil {
		fromMS = validFrom.UTC().UnixMilli()
	}
	if validUntil != nil {
		untilMS = validUntil.UTC().UnixMilli()
	}
	if _, err := env.raw.DB().ExecContext(context.Background(),
		`UPDATE users SET valid_from_ms=?, valid_until_ms=? WHERE id=?`,
		fromMS, untilMS, userID); err != nil {
		t.Fatalf("写入有效期夹具: %v", err)
	}
}

// TestAuthnLoginEnforcesValidity 验证登录在三个边界时刻的即时判定。
func TestAuthnLoginEnforcesValidity(t *testing.T) {
	env := newTestEnv(t)
	userID := env.insertUser("validity-authn", account.StatusActive, false)
	env.setPassword(userID, testPassword, false)
	// 无期限：正常登录。
	if _, err := env.authenticate("validity-authn", testPassword, "127.0.0.1"); err != nil {
		t.Fatalf("无期限登录应成功: %v", err)
	}
	now := env.clock.Now().UTC()
	// valid_until = now：半开区间右端，立即拒绝。
	setUserValidity(t, env, userID, nil, &now)
	if _, err := env.authenticate("validity-authn", testPassword, "127.0.0.1"); err == nil {
		t.Fatal("到期当刻登录应拒绝")
	}
	// 到期前成功；到期后失败。
	before := now.Add(-time.Millisecond)
	setUserValidity(t, env, userID, nil, &before)
	if _, err := env.authenticate("validity-authn", testPassword, "127.0.0.1"); err == nil {
		t.Fatal("已到期登录应拒绝")
	}
	// valid_from 未到：拒绝；到左端当刻成功。
	from := now.Add(time.Hour)
	setUserValidity(t, env, userID, &from, nil)
	if _, err := env.authenticate("validity-authn", testPassword, "127.0.0.1"); err == nil {
		t.Fatal("未开始区间登录应拒绝")
	}
	env.clock.Advance(time.Hour)
	if _, err := env.authenticate("validity-authn", testPassword, "127.0.0.1"); err != nil {
		t.Fatalf("valid_from 当刻登录应成功: %v", err)
	}
	// 手动禁用仍优先拒绝（期限与状态分离）。
	if _, err := env.raw.DB().ExecContext(context.Background(),
		`UPDATE users SET status='disabled' WHERE id=?`, userID); err != nil {
		t.Fatalf("禁用夹具: %v", err)
	}
	if _, err := env.authenticate("validity-authn", testPassword, "127.0.0.1"); err == nil {
		t.Fatal("手动禁用登录应拒绝")
	}
}
