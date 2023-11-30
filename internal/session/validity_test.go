package session_test

// 步骤 234：会话 Validate/Renew/Login 的账户有效期即时校验测试。
//
// 覆盖发布会话后到期立即拒绝、续期后立即恢复、登录时到期拒绝、手动禁用优先，
// 证明不依赖定时扫描；有效期由真实数据库列 + 可注入时钟驱动。

import (
	"context"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// setSessionValidity 直接写库设置有效期夹具。
func setSessionValidity(t *testing.T, env *testEnv, userID string,
	validFrom, validUntil *time.Time) {
	t.Helper()
	var fromMS, untilMS any
	if validFrom != nil {
		fromMS = validFrom.UTC().UnixMilli()
	}
	if validUntil != nil {
		untilMS = validUntil.UTC().UnixMilli()
	}
	env.exec(`UPDATE users SET valid_from_ms=?, valid_until_ms=? WHERE id=?`,
		fromMS, untilMS, userID)
}

// TestSessionValidityImmediate 验证会话各入口的即时判定。
func TestSessionValidityImmediate(t *testing.T) {
	env := newTestEnv(t)
	userID := "usr_00000000000000000000000000000021"
	env.insertUser(userID, "validity-session", account.StatusActive, 1)
	issued := env.loginComplete(userID, 1)
	secret := issued.Secret.Reveal()
	if _, err := env.session.Validate(env.ctx, secret); err != nil {
		t.Fatalf("基线 Validate: %v", err)
	}
	now := env.clock.Now().UTC()
	// valid_until=now：右端半开，Validate/Renew/新登录均拒绝。
	setSessionValidity(t, env, userID, nil, &now)
	if _, err := env.session.Validate(env.ctx, secret); err == nil {
		t.Fatal("到期后 Validate 应拒绝")
	}
	if _, err := env.session.Renew(env.ctx, secret); err == nil {
		t.Fatal("到期后 Renew 应拒绝")
	}
	if _, err := env.session.Login(env.ctx, session.LoginRequest{
		Result: completeResult(userID, 1)}); err == nil {
		t.Fatal("到期后 Login 应拒绝")
	}
	// 续期（until 延后）当刻恢复：旧会话可继续使用，不必等定时器。
	until := now.Add(time.Hour)
	setSessionValidity(t, env, userID, nil, &until)
	if _, err := env.session.Validate(env.ctx, secret); err != nil {
		t.Fatalf("续期后 Validate 应恢复: %v", err)
	}
	// valid_from 未到：同样拒绝。
	from := env.clock.Now().UTC().Add(time.Hour)
	future := env.clock.Now().UTC().Add(2 * time.Hour)
	setSessionValidity(t, env, userID, &from, &future)
	if _, err := env.session.Validate(env.ctx, secret); err == nil {
		t.Fatal("未开始区间 Validate 应拒绝")
	}
	// 手动禁用优先于期限。
	env.exec(`UPDATE users SET status='disabled' WHERE id=?`, userID)
	setSessionValidity(t, env, userID, nil, nil)
	if _, err := env.session.Validate(env.ctx, secret); err == nil {
		t.Fatal("手动禁用后 Validate 应拒绝")
	}
}

// TestSessionValidityContextCancellation 验证取消语义不被判决吞掉。
func TestSessionValidityContextCancellation(t *testing.T) {
	env := newTestEnv(t)
	userID := "usr_00000000000000000000000000000022"
	env.insertUser(userID, "validity-session-cancel", account.StatusActive, 1)
	issued := env.loginComplete(userID, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := env.session.Validate(ctx, issued.Secret.Reveal()); err == nil {
		t.Fatal("取消的上下文不得返回成功")
	}
}
