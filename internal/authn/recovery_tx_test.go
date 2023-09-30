package authn_test

import (
	"context"
	"errors"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
)

// TestPrepareAndApplyRecoveryResetTx 覆盖步骤 205 的 authn 两阶段接口：
//   - PrepareRecoveryReset 只做校验与 Argon2 派生，不写库、不改变安全版本；
//   - ApplyRecoveryResetTx 在调用方事务内复核并写入密码、历史与安全版本；
//   - 准备到提交之间安全版本变化时返回 ErrRecoveryStateConflict，且不写入密码。
func TestPrepareAndApplyRecoveryResetTx(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	userID := env.insertUser("txresetuser", account.StatusActive, false)
	env.setPassword(userID, "OldPass!Tr9x", false)
	beforeVersion := int64(env.queryInt(`SELECT security_version FROM users WHERE id=?`, userID))
	beforeHash := queryPasswordHash(t, env, ctx, userID)

	prepared, err := env.service.PrepareRecoveryReset(ctx, env.systemCaller,
		authn.RecoveryResetRequest{
			UserID: userID, NewPassword: "NewPass!Kq7v", RequestID: "req-tx-prepare"})
	if err != nil {
		t.Fatalf("PrepareRecoveryReset: %v", err)
	}
	// 未提交前不得写库：安全版本与密码哈希保持不变。
	if version := querySecurityVersion(t, env, ctx, userID); version != beforeVersion {
		t.Fatalf("Prepare 改变了安全版本: %d → %d", beforeVersion, version)
	}
	if hash := queryPasswordHash(t, env, ctx, userID); hash != beforeHash {
		t.Fatal("Prepare 改变了密码哈希")
	}
	// 在同一关键审计事务内应用：与成功审计一致提交。
	critical := audit.CriticalRequest{Event: audit.Event{
		Actor:  audit.Actor{Type: audit.ActorSystem, ID: "authn-tx-test"},
		Action: string(authn.ActionPasswordRecoveryReset),
		Target: audit.Target{Type: "user", ID: userID}, Outcome: audit.OutcomeSuccess,
		RequestID: "req-tx-apply",
	}}
	var result authn.SetPasswordResult
	if err := env.recorder.ExecuteCritical(ctx, critical,
		func(txCtx context.Context, tx audit.Tx) error {
			applied, applyErr := env.service.ApplyRecoveryResetTx(
				txCtx, env.systemCaller, prepared, tx)
			if applyErr != nil {
				return applyErr
			}
			result = applied
			return nil
		}); err != nil {
		t.Fatalf("事务内应用找回改密: %v", err)
	}
	if result.SecurityVersion != beforeVersion+1 {
		t.Errorf("安全版本 = %d，期望 %d", result.SecurityVersion, beforeVersion+1)
	}
	if _, err := env.authenticate("txresetuser", "NewPass!Kq7v", "203.0.113.20"); err != nil {
		t.Fatalf("新密码认证失败: %v", err)
	}

	// 并发冲突：Prepare 之后安全版本被并发修改，事务内复核必须拒绝。
	prepared2, err := env.service.PrepareRecoveryReset(ctx, env.systemCaller,
		authn.RecoveryResetRequest{
			UserID: userID, NewPassword: "Another!Pz8w", RequestID: "req-tx-prepare-2"})
	if err != nil {
		t.Fatalf("第二次 PrepareRecoveryReset: %v", err)
	}
	if _, err := env.raw.DB().ExecContext(ctx,
		`UPDATE users SET security_version=security_version+1 WHERE id=?`, userID); err != nil {
		t.Fatalf("模拟并发安全版本变化: %v", err)
	}
	err = env.recorder.ExecuteCritical(ctx, critical,
		func(txCtx context.Context, tx audit.Tx) error {
			_, applyErr := env.service.ApplyRecoveryResetTx(
				txCtx, env.systemCaller, prepared2, tx)
			return applyErr
		})
	if !errors.Is(err, authn.ErrRecoveryStateConflict) {
		t.Fatalf("并发冲突错误 = %v，期望 ErrRecoveryStateConflict", err)
	}
	// 冲突提交未写入新密码：上一轮的新密码仍可登录。
	if _, err := env.authenticate("txresetuser", "NewPass!Kq7v", "203.0.113.20"); err != nil {
		t.Fatalf("冲突后原密码认证失败: %v", err)
	}
}

// querySecurityVersion 读取测试账户当前安全版本。
func querySecurityVersion(t *testing.T, env *testEnv, ctx context.Context, userID string) int64 {
	t.Helper()
	var version int64
	if err := env.raw.DB().QueryRowContext(ctx,
		`SELECT security_version FROM users WHERE id=?`, userID).Scan(&version); err != nil {
		t.Fatalf("读取安全版本: %v", err)
	}
	return version
}

// queryPasswordHash 读取测试账户当前密码哈希（只用于相等性比较，不记录）。
func queryPasswordHash(t *testing.T, env *testEnv, ctx context.Context, userID string) string {
	t.Helper()
	var hash string
	if err := env.raw.DB().QueryRowContext(ctx,
		`SELECT password_hash FROM password_credentials WHERE user_id=?`, userID).Scan(&hash); err != nil {
		t.Fatalf("读取密码哈希: %v", err)
	}
	return hash
}
