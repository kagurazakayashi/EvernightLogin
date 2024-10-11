package recovery_test

// 步骤 288 本地维护恢复代码状态/撤销定向测试。
//
// 覆盖：生成恢复代码后本地维护可读状态与撤销全部代码（无本人近期强认证）、
// 撤销后组不可用、重复撤销 ErrNoActiveGroup、非法目标/空身份拒绝。

import (
	"errors"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/recovery"
)

// TestLocalMaintenanceRecoveryCodes 覆盖本地维护恢复代码撤销。
func TestLocalMaintenanceRecoveryCodes(t *testing.T) {
	env := newTestEnv(t, nil)
	env.seedUser(userID, false, "user@example.test")
	codes := env.generate()
	if len(codes) == 0 {
		t.Fatal("生成恢复代码失败")
	}
	localCaller, err := recovery.NewLocalMaintenanceCaller("os:tester@local")
	if err != nil {
		t.Fatalf("本地维护身份: %v", err)
	}
	status, err := env.service.LocalMaintenanceRecoveryStatus(env.ctx, localCaller, userID)
	if err != nil {
		t.Fatalf("读取恢复代码状态: %v", err)
	}
	if !status.HasActiveGroup || status.RemainingCodes != len(codes) {
		t.Fatalf("恢复代码状态异常: %+v codes=%d", status, len(codes))
	}
	if err := env.service.LocalMaintenanceRevokeRecoveryCodes(env.ctx, localCaller,
		userID, "req-local-recovery-revoke"); err != nil {
		t.Fatalf("本地撤销恢复代码: %v", err)
	}
	status, err = env.service.LocalMaintenanceRecoveryStatus(env.ctx, localCaller, userID)
	if err != nil {
		t.Fatalf("撤销后读取状态: %v", err)
	}
	if status.HasActiveGroup {
		t.Fatalf("撤销后不应有 active 组: %+v", status)
	}
	if err := env.service.LocalMaintenanceRevokeRecoveryCodes(env.ctx, localCaller,
		userID, "req-local-recovery-revoke-again"); !errors.Is(err,
		recovery.ErrNoActiveGroup) {
		t.Fatalf("重复撤销错误 = %v，期望 ErrNoActiveGroup", err)
	}
	if _, err := env.service.LocalMaintenanceRecoveryStatus(env.ctx, localCaller,
		"bad-id"); !errors.Is(err, recovery.ErrInvalidRequest) {
		t.Fatalf("非法目标错误 = %v，期望 ErrInvalidRequest", err)
	}
	if err := env.service.LocalMaintenanceRevokeRecoveryCodes(env.ctx,
		recovery.LocalMaintenanceCaller{}, userID, "req-x"); !errors.Is(
		err, recovery.ErrAccessDenied) {
		t.Fatalf("空本地身份错误 = %v，期望 ErrAccessDenied", err)
	}
}
