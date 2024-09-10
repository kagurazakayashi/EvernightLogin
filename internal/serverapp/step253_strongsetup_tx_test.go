package serverapp

// 步骤 253（R10-18/R10-19）生产适配器定向测试：真实 OpenBase/SQLite 存储验证
//   - 强初始化完成事务内的“账户代际 + 重绑需求代际”条件清除：需求被新恢复申请
//     替换、安全版本变化、账户非 active 时整事务回滚，绝不静默清掉新需求；
//   - 事务内“本次新绑定”复核使用同一审计事务读取，绑定被停用后返回 false；
//   - 需求快照读取只返回未清除需求。
// 测试数据为合成用户/需求/绑定，不含真实秘密；只在本进程临时 SQLite 中运行。

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authfact"
	"github.com/kagurazakayashi/EvernightLogin/internal/mfa"
)

const step253TargetID = "usr_0000000000000000000000000000f253"

// openStep253Base 打开真实生产装配并插入一个 active 普通用户与重绑需求。
func openStep253Base(t *testing.T, requiredAtMS int64, sourceRequestID string) *Base {
	t.Helper()
	ctx := context.Background()
	base, err := OpenBase(ctx, BaseOptions{
		Config: baseTestConfig(t), Keyring: newTestKeyring(t), Migrate: true,
		Logger: baseTestLogger(), Now: func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatalf("OpenBase: %v", err)
	}
	t.Cleanup(func() { _ = base.Close(context.Background()) })
	nowMS := testNow.UnixMilli()
	if _, err := base.Store.DB().ExecContext(ctx, `INSERT INTO users(
id,username,username_normalized,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'active',0,1,1,?,?)`,
		step253TargetID, "step253-rebind", "step253-rebind", nowMS, nowMS); err != nil {
		t.Fatalf("插入用户: %v", err)
	}
	if requiredAtMS > 0 {
		if _, err := base.Store.DB().ExecContext(ctx, `INSERT INTO mfa_rebind_requirements(
user_id,required_at_ms,reason_code,source_request_id,cleared_at_ms) VALUES(?,?,?,?,NULL)`,
			step253TargetID, requiredAtMS, mfaRebindReasonManualRecovery, sourceRequestID); err != nil {
			t.Fatalf("写入重绑需求: %v", err)
		}
	}
	return base
}

// step253AuditChange 在真实审计事务内执行 change，返回 change 的错误。
func step253AuditChange(base *Base, change audit.Change) error {
	event := audit.Event{
		Actor:  audit.Actor{Type: audit.ActorSystem, ID: "step253-test"},
		Action: "mfa.step253_finalize", Target: audit.Target{Type: "user", ID: step253TargetID},
		RequestID: "req_step253_finalize",
	}
	return base.Deps.Audit.ExecuteCritical(context.Background(), audit.CriticalRequest{
		Event:               event,
		FailureReasonCode:   "mfa.step253_finalize_failed",
		FailureErrorCodeFor: func(error) string { return "INTERNAL_ERROR" },
	}, change)
}

// reboundRequirementState 返回当前未清除需求数量与源申请编号。
func reboundRequirementState(t *testing.T, base *Base) (int, string) {
	t.Helper()
	var count int
	var source string
	if err := base.Store.DB().QueryRowContext(context.Background(),
		`SELECT COUNT(*),COALESCE(MAX(source_request_id),'') FROM mfa_rebind_requirements
WHERE user_id=? AND cleared_at_ms IS NULL`, step253TargetID).Scan(&count, &source); err != nil {
		t.Fatalf("读取重绑需求状态: %v", err)
	}
	return count, source
}

// TestStep253FinalizeStrongSetupConditionalClear 验证按快照代际条件清除需求，且在
// 需求被替换/账户安全代际变化/账户禁用时整事务回滚、不清掉新需求。
func TestStep253FinalizeStrongSetupConditionalClear(t *testing.T) {
	ctx := context.Background()
	base := openStep253Base(t, testNow.UnixMilli(), "req_recovery_original")
	rebind := mfaRebindRequirementStore{store: base.Store, audit: base.Deps.Audit, logger: base.Deps.Logger}

	// 1) 快照只读取未清除需求。
	snapshot, err := rebind.RebindRequirementSnapshot(ctx, step253TargetID)
	if err != nil || !snapshot.Present || snapshot.SourceRequestID != "req_recovery_original" {
		t.Fatalf("需求快照 = %+v err=%v", snapshot, err)
	}

	// 2) 完成期间出现新的恢复申请（替换代际）：旧完成必须失败且不清除新需求。
	if _, err := base.Store.DB().ExecContext(ctx, `UPDATE mfa_rebind_requirements
SET required_at_ms=?,source_request_id=? WHERE user_id=?`,
		testNow.UnixMilli()+5000, "req_recovery_newer", step253TargetID); err != nil {
		t.Fatalf("替换新需求: %v", err)
	}
	err = step253AuditChange(base, func(txCtx context.Context, tx audit.Tx) error {
		return rebind.FinalizeStrongSetupTx(txCtx, tx, step253TargetID, snapshot, 1)
	})
	if !errors.Is(err, errRebindRequirementConflict) {
		t.Fatalf("需求代际被替换时应冲突回滚: %v", err)
	}
	if count, source := reboundRequirementState(t, base); count != 1 || source != "req_recovery_newer" {
		t.Fatalf("新恢复需求不得被旧完成清除: count=%d source=%q", count, source)
	}

	// 3) 安全版本变化（例如再次 MFA 重置）：必须回滚。
	current, err := rebind.RebindRequirementSnapshot(ctx, step253TargetID)
	if err != nil || !current.Present {
		t.Fatalf("读取当前需求: %+v err=%v", current, err)
	}
	if _, err := base.Store.DB().ExecContext(ctx,
		`UPDATE users SET security_version=security_version+1 WHERE id=?`, step253TargetID); err != nil {
		t.Fatalf("递增安全版本: %v", err)
	}
	err = step253AuditChange(base, func(txCtx context.Context, tx audit.Tx) error {
		return rebind.FinalizeStrongSetupTx(txCtx, tx, step253TargetID, current, 1)
	})
	if !errors.Is(err, errRebindSecurityStateChanged) {
		t.Fatalf("安全版本变化时应回滚: %v", err)
	}
	if count, _ := reboundRequirementState(t, base); count != 1 {
		t.Fatalf("安全版本变化时不得清除需求: %d", count)
	}

	// 4) 使用当前安全版本（2）与最新代际：条件清除成功且只清一次。
	latest, err := rebind.RebindRequirementSnapshot(ctx, step253TargetID)
	if err != nil || !latest.Present {
		t.Fatalf("读取最新需求: %+v err=%v", latest, err)
	}
	if err := step253AuditChange(base, func(txCtx context.Context, tx audit.Tx) error {
		return rebind.FinalizeStrongSetupTx(txCtx, tx, step253TargetID, latest, 2)
	}); err != nil {
		t.Fatalf("条件清除应成功: %v", err)
	}
	if count, _ := reboundRequirementState(t, base); count != 0 {
		t.Fatalf("需求应已清除: %d", count)
	}
	cleared, err := rebind.RebindRequirementSnapshot(ctx, step253TargetID)
	if err != nil || cleared.Present {
		t.Fatalf("已清除需求不应出现在快照: %+v err=%v", cleared, err)
	}

	// 5) 重复完成（旧快照/已清除）幂等失败，不产生误成功。
	err = step253AuditChange(base, func(txCtx context.Context, tx audit.Tx) error {
		return rebind.FinalizeStrongSetupTx(txCtx, tx, step253TargetID, latest, 2)
	})
	if !errors.Is(err, errRebindRequirementConflict) {
		t.Fatalf("已清除后旧快照应冲突: %v", err)
	}
}

// TestStep253StrongFactorBoundInTransaction 验证生产“本次新绑定”判定在审计事务
// 内读取同一数据库：绑定激活后为 true，停用后为 false，且判定失败不伪造成功。
func TestStep253StrongFactorBoundInTransaction(t *testing.T) {
	ctx := context.Background()
	base := openStep253Base(t, 0, "")
	nowMS := testNow.UnixMilli()
	if _, err := base.Store.DB().ExecContext(ctx, `INSERT INTO totp_bindings(
id,user_id,status,sealed_secret,algorithm,digits,period_seconds,window_steps,
last_accepted_step,attempts,max_attempts,expires_at_ms,created_at_ms,updated_at_ms,activated_at_ms)
VALUES(?,?,'active',X'01020304','SHA1',6,30,1,-1,0,5,?,?,?,?)`,
		"tfb_00000000000000000000000000000001", step253TargetID,
		nowMS+600000, nowMS, nowMS, nowMS+1000); err != nil {
		t.Fatalf("插入 active TOTP 绑定: %v", err)
	}
	verifier := strongFactorSource{store: base.Store}
	since := testNow.Add(-time.Minute)
	var bound bool
	if err := step253AuditChange(base, func(txCtx context.Context, tx audit.Tx) error {
		result, err := verifier.StrongFactorBoundAfterTx(txCtx, tx, step253TargetID,
			authfact.MethodTOTP, since)
		bound = result
		return err
	}); err != nil || !bound {
		t.Fatalf("事务内应判定为新绑定: bound=%v err=%v", bound, err)
	}
	// 绑定在预检查后、提交前被停用：事务内复核必须 false（fail-closed）。
	if _, err := base.Store.DB().ExecContext(ctx,
		`UPDATE totp_bindings SET status='disabled' WHERE user_id=? AND status='active'`,
		step253TargetID); err != nil {
		t.Fatalf("停用绑定: %v", err)
	}
	bound = true
	if err := step253AuditChange(base, func(txCtx context.Context, tx audit.Tx) error {
		result, err := verifier.StrongFactorBoundAfterTx(txCtx, tx, step253TargetID,
			authfact.MethodTOTP, since)
		bound = result
		return err
	}); err != nil || bound {
		t.Fatalf("绑定停用后事务内复核应为 false: bound=%v err=%v", bound, err)
	}
	// 固化 mfa 接口实现关系，防止适配器签名漂移后静默退化为“存在性检查”。
	var _ mfa.StrongSetupFinalizer = rebindForCompileCheck{}
	var _ mfa.StrongSetupBindingVerifierTx = strongFactorSource{}
}

// rebindForCompileCheck 只用于接口编译期断言。
type rebindForCompileCheck struct{}

func (rebindForCompileCheck) RebindRequirementSnapshot(context.Context,
	string) (mfa.RebindRequirementSnapshot, error) {
	return mfa.RebindRequirementSnapshot{}, nil
}

func (rebindForCompileCheck) FinalizeStrongSetupTx(context.Context, audit.Tx, string,
	mfa.RebindRequirementSnapshot, int64) error {
	return nil
}
