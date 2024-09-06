package profile_test

// 步骤 256：直接管理他人用户名的领域能力定向测试。
//
// 覆盖：合法计划准备/事务内条件更名（规范化 display + 唯一性 + 行版本 + 更名时间）、
// 同名/等价名、目标不存在、root 目标、过渡态目标、行版本冲突、并发/计划复用、
// 伪造非规范计划与计划过期。使用真实临时 SQLite + 真实审计事务，不涉及授权证明
//（授权与两步验证证明由 app 门面接入）。

import (
	"context"
	"errors"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/profile"
)

const (
	managementOperatorID = "usr_0000000000000000000000000000d001"
	managementTargetID   = "usr_0000000000000000000000000000d002"
)

// atomicRename 在真实审计事务内应用计划并返回更新后的资料。
func (e *testEnv) managementRename(t *testing.T, plan profile.ManagementRenamePlan) (profile.UserProfile, error) {
	t.Helper()
	caller := audit.Actor{Type: audit.ActorSystem, ID: "direct-user-management-test"}
	var updated profile.UserProfile
	err := e.recorder.ExecuteCritical(e.ctx, audit.CriticalRequest{
		Event: audit.Event{
			Actor: caller, Action: "test.direct_username_change",
			Target: audit.Target{Type: "user", ID: plan.TargetUserID},
		},
		FailureReasonCode: "test.direct_username_change_failed",
	}, func(txCtx context.Context, tx audit.Tx) error {
		value, applyErr := e.service.ApplyManagementRenameTx(txCtx, tx, plan)
		if applyErr != nil {
			return applyErr
		}
		updated = value
		return nil
	})
	return updated, err
}

// prepareRename 断言准备成功。
func (e *testEnv) prepareRename(t *testing.T, newUsername string, expectedVersion int64) profile.ManagementRenamePlan {
	t.Helper()
	plan, err := e.service.PrepareManagementRename(e.ctx, profile.ManagementRenameRequest{
		OperatorUserID: managementOperatorID, TargetUserID: managementTargetID,
		NewUsername: newUsername, ExpectedRowVersion: expectedVersion, RequestID: "req-256-prepare",
	})
	if err != nil {
		t.Fatalf("准备直接管理更名: %v", err)
	}
	return plan
}

// TestManagementRenameSuccessAndRules 覆盖成功链与主要拒绝规则。
func TestManagementRenameSuccessAndRules(t *testing.T) {
	env := newTestEnv(t, nil)
	env.seedUser(t, managementOperatorID, "operator")
	env.seedUser(t, managementTargetID, "bob")

	// 成功：display 按既有 Unicode 规则规范化后写入，唯一性用规范化键；行版本 +1。
	plan := env.prepareRename(t, "Bóbby.New", 1)
	if plan.DisplayUsername != "Bóbby.New" || plan.NormalizedUsername == "" ||
		plan.BeforeUsername != "bob" || plan.ExpectedRowVersion != 1 {
		t.Fatalf("计划字段异常: %+v", plan)
	}
	updated, err := env.managementRename(t, plan)
	if err != nil {
		t.Fatalf("应用直接管理更名: %v", err)
	}
	if updated.Username != "Bóbby.New" || updated.RowVersion != 2 ||
		updated.UserID != managementTargetID || updated.IsRoot {
		t.Fatalf("更新结果异常: %+v", updated)
	}
	if updated.UsernameChangedAt.IsZero() {
		t.Error("直接管理更名应更新 username_changed_at（冷却基准仍保留）")
	}
	// 计划复用（版本已变化）→ 冲突。
	if _, reuseErr := env.managementRename(t, plan); !errors.Is(reuseErr, profile.ErrVersionConflict) {
		t.Fatalf("计划复用错误 = %v，期望 ErrVersionConflict", reuseErr)
	}

	// 同名/等价名：拒绝（规范化键与 display 均相同）。
	same := profile.ManagementRenameRequest{TargetUserID: managementTargetID,
		NewUsername: "Bóbby.New", ExpectedRowVersion: updated.RowVersion, RequestID: "req-256-same"}
	if _, prepareErr := env.service.PrepareManagementRename(env.ctx, same); !errors.Is(prepareErr, profile.ErrInvalidRequest) {
		t.Fatalf("同名更名错误 = %v，期望 ErrInvalidRequest", prepareErr)
	}
	// 等价规范化键但 display 不同（仅大小写/显示形式变化）→ 允许：身份键不变，
	// display 更新是直接管理可表达的显式变更（与本人受控更名口径一致）。
	equivalent := same
	equivalent.NewUsername = "bóbby.new"
	equivalentPlan, prepareErr := env.service.PrepareManagementRename(env.ctx, equivalent)
	if prepareErr != nil {
		t.Fatalf("仅 display 变化应允许: %v", prepareErr)
	}
	displayUpdated, applyErr := env.managementRename(t, equivalentPlan)
	if applyErr != nil {
		t.Fatalf("仅 display 变化应用失败: %v", applyErr)
	}
	if displayUpdated.Username != "bóbby.new" || displayUpdated.UsernameNormalized != updated.UsernameNormalized {
		t.Fatalf("display 变化结果异常: %+v", displayUpdated)
	}
	updated = displayUpdated
	// 占用的用户名：准备可以通过规范化，但事务内唯一性拒绝。
	occupied := profile.ManagementRenameRequest{TargetUserID: managementTargetID,
		NewUsername: "operator", ExpectedRowVersion: updated.RowVersion, RequestID: "req-256-taken"}
	occupiedPlan, prepareErr := env.service.PrepareManagementRename(env.ctx, occupied)
	if prepareErr != nil {
		t.Fatalf("占用名准备不应提前泄露占用状态: %v", prepareErr)
	}
	if _, applyErr := env.managementRename(t, occupiedPlan); !errors.Is(applyErr, profile.ErrUsernameTaken) {
		t.Fatalf("占用名应用错误 = %v，期望 ErrUsernameTaken", applyErr)
	}
	// 目标不存在。
	if _, prepareErr := env.service.PrepareManagementRename(env.ctx,
		profile.ManagementRenameRequest{TargetUserID: "usr_0000000000000000000000000000d0ff",
			NewUsername: "ghost", ExpectedRowVersion: 1, RequestID: "req-256-missing"}); !errors.Is(prepareErr, profile.ErrUserNotFound) {
		t.Fatalf("目标不存在错误 = %v，期望 ErrUserNotFound", prepareErr)
	}
	// 行版本不符。
	if _, prepareErr := env.service.PrepareManagementRename(env.ctx,
		profile.ManagementRenameRequest{TargetUserID: managementTargetID,
			NewUsername: "another.name", ExpectedRowVersion: 1, RequestID: "req-256-version"}); !errors.Is(prepareErr, profile.ErrVersionConflict) {
		t.Fatalf("行版本不符错误 = %v，期望 ErrVersionConflict", prepareErr)
	}
}

// TestManagementRenameProtectedTargets 覆盖 root 与过渡态目标拒绝。
func TestManagementRenameProtectedTargets(t *testing.T) {
	env := newTestEnv(t, nil)
	env.seedUser(t, managementOperatorID, "operator")
	// root 目标：插入唯一 root 账户。
	const rootTargetID = "usr_0000000000000000000000000000d003"
	if _, err := env.storage.DB().ExecContext(env.ctx, `INSERT INTO users(
id,username,username_normalized,nickname,biography,avatar_ref,language,timezone,status,is_root,
security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'','',NULL,'zh-CN','Asia/Shanghai','active',1,1,1,?,?)`,
		rootTargetID, "rootish", "rootish", testStart.UnixMilli(), testStart.UnixMilli()); err != nil {
		t.Fatalf("插入 root 目标: %v", err)
	}
	if _, err := env.service.PrepareManagementRename(env.ctx, profile.ManagementRenameRequest{
		TargetUserID: rootTargetID, NewUsername: "root.renamed",
		ExpectedRowVersion: 1, RequestID: "req-256-root-target"}); !errors.Is(err, profile.ErrTargetNotManageable) {
		t.Fatalf("root 目标错误 = %v，期望 ErrTargetNotManageable", err)
	}
	// 过渡态目标（pending / pending_delete）拒绝。
	env.seedUser(t, managementTargetID, "pending-target")
	if _, err := env.storage.DB().ExecContext(env.ctx,
		`UPDATE users SET status='pending' WHERE id=?`, managementTargetID); err != nil {
		t.Fatalf("设置过渡态: %v", err)
	}
	if _, err := env.service.PrepareManagementRename(env.ctx, profile.ManagementRenameRequest{
		TargetUserID: managementTargetID, NewUsername: "pending.renamed",
		ExpectedRowVersion: 1, RequestID: "req-256-pending"}); !errors.Is(err, profile.ErrTargetNotManageable) {
		t.Fatalf("过渡态目标错误 = %v，期望 ErrTargetNotManageable", err)
	}
}

// TestManagementRenamePlanIntegrity 覆盖伪造非规范计划与计划过期拒绝。
func TestManagementRenamePlanIntegrity(t *testing.T) {
	env := newTestEnv(t, nil)
	env.seedUser(t, managementOperatorID, "operator")
	env.seedUser(t, managementTargetID, "bob")
	plan := env.prepareRename(t, "new.display", 1)

	// 伪造：display 与规范化键不一致 → 拒绝（不得把非规范值写入用户名）。
	forged := plan
	forged.NormalizedUsername = "fake-normalized-key"
	if _, err := env.managementRename(t, forged); !errors.Is(err, profile.ErrInvalidRequest) {
		t.Fatalf("伪造计划错误 = %v，期望 ErrInvalidRequest", err)
	}
	// 伪造目标：改 UserID 但与 before 不匹配 → 拒绝。
	other := plan
	other.TargetUserID = managementOperatorID
	if _, err := env.managementRename(t, other); !errors.Is(err, profile.ErrInvalidRequest) &&
		!errors.Is(err, profile.ErrVersionConflict) && !errors.Is(err, profile.ErrTargetNotManageable) &&
		!errors.Is(err, profile.ErrUserNotFound) {
		t.Fatalf("伪造目标错误 = %v", err)
	}
	// 计划过期（超过 2 分钟 TTL）→ 拒绝；必须重新准备。
	env.now = env.now.Add(3 * 60 * 1e9)
	if _, err := env.managementRename(t, plan); !errors.Is(err, profile.ErrVersionConflict) {
		t.Fatalf("过期计划错误 = %v，期望 ErrVersionConflict", err)
	}
}
