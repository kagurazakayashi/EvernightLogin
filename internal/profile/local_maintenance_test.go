package profile_test

// 步骤 287 本地维护 root 更名定向测试。
//
// 覆盖：本地维护身份成功更名 root（稳定 UserID/IsRoot 保持、username_changed_at
// 更新、行版本 +1）、普通直接管理路径仍拒绝 root、本地方法拒绝非 root 目标、
// 本地身份与计划不匹配拒绝、同名等价名拒绝。使用真实临时 SQLite + 审计事务。

import (
	"context"
	"errors"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/profile"
)

const (
	localRootUserID     = "usr_0000000000000000000000000000e001"
	localNormalUserID   = "usr_0000000000000000000000000000e002"
	localOperatorID     = "os:tester@local"
	rootRenameRequestID = "req-287-root-rename"
)

func seedLocalRoot(t *testing.T, env *testEnv) {
	t.Helper()
	env.seedUser(t, localRootUserID, "root")
	if _, err := env.storage.DB().ExecContext(env.ctx,
		`UPDATE users SET is_root=1 WHERE id=?`, localRootUserID); err != nil {
		t.Fatalf("设置 root: %v", err)
	}
	env.seedUser(t, localNormalUserID, "normal-user")
}

func applyLocalRootRename(t *testing.T, env *testEnv,
	caller profile.LocalMaintenanceCaller,
	plan profile.LocalRootRenamePlan) (profile.UserProfile, error) {
	t.Helper()
	var updated profile.UserProfile
	err := env.recorder.ExecuteCritical(env.ctx, audit.CriticalRequest{
		Event: audit.Event{
			Actor:  audit.Actor{Type: audit.ActorLocalAdmin, ID: caller.OperatorID()},
			Action: "test.local_root_rename",
			Target: audit.Target{Type: "user", ID: plan.TargetUserID},
		},
		FailureReasonCode: "test.local_root_rename_failed",
	}, func(txCtx context.Context, tx audit.Tx) error {
		value, applyErr := env.service.ApplyLocalMaintenanceRootRenameTx(txCtx, tx, caller, plan)
		if applyErr != nil {
			return applyErr
		}
		updated = value
		return nil
	})
	return updated, err
}

// TestLocalMaintenanceRootRenameSuccess 覆盖本地维护成功更名 root 与稳定身份保持。
func TestLocalMaintenanceRootRenameSuccess(t *testing.T) {
	env := newTestEnv(t, nil)
	seedLocalRoot(t, env)
	caller, err := profile.NewLocalMaintenanceCaller(localOperatorID)
	if err != nil {
		t.Fatalf("本地维护身份: %v", err)
	}
	plan, err := env.service.PrepareLocalMaintenanceRootRename(env.ctx, caller,
		profile.ManagementRenameRequest{TargetUserID: localRootUserID,
			NewUsername: "root-owner", ExpectedRowVersion: 1,
			RequestID: rootRenameRequestID})
	if err != nil {
		t.Fatalf("准备 root 更名: %v", err)
	}
	if plan.BeforeUsername != "root" || plan.DisplayUsername != "root-owner" ||
		plan.OperatorID != localOperatorID {
		t.Fatalf("root 更名计划异常: %+v", plan)
	}
	updated, err := applyLocalRootRename(t, env, caller, plan)
	if err != nil {
		t.Fatalf("应用 root 更名: %v", err)
	}
	if updated.UserID != localRootUserID || !updated.IsRoot ||
		updated.Username != "root-owner" || updated.RowVersion != 2 {
		t.Fatalf("root 更名结果异常: %+v", updated)
	}
	if updated.UsernameChangedAt.IsZero() {
		t.Error("本地 root 更名应更新 username_changed_at")
	}
	// 计划复用（版本已变化）→ 冲突。
	if _, reuseErr := applyLocalRootRename(t, env, caller, plan); !errors.Is(
		reuseErr, profile.ErrVersionConflict) {
		t.Fatalf("计划复用错误 = %v，期望 ErrVersionConflict", reuseErr)
	}
	// 同名更名拒绝。
	if _, prepareErr := env.service.PrepareLocalMaintenanceRootRename(env.ctx, caller,
		profile.ManagementRenameRequest{TargetUserID: localRootUserID,
			NewUsername: "root-owner", ExpectedRowVersion: updated.RowVersion,
			RequestID: "req-287-same"}); !errors.Is(prepareErr, profile.ErrInvalidRequest) {
		t.Fatalf("同名 root 更名错误 = %v，期望 ErrInvalidRequest", prepareErr)
	}
	// root 稳定 ID 未变：再次按稳定 ID 读取仍是 root。
	current, getErr := env.service.GetProfile(env.ctx,
		func() profile.Caller {
			caller, callerErr := profile.LocalAdminCaller("os:tester@local")
			if callerErr != nil {
				t.Fatalf("本地资料调用者: %v", callerErr)
			}
			return caller
		}(), localRootUserID)
	if getErr != nil {
		t.Fatalf("读取 root 资料: %v", getErr)
	}
	if !current.IsRoot || current.UserID != localRootUserID {
		t.Fatalf("root 稳定身份变化: %+v", current)
	}
}

// TestLocalMaintenanceRootRenameRejections 覆盖普通路径拒绝 root、本地方法拒绝
// 非 root 目标、身份与计划不匹配。
func TestLocalMaintenanceRootRenameRejections(t *testing.T) {
	env := newTestEnv(t, nil)
	seedLocalRoot(t, env)
	caller, err := profile.NewLocalMaintenanceCaller(localOperatorID)
	if err != nil {
		t.Fatalf("本地维护身份: %v", err)
	}
	// 普通直接管理路径仍拒绝 root（行为不变）。
	if _, prepareErr := env.service.PrepareManagementRename(env.ctx,
		profile.ManagementRenameRequest{TargetUserID: localRootUserID,
			NewUsername: "root-other", ExpectedRowVersion: 1,
			RequestID: "req-256-root"}); !errors.Is(prepareErr, profile.ErrTargetNotManageable) {
		t.Fatalf("普通路径 root 更名错误 = %v，期望 ErrTargetNotManageable", prepareErr)
	}
	// 本地 root 更名方法拒绝非 root 目标（调用方应使用普通直接管理路径）。
	if _, prepareErr := env.service.PrepareLocalMaintenanceRootRename(env.ctx, caller,
		profile.ManagementRenameRequest{TargetUserID: localNormalUserID,
			NewUsername: "normal-renamed", ExpectedRowVersion: 1,
			RequestID: "req-287-normal"}); !errors.Is(prepareErr, profile.ErrTargetNotManageable) {
		t.Fatalf("本地 root 更名非 root 目标错误 = %v，期望 ErrTargetNotManageable", prepareErr)
	}
	// 身份与计划不匹配：构造另一本地身份，应用第一条身份产生的计划必须拒绝。
	plan, err := env.service.PrepareLocalMaintenanceRootRename(env.ctx, caller,
		profile.ManagementRenameRequest{TargetUserID: localRootUserID,
			NewUsername: "root-owner", ExpectedRowVersion: 1,
			RequestID: rootRenameRequestID})
	if err != nil {
		t.Fatalf("准备 root 更名: %v", err)
	}
	other, err := profile.NewLocalMaintenanceCaller("os:other@local")
	if err != nil {
		t.Fatalf("另一本地维护身份: %v", err)
	}
	if _, applyErr := applyLocalRootRename(t, env, other, plan); !errors.Is(
		applyErr, profile.ErrAccessDenied) {
		t.Fatalf("身份不匹配应用错误 = %v，期望 ErrAccessDenied", applyErr)
	}
}
