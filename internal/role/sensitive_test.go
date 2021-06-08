package role_test

import (
	"context"
	"errors"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/role"
)

// denyingRunner 模拟敏感策略拒绝的收敛入口。
type denyingRunner struct {
	calls       int
	operationID string
}

func (r *denyingRunner) Authorize(ctx context.Context, caller reauth.Caller, request reauth.Request) (reauth.Result, error) {
	r.calls++
	r.operationID = request.OperationID
	return reauth.Result{}, reauth.ErrMFARequired
}

func (r *denyingRunner) NotifyOutcome(ctx context.Context, result reauth.Result, outcome reauth.Outcome) error {
	return nil
}

// TestRoleChangesRequireSensitivePolicy 验证角色/权限写入路径接入敏感策略：策略拒绝
// 时 fail-closed 且不产生变更，既有委派 Guard 仍保留在事务内。
func TestRoleChangesRequireSensitivePolicy(t *testing.T) {
	runner := &denyingRunner{}
	env := prepareEnv(t, func(options *role.Options) { options.Sensitive = runner })
	systemRole := env.createRole("system", "ops.manage", "运维管理")

	if _, err := env.service.AssignUserRole(context.Background(), env.system, systemRole.ID, testUserActive); !errors.Is(err, role.ErrAccessDenied) {
		t.Fatalf("策略拒绝后分配角色错误 = %v，期望 ErrAccessDenied", err)
	}
	if assignments, err := env.service.ListRoleAssignments(context.Background(), env.system, systemRole.ID); err != nil || len(assignments.Users) != 0 {
		t.Errorf("被拒绝后不应有角色分配: %+v err=%v", assignments, err)
	}
	if _, err := env.service.AddRolePermission(context.Background(), env.system, systemRole.ID, testPermissionSystem); !errors.Is(err, role.ErrAccessDenied) {
		t.Fatalf("策略拒绝后组合权限错误 = %v，期望 ErrAccessDenied", err)
	}
	if _, err := env.service.RemoveRolePermission(context.Background(), env.system, systemRole.ID, testPermissionSystem); !errors.Is(err, role.ErrAccessDenied) {
		t.Fatalf("策略拒绝后移除权限错误 = %v，期望 ErrAccessDenied", err)
	}
	permissions, err := env.service.ListRolePermissions(context.Background(), env.system, systemRole.ID)
	if err != nil || len(permissions) != 0 {
		t.Errorf("被拒绝后角色权限应保持不变: %+v err=%v", permissions, err)
	}
	if runner.calls < 3 {
		t.Errorf("敏感策略判定调用数 = %d，期望至少 3", runner.calls)
	}
	if runner.operationID == "" {
		t.Error("敏感策略请求缺少稳定操作 ID")
	}
	// 未接线（nil）时保持既有行为：既有授权与委派检查仍生效，测试套件不回归。
	plain := prepareEnv(t)
	plainRole := plain.createRole("system", "ops.manage", "运维管理")
	if changed, err := plain.service.AssignUserRole(context.Background(), plain.system, plainRole.ID, testUserActive); err != nil || !changed {
		t.Fatalf("未接线时既有分配路径 = %v changed=%v", err, changed)
	}
}

// allowRunner 记录调用并允许执行，用于验证成功路径告知。
type allowRunner struct {
	calls       int
	notifyCalls int
	last        reauth.Request
}

func (r *allowRunner) Authorize(ctx context.Context, caller reauth.Caller, request reauth.Request) (reauth.Result, error) {
	r.calls++
	r.last = request
	return reauth.Result{OperationID: request.OperationID, TargetType: request.TargetType,
		TargetID: request.TargetID, UserID: caller.Actor().ID}, nil
}

func (r *allowRunner) NotifyOutcome(ctx context.Context, result reauth.Result, outcome reauth.Outcome) error {
	r.notifyCalls++
	return nil
}

// TestAssignUserRoleNotifiesAfterSuccess 验证接线成功路径调用安全告知。
func TestAssignUserRoleNotifiesAfterSuccess(t *testing.T) {
	runner := &allowRunner{}
	env := prepareEnv(t, func(options *role.Options) { options.Sensitive = runner })
	systemRole := env.createRole("system", "ops.manage", "运维管理")
	if changed, err := env.service.AssignUserRole(context.Background(), env.system, systemRole.ID, testUserActive); err != nil || !changed {
		t.Fatalf("接线成功分配 = %v changed=%v", err, changed)
	}
	if runner.calls != 1 || runner.notifyCalls != 1 {
		t.Errorf("判定/告知调用 = %d/%d，期望 1/1", runner.calls, runner.notifyCalls)
	}
	if runner.last.OperationID != "permission.role.assign" || runner.last.Params["direction"] != "assign" {
		t.Errorf("绑定操作/方向异常: %+v", runner.last)
	}
}

// TestRoleChangesFailClosedWithoutRunner 验证未接线且未显式允许旧语义时拒绝。
func TestRoleChangesFailClosedWithoutRunner(t *testing.T) {
	env := prepareEnv(t, func(options *role.Options) { options.AllowLegacyWithoutSensitive = false })
	systemRole := env.createRole("system", "ops.manage", "运维管理")
	if _, err := env.service.AssignUserRole(context.Background(), env.system, systemRole.ID, testUserActive); !errors.Is(err, role.ErrAccessDenied) {
		t.Fatalf("未接线时分配角色错误 = %v，期望 ErrAccessDenied", err)
	}
	if assignments, err := env.service.ListRoleAssignments(context.Background(), env.system, systemRole.ID); err != nil || len(assignments.Users) != 0 {
		t.Errorf("fail-closed 后不应有角色分配: %+v err=%v", assignments, err)
	}
}
