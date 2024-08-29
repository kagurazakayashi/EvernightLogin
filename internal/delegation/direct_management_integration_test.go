package delegation_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
	"github.com/kagurazakayashi/EvernightLogin/internal/role"
	rolesqlite "github.com/kagurazakayashi/EvernightLogin/internal/role/sqlite"
)

// 两项直接管理权限的稳定机器标识（与 internal/preset 目录一致）。
const (
	directUsernamePermissionKey = "users.username.change.other"
	directPasswordPermissionKey = "users.password.reset.other"
)

// 合成系统权限 ID，只用于临时数据库，避免与既有种子冲突。
const (
	directUpdatePermID   = "perm_66666666666666666666666666666666"
	directUsernamePermID = "perm_77777777777777777777777777777777"
	directPasswordPermID = "perm_88888888888888888888888888888888"
)

// systemRoleAuthorizer 是测试用系统范围角色管理授权器：显式允许受信本地操作者与
// 指定普通用户操作者管理 system 范围角色，用于验证普通用户的委派/角色检查路径。
type systemRoleAuthorizer struct{ adminID string }

func (a systemRoleAuthorizer) allow(caller role.Caller) bool {
	actor := caller.Actor()
	if actor.Type == audit.ActorLocalAdmin {
		return true
	}
	return actor.Type == audit.ActorUser && actor.ID == a.adminID
}

// Authorize 实现 role.Authorizer；未列入白名单的调用者一律拒绝。
func (a systemRoleAuthorizer) Authorize(_ context.Context, caller role.Caller, _ role.Action, _ string) error {
	if a.allow(caller) {
		return nil
	}
	return role.ErrAccessDenied
}

// ManageableScopes 实现 role.Authorizer；测试授权器允许受信调用者管理全部范围。
func (a systemRoleAuthorizer) ManageableScopes(_ context.Context, caller role.Caller) (bool, []string, error) {
	if a.allow(caller) {
		return true, nil, nil
	}
	return false, nil, role.ErrAccessDenied
}

// insertDirectPermission 插入一条系统范围合成权限。
func insertDirectPermission(t *testing.T, env *integrationEnv, permissionID, key string) {
	t.Helper()
	now := env.clock.Now().UnixMilli()
	if _, err := env.raw.ExecContext(context.Background(), `INSERT INTO permissions(
id,scope_id,permission_key,name,description,limits_text,enabled,root_only,created_at_ms,updated_at_ms
) VALUES(?,?,?,?,?,?,1,0,?,?)`, permissionID, "system", key, key, "说明", "限制", now, now); err != nil {
		t.Fatalf("插入权限 %q 失败: %v", key, err)
	}
}

// TestDirectManagementPermissionsRoleAndDelegation 验收两项直接管理权限接入既有
// 角色管理/委派检查：不能借 users.update 隐式获得、两项互相独立、撤销后不能继续
// 组合、不能自我提权、系统权限不能跨到应用范围委派、普通角色分配不能落到 root。
func TestDirectManagementPermissionsRoleAndDelegation(t *testing.T) {
	env := prepareIntegrationEnv(t)
	ctx := context.Background()
	insertDirectPermission(t, env, directUpdatePermID, "users.update")
	insertDirectPermission(t, env, directUsernamePermID, directUsernamePermissionKey)
	insertDirectPermission(t, env, directPasswordPermID, directPasswordPermissionKey)

	// 复用同一数据库构造系统范围角色服务；真实委派 Guard 仍是 env.service。
	roleStore, err := rolesqlite.New(env.raw)
	if err != nil {
		t.Fatalf("构造角色存储失败: %v", err)
	}
	systemRoles, err := role.New(role.Options{
		Store: roleStore, Audit: env.recorder, Authorizer: systemRoleAuthorizer{adminID: testAdmin},
		Transfers: env.service, AllowLegacyWithoutSensitive: true, Now: env.clock.Now,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("构造系统范围角色服务失败: %v", err)
	}
	createRole := func(key string) role.Role {
		record, createErr := systemRoles.CreateRole(ctx, env.roleLocal, role.CreateRequest{
			ScopeID: "system", Key: key, Name: key, Description: "说明", Limits: "限制",
		})
		if createErr != nil {
			t.Fatalf("创建系统角色 %q 失败: %v", key, createErr)
		}
		return record
	}

	// 准备：users.update 角色让管理员实际持有该权限，并签发其委派资格。
	updateRole := createRole("delegated-user-updater")
	if _, err := systemRoles.AddRolePermission(ctx, env.roleLocal, updateRole.ID, directUpdatePermID); err != nil {
		t.Fatalf("受信组合 users.update 失败: %v", err)
	}
	if _, err := systemRoles.AssignUserRole(ctx, env.roleLocal, updateRole.ID, testAdmin); err != nil {
		t.Fatalf("受信分配 users.update 角色失败: %v", err)
	}
	env.grant(delegation.GrantRequest{DelegatorUserID: testAdmin, ScopeID: "system", PermissionKey: "users.update"})

	// 只持有 users.update 时不能把两项直接管理权限组合进角色（无隐式授予）。
	for _, permissionID := range []string{directUsernamePermID, directPasswordPermID} {
		if _, err := systemRoles.AddRolePermission(ctx, env.roleAdmin, updateRole.ID, permissionID); !errors.Is(err, delegation.ErrTransferNotGranted) {
			t.Fatalf("借 users.update 隐式组合权限错误 = %v，期望 ErrTransferNotGranted", err)
		}
	}
	if delegation.CodeOf(delegation.ErrTransferNotGranted) != delegation.CodePermissionRequired {
		t.Fatal("拒绝错误码映射异常，期望 PERMISSION_REQUIRED")
	}

	// 只授予「直接改名」：可以组合改名权限，重置密码权限仍然拒绝（两项独立）。
	usernameGrant := env.grant(delegation.GrantRequest{
		DelegatorUserID: testAdmin, ScopeID: "system", PermissionKey: directUsernamePermissionKey,
	})
	// 管理员持有改名权限：受信通道先建角色并分配（模拟已授权的既有持有）。
	usernameRole := createRole("delegated-username-changer")
	if _, err := systemRoles.AddRolePermission(ctx, env.roleLocal, usernameRole.ID, directUsernamePermID); err != nil {
		t.Fatalf("受信组合直接改名权限失败: %v", err)
	}
	if _, err := systemRoles.AssignUserRole(ctx, env.roleLocal, usernameRole.ID, testAdmin); err != nil {
		t.Fatalf("受信分配直接改名角色失败: %v", err)
	}
	newRole := createRole("delegated-username-target-role")
	if changed, err := systemRoles.AddRolePermission(ctx, env.roleAdmin, newRole.ID, directUsernamePermID); err != nil || !changed {
		t.Fatalf("有委派资格时组合直接改名权限失败: changed=%v err=%v", changed, err)
	}
	if _, err := systemRoles.AddRolePermission(ctx, env.roleAdmin, newRole.ID, directPasswordPermID); !errors.Is(err, delegation.ErrTransferNotGranted) {
		t.Fatalf("未授予重置密码时组合错误 = %v，期望 ErrTransferNotGranted", err)
	}
	// 不能把含直接改名权限的角色分配给自己（自我提权），但可以分配给其他成员。
	if _, err := systemRoles.AssignUserRole(ctx, env.roleAdmin, newRole.ID, testAdmin); !errors.Is(err, delegation.ErrSelfTransferDenied) {
		t.Fatalf("自我分配含直接管理权限角色错误 = %v，期望 ErrSelfTransferDenied", err)
	}
	if changed, err := systemRoles.AssignUserRole(ctx, env.roleAdmin, newRole.ID, testMember); err != nil || !changed {
		t.Fatalf("向其他成员分配含直接管理权限角色失败: changed=%v err=%v", changed, err)
	}

	// 撤销委派资格后不能继续把该权限组合进新的角色。
	if removed, err := env.service.Revoke(ctx, env.local, usernameGrant.ID); err != nil || !removed {
		t.Fatalf("撤销委派资格失败: removed=%v err=%v", removed, err)
	}
	afterRevoke := createRole("delegated-after-revoke")
	if _, err := systemRoles.AddRolePermission(ctx, env.roleAdmin, afterRevoke.ID, directUsernamePermID); !errors.Is(err, delegation.ErrTransferRevoked) {
		t.Fatalf("撤销后组合错误 = %v，期望 ErrTransferRevoked", err)
	}

	// 系统权限键不能跨到应用范围委派：应用内管理员不会自动获得全局操作权。
	if _, err := env.service.Grant(ctx, env.local, delegation.GrantRequest{
		DelegatorUserID: testAdmin, ScopeID: testAppOne, PermissionKey: directUsernamePermissionKey,
	}); !errors.Is(err, delegation.ErrPermissionNotFound) {
		t.Fatalf("系统权限跨应用委派错误 = %v，期望 ErrPermissionNotFound", err)
	}

	// 含直接管理权限的普通角色不能被分配给 root（root 资格不来自普通角色分配）。
	if _, err := systemRoles.AssignUserRole(ctx, env.roleLocal, newRole.ID, testRoot); !errors.Is(err, role.ErrRootProtected) {
		t.Fatalf("向 root 分配普通角色错误 = %v，期望 ErrRootProtected", err)
	}
}
