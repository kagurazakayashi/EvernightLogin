package preset_test

import (
	"context"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/preset"
)

// 两项直接管理权限的稳定机器标识；与 internal/policy 的两条敏感操作用同一语义。
const (
	directUsernameKey = "users.username.change.other"
	directPasswordKey = "users.password.reset.other"
)

// permissionFlags 读取权限行的 is_builtin/root_only/enabled 标记。
func (e *testEnv) permissionFlags(scopeID, key string) (builtin, rootOnly, enabled int) {
	e.t.Helper()
	rows, err := e.raw.QueryContext(context.Background(),
		`SELECT is_builtin,root_only,enabled FROM permissions WHERE scope_id=? AND permission_key=?`,
		scopeID, key)
	if err != nil {
		e.t.Fatalf("读取权限标记失败: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		e.t.Fatalf("权限 %s/%s 不存在", scopeID, key)
	}
	if err := rows.Scan(&builtin, &rootOnly, &enabled); err != nil {
		e.t.Fatalf("扫描权限标记失败: %v", err)
	}
	return builtin, rootOnly, enabled
}

// TestDirectManagementPermissionsFreshInstall 验收新安装：两条直接管理权限作为内置
// 系统权限登记（启用、非 root_only、业务入口未落地保持未实现），直白中文说明落库，
// 新装 system_admin 预设包含两项而客服/用户管理员/普通用户不含，重复安装幂等。
func TestDirectManagementPermissionsFreshInstall(t *testing.T) {
	env := prepareEnv(t, nil)
	ctx := context.Background()
	result, err := env.service.Install(ctx, env.local, preset.InstallRequest{})
	if err != nil {
		t.Fatalf("初始化失败: %v", err)
	}
	if !result.Initialized || !result.Changed || result.CatalogVersion != "1.1.0" {
		t.Fatalf("初始化结果 = %+v，期望 1.1.0 首次初始化", result)
	}
	for _, key := range []string{directUsernameKey, directPasswordKey} {
		definition := findPermission(t, env.catalog.Permissions, key)
		// 步骤 256 已落地直接改名 Go 入口 → username 权限已实现；直接重置密码入口
		// 由步骤 257 落地，届时再改为 true。
		wantImplemented := key == directUsernameKey || key == directPasswordKey
		if definition.Implemented != wantImplemented {
			t.Fatalf("权限 %q Implemented = %v，期望 %v（入口落地状态决定实现标记）",
				key, definition.Implemented, wantImplemented)
		}
		if !definition.RequiresReauth {
			t.Fatalf("权限 %q 必须要求本次再次验证", key)
		}
		builtin, rootOnly, enabled := env.permissionFlags("system", key)
		if builtin != 1 || rootOnly != 0 || enabled != 1 {
			t.Fatalf("权限 %q 标记 = (builtin=%d root_only=%d enabled=%d)，期望 (1,0,1)",
				key, builtin, rootOnly, enabled)
		}
		name, description := env.permissionText("system", key)
		if name != definition.Name {
			t.Fatalf("权限 %q 名称 = %q，期望 %q", key, name, definition.Name)
		}
		wantDescription := definition.Summary + "｜范围：" + definition.Scope
		if description != wantDescription {
			t.Fatalf("权限 %q 说明 = %q，期望 %q", key, description, wantDescription)
		}
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM permissions WHERE scope_id='system'`); got != len(env.catalog.Permissions) {
		t.Fatalf("系统权限行数 = %d，期望 %d", got, len(env.catalog.Permissions))
	}

	// 角色默认组合：新装 system_admin 含两项；客服/用户管理员/普通用户不含。
	roleKeys := map[string]string{
		"system_admin": env.rolePermissionKeys(env.roleID("system", "system_admin")),
		"user_admin":   env.rolePermissionKeys(env.roleID("system", "user_admin")),
		"support":      env.rolePermissionKeys(env.roleID("system", "support")),
		"normal_user":  env.rolePermissionKeys(env.roleID("system", "normal_user")),
	}
	for _, key := range []string{directUsernameKey, directPasswordKey} {
		if !strings.Contains(roleKeys["system_admin"], key) {
			t.Fatalf("新装 system_admin 预设缺少直接管理权限 %q", key)
		}
		for _, roleKey := range []string{"user_admin", "support", "normal_user"} {
			if strings.Contains(roleKeys[roleKey], key) {
				t.Fatalf("角色 %q 不应默认获得直接管理权限 %q", roleKey, key)
			}
		}
	}
	// users.update 只负责显示资料：两项直接管理权限不能借它隐式授予。
	usersUpdate := findPermission(t, env.catalog.Permissions, "users.update")
	if usersUpdate.Implemented != true {
		t.Fatalf("users.update 应保持已实现: %+v", usersUpdate)
	}
	if strings.Contains(usersUpdate.Summary, directUsernameKey) || strings.Contains(usersUpdate.Summary, directPasswordKey) {
		t.Fatalf("users.update 不应声称包含直接管理能力: %q", usersUpdate.Summary)
	}

	// 重复安装幂等：不重复创建、不覆盖角色组合。
	again, err := env.service.Install(ctx, env.local, preset.InstallRequest{})
	if err != nil {
		t.Fatalf("重复初始化失败: %v", err)
	}
	if again.Changed || !again.UpToDate || len(again.CreatedPermissions) != 0 {
		t.Fatalf("重复初始化结果 = %+v，期望无变化", again)
	}
}

// legacyDirectManagementCatalog 把默认目录改造成“新增两项直接管理权限之前”的
// 1.0.0 目录：移除两项权限与 system_admin 中的默认组合，供升级不静默加权的测试使用。
func legacyDirectManagementCatalog(catalog *preset.Catalog) {
	catalog.Version = "1.0.0"
	kept := make([]preset.PermissionDefinition, 0, len(catalog.Permissions))
	for _, definition := range catalog.Permissions {
		if definition.Key == directUsernameKey || definition.Key == directPasswordKey {
			continue
		}
		kept = append(kept, definition)
	}
	catalog.Permissions = kept
	for index := range catalog.Roles {
		if catalog.Roles[index].Key != "system_admin" {
			continue
		}
		defaults := make([]string, 0, len(catalog.Roles[index].DefaultPermissions))
		for _, key := range catalog.Roles[index].DefaultPermissions {
			if key == directUsernameKey || key == directPasswordKey {
				continue
			}
			defaults = append(defaults, key)
		}
		catalog.Roles[index].DefaultPermissions = defaults
	}
}

// TestUpgradeDoesNotSilentlyGrantDirectManagementPermissions 验收“既有角色不因升级
// 无提示提权”：旧 1.0.0 安装升级到 1.1.0 时只创建缺失权限行、保留既有角色组合，
// 并把“待恢复的默认权限”明确列入提示；不得静默把两项高风险权限加进 system_admin。
func TestUpgradeDoesNotSilentlyGrantDirectManagementPermissions(t *testing.T) {
	env := prepareEnv(t, legacyDirectManagementCatalog)
	ctx := context.Background()
	if _, err := env.service.Install(ctx, env.local, preset.InstallRequest{}); err != nil {
		t.Fatalf("1.0.0 初始化失败: %v", err)
	}
	systemAdminID := env.roleID("system", "system_admin")
	supportID := env.roleID("system", "support")
	beforeAdmin := env.rolePermissionKeys(systemAdminID)
	beforeSupport := env.rolePermissionKeys(supportID)
	if strings.Contains(beforeAdmin, directUsernameKey) || strings.Contains(beforeAdmin, directPasswordKey) {
		t.Fatalf("旧 1.0.0 安装不应预置直接管理权限: %q", beforeAdmin)
	}

	// 默认目录（1.1.0，含两项）在同一数据库升级安装。
	upgraded := prepareLegacyEnv(t, env, preset.DefaultCatalog().Version)
	result, err := upgraded.service.Install(ctx, upgraded.local, preset.InstallRequest{})
	if err != nil {
		t.Fatalf("1.1.0 升级失败: %v", err)
	}
	if !result.Upgraded || result.PreviousVersion != "1.0.0" || result.CatalogVersion != "1.1.0" {
		t.Fatalf("升级结果 = %+v，期望 1.0.0 -> 1.1.0", result)
	}
	created := strings.Join(result.CreatedPermissions, ",")
	for _, key := range []string{directUsernameKey, directPasswordKey} {
		if !strings.Contains(created, key) {
			t.Fatalf("升级未创建新增权限 %q，实际创建 %v", key, result.CreatedPermissions)
		}
	}
	// 关键：既有角色组合保持原样，升级不静默追加两项高风险权限。
	if after := env.rolePermissionKeys(systemAdminID); after != beforeAdmin {
		t.Fatalf("升级静默改写了 system_admin 组合: %q -> %q", beforeAdmin, after)
	}
	if after := env.rolePermissionKeys(supportID); after != beforeSupport {
		t.Fatalf("升级静默改写了 support 组合: %q -> %q", beforeSupport, after)
	}
	// 待恢复提示必须明确列出两项，供运维在“恢复默认”时看到并显式确认。
	deferred := strings.Join(result.DeferredRolePermissionAdds, ",")
	for _, key := range []string{directUsernameKey, directPasswordKey} {
		want := "system_admin:" + key
		if !strings.Contains(deferred, want) {
			t.Fatalf("升级提示缺少待恢复项 %q，实际 %v", want, result.DeferredRolePermissionAdds)
		}
	}
	// 升级后两项权限仍可被 root 逐项授予（此处验证目录登记与实现标记）：
	// 直接改名（步骤 256）与直接重置口令（步骤 257）入口均已落地（Implemented=true）。
	usernameDefinition := findPermission(t, upgraded.catalog.Permissions, directUsernameKey)
	if !usernameDefinition.Implemented {
		t.Fatalf("直接改名入口已落地，权限 %q 应标记已实现", directUsernameKey)
	}
	passwordDefinition := findPermission(t, upgraded.catalog.Permissions, directPasswordKey)
	if !passwordDefinition.Implemented {
		t.Fatalf("直接重置口令入口已落地，权限 %q 应标记已实现", directPasswordKey)
	}
}
