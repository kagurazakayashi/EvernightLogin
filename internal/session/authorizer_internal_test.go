package session

import (
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/preset"
)

// TestProtectedTargetPermissionsExistInCatalog 校验“应用范围管理员不得强制下线
// 受保护目标”的权限键集合与 internal/preset 权限目录一致：每个键都必须真实存在，
// 防止拼写错误或目录改名后保护静默失效（目录新增管理权限时应同步复查该集合）。
func TestProtectedTargetPermissionsExistInCatalog(t *testing.T) {
	catalog := preset.DefaultCatalog()
	if catalog == nil {
		t.Fatal("预设权限目录为空")
	}
	known := make(map[string]struct{}, len(catalog.Permissions))
	for _, permission := range catalog.Permissions {
		known[permission.Key] = struct{}{}
	}
	if len(protectedTargetPermissions) == 0 {
		t.Fatal("受保护目标权限集合为空")
	}
	for key := range protectedTargetPermissions {
		if _, ok := known[key]; !ok {
			t.Errorf("受保护目标权限键 %q 不存在于 internal/preset 权限目录", key)
		}
	}
	// 至少覆盖用户管理、角色/权限、应用成员、会话强制退出与审计等核心管理能力。
	for _, required := range []string{
		"users.disable", "users.create", "users.update", "roles.assign",
		"permissions.manage", "applications.members.manage", "sessions.revoke", "audit.read",
	} {
		if _, ok := protectedTargetPermissions[required]; !ok {
			t.Errorf("受保护目标权限集合缺少核心管理权限 %q", required)
		}
	}
}
