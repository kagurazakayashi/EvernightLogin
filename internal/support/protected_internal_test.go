package support

import (
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/preset"
)

// TestBuildProtectedTargetPermissions 验证受保护权限集合由人工基线与权限目录元数据
// 共同生成：目录中 RootOnly/RequiresReauth 的高权限项自动并入（防新增目录漏判），
// 基线拼写/改名漂移导致构造失败（fail-closed）。
func TestBuildProtectedTargetPermissions(t *testing.T) {
	catalog := preset.DefaultCatalog()
	if catalog == nil {
		t.Fatal("默认权限目录为空")
	}
	protected, err := buildProtectedTargetPermissions(catalog.Permissions)
	if err != nil {
		t.Fatalf("构造保护集合: %v", err)
	}
	// 基线中的关键高权限项必须存在。
	for _, key := range []string{"users.delete", "recovery.approve", "backups.restore", "security.policy.manage"} {
		if _, ok := protected[key]; !ok {
			t.Errorf("保护集合缺少基线权限 %q", key)
		}
	}
	// 目录显式声明 RootOnly 或 RequiresReauth 的权限必须自动纳入。
	for _, definition := range catalog.Permissions {
		if definition.RootOnly || definition.RequiresReauth {
			if _, ok := protected[definition.Key]; !ok {
				t.Errorf("目录高权限项 %q 未被保护集合覆盖", definition.Key)
			}
		}
	}
	// 目录新增的高权限项自动纳入。
	definitions := append([]preset.PermissionDefinition{}, catalog.Permissions...)
	definitions = append(definitions, preset.PermissionDefinition{
		Key: "future.high_risk.manage", Name: "未来高权限操作",
		Summary: "测试用", Scope: "测试", Limits: "测试", RequiresReauth: true,
	})
	protected, err = buildProtectedTargetPermissions(definitions)
	if err != nil {
		t.Fatalf("追加目录项后构造: %v", err)
	}
	if _, ok := protected["future.high_risk.manage"]; !ok {
		t.Error("目录新增 RequiresReauth 权限未自动纳入保护集合")
	}
	// 基线权限在目录中缺失（改名/拼写漂移）时拒绝构造。
	var missing []preset.PermissionDefinition
	for _, definition := range catalog.Permissions {
		if definition.Key != "users.delete" {
			missing = append(missing, definition)
		}
	}
	if _, err := buildProtectedTargetPermissions(missing); err == nil {
		t.Fatal("基线权限缺失时构造保护集合应失败（目录漂移 fail-closed）")
	}
}
