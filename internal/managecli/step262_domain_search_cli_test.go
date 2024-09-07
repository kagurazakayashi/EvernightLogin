package managecli

// 步骤 262：角色/权限/用户组/应用列表 CLI 搜索参数契约测试（新文件）。

import (
	"strings"
	"testing"
)

// TestDomainListSearchCLI 验收四个域列表的 --search/--search-fields：
// 字面匹配、字段白名单、JSON 输出与非法参数退出码 2。
func TestDomainListSearchCLI(t *testing.T) {
	fixture := newDomainFixture(t)

	// 角色列表：搜索机器标识（大小写折叠）。
	stdout, stderr, exit := runCLI(t, "role", "list", "--operator", "local-admin",
		"--config", fixture.configPath, "--search", "TEST-ROLE", "--json")
	if exit != ExitOK {
		t.Fatalf("role list --search 退出码 = %d，stderr=%s", exit, stderr)
	}
	data := decodeEnvelope(t, stdout)["data"].(map[string]any)
	roles, _ := data["roles"].([]any)
	if len(roles) != 1 {
		t.Fatalf("角色搜索结果 = %v", roles)
	}
	if first, _ := roles[0].(map[string]any); first["key"] != "test-role" {
		t.Fatalf("角色搜索结果 = %v", roles)
	}
	// 只搜名称时机器标识不再命中（名称是中文“测试角色”）。
	stdout, _, exit = runCLI(t, "role", "list", "--operator", "local-admin",
		"--config", fixture.configPath, "--search", "test-role",
		"--search-fields", "name", "--json")
	if exit != ExitOK {
		t.Fatalf("role list --search-fields name 退出码 = %d", exit)
	}
	if roles, _ := decodeEnvelope(t, stdout)["data"].(map[string]any)["roles"].([]any); len(roles) != 0 {
		t.Fatalf("只搜名称不应命中机器标识: %v", roles)
	}
	// 非法字段拒绝（退出码 2）。
	if _, _, exit := runCLI(t, "role", "list", "--operator", "local-admin",
		"--config", fixture.configPath, "--search", "x",
		"--search-fields", "description", "--json"); exit != ExitUsage {
		t.Fatalf("角色非法搜索字段退出码 = %d，期望 %d", exit, ExitUsage)
	}

	// 用户组列表：搜索 group_key。
	stdout, _, exit = runCLI(t, "group", "list", "--operator", "local-admin",
		"--config", fixture.configPath, "--search", "TEST-GROUP", "--json")
	if exit != ExitOK {
		t.Fatalf("group list --search 退出码 = %d", exit)
	}
	if groups, _ := decodeEnvelope(t, stdout)["data"].(map[string]any)["groups"].([]any); len(groups) != 1 {
		t.Fatalf("用户组搜索结果 = %v", groups)
	}

	// 应用列表：搜索中文名称与描述字面。
	stdout, _, exit = runCLI(t, "app", "list", "--operator", "local-admin",
		"--config", fixture.configPath, "--search", "测试", "--json")
	if exit != ExitOK {
		t.Fatalf("app list --search 退出码 = %d", exit)
	}
	if apps, _ := decodeEnvelope(t, stdout)["data"].(map[string]any)["applications"].([]any); len(apps) != 1 {
		t.Fatalf("应用搜索结果 = %v", apps)
	}
	if _, _, exit := runCLI(t, "app", "list", "--operator", "local-admin",
		"--config", fixture.configPath, "--search", "x",
		"--search-fields", "owner", "--json"); exit != ExitUsage {
		t.Fatalf("应用非法搜索字段退出码 = %d，期望 %d", exit, ExitUsage)
	}

	// 权限目录（固定有界本地过滤）：按机器标识搜到目标权限。
	stdout, _, exit = runCLI(t, "permission", "list", "--search", "users.read", "--json")
	if exit != ExitOK {
		t.Fatalf("permission list --search 退出码 = %d", exit)
	}
	permissions := decodeEnvelope(t, stdout)["data"].(map[string]any)["permissions"].([]any)
	if len(permissions) == 0 || len(permissions) > 3 {
		t.Fatalf("权限搜索结果数量异常 = %d", len(permissions))
	}
	found := false
	for _, raw := range permissions {
		if item, _ := raw.(map[string]any); item["key"] == "users.read" {
			found = true
		}
	}
	if !found {
		t.Fatalf("权限搜索缺少 users.read: %v", permissions)
	}
	// 通配符按字面：% 不应命中全部权限。
	stdout, _, exit = runCLI(t, "permission", "list", "--search", "%", "--json")
	if exit != ExitOK {
		t.Fatalf("permission list %% 退出码 = %d", exit)
	}
	if items := decodeEnvelope(t, stdout)["data"].(map[string]any)["permissions"].([]any); len(items) != 0 {
		t.Fatalf("权限通配符字面结果 = %v", items)
	}
	// 超长搜索：CLI 本地过滤直接返回用法错误。
	if _, _, exit := runCLI(t, "permission", "list", "--search",
		strings.Repeat("a", 65), "--json"); exit != ExitUsage {
		t.Fatalf("权限超长搜索退出码 = %d，期望 %d", exit, ExitUsage)
	}
}
