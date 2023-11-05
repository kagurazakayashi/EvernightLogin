package managecli

// 步骤 220：CLI 有界列表遍历测试。
//   - 默认单页行为与 JSON 契约保持不变；
//   - group list/app list 的 --all 使用公开有界迭代器，JSON 输出遍历元数据；
//   - --max-pages/--max-items 生效并给出明确部分结果；--all 与 --offset 互斥；
//   - 纯文本模式在达到上限时提示；非法参数在参数解析阶段拒绝。

import (
	"fmt"
	"strings"
	"testing"
)

// seedIterationGroups 通过真实 CLI 建组命令追加 count 个系统用户组。
func seedIterationGroups(t *testing.T, fixture *domainFixture, count int) {
	t.Helper()
	for index := 0; index < count; index++ {
		key := fmt.Sprintf("iter-group-%02d", index)
		stdout, stderr, exit := runCLI(t, "group", "create", "--operator", "local-admin",
			"--scope", "system", "--key", key, "--name", "迭代组"+key,
			"--confirm", "CREATE", "--config", fixture.configPath, "--json")
		if exit != ExitOK {
			t.Fatalf("建组 %s 退出码 = %d，stdout=%s stderr=%s", key, exit, stdout, stderr)
		}
	}
}

// TestStep220GroupListAll 覆盖 group list 默认行为与有界 --all。
func TestStep220GroupListAll(t *testing.T) {
	fixture := newDomainFixture(t)
	seedIterationGroups(t, fixture, 3) // 加 fixture 自带 1 个共 4 个

	// 默认单页：输出契约不变，不出现 --all 元数据。
	stdout, stderr, exit := runCLI(t, "group", "list", "--operator", "local-admin",
		"--config", fixture.configPath, "--json")
	if exit != ExitOK {
		t.Fatalf("默认 group list 退出码 = %d，stderr=%s", exit, stderr)
	}
	data := decodeEnvelope(t, stdout)["data"].(map[string]any)
	if len(data["groups"].([]any)) != 4 || data["has_more"] != false {
		t.Fatalf("默认 group list 数据异常: %v", data)
	}
	if _, exists := data["all"]; exists {
		t.Fatalf("默认单页输出不应包含 --all 元数据: %v", data)
	}
	if data["limit"] != float64(domainListDefaultLimit) || data["next_offset"] == nil {
		t.Fatalf("默认分页元数据异常: %v", data)
	}

	// --all 取回全部，每页 1 条，complete=true。
	stdout, _, exit = runCLI(t, "group", "list", "--operator", "local-admin",
		"--all", "--limit", "1", "--config", fixture.configPath, "--json")
	if exit != ExitOK {
		t.Fatalf("group list --all 退出码 = %d", exit)
	}
	allData := decodeEnvelope(t, stdout)["data"].(map[string]any)
	if len(allData["groups"].([]any)) != 4 || allData["all"] != true ||
		allData["complete"] != true || allData["stopped"] != false ||
		allData["pages"] != float64(4) || allData["items_total"] != float64(4) ||
		allData["has_more"] != false {
		t.Fatalf("group list --all 数据异常: %v", allData)
	}
	if allData["stop_reason"] != "complete" {
		t.Fatalf("--all 停止原因 = %v", allData["stop_reason"])
	}

	// --max-pages 有界停止：只取 2 页，明确部分结果。
	stdout, _, exit = runCLI(t, "group", "list", "--operator", "local-admin",
		"--all", "--limit", "1", "--max-pages", "2", "--config",
		fixture.configPath, "--json")
	if exit != ExitOK {
		t.Fatalf("group list --all --max-pages 退出码 = %d", exit)
	}
	partial := decodeEnvelope(t, stdout)["data"].(map[string]any)
	if len(partial["groups"].([]any)) != 2 || partial["complete"] != false ||
		partial["stopped"] != true || partial["stop_reason"] != "max_pages" ||
		partial["pages"] != float64(2) || partial["has_more"] != true {
		t.Fatalf("--max-pages 部分结果异常: %v", partial)
	}

	// --max-items 截断：最多 3 条。
	stdout, _, exit = runCLI(t, "group", "list", "--operator", "local-admin",
		"--all", "--limit", "1", "--max-items", "3", "--config",
		fixture.configPath, "--json")
	if exit != ExitOK {
		t.Fatalf("group list --all --max-items 退出码 = %d", exit)
	}
	limited := decodeEnvelope(t, stdout)["data"].(map[string]any)
	if len(limited["groups"].([]any)) != 3 || limited["items_total"] != float64(3) ||
		limited["stop_reason"] != "max_items" || limited["complete"] != false {
		t.Fatalf("--max-items 部分结果异常: %v", limited)
	}

	// 纯文本模式：达到上限时有明确提示。
	stdout, _, exit = runCLI(t, "group", "list", "--operator", "local-admin",
		"--all", "--limit", "1", "--max-pages", "1", "--config", fixture.configPath)
	if exit != ExitOK || !strings.Contains(stdout, "达到遍历上限") {
		t.Fatalf("纯文本上限提示缺失: exit=%d stdout=%s", exit, stdout)
	}
}

// TestStep220AppListAll 覆盖 app list 的 --all（fixture 1 个应用）。
func TestStep220AppListAll(t *testing.T) {
	fixture := newDomainFixture(t)
	stdout, stderr, exit := runCLI(t, "app", "list", "--operator", "local-admin",
		"--all", "--config", fixture.configPath, "--json")
	if exit != ExitOK {
		t.Fatalf("app list --all 退出码 = %d，stderr=%s", exit, stderr)
	}
	data := decodeEnvelope(t, stdout)["data"].(map[string]any)
	if len(data["applications"].([]any)) != 1 || data["all"] != true ||
		data["complete"] != true || data["stop_reason"] != "complete" {
		t.Fatalf("app list --all 数据异常: %v", data)
	}
}

// TestStep220IterationFlagValidation 覆盖 --all/--max-* 参数互斥与上限拒绝。
func TestStep220IterationFlagValidation(t *testing.T) {
	fixture := newDomainFixture(t)
	base := []string{"group", "list", "--operator", "local-admin",
		"--config", fixture.configPath, "--json"}
	cases := []struct {
		name string
		args []string
	}{
		{"all 与 offset 互斥", []string{"--all", "--offset", "1"}},
		{"max-pages 需 all", []string{"--max-pages", "2"}},
		{"max-items 需 all", []string{"--max-items", "2"}},
		{"max-pages 超上限", []string{"--all", "--max-pages", "100000"}},
		{"max-items 超上限", []string{"--all", "--max-items", "1000000"}},
		{"max-pages 负值", []string{"--all", "--max-pages", "-1"}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			args := append(append([]string{}, base...), test.args...)
			_, stderr, exit := runCLI(t, args...)
			if exit != ExitUsage {
				t.Fatalf("退出码 = %d，期望 %d；stderr=%s", exit, ExitUsage, stderr)
			}
		})
	}
}
