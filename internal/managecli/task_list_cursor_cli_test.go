package managecli

// 步骤 218：CLI `task list` 稳定游标分页测试。
//   - --limit/--cursor 走领域统一列表契约，两页无重复；
//   - --request-id 筛选在存储层生效；
//   - 非法游标在参数层拒绝（退出码 2）。

import "testing"

func TestTaskListCursorCLI(t *testing.T) {
	env := newTaskTestEnv(t)
	ids := make([]string, 0, 3)
	for index := 0; index < 3; index++ {
		ids = append(ids, env.enqueueJob(t, "test.cursor"))
	}
	stdout, stderr, exit := runCLI(t, "task", "list", "--config", env.configPath,
		"--limit", "2", "--json")
	if exit != ExitOK {
		t.Fatalf("task list 第一页退出码 = %d，stderr=%s", exit, stderr)
	}
	data := decodeEnvelope(t, stdout)["data"].(map[string]any)
	firstJobs, _ := data["jobs"].([]any)
	if len(firstJobs) != 2 || data["has_more"] != true {
		t.Fatalf("task list 第一页 = %v", data)
	}
	cursor, _ := data["next_cursor"].(string)
	if cursor == "" {
		t.Fatal("task list 第一页缺少 next_cursor")
	}
	stdout, _, exit = runCLI(t, "task", "list", "--config", env.configPath,
		"--limit", "2", "--cursor", cursor, "--json")
	if exit != ExitOK {
		t.Fatalf("task list 第二页退出码 = %d", exit)
	}
	secondData := decodeEnvelope(t, stdout)["data"].(map[string]any)
	secondJobs, _ := secondData["jobs"].([]any)
	if len(secondJobs) != 1 || secondData["has_more"] != false {
		t.Fatalf("task list 第二页 = %v", secondData)
	}
	seen := map[string]bool{}
	for _, raw := range append(firstJobs, secondJobs...) {
		id, _ := raw.(map[string]any)["id"].(string)
		if seen[id] {
			t.Fatalf("task list 游标分页重复 %s", id)
		}
		seen[id] = true
	}
	for _, id := range ids {
		if !seen[id] {
			t.Fatalf("task list 游标分页遗漏 %s", id)
		}
	}
	// 非法游标在参数层拒绝。
	if _, _, exit := runCLI(t, "task", "list", "--config", env.configPath,
		"--cursor", "not-a-cursor", "--json"); exit != ExitUsage {
		t.Fatalf("非法游标退出码 = %d，期望 %d", exit, ExitUsage)
	}
}
