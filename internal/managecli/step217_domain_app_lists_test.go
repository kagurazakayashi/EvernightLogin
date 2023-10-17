package managecli

// 步骤 217：应用范围列表 CLI 的分页/筛选/排序契约测试。
//   - app list：--sort/--desc/--limit/--offset 进入领域请求，JSON 输出统一分页元数据；
//   - app members：--status/--sort/--desc 生效且输出 next_offset；
//   - app roles / app groups：作用范围固定为路径应用 ID，分页元数据完整；
//   - 非法排序白名单在参数解析阶段拒绝（退出码 2），不进入领域查询。

import "testing"

func TestAppScopedListCommandsPagination(t *testing.T) {
	fixture := newDomainFixture(t)

	stdout, stderr, exit := runCLI(t, "app", "list", "--operator", "local-admin",
		"--sort", "name", "--desc", "true", "--limit", "5", "--offset", "0",
		"--config", fixture.configPath, "--json")
	if exit != ExitOK {
		t.Fatalf("app list 退出码 = %d，stderr=%s", exit, stderr)
	}
	listData := decodeEnvelope(t, stdout)["data"].(map[string]any)
	if listData["sort"] != "name" || listData["desc"] != true ||
		listData["next_offset"] == nil || listData["has_more"] == nil {
		t.Fatalf("app list 分页元数据 = %v", listData)
	}

	stdout, _, exit = runCLI(t, "app", "members", fixture.appID, "--operator",
		"local-admin", "--status", "active", "--sort", "user_id", "--desc", "false",
		"--limit", "5", "--config", fixture.configPath, "--json")
	if exit != ExitOK {
		t.Fatalf("app members 退出码 = %d", exit)
	}
	memberData := decodeEnvelope(t, stdout)["data"].(map[string]any)
	if memberData["sort"] != "user_id" || memberData["next_offset"] == nil {
		t.Fatalf("app members 分页元数据 = %v", memberData)
	}

	for _, subcommand := range []string{"roles", "groups"} {
		stdout, stderr, exit = runCLI(t, "app", subcommand, fixture.appID, "--operator",
			"local-admin", "--sort", "name", "--limit", "5", "--offset", "0",
			"--config", fixture.configPath, "--json")
		if exit != ExitOK {
			t.Fatalf("app %s 退出码 = %d，stderr=%s", subcommand, exit, stderr)
		}
		data := decodeEnvelope(t, stdout)["data"].(map[string]any)
		if data["scope_id"] != fixture.appID || data["has_more"] == nil ||
			data["next_offset"] == nil || data["sort"] != "name" {
			t.Fatalf("app %s 分页元数据 = %v", subcommand, data)
		}
		if items, ok := data[subcommand].([]any); !ok || len(items) != 0 {
			t.Fatalf("app %s 应返回空列表（fixture 无应用范围记录） = %v", subcommand, data)
		}
	}

	if _, _, exit := runCLI(t, "app", "roles", fixture.appID, "--operator", "local-admin",
		"--sort", "bogus", "--config", fixture.configPath, "--json"); exit != ExitUsage {
		t.Fatalf("非法应用角色排序退出码 = %d，期望 %d", exit, ExitUsage)
	}
	if _, _, exit := runCLI(t, "app", "members", fixture.appID, "--operator", "local-admin",
		"--status", "bogus", "--config", fixture.configPath, "--json"); exit != ExitUsage {
		t.Fatalf("非法成员状态退出码 = %d，期望 %d", exit, ExitUsage)
	}
}
