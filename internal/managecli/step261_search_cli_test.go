package managecli

// 步骤 261：用户列表与应用成员列表 CLI 搜索参数契约测试。
//   - user list --search/--search-fields 进入领域请求，JSON 输出回显 search；
//   - app members --search/--search-fields 只在当前应用成员范围内匹配；
//   - 非法字段/超长搜索在参数或领域校验阶段拒绝（退出码 2）。

import (
	"context"
	"strings"
	"testing"
)

// TestUserListSearchCLI 验收 `loginctl user list` 的搜索参数。
func TestUserListSearchCLI(t *testing.T) {
	configPath, _ := newUserTestEnv(t)

	// 大小写折叠：USER1 命中用户名/昵称 user1（夹具昵称与用户名相同）。
	stdout, stderr, exit := runCLI(t, "user", "list", "--operator", "local-admin",
		"--config", configPath, "--search", "USER1", "--json")
	if exit != ExitOK {
		t.Fatalf("user list --search 退出码 = %d，stderr=%s", exit, stderr)
	}
	data := decodeEnvelope(t, stdout)["data"].(map[string]any)
	if data["search"] != "USER1" {
		t.Fatalf("输出未回显搜索条件: %v", data["search"])
	}
	users, _ := data["users"].([]any)
	if len(users) != 1 {
		t.Fatalf("搜索 USER1 结果数 = %d，期望 1", len(users))
	}
	first, _ := users[0].(map[string]any)
	if first["username"] != "user1" {
		t.Fatalf("搜索结果 = %v", first)
	}

	// 字段白名单：只搜昵称同样命中（夹具昵称=用户名）。
	stdout, _, exit = runCLI(t, "user", "list", "--operator", "local-admin",
		"--config", configPath, "--search", "user1", "--search-fields", "nickname", "--json")
	if exit != ExitOK {
		t.Fatalf("限定昵称搜索退出码 = %d", exit)
	}
	if users, _ := decodeEnvelope(t, stdout)["data"].(map[string]any)["users"].([]any); len(users) != 1 {
		t.Fatalf("限定昵称搜索结果 = %v", users)
	}

	// 非法字段/超长搜索被拒绝（退出码 2，不进入领域查询）。
	for _, args := range [][]string{
		{"--search", "user", "--search-fields", "email"},
		{"--search", strings.Repeat("a", 65)},
	} {
		full := append([]string{"user", "list", "--operator", "local-admin",
			"--config", configPath, "--json"}, args...)
		if _, _, exit := runCLI(t, full...); exit != ExitUsage {
			t.Fatalf("非法搜索参数 %v 退出码 = %d，期望 %d", args, exit, ExitUsage)
		}
	}
}

// TestAppMembersSearchCLI 验收 `loginctl app members` 的搜索参数与应用内范围。
func TestAppMembersSearchCLI(t *testing.T) {
	fixture := newDomainFixture(t)
	now := testNow.UnixMilli()
	if _, err := fixture.raw.DB().ExecContext(context.Background(), `INSERT INTO app_memberships(
app_id,user_id,status,profile_json,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,'active','{"v":1}',1,?,?)`, fixture.appID, testUserID(1), now, now); err != nil {
		t.Fatalf("插入成员夹具失败: %v", err)
	}

	stdout, stderr, exit := runCLI(t, "app", "members", fixture.appID, "--operator",
		"local-admin", "--search", "USER1", "--config", fixture.configPath, "--json")
	if exit != ExitOK {
		t.Fatalf("app members --search 退出码 = %d，stderr=%s", exit, stderr)
	}
	data := decodeEnvelope(t, stdout)["data"].(map[string]any)
	if data["search"] != "USER1" {
		t.Fatalf("成员输出未回显搜索条件: %v", data["search"])
	}
	if members, _ := data["members"].([]any); len(members) != 1 {
		t.Fatalf("成员搜索结果数 = %d，期望 1", len(members))
	}
	// 不存在的关键字返回空列表而不是错误。
	stdout, _, exit = runCLI(t, "app", "members", fixture.appID, "--operator",
		"local-admin", "--search", "不存在的人", "--config", fixture.configPath, "--json")
	if exit != ExitOK {
		t.Fatalf("无匹配成员搜索退出码 = %d", exit)
	}
	if members, _ := decodeEnvelope(t, stdout)["data"].(map[string]any)["members"].([]any); len(members) != 0 {
		t.Fatalf("无匹配成员搜索结果 = %v", members)
	}
	// 非法字段拒绝。
	if _, _, exit := runCLI(t, "app", "members", fixture.appID, "--operator",
		"local-admin", "--search", "x", "--search-fields", "phone",
		"--config", fixture.configPath, "--json"); exit != ExitUsage {
		t.Fatalf("非法成员搜索字段退出码 = %d，期望 %d", exit, ExitUsage)
	}
}
