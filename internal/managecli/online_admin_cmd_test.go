package managecli

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/adminapi"
)

// TestAdminOnlineReadCommands 使用真实 adminapi Handler 验证步骤 156 在线只读
// admin 命令：统一 envelope/退出码，未挂载领域 404 不伪成功。
func TestAdminOnlineReadCommands(t *testing.T) {
	fixture := newOnlineFixture(t)
	fixture.serve(func(options *adminapi.Options) {
		options.DomainRoutes = []adminapi.DomainRoute{
			{Method: http.MethodGet, Pattern: "users", Handler: func(_ context.Context,
				caller account.Caller, _ *http.Request) (any, error) {
				return map[string]any{"items": []map[string]any{
					{"id": caller.Actor().ID, "username": "online-admin", "status": "active"},
				}, "has_more": false}, nil
			}},
			{Method: http.MethodPost, Pattern: "users", Handler: func(_ context.Context,
				caller account.Caller, request *http.Request) (any, error) {
				var body map[string]any
				if err := json.NewDecoder(request.Body).Decode(&body); err != nil || body["confirm"] != true {
					return nil, &adminapi.DomainError{Code: "REQ_INVALID", Message: "confirm required"}
				}
				return map[string]any{"id": caller.Actor().ID, "created": true}, nil
			}},
		}
	})
	stdout, stderr, exit := fixture.run("admin", "users", "--json")
	if exit != ExitOK {
		t.Fatalf("admin users --json 失败: exit=%d stderr=%s", exit, stderr)
	}
	if !strings.Contains(stdout, "\"ok\": true") || !strings.Contains(stdout, "online-admin") {
		t.Fatalf("admin users 输出不符: %s", stdout)
	}
	// 写命令：显式确认后提交服务端；缺少确认词只做用法拒绝。
	stdout, stderr, exit = fixture.run("admin", "write", "users", "--body", `{"username":"x"}`,
		"--confirm", "ADMIN-WRITE", "--json")
	if exit != ExitOK || !strings.Contains(stdout, "\"created\": true") {
		t.Fatalf("admin write 成功路径不符: exit=%d stdout=%s stderr=%s", exit, stdout, stderr)
	}
	if _, _, exit = fixture.run("admin", "write", "users", "--body", `{"username":"x"}`, "--json"); exit == ExitOK {
		t.Fatal("缺少确认词的写命令不应成功")
	}
	// 未挂载领域：稳定错误码/非零退出，不返回空成功。
	stdout, stderr, exit = fixture.run("admin", "groups", "--json")
	if exit == ExitOK {
		t.Fatalf("未挂载 groups 不应成功: %s %s", stdout, stderr)
	}
}
