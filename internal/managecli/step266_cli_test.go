package managecli

// 步骤 266：在线 CLI 新增入口的用法校验测试（不连接服务、不发网络请求）。
// 分页/筛选参数的错误必须在连接前拒绝；合法用法由 E2E 覆盖（管理 API 端点）。
// 这里只验证稳定退出码与提示，避免把不可达服务误判为参数通过。

import (
	"strings"
	"testing"
)

// TestStep266HistoryCLIFlagValidation 验证 notifications history / deliveries list 的
// limit 边界在连接前即拒绝（用法错误退出码）。
func TestStep266HistoryCLIFlagValidation(t *testing.T) {
	for _, args := range [][]string{
		{"notifications", "history", "--limit", "0"},
		{"notifications", "history", "--limit", "101"},
		{"deliveries", "list", "--limit", "0"},
		{"deliveries", "list", "--limit", "101"},
	} {
		stdout, stderr, exit := runCLI(t, args...)
		if exit != ExitUsage {
			t.Fatalf("%v 退出码 = %d，期望 %d（stdout=%s stderr=%s）",
				args, exit, ExitUsage, stdout, stderr)
		}
		if !strings.Contains(stderr, "--limit") {
			t.Fatalf("%v 缺少 limit 提示: %s", args, stderr)
		}
	}
}

// TestStep266HistoryCLIHelp 验证新增命令在帮助中可见（能力可发现，不隐藏）。
func TestStep266HistoryCLIHelp(t *testing.T) {
	stdout, _, exit := runCLI(t, "help")
	if exit != ExitOK {
		t.Fatalf("help 退出码 = %d", exit)
	}
	for _, want := range []string{"notifications status|history|test", "deliveries list"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("帮助缺少 %q: %s", want, stdout)
		}
	}
}

// TestStep266HistoryLimitBoundary 验证本地 limit 校验与服务端 adminapi.MaxPageLimit
// 对齐：100 通过、101 拒绝（修复 N-266-1 的 101..200 本地宽松窗口）。
func TestStep266HistoryLimitBoundary(t *testing.T) {
	accepted, err := historyListLimit(map[string]string{"limit": "100"})
	if err != nil || accepted != 100 {
		t.Fatalf("limit=100 应通过本地校验，得到 %d/%v", accepted, err)
	}
	if _, err := historyListLimit(map[string]string{"limit": "101"}); err == nil {
		t.Fatal("limit=101 应在连接前拒绝（服务端上限 100）")
	}
	if _, err := historyListLimit(map[string]string{"limit": "0"}); err == nil {
		t.Fatal("limit=0 应拒绝")
	}
	defaultLimit, err := historyListLimit(map[string]string{})
	if err != nil || defaultLimit != 20 {
		t.Fatalf("默认 limit 应为 20，得到 %d/%v", defaultLimit, err)
	}
}
