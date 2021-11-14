package main

// CLI 契约测试：命令树存在 serve/init、版本与帮助可用、缺少必需参数时诚实失败。
// 这些用例不打开数据库、不监听端口、不创建后台任务。

import (
	"bytes"
	"strings"
	"testing"
)

func runForTest(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestVersion(t *testing.T) {
	code, stdout, stderr := runForTest(t, "--version")
	if code != 0 {
		t.Fatalf("--version 退出码应为 0，实际 %d（stderr=%s）", code, stderr)
	}
	if !strings.Contains(stdout, "login-server") {
		t.Fatalf("--version 输出异常: %s", stdout)
	}
}

func TestHelpListsServeAndInit(t *testing.T) {
	code, stdout, stderr := runForTest(t, "--help")
	if code != 0 {
		t.Fatalf("--help 退出码应为 0，实际 %d（stderr=%s）", code, stderr)
	}
	for _, command := range []string{"serve", "init"} {
		if !strings.Contains(stdout, command) {
			t.Fatalf("帮助未列出 %s 子命令: %s", command, stdout)
		}
	}
}

func TestNoArgumentsFailsHonestly(t *testing.T) {
	code, _, stderr := runForTest(t)
	if code != 1 {
		t.Fatalf("无参数运行退出码应为 1，实际 %d", code)
	}
	if !strings.Contains(stderr, "serve 或 init") {
		t.Fatalf("无参数错误信息未指向真实子命令: %s", stderr)
	}
}

func TestServeRequiresConfig(t *testing.T) {
	code, _, stderr := runForTest(t, "serve")
	if code != 1 {
		t.Fatalf("serve 缺少 --config 应失败，实际退出码 %d", code)
	}
	if !strings.Contains(stderr, "--config") {
		t.Fatalf("serve 缺少 --config 错误信息不明确: %s", stderr)
	}
}

func TestInitRequiresConfig(t *testing.T) {
	code, _, stderr := runForTest(t, "init")
	if code != 1 {
		t.Fatalf("init 缺少 --config 应失败，实际退出码 %d", code)
	}
	if !strings.Contains(stderr, "--config") {
		t.Fatalf("init 缺少 --config 错误信息不明确: %s", stderr)
	}
}

func TestServeRejectsUnknownMigrateValue(t *testing.T) {
	code, _, stderr := runForTest(t, "serve", "--config", "ignored.yaml",
		"--migrate=everything")
	if code != 1 {
		t.Fatalf("非法 --migrate 值应失败，实际退出码 %d", code)
	}
	if !strings.Contains(stderr, "--migrate") {
		t.Fatalf("非法 --migrate 错误信息不明确: %s", stderr)
	}
}
