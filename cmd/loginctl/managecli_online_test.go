package main

// 本文件验证 cmd/loginctl 正确分派步骤 84 的在线管理命令组，且缺少在线公共
// 参数时返回稳定用法错误（与本地运维命令同一边界规则）。

import (
	"bytes"
	"strings"
	"testing"
)

// TestOnlineManageCLIDispatch 验证 audit/reports/backups/notifications/tasks 已接入
// loginctl 入口并能输出帮助；缺少 --session-file 时用法错误。
func TestOnlineManageCLIDispatch(t *testing.T) {
	cases := []struct {
		args     []string
		contains string
	}{
		{[]string{"audit", "help"}, "audit events list"},
		{[]string{"reports", "help"}, "reports history list"},
		{[]string{"backups", "help"}, "backups schedules"},
		{[]string{"notifications", "help"}, "notifications status"},
		{[]string{"tasks", "help"}, "tasks get"},
	}
	for _, testCase := range cases {
		var stdout, stderr bytes.Buffer
		exit := Run(testCase.args, strings.NewReader(""), &stdout, &stderr, nil)
		if exit != ExitOK {
			t.Fatalf("%v 退出码 = %d，stderr=%s", testCase.args, exit, stderr.String())
		}
		if !strings.Contains(stdout.String(), testCase.contains) {
			t.Fatalf("%v 帮助缺少 %q：%s", testCase.args, testCase.contains,
				stdout.String())
		}
	}

	// 在线命令必须提供受保护的管理会话秘密文件。
	var stdout, stderr bytes.Buffer
	exit := Run([]string{"audit", "events", "list"}, strings.NewReader(""),
		&stdout, &stderr, nil)
	if exit != ExitUsage {
		t.Fatalf("缺少 --session-file 退出码 = %d，期望 %d", exit, ExitUsage)
	}
	if !strings.Contains(stderr.String(), "--session-file") {
		t.Fatalf("缺少参数的提示不明: %s", stderr.String())
	}
}
