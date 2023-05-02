package managecli

import (
	"strings"
	"testing"
)

// TestSessionAdminRevokeUsage 覆盖步骤 151 CLI 入口的服务端不可替代检查：缺少
// 目标/理由/确认词时只做用法拒绝，不发起网络请求、不伪成功。
func TestSessionAdminRevokeUsage(t *testing.T) {
	cases := [][]string{
		{"session", "admin-revoke", "--user", "usr_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "--reason", "x"},
		{"session", "admin-revoke", "--user", "usr_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"--reason", "x", "--confirm", "WRONG"},
		{"session", "admin-revoke", "--confirm", "ADMIN-REVOKE", "--reason", "x"},
		{"session", "admin-revoke", "--user", "usr_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "--confirm", "ADMIN-REVOKE"},
		{"session", "admin-revoke", "--user", "usr_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"--session-id", "ses_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "--reason", "x", "--confirm", "ADMIN-REVOKE"},
	}
	for _, args := range cases {
		stdout, stderr, exit := runCLI(t, args...)
		if exit == ExitOK {
			t.Fatalf("参数不完整/未确认不应成功: %v stdout=%q", args, stdout)
		}
		if stdout != "" && stderr == "" {
			t.Fatalf("应输出用法/错误: %v", args)
		}
	}
}

// TestSessionAdminRevokeHelpDispatch 验证 session 帮助与实际分派一致：admin-revoke
// 已注册且帮助中可见，未退化为未知命令。
func TestSessionAdminRevokeHelpDispatch(t *testing.T) {
	stdout, stderr, exit := runCLI(t, "session")
	if exit != ExitOK || !strings.Contains(stdout, "session admin-revoke") {
		t.Fatalf("session 帮助未列出 admin-revoke: exit=%d stdout=%q stderr=%q",
			exit, stdout, stderr)
	}
}
