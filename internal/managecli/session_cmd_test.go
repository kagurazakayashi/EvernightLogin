package managecli

// 本文件覆盖 `loginctl session`：受保护会话文件读取、真实会话校验成功路径、
// 本人会话列表与撤销，以及未认证/受保护文件错误的稳定退出码。

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
)

// TestSessionWhoamiAndList 验证真实签发会话的 whoami/list 成功路径。
func TestSessionWhoamiAndList(t *testing.T) {
	databasePath, store := newTestDatabase(t)
	seedUser(t, store, testUserID(1), "user1", false)
	configPath := writeConfigFile(t, t.TempDir(), databasePath)
	ring, keyringPath := newProtectedKeyringFile(t)
	sessionPath := issueTestSessionForCLI(t, store, ring, testUserID(1))
	stdout, stderr, exit := runCLI(t, "session", "whoami", "--session-file", sessionPath,
		"--keyring-file", keyringPath, "--config", configPath, "--json")
	if exit != ExitOK {
		t.Fatalf("whoami 退出码 = %d，stderr=%s", exit, stderr)
	}
	data := decodeEnvelope(t, stdout)["data"].(map[string]any)
	if data["user_id"] != testUserID(1) || data["kind"] != "normal" {
		t.Fatalf("whoami 输出 = %v", data)
	}
	if stdoutHasSessionSecret(t, stdout, sessionPath) {
		t.Fatal("whoami 输出泄露了会话秘密")
	}
	stdout, _, exit = runCLI(t, "session", "list", "--session-file", sessionPath,
		"--keyring-file", keyringPath, "--config", configPath, "--json")
	if exit != ExitOK {
		t.Fatalf("session list 退出码 = %d", exit)
	}
	list := decodeEnvelope(t, stdout)["data"].(map[string]any)
	sessions, _ := list["sessions"].([]any)
	if len(sessions) != 1 {
		t.Fatalf("会话列表 = %v", list)
	}
	item := sessions[0].(map[string]any)
	if item["current"] != true || item["id"] == "" {
		t.Fatalf("会话项 = %v", item)
	}
	if stdoutHasSessionSecret(t, stdout, sessionPath) {
		t.Fatal("session list 输出泄露了会话秘密")
	}
}

// stdoutHasSessionSecret 报告输出是否包含会话秘密文件内容（防泄露断言）。
func stdoutHasSessionSecret(t *testing.T, output, sessionPath string) bool {
	t.Helper()
	secret, err := os.ReadFile(sessionPath)
	if err != nil {
		t.Fatal(err)
	}
	trimmed := string(secret)
	return len(trimmed) > 0 && containsString(output, trimmed)
}

// containsString 是简单子串判断。
func containsString(haystack, needle string) bool {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return false
	}
	for index := 0; index+len(needle) <= len(haystack); index++ {
		if haystack[index:index+len(needle)] == needle {
			return true
		}
	}
	return false
}

// TestSessionRevokeOwnSession 验证只撤销本人指定会话且秘密不进入输出。
func TestSessionRevokeOwnSession(t *testing.T) {
	databasePath, store := newTestDatabase(t)
	seedUser(t, store, testUserID(1), "user1", false)
	configPath := writeConfigFile(t, t.TempDir(), databasePath)
	ring, keyringPath := newProtectedKeyringFile(t)
	firstSecretPath := issueTestSessionForCLI(t, store, ring, testUserID(1))
	secondSecretPath := issueTestSessionForCLI(t, store, ring, testUserID(1))
	// 用第二个会话列出全部会话，找到第一个会话的公开 ID。
	stdout, _, exit := runCLI(t, "session", "list", "--session-file", secondSecretPath,
		"--keyring-file", keyringPath, "--config", configPath, "--json")
	if exit != ExitOK {
		t.Fatalf("session list 退出码 = %d", exit)
	}
	sessions := decodeEnvelope(t, stdout)["data"].(map[string]any)["sessions"].([]any)
	var targetID string
	currentID := ""
	for _, raw := range sessions {
		item := raw.(map[string]any)
		id, _ := item["id"].(string)
		if item["current"] == true {
			currentID = id
			continue
		}
		targetID = id
	}
	if targetID == "" || currentID == "" {
		t.Fatalf("无法定位目标会话: %v", sessions)
	}
	stdout, stderr, exit := runCLI(t, "session", "revoke", targetID,
		"--session-file", secondSecretPath, "--keyring-file", keyringPath,
		"--config", configPath, "--json")
	if exit != ExitOK {
		t.Fatalf("revoke 退出码 = %d，stderr=%s", exit, stderr)
	}
	data := decodeEnvelope(t, stdout)["data"].(map[string]any)
	if data["revoked"] != true {
		t.Fatalf("撤销结果 = %v", data)
	}
	// 被撤销的会话不能再通过 CLI 校验（退出码 4）。
	_, _, exit = runCLI(t, "session", "whoami", "--session-file", firstSecretPath,
		"--keyring-file", keyringPath, "--config", configPath)
	if exit != ExitUnauthenticated {
		t.Fatalf("已撤销会话 whoami 退出码 = %d，期望 %d", exit, ExitUnauthenticated)
	}
}

// TestSessionInvalidSecretReturnsUnauthenticated 验证无效会话秘密返回退出码 4。
func TestSessionInvalidSecretReturnsUnauthenticated(t *testing.T) {
	databasePath, _ := newTestDatabase(t)
	configPath := writeConfigFile(t, t.TempDir(), databasePath)
	_, keyringPath := newProtectedKeyringFile(t)
	sessionPath := filepath.Join(t.TempDir(), "session.secret")
	if err := os.WriteFile(sessionPath, []byte("ses_invalid_secret_value"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := secrets.ProtectFile(sessionPath); err != nil {
		t.Fatalf("收紧会话文件权限: %v", err)
	}
	stdout, _, exit := runCLI(t, "session", "whoami", "--session-file", sessionPath,
		"--keyring-file", keyringPath, "--config", configPath, "--json")
	if exit != ExitUnauthenticated {
		t.Fatalf("无效会话退出码 = %d，期望 %d", exit, ExitUnauthenticated)
	}
	if code := envelopeErrorCode(t, decodeEnvelope(t, stdout)); code != "AUTH_FAILED" {
		t.Fatalf("错误码 = %s", code)
	}
}

// TestSessionMissingFlagsUsage 验证缺少必需参数是用法错误。
func TestSessionMissingFlagsUsage(t *testing.T) {
	if _, _, exit := runCLI(t, "session", "whoami"); exit != ExitUsage {
		t.Fatalf("缺少参数退出码 = %d，期望 %d", exit, ExitUsage)
	}
	// 步骤 151：管理下线已接在线命令；缺少目标/理由/确认词应返回用法错误，
	// 不发起网络请求，也不伪成功。
	if _, _, exit := runCLI(t, "session", "admin-revoke", "ses_x"); exit != ExitUsage {
		t.Fatalf("管理下线缺参退出码 = %d，期望 %d", exit, ExitUsage)
	}
}

// TestSessionUnprotectedFileRejected 验证未按平台要求保护的文件被拒绝
// （Windows/test 环境若 ACL 判定为受保护则跳过该断言）。
func TestSessionUnprotectedFileRejected(t *testing.T) {
	databasePath, _ := newTestDatabase(t)
	configPath := writeConfigFile(t, t.TempDir(), databasePath)
	_, keyringPath := newProtectedKeyringFile(t)
	sessionPath := filepath.Join(t.TempDir(), "session.secret")
	if err := os.WriteFile(sessionPath, []byte("ses_some_secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := secrets.CheckProtectedFile(sessionPath); err == nil {
		t.Skip("当前环境无法构造未受保护的会话文件")
	}
	stdout, _, exit := runCLI(t, "session", "whoami", "--session-file", sessionPath,
		"--keyring-file", keyringPath, "--config", configPath, "--json")
	if exit != ExitUnauthenticated {
		t.Fatalf("未受保护文件退出码 = %d，期望 %d", exit, ExitUnauthenticated)
	}
	if code := envelopeErrorCode(t, decodeEnvelope(t, stdout)); code != "SESSION_FILE_INVALID" {
		t.Fatalf("错误码 = %s", code)
	}
}
