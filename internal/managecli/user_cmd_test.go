package managecli

// 本文件覆盖 `loginctl user` 的本地管理命令：只读查询、启停写入的真实审计、
// 确认词与版本前置、root 保护与拒绝路径的稳定退出码。

import (
	"context"
	"testing"

	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

// newUserTestEnv 构造含普通用户与 root 的临时数据库。
func newUserTestEnv(t *testing.T) (string, *storagesqlite.Store) {
	t.Helper()
	databasePath, store := newTestDatabase(t)
	seedUser(t, store, testUserID(1), "user1", false)
	seedUser(t, store, testUserID(2), "user2", false)
	rootID := testUserID(9)
	seedUser(t, store, rootID, "root", true)
	return writeConfigFile(t, t.TempDir(), databasePath), store
}

// userRowVersion 读取用户当前 row_version（测试直接读库夹具，不经过 CLI）。
func userRowVersion(t *testing.T, store *storagesqlite.Store, userID string) int64 {
	t.Helper()
	var version int64
	if err := store.DB().QueryRowContext(context.Background(),
		`SELECT row_version FROM users WHERE id = ?`, userID).Scan(&version); err != nil {
		t.Fatalf("读取 row_version: %v", err)
	}
	return version
}

// TestUserListAndGet 验证本地管理员只读查询。
func TestUserListAndGet(t *testing.T) {
	configPath, _ := newUserTestEnv(t)
	stdout, stderr, exit := runCLI(t, "user", "list", "--operator", "local-admin",
		"--config", configPath, "--json")
	if exit != ExitOK {
		t.Fatalf("user list 退出码 = %d，stderr=%s", exit, stderr)
	}
	data := decodeEnvelope(t, stdout)["data"].(map[string]any)
	users, _ := data["users"].([]any)
	if len(users) < 3 {
		t.Fatalf("用户列表 = %v", users)
	}
	stdout, _, exit = runCLI(t, "user", "get", testUserID(1), "--operator", "local-admin",
		"--config", configPath, "--json")
	if exit != ExitOK {
		t.Fatalf("user get 退出码 = %d", exit)
	}
	item := decodeEnvelope(t, stdout)["data"].(map[string]any)
	if item["username"] != "user1" || item["row_version"].(float64) != 1 {
		t.Fatalf("用户详情 = %v", item)
	}
	// 缺少 --operator 时是用法错误。
	if _, _, exit := runCLI(t, "user", "list", "--config", configPath); exit != ExitUsage {
		t.Fatalf("缺少操作者退出码 = %d，期望 %d", exit, ExitUsage)
	}
	// 非法用户 ID 是用法错误。
	if _, _, exit := runCLI(t, "user", "get", "not-a-user", "--operator", "local-admin",
		"--config", configPath); exit != ExitUsage {
		t.Fatalf("非法用户 ID 退出码 = %d，期望 %d", exit, ExitUsage)
	}
}

// TestUserDisableWritesAuditAndEnableRestores 验证启停写操作与真实审计。
func TestUserDisableWritesAuditAndEnableRestores(t *testing.T) {
	configPath, store := newUserTestEnv(t)
	userID := testUserID(1)
	version := userRowVersion(t, store, userID)
	stdout, stderr, exit := runCLI(t, "user", "disable", userID,
		"--operator", "local-admin", "--expected-version", "1",
		"--confirm", "DISABLE", "--config", configPath, "--json")
	if exit != ExitOK {
		t.Fatalf("disable 退出码 = %d，stderr=%s", exit, stderr)
	}
	data := decodeEnvelope(t, stdout)["data"].(map[string]any)
	if data["changed"] != true {
		t.Fatalf("disable 结果 = %v", data)
	}
	if userRowVersion(t, store, userID) != version+1 {
		t.Fatal("禁用后 row_version 未递增")
	}
	var auditCount int
	if err := store.DB().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM audit_events WHERE actor_type='local_admin'
AND actor_id='local-admin' AND action='user.disable' AND outcome='success'`).
		Scan(&auditCount); err != nil {
		t.Fatalf("读取审计事件: %v", err)
	}
	if auditCount == 0 {
		t.Fatal("禁用操作缺少真实审计事件")
	}
	// 启用回到 active。
	newVersion := userRowVersion(t, store, userID)
	stdout, _, exit = runCLI(t, "user", "enable", userID, "--operator", "local-admin",
		"--expected-version", itoa(newVersion), "--confirm", "ENABLE",
		"--config", configPath, "--json")
	if exit != ExitOK {
		t.Fatalf("enable 退出码 = %d", exit)
	}
	if decodeEnvelope(t, stdout)["data"].(map[string]any)["changed"] != true {
		t.Fatal("启用未产生变更")
	}
}

// TestUserDisableConfirmationRequired 验证缺少确认词时不写数据。
func TestUserDisableConfirmationRequired(t *testing.T) {
	configPath, store := newUserTestEnv(t)
	userID := testUserID(2)
	_, _, exit := runCLI(t, "user", "disable", userID, "--operator", "local-admin",
		"--expected-version", "1", "--config", configPath)
	if exit != ExitUsage {
		t.Fatalf("缺少确认退出码 = %d，期望 %d", exit, ExitUsage)
	}
	var status string
	if err := store.DB().QueryRowContext(context.Background(),
		`SELECT status FROM users WHERE id = ?`, userID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "active" {
		t.Fatalf("未确认的操作修改了用户状态: %s", status)
	}
}

// TestUserDisableVersionConflict 验证过期版本返回退出码 6。
func TestUserDisableVersionConflict(t *testing.T) {
	configPath, _ := newUserTestEnv(t)
	stdout, _, exit := runCLI(t, "user", "disable", testUserID(1),
		"--operator", "local-admin", "--expected-version", "99",
		"--confirm", "DISABLE", "--config", configPath, "--json")
	if exit != ExitConflict {
		t.Fatalf("版本冲突退出码 = %d，期望 %d", exit, ExitConflict)
	}
	if code := envelopeErrorCode(t, decodeEnvelope(t, stdout)); code != "CONFLICT" {
		t.Fatalf("错误码 = %s", code)
	}
}

// TestUserDisableRootProtected 验证 root 被账户服务拒绝（退出码 5）。
func TestUserDisableRootProtected(t *testing.T) {
	configPath, _ := newUserTestEnv(t)
	stdout, _, exit := runCLI(t, "user", "disable", testUserID(9),
		"--operator", "local-admin", "--expected-version", "1",
		"--confirm", "DISABLE", "--config", configPath, "--json")
	if exit != ExitForbidden {
		t.Fatalf("root 保护退出码 = %d，期望 %d", exit, ExitForbidden)
	}
	if code := envelopeErrorCode(t, decodeEnvelope(t, stdout)); code != "ACCESS_DENIED" {
		t.Fatalf("错误码 = %s", code)
	}
}

// TestUserUnknownSubcommand 验证未知子命令是用法错误。
func TestUserUnknownSubcommand(t *testing.T) {
	if _, _, exit := runCLI(t, "user", "delete", testUserID(1)); exit != ExitUsage {
		t.Fatalf("未知子命令退出码 = %d，期望 %d", exit, ExitUsage)
	}
}

// itoa 是测试用整数转字符串（避免引入额外导入）。
func itoa(value int64) string {
	if value == 0 {
		return "0"
	}
	digits := make([]byte, 0, 20)
	negative := value < 0
	if negative {
		value = -value
	}
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	if negative {
		return "-" + string(digits)
	}
	return string(digits)
}
