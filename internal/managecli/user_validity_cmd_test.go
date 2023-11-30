package managecli

// 步骤 234：`loginctl user validity` 本地命令测试。
//
// 覆盖默认无期限、到期/续期、手动禁用不解除、root 拒绝、非法区间与参数确认；
// 使用真实临时数据库与真实账户服务/审计。

import (
	"strconv"
	"testing"
	"time"
)

// TestUserValidityCLI 验证有效期读写命令的成功与拒绝路径。
func TestUserValidityCLI(t *testing.T) {
	configPath, store := newUserTestEnv(t)
	userID := testUserID(1)
	version := userRowVersion(t, store, userID)
	stdout, stderr, exit := runCLI(t, "user", "validity", "get", userID,
		"--operator", "local-admin", "--config", configPath, "--json")
	if exit != ExitOK {
		t.Fatalf("validity get 退出码 = %d，stderr=%s", exit, stderr)
	}
	data := decodeEnvelope(t, stdout)["data"].(map[string]any)
	if data["available"] != true || data["reason"] != "available" ||
		data["valid_from"] != nil || data["valid_until"] != nil {
		t.Fatalf("默认有效期异常: %v", data)
	}
	// 设置到过去：立即到期不可用。
	past := testNow.Add(-time.Hour).Format(time.RFC3339)
	stdout, stderr, exit = runCLI(t, "user", "validity", "set", userID,
		"--operator", "local-admin", "--config", configPath,
		"--expected-version", strconv.FormatInt(version, 10), "--confirm", "SET-VALIDITY",
		"--until", past, "--json")
	if exit != ExitOK {
		t.Fatalf("validity set 退出码 = %d，stderr=%s", exit, stderr)
	}
	data = decodeEnvelope(t, stdout)["data"].(map[string]any)
	validity := data["validity"].(map[string]any)
	if validity["available"] != false || validity["reason"] != "expired" {
		t.Fatalf("到期结果异常: %v", validity)
	}
	// 手动禁用后续期：状态仍 disabled，可用 false。
	version = userRowVersion(t, store, userID)
	if _, _, exit := runCLI(t, "user", "disable", userID, "--operator", "local-admin",
		"--config", configPath, "--expected-version", strconv.FormatInt(version, 10),
		"--confirm", "DISABLE", "--json"); exit != ExitOK {
		t.Fatalf("disable 退出码 = %d", exit)
	}
	version = userRowVersion(t, store, userID)
	future := testNow.Add(time.Hour).Format(time.RFC3339)
	stdout, stderr, exit = runCLI(t, "user", "validity", "set", userID,
		"--operator", "local-admin", "--config", configPath,
		"--expected-version", strconv.FormatInt(version, 10), "--confirm", "SET-VALIDITY",
		"--until", future, "--json")
	if exit != ExitOK {
		t.Fatalf("禁用后 set 退出码 = %d，stderr=%s", exit, stderr)
	}
	data = decodeEnvelope(t, stdout)["data"].(map[string]any)
	validity = data["validity"].(map[string]any)
	if validity["status"] != "disabled" || validity["available"] != false ||
		validity["reason"] != "disabled" {
		t.Fatalf("续期不得解除禁用: %v", validity)
	}
	// root：拒绝，退出码 3。
	rootVersion := userRowVersion(t, store, testUserID(9))
	future = testNow.Add(time.Hour).Format(time.RFC3339)
	if _, _, exit := runCLI(t, "user", "validity", "set", testUserID(9),
		"--operator", "local-admin", "--config", configPath,
		"--expected-version", strconv.FormatInt(rootVersion, 10), "--confirm", "SET-VALIDITY",
		"--until", future, "--json"); exit != ExitForbidden {
		t.Fatalf("root 设置退出码 = %d，期望 %d", exit, ExitForbidden)
	}
	// 非法区间：退出码 2。
	version = userRowVersion(t, store, userID)
	if _, _, exit := runCLI(t, "user", "validity", "set", userID,
		"--operator", "local-admin", "--config", configPath,
		"--expected-version", strconv.FormatInt(version, 10), "--confirm", "SET-VALIDITY",
		"--from", future, "--until", past, "--json"); exit != ExitUsage {
		t.Fatalf("非法区间退出码 = %d，期望 %d", exit, ExitUsage)
	}
	// 缺少确认词：退出码 2，不进入数据库写入。
	if _, _, exit := runCLI(t, "user", "validity", "set", userID,
		"--operator", "local-admin", "--config", configPath,
		"--expected-version", strconv.FormatInt(version, 10), "--json"); exit != ExitUsage {
		t.Fatalf("缺少确认词退出码 = %d", exit)
	}
}
