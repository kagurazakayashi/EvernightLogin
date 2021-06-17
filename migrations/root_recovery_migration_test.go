package migrations_test

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// TestRootRecoveryMigration 校验 0028：root 本地应急恢复操作记录与通知 outbox 表
// 的字段、约束与索引；不得出现任何密码/哈希/令牌/认证器材料列。
func TestRootRecoveryMigration(t *testing.T) {
	data, err := migrations.SQLite.ReadFile("0028_root_recovery.sql")
	if err != nil {
		t.Fatalf("读取 0028 迁移: %v", err)
	}
	sqlText := string(data)
	if count := strings.Count(sqlText, "CREATE TABLE "); count != 1 {
		t.Fatalf("0028 CREATE TABLE 数量 = %d，期望 1", count)
	}
	for _, want := range []string{
		"CREATE TABLE root_recovery_events (",
		"root_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT",
		"operator_id TEXT NOT NULL CHECK(length(operator_id) BETWEEN 1 AND 128)",
		"operator_machine TEXT NOT NULL CHECK(length(operator_machine) BETWEEN 1 AND 128)",
		"reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 500)",
		"actions_json TEXT NOT NULL CHECK(json_valid(actions_json))",
		"password_reset INTEGER NOT NULL CHECK(password_reset IN(0,1))",
		"mfa_reset INTEGER NOT NULL CHECK(mfa_reset IN(0,1))",
		"passkeys_revoked INTEGER NOT NULL CHECK(passkeys_revoked IN(0,1))",
		"sessions_revoked INTEGER NOT NULL DEFAULT 0 CHECK(sessions_revoked >= 0)",
		"security_version_after INTEGER NOT NULL CHECK(security_version_after > 0)",
		"notification_state TEXT NOT NULL DEFAULT 'pending'",
		"CHECK(notification_state <> 'delivered' OR delivered_at_ms IS NOT NULL)",
	} {
		if !strings.Contains(sqlText, want) {
			t.Errorf("0028 缺少定义 %q", want)
		}
	}
	for _, index := range []string{
		"CREATE INDEX ix_root_recovery_events_pending",
		"CREATE INDEX ix_root_recovery_events_root",
	} {
		if !strings.Contains(sqlText, index) {
			t.Errorf("0028 缺少索引 %q", index)
		}
	}
	// 迁移/恢复记录不得保存密码、哈希、种子、恢复代码或 Passkey 材料。
	for _, forbidden := range []string{
		"password_hash", "password TEXT", "secret", "token", "seed", "private_key",
		"recovery_codes", "public_key",
	} {
		if strings.Contains(strings.ToLower(sqlText), forbidden) {
			t.Errorf("0028 不应出现敏感列 %q", forbidden)
		}
	}
	if strings.Contains(sqlText, "TIMESTAMP") || strings.Contains(sqlText, "BOOLEAN") {
		t.Error("迁移不应使用 TIMESTAMP/BOOLEAN 类型")
	}
}
