package migrations_test

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// TestRecoveryCodesMigration 校验 0024：恢复代码组、代码摘要与受限恢复尝试三张表
// 的结构与约束；数据库不得保存恢复代码明文。
func TestRecoveryCodesMigration(t *testing.T) {
	data, err := migrations.SQLite.ReadFile("0024_recovery_codes.sql")
	if err != nil {
		t.Fatalf("读取 0024 迁移: %v", err)
	}
	sqlText := string(data)
	if count := strings.Count(sqlText, "CREATE TABLE "); count != 3 {
		t.Fatalf("0024 CREATE TABLE 数量 = %d，期望 3", count)
	}
	groups := tableDefinition(t, sqlText, "recovery_code_groups")
	for _, want := range []string{
		"id TEXT PRIMARY KEY NOT NULL",
		"user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE",
		"generation INTEGER NOT NULL CHECK(generation>=1)",
		"status TEXT NOT NULL CHECK(status IN('active','superseded','exhausted','revoked'))",
		"code_count INTEGER NOT NULL CHECK(code_count>0 AND code_count<=64)",
		"created_at_ms INTEGER NOT NULL",
		"invalidated_at_ms INTEGER",
		"UNIQUE(user_id,generation)",
	} {
		if !strings.Contains(groups, want) {
			t.Errorf("recovery_code_groups 缺少定义 %q", want)
		}
	}
	codes := tableDefinition(t, sqlText, "recovery_codes")
	for _, want := range []string{
		"id TEXT PRIMARY KEY NOT NULL",
		"group_id TEXT NOT NULL REFERENCES recovery_code_groups(id) ON DELETE CASCADE",
		"user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE",
		"digest BLOB NOT NULL CHECK(length(digest)=32)",
		"key_id TEXT NOT NULL",
		"used_at_ms INTEGER",
		"created_at_ms INTEGER NOT NULL",
	} {
		if !strings.Contains(codes, want) {
			t.Errorf("recovery_codes 缺少定义 %q", want)
		}
	}
	attempts := tableDefinition(t, sqlText, "recovery_attempts")
	for _, want := range []string{
		"id TEXT PRIMARY KEY NOT NULL",
		"user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE",
		"group_id TEXT NOT NULL REFERENCES recovery_code_groups(id) ON DELETE RESTRICT",
		"code_id TEXT NOT NULL REFERENCES recovery_codes(id) ON DELETE RESTRICT",
		"status TEXT NOT NULL CHECK(status IN('pending_binding','completed','cancelled','expired','failed'))",
		"session_id TEXT",
		"planned_method TEXT",
		"planned_binding_id TEXT",
		"factor_method TEXT",
		"factor_ref TEXT",
		"attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0)",
		"max_attempts INTEGER NOT NULL CHECK(max_attempts>=1 AND max_attempts<=10)",
		"expires_at_ms INTEGER NOT NULL",
		"created_at_ms INTEGER NOT NULL",
		"updated_at_ms INTEGER NOT NULL",
		"finished_at_ms INTEGER",
	} {
		if !strings.Contains(attempts, want) {
			t.Errorf("recovery_attempts 缺少定义 %q", want)
		}
	}
	// 恢复代码是高熵一次性秘密：数据库不得出现明文代码列或可还原加密列。
	for _, forbidden := range []string{" plaintext", " code TEXT", " secret TEXT", " code_value", " encrypted_code"} {
		if strings.Contains(strings.ToLower(sqlText), forbidden) {
			t.Errorf("0024 不应引入代码明文/可还原列 %q", forbidden)
		}
	}
	for _, index := range []string{
		"CREATE UNIQUE INDEX ux_recovery_code_groups_active",
		"ON recovery_code_groups(user_id) WHERE status='active'",
		"CREATE INDEX ix_recovery_codes_group",
		"CREATE UNIQUE INDEX ux_recovery_attempts_pending",
		"ON recovery_attempts(user_id) WHERE status='pending_binding'",
		"CREATE INDEX ix_recovery_attempts_session",
	} {
		if !strings.Contains(sqlText, index) {
			t.Errorf("0024 缺少索引 %q", index)
		}
	}
	if strings.Contains(sqlText, "TIMESTAMP") || strings.Contains(sqlText, "BOOLEAN") {
		t.Error("迁移不应使用 TIMESTAMP/BOOLEAN 类型")
	}
}
