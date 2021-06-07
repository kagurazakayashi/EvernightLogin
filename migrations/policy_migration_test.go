package migrations_test

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// TestSensitivePolicyMigration 校验 0018 的敏感操作策略结构：作用域版本、覆盖/应用
// 声明行、可配置的五类策略字段、作用域外键与应用删除级联，且不保存明文秘密或
// 重复存储系统默认目录。
func TestSensitivePolicyMigration(t *testing.T) {
	data, err := migrations.SQLite.ReadFile("0018_sensitive_operation_policies.sql")
	if err != nil {
		t.Fatalf("读取敏感策略迁移: %v", err)
	}
	sqlText := string(data)
	if count := strings.Count(sqlText, "CREATE TABLE "); count != 2 {
		t.Fatalf("0018 CREATE TABLE 数量 = %d，期望 2", count)
	}
	for _, want := range []string{
		"CREATE TABLE sensitive_policy_scopes (",
		"scope_id TEXT PRIMARY KEY NOT NULL REFERENCES scopes(id) ON DELETE CASCADE",
		"version INTEGER NOT NULL DEFAULT 0 CHECK(version >= 0)",
		"updated_at_ms INTEGER NOT NULL",
		"CREATE TABLE sensitive_operation_policies (",
		"scope_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE",
		"operation_id TEXT NOT NULL CHECK(length(operation_id) BETWEEN 3 AND 128)",
		"is_sensitive INTEGER NOT NULL CHECK(is_sensitive IN(0,1))",
		"reauth_required INTEGER NOT NULL CHECK(reauth_required IN(0,1))",
		"max_auth_age_seconds INTEGER NOT NULL CHECK(max_auth_age_seconds BETWEEN 0 AND 2592000)",
		"required_strength TEXT NOT NULL CHECK(required_strength IN('none','password','strong'))",
		"confirmation_required INTEGER NOT NULL CHECK(confirmation_required IN(0,1))",
		"notification_required INTEGER NOT NULL CHECK(notification_required IN(0,1))",
		"source_kind TEXT NOT NULL CHECK(source_kind IN('override','application'))",
		"name TEXT NOT NULL DEFAULT ''",
		"description TEXT NOT NULL DEFAULT ''",
		"row_version INTEGER NOT NULL DEFAULT 1 CHECK(row_version > 0)",
		"PRIMARY KEY(scope_id, operation_id)",
	} {
		if !strings.Contains(sqlText, want) {
			t.Errorf("0018 缺少定义 %q", want)
		}
	}
	for _, index := range []string{
		"CREATE INDEX ix_sensitive_operation_policies_scope_source",
	} {
		if !strings.Contains(sqlText, index) {
			t.Errorf("0018 缺少索引 %q", index)
		}
	}
	// 策略表不得保存秘密、原始操作内容或系统默认目录副本；默认值只在代码中维护。
	for _, forbidden := range []string{
		" password ", " secret ", " token ", " policy_json ", " default_policy",
		" full_policy ", " permission_key ", " root_only ",
	} {
		if strings.Contains(strings.ToLower(sqlText), forbidden) {
			t.Errorf("0018 不应引入列 %q", forbidden)
		}
	}
	for _, future := range []string{
		"CREATE TABLE policy_notifications", "CREATE TABLE operation_audit",
		"CREATE TABLE mfa_credentials",
	} {
		if strings.Contains(sqlText, future) {
			t.Errorf("0018 提前创建了后续步骤的表 %q", future)
		}
	}
	if strings.Contains(sqlText, "TIMESTAMP") || strings.Contains(sqlText, "BOOLEAN") {
		t.Error("迁移不应使用 TIMESTAMP/BOOLEAN 类型")
	}
}
