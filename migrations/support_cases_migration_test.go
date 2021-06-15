package migrations_test

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// TestSupportCasesMigration 校验 0026：求助单绑定目标/创建人/指派客服与状态机，
// 处理历史追加式且禁止 UPDATE；不保存密码、MFA、凭证或找回 token。
func TestSupportCasesMigration(t *testing.T) {
	data, err := migrations.SQLite.ReadFile("0026_support_cases.sql")
	if err != nil {
		t.Fatalf("读取客服求助单迁移: %v", err)
	}
	sqlText := string(data)
	if count := strings.Count(sqlText, "CREATE TABLE "); count != 2 {
		t.Fatalf("0026 CREATE TABLE 数量 = %d，期望 2", count)
	}
	for _, want := range []string{
		"CREATE TABLE support_cases (",
		"target_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE",
		"created_by_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE",
		"assignee_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE",
		"reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 2000)",
		"status TEXT NOT NULL CHECK(status IN(",
		"'pending_verification','sent','manual_review','closed','cancelled'",
		"target_masked_email TEXT NOT NULL DEFAULT ''",
		"row_version INTEGER NOT NULL DEFAULT 1 CHECK(row_version >= 1)",
		"CHECK(updated_at_ms >= created_at_ms)",
		"CREATE INDEX ix_support_cases_assignee",
		"CREATE INDEX ix_support_cases_target",
		"CREATE TABLE support_case_events (",
		"case_id TEXT NOT NULL REFERENCES support_cases(id) ON DELETE CASCADE",
		"seq INTEGER NOT NULL CHECK(seq >= 1)",
		"actor_type TEXT NOT NULL CHECK(actor_type IN('user','system','local_admin'))",
		"UNIQUE(case_id, seq)",
		"CREATE INDEX ix_support_case_events_case",
		"CREATE TRIGGER trg_support_case_events_no_update",
		"BEFORE UPDATE ON support_case_events",
		"RAISE(ABORT, 'support_case_events is append-only')",
	} {
		if !strings.Contains(sqlText, want) {
			t.Errorf("0026 缺少定义 %q", want)
		}
	}
	// 求助单/历史只保存脱敏与业务字段，不得出现密码、MFA、凭证或 token 明文列。
	for _, forbidden := range []string{
		"password", "secret", "mfa_secret", "recovery_code", "credential_id",
	} {
		if strings.Contains(strings.ToLower(sqlText), forbidden) {
			t.Errorf("0026 不应保存敏感明文列 %q", forbidden)
		}
	}
}
