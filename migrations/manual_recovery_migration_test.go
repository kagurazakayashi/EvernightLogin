package migrations_test

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// TestManualRecoveryMigration 校验 0027：人工恢复申请/独立批准/一次性执行三张表的
// 结构与安全约束（内容摘要、唯一 active 批准、唯一执行、不保存证据明文/凭证）。
func TestManualRecoveryMigration(t *testing.T) {
	data, err := migrations.SQLite.ReadFile("0027_manual_recovery.sql")
	if err != nil {
		t.Fatalf("读取 0027 迁移: %v", err)
	}
	sqlText := string(data)
	if count := strings.Count(sqlText, "CREATE TABLE "); count != 3 {
		t.Fatalf("0027 CREATE TABLE 数量 = %d，期望 3", count)
	}
	requests := tableDefinition(t, sqlText, "manual_recovery_requests")
	for _, want := range []string{
		"id TEXT PRIMARY KEY NOT NULL",
		"target_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE",
		"initiator_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE",
		"operation_type TEXT NOT NULL CHECK(operation_type IN('password_reset','mfa_reset'))",
		"status TEXT NOT NULL CHECK(status IN(",
		"verification_basis TEXT NOT NULL CHECK(verification_basis IN(",
		"verification_reference TEXT NOT NULL CHECK(length(verification_reference) BETWEEN 1 AND 128)",
		"evidence_digest BLOB NOT NULL CHECK(length(evidence_digest)=32)",
		"delivery_channel TEXT NOT NULL CHECK(delivery_channel IN('verified_email'))",
		"delivery_fingerprint TEXT NOT NULL CHECK(length(delivery_fingerprint) BETWEEN 1 AND 128)",
		"target_security_version INTEGER NOT NULL CHECK(target_security_version>0)",
		"content_digest BLOB NOT NULL CHECK(length(content_digest)=32)",
		"row_version INTEGER NOT NULL DEFAULT 1 CHECK(row_version>=1)",
		"expires_at_ms INTEGER NOT NULL",
	} {
		if !strings.Contains(requests, want) {
			t.Errorf("manual_recovery_requests 缺少定义 %q", want)
		}
	}
	approvals := tableDefinition(t, sqlText, "manual_recovery_approvals")
	for _, want := range []string{
		"request_id TEXT NOT NULL REFERENCES manual_recovery_requests(id) ON DELETE CASCADE",
		"approver_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE",
		"operation_type TEXT NOT NULL CHECK(operation_type IN('password_reset','mfa_reset'))",
		"content_digest BLOB NOT NULL CHECK(length(content_digest)=32)",
		"status TEXT NOT NULL CHECK(status IN('active','consumed','invalidated','expired'))",
		"not_before_ms INTEGER NOT NULL",
		"expires_at_ms INTEGER NOT NULL",
		"CHECK(expires_at_ms>not_before_ms)",
	} {
		if !strings.Contains(approvals, want) {
			t.Errorf("manual_recovery_approvals 缺少定义 %q", want)
		}
	}
	executions := tableDefinition(t, sqlText, "manual_recovery_executions")
	for _, want := range []string{
		"approval_id TEXT NOT NULL UNIQUE REFERENCES manual_recovery_approvals(id) ON DELETE RESTRICT",
		"executor_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE",
		"status TEXT NOT NULL CHECK(status IN('running','succeeded','failed'))",
		"sessions_revoked INTEGER NOT NULL DEFAULT 0 CHECK(sessions_revoked>=0)",
		"factors_reset INTEGER NOT NULL DEFAULT 0 CHECK(factors_reset IN(0,1))",
		"notification_state TEXT NOT NULL DEFAULT 'pending'",
	} {
		if !strings.Contains(executions, want) {
			t.Errorf("manual_recovery_executions 缺少定义 %q", want)
		}
	}
	// 证据/秘密不得以明文列进入数据库。
	for _, forbidden := range []string{" evidence_text", " evidence BLOB", " password ", " secret ", " code ", " token ", " document "} {
		if strings.Contains(strings.ToLower(sqlText), forbidden) {
			t.Errorf("0027 不应引入证据明文/秘密列 %q", forbidden)
		}
	}
	for _, index := range []string{
		"CREATE UNIQUE INDEX ux_manual_recovery_approvals_active",
		"ON manual_recovery_approvals(request_id) WHERE status='active'",
		"CREATE INDEX ix_manual_recovery_requests_target",
		"CREATE INDEX ix_manual_recovery_executions_request",
	} {
		if !strings.Contains(sqlText, index) {
			t.Errorf("0027 缺少索引 %q", index)
		}
	}
	if strings.Contains(sqlText, "TIMESTAMP") || strings.Contains(sqlText, "BOOLEAN") {
		t.Error("迁移不应使用 TIMESTAMP/BOOLEAN 类型")
	}
	if !strings.Contains(sqlText, "-- +migrate whole-file") {
		t.Error("多语句迁移必须声明 whole-file")
	}
}
