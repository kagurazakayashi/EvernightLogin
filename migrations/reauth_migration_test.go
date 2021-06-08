package migrations_test

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// TestReauthAndNotificationsMigration 校验 0019 的再次认证挑战、一次性批准与安全告知
// 记录结构：批准令牌只存摘要、绑定目标与参数摘要、消费态、告知状态与脱敏收件人，
// 且不保存密码、明文令牌、验证码或邮件正文。
func TestReauthAndNotificationsMigration(t *testing.T) {
	data, err := migrations.SQLite.ReadFile("0019_reauth_and_notifications.sql")
	if err != nil {
		t.Fatalf("读取再次认证迁移: %v", err)
	}
	sqlText := string(data)
	if count := strings.Count(sqlText, "CREATE TABLE "); count != 3 {
		t.Fatalf("0019 CREATE TABLE 数量 = %d，期望 3", count)
	}
	for _, want := range []string{
		"CREATE TABLE reauth_challenges (",
		"user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE",
		"operation_id TEXT NOT NULL CHECK(length(operation_id) BETWEEN 3 AND 128)",
		"target_type TEXT NOT NULL CHECK(length(target_type) BETWEEN 1 AND 64)",
		"target_id TEXT NOT NULL DEFAULT '' CHECK(length(target_id) <= 128)",
		"params_sha256 BLOB NOT NULL CHECK(length(params_sha256) = 32)",
		"status TEXT NOT NULL DEFAULT 'pending'",
		"attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0)",
		"max_attempts INTEGER NOT NULL DEFAULT 5 CHECK(max_attempts BETWEEN 1 AND 10)",
		"expires_at_ms INTEGER NOT NULL",
		"CREATE TABLE reauth_approvals (",
		"token_sha256 BLOB NOT NULL UNIQUE CHECK(length(token_sha256) = 32)",
		"granted_strength TEXT NOT NULL CHECK(granted_strength IN('none','password','strong'))",
		"authentication_complete INTEGER NOT NULL DEFAULT 0 CHECK(authentication_complete IN(0,1))",
		"consumed_at_ms INTEGER",
		"CREATE TABLE security_notifications (",
		"outcome TEXT NOT NULL CHECK(outcome IN('success','failure'))",
		"state TEXT NOT NULL CHECK(state IN('sent','failed','no_verified_email','rate_limited','not_configured','suppressed'))",
		"recipient_masked TEXT NOT NULL DEFAULT ''",
	} {
		if !strings.Contains(sqlText, want) {
			t.Errorf("0019 缺少定义 %q", want)
		}
	}
	for _, index := range []string{
		"CREATE INDEX ix_reauth_challenges_user_status",
		"CREATE INDEX ix_reauth_approvals_user_operation",
		"CREATE INDEX ix_security_notifications_user_created",
	} {
		if !strings.Contains(sqlText, index) {
			t.Errorf("0019 缺少索引 %q", index)
		}
	}
	// 不得保存明文令牌/密码/验证码/邮件正文。
	for _, forbidden := range []string{
		" token TEXT", " password", " code TEXT", " body TEXT", " plaintext",
		" secret TEXT", " password_hash", " verify_url",
	} {
		if strings.Contains(strings.ToLower(sqlText), forbidden) {
			t.Errorf("0019 不应引入敏感列 %q", forbidden)
		}
	}
	for _, future := range []string{
		"CREATE TABLE mfa_credentials", "CREATE TABLE passkey_credentials",
		"CREATE TABLE webauthn_challenges",
	} {
		if strings.Contains(sqlText, future) {
			t.Errorf("0019 提前创建了后续 MFA 步骤的表 %q", future)
		}
	}
	if strings.Contains(sqlText, "TIMESTAMP") || strings.Contains(sqlText, "BOOLEAN") {
		t.Error("迁移不应使用 TIMESTAMP/BOOLEAN 类型")
	}
}
