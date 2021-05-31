package migrations_test

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const emailVerificationMigration = "0013_email_verification.sql"

// readEmailVerificationMigration 读取 0013 自主注册邮箱验证迁移。
func readEmailVerificationMigration(t *testing.T) string {
	t.Helper()
	data, err := migrations.SQLite.ReadFile(emailVerificationMigration)
	if err != nil {
		t.Fatalf("读取邮箱验证迁移失败: %v", err)
	}
	return string(data)
}

// TestEmailVerificationMigration 校验步骤 33 的待验证邮箱绑定：每个用户至多一条
// 待验证入口、凭证 ID 与地址均绑定、不含令牌明文/邮件正文等可重放秘密，并覆盖
// 按凭证与地址的索引。
func TestEmailVerificationMigration(t *testing.T) {
	sqlText := readEmailVerificationMigration(t)
	if count := strings.Count(sqlText, "CREATE TABLE "); count != 1 {
		t.Fatalf("0013 CREATE TABLE 数量 = %d，期望只新建 1 张表", count)
	}
	for _, want := range []string{
		"user_id TEXT PRIMARY KEY NOT NULL REFERENCES users(id) ON DELETE CASCADE",
		"credential_id TEXT NOT NULL",
		"email TEXT NOT NULL CHECK(length(email) BETWEEN 3 AND 254)",
		"email_normalized TEXT NOT NULL CHECK(length(email_normalized) BETWEEN 3 AND 254)",
		"created_at_ms INTEGER NOT NULL",
		"expires_at_ms INTEGER NOT NULL",
		"CHECK(expires_at_ms>created_at_ms)",
	} {
		if !strings.Contains(sqlText, want) {
			t.Errorf("0013 缺少列/约束定义 %q", want)
		}
	}
	// 不得保存可直接使用的秘密、验证码、令牌明文或邮件正文。
	for _, forbidden := range []string{" token ", " secret ", " code ", " body ", " subject ", " plaintext "} {
		if strings.Contains(strings.ToLower(sqlText), forbidden) {
			t.Errorf("0013 不应引入明文敏感列 %q", forbidden)
		}
	}
	for _, index := range []string{
		"CREATE INDEX ix_email_verification_tickets_credential ON email_verification_tickets(credential_id);",
		"CREATE INDEX ix_email_verification_tickets_email ON email_verification_tickets(email_normalized);",
	} {
		if !strings.Contains(sqlText, index) {
			t.Errorf("0013 缺少索引 %q", index)
		}
	}
	for _, future := range []string{"CREATE TABLE email_verifications", "CREATE TABLE registration_", "CREATE TABLE mfa_"} {
		if strings.Contains(sqlText, future) {
			t.Errorf("0013 提前创建了后续步骤的表 %q", future)
		}
	}
	if strings.Contains(sqlText, "TIMESTAMP") || strings.Contains(sqlText, "BOOLEAN") {
		t.Error("迁移不应使用 TIMESTAMP/BOOLEAN 类型")
	}
}
