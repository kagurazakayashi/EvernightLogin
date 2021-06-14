package migrations_test

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// TestPasswordResetMigration 校验 0025：找回请求绑定用户/凭证/状态/有效期，不保存
// token 明文；OAuth 撤销 outbox 有 pending 索引且不保存秘密。
func TestPasswordResetMigration(t *testing.T) {
	data, err := migrations.SQLite.ReadFile("0025_password_reset.sql")
	if err != nil {
		t.Fatalf("读取密码找回迁移: %v", err)
	}
	sqlText := string(data)
	if count := strings.Count(sqlText, "CREATE TABLE "); count != 2 {
		t.Fatalf("0025 CREATE TABLE 数量 = %d，期望 2", count)
	}
	for _, want := range []string{
		"CREATE TABLE password_reset_requests (",
		"user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE",
		"masked_email TEXT NOT NULL DEFAULT ''",
		"credential_id TEXT NOT NULL",
		"token_sha256 BLOB NOT NULL CHECK(length(token_sha256) = 32)",
		"state TEXT NOT NULL CHECK(state IN('pending','consumed','expired','cancelled'))",
		"expires_at_ms INTEGER NOT NULL",
		"consumed_at_ms INTEGER",
		"CHECK(expires_at_ms > created_at_ms)",
		"CREATE INDEX ix_password_reset_requests_user_state",
		"CREATE INDEX ix_password_reset_requests_credential",
		"CREATE TABLE oauth_revocation_events (",
		"reason TEXT NOT NULL",
		"processed_at_ms INTEGER",
		"attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0)",
		"CREATE INDEX ix_oauth_revocation_events_pending",
	} {
		if !strings.Contains(sqlText, want) {
			t.Errorf("0025 缺少定义 %q", want)
		}
	}
	for _, forbidden := range []string{"token TEXT", "secret TEXT", "password_hash", " password TEXT"} {
		if strings.Contains(strings.ToLower(sqlText), forbidden) {
			t.Errorf("0025 不应保存敏感明文列 %q", forbidden)
		}
	}
}
