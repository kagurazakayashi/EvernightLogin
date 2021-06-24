package migrations_test

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// TestRefreshTokenMigration 校验 0033：刷新令牌族/令牌表只存摘要、绑定客户端/
// 授权/资源/scope/安全版本，令牌状态与空闲/绝对有效期约束、族撤销索引。
func TestRefreshTokenMigration(t *testing.T) {
	data, err := migrations.SQLite.ReadFile("0033_refresh_tokens.sql")
	if err != nil {
		t.Fatalf("读取 0033 迁移: %v", err)
	}
	sqlText := string(data)
	if count := strings.Count(sqlText, "CREATE TABLE "); count != 2 {
		t.Fatalf("0033 CREATE TABLE 数量 = %d，期望 2", count)
	}
	families := tableDefinition(t, sqlText, "refresh_token_families")
	for _, want := range []string{
		"id TEXT PRIMARY KEY NOT NULL",
		"client_id TEXT NOT NULL",
		"subject_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE",
		"authorization_id TEXT NOT NULL",
		"scope TEXT NOT NULL",
		"audiences_json TEXT NOT NULL",
		"security_version INTEGER NOT NULL CHECK(security_version>0)",
		"created_at_ms INTEGER NOT NULL",
		"absolute_expires_at_ms INTEGER NOT NULL",
		"idle_timeout_ms INTEGER NOT NULL CHECK(idle_timeout_ms>0)",
		"revoked_at_ms INTEGER",
		"revoke_reason TEXT",
	} {
		if !strings.Contains(families, want) {
			t.Errorf("refresh_token_families 缺少定义 %q", want)
		}
	}
	tokens := tableDefinition(t, sqlText, "refresh_tokens")
	for _, want := range []string{
		"family_id TEXT NOT NULL REFERENCES refresh_token_families(id) ON DELETE CASCADE",
		"token_sha256 BLOB NOT NULL UNIQUE CHECK(length(token_sha256)=32)",
		"status TEXT NOT NULL CHECK(status IN('active','used','revoked','expired'))",
		"issued_at_ms INTEGER NOT NULL",
		"idle_expires_at_ms INTEGER NOT NULL",
		"expires_at_ms INTEGER NOT NULL",
		"used_at_ms INTEGER",
		"revoked_at_ms INTEGER",
		"replaced_by_id TEXT",
		"CHECK(idle_expires_at_ms<=expires_at_ms)",
	} {
		if !strings.Contains(tokens, want) {
			t.Errorf("refresh_tokens 缺少定义 %q", want)
		}
	}
	// 刷新令牌明文绝不入库：不得出现 token 明文字段或可逆存储列。
	for _, forbidden := range []string{" token TEXT", " token_value", " plaintext", " encrypted_token", " refresh_token TEXT"} {
		if strings.Contains(strings.ToLower(sqlText), forbidden) {
			t.Errorf("0033 不应引入刷新令牌明文列 %q", forbidden)
		}
	}
	for _, index := range []string{
		"CREATE INDEX ix_refresh_token_families_subject",
		"CREATE INDEX ix_refresh_token_families_client",
		"CREATE INDEX ix_refresh_tokens_family",
		"CREATE INDEX ix_refresh_tokens_status",
	} {
		if !strings.Contains(sqlText, index) {
			t.Errorf("0033 缺少索引 %q", index)
		}
	}
	if !strings.Contains(sqlText, "-- +migrate whole-file") {
		t.Error("0033 必须声明 whole-file")
	}
	if strings.Contains(sqlText, "TIMESTAMP") || strings.Contains(sqlText, "BOOLEAN") {
		t.Error("迁移不应使用 TIMESTAMP/BOOLEAN 类型")
	}
}
