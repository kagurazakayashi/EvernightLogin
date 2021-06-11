package migrations_test

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// TestPasskeyMigration 校验 0022：用户句柄、Passkey 凭证与挑战三张表的结构、
// 唯一约束、状态枚举与索引；不得出现私钥/明文秘密列。
func TestPasskeyMigration(t *testing.T) {
	data, err := migrations.SQLite.ReadFile("0022_passkey.sql")
	if err != nil {
		t.Fatalf("读取 0022 迁移: %v", err)
	}
	sqlText := string(data)
	if count := strings.Count(sqlText, "CREATE TABLE "); count != 3 {
		t.Fatalf("0022 CREATE TABLE 数量 = %d，期望 3", count)
	}
	for _, want := range []string{
		"CREATE TABLE webauthn_user_handles (",
		"handle BLOB NOT NULL UNIQUE CHECK(length(handle) BETWEEN 16 AND 64)",
		"CREATE TABLE webauthn_credentials (",
		"credential_id BLOB NOT NULL UNIQUE",
		"public_key BLOB NOT NULL CHECK(length(public_key) > 0)",
		"aaguid BLOB NOT NULL",
		"sign_count INTEGER NOT NULL DEFAULT 0 CHECK(sign_count >= 0)",
		"backup_eligible INTEGER NOT NULL DEFAULT 0 CHECK(backup_eligible IN(0,1))",
		"backed_up INTEGER NOT NULL DEFAULT 0 CHECK(backed_up IN(0,1))",
		"usage TEXT NOT NULL DEFAULT 'login' CHECK(usage IN('login','second_factor'))",
		"revoked_at_ms INTEGER",
		"CHECK(backup_eligible = 1 OR backed_up = 0)",
		"CREATE TABLE webauthn_ceremonies (",
		"operation TEXT NOT NULL CHECK(operation IN('registration','authentication'))",
		"challenge TEXT NOT NULL",
		"session_data BLOB NOT NULL CHECK(length(session_data) > 0)",
		"consumed_at_ms INTEGER",
	} {
		if !strings.Contains(sqlText, want) {
			t.Errorf("0022 缺少定义 %q", want)
		}
	}
	for _, index := range []string{
		"CREATE INDEX ix_webauthn_credentials_user_active",
		"CREATE INDEX ix_webauthn_ceremonies_user_operation",
		"CREATE INDEX ix_webauthn_ceremonies_expires",
	} {
		if !strings.Contains(sqlText, index) {
			t.Errorf("0022 缺少索引 %q", index)
		}
	}
	// 只保存公钥/元数据，不保存私钥、种子、明文挑战以外的凭据；挑战本身虽然
	// 含随机 challenge，但 session_data 是服务端协议状态，不是可复用秘密。
	for _, forbidden := range []string{
		"private_key", "secret TEXT", "seed TEXT", "password TEXT", "token TEXT",
	} {
		if strings.Contains(strings.ToLower(sqlText), forbidden) {
			t.Errorf("0022 不应出现敏感列 %q", forbidden)
		}
	}
	if strings.Contains(sqlText, "TIMESTAMP") || strings.Contains(sqlText, "BOOLEAN") {
		t.Error("迁移不应使用 TIMESTAMP/BOOLEAN 类型")
	}
}
