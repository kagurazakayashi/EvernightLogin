package migrations_test

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// TestTokenSigningKeysMigration 校验 0030：签名密钥表只存加密私钥与公开 JWK，
// 状态机/部分唯一索引/保留期约束与步骤 50 的轮换与 JWKS 发布要求一致。
func TestTokenSigningKeysMigration(t *testing.T) {
	data, err := migrations.SQLite.ReadFile("0030_token_signing_keys.sql")
	if err != nil {
		t.Fatalf("读取 0030 迁移: %v", err)
	}
	sqlText := string(data)
	if count := strings.Count(sqlText, "CREATE TABLE "); count != 1 {
		t.Fatalf("0030 CREATE TABLE 数量 = %d，期望 1", count)
	}
	definition := tableDefinition(t, sqlText, "token_signing_keys")
	for _, want := range []string{
		"kid TEXT PRIMARY KEY NOT NULL",
		"algorithm TEXT NOT NULL CHECK(algorithm='ES256')",
		"status TEXT NOT NULL CHECK(status IN('next','active','retired','revoked'))",
		"public_jwk BLOB NOT NULL CHECK(length(public_jwk) BETWEEN 1 AND 8192)",
		"sealed_private BLOB NOT NULL CHECK(length(sealed_private) BETWEEN 1 AND 8192)",
		"created_at_ms INTEGER NOT NULL",
		"activated_at_ms INTEGER",
		"retired_at_ms INTEGER",
		"retire_after_ms INTEGER",
		"revoked_at_ms INTEGER",
		"revoked_reason TEXT",
		"row_version INTEGER NOT NULL DEFAULT 1 CHECK(row_version>=1)",
		"CHECK(status<>'retired' OR (retired_at_ms IS NOT NULL AND retire_after_ms IS NOT NULL))",
	} {
		if !strings.Contains(definition, want) {
			t.Errorf("token_signing_keys 缺少定义 %q", want)
		}
	}
	// 私钥必须只以密文保存：迁移不得出现私钥明文/DER/密钥材料列。
	for _, forbidden := range []string{" private_key ", " private_key_pem", " private_key_der", " plaintext ", " jwk_private"} {
		if strings.Contains(strings.ToLower(sqlText), forbidden) {
			t.Errorf("0030 不应引入私钥明文列 %q", forbidden)
		}
	}
	for _, index := range []string{
		"CREATE UNIQUE INDEX ux_token_signing_keys_active",
		"ON token_signing_keys(status) WHERE status='active'",
		"CREATE UNIQUE INDEX ux_token_signing_keys_next",
		"ON token_signing_keys(status) WHERE status='next'",
		"CREATE INDEX ix_token_signing_keys_status",
	} {
		if !strings.Contains(sqlText, index) {
			t.Errorf("0030 缺少索引 %q", index)
		}
	}
	if !strings.Contains(sqlText, "-- +migrate whole-file") {
		t.Error("0030 必须声明 whole-file")
	}
	if strings.Contains(sqlText, "TIMESTAMP") || strings.Contains(sqlText, "BOOLEAN") {
		t.Error("迁移不应使用 TIMESTAMP/BOOLEAN 类型")
	}
}
