package migrations_test

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// TestOAuthClientsMigration 校验 0029：客户端安全设置与 applications 一对一，
// 密钥只存前缀与 32 字节摘要，证书身份只存公钥证书与指纹；不保存明文秘密或私钥。
func TestOAuthClientsMigration(t *testing.T) {
	data, err := migrations.SQLite.ReadFile("0029_oauth_clients.sql")
	if err != nil {
		t.Fatalf("读取 OAuth 客户端迁移: %v", err)
	}
	sqlText := string(data)
	if count := strings.Count(sqlText, "CREATE TABLE "); count != 3 {
		t.Fatalf("0029 CREATE TABLE 数量 = %d，期望 3", count)
	}
	for _, want := range []string{
		"CREATE TABLE oauth_clients (",
		"client_id TEXT PRIMARY KEY NOT NULL REFERENCES applications(id) ON DELETE CASCADE",
		"client_type TEXT NOT NULL CHECK(client_type IN('public','confidential'))",
		"grant_types_json TEXT NOT NULL CHECK(json_valid(grant_types_json))",
		"redirect_uris_json TEXT NOT NULL CHECK(json_valid(redirect_uris_json))",
		"post_logout_redirect_uris_json TEXT NOT NULL CHECK(json_valid(post_logout_redirect_uris_json))",
		"scopes_json TEXT NOT NULL CHECK(json_valid(scopes_json))",
		"audiences_json TEXT NOT NULL CHECK(json_valid(audiences_json))",
		"auth_methods_json TEXT NOT NULL CHECK(json_valid(auth_methods_json))",
		"require_pkce INTEGER NOT NULL CHECK(require_pkce IN(0,1))",
		"row_version INTEGER NOT NULL DEFAULT 1 CHECK(row_version >= 1)",
		"CREATE TABLE oauth_client_secrets (",
		"secret_prefix TEXT NOT NULL CHECK(length(secret_prefix) BETWEEN 4 AND 16)",
		"secret_digest BLOB NOT NULL CHECK(length(secret_digest) = 32)",
		"expires_at_ms INTEGER NOT NULL",
		"retire_at_ms INTEGER",
		"revoked_at_ms INTEGER",
		"CREATE INDEX ix_oauth_client_secrets_client",
		"CREATE TABLE oauth_client_certificates (",
		"fingerprint_sha256 BLOB NOT NULL CHECK(length(fingerprint_sha256) = 32)",
		"not_before_ms INTEGER NOT NULL",
		"not_after_ms INTEGER NOT NULL",
		"certificate_pem TEXT NOT NULL",
		"UNIQUE(client_id, fingerprint_sha256)",
		"CREATE INDEX ix_oauth_client_certificates_client",
	} {
		if !strings.Contains(sqlText, want) {
			t.Errorf("0029 缺少定义 %q", want)
		}
	}
	// 不保存明文秘密或私钥材料列；唯一允许的 "secret" 列是前缀与摘要。
	for _, forbidden := range []string{
		"secret TEXT", "secret_plain", "private_key", "client_secret TEXT",
		"password", "token TEXT",
	} {
		if strings.Contains(strings.ToLower(sqlText), forbidden) {
			t.Errorf("0029 不应保存敏感明文列 %q", forbidden)
		}
	}
}
