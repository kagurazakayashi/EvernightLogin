package migrations_test

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// TestOAuthRevocationMigration 校验 0034 授权撤回/令牌撤销表：不保存令牌/授权码/
// 客户端 secret 明文，撤销标记与边界字段完整。
func TestOAuthRevocationMigration(t *testing.T) {
	data, err := migrations.SQLite.ReadFile("0034_oauth_revocation.sql")
	if err != nil {
		t.Fatalf("读取 0034 迁移: %v", err)
	}
	sql := strings.ToLower(string(data))
	for _, want := range []string{
		"alter table oauth_authorization_codes add column revoked_at_ms",
		"create table oauth_client_user_revocations",
		"create table oauth_user_revocations",
		"create table oauth_access_token_revocations",
		"subject_type text not null check(subject_type in('user','service'))",
		"check(expires_at_ms > revoked_at_ms)",
		"primary key(user_id, client_id)",
		"ix_oauth_access_token_revocations_expiry",
	} {
		if !strings.Contains(sql, want) {
			t.Fatalf("0034 迁移缺少结构: %s", want)
		}
	}
	for _, forbidden := range []string{"token text", "authorization_code text", "client_secret",
		"access_token text", "refresh_token text"} {
		if strings.Contains(sql, forbidden) {
			t.Fatalf("0034 不应保存敏感明文列: %s", forbidden)
		}
	}
}
