package migrations_test

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// TestOAuthAuthorizationMigration 校验 0031 授权码/PKCE 迁移的持久化契约与安全
// 不变量：只存授权码摘要、不存明文/秘密、状态与 PKCE 约束、外键与索引存在。
func TestOAuthAuthorizationMigration(t *testing.T) {
	data, err := migrations.SQLite.ReadFile("0031_oauth_authorization.sql")
	if err != nil {
		t.Fatalf("读取 0031 迁移: %v", err)
	}
	sql := strings.ToLower(string(data))
	if strings.TrimSpace(sql) == "" {
		t.Fatal("0031_oauth_authorization.sql 为空")
	}
	for _, required := range []string{
		"create table oauth_authorization_requests",
		"create table oauth_authorization_codes",
		"code_sha256 blob not null unique",
		"authorization_request_id text not null",
		"references oauth_authorization_requests(id)",
		"response_type text not null check(response_type='code')",
		"status text not null check(status in('pending','approved','denied'))",
		"code_challenge_method text not null check(code_challenge_method='s256')",
		"consumed_at_ms integer",
		"replayed_at_ms integer",
		"ix_oauth_authorization_requests_user_status",
		"ix_oauth_authorization_codes_expiry",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("0031 迁移缺少结构: %s", required)
		}
	}
	// 授权码明文、令牌、会话秘密、客户端 secret、PKCE verifier 不得有存储列。
	for _, forbidden := range []string{"code text", "code_plain", "access_token", "refresh_token",
		"session_secret", "client_secret", "code_verifier"} {
		if strings.Contains(sql, forbidden) {
			t.Fatalf("0031 迁移不应包含敏感列: %s", forbidden)
		}
	}
}
