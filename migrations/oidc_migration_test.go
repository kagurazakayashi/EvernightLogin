package migrations_test

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// TestOIDCAuthFactsMigration 校验 0032：会话记录真实认证方法，授权请求/授权码快照
// 认证时间与方法；只存稳定方法标识，不保存秘密，升级默认值不伪造事实。
func TestOIDCAuthFactsMigration(t *testing.T) {
	data, err := migrations.SQLite.ReadFile("0032_oidc.sql")
	if err != nil {
		t.Fatalf("读取 OIDC 迁移: %v", err)
	}
	sqlText := string(data)
	for _, want := range []string{
		"ALTER TABLE sessions",
		"ADD COLUMN auth_methods_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(auth_methods_json))",
		"ALTER TABLE oauth_authorization_requests",
		"ADD COLUMN auth_time_ms INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE oauth_authorization_codes",
	} {
		if !strings.Contains(sqlText, want) {
			t.Errorf("0032 缺少定义 %q", want)
		}
	}
	if count := strings.Count(sqlText, "auth_methods_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(auth_methods_json))"); count != 3 {
		t.Errorf("0032 auth_methods_json 列数量 = %d，期望 3", count)
	}
	for _, forbidden := range []string{"secret", "password"} {
		if strings.Contains(strings.ToLower(sqlText), forbidden) {
			t.Errorf("0032 不应保存敏感明文列 %q", forbidden)
		}
	}
}
