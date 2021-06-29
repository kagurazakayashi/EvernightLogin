package migrations_test

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// TestOAuthDeviceAuthorizationMigration 校验 0035 设备授权表：高熵设备码存无密钥
// SHA-256 摘要、低熵人工短码存带密钥 HMAC-SHA256 摘要 + key_id（支持密钥轮换）、
// 状态机与绑定字段完整、轮询间隔与过期边界有约束，不保存任何可兑换明文。
func TestOAuthDeviceAuthorizationMigration(t *testing.T) {
	data, err := migrations.SQLite.ReadFile("0035_oauth_device_authorization.sql")
	if err != nil {
		t.Fatalf("读取 0035 迁移: %v", err)
	}
	sql := strings.ToLower(string(data))
	for _, want := range []string{
		"create table oauth_device_authorizations",
		"device_code_sha256 blob not null unique check(length(device_code_sha256)=32)",
		"user_code_digest blob not null unique check(length(user_code_digest)=32)",
		"user_code_key_id text not null check(length(user_code_key_id) between 1 and 64)",
		"status text not null check(status in('pending','approved','denied','cancelled','consumed'))",
		"client_id text not null references applications(id) on delete cascade",
		"user_id text references users(id) on delete cascade",
		"session_id text",
		"security_version integer check(security_version is null or security_version>0)",
		"interval_seconds integer not null check(interval_seconds between 1 and 300)",
		"last_polled_at_ms integer",
		"check(expires_at_ms>created_at_ms)",
		"ix_oauth_device_authorizations_client",
		"ix_oauth_device_authorizations_expiry",
	} {
		if !strings.Contains(sql, want) {
			t.Fatalf("0035 迁移缺少结构: %s", want)
		}
	}
	// 低熵短码不得使用无密钥摘要列（AGENTS §10）；设备码/短码/令牌必须是摘要而非
	// 可直接使用的明文列。
	for _, forbidden := range []string{
		"user_code_sha256", "user_code_hmac", "device_code text", "user_code text",
		"token text", "access_token text", "refresh_token text", "client_secret",
		"authorization_code text",
	} {
		if strings.Contains(sql, forbidden) {
			t.Fatalf("0035 不应保存敏感明文列或无密钥低熵摘要列: %s", forbidden)
		}
	}
}
