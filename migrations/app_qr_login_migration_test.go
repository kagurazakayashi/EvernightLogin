package migrations_test

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// TestAppQRLoginMigration 校验 0036 扫码登录请求表：领取绑定只存带密钥 HMAC 摘要
// （含 key_id）、二维码/请求状态机与确认端会话快照字段完整、有效期与查询间隔有
// 约束，不保存任何可直接使用的秘密明文。
func TestAppQRLoginMigration(t *testing.T) {
	data, err := migrations.SQLite.ReadFile("0036_app_qr_login.sql")
	if err != nil {
		t.Fatalf("读取 0036 迁移: %v", err)
	}
	sql := strings.ToLower(string(data))
	for _, want := range []string{
		"create table app_qr_login_requests",
		"claim_digest blob not null unique check(length(claim_digest)=32)",
		"claim_key_id text not null check(length(claim_key_id) between 1 and 64)",
		"client_id text not null references applications(id) on delete cascade",
		"scopes_json text not null check(json_valid(scopes_json))",
		"request_version integer not null default 1 check(request_version>=1)",
		"status text not null check(status in('pending','approved','denied','cancelled','claimed'))",
		"user_id text references users(id) on delete cascade",
		"session_id text",
		"security_version integer check(security_version is null or security_version>0)",
		"auth_methods_json text not null default '[]' check(json_valid(auth_methods_json))",
		"interval_seconds integer not null check(interval_seconds between 1 and 60)",
		"last_polled_at_ms integer",
		"check(expires_at_ms>created_at_ms)",
		"ix_app_qr_login_requests_client",
		"ix_app_qr_login_requests_expiry",
	} {
		if !strings.Contains(sql, want) {
			t.Fatalf("0036 迁移缺少结构: %s", want)
		}
	}
	// 不得保存领取绑定/会话/令牌明文，也不得使用无密钥摘要保存高熵领取绑定以外的
	// 低熵可猜材料（本表没有低熵材料）。
	for _, forbidden := range []string{
		"claim_secret", "session_secret", "token text", "access_token text",
		"refresh_token text", "client_secret", "qr_content text",
	} {
		if strings.Contains(sql, forbidden) {
			t.Fatalf("0036 不应保存敏感明文列: %s", forbidden)
		}
	}
}
