package migrations_test

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// TestWebhookDeliveryMigration 校验 0037 Webhook 投递表：签名密钥只存密文、事件幂等键
// 唯一、投递 (事件,endpoint) 唯一、状态机与失败查询字段完整，不保存任何明文秘密。
func TestWebhookDeliveryMigration(t *testing.T) {
	data, err := migrations.SQLite.ReadFile("0037_webhook_delivery.sql")
	if err != nil {
		t.Fatalf("读取 0037 迁移: %v", err)
	}
	sql := strings.ToLower(string(data))
	for _, want := range []string{
		"create table webhook_endpoints",
		"unique(application_id, url)",
		"status text not null check(status in('active','disabled'))",
		"create table webhook_endpoint_secrets",
		"sealed_secret blob not null",
		"sealer_key_id text not null",
		"retire_at_ms integer",
		"revoked_at_ms integer",
		"create table webhook_events",
		"idempotency_key text not null unique",
		"payload_json text not null check(json_valid(payload_json)",
		"create table webhook_deliveries",
		"state text not null check(state in('queued','sending','succeeded','failed','cancelled'))",
		"unique(event_id, endpoint_id)",
		"last_error_code text not null",
		"last_response_status integer not null",
		"ix_webhook_deliveries_endpoint",
		"ix_webhook_deliveries_state",
	} {
		if !strings.Contains(sql, want) {
			t.Fatalf("0037 迁移缺少结构: %s", want)
		}
	}
	for _, forbidden := range []string{
		"secret text", "signing_secret text", "token text", "password text",
		"raw_secret", "secret_plaintext",
	} {
		if strings.Contains(sql, forbidden) {
			t.Fatalf("0037 不应保存明文秘密列: %s", forbidden)
		}
	}
}
