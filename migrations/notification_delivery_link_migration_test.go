package migrations_test

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// TestSecurityNotificationDeliveryLinkMigration 校验 0050 的告知-投递关联迁移：
// 只增量增加可空列与索引（不重建表、不复制数据），并保留“告知记录不存秘密”的约束。
func TestSecurityNotificationDeliveryLinkMigration(t *testing.T) {
	data, err := migrations.SQLite.ReadFile("0050_security_notification_delivery_link.sql")
	if err != nil {
		t.Fatalf("读取 0050 迁移: %v", err)
	}
	sqlText := string(data)
	if count := strings.Count(sqlText, "CREATE TABLE "); count != 0 {
		t.Fatalf("0050 不应创建表（只增列），CREATE TABLE 数量 = %d", count)
	}
	if count := strings.Count(sqlText, "INSERT INTO"); count != 0 {
		t.Fatalf("0050 不应复制/写入数据，INSERT INTO 数量 = %d", count)
	}
	for _, want := range []string{
		"ALTER TABLE security_notifications ADD COLUMN delivery_id TEXT",
		"ALTER TABLE security_notifications ADD COLUMN dedup_key TEXT",
		"CREATE UNIQUE INDEX ux_security_notifications_dedup_key",
		"ON security_notifications(dedup_key) WHERE dedup_key IS NOT NULL",
		"CREATE INDEX ix_security_notifications_delivery",
		"ON security_notifications(delivery_id)",
	} {
		if !strings.Contains(sqlText, want) {
			t.Errorf("0050 缺少定义 %q", want)
		}
	}
	// 只增列且必须可空：历史记录没有投递标识/去重键仍须可读。
	for _, forbidden := range []string{
		"NOT NULL DEFAULT", "DROP TABLE", "DROP COLUMN", "RENAME TO",
		" password", " token", " code TEXT", " body TEXT", " secret TEXT",
		"recipient TEXT", " plaintext",
	} {
		if strings.Contains(strings.ToLower(sqlText), strings.ToLower(forbidden)) {
			t.Errorf("0050 不应包含 %q", forbidden)
		}
	}
	if strings.Contains(sqlText, "TIMESTAMP") || strings.Contains(sqlText, "BOOLEAN") {
		t.Error("迁移不应使用 TIMESTAMP/BOOLEAN 类型")
	}
}
