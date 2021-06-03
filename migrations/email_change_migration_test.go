package migrations_test

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// TestEmailChangeMigration 校验 0016 的邮箱变更申请结构：状态枚举、每用户一条 pending
// 部分唯一索引、旧/新邮箱绑定、验证与告知状态，不含令牌/邮件正文。
func TestEmailChangeMigration(t *testing.T) {
	data, err := migrations.SQLite.ReadFile("0016_email_change.sql")
	if err != nil {
		t.Fatalf("读取邮箱变更迁移: %v", err)
	}
	sqlText := string(data)
	for _, want := range []string{
		"user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE",
		"status TEXT NOT NULL CHECK(status IN('pending','completed','cancelled','expired'))",
		"new_email_normalized TEXT NOT NULL CHECK(length(new_email_normalized) BETWEEN 3 AND 254)",
		"credential_id TEXT NOT NULL",
		"CHECK(expires_at_ms>created_at_ms)",
		"CREATE UNIQUE INDEX ux_email_change_pending ON email_change_requests(user_id) WHERE status='pending';",
		"verify_state TEXT NOT NULL DEFAULT 'pending'",
		"notify_state TEXT NOT NULL DEFAULT 'pending' CHECK(notify_state IN('pending','sent','failed','skipped'))",
	} {
		if !strings.Contains(sqlText, want) {
			t.Errorf("0016 缺少定义 %q", want)
		}
	}
	for _, forbidden := range []string{"ADD COLUMN password", "ADD COLUMN mfa", "ADD COLUMN is_root"} {
		if strings.Contains(strings.ToLower(sqlText), forbidden) {
			t.Errorf("0016 不应修改敏感字段 %q", forbidden)
		}
	}
	if strings.Contains(sqlText, "TIMESTAMP") || strings.Contains(sqlText, "BOOLEAN") {
		t.Error("迁移不应使用 TIMESTAMP/BOOLEAN 类型")
	}
}
