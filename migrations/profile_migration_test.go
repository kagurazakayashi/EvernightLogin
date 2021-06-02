package migrations_test

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// TestProfileMigration 校验 0015 只追加电话/电话验证状态/更名时间三列，不引入
// 邮箱验证、密码、MFA、角色或 root 字段。
func TestProfileMigration(t *testing.T) {
	data, err := migrations.SQLite.ReadFile("0015_profile.sql")
	if err != nil {
		t.Fatalf("读取资料迁移: %v", err)
	}
	sqlText := string(data)
	for _, want := range []string{
		"ALTER TABLE users ADD COLUMN phone TEXT",
		"ALTER TABLE users ADD COLUMN phone_verified_at_ms INTEGER",
		"ALTER TABLE users ADD COLUMN username_changed_at_ms INTEGER NOT NULL DEFAULT 0",
	} {
		if !strings.Contains(sqlText, want) {
			t.Errorf("0015 缺少定义 %q", want)
		}
	}
	for _, forbidden := range []string{
		"ADD COLUMN password", "ADD COLUMN mfa", "ADD COLUMN role",
		"ADD COLUMN is_root", "ADD COLUMN email_verified", "ADD COLUMN status",
	} {
		if strings.Contains(strings.ToLower(sqlText), forbidden) {
			t.Errorf("0015 不应修改敏感字段 %q", forbidden)
		}
	}
	if strings.Contains(sqlText, "TIMESTAMP") || strings.Contains(sqlText, "BOOLEAN") {
		t.Error("迁移不应使用 TIMESTAMP/BOOLEAN 类型")
	}
}
