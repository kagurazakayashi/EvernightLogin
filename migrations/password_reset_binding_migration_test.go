package migrations_test

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// TestPasswordResetBindingMigration 校验 0051：只给找回请求增加安全代际与已验证邮箱
// 身份绑定两列，不建表、不回填、不写数据、不保存 token/密码明文。未绑定旧行由服务层
// 保守失效（不在迁移里回填）。
func TestPasswordResetBindingMigration(t *testing.T) {
	data, err := migrations.SQLite.ReadFile("0051_password_reset_binding.sql")
	if err != nil {
		t.Fatalf("读取 0051 迁移: %v", err)
	}
	sqlText := string(data)
	if count := strings.Count(sqlText, "CREATE TABLE "); count != 0 {
		t.Fatalf("0051 不应创建表，CREATE TABLE 数量 = %d", count)
	}
	if count := strings.Count(sqlText, "INSERT INTO "); count != 0 {
		t.Fatalf("0051 不应复制/回填数据，INSERT INTO 数量 = %d", count)
	}
	if count := strings.Count(sqlText, "ALTER TABLE password_reset_requests ADD COLUMN "); count != 2 {
		t.Fatalf("0051 应有 2 条 ALTER TABLE ADD COLUMN，实际 %d", count)
	}
	for _, want := range []string{
		"ALTER TABLE password_reset_requests ADD COLUMN security_version INTEGER;",
		"ALTER TABLE password_reset_requests ADD COLUMN bound_email_normalized TEXT;",
	} {
		if !strings.Contains(sqlText, want) {
			t.Errorf("0051 缺少定义 %q", want)
		}
	}
	// 两列必须可空（兼容迁移前旧行；不回填，旧行由服务层保守失效）。
	if strings.Contains(sqlText, "NOT NULL") {
		t.Errorf("0051 的绑定列必须可空以兼容迁移前旧行")
	}
	for _, forbidden := range []string{
		"token TEXT", "token_sha256", "password_hash", " password TEXT",
		"INSERT INTO password_reset_requests", "UPDATE password_reset_requests",
	} {
		if strings.Contains(strings.ToLower(sqlText), forbidden) {
			t.Errorf("0051 不应包含 %q", forbidden)
		}
	}
}
