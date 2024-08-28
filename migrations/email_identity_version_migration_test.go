package migrations_test

// 步骤 250：0053 已验证邮箱身份代际迁移的结构断言。
//
// 校验：
//   - 只追加两列（users.email_identity_version NOT NULL DEFAULT 0 单调代际；
//     password_reset_requests.bound_email_identity_version 可空以兼容旧行）；
//   - 不建表、不回填、不更新数据、不改已发布迁移、不保存秘密；
//   - 绑定列可空是“旧行保守失效”的前提：NULL 由服务层按未绑定拒绝，不在迁移里
//     回填，也不给旧行伪造代际。

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// migrationSQLStatements 去掉整个迁移文件的行注释，只保留可执行 SQL 文本，避免
// 注释里的说明文字被当成语句/列名参与结构断言。
func migrationSQLStatements(sqlText string) string {
	var builder strings.Builder
	for _, line := range strings.Split(sqlText, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		builder.WriteString(line)
		builder.WriteString("\n")
	}
	return builder.String()
}

// TestEmailIdentityVersionMigration 校验 0053 迁移文件的结构与安全边界。
func TestEmailIdentityVersionMigration(t *testing.T) {
	data, err := migrations.SQLite.ReadFile("0053_email_identity_version.sql")
	if err != nil {
		t.Fatalf("读取 0053 迁移: %v", err)
	}
	sqlOnly := migrationSQLStatements(string(data))
	if count := strings.Count(sqlOnly, "CREATE TABLE "); count != 0 {
		t.Fatalf("0053 不应创建表，CREATE TABLE 数量 = %d", count)
	}
	if count := strings.Count(sqlOnly, "INSERT INTO "); count != 0 {
		t.Fatalf("0053 不应复制/回填数据，INSERT INTO 数量 = %d", count)
	}
	if count := strings.Count(sqlOnly, "UPDATE "); count != 0 {
		t.Fatalf("0053 不应更新数据（旧行不回填），UPDATE 数量 = %d", count)
	}
	alters := 0
	var bindingStatement string
	for _, line := range strings.Split(sqlOnly, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "ALTER TABLE ") {
			continue
		}
		alters++
		if strings.Contains(trimmed, "bound_email_identity_version") {
			bindingStatement = trimmed
		}
	}
	if alters != 2 {
		t.Fatalf("0053 应有 2 条 ALTER TABLE 语句，实际 %d", alters)
	}
	for _, want := range []string{
		// users 代际列必须非空且有 0 默认值，保证既有行可立即参与绑定。
		"ALTER TABLE users ADD COLUMN email_identity_version INTEGER NOT NULL DEFAULT 0;",
		// 找回请求绑定列必须可空：0053 之前已存在的行没有代际，服务层保守拒绝。
		"ALTER TABLE password_reset_requests ADD COLUMN bound_email_identity_version INTEGER;",
	} {
		if !strings.Contains(sqlOnly, want) {
			t.Errorf("0053 缺少定义 %q", want)
		}
	}
	// 绑定列必须没有 NOT NULL：迁移前旧行无法获得代际，回填或强制非空都会
	// 把“旧行失效”错误变成“旧行伪造有效绑定”。
	if bindingStatement == "" {
		t.Fatal("0053 缺少找回请求的邮箱身份代际绑定列")
	}
	if strings.Contains(bindingStatement, "NOT NULL") {
		t.Error("0053 的找回绑定列必须可空以兼容迁移前旧行")
	}
	// 不保存任何秘密/敏感材料，也不改动其他表结构或已发布对象。
	lowerSQL := strings.ToLower(sqlOnly)
	for _, forbidden := range []string{
		"token", "password_hash", " password text", "secret",
		"drop table", "drop column", "rename to", "alter table user_emails",
		"alter table password_credentials", "alter table sessions",
	} {
		if strings.Contains(lowerSQL, forbidden) {
			t.Errorf("0053 不应包含 %q", forbidden)
		}
	}
}
