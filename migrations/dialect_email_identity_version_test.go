package migrations_test

// 步骤 250：0053 已验证邮箱身份代际迁移的四方言静态结构检查。
//
// SQLite 是唯一运行验证目标（由 internal/passwordreset 等真实临时 SQLite 测试覆盖
// 迁移执行与读写）；MySQL 8.0 / PostgreSQL / SQL Server 本轮只做翻译后的结构与
// 编译静态检查，不连接/部署数据库，也不声称已实测：
//   - 三种方言都能从已提交 SQLite 迁移确定性翻译出 0053；
//   - users.email_identity_version 保持“非空 + 默认 0”（既有行可立即参与绑定）；
//   - password_reset_requests.bound_email_identity_version 保持可空（旧行保守失效）；
//   - 不出现迁移表/列名漂移或 SQLite 专属语法泄漏（翻译器自身会拒绝泄漏）。

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
	"github.com/kagurazakayashi/EvernightLogin/migrations/mysql"
	"github.com/kagurazakayashi/EvernightLogin/migrations/postgres"
	"github.com/kagurazakayashi/EvernightLogin/migrations/sqlserver"
)

// findMigration 按版本号查找迁移；找不到直接失败。
func findMigration(t *testing.T, versions []migrate.Migration, version string) migrate.Migration {
	t.Helper()
	for _, migration := range versions {
		if migration.Version == version {
			return migration
		}
	}
	t.Fatalf("翻译结果缺少迁移 %s", version)
	return migrate.Migration{}
}

// assertEmailIdentityVersionDialect 断言给定方言的 0053 迁移保留两列的语义差异：
// users 代际列非空且默认 0，找回请求绑定列可空（旧行 NULL 由服务层保守拒绝）。
func assertEmailIdentityVersionDialect(t *testing.T, dialect string, migration migrate.Migration) {
	t.Helper()
	joined := strings.Join(migration.Statements, "\n")
	lower := strings.ToLower(joined)
	for _, want := range []string{"email_identity_version", "bound_email_identity_version"} {
		if !strings.Contains(lower, want) {
			t.Fatalf("%s 的 0053 缺少列 %q: %s", dialect, want, joined)
		}
	}
	usersStatement := ""
	bindingStatement := ""
	for _, statement := range migration.Statements {
		statementLower := strings.ToLower(statement)
		if strings.Contains(statementLower, "email_identity_version") &&
			strings.Contains(statementLower, "users") {
			usersStatement = statementLower
		}
		if strings.Contains(statementLower, "bound_email_identity_version") {
			bindingStatement = statementLower
		}
	}
	if usersStatement == "" {
		t.Fatalf("%s 的 0053 未翻译 users.email_identity_version 列", dialect)
	}
	if !strings.Contains(usersStatement, "not null") || !strings.Contains(usersStatement, "default 0") {
		t.Fatalf("%s 的 users.email_identity_version 必须为 NOT NULL DEFAULT 0: %s",
			dialect, usersStatement)
	}
	if bindingStatement == "" {
		t.Fatalf("%s 的 0053 未翻译 password_reset_requests.bound_email_identity_version 列", dialect)
	}
	if strings.Contains(bindingStatement, "not null") {
		t.Fatalf("%s 的 bound_email_identity_version 必须可空以兼容迁移前旧行: %s",
			dialect, bindingStatement)
	}
}

// TestEmailIdentityVersionMigrationDialects 校验 0053 在 MySQL/PostgreSQL/SQL Server
// 翻译结果中的结构与可空性语义一致（静态检查，不运行数据库）。
func TestEmailIdentityVersionMigrationDialects(t *testing.T) {
	source, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("读取 SQLite 迁移: %v", err)
	}
	sourceCount := len(source)

	dialects := []struct {
		name string
		load func() ([]migrate.Migration, error)
	}{
		{"mysql", mysql.Load},
		{"postgres", postgres.Load},
		{"sqlserver", sqlserver.Load},
	}
	for _, dialect := range dialects {
		translated, err := dialect.load()
		if err != nil {
			t.Fatalf("%s 翻译全部迁移失败: %v", dialect.name, err)
		}
		if len(translated) != sourceCount {
			t.Fatalf("%s 迁移数量 = %d/%d", dialect.name, len(translated), sourceCount)
		}
		assertEmailIdentityVersionDialect(t, dialect.name, findMigration(t, translated, "0053"))
	}
}
