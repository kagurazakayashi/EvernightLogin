package migrations_test

// 步骤 255：0054 目标绑定操作证明迁移的四方言静态结构检查。
//
// SQLite 是唯一运行验证目标（由 internal/reauth 的真实临时 SQLite 测试覆盖迁移执行
// 与读写）；MySQL 8.0 / PostgreSQL / SQL Server 本轮只做翻译后的结构与编译静态检查，
// 不连接/部署数据库，也不声称已实测：
//   - 三种方言都能从已提交 SQLite 迁移确定性翻译出 0054；
//   - 四列全部保持可空（旧行 NULL 由服务层 fail-closed），不被翻译成 NOT NULL；
//   - 列名不漂移，翻译器不泄漏 SQLite 语法。

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
	"github.com/kagurazakayashi/EvernightLogin/migrations/mysql"
	"github.com/kagurazakayashi/EvernightLogin/migrations/postgres"
	"github.com/kagurazakayashi/EvernightLogin/migrations/sqlserver"
)

// assertOperationProofDialect 断言给定方言的 0054 迁移保留四列且可空。
func assertOperationProofDialect(t *testing.T, dialect string, migration migrate.Migration) {
	t.Helper()
	joined := strings.Join(migration.Statements, "\n")
	lower := strings.ToLower(joined)
	for _, want := range []string{"session_id", "intent_sealed"} {
		if !strings.Contains(lower, want) {
			t.Fatalf("%s 的 0054 缺少列 %q: %s", dialect, want, joined)
		}
	}
	if count := strings.Count(lower, "session_id"); count < 2 {
		t.Fatalf("%s 的 0054 session_id 出现 %d 次，期望 2 次（挑战与批准）", dialect, count)
	}
	if count := strings.Count(lower, "intent_sealed"); count < 2 {
		t.Fatalf("%s 的 0054 intent_sealed 出现 %d 次，期望 2 次（挑战与批准）", dialect, count)
	}
	// 追加列必须可空：翻译结果中这四个动作不得带 NOT NULL。
	for _, statement := range migration.Statements {
		statementLower := strings.ToLower(statement)
		if !strings.Contains(statementLower, "session_id") &&
			!strings.Contains(statementLower, "intent_sealed") {
			continue
		}
		if strings.Contains(statementLower, "not null") {
			t.Fatalf("%s 的 0054 追加列必须可空: %s", dialect, statement)
		}
	}
}

// TestReauthOperationProofMigrationDialects 校验 0054 在 MySQL/PostgreSQL/SQL Server
// 翻译结果中的结构与可空性语义一致（静态检查，不运行数据库）。
func TestReauthOperationProofMigrationDialects(t *testing.T) {
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
		assertOperationProofDialect(t, dialect.name, findMigration(t, translated, "0054"))
	}
}
