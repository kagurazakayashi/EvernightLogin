package mysql

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// TestTranslateAllSQLiteMigrations 是 46 个既有迁移的 MySQL 版本静态验收：
// 全部可翻译、版本/描述一致、SQLite 语法不泄漏、引擎/字符集/排序规则正确。
func TestTranslateAllSQLiteMigrations(t *testing.T) {
	source, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("读取 SQLite 迁移失败: %v", err)
	}
	translated, err := Load()
	if err != nil {
		t.Fatalf("翻译 MySQL 迁移失败: %v", err)
	}
	if len(translated) != 46 || len(translated) != len(source) {
		t.Fatalf("迁移数量 = %d/%d，期望 46", len(translated), len(source))
	}
	for index := range source {
		if translated[index].Version != source[index].Version {
			t.Fatalf("第 %d 条版本 = %s，期望 %s", index, translated[index].Version, source[index].Version)
		}
		if translated[index].Description != source[index].Description {
			t.Fatalf("版本 %s 描述 = %q，期望 %q", translated[index].Version,
				translated[index].Description, source[index].Description)
		}
		if !translated[index].NonTransactional {
			t.Fatalf("版本 %s 必须标记 non-transactional（MySQL DDL 隐式提交）", translated[index].Version)
		}
		if translated[index].Checksum == "" || translated[index].Checksum == source[index].Checksum {
			t.Fatalf("版本 %s 需要独立的 MySQL 校验和", translated[index].Version)
		}
	}

	var all strings.Builder
	for _, migration := range translated {
		for _, statement := range migration.Statements {
			all.WriteString(statement)
			all.WriteString("\n;\n")
		}
	}
	joined := all.String()

	for _, forbidden := range []string{"PRAGMA ", "json_valid(", "AUTOINCREMENT", "INSERT OR ", "ON CONFLICT", " RENAME TO ", "RAISE(", "WITHOUT ROWID"} {
		if strings.Contains(joined, forbidden) {
			t.Errorf("MySQL 迁移仍含 SQLite 语法 %q", forbidden)
		}
	}
	// 裸 rowid 不能被翻译结果包含（_rowid 是允许的列名）。
	if regexp.MustCompile(`(?i)(^|[^_A-Za-z0-9])rowid([^_A-Za-z0-9]|$)`).MatchString(joined) {
		t.Error("MySQL 迁移仍含裸 rowid")
	}
	if count := strings.Count(joined, "CREATE TABLE "); count != 96 {
		t.Errorf("CREATE TABLE 数量 = %d，期望 96", count)
	}
	if count := strings.Count(joined, "ENGINE=InnoDB"); count != 96 {
		t.Errorf("InnoDB 表数量 = %d，期望 96", count)
	}
	if count := strings.Count(joined, "COLLATE=utf8mb4_0900_as_cs"); count != 96 {
		t.Errorf("显式表排序规则数量 = %d，期望 96", count)
	}
	if count := strings.Count(joined, "SIGNAL SQLSTATE '45000'"); count != 4 {
		t.Errorf("触发器 SIGNAL 数量 = %d，期望 4", count)
	}
	if count := strings.Count(joined, "COLLATE utf8mb4_0900_bin"); count == 0 {
		t.Error("身份列缺少 utf8mb4_0900_bin 显式排序规则")
	}
	// 仓储 SQL 使用 rowid 的 4 张表必须有 _rowid 代理列。
	for _, table := range []string{"password_history", "audit_maintenance_log", "stats_health_samples", "user_emails"} {
		pattern := regexp.MustCompile(`CREATE TABLE ` + "`" + table + "`" + ` \([^)]*` + "`_rowid` BIGINT NOT NULL AUTO_INCREMENT")
		if !pattern.MatchString(joined) {
			t.Errorf("表 %s 缺少 _rowid 代理列", table)
		}
	}
	// 种子数据使用 INSERT IGNORE，人工重放半完成迁移不会因主键冲突中止。
	if !strings.Contains(joined, "INSERT IGNORE INTO scopes") {
		t.Error("种子 scope 未使用 INSERT IGNORE")
	}
	// 部分唯一索引必须翻译为生成列 + 唯一索引。
	if !strings.Contains(joined, "GENERATED ALWAYS AS (CASE WHEN") {
		t.Error("partial unique index 未翻译为生成列 + 唯一索引")
	}
	// 外键必须是表级 FOREIGN KEY（MySQL 会忽略列内联 REFERENCES，这是安全风险）。
	if regexp.MustCompile(`(?i)` + "`" + `[a-z_]+` + "`" + ` [A-Z]+[^,)]*REFERENCES`).MatchString(joined) {
		t.Error("存在列内联 REFERENCES；MySQL 会静默忽略，必须提升为表级外键")
	}

	if _, err := migrate.NewRunner(stubBackend{}, translated); err != nil {
		t.Fatalf("翻译后的迁移集合不能被迁移执行器接受: %v", err)
	}
}

// TestTranslatedKeyDDL 抽查关键方言映射，防止后续修改静默改变安全语义。
func TestTranslatedKeyDDL(t *testing.T) {
	translated, err := Load()
	if err != nil {
		t.Fatalf("翻译失败: %v", err)
	}
	byVersion := map[string]string{}
	for _, migration := range translated {
		byVersion[migration.Version] = strings.Join(migration.Statements, "\n;\n")
	}
	users := byVersion["0001"]
	for _, want := range []string{
		"`username_normalized` VARCHAR(254) COLLATE utf8mb4_0900_bin NOT NULL",
		"UNIQUE KEY",
		"`id` VARCHAR(128) COLLATE utf8mb4_0900_bin NOT NULL",
		"`profile_json` TEXT NOT NULL DEFAULT ('{}')",
		"CHECK (JSON_VALID(profile_json))",
		"`ux_single_root`",
		"GENERATED ALWAYS AS (CASE WHEN is_root=1 THEN 1 ELSE NULL END)",
		"FOREIGN KEY (`owner_user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL",
	} {
		if !strings.Contains(users, want) {
			t.Errorf("0001 缺少预期 DDL 片段 %q", want)
		}
	}
	// 人工审计：AUTOINCREMENT 的主键翻译为 BIGINT AUTO_INCREMENT + 主键。
	statistics := byVersion["0041"]
	if !strings.Contains(statistics, "`id` BIGINT NOT NULL AUTO_INCREMENT") {
		t.Errorf("0041 的 AUTOINCREMENT 主键翻译不正确")
	}
	// 重建表 + 数据搬迁 + 重命名。
	fido := byVersion["0023"]
	for _, want := range []string{"CREATE TABLE `webauthn_credentials_v2`", "INSERT INTO webauthn_credentials_v2",
		"DROP TABLE `webauthn_credentials`", "RENAME TABLE `webauthn_credentials_v2` TO `webauthn_credentials`"} {
		if !strings.Contains(fido, want) {
			t.Errorf("0023 缺少预期语句 %q", want)
		}
	}
	// 触发器：append-only 语义必须保留。
	support := byVersion["0026"]
	if !strings.Contains(support, "CREATE TRIGGER `trg_support_case_events_no_update` BEFORE UPDATE ON `support_case_events` FOR EACH ROW SIGNAL SQLSTATE '45000'") {
		t.Errorf("0026 触发器翻译不正确")
	}
	auditRead := byVersion["0040"]
	if !strings.Contains(auditRead, "BEGIN IF EXISTS(SELECT 1 FROM audit_maintenance_log WHERE id=NEW.id) THEN SIGNAL SQLSTATE '45000'") {
		t.Errorf("0040 带 WHEN 的触发器翻译不正确")
	}
}

// TestIdentityAndCheckLengths 防止身份 ID 列被映射得过短：服务层公开契约的 ID 上限为
// 128 字符，迁移 CHECK 也有 <=128 上界；STRICT 模式下过短会 Data too long（非严格模式
// 会静默截断破坏身份/审计一致性）。同时断言外键列与父列类型完全一致。
func TestIdentityAndCheckLengths(t *testing.T) {
	source, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("读取迁移失败: %v", err)
	}
	model, err := buildSchema(parsedForTest(source))
	if err != nil {
		t.Fatalf("构建 MySQL 模型失败: %v", err)
	}
	identityColumns := 0
	limitedColumns := 0
	for _, table := range model.tables {
		for _, column := range table.Columns {
			if column.SQLiteType != "TEXT" || column.MappedType == "TEXT" {
				continue
			}
			length := varcharLength(column.MappedType)
			if length <= 0 {
				continue
			}
			if column.Name == "id" || strings.HasSuffix(column.Name, "_id") {
				identityColumns++
				if length < 128 {
					t.Errorf("表 %s 身份列 %s = %s，短于 API 上限 128", table.Name, column.Name, column.MappedType)
				}
			}
			if column.LengthMax > 0 {
				limitedColumns++
				if length < column.LengthMax {
					t.Errorf("表 %s 列 %s = %s，短于 SQLite CHECK 上界 %d",
						table.Name, column.Name, column.MappedType, column.LengthMax)
				}
			}
		}
	}
	if identityColumns < 200 || limitedColumns < 20 {
		t.Fatalf("断言样本过少：身份列 %d、CHECK 上界列 %d", identityColumns, limitedColumns)
	}
	foreignKeys := 0
	for _, table := range model.tables {
		for _, fk := range table.FKs {
			parent := model.tables[fk.RefTable]
			if parent == nil {
				continue
			}
			for index, column := range fk.Columns {
				if index >= len(fk.RefCols) {
					continue
				}
				child := table.byName[column]
				reference := parent.byName[fk.RefCols[index]]
				if child == nil || reference == nil {
					continue
				}
				foreignKeys++
				if child.MappedType != reference.MappedType || child.BinaryString != reference.BinaryString {
					t.Errorf("表 %s 外键列 %s(%s) 与父列 %s.%s(%s) 类型/排序规则不一致",
						table.Name, column, child.MappedType, fk.RefTable, fk.RefCols[index], reference.MappedType)
				}
			}
		}
	}
	if foreignKeys < 80 {
		t.Fatalf("外键类型断言样本过少: %d", foreignKeys)
	}
}

func varcharLength(mappedType string) int {
	if !strings.HasPrefix(mappedType, "VARCHAR(") {
		return 0
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(mappedType, "VARCHAR("), ")")
	length := 0
	fmt.Sscanf(inner, "%d", &length)
	return length
}

// TestTranslateDeterministic 确认翻译是确定性的：两次结果校验和一致。
func TestTranslateDeterministic(t *testing.T) {
	first, err := Load()
	if err != nil {
		t.Fatalf("第一次翻译失败: %v", err)
	}
	second, err := Load()
	if err != nil {
		t.Fatalf("第二次翻译失败: %v", err)
	}
	for index := range first {
		if first[index].Checksum != second[index].Checksum {
			t.Fatalf("版本 %s 两次翻译校验和不一致", first[index].Version)
		}
	}
}

type stubBackend struct{}

func (stubBackend) Lock(ctx context.Context, fn func(context.Context) error) error { return fn(ctx) }
func (stubBackend) EnsureBookkeeping(ctx context.Context) error                    { return nil }
func (stubBackend) LoadApplied(ctx context.Context) ([]migrate.AppliedMigration, error) {
	return nil, nil
}
func (stubBackend) LoadFailed(ctx context.Context) ([]migrate.FailedMigration, error) {
	return nil, nil
}
func (stubBackend) Apply(ctx context.Context, statements []string, record migrate.AppliedMigration) error {
	return nil
}
func (stubBackend) RecordFailure(ctx context.Context, record migrate.FailedMigration) error {
	return nil
}
func (stubBackend) ClearFailure(ctx context.Context, version string) error { return nil }
