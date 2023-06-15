package sqlserver

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// testModel 用与 Translate 相同的拆分/建模流程构造迁移模型，供静态断言使用。
func testModel(t *testing.T) *schemaModel {
	t.Helper()
	source, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载 SQLite 迁移失败: %v", err)
	}
	parsed := make([]parsedMigration, 0, len(source))
	for _, migration := range source {
		statements := migration.Statements
		if len(statements) == 1 {
			statements, err = splitWholeFileScript(statements[0])
			if err != nil {
				t.Fatalf("拆分迁移 %s 失败: %v", migration.FileName, err)
			}
		}
		parsed = append(parsed, parsedMigration{source: migration, statements: statements})
	}
	model, err := buildSchema(parsed)
	if err != nil {
		t.Fatalf("构造迁移模型失败: %v", err)
	}
	return model
}

func translatedStatements(t *testing.T) []string {
	t.Helper()
	translated, err := Load()
	if err != nil {
		t.Fatalf("翻译失败: %v", err)
	}
	var statements []string
	for _, migration := range translated {
		statements = append(statements, migration.Statements...)
	}
	return statements
}

// TestTranslateAllSQLiteMigrations 是 46 条迁移确定性翻译的机器可查验收：
// 表/索引/触发器/重命名/种子数量、排序规则、主键非聚集、无 SQLite 语法泄漏。
func TestTranslateAllSQLiteMigrations(t *testing.T) {
	source, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载 SQLite 迁移失败: %v", err)
	}
	translated, err := Load()
	if err != nil {
		t.Fatalf("翻译失败: %v", err)
	}
	if len(translated) != 46 || len(source) != 46 {
		t.Fatalf("迁移数量错误：源 %d，翻译 %d，期望 46", len(source), len(translated))
	}
	for index := range source {
		if translated[index].Version != source[index].Version ||
			translated[index].Description != source[index].Description {
			t.Fatalf("第 %d 条迁移版本/描述不一致: %s/%s vs %s/%s", index,
				translated[index].Version, translated[index].Description,
				source[index].Version, source[index].Description)
		}
		if translated[index].NonTransactional {
			t.Errorf("SQL Server 迁移 %s 不应标记 NonTransactional（DDL 可事务回滚）", translated[index].Version)
		}
		if len(translated[index].Checksum) != 64 {
			t.Errorf("迁移 %s 校验和长度错误: %q", translated[index].Version, translated[index].Checksum)
		}
	}

	sourceFiltered := 0
	for _, migration := range source {
		statements := migration.Statements
		if len(statements) == 1 {
			statements, _ = splitWholeFileScript(statements[0])
		}
		for _, statement := range statements {
			upper := strings.ToUpper(statement)
			if strings.HasPrefix(upper, "CREATE UNIQUE INDEX") && regexp.MustCompile(`(?i)\bWHERE\b`).MatchString(statement) {
				sourceFiltered++
			}
		}
	}
	var tables, primaryKeys, collations, filteredIndexes, triggers, renames, seeds int
	for _, statement := range translatedStatements(t) {
		upper := strings.ToUpper(statement)
		tables += strings.Count(upper, "CREATE TABLE [")
		primaryKeys += strings.Count(statement, "PRIMARY KEY NONCLUSTERED")
		collations += strings.Count(statement, "COLLATE "+collationName)
		triggers += strings.Count(upper, "CREATE TRIGGER [")
		renames += strings.Count(upper, "EXEC SP_RENAME")
		seeds += strings.Count(upper, "INSERT INTO ")
		if strings.Contains(upper, "CREATE UNIQUE INDEX") && strings.Contains(upper, " WHERE ") {
			filteredIndexes++
		}
		for _, forbidden := range []string{"`", "AUTOINCREMENT", "PRAGMA ", "RAISE(", "WITHOUT ROWID",
			"ON CONFLICT", "INSERT OR ", "LIMIT ", "json_valid(", " TEXT", "TEXT ,", "TEXT)"} {
			if strings.Contains(statement, forbidden) {
				t.Errorf("翻译结果含 SQLite 语法 %q: %s", forbidden, snippet(statement))
			}
		}
		if regexp.MustCompile(`(?i)(^|[^_A-Za-z0-9])rowid([^_A-Za-z0-9]|$)`).MatchString(statement) {
			t.Errorf("翻译结果含裸 rowid: %s", snippet(statement))
		}
	}
	if tables != 96 {
		t.Errorf("CREATE TABLE 数量 %d，期望 96", tables)
	}
	if primaryKeys != 96 {
		t.Errorf("NONCLUSTERED 主键数量 %d，期望 96", primaryKeys)
	}
	if collations < 300 {
		t.Errorf("显式二进制排序规则数量 %d，明显偏少", collations)
	}
	if filteredIndexes != sourceFiltered {
		t.Errorf("过滤唯一索引数量 %d 与源迁移 %d 不一致", filteredIndexes, sourceFiltered)
	}
	if triggers != 3 {
		t.Errorf("翻译后触发器数量 %d，期望 3（BEFORE INSERT 保护明确不翻译）", triggers)
	}
	if renames != 4 {
		t.Errorf("sp_rename 数量 %d，期望 4", renames)
	}
	if seeds != 6 {
		t.Errorf("迁移种子 INSERT 数量 %d，期望 6", seeds)
	}
	// 唯一索引用 HASHBYTES 摘要替代超长键：verifier_hash 与 webhook url 两处。
	joined := strings.Join(translatedStatements(t), "\n")
	if !strings.Contains(joined, "_hash_verifier_hash") || !strings.Contains(joined, "_hash_url") {
		t.Errorf("缺少超长唯一键的摘要计算列")
	}
	if strings.Contains(joined, "trg_audit_maintenance_log_no_replace") {
		t.Errorf("语义不可用的 INSERT 替换保护触发器不应生成")
	}
	t.Logf("迁移静态计数：46 条 / 96 表 / 96 非聚集主键 / %d 处显式 BINARY 排序规则 / "+
		"%d 个过滤唯一索引 / %d 个触发器 / %d 次 sp_rename / %d 条种子 INSERT",
		collations, filteredIndexes, triggers, renames, seeds)
}

// TestIdentityAndCheckLengths 验证身份列长度不小于服务层 128 字符上限与 SQLite CHECK
// 上界、外键列与父列类型完全一致。
func TestIdentityAndCheckLengths(t *testing.T) {
	model := testModel(t)
	identityColumns := 0
	checkBounded := 0
	for _, table := range model.tables {
		for _, column := range table.Columns {
			if column.SQLiteType != "TEXT" {
				continue
			}
			length := nvarcharLength(column.MappedType)
			if column.Identity {
				identityColumns++
				if length < identityMinLength {
					t.Errorf("表 %s 身份列 %s 长度 %d 小于公开 ID 上限 %d",
						table.Name, column.Name, length, identityMinLength)
				}
				if column.LengthMax > 0 && length < column.LengthMax {
					t.Errorf("表 %s 身份列 %s 长度 %d 小于 CHECK 上界 %d",
						table.Name, column.Name, length, column.LengthMax)
				}
			}
			if column.LengthMax > 0 && length > 0 {
				checkBounded++
				if length < column.LengthMax && length != nvarcharMaxLength {
					t.Errorf("表 %s 列 %s 的 NVARCHAR(%d) 小于 CHECK 上界 %d",
						table.Name, column.Name, length, column.LengthMax)
				}
			}
		}
	}
	foreignKeyColumns := 0
	for _, table := range model.tables {
		for _, fk := range table.TableFKs {
			foreignKeyColumns += len(fk.Columns)
			parent := model.live[model.resolveName(fk.RefTable)]
			if parent == nil {
				t.Errorf("表 %s 的表级外键父表 %s 不存在", table.Name, fk.RefTable)
				continue
			}
			for index, name := range fk.Columns {
				column := table.column(name)
				parentColumn := parent.column(fk.RefCols[index])
				if column == nil || parentColumn == nil {
					t.Errorf("表 %s 表级外键列 %s 无法解析", table.Name, name)
					continue
				}
				if column.MappedType != parentColumn.MappedType {
					t.Errorf("表 %s 表级外键列 %s 类型 %q 与父列 %q 不一致",
						table.Name, name, column.MappedType, parentColumn.MappedType)
				}
			}
		}
		for _, column := range table.Columns {
			if column.Ref == nil {
				continue
			}
			foreignKeyColumns++
			parent := model.live[model.resolveName(column.Ref.Table)]
			if parent == nil {
				t.Errorf("表 %s 列 %s 的外键父表 %s 不存在", table.Name, column.Name, column.Ref.Table)
				continue
			}
			parentColumn := parent.column(column.Ref.Column)
			if parentColumn == nil {
				t.Errorf("表 %s 列 %s 的外键父列不存在", table.Name, column.Name)
				continue
			}
			if parentColumn.MappedType != column.MappedType {
				t.Errorf("表 %s 列 %s 类型 %q 与外键父列 %s.%s 类型 %q 不一致",
					table.Name, column.Name, column.MappedType, parent.Name, parentColumn.Name, parentColumn.MappedType)
			}
		}
	}
	if identityColumns < 250 {
		t.Errorf("身份列数量 %d，明显偏少（扫描器可能失效）", identityColumns)
	}
	if foreignKeyColumns < 100 {
		t.Errorf("外键列数量 %d，明显偏少（扫描器可能失效）", foreignKeyColumns)
	}
	t.Logf("身份/外键静态计数：表 %d / 身份 TEXT 列 %d（全部 ≥128 且 ≥CHECK 上界）/ "+
		"CHECK 上界列 %d / 外键列 %d（类型与父列完全一致）",
		len(model.tables), identityColumns, checkBounded, foreignKeyColumns)
}

// nvarcharLength 解析 NVARCHAR(n) 的 n；NVARCHAR(MAX) 返回 nvarcharMaxLength。
func nvarcharLength(mappedType string) int {
	if strings.HasPrefix(mappedType, "NVARCHAR(MAX)") {
		return nvarcharMaxLength
	}
	length := 0
	if _, err := fmt.Sscanf(strings.TrimPrefix(mappedType, "NVARCHAR("), "%d", &length); err != nil {
		return 0
	}
	return length
}

// TestIndexBudgetAndHashColumns 验证主键索引键均不超过 1700 字节预算、超预算唯一键
// 使用 HASHBYTES 持久化计算列，且计算列声明出现在 CREATE TABLE 中。
func TestIndexBudgetAndHashColumns(t *testing.T) {
	model := testModel(t)
	for _, table := range model.tables {
		primary := primaryKeyOf(table)
		if len(primary) == 0 {
			continue
		}
		if !indexWithinBudgetSingleList(table, primary) {
			t.Errorf("表 %s 的主键索引键超过 1700 字节预算（翻译应 fail-closed）: %v", table.Name, primary)
		}
	}
	translated := strings.Join(translatedStatements(t), "\n")
	for tableName, columns := range map[string][]string{
		"one_time_credentials": {"verifier_hash"},
		"webhook_endpoints":    {"url"},
	} {
		table := model.live[tableName]
		if table == nil {
			t.Fatalf("迁移模型缺少表 %s", tableName)
		}
		for _, columnName := range columns {
			column := table.column(columnName)
			if column == nil {
				t.Fatalf("表 %s 缺少列 %s", tableName, columnName)
			}
			if indexWithinBudgetSingle(column) {
				t.Errorf("表 %s 列 %s 不应被判为超预算（测试前提失效）", tableName, columnName)
			}
			computed := "_hash_" + columnName
			if !strings.Contains(translated, "["+computed+"] AS (HASHBYTES('SHA2_256', ["+columnName+"])) PERSISTED") {
				t.Errorf("表 %s 缺少列 %s 的摘要计算列声明", tableName, columnName)
			}
			if !strings.Contains(translated, "["+computed+"]") {
				t.Errorf("表 %s 的唯一索引未使用摘要列 %s", tableName, computed)
			}
		}
	}
	// 除上述两列外不应有更多摘要计算列（避免无意改变索引语义）。
	if count := strings.Count(translated, "HASHBYTES('SHA2_256'"); count != 2 {
		t.Errorf("HASHBYTES 摘要计算列数量 %d，期望 2", count)
	}
}

// TestTranslatedKeyDDL 抽查关键迁移的 T-SQL 形态。
func TestTranslatedKeyDDL(t *testing.T) {
	translated, err := Load()
	if err != nil {
		t.Fatalf("翻译失败: %v", err)
	}
	byVersion := map[string][]string{}
	for _, migration := range translated {
		byVersion[migration.Version] = migration.Statements
	}
	joined := func(version string) string { return strings.Join(byVersion[version], "\n") }

	case0001 := joined("0001")
	for _, want := range []string{
		"CONSTRAINT [PK_users] PRIMARY KEY NONCLUSTERED ([id])",
		"[username_normalized] NVARCHAR(254) COLLATE Latin1_General_100_BIN2",
		"CREATE UNIQUE INDEX [ux_single_root] ON [users] ([is_root]) WHERE [is_root]=1",
		"CONSTRAINT [FK_applications_owner_user_id] FOREIGN KEY ([owner_user_id]) REFERENCES [users] ([id]) ON DELETE SET NULL",
	} {
		if !strings.Contains(case0001, want) {
			t.Errorf("0001 缺少 %q", want)
		}
	}
	case0009 := joined("0009")
	for _, want := range []string{
		"CREATE TABLE [password_history]",
		"[_rowid] BIGINT IDENTITY(1,1) NOT NULL",
		"CONSTRAINT [PK_password_history] PRIMARY KEY NONCLUSTERED ([user_id], [password_hash])",
		"CONSTRAINT [FK_password_history_user_id] FOREIGN KEY ([user_id]) REFERENCES [users] ([id]) ON DELETE CASCADE",
	} {
		if !strings.Contains(case0009, want) {
			t.Errorf("0009 缺少 %q", want)
		}
	}
	case0021 := joined("0021")
	if !strings.Contains(case0021, "EXEC sp_rename N'[mfa_challenges_v2]', N'mfa_challenges'") {
		t.Errorf("0021 缺少 sp_rename 重命名")
	}
	if strings.Contains(case0021, "CREATE TRIGGER") {
		t.Errorf("0021 不应包含触发器")
	}
	case0023 := joined("0023")
	if count := strings.Count(case0023, "EXEC sp_rename"); count != 3 {
		t.Errorf("0023 sp_rename 数量 %d，期望 3", count)
	}
	for _, want := range []string{
		"[credential_id] VARBINARY(1023) NOT NULL",
		"CONSTRAINT [UQ_webauthn_credentials_v2_credential_id] UNIQUE",
	} {
		if !strings.Contains(case0023, want) {
			t.Errorf("0023 缺少 %q", want)
		}
	}
	case0037 := joined("0037")
	for _, want := range []string{
		"[url] NVARCHAR(2048) COLLATE Latin1_General_100_BIN2 NOT NULL",
		"[_hash_url] AS (HASHBYTES('SHA2_256', [url])) PERSISTED",
		"CREATE UNIQUE INDEX [UX_webhook_endpoints_1] ON [webhook_endpoints] ([application_id], [_hash_url])",
	} {
		if !strings.Contains(case0037, want) {
			t.Errorf("0037 缺少 %q", want)
		}
	}
	case0040 := joined("0040")
	if count := strings.Count(case0040, "CREATE TRIGGER"); count != 2 {
		t.Errorf("0040 触发器数量 %d，期望 2（BEFORE INSERT 保护明确不翻译）", count)
	}
	for _, want := range []string{
		"AFTER UPDATE AS",
		"AFTER DELETE AS",
		"SET NOCOUNT ON;",
		";THROW 50000, N'audit_maintenance_log is append-only', 1;",
		"SELECT 1 FROM inserted",
		"SELECT 1 FROM deleted",
	} {
		if !strings.Contains(case0040, want) {
			t.Errorf("0040 缺少 %q", want)
		}
	}
	if strings.Contains(case0040, "BEFORE") {
		t.Errorf("SQL Server 没有 BEFORE 触发器，翻译结果不应含 BEFORE")
	}
}

// TestTranslateDeterministic 验证同样源迁移产生同样 T-SQL 与校验和。
func TestTranslateDeterministic(t *testing.T) {
	first, err := Load()
	if err != nil {
		t.Fatalf("翻译失败: %v", err)
	}
	for round := 0; round < 3; round++ {
		again, err := Load()
		if err != nil {
			t.Fatalf("第 %d 轮翻译失败: %v", round, err)
		}
		if len(again) != len(first) {
			t.Fatalf("第 %d 轮迁移数量不一致", round)
		}
		for index := range first {
			if first[index].Checksum != again[index].Checksum ||
				strings.Join(first[index].Statements, "\x00") != strings.Join(again[index].Statements, "\x00") {
				t.Fatalf("第 %d 轮迁移 %s 翻译不确定", round, first[index].Version)
			}
		}
	}
}

// TestPrimaryKeyColumns 验证 INSERT OR IGNORE 需要的冲突键来自已提交迁移主键。
func TestPrimaryKeyColumns(t *testing.T) {
	columns, err := PrimaryKeyColumns("password_history")
	if err != nil {
		t.Fatalf("password_history 主键解析失败: %v", err)
	}
	if strings.Join(columns, ",") != "user_id,password_hash" {
		t.Errorf("password_history 主键 %v 不符合预期", columns)
	}
	columns, err = PrimaryKeyColumns("backup_jobs")
	if err != nil {
		t.Fatalf("backup_jobs 主键解析失败: %v", err)
	}
	if strings.Join(columns, ",") != "job_id" {
		t.Errorf("backup_jobs 主键 %v 不符合预期", columns)
	}
	if _, err := PrimaryKeyColumns("no_such_table"); err == nil {
		t.Error("未知表应返回错误而不是空主键")
	}
}

// TestUniqueNullableColumns 记录唯一约束可空列清单：SQLite UNIQUE 允许多行 NULL，
// SQL Server 唯一索引只允许一行 NULL。当前唯一可空列只有 scopes.app_id（system 行
// 为 NULL，应用 scope 非 NULL），实际数据至多一行 NULL，因此语义差异可接受；新增
// 可空唯一列必须重新评估该差异。
func TestUniqueNullableColumns(t *testing.T) {
	model := testModel(t)
	var nullable []string
	for _, table := range model.tables {
		for _, column := range table.Columns {
			if column.Unique && !column.NotNull {
				nullable = append(nullable, table.Name+"."+column.Name)
			}
		}
		for _, unique := range table.TableUniques {
			for _, name := range unique {
				column := table.column(name)
				if column != nil && !column.NotNull {
					nullable = append(nullable, table.Name+"."+name)
				}
			}
		}
	}
	expected := map[string]bool{"scopes.app_id": true}
	for _, item := range nullable {
		if !expected[item] {
			t.Errorf("出现新的可空唯一列 %s：SQL Server 唯一索引只允许一行 NULL，需重新评估语义", item)
		}
	}
	if len(nullable) != len(expected) {
		t.Errorf("可空唯一列清单 %v 与预期不一致", nullable)
	}
}
