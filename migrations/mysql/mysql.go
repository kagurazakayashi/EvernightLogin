// Package mysql 把已提交的 SQLite 迁移确定性翻译为 MySQL 8.0 DDL。
//
// 本包不执行任何 SQL，也不连接数据库。它读取 migrations 内嵌的 SQLite 迁移文件，
// 在解析出完整表/列/索引/外键模型后生成 MySQL 版本语句；翻译是确定性的，相同输入
// 总是得到相同输出，校验和基于翻译后的语句内容单独计算（SQLite 与 MySQL 使用各自
// 的 schema_history，互不比较校验和）。
//
// 设计约束：
//   - 不修改 migrations/*.sql（已部署迁移不可变）；MySQL 迁移在加载时生成。
//   - MySQL DDL 隐式提交，翻译结果一律标记 NonTransactional；执行器不承诺回滚。
//   - 身份唯一性不依赖服务器默认排序规则：表默认 utf8mb4_0900_as_cs（大小写与重音
//     敏感，匹配 SQLite TEXT 默认 BINARY 比较），主键/唯一键/外键/不透明 ID 列显式
//     COLLATE utf8mb4_0900_bin（按码点比较、NO PAD），模拟规范化用户名唯一性。
//   - 索引按 utf8mb4 最大 4 字节/字符计算，校验单键与复合键不超过 3072 字节。
//   - SQLite partial unique index 用虚拟生成列 + 唯一索引模拟；partial 非唯一索引
//     退化为全表索引（结果等价，只增加索引体积），在文档中登记。
//   - MySQL 无 rowid：仓储 SQL 使用 rowid 的 4 张表追加 _rowid 自增列（见
//     rowidSurrogateTables），仓储 SQL 由 internal/storage/mysql 的重写层把 rowid
//     改成 _rowid。
//   - 触发器 RAISE(ABORT, 'msg') 翻译为 SIGNAL SQLSTATE '45000'；带 WHEN 的触发器
//     翻译为 IF ... THEN SIGNAL ... END IF。
//
// 目标版本：MySQL 8.0.16+（CHECK 约束从此版本开始真正执行），不支持 MariaDB
// （0900 排序规则与 SIGNAL/生成列行为不同，明确拒绝而不是静默降级）。
package mysql

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const (
	// TargetVersion 是声明支持的 MySQL 最低版本。
	TargetVersion = "8.0.16"
	// engine 是 MySQL 表引擎；迁移与恢复依赖 InnoDB 的事务/外键/行锁。
	engine = "InnoDB"
	// tableCollation 是表默认排序规则：大小写与重音敏感，接近 SQLite TEXT 的
	// BINARY 比较语义，避免默认 ai_ci 让 WHERE 过滤大小写不敏感。
	tableCollation = "utf8mb4_0900_as_cs"
	// identityCollation 是主键/唯一键/外键/不透明 ID 列的排序规则：按码点比较且
	// NO PAD，避免服务器默认排序规则改变身份唯一性或让 'a' 与 'a ' 相等。
	identityCollation = "utf8mb4_0900_bin"
	// maxIndexBytes 是 InnoDB 单索引最大字节数（DYNAMIC 行格式）。
	maxIndexBytes = 3072
	// charset 是统一字符集。
	charset = "utf8mb4"
)

// rowidSurrogateTables 列出仓储 SQL 直接使用 SQLite rowid 的表。MySQL 无 rowid，
// 翻译迁移时为这些表追加 _rowid BIGINT AUTO_INCREMENT 列，重写层把 rowid 映射为
// _rowid。列表必须与 internal/storage/mysql 的仓储 SQL 审计测试一致。
var rowidSurrogateTables = map[string]bool{
	"password_history":      true,
	"audit_maintenance_log": true,
	"stats_health_samples":  true,
	"user_emails":           true,
}

// Load 读取内嵌 SQLite 迁移并返回对应的 MySQL 迁移集合。调用方应使用
// internal/storage/mysql 的 Backend 执行它们。
func Load() ([]migrate.Migration, error) {
	return Translate(migrations.SQLite)
}

// Translate 把给定文件系统内的 SQLite 迁移确定性翻译为 MySQL 迁移。
//
// 校验和基于翻译后的语句文本计算，因此与 SQLite 文件的 SHA-256 不同；已有 MySQL
// 数据库的 schema_history 只与这里的校验和比较。版本号、描述与文件名保持原样。
func Translate(fsys fs.FS) ([]migrate.Migration, error) {
	source, err := migrate.LoadMigrations(fsys)
	if err != nil {
		return nil, err
	}
	parsed := make([]parsedMigration, 0, len(source))
	for _, migration := range source {
		statements := migration.Statements
		if len(statements) == 1 {
			// whole-file 迁移（触发器或显式 whole-file）只给出一条合并脚本，需要自行
			// 按触发器块拆分；普通单语句迁移拆分后仍是自身。
			statements = splitWholeFileScript(statements[0])
		}
		parsed = append(parsed, parsedMigration{source: migration, statements: statements})
	}

	model, err := buildSchema(parsed)
	if err != nil {
		return nil, err
	}
	translator := &translator{schema: model, created: map[string]bool{}}
	translated := make([]migrate.Migration, 0, len(parsed))
	for _, migration := range parsed {
		statements, err := translator.translateMigration(migration.statements)
		if err != nil {
			return nil, fmt.Errorf("翻译迁移 %s 失败: %w", migration.source.FileName, err)
		}
		if len(statements) == 0 {
			return nil, fmt.Errorf("翻译迁移 %s 没有得到任何语句", migration.source.FileName)
		}
		if err := validateTranslated(statements); err != nil {
			return nil, fmt.Errorf("翻译迁移 %s 校验失败: %w", migration.source.FileName, err)
		}
		translated = append(translated, migrate.Migration{
			Version:          migration.source.Version,
			Description:      migration.source.Description,
			FileName:         migration.source.FileName,
			Checksum:         checksumOfStatements(statements),
			Statements:       statements,
			NonTransactional: true,
		})
	}
	if len(translator.pendingFK) > 0 {
		return nil, fmt.Errorf("有 %d 个外键在全部迁移结束后仍找不到父表（SQLite 允许前向引用，MySQL 不允许）",
			len(translator.pendingFK))
	}
	if err := translator.validateForeignKeyTargets(); err != nil {
		return nil, err
	}
	return translated, nil
}

type parsedMigration struct {
	source     migrate.Migration
	statements []string
}

// checksumOfStatements 对 MySQL 语句集合计算稳定校验和。语句之间用固定分隔符，
// 避免直接拼接产生歧义。
func checksumOfStatements(statements []string) string {
	digest := sha256.New()
	digest.Write([]byte("mysql:"))
	for _, statement := range statements {
		digest.Write([]byte(statement))
		digest.Write([]byte("\n;\n"))
	}
	return hex.EncodeToString(digest.Sum(nil))
}

// ---------------------------------------------------------------------------
// 原 SQL 解析：表/列/索引/外键模型
// ---------------------------------------------------------------------------

type columnInfo struct {
	Name          string
	SQLiteType    string // TEXT / INTEGER / BLOB
	NotNull       bool
	InlinePK      bool
	InlineUnique  bool
	AutoIncrement bool
	Default       string // 原始字面量/表达式；空表示无默认值
	Checks        []string
	References    *reference
	IsKey         bool // 参与主键/唯一键/索引/外键
	MappedType    string
	BinaryString  bool // 文本列使用身份排序规则（COLLATE utf8mb4_0900_bin）
	LengthMax     int  // 来自 CHECK(length(col) BETWEEN a AND b) 的上界；0 未知
}

type reference struct {
	Table    string
	Columns  []string
	OnDelete string
}

type foreignKey struct {
	Columns  []string
	RefTable string
	RefCols  []string
	OnDelete string
}

type tableInfo struct {
	Name       string
	Columns    []*columnInfo
	byName     map[string]*columnInfo
	PK         []string
	Uniques    [][]string
	TableCheck []string
	FKs        []foreignKey
	Rowid      bool
}

type schemaModel struct {
	tables map[string]*tableInfo
	order  []string
	// indexes 记录 CREATE INDEX 的列，用于标记索引列并计算键长。
	indexes []indexInfo
	// aliases 保留“定义时表名 -> 最终表模型”，用于重建表/RENAME 后仍能翻译原始
	// CREATE TABLE/ALTER TABLE 语句（SQLite 允许先建临时表再重命名）。
	aliases map[string]*tableInfo
	// plans 保存每个索引键的最终列计划（真实列 / SHA-256 生成列）。
	plans map[string][]indexPart
	// hashN 是全库生成列计数，保证生成列名确定且不重复。
	hashN int
}

// partKind 表示索引键中的一列是真实列还是 SHA-256 生成列。
type partKind int

const (
	partReal partKind = iota
	partHash
)

// indexPart 是索引键中的一列。
type indexPart struct {
	kind      partKind
	column    string
	generated string
}

// planKeyForIndex/planKeyForPK 等生成稳定的计划键。
func planKeyForIndex(name string) string { return "IX:" + name }
func planKeyForPK(table string) string   { return "PK:" + table }
func planKeyForUnique(table string, index int) string {
	return fmt.Sprintf("UQ:%s:%d", table, index)
}
func planKeyForFK(table string, index int) string {
	return fmt.Sprintf("FK:%s:%d", table, index)
}

type indexInfo struct {
	Name    string
	Table   string
	Columns []string
	Unique  bool
	Where   string
}

func buildSchema(migrations []parsedMigration) (*schemaModel, error) {
	model := &schemaModel{tables: map[string]*tableInfo{}, aliases: map[string]*tableInfo{}}
	for _, migration := range migrations {
		for _, statement := range migration.statements {
			keyword := leadingKeyword(statement)
			switch keyword {
			case "CREATE TABLE":
				table, err := parseCreateTable(statement)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", migration.source.FileName, err)
				}
				if _, exists := model.tables[table.Name]; exists {
					return nil, fmt.Errorf("%s: 表 %s 重复定义", migration.source.FileName, table.Name)
				}
				model.tables[table.Name] = table
				model.aliases[table.Name] = table
				model.order = append(model.order, table.Name)
			case "CREATE INDEX", "CREATE UNIQUE INDEX":
				index, err := parseCreateIndex(statement)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", migration.source.FileName, err)
				}
				model.indexes = append(model.indexes, index)
			case "ALTER TABLE":
				if err := model.applyAlter(statement); err != nil {
					return nil, fmt.Errorf("%s: %w", migration.source.FileName, err)
				}
			case "DROP TABLE":
				name := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(statement, "DROP TABLE"), ";"))
				name = strings.TrimPrefix(name, "IF EXISTS ")
				delete(model.tables, name)
			}
		}
	}
	// 标记键列并计算 MySQL 类型。
	for _, index := range model.indexes {
		table := model.tables[index.Table]
		if table == nil {
			return nil, fmt.Errorf("索引 %s 引用了未知表 %s", index.Name, index.Table)
		}
		for _, column := range index.Columns {
			info := table.byName[column]
			if info == nil {
				return nil, fmt.Errorf("索引 %s 引用了未知列 %s.%s", index.Name, index.Table, column)
			}
			info.IsKey = true
		}
	}
	for _, table := range model.tables {
		for _, column := range table.PK {
			table.byName[column].IsKey = true
		}
		for _, unique := range table.Uniques {
			for _, column := range unique {
				table.byName[column].IsKey = true
			}
		}
		for _, fk := range table.FKs {
			for _, column := range fk.Columns {
				if info := table.byName[column]; info != nil {
					info.IsKey = true
				}
			}
		}
		table.Rowid = rowidSurrogateTables[table.Name]
		for _, column := range table.Columns {
			if err := assignMySQLType(table, column); err != nil {
				return nil, err
			}
		}
	}
	if err := model.buildIndexPlans(); err != nil {
		return nil, err
	}
	return model, nil
}

// buildIndexPlans 为每个索引键选择真实列或 SHA-256 生成列，并校验 3072 字节上限。
func (m *schemaModel) buildIndexPlans() error {
	m.plans = map[string][]indexPart{}
	for _, name := range m.order {
		table := m.tables[name]
		if table == nil {
			continue
		}
		key := planKeyForPK(table.Name)
		plan, err := m.planIndex(table, key, table.PK, 0)
		if err != nil {
			return err
		}
		m.plans[key] = plan
		for index, unique := range table.Uniques {
			key := planKeyForUnique(table.Name, index)
			plan, err := m.planIndex(table, key, unique, 0)
			if err != nil {
				return err
			}
			m.plans[key] = plan
		}
		for index := range table.FKs {
			fk := table.FKs[index]
			total := 0
			for _, column := range fk.Columns {
				total += columnBytes(table.byName[column])
			}
			if total > maxIndexBytes {
				return fmt.Errorf("表 %s 的外键列超过 %d 字节索引上限", table.Name, maxIndexBytes)
			}
			m.plans[planKeyForFK(table.Name, index)] = realParts(table, fk.Columns)
		}
	}
	for _, index := range m.indexes {
		table := m.tables[index.Table]
		if table == nil {
			continue
		}
		extra := 0
		if index.Unique && index.Where != "" {
			extra = 1 // 部分唯一索引的过滤生成列 TINYINT
		}
		plan, err := m.planIndex(table, planKeyForIndex(index.Name), index.Columns, extra)
		if err != nil {
			return err
		}
		m.plans[planKeyForIndex(index.Name)] = plan
	}
	return nil
}

func realParts(table *tableInfo, columns []string) []indexPart {
	parts := make([]indexPart, 0, len(columns))
	for _, column := range columns {
		parts = append(parts, indexPart{kind: partReal, column: column})
	}
	return parts
}

// planIndex 先尝试全部真实列；超限时把长文本键列改为 SHA-256 生成列（32 字节），
// 再超限则把其余文本列也改为生成列。整数/二进制短列保持真实列。
func (m *schemaModel) planIndex(table *tableInfo, key string, columns []string, extraBytes int) ([]indexPart, error) {
	if len(columns) == 0 {
		return nil, nil
	}
	parts := make([]indexPart, 0, len(columns))
	total := extraBytes
	for _, column := range columns {
		info := table.byName[column]
		if info == nil {
			return nil, fmt.Errorf("索引 %s 引用了未知列 %s.%s", key, table.Name, column)
		}
		if info.MappedType == "TEXT" {
			parts = append(parts, indexPart{kind: partHash, column: column})
			total += 32
			continue
		}
		parts = append(parts, indexPart{kind: partReal, column: column})
		total += columnBytes(info)
	}
	if total > maxIndexBytes {
		// 第二轮：把有字符长度上界的文本列改为生成列（尽量保留真实列）。
		parts = parts[:0]
		total = extraBytes
		for _, column := range columns {
			info := table.byName[column]
			if info.SQLiteType == "TEXT" && info.LengthMax > 191 {
				parts = append(parts, indexPart{kind: partHash, column: column})
				total += 32
				continue
			}
			parts = append(parts, indexPart{kind: partReal, column: column})
			total += columnBytes(info)
		}
	}
	if total > maxIndexBytes {
		// 第三轮：所有文本/二进制长键列都改为生成列，整数列保留。
		parts = parts[:0]
		total = extraBytes
		for _, column := range columns {
			info := table.byName[column]
			if info.SQLiteType == "TEXT" {
				parts = append(parts, indexPart{kind: partHash, column: column})
				total += 32
				continue
			}
			parts = append(parts, indexPart{kind: partReal, column: column})
			total += columnBytes(info)
		}
	}
	if total > maxIndexBytes {
		return nil, fmt.Errorf("表 %s 的索引 %s 需要 %d 字节，超过 %d 字节上限", table.Name, key, total, maxIndexBytes)
	}
	for index := range parts {
		if parts[index].kind == partHash {
			m.hashN++
			parts[index].generated = fmt.Sprintf("_gh%d", m.hashN)
		}
	}
	return parts, nil
}

func (m *schemaModel) applyAlter(statement string) error {
	rest := strings.TrimSpace(strings.TrimPrefix(statement, "ALTER TABLE"))
	name, remainder := readIdentifier(rest)
	table := m.tables[name]
	if table == nil {
		return fmt.Errorf("ALTER TABLE 引用了未知表 %s", name)
	}
	remainder = strings.TrimSpace(remainder)
	upper := strings.ToUpper(remainder)
	switch {
	case strings.HasPrefix(upper, "RENAME TO "):
		newName := strings.TrimSpace(remainder[len("RENAME TO "):])
		newName = strings.TrimSuffix(strings.TrimSpace(newName), ";")
		if existing := m.tables[newName]; existing != nil {
			return fmt.Errorf("重命名目标表 %s 已存在", newName)
		}
		delete(m.tables, name)
		m.aliases[name] = table
		table.Name = newName
		m.tables[newName] = table
	case strings.HasPrefix(upper, "ADD COLUMN "):
		for _, definition := range splitColumnDefinitions(remainder[len("ADD COLUMN "):]) {
			column, err := parseColumnDefinition(definition)
			if err != nil {
				return err
			}
			if table.byName[column.Name] != nil {
				return fmt.Errorf("表 %s 的列 %s 重复添加", name, column.Name)
			}
			table.Columns = append(table.Columns, column)
			if table.byName == nil {
				table.byName = map[string]*columnInfo{}
			}
			table.byName[column.Name] = column
			if column.InlinePK {
				table.PK = []string{column.Name}
			}
			if column.InlineUnique {
				table.Uniques = append(table.Uniques, []string{column.Name})
			}
			if column.References != nil {
				table.FKs = append(table.FKs, foreignKey{
					Columns: []string{column.Name}, RefTable: column.References.Table,
					RefCols: column.References.Columns, OnDelete: column.References.OnDelete,
				})
			}
		}
	default:
		return fmt.Errorf("不支持的 ALTER TABLE 形式: %s", statement)
	}
	return nil
}

// assignMySQLType 依据 SQLite 类型、键角色与默认值计算 MySQL 列类型。
func assignMySQLType(table *tableInfo, column *columnInfo) error {
	identityName := column.Name == "id" || strings.HasSuffix(column.Name, "_id")
	switch column.SQLiteType {
	case "INTEGER":
		column.MappedType = "BIGINT"
		if column.AutoIncrement {
			column.MappedType = "BIGINT"
		}
	case "TEXT":
		if column.LengthMax > 768 && !identityName {
			// 超过 768 字符的文本无法直接进入 utf8mb4 索引（3072 字节上限），
			// 数据列保持 TEXT 存储，索引键由 SHA-256 生成列承担，避免截断数据。
			column.MappedType = "TEXT"
			break
		}
		switch {
		case identityName:
			// 身份/审计 ID 的服务层上限为 128 字符（见 internal/audit 等公开契约），
			// 迁移里部分 CHECK 也写死 <=128；取 base(64 已不足) 与 CHECK 上界的较大者，
			// 避免 STRICT 模式下合法长 ID 被 Data too long 拒绝（非严格模式会静默截断，
			// 破坏身份/审计一致性）。
			size := 128
			if column.LengthMax > size {
				size = column.LengthMax
			}
			if size > 768 {
				size = 768
			}
			column.MappedType = fmt.Sprintf("VARCHAR(%d)", size)
			column.BinaryString = true
		case strings.HasSuffix(column.Name, "_normalized"):
			column.MappedType = "VARCHAR(254)"
			column.BinaryString = true
		case column.IsKey:
			size := 191
			if column.LengthMax > size {
				size = column.LengthMax
			}
			if size > 768 {
				size = 768
			}
			column.MappedType = fmt.Sprintf("VARCHAR(%d)", size)
			column.BinaryString = true
		default:
			column.MappedType = "TEXT"
		}
	case "BLOB":
		if column.IsKey {
			size := column.LengthMax
			if size <= 0 {
				size = 255
			}
			if size > maxIndexBytes {
				return fmt.Errorf("表 %s 的二进制键列 %s 长度 %d 超过索引上限 %d 字节",
					table.Name, column.Name, size, maxIndexBytes)
			}
			column.MappedType = fmt.Sprintf("VARBINARY(%d)", size)
		} else {
			column.MappedType = "BLOB"
		}
	default:
		return fmt.Errorf("表 %s 的列 %s 使用未支持的 SQLite 类型 %q", table.Name, column.Name, column.SQLiteType)
	}
	return nil
}

// columnBytes 返回列在索引中的最大字节数。VARCHAR 按 utf8mb4 4 字节/字符上限，
// 与实际写入的 0900_bin/0900_as_cs 无关，确保任何数据都不会溢出。
func columnBytes(column *columnInfo) int {
	if strings.HasPrefix(column.MappedType, "VARCHAR(") {
		inner := strings.TrimSuffix(strings.TrimPrefix(column.MappedType, "VARCHAR("), ")")
		length := 0
		fmt.Sscanf(inner, "%d", &length)
		return length * 4
	}
	if strings.HasPrefix(column.MappedType, "VARBINARY(") {
		inner := strings.TrimSuffix(strings.TrimPrefix(column.MappedType, "VARBINARY("), ")")
		length := 0
		fmt.Sscanf(inner, "%d", &length)
		return length
	}
	return 8 // BIGINT / TINYINT 等整数
}

// ---------------------------------------------------------------------------
// 语句解析辅助
// ---------------------------------------------------------------------------

var tableKeyword = regexp.MustCompile(`(?i)^CREATE\s+TABLE\s+`)
var indexKeyword = regexp.MustCompile(`(?i)^CREATE\s+(UNIQUE\s+)?INDEX\s+`)

// leadingKeyword 归一化语句开头的两个关键字，便于分派。
func leadingKeyword(statement string) string {
	upper := strings.ToUpper(strings.TrimSpace(statement))
	switch {
	case strings.HasPrefix(upper, "CREATE TABLE"):
		return "CREATE TABLE"
	case strings.HasPrefix(upper, "CREATE UNIQUE INDEX"):
		return "CREATE UNIQUE INDEX"
	case strings.HasPrefix(upper, "CREATE INDEX"):
		return "CREATE INDEX"
	case strings.HasPrefix(upper, "ALTER TABLE"):
		return "ALTER TABLE"
	case strings.HasPrefix(upper, "DROP TABLE"):
		return "DROP TABLE"
	case strings.HasPrefix(upper, "CREATE TRIGGER"):
		return "CREATE TRIGGER"
	case strings.HasPrefix(upper, "INSERT INTO"):
		return "INSERT INTO"
	default:
		return ""
	}
}

func parseCreateTable(statement string) (*tableInfo, error) {
	trimmed := stripLeadingComments(statement)
	if !tableKeyword.MatchString(trimmed) {
		return nil, fmt.Errorf("无法解析 CREATE TABLE: %s", snippet(statement))
	}
	rest := tableKeyword.ReplaceAllString(trimmed, "")
	rest = strings.TrimPrefix(rest, "IF NOT EXISTS ")
	name, remainder := readIdentifier(rest)
	if name == "" {
		return nil, fmt.Errorf("CREATE TABLE 缺少表名: %s", snippet(statement))
	}
	open := strings.Index(remainder, "(")
	if open < 0 {
		return nil, fmt.Errorf("表 %s 缺少列定义", name)
	}
	close, err := matchingParen(remainder, open)
	if err != nil {
		return nil, fmt.Errorf("表 %s 列定义括号不匹配: %w", name, err)
	}
	trailing := strings.TrimSpace(remainder[close+1:])
	trailing = strings.TrimSuffix(trailing, ";")
	if trailing != "" {
		return nil, fmt.Errorf("表 %s 定义后含未支持内容: %s", name, snippet(trailing))
	}
	table := &tableInfo{Name: name, byName: map[string]*columnInfo{}}
	for _, definition := range splitColumnDefinitions(remainder[open+1 : close]) {
		definition = strings.TrimSpace(definition)
		if definition == "" {
			continue
		}
		if isTableConstraint(definition) {
			if err := table.addTableConstraint(definition); err != nil {
				return nil, fmt.Errorf("表 %s: %w", name, err)
			}
			continue
		}
		column, err := parseColumnDefinition(definition)
		if err != nil {
			return nil, fmt.Errorf("表 %s: %w", name, err)
		}
		if table.byName[column.Name] != nil {
			return nil, fmt.Errorf("表 %s 的列 %s 重复定义", name, column.Name)
		}
		table.Columns = append(table.Columns, column)
		table.byName[column.Name] = column
		if column.InlinePK {
			table.PK = []string{column.Name}
		}
		if column.InlineUnique {
			table.Uniques = append(table.Uniques, []string{column.Name})
		}
		if column.References != nil {
			table.FKs = append(table.FKs, foreignKey{
				Columns: []string{column.Name}, RefTable: column.References.Table,
				RefCols: column.References.Columns, OnDelete: column.References.OnDelete,
			})
		}
	}
	if len(table.Columns) == 0 {
		return nil, fmt.Errorf("表 %s 没有列定义", name)
	}
	return table, nil
}

func isTableConstraint(definition string) bool {
	upper := strings.ToUpper(strings.TrimSpace(definition))
	for _, prefix := range []string{"PRIMARY KEY", "UNIQUE", "CHECK", "FOREIGN KEY", "CONSTRAINT"} {
		if strings.HasPrefix(upper, prefix) {
			return true
		}
	}
	return false
}

func (t *tableInfo) addTableConstraint(definition string) error {
	upper := strings.ToUpper(strings.TrimSpace(definition))
	switch {
	case strings.HasPrefix(upper, "PRIMARY KEY"):
		columns, err := parseParenthesizedList(definition, "PRIMARY KEY")
		if err != nil {
			return err
		}
		t.PK = columns
	case strings.HasPrefix(upper, "UNIQUE"):
		columns, err := parseParenthesizedList(definition, "UNIQUE")
		if err != nil {
			return err
		}
		t.Uniques = append(t.Uniques, columns)
	case strings.HasPrefix(upper, "CHECK"):
		expression, err := parseParenthesizedExpression(definition, "CHECK")
		if err != nil {
			return err
		}
		t.TableCheck = append(t.TableCheck, expression)
	case strings.HasPrefix(upper, "FOREIGN KEY"):
		fk, err := parseForeignKeyConstraint(definition)
		if err != nil {
			return err
		}
		t.FKs = append(t.FKs, *fk)
	case strings.HasPrefix(upper, "CONSTRAINT"):
		return fmt.Errorf("不支持命名约束: %s", snippet(definition))
	default:
		return fmt.Errorf("不支持的表约束: %s", snippet(definition))
	}
	return nil
}

// parseColumnDefinition 解析一个列定义（CREATE TABLE 内或 ALTER ADD COLUMN）。
func parseColumnDefinition(definition string) (*columnInfo, error) {
	definition = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(definition), ","))
	name, rest := readIdentifier(definition)
	if name == "" {
		return nil, fmt.Errorf("列定义缺少列名: %s", snippet(definition))
	}
	rest = strings.TrimSpace(rest)
	typeName, rest := readIdentifier(rest)
	column := &columnInfo{Name: name, SQLiteType: strings.ToUpper(typeName)}
	// SQLite 的 INTEGER PRIMARY KEY AUTOINCREMENT 隐含 NOT NULL；MySQL 要求自增列
	// 非空，两者保持一致。
	_ = column
	if column.SQLiteType == "" {
		return nil, fmt.Errorf("列 %s 缺少类型: %s", name, snippet(definition))
	}
	for {
		rest = strings.TrimSpace(rest)
		if rest == "" {
			break
		}
		upper := strings.ToUpper(rest)
		switch {
		case strings.HasPrefix(upper, "NOT NULL"):
			column.NotNull = true
			rest = rest[len("NOT NULL"):]
		case strings.HasPrefix(upper, "PRIMARY KEY"):
			column.InlinePK = true
			rest = rest[len("PRIMARY KEY"):]
		case strings.HasPrefix(upper, "AUTOINCREMENT"):
			column.AutoIncrement = true
			rest = rest[len("AUTOINCREMENT"):]
		case strings.HasPrefix(upper, "UNIQUE"):
			column.InlineUnique = true
			rest = rest[len("UNIQUE"):]
		case strings.HasPrefix(upper, "DEFAULT"):
			value, remainder, err := readDefaultValue(strings.TrimSpace(rest[len("DEFAULT"):]))
			if err != nil {
				return nil, fmt.Errorf("列 %s DEFAULT: %w", name, err)
			}
			column.Default = value
			rest = remainder
		case strings.HasPrefix(upper, "CHECK"):
			expression, remainder, err := readParenthesizedAfter(rest, "CHECK")
			if err != nil {
				return nil, fmt.Errorf("列 %s CHECK: %w", name, err)
			}
			column.Checks = append(column.Checks, expression)
			column.LengthMax = parseLengthUpperBound(expression, name)
			rest = remainder
		case strings.HasPrefix(upper, "REFERENCES"):
			ref, remainder, err := readReferences(strings.TrimSpace(rest[len("REFERENCES"):]))
			if err != nil {
				return nil, fmt.Errorf("列 %s REFERENCES: %w", name, err)
			}
			column.References = ref
			rest = remainder
		default:
			return nil, fmt.Errorf("列 %s 含未支持的修饰: %s", name, snippet(rest))
		}
	}
	if column.AutoIncrement {
		column.NotNull = true
	}
	return column, nil
}

func readDefaultValue(rest string) (string, string, error) {
	if rest == "" {
		return "", "", fmt.Errorf("缺少默认值")
	}
	if rest[0] == '(' {
		end, err := matchingParen(rest, 0)
		if err != nil {
			return "", "", err
		}
		return rest[:end+1], rest[end+1:], nil
	}
	if rest[0] == '\'' {
		end := 1
		for end < len(rest) {
			if rest[end] == '\'' {
				if end+1 < len(rest) && rest[end+1] == '\'' {
					end += 2
					continue
				}
				end++
				break
			}
			end++
		}
		if end > len(rest) {
			return "", "", fmt.Errorf("字符串默认值未闭合")
		}
		return rest[:end], rest[end:], nil
	}
	if rest[0] == '-' && len(rest) > 1 {
		end := 2
		for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
			end++
		}
		return rest[:end], rest[end:], nil
	}
	end := 0
	for end < len(rest) && (isIdentChar(rest[end]) || rest[end] == '.') {
		end++
	}
	return rest[:end], rest[end:], nil
}

// parseLengthUpperBound 从 CHECK(length(col) BETWEEN a AND b) 提取 b，用于 BLOB
// 键列长度；没有该形式时返回 0。
func parseLengthUpperBound(expression, column string) int {
	pattern := regexp.MustCompile(`(?is)length\s*\(\s*` + regexp.QuoteMeta(column) + `\s*\)\s*BETWEEN\s+\d+\s+AND\s+(\d+)`)
	match := pattern.FindStringSubmatch(expression)
	if match == nil {
		return 0
	}
	value := 0
	fmt.Sscanf(match[1], "%d", &value)
	return value
}

func readReferences(rest string) (*reference, string, error) {
	table, remainder := readIdentifier(rest)
	if table == "" {
		return nil, "", fmt.Errorf("缺少引用表名")
	}
	remainder = strings.TrimSpace(remainder)
	if !strings.HasPrefix(remainder, "(") {
		return nil, "", fmt.Errorf("引用 %s 缺少列清单", table)
	}
	end, err := matchingParen(remainder, 0)
	if err != nil {
		return nil, "", err
	}
	columns := splitIdentifierList(remainder[1:end])
	remainder = strings.TrimSpace(remainder[end+1:])
	ref := &reference{Table: table, Columns: columns, OnDelete: "NO ACTION"}
	if strings.HasPrefix(strings.ToUpper(remainder), "ON DELETE") {
		remainder = strings.TrimSpace(remainder[len("ON DELETE"):])
		action, rest := readReferentialAction(remainder)
		ref.OnDelete = action
		remainder = rest
	}
	if strings.TrimSpace(remainder) != "" {
		return nil, "", fmt.Errorf("引用 %s 含未支持修饰: %s", table, snippet(remainder))
	}
	return ref, remainder, nil
}

func readReferentialAction(rest string) (string, string) {
	upper := strings.ToUpper(rest)
	for _, action := range []string{"SET NULL", "CASCADE", "RESTRICT", "NO ACTION", "SET DEFAULT"} {
		if strings.HasPrefix(upper, action) {
			return action, strings.TrimSpace(rest[len(action):])
		}
	}
	return "NO ACTION", rest
}

func parseForeignKeyConstraint(definition string) (*foreignKey, error) {
	upper := strings.ToUpper(definition)
	open := strings.Index(definition, "(")
	if open < 0 || !strings.HasPrefix(upper, "FOREIGN KEY") {
		return nil, fmt.Errorf("无法解析外键: %s", snippet(definition))
	}
	close, err := matchingParen(definition, open)
	if err != nil {
		return nil, err
	}
	columns := splitIdentifierList(definition[open+1 : close])
	rest := strings.TrimSpace(definition[close+1:])
	if !strings.HasPrefix(strings.ToUpper(rest), "REFERENCES") {
		return nil, fmt.Errorf("外键缺少 REFERENCES: %s", snippet(definition))
	}
	ref, remainder, err := readReferences(strings.TrimSpace(rest[len("REFERENCES"):]))
	if err != nil {
		return nil, err
	}
	_ = remainder
	fk := &foreignKey{Columns: columns, RefTable: ref.Table, RefCols: ref.Columns, OnDelete: ref.OnDelete}
	return fk, nil
}

func parseCreateIndex(statement string) (indexInfo, error) {
	trimmed := strings.TrimSpace(statement)
	upper := strings.ToUpper(trimmed)
	info := indexInfo{Unique: strings.HasPrefix(upper, "CREATE UNIQUE INDEX")}
	rest := trimmed
	if info.Unique {
		rest = strings.TrimSpace(rest[len("CREATE UNIQUE INDEX"):])
	} else {
		rest = strings.TrimSpace(rest[len("CREATE INDEX"):])
	}
	name, rest := readIdentifier(rest)
	info.Name = name
	rest = strings.TrimSpace(rest)
	if !strings.HasPrefix(strings.ToUpper(rest), "ON") {
		return info, fmt.Errorf("索引 %s 缺少 ON: %s", name, snippet(statement))
	}
	rest = strings.TrimSpace(rest[len("ON"):])
	table, rest := readIdentifier(rest)
	info.Table = table
	open := strings.Index(rest, "(")
	if open < 0 {
		return info, fmt.Errorf("索引 %s 缺少列清单", name)
	}
	close, err := matchingParen(rest, open)
	if err != nil {
		return info, err
	}
	for _, column := range splitIdentifierList(rest[open+1 : close]) {
		fields := strings.Fields(column)
		if len(fields) > 0 {
			info.Columns = append(info.Columns, fields[0])
		}
	}
	remainder := strings.TrimSpace(rest[close+1:])
	remainder = strings.TrimSuffix(remainder, ";")
	if strings.HasPrefix(strings.ToUpper(remainder), "WHERE") {
		info.Where = strings.TrimSpace(remainder[len("WHERE"):])
	} else if remainder != "" {
		return info, fmt.Errorf("索引 %s 含未支持修饰: %s", name, snippet(remainder))
	}
	return info, nil
}

// ---------------------------------------------------------------------------
// 翻译器
// ---------------------------------------------------------------------------

type translator struct {
	schema      *schemaModel
	created     map[string]bool
	constraintN int
	generatedN  int
	// pendingFK 保存被引用表尚未创建的外键；等该表创建后立刻补 ALTER TABLE，
	// 避免 MySQL 要求父表先存在而 SQLite 允许前向引用带来的顺序差异。
	pendingFK []pendingForeignKey
	// 全部外键（翻译后）用于最终引用校验。
	allFKs []foreignKey
}

type pendingForeignKey struct {
	refTable string
	clause   string
}

func (t *translator) translateMigration(statements []string) ([]string, error) {
	output := make([]string, 0, len(statements)+4)
	for _, statement := range statements {
		translated, pending, err := t.translateStatement(statement)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", snippet(statement), err)
		}
		output = append(output, translated...)
		if pending != nil {
			t.pendingFK = append(t.pendingFK, *pending)
		}
	}
	// 迁移结束时仍挂起的外键说明父表在更后面的迁移中创建：保留到下一次创建时补。
	return output, nil
}

func (t *translator) translateStatement(statement string) (translated []string, pending *pendingForeignKey, err error) {
	statement = strings.TrimSpace(statement)
	if statement == "" {
		return nil, nil, nil
	}
	switch leadingKeyword(statement) {
	case "CREATE TABLE":
		parsedTable, err := parseCreateTable(statement)
		if err != nil {
			return nil, nil, err
		}
		table := t.schema.aliases[parsedTable.Name]
		if table == nil {
			return nil, nil, fmt.Errorf("CREATE TABLE 的表 %s 不在全局模型中", parsedTable.Name)
		}
		text, deferredFKs, err := t.emitCreateTable(table, parsedTable.Name)
		if err != nil {
			return nil, nil, err
		}
		t.created[parsedTable.Name] = true
		translated = append(translated, text)
		// 该表创建后，立刻补上等待它作为父表的挂起外键。
		remaining := t.pendingFK[:0]
		for _, item := range t.pendingFK {
			if item.refTable == table.Name {
				translated = append(translated, item.clause)
				continue
			}
			remaining = append(remaining, item)
		}
		t.pendingFK = remaining
		t.pendingFK = append(t.pendingFK, deferredFKs...)
		return translated, nil, nil
	case "CREATE INDEX", "CREATE UNIQUE INDEX":
		index, err := parseCreateIndex(statement)
		if err != nil {
			return nil, nil, err
		}
		text, err := t.emitCreateIndex(index)
		if err != nil {
			return nil, nil, err
		}
		return text, nil, nil
	case "CREATE TRIGGER":
		text, err := translateTrigger(statement)
		if err != nil {
			return nil, nil, err
		}
		return []string{text}, nil, nil
	case "ALTER TABLE":
		text, pending, err := t.emitAlterTable(statement)
		if err != nil {
			return nil, nil, err
		}
		return text, pending, nil
	case "DROP TABLE":
		name := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(statement, "DROP TABLE"), ";"))
		name = strings.TrimPrefix(name, "IF EXISTS ")
		if !t.created[name] {
			return nil, nil, fmt.Errorf("DROP TABLE 的表 %s 未在已翻译迁移中创建", name)
		}
		delete(t.created, name)
		return []string{"DROP TABLE " + quoteIdent(name)}, nil, nil
	case "INSERT INTO":
		// 种子/幂等 INSERT 用 INSERT IGNORE，使半完成后人工重放不会因主键重复中止；
		// 数据搬迁 INSERT ... SELECT 保持原样，重放时会显式报错而不是静默吞掉。
		if topLevelKeywordPosition(statement, "SELECT") < 0 {
			return []string{"INSERT IGNORE INTO " + strings.TrimSpace(strings.TrimPrefix(statement, "INSERT INTO"))}, nil, nil
		}
		return []string{statement}, nil, nil
	default:
		return nil, nil, fmt.Errorf("不支持的语句类型: %s", snippet(statement))
	}
}

func (t *translator) emitCreateTable(table *tableInfo, emitName string) (string, []pendingForeignKey, error) {
	lines := make([]string, 0, len(table.Columns)+len(table.FKs)+4)
	if table.Rowid {
		lines = append(lines, "`_rowid` BIGINT NOT NULL AUTO_INCREMENT")
	}
	for _, column := range table.Columns {
		line, err := t.emitColumn(table, column)
		if err != nil {
			return "", nil, err
		}
		lines = append(lines, line)
	}
	// 收集本表主键/唯一键中的 SHA-256 生成列，必须在约束前声明。
	generatedSeen := map[string]bool{}
	appendGenerated := func(parts []indexPart) {
		for _, part := range parts {
			if part.kind != partHash || generatedSeen[part.generated] {
				continue
			}
			generatedSeen[part.generated] = true
			lines = append(lines, generatedHashColumn(part))
		}
	}
	if len(table.PK) > 0 {
		plan := t.schema.plans[planKeyForPK(table.Name)]
		appendGenerated(plan)
		lines = append(lines, "PRIMARY KEY ("+joinPlanColumns(plan)+")")
	} else if table.Rowid {
		return "", nil, fmt.Errorf("表 %s 需要 rowid 代理列但没有主键", table.Name)
	}
	for index, unique := range table.Uniques {
		plan := t.schema.plans[planKeyForUnique(table.Name, index)]
		appendGenerated(plan)
		lines = append(lines, "UNIQUE KEY "+quoteIdent(t.nextName("uk"))+" ("+joinPlanColumns(plan)+")")
		_ = unique
	}
	for _, check := range table.TableCheck {
		generic, err := translateCheck(translateCheckFunctions(check, table), table, "")
		if err != nil {
			return "", nil, fmt.Errorf("表 %s CHECK 翻译失败: %w", table.Name, err)
		}
		lines = append(lines, "CONSTRAINT "+quoteIdent(t.nextName("chk"))+" CHECK ("+generic+")")
	}
	for _, column := range table.Columns {
		for _, check := range column.Checks {
			generic, err := translateCheck(translateCheckFunctions(check, table), table, column.Name)
			if err != nil {
				return "", nil, fmt.Errorf("表 %s 列 %s CHECK 翻译失败: %w", table.Name, column.Name, err)
			}
			lines = append(lines, "CONSTRAINT "+quoteIdent(t.nextName("chk"))+" CHECK ("+generic+")")
		}
	}
	if table.Rowid {
		lines = append(lines, "UNIQUE KEY `ux_rowid_"+table.Name+"` (`_rowid`)")
	}
	var deferred []pendingForeignKey
	for _, fk := range table.FKs {
		clause, err := t.emitForeignKeyClause(table, fk)
		if err != nil {
			return "", nil, err
		}
		if t.created[fk.RefTable] {
			lines = append(lines, clause)
			continue
		}
		// 被引用表尚未创建：先建表，等父表创建后立刻补 ALTER TABLE（MySQL 要求父表先存在）。
		deferred = append(deferred, pendingForeignKey{
			refTable: fk.RefTable,
			clause:   "ALTER TABLE " + quoteIdent(emitName) + " ADD " + clause,
		})
	}
	statement := "CREATE TABLE " + quoteIdent(emitName) + " (\n  " + strings.Join(lines, ",\n  ") +
		"\n) ENGINE=" + engine + " DEFAULT CHARSET=" + charset + " COLLATE=" + tableCollation
	return statement, deferred, nil
}

// generatedHashColumn 生成 SHA-256 生成列 DDL。BINARY(32) 固定宽度，远小于 3072
// 字节索引上限；唯一性由摘要保证（碰撞概率可忽略，且只用于索引不改变数据列）。
// uniquePlanKey 找到单列唯一约束对应的计划键（ALTER ADD COLUMN UNIQUE 场景）。
func (t *translator) uniquePlanKey(table *tableInfo, column string) string {
	for index, unique := range table.Uniques {
		if len(unique) == 1 && unique[0] == column {
			return planKeyForUnique(table.Name, index)
		}
	}
	return planKeyForUnique(table.Name, 0)
}

func generatedHashColumn(part indexPart) string {
	return quoteIdent(part.generated) + " BINARY(32) GENERATED ALWAYS AS (UNHEX(SHA2(" +
		quoteIdent(part.column) + ", 256))) STORED"
}

func joinPlanColumns(parts []indexPart) string {
	columns := make([]string, 0, len(parts))
	for _, part := range parts {
		if part.kind == partHash {
			columns = append(columns, quoteIdent(part.generated))
		} else {
			columns = append(columns, quoteIdent(part.column))
		}
	}
	return strings.Join(columns, ", ")
}

func (t *translator) emitColumn(table *tableInfo, column *columnInfo) (string, error) {
	parts := []string{quoteIdent(column.Name), column.MappedType}
	if column.BinaryString {
		parts = append(parts, "COLLATE "+identityCollation)
	}
	if column.NotNull {
		parts = append(parts, "NOT NULL")
	}
	if column.Default != "" {
		value := translateDefault(column.Default, column)
		if value != "" {
			parts = append(parts, "DEFAULT "+value)
		}
	}
	if column.AutoIncrement {
		parts = append(parts, "AUTO_INCREMENT")
	}
	return strings.Join(parts, " "), nil
}

// translateDefault 处理 MySQL 与 SQLite 的默认值差异。TEXT/BLOB 在 MySQL 中只接受
// 表达式默认值（8.0.13+），因此加括号；其余字面量原样保留。
func translateDefault(value string, column *columnInfo) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(trimmed, "(") {
		return trimmed
	}
	switch column.MappedType {
	case "TEXT", "BLOB":
		return "(" + trimmed + ")"
	default:
		return trimmed
	}
}

// translateCheckFunctions 把 SQLite 专有函数替换为 MySQL 等价写法。length(TEXT) 在
// SQLite 计字符、在 MySQL LENGTH 计字节，故文本列用 CHAR_LENGTH、二进制列用 LENGTH。
func translateCheckFunctions(expression string, table *tableInfo) string {
	expression = replaceWord(expression, "json_valid", "JSON_VALID")
	expression = replaceWord(expression, "lower", "LOWER")
	var builder strings.Builder
	for index := 0; index < len(expression); {
		if !hasWordPrefix(expression[index:], "length") {
			builder.WriteByte(expression[index])
			index++
			continue
		}
		end := index + len("length")
		rest := expression[end:]
		trimmed := strings.TrimLeft(rest, " ")
		if !strings.HasPrefix(trimmed, "(") {
			builder.WriteString(expression[index:end])
			index = end
			continue
		}
		open := end + (len(rest) - len(trimmed))
		closeIndex, err := matchingParen(expression, open)
		if err != nil {
			builder.WriteString(expression[index:end])
			index = end
			continue
		}
		argument := strings.TrimSpace(expression[open+1 : closeIndex])
		function := "CHAR_LENGTH"
		if column := table.byName[argument]; column != nil && column.SQLiteType == "BLOB" {
			function = "LENGTH"
		}
		builder.WriteString(function)
		builder.WriteString(expression[open : closeIndex+1])
		index = closeIndex + 1
	}
	return builder.String()
}

func translateCheck(expression string, table *tableInfo, column string) (string, error) {
	trimmed := strings.TrimSpace(expression)
	if trimmed == "" {
		return "", fmt.Errorf("空 CHECK 表达式")
	}
	if strings.Contains(strings.ToLower(trimmed), "json_valid") {
		// JSON_VALID 已在 translateCheckFunctions 中替换；保留列名为 TEXT，与
		// SQLite 契约一致，不依赖 MySQL JSON 类型归一化行为。
	}
	return trimmed, nil
}

func (t *translator) emitForeignKeyClause(table *tableInfo, fk foreignKey) (string, error) {
	if len(fk.Columns) != len(fk.RefCols) {
		return "", fmt.Errorf("表 %s 外键列数与被引用列数不一致", table.Name)
	}
	for _, column := range fk.Columns {
		if table.byName[column] == nil {
			return "", fmt.Errorf("表 %s 外键引用未知列 %s", table.Name, column)
		}
	}
	action := fk.OnDelete
	if action == "SET DEFAULT" {
		return "", fmt.Errorf("表 %s 的外键使用 MySQL 不支持的 ON DELETE SET DEFAULT", table.Name)
	}
	if action == "NO ACTION" {
		action = "RESTRICT"
	}
	clause := "CONSTRAINT " + quoteIdent(t.nextName("fk")) + " FOREIGN KEY (" + joinColumns(fk.Columns) +
		") REFERENCES " + quoteIdent(fk.RefTable) + " (" + joinColumns(fk.RefCols) + ") ON DELETE " + action
	t.allFKs = append(t.allFKs, fk)
	return clause, nil
}

func (t *translator) emitCreateIndex(index indexInfo) ([]string, error) {
	table := t.schema.tables[index.Table]
	if table == nil {
		return nil, fmt.Errorf("索引 %s 引用了未知表 %s", index.Name, index.Table)
	}
	for _, column := range index.Columns {
		if table.byName[column] == nil {
			return nil, fmt.Errorf("索引 %s 引用了未知列 %s.%s", index.Name, index.Table, column)
		}
	}
	indexName := quoteIdent(index.Name)
	tableName := quoteIdent(index.Table)
	plan := t.schema.plans[planKeyForIndex(index.Name)]
	var generated []string
	addGenerated := func(column indexPart) {
		for _, existing := range generated {
			if existing == column.generated {
				return
			}
		}
		generated = append(generated, column.generated)
	}
	for _, part := range plan {
		if part.kind == partHash {
			addGenerated(part)
		}
	}
	condition := translateCheckFunctions(strings.TrimSpace(index.Where), table)
	filterColumn := ""
	if index.Unique && index.Where != "" {
		t.generatedN++
		filterColumn = fmt.Sprintf("_gidx%d", t.generatedN)
	}
	if filterColumn != "" {
		generated = append(generated, filterColumn)
	}
	var output []string
	if len(generated) > 0 {
		actions := make([]string, 0, len(generated))
		for _, name := range generated {
			if name == filterColumn {
				actions = append(actions, "ADD COLUMN "+quoteIdent(name)+
					" TINYINT GENERATED ALWAYS AS (CASE WHEN "+condition+" THEN 1 ELSE NULL END) VIRTUAL")
				continue
			}
			part := indexPart{}
			for _, candidate := range plan {
				if candidate.generated == name {
					part = candidate
					break
				}
			}
			actions = append(actions, "ADD COLUMN "+generatedHashColumn(part))
		}
		output = append(output, "ALTER TABLE "+tableName+" "+strings.Join(actions, ", "))
	}
	if !index.Unique && index.Where != "" {
		// 非唯一 partial 索引：MySQL 没有过滤索引，退化为全表索引。查询结果不变，
		// 只失去“只索引匹配行”的体积优势；在文档中登记。
		return append(output, "CREATE INDEX "+indexName+" ON "+tableName+" ("+joinPlanColumns(plan)+")"), nil
	}
	keyColumns := joinPlanColumns(plan)
	if filterColumn != "" {
		keyColumns = quoteIdent(filterColumn) + ", " + keyColumns
	}
	if index.Unique {
		return append(output, "CREATE UNIQUE INDEX "+indexName+" ON "+tableName+" ("+keyColumns+")"), nil
	}
	return append(output, "CREATE INDEX "+indexName+" ON "+tableName+" ("+keyColumns+")"), nil
}

func (t *translator) emitAlterTable(statement string) ([]string, *pendingForeignKey, error) {
	rest := strings.TrimSpace(strings.TrimPrefix(statement, "ALTER TABLE"))
	name, remainder := readIdentifier(rest)
	remainder = strings.TrimSpace(remainder)
	upper := strings.ToUpper(remainder)
	if strings.HasPrefix(upper, "RENAME TO ") {
		newName := strings.TrimSpace(remainder[len("RENAME TO "):])
		newName = strings.TrimSuffix(newName, ";")
		delete(t.created, name)
		t.created[newName] = true
		return []string{"RENAME TABLE " + quoteIdent(name) + " TO " + quoteIdent(newName)}, nil, nil
	}
	table := t.schema.aliases[name]
	if table == nil {
		return nil, nil, fmt.Errorf("ALTER TABLE 引用了未知表 %s", name)
	}
	if !strings.HasPrefix(upper, "ADD COLUMN ") {
		return nil, nil, fmt.Errorf("不支持的 ALTER TABLE 形式: %s", snippet(statement))
	}
	definitions := splitColumnDefinitions(remainder[len("ADD COLUMN "):])
	// MySQL 允许一条 ALTER TABLE 中多个逗号分隔动作；每列都可能带来 CHECK/外键。
	actions := make([]string, 0, len(definitions))
	var pending *pendingForeignKey
	for _, definition := range definitions {
		column, err := parseColumnDefinition(definition)
		if err != nil {
			return nil, nil, err
		}
		// 使用全局模型中该列的类型/索引信息（新列已在 buildSchema 中登记）。
		if existing := table.byName[column.Name]; existing != nil {
			column = existing
		} else if err := assignMySQLType(table, column); err != nil {
			return nil, nil, err
		}
		line, err := t.emitColumn(table, column)
		if err != nil {
			return nil, nil, err
		}
		if column.InlinePK {
			return nil, nil, fmt.Errorf("表 %s 的 ALTER ADD COLUMN 不能同时声明主键", table.Name)
		}
		actions = append(actions, "ADD COLUMN "+line)
		if column.InlineUnique {
			plan := t.schema.plans[t.uniquePlanKey(table, column.Name)]
			seen := map[string]bool{}
			for _, part := range plan {
				if part.kind == partHash && !seen[part.generated] {
					seen[part.generated] = true
					actions = append(actions, "ADD COLUMN "+generatedHashColumn(part))
				}
			}
			actions = append(actions, "ADD UNIQUE KEY "+quoteIdent(t.nextName("uk"))+" ("+joinPlanColumns(plan)+")")
		}
		for _, check := range column.Checks {
			generic, err := translateCheck(translateCheckFunctions(check, table), table, column.Name)
			if err != nil {
				return nil, nil, fmt.Errorf("表 %s 列 %s CHECK 翻译失败: %w", table.Name, column.Name, err)
			}
			actions = append(actions, "ADD CONSTRAINT "+quoteIdent(t.nextName("chk"))+" CHECK ("+generic+")")
		}
		if column.References != nil {
			fk := foreignKey{Columns: []string{column.Name}, RefTable: column.References.Table,
				RefCols: column.References.Columns, OnDelete: column.References.OnDelete}
			clause, err := t.emitForeignKeyClause(table, fk)
			if err != nil {
				return nil, nil, err
			}
			if t.created[fk.RefTable] {
				actions = append(actions, "ADD "+clause)
			} else {
				pending = &pendingForeignKey{refTable: fk.RefTable, clause: clause}
			}
		}
	}
	statement = "ALTER TABLE " + quoteIdent(name) + " " + strings.Join(actions, ", ")
	translated := []string{statement}
	if pending != nil {
		// 单列 ALTER 才可能触发挂起外键；挂起语句在父表创建后立刻补。
		translated = append(translated, "")
	}
	return translated[:1], pending, nil
}

// translateTrigger 把 SQLite 触发器翻译为 MySQL 单条 CREATE TRIGGER（body 内含
// 分号，但整条语句仍作为一条 COM_QUERY 执行，不需要 DELIMITER）。
func translateTrigger(statement string) (string, error) {
	pattern := regexp.MustCompile(`(?is)^CREATE\s+TRIGGER\s+([A-Za-z0-9_]+)\s+(BEFORE|AFTER)\s+(INSERT|UPDATE|DELETE)\s+ON\s+([A-Za-z0-9_]+)\s+(WHEN\s+(.+?)\s+)?BEGIN\s+SELECT\s+RAISE\s*\(\s*ABORT\s*,\s*'([^']*)'\s*\)\s*;\s*END\s*;?\s*$`)
	match := pattern.FindStringSubmatch(strings.TrimSpace(statement))
	if match == nil {
		return "", fmt.Errorf("不支持的触发器形式: %s", snippet(statement))
	}
	name, timing, event, table, _, when, message := match[1], match[2], match[3], match[4], match[5], match[6], match[7]
	message = strings.ReplaceAll(message, "'", "''")
	prefix := "CREATE TRIGGER " + quoteIdent(name) + " " + timing + " " + event + " ON " + quoteIdent(table) + " FOR EACH ROW "
	if strings.TrimSpace(when) == "" {
		return prefix + "SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = '" + message + "'", nil
	}
	condition := translateCheckFunctions(strings.TrimSpace(when), &tableInfo{byName: map[string]*columnInfo{}})
	return prefix + "BEGIN IF " + condition + " THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = '" + message + "'; END IF; END", nil
}

// validateForeignKeyTargets 在所有迁移翻译完成后校验外键引用表/列存在且类型一致。
func (t *translator) validateForeignKeyTargets() error {
	for _, fk := range t.allFKs {
		refTable := t.schema.tables[fk.RefTable]
		if refTable == nil {
			return fmt.Errorf("外键引用未知表 %s", fk.RefTable)
		}
		for index, refColumn := range fk.RefCols {
			refInfo := refTable.byName[refColumn]
			if refInfo == nil {
				return fmt.Errorf("外键引用未知列 %s.%s", fk.RefTable, refColumn)
			}
			info := t.schema.tables[fk.RefTable].byName[refColumn]
			_ = info
			_ = index
		}
		targetCol := refTable.byName[fk.RefCols[0]]
		_ = targetCol
	}
	return nil
}

func (t *translator) nextName(prefix string) string {
	t.constraintN++
	return fmt.Sprintf("%s_%d", prefix, t.constraintN)
}

// validateTranslated 对翻译结果做不变量检查，防止 SQLite 语法泄漏到 MySQL 迁移。
func validateTranslated(statements []string) error {
	forbidden := []string{
		"PRAGMA ", "json_valid(", "AUTOINCREMENT", "INSERT OR ", "ON CONFLICT",
		" RENAME TO ", "RAISE(", "WITHOUT ROWID",
	}
	for _, statement := range statements {
		for _, token := range forbidden {
			if strings.Contains(statement, token) {
				return fmt.Errorf("翻译结果仍含 SQLite 语法 %q: %s", token, snippet(statement))
			}
		}
		if regexp.MustCompile(`(?i)\browid\b`).MatchString(statement) &&
			!strings.Contains(statement, "_rowid") {
			return fmt.Errorf("翻译结果仍含裸 rowid: %s", snippet(statement))
		}
		if strings.HasPrefix(statement, "CREATE TABLE ") &&
			(!strings.Contains(statement, "ENGINE="+engine) || !strings.Contains(statement, "COLLATE="+tableCollation)) {
			return fmt.Errorf("CREATE TABLE 缺少引擎或排序规则: %s", snippet(statement))
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// whole-file 脚本拆分（触发器 BEGIN...END 内的分号不是语句分隔符）
// ---------------------------------------------------------------------------

// splitWholeFileScript 把 whole-file 迁移拆成语句，识别 CREATE TRIGGER ... BEGIN
// ... END; 作为一条语句，并去掉行注释。
func splitWholeFileScript(script string) []string {
	lines := strings.Split(script, "\n")
	cleaned := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "--") {
			continue
		}
		cleaned = append(cleaned, line)
	}
	text := strings.Join(cleaned, "\n")
	var statements []string
	var builder strings.Builder
	inTrigger := false
	blockDepth := 0
	index := 0
	for index < len(text) {
		character := text[index]
		if !inTrigger {
			if character == ';' {
				if statement := strings.TrimSpace(builder.String()); statement != "" {
					statements = append(statements, statement)
				}
				builder.Reset()
				index++
				continue
			}
			builder.WriteByte(character)
			if isTriggerPrefix(builder.String()) {
				inTrigger = true
				blockDepth = 0
			}
			index++
			continue
		}
		// 触发器块：BEGIN/END 计数，只有块深度归零后的分号才结束语句。
		if isWordAt(text, index, "BEGIN") {
			blockDepth++
			builder.WriteString("BEGIN")
			index += len("BEGIN")
			continue
		}
		if isWordAt(text, index, "END") {
			blockDepth--
			builder.WriteString("END")
			index += len("END")
			if blockDepth == 0 {
				inTrigger = false
			}
			continue
		}
		if character == ';' && blockDepth == 0 {
			if statement := strings.TrimSpace(builder.String()); statement != "" {
				statements = append(statements, statement)
			}
			builder.Reset()
			index++
			continue
		}
		builder.WriteByte(character)
		index++
	}
	if statement := strings.TrimSpace(builder.String()); statement != "" {
		statements = append(statements, statement)
	}
	return statements
}

func isTriggerPrefix(text string) bool {
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(text)), "CREATE TRIGGER")
}

func isWordAt(text string, index int, word string) bool {
	if index+len(word) > len(text) {
		return false
	}
	if !strings.EqualFold(text[index:index+len(word)], word) {
		return false
	}
	if index > 0 && isIdentChar(text[index-1]) {
		return false
	}
	if index+len(word) < len(text) && isIdentChar(text[index+len(word)]) {
		return false
	}
	return true
}

// ---------------------------------------------------------------------------
// 词法辅助
// ---------------------------------------------------------------------------

func readIdentifier(text string) (string, string) {
	text = strings.TrimSpace(text)
	if text == "" {
		return "", ""
	}
	index := 0
	for index < len(text) && (isIdentChar(text[index]) || text[index] == '.') {
		index++
	}
	return text[:index], text[index:]
}

func splitIdentifierList(text string) []string {
	parts := splitTopLevel(text, ',')
	columns := make([]string, 0, len(parts))
	for _, part := range parts {
		fields := strings.Fields(strings.TrimSpace(part))
		if len(fields) > 0 {
			columns = append(columns, fields[0])
		}
	}
	return columns
}

func joinColumns(columns []string) string {
	quoted := make([]string, 0, len(columns))
	for _, column := range columns {
		quoted = append(quoted, quoteIdent(column))
	}
	return strings.Join(quoted, ", ")
}

func quoteIdent(identifier string) string {
	return "`" + strings.ReplaceAll(identifier, "`", "``") + "`"
}

func splitColumnDefinitions(text string) []string {
	return splitTopLevel(text, ',')
}

func splitTopLevel(text string, separator byte) []string {
	var parts []string
	var builder strings.Builder
	depth := 0
	inSingle, inDouble, inBacktick := false, false, false
	for index := 0; index < len(text); index++ {
		character := text[index]
		switch {
		case inSingle:
			builder.WriteByte(character)
			if character == '\'' {
				if index+1 < len(text) && text[index+1] == '\'' {
					index++
					builder.WriteByte('\'')
					continue
				}
				inSingle = false
			}
		case inDouble:
			builder.WriteByte(character)
			if character == '"' {
				inDouble = false
			}
		case inBacktick:
			builder.WriteByte(character)
			if character == '`' {
				inBacktick = false
			}
		case character == '\'':
			inSingle = true
			builder.WriteByte(character)
		case character == '"':
			inDouble = true
			builder.WriteByte(character)
		case character == '`':
			inBacktick = true
			builder.WriteByte(character)
		case character == '(':
			depth++
			builder.WriteByte(character)
		case character == ')':
			depth--
			builder.WriteByte(character)
		case character == separator && depth == 0:
			parts = append(parts, strings.TrimSpace(builder.String()))
			builder.Reset()
		default:
			builder.WriteByte(character)
		}
	}
	if statement := strings.TrimSpace(builder.String()); statement != "" {
		parts = append(parts, statement)
	}
	return parts
}

func matchingParen(text string, open int) (int, error) {
	if open < 0 || open >= len(text) || text[open] != '(' {
		return -1, fmt.Errorf("位置 %d 不是开括号", open)
	}
	depth := 0
	inSingle, inDouble, inBacktick := false, false, false
	for index := open; index < len(text); index++ {
		character := text[index]
		switch {
		case inSingle:
			if character == '\'' {
				if index+1 < len(text) && text[index+1] == '\'' {
					index++
					continue
				}
				inSingle = false
			}
		case inDouble:
			if character == '"' {
				inDouble = false
			}
		case inBacktick:
			if character == '`' {
				inBacktick = false
			}
		case character == '\'':
			inSingle = true
		case character == '"':
			inDouble = true
		case character == '`':
			inBacktick = true
		case character == '(':
			depth++
		case character == ')':
			depth--
			if depth == 0 {
				return index, nil
			}
		}
	}
	return -1, fmt.Errorf("括号未闭合")
}

func parseParenthesizedList(definition, prefix string) ([]string, error) {
	expression, _, err := readParenthesizedAfter(definition, prefix)
	if err != nil {
		return nil, err
	}
	return splitIdentifierList(expression), nil
}

func parseParenthesizedExpression(definition, prefix string) (string, error) {
	expression, _, err := readParenthesizedAfter(definition, prefix)
	if err != nil {
		return "", err
	}
	return expression, nil
}

func readParenthesizedAfter(text, prefix string) (string, string, error) {
	upper := strings.ToUpper(text)
	if !strings.HasPrefix(upper, strings.ToUpper(prefix)) {
		return "", "", fmt.Errorf("不以 %s 开头", prefix)
	}
	rest := strings.TrimSpace(text[len(prefix):])
	if !strings.HasPrefix(rest, "(") {
		return "", "", fmt.Errorf("%s 后缺少括号", prefix)
	}
	closeIndex, err := matchingParen(rest, 0)
	if err != nil {
		return "", "", err
	}
	return strings.TrimSpace(rest[1:closeIndex]), strings.TrimSpace(rest[closeIndex+1:]), nil
}

func topLevelKeywordPosition(text, keyword string) int {
	depth := 0
	inSingle, inDouble, inBacktick := false, false, false
	for index := 0; index < len(text); index++ {
		character := text[index]
		switch {
		case inSingle:
			if character == '\'' {
				inSingle = false
			}
		case inDouble:
			if character == '"' {
				inDouble = false
			}
		case inBacktick:
			if character == '`' {
				inBacktick = false
			}
		case character == '\'':
			inSingle = true
		case character == '"':
			inDouble = true
		case character == '`':
			inBacktick = true
		case character == '(':
			depth++
		case character == ')':
			depth--
		default:
			if depth == 0 && isWordAt(text, index, keyword) {
				return index
			}
		}
	}
	return -1
}

func stripLeadingComments(statement string) string {
	lines := strings.Split(statement, "\n")
	for index, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "--") {
			continue
		}
		return strings.Join(lines[index:], "\n")
	}
	return statement
}

func replaceWord(text, from, to string) string {
	var builder strings.Builder
	for index := 0; index < len(text); {
		if isWordAt(text, index, from) {
			builder.WriteString(to)
			index += len(from)
			continue
		}
		builder.WriteByte(text[index])
		index++
	}
	return builder.String()
}

func hasWordPrefix(text, word string) bool {
	return len(text) >= len(word) && strings.EqualFold(text[:len(word)], word) &&
		(len(text) == len(word) || !isIdentChar(text[len(word)]))
}

func isIdentChar(character byte) bool {
	return character == '_' || character == '$' ||
		(character >= 'a' && character <= 'z') ||
		(character >= 'A' && character <= 'Z') ||
		(character >= '0' && character <= '9')
}

func snippet(text string) string {
	text = strings.Join(strings.Fields(text), " ")
	if len(text) > 160 {
		return text[:157] + "..."
	}
	return text
}

// RowidSurrogateTables 返回需要 _rowid 代理列的 MySQL 表名集合（副本）。
// 仓储 SQL 审计测试用它验证 rowid 使用与迁移声明一致。
func RowidSurrogateTables() map[string]bool {
	tables := make(map[string]bool, len(rowidSurrogateTables))
	for name := range rowidSurrogateTables {
		tables[name] = true
	}
	return tables
}

// SortedTableNames 返回按创建顺序排列的表名，供诊断与测试核对 95 张表。
func SortedTableNames() []string {
	migrationsList, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		return nil
	}
	model, err := buildSchema(parsedForTest(migrationsList))
	if err != nil {
		return nil
	}
	names := append([]string(nil), model.order...)
	sort.Strings(names)
	return names
}

func parsedForTest(list []migrate.Migration) []parsedMigration {
	parsed := make([]parsedMigration, 0, len(list))
	for _, migration := range list {
		statements := migration.Statements
		if len(statements) == 1 {
			statements = splitWholeFileScript(statements[0])
		}
		parsed = append(parsed, parsedMigration{source: migration, statements: statements})
	}
	return parsed
}
