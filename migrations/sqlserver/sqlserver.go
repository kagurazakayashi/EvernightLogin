// Package sqlserver 把已提交的 SQLite 迁移确定性翻译为 SQL Server（T-SQL）方言迁移。
//
// 设计边界（与 migrations/mysql、migrations/postgres 对齐、但独立实现）：
//   - 只共享 internal/storage/migrate 的加载/校验/语句拆分机制；DDL 解析与生成各自
//     实现。原因：SQL Server 需要方括号标识符、NVARCHAR(n)/VARBINARY(n) 有界类型、
//     显式二进制排序规则（Latin1_General_100_BIN2）、NONCLUSTERED 主键/唯一约束、
//     HASHBYTES 摘要计算列替代超长索引键、AFTER 触发器与 sp_rename 重命名，与
//     MySQL/PostgreSQL 没有可共用的中间表示，强行抽象会互相污染。
//   - 翻译是确定性的：同样的 SQLite 迁移文件必然产生同样的 T-SQL 语句与校验和。
//   - 不猜测：遇到无法等价翻译的 SQLite 语法立即报错，不做静默降级。
//
// 关键方言决定（详见 docs/database/sqlserver_adapter.md）：
//   - 所有字符列使用 NVARCHAR 并显式 COLLATE Latin1_General_100_BIN2：与 SQLite
//     默认 BINARY 比较语义一致，身份唯一性不受服务器/数据库默认排序规则影响。
//     规范化用户名仍由服务层统一，数据库只按字节保证唯一性。
//   - 身份列（id / *_id / kid）使用 NVARCHAR(max(128, CHECK 上界))：满足服务层
//     128 字符公开上限；超过安全索引阈值（1700 字节索引键上限 / 每字符 2 字节）
//     时翻译期直接失败，而不是截断或用 NVARCHAR(MAX) 让 CREATE INDEX 运行期失败。
//   - 时间保持 BIGINT UTC 毫秒、布尔保持 BIGINT 0/1 + CHECK：既有仓储以 int64
//     绑定/扫描，改成 DATETIME2/BIT 会破坏共享仓储契约。SQL Server 没有会话时区，
//     UTC 由应用写入的毫秒整数保证（服务器校验不依赖 SET TIME ZONE）。
//   - JSON 列保持 NVARCHAR（字节保真），CHECK(json_valid(x)) 翻译为
//     ISJSON(x)=1（SQL Server 2016+）；非法 JSON 由 SQL Server 拒绝。
//   - 主键/唯一约束默认声明 NONCLUSTERED：SQL Server 非聚集索引键上限 1700 字节
//     （聚集索引 900 字节），NONCLUSTERED 更宽松；超出预算的唯一键改用
//     HASHBYTES('SHA2_256', 列) 持久化计算列 + 唯一索引（只会误报冲突，不会放过
//     重复值）；主键超预算直接翻译失败（fail-closed）。
//   - rowid 代理列：4 张被仓储用 rowid 排序/删除的表追加
//     _rowid BIGINT IDENTITY(1,1) NOT NULL，仓储 SQL 里的裸 rowid 由
//     internal/storage/sqlserver 重写为 [_rowid]。
//   - SQLite 触发器（BEFORE ... RAISE(ABORT)）翻译为 AFTER 触发器 + THROW；SQLite
//     的 BEFORE INSERT “禁止替换”保护无法用集合式 AFTER 触发器等价表达，但 T-SQL
//     没有 INSERT OR REPLACE 语法、替换风险不存在，因此该触发器明确不翻译并登记
//     （见 translateTrigger），不生成语义错误的触发器。
//   - ALTER TABLE ... RENAME TO 翻译为 sp_rename；DROP TABLE 前静态检查外键引用。
//   - 迁移语句中不含 GO（SQLite 源没有）；执行器仍会按行首 GO 拆分批次以兼容未来
//     手写 T-SQL 迁移，驱动本身不支持 GO。
package sqlserver

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"regexp"
	"strings"
	"sync"

	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const (
	// collationName 是全部字符列显式使用的二进制排序规则：大小写敏感、按代码点
	// 比较，最接近 SQLite 默认 BINARY。身份唯一性不得依赖服务器默认排序规则。
	collationName = "Latin1_General_100_BIN2"
	// textType 是无长度上界且非索引键的 TEXT 列映射（NVARCHAR(MAX) 不可做索引键）。
	textType = "NVARCHAR(MAX) COLLATE " + collationName
	// nvarcharMaxLength 是 NVARCHAR(n) 的最大声明长度；超过必须使用 NVARCHAR(MAX)。
	nvarcharMaxLength = 4000
	// varbinaryMaxLength 是 VARBINARY(n) 的最大声明长度；超过使用 VARBINARY(MAX)。
	varbinaryMaxLength = 8000
	// identityMinLength 是服务层公开 ID 的字符上限（internal/audit 等公开契约 128）；
	// 身份列长度不得小于该值。
	identityMinLength = 128
	// identityMaxIndexChars 是身份列允许的最大字符长度：NVARCHAR(850) 恰为 1700
	// 字节（非聚集索引键上限）；超过则翻译失败，必须人工决定改用摘要键。
	identityMaxIndexChars = 850
	// indexEntryLimit 是 SQL Server 非聚集索引键上限（1700 字节，SQL Server 2016+）。
	// 本翻译器一律生成 NONCLUSTERED 主键/唯一索引，因此使用 1700 而不是聚集索引的
	// 900 字节；索引键总字节按各列最坏 UTF-16 字节数求和判断。
	indexEntryLimit = 1700
	// bytesPerCharWorstCase 是 NVARCHAR 每字符的存储字节数（UTF-16 代码单元 2 字节）。
	bytesPerCharWorstCase = 2
	// hashBytes 是 SHA2_256 摘要长度，用作超预算索引键的替换键。
	hashBytes = 32
	// rowidSurrogateColumn 是被仓储 rowid 语义使用的代理列名。
	rowidSurrogateColumn = "_rowid"
	// hashColumnPrefix 是超预算索引键的摘要计算列前缀。
	hashColumnPrefix = "_hash_"
)

// rowidTables 是仓储 SQL 使用裸 rowid 的 4 张表。迁移为它们追加 _rowid 代理列；
// internal/storage/sqlserver 的仓储 SQL 审计测试会校验该集合与源码使用一致。
var rowidTables = map[string]bool{
	"password_history":      true,
	"audit_maintenance_log": true,
	"stats_health_samples":  true,
	"user_emails":           true,
}

// RowidSurrogateTables 返回使用 rowid 代理列的迁移表集合（只读副本）。
func RowidSurrogateTables() map[string]bool {
	tables := make(map[string]bool, len(rowidTables))
	for table := range rowidTables {
		tables[table] = true
	}
	return tables
}

// Load 加载内嵌的 SQLite 迁移并翻译为 SQL Server 迁移。
func Load() ([]migrate.Migration, error) {
	return Translate(migrations.SQLite)
}

var (
	modelOnce  sync.Once
	modelCache *schemaModel
	modelErr   error
)

// PrimaryKeyColumns 返回表的主键列（按定义顺序），供仓储 SQL 的
// INSERT OR IGNORE→MERGE 重写解析冲突键。表名使用最终表名；主键列与 SQLite
// 迁移定义一致。翻译模型来自已提交迁移，重复调用使用缓存。
func PrimaryKeyColumns(table string) ([]string, error) {
	modelOnce.Do(func() {
		source, err := migrate.LoadMigrations(migrations.SQLite)
		if err != nil {
			modelErr = err
			return
		}
		parsed := make([]parsedMigration, 0, len(source))
		for _, migration := range source {
			statements := migration.Statements
			if len(statements) == 1 {
				statements, err = splitWholeFileScript(statements[0])
				if err != nil {
					modelErr = err
					return
				}
			}
			parsed = append(parsed, parsedMigration{source: migration, statements: statements})
		}
		modelCache, modelErr = buildSchema(parsed)
	})
	if modelErr != nil {
		return nil, modelErr
	}
	live := modelCache.live[strings.ToLower(strings.TrimSpace(table))]
	if live == nil {
		return nil, fmt.Errorf("迁移模型中不存在表 %q", table)
	}
	columns := primaryKeyOf(live)
	if len(columns) == 0 {
		return nil, fmt.Errorf("表 %q 没有主键，无法为 INSERT OR IGNORE 推断冲突键", table)
	}
	return columns, nil
}

// Translate 把给定文件系统内的 SQLite 迁移确定性翻译为 SQL Server 迁移。
//
// 校验和基于翻译后的语句文本计算（与 SQLite 文件 SHA-256 不同）；版本号、描述与
// 文件名保持原样。SQL Server 支持事务内 DDL，因此不继承 SQLite 的
// non-transactional 标记（失败可回滚）；whole-file 标记只影响源文件语句拆分。
// 迁移主键使用非聚集索引，语句本身不含 GO；执行器仍会按行首 GO 拆分批次。
func Translate(fsys fs.FS) ([]migrate.Migration, error) {
	source, err := migrate.LoadMigrations(fsys)
	if err != nil {
		return nil, err
	}
	parsed := make([]parsedMigration, 0, len(source))
	for _, migration := range source {
		statements := migration.Statements
		if len(statements) == 1 {
			// whole-file 迁移（触发器 BEGIN...END 或历史标记）需要重新拆分。
			statements, err = splitWholeFileScript(statements[0])
			if err != nil {
				return nil, fmt.Errorf("拆分迁移 %s 失败: %w", migration.FileName, err)
			}
		}
		parsed = append(parsed, parsedMigration{source: migration, statements: statements})
	}

	model, err := buildSchema(parsed)
	if err != nil {
		return nil, err
	}
	translator := &translator{
		model:   model,
		created: map[string]bool{},
		renamed: map[string]string{},
		hashed:  map[string]map[string]string{},
	}
	translated := make([]migrate.Migration, 0, len(parsed))
	for _, migration := range parsed {
		statements, err := translator.translateMigration(migration.statements)
		if err != nil {
			return nil, fmt.Errorf("迁移 %s 翻译失败: %w", migration.source.FileName, err)
		}
		if err := validateTranslated(statements); err != nil {
			return nil, fmt.Errorf("迁移 %s 翻译结果校验失败: %w", migration.source.FileName, err)
		}
		translated = append(translated, migrate.Migration{
			Version:          migration.source.Version,
			Description:      migration.source.Description,
			FileName:         migration.source.FileName,
			Checksum:         checksumOfStatements(statements),
			Statements:       statements,
			NonTransactional: false,
		})
	}
	return translated, nil
}

type parsedMigration struct {
	source     migrate.Migration
	statements []string
}

func checksumOfStatements(statements []string) string {
	digest := sha256.Sum256([]byte(strings.Join(statements, "\n;\n")))
	return hex.EncodeToString(digest[:])
}

// ---------------------------------------------------------------------------
// 模型：先解析全部迁移建立最终表结构，再翻译；用于身份列长度、外键类型一致性与
// 索引字节预算，避免“逐条翻译时拿不到父列定义”。
// ---------------------------------------------------------------------------

type reference struct {
	Table  string
	Column string
	Action string // 已包含 ON DELETE/ON UPDATE 子句的原文（可为空）
}

type columnInfo struct {
	Name       string
	SQLiteType string
	// MappedType 是最终 T-SQL 类型（含 COLLATE）。
	MappedType string
	// LengthMax 是从 SQLite CHECK 中解析出的字符/字节上界；0 表示未知。
	LengthMax  int
	Identity   bool
	IsKey      bool
	NotNull    bool
	PrimaryKey bool
	Unique     bool
	Default    string
	// RawChecks 是从列定义中提取的原始 SQLite CHECK 表达式（未翻译）；列加入表后
	// 才能按列类型把 length() 翻译为 LEN/DATALENGTH。
	RawChecks []string
	// Checks 是已翻译的 CHECK 表达式（不含 CHECK 关键字）。
	Checks []string
	Ref    *reference
}

type foreignKey struct {
	Name     string
	Columns  []string
	RefTable string
	RefCols  []string
	Action   string
}

type indexColumn struct {
	Name string
	Desc bool
}

// indexInfo 记录迁移里创建的一个索引，用于 CREATE TABLE 阶段声明摘要计算列与
// 索引键字节预算检查。
type indexInfo struct {
	Name    string
	Columns []indexColumn
	Unique  bool
	Where   string
}

type tableInfo struct {
	// Name 是表当前（最终）名字；CreationName 是 CREATE TABLE 时的名字，翻译 DDL 时
	// 必须使用创建名，否则重建表 + RENAME 的迁移会生成错误语句。
	Name             string
	CreationName     string
	Columns          []*columnInfo
	byName           map[string]*columnInfo
	TablePK          []string
	TableUniques     [][]string
	TableChecks      []string
	TableFKs         []foreignKey
	Indexes          []indexInfo
	Rowid            bool
	CreatedByVersion string
}

func (t *tableInfo) column(name string) *columnInfo {
	if t == nil {
		return nil
	}
	return t.byName[strings.ToLower(strings.TrimSpace(name))]
}

type schemaModel struct {
	// creation 以“CREATE TABLE 时的名字”为键，重命名不改变指向。
	creation map[string]*tableInfo
	// live 是所有迁移执行完后的最终表名 → 表。
	live map[string]*tableInfo
	// renameHistory 记录 ALTER TABLE ... RENAME TO 的历史（旧名 → 新名），用于解析
	// 迁移中较早出现、当时尚未重命名的外键引用。
	renameHistory map[string]string
	tables        []*tableInfo
}

func buildSchema(migrations []parsedMigration) (*schemaModel, error) {
	model := &schemaModel{
		creation:      map[string]*tableInfo{},
		live:          map[string]*tableInfo{},
		renameHistory: map[string]string{},
	}
	order := make([]*tableInfo, 0, 128)
	for _, migration := range migrations {
		for _, statement := range migration.statements {
			leading := leadingKeyword(statement)
			switch leading {
			case "CREATE TABLE":
				table, err := parseCreateTable(statement)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", snippet(statement), err)
				}
				table.CreatedByVersion = migration.source.Version
				if model.creation[table.Name] != nil {
					return nil, fmt.Errorf("表 %s 被重复创建", table.Name)
				}
				model.creation[table.Name] = table
				model.live[table.Name] = table
				order = append(order, table)
			case "ALTER TABLE":
				if err := model.applyAlter(statement); err != nil {
					return nil, err
				}
			case "DROP TABLE":
				name := dropTableName(statement)
				if model.live[name] == nil {
					return nil, fmt.Errorf("DROP TABLE 的表 %s 未在已解析迁移中创建", name)
				}
				delete(model.live, name)
			}
		}
	}
	model.tables = order
	if err := model.collectIndexes(migrations); err != nil {
		return nil, err
	}
	if err := model.resolveTypes(); err != nil {
		return nil, err
	}
	return model, nil
}

// collectIndexes 复放一遍迁移流程，记录 CREATE INDEX 并标记索引键列，供类型映射
// 决定是否使用有界 NVARCHAR；不改变任何表结构。
func (m *schemaModel) collectIndexes(migrations []parsedMigration) error {
	live := map[string]*tableInfo{}
	pattern := regexp.MustCompile(`(?is)^CREATE\s+(UNIQUE\s+)?INDEX\s+([A-Za-z0-9_]+)\s+ON\s+([A-Za-z0-9_]+)\s*\(([^)]*(?:\([^)]*\)[^)]*)*)\)(.*)$`)
	for _, migration := range migrations {
		for _, statement := range migration.statements {
			switch leadingKeyword(statement) {
			case "CREATE TABLE":
				name := tableNameFromCreate(statement)
				live[name] = m.creation[name]
			case "CREATE INDEX", "CREATE UNIQUE INDEX":
				match := pattern.FindStringSubmatch(strings.TrimSpace(statement))
				if match == nil {
					return fmt.Errorf("无法解析索引语句: %s", snippet(statement))
				}
				table := live[match[3]]
				if table == nil {
					table = m.live[m.resolveName(match[3])]
				}
				if table == nil {
					return fmt.Errorf("索引引用了未知表 %s", match[3])
				}
				index := indexInfo{
					Name:   match[2],
					Unique: strings.TrimSpace(match[1]) != "",
				}
				for _, part := range splitTopLevel(match[4], ',') {
					fields := strings.Fields(strings.TrimSpace(part))
					if len(fields) == 0 {
						continue
					}
					column := indexColumn{Name: strings.Trim(fields[0], "[`\"")}
					if len(fields) > 1 && strings.EqualFold(fields[1], "DESC") {
						column.Desc = true
					}
					index.Columns = append(index.Columns, column)
					if definition := table.column(column.Name); definition != nil {
						definition.IsKey = true
					}
				}
				where := strings.TrimSpace(match[5])
				where = strings.TrimSpace(strings.TrimPrefix(strings.ToUpper(where), "WHERE"))
				if strings.TrimSpace(match[5]) != "" {
					// 去掉 WHERE 关键字，只保留表达式。
					parts := strings.Fields(match[5])
					where = strings.TrimSpace(strings.Join(parts[1:], " "))
				}
				index.Where = where
				table.Indexes = append(table.Indexes, index)
			case "ALTER TABLE":
				body := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(statement), "ALTER TABLE"))
				tableName, rest := readIdentifier(body)
				if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(rest)), "RENAME TO") {
					newName := strings.Trim(strings.TrimSpace(strings.TrimSpace(rest)[len("RENAME TO"):]), "`\"[]")
					if table := live[tableName]; table != nil {
						delete(live, tableName)
						live[newName] = table
					}
				}
			case "DROP TABLE":
				delete(live, dropTableName(statement))
			}
		}
	}
	return nil
}

func (m *schemaModel) applyAlter(statement string) error {
	body := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(statement), ";"))
	body = strings.TrimPrefix(body, "ALTER TABLE")
	body = strings.TrimSpace(body)
	tableName, rest := readIdentifier(body)
	table := m.live[tableName]
	if table == nil {
		return fmt.Errorf("ALTER TABLE 的表 %s 不存在", tableName)
	}
	rest = strings.TrimSpace(rest)
	upper := strings.ToUpper(rest)
	switch {
	case strings.HasPrefix(upper, "ADD COLUMN"):
		definition := strings.TrimSpace(rest[len("ADD COLUMN"):])
		column, err := parseColumnDefinition(definition)
		if err != nil {
			return fmt.Errorf("表 %s 新增列解析失败: %w", tableName, err)
		}
		if table.byName[column.Name] != nil {
			return fmt.Errorf("表 %s 的列 %s 重复定义", tableName, column.Name)
		}
		table.Columns = append(table.Columns, column)
		table.byName[column.Name] = column
		if err := translateColumnChecks(table, column); err != nil {
			return fmt.Errorf("表 %s 新增列解析失败: %w", tableName, err)
		}
	case strings.HasPrefix(upper, "RENAME TO"):
		newName := strings.TrimSpace(rest[len("RENAME TO"):])
		newName = strings.Trim(newName, "\"`[]")
		if m.live[newName] != nil {
			return fmt.Errorf("重命名目标表 %s 已存在", newName)
		}
		delete(m.live, tableName)
		m.live[newName] = table
		m.renameHistory[tableName] = newName
		table.Name = newName
	default:
		return fmt.Errorf("不支持的 ALTER TABLE 形式: %s", snippet(statement))
	}
	return nil
}

func dropTableName(statement string) string {
	body := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(statement), ";"))
	body = strings.TrimSpace(strings.TrimPrefix(body, "DROP TABLE"))
	if strings.HasPrefix(strings.ToUpper(body), "IF EXISTS") {
		body = strings.TrimSpace(body[len("IF EXISTS"):])
	}
	for _, field := range strings.Fields(body) {
		return strings.Trim(field, "\"`[]")
	}
	return ""
}

func (m *schemaModel) resolveName(name string) string {
	for depth := 0; depth < 8; depth++ {
		if m.live[name] != nil {
			return name
		}
		next, ok := m.renameHistory[name]
		if !ok || next == name {
			return name
		}
		name = next
	}
	return name
}

// resolveTypes 计算每个列的最终 T-SQL 类型（身份列长度、外键列与父列一致）。
func (m *schemaModel) resolveTypes() error {
	for _, table := range m.tables {
		for _, column := range table.Columns {
			column.MappedType = baseType(column)
		}
	}
	// 外键列必须与父列类型完全一致（类型长度/排序规则不同会导致合法 ID 被拒）。
	for round := 0; round < 4; round++ {
		changed := false
		for _, table := range m.tables {
			for _, column := range table.Columns {
				if column.Ref == nil {
					continue
				}
				parentName := m.resolveName(column.Ref.Table)
				parent := m.live[parentName]
				if parent == nil {
					return fmt.Errorf("表 %s 列 %s 的外键引用未知表 %s", table.Name, column.Name, column.Ref.Table)
				}
				parentColumn := parent.column(column.Ref.Column)
				if parentColumn == nil {
					return fmt.Errorf("表 %s 列 %s 的外键引用未知列 %s.%s",
						table.Name, column.Name, column.Ref.Table, column.Ref.Column)
				}
				if parentColumn.MappedType != column.MappedType {
					column.MappedType = parentColumn.MappedType
					changed = true
				}
			}
		}
		if !changed {
			break
		}
	}
	return nil
}

// baseType 把 SQLite 声明类型映射为 T-SQL 类型。字符列一律显式二进制排序规则。
func baseType(column *columnInfo) string {
	switch column.SQLiteType {
	case "TEXT":
		length := column.LengthMax
		switch {
		case column.Identity:
			if length < identityMinLength {
				length = identityMinLength
			}
		case strings.HasSuffix(column.Name, "_normalized"):
			// 规范化用户名/邮箱等登录查询键：至少 254，且不小于 CHECK 上界。
			if length < 254 {
				length = 254
			}
		case column.IsKey:
			// 索引键 TEXT 未声明上界时给出 191（服务层上限更低），与 MySQL 适配一致。
			if length == 0 {
				length = 191
			}
		}
		if length > 0 && length <= nvarcharMaxLength {
			return fmt.Sprintf("NVARCHAR(%d) COLLATE %s", length, collationName)
		}
		// 无长度上界或上界超过 NVARCHAR(n) 上限：使用 NVARCHAR(MAX)，不可做索引键；
		// 若它出现在索引键中，索引生成阶段用摘要计算列替代。
		return textType
	case "BLOB":
		if column.LengthMax > 0 && column.LengthMax <= varbinaryMaxLength {
			return fmt.Sprintf("VARBINARY(%d)", column.LengthMax)
		}
		return "VARBINARY(MAX)"
	case "INTEGER":
		// 时间/布尔/计数保持 64 位整数，与既有仓储的 int64 绑定/扫描一致。
		return "BIGINT"
	case "REAL":
		return "FLOAT(53)"
	default:
		return ""
	}
}

// identityLength 返回身份列允许的字符长度；超过安全阈值时报错而不是静默截断。
func identityLength(column *columnInfo) (string, error) {
	if !column.Identity || column.SQLiteType != "TEXT" {
		return "", fmt.Errorf("列 %s 不是身份 TEXT 列", column.Name)
	}
	length := identityMinLength
	if column.LengthMax > length {
		length = column.LengthMax
	}
	if length > identityMaxIndexChars {
		return "", fmt.Errorf("身份列 %s 的长度上界 %d 超过安全索引阈值 %d，需人工改为摘要键",
			column.Name, length, identityMaxIndexChars)
	}
	return fmt.Sprintf("NVARCHAR(%d) COLLATE %s", length, collationName), nil
}

// ---------------------------------------------------------------------------
// 解析
// ---------------------------------------------------------------------------

var createTablePattern = regexp.MustCompile(`(?is)^CREATE\s+TABLE\s+([A-Za-z0-9_]+)\s*\((.*)\)\s*$`)

func parseCreateTable(statement string) (*tableInfo, error) {
	trimmed := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(statement), ";"))
	match := createTablePattern.FindStringSubmatch(trimmed)
	if match == nil {
		return nil, fmt.Errorf("无法解析 CREATE TABLE")
	}
	table := &tableInfo{
		Name:         match[1],
		CreationName: match[1],
		byName:       map[string]*columnInfo{},
		Rowid:        rowidTables[match[1]],
	}
	for _, definition := range splitTopLevel(match[2], ',') {
		definition = strings.TrimSpace(definition)
		if definition == "" {
			continue
		}
		upper := strings.ToUpper(definition)
		if isTableConstraint(upper) {
			if err := table.addTableConstraint(definition); err != nil {
				return nil, fmt.Errorf("表 %s 约束解析失败: %w", table.Name, err)
			}
			continue
		}
		column, err := parseColumnDefinition(definition)
		if err != nil {
			return nil, fmt.Errorf("表 %s 列定义解析失败: %w", table.Name, err)
		}
		if table.byName[column.Name] != nil {
			return nil, fmt.Errorf("表 %s 的列 %s 重复定义", table.Name, column.Name)
		}
		table.Columns = append(table.Columns, column)
		table.byName[column.Name] = column
		if err := translateColumnChecks(table, column); err != nil {
			return nil, fmt.Errorf("表 %s 列定义解析失败: %w", table.Name, err)
		}
	}
	if len(table.Columns) == 0 {
		return nil, fmt.Errorf("表 %s 没有列", table.Name)
	}
	if table.Rowid && len(table.TablePK) == 0 && !hasInlinePrimaryKey(table) {
		return nil, fmt.Errorf("rowid 代理表 %s 没有主键", table.Name)
	}
	table.markKeyColumns()
	return table, nil
}

func primaryKeyOf(table *tableInfo) []string {
	if len(table.TablePK) > 0 {
		return append([]string(nil), table.TablePK...)
	}
	for _, column := range table.Columns {
		if column.PrimaryKey {
			return []string{column.Name}
		}
	}
	return nil
}

// markKeyColumns 标记主键/唯一键列；索引键在 buildSchema 的第二次遍历中补充。
func (t *tableInfo) markKeyColumns() {
	for _, column := range t.Columns {
		if column.PrimaryKey || column.Unique {
			column.IsKey = true
		}
	}
	for _, name := range t.TablePK {
		if column := t.column(name); column != nil {
			column.IsKey = true
		}
	}
	for _, unique := range t.TableUniques {
		for _, name := range unique {
			if column := t.column(name); column != nil {
				column.IsKey = true
			}
		}
	}
}

func hasInlinePrimaryKey(table *tableInfo) bool {
	for _, column := range table.Columns {
		if column.PrimaryKey {
			return true
		}
	}
	return false
}

func isTableConstraint(upper string) bool {
	for _, prefix := range []string{"CONSTRAINT ", "PRIMARY KEY", "UNIQUE", "CHECK", "FOREIGN KEY"} {
		if strings.HasPrefix(upper, prefix) {
			return true
		}
	}
	return false
}

var (
	sqliteTypes = []string{"TEXT", "INTEGER", "BLOB", "REAL", "NUMERIC"}
	// checkPattern 匹配 CHECK(...)（允许内部任意深度括号）。
	checkPattern = regexp.MustCompile(`(?is)\bCHECK\s*\(`)
	// referencePattern 匹配列内联 REFERENCES 子句。
	referencePattern = regexp.MustCompile(`(?is)\bREFERENCES\s+([A-Za-z0-9_]+)\s*\(\s*([A-Za-z0-9_]+)\s*\)(\s+ON\s+DELETE\s+(?:CASCADE|SET\s+NULL|SET\s+DEFAULT|RESTRICT|NO\s+ACTION))?(\s+ON\s+UPDATE\s+(?:CASCADE|SET\s+NULL|SET\s+DEFAULT|RESTRICT|NO\s+ACTION))?`)
	// lengthBoundPattern 从 CHECK 表达式提取 length(col) 上界。
	lengthBoundPattern = regexp.MustCompile(`(?is)length\s*\(\s*([A-Za-z0-9_]+)\s*\)\s*(<=|<|=|BETWEEN\s+(-?[0-9]+)\s+AND)\s*(-?[0-9]+)`)
)

func parseColumnDefinition(definition string) (*columnInfo, error) {
	name, rest := readIdentifier(definition)
	if name == "" {
		return nil, fmt.Errorf("缺少列名: %s", snippet(definition))
	}
	rest = strings.TrimSpace(rest)
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return nil, fmt.Errorf("列 %s 缺少类型", name)
	}
	sqliteType := strings.ToUpper(fields[0])
	if !isSQLiteType(sqliteType) {
		return nil, fmt.Errorf("列 %s 的类型 %q 不在已声明映射内", name, fields[0])
	}
	constraints := strings.TrimSpace(rest[len(fields[0]):])
	column := &columnInfo{Name: name, SQLiteType: sqliteType}

	// 收集列内联 REFERENCES（父表未创建时提升为 ALTER TABLE ADD CONSTRAINT）。
	if match := referencePattern.FindStringSubmatch(constraints); match != nil {
		column.Ref = &reference{Table: match[1], Column: match[2], Action: strings.TrimSpace(match[3] + match[4])}
		constraints = strings.Replace(constraints, match[0], " ", 1)
	}
	if strings.Contains(strings.ToUpper(constraints), "AUTOINCREMENT") {
		column.Identity = true
		constraints = regexp.MustCompile(`(?i)\bAUTOINCREMENT\b`).ReplaceAllString(constraints, " ")
	}
	upper := strings.ToUpper(constraints)
	column.NotNull = strings.Contains(upper, "NOT NULL")
	column.PrimaryKey = regexp.MustCompile(`(?i)\bPRIMARY\s+KEY\b`).MatchString(constraints)
	column.Unique = regexp.MustCompile(`(?i)(^|\s)UNIQUE(\s|$|,)`).MatchString(constraints)
	if defaultValue := readDefaultValue(constraints); defaultValue != "" {
		column.Default = defaultValue
	}
	// 先提取原始 CHECK 表达式：长度上界必须从 SQLite 的 length() 原文解析，
	// 翻译为 LEN()/DATALENGTH() 后无法再据此确定列长度。翻译在列加入表后进行。
	rawChecks, err := extractRawChecks(constraints)
	if err != nil {
		return nil, fmt.Errorf("列 %s: %w", name, err)
	}
	column.RawChecks = rawChecks
	for _, expression := range rawChecks {
		if bound := lengthUpperBound(expression); bound > column.LengthMax {
			column.LengthMax = bound
		}
	}
	if column.SQLiteType == "TEXT" && (name == "id" || strings.HasSuffix(name, "_id") || name == "kid") {
		column.Identity = true
	}
	column.MappedType = baseType(column)
	return column, nil
}

func isSQLiteType(value string) bool {
	for _, candidate := range sqliteTypes {
		if value == candidate {
			return true
		}
	}
	return false
}

// extractRawChecks 提取文本中所有 CHECK(...) 的原始表达式（不翻译）。
func extractRawChecks(text string) ([]string, error) {
	var checks []string
	remaining := text
	for {
		match := checkPattern.FindStringIndex(remaining)
		if match == nil {
			return checks, nil
		}
		open := match[1] - 1
		closeIndex, err := matchingParen(remaining, open)
		if err != nil {
			return nil, fmt.Errorf("CHECK 括号未闭合: %w", err)
		}
		checks = append(checks, strings.TrimSpace(remaining[open+1:closeIndex]))
		remaining = remaining[closeIndex+1:]
	}
}

// translateColumnChecks 在列已加入表定义后翻译其原始 CHECK 表达式；这样
// length(blob 列) 才能识别为 DATALENGTH，列名也能加方括号。
func translateColumnChecks(table *tableInfo, column *columnInfo) error {
	column.Checks = make([]string, 0, len(column.RawChecks))
	for _, raw := range column.RawChecks {
		translated, err := translateCheckExpression(raw, table)
		if err != nil {
			return fmt.Errorf("表 %s 列 %s: %w", table.Name, column.Name, err)
		}
		column.Checks = append(column.Checks, translated)
	}
	return nil
}

// readDefaultValue 从约束文本中提取 DEFAULT 后面的字面量（保留原文）。
func readDefaultValue(constraints string) string {
	index := findWord(constraints, "DEFAULT")
	if index < 0 {
		return ""
	}
	rest := strings.TrimSpace(constraints[index+len("DEFAULT"):])
	if rest == "" {
		return ""
	}
	if rest[0] == '\'' || rest[0] == '"' {
		quote := rest[0]
		for position := 1; position < len(rest); position++ {
			if rest[position] == quote {
				if position+1 < len(rest) && rest[position+1] == quote {
					position++
					continue
				}
				return rest[:position+1]
			}
		}
		return rest
	}
	end := 0
	for end < len(rest) && !strings.ContainsRune(" ,)\t\n", rune(rest[end])) {
		end++
	}
	return rest[:end]
}

func (t *tableInfo) addTableConstraint(definition string) error {
	upper := strings.ToUpper(strings.TrimSpace(definition))
	switch {
	case strings.HasPrefix(upper, "PRIMARY KEY"):
		content, err := parenthesizedAfter(definition, "PRIMARY KEY")
		if err != nil {
			return err
		}
		t.TablePK = splitIdentifierList(content)
	case strings.HasPrefix(upper, "UNIQUE"):
		content, err := parenthesizedAfter(definition, "UNIQUE")
		if err != nil {
			return err
		}
		t.TableUniques = append(t.TableUniques, splitIdentifierList(content))
	case strings.HasPrefix(upper, "CHECK"):
		checks, err := extractChecks(definition, t)
		if err != nil {
			return err
		}
		t.TableChecks = append(t.TableChecks, checks...)
	case strings.HasPrefix(upper, "FOREIGN KEY"):
		if err := t.addForeignKey(definition); err != nil {
			return err
		}
	case strings.HasPrefix(upper, "CONSTRAINT"):
		name, rest := readIdentifier(strings.TrimSpace(definition[len("CONSTRAINT"):]))
		rest = strings.TrimSpace(rest)
		inner := strings.ToUpper(rest)
		switch {
		case strings.HasPrefix(inner, "CHECK"):
			checks, err := extractChecks(rest, t)
			if err != nil {
				return err
			}
			t.TableChecks = append(t.TableChecks, checks...)
		case strings.HasPrefix(inner, "UNIQUE"):
			content, err := parenthesizedAfter(rest, "UNIQUE")
			if err != nil {
				return err
			}
			t.TableUniques = append(t.TableUniques, splitIdentifierList(content))
		case strings.HasPrefix(inner, "PRIMARY KEY"):
			content, err := parenthesizedAfter(rest, "PRIMARY KEY")
			if err != nil {
				return err
			}
			t.TablePK = splitIdentifierList(content)
		case strings.HasPrefix(inner, "FOREIGN KEY"):
			fk, err := parseForeignKey(rest)
			if err != nil {
				return err
			}
			fk.Name = name
			t.TableFKs = append(t.TableFKs, *fk)
		default:
			return fmt.Errorf("不支持的命名表约束: %s", snippet(definition))
		}
	default:
		return fmt.Errorf("不支持的约束: %s", snippet(definition))
	}
	return nil
}

func (t *tableInfo) addForeignKey(definition string) error {
	fk, err := parseForeignKey(definition)
	if err != nil {
		return err
	}
	t.TableFKs = append(t.TableFKs, *fk)
	return nil
}

var foreignKeyPattern = regexp.MustCompile(`(?is)^FOREIGN\s+KEY\s*\(([^)]*)\)\s*REFERENCES\s+([A-Za-z0-9_]+)\s*\(([^)]*)\)(.*)$`)

func parseForeignKey(definition string) (*foreignKey, error) {
	match := foreignKeyPattern.FindStringSubmatch(strings.TrimSpace(definition))
	if match == nil {
		return nil, fmt.Errorf("无法解析外键: %s", snippet(definition))
	}
	fk := &foreignKey{
		Columns:  splitIdentifierList(match[1]),
		RefTable: match[2],
		RefCols:  splitIdentifierList(match[3]),
		Action:   normalizeAction(match[4]),
	}
	if len(fk.Columns) != len(fk.RefCols) {
		return nil, fmt.Errorf("外键列数与被引用列数不一致: %s", snippet(definition))
	}
	return fk, nil
}

func normalizeAction(text string) string {
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return ""
	}
	return strings.Join(fields, " ")
}

// extractChecks 提取文本中所有 CHECK(...) 表达式（不含 CHECK 关键字）并翻译。
func extractChecks(text string, table *tableInfo) ([]string, error) {
	var checks []string
	remaining := text
	for {
		match := checkPattern.FindStringIndex(remaining)
		if match == nil {
			return checks, nil
		}
		open := match[1] - 1
		closeIndex, err := matchingParen(remaining, open)
		if err != nil {
			return nil, fmt.Errorf("CHECK 括号未闭合: %w", err)
		}
		expression := strings.TrimSpace(remaining[open+1 : closeIndex])
		translated, err := translateCheckExpression(expression, table)
		if err != nil {
			return nil, err
		}
		checks = append(checks, translated)
		remaining = remaining[closeIndex+1:]
	}
}

// translateCheckExpression 翻译 SQLite CHECK 表达式中的专有函数：
//   - json_valid(x) -> ISJSON([x]) = 1（SQL Server 2016+，x 为 NULL 时 ISJSON 为
//     NULL，CHECK 通过，与 SQLite json_valid(NULL)=NULL 通过一致）
//   - length(x) -> LEN([x])（字符列）或 DATALENGTH([x])（二进制列）。SQL Server 的
//     LEN 不统计末尾空格，与 SQLite length 计数不同；当前 CHECK 都是长度上界，
//     影响被文档登记为已知的排序/长度语义差异。
func translateCheckExpression(expression string, table *tableInfo) (string, error) {
	if expression == "" {
		return "", fmt.Errorf("空 CHECK 表达式")
	}
	var builder strings.Builder
	index := 0
	for index < len(expression) {
		lower := strings.ToLower(expression[index:])
		if strings.HasPrefix(lower, "json_valid") && boundaryBefore(expression, index) &&
			(index+len("json_valid") >= len(expression) || !isIdentChar(expression[index+len("json_valid")])) {
			open := index + len("json_valid")
			for open < len(expression) && expression[open] == ' ' {
				open++
			}
			if open >= len(expression) || expression[open] != '(' {
				return "", fmt.Errorf("json_valid 缺少参数括号")
			}
			closeIndex, err := matchingParen(expression, open)
			if err != nil {
				return "", err
			}
			argument := strings.TrimSpace(expression[open+1 : closeIndex])
			if argument == "" {
				return "", fmt.Errorf("json_valid 参数为空")
			}
			builder.WriteString("ISJSON(" + argument + ") = 1")
			index = closeIndex + 1
			continue
		}
		if strings.HasPrefix(lower, "length") && boundaryBefore(expression, index) &&
			(index+len("length") >= len(expression) || !isIdentChar(expression[index+len("length")])) {
			open := index + len("length")
			for open < len(expression) && expression[open] == ' ' {
				open++
			}
			if open >= len(expression) || expression[open] != '(' {
				return "", fmt.Errorf("length 缺少参数括号")
			}
			closeIndex, err := matchingParen(expression, open)
			if err != nil {
				return "", err
			}
			argument := strings.TrimSpace(expression[open+1 : closeIndex])
			if argument == "" {
				return "", fmt.Errorf("length 参数为空")
			}
			function := "LEN"
			if table != nil {
				if column := table.column(argument); column != nil && column.SQLiteType == "BLOB" {
					function = "DATALENGTH"
				}
			}
			builder.WriteString(function + "(" + argument + ")")
			index = closeIndex + 1
			continue
		}
		builder.WriteByte(expression[index])
		index++
	}
	translated := bracketIdentifiers(builder.String(), table)
	lowered := strings.ToLower(translated)
	for _, forbidden := range []string{"json_extract", "json_each", "strftime", "julianday", "json_valid"} {
		if strings.Contains(lowered, forbidden) {
			return "", fmt.Errorf("CHECK 仍含 SQLite 专有语法 %q: %s", forbidden, snippet(translated))
		}
	}
	if regexp.MustCompile(`(?i)(^|[^a-z_0-9])length\s*\(`).MatchString(translated) {
		return "", fmt.Errorf("CHECK 仍含 SQLite length() 未翻译: %s", snippet(translated))
	}
	return translated, nil
}

// bracketIdentifiers 把表达式中的裸列标识符替换为 [标识符]；只处理已知列名，
// 不触碰字符串字面量、函数名、关键字与参数占位符。
func bracketIdentifiers(expression string, table *tableInfo) string {
	if table == nil {
		return expression
	}
	var builder strings.Builder
	index := 0
	for index < len(expression) {
		if expression[index] == '\'' || expression[index] == '"' {
			end, ok := skipQuoted(expression, index)
			if !ok {
				builder.WriteString(expression[index:])
				break
			}
			builder.WriteString(expression[index : end+1])
			index = end + 1
			continue
		}
		if expression[index] == '[' {
			// 已是方括号标识符：原样保留，避免重复加括号。
			end := index + 1
			for end < len(expression) {
				if expression[end] == ']' {
					if end+1 < len(expression) && expression[end+1] == ']' {
						end += 2
						continue
					}
					end++
					break
				}
				end++
			}
			builder.WriteString(expression[index:end])
			index = end
			continue
		}
		if isIdentStart(expression[index]) {
			end := index
			for end < len(expression) && isIdentChar(expression[end]) {
				end++
			}
			token := expression[index:end]
			next := end
			for next < len(expression) && expression[next] == ' ' {
				next++
			}
			isCall := next < len(expression) && expression[next] == '('
			column := table.column(token)
			if column != nil && !isCall {
				builder.WriteString("[" + token + "]")
			} else {
				builder.WriteString(token)
			}
			index = end
			continue
		}
		builder.WriteByte(expression[index])
		index++
	}
	return builder.String()
}

// lengthUpperBound 解析 length(col) 的 CHECK 上界；无法解析时返回 0。
func lengthUpperBound(expression string) int {
	match := lengthBoundPattern.FindStringSubmatch(expression)
	if match == nil {
		return 0
	}
	operator := strings.ToUpper(strings.Join(strings.Fields(match[2]), " "))
	value := atoiSafe(match[4])
	switch {
	case strings.HasPrefix(operator, "BETWEEN"):
		return value
	case operator == "<=":
		return value
	case operator == "<":
		return value - 1
	case operator == "=":
		return value
	}
	return 0
}

func atoiSafe(text string) int {
	value := 0
	negative := strings.HasPrefix(text, "-")
	for _, character := range strings.TrimPrefix(text, "-") {
		if character < '0' || character > '9' {
			return 0
		}
		value = value*10 + int(character-'0')
	}
	if negative {
		return -value
	}
	return value
}

// ---------------------------------------------------------------------------
// 翻译
// ---------------------------------------------------------------------------

type pendingForeignKey struct {
	refTable string
	clause   string
}

type translator struct {
	model     *schemaModel
	created   map[string]bool
	renamed   map[string]string
	pendingFK []pendingForeignKey
	// hashed 记录每张表已声明的摘要计算列：表名 → 列名 → 计算列名。
	hashed map[string]map[string]string
	extra  int
}

func (t *translator) translateMigration(statements []string) ([]string, error) {
	output := make([]string, 0, len(statements)+8)
	for _, statement := range statements {
		translated, err := t.translateStatement(statement)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", snippet(statement), err)
		}
		output = append(output, translated...)
	}
	return output, nil
}

func (t *translator) translateStatement(statement string) ([]string, error) {
	statement = strings.TrimSpace(statement)
	if statement == "" {
		return nil, nil
	}
	switch leadingKeyword(statement) {
	case "CREATE TABLE":
		table := t.model.creation[tableNameFromCreate(statement)]
		if table == nil {
			return nil, fmt.Errorf("CREATE TABLE 的表不在模型中: %s", snippet(statement))
		}
		text, extras, err := t.emitCreateTable(table)
		if err != nil {
			return nil, err
		}
		createdName := table.CreationName
		if createdName == "" {
			createdName = table.Name
		}
		t.created[createdName] = true
		output := []string{text}
		// 父表刚创建，补上等待它的外键。
		remaining := t.pendingFK[:0]
		for _, item := range t.pendingFK {
			if item.refTable == table.Name {
				output = append(output, item.clause)
				continue
			}
			remaining = append(remaining, item)
		}
		t.pendingFK = remaining
		output = append(output, extras...)
		return output, nil
	case "CREATE INDEX", "CREATE UNIQUE INDEX":
		text, err := t.emitCreateIndex(statement)
		if err != nil {
			return nil, err
		}
		return []string{text}, nil
	case "CREATE TRIGGER":
		return translateTrigger(statement, t.model)
	case "ALTER TABLE":
		return t.emitAlterTable(statement)
	case "DROP TABLE":
		name := dropTableName(statement)
		if !t.created[name] {
			return nil, fmt.Errorf("DROP TABLE 的表 %s 未在已翻译迁移中创建", name)
		}
		// SQL Server 不允许删除仍被外键引用的表；在翻译期静态失败，避免运行到一半。
		for liveName, liveTable := range t.model.creation {
			if !t.created[liveName] || liveName == name {
				continue
			}
			for _, column := range liveTable.Columns {
				if column.Ref != nil && t.model.resolveName(column.Ref.Table) == name {
					return nil, fmt.Errorf("表 %s 仍被 %s.%s 外键引用，不能 DROP TABLE %s",
						name, liveName, column.Name, name)
				}
			}
			for _, fk := range liveTable.TableFKs {
				if t.model.resolveName(fk.RefTable) == name {
					return nil, fmt.Errorf("表 %s 仍被 %s 外键引用，不能 DROP TABLE %s",
						name, liveName, name)
				}
			}
		}
		delete(t.created, name)
		return []string{"DROP TABLE [" + name + "]"}, nil
	case "INSERT INTO":
		return []string{statement}, nil
	case "INSERT OR IGNORE INTO":
		// SQLite 种子数据没有 INSERT OR IGNORE；遇到时 fail-closed（仓储写入由
		// internal/storage/sqlserver 的 MERGE 重写处理，不在迁移 DDL 中猜测）。
		return nil, fmt.Errorf("迁移 DDL 中的 INSERT OR IGNORE 未实现翻译；请改写迁移为 INSERT")
	default:
		return nil, fmt.Errorf("不支持的语句类型: %s", snippet(statement))
	}
}

func tableNameFromCreate(statement string) string {
	trimmed := strings.TrimSpace(statement)
	rest := strings.TrimSpace(trimmed[len("CREATE TABLE"):])
	name, _ := readIdentifier(rest)
	return name
}

// emitCreateTable 生成 T-SQL CREATE TABLE 与紧随其后的补充语句（摘要唯一索引、
// 延迟外键等）。
func (t *translator) emitCreateTable(table *tableInfo) (string, []string, error) {
	lines := make([]string, 0, len(table.Columns)+len(table.TableUniques)+len(table.TableChecks)+len(table.TableFKs)+8)
	var extras []string
	createName := table.CreationName
	if createName == "" {
		createName = table.Name
	}
	t.ensureHashColumns(table)
	for _, column := range table.Columns {
		line, extra, err := t.emitColumn(table, column, createName)
		if err != nil {
			return "", nil, err
		}
		lines = append(lines, line)
		extras = append(extras, extra...)
	}
	if table.Rowid {
		lines = append(lines, "["+rowidSurrogateColumn+"] BIGINT IDENTITY(1,1) NOT NULL")
	}
	// 摘要计算列（HASHBYTES 持久化）必须在基础列之后声明。
	hashNames := t.hashed[table.Name]
	hashColumns := make([]string, 0, len(hashNames))
	for _, column := range table.Columns {
		if hashName, ok := hashNames[column.Name]; ok {
			hashColumns = append(hashColumns, hashName)
		}
	}
	for _, hashName := range hashColumns {
		source := strings.TrimPrefix(hashName, hashColumnPrefix)
		lines = append(lines, "["+hashName+"] AS (HASHBYTES('SHA2_256', ["+source+"])) PERSISTED")
	}
	// 主键：一律 NONCLUSTERED（非聚集索引键上限 1700 字节），超预算 fail-closed。
	primaryColumns := primaryKeyOf(table)
	if len(primaryColumns) > 0 {
		if err := checkIndexBudget(table, primaryColumns, "主键", true); err != nil {
			return "", nil, err
		}
		lines = append(lines, "CONSTRAINT ["+constraintName("PK", createName)+"] PRIMARY KEY NONCLUSTERED ("+
			joinQuoted(primaryColumns)+")")
	}
	for ordinal, unique := range table.TableUniques {
		safe, err := indexWithinBudget(table, unique)
		if err != nil {
			return "", nil, err
		}
		if safe {
			lines = append(lines, "CONSTRAINT ["+constraintName("UQ", fmt.Sprintf("%s_%d", createName, ordinal+1))+
				"] UNIQUE NONCLUSTERED ("+joinQuoted(unique)+")")
			continue
		}
		expressions, err := t.indexExpressions(table, unique)
		if err != nil {
			return "", nil, err
		}
		extras = append(extras, "CREATE UNIQUE INDEX ["+constraintName("UX", fmt.Sprintf("%s_%d", createName, ordinal+1))+
			"] ON ["+createName+"] ("+expressions+")")
	}
	for ordinal, check := range table.TableChecks {
		lines = append(lines, "CONSTRAINT ["+constraintName("CK", fmt.Sprintf("%s_%d", createName, ordinal+1))+
			"] CHECK ("+check+")")
	}
	for ordinal, fk := range table.TableFKs {
		if len(fk.Columns) == 0 {
			continue
		}
		clause := "FOREIGN KEY (" + joinQuoted(fk.Columns) + ") REFERENCES [" +
			fk.RefTable + "] (" + joinQuoted(fk.RefCols) + ")" + actionSuffix(fk.Action)
		constraint := "CONSTRAINT [" + constraintName("FK", fmt.Sprintf("%s_t%d", createName, ordinal+1)) + "] " + clause
		if t.parentReady(fk.RefTable, createName) {
			lines = append(lines, constraint)
			continue
		}
		t.queueForeignKey(fk.RefTable, "ALTER TABLE ["+createName+"] ADD "+constraint)
	}
	// 列级 REFERENCES 在 T-SQL 中不能作为列定义内的命名 FOREIGN KEY 约束，统一提升
	// 为表级约束（父表尚未创建时排队到父表 CREATE 之后）。
	for _, column := range table.Columns {
		if column.Ref == nil {
			continue
		}
		clause := "FOREIGN KEY ([" + column.Name + "]) REFERENCES [" + column.Ref.Table + "] ([" +
			column.Ref.Column + "])" + actionSuffix(column.Ref.Action)
		constraint := "CONSTRAINT [" + constraintName("FK", createName+"_"+column.Name) + "] " + clause
		if t.parentReady(column.Ref.Table, createName) {
			lines = append(lines, constraint)
			continue
		}
		t.queueForeignKey(column.Ref.Table, "ALTER TABLE ["+createName+"] ADD "+constraint)
	}
	return "CREATE TABLE [" + createName + "] (\n  " + strings.Join(lines, ",\n  ") + "\n)", extras, nil
}

// ensureHashColumns 为所有超出索引键预算的列准备摘要计算列声明（唯一约束、列级
// 唯一与 CREATE INDEX 共用）。同一列只声明一次。
func (t *translator) ensureHashColumns(table *tableInfo) {
	if t.hashed == nil {
		t.hashed = map[string]map[string]string{}
	}
	record := func(column string) {
		if t.hashed[table.Name] == nil {
			t.hashed[table.Name] = map[string]string{}
		}
		if _, ok := t.hashed[table.Name][column]; !ok {
			t.hashed[table.Name][column] = hashColumnPrefix + column
		}
	}
	for _, column := range table.Columns {
		if column.Unique {
			if !indexWithinBudgetSingle(column) {
				record(column.Name)
			}
		}
	}
	for _, unique := range table.TableUniques {
		if !indexWithinBudgetSingleList(table, unique) {
			for _, name := range t.hashColumnsFor(table, unique) {
				record(name)
			}
		}
	}
	for _, index := range table.Indexes {
		names := make([]string, 0, len(index.Columns))
		for _, column := range index.Columns {
			names = append(names, column.Name)
		}
		if !indexWithinBudgetSingleList(table, names) {
			for _, name := range t.hashColumnsFor(table, names) {
				record(name)
			}
		}
	}
}

// hashColumnsFor 按索引列顺序累计字节预算，返回需要用摘要替换的列；这些列写入
// 同一索引时最多占用 32 字节，通常不再会超预算。
func (t *translator) hashColumnsFor(table *tableInfo, columns []string) []string {
	used := 0
	hashed := make([]string, 0, 1)
	for _, name := range columns {
		column := table.column(name)
		if column == nil {
			continue
		}
		size := indexColumnBytes(column)
		if used+size > indexEntryLimit {
			hashed = append(hashed, name)
			used += hashBytes
			continue
		}
		used += size
	}
	return hashed
}

func actionSuffix(action string) string {
	if strings.TrimSpace(action) == "" {
		return ""
	}
	return " " + action
}

func (t *translator) parentReady(refTable, self string) bool {
	if refTable == self {
		return true
	}
	if t.created[refTable] {
		return true
	}
	if final, ok := t.renamed[refTable]; ok && t.created[final] {
		return true
	}
	return false
}

func (t *translator) queueForeignKey(refTable, clause string) {
	t.pendingFK = append(t.pendingFK, pendingForeignKey{refTable: refTable, clause: clause})
}

func (t *translator) emitColumn(table *tableInfo, column *columnInfo, createName string) (string, []string, error) {
	var extras []string
	definition := "[" + column.Name + "]"
	if column.Identity && column.SQLiteType == "TEXT" {
		length, err := identityLength(column)
		if err != nil {
			return "", nil, fmt.Errorf("表 %s: %w", table.Name, err)
		}
		definition += " " + length
	} else {
		if column.MappedType == "" {
			return "", nil, fmt.Errorf("表 %s 列 %s 的类型不在已声明映射内（SQLite 类型 %s）",
				table.Name, column.Name, column.SQLiteType)
		}
		definition += " " + column.MappedType
	}
	// 身份命名只影响类型长度策略，不隐含 NOT NULL：可空外键（如 applications.
	// owner_user_id ON DELETE SET NULL）必须保持可空。
	if column.NotNull || column.PrimaryKey {
		definition += " NOT NULL"
	}
	if column.Default != "" {
		definition += " DEFAULT " + column.Default
	}
	// 列级 PRIMARY KEY 统一在 CREATE TABLE 末尾用显式命名约束生成（NONCLUSTERED），
	// 这里不再内联，避免默认聚集索引与匿名约束名。
	if column.Unique {
		if indexWithinBudgetSingle(column) {
			definition += " CONSTRAINT [" + constraintName("UQ", createName+"_"+column.Name) + "] UNIQUE"
		} else {
			hashName, err := t.hashNameForColumn(table, column.Name)
			if err != nil {
				return "", nil, err
			}
			t.extra++
			extras = append(extras, "CREATE UNIQUE INDEX ["+constraintName("UX", fmt.Sprintf("%s_c%d", createName, t.extra))+
				"] ON ["+createName+"] (["+hashName+"])")
		}
	}
	for ordinal, check := range column.Checks {
		definition += " CONSTRAINT [" + constraintName("CK", fmt.Sprintf("%s_%s_%d", createName, column.Name, ordinal+1)) +
			"] CHECK (" + check + ")"
	}
	return definition, extras, nil
}

// hashNameForColumn 返回（必要时声明）某列的摘要计算列名。
func (t *translator) hashNameForColumn(table *tableInfo, column string) (string, error) {
	if t.hashed == nil {
		t.hashed = map[string]map[string]string{}
	}
	if t.hashed[table.Name] == nil {
		t.hashed[table.Name] = map[string]string{}
	}
	if name, ok := t.hashed[table.Name][column]; ok {
		return name, nil
	}
	if table.column(column) == nil {
		return "", fmt.Errorf("表 %s 不存在列 %s", table.Name, column)
	}
	name := hashColumnPrefix + column
	t.hashed[table.Name][column] = name
	return name, nil
}

func (t *translator) emitAlterTable(statement string) ([]string, error) {
	body := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(statement), ";"))
	body = strings.TrimSpace(strings.TrimPrefix(body, "ALTER TABLE"))
	tableName, rest := readIdentifier(body)
	rest = strings.TrimSpace(rest)
	upper := strings.ToUpper(rest)
	switch {
	case strings.HasPrefix(upper, "ADD COLUMN"):
		if !t.created[tableName] {
			return nil, fmt.Errorf("ALTER TABLE 的表 %s 尚未创建", tableName)
		}
		table := t.model.live[tableName]
		if table == nil {
			return nil, fmt.Errorf("ALTER TABLE 的表 %s 不在模型中", tableName)
		}
		definition := strings.TrimSpace(rest[len("ADD COLUMN"):])
		name, _ := readIdentifier(definition)
		column := table.column(name)
		if column == nil {
			return nil, fmt.Errorf("表 %s 的新增列 %s 不在模型中", tableName, name)
		}
		line, extras, err := t.emitColumn(table, column, tableName)
		if err != nil {
			return nil, err
		}
		output := []string{"ALTER TABLE [" + tableName + "] ADD " + line}
		output = append(output, extras...)
		if column.Ref != nil {
			clause := "FOREIGN KEY ([" + column.Name + "]) REFERENCES [" + column.Ref.Table + "] ([" +
				column.Ref.Column + "])" + actionSuffix(column.Ref.Action)
			constraint := "CONSTRAINT [" + constraintName("FK", tableName+"_"+column.Name) + "] " + clause
			if t.parentReady(column.Ref.Table, tableName) {
				output = append(output, "ALTER TABLE ["+tableName+"] ADD "+constraint)
			} else {
				t.queueForeignKey(column.Ref.Table, "ALTER TABLE ["+tableName+"] ADD "+constraint)
			}
		}
		return output, nil
	case strings.HasPrefix(upper, "RENAME TO"):
		newName := strings.TrimSpace(rest[len("RENAME TO"):])
		newName = strings.Trim(newName, "\"`[]")
		delete(t.created, tableName)
		t.created[newName] = true
		t.renamed[tableName] = newName
		// 重命名的表可能正是等待补外键的父表。
		remaining := t.pendingFK[:0]
		output := []string{"EXEC sp_rename N'[" + tableName + "]', N'" + newName + "'"}
		for _, item := range t.pendingFK {
			if item.refTable == tableName {
				output = append(output, item.clause)
				continue
			}
			remaining = append(remaining, item)
		}
		t.pendingFK = remaining
		return output, nil
	default:
		return nil, fmt.Errorf("不支持的 ALTER TABLE 形式: %s", snippet(statement))
	}
}

// indexWithinBudget 判断索引键（列组合）是否在 1700 字节预算内。
func indexWithinBudget(table *tableInfo, columns []string) (bool, error) {
	for _, name := range columns {
		if table.column(name) == nil {
			return false, fmt.Errorf("索引引用了表 %s 的未知列 %s", table.Name, name)
		}
	}
	return indexWithinBudgetSingleList(table, columns), nil
}

func indexWithinBudgetSingleList(table *tableInfo, columns []string) bool {
	used := 0
	for _, name := range columns {
		column := table.column(name)
		if column == nil {
			return false
		}
		used += indexColumnBytes(column)
		if used > indexEntryLimit {
			return false
		}
	}
	return true
}

func indexWithinBudgetSingle(column *columnInfo) bool {
	return indexColumnBytes(column) <= indexEntryLimit
}

// checkIndexBudget 对主键做严格预算检查：超预算时必须人工改为摘要键，翻译失败。
func checkIndexBudget(table *tableInfo, columns []string, label string, strict bool) error {
	if indexWithinBudgetSingleList(table, columns) {
		return nil
	}
	if strict {
		return fmt.Errorf("表 %s 的%s索引键超过 SQL Server 1700 字节限制；需人工改为摘要键",
			table.Name, label)
	}
	return nil
}

// indexColumnBytes 估算索引键列的最坏字节数；未知上界按“不安全”处理。
// 字符列按 UTF-16 每字符 2 字节；二进制列按声明长度；NVARCHAR(MAX)/VARBINARY(MAX)
// 视为超预算。
func indexColumnBytes(column *columnInfo) int {
	if column.MappedType == "" {
		return indexEntryLimit + 1
	}
	target := strings.ToUpper(column.MappedType)
	switch {
	case strings.HasPrefix(target, "VARBINARY(MAX)"), strings.HasPrefix(target, "NVARCHAR(MAX)"):
		return indexEntryLimit + 1
	case strings.HasPrefix(target, "VARBINARY("):
		length := 0
		fmt.Sscanf(target[len("VARBINARY("):], "%d", &length)
		if length == 0 {
			return indexEntryLimit + 1
		}
		return length
	case strings.HasPrefix(target, "NVARCHAR("):
		length := 0
		fmt.Sscanf(target[len("NVARCHAR("):], "%d", &length)
		if length == 0 {
			return indexEntryLimit + 1
		}
		return length * bytesPerCharWorstCase
	case strings.HasPrefix(target, "BIGINT"), strings.HasPrefix(target, "FLOAT"):
		return 8
	default:
		return indexEntryLimit + 1
	}
}

// indexExpressions 生成索引列表达式，超过预算的键列用 HASHBYTES 摘要计算列。
func (t *translator) indexExpressions(table *tableInfo, columns []string) (string, error) {
	used := 0
	expressions := make([]string, 0, len(columns))
	for _, name := range columns {
		column := table.column(name)
		if column == nil {
			return "", fmt.Errorf("索引引用了表 %s 的未知列 %s", table.Name, name)
		}
		size := indexColumnBytes(column)
		if used+size > indexEntryLimit {
			hashName, err := t.hashNameForColumn(table, name)
			if err != nil {
				return "", err
			}
			expressions = append(expressions, "["+hashName+"]")
			used += hashBytes
			continue
		}
		expressions = append(expressions, "["+name+"]")
		used += size
	}
	return strings.Join(expressions, ", "), nil
}

var createIndexPattern = regexp.MustCompile(`(?is)^CREATE\s+(UNIQUE\s+)?INDEX\s+([A-Za-z0-9_]+)\s+ON\s+([A-Za-z0-9_]+)\s*\(([^)]*(?:\([^)]*\)[^)]*)*)\)(.*)$`)

func (t *translator) emitCreateIndex(statement string) (string, error) {
	trimmed := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(statement), ";"))
	match := createIndexPattern.FindStringSubmatch(trimmed)
	if match == nil {
		return "", fmt.Errorf("无法解析 CREATE INDEX: %s", snippet(statement))
	}
	unique := strings.TrimSpace(match[1]) != ""
	name := match[2]
	tableName := strings.Trim(match[3], "\"`[]")
	table := t.model.live[t.model.resolveName(tableName)]
	if table == nil {
		table = t.model.creation[tableName]
	}
	if table == nil {
		return "", fmt.Errorf("索引 %s 引用了未知表 %s", name, match[3])
	}
	parts := splitTopLevel(match[4], ',')
	plainNames := make([]string, 0, len(parts))
	orders := make([]bool, 0, len(parts))
	for _, part := range parts {
		fields := strings.Fields(strings.TrimSpace(part))
		if len(fields) == 0 {
			continue
		}
		plainNames = append(plainNames, strings.Trim(fields[0], "[`\""))
		desc := len(fields) > 1 && strings.EqualFold(fields[1], "DESC")
		orders = append(orders, desc)
	}
	if len(plainNames) == 0 {
		return "", fmt.Errorf("索引 %s 没有列", name)
	}
	used := 0
	expressions := make([]string, 0, len(plainNames))
	for position, columnName := range plainNames {
		column := table.column(columnName)
		if column == nil {
			// 表达式索引（当前迁移没有此类写法）原样保留，交由 SQL Server 判定。
			expressions = append(expressions, columnName)
			continue
		}
		size := indexColumnBytes(column)
		expression := "[" + columnName + "]"
		if used+size > indexEntryLimit {
			hashName, err := t.hashNameForColumn(table, columnName)
			if err != nil {
				return "", err
			}
			expression = "[" + hashName + "]"
			used += hashBytes
		} else {
			used += size
		}
		if orders[position] {
			expression += " DESC"
		}
		expressions = append(expressions, expression)
	}
	suffix := ""
	if where := strings.TrimSpace(match[5]); where != "" {
		upper := strings.ToUpper(where)
		if !strings.HasPrefix(upper, "WHERE") {
			return "", fmt.Errorf("索引 %s 的过滤条件无法解析: %s", name, snippet(where))
		}
		expression := strings.TrimSpace(where[len("WHERE"):])
		translated, err := translateCheckExpression(expression, table)
		if err != nil {
			return "", err
		}
		suffix = " WHERE " + translated
	}
	prefix := "CREATE INDEX "
	if unique {
		prefix = "CREATE UNIQUE INDEX "
	}
	return prefix + "[" + name + "] ON [" + tableName + "] (" +
		strings.Join(expressions, ", ") + ")" + suffix, nil
}

// ---------------------------------------------------------------------------
// 触发器：SQLite BEFORE ... SELECT RAISE(ABORT, ...) END 翻译为 AFTER 触发器 +
// THROW（语句级集合判断 inserted/deleted）。SQL Server 没有 BEFORE 触发器；
// AFTER 触发器抛错会回滚触发语句，append-only 语义保留。
//
// 唯一的 BEFORE INSERT “禁止 INSERT OR REPLACE 替换既有行”触发器无法用 AFTER
// 集合触发器等价表达（NEW 行插入后无法判断插入前是否已存在）。T-SQL 本身没有
// INSERT OR REPLACE 语法、不存在替换风险，因此该触发器明确不翻译（登记为语义
// 不可用，而不是生成错误触发器）；由 static 测试断言跳过的是该触发器。
// ---------------------------------------------------------------------------

var triggerPattern = regexp.MustCompile(`(?is)^CREATE\s+TRIGGER\s+([A-Za-z0-9_]+)\s+(BEFORE|AFTER)\s+(INSERT|UPDATE|DELETE)\s+ON\s+([A-Za-z0-9_]+)\s+(?:WHEN\s+(.+?)\s+)?BEGIN\s+SELECT\s+RAISE\s*\(\s*ABORT\s*,\s*'((?:[^']|'')*)'\s*\)\s*;\s*END\s*;?\s*$`)

func translateTrigger(statement string, model *schemaModel) ([]string, error) {
	trimmed := strings.TrimSpace(statement)
	match := triggerPattern.FindStringSubmatch(trimmed)
	if match == nil {
		return nil, fmt.Errorf("不支持的触发器形式: %s", snippet(statement))
	}
	name := match[1]
	event := strings.ToUpper(match[3])
	table := match[4]
	when := strings.TrimSpace(match[5])
	message := strings.ReplaceAll(match[6], "'", "''")
	if event == "INSERT" && when != "" && strings.Contains(strings.ToUpper(when), "NEW.") {
		// 语义不可用：见函数注释。
		return nil, nil
	}
	pseudo := "inserted"
	if event == "DELETE" {
		pseudo = "deleted"
	}
	var tableInfo *tableInfo
	if model != nil {
		tableInfo = model.live[model.resolveName(table)]
	}
	var body strings.Builder
	body.WriteString("CREATE TRIGGER [" + name + "] ON [" + table + "] AFTER " + event + " AS\nBEGIN\n")
	body.WriteString("  SET NOCOUNT ON;\n")
	condition := ""
	if when != "" {
		translated, err := translateCheckExpression(when, tableInfo)
		if err != nil {
			return nil, fmt.Errorf("触发器 %s 的 WHEN 条件翻译失败: %w", name, err)
		}
		condition = translated
	}
	if condition != "" {
		body.WriteString("  IF EXISTS (SELECT 1 FROM " + pseudo + " WHERE " + condition + ")\n")
	} else {
		body.WriteString("  IF EXISTS (SELECT 1 FROM " + pseudo + ")\n")
	}
	body.WriteString("  BEGIN\n")
	body.WriteString("    ;THROW 50000, N'" + message + "', 1;\n")
	body.WriteString("  END\nEND")
	return []string{body.String()}, nil
}

// ---------------------------------------------------------------------------
// whole-file 脚本拆分与校验
// ---------------------------------------------------------------------------

// splitWholeFileScript 把 whole-file 迁移拆成语句：触发器 BEGIN...END 内的分号不是
// 语句分隔符；没有触发器的 whole-file 文件退回 migrate.SplitStatements。
func splitWholeFileScript(script string) ([]string, error) {
	if !strings.Contains(strings.ToUpper(script), "CREATE TRIGGER") {
		return migrate.SplitStatements(script)
	}
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
			if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(builder.String())), "CREATE TRIGGER") {
				inTrigger = true
				blockDepth = 0
			}
			index++
			continue
		}
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
	if len(statements) == 0 {
		return nil, fmt.Errorf("whole-file 迁移没有可执行语句")
	}
	return statements, nil
}

// validateTranslated 对翻译结果做不变量检查，防止 SQLite 语法泄漏到 SQL Server
// 迁移。迁移 DDL 与仓储 SQL 是两条独立路径：这里检查生成结果，仓储重写器另有
// 自己的 fail-closed 禁用词表。
func validateTranslated(statements []string) error {
	forbidden := []string{
		"PRAGMA ", "json_valid(", "AUTOINCREMENT", "INSERT OR ", "RAISE(", "WITHOUT ROWID",
		"`", "julianday", "strftime", "json_extract", "json_each", "GLOB", "ISNULL(",
		"IFNULL(", "IIF(", "||", " COLLATE \"C\"", " BYTEA", "TEXT NOT NULL", "TEXT PRIMARY KEY",
	}
	for _, statement := range statements {
		for _, token := range forbidden {
			if strings.Contains(statement, token) {
				return fmt.Errorf("翻译结果仍含 SQLite 语法 %q: %s", token, snippet(statement))
			}
		}
		if regexp.MustCompile(`(?i)(^|[^_A-Za-z0-9])rowid([^_A-Za-z0-9]|$)`).MatchString(statement) {
			return fmt.Errorf("翻译结果仍含裸 rowid: %s", snippet(statement))
		}
		if strings.Contains(statement, "CREATE TRIGGER") {
			continue
		}
		// 除触发器外，语句不得出现 SQLite 的 BEGIN...END 复合块或多语句批。
		if regexp.MustCompile(`(?i)\bBEGIN\b\s*$`).MatchString(strings.TrimSpace(statement)) {
			return fmt.Errorf("翻译结果含未拆分复合语句: %s", snippet(statement))
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// 词法辅助
// ---------------------------------------------------------------------------

func leadingKeyword(statement string) string {
	fields := strings.Fields(strings.TrimSpace(statement))
	switch {
	case len(fields) >= 2 && strings.EqualFold(fields[0], "CREATE") && strings.EqualFold(fields[1], "TABLE"):
		return "CREATE TABLE"
	case len(fields) >= 2 && strings.EqualFold(fields[0], "CREATE") && strings.EqualFold(fields[1], "INDEX"):
		return "CREATE INDEX"
	case len(fields) >= 3 && strings.EqualFold(fields[0], "CREATE") && strings.EqualFold(fields[1], "UNIQUE") && strings.EqualFold(fields[2], "INDEX"):
		return "CREATE UNIQUE INDEX"
	case len(fields) >= 2 && strings.EqualFold(fields[0], "CREATE") && strings.EqualFold(fields[1], "TRIGGER"):
		return "CREATE TRIGGER"
	case len(fields) >= 2 && strings.EqualFold(fields[0], "ALTER") && strings.EqualFold(fields[1], "TABLE"):
		return "ALTER TABLE"
	case len(fields) >= 2 && strings.EqualFold(fields[0], "DROP") && strings.EqualFold(fields[1], "TABLE"):
		return "DROP TABLE"
	case len(fields) >= 2 && strings.EqualFold(fields[0], "INSERT") && strings.EqualFold(fields[1], "INTO"):
		return "INSERT INTO"
	case len(fields) >= 3 && strings.EqualFold(fields[0], "INSERT") && strings.EqualFold(fields[1], "OR") && strings.EqualFold(fields[2], "IGNORE"):
		return "INSERT OR IGNORE INTO"
	default:
		return ""
	}
}

func readIdentifier(text string) (string, string) {
	text = strings.TrimSpace(text)
	if text == "" {
		return "", ""
	}
	if text[0] == '"' || text[0] == '`' || text[0] == '[' {
		closeChar := byte('"')
		switch text[0] {
		case '`':
			closeChar = '`'
		case '[':
			closeChar = ']'
		}
		if end := strings.IndexByte(text[1:], closeChar); end >= 0 {
			return text[1 : 1+end], text[2+end:]
		}
		return text[1:], ""
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
			columns = append(columns, strings.Trim(fields[0], "\"`[]"))
		}
	}
	return columns
}

func joinQuoted(columns []string) string {
	quoted := make([]string, 0, len(columns))
	for _, column := range columns {
		quoted = append(quoted, "["+strings.Trim(column, "[]")+"]")
	}
	return strings.Join(quoted, ", ")
}

// constraintName 生成确定性的约束/索引名；SQL Server 标识符上限 128 字符。
func constraintName(prefix, suffix string) string {
	name := prefix + "_" + suffix
	name = strings.NewReplacer(" ", "_", ".", "_", "-", "_", ",", "_").Replace(name)
	if len(name) > 120 {
		name = name[:120]
	}
	return name
}

func splitTopLevel(text string, separator byte) []string {
	var parts []string
	var builder strings.Builder
	depth := 0
	for index := 0; index < len(text); index++ {
		switch text[index] {
		case '\'', '"', '`':
			end, ok := skipQuoted(text, index)
			if !ok {
				builder.WriteString(text[index:])
				index = len(text)
				continue
			}
			builder.WriteString(text[index : end+1])
			index = end
			continue
		case '(':
			depth++
		case ')':
			depth--
		case separator:
			if depth == 0 {
				parts = append(parts, strings.TrimSpace(builder.String()))
				builder.Reset()
				continue
			}
		}
		builder.WriteByte(text[index])
	}
	if statement := strings.TrimSpace(builder.String()); statement != "" {
		parts = append(parts, statement)
	}
	return parts
}

func matchingParen(text string, open int) (int, error) {
	depth := 0
	for index := open; index < len(text); index++ {
		switch text[index] {
		case '\'', '"', '`':
			end, ok := skipQuoted(text, index)
			if !ok {
				return -1, fmt.Errorf("字符串未闭合")
			}
			index = end
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return index, nil
			}
		}
	}
	return -1, fmt.Errorf("括号未闭合")
}

func parenthesizedAfter(text, prefix string) (string, error) {
	index := findWord(text, prefix)
	if index < 0 {
		return "", fmt.Errorf("缺少 %s 子句", prefix)
	}
	rest := text[index+len(prefix):]
	open := strings.Index(rest, "(")
	if open < 0 {
		return "", fmt.Errorf("%s 缺少括号", prefix)
	}
	open += index + len(prefix)
	closeIndex, err := matchingParen(text, open)
	if err != nil {
		return "", err
	}
	return text[open+1 : closeIndex], nil
}

func findWord(text, word string) int {
	for index := 0; index+len(word) <= len(text); index++ {
		if hasWordAt(text, index, word) {
			return index
		}
	}
	return -1
}

func hasWordAt(text string, index int, word string) bool {
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

func boundaryBefore(text string, index int) bool {
	return index == 0 || !isIdentChar(text[index-1])
}

func isWordAt(text string, index int, word string) bool { return hasWordAt(text, index, word) }

func isIdentChar(character byte) bool {
	return character == '_' || (character >= 'a' && character <= 'z') ||
		(character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9')
}

func isIdentStart(character byte) bool {
	return character == '_' || (character >= 'a' && character <= 'z') ||
		(character >= 'A' && character <= 'Z')
}

func skipQuoted(text string, start int) (int, bool) {
	quote := text[start]
	for index := start + 1; index < len(text); index++ {
		if text[index] == quote {
			if index+1 < len(text) && text[index+1] == quote {
				index++
				continue
			}
			return index, true
		}
	}
	return len(text), false
}

func snippet(text string) string {
	text = strings.Join(strings.Fields(text), " ")
	if len(text) > 160 {
		return text[:157] + "..."
	}
	return text
}
