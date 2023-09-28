// Package sqlserver 提供 SQL Server（T-SQL）的存储方言、迁移后端与在线备份能力声明。
//
// 与 internal/storage/mysql、internal/storage/postgres 同一设计模式：不复制业务仓储
// 代码，仓储 SQL 经由 database/sql 驱动连接器在 Prepare 层做 SQLite -> T-SQL 方言
// 重写；迁移 DDL 使用未重写的原始连接池单独执行。
//
// 本包只做静态、编译与 SQL 生成/参数化检查；首次版本不启动 SQL Server、容器或云
// 实例，也没有连接真实数据库的运行验证。任何“SQL Server 兼容性已验证”的说法都
// 不成立。
//
// 实现边界：
//   - 方言：? -> @p1..@pn 命名参数、INSERT OR IGNORE -> MERGE（冲突键来自已提交
//     迁移的主键）、ON CONFLICT ... DO NOTHING/DO UPDATE -> MERGE ... WITH
//     (HOLDLOCK)、裸 rowid -> [_rowid]、LIMIT/OFFSET -> OFFSET ... FETCH NEXT。
//     无法等价翻译的 SQLite 语法在 Prepare 阶段显式报错（fail-closed）；RETURNING
//     明确登记为未实现能力（T-SQL 需改写为 OUTPUT，当前仓储未使用）。
//   - 迁移：由 migrations/sqlserver 从已提交 SQLite 迁移确定性翻译；Backend 使用
//     sp_getapplock 做跨连接排他锁，逐条迁移放在单事务内执行并记录
//     schema_history/schema_failures；执行器按行首 GO 拆分批次（驱动不支持 GO）。
//   - 服务器校验：Microsoft SQL Server 版本/引擎/数据库状态/读写能力/会话 SET 选项，
//     任一不满足即拒绝，不降级。
//   - 在线备份：明确不支持（ErrOnlineBackupUnsupported），不生成假备份。
package sqlserver

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ConflictKeyResolver 为 INSERT OR IGNORE（SQLite 忽略任意冲突的写法）解析目标表的
// 主键列。SQLite 的 INSERT OR IGNORE 没有冲突目标，T-SQL MERGE 必须显式指定 ON
// 条件，因此由调用方提供来自已提交迁移的主键定义（生产为
// migrations/sqlserver.PrimaryKeyColumns），而不是在重写器里猜测。
type ConflictKeyResolver func(table string) ([]string, error)

// TranslateRepositorySQL 把既有仓储 SQL 中的 SQLite 方言确定性翻译为 T-SQL。
//
// 已实现且经过单测/仓储源码审计的转换：
//   - ? -> @p1..@pn（引号、方括号标识符、注释内不转换；禁止混用既有 @ 参数）
//   - INSERT OR IGNORE INTO -> MERGE ... WITH (HOLDLOCK) WHEN NOT MATCHED THEN INSERT
//     （冲突键通过 resolver 从主键解析；MERGE 带 HOLDLOCK 以串行化并发冲突）
//   - ON CONFLICT (...) DO NOTHING / DO UPDATE SET -> MERGE ...（excluded.x ->
//     source.[x]、表名限定的目标列 -> target.[x]；带 HOLDLOCK 防止并发 MERGE 竞争）
//   - 裸 rowid -> [_rowid]（迁移为 4 张使用 rowid 的表追加 _rowid 代理列）
//   - LIMIT n [OFFSET m] -> OFFSET m ROWS FETCH NEXT n ROWS ONLY；同一查询没有
//     ORDER BY 时补 ORDER BY (SELECT NULL)（SQLite 无 ORDER BY 的 LIMIT 本来就是
//     未定义顺序；OFFSET/FETCH 在 T-SQL 中强制要求 ORDER BY）
//
// 翻译后仍残留 SQLite 专有语法时返回错误，绝不猜测翻译。
func TranslateRepositorySQL(query string, resolver ConflictKeyResolver) (string, error) {
	result, err := convertPlaceholders(query)
	if err != nil {
		return "", err
	}
	// RETURNING 不是 SQLite 专有语法，但 T-SQL 需要改写为 OUTPUT 子句。SQL Server 适配器
	// 未实现该改写；必须在任何 INSERT/ON CONFLICT 改写之前显式拒绝，避免尾随子句被静默
	// 丢弃（当前 42 个仓储包没有 RETURNING 用法）。
	if index := topLevelKeyword(result, "RETURNING"); index >= 0 {
		return "", fmt.Errorf("T-SQL 不支持 RETURNING，需要改写为 OUTPUT；本适配器未实现该能力（当前仓储未使用），拒绝猜测")
	}
	lowered := strings.ToLower(result)
	if containsWord(lowered, "insert or") {
		result, err = rewriteInsertOrIgnore(result, resolver)
		if err != nil {
			return "", err
		}
	} else if index := topLevelKeyword(result, "ON CONFLICT"); index >= 0 {
		result, err = rewriteOnConflict(result)
		if err != nil {
			return "", err
		}
	}
	if hasWithoutRowid(result) {
		return "", fmt.Errorf("无法等价翻译的 SQLite 语法 %q；拒绝猜测，请移植该仓储 SQL", "WITHOUT ROWID")
	}
	if containsWord(strings.ToLower(result), "rowid") {
		result = replaceBareRowid(result)
	}
	if containsWord(strings.ToLower(result), "limit") {
		result, err = rewriteLimitOffsets(result)
		if err != nil {
			return "", err
		}
	}
	if err := rejectLeftoverSQLite(result); err != nil {
		return "", err
	}
	if err := validateParameterSequence(query, result); err != nil {
		return "", err
	}
	return result, nil
}

// validateParameterSequence 校验翻译前后的参数数量一致、@pN 从 1 连续编号且不重复。
// T-SQL 命名参数可以出现在文本任意位置（MERGE 的 source/ON/SET 会重排文本），因此
// 只按编号集合校验，而不是按出现顺序。
func validateParameterSequence(original, translated string) error {
	expected := 0
	for index := 0; index < len(original); index++ {
		switch original[index] {
		case '\'', '"', '`':
			end, ok := skipQuoted(original, index)
			if !ok {
				return fmt.Errorf("原始 SQL 含未闭合引号")
			}
			index = end
			continue
		case '[':
			end, ok := skipBracket(original, index)
			if !ok {
				return fmt.Errorf("原始 SQL 含未闭合方括号标识符")
			}
			index = end
			continue
		case '-':
			if index+1 < len(original) && original[index+1] == '-' {
				end := strings.IndexByte(original[index:], '\n')
				if end < 0 {
					index = len(original)
					continue
				}
				index += end
				continue
			}
		case '/':
			if index+1 < len(original) && original[index+1] == '*' {
				end := strings.Index(original[index+2:], "*/")
				if end < 0 {
					return fmt.Errorf("原始 SQL 含未结束块注释")
				}
				index += 2 + end + 1
				continue
			}
		case '?':
			expected++
		}
	}
	seen := map[int]bool{}
	maximum := 0
	for index := 0; index < len(translated); index++ {
		switch translated[index] {
		case '\'', '"', '`':
			end, ok := skipQuoted(translated, index)
			if !ok {
				return fmt.Errorf("翻译结果含未闭合引号")
			}
			index = end
			continue
		case '[':
			end, ok := skipBracket(translated, index)
			if !ok {
				return fmt.Errorf("翻译结果含未闭合方括号标识符")
			}
			index = end
			continue
		case '-':
			if index+1 < len(translated) && translated[index+1] == '-' {
				end := strings.IndexByte(translated[index:], '\n')
				if end < 0 {
					index = len(translated)
					continue
				}
				index += end
				continue
			}
		case '/':
			if index+1 < len(translated) && translated[index+1] == '*' {
				end := strings.Index(translated[index+2:], "*/")
				if end < 0 {
					return fmt.Errorf("翻译结果含未结束块注释")
				}
				index += 2 + end + 1
				continue
			}
		}
		if translated[index] != '@' {
			continue
		}
		end := index + 1
		for end < len(translated) && isIdentChar(translated[end]) {
			end++
		}
		token := translated[index+1 : end]
		if len(token) < 2 || token[0] != 'p' {
			return fmt.Errorf("翻译结果含非 @pN 参数 %q；拒绝混用", "@"+token)
		}
		number, err := strconv.Atoi(token[1:])
		if err != nil {
			return fmt.Errorf("翻译结果参数编号不合法")
		}
		if seen[number] {
			return fmt.Errorf("翻译结果参数 @p%d 重复；拒绝猜测", number)
		}
		seen[number] = true
		if number > maximum {
			maximum = number
		}
		index = end - 1
	}
	if len(seen) != expected || maximum != expected {
		return fmt.Errorf("翻译前后参数数量不一致（原文 ?=%d，结果 @pN=%d，最大编号 %d）", expected, len(seen), maximum)
	}
	for number := 1; number <= expected; number++ {
		if !seen[number] {
			return fmt.Errorf("翻译结果缺少参数 @p%d；拒绝发送", number)
		}
	}
	return nil
}

// CheckForbiddenSQLiteDialect 只做禁用词检查（不尝试翻译、不要求语句完整），供静态
// 审计对“不含方言标记的标准 SQL/拼接片段”做同样的拒绝而非跳过检查。
func CheckForbiddenSQLiteDialect(query string) error {
	return rejectLeftoverSQLite(query)
}

// ---------------------------------------------------------------------------
// INSERT OR IGNORE / ON CONFLICT -> MERGE
// ---------------------------------------------------------------------------

type insertStatement struct {
	table   string
	columns []string
	// values 是 VALUES 形式的表达式列表；selectSQL 非空表示 INSERT ... SELECT 形式
	// （两者恰有一个非空）。
	values    []string
	selectSQL string
}

// parseInsert 解析 INSERT [OR IGNORE] INTO 表 (列) [VALUES (值) | SELECT ...] 的
// 前半部分，返回 INSERT 之后的位置（用于继续解析 ON CONFLICT）。
func parseInsert(query string) (insertStatement, int, error) {
	var parsed insertStatement
	index := topLevelKeyword(query, "INSERT")
	if index < 0 {
		return parsed, 0, fmt.Errorf("无法定位 INSERT")
	}
	position := index + len("INSERT")
	skipSpaces := func() {
		for position < len(query) && (query[position] == ' ' || query[position] == '\n' ||
			query[position] == '\t' || query[position] == '\r') {
			position++
		}
	}
	readWord := func(word string) bool {
		skipSpaces()
		if position+len(word) <= len(query) && strings.EqualFold(query[position:position+len(word)], word) {
			position += len(word)
			return true
		}
		return false
	}
	skipSpaces()
	if strings.HasPrefix(strings.ToLower(query[position:]), "or ignore") {
		position += len("or ignore")
	}
	if !readWord("INTO") {
		return parsed, 0, fmt.Errorf("INSERT 缺少 INTO")
	}
	skipSpaces()
	table, next := readIdentifierToken(query, position)
	if table == "" {
		return parsed, 0, fmt.Errorf("INSERT 缺少目标表")
	}
	parsed.table = table
	position = next
	skipSpaces()
	if position >= len(query) || query[position] != '(' {
		return parsed, 0, fmt.Errorf("INSERT 缺少列表；拒绝猜测列顺序")
	}
	closeIndex, err := matchingParen(query, position)
	if err != nil {
		return parsed, 0, err
	}
	parsed.columns = splitIdentifierList(query[position+1 : closeIndex])
	position = closeIndex + 1
	skipSpaces()
	if position+len("VALUES") <= len(query) && strings.EqualFold(query[position:position+len("VALUES")], "VALUES") {
		position += len("VALUES")
		skipSpaces()
		if position >= len(query) || query[position] != '(' {
			return parsed, 0, fmt.Errorf("INSERT VALUES 缺少括号")
		}
		closeIndex, err = matchingParen(query, position)
		if err != nil {
			return parsed, 0, err
		}
		parsed.values = splitTopLevel(query[position+1:closeIndex], ',')
		if len(parsed.values) != len(parsed.columns) {
			return parsed, 0, fmt.Errorf("INSERT 列数与值数不一致")
		}
		position = closeIndex + 1
		// VALUES 之后只允许空白或结尾分号；任何其它子句（例如 RETURNING）都必须显式
		// 报错，不能被 upsert 改写静默丢弃。
		if trailing := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(query[position:]), ";")); trailing != "" {
			return parsed, 0, fmt.Errorf("INSERT 在 VALUES 之后含未实现子句 %q；拒绝静默丢弃（RETURNING 需改写为 OUTPUT）", snippet(trailing))
		}
		return parsed, position, nil
	}
	if position+len("SELECT") <= len(query) && strings.EqualFold(query[position:position+len("SELECT")], "SELECT") {
		selectSQL := strings.TrimSpace(query[position:])
		selectSQL = strings.TrimSpace(strings.TrimSuffix(selectSQL, ";"))
		if selectSQL == "" {
			return parsed, 0, fmt.Errorf("INSERT SELECT 缺少查询")
		}
		parsed.selectSQL = selectSQL
		return parsed, len(query), nil
	}
	return parsed, 0, fmt.Errorf("INSERT 仅支持 VALUES 或 SELECT 形式")
}

// aliasSelectColumns 给 INSERT ... SELECT 的投影列表逐项加 AS 列名，使 MERGE 的
// USING 派生表可以用 source.[列名] 引用。投影项数必须与 INSERT 列表一致；投影项
// 已含顶层 AS 别名时 fail-closed（当前仓储不使用）。
func aliasSelectColumns(selectSQL string, columns []string) (string, error) {
	trimmed := strings.TrimSpace(selectSQL)
	if len(trimmed) < len("SELECT") || !strings.EqualFold(trimmed[:len("SELECT")], "SELECT") {
		return "", fmt.Errorf("INSERT SELECT 必须以 SELECT 开头")
	}
	rest := trimmed[len("SELECT"):]
	depth := 0
	end := len(rest)
	keywords := []string{"FROM", "WHERE", "GROUP", "ORDER", "HAVING", "UNION", "EXCEPT", "INTERSECT"}
	for index := 0; index < len(rest); index++ {
		switch rest[index] {
		case '\'', '"', '`':
			endIndex, ok := skipQuoted(rest, index)
			if !ok {
				return "", fmt.Errorf("INSERT SELECT 含未闭合引号")
			}
			index = endIndex
			continue
		case '[':
			endIndex, ok := skipBracket(rest, index)
			if !ok {
				return "", fmt.Errorf("INSERT SELECT 含未闭合方括号标识符")
			}
			index = endIndex
			continue
		case '(':
			depth++
			continue
		case ')':
			depth--
			continue
		}
		if depth != 0 {
			continue
		}
		for _, keyword := range keywords {
			if hasWordAt(rest, index, keyword) {
				end = index
				break
			}
		}
		if end != len(rest) {
			break
		}
	}
	items := splitTopLevel(rest[:end], ',')
	if len(items) != len(columns) {
		return "", fmt.Errorf("INSERT SELECT 投影列数 %d 与 INSERT 列数 %d 不一致", len(items), len(columns))
	}
	aliased := make([]string, 0, len(items))
	for index, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			return "", fmt.Errorf("INSERT SELECT 有空投影项")
		}
		if topLevelKeyword(item, "AS") >= 0 {
			return "", fmt.Errorf("INSERT SELECT 投影项自带 AS 别名，未实现该形式的 MERGE 翻译")
		}
		aliased = append(aliased, item+" AS ["+columns[index]+"]")
	}
	remainder := rest[end:]
	if remainder != "" && !strings.HasPrefix(remainder, " ") && !strings.HasPrefix(remainder, "\n") &&
		!strings.HasPrefix(remainder, "\t") && !strings.HasPrefix(remainder, "\r") {
		remainder = " " + remainder
	}
	return "SELECT " + strings.Join(aliased, ", ") + remainder, nil
}

// rewriteInsertOrIgnore 把 INSERT OR IGNORE 改写为 MERGE ... WHEN NOT MATCHED THEN
// INSERT（冲突键 = 目标表主键，由 resolver 提供）。MERGE 使用 HOLDLOCK 防止并发
// 会话在“未匹配”判断上产生竞争：潜在的重复键错误仍由唯一约束兜底（fail-closed）。
func rewriteInsertOrIgnore(query string, resolver ConflictKeyResolver) (string, error) {
	parsed, _, err := parseInsert(query)
	if err != nil {
		return "", fmt.Errorf("INSERT OR IGNORE 翻译失败: %w", err)
	}
	if resolver == nil {
		return "", fmt.Errorf("INSERT OR IGNORE 需要冲突键解析器（目标表主键），不能猜测翻译")
	}
	conflictKeys, err := resolver(parsed.table)
	if err != nil {
		return "", fmt.Errorf("INSERT OR IGNORE 目标表 %s 的冲突键未解析: %w", parsed.table, err)
	}
	if len(conflictKeys) == 0 {
		return "", fmt.Errorf("INSERT OR IGNORE 目标表 %s 没有主键，无法等价翻译", parsed.table)
	}
	return buildMerge(parsed, conflictKeys, "")
}

// rewriteOnConflict 把 ON CONFLICT (...) DO NOTHING / DO UPDATE SET ... 改写为 MERGE。
func rewriteOnConflict(query string) (string, error) {
	conflictIndex := topLevelKeyword(query, "ON CONFLICT")
	if conflictIndex < 0 {
		return "", fmt.Errorf("无法定位 ON CONFLICT")
	}
	insertPart := strings.TrimSpace(query[:conflictIndex])
	// 去掉语句末尾分号（由重写结果重新添加）。
	insertPart = strings.TrimSpace(strings.TrimSuffix(insertPart, ";"))
	parsed, _, err := parseInsert(insertPart)
	if err != nil {
		return "", fmt.Errorf("ON CONFLICT 翻译失败: %w", err)
	}
	position := conflictIndex + len("ON CONFLICT")
	skip := func() {
		for position < len(query) && (query[position] == ' ' || query[position] == '\n' ||
			query[position] == '\t' || query[position] == '\r') {
			position++
		}
	}
	skip()
	if position >= len(query) || query[position] != '(' {
		return "", fmt.Errorf("ON CONFLICT 缺少冲突目标列")
	}
	closeIndex, err := matchingParen(query, position)
	if err != nil {
		return "", err
	}
	conflictKeys := splitIdentifierList(query[position+1 : closeIndex])
	position = closeIndex + 1
	skip()
	// SQLite 的冲突目标可携带 partial unique index 的 WHERE 谓词；MERGE 的 ON 条件
	// 已按冲突键构造，谓词只用于 SQLite 索引选择。跳过它，但其余尾随子句仍 fail-closed。
	if strings.HasPrefix(strings.ToUpper(query[position:]), "WHERE ") {
		doIndex := topLevelKeyword(query[position:], "DO")
		if doIndex < 0 {
			return "", fmt.Errorf("ON CONFLICT ... WHERE 后缺少 DO 子句")
		}
		position += doIndex
		skip()
	}
	upperRest := strings.ToUpper(query[position:])
	if !strings.HasPrefix(upperRest, "DO ") {
		return "", fmt.Errorf("ON CONFLICT 后缺少 DO 子句")
	}
	position += len("DO")
	skip()
	var updateSet string
	switch {
	case strings.HasPrefix(strings.ToUpper(query[position:]), "NOTHING"):
		position += len("NOTHING")
		if trailing := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(query[position:]), ";")); trailing != "" {
			return "", fmt.Errorf("ON CONFLICT DO NOTHING 之后含未实现子句 %q；拒绝静默丢弃（RETURNING 需改写为 OUTPUT）", snippet(trailing))
		}
	case strings.HasPrefix(strings.ToUpper(query[position:]), "UPDATE"):
		position += len("UPDATE")
		skip()
		if position+len("SET") > len(query) || !strings.EqualFold(query[position:position+len("SET")], "SET") {
			return "", fmt.Errorf("ON CONFLICT DO UPDATE 缺少 SET")
		}
		position += len("SET")
		updateSet = strings.TrimSpace(query[position:])
		updateSet = strings.TrimRight(updateSet, "; \t\r\n")
		if index := topLevelSemicolon(updateSet); index >= 0 {
			return "", fmt.Errorf("ON CONFLICT DO UPDATE SET 之后含未实现子句 %q；拒绝静默丢弃",
				snippet(strings.TrimSpace(updateSet[index+1:])))
		}
		// SQLite 的 DO UPDATE 可带 WHERE；仓储未使用，fail-closed。
		if topLevelKeyword(updateSet, "WHERE") >= 0 {
			return "", fmt.Errorf("ON CONFLICT DO UPDATE ... WHERE 未实现翻译；请移植该仓储 SQL")
		}
	default:
		return "", fmt.Errorf("不支持的 ON CONFLICT 动作")
	}
	return buildMerge(parsed, conflictKeys, updateSet)
}

// buildMerge 生成 T-SQL MERGE 语句。updateSet 为空表示 DO NOTHING。
func buildMerge(parsed insertStatement, conflictKeys []string, updateSet string) (string, error) {
	columnSet := make(map[string]bool, len(parsed.columns))
	for _, column := range parsed.columns {
		columnSet[strings.ToLower(column)] = true
	}
	for _, key := range conflictKeys {
		if !columnSet[strings.ToLower(key)] {
			return "", fmt.Errorf("冲突键列 %s 不在 INSERT 列表中，无法构造 MERGE ON 条件", key)
		}
	}
	var sourceSQL string
	if parsed.selectSQL != "" {
		aliased, err := aliasSelectColumns(parsed.selectSQL, parsed.columns)
		if err != nil {
			return "", err
		}
		sourceSQL = aliased
	} else {
		sourceItems := make([]string, 0, len(parsed.columns))
		for index, column := range parsed.columns {
			sourceItems = append(sourceItems, strings.TrimSpace(parsed.values[index])+" AS ["+column+"]")
		}
		sourceSQL = "SELECT " + strings.Join(sourceItems, ", ")
	}
	var builder strings.Builder
	builder.WriteString("MERGE INTO [" + parsed.table + "] WITH (HOLDLOCK) AS target USING (" + sourceSQL +
		") AS source ON ")
	onTerms := make([]string, 0, len(conflictKeys))
	for _, key := range conflictKeys {
		onTerms = append(onTerms, "target.["+key+"] = source.["+key+"]")
	}
	builder.WriteString(strings.Join(onTerms, " AND "))
	if strings.TrimSpace(updateSet) != "" {
		assignments := splitTopLevel(updateSet, ',')
		if len(assignments) == 0 {
			return "", fmt.Errorf("ON CONFLICT DO UPDATE SET 没有赋值")
		}
		rendered := make([]string, 0, len(assignments))
		for _, assignment := range assignments {
			equals := strings.Index(assignment, "=")
			if equals <= 0 {
				return "", fmt.Errorf("无法解析 ON CONFLICT DO UPDATE 赋值: %s", snippet(assignment))
			}
			column := strings.TrimSpace(strings.Trim(assignment[:equals], "[]`\""))
			if !columnSet[strings.ToLower(column)] {
				return "", fmt.Errorf("ON CONFLICT DO UPDATE SET 的列 %s 不在 INSERT 列表中", column)
			}
			expression := strings.TrimSpace(assignment[equals+1:])
			transformed, err := qualifyTargetExpression(expression, parsed.table, columnSet)
			if err != nil {
				return "", err
			}
			rendered = append(rendered, "["+column+"] = "+transformed)
		}
		builder.WriteString(" WHEN MATCHED THEN UPDATE SET " + strings.Join(rendered, ", "))
	}
	insertColumns := make([]string, 0, len(parsed.columns))
	sourceColumns := make([]string, 0, len(parsed.columns))
	for _, column := range parsed.columns {
		insertColumns = append(insertColumns, "["+column+"]")
		sourceColumns = append(sourceColumns, "source.["+column+"]")
	}
	builder.WriteString(" WHEN NOT MATCHED THEN INSERT (" + strings.Join(insertColumns, ", ") +
		") VALUES (" + strings.Join(sourceColumns, ", ") + ");")
	return builder.String(), nil
}

// qualifyTargetExpression 把 MERGE UPDATE SET 的右值转换为 T-SQL 可消歧形式：
// excluded.x -> source.[x]；<目标表>.x -> target.[x]；裸目标列名 -> target.[列名]。
func qualifyTargetExpression(expression, table string, columns map[string]bool) (string, error) {
	var builder strings.Builder
	index := 0
	for index < len(expression) {
		switch expression[index] {
		case '\'', '"':
			end, ok := skipQuoted(expression, index)
			if !ok {
				return "", fmt.Errorf("MERGE 赋值含未闭合引号")
			}
			builder.WriteString(expression[index : end+1])
			index = end + 1
			continue
		case '[':
			end, ok := skipBracket(expression, index)
			if !ok {
				return "", fmt.Errorf("MERGE 赋值含未闭合方括号标识符")
			}
			builder.WriteString(expression[index : end+1])
			index = end + 1
			continue
		case '@':
			// 命名参数 @pN 原样保留。
			end := index + 1
			for end < len(expression) && isIdentChar(expression[end]) {
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
			if next < len(expression) && expression[next] == '.' {
				afterDot := next + 1
				for afterDot < len(expression) && expression[afterDot] == ' ' {
					afterDot++
				}
				column, columnEnd := readIdentifierToken(expression, afterDot)
				if column != "" {
					switch {
					case strings.EqualFold(token, "excluded"):
						builder.WriteString("source.[" + column + "]")
						index = columnEnd
						continue
					case strings.EqualFold(token, table):
						builder.WriteString("target.[" + column + "]")
						index = columnEnd
						continue
					}
				}
			}
			isCall := next < len(expression) && expression[next] == '('
			if !isCall && columns[strings.ToLower(token)] {
				builder.WriteString("target.[" + token + "]")
			} else {
				builder.WriteString(token)
			}
			index = end
			continue
		}
		builder.WriteByte(expression[index])
		index++
	}
	transformed := builder.String()
	if strings.Contains(strings.ToLower(transformed), "excluded.") {
		return "", fmt.Errorf("MERGE 赋值仍含 excluded.*，拒绝猜测")
	}
	return transformed, nil
}

// ---------------------------------------------------------------------------
// 占位符：? -> @p1..@pn
// ---------------------------------------------------------------------------

// convertPlaceholders 把 ? 占位符按出现顺序转换为 @p1..@pn；跳过单引号字符串、
// 双引号/方括号/反引号标识符、-- 行注释与 /* */ 块注释。仓储 SQL 不得混用既有 @
// 参数（T-SQL 变量）或 $ 占位符，出现即 fail-closed。
func convertPlaceholders(query string) (string, error) {
	var builder strings.Builder
	number := 0
	for index := 0; index < len(query); index++ {
		character := query[index]
		switch character {
		case '\'', '"', '`':
			end, ok := skipQuoted(query, index)
			if !ok {
				return "", fmt.Errorf("SQL 含未闭合的引号，拒绝发送到数据库")
			}
			builder.WriteString(query[index : end+1])
			index = end
			continue
		case '[':
			end, ok := skipBracket(query, index)
			if !ok {
				return "", fmt.Errorf("SQL 含未闭合的方括号标识符，拒绝发送到数据库")
			}
			builder.WriteString(query[index : end+1])
			index = end
			continue
		case '-':
			if index+1 < len(query) && query[index+1] == '-' {
				end := strings.IndexByte(query[index:], '\n')
				if end < 0 {
					builder.WriteString(query[index:])
					return builder.String(), nil
				}
				builder.WriteString(query[index : index+end+1])
				index += end
				continue
			}
		case '/':
			if index+1 < len(query) && query[index+1] == '*' {
				end := strings.Index(query[index+2:], "*/")
				if end < 0 {
					return "", fmt.Errorf("SQL 块注释未结束，拒绝发送到数据库")
				}
				builder.WriteString(query[index : index+2+end+2])
				index += 2 + end + 1
				continue
			}
		case '@':
			return "", fmt.Errorf("仓储 SQL 不得使用 @ 参数或 T-SQL 变量；请统一使用 ? 占位符")
		case '$':
			return "", fmt.Errorf("仓储 SQL 不得使用 $ 占位符；请统一使用 ? 占位符")
		case '?':
			number++
			builder.WriteString("@p" + strconv.Itoa(number))
			continue
		}
		builder.WriteByte(character)
	}
	return builder.String(), nil
}

// ---------------------------------------------------------------------------
// LIMIT/OFFSET -> OFFSET ... FETCH NEXT
// ---------------------------------------------------------------------------

// rewriteLimitOffsets 把 LIMIT n [OFFSET m] 改写为 T-SQL 的
// OFFSET m ROWS FETCH NEXT n ROWS ONLY。T-SQL 要求同一查询有 ORDER BY；SQLite
// 在无 ORDER BY 时的 LIMIT 顺序本来就是未定义的，因此补 ORDER BY (SELECT NULL)
// 保留“任意行”的语义（不伪造确定性顺序）。
func rewriteLimitOffsets(query string) (string, error) {
	var builder strings.Builder
	orderSeen := []bool{false}
	depth := 0
	index := 0
	for index < len(query) {
		character := query[index]
		switch {
		case character == '\'' || character == '"' || character == '`':
			end, ok := skipQuoted(query, index)
			if !ok {
				return "", fmt.Errorf("SQL 含未闭合的引号，拒绝翻译 LIMIT")
			}
			builder.WriteString(query[index : end+1])
			index = end + 1
			continue
		case character == '[':
			end, ok := skipBracket(query, index)
			if !ok {
				return "", fmt.Errorf("SQL 含未闭合的方括号标识符，拒绝翻译 LIMIT")
			}
			builder.WriteString(query[index : end+1])
			index = end + 1
			continue
		case character == '-' && index+1 < len(query) && query[index+1] == '-':
			end := strings.IndexByte(query[index:], '\n')
			if end < 0 {
				builder.WriteString(query[index:])
				index = len(query)
				continue
			}
			builder.WriteString(query[index : index+end+1])
			index += end + 1
			continue
		case character == '/' && index+1 < len(query) && query[index+1] == '*':
			end := strings.Index(query[index+2:], "*/")
			if end < 0 {
				return "", fmt.Errorf("SQL 块注释未结束，拒绝翻译 LIMIT")
			}
			builder.WriteString(query[index : index+2+end+2])
			index += 2 + end + 2
			continue
		case character == '(':
			depth++
			orderSeen = append(orderSeen, false)
			builder.WriteByte(character)
			index++
			continue
		case character == ')':
			if depth > 0 {
				depth--
				orderSeen = orderSeen[:len(orderSeen)-1]
			}
			builder.WriteByte(character)
			index++
			continue
		}
		if isWordAt(query, index, "SELECT") {
			orderSeen[depth] = false
			builder.WriteString(query[index : index+len("SELECT")])
			index += len("SELECT")
			continue
		}
		if isWordAt(query, index, "ORDER") {
			after := index + len("ORDER")
			for after < len(query) && (query[after] == ' ' || query[after] == '\n' || query[after] == '\t' || query[after] == '\r') {
				after++
			}
			if after+len("BY") <= len(query) && strings.EqualFold(query[after:after+len("BY")], "BY") {
				orderSeen[depth] = true
			}
			builder.WriteString(query[index : index+len("ORDER")])
			index += len("ORDER")
			continue
		}
		if isWordAt(query, index, "LIMIT") {
			position := index + len("LIMIT")
			skipLimitSpaces := func() {
				for position < len(query) && (query[position] == ' ' || query[position] == '\n' ||
					query[position] == '\t' || query[position] == '\r') {
					position++
				}
			}
			skipLimitSpaces()
			limitText, next, err := readLimitOperand(query, position)
			if err != nil {
				return "", err
			}
			position = next
			offsetText := "0"
			skipLimitSpaces()
			if position+len("OFFSET") <= len(query) && strings.EqualFold(query[position:position+len("OFFSET")], "OFFSET") {
				position += len("OFFSET")
				skipLimitSpaces()
				offset, next, err := readLimitOperand(query, position)
				if err != nil {
					return "", err
				}
				offsetText = offset
				position = next
			}
			if !orderSeen[depth] {
				builder.WriteString(" ORDER BY (SELECT NULL)")
				orderSeen[depth] = true
			}
			builder.WriteString(" OFFSET " + offsetText + " ROWS FETCH NEXT " + limitText + " ROWS ONLY")
			index = position
			continue
		}
		builder.WriteByte(character)
		index++
	}
	return builder.String(), nil
}

// readLimitOperand 读取 LIMIT/OFFSET 的操作数：命名参数 @pN、无符号整数或括号表达式。
func readLimitOperand(query string, start int) (string, int, error) {
	position := start
	if position >= len(query) {
		return "", 0, fmt.Errorf("LIMIT/OFFSET 缺少操作数")
	}
	if query[position] == '@' {
		end := position + 1
		for end < len(query) && isIdentChar(query[end]) {
			end++
		}
		if end == position+1 {
			return "", 0, fmt.Errorf("LIMIT/OFFSET 参数不合法")
		}
		return query[position:end], end, nil
	}
	if query[position] == '-' {
		return "", 0, fmt.Errorf("LIMIT 负数（SQLite 表示不限行数）未实现翻译；请改用显式上限")
	}
	if query[position] == '(' {
		closeIndex, err := matchingParen(query, position)
		if err != nil {
			return "", 0, err
		}
		return query[position : closeIndex+1], closeIndex + 1, nil
	}
	end := position
	for end < len(query) && query[end] >= '0' && query[end] <= '9' {
		end++
	}
	if end == position {
		return "", 0, fmt.Errorf("LIMIT/OFFSET 操作数不是整数或参数")
	}
	return query[position:end], end, nil
}

// ---------------------------------------------------------------------------
// rowid 与禁用词
// ---------------------------------------------------------------------------

// replaceBareRowid 把裸 rowid 标识符替换为 [_rowid]（迁移已为相关表追加代理列）。
func replaceBareRowid(query string) string {
	var builder strings.Builder
	for index := 0; index < len(query); index++ {
		switch query[index] {
		case '\'', '"', '`':
			end, ok := skipQuoted(query, index)
			if !ok {
				builder.WriteString(query[index:])
				index = len(query)
				continue
			}
			builder.WriteString(query[index : end+1])
			index = end
			continue
		case '[':
			end, ok := skipBracket(query, index)
			if !ok {
				builder.WriteString(query[index:])
				index = len(query)
				continue
			}
			builder.WriteString(query[index : end+1])
			index = end
			continue
		}
		if hasWordAt(query, index, "rowid") {
			builder.WriteString("[_rowid]")
			index += len("rowid") - 1
			continue
		}
		builder.WriteByte(query[index])
	}
	return builder.String()
}

// forbiddenSQLiteTokens 是 SQLite 专有、且不在本适配器翻译范围内的语法。迁移 DDL
// 走原始连接（不经过本函数）；仓储 SQL 一旦出现这些词直接失败，而不是交给 SQL
// Server 报难懂的错误或静默按不同语义解释。
var forbiddenSQLiteTokens = []struct {
	token string
	word  bool
}{
	{"INSERT OR", false},
	// RETURNING 由 TranslateRepositorySQL 在改写前显式拒绝（T-SQL 需 OUTPUT）；
	// 此处保留为纵深防御，避免未来新增路径遗漏。
	{"RETURNING", true},
	{"JSON_EXTRACT(", false},
	{"JSON_VALID(", false},
	{"JSON_EACH(", false},
	{"JSON_GROUP_ARRAY(", false},
	{"STRFTIME(", false},
	{"JULIANDAY(", false},
	{"DATETIME(", false},
	{"AUTOINCREMENT", true},
	{"WITHOUT ROWID", false},
	{"GLOB", true},
	{"PRAGMA", true},
	{"ISNULL(", false},
	{"IFNULL(", false},
	{"IIF(", false},
	{"||", false},
}

// rejectLeftoverSQLite 只检查字符串字面量/标识符之外的 token，避免把数据文本误判
// 为语法。RETURNING 不是 SQLite 专有语法，但 SQL Server 需要改写为 OUTPUT 子句；
// 当前仓储未使用，明确登记为未实现能力而不是误标为 SQLite 语法。
func rejectLeftoverSQLite(query string) error {
	for index := 0; index < len(query); index++ {
		switch query[index] {
		case '\'', '"', '`':
			end, ok := skipQuoted(query, index)
			if !ok {
				return fmt.Errorf("SQL 含未闭合的引号，拒绝发送到数据库")
			}
			index = end
			continue
		case '[':
			end, ok := skipBracket(query, index)
			if !ok {
				return fmt.Errorf("SQL 含未闭合的方括号标识符，拒绝发送到数据库")
			}
			index = end
			continue
		}
		for _, forbidden := range forbiddenSQLiteTokens {
			if forbidden.word {
				if hasWordAt(query, index, forbidden.token) {
					if forbidden.token == "RETURNING" {
						return fmt.Errorf("T-SQL 不支持 RETURNING，需要改写为 OUTPUT；本适配器未实现该能力（当前仓储未使用），拒绝猜测")
					}
					return fmt.Errorf("无法等价翻译的 SQLite 语法 %q；拒绝猜测，请移植该仓储 SQL", forbidden.token)
				}
				continue
			}
			if index+len(forbidden.token) <= len(query) &&
				strings.EqualFold(query[index:index+len(forbidden.token)], forbidden.token) {
				return fmt.Errorf("无法等价翻译的 SQLite 语法 %q；拒绝猜测，请移植该仓储 SQL", forbidden.token)
			}
		}
	}
	if containsWord(strings.ToLower(query), "rowid") {
		return fmt.Errorf("翻译后仍含裸 rowid；拒绝猜测，请核对表是否在 rowid 代理列清单中")
	}
	return nil
}

// ---------------------------------------------------------------------------
// 词法辅助
// ---------------------------------------------------------------------------

// topLevelSemicolon 返回引号/注释/方括号之外的第一个分号位置；没有则返回 -1。
func topLevelSemicolon(text string) int {
	depth := 0
	for index := 0; index < len(text); index++ {
		switch text[index] {
		case '\'', '"', '`':
			end, ok := skipQuoted(text, index)
			if !ok {
				return -1
			}
			index = end
			continue
		case '[':
			end, ok := skipBracket(text, index)
			if !ok {
				return -1
			}
			index = end
			continue
		case '(':
			depth++
			continue
		case ')':
			depth--
			continue
		case ';':
			if depth == 0 {
				return index
			}
		}
	}
	return -1
}

func topLevelKeyword(text, keyword string) int {
	depth := 0
	for index := 0; index < len(text); index++ {
		switch text[index] {
		case '\'', '"', '`':
			end, ok := skipQuoted(text, index)
			if !ok {
				return -1
			}
			index = end
			continue
		case '[':
			end, ok := skipBracket(text, index)
			if !ok {
				return -1
			}
			index = end
			continue
		case '(':
			depth++
			continue
		case ')':
			depth--
			continue
		}
		if depth == 0 && hasWordAt(text, index, keyword) {
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

func isWordAt(text string, index int, word string) bool { return hasWordAt(text, index, word) }

// hasWithoutRowid 检测引号/注释之外的 WITHOUT ROWID 短语（SQLite 表选项）。
func hasWithoutRowid(query string) bool {
	for index := 0; index < len(query); index++ {
		switch query[index] {
		case '\'', '"', '`':
			end, ok := skipQuoted(query, index)
			if !ok {
				return false
			}
			index = end
			continue
		case '[':
			end, ok := skipBracket(query, index)
			if !ok {
				return false
			}
			index = end
			continue
		}
		if hasWordAt(query, index, "WITHOUT") {
			after := index + len("WITHOUT")
			for after < len(query) && (query[after] == ' ' || query[after] == '\n' || query[after] == '\t' || query[after] == '\r') {
				after++
			}
			if hasWordAt(query, after, "ROWID") {
				return true
			}
		}
	}
	return false
}

func containsWord(text, word string) bool {
	for index := 0; index+len(word) <= len(text); index++ {
		if hasWordAt(text, index, word) {
			return true
		}
	}
	return false
}

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

// skipBracket 跳过 [方括号标识符]（]] 表示字面 ]）。
func skipBracket(text string, start int) (int, bool) {
	for index := start + 1; index < len(text); index++ {
		if text[index] == ']' {
			if index+1 < len(text) && text[index+1] == ']' {
				index++
				continue
			}
			return index, true
		}
	}
	return len(text), false
}

func readIdentifierToken(text string, start int) (string, int) {
	position := start
	for position < len(text) && (text[position] == ' ' || text[position] == '\t') {
		position++
	}
	if position >= len(text) {
		return "", position
	}
	if text[position] == '[' {
		end, ok := skipBracket(text, position)
		if !ok {
			return "", position
		}
		return strings.ReplaceAll(text[position+1:end], "]]", "]"), end + 1
	}
	if text[position] == '"' || text[position] == '`' {
		end, ok := skipQuoted(text, position)
		if !ok {
			return "", position
		}
		return text[position+1 : end], end + 1
	}
	end := position
	for end < len(text) && (isIdentChar(text[end]) || text[end] == '.' || text[end] == '#') {
		end++
	}
	return text[position:end], end
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
		case '[':
			end, ok := skipBracket(text, index)
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
		case '[':
			end, ok := skipBracket(text, index)
			if !ok {
				return -1, fmt.Errorf("方括号标识符未闭合")
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

func snippet(text string) string {
	text = strings.Join(strings.Fields(text), " ")
	if len(text) > 160 {
		return text[:157] + "..."
	}
	return text
}

// ---------------------------------------------------------------------------
// 重写驱动器：在 database/sql 的 Prepare 层翻译 SQL（含事务内语句），并转换
// Go 侧绑定值的类型以匹配 T-SQL 列类型。
// ---------------------------------------------------------------------------

// newRewriteConnector 包装驱动的连接器：每个 Prepare 先把 SQLite 方言翻译为
// T-SQL，再交给底层驱动。真实连接路径本步未运行实测。
func newRewriteConnector(base driver.Connector, resolver ConflictKeyResolver) driver.Connector {
	return &rewriteConnector{base: base, resolver: resolver}
}

type rewriteConnector struct {
	base     driver.Connector
	resolver ConflictKeyResolver
}

func (c *rewriteConnector) Connect(ctx context.Context) (driver.Conn, error) {
	connection, err := c.base.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &rewriteConn{base: connection, resolver: c.resolver}, nil
}

func (c *rewriteConnector) Driver() driver.Driver {
	return &rewriteDriver{base: c.base.Driver(), resolver: c.resolver}
}

type rewriteDriver struct {
	base     driver.Driver
	resolver ConflictKeyResolver
}

// Open 只在未使用 Connector 的旧路径被调用；本包始终通过 Connector 打开连接。
func (d *rewriteDriver) Open(name string) (driver.Conn, error) {
	connection, err := d.base.Open(name)
	if err != nil {
		return nil, err
	}
	return &rewriteConn{base: connection, resolver: d.resolver}, nil
}

type rewriteConn struct {
	base     driver.Conn
	resolver ConflictKeyResolver
}

func (c *rewriteConn) Prepare(query string) (driver.Stmt, error) {
	translated, err := TranslateRepositorySQL(query, c.resolver)
	if err != nil {
		return nil, err
	}
	statement, err := c.base.Prepare(translated)
	if err != nil {
		return nil, err
	}
	return &rewriteStmt{base: statement}, nil
}

func (c *rewriteConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	translated, err := TranslateRepositorySQL(query, c.resolver)
	if err != nil {
		return nil, err
	}
	preparer, ok := c.base.(driver.ConnPrepareContext)
	if !ok {
		statement, err := c.base.Prepare(translated)
		if err != nil {
			return nil, err
		}
		return &rewriteStmt{base: statement}, nil
	}
	statement, err := preparer.PrepareContext(ctx, translated)
	if err != nil {
		return nil, err
	}
	return &rewriteStmt{base: statement}, nil
}

func (c *rewriteConn) Close() error { return c.base.Close() }

func (c *rewriteConn) Begin() (driver.Tx, error) {
	transaction, err := c.base.Begin()
	if err != nil {
		return nil, err
	}
	return &rewriteTx{base: transaction}, nil
}

func (c *rewriteConn) BeginTx(ctx context.Context, options driver.TxOptions) (driver.Tx, error) {
	beginner, ok := c.base.(driver.ConnBeginTx)
	if !ok {
		if options.Isolation != 0 || options.ReadOnly {
			return nil, errors.New("底层驱动不支持事务选项")
		}
		return c.Begin()
	}
	transaction, err := beginner.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	return &rewriteTx{base: transaction}, nil
}

func (c *rewriteConn) Ping(ctx context.Context) error {
	if pinger, ok := c.base.(driver.Pinger); ok {
		return pinger.Ping(ctx)
	}
	return nil
}

// CheckNamedValue 转换 Go 侧绑定值：布尔 -> 0/1 整数、time.Time -> UTC 毫秒整数，
// 与 SQLite 存储模型（布尔 BIGINT 0/1、时间 BIGINT 毫秒）保持一致后再交给驱动。
func (c *rewriteConn) CheckNamedValue(value *driver.NamedValue) error {
	convertNamedValue(value)
	if checker, ok := c.base.(driver.NamedValueChecker); ok {
		return checker.CheckNamedValue(value)
	}
	return driver.ErrSkip
}

// ResetSession/IsValid 只在底层驱动提供时透传，避免丢失连接复用与失效检测能力。
func (c *rewriteConn) ResetSession(ctx context.Context) error {
	if resetter, ok := c.base.(driver.SessionResetter); ok {
		return resetter.ResetSession(ctx)
	}
	return nil
}

func (c *rewriteConn) IsValid() bool {
	if validator, ok := c.base.(driver.Validator); ok {
		return validator.IsValid()
	}
	return true
}

type rewriteStmt struct {
	base driver.Stmt
}

func (s *rewriteStmt) Close() error  { return s.base.Close() }
func (s *rewriteStmt) NumInput() int { return s.base.NumInput() }
func (s *rewriteStmt) Exec(args []driver.Value) (driver.Result, error) {
	return s.base.Exec(args)
}
func (s *rewriteStmt) Query(args []driver.Value) (driver.Rows, error) {
	return s.base.Query(args)
}
func (s *rewriteStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	for index := range args {
		convertNamedValue(&args[index])
	}
	if executor, ok := s.base.(driver.StmtExecContext); ok {
		return executor.ExecContext(ctx, args)
	}
	values := namedValues(args)
	return s.base.Exec(values)
}
func (s *rewriteStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	for index := range args {
		convertNamedValue(&args[index])
	}
	if querier, ok := s.base.(driver.StmtQueryContext); ok {
		return querier.QueryContext(ctx, args)
	}
	values := namedValues(args)
	return s.base.Query(values)
}

// CheckNamedValue 先做方言值转换，再尝试底层语句的命名值检查。
func (s *rewriteStmt) CheckNamedValue(value *driver.NamedValue) error {
	convertNamedValue(value)
	if checker, ok := s.base.(driver.NamedValueChecker); ok {
		return checker.CheckNamedValue(value)
	}
	return driver.ErrSkip
}

// convertNamedValue 统一转换绑定值；只在类型与 SQLite 存储模型不一致时改写。
func convertNamedValue(value *driver.NamedValue) {
	if value == nil {
		return
	}
	switch typed := value.Value.(type) {
	case bool:
		if typed {
			value.Value = int64(1)
		} else {
			value.Value = int64(0)
		}
	case time.Time:
		// 仓储的时间列是 UTC 毫秒 BIGINT；直接传 time.Time 会被驱动编码为
		// datetime2/datetimeoffset。
		value.Value = typed.UTC().UnixMilli()
	}
}

func namedValues(args []driver.NamedValue) []driver.Value {
	values := make([]driver.Value, len(args))
	for index := range args {
		values[index] = args[index].Value
	}
	return values
}

type rewriteTx struct {
	base driver.Tx
}

func (t *rewriteTx) Commit() error   { return t.base.Commit() }
func (t *rewriteTx) Rollback() error { return t.base.Rollback() }
