package mysql

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"
)

// TranslateRepositorySQL 把既有仓储 SQL 中的 SQLite 方言确定性翻译为 MySQL 语法。
//
// 已实现且经过单测/仓储源码审计的转换：
//   - ON CONFLICT ... DO NOTHING  -> ON DUPLICATE KEY UPDATE <col>=<col>
//     （保留 MySQL 默认“重复键影响 0 行”语义，仓储据此判断冲突/幂等）
//   - ON CONFLICT ... DO UPDATE SET -> ON DUPLICATE KEY UPDATE ...，excluded.x -> VALUES(x)
//   - INSERT OR IGNORE INTO -> INSERT IGNORE INTO（只用于仓储源码中已核对的幂等写入）
//   - 裸 rowid -> _rowid（迁移为 4 张使用 rowid 的表追加 _rowid 自增列）
//   - DELETE/UPDATE 的同表子查询用派生表包裹，绕开 MySQL 1093 限制
//
// 不含上述标记的语句原样返回（占位符 ?、LIMIT/OFFSET、反引号标识符在两种方言中
// 一致）。翻译后仍残留 SQLite 专有语法时返回错误，绝不猜测翻译。
func TranslateRepositorySQL(query string) (string, error) {
	lower := strings.ToLower(query)
	hasMarker := strings.Contains(lower, "on conflict") ||
		strings.Contains(lower, "insert or") ||
		containsWord(lower, "rowid")
	result := query
	if hasMarker {
		result = replaceInsertOrIgnore(result)
		result = replaceBareRowid(result)
	}

	// ON CONFLICT 允许一条语句出现一次（现有仓储均如此）；循环处理以便给出清晰错误。
	for attempts := 0; attempts < 4; attempts++ {
		index := topLevelKeyword(result, "ON CONFLICT")
		if index < 0 {
			break
		}
		converted, err := convertOnConflict(result, index)
		if err != nil {
			return "", err
		}
		result = converted
	}
	result, err := wrapSameTableSubqueries(result)
	if err != nil {
		return "", err
	}
	if err := rejectLeftoverSQLite(result); err != nil {
		return "", err
	}
	return result, nil
}

// replaceInsertOrIgnore 只接受 INSERT OR IGNORE（仓储实际用法）；INSERT OR REPLACE
// 语义与 MySQL REPLACE 不同（REPLACE 会删除后插入并触发级联删除），明确拒绝。
func replaceInsertOrIgnore(query string) string {
	upper := strings.ToUpper(query)
	for {
		index := strings.Index(upper, "INSERT OR ")
		if index < 0 {
			return query
		}
		rest := upper[index+len("INSERT OR "):]
		switch {
		case strings.HasPrefix(rest, "IGNORE"):
			return query[:index] + "INSERT IGNORE" + query[index+len("INSERT OR IGNORE"):]
		case strings.HasPrefix(rest, "REPLACE"):
			// 调用方在 rejectLeftoverSQLite 中会得到明确错误。
			return query
		default:
			return query
		}
	}
}

// replaceBareRowid 把裸 rowid 标识符替换为 _rowid（迁移已为相关表追加代理列）。
// 只替换标识符 token，不改写字符串字面量或反引号标识符。
func replaceBareRowid(query string) string {
	var builder strings.Builder
	for index := 0; index < len(query); index++ {
		switch query[index] {
		case '\'', '`', '"':
			end, ok := skipQuoted(query, index)
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
			builder.WriteString("_rowid")
			index += len("rowid") - 1
			continue
		}
		builder.WriteByte(query[index])
	}
	return builder.String()
}

// convertOnConflict 把一条 ON CONFLICT 子句转换追加为 ON DUPLICATE KEY UPDATE。
func convertOnConflict(query string, index int) (string, error) {
	prefix := query[:index]
	clause := strings.TrimSpace(query[index:])
	upper := strings.ToUpper(clause)
	if !strings.HasPrefix(upper, "ON CONFLICT") {
		return "", fmt.Errorf("内部错误：ON CONFLICT 定位失败")
	}
	rest := strings.TrimSpace(clause[len("ON CONFLICT"):])
	conflictColumns := []string{}
	if strings.HasPrefix(rest, "(") {
		closeIndex, err := matchParen(rest, 0)
		if err != nil {
			return "", fmt.Errorf("解析 ON CONFLICT 目标失败: %w", err)
		}
		conflictColumns = splitIdentifierList(rest[1:closeIndex])
		rest = strings.TrimSpace(rest[closeIndex+1:])
	}
	upperRest := strings.ToUpper(rest)
	switch {
	case strings.HasPrefix(upperRest, "DO NOTHING"):
		targetColumns, err := insertColumns(prefix)
		if err != nil {
			return "", err
		}
		column := targetColumns[0]
		if len(targetColumns) == 0 {
			return "", fmt.Errorf("ON CONFLICT DO NOTHING 需要 INSERT 列清单以生成幂等 UPDATE")
		}
		// 用首个插入列自赋值：MySQL 默认语义下重复键影响 0 行，与 SQLite DO NOTHING
		// 对仓储的可观测结果一致（仓储用 RowsAffected==0 判断冲突）。
		return prefix + "ON DUPLICATE KEY UPDATE " + quoteLocalIdent(column) + "=" + quoteLocalIdent(column), nil
	case strings.HasPrefix(upperRest, "DO UPDATE SET"):
		assignments := strings.TrimSpace(rest[len("DO UPDATE SET"):])
		assignments = strings.TrimSuffix(strings.TrimSpace(assignments), ";")
		targetTable, _ := insertTarget(prefix)
		converted, err := convertAssignments(assignments, targetTable)
		if err != nil {
			return "", err
		}
		_ = conflictColumns
		return prefix + "ON DUPLICATE KEY UPDATE " + converted, nil
	default:
		return "", fmt.Errorf("不支持的 ON CONFLICT 形式: %s", snippet(clause))
	}
}

// convertAssignments 转换 DO UPDATE SET 的赋值列表：
//   - excluded.x -> VALUES(x)
//   - <目标表>.x -> x（MySQL 的 ON DUPLICATE KEY UPDATE 左值/右值引用当前行）
func convertAssignments(assignments, targetTable string) (string, error) {
	parts := splitTopLevel(assignments, ',')
	converted := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		equal := indexTopLevel(part, '=')
		if equal < 0 {
			return "", fmt.Errorf("无法解析 DO UPDATE 赋值: %s", snippet(part))
		}
		left := strings.TrimSpace(part[:equal])
		right := strings.TrimSpace(part[equal+1:])
		left = stripTableQualifier(left, targetTable)
		right = replaceExcludedReference(right)
		right = stripTableQualifier(right, targetTable)
		converted = append(converted, quoteLocalIdent(left)+"="+right)
	}
	if len(converted) == 0 {
		return "", fmt.Errorf("DO UPDATE SET 没有赋值")
	}
	return strings.Join(converted, ", "), nil
}

func replaceExcludedReference(text string) string {
	var builder strings.Builder
	for index := 0; index < len(text); {
		if hasWordAt(text, index, "excluded") && index+len("excluded") < len(text) && text[index+len("excluded")] == '.' {
			end := index + len("excluded") + 1
			column, rest := readIdent(text[end:])
			if column == "" {
				builder.WriteByte(text[index])
				index++
				continue
			}
			builder.WriteString("VALUES(" + quoteLocalIdent(column) + ")")
			index = end + len(column)
			_ = rest
			continue
		}
		builder.WriteByte(text[index])
		index++
	}
	return builder.String()
}

func stripTableQualifier(text, table string) string {
	if table == "" {
		return text
	}
	prefix := table + "."
	for {
		index := strings.Index(strings.ToLower(text), strings.ToLower(prefix))
		if index < 0 {
			return text
		}
		if index > 0 && isIdentChar(text[index-1]) {
			// 前缀是更长标识符的一部分，跳过继续向后找。
			offset := index + len(prefix)
			next := strings.Index(strings.ToLower(text[offset:]), strings.ToLower(prefix))
			if next < 0 {
				return text
			}
			_ = offset
			return text
		}
		text = text[:index] + text[index+len(prefix):]
	}
}

func insertTarget(prefix string) (string, error) {
	upper := strings.ToUpper(prefix)
	index := strings.Index(upper, "INSERT")
	if index < 0 {
		return "", fmt.Errorf("ON CONFLICT 出现在非 INSERT 语句中")
	}
	rest := strings.TrimSpace(prefix[index+len("INSERT"):])
	upperRest := strings.ToUpper(rest)
	if strings.HasPrefix(upperRest, "IGNORE") {
		rest = strings.TrimSpace(rest[len("IGNORE"):])
	}
	if !strings.HasPrefix(strings.ToUpper(rest), "INTO") {
		return "", fmt.Errorf("不支持的 INSERT 形式（缺少 INTO）")
	}
	rest = strings.TrimSpace(rest[len("INTO"):])
	table, _ := readIdent(rest)
	if table == "" {
		return "", fmt.Errorf("无法解析 INSERT 目标表")
	}
	return table, nil
}

func insertColumns(prefix string) ([]string, error) {
	table, err := insertTarget(prefix)
	if err != nil {
		return nil, err
	}
	upper := strings.ToUpper(prefix)
	index := strings.Index(upper, strings.ToUpper(table))
	if index < 0 {
		return nil, fmt.Errorf("无法解析 INSERT 列清单")
	}
	rest := prefix[index+len(table):]
	open := strings.Index(rest, "(")
	if open < 0 {
		return nil, fmt.Errorf("ON CONFLICT DO NOTHING 需要显式 INSERT 列清单")
	}
	closeIndex, err := matchParen(rest, open)
	if err != nil {
		return nil, fmt.Errorf("解析 INSERT 列清单失败: %w", err)
	}
	columns := splitIdentifierList(rest[open+1 : closeIndex])
	if len(columns) == 0 {
		return nil, fmt.Errorf("INSERT 列清单为空")
	}
	return columns, nil
}

// wrapSameTableSubqueries 把同表子查询包成派生表：MySQL 不允许 UPDATE/DELETE 在
// 子查询中直接引用被修改的表（错误 1093）。现有仓储只在 rowid 清理 SQL 使用该形式。
func wrapSameTableSubqueries(query string) (string, error) {
	upper := strings.ToUpper(strings.TrimSpace(query))
	var target string
	switch {
	case strings.HasPrefix(upper, "DELETE FROM "):
		table, _ := readIdent(strings.TrimSpace(query[len("DELETE FROM "):]))
		target = table
	case strings.HasPrefix(upper, "UPDATE "):
		table, _ := readIdent(strings.TrimSpace(query[len("UPDATE "):]))
		target = table
	default:
		return query, nil
	}
	if target == "" {
		return query, nil
	}
	counter := 0
	var builder strings.Builder
	for index := 0; index < len(query); index++ {
		if query[index] != '(' {
			builder.WriteByte(query[index])
			continue
		}
		end, err := matchParen(query, index)
		if err != nil {
			return "", fmt.Errorf("括号不匹配: %w", err)
		}
		inner := strings.TrimSpace(query[index+1 : end])
		if !strings.HasPrefix(strings.ToUpper(inner), "SELECT ") && !strings.HasPrefix(strings.ToUpper(inner), "SELECT\n") {
			builder.WriteString(query[index : end+1])
			index = end
			continue
		}
		if !subqueryReferencesTable(inner, target) {
			builder.WriteString(query[index : end+1])
			index = end
			continue
		}
		counter++
		alias := fmt.Sprintf("_subq%d", counter)
		builder.WriteString("(SELECT * FROM (")
		builder.WriteString(inner)
		builder.WriteString(") AS " + alias + ")")
		index = end
	}
	if counter == 0 {
		return query, nil
	}
	result := builder.String()
	// 被修改表自身的 rowid 在子查询里出现两次；调用方已先完成 rowid 替换。
	return result, nil
}

func subqueryReferencesTable(inner, table string) bool {
	upper := strings.ToUpper(inner)
	needle := "FROM " + strings.ToUpper(table)
	if strings.Contains(upper, needle) {
		return true
	}
	return strings.Contains(upper, "JOIN "+strings.ToUpper(table))
}

// forbiddenSQLiteTokens 是 SQLite 专有、且不在本适配器翻译范围内的语法。迁移 DDL 走
// 原始连接（不经过本函数）；仓储 SQL 一旦出现这些词直接失败，而不是交给 MySQL 报
// 难懂的错误或静默按 MySQL 语法解释出不同语义。
var forbiddenSQLiteTokens = []struct {
	token string
	word  bool
}{
	{"ON CONFLICT", false},
	{"INSERT OR", false},
	{"RETURNING", true},
	{"JSON_EXTRACT(", false},
	{"JSON_VALID(", false},
	{"STRFTIME(", false},
	{"DATETIME(", false},
	{"JULIANDAY(", false},
	{"AUTOINCREMENT", true},
	{"GLOB", true},
	{"PRAGMA", true},
	{"ISNULL(", false},
	{"||", false},
}

// CheckForbiddenSQLiteDialect 只做禁用词检查（不尝试翻译、不要求语句完整），供静态
// 审计对“不含方言标记的标准 SQL/拼接片段”做同样的拒绝而非跳过检查。
func CheckForbiddenSQLiteDialect(query string) error {
	return rejectLeftoverSQLite(query)
}

// rejectLeftoverSQLite 只检查字符串字面量/反引号之外的 token，避免把数据文本误判为语法。
func rejectLeftoverSQLite(query string) error {
	for index := 0; index < len(query); index++ {
		switch query[index] {
		case '\'', '`', '"':
			end, ok := skipQuoted(query, index)
			if !ok {
				return fmt.Errorf("SQL 含未闭合的引号，拒绝发送到数据库")
			}
			index = end
			continue
		}
		for _, forbidden := range forbiddenSQLiteTokens {
			if forbidden.word {
				if hasWordAt(query, index, forbidden.token) {
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
// 词法辅助（与 migrations/mysql 保持一致的最小实现，避免跨包暴露内部解析器）
// ---------------------------------------------------------------------------

func topLevelKeyword(text, keyword string) int {
	depth := 0
	for index := 0; index < len(text); index++ {
		character := text[index]
		switch character {
		case '\'', '`', '"':
			end, ok := skipQuoted(text, index)
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

func skipQuoted(text string, start int) (int, bool) {
	quote := text[start]
	for index := start + 1; index < len(text); index++ {
		if text[index] == quote {
			if quote != '`' && index+1 < len(text) && text[index+1] == quote {
				index++
				continue
			}
			return index, true
		}
	}
	return len(text), false
}

func readIdent(text string) (string, string) {
	text = strings.TrimSpace(text)
	index := 0
	for index < len(text) && (isIdentChar(text[index]) || text[index] == '.') {
		index++
	}
	return text[:index], text[index:]
}

func quoteLocalIdent(identifier string) string {
	identifier = strings.TrimSpace(identifier)
	if strings.HasPrefix(identifier, "`") {
		return identifier
	}
	return "`" + strings.ReplaceAll(identifier, "`", "``") + "`"
}

func matchParen(text string, open int) (int, error) {
	depth := 0
	for index := open; index < len(text); index++ {
		switch text[index] {
		case '\'', '`', '"':
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

func splitTopLevel(text string, separator byte) []string {
	var parts []string
	var builder strings.Builder
	depth := 0
	for index := 0; index < len(text); index++ {
		switch text[index] {
		case '\'', '`', '"':
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

func indexTopLevel(text string, character byte) int {
	depth := 0
	for index := 0; index < len(text); index++ {
		switch text[index] {
		case '\'', '`', '"':
			end, ok := skipQuoted(text, index)
			if !ok {
				return -1
			}
			index = end
		case '(':
			depth++
		case ')':
			depth--
		default:
			if depth == 0 && text[index] == character {
				return index
			}
		}
	}
	return -1
}

func splitIdentifierList(text string) []string {
	parts := splitTopLevel(text, ',')
	columns := make([]string, 0, len(parts))
	for _, part := range parts {
		column, _ := readIdent(part)
		if column != "" {
			columns = append(columns, column)
		}
	}
	return columns
}

func snippet(text string) string {
	text = strings.Join(strings.Fields(text), " ")
	if len(text) > 160 {
		return text[:157] + "..."
	}
	return text
}

// ---------------------------------------------------------------------------
// 重写驱动器：在 database/sql 的 Prepare 层翻译 SQL，覆盖事务内语句
// ---------------------------------------------------------------------------

// newRewriteConnector 包装 go-sql-driver 的连接器：每个 Prepare 先把 SQLite 方言
// 翻译为 MySQL，再交给底层驱动。真实连接路径本步未运行实测。
func newRewriteConnector(base driver.Connector) driver.Connector {
	return &rewriteConnector{base: base}
}

type rewriteConnector struct {
	base driver.Connector
}

func (c *rewriteConnector) Connect(ctx context.Context) (driver.Conn, error) {
	connection, err := c.base.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &rewriteConn{base: connection}, nil
}

func (c *rewriteConnector) Driver() driver.Driver {
	return &rewriteDriver{base: c.base.Driver()}
}

type rewriteDriver struct {
	base driver.Driver
}

// Open 只在未使用 Connector 的旧路径被调用；本包始终通过 Connector 打开连接。
func (d *rewriteDriver) Open(name string) (driver.Conn, error) {
	connection, err := d.base.Open(name)
	if err != nil {
		return nil, err
	}
	return &rewriteConn{base: connection}, nil
}

type rewriteConn struct {
	base driver.Conn
}

func (c *rewriteConn) Prepare(query string) (driver.Stmt, error) {
	translated, err := TranslateRepositorySQL(query)
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
	translated, err := TranslateRepositorySQL(query)
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
	if executor, ok := s.base.(driver.StmtExecContext); ok {
		return executor.ExecContext(ctx, args)
	}
	values := namedValues(args)
	return s.base.Exec(values)
}
func (s *rewriteStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	if querier, ok := s.base.(driver.StmtQueryContext); ok {
		return querier.QueryContext(ctx, args)
	}
	values := namedValues(args)
	return s.base.Query(values)
}

// CheckNamedValue 透传底层语句的命名值检查（例如时间/类型转换）。
func (s *rewriteStmt) CheckNamedValue(value *driver.NamedValue) error {
	if checker, ok := s.base.(driver.NamedValueChecker); ok {
		return checker.CheckNamedValue(value)
	}
	return driver.ErrSkip
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
