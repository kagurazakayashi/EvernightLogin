package postgres

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// TranslateRepositorySQL 把既有仓储 SQL 中的 SQLite 方言确定性翻译为 PostgreSQL 语法。
//
// 已实现且经过单测/仓储源码审计的转换：
//   - ? -> $1..$n 占位符（引号、注释、$ 引用内部不转换；禁止混用既有 $ 占位符）
//   - INSERT OR IGNORE INTO -> INSERT INTO ... ON CONFLICT DO NOTHING
//   - 裸 rowid -> _rowid（迁移为 4 张使用 rowid 的表追加 _rowid 代理列）
//   - LIKE -> ILIKE（SQLite LIKE 对 ASCII 大小写不敏感；`TEXT COLLATE "C"` 下
//     ILIKE 的大小写折叠同样只覆盖 ASCII）
//   - ON CONFLICT / excluded.* / RETURNING 保持原样（PostgreSQL 与 SQLite 均支持，
//     占位符编号在 RETURNING 之前的参数上照常连续）
//
// 翻译后仍残留 SQLite 专有语法时返回错误，绝不猜测翻译。
func TranslateRepositorySQL(query string) (string, error) {
	result := query
	if containsWord(strings.ToLower(result), "insert or ignore") ||
		strings.Contains(strings.ToLower(result), "insert or ") {
		converted, err := convertInsertOrIgnore(result)
		if err != nil {
			return "", err
		}
		result = converted
	}
	if containsWord(strings.ToLower(result), "rowid") {
		result = replaceBareRowid(result)
	}
	if containsWord(strings.ToLower(result), "like") {
		result = replaceWordOutsideQuotes(result, "like", "ILIKE")
	}
	converted, err := convertPlaceholders(result)
	if err != nil {
		return "", err
	}
	if err := rejectLeftoverSQLite(converted); err != nil {
		return "", err
	}
	return converted, nil
}

// convertInsertOrIgnore 只接受 INSERT OR IGNORE（仓储实际用法）；INSERT OR REPLACE
// 语义不同（SQLite REPLACE 会删除后插入），明确拒绝。
func convertInsertOrIgnore(query string) (string, error) {
	index := findWordInsensitive(query, "INSERT OR IGNORE")
	if index < 0 {
		if findWordInsensitive(query, "INSERT OR REPLACE") >= 0 {
			return "", fmt.Errorf("无法等价翻译的 SQLite 语法 \"INSERT OR REPLACE\"；拒绝猜测，请移植该仓储 SQL")
		}
		if strings.Contains(strings.ToLower(query), "insert or ") {
			return "", fmt.Errorf("不支持的 INSERT OR 形式；拒绝猜测，请移植该仓储 SQL")
		}
		return query, nil
	}
	prefix := query[:index]
	rest := strings.TrimSpace(query[index+len("INSERT OR IGNORE"):])
	body := strings.TrimSpace(prefix) + " INSERT " + rest
	trimmed := strings.TrimSpace(body)
	suffix := ""
	if strings.HasSuffix(trimmed, ";") {
		trimmed = strings.TrimSuffix(trimmed, ";")
		suffix = ";"
	}
	if topLevelKeyword(trimmed, "ON CONFLICT") >= 0 {
		return trimmed + suffix, nil
	}
	// ON CONFLICT 必须插在 RETURNING 之前（INSERT ... [ON CONFLICT ...] [RETURNING ...]）。
	if returningIndex := topLevelKeyword(trimmed, "RETURNING"); returningIndex >= 0 {
		return strings.TrimSpace(trimmed[:returningIndex]) + " ON CONFLICT DO NOTHING " +
			strings.TrimSpace(trimmed[returningIndex:]) + suffix, nil
	}
	return trimmed + " ON CONFLICT DO NOTHING" + suffix, nil
}

// replaceBareRowid 把裸 rowid 标识符替换为 _rowid（迁移已为相关表追加代理列）。
// 只替换标识符 token，不改写字符串字面量或双引号标识符。
func replaceBareRowid(query string) string {
	var builder strings.Builder
	for index := 0; index < len(query); index++ {
		switch query[index] {
		case '\'', '"':
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

// replaceWordOutsideQuotes 把引号/注释之外的某个 SQL 关键字替换为另一个词。
func replaceWordOutsideQuotes(query, from, to string) string {
	var builder strings.Builder
	for index := 0; index < len(query); index++ {
		if query[index] == '\'' || query[index] == '"' {
			end, ok := skipQuoted(query, index)
			if !ok {
				builder.WriteString(query[index:])
				return builder.String()
			}
			builder.WriteString(query[index : end+1])
			index = end
			continue
		}
		if hasWordAt(query, index, from) {
			builder.WriteString(to)
			index += len(from) - 1
			continue
		}
		builder.WriteByte(query[index])
	}
	return builder.String()
}

// convertPlaceholders 把 ? 占位符按出现顺序转换为 $1..$n；跳过单引号字符串、
// 双引号标识符、-- 行注释、/* */ 块注释与 $tag$ 引用。仓储 SQL 不得混用既有
// $n 占位符（会出现编号冲突），因此遇到未识别的 $ 直接报错。
func convertPlaceholders(query string) (string, error) {
	var builder strings.Builder
	number := 0
	for index := 0; index < len(query); index++ {
		character := query[index]
		switch character {
		case '\'', '"':
			end, ok := skipQuoted(query, index)
			if !ok {
				return "", fmt.Errorf("SQL 含未闭合的引号，拒绝发送到数据库")
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
		case '$':
			// PostgreSQL 的 $tag$ 引用或既有 $n 占位符：仓储 SQL 不应出现。
			end, ok := skipDollarQuoted(query, index)
			if ok {
				builder.WriteString(query[index : end+1])
				index = end
				continue
			}
			return "", fmt.Errorf("仓储 SQL 不得使用 $ 占位符或 $ 引用；请统一使用 ? 占位符")
		case '?':
			number++
			builder.WriteString("$" + strconv.Itoa(number))
			continue
		}
		builder.WriteByte(character)
	}
	return builder.String(), nil
}

// skipDollarQuoted 识别 $tag$...$tag$ 引用并返回结束位置。
func skipDollarQuoted(text string, start int) (int, bool) {
	end := start + 1
	for end < len(text) && (isIdentChar(text[end]) || text[end] == '$') {
		if text[end] == '$' {
			break
		}
		end++
	}
	if end >= len(text) || text[end] != '$' {
		return 0, false
	}
	tag := text[start : end+1]
	closing := strings.Index(text[end+1:], tag)
	if closing < 0 {
		return 0, false
	}
	return end + 1 + closing + len(tag) - 1, true
}

// forbiddenSQLiteTokens 是 SQLite 专有、且不在本适配器翻译范围内的语法。迁移 DDL
// 走原始连接（不经过本函数）；仓储 SQL 一旦出现这些词直接失败，而不是交给
// PostgreSQL 报难懂的错误或静默按不同语义解释。
var forbiddenSQLiteTokens = []struct {
	token string
	word  bool
}{
	{"INSERT OR", false},
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

// CheckForbiddenSQLiteDialect 只做禁用词检查（不尝试翻译、不要求语句完整），供静态
// 审计对“不含方言标记的标准 SQL/拼接片段”做同样的拒绝而非跳过检查。
func CheckForbiddenSQLiteDialect(query string) error {
	return rejectLeftoverSQLite(query)
}

// rejectLeftoverSQLite 只检查字符串字面量/双引号标识符之外的 token，避免把数据文本
// 误判为语法。
func rejectLeftoverSQLite(query string) error {
	for index := 0; index < len(query); index++ {
		switch query[index] {
		case '\'', '"':
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
// 词法辅助
// ---------------------------------------------------------------------------

func topLevelKeyword(text, keyword string) int {
	depth := 0
	for index := 0; index < len(text); index++ {
		character := text[index]
		switch character {
		case '\'', '"':
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

func findWordInsensitive(text, phrase string) int {
	lower := strings.ToLower(text)
	needle := strings.ToLower(phrase)
	for index := 0; index+len(needle) <= len(lower); index++ {
		if lower[index:index+len(needle)] != needle {
			continue
		}
		if index > 0 && isIdentChar(text[index-1]) {
			continue
		}
		if index+len(needle) < len(text) && isIdentChar(text[index+len(needle)]) {
			continue
		}
		return index
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
			if index+1 < len(text) && text[index+1] == quote {
				index++
				continue
			}
			return index, true
		}
	}
	return len(text), false
}

// ---------------------------------------------------------------------------
// 重写驱动器：在 database/sql 的 Prepare 层翻译 SQL（含事务内语句），并转换
// Go 侧绑定值的类型以匹配 PostgreSQL 列类型。
// ---------------------------------------------------------------------------

// newRewriteConnector 包装 lib/pq 的连接器：每个 Prepare 先把 SQLite 方言翻译为
// PostgreSQL，再交给底层驱动。真实连接路径本步未运行实测。
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

// CheckNamedValue 转换 Go 侧绑定值：布尔 -> 0/1 整数、time.Time -> UTC 毫秒整数，
// 与 SQLite 存储模型（布尔 INTEGER 0/1、时间 BIGINT 毫秒）保持一致后再交给驱动。
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
		// 仓储的时间列是 UTC 毫秒 BIGINT；直接传 time.Time 会被驱动编码为 timestamptz。
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
