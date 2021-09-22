package backup

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"
)

// 受限查询的行数上限。预览默认只取少量行；导出也必须显式受控，不能因为条件
// 过宽就把整库拉进内存或磁盘。
const (
	// DefaultPreviewRows 是预览默认行数。
	DefaultPreviewRows = 20
	// MaxPreviewRows 是预览允许的最大行数。
	MaxPreviewRows = 200
	// DefaultExportRows 是导出默认行数。
	DefaultExportRows = 1000
	// MaxExportRows 是导出允许的最大行数。
	MaxExportRows = 100000
	// MaxFilterValues 是单个 IN 条件的取值数量上限。
	MaxFilterValues = 64
	// maxFilterSpecBytes 是单个过滤条件的文本上限。
	maxFilterSpecBytes = 1024
)

// ColumnFilter 是一个参数化的过滤条件（多个条件之间为 AND）。
type ColumnFilter struct {
	// Column 是字段名（必须存在于该表可用字段集合）。
	Column string `json:"column"`
	// Operator 是受控操作符之一：= != < <= > >= LIKE IN。
	Operator string `json:"operator"`
	// Values 是参数值；IN 可以有多个值，其他操作符固定一个。全部通过占位符
	// 绑定，绝不拼接进 SQL 文本。
	Values []string `json:"values"`
}

// OrderSpec 是受控排序项。
type OrderSpec struct {
	Column string `json:"column"`
	Desc   bool   `json:"desc"`
}

// TableColumn 是快照 schema 中的一列及其默认可见性。
type TableColumn struct {
	Name            string `json:"name"`
	DeclaredType    string `json:"declared_type"`
	Sensitive       bool   `json:"sensitive"`
	SensitiveReason string `json:"sensitive_reason,omitempty"`
}

// TableSchema 是受控目录表在具体备份中的实际可用字段。
type TableSchema struct {
	Table     PreviewTable  `json:"table"`
	Available bool          `json:"available"`
	Columns   []TableColumn `json:"columns"`
}

// 受控过滤操作符白名单。
var allowedFilterOperators = map[string]struct{}{
	"=": {}, "!=": {}, "<": {}, "<=": {}, ">": {}, ">=": {},
	"LIKE": {}, "IN": {},
}

// filterSpecPattern 解析 `<字段><操作符><值>`。字段名先行校验，值交由 IN 解析器
// 或直接作为参数绑定。
var filterSpecPattern = regexp.MustCompile(
	`(?i)^([A-Za-z_][A-Za-z0-9_]*)\s*(<=|>=|!=|=|<|>|LIKE|IN)\s*(.*)$`)

// ParseColumnFilter 解析一个受限过滤条件，例如 `status=active`、
// `created_at_ms>=1735689600000`、`id IN (usr_a,usr_b)`。值可以用单引号包裹
// 以包含空格或逗号（单引号内用两个单引号表示一个单引号）。
func ParseColumnFilter(spec string) (ColumnFilter, error) {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return ColumnFilter{}, fmt.Errorf("%w: 过滤条件为空", ErrQueryInvalid)
	}
	if len(trimmed) > maxFilterSpecBytes {
		return ColumnFilter{}, fmt.Errorf("%w: 过滤条件过长", ErrQueryInvalid)
	}
	matches := filterSpecPattern.FindStringSubmatch(trimmed)
	if matches == nil {
		return ColumnFilter{}, fmt.Errorf(
			"%w: 过滤条件格式应为 <字段><操作符><值>（操作符仅允许 = != < <= > >= LIKE IN）",
			ErrQueryInvalid)
	}
	column := matches[1]
	operator := strings.ToUpper(matches[2])
	if _, ok := allowedFilterOperators[operator]; !ok {
		return ColumnFilter{}, fmt.Errorf("%w: 不支持的操作符 %q", ErrQueryInvalid, operator)
	}
	rawValue := strings.TrimSpace(matches[3])
	if operator == "IN" {
		values, err := parseFilterValueList(rawValue)
		if err != nil {
			return ColumnFilter{}, err
		}
		return ColumnFilter{Column: column, Operator: "IN", Values: values}, nil
	}
	if rawValue == "" {
		return ColumnFilter{}, fmt.Errorf("%w: 操作符 %s 缺少比较值",
			ErrQueryInvalid, matches[2])
	}
	return ColumnFilter{Column: column, Operator: operator,
		Values: []string{unquoteFilterValue(rawValue)}}, nil
}

// parseFilterValueList 解析 IN 列表 `(v1, v2, 'v 3')`。
func parseFilterValueList(raw string) ([]string, error) {
	if len(raw) < 2 || !strings.HasPrefix(raw, "(") || !strings.HasSuffix(raw, ")") {
		return nil, fmt.Errorf("%w: IN 值必须写成 (v1,v2,...)", ErrQueryInvalid)
	}
	body := strings.TrimSpace(raw[1 : len(raw)-1])
	if body == "" {
		return nil, fmt.Errorf("%w: IN 值列表为空", ErrQueryInvalid)
	}
	values := make([]string, 0, 4)
	var current strings.Builder
	quoted := false
	for index := 0; index < len(body); index++ {
		char := body[index]
		if quoted {
			if char == '\'' {
				if index+1 < len(body) && body[index+1] == '\'' {
					current.WriteByte('\'')
					index++
					continue
				}
				quoted = false
				continue
			}
			current.WriteByte(char)
			continue
		}
		switch char {
		case '\'':
			quoted = true
		case ',':
			values = append(values, strings.TrimSpace(current.String()))
			current.Reset()
		case '(', ')':
			return nil, fmt.Errorf("%w: IN 值中不允许嵌套括号", ErrQueryInvalid)
		default:
			current.WriteByte(char)
		}
	}
	if quoted {
		return nil, fmt.Errorf("%w: IN 值单引号未闭合", ErrQueryInvalid)
	}
	values = append(values, strings.TrimSpace(current.String()))
	if len(values) > MaxFilterValues {
		return nil, fmt.Errorf("%w: IN 值数量超过上限 %d", ErrQueryInvalid, MaxFilterValues)
	}
	for _, value := range values {
		if value == "" {
			return nil, fmt.Errorf("%w: IN 值不允许空项", ErrQueryInvalid)
		}
	}
	return values, nil
}

// unquoteFilterValue 去掉值两侧的单引号并还原转义的单引号。
func unquoteFilterValue(raw string) string {
	if len(raw) >= 2 && raw[0] == '\'' && raw[len(raw)-1] == '\'' {
		return strings.ReplaceAll(raw[1:len(raw)-1], "''", "'")
	}
	return raw
}

// ParseOrderSpec 解析排序项：`字段`（升序）、`字段:asc` 或 `字段:desc`。
func ParseOrderSpec(spec string) (OrderSpec, error) {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return OrderSpec{}, fmt.Errorf("%w: 排序条件为空", ErrQueryInvalid)
	}
	if len(trimmed) > 128 {
		return OrderSpec{}, fmt.Errorf("%w: 排序条件过长", ErrQueryInvalid)
	}
	parts := strings.Split(trimmed, ":")
	if len(parts) > 2 {
		return OrderSpec{}, fmt.Errorf("%w: 排序条件应为 <字段>[:asc|:desc]", ErrQueryInvalid)
	}
	column := strings.TrimSpace(parts[0])
	if !safeSQLIdentifier.MatchString(column) {
		return OrderSpec{}, fmt.Errorf("%w: 排序字段名不合法", ErrQueryInvalid)
	}
	order := OrderSpec{Column: column}
	if len(parts) == 2 {
		switch strings.ToLower(strings.TrimSpace(parts[1])) {
		case "asc":
		case "desc":
			order.Desc = true
		default:
			return OrderSpec{}, fmt.Errorf("%w: 排序方向只允许 asc 或 desc", ErrQueryInvalid)
		}
	}
	return order, nil
}

// ParseColumnList 解析逗号分隔的字段列表；拒绝空项与重复项。
func ParseColumnList(spec string) ([]string, error) {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return nil, fmt.Errorf("%w: 字段列表为空", ErrQueryInvalid)
	}
	parts := strings.Split(trimmed, ",")
	if len(parts) > 128 {
		return nil, fmt.Errorf("%w: 字段数量超过上限", ErrQueryInvalid)
	}
	seen := make(map[string]struct{}, len(parts))
	columns := make([]string, 0, len(parts))
	for _, part := range parts {
		column := strings.TrimSpace(part)
		if !safeSQLIdentifier.MatchString(column) {
			return nil, fmt.Errorf("%w: 字段名不合法 %q", ErrQueryInvalid, column)
		}
		if _, exists := seen[column]; exists {
			return nil, fmt.Errorf("%w: 字段重复 %q", ErrQueryInvalid, column)
		}
		seen[column] = struct{}{}
		columns = append(columns, column)
	}
	return columns, nil
}

// DescribeTable 读取认证快照中白名单表的实际字段与敏感分类。表不存在于该备份
// （较旧版本）时 Available=false；未知表名直接拒绝。
func (v *Viewer) DescribeTable(ctx context.Context, name string) (TableSchema, error) {
	ctx = normalizeContext(ctx)
	table, ok := lookupPreviewTable(name)
	if !ok {
		return TableSchema{}, fmt.Errorf(
			"%w: 表 %q 不在受控目录中；可用表：%s", ErrQueryInvalid, name,
			strings.Join(tableNamesForDisplay(), ", "))
	}
	db, err := v.readOnlyDatabase(ctx)
	if err != nil {
		return TableSchema{}, err
	}
	columns, err := readTableColumns(ctx, db, table.Name)
	if err != nil {
		return TableSchema{}, err
	}
	return TableSchema{Table: table, Available: len(columns) > 0, Columns: columns}, nil
}

// ListTableSchemas 返回目录中全部表在本次备份中的实际可用字段。目录外的表永远
// 不会出现在结果里。
func (v *Viewer) ListTableSchemas(ctx context.Context) ([]TableSchema, error) {
	ctx = normalizeContext(ctx)
	schemas := make([]TableSchema, 0, len(previewTableCatalog))
	for _, table := range previewTableCatalog {
		schema, err := v.DescribeTable(ctx, table.Name)
		if err != nil {
			return nil, err
		}
		schemas = append(schemas, schema)
	}
	return schemas, nil
}

// readTableColumns 用 PRAGMA table_info 读取列信息。表名来自静态白名单且再次通过
// 标识符校验与双引号包裹，不来自用户输入。
func readTableColumns(ctx context.Context, db *sql.DB, tableName string) ([]TableColumn, error) {
	quoted, err := quoteSQLiteIdentifier(tableName)
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, "PRAGMA table_info("+quoted+")")
	if err != nil {
		return nil, fmt.Errorf("%w: 无法读取表结构", ErrBackupIO)
	}
	defer rows.Close()
	columns := make([]TableColumn, 0, 16)
	for rows.Next() {
		var columnID int
		var name string
		var declaredType string
		var notNull int
		var defaultValue any
		var primaryKey int
		if err := rows.Scan(&columnID, &name, &declaredType, &notNull,
			&defaultValue, &primaryKey); err != nil {
			return nil, fmt.Errorf("%w: 读取表结构失败", ErrBackupIO)
		}
		if !safeSQLIdentifier.MatchString(name) {
			return nil, fmt.Errorf("%w: 快照表 %s 的列名不符合标识符规则", ErrQueryInvalid,
				tableName)
		}
		column := TableColumn{Name: name, DeclaredType: declaredType}
		if reason, sensitive := sensitiveColumnReason(tableName, name); sensitive {
			column.Sensitive = true
			column.SensitiveReason = reason
		}
		columns = append(columns, column)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: 遍历表结构失败", ErrBackupIO)
	}
	return columns, nil
}

// QueryOptions 是一次受限查询的请求。Filters 之间为 AND；OrderBy 按顺序生效。
type QueryOptions struct {
	// Table 必须位于静态受控目录。
	Table string
	// Columns 为空表示全部默认可见字段（默认排除敏感字段）。
	Columns []string
	// Filters 是参数化 AND 条件。
	Filters []ColumnFilter
	// OrderBy 是受控排序。
	OrderBy []OrderSpec
	// Limit 是返回行数上限（必须 1..MaxExportRows）。
	Limit int
	// IncludeSensitive 显式确认读取默认排除的高敏字段。CLI 传 --include-sensitive。
	IncludeSensitive bool
}

// QueryPlan 是已校验、可执行的受限查询（标识符来自快照 schema，值全部参数化）。
type QueryPlan struct {
	Table     string
	Columns   []string
	Excluded  []string
	Filters   []ColumnFilter
	OrderBy   []OrderSpec
	Limit     int
	Sensitive bool

	statement string
	arguments []any
}

// Statement 返回参数化 SQL 文本（仅供诊断/测试断言，不含用户输入拼接）。
func (p *QueryPlan) Statement() string {
	if p == nil {
		return ""
	}
	return p.statement
}

// Args 返回参数值副本。
func (p *QueryPlan) Args() []any {
	if p == nil {
		return nil
	}
	result := make([]any, len(p.arguments))
	copy(result, p.arguments)
	return result
}

// BuildQueryPlan 校验表/字段/操作符/排序/行数并构造参数化查询。未知表、未知
// 字段、未知操作符、越限行数返回 ErrQueryInvalid；未确认的高敏字段返回
// ErrSensitiveRequired（默认拒绝）。
func (v *Viewer) BuildQueryPlan(ctx context.Context, options QueryOptions) (*QueryPlan, error) {
	ctx = normalizeContext(ctx)
	table, ok := lookupPreviewTable(options.Table)
	if !ok {
		return nil, fmt.Errorf("%w: 表 %q 不在受控目录中；可用表：%s",
			ErrQueryInvalid, options.Table, strings.Join(tableNamesForDisplay(), ", "))
	}
	if options.Limit < 1 || options.Limit > MaxExportRows {
		return nil, fmt.Errorf("%w: 行数上限必须在 1..%d 之间", ErrQueryInvalid,
			MaxExportRows)
	}
	schema, err := v.DescribeTable(ctx, table.Name)
	if err != nil {
		return nil, err
	}
	if !schema.Available {
		return nil, fmt.Errorf("%w: 该备份数据库中不存在表 %s（可能是较旧版本的备份）",
			ErrQueryInvalid, table.Name)
	}
	available := make(map[string]TableColumn, len(schema.Columns))
	for _, column := range schema.Columns {
		available[column.Name] = column
	}
	plan := &QueryPlan{Table: table.Name, Limit: options.Limit,
		Filters: append([]ColumnFilter(nil), options.Filters...),
		OrderBy: append([]OrderSpec(nil), options.OrderBy...)}
	// 选择字段：默认全部非敏感字段；显式字段必须存在且（敏感时）已确认。
	for _, column := range schema.Columns {
		if column.Sensitive {
			plan.Excluded = append(plan.Excluded, column.Name)
		}
	}
	if len(options.Columns) == 0 {
		for _, column := range schema.Columns {
			if !column.Sensitive {
				plan.Columns = append(plan.Columns, column.Name)
			}
		}
	} else {
		for _, name := range options.Columns {
			column, exists := available[name]
			if !exists {
				return nil, fmt.Errorf("%w: 表 %s 不存在字段 %q",
					ErrQueryInvalid, table.Name, name)
			}
			if column.Sensitive {
				if !options.IncludeSensitive {
					return nil, fmt.Errorf(
						"%w: 字段 %s.%s 属于默认排除的高敏字段（%s）；如确需导出请显式使用 --include-sensitive 并确保输出位置受保护",
						ErrSensitiveRequired, table.Name, name, column.SensitiveReason)
				}
				plan.Sensitive = true
			}
			plan.Columns = append(plan.Columns, name)
		}
	}
	if len(plan.Columns) == 0 {
		return nil, fmt.Errorf("%w: 没有可导出的字段（全部为默认排除的高敏字段）",
			ErrQueryInvalid)
	}
	for index := range plan.Filters {
		filter := &plan.Filters[index]
		column, exists := available[filter.Column]
		if !exists {
			return nil, fmt.Errorf("%w: 表 %s 不存在过滤字段 %q",
				ErrQueryInvalid, table.Name, filter.Column)
		}
		if column.Sensitive && !options.IncludeSensitive {
			return nil, fmt.Errorf(
				"%w: 过滤字段 %s.%s 属于默认排除的高敏字段；如确需按该字段过滤请显式使用 --include-sensitive",
				ErrSensitiveRequired, table.Name, filter.Column)
		}
		if _, ok := allowedFilterOperators[filter.Operator]; !ok {
			return nil, fmt.Errorf("%w: 不支持的操作符 %q", ErrQueryInvalid,
				filter.Operator)
		}
		if filter.Operator == "IN" {
			if len(filter.Values) == 0 || len(filter.Values) > MaxFilterValues {
				return nil, fmt.Errorf("%w: IN 值数量必须在 1..%d 之间",
					ErrQueryInvalid, MaxFilterValues)
			}
		} else if len(filter.Values) != 1 {
			return nil, fmt.Errorf("%w: 操作符 %s 需要且仅需要一个值",
				ErrQueryInvalid, filter.Operator)
		}
		if column.Sensitive && options.IncludeSensitive {
			plan.Sensitive = true
		}
	}
	for index := range plan.OrderBy {
		order := &plan.OrderBy[index]
		column, exists := available[order.Column]
		if !exists {
			return nil, fmt.Errorf("%w: 表 %s 不存在排序字段 %q",
				ErrQueryInvalid, table.Name, order.Column)
		}
		if column.Sensitive && !options.IncludeSensitive {
			return nil, fmt.Errorf(
				"%w: 排序字段 %s.%s 属于默认排除的高敏字段", ErrSensitiveRequired,
				table.Name, order.Column)
		}
	}
	// 构造 SQL：标识符全部来自已校验 schema 且加双引号；值全部以 ? 绑定。
	var builder strings.Builder
	builder.WriteString("SELECT ")
	for index, column := range plan.Columns {
		if index > 0 {
			builder.WriteString(", ")
		}
		quoted, quoteErr := quoteSQLiteIdentifier(column)
		if quoteErr != nil {
			return nil, quoteErr
		}
		builder.WriteString(quoted)
	}
	quotedTable, err := quoteSQLiteIdentifier(plan.Table)
	if err != nil {
		return nil, err
	}
	builder.WriteString(" FROM ")
	builder.WriteString(quotedTable)
	arguments := make([]any, 0, 8)
	if len(plan.Filters) > 0 {
		builder.WriteString(" WHERE ")
		for index, filter := range plan.Filters {
			if index > 0 {
				builder.WriteString(" AND ")
			}
			quotedColumn, quoteErr := quoteSQLiteIdentifier(filter.Column)
			if quoteErr != nil {
				return nil, quoteErr
			}
			builder.WriteString(quotedColumn)
			switch filter.Operator {
			case "IN":
				builder.WriteString(" IN (")
				for valueIndex := range filter.Values {
					if valueIndex > 0 {
						builder.WriteString(", ")
					}
					builder.WriteString("?")
				}
				builder.WriteString(")")
				for _, value := range filter.Values {
					arguments = append(arguments, value)
				}
			default:
				builder.WriteString(" ")
				builder.WriteString(filter.Operator)
				builder.WriteString(" ?")
				arguments = append(arguments, filter.Values[0])
			}
		}
	}
	if len(plan.OrderBy) > 0 {
		builder.WriteString(" ORDER BY ")
		for index, order := range plan.OrderBy {
			if index > 0 {
				builder.WriteString(", ")
			}
			quotedColumn, quoteErr := quoteSQLiteIdentifier(order.Column)
			if quoteErr != nil {
				return nil, quoteErr
			}
			builder.WriteString(quotedColumn)
			if order.Desc {
				builder.WriteString(" DESC")
			} else {
				builder.WriteString(" ASC")
			}
		}
	}
	// 多取一行用于判断是否因行数上限被截断；渲染/导出侧不会输出多取的这一行。
	builder.WriteString(" LIMIT ?")
	arguments = append(arguments, plan.Limit+1)
	plan.statement = builder.String()
	plan.arguments = arguments
	return plan, nil
}

// QueryStream 是流式受限查询结果（导出大结果集时不整体载入内存）。
type QueryStream struct {
	ctx       context.Context
	rows      *sql.Rows
	columns   []string
	limit     int
	fetched   int
	truncated bool
	closed    bool
}

// Columns 返回结果列名。
func (s *QueryStream) Columns() []string {
	if s == nil {
		return nil
	}
	result := make([]string, len(s.columns))
	copy(result, s.columns)
	return result
}

// Next 返回下一行；第二返回值为 false 表示结束。达到行数上限后若还有数据，
// Truncated 变为 true（多取的一行被丢弃、不输出）。
func (s *QueryStream) Next() ([]any, bool, error) {
	if s == nil || s.closed {
		return nil, false, fmt.Errorf("%w: 查询结果已关闭", ErrOptionsInvalid)
	}
	if err := s.ctx.Err(); err != nil {
		return nil, false, err
	}
	if !s.rows.Next() {
		if err := s.rows.Err(); err != nil {
			return nil, false, fmt.Errorf("%w: 读取查询结果失败", ErrBackupIO)
		}
		return nil, false, nil
	}
	if s.fetched >= s.limit {
		s.truncated = true
		return nil, false, nil
	}
	values := make([]any, len(s.columns))
	pointers := make([]any, len(s.columns))
	for index := range values {
		pointers[index] = &values[index]
	}
	if err := s.rows.Scan(pointers...); err != nil {
		return nil, false, fmt.Errorf("%w: 读取查询行失败", ErrBackupIO)
	}
	s.fetched++
	return values, true, nil
}

// Truncated 报告结果是否因行数上限被截断。
func (s *QueryStream) Truncated() bool {
	if s == nil {
		return false
	}
	return s.truncated
}

// Count 返回已输出的行数。
func (s *QueryStream) Count() int {
	if s == nil {
		return 0
	}
	return s.fetched
}

// Close 关闭底层结果集。
func (s *QueryStream) Close() error {
	if s == nil || s.closed {
		return nil
	}
	s.closed = true
	return s.rows.Close()
}

// QueryResult 是预览用的小结果集（已整体读取，受行数上限约束）。
type QueryResult struct {
	Table     string   `json:"table"`
	Columns   []string `json:"columns"`
	Rows      [][]any  `json:"rows"`
	Excluded  []string `json:"excluded_sensitive_columns,omitempty"`
	Limit     int      `json:"limit"`
	Truncated bool     `json:"truncated"`
}

// OpenQuery 执行受限查询并返回流式结果。
func (v *Viewer) OpenQuery(ctx context.Context, plan *QueryPlan) (*QueryStream, error) {
	ctx = normalizeContext(ctx)
	if plan == nil {
		return nil, fmt.Errorf("%w: 查询计划为空", ErrOptionsInvalid)
	}
	db, err := v.readOnlyDatabase(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, plan.Statement(), plan.Args()...)
	if err != nil {
		return nil, fmt.Errorf("%w: 受限查询执行失败", ErrBackupIO)
	}
	return &QueryStream{ctx: ctx, rows: rows, columns: append([]string(nil), plan.Columns...),
		limit: plan.Limit}, nil
}

// PreviewQuery 执行受限查询并把最多 Limit 行读入内存（供终端预览）。
func (v *Viewer) PreviewQuery(ctx context.Context, plan *QueryPlan) (*QueryResult, error) {
	stream, err := v.OpenQuery(ctx, plan)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	result := &QueryResult{Table: plan.Table, Columns: stream.Columns(),
		Rows: make([][]any, 0, plan.Limit), Excluded: append([]string(nil),
			plan.Excluded...), Limit: plan.Limit}
	for {
		row, ok, nextErr := stream.Next()
		if nextErr != nil {
			return nil, nextErr
		}
		if !ok {
			break
		}
		result.Rows = append(result.Rows, row)
	}
	result.Truncated = stream.Truncated()
	return result, nil
}
