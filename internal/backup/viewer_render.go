package backup

import (
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// CSV/JSON 渲染与单元格安全（步骤 83）。CSV 沿用项目既有防公式注入策略（步骤
// 73/77 的 safeCSVText）：文本单元格首字符为 = + - @ 或制表/回车/换行时前置
// 单引号；数值类型（INTEGER/REAL 扫描结果）本身就是数字，不添加前缀。JSON 由
// 编码器写出，不执行、不注入，公式样文本只是 JSON 字符串。
const (
	// previewCellMaxRunes 是终端预览单单元格最大显示长度。
	previewCellMaxRunes = 120
	// exportFormatVersionJSON 是 JSON 导出结构的格式版本。
	exportFormatVersionJSON = 1
)

// safeCSVText 防止电子表格把文本单元格当作公式执行：在前导空白/制表/回车/
// 换行/控制字符/Unicode BOM 之后的首个有效字符为 = + - @ 时前置单引号
// （OWASP CSV Injection 防护）；单元格本身以制表/回车/换行开头时同样前置。
// 归一化是为了覆盖 `" =1+1"`、BOM+`=`、制表+`=` 这类电子表格仍会执行的形式。
// 空单元格保持为空。
func safeCSVText(value string) string {
	if value == "" {
		return ""
	}
	trimmed := strings.TrimLeftFunc(value, func(char rune) bool {
		return char == '\uFEFF' || unicode.IsSpace(char) || char < 0x20 || char == 0x7f
	})
	if trimmed != "" {
		first, _ := utf8.DecodeRuneInString(trimmed)
		switch first {
		case '=', '+', '-', '@':
			return "'" + value
		}
	}
	switch value[0] {
	case '\t', '\r', '\n':
		return "'" + value
	default:
		return value
	}
}

// csvCell 把数据库值转换为 CSV 单元格文本。数值类型保持数字文本（负数不假定为
// 公式）；BLOB 用十六进制表示（十六进制文本不会以公式字符开头）；文本执行公式
// 注入防护。
func csvCell(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case int64:
		return strconv.FormatInt(typed, 10)
	case float64:
		return strconv.FormatFloat(typed, 'g', -1, 64)
	case bool:
		if typed {
			return "1"
		}
		return "0"
	case []byte:
		return hex.EncodeToString(typed)
	case string:
		return safeCSVText(typed)
	case time.Time:
		return safeCSVText(typed.UTC().Format(time.RFC3339Nano))
	default:
		return safeCSVText(fmt.Sprint(typed))
	}
}

// previewCell 把值转换为单行终端文本：控制字符转义（防止终端转义序列注入），
// 过长内容截断，避免预览把终端刷乱。
func previewCell(value any) string {
	var text string
	switch typed := value.(type) {
	case nil:
		return "NULL"
	case []byte:
		text = "0x" + hex.EncodeToString(typed)
	case string:
		text = typed
	default:
		text = fmt.Sprint(typed)
	}
	var builder strings.Builder
	for _, char := range text {
		switch {
		case char == '\t':
			builder.WriteString(`\t`)
		case char == '\r':
			builder.WriteString(`\r`)
		case char == '\n':
			builder.WriteString(`\n`)
		case char < 0x20 || char == 0x7f:
			builder.WriteString(fmt.Sprintf(`\x%02x`, char))
		default:
			builder.WriteRune(char)
		}
		if utf8.RuneCountInString(builder.String()) > previewCellMaxRunes {
			escaped := builder.String()
			runes := []rune(escaped)
			return string(runes[:previewCellMaxRunes]) + "…"
		}
	}
	return builder.String()
}

// WritePreviewText 把受限查询结果渲染为终端文本预览。它不输出未选中的敏感字段，
// 并明确说明行数上限与截断状态。
func WritePreviewText(writer io.Writer, result *QueryResult) error {
	if result == nil {
		return fmt.Errorf("%w: 预览结果为空", ErrOptionsInvalid)
	}
	truncated := "否"
	if result.Truncated {
		truncated = "是（达到行数上限，可用更小范围或更高 --limit 查看）"
	}
	if _, err := fmt.Fprintf(writer, "表 %s：返回 %d 行（上限 %d），更多数据：%s\n",
		result.Table, len(result.Rows), result.Limit, truncated); err != nil {
		return err
	}
	header := make([]string, len(result.Columns))
	for index, column := range result.Columns {
		header[index] = previewCell(column)
	}
	if _, err := fmt.Fprintln(writer, strings.Join(header, "\t")); err != nil {
		return err
	}
	for _, row := range result.Rows {
		cells := make([]string, len(row))
		for index, value := range row {
			cells[index] = previewCell(value)
		}
		if _, err := fmt.Fprintln(writer, strings.Join(cells, "\t")); err != nil {
			return err
		}
	}
	if len(result.Excluded) > 0 {
		if _, err := fmt.Fprintf(writer,
			"注意：以下敏感字段默认排除（如确需导出请显式 --include-sensitive）：%s\n",
			strings.Join(result.Excluded, ", ")); err != nil {
			return err
		}
	}
	return nil
}

// writeCSVExport 把受限查询流式写为 CSV，返回行数与截断状态。失败时调用方负责
// 删除不完整输出文件。
func writeCSVExport(writer io.Writer, stream *QueryStream) (int64, error) {
	csvWriter := csv.NewWriter(writer)
	columns := stream.Columns()
	if err := csvWriter.Write(columns); err != nil {
		return 0, fmt.Errorf("%w: 写入 CSV 表头失败", ErrBackupIO)
	}
	var rowCount int64
	for {
		row, ok, err := stream.Next()
		if err != nil {
			return rowCount, err
		}
		if !ok {
			break
		}
		record := make([]string, len(row))
		for index, value := range row {
			record[index] = csvCell(value)
		}
		if err := csvWriter.Write(record); err != nil {
			return rowCount, fmt.Errorf("%w: 写入 CSV 数据行失败", ErrBackupIO)
		}
		rowCount++
	}
	csvWriter.Flush()
	if err := csvWriter.Error(); err != nil {
		return rowCount, fmt.Errorf("%w: CSV 写入失败", ErrBackupIO)
	}
	return rowCount, nil
}

// jsonExportMeta 是 JSON 导出文件的头部元数据（不含数据值）。
type jsonExportMeta struct {
	FormatVersion       int      `json:"format_version"`
	BackupID            string   `json:"backup_id"`
	Table               string   `json:"table"`
	Columns             []string `json:"columns"`
	ExcludedSensitive   []string `json:"excluded_sensitive_columns,omitempty"`
	Limit               int      `json:"limit"`
	SensitiveIncluded   bool     `json:"sensitive_included"`
	BackupFileSHA256    string   `json:"backup_file_sha256"`
	SchemaFormatVersion int      `json:"backup_format_version"`
}

// writeJSONExport 把受限查询流式写为 JSON 对象：头部元数据 + rows 数组 + 行数与
// 截断状态。值由 encoding/json 编码，不会执行任何内容。
func writeJSONExport(writer io.Writer, stream *QueryStream, meta jsonExportMeta) (int64, bool, error) {
	headerBytes, err := json.Marshal(meta)
	if err != nil {
		return 0, false, fmt.Errorf("%w: JSON 元数据序列化失败", ErrInternal)
	}
	headerText := strings.TrimSuffix(string(headerBytes), "}")
	if _, err := io.WriteString(writer, headerText+`,"rows":[`); err != nil {
		return 0, false, fmt.Errorf("%w: 写入 JSON 导出失败", ErrBackupIO)
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(true)
	columns := stream.Columns()
	var rowCount int64
	for {
		row, ok, nextErr := stream.Next()
		if nextErr != nil {
			return rowCount, false, nextErr
		}
		if !ok {
			break
		}
		record := make(map[string]any, len(row))
		for index, value := range row {
			// []byte 由 encoding/json 编为 base64 字符串；nil 编为 null。
			record[columns[index]] = value
		}
		if rowCount > 0 {
			if _, err := io.WriteString(writer, ","); err != nil {
				return rowCount, false, fmt.Errorf("%w: 写入 JSON 导出失败", ErrBackupIO)
			}
		}
		if err := encoder.Encode(record); err != nil {
			return rowCount, false, fmt.Errorf("%w: 写入 JSON 数据行失败", ErrBackupIO)
		}
		rowCount++
	}
	if _, err := fmt.Fprintf(writer, `],"row_count":%d,"truncated":%t}`,
		rowCount, stream.Truncated()); err != nil {
		return rowCount, false, fmt.Errorf("%w: 写入 JSON 导出结尾失败", ErrBackupIO)
	}
	return rowCount, stream.Truncated(), nil
}
