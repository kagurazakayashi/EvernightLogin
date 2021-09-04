package reports

import (
	"encoding/csv"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// reportTimeLayout 是报告文本格式中的时间表示（UTC RFC3339，可含毫秒）。
const reportTimeLayout = time.RFC3339Nano

// csvColumns 是结构化统计数据导出的稳定列顺序。CSV 采用长表（每行一个指标值）
// 以便机器读取所有图表与汇总数据，而不是只有一张人读表格。
var csvColumns = []string{
	"section", "series", "bucket", "bucket_start", "bucket_end", "category",
	"severity", "error_code", "app_id", "metric", "value", "unit", "status",
	"first_seen", "last_seen", "note",
}

// csvNumericValueColumn 是唯一不做公式注入防护的列：value。
//
// 数据行的 value 是十进制数值（计数/占比/百分比，含负增幅），必须保持数字类型，
// 不能被前置单引号变成文本；元数据行的 value 只放受控标识/时间/布尔文本（报告
// 编号、作用范围、时区、RFC3339、true/false），这些值均由服务端生成或白名单
// 校验，不含调用方可控的自由文本，因此不需要公式防护。所有可能来自数据/用户的
// 文本列（error_code/app_id/note 等）仍逐格防护。
const csvNumericValueColumn = 10 // value 列下标（前 9 列 + metric = 第 10 列）

// renderCSV 把快照渲染为 UTF-8 CSV。文本列做公式注入防护；引号、逗号与换行由
// encoding/csv 按 RFC 4180 正确转义；value 列保持数值文本（负数不前置单引号）。
func renderCSV(snapshot Snapshot) ([]byte, error) {
	var builder strings.Builder
	builder.Grow(4096)
	writer := csv.NewWriter(&builder)
	if err := writer.Write(csvColumns); err != nil {
		return nil, fmt.Errorf("%w: CSV 表头写入失败", ErrInvalidRequest)
	}
	writeRow := func(row []string) error {
		if len(row) != len(csvColumns) {
			return fmt.Errorf("%w: CSV 行列数不一致", ErrInvalidRequest)
		}
		for index := range row {
			if index == csvNumericValueColumn {
				continue
			}
			row[index] = safeCSVText(row[index])
		}
		return writer.Write(row)
	}
	// writeValueRow 的参数顺序与列顺序严格一致：
	// section, series, bucket, bucketStart, bucketEnd, category, severity,
	// errorCode, appID, metric, value, unit, status, firstSeen, lastSeen, note。
	writeValueRow := func(section, series, bucket, bucketStart, bucketEnd, category,
		severity, errorCode, appID, metric, value, unit, status, firstSeen,
		lastSeen, note string) error {
		return writeRow([]string{section, series, bucket, bucketStart, bucketEnd,
			category, severity, errorCode, appID, metric, value, unit, status,
			firstSeen, lastSeen, note})
	}
	// 元数据行：报告编号、生成时间、范围、时区、模板版本、完整性状态。
	meta := [][2]string{
		{"report_id", snapshot.Report.ID},
		{"schema_version", snapshot.Schema.Version},
		{"template_version", strconv.Itoa(snapshot.Schema.TemplateVersion)},
		{"time_format", snapshot.Schema.TimeFormat},
		{"unknown_time", snapshot.Schema.UnknownTime},
		{"generated_at", formatTime(snapshot.Report.GeneratedAt)},
		{"requested_by", snapshot.Report.RequestedBy.Type + ":" + snapshot.Report.RequestedBy.ID},
		{"scope_id", snapshot.Report.Scope.ID},
		{"scope_kind", snapshot.Report.Scope.Kind},
		{"timezone", snapshot.Report.Window.TimeZone},
		{"window_start", formatTime(snapshot.Report.Window.Start)},
		{"window_end", formatTime(snapshot.Report.Window.End)},
		{"data_cutoff", formatTime(snapshot.Report.Window.DataCutoff)},
		{"granularity", snapshot.Report.Window.Granularity},
		{"app_id", snapshot.Report.Filters.AppID},
		{"trend_metric", snapshot.Report.Filters.TrendMetric},
		{"overall_status", string(snapshot.Overall)},
	}
	for _, item := range meta {
		if err := writeValueRow("meta", item[0], "", "", "", "", "", "", "",
			"", item[1], "", "", "", "", ""); err != nil {
			return nil, err
		}
	}
	for _, note := range snapshot.Notes {
		if err := writeValueRow("note", "", "", "", "", "", "", "", "", "",
			"", "", "", "", "", note); err != nil {
			return nil, err
		}
	}
	// 活跃度：逐桶值与窗口内去重总数（同一快照）。
	for _, point := range snapshot.Activity.Points {
		if err := writeValueRow("activity", string(snapshot.Activity.Metric),
			point.BucketKey, formatTime(point.Start), formatTime(point.End), "",
			"", "", "", "active_users",
			strconv.FormatInt(point.ActiveUsers, 10), "users", point.Status,
			"", "", ""); err != nil {
			return nil, err
		}
	}
	if err := writeValueRow("activity_total", string(snapshot.Activity.Metric), "", "",
		"", "", "", "", "", "total_distinct_users",
		strconv.FormatInt(snapshot.Activity.Total, 10), "users",
		string(snapshot.Overall), "", "", ""); err != nil {
		return nil, err
	}
	// 错误汇总：三个独立指标不互相换算。
	for _, category := range snapshot.Errors.Categories {
		definitions := []struct {
			metric string
			value  int64
			unit   string
		}{
			{"raw_events", category.RawEvents, "events"},
			{"failed_requests", category.FailedRequests, "requests"},
			{"failed_tasks", category.FailedTasks, "tasks"},
		}
		for _, definition := range definitions {
			if err := writeValueRow("category_summary", category.Category, "", "",
				"", category.Category, category.Severity, "", "",
				definition.metric, strconv.FormatInt(definition.value, 10),
				definition.unit, string(snapshot.Overall), "", "", ""); err != nil {
				return nil, err
			}
		}
	}
	for _, item := range []struct {
		metric string
		value  int64
		unit   string
	}{
		{"total_raw_events", snapshot.Errors.TotalRawEvents, "events"},
		{"failed_requests", snapshot.Errors.FailedRequests, "requests"},
		{"failed_tasks", snapshot.Errors.FailedTasks, "tasks"},
	} {
		if err := writeValueRow("errors_total", "", "", "", "", "", "", "", "",
			item.metric, strconv.FormatInt(item.value, 10), item.unit,
			string(snapshot.Overall), "", "", ""); err != nil {
			return nil, err
		}
	}
	// 趋势：与图表同源的每桶每类别数值。
	for _, point := range snapshot.Trend.Points {
		definitions := []struct {
			metric string
			value  int64
			unit   string
		}{
			{"raw_events", point.RawEvents, "events"},
			{"failed_requests", point.FailedRequests, "requests"},
			{"failed_tasks", point.FailedTasks, "tasks"},
		}
		for _, definition := range definitions {
			if err := writeValueRow("trend", point.Category, point.BucketKey,
				formatTime(point.Start), formatTime(point.End), point.Category,
				point.Severity, "", "", definition.metric,
				strconv.FormatInt(definition.value, 10), definition.unit,
				point.Status, "", "", ""); err != nil {
				return nil, err
			}
		}
	}
	// 错误明细行：字段白名单，不含内部原因码/原始日志。
	for _, row := range snapshot.Errors.Rows {
		first, last := formatTime(row.FirstSeen), formatTime(row.LastSeen)
		for _, definition := range []struct {
			metric string
			value  string
			unit   string
		}{
			{"raw_events", strconv.FormatInt(row.RawEvents, 10), "events"},
			{"failed_requests", strconv.FormatInt(row.FailedRequests, 10), "requests"},
			{"failed_tasks", strconv.FormatInt(row.FailedTasks, 10), "tasks"},
			{"share", formatFloat(row.Share), "ratio"},
		} {
			if err := writeValueRow("error_row", row.ErrorCode, "", "", "",
				row.Category, row.Severity, row.ErrorCode, row.AppID,
				definition.metric, definition.value, definition.unit, row.Status,
				first, last, ""); err != nil {
				return nil, err
			}
		}
		// 增幅：只有可计算百分比时 value 为数值；其他 kind 的 value 留空并在
		// status 给出 kind，绝不用 0 冒充“不可计算”。
		growthValue := ""
		if row.Growth.Percent != nil {
			growthValue = formatFloat(*row.Growth.Percent)
		}
		if err := writeValueRow("error_row", row.ErrorCode, "", "", "",
			row.Category, row.Severity, row.ErrorCode, row.AppID,
			"growth_percent", growthValue, "percent", row.Growth.Kind,
			formatTime(row.Growth.ComparisonStart.Time),
			formatTime(row.Growth.ComparisonEnd.Time), ""); err != nil {
			return nil, err
		}
	}
	// 完整性：保留期、缺失区间、截断与裁剪（缺失不是零）。
	retention := "configured"
	if !snapshot.Completeness.RetentionConfigured {
		retention = "default"
	}
	completeness := []struct{ metric, value string }{
		{"window_within_retention", strconv.FormatBool(snapshot.Completeness.WindowWithinRetention)},
		{"retention_days", strconv.Itoa(snapshot.Completeness.RetentionDays)},
		{"retention_source", retention},
		{"retention_cutoff", formatTime(snapshot.Completeness.RetentionCutoff.Time)},
		{"scope_trimmed", strconv.FormatBool(snapshot.Completeness.ScopeTrimmed)},
		{"source_truncated", strconv.FormatBool(snapshot.Completeness.SourceTruncated)},
		{"detail_rows_truncated", strconv.FormatBool(snapshot.Completeness.DetailRowsTruncated)},
	}
	for _, item := range completeness {
		if err := writeValueRow("completeness", "", "", "", "", "", "", "", "",
			item.metric, item.value, "", string(snapshot.Overall),
			"", "", ""); err != nil {
			return nil, err
		}
	}
	for _, interval := range snapshot.Completeness.MissingIntervals {
		if err := writeValueRow("missing_interval", "", "", formatTime(interval.Start),
			formatTime(interval.End), "", "", "", "", "missing", "", "",
			"unknown", "", "", interval.Reason); err != nil {
			return nil, err
		}
	}
	for _, module := range snapshot.Completeness.ModulesNotEnabled {
		if err := writeValueRow("module_not_enabled", "", "", "", "", "", "",
			"", "", "not_enabled", "", "", "not_enabled", "", "", module); err != nil {
			return nil, err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf("%w: CSV 写入失败", ErrInvalidRequest)
	}
	return []byte(builder.String()), nil
}

// safeCSVText 防止电子表格把文本单元格当作公式执行：首字符为 = + - @ 或制表/
// 回车/换行时前置单引号（OWASP CSV Injection 防护）。空单元格保持为空。
func safeCSVText(value string) string {
	if value == "" {
		return ""
	}
	switch value[0] {
	case '=', '+', '-', '@', '\t', '\r', '\n':
		return "'" + value
	default:
		return value
	}
}

// formatTime 把时间格式化为 UTC RFC3339；零值输出空字符串（未知不是 1970 年）。
func formatTime(moment time.Time) string {
	if moment.IsZero() {
		return ""
	}
	return moment.UTC().Format(reportTimeLayout)
}

// formatFloat 用最短十进制表示浮点数，去掉无意义尾零。
func formatFloat(value float64) string {
	return strconv.FormatFloat(value, 'f', -1, 64)
}
