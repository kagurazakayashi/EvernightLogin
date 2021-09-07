package reports

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
)

// Snapshot 是生成报告时冻结的固定统计快照：一次生成只取一个规范化窗口与一个
// 统计截止点，所有图表、汇总与明细都从本对象读取，避免“图表一个时间范围、
// 明细另一个范围”的不一致。JSON 导出直接序列化本结构，因此字段标签是稳定
// Schema 的一部分（SchemaVersion 变更时才允许不兼容修改）。
type Snapshot struct {
	// Schema 是机器可读结构与时间格式声明。
	Schema SchemaInfo `json:"schema"`
	// Report 是报告元数据：编号、生成时间、范围、时区、模板版本、发起者。
	Report ReportMeta `json:"report"`
	// Metrics 是本次报告使用的口径定义（名称、单位、去重语义）。
	Metrics []MetricDefinition `json:"metrics"`
	// Completeness 是数据完整性（保留期、缺失区间、截断、裁剪），缺失不等于零。
	Completeness CompletenessInfo `json:"completeness"`
	// Notes 是面向读者/智能体的中文完整性说明，不能替代原始状态字段。
	Notes []string `json:"notes"`
	// Overall 是整份快照的总体完整性状态。
	Overall stats.DataStatus `json:"overall_status"`
	// Activity 是登录活跃度（成功认证去重用户）。
	Activity ActivityData `json:"activity"`
	// Errors 是错误聚合与受控明细行。
	Errors ErrorsData `json:"errors"`
	// Trend 是与错误明细同一窗口/口径的时间趋势（图表数据）。
	Trend TrendData `json:"trend"`
}

// SchemaInfo 是报告结构的机器可读声明。
type SchemaInfo struct {
	Version         string `json:"version"`
	TemplateVersion int    `json:"template_version"`
	TimeFormat      string `json:"time_format"`
	// UnknownTime 声明未知/不可用时间在 JSON 中的表示（null），避免把零值伪装成
	// 真实时间 0001-01-01T00:00:00Z。
	UnknownTime string `json:"unknown_time"`
}

// ReportTime 是报告 JSON 中的时间类型：零值序列化为 null（未知），非零值为
// UTC RFC3339 字符串（与 schema.time_format 一致）。CSV 用 .Time 走文本格式化。
type ReportTime struct {
	time.Time
}

// MarshalJSON 实现未知时间为 null 的稳定序列化。
func (moment ReportTime) MarshalJSON() ([]byte, error) {
	if moment.Time.IsZero() {
		return []byte("null"), nil
	}
	return json.Marshal(moment.Time.UTC().Format(reportTimeLayout))
}

// ReportMeta 是报告元数据。时间字段全部为 UTC RFC3339（见 schema.time_format）。
type ReportMeta struct {
	// ID 是报告编号（rpt_ + 128 位随机十六进制），不是数据库主键承诺。
	ID string `json:"id"`
	// GeneratedAt 是本快照唯一的生成时间（UTC 毫秒截断）。
	GeneratedAt time.Time `json:"generated_at"`
	// RequestedBy 是可信发起身份（不来自请求参数）。
	RequestedBy ActorInfo `json:"requested_by"`
	// Scope 是统计作用范围（system 或应用 ID）。
	Scope ScopeInfo `json:"scope"`
	// Window 是规范化后的左闭右开统计窗口与时区。
	Window WindowInfo `json:"window"`
	// Filters 是本次报告实际使用的筛选条件。
	Filters FiltersInfo `json:"filters"`
}

// ActorInfo 是报告发起者的最小身份信息。
type ActorInfo struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// ScopeInfo 是报告作用范围说明。
type ScopeInfo struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}

// WindowInfo 是规范化统计窗口（Start/End 为参与事件比较的绝对时刻，左闭右开）。
type WindowInfo struct {
	TimeZone    string       `json:"timezone"`
	Start       time.Time    `json:"start"`
	End         time.Time    `json:"end"`
	DataCutoff  time.Time    `json:"data_cutoff"`
	Granularity string       `json:"granularity"`
	Clamped     bool         `json:"clamped"`
	Buckets     []BucketInfo `json:"buckets"`
}

// BucketInfo 是一个时间桶。
type BucketInfo struct {
	Key           string    `json:"key"`
	Start         time.Time `json:"start"`
	End           time.Time `json:"end"`
	CalendarStart time.Time `json:"calendar_start"`
	CalendarEnd   time.Time `json:"calendar_end"`
	Partial       bool      `json:"partial"`
	InProgress    bool      `json:"in_progress"`
}

// FiltersInfo 是报告筛选条件快照。
type FiltersInfo struct {
	AppID       string   `json:"app_id,omitempty"`
	Categories  []string `json:"categories,omitempty"`
	TrendMetric string   `json:"trend_metric"`
}

// MetricDefinition 是口径定义，报告必须让读者知道每个数字怎么算。
type MetricDefinition struct {
	Key        string `json:"key"`
	Name       string `json:"name"`
	Unit       string `json:"unit"`
	Definition string `json:"definition"`
}

// CompletenessInfo 是报告数据完整性，缺失信息必须显式表达而不是补零。
type CompletenessInfo struct {
	WindowWithinRetention bool              `json:"window_within_retention"`
	RetentionDays         int               `json:"retention_days"`
	RetentionConfigured   bool              `json:"retention_configured"`
	RetentionCutoff       ReportTime        `json:"retention_cutoff"`
	MissingIntervals      []MissingInterval `json:"missing_intervals"`
	ScopeTrimmed          bool              `json:"scope_trimmed"`
	SourceTruncated       bool              `json:"source_truncated"`
	DetailRowsTruncated   bool              `json:"detail_rows_truncated"`
	ModulesNotEnabled     []string          `json:"modules_not_enabled,omitempty"`
	TrendPointsTruncated  bool              `json:"trend_points_truncated"`
}

// MissingInterval 是缺失/不可知时间区间（真实值未知，不是 0）。
type MissingInterval struct {
	Start  time.Time `json:"start"`
	End    time.Time `json:"end"`
	Reason string    `json:"reason"`
}

// ActivityData 是登录活跃度数据。
type ActivityData struct {
	Metric      string              `json:"metric"`
	DedupeScope string              `json:"dedupe_scope"`
	Total       int64               `json:"total_distinct_users"`
	Points      []ActivityPointData `json:"points"`
}

// ActivityPointData 是一个时间桶的活跃用户数。
type ActivityPointData struct {
	BucketKey   string    `json:"bucket"`
	Start       time.Time `json:"start"`
	End         time.Time `json:"end"`
	ActiveUsers int64     `json:"active_users"`
	Status      string    `json:"status"`
}

// ErrorsData 是错误聚合与受控明细。TotalRawEvents 是原始事件次数；FailedRequests/
// FailedTasks 是窗口内全局去重数，行级去重数不得相加冒充全局值。
type ErrorsData struct {
	TotalRawEvents   int64          `json:"total_raw_events"`
	FailedRequests   int64          `json:"failed_requests"`
	FailedTasks      int64          `json:"failed_tasks"`
	ShareDenominator int64          `json:"share_denominator"`
	Categories       []CategoryData `json:"categories"`
	Rows             []ErrorRowData `json:"rows"`
	Sort             string         `json:"sort"`
	Order            string         `json:"order"`
}

// CategoryData 是按类别的汇总；等待授权/正常拒绝/主动取消/警告/故障分开。
type CategoryData struct {
	Category       string `json:"category"`
	Severity       string `json:"severity"`
	RawEvents      int64  `json:"raw_events"`
	FailedRequests int64  `json:"failed_requests"`
	FailedTasks    int64  `json:"failed_tasks"`
}

// ErrorRowData 是一行受控错误明细（字段白名单，不含内部原因码/原始日志）。
type ErrorRowData struct {
	ErrorCode      string     `json:"error_code"`
	Category       string     `json:"category"`
	Severity       string     `json:"severity"`
	AppID          string     `json:"app_id,omitempty"`
	RawEvents      int64      `json:"raw_events"`
	FailedRequests int64      `json:"failed_requests"`
	FailedTasks    int64      `json:"failed_tasks"`
	Share          float64    `json:"share"`
	FirstSeen      time.Time  `json:"first_seen"`
	LastSeen       time.Time  `json:"last_seen"`
	Growth         GrowthData `json:"growth"`
	Status         string     `json:"status"`
}

// GrowthData 是增幅；不可用时 kind=unavailable，绝不能显示为 0%。
type GrowthData struct {
	Kind            string     `json:"kind"`
	Percent         *float64   `json:"percent,omitempty"`
	ComparisonStart ReportTime `json:"comparison_start"`
	ComparisonEnd   ReportTime `json:"comparison_end"`
}

// TrendData 是时间趋势（图表数据），与 Errors 同窗口同口径。
type TrendData struct {
	Metric string           `json:"metric"`
	Points []TrendPointData `json:"points"`
}

// TrendPointData 是一个时间桶中一个类别的统计值。
type TrendPointData struct {
	BucketKey      string    `json:"bucket"`
	Start          time.Time `json:"start"`
	End            time.Time `json:"end"`
	Category       string    `json:"category"`
	Severity       string    `json:"severity"`
	RawEvents      int64     `json:"raw_events"`
	FailedRequests int64     `json:"failed_requests"`
	FailedTasks    int64     `json:"failed_tasks"`
	Status         string    `json:"status"`
}

// snapshotRequest 是生成快照的冻结参数（来自创建报告时的已授权请求）。
type snapshotRequest struct {
	Caller      account.Caller
	Scope       ScopeInfo
	Window      stats.Window
	AppID       string
	Categories  []stats.Category
	TrendMetric stats.Metric
	DetailRows  int
}

// BuildSnapshot 从 Source 读取同一窗口的活跃度、错误聚合与趋势并冻结为快照。
// 三次读取使用完全相同的时间窗口参数；若来源返回的窗口边界不一致（违反契约），
// 返回错误而不是把不同口径的数据拼进同一份报告。来源返回的统计错误原样返回，
// 由调用方映射为失败/权限错误，不在这里改成“空报告”。
func buildSnapshot(ctx context.Context, source Source, request snapshotRequest,
	generatedAt time.Time, detailLimit int) (Snapshot, error) {
	windowRequest := stats.WindowRequest{
		TimeZone: request.Window.TimeZone, Start: request.Window.Start,
		End: request.Window.End, Granularity: request.Window.Granularity,
	}
	activity, err := source.Activity(ctx, stats.ActivityRequest{
		Caller: request.Caller, ScopeID: request.Scope.ID, Window: windowRequest,
		AppID: request.AppID,
	})
	if err != nil {
		return Snapshot{}, err
	}
	errorsResult, err := source.Errors(ctx, stats.ErrorRequest{
		Caller: request.Caller, ScopeID: request.Scope.ID, Window: windowRequest,
		AppID: request.AppID, Categories: request.Categories,
		Sort: stats.ErrorSortRaw, Order: stats.SortDesc, Limit: detailLimit,
	})
	if err != nil {
		return Snapshot{}, err
	}
	trend, err := source.ErrorTrend(ctx, stats.ErrorTrendRequest{
		Caller: request.Caller, ScopeID: request.Scope.ID, Window: windowRequest,
		AppID: request.AppID, Categories: request.Categories,
		Metric: request.TrendMetric,
	})
	if err != nil {
		return Snapshot{}, err
	}
	if !sameWindow(activity.Window, errorsResult.Window) ||
		!sameWindow(activity.Window, trend.Window) {
		return Snapshot{}, fmt.Errorf("%w: 统计来源返回的窗口不一致", ErrConflict)
	}
	return freezeSnapshot(request, activity, errorsResult, trend, generatedAt), nil
}

// sameWindow 判断两个规范化窗口的边界、时区与粒度是否完全一致。
func sameWindow(left, right stats.Window) bool {
	// 注意：time.Time 的 == 会比较 Location 指针，同一 IANA 时区经两次
	// LoadLocation 得到的指针不同但语义相同，因此必须用 Equal 比较绝对时刻。
	if left.TimeZone != right.TimeZone || !left.Start.Equal(right.Start) ||
		!left.End.Equal(right.End) || left.Granularity != right.Granularity {
		return false
	}
	if len(left.Buckets) != len(right.Buckets) {
		return false
	}
	for index := range left.Buckets {
		if !left.Buckets[index].Start.Equal(right.Buckets[index].Start) ||
			!left.Buckets[index].End.Equal(right.Buckets[index].End) ||
			left.Buckets[index].Key != right.Buckets[index].Key {
			return false
		}
	}
	return true
}

// freezeSnapshot 把统计结果转换为不可变快照并计算总体完整性/说明。
func freezeSnapshot(request snapshotRequest, activity stats.ActivityResult,
	errorsResult stats.ErrorResult, trend stats.ErrorTrendResult,
	generatedAt time.Time) Snapshot {
	window := activity.Window
	completeness := completenessFromStats(errorsResult.Completeness)
	// 明细行达到请求上限且仍有更多行时如实标记截断（明细不完整，不是零）。
	if errorsResult.HasMore {
		completeness.DetailRowsTruncated = true
	}
	snapshot := Snapshot{
		Schema: SchemaInfo{Version: SchemaVersion, TemplateVersion: TemplateVersion,
			TimeFormat: timeFormat, UnknownTime: "null"},
		Report: ReportMeta{
			ID: "", GeneratedAt: generatedAt.UTC(),
			RequestedBy: ActorInfo{},
			Scope:       request.Scope,
			Window:      windowInfo(window),
			Filters: FiltersInfo{AppID: request.AppID,
				Categories:  categoryStrings(request.Categories),
				TrendMetric: string(trend.Metric)},
		},
		Metrics:      metricDefinitions(),
		Completeness: completeness,
		Activity:     activityData(activity),
		Errors:       errorsData(errorsResult),
		Trend:        trendData(trend),
	}
	snapshot.Notes = completenessNotes(completeness)
	snapshot.Overall = overallStatus(activity, errorsResult, trend, completeness)
	return snapshot
}

// completenessFromStats 复制统计完整性并转换缺失区间。
func completenessFromStats(base stats.Completeness) CompletenessInfo {
	info := CompletenessInfo{
		WindowWithinRetention: base.WindowWithinRetention,
		RetentionDays:         base.RetentionDays,
		RetentionConfigured:   base.RetentionConfigured,
		RetentionCutoff:       ReportTime{base.RetentionCutoff.UTC()},
		ScopeTrimmed:          base.ScopeTrimmed,
		SourceTruncated:       base.SourceTruncated,
	}
	for _, interval := range base.MissingIntervals {
		info.MissingIntervals = append(info.MissingIntervals, MissingInterval{
			Start: interval.Start.UTC(), End: interval.End.UTC(),
			Reason: interval.Reason,
		})
	}
	for _, module := range base.ModulesNotEnabled {
		info.ModulesNotEnabled = append(info.ModulesNotEnabled, string(module))
	}
	return info
}

// windowInfo 把统计窗口转换为报告元数据。
func windowInfo(window stats.Window) WindowInfo {
	info := WindowInfo{
		TimeZone: window.TimeZone, Start: window.Start.UTC(),
		End: window.End.UTC(), DataCutoff: window.DataCutoff.UTC(),
		Granularity: string(window.Granularity), Clamped: window.Clamped,
		Buckets: make([]BucketInfo, 0, len(window.Buckets)),
	}
	for _, bucket := range window.Buckets {
		info.Buckets = append(info.Buckets, BucketInfo{
			Key: bucket.Key, Start: bucket.Start.UTC(), End: bucket.End.UTC(),
			CalendarStart: bucket.CalendarStart.UTC(),
			CalendarEnd:   bucket.CalendarEnd.UTC(),
			Partial:       bucket.Partial, InProgress: bucket.InProgress,
		})
	}
	return info
}

// activityData 转换活跃度结果。
func activityData(result stats.ActivityResult) ActivityData {
	data := ActivityData{Metric: string(result.Metric),
		DedupeScope: result.DedupeScope, Total: result.TotalActiveUsers,
		Points: make([]ActivityPointData, 0, len(result.Points))}
	for _, point := range result.Points {
		data.Points = append(data.Points, ActivityPointData{
			BucketKey: point.Bucket.Key, Start: point.Bucket.Start.UTC(),
			End: point.Bucket.End.UTC(), ActiveUsers: point.ActiveUsers,
			Status: string(point.DataStatus),
		})
	}
	return data
}

// errorsData 转换错误聚合结果（仅受控字段）。
func errorsData(result stats.ErrorResult) ErrorsData {
	data := ErrorsData{
		TotalRawEvents: result.TotalRawEvents, FailedRequests: result.FailedRequests,
		FailedTasks: result.FailedTasks, ShareDenominator: result.ShareDenominator,
		Sort: string(result.Sort), Order: string(result.Order),
		Categories: make([]CategoryData, 0, len(result.Categories)),
		Rows:       make([]ErrorRowData, 0, len(result.Rows)),
	}
	for _, category := range result.Categories {
		data.Categories = append(data.Categories, CategoryData{
			Category: string(category.Category), Severity: string(category.Severity),
			RawEvents: category.RawEvents, FailedRequests: category.FailedRequests,
			FailedTasks: category.FailedTasks,
		})
	}
	for _, row := range result.Rows {
		data.Rows = append(data.Rows, ErrorRowData{
			ErrorCode: row.ErrorCode, Category: string(row.Category),
			Severity: string(row.Severity), AppID: row.AppID,
			RawEvents: row.RawEvents, FailedRequests: row.FailedRequests,
			FailedTasks: row.FailedTasks, Share: row.Share,
			FirstSeen: row.FirstSeen.UTC(), LastSeen: row.LastSeen.UTC(),
			Growth: growthData(row.Growth), Status: string(row.DataStatus),
		})
	}
	return data
}

// growthData 转换增幅；只在实际可计算百分比时给出 percent，避免伪造 0%。
func growthData(growth stats.Growth) GrowthData {
	data := GrowthData{Kind: string(growth.Kind),
		ComparisonStart: ReportTime{growth.ComparisonStart.UTC()},
		ComparisonEnd:   ReportTime{growth.ComparisonEnd.UTC()}}
	if growth.Kind == stats.GrowthPercent {
		percent := growth.Percent
		data.Percent = &percent
	}
	return data
}

// trendData 转换趋势结果。
func trendData(result stats.ErrorTrendResult) TrendData {
	data := TrendData{Metric: string(result.Metric),
		Points: make([]TrendPointData, 0, len(result.Points))}
	for _, point := range result.Points {
		data.Points = append(data.Points, TrendPointData{
			BucketKey: point.Bucket.Key, Start: point.Bucket.Start.UTC(),
			End: point.Bucket.End.UTC(), Category: string(point.Category),
			Severity: string(point.Severity), RawEvents: point.RawEvents,
			FailedRequests: point.FailedRequests, FailedTasks: point.FailedTasks,
			Status: string(point.DataStatus),
		})
	}
	return data
}

// categoryStrings 返回类别筛选的稳定字符串副本。
func categoryStrings(categories []stats.Category) []string {
	if len(categories) == 0 {
		return nil
	}
	result := make([]string, 0, len(categories))
	for _, category := range categories {
		result = append(result, string(category))
	}
	sort.Strings(result)
	return result
}

// metricDefinitions 是报告口径表：每个数字都说明怎么算、单位与去重语义。
func metricDefinitions() []MetricDefinition {
	return []MetricDefinition{
		{Key: string(stats.MetricActiveUsers), Name: "活跃用户数", Unit: "人",
			Definition: "窗口内成功完成认证的去重用户数（按稳定用户 ID 去重，多应用合并后去重）；等待第二因素、等待授权、正常拒绝、主动取消不计入。"},
		{Key: string(stats.MetricRawEvents), Name: "错误原始事件次数", Unit: "次",
			Definition: "审计事实中的原始事件行数，按错误类别分类；同一失败请求的多条日志会重复计次，故不能当作失败请求数。"},
		{Key: string(stats.MetricDedupFailedRequests), Name: "去重失败请求数", Unit: "个请求",
			Definition: "失败结果事件按稳定 request_id 去重（缺失时以事件 ID 计一个逻辑请求）；只统计失败，排除任务取消与数据质量警告。"},
		{Key: string(stats.MetricDedupFailedTasks), Name: "去重失败任务数", Unit: "个任务",
			Definition: "失败结果事件按稳定 task_id 去重；任务重试不重复计数，缺失 task_id 的事件不进入任务数量。"},
	}
}

// overallStatus 计算总体完整性状态：任一数据点未知/部分或来源截断都为 partial；
// 权限裁剪与明细截断也标记 partial（数字仍真实但范围不全）。
func overallStatus(activity stats.ActivityResult, errorsResult stats.ErrorResult,
	trend stats.ErrorTrendResult, completeness CompletenessInfo) stats.DataStatus {
	if len(completeness.MissingIntervals) > 0 || completeness.SourceTruncated ||
		completeness.DetailRowsTruncated || completeness.ScopeTrimmed {
		return stats.DataPartial
	}
	statuses := make([]stats.DataStatus, 0, len(activity.Points)+len(trend.Points))
	for _, point := range activity.Points {
		statuses = append(statuses, point.DataStatus)
	}
	for _, point := range trend.Points {
		statuses = append(statuses, point.DataStatus)
	}
	for _, row := range errorsResult.Rows {
		statuses = append(statuses, row.DataStatus)
	}
	partial := false
	for _, status := range statuses {
		if status == stats.DataUnknown {
			return stats.DataPartial
		}
		if status != stats.DataComplete {
			partial = true
		}
	}
	if partial {
		return stats.DataPartial
	}
	return stats.DataComplete
}

// completenessNotes 生成面向读者的中文完整性说明；缺失如实说明，不补零。
func completenessNotes(info CompletenessInfo) []string {
	notes := make([]string, 0, 6)
	notes = append(notes, "本报告基于一次固定统计快照生成，图表与明细使用同一时间窗口与统计截止点。")
	if !info.WindowWithinRetention {
		if len(info.MissingIntervals) > 0 {
			for _, interval := range info.MissingIntervals {
				notes = append(notes, fmt.Sprintf("部分时间区间早于保留期（%s 至 %s），该区间数值未知，不能当作 0：%s。",
					interval.Start.Format(time.RFC3339), interval.End.Format(time.RFC3339), interval.Reason))
			}
		} else {
			notes = append(notes, fmt.Sprintf("请求窗口未完全落在可查询保留期内（保留 %d 天），缺失区间数值未知，不能当作 0。",
				info.RetentionDays))
		}
	}
	if info.SourceTruncated {
		notes = append(notes, "数据来源达到行数或分组上限，统计结果不完整；数量是已知部分而不是完整总量。")
	}
	if info.DetailRowsTruncated {
		notes = append(notes, "错误明细达到本次报告条数上限，仅包含排序后的部分行；趋势与汇总数字仍基于完整统计窗口。")
	}
	if info.ScopeTrimmed {
		notes = append(notes, "统计已按当前权限的数据范围裁剪，不代表全系统总量；未获准的应用数据不在本报告中。")
	}
	if len(info.ModulesNotEnabled) > 0 {
		notes = append(notes, "以下模块或指标当前未启用，报告不包含其数据："+
			strings.Join(info.ModulesNotEnabled, "、")+"。")
	}
	notes = append(notes, "报告不包含原始审计全量记录、凭证、令牌、密码或未脱敏堆栈；明细字段按白名单裁剪。")
	return notes
}

// formatSortedFormats 返回稳定顺序（html、csv、json、pdf、markdown）并去重；空
// 表示未请求格式。
func formatSortedFormats(formats []Format) []Format {
	seen := make(map[Format]bool, len(formats))
	for _, format := range formats {
		seen[format] = true
	}
	ordered := make([]Format, 0, 5)
	for _, candidate := range []Format{FormatHTML, FormatCSV, FormatJSON,
		FormatPDF, FormatMarkdown} {
		if seen[candidate] {
			ordered = append(ordered, candidate)
		}
	}
	return ordered
}
