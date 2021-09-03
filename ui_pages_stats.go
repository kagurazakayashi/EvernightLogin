package login

// 步骤 76：统计看板、活跃度与错误趋势、错误分类排序页面（ui.v1）。
//
// 安全不变量：
//   - 全部路由 UIAccessManagement：宿主 UISessionService 必须用真实
//     session.AuthorizeManagement 判定完整会话与强认证新鲜度；页面不信任前端自报
//     root/角色/权限，能力位只影响呈现。
//   - 每次读取都由适配器重建可信 Caller 交给真实 stats 服务重新授权（权限键
//     reports.read）；作用范围（system 或应用）与数据范围由服务端判定，页面参数
//     不是授权凭证。
//   - 统计值、分桶、占比、增幅、去重与完整性全部由服务端计算并返回；浏览器只接收
//     受控聚合桶与当前分页，不下载全量审计，不在前端补算全局数字。
//   - 缺失、未知、未采样、保留期不足与未启用模块显示 `—` 和原因，绝不填充 0；
//     只有服务端确认的真实零值显示 0；零基数增长显示“新增”。
//   - 当前系统状态卡是观测时刻快照，不随历史筛选改写；历史趋势只呈现所选区间实际
//     采集的聚合桶。
//   - 图表使用服务端内联 SVG 与同源原生数据表，不加载在线图表服务、CDN、远程字体
//     或第三方脚本；点击统计项下钻到步骤 74 审计页，由审计服务再次授权，无明细
//     权限时不渲染伪链接并显示明确限制。

import (
	"context"
	"fmt"
	"html"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// UIStatsScopeSystem 是统计固定开放的系统作用范围稳定 ID。
const UIStatsScopeSystem = "system"

// 统计时间范围稳定标识（由服务端规范化；页面只回显规范化结果）。
const (
	UIStatsRange7Days  = "7d"
	UIStatsRange30Days = "30d"
	UIStatsRangeCustom = "custom"
)

// 统计硬边界：与 internal/stats 的公开上限保持一致，页面层提前给出字段错误。
const (
	UIStatsMaxWindowDays  = 3 * 366
	UIStatsMaxBuckets     = 400
	UIStatsDefaultLimit   = 20
	UIStatsMaxLimit       = 100
	UIStatsMaxOffset      = 100_000
	UIStatsDefaultRange   = UIStatsRange7Days
	UIStatsDefaultGranule = "day"
)

// UIStatsTimeZones 是页面提供的受支持时区白名单（IANA 名称）。只接受白名单内
// 名称，避免把任意字符串当作时区渲染或查询；未知/非白名单名称按字段错误处理。
func UIStatsTimeZones() []string {
	return []string{"UTC", "Asia/Shanghai", "Asia/Tokyo", "Asia/Singapore",
		"Europe/London", "Europe/Berlin", "America/New_York", "America/Los_Angeles"}
}

// UIStatsCategoryValues 返回错误类别稳定值顺序。
func UIStatsCategoryValues() []string {
	return []string{"pending", "denied", "cancelled", "warning", "failure", "unknown"}
}

// UIStatsMetricValues 返回错误趋势主指标稳定值。
func UIStatsMetricValues() []string {
	return []string{"raw_events", "dedup_failed_requests", "dedup_failed_tasks"}
}

// UIStatsSortValues 返回错误排序白名单。
func UIStatsSortValues() []string {
	return []string{"raw_events", "share", "first_seen", "last_seen", "growth"}
}

// UIStatsGranularityValues 返回桶粒度白名单。
func UIStatsGranularityValues() []string {
	return []string{"day", "week", "month"}
}

// UIPageStatsOptions 是步骤 76 统计看板页配置。
type UIPageStatsOptions struct {
	Backend UIPageStatsBackend
	// Now 是页面时间范围规范化使用的服务端时钟；nil 使用 time.Now。页面把规范化
	// 后的显式起止时间交给后端，保证同一页面的图表与明细使用同一时间区间。
	Now func() time.Time
}

// UIStatsCapabilities 是服务端为当前操作者判定的页面能力位（只是交互辅助）。
type UIStatsCapabilities struct {
	// Read 表示可在当前页面查看统计数据。
	Read bool
	// Events 表示可下钻查看审计事件明细（步骤 74 审计读取权限）。false 时页面
	// 保留聚合内容，但不渲染伪链接并显示明确限制。
	Events bool
	// Scopes 是服务端判定的获准作用范围（system 与获准应用稳定 ID）；页面只据此
	// 渲染应用筛选，不泄露未授权应用名称或 ID。
	Scopes []string
}

// UIStatsError 是统计适配层返回的稳定公开错误。
type UIStatsError struct {
	Code              string
	RetryAfterSeconds int
}

// Error 实现 error。
func (e *UIStatsError) Error() string { return "统计页面操作失败: " + e.Code }

// UIStatsWindow 是页面与服务端共用的规范化统计窗口（左闭右开 [Start, End)）。
type UIStatsWindow struct {
	TimeZone    string
	Start       time.Time
	End         time.Time
	Granularity string
	// Range 是范围稳定标识（7d/30d/custom）。
	Range string
	// FromValue/ToValue 是自定义范围的日期回显（YYYY-MM-DD，按所选时区）。
	FromValue string
	ToValue   string
	// InProgress 表示结束时间被钳制到当前观测时刻（末桶可能未完成）。
	InProgress bool
}

// DurationDays 返回窗口近似自然天数（仅用于展示，不用于分桶）。
func (w UIStatsWindow) DurationDays() int {
	days := int(math.Round(w.End.Sub(w.Start).Hours() / 24))
	if days < 1 {
		days = 1
	}
	return days
}

// UIStatsQuery 是统计读取请求：窗口由页面规范化后显式传入，保证同一页面的多个
// 读取使用完全相同的起止时间、时区与作用范围。
type UIStatsQuery struct {
	ScopeID  string
	Window   UIStatsWindow
	Category string
	Metric   string
	Sort     string
	Order    string
	Limit    int
	Offset   int
}

// UIStatsInterval 是缺失/不可知时间区间（原因码为稳定机器值）。
type UIStatsInterval struct {
	Start  time.Time
	End    time.Time
	Reason string
}

// UIStatsCompleteness 是统计完整性信息；页面必须展示，不能把未知当零。
type UIStatsCompleteness struct {
	WindowWithinRetention bool
	RetentionDays         int
	RetentionConfigured   bool
	RetentionCutoff       time.Time
	MissingIntervals      []UIStatsInterval
	SamplingGaps          []UIStatsInterval
	ScopeTrimmed          bool
	SourceTruncated       bool
	ModulesNotEnabled     []string
}

// UIStatsCategorySummary 是按类别的汇总（等待/拒绝/取消/警告/故障/未知分开）。
type UIStatsCategorySummary struct {
	Category       string
	Severity       string
	RawEvents      int64
	FailedRequests int64
	FailedTasks    int64
}

// CategoryKey 返回类别 i18n 键。
func (s UIStatsCategorySummary) CategoryKey() string { return statsCategoryKey(s.Category) }

// SeverityKey 返回严重度 i18n 键。
func (s UIStatsCategorySummary) SeverityKey() string { return statsSeverityKey(s.Severity) }

// ClassKey 返回图表线型 class（按类别稳定序号，不随筛选/序列顺序变化）。
func (s UIStatsCategorySummary) ClassKey() string {
	return "series-" + strconv.Itoa(categorySeriesNumber(s.Category))
}

// categorySeriesNumber 返回类别稳定图表序号（1～6）。
func categorySeriesNumber(category string) int {
	for index, candidate := range UIStatsCategoryValues() {
		if candidate == category {
			return index + 1
		}
	}
	return len(UIStatsCategoryValues())
}

// UIStatsPoint 是活跃度数据点。
type UIStatsPoint struct {
	BucketKey   string
	Start       time.Time
	End         time.Time
	InProgress  bool
	Partial     bool
	ActiveUsers int64
	DataStatus  string
	// DrilldownURL 是服务端生成的审计下钻链接；空表示当前权限/筛选无法精确表达
	// 对应事件，模板显示为不可点击文本并给出原因。
	DrilldownURL string
}

// StatusKey 返回数据状态 i18n 键。
func (p UIStatsPoint) StatusKey() string { return statsDataStatusKey(p.DataStatus) }

// ValueAvailable 报告该点是否有可显示的真实数值：未知/未启用必须显示 —（不是 0）。
func (p UIStatsPoint) ValueAvailable() bool {
	return p.DataStatus != "unknown" && p.DataStatus != "not_enabled"
}

// UIStatsActivity 是活跃度结果：Points 与数据表逐行一致，TotalActiveUsers 是窗口
// 内去重用户数（多应用合并后按稳定用户 ID 去重，不是各应用之和）。
type UIStatsActivity struct {
	Start            time.Time
	End              time.Time
	TimeZone         string
	Granularity      string
	Points           []UIStatsPoint
	TotalActiveUsers int64
	DedupeScope      string
	UpdatedAt        time.Time
	Completeness     UIStatsCompleteness
}

// UIStatsErrorPoint 是错误趋势的一个时间桶×类别数据点。
type UIStatsErrorPoint struct {
	BucketKey      string
	Start          time.Time
	End            time.Time
	InProgress     bool
	Category       string
	Severity       string
	RawEvents      int64
	FailedRequests int64
	FailedTasks    int64
	DataStatus     string
	// MetricValue 是当前趋势主指标数值（由页面按服务端返回的主指标选择，不换算）。
	MetricValue int64
	// DrilldownURL 为空表示无法精确表达对应事件（不渲染伪链接）。
	DrilldownURL string
}

// CategoryKey 返回类别 i18n 键。
func (p UIStatsErrorPoint) CategoryKey() string { return statsCategoryKey(p.Category) }

// SeverityKey 返回严重度 i18n 键。
func (p UIStatsErrorPoint) SeverityKey() string { return statsSeverityKey(p.Severity) }

// StatusKey 返回数据状态 i18n 键。
func (p UIStatsErrorPoint) StatusKey() string { return statsDataStatusKey(p.DataStatus) }

// ValueAvailable 报告该点是否有可显示的真实数值：未知/未启用必须显示 —（不是 0）。
func (p UIStatsErrorPoint) ValueAvailable() bool {
	return p.DataStatus != "unknown" && p.DataStatus != "not_enabled"
}

// UIStatsErrorTrend 是错误趋势结果：图表与数据表使用同一桶集合。
type UIStatsErrorTrend struct {
	Start          time.Time
	End            time.Time
	TimeZone       string
	Granularity    string
	Metric         string
	Points         []UIStatsErrorPoint
	Categories     []UIStatsCategorySummary
	TotalRawEvents int64
	FailedRequests int64
	FailedTasks    int64
	UpdatedAt      time.Time
	Completeness   UIStatsCompleteness
}

// UIStatsErrorRow 是一行错误聚合（服务端已按白名单字段稳定排序与分页）。
type UIStatsErrorRow struct {
	ErrorCode      string
	Category       string
	Severity       string
	AppID          string
	RawEvents      int64
	FailedRequests int64
	FailedTasks    int64
	Share          float64
	FirstSeen      time.Time
	LastSeen       time.Time
	GrowthKind     string
	GrowthPercent  float64
	DataStatus     string
	// DrilldownURL 为空表示当前筛选无法精确表达对应事件（渲染为不可点击文本）。
	DrilldownURL string
}

// CategoryKey 返回类别 i18n 键。
func (r UIStatsErrorRow) CategoryKey() string { return statsCategoryKey(r.Category) }

// SeverityKey 返回严重度 i18n 键。
func (r UIStatsErrorRow) SeverityKey() string { return statsSeverityKey(r.Severity) }

// StatusKey 返回数据状态 i18n 键。
func (r UIStatsErrorRow) StatusKey() string { return statsDataStatusKey(r.DataStatus) }

// ShareText 返回服务端返回占比的百分比文本（不以前端重算）。
func (r UIStatsErrorRow) ShareText() string { return statsShareText(r.Share) }

// GrowthKey 返回“新增/无变化/不可用”i18n 键；可计算百分比时为空。
func (r UIStatsErrorRow) GrowthKey() string { return statsGrowthKey(r.GrowthKind) }

// GrowthText 返回百分比增幅文本；不可计算时为空。
func (r UIStatsErrorRow) GrowthText() string {
	if r.GrowthKind != "percent" {
		return ""
	}
	return statsGrowthText(r.GrowthPercent)
}

// UIStatsErrors 是错误分类明细结果。
type UIStatsErrors struct {
	Start             time.Time
	End               time.Time
	TimeZone          string
	Granularity       string
	Rows              []UIStatsErrorRow
	TotalRawEvents    int64
	FailedRequests    int64
	FailedTasks       int64
	ShareDenominator  int64
	Categories        []UIStatsCategorySummary
	Sort              string
	Order             string
	Limit             int
	Offset            int
	HasMore           bool
	ComparisonStart   time.Time
	ComparisonEnd     time.Time
	ComparisonEnabled bool
	UpdatedAt         time.Time
	Completeness      UIStatsCompleteness
}

// UIStatsHealthSample 是一个模块的当前观测状态（已脱敏、有界）。
type UIStatsHealthSample struct {
	Module         string
	State          string
	Severity       string
	Enabled        bool
	ObservedAt     time.Time
	Source         string
	Reason         string
	LatencyMS      string
	NotAfter       string
	RemainingHours string
}

// UIStatsHealth 是当前系统状态快照；它是观测时刻的事实，不是历史趋势。
type UIStatsHealth struct {
	Modules    []UIStatsHealthSample
	ObservedAt time.Time
	NotEnabled []string
}

// ModuleKey 返回模块 i18n 键。
func (s UIStatsHealthSample) ModuleKey() string { return statsModuleKey(s.Module) }

// StateKey 返回模块状态 i18n 键。
func (s UIStatsHealthSample) StateKey() string { return statsModuleStateKey(s.State) }

// UIStatsOverview 是看板摘要（活跃用户、原始事件、去重失败请求/任务、类别分布）。
type UIStatsOverview struct {
	ScopeID        string
	ScopeKind      string
	Start          time.Time
	End            time.Time
	TimeZone       string
	Granularity    string
	ActiveUsers    int64
	RawEvents      int64
	FailedRequests int64
	FailedTasks    int64
	Categories     []UIStatsCategorySummary
	ActivityStatus string
	DataCutoff     time.Time
	UpdatedAt      time.Time
	Completeness   UIStatsCompleteness
}

// UIStatsDashboard 是看板总览结果。Health 为 nil 表示当前作用范围不适用系统健康
// （例如应用范围）或读取失败；HealthUnavailable 区分“失败”与“不适用”。
type UIStatsDashboard struct {
	Overview          UIStatsOverview
	Health            *UIStatsHealth
	HealthUnavailable bool
	// HealthHistoryAvailable 表示健康采样历史查询成功；false 时页面不宣称“没有采样
	// 空档”，而是明确说明当前无法判断。
	HealthHistoryAvailable bool
	UpdatedAt              time.Time
}

// UIStatsStatistics 是活跃度与错误趋势页结果。
type UIStatsStatistics struct {
	Activity   UIStatsActivity
	ErrorTrend UIStatsErrorTrend
	UpdatedAt  time.Time
}

// UIPageStatsBackend 是统计页面调用真实服务的最小契约；适配器负责可信 Caller 与
// 每次授权，页面层不实现权限判定、不补算统计值。
type UIPageStatsBackend interface {
	Capabilities(ctx context.Context, userID string) (UIStatsCapabilities, error)
	Dashboard(ctx context.Context, userID string, query UIStatsQuery) (UIStatsDashboard, error)
	Statistics(ctx context.Context, userID string, query UIStatsQuery) (UIStatsStatistics, error)
	Errors(ctx context.Context, userID string, query UIStatsQuery) (UIStatsErrors, error)
	// RecordDenial 记录页面级拒绝（能力位不足/非法参数等）为失败审计；审计写失败
	// 不得改变拒绝结果。
	RecordDenial(ctx context.Context, userID, reason string) error
}

// newPageStatsPages 构造步骤 76 路由与处理器。
func newPageStatsPages(options UIPageStatsOptions) (*pageStatsPages, error) {
	if isNilUIValue(options.Backend) {
		return nil, fmt.Errorf("统计页面缺少后端适配器")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	pages := &pageStatsPages{handlers: map[string]UIPageHandler{}, options: options}
	handler := &statsPageHandlers{pages: pages}
	routes := []UIRoute{
		{Name: "admin.dashboard", Method: http.MethodGet, Path: "/admin/dashboard",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/dashboard"},
		{Name: "admin.statistics", Method: http.MethodGet, Path: "/admin/statistics",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/statistics"},
		{Name: "admin.statistics_errors", Method: http.MethodGet,
			Path:   "/admin/statistics/errors",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/statistics_errors"},
	}
	for _, route := range routes {
		pages.routes = append(pages.routes, route)
		pages.handlers[route.Name] = handler
	}
	return pages, nil
}

// pageStatsPages 是统计页面实现。
type pageStatsPages struct {
	routes   []UIRoute
	handlers map[string]UIPageHandler
	options  UIPageStatsOptions
}

// statsCategoryKey 把错误类别稳定值映射为 i18n 键。
func statsCategoryKey(category string) string {
	switch category {
	case "pending":
		return "page.admin.statistics.category.pending"
	case "denied":
		return "page.admin.statistics.category.denied"
	case "cancelled":
		return "page.admin.statistics.category.cancelled"
	case "warning":
		return "page.admin.statistics.category.warning"
	case "failure":
		return "page.admin.statistics.category.failure"
	case "unknown":
		return "page.admin.statistics.category.unknown"
	default:
		return "page.admin.statistics.category.unknown"
	}
}

// statsSeverityKey 把严重度稳定值映射为 i18n 键。
func statsSeverityKey(severity string) string {
	switch severity {
	case "info":
		return "page.admin.statistics.severity.info"
	case "warning":
		return "page.admin.statistics.severity.warning"
	case "error":
		return "page.admin.statistics.severity.error"
	case "critical":
		return "page.admin.statistics.severity.critical"
	default:
		return "page.admin.statistics.severity.unknown"
	}
}

// statsDataStatusKey 把数据状态稳定值映射为 i18n 键。
func statsDataStatusKey(status string) string {
	switch status {
	case "complete":
		return "page.admin.statistics.status.complete"
	case "partial":
		return "page.admin.statistics.status.partial"
	case "in_progress":
		return "page.admin.statistics.status.in_progress"
	case "unknown":
		return "page.admin.statistics.status.unknown"
	case "not_enabled":
		return "page.admin.statistics.status.not_enabled"
	default:
		return "page.admin.statistics.status.unknown"
	}
}

// statsModuleKey 把健康模块稳定标识映射为 i18n 键。
func statsModuleKey(module string) string {
	switch module {
	case "service":
		return "page.admin.statistics.module.service"
	case "requests_errors":
		return "page.admin.statistics.module.requests_errors"
	case "tasks_notifications":
		return "page.admin.statistics.module.tasks_notifications"
	case "database":
		return "page.admin.statistics.module.database"
	case "certificate":
		return "page.admin.statistics.module.certificate"
	case "backup":
		return "page.admin.statistics.module.backup"
	default:
		return "page.admin.statistics.module.unknown"
	}
}

// statsModuleStateKey 把模块状态映射为 i18n 键。
func statsModuleStateKey(state string) string {
	switch state {
	case "healthy":
		return "page.admin.statistics.state.healthy"
	case "degraded":
		return "page.admin.statistics.state.degraded"
	case "unavailable":
		return "page.admin.statistics.state.unavailable"
	case "not_enabled":
		return "page.admin.statistics.state.not_enabled"
	default:
		return "page.admin.statistics.state.unknown"
	}
}

// statsRangeKey 把范围稳定值映射为 i18n 键。
func statsRangeKey(rangeKey string) string {
	switch rangeKey {
	case UIStatsRange30Days:
		return "page.admin.statistics.range.days30"
	case UIStatsRangeCustom:
		return "page.admin.statistics.range.custom"
	default:
		return "page.admin.statistics.range.days7"
	}
}

// statsGranularityKey 把桶粒度映射为 i18n 键。
func statsGranularityKey(granularity string) string {
	switch granularity {
	case "week":
		return "page.admin.statistics.granularity.week"
	case "month":
		return "page.admin.statistics.granularity.month"
	default:
		return "page.admin.statistics.granularity.day"
	}
}

// statsMetricKey 把错误趋势主指标映射为 i18n 键。
func statsMetricKey(metric string) string {
	switch metric {
	case "dedup_failed_requests":
		return "page.admin.statistics.metric.dedup_failed_requests"
	case "dedup_failed_tasks":
		return "page.admin.statistics.metric.dedup_failed_tasks"
	default:
		return "page.admin.statistics.metric.raw_events"
	}
}

// statsSortKey 把排序字段映射为 i18n 键。
func statsSortKey(sortField string) string {
	switch sortField {
	case "share":
		return "page.admin.statistics_errors.sort.share"
	case "first_seen":
		return "page.admin.statistics_errors.sort.first_seen"
	case "last_seen":
		return "page.admin.statistics_errors.sort.last_seen"
	case "growth":
		return "page.admin.statistics_errors.sort.growth"
	default:
		return "page.admin.statistics_errors.sort.raw_events"
	}
}

// statsGrowthKey 把增幅结果映射为 i18n 键（新增/无变化/不可用）。
func statsGrowthKey(kind string) string {
	switch kind {
	case "new":
		return "page.admin.statistics_errors.growth.new"
	case "none":
		return "page.admin.statistics_errors.growth.none"
	case "unavailable":
		return "page.admin.statistics_errors.growth.unavailable"
	default:
		return ""
	}
}

// statsShareText 格式化占比（服务端返回的 [0,1] 比例；不以前端重算）。
func statsShareText(share float64) string {
	return strconv.FormatFloat(math.Round(share*10000)/100, 'f', 2, 64) + "%"
}

// statsGrowthText 格式化增幅：只有百分比时才由服务端数值生成文本，其余返回空。
func statsGrowthText(percent float64) string {
	text := strconv.FormatFloat(percent, 'f', 2, 64)
	if percent > 0 {
		return "+" + text + "%"
	}
	return text + "%"
}

// statsTimeZoneOptions 返回可选时区列表；页面当前时区不在白名单时补在首位（服务端
// 已规范化，无法加载的时区不会进入窗口）。
func statsTimeZoneOptions(current string) []string {
	options := UIStatsTimeZones()
	for _, option := range options {
		if option == current {
			return options
		}
	}
	return append([]string{current}, options...)
}

// parseStatsTimeZone 校验时区白名单并返回 Location；空值使用页面时区/UTC。
func parseStatsTimeZone(raw, fallback string) (string, *time.Location, bool) {
	name := strings.TrimSpace(raw)
	if name == "" {
		name = fallback
	}
	if name == "" {
		name = "UTC"
	}
	found := false
	for _, option := range UIStatsTimeZones() {
		if option == name {
			found = true
			break
		}
	}
	if !found {
		return "", nil, false
	}
	location, err := time.LoadLocation(name)
	if err != nil {
		return "", nil, false
	}
	return name, location, true
}

// startOfDay 返回 moment 在 location 的自然日零点。
func statsStartOfDay(moment time.Time, location *time.Location) time.Time {
	local := moment.In(location)
	year, month, day := local.Date()
	return time.Date(year, month, day, 0, 0, 0, 0, location)
}

// parseUIStatsWindow 解析并规范化页面时间范围。规则固定且与服务端一致：
//   - 7d/30d：包含当前自然日，起点为前置自然日零点、终点为服务端当前观测时刻；
//   - custom：自定义起止日期（含结束日，左闭右开），结束日不得超过当前观测日；
//   - 时区只接受白名单 IANA 名称；跨度与桶数超过服务端上限时给字段错误，不自动改
//     范围；
//   - 所有时间边界都以所选时区的自然日计算，避免跨午夜/跨时区偏移。
func parseUIStatsWindow(values url.Values, page UIPageContext,
	now time.Time) (UIStatsWindow, map[string]string) {
	fieldErrors := map[string]string{}
	timeZone, location, ok := parseStatsTimeZone(values.Get("tz"), page.TimeZone)
	if !ok {
		fieldErrors["tz"] = text("page.admin.statistics.filter.invalid_timezone")
		timeZone, location = "UTC", time.UTC
	}
	granularity := strings.TrimSpace(values.Get("granularity"))
	if granularity == "" {
		granularity = UIStatsDefaultGranule
	}
	validGranularity := false
	for _, candidate := range UIStatsGranularityValues() {
		if candidate == granularity {
			validGranularity = true
			break
		}
	}
	if !validGranularity {
		fieldErrors["granularity"] = text("page.admin.statistics.filter.invalid_value")
		granularity = UIStatsDefaultGranule
	}
	now = now.UTC().Truncate(time.Second)
	rangeKey := strings.TrimSpace(values.Get("range"))
	if rangeKey == "" {
		rangeKey = UIStatsDefaultRange
	}
	window := UIStatsWindow{TimeZone: timeZone, Granularity: granularity, Range: rangeKey}
	switch rangeKey {
	case UIStatsRange7Days, UIStatsRange30Days:
		days := 7
		if rangeKey == UIStatsRange30Days {
			days = 30
		}
		today := statsStartOfDay(now, location)
		window.Start = today.AddDate(0, 0, -(days - 1))
		window.End = now
		window.InProgress = true
	case UIStatsRangeCustom:
		from, fromOK := parseUIStatsDate(values.Get("from"), location)
		to, toOK := parseUIStatsDate(values.Get("to"), location)
		if !fromOK {
			fieldErrors["from"] = text("page.admin.statistics.filter.invalid_time")
		}
		if !toOK {
			fieldErrors["to"] = text("page.admin.statistics.filter.invalid_time")
		}
		if fromOK && toOK {
			start := from.In(location)
			end := to.AddDate(0, 0, 1).In(location)
			if !end.After(start) {
				fieldErrors["to"] = text("page.admin.statistics.filter.invalid_range")
			}
			if end.After(now) {
				end = now
				window.InProgress = true
			}
			if end.Sub(start) > time.Duration(UIStatsMaxWindowDays)*24*time.Hour {
				fieldErrors["to"] = text("page.admin.statistics.filter.range_too_large")
			}
			window.Start, window.End = start.UTC(), end.UTC()
			window.FromValue, window.ToValue = values.Get("from"), values.Get("to")
		}
	default:
		fieldErrors["range"] = text("page.admin.statistics.filter.invalid_value")
		rangeKey = UIStatsDefaultRange
		window.Range = rangeKey
		today := statsStartOfDay(now, location)
		window.Start = today.AddDate(0, 0, -6)
		window.End = now
		window.InProgress = true
	}
	if len(fieldErrors) == 0 && !window.Start.Before(window.End) {
		fieldErrors["to"] = text("page.admin.statistics.filter.invalid_range")
	}
	if len(fieldErrors) == 0 &&
		statsEstimatedBuckets(window.End.Sub(window.Start), window.Granularity) > UIStatsMaxBuckets {
		// 提前按服务端同一上限给出字段错误，避免把必然 400 的查询发到后端。
		fieldErrors["range"] = text("page.admin.statistics.filter.range_too_large")
	}
	return window, fieldErrors
}

// statsEstimatedBuckets 估算窗口在指定粒度下的桶数上界（用于页面提前拒绝超限请求，
// 实际桶边界仍由服务端规范化；估算值只会偏大，不会放过真实超限请求）。
func statsEstimatedBuckets(duration time.Duration, granularity string) int {
	days := int(math.Ceil(duration.Hours() / 24))
	if days < 1 {
		days = 1
	}
	switch granularity {
	case "week":
		return days/7 + 2
	case "month":
		return days/28 + 2
	default:
		return days + 1
	}
}

// parseUIStatsDate 解析 YYYY-MM-DD 为所选时区的当日零点。
func parseUIStatsDate(value string, location *time.Location) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	parsed, err := time.ParseInLocation("2006-01-02", value, location)
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}

// normalizeStatsCategory 校验错误类别筛选；空表示全部。
func normalizeStatsCategory(raw string) (string, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", true
	}
	for _, candidate := range UIStatsCategoryValues() {
		if candidate == value {
			return value, true
		}
	}
	return "", false
}

// normalizeStatsMetric 校验错误趋势主指标；空使用 raw_events。
func normalizeStatsMetric(raw string) (string, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "raw_events", true
	}
	for _, candidate := range UIStatsMetricValues() {
		if candidate == value {
			return value, true
		}
	}
	return "", false
}

// normalizeStatsSort 校验错误排序白名单；空使用 raw_events。
func normalizeStatsSort(raw string) (string, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "raw_events", true
	}
	for _, candidate := range UIStatsSortValues() {
		if candidate == value {
			return value, true
		}
	}
	return "", false
}

// normalizeStatsOrder 校验排序方向；空使用 desc。
func normalizeStatsOrder(raw string) string {
	if strings.TrimSpace(raw) == "asc" {
		return "asc"
	}
	return "desc"
}

// parseStatsPagination 解析分页边界（默认 20，上限 100）。
func parseStatsPagination(values url.Values) (int, int, bool) {
	limit, offset := UIStatsDefaultLimit, 0
	if raw := strings.TrimSpace(values.Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > UIStatsMaxLimit {
			return 0, 0, false
		}
		limit = parsed
	}
	if raw := strings.TrimSpace(values.Get("offset")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 || parsed > UIStatsMaxOffset {
			return 0, 0, false
		}
		offset = parsed
	}
	return limit, offset, true
}

// normalizeStatsScope 校验作用范围稳定值（system 或服务端已判定的获准应用）。
func normalizeStatsScope(raw string, capabilities UIStatsCapabilities,
	defaultScope string) (string, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		value = defaultScope
	}
	if value == "" {
		value = UIStatsScopeSystem
	}
	for _, scope := range capabilities.Scopes {
		if scope == value {
			return value, true
		}
	}
	return "", false
}

// statsScopeLabelKey 返回作用范围显示键：系统范围使用固定文案，应用范围显示稳定
// 应用 ID（不显示未授权应用名称）。
func statsScopeLabelKey(scopeID string) string {
	if scopeID == UIStatsScopeSystem {
		return "page.admin.statistics.scope.system"
	}
	return "page.admin.statistics.scope.app"
}

// statsScopeList 返回获准作用范围（system 在前，应用按稳定 ID 排序）。
func statsScopeList(capabilities UIStatsCapabilities) []string {
	system := false
	apps := make([]string, 0, len(capabilities.Scopes))
	for _, scope := range capabilities.Scopes {
		if scope == UIStatsScopeSystem {
			system = true
			continue
		}
		apps = append(apps, scope)
	}
	sortStrings(apps)
	result := make([]string, 0, len(apps)+1)
	if system {
		result = append(result, UIStatsScopeSystem)
	}
	return append(result, apps...)
}

// sortStrings 是简单插入排序，避免为小集合引入额外依赖。
func sortStrings(values []string) {
	for index := 1; index < len(values); index++ {
		for position := index; position > 0 && values[position] < values[position-1]; position-- {
			values[position], values[position-1] = values[position-1], values[position]
		}
	}
}

// statsRoutePath 返回统计页面命名路由对应的固定后缀。
func statsRoutePath(routeName string) string {
	switch routeName {
	case "admin.statistics":
		return "/admin/statistics"
	case "admin.statistics_errors":
		return "/admin/statistics/errors"
	default:
		return "/admin/dashboard"
	}
}

// statsPageURL 生成站内统计页链接（保留当前非敏感筛选；未知键被丢弃）。
func statsPageURL(basePath, path string, window UIStatsWindow, scopeID string,
	extra url.Values) string {
	values := url.Values{}
	values.Set("scope", scopeID)
	values.Set("tz", window.TimeZone)
	values.Set("granularity", window.Granularity)
	if window.Range == UIStatsRangeCustom {
		values.Set("range", UIStatsRangeCustom)
		values.Set("from", window.FromValue)
		values.Set("to", window.ToValue)
	} else {
		values.Set("range", window.Range)
	}
	for key, items := range extra {
		for _, item := range items {
			values.Add(key, item)
		}
	}
	return basePath + path + "?" + values.Encode()
}

// statsDateValue 返回 moment 在 location 的日期文本。
func statsDateValue(moment time.Time, location *time.Location) string {
	return moment.In(location).Format("2006-01-02")
}

// statsWindowLocation 返回窗口时区（无法加载时回退 UTC）。
func statsWindowLocation(window UIStatsWindow) *time.Location {
	if window.TimeZone != "" {
		if location, err := time.LoadLocation(window.TimeZone); err == nil {
			return location
		}
	}
	return time.UTC
}

// statsAuditDrilldownURL 生成步骤 74 审计列表下钻链接：同一时间区间（按所选时区的
// 自然日）、作用范围/应用、结果与可选错误码筛选。审计页每次读取都会重新授权；
// 函数只生成白名单相对路径，不接受任意目标。tz 参数由审计页白名单校验后用于解释
// 日期，避免统计时区与账户时区不同时明细区间整体偏移。
func statsAuditDrilldownURL(basePath string, timeZone string, start, end time.Time,
	scopeID, appID string, systemOnly bool, outcome, errorCode string) string {
	location := time.UTC
	if timeZone != "" {
		if loaded, err := time.LoadLocation(timeZone); err == nil {
			location = loaded
		}
	}
	// 审计页的日期筛选按“含结束日”解释；统计窗口右开，因此结束日取 End 前一刻的
	// 当地日期。in-progress 窗口的结束日为当前日，审计页会把上界钳制到 now+1 分钟，
	// 明细可能包含统计截止后新增事件（页面显示快照说明）。
	lastMoment := end.Add(-time.Nanosecond)
	values := url.Values{}
	values.Set("from", statsDateValue(start, location))
	values.Set("to", statsDateValue(lastMoment, location))
	if timeZone != "" {
		values.Set("tz", timeZone)
	}
	if appID != "" {
		values.Set("app_id", appID)
	} else if systemOnly && scopeID == UIStatsScopeSystem {
		values.Set("system_only", "1")
	}
	if outcome != "" {
		values.Set("outcome", outcome)
	}
	if errorCode != "" {
		values.Set("error_code", errorCode)
	}
	return basePath + "/admin/audit?" + values.Encode()
}

// statsCategoryOutcome 把错误类别映射为审计结果筛选；无法精确表达时返回空（页面
// 不生成伪链接）。仅在错误码存在且类别可判定时使用。
func statsCategoryOutcome(category string) string {
	switch category {
	case "denied":
		return "denied"
	case "failure", "unknown":
		return "failure"
	default:
		return ""
	}
}

// statsBucketDrilldownURL 生成错误趋势桶/排序行的审计下钻链接；使用该点自己的
// 起止时间而非整窗，无法精确表达错误类别时返回空字符串（模板显示不可点击文本）。
func statsBucketDrilldownURL(basePath string, timeZone string, pointStart,
	pointEnd time.Time, scopeID, appID, category, errorCode string) string {
	outcome := statsCategoryOutcome(category)
	if errorCode != "" {
		return statsAuditDrilldownURL(basePath, timeZone, pointStart, pointEnd,
			scopeID, appID, false, outcome, errorCode)
	}
	if outcome == "" {
		return ""
	}
	return statsAuditDrilldownURL(basePath, timeZone, pointStart, pointEnd,
		scopeID, appID, false, outcome, "")
}

// statsErrorRowDrilldownURL 生成错误排序行的审计下钻链接：使用行真实应用与窗口，
// 无法精确表达时返回空。系统级行（无应用快照）带 system_only 精确到系统事件。
func statsErrorRowDrilldownURL(basePath string, window UIStatsWindow, scopeID string,
	row UIStatsErrorRow) string {
	if row.ErrorCode == "" {
		return ""
	}
	appID := row.AppID
	systemOnly := false
	if appID == "" {
		if scopeID != "" && scopeID != UIStatsScopeSystem {
			appID = scopeID
		} else {
			systemOnly = true
		}
	}
	outcome := statsCategoryOutcome(row.Category)
	if row.Category == "cancelled" {
		// 以失败结果结束的取消（TASK_CANCELLED）在审计中 outcome=failure；成功取消
		// 动作没有错误码，不会进入本分支。
		outcome = "failure"
	}
	return statsAuditDrilldownURL(basePath, window.TimeZone, window.Start, window.End,
		scopeID, appID, systemOnly, outcome, row.ErrorCode)
}

// activityDrilldownURL 生成活跃度桶的成功事件审计链接；携带同一统计作用范围
// （单应用时 app_id）与所选时区，服务端仍重新授权。成功事件列表是审计授权后的
// 记录视图，页面明确说明记录条数不等于去重活跃用户数。
func activityDrilldownURL(basePath string, window UIStatsWindow, scopeID string,
	bucketStart, bucketEnd time.Time) string {
	appID := ""
	if scopeID != "" && scopeID != UIStatsScopeSystem {
		appID = scopeID
	}
	return statsAuditDrilldownURL(basePath, window.TimeZone, bucketStart, bucketEnd,
		scopeID, appID, false, "success", "")
}

// statsCompletenessView 把服务端完整性结构适配为页面 DTO 已由适配器完成；这里只
// 提供展示所需的“是否有提示”判断。
func statsHasCompletenessNotes(completeness UIStatsCompleteness) bool {
	return !completeness.WindowWithinRetention || len(completeness.MissingIntervals) > 0 ||
		len(completeness.SamplingGaps) > 0 || completeness.ScopeTrimmed ||
		completeness.SourceTruncated || len(completeness.ModulesNotEnabled) > 0
}

// statsChartWidth/Height 是内联 SVG 图表的固定视口；模板用 CSS 适应容器宽度。
const (
	statsChartWidth  = 960
	statsChartHeight = 280
)

// statsChartSeries 是一条图表序列（直接文字标签 + 线型 class + 已计算坐标点）。
type statsChartSeries struct {
	Label  string
	Class  string
	Points []statsChartPoint
}

// statsChartPoint 是已计算坐标的图表点；HasValue=false 表示缺失（断线不补零）。
type statsChartPoint struct {
	X          float64
	Y          float64
	HasValue   bool
	InProgress bool
	Partial    bool
	Title      string
}

// statsActivityChart 生成活跃度折线图的内联 SVG。只有服务端确认的数据点才连线；
// unknown 断线并标“采样缺失”，不插值、不补零。
func statsActivityChart(activity UIStatsActivity, caption, summary string) string {
	series := statsChartSeries{Label: caption, Class: "series-1"}
	xLabels := make([]string, len(activity.Points))
	for index, point := range activity.Points {
		xLabels[index] = point.BucketKey
	}
	series.Points = make([]statsChartPoint, len(activity.Points))
	for index, point := range activity.Points {
		series.Points[index] = statsChartPoint{
			Y:          float64(point.ActiveUsers),
			HasValue:   point.DataStatus != "unknown" && point.DataStatus != "not_enabled",
			InProgress: point.InProgress || point.DataStatus == "in_progress",
			Partial:    point.DataStatus == "partial",
			Title:      point.BucketKey,
		}
	}
	return renderStatsSVG(caption, summary, []statsChartSeries{series},
		statsPointValues(activity.Points), xLabels,
		text("page.admin.statistics.chart.active_y"), "ln-activity-chart")
}

// statsPointValues 返回活跃度数值。
func statsPointValues(points []UIStatsPoint) []float64 {
	values := make([]float64, len(points))
	for index, point := range points {
		values[index] = float64(point.ActiveUsers)
	}
	return values
}

// statsErrorTrendChart 生成错误趋势多序列折线图。每条序列使用不同线型 class 且提供
// 直接文字标签；超过 6 条序列时只展示前 6 条并在摘要说明需用表格/筛选查看全部。
func statsErrorTrendChart(trend UIStatsErrorTrend, summary string) string {
	bucketKeys := make([]string, 0, 32)
	seenBuckets := map[string]bool{}
	for _, point := range trend.Points {
		if !seenBuckets[point.BucketKey] {
			seenBuckets[point.BucketKey] = true
			bucketKeys = append(bucketKeys, point.BucketKey)
		}
	}
	categories := make([]string, 0, len(trend.Categories))
	for _, category := range trend.Categories {
		categories = append(categories, category.Category)
	}
	if len(categories) > 6 {
		categories = categories[:6]
	}
	values := make(map[string]map[string]float64, len(categories))
	statuses := make(map[string]map[string]string, len(categories))
	for _, category := range categories {
		values[category] = map[string]float64{}
		statuses[category] = map[string]string{}
	}
	for _, point := range trend.Points {
		if _, ok := values[point.Category]; !ok {
			continue
		}
		values[point.Category][point.BucketKey] = statsTrendMetricValue(trend.Metric, point)
		statuses[point.Category][point.BucketKey] = point.DataStatus
	}
	series := make([]statsChartSeries, 0, len(categories))
	maxValue := 0.0
	for _, category := range categories {
		item := statsChartSeries{Label: text(statsCategoryKey(category)),
			Class: "series-" + strconv.Itoa(categorySeriesNumber(category))}
		item.Points = make([]statsChartPoint, len(bucketKeys))
		for index, key := range bucketKeys {
			status := statuses[category][key]
			value := values[category][key]
			item.Points[index] = statsChartPoint{
				Y:          value,
				HasValue:   status != "unknown" && status != "not_enabled",
				InProgress: status == "in_progress",
				Partial:    status == "partial",
				Title:      key,
			}
			if value > maxValue {
				maxValue = value
			}
		}
		series = append(series, item)
	}
	flat := make([]float64, 0, len(series)*len(bucketKeys))
	for index := range bucketKeys {
		for _, item := range series {
			flat = append(flat, seriesValueAt(item, index))
		}
	}
	return renderStatsSVG(text("page.admin.statistics.error_trend_title"), summary, series,
		flat, bucketKeys, text(statsMetricKey(trend.Metric)), "ln-error-chart")
}

// seriesValueAt 返回序列第 index 个点的值（无值按 0 参与坐标但 HasValue=false）。
func seriesValueAt(series statsChartSeries, index int) float64 {
	if index >= len(series.Points) {
		return 0
	}
	return series.Points[index].Y
}

// statsTrendMetricValue 取趋势点的主指标值（绝不换算其他指标）。
func statsTrendMetricValue(metric string, point UIStatsErrorPoint) float64 {
	switch metric {
	case "dedup_failed_requests":
		return float64(point.FailedRequests)
	case "dedup_failed_tasks":
		return float64(point.FailedTasks)
	default:
		return float64(point.RawEvents)
	}
}

// renderStatsSVG 用可信数值生成内联 SVG 折线图。类别标签、标题与摘要全部 HTML
// 转义；缺失点不连线、不补零；每条序列有直接文字标签，不只依赖颜色。它不是通用
// raw_html 通道，只接受本文件构造的数值与已翻译文本。
func renderStatsSVG(title, summary string, series []statsChartSeries,
	values []float64, xLabels []string, yLabel string, idPrefix string) string {
	if len(xLabels) == 0 {
		return ""
	}
	const (
		left   = 64.0
		right  = 24.0
		top    = 28.0
		bottom = 44.0
	)
	plotWidth := float64(statsChartWidth) - left - right
	plotHeight := float64(statsChartHeight) - top - bottom
	maxValue := 0.0
	for _, value := range values {
		if value > maxValue {
			maxValue = value
		}
	}
	if maxValue <= 0 {
		maxValue = 1
	}
	// 只保留 4 条参考线，避免密集刻度干扰读屏与视觉。
	step := maxValue / 4
	if step <= 0 {
		step = 1
	}
	maxValue = math.Ceil(maxValue/step) * step
	xAt := func(index int) float64 {
		if len(xLabels) == 1 {
			return left + plotWidth/2
		}
		return left + plotWidth*float64(index)/float64(len(xLabels)-1)
	}
	yAt := func(value float64) float64 {
		if value < 0 {
			value = 0
		}
		return top + plotHeight - plotHeight*value/maxValue
	}
	if idPrefix == "" {
		idPrefix = "ln-chart"
	}
	titleID := html.EscapeString(idPrefix + "-title")
	descID := html.EscapeString(idPrefix + "-desc")
	var builder strings.Builder
	builder.WriteString(`<svg class="ln-chart" viewBox="0 0 960 280" role="img" aria-labelledby="` + titleID + `" aria-describedby="` + descID + `">`)
	builder.WriteString(`<title id="` + titleID + `">` + html.EscapeString(title) + `</title>`)
	builder.WriteString(`<desc id="` + descID + `">` + html.EscapeString(summary) + `</desc>`)
	// 参考线与纵轴刻度
	for stepIndex := 0; stepIndex <= 4; stepIndex++ {
		value := maxValue * float64(stepIndex) / 4
		y := yAt(value)
		builder.WriteString(fmt.Sprintf(`<line class="ln-chart__grid" x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f"/>`,
			left, y, left+plotWidth, y))
		builder.WriteString(fmt.Sprintf(`<text class="ln-chart__tick" x="%.1f" y="%.1f" text-anchor="end">%.0f</text>`,
			left-8, y+4, value))
	}
	builder.WriteString(fmt.Sprintf(`<text class="ln-chart__axis" x="%.1f" y="%.1f" text-anchor="middle">%s</text>`,
		left+plotWidth/2, float64(statsChartHeight)-6, html.EscapeString(yLabel)))
	// x 轴标签：按宽度自适应抽样，但保留首尾。
	stride := 1
	if len(xLabels) > 12 {
		stride = int(math.Ceil(float64(len(xLabels)) / 12))
	}
	for index, label := range xLabels {
		if index%stride != 0 && index != len(xLabels)-1 {
			continue
		}
		builder.WriteString(fmt.Sprintf(`<text class="ln-chart__tick" x="%.1f" y="%.1f" text-anchor="middle">%s</text>`,
			xAt(index), top+plotHeight+18, html.EscapeString(label)))
	}
	// 序列：缺失点断开连线，进行中/部分点用空心标记。
	for _, item := range series {
		builder.WriteString(`<g class="ln-chart__series ` + html.EscapeString(item.Class) + `">`)
		builder.WriteString(`<polyline class="ln-chart__line" points="`)
		started := false
		for index, point := range item.Points {
			if !point.HasValue {
				started = false
				continue
			}
			if started {
				builder.WriteString(" ")
			}
			builder.WriteString(fmt.Sprintf("%.1f,%.1f", xAt(index), yAt(point.Y)))
			started = true
		}
		builder.WriteString(`"/>`)
		for index, point := range item.Points {
			if !point.HasValue {
				continue
			}
			class := "ln-chart__point"
			if point.InProgress || point.Partial {
				class += " ln-chart__point--open"
			}
			builder.WriteString(fmt.Sprintf(`<circle class="%s" cx="%.1f" cy="%.1f" r="3.5"><title>%s</title></circle>`,
				class, xAt(index), yAt(point.Y),
				html.EscapeString(item.Label+" "+point.Title)))
		}
		builder.WriteString(`</g>`)
	}
	builder.WriteString(`</svg>`)
	return builder.String()
}
