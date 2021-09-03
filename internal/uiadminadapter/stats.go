// Package uiadminadapter：步骤 76 统计看板页适配器。
//
// 安全边界：适配器只接受页面已通过 UIAccessManagement 验证后传入的操作者用户 ID，
// 每次都重新构造可信 Caller 并调用真实 internal/stats（权限键 reports.read）与可选
// 的审计读取能力判定；统计值、分桶、去重、占比、增幅与完整性都由领域服务计算。
// 适配器不读取前端自报角色、不缓存授权、不把内部错误文本或连接信息写入页面结果；
// 系统健康快照只对系统范围查询，应用范围不泄露全系统基础设施状态。
package uiadminadapter

import (
	"context"
	"errors"
	"log/slog"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
)

// StatsOptions 是统计页适配器依赖。Authorizer 由宿主注入真实权限引擎；nil 时页面
// 一律 fail-closed 拒绝。IsRoot 由宿主实现真实 root 判定；nil 时按非 root。
// AuditRead 判定当前操作者是否拥有审计事件读取能力（下钻）；nil 时不下钻并显示
// 明确限制，而不是生成伪链接。Recorder 用于拒绝留痕（nil 时只记录日志）。
type StatsOptions struct {
	Stats      *stats.Service
	Authorizer stats.Authorizer
	Recorder   AuditRecorder
	IsRoot     func(ctx context.Context, userID string) (bool, error)
	AuditRead  func(ctx context.Context, userID string) (bool, error)
	Logger     *slog.Logger
}

// StatsAdapter 实现 login.UIPageStatsBackend。
type StatsAdapter struct {
	opts StatsOptions
}

// NewStats 校验依赖并构造统计页适配器。统计读取授权在 stats.Service 内部完成，
// 但能力位与获准作用范围呈现依赖 Authorizer/IsRoot；缺失时构造期直接失败，避免
// 宿主漏装配后表现为“整页 403”而被误认为配置成功。
func NewStats(options StatsOptions) (*StatsAdapter, error) {
	if options.Stats == nil {
		return nil, errors.New("统计页适配器缺少 stats 服务")
	}
	if options.Authorizer == nil {
		return nil, errors.New("统计页适配器缺少权限引擎 Authorizer")
	}
	if options.IsRoot == nil {
		return nil, errors.New("统计页适配器缺少 root 判定 IsRoot")
	}
	return &StatsAdapter{opts: options}, nil
}

// statsCaller 把页面已认证用户 ID 重建为可信 Caller。
func statsCaller(userID string) (account.Caller, error) {
	if userID == "" || !account.ValidUserID(userID) {
		return account.Caller{}, &login.UIStatsError{Code: "ACCESS_DENIED"}
	}
	return account.UserCaller(userID)
}

// isRoot 判定 root；依赖失败按非 root（fail-closed）。
func (a *StatsAdapter) isRoot(ctx context.Context, userID string) bool {
	if a.opts.IsRoot == nil {
		return false
	}
	root, err := a.opts.IsRoot(ctx, userID)
	return err == nil && root
}

// Capabilities 返回页面能力位与获准作用范围。能力位只是呈现辅助，每次读取仍由
// 领域服务重新授权；未装配授权器或失败为 false。
func (a *StatsAdapter) Capabilities(ctx context.Context,
	userID string) (login.UIStatsCapabilities, error) {
	caller, err := statsCaller(userID)
	if err != nil {
		return login.UIStatsCapabilities{}, err
	}
	caps := login.UIStatsCapabilities{Scopes: []string{}}
	if a.isRoot(ctx, userID) {
		// root 可查询任意应用，但页面无法枚举全部应用；仍以系统范围为默认入口，
		// 由服务端按 URL 中的显式应用范围再次校验。
		caps.Read = true
		caps.Scopes = []string{stats.ScopeSystem}
	} else if a.opts.Authorizer != nil {
		grant, grantErr := a.opts.Authorizer.AuthorizeScope(ctx, caller,
			stats.PermissionRead, stats.ScopeSystem)
		if grantErr == nil && grant.Allowed {
			caps.Read = true
			caps.Scopes = statsScopesFromGrant(grant)
		}
	}
	if a.opts.AuditRead != nil {
		if allowed, auditErr := a.opts.AuditRead(ctx, userID); auditErr == nil {
			caps.Events = allowed
		}
	}
	return caps, nil
}

// statsScopesFromGrant 把授权结果映射为页面可见作用范围：全数据权限显示系统范围
// 与“全部可查看应用”（以 system 表示），资源范围只显示获准应用与系统级事件。
func statsScopesFromGrant(grant stats.ScopeGrant) []string {
	scopes := make([]string, 0, len(grant.ResourceIDs)+1)
	if grant.AllData {
		return []string{stats.ScopeSystem}
	}
	system := false
	for _, resource := range grant.ResourceIDs {
		if resource == stats.ScopeSystem {
			system = true
			continue
		}
		scopes = append(scopes, resource)
	}
	if system {
		scopes = append(scopes, stats.ScopeSystem)
	}
	return scopes
}

// mapStatsError 把 stats 领域错误映射为页面公开错误（不泄露内部细节）。
func mapStatsError(err error) error {
	if err == nil {
		return nil
	}
	var publicErr *login.UIStatsError
	if errors.As(err, &publicErr) {
		return err
	}
	switch {
	case errors.Is(err, stats.ErrAccessDenied):
		return &login.UIStatsError{Code: "ACCESS_DENIED"}
	case errors.Is(err, stats.ErrInvalidRequest), errors.Is(err, stats.ErrOptionsInvalid):
		return &login.UIStatsError{Code: "REQ_INVALID"}
	case errors.Is(err, stats.ErrStoreUnavailable):
		return &login.UIStatsError{Code: "DB_UNAVAILABLE"}
	default:
		return &login.UIStatsError{Code: "INTERNAL_ERROR"}
	}
}

// statsWindowRequest 把页面规范化窗口转换为领域窗口请求。页面已校验粒度白名单。
func statsWindowRequest(window login.UIStatsWindow) (stats.WindowRequest, error) {
	granularity := stats.Granularity(window.Granularity)
	switch granularity {
	case stats.GranularityDay, stats.GranularityWeek, stats.GranularityMonth:
	case "":
		granularity = stats.GranularityDay
	default:
		return stats.WindowRequest{}, &login.UIStatsError{Code: "REQ_INVALID"}
	}
	if window.TimeZone == "" || window.Start.IsZero() || window.End.IsZero() {
		return stats.WindowRequest{}, &login.UIStatsError{Code: "REQ_INVALID"}
	}
	return stats.WindowRequest{TimeZone: window.TimeZone, Start: window.Start,
		End: window.End, Granularity: granularity}, nil
}

// toCompleteness 转换完整性结构（只含稳定、可公开展示的字段）。
func toCompleteness(completeness stats.Completeness) login.UIStatsCompleteness {
	result := login.UIStatsCompleteness{
		WindowWithinRetention: completeness.WindowWithinRetention,
		RetentionDays:         completeness.RetentionDays,
		RetentionConfigured:   completeness.RetentionConfigured,
		RetentionCutoff:       completeness.RetentionCutoff,
		ScopeTrimmed:          completeness.ScopeTrimmed,
		SourceTruncated:       completeness.SourceTruncated,
	}
	result.MissingIntervals = toIntervals(completeness.MissingIntervals)
	result.SamplingGaps = toIntervals(completeness.SamplingGaps)
	for _, module := range completeness.ModulesNotEnabled {
		result.ModulesNotEnabled = append(result.ModulesNotEnabled, string(module))
	}
	return result
}

// toIntervals 转换缺失区间。
func toIntervals(intervals []stats.MissingInterval) []login.UIStatsInterval {
	result := make([]login.UIStatsInterval, 0, len(intervals))
	for _, interval := range intervals {
		result = append(result, login.UIStatsInterval{Start: interval.Start,
			End: interval.End, Reason: interval.Reason})
	}
	return result
}

// toCategorySummary 转换类别汇总。
func toCategorySummary(summaries []stats.CategorySummary) []login.UIStatsCategorySummary {
	result := make([]login.UIStatsCategorySummary, 0, len(summaries))
	for _, summary := range summaries {
		result = append(result, login.UIStatsCategorySummary{
			Category: string(summary.Category), Severity: string(summary.Severity),
			RawEvents: summary.RawEvents, FailedRequests: summary.FailedRequests,
			FailedTasks: summary.FailedTasks})
	}
	return result
}

// Dashboard 读取同一窗口的看板摘要与当前系统状态。健康快照只在系统范围读取；应用
// 范围不适用或读取失败都如实标记，绝不用历史筛选值冒充当前状态。
func (a *StatsAdapter) Dashboard(ctx context.Context, userID string,
	query login.UIStatsQuery) (login.UIStatsDashboard, error) {
	caller, err := statsCaller(userID)
	if err != nil {
		return login.UIStatsDashboard{}, err
	}
	window, err := statsWindowRequest(query.Window)
	if err != nil {
		return login.UIStatsDashboard{}, err
	}
	overview, err := a.opts.Stats.Overview(ctx, stats.OverviewRequest{
		Caller: caller, ScopeID: query.ScopeID, Window: window})
	if err != nil {
		return login.UIStatsDashboard{}, mapStatsError(err)
	}
	// 健康采样空档必须来自真实历史采样查询（当前快照没有历史）。它在仪表盘上独立
	// 标注来源；查询失败只影响空档提示，不伪装成“没有空档”。
	historyAvailable := false
	var historyGaps []stats.MissingInterval
	if query.ScopeID == stats.ScopeSystem {
		if history, historyErr := a.opts.Stats.HealthHistory(ctx, stats.HealthHistoryRequest{
			Caller: caller, ScopeID: stats.ScopeSystem, Window: window}); historyErr == nil {
			historyAvailable = true
			historyGaps = history.Completeness.SamplingGaps
		}
	}
	result := login.UIStatsDashboard{
		Overview: login.UIStatsOverview{
			ScopeID: overview.Scope.ID, ScopeKind: overview.Scope.Kind,
			Start: overview.Window.Start, End: overview.Window.End,
			TimeZone: overview.Window.TimeZone, Granularity: string(overview.Window.Granularity),
			ActiveUsers: overview.ActiveUsers, RawEvents: overview.TotalRawEvents,
			FailedRequests: overview.FailedRequests, FailedTasks: overview.FailedTasks,
			Categories:     toCategorySummary(overview.Categories),
			ActivityStatus: string(overview.ActivityStatus),
			DataCutoff:     overview.Window.DataCutoff,
			UpdatedAt:      overview.GeneratedAt,
			Completeness:   toCompleteness(overview.Completeness),
		},
		UpdatedAt:              overview.GeneratedAt,
		HealthHistoryAvailable: historyAvailable,
	}
	result.Overview.Completeness.SamplingGaps = toIntervals(historyGaps)
	// 系统健康是系统级数据：只有系统作用范围才读取，避免向应用管理员泄露基础设施
	// 状态；应用范围标记为不适用而不是失败。
	if query.ScopeID == stats.ScopeSystem {
		health, healthErr := a.opts.Stats.Health(ctx, stats.HealthRequest{
			Caller: caller, ScopeID: stats.ScopeSystem})
		if healthErr != nil {
			result.HealthUnavailable = true
		} else {
			result.Health = toHealth(health)
		}
	} else {
		result.HealthUnavailable = true
	}
	return result, nil
}

// toHealth 转换当前健康快照（只保留稳定模块/状态/时间/来源与脱敏补充字段）。
func toHealth(health stats.HealthResult) *login.UIStatsHealth {
	result := &login.UIStatsHealth{ObservedAt: health.ObservedAt,
		Modules: make([]login.UIStatsHealthSample, 0, len(health.Modules))}
	for _, module := range health.Modules {
		sample := login.UIStatsHealthSample{
			Module: string(module.Module), State: string(module.State),
			Severity: string(module.Severity), Enabled: module.Enabled,
			ObservedAt: module.ObservedAt, Source: module.Source,
		}
		if module.Detail != nil {
			sample.Reason = module.Detail["reason"]
			sample.LatencyMS = module.Detail["latency_ms"]
			sample.NotAfter = module.Detail["not_after"]
			sample.RemainingHours = module.Detail["remaining_h"]
		}
		if module.State == stats.StateNotEnabled {
			result.NotEnabled = append(result.NotEnabled, string(module.Module))
		}
		result.Modules = append(result.Modules, sample)
	}
	return result
}

// toActivity 转换活跃度结果。
func toActivity(activity stats.ActivityResult) login.UIStatsActivity {
	result := login.UIStatsActivity{
		Start: activity.Window.Start, End: activity.Window.End,
		TimeZone: activity.Window.TimeZone, Granularity: string(activity.Window.Granularity),
		TotalActiveUsers: activity.TotalActiveUsers, DedupeScope: activity.DedupeScope,
		UpdatedAt: activity.GeneratedAt, Completeness: toCompleteness(activity.Completeness),
		Points: make([]login.UIStatsPoint, 0, len(activity.Points)),
	}
	for _, point := range activity.Points {
		result.Points = append(result.Points, login.UIStatsPoint{
			BucketKey: point.Bucket.Key, Start: point.Bucket.Start, End: point.Bucket.End,
			InProgress: point.Bucket.InProgress, Partial: point.Bucket.Partial,
			ActiveUsers: point.ActiveUsers, DataStatus: string(point.DataStatus)})
	}
	return result
}

// Statistics 读取同一窗口的活跃度与错误趋势；两次读取使用同一显式起止时间与作用
// 范围，返回窗口若不一致由页面明确标注而不是拼接。
func (a *StatsAdapter) Statistics(ctx context.Context, userID string,
	query login.UIStatsQuery) (login.UIStatsStatistics, error) {
	caller, err := statsCaller(userID)
	if err != nil {
		return login.UIStatsStatistics{}, err
	}
	window, err := statsWindowRequest(query.Window)
	if err != nil {
		return login.UIStatsStatistics{}, err
	}
	categories := []stats.Category(nil)
	if query.Category != "" {
		categories = []stats.Category{stats.Category(query.Category)}
	}
	metric := stats.Metric(query.Metric)
	if metric == "" {
		metric = stats.MetricRawEvents
	}
	activity, err := a.opts.Stats.Activity(ctx, stats.ActivityRequest{
		Caller: caller, ScopeID: query.ScopeID, Window: window})
	if err != nil {
		return login.UIStatsStatistics{}, mapStatsError(err)
	}
	trend, err := a.opts.Stats.ErrorTrend(ctx, stats.ErrorTrendRequest{
		Caller: caller, ScopeID: query.ScopeID, Window: window,
		Categories: categories, Metric: metric})
	if err != nil {
		return login.UIStatsStatistics{}, mapStatsError(err)
	}
	result := login.UIStatsStatistics{Activity: toActivity(activity),
		ErrorTrend: toErrorTrend(trend)}
	result.UpdatedAt = activity.GeneratedAt
	if trend.GeneratedAt.After(result.UpdatedAt) {
		result.UpdatedAt = trend.GeneratedAt
	}
	return result, nil
}

// toErrorTrend 转换错误趋势结果。
func toErrorTrend(trend stats.ErrorTrendResult) login.UIStatsErrorTrend {
	result := login.UIStatsErrorTrend{
		Start: trend.Window.Start, End: trend.Window.End,
		TimeZone: trend.Window.TimeZone, Granularity: string(trend.Window.Granularity),
		Metric: string(trend.Metric), Categories: toCategorySummary(trend.Categories),
		TotalRawEvents: trend.TotalRawEvents, FailedRequests: trend.FailedRequests,
		FailedTasks: trend.FailedTasks, UpdatedAt: trend.GeneratedAt,
		Completeness: toCompleteness(trend.Completeness),
		Points:       make([]login.UIStatsErrorPoint, 0, len(trend.Points)),
	}
	for _, point := range trend.Points {
		result.Points = append(result.Points, login.UIStatsErrorPoint{
			BucketKey: point.Bucket.Key, Start: point.Bucket.Start, End: point.Bucket.End,
			InProgress: point.Bucket.InProgress, Category: string(point.Category),
			Severity: string(point.Severity), RawEvents: point.RawEvents,
			FailedRequests: point.FailedRequests, FailedTasks: point.FailedTasks,
			DataStatus: string(point.DataStatus)})
	}
	return result
}

// Errors 读取错误分类明细（五种白名单排序、占比、首次/最近发生与增幅）。
func (a *StatsAdapter) Errors(ctx context.Context, userID string,
	query login.UIStatsQuery) (login.UIStatsErrors, error) {
	caller, err := statsCaller(userID)
	if err != nil {
		return login.UIStatsErrors{}, err
	}
	window, err := statsWindowRequest(query.Window)
	if err != nil {
		return login.UIStatsErrors{}, err
	}
	categories := []stats.Category(nil)
	if query.Category != "" {
		categories = []stats.Category{stats.Category(query.Category)}
	}
	result, err := a.opts.Stats.Errors(ctx, stats.ErrorRequest{
		Caller: caller, ScopeID: query.ScopeID, Window: window,
		Categories: categories, Sort: stats.ErrorSort(query.Sort),
		Order: stats.SortOrder(query.Order), Limit: query.Limit, Offset: query.Offset})
	if err != nil {
		return login.UIStatsErrors{}, mapStatsError(err)
	}
	page := login.UIStatsErrors{
		Start: result.Window.Start, End: result.Window.End,
		TimeZone: result.Window.TimeZone, Granularity: string(result.Window.Granularity),
		TotalRawEvents: result.TotalRawEvents, FailedRequests: result.FailedRequests,
		FailedTasks: result.FailedTasks, ShareDenominator: result.ShareDenominator,
		Categories: toCategorySummary(result.Categories), Sort: string(result.Sort),
		Order: string(result.Order), Limit: result.Limit, Offset: result.Offset,
		HasMore:           result.HasMore,
		ComparisonStart:   result.Comparison.Start,
		ComparisonEnd:     result.Comparison.End,
		ComparisonEnabled: result.Comparison.Reason == "",
		UpdatedAt:         result.GeneratedAt,
		Completeness:      toCompleteness(result.Completeness),
		Rows:              make([]login.UIStatsErrorRow, 0, len(result.Rows)),
	}
	for _, row := range result.Rows {
		page.Rows = append(page.Rows, login.UIStatsErrorRow{
			ErrorCode: row.ErrorCode, Category: string(row.Category),
			Severity: string(row.Severity), AppID: row.AppID,
			RawEvents: row.RawEvents, FailedRequests: row.FailedRequests,
			FailedTasks: row.FailedTasks, Share: row.Share,
			FirstSeen: row.FirstSeen, LastSeen: row.LastSeen,
			GrowthKind: string(row.Growth.Kind), GrowthPercent: row.Growth.Percent,
			DataStatus: string(row.DataStatus),
		})
	}
	return page, nil
}

// RecordDenial 记录一次页面级拒绝（非法参数/能力位不足等），只写稳定动作/目标/
// 原因标记；审计写失败不改变拒绝结果，仅记录日志。
func (a *StatsAdapter) RecordDenial(ctx context.Context, userID, reason string) error {
	caller, err := statsCaller(userID)
	if err != nil {
		return err
	}
	if a.opts.Recorder == nil {
		return nil
	}
	event := audit.Event{Actor: caller.Actor(), Action: "stats.page.denied",
		Target:  audit.Target{Type: "statistics_page", ID: "page_denied"},
		Outcome: audit.OutcomeDenied, ErrorCode: "ACCESS_DENIED",
		ReasonCode: safeDenialToken(reason)}
	if err := a.opts.Recorder.RecordFailure(ctx, event); err != nil {
		if a.opts.Logger != nil {
			a.opts.Logger.Warn("统计页面拒绝审计写入失败", "code", "AUDIT_WRITE_FAILED")
		}
	}
	return nil
}

// 编译期确认实现 login.UIPageStatsBackend。
var _ login.UIPageStatsBackend = (*StatsAdapter)(nil)
