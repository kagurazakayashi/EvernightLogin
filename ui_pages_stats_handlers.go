package login

// 步骤 76 统计看板页处理器：筛选参数由页面规范化白名单后交给适配器，所有统计值、
// 分桶、占比、增幅与完整性都来自真实统计服务；页面只负责呈现、状态映射与下钻链接
// 生成，不补算统计值、不伪造链接。

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"html/template"
)

// statsPageHandlers 实现统计看板页处理器。
type statsPageHandlers struct {
	pages *pageStatsPages
}

// HandlePage 按路由分派。
func (h *statsPageHandlers) HandlePage(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	switch page.RouteName {
	case "admin.dashboard":
		return h.dashboard(ctx, request, page)
	case "admin.statistics":
		return h.statistics(ctx, request, page)
	case "admin.statistics_errors":
		return h.errors(ctx, request, page)
	default:
		return UIPageOutcome{}, nil
	}
}

// statsCapabilities 读取页面能力位；失败时全部 false（fail-closed，只影响呈现，
// 每次读取仍由服务端重新授权）。
func (h *statsPageHandlers) statsCapabilities(ctx context.Context,
	page UIPageContext) UIStatsCapabilities {
	caps, err := h.pages.options.Backend.Capabilities(ctx, page.Session.UserID)
	if err != nil {
		return UIStatsCapabilities{}
	}
	caps.Scopes = statsScopeList(caps)
	return caps
}

// recordPageDenial 尽力记录一次页面级拒绝（失败只影响留痕，不改变拒绝结果）。
func (h *statsPageHandlers) recordPageDenial(ctx context.Context, page UIPageContext,
	reason string) {
	_ = h.pages.options.Backend.RecordDenial(ctx, page.Session.UserID, reason)
}

// statsBaseData 构造所有统计页共用的数据与过滤器回显。
func (h *statsPageHandlers) statsBaseData(page UIPageContext,
	caps UIStatsCapabilities) map[string]any {
	routePath := statsRoutePath(page.RouteName)
	// 错误类别筛选只在统计页与错误明细页生效：看板摘要来自 Overview（口径不接受类别
	// 过滤），不渲染会误导用户的筛选控件。
	showCategory := page.RouteName == "admin.statistics" ||
		page.RouteName == "admin.statistics_errors"
	resetWindow := UIStatsWindow{TimeZone: page.TimeZone,
		Granularity: UIStatsDefaultGranule, Range: UIStatsRange7Days}
	return map[string]any{
		"capabilities": caps, "scopes": caps.Scopes,
		"forbidden": false, "invalid": false, "loadFailed": false,
		"filterAction": page.BasePath + routePath, "showCategory": showCategory,
		"resetURL": statsPageURL(page.BasePath, routePath, resetWindow,
			UIStatsScopeSystem, nil),
		"categoryURLs": map[string]string{},
		"timezone":     page.TimeZone, "updatedAt": time.Time{},
		"completeness": UIStatsCompleteness{}, "completenessNotes": false,
		"window": UIStatsWindow{}, "scopeID": UIStatsScopeSystem,
		"dashboardURL": statsPageURL(page.BasePath, "/admin/dashboard",
			UIStatsWindow{TimeZone: page.TimeZone, Granularity: UIStatsDefaultGranule,
				Range: UIStatsRange7Days}, UIStatsScopeSystem, nil),
		"statisticsURL": statsPageURL(page.BasePath, "/admin/statistics",
			UIStatsWindow{TimeZone: page.TimeZone, Granularity: UIStatsDefaultGranule,
				Range: UIStatsRange7Days}, UIStatsScopeSystem, nil),
		"errorsURL": statsPageURL(page.BasePath, "/admin/statistics/errors",
			UIStatsWindow{TimeZone: page.TimeZone, Granularity: UIStatsDefaultGranule,
				Range: UIStatsRange7Days}, UIStatsScopeSystem, nil),
	}
}

// statsFilterEcho 把规范化后的筛选写回模板（表单回显与链接均以服务端结果为准）。
func statsFilterEcho(data map[string]any, window UIStatsWindow, scopeID, category,
	metric, sortField, order string, limit, offset int) {
	data["window"] = window
	data["scopeID"] = scopeID
	data["timezone"] = window.TimeZone
	data["timezoneOptions"] = statsTimeZoneOptions(window.TimeZone)
	data["granularity"] = window.Granularity
	data["range"] = window.Range
	data["rangeKey"] = statsRangeKey(window.Range)
	data["fromValue"] = window.FromValue
	data["toValue"] = window.ToValue
	data["category"] = category
	data["metric"] = metric
	data["sort"] = sortField
	data["order"] = order
	data["limit"], data["offset"] = limit, offset
	data["categoryOptions"] = UIStatsCategoryValues()
	data["metricOptions"] = UIStatsMetricValues()
	data["granularityOptions"] = UIStatsGranularityValues()
	data["sortOptions"] = UIStatsSortValues()
	data["inProgress"] = window.InProgress
	data["rangeStartDate"] = statsDateValue(window.Start, statsWindowLocation(window))
	lastMoment := window.End.Add(-time.Nanosecond)
	data["rangeEndDate"] = statsDateValue(lastMoment, statsWindowLocation(window))
}

// statsResetURL 返回当前页默认筛选链接，保留当前真实作用范围（应用管理员重置不能
// 被固定成无权的 system 范围）。
func statsResetURL(page UIPageContext, scopeID string) string {
	if scopeID == "" {
		scopeID = UIStatsScopeSystem
	}
	resetWindow := UIStatsWindow{TimeZone: page.TimeZone,
		Granularity: UIStatsDefaultGranule, Range: UIStatsRange7Days}
	return statsPageURL(page.BasePath, statsRoutePath(page.RouteName), resetWindow,
		scopeID, nil)
}

// scopeLabel 返回作用范围显示文本：系统范围使用固定文案，应用范围显示稳定 ID。
func scopeLabel(page UIPageContext, scopeID string) string {
	if scopeID == UIStatsScopeSystem {
		return text("page.admin.statistics.scope.system")
	}
	return text("page.admin.statistics.scope.app") + " " + scopeID
}

// statsCommon 是统计页共用的筛选解析结果。
type statsCommon struct {
	caps        UIStatsCapabilities
	window      UIStatsWindow
	scopeID     string
	category    string
	metric      string
	sortField   string
	order       string
	limit       int
	offset      int
	fieldErrors map[string]string
}

// parseStatsCommon 解析筛选、作用范围与分页；失败时返回字段错误，不执行查询。
func (h *statsPageHandlers) parseStatsCommon(request *http.Request,
	page UIPageContext, caps UIStatsCapabilities) statsCommon {
	values := request.URL.Query()
	common := statsCommon{caps: caps, category: "", metric: "raw_events",
		sortField: "raw_events", order: "desc", limit: UIStatsDefaultLimit}
	fieldErrors := map[string]string{}
	common.window, fieldErrors = parseUIStatsWindow(values, page, h.pages.options.Now())
	// 作用范围：未指定时优先当前应用上下文；没有应用上下文但账户只有应用范围权限时
	// 回退到第一个获准应用范围，不能固定 system 让合法应用管理员得到 400。
	systemAllowed := false
	appScope := ""
	for _, scope := range caps.Scopes {
		if scope == UIStatsScopeSystem {
			systemAllowed = true
			continue
		}
		if appScope == "" {
			appScope = scope
		}
	}
	defaultScope := UIStatsScopeSystem
	if page.Session.AppID != "" {
		for _, scope := range caps.Scopes {
			if scope == page.Session.AppID {
				defaultScope = page.Session.AppID
				break
			}
		}
	} else if !systemAllowed && appScope != "" {
		defaultScope = appScope
	}
	scopeID, ok := normalizeStatsScope(values.Get("scope"), caps, defaultScope)
	if !ok {
		fieldErrors["scope"] = text("page.admin.statistics.filter.invalid_scope")
	}
	common.scopeID = scopeID
	category, categoryOK := normalizeStatsCategory(values.Get("category"))
	if !categoryOK {
		fieldErrors["category"] = text("page.admin.statistics.filter.invalid_value")
	}
	common.category = category
	metric, metricOK := normalizeStatsMetric(values.Get("metric"))
	if !metricOK {
		fieldErrors["metric"] = text("page.admin.statistics.filter.invalid_value")
	}
	common.metric = metric
	sortField, sortOK := normalizeStatsSort(values.Get("sort"))
	if !sortOK {
		fieldErrors["sort"] = text("page.admin.statistics.filter.invalid_value")
	}
	common.sortField = sortField
	common.order = normalizeStatsOrder(values.Get("order"))
	limit, offset, pageOK := parseStatsPagination(values)
	if !pageOK {
		fieldErrors["limit"] = text("page.admin.statistics.filter.invalid_page")
	}
	common.limit, common.offset = limit, offset
	common.fieldErrors = fieldErrors
	return common
}

// statsLoadFailed 构造区域读取失败的稳定结果：保留筛选回显，不把旧数据伪装成新值。
func statsLoadFailed(data map[string]any, err error,
	fallbackKey string) UIPageOutcome {
	code := "INTERNAL_ERROR"
	status := http.StatusInternalServerError
	var publicErr *UIStatsError
	if errors.As(err, &publicErr) {
		code = publicErr.Code
	}
	switch code {
	case "ACCESS_DENIED":
		status = http.StatusForbidden
		data["forbidden"] = true
		data["loadFailed"] = true
	case "REAUTH_REQUIRED":
		status = http.StatusForbidden
		data["reauthRequired"] = true
	case "REQ_INVALID":
		status = http.StatusBadRequest
		data["invalid"] = true
	case "DB_UNAVAILABLE":
		status = http.StatusServiceUnavailable
		data["loadFailed"] = true
	case "RATE_LIMITED":
		status = http.StatusTooManyRequests
		data["loadFailed"] = true
	default:
		data["loadFailed"] = true
	}
	return UIPageOutcome{StatusCode: status, Data: data, ErrorCode: code,
		ErrorSummary: text(fallbackKey)}
}

// applyStatsWindow 把后端返回的规范化窗口写回数据，供模板显示区间与时区。
func applyStatsWindow(data map[string]any, window UIStatsWindow) {
	data["window"] = window
	data["timezone"] = window.TimeZone
	data["inProgress"] = window.InProgress
	data["rangeStartDate"] = statsDateValue(window.Start, statsWindowLocation(window))
	data["rangeEndDate"] = statsDateValue(window.End.Add(-time.Nanosecond),
		statsWindowLocation(window))
}

// attachCompleteness 写入完整性信息与展示提示判断。
func attachCompleteness(data map[string]any, completeness UIStatsCompleteness) {
	data["completeness"] = completeness
	data["completenessNotes"] = statsHasCompletenessNotes(completeness)
}

// buildStatsLinks 写入页面间链接（保留当前筛选，不夹带秘密或未知键）。
func buildStatsLinks(page UIPageContext, data map[string]any, common statsCommon) {
	window := common.window
	extra := url.Values{}
	if common.category != "" {
		extra.Set("category", common.category)
	}
	data["dashboardURL"] = statsPageURL(page.BasePath, "/admin/dashboard", window,
		common.scopeID, nil)
	data["statisticsURL"] = statsPageURL(page.BasePath, "/admin/statistics", window,
		common.scopeID, extra)
	data["errorsURL"] = statsPageURL(page.BasePath, "/admin/statistics/errors", window,
		common.scopeID, extra)
	data["scopeLabel"] = scopeLabel(page, common.scopeID)
	data["eventsAllowed"] = common.caps.Events
}

// dashboard 渲染看板总览：摘要卡、当前系统状态（独立于历史筛选）、完整性与入口。
func (h *statsPageHandlers) dashboard(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	caps := h.statsCapabilities(ctx, page)
	data := h.statsBaseData(page, caps)
	if !caps.Read {
		h.recordPageDenial(ctx, page, "stats_read_capability_denied")
		data["forbidden"] = true
		return UIPageOutcome{StatusCode: http.StatusForbidden, Data: data,
			ErrorSummary: text("page.admin.statistics.common.forbidden")}, nil
	}
	common := h.parseStatsCommon(request, page, caps)
	statsFilterEcho(data, common.window, common.scopeID, common.category,
		common.metric, common.sortField, common.order, common.limit, common.offset)
	buildStatsLinks(page, data, common)
	data["refreshURL"] = statsWhitelistURL(page, common)
	data["resetURL"] = statsResetURL(page, common.scopeID)
	if len(common.fieldErrors) > 0 {
		data["invalid"] = true
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
			FieldErrors:  common.fieldErrors,
			ErrorSummary: text("page.admin.statistics.filter.invalid_summary")}, nil
	}
	result, err := h.pages.options.Backend.Dashboard(ctx, page.Session.UserID,
		UIStatsQuery{ScopeID: common.scopeID, Window: common.window,
			Category: common.category, Metric: common.metric,
			Sort: common.sortField, Order: common.order})
	if err != nil {
		return statsLoadFailed(data, err, "page.admin.statistics.dashboard.load_failed"), nil
	}
	data["overview"] = result.Overview
	data["health"] = result.Health
	data["healthUnavailable"] = result.HealthUnavailable
	data["healthHistoryAvailable"] = result.HealthHistoryAvailable
	data["updatedAt"] = result.UpdatedAt
	applyStatsWindow(data, UIStatsWindow{TimeZone: result.Overview.TimeZone,
		Start: result.Overview.Start, End: result.Overview.End,
		Granularity: result.Overview.Granularity, Range: common.window.Range,
		FromValue: common.window.FromValue, ToValue: common.window.ToValue,
		InProgress: common.window.InProgress})
	attachCompleteness(data, result.Overview.Completeness)
	// 类别摘要提供到错误分类明细（内部页面，仍由服务端授权）的入口。
	data["categorySummary"] = result.Overview.Categories
	categoryURLs := make(map[string]string, len(result.Overview.Categories))
	for _, category := range result.Overview.Categories {
		extra := url.Values{}
		extra.Set("category", category.Category)
		categoryURLs[category.Category] = statsPageURL(page.BasePath,
			"/admin/statistics/errors", common.window, common.scopeID, extra)
	}
	data["categoryURLs"] = categoryURLs
	// 摘要是否为空：真实覆盖完整且所有计数为 0 时显示真实空结果，不显示示例数字。
	empty := result.Overview.ActiveUsers == 0 && result.Overview.RawEvents == 0 &&
		result.Overview.FailedRequests == 0 && result.Overview.FailedTasks == 0
	data["empty"] = empty
	return UIPageOutcome{Data: data}, nil
}

// statistics 渲染活跃度与错误趋势：图表、同源数据表与口径说明使用同一窗口。
func (h *statsPageHandlers) statistics(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	caps := h.statsCapabilities(ctx, page)
	data := h.statsBaseData(page, caps)
	if !caps.Read {
		h.recordPageDenial(ctx, page, "stats_read_capability_denied")
		data["forbidden"] = true
		return UIPageOutcome{StatusCode: http.StatusForbidden, Data: data,
			ErrorSummary: text("page.admin.statistics.common.forbidden")}, nil
	}
	common := h.parseStatsCommon(request, page, caps)
	statsFilterEcho(data, common.window, common.scopeID, common.category,
		common.metric, common.sortField, common.order, common.limit, common.offset)
	buildStatsLinks(page, data, common)
	data["refreshURL"] = statsWhitelistURL(page, common)
	data["resetURL"] = statsResetURL(page, common.scopeID)
	if len(common.fieldErrors) > 0 {
		data["invalid"] = true
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
			FieldErrors:  common.fieldErrors,
			ErrorSummary: text("page.admin.statistics.filter.invalid_summary")}, nil
	}
	result, err := h.pages.options.Backend.Statistics(ctx, page.Session.UserID,
		UIStatsQuery{ScopeID: common.scopeID, Window: common.window,
			Category: common.category, Metric: common.metric})
	if err != nil {
		return statsLoadFailed(data, err, "page.admin.statistics.statistics.load_failed"), nil
	}
	activity := result.Activity
	trend := result.ErrorTrend
	// 同一请求内两次服务端读取必须归一到同一窗口；不一致时明确标出，不拼成一组数据。
	sameWindow := activity.Start.Equal(trend.Start) && activity.End.Equal(trend.End)
	data["sameWindow"] = sameWindow
	data["windowMismatch"] = !sameWindow
	applyStatsWindow(data, UIStatsWindow{TimeZone: activity.TimeZone,
		Start: activity.Start, End: activity.End, Granularity: activity.Granularity,
		Range: common.window.Range, FromValue: common.window.FromValue,
		ToValue: common.window.ToValue, InProgress: common.window.InProgress})
	attachCompleteness(data, trend.Completeness)
	// 活跃度图表与数据表
	data["activity"] = activity
	data["activityChartSVG"] = template.HTML(statsActivityChart(activity,
		text("page.admin.statistics.activity_title"),
		text("page.admin.statistics.chart_summary")))
	data["activityEmpty"] = activity.TotalActiveUsers == 0
	for index := range activity.Points {
		point := &activity.Points[index]
		if caps.Events {
			point.DrilldownURL = activityDrilldownURL(page.BasePath, common.window,
				common.scopeID, point.Start, point.End)
		}
	}
	// 错误趋势图表、同源数据表与主指标值
	trendData := trend
	for index := range trendData.Points {
		point := &trendData.Points[index]
		point.MetricValue = int64(statsTrendMetricValue(trendData.Metric, *point))
		if caps.Events {
			appID := ""
			if common.scopeID != UIStatsScopeSystem {
				appID = common.scopeID
			}
			point.DrilldownURL = statsBucketDrilldownURL(page.BasePath,
				common.window.TimeZone, point.Start, point.End, common.scopeID,
				appID, point.Category, "")
		}
	}
	data["errorTrend"] = trendData
	data["errorChartSVG"] = template.HTML(statsErrorTrendChart(trendData,
		text("page.admin.statistics.chart_summary")))
	data["errorEmpty"] = trendData.TotalRawEvents == 0
	data["metricLabelKey"] = statsMetricKey(trendData.Metric)
	data["metricValueLabelKey"] = "page.admin.statistics.metric." + statsMetricSuffix(trendData.Metric)
	data["updatedAt"] = result.UpdatedAt
	// 类别筛选在统计页同时影响活跃度与错误趋势（服务端口径），页面显式说明。
	data["categoryFiltered"] = common.category != ""
	return UIPageOutcome{Data: data}, nil
}

// statsMetricSuffix 返回趋势指标的数据表列/单位键后缀。
func statsMetricSuffix(metric string) string {
	switch metric {
	case "dedup_failed_requests":
		return "dedup_failed_requests"
	case "dedup_failed_tasks":
		return "dedup_failed_tasks"
	default:
		return "raw_events"
	}
}

// errors 渲染错误分类明细：五种白名单排序、占比、首次/最近发生与增幅。
func (h *statsPageHandlers) errors(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	caps := h.statsCapabilities(ctx, page)
	data := h.statsBaseData(page, caps)
	if !caps.Read {
		h.recordPageDenial(ctx, page, "stats_read_capability_denied")
		data["forbidden"] = true
		return UIPageOutcome{StatusCode: http.StatusForbidden, Data: data,
			ErrorSummary: text("page.admin.statistics.common.forbidden")}, nil
	}
	common := h.parseStatsCommon(request, page, caps)
	statsFilterEcho(data, common.window, common.scopeID, common.category,
		common.metric, common.sortField, common.order, common.limit, common.offset)
	buildStatsLinks(page, data, common)
	data["refreshURL"] = statsWhitelistURL(page, common)
	data["resetURL"] = statsResetURL(page, common.scopeID)
	if len(common.fieldErrors) > 0 {
		data["invalid"] = true
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
			FieldErrors:  common.fieldErrors,
			ErrorSummary: text("page.admin.statistics.filter.invalid_summary")}, nil
	}
	result, err := h.pages.options.Backend.Errors(ctx, page.Session.UserID,
		UIStatsQuery{ScopeID: common.scopeID, Window: common.window,
			Category: common.category, Sort: common.sortField, Order: common.order,
			Limit: common.limit, Offset: common.offset})
	if err != nil {
		return statsLoadFailed(data, err, "page.admin.statistics.errors.load_failed"), nil
	}
	applyStatsWindow(data, UIStatsWindow{TimeZone: result.TimeZone,
		Start: result.Start, End: result.End, Granularity: result.Granularity,
		Range: common.window.Range, FromValue: common.window.FromValue,
		ToValue: common.window.ToValue, InProgress: common.window.InProgress})
	attachCompleteness(data, result.Completeness)
	data["errors"] = result
	data["updatedAt"] = result.UpdatedAt
	data["empty"] = len(result.Rows) == 0
	data["shareZeroDenominator"] = result.ShareDenominator == 0
	data["comparisonEnabled"] = result.ComparisonEnabled
	data["sortLabelKey"] = statsSortKey(result.Sort)
	// 排序表头链接：切换排序保持其余筛选，排序变化回到第一页。
	data["sortLinks"] = statsSortLinks(page, common)
	// 下钻链接只在拥有审计读取能力时生成；否则模板显示权限原因而非伪链接。
	if caps.Events {
		for index := range result.Rows {
			row := &result.Rows[index]
			row.DrilldownURL = statsErrorRowDrilldownURL(page.BasePath, common.window,
				common.scopeID, *row)
		}
		data["errors"] = result
		data["eventsAllowed"] = true
	}
	data["prevURL"], data["nextURL"] = statsPaginationURLs(page, common,
		result.HasMore, result.Offset)
	return UIPageOutcome{Data: data}, nil
}

// statsSortLinks 生成五种白名单排序的表头链接（升/降切换、回到第一页）。
func statsSortLinks(page UIPageContext, common statsCommon) map[string]string {
	links := make(map[string]string, len(UIStatsSortValues()))
	for _, sortField := range UIStatsSortValues() {
		order := "desc"
		if common.sortField == sortField && common.order == "desc" {
			order = "asc"
		}
		extra := url.Values{}
		extra.Set("sort", sortField)
		extra.Set("order", order)
		if common.category != "" {
			extra.Set("category", common.category)
		}
		links[sortField] = statsPageURL(page.BasePath, "/admin/statistics/errors",
			common.window, common.scopeID, extra)
	}
	return links
}

// statsWhitelistURL 从规范化筛选重建当前页 URL（只含白名单参数，未知/敏感查询参数
// 不进入刷新与分页链接）。
func statsWhitelistURL(page UIPageContext, common statsCommon) string {
	extra := url.Values{}
	if common.category != "" {
		extra.Set("category", common.category)
	}
	extra.Set("metric", common.metric)
	extra.Set("sort", common.sortField)
	extra.Set("order", common.order)
	extra.Set("limit", formatUINumber(int64(common.limit)))
	if common.offset > 0 {
		extra.Set("offset", formatUINumber(int64(common.offset)))
	}
	return statsPageURL(page.BasePath, statsRoutePath(page.RouteName), common.window,
		common.scopeID, extra)
}

// statsPaginationURLs 生成上一页/下一页白名单链接；HasMore 之外不伪造总页数或末页。
// 链接从规范化筛选重建，不复制原始查询串中的未知参数。
func statsPaginationURLs(page UIPageContext, common statsCommon, hasMore bool,
	offset int) (string, string) {
	build := func(nextOffset int) string {
		cloned := common
		cloned.offset = nextOffset
		return statsWhitelistURL(page, cloned)
	}
	previous := ""
	if offset > 0 && offset >= common.limit {
		previous = build(offset - common.limit)
	}
	next := ""
	if hasMore {
		next = build(offset + common.limit)
	}
	return previous, next
}
