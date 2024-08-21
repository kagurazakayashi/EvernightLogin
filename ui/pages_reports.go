package ui

// 步骤 79：报告计划、历史报告、受控下载与保留清理管理页面（ui.v1）。
//
// 安全不变量：
//   - 全部路由 UIAccessManagement：由宿主 UISessionService 用真实管理会话判定；
//     页面能力位只影响呈现，每次读取/写入/下载/清理都由适配器重建可信 Caller 交给
//     internal/reports 重新授权（reports.read / generate / export / schedule.manage /
//     cleanup 与数据范围）。
//   - 所有状态变更使用 POST 并校验与会话绑定的页面 CSRF 令牌与服务器端校验器；
//     下载走一次性短期令牌并由领域服务再次鉴权，响应 no-store/no-referrer/nosniff，
//     不提供公开分享或永久链接。
//   - 页面只显示服务端返回的真实状态与受控字段；通知结果与生成状态分开，缺失/未知
//     不伪造成 0 或成功；清理明确标注“不删除原始审计”。
//   - 计划编辑携带行版本，冲突时要求重新读取，旧表单不能覆盖新版本；所有者/计划 ID
//     只读，页面不接受客户端自报归属。

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// UIReportsTimeZones 是计划编辑页提供的受控时区白名单。
func UIReportsTimeZones() []string {
	return []string{"UTC", "Asia/Shanghai", "Asia/Tokyo", "Asia/Singapore",
		"Europe/London", "Europe/Berlin", "America/New_York", "America/Los_Angeles"}
}

// UIReportsFormats 返回可选择的报告格式稳定值。
func UIReportsFormats() []string {
	return []string{"html", "csv", "json", "pdf", "markdown"}
}

// UIReportsScheduleTypes 返回计划周期稳定值。
func UIReportsScheduleTypes() []string {
	return []string{"daily", "weekly", "monthly", "custom"}
}

// UIReportsGranularities 返回统计粒度稳定值。
func UIReportsGranularities() []string { return []string{"day", "week", "month"} }

// UIReportsMissedPolicies 返回停机补跑策略稳定值。
func UIReportsMissedPolicies() []string { return []string{"skip", "latest", "all"} }

// UIReportsCategories 返回错误类别稳定值。
func UIReportsCategories() []string {
	return []string{"pending", "denied", "cancelled", "warning", "failure", "unknown"}
}

// UIReportsMetrics 返回错误趋势指标稳定值。
func UIReportsMetrics() []string {
	return []string{"raw_events", "dedup_failed_requests", "dedup_failed_tasks"}
}

// UIReportsStateValues 返回历史状态筛选稳定值（取消请求与实际取消分开）。
func UIReportsStateValues() []string {
	return []string{"queued", "running", "cancel_requested", "cancelled",
		"succeeded", "failed", "timed_out"}
}

// UIReportsCapabilities 是服务端为当前操作者判定的页面能力位（只影响呈现）。
type UIReportsCapabilities struct {
	Read           bool
	Generate       bool
	Export         bool
	ScheduleManage bool
	Cleanup        bool
	// DownloadTTL 是短期下载令牌有效期（页面显示“几分钟内有效”）。
	DownloadTTL time.Duration
}

// UIReportsError 是报告页面适配层返回的稳定公开错误。
type UIReportsError struct{ Code string }

// Error 实现 error。
func (e *UIReportsError) Error() string { return "报告页面操作失败: " + e.Code }

// UIReportPlan 是报告计划页面视图。
type UIReportPlan struct {
	ID                string
	ScheduleID        string
	Version           int64
	Name              string
	Enabled           bool
	PermissionState   string
	PermissionReason  string
	ScheduleType      string
	Expression        string
	TimeZone          string
	PeriodDescription string
	ScopeID           string
	ScopeKind         string
	AppID             string
	Granularity       string
	WindowDays        int
	Categories        []string
	TrendMetric       string
	Formats           []string
	DetailRows        int
	MissedPolicy      string
	MaxCatchUp        int
	TimeoutSeconds    int
	MaxAttempts       int
	Owner             string
	ExecutionActor    string
	NextRun           time.Time
	NextRunUnknown    bool
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// UIReportPlanRequest 是创建/编辑计划请求（所有者由服务端按当前会话决定）。
type UIReportPlanRequest struct {
	Name string
	// ScopeID 是统计范围（system 或应用 ID）；页面按当前视图回填，服务端会同时
	// 校验旧范围与新范围权限，不接受客户端自报越权范围。
	ScopeID        string
	ScheduleType   string
	Expression     string
	TimeZone       string
	Granularity    string
	WindowDays     int
	Categories     []string
	TrendMetric    string
	Formats        []string
	DetailRows     int
	MissedPolicy   string
	MaxCatchUp     int
	TimeoutSeconds int
	MaxAttempts    int
	Enabled        bool
	Reason         string
	Version        int64
}

// UIReportPlanDeletePreview 是删除计划的影响预览。
type UIReportPlanDeletePreview struct {
	PlanID           string
	Name             string
	ScopeID          string
	Enabled          bool
	NextRun          time.Time
	NextRunUnknown   bool
	MissedPolicy     string
	ActiveTasksNote  string
	HistoryNote      string
	RawAuditNote     string
	Irreversible     bool
	PermissionState  string
	PermissionReason string
	CreatedAt        time.Time
	PreviewedAt      time.Time
}

// UIReportHistoryQuery 是历史列表筛选与游标分页。
type UIReportHistoryQuery struct {
	PlanID          string
	State           string
	Limit           int
	BeforeCreatedAt time.Time
	BeforeID        string
	// Cursor 是服务端上一页返回的稳定游标；与 Before* 互斥。
	Cursor string
}

// UIReportHistoryEntry 是历史列表条目。
type UIReportHistoryEntry struct {
	ID            string
	PlanID        string
	Name          string
	ScopeID       string
	ScopeKind     string
	State         string
	Formats       []string
	Owner         string
	TaskID        string
	ErrorCode     string
	FailureReason string
	RequestID     string
	CreatedAt     time.Time
	StartedAt     time.Time
	FinishedAt    time.Time
	ExpiresAt     time.Time
	CleanupState  string
}

// UIReportHistoryPage 是历史列表页。
type UIReportHistoryPage struct {
	Records []UIReportHistoryEntry
	HasMore bool
	// NextCursor 是服务端返回的下一页稳定游标；HasMore=false 时为空。
	NextCursor string
}

// UIReportArtifact 是历史详情中的产物可用性摘要。
type UIReportArtifact struct {
	Format    string
	Bytes     int64
	SHA256    string
	Available bool
	ExpiresAt time.Time
}

// UIReportDetail 是历史报告详情。
type UIReportDetail struct {
	ID                string
	ScopeID           string
	ScopeKind         string
	State             string
	RequestedBy       string
	CreatedAt         time.Time
	StartedAt         time.Time
	FinishedAt        time.Time
	GeneratedAt       time.Time
	OverallStatus     string
	TaskID            string
	ExecutorID        string
	ErrorCode         string
	FailureReason     string
	RequestID         string
	SchemaVersion     string
	TemplateVersion   int
	ArtifactExpiresAt time.Time
	Formats           []string
	Artifacts         []UIReportArtifact
	// RetryOf 是重试来源报告编号（空表示不是重试）。
	RetryOf string
	// Retryable 表示服务端判定该终态允许重试（仅失败/取消/超时）。
	Retryable bool
}

// UIReportCancelResult 是取消请求的真实结果：Accepted 表示请求已受理，不等于任务
// 已实际取消；实际终态仍以服务端报告状态为准。
type UIReportCancelResult struct {
	ReportID string
	Accepted bool
	State    string
	Note     string
}

// UIReportPreview 是历史报告详情的受控预览（同一固定快照，不重新计算第二套数字）。
type UIReportPreview struct {
	ReportID              string
	OverallStatus         string
	GeneratedAt           time.Time
	ActivityTotal         int64
	RawEvents             int64
	FailedRequests        int64
	FailedTasks           int64
	DetailRowCount        int
	Notes                 []string
	WindowWithinRetention bool
	RetentionDays         int
	RetentionConfigured   bool
	MissingReasons        []string
	ScopeTrimmed          bool
	SourceTruncated       bool
	DetailRowsTruncated   bool
	ErrorRows             []UIReportPreviewRow
}

// UIReportPreviewRow 是预览中的受控错误行（不含原始审计正文/秘密）。
type UIReportPreviewRow struct {
	ErrorCode      string
	Category       string
	Severity       string
	RawEvents      int64
	FailedRequests int64
	FailedTasks    int64
	Status         string
}

// UIReportFile 是受控下载文件（只在页面响应体中输出，响应头由页面设置）。
type UIReportFile struct {
	ReportID    string
	Format      string
	FileName    string
	ContentType string
	Bytes       []byte
	Size        int64
	ExpiresAt   time.Time
}

// UIReportRetentionPolicy 是保留策略公开说明。
type UIReportRetentionPolicy struct {
	ArtifactTTL    time.Duration
	CleanupGrace   time.Duration
	EligibleBefore time.Time
	Source         string
	HistoryNote    string
	RawAuditNote   string
}

// UIReportCleanupTarget 是清理预览目标。
type UIReportCleanupTarget struct {
	ReportID      string
	PlanID        string
	Name          string
	ScopeID       string
	State         string
	CleanupState  string
	ExpiresAt     time.Time
	Formats       []string
	ArtifactCount int
	Bytes         int64
}

// UIReportCleanupPreview 是清理预览（不是授权凭证）。
type UIReportCleanupPreview struct {
	Policy          UIReportRetentionPolicy
	Targets         []UIReportCleanupTarget
	TargetCount     int
	TotalBytes      int64
	Scopes          []string
	OldestExpiresAt time.Time
	NewestExpiresAt time.Time
	PreviewedAt     time.Time
	Note            string
}

// UIReportCleanupFailure 是单个目标清理失败的真实原因。
type UIReportCleanupFailure struct {
	ReportID string
	Reason   string
}

// UIReportCleanupResult 是清理真实结果。
type UIReportCleanupResult struct {
	RequestedCount int
	CleanedCount   int
	FailedCount    int
	DeletedFiles   int
	FreedBytes     int64
	SkippedCount   int
	Failures       []UIReportCleanupFailure
	RawAuditNote   string
	StartedAt      time.Time
	FinishedAt     time.Time
}

// UIReportPlanPage 是报告计划分页结果（步骤 218）。
type UIReportPlanPage struct {
	Plans      []UIReportPlan
	HasMore    bool
	NextOffset int
}

// UIReportPlanPagedBackend 是支持报告计划分页的可选后端契约；旧后端仍按 ListPlans
// 全量返回（页面回退且不伪造分页）。
type UIReportPlanPagedBackend interface {
	ListPlansPage(ctx context.Context, userID string, limit, offset int) (UIReportPlanPage, error)
}

// UIPageReportsBackend 是报告管理页面调用真实报告服务的最小契约。适配器负责可信
// Caller 与每次授权；页面层不实现权限判定、不补造状态。
type UIPageReportsBackend interface {
	Capabilities(ctx context.Context, userID string) (UIReportsCapabilities, error)
	RecordDenial(ctx context.Context, userID, reason string) error

	ListPlans(ctx context.Context, userID string) ([]UIReportPlan, error)
	GetPlan(ctx context.Context, userID, planID string) (UIReportPlan, error)
	CreatePlan(ctx context.Context, userID string, request UIReportPlanRequest,
		requestID string) (UIReportPlan, error)
	UpdatePlan(ctx context.Context, userID, planID string, version int64,
		request UIReportPlanRequest, requestID string) (UIReportPlan, error)
	SetPlanEnabled(ctx context.Context, userID, planID string, enabled bool,
		reason, requestID string) (UIReportPlan, error)
	PlanDeletePreview(ctx context.Context, userID,
		planID string) (UIReportPlanDeletePreview, error)
	DeletePlan(ctx context.Context, userID, planID, reason, requestID string) error

	ListHistory(ctx context.Context, userID string,
		query UIReportHistoryQuery) (UIReportHistoryPage, error)
	GetReport(ctx context.Context, userID, reportID string) (UIReportDetail, error)
	Download(ctx context.Context, userID, reportID,
		format string) (UIReportFile, error)
	// Preview 返回已完成报告的受控预览（服务端按当前权限重新授权，缺失数据标记缺失）。
	Preview(ctx context.Context, userID, reportID string) (UIReportPreview, error)
	// Retry 重试失败/取消/超时报告，创建新运行记录并保留原记录；返回新报告详情。
	Retry(ctx context.Context, userID, reportID, reason,
		requestID string) (UIReportDetail, error)
	// Cancel 请求取消进行中的报告任务；返回真实受理状态（不等于已取消）。
	Cancel(ctx context.Context, userID, reportID, reason,
		requestID string) (UIReportCancelResult, error)

	CleanupPreview(ctx context.Context, userID string) (UIReportCleanupPreview, error)
	RunCleanup(ctx context.Context, userID, reason,
		requestID string) (UIReportCleanupResult, error)
}

// UIPageReportsOptions 是步骤 79 报告管理页配置。
type UIPageReportsOptions struct {
	Backend UIPageReportsBackend
	// ValidateCSRF 校验页面表单安全令牌（必须接入 session.ValidateCSRFToken 等
	// 服务器端校验）；缺失时拒绝构造。
	ValidateCSRF func(ctx context.Context, request *http.Request, token string) error
	Now          func() time.Time
}

// newPageReportsPages 构造步骤 79 路由与处理器。
func newPageReportsPages(options UIPageReportsOptions) (*pageReportsPages, error) {
	if isNilUIValue(options.Backend) {
		return nil, fmt.Errorf("报告页面缺少后端适配器")
	}
	if options.ValidateCSRF == nil {
		return nil, fmt.Errorf("报告页面缺少 CSRF 校验器：必须接入服务器端 CSRF 校验")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	pages := &pageReportsPages{handlers: map[string]UIPageHandler{}, options: options}
	handler := &reportsPageHandlers{pages: pages}
	routes := []UIRoute{
		{Name: "admin.reports", Method: http.MethodGet, Path: "/admin/reports",
			Access: UIAccessManagement, Layout: "layout/base",
			Template: "page/admin/report_history"},
		{Name: "admin.report_detail", Method: http.MethodGet, Path: "/admin/reports/detail",
			Access: UIAccessManagement, Layout: "layout/base",
			Template: "page/admin/report_detail"},
		{Name: "admin.report_download", Method: http.MethodPost, Path: "/admin/reports/download",
			Access: UIAccessManagement, Layout: "layout/base",
			Template: "page/admin/report_detail"},
		{Name: "admin.report_retry", Method: http.MethodPost, Path: "/admin/reports/retry",
			Access: UIAccessManagement, Layout: "layout/base",
			Template: "page/admin/report_detail"},
		{Name: "admin.report_cancel", Method: http.MethodPost, Path: "/admin/reports/cancel",
			Access: UIAccessManagement, Layout: "layout/base",
			Template: "page/admin/report_detail"},
		{Name: "admin.report_schedules", Method: http.MethodGet,
			Path: "/admin/reports/schedules", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/report_schedules"},
		{Name: "admin.report_schedule_detail", Method: http.MethodGet,
			Path: "/admin/reports/schedules/detail", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/report_schedule_detail"},
		{Name: "admin.report_schedule_new", Method: http.MethodGet,
			Path: "/admin/reports/schedules/new", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/report_schedule_form"},
		{Name: "admin.report_schedule_create", Method: http.MethodPost,
			Path: "/admin/reports/schedules/create", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/report_schedule_form"},
		{Name: "admin.report_schedule_edit", Method: http.MethodGet,
			Path: "/admin/reports/schedules/edit", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/report_schedule_form"},
		{Name: "admin.report_schedule_update", Method: http.MethodPost,
			Path: "/admin/reports/schedules/update", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/report_schedule_form"},
		{Name: "admin.report_schedule_state", Method: http.MethodPost,
			Path: "/admin/reports/schedules/state", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/report_schedule_detail"},
		{Name: "admin.report_schedule_delete_preview", Method: http.MethodGet,
			Path: "/admin/reports/schedules/delete", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/report_schedule_delete"},
		{Name: "admin.report_schedule_delete", Method: http.MethodPost,
			Path: "/admin/reports/schedules/delete", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/report_schedules"},
		{Name: "admin.report_retention", Method: http.MethodGet,
			Path: "/admin/reports/retention", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/report_retention"},
		{Name: "admin.report_cleanup", Method: http.MethodPost,
			Path: "/admin/reports/cleanup", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/report_retention"},
	}
	for _, route := range routes {
		pages.routes = append(pages.routes, route)
		pages.handlers[route.Name] = handler
	}
	return pages, nil
}

// pageReportsPages 是报告管理页面实现。
type pageReportsPages struct {
	routes   []UIRoute
	handlers map[string]UIPageHandler
	options  UIPageReportsOptions
}

// reportsPageHandlers 实现报告管理页处理器。
type reportsPageHandlers struct{ pages *pageReportsPages }

// HandlePage 按路由分派。
func (h *reportsPageHandlers) HandlePage(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	switch page.RouteName {
	case "admin.reports":
		return h.historyList(ctx, request, page)
	case "admin.report_detail":
		return h.reportDetail(ctx, request, page)
	case "admin.report_download":
		return h.download(ctx, request, page)
	case "admin.report_retry":
		return h.retry(ctx, request, page)
	case "admin.report_cancel":
		return h.cancelReport(ctx, request, page)
	case "admin.report_schedules":
		return h.planList(ctx, request, page)
	case "admin.report_schedule_detail":
		return h.planDetail(ctx, request, page)
	case "admin.report_schedule_new":
		return h.planForm(ctx, request, page, false)
	case "admin.report_schedule_create":
		return h.planCreate(ctx, request, page)
	case "admin.report_schedule_edit":
		return h.planForm(ctx, request, page, true)
	case "admin.report_schedule_update":
		return h.planUpdate(ctx, request, page)
	case "admin.report_schedule_state":
		return h.planState(ctx, request, page)
	case "admin.report_schedule_delete_preview":
		return h.planDeletePreview(ctx, request, page)
	case "admin.report_schedule_delete":
		return h.planDelete(ctx, request, page)
	case "admin.report_retention":
		return h.retention(ctx, request, page)
	case "admin.report_cleanup":
		return h.cleanup(ctx, request, page)
	default:
		return UIPageOutcome{}, nil
	}
}

// reportsCapabilities 读取能力位；失败时全部 false（fail-closed，只影响呈现）。
func (h *reportsPageHandlers) reportsCapabilities(ctx context.Context,
	page UIPageContext) UIReportsCapabilities {
	caps, err := h.pages.options.Backend.Capabilities(ctx, page.Session.UserID)
	if err != nil {
		return UIReportsCapabilities{}
	}
	return caps
}

// recordDenial 尽力记录页面级拒绝；失败不改变拒绝结果。
func (h *reportsPageHandlers) recordDenial(ctx context.Context, page UIPageContext,
	reason string) {
	_ = h.pages.options.Backend.RecordDenial(ctx, page.Session.UserID, reason)
}

// checkCSRF 校验 POST 表单安全令牌。
func (h *reportsPageHandlers) checkCSRF(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, bool) {
	if err := request.ParseForm(); err != nil {
		h.recordDenial(ctx, page, "form_parse_failed")
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: reportsText("page.admin.reports.common.invalid_form")}, false
	}
	token := strings.TrimSpace(request.PostForm.Get(page.CSRFField))
	if token == "" || page.CSRF == "" ||
		subtle.ConstantTimeCompare([]byte(token), []byte(page.CSRF)) != 1 {
		h.recordDenial(ctx, page, "csrf_invalid")
		return UIPageOutcome{StatusCode: http.StatusForbidden,
			ErrorSummary: reportsText("page.admin.reports.common.csrf_invalid")}, false
	}
	if err := h.pages.options.ValidateCSRF(ctx, request, token); err != nil {
		h.recordDenial(ctx, page, "csrf_invalid")
		return UIPageOutcome{StatusCode: http.StatusForbidden,
			ErrorSummary: reportsText("page.admin.reports.common.csrf_invalid")}, false
	}
	return UIPageOutcome{}, true
}

// reportsStatus 把适配器错误映射为 HTTP 状态与公开摘要。
func reportsStatus(err error) (int, string) {
	var reportsErr *UIReportsError
	if !errorsAs(err, &reportsErr) || reportsErr == nil {
		return http.StatusServiceUnavailable,
			reportsText("page.admin.reports.common.load_failed")
	}
	switch reportsErr.Code {
	case "ACCESS_DENIED":
		return http.StatusForbidden, reportsText("page.admin.reports.common.forbidden")
	case "NOT_FOUND":
		return http.StatusNotFound, reportsText("page.admin.reports.common.not_found")
	case "CONFLICT":
		return http.StatusConflict, reportsText("page.admin.reports.common.conflict")
	case "INVALID":
		return http.StatusBadRequest, reportsText("page.admin.reports.common.invalid_form")
	default:
		return http.StatusServiceUnavailable,
			reportsText("page.admin.reports.common.load_failed")
	}
}

// errorsAs 是本文件的局部 errors.As 替代（避免与 crypto/subtle 导入混淆）。
func errorsAs(err error, target **UIReportsError) bool {
	for err != nil {
		if typed, ok := err.(*UIReportsError); ok {
			*target = typed
			return true
		}
		type unwrapper interface{ Unwrap() error }
		if wrapped, ok := err.(unwrapper); ok {
			err = wrapped.Unwrap()
			continue
		}
		return false
	}
	return false
}

// reportsText 返回报告页服务端摘要文案（zh-CN 基线；模板静态文案走 i18n 目录）。
func reportsText(key string) string {
	if message, ok := reportSummaryText[key]; ok {
		return message
	}
	return key
}

// reportSummaryText 是报告页服务端摘要的中文基线。
var reportSummaryText = map[string]string{
	"page.admin.reports.common.invalid_form":  "表单内容不完整或格式不正确，请检查后重试",
	"page.admin.reports.common.csrf_invalid":  "表单安全令牌无效或已过期，请刷新页面后重试",
	"page.admin.reports.common.forbidden":     "当前会话无权执行该报告操作",
	"page.admin.reports.common.not_found":     "报告或计划不存在，或当前会话无权查看",
	"page.admin.reports.common.conflict":      "对象状态或行版本已变化，请重新读取后再操作",
	"page.admin.reports.common.load_failed":   "报告服务暂时不可用，请稍后重试",
	"page.admin.reports.common.download_fail": "下载未获准或产物已过期/已清理",
}

// reportsBaseData 构造所有报告页共用的基础数据与错误/状态位。
func (h *reportsPageHandlers) reportsBaseData(page UIPageContext,
	caps UIReportsCapabilities) map[string]any {
	return map[string]any{
		"capabilities": caps, "forbidden": false, "loadFailed": false,
		"timezone": page.TimeZone, "now": h.pages.options.Now(),
		"reportsURL":    routeURL(page, "admin.reports"),
		"schedulesURL":  routeURL(page, "admin.report_schedules"),
		"retentionURL":  routeURL(page, "admin.report_retention"),
		"newPlanURL":    routeURL(page, "admin.report_schedule_new"),
		"formatOptions": UIReportsFormats(), "timezoneOptions": UIReportsTimeZones(),
		"scheduleTypeOptions": UIReportsScheduleTypes(),
		"granularityOptions":  UIReportsGranularities(),
		"missedPolicyOptions": UIReportsMissedPolicies(),
		"categoryOptions":     UIReportsCategories(),
		"metricOptions":       UIReportsMetrics(),
		"stateOptions":        UIReportsStateValues(),
		"downloadTTLMinutes":  int(caps.DownloadTTL.Minutes()),
	}
}

// routeURL 生成站内命名路由的相对 URL（框架加 BasePath）。
func routeURL(page UIPageContext, name string) string {
	return page.BasePath + "/" + strings.TrimPrefix(routePaths[name], "/")
}

// routePaths 是报告页路由静态路径（与 newPageReportsPages 一致；仅用于链接生成）。
var routePaths = map[string]string{
	"admin.reports":             "/admin/reports",
	"admin.report_schedules":    "/admin/reports/schedules",
	"admin.report_retention":    "/admin/reports/retention",
	"admin.report_schedule_new": "/admin/reports/schedules/new",
}

// historyList 渲染历史报告列表。
func (h *reportsPageHandlers) historyList(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	caps := h.reportsCapabilities(ctx, page)
	data := h.reportsBaseData(page, caps)
	if !caps.Read {
		h.recordDenial(ctx, page, "reports_read_denied")
		data["forbidden"] = true
		return UIPageOutcome{StatusCode: http.StatusForbidden, Data: data,
			ErrorSummary: reportsText("page.admin.reports.common.forbidden")}, nil
	}
	values := request.URL.Query()
	query := UIReportHistoryQuery{
		PlanID: strings.TrimSpace(values.Get("plan_id")),
		State:  strings.TrimSpace(values.Get("state")),
		Limit:  20,
	}
	if rawLimit := strings.TrimSpace(values.Get("limit")); rawLimit != "" {
		if limit, err := strconv.Atoi(rawLimit); err == nil && limit >= 1 && limit <= 100 {
			query.Limit = limit
		}
	}
	if !validReportHistoryState(query.State) {
		data["invalid"] = true
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
			ErrorSummary: reportsText("page.admin.reports.history.filter_invalid")}, nil
	}
	data["filter"] = map[string]string{"plan_id": query.PlanID, "state": query.State}
	cursor := strings.TrimSpace(values.Get("cursor"))
	if cursor != "" {
		if len(cursor) > 4096 || strings.TrimSpace(values.Get("before")) != "" {
			data["invalid"] = true
			return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
				ErrorSummary: reportsText("page.admin.reports.history.filter_invalid")}, nil
		}
		query.Cursor = cursor
	} else if before := strings.TrimSpace(values.Get("before")); before != "" {
		if moment, err := time.Parse(time.RFC3339Nano, before); err == nil {
			query.BeforeCreatedAt = moment.UTC()
			query.BeforeID = strings.TrimSpace(values.Get("before_id"))
		}
	}
	result, err := h.pages.options.Backend.ListHistory(ctx, page.Session.UserID, query)
	if err != nil {
		status, summary := reportsStatus(err)
		data["loadFailed"] = true
		return UIPageOutcome{StatusCode: status, Data: data,
			ErrorSummary: summary}, nil
	}
	data["reports"] = result.Records
	data["hasMore"] = result.HasMore
	data["empty"] = len(result.Records) == 0 && !result.HasMore
	if result.HasMore && result.NextCursor != "" {
		more := url.Values{}
		more.Set("cursor", result.NextCursor)
		if query.State != "" {
			more.Set("state", query.State)
		}
		if query.PlanID != "" {
			more.Set("plan_id", query.PlanID)
		}
		data["moreURL"] = routeURL(page, "admin.reports") + "?" + more.Encode()
	} else if result.HasMore && len(result.Records) > 0 {
		last := result.Records[len(result.Records)-1]
		more := url.Values{}
		more.Set("before", last.CreatedAt.UTC().Format(time.RFC3339Nano))
		more.Set("before_id", last.ID)
		if query.State != "" {
			more.Set("state", query.State)
		}
		if query.PlanID != "" {
			more.Set("plan_id", query.PlanID)
		}
		data["moreURL"] = routeURL(page, "admin.reports") + "?" + more.Encode()
	}
	data["planFilter"] = query.PlanID
	data["stateFilter"] = query.State
	return UIPageOutcome{Data: data}, nil
}

// validReportHistoryState 校验历史状态筛选白名单。
func validReportHistoryState(state string) bool {
	if state == "" {
		return true
	}
	for _, candidate := range UIReportsStateValues() {
		if candidate == state {
			return true
		}
	}
	return false
}

// reportDetail 渲染历史报告详情与可用下载入口。
func (h *reportsPageHandlers) reportDetail(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	caps := h.reportsCapabilities(ctx, page)
	data := h.reportsBaseData(page, caps)
	if !caps.Read {
		h.recordDenial(ctx, page, "reports_read_denied")
		data["forbidden"] = true
		return UIPageOutcome{StatusCode: http.StatusForbidden, Data: data,
			ErrorSummary: reportsText("page.admin.reports.common.forbidden")}, nil
	}
	reportID := strings.TrimSpace(request.URL.Query().Get("report_id"))
	if reportID == "" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
			ErrorSummary: reportsText("page.admin.reports.history.filter_invalid")}, nil
	}
	detail, err := h.pages.options.Backend.GetReport(ctx, page.Session.UserID, reportID)
	if err != nil {
		status, summary := reportsStatus(err)
		data["loadFailed"] = true
		data["reportID"] = reportID
		return UIPageOutcome{StatusCode: status, Data: data,
			ErrorSummary: summary}, nil
	}
	data["report"] = detail
	data["reportID"] = detail.ID
	detail.Retryable = detail.State == "failed" || detail.State == "cancelled" ||
		detail.State == "timed_out"
	data["retryable"] = detail.Retryable
	data["cancelable"] = detail.State == "queued" || detail.State == "running"
	data["cancelRequested"] = detail.State == "cancel_requested"
	if detail.State == "succeeded" {
		preview, previewErr := h.pages.options.Backend.Preview(ctx,
			page.Session.UserID, detail.ID)
		if previewErr != nil {
			data["previewFailed"] = true
		} else {
			data["preview"] = preview
		}
	}
	data["downloadPath"] = page.BasePath + "/admin/reports/download"
	data["succeeded"] = detail.State == "succeeded"
	return UIPageOutcome{Data: data}, nil
}

// download 以一次性短期令牌兑换方式输出受控产物，响应禁止缓存与 Referer 传递。
func (h *reportsPageHandlers) download(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	if outcome, ok := h.checkCSRF(ctx, request, page); !ok {
		return outcome, nil
	}
	if !h.reportsCapabilities(ctx, page).Export {
		h.recordDenial(ctx, page, "reports_export_denied")
		return UIPageOutcome{StatusCode: http.StatusForbidden,
			ErrorSummary: reportsText("page.admin.reports.common.forbidden")}, nil
	}
	reportID := strings.TrimSpace(request.PostForm.Get("report_id"))
	format := strings.TrimSpace(request.PostForm.Get("format"))
	file, err := h.pages.options.Backend.Download(ctx, page.Session.UserID,
		reportID, format)
	if err != nil {
		status, summary := reportsStatus(err)
		if status == http.StatusConflict {
			summary = reportsText("page.admin.reports.common.download_fail")
		}
		return UIPageOutcome{StatusCode: status, ErrorSummary: summary}, nil
	}
	headers := http.Header{}
	headers.Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
	headers.Set("Pragma", "no-cache")
	headers.Set("Referrer-Policy", "no-referrer")
	headers.Set("X-Content-Type-Options", "nosniff")
	headers.Set("Content-Disposition",
		`attachment; filename="`+sanitizeDownloadFilename(file.FileName)+`"`)
	headers.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	return UIPageOutcome{StatusCode: http.StatusOK, ContentType: file.ContentType,
		Body: file.Bytes, Headers: headers, Data: nil}, nil
}

// retry 处理历史报告重试 POST：CSRF、当前权限、敏感操作由领域服务完成，成功
// 后跳转到新运行记录详情；原记录保持真实状态。
func (h *reportsPageHandlers) retry(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	caps := h.reportsCapabilities(ctx, page)
	data := h.reportsBaseData(page, caps)
	if !caps.Read || !caps.Generate || !caps.Export {
		h.recordDenial(ctx, page, "reports_retry_denied")
		data["forbidden"] = true
		return UIPageOutcome{StatusCode: http.StatusForbidden, Data: data,
			ErrorSummary: reportsText("page.admin.reports.common.forbidden")}, nil
	}
	if outcome, ok := h.checkCSRF(ctx, request, page); !ok {
		return outcome, nil
	}
	reportID := strings.TrimSpace(request.PostForm.Get("report_id"))
	reason := strings.TrimSpace(request.PostForm.Get("reason"))
	if reason == "" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
			ErrorSummary: reportsText("page.admin.reports.form.reason_required")}, nil
	}
	detail, err := h.pages.options.Backend.Retry(ctx, page.Session.UserID,
		reportID, reason, page.RequestID)
	if err != nil {
		status, summary := reportsStatus(err)
		data["loadFailed"] = true
		return UIPageOutcome{StatusCode: status, Data: data,
			ErrorSummary: summary}, nil
	}
	return UIPageOutcome{RedirectPath: "/admin/reports/detail",
		RedirectQuery: url.Values{"report_id": {detail.ID}}}, nil
}

// cancelReport 处理取消进行中报告的 POST：CSRF、原因必填；取消请求受理不等于
// 实际取消，页面返回服务端真实受理状态与刷新后的报告状态。
func (h *reportsPageHandlers) cancelReport(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	caps := h.reportsCapabilities(ctx, page)
	data := h.reportsBaseData(page, caps)
	if !caps.Read || !caps.Generate {
		h.recordDenial(ctx, page, "reports_cancel_denied")
		data["forbidden"] = true
		return UIPageOutcome{StatusCode: http.StatusForbidden, Data: data,
			ErrorSummary: reportsText("page.admin.reports.common.forbidden")}, nil
	}
	if outcome, ok := h.checkCSRF(ctx, request, page); !ok {
		return outcome, nil
	}
	reportID := strings.TrimSpace(request.PostForm.Get("report_id"))
	reason := strings.TrimSpace(request.PostForm.Get("reason"))
	if reason == "" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
			ErrorSummary: reportsText("page.admin.reports.form.reason_required")}, nil
	}
	result, err := h.pages.options.Backend.Cancel(ctx, page.Session.UserID,
		reportID, reason, page.RequestID)
	if err != nil {
		status, summary := reportsStatus(err)
		data["loadFailed"] = true
		return UIPageOutcome{StatusCode: status, Data: data,
			ErrorSummary: summary}, nil
	}
	data["cancelResult"] = result
	detail, detailErr := h.pages.options.Backend.GetReport(ctx,
		page.Session.UserID, reportID)
	if detailErr == nil {
		data["report"] = detail
		data["reportID"] = detail.ID
		data["cancelable"] = detail.State == "queued" || detail.State == "running"
		data["cancelRequested"] = detail.State == "cancel_requested"
	}
	return UIPageOutcome{Data: data}, nil
}

// sanitizeDownloadFilename 只保留安全文件名字符。
func sanitizeDownloadFilename(name string) string {
	var builder strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			builder.WriteRune(r)
		}
	}
	result := builder.String()
	if result == "" || strings.HasPrefix(result, ".") {
		return "report.bin"
	}
	return result
}

// planList 渲染报告计划列表。
func (h *reportsPageHandlers) planList(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	caps := h.reportsCapabilities(ctx, page)
	data := h.reportsBaseData(page, caps)
	if !caps.Read {
		h.recordDenial(ctx, page, "reports_read_denied")
		data["forbidden"] = true
		return UIPageOutcome{StatusCode: http.StatusForbidden, Data: data,
			ErrorSummary: reportsText("page.admin.reports.common.forbidden")}, nil
	}
	limit, offset := 20, 0
	if raw := strings.TrimSpace(request.URL.Query().Get("limit")); raw != "" {
		if parsed, parseErr := strconv.Atoi(raw); parseErr == nil && parsed >= 1 && parsed <= 100 {
			limit = parsed
		}
	}
	if raw := strings.TrimSpace(request.URL.Query().Get("offset")); raw != "" {
		if parsed, parseErr := strconv.Atoi(raw); parseErr == nil && parsed >= 0 && parsed <= 1_000_000 {
			offset = parsed
		}
	}
	if paged, ok := h.pages.options.Backend.(UIReportPlanPagedBackend); ok {
		result, pageErr := paged.ListPlansPage(ctx, page.Session.UserID, limit, offset)
		if pageErr != nil {
			status, summary := reportsStatus(pageErr)
			data["loadFailed"] = true
			return UIPageOutcome{StatusCode: status, Data: data,
				ErrorSummary: summary}, nil
		}
		data["plans"] = result.Plans
		data["empty"] = len(result.Plans) == 0 && !result.HasMore
		data["hasMore"] = result.HasMore
		data["nextOffset"] = result.NextOffset
		data["offset"] = offset
		data["limit"] = limit
		data["canManage"] = caps.ScheduleManage
		return UIPageOutcome{Data: data}, nil
	}
	plans, err := h.pages.options.Backend.ListPlans(ctx, page.Session.UserID)
	if err != nil {
		status, summary := reportsStatus(err)
		data["loadFailed"] = true
		return UIPageOutcome{StatusCode: status, Data: data,
			ErrorSummary: summary}, nil
	}
	data["plans"] = plans
	data["empty"] = len(plans) == 0
	data["canManage"] = caps.ScheduleManage
	return UIPageOutcome{Data: data}, nil
}

// planDetail 渲染计划详情、最近执行与启停/删除入口。
func (h *reportsPageHandlers) planDetail(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	caps := h.reportsCapabilities(ctx, page)
	data := h.reportsBaseData(page, caps)
	if !caps.Read {
		h.recordDenial(ctx, page, "reports_read_denied")
		data["forbidden"] = true
		return UIPageOutcome{StatusCode: http.StatusForbidden, Data: data,
			ErrorSummary: reportsText("page.admin.reports.common.forbidden")}, nil
	}
	planID := strings.TrimSpace(request.URL.Query().Get("plan_id"))
	plan, err := h.pages.options.Backend.GetPlan(ctx, page.Session.UserID, planID)
	if err != nil {
		status, summary := reportsStatus(err)
		data["loadFailed"] = true
		return UIPageOutcome{StatusCode: status, Data: data,
			ErrorSummary: summary}, nil
	}
	data["plan"] = plan
	data["canManage"] = caps.ScheduleManage
	runs, runErr := h.pages.options.Backend.ListHistory(ctx, page.Session.UserID,
		UIReportHistoryQuery{PlanID: plan.ID, Limit: 20})
	if runErr == nil {
		data["runs"] = runs.Records
	} else {
		data["runsLoadFailed"] = true
	}
	return UIPageOutcome{Data: data}, nil
}

// planForm 渲染创建/编辑计划表单。
func (h *reportsPageHandlers) planForm(ctx context.Context, request *http.Request,
	page UIPageContext, editing bool) (UIPageOutcome, error) {
	caps := h.reportsCapabilities(ctx, page)
	data := h.reportsBaseData(page, caps)
	if !caps.ScheduleManage || !caps.Read {
		h.recordDenial(ctx, page, "reports_schedule_manage_denied")
		data["forbidden"] = true
		return UIPageOutcome{StatusCode: http.StatusForbidden, Data: data,
			ErrorSummary: reportsText("page.admin.reports.common.forbidden")}, nil
	}
	data["editing"] = editing
	form := UIReportPlanRequest{Name: "", ScopeID: "system",
		ScheduleType: "daily", Expression: "09:00", TimeZone: "Asia/Shanghai",
		Granularity: "day",
		WindowDays:  1, Formats: []string{"html"}, MissedPolicy: "latest",
		MaxCatchUp: 1, TimeoutSeconds: 600, MaxAttempts: 1, DetailRows: 20,
		Enabled: false}
	if editing {
		planID := strings.TrimSpace(request.URL.Query().Get("plan_id"))
		plan, err := h.pages.options.Backend.GetPlan(ctx, page.Session.UserID, planID)
		if err != nil {
			status, summary := reportsStatus(err)
			data["loadFailed"] = true
			return UIPageOutcome{StatusCode: status, Data: data,
				ErrorSummary: summary}, nil
		}
		data["plan"] = plan
		data["planID"] = planID
		form = planRequestFromPlan(plan)
	}
	data["form"] = form
	data["downloadTTLMinutes"] = int(caps.DownloadTTL.Minutes())
	return UIPageOutcome{Data: data}, nil
}

// planRequestFromPlan 把已有计划转换为表单回显请求。
func planRequestFromPlan(plan UIReportPlan) UIReportPlanRequest {
	return UIReportPlanRequest{
		Name: plan.Name, ScheduleType: plan.ScheduleType,
		Expression: plan.Expression, TimeZone: plan.TimeZone,
		Granularity: plan.Granularity, WindowDays: plan.WindowDays,
		Categories: plan.Categories, TrendMetric: plan.TrendMetric,
		Formats: plan.Formats, DetailRows: plan.DetailRows,
		MissedPolicy: plan.MissedPolicy, MaxCatchUp: plan.MaxCatchUp,
		TimeoutSeconds: plan.TimeoutSeconds, MaxAttempts: plan.MaxAttempts,
		ScopeID: plan.ScopeID, Enabled: plan.Enabled, Version: plan.Version,
	}
}

// parsePlanForm 解析并校验计划表单（字段级白名单）；失败返回字段错误。
func parsePlanForm(values url.Values) (UIReportPlanRequest, map[string]string) {
	form := UIReportPlanRequest{
		Name:         strings.TrimSpace(values.Get("name")),
		ScopeID:      strings.TrimSpace(values.Get("scope_id")),
		ScheduleType: strings.TrimSpace(values.Get("schedule_type")),
		Expression:   strings.TrimSpace(values.Get("expression")),
		TimeZone:     strings.TrimSpace(values.Get("time_zone")),
		Granularity:  strings.TrimSpace(values.Get("granularity")),
		TrendMetric:  strings.TrimSpace(values.Get("trend_metric")),
		MissedPolicy: strings.TrimSpace(values.Get("missed_policy")),
		Formats:      values["formats"], Categories: values["categories"],
		Reason:  strings.TrimSpace(values.Get("reason")),
		Enabled: values.Get("enabled") == "1" || values.Get("enabled") == "on",
	}
	errors := map[string]string{}
	if len([]rune(form.Name)) < 1 || len([]rune(form.Name)) > 120 {
		errors["name"] = "page.admin.reports.form.name_invalid"
	}
	if !containsUIDefault(UIReportsScheduleTypes(), form.ScheduleType) {
		errors["schedule_type"] = "page.admin.reports.form.schedule_type_invalid"
	}
	if form.Expression == "" || len(form.Expression) > 128 {
		errors["expression"] = "page.admin.reports.form.expression_invalid"
	}
	if !containsUIDefault(UIReportsTimeZones(), form.TimeZone) {
		errors["time_zone"] = "page.admin.reports.form.time_zone_invalid"
	}
	if !containsUIDefault(UIReportsGranularities(), form.Granularity) {
		errors["granularity"] = "page.admin.reports.form.granularity_invalid"
	}
	if len(form.Formats) == 0 {
		errors["formats"] = "page.admin.reports.form.formats_required"
	}
	for _, format := range form.Formats {
		if !containsUIDefault(UIReportsFormats(), format) {
			errors["formats"] = "page.admin.reports.form.formats_invalid"
		}
	}
	if form.TrendMetric != "" && !containsUIDefault(UIReportsMetrics(), form.TrendMetric) {
		errors["trend_metric"] = "page.admin.reports.form.metric_invalid"
	}
	if !containsUIDefault(UIReportsMissedPolicies(), form.MissedPolicy) {
		errors["missed_policy"] = "page.admin.reports.form.missed_policy_invalid"
	}
	for _, category := range form.Categories {
		if !containsUIDefault(UIReportsCategories(), category) {
			errors["categories"] = "page.admin.reports.form.category_invalid"
		}
	}
	form.WindowDays = parseBoundedInt(values.Get("window_days"), 1, 90, 1)
	form.DetailRows = parseBoundedInt(values.Get("detail_rows"), 1, 200, 20)
	form.MaxCatchUp = parseBoundedInt(values.Get("max_catch_up"), 1, 1000, 1)
	form.TimeoutSeconds = parseBoundedInt(values.Get("timeout_seconds"), 10, 3600, 600)
	form.MaxAttempts = parseBoundedInt(values.Get("max_attempts"), 1, 10, 1)
	if rawVersion := strings.TrimSpace(values.Get("version")); rawVersion != "" {
		if version, err := strconv.ParseInt(rawVersion, 10, 64); err == nil && version >= 0 {
			form.Version = version
		}
	}
	return form, errors
}

// containsUIDefault 判断稳定值是否在受控白名单内。
func containsUIDefault(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// parseBoundedInt 解析有界整数；非法时回退默认值。
func parseBoundedInt(raw string, minimum, maximum, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value < minimum || value > maximum {
		return fallback
	}
	return value
}

// planCreate 处理创建计划 POST。
func (h *reportsPageHandlers) planCreate(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	caps := h.reportsCapabilities(ctx, page)
	data := h.reportsBaseData(page, caps)
	if !caps.ScheduleManage || !caps.Read {
		h.recordDenial(ctx, page, "reports_schedule_manage_denied")
		data["forbidden"] = true
		return UIPageOutcome{StatusCode: http.StatusForbidden, Data: data,
			ErrorSummary: reportsText("page.admin.reports.common.forbidden")}, nil
	}
	if outcome, ok := h.checkCSRF(ctx, request, page); !ok {
		return outcome, nil
	}
	form, fieldErrors := parsePlanForm(request.PostForm)
	if len(fieldErrors) > 0 {
		data["editing"] = false
		data["form"] = form
		data["fieldErrors"] = fieldErrors
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
			FieldErrors:  fieldErrors,
			ErrorSummary: reportsText("page.admin.reports.common.invalid_form")}, nil
	}
	created, err := h.pages.options.Backend.CreatePlan(ctx, page.Session.UserID,
		form, page.RequestID)
	if err != nil {
		status, summary := reportsStatus(err)
		data["editing"] = false
		data["form"] = form
		return UIPageOutcome{StatusCode: status, Data: data,
			ErrorSummary: summary}, nil
	}
	return UIPageOutcome{RedirectPath: "/admin/reports/schedules/detail",
		RedirectQuery: url.Values{"plan_id": {created.ID}}}, nil
}

// planUpdate 处理编辑计划 POST（携带行版本）。
func (h *reportsPageHandlers) planUpdate(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	caps := h.reportsCapabilities(ctx, page)
	data := h.reportsBaseData(page, caps)
	if !caps.ScheduleManage || !caps.Read {
		h.recordDenial(ctx, page, "reports_schedule_manage_denied")
		data["forbidden"] = true
		return UIPageOutcome{StatusCode: http.StatusForbidden, Data: data,
			ErrorSummary: reportsText("page.admin.reports.common.forbidden")}, nil
	}
	if outcome, ok := h.checkCSRF(ctx, request, page); !ok {
		return outcome, nil
	}
	planID := strings.TrimSpace(request.PostForm.Get("plan_id"))
	form, fieldErrors := parsePlanForm(request.PostForm)
	if len(fieldErrors) > 0 {
		data["editing"] = true
		data["form"] = form
		data["planID"] = planID
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
			FieldErrors:  fieldErrors,
			ErrorSummary: reportsText("page.admin.reports.common.invalid_form")}, nil
	}
	updated, err := h.pages.options.Backend.UpdatePlan(ctx, page.Session.UserID,
		planID, form.Version, form, page.RequestID)
	if err != nil {
		status, summary := reportsStatus(err)
		data["editing"] = true
		data["form"] = form
		data["planID"] = planID
		return UIPageOutcome{StatusCode: status, Data: data,
			ErrorSummary: summary}, nil
	}
	return UIPageOutcome{RedirectPath: "/admin/reports/schedules/detail",
		RedirectQuery: url.Values{"plan_id": {updated.ID}}}, nil
}

// planState 处理启用/停用计划 POST。
func (h *reportsPageHandlers) planState(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	if !h.reportsCapabilities(ctx, page).ScheduleManage {
		h.recordDenial(ctx, page, "reports_schedule_manage_denied")
		return UIPageOutcome{StatusCode: http.StatusForbidden,
			ErrorSummary: reportsText("page.admin.reports.common.forbidden")}, nil
	}
	if outcome, ok := h.checkCSRF(ctx, request, page); !ok {
		return outcome, nil
	}
	planID := strings.TrimSpace(request.PostForm.Get("plan_id"))
	enable := request.PostForm.Get("enabled") == "1" || request.PostForm.Get("enabled") == "on"
	reason := strings.TrimSpace(request.PostForm.Get("reason"))
	if reason == "" {
		if enable {
			reason = "页面启用计划"
		} else {
			reason = "页面停用计划"
		}
	}
	if _, err := h.pages.options.Backend.SetPlanEnabled(ctx, page.Session.UserID,
		planID, enable, reason, page.RequestID); err != nil {
		status, summary := reportsStatus(err)
		return UIPageOutcome{StatusCode: status,
			ErrorSummary: summary}, nil
	}
	return UIPageOutcome{RedirectPath: "/admin/reports/schedules/detail",
		RedirectQuery: url.Values{"plan_id": {planID}}}, nil
}

// planDeletePreview 渲染删除计划影响预览。
func (h *reportsPageHandlers) planDeletePreview(ctx context.Context,
	request *http.Request, page UIPageContext) (UIPageOutcome, error) {
	caps := h.reportsCapabilities(ctx, page)
	data := h.reportsBaseData(page, caps)
	if !caps.ScheduleManage || !caps.Read {
		h.recordDenial(ctx, page, "reports_schedule_manage_denied")
		data["forbidden"] = true
		return UIPageOutcome{StatusCode: http.StatusForbidden, Data: data,
			ErrorSummary: reportsText("page.admin.reports.common.forbidden")}, nil
	}
	planID := strings.TrimSpace(request.URL.Query().Get("plan_id"))
	preview, err := h.pages.options.Backend.PlanDeletePreview(ctx,
		page.Session.UserID, planID)
	if err != nil {
		status, summary := reportsStatus(err)
		data["loadFailed"] = true
		return UIPageOutcome{StatusCode: status, Data: data,
			ErrorSummary: summary}, nil
	}
	data["preview"] = preview
	return UIPageOutcome{Data: data}, nil
}

// planDelete 处理删除计划 POST（预览不是授权）。
func (h *reportsPageHandlers) planDelete(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	if !h.reportsCapabilities(ctx, page).ScheduleManage {
		h.recordDenial(ctx, page, "reports_schedule_manage_denied")
		return UIPageOutcome{StatusCode: http.StatusForbidden,
			ErrorSummary: reportsText("page.admin.reports.common.forbidden")}, nil
	}
	if outcome, ok := h.checkCSRF(ctx, request, page); !ok {
		return outcome, nil
	}
	planID := strings.TrimSpace(request.PostForm.Get("plan_id"))
	reason := strings.TrimSpace(request.PostForm.Get("reason"))
	if reason == "" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: reportsText("page.admin.reports.form.reason_required")}, nil
	}
	if err := h.pages.options.Backend.DeletePlan(ctx, page.Session.UserID,
		planID, reason, page.RequestID); err != nil {
		status, summary := reportsStatus(err)
		return UIPageOutcome{StatusCode: status, ErrorSummary: summary}, nil
	}
	return UIPageOutcome{RedirectPath: "/admin/reports/schedules"}, nil
}

// retention 渲染保留策略说明与清理预览。
func (h *reportsPageHandlers) retention(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	caps := h.reportsCapabilities(ctx, page)
	data := h.reportsBaseData(page, caps)
	if !caps.Read {
		h.recordDenial(ctx, page, "reports_read_denied")
		data["forbidden"] = true
		return UIPageOutcome{StatusCode: http.StatusForbidden, Data: data,
			ErrorSummary: reportsText("page.admin.reports.common.forbidden")}, nil
	}
	preview, err := h.pages.options.Backend.CleanupPreview(ctx, page.Session.UserID)
	if err != nil {
		status, summary := reportsStatus(err)
		data["loadFailed"] = true
		return UIPageOutcome{StatusCode: status, Data: data,
			ErrorSummary: summary}, nil
	}
	data["policy"] = preview.Policy
	data["preview"] = preview
	data["canCleanup"] = caps.Cleanup
	return UIPageOutcome{Data: data}, nil
}

// cleanup 执行报告文件清理（强认证由领域服务完成，确认框不是授权）。
func (h *reportsPageHandlers) cleanup(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	caps := h.reportsCapabilities(ctx, page)
	data := h.reportsBaseData(page, caps)
	if !caps.Cleanup {
		h.recordDenial(ctx, page, "reports_cleanup_denied")
		data["forbidden"] = true
		return UIPageOutcome{StatusCode: http.StatusForbidden, Data: data,
			ErrorSummary: reportsText("page.admin.reports.common.forbidden")}, nil
	}
	if outcome, ok := h.checkCSRF(ctx, request, page); !ok {
		return outcome, nil
	}
	reason := strings.TrimSpace(request.PostForm.Get("reason"))
	if reason == "" {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: reportsText("page.admin.reports.form.reason_required")}, nil
	}
	result, err := h.pages.options.Backend.RunCleanup(ctx, page.Session.UserID,
		reason, page.RequestID)
	if err != nil {
		status, summary := reportsStatus(err)
		data["loadFailed"] = true
		data["result"] = result
		return UIPageOutcome{StatusCode: status, Data: data,
			ErrorSummary: summary}, nil
	}
	data["result"] = result
	preview, previewErr := h.pages.options.Backend.CleanupPreview(ctx,
		page.Session.UserID)
	if previewErr == nil {
		data["policy"] = preview.Policy
		data["preview"] = preview
	}
	return UIPageOutcome{Data: data}, nil
}
