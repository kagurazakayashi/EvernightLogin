package login

// 步骤 81：备份计划、备份任务、历史备份、独立下载、保留策略与清理管理页面（ui.v1）。
//
// 安全不变量：
//   - 全部路由 UIAccessManagement：由宿主 UISessionService 用真实管理会话判定；页面
//     能力位只影响呈现，每次读取/写入/下载/清理/取消都由适配器重建可信 Caller 交给
//     internal/backupadmin 重新授权（backups.read/create/cancel/export/retention/
//     cleanup），下载与清理另需再次认证。
//   - 所有状态变更使用 POST 并校验与会话绑定的页面 CSRF 令牌；下载响应 no-store、
//     no-referrer、nosniff，不提供公开分享或永久链接。
//   - 页面只显示服务端返回的真实状态：取消请求已接受不等于已取消，任务完成不等于
//     产物存在/校验通过，通知失败不改变备份事实，恢复功能仍显示“尚未实现”。
//   - 保留策略保存与清理严格分开；清理预览不是删除授权，页面明确“不删除原始审计”。

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// UIBackupTimeZones 是计划编辑页提供的受控时区白名单。
func UIBackupTimeZones() []string {
	return []string{"UTC", "Asia/Shanghai", "Asia/Tokyo", "Asia/Singapore",
		"Europe/London", "Europe/Berlin", "America/New_York", "America/Los_Angeles"}
}

// UIBackupScheduleTypes 返回计划周期稳定值。
func UIBackupScheduleTypes() []string { return []string{"daily", "weekly", "monthly", "custom"} }

// UIBackupMissedPolicies 返回停机补跑策略稳定值。
func UIBackupMissedPolicies() []string { return []string{"skip", "latest", "all"} }

// UIBackupJobStates 返回任务状态筛选稳定值；取消被拒绝是操作结果，不是任务状态。
func UIBackupJobStates() []string {
	return []string{"queued", "running", "cancel_requested", "cancelled",
		"succeeded", "failed", "timed_out"}
}

// UIBackupVerificationStates 返回校验状态筛选稳定值。
func UIBackupVerificationStates() []string {
	return []string{"verified", "unverified", "unknown", "failed"}
}

// UIBackupCapabilities 是服务端为当前操作者判定的页面能力位（只影响呈现）。
type UIBackupCapabilities struct {
	Read        bool
	Create      bool
	Cancel      bool
	Download    bool
	Retention   bool
	Cleanup     bool
	DownloadTTL time.Duration
}

// UIBackupError 是备份页面适配层返回的稳定公开错误。
type UIBackupError struct{ Code string }

// Error 实现 error。
func (e *UIBackupError) Error() string { return "备份页面操作失败: " + e.Code }

// UIBackupSchedule 是备份计划页面视图。
type UIBackupSchedule struct {
	ID                string
	Name              string
	Enabled           bool
	ScheduleType      string
	Expression        string
	TimeZone          string
	PeriodDescription string
	MissedPolicy      string
	MaxCatchUp        int
	TimeoutSeconds    int
	MaxAttempts       int
	Owner             string
	ExecutionActor    string
	ScopeID           string
	NextRun           time.Time
	NextRunUnknown    bool
	RetentionVersion  int64
	NotifyFailures    bool
	NotifySuccess     bool
	LastScheduledAt   time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
	PermissionState   string
}

// UIBackupScheduleRequest 是创建/编辑备份计划的页面请求（所有者/执行身份由服务端
// 按可信调用者决定，不接受表单自报）。
type UIBackupScheduleRequest struct {
	Name             string
	ScheduleType     string
	Expression       string
	TimeZone         string
	MissedPolicy     string
	MaxCatchUp       int
	TimeoutSeconds   int
	MaxAttempts      int
	RetentionVersion int64
	NotifyFailures   bool
	NotifySuccess    bool
	NotifyTarget     string
	Enabled          bool
	Reason           string
}

// UIBackupJob 是备份/清理任务页面视图。
type UIBackupJob struct {
	ID                string
	Kind              string
	Origin            string
	ScheduleID        string
	State             string
	StageCode         string
	StageDescription  string
	ProgressDone      *int64
	ProgressTotal     *int64
	ProgressUnit      string
	Attempt           int
	MaxAttempts       int
	Initiator         string
	Canceller         string
	ErrorCode         string
	FailureReason     string
	RequestID         string
	BackupID          string
	NotificationState string
	NotificationCode  string
	ResultSummary     string
	CreatedAt         time.Time
	StartedAt         time.Time
	FinishedAt        time.Time
	CancelRequestedAt time.Time
	UpdatedAt         time.Time
}

// UIBackupJobRef 是任务提交结果；Existing 表示服务端按幂等规则返回已存在任务。
type UIBackupJobRef struct {
	JobID    string
	Existing bool
	State    string
}

// UIBackupCancelResult 是取消请求结果；请求接受不等于实际取消。
type UIBackupCancelResult struct {
	JobID            string
	Accepted         bool
	AlreadyRequested bool
	State            string
	Note             string
}

// UIBackupArtifact 是历史备份页面视图（受控元数据，不含宿主路径/密钥）。
type UIBackupArtifact struct {
	BackupID         string
	JobID            string
	ScheduleID       string
	Origin           string
	SizeBytes        int64
	FileSHA256       string
	FormatVersion    int
	SchemaVersion    string
	ContentDatabase  bool
	ContentAttach    string
	ContentConfig    string
	EntryCount       int
	Verification     string
	VerifiedAt       time.Time
	RetentionVersion int64
	Cleanup          string
	CleanedAt        time.Time
	CreatedAt        time.Time
	PublishedAt      time.Time
	FileExists       bool
	IsLastUsable     bool
	ProtectionReason string
	Downloadable     bool
}

// UIBackupNotification 是通知投递摘要。
type UIBackupNotification struct {
	ID              string
	Kind            string
	State           string
	Channel         string
	RecipientMasked string
	ErrorCode       string
	Attempts        int
	CreatedAt       time.Time
}

// UIBackupDownload 是受控下载结果（字节只在本次响应返回）。
type UIBackupDownload struct {
	BackupID string
	FileName string
	SHA256   string
	Size     int64
	Data     []byte
}

// UIBackupRetention 是保留策略页面视图。
type UIBackupRetention struct {
	Version       int64
	MaxCount      int
	MaxAgeDays    int
	MaxTotalBytes int64
	IsDefault     bool
	UpdatedAt     time.Time
	UpdatedBy     string
	Reason        string
	LastCleanup   *UIBackupCleanupSummary
}

// UIBackupCleanupSummary 是最近一次清理任务的真实分项结果。
type UIBackupCleanupSummary struct {
	JobID          string
	State          string
	RequestedCount int
	CleanedCount   int
	FailedCount    int
	ProtectedCount int
	FreedBytes     int64
	FinishedAt     time.Time
}

// UIBackupCleanupCandidate 是清理预览中的一项。
type UIBackupCleanupCandidate struct {
	Artifact UIBackupArtifact
	Reason   string
}

// UIBackupCleanupPreview 是清理预览（不是删除授权）。
type UIBackupCleanupPreview struct {
	Policy        UIBackupRetention
	Targets       []UIBackupCleanupCandidate
	Protected     []UIBackupCleanupCandidate
	TotalRetained int
	TotalBytes    int64
	TargetBytes   int64
	PreviewedAt   time.Time
	Note          string
}

// UIBackupRetentionRequest 是保存保留策略的页面请求。
type UIBackupRetentionRequest struct {
	MaxCount        int
	MaxAgeDays      int
	MaxTotalBytes   int64
	ExpectedVersion int64
	Reason          string
}

// UIBackupArtifactQuery 是历史备份筛选（服务端白名单字段 + 受控分页）。
type UIBackupArtifactQuery struct {
	Verification string
	Cleanup      string
	Origin       string
	Limit        int
	Offset       int
}

// UIBackupReconcileResult 是孤儿成品对账结果。
type UIBackupReconcileResult struct {
	Scanned      int
	Orphans      int
	MissingFiles int
}

// UIPageBackupBackend 是备份管理页面调用真实备份服务的契约。适配器负责可信 Caller
// 与每次授权；页面层不实现权限判定、不补造状态。
type UIPageBackupBackend interface {
	Capabilities(ctx context.Context, userID string) (UIBackupCapabilities, error)
	RecordDenial(ctx context.Context, userID, reason string) error

	ListSchedules(ctx context.Context, userID string) ([]UIBackupSchedule, error)
	GetSchedule(ctx context.Context, userID, scheduleID string) (UIBackupSchedule, error)
	SaveSchedule(ctx context.Context, userID, scheduleID string,
		request UIBackupScheduleRequest, requestID string) (UIBackupSchedule, error)
	SetScheduleEnabled(ctx context.Context, userID, scheduleID string, enabled bool,
		reason, requestID string) (UIBackupSchedule, error)
	DeleteSchedule(ctx context.Context, userID, scheduleID, reason, requestID string) error

	EnqueueBackup(ctx context.Context, userID, requestID string) (UIBackupJobRef, error)
	ListJobs(ctx context.Context, userID, kind string, limit,
		offset int) ([]UIBackupJob, bool, error)
	GetJob(ctx context.Context, userID, jobID string) (UIBackupJob, error)
	CancelJob(ctx context.Context, userID, jobID, reason,
		requestID string) (UIBackupCancelResult, error)

	ListArtifacts(ctx context.Context, userID string,
		query UIBackupArtifactQuery) ([]UIBackupArtifact, bool, error)
	GetArtifact(ctx context.Context, userID, backupID string) (UIBackupArtifact, error)
	Download(ctx context.Context, userID, backupID string) (UIBackupDownload, error)
	ListNotifications(ctx context.Context, userID, jobID,
		backupID string) ([]UIBackupNotification, error)

	Retention(ctx context.Context, userID string) (UIBackupRetention, error)
	SaveRetention(ctx context.Context, userID string,
		request UIBackupRetentionRequest, requestID string) (UIBackupRetention, error)
	CleanupPreview(ctx context.Context, userID string) (UIBackupCleanupPreview, error)
	RunCleanup(ctx context.Context, userID, requestID string) (UIBackupJobRef, error)
	Reconcile(ctx context.Context, userID string) (UIBackupReconcileResult, error)
}

// UIBackupSchedulePagedBackend 是支持备份计划分页的可选后端契约（步骤 218）。
type UIBackupSchedulePagedBackend interface {
	ListSchedulesPage(ctx context.Context, userID string, limit, offset int) ([]UIBackupSchedule, bool, error)
}

// UIPageBackupOptions 是备份管理页配置。
type UIPageBackupOptions struct {
	Backend UIPageBackupBackend
	// ValidateCSRF 校验页面表单安全令牌；缺失时拒绝构造。
	ValidateCSRF func(ctx context.Context, request *http.Request, token string) error
	Now          func() time.Time
}

// newPageBackupPages 构造步骤 81 路由与处理器。
func newPageBackupPages(options UIPageBackupOptions) (*pageBackupPages, error) {
	if isNilUIValue(options.Backend) {
		return nil, fmt.Errorf("备份页面缺少后端适配器")
	}
	if options.ValidateCSRF == nil {
		return nil, fmt.Errorf("备份页面缺少 CSRF 校验器")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	pages := &pageBackupPages{handlers: map[string]UIPageHandler{}, options: options}
	handler := &backupPageHandlers{pages: pages}
	routes := []UIRoute{
		{Name: "admin.backup_schedules", Method: http.MethodGet,
			Path: "/admin/backups/schedules", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/backup_schedules"},
		{Name: "admin.backup_schedule_new", Method: http.MethodGet,
			Path: "/admin/backups/schedules/new", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/backup_schedule_form"},
		{Name: "admin.backup_schedule_edit", Method: http.MethodGet,
			Path: "/admin/backups/schedules/edit", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/backup_schedule_form"},
		{Name: "admin.backup_schedule_save", Method: http.MethodPost,
			Path: "/admin/backups/schedules/save", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/backup_schedule_form"},
		{Name: "admin.backup_schedule_state", Method: http.MethodPost,
			Path: "/admin/backups/schedules/state", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/backup_schedules"},
		{Name: "admin.backup_schedule_delete", Method: http.MethodPost,
			Path: "/admin/backups/schedules/delete", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/backup_schedules"},
		{Name: "admin.backup_run", Method: http.MethodPost,
			Path: "/admin/backups/run", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/backup_jobs"},
		{Name: "admin.backup_jobs", Method: http.MethodGet,
			Path: "/admin/backups/jobs", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/backup_jobs"},
		{Name: "admin.backup_job_detail", Method: http.MethodGet,
			Path: "/admin/backups/jobs/detail", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/backup_job_detail"},
		{Name: "admin.backup_cancel", Method: http.MethodPost,
			Path: "/admin/backups/jobs/cancel", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/backup_job_detail"},
		{Name: "admin.backups", Method: http.MethodGet,
			Path: "/admin/backups", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/backups"},
		{Name: "admin.backup_detail", Method: http.MethodGet,
			Path: "/admin/backups/detail", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/backup_detail"},
		{Name: "admin.backup_download", Method: http.MethodPost,
			Path: "/admin/backups/download", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/backup_detail"},
		{Name: "admin.backup_retention", Method: http.MethodGet,
			Path: "/admin/backups/retention", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/backup_retention"},
		{Name: "admin.backup_retention_save", Method: http.MethodPost,
			Path: "/admin/backups/retention", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/backup_retention"},
		{Name: "admin.backup_cleanup_preview", Method: http.MethodGet,
			Path: "/admin/backups/cleanup/preview", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/backup_retention"},
		{Name: "admin.backup_cleanup", Method: http.MethodPost,
			Path: "/admin/backups/cleanup", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/backup_retention"},
		{Name: "admin.backup_reconcile", Method: http.MethodPost,
			Path: "/admin/backups/reconcile", Access: UIAccessManagement,
			Layout: "layout/base", Template: "page/admin/backups"},
	}
	for _, route := range routes {
		pages.routes = append(pages.routes, route)
		pages.handlers[route.Name] = handler
	}
	return pages, nil
}

// pageBackupPages 是备份管理页面实现。
type pageBackupPages struct {
	routes   []UIRoute
	handlers map[string]UIPageHandler
	options  UIPageBackupOptions
}

// backupPageHandlers 实现备份管理页处理器。
type backupPageHandlers struct{ pages *pageBackupPages }

// HandlePage 按路由分派。
func (h *backupPageHandlers) HandlePage(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	switch page.RouteName {
	case "admin.backup_schedules":
		return h.scheduleList(ctx, request, page)
	case "admin.backup_schedule_new":
		return h.scheduleForm(ctx, request, page, "")
	case "admin.backup_schedule_edit":
		return h.scheduleForm(ctx, request, page, request.URL.Query().Get("schedule_id"))
	case "admin.backup_schedule_save":
		return h.scheduleSave(ctx, request, page)
	case "admin.backup_schedule_state":
		return h.scheduleState(ctx, request, page)
	case "admin.backup_schedule_delete":
		return h.scheduleDelete(ctx, request, page)
	case "admin.backup_run":
		return h.runBackup(ctx, request, page)
	case "admin.backup_jobs":
		return h.jobList(ctx, request, page)
	case "admin.backup_job_detail":
		return h.jobDetail(ctx, request, page)
	case "admin.backup_cancel":
		return h.cancelJob(ctx, request, page)
	case "admin.backups":
		return h.artifactList(ctx, request, page)
	case "admin.backup_detail":
		return h.artifactDetail(ctx, request, page)
	case "admin.backup_download":
		return h.download(ctx, request, page)
	case "admin.backup_retention", "admin.backup_retention_save",
		"admin.backup_cleanup_preview", "admin.backup_cleanup":
		return h.retention(ctx, request, page)
	case "admin.backup_reconcile":
		return h.reconcile(ctx, request, page)
	default:
		return UIPageOutcome{}, nil
	}
}

// backupCapabilities 读取能力位；失败时全部 false（只影响呈现，fail-closed）。
func (h *backupPageHandlers) backupCapabilities(ctx context.Context,
	page UIPageContext) UIBackupCapabilities {
	caps, err := h.pages.options.Backend.Capabilities(ctx, page.Session.UserID)
	if err != nil {
		return UIBackupCapabilities{}
	}
	return caps
}

// recordDenial 尽力记录页面级拒绝；失败不改变拒绝结果。
func (h *backupPageHandlers) recordDenial(ctx context.Context, page UIPageContext, reason string) {
	_ = h.pages.options.Backend.RecordDenial(ctx, page.Session.UserID, reason)
}

// checkCSRF 校验 POST 表单安全令牌。
func (h *backupPageHandlers) checkCSRF(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, bool) {
	if err := request.ParseForm(); err != nil {
		h.recordDenial(ctx, page, "form_parse_failed")
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: backupText("page.admin.backups.common.invalid_form")}, false
	}
	token := strings.TrimSpace(request.PostForm.Get(page.CSRFField))
	if token == "" || page.CSRF == "" ||
		subtle.ConstantTimeCompare([]byte(token), []byte(page.CSRF)) != 1 {
		h.recordDenial(ctx, page, "csrf_invalid")
		return UIPageOutcome{StatusCode: http.StatusForbidden,
			ErrorSummary: backupText("page.admin.backups.common.csrf_invalid")}, false
	}
	if err := h.pages.options.ValidateCSRF(ctx, request, token); err != nil {
		h.recordDenial(ctx, page, "csrf_invalid")
		return UIPageOutcome{StatusCode: http.StatusForbidden,
			ErrorSummary: backupText("page.admin.backups.common.csrf_invalid")}, false
	}
	return UIPageOutcome{}, true
}

// backupStatus 把适配器错误映射为 HTTP 状态与公开摘要。
func backupStatus(err error) (int, string, string) {
	var pageErr *UIBackupError
	if !errors.As(err, &pageErr) || pageErr == nil {
		return http.StatusServiceUnavailable,
			backupText("page.admin.backups.common.load_failed"), "UNAVAILABLE"
	}
	switch pageErr.Code {
	case "ACCESS_DENIED":
		return http.StatusForbidden, backupText("page.admin.backups.common.forbidden"), pageErr.Code
	case "NOT_FOUND":
		return http.StatusNotFound, backupText("page.admin.backups.common.not_found"), pageErr.Code
	case "CONFLICT":
		return http.StatusConflict, backupText("page.admin.backups.common.conflict"), pageErr.Code
	case "INVALID":
		return http.StatusBadRequest, backupText("page.admin.backups.common.invalid_form"), pageErr.Code
	default:
		return http.StatusServiceUnavailable,
			backupText("page.admin.backups.common.load_failed"), pageErr.Code
	}
}

// backupText 返回备份页服务端摘要文案（zh-CN 基线；模板静态文案走 i18n 目录）。
func backupText(key string) string {
	if message, ok := backupSummaryText[key]; ok {
		return message
	}
	return key
}

// backupSummaryText 是备份页服务端摘要的中文基线。
var backupSummaryText = map[string]string{
	"page.admin.backups.common.invalid_form":  "表单内容不完整或格式不正确，请检查后重试",
	"page.admin.backups.common.csrf_invalid":  "表单安全令牌无效或已过期，请刷新页面后重试",
	"page.admin.backups.common.forbidden":     "当前会话无权执行该备份操作",
	"page.admin.backups.common.not_found":     "备份对象不存在，或当前会话无权查看",
	"page.admin.backups.common.conflict":      "对象状态或版本已变化，请重新读取后再操作",
	"page.admin.backups.common.load_failed":   "备份服务暂时不可用，请稍后重试",
	"page.admin.backups.common.cancel_failed": "取消请求未完成，任务状态未被确认更改",
	"page.admin.backups.download.denied":      "当前账户没有下载此备份的独立权限",
	"page.admin.backups.download.expired":     "下载入口已过期，备份本身未必被删除",
	"page.admin.backups.download.failed":      "下载未完成，请重新验证后重试",
}

// backupURLs 返回页面间受控导航地址（由命名路由生成，模板不拼路径）。
func backupURLs(page UIPageContext) map[string]string {
	return map[string]string{
		"schedulesURL": routeURL(page, "admin.backup_schedules"),
		"jobsURL":      routeURL(page, "admin.backup_jobs"),
		"backupsURL":   routeURL(page, "admin.backups"),
		"retentionURL": routeURL(page, "admin.backup_retention"),
	}
}

// backupRoutePaths maps this page's named routes (must match newPageBackupPages; links only).
var backupRoutePaths = map[string]string{
	"admin.backup_schedules":       "/admin/backups/schedules",
	"admin.backup_schedule_new":    "/admin/backups/schedules/new",
	"admin.backup_schedule_edit":   "/admin/backups/schedules/edit",
	"admin.backup_jobs":            "/admin/backups/jobs",
	"admin.backup_job_detail":      "/admin/backups/jobs/detail",
	"admin.backups":                "/admin/backups",
	"admin.backup_detail":          "/admin/backups/detail",
	"admin.backup_retention":       "/admin/backups/retention",
	"admin.backup_cleanup_preview": "/admin/backups/cleanup/preview",
}

// scheduleList 渲染备份计划列表。
func (h *backupPageHandlers) scheduleList(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	caps := h.backupCapabilities(ctx, page)
	data := map[string]any{"timezone": page.TimeZone, "canRead": caps.Read,
		"canCreate": caps.Create}
	for key, value := range backupURLs(page) {
		data[key] = value
	}
	if !caps.Read {
		data["forbidden"] = true
		return UIPageOutcome{StatusCode: http.StatusForbidden, Data: data}, nil
	}
	limit, offset := backupPageValues(request.URL.Query().Get("limit"),
		request.URL.Query().Get("offset"))
	var schedules []UIBackupSchedule
	hasMore := false
	var err error
	if paged, ok := h.pages.options.Backend.(UIBackupSchedulePagedBackend); ok {
		schedules, hasMore, err = paged.ListSchedulesPage(ctx, page.Session.UserID, limit, offset)
	} else {
		schedules, err = h.pages.options.Backend.ListSchedules(ctx, page.Session.UserID)
	}
	if err != nil {
		status, summary, _ := backupStatus(err)
		data["loadFailed"] = true
		return UIPageOutcome{StatusCode: status, Data: data, ErrorSummary: summary}, nil
	}
	data["schedules"] = schedules
	data["empty"] = len(schedules) == 0
	data["hasMore"] = hasMore
	data["limit"] = limit
	data["offset"] = offset
	data["nextOffset"] = offset + len(schedules)
	return UIPageOutcome{Data: data}, nil
}

// scheduleForm 渲染新建/编辑计划表单；错误时保留非敏感输入。
func (h *backupPageHandlers) scheduleForm(ctx context.Context, request *http.Request,
	page UIPageContext, scheduleID string) (UIPageOutcome, error) {
	caps := h.backupCapabilities(ctx, page)
	data := map[string]any{"timezone": page.TimeZone, "canCreate": caps.Create,
		"timezones": UIBackupTimeZones(), "scheduleTypes": UIBackupScheduleTypes(),
		"missedPolicies": UIBackupMissedPolicies(),
		"editing":        strings.TrimSpace(scheduleID) != ""}
	for key, value := range backupURLs(page) {
		data[key] = value
	}
	if !caps.Create {
		data["forbidden"] = true
		return UIPageOutcome{StatusCode: http.StatusForbidden, Data: data}, nil
	}
	if data["editing"].(bool) {
		schedule, err := h.pages.options.Backend.GetSchedule(ctx, page.Session.UserID,
			strings.TrimSpace(scheduleID))
		if err != nil {
			status, summary, _ := backupStatus(err)
			data["loadFailed"] = true
			return UIPageOutcome{StatusCode: status, Data: data, ErrorSummary: summary}, nil
		}
		if !schedule.Enabled {
			data["canReenable"] = true
		}
		data["schedule"] = schedule
	}
	return UIPageOutcome{Data: data}, nil
}

// scheduleRequest 从表单白名单构建计划请求。
func (h *backupPageHandlers) scheduleRequest(request *http.Request) (UIBackupScheduleRequest,
	map[string]string) {
	form := request.PostForm
	parseInt := func(name string) (int, bool) {
		raw := strings.TrimSpace(form.Get(name))
		if raw == "" {
			return 0, true
		}
		value, err := strconv.Atoi(raw)
		if err != nil {
			return 0, false
		}
		return value, true
	}
	fieldErrors := map[string]string{}
	maxCatchUp, ok := parseInt("max_catch_up")
	if !ok {
		fieldErrors["max_catch_up"] = backupText("page.admin.backups.common.invalid_form")
	}
	timeout, ok := parseInt("timeout_seconds")
	if !ok {
		fieldErrors["timeout_seconds"] = backupText("page.admin.backups.common.invalid_form")
	}
	maxAttempts, ok := parseInt("max_attempts")
	if !ok {
		fieldErrors["max_attempts"] = backupText("page.admin.backups.common.invalid_form")
	}
	retentionVersion, _ := strconv.ParseInt(strings.TrimSpace(form.Get("retention_version")), 10, 64)
	return UIBackupScheduleRequest{
		Name:             strings.TrimSpace(form.Get("name")),
		ScheduleType:     strings.TrimSpace(form.Get("schedule_type")),
		Expression:       strings.TrimSpace(form.Get("expression")),
		TimeZone:         strings.TrimSpace(form.Get("time_zone")),
		MissedPolicy:     strings.TrimSpace(form.Get("missed_policy")),
		MaxCatchUp:       maxCatchUp,
		TimeoutSeconds:   timeout,
		MaxAttempts:      maxAttempts,
		RetentionVersion: retentionVersion,
		NotifyFailures:   form.Get("notify_failures") != "",
		NotifySuccess:    form.Get("notify_success") != "",
		NotifyTarget:     strings.TrimSpace(form.Get("notify_target")),
		Enabled:          form.Get("enabled") != "",
		Reason:           strings.TrimSpace(form.Get("reason")),
	}, fieldErrors
}

// scheduleSave 处理创建/更新计划。
func (h *backupPageHandlers) scheduleSave(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	if outcome, ok := h.checkCSRF(ctx, request, page); !ok {
		return outcome, nil
	}
	scheduleID := strings.TrimSpace(request.PostForm.Get("schedule_id"))
	scheduleRequest, fieldErrors := h.scheduleRequest(request)
	data := map[string]any{"timezone": page.TimeZone, "canCreate": true,
		"timezones": UIBackupTimeZones(), "scheduleTypes": UIBackupScheduleTypes(),
		"missedPolicies": UIBackupMissedPolicies(),
		"editing":        scheduleID != "", "form": scheduleRequest}
	for key, value := range backupURLs(page) {
		data[key] = value
	}
	if len(fieldErrors) > 0 {
		return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
			FieldErrors:  fieldErrors,
			ErrorSummary: backupText("page.admin.backups.common.invalid_form")}, nil
	}
	if _, err := h.pages.options.Backend.SaveSchedule(ctx, page.Session.UserID,
		scheduleID, scheduleRequest, page.RequestID); err != nil {
		status, summary, _ := backupStatus(err)
		data["fieldErrors"] = nil
		return UIPageOutcome{StatusCode: status, Data: data, ErrorSummary: summary}, nil
	}
	return UIPageOutcome{RedirectRoute: "admin.backup_schedules"}, nil
}

// scheduleState 启停计划；停用只停止未来触发。
func (h *backupPageHandlers) scheduleState(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	if outcome, ok := h.checkCSRF(ctx, request, page); !ok {
		return outcome, nil
	}
	scheduleID := strings.TrimSpace(request.PostForm.Get("schedule_id"))
	enabled := request.PostForm.Get("enabled") != ""
	reason := strings.TrimSpace(request.PostForm.Get("reason"))
	if _, err := h.pages.options.Backend.SetScheduleEnabled(ctx, page.Session.UserID,
		scheduleID, enabled, reason, page.RequestID); err != nil {
		status, summary, _ := backupStatus(err)
		return UIPageOutcome{StatusCode: status, ErrorSummary: summary}, nil
	}
	return UIPageOutcome{RedirectRoute: "admin.backup_schedules"}, nil
}

// scheduleDelete 删除计划；历史备份与既有任务不受影响。
func (h *backupPageHandlers) scheduleDelete(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	if outcome, ok := h.checkCSRF(ctx, request, page); !ok {
		return outcome, nil
	}
	scheduleID := strings.TrimSpace(request.PostForm.Get("schedule_id"))
	reason := strings.TrimSpace(request.PostForm.Get("reason"))
	if err := h.pages.options.Backend.DeleteSchedule(ctx, page.Session.UserID,
		scheduleID, reason, page.RequestID); err != nil {
		status, summary, _ := backupStatus(err)
		return UIPageOutcome{StatusCode: status, ErrorSummary: summary}, nil
	}
	return UIPageOutcome{RedirectRoute: "admin.backup_schedules"}, nil
}

// runBackup 提交手动备份任务；提交成功不等于备份完成。
func (h *backupPageHandlers) runBackup(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	if outcome, ok := h.checkCSRF(ctx, request, page); !ok {
		return outcome, nil
	}
	ref, err := h.pages.options.Backend.EnqueueBackup(ctx, page.Session.UserID, page.RequestID)
	if err != nil {
		status, summary, _ := backupStatus(err)
		return UIPageOutcome{StatusCode: status, ErrorSummary: summary}, nil
	}
	return UIPageOutcome{RedirectRoute: "admin.backup_job_detail",
		RedirectQuery: map[string][]string{"job_id": {ref.JobID}}}, nil
}

// jobList 渲染任务列表（受控分页与筛选）。
func (h *backupPageHandlers) jobList(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	caps := h.backupCapabilities(ctx, page)
	data := map[string]any{"timezone": page.TimeZone, "canRead": caps.Read,
		"canCreate": caps.Create, "canCancel": caps.Cancel}
	for key, value := range backupURLs(page) {
		data[key] = value
	}
	if !caps.Read {
		data["forbidden"] = true
		return UIPageOutcome{StatusCode: http.StatusForbidden, Data: data}, nil
	}
	query := request.URL.Query()
	kind := strings.TrimSpace(query.Get("kind"))
	if kind != "" && kind != backupKindCreate && kind != backupKindCleanup {
		kind = ""
	}
	limit, offset := backupPageValues(query.Get("limit"), query.Get("offset"))
	jobs, hasMore, err := h.pages.options.Backend.ListJobs(ctx, page.Session.UserID,
		kind, limit, offset)
	if err != nil {
		status, summary, _ := backupStatus(err)
		data["loadFailed"] = true
		return UIPageOutcome{StatusCode: status, Data: data, ErrorSummary: summary}, nil
	}
	data["jobs"] = jobs
	data["empty"] = len(jobs) == 0
	data["hasMore"] = hasMore
	data["kind"] = kind
	data["offset"] = offset
	data["limit"] = limit
	data["nextOffset"] = offset + limit
	data["prevOffset"] = maxInt(offset-limit, 0)
	return UIPageOutcome{Data: data}, nil
}

// backupKindCreate/Cleanup 与 internal/task 任务类型一致（页面筛选稳定值）。
const (
	backupKindCreate  = "backup.create"
	backupKindCleanup = "backup.cleanup"
)

// jobDetail 渲染任务详情与通知投递摘要。
func (h *backupPageHandlers) jobDetail(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	caps := h.backupCapabilities(ctx, page)
	data := map[string]any{"timezone": page.TimeZone, "canRead": caps.Read,
		"canCancel": caps.Cancel}
	for key, value := range backupURLs(page) {
		data[key] = value
	}
	if !caps.Read {
		data["forbidden"] = true
		return UIPageOutcome{StatusCode: http.StatusForbidden, Data: data}, nil
	}
	jobID := strings.TrimSpace(request.URL.Query().Get("job_id"))
	job, err := h.pages.options.Backend.GetJob(ctx, page.Session.UserID, jobID)
	if err != nil {
		status, summary, _ := backupStatus(err)
		return UIPageOutcome{StatusCode: status, Data: data, ErrorSummary: summary}, nil
	}
	notifications, err := h.pages.options.Backend.ListNotifications(ctx,
		page.Session.UserID, jobID, "")
	if err != nil {
		notifications = nil
	}
	data["job"] = job
	data["notifications"] = notifications
	return UIPageOutcome{Data: data}, nil
}

// cancelJob 提交取消请求并回真实任务详情（PRG）；请求接受不等于已取消。
func (h *backupPageHandlers) cancelJob(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	if outcome, ok := h.checkCSRF(ctx, request, page); !ok {
		return outcome, nil
	}
	jobID := strings.TrimSpace(request.PostForm.Get("job_id"))
	reason := strings.TrimSpace(request.PostForm.Get("reason"))
	if _, err := h.pages.options.Backend.CancelJob(ctx, page.Session.UserID,
		jobID, reason, page.RequestID); err != nil {
		status, summary, _ := backupStatus(err)
		return UIPageOutcome{StatusCode: status, ErrorSummary: summary}, nil
	}
	return UIPageOutcome{RedirectRoute: "admin.backup_job_detail",
		RedirectQuery: map[string][]string{"job_id": {jobID}}}, nil
}

// artifactList 渲染历史备份列表。
func (h *backupPageHandlers) artifactList(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	caps := h.backupCapabilities(ctx, page)
	data := map[string]any{"timezone": page.TimeZone, "canRead": caps.Read,
		"canDownload": caps.Download, "canReconcile": caps.Create}
	for key, value := range backupURLs(page) {
		data[key] = value
	}
	if !caps.Read {
		data["forbidden"] = true
		return UIPageOutcome{StatusCode: http.StatusForbidden, Data: data}, nil
	}
	query := request.URL.Query()
	filter := UIBackupArtifactQuery{
		Verification: strings.TrimSpace(query.Get("verification")),
		Cleanup:      strings.TrimSpace(query.Get("cleanup")),
		Origin:       strings.TrimSpace(query.Get("origin")),
	}
	filter.Limit, filter.Offset = backupPageValues(query.Get("limit"), query.Get("offset"))
	artifacts, hasMore, err := h.pages.options.Backend.ListArtifacts(ctx,
		page.Session.UserID, filter)
	if err != nil {
		status, summary, _ := backupStatus(err)
		data["loadFailed"] = true
		return UIPageOutcome{StatusCode: status, Data: data, ErrorSummary: summary}, nil
	}
	data["artifacts"] = artifacts
	data["empty"] = len(artifacts) == 0
	data["hasMore"] = hasMore
	data["filter"] = filter
	data["nextOffset"] = filter.Offset + filter.Limit
	data["prevOffset"] = maxInt(filter.Offset-filter.Limit, 0)
	return UIPageOutcome{Data: data}, nil
}

// artifactDetail 渲染备份详情、校验/保护状态与通知记录。
func (h *backupPageHandlers) artifactDetail(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	caps := h.backupCapabilities(ctx, page)
	data := map[string]any{"timezone": page.TimeZone, "canRead": caps.Read,
		"canDownload": caps.Download}
	for key, value := range backupURLs(page) {
		data[key] = value
	}
	if !caps.Read {
		data["forbidden"] = true
		return UIPageOutcome{StatusCode: http.StatusForbidden, Data: data}, nil
	}
	backupID := strings.TrimSpace(request.URL.Query().Get("backup_id"))
	artifact, err := h.pages.options.Backend.GetArtifact(ctx, page.Session.UserID, backupID)
	if err != nil {
		status, summary, _ := backupStatus(err)
		return UIPageOutcome{StatusCode: status, Data: data, ErrorSummary: summary}, nil
	}
	notifications, err := h.pages.options.Backend.ListNotifications(ctx,
		page.Session.UserID, "", backupID)
	if err != nil {
		notifications = nil
	}
	data["artifact"] = artifact
	data["notifications"] = notifications
	return UIPageOutcome{Data: data}, nil
}

// download 执行受控下载：每次重新鉴权与再次认证，响应不缓存、不提供永久链接。
func (h *backupPageHandlers) download(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	if outcome, ok := h.checkCSRF(ctx, request, page); !ok {
		return outcome, nil
	}
	backupID := strings.TrimSpace(request.PostForm.Get("backup_id"))
	file, err := h.pages.options.Backend.Download(ctx, page.Session.UserID, backupID)
	if err != nil {
		// 失败时停留在错误页显示真实原因（不再重定向，避免把拒绝包装成成功跳转）。
		status, summary, _ := backupStatus(err)
		return UIPageOutcome{StatusCode: status, ErrorSummary: summary}, nil
	}
	headers := http.Header{}
	headers.Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
	headers.Set("Pragma", "no-cache")
	headers.Set("Referrer-Policy", "no-referrer")
	headers.Set("X-Content-Type-Options", "nosniff")
	// 备份文件是下载用的二进制附件，禁止其被当作文档执行/同源加载。
	// 与报告下载响应保持一致：先 default-src 'none' 兜底，再 sandbox 隔离。
	headers.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	headers.Set("Content-Disposition", "attachment; filename=\""+
		backupDownloadName(file.FileName)+"\"")
	headers.Set("X-Content-SHA256", file.SHA256)
	return UIPageOutcome{StatusCode: http.StatusOK,
		ContentType: "application/octet-stream", Body: file.Data, Headers: headers}, nil
}

// safeDownloadName 只保留安全文件名（不含路径或控制字符）。
func backupDownloadName(name string) string {
	name = strings.ReplaceAll(name, "\\", "_")
	name = strings.ReplaceAll(name, "/", "_")
	builder := make([]rune, 0, len(name))
	for _, r := range name {
		if r < 0x20 || r == 0x7f || r == '"' {
			continue
		}
		builder = append(builder, r)
	}
	cleaned := string(builder)
	if cleaned == "" {
		return "backup.elnbak"
	}
	return cleaned
}

// retention 处理保留策略查看/保存、清理预览与清理提交。
func (h *backupPageHandlers) retention(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	caps := h.backupCapabilities(ctx, page)
	data := map[string]any{"timezone": page.TimeZone, "canRead": caps.Read,
		"canRetention": caps.Retention, "canCleanup": caps.Cleanup}
	for key, value := range backupURLs(page) {
		data[key] = value
	}
	if !caps.Read {
		data["forbidden"] = true
		return UIPageOutcome{StatusCode: http.StatusForbidden, Data: data}, nil
	}
	write := page.RouteName == "admin.backup_retention_save" ||
		page.RouteName == "admin.backup_cleanup"
	if write {
		if outcome, ok := h.checkCSRF(ctx, request, page); !ok {
			return outcome, nil
		}
	}
	current, err := h.pages.options.Backend.Retention(ctx, page.Session.UserID)
	if err != nil {
		status, summary, _ := backupStatus(err)
		data["loadFailed"] = true
		return UIPageOutcome{StatusCode: status, Data: data, ErrorSummary: summary}, nil
	}
	data["retention"] = current
	switch page.RouteName {
	case "admin.backup_retention_save":
		if !caps.Retention {
			data["forbidden"] = true
			return UIPageOutcome{StatusCode: http.StatusForbidden, Data: data}, nil
		}
		maxCount, okCount := parseNonNegative(request.PostForm.Get("max_count"))
		maxAge, okAge := parseNonNegative(request.PostForm.Get("max_age_days"))
		maxTotal, okTotal := parseNonNegative64(request.PostForm.Get("max_total_bytes"))
		expected := int64(0)
		if value, err := strconv.ParseInt(strings.TrimSpace(request.PostForm.Get("expected_version")), 10, 64); err == nil {
			expected = value
		}
		if !okCount || !okAge || !okTotal {
			return UIPageOutcome{StatusCode: http.StatusBadRequest, Data: data,
				ErrorSummary: backupText("page.admin.backups.common.invalid_form")}, nil
		}
		saved, err := h.pages.options.Backend.SaveRetention(ctx, page.Session.UserID,
			UIBackupRetentionRequest{MaxCount: maxCount, MaxAgeDays: maxAge,
				MaxTotalBytes: maxTotal, ExpectedVersion: expected,
				Reason: strings.TrimSpace(request.PostForm.Get("reason"))}, page.RequestID)
		if err != nil {
			status, summary, _ := backupStatus(err)
			return UIPageOutcome{StatusCode: status, Data: data, ErrorSummary: summary}, nil
		}
		data["retention"] = saved
		data["saved"] = true
	case "admin.backup_cleanup_preview":
		if !caps.Cleanup {
			data["forbidden"] = true
			return UIPageOutcome{StatusCode: http.StatusForbidden, Data: data}, nil
		}
		preview, err := h.pages.options.Backend.CleanupPreview(ctx, page.Session.UserID)
		if err != nil {
			status, summary, _ := backupStatus(err)
			return UIPageOutcome{StatusCode: status, Data: data, ErrorSummary: summary}, nil
		}
		data["preview"] = preview
	case "admin.backup_cleanup":
		if !caps.Cleanup {
			data["forbidden"] = true
			return UIPageOutcome{StatusCode: http.StatusForbidden, Data: data}, nil
		}
		ref, err := h.pages.options.Backend.RunCleanup(ctx, page.Session.UserID, page.RequestID)
		if err != nil {
			status, summary, _ := backupStatus(err)
			return UIPageOutcome{StatusCode: status, Data: data, ErrorSummary: summary}, nil
		}
		return UIPageOutcome{RedirectRoute: "admin.backup_job_detail",
			RedirectQuery: map[string][]string{"job_id": {ref.JobID}}}, nil
	}
	return UIPageOutcome{Data: data}, nil
}

// reconcile 触发孤儿成品对账（要求备份创建/管理权限之外的显式能力位）。
func (h *backupPageHandlers) reconcile(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	if outcome, ok := h.checkCSRF(ctx, request, page); !ok {
		return outcome, nil
	}
	result, err := h.pages.options.Backend.Reconcile(ctx, page.Session.UserID)
	if err != nil {
		status, summary, _ := backupStatus(err)
		return UIPageOutcome{StatusCode: status, ErrorSummary: summary}, nil
	}
	return UIPageOutcome{RedirectRoute: "admin.backups",
		RedirectQuery: map[string][]string{
			"reconcile_orphans": {strconv.Itoa(result.Orphans)},
			"reconcile_missing": {strconv.Itoa(result.MissingFiles)},
		}}, nil
}

// backupPageValues 归一化受控分页参数。
func backupPageValues(rawLimit, rawOffset string) (int, int) {
	limit, err := strconv.Atoi(strings.TrimSpace(rawLimit))
	if err != nil || limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	offset, err := strconv.Atoi(strings.TrimSpace(rawOffset))
	if err != nil || offset < 0 {
		offset = 0
	}
	return limit, offset
}

// parseNonNegative 解析非负整数；空串按 0（由服务端语义判定是否为不启用）。
func parseNonNegative(raw string) (int, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, true
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 0 {
		return 0, false
	}
	return value, true
}

// parseNonNegative64 解析非负 64 位整数。
func parseNonNegative64(raw string) (int64, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, true
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < 0 {
		return 0, false
	}
	return value, true
}

// maxInt 返回较大值。
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
