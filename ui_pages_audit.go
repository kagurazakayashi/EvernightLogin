package login

// 步骤 74：审计记录、错误码诊断、审计导出任务与 root 审计清理页面（ui.v1）。
//
// 安全不变量：
//   - 全部路由 UIAccessManagement：宿主 UISessionService 必须用真实
//     session.AuthorizeManagement 判定完整会话与强认证新鲜度；页面不信任前端自报
//     root/角色/权限，能力位只影响控件呈现。
//   - 每次读取、详情、关联查询、导出、下载、预估、清理与取消都由适配器重建可信
//     Caller 交给真实 auditops 服务重新授权；链接与筛选参数不是授权凭证，跨应用/
//     ���范围/非 root 一律 fail-closed。
//   - 数据范围在服务层转成 SQL 条件；页面只展示服务端裁剪后的稳定字段，不显示原始
//     detail_json、数据库堆栈、SQL、文件路径、Cookie、Token 或秘密。
//   - 状态区分：查无记录、无权限、已过保留期、不可披露、加载失败互不伪装；导出与
//     清理的已提交/排队/运行/取消请求/取消/失败/超时/完成分别呈现，旧结果带原
//     task_id 与时间，失败不把旧数据伪装成新成功。
//   - 所有写操作显式 POST + 页面 CSRF + 服务端 request_id；root 清理必须独立确认页
//     复述范围/截止时间/预估/上限/不可逆后果，确认不是授权，提交时再次授权。

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// UIAuditScopeSystem 是审计页面固定开放的系统作用域稳定 ID。
const UIAuditScopeSystem = "system"

// UIPageAuditOptions 是步骤 74 审计与错误诊断页配置。
type UIPageAuditOptions struct {
	Backend UIPageAuditBackend
	// ValidateCSRF 是宿主提供的页面表单令牌校验器（生产接
	// session.ValidateCSRFToken 或等价服务端校验）。为 nil 时拒绝构造：导出、下载、
	// 取消与清理动作不能只依赖可能默认关闭的 transport CSRF 中间件。
	ValidateCSRF func(ctx context.Context, request *http.Request, token string) error
	// Now 是页面日期边界钳制使用的服务端时钟；nil 使用 time.Now。日期筛选的结束日
	// 按“含当天”解释，但上界不得超过服务端当前时间（超出部分钳制到 now+1 分钟，与
	// auditops“结束时间不能在未来”的校验一致）。
	Now func() time.Time
}

// UIAuditCapabilities 是服务端为当前操作者判定的页面能力位（只是交互辅助）。
type UIAuditCapabilities struct {
	Read   bool
	Export bool
	Purge  bool
}

// UIAuditError 是审计适配层返回的稳定公开错误。Disclosed 表示服务端允许向当前
// 调用者披露"记录不存在/已过保留期"的区分；false 时页面按不可披露处理。
type UIAuditError struct {
	Code              string
	RetryAfterSeconds int
	Disclosed         bool
}

// Error 实现 error。
func (e *UIAuditError) Error() string { return "审计页面操作失败: " + e.Code }

// UIAuditFilter 是审计列表白名单筛选条件（页面层同名参数，服务端再次校验）。
type UIAuditFilter struct {
	From       time.Time
	To         time.Time
	AppID      string
	SystemOnly bool
	ActorType  string
	ActorID    string
	Action     string
	Outcome    string
	ErrorCode  string
	RequestID  string
	TaskID     string
	TargetType string
	TargetID   string
}

// Empty 报告当前没有任何已生效筛选条件。
func (f UIAuditFilter) Empty() bool {
	return f.From.IsZero() && f.To.IsZero() && f.AppID == "" && !f.SystemOnly &&
		f.ActorType == "" && f.ActorID == "" && f.Action == "" && f.Outcome == "" &&
		f.ErrorCode == "" && f.RequestID == "" && f.TaskID == "" && f.TargetType == "" &&
		f.TargetID == ""
}

// UIAuditQuery 是审计列表查询请求。
type UIAuditQuery struct {
	ScopeID string
	Filter  UIAuditFilter
	Order   string
	Limit   int
	Offset  int
}

// UIAuditEventView 是列表与详情共用的审计事件稳定字段（无原始 detail_json）。
type UIAuditEventView struct {
	ID         string
	OccurredAt time.Time
	ActorType  string
	ActorID    string
	AppID      string
	Action     string
	TargetType string
	TargetID   string
	Outcome    string
	ErrorCode  string
	RequestID  string
	TaskID     string
	Summary    string
}

// OutcomeKey 返回审计结果 i18n 键。
func (e UIAuditEventView) OutcomeKey() string {
	switch e.Outcome {
	case "success":
		return "audit.outcome.success"
	case "failure":
		return "audit.outcome.failure"
	case "denied":
		return "audit.outcome.denied"
	default:
		return "audit.outcome.unknown"
	}
}

// ActorKindKey 返回操作者类型 i18n 键。
func (e UIAuditEventView) ActorKindKey() string {
	switch e.ActorType {
	case "user":
		return "audit.actor_kind.user"
	case "system":
		return "audit.actor_kind.system"
	case "local_admin":
		return "audit.actor_kind.local_admin"
	case "anonymous":
		return "audit.actor_kind.anonymous"
	default:
		return "audit.actor_kind.unknown"
	}
}

// UIAuditChange 是一条已裁剪的审计差异。
type UIAuditChange struct {
	Field    string
	Before   string
	After    string
	Redacted bool
}

// UIAuditDetail 是审计事件详情（公开说明与受限诊断分开）。
type UIAuditDetail struct {
	Event               UIAuditEventView
	Changes             []UIAuditChange
	ScopeID             string
	ScopeKind           string
	RetentionDays       int
	RetentionConfigured bool
	RetentionCutoff     time.Time
	// Stale 表示记录已过保留期但仍存在（尚未清理），页面必须如实标注。
	Stale bool
	// ErrorCode 与公开说明来自同一注册表；未知码不猜测原因。
	ErrorCode string
	Error     UIErrorEntry
	// RelatedTask 是同一 task_id 的真实任务摘要（服务端未提供时为 nil）。
	RelatedTask *UIExportTaskSummary
	// RestrictedReasonCode 是获准显示的受限原因码；空表示无独立诊断权限或
	// 无受限原因。它只在独立诊断权限通过后由适配器填充，公开区不得携带。
	RestrictedReasonCode string
	// Restricted 表示当前调用者拥有独立受限诊断权限（仅影响呈现分区）。
	Restricted bool
}

// UIAuditPage 是审计列表结果（HasMore 由服务端判定；不伪造总数）。
type UIAuditPage struct {
	Events              []UIAuditEventView
	HasMore             bool
	Limit               int
	Offset              int
	Order               string
	ScopeID             string
	ScopeKind           string
	RetentionDays       int
	RetentionConfigured bool
	RetentionCutoff     time.Time
	// DataScope 是服务端授权结果对应的可见数据范围摘要（真实事实；无法得知时为空，
	// 页面显示“以服务端判定为准”，不推断跨应用记录）。
	DataScope string
}

// UIErrorQuery 是错误码检索请求。
type UIErrorQuery struct {
	Code     string
	Keyword  string
	Category string
}

// UIErrorEntry 是一个已登记错误码的公开说明（来源：同一注册表与手册）。
type UIErrorEntry struct {
	Code          string
	Category      string
	Message       string
	HTTPStatus    int
	HasHTTPStatus bool
	Cause         string
	Advice        string
	Retry         string
	HasGuidance   bool
	// Restricted 表示本页展示的是受限诊断；公开检索恒为 false。
	Restricted bool
}

// UIErrorSearch 是错误码检索结果。
type UIErrorSearch struct {
	Entries []UIErrorEntry
	// UnknownCode 非空表示请求的完整码未登记（不猜测原因）。
	UnknownCode string
	// Searched 表示本次确实执行了检索（区别于默认空态）。
	Searched bool
}

// UIAuditExportRequest 是创建审计导出任务请求。
type UIAuditExportRequest struct {
	ScopeID   string
	Filter    UIAuditFilter
	Order     string
	Format    string
	RequestID string
}

// UIExportTaskSummary 是异步任务真实状态摘要（来自 internal/task）。
type UIExportTaskSummary struct {
	ID            string
	Kind          string
	State         string
	Attempt       int
	MaxAttempts   int
	ErrorCode     string
	FailureReason string
	RequestID     string
}

// UIAuditExport 是审计导出任务视图（不含服务器路径）。
type UIAuditExport struct {
	ID            string
	ScopeID       string
	ScopeKind     string
	Format        string
	State         string
	MaxRows       int
	RowCount      int
	Truncated     bool
	TaskID        string
	FileAvailable bool
	FileSize      int64
	FileSHA256    string
	FileExpiresAt time.Time
	ErrorCode     string
	FailureReason string
	RequestID     string
	RequestedBy   string
	CreatedAt     time.Time
	StartedAt     time.Time
	FinishedAt    time.Time
	Task          *UIExportTaskSummary
}

// UIAuditExportPage 是导出任务列表。
type UIAuditExportPage struct {
	Exports []UIAuditExport
	HasMore bool
	Limit   int
	Offset  int
}

// UIAuditExportFile 是受控下载内容（只含安全元数据与字节，不含服务器路径）。
type UIAuditExportFile struct {
	Name        string
	ContentType string
	Body        []byte
}

// UIPurgeRetention 是当前保留策略只读事实。
type UIPurgeRetention struct {
	Days       int
	Configured bool
	Version    int64
	Cutoff     time.Time
	UpdatedAt  time.Time
}

// UIPurgeRequest 是清理预估/提交参数。
type UIPurgeRequest struct {
	ScopeID    string
	Cutoff     time.Time
	BatchSize  int
	MaxRecords int
}

// UIPurgePreview 是只读清理预估结果；不是删除结果。
type UIPurgePreview struct {
	ScopeID              string
	ScopeKind            string
	Cutoff               time.Time
	BatchSize            int
	MaxRecords           int
	EstimatedCount       int64
	AtLeast              bool
	Retention            UIPurgeRetention
	WithinRetention      bool
	MaintenanceProtected bool
	ArtifactsIncluded    bool
	Digest               string
	GeneratedAt          time.Time
}

// UIPurgeRun 是清理运行视图（真实任务状态与真实计数）。
type UIPurgeRun struct {
	ID            string
	State         string
	TaskID        string
	ScopeID       string
	ScopeKind     string
	Cutoff        time.Time
	BatchSize     int
	MaxRecords    int
	Scanned       int
	Cleaned       int
	Skipped       int
	Failed        int
	Batches       int
	LimitReached  bool
	ErrorCode     string
	FailureReason string
	RequestID     string
	RequestedBy   string
	CreatedAt     time.Time
	StartedAt     time.Time
	FinishedAt    time.Time
	Task          *UIExportTaskSummary
}

// UIPurgeContext 是清理页面只读上下文（保留策略 + 最近运行）。
type UIPurgeContext struct {
	Retention UIPurgeRetention
	Runs      []UIPurgeRun
	HasMore   bool
	Limit     int
	Offset    int
}

// UIPageAuditBackend 是审计与错误诊断页面调用真实服务的最小契约；适配器负责可信
// Caller 与每次授权，页面层不实现权限判定。
type UIPageAuditBackend interface {
	Capabilities(ctx context.Context, userID string) (UIAuditCapabilities, error)

	ListAudit(ctx context.Context, userID string, query UIAuditQuery) (UIAuditPage, error)
	GetAudit(ctx context.Context, userID, eventID string, occurredAtHint time.Time) (UIAuditDetail, error)
	QueryOwnActivity(ctx context.Context, userID string, query UIAuditQuery) (UIAuditPage, error)
	GetOwnActivity(ctx context.Context, userID, eventID string, occurredAtHint time.Time) (UIAuditDetail, error)

	SearchErrors(ctx context.Context, userID string, query UIErrorQuery) (UIErrorSearch, error)
	// RecordDenial 记录页面级拒绝（能力位不足/CSRF 失败等）为失败审计；实现必须
	// 不因审计写失败改变拒绝结果。
	RecordDenial(ctx context.Context, userID, reason string) error

	CreateExport(ctx context.Context, userID string, request UIAuditExportRequest) (UIAuditExport, error)
	ListExports(ctx context.Context, userID, scopeID, state string, limit, offset int) (UIAuditExportPage, error)
	GetExport(ctx context.Context, userID, exportID string) (UIAuditExport, error)
	CancelExport(ctx context.Context, userID, exportID, reason, requestID string) (UIAuditExport, error)
	DownloadExport(ctx context.Context, userID, exportID string) (UIAuditExportFile, error)

	PurgeContext(ctx context.Context, userID, scopeID string, limit, offset int) (UIPurgeContext, error)
	PreviewPurge(ctx context.Context, userID string, request UIPurgeRequest) (UIPurgePreview, error)
	StartPurge(ctx context.Context, userID string, request UIPurgeRequest, digest, reason,
		requestID string) (UIPurgeRun, error)
	CancelPurge(ctx context.Context, userID, runID, reason, requestID string) (UIPurgeRun, error)
}

// newPageAuditPages 构造步骤 74 路由/处理器。
func newPageAuditPages(options UIPageAuditOptions) (*pageAuditPages, error) {
	if isNilUIValue(options.Backend) {
		return nil, fmt.Errorf("审计页面缺少后端适配器")
	}
	if options.ValidateCSRF == nil {
		return nil, fmt.Errorf("审计页面缺少 CSRF 校验器：必须接入 session.ValidateCSRFToken 等服务器端校验")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	pages := &pageAuditPages{handlers: map[string]UIPageHandler{}, options: options}
	handler := &auditPageHandlers{pages: pages}
	routes := []UIRoute{
		{Name: "account.activity", Method: http.MethodGet, Path: "/account/activity",
			Access: UIAccessUser, Layout: "layout/base", Template: "page/account/activity"},
		{Name: "account.activity_detail", Method: http.MethodGet, Path: "/account/activity/detail",
			Access: UIAccessUser, Layout: "layout/base", Template: "page/account/activity_detail"},
		{Name: "admin.audit", Method: http.MethodGet, Path: "/admin/audit",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/audit_list"},
		{Name: "admin.audit_detail", Method: http.MethodGet, Path: "/admin/audit/detail",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/audit_detail"},
		{Name: "admin.audit_exports", Method: http.MethodGet, Path: "/admin/audit/exports",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/audit_exports"},
		{Name: "admin.audit_export_create", Method: http.MethodPost, Path: "/admin/audit/exports/create",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/audit_exports"},
		{Name: "admin.audit_export_cancel", Method: http.MethodPost, Path: "/admin/audit/exports/cancel",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/audit_exports"},
		{Name: "admin.audit_export_download", Method: http.MethodGet, Path: "/admin/audit/exports/download",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/audit_exports"},
		{Name: "admin.error_codes", Method: http.MethodGet, Path: "/admin/errors",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/audit_errors"},
		{Name: "admin.audit_maintenance", Method: http.MethodGet, Path: "/admin/audit/maintenance",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/audit_maintenance"},
		{Name: "admin.audit_maintenance_preview", Method: http.MethodPost,
			Path:   "/admin/audit/maintenance/preview",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/audit_maintenance"},
		{Name: "admin.audit_maintenance_start", Method: http.MethodPost,
			Path:   "/admin/audit/maintenance/start",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/audit_maintenance"},
		{Name: "admin.audit_maintenance_cancel", Method: http.MethodPost,
			Path:   "/admin/audit/maintenance/cancel",
			Access: UIAccessManagement, Layout: "layout/base", Template: "page/admin/audit_maintenance"},
	}
	for _, route := range routes {
		pages.routes = append(pages.routes, route)
		pages.handlers[route.Name] = handler
	}
	return pages, nil
}

// pageAuditPages 是审计与错误诊断页实现。
type pageAuditPages struct {
	routes   []UIRoute
	handlers map[string]UIPageHandler
	options  UIPageAuditOptions
}

// exportStateKey 把导出/清理任务真实状态映射为 i18n 键。
func exportStateKey(state string) string {
	switch state {
	case "queued":
		return "common.task.state.queued"
	case "running":
		return "common.task.state.running"
	case "succeeded":
		return "common.task.state.succeeded"
	case "failed":
		return "common.task.state.failed"
	case "cancel_requested":
		return "common.task.state.cancel_requested"
	case "cancelled":
		return "common.task.state.cancelled"
	case "timed_out":
		return "common.task.state.timed_out"
	default:
		return "common.task.state.unknown"
	}
}

// auditErrorOutcome 把适配器错误映射为稳定状态码与中文摘要。
func auditErrorOutcome(err error, data map[string]any, fallbackKey string) UIPageOutcome {
	if data == nil {
		data = map[string]any{}
	}
	outcome := UIPageOutcome{Data: data, StatusCode: http.StatusBadRequest,
		ErrorSummary: text(fallbackKey)}
	var publicErr *UIAuditError
	if errors.As(err, &publicErr) {
		outcome.ErrorCode = publicErr.Code
		switch publicErr.Code {
		case "ACCESS_DENIED":
			outcome.StatusCode = http.StatusForbidden
			outcome.ErrorSummary = text("page.admin.audit.common.forbidden")
			data["forbidden"] = true
		case "REAUTH_REQUIRED":
			outcome.StatusCode = http.StatusForbidden
			outcome.ErrorSummary = text("page.admin.audit.common.reauth_required")
			data["reauthRequired"] = true
		case "NOT_FOUND":
			outcome.StatusCode = http.StatusNotFound
			if publicErr.Disclosed {
				outcome.ErrorSummary = text("page.admin.audit.detail.not_found")
				data["notFound"] = true
			} else {
				outcome.ErrorSummary = text("page.admin.audit.detail.undisclosed")
				data["undisclosed"] = true
			}
		case "RETENTION_EXPIRED":
			outcome.StatusCode = http.StatusGone
			if publicErr.Disclosed {
				outcome.ErrorSummary = text("page.admin.audit.detail.retention_expired")
				data["retentionExpired"] = true
			} else {
				outcome.ErrorSummary = text("page.admin.audit.detail.undisclosed")
				data["undisclosed"] = true
			}
		case "CONFLICT", "TASK_CANCEL_CONFLICT":
			outcome.StatusCode = http.StatusConflict
			outcome.ErrorSummary = text("page.admin.audit.common.conflict")
		case "RATE_LIMITED":
			outcome.StatusCode = http.StatusTooManyRequests
			outcome.ErrorSummary = text("page.admin.audit.common.rate_limited")
		case "REQ_INVALID":
			outcome.StatusCode = http.StatusBadRequest
			outcome.ErrorSummary = text(fallbackKey)
		case "DB_UNAVAILABLE", "AUDIT_WRITE_FAILED":
			outcome.StatusCode = http.StatusServiceUnavailable
			outcome.ErrorSummary = text("page.admin.audit.common.unavailable")
			data["loadFailed"] = true
		default:
			outcome.StatusCode = http.StatusInternalServerError
			outcome.ErrorSummary = text("common.state.error")
			data["loadFailed"] = true
		}
	}
	return outcome
}
