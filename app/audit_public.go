// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package app

// 审计/运行诊断公开 Go 接口（步骤 230）。
//
// 边界：
//   - 只复用 internal/auditops（查询/导出/清理/保留）、internal/stats（错误分类统计）、
//     internal/task（任务状态/取消）的真实语义；不复制 SQL/授权/root 判定；
//   - 身份统一来自 AdminCaller（LocalAdmin/AdminSession），经 adminFacade.begin 解析
//     请求编号并校验 Runtime 归属；权限、数据范围、root、强认证与审计由各领域重新判定；
//   - 只有 root 可清理审计或修改保留策略：LocalAdmin 是 local_admin 不是 root，
//     领域 requireRoot 会拒绝；本门面不提供绕过通道；
//   - 导出/产物只以流式句柄返回（AdminDownload），公开类型不含宿主磁盘路径；
//   - 错误沿用领域 CodeOf + 统一 mapDomainError，不泄露路径、底层消息或秘密。
//
// 访问器 Runtime.Audit() 由本文件定义；不编辑 app/runtime.go、app/admin.go|types.go
//（217/218/223 边界），与 223 users_public.go 的访问器模式一致。

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/auditops"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// AuditService 是审计查询、错误分类统计、导出、清理/保留策略与后台任务运行诊断
// 的公开门面。所有方法都要求 AdminCaller；敏感写操作另需密码/TOTP 再次认证。
type AuditService interface {
	// Query 分页查询审计事件（复用步骤 218 的稳定游标/筛选契约）。
	Query(ctx context.Context, req AdminListAuditEventsRequest) (AdminAuditEventList, error)
	// GetEvent 读取单条审计事件详情（含作用范围、保留期与 stale 标记）。
	GetEvent(ctx context.Context, req AdminAuditEventRequest) (AdminAuditEventDetail, error)
	// Retention 读取当前审计保留策略（只读）。
	Retention(ctx context.Context, req AdminAuditRetentionRequest) (AdminAuditRetention, error)
	// ErrorStats 读取错误分类统计（类别/严重度/应用/窗口；缺数据标记未知/截断）。
	ErrorStats(ctx context.Context, req AdminErrorStatsRequest) (AdminErrorStatsResult, error)

	// StartExport 创建审计导出任务（csv/json；行数/字节上限，truncated 如实标记）。
	StartExport(ctx context.Context, req AdminAuditExportStartRequest) (AdminAuditExport, error)
	ListExports(ctx context.Context, req AdminAuditExportListRequest) (AdminAuditExportList, error)
	GetExport(ctx context.Context, req AdminAuditExportRequest) (AdminAuditExport, error)
	CancelExport(ctx context.Context, req AdminAuditExportCancelRequest) (AdminTaskCancelResult, error)
	// OpenExport 流式读取导出产物；不返回宿主路径。
	OpenExport(ctx context.Context, req AdminAuditExportRequest) (AdminDownload, error)

	// PreviewPurge 只读预估清理影响（不删除）；StartPurge 仅 root，需 digest+原因+reauth。
	PreviewPurge(ctx context.Context, req AdminAuditPurgePreviewRequest) (AdminAuditPurgePreview, error)
	StartPurge(ctx context.Context, req AdminAuditPurgeStartRequest) (AdminAuditPurgeRun, error)
	ListPurgeRuns(ctx context.Context, req AdminAuditPurgeRunListRequest) (AdminAuditPurgeRunList, error)
	GetPurgeRun(ctx context.Context, req AdminAuditPurgeRunRequest) (AdminAuditPurgeRun, error)
	CancelPurge(ctx context.Context, req AdminAuditPurgeCancelRequest) (AdminTaskCancelResult, error)
	// SetRetention 仅 root，且要求审计清理敏感策略再次认证与版本 CAS。
	SetRetention(ctx context.Context, req AdminAuditRetentionSetRequest) (AdminAuditRetention, error)

	// 通用后台任务运行诊断：本机受信操作者可读全部；管理会话只读/取消本人发起的任务。
	GetTask(ctx context.Context, req AdminTaskRequest) (AdminTask, error)
	ListTaskAttempts(ctx context.Context, req AdminTaskRequest) ([]AdminTaskAttempt, error)
	CancelTask(ctx context.Context, req AdminTaskCancelRequest) (AdminTaskCancelResult, error)
}

// AdminDownload 是受控产物/导出文件的流式句柄。宿主负责 Close；本类型不包含
// 宿主磁盘路径，FileName 只来自受控元数据/格式派生，禁止写入日志或展示为绝对路径。
type AdminDownload struct {
	Reader      io.ReadCloser
	FileName    string
	ContentType string
	Size        int64
	SHA256      string
	ExpiresAt   time.Time
}

// AdminTaskAttempt 是一次任务尝试的只读记录。
type AdminTaskAttempt struct {
	Attempt    int
	StartedAt  time.Time
	FinishedAt time.Time
	Outcome    string
	ErrorCode  string
}

// AdminTaskCancelRequest 是任务取消请求；Reason 进入审计，不冒充“已取消”。
type AdminTaskCancelRequest struct {
	Caller    AdminCaller
	TaskID    string
	Reason    string
	RequestID string
}

// AdminTaskCancelResult 是取消请求结果：Accepted 只表示请求被接受，真实终态需
// 再次 GetTask；AlreadyRequested 表示此前已接受。
type AdminTaskCancelResult struct {
	TaskID           string
	Accepted         bool
	AlreadyRequested bool
	State            string
	Note             string
}

// AdminTaskRequest 是任务只读请求。
type AdminTaskRequest struct {
	Caller    AdminCaller
	TaskID    string
	RequestID string
}

// AdminAuditEventRequest 读取单条审计事件。
type AdminAuditEventRequest struct {
	Caller         AdminCaller
	ScopeID        string
	EventID        string
	OccurredAtHint time.Time
	RequestID      string
}

// AdminAuditEventDetail 是审计详情（事件本身沿用步骤 218 的脱敏视图）。
type AdminAuditEventDetail struct {
	Event               AdminAuditEvent
	ScopeID             string
	ScopeKind           string
	RetentionDays       int
	RetentionConfigured bool
	RetentionCutoff     time.Time
	Stale               bool
}

// AdminAuditRetention 是审计保留策略只读视图。
type AdminAuditRetention struct {
	Days       int
	Configured bool
	Version    int64
	Cutoff     time.Time
	UpdatedAt  time.Time
}

// AdminAuditRetentionRequest 读取保留策略。
type AdminAuditRetentionRequest struct {
	Caller    AdminCaller
	RequestID string
}

// AdminAuditRetentionSetRequest 修改保留策略（仅 root，需再次认证）。
type AdminAuditRetentionSetRequest struct {
	Caller          AdminCaller
	RetentionDays   int
	Reason          string
	ExpectedVersion int64
	Password        string
	TOTPCode        string
	RequestID       string
}

// AdminErrorStatsRequest 是错误分类统计请求；窗口语义与统计/报告服务一致。
type AdminErrorStatsRequest struct {
	Caller      AdminCaller
	ScopeID     string
	AppID       string
	TimeZone    string
	Start       time.Time
	End         time.Time
	Granularity string
	Categories  []string
	Sort        string
	Order       string
	Limit       int
	Offset      int
	RequestID   string
}

// AdminErrorStatsRow 是一行错误聚合（错误码/类别/严重度/应用/去重指标）。
type AdminErrorStatsRow struct {
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
	GrowthPercent  float64
	GrowthKind     string
	DataStatus     string
}

// AdminErrorCategorySummary 是按类别的汇总。
type AdminErrorCategorySummary struct {
	Category       string
	Severity       string
	RawEvents      int64
	FailedRequests int64
	FailedTasks    int64
}

// AdminStatsMissingInterval 是统计缺失区间（真实值未知，不是 0）。
type AdminStatsMissingInterval struct {
	Start  time.Time
	End    time.Time
	Reason string
}

// AdminStatsCompleteness 是统计完整性；页面/宿主必须展示而不是补零。
type AdminStatsCompleteness struct {
	WindowWithinRetention bool
	RetentionDays         int
	RetentionConfigured   bool
	RetentionCutoff       time.Time
	MissingIntervals      []AdminStatsMissingInterval
	ScopeTrimmed          bool
	SourceTruncated       bool
	ModulesNotEnabled     []string
}

// AdminErrorStatsResult 是错误分类统计结果；JSON/CSV 同源数据由域内生成。
type AdminErrorStatsResult struct {
	TimeZone         string
	Start            time.Time
	End              time.Time
	Granularity      string
	Rows             []AdminErrorStatsRow
	Categories       []AdminErrorCategorySummary
	TotalRawEvents   int64
	FailedRequests   int64
	FailedTasks      int64
	ShareDenominator int64
	Sort             string
	Order            string
	Limit            int
	Offset           int
	HasMore          bool
	Completeness     AdminStatsCompleteness
	GeneratedAt      time.Time
}

// AdminAuditExport 是审计导出任务视图（不含路径/正文/秘密）。
type AdminAuditExport struct {
	ID            string
	ScopeID       string
	ScopeKind     string
	Format        string
	State         string
	RequestedType string
	RequestedID   string
	MaxRows       int
	RowCount      int
	Truncated     bool
	TaskID        string
	FileAvailable bool
	FileExpiresAt time.Time
	ErrorCode     string
	FailureReason string
	RequestID     string
	ExecutorID    string
	CreatedAt     time.Time
	StartedAt     time.Time
	FinishedAt    time.Time
}

// AdminAuditExportStartRequest 创建导出任务（需 audit.export + 再次认证）。
type AdminAuditExportStartRequest struct {
	Caller    AdminCaller
	ScopeID   string
	Filter    AdminAuditFilter
	Order     string
	Format    string
	MaxRows   int
	Password  string
	TOTPCode  string
	RequestID string
}

// AdminAuditExportListRequest 列出导出任务（offset 分页）。
type AdminAuditExportListRequest struct {
	Caller    AdminCaller
	ScopeID   string
	State     string
	Page      AdminPage
	RequestID string
}

// AdminAuditExportList 是导出任务列表。
type AdminAuditExportList struct {
	Exports []AdminAuditExport
	HasMore bool
	Page    AdminPageInfo
}

// AdminAuditExportRequest 读取/下载单个导出任务。
type AdminAuditExportRequest struct {
	Caller    AdminCaller
	ExportID  string
	RequestID string
}

// AdminAuditExportCancelRequest 取消导出任务（需再次认证）。
type AdminAuditExportCancelRequest struct {
	Caller    AdminCaller
	ExportID  string
	Reason    string
	Password  string
	TOTPCode  string
	RequestID string
}

// AdminAuditPurgePreviewRequest 只读清理预估。
type AdminAuditPurgePreviewRequest struct {
	Caller     AdminCaller
	ScopeID    string
	Cutoff     time.Time
	BatchSize  int
	MaxRecords int
	RequestID  string
}

// AdminAuditPurgePreview 是清理预估结果（计数有上限，AtLeast 表示截断）。
type AdminAuditPurgePreview struct {
	ScopeID              string
	ScopeKind            string
	Cutoff               time.Time
	BatchSize            int
	MaxRecords           int
	EstimatedCount       int64
	AtLeast              bool
	WithinRetention      bool
	MaintenanceProtected bool
	ArtifactsIncluded    bool
	Digest               string
	Retention            AdminAuditRetention
	GeneratedAt          time.Time
}

// AdminAuditPurgeStartRequest 提交清理（仅 root；digest 来自同参数预览）。
type AdminAuditPurgeStartRequest struct {
	Caller     AdminCaller
	ScopeID    string
	Cutoff     time.Time
	BatchSize  int
	MaxRecords int
	Reason     string
	Digest     string
	Password   string
	TOTPCode   string
	RequestID  string
}

// AdminAuditPurgeRun 是一次清理运行视图。
type AdminAuditPurgeRun struct {
	ID            string
	Kind          string
	ScopeID       string
	ScopeKind     string
	State         string
	TaskID        string
	RequestedType string
	RequestedID   string
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
	ExecutorID    string
	CreatedAt     time.Time
	StartedAt     time.Time
	FinishedAt    time.Time
}

// AdminAuditPurgeRunListRequest 列出清理运行。
type AdminAuditPurgeRunListRequest struct {
	Caller    AdminCaller
	Kind      string
	State     string
	Page      AdminPage
	RequestID string
}

// AdminAuditPurgeRunList 是清理运行列表。
type AdminAuditPurgeRunList struct {
	Runs    []AdminAuditPurgeRun
	HasMore bool
	Page    AdminPageInfo
}

// AdminAuditPurgeRunRequest 读取单个清理运行。
type AdminAuditPurgeRunRequest struct {
	Caller    AdminCaller
	RunID     string
	RequestID string
}

// AdminAuditPurgeCancelRequest 取消清理运行（root 约束由领域判定）。
type AdminAuditPurgeCancelRequest struct {
	Caller    AdminCaller
	RunID     string
	Reason    string
	Password  string
	TOTPCode  string
	RequestID string
}

// auditPublicFacade 实现 AuditService。
type auditPublicFacade struct{ r *Runtime }

// Audit 返回审计/运行诊断公开门面。
func (r *Runtime) Audit() AuditService { return &auditPublicFacade{r: r} }

// adminFacade 返回共享的 AdminCaller 解析器（不改变管理门面接口）。
func (f *auditPublicFacade) admin() *adminFacade { return &adminFacade{r: f.r} }

// Query 复用步骤 218 的审计查询实现（含游标/筛选/范围）。
func (f *auditPublicFacade) Query(ctx context.Context,
	req AdminListAuditEventsRequest) (AdminAuditEventList, error) {
	return f.admin().ListAuditEvents(ctx, req)
}

// GetEvent 读取单条审计事件详情。
func (f *auditPublicFacade) GetEvent(ctx context.Context,
	req AdminAuditEventRequest) (AdminAuditEventDetail, error) {
	call, err := f.admin().begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminAuditEventDetail{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.AuditOps == nil {
		return AdminAuditEventDetail{}, call.configError("审计服务未装配")
	}
	caller, err := f.admin().accountCaller(call.identity)
	if err != nil {
		return AdminAuditEventDetail{}, call.configError("审计服务调用者无效")
	}
	detail, err := managed.AuditOps.GetEvent(ctx, auditops.GetRequest{
		Caller: caller, ScopeID: strings.TrimSpace(req.ScopeID),
		EventID: strings.TrimSpace(req.EventID), OccurredAtHint: req.OccurredAtHint})
	if err != nil {
		if errors.Is(err, auditops.ErrNotFound) {
			return AdminAuditEventDetail{}, call.notFound("audit event")
		}
		return AdminAuditEventDetail{}, call.domainError("读取审计事件失败",
			string(auditops.CodeOf(err)))
	}
	return AdminAuditEventDetail{Event: toAdminAuditEventFromDetail(detail),
		ScopeID: detail.Scope.ID, ScopeKind: detail.Scope.Kind,
		RetentionDays:       detail.Retention.Days,
		RetentionConfigured: detail.Retention.Configured,
		RetentionCutoff:     detail.Retention.Cutoff, Stale: detail.Stale}, nil
}

// Retention 读取当前审计保留策略。
func (f *auditPublicFacade) Retention(ctx context.Context,
	req AdminAuditRetentionRequest) (AdminAuditRetention, error) {
	call, err := f.admin().begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminAuditRetention{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.AuditOps == nil {
		return AdminAuditRetention{}, call.configError("审计服务未装配")
	}
	caller, err := f.admin().accountCaller(call.identity)
	if err != nil {
		return AdminAuditRetention{}, call.configError("审计服务调用者无效")
	}
	info, err := managed.AuditOps.Retention(ctx, caller)
	if err != nil {
		return AdminAuditRetention{}, call.domainError("读取审计保留策略失败",
			string(auditops.CodeOf(err)))
	}
	return toAdminAuditRetention(info), nil
}

// ErrorStats 读取错误分类统计。
func (f *auditPublicFacade) ErrorStats(ctx context.Context,
	req AdminErrorStatsRequest) (AdminErrorStatsResult, error) {
	call, err := f.admin().begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminErrorStatsResult{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Stats == nil {
		return AdminErrorStatsResult{}, call.configError("统计服务未装配")
	}
	caller, err := f.admin().accountCaller(call.identity)
	if err != nil {
		return AdminErrorStatsResult{}, call.configError("统计服务调用者无效")
	}
	categories := make([]stats.Category, 0, len(req.Categories))
	for _, raw := range req.Categories {
		categories = append(categories, stats.Category(strings.TrimSpace(raw)))
	}
	result, err := managed.Stats.Errors(ctx, stats.ErrorRequest{
		Caller: caller, ScopeID: strings.TrimSpace(req.ScopeID),
		Window: stats.WindowRequest{TimeZone: strings.TrimSpace(req.TimeZone),
			Start: req.Start, End: req.End, Granularity: stats.Granularity(req.Granularity)},
		AppID: strings.TrimSpace(req.AppID), Categories: categories,
		Sort:  stats.ErrorSort(strings.TrimSpace(req.Sort)),
		Order: stats.SortOrder(strings.TrimSpace(req.Order)),
		Limit: req.Limit, Offset: req.Offset})
	if err != nil {
		code := "INTERNAL_ERROR"
		switch {
		case errors.Is(err, stats.ErrAccessDenied):
			code = "ACCESS_DENIED"
		case errors.Is(err, stats.ErrInvalidRequest):
			code = "REQ_INVALID"
		case errors.Is(err, stats.ErrStoreUnavailable):
			code = "INTERNAL_ERROR"
		}
		return AdminErrorStatsResult{}, call.domainError("查询错误分类统计失败", code)
	}
	return toAdminErrorStatsResult(result), nil
}

// StartExport 创建审计导出任务。
func (f *auditPublicFacade) StartExport(ctx context.Context,
	req AdminAuditExportStartRequest) (AdminAuditExport, error) {
	call, err := f.admin().begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminAuditExport{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.AuditOps == nil {
		return AdminAuditExport{}, call.configError("审计服务未装配")
	}
	caller, err := f.admin().accountCaller(call.identity)
	if err != nil {
		return AdminAuditExport{}, call.configError("审计服务调用者无效")
	}
	format := auditops.ExportFormat(strings.TrimSpace(req.Format))
	if !format.Valid() {
		return AdminAuditExport{}, call.domainError("导出格式只支持 csv 或 json", "REQ_INVALID")
	}
	approved, err := f.admin().sensitiveContext(ctx, call.identity,
		auditops.OperationExport, "audit_export", "", nil, req.Password, req.TOTPCode,
		call.requestID)
	if err != nil {
		return AdminAuditExport{}, err
	}
	view, err := managed.AuditOps.StartExport(approved, auditops.StartExportRequest{
		Caller: caller, ScopeID: strings.TrimSpace(req.ScopeID),
		Filter: auditops.Filter{From: req.Filter.From, To: req.Filter.To,
			AppID: strings.TrimSpace(req.Filter.AppID), SystemOnly: req.Filter.SystemOnly,
			ActorType:  auditActorKind(req.Filter.ActorType),
			ActorID:    strings.TrimSpace(req.Filter.ActorID),
			Action:     strings.TrimSpace(req.Filter.Action),
			Outcome:    auditOutcome(req.Filter.Outcome),
			ErrorCode:  strings.TrimSpace(req.Filter.ErrorCode),
			RequestID:  strings.TrimSpace(req.Filter.RequestID),
			TaskID:     strings.TrimSpace(req.Filter.TaskID),
			TargetType: strings.TrimSpace(req.Filter.TargetType),
			TargetID:   strings.TrimSpace(req.Filter.TargetID)},
		Order: auditops.SortOrder(strings.TrimSpace(req.Order)), Format: format,
		MaxRows: req.MaxRows, RequestID: call.requestID})
	if err != nil {
		return AdminAuditExport{}, call.domainError("创建审计导出失败",
			string(auditops.CodeOf(err)))
	}
	return toAdminAuditExport(view), nil
}

// ListExports 列出审计导出任务。
func (f *auditPublicFacade) ListExports(ctx context.Context,
	req AdminAuditExportListRequest) (AdminAuditExportList, error) {
	call, err := f.admin().begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminAuditExportList{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.AuditOps == nil {
		return AdminAuditExportList{}, call.configError("审计服务未装配")
	}
	caller, err := f.admin().accountCaller(call.identity)
	if err != nil {
		return AdminAuditExportList{}, call.configError("审计服务调用者无效")
	}
	page, err := call.page(req.Page)
	if err != nil {
		return AdminAuditExportList{}, err
	}
	views, hasMore, err := managed.AuditOps.ListExports(ctx, auditops.ExportListRequest{
		Caller: caller, ScopeID: strings.TrimSpace(req.ScopeID),
		State: strings.TrimSpace(req.State), Limit: page.Limit, Offset: page.Offset})
	if err != nil {
		return AdminAuditExportList{}, call.domainError("查询审计导出列表失败",
			string(auditops.CodeOf(err)))
	}
	exports := make([]AdminAuditExport, 0, len(views))
	for _, view := range views {
		exports = append(exports, toAdminAuditExport(view))
	}
	return AdminAuditExportList{Exports: exports, HasMore: hasMore,
		Page: NewAdminPageInfo(page, len(exports), hasMore)}, nil
}

// GetExport 读取单个导出任务。
func (f *auditPublicFacade) GetExport(ctx context.Context,
	req AdminAuditExportRequest) (AdminAuditExport, error) {
	call, err := f.admin().begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminAuditExport{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.AuditOps == nil {
		return AdminAuditExport{}, call.configError("审计服务未装配")
	}
	caller, err := f.admin().accountCaller(call.identity)
	if err != nil {
		return AdminAuditExport{}, call.configError("审计服务调用者无效")
	}
	view, err := managed.AuditOps.GetExport(ctx, caller, strings.TrimSpace(req.ExportID))
	if err != nil {
		if errors.Is(err, auditops.ErrNotFound) {
			return AdminAuditExport{}, call.notFound("audit export")
		}
		return AdminAuditExport{}, call.domainError("读取审计导出失败",
			string(auditops.CodeOf(err)))
	}
	return toAdminAuditExport(view), nil
}

// CancelExport 取消导出任务；请求被接受不等于任务已取消。
func (f *auditPublicFacade) CancelExport(ctx context.Context,
	req AdminAuditExportCancelRequest) (AdminTaskCancelResult, error) {
	call, err := f.admin().begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminTaskCancelResult{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.AuditOps == nil {
		return AdminTaskCancelResult{}, call.configError("审计服务未装配")
	}
	caller, err := f.admin().accountCaller(call.identity)
	if err != nil {
		return AdminTaskCancelResult{}, call.configError("审计服务调用者无效")
	}
	approved, err := f.admin().sensitiveContext(ctx, call.identity,
		auditops.OperationExport, "audit_export", strings.TrimSpace(req.ExportID), nil,
		req.Password, req.TOTPCode, call.requestID)
	if err != nil {
		return AdminTaskCancelResult{}, err
	}
	result, err := managed.AuditOps.CancelExport(approved, caller,
		strings.TrimSpace(req.ExportID), strings.TrimSpace(req.Reason), call.requestID)
	if err != nil {
		return AdminTaskCancelResult{}, call.domainError("取消审计导出失败",
			string(auditops.CodeOf(err)))
	}
	return AdminTaskCancelResult{TaskID: strings.TrimSpace(req.ExportID),
		Accepted: result.Accepted, AlreadyRequested: result.AlreadyRequested,
		State: string(result.State),
		Note:  "取消请求被接受不等于已取消，请用 GetExport 确认真实状态"}, nil
}

// OpenExport 流式读取审计导出产物。
func (f *auditPublicFacade) OpenExport(ctx context.Context,
	req AdminAuditExportRequest) (AdminDownload, error) {
	call, err := f.admin().begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminDownload{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.AuditOps == nil {
		return AdminDownload{}, call.configError("审计服务未装配")
	}
	caller, err := f.admin().accountCaller(call.identity)
	if err != nil {
		return AdminDownload{}, call.configError("审计服务调用者无效")
	}
	handle, err := managed.AuditOps.OpenExportFile(ctx, caller,
		strings.TrimSpace(req.ExportID))
	if err != nil {
		if errors.Is(err, auditops.ErrNotFound) {
			return AdminDownload{}, call.notFound("audit export")
		}
		return AdminDownload{}, call.domainError("打开审计导出产物失败",
			string(auditops.CodeOf(err)))
	}
	return openAdminFile(handle.HostPath, filepath.Base(handle.HostPath), handle.Size,
		handle.SHA256, handle.ExpiresAt, exportContentType(handle.Format))
}

// PreviewPurge 只读预估清理。
func (f *auditPublicFacade) PreviewPurge(ctx context.Context,
	req AdminAuditPurgePreviewRequest) (AdminAuditPurgePreview, error) {
	call, err := f.admin().begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminAuditPurgePreview{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.AuditOps == nil {
		return AdminAuditPurgePreview{}, call.configError("审计服务未装配")
	}
	caller, err := f.admin().accountCaller(call.identity)
	if err != nil {
		return AdminAuditPurgePreview{}, call.configError("审计服务调用者无效")
	}
	preview, err := managed.AuditOps.PreviewPurge(ctx, auditops.PurgePreviewRequest{
		Caller: caller, ScopeID: strings.TrimSpace(req.ScopeID), Cutoff: req.Cutoff,
		BatchSize: req.BatchSize, MaxRecords: req.MaxRecords, RequestID: call.requestID})
	if err != nil {
		return AdminAuditPurgePreview{}, call.domainError("审计清理预估失败",
			string(auditops.CodeOf(err)))
	}
	return AdminAuditPurgePreview{ScopeID: preview.ScopeID, ScopeKind: preview.ScopeKind,
		Cutoff: preview.Cutoff, BatchSize: preview.BatchSize,
		MaxRecords: preview.MaxRecords, EstimatedCount: preview.EstimatedCount,
		AtLeast: preview.AtLeast, WithinRetention: preview.WithinRetention,
		MaintenanceProtected: preview.MaintenanceProtected,
		ArtifactsIncluded:    preview.ArtifactsIncluded, Digest: preview.Digest,
		Retention:   toAdminAuditRetention(preview.Retention),
		GeneratedAt: preview.GeneratedAt}, nil
}

// StartPurge 提交清理（仅 root；由领域 requireRoot 判定）。
func (f *auditPublicFacade) StartPurge(ctx context.Context,
	req AdminAuditPurgeStartRequest) (AdminAuditPurgeRun, error) {
	call, err := f.admin().begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminAuditPurgeRun{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.AuditOps == nil {
		return AdminAuditPurgeRun{}, call.configError("审计服务未装配")
	}
	caller, err := f.admin().accountCaller(call.identity)
	if err != nil {
		return AdminAuditPurgeRun{}, call.configError("审计服务调用者无效")
	}
	approved, err := f.admin().sensitiveContext(ctx, call.identity,
		auditops.OperationPurge, "audit_retention", "", nil, req.Password, req.TOTPCode,
		call.requestID)
	if err != nil {
		return AdminAuditPurgeRun{}, err
	}
	run, err := managed.AuditOps.StartPurge(approved, auditops.StartPurgeRequest{
		Caller: caller, ScopeID: strings.TrimSpace(req.ScopeID), Cutoff: req.Cutoff,
		BatchSize: req.BatchSize, MaxRecords: req.MaxRecords,
		Reason: strings.TrimSpace(req.Reason), Digest: strings.TrimSpace(req.Digest),
		RequestID: call.requestID})
	if err != nil {
		return AdminAuditPurgeRun{}, call.domainError("提交审计清理失败",
			string(auditops.CodeOf(err)))
	}
	return toAdminAuditPurgeRun(run), nil
}

// ListPurgeRuns 列出清理运行。
func (f *auditPublicFacade) ListPurgeRuns(ctx context.Context,
	req AdminAuditPurgeRunListRequest) (AdminAuditPurgeRunList, error) {
	call, err := f.admin().begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminAuditPurgeRunList{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.AuditOps == nil {
		return AdminAuditPurgeRunList{}, call.configError("审计服务未装配")
	}
	caller, err := f.admin().accountCaller(call.identity)
	if err != nil {
		return AdminAuditPurgeRunList{}, call.configError("审计服务调用者无效")
	}
	page, err := call.page(req.Page)
	if err != nil {
		return AdminAuditPurgeRunList{}, err
	}
	runs, hasMore, err := managed.AuditOps.ListPurgeRuns(ctx, auditops.PurgeListRequest{
		Caller: caller, Kind: strings.TrimSpace(req.Kind),
		State: strings.TrimSpace(req.State), Limit: page.Limit, Offset: page.Offset})
	if err != nil {
		return AdminAuditPurgeRunList{}, call.domainError("查询审计清理列表失败",
			string(auditops.CodeOf(err)))
	}
	items := make([]AdminAuditPurgeRun, 0, len(runs))
	for _, run := range runs {
		items = append(items, toAdminAuditPurgeRun(run))
	}
	return AdminAuditPurgeRunList{Runs: items, HasMore: hasMore,
		Page: NewAdminPageInfo(page, len(items), hasMore)}, nil
}

// GetPurgeRun 读取单个清理运行。
func (f *auditPublicFacade) GetPurgeRun(ctx context.Context,
	req AdminAuditPurgeRunRequest) (AdminAuditPurgeRun, error) {
	call, err := f.admin().begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminAuditPurgeRun{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.AuditOps == nil {
		return AdminAuditPurgeRun{}, call.configError("审计服务未装配")
	}
	caller, err := f.admin().accountCaller(call.identity)
	if err != nil {
		return AdminAuditPurgeRun{}, call.configError("审计服务调用者无效")
	}
	run, err := managed.AuditOps.GetPurgeRun(ctx, caller, strings.TrimSpace(req.RunID))
	if err != nil {
		if errors.Is(err, auditops.ErrNotFound) {
			return AdminAuditPurgeRun{}, call.notFound("audit purge run")
		}
		return AdminAuditPurgeRun{}, call.domainError("读取审计清理失败",
			string(auditops.CodeOf(err)))
	}
	return toAdminAuditPurgeRun(run), nil
}

// CancelPurge 取消清理运行（root 约束由领域判定）。
func (f *auditPublicFacade) CancelPurge(ctx context.Context,
	req AdminAuditPurgeCancelRequest) (AdminTaskCancelResult, error) {
	call, err := f.admin().begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminTaskCancelResult{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.AuditOps == nil {
		return AdminTaskCancelResult{}, call.configError("审计服务未装配")
	}
	caller, err := f.admin().accountCaller(call.identity)
	if err != nil {
		return AdminTaskCancelResult{}, call.configError("审计服务调用者无效")
	}
	approved, err := f.admin().sensitiveContext(ctx, call.identity,
		auditops.OperationPurge, "audit_retention", strings.TrimSpace(req.RunID), nil,
		req.Password, req.TOTPCode, call.requestID)
	if err != nil {
		return AdminTaskCancelResult{}, err
	}
	result, err := managed.AuditOps.CancelPurge(approved, caller,
		strings.TrimSpace(req.RunID), strings.TrimSpace(req.Reason), call.requestID)
	if err != nil {
		return AdminTaskCancelResult{}, call.domainError("取消审计清理失败",
			string(auditops.CodeOf(err)))
	}
	return AdminTaskCancelResult{TaskID: strings.TrimSpace(req.RunID),
		Accepted: result.Accepted, AlreadyRequested: result.AlreadyRequested,
		State: string(result.State),
		Note:  "取消请求被接受不等于已取消，请用 GetPurgeRun 确认真实状态"}, nil
}

// SetRetention 修改审计保留策略（仅 root；LocalAdmin 也不是 root）。
func (f *auditPublicFacade) SetRetention(ctx context.Context,
	req AdminAuditRetentionSetRequest) (AdminAuditRetention, error) {
	call, err := f.admin().begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminAuditRetention{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.AuditOps == nil {
		return AdminAuditRetention{}, call.configError("审计服务未装配")
	}
	caller, err := f.admin().accountCaller(call.identity)
	if err != nil {
		return AdminAuditRetention{}, call.configError("审计服务调用者无效")
	}
	approved, err := f.admin().sensitiveContext(ctx, call.identity,
		auditops.OperationPurge, "audit_retention", "", nil, req.Password, req.TOTPCode,
		call.requestID)
	if err != nil {
		return AdminAuditRetention{}, err
	}
	info, err := managed.AuditOps.SetRetention(approved, auditops.SetRetentionRequest{
		Caller: caller, RetentionDays: req.RetentionDays,
		Reason: strings.TrimSpace(req.Reason), RequestID: call.requestID,
		ExpectedVersion: req.ExpectedVersion})
	if err != nil {
		return AdminAuditRetention{}, call.domainError("修改审计保留策略失败",
			string(auditops.CodeOf(err)))
	}
	return toAdminAuditRetention(info), nil
}

// GetTask 读取任务状态；本机受信操作者不可见范围之外的调用者得到 ACCESS_DENIED。
func (f *auditPublicFacade) GetTask(ctx context.Context,
	req AdminTaskRequest) (AdminTask, error) {
	job, err := f.authorizedTask(ctx, req.Caller, req.RequestID, req.TaskID)
	if err != nil {
		return AdminTask{}, err
	}
	return toAdminTaskPublic(job), nil
}

// ListTaskAttempts 读取任务尝试历史。
func (f *auditPublicFacade) ListTaskAttempts(ctx context.Context,
	req AdminTaskRequest) ([]AdminTaskAttempt, error) {
	if f.r == nil || f.r.base == nil || f.r.base.Tasks == nil ||
		f.r.base.Tasks.Executor() == nil {
		return nil, configError("后台任务运行时未装配")
	}
	job, err := f.authorizedTask(ctx, req.Caller, req.RequestID, req.TaskID)
	if err != nil {
		return nil, err
	}
	attempts, err := f.r.base.Tasks.Executor().Attempts(ctx, job.ID)
	if err != nil {
		return nil, mapDomainError("读取任务尝试历史失败", "INTERNAL_ERROR", "")
	}
	result := make([]AdminTaskAttempt, 0, len(attempts))
	for _, attempt := range attempts {
		result = append(result, AdminTaskAttempt{Attempt: attempt.Attempt,
			StartedAt: attempt.StartedAt, FinishedAt: attempt.FinishedAt,
			Outcome: attempt.Outcome, ErrorCode: attempt.ErrorCode})
	}
	return result, nil
}

// CancelTask 取消通用后台任务；本机受信操作者与任务发起者可取消，其他调用者拒绝。
func (f *auditPublicFacade) CancelTask(ctx context.Context,
	req AdminTaskCancelRequest) (AdminTaskCancelResult, error) {
	call, err := f.admin().begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminTaskCancelResult{}, err
	}
	if f.r == nil || f.r.base == nil || f.r.base.Tasks == nil ||
		f.r.base.Tasks.Executor() == nil {
		return AdminTaskCancelResult{}, call.configError("后台任务运行时未装配")
	}
	executor := f.r.base.Tasks.Executor()
	taskID := strings.TrimSpace(req.TaskID)
	job, err := executor.Get(ctx, taskID)
	if err != nil {
		if errors.Is(err, task.ErrTaskNotFound) {
			return AdminTaskCancelResult{}, call.notFound("task")
		}
		return AdminTaskCancelResult{}, call.domainError("读取任务失败", "REQ_INVALID")
	}
	if !call.identity.local && (job.Initiator.Type != call.identity.actor.Type ||
		job.Initiator.ID != call.identity.actor.ID) {
		return AdminTaskCancelResult{}, call.domainError("无权取消该任务", "ACCESS_DENIED")
	}
	result, err := executor.RequestCancel(ctx, task.CancelRequest{
		JobID: taskID, Actor: call.identity.actor, Reason: strings.TrimSpace(req.Reason),
		RequestID: call.requestID})
	if err != nil {
		switch {
		case errors.Is(err, task.ErrTaskNotFound):
			return AdminTaskCancelResult{}, call.notFound("task")
		case errors.Is(err, task.ErrTaskTerminal):
			return AdminTaskCancelResult{}, call.domainError("任务已结束，不能再取消", "CONFLICT")
		case errors.Is(err, task.ErrInvalidRequest):
			return AdminTaskCancelResult{}, call.domainError("取消任务参数无效", "REQ_INVALID")
		default:
			return AdminTaskCancelResult{}, call.domainError("取消任务失败", "INTERNAL_ERROR")
		}
	}
	return AdminTaskCancelResult{TaskID: taskID, Accepted: result.Accepted,
		AlreadyRequested: result.AlreadyRequested, State: string(result.State),
		Note: "取消请求被接受不等于已取消，请用 GetTask 确认真实状态"}, nil
}

// authorizedTask 读取任务并校验调用者可见性：本机受信操作者全部；管理会话仅本人
// 发起的任务（与步骤 218 ListTasks 的可见范围一致）。
func (f *auditPublicFacade) authorizedTask(ctx context.Context, caller AdminCaller,
	requestID, taskID string) (task.Job, error) {
	call, err := f.admin().begin(ctx, caller, requestID)
	if err != nil {
		return task.Job{}, err
	}
	if f.r == nil || f.r.base == nil || f.r.base.Tasks == nil ||
		f.r.base.Tasks.Executor() == nil {
		return task.Job{}, call.configError("后台任务运行时未装配")
	}
	taskID = strings.TrimSpace(taskID)
	job, err := f.r.base.Tasks.Executor().Get(ctx, taskID)
	if err != nil {
		if errors.Is(err, task.ErrTaskNotFound) {
			return task.Job{}, call.notFound("task")
		}
		return task.Job{}, call.domainError("读取任务失败", "REQ_INVALID")
	}
	if call.identity.local {
		return job, nil
	}
	if job.Initiator.Type != call.identity.actor.Type ||
		job.Initiator.ID != call.identity.actor.ID {
		return task.Job{}, call.domainError("无权读取该任务", "ACCESS_DENIED")
	}
	return job, nil
}

// openAdminFile 打开领域已校验的受控文件并返回流式句柄；路径只在实现内部使用，
// 不进入公开结构、错误或日志。
func openAdminFile(path, fileName string, size int64, sha256 string, expiresAt time.Time,
	contentType string) (AdminDownload, error) {
	if strings.TrimSpace(path) == "" {
		return AdminDownload{}, configError("受控文件路径为空")
	}
	file, err := os.Open(path)
	if err != nil {
		return AdminDownload{}, mapDomainError("打开受控文件失败", "INTERNAL_ERROR", "")
	}
	if fileName == "" {
		_ = file.Close()
		return AdminDownload{}, configError("受控文件名称为空")
	}
	return AdminDownload{Reader: file, FileName: fileName, ContentType: contentType,
		Size: size, SHA256: sha256, ExpiresAt: expiresAt}, nil
}

// exportContentType 返回审计导出格式的内容类型。
func exportContentType(format auditops.ExportFormat) string {
	switch format {
	case auditops.FormatCSV:
		return "text/csv; charset=utf-8"
	case auditops.FormatJSON:
		return "application/json; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}

// toAdminAuditEventFromDetail 投影审计详情事件。
func toAdminAuditEventFromDetail(detail auditops.EventDetail) AdminAuditEvent {
	return toAdminAuditEvent(detail.Event)
}

// toAdminAuditRetention 投影保留策略。
func toAdminAuditRetention(info auditops.RetentionInfo) AdminAuditRetention {
	return AdminAuditRetention{Days: info.Days, Configured: info.Configured,
		Version: info.Version, Cutoff: info.Cutoff, UpdatedAt: info.UpdatedAt}
}

// toAdminErrorStatsResult 投影错误分类统计。
func toAdminErrorStatsResult(result stats.ErrorResult) AdminErrorStatsResult {
	view := AdminErrorStatsResult{
		TimeZone: result.Window.TimeZone, Start: result.Window.Start,
		End: result.Window.End, Granularity: string(result.Window.Granularity),
		TotalRawEvents: result.TotalRawEvents, FailedRequests: result.FailedRequests,
		FailedTasks: result.FailedTasks, ShareDenominator: result.ShareDenominator,
		Sort: string(result.Sort), Order: string(result.Order), Limit: result.Limit,
		Offset: result.Offset, HasMore: result.HasMore, GeneratedAt: result.GeneratedAt,
		Completeness: AdminStatsCompleteness{
			WindowWithinRetention: result.Completeness.WindowWithinRetention,
			RetentionDays:         result.Completeness.RetentionDays,
			RetentionConfigured:   result.Completeness.RetentionConfigured,
			RetentionCutoff:       result.Completeness.RetentionCutoff,
			ScopeTrimmed:          result.Completeness.ScopeTrimmed,
			SourceTruncated:       result.Completeness.SourceTruncated,
		}}
	for _, module := range result.Completeness.ModulesNotEnabled {
		view.Completeness.ModulesNotEnabled = append(view.Completeness.ModulesNotEnabled,
			string(module))
	}
	for _, row := range result.Rows {
		view.Rows = append(view.Rows, AdminErrorStatsRow{ErrorCode: row.ErrorCode,
			Category: string(row.Category), Severity: string(row.Severity),
			AppID: row.AppID, RawEvents: row.RawEvents,
			FailedRequests: row.FailedRequests, FailedTasks: row.FailedTasks,
			Share: row.Share, FirstSeen: row.FirstSeen, LastSeen: row.LastSeen,
			GrowthPercent: row.Growth.Percent, GrowthKind: string(row.Growth.Kind),
			DataStatus: string(row.DataStatus)})
	}
	for _, summary := range result.Categories {
		view.Categories = append(view.Categories, AdminErrorCategorySummary{
			Category: string(summary.Category), Severity: string(summary.Severity),
			RawEvents: summary.RawEvents, FailedRequests: summary.FailedRequests,
			FailedTasks: summary.FailedTasks})
	}
	for _, interval := range result.Completeness.MissingIntervals {
		view.Completeness.MissingIntervals = append(view.Completeness.MissingIntervals,
			AdminStatsMissingInterval{Start: interval.Start, End: interval.End,
				Reason: interval.Reason})
	}
	return view
}

// toAdminAuditExport 投影审计导出任务。
func toAdminAuditExport(view auditops.ExportView) AdminAuditExport {
	return AdminAuditExport{ID: view.ID, ScopeID: view.ScopeID, ScopeKind: view.ScopeKind,
		Format: string(view.Format), State: view.State,
		RequestedType: string(view.RequestedBy.Type), RequestedID: view.RequestedBy.ID,
		MaxRows: view.MaxRows, RowCount: view.RowCount, Truncated: view.Truncated,
		TaskID: view.TaskID, FileAvailable: view.FileAvailable,
		FileExpiresAt: view.FileExpiresAt, ErrorCode: view.ErrorCode,
		FailureReason: view.FailureReason, RequestID: view.RequestID,
		ExecutorID: view.ExecutorID, CreatedAt: view.CreatedAt,
		StartedAt: view.StartedAt, FinishedAt: view.FinishedAt}
}

// toAdminAuditPurgeRun 投影清理运行。
func toAdminAuditPurgeRun(run auditops.PurgeRunView) AdminAuditPurgeRun {
	return AdminAuditPurgeRun{ID: run.ID, Kind: run.Kind, ScopeID: run.ScopeID,
		ScopeKind: run.ScopeKind, State: run.State, TaskID: run.TaskID,
		RequestedType: string(run.RequestedBy.Type), RequestedID: run.RequestedBy.ID,
		Cutoff: run.Cutoff, BatchSize: run.BatchSize, MaxRecords: run.MaxRecords,
		Scanned: run.Scanned, Cleaned: run.Cleaned, Skipped: run.Skipped,
		Failed: run.Failed, Batches: run.Batches, LimitReached: run.LimitReached,
		ErrorCode: run.ErrorCode, FailureReason: run.FailureReason,
		RequestID: run.RequestID, ExecutorID: run.ExecutorID, CreatedAt: run.CreatedAt,
		StartedAt: run.StartedAt, FinishedAt: run.FinishedAt}
}

// toAdminTaskPublic 投影任务为公开视图（不含 payload）。
func toAdminTaskPublic(job task.Job) AdminTask {
	return AdminTask{ID: job.ID, Kind: job.Kind, State: string(job.State),
		InitiatorType: string(job.Initiator.Type), InitiatorID: job.Initiator.ID,
		ExecutorID: job.ExecutorID, Attempt: job.Attempt, MaxAttempts: job.MaxAttempts,
		ErrorCode: job.ErrorCode, FailureReason: job.FailureReason,
		RequestID: job.RequestID, CreatedAt: job.CreatedAt, StartedAt: job.StartedAt,
		FinishedAt: job.FinishedAt}
}

// auditActorKind/auditOutcome 把公开字符串映射为审计领域类型（领域会再校验）。
func auditActorKind(value string) audit.ActorKind {
	return audit.ActorKind(strings.TrimSpace(value))
}

func auditOutcome(value string) audit.Outcome {
	return audit.Outcome(strings.TrimSpace(value))
}
