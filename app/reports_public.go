// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package app

// 安全/活跃度报告公开 Go 接口（步骤 230）。
//
// 边界：
//   - 复用 internal/reports 的真实生成/取消/重试/受控产物/清理语义；报告数据来自
//     注入的 stats.Service，图表与明细来自同一快照；本文件不重新实现渲染；
//   - 报告生成/重试/清理属敏感操作：用户主体走真实 reauth（密码 + 强认证要求的
//     动态码）；LocalAdmin 走既有受信本机通道（写独立审计事件后以强认证事实执行），
//     不是 root、不改变 root 保护；
//   - 报告历史/计划列表继续使用步骤 218 的 AdminService.ListReports/ListReportPlans
//     （已分页），本服务不重复实现；
//   - 产物只以 AdminDownload 流式返回，公开类型/错误/日志不含宿主路径；HTML/CSV/JSON/
//     PDF/Markdown 均由既有渲染器完成安全转义、CSV 防公式与 Markdown 不可信数据边界；
//   - PDF 仅在受信字体已配置（PDFAvailable）时允许，否则拒绝，不生成假 PDF。
//
// 访问器 Runtime.Reports() 由本文件定义；不编辑 app/runtime.go（222 边界）。

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/reports"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
)

// ReportsService 是统计报告生成与受控产物的公开门面。
type ReportsService interface {
	// Capabilities 返回本实例真实可用的格式与上限（PDF 依赖受信字体配置）。
	Capabilities(ctx context.Context, req AdminReportCapabilitiesRequest) (AdminReportCapabilities, error)
	// Start 创建即时统计报告（安全/活跃度/错误统计同源快照），返回受理状态。
	Start(ctx context.Context, req AdminReportStartRequest) (AdminReport, error)
	// Get 查询报告真实状态与脱敏元数据（不返回宿主路径）。
	Get(ctx context.Context, req AdminReportRequest) (AdminReport, error)
	// Cancel 请求取消报告生成；Accepted 不等于 Cancelled，真实终态以 Get 为准。
	Cancel(ctx context.Context, req AdminReportCancelRequest) (AdminTaskCancelResult, error)
	// Retry 重试失败/取消/超时的报告（敏感操作，生成新运行记录）。
	Retry(ctx context.Context, req AdminReportRetryRequest) (AdminReport, error)
	// OpenArtifact 流式读取报告产物；当前权限/范围/到期/摘要由领域复核。
	OpenArtifact(ctx context.Context, req AdminReportArtifactRequest) (AdminDownload, error)
	// CleanupPreview 预览当前调用者范围内到期可清理的报告文件（不删除）。
	CleanupPreview(ctx context.Context, req AdminReportCleanupPreviewRequest) (AdminReportCleanupPreview, error)
	// CleanupExecute 清理报告产物文件（敏感操作；不删除原始审计记录）。
	CleanupExecute(ctx context.Context, req AdminReportCleanupRequest) (AdminReportCleanupResult, error)
}

// AdminReportCapabilitiesRequest 读取报告能力。
type AdminReportCapabilitiesRequest struct {
	Caller    AdminCaller
	RequestID string
}

// AdminReportCapabilities 是报告能力说明。
type AdminReportCapabilities struct {
	Formats           []string
	PDFAvailable      bool
	MarkdownAvailable bool
	DefaultDetailRows int
	MaxDetailRows     int
}

// AdminReportStartRequest 创建统计报告。Formats 为空时按领域默认（HTML）；PDF 需要
// 受信字体；敏感操作需 Password（必要时 TOTPCode）。
type AdminReportStartRequest struct {
	Caller        AdminCaller
	ScopeID       string
	AppID         string
	TimeZone      string
	Start         time.Time
	End           time.Time
	Granularity   string
	Categories    []string
	TrendMetric   string
	Formats       []string
	MaxDetailRows int
	Password      string
	TOTPCode      string
	RequestID     string
}

// AdminReportRequest 查询单个报告。
type AdminReportRequest struct {
	Caller    AdminCaller
	ReportID  string
	RequestID string
}

// AdminReportCancelRequest 取消报告生成。
type AdminReportCancelRequest struct {
	Caller    AdminCaller
	ReportID  string
	Reason    string
	RequestID string
}

// AdminReportRetryRequest 重试报告生成（敏感操作）。
type AdminReportRetryRequest struct {
	Caller    AdminCaller
	ReportID  string
	Reason    string
	Password  string
	TOTPCode  string
	RequestID string
}

// AdminReportArtifactRequest 读取一个报告产物（格式必须属于该报告）。
type AdminReportArtifactRequest struct {
	Caller    AdminCaller
	ReportID  string
	Format    string
	RequestID string
}

// AdminReportArtifactInfo 是产物摘要（可用性按当前时间判断；不含路径）。
type AdminReportArtifactInfo struct {
	Format    string
	Bytes     int64
	SHA256    string
	Available bool
	ExpiresAt time.Time
}

// AdminReportCompleteness 是报告数据完整性；缺失区间必须展示，不补零。
type AdminReportCompleteness struct {
	WindowWithinRetention bool
	RetentionDays         int
	RetentionConfigured   bool
	RetentionCutoff       time.Time
	MissingIntervals      []AdminStatsMissingInterval
	ScopeTrimmed          bool
	SourceTruncated       bool
	DetailRowsTruncated   bool
	ModulesNotEnabled     []string
	TrendPointsTruncated  bool
}

// AdminReportSummary 是报告核心数字摘要。
type AdminReportSummary struct {
	ActiveUsers    int64
	TotalRawEvents int64
	FailedRequests int64
	FailedTasks    int64
	DetailRows     int
	TrendPoints    int
}

// AdminReport 是脱敏报告视图（无宿主路径/原始记录/秘密）。
type AdminReport struct {
	ID                string
	ScopeID           string
	ScopeKind         string
	State             string
	Formats           []string
	RequestedType     string
	RequestedID       string
	CreatedAt         time.Time
	StartedAt         time.Time
	FinishedAt        time.Time
	GeneratedAt       time.Time
	SchemaVersion     string
	TemplateVersion   int
	OverallStatus     string
	Completeness      AdminReportCompleteness
	Notes             []string
	Summary           AdminReportSummary
	TaskID            string
	ExecutorID        string
	ErrorCode         string
	FailureReason     string
	RequestID         string
	Artifacts         []AdminReportArtifactInfo
	ArtifactExpiresAt time.Time
	RetryOf           string
}

// AdminReportRetentionPolicy 是报告文件保留说明（只读）。
type AdminReportRetentionPolicy struct {
	ArtifactTTL    time.Duration
	CleanupGrace   time.Duration
	EligibleBefore time.Time
	Source         string
	HistoryNote    string
	RawAuditNote   string
}

// AdminReportCleanupTarget 是一个到期可清理目标（不含路径）。
type AdminReportCleanupTarget struct {
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

// AdminReportCleanupPreviewRequest 预览报告产物清理。
type AdminReportCleanupPreviewRequest struct {
	Caller    AdminCaller
	RequestID string
}

// AdminReportCleanupPreview 是清理预览（不是授权凭证）。
type AdminReportCleanupPreview struct {
	Policy          AdminReportRetentionPolicy
	Targets         []AdminReportCleanupTarget
	TargetCount     int
	TotalBytes      int64
	Scopes          []string
	OldestExpiresAt time.Time
	NewestExpiresAt time.Time
	PreviewedAt     time.Time
	Note            string
}

// AdminReportCleanupRequest 执行报告产物清理（原因必填；敏感操作需再次认证）。
type AdminReportCleanupRequest struct {
	Caller     AdminCaller
	Reason     string
	MaxTargets int
	Password   string
	TOTPCode   string
	RequestID  string
}

// AdminReportCleanupFailure 是单目标清理失败的真实原因。
type AdminReportCleanupFailure struct {
	ReportID string
	Reason   string
}

// AdminReportCleanupResult 是清理真实结果。
type AdminReportCleanupResult struct {
	OperatorType   string
	OperatorID     string
	StartedAt      time.Time
	FinishedAt     time.Time
	RequestedCount int
	CleanedCount   int
	FailedCount    int
	DeletedFiles   int
	FreedBytes     int64
	SkippedCount   int
	Failures       []AdminReportCleanupFailure
	Policy         AdminReportRetentionPolicy
	RawAuditNote   string
}

// reportsPublicFacade 实现 ReportsService。
type reportsPublicFacade struct{ r *Runtime }

// Reports 返回报告公开门面。
func (r *Runtime) Reports() ReportsService { return &reportsPublicFacade{r: r} }

// admin 返回共享 AdminCaller 解析器。
func (f *reportsPublicFacade) admin() *adminFacade { return &adminFacade{r: f.r} }

// Capabilities 返回真实可用格式与上限。
func (f *reportsPublicFacade) Capabilities(ctx context.Context,
	req AdminReportCapabilitiesRequest) (AdminReportCapabilities, error) {
	call, err := f.admin().begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminReportCapabilities{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Reports == nil {
		return AdminReportCapabilities{}, call.configError("报告服务未装配")
	}
	formats := []string{string(reports.FormatHTML), string(reports.FormatCSV),
		string(reports.FormatJSON), string(reports.FormatMarkdown)}
	pdf := managed.Reports.PDFAvailable()
	if pdf {
		formats = append(formats, string(reports.FormatPDF))
	}
	return AdminReportCapabilities{Formats: formats, PDFAvailable: pdf,
		MarkdownAvailable: true, DefaultDetailRows: reports.DefaultDetailRows,
		MaxDetailRows: reports.MaxDetailRows}, nil
}

// Start 创建即时统计报告。
func (f *reportsPublicFacade) Start(ctx context.Context,
	req AdminReportStartRequest) (AdminReport, error) {
	call, err := f.admin().begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminReport{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Reports == nil {
		return AdminReport{}, call.configError("报告服务未装配")
	}
	caller, err := f.admin().accountCaller(call.identity)
	if err != nil {
		return AdminReport{}, call.configError("报告服务调用者无效")
	}
	formats := make([]reports.Format, 0, len(req.Formats))
	for _, raw := range req.Formats {
		format := reports.Format(strings.TrimSpace(raw))
		if !format.Valid() {
			return AdminReport{}, call.domainError("报告格式只支持 html/csv/json/pdf/markdown",
				"REQ_INVALID")
		}
		if format == reports.FormatPDF && !managed.Reports.PDFAvailable() {
			return AdminReport{}, call.domainError("PDF 输出需要配置受控中文字体", "REQ_INVALID")
		}
		formats = append(formats, format)
	}
	categories := make([]stats.Category, 0, len(req.Categories))
	for _, raw := range req.Categories {
		categories = append(categories, stats.Category(strings.TrimSpace(raw)))
	}
	approved, err := f.admin().sensitiveContext(ctx, call.identity,
		reports.OperationExport, "report", "", nil, req.Password, req.TOTPCode,
		call.requestID)
	if err != nil {
		return AdminReport{}, err
	}
	view, err := managed.Reports.Start(approved, reports.StartRequest{
		Caller: caller, ScopeID: strings.TrimSpace(req.ScopeID),
		Window: stats.WindowRequest{TimeZone: strings.TrimSpace(req.TimeZone),
			Start: req.Start, End: req.End,
			Granularity: stats.Granularity(strings.TrimSpace(req.Granularity))},
		AppID: strings.TrimSpace(req.AppID), Categories: categories,
		TrendMetric:   stats.Metric(strings.TrimSpace(req.TrendMetric)),
		Formats:       formats,
		MaxDetailRows: req.MaxDetailRows,
		RequestID:     call.requestID})
	if err != nil {
		return AdminReport{}, mapReportError(call, "创建报告失败", err)
	}
	return toAdminReport(view), nil
}

// Get 查询报告状态。
func (f *reportsPublicFacade) Get(ctx context.Context,
	req AdminReportRequest) (AdminReport, error) {
	call, err := f.admin().begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminReport{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Reports == nil {
		return AdminReport{}, call.configError("报告服务未装配")
	}
	caller, err := f.admin().accountCaller(call.identity)
	if err != nil {
		return AdminReport{}, call.configError("报告服务调用者无效")
	}
	view, err := managed.Reports.Get(ctx, caller, strings.TrimSpace(req.ReportID))
	if err != nil {
		return AdminReport{}, mapReportError(call, "读取报告失败", err)
	}
	return toAdminReport(view), nil
}

// Cancel 请求取消报告生成。
func (f *reportsPublicFacade) Cancel(ctx context.Context,
	req AdminReportCancelRequest) (AdminTaskCancelResult, error) {
	call, err := f.admin().begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminTaskCancelResult{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Reports == nil {
		return AdminTaskCancelResult{}, call.configError("报告服务未装配")
	}
	caller, err := f.admin().accountCaller(call.identity)
	if err != nil {
		return AdminTaskCancelResult{}, call.configError("报告服务调用者无效")
	}
	result, err := managed.Reports.Cancel(ctx, caller, strings.TrimSpace(req.ReportID),
		strings.TrimSpace(req.Reason), call.requestID)
	if err != nil {
		return AdminTaskCancelResult{}, mapReportError(call, "取消报告失败", err)
	}
	return AdminTaskCancelResult{TaskID: strings.TrimSpace(req.ReportID),
		Accepted: result.Accepted, AlreadyRequested: result.AlreadyRequested,
		State: string(result.State),
		Note:  "取消请求被接受不等于已取消，请用 Get 确认真实状态"}, nil
}

// Retry 重试报告生成（敏感操作）。
func (f *reportsPublicFacade) Retry(ctx context.Context,
	req AdminReportRetryRequest) (AdminReport, error) {
	call, err := f.admin().begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminReport{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Reports == nil {
		return AdminReport{}, call.configError("报告服务未装配")
	}
	caller, err := f.admin().accountCaller(call.identity)
	if err != nil {
		return AdminReport{}, call.configError("报告服务调用者无效")
	}
	approved, err := f.admin().sensitiveContext(ctx, call.identity,
		reports.OperationExport, "report", strings.TrimSpace(req.ReportID), nil,
		req.Password, req.TOTPCode, call.requestID)
	if err != nil {
		return AdminReport{}, err
	}
	view, err := managed.Reports.Retry(approved, caller, strings.TrimSpace(req.ReportID),
		strings.TrimSpace(req.Reason), call.requestID)
	if err != nil {
		return AdminReport{}, mapReportError(call, "重试报告失败", err)
	}
	return toAdminReport(view), nil
}

// OpenArtifact 流式读取报告产物。
func (f *reportsPublicFacade) OpenArtifact(ctx context.Context,
	req AdminReportArtifactRequest) (AdminDownload, error) {
	call, err := f.admin().begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminDownload{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Reports == nil {
		return AdminDownload{}, call.configError("报告服务未装配")
	}
	caller, err := f.admin().accountCaller(call.identity)
	if err != nil {
		return AdminDownload{}, call.configError("报告服务调用者无效")
	}
	format := reports.Format(strings.TrimSpace(req.Format))
	if !format.Valid() {
		return AdminDownload{}, call.domainError("报告格式无效", "REQ_INVALID")
	}
	handle, err := managed.Reports.OpenFile(ctx, caller,
		strings.TrimSpace(req.ReportID), format)
	if err != nil {
		return AdminDownload{}, mapReportError(call, "打开报告产物失败", err)
	}
	return openAdminFile(handle.HostPath, filepath.Base(handle.HostPath), handle.Bytes,
		handle.SHA256, handle.ExpiresAt, reportContentType(format))
}

// CleanupPreview 预览报告产物清理。
func (f *reportsPublicFacade) CleanupPreview(ctx context.Context,
	req AdminReportCleanupPreviewRequest) (AdminReportCleanupPreview, error) {
	call, err := f.admin().begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminReportCleanupPreview{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Reports == nil {
		return AdminReportCleanupPreview{}, call.configError("报告服务未装配")
	}
	caller, err := f.admin().accountCaller(call.identity)
	if err != nil {
		return AdminReportCleanupPreview{}, call.configError("报告服务调用者无效")
	}
	preview, err := managed.Reports.CleanupPreview(ctx, caller)
	if err != nil {
		return AdminReportCleanupPreview{}, mapReportError(call, "预览报告清理失败", err)
	}
	return toAdminReportCleanupPreview(preview), nil
}

// CleanupExecute 执行报告产物清理（敏感操作）。
func (f *reportsPublicFacade) CleanupExecute(ctx context.Context,
	req AdminReportCleanupRequest) (AdminReportCleanupResult, error) {
	call, err := f.admin().begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminReportCleanupResult{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Reports == nil {
		return AdminReportCleanupResult{}, call.configError("报告服务未装配")
	}
	caller, err := f.admin().accountCaller(call.identity)
	if err != nil {
		return AdminReportCleanupResult{}, call.configError("报告服务调用者无效")
	}
	approved, err := f.admin().sensitiveContext(ctx, call.identity,
		reports.OperationCleanup, "report_cleanup", "", nil, req.Password, req.TOTPCode,
		call.requestID)
	if err != nil {
		return AdminReportCleanupResult{}, err
	}
	result, err := managed.Reports.CleanupExecute(approved, reports.CleanupExecuteRequest{
		Caller: caller, Reason: strings.TrimSpace(req.Reason),
		MaxTargets: req.MaxTargets, RequestID: call.requestID})
	if err != nil {
		return AdminReportCleanupResult{}, mapReportError(call, "清理报告产物失败", err)
	}
	return toAdminReportCleanupResult(result), nil
}

// mapReportError 统一映射 reports 领域错误。
func mapReportError(call adminRequest, message string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, reports.ErrNotFound) {
		return call.notFound("report")
	}
	return call.domainError(message, string(reports.CodeOf(err)))
}

// reportContentType 返回报告格式内容类型。
func reportContentType(format reports.Format) string {
	switch format {
	case reports.FormatHTML:
		return "text/html; charset=utf-8"
	case reports.FormatCSV:
		return "text/csv; charset=utf-8"
	case reports.FormatJSON:
		return "application/json; charset=utf-8"
	case reports.FormatPDF:
		return "application/pdf"
	case reports.FormatMarkdown:
		return "text/markdown; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}

// toAdminReport 投影报告视图（无路径）。
func toAdminReport(view reports.ReportView) AdminReport {
	result := AdminReport{ID: view.ID, ScopeID: view.ScopeID, ScopeKind: view.ScopeKind,
		State: view.State, RequestedType: string(view.RequestedBy.Type),
		RequestedID: view.RequestedBy.ID, CreatedAt: view.CreatedAt,
		StartedAt: view.StartedAt, FinishedAt: view.FinishedAt,
		GeneratedAt: view.GeneratedAt, SchemaVersion: view.SchemaVersion,
		TemplateVersion: view.TemplateVersion, OverallStatus: view.OverallStatus,
		TaskID: view.TaskID, ExecutorID: view.ExecutorID, ErrorCode: view.ErrorCode,
		FailureReason: view.FailureReason, RequestID: view.RequestID,
		ArtifactExpiresAt: view.ArtifactExpiresAt, RetryOf: view.RetryOf,
		Summary: AdminReportSummary{ActiveUsers: view.Summary.ActiveUsers,
			TotalRawEvents: view.Summary.TotalRawEvents,
			FailedRequests: view.Summary.FailedRequests,
			FailedTasks:    view.Summary.FailedTasks,
			DetailRows:     view.Summary.DetailRows,
			TrendPoints:    view.Summary.TrendPoints},
		Completeness: AdminReportCompleteness{
			WindowWithinRetention: view.Completeness.WindowWithinRetention,
			RetentionDays:         view.Completeness.RetentionDays,
			RetentionConfigured:   view.Completeness.RetentionConfigured,
			RetentionCutoff:       view.Completeness.RetentionCutoff.Time,
			ScopeTrimmed:          view.Completeness.ScopeTrimmed,
			SourceTruncated:       view.Completeness.SourceTruncated,
			DetailRowsTruncated:   view.Completeness.DetailRowsTruncated,
			ModulesNotEnabled: append([]string(nil),
				view.Completeness.ModulesNotEnabled...),
			TrendPointsTruncated: view.Completeness.TrendPointsTruncated,
		},
		Notes: append([]string(nil), view.Notes...)}
	for _, interval := range view.Completeness.MissingIntervals {
		result.Completeness.MissingIntervals = append(
			result.Completeness.MissingIntervals, AdminStatsMissingInterval{
				Start: interval.Start, End: interval.End, Reason: interval.Reason})
	}
	for _, format := range view.Formats {
		result.Formats = append(result.Formats, string(format))
	}
	for _, artifact := range view.Artifacts {
		result.Artifacts = append(result.Artifacts, AdminReportArtifactInfo{
			Format: string(artifact.Format), Bytes: artifact.Bytes,
			SHA256: artifact.SHA256, Available: artifact.Available,
			ExpiresAt: artifact.ExpiresAt})
	}
	return result
}

// toAdminReportCleanupPreview 投影清理预览。
func toAdminReportCleanupPreview(preview reports.CleanupPreview) AdminReportCleanupPreview {
	result := AdminReportCleanupPreview{
		Policy: AdminReportRetentionPolicy{
			ArtifactTTL:    preview.Policy.ArtifactTTL,
			CleanupGrace:   preview.Policy.CleanupGrace,
			EligibleBefore: preview.Policy.EligibleBefore,
			Source:         preview.Policy.Source, HistoryNote: preview.Policy.HistoryNote,
			RawAuditNote: preview.Policy.RawAuditNote},
		TargetCount: preview.TargetCount, TotalBytes: preview.TotalBytes,
		OldestExpiresAt: preview.OldestExpiresAt,
		NewestExpiresAt: preview.NewestExpiresAt,
		PreviewedAt:     preview.PreviewedAt, Note: preview.Note,
		Scopes: append([]string(nil), preview.Scopes...)}
	for _, target := range preview.Targets {
		item := AdminReportCleanupTarget{ReportID: target.ReportID, PlanID: target.PlanID,
			Name: target.Name, ScopeID: target.ScopeID, State: target.State,
			CleanupState: target.CleanupState, ExpiresAt: target.ExpiresAt,
			ArtifactCount: target.ArtifactCount, Bytes: target.Bytes}
		for _, format := range target.Formats {
			item.Formats = append(item.Formats, string(format))
		}
		result.Targets = append(result.Targets, item)
	}
	return result
}

// toAdminReportCleanupResult 投影清理结果。
func toAdminReportCleanupResult(result reports.CleanupResult) AdminReportCleanupResult {
	view := AdminReportCleanupResult{OperatorType: string(result.Operator.Type),
		OperatorID: result.Operator.ID, StartedAt: result.StartedAt,
		FinishedAt: result.FinishedAt, RequestedCount: result.RequestedCount,
		CleanedCount: result.CleanedCount, FailedCount: result.FailedCount,
		DeletedFiles: result.DeletedFiles, FreedBytes: result.FreedBytes,
		SkippedCount: result.SkippedCount, RawAuditNote: result.RawAuditNote,
		Policy: AdminReportRetentionPolicy{
			ArtifactTTL:    result.Policy.ArtifactTTL,
			CleanupGrace:   result.Policy.CleanupGrace,
			EligibleBefore: result.Policy.EligibleBefore,
			Source:         result.Policy.Source,
			HistoryNote:    result.Policy.HistoryNote,
			RawAuditNote:   result.Policy.RawAuditNote}}
	for _, failure := range result.Failures {
		view.Failures = append(view.Failures, AdminReportCleanupFailure{
			ReportID: failure.ReportID, Reason: failure.Reason})
	}
	return view
}
