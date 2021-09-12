// Package uiadminadapter：步骤 79 报告计划/历史/下载/保留清理页适配器。
//
// 安全边界：适配器只接受页面已通过 UIAccessManagement 验证后传入的操作者用户 ID，
// 每次操作重新构造可信 Caller 并调用真实 internal/reports 服务；每次读取、计划变更、
// 下载、清理都由领域服务重新授权、复核数据范围与敏感操作，页面能力位只影响呈现。
// 下载走一次性短期令牌（签发后立即兑换并再次鉴权），页面响应不包含宿主路径或长期
// 凭证；本适配器不读取前端自报角色、不缓存授权。
package uiadminadapter

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/reports"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// ReportsRecorder 是拒绝留痕契约（生产 *audit.Recorder）。
type ReportsRecorder interface {
	RecordFailure(ctx context.Context, event audit.Event) error
}

// ReportsOptions 是报告页适配器依赖。Reports/Plans 必填；Authorizer/Root 用于
// 能力位判定（只影响呈现，真实授权仍由领域服务执行）；Recorder 用于拒绝留痕。
type ReportsOptions struct {
	Reports    *reports.Service
	Plans      *reports.PlanService
	Authorizer reports.Authorizer
	Root       reports.RootChecker
	Recorder   ReportsRecorder
	Now        func() time.Time
}

// ReportsAdapter 实现 login.UIPageReportsBackend。
type ReportsAdapter struct {
	opts ReportsOptions
}

// NewReports 校验依赖并构造报告页适配器。
func NewReports(options ReportsOptions) (*ReportsAdapter, error) {
	if options.Reports == nil || options.Plans == nil {
		return nil, errors.New("报告页适配器缺少报告服务或计划服务")
	}
	if options.Authorizer == nil || options.Root == nil {
		return nil, errors.New("报告页适配器缺少授权或 root 判定")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &ReportsAdapter{opts: options}, nil
}

// reportsCaller 把页面已认证用户 ID 重建为可信 Caller。
func reportsCaller(userID string) (account.Caller, error) {
	if userID == "" || !account.ValidUserID(userID) {
		return account.Caller{}, &login.UIReportsError{Code: "ACCESS_DENIED"}
	}
	return account.UserCaller(userID)
}

// mapReportsError 把领域错误映射为页面稳定错误码（不泄漏内部细节）。
func mapReportsError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, reports.ErrAccessDenied):
		return &login.UIReportsError{Code: "ACCESS_DENIED"}
	case errors.Is(err, reports.ErrNotFound):
		return &login.UIReportsError{Code: "NOT_FOUND"}
	case errors.Is(err, reports.ErrConflict), errors.Is(err, reports.ErrTicketExpired),
		errors.Is(err, reports.ErrTicketInvalid), errors.Is(err, reports.ErrTicketAccessDenied):
		return &login.UIReportsError{Code: "CONFLICT"}
	case errors.Is(err, reports.ErrInvalidRequest), errors.Is(err, reports.ErrTicketNotAllowed):
		return &login.UIReportsError{Code: "INVALID"}
	default:
		return &login.UIReportsError{Code: "UNAVAILABLE"}
	}
}

// allow 判定当前用户在系统范围的某个报告权限（仅能力位/呈现辅助）。
func (a *ReportsAdapter) allow(ctx context.Context, caller account.Caller,
	permission string) bool {
	if a.opts.Root != nil {
		if root, err := a.opts.Root.IsRoot(ctx, caller); err == nil && root {
			return true
		}
	}
	grant, err := a.opts.Authorizer.AuthorizeScope(ctx, caller, permission,
		reports.ScopeSystem)
	return err == nil && grant.Allowed
}

// Capabilities 实现 login.UIPageReportsBackend。
func (a *ReportsAdapter) Capabilities(ctx context.Context,
	userID string) (login.UIReportsCapabilities, error) {
	caller, err := reportsCaller(userID)
	if err != nil {
		return login.UIReportsCapabilities{}, err
	}
	return login.UIReportsCapabilities{
		Read:           a.allow(ctx, caller, reports.PermissionRead),
		Generate:       a.allow(ctx, caller, reports.PermissionGenerate),
		Export:         a.allow(ctx, caller, reports.PermissionExport),
		ScheduleManage: a.allow(ctx, caller, reports.PermissionScheduleManage),
		Cleanup:        a.allow(ctx, caller, reports.PermissionCleanup),
		DownloadTTL:    a.opts.Reports.DownloadTicketTTL(),
	}, nil
}

// RecordDenial 实现 login.UIPageReportsBackend。
func (a *ReportsAdapter) RecordDenial(ctx context.Context, userID, reason string) error {
	if a.opts.Recorder == nil {
		return nil
	}
	actor := audit.Actor{Type: audit.ActorUser, ID: userID}
	if err := actor.Validate(); err != nil {
		return nil
	}
	return a.opts.Recorder.RecordFailure(ctx, audit.Event{
		Actor: actor, Action: reports.ActionAccessDenied,
		Target:  audit.Target{Type: "report_page", ID: "reports_ui"},
		Outcome: audit.OutcomeDenied, ErrorCode: string(reports.CodeAccessDenied),
		ReasonCode: safeDenialToken(reason),
	})
}

// planView 把计划领域视图映射为页面视图。
func planView(view reports.PlanView) login.UIReportPlan {
	formats := make([]string, 0, len(view.Formats))
	for _, format := range view.Formats {
		formats = append(formats, string(format))
	}
	categories := make([]string, 0, len(view.Categories))
	for _, category := range view.Categories {
		categories = append(categories, string(category))
	}
	return login.UIReportPlan{
		ID: view.ID, ScheduleID: view.ScheduleID, Version: view.Version,
		Name: view.Name, Enabled: view.Enabled,
		PermissionState: view.PermissionState, PermissionReason: view.PermissionReason,
		ScheduleType: string(view.ScheduleType), Expression: view.Expression,
		TimeZone: view.TimeZone, PeriodDescription: view.PeriodDescription,
		ScopeID: view.ScopeID, ScopeKind: view.ScopeKind, AppID: view.AppID,
		Granularity: string(view.Granularity), WindowDays: view.WindowDays,
		Categories: categories, TrendMetric: string(view.TrendMetric),
		Formats: formats, DetailRows: view.DetailRows,
		MissedPolicy: string(view.MissedPolicy), MaxCatchUp: view.MaxCatchUp,
		TimeoutSeconds: view.TimeoutSeconds, MaxAttempts: view.MaxAttempts,
		Owner: planOwnerText(view.Owner), ExecutionActor: planOwnerText(view.ExecutionActor),
		NextRun: view.NextRun, NextRunUnknown: view.NextRunUnknown,
		CreatedAt: view.CreatedAt, UpdatedAt: view.UpdatedAt,
	}
}

// planOwnerText 只显示身份类型与稳定 ID，不披露账户资料。
func planOwnerText(actor audit.Actor) string {
	return string(actor.Type) + " · " + actor.ID
}

// ListPlans 实现 login.UIPageReportsBackend。
func (a *ReportsAdapter) ListPlans(ctx context.Context,
	userID string) ([]login.UIReportPlan, error) {
	caller, err := reportsCaller(userID)
	if err != nil {
		return nil, err
	}
	views, err := a.opts.Plans.List(ctx, caller)
	if err != nil {
		return nil, mapReportsError(err)
	}
	plans := make([]login.UIReportPlan, 0, len(views))
	for _, view := range views {
		plans = append(plans, planView(view))
	}
	return plans, nil
}

// GetPlan 实现 login.UIPageReportsBackend。
func (a *ReportsAdapter) GetPlan(ctx context.Context, userID,
	planID string) (login.UIReportPlan, error) {
	caller, err := reportsCaller(userID)
	if err != nil {
		return login.UIReportPlan{}, err
	}
	view, err := a.opts.Plans.Get(ctx, caller, strings.TrimSpace(planID))
	if err != nil {
		return login.UIReportPlan{}, mapReportsError(err)
	}
	return planView(view), nil
}

// planRequest 把页面请求映射为领域创建请求。
func planRequest(userID string, request login.UIReportPlanRequest,
	requestID string) (reports.PlanCreateRequest, error) {
	caller, err := reportsCaller(userID)
	if err != nil {
		return reports.PlanCreateRequest{}, err
	}
	formats := make([]reports.Format, 0, len(request.Formats))
	for _, rawFormat := range request.Formats {
		format := reports.Format(rawFormat)
		if !format.Valid() {
			return reports.PlanCreateRequest{}, &login.UIReportsError{Code: "INVALID"}
		}
		formats = append(formats, format)
	}
	categories := make([]stats.Category, 0, len(request.Categories))
	for _, rawCategory := range request.Categories {
		category := stats.Category(rawCategory)
		if !category.Valid() {
			return reports.PlanCreateRequest{}, &login.UIReportsError{Code: "INVALID"}
		}
		categories = append(categories, category)
	}
	return reports.PlanCreateRequest{
		Caller: caller, Name: request.Name,
		ScheduleType: task.ScheduleType(strings.TrimSpace(request.ScheduleType)),
		Expression:   request.Expression, TimeZone: request.TimeZone,
		ScopeID:     reportScopeOrDefault(request.ScopeID),
		Granularity: stats.Granularity(request.Granularity),
		WindowDays:  request.WindowDays, AppID: "",
		Categories: categories, TrendMetric: stats.Metric(request.TrendMetric),
		Formats: formats, DetailRows: request.DetailRows,
		MissedPolicy:   task.MissedPolicy(strings.TrimSpace(request.MissedPolicy)),
		MaxCatchUp:     request.MaxCatchUp,
		TimeoutSeconds: request.TimeoutSeconds, MaxAttempts: request.MaxAttempts,
		Enabled: request.Enabled, RequestID: requestID,
	}, nil
}

// reportScopeOrDefault 归一化页面范围：空值使用系统范围，应用范围必须是稳定 ID；
// 真实越权判断仍由领域服务对旧/新范围双重授权。
func reportScopeOrDefault(scopeID string) string {
	scopeID = strings.TrimSpace(scopeID)
	if scopeID == "" {
		return reports.ScopeSystem
	}
	return scopeID
}

// CreatePlan 实现 login.UIPageReportsBackend。
func (a *ReportsAdapter) CreatePlan(ctx context.Context, userID string,
	request login.UIReportPlanRequest, requestID string) (login.UIReportPlan, error) {
	domainRequest, err := planRequest(userID, request, requestID)
	if err != nil {
		return login.UIReportPlan{}, err
	}
	view, err := a.opts.Plans.Create(ctx, domainRequest)
	if err != nil {
		return login.UIReportPlan{}, mapReportsError(err)
	}
	return planView(view), nil
}

// UpdatePlan 实现 login.UIPageReportsBackend。
func (a *ReportsAdapter) UpdatePlan(ctx context.Context, userID, planID string,
	version int64, request login.UIReportPlanRequest,
	requestID string) (login.UIReportPlan, error) {
	domainRequest, err := planRequest(userID, request, requestID)
	if err != nil {
		return login.UIReportPlan{}, err
	}
	view, err := a.opts.Plans.Update(ctx, reports.PlanUpdateRequest{
		PlanCreateRequest: domainRequest, PlanID: strings.TrimSpace(planID),
		Version: version, Reason: strings.TrimSpace(request.Reason),
	})
	if err != nil {
		return login.UIReportPlan{}, mapReportsError(err)
	}
	return planView(view), nil
}

// SetPlanEnabled 实现 login.UIPageReportsBackend。
func (a *ReportsAdapter) SetPlanEnabled(ctx context.Context, userID, planID string,
	enabled bool, reason, requestID string) (login.UIReportPlan, error) {
	caller, err := reportsCaller(userID)
	if err != nil {
		return login.UIReportPlan{}, err
	}
	view, err := a.opts.Plans.SetEnabled(ctx, caller, strings.TrimSpace(planID),
		enabled, strings.TrimSpace(reason), requestID)
	if err != nil {
		return login.UIReportPlan{}, mapReportsError(err)
	}
	return planView(view), nil
}

// PlanDeletePreview 实现 login.UIPageReportsBackend。
func (a *ReportsAdapter) PlanDeletePreview(ctx context.Context, userID,
	planID string) (login.UIReportPlanDeletePreview, error) {
	caller, err := reportsCaller(userID)
	if err != nil {
		return login.UIReportPlanDeletePreview{}, err
	}
	preview, err := a.opts.Plans.DeletePreview(ctx, caller, strings.TrimSpace(planID))
	if err != nil {
		return login.UIReportPlanDeletePreview{}, mapReportsError(err)
	}
	return login.UIReportPlanDeletePreview{
		PlanID: preview.PlanID, Name: preview.Name, ScopeID: preview.ScopeID,
		Enabled: preview.Enabled, NextRun: preview.NextRun,
		NextRunUnknown: preview.NextRunUnknown, MissedPolicy: preview.MissedPolicy,
		ActiveTasksNote: preview.ActiveTasksNote, HistoryNote: preview.HistoryNote,
		RawAuditNote: preview.RawAuditNote, Irreversible: preview.Irreversible,
		PermissionState: preview.PermissionState, PermissionReason: preview.PermissionReason,
		CreatedAt: preview.CreatedAt, PreviewedAt: preview.PreviewedAt,
	}, nil
}

// DeletePlan 实现 login.UIPageReportsBackend。
func (a *ReportsAdapter) DeletePlan(ctx context.Context, userID, planID, reason,
	requestID string) error {
	caller, err := reportsCaller(userID)
	if err != nil {
		return err
	}
	return mapReportsError(a.opts.Plans.Delete(ctx, caller, strings.TrimSpace(planID),
		strings.TrimSpace(reason), requestID))
}

// ListHistory 实现 login.UIPageReportsBackend。
func (a *ReportsAdapter) ListHistory(ctx context.Context, userID string,
	query login.UIReportHistoryQuery) (login.UIReportHistoryPage, error) {
	caller, err := reportsCaller(userID)
	if err != nil {
		return login.UIReportHistoryPage{}, err
	}
	page, err := a.opts.Reports.HistoryList(ctx, reports.HistoryListRequest{
		Caller: caller, PlanID: strings.TrimSpace(query.PlanID),
		State: strings.TrimSpace(query.State), Limit: query.Limit,
		BeforeCreatedAt: query.BeforeCreatedAt, BeforeID: query.BeforeID,
	})
	if err != nil {
		return login.UIReportHistoryPage{}, mapReportsError(err)
	}
	records := make([]login.UIReportHistoryEntry, 0, len(page.Records))
	for _, record := range page.Records {
		records = append(records, historyEntry(record))
	}
	return login.UIReportHistoryPage{Records: records, HasMore: page.HasMore}, nil
}

// historyEntry 把历史领域视图映射为页面条目。
func historyEntry(record reports.ReportHistoryView) login.UIReportHistoryEntry {
	entry := login.UIReportHistoryEntry{
		ID: record.ID, PlanID: record.PlanID, Name: record.Name,
		ScopeID: record.ScopeID, ScopeKind: record.ScopeKind, State: record.State,
		Formats: make([]string, 0, len(record.Formats)),
		Owner:   planOwnerText(record.Owner),
		TaskID:  record.TaskID, ErrorCode: record.ErrorCode,
		FailureReason: truncateReportText(record.FailureReason),
		RequestID:     record.RequestID, CreatedAt: record.CreatedAt,
		StartedAt: record.StartedAt, FinishedAt: record.FinishedAt,
		ExpiresAt: record.ExpiresAt, CleanupState: record.CleanupState,
	}
	for _, format := range record.Formats {
		entry.Formats = append(entry.Formats, string(format))
	}
	return entry
}

// truncateReportText 裁剪展示用失败原因，避免超长自由文本进入页面。
func truncateReportText(value string) string {
	value = strings.TrimSpace(value)
	runes := []rune(value)
	if len(runes) <= 200 {
		return value
	}
	return string(runes[:200]) + "…"
}

// GetReport 实现 login.UIPageReportsBackend：返回受控元数据与当前仍可用的格式。
func (a *ReportsAdapter) GetReport(ctx context.Context, userID,
	reportID string) (login.UIReportDetail, error) {
	caller, err := reportsCaller(userID)
	if err != nil {
		return login.UIReportDetail{}, err
	}
	view, err := a.opts.Reports.Get(ctx, caller, strings.TrimSpace(reportID))
	if err != nil {
		return login.UIReportDetail{}, mapReportsError(err)
	}
	detail := login.UIReportDetail{
		ID: view.ID, ScopeID: view.ScopeID, ScopeKind: view.ScopeKind,
		State: view.State, RequestedBy: planOwnerText(view.RequestedBy),
		CreatedAt: view.CreatedAt, StartedAt: view.StartedAt,
		FinishedAt: view.FinishedAt, GeneratedAt: view.GeneratedAt,
		OverallStatus: view.OverallStatus,
		TaskID:        view.TaskID, ExecutorID: view.ExecutorID,
		ErrorCode:     view.ErrorCode,
		FailureReason: truncateReportText(view.FailureReason),
		RequestID:     view.RequestID, SchemaVersion: view.SchemaVersion,
		TemplateVersion:   view.TemplateVersion,
		ArtifactExpiresAt: view.ArtifactExpiresAt, RetryOf: view.RetryOf,
		Formats:   make([]string, 0, len(view.Formats)),
		Artifacts: make([]login.UIReportArtifact, 0, len(view.Artifacts)),
	}
	for _, format := range view.Formats {
		detail.Formats = append(detail.Formats, string(format))
	}
	now := a.opts.Now()
	for _, artifact := range view.Artifacts {
		detail.Artifacts = append(detail.Artifacts, login.UIReportArtifact{
			Format:    string(artifact.Format),
			Bytes:     artifact.Bytes,
			SHA256:    artifact.SHA256,
			Available: artifact.Available && now.Before(artifact.ExpiresAt),
			ExpiresAt: artifact.ExpiresAt,
		})
	}
	return detail, nil
}

// Download 实现 login.UIPageReportsBackend：签发一次性令牌并立即兑换，读取受控
// 产物字节；每次调用都由领域服务重新授权并写下载审计。
func (a *ReportsAdapter) Download(ctx context.Context, userID, reportID,
	formatText string) (login.UIReportFile, error) {
	caller, err := reportsCaller(userID)
	if err != nil {
		return login.UIReportFile{}, err
	}
	format := reports.Format(strings.TrimSpace(formatText))
	if !format.Valid() {
		return login.UIReportFile{}, &login.UIReportsError{Code: "INVALID"}
	}
	ticket, err := a.opts.Reports.IssueDownloadTicket(ctx, caller,
		strings.TrimSpace(reportID), format)
	if err != nil {
		return login.UIReportFile{}, mapReportsError(err)
	}
	artifact, err := a.opts.Reports.RedeemDownloadTicket(ctx, caller, ticket.Token)
	if err != nil {
		return login.UIReportFile{}, mapReportsError(err)
	}
	if artifact.Bytes < 1 || artifact.Bytes > reports.MaxArtifactBytes {
		return login.UIReportFile{}, &login.UIReportsError{Code: "UNAVAILABLE"}
	}
	data, err := os.ReadFile(artifact.HostPath)
	if err != nil || int64(len(data)) != artifact.Bytes {
		return login.UIReportFile{}, &login.UIReportsError{Code: "UNAVAILABLE"}
	}
	return login.UIReportFile{
		ReportID: artifact.ReportID, Format: string(artifact.Format),
		FileName:    downloadFileName(artifact.ReportID, artifact.Format),
		ContentType: downloadContentType(artifact.Format),
		Bytes:       data, Size: artifact.Bytes,
		ExpiresAt: artifact.ExpiresAt,
	}, nil
}

// downloadFileName 返回受控下载文件名（不含路径）。
func downloadFileName(reportID string, format reports.Format) string {
	extension := string(format)
	if format == reports.FormatMarkdown {
		extension = "md"
	}
	return "report_" + reportID + "." + extension
}

// downloadContentType 返回安全的下载内容类型。
func downloadContentType(format reports.Format) string {
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

// Preview 实现 login.UIPageReportsBackend：从固定快照返回受控预览，缺失数据
// 以状态字段呈现，不用 0 填充。
func (a *ReportsAdapter) Preview(ctx context.Context, userID,
	reportID string) (login.UIReportPreview, error) {
	caller, err := reportsCaller(userID)
	if err != nil {
		return login.UIReportPreview{}, err
	}
	snapshot, err := a.opts.Reports.GetSnapshot(ctx, caller,
		strings.TrimSpace(reportID))
	if err != nil {
		return login.UIReportPreview{}, mapReportsError(err)
	}
	preview := login.UIReportPreview{
		ReportID: snapshot.Report.ID, OverallStatus: string(snapshot.Overall),
		GeneratedAt:           snapshot.Report.GeneratedAt,
		ActivityTotal:         snapshot.Activity.Total,
		RawEvents:             snapshot.Errors.TotalRawEvents,
		FailedRequests:        snapshot.Errors.FailedRequests,
		FailedTasks:           snapshot.Errors.FailedTasks,
		DetailRowCount:        len(snapshot.Errors.Rows),
		Notes:                 append([]string(nil), snapshot.Notes...),
		WindowWithinRetention: snapshot.Completeness.WindowWithinRetention,
		RetentionDays:         snapshot.Completeness.RetentionDays,
		RetentionConfigured:   snapshot.Completeness.RetentionConfigured,
		ScopeTrimmed:          snapshot.Completeness.ScopeTrimmed,
		SourceTruncated:       snapshot.Completeness.SourceTruncated,
		DetailRowsTruncated:   snapshot.Completeness.DetailRowsTruncated,
		MissingReasons:        make([]string, 0, len(snapshot.Completeness.MissingIntervals)),
		ErrorRows:             make([]login.UIReportPreviewRow, 0, len(snapshot.Errors.Rows)),
	}
	for _, interval := range snapshot.Completeness.MissingIntervals {
		preview.MissingReasons = append(preview.MissingReasons, interval.Reason)
	}
	for _, row := range snapshot.Errors.Rows {
		preview.ErrorRows = append(preview.ErrorRows, login.UIReportPreviewRow{
			ErrorCode: row.ErrorCode, Category: row.Category,
			Severity: row.Severity, RawEvents: row.RawEvents,
			FailedRequests: row.FailedRequests, FailedTasks: row.FailedTasks,
			Status: row.Status,
		})
	}
	return preview, nil
}

// Retry 实现 login.UIPageReportsBackend：领域服务完成当前权限、数据范围与敏感操作
// 复核后创建新运行记录；成功后返回新报告详情。
func (a *ReportsAdapter) Retry(ctx context.Context, userID, reportID, reason,
	requestID string) (login.UIReportDetail, error) {
	caller, err := reportsCaller(userID)
	if err != nil {
		return login.UIReportDetail{}, err
	}
	view, err := a.opts.Reports.Retry(ctx, caller, strings.TrimSpace(reportID),
		strings.TrimSpace(reason), requestID)
	if err != nil {
		return login.UIReportDetail{}, mapReportsError(err)
	}
	return a.GetReport(ctx, userID, view.ID)
}

// Cancel 实现 login.UIPageReportsBackend：调用领域服务取消任务（服务端重新授权、
// 记录真实受理状态与审计）；返回结果不把“请求已受理”写成“已取消”。
func (a *ReportsAdapter) Cancel(ctx context.Context, userID, reportID, reason,
	requestID string) (login.UIReportCancelResult, error) {
	caller, err := reportsCaller(userID)
	if err != nil {
		return login.UIReportCancelResult{}, err
	}
	result, err := a.opts.Reports.Cancel(ctx, caller, strings.TrimSpace(reportID),
		strings.TrimSpace(reason), requestID)
	if err != nil {
		return login.UIReportCancelResult{}, mapReportsError(err)
	}
	note := "取消请求已受理，等待任务状态收敛；受理不等于实际取消。"
	if !result.Accepted {
		note = "服务端未受理取消请求，任务状态以查询结果为准。"
	}
	return login.UIReportCancelResult{ReportID: strings.TrimSpace(reportID),
		Accepted: result.Accepted, State: string(result.State), Note: note}, nil
}

// CleanupPreview 实现 login.UIPageReportsBackend。
func (a *ReportsAdapter) CleanupPreview(ctx context.Context,
	userID string) (login.UIReportCleanupPreview, error) {
	caller, err := reportsCaller(userID)
	if err != nil {
		return login.UIReportCleanupPreview{}, err
	}
	preview, err := a.opts.Reports.CleanupPreview(ctx, caller)
	if err != nil {
		return login.UIReportCleanupPreview{}, mapReportsError(err)
	}
	result := login.UIReportCleanupPreview{
		TargetCount: preview.TargetCount, TotalBytes: preview.TotalBytes,
		Scopes:          append([]string(nil), preview.Scopes...),
		OldestExpiresAt: preview.OldestExpiresAt,
		NewestExpiresAt: preview.NewestExpiresAt,
		PreviewedAt:     preview.PreviewedAt, Note: preview.Note,
		Policy: login.UIReportRetentionPolicy{
			ArtifactTTL:    preview.Policy.ArtifactTTL,
			CleanupGrace:   preview.Policy.CleanupGrace,
			EligibleBefore: preview.Policy.EligibleBefore,
			Source:         preview.Policy.Source,
			HistoryNote:    preview.Policy.HistoryNote,
			RawAuditNote:   preview.Policy.RawAuditNote,
		},
		Targets: make([]login.UIReportCleanupTarget, 0, len(preview.Targets)),
	}
	for _, target := range preview.Targets {
		formats := make([]string, 0, len(target.Formats))
		for _, format := range target.Formats {
			formats = append(formats, string(format))
		}
		result.Targets = append(result.Targets, login.UIReportCleanupTarget{
			ReportID: target.ReportID, PlanID: target.PlanID, Name: target.Name,
			ScopeID: target.ScopeID, State: target.State,
			CleanupState: target.CleanupState, ExpiresAt: target.ExpiresAt,
			Formats: formats, ArtifactCount: target.ArtifactCount,
			Bytes: target.Bytes,
		})
	}
	return result, nil
}

// RunCleanup 实现 login.UIPageReportsBackend。
func (a *ReportsAdapter) RunCleanup(ctx context.Context, userID, reason,
	requestID string) (login.UIReportCleanupResult, error) {
	caller, err := reportsCaller(userID)
	if err != nil {
		return login.UIReportCleanupResult{}, err
	}
	result, err := a.opts.Reports.CleanupExecute(ctx, reports.CleanupExecuteRequest{
		Caller: caller, Reason: strings.TrimSpace(reason), RequestID: requestID,
	})
	if err != nil {
		// 清理可能已部分执行：有真实结果时仍返回结果与错误，由页面显示真实计数。
		if result.RequestedCount > 0 || result.CleanedCount > 0 || result.FailedCount > 0 {
			return uiCleanupResult(result), mapReportsError(err)
		}
		return login.UIReportCleanupResult{}, mapReportsError(err)
	}
	return uiCleanupResult(result), nil
}

// uiCleanupResult 映射清理真实结果。
func uiCleanupResult(result reports.CleanupResult) login.UIReportCleanupResult {
	failures := make([]login.UIReportCleanupFailure, 0, len(result.Failures))
	for _, failure := range result.Failures {
		failures = append(failures, login.UIReportCleanupFailure{
			ReportID: failure.ReportID, Reason: failure.Reason})
	}
	return login.UIReportCleanupResult{
		RequestedCount: result.RequestedCount, CleanedCount: result.CleanedCount,
		FailedCount: result.FailedCount, DeletedFiles: result.DeletedFiles,
		FreedBytes: result.FreedBytes, SkippedCount: result.SkippedCount,
		Failures: failures, RawAuditNote: result.RawAuditNote,
		StartedAt: result.StartedAt, FinishedAt: result.FinishedAt,
	}
}
