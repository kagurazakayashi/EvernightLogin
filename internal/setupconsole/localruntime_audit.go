package setupconsole

// WS3 291 审计/诊断/任务适配器（本地维护只读 + 显式危险动作边界）。
//
// 已实测：真实生产 auditops 授权层允许 actor_local_admin 本地调用者执行**只读**
// 审计查询（冒烟测试证据），因此复用 Base.Managed.AuditOps，不复制审计读取实现。
// 危险清理（purge/保留策略）不在本适配器自动执行：仅保留"明确不可用/需单独确认"
// 的入口，避免把本地绝对权限误接到无法保留独立维护证据的操作。
//
// 报告/通知投递列表依赖 reports/mail 域本地适配，尚返回 ErrLocalUnsupported（画面
// 明确显示不可用，不伪造零结果）；任务列表/取消复用 task.Executor 既有 API，取消
// 实际执行者为本地维护 actor（只接受显式原因）。

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/auditops"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	"github.com/kagurazakayashi/EvernightLogin/internal/reports"
	"github.com/kagurazakayashi/EvernightLogin/internal/serverapp"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
	"github.com/kagurazakayashi/EvernightLogin/migrations"

	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
)

type localAuditAdmin struct {
	base       *serverapp.Base
	operatorID string
}

func newLocalAuditAdmin(base *serverapp.Base, operatorID string) (*localAuditAdmin, error) {
	if base == nil {
		return nil, fmt.Errorf("%w: 实例未装配", ErrLocalRuntimeUnavailable)
	}
	return &localAuditAdmin{base: base, operatorID: operatorID}, nil
}

func (a *localAuditAdmin) caller() (account.Caller, error) {
	return account.LocalBootstrapCaller(a.operatorID)
}

func (a *localAuditAdmin) auditRecorder() *audit.Recorder {
	if a.base == nil {
		return nil
	}
	return a.base.Audit
}

func (a *localAuditAdmin) QueryAudit(ctx context.Context,
	filter LocalAuditFilter) (LocalAuditPage, error) {
	if a.base == nil || a.base.Managed == nil || a.base.Managed.AuditOps == nil {
		return LocalAuditPage{}, fmt.Errorf("%w: 审计查询服务未装配", ErrLocalUnsupported)
	}
	caller, err := a.caller()
	if err != nil {
		return LocalAuditPage{}, err
	}
	limit := filter.Limit
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	request := auditops.QueryRequest{Caller: caller, ScopeID: "system",
		Limit: limit, Offset: offset,
		Filter: auditops.Filter{Action: strings.TrimSpace(filter.Action),
			ActorID:   strings.TrimSpace(filter.ActorID),
			ErrorCode: strings.TrimSpace(filter.ErrorCode)}}
	if outcome := strings.TrimSpace(filter.Outcome); outcome != "" {
		request.Filter.Outcome = audit.Outcome(outcome)
	}
	result, err := a.base.Managed.AuditOps.Query(ctx, request)
	if err != nil {
		return LocalAuditPage{}, localDomainError("审计查询", err)
	}
	page := LocalAuditPage{Pagination: LocalPagination{HasMore: result.HasMore,
		Offset: offset, Limit: limit}}
	for _, event := range result.Events {
		page.Entries = append(page.Entries, LocalAuditEntry{
			CreatedAt: event.OccurredAt, ActorType: string(event.Actor.Type),
			ActorID: event.Actor.ID, Action: event.Action,
			Target:  event.Target.Type + ":" + event.Target.ID,
			Outcome: string(event.Outcome), ErrorCode: event.ErrorCode,
			RequestID: event.RequestID})
	}
	return page, nil
}

// Diagnostics 返回脱敏实例诊断；数据来自已打开实例与迁移检查，不执行写入。
func (a *localAuditAdmin) Diagnostics(ctx context.Context) (LocalDiagnostics, error) {
	if a.base == nil {
		return LocalDiagnostics{}, fmt.Errorf("%w: 实例未装配", ErrLocalRuntimeUnavailable)
	}
	diagnostics := LocalDiagnostics{InstanceReady: !a.base.Uninitialized,
		DatabasePath: a.base.Config.Database.Path}
	latest, err := migrate.LoadMigrations(migrations.SQLite)
	if err == nil {
		diagnostics.LatestCount = len(latest)
	}
	if a.base.Store != nil {
		if pending, checkErr := serverapp.CheckMigrated(ctx, a.base.Store); checkErr == nil {
			diagnostics.AppliedCount = diagnostics.LatestCount - len(pending)
			if len(pending) > 0 {
				diagnostics.Notes = append(diagnostics.Notes,
					fmt.Sprintf("待应用迁移 %d 个", len(pending)))
			}
		} else {
			diagnostics.Notes = append(diagnostics.Notes, "迁移状态检查失败")
		}
	}
	if a.base.Services != nil && a.base.Services.BootstrapStore != nil {
		if root, found, rootErr := a.base.Services.BootstrapStore.GetRootAccount(ctx); rootErr == nil && found {
			diagnostics.RootUserID = root.UserID
		} else if rootErr != nil {
			diagnostics.Notes = append(diagnostics.Notes, "root 记录读取失败")
		}
	}
	return diagnostics, nil
}

func (a *localAuditAdmin) ListDeliveries(ctx context.Context, limit, offset int) (
	[]LocalDelivery, bool, error) {
	if a.base == nil || a.base.Tasks == nil || a.base.Tasks.Mail() == nil {
		return nil, false, fmt.Errorf("%w: 邮件投递服务未启用（mail.enabled/tasks）",
			ErrLocalUnsupported)
	}
	_ = offset
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	caller, err := mailer.LocalAdminCaller(a.operatorID)
	if err != nil {
		return nil, false, err
	}
	records, err := a.base.Tasks.Mail().List(ctx, caller, mailer.ListQuery{Limit: limit})
	if err != nil {
		return nil, false, localDomainError("读取投递状态", err)
	}
	items := make([]LocalDelivery, 0, len(records))
	for _, record := range records {
		items = append(items, LocalDelivery{ID: record.ID, Kind: string(record.Kind),
			State: string(record.State), Attempts: record.Attempts,
			LastError: record.LastErrorCode, CreatedAt: record.CreatedAt,
			UpdatedAt: record.UpdatedAt})
	}
	return items, len(items) >= limit, nil
}

func (a *localAuditAdmin) ListReports(ctx context.Context, limit, offset int) (
	[]LocalReport, bool, error) {
	if a.base == nil || a.base.Managed == nil || a.base.Managed.Reports == nil {
		return nil, false, fmt.Errorf("%w: 报告服务未装配", ErrLocalUnsupported)
	}
	_ = offset
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	caller, err := a.caller()
	if err != nil {
		return nil, false, err
	}
	result, err := a.base.Managed.Reports.HistoryList(ctx, reports.HistoryListRequest{
		Caller: caller, Limit: limit})
	if err != nil {
		return nil, false, localDomainError("读取报告历史", err)
	}
	items := make([]LocalReport, 0, len(result.Records))
	for _, record := range result.Records {
		format := ""
		if len(record.Formats) > 0 {
			format = string(record.Formats[0])
		}
		items = append(items, LocalReport{ID: record.ID, Kind: record.Template,
			Format: format, State: record.State, CreatedAt: record.CreatedAt})
	}
	return items, result.HasMore, nil
}

func (a *localAuditAdmin) GenerateReport(ctx context.Context,
	request LocalReportRequest) (LocalReport, error) {
	if a.base == nil || a.base.Managed == nil || a.base.Managed.Reports == nil {
		return LocalReport{}, fmt.Errorf("%w: 报告服务未装配", ErrLocalUnsupported)
	}
	caller, err := reports.NewLocalMaintenanceCaller(a.operatorID)
	if err != nil {
		return LocalReport{}, err
	}
	scopeID := strings.TrimSpace(request.ScopeID)
	if scopeID == "" {
		scopeID = "system"
	}
	from := request.From
	to := request.To
	now := time.Now().UTC()
	if from.IsZero() {
		from = now.Add(-24 * time.Hour)
	}
	if to.IsZero() {
		to = now
	}
	formats := make([]reports.Format, 0, len(request.Formats))
	for _, raw := range request.Formats {
		formats = append(formats, reports.Format(strings.TrimSpace(raw)))
	}
	if len(formats) == 0 {
		formats = []reports.Format{reports.FormatHTML}
	}
	detailRows := request.DetailRows
	if detailRows <= 0 {
		detailRows = 100
	}
	view, err := a.base.Managed.Reports.LocalMaintenanceStart(ctx, caller,
		reports.StartRequest{ScopeID: scopeID, Window: stats.WindowRequest{
			Start: from, End: to}, Formats: formats, MaxDetailRows: detailRows,
			RequestID: ws3RequestID("req_local_report_start")})
	if err != nil {
		return LocalReport{}, localDomainError("提交报告生成任务", err)
	}
	format := ""
	if len(view.Formats) > 0 {
		format = string(view.Formats[0])
	}
	return LocalReport{ID: view.ID, Kind: "standard", Format: format,
		State: view.State, TaskID: view.TaskID, CreatedAt: view.CreatedAt}, nil
}

// ---------- 审计保留策略 / 危险清理（本地维护显式动作） ----------

func (a *localAuditAdmin) retentionClient() (*auditops.Service, auditops.LocalMaintenanceCaller, error) {
	if a.base == nil || a.base.Managed == nil || a.base.Managed.AuditOps == nil {
		return nil, auditops.LocalMaintenanceCaller{}, fmt.Errorf(
			"%w: 审计查询服务未装配", ErrLocalUnsupported)
	}
	caller, err := auditops.NewLocalMaintenanceCaller(a.operatorID)
	if err != nil {
		return nil, auditops.LocalMaintenanceCaller{}, err
	}
	return a.base.Managed.AuditOps, caller, nil
}

func mapLocalRetention(info auditops.RetentionInfo) LocalRetention {
	return LocalRetention{Days: info.Days, Configured: info.Configured,
		Version: info.Version, Cutoff: info.Cutoff, UpdatedAt: info.UpdatedAt}
}

func (a *localAuditAdmin) Retention(ctx context.Context) (LocalRetention, error) {
	service, _, err := a.retentionClient()
	if err != nil {
		return LocalRetention{}, err
	}
	info, err := service.LocalMaintenanceRetention(ctx)
	if err != nil {
		return LocalRetention{}, localDomainError("读取保留策略", err)
	}
	return mapLocalRetention(info), nil
}

func (a *localAuditAdmin) SetRetention(ctx context.Context, retentionDays int,
	reason string) (LocalRetention, error) {
	service, caller, err := a.retentionClient()
	if err != nil {
		return LocalRetention{}, err
	}
	info, err := service.LocalMaintenanceRetention(ctx)
	if err != nil {
		return LocalRetention{}, localDomainError("读取保留策略", err)
	}
	updated, err := service.LocalMaintenanceSetRetention(ctx, caller, retentionDays,
		reason, ws3RequestID("req_local_audit_retention"), info.Version)
	if err != nil {
		return LocalRetention{}, localDomainError("设置保留策略", err)
	}
	return mapLocalRetention(updated), nil
}

func (a *localAuditAdmin) PreviewPurge(ctx context.Context, cutoff time.Time,
	maxRecords int) (LocalPurgePreview, error) {
	service, caller, err := a.retentionClient()
	if err != nil {
		return LocalPurgePreview{}, err
	}
	if maxRecords <= 0 || maxRecords > 100000 {
		maxRecords = 1000
	}
	preview, err := service.LocalMaintenancePreviewPurge(ctx, caller, "system", cutoff,
		500, maxRecords, ws3RequestID("req_local_audit_purge_preview"))
	if err != nil {
		return LocalPurgePreview{}, localDomainError("清理预估", err)
	}
	return LocalPurgePreview{ScopeID: preview.ScopeID, Cutoff: preview.Cutoff,
		BatchSize: preview.BatchSize, MaxRecords: preview.MaxRecords,
		EstimatedCount: preview.EstimatedCount, AtLeast: preview.AtLeast,
		WithinRetention:      preview.WithinRetention,
		MaintenanceProtected: preview.MaintenanceProtected, Digest: preview.Digest,
		Retention:   mapLocalRetention(preview.Retention),
		GeneratedAt: preview.GeneratedAt}, nil
}

func (a *localAuditAdmin) StartPurge(ctx context.Context, preview LocalPurgePreview,
	reason string) (LocalPurgeRun, error) {
	service, caller, err := a.retentionClient()
	if err != nil {
		return LocalPurgeRun{}, err
	}
	batchSize := preview.BatchSize
	if batchSize <= 0 {
		batchSize = 500
	}
	maxRecords := preview.MaxRecords
	if maxRecords <= 0 {
		maxRecords = 1000
	}
	run, err := service.LocalMaintenanceStartPurge(ctx, caller, preview.ScopeID,
		preview.Cutoff, preview.BatchSize, preview.MaxRecords, reason, preview.Digest,
		ws3RequestID("req_local_audit_purge_start"))
	_ = batchSize
	_ = maxRecords
	if err != nil {
		return LocalPurgeRun{}, localDomainError("提交清理任务", err)
	}
	return mapLocalPurgeRun(run), nil
}

func (a *localAuditAdmin) ListPurgeRuns(ctx context.Context, limit, offset int) (
	[]LocalPurgeRun, bool, error) {
	service, caller, err := a.retentionClient()
	if err != nil {
		return nil, false, err
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	runs, hasMore, err := service.LocalMaintenanceListPurgeRuns(ctx, caller, "manual", "",
		limit, maxInt(offset, 0))
	if err != nil {
		return nil, false, localDomainError("读取清理记录", err)
	}
	items := make([]LocalPurgeRun, 0, len(runs))
	for _, run := range runs {
		items = append(items, mapLocalPurgeRun(run))
	}
	return items, hasMore, nil
}

func (a *localAuditAdmin) PurgeEvidence(ctx context.Context, runID string) (
	[]LocalPurgeEvidence, error) {
	service, caller, err := a.retentionClient()
	if err != nil {
		return nil, err
	}
	entries, err := service.LocalMaintenanceLog(ctx, caller, runID)
	if err != nil {
		return nil, localDomainError("读取维护证据", err)
	}
	items := make([]LocalPurgeEvidence, 0, len(entries))
	for _, entry := range entries {
		items = append(items, LocalPurgeEvidence{OperationID: entry.ID,
			Action: entry.Action, Result: entry.Result, ErrorCode: entry.ErrorCode,
			StartedAt: entry.OccurredAt, FinishedAt: entry.OccurredAt,
			RequestID: entry.RequestID})
	}
	return items, nil
}

func mapLocalPurgeRun(run auditops.PurgeRunView) LocalPurgeRun {
	return LocalPurgeRun{ID: run.ID, Kind: run.Kind, ScopeID: run.ScopeID,
		State: run.State, TaskID: run.TaskID, Cutoff: run.Cutoff,
		Scanned: run.Scanned, Cleaned: run.Cleaned, Skipped: run.Skipped,
		Failed: run.Failed, LimitReached: run.LimitReached,
		ErrorCode: run.ErrorCode, FailureReason: run.FailureReason,
		CreatedAt: run.CreatedAt}
}

func (a *localAuditAdmin) ListTasks(ctx context.Context, limit, offset int) ([]LocalTask, bool, error) {
	if a.base == nil || a.base.Managed == nil || a.base.Managed.Tasks == nil {
		return nil, false, fmt.Errorf("%w: 后台任务服务未装配", ErrLocalUnsupported)
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	page, err := a.base.Managed.Tasks.ListJobs(ctx, task.ListJobsRequest{Limit: limit,
		Cursor: ""})
	_ = offset
	if err != nil {
		return nil, false, localDomainError("任务列表", err)
	}
	result := make([]LocalTask, 0, len(page.Jobs))
	for _, job := range page.Jobs {
		item := LocalTask{ID: job.ID, Kind: job.Kind, State: string(job.State),
			CreatedAt: job.CreatedAt, UpdatedAt: job.UpdatedAt,
			LastError: job.ErrorCode}
		if job.Canceller != nil {
			item.CancelState = "已请求取消"
		}
		result = append(result, item)
	}
	return result, page.HasMore, nil
}

func (a *localAuditAdmin) CancelTask(ctx context.Context, taskID,
	reason string) (LocalTask, error) {
	if a.base == nil || a.base.Managed == nil || a.base.Managed.Tasks == nil {
		return LocalTask{}, fmt.Errorf("%w: 后台任务服务未装配", ErrLocalUnsupported)
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return LocalTask{}, fmt.Errorf("取消任务必须给出原因")
	}
	actor := audit.Actor{Type: audit.ActorLocalAdmin, ID: a.operatorID}
	result, err := a.base.Managed.Tasks.RequestCancel(ctx, task.CancelRequest{
		JobID: strings.TrimSpace(taskID), Actor: actor, Reason: reason,
		RequestID: ws3RequestID("req_local_task_cancel")})
	if err != nil {
		return LocalTask{}, localDomainError("取消任务", err)
	}
	job, err := a.base.Managed.Tasks.Get(ctx, strings.TrimSpace(taskID))
	if err != nil {
		return LocalTask{ID: strings.TrimSpace(taskID), State: string(result.State),
			CancelState: "取消请求已受理"}, nil
	}
	return LocalTask{ID: job.ID, Kind: job.Kind, State: string(job.State),
		CreatedAt: job.CreatedAt, UpdatedAt: job.UpdatedAt,
		LastError: job.ErrorCode, CancelState: "取消请求已受理"}, nil
}

var _ = errors.Is
