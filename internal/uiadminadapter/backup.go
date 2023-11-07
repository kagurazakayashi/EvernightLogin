// Package uiadminadapter：步骤 81 备份计划/任务/历史/下载/保留清理页适配器。
//
// 安全边界：适配器只接受页面已通过 UIAccessManagement 验证后传入的操作者用户 ID，
// 每次操作重新构造可信 Caller 并调用真实 internal/backupadmin 服务；每次读取、计划
// 变更、手动备份、下载、取消、保留策略与清理都由领域服务重新授权、复核系统范围并
// 执行强认证敏感操作。下载走一次性短期令牌并立即兑换，响应不包含宿主路径或长期
// 凭证；本适配器不读取前端自报角色、不缓存授权。
package uiadminadapter

import (
	"context"
	"errors"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/backupadmin"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// BackupsRecorder 是拒绝留痕契约（生产 *audit.Recorder）。
type BackupsRecorder interface {
	RecordFailure(ctx context.Context, event audit.Event) error
}

// BackupsOptions 是备份页适配器依赖。
type BackupsOptions struct {
	Admin    *backupadmin.Service
	Recorder BackupsRecorder
	Now      func() time.Time
}

// BackupsAdapter 实现 login.UIPageBackupBackend。
type BackupsAdapter struct {
	opts BackupsOptions
}

// NewBackups 校验依赖并构造备份页适配器。
func NewBackups(options BackupsOptions) (*BackupsAdapter, error) {
	if options.Admin == nil {
		return nil, errors.New("备份页适配器缺少备份管理服务")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &BackupsAdapter{opts: options}, nil
}

// backupCaller 把页面已认证用户 ID 重建为可信 Caller。
func backupCaller(userID string) (account.Caller, error) {
	if userID == "" || !account.ValidUserID(userID) {
		return account.Caller{}, &login.UIBackupError{Code: "ACCESS_DENIED"}
	}
	return account.UserCaller(userID)
}

// mapBackupError 把领域错误映射为页面稳定错误码（不泄漏内部细节）。
func mapBackupError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, backupadmin.ErrAccessDenied):
		return &login.UIBackupError{Code: "ACCESS_DENIED"}
	case errors.Is(err, backupadmin.ErrNotFound):
		return &login.UIBackupError{Code: "NOT_FOUND"}
	case errors.Is(err, backupadmin.ErrConflict), errors.Is(err, backupadmin.ErrProtection),
		errors.Is(err, backupadmin.ErrNotDownloadable),
		errors.Is(err, backupadmin.ErrDownloadTooLarge):
		return &login.UIBackupError{Code: "CONFLICT"}
	case errors.Is(err, backupadmin.ErrInvalidRequest),
		errors.Is(err, backupadmin.ErrRetentionInvalid):
		return &login.UIBackupError{Code: "INVALID"}
	default:
		return &login.UIBackupError{Code: "UNAVAILABLE"}
	}
}

// actorText 只显示身份类型与稳定 ID，不披露账户资料。
func actorText(actor audit.Actor) string {
	return string(actor.Type) + " · " + actor.ID
}

// Capabilities 实现 login.UIPageBackupBackend。
func (a *BackupsAdapter) Capabilities(ctx context.Context,
	userID string) (login.UIBackupCapabilities, error) {
	caller, err := backupCaller(userID)
	if err != nil {
		return login.UIBackupCapabilities{}, err
	}
	caps, err := a.opts.Admin.Capabilities(ctx, caller)
	if err != nil {
		return login.UIBackupCapabilities{}, mapBackupError(err)
	}
	return login.UIBackupCapabilities{
		Read: caps.Read, Create: caps.Create, Cancel: caps.Cancel,
		Download: caps.Download, Retention: caps.Retention, Cleanup: caps.Cleanup,
		DownloadTTL: caps.DownloadTTL,
	}, nil
}

// RecordDenial 实现 login.UIPageBackupBackend。
func (a *BackupsAdapter) RecordDenial(ctx context.Context, userID, reason string) error {
	if a.opts.Recorder == nil || userID == "" {
		return nil
	}
	actor := audit.Actor{Type: audit.ActorUser, ID: userID}
	if err := actor.Validate(); err != nil {
		return nil
	}
	return a.opts.Recorder.RecordFailure(ctx, audit.Event{
		Actor: actor, Action: backupadmin.ActionAccessDenied,
		Target:  audit.Target{Type: "backup_page", ID: "backups_ui"},
		Outcome: audit.OutcomeDenied, ErrorCode: "ACCESS_DENIED",
		ReasonCode: safeDenialToken(reason),
	})
}

// scheduleView 把领域计划视图映射为页面视图。
func scheduleView(view backupadmin.ScheduleView) login.UIBackupSchedule {
	return login.UIBackupSchedule{
		ID: view.ID, Name: view.Name, Enabled: view.Enabled,
		ScheduleType: view.ScheduleType, Expression: view.Expression,
		TimeZone: view.TimeZone, PeriodDescription: view.PeriodDescription,
		MissedPolicy: view.MissedPolicy, MaxCatchUp: view.MaxCatchUp,
		TimeoutSeconds: view.TimeoutSeconds, MaxAttempts: view.MaxAttempts,
		Owner: actorText(view.Owner), ExecutionActor: actorText(view.ExecutionActor),
		ScopeID: view.ScopeID, NextRun: view.NextRun, NextRunUnknown: view.NextRunUnknown,
		RetentionVersion: view.RetentionVersion, NotifyFailures: view.NotifyFailures,
		NotifySuccess: view.NotifySuccess, LastScheduledAt: view.LastScheduledAt,
		CreatedAt: view.CreatedAt, UpdatedAt: view.UpdatedAt,
		PermissionState: view.PermissionState,
	}
}

// ListSchedules 实现 login.UIPageBackupBackend。
func (a *BackupsAdapter) ListSchedules(ctx context.Context,
	userID string) ([]login.UIBackupSchedule, error) {
	caller, err := backupCaller(userID)
	if err != nil {
		return nil, err
	}
	views, err := a.opts.Admin.ListSchedules(ctx, caller)
	if err != nil {
		return nil, mapBackupError(err)
	}
	schedules := make([]login.UIBackupSchedule, 0, len(views))
	for _, view := range views {
		schedules = append(schedules, scheduleView(view))
	}
	return schedules, nil
}

// ListSchedulesPage 实现 login.UIBackupSchedulePagedBackend（步骤 218）。
func (a *BackupsAdapter) ListSchedulesPage(ctx context.Context, userID string,
	limit, offset int) ([]login.UIBackupSchedule, bool, error) {
	caller, err := backupCaller(userID)
	if err != nil {
		return nil, false, err
	}
	views, hasMore, err := a.opts.Admin.ListSchedulesPage(ctx, caller, limit, offset)
	if err != nil {
		return nil, false, mapBackupError(err)
	}
	schedules := make([]login.UIBackupSchedule, 0, len(views))
	for _, view := range views {
		schedules = append(schedules, scheduleView(view))
	}
	return schedules, hasMore, nil
}

// GetSchedule 实现 login.UIPageBackupBackend。
func (a *BackupsAdapter) GetSchedule(ctx context.Context, userID,
	scheduleID string) (login.UIBackupSchedule, error) {
	caller, err := backupCaller(userID)
	if err != nil {
		return login.UIBackupSchedule{}, err
	}
	view, err := a.opts.Admin.GetSchedule(ctx, caller, scheduleID)
	if err != nil {
		return login.UIBackupSchedule{}, mapBackupError(err)
	}
	return scheduleView(view), nil
}

// scheduleRequest 把页面请求映射为领域请求。
func scheduleRequest(caller account.Caller, requestID string,
	request login.UIBackupScheduleRequest) backupadmin.ScheduleRequest {
	return backupadmin.ScheduleRequest{
		Caller: caller, Name: request.Name,
		ScheduleType: task.ScheduleType(request.ScheduleType),
		Expression:   request.Expression, TimeZone: request.TimeZone,
		MissedPolicy: task.MissedPolicy(request.MissedPolicy),
		MaxCatchUp:   request.MaxCatchUp, TimeoutSeconds: request.TimeoutSeconds,
		MaxAttempts:      request.MaxAttempts,
		RetentionVersion: request.RetentionVersion,
		NotifyFailures:   request.NotifyFailures, NotifySuccess: request.NotifySuccess,
		NotifyTarget: request.NotifyTarget, Enabled: request.Enabled,
		RequestID: requestID,
	}
}

// SaveSchedule 实现 login.UIPageBackupBackend：scheduleID 为空时创建，否则编辑。
func (a *BackupsAdapter) SaveSchedule(ctx context.Context, userID, scheduleID string,
	request login.UIBackupScheduleRequest, requestID string) (login.UIBackupSchedule, error) {
	caller, err := backupCaller(userID)
	if err != nil {
		return login.UIBackupSchedule{}, err
	}
	domainRequest := scheduleRequest(caller, requestID, request)
	var view backupadmin.ScheduleView
	if scheduleID == "" {
		view, err = a.opts.Admin.CreateSchedule(ctx, domainRequest)
	} else {
		view, err = a.opts.Admin.UpdateSchedule(ctx, scheduleID, domainRequest)
	}
	if err != nil {
		return login.UIBackupSchedule{}, mapBackupError(err)
	}
	return scheduleView(view), nil
}

// SetScheduleEnabled 实现 login.UIPageBackupBackend。
func (a *BackupsAdapter) SetScheduleEnabled(ctx context.Context, userID, scheduleID string,
	enabled bool, reason, requestID string) (login.UIBackupSchedule, error) {
	caller, err := backupCaller(userID)
	if err != nil {
		return login.UIBackupSchedule{}, err
	}
	view, err := a.opts.Admin.SetScheduleEnabled(ctx, caller, scheduleID, enabled,
		reason, requestID)
	if err != nil {
		return login.UIBackupSchedule{}, mapBackupError(err)
	}
	return scheduleView(view), nil
}

// DeleteSchedule 实现 login.UIPageBackupBackend。
func (a *BackupsAdapter) DeleteSchedule(ctx context.Context, userID, scheduleID, reason,
	requestID string) error {
	caller, err := backupCaller(userID)
	if err != nil {
		return err
	}
	return mapBackupError(a.opts.Admin.DeleteSchedule(ctx, caller, scheduleID, reason, requestID))
}

// EnqueueBackup 实现 login.UIPageBackupBackend。
func (a *BackupsAdapter) EnqueueBackup(ctx context.Context, userID,
	requestID string) (login.UIBackupJobRef, error) {
	caller, err := backupCaller(userID)
	if err != nil {
		return login.UIBackupJobRef{}, err
	}
	ref, err := a.opts.Admin.EnqueueBackup(ctx, caller, requestID)
	if err != nil {
		return login.UIBackupJobRef{}, mapBackupError(err)
	}
	return login.UIBackupJobRef{JobID: ref.JobID, Existing: ref.Existing, State: ref.State}, nil
}

// jobView 把领域任务视图映射为页面视图。
func jobView(view backupadmin.JobView) login.UIBackupJob {
	canceller := ""
	if view.Canceller != nil {
		canceller = actorText(*view.Canceller)
	}
	return login.UIBackupJob{
		ID: view.ID, Kind: view.Kind, Origin: view.Origin,
		ScheduleID: view.ScheduleID, State: view.State, StageCode: view.StageCode,
		StageDescription: view.StageDescription, ProgressDone: view.ProgressDone,
		ProgressTotal: view.ProgressTotal, ProgressUnit: view.ProgressUnit,
		Attempt: view.Attempt, MaxAttempts: view.MaxAttempts,
		Initiator: actorText(view.Initiator), Canceller: canceller,
		ErrorCode: view.ErrorCode, FailureReason: truncateReportText(view.FailureReason),
		RequestID: view.RequestID, BackupID: view.BackupID,
		NotificationState: view.NotificationStat, NotificationCode: view.NotificationCode,
		ResultSummary: view.ResultSummary, CreatedAt: view.CreatedAt,
		StartedAt: view.StartedAt, FinishedAt: view.FinishedAt,
		CancelRequestedAt: view.CancelRequestedAt, UpdatedAt: view.UpdatedAt,
	}
}

// ListJobs 实现 login.UIPageBackupBackend。
func (a *BackupsAdapter) ListJobs(ctx context.Context, userID, kind string, limit,
	offset int) ([]login.UIBackupJob, bool, error) {
	caller, err := backupCaller(userID)
	if err != nil {
		return nil, false, err
	}
	views, hasMore, err := a.opts.Admin.ListJobs(ctx, caller,
		backupadmin.JobFilter{Kind: kind, Limit: limit, Offset: offset})
	if err != nil {
		return nil, false, mapBackupError(err)
	}
	jobs := make([]login.UIBackupJob, 0, len(views))
	for _, view := range views {
		jobs = append(jobs, jobView(view))
	}
	return jobs, hasMore, nil
}

// GetJob 实现 login.UIPageBackupBackend。
func (a *BackupsAdapter) GetJob(ctx context.Context, userID,
	jobID string) (login.UIBackupJob, error) {
	caller, err := backupCaller(userID)
	if err != nil {
		return login.UIBackupJob{}, err
	}
	view, err := a.opts.Admin.GetJob(ctx, caller, jobID)
	if err != nil {
		return login.UIBackupJob{}, mapBackupError(err)
	}
	return jobView(view), nil
}

// CancelJob 实现 login.UIPageBackupBackend：返回真实受理状态，不把请求写成已取消。
func (a *BackupsAdapter) CancelJob(ctx context.Context, userID, jobID, reason,
	requestID string) (login.UIBackupCancelResult, error) {
	caller, err := backupCaller(userID)
	if err != nil {
		return login.UIBackupCancelResult{}, err
	}
	view, err := a.opts.Admin.CancelJob(ctx, caller, jobID, reason, requestID)
	if err != nil {
		return login.UIBackupCancelResult{}, mapBackupError(err)
	}
	return login.UIBackupCancelResult{
		JobID: view.JobID, Accepted: view.Accepted,
		AlreadyRequested: view.AlreadyRequested, State: view.State, Note: view.Note,
	}, nil
}

// artifactView 把领域产物视图映射为页面视图。
func artifactView(view backupadmin.ArtifactView) login.UIBackupArtifact {
	return login.UIBackupArtifact{
		BackupID: view.BackupID, JobID: view.JobID, ScheduleID: view.ScheduleID,
		Origin: view.Origin, SizeBytes: view.SizeBytes, FileSHA256: view.FileSHA256,
		FormatVersion: view.FormatVersion, SchemaVersion: view.SchemaVersion,
		ContentDatabase: view.ContentDatabase, ContentAttach: view.ContentAttach,
		ContentConfig: view.ContentConfig, EntryCount: view.EntryCount,
		Verification: view.Verification, VerifiedAt: view.VerifiedAt,
		RetentionVersion: view.RetentionVersion, Cleanup: view.Cleanup,
		CleanedAt: view.CleanedAt, CreatedAt: view.CreatedAt,
		PublishedAt: view.PublishedAt, FileExists: view.FileExists,
		IsLastUsable: view.IsLastUsable, ProtectionReason: view.ProtectionReason,
		Downloadable: view.Downloadable,
	}
}

// ListArtifacts 实现 login.UIPageBackupBackend。
func (a *BackupsAdapter) ListArtifacts(ctx context.Context, userID string,
	query login.UIBackupArtifactQuery) ([]login.UIBackupArtifact, bool, error) {
	caller, err := backupCaller(userID)
	if err != nil {
		return nil, false, err
	}
	views, hasMore, err := a.opts.Admin.ListArtifacts(ctx, caller,
		backupadmin.ArtifactFilter{
			Origin:       backupadmin.Origin(query.Origin),
			Verification: backupadmin.VerificationState(query.Verification),
			Cleanup:      backupadmin.CleanupState(query.Cleanup),
			Limit:        query.Limit, Offset: query.Offset,
		})
	if err != nil {
		return nil, false, mapBackupError(err)
	}
	artifacts := make([]login.UIBackupArtifact, 0, len(views))
	for _, view := range views {
		artifacts = append(artifacts, artifactView(view))
	}
	return artifacts, hasMore, nil
}

// GetArtifact 实现 login.UIPageBackupBackend。
func (a *BackupsAdapter) GetArtifact(ctx context.Context, userID,
	backupID string) (login.UIBackupArtifact, error) {
	caller, err := backupCaller(userID)
	if err != nil {
		return login.UIBackupArtifact{}, err
	}
	view, err := a.opts.Admin.GetArtifact(ctx, caller, backupID)
	if err != nil {
		return login.UIBackupArtifact{}, mapBackupError(err)
	}
	return artifactView(view), nil
}

// Download 实现 login.UIPageBackupBackend：签发一次性令牌并立即兑换，领域服务在
// 签发与兑换时都重新检查独立下载权限与再次认证。
func (a *BackupsAdapter) Download(ctx context.Context, userID,
	backupID string) (login.UIBackupDownload, error) {
	caller, err := backupCaller(userID)
	if err != nil {
		return login.UIBackupDownload{}, err
	}
	ticket, err := a.opts.Admin.IssueDownloadTicket(ctx, caller, backupID, "")
	if err != nil {
		return login.UIBackupDownload{}, mapBackupError(err)
	}
	file, err := a.opts.Admin.RedeemDownloadTicket(ctx, caller, ticket.Token, "")
	if err != nil {
		return login.UIBackupDownload{}, mapBackupError(err)
	}
	return login.UIBackupDownload{BackupID: file.BackupID, FileName: file.FileName,
		SHA256: file.SHA256, Size: file.Size, Data: file.Data}, nil
}

// ListNotifications 实现 login.UIPageBackupBackend。
func (a *BackupsAdapter) ListNotifications(ctx context.Context, userID, jobID,
	backupID string) ([]login.UIBackupNotification, error) {
	caller, err := backupCaller(userID)
	if err != nil {
		return nil, err
	}
	records, err := a.opts.Admin.ListNotifications(ctx, caller, jobID, backupID)
	if err != nil {
		return nil, mapBackupError(err)
	}
	notifications := make([]login.UIBackupNotification, 0, len(records))
	for _, record := range records {
		notifications = append(notifications, login.UIBackupNotification{
			ID: record.ID, Kind: record.Kind, State: record.State,
			Channel: record.Channel, RecipientMasked: record.RecipientMasked,
			ErrorCode: record.ErrorCode, Attempts: record.Attempts,
			CreatedAt: record.CreatedAt,
		})
	}
	return notifications, nil
}

// retentionView 把领域保留策略映射为页面视图。
func retentionView(view backupadmin.RetentionView) login.UIBackupRetention {
	result := login.UIBackupRetention{
		Version: view.Policy.Version, MaxCount: view.Policy.MaxCount,
		MaxAgeDays: view.Policy.MaxAgeDays, MaxTotalBytes: view.Policy.MaxTotalBytes,
		IsDefault: view.IsDefault, UpdatedAt: view.Policy.UpdatedAt,
		UpdatedBy: actorText(view.Policy.UpdatedBy), Reason: view.Policy.Reason,
	}
	if view.LastCleanup != nil {
		result.LastCleanup = &login.UIBackupCleanupSummary{
			JobID: view.LastCleanup.JobID, State: view.LastCleanup.State,
			RequestedCount: view.LastCleanup.RequestedCount,
			CleanedCount:   view.LastCleanup.CleanedCount,
			FailedCount:    view.LastCleanup.FailedCount,
			ProtectedCount: view.LastCleanup.ProtectedCount,
			FreedBytes:     view.LastCleanup.FreedBytes, FinishedAt: view.LastCleanup.FinishedAt,
		}
	}
	return result
}

// Retention 实现 login.UIPageBackupBackend。
func (a *BackupsAdapter) Retention(ctx context.Context,
	userID string) (login.UIBackupRetention, error) {
	caller, err := backupCaller(userID)
	if err != nil {
		return login.UIBackupRetention{}, err
	}
	view, err := a.opts.Admin.Retention(ctx, caller)
	if err != nil {
		return login.UIBackupRetention{}, mapBackupError(err)
	}
	return retentionView(view), nil
}

// SaveRetention 实现 login.UIPageBackupBackend。
func (a *BackupsAdapter) SaveRetention(ctx context.Context, userID string,
	request login.UIBackupRetentionRequest, requestID string) (login.UIBackupRetention, error) {
	caller, err := backupCaller(userID)
	if err != nil {
		return login.UIBackupRetention{}, err
	}
	view, err := a.opts.Admin.SaveRetention(ctx, backupadmin.RetentionChange{
		Caller: caller, MaxCount: request.MaxCount, MaxAgeDays: request.MaxAgeDays,
		MaxTotalBytes: request.MaxTotalBytes, ExpectedVersion: request.ExpectedVersion,
		Reason: request.Reason, RequestID: requestID,
	})
	if err != nil {
		return login.UIBackupRetention{}, mapBackupError(err)
	}
	// 保存后重新读取，确保最近清理摘要与页面数据来自真实服务。
	refreshed, readErr := a.opts.Admin.Retention(ctx, caller)
	if readErr != nil {
		return retentionView(view), nil
	}
	return retentionView(refreshed), nil
}

// CleanupPreview 实现 login.UIPageBackupBackend：预览不是删除授权。
func (a *BackupsAdapter) CleanupPreview(ctx context.Context,
	userID string) (login.UIBackupCleanupPreview, error) {
	caller, err := backupCaller(userID)
	if err != nil {
		return login.UIBackupCleanupPreview{}, err
	}
	preview, err := a.opts.Admin.CleanupPreview(ctx, caller)
	if err != nil {
		return login.UIBackupCleanupPreview{}, mapBackupError(err)
	}
	result := login.UIBackupCleanupPreview{
		Policy:        retentionView(backupadmin.RetentionView{Policy: preview.Policy}),
		TotalRetained: preview.TotalRetained, TotalBytes: preview.TotalBytes,
		TargetBytes: preview.TargetBytes, PreviewedAt: preview.PreviewedAt,
		Note:      preview.Note,
		Targets:   make([]login.UIBackupCleanupCandidate, 0, len(preview.Targets)),
		Protected: make([]login.UIBackupCleanupCandidate, 0, len(preview.Protected)),
	}
	for _, target := range preview.Targets {
		result.Targets = append(result.Targets, login.UIBackupCleanupCandidate{
			Artifact: artifactView(target.ArtifactView), Reason: target.Reason})
	}
	for _, item := range preview.Protected {
		result.Protected = append(result.Protected, login.UIBackupCleanupCandidate{
			Artifact: artifactView(item.ArtifactView), Reason: item.Reason})
	}
	return result, nil
}

// RunCleanup 实现 login.UIPageBackupBackend：提交清理任务并返回真实任务编号。
func (a *BackupsAdapter) RunCleanup(ctx context.Context, userID,
	requestID string) (login.UIBackupJobRef, error) {
	caller, err := backupCaller(userID)
	if err != nil {
		return login.UIBackupJobRef{}, err
	}
	ref, err := a.opts.Admin.EnqueueCleanup(ctx, caller, requestID)
	if err != nil {
		return login.UIBackupJobRef{}, mapBackupError(err)
	}
	return login.UIBackupJobRef{JobID: ref.JobID, Existing: ref.Existing, State: ref.State}, nil
}

// Reconcile 实现 login.UIPageBackupBackend：只登记孤儿成品为“可用性未知”，不删除。
func (a *BackupsAdapter) Reconcile(ctx context.Context,
	userID string) (login.UIBackupReconcileResult, error) {
	caller, err := backupCaller(userID)
	if err != nil {
		return login.UIBackupReconcileResult{}, err
	}
	// 对账是只读巡检 + 登记，要求查看权限即可；调用前仍由服务重新授权。
	if err := a.opts.Admin.CheckReadAccess(ctx, caller); err != nil {
		return login.UIBackupReconcileResult{}, mapBackupError(err)
	}
	result, err := a.opts.Admin.Reconcile(ctx)
	if err != nil {
		return login.UIBackupReconcileResult{}, mapBackupError(err)
	}
	return login.UIBackupReconcileResult{Scanned: result.Scanned,
		Orphans: result.Orphans, MissingFiles: result.MissingFiles}, nil
}

// 页面契约编译期断言：适配器必须完整实现备份管理页面后端。
var _ login.UIPageBackupBackend = (*BackupsAdapter)(nil)
