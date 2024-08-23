package app

import (
	"context"
	"errors"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/auditops"
	"github.com/kagurazakayashi/EvernightLogin/internal/backupadmin"
	"github.com/kagurazakayashi/EvernightLogin/internal/reports"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
	"strings"
)

// ListUserSessions 管理员按作用范围分页读取目标用户活动会话。只有真实 AdminSession
// 调用者可用（强认证/范围/root 保护/读审计在会话服务内重新判定）；LocalAdmin 没有
// 管理会话秘密，无法通过该入口读取会话（明确拒绝，不伪造授权）。
func (f *adminFacade) ListUserSessions(ctx context.Context,
	req AdminListUserSessionsRequest) (AdminUserSessionList, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminUserSessionList{}, err
	}
	services := f.r.coreServices()
	if services == nil || services.Sessions == nil {
		return AdminUserSessionList{}, call.configError("会话服务未装配")
	}
	if call.identity.local || len(call.identity.sessionSecret) == 0 {
		return AdminUserSessionList{}, call.domainError(
			"读取会话列表需要真实管理会话", "ACCESS_DENIED")
	}
	page, err := call.page(req.Page)
	if err != nil {
		return AdminUserSessionList{}, err
	}
	result, err := services.Sessions.AdminListSessionsPage(ctx,
		string(call.identity.sessionSecret), session.AdminSessionListPageRequest{
			ScopeAppID:   strings.TrimSpace(req.ScopeApplicationID),
			TargetUserID: strings.TrimSpace(req.TargetUserID),
			Limit:        page.Limit, Offset: page.Offset, RequestID: call.requestID})
	if err != nil {
		return AdminUserSessionList{}, call.domainError("查询用户会话失败", string(session.CodeOf(err)))
	}
	sessions := make([]AdminSessionView, 0, len(result.Sessions))
	for _, record := range result.Sessions {
		sessions = append(sessions, AdminSessionView{
			ID: record.ID, AppID: record.AppID, Kind: string(record.Kind),
			Reason: string(record.Reason), CreatedAt: record.CreatedAt,
			LastSeenAt: record.LastSeenAt, IdleExpiresAt: record.IdleExpiresAt,
			AbsoluteExpiresAt: record.AbsoluteExpiresAt, RememberMe: record.RememberMe,
			Current: record.Current, ClientUserAgent: record.Client.UserAgent,
			ClientAddress: record.Client.Address})
	}
	return AdminUserSessionList{TargetUserID: result.TargetUserID,
		ScopeApplicationID: result.ScopeAppID, Sessions: sessions, Total: result.Total,
		HasMore: result.HasMore,
		Page:    NewAdminPageInfo(page, len(sessions), result.HasMore)}, nil
}

// ListAuditEvents 分页查询审计事件。授权、数据范围与筛选校验由审计服务先行判定；
// 门面只规范化 limit/cursor 并把领域结果投影为脱敏公开视图。
func (f *adminFacade) ListAuditEvents(ctx context.Context,
	req AdminListAuditEventsRequest) (AdminAuditEventList, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminAuditEventList{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.AuditOps == nil {
		return AdminAuditEventList{}, call.configError("审计服务未装配")
	}
	caller, err := f.accountCaller(call.identity)
	if err != nil {
		return AdminAuditEventList{}, call.configError("审计服务调用者无效")
	}
	limit, err := normalizeAdminCursorLimit(req.Limit)
	if err != nil {
		return AdminAuditEventList{}, err
	}
	cursor, err := normalizeAdminCursor(req.Cursor)
	if err != nil {
		return AdminAuditEventList{}, err
	}
	filter := req.Filter
	result, err := managed.AuditOps.Query(ctx, auditops.QueryRequest{
		Caller: caller, ScopeID: strings.TrimSpace(req.ScopeID),
		Filter: auditops.Filter{
			From: filter.From, To: filter.To, AppID: strings.TrimSpace(filter.AppID),
			SystemOnly: filter.SystemOnly, ActorType: audit.ActorKind(filter.ActorType),
			ActorID: strings.TrimSpace(filter.ActorID), Action: strings.TrimSpace(filter.Action),
			Outcome: audit.Outcome(filter.Outcome), ErrorCode: strings.TrimSpace(filter.ErrorCode),
			RequestID: strings.TrimSpace(filter.RequestID), TaskID: strings.TrimSpace(filter.TaskID),
			TargetType: strings.TrimSpace(filter.TargetType), TargetID: strings.TrimSpace(filter.TargetID),
		},
		Order: auditops.SortOrder(strings.TrimSpace(req.Order)),
		Limit: limit, Cursor: cursor})
	if err != nil {
		return AdminAuditEventList{}, call.domainError("查询审计事件失败",
			string(auditops.CodeOf(err)))
	}
	events := make([]AdminAuditEvent, 0, len(result.Events))
	for _, event := range result.Events {
		events = append(events, toAdminAuditEvent(event))
	}
	return AdminAuditEventList{Events: events, HasMore: result.HasMore,
		Limit: result.Limit, NextCursor: result.NextCursor, Order: string(result.Order),
		ScopeID: result.Scope.ID, ScopeKind: result.Scope.Kind,
		RetentionDays:       result.Retention.Days,
		RetentionConfigured: result.Retention.Configured,
		RetentionCutoff:     result.Retention.Cutoff}, nil
}

// ListReports 分页查询历史报告（游标绑定 plan_id/state 筛选）。
func (f *adminFacade) ListReports(ctx context.Context,
	req AdminListReportsRequest) (AdminReportList, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminReportList{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Reports == nil {
		return AdminReportList{}, call.configError("报告服务未装配")
	}
	caller, err := f.accountCaller(call.identity)
	if err != nil {
		return AdminReportList{}, call.configError("报告服务调用者无效")
	}
	limit, err := normalizeAdminCursorLimit(req.Limit)
	if err != nil {
		return AdminReportList{}, err
	}
	cursor, err := normalizeAdminCursor(req.Cursor)
	if err != nil {
		return AdminReportList{}, err
	}
	result, err := managed.Reports.HistoryList(ctx, reports.HistoryListRequest{
		Caller: caller, PlanID: strings.TrimSpace(req.PlanID),
		State: strings.TrimSpace(req.State), Limit: limit, Cursor: cursor})
	if err != nil {
		return AdminReportList{}, call.domainError("查询历史报告失败",
			string(reports.CodeOf(err)))
	}
	records := make([]AdminReportHistory, 0, len(result.Records))
	for _, record := range result.Records {
		records = append(records, toAdminReportHistory(record))
	}
	return AdminReportList{Reports: records, HasMore: result.HasMore, Limit: limit,
		NextCursor: result.NextCursor, ScopeTrimmed: result.ScopeTrimmed}, nil
}

// ListReportPlans 分页查询报告计划（offset 契约）。
func (f *adminFacade) ListReportPlans(ctx context.Context,
	req AdminListReportPlansRequest) (AdminReportPlanList, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminReportPlanList{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.Plans == nil {
		return AdminReportPlanList{}, call.configError("报告计划服务未装配")
	}
	caller, err := f.accountCaller(call.identity)
	if err != nil {
		return AdminReportPlanList{}, call.configError("报告服务调用者无效")
	}
	page, err := call.page(req.Page)
	if err != nil {
		return AdminReportPlanList{}, err
	}
	result, err := managed.Plans.ListPage(ctx, reports.PlanListRequest{
		Caller: caller, Limit: page.Limit, Offset: page.Offset})
	if err != nil {
		return AdminReportPlanList{}, call.domainError("查询报告计划失败",
			string(reports.CodeOf(err)))
	}
	plans := make([]AdminReportPlan, 0, len(result.Plans))
	for _, plan := range result.Plans {
		plans = append(plans, toAdminReportPlan(plan))
	}
	return AdminReportPlanList{Plans: plans, HasMore: result.HasMore,
		Page: NewAdminPageInfo(page, len(plans), result.HasMore)}, nil
}

// ListBackupJobs 分页查询备份/清理任务（offset 契约）。
func (f *adminFacade) ListBackupJobs(ctx context.Context,
	req AdminListBackupJobsRequest) (AdminBackupJobList, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminBackupJobList{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.BackupAdmin == nil {
		return AdminBackupJobList{}, call.configError("备份管理服务未装配")
	}
	caller, err := f.accountCaller(call.identity)
	if err != nil {
		return AdminBackupJobList{}, call.configError("备份服务调用者无效")
	}
	page, err := call.page(req.Page)
	if err != nil {
		return AdminBackupJobList{}, err
	}
	views, hasMore, err := managed.BackupAdmin.ListJobs(ctx, caller, backupadmin.JobFilter{
		Kind: strings.TrimSpace(req.Kind), ScheduleID: strings.TrimSpace(req.ScheduleID),
		Limit: page.Limit, Offset: page.Offset})
	if err != nil {
		return AdminBackupJobList{}, call.domainError("查询备份任务失败",
			string(backupadmin.CodeOf(err)))
	}
	jobs := make([]AdminBackupJob, 0, len(views))
	for _, view := range views {
		jobs = append(jobs, AdminBackupJob{ID: view.ID, Kind: view.Kind,
			Origin: view.Origin, ScheduleID: view.ScheduleID, State: view.State,
			StageCode: view.StageCode, Attempt: view.Attempt, MaxAttempts: view.MaxAttempts,
			InitiatorType: string(view.Initiator.Type), InitiatorID: view.Initiator.ID,
			ErrorCode: view.ErrorCode, FailureReason: view.FailureReason,
			RequestID: view.RequestID, BackupID: view.BackupID, CreatedAt: view.CreatedAt,
			StartedAt: view.StartedAt, FinishedAt: view.FinishedAt})
	}
	return AdminBackupJobList{Jobs: jobs, HasMore: hasMore,
		Page: NewAdminPageInfo(page, len(jobs), hasMore)}, nil
}

// ListBackupArtifacts 分页查询备份产物（offset 契约）。
func (f *adminFacade) ListBackupArtifacts(ctx context.Context,
	req AdminListBackupArtifactsRequest) (AdminBackupArtifactList, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminBackupArtifactList{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.BackupAdmin == nil {
		return AdminBackupArtifactList{}, call.configError("备份管理服务未装配")
	}
	caller, err := f.accountCaller(call.identity)
	if err != nil {
		return AdminBackupArtifactList{}, call.configError("备份服务调用者无效")
	}
	page, err := call.page(req.Page)
	if err != nil {
		return AdminBackupArtifactList{}, err
	}
	views, hasMore, err := managed.BackupAdmin.ListArtifacts(ctx, caller,
		backupadmin.ArtifactFilter{Origin: backupadmin.Origin(strings.TrimSpace(req.Origin)),
			Verification: backupadmin.VerificationState(strings.TrimSpace(req.Verification)),
			Cleanup:      backupadmin.CleanupState(strings.TrimSpace(req.Cleanup)),
			ScheduleID:   strings.TrimSpace(req.ScheduleID), JobID: strings.TrimSpace(req.JobID),
			Limit: page.Limit, Offset: page.Offset})
	if err != nil {
		return AdminBackupArtifactList{}, call.domainError("查询备份产物失败",
			string(backupadmin.CodeOf(err)))
	}
	artifacts := make([]AdminBackupArtifact, 0, len(views))
	for _, view := range views {
		artifacts = append(artifacts, AdminBackupArtifact{ID: view.BackupID,
			JobID: view.JobID, ScheduleID: view.ScheduleID, Origin: view.Origin,
			SizeBytes: view.SizeBytes, FileSHA256: view.FileSHA256,
			Verification: view.Verification, VerifiedAt: view.VerifiedAt,
			Cleanup: view.Cleanup, CreatedAt: view.CreatedAt, PublishedAt: view.PublishedAt,
			FileExists: view.FileExists, IsLastUsable: view.IsLastUsable,
			ProtectionReason: view.ProtectionReason, Downloadable: view.Downloadable})
	}
	return AdminBackupArtifactList{Artifacts: artifacts, HasMore: hasMore,
		Page: NewAdminPageInfo(page, len(artifacts), hasMore)}, nil
}

// ListBackupSchedules 分页查询备份计划（offset 契约）。
func (f *adminFacade) ListBackupSchedules(ctx context.Context,
	req AdminListBackupSchedulesRequest) (AdminBackupScheduleList, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminBackupScheduleList{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.BackupAdmin == nil {
		return AdminBackupScheduleList{}, call.configError("备份管理服务未装配")
	}
	caller, err := f.accountCaller(call.identity)
	if err != nil {
		return AdminBackupScheduleList{}, call.configError("备份服务调用者无效")
	}
	page, err := call.page(req.Page)
	if err != nil {
		return AdminBackupScheduleList{}, err
	}
	views, hasMore, err := managed.BackupAdmin.ListSchedulesPage(ctx, caller,
		page.Limit, page.Offset)
	if err != nil {
		return AdminBackupScheduleList{}, call.domainError("查询备份计划失败",
			string(backupadmin.CodeOf(err)))
	}
	schedules := make([]AdminBackupSchedule, 0, len(views))
	for _, view := range views {
		schedules = append(schedules, AdminBackupSchedule{ID: view.ID, Name: view.Name,
			Enabled: view.Enabled, ScheduleType: view.ScheduleType,
			Expression: view.Expression, TimeZone: view.TimeZone,
			PeriodDescription: view.PeriodDescription, MissedPolicy: view.MissedPolicy,
			ScopeID: view.ScopeID, NextRun: view.NextRun, NextRunUnknown: view.NextRunUnknown,
			CreatedAt: view.CreatedAt, UpdatedAt: view.UpdatedAt,
			PermissionState: view.PermissionState})
	}
	return AdminBackupScheduleList{Schedules: schedules, HasMore: hasMore,
		Page: NewAdminPageInfo(page, len(schedules), hasMore)}, nil
}

// ListBackupNotifications 分页查询任务/产物的通知投递记录（offset 契约）。
func (f *adminFacade) ListBackupNotifications(ctx context.Context,
	req AdminListBackupNotificationsRequest) (AdminBackupNotificationList, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminBackupNotificationList{}, err
	}
	managed := f.r.managedServices()
	if managed == nil || managed.BackupAdmin == nil {
		return AdminBackupNotificationList{}, call.configError("备份管理服务未装配")
	}
	caller, err := f.accountCaller(call.identity)
	if err != nil {
		return AdminBackupNotificationList{}, call.configError("备份服务调用者无效")
	}
	page, err := call.page(req.Page)
	if err != nil {
		return AdminBackupNotificationList{}, err
	}
	records, hasMore, err := managed.BackupAdmin.ListNotificationsPage(ctx, caller,
		strings.TrimSpace(req.JobID), strings.TrimSpace(req.BackupID),
		page.Limit, page.Offset)
	if err != nil {
		return AdminBackupNotificationList{}, call.domainError("查询备份通知失败",
			string(backupadmin.CodeOf(err)))
	}
	notifications := make([]AdminBackupNotification, 0, len(records))
	for _, record := range records {
		notifications = append(notifications, AdminBackupNotification{
			ID: record.ID, JobID: record.JobID, BackupID: record.BackupID,
			Kind: record.Kind, State: record.State, Channel: record.Channel,
			RecipientMasked: record.RecipientMasked, ErrorCode: record.ErrorCode,
			Attempts: record.Attempts, CreatedAt: record.CreatedAt,
			UpdatedAt: record.UpdatedAt})
	}
	return AdminBackupNotificationList{Notifications: notifications, HasMore: hasMore,
		Page: NewAdminPageInfo(page, len(notifications), hasMore)}, nil
}

// ListTasks 分页查询后台任务（稳定游标）。本机受信操作者可查看全部；管理会话只
// 返回本人发起的任务（列表授权由任务领域按发起者过滤，不使用客户端自报范围）。
func (f *adminFacade) ListTasks(ctx context.Context,
	req AdminListTasksRequest) (AdminTaskList, error) {
	call, err := f.begin(ctx, req.Caller, req.RequestID)
	if err != nil {
		return AdminTaskList{}, err
	}
	if f.r.base == nil || f.r.base.Tasks == nil || f.r.base.Tasks.Executor() == nil {
		return AdminTaskList{}, call.configError("后台任务运行时未装配")
	}
	limit, err := normalizeAdminCursorLimit(req.Limit)
	if err != nil {
		return AdminTaskList{}, err
	}
	cursor, err := normalizeAdminCursor(req.Cursor)
	if err != nil {
		return AdminTaskList{}, err
	}
	listRequest := task.ListJobsRequest{State: task.State(strings.TrimSpace(req.State)),
		Kind: strings.TrimSpace(req.Kind), RequestID: strings.TrimSpace(req.TaskRequestID),
		From: req.From, To: req.To, Limit: limit, Cursor: cursor}
	if !call.identity.local {
		listRequest.InitiatorType = call.identity.actor.Type
		listRequest.InitiatorID = call.identity.actor.ID
	}
	page, err := f.r.base.Tasks.Executor().ListJobs(ctx, listRequest)
	if err != nil {
		code := "INTERNAL_ERROR"
		if errors.Is(err, task.ErrInvalidRequest) {
			code = "REQ_INVALID"
		}
		return AdminTaskList{}, call.domainError("查询后台任务失败", code)
	}
	tasks := make([]AdminTask, 0, len(page.Jobs))
	for _, job := range page.Jobs {
		tasks = append(tasks, AdminTask{ID: job.ID, Kind: job.Kind,
			State: string(job.State), InitiatorType: string(job.Initiator.Type),
			InitiatorID: job.Initiator.ID, ExecutorID: job.ExecutorID,
			Attempt: job.Attempt, MaxAttempts: job.MaxAttempts, ErrorCode: job.ErrorCode,
			FailureReason: job.FailureReason, RequestID: job.RequestID,
			CreatedAt: job.CreatedAt, StartedAt: job.StartedAt, FinishedAt: job.FinishedAt})
	}
	return AdminTaskList{Tasks: tasks, HasMore: page.HasMore, Limit: page.Limit,
		NextCursor: page.NextCursor}, nil
}

// toAdminAuditEvent 把领域审计事件投影为公开脱敏视图。
func toAdminAuditEvent(event audit.Event) AdminAuditEvent {
	view := AdminAuditEvent{ID: event.ID, OccurredAt: event.OccurredAt,
		ActorType: string(event.Actor.Type), ActorID: event.Actor.ID, AppID: event.AppID,
		Action: event.Action, TargetType: event.Target.Type, TargetID: event.Target.ID,
		Outcome: string(event.Outcome), ErrorCode: event.ErrorCode,
		ReasonCode: event.ReasonCode, RequestID: event.RequestID, TaskID: event.TaskID}
	for _, change := range event.Changes {
		view.Changes = append(view.Changes, AdminAuditChange{Field: change.Field,
			Before: change.Before, After: change.After})
	}
	return view
}

// toAdminReportHistory 把报告历史视图投影为公开脱敏视图。
func toAdminReportHistory(record reports.ReportHistoryView) AdminReportHistory {
	view := AdminReportHistory{ID: record.ID, PlanID: record.PlanID, Name: record.Name,
		OwnerType: string(record.Owner.Type), OwnerID: record.Owner.ID,
		ScopeID: record.ScopeID, ScopeKind: record.ScopeKind, AppID: record.AppID,
		State: record.State, TaskID: record.TaskID, ExecutorID: record.ExecutorID,
		ErrorCode: record.ErrorCode, FailureReason: record.FailureReason,
		RequestID: record.RequestID, CreatedAt: record.CreatedAt,
		StartedAt: record.StartedAt, FinishedAt: record.FinishedAt,
		ExpiresAt: record.ExpiresAt, CleanupState: record.CleanupState}
	for _, format := range record.Formats {
		view.Formats = append(view.Formats, string(format))
	}
	for _, artifact := range record.Artifacts {
		view.Artifacts = append(view.Artifacts, AdminReportArtifact{
			Format: string(artifact.Format), Bytes: artifact.Bytes,
			SHA256: artifact.SHA256, Available: artifact.Available,
			ExpiresAt: artifact.ExpiresAt})
	}
	return view
}

// toAdminReportPlan 把报告计划视图投影为公开脱敏视图。
func toAdminReportPlan(plan reports.PlanView) AdminReportPlan {
	view := AdminReportPlan{ID: plan.ID, Name: plan.Name, OwnerType: string(plan.Owner.Type),
		OwnerID: plan.Owner.ID, ScopeID: plan.ScopeID, ScopeKind: plan.ScopeKind,
		AppID: plan.AppID, ScheduleType: string(plan.ScheduleType),
		Expression: plan.Expression, TimeZone: plan.TimeZone,
		Granularity: string(plan.Granularity), Enabled: plan.Enabled,
		Version: plan.Version, CreatedAt: plan.CreatedAt, UpdatedAt: plan.UpdatedAt,
		PermissionState: plan.PermissionState}
	for _, format := range plan.Formats {
		view.Formats = append(view.Formats, string(format))
	}
	return view
}
