package adminapi

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/backupadmin"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/reports"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// 管理 API 自身写操作的敏感操作 ID（领域服务未内置 reauth 的动作）。这些 ID
// 使用 internal/policy 目录已登记的语义名称，不新增权限键。
const (
	OperationScheduleManage       = "reports.schedule.manage"
	OperationBackupScheduleManage = "backups.create"
	OperationNotificationTest     = "notifications.test"
)

// authorizeSensitive 执行管理 API 自身写操作的敏感策略（强认证/再次认证）。
// 未装配 Sensitive 时 fail-closed（403 REAUTH_REQUIRED），绝不退化为只查权限。
// 策略拒绝统一映射为 REAUTH_REQUIRED，不泄露策略细节。
func (s *Server) authorizeSensitive(ctx context.Context, caller account.Caller,
	operationID, scopeID, targetType, targetID, requestID string,
	params map[string]string) *problem {
	if s.sensitive == nil {
		return s.codeProblem(string(codeReauthRequired), nil)
	}
	reauthCaller, err := reauth.CallerFromActor(caller.Actor())
	if err != nil {
		return s.codeProblem(string(codeAccessDenied), err)
	}
	result, err := s.sensitive.Authorize(ctx, reauthCaller, reauth.Request{
		ScopeID: scopeID, OperationID: operationID, TargetType: targetType,
		TargetID: targetID, Params: params, RequestID: requestID,
		Description: "管理 API 敏感操作"})
	if err != nil {
		if reauth.CodeOf(err) == reauth.CodeReauthRequired {
			return s.codeProblem(string(codeReauthRequired), err)
		}
		return s.codeProblem(string(codeAccessDenied), err)
	}
	// 结果回执只记录在敏感操作模块内；失败不影响已完成的授权判定。
	_ = s.sensitive.NotifyOutcome(ctx, result, reauth.OutcomeSuccess)
	return nil
}

// planWriteInput 是报告计划创建/编辑请求的服务端白名单字段。所有者、执行身份
// 与计划编号不能由客户端自报：所有者固定为当前调用者，计划编号只来自路径。
type planWriteInput struct {
	Confirm        bool     `json:"confirm"`
	Name           string   `json:"name"`
	ScheduleType   string   `json:"schedule_type"`
	Expression     string   `json:"expression"`
	TimeZone       string   `json:"time_zone"`
	ScopeID        string   `json:"scope_id"`
	AppID          string   `json:"app_id"`
	Granularity    string   `json:"granularity"`
	WindowDays     int      `json:"window_days"`
	Categories     []string `json:"categories"`
	TrendMetric    string   `json:"trend_metric"`
	Formats        []string `json:"formats"`
	DetailRows     int      `json:"detail_rows"`
	MissedPolicy   string   `json:"missed_policy"`
	MaxCatchUp     int      `json:"max_catch_up"`
	TimeoutSeconds int      `json:"timeout_seconds"`
	MaxAttempts    int      `json:"max_attempts"`
	Enabled        bool     `json:"enabled"`
	RequestID      string   `json:"request_id"`
	Version        int64    `json:"version"`
	Reason         string   `json:"reason"`
}

// createRequest 转换为报告计划创建请求（权限/审计/校验由 PlanService 执行）。
func (input planWriteInput) createRequest(caller account.Caller, requestID string) reports.PlanCreateRequest {
	categories := make([]stats.Category, 0, len(input.Categories))
	for _, category := range input.Categories {
		categories = append(categories, stats.Category(category))
	}
	formats := make([]reports.Format, 0, len(input.Formats))
	for _, format := range input.Formats {
		formats = append(formats, reports.Format(format))
	}
	return reports.PlanCreateRequest{
		Caller: caller, Name: input.Name,
		ScheduleType: task.ScheduleType(input.ScheduleType),
		Expression:   input.Expression, TimeZone: input.TimeZone,
		ScopeID: input.ScopeID, Granularity: stats.Granularity(input.Granularity),
		WindowDays: input.WindowDays, AppID: input.AppID, Categories: categories,
		TrendMetric: stats.Metric(input.TrendMetric), Formats: formats,
		DetailRows: input.DetailRows, MissedPolicy: task.MissedPolicy(input.MissedPolicy),
		MaxCatchUp: input.MaxCatchUp, TimeoutSeconds: input.TimeoutSeconds,
		MaxAttempts: input.MaxAttempts, Enabled: input.Enabled,
		RequestID: firstNonEmpty(input.RequestID, requestID),
	}
}

// handlePlanCreate 处理 POST /report-plans：确认 + 敏感策略 + 领域权限/审计。
func (s *Server) handlePlanCreate(c *callContext) error {
	var input planWriteInput
	if err := c.decodeJSON(&input); err != nil {
		return err
	}
	if err := requireConfirm(input.Confirm); err != nil {
		return err
	}
	scopeID := input.ScopeID
	if scopeID == "" {
		return fmt.Errorf("%w: 缺少作用范围 scope_id", ErrInvalidRequest)
	}
	if problem := s.authorizeSensitive(c.request.Context(), c.caller,
		OperationScheduleManage, scopeID, "report_plan", "", c.requestID,
		map[string]string{"scope_id": scopeID, "name": input.Name}); problem != nil {
		return problem
	}
	view, err := s.plans.Create(c.request.Context(),
		input.createRequest(c.caller, c.requestID))
	if err != nil {
		return s.reportProblem(err)
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{"plan": toPlanDTO(view)})
	return nil
}

// handlePlanUpdate 处理 PUT /report-plans/{plan_id}：行版本乐观并发 + 确认 +
// 敏感策略；PlanID 只来自路径，不接受请求体自报归属。
func (s *Server) handlePlanUpdate(c *callContext) error {
	var input planWriteInput
	if err := c.decodeJSON(&input); err != nil {
		return err
	}
	if err := requireConfirm(input.Confirm); err != nil {
		return err
	}
	planID := c.pathParam("plan_id")
	if strings.TrimSpace(planID) == "" {
		return fmt.Errorf("%w: 计划编号无效", ErrInvalidRequest)
	}
	if input.Version <= 0 {
		return fmt.Errorf("%w: 编辑计划必须提供读取时的行版本 version", ErrInvalidRequest)
	}
	scopeID := input.ScopeID
	if scopeID == "" {
		scopeID = reports.ScopeSystem
	}
	request := input.createRequest(c.caller, c.requestID)
	update := reports.PlanUpdateRequest{PlanCreateRequest: request,
		PlanID: planID, Version: input.Version, Reason: input.Reason}
	if problem := s.authorizeSensitive(c.request.Context(), c.caller,
		OperationScheduleManage, scopeID, "report_plan", planID, c.requestID,
		map[string]string{"plan_id": planID, "version": fmt.Sprintf("%d", input.Version)}); problem != nil {
		return problem
	}
	view, err := s.plans.Update(c.request.Context(), update)
	if err != nil {
		return s.reportProblem(err)
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{"plan": toPlanDTO(view)})
	return nil
}

// planEnabledInput 是报告计划启停请求体。
type planEnabledInput struct {
	Confirm bool   `json:"confirm"`
	Enabled bool   `json:"enabled"`
	Reason  string `json:"reason"`
}

// handlePlanSetEnabled 处理 POST /report-plans/{plan_id}/enabled：启停可能改变
// 实际执行范围，必须确认 + 敏感策略 + 原因（进入审计）。
func (s *Server) handlePlanSetEnabled(c *callContext) error {
	var input planEnabledInput
	if err := c.decodeJSON(&input); err != nil {
		return err
	}
	if err := requireConfirm(input.Confirm); err != nil {
		return err
	}
	reason, err := requireReason(input.Reason)
	if err != nil {
		return err
	}
	planID := c.pathParam("plan_id")
	if problem := s.authorizeSensitive(c.request.Context(), c.caller,
		OperationScheduleManage, reports.ScopeSystem, "report_plan", planID,
		c.requestID, map[string]string{"plan_id": planID,
			"enabled": fmt.Sprintf("%t", input.Enabled)}); problem != nil {
		return problem
	}
	view, err := s.plans.SetEnabled(c.request.Context(), c.caller, planID,
		input.Enabled, reason, c.requestID)
	if err != nil {
		return s.reportProblem(err)
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{"plan": toPlanDTO(view)})
	return nil
}

// planDeletePreviewDTO 是计划删除前的影响预览公开投影（预览不是删除授权）。
type planDeletePreviewDTO struct {
	PlanID           string    `json:"plan_id"`
	Name             string    `json:"name"`
	ScopeID          string    `json:"scope_id"`
	Enabled          bool      `json:"enabled"`
	NextRun          time.Time `json:"next_run,omitempty"`
	NextRunUnknown   bool      `json:"next_run_unknown"`
	MissedPolicy     string    `json:"missed_policy,omitempty"`
	ActiveTasksNote  string    `json:"active_tasks_note,omitempty"`
	HistoryNote      string    `json:"history_note,omitempty"`
	RawAuditNote     string    `json:"raw_audit_note,omitempty"`
	Irreversible     bool      `json:"irreversible"`
	PermissionState  string    `json:"permission_state,omitempty"`
	PermissionReason string    `json:"permission_reason,omitempty"`
	CreatedAt        time.Time `json:"created_at,omitempty"`
	PreviewedAt      time.Time `json:"previewed_at"`
}

// handlePlanDeletePreview 处理 GET /report-plans/{plan_id}/delete-preview。
func (s *Server) handlePlanDeletePreview(c *callContext) error {
	preview, err := s.plans.DeletePreview(c.request.Context(), c.caller,
		c.pathParam("plan_id"))
	if err != nil {
		return s.reportProblem(err)
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{
		"delete_preview": planDeletePreviewDTO{
			PlanID: preview.PlanID, Name: preview.Name, ScopeID: preview.ScopeID,
			Enabled: preview.Enabled, NextRun: preview.NextRun,
			NextRunUnknown:  preview.NextRunUnknown,
			MissedPolicy:    preview.MissedPolicy,
			ActiveTasksNote: preview.ActiveTasksNote,
			HistoryNote:     preview.HistoryNote, RawAuditNote: preview.RawAuditNote,
			Irreversible:     preview.Irreversible,
			PermissionState:  preview.PermissionState,
			PermissionReason: preview.PermissionReason, CreatedAt: preview.CreatedAt,
			PreviewedAt: preview.PreviewedAt}})
	return nil
}

// handlePlanDelete 处理 DELETE /report-plans/{plan_id}：确认 + 原因 + 敏感策略。
func (s *Server) handlePlanDelete(c *callContext) error {
	var input planEnabledInput
	if err := c.decodeJSON(&input); err != nil {
		return err
	}
	if err := requireConfirm(input.Confirm); err != nil {
		return err
	}
	reason, err := requireReason(input.Reason)
	if err != nil {
		return err
	}
	planID := c.pathParam("plan_id")
	if problem := s.authorizeSensitive(c.request.Context(), c.caller,
		OperationScheduleManage, reports.ScopeSystem, "report_plan", planID,
		c.requestID, map[string]string{"plan_id": planID}); problem != nil {
		return problem
	}
	if err := s.plans.Delete(c.request.Context(), c.caller, planID, reason,
		c.requestID); err != nil {
		return s.reportProblem(err)
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{"deleted": true, "plan_id": planID})
	return nil
}

// backupScheduleInput 是备份计划创建/编辑请求的服务端白名单字段。
type backupScheduleInput struct {
	Confirm          bool   `json:"confirm"`
	Name             string `json:"name"`
	ScheduleType     string `json:"schedule_type"`
	Expression       string `json:"expression"`
	TimeZone         string `json:"time_zone"`
	MissedPolicy     string `json:"missed_policy"`
	MaxCatchUp       int    `json:"max_catch_up"`
	TimeoutSeconds   int    `json:"timeout_seconds"`
	MaxAttempts      int    `json:"max_attempts"`
	RetentionVersion int64  `json:"retention_version"`
	NotifyFailures   bool   `json:"notify_failures"`
	NotifySuccess    bool   `json:"notify_success"`
	NotifyTarget     string `json:"notify_target"`
	Enabled          bool   `json:"enabled"`
	RequestID        string `json:"request_id"`
	Reason           string `json:"reason"`
}

// scheduleRequest 转换为备份计划请求（权限/校验/审计由 backupadmin 执行）。
func (input backupScheduleInput) scheduleRequest(caller account.Caller,
	requestID string) backupadmin.ScheduleRequest {
	return backupadmin.ScheduleRequest{
		Caller: caller, Name: input.Name,
		ScheduleType: task.ScheduleType(input.ScheduleType),
		Expression:   input.Expression, TimeZone: input.TimeZone,
		MissedPolicy: task.MissedPolicy(input.MissedPolicy),
		MaxCatchUp:   input.MaxCatchUp, TimeoutSeconds: input.TimeoutSeconds,
		MaxAttempts: input.MaxAttempts, RetentionVersion: input.RetentionVersion,
		NotifyFailures: input.NotifyFailures, NotifySuccess: input.NotifySuccess,
		NotifyTarget: input.NotifyTarget, Enabled: input.Enabled,
		RequestID: firstNonEmpty(input.RequestID, requestID),
	}
}

// handleBackupScheduleGet 处理 GET /backups/schedules/{schedule_id}。
func (s *Server) handleBackupScheduleGet(c *callContext) error {
	view, err := s.backups.GetSchedule(c.request.Context(), c.caller,
		c.pathParam("schedule_id"))
	if err != nil {
		return s.backupProblem(err)
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{"schedule": toBackupScheduleDTO(view)})
	return nil
}

// handleBackupScheduleCreate 处理 POST /backups/schedules。
func (s *Server) handleBackupScheduleCreate(c *callContext) error {
	var input backupScheduleInput
	if err := c.decodeJSON(&input); err != nil {
		return err
	}
	if err := requireConfirm(input.Confirm); err != nil {
		return err
	}
	if problem := s.authorizeSensitive(c.request.Context(), c.caller,
		OperationBackupScheduleManage, reports.ScopeSystem, "backup_schedule", "",
		c.requestID, map[string]string{"name": input.Name}); problem != nil {
		return problem
	}
	view, err := s.backups.CreateSchedule(c.request.Context(),
		input.scheduleRequest(c.caller, c.requestID))
	if err != nil {
		return s.backupProblem(err)
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{"schedule": toBackupScheduleDTO(view)})
	return nil
}

// handleBackupScheduleUpdate 处理 PUT /backups/schedules/{schedule_id}。
func (s *Server) handleBackupScheduleUpdate(c *callContext) error {
	var input backupScheduleInput
	if err := c.decodeJSON(&input); err != nil {
		return err
	}
	if err := requireConfirm(input.Confirm); err != nil {
		return err
	}
	scheduleID := c.pathParam("schedule_id")
	if problem := s.authorizeSensitive(c.request.Context(), c.caller,
		OperationBackupScheduleManage, reports.ScopeSystem, "backup_schedule",
		scheduleID, c.requestID, map[string]string{"schedule_id": scheduleID}); problem != nil {
		return problem
	}
	view, err := s.backups.UpdateSchedule(c.request.Context(), scheduleID,
		input.scheduleRequest(c.caller, c.requestID))
	if err != nil {
		return s.backupProblem(err)
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{"schedule": toBackupScheduleDTO(view)})
	return nil
}

// handleBackupScheduleSetEnabled 处理 POST /backups/schedules/{id}/enabled。
func (s *Server) handleBackupScheduleSetEnabled(c *callContext) error {
	var input planEnabledInput
	if err := c.decodeJSON(&input); err != nil {
		return err
	}
	if err := requireConfirm(input.Confirm); err != nil {
		return err
	}
	reason, err := requireReason(input.Reason)
	if err != nil {
		return err
	}
	scheduleID := c.pathParam("schedule_id")
	if problem := s.authorizeSensitive(c.request.Context(), c.caller,
		OperationBackupScheduleManage, reports.ScopeSystem, "backup_schedule",
		scheduleID, c.requestID, map[string]string{"schedule_id": scheduleID,
			"enabled": fmt.Sprintf("%t", input.Enabled)}); problem != nil {
		return problem
	}
	view, err := s.backups.SetScheduleEnabled(c.request.Context(), c.caller,
		scheduleID, input.Enabled, reason, c.requestID)
	if err != nil {
		return s.backupProblem(err)
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{"schedule": toBackupScheduleDTO(view)})
	return nil
}

// handleBackupScheduleDelete 处理 DELETE /backups/schedules/{schedule_id}。
func (s *Server) handleBackupScheduleDelete(c *callContext) error {
	var input planEnabledInput
	if err := c.decodeJSON(&input); err != nil {
		return err
	}
	if err := requireConfirm(input.Confirm); err != nil {
		return err
	}
	reason, err := requireReason(input.Reason)
	if err != nil {
		return err
	}
	scheduleID := c.pathParam("schedule_id")
	if problem := s.authorizeSensitive(c.request.Context(), c.caller,
		OperationBackupScheduleManage, reports.ScopeSystem, "backup_schedule",
		scheduleID, c.requestID, map[string]string{"schedule_id": scheduleID}); problem != nil {
		return problem
	}
	if err := s.backups.DeleteSchedule(c.request.Context(), c.caller, scheduleID,
		reason, c.requestID); err != nil {
		return s.backupProblem(err)
	}
	s.writeSuccess(c.writer, c.requestID,
		map[string]any{"deleted": true, "schedule_id": scheduleID})
	return nil
}
