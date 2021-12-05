package adminapi

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/backupadmin"
)

// backupArtifactDTO 是备份产物公开投影：不含宿主绝对路径、密钥或明文内容。
type backupArtifactDTO struct {
	BackupID         string    `json:"backup_id"`
	JobID            string    `json:"job_id,omitempty"`
	ScheduleID       string    `json:"schedule_id,omitempty"`
	Origin           string    `json:"origin"`
	SizeBytes        int64     `json:"size_bytes"`
	FileSHA256       string    `json:"file_sha256,omitempty"`
	ManifestSHA256   string    `json:"manifest_sha256,omitempty"`
	FormatVersion    int       `json:"format_version"`
	SchemaVersion    string    `json:"schema_version,omitempty"`
	ContentDatabase  bool      `json:"content_database"`
	ContentAttach    string    `json:"content_attach,omitempty"`
	ContentConfig    string    `json:"content_config,omitempty"`
	EntryCount       int       `json:"entry_count"`
	Hostname         string    `json:"hostname,omitempty"`
	AppVersion       string    `json:"app_version,omitempty"`
	Verification     string    `json:"verification"`
	VerifiedAt       time.Time `json:"verified_at,omitempty"`
	RetentionVersion int64     `json:"retention_version"`
	Cleanup          string    `json:"cleanup"`
	CleanedAt        time.Time `json:"cleaned_at,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	PublishedAt      time.Time `json:"published_at,omitempty"`
	FileExists       bool      `json:"file_exists"`
	IsLastUsable     bool      `json:"is_last_usable"`
	ProtectionReason string    `json:"protection_reason,omitempty"`
	Downloadable     bool      `json:"downloadable"`
}

func toBackupArtifactDTO(view backupadmin.ArtifactView) backupArtifactDTO {
	return backupArtifactDTO{BackupID: view.BackupID, JobID: view.JobID,
		ScheduleID: view.ScheduleID, Origin: string(view.Origin),
		SizeBytes: view.SizeBytes, FileSHA256: view.FileSHA256,
		ManifestSHA256: view.ManifestSHA256, FormatVersion: view.FormatVersion,
		SchemaVersion: view.SchemaVersion, ContentDatabase: view.ContentDatabase,
		ContentAttach: view.ContentAttach, ContentConfig: view.ContentConfig,
		EntryCount: view.EntryCount, Hostname: view.Hostname,
		AppVersion: view.AppVersion, Verification: string(view.Verification),
		VerifiedAt: view.VerifiedAt, RetentionVersion: view.RetentionVersion,
		Cleanup: string(view.Cleanup), CleanedAt: view.CleanedAt,
		CreatedAt: view.CreatedAt, PublishedAt: view.PublishedAt,
		FileExists: view.FileExists, IsLastUsable: view.IsLastUsable,
		ProtectionReason: view.ProtectionReason, Downloadable: view.Downloadable}
}

// backupJobDTO 是备份/清理任务公开投影：状态来自 internal/task 真实状态机，
// 缺少进度即未知，不伪造百分比。
type backupJobDTO struct {
	ID                string    `json:"id"`
	Kind              string    `json:"kind"`
	Origin            string    `json:"origin"`
	ScheduleID        string    `json:"schedule_id,omitempty"`
	State             string    `json:"state"`
	StageCode         string    `json:"stage_code,omitempty"`
	StageDescription  string    `json:"stage_description,omitempty"`
	ProgressDone      *int64    `json:"progress_done,omitempty"`
	ProgressTotal     *int64    `json:"progress_total,omitempty"`
	ProgressUnit      string    `json:"progress_unit,omitempty"`
	Attempt           int       `json:"attempt"`
	MaxAttempts       int       `json:"max_attempts"`
	Initiator         actorDTO  `json:"initiator"`
	ErrorCode         string    `json:"error_code,omitempty"`
	FailureReason     string    `json:"failure_reason,omitempty"`
	RequestID         string    `json:"request_id,omitempty"`
	BackupID          string    `json:"backup_id,omitempty"`
	NotificationState string    `json:"notification_state,omitempty"`
	NotificationCode  string    `json:"notification_code,omitempty"`
	ResultSummary     string    `json:"result_summary,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	StartedAt         time.Time `json:"started_at,omitempty"`
	FinishedAt        time.Time `json:"finished_at,omitempty"`
	UpdatedAt         time.Time `json:"updated_at,omitempty"`
}

func toBackupJobDTO(view backupadmin.JobView) backupJobDTO {
	return backupJobDTO{ID: view.ID, Kind: view.Kind, Origin: view.Origin,
		ScheduleID: view.ScheduleID, State: view.State, StageCode: view.StageCode,
		StageDescription: view.StageDescription, ProgressDone: view.ProgressDone,
		ProgressTotal: view.ProgressTotal, ProgressUnit: view.ProgressUnit,
		Attempt: view.Attempt, MaxAttempts: view.MaxAttempts,
		Initiator: toActorDTO(view.Initiator), ErrorCode: view.ErrorCode,
		FailureReason: view.FailureReason, RequestID: view.RequestID,
		BackupID: view.BackupID, NotificationState: view.NotificationStat,
		NotificationCode: view.NotificationCode, ResultSummary: view.ResultSummary,
		CreatedAt: view.CreatedAt, StartedAt: view.StartedAt,
		FinishedAt: view.FinishedAt, UpdatedAt: view.UpdatedAt}
}

// backupScheduleDTO 是备份计划公开投影（周期与时区来自真实计划）。
type backupScheduleDTO struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	Enabled           bool      `json:"enabled"`
	ScheduleType      string    `json:"schedule_type"`
	Expression        string    `json:"expression"`
	TimeZone          string    `json:"time_zone"`
	PeriodDescription string    `json:"period_description,omitempty"`
	MissedPolicy      string    `json:"missed_policy"`
	MaxCatchUp        int       `json:"max_catch_up"`
	TimeoutSeconds    int       `json:"timeout_seconds"`
	MaxAttempts       int       `json:"max_attempts"`
	Owner             actorDTO  `json:"owner"`
	ExecutionActor    actorDTO  `json:"execution_actor"`
	ScopeID           string    `json:"scope_id"`
	NextRun           time.Time `json:"next_run,omitempty"`
	NextRunUnknown    bool      `json:"next_run_unknown"`
	RetentionVersion  int64     `json:"retention_version"`
	NotifyFailures    bool      `json:"notify_failures"`
	NotifySuccess     bool      `json:"notify_success"`
	LastScheduledAt   time.Time `json:"last_scheduled_at,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
	PermissionState   string    `json:"permission_state,omitempty"`
}

func toBackupScheduleDTO(view backupadmin.ScheduleView) backupScheduleDTO {
	return backupScheduleDTO{ID: view.ID, Name: view.Name, Enabled: view.Enabled,
		ScheduleType: string(view.ScheduleType), Expression: view.Expression,
		TimeZone: view.TimeZone, PeriodDescription: view.PeriodDescription,
		MissedPolicy: string(view.MissedPolicy), MaxCatchUp: view.MaxCatchUp,
		TimeoutSeconds: view.TimeoutSeconds, MaxAttempts: view.MaxAttempts,
		Owner: toActorDTO(view.Owner), ExecutionActor: toActorDTO(view.ExecutionActor),
		ScopeID: view.ScopeID, NextRun: view.NextRun,
		NextRunUnknown: view.NextRunUnknown, RetentionVersion: view.RetentionVersion,
		NotifyFailures: view.NotifyFailures, NotifySuccess: view.NotifySuccess,
		LastScheduledAt: view.LastScheduledAt, CreatedAt: view.CreatedAt,
		UpdatedAt: view.UpdatedAt, PermissionState: view.PermissionState}
}

// backupRetentionPolicyDTO 是备份保留策略公开投影（0 表示该项未启用）。
type backupRetentionPolicyDTO struct {
	Version       int64     `json:"version"`
	MaxCount      int       `json:"max_count"`
	MaxAgeDays    int       `json:"max_age_days"`
	MaxTotalBytes int64     `json:"max_total_bytes"`
	UpdatedAt     time.Time `json:"updated_at"`
	UpdatedBy     actorDTO  `json:"updated_by"`
	Reason        string    `json:"reason,omitempty"`
	RequestID     string    `json:"request_id,omitempty"`
}

// backupRetentionDTO 是保留策略页面视图公开投影。
type backupRetentionDTO struct {
	Policy      backupRetentionPolicyDTO `json:"policy"`
	IsDefault   bool                     `json:"is_default"`
	LastCleanup *backupCleanupSummaryDTO `json:"last_cleanup,omitempty"`
}

type backupCleanupSummaryDTO struct {
	JobID          string    `json:"job_id,omitempty"`
	State          string    `json:"state,omitempty"`
	RequestedCount int       `json:"requested_count"`
	CleanedCount   int       `json:"cleaned_count"`
	FailedCount    int       `json:"failed_count"`
	ProtectedCount int       `json:"protected_count"`
	FreedBytes     int64     `json:"freed_bytes"`
	FinishedAt     time.Time `json:"finished_at,omitempty"`
}

// backupCleanupPreviewDTO 是备份清理预览公开投影（不是删除授权）。
type backupCleanupPreviewDTO struct {
	Policy        backupRetentionPolicyDTO `json:"policy"`
	Targets       []backupCandidateDTO     `json:"targets,omitempty"`
	Protected     []backupCandidateDTO     `json:"protected,omitempty"`
	TotalRetained int                      `json:"total_retained"`
	TotalBytes    int64                    `json:"total_bytes"`
	TargetBytes   int64                    `json:"target_bytes"`
	PreviewedAt   time.Time                `json:"previewed_at"`
	Note          string                   `json:"note,omitempty"`
}

type backupCandidateDTO struct {
	BackupID  string    `json:"backup_id"`
	SizeBytes int64     `json:"size_bytes"`
	CreatedAt time.Time `json:"created_at,omitempty"`
	Reason    string    `json:"reason"`
}

// backupCapabilitiesDTO 是当前操作者能力位（每次请求仍重新授权）。
type backupCapabilitiesDTO struct {
	Read        bool `json:"read"`
	Create      bool `json:"create"`
	Cancel      bool `json:"cancel"`
	Download    bool `json:"download"`
	Retention   bool `json:"retention"`
	Cleanup     bool `json:"cleanup"`
	DownloadTTL int  `json:"download_ttl_seconds"`
}

// backupProblem 把备份领域错误映射为统一 problem。
func (s *Server) backupProblem(err error) *problem {
	code := string(backupadmin.CodeOf(err))
	if code == "" {
		code = string(codeInternalError)
	}
	return s.codeProblem(code, err)
}

// handleBackupArtifactList 处理 GET /backups。
func (s *Server) handleBackupArtifactList(c *callContext) error {
	limit, offset, err := pageParams(c.request)
	if err != nil {
		return err
	}
	filter := backupadmin.ArtifactFilter{Limit: limit, Offset: offset}
	if filter.Origin, err = backupEnum[backupadmin.Origin](c, "origin", 32); err != nil {
		return err
	}
	if filter.Verification, err = backupEnum[backupadmin.VerificationState](c, "verification", 32); err != nil {
		return err
	}
	if filter.Cleanup, err = backupEnum[backupadmin.CleanupState](c, "cleanup", 32); err != nil {
		return err
	}
	if filter.ScheduleID, err = queryString(c.request, "schedule_id", 64); err != nil {
		return err
	}
	if filter.JobID, err = queryString(c.request, "job_id", 64); err != nil {
		return err
	}
	views, hasMore, err := s.backups.ListArtifacts(c.request.Context(), c.caller, filter)
	if err != nil {
		return s.backupProblem(err)
	}
	items := make([]backupArtifactDTO, 0, len(views))
	for _, view := range views {
		items = append(items, toBackupArtifactDTO(view))
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{
		"backups": items, "has_more": hasMore, "limit": limit, "offset": offset})
	return nil
}

// backupEnum 读取枚举查询参数并转换为领域类型；空字符串表示不筛选。
func backupEnum[T ~string](c *callContext, key string, maxBytes int) (T, error) {
	raw, err := queryString(c.request, key, maxBytes)
	if err != nil {
		var zero T
		return zero, err
	}
	return T(raw), nil
}

// handleBackupArtifactGet 处理 GET /backups/{backup_id}。
func (s *Server) handleBackupArtifactGet(c *callContext) error {
	view, err := s.backups.GetArtifact(c.request.Context(), c.caller, c.pathParam("backup_id"))
	if err != nil {
		return s.backupProblem(err)
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{"backup": toBackupArtifactDTO(view)})
	return nil
}

// handleBackupCapabilities 处理 GET /backups/capabilities。
func (s *Server) handleBackupCapabilities(c *callContext) error {
	capabilities, err := s.backups.Capabilities(c.request.Context(), c.caller)
	if err != nil {
		return s.backupProblem(err)
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{
		"capabilities": backupCapabilitiesDTO{
			Read: capabilities.Read, Create: capabilities.Create,
			Cancel: capabilities.Cancel, Download: capabilities.Download,
			Retention: capabilities.Retention, Cleanup: capabilities.Cleanup,
			DownloadTTL: int(capabilities.DownloadTTL.Seconds())}})
	return nil
}

// handleBackupJobList 处理 GET /backups/jobs。
func (s *Server) handleBackupJobList(c *callContext) error {
	limit, offset, err := pageParams(c.request)
	if err != nil {
		return err
	}
	filter := backupadmin.JobFilter{Limit: limit, Offset: offset}
	if filter.Kind, err = queryString(c.request, "kind", 64); err != nil {
		return err
	}
	if filter.ScheduleID, err = queryString(c.request, "schedule_id", 64); err != nil {
		return err
	}
	views, hasMore, err := s.backups.ListJobs(c.request.Context(), c.caller, filter)
	if err != nil {
		return s.backupProblem(err)
	}
	items := make([]backupJobDTO, 0, len(views))
	for _, view := range views {
		items = append(items, toBackupJobDTO(view))
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{
		"jobs": items, "has_more": hasMore, "limit": limit, "offset": offset})
	return nil
}

// handleBackupJobGet 处理 GET /backups/jobs/{job_id}。
func (s *Server) handleBackupJobGet(c *callContext) error {
	view, err := s.backups.GetJob(c.request.Context(), c.caller, c.pathParam("job_id"))
	if err != nil {
		return s.backupProblem(err)
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{"job": toBackupJobDTO(view)})
	return nil
}

// handleBackupScheduleList 处理 GET /backups/schedules（只读；计划写入本轮未开放）。
func (s *Server) handleBackupScheduleList(c *callContext) error {
	views, err := s.backups.ListSchedules(c.request.Context(), c.caller)
	if err != nil {
		return s.backupProblem(err)
	}
	items := make([]backupScheduleDTO, 0, len(views))
	for _, view := range views {
		items = append(items, toBackupScheduleDTO(view))
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{"schedules": items})
	return nil
}

// simpleConfirmInput 是仅需确认的非破坏性写操作请求体。
type simpleConfirmInput struct {
	Confirm   bool   `json:"confirm"`
	RequestID string `json:"request_id"`
}

// handleBackupCreate 处理 POST /backups：提交成功不等于备份完成；幂等冲突由
// 服务层按活动任务规则返回既有任务。
func (s *Server) handleBackupCreate(c *callContext) error {
	var input simpleConfirmInput
	if err := c.decodeJSON(&input); err != nil {
		return err
	}
	if err := requireConfirm(input.Confirm); err != nil {
		return err
	}
	ref, err := s.backups.EnqueueBackup(c.request.Context(), c.caller,
		firstNonEmpty(input.RequestID, c.requestID))
	if err != nil {
		return s.backupProblem(err)
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{"job": map[string]any{
		"job_id": ref.JobID, "existing": ref.Existing, "state": ref.State}})
	return nil
}

// handleBackupJobCancel 处理 POST /backups/jobs/{job_id}/cancel。
func (s *Server) handleBackupJobCancel(c *callContext) error {
	var input cancelInput
	if err := c.decodeJSON(&input); err != nil {
		return err
	}
	reason, err := input.parse()
	if err != nil {
		return err
	}
	view, err := s.backups.CancelJob(c.request.Context(), c.caller,
		c.pathParam("job_id"), reason, c.requestID)
	if err != nil {
		return s.backupProblem(err)
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{"cancel": map[string]any{
		"job_id": view.JobID, "accepted": view.Accepted,
		"already_requested": view.AlreadyRequested, "state": view.State,
		"note": view.Note}})
	return nil
}

// handleBackupDownloadTicket 处理 POST /backups/{backup_id}/download-tickets。
func (s *Server) handleBackupDownloadTicket(c *callContext) error {
	var input simpleConfirmInput
	if err := c.decodeJSON(&input); err != nil {
		return err
	}
	if err := requireConfirm(input.Confirm); err != nil {
		return err
	}
	ticket, err := s.backups.IssueDownloadTicket(c.request.Context(), c.caller,
		c.pathParam("backup_id"), firstNonEmpty(input.RequestID, c.requestID))
	if err != nil {
		return s.backupProblem(err)
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{"ticket": map[string]any{
		"backup_id": ticket.BackupID, "token": ticket.Token,
		"expires_at": ticket.ExpiresAt}})
	return nil
}

// handleBackupDownloadRedeem 处理 POST /backups/download-tickets/redeem：令牌
// 单次消费，兑换时再次授权并复核产物状态。
func (s *Server) handleBackupDownloadRedeem(c *callContext) error {
	var input downloadRedeemInput
	if err := c.decodeJSON(&input); err != nil {
		return err
	}
	token := input.Token
	if len(token) == 0 || len(token) > 512 {
		return fmt.Errorf("%w: 下载令牌无效", ErrInvalidRequest)
	}
	file, err := s.backups.RedeemDownloadTicket(c.request.Context(), c.caller,
		token, c.requestID)
	if err != nil {
		return s.backupProblem(err)
	}
	header := c.writer.Header()
	header.Set("Content-Type", file.ContentType)
	header.Set("Cache-Control", "no-store")
	header.Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="backup-%s.bin"`, safeFileID(file.BackupID)))
	header.Set("Content-Length", strconv.FormatInt(int64(len(file.Data)), 10))
	c.writer.WriteHeader(http.StatusOK)
	_, _ = c.writer.Write(file.Data)
	return nil
}

// handleBackupRetentionGet 处理 GET /backups/retention。
func (s *Server) handleBackupRetentionGet(c *callContext) error {
	view, err := s.backups.Retention(c.request.Context(), c.caller)
	if err != nil {
		return s.backupProblem(err)
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{
		"retention": toBackupRetentionDTO(view)})
	return nil
}

// handleBackupRetentionSet 处理 PUT /backups/retention：版本并发 + 确认 + 原因 +
// 敏感策略（服务层）。
func (s *Server) handleBackupRetentionSet(c *callContext) error {
	var input struct {
		Confirm         bool   `json:"confirm"`
		MaxCount        int    `json:"max_count"`
		MaxAgeDays      int    `json:"max_age_days"`
		MaxTotalBytes   int64  `json:"max_total_bytes"`
		ExpectedVersion int64  `json:"expected_version"`
		Reason          string `json:"reason"`
	}
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
	view, err := s.backups.SaveRetention(c.request.Context(), backupadmin.RetentionChange{
		Caller: c.caller, MaxCount: input.MaxCount, MaxAgeDays: input.MaxAgeDays,
		MaxTotalBytes: input.MaxTotalBytes, ExpectedVersion: input.ExpectedVersion,
		Reason: reason, RequestID: c.requestID})
	if err != nil {
		return s.backupProblem(err)
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{
		"retention": toBackupRetentionDTO(view)})
	return nil
}

// handleBackupCleanupPreview 处理 GET /backups/cleanup-preview。
func (s *Server) handleBackupCleanupPreview(c *callContext) error {
	preview, err := s.backups.CleanupPreview(c.request.Context(), c.caller)
	if err != nil {
		return s.backupProblem(err)
	}
	dto := backupCleanupPreviewDTO{
		Policy:        toBackupRetentionPolicyDTO(preview.Policy),
		TotalRetained: preview.TotalRetained, TotalBytes: preview.TotalBytes,
		TargetBytes: preview.TargetBytes, PreviewedAt: preview.PreviewedAt,
		Note: preview.Note}
	for _, target := range preview.Targets {
		dto.Targets = append(dto.Targets, backupCandidateDTO{
			BackupID: target.BackupID, SizeBytes: target.SizeBytes,
			CreatedAt: target.CreatedAt, Reason: target.Reason})
	}
	for _, protected := range preview.Protected {
		dto.Protected = append(dto.Protected, backupCandidateDTO{
			BackupID: protected.BackupID, SizeBytes: protected.SizeBytes,
			CreatedAt: protected.CreatedAt, Reason: protected.Reason})
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{"cleanup_preview": dto})
	return nil
}

// handleBackupCleanupEnqueue 处理 POST /backups/cleanup：清理在执行时重新计算
// 候选与保护状态，不按旧预览强删；原始安全审计不受影响。
func (s *Server) handleBackupCleanupEnqueue(c *callContext) error {
	var input simpleConfirmInput
	if err := c.decodeJSON(&input); err != nil {
		return err
	}
	if err := requireConfirm(input.Confirm); err != nil {
		return err
	}
	ref, err := s.backups.EnqueueCleanup(c.request.Context(), c.caller,
		firstNonEmpty(input.RequestID, c.requestID))
	if err != nil {
		return s.backupProblem(err)
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{"job": map[string]any{
		"job_id": ref.JobID, "existing": ref.Existing, "state": ref.State}})
	return nil
}

// toBackupRetentionDTO 转换保留策略页面视图。
func toBackupRetentionDTO(view backupadmin.RetentionView) backupRetentionDTO {
	dto := backupRetentionDTO{Policy: toBackupRetentionPolicyDTO(view.Policy),
		IsDefault: view.IsDefault}
	if view.LastCleanup != nil {
		dto.LastCleanup = &backupCleanupSummaryDTO{
			JobID: view.LastCleanup.JobID, State: view.LastCleanup.State,
			RequestedCount: view.LastCleanup.RequestedCount,
			CleanedCount:   view.LastCleanup.CleanedCount,
			FailedCount:    view.LastCleanup.FailedCount,
			ProtectedCount: view.LastCleanup.ProtectedCount,
			FreedBytes:     view.LastCleanup.FreedBytes,
			FinishedAt:     view.LastCleanup.FinishedAt}
	}
	return dto
}

// toBackupRetentionPolicyDTO 转换保留策略。
func toBackupRetentionPolicyDTO(policy backupadmin.RetentionPolicy) backupRetentionPolicyDTO {
	return backupRetentionPolicyDTO{Version: policy.Version, MaxCount: policy.MaxCount,
		MaxAgeDays: policy.MaxAgeDays, MaxTotalBytes: policy.MaxTotalBytes,
		UpdatedAt: policy.UpdatedAt, UpdatedBy: toActorDTO(policy.UpdatedBy),
		Reason: policy.Reason, RequestID: policy.RequestID}
}
