package backupadmin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/backup"
	"github.com/kagurazakayashi/EvernightLogin/internal/fsutil"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// TaskHandlers 返回需要宿主注册到 internal/task Executor 的任务处理器。宿主负责
// 执行器/调度器生命周期；本包不自行启动协程。
func (s *Service) TaskHandlers() map[string]task.Handler {
	return map[string]task.Handler{
		KindBackupCreate:  s.handleBackupTask,
		KindBackupCleanup: s.handleCleanupTask,
	}
}

// decodeJobPayload 解析受控任务载荷；非法载荷按不可重试配置错误处理。
func decodeJobPayload(job task.Job) (jobPayload, error) {
	payload := jobPayload{}
	if len(job.Payload) > 0 {
		if err := json.Unmarshal(job.Payload, &payload); err != nil {
			return jobPayload{}, fmt.Errorf("%w: 任务载荷无效", ErrInvalidRequest)
		}
	}
	if !Origin(payload.Origin).Valid() {
		payload.Origin = string(OriginManual)
	}
	return payload, nil
}

// handleBackupTask 是 backup.create 任务的处理器：每次尝试都重新复核执行身份权限，
// 调用真实备份服务，成功时登记受控产物元数据并触发保留检查。
func (s *Service) handleBackupTask(ctx context.Context, job task.Job) error {
	payload, err := decodeJobPayload(job)
	if err != nil {
		return task.NonRetryable(err)
	}
	// 计划触发的任务由调度器直接入队，载荷里没有计划编号；从管理索引补齐，用于
	// 关联产物、通知配置与页面追踪链。索引缺失时保持空值，不伪造关联。
	if entry, found, lookupErr := s.opts.Store.GetJob(ctx, job.ID); lookupErr == nil && found {
		if payload.ScheduleID == "" {
			payload.ScheduleID = entry.ScheduleID
		}
		if entry.Origin.Valid() && entry.Origin != OriginManual {
			payload.Origin = string(entry.Origin)
		}
	}
	caller, err := callerFromActor(job.Initiator)
	if err != nil {
		return task.NonRetryable(fmt.Errorf("%w: 任务执行身份无效", ErrAccessDenied))
	}
	if err := s.authorize(ctx, caller, PermissionCreate); err != nil {
		s.updateStage(ctx, job.ID, "permission", nil)
		s.notifyFailure(ctx, job, payload, NotificationPermissionDenied, string(CodeOf(err)))
		return task.NonRetryable(fmt.Errorf("%w: 执行身份未通过权限复核", ErrAccessDenied))
	}
	s.beginProgress(job.ID)
	defer s.endProgress()
	s.updateStage(ctx, job.ID, "prepare", nil)
	result, err := s.opts.Backup.Create(ctx, backup.CreateRequest{
		Caller: caller, RequestID: firstNonEmpty(job.RequestID, caller.RequestID()),
	})
	if err != nil {
		code := backup.CodeOf(err)
		s.updateStage(ctx, job.ID, "failed", nil)
		s.persistJobError(ctx, job, string(code))
		if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, backup.ErrCancelled) {
			// 已接受取消导致的真实终止：不是失败，不发失败通知。
			return task.NonRetryable(fmt.Errorf("%w: 备份在取消请求后终止", ErrAccessDenied))
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, backup.ErrTimeout) {
			s.notifyFailure(ctx, job, payload, NotificationBackupTimeout, string(code))
			return task.NonRetryable(fmt.Errorf("%w: 任务超过墙钟上限", backup.ErrTimeout))
		}
		// 只有 SQLite BUSY/存储暂不可用等瞬时故障允许任务级重试；权限、审计、
		// 取消、超时、参数、容量与校验错误一律不重试（备份服务内部另有有界重试）。
		wrapped := fmt.Errorf("备份任务失败: %w", err)
		if errors.Is(err, storage.ErrBusy) || errors.Is(err, storage.ErrUnavailable) {
			s.notifyFailure(ctx, job, payload, NotificationBackupFailed, string(code))
			return wrapped
		}
		s.notifyFailure(ctx, job, payload, NotificationBackupFailed, string(code))
		return task.NonRetryable(wrapped)
	}
	// 成功：登记受控元数据。登记失败如实返回失败（产物可能已发布，由对账把无登记
	// 的成品标为“可用性未知”，不会被当作可下载或可清理对象）。
	artifact := Artifact{
		BackupID: result.BackupID, JobID: job.ID, ScheduleID: payload.ScheduleID,
		Origin: Origin(payload.Origin), FileName: result.FileName,
		SizeBytes: result.SizeBytes, PayloadBytes: result.PayloadBytes,
		FileSHA256: result.SHA256, ManifestSHA256: result.ManifestSHA256,
		FormatVersion: backup.FormatVersion, SchemaVersion: result.Database.SchemaVersion,
		ContentDatabase: result.Content.Database,
		ContentAttach:   ContentStatus(result.Content.Attachments.Status),
		ContentConfig:   ContentStatus(result.Content.Config.Status),
		EntryCount:      len(result.Entries),
		// 发布前已用同一校验器完整认证校验；这里如实标记 verified 并记录校验时间。
		Verification: VerificationVerified,
		// 校验发生在发布前、Create 返回后编目时；用编目时刻而不是快照创建时刻。
		VerifiedAt:       s.now(),
		RetentionVersion: payload.RetentionVersion,
		Cleanup:          CleanupRetained,
		CreatedAt:        result.CreatedAt, PublishedAt: s.now(),
		RequestID: normalizeRequestID(job.RequestID),
	}
	if artifact.RetentionVersion == 0 {
		artifact.RetentionVersion = s.currentRetentionVersion(ctx)
	}
	if err := s.opts.Store.InsertArtifact(ctx, artifact); err != nil {
		s.updateStage(ctx, job.ID, "artifact_register_failed", nil)
		s.notifyFailure(ctx, job, payload, NotificationBackupFailed, string(CodeOf(err)))
		return task.NonRetryable(fmt.Errorf("备份产物登记失败: %w", err))
	}
	s.updateJobState(ctx, JobProgressState{
		JobID: job.ID, BackupID: artifact.BackupID, StageCode: "finish",
		NotificationStat: "not_configured", UpdatedAt: s.now(),
	})
	s.notifySuccess(ctx, job, payload, artifact)
	// 先确认新产物已登记为可用恢复点，再评估旧产物清理（失败的新备份不会进入这里，
	// 因此不会先删旧可用备份）。
	s.maybeAutoCleanup(ctx)
	return nil
}

// handleCleanupTask 是 backup.cleanup 任务的处理器：执行时重新计算保护状态与候选，
// 逐项重新检查后删除文件并记录真实分项结果。
func (s *Service) handleCleanupTask(ctx context.Context, job task.Job) error {
	caller, err := callerFromActor(job.Initiator)
	if err != nil {
		return task.NonRetryable(fmt.Errorf("%w: 清理任务执行身份无效", ErrAccessDenied))
	}
	if err := s.authorize(ctx, caller, PermissionCleanup); err != nil {
		s.updateStage(ctx, job.ID, "permission", nil)
		return task.NonRetryable(fmt.Errorf("%w: 清理任务执行身份未通过权限复核", ErrAccessDenied))
	}
	s.updateStage(ctx, job.ID, "cleanup", nil)
	payload, err := decodeJobPayload(job)
	if err != nil {
		return task.NonRetryable(err)
	}
	// 先对账孤儿成品：把无登记的完整文件标记为可用性未知，避免清理阶段误判集合。
	if _, err := s.Reconcile(ctx); err != nil {
		s.logger.Warn("清理前对账失败", "job_id", job.ID, "reason", safeToken(fmt.Sprint(CodeOf(err))))
	}
	plan, err := s.buildCleanupPlan(ctx, s.now())
	if err != nil {
		s.updateStage(ctx, job.ID, "failed", nil)
		return task.NonRetryable(fmt.Errorf("%w: 无法计算清理候选", ErrStoreUnavailable))
	}
	// 再次认证批准的目标集合与策略版本必须与执行时一致；不一致（策略/产物变化、
	// 载荷被篡改）时拒绝执行，要求重新预览，不能扩大删除范围。
	if payload.Origin == string(OriginManual) || payload.TargetDigest != "" {
		currentDigest := cleanupTargetDigest(plan.targets)
		if payload.TargetDigest == "" || currentDigest != payload.TargetDigest ||
			payload.PolicyVersion != plan.policy.Version ||
			payload.TargetCount != len(plan.targets) {
			s.recordChangeFailure(ctx, job.Initiator, ActionCleanupRequest,
				"backup_cleanup", job.ID, job.RequestID, "cleanup_target_changed")
			s.updateStage(ctx, job.ID, "failed", nil)
			return task.NonRetryable(fmt.Errorf(
				"%w: 清理目标或策略已变化，请重新预览后再执行", ErrConflict))
		}
	}
	intent := audit.Event{
		Actor: job.Initiator, Action: ActionCleanupRequest,
		Target:  audit.Target{Type: "backup_cleanup", ID: job.ID},
		Outcome: audit.OutcomeSuccess, RequestID: normalizeRequestID(job.RequestID),
		Changes: []audit.FieldChange{
			{Field: "requested", After: strconv.Itoa(len(plan.targets))},
			{Field: "policy_version", After: fmt.Sprint(plan.policy.Version)},
		},
	}
	if err := s.record(ctx, intent); err != nil {
		return task.NonRetryable(err)
	}
	summary := cleanupResultSummary{}
	lastUsable := s.lastUsableID(ctx)
	for _, target := range plan.targets {
		summary.Requested++
		// 执行时重新读取并复核：已成为最后可用、状态变化或文件缺失都跳过，不按旧
		// 预览强删。
		current, found, err := s.opts.Store.GetArtifact(ctx, target.BackupID)
		if err != nil || !found || current.Cleanup != CleanupRetained {
			summary.Skipped++
			continue
		}
		if current.BackupID == s.lastUsableID(ctx) || current.BackupID == lastUsable {
			summary.Protected++
			continue
		}
		if current.Verification != VerificationVerified || !s.artifactFileExists(current) {
			summary.Protected++
			continue
		}
		path, err := s.backupPath(current)
		if err != nil {
			summary.Failed++
			continue
		}
		// 保护条件（最后可用备份、已验证、文件仍存在）已在上方逐项复核并保持原
		// 逻辑；这里只对删除调用做 Windows 瞬时错误的有界重试：受控输出目录内的
		// 产物可能正被杀软扫描/过滤驱动短暂持有，瞬时失败不应计为清理失败。路径
		// 不存在按成功处理（与原 os.IsNotExist 判断一致），预算耗尽仍计入 Failed。
		if err := fsutil.RemoveRetry(path); err != nil {
			summary.Failed++
			continue
		}
		if err := s.opts.Store.MarkArtifactCleaned(ctx, current.BackupID, job.Initiator,
			s.now()); err != nil {
			summary.Failed++
			continue
		}
		summary.Cleaned++
		summary.Bytes += current.SizeBytes
	}
	summary.Finished = s.now().UnixMilli()
	encoded, encodeErr := json.Marshal(summary)
	if encodeErr != nil {
		return task.NonRetryable(fmt.Errorf("%w: 清理结果编码失败", ErrInvalidRequest))
	}
	s.updateJobState(ctx, JobProgressState{
		JobID: job.ID, StageCode: "done", ResultSummary: string(encoded),
		UpdatedAt: s.now(),
	})
	s.recordBestEffort(ctx, audit.Event{
		Actor: job.Initiator, Action: ActionCleanupFinish,
		Target:  audit.Target{Type: "backup_cleanup", ID: job.ID},
		Outcome: audit.OutcomeSuccess, RequestID: normalizeRequestID(job.RequestID),
		Changes: []audit.FieldChange{
			{Field: "cleaned", After: strconv.Itoa(summary.Cleaned)},
			{Field: "failed", After: strconv.Itoa(summary.Failed)},
			{Field: "protected", After: strconv.Itoa(summary.Protected)},
			{Field: "freed_bytes", After: strconv.FormatInt(summary.Bytes, 10)},
		},
	})
	if summary.Failed > 0 {
		// 清理失败通知按任务生效配置发送（复用既有通知契约；失败只影响通知状态）。
		settings := s.settingsFor(ctx, job, payload, false)
		if settings.enabled {
			s.sendNotification(ctx, job, payload, NotificationCleanupFailed,
				"CLEANUP_PARTIAL_FAILED", settings.channel, false)
		}
		// 部分失败不被“任务完成”掩盖：终态为失败，但分项结果仍可在任务详情查看。
		return task.NonRetryable(fmt.Errorf("备份清理有 %d 项失败", summary.Failed))
	}
	return nil
}

// recordProgress 接收 internal/backup 的真实进度并写入任务状态；只在阶段切换或
// 进度明显前进时落库，避免每页都写数据库。写失败只告警（任务事实不依赖进度）。
func (s *Service) recordProgress(progress backup.Progress) {
	s.progressMu.Lock()
	jobID := s.currentJob
	s.progressMu.Unlock()
	if jobID == "" {
		return
	}
	stage := progressStage(progress.Phase)
	if stage == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	state, found, err := s.opts.Store.JobState(ctx, jobID)
	if err != nil {
		return
	}
	if !found {
		state = JobProgressState{JobID: jobID}
	}
	unit := ""
	var done *int64
	var total *int64
	if progress.Total > 0 && progress.Done >= 0 {
		value := progress.Done
		totalValue := progress.Total
		done = &value
		total = &totalValue
		if progress.Phase == "snapshot" {
			unit = "pages"
		} else {
			unit = "bytes"
		}
	}
	// 阶段变化必定落库；同阶段只在进度前进约 1% 或阶段首次出现时更新。
	if state.StageCode == stage && state.ProgressDone != nil && done != nil &&
		state.ProgressTotal != nil && *state.ProgressTotal == *total {
		step := *total / 100
		if step < 1 {
			step = 1
		}
		if *done-*state.ProgressDone < step {
			return
		}
	}
	state.StageCode = stage
	state.ProgressDone = done
	state.ProgressTotal = total
	state.ProgressUnit = unit
	state.BackupID = progress.BackupID
	state.UpdatedAt = s.now()
	if err := s.opts.Store.SaveJobState(ctx, state); err != nil {
		s.logger.Warn("备份进度写入失败", "job_id", jobID, "phase", progress.Phase)
	}
}

// progressStage 把备份阶段映射为稳定 stage_code。
func progressStage(phase string) string {
	switch phase {
	case "snapshot":
		return "snapshot"
	case "attachments", "config":
		return "content"
	case "encrypt":
		return "write"
	case "verify":
		return "verify"
	case "publish":
		return "publish"
	default:
		return ""
	}
}

// updateStage 写入任务阶段（进度未知时清空分子/分母，不用旧值冒充）。
func (s *Service) updateStage(ctx context.Context, jobID, stage string, progress *backup.Progress) {
	state, found, err := s.opts.Store.JobState(ctx, jobID)
	if err != nil {
		s.logger.Warn("任务阶段读取失败", "job_id", jobID)
		return
	}
	if !found {
		state = JobProgressState{JobID: jobID}
	}
	state.StageCode = stage
	if progress != nil && progress.Total > 0 {
		done, total := progress.Done, progress.Total
		state.ProgressDone, state.ProgressTotal = &done, &total
		state.ProgressUnit = "bytes"
	} else {
		state.ProgressDone, state.ProgressTotal, state.ProgressUnit = nil, nil, ""
	}
	state.UpdatedAt = s.now()
	if err := s.opts.Store.SaveJobState(ctx, state); err != nil {
		s.logger.Warn("任务阶段写入失败", "job_id", jobID, "stage", stage)
	}
}

// updateJobState 合并写入任务状态字段。
func (s *Service) updateJobState(ctx context.Context, update JobProgressState) {
	state, found, err := s.opts.Store.JobState(ctx, update.JobID)
	if err != nil {
		s.logger.Warn("任务状态读取失败", "job_id", update.JobID)
		return
	}
	if !found {
		state = JobProgressState{JobID: update.JobID}
	}
	if update.BackupID != "" {
		state.BackupID = update.BackupID
	}
	if update.StageCode != "" {
		state.StageCode = update.StageCode
	}
	if update.NotificationStat != "" {
		state.NotificationStat = update.NotificationStat
	}
	if update.NotificationCode != "" {
		state.NotificationCode = update.NotificationCode
	}
	if update.ResultSummary != "" {
		state.ResultSummary = update.ResultSummary
	}
	state.UpdatedAt = s.now()
	if err := s.opts.Store.SaveJobState(ctx, state); err != nil {
		s.logger.Warn("任务状态写入失败", "job_id", update.JobID)
	}
}

// persistJobError 把错误码写入任务侧状态，便于页面在通知结果之外看到真实失败原因。
func (s *Service) persistJobError(ctx context.Context, job task.Job, errorCode string) {
	s.updateJobState(ctx, JobProgressState{JobID: job.ID,
		NotificationCode: safeToken(errorCode), UpdatedAt: s.now()})
}

// beginProgress/endProgress 标记当前正在运行的备份任务编号（单实例 + 全局互斥）。
func (s *Service) beginProgress(jobID string) {
	s.progressMu.Lock()
	s.currentJob = jobID
	s.progressMu.Unlock()
}

func (s *Service) endProgress() {
	s.progressMu.Lock()
	s.currentJob = ""
	s.progressMu.Unlock()
}

// firstNonEmpty 返回第一个非空字符串。
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// saturatingText 把展示文本限制到安全长度并去除控制字符。
func saturatingText(value string, max int) string {
	var builder []rune
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			continue
		}
		builder = append(builder, r)
		if len(builder) >= max {
			break
		}
	}
	return string(builder)
}
