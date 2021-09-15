// 本文件实现恢复执行主流程：维护状态 + 库外排他锁 → 恢复前回退备份 → 受控暂存
// → 再次验证 → 原子切换 → 恢复后凭证失效/处置 → 审计合并 → 退出维护。失败/中断
// 规则见文件内各阶段注释：切换前失败回退为零副作用并保持维护；切换后失败回退到
// 恢复前数据库并保持维护；恢复失败默认保持维护，不自动对外放行。
package restore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/backup"
	"github.com/kagurazakayashi/EvernightLogin/internal/maintenance"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

// errTimeoutCause 是恢复墙钟超时的 context cause；用于把超时与调用方取消分开。
var errTimeoutCause = errors.New("restore wall clock timeout")

// databaseSwitch 记录数据库切换前后的文件位置，供成功后清理与失败回退使用。
type databaseSwitch struct {
	livePath       string
	preRestorePath string
	failedPath     string
	switched       bool
}

// attachmentSwap 记录一个附件文件在恢复前的备份位置（空表示原本不存在）。
type attachmentSwap struct {
	target string
	backup string
}

// attachmentRollback 记录附件替换集合，供失败回退。
type attachmentRollback struct {
	backupDir string
	swaps     []attachmentSwap
}

// execution 是单次恢复执行的可变状态；失败路径统一由 fail 处理回退与审计。
type execution struct {
	service        *Service
	ctx            context.Context
	request        Request
	actor          audit.Actor
	restoreID      string
	token          maintenance.Token
	rehearsal      Rehearsal
	rollbackBackup backup.Result

	database    *databaseSwitch
	attachments *attachmentRollback
	switched    bool
	step        string
	logged      map[string]bool
}

// Execute 执行一次完整恢复并返回真实结果。调用前宿主必须停止服务或允许本流程
// 排他访问数据库（Windows 上已打开的数据库文件无法被改名，本函数会明确报错）；
// 本函数会自动进入并（成功时）退出维护状态。失败时默认保持维护状态。
func (s *Service) Execute(ctx context.Context, request Request) (Result, error) {
	ctx = normalizeContext(ctx)
	actor, err := s.authorize(ctx, request.Caller)
	if err != nil {
		return Result{}, err
	}
	request, err = s.normalizeRequest(request)
	if err != nil {
		return Result{}, err
	}
	restoreID, err := s.newRestoreID()
	if err != nil {
		return Result{}, err
	}
	result := Result{RestoreID: restoreID, StartedAt: s.nowUTC()}
	workCtx, cancel := context.WithTimeoutCause(ctx, s.opts.Timeout, errTimeoutCause)
	defer cancel()
	exec := &execution{service: s, ctx: workCtx, request: request, actor: actor,
		restoreID: restoreID, logged: make(map[string]bool)}

	// 阶段 0：先取得库外恢复排他锁，避免与其它恢复/维护会话并发；取锁不是数据库
	// 副作用，失败时直接拒绝且不进入维护状态。
	releaseLock, err := s.controller.LockRestore(workCtx)
	if err != nil {
		return result, fmt.Errorf("%w: %w", ErrRestoreLocked, err)
	}
	defer releaseLock()

	// 阶段 1：恢复前预演。预演失败不修改当前数据库、不进入维护状态。
	exec.step = "preflight"
	rehearsal := s.rehearse(workCtx, request)
	exec.rehearsal = rehearsal
	if err := exec.log(ActionPreflight, outcomeFromBool(rehearsal.Restorable),
		rehearsal.Backup.BackupID, "", "preflight", rehearsalChanges(rehearsal)); err != nil {
		return result, err
	}
	if !rehearsal.Restorable {
		return result, fmt.Errorf("%w: %s", ErrPreflightFailed,
			strings.Join(rehearsal.BlockingReasons, "；"))
	}
	result.Backup = rehearsal.Backup

	// 阶段 2：进入维护状态（阻止新写入、有界等待在途写入收束）。
	exec.step = "maintenance"
	operator := maintenance.Operator{Type: string(actor.Type), ID: actor.ID,
		Machine: s.machineName()}
	if err := s.controller.EnterMaintenance(workCtx, maintenance.EnterRequest{
		Operator: operator, Reason: request.Reason, RequestID: request.RequestID,
	}); err != nil {
		if journalErr := exec.log(ActionMaintenanceEnter, audit.OutcomeFailure, "", "",
			"maintenance", nil); journalErr != nil {
			return result, journalErr
		}
		return result, s.wrapMaintenanceError(err)
	}
	if err := exec.log(ActionMaintenanceEnter, audit.OutcomeSuccess, "", "",
		"maintenance", nil); err != nil {
		return result, err
	}

	// 阶段 3：登记恢复尝试（库外 pending + 下一恢复代际）。
	exec.step = "begin"
	token, err := s.controller.BeginRestore(workCtx, maintenance.BeginRequest{
		RestoreID: restoreID, BackupSHA256: rehearsal.Backup.FileSHA256, Operator: operator,
	})
	if err != nil {
		return exec.fail(fmt.Errorf("登记恢复尝试失败: %w", err))
	}
	exec.token = token
	result.Generation = token.NextGeneration
	if err := exec.log(ActionStarted, audit.OutcomeSuccess, restoreID, "", "begin",
		[]audit.FieldChange{
			{Field: "generation", After: fmt.Sprintf("%d", token.NextGeneration)},
			{Field: "backup_sha256", After: rehearsal.Backup.FileSHA256},
			{Field: "schema_version", After: rehearsal.Backup.SchemaVersion},
		}); err != nil {
		return exec.fail(err)
	}

	// 阶段 4：恢复前回退备份（新文件；绝不覆盖用户原始备份）。
	exec.step = "rollback_backup"
	if err := s.fault("before_rollback_backup"); err != nil {
		return exec.fail(err)
	}
	rollback, err := s.createRollbackBackup(workCtx, request, restoreID)
	if err != nil {
		return exec.fail(fmt.Errorf("创建恢复前回退备份失败: %w", err))
	}
	exec.rollbackBackup = rollback
	result.RollbackBackupPath = rollback.Path
	result.RollbackBackupSHA256 = rollback.SHA256
	if err := exec.log(ActionRollbackBackup, audit.OutcomeSuccess, rollback.BackupID,
		"", "rollback_backup", []audit.FieldChange{
			{Field: "file_sha256", After: rollback.SHA256},
			{Field: "size_bytes", After: fmt.Sprintf("%d", rollback.SizeBytes)},
		}); err != nil {
		return exec.fail(err)
	}

	// 阶段 5：受控暂存 + 再次认证校验 + 暂存数据库迁移/完整性检查。
	exec.step = "staging"
	if err := s.fault("before_stage"); err != nil {
		return exec.fail(err)
	}
	stagingDir, err := s.newStagingDirectory()
	if err != nil {
		return exec.fail(err)
	}
	defer func() { _ = os.RemoveAll(stagingDir) }()
	keyring, err := s.loadKeyring(workCtx)
	if err != nil {
		return exec.fail(err)
	}
	extracted, err := backup.Extract(workCtx, backup.ExtractOptions{
		Path: request.BackupPath, Keyring: keyring, Destination: stagingDir,
	})
	if err != nil {
		return exec.fail(fmt.Errorf("暂存解包失败: %w", err))
	}
	if extracted.DatabasePath == "" {
		return exec.fail(fmt.Errorf("%w: 备份缺少数据库条目", ErrStageFailed))
	}
	staged, err := s.prepareStagedDatabase(workCtx, extracted.DatabasePath)
	if err != nil {
		return exec.fail(fmt.Errorf("暂存数据库再次验证失败: %w", err))
	}
	if staged.SchemaVersionNumber < rehearsal.Backup.SchemaVersionNumber {
		return exec.fail(fmt.Errorf("%w: 暂存数据库版本低于备份声明", ErrStageFailed))
	}
	if err := s.fault("after_stage_before_switch"); err != nil {
		return exec.fail(err)
	}
	if err := exec.log(ActionStaged, audit.OutcomeSuccess, restoreID, "", "staging",
		[]audit.FieldChange{
			{Field: "staged_schema", After: staged.SchemaVersion},
			{Field: "staged_entries", After: fmt.Sprintf("%d", len(extracted.Entries))},
			{Field: "attachments", After: fmt.Sprintf("%d", len(extracted.Attachments))},
		}); err != nil {
		return exec.fail(err)
	}

	// 阶段 6：同目录原子改名切换数据库（原库重命名为恢复前副本，不复制运行中文件）。
	exec.step = "switch"
	switched, err := s.switchDatabase(workCtx, extracted.DatabasePath, restoreID,
		extracted.Report.Database.SHA256)
	if err != nil {
		return exec.fail(fmt.Errorf("切换数据库失败: %w", err))
	}
	exec.database = switched
	exec.switched = true
	result.SwitchedAt = s.nowUTC()
	if err := exec.log(ActionSwitched, audit.OutcomeSuccess, restoreID, "", "switch",
		[]audit.FieldChange{
			{Field: "database_sha256", After: extracted.Report.Database.SHA256},
			{Field: "generation", After: fmt.Sprintf("%d", token.NextGeneration)},
		}); err != nil {
		return exec.fail(err)
	}
	if err := s.fault("after_switch_before_attachments"); err != nil {
		return exec.fail(err)
	}

	// 阶段 7：附件替换（逐文件原子改名；失败回退）。
	exec.step = "attachments"
	attachments, restoredAttachments, err := s.applyAttachments(workCtx,
		extracted.Attachments, restoreID)
	if err != nil {
		return exec.fail(fmt.Errorf("恢复附件失败: %w", err))
	}
	exec.attachments = attachments
	result.AttachmentsRestored = restoredAttachments

	// 阶段 8：恢复后处理（同一事务内凭证失效 + 默认暂停 + 恢复记录/代际）。
	exec.step = "postprocess"
	outcome, err := s.postProcessRestoredDatabase(workCtx, token, actor, request,
		rehearsal.Backup, result.StartedAt, rollback.FileName)
	if err != nil {
		return exec.fail(err)
	}
	result.Revoked = outcome.Revoked
	result.Paused = outcome.Paused
	if err := exec.log(ActionCredentialsReset, audit.OutcomeSuccess, restoreID, "",
		"postprocess", []audit.FieldChange{
			{Field: "total_deleted", After: fmt.Sprintf("%d", outcome.Revoked.TotalDeleted)},
			{Field: "sessions", After: fmt.Sprintf("%d", outcome.Revoked.Sessions)},
			{Field: "refresh_families", After: fmt.Sprintf("%d", outcome.Revoked.RefreshFamilies)},
			{Field: "authorization_codes", After: fmt.Sprintf("%d", outcome.Revoked.AuthorizationCodes)},
			{Field: "recovery_codes", After: fmt.Sprintf("%d", outcome.Revoked.RecoveryCodes)},
			{Field: "verification_tickets", After: fmt.Sprintf("%d", outcome.Revoked.VerificationTickets)},
			{Field: "qr_requests", After: fmt.Sprintf("%d", outcome.Revoked.QRLoginRequests)},
			{Field: "signing_keys", After: fmt.Sprintf("%d", outcome.Revoked.SigningKeys)},
		}); err != nil {
		return exec.fail(err)
	}
	if err := exec.log(ActionDispositionPause, audit.OutcomeSuccess, restoreID, "",
		"postprocess", []audit.FieldChange{
			{Field: "schedules", After: fmt.Sprintf("%d", outcome.Paused.Schedules)},
			{Field: "webhooks", After: fmt.Sprintf("%d", outcome.Paused.Webhooks)},
			{Field: "jobs", After: fmt.Sprintf("%d", outcome.Paused.Jobs)},
			{Field: "mails", After: fmt.Sprintf("%d", outcome.Paused.MailDeliveries)},
			{Field: "notifications", After: fmt.Sprintf("%d", outcome.Paused.Notifications)},
		}); err != nil {
		return exec.fail(err)
	}
	exec.step = "complete_generation"
	if err := s.controller.CompleteRestore(workCtx, token); err != nil {
		return exec.fail(fmt.Errorf("推进库外恢复代际失败: %w", err))
	}

	// 配置快照不自动应用：复制到库外待审查目录。
	if extracted.ConfigPath != "" {
		pendingPath, copyErr := s.stagePendingConfig(workCtx, extracted.ConfigPath, restoreID)
		if copyErr != nil {
			return exec.fail(fmt.Errorf("暂存待审查配置失败: %w", copyErr))
		}
		result.PendingConfigPath = pendingPath
	}
	exec.step = "completed"
	if err := exec.log(ActionCompleted, audit.OutcomeSuccess, restoreID, "", "completed",
		[]audit.FieldChange{
			{Field: "generation", After: fmt.Sprintf("%d", token.NextGeneration)},
		}); err != nil {
		return exec.fail(err)
	}

	// 阶段 9：恢复审计可靠合并进恢复后数据库；失败保持维护并保留库外日志。
	exec.step = "audit_merge"
	if err := s.fault("before_audit_merge"); err != nil {
		return result, fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	}
	merged, err := s.mergeRestoredAudit(workCtx, actor, restoreID)
	if err != nil {
		return result, fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	}
	result.AuditMerged = merged

	// 阶段 10：成功后清理恢复前明文副本、退出维护状态（仅在完成后放行）。
	exec.step = "cleanup"
	if err := s.cleanupSuccessfulSwitch(exec.database); err != nil {
		s.logger.Warn("恢复成功但清理恢复前数据库副本失败（不影响已完成的恢复）",
			"error", err)
	}
	if err := s.finishAttachments(exec.attachments); err != nil {
		s.logger.Warn("恢复成功但清理附件备份失败", "error", err)
	}
	exec.step = "exit_maintenance"
	if err := exec.log(ActionMaintenanceExit, audit.OutcomeSuccess, "", "",
		"exit_maintenance", nil); err != nil {
		return result, err
	}
	if err := s.controller.ExitMaintenance(workCtx, maintenance.ExitRequest{
		Operator: maintenance.Operator{Type: string(actor.Type), ID: actor.ID,
			Machine: s.machineName()},
		Reason: "恢复完成：" + request.Reason,
	}); err != nil {
		return result, s.wrapMaintenanceError(err)
	}
	result.MaintenanceExited = true
	result.CompletedAt = s.nowUTC()
	result.Duration = result.CompletedAt.Sub(result.StartedAt)
	result.DurationMS = result.Duration.Milliseconds()
	return result, nil
}

// log 追加一条库外审计事件（同一动作只记录一次由无状态设计保证，失败即中止）。
func (e *execution) log(action string, outcome audit.Outcome, targetID, errorCode,
	reasonCode string, changes []audit.FieldChange) error {
	_, err := e.service.appendJournal(e.ctx, journalEvent{
		RestoreID: e.restoreID, Actor: e.actor, Action: action,
		TargetType: TargetTypeRestore, TargetID: targetID, Outcome: outcome,
		ErrorCode: errorCode, ReasonCode: reasonCode,
		RequestID: e.request.RequestID, Changes: changes,
	})
	return err
}

// fail 处理恢复开始后的失败：写失败审计、按已切换状态尝试回退数据库与附件，并
// 保持维护状态；返回带真实原因的错误。回退失败时错误同时包含回退失败原因。
func (e *execution) fail(cause error) (Result, error) {
	stage := e.step
	wrapped := fmt.Errorf("恢复在 %s 阶段失败: %w", stage, cause)
	// 失败审计与回退必须不受调用方取消影响（否则取消会丢失失败证据或留下半状态）。
	criticalCtx, cancel := context.WithTimeout(context.WithoutCancel(e.ctx), 30*time.Second)
	defer cancel()
	// 失败审计本身尽力写入（不掩盖原始失败）；写失败只记日志。
	if _, journalErr := e.service.appendJournal(criticalCtx, journalEvent{
		RestoreID: e.restoreID, Actor: e.actor, Action: ActionFailed,
		TargetType: TargetTypeRestore, TargetID: e.restoreID,
		Outcome: audit.OutcomeFailure, ErrorCode: string(CodeOf(wrapped)),
		ReasonCode: sanitizeReasonCode(stage), RequestID: e.request.RequestID,
		Changes: []audit.FieldChange{{Field: "stage", After: stage}},
	}); journalErr != nil {
		e.service.logger.Error("恢复失败审计未能写入库外日志", "error", journalErr)
	}
	if !e.switched {
		// 切换前失败：数据库与附件均未改变，零副作用；清除未完成尝试、保持维护。
		if err := e.service.controller.AbortRestore(criticalCtx, e.restoreID); err != nil {
			e.service.logger.Error("清除未完成恢复尝试失败", "error", err)
		}
		return Result{RestoreID: e.restoreID}, wrapped
	}
	// 切换后失败：先回退附件再回退数据库；回退成功后数据库回到恢复前状态。
	rollbackErr := e.rollback()
	if rollbackErr != nil {
		combined := errors.Join(wrapped, fmt.Errorf("%w: %w", ErrRollbackFailed, rollbackErr))
		if _, journalErr := e.service.appendJournal(criticalCtx, journalEvent{
			RestoreID: e.restoreID, Actor: e.actor, Action: ActionRolledBack,
			TargetType: TargetTypeRestore, TargetID: e.restoreID,
			Outcome: audit.OutcomeFailure, ErrorCode: string(CodeBackupFailed),
			ReasonCode: "rollback_failed", RequestID: e.request.RequestID,
			Changes: []audit.FieldChange{{Field: "stage", After: stage}},
		}); journalErr != nil {
			e.service.logger.Error("回退失败审计未能写入库外日志", "error", journalErr)
		}
		return Result{RestoreID: e.restoreID}, combined
	}
	// 回退成功：清除未完成尝试（数据库已是恢复前状态，代际未推进），保持维护。
	if err := e.service.controller.AbortRestore(criticalCtx, e.restoreID); err != nil {
		e.service.logger.Error("清除未完成恢复尝试失败", "error", err)
	}
	if _, journalErr := e.service.appendJournal(criticalCtx, journalEvent{
		RestoreID: e.restoreID, Actor: e.actor, Action: ActionRolledBack,
		TargetType: TargetTypeRestore, TargetID: e.restoreID,
		Outcome: audit.OutcomeSuccess, ReasonCode: "rolled_back",
		RequestID: e.request.RequestID,
		Changes:   []audit.FieldChange{{Field: "stage", After: stage}},
	}); journalErr != nil {
		e.service.logger.Error("回退审计未能写入库外日志", "error", journalErr)
	}
	return Result{RestoreID: e.restoreID}, wrapped
}

// rollback 把数据库与附件回退到恢复前状态。
func (e *execution) rollback() error {
	var problems []error
	if e.database != nil {
		if err := e.service.rollbackDatabase(e.database); err != nil {
			problems = append(problems, err)
		}
	}
	if e.attachments != nil {
		if err := e.service.rollbackAttachments(e.attachments); err != nil {
			problems = append(problems, err)
		}
	}
	if len(problems) > 0 {
		return errors.Join(problems...)
	}
	return nil
}

// sanitizeReasonCode 把阶段名限制为稳定原因码（≤64 字节，小写/数字/下划线/连字符）。
func sanitizeReasonCode(stage string) string {
	result := make([]byte, 0, len(stage))
	for index := 0; index < len(stage); index++ {
		character := stage[index]
		switch {
		case character >= 'a' && character <= 'z':
			result = append(result, character)
		case character >= '0' && character <= '9':
			result = append(result, character)
		case character == '_' || character == '-':
			result = append(result, character)
		default:
			result = append(result, '_')
		}
	}
	if len(result) > 64 {
		result = result[:64]
	}
	if len(result) == 0 {
		return "restore"
	}
	return string(result)
}

// wrapMaintenanceError 把维护状态错误映射为恢复域错误。
func (s *Service) wrapMaintenanceError(err error) error {
	switch {
	case errors.Is(err, maintenance.ErrDrainTimeout):
		return fmt.Errorf("%w: 在途写入未能在上限内收束（已保持维护状态）",
			ErrDrainTimeout)
	case errors.Is(err, maintenance.ErrRestoreLocked):
		return fmt.Errorf("%w: 恢复排他锁被占用", ErrRestoreLocked)
	case errors.Is(err, maintenance.ErrPendingRestore):
		return fmt.Errorf("%w: %w", ErrPendingRestore, err)
	case errors.Is(err, maintenance.ErrStateInvalid):
		return fmt.Errorf("%w: 库外恢复状态文件无效", ErrStoreUnavailable)
	default:
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
}

// machineName 返回本机标识（审计元数据，不含秘密）。
func (s *Service) machineName() string {
	operator := maintenance.LocalOperator()
	return operator.Machine
}

// loadKeyring 加载主密钥环；失败按备份解密不可用处理。
func (s *Service) loadKeyring(ctx context.Context) (*secrets.Keyring, error) {
	ring, err := secrets.LoadKeyring(ctx, s.opts.Keyring)
	if err != nil {
		return nil, fmt.Errorf("%w: 主密钥环不可用", ErrBackupUnusable)
	}
	return ring, nil
}

// outcomeFromBool 把布尔成功标记映射为审计结果类别。
func outcomeFromBool(success bool) audit.Outcome {
	if success {
		return audit.OutcomeSuccess
	}
	return audit.OutcomeFailure
}

// createRollbackBackup 通过注入的真实回退备份实现创建恢复前加密备份。它产生新文件
// （受控输出目录内唯一名称），绝不覆盖用户原始备份；失败按恢复失败处理（保持维护）。
func (s *Service) createRollbackBackup(ctx context.Context, request Request,
	restoreID string) (backup.Result, error) {
	requestID := "restore-rollback:" + restoreID
	if len(requestID) > 64 {
		requestID = requestID[:64]
	}
	result, err := s.opts.RollbackBackup(ctx, request.Caller, requestID)
	if err != nil {
		return backup.Result{}, fmt.Errorf("%w: %w", ErrBackupUnusable, err)
	}
	if result.Path == "" || result.SHA256 == "" || result.BackupID == "" {
		return backup.Result{}, fmt.Errorf("%w: 回退备份结果不完整", ErrBackupUnusable)
	}
	absolute, pathErr := absoluteFile(result.Path)
	if pathErr != nil {
		return backup.Result{}, fmt.Errorf("%w: 回退备份路径无效", ErrBackupUnusable)
	}
	result.Path = absolute
	return result, nil
}

// newStagingDirectory 在库外受控状态目录内创建 0700 暂存目录。
func (s *Service) newStagingDirectory() (string, error) {
	directory, err := os.MkdirTemp(s.stateDir, stagingDirPrefix+s.stagingSuffix()+"-")
	if err != nil {
		return "", fmt.Errorf("%w: 无法创建恢复暂存目录", ErrStoreUnavailable)
	}
	if err := os.Chmod(directory, 0o700); err != nil && !isWindowsPlatform() {
		_ = os.RemoveAll(directory)
		return "", fmt.Errorf("%w: 无法限制暂存目录权限", ErrStoreUnavailable)
	}
	return directory, nil
}

// switchDatabase 执行数据库原子切换：
//  1. 对当前数据库执行 WAL checkpoint 并关闭连接（避免 WAL 与主文件不一致）；
//  2. 把暂存数据库复制到数据库目录内的独占临时文件（fsync 并复核 SHA-256）；
//  3. 把当前数据库改名为恢复前副本（同目录原子改名）；
//  4. 把临时文件改名为活动数据库路径。
//
// 第 3 步成功后第 4 步失败时尝试把恢复前副本改回活动路径；整体失败返回错误，
// 调用方保持维护状态。
func (s *Service) switchDatabase(ctx context.Context, stagedPath, restoreID string,
	expectedSHA256 string) (*databaseSwitch, error) {
	if err := s.checkpointLiveDatabase(ctx); err != nil {
		return nil, err
	}
	databaseDir := filepath.Dir(s.databasePath)
	temporary, err := os.CreateTemp(databaseDir, ".restore-staged-*.db")
	if err != nil {
		return nil, fmt.Errorf("无法在数据库目录创建恢复临时文件: %w", err)
	}
	temporaryPath := temporary.Name()
	cleanupTemporary := func() { _ = temporary.Close(); _ = os.Remove(temporaryPath) }
	copiedSHA, copiedBytes, err := copyFileWithDigest(stagedPath, temporary)
	if err != nil {
		cleanupTemporary()
		return nil, fmt.Errorf("复制暂存数据库失败: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		cleanupTemporary()
		return nil, fmt.Errorf("恢复临时数据库 fsync 失败: %w", err)
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return nil, fmt.Errorf("恢复临时数据库关闭失败: %w", err)
	}
	if copiedBytes <= 0 {
		_ = os.Remove(temporaryPath)
		return nil, fmt.Errorf("%w: 暂存数据库为空", ErrStageFailed)
	}
	if expectedSHA256 != "" && !strings.EqualFold(copiedSHA, expectedSHA256) {
		_ = os.Remove(temporaryPath)
		return nil, fmt.Errorf("%w: 暂存数据库复制后摘要与清单不一致", ErrStageFailed)
	}
	sw := &databaseSwitch{
		livePath:       s.databasePath,
		preRestorePath: filepath.Join(databaseDir, preRestorePrefix+restoreID+".db"),
		failedPath:     filepath.Join(databaseDir, failedRestorePrefix+restoreID+".db"),
	}
	removeWALSidecars(s.databasePath)
	if err := os.Rename(s.databasePath, sw.preRestorePath); err != nil {
		_ = os.Remove(temporaryPath)
		return nil, fmt.Errorf("无法把当前数据库改名为恢复前副本（可能仍有进程占用，"+
			"请先停止服务）: %w", err)
	}
	if err := os.Rename(temporaryPath, s.databasePath); err != nil {
		// 尝试立刻回退，避免留下“活动数据库缺失”的状态。
		restoreErr := os.Rename(sw.preRestorePath, s.databasePath)
		if restoreErr != nil {
			return nil, fmt.Errorf("切换数据库失败且回退失败（活动数据库可能缺失，"+
				"恢复前副本位于 %s）: %w", sw.preRestorePath, errors.Join(err, restoreErr))
		}
		_ = os.Remove(temporaryPath)
		return nil, fmt.Errorf("切换数据库失败（已回退到恢复前数据库）: %w", err)
	}
	removeWALSidecars(s.databasePath)
	maintenance.SyncDirectory(databaseDir)
	sw.switched = true
	return sw, nil
}

// rollbackDatabase 把活动数据库回退为恢复前副本；当前（恢复失败的）数据库改名保留
// 为诊断副本。失败时保持维护状态并返回原因。
func (s *Service) rollbackDatabase(sw *databaseSwitch) error {
	if sw == nil || !sw.switched {
		return nil
	}
	if err := os.Rename(sw.livePath, sw.failedPath); err != nil {
		return fmt.Errorf("无法移走恢复后的数据库以回退: %w", err)
	}
	removeWALSidecars(sw.livePath)
	if err := os.Rename(sw.preRestorePath, sw.livePath); err != nil {
		// 尽量恢复一个可用数据库（即使它是恢复失败的那份），并保持维护。
		_ = os.Rename(sw.failedPath, sw.livePath)
		return fmt.Errorf("无法把恢复前数据库改回活动路径: %w", err)
	}
	maintenance.SyncDirectory(filepath.Dir(sw.livePath))
	sw.switched = false
	return nil
}

// cleanupSuccessfulSwitch 删除恢复前明文副本并清理历史诊断副本（仅保留自身）。
func (s *Service) cleanupSuccessfulSwitch(sw *databaseSwitch) error {
	if sw == nil {
		return nil
	}
	var problems []error
	if err := os.Remove(sw.preRestorePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		problems = append(problems, err)
	}
	pruneRestoreResidues(filepath.Dir(sw.livePath), preRestorePrefix, 0)
	pruneRestoreResidues(filepath.Dir(sw.livePath), failedRestorePrefix, 1)
	if len(problems) > 0 {
		return errors.Join(problems...)
	}
	return nil
}

// pruneRestoreResidues 保留指定前缀中最新的 keep 个文件，删除更早的恢复残留。
func pruneRestoreResidues(directory, prefix string, keep int) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return
	}
	matches := make([]os.FileInfo, 0, 4)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		matches = append(matches, info)
	}
	// 按修改时间从新到旧排序。
	for left := 0; left < len(matches); left++ {
		for right := left + 1; right < len(matches); right++ {
			if matches[right].ModTime().After(matches[left].ModTime()) {
				matches[left], matches[right] = matches[right], matches[left]
			}
		}
	}
	for index := keep; index < len(matches); index++ {
		_ = os.Remove(filepath.Join(directory, matches[index].Name()))
	}
}

// checkpointLiveDatabase 对当前数据库执行 WAL checkpoint 并关闭连接，确保切换前
// 所有已提交数据都在主文件中；仍然被其他进程占用时明确失败。
func (s *Service) checkpointLiveDatabase(ctx context.Context) error {
	store, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(s.databasePath))
	if err != nil {
		return fmt.Errorf("无法打开当前数据库执行切换前检查: %w", err)
	}
	var busy, logFrames, checkpointed int
	scanErr := store.DB().QueryRowContext(ctx,
		`PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logFrames, &checkpointed)
	closeErr := store.Close()
	if scanErr != nil {
		return fmt.Errorf("切换前数据库 checkpoint 失败: %w", scanErr)
	}
	if busy != 0 {
		return fmt.Errorf("切换前数据库仍有其他连接在使用（请先停止服务）")
	}
	if closeErr != nil {
		return fmt.Errorf("切换前关闭数据库失败: %w", closeErr)
	}
	return nil
}

// removeWALSidecars 删除 WAL/SHM 旁文件（数据库已 checkpoint 且关闭）；只删除
// 数据库路径同目录的固定派生文件名，不跟随符号链接。
func removeWALSidecars(databasePath string) {
	for _, suffix := range []string{"-wal", "-shm"} {
		path := databasePath + suffix
		if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() {
			_ = os.Remove(path)
		}
	}
}

// copyFileWithDigest 把源文件复制到已打开的目标文件，返回 SHA-256 与字节数。
func copyFileWithDigest(sourcePath string, destination *os.File) (string, int64, error) {
	source, err := os.Open(sourcePath)
	if err != nil {
		return "", 0, err
	}
	defer source.Close()
	hasher := sha256.New()
	written, err := io.Copy(io.MultiWriter(destination, hasher), source)
	if err != nil {
		return "", written, err
	}
	return hex.EncodeToString(hasher.Sum(nil)), written, nil
}

// applyAttachments 把暂存附件逐文件替换到附件受控目录，原文件先移动到库外备份
// 目录以便失败回退。返回回退状态与实际恢复文件数。
func (s *Service) applyAttachments(ctx context.Context, entries []backup.ExtractedEntry,
	restoreID string) (*attachmentRollback, int64, error) {
	if len(entries) == 0 {
		return nil, 0, nil
	}
	if s.opts.AttachmentsDir == "" {
		return nil, 0, fmt.Errorf("%w: 备份包含附件但未配置附件受控目录", ErrStageFailed)
	}
	backupDir := filepath.Join(s.stateDir, restoreAttachmentsPrefix+restoreID)
	if err := os.Mkdir(backupDir, 0o700); err != nil {
		return nil, 0, fmt.Errorf("无法创建附件回退目录: %w", err)
	}
	state := &attachmentRollback{backupDir: backupDir}
	rollback := func() {
		_ = s.rollbackAttachments(state)
		_ = os.RemoveAll(backupDir)
	}
	var applied int64
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			rollback()
			return nil, applied, err
		}
		key := strings.TrimPrefix(entry.Name, attachmentEntryPrefix)
		if err := validateAttachmentKey(key); err != nil {
			rollback()
			return nil, applied, err
		}
		target := filepath.Join(s.opts.AttachmentsDir, filepath.FromSlash(key))
		relative, err := filepath.Rel(s.opts.AttachmentsDir, target)
		if err != nil || relative == ".." ||
			strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			rollback()
			return nil, applied, fmt.Errorf("%w: 附件目标路径逃逸受控目录", ErrStageFailed)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			rollback()
			return nil, applied, fmt.Errorf("无法创建附件目标目录: %w", err)
		}
		swap := attachmentSwap{target: target}
		if _, statErr := os.Lstat(target); statErr == nil {
			safeName := strings.ReplaceAll(key, "/", "_")
			backupPath := filepath.Join(backupDir, fmt.Sprintf("%d-%s", applied, safeName))
			if err := moveFile(target, backupPath); err != nil {
				rollback()
				return nil, applied, fmt.Errorf("无法备份原附件: %w", err)
			}
			swap.backup = backupPath
		}
		if err := moveFile(entry.Path, target); err != nil {
			state.swaps = append(state.swaps, swap)
			rollback()
			return nil, applied, fmt.Errorf("无法写入恢复附件: %w", err)
		}
		state.swaps = append(state.swaps, swap)
		applied++
	}
	return state, applied, nil
}

// validateAttachmentKey 校验附件存储键是受控相对键：允许与头像存储一致的按前缀
// 分片子目录（如 a9/xxxx.png），拒绝绝对路径、反斜杠、空段与 .. 段。
func validateAttachmentKey(key string) error {
	if key == "" || len(key) > 200 {
		return fmt.Errorf("%w: 附件存储键为空或过长", ErrStageFailed)
	}
	if strings.ContainsAny(key, `\\`) || strings.HasPrefix(key, "/") {
		return fmt.Errorf("%w: 附件存储键包含非法分隔符", ErrStageFailed)
	}
	for index := 0; index < len(key); index++ {
		character := key[index]
		allowed := character == '/' || character == '.' || character == '_' ||
			character == '-' || (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9')
		if !allowed {
			return fmt.Errorf("%w: 附件存储键包含不允许的字符", ErrStageFailed)
		}
	}
	for _, segment := range strings.Split(key, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return fmt.Errorf("%w: 附件存储键包含危险路径段", ErrStageFailed)
		}
	}
	return nil
}

// rollbackAttachments 把附件恢复为替换前状态（幂等，按逆序处理）。
func (s *Service) rollbackAttachments(state *attachmentRollback) error {
	if state == nil {
		return nil
	}
	var problems []error
	for index := len(state.swaps) - 1; index >= 0; index-- {
		swap := state.swaps[index]
		if swap.backup != "" {
			if _, err := os.Lstat(swap.target); err == nil {
				if err := moveFile(swap.target, swap.target+".restore-failed"); err != nil {
					problems = append(problems, err)
					continue
				}
			}
			if err := moveFile(swap.backup, swap.target); err != nil {
				problems = append(problems, err)
			}
			continue
		}
		// 原本不存在的附件：删除恢复写入的文件。
		if err := os.Remove(swap.target); err != nil && !errors.Is(err, os.ErrNotExist) {
			problems = append(problems, err)
		}
	}
	_ = os.RemoveAll(state.backupDir)
	if len(problems) > 0 {
		return errors.Join(problems...)
	}
	return nil
}

// finishAttachments 成功后删除附件回退备份目录。
func (s *Service) finishAttachments(state *attachmentRollback) error {
	if state == nil {
		return nil
	}
	return os.RemoveAll(state.backupDir)
}

// moveFile 优先使用同卷原子改名；跨卷时退化为复制 + fsync + 删除源文件。
func moveFile(source, target string) error {
	if err := os.Rename(source, target); err == nil {
		return nil
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("源文件不是普通文件")
	}
	output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, input)
	if copyErr == nil {
		copyErr = output.Sync()
	}
	closeErr := output.Close()
	if copyErr != nil || closeErr != nil {
		_ = os.Remove(target)
		return errors.Join(copyErr, closeErr)
	}
	return os.Remove(source)
}

// mergeRestoredAudit 打开恢复后数据库并把库外恢复审计合并进去。
func (s *Service) mergeRestoredAudit(ctx context.Context, actor audit.Actor,
	restoreID string) (int, error) {
	store, err := s.openLiveStore(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = store.Close() }()
	return s.mergeJournalToDB(ctx, store, actor, restoreID)
}

// stagePendingConfig 把备份中的配置快照复制到库外待审查目录（不自动应用）。
func (s *Service) stagePendingConfig(ctx context.Context, configPath, restoreID string) (string, error) {
	directory := filepath.Join(s.stateDir, pendingConfigDirName, restoreID)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", fmt.Errorf("%w: 无法创建配置审查目录", ErrStoreUnavailable)
	}
	target := filepath.Join(directory, "config.yaml")
	source, err := os.Open(configPath)
	if err != nil {
		return "", fmt.Errorf("%w: 无法读取待审查配置", ErrStageFailed)
	}
	defer source.Close()
	file, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("%w: 无法写入待审查配置", ErrStageFailed)
	}
	if _, err := io.Copy(file, source); err != nil {
		_ = file.Close()
		_ = os.Remove(target)
		return "", fmt.Errorf("%w: 复制待审查配置失败", ErrStageFailed)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(target)
		return "", fmt.Errorf("%w: 待审查配置 fsync 失败", ErrStageFailed)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("%w: 待审查配置关闭失败", ErrStageFailed)
	}
	return target, nil
}

// attachmentEntryPrefix 与 backup 容器内附件条目前缀一致（恢复侧解析用）。
const attachmentEntryPrefix = "attachments/"

// isWindowsPlatform 报告当前平台是否为 Windows（权限语义差异）。
func isWindowsPlatform() bool {
	// 通过编译期平台文件实现替换：见平台实现文件。
	return platformIsWindows
}
