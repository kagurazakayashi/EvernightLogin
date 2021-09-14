package backupadmin

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// BackupTaskTimeoutSeconds 是备份任务的墙钟上限（任务层）。备份服务内部有自己的
// 更短超时（默认 10 分钟、上限 6 小时），任务层必须不小于它，否则任务先超时会把
// 服务自身的清理与审计打断；因此默认 1 小时。
const BackupTaskTimeoutSeconds = 3600

// JobView 是备份/清理任务页面视图。State 来自 internal/task 真实状态机；Stage 与
// 进度来自处理器持久化的真实阶段，缺失即未知（不伪造百分比）。
type JobView struct {
	ID                string
	Kind              string
	Origin            string
	ScheduleID        string
	State             string
	StageCode         string
	StageDescription  string
	ProgressDone      *int64
	ProgressTotal     *int64
	ProgressUnit      string
	Attempt           int
	MaxAttempts       int
	Initiator         audit.Actor
	Canceller         *audit.Actor
	ErrorCode         string
	FailureReason     string
	RequestID         string
	BackupID          string
	NotificationStat  string
	NotificationCode  string
	ResultSummary     string
	CreatedAt         time.Time
	StartedAt         time.Time
	FinishedAt        time.Time
	CancelRequestedAt time.Time
	UpdatedAt         time.Time
}

// JobRef 是任务提交结果。Existing 为 true 表示服务端按幂等规则返回了已存在的活动
// 任务而不是新建；提交成功不代表备份完成。
type JobRef struct {
	JobID    string
	Existing bool
	State    string
}

// CancelView 是取消请求结果。Accepted 表示请求被接受；AlreadyRequested 表示此前已
// 接受；State 是处理后的真实状态（取消请求被接受不等于任务已取消）。
type CancelView struct {
	JobID            string
	Accepted         bool
	AlreadyRequested bool
	State            string
	Note             string
}

// EnqueueBackup 触发一次手动备份任务（要求 backups.create，并按 backup.create 敏感
// 操作再次认证）。相同互斥组已有活动备份任务时返回已存在任务，不重复创建。
func (s *Service) EnqueueBackup(ctx context.Context, caller account.Caller,
	requestID string) (JobRef, error) {
	if err := s.authorize(ctx, caller, PermissionCreate); err != nil {
		return JobRef{}, err
	}
	if active, found, err := s.activeBackupJob(ctx, caller); err != nil {
		return JobRef{}, err
	} else if found {
		return JobRef{JobID: active.ID, Existing: true, State: string(active.State)}, nil
	}
	requestID = normalizeRequestID(requestID)
	result, err := s.authorizeSensitive(ctx, caller, OperationCreate, "backup", "",
		map[string]string{"scope": ScopeSystem, "kind": KindBackupCreate},
		"创建加密备份（系统范围全量数据）", requestID)
	if err != nil {
		return JobRef{}, err
	}
	payload, err := encodeJobPayload(jobPayload{Origin: string(OriginManual),
		RetentionVersion: s.currentRetentionVersion(ctx)})
	if err != nil {
		return JobRef{}, err
	}
	job, err := s.opts.Enqueuer.Enqueue(ctx, task.EnqueueRequest{
		Kind: KindBackupCreate, Actor: caller.Actor(), Payload: payload,
		MutexKey: DefaultBackupMutexKey, TimeoutSeconds: BackupTaskTimeoutSeconds,
		MaxAttempts: 2, PermissionRequired: true, RequestID: requestID,
	})
	if err != nil {
		return JobRef{}, mapTaskError(err)
	}
	s.registerJob(ctx, job, OriginManual, "", caller.Actor())
	// 入队审计由 internal/task 在同一事务中写入；这里补充“页面/服务触发”的来源审计，
	// 失败只告警，不把已入队的任务说成未提交。
	s.recordBestEffort(ctx, audit.Event{
		Actor: caller.Actor(), Action: ActionJobEnqueued,
		Target:  audit.Target{Type: "backup_job", ID: job.ID},
		Outcome: audit.OutcomeSuccess, RequestID: requestID,
		Changes: []audit.FieldChange{
			{Field: "kind", After: KindBackupCreate},
			{Field: "origin", After: string(OriginManual)},
			{Field: "scope", After: ScopeSystem},
		},
	})
	s.notifySensitiveOutcome(ctx, result)
	return JobRef{JobID: job.ID, State: string(job.State)}, nil
}

// activeBackupJob 查找仍在活动状态（queued/running/cancel_requested）的备份任务。
func (s *Service) activeBackupJob(ctx context.Context, caller account.Caller) (task.Job, bool, error) {
	entries, err := s.opts.Store.ListJobs(ctx, JobFilter{Kind: KindBackupCreate, Limit: 50})
	if err != nil {
		return task.Job{}, false, err
	}
	for _, entry := range entries {
		job, err := s.opts.TaskReader.Get(ctx, entry.JobID)
		if err != nil {
			continue
		}
		if job.State == task.StateQueued || job.State == task.StateRunning ||
			job.State == task.StateCancelRequested {
			// 只有同一互斥组（全局备份锁）才真正会串行；活动任务存在即按幂等返回，
			// 由页面显示为“已有任务”，不创建第二个排队任务。
			return job, true, nil
		}
	}
	return task.Job{}, false, nil
}

// jobPayload 是备份/清理任务载荷（不含秘密、宿主路径或浏览器自报身份）。清理任务
// 另存再次认证批准的目标摘要与策略版本：执行时校验“批准集合=实际待删集合”，防止
// 批准后策略/目标变化导致删除范围被悄悄扩大。
type jobPayload struct {
	Origin           string `json:"origin"`
	ScheduleID       string `json:"schedule_id"`
	RetentionVersion int64  `json:"retention_version"`
	// TargetDigest 是批准清理目标集合的 SHA-256（按备份编号排序拼接），仅清理任务。
	TargetDigest string `json:"target_digest,omitempty"`
	// PolicyVersion 是批准时的保留策略版本。
	PolicyVersion int64 `json:"policy_version,omitempty"`
	// TargetCount 是批准时的目标数量。
	TargetCount int `json:"target_count,omitempty"`
}

// encodeJobPayload 编码受控任务载荷。
func encodeJobPayload(payload jobPayload) ([]byte, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: 任务载荷编码失败", ErrInvalidRequest)
	}
	return encoded, nil
}

// registerJob 记录任务索引与初始状态；失败只告警（任务本身已由 internal/task 持久化，
// 页面可能暂时缺少索引，由对账/下次查询修复）。
func (s *Service) registerJob(ctx context.Context, job task.Job, origin Origin,
	scheduleID string, initiator audit.Actor) {
	entry := JobIndexEntry{JobID: job.ID, Kind: job.Kind, Origin: origin,
		ScheduleID: scheduleID, Initiator: initiator, CreatedAt: job.CreatedAt}
	if err := s.opts.Store.InsertJob(ctx, entry); err != nil {
		s.logger.Warn("备份任务索引写入失败", "job_id", job.ID)
	}
	if err := s.opts.Store.SaveJobState(ctx, JobProgressState{
		JobID: job.ID, UpdatedAt: s.now(),
	}); err != nil {
		s.logger.Warn("备份任务状态初始化失败", "job_id", job.ID)
	}
}

// ListJobs 列出备份/清理任务（要求 backups.read）；返回 hasMore 由 limit+1 判定。
func (s *Service) ListJobs(ctx context.Context, caller account.Caller,
	filter JobFilter) ([]JobView, bool, error) {
	if err := s.authorize(ctx, caller, PermissionRead); err != nil {
		return nil, false, err
	}
	if filter.Limit <= 0 {
		filter.Limit = defaultListLimit
	}
	if filter.Limit > maxListLimit {
		filter.Limit = maxListLimit
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}
	entries, err := s.opts.Store.ListJobs(ctx, JobFilter{Kind: filter.Kind,
		ScheduleID: filter.ScheduleID, Limit: filter.Limit + 1, Offset: filter.Offset})
	if err != nil {
		return nil, false, err
	}
	hasMore := len(entries) > filter.Limit
	if hasMore {
		entries = entries[:filter.Limit]
	}
	views := make([]JobView, 0, len(entries))
	for _, entry := range entries {
		job, err := s.opts.TaskReader.Get(ctx, entry.JobID)
		if err != nil {
			// 索引残留但任务不可读：显示“状态未知”，不伪造完成或失败。
			views = append(views, JobView{ID: entry.JobID, Kind: entry.Kind,
				Origin: string(entry.Origin), ScheduleID: entry.ScheduleID,
				State: "unknown", CreatedAt: entry.CreatedAt, Initiator: entry.Initiator})
			continue
		}
		views = append(views, s.jobView(ctx, job, entry))
	}
	return views, hasMore, nil
}

// GetJob 读取单个任务真实状态（要求 backups.read）。
func (s *Service) GetJob(ctx context.Context, caller account.Caller,
	jobID string) (JobView, error) {
	if err := s.authorize(ctx, caller, PermissionRead); err != nil {
		return JobView{}, err
	}
	jobID = strings.TrimSpace(jobID)
	if err := task.ValidateJobID(jobID); err != nil {
		return JobView{}, fmt.Errorf("%w: 任务编号无效", ErrInvalidRequest)
	}
	job, err := s.opts.TaskReader.Get(ctx, jobID)
	if err != nil {
		return JobView{}, ErrNotFound
	}
	entry, found, err := s.opts.Store.GetJob(ctx, jobID)
	if err != nil {
		return JobView{}, err
	}
	if !found {
		entry = JobIndexEntry{JobID: job.ID, Kind: job.Kind, Origin: OriginManual,
			Initiator: job.Initiator, CreatedAt: job.CreatedAt}
	}
	return s.jobView(ctx, job, entry), nil
}

// jobView 合并任务状态机与持久化的阶段/进度/通知摘要。
func (s *Service) jobView(ctx context.Context, job task.Job, entry JobIndexEntry) JobView {
	view := JobView{
		ID: job.ID, Kind: job.Kind, Origin: string(entry.Origin),
		ScheduleID: entry.ScheduleID, State: string(job.State),
		Attempt: job.Attempt, MaxAttempts: job.MaxAttempts, Initiator: job.Initiator,
		Canceller: job.Canceller, ErrorCode: job.ErrorCode,
		FailureReason: job.FailureReason, RequestID: job.RequestID,
		CreatedAt: job.CreatedAt, StartedAt: job.StartedAt, FinishedAt: job.FinishedAt,
		CancelRequestedAt: job.CancelRequestedAt, UpdatedAt: job.UpdatedAt,
	}
	if state, found, err := s.opts.Store.JobState(ctx, job.ID); err == nil && found {
		view.StageCode = state.StageCode
		view.StageDescription = stageDescription(state.StageCode)
		view.ProgressDone = state.ProgressDone
		view.ProgressTotal = state.ProgressTotal
		view.ProgressUnit = state.ProgressUnit
		view.BackupID = state.BackupID
		view.NotificationStat = state.NotificationStat
		view.NotificationCode = state.NotificationCode
		view.ResultSummary = state.ResultSummary
	}
	if view.BackupID == "" {
		if artifact, found, err := s.artifactByJob(ctx, job.ID); err == nil && found {
			view.BackupID = artifact.BackupID
		}
	}
	return view
}

// stageDescription 把稳定阶段码映射为直白中文；只显示后端真实报告过的阶段。
func stageDescription(stage string) string {
	switch stage {
	case "":
		return ""
	case "prepare":
		return "正在准备备份"
	case "permission":
		return "正在复核执行权限"
	case "snapshot":
		return "正在建立数据库一致性快照"
	case "content":
		return "正在协调备份内容"
	case "write":
		return "正在写入加密备份"
	case "verify":
		return "正在校验备份"
	case "publish":
		return "正在发布备份"
	case "finish":
		return "正在记录结果"
	case "cleanup":
		return "正在清理备份产物"
	case "done":
		return "已完成"
	default:
		return "未知阶段"
	}
}

// CancelJob 请求取消备份/清理任务（要求独立 backups.cancel 权限）。
func (s *Service) CancelJob(ctx context.Context, caller account.Caller, jobID, reason,
	requestID string) (CancelView, error) {
	if err := s.authorize(ctx, caller, PermissionCancel); err != nil {
		return CancelView{}, err
	}
	reason, err := validateReason(reason)
	if err != nil {
		return CancelView{}, err
	}
	jobID = strings.TrimSpace(jobID)
	if err := task.ValidateJobID(jobID); err != nil {
		return CancelView{}, fmt.Errorf("%w: 任务编号无效", ErrInvalidRequest)
	}
	result, err := s.opts.Canceller.RequestCancel(ctx, task.CancelRequest{
		JobID: jobID, Actor: caller.Actor(), Reason: reason,
		RequestID: normalizeRequestID(requestID),
	})
	if err != nil {
		return CancelView{}, mapTaskError(err)
	}
	note := "取消请求已接受；任务可能仍在收尾，实际结果以任务状态为准。"
	if !result.Accepted {
		note = "服务端未受理取消请求，任务状态以查询结果为准。"
		if result.AlreadyRequested {
			note = "此前已接受过取消请求；请以任务真实状态为准。"
		}
	}
	s.recordBestEffort(ctx, audit.Event{
		Actor: caller.Actor(), Action: ActionJobCancel,
		Target:  audit.Target{Type: "backup_job", ID: jobID},
		Outcome: audit.OutcomeSuccess, RequestID: normalizeRequestID(requestID),
		Changes: []audit.FieldChange{
			{Field: "accepted", After: boolText(result.Accepted)},
			{Field: "already_requested", After: boolText(result.AlreadyRequested)},
			{Field: "state", After: string(result.State)},
		},
	})
	return CancelView{JobID: jobID, Accepted: result.Accepted,
		AlreadyRequested: result.AlreadyRequested, State: string(result.State),
		Note: note}, nil
}

// ArtifactView 是备份产物页面视图。不含宿主绝对路径、密钥或明文内容；FileExists
// 是服务端对受控目录的真实检查结果。
type ArtifactView struct {
	BackupID         string
	JobID            string
	ScheduleID       string
	Origin           string
	SizeBytes        int64
	FileSHA256       string
	ManifestSHA256   string
	FormatVersion    int
	SchemaVersion    string
	ContentDatabase  bool
	ContentAttach    string
	ContentConfig    string
	EntryCount       int
	Hostname         string
	AppVersion       string
	Verification     string
	VerifiedAt       time.Time
	RetentionVersion int64
	Cleanup          string
	CleanedAt        time.Time
	CreatedAt        time.Time
	PublishedAt      time.Time
	FileExists       bool
	// IsLastUsable 由服务端按全部真实产物计算；为 true 时受清理保护。
	IsLastUsable bool
	// ProtectionReason 是受保护原因（只显示服务端结论）。
	ProtectionReason string
	// Downloadable 是当前产物状态是否允许进入下载流程（仍需独立下载权限与再次认证）。
	Downloadable bool
}

// ListArtifacts 列出历史备份（要求 backups.read）。
func (s *Service) ListArtifacts(ctx context.Context, caller account.Caller,
	filter ArtifactFilter) ([]ArtifactView, bool, error) {
	if err := s.authorize(ctx, caller, PermissionRead); err != nil {
		return nil, false, err
	}
	if filter.Limit <= 0 {
		filter.Limit = defaultListLimit
	}
	if filter.Limit > maxListLimit {
		filter.Limit = maxListLimit
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}
	all, err := s.opts.Store.ListArtifacts(ctx, ArtifactFilter{Limit: filter.Limit + 1,
		Offset: filter.Offset, Origin: filter.Origin, Verification: filter.Verification,
		Cleanup: filter.Cleanup, ScheduleID: filter.ScheduleID, JobID: filter.JobID})
	if err != nil {
		return nil, false, err
	}
	hasMore := len(all) > filter.Limit
	if hasMore {
		all = all[:filter.Limit]
	}
	// 最后可用判定必须基于全量产物，不能只看当前页，否则会把某页最早一条误判为
	// “最后可用”。这里重新读取全部未清理产物（上限 1000，防止无界扫描）。
	lastUsable := s.lastUsableID(ctx)
	views := make([]ArtifactView, 0, len(all))
	for _, artifact := range all {
		views = append(views, s.artifactView(artifact, lastUsable))
	}
	return views, hasMore, nil
}

// GetArtifact 读取单个产物受控元数据（要求 backups.read）。
func (s *Service) GetArtifact(ctx context.Context, caller account.Caller,
	backupID string) (ArtifactView, error) {
	if err := s.authorize(ctx, caller, PermissionRead); err != nil {
		return ArtifactView{}, err
	}
	artifact, err := s.lookupArtifact(ctx, backupID)
	if err != nil {
		return ArtifactView{}, err
	}
	return s.artifactView(artifact, s.lastUsableID(ctx)), nil
}

// lookupArtifact 读取产物并校验编号格式。
func (s *Service) lookupArtifact(ctx context.Context, backupID string) (Artifact, error) {
	backupID = strings.TrimSpace(backupID)
	if backupID == "" || len(backupID) > 64 {
		return Artifact{}, fmt.Errorf("%w: 备份编号无效", ErrInvalidRequest)
	}
	artifact, found, err := s.opts.Store.GetArtifact(ctx, backupID)
	if err != nil {
		return Artifact{}, err
	}
	if !found {
		return Artifact{}, ErrNotFound
	}
	return artifact, nil
}

// artifactByJob 按任务编号查找关联产物（用于任务详情显示真实产物链接）。
func (s *Service) artifactByJob(ctx context.Context, jobID string) (Artifact, bool, error) {
	artifacts, err := s.opts.Store.ListArtifacts(ctx,
		ArtifactFilter{JobID: jobID, Limit: 1})
	if err != nil {
		return Artifact{}, false, err
	}
	if len(artifacts) == 0 {
		return Artifact{}, false, nil
	}
	return artifacts[0], true, nil
}

// artifactView 映射产物视图并计算保护原因。
func (s *Service) artifactView(artifact Artifact, lastUsableID string) ArtifactView {
	exists := s.artifactFileExists(artifact)
	view := ArtifactView{
		BackupID: artifact.BackupID, JobID: artifact.JobID,
		ScheduleID: artifact.ScheduleID, Origin: string(artifact.Origin),
		SizeBytes: artifact.SizeBytes, FileSHA256: artifact.FileSHA256,
		ManifestSHA256: artifact.ManifestSHA256, FormatVersion: artifact.FormatVersion,
		SchemaVersion: artifact.SchemaVersion, ContentDatabase: artifact.ContentDatabase,
		ContentAttach: string(artifact.ContentAttach), ContentConfig: string(artifact.ContentConfig),
		EntryCount: artifact.EntryCount, Hostname: artifact.Hostname,
		AppVersion: artifact.AppVersion, Verification: string(artifact.Verification),
		VerifiedAt: artifact.VerifiedAt, RetentionVersion: artifact.RetentionVersion,
		Cleanup: string(artifact.Cleanup), CleanedAt: artifact.CleanedAt,
		CreatedAt: artifact.CreatedAt, PublishedAt: artifact.PublishedAt,
		FileExists: exists,
	}
	switch {
	case artifact.Cleanup == CleanupCleaned:
		view.ProtectionReason = "文件已按保留策略清理"
	case artifact.BackupID == lastUsableID:
		view.IsLastUsable = true
		view.ProtectionReason = "受保护：这是当前范围最后一份可用备份。"
	case artifact.Verification == VerificationUnknown || artifact.Verification == VerificationUnverified:
		view.ProtectionReason = "可用性未知，按保护规则暂不作为可清理对象。"
	case artifact.Verification == VerificationFailed:
		view.ProtectionReason = "校验失败，保留为诊断证据，暂不清理。"
	}
	if artifact.Cleanup == CleanupRetained && artifact.Verification == VerificationVerified && exists {
		view.Downloadable = true
	}
	return view
}

// backupPath 返回受控输出目录内的产物路径；拒绝路径穿越与非法文件名。
func (s *Service) backupPath(artifact Artifact) (string, error) {
	name := filepath.Base(artifact.FileName)
	if name != artifact.FileName || name == "." || name == ".." {
		return "", fmt.Errorf("%w: 备份文件名非法", ErrInvalidRequest)
	}
	if !strings.HasPrefix(name, artifactFilePrefix) || !strings.HasSuffix(name, artifactFileSuffix) {
		return "", fmt.Errorf("%w: 备份文件名非法", ErrInvalidRequest)
	}
	path := filepath.Join(s.outputDir, name)
	relative, err := filepath.Rel(s.outputDir, path)
	if err != nil || strings.HasPrefix(relative, "..") {
		return "", fmt.Errorf("%w: 备份路径越界", ErrInvalidRequest)
	}
	return path, nil
}

// artifactFileExists 检查产物文件是否仍存在且是普通文件。
func (s *Service) artifactFileExists(artifact Artifact) bool {
	path, err := s.backupPath(artifact)
	if err != nil {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}

// lastUsableID 返回最新一份“已发布且校验通过且未清理”的备份编号；没有时为 ""。
func (s *Service) lastUsableID(ctx context.Context) string {
	artifacts, err := s.opts.Store.ListArtifacts(ctx,
		ArtifactFilter{Verification: VerificationVerified, Cleanup: CleanupRetained, Limit: 1000})
	if err != nil {
		return ""
	}
	var newest Artifact
	for _, artifact := range artifacts {
		if newest.BackupID == "" || artifact.PublishedAt.After(newest.PublishedAt) ||
			(artifact.PublishedAt.Equal(newest.PublishedAt) &&
				artifact.BackupID > newest.BackupID) {
			newest = artifact
		}
	}
	return newest.BackupID
}

// currentRetentionVersion 返回当前生效保留策略版本；失败时返回 0（不伪造）。
func (s *Service) currentRetentionVersion(ctx context.Context) int64 {
	policy, found, err := s.opts.Store.RetentionPolicy(ctx)
	if err != nil || !found {
		return 0
	}
	return policy.Version
}

// ===================== 下载（一次性短期令牌） =====================

// DownloadTicket 是一次性下载令牌（只返回给当前已认证操作者，不是公开链接）。
type DownloadTicket struct {
	BackupID  string
	Token     string
	ExpiresAt time.Time
}

// DownloadFile 是受控下载结果；Data 只在当前请求内返回，不写日志、不缓存。
type DownloadFile struct {
	BackupID    string
	FileName    string
	ContentType string
	SHA256      string
	Size        int64
	ExpiresAt   time.Time
	Data        []byte
}

// IssueDownloadTicket 校验独立下载权限与敏感操作后签发一次性短时令牌。
func (s *Service) IssueDownloadTicket(ctx context.Context, caller account.Caller,
	backupID, requestID string) (DownloadTicket, error) {
	if err := s.authorize(ctx, caller, PermissionDownload); err != nil {
		return DownloadTicket{}, err
	}
	artifact, err := s.lookupArtifact(ctx, backupID)
	if err != nil {
		return DownloadTicket{}, err
	}
	if !s.downloadable(artifact) {
		return DownloadTicket{}, ErrNotDownloadable
	}
	requestID = normalizeRequestID(requestID)
	result, err := s.authorizeSensitive(ctx, caller, OperationDownload, "backup",
		artifact.BackupID, map[string]string{
			"backup_id": artifact.BackupID,
			"sha256":    artifact.FileSHA256,
			"size":      fmt.Sprint(artifact.SizeBytes),
		}, "下载加密备份文件", requestID)
	if err != nil {
		return DownloadTicket{}, err
	}
	token, digest, err := s.newDownloadToken()
	if err != nil {
		return DownloadTicket{}, err
	}
	expiresAt := s.now().Add(s.opts.DownloadTTL)
	s.tickets.put(digest, s.now(), ticketEntry{
		Actor: caller.Actor(), BackupID: artifact.BackupID,
		FileSHA256: artifact.FileSHA256, ExpiresAt: expiresAt,
	})
	if err := s.record(ctx, audit.Event{
		Actor: caller.Actor(), Action: ActionDownloadIssued,
		Target:  audit.Target{Type: "backup", ID: artifact.BackupID},
		Outcome: audit.OutcomeSuccess, RequestID: requestID,
		Changes: []audit.FieldChange{
			{Field: "expires_in_seconds", After: fmt.Sprint(int(s.opts.DownloadTTL.Seconds()))},
		},
	}); err != nil {
		return DownloadTicket{}, err
	}
	s.notifySensitiveOutcome(ctx, result)
	return DownloadTicket{BackupID: artifact.BackupID, Token: token, ExpiresAt: expiresAt}, nil
}

// RedeemDownloadTicket 兑换一次性令牌并返回受控文件字节；过期、重放、跨账户或
// 权限已撤销都被拒绝。
func (s *Service) RedeemDownloadTicket(ctx context.Context, caller account.Caller,
	token, requestID string) (DownloadFile, error) {
	if err := s.authorize(ctx, caller, PermissionDownload); err != nil {
		return DownloadFile{}, err
	}
	digest := sha256.Sum256([]byte(strings.TrimSpace(token)))
	entry, found := s.tickets.take(digest)
	if !found || s.now().After(entry.ExpiresAt) {
		return DownloadFile{}, fmt.Errorf("%w: 下载入口无效或已过期", ErrAccessDenied)
	}
	if entry.Actor.Type != caller.Actor().Type || entry.Actor.ID != caller.Actor().ID {
		return DownloadFile{}, fmt.Errorf("%w: 下载入口不属于当前账户", ErrAccessDenied)
	}
	artifact, err := s.lookupArtifact(ctx, entry.BackupID)
	if err != nil {
		return DownloadFile{}, err
	}
	if artifact.FileSHA256 != entry.FileSHA256 || !s.downloadable(artifact) {
		return DownloadFile{}, ErrNotDownloadable
	}
	path, err := s.backupPath(artifact)
	if err != nil {
		return DownloadFile{}, err
	}
	if artifact.SizeBytes > s.opts.MaxPageDownloadBytes {
		return DownloadFile{}, ErrDownloadTooLarge
	}
	data, err := os.ReadFile(path)
	if err != nil || int64(len(data)) != artifact.SizeBytes {
		return DownloadFile{}, ErrNotDownloadable
	}
	if subtle.ConstantTimeCompare([]byte(sha256Hex(data)), []byte(artifact.FileSHA256)) != 1 {
		return DownloadFile{}, ErrNotDownloadable
	}
	if err := s.record(ctx, audit.Event{
		Actor: caller.Actor(), Action: ActionDownloadRedeemed,
		Target:  audit.Target{Type: "backup", ID: artifact.BackupID},
		Outcome: audit.OutcomeSuccess, RequestID: normalizeRequestID(requestID),
		Changes: []audit.FieldChange{
			{Field: "size", After: fmt.Sprint(artifact.SizeBytes)},
		},
	}); err != nil {
		return DownloadFile{}, err
	}
	return DownloadFile{
		BackupID: artifact.BackupID, FileName: artifact.FileName,
		ContentType: "application/octet-stream", SHA256: artifact.FileSHA256,
		Size: artifact.SizeBytes, ExpiresAt: entry.ExpiresAt, Data: data,
	}, nil
}

// downloadable 判断产物是否当前可下载：已校验、未清理且文件存在。
func (s *Service) downloadable(artifact Artifact) bool {
	return artifact.Cleanup == CleanupRetained &&
		artifact.Verification == VerificationVerified && s.artifactFileExists(artifact)
}

// newDownloadToken 生成一次性令牌与其摘要。
func (s *Service) newDownloadToken() (string, [32]byte, error) {
	buffer := make([]byte, ticketRandomBytes)
	if _, err := io.ReadFull(s.random, buffer); err != nil {
		return "", [32]byte{}, fmt.Errorf("%w: 安全随机源不可用", ErrStoreUnavailable)
	}
	token := base64.RawURLEncoding.EncodeToString(buffer)
	return token, sha256.Sum256([]byte(token)), nil
}

// ticketEntry 是一次性下载令牌的进程内记录。令牌只用于页面同一进程内的立即兑换，
// 不跨实例、不落库、不写日志；进程重启后自然失效（文档明确单实例假设）。
type ticketEntry struct {
	Actor      audit.Actor
	BackupID   string
	FileSHA256 string
	ExpiresAt  time.Time
}

// ticketRegistry 是受控的进程内一次性令牌表。
type ticketRegistry struct {
	mu      sync.Mutex
	entries map[[32]byte]ticketEntry
}

// newTicketRegistry 构造令牌表。
func newTicketRegistry() *ticketRegistry {
	return &ticketRegistry{entries: make(map[[32]byte]ticketEntry)}
}

// maxTickets 是一次性下载令牌表硬上限；超过时回收过期项后仍满则淘汰任意一项，
// 使内存有界（被淘汰令牌立即失效，页面重新申请即可）。
const maxTickets = 256

// put 写入令牌并回收过期条目；表满时淘汰任意一项以保持内存有界。
func (r *ticketRegistry) put(digest [32]byte, now time.Time, entry ticketEntry) {
	r.mu.Lock()
	for key, existing := range r.entries {
		if now.After(existing.ExpiresAt) {
			delete(r.entries, key)
		}
	}
	if len(r.entries) >= maxTickets {
		for key := range r.entries {
			delete(r.entries, key)
			break
		}
	}
	r.entries[digest] = entry
	r.mu.Unlock()
}

// take 一次性取出令牌；不存在或已被消费返回 false。
func (r *ticketRegistry) take(digest [32]byte) (ticketEntry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, found := r.entries[digest]
	if !found {
		return ticketEntry{}, false
	}
	delete(r.entries, digest)
	return entry, true
}

// ===================== 对账 =====================

// ReconcileResult 是孤儿成品对账结果。
type ReconcileResult struct {
	Scanned      int
	Orphans      int
	MissingFiles int
	Registered   []string
}

// Reconcile 对账受控输出目录与产物表：
//   - 目录中存在完整 .elnbak 但登记表没有（claimFinish→rename→成功审计窗口被强杀的
//     典型残留）→ 用无密钥 InspectFile 读取头部，登记为 verification_state=unknown
//     的孤儿产物，绝不冒充校验通过，也不删除文件；
//   - 登记表存在但文件缺失 → 保持记录并计入 missingFiles，由页面显示不一致。
//
// 本方法由宿主按周期调用，也会在每次清理任务开始时执行；它不删除任何文件。
func (s *Service) Reconcile(ctx context.Context) (ReconcileResult, error) {
	entries, err := os.ReadDir(s.outputDir)
	if err != nil {
		return ReconcileResult{}, fmt.Errorf("%w: 无法读取备份输出目录", ErrStoreUnavailable)
	}
	result := ReconcileResult{}
	known := make(map[string]struct{})
	artifacts, err := s.opts.Store.ListArtifacts(ctx, ArtifactFilter{Limit: 1000})
	if err != nil {
		return ReconcileResult{}, err
	}
	for _, artifact := range artifacts {
		known[artifact.FileName] = struct{}{}
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, artifactFilePrefix) || !strings.HasSuffix(name, artifactFileSuffix) {
			continue
		}
		result.Scanned++
		if _, found := known[name]; found {
			continue
		}
		path := filepath.Join(s.outputDir, name)
		report, err := s.opts.Inspect(ctx, path)
		if err != nil || !report.StructuralValid || report.BackupID == "" {
			// 文件无法解析：不登记为备份产物（不能把损坏文件当可用备份），只计数。
			continue
		}
		artifact := Artifact{
			BackupID: report.BackupID, Origin: OriginSystem, FileName: name,
			SizeBytes: report.FileSize, PayloadBytes: report.Encryption.PayloadCipherBytes,
			FileSHA256: report.FileSHA256, ManifestSHA256: report.ManifestSHA256,
			FormatVersion: report.FormatVersion, SchemaVersion: report.Database.SchemaVersion,
			ContentDatabase: report.Content.Database,
			ContentAttach:   ContentStatus(report.Content.Attachments.Status),
			ContentConfig:   ContentStatus(report.Content.Config.Status),
			EntryCount:      len(report.Entries), Hostname: report.Host,
			AppVersion: report.AppVersion, Verification: VerificationUnknown,
			CreatedAt: report.CreatedAt, PublishedAt: report.CreatedAt,
			Cleanup: CleanupRetained,
		}
		if err := s.opts.Store.InsertArtifact(ctx, artifact); err != nil {
			if errors.Is(err, ErrConflict) {
				continue
			}
			return result, err
		}
		result.Orphans++
		result.Registered = append(result.Registered, report.BackupID)
		s.recordBestEffort(ctx, audit.Event{
			Actor:   audit.Actor{Type: audit.ActorSystem, ID: "backup_reconcile"},
			Action:  ActionReconcile,
			Target:  audit.Target{Type: "backup", ID: report.BackupID},
			Outcome: audit.OutcomeSuccess,
			Changes: []audit.FieldChange{
				{Field: "state", After: "orphan_registered"},
				{Field: "verification", After: string(VerificationUnknown)},
			},
		})
	}
	// 逆方向：登记表有记录但文件缺失。
	for _, artifact := range artifacts {
		if artifact.Cleanup == CleanupCleaned {
			continue
		}
		if !s.artifactFileExists(artifact) {
			result.MissingFiles++
		}
	}
	return result, nil
}
