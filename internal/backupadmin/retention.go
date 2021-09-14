package backupadmin

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/task"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// RetentionView 是保留策略页面视图：当前生效值、来源（默认/已保存）、责任身份与
// 最近一次清理摘要（来自真实清理任务结果，不用 0 冒充）。
type RetentionView struct {
	Policy      RetentionPolicy
	IsDefault   bool
	LastCleanup *CleanupSummary
}

// RetentionChange 是保存保留策略的服务端白名单请求。
type RetentionChange struct {
	Caller          account.Caller
	MaxCount        int
	MaxAgeDays      int
	MaxTotalBytes   int64
	ExpectedVersion int64
	Reason          string
	RequestID       string
}

// CleanupCandidate 是清理计划中的一项，Reason 是服务端计算的具体触发原因。
type CleanupCandidate struct {
	ArtifactView
	Reason string
}

// CleanupPreview 是清理预览（不是删除授权，也不是最终目标清单）。
type CleanupPreview struct {
	Policy        RetentionPolicy
	Targets       []CleanupCandidate
	Protected     []CleanupCandidate
	TotalRetained int
	TotalBytes    int64
	TargetBytes   int64
	PreviewedAt   time.Time
	Note          string
}

// CleanupSummary 是一次清理任务的真实分项结果（来自任务结果摘要）。
type CleanupSummary struct {
	JobID          string
	State          string
	RequestedCount int
	CleanedCount   int
	FailedCount    int
	ProtectedCount int
	FreedBytes     int64
	FinishedAt     time.Time
}

// cleanupResultSummary 是清理任务持久化的受控结果摘要。
type cleanupResultSummary struct {
	Requested int   `json:"requested"`
	Cleaned   int   `json:"cleaned"`
	Failed    int   `json:"failed"`
	Protected int   `json:"protected"`
	Skipped   int   `json:"skipped"`
	Bytes     int64 `json:"freed_bytes"`
	Finished  int64 `json:"finished_at_ms"`
}

// Retention 读取当前生效保留策略（要求 backups.read）。
func (s *Service) Retention(ctx context.Context, caller account.Caller) (RetentionView, error) {
	if err := s.authorize(ctx, caller, PermissionRead); err != nil {
		return RetentionView{}, err
	}
	policy, found, err := s.opts.Store.RetentionPolicy(ctx)
	if err != nil {
		return RetentionView{}, err
	}
	view := RetentionView{Policy: policy, IsDefault: !found}
	if !found {
		view.Policy = s.defaultRetention()
	}
	view.LastCleanup = s.lastCleanupSummary(ctx)
	return view, nil
}

// defaultRetention 返回默认策略副本（不写库、不冒充已保存）。
func (s *Service) defaultRetention() RetentionPolicy {
	policy := s.opts.DefaultRetention
	policy.Reason = ""
	policy.RequestID = ""
	policy.UpdatedBy = audit.Actor{Type: audit.ActorSystem, ID: "backup_default"}
	return policy
}

// lastCleanupSummary 读取最近一次清理任务的真实分项结果。
func (s *Service) lastCleanupSummary(ctx context.Context) *CleanupSummary {
	entries, err := s.opts.Store.ListJobs(ctx, JobFilter{Kind: KindBackupCleanup, Limit: 1})
	if err != nil || len(entries) == 0 {
		return nil
	}
	job, err := s.opts.TaskReader.Get(ctx, entries[0].JobID)
	if err != nil {
		return nil
	}
	state, found, err := s.opts.Store.JobState(ctx, entries[0].JobID)
	if err != nil || !found || state.ResultSummary == "" {
		return &CleanupSummary{JobID: job.ID, State: string(job.State)}
	}
	var summary cleanupResultSummary
	if err := json.Unmarshal([]byte(state.ResultSummary), &summary); err != nil {
		return &CleanupSummary{JobID: job.ID, State: string(job.State)}
	}
	return &CleanupSummary{
		JobID: job.ID, State: string(job.State), RequestedCount: summary.Requested,
		CleanedCount: summary.Cleaned, FailedCount: summary.Failed,
		ProtectedCount: summary.Protected, FreedBytes: summary.Bytes,
		FinishedAt: time.UnixMilli(summary.Finished).UTC(),
	}
}

// SaveRetention 保存保留策略（要求独立 backups.retention 权限 + 强认证敏感操作）；
// 责任身份来自可信调用者，行版本冲突拒绝覆盖。保存不执行清理。
func (s *Service) SaveRetention(ctx context.Context, change RetentionChange) (RetentionView, error) {
	if err := s.authorize(ctx, change.Caller, PermissionRetention); err != nil {
		return RetentionView{}, err
	}
	reason, err := validateReason(change.Reason)
	if err != nil {
		return RetentionView{}, err
	}
	policy := RetentionPolicy{
		Version:       change.ExpectedVersion + 1,
		MaxCount:      change.MaxCount,
		MaxAgeDays:    change.MaxAgeDays,
		MaxTotalBytes: change.MaxTotalBytes,
		UpdatedAt:     s.now(),
		UpdatedBy:     change.Caller.Actor(),
		Reason:        reason,
		RequestID:     normalizeRequestID(change.RequestID),
	}
	if err := validateRetention(policy); err != nil {
		return RetentionView{}, err
	}
	current, found, err := s.opts.Store.RetentionPolicy(ctx)
	if err != nil {
		return RetentionView{}, err
	}
	if !found {
		if change.ExpectedVersion != 0 && change.ExpectedVersion != 1 {
			return RetentionView{}, ErrConflict
		}
	} else if current.Version != change.ExpectedVersion {
		return RetentionView{}, ErrConflict
	}
	sensitiveResult, err := s.authorizeSensitive(ctx, change.Caller,
		OperationRetention, "backup_retention", "system", map[string]string{
			"version":         fmt.Sprint(policy.Version),
			"max_count":       fmt.Sprint(policy.MaxCount),
			"max_age_days":    fmt.Sprint(policy.MaxAgeDays),
			"max_total_bytes": fmt.Sprint(policy.MaxTotalBytes),
		}, "修改备份保留策略（不删除原始审计）", policy.RequestID)
	if err != nil {
		return RetentionView{}, err
	}
	// 关键管理变更先写审计意图：审计不可用时拒绝保存，策略不会生效。
	if err := s.record(ctx, audit.Event{
		Actor: change.Caller.Actor(), Action: ActionRetentionUpdate,
		Target:  audit.Target{Type: "backup_retention", ID: "system"},
		Outcome: audit.OutcomeSuccess, RequestID: policy.RequestID,
		Changes: []audit.FieldChange{
			{Field: "version", After: fmt.Sprint(policy.Version)},
			{Field: "max_count", After: fmt.Sprint(policy.MaxCount)},
			{Field: "max_age_days", After: fmt.Sprint(policy.MaxAgeDays)},
			{Field: "max_total_bytes", After: fmt.Sprint(policy.MaxTotalBytes)},
			{Field: "reason_present", After: "true"},
		},
	}); err != nil {
		return RetentionView{}, err
	}
	if err := s.opts.Store.SaveRetentionPolicy(ctx, policy, change.ExpectedVersion); err != nil {
		s.recordChangeFailure(ctx, change.Caller.Actor(), ActionRetentionUpdate,
			"backup_retention", "system", policy.RequestID, "retention_save_failed")
		return RetentionView{}, err
	}
	s.notifySensitiveOutcome(ctx, sensitiveResult)
	return RetentionView{Policy: policy, IsDefault: false,
		LastCleanup: s.lastCleanupSummary(ctx)}, nil
}

// validateRetention 校验保留策略：三项非负、至少一项有限上限、天数上限合理。
func validateRetention(policy RetentionPolicy) error {
	if policy.MaxCount < 0 || policy.MaxAgeDays < 0 || policy.MaxTotalBytes < 0 {
		return fmt.Errorf("%w: 上限不能为负数", ErrRetentionInvalid)
	}
	if policy.MaxAgeDays > 36500 {
		return fmt.Errorf("%w: 最长保留天数超过允许范围", ErrRetentionInvalid)
	}
	if policy.MaxTotalBytes > 1<<50 {
		return fmt.Errorf("%w: 最大总容量超过允许范围", ErrRetentionInvalid)
	}
	if !policy.Enabled() {
		return fmt.Errorf("%w: 至少启用一项有限上限（不允许无限保留被静默默认）", ErrRetentionInvalid)
	}
	return nil
}

// CleanupPreview 计算清理预览（要求独立 backups.cleanup 权限）；预览不是授权。
func (s *Service) CleanupPreview(ctx context.Context, caller account.Caller) (CleanupPreview, error) {
	if err := s.authorize(ctx, caller, PermissionCleanup); err != nil {
		return CleanupPreview{}, err
	}
	plan, err := s.buildCleanupPlan(ctx, s.now())
	if err != nil {
		return CleanupPreview{}, err
	}
	return plan.preview(), nil
}

// cleanupPlan 是服务端计算出的清理计划（执行时重新计算，不复用旧预览）。
type cleanupPlan struct {
	policy        RetentionPolicy
	targets       []CleanupCandidate
	protected     []CleanupCandidate
	totalRetained int
	totalBytes    int64
	targetBytes   int64
	overCapacity  bool
}

// preview 转换为页面预览。
func (p cleanupPlan) preview() CleanupPreview {
	preview := CleanupPreview{
		Policy: p.policy, TotalRetained: p.totalRetained, TotalBytes: p.totalBytes,
		TargetBytes: p.targetBytes, PreviewedAt: time.Now().UTC(),
		Targets:   make([]CleanupCandidate, 0, len(p.targets)),
		Protected: make([]CleanupCandidate, 0, len(p.protected)),
	}
	preview.Targets = append(preview.Targets, p.targets...)
	preview.Protected = append(preview.Protected, p.protected...)
	if p.overCapacity {
		preview.Note = fmt.Sprintf("容量已超过上限；有 %d 份备份因保护规则保留。", len(p.protected))
	} else {
		preview.Note = "预览不是删除授权；执行时会重新检查权限、状态与保护规则。"
	}
	return preview
}

// buildCleanupPlan 计算清理候选与受保护项。核心保护规则：
//  1. 最新一份校验通过的备份永远受保护；
//  2. 校验状态未知/未校验/失败的产物不作为候选（保守保护）；
//  3. 数量上限只统计“已发布且校验通过”的备份；过期与容量对全部保留产物计算；
//  4. 任一上限触发即产生候选，但仍需通过保护规则；容量不足时如实报告未达标。
func (s *Service) buildCleanupPlan(ctx context.Context, now time.Time) (cleanupPlan, error) {
	policy, found, err := s.opts.Store.RetentionPolicy(ctx)
	if err != nil {
		return cleanupPlan{}, err
	}
	if !found {
		policy = s.defaultRetention()
	}
	artifacts, err := s.opts.Store.ListArtifacts(ctx,
		ArtifactFilter{Cleanup: CleanupRetained, Limit: 1000})
	if err != nil {
		return cleanupPlan{}, err
	}
	plan := cleanupPlan{policy: policy, totalRetained: len(artifacts)}
	verified := make([]Artifact, 0, len(artifacts))
	for _, artifact := range artifacts {
		plan.totalBytes += artifact.SizeBytes
		if artifact.Verification == VerificationVerified && s.artifactFileExists(artifact) {
			verified = append(verified, artifact)
		}
	}
	sortArtifactsPublishedAsc(verified)
	var lastUsable Artifact
	if len(verified) > 0 {
		lastUsable = verified[len(verified)-1]
	}
	// 可清理集合：已校验、文件存在、不是最后可用备份；按发布时间升序（最早优先）。
	cleanable := make([]Artifact, 0, len(verified))
	for _, artifact := range verified {
		if artifact.BackupID == lastUsable.BackupID {
			continue
		}
		cleanable = append(cleanable, artifact)
	}
	trigger := make(map[string][]string, len(cleanable))
	// 数量上限：超过部分从最早开始清理。
	if policy.MaxCount > 0 && len(verified) > policy.MaxCount {
		need := len(verified) - policy.MaxCount
		for index := 0; index < len(cleanable) && index < need; index++ {
			trigger[cleanable[index].BackupID] = append(trigger[cleanable[index].BackupID],
				"超过最多保留数量")
		}
	}
	// 天数上限：以发布时刻起算，超过天数且不是最后可用备份。
	if policy.MaxAgeDays > 0 {
		cutoff := now.Add(-time.Duration(policy.MaxAgeDays) * 24 * time.Hour)
		for _, artifact := range cleanable {
			if artifact.PublishedAt.Before(cutoff) {
				trigger[artifact.BackupID] = append(trigger[artifact.BackupID],
					"超过最长保留天数")
			}
		}
	}
	// 容量上限：从最早开始累计需要释放的空间；受保护项仍占容量。
	if policy.MaxTotalBytes > 0 && plan.totalBytes > policy.MaxTotalBytes {
		need := plan.totalBytes - policy.MaxTotalBytes
		var freed int64
		for _, artifact := range cleanable {
			if freed >= need {
				break
			}
			if _, exists := trigger[artifact.BackupID]; !exists {
				trigger[artifact.BackupID] = append(trigger[artifact.BackupID],
					"超过最大总容量")
			}
			freed += artifact.SizeBytes
		}
		if freed < need {
			plan.overCapacity = true
		}
	}
	// 汇总目标与受保护项。
	for _, artifact := range artifacts {
		reasons, isTarget := trigger[artifact.BackupID]
		view := s.artifactView(artifact, lastUsable.BackupID)
		if isTarget && artifact.Verification == VerificationVerified &&
			artifact.BackupID != lastUsable.BackupID && s.artifactFileExists(artifact) {
			target := CleanupCandidate{ArtifactView: view, Reason: strings.Join(reasons, "；")}
			plan.targets = append(plan.targets, target)
			plan.targetBytes += artifact.SizeBytes
			continue
		}
		if view.ProtectionReason != "" {
			plan.protected = append(plan.protected,
				CleanupCandidate{ArtifactView: view, Reason: view.ProtectionReason})
		}
	}
	sort.SliceStable(plan.targets, func(i, j int) bool {
		return plan.targets[i].PublishedAt.Before(plan.targets[j].PublishedAt)
	})
	sort.SliceStable(plan.protected, func(i, j int) bool {
		return plan.protected[i].PublishedAt.After(plan.protected[j].PublishedAt)
	})
	return plan, nil
}

// cleanupTargetDigest 计算清理目标集合摘要：按备份编号排序拼接后 SHA-256，用于把
// 再次认证批准的目标集合绑定到任务载荷（与顺序无关，集合变化必然改变摘要）。
func cleanupTargetDigest(targets []CleanupCandidate) string {
	ids := make([]string, 0, len(targets))
	for _, target := range targets {
		ids = append(ids, target.BackupID)
	}
	sort.Strings(ids)
	return sha256Hex([]byte(strings.Join(ids, ",")))
}

// EnqueueCleanup 提交一次按保留策略的清理任务（要求 backups.cleanup + 强认证）。
// 提交成功只表示任务已入队，最终结果以任务状态与分项结果为准。
func (s *Service) EnqueueCleanup(ctx context.Context, caller account.Caller,
	requestID string) (JobRef, error) {
	if err := s.authorize(ctx, caller, PermissionCleanup); err != nil {
		return JobRef{}, err
	}
	plan, err := s.buildCleanupPlan(ctx, s.now())
	if err != nil {
		return JobRef{}, err
	}
	if len(plan.targets) == 0 {
		return JobRef{}, fmt.Errorf("%w: 当前没有可清理的备份产物（保护规则优先）", ErrProtection)
	}
	requestID = normalizeRequestID(requestID)
	approvedDigest := cleanupTargetDigest(plan.targets)
	result, err := s.authorizeSensitive(ctx, caller, OperationCleanup, "backup_cleanup",
		"system", map[string]string{
			"target_count":   fmt.Sprint(len(plan.targets)),
			"target_bytes":   fmt.Sprint(plan.targetBytes),
			"policy_version": fmt.Sprint(plan.policy.Version),
			"target_digest":  approvedDigest,
		}, "清理过期备份产物（不删除原始审计）", requestID)
	if err != nil {
		return JobRef{}, err
	}
	job, err := s.enqueueCleanupJob(ctx, caller.Actor(), OriginManual, requestID,
		jobPayload{TargetDigest: approvedDigest,
			PolicyVersion: plan.policy.Version, TargetCount: len(plan.targets)})
	if err != nil {
		return JobRef{}, err
	}
	s.recordBestEffort(ctx, audit.Event{
		Actor: caller.Actor(), Action: ActionCleanupRequest,
		Target:  audit.Target{Type: "backup_cleanup", ID: job.ID},
		Outcome: audit.OutcomeSuccess, RequestID: requestID,
		Changes: []audit.FieldChange{
			{Field: "requested", After: fmt.Sprint(len(plan.targets))},
			{Field: "policy_version", After: fmt.Sprint(plan.policy.Version)},
		},
	})
	s.notifySensitiveOutcome(ctx, result)
	return JobRef{JobID: job.ID, State: string(job.State)}, nil
}

// enqueueCleanupJob 提交清理任务（内部/自动清理也走同一路径与保护规则）。binding
// 非空时把再次认证批准的目标摘要写入任务载荷，执行时据此校验删除范围。
func (s *Service) enqueueCleanupJob(ctx context.Context, actor audit.Actor,
	origin Origin, requestID string, binding jobPayload) (task.Job, error) {
	binding.Origin = string(origin)
	binding.RetentionVersion = s.currentRetentionVersion(ctx)
	payload, err := encodeJobPayload(binding)
	if err != nil {
		return task.Job{}, err
	}
	job, err := s.opts.Enqueuer.Enqueue(ctx, task.EnqueueRequest{
		Kind: KindBackupCleanup, Actor: actor, Payload: payload,
		MutexKey: DefaultCleanupMutexKey, TimeoutSeconds: 1800, MaxAttempts: 1,
		PermissionRequired: true, RequestID: normalizeRequestID(requestID),
	})
	if err != nil {
		return task.Job{}, mapTaskError(err)
	}
	s.registerJob(ctx, job, origin, "", actor)
	return job, nil
}

// maybeAutoCleanup 在成功备份后按当前策略检查是否需要清理；需要时提交系统清理
// 任务。策略错误或入队失败只告警，不影响已发布备份。
func (s *Service) maybeAutoCleanup(ctx context.Context) {
	plan, err := s.buildCleanupPlan(ctx, s.now())
	if err != nil || len(plan.targets) == 0 {
		return
	}
	systemActor := audit.Actor{Type: audit.ActorSystem, ID: "backup_scheduler"}
	if _, err := s.enqueueCleanupJob(ctx, systemActor, OriginSystem, "",
		jobPayload{}); err != nil {
		s.logger.Warn("自动清理任务提交失败", "reason", safeToken(fmt.Sprint(CodeOf(err))))
	}
}
