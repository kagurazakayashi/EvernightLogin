package auditops

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// 清理运行状态枚举（与 migrations/0040 的 CHECK 约束一致）。
const (
	PurgeQueued    = "queued"
	PurgeRunning   = "running"
	PurgeSucceeded = "succeeded"
	PurgeFailed    = "failed"
	PurgeCancelled = "cancelled"
)

func validPurgeState(state string) bool {
	switch state {
	case PurgeQueued, PurgeRunning, PurgeSucceeded, PurgeFailed, PurgeCancelled:
		return true
	default:
		return false
	}
}

// SetRetentionRequest 是 root 设置保留策略请求；ExpectedVersion 做乐观并发，
// 0 表示首次设置。
type SetRetentionRequest struct {
	Caller          account.Caller
	RetentionDays   int
	Reason          string
	RequestID       string
	ExpectedVersion int64
}

// PurgePreviewRequest 是只读清理预估请求；它不删除任何记录。
type PurgePreviewRequest struct {
	Caller     account.Caller
	ScopeID    string
	Cutoff     time.Time
	BatchSize  int
	MaxRecords int
	RequestID  string
}

// PurgePreview 是清理预估结果：真实计数/截断标记、保留期边界、受保护范围与
// 供提交时复核的参数摘要。预估不是删除结果。
type PurgePreview struct {
	ScopeID    string
	ScopeKind  string
	Cutoff     time.Time
	BatchSize  int
	MaxRecords int
	// EstimatedCount 是预估条数；AtLeast 表示达到上限后截断，不是精确总数。
	EstimatedCount int64
	AtLeast        bool
	Retention      RetentionInfo
	// WithinRetention 表示截止时间落在保留期内（仍在保留期内的记录不应清理）。
	WithinRetention bool
	// MaintenanceProtected 表示本次清理自身的运行与受保护清理审计不受影响。
	MaintenanceProtected bool
	// ArtifactsIncluded 表示是否包含导出/报告/备份产物；恒为 false。
	ArtifactsIncluded bool
	// Digest 绑定范围、时间、上限、预估与保留策略版本，提交时必须原样带回。
	Digest      string
	GeneratedAt time.Time
}

// StartPurgeRequest 是提交清理任务请求。Digest 来自同参数的 PurgePreview，
// 参数或数据变化时服务端拒绝并要求重新预估。
type StartPurgeRequest struct {
	Caller     account.Caller
	ScopeID    string
	Cutoff     time.Time
	BatchSize  int
	MaxRecords int
	Reason     string
	Digest     string
	RequestID  string
}

// PurgeRunView 是清理运行视图（真实任务状态摘要 + 真实计数）。
type PurgeRunView struct {
	ID            string
	Kind          string
	ScopeID       string
	ScopeKind     string
	State         string
	TaskID        string
	RequestedBy   audit.Actor
	Cutoff        time.Time
	BatchSize     int
	MaxRecords    int
	Scanned       int
	Cleaned       int
	Skipped       int
	Failed        int
	Batches       int
	LimitReached  bool
	ErrorCode     string
	FailureReason string
	RequestID     string
	// ExecutorID 是真实执行清理任务的任务执行器标识。
	ExecutorID string
	CreatedAt  time.Time
	StartedAt  time.Time
	FinishedAt time.Time
	Task       *TaskSummary
}

// PurgeListRequest 是清理运行列表请求。
type PurgeListRequest struct {
	Caller account.Caller
	Kind   string
	State  string
	Limit  int
	Offset int
}

// SetRetention 设置保留策略：仅 root，要求 audit.purge 敏感策略校验；版本 CAS
// 防止旧页面覆盖新策略；受保护清理日志与审计事件同事务写入。
func (s *Service) SetRetention(ctx context.Context, request SetRetentionRequest) (RetentionInfo, error) {
	return s.setRetentionInternal(ctx, request, false)
}

// setRetentionInternal 是 SetRetention 实现；skipGuard 仅供本地维护控制台显式
// 窄方法使用（不要求 root/近期强认证，但仍写受保护清理日志与审计，危险动作需
// 维护锁由调用方写门保证）。
func (s *Service) setRetentionInternal(ctx context.Context, request SetRetentionRequest,
	skipGuard bool) (RetentionInfo, error) {
	if !skipGuard {
		if err := s.requireRoot(ctx, request.Caller); err != nil {
			return RetentionInfo{}, err
		}
	}
	if request.RetentionDays < 1 || request.RetentionDays > MaxRetentionDays {
		return RetentionInfo{}, fmt.Errorf("%w: 保留天数必须在 1～%d 之间", ErrInvalidRequest, MaxRetentionDays)
	}
	if err := validateReason(request.Reason); err != nil {
		return RetentionInfo{}, err
	}
	if request.ExpectedVersion < 0 {
		return RetentionInfo{}, fmt.Errorf("%w: 期望版本号无效", ErrInvalidRequest)
	}
	current, found, err := s.opts.Store.GetRetention(ctx)
	if err != nil {
		return RetentionInfo{}, storeError(err)
	}
	currentVersion := int64(0)
	if found {
		currentVersion = current.Version
	}
	if request.ExpectedVersion != currentVersion {
		return RetentionInfo{}, ErrConflict
	}
	var sensitiveResult reauth.Result
	if !skipGuard {
		var sensitiveErr error
		sensitiveResult, sensitiveErr = s.authorizeSensitive(ctx, request.Caller, OperationPurge, ScopeSystem,
			"audit_retention", ScopeSystem,
			map[string]string{"retention_days": fmt.Sprintf("%d", request.RetentionDays),
				"expected_version": fmt.Sprintf("%d", request.ExpectedVersion)},
			"修改安全审计保留策略", request.RequestID)
		if sensitiveErr != nil {
			s.recordFailure(ctx, request.Caller.Actor(), ActionRetentionSet, ScopeSystem,
				"retention_reauth_denied", CodeAccessDenied, request.RequestID)
			return RetentionInfo{}, sensitiveErr
		}
	}
	now := s.now()
	record := RetentionRecord{
		RetentionDays: request.RetentionDays, Version: currentVersion + 1,
		UpdatedBy: request.Caller.Actor(), Reason: safeReason(request.Reason), UpdatedAt: now,
	}
	entry := s.maintenanceEntry(request.Caller.Actor(), "", ActionRetentionSet,
		ScopeInfo{ID: ScopeSystem, Kind: "system"}, time.Time{}, 0, 0, 0,
		"persisted", "", request.RequestID, "")
	event := s.auditEvent(request.Caller.Actor(), ScopeInfo{ID: ScopeSystem, Kind: "system"},
		ActionRetentionSet, "audit_retention", ScopeSystem, audit.OutcomeSuccess, "",
		request.RequestID, "")
	event.Changes = []audit.FieldChange{
		{Field: "retention_days", Before: fmt.Sprintf("%d", current.RetentionDays),
			After: fmt.Sprintf("%d", request.RetentionDays)},
	}
	written, err := s.opts.Store.SetRetention(ctx, record, entry, event)
	if err != nil {
		return RetentionInfo{}, storeError(err)
	}
	if !written {
		return RetentionInfo{}, ErrConflict
	}
	if !skipGuard {
		s.notifySensitive(ctx, sensitiveResult)
	}
	return s.retentionInfo(ctx)
}

// PreviewPurge 生成只读清理预估（root）：真实计数/截断、保留期边界与参数摘要。
// 它不删除记录，并记录一次成功审计便于追踪“谁在何时预估了什么范围”。
func (s *Service) PreviewPurge(ctx context.Context, request PurgePreviewRequest) (PurgePreview, error) {
	return s.previewPurgeInternal(ctx, request, false)
}

// previewPurgeInternal 是 PreviewPurge 实现；skipGuard 仅供本地维护控制台使用。
func (s *Service) previewPurgeInternal(ctx context.Context, request PurgePreviewRequest,
	skipGuard bool) (PurgePreview, error) {
	if !skipGuard {
		if err := s.requireRoot(ctx, request.Caller); err != nil {
			return PurgePreview{}, err
		}
	}
	scope, cutoff, batchSize, maxRecords, err := s.normalizePurgeRequest(request.ScopeID,
		request.Cutoff, request.BatchSize, request.MaxRecords)
	if err != nil {
		return PurgePreview{}, err
	}
	retention, err := s.retentionInfo(ctx)
	if err != nil {
		return PurgePreview{}, err
	}
	if err := requireBeyondRetention(cutoff, retention); err != nil {
		return PurgePreview{}, err
	}
	_, count, capped, err := s.purgeEstimate(ctx, scope, cutoff, maxRecords)
	if err != nil {
		return PurgePreview{}, err
	}
	digest := purgeDigest(scope, cutoff, batchSize, maxRecords, count, capped, retention.Version)
	now := s.now()
	preview := PurgePreview{
		ScopeID: scope.ID, ScopeKind: scope.Kind, Cutoff: cutoff,
		BatchSize: batchSize, MaxRecords: maxRecords,
		EstimatedCount: count, AtLeast: capped, Retention: retention,
		WithinRetention:      cutoff.After(retention.Cutoff),
		MaintenanceProtected: true, ArtifactsIncluded: false,
		Digest: digest, GeneratedAt: now,
	}
	event := s.auditEvent(request.Caller.Actor(), scope, ActionPurgePreview,
		"audit_retention", scope.ID, audit.OutcomeSuccess, "", request.RequestID, "")
	event.Changes = []audit.FieldChange{
		{Field: "cutoff", After: cutoff.UTC().Format(time.RFC3339)},
		{Field: "estimated_count", After: fmt.Sprintf("%d", count)},
	}
	if err := s.opts.Audit.Record(ctx, event); err != nil {
		s.opts.Logger.Warn("清理预估审计写入失败", "code", string(CodeAuditWriteFailed))
	}
	return preview, nil
}

// purgeEstimate 复用与清理相同的范围与截至时间计算预估条数。
func (s *Service) purgeEstimate(ctx context.Context, scope ScopeInfo, cutoff time.Time,
	maxRecords int) (queryScope, int64, bool, error) {
	constraint := purgeConstraint(scope)
	filter := Filter{To: cutoff}
	if scope.Kind == "system" {
		filter.SystemOnly = true
	} else {
		filter.AppID = scope.ID
	}
	result, err := s.opts.Store.CountEvents(ctx, EventQuery{
		Filter: filter, AllData: constraint.allData, AppIDs: constraint.appIDs,
		IncludeSystem: constraint.includeSystem, Limit: 0, Offset: 0,
	}, int64(maxRecords)+1)
	if err != nil {
		return queryScope{}, 0, false, storeError(err)
	}
	capped := result.Capped || result.Count > int64(maxRecords)
	if result.Count > int64(maxRecords) {
		result.Count = int64(maxRecords)
	}
	return constraint, result.Count, capped, nil
}

// StartPurge 提交 root 手动清理任务：root + audit.purge 敏感策略 + 预估摘要
// 复核 + 异步任务；保存请求、执行者、范围、截止时间与上限。
func (s *Service) StartPurge(ctx context.Context, request StartPurgeRequest) (PurgeRunView, error) {
	return s.startPurgeInternal(ctx, request, false)
}

// startPurgeInternal 是 StartPurge 实现；skipGuard 仅供本地维护控制台使用。
func (s *Service) startPurgeInternal(ctx context.Context, request StartPurgeRequest,
	skipGuard bool) (PurgeRunView, error) {
	if !skipGuard {
		if err := s.requireRoot(ctx, request.Caller); err != nil {
			return PurgeRunView{}, err
		}
	}
	scope, cutoff, batchSize, maxRecords, err := s.normalizePurgeRequest(request.ScopeID,
		request.Cutoff, request.BatchSize, request.MaxRecords)
	if err != nil {
		return PurgeRunView{}, err
	}
	if err := validateReason(request.Reason); err != nil {
		return PurgeRunView{}, err
	}
	if request.Digest == "" {
		return PurgeRunView{}, fmt.Errorf("%w: 缺少预估摘要，请重新预估", ErrInvalidRequest)
	}
	retention, err := s.retentionInfo(ctx)
	if err != nil {
		return PurgeRunView{}, err
	}
	if err := requireBeyondRetention(cutoff, retention); err != nil {
		s.recordFailure(ctx, request.Caller.Actor(), ActionPurgeRequest, scope.ID,
			"purge_within_retention", CodeAccessDenied, request.RequestID)
		return PurgeRunView{}, err
	}
	_, count, capped, err := s.purgeEstimate(ctx, scope, cutoff, maxRecords)
	if err != nil {
		return PurgeRunView{}, err
	}
	expectedDigest := purgeDigest(scope, cutoff, batchSize, maxRecords, count, capped, retention.Version)
	if expectedDigest != request.Digest {
		return PurgeRunView{}, fmt.Errorf("%w: 预估已过期或参数变化，请重新预估", ErrConflict)
	}
	var sensitiveResult reauth.Result
	if !skipGuard {
		var sensitiveErr error
		sensitiveResult, sensitiveErr = s.authorizeSensitive(ctx, request.Caller, OperationPurge, scope.ID,
			"audit_retention", scope.ID,
			map[string]string{"scope": scope.ID, "cutoff": cutoff.UTC().Format(time.RFC3339),
				"batch_size":     fmt.Sprintf("%d", batchSize),
				"max_records":    fmt.Sprintf("%d", maxRecords),
				"preview_digest": request.Digest},
			"清理安全审计记录", request.RequestID)
		if sensitiveErr != nil {
			s.recordFailure(ctx, request.Caller.Actor(), ActionPurgeRequest, scope.ID,
				"purge_reauth_denied", CodeAccessDenied, request.RequestID)
			return PurgeRunView{}, sensitiveErr
		}
	}
	runID, err := s.newID(purgeIDPrefix)
	if err != nil {
		return PurgeRunView{}, err
	}
	now := s.now()
	record := PurgeRunRecord{
		ID: runID, Kind: "manual", ScopeKind: scope.Kind, ScopeID: scope.ID,
		RequestedBy: request.Caller.Actor(), Cutoff: cutoff, BatchSize: batchSize,
		MaxRecords: maxRecords, State: PurgeQueued, RequestID: request.RequestID,
		CreatedAt: now,
	}
	entry := s.maintenanceEntry(request.Caller.Actor(), runID, ActionPurgeRequest,
		scope, cutoff, 0, 0, 0, "accepted", "", request.RequestID, "")
	event := s.auditEvent(request.Caller.Actor(), scope, ActionPurgeRequest,
		"audit_retention", runID, audit.OutcomeSuccess, "", request.RequestID, "")
	event.Changes = []audit.FieldChange{
		{Field: "cutoff", After: cutoff.UTC().Format(time.RFC3339)},
		{Field: "batch_size", After: fmt.Sprintf("%d", batchSize)},
		{Field: "max_records", After: fmt.Sprintf("%d", maxRecords)},
	}
	if err := s.opts.Store.CreatePurgeRun(ctx, record, entry, event); err != nil {
		return PurgeRunView{}, storeError(err)
	}
	job, err := s.enqueue(ctx, TaskKindAuditPurge, request.Caller.Actor(), request.RequestID,
		map[string]string{"run_id": runID}, purgeTaskTimeoutSeconds)
	if err != nil {
		s.finishPurgeFailure(ctx, record, CodeDBUnavailable, "purge_enqueue_failed")
		return PurgeRunView{}, err
	}
	if err := s.opts.Store.SetPurgeTask(ctx, runID, job.ID, s.now()); err != nil {
		s.finishPurgeFailure(ctx, record, CodeDBUnavailable, "purge_task_bind_failed")
		return PurgeRunView{}, storeError(err)
	}
	record.TaskID = job.ID
	view, err := s.purgeView(ctx, record)
	if err != nil {
		return PurgeRunView{}, err
	}
	if !skipGuard {
		s.notifySensitive(ctx, sensitiveResult)
	}
	return view, nil
}

// PurgeHandler 是注册到 internal/task 的清理处理器：每批删除一批事件，累计计数并
// 写受保护清理日志；可被任务取消/墙钟期限中止；预估与执行均由服务端重新校验。
func (s *Service) PurgeHandler(ctx context.Context, job task.Job) error {
	if job.Kind != TaskKindAuditPurge {
		return fmt.Errorf("%w: 任务类型不匹配", ErrInvalidRequest)
	}
	runID, err := payloadPurgeID(job.Payload)
	if err != nil {
		return err
	}
	record, found, err := s.opts.Store.GetPurgeRun(ctx, runID)
	if err != nil {
		return storeError(err)
	}
	if !found {
		return ErrNotFound
	}
	if record.RequestedBy != job.Initiator {
		return ErrAccessDenied
	}
	if record.State != PurgeQueued && record.State != PurgeRunning {
		return ErrTaskTerminal
	}
	started, err := s.opts.Store.StartPurgeRun(ctx, runID, job.ExecutorID, s.now())
	if err != nil {
		return storeError(err)
	}
	if !started && record.State != PurgeRunning {
		return ErrConflict
	}
	record.State = PurgeRunning
	caller, err := callerFromActor(record.RequestedBy)
	if err != nil {
		return s.finishPurge(ctx, record, PurgeFailed, CodeAccessDenied,
			"requested_by_invalid", 0, 0, 0, false)
	}
	if s.requireRoot(ctx, caller) != nil {
		return s.finishPurge(ctx, record, PurgeFailed, CodeAccessDenied,
			"root_required", 0, 0, 0, false)
	}
	scope := ScopeInfo{ID: record.ScopeID, Kind: record.ScopeKind}
	cleaned, scanned, batches, limitReached := 0, 0, 0, false
	for cleaned < record.MaxRecords {
		if err := ctx.Err(); err != nil {
			return s.finishPurge(ctx, record, PurgeCancelled, CodeTaskCancelled,
				"task_cancelled", cleaned, scanned, batches, false)
		}
		remaining := record.MaxRecords - cleaned
		batchSize := record.BatchSize
		if remaining < batchSize {
			batchSize = remaining
		}
		result, err := s.opts.Store.PurgeBatch(ctx, PurgeBatchCommand{
			RunID: record.ID, ScopeKind: record.ScopeKind, ScopeID: record.ScopeID,
			Cutoff: record.Cutoff, BatchSize: batchSize, BatchIndex: batches,
			Remaining: remaining, Actor: record.RequestedBy,
			RequestID: record.RequestID, TaskID: record.TaskID, Now: s.now(),
		})
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return s.finishPurge(ctx, record, PurgeCancelled, CodeTaskCancelled,
					"task_cancelled", cleaned, scanned, batches, false)
			}
			return s.finishPurge(ctx, record, PurgeFailed, CodeDBUnavailable,
				"purge_batch_failed", cleaned, scanned, batches, false)
		}
		cleaned += result.Cleaned
		scanned += result.Scanned
		batches++
		if result.Cleaned < batchSize {
			break
		}
	}
	if cleaned >= record.MaxRecords {
		_, remainingCount, _, countErr := s.purgeEstimate(ctx, scope, record.Cutoff, 1)
		if countErr == nil && remainingCount > 0 {
			limitReached = true
		}
	}
	return s.finishPurge(ctx, record, PurgeSucceeded, "", "", cleaned, scanned,
		batches, limitReached)
}

// GetPurgeRun 读取清理运行；仅 root。
func (s *Service) GetPurgeRun(ctx context.Context, caller account.Caller,
	runID string) (PurgeRunView, error) {
	return s.getPurgeRunInternal(ctx, caller, runID, false)
}

// getPurgeRunInternal 是 GetPurgeRun 实现；skipGuard 仅供本地维护控制台使用。
func (s *Service) getPurgeRunInternal(ctx context.Context, caller account.Caller,
	runID string, skipGuard bool) (PurgeRunView, error) {
	if !skipGuard {
		if err := s.requireRoot(ctx, caller); err != nil {
			return PurgeRunView{}, err
		}
	}
	if !validPurgeID(runID) {
		return PurgeRunView{}, fmt.Errorf("%w: 清理编号格式无效", ErrInvalidRequest)
	}
	record, found, err := s.opts.Store.GetPurgeRun(ctx, runID)
	if err != nil {
		return PurgeRunView{}, storeError(err)
	}
	if !found {
		return PurgeRunView{}, ErrNotFound
	}
	return s.purgeView(ctx, record)
}

// ListPurgeRuns 列出清理运行；仅 root。
func (s *Service) ListPurgeRuns(ctx context.Context, request PurgeListRequest) ([]PurgeRunView, bool, error) {
	return s.listPurgeRunsInternal(ctx, request, false)
}

// listPurgeRunsInternal 是 ListPurgeRuns 实现；skipGuard 仅供本地维护控制台使用。
func (s *Service) listPurgeRunsInternal(ctx context.Context, request PurgeListRequest,
	skipGuard bool) ([]PurgeRunView, bool, error) {
	if !skipGuard {
		if err := s.requireRoot(ctx, request.Caller); err != nil {
			return nil, false, err
		}
	}
	if request.Kind != "" && request.Kind != "manual" && request.Kind != "policy" {
		return nil, false, fmt.Errorf("%w: 清理类型未知", ErrInvalidRequest)
	}
	if request.State != "" && !validPurgeState(request.State) {
		return nil, false, fmt.Errorf("%w: 清理状态未知", ErrInvalidRequest)
	}
	limit := request.Limit
	if limit == 0 {
		limit = DefaultLimit
	}
	if limit < 1 || limit > MaxExportListLimit {
		return nil, false, fmt.Errorf("%w: 每页条数超出范围", ErrInvalidRequest)
	}
	if request.Offset < 0 || request.Offset > MaxOffset {
		return nil, false, fmt.Errorf("%w: 分页偏移超出范围", ErrInvalidRequest)
	}
	records, err := s.opts.Store.ListPurgeRuns(ctx, PurgeListQuery{
		Kind: request.Kind, State: request.State, Limit: limit + 1, Offset: request.Offset})
	if err != nil {
		return nil, false, storeError(err)
	}
	hasMore := len(records) > limit
	views := make([]PurgeRunView, 0, limit)
	for _, record := range records {
		view, viewErr := s.purgeView(ctx, record)
		if viewErr != nil {
			return nil, false, viewErr
		}
		views = append(views, view)
		if len(views) == limit {
			break
		}
	}
	return views, hasMore, nil
}

// CancelPurge 请求取消清理任务；提交取消请求不等于实际取消，真实终态以任务与
// 运行状态为准。取消请求本身写入受保护清理日志以便追踪。
func (s *Service) CancelPurge(ctx context.Context, caller account.Caller, runID,
	reason, requestID string) (task.CancelResult, error) {
	return s.cancelPurgeInternal(ctx, caller, runID, reason, requestID, false)
}

// cancelPurgeInternal 是 CancelPurge 实现；skipGuard 仅供本地维护控制台使用。
func (s *Service) cancelPurgeInternal(ctx context.Context, caller account.Caller, runID,
	reason, requestID string, skipGuard bool) (task.CancelResult, error) {
	if !skipGuard {
		if err := s.requireRoot(ctx, caller); err != nil {
			return task.CancelResult{}, err
		}
	}
	if !validPurgeID(runID) {
		return task.CancelResult{}, fmt.Errorf("%w: 清理编号格式无效", ErrInvalidRequest)
	}
	if err := validateReason(reason); err != nil {
		return task.CancelResult{}, err
	}
	record, found, err := s.opts.Store.GetPurgeRun(ctx, runID)
	if err != nil {
		return task.CancelResult{}, storeError(err)
	}
	if !found {
		return task.CancelResult{}, ErrNotFound
	}
	if record.TaskID == "" {
		return task.CancelResult{}, fmt.Errorf("%w: 清理任务尚未取得任务编号", ErrConflict)
	}
	result, err := s.opts.Canceller.RequestCancel(ctx, task.CancelRequest{
		JobID: record.TaskID, Actor: caller.Actor(), Reason: reason, RequestID: requestID,
	})
	if err != nil {
		if errors.Is(err, task.ErrTaskTerminal) {
			return task.CancelResult{}, fmt.Errorf("%w: %w", ErrTaskTerminal, err)
		}
		return task.CancelResult{}, fmt.Errorf("%w: %w", ErrTaskRejected, err)
	}
	if result.State == task.StateCancelled {
		// queued 清理任务被取消时执行器不再调用处理器，必须在此写入真实取消终态，
		// 否则运行记录会永远停在 queued。
		_ = s.finishPurge(ctx, record, PurgeCancelled, CodeTaskCancelled,
			"cancel_effective", record.Cleaned, record.Scanned, record.Batches,
			record.LimitReached)
		return result, nil
	}
	entry := s.maintenanceEntry(caller.Actor(), runID, ActionPurgeCancel,
		ScopeInfo{ID: record.ScopeID, Kind: record.ScopeKind}, record.Cutoff, 0, 0, 0,
		"cancel_requested", "", requestID, record.TaskID)
	if err := s.opts.Store.AppendMaintenanceLog(context.WithoutCancel(ctx), entry); err != nil {
		s.opts.Logger.Warn("清理取消请求受保护日志写入失败", "code", string(CodeAuditWriteFailed))
	}
	return result, nil
}

// MaintenanceLog 读取某次清理的受保护审计记录；仅 root。
func (s *Service) MaintenanceLog(ctx context.Context, caller account.Caller,
	runID string) ([]MaintenanceEntry, error) {
	return s.maintenanceLogInternal(ctx, caller, runID, false)
}

// maintenanceLogInternal 是 MaintenanceLog 实现；skipGuard 仅供本地维护控制台使用。
func (s *Service) maintenanceLogInternal(ctx context.Context, caller account.Caller,
	runID string, skipGuard bool) ([]MaintenanceEntry, error) {
	if !skipGuard {
		if err := s.requireRoot(ctx, caller); err != nil {
			return nil, err
		}
	}
	if !validPurgeID(runID) {
		return nil, fmt.Errorf("%w: 清理编号格式无效", ErrInvalidRequest)
	}
	entries, err := s.opts.Store.MaintenanceLog(ctx, runID)
	if err != nil {
		return nil, storeError(err)
	}
	if entries == nil {
		entries = []MaintenanceEntry{}
	}
	return entries, nil
}

// finishPurge 写入清理终态：终态、计数、审计事件与受保护日志同事务；使用
// 非取消上下文，保证任务被取消/超时后终态仍能可靠落库。
func (s *Service) finishPurge(ctx context.Context, record PurgeRunRecord, state string,
	code ErrorCode, reason string, cleaned, scanned, batchCount int, limitReached bool) error {
	finalCtx := context.WithoutCancel(ctx)
	scope := ScopeInfo{ID: record.ScopeID, Kind: record.ScopeKind}
	entryAction := ActionPurgeFinish
	if state == PurgeCancelled {
		entryAction = ActionPurgeCancel
	}
	entry := s.maintenanceEntry(record.RequestedBy, record.ID, entryAction, scope,
		record.Cutoff, batchCount, cleaned, limitReachedInt(limitReached), state,
		code, record.RequestID, record.TaskID)
	command := PurgeFinishCommand{
		RunID: record.ID, State: state, Scanned: scanned, Cleaned: cleaned,
		Skipped: 0, Failed: 0, Batches: batchCount, LimitReached: limitReached,
		ErrorCode: string(code), FailureReason: safeReason(reason), Now: s.now(),
	}
	outcome := audit.OutcomeSuccess
	if state != PurgeSucceeded {
		outcome = audit.OutcomeFailure
	}
	event := s.auditEvent(record.RequestedBy, scope, ActionPurgeFinish,
		"audit_retention", record.ID, outcome, code, record.RequestID, record.TaskID)
	event.Changes = []audit.FieldChange{
		{Field: "state", After: state},
		{Field: "cleaned", After: fmt.Sprintf("%d", cleaned)},
		{Field: "batches", After: fmt.Sprintf("%d", batchCount)},
	}
	command.Event = event
	command.Entry = &entry
	written, finishErr := s.opts.Store.FinishPurgeRun(finalCtx, command)
	if finishErr != nil {
		// 终态/审计未可靠落库：不得向任务执行器报告成功。
		s.opts.Logger.Error("清理终态写入失败", "code", string(CodeAuditWriteFailed))
		if state == PurgeCancelled {
			return context.Canceled
		}
		return fmt.Errorf("%w: 清理终态未能可靠记录", ErrAuditUnavailable)
	}
	if state == PurgeCancelled {
		return context.Canceled
	}
	if state == PurgeFailed {
		if !written {
			s.opts.Logger.Error("清理失败终态已被其他写入占用", "code", string(CodeConflict))
		}
		return fmt.Errorf("%w: 清理失败", ErrStoreUnavailable)
	}
	if !written {
		return fmt.Errorf("%w: 清理运行已进入其他终态", ErrTaskTerminal)
	}
	return nil
}

// finishPurgeFailure 在入队/绑定失败时把运行写为失败，避免“已受理但无任务”。
func (s *Service) finishPurgeFailure(ctx context.Context, record PurgeRunRecord,
	code ErrorCode, reason string) {
	entry := s.maintenanceEntry(record.RequestedBy, record.ID, ActionPurgeFinish,
		ScopeInfo{ID: record.ScopeID, Kind: record.ScopeKind}, record.Cutoff, 0, 0, 0,
		PurgeFailed, code, record.RequestID, record.TaskID)
	command := PurgeFinishCommand{RunID: record.ID, State: PurgeFailed,
		ErrorCode: string(code), FailureReason: safeReason(reason), Now: s.now()}
	event := s.auditEvent(record.RequestedBy, ScopeInfo{ID: record.ScopeID,
		Kind: record.ScopeKind}, ActionPurgeFinish, "audit_retention", record.ID,
		audit.OutcomeFailure, code, record.RequestID, record.TaskID)
	command.Event = event
	command.Entry = &entry
	if _, err := s.opts.Store.FinishPurgeRun(context.WithoutCancel(ctx), command); err != nil {
		s.opts.Logger.Error("清理失败状态写入失败", "code", string(CodeAuditWriteFailed))
	}
}

// purgeView 构造清理运行视图，附带真实任务状态摘要。
func (s *Service) purgeView(ctx context.Context, record PurgeRunRecord) (PurgeRunView, error) {
	view := PurgeRunView{
		ID: record.ID, Kind: record.Kind, ScopeID: record.ScopeID,
		ScopeKind: record.ScopeKind, State: record.State, TaskID: record.TaskID,
		RequestedBy: record.RequestedBy, Cutoff: record.Cutoff,
		BatchSize: record.BatchSize, MaxRecords: record.MaxRecords,
		Scanned: record.Scanned, Cleaned: record.Cleaned, Skipped: record.Skipped,
		Failed: record.Failed, Batches: record.Batches,
		LimitReached: record.LimitReached, ErrorCode: record.ErrorCode,
		FailureReason: record.FailureReason, RequestID: record.RequestID,
		ExecutorID: record.ExecutorID, CreatedAt: record.CreatedAt,
		StartedAt:  record.StartedAt,
		FinishedAt: record.FinishedAt,
	}
	if s.opts.Tasks != nil && record.TaskID != "" {
		job, found, err := s.opts.Tasks.Get(ctx, record.TaskID)
		if err != nil {
			return PurgeRunView{}, storeError(err)
		}
		if found {
			view.Task = &TaskSummary{ID: job.ID, Kind: job.Kind, State: string(job.State),
				Initiator: job.Initiator, ExecutorID: job.ExecutorID,
				Attempt: job.Attempt, MaxAttempts: job.MaxAttempts,
				ErrorCode: job.ErrorCode, FailureReason: job.FailureReason,
				RequestID: job.RequestID, CreatedAt: job.CreatedAt,
				StartedAt: job.StartedAt, FinishedAt: job.FinishedAt}
		}
	}
	return view, nil
}

// requireBeyondRetention 强制手动清理只能处理保留期边界之前的数据：保留期内的
// 记录必须通过版本化的保留策略调整（可审计）而不能借一次清理悄悄抹除。
func requireBeyondRetention(cutoff time.Time, retention RetentionInfo) error {
	if !retention.Cutoff.IsZero() && cutoff.After(retention.Cutoff) {
		return fmt.Errorf("%w: 清理截止时间不能晚于保留期边界", ErrInvalidRequest)
	}
	return nil
}

// normalizePurgeRequest 校验并规范化清理范围/截止时间/批大小/条数上限。
func (s *Service) normalizePurgeRequest(rawScope string, cutoff time.Time, batchSize,
	maxRecords int) (ScopeInfo, time.Time, int, int, error) {
	scope, err := parseScope(rawScope)
	if err != nil {
		return ScopeInfo{}, time.Time{}, 0, 0, err
	}
	now := s.now()
	cutoff = cutoff.UTC().Truncate(time.Millisecond)
	if cutoff.IsZero() {
		return ScopeInfo{}, time.Time{}, 0, 0,
			fmt.Errorf("%w: 清理截止时间不能为空", ErrInvalidRequest)
	}
	if cutoff.After(now) {
		return ScopeInfo{}, time.Time{}, 0, 0,
			fmt.Errorf("%w: 清理截止时间不能在未来", ErrInvalidRequest)
	}
	if cutoff.Before(time.UnixMilli(1).UTC()) {
		return ScopeInfo{}, time.Time{}, 0, 0,
			fmt.Errorf("%w: 清理截止时间无效", ErrInvalidRequest)
	}
	if batchSize == 0 {
		batchSize = s.maxBatchSize
	}
	if batchSize < 1 || batchSize > s.maxBatchSize {
		return ScopeInfo{}, time.Time{}, 0, 0,
			fmt.Errorf("%w: 批大小必须在 1～%d 之间", ErrInvalidRequest, s.maxBatchSize)
	}
	if maxRecords == 0 {
		maxRecords = s.maxPurgeRecords
	}
	if maxRecords < 1 || maxRecords > s.maxPurgeRecords {
		return ScopeInfo{}, time.Time{}, 0, 0,
			fmt.Errorf("%w: 清理条数上限必须在 1～%d 之间", ErrInvalidRequest, s.maxPurgeRecords)
	}
	return scope, cutoff, batchSize, maxRecords, nil
}

// purgeConstraint 返回清理范围约束：系统范围只清无应用快照事件，应用范围只清
// 该应用快照事件；与查询使用同一数据范围语义，且不包含“全部应用”。
func purgeConstraint(scope ScopeInfo) queryScope {
	if scope.Kind == "app" {
		return queryScope{kind: "app", scopeID: scope.ID, appIDs: []string{scope.ID}}
	}
	return queryScope{kind: "system", scopeID: ScopeSystem, includeSystem: true}
}

// purgeDigest 计算清理参数摘要，绑定范围、截止时间、上限、预估条数与保留策略版本。
func purgeDigest(scope ScopeInfo, cutoff time.Time, batchSize, maxRecords int,
	count int64, capped bool, retentionVersion int64) string {
	document := fmt.Sprintf("scope=%s:%s;cutoff=%d;batch=%d;max=%d;count=%d;capped=%t;retention=%d",
		scope.Kind, scope.ID, cutoff.UTC().UnixMilli(), batchSize, maxRecords,
		count, capped, retentionVersion)
	return digestString(document)
}

// maintenanceEntry 构造受保护清理日志条目。
func (s *Service) maintenanceEntry(actor audit.Actor, runID, action string,
	scope ScopeInfo, cutoff time.Time, batchIndex, scanned, cleaned int, result string,
	code ErrorCode, requestID, taskID string) MaintenanceEntry {
	entry := MaintenanceEntry{
		ID: "", RunID: runID, OccurredAt: s.now(), Action: action, Actor: actor,
		ScopeKind: scope.Kind, ScopeID: scope.ID, BatchIndex: batchIndex,
		Scanned: scanned, Cleaned: cleaned, Result: result,
		ErrorCode: string(code), RequestID: requestID, TaskID: taskID,
	}
	if !cutoff.IsZero() {
		entry.Cutoff = cutoff
	}
	return entry
}

// auditEvent 构造审计事件（调用方按需补充 Changes）。
func (s *Service) auditEvent(actor audit.Actor, scope ScopeInfo, action, targetType,
	targetID string, outcome audit.Outcome, code ErrorCode, requestID, taskID string) audit.Event {
	return audit.Event{
		Actor: actor, AppID: appIDForScope(scope.ID), Action: action,
		Target:  audit.Target{Type: targetType, ID: targetID},
		Outcome: outcome, ErrorCode: string(code), RequestID: requestID, TaskID: taskID,
	}
}

// limitReachedInt 把布尔值转为 0/1 计数。
func limitReachedInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
