package auditops

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// ExportFormat 是导出产物格式；第一版只支持 CSV 与 JSON（不使用外部依赖）。
type ExportFormat string

const (
	// FormatCSV 是 CSV 导出（UTF-8、防公式注入）。
	FormatCSV ExportFormat = "csv"
	// FormatJSON 是 JSON 导出（数组、UTF-8）。
	FormatJSON ExportFormat = "json"
)

// Valid 报告导出格式是否已定义。
func (f ExportFormat) Valid() bool {
	return f == FormatCSV || f == FormatJSON
}

// 导出状态枚举（与 migrations/0040 的 CHECK 约束一致）。
const (
	ExportQueued    = "queued"
	ExportRunning   = "running"
	ExportSucceeded = "succeeded"
	ExportFailed    = "failed"
	ExportCancelled = "cancelled"
)

func validExportState(state string) bool {
	switch state {
	case ExportQueued, ExportRunning, ExportSucceeded, ExportFailed, ExportCancelled:
		return true
	default:
		return false
	}
}

// exportFilterSnapshot 是导出任务的不可变筛选快照。创建后列表变化、权限变化都
// 不改变本快照语义；执行与下载时仍按当前权限复核。
type exportFilterSnapshot struct {
	Version     int        `json:"v"`
	ScopeKind   string     `json:"scope_kind"`
	ScopeID     string     `json:"scope_id"`
	Order       SortOrder  `json:"order"`
	Filter      filterJSON `json:"filter"`
	RequestTime time.Time  `json:"request_time"`
}

// filterJSON 是 Filter 的可序列化稳定表示（时间用 UTC 毫秒，空值省略）。
type filterJSON struct {
	FromMs     int64  `json:"from_ms,omitempty"`
	ToMs       int64  `json:"to_ms,omitempty"`
	AppID      string `json:"app_id,omitempty"`
	SystemOnly bool   `json:"system_only,omitempty"`
	ActorType  string `json:"actor_type,omitempty"`
	ActorID    string `json:"actor_id,omitempty"`
	Action     string `json:"action,omitempty"`
	Outcome    string `json:"outcome,omitempty"`
	ErrorCode  string `json:"error_code,omitempty"`
	RequestID  string `json:"request_id,omitempty"`
	TaskID     string `json:"task_id,omitempty"`
	TargetType string `json:"target_type,omitempty"`
	TargetID   string `json:"target_id,omitempty"`
}

// dataScopeSnapshot 是导出创建时的数据范围快照，用于下载时判断当前权限是否仍
// 覆盖当时导出的范围（权限收缩后不因曾有权限而永久可下载）。
type dataScopeSnapshot struct {
	All       bool     `json:"all"`
	Resources []string `json:"resources,omitempty"`
}

// StartExportRequest 是创建审计导出任务请求。导出是独立授权动作，不复用
// audit.read 权限。
type StartExportRequest struct {
	Caller    account.Caller
	ScopeID   string
	Filter    Filter
	Order     SortOrder
	Format    ExportFormat
	MaxRows   int
	RequestID string
}

// ExportView 是导出任务视图，不包含宿主文件路径、审计正文或秘密。
type ExportView struct {
	ID            string
	ScopeID       string
	ScopeKind     string
	Format        ExportFormat
	State         string
	RequestedBy   audit.Actor
	MaxRows       int
	RowCount      int
	Truncated     bool
	TaskID        string
	FileAvailable bool
	FileExpiresAt time.Time
	ErrorCode     string
	FailureReason string
	RequestID     string
	// ExecutorID 是真实执行导出任务的任务执行器标识。
	ExecutorID string
	CreatedAt  time.Time
	StartedAt  time.Time
	FinishedAt time.Time
	Task       *TaskSummary
}

// ExportListRequest 是导出任务列表请求。
type ExportListRequest struct {
	Caller  account.Caller
	ScopeID string
	State   string
	Limit   int
	Offset  int
}

// ExportFile 是宿主下载适配使用的受控产物句柄。HostPath 只能交给宿主文件流，
// 禁止写入页面、日志、错误或 API 响应。
type ExportFile struct {
	ID        string
	HostPath  string
	Format    ExportFormat
	Size      int64
	SHA256    string
	RowCount  int
	Truncated bool
	ExpiresAt time.Time
}

// TaskSummary 是异步任务真实状态摘要（来自 internal/task，不伪造进度）。
type TaskSummary struct {
	ID            string
	Kind          string
	State         string
	Initiator     audit.Actor
	ExecutorID    string
	Attempt       int
	MaxAttempts   int
	ErrorCode     string
	FailureReason string
	RequestID     string
	CreatedAt     time.Time
	StartedAt     time.Time
	FinishedAt    time.Time
}

// StartExport 创建异步审计导出任务：独立 audit.export 授权 + 敏感操作校验 +
// 筛选/数据范围快照 + 入队 internal/task。提交成功只表示任务已受理。
func (s *Service) StartExport(ctx context.Context, request StartExportRequest) (ExportView, error) {
	caller := request.Caller
	actor := caller.Actor()
	if err := actor.Validate(); err != nil {
		return ExportView{}, ErrAccessDenied
	}
	scope, err := parseScope(request.ScopeID)
	if err != nil {
		return ExportView{}, err
	}
	grant, err := s.authorizeScope(ctx, caller, PermissionExport, scope.ID)
	if err != nil {
		s.recordFailure(ctx, actor, ActionExportRequest, scope.ID, "export_not_authorized",
			CodeAccessDenied, request.RequestID)
		return ExportView{}, err
	}
	constraint, err := scopeConstraint(scope, grant)
	if err != nil {
		return ExportView{}, err
	}
	format := request.Format
	if !format.Valid() {
		return ExportView{}, fmt.Errorf("%w: 导出格式只支持 csv 或 json", ErrInvalidRequest)
	}
	order, err := normalizeOrder(request.Order, SortNewestFirst)
	if err != nil {
		return ExportView{}, err
	}
	if err := s.validateFilter(request.Filter, constraint); err != nil {
		return ExportView{}, err
	}
	maxRows := request.MaxRows
	if maxRows == 0 {
		maxRows = s.maxExportRows
	}
	if maxRows < 1 || maxRows > s.maxExportRows {
		return ExportView{}, fmt.Errorf("%w: 导出行数上限必须在 1～%d 之间", ErrInvalidRequest, s.maxExportRows)
	}
	snapshot, dataScope, err := encodeExportSnapshot(scope, request.Filter, order, constraint, s.now())
	if err != nil {
		return ExportView{}, err
	}
	sensitiveResult, err := s.authorizeSensitive(ctx, caller, OperationExport, scope.ID,
		"audit_export", scope.ID,
		map[string]string{"scope": scope.ID, "format": string(format),
			"max_rows": fmt.Sprintf("%d", maxRows),
			"filter_digest": reauth.ParamsDigestHex(map[string]string{
				"filter": digestString(snapshot), "scope": scope.ID})},
		"导出安全审计记录", request.RequestID)
	if err != nil {
		s.recordFailure(ctx, actor, ActionExportRequest, scope.ID, "export_reauth_denied",
			CodeAccessDenied, request.RequestID)
		return ExportView{}, err
	}
	exportID, err := s.newID(exportIDPrefix)
	if err != nil {
		return ExportView{}, err
	}
	now := s.now()
	record := ExportRecord{
		ID: exportID, ScopeKind: scope.Kind, ScopeID: scope.ID, RequestedBy: actor,
		FilterJSON: snapshot, DataScopeJSON: dataScope, Format: string(format),
		MaxRows: maxRows, State: ExportQueued, RequestID: request.RequestID,
		CreatedAt: now, ExpiresAt: now.Add(defaultExportTTL),
	}
	event := s.auditEvent(actor, scope, ActionExportRequest, "audit_export", exportID,
		audit.OutcomeSuccess, "", request.RequestID, "")
	if err := s.opts.Store.CreateExport(ctx, record, event); err != nil {
		return ExportView{}, storeError(err)
	}
	job, err := s.enqueue(ctx, TaskKindAuditExport, actor, request.RequestID,
		map[string]string{"export_id": exportID}, defaultTaskTimeoutSeconds)
	if err != nil {
		s.finishExportFailure(ctx, record, ErrTaskRejected, CodeDBUnavailable, request.RequestID)
		return ExportView{}, fmt.Errorf("%w: 导出任务入队失败", ErrTaskRejected)
	}
	if err := s.opts.Store.SetExportTask(ctx, exportID, job.ID, s.now()); err != nil {
		s.finishExportFailure(ctx, record, ErrTaskRejected, CodeDBUnavailable, request.RequestID)
		return ExportView{}, fmt.Errorf("%w: 导出任务编号写入失败", ErrTaskRejected)
	}
	record.TaskID = job.ID
	view, err := s.exportView(ctx, record)
	if err != nil {
		return ExportView{}, err
	}
	s.notifySensitive(ctx, sensitiveResult)
	return view, nil
}

// ExportHandler 是注册到 internal/task 的导出处理器。它在执行前重新授权并复核
// 当前数据范围仍覆盖创建时快照；产物写入受控目录，失败不留下“假成功”。
func (s *Service) ExportHandler(ctx context.Context, job task.Job) error {
	if job.Kind != TaskKindAuditExport {
		return fmt.Errorf("%w: 任务类型不匹配", ErrInvalidRequest)
	}
	exportID, err := payloadExportID(job.Payload)
	if err != nil {
		return err
	}
	record, found, err := s.opts.Store.GetExport(ctx, exportID)
	if err != nil {
		return storeError(err)
	}
	if !found {
		return ErrNotFound
	}
	if record.RequestedBy != job.Initiator {
		s.recordFailure(ctx, job.Initiator, ActionExportFinish, record.ScopeID,
			"export_initiator_mismatch", CodeAccessDenied, record.RequestID)
		return ErrAccessDenied
	}
	if record.State != ExportQueued && record.State != ExportRunning {
		return ErrTaskTerminal
	}
	record, err = s.startExport(ctx, record, job)
	if err != nil {
		return err
	}
	caller, err := callerFromActor(record.RequestedBy)
	if err != nil {
		return s.failExportRun(ctx, record, ErrAccessDenied, CodeReportAccessDenied, "initiator_invalid")
	}
	grant, err := s.authorizeScope(ctx, caller, PermissionExport, record.ScopeID)
	if err != nil {
		return s.failExportRun(ctx, record, ErrAccessDenied, CodeReportAccessDenied, "export_not_authorized")
	}
	_, scope, order, filter, err := s.decodeExportSnapshot(record.FilterJSON)
	if err != nil {
		return s.failExportRun(ctx, record, ErrInvalidRequest, CodeReportGeneration, "snapshot_invalid")
	}
	if !grantCovers(record.DataScopeJSON, grant) {
		return s.failExportRun(ctx, record, ErrAccessDenied, CodeReportAccessDenied, "data_scope_shrunk")
	}
	constraint, err := scopeConstraint(scope, grant)
	if err != nil {
		return s.failExportRun(ctx, record, ErrAccessDenied, CodeReportAccessDenied, "scope_denied")
	}
	if err := s.validateFilter(filter, constraint); err != nil {
		return s.failExportRun(ctx, record, ErrAccessDenied, CodeReportAccessDenied, "filter_out_of_scope")
	}
	limit := s.maxExportRows
	if record.MaxRows < limit {
		limit = record.MaxRows
	}
	events, truncated, err := s.collectExportEvents(ctx, filter, order, constraint, limit)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			s.cancelExportRun(ctx, record)
			return err
		}
		return s.failExportRun(ctx, record, ErrStoreUnavailable, CodeReportGeneration, "export_read_failed")
	}
	name := exportFilePrefix + record.ID + "." + string(record.Format)
	path := filepath.Join(s.outputDir, name)
	digest, size, err := s.writeExportFile(path, ExportFormat(record.Format), events)
	if err != nil {
		removeExportArtifact(path)
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			s.cancelExportRun(ctx, record)
			return err
		}
		code := CodeReportGeneration
		domain := ErrInvalidRequest
		if errors.Is(err, ErrExportPathUnsafe) {
			code = CodeExportPathUnsafe
			domain = ErrExportPathUnsafe
		}
		return s.failExportRun(ctx, record, domain, code, "export_write_failed")
	}
	now := s.now()
	event := s.auditEvent(record.RequestedBy, scope, ActionExportFinish, "audit_export",
		record.ID, audit.OutcomeSuccess, "", record.RequestID, record.TaskID)
	command := ExportUpdateCommand{
		ID: record.ID, State: ExportSucceeded, ExecutorID: job.ExecutorID,
		RowCount: len(events), Truncated: truncated, FileName: name,
		FileSHA256: digest, FileBytes: size, Now: now,
	}
	written, err := s.opts.Store.UpdateExport(ctx, command, event)
	if err != nil {
		removeExportArtifact(path)
		return storeError(err)
	}
	if !written {
		removeExportArtifact(path)
		return ErrConflict
	}
	return nil
}

// ListExports 列出当前调用者在指定作用范围内仍可查看的导出任务；权限收缩后
// 旧任务不再可见（下载会被拒绝），但审计原始记录不被改写。
func (s *Service) ListExports(ctx context.Context, request ExportListRequest) ([]ExportView, bool, error) {
	scope, err := parseScope(request.ScopeID)
	if err != nil {
		return nil, false, err
	}
	grant, err := s.authorizeScope(ctx, request.Caller, PermissionExport, scope.ID)
	if err != nil {
		return nil, false, err
	}
	if request.State != "" && !validExportState(request.State) {
		return nil, false, fmt.Errorf("%w: 导出状态未知", ErrInvalidRequest)
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
	records, err := s.opts.Store.ListExports(ctx, ExportListQuery{
		ScopeID: scope.ID, State: request.State, Limit: limit + 1, Offset: request.Offset,
	})
	if err != nil {
		return nil, false, storeError(err)
	}
	hasMore := len(records) > limit
	views := make([]ExportView, 0, limit)
	for _, record := range records {
		if !grantCovers(record.DataScopeJSON, grant) {
			continue
		}
		view, viewErr := s.exportView(ctx, record)
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

// GetExport 读取导出任务状态；每次都按当前权限与数据范围重新授权。
func (s *Service) GetExport(ctx context.Context, caller account.Caller, exportID string) (ExportView, error) {
	record, _, err := s.authorizeExportRecord(ctx, caller, exportID)
	if err != nil {
		return ExportView{}, err
	}
	return s.exportView(ctx, record)
}

// CancelExport 请求取消导出任务。提交取消请求不等于实际取消；真实终态以任务
// 状态为准，重复取消幂等。
func (s *Service) CancelExport(ctx context.Context, caller account.Caller, exportID,
	reason, requestID string) (task.CancelResult, error) {
	record, _, err := s.authorizeExportRecord(ctx, caller, exportID)
	if err != nil {
		return task.CancelResult{}, err
	}
	// 取消/下载绑定发起者或 root：root 的 owner-or-root 例外属于步骤 252 保留的
	// root 专属身份能力（读取范围仍先经 PermissionExport 内核授权），不是普通权限
	// 放行。
	if record.RequestedBy != caller.Actor() && !s.isRoot(ctx, caller) {
		s.recordFailure(ctx, caller.Actor(), ActionExportRequest, record.ScopeID,
			"export_cancel_not_owner", CodeAccessDenied, requestID)
		return task.CancelResult{}, ErrAccessDenied
	}
	if err := validateReason(reason); err != nil {
		return task.CancelResult{}, err
	}
	if record.TaskID == "" {
		return task.CancelResult{}, fmt.Errorf("%w: 导出任务尚未取得任务编号", ErrConflict)
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
	event := audit.Event{
		Actor: caller.Actor(), AppID: appIDForScope(record.ScopeID),
		Action: ActionExportCancel, Target: audit.Target{Type: "audit_export", ID: record.ID},
		Outcome: audit.OutcomeSuccess, RequestID: requestID,
		Changes: []audit.FieldChange{{Field: "cancel_requested", After: "true"}},
	}
	if err := s.opts.Audit.Record(ctx, event); err != nil {
		s.opts.Logger.Warn("导出取消请求审计写入失败", "code", string(CodeAuditWriteFailed))
	}
	// queued 任务被取消时执行器直接置 cancelled 且不再调用处理器；必须在这里
	// 把导出记录收敛到真实取消终态，避免记录永远停在 queued。
	if result.State == task.StateCancelled {
		s.finalizeExportCancelled(ctx, record)
	}
	return result, nil
}

// finalizeExportCancelled 把导出记录条件迁移到真实取消终态（queued/running→cancelled），
// 使用不受调用方取消影响的上下文并同事务写审计事件。
func (s *Service) finalizeExportCancelled(ctx context.Context, record ExportRecord) {
	finalCtx := context.WithoutCancel(ctx)
	event := s.auditEvent(record.RequestedBy, ScopeInfo{ID: record.ScopeID,
		Kind: record.ScopeKind}, ActionExportCancel, "audit_export", record.ID,
		audit.OutcomeFailure, CodeTaskCancelled, record.RequestID, record.TaskID)
	command := ExportUpdateCommand{ID: record.ID, State: ExportCancelled,
		ErrorCode: string(CodeTaskCancelled), FailureReason: "任务已取消", Now: s.now()}
	written, err := s.opts.Store.UpdateExport(finalCtx, command, event)
	if err != nil {
		s.opts.Logger.Error("导出取消终态写入失败", "code", string(CodeAuditWriteFailed))
		return
	}
	if !written {
		s.opts.Logger.Warn("导出取消终态未写入", "reason", "already_terminal")
	}
}

// OpenExportFile 返回受控产物的宿主下载句柄（路径只给宿主文件流，不进入页面）。
// 只有任务成功、产物存在、未过期且当前权限仍覆盖创建时范围时才允许。
func (s *Service) OpenExportFile(ctx context.Context, caller account.Caller,
	exportID string) (ExportFile, error) {
	record, _, err := s.authorizeExportRecord(ctx, caller, exportID)
	if err != nil {
		return ExportFile{}, err
	}
	// 产物下载绑定发起者或 root：同范围其他用户即使可查询元数据，也不能下载
	// 他人生成的受控产物（最小可见原则）。
	if record.RequestedBy != caller.Actor() && !s.isRoot(ctx, caller) {
		s.recordFailure(ctx, caller.Actor(), ActionExportFinish, record.ScopeID,
			"download_not_owner", CodeReportAccessDenied, "")
		return ExportFile{}, ErrAccessDenied
	}
	if record.State != ExportSucceeded {
		return ExportFile{}, fmt.Errorf("%w: 导出尚未成功完成", ErrConflict)
	}
	now := s.now()
	if record.ExpiresAt.IsZero() || !now.Before(record.ExpiresAt) {
		return ExportFile{}, fmt.Errorf("%w: 导出文件已过期", ErrConflict)
	}
	if record.FileName == "" || len(record.FileSHA256) != sha256.Size {
		return ExportFile{}, fmt.Errorf("%w: 导出产物元数据不完整", ErrConflict)
	}
	name := record.FileName
	if filepath.Base(name) != name || !strings.HasPrefix(name, exportFilePrefix) ||
		!strings.HasSuffix(name, "."+record.Format) {
		return ExportFile{}, ErrExportPathUnsafe
	}
	path := filepath.Join(s.outputDir, name)
	info, statErr := os.Lstat(path)
	if statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return ExportFile{}, fmt.Errorf("%w: 导出产物不存在或类型不安全", ErrExportPathUnsafe)
	}
	if info.Size() != record.FileBytes {
		return ExportFile{}, fmt.Errorf("%w: 导出产物大小不符", ErrExportPathUnsafe)
	}
	// 防御纵深：打开前按记录摘要流式重算 SHA-256，篡改/截断产物拒绝下发。
	digest, digestErr := fileSHA256(path)
	if digestErr != nil || !equalBytes(digest, record.FileSHA256) {
		return ExportFile{}, fmt.Errorf("%w: 导出产物摘要不符", ErrExportPathUnsafe)
	}
	return ExportFile{ID: record.ID, HostPath: path, Format: ExportFormat(record.Format),
		Size: record.FileBytes, SHA256: hex.EncodeToString(record.FileSHA256),
		RowCount: record.RowCount, Truncated: record.Truncated,
		ExpiresAt: record.ExpiresAt}, nil
}

// startExport 把导出记录条件迁移为 running 并写审计。
func (s *Service) startExport(ctx context.Context, record ExportRecord,
	job task.Job) (ExportRecord, error) {
	if record.State == ExportRunning {
		return record, nil
	}
	now := s.now()
	event := s.auditEvent(record.RequestedBy, ScopeInfo{ID: record.ScopeID,
		Kind: record.ScopeKind}, ActionExportFinish, "audit_export", record.ID,
		audit.OutcomeSuccess, "", record.RequestID, record.TaskID)
	ok, err := s.opts.Store.UpdateExport(ctx, ExportUpdateCommand{
		ID: record.ID, State: ExportRunning, ExecutorID: job.ExecutorID, Now: now,
	}, event)
	if err != nil {
		return ExportRecord{}, storeError(err)
	}
	if !ok {
		return ExportRecord{}, ErrConflict
	}
	record.State = ExportRunning
	record.StartedAt = now
	return record, nil
}

// failExportRun 把导出记录写为失败终态并保留旧的失败说明；返回原始错误。
func (s *Service) failExportRun(ctx context.Context, record ExportRecord,
	cause error, code ErrorCode, reason string) error {
	finalCtx := context.WithoutCancel(ctx)
	now := s.now()
	event := s.auditEvent(record.RequestedBy, ScopeInfo{ID: record.ScopeID,
		Kind: record.ScopeKind}, ActionExportFinish, "audit_export", record.ID,
		audit.OutcomeFailure, code, record.RequestID, record.TaskID)
	command := ExportUpdateCommand{ID: record.ID, State: ExportFailed, ErrorCode: string(code),
		FailureReason: safeReason(reason), Now: now}
	if _, err := s.opts.Store.UpdateExport(finalCtx, command, event); err != nil {
		s.opts.Logger.Error("导出失败状态写入失败", "code", string(CodeAuditWriteFailed))
	}
	return cause
}

// cancelExportRun 把导出记录写为真实取消终态（尚未成功的部分产物已删除）。
func (s *Service) cancelExportRun(ctx context.Context, record ExportRecord) {
	finalCtx := context.WithoutCancel(ctx)
	event := s.auditEvent(record.RequestedBy, ScopeInfo{ID: record.ScopeID,
		Kind: record.ScopeKind}, ActionExportFinish, "audit_export", record.ID,
		audit.OutcomeFailure, CodeTaskCancelled, record.RequestID, record.TaskID)
	command := ExportUpdateCommand{ID: record.ID, State: ExportCancelled,
		ErrorCode: string(CodeTaskCancelled), FailureReason: "任务已取消", Now: s.now()}
	if _, err := s.opts.Store.UpdateExport(finalCtx, command, event); err != nil {
		s.opts.Logger.Error("导出取消状态写入失败", "code", string(CodeAuditWriteFailed))
	}
}

// finishExportFailure 在任务入队失败时把记录写为失败，避免出现“已受理但无任务”。
func (s *Service) finishExportFailure(ctx context.Context, record ExportRecord,
	cause error, code ErrorCode, requestID string) {
	finalCtx := context.WithoutCancel(ctx)
	event := s.auditEvent(record.RequestedBy, ScopeInfo{ID: record.ScopeID,
		Kind: record.ScopeKind}, ActionExportFinish, "audit_export", record.ID,
		audit.OutcomeFailure, code, requestID, "")
	command := ExportUpdateCommand{ID: record.ID, State: ExportFailed, ErrorCode: string(code),
		FailureReason: safeReason(cause.Error()), Now: s.now()}
	if _, err := s.opts.Store.UpdateExport(finalCtx, command, event); err != nil {
		s.opts.Logger.Error("导出入队失败状态写入失败", "code", string(CodeAuditWriteFailed))
	}
}

// authorizeExportRecord 统一校验导出记录访问：先按记录的作用范围重新授权
// audit.export，再确认当前数据范围覆盖创建时快照。
func (s *Service) authorizeExportRecord(ctx context.Context, caller account.Caller,
	exportID string) (ExportRecord, ScopeGrant, error) {
	if !validExportID(exportID) {
		return ExportRecord{}, ScopeGrant{}, fmt.Errorf("%w: 导出编号格式无效", ErrInvalidRequest)
	}
	record, found, err := s.opts.Store.GetExport(ctx, exportID)
	if err != nil {
		return ExportRecord{}, ScopeGrant{}, storeError(err)
	}
	if !found {
		return ExportRecord{}, ScopeGrant{}, ErrNotFound
	}
	grant, err := s.authorizeScope(ctx, caller, PermissionExport, record.ScopeID)
	if err != nil {
		return ExportRecord{}, ScopeGrant{}, err
	}
	if !grantCovers(record.DataScopeJSON, grant) {
		return ExportRecord{}, ScopeGrant{}, ErrAccessDenied
	}
	return record, grant, nil
}

// exportView 构造导出任务视图，附带真实任务状态摘要（如有任务读取器）。
func (s *Service) exportView(ctx context.Context, record ExportRecord) (ExportView, error) {
	view := ExportView{
		ID: record.ID, ScopeID: record.ScopeID, ScopeKind: record.ScopeKind,
		Format: ExportFormat(record.Format), State: record.State,
		RequestedBy: record.RequestedBy, MaxRows: record.MaxRows,
		RowCount: record.RowCount, Truncated: record.Truncated,
		TaskID: record.TaskID, FileExpiresAt: record.ExpiresAt,
		ErrorCode: record.ErrorCode, FailureReason: record.FailureReason,
		RequestID: record.RequestID, ExecutorID: record.ExecutorID,
		CreatedAt: record.CreatedAt,
		StartedAt: record.StartedAt, FinishedAt: record.FinishedAt,
	}
	view.FileAvailable = record.State == ExportSucceeded && record.FileName != "" &&
		!record.ExpiresAt.IsZero() && s.now().Before(record.ExpiresAt)
	if s.opts.Tasks != nil && record.TaskID != "" {
		job, found, err := s.opts.Tasks.Get(ctx, record.TaskID)
		if err != nil {
			return ExportView{}, storeError(err)
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

// collectExportEvents 分页读取导出事件，最多 readLimit+1 条用于判定是否截断。
func (s *Service) collectExportEvents(ctx context.Context, filter Filter, order SortOrder,
	constraint queryScope, readLimit int) ([]audit.Event, bool, error) {
	const pageSize = 200
	events := make([]audit.Event, 0, 256)
	offset := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		remaining := readLimit + 1 - len(events)
		if remaining <= 0 {
			break
		}
		limit := pageSize
		if remaining < limit {
			limit = remaining
		}
		page, err := s.opts.Store.QueryEvents(ctx, EventQuery{
			Filter: filter, AllData: constraint.allData, AppIDs: constraint.appIDs,
			IncludeSystem: constraint.includeSystem, Order: order,
			Limit: limit, Offset: offset,
		})
		if err != nil {
			return nil, false, err
		}
		events = append(events, page.Events...)
		if !page.HasMore || len(page.Events) == 0 {
			break
		}
		offset += len(page.Events)
	}
	truncated := len(events) > readLimit
	if truncated {
		events = events[:readLimit]
	}
	return events, truncated, nil
}

// exportColumns 是导出字段白名单（顺序即 CSV 列顺序）。受限诊断 reason_code
// 不导出；差异值在写入审计时已脱敏。
var exportColumns = []string{
	"event_id", "occurred_at", "actor_type", "actor_id", "app_id", "action",
	"target_type", "target_id", "outcome", "error_code", "request_id", "task_id",
	"changes",
}

// exportRow 是导出行（稳定字段名，不包含内部原因码或原始日志）。
type exportRow struct {
	EventID    string         `json:"event_id"`
	OccurredAt string         `json:"occurred_at"`
	ActorType  string         `json:"actor_type"`
	ActorID    string         `json:"actor_id,omitempty"`
	AppID      string         `json:"app_id,omitempty"`
	Action     string         `json:"action"`
	TargetType string         `json:"target_type"`
	TargetID   string         `json:"target_id,omitempty"`
	Outcome    string         `json:"outcome"`
	ErrorCode  string         `json:"error_code,omitempty"`
	RequestID  string         `json:"request_id,omitempty"`
	TaskID     string         `json:"task_id,omitempty"`
	Changes    []exportChange `json:"changes,omitempty"`
}

// exportChange 是脱敏差异行；敏感值保持写入期的 [REDACTED] 标记。
type exportChange struct {
	Field  string `json:"field"`
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
}

// writeExportFile 把事件写入受控目录：随机/受控文件名、O_EXCL 独占创建、字节
// 上限、CSV 防公式注入；返回 SHA-256 与字节数。
func (s *Service) writeExportFile(path string, format ExportFormat,
	events []audit.Event) ([]byte, int64, error) {
	if filepath.Base(path) != filepath.Clean(filepath.Base(path)) ||
		!strings.HasPrefix(filepath.Base(path), exportFilePrefix) {
		return nil, 0, ErrExportPathUnsafe
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, 0, fmt.Errorf("%w: 导出文件已存在", ErrExportPathUnsafe)
		}
		return nil, 0, fmt.Errorf("%w: 无法创建导出文件", ErrExportPathUnsafe)
	}
	digest := sha256.New()
	writer := &limitedDigestWriter{writer: file, digest: digest, limit: s.maxExportBytes}
	writeErr := s.writeExportRows(writer, format, events)
	closeErr := writer.close(file)
	if writeErr != nil {
		return nil, 0, writeErr
	}
	if closeErr != nil {
		return nil, 0, fmt.Errorf("%w: 导出文件写入失败", ErrInvalidRequest)
	}
	return digest.Sum(nil), writer.written, nil
}

// writeExportRows 按格式写入导出行。
func (s *Service) writeExportRows(writer *limitedDigestWriter, format ExportFormat,
	events []audit.Event) error {
	rows := make([]exportRow, 0, len(events))
	for _, event := range events {
		rows = append(rows, exportRowFromEvent(event))
	}
	switch format {
	case FormatCSV:
		csvWriter := csv.NewWriter(writer)
		if err := csvWriter.Write(exportColumns); err != nil {
			return fmt.Errorf("%w: 导出表头写入失败", ErrInvalidRequest)
		}
		for _, row := range rows {
			record := []string{
				row.EventID, row.OccurredAt, row.ActorType, row.ActorID, row.AppID,
				row.Action, row.TargetType, row.TargetID, row.Outcome, row.ErrorCode,
				row.RequestID, row.TaskID, changesText(row.Changes),
			}
			for index := range record {
				record[index] = safeCSVCell(record[index])
			}
			if err := csvWriter.Write(record); err != nil {
				return fmt.Errorf("%w: 导出记录写入失败", ErrInvalidRequest)
			}
		}
		csvWriter.Flush()
		if err := csvWriter.Error(); err != nil {
			return fmt.Errorf("%w: 导出记录写入失败", ErrInvalidRequest)
		}
		return nil
	case FormatJSON:
		encoder := json.NewEncoder(writer)
		encoder.SetEscapeHTML(true)
		if err := encoder.Encode(rows); err != nil {
			return fmt.Errorf("%w: 导出 JSON 写入失败", ErrInvalidRequest)
		}
		return nil
	default:
		return fmt.Errorf("%w: 导出格式未知", ErrInvalidRequest)
	}
}

// exportRowFromEvent 把审计事件映射为导出白名单行。
func exportRowFromEvent(event audit.Event) exportRow {
	row := exportRow{
		EventID: event.ID, OccurredAt: event.OccurredAt.UTC().Format(time.RFC3339Nano),
		ActorType: string(event.Actor.Type), ActorID: event.Actor.ID,
		AppID: event.AppID, Action: event.Action, TargetType: event.Target.Type,
		TargetID: event.Target.ID, Outcome: string(event.Outcome),
		ErrorCode: event.ErrorCode, RequestID: event.RequestID, TaskID: event.TaskID,
	}
	for _, change := range event.Changes {
		row.Changes = append(row.Changes, exportChange{
			Field: change.Field, Before: change.Before, After: change.After})
	}
	return row
}

// changesText 把差异序列化为稳定 JSON 文本（不输出原始事件 JSON）。
func changesText(changes []exportChange) string {
	if len(changes) == 0 {
		return ""
	}
	encoded, err := json.Marshal(changes)
	if err != nil {
		return ""
	}
	return string(encoded)
}

// safeCSVCell 防 CSV 公式注入：对以 = + - @ 制表/回车开头的单元格加前导单引号。
func safeCSVCell(value string) string {
	if value == "" {
		return value
	}
	switch value[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + value
	default:
		return value
	}
}

// limitedDigestWriter 同时计算摘要并限制总字节数。
type limitedDigestWriter struct {
	writer  *os.File
	digest  interface{ Write([]byte) (int, error) }
	limit   int64
	written int64
}

// Write 写入并限制大小。
func (w *limitedDigestWriter) Write(buffer []byte) (int, error) {
	if w.written+int64(len(buffer)) > w.limit {
		return 0, fmt.Errorf("%w: 导出产物超过 %d 字节上限", ErrInvalidRequest, w.limit)
	}
	written, err := w.writer.Write(buffer)
	if written > 0 {
		w.written += int64(written)
		if _, digestErr := w.digest.Write(buffer[:written]); digestErr != nil {
			return written, digestErr
		}
	}
	return written, err
}

// close 关闭产物文件并检查关闭错误。
func (w *limitedDigestWriter) close(file *os.File) error {
	return file.Close()
}

// encodeExportSnapshot 序列化筛选与数据范围快照。
func encodeExportSnapshot(scope ScopeInfo, filter Filter, order SortOrder,
	constraint queryScope, now time.Time) (string, string, error) {
	filterDocument := filterJSON{
		AppID: filter.AppID, SystemOnly: filter.SystemOnly,
		ActorType: string(filter.ActorType), ActorID: filter.ActorID,
		Action: filter.Action, Outcome: string(filter.Outcome),
		ErrorCode: filter.ErrorCode, RequestID: filter.RequestID,
		TaskID: filter.TaskID, TargetType: filter.TargetType, TargetID: filter.TargetID,
	}
	if !filter.From.IsZero() {
		filterDocument.FromMs = filter.From.UTC().UnixMilli()
	}
	if !filter.To.IsZero() {
		filterDocument.ToMs = filter.To.UTC().UnixMilli()
	}
	snapshot := exportFilterSnapshot{Version: 1, ScopeKind: scope.Kind, ScopeID: scope.ID,
		Order: order, Filter: filterDocument,
		RequestTime: now.UTC().Truncate(time.Millisecond)}
	encodedFilter, err := json.Marshal(snapshot)
	if err != nil || len(encodedFilter) > MaxExportFilterBytes {
		return "", "", fmt.Errorf("%w: 筛选快照无法序列化", ErrInvalidRequest)
	}
	scopeDocument := dataScopeSnapshot{All: constraint.allData,
		Resources: append([]string(nil), constraint.appIDs...)}
	if constraint.includeSystem && !constraint.allData {
		scopeDocument.Resources = append(scopeDocument.Resources, ScopeSystem)
	}
	encodedScope, err := json.Marshal(scopeDocument)
	if err != nil {
		return "", "", fmt.Errorf("%w: 数据范围快照无法序列化", ErrInvalidRequest)
	}
	return string(encodedFilter), string(encodedScope), nil
}

// decodeExportSnapshot 解析并校验筛选快照。
func (s *Service) decodeExportSnapshot(raw string) (exportFilterSnapshot, ScopeInfo,
	SortOrder, Filter, error) {
	if len(raw) == 0 || len(raw) > MaxExportFilterBytes {
		return exportFilterSnapshot{}, ScopeInfo{}, "", Filter{},
			fmt.Errorf("%w: 筛选快照无效", ErrInvalidRequest)
	}
	var snapshot exportFilterSnapshot
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil {
		return exportFilterSnapshot{}, ScopeInfo{}, "", Filter{},
			fmt.Errorf("%w: 筛选快照无效", ErrInvalidRequest)
	}
	if snapshot.Version != 1 {
		return exportFilterSnapshot{}, ScopeInfo{}, "", Filter{},
			fmt.Errorf("%w: 筛选快照版本不受支持", ErrInvalidRequest)
	}
	scope := ScopeInfo{ID: snapshot.ScopeID, Kind: snapshot.ScopeKind}
	if snapshot.ScopeKind == "system" {
		scope = ScopeInfo{ID: ScopeSystem, Kind: "system"}
	} else if snapshot.ScopeKind != "app" {
		return exportFilterSnapshot{}, ScopeInfo{}, "", Filter{},
			fmt.Errorf("%w: 筛选快照作用范围无效", ErrInvalidRequest)
	}
	if !snapshot.Order.Valid() {
		return exportFilterSnapshot{}, ScopeInfo{}, "", Filter{},
			fmt.Errorf("%w: 筛选快照排序无效", ErrInvalidRequest)
	}
	filter := Filter{
		AppID: snapshot.Filter.AppID, SystemOnly: snapshot.Filter.SystemOnly,
		ActorType: audit.ActorKind(snapshot.Filter.ActorType),
		ActorID:   snapshot.Filter.ActorID, Action: snapshot.Filter.Action,
		Outcome:   audit.Outcome(snapshot.Filter.Outcome),
		ErrorCode: snapshot.Filter.ErrorCode, RequestID: snapshot.Filter.RequestID,
		TaskID: snapshot.Filter.TaskID, TargetType: snapshot.Filter.TargetType,
		TargetID: snapshot.Filter.TargetID,
	}
	if snapshot.Filter.FromMs > 0 {
		filter.From = time.UnixMilli(snapshot.Filter.FromMs).UTC()
	}
	if snapshot.Filter.ToMs > 0 {
		filter.To = time.UnixMilli(snapshot.Filter.ToMs).UTC()
	}
	return snapshot, scope, snapshot.Order, filter, nil
}

// grantCovers 判断当前授权是否覆盖创建时数据范围快照：快照为 all 时必须仍是
// all；快照为 resources 时当前 all 或包含全部资源都算覆盖。
func grantCovers(dataScopeJSON string, grant ScopeGrant) bool {
	if !grant.Allowed {
		return false
	}
	document := dataScopeSnapshot{}
	if err := json.Unmarshal([]byte(dataScopeJSON), &document); err != nil {
		return false
	}
	if document.All {
		return grant.AllData
	}
	if grant.AllData {
		return true
	}
	for _, resource := range document.Resources {
		if !containsString(grant.ResourceIDs, resource) {
			return false
		}
	}
	return true
}

// appIDForScope 把系统范围转换为空应用快照 ID，应用范围返回自身 ID。
func appIDForScope(scopeID string) string {
	if scopeID == ScopeSystem {
		return ""
	}
	return scopeID
}

// digestString 计算字符串 SHA-256 十六进制摘要（用于敏感操作参数绑定）。
func digestString(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// validExportID 校验导出编号格式。
func validExportID(id string) bool {
	return validPrefixedID(id, exportIDPrefix)
}

// validPurgeID 校验清理运行编号格式。
func validPurgeID(id string) bool {
	return validPrefixedID(id, purgeIDPrefix)
}

// validPrefixedID 校验“前缀 + 32 位小写十六进制”的编号格式。
func validPrefixedID(id, prefix string) bool {
	if len(id) != len(prefix)+32 || !strings.HasPrefix(id, prefix) {
		return false
	}
	for index := len(prefix); index < len(id); index++ {
		c := id[index]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// payloadExportID 从任务载荷中读取导出编号（载荷只允许该字段）。
func payloadExportID(payload json.RawMessage) (string, error) {
	var document struct {
		ExportID string `json:"export_id"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return "", fmt.Errorf("%w: 导出任务载荷无效", ErrInvalidRequest)
	}
	if !validExportID(document.ExportID) {
		return "", fmt.Errorf("%w: 导出任务载荷编号无效", ErrInvalidRequest)
	}
	return document.ExportID, nil
}

// payloadPurgeID 从任务载荷中读取清理运行编号（载荷只允许该字段）。
func payloadPurgeID(payload json.RawMessage) (string, error) {
	var document struct {
		RunID string `json:"run_id"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return "", fmt.Errorf("%w: 清理任务载荷无效", ErrInvalidRequest)
	}
	if !validPurgeID(document.RunID) {
		return "", fmt.Errorf("%w: 清理任务载荷编号无效", ErrInvalidRequest)
	}
	return document.RunID, nil
}

// enqueue 提交异步任务。
func (s *Service) enqueue(ctx context.Context, kind string, actor audit.Actor,
	requestID string, payload map[string]string, timeoutSeconds int) (task.Job, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return task.Job{}, fmt.Errorf("%w: 任务载荷无法序列化", ErrInvalidRequest)
	}
	job, err := s.opts.Enqueuer.Enqueue(ctx, task.EnqueueRequest{
		Kind: kind, Actor: actor, Payload: encoded, TimeoutSeconds: timeoutSeconds,
		PermissionRequired: true, RequestID: requestID,
	})
	if err != nil {
		return task.Job{}, fmt.Errorf("%w: %w", ErrTaskRejected, err)
	}
	return job, nil
}

// removeExportArtifact 删除本次执行产生的部分产物（只删除受控目录内由本服务
// 生成的文件）。
func removeExportArtifact(path string) {
	if filepath.Base(path) != filepath.Clean(filepath.Base(path)) ||
		!strings.HasPrefix(filepath.Base(path), exportFilePrefix) {
		return
	}
	_ = os.Remove(path)
}

// fileSHA256 流式计算文件 SHA-256（用于下载前核验受控产物）。
func fileSHA256(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return nil, err
	}
	return digest.Sum(nil), nil
}

// equalBytes 恒定时间比较两个字节切片（摘要比较不泄露前缀信息）。
func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var diff byte
	for index := range left {
		diff |= left[index] ^ right[index]
	}
	return diff == 0
}

// storeError 把存储错误统一包装为 ErrStoreUnavailable，避免泄露底层错误文本。
func storeError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
}
