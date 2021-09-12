package reports

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// StartRequest 是创建即时报告请求。Caller 必须来自可信调用上下文；ScopeID 是
// system 或应用 ID；Window 为统计窗口/时区/粒度；Formats 为空时默认 HTML。
type StartRequest struct {
	Caller        account.Caller
	ScopeID       string
	Window        stats.WindowRequest
	AppID         string
	Categories    []stats.Category
	TrendMetric   stats.Metric
	Formats       []Format
	MaxDetailRows int
	RequestID     string
}

// ReportSummary 是报告核心数字摘要（供即时结果查询与页面预览）。
type ReportSummary struct {
	ActiveUsers    int64 `json:"active_users"`
	TotalRawEvents int64 `json:"total_raw_events"`
	FailedRequests int64 `json:"failed_requests"`
	FailedTasks    int64 `json:"failed_tasks"`
	DetailRows     int   `json:"detail_rows"`
	TrendPoints    int   `json:"trend_points"`
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

// ReportView 是报告公开视图：不含产物宿主路径、原始审计记录或秘密。
type ReportView struct {
	ID                string
	ScopeID           string
	ScopeKind         string
	State             string
	Formats           []Format
	RequestedBy       audit.Actor
	CreatedAt         time.Time
	StartedAt         time.Time
	FinishedAt        time.Time
	GeneratedAt       time.Time
	SchemaVersion     string
	TemplateVersion   int
	OverallStatus     string
	Completeness      CompletenessInfo
	Notes             []string
	Summary           ReportSummary
	TaskID            string
	ExecutorID        string
	ErrorCode         string
	FailureReason     string
	RequestID         string
	Artifacts         []ArtifactView
	ArtifactExpiresAt time.Time
	Task              *TaskSummary
	// RetryOf 是重试来源报告编号（页面用于链式追踪）。
	RetryOf string
}

// reportRecord 是进程内即时报告记录。历史持久化与定期计划属于步骤 79；本步骤
// 不把内存记录伪装成持久历史。
type reportRecord struct {
	ID          string
	PlanID      string
	Name        string
	Template    string
	ScopeID     string
	ScopeKind   string
	RequestedBy audit.Actor
	State       string
	// RetryOf 是本次运行重试的原报告编号（空表示不是重试）；链式重试保留历史。
	RetryOf       string
	Formats       []Format
	Window        stats.Window
	AppID         string
	Categories    []stats.Category
	TrendMetric   stats.Metric
	DetailRows    int
	DataScope     dataScope
	RequestID     string
	TaskID        string
	ExecutorID    string
	CreatedAt     time.Time
	StartedAt     time.Time
	FinishedAt    time.Time
	ErrorCode     string
	FailureReason string
	Snapshot      *Snapshot
	Artifacts     map[Format]Artifact
	ExpiresAt     time.Time
}

// payloadReportID 是任务载荷中的报告编号（不保存秘密或大对象）。
type payloadReportID struct {
	ReportID string `json:"report_id"`
}

// Start 创建即时报告生成任务。授权顺序：查看（reports.read，数据来源需要）→
// 生成（reports.generate）→ 导出（reports.export，所有格式产物都受控导出）→
// 敏感操作确认（reports.export 策略，强认证）；然后冻结窗口/筛选并投递任务。
// 提交成功只表示已受理，真实结果由 Get 查询任务状态。
func (s *Service) Start(ctx context.Context, request StartRequest) (ReportView, error) {
	actor := request.Caller.Actor()
	if err := actor.Validate(); err != nil {
		return ReportView{}, ErrAccessDenied
	}
	scope, err := parseScope(request.ScopeID)
	if err != nil {
		return ReportView{}, err
	}
	// 审计/任务事件只接受合法请求编号；非法值归一为空，避免留痕被拒而丢失。
	requestID := normalizeRequestID(request.RequestID)
	// 数据来源（生产为 stats.Service）自身要求 reports.read；生成前先复核该权限，
	// 避免任务在读取阶段才因缺读权限失败而留下半成品。
	readGrant, err := s.authorizeScope(ctx, request.Caller, PermissionRead, scope.ID)
	if err != nil {
		s.recordFailure(ctx, actor, ActionGenerateRequest, scope.ID,
			"read_not_authorized", CodeAccessDenied, requestID, "")
		return ReportView{}, err
	}
	if _, err := s.authorizeScope(ctx, request.Caller, PermissionGenerate, scope.ID); err != nil {
		s.recordFailure(ctx, actor, ActionGenerateRequest, scope.ID,
			"generate_not_authorized", CodeAccessDenied, requestID, "")
		return ReportView{}, err
	}
	// 先校验请求中的每个格式，未知格式必须拒绝，不能因“过滤未知值”静默降级为
	// 只生成 HTML（那会让调用方以为请求的格式已生成）。
	for _, format := range request.Formats {
		if !format.Valid() {
			return ReportView{}, fmt.Errorf("%w: 报告格式只支持 html/csv/json/pdf/markdown", ErrInvalidRequest)
		}
	}
	// PDF 需要受信嵌入字体；未配置/校验失败时构造已被拒绝，此处兜底拒绝请求，
	// 不生成“纯文本改扩展名”的假 PDF。
	if containsFormat(request.Formats, FormatPDF) && !s.PDFAvailable() {
		return ReportView{}, fmt.Errorf("%w: PDF 输出需要配置受控中文字体", ErrInvalidRequest)
	}
	formats := formatSortedFormats(request.Formats)
	if len(formats) == 0 {
		formats = []Format{FormatHTML}
	}
	// 每个格式都会写受控可下载产物，因而都属于“导出”面：与 internal/policy 中
	// reports.export 操作的 PermissionKey 声明保持一致，不因只请求 HTML 而放宽。
	if _, err := s.authorizeScope(ctx, request.Caller, PermissionExport, scope.ID); err != nil {
		s.recordFailure(ctx, actor, ActionGenerateRequest, scope.ID,
			"export_not_authorized", CodeAccessDenied, requestID, "")
		return ReportView{}, err
	}
	if err := validateAppFilter(request.AppID, scope, readGrant); err != nil {
		s.recordFailure(ctx, actor, ActionGenerateRequest, scope.ID,
			"app_filter_out_of_scope", CodeAccessDenied, requestID, "")
		return ReportView{}, err
	}
	categories, err := normalizeCategories(request.Categories)
	if err != nil {
		return ReportView{}, err
	}
	trendMetric, err := normalizeTrendMetric(request.TrendMetric)
	if err != nil {
		return ReportView{}, err
	}
	detailRows := request.MaxDetailRows
	if detailRows == 0 {
		detailRows = s.maxDetailRows
	}
	if detailRows < 1 || detailRows > s.maxDetailRows {
		return ReportView{}, fmt.Errorf("%w: 明细条数上限必须在 1～%d 之间",
			ErrInvalidRequest, s.maxDetailRows)
	}
	window, err := stats.NormalizeWindow(request.Window, s.now())
	if err != nil {
		return ReportView{}, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	sensitiveResult, err := s.authorizeSensitive(ctx, request.Caller, scope.ID, formats,
		window, request.AppID, detailRows, requestID)
	if err != nil {
		s.recordFailure(ctx, actor, ActionGenerateRequest, scope.ID,
			"export_reauth_denied", CodeAccessDenied, requestID, "")
		return ReportView{}, err
	}
	reportID, err := s.newID(reportIDPrefix)
	if err != nil {
		return ReportView{}, err
	}
	now := s.now()
	record := &reportRecord{
		ID: reportID, Name: "即时统计报告", Template: "standard",
		ScopeID: scope.ID, ScopeKind: scope.Kind,
		RequestedBy: actor, State: StateQueued, Formats: formats,
		Window: window, AppID: request.AppID, Categories: categories,
		TrendMetric: trendMetric, DetailRows: detailRows,
		DataScope: dataScope{All: readGrant.AllData,
			Resources: append([]string(nil), readGrant.ResourceIDs...)},
		RequestID: requestID, CreatedAt: now,
		ExpiresAt: now.Add(s.artifactTTL),
	}
	s.insert(record)
	job, err := s.enqueue(ctx, actor, reportID, requestID)
	if err != nil {
		s.failRecord(ctx, reportID, ErrTaskRejected, CodeDBUnavailable,
			"报告任务入队失败", requestID)
		return ReportView{}, fmt.Errorf("%w: 报告任务入队失败", ErrTaskRejected)
	}
	s.mutate(reportID, func(current *reportRecord) bool {
		if current.State != StateQueued {
			return false
		}
		current.TaskID = job.ID
		return true
	})
	s.persistHistory(ctx, reportID)
	s.notifySensitive(ctx, sensitiveResult)
	// 直接用已授权创建结果构造视图，避免任务已受理后再次授权失败导致“返回错误
	// 但任务仍在跑”的歧义；之后查询/下载仍逐次重新授权。
	created, found := s.get(reportID)
	if !found {
		return ReportView{}, ErrNotFound
	}
	return s.viewFromRecord(ctx, created), nil
}

// enqueue 投递生成任务（不启用执行器级权限复验：处理器自身会重新授权）。
func (s *Service) enqueue(ctx context.Context, actor audit.Actor, reportID,
	requestID string) (task.Job, error) {
	payload, err := json.Marshal(payloadReportID{ReportID: reportID})
	if err != nil {
		return task.Job{}, fmt.Errorf("%w: 报告任务载荷无效", ErrInvalidRequest)
	}
	return s.opts.Enqueuer.Enqueue(ctx, task.EnqueueRequest{
		Kind: TaskKindReportGenerate, Actor: actor,
		Payload: payload, TimeoutSeconds: reportTaskTimeoutSeconds,
		MaxAttempts: 1, RequestID: requestID,
	})
}

// authorizeSensitive 执行敏感操作校验（强认证/确认）；未装配时构造已被拒绝，
// 因此这里不会静默放行。返回结果供成功告知使用。
func (s *Service) authorizeSensitive(ctx context.Context, caller account.Caller,
	scopeID string, formats []Format, window stats.Window, appID string,
	detailRows int, requestID string) (reauth.Result, error) {
	reauthCaller, err := reauth.CallerFromActor(caller.Actor())
	if err != nil {
		return reauth.Result{}, ErrAccessDenied
	}
	formatText := make([]string, 0, len(formats))
	for _, format := range formats {
		formatText = append(formatText, string(format))
	}
	params := map[string]string{
		"scope": scopeID, "formats": strings.Join(formatText, ","),
		"max_detail_rows": strconv.Itoa(detailRows),
		"window_start_ms": strconv.FormatInt(window.Start.UnixMilli(), 10),
		"window_end_ms":   strconv.FormatInt(window.End.UnixMilli(), 10),
		"timezone":        window.TimeZone,
		"granularity":     string(window.Granularity),
		"app_id":          appID,
	}
	result, err := s.opts.Sensitive.Authorize(ctx, reauthCaller, reauth.Request{
		ScopeID: scopeID, OperationID: OperationExport, TargetType: "report",
		TargetID: "", Params: params, Description: "生成并导出统计报告",
		RequestID: requestID,
	})
	if err != nil {
		return reauth.Result{}, fmt.Errorf("%w: %w", ErrAccessDenied, err)
	}
	return result, nil
}

// notifySensitive 记录成功告知；告知失败只记录日志，不回滚已受理任务。
func (s *Service) notifySensitive(ctx context.Context, result reauth.Result) {
	if result.OperationID == "" {
		return
	}
	if err := s.opts.Sensitive.NotifyOutcome(ctx, result, reauth.OutcomeSuccess); err != nil {
		s.opts.Logger.Warn("报告操作安全告知未完成", "reason", "notify_unavailable")
	}
}

// GenerateHandler 是注册到 internal/task 的生成处理器。执行前重新授权并复核
// 当前数据范围仍覆盖创建时快照；图表与明细来自同一次快照构建；产物写入受控
// 目录，失败/取消删除本次产物，不留下可下载的不完整文件。
func (s *Service) GenerateHandler(ctx context.Context, job task.Job) error {
	if job.Kind != TaskKindReportGenerate {
		return fmt.Errorf("%w: 任务类型不匹配", ErrInvalidRequest)
	}
	reportID, err := payloadReportIDFromJob(job)
	if err != nil {
		return err
	}
	record, found := s.get(reportID)
	if !found {
		return ErrNotFound
	}
	if record.RequestedBy != job.Initiator {
		s.recordFailure(ctx, job.Initiator, ActionGenerateFinish, record.ScopeID,
			"report_initiator_mismatch", CodeAccessDenied, record.RequestID, record.ID)
		return ErrAccessDenied
	}
	if record.State != StateQueued && record.State != StateRunning {
		return ErrTaskTerminal
	}
	started := s.mutate(reportID, func(current *reportRecord) bool {
		// 只允许第一次从 queued 进入 running；同一任务被重复调用时返回终态错误，
		// 避免两个执行流同时写产物或互相删除产物。
		if current.State != StateQueued {
			return false
		}
		current.State = StateRunning
		current.ExecutorID = job.ExecutorID
		if current.StartedAt.IsZero() {
			current.StartedAt = s.now()
		}
		return true
	})
	if !started {
		return ErrTaskTerminal
	}
	return s.runGeneration(ctx, record, job)
}

// runGeneration 执行已进入 running 状态的报告记录：再次按当前权限与数据范围
// 复核（权限/范围收缩后不因曾有权限而成功）、构建同一固定快照、渲染并写受控
// 产物，最后以真实终态提交。GenerateHandler（即时报告）与
// GenerateScheduledHandler（计划触发）共用该实现，避免两套生成语义。
func (s *Service) runGeneration(ctx context.Context, record reportRecord, job task.Job) error {
	_ = job // 生成核心不需要任务字段；签名保留以确保调用方传入真实触发上下文。
	reportID := record.ID
	s.persistHistory(ctx, reportID) // 运行中状态（真实任务状态，不是进度百分比）
	caller, err := callerFromActor(record.RequestedBy)
	if err != nil {
		return s.failRun(ctx, reportID, ErrAccessDenied, CodeReportAccessDenied,
			"发起身份无效", record.RequestID)
	}
	readGrant, err := s.authorizeScope(ctx, caller, PermissionRead, record.ScopeID)
	if err != nil {
		return s.failRun(ctx, reportID, ErrAccessDenied, CodeReportAccessDenied,
			"数据读取权限已撤销", record.RequestID)
	}
	if !s.grantCovers(record.DataScope, readGrant) {
		return s.failRun(ctx, reportID, ErrAccessDenied, CodeReportAccessDenied,
			"数据范围已收缩", record.RequestID)
	}
	if _, err := s.authorizeScope(ctx, caller, PermissionGenerate, record.ScopeID); err != nil {
		return s.failRun(ctx, reportID, ErrAccessDenied, CodeReportAccessDenied,
			"生成权限已撤销", record.RequestID)
	}
	if _, err := s.authorizeScope(ctx, caller, PermissionExport, record.ScopeID); err != nil {
		return s.failRun(ctx, reportID, ErrAccessDenied, CodeReportAccessDenied,
			"导出权限已撤销", record.RequestID)
	}
	snapshot, err := s.build(ctx, record, caller)
	if err != nil {
		// 超时是失败（TASK_TIMEOUT），只有真实取消才写取消终态；两者不能混写。
		if errors.Is(err, context.DeadlineExceeded) {
			return s.failRun(ctx, reportID, err, CodeTaskTimeout,
				"报告生成超时", record.RequestID)
		}
		if errors.Is(err, context.Canceled) {
			s.cancelRun(ctx, reportID, record.RequestID)
			return err
		}
		if errors.Is(err, stats.ErrAccessDenied) {
			return s.failRun(ctx, reportID, ErrAccessDenied, CodeReportAccessDenied,
				"统计读取被拒绝", record.RequestID)
		}
		return s.failRun(ctx, reportID, ErrStoreUnavailable, CodeReportGeneration,
			"统计快照构建失败", record.RequestID)
	}
	rendered := make(map[Format][]byte, len(record.Formats))
	for _, format := range record.Formats {
		data, renderErr := s.renderSnapshot(ctx, snapshot, format)
		if renderErr != nil {
			// 渲染阶段也会检查上下文（PDF 可达 45 秒窗口），必须沿用步骤 77 的终态
			// 分离语义：真实取消 → cancelled/TASK_CANCELLED；任务或渲染墙钟超时 →
			// failed/TASK_TIMEOUT；其他渲染错误 → failed/REPORT_GENERATION_FAILED。
			// 不能把所有渲染错误一律写成“生成失败”，否则取消/超时会被误记。
			if errors.Is(renderErr, context.Canceled) {
				s.cancelRun(ctx, reportID, record.RequestID)
				return renderErr
			}
			if errors.Is(renderErr, context.DeadlineExceeded) {
				return s.failRun(ctx, reportID, renderErr, CodeTaskTimeout,
					"报告生成超时", record.RequestID)
			}
			return s.failRun(ctx, reportID, renderErr, CodeReportGeneration,
				"报告渲染失败", record.RequestID)
		}
		rendered[format] = data
	}
	expiresAt := s.now().Add(s.artifactTTL)
	artifacts := make(map[Format]Artifact, len(record.Formats))
	created := make([]Artifact, 0, len(record.Formats))
	for _, format := range record.Formats {
		artifact, writeErr := s.writeArtifact(reportID, format, rendered[format], expiresAt)
		if writeErr != nil {
			s.cleanupArtifacts(created)
			return s.failRun(ctx, reportID, writeErr, CodeReportGeneration,
				"报告产物写入失败", record.RequestID)
		}
		artifacts[format] = artifact
		created = append(created, artifact)
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		s.cleanupArtifacts(created)
		if errors.Is(ctxErr, context.DeadlineExceeded) {
			return s.failRun(ctx, reportID, ctxErr, CodeTaskTimeout,
				"报告生成超时", record.RequestID)
		}
		s.cancelRun(ctx, reportID, record.RequestID)
		return ctxErr
	}
	// 先提交成功状态，再写成功审计。顺序如此可避免“成功审计已写、状态未提交”
	// 的窄竞态；若审计写入失败，则用幂等补偿把报告回滚为失败并删除产物，确保
	// 不存在“可下载但无持久审计”的敏感导出，也不会在失败/取消终态记成功。
	finished := s.mutate(reportID, func(current *reportRecord) bool {
		if current.State != StateRunning {
			// 期间已被取消：删除刚写的产物，保持取消终态。
			return false
		}
		current.State = StateSucceeded
		current.Snapshot = &snapshot
		current.Artifacts = artifacts
		current.FinishedAt = s.now()
		current.ExpiresAt = expiresAt
		return true
	})
	if !finished {
		s.cleanupArtifacts(created)
		return ErrTaskTerminal
	}
	event := audit.Event{
		Actor: record.RequestedBy, AppID: appIDForScope(record.ScopeID),
		Action: ActionGenerateFinish, Target: audit.Target{Type: "report", ID: reportID},
		Outcome: audit.OutcomeSuccess, RequestID: record.RequestID,
		Changes: []audit.FieldChange{{Field: "state", After: StateSucceeded}},
	}
	if err := s.opts.Audit.Record(ctx, event); err != nil {
		s.cleanupArtifacts(created)
		s.rollbackSuccessAfterAuditFailure(context.WithoutCancel(ctx), reportID,
			record.RequestID)
		return fmt.Errorf("%w: 生成成功审计写入失败", ErrAuditUnavailable)
	}
	s.persistHistory(ctx, reportID)
	s.notifyReportResult(ctx, reportID)
	return nil
}

// rollbackSuccessAfterAuditFailure 把“已提交成功但成功审计写入失败”的报告幂等
// 回滚为失败并清空快照/产物引用，避免审计与真实终态不一致。
func (s *Service) rollbackSuccessAfterAuditFailure(ctx context.Context, reportID,
	requestID string) {
	var record reportRecord
	rolledBack := s.mutate(reportID, func(current *reportRecord) bool {
		if current.State != StateSucceeded || current.ErrorCode != "" {
			return false
		}
		current.State = StateFailed
		current.ErrorCode = string(CodeAuditWriteFailed)
		current.FailureReason = "生成成功审计写入失败"
		current.FinishedAt = s.now()
		current.Snapshot = nil
		current.Artifacts = nil
		record = *current
		return true
	})
	if !rolledBack {
		return
	}
	s.recordFailure(ctx, record.RequestedBy, ActionGenerateFinish, record.ScopeID,
		"audit_write_failed_after_success", CodeAuditWriteFailed, requestID, reportID)
	s.persistHistory(ctx, reportID)
}

// build 用冻结参数构建快照并补全报告元数据（编号/发起者/生成时间）。
func (s *Service) build(ctx context.Context, record reportRecord,
	caller account.Caller) (Snapshot, error) {
	request := snapshotRequest{
		Caller: caller, Scope: ScopeInfo{ID: record.ScopeID, Kind: record.ScopeKind},
		Window: record.Window, AppID: record.AppID, Categories: record.Categories,
		TrendMetric: record.TrendMetric, DetailRows: record.DetailRows,
	}
	snapshot, err := buildSnapshot(ctx, s.opts.Source, request, s.now(), record.DetailRows)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot.Report.ID = record.ID
	snapshot.Report.RequestedBy = ActorInfo{Type: string(record.RequestedBy.Type),
		ID: record.RequestedBy.ID}
	snapshot.Report.GeneratedAt = s.now()
	return snapshot, nil
}

// renderSnapshot 按格式渲染快照。PDF/Markdown 与 HTML/CSV/JSON 读取同一 Snapshot，
// 保证数值同源。PDF 渲染有独立墙钟上限并在排版循环中检查上下文，输入来自受控快照
// 且行数在上游受限；渲染器不访问网络、不读任意本地文件（字体已在构造时读入内存）、
// 不启动子进程。
func (s *Service) renderSnapshot(ctx context.Context, snapshot Snapshot, format Format) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch format {
	case FormatHTML:
		return renderHTML(snapshot)
	case FormatCSV:
		return renderCSV(snapshot)
	case FormatJSON:
		return renderJSON(snapshot)
	case FormatPDF:
		if !s.PDFAvailable() {
			return nil, fmt.Errorf("%w: PDF 输出需要配置受控中文字体", ErrInvalidRequest)
		}
		renderCtx, cancel := context.WithTimeout(ctx, pdfRenderTimeout)
		defer cancel()
		return renderPDF(renderCtx, snapshot, s.font)
	case FormatMarkdown:
		return renderMarkdown(snapshot)
	default:
		return nil, fmt.Errorf("%w: 报告格式未定义", ErrInvalidRequest)
	}
}

// Get 按编号查询即时报告结果/失败/取消；每次都按当前权限与数据范围重新授权，
// 权限撤销后旧报告不可查看。只返回受控元数据与摘要，不含产物路径。
func (s *Service) Get(ctx context.Context, caller account.Caller, reportID string) (ReportView, error) {
	if !validReportID(reportID) {
		return ReportView{}, fmt.Errorf("%w: 报告编号格式无效", ErrInvalidRequest)
	}
	return s.view(ctx, reportID, caller, PermissionRead)
}

// GetSnapshot 返回已完成报告的固定快照（机器可读，与 JSON 产物等价，含受控
// 明细行）。它属“导出”数据面，因此要求 reports.read + reports.export 并复核当前
// 数据范围；页面预览若只需受控字段应使用 Get 的摘要视图，而不是绕过导出权限。
func (s *Service) GetSnapshot(ctx context.Context, caller account.Caller,
	reportID string) (Snapshot, error) {
	if !validReportID(reportID) {
		return Snapshot{}, fmt.Errorf("%w: 报告编号格式无效", ErrInvalidRequest)
	}
	record, found := s.get(reportID)
	if !found {
		// 进程重启后回源持久历史：重新按当前权限与数据范围授权并写导出审计。
		return s.getHistorySnapshot(ctx, caller, reportID)
	}
	if err := s.authorizeSnapshotExport(ctx, caller, record); err != nil {
		return Snapshot{}, err
	}
	if record.State != StateSucceeded || record.Snapshot == nil {
		return Snapshot{}, fmt.Errorf("%w: 报告尚未成功完成", ErrConflict)
	}
	// 快照读取与 JSON 产物等价，属敏感导出面：必须留审计；审计不可用时拒绝
	// 返回完整快照（fail-closed，不能绕过 OpenFile 的审计约束）。
	event := audit.Event{
		Actor: caller.Actor(), AppID: appIDForScope(record.ScopeID),
		Action: ActionExportSnapshot, Target: audit.Target{Type: "report",
			ID: reportID},
		Outcome: audit.OutcomeSuccess, RequestID: record.RequestID,
		Changes: []audit.FieldChange{{Field: "format", After: "json_snapshot"}},
	}
	if err := s.opts.Audit.Record(ctx, event); err != nil {
		return Snapshot{}, fmt.Errorf("%w: 快照读取审计写入失败", ErrAuditUnavailable)
	}
	return *record.Snapshot, nil
}

// authorizeView 复核查看权限与当前数据范围仍覆盖生成时范围。
func (s *Service) authorizeView(ctx context.Context, caller account.Caller,
	record reportRecord) error {
	grant, err := s.authorizeScope(ctx, caller, PermissionRead, record.ScopeID)
	if err != nil {
		return err
	}
	if !s.grantCovers(record.DataScope, grant) {
		s.recordDenied(ctx, caller.Actor(), record.ScopeID, PermissionRead, "data_scope_shrunk")
		return ErrAccessDenied
	}
	return nil
}

// authorizeSnapshotExport 复核机器可读快照导出：read + export 双权限与数据范围。
func (s *Service) authorizeSnapshotExport(ctx context.Context, caller account.Caller,
	record reportRecord) error {
	for _, permission := range []string{PermissionRead, PermissionExport} {
		grant, err := s.authorizeScope(ctx, caller, permission, record.ScopeID)
		if err != nil {
			return err
		}
		if !s.grantCovers(record.DataScope, grant) {
			s.recordDenied(ctx, caller.Actor(), record.ScopeID, permission, "data_scope_shrunk")
			return ErrAccessDenied
		}
	}
	return nil
}

// view 构造报告视图；permission 决定使用哪个权限键做查看/导出授权。
func (s *Service) view(ctx context.Context, reportID string, caller account.Caller,
	permission string) (ReportView, error) {
	record, found := s.get(reportID)
	if !found {
		// 进程内记录未命中（例如进程重启）时回源持久历史；回源不跳过任何当前
		// 权限与数据范围检查，旧 ID 在失权后仍返回拒绝。
		if !s.historyAvailable() {
			return ReportView{}, ErrNotFound
		}
		historyRecord, err := s.historyForRead(ctx, caller, reportID)
		if err != nil {
			return ReportView{}, err
		}
		return s.historyReportView(ctx, caller, historyRecord), nil
	}
	grant, err := s.authorizeScope(ctx, caller, permission, record.ScopeID)
	if err != nil {
		return ReportView{}, err
	}
	if !s.grantCovers(record.DataScope, grant) {
		s.recordDenied(ctx, caller.Actor(), record.ScopeID, permission, "data_scope_shrunk")
		return ReportView{}, ErrAccessDenied
	}
	return s.viewFromRecord(ctx, record), nil
}

// viewFromRecord 把记录转换为公开视图并附带真实任务状态摘要。
func (s *Service) viewFromRecord(ctx context.Context, record reportRecord) ReportView {
	view := ReportView{
		ID: record.ID, ScopeID: record.ScopeID, ScopeKind: record.ScopeKind,
		State: record.State, Formats: append([]Format(nil), record.Formats...),
		RequestedBy: record.RequestedBy, CreatedAt: record.CreatedAt,
		StartedAt: record.StartedAt, FinishedAt: record.FinishedAt,
		TaskID: record.TaskID, ExecutorID: record.ExecutorID,
		ErrorCode: record.ErrorCode, FailureReason: record.FailureReason,
		RequestID: record.RequestID, ArtifactExpiresAt: record.ExpiresAt,
		SchemaVersion: SchemaVersion, TemplateVersion: TemplateVersion,
		RetryOf: record.RetryOf,
	}
	if record.Snapshot != nil {
		view.GeneratedAt = record.Snapshot.Report.GeneratedAt
		view.OverallStatus = string(record.Snapshot.Overall)
		view.Completeness = record.Snapshot.Completeness
		view.Notes = append([]string(nil), record.Snapshot.Notes...)
		view.Summary = ReportSummary{
			ActiveUsers:    record.Snapshot.Activity.Total,
			TotalRawEvents: record.Snapshot.Errors.TotalRawEvents,
			FailedRequests: record.Snapshot.Errors.FailedRequests,
			FailedTasks:    record.Snapshot.Errors.FailedTasks,
			DetailRows:     len(record.Snapshot.Errors.Rows),
			TrendPoints:    len(record.Snapshot.Trend.Points),
		}
	}
	if record.State == StateSucceeded {
		view.Artifacts = make([]ArtifactView, 0, len(record.Artifacts))
		now := s.now()
		for _, format := range record.Formats {
			artifact, exists := record.Artifacts[format]
			if !exists {
				continue
			}
			view.Artifacts = append(view.Artifacts, ArtifactView{
				Format: format, Bytes: artifact.Bytes, SHA256: artifact.SHA256,
				Available: now.Before(artifact.ExpiresAt), ExpiresAt: artifact.ExpiresAt,
			})
		}
	}
	if s.opts.Tasks != nil && record.TaskID != "" {
		// 真实 *task.Executor.Get 在任务不存在时返回错误；视图按“无任务摘要”
		// 处理，不把可选读取失败升级成报告查询失败。
		job, err := s.opts.Tasks.Get(ctx, record.TaskID)
		if err == nil {
			view.Task = &TaskSummary{ID: job.ID, Kind: job.Kind,
				State: string(job.State), Initiator: job.Initiator,
				ExecutorID: job.ExecutorID, Attempt: job.Attempt,
				MaxAttempts: job.MaxAttempts, ErrorCode: job.ErrorCode,
				FailureReason: job.FailureReason, RequestID: job.RequestID,
				CreatedAt: job.CreatedAt, StartedAt: job.StartedAt,
				FinishedAt: job.FinishedAt}
		}
	}
	return view
}

// resolvedArtifact 是“已通过当前鉴权与产物校验”的下载解析结果；它只在打开文件
// 与签发/兑换短期下载令牌时内部使用，不含公开 API 语义。
type resolvedArtifact struct {
	file      ArtifactFile
	scopeID   string
	requestID string
}

// resolveArtifact 复核下载权限并打开受控产物（不写下载审计）。进程内记录未命中
// 时回源持久历史；回源同样按当前权限与生成时数据范围重新授权。它供 OpenFile 与
// 下载令牌签发共用，避免两套鉴权语义。
func (s *Service) resolveArtifact(ctx context.Context, caller account.Caller,
	reportID string, format Format) (resolvedArtifact, error) {
	if !validReportID(reportID) {
		return resolvedArtifact{}, fmt.Errorf("%w: 报告编号格式无效", ErrInvalidRequest)
	}
	if !format.Valid() {
		return resolvedArtifact{}, fmt.Errorf("%w: 报告格式未定义", ErrInvalidRequest)
	}
	record, found := s.get(reportID)
	if !found {
		// 进程重启后内存记录不存在：回源持久历史并重新授权；历史能力未装配时
		// 按不存在处理，不伪造可下载状态。
		return s.resolveHistoryArtifact(ctx, caller, reportID, format)
	}
	// 下载同时要求查看与导出权限：撤销 reports.read 后不得继续下载已生成产物。
	readGrant, err := s.authorizeScope(ctx, caller, PermissionRead, record.ScopeID)
	if err != nil {
		return resolvedArtifact{}, err
	}
	if !s.grantCovers(record.DataScope, readGrant) {
		s.recordDenied(ctx, caller.Actor(), record.ScopeID, PermissionRead, "data_scope_shrunk")
		return resolvedArtifact{}, ErrAccessDenied
	}
	grant, err := s.authorizeScope(ctx, caller, PermissionExport, record.ScopeID)
	if err != nil {
		return resolvedArtifact{}, err
	}
	if !s.grantCovers(record.DataScope, grant) {
		s.recordDenied(ctx, caller.Actor(), record.ScopeID, PermissionExport, "data_scope_shrunk")
		return resolvedArtifact{}, ErrAccessDenied
	}
	if record.RequestedBy != caller.Actor() && !s.isRoot(ctx, caller) {
		s.recordFailure(ctx, caller.Actor(), ActionExportDownload, record.ScopeID,
			"download_not_owner", CodeReportAccessDenied, record.RequestID, reportID)
		return resolvedArtifact{}, ErrAccessDenied
	}
	if record.State != StateSucceeded {
		return resolvedArtifact{}, fmt.Errorf("%w: 报告尚未成功完成", ErrConflict)
	}
	artifact, exists := record.Artifacts[format]
	if !exists {
		return resolvedArtifact{}, fmt.Errorf("%w: 该格式产物不存在", ErrNotFound)
	}
	now := s.now()
	if artifact.ExpiresAt.IsZero() || !now.Before(artifact.ExpiresAt) {
		return resolvedArtifact{}, fmt.Errorf("%w: 报告产物已过期", ErrConflict)
	}
	path, err := s.openArtifact(artifact)
	if err != nil {
		return resolvedArtifact{}, err
	}
	return resolvedArtifact{
		file: ArtifactFile{ReportID: reportID, Format: format, HostPath: path,
			Bytes: artifact.Bytes, SHA256: artifact.SHA256,
			ExpiresAt: artifact.ExpiresAt},
		scopeID: record.ScopeID, requestID: record.RequestID,
	}, nil
}

// OpenFile 返回受控报告产物的宿主下载句柄（路径只给宿主文件流）。下载再次鉴权
// 并复核数据范围；只有成功、产物存在、未过期且当前权限覆盖生成时范围才允许；
// 产物绑定发起者或 root（最小可见原则）。产物摘要不符拒绝下发。
func (s *Service) OpenFile(ctx context.Context, caller account.Caller,
	reportID string, format Format) (ArtifactFile, error) {
	resolved, err := s.resolveArtifact(ctx, caller, reportID, format)
	if err != nil {
		return ArtifactFile{}, err
	}
	// 下载是真正的“导出”动作：成功必须留下审计；审计不可用时拒绝下发句柄
	// （fail-closed），不出现“文件已交宿主但无持久审计”的静默导出。
	event := audit.Event{
		Actor: caller.Actor(), AppID: appIDForScope(resolved.scopeID),
		Action: ActionExportDownload, Target: audit.Target{Type: "report", ID: reportID},
		Outcome: audit.OutcomeSuccess, RequestID: resolved.requestID,
		Changes: []audit.FieldChange{{Field: "format", After: string(format)}},
	}
	if err := s.opts.Audit.Record(ctx, event); err != nil {
		return ArtifactFile{}, fmt.Errorf("%w: 下载审计写入失败", ErrAuditUnavailable)
	}
	return resolved.file, nil
}

// Cancel 请求取消报告生成任务。提交取消请求不等于实际取消；真实终态以任务状态
// 为准。queued 任务被取消时收敛为取消终态并清理本次产物，重复取消幂等。
func (s *Service) Cancel(ctx context.Context, caller account.Caller, reportID,
	reason, requestID string) (task.CancelResult, error) {
	requestID = normalizeRequestID(requestID)
	if !validReportID(reportID) {
		return task.CancelResult{}, fmt.Errorf("%w: 报告编号格式无效", ErrInvalidRequest)
	}
	record, found := s.get(reportID)
	if !found {
		return task.CancelResult{}, ErrNotFound
	}
	grant, err := s.authorizeScope(ctx, caller, PermissionGenerate, record.ScopeID)
	if err != nil {
		return task.CancelResult{}, err
	}
	if !s.grantCovers(record.DataScope, grant) {
		s.recordDenied(ctx, caller.Actor(), record.ScopeID, PermissionGenerate, "data_scope_shrunk")
		return task.CancelResult{}, ErrAccessDenied
	}
	if record.RequestedBy != caller.Actor() && !s.isRoot(ctx, caller) {
		s.recordFailure(ctx, caller.Actor(), ActionGenerateCancel, record.ScopeID,
			"cancel_not_owner", CodeReportAccessDenied, requestID, reportID)
		return task.CancelResult{}, ErrAccessDenied
	}
	if err := validateReason(reason); err != nil {
		return task.CancelResult{}, err
	}
	if record.TaskID == "" {
		return task.CancelResult{}, fmt.Errorf("%w: 报告任务尚未取得任务编号", ErrConflict)
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
		Action: ActionGenerateCancel, Target: audit.Target{Type: "report", ID: reportID},
		Outcome: audit.OutcomeSuccess, RequestID: requestID,
		Changes: []audit.FieldChange{{Field: "cancel_requested", After: "true"}},
	}
	if err := s.opts.Audit.Record(ctx, event); err != nil {
		s.opts.Logger.Warn("报告取消请求审计写入失败", "code", string(CodeAuditWriteFailed))
	}
	// queued 任务被取消时执行器直接置 cancelled 且不再调用处理器；必须在这里
	// 收敛记录并清理任何已写产物，避免“已取消但仍可下载”。
	if result.State == task.StateCancelled {
		s.finalizeCancelled(ctx, reportID, record.RequestID)
	}
	return result, nil
}

// failRun 把记录写为失败终态并保留真实错误码；返回原始错误。
func (s *Service) failRun(ctx context.Context, reportID string, cause error,
	code ErrorCode, reason, requestID string) error {
	finalCtx := context.WithoutCancel(ctx)
	s.failRecord(finalCtx, reportID, cause, code, reason, requestID)
	return cause
}

// failRecord 条件写入失败终态；已处于终态时不覆盖（晚到失败不能改写真实取消）。
func (s *Service) failRecord(ctx context.Context, reportID string, cause error,
	code ErrorCode, reason, requestID string) {
	var record reportRecord
	found := s.mutate(reportID, func(current *reportRecord) bool {
		if current.State == StateFailed || current.State == StateCancelled ||
			current.State == StateSucceeded {
			return false
		}
		current.State = StateFailed
		current.ErrorCode = string(code)
		current.FailureReason = safeReason(reason)
		current.FinishedAt = s.now()
		record = *current
		return true
	})
	if !found {
		return
	}
	s.recordFailure(ctx, record.RequestedBy, ActionGenerateFinish, record.ScopeID,
		string(code), code, requestID, reportID)
	s.persistHistory(ctx, reportID)
	s.notifyReportResult(ctx, reportID)
}

// cancelRun 把记录写为真实取消终态并清理产物。
func (s *Service) cancelRun(ctx context.Context, reportID, requestID string) {
	s.finalizeCancelled(context.WithoutCancel(ctx), reportID, requestID)
}

// finalizeCancelled 收敛为取消终态（queued/running→cancelled），清理产物并写审计。
func (s *Service) finalizeCancelled(ctx context.Context, reportID, requestID string) {
	var record reportRecord
	var stale []Artifact
	s.mutate(reportID, func(current *reportRecord) bool {
		if current.State == StateCancelled {
			return false
		}
		if current.State == StateSucceeded || current.State == StateFailed {
			return false
		}
		current.State = StateCancelled
		current.ErrorCode = string(CodeTaskCancelled)
		current.FailureReason = "任务已取消"
		current.FinishedAt = s.now()
		for _, artifact := range current.Artifacts {
			stale = append(stale, artifact)
		}
		current.Artifacts = nil
		record = *current
		return true
	})
	if record.ID == "" {
		return
	}
	s.cleanupArtifacts(stale)
	s.recordFailure(ctx, record.RequestedBy, ActionGenerateFinish, record.ScopeID,
		"cancelled", CodeTaskCancelled, requestID, reportID)
	s.persistHistory(ctx, reportID)
	s.notifyReportResult(ctx, reportID)
}

// parseScope 解析作用范围："system" 或应用 ID。
func parseScope(raw string) (ScopeInfo, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ScopeInfo{}, fmt.Errorf("%w: 作用范围不能为空", ErrInvalidRequest)
	}
	if trimmed == ScopeSystem {
		return ScopeInfo{ID: ScopeSystem, Kind: "system"}, nil
	}
	if !validToken(trimmed, 64) {
		return ScopeInfo{}, fmt.Errorf("%w: 作用范围格式无效", ErrInvalidRequest)
	}
	return ScopeInfo{ID: trimmed, Kind: "app"}, nil
}

// validateAppFilter 校验显式应用筛选不越权（与统计服务同一语义）。
func validateAppFilter(appID string, scope ScopeInfo, grant stats.ScopeGrant) error {
	if appID == "" {
		return nil
	}
	if !validToken(appID, 64) {
		return fmt.Errorf("%w: 应用 ID 格式无效", ErrInvalidRequest)
	}
	if scope.Kind == "app" {
		if appID != scope.ID {
			return fmt.Errorf("%w: 不能生成当前作用范围以外的应用报告", ErrAccessDenied)
		}
		return nil
	}
	if !grant.AllData && !containsString(grant.ResourceIDs, appID) {
		return fmt.Errorf("%w: 不能生成当前数据范围以外的应用报告", ErrAccessDenied)
	}
	return nil
}

// normalizeCategories 校验并去重类别筛选。
func normalizeCategories(categories []stats.Category) ([]stats.Category, error) {
	if len(categories) == 0 {
		return nil, nil
	}
	seen := make(map[stats.Category]bool, len(categories))
	result := make([]stats.Category, 0, len(categories))
	for _, category := range categories {
		if !category.Valid() {
			return nil, fmt.Errorf("%w: 错误类别未定义", ErrInvalidRequest)
		}
		if seen[category] {
			continue
		}
		seen[category] = true
		result = append(result, category)
	}
	return result, nil
}

// normalizeTrendMetric 校验趋势指标；空值为原始事件次数。
func normalizeTrendMetric(metric stats.Metric) (stats.Metric, error) {
	if metric == "" {
		return stats.MetricRawEvents, nil
	}
	switch metric {
	case stats.MetricRawEvents, stats.MetricDedupFailedRequests, stats.MetricDedupFailedTasks:
		return metric, nil
	default:
		return "", fmt.Errorf("%w: 趋势指标未登记", ErrInvalidRequest)
	}
}

// validToken 校验稳定标识：非空、长度受限、只含 ASCII 字母/数字与 . _ -。
func validToken(value string, max int) bool {
	if value == "" || len(value) > max {
		return false
	}
	for index := 0; index < len(value); index++ {
		c := value[index]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') &&
			c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// validReportID 校验报告编号格式（rpt_ + 32 位小写十六进制）。
func validReportID(id string) bool {
	return validToken(id, 128) && strings.HasPrefix(id, reportIDPrefix) &&
		len(id) == len(reportIDPrefix)+2*idRandomBytes
}

// payloadReportIDFromJob 解析任务载荷中的报告编号。
func payloadReportIDFromJob(job task.Job) (string, error) {
	var payload payloadReportID
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return "", fmt.Errorf("%w: 报告任务载荷无效", ErrInvalidRequest)
	}
	if !validReportID(payload.ReportID) {
		return "", fmt.Errorf("%w: 报告编号格式无效", ErrInvalidRequest)
	}
	return payload.ReportID, nil
}

// insert 保存新记录。
func (s *Service) insert(record *reportRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[record.ID] = record
}

// get 返回记录副本（产物映射与筛选切片都是副本，避免调用方修改内部状态）。
func (s *Service) get(reportID string) (reportRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, found := s.records[reportID]
	if !found {
		return reportRecord{}, false
	}
	return cloneRecord(record), true
}

// mutate 在锁内修改记录；mutate 返回 false 表示状态不允许修改。
func (s *Service) mutate(reportID string, mutate func(*reportRecord) bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, found := s.records[reportID]
	if !found {
		return false
	}
	return mutate(record)
}

// cloneRecord 复制记录的可变部分。
func cloneRecord(record *reportRecord) reportRecord {
	clone := *record
	clone.Formats = append([]Format(nil), record.Formats...)
	clone.Categories = append([]stats.Category(nil), record.Categories...)
	clone.DataScope = dataScope{All: record.DataScope.All,
		Resources: append([]string(nil), record.DataScope.Resources...)}
	if record.Artifacts != nil {
		clone.Artifacts = make(map[Format]Artifact, len(record.Artifacts))
		for format, artifact := range record.Artifacts {
			clone.Artifacts[format] = artifact
		}
	}
	return clone
}
