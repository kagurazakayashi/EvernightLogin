package adminapi

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/auditops"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// actorDTO 是审计操作者的公开投影（只含可信类型与稳定 ID）。
type actorDTO struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

func toActorDTO(actor audit.Actor) actorDTO {
	return actorDTO{Type: string(actor.Type), ID: actor.ID}
}

// targetDTO 是审计目标的公开投影。
type targetDTO struct {
	Type string `json:"type"`
	ID   string `json:"id,omitempty"`
}

// auditEventDTO 是审计事件的公开投影：不包含原始正文、请求内容或任何秘密，
// 变更差异已在写入期脱敏。
type auditEventDTO struct {
	ID         string        `json:"id"`
	OccurredAt time.Time     `json:"occurred_at"`
	Actor      actorDTO      `json:"actor"`
	AppID      string        `json:"app_id,omitempty"`
	Action     string        `json:"action"`
	Target     targetDTO     `json:"target"`
	Outcome    string        `json:"outcome"`
	ErrorCode  string        `json:"error_code,omitempty"`
	ReasonCode string        `json:"reason_code,omitempty"`
	RequestID  string        `json:"request_id,omitempty"`
	TaskID     string        `json:"task_id,omitempty"`
	Changes    []auditChange `json:"changes,omitempty"`
}

type auditChange struct {
	Field  string `json:"field"`
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
}

func toAuditEventDTO(event audit.Event, includeChanges bool) auditEventDTO {
	dto := auditEventDTO{
		ID: event.ID, OccurredAt: event.OccurredAt,
		Actor: toActorDTO(event.Actor), AppID: event.AppID, Action: event.Action,
		Target:  targetDTO{Type: event.Target.Type, ID: event.Target.ID},
		Outcome: string(event.Outcome), ErrorCode: event.ErrorCode,
		ReasonCode: event.ReasonCode, RequestID: event.RequestID, TaskID: event.TaskID,
	}
	if includeChanges {
		for _, change := range event.Changes {
			dto.Changes = append(dto.Changes, auditChange{
				Field: change.Field, Before: change.Before, After: change.After})
		}
	}
	return dto
}

// scopeDTO 是作用范围公开投影。
type scopeDTO struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}

func toScopeDTO(scope auditops.ScopeInfo) scopeDTO {
	return scopeDTO{ID: scope.ID, Kind: scope.Kind}
}

// retentionDTO 是审计保留期公开投影（运维信息，不是秘密）。
type retentionDTO struct {
	Days       int       `json:"days"`
	Configured bool      `json:"configured"`
	Version    int64     `json:"version"`
	Cutoff     time.Time `json:"cutoff"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func toRetentionDTO(info auditops.RetentionInfo) retentionDTO {
	return retentionDTO{Days: info.Days, Configured: info.Configured,
		Version: info.Version, Cutoff: info.Cutoff, UpdatedAt: info.UpdatedAt}
}

// taskSummaryDTO 是受控任务摘要（来自 internal/task 真实状态）。
type taskSummaryDTO struct {
	ID            string    `json:"id"`
	Kind          string    `json:"kind,omitempty"`
	State         string    `json:"state,omitempty"`
	ExecutorID    string    `json:"executor_id,omitempty"`
	Attempt       int       `json:"attempt,omitempty"`
	MaxAttempts   int       `json:"max_attempts,omitempty"`
	ErrorCode     string    `json:"error_code,omitempty"`
	FailureReason string    `json:"failure_reason,omitempty"`
	RequestID     string    `json:"request_id,omitempty"`
	CreatedAt     time.Time `json:"created_at,omitempty"`
	StartedAt     time.Time `json:"started_at,omitempty"`
	FinishedAt    time.Time `json:"finished_at,omitempty"`
}

func toTaskSummaryDTO(summary *auditops.TaskSummary) *taskSummaryDTO {
	if summary == nil {
		return nil
	}
	return &taskSummaryDTO{ID: summary.ID, Kind: summary.Kind, State: summary.State,
		ExecutorID: summary.ExecutorID, Attempt: summary.Attempt,
		MaxAttempts: summary.MaxAttempts, ErrorCode: summary.ErrorCode,
		FailureReason: summary.FailureReason, RequestID: summary.RequestID,
		CreatedAt: summary.CreatedAt, StartedAt: summary.StartedAt,
		FinishedAt: summary.FinishedAt}
}

// exportDTO 是审计导出任务公开投影：不包含宿主文件路径。
type exportDTO struct {
	ID            string          `json:"id"`
	ScopeID       string          `json:"scope_id"`
	ScopeKind     string          `json:"scope_kind"`
	Format        string          `json:"format"`
	State         string          `json:"state"`
	RequestedBy   actorDTO        `json:"requested_by"`
	MaxRows       int             `json:"max_rows"`
	RowCount      int             `json:"row_count"`
	Truncated     bool            `json:"truncated"`
	TaskID        string          `json:"task_id,omitempty"`
	FileAvailable bool            `json:"file_available"`
	FileExpiresAt time.Time       `json:"file_expires_at,omitempty"`
	ErrorCode     string          `json:"error_code,omitempty"`
	FailureReason string          `json:"failure_reason,omitempty"`
	RequestID     string          `json:"request_id,omitempty"`
	ExecutorID    string          `json:"executor_id,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
	StartedAt     time.Time       `json:"started_at,omitempty"`
	FinishedAt    time.Time       `json:"finished_at,omitempty"`
	Task          *taskSummaryDTO `json:"task,omitempty"`
}

func toExportDTO(view auditops.ExportView) exportDTO {
	return exportDTO{ID: view.ID, ScopeID: view.ScopeID, ScopeKind: view.ScopeKind,
		Format: string(view.Format), State: view.State,
		RequestedBy: toActorDTO(view.RequestedBy), MaxRows: view.MaxRows,
		RowCount: view.RowCount, Truncated: view.Truncated, TaskID: view.TaskID,
		FileAvailable: view.FileAvailable, FileExpiresAt: view.FileExpiresAt,
		ErrorCode: view.ErrorCode, FailureReason: view.FailureReason,
		RequestID: view.RequestID, ExecutorID: view.ExecutorID,
		CreatedAt: view.CreatedAt, StartedAt: view.StartedAt,
		FinishedAt: view.FinishedAt, Task: toTaskSummaryDTO(view.Task)}
}

// purgeRunDTO 是审计清理运行公开投影。
type purgeRunDTO struct {
	ID            string          `json:"id"`
	Kind          string          `json:"kind"`
	ScopeID       string          `json:"scope_id"`
	ScopeKind     string          `json:"scope_kind"`
	State         string          `json:"state"`
	TaskID        string          `json:"task_id,omitempty"`
	RequestedBy   actorDTO        `json:"requested_by"`
	Cutoff        time.Time       `json:"cutoff"`
	BatchSize     int             `json:"batch_size"`
	MaxRecords    int             `json:"max_records"`
	Scanned       int             `json:"scanned"`
	Cleaned       int             `json:"cleaned"`
	Skipped       int             `json:"skipped"`
	Failed        int             `json:"failed"`
	Batches       int             `json:"batches"`
	LimitReached  bool            `json:"limit_reached"`
	ErrorCode     string          `json:"error_code,omitempty"`
	FailureReason string          `json:"failure_reason,omitempty"`
	RequestID     string          `json:"request_id,omitempty"`
	ExecutorID    string          `json:"executor_id,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
	StartedAt     time.Time       `json:"started_at,omitempty"`
	FinishedAt    time.Time       `json:"finished_at,omitempty"`
	Task          *taskSummaryDTO `json:"task,omitempty"`
}

func toPurgeRunDTO(view auditops.PurgeRunView) purgeRunDTO {
	return purgeRunDTO{ID: view.ID, Kind: view.Kind, ScopeID: view.ScopeID,
		ScopeKind: view.ScopeKind, State: view.State, TaskID: view.TaskID,
		RequestedBy: toActorDTO(view.RequestedBy), Cutoff: view.Cutoff,
		BatchSize: view.BatchSize, MaxRecords: view.MaxRecords,
		Scanned: view.Scanned, Cleaned: view.Cleaned, Skipped: view.Skipped,
		Failed: view.Failed, Batches: view.Batches, LimitReached: view.LimitReached,
		ErrorCode: view.ErrorCode, FailureReason: view.FailureReason,
		RequestID: view.RequestID, ExecutorID: view.ExecutorID,
		CreatedAt: view.CreatedAt, StartedAt: view.StartedAt,
		FinishedAt: view.FinishedAt, Task: toTaskSummaryDTO(view.Task)}
}

// purgePreviewDTO 是审计清理预估公开投影（不是删除授权）。
type purgePreviewDTO struct {
	ScopeID              string       `json:"scope_id"`
	ScopeKind            string       `json:"scope_kind"`
	Cutoff               time.Time    `json:"cutoff"`
	BatchSize            int          `json:"batch_size"`
	MaxRecords           int          `json:"max_records"`
	EstimatedCount       int64        `json:"estimated_count"`
	AtLeast              bool         `json:"at_least"`
	Retention            retentionDTO `json:"retention"`
	WithinRetention      bool         `json:"within_retention"`
	MaintenanceProtected bool         `json:"maintenance_protected"`
	ArtifactsIncluded    bool         `json:"artifacts_included"`
	Digest               string       `json:"digest"`
	GeneratedAt          time.Time    `json:"generated_at"`
}

// auditProblem 把审计领域错误映射为统一 problem（复用根包既有错误码）。
func (s *Server) auditProblem(err error) *problem {
	code := string(auditops.CodeOf(err))
	if code == "" {
		code = string(codeInternalError)
	}
	return s.codeProblem(code, err)
}

// filterInput 是审计筛选的请求投影；所有字段白名单精确匹配或时间区间。
type filterInput struct {
	From       string `json:"from"`
	To         string `json:"to"`
	AppID      string `json:"app_id"`
	SystemOnly bool   `json:"system_only"`
	ActorType  string `json:"actor_type"`
	ActorID    string `json:"actor_id"`
	Action     string `json:"action"`
	Outcome    string `json:"outcome"`
	ErrorCode  string `json:"error_code"`
	RequestID  string `json:"request_id"`
	TaskID     string `json:"task_id"`
	TargetType string `json:"target_type"`
	TargetID   string `json:"target_id"`
}

// parse 把请求投影转换为服务层筛选；时间必须是 RFC3339，枚举值由服务层复核。
func (input filterInput) parse() (auditops.Filter, error) {
	filter := auditops.Filter{
		AppID: input.AppID, SystemOnly: input.SystemOnly,
		ActorType: audit.ActorKind(input.ActorType), ActorID: input.ActorID,
		Action: input.Action, Outcome: audit.Outcome(input.Outcome),
		ErrorCode: input.ErrorCode, RequestID: input.RequestID,
		TaskID: input.TaskID, TargetType: input.TargetType, TargetID: input.TargetID,
	}
	var err error
	if filter.From, err = parseRFC3339(input.From); err != nil {
		return auditops.Filter{}, err
	}
	if filter.To, err = parseRFC3339(input.To); err != nil {
		return auditops.Filter{}, err
	}
	return filter, nil
}

// parseRFC3339 解析可选时间参数；空字符串返回零值。
func parseRFC3339(raw string) (time.Time, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return time.Time{}, nil
	}
	value, err := time.Parse(time.RFC3339, trimmed)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: 时间必须是 RFC3339 格式", ErrInvalidRequest)
	}
	return value.UTC(), nil
}

// parseOrder 把查询参数映射为审计稳定排序；未知值由服务层拒绝。
func parseOrder(raw string) (auditops.SortOrder, error) {
	switch strings.TrimSpace(raw) {
	case "":
		return "", nil
	case string(auditops.SortNewestFirst):
		return auditops.SortNewestFirst, nil
	case string(auditops.SortOldestFirst):
		return auditops.SortOldestFirst, nil
	default:
		return "", fmt.Errorf("%w: 排序参数无效", ErrInvalidRequest)
	}
}

// handleAuditEventList 处理 GET /audit/events：管理查询由服务层按当前权限与数据
// 范围重新授权，并拒绝跨范围筛选。
func (s *Server) handleAuditEventList(c *callContext) error {
	limit, offset, err := pageParams(c.request)
	if err != nil {
		return err
	}
	scopeID, err := queryString(c.request, "scope_id", 64)
	if err != nil {
		return err
	}
	if scopeID == "" {
		scopeID = auditops.ScopeSystem
	}
	order, err := parseOrder(c.request.URL.Query().Get("order"))
	if err != nil {
		return err
	}
	filter := auditops.Filter{
		AppID:      firstNonEmpty(c.request.URL.Query().Get("app_id")),
		ActorType:  audit.ActorKind(c.request.URL.Query().Get("actor_type")),
		ActorID:    c.request.URL.Query().Get("actor_id"),
		Action:     c.request.URL.Query().Get("action"),
		Outcome:    audit.Outcome(c.request.URL.Query().Get("outcome")),
		ErrorCode:  c.request.URL.Query().Get("error_code"),
		RequestID:  c.request.URL.Query().Get("request_id"),
		TaskID:     c.request.URL.Query().Get("task_id"),
		TargetType: c.request.URL.Query().Get("target_type"),
		TargetID:   c.request.URL.Query().Get("target_id"),
	}
	systemOnly, err := queryBool(c.request, "system_only")
	if err != nil {
		return err
	}
	filter.SystemOnly = systemOnly
	if filter.From, err = queryTime(c.request, "from"); err != nil {
		return err
	}
	if filter.To, err = queryTime(c.request, "to"); err != nil {
		return err
	}
	cursor, err := queryString(c.request, "cursor", 4096)
	if err != nil {
		return err
	}
	result, err := s.audit.Query(c.request.Context(), auditops.QueryRequest{
		Caller: c.caller, ScopeID: scopeID, Filter: filter, Order: order,
		Limit: limit, Offset: offset, Cursor: cursor})
	if err != nil {
		return s.auditProblem(err)
	}
	events := make([]auditEventDTO, 0, len(result.Events))
	for _, event := range result.Events {
		events = append(events, toAuditEventDTO(event, false))
	}
	payload := map[string]any{
		"events": events, "has_more": result.HasMore,
		"limit": result.Limit, "offset": result.Offset,
		"order": string(result.Order), "scope": toScopeDTO(result.Scope),
		"retention": toRetentionDTO(result.Retention),
	}
	if result.NextCursor != "" {
		payload["next_cursor"] = result.NextCursor
	}
	s.writeSuccess(c.writer, c.requestID, payload)
	return nil
}

// handleAuditEventGet 处理 GET /audit/events/{event_id}：详情包含已脱敏的字段变更。
func (s *Server) handleAuditEventGet(c *callContext) error {
	eventID := c.pathParam("event_id")
	if strings.TrimSpace(eventID) == "" || len(eventID) > 128 {
		return fmt.Errorf("%w: 事件编号无效", ErrInvalidRequest)
	}
	occurredAtHint, err := queryTime(c.request, "occurred_at_hint")
	if err != nil {
		return err
	}
	scopeID, err := queryString(c.request, "scope_id", 64)
	if err != nil {
		return err
	}
	if scopeID == "" {
		scopeID = auditops.ScopeSystem
	}
	detail, err := s.audit.GetEvent(c.request.Context(), auditops.GetRequest{
		Caller: c.caller, ScopeID: scopeID, EventID: eventID,
		OccurredAtHint: occurredAtHint})
	if err != nil {
		return s.auditProblem(err)
	}
	event := toAuditEventDTO(detail.Event, true)
	s.writeSuccess(c.writer, c.requestID, map[string]any{
		"event": event, "scope": toScopeDTO(detail.Scope),
		"retention": toRetentionDTO(detail.Retention), "stale": detail.Stale})
	return nil
}

// handleAuditRetentionGet 处理 GET /audit/retention。
func (s *Server) handleAuditRetentionGet(c *callContext) error {
	info, err := s.audit.Retention(c.request.Context(), c.caller)
	if err != nil {
		return s.auditProblem(err)
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{"retention": toRetentionDTO(info)})
	return nil
}

// handleAuditExportList 处理 GET /audit/exports。
func (s *Server) handleAuditExportList(c *callContext) error {
	limit, offset, err := pageParams(c.request)
	if err != nil {
		return err
	}
	scopeID, err := queryString(c.request, "scope_id", 64)
	if err != nil {
		return err
	}
	if scopeID == "" {
		scopeID = auditops.ScopeSystem
	}
	state, err := queryString(c.request, "state", 32)
	if err != nil {
		return err
	}
	views, hasMore, err := s.audit.ListExports(c.request.Context(), auditops.ExportListRequest{
		Caller: c.caller, ScopeID: scopeID, State: state, Limit: limit, Offset: offset})
	if err != nil {
		return s.auditProblem(err)
	}
	exports := make([]exportDTO, 0, len(views))
	for _, view := range views {
		exports = append(exports, toExportDTO(view))
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{
		"exports": exports, "has_more": hasMore, "limit": limit, "offset": offset})
	return nil
}

// handleAuditExportGet 处理 GET /audit/exports/{export_id}。
func (s *Server) handleAuditExportGet(c *callContext) error {
	view, err := s.audit.GetExport(c.request.Context(), c.caller, c.pathParam("export_id"))
	if err != nil {
		return s.auditProblem(err)
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{"export": toExportDTO(view)})
	return nil
}

// exportStartInput 是创建审计导出请求体；确认语义与幂等请求编号由服务端记录。
type exportStartInput struct {
	Confirm   bool        `json:"confirm"`
	ScopeID   string      `json:"scope_id"`
	Format    string      `json:"format"`
	MaxRows   int         `json:"max_rows"`
	Order     string      `json:"order"`
	RequestID string      `json:"request_id"`
	Filter    filterInput `json:"filter"`
}

// handleAuditExportStart 处理 POST /audit/exports：导出是独立敏感操作（服务层
// 校验 audit.export 权限 + 敏感策略再次认证），并写真实审计。
func (s *Server) handleAuditExportStart(c *callContext) error {
	var input exportStartInput
	if err := c.decodeJSON(&input); err != nil {
		return err
	}
	if err := requireConfirm(input.Confirm); err != nil {
		return err
	}
	filter, err := input.Filter.parse()
	if err != nil {
		return err
	}
	order, err := parseOrder(input.Order)
	if err != nil {
		return err
	}
	if input.ScopeID == "" {
		input.ScopeID = auditops.ScopeSystem
	}
	view, err := s.audit.StartExport(c.request.Context(), auditops.StartExportRequest{
		Caller: c.caller, ScopeID: input.ScopeID, Filter: filter, Order: order,
		Format: auditops.ExportFormat(input.Format), MaxRows: input.MaxRows,
		RequestID: firstNonEmpty(input.RequestID, c.requestID)})
	if err != nil {
		return s.auditProblem(err)
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{"export": toExportDTO(view)})
	return nil
}

// cancelInput 是取消类写操作的请求体（需确认与原因）。
type cancelInput struct {
	Confirm bool   `json:"confirm"`
	Reason  string `json:"reason"`
}

// parseCancel 校验确认与原因。
func (input cancelInput) parse() (string, error) {
	if err := requireConfirm(input.Confirm); err != nil {
		return "", err
	}
	return requireReason(input.Reason)
}

// handleAuditExportCancel 处理 POST /audit/exports/{export_id}/cancel。取消请求
// 被接受不等于导出已取消，响应如实返回任务状态。
func (s *Server) handleAuditExportCancel(c *callContext) error {
	var input cancelInput
	if err := c.decodeJSON(&input); err != nil {
		return err
	}
	reason, err := input.parse()
	if err != nil {
		return err
	}
	result, err := s.audit.CancelExport(c.request.Context(), c.caller,
		c.pathParam("export_id"), reason, c.requestID)
	if err != nil {
		return s.auditProblem(err)
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{"cancel": toCancelDTO(result)})
	return nil
}

// cancelResultDTO 是任务取消结果公开投影：请求被接受不等于实际取消。
type cancelResultDTO struct {
	State            string `json:"state"`
	Accepted         bool   `json:"accepted"`
	AlreadyRequested bool   `json:"already_requested"`
}

func toCancelDTO(result task.CancelResult) cancelResultDTO {
	return cancelResultDTO{State: string(result.State), Accepted: result.Accepted,
		AlreadyRequested: result.AlreadyRequested}
}

// handleAuditExportDownload 处理 GET /audit/exports/{export_id}/download：服务层
// 每次重新授权并复核产物可下载状态；响应只输出文件字节，不输出宿主路径。
func (s *Server) handleAuditExportDownload(c *callContext) error {
	file, err := s.audit.OpenExportFile(c.request.Context(), c.caller, c.pathParam("export_id"))
	if err != nil {
		return s.auditProblem(err)
	}
	return s.streamExportFile(c, file)
}

// streamExportFile 流式输出受控导出产物；文件名由本包生成，不使用宿主路径。
func (s *Server) streamExportFile(c *callContext, file auditops.ExportFile) error {
	handle, err := os.Open(file.HostPath)
	if err != nil {
		return s.codeProblem(string(codeInternalError), err)
	}
	defer handle.Close()
	contentType := "application/octet-stream"
	extension := "bin"
	switch file.Format {
	case auditops.FormatCSV:
		contentType = "text/csv; charset=utf-8"
		extension = "csv"
	case auditops.FormatJSON:
		contentType = "application/json; charset=utf-8"
		extension = "json"
	}
	header := c.writer.Header()
	header.Set("Content-Type", contentType)
	header.Set("Cache-Control", "no-store")
	header.Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="audit-export-%s.%s"`, safeFileID(file.ID), extension))
	if file.Size > 0 {
		header.Set("Content-Length", fmt.Sprintf("%d", file.Size))
	}
	c.writer.WriteHeader(http.StatusOK)
	_, copyErr := io.Copy(c.writer, io.LimitReader(handle, file.Size+1))
	return copyErr
}

// safeFileID 把对象编号限制为可安全放进响应头的字符集。
func safeFileID(id string) string {
	var builder strings.Builder
	for _, character := range id {
		switch {
		case character >= 'a' && character <= 'z',
			character >= 'A' && character <= 'Z',
			character >= '0' && character <= '9', character == '-', character == '_':
			builder.WriteRune(character)
		}
		if builder.Len() >= 64 {
			break
		}
	}
	if builder.Len() == 0 {
		return "artifact"
	}
	return builder.String()
}

// handleAuditPurgeList 处理 GET /audit/purge-runs：root 专属读取由服务层判定。
func (s *Server) handleAuditPurgeList(c *callContext) error {
	limit, offset, err := pageParams(c.request)
	if err != nil {
		return err
	}
	kind, err := queryString(c.request, "kind", 32)
	if err != nil {
		return err
	}
	state, err := queryString(c.request, "state", 32)
	if err != nil {
		return err
	}
	views, hasMore, err := s.audit.ListPurgeRuns(c.request.Context(), auditops.PurgeListRequest{
		Caller: c.caller, Kind: kind, State: state, Limit: limit, Offset: offset})
	if err != nil {
		return s.auditProblem(err)
	}
	runs := make([]purgeRunDTO, 0, len(views))
	for _, view := range views {
		runs = append(runs, toPurgeRunDTO(view))
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{
		"purge_runs": runs, "has_more": hasMore, "limit": limit, "offset": offset})
	return nil
}

// handleAuditPurgeGet 处理 GET /audit/purge-runs/{run_id}。
func (s *Server) handleAuditPurgeGet(c *callContext) error {
	view, err := s.audit.GetPurgeRun(c.request.Context(), c.caller, c.pathParam("run_id"))
	if err != nil {
		return s.auditProblem(err)
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{"purge_run": toPurgeRunDTO(view)})
	return nil
}

// purgePreviewInput 是审计清理预估请求体（只读，不删除记录）。
type purgePreviewInput struct {
	ScopeID    string `json:"scope_id"`
	Cutoff     string `json:"cutoff"`
	BatchSize  int    `json:"batch_size"`
	MaxRecords int    `json:"max_records"`
}

// parse 解析并校验预估参数。
func (input purgePreviewInput) parse() (string, time.Time, int, int, error) {
	scopeID := input.ScopeID
	if scopeID == "" {
		scopeID = auditops.ScopeSystem
	}
	cutoff, err := parseRFC3339(input.Cutoff)
	if err != nil {
		return "", time.Time{}, 0, 0, err
	}
	if cutoff.IsZero() {
		return "", time.Time{}, 0, 0, fmt.Errorf("%w: 清理预估必须提供截止时间", ErrInvalidRequest)
	}
	return scopeID, cutoff, input.BatchSize, input.MaxRecords, nil
}

// handleAuditPurgePreview 处理 POST /audit/purge/preview：root 专属只读预估，
// 返回的 digest 是提交执行时必须原样带回的参数摘要（防止预览与执行不一致）。
func (s *Server) handleAuditPurgePreview(c *callContext) error {
	var input purgePreviewInput
	if err := c.decodeJSON(&input); err != nil {
		return err
	}
	scopeID, cutoff, batchSize, maxRecords, err := input.parse()
	if err != nil {
		return err
	}
	preview, err := s.audit.PreviewPurge(c.request.Context(), auditops.PurgePreviewRequest{
		Caller: c.caller, ScopeID: scopeID, Cutoff: cutoff,
		BatchSize: batchSize, MaxRecords: maxRecords, RequestID: c.requestID})
	if err != nil {
		return s.auditProblem(err)
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{
		"purge_preview": purgePreviewDTO{
			ScopeID: preview.ScopeID, ScopeKind: preview.ScopeKind,
			Cutoff: preview.Cutoff, BatchSize: preview.BatchSize,
			MaxRecords: preview.MaxRecords, EstimatedCount: preview.EstimatedCount,
			AtLeast: preview.AtLeast, Retention: toRetentionDTO(preview.Retention),
			WithinRetention:      preview.WithinRetention,
			MaintenanceProtected: preview.MaintenanceProtected,
			ArtifactsIncluded:    preview.ArtifactsIncluded, Digest: preview.Digest,
			GeneratedAt: preview.GeneratedAt},
	})
	return nil
}

// purgeStartInput 是提交审计清理任务请求体（root + 敏感策略 + 确认 + 原因）。
type purgeStartInput struct {
	Confirm    bool   `json:"confirm"`
	ScopeID    string `json:"scope_id"`
	Cutoff     string `json:"cutoff"`
	BatchSize  int    `json:"batch_size"`
	MaxRecords int    `json:"max_records"`
	Reason     string `json:"reason"`
	Digest     string `json:"digest"`
}

// handleAuditPurgeStart 处理 POST /audit/purge。
func (s *Server) handleAuditPurgeStart(c *callContext) error {
	var input purgeStartInput
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
	if strings.TrimSpace(input.Digest) == "" {
		return fmt.Errorf("%w: 缺少清理预估摘要 digest", ErrInvalidRequest)
	}
	scopeID, cutoff, batchSize, maxRecords, err := purgePreviewInput{
		ScopeID: input.ScopeID, Cutoff: input.Cutoff,
		BatchSize: input.BatchSize, MaxRecords: input.MaxRecords}.parse()
	if err != nil {
		return err
	}
	view, err := s.audit.StartPurge(c.request.Context(), auditops.StartPurgeRequest{
		Caller: c.caller, ScopeID: scopeID, Cutoff: cutoff, BatchSize: batchSize,
		MaxRecords: maxRecords, Reason: reason, Digest: input.Digest,
		RequestID: c.requestID})
	if err != nil {
		return s.auditProblem(err)
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{"purge_run": toPurgeRunDTO(view)})
	return nil
}

// handleAuditPurgeCancel 处理 POST /audit/purge/{run_id}/cancel。
func (s *Server) handleAuditPurgeCancel(c *callContext) error {
	var input cancelInput
	if err := c.decodeJSON(&input); err != nil {
		return err
	}
	reason, err := input.parse()
	if err != nil {
		return err
	}
	result, err := s.audit.CancelPurge(c.request.Context(), c.caller,
		c.pathParam("run_id"), reason, c.requestID)
	if err != nil {
		return s.auditProblem(err)
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{"cancel": toCancelDTO(result)})
	return nil
}

// retentionSetInput 是设置审计保留策略请求体（root + 敏感策略 + 版本并发）。
type retentionSetInput struct {
	Confirm         bool   `json:"confirm"`
	RetentionDays   int    `json:"retention_days"`
	Reason          string `json:"reason"`
	ExpectedVersion int64  `json:"expected_version"`
}

// handleAuditRetentionSet 处理 PUT /audit/retention。
func (s *Server) handleAuditRetentionSet(c *callContext) error {
	var input retentionSetInput
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
	info, err := s.audit.SetRetention(c.request.Context(), auditops.SetRetentionRequest{
		Caller: c.caller, RetentionDays: input.RetentionDays, Reason: reason,
		RequestID: c.requestID, ExpectedVersion: input.ExpectedVersion})
	if err != nil {
		return s.auditProblem(err)
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{"retention": toRetentionDTO(info)})
	return nil
}

// firstNonEmpty 返回第一个非空字符串（去掉首尾空白）。
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
