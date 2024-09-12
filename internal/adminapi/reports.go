package adminapi

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/reports"
)

// parseSearchFieldList 解析逗号分隔的搜索字段白名单；空表示使用领域默认字段。
// 具体字段合法性由领域层按白名单复核（未知字段 REQ_INVALID）。
func parseSearchFieldList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	fields := make([]string, 0, 2)
	for _, part := range strings.Split(raw, ",") {
		value := strings.TrimSpace(part)
		if value != "" {
			fields = append(fields, value)
		}
	}
	return fields
}

// reportHistoryDTO 是历史报告公开投影：受控元数据与产物可用性，不含宿主路径。
type reportHistoryDTO struct {
	ID            string        `json:"id"`
	PlanID        string        `json:"plan_id,omitempty"`
	Name          string        `json:"name,omitempty"`
	Owner         actorDTO      `json:"owner"`
	ScopeID       string        `json:"scope_id"`
	ScopeKind     string        `json:"scope_kind"`
	AppID         string        `json:"app_id,omitempty"`
	Template      string        `json:"template,omitempty"`
	State         string        `json:"state"`
	Formats       []string      `json:"formats,omitempty"`
	DetailRows    int           `json:"detail_rows"`
	Artifacts     []artifactDTO `json:"artifacts,omitempty"`
	TaskID        string        `json:"task_id,omitempty"`
	ExecutorID    string        `json:"executor_id,omitempty"`
	ErrorCode     string        `json:"error_code,omitempty"`
	FailureReason string        `json:"failure_reason,omitempty"`
	RequestID     string        `json:"request_id,omitempty"`
	CreatedAt     time.Time     `json:"created_at"`
	StartedAt     time.Time     `json:"started_at,omitempty"`
	FinishedAt    time.Time     `json:"finished_at,omitempty"`
	ExpiresAt     time.Time     `json:"expires_at,omitempty"`
	CleanupState  string        `json:"cleanup_state,omitempty"`
}

// artifactDTO 是报告产物摘要公开投影（不含路径）。
type artifactDTO struct {
	Format    string    `json:"format"`
	Bytes     int64     `json:"bytes"`
	SHA256    string    `json:"sha256"`
	Available bool      `json:"available"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

func toArtifactDTOs(artifacts []reports.ArtifactView) []artifactDTO {
	if len(artifacts) == 0 {
		return nil
	}
	converted := make([]artifactDTO, 0, len(artifacts))
	for _, artifact := range artifacts {
		converted = append(converted, artifactDTO{Format: string(artifact.Format),
			Bytes: artifact.Bytes, SHA256: artifact.SHA256,
			Available: artifact.Available, ExpiresAt: artifact.ExpiresAt})
	}
	return converted
}

// formatStrings 把报告格式枚举转换为稳定字符串切片。
func formatStrings(formats []reports.Format) []string {
	converted := make([]string, 0, len(formats))
	for _, format := range formats {
		converted = append(converted, string(format))
	}
	return converted
}

func toReportHistoryDTO(view reports.ReportHistoryView) reportHistoryDTO {
	return reportHistoryDTO{ID: view.ID, PlanID: view.PlanID, Name: view.Name,
		Owner: toActorDTO(view.Owner), ScopeID: view.ScopeID,
		ScopeKind: view.ScopeKind, AppID: view.AppID, Template: view.Template,
		State: view.State, Formats: formatStrings(view.Formats),
		DetailRows: view.DetailRows, Artifacts: toArtifactDTOs(view.Artifacts),
		TaskID: view.TaskID, ExecutorID: view.ExecutorID,
		ErrorCode: view.ErrorCode, FailureReason: view.FailureReason,
		RequestID: view.RequestID, CreatedAt: view.CreatedAt,
		StartedAt: view.StartedAt, FinishedAt: view.FinishedAt,
		ExpiresAt: view.ExpiresAt, CleanupState: view.CleanupState}
}

// reportViewDTO 是即时报告视图公开投影。
type reportViewDTO struct {
	ID                string        `json:"id"`
	ScopeID           string        `json:"scope_id"`
	ScopeKind         string        `json:"scope_kind"`
	State             string        `json:"state"`
	Formats           []string      `json:"formats,omitempty"`
	RequestedBy       actorDTO      `json:"requested_by"`
	CreatedAt         time.Time     `json:"created_at"`
	StartedAt         time.Time     `json:"started_at,omitempty"`
	FinishedAt        time.Time     `json:"finished_at,omitempty"`
	GeneratedAt       time.Time     `json:"generated_at,omitempty"`
	SchemaVersion     string        `json:"schema_version,omitempty"`
	TemplateVersion   int           `json:"template_version,omitempty"`
	OverallStatus     string        `json:"overall_status,omitempty"`
	Notes             []string      `json:"notes,omitempty"`
	Artifacts         []artifactDTO `json:"artifacts,omitempty"`
	ArtifactExpiresAt time.Time     `json:"artifact_expires_at,omitempty"`
	TaskID            string        `json:"task_id,omitempty"`
	ExecutorID        string        `json:"executor_id,omitempty"`
	ErrorCode         string        `json:"error_code,omitempty"`
	FailureReason     string        `json:"failure_reason,omitempty"`
	RequestID         string        `json:"request_id,omitempty"`
	RetryOf           string        `json:"retry_of,omitempty"`
}

func toReportViewDTO(view reports.ReportView) reportViewDTO {
	return reportViewDTO{ID: view.ID, ScopeID: view.ScopeID,
		ScopeKind: view.ScopeKind, State: view.State,
		Formats: formatStrings(view.Formats), RequestedBy: toActorDTO(view.RequestedBy),
		CreatedAt: view.CreatedAt, StartedAt: view.StartedAt,
		FinishedAt: view.FinishedAt, GeneratedAt: view.GeneratedAt,
		SchemaVersion: view.SchemaVersion, TemplateVersion: view.TemplateVersion,
		OverallStatus: view.OverallStatus, Notes: view.Notes,
		Artifacts:         toArtifactDTOs(view.Artifacts),
		ArtifactExpiresAt: view.ArtifactExpiresAt, TaskID: view.TaskID,
		ExecutorID: view.ExecutorID, ErrorCode: view.ErrorCode,
		FailureReason: view.FailureReason, RequestID: view.RequestID,
		RetryOf: view.RetryOf}
}

// planDTO 是报告计划公开投影。
type planDTO struct {
	ID                string    `json:"id"`
	ScheduleID        string    `json:"schedule_id"`
	Version           int64     `json:"version"`
	Name              string    `json:"name"`
	Enabled           bool      `json:"enabled"`
	PermissionState   string    `json:"permission_state,omitempty"`
	PermissionReason  string    `json:"permission_reason,omitempty"`
	ScheduleType      string    `json:"schedule_type"`
	Expression        string    `json:"expression"`
	TimeZone          string    `json:"time_zone"`
	PeriodDescription string    `json:"period_description,omitempty"`
	ScopeID           string    `json:"scope_id"`
	ScopeKind         string    `json:"scope_kind"`
	WindowDays        int       `json:"window_days"`
	Formats           []string  `json:"formats,omitempty"`
	DetailRows        int       `json:"detail_rows"`
	MaxCatchUp        int       `json:"max_catch_up"`
	TimeoutSeconds    int       `json:"timeout_seconds"`
	MaxAttempts       int       `json:"max_attempts"`
	Owner             actorDTO  `json:"owner"`
	ExecutionActor    actorDTO  `json:"execution_actor"`
	NextRun           time.Time `json:"next_run,omitempty"`
	NextRunUnknown    bool      `json:"next_run_unknown"`
	NextRunReason     string    `json:"next_run_reason,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

func toPlanDTO(view reports.PlanView) planDTO {
	return planDTO{ID: view.ID, ScheduleID: view.ScheduleID, Version: view.Version,
		Name: view.Name, Enabled: view.Enabled,
		PermissionState: view.PermissionState, PermissionReason: view.PermissionReason,
		ScheduleType: string(view.ScheduleType), Expression: view.Expression,
		TimeZone: view.TimeZone, PeriodDescription: view.PeriodDescription,
		ScopeID: view.ScopeID, ScopeKind: view.ScopeKind,
		WindowDays: view.WindowDays, Formats: formatStrings(view.Formats),
		DetailRows: view.DetailRows, MaxCatchUp: view.MaxCatchUp,
		TimeoutSeconds: view.TimeoutSeconds, MaxAttempts: view.MaxAttempts,
		Owner: toActorDTO(view.Owner), ExecutionActor: toActorDTO(view.ExecutionActor),
		NextRun: view.NextRun, NextRunUnknown: view.NextRunUnknown,
		NextRunReason: view.NextRunReason, CreatedAt: view.CreatedAt,
		UpdatedAt: view.UpdatedAt}
}

// retentionPolicyDTO 是报告文件保留策略公开说明（只读，不含宿主路径）。
type retentionPolicyDTO struct {
	ArtifactTTL    string `json:"artifact_ttl"`
	CleanupGrace   string `json:"cleanup_grace"`
	EligibleBefore string `json:"eligible_before,omitempty"`
	Source         string `json:"source"`
	HistoryNote    string `json:"history_note,omitempty"`
	RawAuditNote   string `json:"raw_audit_note,omitempty"`
}

func toRetentionPolicyDTO(policy reports.RetentionPolicy) retentionPolicyDTO {
	dto := retentionPolicyDTO{ArtifactTTL: policy.ArtifactTTL.String(),
		CleanupGrace: policy.CleanupGrace.String(), Source: policy.Source,
		HistoryNote: policy.HistoryNote, RawAuditNote: policy.RawAuditNote}
	if !policy.EligibleBefore.IsZero() {
		dto.EligibleBefore = policy.EligibleBefore.UTC().Format(time.RFC3339)
	}
	return dto
}

// reportCleanupPreviewDTO 是报告文件清理预览公开投影（不是删除授权）。
type reportCleanupPreviewDTO struct {
	Policy          retentionPolicyDTO `json:"policy"`
	Targets         []cleanupTargetDTO `json:"targets,omitempty"`
	TargetCount     int                `json:"target_count"`
	TotalBytes      int64              `json:"total_bytes"`
	Scopes          []string           `json:"scopes,omitempty"`
	OldestExpiresAt time.Time          `json:"oldest_expires_at,omitempty"`
	NewestExpiresAt time.Time          `json:"newest_expires_at,omitempty"`
	PreviewedAt     time.Time          `json:"previewed_at"`
	Note            string             `json:"note,omitempty"`
}

// cleanupTargetDTO 是单个到期报告目标公开投影。
type cleanupTargetDTO struct {
	ReportID      string    `json:"report_id"`
	PlanID        string    `json:"plan_id,omitempty"`
	Name          string    `json:"name,omitempty"`
	ScopeID       string    `json:"scope_id,omitempty"`
	State         string    `json:"state,omitempty"`
	CleanupState  string    `json:"cleanup_state,omitempty"`
	ExpiresAt     time.Time `json:"expires_at,omitempty"`
	Formats       []string  `json:"formats,omitempty"`
	ArtifactCount int       `json:"artifact_count"`
	Bytes         int64     `json:"bytes"`
}

// reportCleanupResultDTO 是报告清理真实结果公开投影：原始审计记录未被删除。
type reportCleanupResultDTO struct {
	Operator       actorDTO            `json:"operator"`
	StartedAt      time.Time           `json:"started_at"`
	FinishedAt     time.Time           `json:"finished_at"`
	RequestedCount int                 `json:"requested_count"`
	CleanedCount   int                 `json:"cleaned_count"`
	FailedCount    int                 `json:"failed_count"`
	DeletedFiles   int                 `json:"deleted_files"`
	FreedBytes     int64               `json:"freed_bytes"`
	SkippedCount   int                 `json:"skipped_count"`
	Failures       []cleanupFailureDTO `json:"failures,omitempty"`
	Policy         retentionPolicyDTO  `json:"policy"`
	RawAuditNote   string              `json:"raw_audit_note,omitempty"`
}

type cleanupFailureDTO struct {
	ReportID string `json:"report_id"`
	Reason   string `json:"reason"`
}

// reportProblem 把报告领域错误映射为统一 problem。
func (s *Server) reportProblem(err error) *problem {
	code := string(reports.CodeOf(err))
	if code == "" {
		code = string(codeInternalError)
	}
	return s.codeProblem(code, err)
}

// handleReportHistoryList 处理 GET /reports：当前权限范围实时推导，撤销权限后
// 不再返回对应历史；分页使用创建时间 + 编号游标。
func (s *Server) handleReportHistoryList(c *callContext) error {
	limit, _, err := pageParams(c.request)
	if err != nil {
		return err
	}
	planID, err := queryString(c.request, "plan_id", 64)
	if err != nil {
		return err
	}
	state, err := queryString(c.request, "state", 32)
	if err != nil {
		return err
	}
	beforeCreatedAt, err := queryTime(c.request, "before_created_at")
	if err != nil {
		return err
	}
	beforeID, err := queryString(c.request, "before_id", 128)
	if err != nil {
		return err
	}
	cursor, err := queryString(c.request, "cursor", 4096)
	if err != nil {
		return err
	}
	// 步骤 263：报告名称有界字面搜索；字段白名单与长度由领域层复核。
	searchText, err := queryString(c.request, "search", 256)
	if err != nil {
		return err
	}
	rawSearchFields, err := queryString(c.request, "search_fields", 256)
	if err != nil {
		return err
	}
	searchFields := make([]reports.HistorySearchField, 0, 2)
	for _, field := range parseSearchFieldList(rawSearchFields) {
		searchFields = append(searchFields, reports.HistorySearchField(field))
	}
	result, err := s.reports.HistoryList(c.request.Context(), reports.HistoryListRequest{
		Caller: c.caller, PlanID: planID, State: state, Limit: limit,
		BeforeCreatedAt: beforeCreatedAt, BeforeID: beforeID, Cursor: cursor,
		Search: searchText, SearchFields: searchFields})
	if err != nil {
		return s.reportProblem(err)
	}
	records := make([]reportHistoryDTO, 0, len(result.Records))
	for _, record := range result.Records {
		records = append(records, toReportHistoryDTO(record))
	}
	payload := map[string]any{
		"reports": records, "has_more": result.HasMore,
		"scope_trimmed": result.ScopeTrimmed}
	if result.NextCursor != "" {
		payload["next_cursor"] = result.NextCursor
	}
	s.writeSuccess(c.writer, c.requestID, payload)
	return nil
}

// handleReportGet 处理 GET /reports/{report_id}。
func (s *Server) handleReportGet(c *callContext) error {
	view, err := s.reports.Get(c.request.Context(), c.caller, c.pathParam("report_id"))
	if err != nil {
		return s.reportProblem(err)
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{"report": toReportViewDTO(view)})
	return nil
}

// handleReportSnapshot 处理 GET /reports/{report_id}/snapshot：返回生成时冻结的
// 固定统计快照（JSON 结构本身就是稳定 schema，缺失数据有显式完整性标记）。
func (s *Server) handleReportSnapshot(c *callContext) error {
	snapshot, err := s.reports.GetSnapshot(c.request.Context(), c.caller,
		c.pathParam("report_id"))
	if err != nil {
		return s.reportProblem(err)
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{"snapshot": snapshot})
	return nil
}

// reportDownloadTicketInput 是签发报告下载令牌请求体（敏感操作）。
type reportDownloadTicketInput struct {
	Confirm bool   `json:"confirm"`
	Format  string `json:"format"`
}

// handleReportDownloadTicket 处理 POST /reports/{report_id}/download-tickets。
// 令牌一次性、短时有效、绑定报告与格式；响应只返回一次原文，不写日志/审计。
func (s *Server) handleReportDownloadTicket(c *callContext) error {
	var input reportDownloadTicketInput
	if err := c.decodeJSON(&input); err != nil {
		return err
	}
	if err := requireConfirm(input.Confirm); err != nil {
		return err
	}
	ticket, err := s.reports.IssueDownloadTicket(c.request.Context(), c.caller,
		c.pathParam("report_id"), reports.Format(input.Format))
	if err != nil {
		return s.reportProblem(err)
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{
		"ticket": map[string]any{
			"token": ticket.Token, "report_id": ticket.ReportID,
			"format": string(ticket.Format), "issued_at": ticket.IssuedAt,
			"expires_at": ticket.ExpiresAt, "ttl_seconds": int(ticket.TTL.Seconds()),
		}})
	return nil
}

// downloadRedeemInput 是兑换一次性下载令牌请求体。
type downloadRedeemInput struct {
	Token string `json:"token"`
}

// handleReportDownloadRedeem 处理 POST /reports/download-tickets/redeem：令牌
// 单次消费，重复兑换与撤权后兑换都由服务层拒绝。
func (s *Server) handleReportDownloadRedeem(c *callContext) error {
	var input downloadRedeemInput
	if err := c.decodeJSON(&input); err != nil {
		return err
	}
	token := strings.TrimSpace(input.Token)
	if token == "" || len(token) > 512 {
		return fmt.Errorf("%w: 下载令牌无效", ErrInvalidRequest)
	}
	file, err := s.reports.RedeemDownloadTicket(c.request.Context(), c.caller, token)
	if err != nil {
		return s.reportProblem(err)
	}
	return s.streamReportFile(c, file)
}

// streamReportFile 流式输出报告产物；文件名由本包生成，不使用宿主路径。
func (s *Server) streamReportFile(c *callContext, file reports.ArtifactFile) error {
	handle, err := os.Open(file.HostPath)
	if err != nil {
		return s.codeProblem(string(codeInternalError), err)
	}
	defer handle.Close()
	contentType, extension := reportContentType(file.Format)
	header := c.writer.Header()
	header.Set("Content-Type", contentType)
	header.Set("Cache-Control", "no-store")
	header.Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="report-%s.%s"`, safeFileID(file.ReportID), extension))
	if file.Bytes > 0 {
		header.Set("Content-Length", fmt.Sprintf("%d", file.Bytes))
	}
	c.writer.WriteHeader(http.StatusOK)
	_, copyErr := io.Copy(c.writer, io.LimitReader(handle, file.Bytes+1))
	return copyErr
}

// reportContentType 返回报告格式的响应 Content-Type 与文件扩展名。
func reportContentType(format reports.Format) (string, string) {
	switch format {
	case reports.FormatHTML:
		return "text/html; charset=utf-8", "html"
	case reports.FormatCSV:
		return "text/csv; charset=utf-8", "csv"
	case reports.FormatJSON:
		return "application/json; charset=utf-8", "json"
	case reports.FormatPDF:
		return "application/pdf", "pdf"
	case reports.FormatMarkdown:
		return "text/markdown; charset=utf-8", "md"
	default:
		return "application/octet-stream", "bin"
	}
}

// handleReportCancel 处理 POST /reports/{report_id}/cancel。
func (s *Server) handleReportCancel(c *callContext) error {
	var input cancelInput
	if err := c.decodeJSON(&input); err != nil {
		return err
	}
	reason, err := input.parse()
	if err != nil {
		return err
	}
	result, err := s.reports.Cancel(c.request.Context(), c.caller,
		c.pathParam("report_id"), reason, c.requestID)
	if err != nil {
		return s.reportProblem(err)
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{"cancel": toCancelDTO(result)})
	return nil
}

// handleReportRetry 处理 POST /reports/{report_id}/retry：重试产生新的报告记录，
// 原记录保留；权限与敏感策略由服务层重新判定。
func (s *Server) handleReportRetry(c *callContext) error {
	var input cancelInput
	if err := c.decodeJSON(&input); err != nil {
		return err
	}
	reason, err := input.parse()
	if err != nil {
		return err
	}
	view, err := s.reports.Retry(c.request.Context(), c.caller,
		c.pathParam("report_id"), reason, c.requestID)
	if err != nil {
		return s.reportProblem(err)
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{"report": toReportViewDTO(view)})
	return nil
}

// handleReportCleanupPreview 处理 GET /reports/cleanup-preview。
func (s *Server) handleReportCleanupPreview(c *callContext) error {
	preview, err := s.reports.CleanupPreview(c.request.Context(), c.caller)
	if err != nil {
		return s.reportProblem(err)
	}
	dto := reportCleanupPreviewDTO{
		Policy: toRetentionPolicyDTO(preview.Policy), TargetCount: preview.TargetCount,
		TotalBytes: preview.TotalBytes, Scopes: preview.Scopes,
		OldestExpiresAt: preview.OldestExpiresAt, NewestExpiresAt: preview.NewestExpiresAt,
		PreviewedAt: preview.PreviewedAt, Note: preview.Note}
	for _, target := range preview.Targets {
		dto.Targets = append(dto.Targets, cleanupTargetDTO{
			ReportID: target.ReportID, PlanID: target.PlanID, Name: target.Name,
			ScopeID: target.ScopeID, State: target.State,
			CleanupState: target.CleanupState, ExpiresAt: target.ExpiresAt,
			Formats: formatStrings(target.Formats), ArtifactCount: target.ArtifactCount,
			Bytes: target.Bytes})
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{"cleanup_preview": dto})
	return nil
}

// reportCleanupInput 是执行报告文件清理请求体（权限 + 敏感策略 + 确认 + 原因）。
type reportCleanupInput struct {
	Confirm    bool   `json:"confirm"`
	Reason     string `json:"reason"`
	MaxTargets int    `json:"max_targets"`
}

// handleReportCleanupExecute 处理 POST /reports/cleanup：只删除受控报告文件，
// 不删除原始安全审计；实际结果如实返回成功与失败计数。
func (s *Server) handleReportCleanupExecute(c *callContext) error {
	var input reportCleanupInput
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
	result, err := s.reports.CleanupExecute(c.request.Context(), reports.CleanupExecuteRequest{
		Caller: c.caller, Reason: reason, RequestID: c.requestID,
		MaxTargets: input.MaxTargets})
	if err != nil {
		return s.reportProblem(err)
	}
	dto := reportCleanupResultDTO{
		Operator: toActorDTO(result.Operator), StartedAt: result.StartedAt,
		FinishedAt: result.FinishedAt, RequestedCount: result.RequestedCount,
		CleanedCount: result.CleanedCount, FailedCount: result.FailedCount,
		DeletedFiles: result.DeletedFiles, FreedBytes: result.FreedBytes,
		SkippedCount: result.SkippedCount,
		Policy:       toRetentionPolicyDTO(result.Policy), RawAuditNote: result.RawAuditNote}
	for _, failure := range result.Failures {
		dto.Failures = append(dto.Failures, cleanupFailureDTO{
			ReportID: failure.ReportID, Reason: failure.Reason})
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{"cleanup_result": dto})
	return nil
}

// handlePlanList 处理 GET /report-plans：只读分页列表，每次重新授权。
func (s *Server) handlePlanList(c *callContext) error {
	limit, offset, err := pageParams(c.request)
	if err != nil {
		return err
	}
	// 步骤 263：计划显示名有界字面搜索（可见范围过滤后执行）。
	searchText, err := queryString(c.request, "search", 256)
	if err != nil {
		return err
	}
	rawSearchFields, err := queryString(c.request, "search_fields", 256)
	if err != nil {
		return err
	}
	result, err := s.plans.ListPage(c.request.Context(), reports.PlanListRequest{
		Caller: c.caller, Limit: limit, Offset: offset,
		Search: searchText, SearchFields: parseSearchFieldList(rawSearchFields)})
	if err != nil {
		return s.reportProblem(err)
	}
	items := make([]planDTO, 0, len(result.Plans))
	for _, plan := range result.Plans {
		items = append(items, toPlanDTO(plan))
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{
		"plans": items, "has_more": result.HasMore, "limit": result.Limit,
		"offset": result.Offset, "next_offset": result.NextOffset})
	return nil
}

// handlePlanGet 处理 GET /report-plans/{plan_id}。
func (s *Server) handlePlanGet(c *callContext) error {
	plan, err := s.plans.Get(c.request.Context(), c.caller, c.pathParam("plan_id"))
	if err != nil {
		return s.reportProblem(err)
	}
	s.writeSuccess(c.writer, c.requestID, map[string]any{"plan": toPlanDTO(plan)})
	return nil
}

var _ http.Handler = (*Server)(nil)
