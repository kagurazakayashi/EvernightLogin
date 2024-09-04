// Package uiadminadapter：步骤 74 审计与错误诊断页适配器。
//
// 安全边界：适配器只接受页面已通过 UIAccessManagement 验证后传入的操作者用户 ID，
// 每次都重新构造可信 Caller 并调用真实 internal/auditops（查询/导出/清理）与根包
// 错误码注册表；每次读取/导出/下载/预估/清理都由领域服务重新授权、复核数据范围与
// 敏感操作，页面层能力位只影响呈现。适配器不读取前端自报角色、不缓存授权、不把
// 服务器文件路径写入页面结果。
package uiadminadapter

import (
	"context"
	"errors"
	"fmt"
	"github.com/kagurazakayashi/EvernightLogin/errs"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/auditops"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
	ui "github.com/kagurazakayashi/EvernightLogin/ui"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"
)

// AuditRecorder 是拒绝审计写入契约（生产 *audit.Recorder）。
type AuditRecorder interface {
	RecordFailure(ctx context.Context, event audit.Event) error
}

// TaskReadStore 是任务只读视图（生产 *task.Executor）；用于详情关联任务摘要。
type TaskReadStore interface {
	Get(ctx context.Context, id string) (task.Job, bool, error)
}

// AuditOptions 是审计页适配器依赖。Authorizer 由宿主注入真实权限引擎；nil 时页面
// 读取/错误码检索/能力位一律 fail-closed 拒绝（不把“未装配”当放行）。IsRoot 由宿主
// 实现（读取真实 root 状态），仅用于 root 专属清理能力/受限诊断等身份能力，不用于
// 普通读取/导出授权——后者统一走 Authorizer（生产装配把 root 交权限内核，步骤 252）。
// RestrictedDiagnosis nil 时一律隐藏受限原因码；Recorder 用于拒绝留痕（nil 时拒绝仍
// 生效但不写审计，宿主应装配）。
type AuditOptions struct {
	Audit      *auditops.Service
	Authorizer auditops.Authorizer
	Recorder   AuditRecorder
	IsRoot     func(ctx context.Context, userID string) (bool, error)
	// RestrictedDiagnosis 由宿主实现：判定当前调用者是否拥有独立的受限诊断权限
	// 与数据范围。nil 时一律不展示受限原因码（默认最小披露）。
	RestrictedDiagnosis func(ctx context.Context, userID string) (bool, error)
	Tasks               TaskReadStore
	Logger              *slog.Logger
}

// AuditAdapter 实现 ui.UIPageAuditBackend。
type AuditAdapter struct {
	opts AuditOptions
}

// NewAudit 校验依赖并构造审计页适配器。
func NewAudit(options AuditOptions) (*AuditAdapter, error) {
	if options.Audit == nil {
		return nil, errors.New("审计页适配器缺少 auditops 服务")
	}
	return &AuditAdapter{opts: options}, nil
}

// auditCaller 把页面已认证用户 ID 重建为可信 Caller。
func auditCaller(userID string) (account.Caller, error) {
	if userID == "" || !account.ValidUserID(userID) {
		return account.Caller{}, &ui.UIAuditError{Code: "ACCESS_DENIED"}
	}
	return account.UserCaller(userID)
}

// safeDenialToken 把拒绝原因限制为 ASCII 短标记，避免写入原始错误或用户输入。
func safeDenialToken(value string) string {
	var builder strings.Builder
	for index := 0; index < len(value) && builder.Len() < 64; index++ {
		c := value[index]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '_' || c == '-' {
			builder.WriteByte(c)
		}
	}
	if builder.Len() == 0 {
		return "denied"
	}
	return builder.String()
}

// authorize 使用宿主注入的真实权限引擎重新判定页面读取类动作；未装配或失败一律
// 拒绝（fail-closed），不能把“没有授权器”当成放行。root 也不再走旁路：生产装配的
// Authorizer 把 root 交权限内核判定，停用/未实现权限对 root 同样拒绝（步骤 252）。
func (a *AuditAdapter) authorize(ctx context.Context, caller account.Caller,
	permissionKey string) error {
	if a.opts.Authorizer == nil {
		return &ui.UIAuditError{Code: "ACCESS_DENIED"}
	}
	grant, err := a.opts.Authorizer.AuthorizeScope(ctx, caller, permissionKey,
		auditops.ScopeSystem)
	if err != nil || !grant.Allowed {
		return &ui.UIAuditError{Code: "ACCESS_DENIED"}
	}
	return nil
}

// RecordDenial 记录一次页面级拒绝（能力位不足、CSRF 失败等），与既有失败审计一致：
// 只写稳定动作/目标/原因标记，不写用户输入、秘密或内部错误文本；审计写失败不改
// 变拒绝结果，仅记录日志。
func (a *AuditAdapter) RecordDenial(ctx context.Context, userID, reason string) error {
	caller, err := auditCaller(userID)
	if err != nil {
		return err
	}
	if a.opts.Recorder == nil {
		return nil
	}
	event := audit.Event{Actor: caller.Actor(), Action: auditops.ActionAccessDenied,
		Target:  audit.Target{Type: "audit_page", ID: "page_denied"},
		Outcome: audit.OutcomeDenied, ErrorCode: "ACCESS_DENIED",
		ReasonCode: safeDenialToken(reason)}
	if err := a.opts.Recorder.RecordFailure(ctx, event); err != nil {
		if a.opts.Logger != nil {
			a.opts.Logger.Warn("页面拒绝审计写入失败", "code", "AUDIT_WRITE_FAILED")
		}
	}
	return nil
}

// mapAuditError 把 auditops 领域错误映射为页面公开错误（区分披露许可）。
func mapAuditError(err error) error {
	if err == nil {
		return nil
	}
	var publicErr *ui.UIAuditError
	if errors.As(err, &publicErr) {
		return err
	}
	switch {
	case errors.Is(err, auditops.ErrAccessDenied), errors.Is(err, auditops.ErrRootRequired):
		return &ui.UIAuditError{Code: "ACCESS_DENIED"}
	case errors.Is(err, auditops.ErrNotFound):
		return &ui.UIAuditError{Code: "NOT_FOUND", Disclosed: true}
	case errors.Is(err, auditops.ErrRetentionExpired):
		return &ui.UIAuditError{Code: "RETENTION_EXPIRED", Disclosed: true}
	case errors.Is(err, auditops.ErrConflict), errors.Is(err, auditops.ErrTaskTerminal):
		return &ui.UIAuditError{Code: "CONFLICT"}
	case errors.Is(err, auditops.ErrInvalidRequest), errors.Is(err, auditops.ErrOptionsInvalid):
		return &ui.UIAuditError{Code: "REQ_INVALID"}
	case errors.Is(err, auditops.ErrStoreUnavailable), errors.Is(err, auditops.ErrTaskRejected):
		return &ui.UIAuditError{Code: "DB_UNAVAILABLE"}
	case errors.Is(err, auditops.ErrAuditUnavailable):
		return &ui.UIAuditError{Code: "AUDIT_WRITE_FAILED"}
	case errors.Is(err, auditops.ErrExportPathUnsafe):
		return &ui.UIAuditError{Code: "EXPORT_PATH_UNSAFE"}
	default:
		return &ui.UIAuditError{Code: "INTERNAL_ERROR"}
	}
}

// Capabilities 返回页面能力位：读取/导出来自宿主真实权限引擎的重新判定（未装配或
// 失败为 false），清理只对真实 root 显示。能力位仍只是呈现辅助，每次读取/写入由
// 领域服务重新授权。
func (a *AuditAdapter) Capabilities(ctx context.Context,
	userID string) (ui.UIAuditCapabilities, error) {
	caller, err := auditCaller(userID)
	if err != nil {
		return ui.UIAuditCapabilities{}, err
	}
	caps := ui.UIAuditCapabilities{
		Read:   a.authorize(ctx, caller, auditops.PermissionRead) == nil,
		Export: a.authorize(ctx, caller, auditops.PermissionExport) == nil,
	}
	if a.opts.IsRoot != nil {
		root, rootErr := a.opts.IsRoot(ctx, userID)
		if rootErr == nil {
			caps.Purge = root
		}
	}
	return caps, nil
}

// toAuditFilter 把页面筛选转换为 auditops 白名单筛选。
func toAuditFilter(filter ui.UIAuditFilter) auditops.Filter {
	result := auditops.Filter{
		From: filter.From, To: filter.To, AppID: filter.AppID,
		SystemOnly: filter.SystemOnly, ActorID: filter.ActorID, Action: filter.Action,
		ErrorCode: filter.ErrorCode, RequestID: filter.RequestID, TaskID: filter.TaskID,
		TargetType: filter.TargetType, TargetID: filter.TargetID,
	}
	if filter.ActorType != "" {
		result.ActorType = audit.ActorKind(filter.ActorType)
	}
	if filter.Outcome != "" {
		result.Outcome = audit.Outcome(filter.Outcome)
	}
	return result
}

// toAuditOrder 映射稳定排序。
func toAuditOrder(order string) auditops.SortOrder {
	if order == "occurred_asc" {
		return auditops.SortOldestFirst
	}
	return auditops.SortNewestFirst
}

// toAuditEventView 转换稳定事件字段。
func toAuditEventView(event audit.Event) ui.UIAuditEventView {
	return ui.UIAuditEventView{
		ID: event.ID, OccurredAt: event.OccurredAt, ActorType: string(event.Actor.Type),
		ActorID: event.Actor.ID, AppID: event.AppID, Action: event.Action,
		TargetType: event.Target.Type, TargetID: event.Target.ID,
		Outcome: string(event.Outcome), ErrorCode: event.ErrorCode,
		RequestID: event.RequestID, TaskID: event.TaskID,
	}
}

// ListAudit 查询授权范围内审计列表。
func (a *AuditAdapter) ListAudit(ctx context.Context, userID string,
	query ui.UIAuditQuery) (ui.UIAuditPage, error) {
	caller, err := auditCaller(userID)
	if err != nil {
		return ui.UIAuditPage{}, err
	}
	result, err := a.opts.Audit.Query(ctx, auditops.QueryRequest{
		Caller: caller, ScopeID: query.ScopeID, Filter: toAuditFilter(query.Filter),
		Order: toAuditOrder(query.Order), Limit: query.Limit, Offset: query.Offset,
		Cursor: query.Cursor})
	if err != nil {
		return ui.UIAuditPage{}, mapAuditError(err)
	}
	page := ui.UIAuditPage{
		Events:  make([]ui.UIAuditEventView, 0, len(result.Events)),
		HasMore: result.HasMore, Limit: result.Limit, Offset: result.Offset,
		NextCursor: result.NextCursor,
		Order:      string(result.Order), ScopeID: result.Scope.ID, ScopeKind: result.Scope.Kind,
		RetentionDays:       result.Retention.Days,
		RetentionConfigured: result.Retention.Configured,
		RetentionCutoff:     result.Retention.Cutoff,
	}
	page.DataScope = a.dataScope(ctx, caller)
	for _, event := range result.Events {
		page.Events = append(page.Events, toAuditEventView(event))
	}
	return page, nil
}

// dataScope 返回授权结果对应的可见数据范围摘要（只在授权成功后读取；不显示未授权
// 应用名称，仅给出范围事实，避免从页面推断跨应用记录）。root 与普通主体一样以
// Authorizer 的授权结果为准（生产内核为 root 返回 all），不再以 root 身份旁路。
func (a *AuditAdapter) dataScope(ctx context.Context, caller account.Caller) string {
	if a.opts.Authorizer == nil {
		return ""
	}
	grant, err := a.opts.Authorizer.AuthorizeScope(ctx, caller, auditops.PermissionRead,
		auditops.ScopeSystem)
	if err != nil || !grant.Allowed {
		return ""
	}
	if grant.AllData {
		return "全部数据范围"
	}
	if len(grant.ResourceIDs) > 0 {
		return "仅限获准的 " + fmt.Sprintf("%d", len(grant.ResourceIDs)) + " 个应用范围"
	}
	return "系统级事件范围"
}

// GetAudit 读取单条审计事件详情（范围与披露由服务重判）。
func (a *AuditAdapter) GetAudit(ctx context.Context, userID, eventID string,
	occurredAtHint time.Time) (ui.UIAuditDetail, error) {
	caller, err := auditCaller(userID)
	if err != nil {
		return ui.UIAuditDetail{}, err
	}
	detail, err := a.opts.Audit.GetEvent(ctx, auditops.GetRequest{
		Caller: caller, ScopeID: ui.UIAuditScopeSystem, EventID: eventID,
		OccurredAtHint: occurredAtHint})
	if err != nil {
		return ui.UIAuditDetail{}, mapAuditError(err)
	}
	result := ui.UIAuditDetail{
		Event: toAuditEventView(detail.Event), ScopeID: detail.Scope.ID,
		ScopeKind: detail.Scope.Kind, RetentionDays: detail.Retention.Days,
		RetentionConfigured: detail.Retention.Configured,
		RetentionCutoff:     detail.Retention.Cutoff, Stale: detail.Stale,
		ErrorCode: detail.Event.ErrorCode,
	}
	for _, change := range detail.Event.Changes {
		redacted := strings.Contains(change.Before, "[REDACTED]") ||
			strings.Contains(change.After, "[REDACTED]")
		result.Changes = append(result.Changes, ui.UIAuditChange{
			Field: change.Field, Before: change.Before, After: change.After,
			Redacted: redacted})
	}
	if detail.Event.ErrorCode != "" {
		result.Error = errorEntryOf(detail.Event.ErrorCode)
	}
	// 关联任务摘要：只在真实任务存储提供且任务存在时显示；没有字段保持 nil（页面
	// 显示“—”，不伪造任务状态）。
	if detail.Event.TaskID != "" && a.opts.Tasks != nil {
		if job, found, taskErr := a.opts.Tasks.Get(ctx, detail.Event.TaskID); taskErr == nil && found {
			result.RelatedTask = &ui.UIExportTaskSummary{ID: job.ID, Kind: job.Kind,
				State: string(job.State), Attempt: job.Attempt, MaxAttempts: job.MaxAttempts,
				ErrorCode: job.ErrorCode, FailureReason: job.FailureReason,
				RequestID: job.RequestID}
		}
	}
	// 受限诊断与公开说明分区：只有独立诊断权限通过后才填充受限原因码，公开区
	// 与模板隐藏区域都不携带该值。
	if detail.Event.ReasonCode != "" && a.opts.RestrictedDiagnosis != nil {
		allowed, gateErr := a.opts.RestrictedDiagnosis(ctx, userID)
		if gateErr == nil && allowed {
			result.RestrictedReasonCode = detail.Event.ReasonCode
			result.Restricted = true
		}
	}
	return result, nil
}

// QueryOwnActivity 查询调用者本人安全活动（服务端固定操作者本人，不接受他人筛选）。
func (a *AuditAdapter) QueryOwnActivity(ctx context.Context, userID string,
	query ui.UIAuditQuery) (ui.UIAuditPage, error) {
	caller, err := auditCaller(userID)
	if err != nil {
		return ui.UIAuditPage{}, err
	}
	result, err := a.opts.Audit.QueryOwnActivity(ctx, auditops.OwnQueryRequest{
		Caller: caller, Filter: toAuditFilter(query.Filter),
		Order: toAuditOrder(query.Order), Limit: query.Limit, Offset: query.Offset,
		Cursor: query.Cursor})
	if err != nil {
		return ui.UIAuditPage{}, mapAuditError(err)
	}
	page := ui.UIAuditPage{
		Events:  make([]ui.UIAuditEventView, 0, len(result.Events)),
		HasMore: result.HasMore, Limit: result.Limit, Offset: result.Offset,
		NextCursor: result.NextCursor,
		Order:      string(result.Order), ScopeID: result.Scope.ID, ScopeKind: result.Scope.Kind,
		RetentionDays:       result.Retention.Days,
		RetentionConfigured: result.Retention.Configured,
		RetentionCutoff:     result.Retention.Cutoff,
	}
	for _, event := range result.Events {
		page.Events = append(page.Events, toAuditEventView(event))
	}
	return page, nil
}

// GetOwnActivity 读取本人单条安全活动；他人事件由服务端按不存在处理。
func (a *AuditAdapter) GetOwnActivity(ctx context.Context, userID, eventID string,
	occurredAtHint time.Time) (ui.UIAuditDetail, error) {
	caller, err := auditCaller(userID)
	if err != nil {
		return ui.UIAuditDetail{}, err
	}
	detail, err := a.opts.Audit.GetOwnEvent(ctx, caller, eventID, occurredAtHint)
	if err != nil {
		return ui.UIAuditDetail{}, mapAuditError(err)
	}
	result := ui.UIAuditDetail{
		Event: toAuditEventView(detail.Event), ScopeID: detail.Scope.ID,
		ScopeKind: detail.Scope.Kind, RetentionDays: detail.Retention.Days,
		RetentionConfigured: detail.Retention.Configured,
		RetentionCutoff:     detail.Retention.Cutoff, Stale: detail.Stale,
		ErrorCode: detail.Event.ErrorCode,
	}
	for _, change := range detail.Event.Changes {
		redacted := strings.Contains(change.Before, "[REDACTED]") ||
			strings.Contains(change.After, "[REDACTED]")
		result.Changes = append(result.Changes, ui.UIAuditChange{
			Field: change.Field, Before: change.Before, After: change.After,
			Redacted: redacted})
	}
	if detail.Event.ErrorCode != "" {
		result.Error = errorEntryOf(detail.Event.ErrorCode)
	}
	return result, nil
}

// SearchErrors 检索同一错误码注册表（公开说明；未知码不猜原因）。
func (a *AuditAdapter) SearchErrors(ctx context.Context, userID string,
	query ui.UIErrorQuery) (ui.UIErrorSearch, error) {
	if _, err := auditCaller(userID); err != nil {
		return ui.UIErrorSearch{}, err
	}
	caller, err := auditCaller(userID)
	if err != nil {
		return ui.UIErrorSearch{}, err
	}
	// 错误码目录属审计读取能力：同样由真实权限引擎重新判定，未装配/失败 fail-closed。
	if err := a.authorize(ctx, caller, auditops.PermissionRead); err != nil {
		return ui.UIErrorSearch{}, err
	}
	result := ui.UIErrorSearch{Searched: query.Code != "" || query.Keyword != "" ||
		query.Category != ""}
	keyword := strings.ToLower(query.Keyword)
	for _, definition := range errs.RegisteredErrorCodes() {
		code := string(definition.Code)
		if query.Code != "" && code != query.Code {
			continue
		}
		if query.Category != "" && string(definition.Category) != query.Category {
			continue
		}
		entry := errorEntryOf(code)
		if keyword != "" && !strings.Contains(strings.ToLower(entry.Code+" "+
			entry.Category+" "+entry.Message+" "+entry.Cause+" "+entry.Advice), keyword) {
			continue
		}
		result.Entries = append(result.Entries, entry)
	}
	if query.Code != "" && len(result.Entries) == 0 {
		result.UnknownCode = query.Code
	}
	return result, nil
}

// errorEntryOf 从根包注册表与手册说明构造公开条目。
func errorEntryOf(code string) ui.UIErrorEntry {
	entry := ui.UIErrorEntry{Code: code}
	definition, ok := errs.LookupErrorCode(errs.ErrorCode(code))
	if ok {
		entry.Category = string(definition.Category)
		entry.Message = definition.DefaultMessage
		entry.HTTPStatus = definition.HTTPStatus
		entry.HasHTTPStatus = definition.HTTPStatus != 0
	}
	if guidance, ok := errs.LookupErrorCodeGuidance(errs.ErrorCode(code)); ok {
		entry.Cause, entry.Advice, entry.Retry = guidance.Cause, guidance.Advice, guidance.Retry
		entry.HasGuidance = true
	}
	return entry
}

// toTaskSummary 转换真实任务摘要（nil 保持 nil）。
func toTaskSummary(summary *auditops.TaskSummary) *ui.UIExportTaskSummary {
	if summary == nil {
		return nil
	}
	return &ui.UIExportTaskSummary{ID: summary.ID, Kind: summary.Kind,
		State: summary.State, Attempt: summary.Attempt, MaxAttempts: summary.MaxAttempts,
		ErrorCode: summary.ErrorCode, FailureReason: summary.FailureReason,
		RequestID: summary.RequestID}
}

// toExportView 转换导出任务视图（不含服务器路径）。
func toExportView(view auditops.ExportView) ui.UIAuditExport {
	return ui.UIAuditExport{ID: view.ID, ScopeID: view.ScopeID,
		ScopeKind: view.ScopeKind, Format: string(view.Format), State: view.State,
		MaxRows: view.MaxRows, RowCount: view.RowCount, Truncated: view.Truncated,
		TaskID: view.TaskID, FileAvailable: view.FileAvailable,
		FileExpiresAt: view.FileExpiresAt, ErrorCode: view.ErrorCode,
		FailureReason: view.FailureReason, RequestID: view.RequestID,
		RequestedBy: string(view.RequestedBy.Type) + ":" + view.RequestedBy.ID,
		CreatedAt:   view.CreatedAt, StartedAt: view.StartedAt, FinishedAt: view.FinishedAt,
		Task: toTaskSummary(view.Task)}
}

// CreateExport 创建真实异步导出任务；返回已受理而非已完成。
func (a *AuditAdapter) CreateExport(ctx context.Context, userID string,
	request ui.UIAuditExportRequest) (ui.UIAuditExport, error) {
	caller, err := auditCaller(userID)
	if err != nil {
		return ui.UIAuditExport{}, err
	}
	view, err := a.opts.Audit.StartExport(ctx, auditops.StartExportRequest{
		Caller: caller, ScopeID: request.ScopeID, Filter: toAuditFilter(request.Filter),
		Order: toAuditOrder(request.Order), Format: auditops.ExportFormat(request.Format),
		RequestID: request.RequestID})
	if err != nil {
		return ui.UIAuditExport{}, mapAuditError(err)
	}
	return toExportView(view), nil
}

// ListExports 列出当前授权可见导出任务。
func (a *AuditAdapter) ListExports(ctx context.Context, userID, scopeID, state string,
	limit, offset int) (ui.UIAuditExportPage, error) {
	caller, err := auditCaller(userID)
	if err != nil {
		return ui.UIAuditExportPage{}, err
	}
	views, hasMore, err := a.opts.Audit.ListExports(ctx, auditops.ExportListRequest{
		Caller: caller, ScopeID: scopeID, State: state, Limit: limit, Offset: offset})
	if err != nil {
		return ui.UIAuditExportPage{}, mapAuditError(err)
	}
	page := ui.UIAuditExportPage{HasMore: hasMore, Limit: limit, Offset: offset,
		Exports: make([]ui.UIAuditExport, 0, len(views))}
	for _, view := range views {
		page.Exports = append(page.Exports, toExportView(view))
	}
	return page, nil
}

// GetExport 读取单个导出任务真实状态。
func (a *AuditAdapter) GetExport(ctx context.Context, userID,
	exportID string) (ui.UIAuditExport, error) {
	caller, err := auditCaller(userID)
	if err != nil {
		return ui.UIAuditExport{}, err
	}
	view, err := a.opts.Audit.GetExport(ctx, caller, exportID)
	if err != nil {
		return ui.UIAuditExport{}, mapAuditError(err)
	}
	return toExportView(view), nil
}

// CancelExport 请求取消导出任务；请求被接受不等于实际取消。
func (a *AuditAdapter) CancelExport(ctx context.Context, userID, exportID, reason,
	requestID string) (ui.UIAuditExport, error) {
	caller, err := auditCaller(userID)
	if err != nil {
		return ui.UIAuditExport{}, err
	}
	result, err := a.opts.Audit.CancelExport(ctx, caller, exportID, reason, requestID)
	if err != nil {
		return ui.UIAuditExport{}, mapAuditError(err)
	}
	view, err := a.opts.Audit.GetExport(ctx, caller, exportID)
	if err != nil {
		return ui.UIAuditExport{}, mapAuditError(err)
	}
	converted := toExportView(view)
	// 取消请求被接受但尚未实际取消：真实任务状态是 cancel_requested，而导出记录
	// 仍可能显示 queued/running。页面显示状态反映"取消已请求"，不宣称已取消；
	// 该值不写回存储，终态仍由真实执行结果决定。
	if result.State == task.StateCancelRequested {
		converted.State = "cancel_requested"
	}
	return converted, nil
}

// DownloadExport 读取受控导出产物字节；产物路径永不进入页面结果。
func (a *AuditAdapter) DownloadExport(ctx context.Context, userID,
	exportID string) (ui.UIAuditExportFile, error) {
	caller, err := auditCaller(userID)
	if err != nil {
		return ui.UIAuditExportFile{}, err
	}
	file, err := a.opts.Audit.OpenExportFile(ctx, caller, exportID)
	if err != nil {
		return ui.UIAuditExportFile{}, mapAuditError(err)
	}
	if file.Size < 0 || file.Size > auditops.MaxExportBytes {
		return ui.UIAuditExportFile{}, &ui.UIAuditError{Code: "REQ_INVALID"}
	}
	handle, err := os.Open(file.HostPath)
	if err != nil {
		return ui.UIAuditExportFile{}, &ui.UIAuditError{Code: "NOT_FOUND", Disclosed: true}
	}
	defer handle.Close()
	body, err := io.ReadAll(io.LimitReader(handle, auditops.MaxExportBytes+1))
	if err != nil || int64(len(body)) > auditops.MaxExportBytes {
		return ui.UIAuditExportFile{}, &ui.UIAuditError{Code: "INTERNAL_ERROR"}
	}
	name := "audit_export_" + file.ID + "." + string(file.Format)
	contentType := "text/csv; charset=utf-8"
	if file.Format == auditops.FormatJSON {
		contentType = "application/json; charset=utf-8"
	}
	return ui.UIAuditExportFile{Name: name, ContentType: contentType, Body: body}, nil
}

// PurgeContext 读取保留策略与最近清理运行。
func (a *AuditAdapter) PurgeContext(ctx context.Context, userID, scopeID string,
	limit, offset int) (ui.UIPurgeContext, error) {
	caller, err := auditCaller(userID)
	if err != nil {
		return ui.UIPurgeContext{}, err
	}
	retention, err := a.opts.Audit.Retention(ctx, caller)
	if err != nil {
		return ui.UIPurgeContext{}, mapAuditError(err)
	}
	views, hasMore, err := a.opts.Audit.ListPurgeRuns(ctx, auditops.PurgeListRequest{
		Caller: caller, Limit: limit, Offset: offset})
	if err != nil {
		return ui.UIPurgeContext{}, mapAuditError(err)
	}
	result := ui.UIPurgeContext{
		Retention: ui.UIPurgeRetention{Days: retention.Days,
			Configured: retention.Configured, Version: retention.Version,
			Cutoff: retention.Cutoff, UpdatedAt: retention.UpdatedAt},
		HasMore: hasMore, Limit: limit, Offset: offset}
	for _, view := range views {
		result.Runs = append(result.Runs, toPurgeView(view))
	}
	return result, nil
}

// toPurgeView 转换清理运行视图。
func toPurgeView(view auditops.PurgeRunView) ui.UIPurgeRun {
	return ui.UIPurgeRun{ID: view.ID, State: view.State, TaskID: view.TaskID,
		ScopeID: view.ScopeID, ScopeKind: view.ScopeKind, Cutoff: view.Cutoff,
		BatchSize: view.BatchSize, MaxRecords: view.MaxRecords, Scanned: view.Scanned,
		Cleaned: view.Cleaned, Skipped: view.Skipped, Failed: view.Failed,
		Batches: view.Batches, LimitReached: view.LimitReached,
		ErrorCode: view.ErrorCode, FailureReason: view.FailureReason,
		RequestID:   view.RequestID,
		RequestedBy: string(view.RequestedBy.Type) + ":" + view.RequestedBy.ID,
		CreatedAt:   view.CreatedAt, StartedAt: view.StartedAt, FinishedAt: view.FinishedAt,
		Task: toTaskSummary(view.Task)}
}

// PreviewPurge 执行只读清理预估（不删除记录）。
func (a *AuditAdapter) PreviewPurge(ctx context.Context, userID string,
	request ui.UIPurgeRequest) (ui.UIPurgePreview, error) {
	caller, err := auditCaller(userID)
	if err != nil {
		return ui.UIPurgePreview{}, err
	}
	preview, err := a.opts.Audit.PreviewPurge(ctx, auditops.PurgePreviewRequest{
		Caller: caller, ScopeID: request.ScopeID, Cutoff: request.Cutoff,
		BatchSize: request.BatchSize, MaxRecords: request.MaxRecords})
	if err != nil {
		return ui.UIPurgePreview{}, mapAuditError(err)
	}
	return ui.UIPurgePreview{ScopeID: preview.ScopeID, ScopeKind: preview.ScopeKind,
		Cutoff: preview.Cutoff, BatchSize: preview.BatchSize,
		MaxRecords: preview.MaxRecords, EstimatedCount: preview.EstimatedCount,
		AtLeast: preview.AtLeast,
		Retention: ui.UIPurgeRetention{Days: preview.Retention.Days,
			Configured: preview.Retention.Configured,
			Version:    preview.Retention.Version, Cutoff: preview.Retention.Cutoff,
			UpdatedAt: preview.Retention.UpdatedAt},
		WithinRetention:      preview.WithinRetention,
		MaintenanceProtected: preview.MaintenanceProtected,
		ArtifactsIncluded:    preview.ArtifactsIncluded,
		Digest:               preview.Digest, GeneratedAt: preview.GeneratedAt}, nil
}

// StartPurge 提交真实清理任务；摘要不一致时服务端拒绝并要求重新预估。
func (a *AuditAdapter) StartPurge(ctx context.Context, userID string,
	request ui.UIPurgeRequest, digest, reason,
	requestID string) (ui.UIPurgeRun, error) {
	caller, err := auditCaller(userID)
	if err != nil {
		return ui.UIPurgeRun{}, err
	}
	run, err := a.opts.Audit.StartPurge(ctx, auditops.StartPurgeRequest{
		Caller: caller, ScopeID: request.ScopeID, Cutoff: request.Cutoff,
		BatchSize: request.BatchSize, MaxRecords: request.MaxRecords,
		Reason: reason, Digest: digest, RequestID: requestID})
	if err != nil {
		return ui.UIPurgeRun{}, mapAuditError(err)
	}
	return toPurgeView(run), nil
}

// CancelPurge 请求取消清理任务。
func (a *AuditAdapter) CancelPurge(ctx context.Context, userID, runID, reason,
	requestID string) (ui.UIPurgeRun, error) {
	caller, err := auditCaller(userID)
	if err != nil {
		return ui.UIPurgeRun{}, err
	}
	result, err := a.opts.Audit.CancelPurge(ctx, caller, runID, reason, requestID)
	if err != nil {
		return ui.UIPurgeRun{}, mapAuditError(err)
	}
	run, err := a.opts.Audit.GetPurgeRun(ctx, caller, runID)
	if err != nil {
		return ui.UIPurgeRun{}, mapAuditError(err)
	}
	converted := toPurgeView(run)
	if result.State == task.StateCancelRequested {
		converted.State = "cancel_requested"
	}
	return converted, nil
}

// 保留 task 包导入用于任务状态常量文档引用（真实状态来自 auditops 视图）。
var _ = task.StateQueued
