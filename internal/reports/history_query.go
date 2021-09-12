package reports

// 本文件实现步骤 79 的历史报告读路径：进程内记录未命中时回源持久历史
// （report_history），并按调用者“当前”权限与数据范围重新授权；列表按当前权限
// 分页查询。旧报告 ID/旧链接在权限撤销后不再可读，已有产物也不会被自动公开。
//
// 安全不变量：
//   - 回源读取只用持久历史，不从旧页面缓存或前端断言推断权限；每次查询/预览/
//     下载都重新授权当前调用者与数据范围。
//   - 数据范围缩小后，历史中记录的生成时范围不再被当前授权覆盖时拒绝读取。
//   - 列表不返回无权对象；读取失败与不存在使用一致的对外错误，不泄露存在性。
//   - 历史视图不含产物宿主路径；可用性按到期时间与清理状态实时计算。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
)

const (
	// historyDefaultLimit/historyMaxLimit 是历史列表页大小默认与硬上限。
	historyDefaultLimit = 20
	historyMaxLimit     = 100
)

// HistoryListRequest 是历史报告列表请求。Caller 必须来自可信调用上下文；
// 筛选字段为空表示不筛选，排序固定为创建时间倒序。
type HistoryListRequest struct {
	Caller          account.Caller
	PlanID          string
	State           string
	Limit           int
	BeforeCreatedAt time.Time
	BeforeID        string
}

// ReportHistoryView 是历史报告公开视图（受控元数据 + 产物可用性，无宿主路径）。
type ReportHistoryView struct {
	ID            string
	PlanID        string
	Name          string
	Owner         audit.Actor
	ScopeID       string
	ScopeKind     string
	AppID         string
	Template      string
	State         string
	Formats       []Format
	Categories    []stats.Category
	TrendMetric   stats.Metric
	DetailRows    int
	Artifacts     []ArtifactView
	TaskID        string
	ExecutorID    string
	ErrorCode     string
	FailureReason string
	RequestID     string
	CreatedAt     time.Time
	StartedAt     time.Time
	FinishedAt    time.Time
	ExpiresAt     time.Time
	CleanupState  string
}

// HistoryListView 是历史列表页。
type HistoryListView struct {
	Records []ReportHistoryView
	HasMore bool
	// ScopeTrimmed 表示列表已按当前权限裁剪，不代表全系统总量。
	ScopeTrimmed bool
}

// authorizeQuiet 执行一次不写拒绝审计的授权探测，用于“能力判断”（例如判断是否
// 以管理视角查看历史）。它仍以返回错误表示拒绝，绝不把错误当作放行。
func (s *Service) authorizeQuiet(ctx context.Context, caller account.Caller,
	permissionKey, scopeID string) (stats.ScopeGrant, error) {
	actor := caller.Actor()
	if err := actor.Validate(); err != nil {
		return stats.ScopeGrant{}, ErrAccessDenied
	}
	if s.isRoot(ctx, caller) {
		return stats.ScopeGrant{Allowed: true, AllData: true}, nil
	}
	grant, err := s.opts.Authorizer.AuthorizeScope(ctx, caller, permissionKey, scopeID)
	if err != nil || !grant.Allowed {
		return stats.ScopeGrant{}, ErrAccessDenied
	}
	return grant, nil
}

// historyAvailable 报告是否装配了持久历史读取能力。
func (s *Service) historyAvailable() bool {
	return !isNil(s.history)
}

// HistoryList 返回当前调用者可见的历史报告。普通调用者只能看到自己拥有且当前
// 仍有读取权限的记录；拥有 reports.schedule.manage 的管理者可查看该范围全部记录。
// 没有管理权限时不通过“编号猜测”或旧缓存扩大可见范围。
func (s *Service) HistoryList(ctx context.Context,
	request HistoryListRequest) (HistoryListView, error) {
	if !s.historyAvailable() {
		return HistoryListView{}, ErrStoreUnavailable
	}
	actor := request.Caller.Actor()
	if err := actor.Validate(); err != nil || actor.Type == audit.ActorAnonymous {
		return HistoryListView{}, ErrAccessDenied
	}
	limit := request.Limit
	if limit == 0 {
		limit = historyDefaultLimit
	}
	if limit < 1 || limit > historyMaxLimit {
		return HistoryListView{}, fmt.Errorf("%w: 历史列表页大小超出范围", ErrInvalidRequest)
	}
	if request.State != "" && !validHistoryState(request.State) {
		return HistoryListView{}, fmt.Errorf("%w: 历史状态筛选无效", ErrInvalidRequest)
	}
	beforeAt := request.BeforeCreatedAt
	beforeID := request.BeforeID
	if beforeAt.IsZero() != (beforeID == "") {
		return HistoryListView{}, fmt.Errorf("%w: 历史分页游标不完整", ErrInvalidRequest)
	}
	root := s.isRoot(ctx, request.Caller)
	readerScopes := make([]string, 0, 8)
	managerScopes := make([]string, 0, 8)
	if !root {
		scopes, err := s.history.ListHistoryScopeIDs(ctx)
		if err != nil {
			return HistoryListView{}, ErrStoreUnavailable
		}
		for _, scopeID := range scopes {
			if _, err := s.authorizeQuiet(ctx, request.Caller, PermissionRead, scopeID); err != nil {
				continue
			}
			readerScopes = append(readerScopes, scopeID)
			if _, err := s.authorizeQuiet(ctx, request.Caller,
				PermissionScheduleManage, scopeID); err == nil {
				managerScopes = append(managerScopes, scopeID)
			}
		}
	}
	type queryPlan struct {
		access AccessScope
		owner  *audit.Actor
	}
	plans := make([]queryPlan, 0, 2)
	if root {
		plans = append(plans, queryPlan{access: AccessScope{AllData: true}})
	} else {
		if len(managerScopes) > 0 {
			plans = append(plans, queryPlan{access: AccessScope{ResourceIDs: managerScopes}})
		}
		if len(readerScopes) > 0 {
			owner := request.Caller.Actor()
			plans = append(plans, queryPlan{
				access: AccessScope{ResourceIDs: readerScopes}, owner: &owner})
		}
	}
	if len(plans) == 0 {
		return HistoryListView{ScopeTrimmed: true}, nil
	}
	merged := make(map[string]HistoryRecord, limit+2)
	hasMore := false
	for _, plan := range plans {
		page, err := s.history.ListHistory(ctx, HistoryQuery{
			Access: plan.access, PlanID: request.PlanID, State: request.State,
			Owner: plan.owner, Limit: limit, BeforeCreatedAt: beforeAt, BeforeID: beforeID,
		})
		if err != nil {
			return HistoryListView{}, ErrStoreUnavailable
		}
		if page.HasMore {
			hasMore = true
		}
		for _, record := range page.Records {
			merged[record.ReportID] = record
		}
	}
	records := make([]HistoryRecord, 0, len(merged))
	for _, record := range merged {
		records = append(records, record)
	}
	sort.Slice(records, func(left, right int) bool {
		if !records[left].CreatedAt.Equal(records[right].CreatedAt) {
			return records[left].CreatedAt.After(records[right].CreatedAt)
		}
		return records[left].ReportID > records[right].ReportID
	})
	if len(records) > limit {
		records = records[:limit]
		hasMore = true
	}
	views := make([]ReportHistoryView, 0, len(records))
	for _, record := range records {
		view, err := s.historyView(record)
		if err != nil {
			return HistoryListView{}, err
		}
		views = append(views, view)
	}
	return HistoryListView{Records: views, HasMore: hasMore, ScopeTrimmed: true}, nil
}

// validHistoryState 校验历史状态白名单（与迁移 CHECK 一致）。
func validHistoryState(state string) bool {
	switch state {
	case StateQueued, StateRunning, "cancel_requested", StateCancelled,
		StateSucceeded, StateFailed, "timed_out":
		return true
	default:
		return false
	}
}

// historyArtifactRef 是历史产物引用（与写入侧 historyArtifact 对齐）。
type historyArtifactRef struct {
	Format string `json:"format"`
	Name   string `json:"name"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// historyArtifacts 解析历史产物引用；非法/缺省返回空列表（页面显示“引用不可用”），
// 不根据文件名猜测产物存在。
func historyArtifacts(record HistoryRecord) []historyArtifactRef {
	if len(record.ArtifactsJSON) == 0 {
		return nil
	}
	var refs []historyArtifactRef
	if err := json.Unmarshal(record.ArtifactsJSON, &refs); err != nil {
		return nil
	}
	return refs
}

// historyView 把持久历史记录转换为公开视图，并按真实到期/清理状态计算可用性。
func (s *Service) historyView(record HistoryRecord) (ReportHistoryView, error) {
	now := s.now()
	view := ReportHistoryView{
		ID: record.ReportID, PlanID: record.PlanID, Name: record.Name,
		Owner: record.Owner, ScopeID: record.ScopeID, ScopeKind: record.ScopeKind,
		AppID: record.AppID, Template: record.Template, State: record.State,
		Formats:     append([]Format(nil), record.Formats...),
		Categories:  append([]stats.Category(nil), record.Categories...),
		TrendMetric: record.TrendMetric, DetailRows: record.DetailRows,
		TaskID: record.TaskID, ExecutorID: record.ExecutorID,
		ErrorCode: record.ErrorCode, FailureReason: record.FailureReason,
		RequestID: record.RequestID, CreatedAt: record.CreatedAt,
		StartedAt: record.StartedAt, FinishedAt: record.FinishedAt,
		ExpiresAt: record.ExpiresAt, CleanupState: record.CleanupState,
	}
	if record.State == StateSucceeded && record.CleanupState != "cleaned" {
		refs := historyArtifacts(record)
		view.Artifacts = make([]ArtifactView, 0, len(refs))
		for _, ref := range refs {
			format := Format(ref.Format)
			if !format.Valid() || !validateArtifactName(ref.Name, format) {
				continue
			}
			expiresAt := record.ExpiresAt
			available := !expiresAt.IsZero() && now.Before(expiresAt)
			view.Artifacts = append(view.Artifacts, ArtifactView{
				Format: format, Bytes: ref.Bytes, SHA256: ref.SHA256,
				Available: available, ExpiresAt: expiresAt,
			})
		}
	}
	return view, nil
}

// historyForRead 回源读取一条历史并按当前权限重新授权。
//
// 读取顺序（对象级授权）：按编号取受控历史 → 当前读取权限 → 当前数据范围是否
// 仍覆盖生成时范围 → 所有者/root/该范围管理者。任一步失败都按“不存在或无权”
// 拒绝，不返回历史内容，也不泄露记录是否存在。
func (s *Service) historyForRead(ctx context.Context, caller account.Caller,
	reportID string) (HistoryRecord, error) {
	if !s.historyAvailable() {
		return HistoryRecord{}, ErrNotFound
	}
	if !validReportID(reportID) {
		return HistoryRecord{}, fmt.Errorf("%w: 报告编号格式无效", ErrInvalidRequest)
	}
	// 读取仅用于授权判定：范围过滤在建库 SQL 中完成，这里先按编号取记录。
	// 服务层随后用记录自己的 ScopeID 做当前权限检查；没有当前权限时不返回内容。
	broad := AccessScope{AllData: true}
	record, found, err := s.history.GetHistory(ctx, reportID, broad)
	if err != nil {
		return HistoryRecord{}, ErrStoreUnavailable
	}
	if !found {
		return HistoryRecord{}, ErrNotFound
	}
	scope, err := parseScope(record.ScopeID)
	if err != nil {
		return HistoryRecord{}, ErrNotFound
	}
	grant, err := s.authorizeScope(ctx, caller, PermissionRead, scope.ID)
	if err != nil {
		return HistoryRecord{}, ErrAccessDenied
	}
	if !s.grantCovers(decodeHistoryDataScope(record.DataScopeJSON), grant) {
		s.recordDenied(ctx, caller.Actor(), scope.ID, PermissionRead, "data_scope_shrunk")
		return HistoryRecord{}, ErrAccessDenied
	}
	if record.Owner != caller.Actor() {
		if s.isRoot(ctx, caller) {
			return record, nil
		}
		if _, err := s.authorizeQuiet(ctx, caller,
			PermissionScheduleManage, scope.ID); err != nil {
			s.recordDenied(ctx, caller.Actor(), scope.ID, PermissionScheduleManage,
				"history_not_owner_or_manager")
			return HistoryRecord{}, ErrAccessDenied
		}
	}
	return record, nil
}

// resolveHistoryArtifact 从持久历史回源下载产物（不写下载审计；OpenFile 统一写）。
// 它再次按当前权限与数据范围授权，校验真实状态/清理状态/到期/产物摘要后交给
// 宿主。它不接受历史中的任意路径，只从受控文件名解析输出目录内的文件。
func (s *Service) resolveHistoryArtifact(ctx context.Context, caller account.Caller,
	reportID string, format Format) (resolvedArtifact, error) {
	record, err := s.historyForRead(ctx, caller, reportID)
	if err != nil {
		return resolvedArtifact{}, err
	}
	for _, permission := range []string{PermissionRead, PermissionExport} {
		grant, authErr := s.authorizeScope(ctx, caller, permission, record.ScopeID)
		if authErr != nil {
			return resolvedArtifact{}, authErr
		}
		if !s.grantCovers(decodeHistoryDataScope(record.DataScopeJSON), grant) {
			s.recordDenied(ctx, caller.Actor(), record.ScopeID, permission, "data_scope_shrunk")
			return resolvedArtifact{}, ErrAccessDenied
		}
	}
	if record.State != StateSucceeded {
		return resolvedArtifact{}, fmt.Errorf("%w: 报告尚未成功完成", ErrConflict)
	}
	if record.CleanupState == "cleaned" {
		return resolvedArtifact{}, fmt.Errorf("%w: 报告产物已按保留策略清理", ErrConflict)
	}
	var ref *historyArtifactRef
	for _, candidate := range historyArtifacts(record) {
		if Format(candidate.Format) == format {
			ref = &candidate
			break
		}
	}
	if ref == nil {
		return resolvedArtifact{}, fmt.Errorf("%w: 该格式产物不存在", ErrNotFound)
	}
	if !validateArtifactName(ref.Name, format) {
		return resolvedArtifact{}, ErrArtifactUnsafe
	}
	expiresAt := record.ExpiresAt
	if expiresAt.IsZero() || !s.now().Before(expiresAt) {
		return resolvedArtifact{}, fmt.Errorf("%w: 报告产物已过期", ErrConflict)
	}
	path, err := s.openArtifact(Artifact{Format: format, FileName: ref.Name,
		SHA256: ref.SHA256, Bytes: ref.Bytes, ExpiresAt: expiresAt})
	if err != nil {
		return resolvedArtifact{}, err
	}
	return resolvedArtifact{
		file: ArtifactFile{ReportID: reportID, Format: format, HostPath: path,
			Bytes: ref.Bytes, SHA256: ref.SHA256, ExpiresAt: expiresAt},
		scopeID: record.ScopeID, requestID: record.RequestID,
	}, nil
}

// getHistorySnapshot 从持久历史回源机器可读快照；它属导出数据面，要求
// reports.read + reports.export 并对每次读取写审计。
func (s *Service) getHistorySnapshot(ctx context.Context, caller account.Caller,
	reportID string) (Snapshot, error) {
	record, err := s.historyForRead(ctx, caller, reportID)
	if err != nil {
		return Snapshot{}, err
	}
	for _, permission := range []string{PermissionRead, PermissionExport} {
		grant, authErr := s.authorizeScope(ctx, caller, permission, record.ScopeID)
		if authErr != nil {
			return Snapshot{}, authErr
		}
		if !s.grantCovers(decodeHistoryDataScope(record.DataScopeJSON), grant) {
			s.recordDenied(ctx, caller.Actor(), record.ScopeID, permission, "data_scope_shrunk")
			return Snapshot{}, ErrAccessDenied
		}
	}
	if record.State != StateSucceeded {
		return Snapshot{}, fmt.Errorf("%w: 报告尚未成功完成", ErrConflict)
	}
	if len(record.SnapshotJSON) == 0 {
		return Snapshot{}, fmt.Errorf("%w: 历史快照引用不可用", ErrConflict)
	}
	var snapshot Snapshot
	if err := json.Unmarshal(record.SnapshotJSON, &snapshot); err != nil {
		return Snapshot{}, fmt.Errorf("%w: 历史快照无法解析", ErrStoreUnavailable)
	}
	event := audit.Event{
		Actor: caller.Actor(), AppID: appIDForScope(record.ScopeID),
		Action: ActionExportSnapshot, Target: audit.Target{Type: "report", ID: reportID},
		Outcome: audit.OutcomeSuccess, RequestID: record.RequestID,
		Changes: []audit.FieldChange{{Field: "format", After: "json_snapshot"}},
	}
	if err := s.opts.Audit.Record(ctx, event); err != nil {
		return Snapshot{}, fmt.Errorf("%w: 快照读取审计写入失败", ErrAuditUnavailable)
	}
	return snapshot, nil
}

// historyViewFromRecord 把持久历史转换为 ReportView（与内存视图字段语义一致）。
func (s *Service) historyReportView(ctx context.Context, caller account.Caller,
	record HistoryRecord) ReportView {
	base, err := s.historyView(record)
	if err != nil {
		return ReportView{}
	}
	view := ReportView{
		ID: base.ID, ScopeID: base.ScopeID, ScopeKind: base.ScopeKind,
		State: base.State, Formats: base.Formats, RequestedBy: base.Owner,
		CreatedAt: base.CreatedAt, StartedAt: base.StartedAt,
		FinishedAt: base.FinishedAt, TaskID: base.TaskID,
		ExecutorID: base.ExecutorID, ErrorCode: base.ErrorCode,
		FailureReason: base.FailureReason, RequestID: base.RequestID,
		ArtifactExpiresAt: base.ExpiresAt, Artifacts: base.Artifacts,
		SchemaVersion: SchemaVersion, TemplateVersion: TemplateVersion,
	}
	if record.State == StateSucceeded && len(record.SnapshotJSON) > 0 {
		var snapshot Snapshot
		if err := json.Unmarshal(record.SnapshotJSON, &snapshot); err == nil {
			view.GeneratedAt = snapshot.Report.GeneratedAt
			view.OverallStatus = string(snapshot.Overall)
			view.Completeness = snapshot.Completeness
			view.Notes = append([]string(nil), snapshot.Notes...)
			view.Summary = ReportSummary{
				ActiveUsers:    snapshot.Activity.Total,
				TotalRawEvents: snapshot.Errors.TotalRawEvents,
				FailedRequests: snapshot.Errors.FailedRequests,
				FailedTasks:    snapshot.Errors.FailedTasks,
				DetailRows:     len(snapshot.Errors.Rows),
				TrendPoints:    len(snapshot.Trend.Points),
			}
		}
	}
	if s.opts.Tasks != nil && record.TaskID != "" {
		if job, err := s.opts.Tasks.Get(ctx, record.TaskID); err == nil {
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

// describeCleanupState 把清理状态转为直白中文；未知状态不伪装成可下载。
func describeCleanupState(state string) string {
	switch state {
	case "none":
		return "未到期清理"
	case "pending":
		return "已到期待清理"
	case "cleaned":
		return "已清理"
	default:
		return "状态未知"
	}
}

// cleanupStateAllowsDownload 报告文件清理后不可再下载。
func cleanupStateAllowsDownload(state string) bool {
	return state == "" || state == "none" || state == "pending"
}

// historyErrorsIsNotFound 判断错误是否为“不存在/无权”的统一对外表现。
func historyErrorsIsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound) || errors.Is(err, ErrAccessDenied)
}

// trimHistoryFailureReason 裁剪失败原因用于列表展示，保留可排障的短文本。
func trimHistoryFailureReason(reason string) string {
	trimmed := strings.TrimSpace(reason)
	if len(trimmed) <= 256 {
		return trimmed
	}
	return trimmed[:256]
}
