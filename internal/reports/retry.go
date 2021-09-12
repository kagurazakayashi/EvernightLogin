package reports

// 本文件实现历史报告的受控重试（步骤 79 验收要求「历史列表提供…重试」「取消/失败重试」）：
// 仅失败/取消/超时终态可重试；重试前按当前权限与数据范围重新授权并执行敏感操作
// 校验（复用 reports.export 策略的强认证/确认），生成新的运行记录并保留原记录，
// 通过 RetryOf 链式关联；不覆盖、不删除原记录，不伪造成功。
//
// 安全不变量：
//   - 重试不是“再下载一次”：始终创建新报告记录与新任务，原记录的真实状态保留。
//   - 每次重试都重新授权当前调用者的 read/generate/export 与数据范围，并复核
//     发起者/root/该范围管理者；权限撤销后不能借重试继续生成。
//   - 重试的敏感操作校验绑定原报告、范围与格式；审计写入失败时不创建可执行任务
//     （fail-closed），不留下“已重试但无审计”的静默导出。
//   - 历史回源的重试在进程重启后仍可用：从持久历史恢复窗口/格式/类别/数据范围，
//     但执行期仍由处理器再次授权。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
)

// ActionRetry 是报告重试的稳定审计动作。
const ActionRetry = "reports.retry"

// retryableState 判断报告真实终态是否允许重试：只有失败/取消/超时可以重试；
// 进行中重复重试会与既有任务竞争，成功报告没有重试意义（重新生成请新建）。
func retryableState(state string) bool {
	switch state {
	case StateFailed, StateCancelled, "timed_out":
		return true
	default:
		return false
	}
}

// recordFromHistory 从持久历史恢复可重试的报告参数；不能恢复完整参数时拒绝重试
// （不猜测窗口或格式，避免生成与历史不一致的新报告）。
func recordFromHistory(record HistoryRecord) (reportRecord, error) {
	result := reportRecord{
		ID: record.ReportID, PlanID: record.PlanID, Name: record.Name,
		Template: record.Template, ScopeID: record.ScopeID,
		ScopeKind: record.ScopeKind, RequestedBy: record.Owner,
		State: record.State, Formats: append([]Format(nil), record.Formats...),
		Categories:  append([]stats.Category(nil), record.Categories...),
		TrendMetric: record.TrendMetric, DetailRows: record.DetailRows,
		DataScope: decodeHistoryDataScope(record.DataScopeJSON),
		TaskID:    record.TaskID, ExecutorID: record.ExecutorID,
		RequestID: record.RequestID, CreatedAt: record.CreatedAt,
		StartedAt: record.StartedAt, FinishedAt: record.FinishedAt,
		ExpiresAt: record.ExpiresAt, ErrorCode: record.ErrorCode,
		FailureReason: record.FailureReason, RetryOf: record.RetryOf,
	}
	if len(record.WindowJSON) > 0 {
		var window stats.Window
		if err := json.Unmarshal(record.WindowJSON, &window); err != nil ||
			window.TimeZone == "" || len(window.Buckets) == 0 {
			return reportRecord{}, fmt.Errorf("%w: 历史窗口无法恢复，不能重试", ErrConflict)
		}
		result.Window = window
	}
	if result.DetailRows < 1 {
		result.DetailRows = DefaultDetailRows
	}
	if len(result.Formats) == 0 {
		return reportRecord{}, fmt.Errorf("%w: 历史报告缺少输出格式，不能重试", ErrConflict)
	}
	return result, nil
}

// authorizeRetrySensitive 执行重试的敏感操作校验（复用 reports.export 策略的强认证/
// 确认），参数绑定原报告、范围、格式与动作；拒绝时返回 ErrAccessDenied。
func (s *Service) authorizeRetrySensitive(ctx context.Context, caller account.Caller,
	scopeID, reportID string, formats []Format,
	requestID string) (reauth.Result, error) {
	reauthCaller, err := reauth.CallerFromActor(caller.Actor())
	if err != nil {
		return reauth.Result{}, ErrAccessDenied
	}
	formatText := make([]string, 0, len(formats))
	for _, format := range formats {
		formatText = append(formatText, string(format))
	}
	result, err := s.opts.Sensitive.Authorize(ctx, reauthCaller, reauth.Request{
		ScopeID: scopeID, OperationID: OperationExport,
		TargetType: "report", TargetID: reportID,
		Params: map[string]string{
			"action": "retry", "retry_of": reportID, "scope": scopeID,
			"formats":     joinFormatText(formatText),
			"detail_rows": strconv.Itoa(DefaultDetailRows),
		},
		Description: "重试生成统计报告",
		RequestID:   requestID,
	})
	if err != nil {
		return reauth.Result{}, fmt.Errorf("%w: %w", ErrAccessDenied, err)
	}
	return result, nil
}

// joinFormatText 拼接格式列表用于敏感操作参数摘要。
func joinFormatText(formats []string) string {
	result := ""
	for index, format := range formats {
		if index > 0 {
			result += ","
		}
		result += format
	}
	return result
}

// retryDenied 返回对外一致的拒绝：既不确认报告是否存在，也不暴露终态。它同时
// 匹配 ErrAccessDenied（既有调用方语义）与 ErrNotFound（不泄露存在性），使无权限
// 调用者无法通过 ACCESS_DENIED/CONFLICT/NOT_FOUND 差异探测报告 ID 与终态。
func retryDenied() error {
	return fmt.Errorf("%w: %w", ErrAccessDenied, ErrNotFound)
}

// Retry 重试一份失败/取消/超时的报告：重新授权、敏感操作校验、创建新运行记录与
// 新任务，并通过 RetryOf 关联原记录；原记录保持不变。
func (s *Service) Retry(ctx context.Context, caller account.Caller, reportID,
	reason, requestID string) (ReportView, error) {
	if !validReportID(reportID) {
		return ReportView{}, fmt.Errorf("%w: 报告编号格式无效", ErrInvalidRequest)
	}
	actor := caller.Actor()
	if err := actor.Validate(); err != nil || actor.Type == audit.ActorAnonymous {
		return ReportView{}, ErrAccessDenied
	}
	if err := validateReason(reason); err != nil {
		return ReportView{}, err
	}
	requestID = normalizeRequestID(requestID)
	var record reportRecord
	found := false
	if memoryRecord, ok := s.get(reportID); ok {
		record = memoryRecord
		found = true
	} else if s.historyAvailable() {
		historyRecord, err := s.historyForRead(ctx, caller, reportID)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return ReportView{}, ErrNotFound
			}
			return ReportView{}, retryDenied()
		}
		restored, restoreErr := recordFromHistory(historyRecord)
		if restoreErr != nil {
			return ReportView{}, restoreErr
		}
		record = restored
		found = true
	}
	if !found {
		return ReportView{}, ErrNotFound
	}
	// 授权先于状态检查：无权限调用者不能通过 CONFLICT/ACCESS_DENIED 差异探测
	// 报告是否存在或处于何种终态。
	scope, err := parseScope(record.ScopeID)
	if err != nil {
		return ReportView{}, ErrNotFound
	}
	readGrant, err := s.authorizeScope(ctx, caller, PermissionRead, scope.ID)
	if err != nil {
		return ReportView{}, retryDenied()
	}
	if !s.grantCovers(record.DataScope, readGrant) {
		s.recordDenied(ctx, actor, scope.ID, PermissionRead, "data_scope_shrunk")
		return ReportView{}, retryDenied()
	}
	for _, permission := range []string{PermissionGenerate, PermissionExport} {
		grant, authErr := s.authorizeScope(ctx, caller, permission, scope.ID)
		if authErr != nil {
			return ReportView{}, retryDenied()
		}
		if !s.grantCovers(record.DataScope, grant) {
			s.recordDenied(ctx, actor, scope.ID, permission, "data_scope_shrunk")
			return ReportView{}, retryDenied()
		}
	}
	if record.RequestedBy != actor && !s.isRoot(ctx, caller) {
		if _, manageErr := s.authorizeQuiet(ctx, caller,
			PermissionScheduleManage, scope.ID); manageErr != nil {
			s.recordFailure(ctx, actor, ActionRetry, scope.ID, "retry_not_owner",
				CodeReportAccessDenied, requestID, reportID)
			return ReportView{}, retryDenied()
		}
	}
	sensitiveResult, err := s.authorizeRetrySensitive(ctx, caller, scope.ID,
		reportID, record.Formats, requestID)
	if err != nil {
		s.recordFailure(ctx, actor, ActionRetry, scope.ID, "retry_reauth_denied",
			CodeAccessDenied, requestID, reportID)
		return ReportView{}, err
	}
	// 授权通过后才检查终态：仅失败/取消/超时可重试，成功与进行中拒绝（不覆盖）。
	if !retryableState(record.State) {
		return ReportView{}, fmt.Errorf("%w: 只有失败/取消/超时的报告可以重试", ErrConflict)
	}
	newID, err := s.newID(reportIDPrefix)
	if err != nil {
		return ReportView{}, err
	}
	now := s.now()
	retried := reportRecord{
		ID: newID, PlanID: record.PlanID, Name: record.Name,
		Template: record.Template, ScopeID: record.ScopeID,
		ScopeKind: record.ScopeKind, RequestedBy: actor, State: StateQueued,
		Formats: append([]Format(nil), record.Formats...),
		Window:  record.Window, AppID: record.AppID,
		Categories:  append([]stats.Category(nil), record.Categories...),
		TrendMetric: record.TrendMetric, DetailRows: record.DetailRows,
		DataScope: dataScope{All: readGrant.AllData,
			Resources: append([]string(nil), readGrant.ResourceIDs...)},
		RequestID: requestID, RetryOf: reportID,
		CreatedAt: now, ExpiresAt: now.Add(s.artifactTTL),
	}
	// 先写重试审计（fail-closed）：审计不可用时不留可执行任务或“已重试”假记录。
	event := audit.Event{
		Actor: actor, AppID: appIDForScope(scope.ID), Action: ActionRetry,
		Target:  audit.Target{Type: "report", ID: newID},
		Outcome: audit.OutcomeSuccess, RequestID: requestID,
		Changes: []audit.FieldChange{
			{Field: "retry_of", After: reportID},
			{Field: "previous_state", After: record.State},
			{Field: "reason_present", After: "true"},
		},
	}
	if err := s.opts.Audit.Record(ctx, event); err != nil {
		s.notifySensitiveResult(ctx, sensitiveResult)
		return ReportView{}, fmt.Errorf("%w: 重试审计写入失败", ErrAuditUnavailable)
	}
	s.insert(&retried)
	job, enqueueErr := s.enqueue(ctx, actor, newID, requestID)
	if enqueueErr != nil {
		s.failRecord(context.WithoutCancel(ctx), newID, ErrTaskRejected,
			CodeDBUnavailable, "重试任务入队失败", requestID)
		return ReportView{}, fmt.Errorf("%w: 重试任务入队失败", ErrTaskRejected)
	}
	s.mutate(newID, func(current *reportRecord) bool {
		if current.State != StateQueued {
			return false
		}
		current.TaskID = job.ID
		return true
	})
	s.persistHistory(ctx, newID)
	s.notifySensitiveResult(ctx, sensitiveResult)
	view, foundView := s.get(newID)
	if !foundView {
		return ReportView{}, ErrNotFound
	}
	return s.viewFromRecord(ctx, view), nil
}

// notifySensitiveResult 在敏感操作成功后尽力告知；失败只告警。
func (s *Service) notifySensitiveResult(ctx context.Context, result reauth.Result) {
	if result.OperationID == "" {
		return
	}
	if err := s.opts.Sensitive.NotifyOutcome(ctx, result, reauth.OutcomeSuccess); err != nil {
		s.opts.Logger.Warn("报告重试安全告知未完成", "reason", "notify_unavailable")
	}
}
