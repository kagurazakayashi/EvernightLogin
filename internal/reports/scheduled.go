package reports

// 本文件实现步骤 79 的计划触发报告生成处理器：报告计划由 internal/task 调度器
// 在触发前做一次权限复验，这里在真正执行前再用计划所有者（执行身份）的当前权限
// 与数据范围复核一次，避免「触发前有权限、执行时已失权」的窄窗口。
//
// 安全不变量：
//   - 执行身份必须与任务发起身份一致，不接受载荷自报他人身份。
//   - 授权失败不创建报告记录、不写产物；任务以真实失败终态记录，不伪造成功。
//   - 统计窗口在每次执行时按触发时刻重新计算（相对窗口），历史报告不共享窗口。
//   - 与即时报告使用同一快照构建、渲染、终态与审计实现，不复制两套语义。

import (
	"context"
	"fmt"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// GenerateScheduledHandler 是注册到 internal/task 的「计划报告生成」处理器。
// 宿主应把 TaskKindPlannedReportGenerate 映射到本方法；它与即时报告的
// GenerateHandler 分开注册，避免把无报告的定时触发交给即时记录路径。
func (s *Service) GenerateScheduledHandler(ctx context.Context, job task.Job) error {
	if job.Kind != TaskKindPlannedReportGenerate {
		return fmt.Errorf("%w: 任务类型不匹配", ErrInvalidRequest)
	}
	payload, err := decodePlanPayload(job.Payload)
	if err != nil {
		return err
	}
	owner, err := payload.Owner.auditActor()
	if err != nil {
		return ErrAccessDenied
	}
	// 执行身份必须是计划所有者本人：调度器用 ExecutionActor 入队，载荷中的所有者
	// 只用于显示与审计；两者不一致说明载荷被篡改或装配错误，默认拒绝。
	if owner != job.Initiator {
		s.recordDenied(ctx, job.Initiator, payload.ScopeID, PermissionRead, "scheduled_owner_mismatch")
		return ErrAccessDenied
	}
	caller, err := callerFromActor(owner)
	if err != nil {
		return ErrAccessDenied
	}
	scope, err := parseScope(payload.ScopeID)
	if err != nil {
		return ErrAccessDenied
	}
	// 执行时再次授权：读取（数据来源需要）、生成、导出缺一不可；拒绝时不再继续。
	readGrant, err := s.authorizeScope(ctx, caller, PermissionRead, scope.ID)
	if err != nil {
		return s.rejectScheduled(ctx, owner, payload, "计划执行读取权限已失效")
	}
	if _, err := s.authorizeScope(ctx, caller, PermissionGenerate, scope.ID); err != nil {
		return s.rejectScheduled(ctx, owner, payload, "计划执行生成权限已失效")
	}
	if _, err := s.authorizeScope(ctx, caller, PermissionExport, scope.ID); err != nil {
		return s.rejectScheduled(ctx, owner, payload, "计划执行导出权限已失效")
	}
	if err := validateAppFilter(payload.AppID, scope, readGrant); err != nil {
		return s.rejectScheduled(ctx, owner, payload, "计划应用筛选超出当前数据范围")
	}
	formats := formatSortedFormats(formatsOf(payload.Formats))
	if len(formats) == 0 {
		return s.rejectScheduled(ctx, owner, payload, "计划没有可生成的输出格式")
	}
	// PDF 依赖受信字体：运行期字体能力变化时拒绝本次执行，不生成缺字假 PDF。
	if containsFormat(formats, FormatPDF) && !s.PDFAvailable() {
		return s.rejectScheduled(ctx, owner, payload, "PDF 输出当前不可用")
	}
	now := s.now()
	// 相对窗口：每次执行按本次触发时刻回看 WindowDays 天，而不是复用计划创建时
	// 冻结的绝对窗口；边界与去重口径由 stats.NormalizeWindow 统一定义。
	window, err := stats.NormalizeWindow(stats.WindowRequest{
		TimeZone:    payload.TimeZone,
		Start:       now.AddDate(0, 0, -payload.WindowDays),
		End:         now,
		Granularity: stats.Granularity(payload.Granularity),
	}, now)
	if err != nil {
		return s.rejectScheduled(ctx, owner, payload, "计划统计窗口无效")
	}
	reportID, err := s.newID(reportIDPrefix)
	if err != nil {
		return err
	}
	record := &reportRecord{
		ID: reportID, PlanID: payload.PlanID, Name: payload.Name,
		Template: "standard",
		ScopeID:  scope.ID, ScopeKind: scope.Kind,
		RequestedBy: owner, State: StateQueued, Formats: formats,
		Window: window, AppID: payload.AppID,
		Categories:  categoriesOf(payload.Categories),
		TrendMetric: stats.Metric(payload.TrendMetric), DetailRows: payload.DetailRows,
		DataScope: dataScope{All: readGrant.AllData,
			Resources: append([]string(nil), readGrant.ResourceIDs...)},
		RequestID: normalizeRequestID(job.RequestID), CreatedAt: now,
		ExpiresAt: now.Add(s.artifactTTL),
	}
	s.insert(record)
	started := s.mutate(reportID, func(current *reportRecord) bool {
		if current.State != StateQueued {
			return false
		}
		current.State = StateRunning
		current.ExecutorID = job.ExecutorID
		current.StartedAt = now
		return true
	})
	if !started {
		return ErrTaskTerminal
	}
	// 重新读取记录副本交给共享生成核心；后续状态变更都在核心内部幂等提交。
	current, found := s.get(reportID)
	if !found {
		return ErrNotFound
	}
	return s.runGeneration(ctx, current, job)
}

// rejectScheduled 记录计划执行拒绝：写失败审计并返回 ErrAccessDenied。它不创建
// 报告记录、不写产物，避免为一次失权执行留下可下载的假报告。
func (s *Service) rejectScheduled(ctx context.Context, owner audit.Actor,
	payload planPayload, reason string) error {
	s.recordFailure(ctx, owner, ActionGenerateRequest, payload.ScopeID,
		"plan_execution_denied", CodeReportAccessDenied, "", "")
	// 历史中留一条“执行前拒绝、未生成报告”的真实记录：状态为 failed、错误码
	// ACCESS_DENIED，绝不写成成功；页面可据此显示失权原因与恢复路径。
	s.persistRejectedHistory(ctx, HistoryRecord{
		Name: payload.Name, Owner: owner, ScopeID: payload.ScopeID,
		ScopeKind: payload.ScopeKind, AppID: payload.AppID,
		State: StateFailed, Formats: formatsOf(payload.Formats),
		Categories:  categoriesOf(payload.Categories),
		TrendMetric: stats.Metric(payload.TrendMetric), DetailRows: payload.DetailRows,
		ErrorCode: string(CodeAccessDenied), FailureReason: reason,
		WindowJSON: []byte("{}"), ArtifactsJSON: []byte("[]"),
	})
	return fmt.Errorf("%w: %s", ErrAccessDenied, reason)
}
