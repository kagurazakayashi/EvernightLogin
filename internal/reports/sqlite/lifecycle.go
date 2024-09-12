package sqlite

// 本文件把 reports 包的生命周期契约适配到 0042 迁移的 SQLite 仓储：
//   - *HistoryRecorder 同时实现 reports.HistoryStore（写入 + 受控读取）；
//   - *PlanProjectionStore 实现 reports.PlanProjectionStore（计划管理读模型）。
//
// 适配层只做字段映射与范围类型转换，不做授权放行，也不补造状态；范围条件仍由
// 仓储 SQL 执行，避免“全量读取后内存过滤”。
//
// 安全不变量：
//   - 历史读取必须携带服务层授权后的 AccessScope；无权范围返回空/不存在；
//   - 计划投影读取仅供服务层授权判定使用（同进程内），不得直接暴露给 HTTP 调用方；
//   - 清理只删除报告产物文件元数据状态，不接触原始审计记录。

import (
	"context"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/reports"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// toAccess 把报告领域数据范围转换为仓储范围。
func toAccess(access reports.AccessScope) AccessScope {
	return AccessScope{AllData: access.AllData, ResourceIDs: access.ResourceIDs}
}

// reportFormats 把格式列表转换为稳定字符串列表。
func reportFormats(formats []reports.Format) []string {
	result := make([]string, 0, len(formats))
	for _, format := range formats {
		result = append(result, string(format))
	}
	return result
}

// reportCategories 把统计类别列表转换为稳定字符串列表。
func reportCategories(categories []stats.Category) []string {
	result := make([]string, 0, len(categories))
	for _, category := range categories {
		result = append(result, string(category))
	}
	return result
}

// historyRecordToStore 把受控历史条目映射为仓储记录。
func historyRecordToStore(record reports.HistoryRecord) HistoryRecord {
	return HistoryRecord{
		ID: record.ReportID, PlanID: record.PlanID, RetryOf: record.RetryOf,
		Name:  record.Name,
		Owner: record.Owner, ScopeID: record.ScopeID, ScopeKind: record.ScopeKind,
		AppID: record.AppID, Template: record.Template, State: record.State,
		Formats: reportFormats(record.Formats), Categories: reportCategories(record.Categories),
		TrendMetric: string(record.TrendMetric), DetailRows: record.DetailRows,
		DataScopeJSON: record.DataScopeJSON, WindowJSON: record.WindowJSON,
		SnapshotJSON: record.SnapshotJSON, ArtifactsJSON: record.ArtifactsJSON,
		TaskID: record.TaskID, ExecutorID: record.ExecutorID,
		ErrorCode: record.ErrorCode, FailureReason: record.FailureReason,
		RequestID: record.RequestID, CreatedAt: record.CreatedAt,
		StartedAt: record.StartedAt, FinishedAt: record.FinishedAt,
		ExpiresAt: record.ExpiresAt, CleanupState: record.CleanupState,
	}
}

// historyRecordFromStore 把仓储记录映射为受控历史条目。
func historyRecordFromStore(record HistoryRecord) reports.HistoryRecord {
	formats := make([]reports.Format, 0, len(record.Formats))
	for _, format := range record.Formats {
		formats = append(formats, reports.Format(format))
	}
	categories := make([]stats.Category, 0, len(record.Categories))
	for _, category := range record.Categories {
		categories = append(categories, stats.Category(category))
	}
	return reports.HistoryRecord{
		ReportID: record.ID, PlanID: record.PlanID, RetryOf: record.RetryOf,
		Name:  record.Name,
		Owner: record.Owner, ScopeID: record.ScopeID, ScopeKind: record.ScopeKind,
		AppID: record.AppID, Template: record.Template, State: record.State,
		Formats: formats, Categories: categories,
		TrendMetric: stats.Metric(record.TrendMetric), DetailRows: record.DetailRows,
		DataScopeJSON: record.DataScopeJSON, WindowJSON: record.WindowJSON,
		SnapshotJSON: record.SnapshotJSON, ArtifactsJSON: record.ArtifactsJSON,
		TaskID: record.TaskID, ExecutorID: record.ExecutorID,
		ErrorCode: record.ErrorCode, FailureReason: record.FailureReason,
		RequestID: record.RequestID, CreatedAt: record.CreatedAt,
		StartedAt: record.StartedAt, FinishedAt: record.FinishedAt,
		ExpiresAt: record.ExpiresAt, RetentionUntil: record.RetentionUntil,
		CleanupState: record.CleanupState,
	}
}

// GetHistory 实现 reports.HistoryReader：按编号与数据范围读取持久历史。
func (h *HistoryRecorder) GetHistory(ctx context.Context, reportID string,
	access reports.AccessScope) (reports.HistoryRecord, bool, error) {
	record, found, err := h.store.GetHistory(ctx, reportID, toAccess(access))
	if err != nil || !found {
		return reports.HistoryRecord{}, found, err
	}
	return historyRecordFromStore(record), true, nil
}

// ListHistory 实现 reports.HistoryReader：受控分页列表。
func (h *HistoryRecorder) ListHistory(ctx context.Context,
	query reports.HistoryQuery) (reports.HistoryPage, error) {
	storeQuery := HistoryQuery{
		Access: toAccess(query.Access), PlanID: query.PlanID, State: query.State,
		Limit: query.Limit, BeforeCreatedAt: query.BeforeCreatedAt,
		BeforeID: query.BeforeID, Search: query.Search,
	}
	for _, field := range query.SearchFields {
		storeQuery.SearchFields = append(storeQuery.SearchFields, string(field))
	}
	if query.Owner != nil {
		storeQuery.OwnerType = string(query.Owner.Type)
		storeQuery.OwnerID = query.Owner.ID
	}
	page, err := h.store.ListHistory(ctx, storeQuery)
	if err != nil {
		return reports.HistoryPage{}, err
	}
	records := make([]reports.HistoryRecord, 0, len(page.Records))
	for _, record := range page.Records {
		records = append(records, historyRecordFromStore(record))
	}
	return reports.HistoryPage{Records: records, HasMore: page.HasMore}, nil
}

// ListHistoryScopeIDs 实现 reports.HistoryReader。
func (h *HistoryRecorder) ListHistoryScopeIDs(ctx context.Context) ([]string, error) {
	return h.store.ListHistoryScopeIDs(ctx)
}

// ListCleanupCandidateScopes 实现 reports.HistoryReader。
func (h *HistoryRecorder) ListCleanupCandidateScopes(ctx context.Context,
	cutoff time.Time) ([]string, error) {
	return h.store.ListCleanupCandidateScopes(ctx, cutoff)
}

// ListCleanupCandidates 实现 reports.HistoryReader。
func (h *HistoryRecorder) ListCleanupCandidates(ctx context.Context,
	access reports.AccessScope, cutoff time.Time, limit int) ([]reports.HistoryRecord, error) {
	records, err := h.store.ListCleanupCandidates(ctx, toAccess(access), cutoff, limit)
	if err != nil {
		return nil, err
	}
	result := make([]reports.HistoryRecord, 0, len(records))
	for _, record := range records {
		result = append(result, historyRecordFromStore(record))
	}
	return result, nil
}

// MarkHistoryCleanup 实现 reports.HistoryReader。
func (h *HistoryRecorder) MarkHistoryCleanup(ctx context.Context,
	reportID, cleanupState string) error {
	return h.store.MarkHistoryCleanup(ctx, reportID, cleanupState)
}

// 编译期确认历史适配器同时满足写入与读取契约。
var _ reports.HistoryStore = (*HistoryRecorder)(nil)

// PlanProjectionStore 是 reports.PlanProjectionStore 的 SQLite 实现。
type PlanProjectionStore struct {
	store *Store
}

// NewPlanProjectionStore 包装报告计划仓储；store 为空时拒绝构造。
func NewPlanProjectionStore(store *Store) (*PlanProjectionStore, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: 报告计划仓储为空", reports.ErrOptionsInvalid)
	}
	return &PlanProjectionStore{store: store}, nil
}

// 编译期确认实现 reports.PlanProjectionStore。
var _ reports.PlanProjectionStore = (*PlanProjectionStore)(nil)

// planProjectionToRecord 把领域投影映射为仓储记录。
func planProjectionToRecord(plan reports.PlanProjection) PlanRecord {
	return PlanRecord{
		ID: plan.ID, Name: plan.Name, Owner: plan.Owner,
		ExecutionActor: plan.ExecutionActor, ScopeID: plan.ScopeID,
		ScopeKind: plan.ScopeKind, AppID: plan.AppID, Template: plan.Template,
		ScheduleType: string(plan.ScheduleType), Expression: plan.Expression,
		TimeZone: plan.TimeZone, Granularity: string(plan.Granularity),
		WindowDays: plan.WindowDays, Categories: reportCategories(plan.Categories),
		TrendMetric: string(plan.TrendMetric), Formats: reportFormats(plan.Formats),
		DetailRows: plan.DetailRows, MissedPolicy: string(plan.MissedPolicy),
		MaxCatchUp: plan.MaxCatchUp, TimeoutSeconds: plan.TimeoutSeconds,
		MaxAttempts: plan.MaxAttempts, Enabled: plan.Enabled, Version: plan.Version,
		CreatedAt: plan.CreatedAt, UpdatedAt: plan.UpdatedAt,
	}
}

// planProjectionFromRecord 把仓储记录映射为领域投影。
func planProjectionFromRecord(plan PlanRecord) reports.PlanProjection {
	categories := make([]stats.Category, 0, len(plan.Categories))
	for _, category := range plan.Categories {
		categories = append(categories, stats.Category(category))
	}
	formats := make([]reports.Format, 0, len(plan.Formats))
	for _, format := range plan.Formats {
		formats = append(formats, reports.Format(format))
	}
	return reports.PlanProjection{
		ID: plan.ID, Name: plan.Name, Owner: plan.Owner,
		ExecutionActor: plan.ExecutionActor, ScopeID: plan.ScopeID,
		ScopeKind: plan.ScopeKind, AppID: plan.AppID, Template: plan.Template,
		ScheduleType: task.ScheduleType(plan.ScheduleType),
		Expression:   plan.Expression, TimeZone: plan.TimeZone,
		Granularity: stats.Granularity(plan.Granularity), WindowDays: plan.WindowDays,
		Categories: categories, TrendMetric: stats.Metric(plan.TrendMetric),
		Formats: formats, DetailRows: plan.DetailRows,
		MissedPolicy: task.MissedPolicy(plan.MissedPolicy),
		MaxCatchUp:   plan.MaxCatchUp, TimeoutSeconds: plan.TimeoutSeconds,
		MaxAttempts: plan.MaxAttempts, Enabled: plan.Enabled, Version: plan.Version,
		CreatedAt: plan.CreatedAt, UpdatedAt: plan.UpdatedAt,
	}
}

// CreatePlanProjection 实现 reports.PlanProjectionStore。
func (p *PlanProjectionStore) CreatePlanProjection(ctx context.Context,
	plan reports.PlanProjection) (reports.PlanProjection, error) {
	created, err := p.store.CreatePlan(ctx, planProjectionToRecord(plan))
	if err != nil {
		return reports.PlanProjection{}, err
	}
	return planProjectionFromRecord(created), nil
}

// GetPlanProjection 实现 reports.PlanProjectionStore。返回值仅供服务层授权判定，
// 不得直接作为页面数据源对外输出。
func (p *PlanProjectionStore) GetPlanProjection(ctx context.Context,
	planID string) (reports.PlanProjection, bool, error) {
	record, found, err := p.store.GetPlan(ctx, planID, AccessScope{AllData: true})
	if err != nil || !found {
		return reports.PlanProjection{}, found, err
	}
	return planProjectionFromRecord(record), true, nil
}

// UpdatePlanProjection 实现 reports.PlanProjectionStore：行版本不一致返回
// reports.ErrConflict，不静默覆盖他人修改。
func (p *PlanProjectionStore) UpdatePlanProjection(ctx context.Context,
	plan reports.PlanProjection, expectedVersion int64) (reports.PlanProjection, error) {
	updated, err := p.store.UpdatePlan(ctx, planProjectionToRecord(plan), expectedVersion)
	if err != nil {
		return reports.PlanProjection{}, err
	}
	return planProjectionFromRecord(updated), nil
}

// SetPlanProjectionEnabled 实现 reports.PlanProjectionStore。
func (p *PlanProjectionStore) SetPlanProjectionEnabled(ctx context.Context,
	planID string, enabled bool) error {
	plan, found, err := p.store.GetPlan(ctx, planID, AccessScope{AllData: true})
	if err != nil {
		return err
	}
	if !found {
		return reports.ErrNotFound
	}
	_, err = p.store.SetPlanEnabled(ctx, planID, enabled, plan.Version, time.Now().UTC())
	return err
}

// ListPlanProjectionIDs 返回读模型中全部计划编号，供服务层对账清理残留投影。
func (p *PlanProjectionStore) ListPlanProjectionIDs(ctx context.Context) ([]string, error) {
	return p.store.ListPlanIDs(ctx)
}

// DeletePlanProjection 实现 reports.PlanProjectionStore。
func (p *PlanProjectionStore) DeletePlanProjection(ctx context.Context,
	planID string) error {
	plan, found, err := p.store.GetPlan(ctx, planID, AccessScope{AllData: true})
	if err != nil {
		return err
	}
	if !found {
		return reports.ErrNotFound
	}
	return p.store.DeletePlan(ctx, planID, plan.Version)
}
