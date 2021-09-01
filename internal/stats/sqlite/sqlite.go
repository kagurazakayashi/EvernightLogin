// Package sqlite 实现 internal/stats.Store 的 SQLite 生产持久化。
//
// 表由 migrations/0041_statistics.sql 创建，本包不执行迁移；调用方应在启动或测试
// 中先通过 internal/storage/migrate 应用全部迁移。本包不拥有数据库连接：
// *sqlite.Store 的关闭由外层负责。构造后不可变，可被多个 goroutine 并发使用。
//
// 安全不变量：
//   - 活跃/错误聚合只读取 audit_events（可信审计事实），范围约束（应用快照 ID
//     集合/系统级事件）直接写进 SQL WHERE 子句，不提供全量读取后内存过滤的接口。
//   - 只有“完整成功认证”计入活跃：actor_type=user 且 outcome=success，并限定
//     session.issue 的 session_kind=normal（受限/待补步骤会话不计入）或可信登录
//     批准后的 session.login_grant_issued。
//   - 去重失败请求/任务数按稳定 request_id/task_id 去重；缺失关联编号时以事件 ID
//     计一个逻辑请求/任务，不把同一失败的多条日志或任务重试重复计数。
//   - 健康采样按 (module, observed_at_ms) 幂等写入；清理按截止时间与单次行数上限
//     删除，限制存储增长。业务活动上报用唯一 dedupe_key 幂等。
//   - 不返回连接串、凭据、原始事件正文或自由文本。
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

// Store 是 stats.Store 的 SQLite 实现。
type Store struct {
	store *storagesqlite.Store
}

// New 包装一个已打开并完成迁移的 SQLite 存储。store 为空时返回
// stats.ErrOptionsInvalid，不会创建替代连接。
func New(store *storagesqlite.Store) (*Store, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", stats.ErrOptionsInvalid)
	}
	return &Store{store: store}, nil
}

// 编译期确认实现 stats.Store。
var _ stats.Store = (*Store)(nil)

// authFactSQL 查询完整成功认证事实。session_kind=normal 由审计差异 detail_json
// 的固定字段表达（写入侧由 audit.DetailJSON 稳定序列化）；此条件与审计写入格式
// 绑定，修改序列化格式必须同步本查询与测试。
const authFactSQL = `SELECT occurred_at_ms, actor_id, COALESCE(app_id_snapshot,'')
FROM audit_events
WHERE occurred_at_ms >= ? AND occurred_at_ms < ?
AND actor_type = 'user' AND actor_id IS NOT NULL AND actor_id <> ''
AND outcome = 'success'
AND (action = 'session.login_grant_issued'
     OR (action = 'session.issue'
         AND detail_json LIKE '%"field":"session_kind","after":"normal"%'))`

// errorGroupSQL 查询错误统计候选分组。SQL 只做粗筛（拒绝/失败/统计相关动作或
// 警告码），最终类别与严重度由 stats.ClassifyEvent 在服务层统一判定，避免 SQL 与
// 业务字典两套分类漂移。行级去重失败请求/任务数只统计失败结果，并排除任务取消与
// 数据质量警告（取消/警告不是失败；正常拒绝只保留原始次数）。
func errorGroupSQL() (string, []any) {
	condition, conditionArgs := failureDedupeCondition()
	args := make([]any, 0, 2*len(conditionArgs))
	args = append(args, conditionArgs...)
	args = append(args, conditionArgs...)
	sqlText := `SELECT COALESCE(error_code,''), COALESCE(app_id_snapshot,''),
outcome, action, COUNT(*),
COUNT(DISTINCT CASE WHEN ` + condition + ` THEN CASE WHEN request_id IS NOT NULL AND request_id <> '' THEN request_id ELSE id END END),
COUNT(DISTINCT CASE WHEN ` + condition + ` THEN task_id END),
MIN(occurred_at_ms), MAX(occurred_at_ms)
FROM audit_events
WHERE occurred_at_ms >= ? AND occurred_at_ms < ?`
	return sqlText, args
}

// failureDedupeCondition 返回“失败结果且非取消结果/非警告”的 SQL 条件与参数，供行级
// 去重计数与全局去重计数共用，避免两处口径漂移。
func failureDedupeCondition() (string, []any) {
	parts := []string{"outcome = 'failure'"}
	args := make([]any, 0, 8)
	// 不按动作排除：取消类动作以失败结果结束时是“取消失败”，仍要计入失败请求/
	// 任务去重；只排除取消结果码与数据质量警告码。
	if codes := stats.NonFailureCodes(); len(codes) > 0 {
		placeholders := make([]string, len(codes))
		for index, code := range codes {
			placeholders[index] = "?"
			args = append(args, code)
		}
		parts = append(parts, "COALESCE(error_code,'') NOT IN ("+strings.Join(placeholders, ",")+")")
	}
	return strings.Join(parts, " AND "), args
}

// GetRetention 实现 stats.Store。
func (s *Store) GetRetention(ctx context.Context) (stats.RetentionRecord, bool, error) {
	row := s.store.DB().QueryRowContext(ctx,
		`SELECT retention_days, version, updated_at_ms FROM audit_retention_policy WHERE id = 1`)
	var record stats.RetentionRecord
	var updatedAtMS int64
	if err := row.Scan(&record.Days, &record.Version, &updatedAtMS); err != nil {
		if err == sql.ErrNoRows {
			return stats.RetentionRecord{}, false, nil
		}
		return stats.RetentionRecord{}, false, err
	}
	record.UpdatedAt = time.UnixMilli(updatedAtMS).UTC()
	return record, true, nil
}

// QueryAuthFacts 实现 stats.Store。
func (s *Store) QueryAuthFacts(ctx context.Context,
	query stats.AuthFactQuery) (stats.AuthFactPage, error) {
	limit := query.Limit
	if limit <= 0 {
		limit = stats.MaxFactRows
	}
	where, scopeArgs := scopeClause(query.Scope, "app_id_snapshot")
	sqlText := authFactSQL + where + " ORDER BY occurred_at_ms, id LIMIT ?"
	args := []any{query.From.UTC().UnixMilli(), query.To.UTC().UnixMilli()}
	args = append(args, scopeArgs...)
	args = append(args, limit+1)
	rows, err := s.store.QueryContext(ctx, sqlText, args...)
	if err != nil {
		return stats.AuthFactPage{}, err
	}
	defer rows.Close()
	page := stats.AuthFactPage{Facts: make([]stats.AuthFact, 0, limit)}
	for rows.Next() {
		var occurredAtMS int64
		var fact stats.AuthFact
		if err := rows.Scan(&occurredAtMS, &fact.UserID, &fact.AppID); err != nil {
			return stats.AuthFactPage{}, err
		}
		fact.OccurredAt = time.UnixMilli(occurredAtMS).UTC()
		page.Facts = append(page.Facts, fact)
	}
	if err := rows.Err(); err != nil {
		return stats.AuthFactPage{}, err
	}
	if len(page.Facts) > limit {
		page.Facts = page.Facts[:limit]
		page.Truncated = true
	}
	return page, nil
}

// AggregateErrorGroups 实现 stats.Store。
func (s *Store) AggregateErrorGroups(ctx context.Context,
	query stats.ErrorGroupQuery) ([]stats.ErrorGroupRow, bool, error) {
	limit := query.Limit
	if limit <= 0 {
		limit = stats.MaxErrorGroups
	}
	conditions, condArgs := relevantConditions()
	where, scopeArgs := scopeClause(query.Scope, "app_id_snapshot")
	baseSQL, dedupeArgs := errorGroupSQL()
	args := append([]any{}, dedupeArgs...)
	args = append(args, query.From.UTC().UnixMilli(), query.To.UTC().UnixMilli())
	args = append(args, condArgs...)
	args = append(args, scopeArgs...)
	sqlText := baseSQL + " AND (" + strings.Join(conditions, " OR ") + ")" + where +
		" GROUP BY error_code, app_id_snapshot, outcome, action" +
		" ORDER BY error_code, app_id_snapshot, outcome, action LIMIT ?"
	args = append(args, limit+1)
	rows, err := s.store.QueryContext(ctx, sqlText, args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	groups := make([]stats.ErrorGroupRow, 0, 32)
	for rows.Next() {
		var group stats.ErrorGroupRow
		var outcome string
		var firstMS, lastMS int64
		if err := rows.Scan(&group.ErrorCode, &group.AppID, &outcome, &group.Action,
			&group.RawEvents, &group.FailedRequests, &group.FailedTasks,
			&firstMS, &lastMS); err != nil {
			return nil, false, err
		}
		group.Outcome = audit.Outcome(outcome)
		group.FirstSeen = time.UnixMilli(firstMS).UTC()
		group.LastSeen = time.UnixMilli(lastMS).UTC()
		groups = append(groups, group)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	truncated := false
	if len(groups) > limit {
		groups = groups[:limit]
		truncated = true
	}
	return groups, truncated, nil
}

// CountFailureKeys 实现 stats.Store：全局去重失败请求/任务数只统计失败结果并排除
// 取消与数据质量警告；正常拒绝不计入“失败”，但保留在原始事件次数中。
func (s *Store) CountFailureKeys(ctx context.Context,
	query stats.FailureKeyQuery) (stats.FailureKeyCount, error) {
	condition, conditionArgs := failureDedupeCondition()
	where, scopeArgs := scopeClause(query.Scope, "app_id_snapshot")
	args := append([]any{}, conditionArgs...)
	args = append(args, conditionArgs...)
	args = append(args, query.From.UTC().UnixMilli(), query.To.UTC().UnixMilli())
	args = append(args, scopeArgs...)
	var count stats.FailureKeyCount
	sqlText := `SELECT
COUNT(DISTINCT CASE WHEN ` + condition + ` THEN CASE WHEN request_id IS NOT NULL AND request_id <> '' THEN request_id ELSE id END END),
COUNT(DISTINCT CASE WHEN ` + condition + ` THEN task_id END)
FROM audit_events
WHERE occurred_at_ms >= ? AND occurred_at_ms < ?` + where
	if err := s.store.DB().QueryRowContext(ctx, sqlText, args...).
		Scan(&count.DistinctRequests, &count.DistinctTasks); err != nil {
		return stats.FailureKeyCount{}, err
	}
	return count, nil
}

// InsertBusinessActivity 实现 stats.Store。
func (s *Store) InsertBusinessActivity(ctx context.Context,
	record stats.BusinessActivityRecord) (bool, error) {
	if record.Source != stats.SourceAppServer {
		return false, fmt.Errorf("%w: 业务活动来源不可信", stats.ErrInvalidRequest)
	}
	result, err := s.store.ExecContext(ctx,
		`INSERT INTO stats_business_activity(
app_id,user_id,activity_key,occurred_at_ms,recorded_at_ms,source,dedupe_key
) VALUES(?,?,?,?,?,?,?)
ON CONFLICT(app_id,dedupe_key) DO NOTHING`,
		record.AppID, record.UserID, record.ActivityKey,
		record.OccurredAt.UTC().UnixMilli(), record.RecordedAt.UTC().UnixMilli(),
		record.Source, record.DedupeKey)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected > 0, nil
}

// QueryBusinessActivity 实现 stats.Store。
func (s *Store) QueryBusinessActivity(ctx context.Context,
	query stats.BusinessActivityFactQuery) (stats.BusinessActivityPage, error) {
	limit := query.Limit
	if limit <= 0 {
		limit = stats.MaxBusinessActivityRows
	}
	where, args := scopeClause(query.Scope, "app_id")
	args = append([]any{query.From.UTC().UnixMilli(), query.To.UTC().UnixMilli()}, args...)
	args = append(args, limit+1)
	rows, err := s.store.QueryContext(ctx,
		`SELECT occurred_at_ms, user_id, app_id, activity_key
FROM stats_business_activity
WHERE occurred_at_ms >= ? AND occurred_at_ms < ?`+where+
			` ORDER BY occurred_at_ms, id LIMIT ?`, args...)
	if err != nil {
		return stats.BusinessActivityPage{}, err
	}
	defer rows.Close()
	page := stats.BusinessActivityPage{Facts: make([]stats.BusinessActivityFact, 0, 32)}
	for rows.Next() {
		var occurredAtMS int64
		var fact stats.BusinessActivityFact
		if err := rows.Scan(&occurredAtMS, &fact.UserID, &fact.AppID, &fact.ActivityKey); err != nil {
			return stats.BusinessActivityPage{}, err
		}
		fact.OccurredAt = time.UnixMilli(occurredAtMS).UTC()
		page.Facts = append(page.Facts, fact)
	}
	if err := rows.Err(); err != nil {
		return stats.BusinessActivityPage{}, err
	}
	if len(page.Facts) > limit {
		page.Facts = page.Facts[:limit]
		page.Truncated = true
	}
	return page, nil
}

// InsertHealthSamples 实现 stats.Store：按 (module, observed_at_ms) 幂等忽略重复。
func (s *Store) InsertHealthSamples(ctx context.Context, samples []stats.HealthSample) error {
	if len(samples) == 0 {
		return nil
	}
	return s.store.Transaction(ctx, func(txCtx context.Context, tx *sql.Tx) error {
		statement, err := tx.PrepareContext(txCtx,
			`INSERT INTO stats_health_samples(
module,observed_at_ms,state,severity,enabled,source,detail_json
) VALUES(?,?,?,?,?,?,?)
ON CONFLICT(module,observed_at_ms) DO NOTHING`)
		if err != nil {
			return err
		}
		defer statement.Close()
		for _, sample := range samples {
			detail, err := json.Marshal(sample.Detail)
			if err != nil {
				return fmt.Errorf("序列化健康采样补充信息失败: %w", err)
			}
			enabled := 0
			if sample.Enabled {
				enabled = 1
			}
			severity := sample.Severity
			if severity == "" {
				severity = stats.SeverityUnknown
			}
			if _, err := statement.ExecContext(txCtx, string(sample.Module),
				sample.ObservedAt.UTC().UnixMilli(), string(sample.State), string(severity),
				enabled, sample.Source, string(detail)); err != nil {
				return err
			}
		}
		return nil
	})
}

// QueryHealthSamples 实现 stats.Store。
func (s *Store) QueryHealthSamples(ctx context.Context,
	query stats.HealthSampleQuery) (stats.HealthSamplePage, error) {
	limit := query.Limit
	if limit <= 0 {
		limit = stats.MaxFactRows
	}
	sqlText := `SELECT module, observed_at_ms, state, severity, enabled, source, detail_json
FROM stats_health_samples
WHERE observed_at_ms >= ? AND observed_at_ms < ?`
	args := []any{query.From.UTC().UnixMilli(), query.To.UTC().UnixMilli()}
	if len(query.Modules) > 0 {
		placeholders := make([]string, len(query.Modules))
		for index, module := range query.Modules {
			placeholders[index] = "?"
			args = append(args, string(module))
		}
		sqlText += " AND module IN (" + strings.Join(placeholders, ",") + ")"
	}
	sqlText += " ORDER BY observed_at_ms, module LIMIT ?"
	args = append(args, limit+1)
	rows, err := s.store.QueryContext(ctx, sqlText, args...)
	if err != nil {
		return stats.HealthSamplePage{}, err
	}
	defer rows.Close()
	page := stats.HealthSamplePage{Samples: make([]stats.HealthSample, 0, 32)}
	for rows.Next() {
		var module, state, severity, source, detailJSON string
		var observedAtMS int64
		var enabled int
		if err := rows.Scan(&module, &observedAtMS, &state, &severity, &enabled,
			&source, &detailJSON); err != nil {
			return stats.HealthSamplePage{}, err
		}
		sample := stats.HealthSample{Module: stats.Module(module),
			State: stats.ModuleState(state), Severity: stats.Severity(severity),
			Enabled: enabled == 1, ObservedAt: time.UnixMilli(observedAtMS).UTC(),
			Source: source}
		if detailJSON != "" {
			if err := json.Unmarshal([]byte(detailJSON), &sample.Detail); err != nil {
				return stats.HealthSamplePage{}, fmt.Errorf("健康采样补充信息损坏: %w", err)
			}
		}
		page.Samples = append(page.Samples, sample)
	}
	if err := rows.Err(); err != nil {
		return stats.HealthSamplePage{}, err
	}
	if len(page.Samples) > limit {
		page.Samples = page.Samples[:limit]
		page.Truncated = true
	}
	return page, nil
}

// PruneHealthSamples 实现 stats.Store：单次最多删除 maxRows 行，限制单次清理量。
func (s *Store) PruneHealthSamples(ctx context.Context, before time.Time, maxRows int) (int64, error) {
	if maxRows <= 0 {
		maxRows = stats.MaxPruneBatch
	}
	if maxRows > stats.MaxPruneBatch {
		maxRows = stats.MaxPruneBatch
	}
	result, err := s.store.ExecContext(ctx,
		`DELETE FROM stats_health_samples WHERE rowid IN (
SELECT rowid FROM stats_health_samples WHERE observed_at_ms < ? LIMIT ?)`,
		before.UTC().UnixMilli(), maxRows)
	if err != nil {
		return 0, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return affected, nil
}

// scopeClause 返回范围约束 SQL 片段（以 " AND " 开头）与参数。column 是应用快照
// 列名（audit_events.app_id_snapshot 或 stats_business_activity.app_id）。
func scopeClause(scope stats.ScopeConstraint, column string) (string, []any) {
	if scope.AppID != "" {
		return " AND " + column + " = ?", []any{scope.AppID}
	}
	if scope.AllData {
		return "", nil
	}
	parts := make([]string, 0, 2)
	args := make([]any, 0, len(scope.AppIDs)+1)
	if len(scope.AppIDs) > 0 {
		placeholders := make([]string, len(scope.AppIDs))
		for index, appID := range scope.AppIDs {
			placeholders[index] = "?"
			args = append(args, appID)
		}
		parts = append(parts, column+" IN ("+strings.Join(placeholders, ",")+")")
	}
	if scope.IncludeSystem {
		parts = append(parts, "COALESCE("+column+",'') = ''")
	}
	if len(parts) == 0 {
		// 空数据范围默认拒绝：用恒假条件而不是返回全量。
		return " AND 1 = 0", nil
	}
	return " AND (" + strings.Join(parts, " OR ") + ")", args
}

// relevantConditions 返回错误统计候选行的 SQL 粗筛条件与参数。
func relevantConditions() ([]string, []any) {
	conditions := []string{"outcome IN ('failure','denied')"}
	args := make([]any, 0, 8)
	for _, action := range stats.StatisticallyRelevantActions() {
		conditions = append(conditions, "action = ?")
		args = append(args, action)
	}
	for _, code := range stats.StatisticallyRelevantCodes() {
		conditions = append(conditions, "error_code = ?")
		args = append(args, code)
	}
	return conditions, args
}
