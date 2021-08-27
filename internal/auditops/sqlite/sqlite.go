// Package sqlite 实现 internal/auditops.Store 的 SQLite 生产持久化。
//
// 表由 migrations/0040_audit_read_lifecycle.sql 创建，本包不执行迁移；调用方应在
// 启动或测试中先通过 internal/storage/migrate 应用全部迁移。本包不拥有数据库
// 连接：*sqlite.Store 的关闭由外层负责。构造后不可变，可被多个 goroutine 并发
// 使用。
//
// 安全不变量：
//   - 所有查询/删除都把调用者的数据范围（应用快照 ID 集合/系统级事件）写进 SQL
//     WHERE 子句，不提供全量读取后内存过滤的接口。
//   - 清理批次在同一事务内删除 audit_events、累加运行计数并追加受保护清理日志；
//     任何一步失败整体回滚，不出现“删了数据但没有清理记录”。
//   - 清理只操作 audit_events，不触碰 audit_maintenance_log/audit_maintenance_runs
//     与导出产物；受保护表上的触发器拒绝 UPDATE/DELETE。
//   - 状态迁移使用条件 UPDATE，终态只写一次；审计事件与状态变化同事务提交。
package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/auditops"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

const (
	eventColumns = `id,occurred_at_ms,actor_type,actor_id,app_id_snapshot,action,
target_type,target_id,outcome,error_code,reason_code,request_id,task_id,detail_json`

	insertEventSQL = `INSERT INTO audit_events(
id,occurred_at_ms,actor_type,actor_id,app_id_snapshot,action,target_type,target_id,
outcome,error_code,reason_code,request_id,task_id,detail_json,dedupe_key
) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

	insertMaintenanceLogSQL = `INSERT INTO audit_maintenance_log(
id,run_id,occurred_at_ms,action,actor_type,actor_id,scope_kind,scope_id,cutoff_ms,
batch_index,scanned,cleaned,result,error_code,request_id,task_id
) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

	maintenanceLogColumns = `id,run_id,occurred_at_ms,action,actor_type,actor_id,
scope_kind,scope_id,cutoff_ms,batch_index,scanned,cleaned,result,error_code,
request_id,task_id`
)

// Store 是 auditops.Store 的 SQLite 实现。
type Store struct {
	store *storagesqlite.Store
}

// New 包装一个已打开并完成迁移的 SQLite 存储。store 为空时返回
// auditops.ErrOptionsInvalid，不会创建替代连接。
func New(store *storagesqlite.Store) (*Store, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", auditops.ErrOptionsInvalid)
	}
	return &Store{store: store}, nil
}

// 编译期确认实现 auditops.Store。
var _ auditops.Store = (*Store)(nil)

// execer 是 transaction 与 *sql.Tx 共用的执行接口。
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// QueryEvents 按授权范围与筛选读取稳定排序的一页事件；多取一条判定 HasMore。
func (s *Store) QueryEvents(ctx context.Context, query auditops.EventQuery) (auditops.EventPage, error) {
	where, args, err := eventWhere(query)
	if err != nil {
		return auditops.EventPage{}, err
	}
	statement := `SELECT ` + eventColumns + ` FROM audit_events` + where +
		` ORDER BY ` + eventOrder(query.Order) + ` LIMIT ? OFFSET ?`
	args = append(args, query.Limit+1, query.Offset)
	rows, err := s.store.QueryContext(ctx, statement, args...)
	if err != nil {
		return auditops.EventPage{}, err
	}
	defer rows.Close()
	events := make([]audit.Event, 0, query.Limit+1)
	for rows.Next() {
		event, scanErr := scanEvent(rows)
		if scanErr != nil {
			return auditops.EventPage{}, scanErr
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return auditops.EventPage{}, err
	}
	page := auditops.EventPage{}
	if len(events) > query.Limit {
		page.HasMore = true
		events = events[:query.Limit]
	}
	page.Events = events
	return page, nil
}

// CountEvents 返回有上限的计数；达到上限后标记截断。
func (s *Store) CountEvents(ctx context.Context, query auditops.EventQuery,
	cap int64) (auditops.CountResult, error) {
	if cap < 1 {
		return auditops.CountResult{}, fmt.Errorf("%w: 计数上限无效", auditops.ErrInvalidRequest)
	}
	where, args, err := eventWhere(query)
	if err != nil {
		return auditops.CountResult{}, err
	}
	statement := `SELECT COUNT(*) FROM (SELECT 1 FROM audit_events` + where + ` LIMIT ?)`
	args = append(args, cap+1)
	rows, err := s.store.QueryContext(ctx, statement, args...)
	if err != nil {
		return auditops.CountResult{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		return auditops.CountResult{}, rows.Err()
	}
	var count int64
	if err := rows.Scan(&count); err != nil {
		return auditops.CountResult{}, err
	}
	result := auditops.CountResult{Count: count}
	if count > cap {
		result.Count = cap
		result.Capped = true
	}
	return result, rows.Err()
}

// GetEvent 读取单条事件。
func (s *Store) GetEvent(ctx context.Context, eventID string) (audit.Event, bool, error) {
	rows, err := s.store.QueryContext(ctx,
		`SELECT `+eventColumns+` FROM audit_events WHERE id=? LIMIT 1`, eventID)
	if err != nil {
		return audit.Event{}, false, err
	}
	defer rows.Close()
	if !rows.Next() {
		return audit.Event{}, false, rows.Err()
	}
	event, err := scanEvent(rows)
	if err != nil {
		return audit.Event{}, false, err
	}
	return event, true, rows.Err()
}

// GetRetention 读取保留策略。
func (s *Store) GetRetention(ctx context.Context) (auditops.RetentionRecord, bool, error) {
	rows, err := s.store.QueryContext(ctx,
		`SELECT retention_days,version,updated_by_type,updated_by_id,reason,updated_at_ms
FROM audit_retention_policy WHERE id=1`)
	if err != nil {
		return auditops.RetentionRecord{}, false, err
	}
	defer rows.Close()
	if !rows.Next() {
		return auditops.RetentionRecord{}, false, rows.Err()
	}
	var record auditops.RetentionRecord
	var actorType, actorID string
	var reason sql.NullString
	var updatedAt int64
	if err := rows.Scan(&record.RetentionDays, &record.Version, &actorType, &actorID,
		&reason, &updatedAt); err != nil {
		return auditops.RetentionRecord{}, false, err
	}
	record.UpdatedBy = audit.Actor{Type: audit.ActorKind(actorType), ID: actorID}
	record.Reason = reason.String
	record.UpdatedAt = time.UnixMilli(updatedAt).UTC()
	return record, true, rows.Err()
}

// SetRetention 用版本 CAS 写入保留策略，并同事务追加受保护清理日志与审计事件。
func (s *Store) SetRetention(ctx context.Context, record auditops.RetentionRecord,
	entry auditops.MaintenanceEntry, event audit.Event) (bool, error) {
	written := false
	err := s.store.Transaction(ctx, func(txCtx context.Context, tx *sql.Tx) error {
		expected := record.Version - 1
		result, err := tx.ExecContext(txCtx,
			`UPDATE audit_retention_policy SET retention_days=?,version=?,updated_by_type=?,
updated_by_id=?,reason=?,updated_at_ms=? WHERE id=1 AND version=?`,
			record.RetentionDays, record.Version, string(record.UpdatedBy.Type),
			record.UpdatedBy.ID, nullable(record.Reason), record.UpdatedAt.UTC().UnixMilli(),
			expected)
		if err != nil {
			return err
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if affected == 0 {
			if expected != 0 {
				return nil
			}
			if _, err := tx.ExecContext(txCtx,
				`INSERT INTO audit_retention_policy(retention_days,version,updated_by_type,
updated_by_id,reason,updated_at_ms) VALUES(?,?,?,?,?,?)`,
				record.RetentionDays, record.Version, string(record.UpdatedBy.Type),
				record.UpdatedBy.ID, nullable(record.Reason),
				record.UpdatedAt.UTC().UnixMilli()); err != nil {
				if errors.Is(err, storage.ErrUniqueViolation) {
					// 并发首次设置：另一个写入已建立策略，按版本冲突返回。
					return auditops.ErrConflict
				}
				return err
			}
		}
		if err := appendMaintenanceLog(txCtx, tx, entry); err != nil {
			return err
		}
		if err := appendEvent(txCtx, tx, event, record.UpdatedAt); err != nil {
			return err
		}
		written = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return written, nil
}

// CreateExport 在同一事务内创建导出记录与审计事件。
func (s *Store) CreateExport(ctx context.Context, record auditops.ExportRecord,
	event audit.Event) error {
	return s.store.Transaction(ctx, func(txCtx context.Context, tx *sql.Tx) error {
		if _, err := tx.ExecContext(txCtx,
			`INSERT INTO audit_exports(id,scope_kind,scope_id,requested_by_type,
requested_by_id,filter_json,data_scope_json,format,max_rows,state,truncated,task_id,
request_id,executor_id,created_at_ms,expires_at_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			record.ID, record.ScopeKind, record.ScopeID, string(record.RequestedBy.Type),
			record.RequestedBy.ID, record.FilterJSON, record.DataScopeJSON,
			record.Format, record.MaxRows, record.State, boolInt(record.Truncated),
			nullable(record.TaskID), nullable(record.RequestID), nullable(record.ExecutorID),
			record.CreatedAt.UTC().UnixMilli(), record.ExpiresAt.UTC().UnixMilli()); err != nil {
			return err
		}
		return appendEvent(txCtx, tx, event, record.CreatedAt)
	})
}

// GetExport 读取导出记录。
func (s *Store) GetExport(ctx context.Context, exportID string) (auditops.ExportRecord, bool, error) {
	rows, err := s.store.QueryContext(ctx, `SELECT `+exportColumns+
		` FROM audit_exports WHERE id=? LIMIT 1`, exportID)
	if err != nil {
		return auditops.ExportRecord{}, false, err
	}
	defer rows.Close()
	if !rows.Next() {
		return auditops.ExportRecord{}, false, rows.Err()
	}
	record, err := scanExport(rows)
	if err != nil {
		return auditops.ExportRecord{}, false, err
	}
	return record, true, rows.Err()
}

// SetExportTask 绑定任务编号。
func (s *Store) SetExportTask(ctx context.Context, exportID, taskID string, now time.Time) error {
	result, err := s.store.ExecContext(ctx,
		`UPDATE audit_exports SET task_id=? WHERE id=? AND task_id IS NULL`,
		taskID, exportID)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		// 幂等：已经是同一任务编号时视为成功，否则冲突。
		existing, found, getErr := s.GetExport(ctx, exportID)
		if getErr != nil {
			return getErr
		}
		if found && existing.TaskID == taskID {
			return nil
		}
		return auditops.ErrConflict
	}
	return nil
}

// UpdateExport 执行受控状态迁移并同事务写入审计事件。
func (s *Store) UpdateExport(ctx context.Context, command auditops.ExportUpdateCommand,
	event audit.Event) (bool, error) {
	updated := false
	err := s.store.Transaction(ctx, func(txCtx context.Context, tx *sql.Tx) error {
		var result sql.Result
		var err error
		nowMS := command.Now.UTC().UnixMilli()
		switch command.State {
		case auditops.ExportRunning:
			result, err = tx.ExecContext(txCtx,
				`UPDATE audit_exports SET state='running',started_at_ms=?,executor_id=?
WHERE id=? AND state='queued'`, nowMS, nullable(command.ExecutorID), command.ID)
		case auditops.ExportSucceeded:
			result, err = tx.ExecContext(txCtx,
				`UPDATE audit_exports SET state='succeeded',row_count=?,truncated=?,
file_name=?,file_sha256=?,file_bytes=?,error_code=NULL,failure_reason=NULL,
executor_id=COALESCE(?,executor_id),finished_at_ms=?
WHERE id=? AND state IN('queued','running')`,
				command.RowCount, boolInt(command.Truncated), nullable(command.FileName),
				nullableBytes(command.FileSHA256), nullableInt64(command.FileBytes),
				nullable(command.ExecutorID), nowMS, command.ID)
		case auditops.ExportFailed, auditops.ExportCancelled:
			result, err = tx.ExecContext(txCtx,
				`UPDATE audit_exports SET state=?,error_code=?,failure_reason=?,
executor_id=COALESCE(?,executor_id),finished_at_ms=?
WHERE id=? AND state IN('queued','running')`,
				command.State, nullable(command.ErrorCode), nullable(command.FailureReason),
				nullable(command.ExecutorID), nowMS, command.ID)
		default:
			return auditops.ErrInvalidRequest
		}
		if err != nil {
			return err
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if affected == 0 {
			return nil
		}
		if err := appendEvent(txCtx, tx, event, command.Now); err != nil {
			return err
		}
		updated = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return updated, nil
}

// ListExports 列出导出记录（按创建时间倒序）。
func (s *Store) ListExports(ctx context.Context, query auditops.ExportListQuery) ([]auditops.ExportRecord, error) {
	statement := `SELECT ` + exportColumns + ` FROM audit_exports WHERE scope_id=?`
	args := []any{query.ScopeID}
	if query.State != "" {
		statement += ` AND state=?`
		args = append(args, query.State)
	}
	statement += ` ORDER BY created_at_ms DESC,id DESC LIMIT ? OFFSET ?`
	args = append(args, query.Limit, query.Offset)
	rows, err := s.store.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := make([]auditops.ExportRecord, 0, query.Limit)
	for rows.Next() {
		record, err := scanExport(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

// CreatePurgeRun 在同一事务内创建清理运行、受保护日志与审计事件。
func (s *Store) CreatePurgeRun(ctx context.Context, record auditops.PurgeRunRecord,
	entry auditops.MaintenanceEntry, event audit.Event) error {
	return s.store.Transaction(ctx, func(txCtx context.Context, tx *sql.Tx) error {
		if _, err := tx.ExecContext(txCtx,
			`INSERT INTO audit_maintenance_runs(id,kind,scope_kind,scope_id,
requested_by_type,requested_by_id,cutoff_ms,batch_size,max_records,state,task_id,
scanned,cleaned,skipped,failed,batches,limit_reached,error_code,failure_reason,
request_id,executor_id,created_at_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			record.ID, record.Kind, record.ScopeKind, record.ScopeID,
			string(record.RequestedBy.Type), record.RequestedBy.ID,
			record.Cutoff.UTC().UnixMilli(), record.BatchSize, record.MaxRecords,
			record.State, nullable(record.TaskID), record.Scanned, record.Cleaned,
			record.Skipped, record.Failed, record.Batches,
			boolInt(record.LimitReached), nullable(record.ErrorCode),
			nullable(record.FailureReason), nullable(record.RequestID),
			nullable(record.ExecutorID), record.CreatedAt.UTC().UnixMilli()); err != nil {
			return err
		}
		entry.RunID = record.ID
		if err := appendMaintenanceLog(txCtx, tx, entry); err != nil {
			return err
		}
		return appendEvent(txCtx, tx, event, record.CreatedAt)
	})
}

// GetPurgeRun 读取清理运行。
func (s *Store) GetPurgeRun(ctx context.Context, runID string) (auditops.PurgeRunRecord, bool, error) {
	rows, err := s.store.QueryContext(ctx, `SELECT `+purgeRunColumns+
		` FROM audit_maintenance_runs WHERE id=? LIMIT 1`, runID)
	if err != nil {
		return auditops.PurgeRunRecord{}, false, err
	}
	defer rows.Close()
	if !rows.Next() {
		return auditops.PurgeRunRecord{}, false, rows.Err()
	}
	record, err := scanPurgeRun(rows)
	if err != nil {
		return auditops.PurgeRunRecord{}, false, err
	}
	return record, true, rows.Err()
}

// SetPurgeTask 绑定任务编号。
func (s *Store) SetPurgeTask(ctx context.Context, runID, taskID string, now time.Time) error {
	result, err := s.store.ExecContext(ctx,
		`UPDATE audit_maintenance_runs SET task_id=? WHERE id=? AND task_id IS NULL`,
		taskID, runID)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		record, found, getErr := s.GetPurgeRun(ctx, runID)
		if getErr != nil {
			return getErr
		}
		if found && record.TaskID == taskID {
			return nil
		}
		return auditops.ErrConflict
	}
	return nil
}

// StartPurgeRun 把 queued 条件迁移为 running。
func (s *Store) StartPurgeRun(ctx context.Context, runID, executorID string,
	now time.Time) (bool, error) {
	result, err := s.store.ExecContext(ctx,
		`UPDATE audit_maintenance_runs SET state='running',started_at_ms=?,executor_id=?
WHERE id=? AND state='queued'`, now.UTC().UnixMilli(), nullable(executorID), runID)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected > 0, nil
}

// PurgeBatch 在同一事务内删除一批事件、累加运行计数并追加受保护清理日志。
func (s *Store) PurgeBatch(ctx context.Context, command auditops.PurgeBatchCommand) (auditops.PurgedBatch, error) {
	result := auditops.PurgedBatch{}
	err := s.store.Transaction(ctx, func(txCtx context.Context, tx *sql.Tx) error {
		scopeClause, scopeArgs := purgeScopeWhere(command.ScopeKind, command.ScopeID)
		limit := command.BatchSize
		if command.Remaining > 0 && command.Remaining < limit {
			limit = command.Remaining
		}
		if limit < 1 {
			return nil
		}
		rows, err := tx.QueryContext(txCtx,
			`SELECT id FROM audit_events WHERE occurred_at_ms<? AND `+scopeClause+
				` ORDER BY occurred_at_ms ASC,id ASC LIMIT ?`,
			append([]any{command.Cutoff.UTC().UnixMilli()}, append(scopeArgs, limit)...)...)
		if err != nil {
			return err
		}
		ids := make([]string, 0, limit)
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if len(ids) == 0 {
			return nil
		}
		placeholders := make([]string, len(ids))
		deleteArgs := make([]any, len(ids))
		for index, id := range ids {
			placeholders[index] = "?"
			deleteArgs[index] = id
		}
		deleted, err := tx.ExecContext(txCtx,
			`DELETE FROM audit_events WHERE id IN (`+joinStrings(placeholders, ",")+`)`,
			deleteArgs...)
		if err != nil {
			return err
		}
		cleaned, err := deleted.RowsAffected()
		if err != nil {
			return err
		}
		update, err := tx.ExecContext(txCtx,
			`UPDATE audit_maintenance_runs SET scanned=scanned+?,cleaned=cleaned+?,
batches=batches+1 WHERE id=? AND state='running'`,
			len(ids), cleaned, command.RunID)
		if err != nil {
			return err
		}
		affected, err := update.RowsAffected()
		if err != nil {
			return err
		}
		if affected == 0 {
			return auditops.ErrConflict
		}
		entry := auditops.MaintenanceEntry{
			RunID: command.RunID, OccurredAt: command.Now, Action: auditops.ActionPurgeBatch,
			Actor: command.Actor, ScopeKind: command.ScopeKind, ScopeID: command.ScopeID,
			Cutoff: command.Cutoff, BatchIndex: command.BatchIndex,
			Scanned: len(ids), Cleaned: int(cleaned), Result: "batch_cleaned",
			RequestID: command.RequestID, TaskID: command.TaskID,
		}
		if err := appendMaintenanceLog(txCtx, tx, entry); err != nil {
			return err
		}
		result.Scanned = len(ids)
		result.Cleaned = int(cleaned)
		return nil
	})
	if err != nil {
		return auditops.PurgedBatch{}, err
	}
	return result, nil
}

// FinishPurgeRun 写入终态、计数与审计事件；终态只写一次。
func (s *Store) FinishPurgeRun(ctx context.Context, command auditops.PurgeFinishCommand) (bool, error) {
	finished := false
	err := s.store.Transaction(ctx, func(txCtx context.Context, tx *sql.Tx) error {
		result, err := tx.ExecContext(txCtx,
			`UPDATE audit_maintenance_runs SET state=?,scanned=?,cleaned=?,skipped=?,
failed=?,batches=?,limit_reached=?,error_code=?,failure_reason=?,finished_at_ms=?
WHERE id=? AND state IN('queued','running')`,
			command.State, command.Scanned, command.Cleaned, command.Skipped,
			command.Failed, command.Batches, boolInt(command.LimitReached),
			nullable(command.ErrorCode), nullable(command.FailureReason),
			command.Now.UTC().UnixMilli(), command.RunID)
		if err != nil {
			return err
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if affected == 0 {
			return nil
		}
		if command.Entry != nil {
			if err := appendMaintenanceLog(txCtx, tx, *command.Entry); err != nil {
				return err
			}
		}
		if err := appendEvent(txCtx, tx, command.Event, command.Now); err != nil {
			return err
		}
		finished = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return finished, nil
}

// ListPurgeRuns 列出清理运行（按创建时间倒序）。
func (s *Store) ListPurgeRuns(ctx context.Context, query auditops.PurgeListQuery) ([]auditops.PurgeRunRecord, error) {
	statement := `SELECT ` + purgeRunColumns + ` FROM audit_maintenance_runs WHERE 1=1`
	args := []any{}
	if query.Kind != "" {
		statement += ` AND kind=?`
		args = append(args, query.Kind)
	}
	if query.State != "" {
		statement += ` AND state=?`
		args = append(args, query.State)
	}
	statement += ` ORDER BY created_at_ms DESC,id DESC LIMIT ? OFFSET ?`
	args = append(args, query.Limit, query.Offset)
	rows, err := s.store.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := make([]auditops.PurgeRunRecord, 0, query.Limit)
	for rows.Next() {
		record, err := scanPurgeRun(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

// AppendMaintenanceLog 追加受保护清理日志（表禁止 UPDATE/DELETE）。
func (s *Store) AppendMaintenanceLog(ctx context.Context, entry auditops.MaintenanceEntry) error {
	return appendMaintenanceLog(ctx, s.store, entry)
}

// MaintenanceLog 读取某次清理的受保护日志（按时间正序）。
func (s *Store) MaintenanceLog(ctx context.Context, runID string) ([]auditops.MaintenanceEntry, error) {
	rows, err := s.store.QueryContext(ctx, `SELECT `+maintenanceLogColumns+
		` FROM audit_maintenance_log WHERE run_id=? ORDER BY rowid ASC`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	entries := make([]auditops.MaintenanceEntry, 0, 16)
	for rows.Next() {
		entry, err := scanMaintenanceEntry(rows)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

// appendEvent 在给定事务/执行器内规范化并写入审计事件。
func appendEvent(ctx context.Context, exec execer, event audit.Event, occurredAt time.Time) error {
	prepared, err := audit.PrepareEvent(event, occurredAt)
	if err != nil {
		return err
	}
	detail, err := audit.DetailJSON(prepared.Changes)
	if err != nil {
		return err
	}
	_, err = exec.ExecContext(ctx, insertEventSQL,
		prepared.ID, prepared.OccurredAt.UTC().UnixMilli(), string(prepared.Actor.Type),
		nullable(prepared.Actor.ID), nullable(prepared.AppID), prepared.Action,
		prepared.Target.Type, nullable(prepared.Target.ID), string(prepared.Outcome),
		nullable(prepared.ErrorCode), nullable(prepared.ReasonCode),
		nullable(prepared.RequestID), nullable(prepared.TaskID), detail,
		nullable(prepared.DedupeKey))
	return err
}

// appendMaintenanceLog 追加受保护清理日志；空 ID 时生成随机 ID。
func appendMaintenanceLog(ctx context.Context, exec execer, entry auditops.MaintenanceEntry) error {
	id := entry.ID
	if id == "" {
		generated, err := newMaintenanceID()
		if err != nil {
			return err
		}
		id = generated
	}
	occurredAt := entry.OccurredAt
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}
	var cutoff any
	if !entry.Cutoff.IsZero() {
		cutoff = entry.Cutoff.UTC().UnixMilli()
	}
	_, err := exec.ExecContext(ctx, insertMaintenanceLogSQL, id, nullable(entry.RunID),
		occurredAt.UTC().Truncate(time.Millisecond).UnixMilli(), entry.Action,
		string(entry.Actor.Type), nullable(entry.Actor.ID), entry.ScopeKind, entry.ScopeID,
		cutoff, entry.BatchIndex, entry.Scanned, entry.Cleaned, entry.Result,
		nullable(entry.ErrorCode), nullable(entry.RequestID), nullable(entry.TaskID))
	return err
}

// newMaintenanceID 生成受保护清理日志编号。
func newMaintenanceID() (string, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("%w: 无法生成清理日志编号", auditops.ErrStoreUnavailable)
	}
	return "mnt_" + hex.EncodeToString(buffer), nil
}

// eventWhere 把授权范围与筛选条件转换为参数化 SQL WHERE 子句。
func eventWhere(query auditops.EventQuery) (string, []any, error) {
	clauses := make([]string, 0, 14)
	args := make([]any, 0, 16)
	scopeClause, scopeArgs := queryScopeWhere(query)
	if scopeClause != "" {
		clauses = append(clauses, scopeClause)
		args = append(args, scopeArgs...)
	}
	filter := query.Filter
	if !filter.From.IsZero() {
		clauses = append(clauses, "occurred_at_ms>=?")
		args = append(args, filter.From.UTC().UnixMilli())
	}
	if !filter.To.IsZero() {
		clauses = append(clauses, "occurred_at_ms<?")
		args = append(args, filter.To.UTC().UnixMilli())
	}
	if filter.AppID != "" {
		clauses = append(clauses, "app_id_snapshot=?")
		args = append(args, filter.AppID)
	}
	if filter.SystemOnly {
		clauses = append(clauses, "app_id_snapshot IS NULL")
	}
	if filter.ActorType != "" {
		clauses = append(clauses, "actor_type=?")
		args = append(args, string(filter.ActorType))
	}
	if filter.ActorID != "" {
		clauses = append(clauses, "actor_id=?")
		args = append(args, filter.ActorID)
	}
	if filter.Action != "" {
		clauses = append(clauses, "action=?")
		args = append(args, filter.Action)
	}
	if filter.Outcome != "" {
		clauses = append(clauses, "outcome=?")
		args = append(args, string(filter.Outcome))
	}
	if filter.ErrorCode != "" {
		clauses = append(clauses, "error_code=?")
		args = append(args, filter.ErrorCode)
	}
	if filter.RequestID != "" {
		clauses = append(clauses, "request_id=?")
		args = append(args, filter.RequestID)
	}
	if filter.TaskID != "" {
		clauses = append(clauses, "task_id=?")
		args = append(args, filter.TaskID)
	}
	if filter.TargetType != "" {
		clauses = append(clauses, "target_type=?")
		args = append(args, filter.TargetType)
	}
	if filter.TargetID != "" {
		clauses = append(clauses, "target_id=?")
		args = append(args, filter.TargetID)
	}
	if len(clauses) == 0 {
		return "", args, nil
	}
	return " WHERE " + joinStrings(clauses, " AND "), args, nil
}

// queryScopeWhere 把数据范围约束转换为参数化 SQL（存储层限制，不做内存过滤）。
func queryScopeWhere(query auditops.EventQuery) (string, []any) {
	if query.AllData {
		if query.IncludeSystem {
			return "", nil
		}
		return "app_id_snapshot IS NOT NULL", nil
	}
	parts := make([]string, 0, 2)
	args := make([]any, 0, len(query.AppIDs))
	if len(query.AppIDs) > 0 {
		placeholders := make([]string, len(query.AppIDs))
		for index, appID := range query.AppIDs {
			placeholders[index] = "?"
			args = append(args, appID)
		}
		parts = append(parts, "app_id_snapshot IN ("+joinStrings(placeholders, ",")+")")
	}
	if query.IncludeSystem {
		parts = append(parts, "app_id_snapshot IS NULL")
	}
	if len(parts) == 0 {
		// 没有可用范围时返回恒假条件，绝不扩大为全部数据。
		return "1=0", args
	}
	return "(" + joinStrings(parts, " OR ") + ")", args
}

// purgeScopeWhere 返回清理范围条件（系统范围只清无应用快照事件）。
func purgeScopeWhere(scopeKind, scopeID string) (string, []any) {
	if scopeKind == "app" {
		return "app_id_snapshot=?", []any{scopeID}
	}
	return "app_id_snapshot IS NULL", nil
}

// eventOrder 返回稳定排序子句。
func eventOrder(order auditops.SortOrder) string {
	if order == auditops.SortOldestFirst {
		return "occurred_at_ms ASC,id ASC"
	}
	return "occurred_at_ms DESC,id DESC"
}

// scanEvent 扫描事件行并解析脱敏差异 JSON。
func scanEvent(rows *sql.Rows) (audit.Event, error) {
	var event audit.Event
	var occurredAt int64
	var actorType string
	var actorID, appID, targetID, errorCode, reasonCode, requestID, taskID sql.NullString
	var detail string
	if err := rows.Scan(&event.ID, &occurredAt, &actorType, &actorID, &appID,
		&event.Action, &event.Target.Type, &targetID, &event.Outcome, &errorCode,
		&reasonCode, &requestID, &taskID, &detail); err != nil {
		return audit.Event{}, err
	}
	event.OccurredAt = time.UnixMilli(occurredAt).UTC()
	event.Actor = audit.Actor{Type: audit.ActorKind(actorType), ID: actorID.String}
	event.AppID = appID.String
	event.Target = audit.Target{Type: event.Target.Type, ID: targetID.String}
	event.ErrorCode = errorCode.String
	event.ReasonCode = reasonCode.String
	event.RequestID = requestID.String
	event.TaskID = taskID.String
	changes, err := decodeDetail(detail)
	if err != nil {
		return audit.Event{}, err
	}
	event.Changes = changes
	return event, nil
}

// decodeDetail 解析 detail_json，只接受当前版本结构。
func decodeDetail(raw string) ([]audit.FieldChange, error) {
	if raw == "" || raw == "{}" {
		return nil, nil
	}
	var document struct {
		Version int                 `json:"v"`
		Changes []audit.FieldChange `json:"changes"`
	}
	if err := json.Unmarshal([]byte(raw), &document); err != nil {
		return nil, fmt.Errorf("%w: 审计差异数据无效", auditops.ErrStoreUnavailable)
	}
	if document.Version != 1 {
		return nil, fmt.Errorf("%w: 审计差异版本不受支持", auditops.ErrStoreUnavailable)
	}
	return document.Changes, nil
}

// scanExport 扫描导出记录。
func scanExport(rows *sql.Rows) (auditops.ExportRecord, error) {
	var record auditops.ExportRecord
	var requestedByType, scopeKind, scopeID, requestedByID, filterJSON, dataScopeJSON,
		format, state string
	var taskID, fileName, errorCode, failureReason, requestID, executorID sql.NullString
	var rowCount, fileBytes sql.NullInt64
	var truncated int
	var fileSHA []byte
	var createdAt int64
	var startedAt, finishedAt, expiresAt sql.NullInt64
	if err := rows.Scan(&record.ID, &scopeKind, &scopeID, &requestedByType, &requestedByID,
		&filterJSON, &dataScopeJSON, &format, &record.MaxRows, &state, &rowCount,
		&truncated, &taskID, &fileName, &fileSHA, &fileBytes, &errorCode,
		&failureReason, &requestID, &executorID, &createdAt, &startedAt, &finishedAt,
		&expiresAt); err != nil {
		return auditops.ExportRecord{}, err
	}
	record.ScopeKind = scopeKind
	record.ScopeID = scopeID
	record.RequestedBy = audit.Actor{Type: audit.ActorKind(requestedByType),
		ID: requestedByID}
	record.FilterJSON = filterJSON
	record.DataScopeJSON = dataScopeJSON
	record.Format = format
	record.State = state
	record.RowCount = int(rowCount.Int64)
	record.Truncated = truncated != 0
	record.TaskID = taskID.String
	record.FileName = fileName.String
	record.FileSHA256 = fileSHA
	record.FileBytes = fileBytes.Int64
	record.ErrorCode = errorCode.String
	record.FailureReason = failureReason.String
	record.RequestID = requestID.String
	record.ExecutorID = executorID.String
	record.CreatedAt = time.UnixMilli(createdAt).UTC()
	record.StartedAt = timeFromNullable(startedAt)
	record.FinishedAt = timeFromNullable(finishedAt)
	record.ExpiresAt = timeFromNullable(expiresAt)
	return record, nil
}

// exportColumns 是导出表查询列（顺序与 scanExport 一致）。
const exportColumns = `id,scope_kind,scope_id,requested_by_type,requested_by_id,
filter_json,data_scope_json,format,max_rows,state,row_count,truncated,task_id,
file_name,file_sha256,file_bytes,error_code,failure_reason,request_id,executor_id,
created_at_ms,started_at_ms,finished_at_ms,expires_at_ms`

// scanPurgeRun 扫描清理运行记录。
func scanPurgeRun(rows *sql.Rows) (auditops.PurgeRunRecord, error) {
	var record auditops.PurgeRunRecord
	var kind, scopeKind, scopeID, requestedByType, requestedByID, state string
	var taskID, errorCode, failureReason, requestID, executorID sql.NullString
	var cutoff, createdAt int64
	var startedAt, finishedAt sql.NullInt64
	var limitReached int
	if err := rows.Scan(&record.ID, &kind, &scopeKind, &scopeID, &requestedByType,
		&requestedByID, &cutoff, &record.BatchSize, &record.MaxRecords, &state,
		&taskID, &record.Scanned, &record.Cleaned, &record.Skipped, &record.Failed,
		&record.Batches, &limitReached, &errorCode, &failureReason, &requestID,
		&executorID, &createdAt, &startedAt, &finishedAt); err != nil {
		return auditops.PurgeRunRecord{}, err
	}
	record.Kind = kind
	record.ScopeKind = scopeKind
	record.ScopeID = scopeID
	record.RequestedBy = audit.Actor{Type: audit.ActorKind(requestedByType),
		ID: requestedByID}
	record.Cutoff = time.UnixMilli(cutoff).UTC()
	record.State = state
	record.TaskID = taskID.String
	record.LimitReached = limitReached != 0
	record.ErrorCode = errorCode.String
	record.FailureReason = failureReason.String
	record.RequestID = requestID.String
	record.ExecutorID = executorID.String
	record.CreatedAt = time.UnixMilli(createdAt).UTC()
	record.StartedAt = timeFromNullable(startedAt)
	record.FinishedAt = timeFromNullable(finishedAt)
	return record, nil
}

// purgeRunColumns 是清理运行表查询列（顺序与 scanPurgeRun 一致）。
const purgeRunColumns = `id,kind,scope_kind,scope_id,requested_by_type,requested_by_id,
cutoff_ms,batch_size,max_records,state,task_id,scanned,cleaned,skipped,failed,batches,
limit_reached,error_code,failure_reason,request_id,executor_id,created_at_ms,
started_at_ms,finished_at_ms`

// scanMaintenanceEntry 扫描受保护清理日志。
func scanMaintenanceEntry(rows *sql.Rows) (auditops.MaintenanceEntry, error) {
	var entry auditops.MaintenanceEntry
	var runID, actorID, errorCode, requestID, taskID sql.NullString
	var actorType string
	var occurredAt int64
	var cutoff sql.NullInt64
	if err := rows.Scan(&entry.ID, &runID, &occurredAt, &entry.Action,
		&actorType, &actorID, &entry.ScopeKind, &entry.ScopeID, &cutoff,
		&entry.BatchIndex, &entry.Scanned, &entry.Cleaned, &entry.Result,
		&errorCode, &requestID, &taskID); err != nil {
		return auditops.MaintenanceEntry{}, err
	}
	entry.RunID = runID.String
	entry.OccurredAt = time.UnixMilli(occurredAt).UTC()
	entry.Actor = audit.Actor{Type: audit.ActorKind(actorType), ID: actorID.String}
	entry.Cutoff = timeFromNullable(cutoff)
	entry.ErrorCode = errorCode.String
	entry.RequestID = requestID.String
	entry.TaskID = taskID.String
	return entry, nil
}

// timeFromNullable 转换可空毫秒时间为 UTC 时间。
func timeFromNullable(value sql.NullInt64) time.Time {
	if !value.Valid {
		return time.Time{}
	}
	return time.UnixMilli(value.Int64).UTC()
}

// boolInt 把布尔值转为 SQLite 0/1。
func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

// nullable 把空字符串映射为 SQL NULL。
func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}

// nullableBytes 把空字节切片映射为 SQL NULL。
func nullableBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

// nullableInt64 把零值映射为 SQL NULL（用于非零才有意义的计数）。
func nullableInt64(value int64) any {
	if value == 0 {
		return nil
	}
	return value
}

// joinStrings 以分隔符连接字符串。
func joinStrings(values []string, separator string) string {
	result := ""
	for index, value := range values {
		if index > 0 {
			result += separator
		}
		result += value
	}
	return result
}
