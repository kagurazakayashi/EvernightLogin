// Package sqlite 实现 internal/audit.Store 的 SQLite 生产持久化。
//
// 表由 migrations/0003_audit_events.sql 创建，本包不执行迁移；调用方应在启动
// 或测试中先通过 internal/storage/migrate 应用全部迁移。本包不拥有数据库连接：
// *sqlite.Store 的关闭由外层负责。构造后不可变，可被多个 goroutine 并发使用。
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

const (
	insertEventSQL = `INSERT INTO audit_events(
id,occurred_at_ms,actor_type,actor_id,app_id_snapshot,action,target_type,target_id,
outcome,error_code,reason_code,request_id,task_id,detail_json,dedupe_key
) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

	dedupeExistsSQL = `SELECT 1 FROM audit_events WHERE dedupe_key=? LIMIT 1`
)

// Store 是 audit.Store 的 SQLite 实现。
type Store struct {
	store *storagesqlite.Store
}

// New 包装一个已打开并完成迁移的 SQLite 存储。store 为空时返回
// audit.ErrOptionsInvalid，不会创建替代连接。
func New(store *storagesqlite.Store) (*Store, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", audit.ErrOptionsInvalid)
	}
	return &Store{store: store}, nil
}

// 编译期确认实现 audit.Store。
var _ audit.Store = (*Store)(nil)

// Append 在独立事务中写入一条审计事件。dedupe_key 冲突返回
// audit.ErrDuplicateEvent，其它失败返回 audit.ErrAuditUnavailable。
func (s *Store) Append(ctx context.Context, event audit.Event) error {
	normalized, err := audit.NormalizeEvent(event)
	if err != nil {
		return err
	}
	args, err := eventArgs(normalized)
	if err != nil {
		return err
	}
	if _, err := s.store.ExecContext(ctx, insertEventSQL, args...); err != nil {
		if errors.Is(err, storage.ErrUniqueViolation) {
			return audit.ErrDuplicateEvent
		}
		return fmt.Errorf("%w: %w", audit.ErrAuditUnavailable, err)
	}
	return nil
}

// RunCritical 开启数据库事务执行关键变更，并在同一事务内写入成功审计事件。
//
// 带 dedupe_key 时先在事务内检查是否已存在：存在则返回 audit.ErrDuplicateEvent
// 且不执行 change。change 失败或成功审计写入失败时整个事务回滚；审计写入失败
// 返回可被 errors.Is(err, audit.ErrAuditUnavailable) 识别的错误，供 Recorder
// 拒绝关键管理变更并告警。
func (s *Store) RunCritical(ctx context.Context, success audit.Event, change func(ctx context.Context, tx audit.Tx) error) error {
	normalized, err := audit.NormalizeEvent(success)
	if err != nil {
		return err
	}
	return s.store.Transaction(ctx, func(txCtx context.Context, tx *sql.Tx) error {
		adapter := &transaction{tx: tx}
		if normalized.DedupeKey != "" {
			exists, err := adapter.dedupeExists(txCtx, normalized.DedupeKey)
			if err != nil {
				return fmt.Errorf("%w: %w", audit.ErrAuditUnavailable, err)
			}
			if exists {
				return audit.ErrDuplicateEvent
			}
		}
		if err := change(txCtx, adapter); err != nil {
			return err
		}
		if err := adapter.AppendEvent(txCtx, normalized); err != nil {
			return fmt.Errorf("%w: %w", audit.ErrAuditUnavailable, err)
		}
		return nil
	})
}

// eventArgs 把已验证事件映射为插入参数；空字符串映射为 SQL NULL。
func eventArgs(event audit.Event) ([]any, error) {
	detail, err := audit.DetailJSON(event.Changes)
	if err != nil {
		return nil, err
	}
	return []any{
		event.ID,
		event.OccurredAt.UTC().UnixMilli(),
		string(event.Actor.Type),
		nullable(event.Actor.ID),
		nullable(event.AppID),
		event.Action,
		event.Target.Type,
		nullable(event.Target.ID),
		string(event.Outcome),
		nullable(event.ErrorCode),
		nullable(event.ReasonCode),
		nullable(event.RequestID),
		nullable(event.TaskID),
		detail,
		nullable(event.DedupeKey),
	}, nil
}

// nullable 把空字符串映射为 SQL NULL。
func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}

// transaction 是 audit.Tx 的 SQLite 事务适配器。业务变更可以使用 ExecContext
// 执行自己的参数化 SQL；AppendEvent 在同一事务内写入审计事件。
type transaction struct {
	tx *sql.Tx
}

// AppendEvent 实现 audit.Tx。
func (t *transaction) AppendEvent(ctx context.Context, event audit.Event) error {
	normalized, err := audit.NormalizeEvent(event)
	if err != nil {
		return err
	}
	args, err := eventArgs(normalized)
	if err != nil {
		return err
	}
	_, err = t.tx.ExecContext(ctx, insertEventSQL, args...)
	return err
}

// ExecContext 实现 audit.Tx。
func (t *transaction) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return t.tx.ExecContext(ctx, query, args...)
}

// QueryContext 实现 audit.Tx，让关键变更在同一事务内读取授权状态。
func (t *transaction) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return t.tx.QueryContext(ctx, query, args...)
}

// dedupeExists 判断幂等键是否已存在。
func (t *transaction) dedupeExists(ctx context.Context, dedupeKey string) (bool, error) {
	rows, err := t.tx.QueryContext(ctx, dedupeExistsSQL, dedupeKey)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return false, err
		}
		return false, nil
	}
	return true, rows.Err()
}
