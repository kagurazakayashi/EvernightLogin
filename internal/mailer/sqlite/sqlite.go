// Package sqlite 实现 internal/mailer.Store 的 SQLite 持久化。
//
// 表结构来自 migrations/0012_mail_deliveries.sql。本包不执行迁移、不拥有数据库
// 连接；敏感模板数据列只保存 secrets.Sealer 的密文，本包不接触明文或 SMTP 凭据。
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

const selectColumns = `id,idempotency_key,template_kind,recipient,owner_type,owner_id,state,attempts,max_attempts,
COALESCE(task_id,''),COALESCE(last_error_code,''),COALESCE(last_error_kind,''),sealed_payload,
COALESCE(request_id,''),created_at_ms,updated_at_ms`

const insertSQL = `INSERT INTO mail_deliveries(
id,idempotency_key,template_kind,recipient,owner_type,owner_id,state,attempts,max_attempts,task_id,
last_error_code,last_error_kind,sealed_payload,request_id,created_at_ms,updated_at_ms
 ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(idempotency_key) DO NOTHING`

const selectByIDSQL = `SELECT ` + selectColumns + ` FROM mail_deliveries WHERE id=?`

const selectByKeySQL = `SELECT ` + selectColumns + ` FROM mail_deliveries WHERE idempotency_key=?`

// Store 是 mailer.Store 的 SQLite 实现，可被多个 goroutine 并发使用。
type Store struct {
	store *storagesqlite.Store
}

// New 包装一个已打开并完成迁移的 SQLite 存储。
func New(store *storagesqlite.Store) (*Store, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", mailer.ErrOptionsInvalid)
	}
	return &Store{store: store}, nil
}

// Create 以幂等键创建投递记录；键重复时返回既有记录且 created=false。
func (s *Store) Create(ctx context.Context, record mailer.Record) (mailer.Record, bool, error) {
	result, err := s.store.ExecContext(ctx, insertSQL,
		record.ID, record.IdempotencyKey, string(record.Kind), record.Recipient,
		string(record.OwnerType), record.OwnerID, string(record.State),
		record.Attempts, record.MaxAttempts, nullString(record.TaskID),
		nullString(record.LastErrorCode), nullString(string(record.LastErrorKind)), record.SealedPayload,
		nullString(record.RequestID), record.CreatedAt.UnixMilli(), record.UpdatedAt.UnixMilli())
	if err != nil {
		return mailer.Record{}, false, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return mailer.Record{}, false, err
	}
	if affected == 0 {
		existing, err := s.GetByIdempotencyKey(ctx, record.IdempotencyKey)
		if err != nil {
			return mailer.Record{}, false, err
		}
		return existing, false, nil
	}
	return record, true, nil
}

// Get 按 ID 读取投递记录；不存在返回 mailer.ErrDeliveryNotFound。
func (s *Store) Get(ctx context.Context, id string) (mailer.Record, error) {
	rows, err := s.store.QueryContext(ctx, selectByIDSQL, id)
	if err != nil {
		return mailer.Record{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return mailer.Record{}, err
		}
		return mailer.Record{}, mailer.ErrDeliveryNotFound
	}
	return scanRecord(rows)
}

// GetByIdempotencyKey 按幂等键读取投递记录。
func (s *Store) GetByIdempotencyKey(ctx context.Context, key string) (mailer.Record, error) {
	rows, err := s.store.QueryContext(ctx, selectByKeySQL, key)
	if err != nil {
		return mailer.Record{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return mailer.Record{}, err
		}
		return mailer.Record{}, mailer.ErrDeliveryNotFound
	}
	return scanRecord(rows)
}

// SetTaskID 关联任务编号。
func (s *Store) SetTaskID(ctx context.Context, id, taskID string, now time.Time) error {
	_, err := s.store.ExecContext(ctx,
		`UPDATE mail_deliveries SET task_id=?,updated_at_ms=? WHERE id=?`, taskID, now.UnixMilli(), id)
	return err
}

// MarkSending 记录一次尝试开始；attempts 取历史最大值，避免并发重试回退计数。
func (s *Store) MarkSending(ctx context.Context, id string, attempt int, now time.Time) error {
	_, err := s.store.ExecContext(ctx,
		`UPDATE mail_deliveries SET state='sending',attempts=CASE WHEN attempts>? THEN attempts ELSE ? END,updated_at_ms=? WHERE id=?`,
		attempt, attempt, now.UnixMilli(), id)
	return err
}

// Finish 记录终态或重排队；空错误码写入 NULL。
func (s *Store) Finish(ctx context.Context, id string, state mailer.DeliveryState, errorCode string, kind mailer.FailureKind, now time.Time) error {
	_, err := s.store.ExecContext(ctx,
		`UPDATE mail_deliveries SET state=?,last_error_code=?,last_error_kind=?,updated_at_ms=? WHERE id=?`,
		string(state), nullString(errorCode), nullString(string(kind)), now.UnixMilli(), id)
	return err
}

// Requeue 受控重试：只允许 failed 记录回到 queued 并绑定新任务。
func (s *Store) Requeue(ctx context.Context, id, taskID string, now time.Time) error {
	result, err := s.store.ExecContext(ctx,
		`UPDATE mail_deliveries SET state='queued',task_id=?,last_error_code=NULL,last_error_kind=NULL,updated_at_ms=?
WHERE id=? AND state='failed'`, taskID, now.UnixMilli(), id)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return mailer.ErrDeliveryConflict
	}
	return nil
}

// List 按条件查询投递记录，按创建时间倒序。
func (s *Store) List(ctx context.Context, query mailer.ListQuery) ([]mailer.Record, error) {
	statement := `SELECT ` + selectColumns + ` FROM mail_deliveries WHERE 1=1`
	args := make([]any, 0, 3)
	if query.State != "" {
		statement += ` AND state=?`
		args = append(args, string(query.State))
	}
	if query.Recipient != "" {
		statement += ` AND recipient=?`
		args = append(args, query.Recipient)
	}
	if query.OwnerType != "" {
		statement += ` AND owner_type=?`
		args = append(args, string(query.OwnerType))
	}
	if query.OwnerID != "" {
		statement += ` AND owner_id=?`
		args = append(args, query.OwnerID)
	}
	statement += ` ORDER BY created_at_ms DESC,id DESC LIMIT ?`
	limit := query.Limit
	if limit <= 0 || limit > mailer.MaxListLimit {
		limit = mailer.MaxListLimit
	}
	args = append(args, limit)

	rows, err := s.store.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []mailer.Record
	for rows.Next() {
		record, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

// scanRecord 读取一行投递记录。
func scanRecord(rows *sql.Rows) (mailer.Record, error) {
	var (
		record    mailer.Record
		kind      string
		state     string
		errorCode string
		errorKind string
		ownerType string
		createdAt int64
		updatedAt int64
	)
	if err := rows.Scan(
		&record.ID, &record.IdempotencyKey, &kind, &record.Recipient, &ownerType, &record.OwnerID, &state,
		&record.Attempts, &record.MaxAttempts, &record.TaskID, &errorCode, &errorKind,
		&record.SealedPayload, &record.RequestID, &createdAt, &updatedAt,
	); err != nil {
		return mailer.Record{}, err
	}
	record.Kind = mailer.Kind(kind)
	record.OwnerType = audit.ActorKind(ownerType)
	record.State = mailer.DeliveryState(state)
	record.LastErrorCode = errorCode
	record.LastErrorKind = mailer.FailureKind(errorKind)
	record.CreatedAt = time.UnixMilli(createdAt).UTC()
	record.UpdatedAt = time.UnixMilli(updatedAt).UTC()
	return record, nil
}

// nullString 把空字符串写为 NULL。
func nullString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

var _ mailer.Store = (*Store)(nil)

// Counts 实现 mailer.CountsStore：按状态统计投递记录数量。
func (s *Store) Counts(ctx context.Context) (map[mailer.DeliveryState]int, error) {
	rows, err := s.store.QueryContext(ctx, `SELECT state,COUNT(*) FROM mail_deliveries GROUP BY state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := make(map[mailer.DeliveryState]int, 5)
	for rows.Next() {
		var state string
		var count int
		if err := rows.Scan(&state, &count); err != nil {
			return nil, err
		}
		counts[mailer.DeliveryState(state)] = count
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return counts, nil
}
