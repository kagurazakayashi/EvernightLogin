package httpapi

import (
	"context"
	"errors"
	"time"

	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

const (
	beginIdempotencySQL = `INSERT INTO managed_api_idempotency(
application_id,principal_kind,principal_id,idempotency_key,operation,request_hash,
status,response_status,response_body,created_at_ms,expires_at_ms)
VALUES(?,?,?,?,?,?,'in_progress',0,'',?,?)
ON CONFLICT(application_id,principal_kind,principal_id,idempotency_key) DO NOTHING`

	selectIdempotencySQL = `SELECT request_hash,status,response_status,response_body,
expires_at_ms FROM managed_api_idempotency
WHERE application_id=? AND principal_kind=? AND principal_id=? AND idempotency_key=?`

	completeIdempotencySQL = `UPDATE managed_api_idempotency
SET status='completed',response_status=?,response_body=? WHERE application_id=?
AND principal_kind=? AND principal_id=? AND idempotency_key=? AND status='in_progress'`

	abortIdempotencySQL = `DELETE FROM managed_api_idempotency WHERE application_id=?
AND principal_kind=? AND principal_id=? AND idempotency_key=? AND status='in_progress'`

	expireIdempotencySQL = `DELETE FROM managed_api_idempotency
WHERE application_id=? AND principal_kind=? AND principal_id=?
AND idempotency_key=? AND expires_at_ms <= ?`
)

// SQLIdempotencyStore 是 SQLite 幂等记录存储（迁移 0045）。
type SQLIdempotencyStore struct {
	store *storagesqlite.Store
}

// NewSQLIdempotencyStore 构造 SQLite 幂等存储；底层存储为空时拒绝。
func NewSQLIdempotencyStore(store *storagesqlite.Store) (*SQLIdempotencyStore, error) {
	if store == nil {
		return nil, errors.New("幂等存储缺少底层数据库")
	}
	return &SQLIdempotencyStore{store: store}, nil
}

var _ IdempotencyStore = (*SQLIdempotencyStore)(nil)

// Begin 原子插入 in_progress 或返回已有记录；过期记录先删除再插入。
func (s *SQLIdempotencyStore) Begin(ctx context.Context, scope IdempotencyScope,
	operation, requestHash string, now, expiresAt time.Time) (*StoredResponse, bool, error) {
	nowMs := now.UnixMilli()
	expiresMs := expiresAt.UnixMilli()
	if _, err := s.store.ExecContext(ctx, expireIdempotencySQL, scope.ApplicationID,
		scope.PrincipalKind, scope.PrincipalID, scope.Key, nowMs); err != nil {
		return nil, false, err
	}
	inserted, err := s.store.ExecContext(ctx, beginIdempotencySQL, scope.ApplicationID,
		scope.PrincipalKind, scope.PrincipalID, scope.Key, operation, requestHash,
		nowMs, expiresMs)
	if err != nil {
		return nil, false, err
	}
	insertedRows, err := inserted.RowsAffected()
	if err != nil {
		return nil, false, err
	}
	rows, err := s.store.QueryContext(ctx, selectIdempotencySQL, scope.ApplicationID,
		scope.PrincipalKind, scope.PrincipalID, scope.Key)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, false, errors.New("幂等记录不可见")
	}
	var storedHash, status, body string
	var responseStatus int
	var storedExpires int64
	if err := rows.Scan(&storedHash, &status, &responseStatus, &body, &storedExpires); err != nil {
		return nil, false, err
	}
	if storedHash != requestHash {
		return nil, true, nil
	}
	if status == "completed" {
		return &StoredResponse{Status: responseStatus, Body: []byte(body)}, false, nil
	}
	if insertedRows > 0 {
		return nil, false, nil // 本次刚创建 in_progress，可执行
	}
	return nil, true, nil // 其它请求持有同一 in_progress 记录
}

// Complete 把 in_progress 记录改为 completed；找不到 in_progress 视为错误。
func (s *SQLIdempotencyStore) Complete(ctx context.Context, scope IdempotencyScope,
	status int, body []byte) error {
	result, err := s.store.ExecContext(ctx, completeIdempotencySQL, status, string(body),
		scope.ApplicationID, scope.PrincipalKind, scope.PrincipalID, scope.Key)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return errors.New("幂等完成记录未更新")
	}
	return nil
}

// Abort 删除未完成的幂等记录，允许失败后重试。
func (s *SQLIdempotencyStore) Abort(ctx context.Context, scope IdempotencyScope) error {
	_, err := s.store.ExecContext(ctx, abortIdempotencySQL, scope.ApplicationID,
		scope.PrincipalKind, scope.PrincipalID, scope.Key)
	return err
}
