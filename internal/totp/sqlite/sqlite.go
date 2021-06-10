// Package sqlite 实现 internal/totp.Store 的 SQLite 生产仓储。
//
// 表结构由 migrations/0021_totp.sql 创建；本包不执行迁移、不拥有数据库连接。
// sealed_secret 是 internal/secrets 的认证加密信封，本包不解析也不解密；明文种子
// 永不进入本包。状态迁移与时间步推进全部使用条件更新保证并发单赢家。
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	sqlitestore "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/totp"
)

const insertBindingSQL = `INSERT INTO totp_bindings(
id,user_id,status,sealed_secret,algorithm,digits,period_seconds,window_steps,
last_accepted_step,attempts,max_attempts,expires_at_ms,created_at_ms,updated_at_ms,activated_at_ms
) VALUES(?,?,'pending',?,?,?,?,?,-1,0,?,?,?,?,NULL)`

const bindingColumns = `id,user_id,status,sealed_secret,algorithm,digits,period_seconds,
window_steps,last_accepted_step,attempts,max_attempts,expires_at_ms,created_at_ms,updated_at_ms,
COALESCE(activated_at_ms,0)`

const pendingBindingSQL = `SELECT ` + bindingColumns + `
FROM totp_bindings WHERE id=? AND user_id=? AND status='pending'`

const activeBindingSQL = `SELECT ` + bindingColumns + `
FROM totp_bindings WHERE user_id=? AND status='active'`

const listBindingsSQL = `SELECT ` + bindingColumns + `
FROM totp_bindings WHERE user_id=? ORDER BY created_at_ms DESC`

const countPendingSQL = `SELECT COUNT(*) FROM totp_bindings
WHERE user_id=? AND status='pending' AND expires_at_ms>?`

const deleteExpiredPendingSQL = `DELETE FROM totp_bindings
WHERE user_id=? AND status='pending' AND expires_at_ms<=?`

const incrementAttemptsSQL = `UPDATE totp_bindings SET attempts=attempts+1,updated_at_ms=?
WHERE id=? AND user_id=? AND status='pending' AND attempts<max_attempts`

const selectAttemptsSQL = `SELECT attempts FROM totp_bindings WHERE id=?`

const activateSQL = `UPDATE totp_bindings SET status='active',activated_at_ms=?,updated_at_ms=?,
last_accepted_step=?
WHERE id=? AND user_id=? AND status='pending' AND expires_at_ms>?`

const disableOtherActiveSQL = `UPDATE totp_bindings SET status='disabled',updated_at_ms=?
WHERE user_id=? AND status='active' AND id<>?`

const disableActiveSQL = `UPDATE totp_bindings SET status='disabled',updated_at_ms=?
WHERE user_id=? AND status='active'`

const advanceStepSQL = `UPDATE totp_bindings SET last_accepted_step=?,updated_at_ms=?
WHERE id=? AND user_id=? AND status='active' AND last_accepted_step<?`

const hasActiveSQL = `SELECT COUNT(*) FROM totp_bindings WHERE user_id=? AND status='active'`

const usernameSQL = `SELECT username FROM users WHERE id=?`

// Store 是 totp.Store 的 SQLite 实现。
type Store struct {
	store *sqlitestore.Store
}

// New 包装已迁移的 SQLite 存储。
func New(store *sqlitestore.Store) (*Store, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", totp.ErrOptionsInvalid)
	}
	return &Store{store: store}, nil
}

var _ totp.Store = (*Store)(nil)

// CreatePendingTx 在审计事务内创建 pending 绑定。
func (s *Store) CreatePendingTx(ctx context.Context, tx audit.Tx, binding totp.Binding) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", totp.ErrOptionsInvalid)
	}
	sealed := binding.SealedSecret()
	if _, err := tx.ExecContext(ctx, insertBindingSQL, binding.ID, binding.UserID, sealed,
		string(binding.Algorithm), binding.Digits, binding.PeriodSeconds, binding.WindowSteps,
		binding.MaxAttempts, binding.ExpiresAt.UTC().UnixMilli(),
		binding.CreatedAt.UTC().UnixMilli(), binding.UpdatedAt.UTC().UnixMilli()); err != nil {
		return fmt.Errorf("%w: %w", totp.ErrStoreUnavailable, err)
	}
	return nil
}

// CountPending 统计未过期 pending 绑定数。
func (s *Store) CountPending(ctx context.Context, userID string, now time.Time) (int, error) {
	rows, err := s.store.QueryContext(ctx, countPendingSQL, userID, now.UTC().UnixMilli())
	if err != nil {
		return 0, fmt.Errorf("%w: %w", totp.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return 0, fmt.Errorf("%w: 无法统计绑定", totp.ErrStoreUnavailable)
	}
	var count int
	if err := rows.Scan(&count); err != nil {
		return 0, fmt.Errorf("%w: %w", totp.ErrStoreUnavailable, err)
	}
	return count, nil
}

// DeleteExpiredPending 惰性清理过期 pending 绑定。
func (s *Store) DeleteExpiredPending(ctx context.Context, userID string, now time.Time) (int64, error) {
	result, err := s.store.ExecContext(ctx, deleteExpiredPendingSQL, userID, now.UTC().UnixMilli())
	if err != nil {
		return 0, fmt.Errorf("%w: %w", totp.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("%w: %w", totp.ErrStoreUnavailable, err)
	}
	return affected, nil
}

// GetPending 读取用户 pending 绑定。
func (s *Store) GetPending(ctx context.Context, userID, bindingID string) (totp.Binding, bool, error) {
	return s.queryBinding(ctx, pendingBindingSQL, bindingID, userID)
}

// GetActive 读取用户 active 绑定。
func (s *Store) GetActive(ctx context.Context, userID string) (totp.Binding, bool, error) {
	return s.queryBinding(ctx, activeBindingSQL, userID)
}

// List 读取用户全部绑定（含加密信封，服务层输出前剥离）。
func (s *Store) List(ctx context.Context, userID string) ([]totp.Binding, error) {
	rows, err := s.store.QueryContext(ctx, listBindingsSQL, userID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", totp.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	bindings := make([]totp.Binding, 0, 2)
	for rows.Next() {
		binding, scanErr := scanBinding(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		bindings = append(bindings, binding)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", totp.ErrStoreUnavailable, err)
	}
	return bindings, nil
}

// IncrementAttemptsTx 条件递增确认尝试次数。
func (s *Store) IncrementAttemptsTx(ctx context.Context, tx audit.Tx, userID, bindingID string,
	now time.Time) (int, bool, error) {
	if tx == nil {
		return 0, false, fmt.Errorf("%w: 审计事务为空", totp.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, incrementAttemptsSQL, now.UTC().UnixMilli(), bindingID, userID)
	if err != nil {
		return 0, false, fmt.Errorf("%w: %w", totp.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, false, fmt.Errorf("%w: %w", totp.ErrStoreUnavailable, err)
	}
	if affected != 1 {
		return 0, false, nil
	}
	rows, err := tx.QueryContext(ctx, selectAttemptsSQL, bindingID)
	if err != nil {
		return 0, false, fmt.Errorf("%w: %w", totp.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return 0, false, fmt.Errorf("%w: 无法读取尝试计数", totp.ErrStoreUnavailable)
	}
	var attempts int
	if err := rows.Scan(&attempts); err != nil {
		return 0, false, fmt.Errorf("%w: %w", totp.ErrStoreUnavailable, err)
	}
	return attempts, true, nil
}

// IncrementAttempts 非事务递增确认尝试次数。
func (s *Store) IncrementAttempts(ctx context.Context, userID, bindingID string, now time.Time) (int, bool, error) {
	result, err := s.store.ExecContext(ctx, incrementAttemptsSQL, now.UTC().UnixMilli(), bindingID, userID)
	if err != nil {
		return 0, false, fmt.Errorf("%w: %w", totp.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, false, fmt.Errorf("%w: %w", totp.ErrStoreUnavailable, err)
	}
	if affected != 1 {
		return 0, false, nil
	}
	rows, err := s.store.QueryContext(ctx, selectAttemptsSQL, bindingID)
	if err != nil {
		return 0, false, fmt.Errorf("%w: %w", totp.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return 0, false, fmt.Errorf("%w: 无法读取尝试计数", totp.ErrStoreUnavailable)
	}
	var attempts int
	if err := rows.Scan(&attempts); err != nil {
		return 0, false, fmt.Errorf("%w: %w", totp.ErrStoreUnavailable, err)
	}
	return attempts, true, nil
}

// ActivateTx 激活 pending 并停用旧 active（同一事务内完成重绑替换）。
func (s *Store) ActivateTx(ctx context.Context, tx audit.Tx, userID, bindingID string,
	step int64, now time.Time) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("%w: 审计事务为空", totp.ErrOptionsInvalid)
	}
	nowMS := now.UTC().UnixMilli()
	// 先停用旧 active 再激活新绑定：部分唯一索引只允许每用户一个 active，顺序
	// 反了会触发唯一约束；两步在同一事务内，任一步失败整体回滚（旧绑定保留）。
	if _, err := tx.ExecContext(ctx, disableOtherActiveSQL, nowMS, userID, bindingID); err != nil {
		return false, fmt.Errorf("%w: %w", totp.ErrStoreUnavailable, err)
	}
	result, err := tx.ExecContext(ctx, activateSQL, nowMS, nowMS, step, bindingID, userID, nowMS)
	if err != nil {
		return false, fmt.Errorf("%w: %w", totp.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("%w: %w", totp.ErrStoreUnavailable, err)
	}
	if affected != 1 {
		return false, nil
	}
	return true, nil
}

// DisableActiveTx 停用当前 active 绑定。
func (s *Store) DisableActiveTx(ctx context.Context, tx audit.Tx, userID string, now time.Time) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("%w: 审计事务为空", totp.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, disableActiveSQL, now.UTC().UnixMilli(), userID)
	if err != nil {
		return false, fmt.Errorf("%w: %w", totp.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("%w: %w", totp.ErrStoreUnavailable, err)
	}
	return affected == 1, nil
}

// AdvanceAcceptedStepTx 条件推进已接受时间步（严格更大值才成功）。
func (s *Store) AdvanceAcceptedStepTx(ctx context.Context, tx audit.Tx, userID, bindingID string,
	step int64, now time.Time) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("%w: 审计事务为空", totp.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, advanceStepSQL, step, now.UTC().UnixMilli(),
		bindingID, userID, step)
	if err != nil {
		return false, fmt.Errorf("%w: %w", totp.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("%w: %w", totp.ErrStoreUnavailable, err)
	}
	return affected == 1, nil
}

// HasActive 报告用户是否有 active 绑定。
func (s *Store) HasActive(ctx context.Context, userID string) (bool, error) {
	rows, err := s.store.QueryContext(ctx, hasActiveSQL, userID)
	if err != nil {
		return false, fmt.Errorf("%w: %w", totp.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return false, fmt.Errorf("%w: 无法查询绑定", totp.ErrStoreUnavailable)
	}
	var count int
	if err := rows.Scan(&count); err != nil {
		return false, fmt.Errorf("%w: %w", totp.ErrStoreUnavailable, err)
	}
	return count > 0, nil
}

// Username 返回用户显示用户名。
func (s *Store) Username(ctx context.Context, userID string) (string, bool, error) {
	rows, err := s.store.QueryContext(ctx, usernameSQL, userID)
	if err != nil {
		return "", false, fmt.Errorf("%w: %w", totp.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return "", false, nil
	}
	var username string
	if err := rows.Scan(&username); err != nil {
		return "", false, fmt.Errorf("%w: %w", totp.ErrStoreUnavailable, err)
	}
	return username, true, nil
}

func (s *Store) queryBinding(ctx context.Context, query string, args ...any) (totp.Binding, bool, error) {
	rows, err := s.store.QueryContext(ctx, query, args...)
	if err != nil {
		return totp.Binding{}, false, fmt.Errorf("%w: %w", totp.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return totp.Binding{}, false, nil
	}
	binding, err := scanBinding(rows)
	if err != nil {
		return totp.Binding{}, false, err
	}
	return binding, true, nil
}

func scanBinding(rows *sql.Rows) (totp.Binding, error) {
	var binding totp.Binding
	var sealed []byte
	var algorithm, status string
	var activatedAt, expiresAt, createdAt, updatedAt int64
	if err := rows.Scan(&binding.ID, &binding.UserID, &status, &sealed, &algorithm,
		&binding.Digits, &binding.PeriodSeconds, &binding.WindowSteps,
		&binding.LastAcceptedStep, &binding.Attempts, &binding.MaxAttempts,
		&expiresAt, &createdAt, &updatedAt, &activatedAt); err != nil {
		return totp.Binding{}, fmt.Errorf("%w: %w", totp.ErrStoreUnavailable, err)
	}
	binding.ExpiresAt = time.UnixMilli(expiresAt).UTC()
	binding.CreatedAt = time.UnixMilli(createdAt).UTC()
	binding.UpdatedAt = time.UnixMilli(updatedAt).UTC()
	binding.Status = status
	binding.Algorithm = totp.Algorithm(algorithm)
	binding.SetSealedSecret(sealed)
	if activatedAt > 0 {
		binding.ActivatedAt = time.UnixMilli(activatedAt).UTC()
	}
	return binding, nil
}
