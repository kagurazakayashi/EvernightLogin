// Package sqlite 实现 internal/recovery.Store 的 SQLite 生产仓储。
//
// 表结构由 migrations/0024_recovery_codes.sql 创建；本包不执行迁移、不拥有数据库
// 连接、不保存恢复代码明文。代码消费与尝试状态迁移全部使用条件更新，保证并发使用
// 同一代码或并发完成/取消时只有一个赢家。
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/recovery"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

const selectUserStateSQL = `SELECT status,is_root,security_version FROM users WHERE id=?`

const selectUsernameSQL = `SELECT username FROM users WHERE id=?`

const selectVerifiedEmailSQL = `SELECT email FROM user_emails
WHERE user_id=? AND verified_at_ms IS NOT NULL ORDER BY verified_at_ms DESC LIMIT 1`

const selectGroupSQL = `SELECT id,user_id,generation,status,code_count,created_at_ms
FROM recovery_code_groups WHERE id=?`

const selectActiveGroupSQL = `SELECT id,user_id,generation,status,code_count,created_at_ms
FROM recovery_code_groups WHERE user_id=? AND status='active' LIMIT 1`

const insertGroupSQL = `INSERT INTO recovery_code_groups(
id,user_id,generation,status,code_count,created_at_ms) VALUES(?,?,?,?,?,?)`

const insertCodeSQL = `INSERT INTO recovery_codes(
id,group_id,user_id,digest,key_id,used_at_ms,created_at_ms) VALUES(?,?,?,?,?,NULL,?)`

const listUnusedCodesSQL = `SELECT c.id,c.group_id,c.user_id,c.digest,c.key_id,c.used_at_ms,c.created_at_ms
FROM recovery_codes c JOIN recovery_code_groups g ON g.id=c.group_id
WHERE c.user_id=? AND g.status='active' AND c.used_at_ms IS NULL ORDER BY c.created_at_ms`

const countUnusedCodesSQL = `SELECT COUNT(*) FROM recovery_codes
WHERE group_id=? AND used_at_ms IS NULL`

const consumeCodeSQL = `UPDATE recovery_codes SET used_at_ms=?
WHERE id=? AND used_at_ms IS NULL AND EXISTS(
  SELECT 1 FROM recovery_code_groups g WHERE g.id=recovery_codes.group_id AND g.status='active')`

const invalidateGroupSQL = `UPDATE recovery_code_groups SET status=?,invalidated_at_ms=?
WHERE id=? AND status IN('active','exhausted')`

const insertAttemptSQL = `INSERT INTO recovery_attempts(
id,user_id,group_id,code_id,status,session_id,planned_method,planned_binding_id,
factor_method,factor_ref,attempts,max_attempts,expires_at_ms,created_at_ms,updated_at_ms,finished_at_ms)
VALUES(?,?,?,?,'pending_binding',NULL,NULL,NULL,NULL,NULL,0,?,?,?,?,NULL)`

const selectAttemptSQL = `SELECT id,user_id,group_id,code_id,status,COALESCE(session_id,''),
COALESCE(planned_method,''),COALESCE(planned_binding_id,''),COALESCE(factor_method,''),
COALESCE(factor_ref,''),attempts,max_attempts,expires_at_ms,created_at_ms,updated_at_ms,
COALESCE(finished_at_ms,0) FROM recovery_attempts WHERE id=?`

const selectAttemptBySessionSQL = `SELECT id,user_id,group_id,code_id,status,COALESCE(session_id,''),
COALESCE(planned_method,''),COALESCE(planned_binding_id,''),COALESCE(factor_method,''),
COALESCE(factor_ref,''),attempts,max_attempts,expires_at_ms,created_at_ms,updated_at_ms,
COALESCE(finished_at_ms,0) FROM recovery_attempts WHERE session_id=? LIMIT 1`

const bindAttemptSessionSQL = `UPDATE recovery_attempts SET session_id=?,updated_at_ms=?
WHERE id=? AND status='pending_binding' AND session_id IS NULL AND expires_at_ms>?`

const planRebindSQL = `UPDATE recovery_attempts SET planned_method=?,planned_binding_id=?,updated_at_ms=?
WHERE id=? AND status='pending_binding' AND expires_at_ms>?`

const recordRebindFailureSQL = `UPDATE recovery_attempts SET attempts=attempts+1,updated_at_ms=?,
status=CASE WHEN attempts+1>=max_attempts THEN 'failed' ELSE status END,
finished_at_ms=CASE WHEN attempts+1>=max_attempts THEN ? ELSE finished_at_ms END
WHERE id=? AND status='pending_binding' AND expires_at_ms>?`

const selectAttemptAttemptsSQL = `SELECT attempts,status FROM recovery_attempts WHERE id=?`

const completeAttemptSQL = `UPDATE recovery_attempts SET status='completed',factor_method=?,
factor_ref=?,finished_at_ms=?,updated_at_ms=?
WHERE id=? AND status='pending_binding' AND expires_at_ms>?`

const cancelAttemptSQL = `UPDATE recovery_attempts SET status='cancelled',finished_at_ms=?,updated_at_ms=?
WHERE id=? AND status='pending_binding'`

const expireAttemptSQL = `UPDATE recovery_attempts SET status='expired',finished_at_ms=?,updated_at_ms=?
WHERE id=? AND status='pending_binding'`

const incrementSecurityVersionSQL = `UPDATE users SET security_version=security_version+1,
row_version=row_version+1,updated_at_ms=? WHERE id=? AND status='active'`

const selectSecurityVersionSQL = `SELECT security_version FROM users WHERE id=?`

// Store 是 recovery.Store 的 SQLite 实现。
type Store struct {
	store *storagesqlite.Store
}

// New 包装已迁移的 SQLite 存储。
func New(store *storagesqlite.Store) (*Store, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", recovery.ErrOptionsInvalid)
	}
	return &Store{store: store}, nil
}

var _ recovery.Store = (*Store)(nil)

// storeError 把驱动错误包装为稳定领域错误，避免原始 SQL 文本外泄。
func storeError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %s失败", recovery.ErrStoreUnavailable, operation)
}

// UserState 读取账户状态。
func (s *Store) UserState(ctx context.Context, userID string) (recovery.UserState, bool, error) {
	rows, err := s.store.QueryContext(ctx, selectUserStateSQL, userID)
	if err != nil {
		return recovery.UserState{}, false, storeError("读取账户状态", err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return recovery.UserState{}, false, storeError("读取账户状态", err)
		}
		return recovery.UserState{}, false, nil
	}
	var status string
	var isRoot int
	var securityVersion int64
	if err := rows.Scan(&status, &isRoot, &securityVersion); err != nil {
		return recovery.UserState{}, false, storeError("读取账户状态", err)
	}
	return recovery.UserState{
		Status:          account.Status(status),
		IsRoot:          isRoot == 1,
		SecurityVersion: securityVersion,
	}, true, nil
}

// Username 读取账户显示用户名。
func (s *Store) Username(ctx context.Context, userID string) (string, bool, error) {
	rows, err := s.store.QueryContext(ctx, selectUsernameSQL, userID)
	if err != nil {
		return "", false, storeError("读取用户名", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return "", false, rows.Err()
	}
	var username string
	if err := rows.Scan(&username); err != nil {
		return "", false, storeError("读取用户名", err)
	}
	return username, true, nil
}

// VerifiedEmail 返回用户最近一个已验证邮箱。
func (s *Store) VerifiedEmail(ctx context.Context, userID string) (string, bool, error) {
	rows, err := s.store.QueryContext(ctx, selectVerifiedEmailSQL, userID)
	if err != nil {
		return "", false, storeError("读取已验证邮箱", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return "", false, rows.Err()
	}
	var email string
	if err := rows.Scan(&email); err != nil {
		return "", false, storeError("读取已验证邮箱", err)
	}
	return email, true, nil
}

// ActiveGroup 返回用户当前 active 代码组。
func (s *Store) ActiveGroup(ctx context.Context, userID string) (recovery.Group, bool, error) {
	return s.scanGroup(s.store.QueryContext(ctx, selectActiveGroupSQL, userID))
}

// Group 按 ID 读取代码组。
func (s *Store) Group(ctx context.Context, groupID string) (recovery.Group, bool, error) {
	return s.scanGroup(s.store.QueryContext(ctx, selectGroupSQL, groupID))
}

// scanGroup 执行代码组查询并扫描单行结果。
func (s *Store) scanGroup(rows *sql.Rows, queryErr error) (recovery.Group, bool, error) {
	if queryErr != nil {
		return recovery.Group{}, false, storeError("读取恢复代码组", queryErr)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return recovery.Group{}, false, storeError("读取恢复代码组", err)
		}
		return recovery.Group{}, false, nil
	}
	var group recovery.Group
	var status string
	var createdAtMS int64
	if err := rows.Scan(&group.ID, &group.UserID, &group.Generation, &status, &group.CodeCount, &createdAtMS); err != nil {
		return recovery.Group{}, false, storeError("读取恢复代码组", err)
	}
	group.Status = recovery.GroupStatus(status)
	group.CreatedAt = time.UnixMilli(createdAtMS).UTC()
	return group, true, nil
}

// ListUnusedCodes 返回当前 active 组内未使用代码记录。
func (s *Store) ListUnusedCodes(ctx context.Context, userID string) ([]recovery.CodeRecord, error) {
	rows, err := s.store.QueryContext(ctx, listUnusedCodesSQL, userID)
	if err != nil {
		return nil, storeError("读取恢复代码", err)
	}
	defer rows.Close()
	records := make([]recovery.CodeRecord, 0, recovery.MaxCodeCount)
	for rows.Next() {
		var record recovery.CodeRecord
		var usedAt sql.NullInt64
		var createdAtMS int64
		if err := rows.Scan(&record.ID, &record.GroupID, &record.UserID, &record.Digest,
			&record.KeyID, &usedAt, &createdAtMS); err != nil {
			return nil, storeError("读取恢复代码", err)
		}
		if usedAt.Valid {
			record.UsedAt = time.UnixMilli(usedAt.Int64).UTC()
		}
		record.CreatedAt = time.UnixMilli(createdAtMS).UTC()
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, storeError("读取恢复代码", err)
	}
	return records, nil
}

// CountUnusedCodesTx 在审计事务内统计组内未使用代码数量。
func (s *Store) CountUnusedCodesTx(ctx context.Context, tx audit.Tx, groupID string) (int, error) {
	rows, err := tx.QueryContext(ctx, countUnusedCodesSQL, groupID)
	if err != nil {
		return 0, storeError("统计恢复代码", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return 0, storeError("统计恢复代码", sql.ErrNoRows)
	}
	var count int
	if err := rows.Scan(&count); err != nil {
		return 0, storeError("统计恢复代码", err)
	}
	return count, nil
}

// InsertGroupTx 在审计事务内插入代码组；唯一约束冲突按并发更新失败处理。
func (s *Store) InsertGroupTx(ctx context.Context, tx audit.Tx, group recovery.Group) error {
	_, err := tx.ExecContext(ctx, insertGroupSQL, group.ID, group.UserID, group.Generation,
		string(group.Status), group.CodeCount, group.CreatedAt.UnixMilli())
	if err != nil {
		if isUniqueViolation(err) {
			return recovery.ErrConcurrentRotation
		}
		return storeError("写入恢复代码组", err)
	}
	return nil
}

// InsertCodesTx 在审计事务内批量插入代码记录。
func (s *Store) InsertCodesTx(ctx context.Context, tx audit.Tx, codes []recovery.CodeRecord) error {
	for _, code := range codes {
		if _, err := tx.ExecContext(ctx, insertCodeSQL, code.ID, code.GroupID, code.UserID,
			code.Digest, code.KeyID, code.CreatedAt.UnixMilli()); err != nil {
			return storeError("写入恢复代码", err)
		}
	}
	return nil
}

// InvalidateGroupTx 条件把 active/exhausted 组迁移为指定终态。
func (s *Store) InvalidateGroupTx(ctx context.Context, tx audit.Tx, groupID string,
	status recovery.GroupStatus, now time.Time) (bool, error) {
	result, err := tx.ExecContext(ctx, invalidateGroupSQL, string(status), now.UnixMilli(), groupID)
	if err != nil {
		return false, storeError("作废恢复代码组", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, storeError("作废恢复代码组", err)
	}
	return affected == 1, nil
}

// ConsumeCodeTx 原子消费代码；只有从未使用且组仍 active 时成功。
func (s *Store) ConsumeCodeTx(ctx context.Context, tx audit.Tx, codeID string, now time.Time) (bool, error) {
	result, err := tx.ExecContext(ctx, consumeCodeSQL, now.UnixMilli(), codeID)
	if err != nil {
		return false, storeError("消费恢复代码", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, storeError("消费恢复代码", err)
	}
	return affected == 1, nil
}

// CreateAttemptTx 在审计事务内创建待绑定尝试。
func (s *Store) CreateAttemptTx(ctx context.Context, tx audit.Tx, attempt recovery.Attempt) error {
	_, err := tx.ExecContext(ctx, insertAttemptSQL, attempt.ID, attempt.UserID, attempt.GroupID,
		attempt.CodeID, attempt.MaxAttempts, attempt.ExpiresAt.UnixMilli(),
		attempt.CreatedAt.UnixMilli(), attempt.UpdatedAt.UnixMilli())
	if err != nil {
		if isUniqueViolation(err) {
			return recovery.ErrAttemptInProgress
		}
		return storeError("创建恢复尝试", err)
	}
	return nil
}

// GetAttempt 按 ID 读取尝试。
func (s *Store) GetAttempt(ctx context.Context, attemptID string) (recovery.Attempt, bool, error) {
	return s.scanAttempt(s.store.QueryContext(ctx, selectAttemptSQL, attemptID))
}

// GetAttemptBySession 按受限恢复会话 ID 读取尝试。
func (s *Store) GetAttemptBySession(ctx context.Context, sessionID string) (recovery.Attempt, bool, error) {
	return s.scanAttempt(s.store.QueryContext(ctx, selectAttemptBySessionSQL, sessionID))
}

// scanAttempt 执行尝试查询并扫描单行结果。
func (s *Store) scanAttempt(rows *sql.Rows, queryErr error) (recovery.Attempt, bool, error) {
	if queryErr != nil {
		return recovery.Attempt{}, false, storeError("读取恢复尝试", queryErr)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return recovery.Attempt{}, false, storeError("读取恢复尝试", err)
		}
		return recovery.Attempt{}, false, nil
	}
	var attempt recovery.Attempt
	var status, plannedMethod, factorMethod string
	var expiresMS, createdMS, updatedMS, finishedMS int64
	if err := rows.Scan(&attempt.ID, &attempt.UserID, &attempt.GroupID, &attempt.CodeID, &status,
		&attempt.SessionID, &plannedMethod, &attempt.PlannedBindingID, &factorMethod,
		&attempt.FactorRef, &attempt.Attempts, &attempt.MaxAttempts, &expiresMS,
		&createdMS, &updatedMS, &finishedMS); err != nil {
		return recovery.Attempt{}, false, storeError("读取恢复尝试", err)
	}
	attempt.Status = recovery.AttemptStatus(status)
	attempt.PlannedMethod = recovery.FactorMethod(plannedMethod)
	attempt.FactorMethod = recovery.FactorMethod(factorMethod)
	attempt.ExpiresAt = time.UnixMilli(expiresMS).UTC()
	attempt.CreatedAt = time.UnixMilli(createdMS).UTC()
	attempt.UpdatedAt = time.UnixMilli(updatedMS).UTC()
	if finishedMS != 0 {
		attempt.FinishedAt = time.UnixMilli(finishedMS).UTC()
	}
	return attempt, true, nil
}

// BindSessionTx 条件把恢复会话 ID 绑定到尝试。
func (s *Store) BindSessionTx(ctx context.Context, tx audit.Tx, attemptID, sessionID string, now time.Time) (bool, error) {
	result, err := tx.ExecContext(ctx, bindAttemptSessionSQL, sessionID, now.UnixMilli(), attemptID, now.UnixMilli())
	if err != nil {
		return false, storeError("绑定恢复会话", err)
	}
	return rowsAffected(result, "绑定恢复会话")
}

// PlanRebindTx 条件记录计划绑定的新因素方法与绑定 ID。
func (s *Store) PlanRebindTx(ctx context.Context, tx audit.Tx, attemptID string,
	method recovery.FactorMethod, bindingID string, now time.Time) (bool, error) {
	result, err := tx.ExecContext(ctx, planRebindSQL, string(method), bindingID, now.UnixMilli(),
		attemptID, now.UnixMilli())
	if err != nil {
		return false, storeError("记录新因素绑定计划", err)
	}
	return rowsAffected(result, "记录新因素绑定计划")
}

// RecordRebindFailureTx 条件递增失败次数，达到上限时同事务迁移 failed。
func (s *Store) RecordRebindFailureTx(ctx context.Context, tx audit.Tx, attemptID string,
	maxAttempts int, now time.Time) (int, bool, bool, error) {
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	result, err := tx.ExecContext(ctx, recordRebindFailureSQL,
		now.UnixMilli(), now.UnixMilli(), attemptID, now.UnixMilli())
	if err != nil {
		return 0, false, false, storeError("记录恢复验证失败", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, false, false, storeError("记录恢复验证失败", err)
	}
	if affected != 1 {
		return 0, false, false, nil
	}
	rows, err := tx.QueryContext(ctx, selectAttemptAttemptsSQL, attemptID)
	if err != nil {
		return 0, false, false, storeError("读取恢复验证失败次数", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return 0, false, false, storeError("读取恢复验证失败次数", sql.ErrNoRows)
	}
	var attempts int
	var status string
	if err := rows.Scan(&attempts, &status); err != nil {
		return 0, false, false, storeError("读取恢复验证失败次数", err)
	}
	limited := status == string(recovery.AttemptFailed)
	return attempts, limited, true, nil
}

// CompleteAttemptTx 条件迁移 completed 并写入新因素证明字段。
func (s *Store) CompleteAttemptTx(ctx context.Context, tx audit.Tx, attemptID string,
	proof recovery.FactorProof, now time.Time) (bool, error) {
	result, err := tx.ExecContext(ctx, completeAttemptSQL, string(proof.Method), proof.FactorRef,
		now.UnixMilli(), now.UnixMilli(), attemptID, now.UnixMilli())
	if err != nil {
		return false, storeError("完成恢复尝试", err)
	}
	return rowsAffected(result, "完成恢复尝试")
}

// CancelAttemptTx 条件迁移 cancelled。
func (s *Store) CancelAttemptTx(ctx context.Context, tx audit.Tx, attemptID string, now time.Time) (bool, error) {
	result, err := tx.ExecContext(ctx, cancelAttemptSQL, now.UnixMilli(), now.UnixMilli(), attemptID)
	if err != nil {
		return false, storeError("取消恢复尝试", err)
	}
	return rowsAffected(result, "取消恢复尝试")
}

// ExpireAttemptTx 条件迁移 expired。
func (s *Store) ExpireAttemptTx(ctx context.Context, tx audit.Tx, attemptID string, now time.Time) (bool, error) {
	result, err := tx.ExecContext(ctx, expireAttemptSQL, now.UnixMilli(), now.UnixMilli(), attemptID)
	if err != nil {
		return false, storeError("过期恢复尝试", err)
	}
	return rowsAffected(result, "过期恢复尝试")
}

// IncrementSecurityVersionTx 在同一事务内递增账户安全版本并返回新值。
func (s *Store) IncrementSecurityVersionTx(ctx context.Context, tx audit.Tx, userID string, now time.Time) (int64, error) {
	result, err := tx.ExecContext(ctx, incrementSecurityVersionSQL, now.UnixMilli(), userID)
	if err != nil {
		return 0, storeError("递增账户安全版本", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, storeError("递增账户安全版本", err)
	}
	if affected != 1 {
		return 0, recovery.ErrStoreUnavailable
	}
	rows, err := tx.QueryContext(ctx, selectSecurityVersionSQL, userID)
	if err != nil {
		return 0, storeError("读取账户安全版本", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return 0, storeError("读取账户安全版本", sql.ErrNoRows)
	}
	var version int64
	if err := rows.Scan(&version); err != nil {
		return 0, storeError("读取账户安全版本", err)
	}
	if version <= 0 {
		return 0, recovery.ErrStoreUnavailable
	}
	return version, nil
}

// rowsAffected 把条件更新结果转换为“是否只有一行生效”。
func rowsAffected(result sql.Result, operation string) (bool, error) {
	affected, err := result.RowsAffected()
	if err != nil {
		return false, storeError(operation, err)
	}
	return affected == 1, nil
}

// isUniqueViolation 识别 SQLite 唯一约束冲突（恢复尝试并发进行中/并发生成代码组）。
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, "UNIQUE constraint failed") || strings.Contains(message, "constraint failed")
}
