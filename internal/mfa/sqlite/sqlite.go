// Package sqlite 实现 internal/mfa.Store 的 SQLite 生产仓储。
//
// 表结构由 migrations/0020_mfa.sql 创建；本包不执行迁移、不拥有数据库连接、不保存
// 明文验证码或尝试令牌。挑战状态与重发代数全部使用条件更新保证单赢家。
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/mfa"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

const insertFactorSQL = `INSERT INTO mfa_factors(id,user_id,factor_type,status,created_at_ms,updated_at_ms)
VALUES(?,?,?,'active',?,?)`

const deleteFactorSQL = `DELETE FROM mfa_factors WHERE user_id=? AND factor_type=? AND status='active'`

const listFactorsSQL = `SELECT id,user_id,factor_type,status,created_at_ms
FROM mfa_factors WHERE user_id=? ORDER BY created_at_ms`

const countFactorSQL = `SELECT COUNT(*) FROM mfa_factors
WHERE user_id=? AND factor_type=? AND status='active'`

const insertChallengeSQL = `INSERT INTO mfa_challenges(
id,user_id,factor_type,purpose,attempt_sha256,credential_id,generation,state,username,
app_id,remember_me,client_user_agent,client_address,restricted_session_id,attempts,max_attempts,
security_version,completed_at_ms,expires_at_ms,created_at_ms,updated_at_ms,verified_at_ms
) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'',?,?,?,?,?,?,?,NULL)`

const selectChallengeSQL = `SELECT id,user_id,factor_type,purpose,attempt_sha256,credential_id,
generation,state,username,app_id,remember_me,client_user_agent,client_address,
restricted_session_id,attempts,max_attempts,security_version,completed_at_ms,expires_at_ms,
created_at_ms,updated_at_ms,COALESCE(verified_at_ms,0)
FROM mfa_challenges WHERE id=?`

const bindSessionSQL = `UPDATE mfa_challenges SET restricted_session_id=?,updated_at_ms=?
WHERE id=? AND state='pending' AND generation=? AND attempt_sha256=?
AND restricted_session_id='' AND expires_at_ms>?`

const recordAttemptSQL = `UPDATE mfa_challenges SET attempts=attempts+1,updated_at_ms=?
WHERE id=? AND state='pending' AND generation=? AND attempt_sha256=? AND expires_at_ms>?`

const selectAttemptsSQL = `SELECT attempts FROM mfa_challenges WHERE id=?`

const transitionChallengeSQL = `UPDATE mfa_challenges SET state=?,updated_at_ms=?,
verified_at_ms=CASE WHEN ?='verified' THEN ? ELSE verified_at_ms END
WHERE id=? AND state=? AND generation=? AND attempt_sha256=? AND expires_at_ms>?`

const rotateChallengeSQL = `UPDATE mfa_challenges SET credential_id=?,generation=generation+1,
expires_at_ms=?,updated_at_ms=?
WHERE id=? AND state='pending' AND generation=? AND attempt_sha256=? AND expires_at_ms>?`

const verifiedEmailSQL = `SELECT email FROM user_emails
WHERE user_id=? AND verified_at_ms IS NOT NULL ORDER BY verified_at_ms DESC LIMIT 1`

const usernameSQL = `SELECT username FROM users WHERE id=?`

// Store 是 mfa.Store 的 SQLite 实现。
type Store struct {
	store *storagesqlite.Store
}

// New 包装已迁移的 SQLite 存储。
func New(store *storagesqlite.Store) (*Store, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", mfa.ErrOptionsInvalid)
	}
	return &Store{store: store}, nil
}

var _ mfa.Store = (*Store)(nil)

// GetFactors 读取用户全部因素。
func (s *Store) GetFactors(ctx context.Context, userID string) ([]mfa.Factor, error) {
	rows, err := s.store.QueryContext(ctx, listFactorsSQL, userID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", mfa.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	factors := make([]mfa.Factor, 0, 2)
	for rows.Next() {
		var factor mfa.Factor
		var createdAt int64
		var status string
		if err := rows.Scan(&factor.ID, &factor.UserID, &factor.Type, &status, &createdAt); err != nil {
			return nil, fmt.Errorf("%w: %w", mfa.ErrStoreUnavailable, err)
		}
		factor.State = status
		factor.CreatedAt = time.UnixMilli(createdAt).UTC()
		factors = append(factors, factor)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", mfa.ErrStoreUnavailable, err)
	}
	return factors, nil
}

// CountActiveFactors 统计活动因素数量。
func (s *Store) CountActiveFactors(ctx context.Context, userID string, factorType mfa.FactorType) (int, error) {
	rows, err := s.store.QueryContext(ctx, countFactorSQL, userID, string(factorType))
	if err != nil {
		return 0, fmt.Errorf("%w: %w", mfa.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return 0, fmt.Errorf("%w: 无法统计因素", mfa.ErrStoreUnavailable)
	}
	var count int
	if err := rows.Scan(&count); err != nil {
		return 0, fmt.Errorf("%w: %w", mfa.ErrStoreUnavailable, err)
	}
	return count, nil
}

// InsertFactorTx 在审计事务内插入活动因素（唯一约束拒绝重复）。
func (s *Store) InsertFactorTx(ctx context.Context, tx audit.Tx, factor mfa.Factor) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", mfa.ErrOptionsInvalid)
	}
	if _, err := tx.ExecContext(ctx, insertFactorSQL, factor.ID, factor.UserID, string(factor.Type),
		factor.CreatedAt.UTC().UnixMilli(), factor.CreatedAt.UTC().UnixMilli()); err != nil {
		return fmt.Errorf("%w: %w", mfa.ErrFactorExists, err)
	}
	return nil
}

// RemoveFactorTx 在审计事务内删除活动因素；不存在返回 false。
func (s *Store) RemoveFactorTx(ctx context.Context, tx audit.Tx, userID string, factorType mfa.FactorType) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("%w: 审计事务为空", mfa.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, deleteFactorSQL, userID, string(factorType))
	if err != nil {
		return false, fmt.Errorf("%w: %w", mfa.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("%w: %w", mfa.ErrStoreUnavailable, err)
	}
	return affected == 1, nil
}

// CreateChallengeTx 在审计事务内创建挑战。
func (s *Store) CreateChallengeTx(ctx context.Context, tx audit.Tx, challenge mfa.Challenge) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", mfa.ErrOptionsInvalid)
	}
	if _, err := tx.ExecContext(ctx, insertChallengeSQL, challenge.ID, challenge.UserID,
		string(challenge.FactorType), string(challenge.Purpose), challenge.AttemptSHA256,
		challenge.CredentialID, challenge.Generation, string(challenge.State), challenge.Username,
		challenge.AppID, boolInt(challenge.RememberMe), challenge.ClientUserAgent,
		challenge.ClientAddress, challenge.Attempts, challenge.MaxAttempts,
		challenge.SecurityVersion, challenge.CompletedAt.UTC().UnixMilli(),
		challenge.ExpiresAt.UTC().UnixMilli(), challenge.CreatedAt.UTC().UnixMilli(),
		challenge.UpdatedAt.UTC().UnixMilli()); err != nil {
		return fmt.Errorf("%w: %w", mfa.ErrStoreUnavailable, err)
	}
	return nil
}

// GetChallenge 读取挑战。
func (s *Store) GetChallenge(ctx context.Context, id string) (mfa.Challenge, bool, error) {
	rows, err := s.store.QueryContext(ctx, selectChallengeSQL, id)
	if err != nil {
		return mfa.Challenge{}, false, fmt.Errorf("%w: %w", mfa.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return mfa.Challenge{}, false, nil
	}
	var challenge mfa.Challenge
	var attempt []byte
	var factorType, purpose, state string
	var rememberMe int
	var completedAt, expiresAt, createdAt, updatedAt, verifiedAt int64
	if err := rows.Scan(&challenge.ID, &challenge.UserID, &factorType, &purpose, &attempt,
		&challenge.CredentialID, &challenge.Generation, &state, &challenge.Username,
		&challenge.AppID, &rememberMe, &challenge.ClientUserAgent, &challenge.ClientAddress,
		&challenge.RestrictedSessionID, &challenge.Attempts, &challenge.MaxAttempts,
		&challenge.SecurityVersion, &completedAt, &expiresAt, &createdAt, &updatedAt,
		&verifiedAt); err != nil {
		return mfa.Challenge{}, false, fmt.Errorf("%w: %w", mfa.ErrStoreUnavailable, err)
	}
	challenge.AttemptSHA256 = attempt
	challenge.RememberMe = rememberMe == 1
	challenge.FactorType = mfa.FactorType(factorType)
	challenge.Purpose = mfa.Purpose(purpose)
	challenge.State = mfa.ChallengeState(state)
	if completedAt > 0 {
		challenge.CompletedAt = time.UnixMilli(completedAt).UTC()
	}
	challenge.ExpiresAt = time.UnixMilli(expiresAt).UTC()
	challenge.CreatedAt = time.UnixMilli(createdAt).UTC()
	challenge.UpdatedAt = time.UnixMilli(updatedAt).UTC()
	if verifiedAt > 0 {
		challenge.VerifiedAt = time.UnixMilli(verifiedAt).UTC()
	}
	return challenge, true, nil
}

// UpdateChallengeStateTx 条件迁移挑战状态。
func (s *Store) UpdateChallengeStateTx(ctx context.Context, tx audit.Tx, challengeID string,
	attemptDigest []byte, generation int, from, to mfa.ChallengeState, now time.Time) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("%w: 审计事务为空", mfa.ErrOptionsInvalid)
	}
	nowMS := now.UTC().UnixMilli()
	result, err := tx.ExecContext(ctx, transitionChallengeSQL, string(to), nowMS, string(to),
		nowMS, challengeID, string(from), generation, attemptDigest, nowMS)
	if err != nil {
		return false, fmt.Errorf("%w: %w", mfa.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("%w: %w", mfa.ErrStoreUnavailable, err)
	}
	if affected == 0 {
		return false, nil
	}
	if affected != 1 {
		return false, fmt.Errorf("%w: 挑战状态更新影响行数异常", mfa.ErrStoreUnavailable)
	}
	return true, nil
}

// RotateChallengeTx 条件替换验证码凭证并递增重发代数。
func (s *Store) RotateChallengeTx(ctx context.Context, tx audit.Tx, challengeID string,
	attemptDigest []byte, generation int, newCredentialID string, expiresAt, now time.Time) (int, bool, error) {
	if tx == nil {
		return 0, false, fmt.Errorf("%w: 审计事务为空", mfa.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, rotateChallengeSQL, newCredentialID,
		expiresAt.UTC().UnixMilli(), now.UTC().UnixMilli(), challengeID, generation,
		attemptDigest, now.UTC().UnixMilli())
	if err != nil {
		return 0, false, fmt.Errorf("%w: %w", mfa.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, false, fmt.Errorf("%w: %w", mfa.ErrStoreUnavailable, err)
	}
	if affected == 0 {
		return 0, false, nil
	}
	return generation + 1, true, nil
}

// BindRestrictedSessionTx 条件绑定第一步受限会话 ID。
func (s *Store) BindRestrictedSessionTx(ctx context.Context, tx audit.Tx, challengeID string,
	attemptDigest []byte, generation int, sessionID string, now time.Time) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("%w: 审计事务为空", mfa.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, bindSessionSQL, sessionID, now.UTC().UnixMilli(),
		challengeID, generation, attemptDigest, now.UTC().UnixMilli())
	if err != nil {
		return false, fmt.Errorf("%w: %w", mfa.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("%w: %w", mfa.ErrStoreUnavailable, err)
	}
	return affected == 1, nil
}

// RecordAttemptTx 条件递增挑战自身的验证尝试计数。
func (s *Store) RecordAttemptTx(ctx context.Context, tx audit.Tx, challengeID string,
	attemptDigest []byte, generation int, now time.Time) (int, bool, error) {
	if tx == nil {
		return 0, false, fmt.Errorf("%w: 审计事务为空", mfa.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, recordAttemptSQL, now.UTC().UnixMilli(), challengeID,
		generation, attemptDigest, now.UTC().UnixMilli())
	if err != nil {
		return 0, false, fmt.Errorf("%w: %w", mfa.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, false, fmt.Errorf("%w: %w", mfa.ErrStoreUnavailable, err)
	}
	if affected != 1 {
		return 0, false, nil
	}
	rows, err := tx.QueryContext(ctx, selectAttemptsSQL, challengeID)
	if err != nil {
		return 0, false, fmt.Errorf("%w: %w", mfa.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return 0, false, fmt.Errorf("%w: 无法读取尝试计数", mfa.ErrStoreUnavailable)
	}
	var attempts int
	if err := rows.Scan(&attempts); err != nil {
		return 0, false, fmt.Errorf("%w: %w", mfa.ErrStoreUnavailable, err)
	}
	return attempts, true, nil
}

// VerifiedEmail 返回最近一个已验证邮箱。
func (s *Store) VerifiedEmail(ctx context.Context, userID string) (string, bool, error) {
	return s.queryString(ctx, verifiedEmailSQL, userID)
}

// Username 返回用户显示用户名。
func (s *Store) Username(ctx context.Context, userID string) (string, bool, error) {
	return s.queryString(ctx, usernameSQL, userID)
}

func (s *Store) queryString(ctx context.Context, query, argument string) (string, bool, error) {
	rows, err := s.store.QueryContext(ctx, query, argument)
	if err != nil {
		return "", false, fmt.Errorf("%w: %w", mfa.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return "", false, nil
	}
	var value string
	if err := rows.Scan(&value); err != nil {
		return "", false, fmt.Errorf("%w: %w", mfa.ErrStoreUnavailable, err)
	}
	return value, value != "", nil
}

// 保留 sql 引用以提示实现者：本包不执行任意查询。
var _ = sql.ErrNoRows

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
