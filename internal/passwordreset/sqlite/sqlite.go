// Package sqlite 实现 internal/passwordreset.Store 的 SQLite 生产仓储。
//
// 表结构由 migrations/0025_password_reset.sql 创建；本包不执行迁移、不拥有数据库
// 连接、不保存密码、密码哈希或找回 token 明文。状态迁移使用条件更新，凭证原子
// 消费由 internal/credential 保证。
package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/passwordreset"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

const findUserSQL = `SELECT u.id,u.username,u.status,u.is_root,e.email,
EXISTS(SELECT 1 FROM password_credentials p WHERE p.user_id=u.id)
FROM user_emails e JOIN users u ON u.id=e.user_id
WHERE e.email_normalized=? AND e.verified_at_ms IS NOT NULL
LIMIT 1`

const insertRequestSQL = `INSERT INTO password_reset_requests(
id,user_id,masked_email,credential_id,token_sha256,state,created_at_ms,expires_at_ms,consumed_at_ms
) VALUES(?,?,?,?,?,'pending',?,?,NULL)`

const selectRequestSQL = `SELECT id,user_id,masked_email,credential_id,token_sha256,state,
created_at_ms,expires_at_ms,COALESCE(consumed_at_ms,0) FROM password_reset_requests WHERE id=?`

const listPendingSQL = `SELECT id,user_id,masked_email,credential_id,token_sha256,state,
created_at_ms,expires_at_ms,COALESCE(consumed_at_ms,0)
FROM password_reset_requests WHERE user_id=? AND state='pending' ORDER BY created_at_ms`

const cancelPendingSQL = `UPDATE password_reset_requests SET state='cancelled'
WHERE user_id=? AND state='pending'`

const verifiedEmailSQL = `SELECT email FROM user_emails
WHERE user_id=? AND verified_at_ms IS NOT NULL ORDER BY verified_at_ms DESC LIMIT 1`

const resetTargetSQL = `SELECT u.id,u.username,u.status,u.is_root,e.email,
EXISTS(SELECT 1 FROM password_credentials p WHERE p.user_id=u.id)
FROM user_emails e JOIN users u ON u.id=e.user_id
WHERE e.user_id=? AND e.verified_at_ms IS NOT NULL
ORDER BY e.verified_at_ms DESC LIMIT 1`

const consumeRequestSQL = `UPDATE password_reset_requests SET state='consumed',consumed_at_ms=?
WHERE id=? AND state='pending' AND expires_at_ms>?`

const insertOutboxSQL = `INSERT INTO oauth_revocation_events(
id,user_id,reason,created_at_ms,processed_at_ms,attempt_count
) VALUES(?,?,?,?,NULL,0)`

// Store 是 passwordreset.Store 的 SQLite 实现。
type Store struct {
	store *storagesqlite.Store
}

// New 包装已迁移的 SQLite 存储。
func New(store *storagesqlite.Store) (*Store, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", passwordreset.ErrOptionsInvalid)
	}
	return &Store{store: store}, nil
}

var _ passwordreset.Store = (*Store)(nil)

// FindUserByEmail 按规范化邮箱查已验证邮箱候选账户。
func (s *Store) FindUserByEmail(ctx context.Context, normalizedEmail string) (passwordreset.Candidate, bool, error) {
	rows, err := s.store.QueryContext(ctx, findUserSQL, normalizedEmail)
	if err != nil {
		return passwordreset.Candidate{}, false, fmt.Errorf("%w: %w", passwordreset.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return passwordreset.Candidate{}, false, nil
	}
	var candidate passwordreset.Candidate
	var status string
	var isRoot, hasPassword int
	if err := rows.Scan(&candidate.UserID, &candidate.Username, &status, &isRoot,
		&candidate.Email, &hasPassword); err != nil {
		return passwordreset.Candidate{}, false, fmt.Errorf("%w: %w", passwordreset.ErrStoreUnavailable, err)
	}
	candidate.HasPassword = hasPassword == 1
	candidate.Active = status == "active"
	candidate.IsRoot = isRoot == 1
	candidate.MaskedEmail = mask(candidate.Email)
	return candidate, true, nil
}

// CreateRequestTx 在审计事务内创建 pending 找回请求。
func (s *Store) CreateRequestTx(ctx context.Context, tx audit.Tx, request passwordreset.ResetRequest) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", passwordreset.ErrOptionsInvalid)
	}
	if _, err := tx.ExecContext(ctx, insertRequestSQL, request.ID, request.UserID,
		request.MaskedEmail, request.CredentialID, request.TokenSHA256,
		request.CreatedAt.UTC().UnixMilli(),
		request.ExpiresAt.UTC().UnixMilli()); err != nil {
		return fmt.Errorf("%w: %w", passwordreset.ErrStoreUnavailable, err)
	}
	return nil
}

// GetRequest 按 ID 读取找回请求。
func (s *Store) GetRequest(ctx context.Context, id string) (passwordreset.ResetRequest, bool, error) {
	rows, err := s.store.QueryContext(ctx, selectRequestSQL, id)
	if err != nil {
		return passwordreset.ResetRequest{}, false, fmt.Errorf("%w: %w", passwordreset.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return passwordreset.ResetRequest{}, false, nil
	}
	var request passwordreset.ResetRequest
	var createdAt, expiresAt, consumedAt int64
	if err := rows.Scan(&request.ID, &request.UserID, &request.MaskedEmail,
		&request.CredentialID, &request.TokenSHA256, &request.State, &createdAt,
		&expiresAt, &consumedAt); err != nil {
		return passwordreset.ResetRequest{}, false, fmt.Errorf("%w: %w", passwordreset.ErrStoreUnavailable, err)
	}
	request.CreatedAt = time.UnixMilli(createdAt).UTC()
	request.ExpiresAt = time.UnixMilli(expiresAt).UTC()
	if consumedAt > 0 {
		request.ConsumedAt = time.UnixMilli(consumedAt).UTC()
	}
	return request, true, nil
}

// ConsumeRequestTx 条件标记请求已消费（并发/重放单赢家）。
func (s *Store) ConsumeRequestTx(ctx context.Context, tx audit.Tx, id string, now time.Time) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("%w: 审计事务为空", passwordreset.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, consumeRequestSQL, now.UTC().UnixMilli(), id, now.UTC().UnixMilli())
	if err != nil {
		return false, fmt.Errorf("%w: %w", passwordreset.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("%w: %w", passwordreset.ErrStoreUnavailable, err)
	}
	return affected == 1, nil
}

// InsertOutboxTx 写入 OAuth 撤销可靠事件并返回事件 ID。
func (s *Store) InsertOutboxTx(ctx context.Context, tx audit.Tx, userID, reason string,
	now time.Time) (string, error) {
	if tx == nil {
		return "", fmt.Errorf("%w: 审计事务为空", passwordreset.ErrOptionsInvalid)
	}
	eventID, err := newEventID()
	if err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, insertOutboxSQL, eventID, userID, reason,
		now.UTC().UnixMilli()); err != nil {
		return "", fmt.Errorf("%w: %w", passwordreset.ErrStoreUnavailable, err)
	}
	return eventID, nil
}

// VerifiedEmail 返回用户最近已验证邮箱。
func (s *Store) VerifiedEmail(ctx context.Context, userID string) (string, bool, error) {
	rows, err := s.store.QueryContext(ctx, verifiedEmailSQL, userID)
	if err != nil {
		return "", false, fmt.Errorf("%w: %w", passwordreset.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return "", false, nil
	}
	var email string
	if err := rows.Scan(&email); err != nil {
		return "", false, fmt.Errorf("%w: %w", passwordreset.ErrStoreUnavailable, err)
	}
	return email, email != "", nil
}

// ListPending 列出用户 pending 找回请求。
func (s *Store) ListPending(ctx context.Context, userID string) ([]passwordreset.ResetRequest, error) {
	rows, err := s.store.QueryContext(ctx, listPendingSQL, userID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", passwordreset.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	return scanRequests(rows)
}

// ListPendingTx 在调用方审计事务内列出用户 pending 找回请求；语义同 ListPending。
func (s *Store) ListPendingTx(ctx context.Context, tx audit.Tx,
	userID string) ([]passwordreset.ResetRequest, error) {
	if tx == nil {
		return nil, fmt.Errorf("%w: 审计事务为空", passwordreset.ErrOptionsInvalid)
	}
	rows, err := tx.QueryContext(ctx, listPendingSQL, userID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", passwordreset.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	return scanRequests(rows)
}

// CancelPendingTx 在审计事务内取消用户全部 pending 请求。
func (s *Store) CancelPendingTx(ctx context.Context, tx audit.Tx, userID string, now time.Time) (int64, error) {
	if tx == nil {
		return 0, fmt.Errorf("%w: 审计事务为空", passwordreset.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, cancelPendingSQL, userID)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", passwordreset.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("%w: %w", passwordreset.ErrStoreUnavailable, err)
	}
	return affected, nil
}

// GetResetTarget 按用户 ID 重新确认账户可找回。
func (s *Store) GetResetTarget(ctx context.Context, userID string) (passwordreset.Candidate, bool, error) {
	rows, err := s.store.QueryContext(ctx, resetTargetSQL, userID)
	if err != nil {
		return passwordreset.Candidate{}, false, fmt.Errorf("%w: %w", passwordreset.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return passwordreset.Candidate{}, false, nil
	}
	var candidate passwordreset.Candidate
	var status string
	var isRoot, hasPassword int
	if err := rows.Scan(&candidate.UserID, &candidate.Username, &status, &isRoot,
		&candidate.Email, &hasPassword); err != nil {
		return passwordreset.Candidate{}, false, fmt.Errorf("%w: %w", passwordreset.ErrStoreUnavailable, err)
	}
	candidate.HasPassword = hasPassword == 1
	candidate.Active = status == "active"
	candidate.IsRoot = isRoot == 1
	candidate.MaskedEmail = mask(candidate.Email)
	return candidate, true, nil
}

// scanRequests 把找回请求行扫描为领域快照；调用方负责关闭 rows。
func scanRequests(rows *sql.Rows) ([]passwordreset.ResetRequest, error) {
	requests := make([]passwordreset.ResetRequest, 0, 2)
	for rows.Next() {
		var request passwordreset.ResetRequest
		var createdAt, expiresAt, consumedAt int64
		if err := rows.Scan(&request.ID, &request.UserID, &request.MaskedEmail,
			&request.CredentialID, &request.TokenSHA256, &request.State, &createdAt,
			&expiresAt, &consumedAt); err != nil {
			return nil, fmt.Errorf("%w: %w", passwordreset.ErrStoreUnavailable, err)
		}
		request.CreatedAt = time.UnixMilli(createdAt).UTC()
		request.ExpiresAt = time.UnixMilli(expiresAt).UTC()
		if consumedAt > 0 {
			request.ConsumedAt = time.UnixMilli(consumedAt).UTC()
		}
		requests = append(requests, request)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", passwordreset.ErrStoreUnavailable, err)
	}
	return requests, nil
}

func newEventID() (string, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("%w: 安全随机源不可用", passwordreset.ErrStoreUnavailable)
	}
	return "oae_" + hex.EncodeToString(buffer), nil
}

func mask(address string) string {
	for index := 0; index < len(address); index++ {
		if address[index] == '@' {
			if index == 0 || index == len(address)-1 {
				return "[REDACTED]"
			}
			return string(address[0]) + "***@" + address[index+1:]
		}
	}
	return "[REDACTED]"
}
