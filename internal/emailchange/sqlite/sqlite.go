// Package sqlite 实现 internal/emailchange.Store 的 SQLite 生产仓储。
//
// 表由 migrations/0016_email_change.sql 创建，邮箱行复用 0009 user_emails；本包不执行
// 迁移、不拥有数据库连接，也不读写邮件正文或令牌明文。
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/emailchange"
	storage "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

const selectEmailSQL = `SELECT email,email_normalized FROM user_emails
WHERE user_id=? AND verified_at_ms IS NOT NULL ORDER BY created_at_ms DESC LIMIT 1`

const selectRequestColumns = `id,user_id,old_email,old_email_normalized,new_email,
new_email_normalized,status,credential_id,created_at_ms,expires_at_ms,completed_at_ms,
cancelled_at_ms,verify_state,COALESCE(verify_error_code,''),verify_notified_at_ms,
notify_state,COALESCE(notify_error_code,''),notified_at_ms`

const selectRequestSQL = `SELECT ` + selectRequestColumns + ` FROM email_change_requests WHERE id=?`
const selectActiveRequestSQL = `SELECT ` + selectRequestColumns + ` FROM email_change_requests
WHERE user_id=? AND status='pending' ORDER BY created_at_ms DESC LIMIT 1`
const selectPendingCredentialSQL = `SELECT credential_id FROM email_change_requests
WHERE user_id=? AND status='pending'`

// Store 是 emailchange.Store 的 SQLite 实现。
type Store struct{ store *storage.Store }

// New 包装已迁移的 SQLite 存储。
func New(store *storage.Store) (*Store, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", emailchange.ErrOptionsInvalid)
	}
	return &Store{store: store}, nil
}

var _ emailchange.Store = (*Store)(nil)

// CurrentEmail 读取用户当前已验证邮箱（最新一条）。
func (s *Store) CurrentEmail(ctx context.Context, userID string) (emailchange.EmailRecord, bool, error) {
	return s.queryCurrentEmail(ctx, nil, userID)
}

func (s *Store) queryCurrentEmail(ctx context.Context, tx audit.Tx, userID string) (emailchange.EmailRecord, bool, error) {
	var rows *sql.Rows
	var err error
	if tx != nil {
		rows, err = tx.QueryContext(ctx, selectEmailSQL, userID)
	} else {
		rows, err = s.store.QueryContext(ctx, selectEmailSQL, userID)
	}
	if err != nil {
		return emailchange.EmailRecord{}, false, fmt.Errorf("%w: %w", emailchange.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return emailchange.EmailRecord{}, false, nil
	}
	var record emailchange.EmailRecord
	if err := rows.Scan(&record.Email, &record.Normalized); err != nil {
		return emailchange.EmailRecord{}, false, fmt.Errorf("%w: %w", emailchange.ErrStoreUnavailable, err)
	}
	return record, true, nil
}

// EmailInUse 报告规范化邮箱是否已被其他用户占用（含未验证行）。
func (s *Store) EmailInUse(ctx context.Context, normalized, excludeUserID string) (bool, error) {
	rows, err := s.store.QueryContext(ctx,
		`SELECT 1 FROM user_emails WHERE email_normalized=? AND user_id<>? LIMIT 1`, normalized, excludeUserID)
	if err != nil {
		return false, fmt.Errorf("%w: %w", emailchange.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	return rows.Next(), nil
}

// BeginRequest 在事务内取消旧 pending 申请并写入新申请，返回旧凭证 ID 列表。

// GetRequest 按 ID 读取申请。
func (s *Store) GetRequest(ctx context.Context, id string) (emailchange.Request, bool, error) {
	return s.queryRequest(ctx, nil, selectRequestSQL, id)
}

// GetActiveRequest 读取用户当前 pending 申请。
func (s *Store) GetActiveRequest(ctx context.Context, userID string) (emailchange.Request, bool, error) {
	return s.queryRequest(ctx, nil, selectActiveRequestSQL, userID)
}

// LoadRequestTx 在审计事务内读取申请。
func (s *Store) LoadRequestTx(ctx context.Context, tx audit.Tx, id string) (emailchange.Request, bool, error) {
	if tx == nil {
		return emailchange.Request{}, false, fmt.Errorf("%w: 审计事务为空", emailchange.ErrOptionsInvalid)
	}
	return s.queryRequest(ctx, tx, selectRequestSQL, id)
}

func (s *Store) queryRequest(ctx context.Context, tx audit.Tx, query string, args ...any) (emailchange.Request, bool, error) {
	var rows *sql.Rows
	var err error
	if tx != nil {
		rows, err = tx.QueryContext(ctx, query, args...)
	} else {
		rows, err = s.store.QueryContext(ctx, query, args...)
	}
	if err != nil {
		return emailchange.Request{}, false, fmt.Errorf("%w: %w", emailchange.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return emailchange.Request{}, false, nil
	}
	var record emailchange.Request
	var oldEmail, oldNormalized sql.NullString
	var completedAt, cancelledAt, verifyNotifiedAt, notifiedAt sql.NullInt64
	var createdAt, expiresAt int64
	if err := rows.Scan(&record.ID, &record.UserID, &oldEmail, &oldNormalized,
		&record.NewEmail, &record.NewEmailNormalized, &record.Status, &record.CredentialID,
		&createdAt, &expiresAt, &completedAt, &cancelledAt, &record.VerifyState,
		&record.VerifyError, &verifyNotifiedAt, &record.NotifyState, &record.NotifyError,
		&notifiedAt); err != nil {
		return emailchange.Request{}, false, fmt.Errorf("%w: %w", emailchange.ErrStoreUnavailable, err)
	}
	record.OldEmail = oldEmail.String
	record.OldEmailNormalized = oldNormalized.String
	record.CreatedAt = time.UnixMilli(createdAt).UTC()
	record.ExpiresAt = time.UnixMilli(expiresAt).UTC()
	if completedAt.Valid {
		record.CompletedAt = time.UnixMilli(completedAt.Int64).UTC()
	}
	if cancelledAt.Valid {
		record.CancelledAt = time.UnixMilli(cancelledAt.Int64).UTC()
	}
	if verifyNotifiedAt.Valid {
		record.VerifyNotifiedAt = time.UnixMilli(verifyNotifiedAt.Int64).UTC()
	}
	if notifiedAt.Valid {
		record.NotifiedAt = time.UnixMilli(notifiedAt.Int64).UTC()
	}
	return record, true, nil
}

// CancelRequestTx 条件取消 pending 申请。
func (s *Store) CancelRequestTx(ctx context.Context, tx audit.Tx, requestID, userID string, now time.Time) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("%w: 审计事务为空", emailchange.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, `UPDATE email_change_requests
SET status='cancelled',cancelled_at_ms=? WHERE id=? AND user_id=? AND status='pending'`,
		now.UTC().UnixMilli(), requestID, userID)
	if err != nil {
		return false, fmt.Errorf("%w: %w", emailchange.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("%w: %w", emailchange.ErrStoreUnavailable, err)
	}
	return affected == 1, nil
}

// CompleteRequestTx 在事务内校验并切换邮箱。
func (s *Store) CompleteRequestTx(ctx context.Context, tx audit.Tx, params emailchange.CompleteParams) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("%w: 审计事务为空", emailchange.ErrOptionsInvalid)
	}
	record, found, err := s.LoadRequestTx(ctx, tx, params.RequestID)
	if err != nil {
		return false, err
	}
	if !found || record.Status != emailchange.StatusPending || !params.Now.Before(record.ExpiresAt) {
		return false, nil
	}
	// 禁用/待删除账户不能完成邮箱切换（对齐注册与认证的账户状态语义）。
	statusRows, err := tx.QueryContext(ctx, `SELECT status FROM users WHERE id=?`, record.UserID)
	if err != nil {
		return false, fmt.Errorf("%w: %w", emailchange.ErrStoreUnavailable, err)
	}
	var accountStatus string
	statusFound := statusRows.Next()
	if statusFound {
		if err := statusRows.Scan(&accountStatus); err != nil {
			_ = statusRows.Close()
			return false, fmt.Errorf("%w: %w", emailchange.ErrStoreUnavailable, err)
		}
	}
	_ = statusRows.Close()
	if !statusFound {
		return false, nil
	}
	if accountStatus != "active" && accountStatus != "pending" {
		return false, emailchange.ErrAccessDenied
	}
	if record.NewEmailNormalized != params.NewEmailNormalized ||
		record.NewEmail != params.NewEmail {
		return false, nil
	}
	current, hasCurrent, err := s.queryCurrentEmail(ctx, tx, record.UserID)
	if err != nil {
		return false, err
	}
	if record.OldEmailNormalized != "" {
		if !hasCurrent || current.Normalized != record.OldEmailNormalized {
			return false, nil
		}
	} else if hasCurrent {
		// 首次添加期间用户已通过其他流程获得已验证邮箱：旧版本失效，必须重新申请。
		return false, nil
	}
	now := params.Now.UTC().UnixMilli()
	if record.OldEmailNormalized != "" {
		if _, err := tx.ExecContext(ctx, `DELETE FROM user_emails
WHERE user_id=? AND verified_at_ms IS NOT NULL`, record.UserID); err != nil {
			return false, fmt.Errorf("%w: %w", emailchange.ErrStoreUnavailable, err)
		}
	}
	// 同用户可能已存在该新地址的未验证行：先清掉再写入已验证行，避免 ON CONFLICT
	// 影响 0 行被误判为“被他人占用”。
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_emails
WHERE user_id=? AND email_normalized=? AND verified_at_ms IS NULL`,
		record.UserID, record.NewEmailNormalized); err != nil {
		return false, fmt.Errorf("%w: %w", emailchange.ErrStoreUnavailable, err)
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO user_emails(
email_normalized,user_id,email,verified_at_ms,created_at_ms,updated_at_ms
) VALUES(?,?,?,?,?,?) ON CONFLICT(email_normalized) DO NOTHING`,
		record.NewEmailNormalized, record.UserID, record.NewEmail, now, now, now)
	if err != nil {
		return false, fmt.Errorf("%w: %w", emailchange.ErrStoreUnavailable, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("%w: %w", emailchange.ErrStoreUnavailable, err)
	}
	if rows == 0 {
		return false, emailchange.ErrEmailInUse
	}
	// 步骤 250：已验证邮箱身份在本事务内发生了真实变化（换绑或首次添加），同一事务
	// 递增 users.email_identity_version（单调、只增不减）。密码找回入口签发时绑定该
	// 代际并在完成/预检查的提交边界核对，因此邮箱 A→B→A 往返后即使文本复原、安全版本
	// 未变，旧链接也因代际前进而永久失效，不依赖异步清理。递增失败整体回滚，绝不留下
	// “邮箱已换而代际未变”的可复活窗口。
	identityUpdate, err := tx.ExecContext(ctx, `UPDATE users
SET email_identity_version=email_identity_version+1 WHERE id=?`, record.UserID)
	if err != nil {
		return false, fmt.Errorf("%w: %w", emailchange.ErrStoreUnavailable, err)
	}
	if affected, err := identityUpdate.RowsAffected(); err != nil {
		return false, fmt.Errorf("%w: %w", emailchange.ErrStoreUnavailable, err)
	} else if affected != 1 {
		return false, emailchange.ErrRequestNotFound
	}
	updateResult, err := tx.ExecContext(ctx, `UPDATE email_change_requests
SET status='completed',completed_at_ms=? WHERE id=? AND status='pending'`, now, record.ID)
	if err != nil {
		return false, fmt.Errorf("%w: %w", emailchange.ErrStoreUnavailable, err)
	}
	affected, err := updateResult.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("%w: %w", emailchange.ErrStoreUnavailable, err)
	}
	if affected != 1 {
		return false, nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE email_change_requests
SET status='cancelled',cancelled_at_ms=? WHERE user_id=? AND status='pending' AND id<>?`,
		now, record.UserID, record.ID); err != nil {
		return false, fmt.Errorf("%w: %w", emailchange.ErrStoreUnavailable, err)
	}
	return true, nil
}

// MarkVerify 记录验证邮件投递状态。
func (s *Store) MarkVerify(ctx context.Context, requestID string, state emailchange.NotifyState, errorCode string, now time.Time) error {
	return s.markState(ctx, "verify_state", "verify_error_code", "verify_notified_at_ms",
		requestID, state, errorCode, now)
}

// MarkNotify 记录旧邮箱告知状态。
func (s *Store) MarkNotify(ctx context.Context, requestID string, state emailchange.NotifyState, errorCode string, now time.Time) error {
	return s.markState(ctx, "notify_state", "notify_error_code", "notified_at_ms",
		requestID, state, errorCode, now)
}

func (s *Store) markState(ctx context.Context, stateColumn, errorColumn, timeColumn,
	requestID string, state emailchange.NotifyState, errorCode string, now time.Time) error {
	query := fmt.Sprintf(`UPDATE email_change_requests SET %s=?,%s=?,%s=? WHERE id=?`,
		stateColumn, errorColumn, timeColumn)
	result, err := s.store.ExecContext(ctx, query, string(state), nullable(errorCode), now.UTC().UnixMilli(), requestID)
	if err != nil {
		return fmt.Errorf("%w: %w", emailchange.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: %w", emailchange.ErrStoreUnavailable, err)
	}
	if affected != 1 {
		return emailchange.ErrRequestNotFound
	}
	return nil
}

func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}

// UpdateCredential 在事务失败补偿时更新 pending 申请的凭证 ID（只影响仍 pending 的行）。
func (s *Store) UpdateCredential(ctx context.Context, requestID string, credentialID string) error {
	result, err := s.store.ExecContext(ctx, `UPDATE email_change_requests SET credential_id=?
WHERE id=? AND status='pending'`, credentialID, requestID)
	if err != nil {
		return fmt.Errorf("%w: %w", emailchange.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: %w", emailchange.ErrStoreUnavailable, err)
	}
	if affected != 1 {
		return emailchange.ErrRequestNotFound
	}
	return nil
}

// BeginRequest 在事务内取消旧 pending 申请并写入新申请。
func (s *Store) BeginRequest(ctx context.Context, tx audit.Tx, record emailchange.RequestRecord) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", emailchange.ErrOptionsInvalid)
	}
	now := record.CreatedAt.UTC().UnixMilli()
	if _, err := tx.ExecContext(ctx, `UPDATE email_change_requests
SET status='cancelled',cancelled_at_ms=? WHERE user_id=? AND status='pending'`, now, record.UserID); err != nil {
		return fmt.Errorf("%w: %w", emailchange.ErrStoreUnavailable, err)
	}
	var oldEmail, oldNormalized any
	if record.OldEmail != "" {
		oldEmail = record.OldEmail
		oldNormalized = record.OldEmailNormalized
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO email_change_requests(
id,user_id,old_email,old_email_normalized,new_email,new_email_normalized,status,credential_id,
created_at_ms,expires_at_ms,request_id,verify_state,notify_state
) VALUES(?,?,?,?,?,?,'pending',?,?,?,?,'pending','pending')`,
		record.ID, record.UserID, oldEmail, oldNormalized, record.NewEmail,
		record.NewEmailNormalized, record.CredentialID, now,
		record.ExpiresAt.UTC().UnixMilli(), nullable(record.RequestID)); err != nil {
		return fmt.Errorf("%w: %w", emailchange.ErrStoreUnavailable, err)
	}
	return nil
}
