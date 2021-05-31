// Package sqlite 实现 internal/registration.Store 的 SQLite 生产仓储。
//
// 表结构来自 0001（users）、0009（password_credentials/user_emails）与 0013
// （email_verification_tickets）。本包不执行迁移、不拥有数据库连接：调用方应先
// 应用全部迁移，并由外层关闭 *storagesqlite.Store。构造后不可变，可被多个
// goroutine 并发使用。
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/registration"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

const (
	// insertUserSQL 使用 ON CONFLICT(username_normalized) DO NOTHING 把并发重名
	// 转成受影响行数 0；主键冲突（随机 ID 重复）仍作为存储错误 fail-closed。
	insertUserSQL = `INSERT INTO users(
id,username,username_normalized,nickname,biography,avatar_ref,language,timezone,status,is_root,security_version,row_version,created_at_ms,updated_at_ms
) VALUES(?,?,?,?,'',NULL,?,?,?,0,1,1,?,?)
ON CONFLICT(username_normalized) DO NOTHING`

	// insertPasswordSQL 写入 Argon2id PHC 哈希；hash_version=19 与 0009 的 CHECK
	// 及 authn 生成的 PHC v=19 一致。
	insertPasswordSQL = `INSERT INTO password_credentials(
user_id,hash_scheme,hash_version,password_hash,must_change,row_version,created_at_ms,updated_at_ms,changed_at_ms
) VALUES(?,'argon2id',19,?,0,1,?,?,?)`

	insertEmailSQL = `INSERT INTO user_emails(email_normalized,user_id,email,verified_at_ms,created_at_ms,updated_at_ms)
VALUES(?,?,?,NULL,?,?)
ON CONFLICT(email_normalized) DO NOTHING`

	insertDefaultRoleSQL = `INSERT INTO user_roles(user_id,role_id,scope_id,data_scope_json,assigned_by,created_at_ms)
SELECT ?,?,?,'{}','system:registration',? FROM roles r
WHERE r.id=? AND r.scope_id=? AND r.scope_id='system' AND r.enabled=1`

	selectUserSnapshotSQL = `SELECT u.id,u.username,u.nickname,u.status,
e.email,e.email_normalized,e.verified_at_ms,e.updated_at_ms
FROM users u LEFT JOIN user_emails e ON e.email_normalized=(
  SELECT e2.email_normalized FROM user_emails e2 WHERE e2.user_id=u.id
  ORDER BY e2.created_at_ms DESC, e2.rowid DESC LIMIT 1)
WHERE u.id=?`

	selectTicketSQL = `SELECT user_id,credential_id,email,email_normalized,created_at_ms,expires_at_ms
FROM email_verification_tickets WHERE user_id=?`

	deleteUnverifiedEmailsSQL = `DELETE FROM user_emails WHERE user_id=? AND verified_at_ms IS NULL`

	upsertTicketSQL = `INSERT INTO email_verification_tickets(
user_id,credential_id,email,email_normalized,created_at_ms,expires_at_ms
) VALUES(?,?,?,?,?,?)
ON CONFLICT(user_id) DO UPDATE SET
credential_id=excluded.credential_id,
email=excluded.email,
email_normalized=excluded.email_normalized,
created_at_ms=excluded.created_at_ms,
expires_at_ms=excluded.expires_at_ms`

	verifyEmailSQL = `UPDATE user_emails SET verified_at_ms=?, updated_at_ms=?
WHERE user_id=? AND email_normalized=? AND verified_at_ms IS NULL`

	deleteTicketSQL = `DELETE FROM email_verification_tickets WHERE user_id=?`
)

// Store 是 registration.Store 的 SQLite 实现。
type Store struct {
	store *storagesqlite.Store
}

// New 包装一个已打开并完成迁移的 SQLite 存储；store 为空时返回
// registration.ErrOptionsInvalid，不会创建替代连接。
func New(store *storagesqlite.Store) (*Store, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", registration.ErrOptionsInvalid)
	}
	return &Store{store: store}, nil
}

// 编译期确认实现 registration.Store。
var _ registration.Store = (*Store)(nil)

// CreateUser 在调用方审计事务内创建用户、密码凭证、可选未验证邮箱与默认角色。
// 用户名或邮箱唯一约束冲突统一返回 ErrRegistrationConflict；任一步失败整体回滚。
func (s *Store) CreateUser(ctx context.Context, tx audit.Tx, params registration.CreateUserParams) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", registration.ErrOptionsInvalid)
	}
	if !account.ValidUserID(params.UserID) {
		return fmt.Errorf("%w: 目标用户 ID 格式无效", registration.ErrInvalidRequest)
	}
	createdAt := params.Now.UTC().UnixMilli()
	result, err := tx.ExecContext(ctx, insertUserSQL,
		params.UserID, params.Username, params.UsernameNormalized, params.Nickname,
		params.Language, params.Timezone, string(params.Status), createdAt, createdAt)
	if err != nil {
		return fmt.Errorf("%w: %w", registration.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: %w", registration.ErrStoreUnavailable, err)
	}
	if affected == 0 {
		return registration.ErrRegistrationConflict
	}
	if affected != 1 {
		return fmt.Errorf("%w: 插入用户影响行数异常", registration.ErrStoreUnavailable)
	}
	if _, err := tx.ExecContext(ctx, insertPasswordSQL, params.UserID, params.PasswordHash,
		createdAt, createdAt, createdAt); err != nil {
		return fmt.Errorf("%w: %w", registration.ErrStoreUnavailable, err)
	}
	if params.EmailNormalized != "" {
		emailResult, err := tx.ExecContext(ctx, insertEmailSQL, params.EmailNormalized,
			params.UserID, params.Email, createdAt, createdAt)
		if err != nil {
			return fmt.Errorf("%w: %w", registration.ErrStoreUnavailable, err)
		}
		emailAffected, err := emailResult.RowsAffected()
		if err != nil {
			return fmt.Errorf("%w: %w", registration.ErrStoreUnavailable, err)
		}
		if emailAffected == 0 {
			return registration.ErrRegistrationConflict
		}
	}
	for _, role := range params.DefaultRoles {
		roleResult, err := tx.ExecContext(ctx, insertDefaultRoleSQL,
			params.UserID, role.RoleID, role.ScopeID, createdAt, role.RoleID, role.ScopeID)
		if err != nil {
			return fmt.Errorf("%w: %w", registration.ErrStoreUnavailable, err)
		}
		roleAffected, err := roleResult.RowsAffected()
		if err != nil {
			return fmt.Errorf("%w: %w", registration.ErrStoreUnavailable, err)
		}
		if roleAffected != 1 {
			return fmt.Errorf("%w: 默认角色不存在、已停用或作用域不匹配", registration.ErrOptionsInvalid)
		}
	}
	return nil
}

// GetUserSnapshot 读取注册/重发所需的账户最小快照；账户不存在返回 found=false。
func (s *Store) GetUserSnapshot(ctx context.Context, userID string) (registration.UserSnapshot, bool, error) {
	rows, err := s.store.QueryContext(ctx, selectUserSnapshotSQL, userID)
	if err != nil {
		return registration.UserSnapshot{}, false, fmt.Errorf("%w: %w", registration.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return registration.UserSnapshot{}, false, fmt.Errorf("%w: %w", registration.ErrStoreUnavailable, err)
		}
		return registration.UserSnapshot{}, false, nil
	}
	var snapshot registration.UserSnapshot
	var status string
	var email, emailNormalized sql.NullString
	var verifiedAt, emailUpdatedAt sql.NullInt64
	if err := rows.Scan(&snapshot.UserID, &snapshot.Username, &snapshot.Nickname, &status,
		&email, &emailNormalized, &verifiedAt, &emailUpdatedAt); err != nil {
		return registration.UserSnapshot{}, false, fmt.Errorf("%w: %w", registration.ErrStoreUnavailable, err)
	}
	if err := rows.Err(); err != nil {
		return registration.UserSnapshot{}, false, fmt.Errorf("%w: %w", registration.ErrStoreUnavailable, err)
	}
	snapshot.Status = account.Status(status)
	if !snapshot.Status.Valid() {
		return registration.UserSnapshot{}, false, fmt.Errorf("%w: 账户状态非法", registration.ErrStoreUnavailable)
	}
	if email.Valid && emailNormalized.Valid {
		snapshot.HasEmail = true
		snapshot.Email = registration.EmailRecord{
			Email:           email.String,
			EmailNormalized: emailNormalized.String,
			Verified:        verifiedAt.Valid,
		}
		if verifiedAt.Valid {
			snapshot.Email.VerifiedAt = time.UnixMilli(verifiedAt.Int64).UTC()
		}
		if emailUpdatedAt.Valid {
			snapshot.Email.UpdatedAt = time.UnixMilli(emailUpdatedAt.Int64).UTC()
		}
	}
	return snapshot, true, nil
}

// GetVerificationTicket 读取该用户当前待验证票据；没有返回 found=false。
func (s *Store) GetVerificationTicket(ctx context.Context, userID string) (registration.Ticket, bool, error) {
	rows, err := s.store.QueryContext(ctx, selectTicketSQL, userID)
	if err != nil {
		return registration.Ticket{}, false, fmt.Errorf("%w: %w", registration.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return registration.Ticket{}, false, fmt.Errorf("%w: %w", registration.ErrStoreUnavailable, err)
		}
		return registration.Ticket{}, false, nil
	}
	var ticket registration.Ticket
	var createdAt, expiresAt int64
	if err := rows.Scan(&ticket.UserID, &ticket.CredentialID, &ticket.Email,
		&ticket.EmailNormalized, &createdAt, &expiresAt); err != nil {
		return registration.Ticket{}, false, fmt.Errorf("%w: %w", registration.ErrStoreUnavailable, err)
	}
	ticket.CreatedAt = time.UnixMilli(createdAt).UTC()
	ticket.ExpiresAt = time.UnixMilli(expiresAt).UTC()
	return ticket, true, nil
}

// ReplaceTicket 在审计事务内可选替换未验证邮箱并覆盖验证票据。替换邮箱时先删除
// 该用户所有未验证邮箱行再插入新行；邮箱已被其他账户占用时返回
// ErrRegistrationConflict（整体回滚，不留下半更新状态）。
func (s *Store) ReplaceTicket(ctx context.Context, tx audit.Tx, params registration.ReplaceTicketParams) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", registration.ErrOptionsInvalid)
	}
	if params.EmailChanged {
		if _, err := tx.ExecContext(ctx, deleteUnverifiedEmailsSQL, params.Ticket.UserID); err != nil {
			return fmt.Errorf("%w: %w", registration.ErrStoreUnavailable, err)
		}
		result, err := tx.ExecContext(ctx, insertEmailSQL, params.NewEmailNorm,
			params.Ticket.UserID, params.NewEmail, params.ReplacedAt.UTC().UnixMilli(),
			params.ReplacedAt.UTC().UnixMilli())
		if err != nil {
			return fmt.Errorf("%w: %w", registration.ErrStoreUnavailable, err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("%w: %w", registration.ErrStoreUnavailable, err)
		}
		if affected == 0 {
			return registration.ErrRegistrationConflict
		}
	}
	_, err := tx.ExecContext(ctx, upsertTicketSQL,
		params.Ticket.UserID,
		params.Ticket.CredentialID,
		params.Ticket.Email,
		params.Ticket.EmailNormalized,
		params.Ticket.CreatedAt.UTC().UnixMilli(),
		params.Ticket.ExpiresAt.UTC().UnixMilli(),
	)
	if err != nil {
		return fmt.Errorf("%w: %w", registration.ErrStoreUnavailable, err)
	}
	return nil
}

// CompleteEmailVerification 在审计事务内条件把匹配的未验证邮箱置为已验证并删除
// 验证票据。条件不满足时返回 (false, nil)，调用方必须当作验证失败整体回滚。
func (s *Store) CompleteEmailVerification(ctx context.Context, tx audit.Tx, params registration.CompleteVerificationParams) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("%w: 审计事务为空", registration.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, verifyEmailSQL, params.VerifiedAt.UTC().UnixMilli(),
		params.VerifiedAt.UTC().UnixMilli(), params.UserID, params.EmailNormalized)
	if err != nil {
		return false, fmt.Errorf("%w: %w", registration.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("%w: %w", registration.ErrStoreUnavailable, err)
	}
	if affected == 0 {
		return false, nil
	}
	if affected != 1 {
		return false, fmt.Errorf("%w: 邮箱验证影响行数异常", registration.ErrStoreUnavailable)
	}
	if _, err := tx.ExecContext(ctx, deleteTicketSQL, params.UserID); err != nil {
		return false, fmt.Errorf("%w: %w", registration.ErrStoreUnavailable, err)
	}
	return true, nil
}
