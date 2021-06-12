// Package sqlite 实现 internal/passkey.Store 的 SQLite 生产仓储。
//
// 表结构由 migrations/0022_passkey.sql 创建；本包不执行迁移、不拥有数据库连接。
// 挑战一次性消费使用条件更新保证并发单赢家；凭证 ID 唯一性由数据库唯一约束兜底；
// 签名计数器只在更大时推进（同步凭证允许不递增）。
package sqlite

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/passkey"
	sqlitestore "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

const credentialColumns = `id,user_id,credential_id,public_key,aaguid,rp_id,name,sign_count,
transports,backup_eligible,backed_up,user_present,user_verified,attachment,usage,version,
COALESCE(last_used_at_ms,0),COALESCE(revoked_at_ms,0),revoked_reason,created_at_ms,updated_at_ms`

const ceremonyColumns = `id,COALESCE(user_id,''),operation,purpose,context_id,challenge,
rp_id,session_data,app_id,remember_me,client_user_agent,client_address,request_id,
created_at_ms,expires_at_ms,COALESCE(consumed_at_ms,0)`

const (
	insertHandleSQL = `INSERT INTO webauthn_user_handles(user_id,handle,created_at_ms,updated_at_ms)
VALUES(?,?,?,?) ON CONFLICT(user_id) DO NOTHING`

	selectHandleSQL = `SELECT handle FROM webauthn_user_handles WHERE user_id=?`

	userStateSQL = `SELECT u.id,u.username,u.status,u.is_root,u.security_version,COALESCE(h.handle,X'')
FROM users u LEFT JOIN webauthn_user_handles h ON h.user_id=u.id WHERE u.id=?`

	userStateByHandleSQL = `SELECT u.id,u.username,u.status,u.is_root,u.security_version,h.handle
FROM webauthn_user_handles h JOIN users u ON u.id=h.user_id WHERE h.handle=?`

	userIDByUsernameSQL = `SELECT id FROM users WHERE username_normalized=?`

	activeCredentialsSQL = `SELECT ` + credentialColumns + `
FROM webauthn_credentials WHERE user_id=? AND revoked_at_ms IS NULL ORDER BY created_at_ms,id`

	credentialByIDSQL = `SELECT ` + credentialColumns + `
FROM webauthn_credentials WHERE id=? AND user_id=? AND revoked_at_ms IS NULL`

	credentialByRawIDSQL = `SELECT ` + credentialColumns + `
FROM webauthn_credentials WHERE credential_id=? AND revoked_at_ms IS NULL`

	countActiveSQL = `SELECT COUNT(*) FROM webauthn_credentials WHERE user_id=? AND revoked_at_ms IS NULL`

	bumpSecurityVersionSQL = `UPDATE users SET security_version=security_version+1,updated_at_ms=?
WHERE id=?`

	countActiveSecondFactorSQL = `SELECT COUNT(*) FROM webauthn_credentials
WHERE user_id=? AND revoked_at_ms IS NULL AND usage IN('second_factor','both')`

	hasPasswordSQL = `SELECT COUNT(*) FROM password_credentials WHERE user_id=?`

	hasSecondFactorSQL = `SELECT COUNT(*) FROM webauthn_credentials
WHERE user_id=? AND revoked_at_ms IS NULL AND usage IN('second_factor','both')`

	insertCredentialSQL = `INSERT INTO webauthn_credentials(
id,user_id,credential_id,public_key,aaguid,rp_id,name,sign_count,transports,
backup_eligible,backed_up,user_present,user_verified,attachment,usage,version,
last_used_at_ms,revoked_at_ms,revoked_reason,created_at_ms,updated_at_ms
) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,NULL,NULL,'',?,?)
ON CONFLICT(credential_id) DO NOTHING`

	renameCredentialSQL = `UPDATE webauthn_credentials SET name=?,updated_at_ms=?
WHERE id=? AND user_id=? AND revoked_at_ms IS NULL`

	revokeCredentialSQL = `UPDATE webauthn_credentials SET revoked_at_ms=?,revoked_reason=?,
updated_at_ms=?,version=version+1
WHERE id=? AND user_id=? AND revoked_at_ms IS NULL`

	updateUsageSQL = `UPDATE webauthn_credentials SET
sign_count=CASE WHEN ? > sign_count THEN ? ELSE sign_count END,
backed_up=?,user_present=?,user_verified=?,attachment=?,last_used_at_ms=?,
version=version+1,updated_at_ms=?
WHERE id=? AND user_id=? AND revoked_at_ms IS NULL`

	insertCeremonySQL = `INSERT INTO webauthn_ceremonies(
id,user_id,operation,purpose,context_id,challenge,rp_id,session_data,app_id,remember_me,
client_user_agent,client_address,request_id,created_at_ms,expires_at_ms,consumed_at_ms
) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)`

	ceremonyByIDSQL = `SELECT ` + ceremonyColumns + ` FROM webauthn_ceremonies WHERE id=?`

	consumeCeremonySQL = `UPDATE webauthn_ceremonies SET consumed_at_ms=?
WHERE id=? AND operation=? AND consumed_at_ms IS NULL AND expires_at_ms>?`

	cleanupCeremonySQL = `DELETE FROM webauthn_ceremonies WHERE id IN (
SELECT id FROM webauthn_ceremonies WHERE consumed_at_ms IS NOT NULL OR expires_at_ms<=?
ORDER BY expires_at_ms LIMIT ?)`
)

// Store 是 passkey.Store 的 SQLite 实现。
type Store struct {
	store *sqlitestore.Store
}

// New 包装已迁移的 SQLite 存储。
func New(store *sqlitestore.Store) (*Store, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", passkey.ErrOptionsInvalid)
	}
	return &Store{store: store}, nil
}

var _ passkey.Store = (*Store)(nil)

// EnsureUserHandle 返回用户句柄；不存在时用给定随机值创建（并发安全）。
func (s *Store) EnsureUserHandle(ctx context.Context, userID string, handle []byte, now time.Time) ([]byte, error) {
	if len(handle) < 16 || len(handle) > 64 {
		return nil, fmt.Errorf("%w: 用户句柄长度非法", passkey.ErrOptionsInvalid)
	}
	millis := now.UTC().UnixMilli()
	if _, err := s.store.ExecContext(ctx, insertHandleSQL, userID, handle, millis, millis); err != nil {
		return nil, fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
	}
	rows, err := s.store.QueryContext(ctx, selectHandleSQL, userID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, fmt.Errorf("%w: 无法读取用户句柄", passkey.ErrStoreUnavailable)
	}
	var stored []byte
	if err := rows.Scan(&stored); err != nil {
		return nil, fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
	}
	return stored, nil
}

// UserState 读取账户快照。
func (s *Store) UserState(ctx context.Context, userID string) (passkey.UserState, bool, error) {
	return s.queryUserState(ctx, userStateSQL, userID)
}

// UserStateByHandle 按 WebAuthn 用户句柄读取账户。
func (s *Store) UserStateByHandle(ctx context.Context, handle []byte) (passkey.UserState, bool, error) {
	return s.queryUserState(ctx, userStateByHandleSQL, handle)
}

func (s *Store) queryUserState(ctx context.Context, query string, argument any) (passkey.UserState, bool, error) {
	rows, err := s.store.QueryContext(ctx, query, argument)
	if err != nil {
		return passkey.UserState{}, false, fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return passkey.UserState{}, false, fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
		}
		return passkey.UserState{}, false, nil
	}
	var (
		state  passkey.UserState
		isRoot int
	)
	if err := rows.Scan(&state.UserID, &state.Username, &state.Status, &isRoot,
		&state.SecurityVersion, &state.Handle); err != nil {
		return passkey.UserState{}, false, fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
	}
	state.IsRoot = isRoot != 0
	return state, true, nil
}

// UserIDByNormalizedUsername 按规范化用户名查找用户 ID。
func (s *Store) UserIDByNormalizedUsername(ctx context.Context, normalized string) (string, bool, error) {
	rows, err := s.store.QueryContext(ctx, userIDByUsernameSQL, normalized)
	if err != nil {
		return "", false, fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return "", false, fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
		}
		return "", false, nil
	}
	var userID string
	if err := rows.Scan(&userID); err != nil {
		return "", false, fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
	}
	return userID, true, nil
}

// ListActiveCredentials 返回用户未撤销凭证。
func (s *Store) ListActiveCredentials(ctx context.Context, userID string) ([]passkey.Credential, error) {
	rows, err := s.store.QueryContext(ctx, activeCredentialsSQL, userID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	credentials := make([]passkey.Credential, 0, 4)
	for rows.Next() {
		credential, scanErr := scanCredential(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, scanErr)
		}
		credentials = append(credentials, credential)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
	}
	return credentials, nil
}

// CredentialByID 返回用户指定服务端凭证 ID 的有效记录。
func (s *Store) CredentialByID(ctx context.Context, userID, recordID string) (passkey.Credential, bool, error) {
	rows, err := s.store.QueryContext(ctx, credentialByIDSQL, recordID, userID)
	if err != nil {
		return passkey.Credential{}, false, fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return passkey.Credential{}, false, fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
		}
		return passkey.Credential{}, false, nil
	}
	credential, scanErr := scanCredential(rows)
	if scanErr != nil {
		return passkey.Credential{}, false, fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, scanErr)
	}
	return credential, true, nil
}

// ActiveCredentialByRawID 返回指定认证器凭证 ID 的有效记录。
func (s *Store) ActiveCredentialByRawID(ctx context.Context, credentialID []byte) (passkey.Credential, bool, error) {
	rows, err := s.store.QueryContext(ctx, credentialByRawIDSQL, credentialID)
	if err != nil {
		return passkey.Credential{}, false, fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return passkey.Credential{}, false, fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
		}
		return passkey.Credential{}, false, nil
	}
	credential, scanErr := scanCredential(rows)
	if scanErr != nil {
		return passkey.Credential{}, false, fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, scanErr)
	}
	return credential, true, nil
}

// CountActiveCredentialsTx 在审计事务中统计用户未撤销凭证数。
func (s *Store) CountActiveCredentialsTx(ctx context.Context, tx audit.Tx, userID string) (int, error) {
	if tx == nil {
		return 0, fmt.Errorf("%w: 审计事务为空", passkey.ErrStoreUnavailable)
	}
	rows, err := tx.QueryContext(ctx, countActiveSQL, userID)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return 0, fmt.Errorf("%w: 无法统计凭证数量", passkey.ErrStoreUnavailable)
	}
	var count int
	if err := rows.Scan(&count); err != nil {
		return 0, fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
	}
	return count, nil
}

// HasPasswordCredentialTx 在审计事务中报告用户是否有正式密码登录方式。
func (s *Store) HasPasswordCredentialTx(ctx context.Context, tx audit.Tx, userID string) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("%w: 审计事务为空", passkey.ErrStoreUnavailable)
	}
	rows, err := tx.QueryContext(ctx, hasPasswordSQL, userID)
	if err != nil {
		return false, fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return false, fmt.Errorf("%w: 无法统计密码登录方式", passkey.ErrStoreUnavailable)
	}
	var count int
	if err := rows.Scan(&count); err != nil {
		return false, fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
	}
	return count > 0, nil
}

// CountActiveSecondFactorCredentialsTx 在审计事务中统计第二步用途凭证数量。
func (s *Store) CountActiveSecondFactorCredentialsTx(ctx context.Context, tx audit.Tx, userID string) (int, error) {
	if tx == nil {
		return 0, fmt.Errorf("%w: 审计事务为空", passkey.ErrStoreUnavailable)
	}
	rows, err := tx.QueryContext(ctx, countActiveSecondFactorSQL, userID)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return 0, fmt.Errorf("%w: 无法统计第二步凭证", passkey.ErrStoreUnavailable)
	}
	var count int
	if err := rows.Scan(&count); err != nil {
		return 0, fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
	}
	return count, nil
}

// HasSecondFactorCredential 报告用户是否存在用途允许第二步验证的有效凭证。
func (s *Store) HasSecondFactorCredential(ctx context.Context, userID string) (bool, error) {
	rows, err := s.store.QueryContext(ctx, hasSecondFactorSQL, userID)
	if err != nil {
		return false, fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return false, fmt.Errorf("%w: 无法统计第二步凭证", passkey.ErrStoreUnavailable)
	}
	var count int
	if err := rows.Scan(&count); err != nil {
		return false, fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
	}
	return count > 0, nil
}

// CreateCredentialTx 在审计事务中创建凭证；凭证 ID 冲突返回 ErrCredentialConflict。
func (s *Store) CreateCredentialTx(ctx context.Context, tx audit.Tx, credential passkey.Credential) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", passkey.ErrStoreUnavailable)
	}
	transports, err := json.Marshal(credential.Transports)
	if err != nil {
		return fmt.Errorf("%w: %v", passkey.ErrOptionsInvalid, err)
	}
	result, err := tx.ExecContext(ctx, insertCredentialSQL,
		credential.ID, credential.UserID, credential.CredentialID, credential.PublicKey,
		credential.AAGUID, credential.RPID, credential.Name, int64(credential.SignCount),
		string(transports), boolInt(credential.BackupEligible), boolInt(credential.BackedUp),
		boolInt(credential.UserPresent), boolInt(credential.UserVerified), credential.Attachment,
		credential.Usage, credential.CreatedAt.UTC().UnixMilli(),
		credential.UpdatedAt.UTC().UnixMilli())
	if err != nil {
		return fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
	}
	if affected != 1 {
		return passkey.ErrCredentialConflict
	}
	return nil
}

// RenameCredentialTx 在审计事务中修改本人凭证显示名。
func (s *Store) RenameCredentialTx(ctx context.Context, tx audit.Tx, userID, recordID, name string, now time.Time) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("%w: 审计事务为空", passkey.ErrStoreUnavailable)
	}
	result, err := tx.ExecContext(ctx, renameCredentialSQL, name, now.UTC().UnixMilli(), recordID, userID)
	if err != nil {
		return false, fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
	}
	return affected == 1, nil
}

// RevokeCredentialTx 在审计事务中撤销本人凭证。
func (s *Store) RevokeCredentialTx(ctx context.Context, tx audit.Tx, userID, recordID, reason string, now time.Time) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("%w: 审计事务为空", passkey.ErrStoreUnavailable)
	}
	result, err := tx.ExecContext(ctx, revokeCredentialSQL, now.UTC().UnixMilli(), reason,
		now.UTC().UnixMilli(), recordID, userID)
	if err != nil {
		return false, fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
	}
	return affected == 1, nil
}

// IncrementUserSecurityVersionTx 在审计事务内递增用户安全版本使既有会话失效。
func (s *Store) IncrementUserSecurityVersionTx(ctx context.Context, tx audit.Tx, userID string, now time.Time) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", passkey.ErrStoreUnavailable)
	}
	result, err := tx.ExecContext(ctx, bumpSecurityVersionSQL, now.UTC().UnixMilli(), userID)
	if err != nil {
		return fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
	}
	if affected != 1 {
		return passkey.ErrStoreUnavailable
	}
	return nil
}

// UpdateCredentialUsageTx 在认证成功后更新计数器、备份状态与最近使用时间。
func (s *Store) UpdateCredentialUsageTx(ctx context.Context, tx audit.Tx, credential passkey.Credential, now time.Time) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", passkey.ErrStoreUnavailable)
	}
	result, err := tx.ExecContext(ctx, updateUsageSQL,
		int64(credential.SignCount), int64(credential.SignCount),
		boolInt(credential.BackedUp), boolInt(credential.UserPresent),
		boolInt(credential.UserVerified), credential.Attachment,
		now.UTC().UnixMilli(), now.UTC().UnixMilli(), credential.ID, credential.UserID)
	if err != nil {
		return fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
	}
	if affected != 1 {
		return passkey.ErrCredentialNotFound
	}
	return nil
}

// CreateCeremony 保存挑战记录。
func (s *Store) CreateCeremony(ctx context.Context, ceremony passkey.Ceremony) error {
	var userID any
	if ceremony.UserID != "" {
		userID = ceremony.UserID
	}
	purpose := ceremony.Purpose
	if purpose == "" {
		purpose = passkey.PurposeLogin
	}
	if _, err := s.store.ExecContext(ctx, insertCeremonySQL,
		ceremony.ID, userID, string(ceremony.Operation), string(purpose),
		ceremony.ContextID, ceremony.Challenge,
		ceremony.RPID, ceremony.SessionData, ceremony.AppID, boolInt(ceremony.RememberMe),
		ceremony.UserAgent, ceremony.Address, ceremony.RequestID,
		ceremony.CreatedAt.UTC().UnixMilli(), ceremony.ExpiresAt.UTC().UnixMilli()); err != nil {
		return fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
	}
	return nil
}

// ConsumeCeremony 一次性原子消费挑战；并发只有一方成功。
func (s *Store) ConsumeCeremony(ctx context.Context, id string, operation passkey.Operation,
	userID, contextID string, now time.Time) (passkey.Ceremony, error) {
	millis := now.UTC().UnixMilli()
	ceremony, found, err := s.ceremonyByID(ctx, id)
	if err != nil {
		return passkey.Ceremony{}, err
	}
	if !found {
		return passkey.Ceremony{}, passkey.ErrCeremonyInvalid
	}
	if ceremony.Operation != operation {
		return passkey.Ceremony{}, passkey.ErrCeremonyInvalid
	}
	if userID != "" && ceremony.UserID != userID {
		return passkey.Ceremony{}, passkey.ErrCeremonyInvalid
	}
	if contextID != "" && ceremony.ContextID != contextID {
		return passkey.Ceremony{}, passkey.ErrCeremonyInvalid
	}
	if !ceremony.ConsumedAt.IsZero() {
		return passkey.Ceremony{}, passkey.ErrCeremonyInvalid
	}
	if !now.Before(ceremony.ExpiresAt) {
		return passkey.Ceremony{}, passkey.ErrCeremonyExpired
	}
	result, err := s.store.ExecContext(ctx, consumeCeremonySQL, millis, id, string(operation), millis)
	if err != nil {
		return passkey.Ceremony{}, fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return passkey.Ceremony{}, fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
	}
	if affected != 1 {
		// 并发消费/过期竞争：重新判断为无效或过期，不泄露具体原因。
		if !now.Before(ceremony.ExpiresAt) {
			return passkey.Ceremony{}, passkey.ErrCeremonyExpired
		}
		return passkey.Ceremony{}, passkey.ErrCeremonyInvalid
	}
	ceremony.ConsumedAt = now
	return ceremony, nil
}

// CleanupExpiredCeremonies 惰性清理已消费或过期的挑战。
func (s *Store) CleanupExpiredCeremonies(ctx context.Context, before time.Time, limit int) (int64, error) {
	if limit <= 0 {
		limit = 100
	}
	result, err := s.store.ExecContext(ctx, cleanupCeremonySQL, before.UTC().UnixMilli(), limit)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
	}
	return affected, nil
}

func (s *Store) ceremonyByID(ctx context.Context, id string) (passkey.Ceremony, bool, error) {
	rows, err := s.store.QueryContext(ctx, ceremonyByIDSQL, id)
	if err != nil {
		return passkey.Ceremony{}, false, fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return passkey.Ceremony{}, false, fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
		}
		return passkey.Ceremony{}, false, nil
	}
	var (
		ceremony        passkey.Ceremony
		operation       string
		purpose         string
		rememberMe      int
		createdAtMillis int64
		expiresAtMillis int64
		consumedAtMill  int64
	)
	if err := rows.Scan(&ceremony.ID, &ceremony.UserID, &operation, &purpose,
		&ceremony.ContextID, &ceremony.Challenge,
		&ceremony.RPID, &ceremony.SessionData, &ceremony.AppID, &rememberMe,
		&ceremony.UserAgent, &ceremony.Address, &ceremony.RequestID,
		&createdAtMillis, &expiresAtMillis, &consumedAtMill); err != nil {
		return passkey.Ceremony{}, false, fmt.Errorf("%w: %w", passkey.ErrStoreUnavailable, err)
	}
	ceremony.Operation = passkey.Operation(operation)
	ceremony.Purpose = passkey.Purpose(purpose)
	ceremony.RememberMe = rememberMe != 0
	ceremony.CreatedAt = time.UnixMilli(createdAtMillis).UTC()
	ceremony.ExpiresAt = time.UnixMilli(expiresAtMillis).UTC()
	if consumedAtMill > 0 {
		ceremony.ConsumedAt = time.UnixMilli(consumedAtMill).UTC()
	}
	return ceremony, true, nil
}

// rowScanner 是 *sql.Rows 的最小扫描契约。
type rowScanner interface {
	Scan(dest ...any) error
}

func scanCredential(rows rowScanner) (passkey.Credential, error) {
	var (
		credential     passkey.Credential
		signCount      int64
		transports     string
		backupEligible int
		backedUp       int
		userPresent    int
		userVerified   int
		version        int64
		lastUsedMillis int64
		revokedMillis  int64
		createdMillis  int64
		updatedMillis  int64
	)
	if err := rows.Scan(&credential.ID, &credential.UserID, &credential.CredentialID,
		&credential.PublicKey, &credential.AAGUID, &credential.RPID, &credential.Name,
		&signCount, &transports, &backupEligible, &backedUp, &userPresent, &userVerified,
		&credential.Attachment, &credential.Usage, &version, &lastUsedMillis,
		&revokedMillis, &credential.RevokedReason, &createdMillis, &updatedMillis); err != nil {
		return passkey.Credential{}, err
	}
	credential.SignCount = uint32(signCount)
	credential.BackupEligible = backupEligible != 0
	credential.BackedUp = backedUp != 0
	credential.UserPresent = userPresent != 0
	credential.UserVerified = userVerified != 0
	credential.Version = version
	if transports != "" {
		if err := json.Unmarshal([]byte(transports), &credential.Transports); err != nil {
			return passkey.Credential{}, fmt.Errorf("认证器传输方式损坏: %w", err)
		}
	}
	if lastUsedMillis > 0 {
		credential.LastUsedAt = time.UnixMilli(lastUsedMillis).UTC()
	}
	if revokedMillis > 0 {
		credential.RevokedAt = time.UnixMilli(revokedMillis).UTC()
	}
	credential.CreatedAt = time.UnixMilli(createdMillis).UTC()
	credential.UpdatedAt = time.UnixMilli(updatedMillis).UTC()
	return credential, nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
