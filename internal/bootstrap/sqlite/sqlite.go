// Package sqlite 实现 internal/bootstrap.Store 的 SQLite 生产持久化。
//
// 表结构来自 migrations/0001_identity_and_scope_core.sql（users）、
// 0002_one_time_credentials.sql（配置凭证）与 0008_root_initialization.sql
// （初始化状态单例）；本包不执行迁移，调用方应在启动或测试中先应用全部迁移。
// 本包不拥有数据库连接：*storage/sqlite.Store 的关闭由外层负责。构造后不可变，
// 可被多个 goroutine 并发使用。
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/bootstrap"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

const (
	// selectInitializationSQL 读取唯一的初始化状态记录。
	selectInitializationSQL = `SELECT root_user_id,state,COALESCE(setup_credential_id,''),started_by,created_at_ms,updated_at_ms,verified_at_ms,ready_at_ms
FROM root_initializations WHERE singleton=1`

	// selectRootAccountSQL 读取唯一 root 账户快照。
	selectRootAccountSQL = `SELECT id,username,status,security_version,created_at_ms,updated_at_ms
FROM users WHERE is_root=1`

	// selectSetupCredentialSQL 读取配置凭证的安全诊断列；不读取 verifier_hash。
	selectSetupCredentialSQL = `SELECT expires_at_ms,consumed_at_ms,revoked_at_ms,attempts,max_attempts
FROM one_time_credentials WHERE id=?`

	// rootExistsSQL 用一条只读查询判断 root 或初始化记录是否已存在。
	rootExistsSQL = `SELECT 1 FROM users WHERE is_root=1
UNION ALL SELECT 1 FROM root_initializations WHERE singleton=1 LIMIT 1`

	// usernameTakenSQL 判断 root 保留用户名是否已被其他账户占用。
	usernameTakenSQL = `SELECT 1 FROM users WHERE username_normalized=? LIMIT 1`

	// insertRootUserSQL 使用条件 INSERT：仅在当前没有 root 时插入 is_root=1 的
	// root 行。受影响 0 表示并发初始化已抢先创建（或存在旧 root），配合
	// ux_single_root 唯一索引形成最终保证。
	insertRootUserSQL = `INSERT INTO users(
id,username,username_normalized,nickname,biography,avatar_ref,language,timezone,status,is_root,security_version,row_version,created_at_ms,updated_at_ms
) SELECT ?,?,?,?,?,NULL,?,?,?,1,1,1,?,?
WHERE NOT EXISTS(SELECT 1 FROM users WHERE is_root=1)`

	// insertInitializationSQL 使用条件 INSERT：仅在尚无初始化记录时插入单例行。
	// 与 root 行插入处于同一事务，任一步失败整体回滚。
	insertInitializationSQL = `INSERT INTO root_initializations(
singleton,root_user_id,state,setup_credential_id,started_by,created_at_ms,updated_at_ms,verified_at_ms,ready_at_ms
) SELECT 1,?,?,?,?,?,?,NULL,NULL
WHERE NOT EXISTS(SELECT 1 FROM root_initializations WHERE singleton=1)`

	// markSetupVerifiedSQL 把 pending_setup 条件更新为 setup_verified；状态或凭证
	// ID 已被并发修改时受影响 0 行。
	markSetupVerifiedSQL = `UPDATE root_initializations
SET state='setup_verified',verified_at_ms=?,ready_at_ms=NULL,updated_at_ms=?
WHERE singleton=1 AND root_user_id=? AND state='pending_setup' AND COALESCE(setup_credential_id,'')=?`

	// updateSetupCredentialSQL 重新绑定配置凭证并把受限状态复位为 pending_setup；
	// 只有状态与当前凭证 ID 都匹配时才更新，避免并发重签/兑换互相覆盖。
	updateSetupCredentialSQL = `UPDATE root_initializations
SET setup_credential_id=?,state='pending_setup',verified_at_ms=NULL,ready_at_ms=NULL,updated_at_ms=?
WHERE singleton=1 AND root_user_id=? AND state IN('pending_setup','setup_verified')
AND COALESCE(setup_credential_id,'')=?`

	// markReadySQL 把 setup_verified 条件更新为 ready，并强制要求同一事务内已存在
	// 正式密码凭证：只有受限配置完成、正式密码已落库时才可能转换，防止内部调用者
	// 在无密码时直接把 root 置为 ready（必需强认证仍由调用方在转换前判定）。
	markReadySQL = `UPDATE root_initializations
SET state='ready',ready_at_ms=?,updated_at_ms=?
WHERE singleton=1 AND root_user_id=? AND state='setup_verified'
AND EXISTS(SELECT 1 FROM password_credentials WHERE user_id=?)`
)

// Store 是 bootstrap.Store 的 SQLite 实现。
type Store struct {
	store *storagesqlite.Store
}

// New 包装一个已打开并完成迁移的 SQLite 存储；store 为空时返回
// bootstrap.ErrOptionsInvalid，不会创建替代连接。
func New(store *storagesqlite.Store) (*Store, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", bootstrap.ErrOptionsInvalid)
	}
	return &Store{store: store}, nil
}

// 编译期确认实现 bootstrap.Store。
var _ bootstrap.Store = (*Store)(nil)

// GetInitialization 读取唯一的初始化状态记录；不存在时返回 (Record{}, false, nil)。
func (s *Store) GetInitialization(ctx context.Context) (bootstrap.Record, bool, error) {
	rows, err := s.store.QueryContext(ctx, selectInitializationSQL)
	if err != nil {
		return bootstrap.Record{}, false, fmt.Errorf("%w: %w", bootstrap.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return bootstrap.Record{}, false, fmt.Errorf("%w: %w", bootstrap.ErrStoreUnavailable, err)
		}
		return bootstrap.Record{}, false, nil
	}
	var (
		record      bootstrap.Record
		state       string
		createdAtMS int64
		updatedAtMS int64
		verifiedAt  sql.NullInt64
		readyAt     sql.NullInt64
	)
	if err := rows.Scan(&record.RootUserID, &state, &record.SetupCredentialID, &record.StartedBy,
		&createdAtMS, &updatedAtMS, &verifiedAt, &readyAt); err != nil {
		return bootstrap.Record{}, false, fmt.Errorf("%w: %w", bootstrap.ErrStoreUnavailable, err)
	}
	if err := rows.Err(); err != nil {
		return bootstrap.Record{}, false, fmt.Errorf("%w: %w", bootstrap.ErrStoreUnavailable, err)
	}
	record.State = bootstrap.State(state)
	if !record.State.Valid() || record.State == bootstrap.StateUninitialized || record.State == bootstrap.StateExistingRoot {
		return bootstrap.Record{}, false, fmt.Errorf("%w: 初始化状态数据无效", bootstrap.ErrStoreUnavailable)
	}
	record.CreatedAt = timeFromUnixMilli(createdAtMS)
	record.UpdatedAt = timeFromUnixMilli(updatedAtMS)
	record.VerifiedAt = nullableTime(verifiedAt)
	record.ReadyAt = nullableTime(readyAt)
	return record, true, nil
}

// GetRootAccount 读取 root 账户快照；不存在时返回 (RootAccount{}, false, nil)。
func (s *Store) GetRootAccount(ctx context.Context) (bootstrap.RootAccount, bool, error) {
	rows, err := s.store.QueryContext(ctx, selectRootAccountSQL)
	if err != nil {
		return bootstrap.RootAccount{}, false, fmt.Errorf("%w: %w", bootstrap.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return bootstrap.RootAccount{}, false, fmt.Errorf("%w: %w", bootstrap.ErrStoreUnavailable, err)
		}
		return bootstrap.RootAccount{}, false, nil
	}
	var (
		root        bootstrap.RootAccount
		status      string
		createdAtMS int64
		updatedAtMS int64
	)
	if err := rows.Scan(&root.UserID, &root.Username, &status, &root.SecurityVersion,
		&createdAtMS, &updatedAtMS); err != nil {
		return bootstrap.RootAccount{}, false, fmt.Errorf("%w: %w", bootstrap.ErrStoreUnavailable, err)
	}
	if err := rows.Err(); err != nil {
		return bootstrap.RootAccount{}, false, fmt.Errorf("%w: %w", bootstrap.ErrStoreUnavailable, err)
	}
	root.Status = account.Status(status)
	if !root.Status.Valid() || !account.ValidUserID(root.UserID) {
		return bootstrap.RootAccount{}, false, fmt.Errorf("%w: root 账户数据无效", bootstrap.ErrStoreUnavailable)
	}
	root.CreatedAt = timeFromUnixMilli(createdAtMS)
	root.UpdatedAt = timeFromUnixMilli(updatedAtMS)
	return root, true, nil
}

// GetSetupCredentialStatus 读取配置凭证的安全诊断状态（不含摘要）。凭证行已被
// 清理时返回 Found=false 的状态而不是错误。
func (s *Store) GetSetupCredentialStatus(ctx context.Context, credentialID string) (bootstrap.SetupCredentialStatus, error) {
	rows, err := s.store.QueryContext(ctx, selectSetupCredentialSQL, credentialID)
	if err != nil {
		return bootstrap.SetupCredentialStatus{}, fmt.Errorf("%w: %w", bootstrap.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return bootstrap.SetupCredentialStatus{}, fmt.Errorf("%w: %w", bootstrap.ErrStoreUnavailable, err)
		}
		return bootstrap.SetupCredentialStatus{Found: false}, nil
	}
	var (
		status      bootstrap.SetupCredentialStatus
		expiresAtMS int64
		consumedAt  sql.NullInt64
		revokedAt   sql.NullInt64
	)
	if err := rows.Scan(&expiresAtMS, &consumedAt, &revokedAt, &status.Attempts, &status.MaxAttempts); err != nil {
		return bootstrap.SetupCredentialStatus{}, fmt.Errorf("%w: %w", bootstrap.ErrStoreUnavailable, err)
	}
	if err := rows.Err(); err != nil {
		return bootstrap.SetupCredentialStatus{}, fmt.Errorf("%w: %w", bootstrap.ErrStoreUnavailable, err)
	}
	status.Found = true
	status.ExpiresAt = timeFromUnixMilli(expiresAtMS)
	status.ConsumedAt = nullableTime(consumedAt)
	status.RevokedAt = nullableTime(revokedAt)
	return status, nil
}

// Create 在调用方审计事务中条件插入 root 行与初始化记录。root 或初始化记录已
// 存在返回 bootstrap.ErrAlreadyInitialized；root 保留用户名被非 root 账户占用
// 返回 bootstrap.ErrRootUsernameTaken；任一步失败整体回滚。
func (s *Store) Create(ctx context.Context, tx audit.Tx, root account.User, record bootstrap.Record) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", bootstrap.ErrOptionsInvalid)
	}
	exists, err := queryExistsTx(ctx, tx, rootExistsSQL)
	if err != nil {
		return fmt.Errorf("%w: %w", bootstrap.ErrStoreUnavailable, err)
	}
	if exists {
		return bootstrap.ErrAlreadyInitialized
	}
	taken, err := queryExistsTx(ctx, tx, usernameTakenSQL, root.UsernameNormalized)
	if err != nil {
		return fmt.Errorf("%w: %w", bootstrap.ErrStoreUnavailable, err)
	}
	if taken {
		return bootstrap.ErrRootUsernameTaken
	}
	result, err := tx.ExecContext(ctx, insertRootUserSQL,
		root.ID,
		root.Username,
		root.UsernameNormalized,
		root.Nickname,
		root.Biography,
		root.Language,
		root.Timezone,
		string(root.Status),
		root.CreatedAt.UTC().UnixMilli(),
		root.UpdatedAt.UTC().UnixMilli(),
	)
	if err != nil {
		return fmt.Errorf("%w: %w", bootstrap.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: %w", bootstrap.ErrStoreUnavailable, err)
	}
	if affected != 1 {
		// 条件插入未生效：并发实例已创建 root（或出现旧 root）。再做一次只读探测
		// 以区分“已初始化”与异常存储状态。
		exists, probeErr := queryExistsTx(ctx, tx, rootExistsSQL)
		if probeErr == nil && exists {
			return bootstrap.ErrAlreadyInitialized
		}
		return fmt.Errorf("%w: 插入 root 账户未生效", bootstrap.ErrStoreUnavailable)
	}
	result, err = tx.ExecContext(ctx, insertInitializationSQL,
		record.RootUserID,
		string(record.State),
		record.SetupCredentialID,
		record.StartedBy,
		record.CreatedAt.UTC().UnixMilli(),
		record.UpdatedAt.UTC().UnixMilli(),
	)
	if err != nil {
		return fmt.Errorf("%w: %w", bootstrap.ErrStoreUnavailable, err)
	}
	affected, err = result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: %w", bootstrap.ErrStoreUnavailable, err)
	}
	if affected != 1 {
		return bootstrap.ErrAlreadyInitialized
	}
	return nil
}

// MarkSetupVerified 在审计事务中条件更新 pending_setup -> setup_verified。
// 条件不满足（状态或凭证 ID 已变化）返回 bootstrap.ErrSetupStateConflict。
func (s *Store) MarkSetupVerified(ctx context.Context, tx audit.Tx, change bootstrap.SetupVerifiedChange) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", bootstrap.ErrOptionsInvalid)
	}
	nowMS := change.Now.UTC().UnixMilli()
	result, err := tx.ExecContext(ctx, markSetupVerifiedSQL, nowMS, nowMS, change.RootUserID, change.CredentialID)
	if err != nil {
		return fmt.Errorf("%w: %w", bootstrap.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: %w", bootstrap.ErrStoreUnavailable, err)
	}
	switch affected {
	case 1:
		return nil
	case 0:
		return bootstrap.ErrSetupStateConflict
	default:
		return fmt.Errorf("%w: 状态更新影响行数异常", bootstrap.ErrStoreUnavailable)
	}
}

// UpdateSetupCredential 在审计事务中条件绑定新的配置凭证并把受限状态复位为
// pending_setup。当前状态或旧凭证 ID 不匹配时返回 bootstrap.ErrSetupStateConflict。
func (s *Store) UpdateSetupCredential(ctx context.Context, tx audit.Tx, change bootstrap.CredentialReissueChange) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", bootstrap.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, updateSetupCredentialSQL,
		change.NewCredentialID,
		change.Now.UTC().UnixMilli(),
		change.RootUserID,
		change.PreviousCredentialID,
	)
	if err != nil {
		return fmt.Errorf("%w: %w", bootstrap.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: %w", bootstrap.ErrStoreUnavailable, err)
	}
	switch affected {
	case 1:
		return nil
	case 0:
		return bootstrap.ErrSetupStateConflict
	default:
		return fmt.Errorf("%w: 凭证更新影响行数异常", bootstrap.ErrStoreUnavailable)
	}
}

// MarkReady 在审计事务中条件更新 setup_verified -> ready。转换要求当前状态为
// setup_verified 且同一事务内已存在正式密码凭证；状态被并发修改、仍处于
// pending_setup 或没有任何正式密码时返回 bootstrap.ErrSetupStateConflict，由调用方
// 整体回滚。它不判断强认证是否已配置，那是正式密码服务调用前的职责。
func (s *Store) MarkReady(ctx context.Context, tx audit.Tx, change bootstrap.RootReadyChange) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", bootstrap.ErrOptionsInvalid)
	}
	nowMS := change.Now.UTC().UnixMilli()
	result, err := tx.ExecContext(ctx, markReadySQL, nowMS, nowMS, change.RootUserID, change.RootUserID)
	if err != nil {
		return fmt.Errorf("%w: %w", bootstrap.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: %w", bootstrap.ErrStoreUnavailable, err)
	}
	switch affected {
	case 1:
		return nil
	case 0:
		return bootstrap.ErrSetupStateConflict
	default:
		return fmt.Errorf("%w: ready 状态更新影响行数异常", bootstrap.ErrStoreUnavailable)
	}
}

// queryExistsTx 在给定审计事务中执行存在性查询。
func queryExistsTx(ctx context.Context, tx audit.Tx, query string, args ...any) (bool, error) {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	if rows.Next() {
		return true, rows.Err()
	}
	return false, rows.Err()
}

// timeFromUnixMilli 把数据库毫秒时间转成 UTC 时间。
func timeFromUnixMilli(value int64) time.Time {
	return time.UnixMilli(value).UTC()
}

// nullableTime 把可空毫秒列转成 *time.Time；NULL 返回 nil。
func nullableTime(value sql.NullInt64) *time.Time {
	if !value.Valid {
		return nil
	}
	converted := timeFromUnixMilli(value.Int64)
	return &converted
}
