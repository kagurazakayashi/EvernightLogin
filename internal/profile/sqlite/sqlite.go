// Package sqlite 实现 internal/profile.Store 的 SQLite 生产仓储。
//
// 资料列来自 0001 users 与 0015 追加的 phone/phone_verified_at_ms/
// username_changed_at_ms；本包不执行迁移、不拥有数据库连接。应用专属资料
// （app_memberships.profile_json）不属于本包，绝不在此读写。
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/profile"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

const selectProfileColumns = `id,is_root,status,username,username_normalized,nickname,biography,
language,timezone,phone,phone_verified_at_ms,row_version,created_at_ms,updated_at_ms,
username_changed_at_ms`

const selectProfileSQL = `SELECT ` + selectProfileColumns + ` FROM users WHERE id=?`

const updateProfileSQL = `UPDATE users SET nickname=?,biography=?,language=?,timezone=?,phone=?,
phone_verified_at_ms=CASE WHEN ? THEN NULL ELSE phone_verified_at_ms END,
row_version=row_version+1,updated_at_ms=? WHERE id=? AND row_version=?`

const usernameTakenSQL = `SELECT 1 FROM users WHERE username_normalized=? AND id<>?`

const updateUsernameSQL = `UPDATE users SET username=?,username_normalized=?,username_changed_at_ms=?,
row_version=row_version+1,updated_at_ms=? WHERE id=? AND row_version=?`

// Store 是 profile.Store 的 SQLite 实现。
type Store struct {
	store *storagesqlite.Store
}

// New 包装已迁移的 SQLite 存储。
func New(store *storagesqlite.Store) (*Store, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", profile.ErrOptionsInvalid)
	}
	return &Store{store: store}, nil
}

var _ profile.Store = (*Store)(nil)

// GetProfile 读取用户全局资料。
func (s *Store) GetProfile(ctx context.Context, userID string) (profile.UserProfile, bool, error) {
	return s.queryProfile(ctx, nil, userID)
}

// GetProfileTx 在审计事务内读取用户全局资料。
func (s *Store) GetProfileTx(ctx context.Context, tx audit.Tx, userID string) (profile.UserProfile, bool, error) {
	if tx == nil {
		return profile.UserProfile{}, false, fmt.Errorf("%w: 审计事务为空", profile.ErrOptionsInvalid)
	}
	return s.queryProfile(ctx, tx, userID)
}

func (s *Store) queryProfile(ctx context.Context, tx audit.Tx, userID string) (profile.UserProfile, bool, error) {
	var rows *sql.Rows
	var err error
	if tx != nil {
		rows, err = tx.QueryContext(ctx, selectProfileSQL, userID)
	} else {
		rows, err = s.store.QueryContext(ctx, selectProfileSQL, userID)
	}
	if err != nil {
		return profile.UserProfile{}, false, fmt.Errorf("%w: %w", profile.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return profile.UserProfile{}, false, nil
	}
	var record profile.UserProfile
	var phone, phoneVerified sql.NullString
	var phoneVerifiedMS sql.NullInt64
	var isRoot int
	var status string
	var createdAt, updatedAt, usernameChangedAt int64
	if err := rows.Scan(&record.UserID, &isRoot, &status, &record.Username, &record.UsernameNormalized,
		&record.Nickname, &record.Biography, &record.Language, &record.Timezone,
		&phone, &phoneVerifiedMS, &record.RowVersion, &createdAt, &updatedAt,
		&usernameChangedAt); err != nil {
		return profile.UserProfile{}, false, fmt.Errorf("%w: %w", profile.ErrStoreUnavailable, err)
	}
	_ = phoneVerified
	record.IsRoot = isRoot == 1
	record.Status = account.Status(status)
	if !record.Status.Valid() {
		return profile.UserProfile{}, false, fmt.Errorf("%w: 账户状态非法", profile.ErrStoreUnavailable)
	}
	record.Phone = phone.String
	record.PhoneVerified = phoneVerifiedMS.Valid
	record.CreatedAt = time.UnixMilli(createdAt).UTC()
	record.UpdatedAt = time.UnixMilli(updatedAt).UTC()
	if usernameChangedAt > 0 {
		record.UsernameChangedAt = time.UnixMilli(usernameChangedAt).UTC()
	}
	return record, true, nil
}

// UpdateProfile 条件更新白名单资料；影响 0 行返回 false（版本冲突或账户已删）。
func (s *Store) UpdateProfile(ctx context.Context, tx audit.Tx, record profile.UpdateRecord) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("%w: 审计事务为空", profile.ErrOptionsInvalid)
	}
	var phone any
	if record.Phone != "" {
		phone = record.Phone
	}
	result, err := tx.ExecContext(ctx, updateProfileSQL,
		record.Nickname, record.Biography, record.Language, record.Timezone, phone,
		record.PhoneChanged, record.Now.UTC().UnixMilli(), record.UserID, record.ExpectedRowVersion)
	if err != nil {
		return false, fmt.Errorf("%w: %w", profile.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("%w: %w", profile.ErrStoreUnavailable, err)
	}
	if affected == 0 {
		return false, nil
	}
	if affected != 1 {
		return false, fmt.Errorf("%w: 资料更新影响行数异常", profile.ErrStoreUnavailable)
	}
	return true, nil
}

// UpdateUsername 条件更名；唯一冲突返回 ErrUsernameTaken，版本不匹配返回 false。
func (s *Store) UpdateUsername(ctx context.Context, tx audit.Tx, update profile.UsernameUpdate) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("%w: 审计事务为空", profile.ErrOptionsInvalid)
	}
	rows, err := tx.QueryContext(ctx, usernameTakenSQL, update.UsernameNormalized, update.UserID)
	if err != nil {
		return false, fmt.Errorf("%w: %w", profile.ErrStoreUnavailable, err)
	}
	taken := rows.Next()
	_ = rows.Close()
	if taken {
		return false, profile.ErrUsernameTaken
	}
	result, err := tx.ExecContext(ctx, updateUsernameSQL,
		update.Username, update.UsernameNormalized, update.Now.UTC().UnixMilli(),
		update.Now.UTC().UnixMilli(), update.UserID, update.ExpectedRowVersion)
	if err != nil {
		// 并发更名到同一规范化用户名会触发唯一约束；重读一次区分唯一冲突与其他
		// 存储故障，避免把所有 SQL 错误都伪装成 CONFLICT（也不能 fail-open）。
		takenRows, checkErr := tx.QueryContext(ctx, usernameTakenSQL, update.UsernameNormalized, update.UserID)
		if checkErr == nil {
			taken := takenRows.Next()
			_ = takenRows.Close()
			if taken {
				return false, profile.ErrUsernameTaken
			}
		}
		return false, fmt.Errorf("%w: %w", profile.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("%w: %w", profile.ErrStoreUnavailable, err)
	}
	if affected == 0 {
		return false, nil
	}
	if affected != 1 {
		return false, fmt.Errorf("%w: 更名影响行数异常", profile.ErrStoreUnavailable)
	}
	return true, nil
}
