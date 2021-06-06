// Package sqlite 实现 internal/avatar.Store 的 SQLite 生产仓储。
//
// 表结构由 migrations/0017_avatar.sql 创建；本包不执行迁移、不拥有数据库连接、
// 不读写头像文件。当前头像引用同时存在于 users.avatar_ref 与 avatars 行，二者
// 只在调用方的审计事务内一起更新，保证“引用/记录/文件”不会部分成立。
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/avatar"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

const selectAvatarColumns = `a.id,a.user_id,a.storage_key,a.media_type,a.byte_size,
a.width,a.height,a.content_sha256,a.source_kind,a.created_at_ms,a.updated_at_ms,u.row_version`

const currentAvatarSQL = `SELECT ` + selectAvatarColumns + `
FROM avatars a JOIN users u ON u.id=a.user_id WHERE a.user_id=?`

const avatarByIDSQL = `SELECT ` + selectAvatarColumns + `
FROM avatars a JOIN users u ON u.id=a.user_id WHERE a.id=?`

const userStateSQL = `SELECT is_root,row_version,COALESCE(avatar_ref,'') FROM users WHERE id=?`

const updateAvatarRefSQL = `UPDATE users SET avatar_ref=?,row_version=row_version+1,updated_at_ms=?
WHERE id=? AND row_version=?`

const clearAvatarRefSQL = `UPDATE users SET avatar_ref=NULL,row_version=row_version+1,updated_at_ms=?
WHERE id=? AND row_version=?`

const deleteAvatarByUserSQL = `DELETE FROM avatars WHERE user_id=?`

const insertAvatarSQL = `INSERT INTO avatars(id,user_id,storage_key,media_type,byte_size,
width,height,content_sha256,source_kind,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?,?,?,?,?,?)`

const listStorageKeysSQL = `SELECT storage_key FROM avatars`

// Store 是 avatar.Store 的 SQLite 实现。
type Store struct {
	store *storagesqlite.Store
}

// New 包装已迁移的 SQLite 存储。
func New(store *storagesqlite.Store) (*Store, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", avatar.ErrOptionsInvalid)
	}
	return &Store{store: store}, nil
}

var _ avatar.Store = (*Store)(nil)

// GetUserState 读取用户是否存在、root 标记、行版本与当前头像引用。
func (s *Store) GetUserState(ctx context.Context, userID string) (avatar.UserState, error) {
	rows, err := s.store.QueryContext(ctx, userStateSQL, userID)
	if err != nil {
		return avatar.UserState{}, fmt.Errorf("%w: %w", avatar.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return avatar.UserState{UserID: userID}, nil
	}
	var isRoot int
	var state avatar.UserState
	state.UserID = userID
	if err := rows.Scan(&isRoot, &state.RowVersion, &state.AvatarRef); err != nil {
		return avatar.UserState{}, fmt.Errorf("%w: %w", avatar.ErrStoreUnavailable, err)
	}
	if err := rows.Err(); err != nil {
		return avatar.UserState{}, fmt.Errorf("%w: %w", avatar.ErrStoreUnavailable, err)
	}
	state.Exists = true
	state.IsRoot = isRoot == 1
	return state, nil
}

// GetAvatar 按头像 ID 读取记录。
func (s *Store) GetAvatar(ctx context.Context, avatarID string) (avatar.AvatarRecord, bool, error) {
	return s.queryAvatar(ctx, nil, avatarByIDSQL, avatarID)
}

// Current 读取用户当前头像记录。
func (s *Store) Current(ctx context.Context, userID string) (avatar.AvatarRecord, bool, error) {
	return s.queryAvatar(ctx, nil, currentAvatarSQL, userID)
}

// currentTx 在审计事务内读取用户当前头像记录。
func (s *Store) currentTx(ctx context.Context, tx audit.Tx, userID string) (avatar.AvatarRecord, bool, error) {
	return s.queryAvatar(ctx, tx, currentAvatarSQL, userID)
}

// queryAvatar 执行单行查询；tx 非空时在事务内读取。
func (s *Store) queryAvatar(ctx context.Context, tx audit.Tx, query string, argument string) (avatar.AvatarRecord, bool, error) {
	var rows *sql.Rows
	var err error
	if tx != nil {
		rows, err = tx.QueryContext(ctx, query, argument)
	} else {
		rows, err = s.store.QueryContext(ctx, query, argument)
	}
	if err != nil {
		return avatar.AvatarRecord{}, false, fmt.Errorf("%w: %w", avatar.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if rowsErr := rows.Err(); rowsErr != nil {
			return avatar.AvatarRecord{}, false, fmt.Errorf("%w: %w", avatar.ErrStoreUnavailable, rowsErr)
		}
		return avatar.AvatarRecord{}, false, nil
	}
	var record avatar.AvatarRecord
	var createdAt, updatedAt int64
	if err := rows.Scan(&record.ID, &record.UserID, &record.StorageKey, &record.MediaType,
		&record.ByteSize, &record.Width, &record.Height, &record.SHA256,
		&record.SourceKind, &createdAt, &updatedAt, &record.RowVersion); err != nil {
		return avatar.AvatarRecord{}, false, fmt.Errorf("%w: %w", avatar.ErrStoreUnavailable, err)
	}
	record.CreatedAt = time.UnixMilli(createdAt).UTC()
	record.UpdatedAt = time.UnixMilli(updatedAt).UTC()
	return record, true, nil
}

// ReplaceTx 条件替换头像：先确认用户行版本并更新引用，再删除旧头像行并插入新行。
// 行版本不匹配返回 ok=false 且不产生任何修改（由调用方回滚事务）。
func (s *Store) ReplaceTx(ctx context.Context, tx audit.Tx, replace avatar.ReplaceRecord) (avatar.AvatarRecord, bool, error) {
	if tx == nil {
		return avatar.AvatarRecord{}, false, fmt.Errorf("%w: 审计事务为空", avatar.ErrOptionsInvalid)
	}
	previous, hadPrevious, err := s.currentTx(ctx, tx, replace.UserID)
	if err != nil {
		return avatar.AvatarRecord{}, false, err
	}
	result, err := tx.ExecContext(ctx, updateAvatarRefSQL, replace.New.ID,
		replace.Now.UTC().UnixMilli(), replace.UserID, replace.ExpectedRowVersion)
	if err != nil {
		return avatar.AvatarRecord{}, false, fmt.Errorf("%w: %w", avatar.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return avatar.AvatarRecord{}, false, fmt.Errorf("%w: %w", avatar.ErrStoreUnavailable, err)
	}
	if affected == 0 {
		return avatar.AvatarRecord{}, false, nil
	}
	if affected != 1 {
		return avatar.AvatarRecord{}, false, fmt.Errorf("%w: 头像引用更新影响行数异常", avatar.ErrStoreUnavailable)
	}
	if hadPrevious {
		if err := s.deleteAvatarRow(ctx, tx, replace.UserID); err != nil {
			return avatar.AvatarRecord{}, false, err
		}
	}
	if _, err := tx.ExecContext(ctx, insertAvatarSQL, replace.New.ID, replace.New.UserID,
		replace.New.StorageKey, replace.New.MediaType, replace.New.ByteSize, replace.New.Width,
		replace.New.Height, replace.New.SHA256, replace.New.SourceKind,
		replace.New.CreatedAt.UTC().UnixMilli(), replace.New.UpdatedAt.UTC().UnixMilli()); err != nil {
		return avatar.AvatarRecord{}, false, fmt.Errorf("%w: %w", avatar.ErrStoreUnavailable, err)
	}
	return previous, true, nil
}

// RemoveTx 条件清除头像引用并删除头像行；行版本不匹配返回 ok=false。
func (s *Store) RemoveTx(ctx context.Context, tx audit.Tx, userID string, expectedRowVersion int64,
	now time.Time) (avatar.AvatarRecord, bool, error) {
	if tx == nil {
		return avatar.AvatarRecord{}, false, fmt.Errorf("%w: 审计事务为空", avatar.ErrOptionsInvalid)
	}
	previous, hadPrevious, err := s.currentTx(ctx, tx, userID)
	if err != nil {
		return avatar.AvatarRecord{}, false, err
	}
	result, err := tx.ExecContext(ctx, clearAvatarRefSQL, now.UTC().UnixMilli(), userID, expectedRowVersion)
	if err != nil {
		return avatar.AvatarRecord{}, false, fmt.Errorf("%w: %w", avatar.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return avatar.AvatarRecord{}, false, fmt.Errorf("%w: %w", avatar.ErrStoreUnavailable, err)
	}
	if affected == 0 {
		return avatar.AvatarRecord{}, false, nil
	}
	if affected != 1 {
		return avatar.AvatarRecord{}, false, fmt.Errorf("%w: 头像引用清除影响行数异常", avatar.ErrStoreUnavailable)
	}
	if hadPrevious {
		if err := s.deleteAvatarRow(ctx, tx, userID); err != nil {
			return avatar.AvatarRecord{}, false, err
		}
	}
	return previous, true, nil
}

// deleteAvatarRow 删除用户的头像行；唯一约束保证每用户至多一行。
func (s *Store) deleteAvatarRow(ctx context.Context, tx audit.Tx, userID string) error {
	if _, err := tx.ExecContext(ctx, deleteAvatarByUserSQL, userID); err != nil {
		return fmt.Errorf("%w: %w", avatar.ErrStoreUnavailable, err)
	}
	return nil
}

// ListStorageKeys 返回数据库中仍被引用的全部存储键。
func (s *Store) ListStorageKeys(ctx context.Context) ([]string, error) {
	rows, err := s.store.QueryContext(ctx, listStorageKeysSQL)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", avatar.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	keys := make([]string, 0, 16)
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, fmt.Errorf("%w: %w", avatar.ErrStoreUnavailable, err)
		}
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", avatar.ErrStoreUnavailable, err)
	}
	return keys, nil
}
