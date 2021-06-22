// Package sqlite 实现 internal/oidc.UserInfoSource 的 SQLite 生产仓储。
//
// 只读 users/user_emails 的展示与验证状态字段；不读取密码、MFA 秘密、会话、
// 凭证或恢复材料。表结构由既有迁移创建（本包不拥有迁移）。
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/oidc"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

// userInfoSQL 一次读取用户资料与最近一个已验证邮箱；邮箱缺失时返回 NULL。
const userInfoSQL = `SELECT u.id,u.username,u.nickname,u.language,u.timezone,u.status,
u.updated_at_ms,e.email
FROM users u
LEFT JOIN user_emails e ON e.user_id=u.id AND e.verified_at_ms IS NOT NULL
WHERE u.id=?
ORDER BY COALESCE(e.verified_at_ms,0) DESC LIMIT 1`

// Store 是 oidc.UserInfoSource 的 SQLite 实现。
type Store struct {
	store *storagesqlite.Store
}

// New 包装已迁移的 SQLite 存储。
func New(store *storagesqlite.Store) (*Store, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", oidc.ErrOptionsInvalid)
	}
	return &Store{store: store}, nil
}

var _ oidc.UserInfoSource = (*Store)(nil)

// LoadUserInfo 读取用户资料快照；不存在返回 found=false。
func (s *Store) LoadUserInfo(ctx context.Context, userID string) (oidc.UserInfoRecord, bool, error) {
	rows, err := s.store.QueryContext(ctx, userInfoSQL, userID)
	if err != nil {
		return oidc.UserInfoRecord{}, false, fmt.Errorf("%w: %w", oidc.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return oidc.UserInfoRecord{}, false, fmt.Errorf("%w: %w", oidc.ErrStoreUnavailable, err)
		}
		return oidc.UserInfoRecord{}, false, nil
	}
	var record oidc.UserInfoRecord
	var email sql.NullString
	var updatedAt int64
	if err := rows.Scan(&record.UserID, &record.Username, &record.Nickname, &record.Language,
		&record.Timezone, &record.Status, &updatedAt, &email); err != nil {
		return oidc.UserInfoRecord{}, false, fmt.Errorf("%w: %w", oidc.ErrStoreUnavailable, err)
	}
	record.UpdatedAt = time.UnixMilli(updatedAt).UTC()
	if email.Valid && email.String != "" {
		record.Email = email.String
		record.EmailVerified = true
	}
	return record, true, nil
}
