// Package sqlite 实现 internal/account.Store 的 SQLite 生产仓储。
//
// 表结构来自 migrations/0001_identity_and_scope_core.sql 的 users 表；本包不执行
// 迁移，调用方应在启动或测试中先应用全部迁移。本包不拥有数据库连接：
// *storage/sqlite.Store 的关闭由外层负责。构造后不可变，可被多个 goroutine
// 并发使用。
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

const (
	// insertUserSQL 使用 ON CONFLICT(username_normalized) DO NOTHING 把并发重名
	// 转成受影响行数 0，而不依赖驱动错误文本；主键冲突（随机 ID 重复，概率可忽略）
	// 仍会返回错误而不会被误判为用户名冲突。
	insertUserSQL = `INSERT INTO users(
id,username,username_normalized,nickname,biography,avatar_ref,language,timezone,status,is_root,security_version,row_version,created_at_ms,updated_at_ms
) VALUES(?,?,?,?,?,NULL,?,?,?,0,1,1,?,?)
ON CONFLICT(username_normalized) DO NOTHING`

	selectUserColumns = `id,username,username_normalized,nickname,biography,language,timezone,status,row_version,created_at_ms,updated_at_ms`

	selectUserByIDSQL = `SELECT ` + selectUserColumns + ` FROM users WHERE id=?`
)

// Store 是 account.Store 的 SQLite 实现。
type Store struct {
	store *storagesqlite.Store
}

// New 包装一个已打开并完成迁移的 SQLite 存储；store 为空时返回
// account.ErrOptionsInvalid，不会创建替代连接。
func New(store *storagesqlite.Store) (*Store, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", account.ErrOptionsInvalid)
	}
	return &Store{store: store}, nil
}

// 编译期确认实现 account.Store。
var _ account.Store = (*Store)(nil)

// CreateUser 在调用方提供的审计事务中插入新用户。规范化用户名冲突返回
// account.ErrUsernameTaken；其他存储失败返回 account.ErrStoreUnavailable。
func (s *Store) CreateUser(ctx context.Context, tx audit.Tx, user account.User) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", account.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, insertUserSQL,
		user.ID,
		user.Username,
		user.UsernameNormalized,
		user.Nickname,
		user.Biography,
		user.Language,
		user.Timezone,
		string(user.Status),
		user.CreatedAt.UTC().UnixMilli(),
		user.UpdatedAt.UTC().UnixMilli(),
	)
	if err != nil {
		return fmt.Errorf("%w: %w", account.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: %w", account.ErrStoreUnavailable, err)
	}
	if affected == 0 {
		return account.ErrUsernameTaken
	}
	if affected != 1 {
		return fmt.Errorf("%w: 插入用户影响行数异常", account.ErrStoreUnavailable)
	}
	return nil
}

// GetUser 按稳定用户 ID 查询账户快照。不存在返回 account.ErrUserNotFound；其他
// 存储错误返回 account.ErrStoreUnavailable（不泄露驱动错误文本）。
func (s *Store) GetUser(ctx context.Context, id string) (account.User, error) {
	rows, err := s.store.QueryContext(ctx, selectUserByIDSQL, id)
	if err != nil {
		return account.User{}, fmt.Errorf("%w: %w", account.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return account.User{}, fmt.Errorf("%w: %w", account.ErrStoreUnavailable, err)
		}
		return account.User{}, account.ErrUserNotFound
	}
	user, err := scanUser(rows)
	if err != nil {
		return account.User{}, err
	}
	if err := rows.Err(); err != nil {
		return account.User{}, fmt.Errorf("%w: %w", account.ErrStoreUnavailable, err)
	}
	return user, nil
}

// ListUsers 执行有限分页查询。Sort 必须是 account.SortField 白名单值，仓储再次
// 校验并映射为固定列名，绝不拼接调用方字符串。查询同时取 Limit+1 行用于判断
// HasMore。
func (s *Store) ListUsers(ctx context.Context, query account.ListQuery) ([]account.User, bool, error) {
	column, ok := sortColumn(query.Sort)
	if !ok {
		return nil, false, fmt.Errorf("%w: 排序字段不在允许列表内", account.ErrInvalidRequest)
	}
	direction := "ASC"
	if query.Descending {
		direction = "DESC"
	}
	statement := `SELECT ` + selectUserColumns + ` FROM users`
	args := make([]any, 0, 4)
	if query.Status != "" {
		statement += ` WHERE status=?`
		args = append(args, string(query.Status))
	}
	// 列名与方向来自固定白名单与布尔判断，不包含用户输入原文。
	statement += ` ORDER BY ` + column + ` ` + direction + `, id ` + direction + ` LIMIT ? OFFSET ?`
	fetchLimit := query.Limit + 1
	args = append(args, fetchLimit, query.Offset)

	rows, err := s.store.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %w", account.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	users := make([]account.User, 0, query.Limit+1)
	for rows.Next() {
		user, scanErr := scanUser(rows)
		if scanErr != nil {
			return nil, false, scanErr
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("%w: %w", account.ErrStoreUnavailable, err)
	}
	hasMore := false
	if len(users) > query.Limit {
		hasMore = true
		users = users[:query.Limit]
	}
	return users, hasMore, nil
}

// sortColumn 把排序枚举映射为固定 SQL 列名；未知值返回 false。
func sortColumn(sort account.SortField) (string, bool) {
	switch sort {
	case account.SortID:
		return "id", true
	case account.SortUsername:
		return "username_normalized", true
	case account.SortCreatedAt:
		return "created_at_ms", true
	case account.SortUpdatedAt:
		return "updated_at_ms", true
	default:
		return "", false
	}
}

// scanUser 读取一行用户快照并做基本一致性检查；状态/时间异常按存储故障处理，
// 不把损坏数据当作正常用户返回。
func scanUser(rows *sql.Rows) (account.User, error) {
	var (
		user        account.User
		status      string
		createdAtMS int64
		updatedAtMS int64
	)
	if err := rows.Scan(
		&user.ID,
		&user.Username,
		&user.UsernameNormalized,
		&user.Nickname,
		&user.Biography,
		&user.Language,
		&user.Timezone,
		&status,
		&user.RowVersion,
		&createdAtMS,
		&updatedAtMS,
	); err != nil {
		return account.User{}, fmt.Errorf("%w: %w", account.ErrStoreUnavailable, err)
	}
	user.Status = account.Status(status)
	if !user.Status.Valid() {
		return account.User{}, fmt.Errorf("%w: 用户状态数据无效", account.ErrStoreUnavailable)
	}
	if !account.ValidUserID(user.ID) {
		return account.User{}, fmt.Errorf("%w: 用户 ID 数据格式无效", account.ErrStoreUnavailable)
	}
	user.CreatedAt = timeFromUnixMilli(createdAtMS)
	user.UpdatedAt = timeFromUnixMilli(updatedAtMS)
	return user, nil
}

// timeFromUnixMilli 把数据库毫秒时间转成 UTC 时间。
func timeFromUnixMilli(value int64) time.Time {
	return time.UnixMilli(value).UTC()
}
