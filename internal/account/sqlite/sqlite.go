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
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/search"
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

	selectUserColumns = `id,username,username_normalized,nickname,biography,language,timezone,status,row_version,security_version,valid_from_ms,valid_until_ms,created_at_ms,updated_at_ms`

	selectUserByIDSQL = `SELECT ` + selectUserColumns + ` FROM users WHERE id=?`

	selectUserByUsernameSQL = `SELECT ` + selectUserColumns + ` FROM users WHERE username_normalized=?`

	selectUserStateSQL = `SELECT ` + selectUserColumns + `,is_root FROM users WHERE id=?`

	updateUserStateSQL = `UPDATE users SET status=?, security_version=security_version+?, row_version=row_version+1, updated_at_ms=?
WHERE id=? AND status=? AND row_version=? AND is_root=0`

	previewDeletionCountsSQL = `SELECT
(SELECT COUNT(*) FROM app_memberships WHERE user_id=?),
(SELECT COUNT(*) FROM user_roles WHERE user_id=?),
(SELECT COUNT(*) FROM group_members WHERE user_id=?),
(SELECT COUNT(*) FROM one_time_credentials WHERE subject_id=?),
(SELECT COUNT(*) FROM applications WHERE owner_user_id=?)`

	deleteCredentialsSQL    = `DELETE FROM one_time_credentials WHERE subject_id=?`
	deleteUserRolesSQL      = `DELETE FROM user_roles WHERE user_id=?`
	deleteGroupMembersSQL   = `DELETE FROM group_members WHERE user_id=?`
	deleteAppMembershipsSQL = `DELETE FROM app_memberships WHERE user_id=?`
	deleteUserSQL           = `DELETE FROM users WHERE id=? AND status='pending_delete' AND row_version=? AND is_root=0`
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

// GetUserByUsername 按规范化用户名查询账户快照。调用方负责先做 NFKC + 大小写
// 折叠；仓储只做精确匹配，避免在 SQL 中复制规范化规则。不存在返回
// account.ErrUserNotFound，其他存储错误返回 account.ErrStoreUnavailable。
func (s *Store) GetUserByUsername(ctx context.Context, normalizedUsername string) (account.User, error) {
	rows, err := s.store.QueryContext(ctx, selectUserByUsernameSQL, normalizedUsername)
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
//
// 可选的字面搜索与状态/排序/分页组合在同一 WHERE 中，且在授权范围过滤之后执行；
// 只用参数化 LIKE（ESCAPE '!'），模式由 internal/search 转义 `%`、`_`、`\`、`[`、
// `]` 与 ESCAPE 字符自身，用户输入不会变成 SQL 模式或注入。用户名用已规范化的
// username_normalized 列匹配（复用 NFKC + 大小写折叠口径，全角/大小写按同一字面）；
// 昵称用 LOWER(nickname) 按方言大小写规则匹配（SQLite 只折叠 ASCII，中文不受影响）。
func (s *Store) ListUsers(ctx context.Context, query account.ListQuery) ([]account.User, bool, error) {
	column, ok := sortColumn(query.Sort)
	if !ok {
		return nil, false, fmt.Errorf("%w: 排序字段不在允许列表内", account.ErrInvalidRequest)
	}
	direction := "ASC"
	if query.Descending {
		direction = "DESC"
	}
	conditions := make([]string, 0, 2)
	args := make([]any, 0, 6)
	if query.Status != "" {
		conditions = append(conditions, `status=?`)
		args = append(args, string(query.Status))
	}
	if query.Search != "" {
		pattern := search.ContainsPattern(query.Search)
		if pattern != "" {
			searchClauses := make([]string, 0, len(query.SearchFields))
			for _, field := range query.SearchFields {
				switch field {
				case account.UserSearchUsername:
					searchClauses = append(searchClauses, `username_normalized LIKE ? ESCAPE '!'`)
					args = append(args, pattern)
				case account.UserSearchNickname:
					searchClauses = append(searchClauses, `LOWER(nickname) LIKE ? ESCAPE '!'`)
					args = append(args, pattern)
				default:
					// 已由服务层白名单校验；这里再次 fail-closed，不生成未知列。
					return nil, false, fmt.Errorf("%w: 搜索字段不在允许列表内",
						account.ErrInvalidRequest)
				}
			}
			if len(searchClauses) == 0 {
				return nil, false, fmt.Errorf("%w: 搜索字段为空", account.ErrInvalidRequest)
			}
			conditions = append(conditions, `(`+strings.Join(searchClauses, ` OR `)+`)`)
		}
	}
	statement := `SELECT ` + selectUserColumns + ` FROM users`
	if len(conditions) > 0 {
		statement += ` WHERE ` + strings.Join(conditions, ` AND `)
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

// GetUserState 返回账户快照与 is_root 受保护标记。
func (s *Store) GetUserState(ctx context.Context, id string) (account.StateSnapshot, error) {
	user, isRoot, err := s.queryUserState(ctx, id)
	if err != nil {
		return account.StateSnapshot{}, err
	}
	return account.StateSnapshot{User: user, IsRoot: isRoot}, nil
}

// PreviewDeletion 读取删除影响范围快照；不过滤受保护账户（调用方据 IsRoot 拒绝）。
func (s *Store) PreviewDeletion(ctx context.Context, id string) (account.DeletionPreview, error) {
	user, isRoot, err := s.queryUserState(ctx, id)
	if err != nil {
		return account.DeletionPreview{}, err
	}
	rows, err := s.store.QueryContext(ctx, previewDeletionCountsSQL, id, id, id, id, id)
	if err != nil {
		return account.DeletionPreview{}, fmt.Errorf("%w: %w", account.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	preview := account.DeletionPreview{
		UserID:          user.ID,
		Username:        user.Username,
		Status:          user.Status,
		RowVersion:      user.RowVersion,
		SecurityVersion: user.SecurityVersion,
		IsRoot:          isRoot,
	}
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return account.DeletionPreview{}, fmt.Errorf("%w: %w", account.ErrStoreUnavailable, err)
		}
		return account.DeletionPreview{}, account.ErrUserNotFound
	}
	if err := rows.Scan(
		&preview.AppMemberships,
		&preview.UserRoles,
		&preview.GroupMemberships,
		&preview.OneTimeCredentials,
		&preview.OwnedApplications,
	); err != nil {
		return account.DeletionPreview{}, fmt.Errorf("%w: %w", account.ErrStoreUnavailable, err)
	}
	if err := rows.Err(); err != nil {
		return account.DeletionPreview{}, fmt.Errorf("%w: %w", account.ErrStoreUnavailable, err)
	}
	return preview, nil
}

// ApplyStateChange 执行带状态与行版本条件的更新。条件不匹配（并发修改、状态变化
// 或 root 保护）返回 account.ErrStateConflict；调用方在事务内已做业务校验，这里
// 是最后一道原子防线。
func (s *Store) ApplyStateChange(ctx context.Context, tx audit.Tx, change account.StateChange) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", account.ErrOptionsInvalid)
	}
	bump := 0
	if change.BumpSecurityVersion {
		bump = 1
	}
	result, err := tx.ExecContext(ctx, updateUserStateSQL,
		string(change.NewStatus),
		bump,
		change.Now.UTC().UnixMilli(),
		change.UserID,
		string(change.ExpectedStatus),
		change.ExpectedRowVersion,
	)
	if err != nil {
		return fmt.Errorf("%w: %w", account.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: %w", account.ErrStoreUnavailable, err)
	}
	switch affected {
	case 1:
		return nil
	case 0:
		return account.ErrStateConflict
	default:
		return fmt.Errorf("%w: 状态更新影响行数异常", account.ErrStoreUnavailable)
	}
}

// ApplyValidityChange 在调用方审计事务内条件更新账户有效期：行版本 CAS 且
// is_root=0；受保护 root 或并发修改返回 account.ErrStateConflict，不留部分更新。
func (s *Store) ApplyValidityChange(ctx context.Context, tx audit.Tx,
	change account.ValidityChange) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", account.ErrOptionsInvalid)
	}
	const statement = `UPDATE users SET valid_from_ms=?, valid_until_ms=?,
row_version=row_version+1, updated_at_ms=?
WHERE id=? AND row_version=? AND is_root=0`
	result, err := tx.ExecContext(ctx, statement,
		optionalUnixMilli(change.ValidFrom), optionalUnixMilli(change.ValidUntil),
		change.Now.UTC().UnixMilli(), change.UserID, change.ExpectedRowVersion)
	if err != nil {
		return fmt.Errorf("%w: %w", account.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: %w", account.ErrStoreUnavailable, err)
	}
	if affected != 1 {
		return account.ErrStateConflict
	}
	return nil
}

// optionalUnixMilli 把可选 UTC 时间转换为可空毫秒参数。
func optionalUnixMilli(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UTC().UnixMilli()
}

// CompleteDeletion 在审计事务中按明确策略清理关联个人数据后删除用户行：
//   - 一次性凭证、应用成员关系、角色分配、用户组成员关系删除（属于账户个人
//     数据/关系，删除前计数已写入审计）；
//   - applications.owner_user_id 由外键 ON DELETE SET NULL 置空，应用记录保留；
//   - 安全审计历史不删除（无用户外键），保留脱敏快照；未来会话/令牌表尚未实现，
//     需消费 user.delete.complete 审计事件与禁用/删除请求时的 security_version
//     递增作为失效依据。
//
// 任一步失败整体回滚；最终 users 行条件删除影响 0 行返回 ErrStateConflict。
func (s *Store) CompleteDeletion(ctx context.Context, tx audit.Tx, request account.CompleteDeletionRequest) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", account.ErrOptionsInvalid)
	}
	for _, statement := range []struct {
		query string
		arg   string
	}{
		{deleteCredentialsSQL, request.UserID},
		{deleteUserRolesSQL, request.UserID},
		{deleteGroupMembersSQL, request.UserID},
		{deleteAppMembershipsSQL, request.UserID},
	} {
		if _, err := tx.ExecContext(ctx, statement.query, statement.arg); err != nil {
			return fmt.Errorf("%w: %w", account.ErrStoreUnavailable, err)
		}
	}
	result, err := tx.ExecContext(ctx, deleteUserSQL, request.UserID, request.ExpectedRowVersion)
	if err != nil {
		return fmt.Errorf("%w: %w", account.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: %w", account.ErrStoreUnavailable, err)
	}
	if affected == 0 {
		return account.ErrStateConflict
	}
	if affected != 1 {
		return fmt.Errorf("%w: 删除用户影响行数异常", account.ErrStoreUnavailable)
	}
	return nil
}

// queryUserState 读取一行用户状态快照（含 is_root）。
func (s *Store) queryUserState(ctx context.Context, id string) (account.User, bool, error) {
	rows, err := s.store.QueryContext(ctx, selectUserStateSQL, id)
	if err != nil {
		return account.User{}, false, fmt.Errorf("%w: %w", account.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return account.User{}, false, fmt.Errorf("%w: %w", account.ErrStoreUnavailable, err)
		}
		return account.User{}, false, account.ErrUserNotFound
	}
	user, isRoot, err := scanUserState(rows, true)
	if err != nil {
		return account.User{}, false, err
	}
	if err := rows.Err(); err != nil {
		return account.User{}, false, fmt.Errorf("%w: %w", account.ErrStoreUnavailable, err)
	}
	return user, isRoot, nil
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
	user, _, err := scanUserState(rows, false)
	return user, err
}

// scanUserState 读取用户行；withRoot=true 时同一行多读一个 is_root 整数列。
func scanUserState(rows *sql.Rows, withRoot bool) (account.User, bool, error) {
	var (
		user         account.User
		status       string
		createdAtMS  int64
		updatedAtMS  int64
		validFromMS  sql.NullInt64
		validUntilMS sql.NullInt64
		isRoot       int64
	)
	targets := []any{
		&user.ID,
		&user.Username,
		&user.UsernameNormalized,
		&user.Nickname,
		&user.Biography,
		&user.Language,
		&user.Timezone,
		&status,
		&user.RowVersion,
		&user.SecurityVersion,
		&validFromMS,
		&validUntilMS,
		&createdAtMS,
		&updatedAtMS,
	}
	if withRoot {
		targets = append(targets, &isRoot)
	}
	if err := rows.Scan(targets...); err != nil {
		return account.User{}, false, fmt.Errorf("%w: %w", account.ErrStoreUnavailable, err)
	}
	user.Status = account.Status(status)
	if !user.Status.Valid() {
		return account.User{}, false, fmt.Errorf("%w: 用户状态数据无效", account.ErrStoreUnavailable)
	}
	if !account.ValidUserID(user.ID) {
		return account.User{}, false, fmt.Errorf("%w: 用户 ID 数据格式无效", account.ErrStoreUnavailable)
	}
	user.CreatedAt = timeFromUnixMilli(createdAtMS)
	user.UpdatedAt = timeFromUnixMilli(updatedAtMS)
	user.ValidFrom = optionalTimeFromUnixMilli(validFromMS)
	user.ValidUntil = optionalTimeFromUnixMilli(validUntilMS)
	return user, isRoot == 1, nil
}

// optionalTimeFromUnixMilli 把可空毫秒时间转成 UTC 时间；NULL 表示该端不限制。
func optionalTimeFromUnixMilli(value sql.NullInt64) *time.Time {
	if !value.Valid {
		return nil
	}
	converted := timeFromUnixMilli(value.Int64)
	return &converted
}

// timeFromUnixMilli 把数据库毫秒时间转成 UTC 时间。
func timeFromUnixMilli(value int64) time.Time {
	return time.UnixMilli(value).UTC()
}
