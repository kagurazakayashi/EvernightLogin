// Package sqlite 实现 internal/group.Store 的 SQLite 生产仓储。
//
// 表结构来自 migrations/0001_identity_and_scope_core.sql 的 user_groups、
// group_members（以及未来 group_roles）；本包不执行迁移。组作用范围由 scope_id
// 引用 scopes(id)：系统范围为固定 "system"，应用范围 ID 与应用 ID 相同。
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/group"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

const (
	groupColumns = `g.id,g.scope_id,g.group_key,g.name,g.description,g.created_at_ms,g.updated_at_ms`

	selectGroupByIDSQL = `SELECT ` + groupColumns + ` FROM user_groups g WHERE g.id=?`

	selectGroupScopeSQL = `SELECT scope_id FROM user_groups WHERE id=?`

	insertGroupSQL = `INSERT INTO user_groups(id,scope_id,group_key,name,description,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?,?)
ON CONFLICT(scope_id,group_key) DO NOTHING`

	updateGroupSQL = `UPDATE user_groups SET name=?,description=?,updated_at_ms=? WHERE id=?`

	deleteGroupSQL = `DELETE FROM user_groups WHERE id=?`

	selectSystemScopeSQL = `SELECT 1 FROM scopes WHERE id='system' AND kind='system'`

	selectApplicationScopeSQL = `SELECT a.status FROM applications a
JOIN scopes s ON s.id=? AND s.kind='application' AND s.app_id=a.id WHERE a.id=?`

	selectMembersSQL = `SELECT group_id,user_id,created_at_ms FROM group_members WHERE group_id=?
ORDER BY user_id ASC LIMIT ? OFFSET ?`

	deleteMemberSQL = `DELETE FROM group_members WHERE group_id=? AND user_id=?`

	insertMemberSystemSQL = `INSERT INTO group_members(group_id,user_id,created_at_ms)
SELECT ?,?,? WHERE EXISTS(SELECT 1 FROM users WHERE id=? AND status='active')
ON CONFLICT(group_id,user_id) DO NOTHING`

	insertMemberApplicationSQL = `INSERT INTO group_members(group_id,user_id,created_at_ms)
SELECT ?,?,? WHERE EXISTS(SELECT 1 FROM users WHERE id=? AND status='active')
AND EXISTS(SELECT 1 FROM app_memberships WHERE app_id=? AND user_id=? AND status='active')
AND EXISTS(SELECT 1 FROM applications WHERE id=? AND status='active')
ON CONFLICT(group_id,user_id) DO NOTHING`
)

// Store 是 group.Store 的 SQLite 实现。
type Store struct {
	store *storagesqlite.Store
}

// New 包装已打开且完成迁移的 SQLite 存储。
func New(store *storagesqlite.Store) (*Store, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", group.ErrOptionsInvalid)
	}
	return &Store{store: store}, nil
}

// 编译期确认实现 group.Store。
var _ group.Store = (*Store)(nil)

// GetScope 读取作用范围并确认应用状态；应用 scope 必须真实存在且 app_id 一致。
func (s *Store) GetScope(ctx context.Context, scopeID string) (group.ScopeInfo, error) {
	kind, applicationID, err := group.ParseScope(scopeID)
	if err != nil {
		return group.ScopeInfo{}, err
	}
	if kind == group.ScopeKindSystem {
		rows, queryErr := s.store.QueryContext(ctx, selectSystemScopeSQL)
		if queryErr != nil {
			return group.ScopeInfo{}, fmt.Errorf("%w: %w", group.ErrStoreUnavailable, queryErr)
		}
		defer rows.Close()
		if !rows.Next() {
			return group.ScopeInfo{}, group.ErrScopeInvalid
		}
		return group.ScopeInfo{ScopeID: group.ScopeSystem, Kind: group.ScopeKindSystem}, nil
	}
	rows, queryErr := s.store.QueryContext(ctx, selectApplicationScopeSQL, scopeID, applicationID)
	if queryErr != nil {
		return group.ScopeInfo{}, fmt.Errorf("%w: %w", group.ErrStoreUnavailable, queryErr)
	}
	defer rows.Close()
	if !rows.Next() {
		return group.ScopeInfo{}, group.ErrScopeInvalid
	}
	var status string
	if err := rows.Scan(&status); err != nil {
		return group.ScopeInfo{}, fmt.Errorf("%w: %w", group.ErrStoreUnavailable, err)
	}
	return group.ScopeInfo{
		ScopeID:           scopeID,
		Kind:              group.ScopeKindApplication,
		ApplicationID:     applicationID,
		ApplicationActive: status == string(app.StatusActive),
	}, nil
}

// CreateGroup 在审计事务中插入组；同一范围 group_key 冲突返回 ErrGroupKeyTaken。
func (s *Store) CreateGroup(ctx context.Context, tx audit.Tx, record group.Group) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", group.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, insertGroupSQL,
		record.ID,
		record.ScopeID,
		record.GroupKey,
		record.Name,
		record.Description,
		record.CreatedAt.UTC().UnixMilli(),
		record.UpdatedAt.UTC().UnixMilli(),
	)
	if err != nil {
		return fmt.Errorf("%w: %w", group.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: %w", group.ErrStoreUnavailable, err)
	}
	if affected == 0 {
		return group.ErrGroupKeyTaken
	}
	if affected != 1 {
		return fmt.Errorf("%w: 插入用户组影响行数异常", group.ErrStoreUnavailable)
	}
	return nil
}

// GetGroup 按稳定 ID 读取组。
func (s *Store) GetGroup(ctx context.Context, id string) (group.Group, error) {
	rows, err := s.store.QueryContext(ctx, selectGroupByIDSQL, id)
	if err != nil {
		return group.Group{}, fmt.Errorf("%w: %w", group.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return group.Group{}, fmt.Errorf("%w: %w", group.ErrStoreUnavailable, err)
		}
		return group.Group{}, group.ErrGroupNotFound
	}
	record, err := scanGroup(rows)
	if err != nil {
		return group.Group{}, err
	}
	return record, rows.Err()
}

// GetGroupScope 只读取组的作用范围，供服务先鉴权后读取完整记录。
func (s *Store) GetGroupScope(ctx context.Context, id string) (string, error) {
	rows, err := s.store.QueryContext(ctx, selectGroupScopeSQL, id)
	if err != nil {
		return "", fmt.Errorf("%w: %w", group.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return "", fmt.Errorf("%w: %w", group.ErrStoreUnavailable, err)
		}
		return "", group.ErrGroupNotFound
	}
	var scopeID string
	if err := rows.Scan(&scopeID); err != nil {
		return "", fmt.Errorf("%w: %w", group.ErrStoreUnavailable, err)
	}
	return scopeID, rows.Err()
}

// ListGroups 执行可管理范围内的分页查询；排序固定为创建时间与 ID，拒绝任意列。
func (s *Store) ListGroups(ctx context.Context, query group.ListQuery) ([]group.Group, bool, error) {
	statement := `SELECT ` + groupColumns + ` FROM user_groups g`
	conditions := make([]string, 0, 2)
	args := make([]any, 0, 8)
	if query.ScopeFilter != "" {
		conditions = append(conditions, "g.scope_id=?")
		args = append(args, query.ScopeFilter)
	} else if !query.AllScopes {
		if len(query.ScopeIDs) == 0 {
			return []group.Group{}, false, nil
		}
		placeholders := make([]string, len(query.ScopeIDs))
		for index, scopeID := range query.ScopeIDs {
			placeholders[index] = "?"
			args = append(args, scopeID)
		}
		conditions = append(conditions, "g.scope_id IN ("+strings.Join(placeholders, ",")+")")
	}
	if len(conditions) > 0 {
		statement += ` WHERE ` + strings.Join(conditions, " AND ")
	}
	statement += ` ORDER BY g.created_at_ms ASC, g.id ASC LIMIT ? OFFSET ?`
	args = append(args, query.Limit+1, query.Offset)
	rows, err := s.store.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %w", group.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	groups := make([]group.Group, 0, query.Limit+1)
	for rows.Next() {
		record, scanErr := scanGroup(rows)
		if scanErr != nil {
			return nil, false, scanErr
		}
		groups = append(groups, record)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("%w: %w", group.ErrStoreUnavailable, err)
	}
	hasMore := false
	if len(groups) > query.Limit {
		hasMore = true
		groups = groups[:query.Limit]
	}
	return groups, hasMore, nil
}

// UpdateGroup 更新显示名称与说明；scope/group_key 不在 SQL 中，无法被转移。
func (s *Store) UpdateGroup(ctx context.Context, tx audit.Tx, id, name, description string, now time.Time) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", group.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, updateGroupSQL, name, description, now.UTC().UnixMilli(), id)
	if err != nil {
		return fmt.Errorf("%w: %w", group.ErrStoreUnavailable, err)
	}
	return checkAffected(result, group.ErrGroupNotFound)
}

// DeleteGroup 删除组记录；group_members 与 group_roles 由外键级联删除，用户与
// 安全审计历史保留。
func (s *Store) DeleteGroup(ctx context.Context, tx audit.Tx, id string) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", group.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, deleteGroupSQL, id)
	if err != nil {
		return fmt.Errorf("%w: %w", group.ErrStoreUnavailable, err)
	}
	return checkAffected(result, group.ErrGroupNotFound)
}

// ListMembers 分页读取组成员（按 user_id 稳定排序）。
func (s *Store) ListMembers(ctx context.Context, groupID string, limit, offset int) ([]group.Member, bool, error) {
	rows, err := s.store.QueryContext(ctx, selectMembersSQL, groupID, limit+1, offset)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %w", group.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	members := make([]group.Member, 0, limit+1)
	for rows.Next() {
		var member group.Member
		var createdAtMS int64
		if err := rows.Scan(&member.GroupID, &member.UserID, &createdAtMS); err != nil {
			return nil, false, fmt.Errorf("%w: %w", group.ErrStoreUnavailable, err)
		}
		member.CreatedAt = time.UnixMilli(createdAtMS).UTC()
		members = append(members, member)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("%w: %w", group.ErrStoreUnavailable, err)
	}
	hasMore := false
	if len(members) > limit {
		hasMore = true
		members = members[:limit]
	}
	return members, hasMore, nil
}

// ExistingMembers 返回请求用户中已属于该组的用户 ID；用于幂等语义。
func (s *Store) ExistingMembers(ctx context.Context, groupID string, userIDs []string) ([]string, error) {
	if len(userIDs) == 0 {
		return nil, nil
	}
	placeholders := make([]string, len(userIDs))
	args := make([]any, 0, len(userIDs)+1)
	args = append(args, groupID)
	for index, userID := range userIDs {
		placeholders[index] = "?"
		args = append(args, userID)
	}
	rows, err := s.store.QueryContext(ctx,
		`SELECT user_id FROM group_members WHERE group_id=? AND user_id IN (`+strings.Join(placeholders, ",")+`)`, args...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", group.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	existing := make([]string, 0, len(userIDs))
	for rows.Next() {
		var userID string
		if err := rows.Scan(&userID); err != nil {
			return nil, fmt.Errorf("%w: %w", group.ErrStoreUnavailable, err)
		}
		existing = append(existing, userID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", group.ErrStoreUnavailable, err)
	}
	return existing, nil
}

// ValidateMembers 检查所有目标用户是否合格：系统组要求全局账户 active；应用组
// 额外要求 app_memberships 为 active 且应用存在。返回不合格用户 ID 列表。
func (s *Store) ValidateMembers(ctx context.Context, scope group.GroupScope, userIDs []string) ([]string, error) {
	if len(userIDs) == 0 {
		return nil, nil
	}
	eligible, err := s.activeUsers(ctx, userIDs)
	if err != nil {
		return nil, err
	}
	if scope.Kind == group.ScopeKindApplication {
		appMembers, err := s.activeApplicationMembers(ctx, scope.ApplicationID, userIDs)
		if err != nil {
			return nil, err
		}
		for userID := range eligible {
			if _, ok := appMembers[userID]; !ok {
				delete(eligible, userID)
			}
		}
	}
	ineligible := make([]string, 0, len(userIDs))
	for _, userID := range userIDs {
		if _, ok := eligible[userID]; !ok {
			ineligible = append(ineligible, userID)
		}
	}
	return ineligible, nil
}

// activeUsers 返回全局账户 active 的用户集合。
func (s *Store) activeUsers(ctx context.Context, userIDs []string) (map[string]struct{}, error) {
	placeholders := make([]string, len(userIDs))
	args := make([]any, 0, len(userIDs))
	for index, userID := range userIDs {
		placeholders[index] = "?"
		args = append(args, userID)
	}
	rows, err := s.store.QueryContext(ctx,
		`SELECT id FROM users WHERE status='active' AND id IN (`+strings.Join(placeholders, ",")+`)`, args...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", group.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	eligible := make(map[string]struct{}, len(userIDs))
	for rows.Next() {
		var userID string
		if err := rows.Scan(&userID); err != nil {
			return nil, fmt.Errorf("%w: %w", group.ErrStoreUnavailable, err)
		}
		eligible[userID] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", group.ErrStoreUnavailable, err)
	}
	return eligible, nil
}

// activeApplicationMembers 返回指定应用中 active 的成员集合。
func (s *Store) activeApplicationMembers(ctx context.Context, applicationID string, userIDs []string) (map[string]struct{}, error) {
	placeholders := make([]string, len(userIDs))
	args := make([]any, 0, len(userIDs)+1)
	args = append(args, applicationID)
	for index, userID := range userIDs {
		placeholders[index] = "?"
		args = append(args, userID)
	}
	rows, err := s.store.QueryContext(ctx,
		`SELECT user_id FROM app_memberships WHERE app_id=? AND status='active' AND user_id IN (`+strings.Join(placeholders, ",")+`)`, args...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", group.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	members := make(map[string]struct{}, len(userIDs))
	for rows.Next() {
		var userID string
		if err := rows.Scan(&userID); err != nil {
			return nil, fmt.Errorf("%w: %w", group.ErrStoreUnavailable, err)
		}
		members[userID] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", group.ErrStoreUnavailable, err)
	}
	return members, nil
}

// AddMembers 在审计事务中逐个条件插入成员。条件包含全局 active 与应用成员资格，
// 保证并发状态变化时不会插入不合格成员；任一插入影响 0 行（资格变化或并发重复）
// 返回 ErrStateConflict 让整批回滚，避免部分成功。
func (s *Store) AddMembers(ctx context.Context, tx audit.Tx, groupID string, scope group.GroupScope, userIDs []string, now time.Time) (int, error) {
	if tx == nil {
		return 0, fmt.Errorf("%w: 审计事务为空", group.ErrOptionsInvalid)
	}
	added := 0
	for _, userID := range userIDs {
		var result sql.Result
		var err error
		if scope.Kind == group.ScopeKindApplication {
			result, err = tx.ExecContext(ctx, insertMemberApplicationSQL,
				groupID, userID, now.UTC().UnixMilli(), userID, scope.ApplicationID, userID, scope.ApplicationID)
		} else {
			result, err = tx.ExecContext(ctx, insertMemberSystemSQL,
				groupID, userID, now.UTC().UnixMilli(), userID)
		}
		if err != nil {
			return 0, fmt.Errorf("%w: %w", group.ErrStoreUnavailable, err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("%w: %w", group.ErrStoreUnavailable, err)
		}
		switch affected {
		case 1:
			added++
		case 0:
			return 0, group.ErrStateConflict
		default:
			return 0, fmt.Errorf("%w: 插入组成员影响行数异常", group.ErrStoreUnavailable)
		}
	}
	return added, nil
}

// RemoveMembers 在审计事务中逐个删除成员；不存在成员计为 skipped，幂等。
func (s *Store) RemoveMembers(ctx context.Context, tx audit.Tx, groupID string, userIDs []string) (int, int, error) {
	if tx == nil {
		return 0, 0, fmt.Errorf("%w: 审计事务为空", group.ErrOptionsInvalid)
	}
	removed := 0
	skipped := 0
	for _, userID := range userIDs {
		result, err := tx.ExecContext(ctx, deleteMemberSQL, groupID, userID)
		if err != nil {
			return 0, 0, fmt.Errorf("%w: %w", group.ErrStoreUnavailable, err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return 0, 0, fmt.Errorf("%w: %w", group.ErrStoreUnavailable, err)
		}
		switch affected {
		case 1:
			removed++
		case 0:
			skipped++
		default:
			return 0, 0, fmt.Errorf("%w: 删除组成员影响行数异常", group.ErrStoreUnavailable)
		}
	}
	return removed, skipped, nil
}

// checkAffected 把条件更新结果转换为领域错误。
func checkAffected(result sql.Result, notFound error) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: %w", group.ErrStoreUnavailable, err)
	}
	switch affected {
	case 1:
		return nil
	case 0:
		return notFound
	default:
		return fmt.Errorf("%w: 条件更新影响行数异常", group.ErrStoreUnavailable)
	}
}

// scanGroup 读取一行用户组并校验 scope 约定。
func scanGroup(rows *sql.Rows) (group.Group, error) {
	var (
		record      group.Group
		createdAtMS int64
		updatedAtMS int64
	)
	if err := rows.Scan(&record.ID, &record.ScopeID, &record.GroupKey, &record.Name,
		&record.Description, &createdAtMS, &updatedAtMS); err != nil {
		return group.Group{}, fmt.Errorf("%w: %w", group.ErrStoreUnavailable, err)
	}
	if !group.ValidGroupID(record.ID) {
		return group.Group{}, fmt.Errorf("%w: 用户组 ID 数据格式无效", group.ErrStoreUnavailable)
	}
	kind, applicationID, err := group.ParseScope(record.ScopeID)
	if err != nil {
		return group.Group{}, fmt.Errorf("%w: 用户组作用范围数据无效", group.ErrStoreUnavailable)
	}
	record.ScopeKind = kind
	record.ApplicationID = applicationID
	record.CreatedAt = time.UnixMilli(createdAtMS).UTC()
	record.UpdatedAt = time.UnixMilli(updatedAtMS).UTC()
	return record, nil
}
