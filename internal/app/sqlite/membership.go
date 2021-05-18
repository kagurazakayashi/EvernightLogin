package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// 应用成员持久化 SQL。表结构来自 migrations/0001_identity_and_scope_core.sql 的
// app_memberships；本包不执行迁移。所有语句都以 (application_id,user_id) 为范围，
// 不提供跨应用读写；成员资料只写 profile_json，不触碰 users 表。

const (
	memberColumns = `m.app_id,m.user_id,m.status,m.profile_json,m.row_version,m.created_at_ms,m.updated_at_ms`

	selectMemberSQL = `SELECT ` + memberColumns + ` FROM app_memberships m WHERE m.app_id=? AND m.user_id=?`

	insertMemberSQL = `INSERT INTO app_memberships(app_id,user_id,status,profile_json,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?,?)
ON CONFLICT(app_id,user_id) DO NOTHING`

	updateMemberProfileSQL = `UPDATE app_memberships
SET profile_json=?,row_version=row_version+1,updated_at_ms=?
WHERE app_id=? AND user_id=? AND row_version=?`

	applyMemberStatusSQL = `UPDATE app_memberships
SET status=?,row_version=row_version+1,updated_at_ms=?
WHERE app_id=? AND user_id=? AND status=? AND row_version=?`

	removeMemberSQL = `DELETE FROM app_memberships WHERE app_id=? AND user_id=? AND row_version=?`

	lookupUserStatusSQL = `SELECT status,is_root FROM users WHERE id=?`
)

// GetMembership 读取指定应用的成员关系；profile_json 必须是当前版本的规范 JSON，
// 否则按存储不一致拒绝返回。
func (s *Store) GetMembership(ctx context.Context, applicationID, userID string) (app.Membership, error) {
	rows, err := s.store.QueryContext(ctx, selectMemberSQL, applicationID, userID)
	if err != nil {
		return app.Membership{}, fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return app.Membership{}, fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
		}
		return app.Membership{}, app.ErrMemberNotFound
	}
	membership, err := scanMembership(rows)
	if err != nil {
		return app.Membership{}, err
	}
	if err := rows.Err(); err != nil {
		return app.Membership{}, fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
	}
	return membership, nil
}

// ListMemberships 按应用隔离执行有限分页查询；排序只映射白名单固定列名，不拼接
// 调用方原文，也不允许查询其他应用。
func (s *Store) ListMemberships(ctx context.Context, query app.MemberListQuery) ([]app.Membership, bool, error) {
	column, ok := memberSortColumn(query.Sort)
	if !ok {
		return nil, false, fmt.Errorf("%w: 排序字段不在允许列表内", app.ErrInvalidRequest)
	}
	direction := "ASC"
	if query.Descending {
		direction = "DESC"
	}
	statement := `SELECT ` + memberColumns + ` FROM app_memberships m WHERE m.app_id=?`
	args := make([]any, 0, 4)
	args = append(args, query.ApplicationID)
	if query.Status != "" {
		statement += ` AND m.status=?`
		args = append(args, string(query.Status))
	}
	statement += ` ORDER BY ` + column + ` ` + direction + `, m.user_id ` + direction + ` LIMIT ? OFFSET ?`
	args = append(args, query.Limit+1, query.Offset)
	rows, err := s.store.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	members := make([]app.Membership, 0, query.Limit+1)
	for rows.Next() {
		membership, scanErr := scanMembership(rows)
		if scanErr != nil {
			return nil, false, scanErr
		}
		members = append(members, membership)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
	}
	hasMore := false
	if len(members) > query.Limit {
		hasMore = true
		members = members[:query.Limit]
	}
	return members, hasMore, nil
}

// CreateMembership 在调用方审计事务中写入成员关系。重复加入通过唯一主键冲突的
// DO NOTHING 判定：受影响行数 0 返回 ErrMemberExists，不覆盖已有成员资料。
func (s *Store) CreateMembership(ctx context.Context, tx audit.Tx, membership app.Membership) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", app.ErrOptionsInvalid)
	}
	profileJSON, err := app.EncodeMemberProfile(membership.Profile)
	if err != nil {
		return fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
	}
	result, err := tx.ExecContext(ctx, insertMemberSQL,
		membership.ApplicationID,
		membership.UserID,
		string(membership.Status),
		profileJSON,
		membership.RowVersion,
		membership.CreatedAt.UTC().UnixMilli(),
		membership.UpdatedAt.UTC().UnixMilli(),
	)
	if err != nil {
		return fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
	}
	switch affected {
	case 1:
		return nil
	case 0:
		return app.ErrMemberExists
	default:
		return fmt.Errorf("%w: 成员写入影响行数异常", app.ErrStoreUnavailable)
	}
}

// UpdateMembershipProfile 只更新 profile_json 与 row_version；行版本不符时返回
// ErrStateConflict，不覆盖并发修改。
func (s *Store) UpdateMembershipProfile(ctx context.Context, tx audit.Tx, update app.MemberProfileUpdate) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", app.ErrOptionsInvalid)
	}
	profileJSON, err := app.EncodeMemberProfile(update.Profile)
	if err != nil {
		return fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
	}
	result, err := tx.ExecContext(ctx, updateMemberProfileSQL,
		profileJSON,
		update.Now.UTC().UnixMilli(),
		update.ApplicationID,
		update.UserID,
		update.ExpectedRowVersion,
	)
	if err != nil {
		return fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
	}
	return checkMembershipAffected(result)
}

// ApplyMembershipStatus 以状态与行版本为条件更新应用内成员状态。
func (s *Store) ApplyMembershipStatus(ctx context.Context, tx audit.Tx, change app.MemberStatusChange) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", app.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, applyMemberStatusSQL,
		string(change.NewStatus),
		change.Now.UTC().UnixMilli(),
		change.ApplicationID,
		change.UserID,
		string(change.ExpectedStatus),
		change.ExpectedRowVersion,
	)
	if err != nil {
		return fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
	}
	return checkMembershipAffected(result)
}

// RemoveMembership 以行版本为条件删除成员关系；只影响指定应用的一行。
func (s *Store) RemoveMembership(ctx context.Context, tx audit.Tx, remove app.MemberRemove) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", app.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, removeMemberSQL,
		remove.ApplicationID, remove.UserID, remove.ExpectedRowVersion)
	if err != nil {
		return fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
	}
	return checkMembershipAffected(result)
}

// listMemberEffectivePermissionIDsSQL 与 internal/authz 的有效权限判定一致：
// 直接角色与经用户组的角色合并，角色与权限都启用且权限非 root_only。
const listMemberEffectivePermissionIDsSQL = `SELECT DISTINCT p.id
FROM (
  SELECT ur.role_id,ur.scope_id FROM user_roles ur WHERE ur.user_id=? AND ur.scope_id=?
  UNION ALL
  SELECT gr.role_id,gr.scope_id FROM group_members gm
  JOIN group_roles gr ON gr.group_id=gm.group_id
  WHERE gm.user_id=? AND gr.scope_id=?
) chosen
JOIN roles r ON r.id=chosen.role_id AND r.scope_id=chosen.scope_id
JOIN role_permissions rp ON rp.role_id=r.id
JOIN permissions p ON p.id=rp.permission_id AND p.scope_id=chosen.scope_id
WHERE r.enabled=1 AND p.enabled=1 AND p.root_only=0
ORDER BY p.id`

// ListMemberEffectivePermissionIDs 在调用方事务内读取用户在该应用范围内当前会
// 生效的权限 ID，供成员加入/重新启用前做可转授检查。
func (s *Store) ListMemberEffectivePermissionIDs(ctx context.Context, tx audit.Tx, applicationID, userID string) ([]string, error) {
	if tx == nil {
		return nil, fmt.Errorf("%w: 审计事务为空", app.ErrOptionsInvalid)
	}
	rows, err := tx.QueryContext(ctx, listMemberEffectivePermissionIDsSQL, userID, applicationID, userID, applicationID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	ids := make([]string, 0, 8)
	for rows.Next() {
		var permissionID string
		if err := rows.Scan(&permissionID); err != nil {
			return nil, fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
		}
		ids = append(ids, permissionID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
	}
	return ids, nil
}

// LookupUserState 读取全局账户状态与 root 标记；不存在时返回 found=false。
// 加入/启用成员前由服务要求 active 且非 root，停用/移除允许清理非 active 账户。
func (s *Store) LookupUserState(ctx context.Context, userID string) (account.Status, bool, bool, error) {
	rows, err := s.store.QueryContext(ctx, lookupUserStatusSQL, userID)
	if err != nil {
		return "", false, false, fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return "", false, false, fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
		}
		return "", false, false, nil
	}
	var (
		status string
		isRoot int
	)
	if err := rows.Scan(&status, &isRoot); err != nil {
		return "", false, false, fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
	}
	parsed := account.Status(status)
	if status == "" || !parsed.Valid() {
		return "", false, false, fmt.Errorf("%w: 账户状态数据无效", app.ErrStoreUnavailable)
	}
	if err := rows.Err(); err != nil {
		return "", false, false, fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
	}
	return parsed, isRoot == 1, true, nil
}

// scanMembership 读取一行成员快照并校验 ID、状态、版本与资料 JSON 一致性。
func scanMembership(rows *sql.Rows) (app.Membership, error) {
	var (
		membership  app.Membership
		status      string
		profileJSON string
		createdAtMS int64
		updatedAtMS int64
	)
	if err := rows.Scan(
		&membership.ApplicationID,
		&membership.UserID,
		&status,
		&profileJSON,
		&membership.RowVersion,
		&createdAtMS,
		&updatedAtMS,
	); err != nil {
		return app.Membership{}, fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
	}
	if !app.ValidApplicationID(membership.ApplicationID) {
		return app.Membership{}, fmt.Errorf("%w: 成员关系中的应用 ID 数据无效", app.ErrStoreUnavailable)
	}
	if !account.ValidUserID(membership.UserID) {
		return app.Membership{}, fmt.Errorf("%w: 成员关系中的用户 ID 数据无效", app.ErrStoreUnavailable)
	}
	membership.Status = app.MembershipStatus(status)
	if !membership.Status.Valid() {
		return app.Membership{}, fmt.Errorf("%w: 成员状态数据无效", app.ErrStoreUnavailable)
	}
	if membership.RowVersion <= 0 {
		return app.Membership{}, fmt.Errorf("%w: 成员行版本数据无效", app.ErrStoreUnavailable)
	}
	profile, err := app.DecodeMemberProfile(profileJSON)
	if err != nil {
		return app.Membership{}, err
	}
	membership.Profile = profile
	membership.CreatedAt = time.UnixMilli(createdAtMS).UTC()
	membership.UpdatedAt = time.UnixMilli(updatedAtMS).UTC()
	return membership, nil
}

// checkMembershipAffected 把条件写结果转换为领域错误；0 行表示行版本/状态已变化
// 或成员已被并发移除，统一按并发冲突拒绝。
func checkMembershipAffected(result sql.Result) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: %w", app.ErrStoreUnavailable, err)
	}
	switch affected {
	case 1:
		return nil
	case 0:
		return app.ErrStateConflict
	default:
		return fmt.Errorf("%w: 成员条件更新影响行数异常", app.ErrStoreUnavailable)
	}
}

// memberSortColumn 把成员排序枚举映射为固定 SQL 列名。
func memberSortColumn(sort app.MemberSortField) (string, bool) {
	switch sort {
	case app.MemberSortCreatedAt:
		return "m.created_at_ms", true
	case app.MemberSortUpdatedAt:
		return "m.updated_at_ms", true
	case app.MemberSortUserID:
		return "m.user_id", true
	default:
		return "", false
	}
}

var _ app.Store = (*Store)(nil)
