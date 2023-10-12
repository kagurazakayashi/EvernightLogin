// Package sqlite 实现 internal/role.Store 的 SQLite 生产仓储。
//
// 表结构来自 migrations/0001_identity_and_scope_core.sql 的 roles、role_permissions、
// user_roles 与 group_roles 表；本包不执行迁移。角色以 (scope_id, role_key) 唯一；
// role_permissions/user_roles/group_roles 使用复合外键保证角色、权限、用户组作用
// 范围一致，仓储只写关系行，不修改用户、应用、权限或用户组状态。
package sqlite

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
	"github.com/kagurazakayashi/EvernightLogin/internal/role"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

const (
	roleColumns = `r.id,r.scope_id,r.role_key,r.name,r.description,r.limits_text,r.is_builtin,r.enabled,r.created_at_ms,r.updated_at_ms,s.kind,s.app_id,a.status`

	selectRoleByIDSQL = `SELECT ` + roleColumns + ` FROM roles r
JOIN scopes s ON s.id=r.scope_id
LEFT JOIN applications a ON a.id=s.app_id
WHERE r.id=?`

	selectRoleScopeSQL = `SELECT scope_id FROM roles WHERE id=?`

	insertRoleSQL = `INSERT INTO roles(
id,scope_id,role_key,name,description,limits_text,is_builtin,enabled,created_at_ms,updated_at_ms
) VALUES(?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(scope_id,role_key) DO NOTHING`

	updateRoleSQL = `UPDATE roles SET name=?,description=?,limits_text=?,updated_at_ms=?
WHERE id=? AND is_builtin=0`

	setRoleEnabledSQL = `UPDATE roles SET enabled=?,updated_at_ms=? WHERE id=? AND enabled=?`

	countRolePermissionsSQL      = `SELECT COUNT(*) FROM role_permissions WHERE role_id=?`
	countRoleUserAssignmentsSQL  = `SELECT COUNT(*) FROM user_roles WHERE role_id=?`
	countRoleGroupAssignmentsSQL = `SELECT COUNT(*) FROM group_roles WHERE role_id=?`

	deleteRoleSQL = `DELETE FROM roles WHERE id=?
AND NOT EXISTS(SELECT 1 FROM role_permissions WHERE role_id=?)
AND NOT EXISTS(SELECT 1 FROM user_roles WHERE role_id=?)
AND NOT EXISTS(SELECT 1 FROM group_roles WHERE role_id=?)`

	selectSystemScopeSQL = `SELECT 1 FROM scopes WHERE id='system' AND kind='system'`

	// selectRoleAssignmentTargetsSQL 读取角色当前分配的用户与用户组目标。启用角色
	// 或向角色组合权限时，这些主体会重新获得权限，必须按委派目标限制复核。
	selectRoleAssignmentTargetsSQL = `
SELECT 'user',user_id FROM user_roles WHERE role_id=? AND scope_id=?
UNION
SELECT 'group',group_id FROM group_roles WHERE role_id=? AND scope_id=?
ORDER BY 1,2 LIMIT ?`

	selectApplicationScopeSQL = `SELECT a.status FROM applications a
JOIN scopes s ON s.id=? AND s.kind='application' AND s.app_id=a.id WHERE a.id=?`

	selectPermissionForRoleSQL = `SELECT id,scope_id,permission_key,name,enabled,root_only FROM permissions WHERE id=?`

	insertRolePermissionSQL = `INSERT INTO role_permissions(role_id,permission_id,scope_id) VALUES(?,?,?)
ON CONFLICT(role_id,permission_id) DO NOTHING`

	deleteRolePermissionSQL = `DELETE FROM role_permissions WHERE role_id=? AND permission_id=?`

	listRolePermissionsSQL = `SELECT p.id,p.permission_key,p.name,p.scope_id,p.enabled,p.root_only
FROM role_permissions rp JOIN permissions p ON p.id=rp.permission_id
WHERE rp.role_id=? ORDER BY p.permission_key,p.id`

	// listRoleEffectivePermissionIDsSQL 与 internal/authz 的有效权限判定一致：
	// 权限必须启用且非 root_only。不过滤角色 enabled，因为启用角色前也要检查。
	listRoleEffectivePermissionIDsSQL = `SELECT rp.permission_id
FROM role_permissions rp
JOIN roles r ON r.id=rp.role_id AND r.scope_id=rp.scope_id
JOIN permissions p ON p.id=rp.permission_id AND p.scope_id=rp.scope_id
WHERE rp.role_id=? AND p.enabled=1 AND p.root_only=0
ORDER BY rp.permission_id`

	selectUserForRoleSQL = `SELECT status,is_root FROM users WHERE id=?`

	selectApplicationMembershipSQL = `SELECT status FROM app_memberships WHERE app_id=? AND user_id=?`

	selectGroupForRoleSQL = `SELECT g.scope_id,s.kind,s.app_id FROM user_groups g
JOIN scopes s ON s.id=g.scope_id WHERE g.id=?`

	selectGroupRootMemberSQL = `SELECT 1 FROM group_members gm
JOIN users u ON u.id=gm.user_id WHERE gm.group_id=? AND u.is_root=1 LIMIT 1`

	insertUserRoleSQL = `INSERT INTO user_roles(user_id,role_id,scope_id,data_scope_json,assigned_by,created_at_ms)
VALUES(?,?,?,?,?,?)
ON CONFLICT(user_id,role_id) DO NOTHING`

	deleteUserRoleSQL = `DELETE FROM user_roles WHERE role_id=? AND user_id=?`

	insertGroupRoleSQL = `INSERT INTO group_roles(group_id,role_id,scope_id,data_scope_json,created_at_ms)
VALUES(?,?,?,?,?)
ON CONFLICT(group_id,role_id) DO NOTHING`

	deleteGroupRoleSQL = `DELETE FROM group_roles WHERE role_id=? AND group_id=?`

	listUserAssignmentsSQL = `SELECT user_id,role_id,scope_id,data_scope_json,assigned_by,created_at_ms
FROM user_roles WHERE role_id=? ORDER BY user_id`

	listGroupAssignmentsSQL = `SELECT group_id,role_id,scope_id,data_scope_json,created_at_ms
FROM group_roles WHERE role_id=? ORDER BY group_id`
)

// Store 是 role.Store 的 SQLite 实现。
type Store struct {
	store *storagesqlite.Store
}

// New 包装已打开且完成迁移的 SQLite 存储。
func New(store *storagesqlite.Store) (*Store, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", role.ErrOptionsInvalid)
	}
	return &Store{store: store}, nil
}

// 编译期确认实现 role.Store。
var _ role.Store = (*Store)(nil)

// GetScope 读取作用范围并确认应用状态。
func (s *Store) GetScope(ctx context.Context, scopeID string) (role.ScopeInfo, error) {
	kind, applicationID, err := role.ParseScope(scopeID)
	if err != nil {
		return role.ScopeInfo{}, err
	}
	if kind == role.ScopeKindSystem {
		rows, queryErr := s.store.QueryContext(ctx, selectSystemScopeSQL)
		if queryErr != nil {
			return role.ScopeInfo{}, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, queryErr)
		}
		defer rows.Close()
		if !rows.Next() {
			return role.ScopeInfo{}, role.ErrScopeInvalid
		}
		return role.ScopeInfo{ScopeID: role.ScopeSystem, Kind: role.ScopeKindSystem}, nil
	}
	rows, queryErr := s.store.QueryContext(ctx, selectApplicationScopeSQL, scopeID, applicationID)
	if queryErr != nil {
		return role.ScopeInfo{}, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, queryErr)
	}
	defer rows.Close()
	if !rows.Next() {
		return role.ScopeInfo{}, role.ErrScopeInvalid
	}
	var status string
	if err := rows.Scan(&status); err != nil {
		return role.ScopeInfo{}, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	return role.ScopeInfo{
		ScopeID: scopeID, Kind: role.ScopeKindApplication,
		ApplicationID: applicationID, ApplicationActive: status == string(app.StatusActive),
	}, nil
}

// CreateRole 在审计事务中插入角色；同 scope 机器标识冲突返回 CONFLICT 语义。
func (s *Store) CreateRole(ctx context.Context, tx audit.Tx, record role.Role) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", role.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, insertRoleSQL,
		record.ID,
		record.ScopeID,
		record.Key,
		record.Name,
		record.Description,
		record.Limits,
		boolToInt(record.IsBuiltin),
		boolToInt(record.Enabled),
		record.CreatedAt.UTC().UnixMilli(),
		record.UpdatedAt.UTC().UnixMilli(),
	)
	if err != nil {
		return fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	switch affected {
	case 1:
		return nil
	case 0:
		return role.ErrRoleKeyTaken
	default:
		return fmt.Errorf("%w: 插入角色影响行数异常", role.ErrStoreUnavailable)
	}
}

// GetRole 按稳定 ID 读取角色。
func (s *Store) GetRole(ctx context.Context, id string) (role.Role, error) {
	rows, err := s.store.QueryContext(ctx, selectRoleByIDSQL, id)
	if err != nil {
		return role.Role{}, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return role.Role{}, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
		}
		return role.Role{}, role.ErrRoleNotFound
	}
	record, err := scanRole(rows)
	if err != nil {
		return role.Role{}, err
	}
	if err := rows.Err(); err != nil {
		return role.Role{}, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	return record, nil
}

// GetRoleScope 只读取角色 scope，供先鉴权后读取完整记录使用。
func (s *Store) GetRoleScope(ctx context.Context, id string) (string, error) {
	rows, err := s.store.QueryContext(ctx, selectRoleScopeSQL, id)
	if err != nil {
		return "", fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return "", fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
		}
		return "", role.ErrRoleNotFound
	}
	var scopeID string
	if err := rows.Scan(&scopeID); err != nil {
		return "", fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	return scopeID, rows.Err()
}

// ListRoles 按可管理范围/状态过滤分页查询；排序固定为创建时间与 ID，不接受调用方
// 任意列。
func (s *Store) ListRoles(ctx context.Context, query role.ListQuery) ([]role.Role, bool, error) {
	statement := `SELECT ` + roleColumns + ` FROM roles r
JOIN scopes s ON s.id=r.scope_id
LEFT JOIN applications a ON a.id=s.app_id`
	conditions := make([]string, 0, 4)
	args := make([]any, 0, 8)
	if query.ScopeFilter != "" {
		conditions = append(conditions, "r.scope_id=?")
		args = append(args, query.ScopeFilter)
	}
	if !query.AllScopes {
		if len(query.ScopeIDs) == 0 {
			return []role.Role{}, false, nil
		}
		placeholders := make([]string, len(query.ScopeIDs))
		for index, scopeID := range query.ScopeIDs {
			placeholders[index] = "?"
			args = append(args, scopeID)
		}
		conditions = append(conditions, "r.scope_id IN ("+strings.Join(placeholders, ",")+")")
	}
	if query.Enabled != nil {
		conditions = append(conditions, "r.enabled=?")
		args = append(args, boolToInt(*query.Enabled))
	}
	if query.Builtin != nil {
		conditions = append(conditions, "r.is_builtin=?")
		args = append(args, boolToInt(*query.Builtin))
	}
	if len(conditions) > 0 {
		statement += ` WHERE ` + strings.Join(conditions, " AND ")
	}
	column, ok := roleSortColumn(query.Sort)
	if !ok {
		return nil, false, fmt.Errorf("%w: 排序字段不在允许列表内", role.ErrInvalidRequest)
	}
	direction := "ASC"
	if query.Descending {
		direction = "DESC"
	}
	statement += ` ORDER BY ` + column + ` ` + direction + `, r.id ` + direction + ` LIMIT ? OFFSET ?`
	args = append(args, query.Limit+1, query.Offset)
	rows, err := s.store.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	records := make([]role.Role, 0, query.Limit+1)
	for rows.Next() {
		record, scanErr := scanRole(rows)
		if scanErr != nil {
			return nil, false, scanErr
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	hasMore := false
	if len(records) > query.Limit {
		hasMore = true
		records = records[:query.Limit]
	}
	return records, hasMore, nil
}

// UpdateRole 更新自定义角色资料；内置角色由条件 is_builtin=0 保护。
func (s *Store) UpdateRole(ctx context.Context, tx audit.Tx, id, name, description, limits string, now time.Time) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", role.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, updateRoleSQL,
		name, description, limits, now.UTC().UnixMilli(), id)
	if err != nil {
		return fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	return checkAffected(result)
}

// SetRoleEnabled 条件更新角色启停。
func (s *Store) SetRoleEnabled(ctx context.Context, tx audit.Tx, id string, expectedEnabled, enabled bool, now time.Time) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", role.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, setRoleEnabledSQL,
		boolToInt(enabled), now.UTC().UnixMilli(), id, boolToInt(expectedEnabled))
	if err != nil {
		return fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	return checkAffected(result)
}

// CountDeleteReferences 统计角色被权限组合、用户分配和用户组分配的引用数量。
func (s *Store) CountDeleteReferences(ctx context.Context, id string) (role.ReferenceCounts, error) {
	var counts role.ReferenceCounts
	queries := []struct {
		statement string
		target    *int
	}{
		{countRolePermissionsSQL, &counts.Permissions},
		{countRoleUserAssignmentsSQL, &counts.Users},
		{countRoleGroupAssignmentsSQL, &counts.Groups},
	}
	for _, item := range queries {
		rows, err := s.store.QueryContext(ctx, item.statement, id)
		if err != nil {
			return role.ReferenceCounts{}, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
		}
		if !rows.Next() {
			rows.Close()
			if err := rows.Err(); err != nil {
				return role.ReferenceCounts{}, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
			}
			return role.ReferenceCounts{}, fmt.Errorf("%w: 引用计数查询无结果", role.ErrStoreUnavailable)
		}
		if err := rows.Scan(item.target); err != nil {
			rows.Close()
			return role.ReferenceCounts{}, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return role.ReferenceCounts{}, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
		}
		rows.Close()
	}
	return counts, nil
}

// DeleteRole 在同一事务条件删除角色，并确认没有被权限组合/用户/用户组引用。
func (s *Store) DeleteRole(ctx context.Context, tx audit.Tx, id string) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", role.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, deleteRoleSQL, id, id, id, id)
	if err != nil {
		return fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	switch affected {
	case 0:
		return role.ErrRoleInUse
	case 1:
		return nil
	default:
		return fmt.Errorf("%w: 删除角色影响行数异常", role.ErrStoreUnavailable)
	}
}

// GetPermissionForRole 读取待组合权限的状态与范围。
func (s *Store) GetPermissionForRole(ctx context.Context, permissionID string) (role.PermissionRecord, error) {
	rows, err := s.store.QueryContext(ctx, selectPermissionForRoleSQL, permissionID)
	if err != nil {
		return role.PermissionRecord{}, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return role.PermissionRecord{}, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
		}
		return role.PermissionRecord{}, role.ErrPermissionNotFound
	}
	var (
		record   role.PermissionRecord
		enabled  int
		rootOnly int
	)
	if err := rows.Scan(&record.PermissionID, &record.ScopeID, &record.Key, &record.Name, &enabled, &rootOnly); err != nil {
		return role.PermissionRecord{}, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	record.Enabled = enabled == 1
	record.RootOnly = rootOnly == 1
	if err := rows.Err(); err != nil {
		return role.PermissionRecord{}, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	return record, nil
}

// AddRolePermission 条件插入角色权限组合；重复组合返回 inserted=false。
func (s *Store) AddRolePermission(ctx context.Context, tx audit.Tx, roleID, permissionID, scopeID string) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("%w: 审计事务为空", role.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, insertRolePermissionSQL, roleID, permissionID, scopeID)
	if err != nil {
		return false, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	return changedByInsert(result)
}

// RemoveRolePermission 条件删除角色权限组合；不存在返回 removed=false。
func (s *Store) RemoveRolePermission(ctx context.Context, tx audit.Tx, roleID, permissionID string) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("%w: 审计事务为空", role.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, deleteRolePermissionSQL, roleID, permissionID)
	if err != nil {
		return false, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	return changedByDelete(result)
}

// ListRolePermissions 返回角色组合中的权限摘要。
func (s *Store) ListRolePermissions(ctx context.Context, roleID string) ([]role.PermissionSummary, error) {
	rows, err := s.store.QueryContext(ctx, listRolePermissionsSQL, roleID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	summaries := make([]role.PermissionSummary, 0, 8)
	for rows.Next() {
		var (
			summary  role.PermissionSummary
			enabled  int
			rootOnly int
		)
		if err := rows.Scan(&summary.PermissionID, &summary.Key, &summary.Name, &summary.ScopeID, &enabled, &rootOnly); err != nil {
			return nil, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
		}
		summary.Enabled = enabled == 1
		summary.RootOnly = rootOnly == 1
		summaries = append(summaries, summary)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	return summaries, nil
}

// ListRoleEffectivePermissionIDs 在调用方事务内读取角色组合中当前会生效的权限
// ID（权限启用且非 root_only）；供委派检查在同一事务内判断可转授范围。
func (s *Store) ListRoleEffectivePermissionIDs(ctx context.Context, tx audit.Tx, roleID string) ([]string, error) {
	if tx == nil {
		return nil, fmt.Errorf("%w: 审计事务为空", role.ErrOptionsInvalid)
	}
	rows, err := tx.QueryContext(ctx, listRoleEffectivePermissionIDsSQL, roleID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	ids := make([]string, 0, 8)
	for rows.Next() {
		var permissionID string
		if err := rows.Scan(&permissionID); err != nil {
			return nil, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
		}
		ids = append(ids, permissionID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	return ids, nil
}

// RoleAssignmentTargets 在调用方事务内读取角色当前分配的用户与用户组目标，供启用
// 角色与组合权限前的委派目标复核使用。超过检查上限返回错误由调用方 fail-closed。
func (s *Store) RoleAssignmentTargets(ctx context.Context, tx audit.Tx, roleID, scopeID string) ([]delegation.Target, error) {
	if tx == nil {
		return nil, fmt.Errorf("%w: 审计事务为空", role.ErrOptionsInvalid)
	}
	rows, err := tx.QueryContext(ctx, selectRoleAssignmentTargetsSQL,
		roleID, scopeID, roleID, scopeID, delegation.MaxAffectedTargets+1)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	targets := make([]delegation.Target, 0, 8)
	for rows.Next() {
		var (
			kind string
			id   string
		)
		if err := rows.Scan(&kind, &id); err != nil {
			return nil, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
		}
		targets = append(targets, delegation.Target{Kind: delegation.TargetKind(kind), ID: id})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	return targets, nil
}

// GetUserForRole 读取角色分配目标账户状态与 root 标记。
func (s *Store) GetUserForRole(ctx context.Context, userID string) (role.UserRecord, error) {
	rows, err := s.store.QueryContext(ctx, selectUserForRoleSQL, userID)
	if err != nil {
		return role.UserRecord{}, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return role.UserRecord{}, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
		}
		return role.UserRecord{}, role.ErrUserNotFound
	}
	var (
		status string
		isRoot int
	)
	if err := rows.Scan(&status, &isRoot); err != nil {
		return role.UserRecord{}, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	parsed := account.Status(status)
	if status == "" || !parsed.Valid() {
		return role.UserRecord{}, fmt.Errorf("%w: 账户状态数据无效", role.ErrStoreUnavailable)
	}
	if err := rows.Err(); err != nil {
		return role.UserRecord{}, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	return role.UserRecord{UserID: userID, Status: parsed, IsRoot: isRoot == 1}, nil
}

// GetApplicationMembership 读取应用成员状态；不存在时 found=false。
func (s *Store) GetApplicationMembership(ctx context.Context, applicationID, userID string) (app.MembershipStatus, bool, error) {
	rows, err := s.store.QueryContext(ctx, selectApplicationMembershipSQL, applicationID, userID)
	if err != nil {
		return "", false, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return "", false, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
		}
		return "", false, nil
	}
	var status string
	if err := rows.Scan(&status); err != nil {
		return "", false, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	parsed := app.MembershipStatus(status)
	if !parsed.Valid() {
		return "", false, fmt.Errorf("%w: 应用成员状态数据无效", role.ErrStoreUnavailable)
	}
	if err := rows.Err(); err != nil {
		return "", false, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	return parsed, true, nil
}

// GetGroupForRole 读取角色分配目标用户组的范围。
func (s *Store) GetGroupForRole(ctx context.Context, groupID string) (role.GroupRecord, error) {
	rows, err := s.store.QueryContext(ctx, selectGroupForRoleSQL, groupID)
	if err != nil {
		return role.GroupRecord{}, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return role.GroupRecord{}, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
		}
		return role.GroupRecord{}, role.ErrGroupNotFound
	}
	var (
		record        role.GroupRecord
		kind          string
		applicationID sql.NullString
	)
	if err := rows.Scan(&record.ScopeID, &kind, &applicationID); err != nil {
		return role.GroupRecord{}, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	record.GroupID = groupID
	record.Kind = role.ScopeKind(kind)
	record.ApplicationID = applicationID.String
	if record.Kind != role.ScopeKindSystem && record.Kind != role.ScopeKindApplication {
		return role.GroupRecord{}, fmt.Errorf("%w: 用户组作用范围数据无效", role.ErrStoreUnavailable)
	}
	if err := rows.Err(); err != nil {
		return role.GroupRecord{}, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	return record, nil
}

// GroupHasRootMember 报告用户组是否包含 root 账户；向含 root 的组分配普通角色
// 会被服务层拒绝，避免通过组间接给 root 分配普通角色。
func (s *Store) GroupHasRootMember(ctx context.Context, groupID string) (bool, error) {
	rows, err := s.store.QueryContext(ctx, selectGroupRootMemberSQL, groupID)
	if err != nil {
		return false, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if rows.Next() {
		return true, nil
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	return false, nil
}

// AddUserRole 条件插入用户角色分配；重复分配返回 inserted=false。
func (s *Store) AddUserRole(ctx context.Context, tx audit.Tx, assignment role.UserRoleAssignment) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("%w: 审计事务为空", role.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, insertUserRoleSQL,
		assignment.UserID, assignment.RoleID, assignment.ScopeID,
		assignment.DataScope, assignment.AssignedBy, assignment.CreatedAt.UTC().UnixMilli())
	if err != nil {
		return false, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	return changedByInsert(result)
}

// RemoveUserRole 条件删除用户角色分配；不存在返回 removed=false。
func (s *Store) RemoveUserRole(ctx context.Context, tx audit.Tx, roleID, userID string) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("%w: 审计事务为空", role.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, deleteUserRoleSQL, roleID, userID)
	if err != nil {
		return false, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	return changedByDelete(result)
}

// AddGroupRole 条件插入用户组角色分配；重复分配返回 inserted=false。
func (s *Store) AddGroupRole(ctx context.Context, tx audit.Tx, assignment role.GroupRoleAssignment) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("%w: 审计事务为空", role.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, insertGroupRoleSQL,
		assignment.GroupID, assignment.RoleID, assignment.ScopeID,
		assignment.DataScope, assignment.CreatedAt.UTC().UnixMilli())
	if err != nil {
		return false, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	return changedByInsert(result)
}

// RemoveGroupRole 条件删除用户组角色分配；不存在返回 removed=false。
func (s *Store) RemoveGroupRole(ctx context.Context, tx audit.Tx, roleID, groupID string) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("%w: 审计事务为空", role.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, deleteGroupRoleSQL, roleID, groupID)
	if err != nil {
		return false, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	return changedByDelete(result)
}

// ListRoleAssignments 返回角色的用户与用户组分配快照。
// roleSortColumn 把白名单排序字段映射为固定 SQL 列（不接受用户输入原文）。
func roleSortColumn(field role.SortField) (string, bool) {
	if field == "" {
		return "r.created_at_ms", true
	}
	switch field {
	case role.SortCreatedAt:
		return "r.created_at_ms", true
	case role.SortUpdatedAt:
		return "r.updated_at_ms", true
	case role.SortName:
		return "r.name", true
	case role.SortKey:
		return "r.role_key", true
	default:
		return "", false
	}
}

// assignmentSortColumn 把分配排序白名单映射为固定 SQL 列。
func assignmentSortColumn(field role.AssignmentSortField, targetColumn string) (string, bool) {
	switch field {
	case role.AssignmentSortCreatedAt:
		return "created_at_ms", true
	case role.AssignmentSortTargetID:
		return targetColumn, true
	default:
		return "", false
	}
}

// ListRoleUserAssignments 分页读取角色的用户分配（LIMIT/OFFSET 在数据库执行）。
func (s *Store) ListRoleUserAssignments(ctx context.Context, roleID string, limit, offset int,
	sort role.AssignmentSortField, descending bool) ([]role.UserRoleAssignment, bool, error) {
	column, ok := assignmentSortColumn(sort, "user_id")
	if !ok {
		return nil, false, fmt.Errorf("%w: 分配排序字段不在允许列表内", role.ErrInvalidRequest)
	}
	direction := "ASC"
	if descending {
		direction = "DESC"
	}
	statement := `SELECT user_id,role_id,scope_id,data_scope_json,assigned_by,created_at_ms
FROM user_roles WHERE role_id=? ORDER BY ` + column + ` ` + direction +
		`, user_id ` + direction + ` LIMIT ? OFFSET ?`
	rows, err := s.store.QueryContext(ctx, statement, roleID, limit+1, offset)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	assignments := make([]role.UserRoleAssignment, 0, limit+1)
	for rows.Next() {
		var assignment role.UserRoleAssignment
		var createdMS int64
		if err := rows.Scan(&assignment.UserID, &assignment.RoleID, &assignment.ScopeID,
			&assignment.DataScope, &assignment.AssignedBy, &createdMS); err != nil {
			return nil, false, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
		}
		assignment.CreatedAt = time.UnixMilli(createdMS).UTC()
		assignments = append(assignments, assignment)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	hasMore := false
	if len(assignments) > limit {
		hasMore = true
		assignments = assignments[:limit]
	}
	return assignments, hasMore, nil
}

// ListRoleGroupAssignments 分页读取角色的用户组分配（LIMIT/OFFSET 在数据库执行）。
func (s *Store) ListRoleGroupAssignments(ctx context.Context, roleID string, limit, offset int,
	sort role.AssignmentSortField, descending bool) ([]role.GroupRoleAssignment, bool, error) {
	column, ok := assignmentSortColumn(sort, "group_id")
	if !ok {
		return nil, false, fmt.Errorf("%w: 分配排序字段不在允许列表内", role.ErrInvalidRequest)
	}
	direction := "ASC"
	if descending {
		direction = "DESC"
	}
	statement := `SELECT group_id,role_id,scope_id,data_scope_json,created_at_ms
FROM group_roles WHERE role_id=? ORDER BY ` + column + ` ` + direction +
		`, group_id ` + direction + ` LIMIT ? OFFSET ?`
	rows, err := s.store.QueryContext(ctx, statement, roleID, limit+1, offset)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	assignments := make([]role.GroupRoleAssignment, 0, limit+1)
	for rows.Next() {
		var assignment role.GroupRoleAssignment
		var createdMS int64
		if err := rows.Scan(&assignment.GroupID, &assignment.RoleID, &assignment.ScopeID,
			&assignment.DataScope, &createdMS); err != nil {
			return nil, false, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
		}
		assignment.CreatedAt = time.UnixMilli(createdMS).UTC()
		assignments = append(assignments, assignment)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	hasMore := false
	if len(assignments) > limit {
		hasMore = true
		assignments = assignments[:limit]
	}
	return assignments, hasMore, nil
}

func (s *Store) ListRoleAssignments(ctx context.Context, roleID string) (role.Assignments, error) {
	var result role.Assignments
	userRows, err := s.store.QueryContext(ctx, listUserAssignmentsSQL, roleID)
	if err != nil {
		return role.Assignments{}, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	for userRows.Next() {
		var (
			assignment role.UserRoleAssignment
			createdMS  int64
		)
		if err := userRows.Scan(&assignment.UserID, &assignment.RoleID, &assignment.ScopeID,
			&assignment.DataScope, &assignment.AssignedBy, &createdMS); err != nil {
			userRows.Close()
			return role.Assignments{}, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
		}
		assignment.CreatedAt = time.UnixMilli(createdMS).UTC()
		result.Users = append(result.Users, assignment)
	}
	if err := userRows.Err(); err != nil {
		userRows.Close()
		return role.Assignments{}, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	userRows.Close()

	groupRows, err := s.store.QueryContext(ctx, listGroupAssignmentsSQL, roleID)
	if err != nil {
		return role.Assignments{}, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	defer groupRows.Close()
	for groupRows.Next() {
		var (
			assignment role.GroupRoleAssignment
			createdMS  int64
		)
		if err := groupRows.Scan(&assignment.GroupID, &assignment.RoleID, &assignment.ScopeID,
			&assignment.DataScope, &createdMS); err != nil {
			return role.Assignments{}, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
		}
		assignment.CreatedAt = time.UnixMilli(createdMS).UTC()
		result.Groups = append(result.Groups, assignment)
	}
	if err := groupRows.Err(); err != nil {
		return role.Assignments{}, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	return result, nil
}

// scanRole 读取一行角色快照并校验 ID、scope、状态一致性。
func scanRole(rows *sql.Rows) (role.Role, error) {
	var (
		record        role.Role
		isBuiltin     int
		enabled       int
		createdAtMS   int64
		updatedAtMS   int64
		kind          string
		applicationID sql.NullString
		appStatus     sql.NullString
	)
	if err := rows.Scan(
		&record.ID, &record.ScopeID, &record.Key, &record.Name, &record.Description,
		&record.Limits, &isBuiltin, &enabled, &createdAtMS, &updatedAtMS,
		&kind, &applicationID, &appStatus,
	); err != nil {
		return role.Role{}, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	if !role.ValidRoleID(record.ID) {
		return role.Role{}, fmt.Errorf("%w: 角色 ID 数据格式无效", role.ErrStoreUnavailable)
	}
	record.IsBuiltin = isBuiltin == 1
	record.Enabled = enabled == 1
	record.ScopeKind = role.ScopeKind(kind)
	record.ApplicationID = applicationID.String
	record.CreatedAt = time.UnixMilli(createdAtMS).UTC()
	record.UpdatedAt = time.UnixMilli(updatedAtMS).UTC()
	switch record.ScopeKind {
	case role.ScopeKindSystem:
		if record.ScopeID != role.ScopeSystem || applicationID.Valid {
			return role.Role{}, fmt.Errorf("%w: 系统角色作用范围数据不一致", role.ErrStoreUnavailable)
		}
	case role.ScopeKindApplication:
		if !validApplicationID(record.ScopeID) || record.ApplicationID != record.ScopeID || !appStatus.Valid {
			return role.Role{}, fmt.Errorf("%w: 应用角色作用范围数据不一致", role.ErrStoreUnavailable)
		}
		if appStatus.String != string(app.StatusActive) && appStatus.String != string(app.StatusDisabled) {
			return role.Role{}, fmt.Errorf("%w: 应用状态数据无效", role.ErrStoreUnavailable)
		}
	default:
		return role.Role{}, fmt.Errorf("%w: 角色作用范围数据无效", role.ErrStoreUnavailable)
	}
	return record, nil
}

// validApplicationID 复制应用 ID 格式校验，用于读取数据的一致性检查。
func validApplicationID(id string) bool {
	if len(id) != 4+32 || !strings.HasPrefix(id, "app_") {
		return false
	}
	_, err := hex.DecodeString(id[4:])
	return err == nil
}

// checkAffected 把条件更新结果转换为领域错误。
func checkAffected(result sql.Result) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	switch affected {
	case 1:
		return nil
	case 0:
		return role.ErrStateConflict
	default:
		return fmt.Errorf("%w: 条件更新影响行数异常", role.ErrStoreUnavailable)
	}
}

// changedByInsert 把条件插入结果转换为是否新增；唯一冲突（DO NOTHING）视为未变化。
func changedByInsert(result sql.Result) (bool, error) {
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	switch affected {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, fmt.Errorf("%w: 插入影响行数异常", role.ErrStoreUnavailable)
	}
}

// changedByDelete 把条件删除结果转换为是否删除；不存在视为未变化。
func changedByDelete(result sql.Result) (bool, error) {
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("%w: %w", role.ErrStoreUnavailable, err)
	}
	switch affected {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, fmt.Errorf("%w: 删除影响行数异常", role.ErrStoreUnavailable)
	}
}

// boolToInt 把布尔值映射为 SQLite 的 0/1。
func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
