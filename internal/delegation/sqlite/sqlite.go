// Package sqlite 实现 internal/delegation.Store 的 SQLite 持久化与事务内检查。
//
// 事务内方法通过 audit.Tx.QueryContext 在调用方的审计事务中读取委派资格、权限
// 定义、操作者当前持有情况与目标限制，使“检查 + 写入”处于同一一致性边界。本包
// 不执行迁移、不拥有数据库连接；表由迁移 0006 创建。
package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

// 状态字面值与步骤 18/20/21 的稳定定义一致；本包不导入 app 包以避免与
// 应用服务（它依赖 delegation.Guard）形成导入环。
const (
	statusActive = "active"
)

const (
	selectAccountSQL = `SELECT status,is_root FROM users WHERE id=?`

	selectApplicationSQL = `SELECT status FROM applications WHERE id=?`

	selectMembershipSQL = `SELECT status FROM app_memberships WHERE app_id=? AND user_id=?`

	selectPermissionByIDSQL = `SELECT id,scope_id,permission_key,name,enabled,root_only
FROM permissions WHERE id=?`

	selectPermissionByKeySQL = `SELECT id,scope_id,permission_key,name,enabled,root_only
FROM permissions WHERE scope_id=? AND permission_key=?`

	// selectHeldPermissionSQL 与 internal/authz/sqlite 的有效权限判定保持一致：
	// 直接用户角色与经用户组的角色来源合并，角色与权限都必须启用且非 root_only。
	// 两处语义必须同步调整，任何差异都可能导致“持有判断”与“有效权限”不一致。
	selectHeldPermissionSQL = `SELECT 1 FROM (
  SELECT ur.role_id,ur.scope_id FROM user_roles ur WHERE ur.user_id=? AND ur.scope_id=?
  UNION ALL
  SELECT gr.role_id,gr.scope_id FROM group_members gm
  JOIN group_roles gr ON gr.group_id=gm.group_id
  WHERE gm.user_id=? AND gr.scope_id=?
) chosen
JOIN roles r ON r.id=chosen.role_id AND r.scope_id=chosen.scope_id
JOIN role_permissions rp ON rp.role_id=r.id
JOIN permissions p ON p.id=rp.permission_id AND p.scope_id=chosen.scope_id
WHERE p.id=? AND r.enabled=1 AND p.enabled=1 AND p.root_only=0
LIMIT 1`

	selectGroupMemberSQL = `SELECT 1 FROM group_members WHERE group_id=? AND user_id=? LIMIT 1`

	// selectRestorationPermissionsSQL 读取“启用应用会被恢复”的权限：权限本身启用、
	// 非 root_only，且被至少一个启用角色组合，该角色当前有用户或用户组分配。
	// 与 selectRestorationTargetsSQL 的判据必须保持一致：目标集合是这些角色分配的
	// 用户与用户组，绝不遗漏“将被恢复”的权限持有路径。
	selectRestorationPermissionsSQL = `SELECT DISTINCT p.id FROM permissions p
WHERE p.scope_id=? AND p.enabled=1 AND p.root_only=0
AND EXISTS(
  SELECT 1 FROM role_permissions rp
  JOIN roles r ON r.id=rp.role_id AND r.scope_id=rp.scope_id
  WHERE rp.permission_id=p.id AND rp.scope_id=p.scope_id AND r.enabled=1
  AND (EXISTS(SELECT 1 FROM user_roles ur WHERE ur.role_id=r.id AND ur.scope_id=r.scope_id)
    OR EXISTS(SELECT 1 FROM group_roles gr WHERE gr.role_id=r.id AND gr.scope_id=r.scope_id))
)
ORDER BY p.id LIMIT ?`

	selectRestorationTargetsSQL = `SELECT 'user',ur.user_id FROM user_roles ur
JOIN roles r ON r.id=ur.role_id AND r.scope_id=ur.scope_id
WHERE ur.scope_id=? AND r.enabled=1
AND EXISTS(
  SELECT 1 FROM role_permissions rp
  JOIN permissions p ON p.id=rp.permission_id AND p.scope_id=rp.scope_id
  WHERE rp.role_id=r.id AND rp.scope_id=r.scope_id AND p.enabled=1 AND p.root_only=0
)
UNION
SELECT 'group',gr.group_id FROM group_roles gr
JOIN roles r ON r.id=gr.role_id AND r.scope_id=gr.scope_id
WHERE gr.scope_id=? AND r.enabled=1
AND EXISTS(
  SELECT 1 FROM role_permissions rp
  JOIN permissions p ON p.id=rp.permission_id AND p.scope_id=rp.scope_id
  WHERE rp.role_id=r.id AND rp.scope_id=r.scope_id AND p.enabled=1 AND p.root_only=0
)
ORDER BY 1,2 LIMIT ?`

	selectGrantColumns = `d.id,d.delegator_user_id,d.scope_id,d.permission_id,
COALESCE(p.permission_key,''),COALESCE(p.name,''),d.max_data_scope_json,d.allowed_targets_json,
d.allow_self,d.expires_at_ms,d.revoked_at_ms,d.created_by_type,d.created_by_id,d.created_at_ms,d.updated_at_ms`

	selectGrantFromSQL = ` FROM permission_delegations d
LEFT JOIN permissions p ON p.id=d.permission_id`

	selectGrantByIDSQL = `SELECT ` + selectGrantColumns + selectGrantFromSQL + ` WHERE d.id=?`

	selectGrantByKeySQL = `SELECT ` + selectGrantColumns + selectGrantFromSQL + `
WHERE d.delegator_user_id=? AND d.scope_id=? AND d.permission_id=?`

	selectGrantsForDelegatorSQL = `SELECT ` + selectGrantColumns + selectGrantFromSQL + `
WHERE d.delegator_user_id=? AND d.scope_id=? ORDER BY d.permission_id`

	selectGrantsSQL = `SELECT ` + selectGrantColumns + selectGrantFromSQL + `
WHERE (?='' OR d.delegator_user_id=?) AND (?=1 OR d.revoked_at_ms IS NULL)
ORDER BY d.created_at_ms,d.id LIMIT ? OFFSET ?`

	selectDelegatableSQL = `SELECT d.permission_id,p.permission_key,p.name,
d.max_data_scope_json,d.allow_self,d.expires_at_ms
FROM permission_delegations d
JOIN permissions p ON p.id=d.permission_id AND p.scope_id=d.scope_id
WHERE d.delegator_user_id=? AND d.scope_id=? AND d.revoked_at_ms IS NULL
AND (d.expires_at_ms IS NULL OR d.expires_at_ms>?)
AND p.enabled=1 AND p.root_only=0
AND EXISTS(
  SELECT 1 FROM (
    SELECT ur.role_id,ur.scope_id FROM user_roles ur
    WHERE ur.user_id=d.delegator_user_id AND ur.scope_id=d.scope_id
    UNION ALL
    SELECT gr.role_id,gr.scope_id FROM group_members gm
    JOIN group_roles gr ON gr.group_id=gm.group_id
    WHERE gm.user_id=d.delegator_user_id AND gr.scope_id=d.scope_id
  ) chosen
  JOIN roles r ON r.id=chosen.role_id AND r.scope_id=chosen.scope_id
  JOIN role_permissions rp ON rp.role_id=r.id
  JOIN permissions hp ON hp.id=rp.permission_id AND hp.scope_id=chosen.scope_id
  WHERE hp.id=d.permission_id AND r.enabled=1 AND hp.enabled=1 AND hp.root_only=0
)
ORDER BY p.permission_key,p.id LIMIT 1000`

	insertGrantSQL = `INSERT INTO permission_delegations(
id,delegator_user_id,scope_id,permission_id,max_data_scope_json,allowed_targets_json,
allow_self,expires_at_ms,revoked_at_ms,created_by_type,created_by_id,created_at_ms,updated_at_ms
) VALUES(?,?,?,?,?,?,?,?,NULL,?,?,?,?)
ON CONFLICT(delegator_user_id,scope_id,permission_id) DO UPDATE SET
id=excluded.id,
max_data_scope_json=excluded.max_data_scope_json,
allowed_targets_json=excluded.allowed_targets_json,
allow_self=excluded.allow_self,
expires_at_ms=excluded.expires_at_ms,
revoked_at_ms=NULL,
created_by_type=excluded.created_by_type,
created_by_id=excluded.created_by_id,
created_at_ms=excluded.created_at_ms,
updated_at_ms=excluded.updated_at_ms`

	revokeGrantSQL = `UPDATE permission_delegations SET revoked_at_ms=?,updated_at_ms=?
WHERE id=? AND revoked_at_ms IS NULL`
)

// Store 是 delegation.Store 的 SQLite 实现。
type Store struct {
	store *storagesqlite.Store
}

// New 包装已打开并完成迁移的 SQLite 存储；store 为空返回 ErrOptionsInvalid。
func New(store *storagesqlite.Store) (*Store, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", delegation.ErrOptionsInvalid)
	}
	return &Store{store: store}, nil
}

// 编译期确认实现 delegation.Store。
var _ delegation.Store = (*Store)(nil)

// AccountState 在事务内读取账户状态。
func (s *Store) AccountState(ctx context.Context, tx audit.Tx, userID string) (delegation.AccountState, bool, error) {
	rows, err := queryTx(ctx, tx, selectAccountSQL, userID)
	if err != nil {
		return delegation.AccountState{}, false, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return delegation.AccountState{}, false, storeError(err)
		}
		return delegation.AccountState{}, false, nil
	}
	var (
		status string
		isRoot int
	)
	if err := rows.Scan(&status, &isRoot); err != nil {
		return delegation.AccountState{}, false, storeError(err)
	}
	parsed := account.Status(status)
	if !parsed.Valid() {
		return delegation.AccountState{}, false, fmt.Errorf("%w: 账户状态数据无效", delegation.ErrStoreUnavailable)
	}
	if err := rows.Err(); err != nil {
		return delegation.AccountState{}, false, storeError(err)
	}
	return delegation.AccountState{Status: parsed, IsRoot: isRoot == 1}, true, nil
}

// ApplicationState 在事务内读取应用状态。
func (s *Store) ApplicationState(ctx context.Context, tx audit.Tx, applicationID string) (bool, bool, error) {
	rows, err := queryTx(ctx, tx, selectApplicationSQL, applicationID)
	if err != nil {
		return false, false, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return false, false, storeError(err)
		}
		return false, false, nil
	}
	var status string
	if err := rows.Scan(&status); err != nil {
		return false, false, storeError(err)
	}
	return status == statusActive, true, nil
}

// MembershipState 在事务内读取应用成员状态。
func (s *Store) MembershipState(ctx context.Context, tx audit.Tx, applicationID, userID string) (bool, bool, error) {
	rows, err := queryTx(ctx, tx, selectMembershipSQL, applicationID, userID)
	if err != nil {
		return false, false, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return false, false, storeError(err)
		}
		return false, false, nil
	}
	var status string
	if err := rows.Scan(&status); err != nil {
		return false, false, storeError(err)
	}
	return true, status == statusActive, nil
}

// PermissionDefinition 在事务内读取权限定义。
func (s *Store) PermissionDefinition(ctx context.Context, tx audit.Tx, permissionID string) (delegation.PermissionState, bool, error) {
	return scanPermissionState(queryTx(ctx, tx, selectPermissionByIDSQL, permissionID))
}

// HeldPermission 在事务内判断操作者当前是否实际持有指定权限。
func (s *Store) HeldPermission(ctx context.Context, tx audit.Tx, userID, scopeID, permissionID string) (bool, error) {
	rows, err := queryTx(ctx, tx, selectHeldPermissionSQL, userID, scopeID, userID, scopeID, permissionID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	found := false
	if rows.Next() {
		found = true
	}
	if err := rows.Err(); err != nil {
		return false, storeError(err)
	}
	return found, nil
}

// GroupHasMember 在事务内判断用户是否为指定用户组成员。
func (s *Store) GroupHasMember(ctx context.Context, tx audit.Tx, groupID, userID string) (bool, error) {
	rows, err := queryTx(ctx, tx, selectGroupMemberSQL, groupID, userID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	found := false
	if rows.Next() {
		found = true
	}
	if err := rows.Err(); err != nil {
		return false, storeError(err)
	}
	return found, nil
}

// ScopeRestorationState 在事务内读取“启用该范围应用会被恢复”的权限与持有目标。
// 任一查询失败、结果超过检查上限或目标类型损坏都返回错误，由调用方 fail-closed。
func (s *Store) ScopeRestorationState(ctx context.Context, tx audit.Tx, scopeID string) ([]string, []delegation.Target, error) {
	rows, err := queryTx(ctx, tx, selectRestorationPermissionsSQL, scopeID, delegation.MaxPermissionRefs+1)
	if err != nil {
		return nil, nil, err
	}
	permissionIDs := make([]string, 0, 16)
	for rows.Next() {
		var permissionID string
		if err := rows.Scan(&permissionID); err != nil {
			rows.Close()
			return nil, nil, storeError(err)
		}
		permissionIDs = append(permissionIDs, permissionID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, nil, storeError(err)
	}
	rows.Close()

	rows, err = queryTx(ctx, tx, selectRestorationTargetsSQL, scopeID, scopeID, delegation.MaxAffectedTargets+1)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	targets := make([]delegation.Target, 0, 16)
	for rows.Next() {
		var (
			kind string
			id   string
		)
		if err := rows.Scan(&kind, &id); err != nil {
			return nil, nil, storeError(err)
		}
		targets = append(targets, delegation.Target{Kind: delegation.TargetKind(kind), ID: id})
	}
	if err := rows.Err(); err != nil {
		return nil, nil, storeError(err)
	}
	return permissionIDs, targets, nil
}

// LoadGrants 在事务内读取指定委派对象在指定范围的全部资格（含已撤回/过期）。
func (s *Store) LoadGrants(ctx context.Context, tx audit.Tx, delegatorUserID, scopeID string) ([]delegation.Grant, error) {
	rows, err := queryTx(ctx, tx, selectGrantsForDelegatorSQL, delegatorUserID, scopeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanGrants(rows)
}

// ResolvePermission 在事务内按 scope + 机器标识读取权限定义。
func (s *Store) ResolvePermission(ctx context.Context, tx audit.Tx, scopeID, permissionKey string) (delegation.PermissionState, bool, error) {
	return scanPermissionState(queryTx(ctx, tx, selectPermissionByKeySQL, scopeID, permissionKey))
}

// GetGrantInTx 在事务内按 ID 读取委派资格。
func (s *Store) GetGrantInTx(ctx context.Context, tx audit.Tx, id string) (delegation.Grant, error) {
	rows, err := queryTx(ctx, tx, selectGrantByIDSQL, id)
	if err != nil {
		return delegation.Grant{}, err
	}
	defer rows.Close()
	grants, err := scanGrants(rows)
	if err != nil {
		return delegation.Grant{}, err
	}
	if len(grants) == 0 {
		return delegation.Grant{}, delegation.ErrGrantNotFound
	}
	return grants[0], nil
}

// CreateOrReplaceGrant 在事务内按唯一键写入或覆盖委派资格，并返回覆盖前的快照。
func (s *Store) CreateOrReplaceGrant(ctx context.Context, tx audit.Tx, grant delegation.Grant) (*delegation.Grant, error) {
	if tx == nil {
		return nil, fmt.Errorf("%w: 审计事务为空", delegation.ErrOptionsInvalid)
	}
	previous, exists, err := s.grantByKey(ctx, tx, grant.DelegatorUserID, grant.ScopeID, grant.PermissionID)
	if err != nil {
		return nil, err
	}
	targetsJSON, encodeErr := grant.AllowedTargets.JSON()
	if encodeErr != nil {
		// 目标白名单不能编码时 fail-closed，绝不以空值（表示不限制）落库。
		return nil, fmt.Errorf("%w: %v", delegation.ErrInvalidRequest, encodeErr)
	}
	result, err := tx.ExecContext(ctx, insertGrantSQL,
		grant.ID, grant.DelegatorUserID, grant.ScopeID, grant.PermissionID,
		grant.MaxDataScope, targetsJSON, grant.AllowSelf,
		nullableTime(grant.ExpiresAt), grant.CreatedBy.Type, grant.CreatedBy.ID,
		grant.CreatedAt.UTC().UnixMilli(), grant.UpdatedAt.UTC().UnixMilli())
	if err != nil {
		return nil, storeError(err)
	}
	if _, err := result.RowsAffected(); err != nil {
		return nil, storeError(err)
	}
	if exists {
		return &previous, nil
	}
	return nil, nil
}

// RevokeGrant 在事务内条件撤回委派资格；已撤回或不存在返回 changed=false。
func (s *Store) RevokeGrant(ctx context.Context, tx audit.Tx, id string, now time.Time) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("%w: 审计事务为空", delegation.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, revokeGrantSQL,
		now.UTC().UnixMilli(), now.UTC().UnixMilli(), id)
	if err != nil {
		return false, storeError(err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, storeError(err)
	}
	return affected == 1, nil
}

// GetGrant 按 ID 读取委派资格（非事务只读）。
func (s *Store) GetGrant(ctx context.Context, id string) (delegation.Grant, error) {
	rows, err := s.query(ctx, selectGrantByIDSQL, id)
	if err != nil {
		return delegation.Grant{}, err
	}
	defer rows.Close()
	grants, err := scanGrants(rows)
	if err != nil {
		return delegation.Grant{}, err
	}
	if len(grants) == 0 {
		return delegation.Grant{}, delegation.ErrGrantNotFound
	}
	return grants[0], nil
}

// ListGrants 按委派对象/是否含已撤回查询委派资格（非事务只读）。
func (s *Store) ListGrants(ctx context.Context, query delegation.GrantQuery) ([]delegation.Grant, error) {
	rows, err := s.query(ctx, selectGrantsSQL, query.DelegatorUserID, query.DelegatorUserID,
		boolInt(query.IncludeRevoked), query.Limit, query.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanGrants(rows)
}

// DelegatablePermissions 返回操作者当前仍实际可转授的权限（非事务只读）。
func (s *Store) DelegatablePermissions(ctx context.Context, delegatorUserID, scopeID string, now time.Time) ([]delegation.DelegatablePermission, error) {
	rows, err := s.query(ctx, selectDelegatableSQL, delegatorUserID, scopeID, now.UTC().UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	permissions := make([]delegation.DelegatablePermission, 0, 16)
	for rows.Next() {
		var (
			permission     delegation.DelegatablePermission
			allowSelf      int
			expiresAtMilli sql.NullInt64
		)
		if err := rows.Scan(&permission.PermissionID, &permission.Key, &permission.Name,
			&permission.MaxDataScope, &allowSelf, &expiresAtMilli); err != nil {
			return nil, storeError(err)
		}
		permission.AllowSelf = allowSelf == 1
		permission.ExpiresAt = timeFromNull(expiresAtMilli)
		permissions = append(permissions, permission)
	}
	if err := rows.Err(); err != nil {
		return nil, storeError(err)
	}
	return permissions, nil
}

// grantByKey 在事务内按唯一键读取资格。
func (s *Store) grantByKey(ctx context.Context, tx audit.Tx, delegatorID, scopeID, permissionID string) (delegation.Grant, bool, error) {
	rows, err := queryTx(ctx, tx, selectGrantByKeySQL, delegatorID, scopeID, permissionID)
	if err != nil {
		return delegation.Grant{}, false, err
	}
	defer rows.Close()
	grants, err := scanGrants(rows)
	if err != nil {
		return delegation.Grant{}, false, err
	}
	if len(grants) == 0 {
		return delegation.Grant{}, false, nil
	}
	return grants[0], true, nil
}

// query 在连接池上执行只读查询。
func (s *Store) query(ctx context.Context, statement string, args ...any) (*sql.Rows, error) {
	if s == nil || s.store == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", delegation.ErrOptionsInvalid)
	}
	rows, err := s.store.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, storeError(err)
	}
	return rows, nil
}

// queryTx 在调用方审计事务内执行只读查询。
func queryTx(ctx context.Context, tx audit.Tx, statement string, args ...any) (*sql.Rows, error) {
	if tx == nil {
		return nil, fmt.Errorf("%w: 审计事务为空", delegation.ErrOptionsInvalid)
	}
	rows, err := tx.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, storeError(err)
	}
	return rows, nil
}

// scanPermissionState 读取并校验权限定义行。
func scanPermissionState(rows *sql.Rows, err error) (delegation.PermissionState, bool, error) {
	if err != nil {
		return delegation.PermissionState{}, false, err
	}
	defer rows.Close()
	if !rows.Next() {
		if rowsErr := rows.Err(); rowsErr != nil {
			return delegation.PermissionState{}, false, storeError(rowsErr)
		}
		return delegation.PermissionState{}, false, nil
	}
	var (
		state    delegation.PermissionState
		enabled  int
		rootOnly int
	)
	if err := rows.Scan(&state.PermissionID, &state.ScopeID, &state.Key, &state.Name, &enabled, &rootOnly); err != nil {
		return delegation.PermissionState{}, false, storeError(err)
	}
	state.Enabled = enabled == 1
	state.RootOnly = rootOnly == 1
	if err := rows.Err(); err != nil {
		return delegation.PermissionState{}, false, storeError(err)
	}
	return state, true, nil
}

// scanGrants 读取委派资格行。
func scanGrants(rows *sql.Rows) ([]delegation.Grant, error) {
	grants := make([]delegation.Grant, 0, 8)
	for rows.Next() {
		var (
			grant        delegation.Grant
			targetsJSON  string
			allowSelf    int
			expiresMilli sql.NullInt64
			revokedMilli sql.NullInt64
			createdType  string
			createdID    string
			createdMS    int64
			updatedMS    int64
		)
		if err := rows.Scan(&grant.ID, &grant.DelegatorUserID, &grant.ScopeID, &grant.PermissionID,
			&grant.PermissionKey, &grant.PermissionName, &grant.MaxDataScope, &targetsJSON,
			&allowSelf, &expiresMilli, &revokedMilli, &createdType, &createdID, &createdMS, &updatedMS); err != nil {
			return nil, storeError(err)
		}
		targets, err := delegation.ParseAllowedTargetsJSON(targetsJSON)
		if err != nil {
			return nil, fmt.Errorf("%w: 委派目标白名单数据无效", delegation.ErrStoreUnavailable)
		}
		grant.AllowedTargets = targets
		grant.AllowSelf = allowSelf == 1
		grant.ExpiresAt = timeFromNull(expiresMilli)
		grant.RevokedAt = timeFromNull(revokedMilli)
		grant.CreatedBy = audit.Actor{Type: audit.ActorKind(createdType), ID: createdID}
		grant.CreatedAt = time.UnixMilli(createdMS).UTC()
		grant.UpdatedAt = time.UnixMilli(updatedMS).UTC()
		grant.ScopeKind = delegation.ScopeKindSystem
		if grant.ScopeID != delegation.ScopeSystem {
			grant.ScopeKind = delegation.ScopeKindApplication
			grant.ApplicationID = grant.ScopeID
		}
		grants = append(grants, grant)
	}
	if err := rows.Err(); err != nil {
		return nil, storeError(err)
	}
	return grants, nil
}

// nullableTime 把可空时间转换为毫秒整数或 NULL。
func nullableTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UTC().UnixMilli()
}

// timeFromNull 把毫秒整数或 NULL 转换为可空时间。
func timeFromNull(value sql.NullInt64) *time.Time {
	if !value.Valid {
		return nil
	}
	parsed := time.UnixMilli(value.Int64).UTC()
	return &parsed
}

// boolInt 把布尔值转换为 0/1。
func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

// storeError 把底层数据库错误映射为委派存储不可用，避免泄露驱动细节。
func storeError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", delegation.ErrStoreUnavailable, err)
}
