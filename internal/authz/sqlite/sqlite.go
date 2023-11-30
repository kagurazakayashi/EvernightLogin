// Package sqlite 实现 internal/authz.Reader/Store 的 SQLite 只读快照。
//
// 所有读取在调用方 Store.Snapshot 打开的同一数据库事务中完成，保证账户、应用、
// 成员、角色、权限与分配的一致性。本包不写数据、不执行迁移，也不缓存权限结果。
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

const (
	selectAccountSQL = `SELECT id,status,is_root,valid_from_ms,valid_until_ms FROM users WHERE id=?`

	selectApplicationSQL = `SELECT id,status FROM applications WHERE id=?`

	selectMembershipSQL = `SELECT status FROM app_memberships WHERE app_id=? AND user_id=?`

	selectPermissionSQL = `SELECT id,scope_id,permission_key,name,enabled,root_only
FROM permissions WHERE scope_id=? AND permission_key=?`

	selectGrantedPermissionsSQL = `SELECT DISTINCT p.id,p.scope_id,p.permission_key,p.name,p.enabled,p.root_only
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
ORDER BY p.permission_key,p.id LIMIT ? OFFSET ?`

	// selectSourcesTemplate 使用 %s 作为权限 ID IN 占位符；两段对应直接用户角色与
	// 用户组角色来源。仓储只依据 (user_id, scope_id) 与权限 ID 过滤，不拼接调用方
	// 自由文本。
	selectSourcesFormat = `SELECT * FROM (
  SELECT p.id AS permission_id,p.permission_key AS permission_key,p.name AS permission_name,
         p.enabled AS permission_enabled,p.root_only AS permission_root_only,
         r.id AS role_id,r.role_key AS role_key,r.name AS role_name,r.enabled AS role_enabled,
         r.scope_id AS scope_id,
         'user_role' AS kind,NULL AS group_id,NULL AS group_key,NULL AS group_name,
         ur.data_scope_json AS data_scope_json,ur.assigned_by AS assigned_by,
         ur.created_at_ms AS created_at_ms
  FROM user_roles ur
  JOIN roles r ON r.id=ur.role_id AND r.scope_id=?
  JOIN role_permissions rp ON rp.role_id=r.id
  JOIN permissions p ON p.id=rp.permission_id AND p.scope_id=r.scope_id
  WHERE ur.user_id=? AND p.id IN (%s)
  UNION ALL
  SELECT p.id AS permission_id,p.permission_key AS permission_key,p.name AS permission_name,
         p.enabled AS permission_enabled,p.root_only AS permission_root_only,
         r.id AS role_id,r.role_key AS role_key,r.name AS role_name,r.enabled AS role_enabled,
         r.scope_id AS scope_id,
         'group_role' AS kind,g.id AS group_id,g.group_key AS group_key,g.name AS group_name,
         gr.data_scope_json AS data_scope_json,'' AS assigned_by,
         gr.created_at_ms AS created_at_ms
  FROM group_members gm
  JOIN group_roles gr ON gr.group_id=gm.group_id AND gr.scope_id=?
  JOIN roles r ON r.id=gr.role_id AND r.scope_id=?
  JOIN role_permissions rp ON rp.role_id=r.id
  JOIN permissions p ON p.id=rp.permission_id AND p.scope_id=r.scope_id
  JOIN user_groups g ON g.id=gr.group_id AND g.scope_id=gr.scope_id
  WHERE gm.user_id=? AND p.id IN (%s)
) sources
ORDER BY permission_id,kind,role_id,group_id,created_at_ms
LIMIT ? OFFSET ?`
)

// Store 是 authz.Store 的 SQLite 实现。
type Store struct {
	store *storagesqlite.Store
}

// New 包装已打开且完成迁移的 SQLite 存储。
func New(store *storagesqlite.Store) (*Store, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", authz.ErrOptionsInvalid)
	}
	return &Store{store: store}, nil
}

// 编译期确认实现 authz.Store。
var _ authz.Store = (*Store)(nil)

// Snapshot 在单个数据库事务中执行只读回调。事务使用存储层已配置的有界忙等待；
// 第一版以一致性优先，读取期间可能与并发写事务竞争，不做无锁脏读。回调返回错误
// 时事务整体回滚；本包只读，不回写任何状态。
func (s *Store) Snapshot(ctx context.Context, fn func(ctx context.Context, reader authz.Reader) error) error {
	if s == nil || s.store == nil {
		return fmt.Errorf("%w: SQLite 存储为空", authz.ErrOptionsInvalid)
	}
	if fn == nil {
		return fmt.Errorf("%w: 快照回调为空", authz.ErrOptionsInvalid)
	}
	return s.store.Transaction(ctx, func(txCtx context.Context, tx *sql.Tx) error {
		return fn(txCtx, &snapshotReader{tx: tx})
	})
}

// snapshotReader 是事务内的只读查询器。
type snapshotReader struct {
	tx *sql.Tx
}

// Account 读取账户状态。
func (r *snapshotReader) Account(ctx context.Context, userID string) (authz.AccountInfo, bool, error) {
	rows, err := r.tx.QueryContext(ctx, selectAccountSQL, userID)
	if err != nil {
		return authz.AccountInfo{}, false, storeError(err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return authz.AccountInfo{}, false, storeError(err)
		}
		return authz.AccountInfo{}, false, nil
	}
	var (
		info         authz.AccountInfo
		status       string
		isRoot       int
		validFromMS  sql.NullInt64
		validUntilMS sql.NullInt64
	)
	if err := rows.Scan(&info.UserID, &status, &isRoot, &validFromMS,
		&validUntilMS); err != nil {
		return authz.AccountInfo{}, false, storeError(err)
	}
	parsed := account.Status(status)
	if status == "" || !parsed.Valid() {
		return authz.AccountInfo{}, false, fmt.Errorf("%w: 账户状态数据无效", authz.ErrStoreUnavailable)
	}
	info.Status = parsed
	info.IsRoot = isRoot == 1
	info.ValidFrom = authzTimeFromMilli(validFromMS)
	info.ValidUntil = authzTimeFromMilli(validUntilMS)
	if err := rows.Err(); err != nil {
		return authz.AccountInfo{}, false, storeError(err)
	}
	return info, true, nil
}

// Application 读取应用状态。
func (r *snapshotReader) Application(ctx context.Context, applicationID string) (authz.ApplicationInfo, bool, error) {
	rows, err := r.tx.QueryContext(ctx, selectApplicationSQL, applicationID)
	if err != nil {
		return authz.ApplicationInfo{}, false, storeError(err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return authz.ApplicationInfo{}, false, storeError(err)
		}
		return authz.ApplicationInfo{}, false, nil
	}
	var (
		info   authz.ApplicationInfo
		status string
	)
	if err := rows.Scan(&info.ApplicationID, &status); err != nil {
		return authz.ApplicationInfo{}, false, storeError(err)
	}
	info.Status = app.Status(status)
	if !info.Status.Valid() {
		return authz.ApplicationInfo{}, false, fmt.Errorf("%w: 应用状态数据无效", authz.ErrStoreUnavailable)
	}
	if err := rows.Err(); err != nil {
		return authz.ApplicationInfo{}, false, storeError(err)
	}
	return info, true, nil
}

// Membership 读取应用成员状态。
func (r *snapshotReader) Membership(ctx context.Context, applicationID, userID string) (authz.MembershipInfo, error) {
	info := authz.MembershipInfo{ApplicationID: applicationID, UserID: userID}
	rows, err := r.tx.QueryContext(ctx, selectMembershipSQL, applicationID, userID)
	if err != nil {
		return authz.MembershipInfo{}, storeError(err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return authz.MembershipInfo{}, storeError(err)
		}
		return info, nil
	}
	var status string
	if err := rows.Scan(&status); err != nil {
		return authz.MembershipInfo{}, storeError(err)
	}
	parsed := app.MembershipStatus(status)
	if !parsed.Valid() {
		return authz.MembershipInfo{}, fmt.Errorf("%w: 应用成员状态数据无效", authz.ErrStoreUnavailable)
	}
	info.Status = parsed
	info.Found = true
	if err := rows.Err(); err != nil {
		return authz.MembershipInfo{}, storeError(err)
	}
	return info, nil
}

// Permission 读取指定 scope 的权限定义。
func (r *snapshotReader) Permission(ctx context.Context, scopeID, key string) (authz.PermissionInfo, bool, error) {
	rows, err := r.tx.QueryContext(ctx, selectPermissionSQL, scopeID, key)
	if err != nil {
		return authz.PermissionInfo{}, false, storeError(err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return authz.PermissionInfo{}, false, storeError(err)
		}
		return authz.PermissionInfo{}, false, nil
	}
	info, scanErr := scanPermission(rows)
	if scanErr != nil {
		return authz.PermissionInfo{}, false, scanErr
	}
	if err := rows.Err(); err != nil {
		return authz.PermissionInfo{}, false, storeError(err)
	}
	return info, true, nil
}

// GrantedPermissions 返回已过滤停用角色/权限与 root_only 的有效权限页。
func (r *snapshotReader) GrantedPermissions(ctx context.Context, scopeID, userID string, limit, offset int) ([]authz.PermissionInfo, bool, error) {
	rows, err := r.tx.QueryContext(ctx, selectGrantedPermissionsSQL, userID, scopeID, userID, scopeID, limit+1, offset)
	if err != nil {
		return nil, false, storeError(err)
	}
	defer rows.Close()
	permissions := make([]authz.PermissionInfo, 0, limit+1)
	for rows.Next() {
		info, scanErr := scanPermission(rows)
		if scanErr != nil {
			return nil, false, scanErr
		}
		permissions = append(permissions, info)
	}
	if err := rows.Err(); err != nil {
		return nil, false, storeError(err)
	}
	hasMore := false
	if len(permissions) > limit {
		hasMore = true
		permissions = permissions[:limit]
	}
	return permissions, hasMore, nil
}

// PermissionSources 返回权限候选来源（含停用/被限制项），按固定次序分页。
func (r *snapshotReader) PermissionSources(ctx context.Context, scopeID, userID string, permissionIDs []string, limit, offset int) ([]authz.GrantSource, bool, error) {
	if len(permissionIDs) == 0 {
		return []authz.GrantSource{}, false, nil
	}
	if len(permissionIDs) > 256 {
		return nil, false, fmt.Errorf("%w: 来源查询权限数量过多", authz.ErrInvalidRequest)
	}
	if limit <= 0 || limit > authz.MaxSourceRows {
		return nil, false, fmt.Errorf("%w: 来源查询数量边界无效", authz.ErrInvalidRequest)
	}
	placeholders := make([]string, len(permissionIDs))
	args := make([]any, 0, len(permissionIDs)*2+7)
	args = append(args, scopeID, userID)
	for index, permissionID := range permissionIDs {
		placeholders[index] = "?"
		args = append(args, permissionID)
	}
	args = append(args, scopeID, scopeID, userID)
	for _, permissionID := range permissionIDs {
		args = append(args, permissionID)
	}
	args = append(args, limit+1, offset)
	inClause := strings.Join(placeholders, ",")
	statement := fmt.Sprintf(selectSourcesFormat, inClause, inClause)
	rows, err := r.tx.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, false, storeError(err)
	}
	defer rows.Close()
	sources := make([]authz.GrantSource, 0, limit+1)
	for rows.Next() {
		source, scanErr := scanSource(rows)
		if scanErr != nil {
			return nil, false, scanErr
		}
		sources = append(sources, source)
	}
	if err := rows.Err(); err != nil {
		return nil, false, storeError(err)
	}
	hasMore := false
	if len(sources) > limit {
		hasMore = true
		sources = sources[:limit]
	}
	return sources, hasMore, nil
}

// scanPermission 读取权限快照并校验状态与 scope 一致性。
func scanPermission(rows *sql.Rows) (authz.PermissionInfo, error) {
	var (
		info     authz.PermissionInfo
		enabled  int
		rootOnly int
	)
	if err := rows.Scan(&info.PermissionID, &info.ScopeID, &info.Key, &info.Name, &enabled, &rootOnly); err != nil {
		return authz.PermissionInfo{}, storeError(err)
	}
	if info.PermissionID == "" || info.ScopeID == "" || info.Key == "" {
		return authz.PermissionInfo{}, fmt.Errorf("%w: 权限数据不完整", authz.ErrStoreUnavailable)
	}
	info.Enabled = enabled == 1
	info.RootOnly = rootOnly == 1
	return info, nil
}

// scanSource 读取候选来源快照。
func scanSource(rows *sql.Rows) (authz.GrantSource, error) {
	var (
		source       authz.GrantSource
		permissionOn int
		rootOnly     int
		roleEnabled  int
		kind         string
		groupID      sql.NullString
		groupKey     sql.NullString
		groupName    sql.NullString
		assignedBy   string
		createdAtMS  int64
	)
	if err := rows.Scan(
		&source.PermissionID, &source.PermissionKey, &source.PermissionName,
		&permissionOn, &rootOnly,
		&source.RoleID, &source.RoleKey, &source.RoleName, &roleEnabled, &source.ScopeID,
		&kind, &groupID, &groupKey, &groupName,
		&source.DataScopeJSON, &assignedBy, &createdAtMS,
	); err != nil {
		return authz.GrantSource{}, storeError(err)
	}
	source.PermissionEnabled = permissionOn == 1
	source.PermissionRootOnly = rootOnly == 1
	source.RoleEnabled = roleEnabled == 1
	source.Kind = authz.SourceKind(kind)
	if source.Kind != authz.SourceKindUserRole && source.Kind != authz.SourceKindGroupRole {
		return authz.GrantSource{}, fmt.Errorf("%w: 权限来源类型数据无效", authz.ErrStoreUnavailable)
	}
	source.GroupID = groupID.String
	source.GroupKey = groupKey.String
	source.GroupName = groupName.String
	source.AssignedBy = assignedBy
	source.CreatedAt = time.UnixMilli(createdAtMS).UTC()
	return source, nil
}

// storeError 把底层数据库错误映射为授权存储不可用，避免泄露驱动细节。
func storeError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", authz.ErrStoreUnavailable, err)
}

// authzTimeFromMilli 把可空毫秒列转成 UTC 时间；NULL 表示该端不限制。
func authzTimeFromMilli(value sql.NullInt64) *time.Time {
	if !value.Valid {
		return nil
	}
	converted := time.UnixMilli(value.Int64).UTC()
	return &converted
}
