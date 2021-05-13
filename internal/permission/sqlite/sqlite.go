// Package sqlite 实现 internal/permission.Store 的 SQLite 生产仓储。
//
// 表结构来自 migrations/0001_identity_and_scope_core.sql 的 permissions 表与
// role_permissions 引用表；本包不执行迁移。权限以 (scope_id, permission_key) 唯一，
// scope_id 引用 scopes(id)：系统固定 "system"，应用 scope ID 与应用 ID 相同。
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
	"github.com/kagurazakayashi/EvernightLogin/internal/permission"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

const (
	permissionColumns = `p.id,p.scope_id,p.permission_key,p.name,p.description,p.limits_text,p.is_builtin,p.root_only,p.enabled,p.created_at_ms,p.updated_at_ms`

	selectPermissionByIDSQL = `SELECT ` + permissionColumns + ` FROM permissions p WHERE p.id=?`

	selectPermissionScopeSQL = `SELECT scope_id FROM permissions WHERE id=?`

	insertPermissionSQL = `INSERT INTO permissions(
id,scope_id,permission_key,name,description,limits_text,is_builtin,root_only,enabled,created_at_ms,updated_at_ms
) VALUES(?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(scope_id,permission_key) DO NOTHING`

	updatePermissionSQL = `UPDATE permissions SET name=?,description=?,limits_text=?,updated_at_ms=? WHERE id=?`

	setPermissionEnabledSQL = `UPDATE permissions SET enabled=?,updated_at_ms=? WHERE id=?`

	countPermissionReferencesSQL = `SELECT COUNT(*) FROM role_permissions WHERE permission_id=?`

	deletePermissionSQL = `DELETE FROM permissions WHERE id=? AND NOT EXISTS(SELECT 1 FROM role_permissions WHERE permission_id=?)`

	selectSystemScopeSQL = `SELECT 1 FROM scopes WHERE id='system' AND kind='system'`

	// selectPermissionHolderTargetsSQL 读取“权限被启用后会重新获得它”的目标：组合
	// 该权限的启用角色当前分配的用户与用户组。启用权限等于恢复这些持有路径，必须
	// 按委派目标限制复核；停用是收缩路径，不需要目标集合。
	selectPermissionHolderTargetsSQL = `
SELECT 'user',ur.user_id FROM user_roles ur
JOIN roles r ON r.id=ur.role_id AND r.scope_id=ur.scope_id
JOIN role_permissions rp ON rp.role_id=r.id AND rp.scope_id=r.scope_id
WHERE rp.permission_id=? AND r.enabled=1
UNION
SELECT 'group',gr.group_id FROM group_roles gr
JOIN roles r ON r.id=gr.role_id AND r.scope_id=gr.scope_id
JOIN role_permissions rp ON rp.role_id=r.id AND rp.scope_id=r.scope_id
WHERE rp.permission_id=? AND r.enabled=1
ORDER BY 1,2 LIMIT ?`

	selectApplicationScopeSQL = `SELECT a.status FROM applications a
JOIN scopes s ON s.id=? AND s.kind='application' AND s.app_id=a.id WHERE a.id=?`
)

// Store 是 permission.Store 的 SQLite 实现。
type Store struct {
	store *storagesqlite.Store
}

// New 包装已打开且完成迁移的 SQLite 存储。
func New(store *storagesqlite.Store) (*Store, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", permission.ErrOptionsInvalid)
	}
	return &Store{store: store}, nil
}

// 编译期确认实现 permission.Store。
var _ permission.Store = (*Store)(nil)

// GetScope 读取作用范围并确认应用状态。
func (s *Store) GetScope(ctx context.Context, scopeID string) (permission.ScopeInfo, error) {
	kind, applicationID, err := permission.ParseScope(scopeID)
	if err != nil {
		return permission.ScopeInfo{}, err
	}
	if kind == permission.ScopeKindSystem {
		rows, queryErr := s.store.QueryContext(ctx, selectSystemScopeSQL)
		if queryErr != nil {
			return permission.ScopeInfo{}, fmt.Errorf("%w: %w", permission.ErrStoreUnavailable, queryErr)
		}
		defer rows.Close()
		if !rows.Next() {
			return permission.ScopeInfo{}, permission.ErrScopeInvalid
		}
		return permission.ScopeInfo{ScopeID: permission.ScopeSystem, Kind: permission.ScopeKindSystem}, nil
	}
	rows, queryErr := s.store.QueryContext(ctx, selectApplicationScopeSQL, scopeID, applicationID)
	if queryErr != nil {
		return permission.ScopeInfo{}, fmt.Errorf("%w: %w", permission.ErrStoreUnavailable, queryErr)
	}
	defer rows.Close()
	if !rows.Next() {
		return permission.ScopeInfo{}, permission.ErrScopeInvalid
	}
	var status string
	if err := rows.Scan(&status); err != nil {
		return permission.ScopeInfo{}, fmt.Errorf("%w: %w", permission.ErrStoreUnavailable, err)
	}
	return permission.ScopeInfo{
		ScopeID: scopeID, Kind: permission.ScopeKindApplication,
		ApplicationID: applicationID, ApplicationActive: status == string(app.StatusActive),
	}, nil
}

// CreatePermission 在审计事务中插入权限；同 scope 机器标识冲突返回 CONFLICT 语义。
func (s *Store) CreatePermission(ctx context.Context, tx audit.Tx, record permission.Permission) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", permission.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, insertPermissionSQL,
		record.ID,
		record.ScopeID,
		record.Key,
		record.Name,
		record.Description,
		record.Limits,
		boolToInt(record.IsBuiltin),
		boolToInt(record.RootOnly),
		boolToInt(record.Enabled),
		record.CreatedAt.UTC().UnixMilli(),
		record.UpdatedAt.UTC().UnixMilli(),
	)
	if err != nil {
		return fmt.Errorf("%w: %w", permission.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: %w", permission.ErrStoreUnavailable, err)
	}
	if affected == 0 {
		return permission.ErrPermissionKeyTaken
	}
	if affected != 1 {
		return fmt.Errorf("%w: 插入权限影响行数异常", permission.ErrStoreUnavailable)
	}
	return nil
}

// GetPermission 按稳定 ID 读取权限。
func (s *Store) GetPermission(ctx context.Context, id string) (permission.Permission, error) {
	rows, err := s.store.QueryContext(ctx, selectPermissionByIDSQL, id)
	if err != nil {
		return permission.Permission{}, fmt.Errorf("%w: %w", permission.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return permission.Permission{}, fmt.Errorf("%w: %w", permission.ErrStoreUnavailable, err)
		}
		return permission.Permission{}, permission.ErrPermissionNotFound
	}
	record, err := scanPermission(rows)
	if err != nil {
		return permission.Permission{}, err
	}
	return record, rows.Err()
}

// GetPermissionScope 只读取权限 scope，供先鉴权后读取完整记录。
func (s *Store) GetPermissionScope(ctx context.Context, id string) (string, error) {
	rows, err := s.store.QueryContext(ctx, selectPermissionScopeSQL, id)
	if err != nil {
		return "", fmt.Errorf("%w: %w", permission.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return "", fmt.Errorf("%w: %w", permission.ErrStoreUnavailable, err)
		}
		return "", permission.ErrPermissionNotFound
	}
	var scopeID string
	if err := rows.Scan(&scopeID); err != nil {
		return "", fmt.Errorf("%w: %w", permission.ErrStoreUnavailable, err)
	}
	return scopeID, rows.Err()
}

// ListPermissions 在可管理范围内分页查询；排序固定为创建时间与 ID。
func (s *Store) ListPermissions(ctx context.Context, query permission.ListQuery) ([]permission.Permission, bool, error) {
	statement := `SELECT ` + permissionColumns + ` FROM permissions p`
	conditions := make([]string, 0, 3)
	args := make([]any, 0, 8)
	if query.ScopeFilter != "" {
		conditions = append(conditions, "p.scope_id=?")
		args = append(args, query.ScopeFilter)
	} else if !query.AllScopes {
		if len(query.ScopeIDs) == 0 {
			return []permission.Permission{}, false, nil
		}
		placeholders := make([]string, len(query.ScopeIDs))
		for index, scopeID := range query.ScopeIDs {
			placeholders[index] = "?"
			args = append(args, scopeID)
		}
		conditions = append(conditions, "p.scope_id IN ("+strings.Join(placeholders, ",")+")")
	}
	if query.Enabled != nil {
		conditions = append(conditions, "p.enabled=?")
		args = append(args, boolToInt(*query.Enabled))
	}
	if len(conditions) > 0 {
		statement += ` WHERE ` + strings.Join(conditions, " AND ")
	}
	statement += ` ORDER BY p.created_at_ms ASC, p.id ASC LIMIT ? OFFSET ?`
	args = append(args, query.Limit+1, query.Offset)
	rows, err := s.store.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %w", permission.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	records := make([]permission.Permission, 0, query.Limit+1)
	for rows.Next() {
		record, scanErr := scanPermission(rows)
		if scanErr != nil {
			return nil, false, scanErr
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("%w: %w", permission.ErrStoreUnavailable, err)
	}
	hasMore := false
	if len(records) > query.Limit {
		hasMore = true
		records = records[:query.Limit]
	}
	return records, hasMore, nil
}

// UpdatePermission 更新自定义权限名称/说明/限制；key/scope/builtin/root_only 不在
// SQL 中，无法被修改。
func (s *Store) UpdatePermission(ctx context.Context, tx audit.Tx, id, name, description, limits string, now time.Time) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", permission.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, updatePermissionSQL, name, description, limits, now.UTC().UnixMilli(), id)
	if err != nil {
		return fmt.Errorf("%w: %w", permission.ErrStoreUnavailable, err)
	}
	return checkAffected(result)
}

// SetEnabled 执行条件启停更新；重复调用由服务幂等短路。
func (s *Store) SetEnabled(ctx context.Context, tx audit.Tx, id string, enabled bool, now time.Time) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", permission.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, setPermissionEnabledSQL, boolToInt(enabled), now.UTC().UnixMilli(), id)
	if err != nil {
		return fmt.Errorf("%w: %w", permission.ErrStoreUnavailable, err)
	}
	return checkAffected(result)
}

// PermissionHolderTargets 在调用方事务内读取“启用该权限后会重新获得它”的用户与
// 用户组目标（组合该权限的启用角色的当前分配）。超过检查上限返回错误，由调用方
// fail-closed；查询失败同样不返回部分结果。
func (s *Store) PermissionHolderTargets(ctx context.Context, tx audit.Tx, permissionID string) ([]delegation.Target, error) {
	if tx == nil {
		return nil, fmt.Errorf("%w: 审计事务为空", permission.ErrOptionsInvalid)
	}
	rows, err := tx.QueryContext(ctx, selectPermissionHolderTargetsSQL,
		permissionID, permissionID, delegation.MaxAffectedTargets+1)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", permission.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	targets := make([]delegation.Target, 0, 8)
	for rows.Next() {
		var (
			kind string
			id   string
		)
		if err := rows.Scan(&kind, &id); err != nil {
			return nil, fmt.Errorf("%w: %w", permission.ErrStoreUnavailable, err)
		}
		targets = append(targets, delegation.Target{Kind: delegation.TargetKind(kind), ID: id})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", permission.ErrStoreUnavailable, err)
	}
	return targets, nil
}

// CountReferences 返回 role_permissions 对权限的引用数量。
func (s *Store) CountReferences(ctx context.Context, id string) (int, error) {
	rows, err := s.store.QueryContext(ctx, countPermissionReferencesSQL, id)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", permission.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return 0, fmt.Errorf("%w: %w", permission.ErrStoreUnavailable, err)
		}
		return 0, nil
	}
	var count int
	if err := rows.Scan(&count); err != nil {
		return 0, fmt.Errorf("%w: %w", permission.ErrStoreUnavailable, err)
	}
	return count, rows.Err()
}

// DeletePermission 条件删除权限并确认无 role_permissions 引用；有引用（含并发新增）
// 时返回 ErrPermissionInUse，让调用方按冲突处理而不是隐式级联。
func (s *Store) DeletePermission(ctx context.Context, tx audit.Tx, id string) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", permission.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, deletePermissionSQL, id, id)
	if err != nil {
		return fmt.Errorf("%w: %w", permission.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: %w", permission.ErrStoreUnavailable, err)
	}
	switch affected {
	case 1:
		return nil
	case 0:
		return permission.ErrPermissionInUse
	default:
		return fmt.Errorf("%w: 删除权限影响行数异常", permission.ErrStoreUnavailable)
	}
}

// checkAffected 把条件更新结果转换为领域错误。
func checkAffected(result sql.Result) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: %w", permission.ErrStoreUnavailable, err)
	}
	switch affected {
	case 1:
		return nil
	case 0:
		return permission.ErrPermissionNotFound
	default:
		return fmt.Errorf("%w: 条件更新影响行数异常", permission.ErrStoreUnavailable)
	}
}

// scanPermission 读取一行权限并校验 ID/scope/key/布尔字段。
func scanPermission(rows *sql.Rows) (permission.Permission, error) {
	var (
		record      permission.Permission
		isBuiltin   int
		rootOnly    int
		enabled     int
		createdAtMS int64
		updatedAtMS int64
	)
	if err := rows.Scan(&record.ID, &record.ScopeID, &record.Key, &record.Name,
		&record.Description, &record.Limits, &isBuiltin, &rootOnly, &enabled,
		&createdAtMS, &updatedAtMS); err != nil {
		return permission.Permission{}, fmt.Errorf("%w: %w", permission.ErrStoreUnavailable, err)
	}
	if !permission.ValidPermissionID(record.ID) {
		return permission.Permission{}, fmt.Errorf("%w: 权限 ID 数据格式无效", permission.ErrStoreUnavailable)
	}
	key, err := permission.ValidateKey(record.Key)
	if err != nil {
		return permission.Permission{}, fmt.Errorf("%w: 权限机器标识数据无效", permission.ErrStoreUnavailable)
	}
	record.Key = key
	record.Group = permission.KeyGroup(key)
	kind, applicationID, err := permission.ParseScope(record.ScopeID)
	if err != nil {
		return permission.Permission{}, fmt.Errorf("%w: 权限作用范围数据无效", permission.ErrStoreUnavailable)
	}
	record.ScopeKind = kind
	record.ApplicationID = applicationID
	if isBuiltin != 0 && isBuiltin != 1 || rootOnly != 0 && rootOnly != 1 || enabled != 0 && enabled != 1 {
		return permission.Permission{}, fmt.Errorf("%w: 权限布尔字段数据无效", permission.ErrStoreUnavailable)
	}
	record.IsBuiltin = isBuiltin == 1
	record.RootOnly = rootOnly == 1
	record.Enabled = enabled == 1
	record.CreatedAt = time.UnixMilli(createdAtMS).UTC()
	record.UpdatedAt = time.UnixMilli(updatedAtMS).UTC()
	return record, nil
}

// boolToInt 把布尔转换为 SQLite INTEGER 0/1。
func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
