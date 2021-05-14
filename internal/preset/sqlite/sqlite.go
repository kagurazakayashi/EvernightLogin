// Package sqlite 实现 internal/preset.Store 的 SQLite 生产仓储。
//
// 目录项（权限、角色、角色权限组合、用户组）复用步骤 22/23/24 的既有仓储实现，
// 保证与各领域服务一致的唯一约束、复合外键与条件写入语义；本包只额外维护迁移
// 0007 的 preset_installations 初始化版本记录。本包不执行迁移、不拥有数据库
// 连接；所有写入都在调用方的安全审计事务内执行。
package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
	groupsqlite "github.com/kagurazakayashi/EvernightLogin/internal/group/sqlite"
	permissionsqlite "github.com/kagurazakayashi/EvernightLogin/internal/permission/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/preset"
	rolesqlite "github.com/kagurazakayashi/EvernightLogin/internal/role/sqlite"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"

	"github.com/kagurazakayashi/EvernightLogin/internal/group"
	"github.com/kagurazakayashi/EvernightLogin/internal/permission"
	"github.com/kagurazakayashi/EvernightLogin/internal/role"
)

const (
	// 分页读取上限复用各领域仓储的最大每页数量，循环取完避免漏项。
	listPageLimit = 100

	selectInstallStateSQL = `SELECT scope_id,catalog_version,applied_at_ms,updated_at_ms
FROM preset_installations WHERE scope_id=?`

	listInstallStatesSQL = `SELECT scope_id,catalog_version,applied_at_ms,updated_at_ms
FROM preset_installations ORDER BY scope_id ASC LIMIT ? OFFSET ?`

	// saveInstallStateSQL 在调用方事务内新增或更新初始化版本记录；应用/系统范围
	// 各自独立，不共用跨应用记录。
	saveInstallStateSQL = `INSERT INTO preset_installations(
scope_id,catalog_version,applied_at_ms,updated_at_ms
) VALUES(?,?,?,?)
ON CONFLICT(scope_id) DO UPDATE SET
catalog_version=excluded.catalog_version,
applied_at_ms=excluded.applied_at_ms,
updated_at_ms=excluded.updated_at_ms`
)

// Store 是 preset.Store 的 SQLite 实现。
type Store struct {
	store       *storagesqlite.Store
	permissions *permissionsqlite.Store
	roles       *rolesqlite.Store
	groups      *groupsqlite.Store
}

// New 包装已打开且完成迁移的 SQLite 存储，并构造既有领域仓储适配器。
func New(store *storagesqlite.Store) (*Store, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: SQLite 存储为空", preset.ErrOptionsInvalid)
	}
	permissionStore, err := permissionsqlite.New(store)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", preset.ErrOptionsInvalid, err)
	}
	roleStore, err := rolesqlite.New(store)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", preset.ErrOptionsInvalid, err)
	}
	groupStore, err := groupsqlite.New(store)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", preset.ErrOptionsInvalid, err)
	}
	return &Store{store: store, permissions: permissionStore, roles: roleStore, groups: groupStore}, nil
}

// 编译期确认实现 preset.Store。
var _ preset.Store = (*Store)(nil)

// GetScope 读取作用范围与作用范围类型/应用状态。
func (s *Store) GetScope(ctx context.Context, scopeID string) (preset.ScopeInfo, error) {
	scope, err := s.permissions.GetScope(ctx, scopeID)
	if err != nil {
		return preset.ScopeInfo{}, mapStoreError(err)
	}
	kind := preset.ScopeKindSystem
	if scope.Kind == permission.ScopeKindApplication {
		kind = preset.ScopeKindApplication
	}
	return preset.ScopeInfo{
		ScopeID: scope.ScopeID, Kind: kind,
		ApplicationID: scope.ApplicationID, ApplicationActive: scope.ApplicationActive,
	}, nil
}

// ListPermissions 读取作用范围内全部权限目录项（分页取尽）。
func (s *Store) ListPermissions(ctx context.Context, scopeID string) ([]preset.PermissionRecord, error) {
	result := make([]preset.PermissionRecord, 0, 64)
	offset := 0
	for {
		records, hasMore, err := s.permissions.ListPermissions(ctx, permission.ListQuery{
			ScopeFilter: scopeID, AllScopes: true, Limit: listPageLimit, Offset: offset,
		})
		if err != nil {
			return nil, mapStoreError(err)
		}
		for _, record := range records {
			result = append(result, preset.PermissionRecord{
				ID: record.ID, ScopeID: record.ScopeID, Key: record.Key,
				Name: record.Name, Description: record.Description, Limits: record.Limits,
				IsBuiltin: record.IsBuiltin, RootOnly: record.RootOnly, Enabled: record.Enabled,
			})
		}
		if !hasMore {
			return result, nil
		}
		offset += len(records)
		if len(records) == 0 {
			return result, nil
		}
	}
}

// ListRoles 读取作用范围内全部角色（分页取尽）。
func (s *Store) ListRoles(ctx context.Context, scopeID string) ([]preset.RoleRecord, error) {
	result := make([]preset.RoleRecord, 0, 16)
	offset := 0
	for {
		records, hasMore, err := s.roles.ListRoles(ctx, role.ListQuery{
			ScopeFilter: scopeID, AllScopes: true, Limit: listPageLimit, Offset: offset,
		})
		if err != nil {
			return nil, mapStoreError(err)
		}
		for _, record := range records {
			result = append(result, preset.RoleRecord{
				ID: record.ID, ScopeID: record.ScopeID, Key: record.Key, Name: record.Name,
				Description: record.Description, Limits: record.Limits,
				IsBuiltin: record.IsBuiltin, Enabled: record.Enabled,
			})
		}
		if !hasMore {
			return result, nil
		}
		offset += len(records)
		if len(records) == 0 {
			return result, nil
		}
	}
}

// ListRolePermissions 读取角色当前组合的权限摘要。
func (s *Store) ListRolePermissions(ctx context.Context, roleID string) ([]preset.RolePermissionRecord, error) {
	summaries, err := s.roles.ListRolePermissions(ctx, roleID)
	if err != nil {
		return nil, mapStoreError(err)
	}
	result := make([]preset.RolePermissionRecord, 0, len(summaries))
	for _, summary := range summaries {
		result = append(result, preset.RolePermissionRecord{
			PermissionID: summary.PermissionID, Key: summary.Key,
			Enabled: summary.Enabled, RootOnly: summary.RootOnly,
		})
	}
	return result, nil
}

// ListGroups 读取作用范围内全部用户组（分页取尽）。
func (s *Store) ListGroups(ctx context.Context, scopeID string) ([]preset.GroupRecord, error) {
	result := make([]preset.GroupRecord, 0, 8)
	offset := 0
	for {
		records, hasMore, err := s.groups.ListGroups(ctx, group.ListQuery{
			ScopeFilter: scopeID, AllScopes: true, Limit: listPageLimit, Offset: offset,
		})
		if err != nil {
			return nil, mapStoreError(err)
		}
		for _, record := range records {
			result = append(result, preset.GroupRecord{
				ID: record.ID, ScopeID: record.ScopeID, GroupKey: record.GroupKey,
				Name: record.Name, Description: record.Description,
			})
		}
		if !hasMore {
			return result, nil
		}
		offset += len(records)
		if len(records) == 0 {
			return result, nil
		}
	}
}

// PermissionHolderTargets 在调用方事务内读取启用该权限后会重新获得它的目标。
func (s *Store) PermissionHolderTargets(ctx context.Context, tx audit.Tx, permissionID string) ([]delegation.Target, error) {
	targets, err := s.permissions.PermissionHolderTargets(ctx, tx, permissionID)
	if err != nil {
		return nil, mapStoreError(err)
	}
	return targets, nil
}

// RoleAssignmentTargets 在调用方事务内读取角色当前分配的用户与用户组目标。
func (s *Store) RoleAssignmentTargets(ctx context.Context, tx audit.Tx, roleID, scopeID string) ([]delegation.Target, error) {
	targets, err := s.roles.RoleAssignmentTargets(ctx, tx, roleID, scopeID)
	if err != nil {
		return nil, mapStoreError(err)
	}
	return targets, nil
}

// GetInstallState 读取作用范围的初始化版本记录。
func (s *Store) GetInstallState(ctx context.Context, scopeID string) (preset.InstallState, bool, error) {
	rows, err := s.store.QueryContext(ctx, selectInstallStateSQL, scopeID)
	if err != nil {
		return preset.InstallState{}, false, fmt.Errorf("%w: %w", preset.ErrStoreUnavailable, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if rowsErr := rows.Err(); rowsErr != nil {
			return preset.InstallState{}, false, fmt.Errorf("%w: %w", preset.ErrStoreUnavailable, rowsErr)
		}
		return preset.InstallState{}, false, nil
	}
	state, err := scanInstallState(rows)
	if err != nil {
		return preset.InstallState{}, false, err
	}
	if err := rows.Err(); err != nil {
		return preset.InstallState{}, false, fmt.Errorf("%w: %w", preset.ErrStoreUnavailable, err)
	}
	return state, true, nil
}

// ListInstallStates 读取全部已初始化作用范围，供显式整体恢复展开选择。
func (s *Store) ListInstallStates(ctx context.Context) ([]preset.InstallState, error) {
	result := make([]preset.InstallState, 0, 8)
	offset := 0
	for {
		rows, err := s.store.QueryContext(ctx, listInstallStatesSQL, listPageLimit+1, offset)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", preset.ErrStoreUnavailable, err)
		}
		count := 0
		hasMore := false
		for rows.Next() {
			count++
			if count > listPageLimit {
				hasMore = true
				break
			}
			state, scanErr := scanInstallState(rows)
			if scanErr != nil {
				rows.Close()
				return nil, scanErr
			}
			result = append(result, state)
		}
		if rowsErr := rows.Err(); rowsErr != nil {
			rows.Close()
			return nil, fmt.Errorf("%w: %w", preset.ErrStoreUnavailable, rowsErr)
		}
		rows.Close()
		if !hasMore {
			return result, nil
		}
		offset += listPageLimit
	}
}

// CreatePermission 在调用方事务内插入 preset 权限（固定为内置语义由调用方保证）。
func (s *Store) CreatePermission(ctx context.Context, tx audit.Tx, record preset.PermissionRecord) error {
	now := time.Now().UTC()
	err := s.permissions.CreatePermission(ctx, tx, permission.Permission{
		ID: record.ID, ScopeID: record.ScopeID, Key: record.Key, Name: record.Name,
		Description: record.Description, Limits: record.Limits,
		IsBuiltin: record.IsBuiltin, RootOnly: record.RootOnly, Enabled: record.Enabled,
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		return mapStoreError(err)
	}
	return nil
}

// UpdatePermissionText 在调用方事务内同步预设权限中文名称/说明/限制，不改变
// root_only/is_builtin/enabled 语义。
func (s *Store) UpdatePermissionText(ctx context.Context, tx audit.Tx, id, name, description, limits string, now time.Time) error {
	if err := s.permissions.UpdatePermission(ctx, tx, id, name, description, limits, now); err != nil {
		return mapStoreError(err)
	}
	return nil
}

// SetPermissionEnabled 在调用方事务内恢复预设内置权限启用状态。
func (s *Store) SetPermissionEnabled(ctx context.Context, tx audit.Tx, id string, enabled bool, now time.Time) error {
	if err := s.permissions.SetEnabled(ctx, tx, id, enabled, now); err != nil {
		return mapStoreError(err)
	}
	return nil
}

// CreateRole 在调用方事务内插入预设角色。
func (s *Store) CreateRole(ctx context.Context, tx audit.Tx, record preset.RoleRecord) error {
	now := time.Now().UTC()
	err := s.roles.CreateRole(ctx, tx, role.Role{
		ID: record.ID, ScopeID: record.ScopeID, Key: record.Key, Name: record.Name,
		Description: record.Description, Limits: record.Limits,
		IsBuiltin: record.IsBuiltin, Enabled: record.Enabled, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		return mapStoreError(err)
	}
	return nil
}

// CreateGroup 在调用方事务内插入默认用户组（空组，不加入成员）。
func (s *Store) CreateGroup(ctx context.Context, tx audit.Tx, record preset.GroupRecord) error {
	now := time.Now().UTC()
	err := s.groups.CreateGroup(ctx, tx, group.Group{
		ID: record.ID, ScopeID: record.ScopeID, GroupKey: record.GroupKey,
		Name: record.Name, Description: record.Description, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		return mapStoreError(err)
	}
	return nil
}

// AddRolePermission 在调用方事务内组合角色权限；重复组合返回 false。
func (s *Store) AddRolePermission(ctx context.Context, tx audit.Tx, roleID, permissionID, scopeID string) (bool, error) {
	changed, err := s.roles.AddRolePermission(ctx, tx, roleID, permissionID, scopeID)
	if err != nil {
		return false, mapStoreError(err)
	}
	return changed, nil
}

// RemoveRolePermission 在调用方事务内移除角色权限；不存在返回 false。
func (s *Store) RemoveRolePermission(ctx context.Context, tx audit.Tx, roleID, permissionID string) (bool, error) {
	changed, err := s.roles.RemoveRolePermission(ctx, tx, roleID, permissionID)
	if err != nil {
		return false, mapStoreError(err)
	}
	return changed, nil
}

// SaveInstallState 在调用方事务内保存初始化版本记录。
func (s *Store) SaveInstallState(ctx context.Context, tx audit.Tx, state preset.InstallState) error {
	if tx == nil {
		return fmt.Errorf("%w: 审计事务为空", preset.ErrOptionsInvalid)
	}
	result, err := tx.ExecContext(ctx, saveInstallStateSQL,
		state.ScopeID, state.CatalogVersion,
		state.AppliedAt.UTC().UnixMilli(), state.UpdatedAt.UTC().UnixMilli(),
	)
	if err != nil {
		return fmt.Errorf("%w: %w", preset.ErrStoreUnavailable, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: %w", preset.ErrStoreUnavailable, err)
	}
	if affected != 1 {
		return fmt.Errorf("%w: 保存初始化版本影响行数异常", preset.ErrStoreUnavailable)
	}
	return nil
}

// scanInstallState 从查询结果扫描初始化版本记录。
func scanInstallState(rows *sql.Rows) (preset.InstallState, error) {
	var (
		state              preset.InstallState
		appliedAt, updated int64
	)
	if err := rows.Scan(&state.ScopeID, &state.CatalogVersion, &appliedAt, &updated); err != nil {
		return preset.InstallState{}, fmt.Errorf("%w: %w", preset.ErrStoreUnavailable, err)
	}
	state.AppliedAt = time.UnixMilli(appliedAt).UTC()
	state.UpdatedAt = time.UnixMilli(updated).UTC()
	return state, nil
}

// mapStoreError 把既有领域仓储错误映射为预设领域错误：唯一键冲突映射为目录冲突，
// 作用范围/应用状态保留明确的可诊断错误，其余存储失败映射为 DB_UNAVAILABLE。
func mapStoreError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, permission.ErrPermissionKeyTaken), errors.Is(err, role.ErrRoleKeyTaken),
		errors.Is(err, group.ErrGroupKeyTaken):
		return fmt.Errorf("%w: %w", preset.ErrCatalogConflict, err)
	case errors.Is(err, permission.ErrScopeInvalid), errors.Is(err, role.ErrScopeInvalid),
		errors.Is(err, group.ErrScopeInvalid):
		return fmt.Errorf("%w: %w", preset.ErrScopeInvalid, err)
	case errors.Is(err, permission.ErrApplicationInactive), errors.Is(err, role.ErrApplicationInactive),
		errors.Is(err, group.ErrApplicationInactive):
		return fmt.Errorf("%w: %w", preset.ErrApplicationInactive, err)
	case errors.Is(err, permission.ErrPermissionNotFound), errors.Is(err, role.ErrRoleNotFound),
		errors.Is(err, group.ErrGroupNotFound):
		return fmt.Errorf("%w: %w", preset.ErrInvalidRequest, err)
	case errors.Is(err, permission.ErrStoreUnavailable), errors.Is(err, role.ErrStoreUnavailable),
		errors.Is(err, group.ErrStoreUnavailable):
		return fmt.Errorf("%w: %w", preset.ErrStoreUnavailable, err)
	case errors.Is(err, permission.ErrStateConflict), errors.Is(err, role.ErrStateConflict):
		return fmt.Errorf("%w: %w", preset.ErrStateConflict, err)
	default:
		return fmt.Errorf("%w: %w", preset.ErrStoreUnavailable, err)
	}
}

// fingerprintQueryer 是普通存储与审计事务视图共有的只读查询能力。
type fingerprintQueryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// 目录状态指纹使用的确定性查询：恢复差异计算只依赖这些行，因此它们必须与
// 预览时完全一致，恢复才能在事务内条件校验“状态未被并发修改”。
const (
	fingerprintScopeSQL = `SELECT s.kind, COALESCE(s.app_id,''), COALESCE(a.status,'')
FROM scopes s LEFT JOIN applications a ON a.id=s.app_id WHERE s.id=?`

	fingerprintInstallSQL = `SELECT catalog_version FROM preset_installations WHERE scope_id=?`

	fingerprintPermissionsSQL = `SELECT id,permission_key,name,description,limits_text,is_builtin,root_only,enabled
FROM permissions WHERE scope_id=? ORDER BY permission_key ASC, id ASC`

	fingerprintRolesSQL = `SELECT id,role_key,name,description,limits_text,is_builtin,enabled
FROM roles WHERE scope_id=? ORDER BY role_key ASC, id ASC`

	fingerprintRolePermissionsSQL = `SELECT rp.role_id,rp.permission_id FROM role_permissions rp
JOIN roles r ON r.id=rp.role_id AND r.scope_id=rp.scope_id
WHERE r.scope_id=? ORDER BY rp.role_id ASC, rp.permission_id ASC`

	fingerprintGroupsSQL = `SELECT id,group_key,name,description
FROM user_groups WHERE scope_id=? ORDER BY group_key ASC, id ASC`
)

// SnapshotFingerprint 实现 preset.Store：事务外记录预览时目录状态摘要。
func (s *Store) SnapshotFingerprint(ctx context.Context, scopeIDs []string) (string, error) {
	return snapshotFingerprint(ctx, s.store, scopeIDs)
}

// SnapshotFingerprintTx 实现 preset.Store：在调用方事务内重算同一摘要，供恢复在
// 写入前做 TOCTOU 条件校验。
func (s *Store) SnapshotFingerprintTx(ctx context.Context, tx audit.Tx, scopeIDs []string) (string, error) {
	if tx == nil {
		return "", fmt.Errorf("%w: 审计事务为空", preset.ErrOptionsInvalid)
	}
	return snapshotFingerprint(ctx, tx, scopeIDs)
}

// snapshotFingerprint 用长度前缀编码把各作用范围目录状态串成稳定摘要，避免字段
// 拼接歧义；读取失败返回 DB_UNAVAILABLE，绝不返回“看似一致”的空摘要。
func snapshotFingerprint(ctx context.Context, queryer fingerprintQueryer, scopeIDs []string) (string, error) {
	if len(scopeIDs) == 0 {
		return "", fmt.Errorf("%w: 缺少作用范围", preset.ErrInvalidRequest)
	}
	hasher := sha256.New()
	var prefix [8]byte
	write := func(values ...string) {
		for _, value := range values {
			binary.LittleEndian.PutUint64(prefix[:], uint64(len(value)))
			_, _ = hasher.Write(prefix[:])
			_, _ = hasher.Write([]byte(value))
		}
	}
	for _, scopeID := range scopeIDs {
		write("scope", scopeID)
		if err := eachRow(ctx, queryer, fingerprintScopeSQL, scopeID, func(rows *sql.Rows) error {
			var kind, appID, status string
			if err := rows.Scan(&kind, &appID, &status); err != nil {
				return err
			}
			write(kind, appID, status)
			return nil
		}); err != nil {
			return "", mapStoreError(err)
		}
		if err := eachRow(ctx, queryer, fingerprintInstallSQL, scopeID, func(rows *sql.Rows) error {
			var version string
			if err := rows.Scan(&version); err != nil {
				return err
			}
			write("install", version)
			return nil
		}); err != nil {
			return "", mapStoreError(err)
		}
		if err := eachRow(ctx, queryer, fingerprintPermissionsSQL, scopeID, func(rows *sql.Rows) error {
			var id, key, name, description, limits string
			var builtin, rootOnly, enabled int
			if err := rows.Scan(&id, &key, &name, &description, &limits, &builtin, &rootOnly, &enabled); err != nil {
				return err
			}
			write("permission", id, key, name, description, limits,
				strconv.Itoa(builtin), strconv.Itoa(rootOnly), strconv.Itoa(enabled))
			return nil
		}); err != nil {
			return "", mapStoreError(err)
		}
		if err := eachRow(ctx, queryer, fingerprintRolesSQL, scopeID, func(rows *sql.Rows) error {
			var id, key, name, description, limits string
			var builtin, enabled int
			if err := rows.Scan(&id, &key, &name, &description, &limits, &builtin, &enabled); err != nil {
				return err
			}
			write("role", id, key, name, description, limits, strconv.Itoa(builtin), strconv.Itoa(enabled))
			return nil
		}); err != nil {
			return "", mapStoreError(err)
		}
		if err := eachRow(ctx, queryer, fingerprintRolePermissionsSQL, scopeID, func(rows *sql.Rows) error {
			var roleID, permissionID string
			if err := rows.Scan(&roleID, &permissionID); err != nil {
				return err
			}
			write("role_permission", roleID, permissionID)
			return nil
		}); err != nil {
			return "", mapStoreError(err)
		}
		if err := eachRow(ctx, queryer, fingerprintGroupsSQL, scopeID, func(rows *sql.Rows) error {
			var id, key, name, description string
			if err := rows.Scan(&id, &key, &name, &description); err != nil {
				return err
			}
			write("group", id, key, name, description)
			return nil
		}); err != nil {
			return "", mapStoreError(err)
		}
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// eachRow 在给定查询上迭代，并把每行交给回调处理。
func eachRow(ctx context.Context, queryer fingerprintQueryer, query string, scopeID string, scan func(*sql.Rows) error) error {
	rows, err := queryer.QueryContext(ctx, query, scopeID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := scan(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}
