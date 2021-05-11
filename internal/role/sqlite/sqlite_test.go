package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/role"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const (
	testApplicationID = "app_00000000000000000000000000000001"
	testUserID        = "usr_00000000000000000000000000000001"
	testPermissionID  = "perm_00000000000000000000000000000001"
	testGroupID       = "grp_00000000000000000000000000000001"
	testRoleKey       = "ops.manage"
)

func openMigratedStore(t *testing.T) *storagesqlite.Store {
	t.Helper()
	ctx := context.Background()
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(filepath.Join(t.TempDir(), "role.sqlite")))
	if err != nil {
		t.Fatalf("打开临时数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	migrationSet, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移失败: %v", err)
	}
	if _, err := raw.Migrate(ctx, migrationSet); err != nil {
		t.Fatalf("执行迁移失败: %v", err)
	}
	return raw
}

// testAuditTx 是只实现 ExecContext 的审计事务适配器；仓储直接测试不需要写审计。
type testAuditTx struct {
	tx *sql.Tx
}

func (t testAuditTx) AppendEvent(context.Context, audit.Event) error { return nil }

func (t testAuditTx) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return t.tx.ExecContext(ctx, query, args...)
}

// runTx 在真实 SQLite 事务中执行仓储写入，通过 testAuditTx 适配角色仓储契约。
func runTx(t *testing.T, raw *storagesqlite.Store, fn func(context.Context, audit.Tx) error) error {
	t.Helper()
	return raw.Transaction(context.Background(), func(ctx context.Context, tx *sql.Tx) error {
		return fn(ctx, testAuditTx{tx: tx})
	})
}

func TestNewValidation(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("空存储应被拒绝")
	}
}

func TestScopeQueries(t *testing.T) {
	raw := openMigratedStore(t)
	store, err := New(raw)
	if err != nil {
		t.Fatalf("构造仓储失败: %v", err)
	}
	ctx := context.Background()
	if info, err := store.GetScope(ctx, role.ScopeSystem); err != nil || info.Kind != role.ScopeKindSystem {
		t.Fatalf("系统 scope = %+v, %v", info, err)
	}
	if _, err := store.GetScope(ctx, testApplicationID); !errors.Is(err, role.ErrScopeInvalid) {
		t.Fatalf("未知应用 scope 错误 = %v", err)
	}
	now := int64(1_700_000_000_000)
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO applications(id,name,description,status,client_type,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,'','active','confidential',1,?,?)`, testApplicationID, "测试应用", now, now); err != nil {
		t.Fatalf("插入应用失败: %v", err)
	}
	if _, err := raw.ExecContext(ctx, `INSERT INTO scopes(id,kind,app_id) VALUES(?,'application',?)`, testApplicationID, testApplicationID); err != nil {
		t.Fatalf("插入 scope 失败: %v", err)
	}
	info, err := store.GetScope(ctx, testApplicationID)
	if err != nil || info.ApplicationID != testApplicationID || !info.ApplicationActive {
		t.Fatalf("应用 scope = %+v, %v", info, err)
	}
	// 空库读取角色/引用计数失败语义。
	if _, err := store.GetRole(ctx, "role_ffffffffffffffffffffffffffffffff"); !errors.Is(err, role.ErrRoleNotFound) {
		t.Fatalf("不存在角色错误 = %v", err)
	}
}

func TestRoleMembershipStoreOperations(t *testing.T) {
	raw := openMigratedStore(t)
	store, err := New(raw)
	if err != nil {
		t.Fatalf("构造仓储失败: %v", err)
	}
	ctx := context.Background()
	now := int64(1_700_000_000_000)
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO users(id,username,username_normalized,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'active',0,1,1,?,?)`, testUserID, "storeuser", "storeuser", now, now); err != nil {
		t.Fatalf("插入用户失败: %v", err)
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO applications(id,name,description,status,client_type,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,'','active','public',1,?,?)`, testApplicationID, "测试应用", now, now); err != nil {
		t.Fatalf("插入应用失败: %v", err)
	}
	if _, err := raw.ExecContext(ctx, `INSERT INTO scopes(id,kind,app_id) VALUES(?,'application',?)`, testApplicationID, testApplicationID); err != nil {
		t.Fatalf("插入 scope 失败: %v", err)
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO permissions(id,scope_id,permission_key,name,description,limits_text,is_builtin,root_only,enabled,created_at_ms,updated_at_ms)
VALUES(?, 'system','users.read','查看用户','','',0,0,1,?,?)`, testPermissionID, now, now); err != nil {
		t.Fatalf("插入权限失败: %v", err)
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO user_groups(id,scope_id,group_key,name,description,created_at_ms,updated_at_ms)
VALUES(?, 'system','system.ops','系统组','',?,?)`, testGroupID, now, now); err != nil {
		t.Fatalf("插入用户组失败: %v", err)
	}
	record := role.Role{
		ID: "role_00000000000000000000000000000001", ScopeID: "system", ScopeKind: role.ScopeKindSystem,
		Key: testRoleKey, Name: "运维管理", Description: "说明", Limits: "限制",
		Enabled: true, CreatedAt: time.UnixMilli(now).UTC(), UpdatedAt: time.UnixMilli(now).UTC(),
	}
	if txErr := runTx(t, raw, func(txCtx context.Context, tx audit.Tx) error {
		return store.CreateRole(txCtx, tx, record)
	}); txErr != nil {
		t.Fatalf("创建角色失败: %v", txErr)
	}
	if loaded, err := store.GetRole(ctx, record.ID); err != nil || loaded.Key != record.Key || loaded.ScopeID != "system" {
		t.Fatalf("读取角色 = %+v, %v", loaded, err)
	}
	if scopeID, err := store.GetRoleScope(ctx, record.ID); err != nil || scopeID != "system" {
		t.Fatalf("读取角色 scope = %q, %v", scopeID, err)
	}
	if permission, err := store.GetPermissionForRole(ctx, testPermissionID); err != nil || permission.RootOnly {
		t.Fatalf("读取待组合权限 = %+v, %v", permission, err)
	}
	if user, err := store.GetUserForRole(ctx, testUserID); err != nil || user.IsRoot || !user.Status.Valid() {
		t.Fatalf("读取账户 = %+v, %v", user, err)
	}
	if group, err := store.GetGroupForRole(ctx, testGroupID); err != nil || group.ScopeID != "system" {
		t.Fatalf("读取用户组 = %+v, %v", group, err)
	}
	if _, found, err := store.GetApplicationMembership(ctx, testApplicationID, testUserID); err != nil || found {
		t.Fatalf("不存在的成员关系 = found=%v, %v", found, err)
	}
	if hasRoot, err := store.GroupHasRootMember(ctx, testGroupID); err != nil || hasRoot {
		t.Fatalf("初始组 root 成员 = %v, %v", hasRoot, err)
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO users(id,username,username_normalized,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES('usr_00000000000000000000000000000009','storeroot','storeroot','active',1,1,1,?,?)`, now, now); err != nil {
		t.Fatalf("插入 root 用户失败: %v", err)
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO group_members(group_id,user_id,created_at_ms) VALUES(?,'usr_00000000000000000000000000000009',?)`,
		testGroupID, now); err != nil {
		t.Fatalf("插入 root 组成员失败: %v", err)
	}
	if hasRoot, err := store.GroupHasRootMember(ctx, testGroupID); err != nil || !hasRoot {
		t.Fatalf("含 root 组成员查询 = %v, %v", hasRoot, err)
	}
	// 引用计数与删除保护。
	if counts, err := store.CountDeleteReferences(ctx, record.ID); err != nil || counts.Total() != 0 {
		t.Fatalf("初始引用计数 = %+v, %v", counts, err)
	}
	if txErr := runTx(t, raw, func(txCtx context.Context, tx audit.Tx) error {
		_, err := store.AddRolePermission(txCtx, tx, record.ID, testPermissionID, "system")
		return err
	}); txErr != nil {
		t.Fatalf("组合权限失败: %v", txErr)
	}
	if permissions, err := store.ListRolePermissions(ctx, record.ID); err != nil || len(permissions) != 1 {
		t.Fatalf("角色权限列表 = %+v, %v", permissions, err)
	}
	if counts, err := store.CountDeleteReferences(ctx, record.ID); err != nil || counts.Permissions != 1 {
		t.Fatalf("组合后引用计数 = %+v, %v", counts, err)
	}
	deletedInUse := runTx(t, raw, func(txCtx context.Context, tx audit.Tx) error {
		return store.DeleteRole(txCtx, tx, record.ID)
	})
	if !errors.Is(deletedInUse, role.ErrRoleInUse) {
		t.Fatalf("有引用删除错误 = %v", deletedInUse)
	}
	// 分配用户与用户组，查询分配快照。
	assignmentErr := runTx(t, raw, func(txCtx context.Context, tx audit.Tx) error {
		inserted, err := store.AddUserRole(txCtx, tx, role.UserRoleAssignment{
			UserID: testUserID, RoleID: record.ID, ScopeID: "system", DataScope: "{}",
			AssignedBy: "system-1", CreatedAt: time.UnixMilli(now).UTC(),
		})
		if err != nil {
			return err
		}
		if !inserted {
			return errors.New("分配用户未插入")
		}
		groupInserted, err := store.AddGroupRole(txCtx, tx, role.GroupRoleAssignment{
			GroupID: testGroupID, RoleID: record.ID, ScopeID: "system", DataScope: "{}",
			CreatedAt: time.UnixMilli(now).UTC(),
		})
		if err != nil {
			return err
		}
		if !groupInserted {
			return errors.New("分配用户组未插入")
		}
		return nil
	})
	if assignmentErr != nil {
		t.Fatalf("分配用户/用户组失败: %v", assignmentErr)
	}
	assignments, err := store.ListRoleAssignments(ctx, record.ID)
	if err != nil || len(assignments.Users) != 1 || len(assignments.Groups) != 1 {
		t.Fatalf("角色分配快照 = %+v, %v", assignments, err)
	}
	if counts, err := store.CountDeleteReferences(ctx, record.ID); err != nil || counts.Total() != 3 {
		t.Fatalf("分配后引用计数 = %+v, %v", counts, err)
	}
	// 解除引用后可删除。
	cleanupErr := runTx(t, raw, func(txCtx context.Context, tx audit.Tx) error {
		if _, err := store.RemoveRolePermission(txCtx, tx, record.ID, testPermissionID); err != nil {
			return err
		}
		if _, err := store.RemoveUserRole(txCtx, tx, record.ID, testUserID); err != nil {
			return err
		}
		if _, err := store.RemoveGroupRole(txCtx, tx, record.ID, testGroupID); err != nil {
			return err
		}
		return store.DeleteRole(txCtx, tx, record.ID)
	})
	if cleanupErr != nil {
		t.Fatalf("解除引用后删除失败: %v", cleanupErr)
	}
	if _, err := store.GetRole(ctx, record.ID); !errors.Is(err, role.ErrRoleNotFound) {
		t.Fatalf("删除后读取错误 = %v", err)
	}
}
