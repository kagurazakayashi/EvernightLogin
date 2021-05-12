package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const (
	testApplicationID = "app_00000000000000000000000000000001"
	testUserID        = "usr_00000000000000000000000000000001"
	testPermissionID  = "perm_00000000000000000000000000000001"
	testRoleID        = "role_00000000000000000000000000000001"
	testGroupID       = "grp_00000000000000000000000000000001"
	testNowMS         = int64(1_700_000_000_000)
)

func openMigratedStore(t *testing.T) *storagesqlite.Store {
	t.Helper()
	ctx := context.Background()
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(filepath.Join(t.TempDir(), "authz.sqlite")))
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

func TestNewValidation(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("空存储应被拒绝")
	}
}

func TestSnapshotReads(t *testing.T) {
	raw := openMigratedStore(t)
	store, err := New(raw)
	if err != nil {
		t.Fatalf("构造授权存储失败: %v", err)
	}
	ctx := context.Background()
	// 插入最小数据：账户、应用、成员、权限、角色、组、角色权限与分配。
	execute := func(query string, args ...any) {
		t.Helper()
		if _, err := raw.ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("执行测试数据插入失败: %v", err)
		}
	}
	execute(`INSERT INTO users(id,username,username_normalized,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'active',0,1,1,?,?)`, testUserID, "storeuser", "storeuser", testNowMS, testNowMS)
	execute(`INSERT INTO applications(id,name,description,status,client_type,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,'','active','public',1,?,?)`, testApplicationID, "测试应用", testNowMS, testNowMS)
	execute(`INSERT INTO scopes(id,kind,app_id) VALUES(?,'application',?)`, testApplicationID, testApplicationID)
	execute(`INSERT INTO app_memberships(app_id,user_id,status,profile_json,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,'active','{"v":1}',1,?,?)`, testApplicationID, testUserID, testNowMS, testNowMS)
	execute(`INSERT INTO permissions(id,scope_id,permission_key,name,description,limits_text,is_builtin,root_only,enabled,created_at_ms,updated_at_ms)
VALUES(?,?,'invoices.approve','审批','','',0,0,1,?,?)`, testPermissionID, testApplicationID, testNowMS, testNowMS)
	execute(`INSERT INTO roles(id,scope_id,role_key,name,description,limits_text,is_builtin,enabled,created_at_ms,updated_at_ms)
VALUES(?,?,'approver','审批角色','','',0,1,?,?)`, testRoleID, testApplicationID, testNowMS, testNowMS)
	execute(`INSERT INTO role_permissions(role_id,permission_id,scope_id) VALUES(?,?,?)`,
		testRoleID, testPermissionID, testApplicationID)
	execute(`INSERT INTO user_groups(id,scope_id,group_key,name,description,created_at_ms,updated_at_ms)
VALUES(?,?,'reviewer','审核组','',?,?)`, testGroupID, testApplicationID, testNowMS, testNowMS)
	execute(`INSERT INTO group_members(group_id,user_id,created_at_ms) VALUES(?,?,?)`, testGroupID, testUserID, testNowMS)
	execute(`INSERT INTO group_roles(group_id,role_id,scope_id,data_scope_json,created_at_ms) VALUES(?,?,?,?,?)`,
		testGroupID, testRoleID, testApplicationID, `{"v":1,"mode":"resources","resources":["x"]}`, testNowMS)
	execute(`INSERT INTO user_roles(user_id,role_id,scope_id,data_scope_json,assigned_by,created_at_ms) VALUES(?,?,?,?,?,?)`,
		testUserID, testRoleID, testApplicationID, `{"v":1,"mode":"all"}`, "system-1", testNowMS)

	err = store.Snapshot(ctx, func(snapshotCtx context.Context, reader authz.Reader) error {
		accountInfo, found, err := reader.Account(snapshotCtx, testUserID)
		if err != nil || !found || accountInfo.Status != "active" {
			t.Fatalf("账户读取 = %+v found=%v err=%v", accountInfo, found, err)
		}
		if _, found, err := reader.Account(snapshotCtx, "usr_ffffffffffffffffffffffffffffffff"); err != nil || found {
			t.Fatalf("不存在账户 = found=%v err=%v", found, err)
		}
		application, found, err := reader.Application(snapshotCtx, testApplicationID)
		if err != nil || !found || application.Status != "active" {
			t.Fatalf("应用读取 = %+v found=%v err=%v", application, found, err)
		}
		membership, err := reader.Membership(snapshotCtx, testApplicationID, testUserID)
		if err != nil || !membership.Found || membership.Status != "active" {
			t.Fatalf("成员读取 = %+v err=%v", membership, err)
		}
		permission, found, err := reader.Permission(snapshotCtx, testApplicationID, "invoices.approve")
		if err != nil || !found || !permission.Enabled || permission.RootOnly {
			t.Fatalf("权限读取 = %+v found=%v err=%v", permission, found, err)
		}
		permissions, hasMore, err := reader.GrantedPermissions(snapshotCtx, testApplicationID, testUserID, 10, 0)
		if err != nil || len(permissions) != 1 || hasMore {
			t.Fatalf("有效权限目录 = %+v hasMore=%v err=%v", permissions, hasMore, err)
		}
		sources, hasMore, err := reader.PermissionSources(snapshotCtx, testApplicationID, testUserID, []string{testPermissionID}, 10, 0)
		if err != nil || len(sources) != 2 || hasMore {
			t.Fatalf("权限来源 = %+v hasMore=%v err=%v", sources, hasMore, err)
		}
		kinds := make(map[authz.SourceKind]int)
		for _, source := range sources {
			kinds[source.Kind]++
			if source.RoleID != testRoleID || source.ScopeID != testApplicationID {
				t.Fatalf("来源数据 = %+v", source)
			}
			if source.Kind == authz.SourceKindGroupRole && source.GroupID != testGroupID {
				t.Fatalf("组来源缺少组信息: %+v", source)
			}
		}
		if kinds[authz.SourceKindUserRole] != 1 || kinds[authz.SourceKindGroupRole] != 1 {
			t.Fatalf("来源类型计数 = %+v", kinds)
		}
		// 关闭 root_only/enabled 等过滤后，候选来源分页边界。
		page, pageHasMore, err := reader.PermissionSources(snapshotCtx, testApplicationID, testUserID, []string{testPermissionID}, 1, 0)
		if err != nil || len(page) != 1 || !pageHasMore {
			t.Fatalf("来源分页 = %+v hasMore=%v err=%v", page, pageHasMore, err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("快照读取失败: %v", err)
	}
}

// TestSnapshotRollbackOnError 验证回调错误会关闭事务且不留下部分写入（本包只读，
// 只验证错误传播与后续可继续使用）。
func TestSnapshotRollbackOnError(t *testing.T) {
	raw := openMigratedStore(t)
	store, err := New(raw)
	if err != nil {
		t.Fatalf("构造授权存储失败: %v", err)
	}
	sentinel := errors.New("callback failed")
	err = store.Snapshot(context.Background(), func(context.Context, authz.Reader) error {
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("快照回调错误 = %v", err)
	}
	// 事务已回滚，后续快照仍可用。
	if err := store.Snapshot(context.Background(), func(context.Context, authz.Reader) error {
		return nil
	}); err != nil {
		t.Fatalf("后续快照失败: %v", err)
	}
}
