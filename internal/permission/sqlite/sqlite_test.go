package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/permission"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const testAppID = "app_00000000000000000000000000000001"

func openMigratedStore(t *testing.T) *storagesqlite.Store {
	t.Helper()
	ctx := context.Background()
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(filepath.Join(testutil.TempDir(t), "permission.sqlite")))
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

func TestScopeAndPermissionQueries(t *testing.T) {
	raw := openMigratedStore(t)
	store, err := New(raw)
	if err != nil {
		t.Fatalf("构造仓储失败: %v", err)
	}
	ctx := context.Background()
	now := int64(1_700_000_000_000)
	if info, err := store.GetScope(ctx, permission.ScopeSystem); err != nil || info.Kind != permission.ScopeKindSystem {
		t.Fatalf("系统 scope = %+v, %v", info, err)
	}
	if _, err := store.GetScope(ctx, testAppID); !errors.Is(err, permission.ErrScopeInvalid) {
		t.Fatalf("未知应用 scope 错误 = %v", err)
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO applications(id,name,description,icon_ref,homepage,owner_user_id,contact_info,status,client_type,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,'',NULL,NULL,NULL,NULL,'active','public',1,?,?)`, testAppID, "测试应用", now, now); err != nil {
		t.Fatalf("插入应用失败: %v", err)
	}
	if _, err := raw.ExecContext(ctx, `INSERT INTO scopes(id,kind,app_id) VALUES(?,'application',?)`, testAppID, testAppID); err != nil {
		t.Fatalf("插入 scope 失败: %v", err)
	}
	if info, err := store.GetScope(ctx, testAppID); err != nil || info.ApplicationID != testAppID || !info.ApplicationActive {
		t.Fatalf("应用 scope = %+v, %v", info, err)
	}
	// 系统内置与系统自定义权限 + 应用同名权限。
	records := []struct {
		id       string
		scopeID  string
		key      string
		builtin  int
		rootOnly int
	}{
		{"perm_00000000000000000000000000000001", permission.ScopeSystem, "users.read", 1, 0},
		{"perm_00000000000000000000000000000002", permission.ScopeSystem, "reports.custom", 0, 0},
		{"perm_00000000000000000000000000000003", testAppID, "users.read", 0, 0},
	}
	for _, record := range records {
		if _, err := raw.ExecContext(ctx,
			`INSERT INTO permissions(id,scope_id,permission_key,name,description,limits_text,is_builtin,root_only,enabled,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?,?,?,1,?,?)`, record.id, record.scopeID, record.key, "名称", "说明", "限制", record.builtin, record.rootOnly, now, now); err != nil {
			t.Fatalf("插入权限失败: %v", err)
		}
	}
	record, err := store.GetPermission(ctx, records[0].id)
	if err != nil || !record.IsBuiltin || !record.Enabled || record.Group != "users" {
		t.Fatalf("读取内置权限 = %+v, %v", record, err)
	}
	if _, err := store.GetPermission(ctx, "perm_ffffffffffffffffffffffffffffffff"); !errors.Is(err, permission.ErrPermissionNotFound) {
		t.Fatalf("不存在权限错误 = %v", err)
	}
	scopeID, err := store.GetPermissionScope(ctx, records[2].id)
	if err != nil || scopeID != testAppID {
		t.Fatalf("读取权限 scope = %q, %v", scopeID, err)
	}
	all, hasMore, err := store.ListPermissions(ctx, permission.ListQuery{Limit: 2, AllScopes: true})
	if err != nil || len(all) != 2 || !hasMore {
		t.Fatalf("全部权限分页 = %+v, hasMore=%v, err=%v", all, hasMore, err)
	}
	appOnly, _, err := store.ListPermissions(ctx, permission.ListQuery{Limit: 10, ScopeFilter: testAppID})
	if err != nil || len(appOnly) != 1 || appOnly[0].ScopeID != testAppID {
		t.Fatalf("应用 scope 列表 = %+v, %v", appOnly, err)
	}
	enabled := true
	enabledOnly, _, err := store.ListPermissions(ctx, permission.ListQuery{Limit: 10, AllScopes: true, Enabled: &enabled})
	if err != nil || len(enabledOnly) != 3 {
		t.Fatalf("enabled 过滤 = %+v, %v", enabledOnly, err)
	}
	if count, err := store.CountReferences(ctx, records[1].id); err != nil || count != 0 {
		t.Fatalf("引用计数 = %d, %v", count, err)
	}
}
