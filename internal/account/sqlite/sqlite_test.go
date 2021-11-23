package sqlite

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// openMigratedStore 在临时目录创建数据库并应用全部迁移。
func openMigratedStore(t *testing.T) *storagesqlite.Store {
	t.Helper()
	ctx := context.Background()
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(filepath.Join(testutil.TempDir(t), "account.sqlite")))
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

func TestUsersSchemaAndQueries(t *testing.T) {
	raw := openMigratedStore(t)
	store, err := New(raw)
	if err != nil {
		t.Fatalf("构造仓储失败: %v", err)
	}
	ctx := context.Background()

	// 确认 0001 迁移已经提供本步依赖的用户名规范化唯一约束与资料列。
	rows, err := raw.QueryContext(ctx, `SELECT name FROM pragma_table_info('users')`)
	if err != nil {
		t.Fatalf("读取 users 表结构失败: %v", err)
	}
	columns := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("读取列名失败: %v", err)
		}
		columns[name] = true
	}
	_ = rows.Close()
	for _, column := range []string{"id", "username", "username_normalized", "nickname", "biography", "language", "timezone", "status", "is_root", "security_version", "row_version", "created_at_ms", "updated_at_ms"} {
		if !columns[column] {
			t.Errorf("users 表缺少列 %s", column)
		}
	}
	indexRows, err := raw.QueryContext(ctx, `SELECT name FROM pragma_index_list('users')`)
	if err != nil {
		t.Fatalf("读取 users 索引失败: %v", err)
	}
	indexes := map[string]bool{}
	for indexRows.Next() {
		var name string
		if err := indexRows.Scan(&name); err != nil {
			t.Fatalf("读取索引名失败: %v", err)
		}
		indexes[name] = true
	}
	_ = indexRows.Close()
	if !indexes["ux_single_root"] {
		t.Error("users 表缺少唯一 root 索引")
	}
	// username_normalized 的 UNIQUE 约束可能通过自动索引实现，插入重复值验证。
	const insertSQL = `INSERT INTO users(id,username,username_normalized,language,timezone,status,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?,?,?)`
	if _, err := raw.ExecContext(ctx, insertSQL, "usr_00000000000000000000000000000001", "Alice", "alice", "zh-CN", "Asia/Shanghai", "active", 1, 1); err != nil {
		t.Fatalf("插入测试用户失败: %v", err)
	}
	if _, err := raw.ExecContext(ctx, insertSQL, "usr_00000000000000000000000000000002", "ALICE", "alice", "zh-CN", "Asia/Shanghai", "active", 2, 2); err == nil {
		t.Fatal("username_normalized 唯一约束未生效")
	}

	user, err := store.GetUser(ctx, "usr_00000000000000000000000000000001")
	if err != nil {
		t.Fatalf("查询用户失败: %v", err)
	}
	if user.Username != "Alice" || user.Status != account.StatusActive || user.RowVersion != 1 {
		t.Errorf("查询结果 = %+v", user)
	}
	if _, err := store.GetUser(ctx, "usr_000000000000000000000000000000ff"); err == nil {
		t.Fatal("不存在的用户应返回错误")
	}
	list, hasMore, err := store.ListUsers(ctx, account.ListQuery{Limit: 10, Sort: account.SortCreatedAt})
	if err != nil || hasMore || len(list) != 1 {
		t.Fatalf("列表查询 = %d, hasMore=%v, err=%v", len(list), hasMore, err)
	}
	if _, _, err := store.ListUsers(ctx, account.ListQuery{Limit: 10, Sort: "password"}); err == nil {
		t.Fatal("非白名单排序字段应被拒绝")
	}
}
