package httpapi

// 真实 SQLite 幂等存储测试：迁移 0045、原子 Begin、completed 重放、请求摘要冲突、
// in_progress 冲突、Abort 后重试与过期清理。测试只用临时数据库。

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

func newIdempotencySQLiteTest(t *testing.T) *SQLIdempotencyStore {
	t.Helper()
	ctx := context.Background()
	store, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(
		filepath.Join(testutil.TempDir(t), "idempotency.db")))
	if err != nil {
		t.Fatalf("打开临时数据库: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	set, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移: %v", err)
	}
	if _, err := store.Migrate(ctx, set); err != nil {
		t.Fatalf("执行迁移: %v", err)
	}
	repository, err := NewSQLIdempotencyStore(store)
	if err != nil {
		t.Fatalf("构造幂等存储: %v", err)
	}
	return repository
}

func TestSQLIdempotencyStoreLifecycle(t *testing.T) {
	ctx := context.Background()
	store := newIdempotencySQLiteTest(t)
	now := time.Date(2026, 11, 21, 20, 0, 0, 0, time.UTC)
	scope := IdempotencyScope{ApplicationID: testAppA, PrincipalKind: "user",
		PrincipalID: testUser, Key: "idem-sql-1"}
	expires := now.Add(24 * time.Hour)
	stored, conflict, err := store.Begin(ctx, scope, "POST /users", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", now, expires)
	if err != nil || conflict || stored != nil {
		t.Fatalf("首次 Begin = stored=%+v conflict=%v err=%v", stored, conflict, err)
	}
	if err := store.Complete(ctx, scope, 200, []byte(`{"ok":true}`)); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	replay, conflict, err := store.Begin(ctx, scope, "POST /users", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", now, expires)
	if err != nil || conflict || replay == nil || replay.Status != 200 ||
		string(replay.Body) != `{"ok":true}` {
		t.Fatalf("重放 = %+v conflict=%v err=%v", replay, conflict, err)
	}
	if _, conflict, err := store.Begin(ctx, scope, "POST /users", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", now, expires); err != nil || !conflict {
		t.Fatalf("不同摘要必须冲突: conflict=%v err=%v", conflict, err)
	}
	// in_progress 不得重放为成功。
	scope2 := scope
	scope2.Key = "idem-sql-2"
	if _, conflict, err := store.Begin(ctx, scope2, "POST /users", "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", now, expires); err != nil || conflict {
		t.Fatalf("第二次 Begin: conflict=%v err=%v", conflict, err)
	}
	if _, conflict, err := store.Begin(ctx, scope2, "POST /users", "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", now, expires); err != nil || !conflict {
		t.Fatalf("进行中必须冲突: conflict=%v err=%v", conflict, err)
	}
	if err := store.Abort(ctx, scope2); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	if _, conflict, err := store.Begin(ctx, scope2, "POST /users", "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", now, expires); err != nil || conflict {
		t.Fatalf("Abort 后应可重试: conflict=%v err=%v", conflict, err)
	}
}

func TestSQLIdempotencyStoreExpiry(t *testing.T) {
	ctx := context.Background()
	store := newIdempotencySQLiteTest(t)
	now := time.Date(2026, 11, 21, 20, 0, 0, 0, time.UTC)
	scope := IdempotencyScope{ApplicationID: testAppA, PrincipalKind: "service",
		PrincipalID: testAppA, Key: "idem-expired"}
	if _, conflict, err := store.Begin(ctx, scope, "POST /members", "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		now.Add(-2*time.Hour), now.Add(-time.Hour)); err != nil || conflict {
		t.Fatalf("过期前 Begin: conflict=%v err=%v", conflict, err)
	}
	if err := store.Complete(ctx, scope, 200, []byte(`{"ok":true}`)); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	// 已过期记录在 Begin 时被清理，同一 key 可建立新记录，不重放旧结果。
	stored, conflict, err := store.Begin(ctx, scope, "POST /members", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		now, now.Add(time.Hour))
	if err != nil || conflict || stored != nil {
		t.Fatalf("过期记录清理失败: stored=%+v conflict=%v err=%v", stored, conflict, err)
	}
}
