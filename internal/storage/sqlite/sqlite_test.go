package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	sqlite3 "modernc.org/sqlite/lib"

	"github.com/kagurazakayashi/EvernightLogin/internal/storage"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	appmigrations "github.com/kagurazakayashi/EvernightLogin/migrations"
)

func testStore(t *testing.T, options Options) (*Store, string) {
	t.Helper()
	if options.Path == "" {
		options.Path = filepath.Join(t.TempDir(), "login.db")
	}
	store, err := Open(context.Background(), options)
	if err != nil {
		t.Fatalf("Open() 失败：%v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, options.Path
}

func defaultTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	return testStore(t, DefaultOptions(""))
}

func mustExec(t *testing.T, store *Store, query string, args ...any) {
	t.Helper()
	if _, err := store.ExecContext(context.Background(), query, args...); err != nil {
		t.Fatalf("执行 SQL 失败：%v", err)
	}
}

func queryInt(t *testing.T, store *Store, query string, args ...any) int {
	t.Helper()
	var value int
	if err := store.DB().QueryRowContext(context.Background(), query, args...).Scan(&value); err != nil {
		t.Fatalf("查询失败：%v", err)
	}
	return value
}

func loadedMigrations(t *testing.T) []migrate.Migration {
	t.Helper()
	migrations, err := migrate.LoadMigrations(appmigrations.SQLite)
	if err != nil {
		t.Fatalf("加载内嵌迁移失败：%v", err)
	}
	return migrations
}

func TestOpenAndPragmas(t *testing.T) {
	store, path := defaultTestStore(t)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("打开后数据库文件不存在：%v", err)
	}

	err := store.WithConn(context.Background(), func(ctx context.Context, conn *sql.Conn) error {
		var foreignKeys int
		if err := conn.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
			return err
		}
		if foreignKeys != 1 {
			t.Errorf("foreign_keys = %d，期望 1", foreignKeys)
		}
		var busyTimeout int
		if err := conn.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
			return err
		}
		if time.Duration(busyTimeout)*time.Millisecond != DefaultBusyTimeout {
			t.Errorf("busy_timeout = %dms，期望 %v", busyTimeout, DefaultBusyTimeout)
		}
		var journalMode string
		if err := conn.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil {
			return err
		}
		if !strings.EqualFold(journalMode, "wal") {
			t.Errorf("journal_mode = %q，期望 wal", journalMode)
		}
		var synchronous int
		if err := conn.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous); err != nil {
			return err
		}
		if synchronous != 1 {
			t.Errorf("synchronous = %d，期望 NORMAL(1)", synchronous)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("验证 PRAGMA 失败：%v", err)
	}

	if stats := store.DB().Stats(); stats.MaxOpenConnections != DefaultMaxOpenConns {
		t.Errorf("连接池上限 = %d，期望 %d", stats.MaxOpenConnections, DefaultMaxOpenConns)
	}
}

func TestWALCanBeDisabled(t *testing.T) {
	options := DefaultOptions(filepath.Join(t.TempDir(), "login.db"))
	options.WAL = false
	store, _ := testStore(t, options)
	err := store.WithConn(context.Background(), func(ctx context.Context, conn *sql.Conn) error {
		var journalMode string
		if err := conn.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil {
			return err
		}
		if strings.EqualFold(journalMode, "wal") {
			t.Errorf("WAL 已关闭但 journal_mode = %q", journalMode)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithConn() 失败：%v", err)
	}
}

func TestOpenErrorsAreSafe(t *testing.T) {
	dir := t.TempDir()
	missingParent := filepath.Join(dir, "missing", "login.db")
	_, err := Open(context.Background(), DefaultOptions(missingParent))
	if err == nil {
		t.Fatal("不存在的父目录应导致打开失败")
	}
	if !errors.Is(err, storage.ErrUnavailable) && !errors.Is(err, storage.ErrPermission) {
		t.Errorf("错误类别 = %v，期望 ErrUnavailable/ErrPermission", err)
	}
	if strings.Contains(err.Error(), missingParent) {
		t.Errorf("公开错误泄露数据库路径：%v", err)
	}
	if strings.Contains(err.Error(), "PRAGMA") || strings.Contains(err.Error(), "SELECT") {
		t.Errorf("公开错误泄露 SQL：%v", err)
	}

	if _, err := Open(context.Background(), DefaultOptions(dir)); err == nil {
		t.Error("以目录为数据库路径应失败")
	}
	if _, err := Open(context.Background(), DefaultOptions("")); err == nil {
		t.Error("空路径应失败")
	}
	badPool := DefaultOptions(filepath.Join(dir, "pool.db"))
	badPool.MaxOpenConns = MaxAllowedOpenConns + 1
	if _, err := Open(context.Background(), badPool); err == nil {
		t.Error("超限连接池应被拒绝")
	}
}

func TestWrapHostDBOwnership(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host.db")
	host, err := sql.Open("sqlite", path+"?_foreign_keys=1")
	if err != nil {
		t.Fatalf("打开宿主连接失败：%v", err)
	}
	defer host.Close()

	wrapped, err := WrapDB(host, Options{})
	if err != nil {
		t.Fatalf("WrapDB() 失败：%v", err)
	}
	if wrapped.DB() != host {
		t.Error("WrapDB 应包装同一宿主连接")
	}
	if err := wrapped.Close(); err != nil {
		t.Fatalf("关闭包装失败：%v", err)
	}
	if err := host.Ping(); err != nil {
		t.Errorf("Close 不应关闭宿主连接：%v", err)
	}

	noForeignKeys := filepath.Join(t.TempDir(), "nofk.db")
	hostWithoutFK, err := sql.Open("sqlite", noForeignKeys)
	if err != nil {
		t.Fatalf("打开宿主连接失败：%v", err)
	}
	defer hostWithoutFK.Close()
	if _, err := WrapDB(hostWithoutFK, Options{}); err == nil {
		t.Error("未启用外键的宿主连接应被拒绝")
	}
}

func TestCloseIdempotentAndClosedOperations(t *testing.T) {
	store, _ := defaultTestStore(t)
	if err := store.Close(); err != nil {
		t.Fatalf("Close() 失败：%v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("重复 Close() 失败：%v", err)
	}
	if err := store.Ping(context.Background()); !errors.Is(err, storage.ErrClosed) {
		t.Errorf("关闭后 Ping 错误 = %v", err)
	}
	if err := store.Transaction(context.Background(), func(context.Context, *sql.Tx) error { return nil }); !errors.Is(err, storage.ErrClosed) {
		t.Errorf("关闭后 Transaction 错误 = %v", err)
	}
	if err := store.WithConn(context.Background(), func(context.Context, *sql.Conn) error { return nil }); !errors.Is(err, storage.ErrClosed) {
		t.Errorf("关闭后 WithConn 错误 = %v", err)
	}
}

func TestTransactionCommitAndRollback(t *testing.T) {
	store, _ := defaultTestStore(t)
	mustExec(t, store, `CREATE TABLE test_items (id TEXT PRIMARY KEY, value TEXT NOT NULL)`)

	if err := store.Transaction(context.Background(), func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO test_items(id, value) VALUES(?,?)`, "a", "1")
		return err
	}); err != nil {
		t.Fatalf("提交事务失败：%v", err)
	}
	if got := queryInt(t, store, `SELECT COUNT(*) FROM test_items`); got != 1 {
		t.Fatalf("提交后行数 = %d", got)
	}

	rollbackCause := errors.New("业务失败")
	err := store.Transaction(context.Background(), func(ctx context.Context, tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO test_items(id, value) VALUES(?,?)`, "b", "2"); err != nil {
			return err
		}
		return rollbackCause
	})
	if !errors.Is(err, rollbackCause) {
		t.Fatalf("事务错误 = %v", err)
	}
	if got := queryInt(t, store, `SELECT COUNT(*) FROM test_items`); got != 1 {
		t.Fatalf("回滚后行数 = %d，期望 1", got)
	}

	func() {
		defer func() {
			if recover() == nil {
				t.Error("panic 应继续向上传播")
			}
		}()
		_ = store.Transaction(context.Background(), func(ctx context.Context, tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, `INSERT INTO test_items(id, value) VALUES(?,?)`, "c", "3"); err != nil {
				return err
			}
			panic("模拟 panic")
		})
	}()
	if got := queryInt(t, store, `SELECT COUNT(*) FROM test_items`); got != 1 {
		t.Fatalf("panic 后行数 = %d，期望回滚", got)
	}
}

func TestForeignKeys(t *testing.T) {
	store, _ := defaultTestStore(t)
	mustExec(t, store, `CREATE TABLE parents (id TEXT PRIMARY KEY)`)
	mustExec(t, store, `CREATE TABLE children (
		id TEXT PRIMARY KEY,
		parent_id TEXT NOT NULL REFERENCES parents(id) ON DELETE CASCADE
	)`)
	mustExec(t, store, `INSERT INTO parents(id) VALUES('p1')`)
	mustExec(t, store, `INSERT INTO children(id, parent_id) VALUES('c1','p1')`)

	_, err := store.ExecContext(context.Background(),
		`INSERT INTO children(id, parent_id) VALUES('c2','missing')`)
	if !errors.Is(err, storage.ErrConstraint) {
		t.Errorf("外键错误 = %v，期望 ErrConstraint", err)
	}
	mustExec(t, store, `DELETE FROM parents WHERE id='p1'`)
	if got := queryInt(t, store, `SELECT COUNT(*) FROM children`); got != 0 {
		t.Errorf("级联删除后子行数 = %d", got)
	}
}

func TestUniqueViolation(t *testing.T) {
	store, _ := defaultTestStore(t)
	mustExec(t, store, `CREATE TABLE unique_items (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE)`)
	mustExec(t, store, `INSERT INTO unique_items(id, name) VALUES('1','same')`)
	_, err := store.ExecContext(context.Background(),
		`INSERT INTO unique_items(id, name) VALUES('2','same')`)
	if !errors.Is(err, storage.ErrUniqueViolation) {
		t.Fatalf("唯一约束错误 = %v，期望 ErrUniqueViolation", err)
	}
	if strings.Contains(err.Error(), "unique_items") || strings.Contains(err.Error(), "INSERT") {
		t.Errorf("公开错误泄露表名或 SQL：%v", err)
	}
}

func TestVersionConflict(t *testing.T) {
	store, _ := defaultTestStore(t)
	mustExec(t, store, `CREATE TABLE versioned_items (id TEXT PRIMARY KEY, name TEXT NOT NULL, row_version INTEGER NOT NULL)`)
	mustExec(t, store, `INSERT INTO versioned_items(id, name, row_version) VALUES('a','one',1)`)

	result, err := store.ExecContext(context.Background(),
		`UPDATE versioned_items SET name=?, row_version=row_version+1 WHERE id=? AND row_version=?`,
		"two", "a", 1)
	if err != nil {
		t.Fatalf("更新失败：%v", err)
	}
	if err := storage.CheckVersionedUpdate(result); err != nil {
		t.Fatalf("首次更新应成功：%v", err)
	}

	stale, err := store.ExecContext(context.Background(),
		`UPDATE versioned_items SET name=?, row_version=row_version+1 WHERE id=? AND row_version=?`,
		"three", "a", 1)
	if err != nil {
		t.Fatalf("过期更新执行失败：%v", err)
	}
	if err := storage.CheckVersionedUpdate(stale); !errors.Is(err, storage.ErrVersionConflict) {
		t.Fatalf("过期更新错误 = %v，期望 ErrVersionConflict", err)
	}
}

func TestBusyTimeoutWaitsThenSucceeds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "busy.db")
	first, _ := testStore(t, DefaultOptions(path))
	second, _ := testStore(t, DefaultOptions(path))
	mustExec(t, first, `CREATE TABLE busy_items (id TEXT PRIMARY KEY)`)

	hold := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- first.Transaction(context.Background(), func(ctx context.Context, tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, `INSERT INTO busy_items(id) VALUES('first')`); err != nil {
				return err
			}
			close(hold)
			<-release
			return nil
		})
	}()
	select {
	case <-hold:
	case <-time.After(3 * time.Second):
		t.Fatal("第一个事务未取得写锁")
	}

	started := time.Now()
	go func() {
		// 第一个事务持有写锁约 100ms 后释放，第二个事务应等待而不是立即失败。
		time.Sleep(100 * time.Millisecond)
		close(release)
	}()
	err := second.Transaction(context.Background(), func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO busy_items(id) VALUES('second')`)
		return err
	})
	elapsed := time.Since(started)
	if err := <-firstDone; err != nil {
		t.Fatalf("第一个事务失败：%v", err)
	}
	if err != nil {
		t.Fatalf("第二个事务应在 busy_timeout 内等待成功：%v", err)
	}
	if elapsed < 50*time.Millisecond {
		t.Errorf("第二个事务等待时间 = %v，未体现锁等待", elapsed)
	}
	if got := queryInt(t, first, `SELECT COUNT(*) FROM busy_items`); got != 2 {
		t.Errorf("提交后行数 = %d", got)
	}
}

func TestLockTimeoutIsBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "timeout.db")
	first, _ := testStore(t, DefaultOptions(path))
	secondOptions := DefaultOptions(path)
	secondOptions.BusyTimeout = 100 * time.Millisecond
	second, _ := testStore(t, secondOptions)
	mustExec(t, first, `CREATE TABLE lock_items (id TEXT PRIMARY KEY)`)

	hold := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- first.Transaction(context.Background(), func(ctx context.Context, tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, `INSERT INTO lock_items(id) VALUES('first')`); err != nil {
				return err
			}
			close(hold)
			<-release
			return nil
		})
	}()
	select {
	case <-hold:
	case <-time.After(3 * time.Second):
		t.Fatal("第一个事务未取得写锁")
	}

	started := time.Now()
	err := second.Transaction(context.Background(), func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO lock_items(id) VALUES('second')`)
		return err
	})
	elapsed := time.Since(started)
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("第一个事务失败：%v", err)
	}
	if !errors.Is(err, storage.ErrBusy) {
		t.Fatalf("锁超时错误 = %v，期望 ErrBusy", err)
	}
	if elapsed < 80*time.Millisecond || elapsed > 3*time.Second {
		t.Errorf("锁等待时间 = %v，期望约 100ms 且有界", elapsed)
	}
}

func TestRetryOnBusySucceeds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "retry.db")
	first, _ := testStore(t, DefaultOptions(path))
	secondOptions := DefaultOptions(path)
	secondOptions.BusyTimeout = 30 * time.Millisecond
	secondOptions.Retry = storage.RetryPolicy{MaxAttempts: 1, InitialDelay: time.Millisecond, MaxDelay: time.Millisecond}
	second, _ := testStore(t, secondOptions)
	mustExec(t, first, `CREATE TABLE retry_items (id TEXT PRIMARY KEY)`)

	hold := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- first.Transaction(context.Background(), func(ctx context.Context, tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, `INSERT INTO retry_items(id) VALUES('first')`); err != nil {
				return err
			}
			close(hold)
			<-release
			return nil
		})
	}()
	select {
	case <-hold:
	case <-time.After(3 * time.Second):
		t.Fatal("第一个事务未取得写锁")
	}
	go func() {
		time.Sleep(120 * time.Millisecond)
		close(release)
	}()

	attempts := 0
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	policy := storage.RetryPolicy{MaxAttempts: 10, InitialDelay: 10 * time.Millisecond, MaxDelay: 50 * time.Millisecond}
	err := storage.Retry(ctx, policy, storage.Retryable, func(ctx context.Context) error {
		attempts++
		return second.Transaction(ctx, func(ctx context.Context, tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `INSERT INTO retry_items(id) VALUES('second')`)
			return err
		})
	})
	if err != nil {
		t.Fatalf("有界重试最终失败：%v", err)
	}
	if err := <-firstDone; err != nil {
		t.Fatalf("第一个事务失败：%v", err)
	}
	if attempts < 2 {
		t.Errorf("尝试次数 = %d，期望重试至少一次", attempts)
	}
}

func TestContextCancellationRollsBack(t *testing.T) {
	store, _ := defaultTestStore(t)
	mustExec(t, store, `CREATE TABLE cancel_items (id TEXT PRIMARY KEY)`)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	err := store.Transaction(ctx, func(ctx context.Context, tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO cancel_items(id) VALUES('x')`); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx,
			`WITH RECURSIVE counter(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM counter WHERE x < 10000000) SELECT count(*) FROM counter`)
		return err
	})
	if err == nil {
		t.Fatal("超时事务应返回错误")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, storage.ErrUnavailable) {
		t.Fatalf("错误 = %v，期望上下文超时或安全存储错误", err)
	}
	if got := queryInt(t, store, `SELECT COUNT(*) FROM cancel_items`); got != 0 {
		t.Errorf("取消后行数 = %d，期望回滚", got)
	}
}

func TestContextCancellationWhileWaitingForLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cancel-lock.db")
	first, _ := testStore(t, DefaultOptions(path))
	secondOptions := DefaultOptions(path)
	secondOptions.BusyTimeout = 300 * time.Millisecond
	secondOptions.Retry = storage.RetryPolicy{MaxAttempts: 1, InitialDelay: time.Millisecond, MaxDelay: time.Millisecond}
	second, _ := testStore(t, secondOptions)
	mustExec(t, first, `CREATE TABLE wait_items (id TEXT PRIMARY KEY)`)

	hold := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- first.Transaction(context.Background(), func(ctx context.Context, tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, `INSERT INTO wait_items(id) VALUES('first')`); err != nil {
				return err
			}
			close(hold)
			<-release
			return nil
		})
	}()
	select {
	case <-hold:
	case <-time.After(3 * time.Second):
		t.Fatal("第一个事务未取得写锁")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := second.Transaction(ctx, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO wait_items(id) VALUES('second')`)
		return err
	})
	elapsed := time.Since(started)
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("第一个事务失败：%v", err)
	}
	if err == nil {
		t.Fatal("等待锁时 ctx 取消应返回错误")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, storage.ErrBusy) {
		t.Fatalf("错误 = %v，期望取消或 ErrBusy", err)
	}
	if elapsed > 3*time.Second {
		t.Errorf("取消等待耗时 %v，超出上限", elapsed)
	}
}

func TestMigrateAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "migrate.db")
	store, err := Open(context.Background(), DefaultOptions(path))
	if err != nil {
		t.Fatalf("Open() 失败：%v", err)
	}
	migrations := loadedMigrations(t)

	result, err := store.Migrate(context.Background(), migrations)
	if err != nil {
		t.Fatalf("Migrate() 失败：%v", err)
	}
	if result.UpToDate || len(result.Applied) != 37 {
		t.Fatalf("首次迁移结果 = %+v", result)
	}
	if got := queryInt(t, store, `SELECT COUNT(*) FROM schema_history`); got != 37 {
		t.Errorf("schema_history 行数 = %d", got)
	}
	if got := queryInt(t, store, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='users'`); got != 1 {
		t.Errorf("users 表未创建")
	}
	if got := queryInt(t, store, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='one_time_credentials'`); got != 1 {
		t.Errorf("one_time_credentials 表未创建")
	}
	if got := queryInt(t, store, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='audit_events'`); got != 1 {
		t.Errorf("audit_events 表未创建")
	}
	if got := queryInt(t, store, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='jobs'`); got != 1 {
		t.Errorf("jobs 表未创建")
	}
	if got := queryInt(t, store, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='job_attempts'`); got != 1 {
		t.Errorf("job_attempts 表未创建")
	}
	if got := queryInt(t, store, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schedules'`); got != 1 {
		t.Errorf("schedules 表未创建")
	}
	if got := queryInt(t, store, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schedule_firings'`); got != 1 {
		t.Errorf("schedule_firings 表未创建")
	}
	if got := queryInt(t, store, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='sessions'`); got != 1 {
		t.Errorf("sessions 表未创建")
	}
	if got := queryInt(t, store, `SELECT COUNT(*) FROM scopes WHERE kind='system'`); got != 1 {
		t.Errorf("system scope 行数 = %d", got)
	}

	result, err = store.Migrate(context.Background(), migrations)
	if err != nil {
		t.Fatalf("重复 Migrate() 失败：%v", err)
	}
	if !result.UpToDate {
		t.Errorf("重复迁移应 UpToDate，实际 %+v", result)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("Close() 失败：%v", err)
	}
	reopened, err := Open(context.Background(), DefaultOptions(path))
	if err != nil {
		t.Fatalf("重新打开失败：%v", err)
	}
	defer reopened.Close()
	result, err = reopened.Migrate(context.Background(), migrations)
	if err != nil {
		t.Fatalf("重开后 Migrate() 失败：%v", err)
	}
	if !result.UpToDate {
		t.Errorf("重开后迁移应 UpToDate，实际 %+v", result)
	}
	if got := queryInt(t, reopened, `SELECT COUNT(*) FROM scopes WHERE kind='system'`); got != 1 {
		t.Errorf("重开后 system scope 行数 = %d", got)
	}
}

func TestMigrateChecksumMismatchRejected(t *testing.T) {
	store, _ := defaultTestStore(t)
	migrations := loadedMigrations(t)
	if _, err := store.Migrate(context.Background(), migrations); err != nil {
		t.Fatalf("Migrate() 失败：%v", err)
	}

	changed := loadedMigrations(t)
	changed[0].Checksum = strings.Repeat("0", 64)
	if _, err := store.Migrate(context.Background(), changed); !errors.Is(err, migrate.ErrChecksumMismatch) {
		t.Fatalf("错误 = %v，期望 ErrChecksumMismatch", err)
	}
	if got := queryInt(t, store, `SELECT COUNT(*) FROM schema_history`); got != 37 {
		t.Errorf("校验和不符不应改变历史，实际 %d", got)
	}
}

func TestMigrateFailureRecordedAndRetryNeedsClear(t *testing.T) {
	store, _ := defaultTestStore(t)
	bad := []migrate.Migration{{
		Version:     "0001",
		Description: "bad sql",
		FileName:    "0001_bad_sql.sql",
		Checksum:    strings.Repeat("a", 64),
		Statements:  []string{"THIS IS NOT SQL"},
	}}
	_, err := store.Migrate(context.Background(), bad)
	if err == nil {
		t.Fatal("非法迁移应失败")
	}
	if strings.Contains(err.Error(), "THIS IS NOT SQL") {
		t.Errorf("迁移错误泄露原始 SQL：%v", err)
	}
	if got := queryInt(t, store, `SELECT COUNT(*) FROM schema_failures`); got != 1 {
		t.Fatalf("失败记录数 = %d", got)
	}
	if got := queryInt(t, store, `SELECT COUNT(*) FROM schema_history`); got != 0 {
		t.Errorf("失败迁移不应写入历史，实际 %d", got)
	}

	if _, err := store.Migrate(context.Background(), bad); !errors.Is(err, migrate.ErrFailurePending) {
		t.Fatalf("再次迁移错误 = %v，期望 ErrFailurePending", err)
	}

	runner, err := store.MigrationRunner(bad)
	if err != nil {
		t.Fatalf("MigrationRunner() 失败：%v", err)
	}
	if err := runner.ClearFailure(context.Background(), "0001"); err != nil {
		t.Fatalf("ClearFailure() 失败：%v", err)
	}
	valid := loadedMigrations(t)
	if _, err := store.Migrate(context.Background(), valid); err != nil {
		t.Fatalf("清理失败记录后迁移失败：%v", err)
	}
	if got := queryInt(t, store, `SELECT COUNT(*) FROM schema_failures`); got != 0 {
		t.Errorf("成功迁移后失败记录数 = %d", got)
	}
}

func TestConcurrentMigrateTwoConnections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "concurrent.db")
	first, _ := testStore(t, DefaultOptions(path))
	secondOptions := DefaultOptions(path)
	secondOptions.BusyTimeout = 2 * time.Second
	second, _ := testStore(t, secondOptions)
	migrations := loadedMigrations(t)

	var wait sync.WaitGroup
	errs := make([]error, 2)
	wait.Add(2)
	go func() {
		defer wait.Done()
		_, errs[0] = first.Migrate(context.Background(), migrations)
	}()
	go func() {
		defer wait.Done()
		_, errs[1] = second.Migrate(context.Background(), migrations)
	}()
	wait.Wait()
	for index, err := range errs {
		if err != nil {
			t.Errorf("并发迁移 %d 失败：%v", index, err)
		}
	}
	if got := queryInt(t, first, `SELECT COUNT(*) FROM schema_history`); got != 37 {
		t.Errorf("schema_history 行数 = %d，期望 36", got)
	}
	if got := queryInt(t, first, `SELECT COUNT(*) FROM schema_failures`); got != 0 {
		t.Errorf("schema_failures 行数 = %d，期望 0", got)
	}
}

func TestErrorClassificationCodes(t *testing.T) {
	cases := []struct {
		code int
		kind error
	}{
		{sqlite3.SQLITE_BUSY, storage.ErrBusy},
		{sqlite3.SQLITE_LOCKED, storage.ErrBusy},
		{sqlite3.SQLITE_CONSTRAINT_UNIQUE, storage.ErrUniqueViolation},
		{sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY, storage.ErrUniqueViolation},
		{sqlite3.SQLITE_CONSTRAINT_FOREIGNKEY, storage.ErrConstraint},
		{sqlite3.SQLITE_FULL, storage.ErrDiskFull},
		{sqlite3.SQLITE_READONLY, storage.ErrPermission},
		{sqlite3.SQLITE_PERM, storage.ErrPermission},
		{sqlite3.SQLITE_CANTOPEN, storage.ErrUnavailable},
		{sqlite3.SQLITE_IOERR, storage.ErrUnavailable},
		{sqlite3.SQLITE_CORRUPT, storage.ErrCorrupt},
		{sqlite3.SQLITE_NOTADB, storage.ErrCorrupt},
		{sqlite3.SQLITE_ERROR, storage.ErrUnavailable},
	}
	for _, test := range cases {
		kind, message := classifyErrorCode(test.code)
		if kind != test.kind {
			t.Errorf("code %d 类别 = %v，期望 %v", test.code, kind, test.kind)
		}
		if strings.Contains(message, "/") || strings.Contains(message, "SELECT") {
			t.Errorf("code %d 消息含路径/SQL：%q", test.code, message)
		}
	}
}

func TestOptionsValidation(t *testing.T) {
	valid := DefaultOptions(filepath.Join(t.TempDir(), "x.db"))
	if _, err := valid.normalize(true); err != nil {
		t.Fatalf("默认配置不合法：%v", err)
	}
	cases := []Options{
		{Path: ""},
		{Path: "x?y.db"},
		{Path: "x.db", BusyTimeout: -1},
		{Path: "x.db", MaxOpenConns: MaxAllowedOpenConns + 1},
		{Path: "x.db", MaxOpenConns: 2, MaxIdleConns: 3},
	}
	for _, options := range cases {
		if _, err := options.normalize(true); err == nil {
			t.Errorf("非法配置 %+v 未报错", options)
		}
	}
}
