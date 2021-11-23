package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	appmigrations "github.com/kagurazakayashi/EvernightLogin/migrations"
)

// querySnapshot 打开只读快照文件执行查询；测试专用，不经过 Store 的写配置。
func querySnapshot(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path+"?_query_only=1&_busy_timeout=5000")
	if err != nil {
		t.Fatalf("打开快照失败：%v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// TestOnlineBackupUnderConcurrentWrites 验证备份期间的持续写入不会破坏快照一致性：
// 写入事务总是同时增加两行计数，备份文件中的两行必须相等。
func TestOnlineBackupUnderConcurrentWrites(t *testing.T) {
	store, _ := defaultTestStore(t)
	ctx := context.Background()
	migrations, err := migrate.LoadMigrations(appmigrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移失败：%v", err)
	}
	if _, err := store.Migrate(ctx, migrations); err != nil {
		t.Fatalf("执行迁移失败：%v", err)
	}
	mustExec(t, store, `CREATE TABLE backup_invariant(
		id INTEGER PRIMARY KEY, value INTEGER NOT NULL)`)
	mustExec(t, store, `INSERT INTO backup_invariant(id, value) VALUES(1, 0), (2, 0)`)

	var stop atomic.Bool
	var writes atomic.Int64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			err := store.Transaction(ctx, func(txCtx context.Context, tx *sql.Tx) error {
				if _, err := tx.ExecContext(txCtx,
					`UPDATE backup_invariant SET value=value+1 WHERE id IN (1,2)`); err != nil {
					return err
				}
				return nil
			})
			if err != nil {
				// 并发写与在线备份竞争时可能暂时 BUSY；测试写入尽力而为即可。
				return
			}
			writes.Add(1)
		}
	}()

	destination := filepath.Join(testutil.TempDir(t), "snapshot.db")
	var lastProgress atomic.Int64
	err = store.OnlineBackup(ctx, destination, func(done, total int) {
		if done >= 0 && total >= 0 {
			lastProgress.Store(int64(done))
		}
	})
	stop.Store(true)
	wg.Wait()
	if err != nil {
		t.Fatalf("OnlineBackup 失败：%v", err)
	}
	if writes.Load() == 0 {
		t.Fatal("并发写入测试没有发生任何写入，无法证明在线备份一致性")
	}
	if got := lastProgress.Load(); got <= 0 {
		t.Fatalf("进度回调未报告已完成页（%d），无法证明真实分批复制", got)
	}

	snapshot := querySnapshot(t, destination)
	var left, right int64
	if err := snapshot.QueryRow(`SELECT value FROM backup_invariant WHERE id=1`).Scan(&left); err != nil {
		t.Fatalf("读取快照 id=1 失败：%v", err)
	}
	if err := snapshot.QueryRow(`SELECT value FROM backup_invariant WHERE id=2`).Scan(&right); err != nil {
		t.Fatalf("读取快照 id=2 失败：%v", err)
	}
	if left != right {
		t.Fatalf("快照中两行计数不一致：left=%d right=%d（在线备份未取得一致快照）", left, right)
	}
	var integrity string
	if err := snapshot.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil {
		t.Fatalf("快照完整性检查失败：%v", err)
	}
	if integrity != "ok" {
		t.Fatalf("快照 integrity_check = %q，期望 ok", integrity)
	}
}

// TestOnlineBackupCancel 验证取消后停止复制并返回 context 错误，不产生成功结果。
func TestOnlineBackupCancel(t *testing.T) {
	store, _ := defaultTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	destination := filepath.Join(testutil.TempDir(t), "snapshot.db")
	progressCalls := 0
	err := store.OnlineBackup(ctx, destination, func(done, total int) {
		progressCalls++
		cancel()
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("取消后错误 = %v，期望 context.Canceled", err)
	}
	if progressCalls == 0 {
		t.Fatal("取消测试未触发进度回调，无法证明真实复制已开始")
	}
}

// TestOnlineBackupRejectsExistingDestination 验证在线备份拒绝覆盖已有文件，避免
// 把旧备份原样保留成“成功”的假象。
func TestOnlineBackupRejectsExistingDestination(t *testing.T) {
	store, _ := defaultTestStore(t)
	destination := filepath.Join(testutil.TempDir(t), "snapshot.db")
	if err := os.WriteFile(destination, []byte("keep"), 0o600); err != nil {
		t.Fatalf("准备目标文件失败：%v", err)
	}
	err := store.OnlineBackup(context.Background(), destination, nil)
	if err == nil {
		t.Fatal("已存在的目标文件未被拒绝")
	}
	content, readErr := os.ReadFile(destination)
	if readErr != nil {
		t.Fatalf("读取目标文件失败：%v", readErr)
	}
	if string(content) != "keep" {
		t.Fatalf("已存在目标文件被修改：%q", string(content))
	}
}

// TestOnlineBackupContextTimeout 验证备份遵守调用方期限。
func TestOnlineBackupContextTimeout(t *testing.T) {
	store, _ := defaultTestStore(t)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	err := store.OnlineBackup(ctx, filepath.Join(testutil.TempDir(t), "snapshot.db"), nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("超时错误 = %v，期望 context.DeadlineExceeded", err)
	}
}
