package rootrecovery

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
)

// TestFileLockExclusiveAdapter 直接验证 OS 文件锁适配器：同一路径第二个排他锁
// 立即失败，释放后可重新取得。它不依赖恢复流程，覆盖跨进程互斥的底层实现。
func TestFileLockExclusiveAdapter(t *testing.T) {
	path := filepath.Join(testutil.TempDir(t), "lock.db")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("准备文件: %v", err)
	}
	first, err := acquireLock(path, Operator{ID: "os:test@host", Machine: "host"}, time.Now())
	if err != nil {
		t.Fatalf("第一次取得锁: %v", err)
	}
	// 进程内注册表会先拒绝；为验证 OS 锁本身，直接对同一路径新建文件句柄加锁，
	// 绕开注册表检查。
	secondFile, err := os.OpenFile(filepath.Join(filepath.Dir(path), LockFileName),
		os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("打开锁文件: %v", err)
	}
	if err := lockFileExclusive(secondFile); err == nil {
		_ = unlockFile(secondFile)
		_ = secondFile.Close()
		t.Fatal("同一文件句柄之外的第二个排他锁应失败")
	}
	_ = secondFile.Close()
	first.Release()
	third, err := acquireLock(path, Operator{ID: "os:test@host", Machine: "host"}, time.Now())
	if err != nil {
		t.Fatalf("释放后重新取得锁: %v", err)
	}
	third.Release()
}
