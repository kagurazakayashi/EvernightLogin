package serverapp_test

// 测试临时目录清理稳定性辅助。
//
// 背景：Windows 下 t.TempDir 的自动清理（标准库 testing 包内的 removeAll）只对
// ERROR_ACCESS_DENIED 与 ERROR_SHARING_VIOLATION 做有限重试，不重试
// ERROR_DIR_NOT_EMPTY。全量测试运行时，本机安全软件/文件系统过滤驱动可能在
// “枚举目录项 → RemoveDirectory”之间的窗口内延迟释放目录项，使删除目录返回
// “The directory is not empty”，而该瞬时状态在隔离运行时无法复现。若直接交给
// t.TempDir 清理，会把环境瞬时状态当作测试失败。
//
// 因此这里改用 os.MkdirTemp + 自定义 t.Cleanup：先等调用方登记的数据库连接
// Close（t.Cleanup 后进先出）执行完，再在有限时间预算内对已知的 Windows 瞬时
// 文件系统错误重试 os.RemoveAll。预算耗尽仍失败时如实报告错误，不吞错、不跳过
// 断言、不影响被测产品行为。

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	// testTempDirRemoveBudget 是清理临时目录的总时间预算。标准库 testing 包对
	// Windows 瞬时错误的重试上限是 2 秒，这里略放宽以覆盖安全软件扫描排队。
	testTempDirRemoveBudget = 5 * time.Second

	// Windows 瞬时文件系统错误码；用数值定义以保持测试辅助可跨平台编译（在
	// 非 Windows 平台上这些 Errno 不会命中，等价于不重试）。
	winErrorAccessDenied     = syscall.Errno(5)    // ERROR_ACCESS_DENIED
	winErrorSharingViolation = syscall.Errno(32)   // ERROR_SHARING_VIOLATION
	winErrorLockViolation    = syscall.Errno(33)   // ERROR_LOCK_VIOLATION
	winErrorDirNotEmpty      = syscall.Errno(145)  // ERROR_DIR_NOT_EMPTY
	winErrorUserMappedFile   = syscall.Errno(1224) // ERROR_USER_MAPPED_FILE
)

// testTempDir 返回测试专用临时目录，并注册带有限重试的清理。
//
// 调用方应在本函数之后登记数据库/任务等资源的 Close 清理，依靠 t.Cleanup 的
// 后进先出顺序保证“先关闭连接与后台任务，最后删除目录”。
func testTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(os.Getenv("GOTMPDIR"), sanitizeTempDirPattern(t.Name())+"-")
	if err != nil {
		t.Fatalf("创建测试临时目录失败: %v", err)
	}
	t.Cleanup(func() {
		if err := removeTempDirWithRetry(dir, testTempDirRemoveBudget); err != nil {
			t.Errorf("清理测试临时目录失败: %v", err)
		}
	})
	return dir
}

// sanitizeTempDirPattern 把测试名转换为可安全用作临时目录名前缀的形式。
func sanitizeTempDirPattern(name string) string {
	replacer := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "*", "_",
		"?", "_", "\"", "_", "<", "_", ">", "_", "|", "_", " ", "_")
	clean := replacer.Replace(name)
	if len(clean) > 64 {
		clean = clean[:64]
	}
	return clean
}

// removeTempDirWithRetry 在时间预算内重试删除目录；只重试已知的 Windows 瞬时
// 文件系统错误，其余错误（例如权限被永久拒绝）立即返回。
func removeTempDirWithRetry(dir string, budget time.Duration) error {
	deadline := time.Now().Add(budget)
	sleep := time.Millisecond
	for {
		err := os.RemoveAll(dir)
		if err == nil {
			return nil
		}
		if !isTransientRemoveError(err) || !time.Now().Before(deadline) {
			return err
		}
		time.Sleep(sleep)
		if sleep < 50*time.Millisecond {
			sleep *= 2
		}
	}
}

// isTransientRemoveError 判断错误是否属于 Windows 上可能瞬时出现、值得重试的
// 文件系统错误。
func isTransientRemoveError(err error) bool {
	for _, transient := range []error{
		winErrorAccessDenied, winErrorSharingViolation, winErrorLockViolation,
		winErrorDirNotEmpty, winErrorUserMappedFile,
	} {
		if errors.Is(err, transient) {
			return true
		}
	}
	return false
}

// TestTempDirHelperRetriesTransientRemoveError 验证清理辅助对“文件仍被占用”这类
// Windows 瞬时错误做了有界重试：先占用文件，延迟释放，清理仍应成功。在非
// Windows 平台上删除打开中的文件通常直接成功，该用例同样通过（不产生假阴性）。
func TestTempDirHelperRetriesTransientRemoveError(t *testing.T) {
	dir, err := os.MkdirTemp(os.Getenv("GOTMPDIR"), "tempdir-retry-")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	file, err := os.OpenFile(filepath.Join(dir, "held-open.bin"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("创建占用文件失败: %v", err)
	}
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = file.Close()
	}()
	start := time.Now()
	if err := removeTempDirWithRetry(dir, 3*time.Second); err != nil {
		t.Fatalf("占用释放后重试清理应成功: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("清理后目录仍存在: %v", err)
	}
	t.Logf("带重试清理耗时 %v", time.Since(start))
}
