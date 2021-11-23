// Package testutil 提供仅供测试代码使用的共享辅助，不属于产品运行时依赖。
//
// 本包只应由 *_test.go 或其它测试辅助导入；当前提供 TempDir，用于替代标准库
// t.TempDir 在 Windows 上不够稳健的清理逻辑（详见 TempDir 文档）。
package testutil

import (
	"errors"
	"io/fs"
	"math/rand/v2"
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"
)

const (
	// cleanupBudget 是清理临时目录的总时间预算。标准库 testing 包对 Windows
	// 瞬时错误的重试上限是 2 秒，这里略放宽以覆盖安全软件扫描排队。
	cleanupBudget = 5 * time.Second

	// minBackoff、maxBackoff 是抖动退避的上下限。
	minBackoff = time.Millisecond
	maxBackoff = 50 * time.Millisecond

	// maxPatternLen 是临时目录名前缀的最大字节数。
	maxPatternLen = 64
)

// windowsRetryableErrnos 是 Windows 上可能瞬时出现、值得重试的文件系统错误码。
// 用数值定义以保持测试辅助可跨平台编译（非 Windows 平台这些 Errno 不会命中，
// 且 isRetryableRemoveError 会直接返回 false，等价于单次尝试）。
var windowsRetryableErrnos = []syscall.Errno{
	5,    // ERROR_ACCESS_DENIED：文件/目录仍被占用或映射
	32,   // ERROR_SHARING_VIOLATION：文件被其它句柄共享占用
	145,  // ERROR_DIR_NOT_EMPTY：目录项尚未全部消失
	16,   // ERROR_CURRENT_DIRECTORY：目录仍是某进程当前目录
	1224, // ERROR_USER_MAPPED_FILE：文件仍有用户内存映射
}

// TempDir 返回测试专用临时目录，并注册带有限重试的清理。
//
// 目录位置遵循 GOTMPDIR（未设置时使用系统临时目录），名称为 t.Name() 清洗后的
// 前缀。之所以不直接用 testing.T.TempDir：Windows 下标准库清理只对
// ERROR_ACCESS_DENIED 与 ERROR_SHARING_VIOLATION 重试，不重试
// ERROR_DIR_NOT_EMPTY；安全软件/文件系统过滤驱动可能在“枚举目录项 →
// RemoveDirectory”的窗口内延迟释放目录项，使删除瞬时返回“目录非空”，而标准库
// 会把它当作测试失败，即使毫秒后目录已为空。
//
// 因此这里改用 os.MkdirTemp + 自定义 t.Cleanup：在 5 秒预算内对已知的 Windows
// 瞬时错误做 1ms→50ms 的抖动退避重试；目录已不存在视为成功；预算耗尽仍失败时
// 报告错误，不吞错、不跳过断言、不影响被测产品行为。
//
// 调用方应在本函数之后登记数据库连接、后台任务等资源的关闭，依靠 t.Cleanup 的
// 后进先出顺序保证“先关闭连接与后台任务，最后删除目录”。
func TempDir(t testing.TB) string {
	t.Helper()
	dir, err := os.MkdirTemp(os.Getenv("GOTMPDIR"), sanitizeTempDirPattern(t.Name()))
	if err != nil {
		t.Fatalf("创建测试临时目录失败: %v", err)
	}
	t.Cleanup(func() {
		if err := removeAllWithRetry(dir, cleanupBudget, os.RemoveAll); err != nil {
			t.Errorf("清理测试临时目录失败: %v", err)
		}
	})
	return dir
}

// sanitizeTempDirPattern 把测试名转换为可安全用作临时目录名前缀的形式：替换
// 路径分隔符与 Windows 保留字符，并按字节截断到 64 个字符（不切断多字节字符）。
func sanitizeTempDirPattern(name string) string {
	replacer := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "*", "_",
		"?", "_", "\"", "_", "<", "_", ">", "_", "|", "_", " ", "_")
	clean := replacer.Replace(name)
	if len(clean) > maxPatternLen {
		clean = clean[:maxPatternLen]
		for len(clean) > 0 && !utf8.ValidString(clean) {
			clean = clean[:len(clean)-1]
		}
	}
	return clean
}

// removeAllWithRetry 在时间预算内重试删除目录。
//
// removeAll 是删除函数（生产调用传 os.RemoveAll），可注入以便单元测试覆盖重试
// 与预算耗尽路径。只重试 Windows 上已知的瞬时文件系统错误；路径不存在直接视为
// 成功；其它错误（例如权限被永久拒绝、非瞬时 I/O 错误）立即返回，避免把真实
// 故障拖成 5 秒等待。
func removeAllWithRetry(dir string, budget time.Duration, removeAll func(string) error) error {
	deadline := time.Now().Add(budget)
	backoff := minBackoff
	for {
		err := removeAll(dir)
		if err == nil || errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if !isRetryableRemoveError(err) || !time.Now().Before(deadline) {
			return err
		}
		time.Sleep(jitteredBackoff(backoff))
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

// isRetryableRemoveError 判断错误是否属于 Windows 上可能瞬时出现、值得重试的
// 文件系统错误。非 Windows 平台一律返回 false，即单次尝试。
func isRetryableRemoveError(err error) bool {
	if runtime.GOOS != "windows" {
		return false
	}
	for _, code := range windowsRetryableErrnos {
		if errors.Is(err, code) {
			return true
		}
	}
	return false
}

// jitteredBackoff 在 base 与 base 的 1.5 倍之间取抖动值，避免多个测试同时重试
// 形成同步删除风暴。base 非法时原样返回。
func jitteredBackoff(base time.Duration) time.Duration {
	half := base / 2
	if half <= 0 {
		return base
	}
	return base + time.Duration(rand.Int64N(int64(half)+1))
}
