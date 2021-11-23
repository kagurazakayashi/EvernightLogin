package testutil

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"
)

// TestTempDirCreatesAndCleansUp 验证 TempDir 在测试名前缀下创建目录，并在子测试
// 结束后由 t.Cleanup 删除该目录。
func TestTempDirCreatesAndCleansUp(t *testing.T) {
	var dir string
	t.Run("inner", func(t *testing.T) {
		dir = TempDir(t)
		prefix := sanitizeTempDirPattern(t.Name())
		if base := filepath.Base(dir); !strings.HasPrefix(base, prefix) {
			t.Fatalf("临时目录名 %q 未使用测试名前缀 %q", base, prefix)
		}
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("临时目录应存在: %v", err)
		}
		if !info.IsDir() {
			t.Fatalf("临时目录路径不是目录: %s", dir)
		}
		if err := os.WriteFile(filepath.Join(dir, "probe.txt"), []byte("probe"), 0o600); err != nil {
			t.Fatalf("写入探针文件失败: %v", err)
		}
	})
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("子测试结束后临时目录应已被清理，实际 Stat 错误: %v", err)
	}
}

// TestTempDirUsesGOTMPDIR 验证临时目录位置遵循 GOTMPDIR 环境变量。
func TestTempDirUsesGOTMPDIR(t *testing.T) {
	base := TempDir(t)
	t.Setenv("GOTMPDIR", base)
	dir := TempDir(t)
	if got, want := filepath.Clean(filepath.Dir(dir)), filepath.Clean(base); got != want {
		t.Fatalf("临时目录应在 GOTMPDIR 下创建：父目录 = %q，期望 %q", got, want)
	}
}

// TestTempDirCleanupRetriesWhenFileStillOpen 验证清理注册项在目录内文件仍被打开
// 时会重试，而不是立刻报错；goroutine 稍后关闭文件后清理应成功。
//
// 该用例依赖 Windows 的共享占用语义，非 Windows 上跳过（那边删除打开中的文件
// 通常直接成功，无法覆盖重试分支）。
func TestTempDirCleanupRetriesWhenFileStillOpen(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("仅 Windows 存在打开文件的共享占用语义")
	}
	dir := TempDir(t)
	file, err := os.OpenFile(filepath.Join(dir, "held-open.bin"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("创建占用文件失败: %v", err)
	}
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = file.Close()
	}()
	// 不在测试体内删除：由 TempDir 注册的清理在测试结束时完成，从而覆盖重试路径。
	// 若清理失败，t.Cleanup 中的 t.Errorf 会让本测试失败。
}

// TestSanitizeTempDirPattern 验证测试名清洗：路径分隔符与 Windows 保留字符被
// 替换，超长名称截断到上限且不产生非法 UTF-8。
func TestSanitizeTempDirPattern(t *testing.T) {
	cases := []struct{ in, want string }{
		{"TestFoo", "TestFoo"},
		{"TestFoo/bar", "TestFoo_bar"},
		{`TestFoo\bar`, "TestFoo_bar"},
		{`TestFoo:bar*baz?qux`, "TestFoo_bar_baz_qux"},
		{`TestFoo"bar<baz>qux|end`, `TestFoo_bar_baz_qux_end`},
		{"TestFoo bar", "TestFoo_bar"},
	}
	for _, tc := range cases {
		if got := sanitizeTempDirPattern(tc.in); got != tc.want {
			t.Errorf("sanitizeTempDirPattern(%q) = %q，期望 %q", tc.in, got, tc.want)
		}
	}

	long := strings.Repeat("a", 100)
	if got := sanitizeTempDirPattern(long); len(got) != maxPatternLen {
		t.Errorf("超长 ASCII 名称应截断到 %d 字节，实际 %d", maxPatternLen, len(got))
	}

	multi := strings.Repeat("测", 40)
	got := sanitizeTempDirPattern(multi)
	if len(got) > maxPatternLen {
		t.Errorf("多字节名称截断后仍超过 %d 字节: %d", maxPatternLen, len(got))
	}
	if !utf8.ValidString(got) {
		t.Errorf("多字节名称截断产生了非法 UTF-8: %q", got)
	}
}

// TestRemoveAllWithRetryTreatsNotExistAsSuccess 验证“路径不存在”视为清理成功，
// 且不触发重试。
func TestRemoveAllWithRetryTreatsNotExistAsSuccess(t *testing.T) {
	calls := 0
	removeAll := func(string) error {
		calls++
		return &os.PathError{Op: "remove", Path: "probe", Err: fs.ErrNotExist}
	}
	if err := removeAllWithRetry("probe", time.Second, removeAll); err != nil {
		t.Fatalf("路径不存在应视为成功，实际返回: %v", err)
	}
	if calls != 1 {
		t.Fatalf("路径不存在不应重试，实际调用 %d 次", calls)
	}

	// os.RemoveAll 对不存在的真实路径本身也返回 nil，一并覆盖生产路径。
	if err := removeAllWithRetry(filepath.Join(TempDir(t), "missing-dir"), time.Second, os.RemoveAll); err != nil {
		t.Fatalf("删除不存在的真实路径应成功，实际返回: %v", err)
	}
}

// TestRemoveAllWithRetryDoesNotRetryPermanentError 验证非瞬时错误只尝试一次并
// 原样返回，不把真实故障拖成时间预算等待。
func TestRemoveAllWithRetryDoesNotRetryPermanentError(t *testing.T) {
	permanent := errors.New("永久失败")
	calls := 0
	removeAll := func(string) error {
		calls++
		return permanent
	}
	err := removeAllWithRetry("probe", time.Second, removeAll)
	if !errors.Is(err, permanent) {
		t.Fatalf("应原样返回永久错误，实际返回: %v", err)
	}
	if calls != 1 {
		t.Fatalf("永久错误不应重试，实际调用 %d 次", calls)
	}
}

// TestRemoveAllWithRetrySucceedsAfterTransientErrors 验证 Windows 瞬时错误会在
// 预算内重试直到成功，且重试之间确实有退避。
func TestRemoveAllWithRetrySucceedsAfterTransientErrors(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows 瞬时错误重试仅适用于 Windows")
	}
	transient := syscall.Errno(145) // ERROR_DIR_NOT_EMPTY
	calls := 0
	removeAll := func(string) error {
		calls++
		if calls <= 2 {
			return transient
		}
		return nil
	}
	start := time.Now()
	if err := removeAllWithRetry("probe", 2*time.Second, removeAll); err != nil {
		t.Fatalf("瞬时错误重试后应成功，实际返回: %v", err)
	}
	if calls != 3 {
		t.Fatalf("应在第 3 次调用成功，实际调用 %d 次", calls)
	}
	if elapsed := time.Since(start); elapsed < minBackoff {
		t.Fatalf("重试之间应有退避，实际耗时 %v 小于 %v", elapsed, minBackoff)
	}
}

// TestRemoveAllWithRetryExhaustsBudget 验证瞬时错误持续存在时会在预算耗尽后
// 返回最后一个错误，而不是无限重试。
func TestRemoveAllWithRetryExhaustsBudget(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows 瞬时错误重试仅适用于 Windows")
	}
	transient := syscall.Errno(1224) // ERROR_USER_MAPPED_FILE
	calls := 0
	removeAll := func(string) error {
		calls++
		return transient
	}
	budget := 20 * time.Millisecond
	start := time.Now()
	err := removeAllWithRetry("probe", budget, removeAll)
	if !errors.Is(err, transient) {
		t.Fatalf("预算耗尽应返回最后一个瞬时错误，实际返回: %v", err)
	}
	if calls < 2 {
		t.Fatalf("预算耗尽前应至少重试一次，实际调用 %d 次", calls)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("清理重试超出预期耗时: %v", elapsed)
	}
}

// TestRemoveAllWithRetrySingleAttemptOnNonWindows 验证非 Windows 平台对错误只做
// 单次尝试（不重试 Windows 瞬时错误码）。
func TestRemoveAllWithRetrySingleAttemptOnNonWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("该用例验证非 Windows 的单次尝试语义")
	}
	code := syscall.Errno(145)
	calls := 0
	removeAll := func(string) error {
		calls++
		return code
	}
	err := removeAllWithRetry("probe", time.Second, removeAll)
	if !errors.Is(err, code) {
		t.Fatalf("应返回原始错误，实际返回: %v", err)
	}
	if calls != 1 {
		t.Fatalf("非 Windows 应只尝试一次，实际调用 %d 次", calls)
	}
}

// TestJitteredBackoffWithinBounds 验证抖动退避位于 [base, base*1.5] 范围内。
func TestJitteredBackoffWithinBounds(t *testing.T) {
	bases := []time.Duration{time.Millisecond, 7 * time.Millisecond, maxBackoff}
	for _, base := range bases {
		for i := 0; i < 50; i++ {
			got := jitteredBackoff(base)
			if got < base || got > base+base/2 {
				t.Fatalf("jitteredBackoff(%v) = %v，超出 [%v, %v]", base, got, base, base+base/2)
			}
		}
	}
	if got := jitteredBackoff(0); got != 0 {
		t.Fatalf("jitteredBackoff(0) = %v，期望 0", got)
	}
}
