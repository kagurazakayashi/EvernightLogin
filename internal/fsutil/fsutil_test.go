package fsutil

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
)

// fakeClock 是测试用假时钟：Sleep 只推进逻辑时间并记录等待时长，不真实休眠，
// 从而能快速、确定地覆盖预算耗尽与退避参数。
type fakeClock struct {
	now    time.Time
	sleeps []time.Duration
}

// newFakeClock 返回从固定时刻开始的假时钟。
func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)}
}

// hooks 返回使用该假时钟的 retryHooks。
func (c *fakeClock) hooks() retryHooks {
	return retryHooks{
		now: func() time.Time { return c.now },
		sleep: func(delay time.Duration) {
			c.sleeps = append(c.sleeps, delay)
			c.now = c.now.Add(delay)
		},
	}
}

// testPolicy 返回测试用重试参数：预算缩短到 100ms 但仍使用产品退避参数。
func testPolicy() retryPolicy {
	return retryPolicy{
		budget:       100 * time.Millisecond,
		initialDelay: minRemoveDelay,
		maxDelay:     maxRemoveDelay,
	}
}

// pathError 构造与 os.Remove/os.RemoveAll 相同形态的错误，便于注入。
func pathError(err error) error {
	return &os.PathError{Op: "remove", Path: "probe", Err: err}
}

// TestRemoveAllRetryRemovesTree 验证真实删除路径：目录树被递归删除，随后路径不存在。
func TestRemoveAllRetryRemovesTree(t *testing.T) {
	root := testutil.TempDir(t)
	target := filepath.Join(root, "staging")
	if err := os.MkdirAll(filepath.Join(target, "nested", "deeper"), 0o700); err != nil {
		t.Fatalf("创建测试目录树失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join(target, "nested", "deeper", "probe.bin"),
		[]byte("probe"), 0o600); err != nil {
		t.Fatalf("写入测试文件失败: %v", err)
	}
	if err := RemoveAllRetry(target); err != nil {
		t.Fatalf("删除目录树失败: %v", err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("目录树应已删除，实际 Lstat 错误: %v", err)
	}
}

// TestRemoveAllRetryRemovesRegularFile 验证 RemoveAllRetry 与 os.RemoveAll 一致：
// 对单个文件路径同样删除成功。
func TestRemoveAllRetryRemovesRegularFile(t *testing.T) {
	path := filepath.Join(testutil.TempDir(t), "temp.bin")
	if err := os.WriteFile(path, []byte("probe"), 0o600); err != nil {
		t.Fatalf("写入测试文件失败: %v", err)
	}
	if err := RemoveAllRetry(path); err != nil {
		t.Fatalf("删除临时文件失败: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("临时文件应已删除，实际 Lstat 错误: %v", err)
	}
}

// TestRemoveAllRetryMissingPathIsSuccess 验证路径不存在视为清理成功（幂等），
// 与 os.RemoveAll 的语义一致。
func TestRemoveAllRetryMissingPathIsSuccess(t *testing.T) {
	missing := filepath.Join(testutil.TempDir(t), "never-created", "staging")
	if err := RemoveAllRetry(missing); err != nil {
		t.Fatalf("不存在的路径应视为成功，实际返回: %v", err)
	}
	if err := RemoveRetry(missing); err != nil {
		t.Fatalf("RemoveRetry 对不存在的路径应视为成功，实际返回: %v", err)
	}
}

// TestRemoveRetryRemovesSingleFile 验证 RemoveRetry 删除单个真实文件，并在重复
// 调用时仍视为成功。
func TestRemoveRetryRemovesSingleFile(t *testing.T) {
	path := filepath.Join(testutil.TempDir(t), "state.json")
	if err := os.WriteFile(path, []byte("probe"), 0o600); err != nil {
		t.Fatalf("写入测试文件失败: %v", err)
	}
	if err := RemoveRetry(path); err != nil {
		t.Fatalf("删除临时文件失败: %v", err)
	}
	if err := RemoveRetry(path); err != nil {
		t.Fatalf("重复删除应视为成功，实际返回: %v", err)
	}
}

// TestRemoveWithRetryRetriesTransientErrorThenSucceeds 验证可注入删除函数上的
// 重试路径：连续两次 ERROR_DIR_NOT_EMPTY 后成功，且只重试瞬时错误、等待时长
// 落在抖动退避区间内。
func TestRemoveWithRetryRetriesTransientErrorThenSucceeds(t *testing.T) {
	calls := 0
	remove := func(string) error {
		calls++
		if calls <= 2 {
			return pathError(syscall.Errno(145)) // ERROR_DIR_NOT_EMPTY
		}
		return nil
	}
	clock := newFakeClock()
	start := clock.now
	err := removeWithRetry("probe", "windows", remove, testPolicy(), clock.hooks())
	if err != nil {
		t.Fatalf("瞬时错误重试后应成功，实际返回: %v", err)
	}
	if calls != 3 {
		t.Fatalf("应在第 3 次尝试成功，实际调用 %d 次", calls)
	}
	if len(clock.sleeps) != 2 {
		t.Fatalf("应退避 2 次，实际 %d 次: %v", len(clock.sleeps), clock.sleeps)
	}
	// 退避从 1ms 起翻倍，每次等待在 [base/2, base] 内。
	for index, base := range []time.Duration{minRemoveDelay, 2 * minRemoveDelay} {
		wait := clock.sleeps[index]
		if wait < base/2 || wait > base {
			t.Fatalf("第 %d 次退避 %v 超出 [%v, %v]", index+1, wait, base/2, base)
		}
	}
	if elapsed := clock.now.Sub(start); elapsed <= 0 {
		t.Fatalf("重试应推进时间，实际推进 %v", elapsed)
	}
}

// TestRemoveWithRetryReturnsLastErrorAfterBudget 验证预算耗尽时返回最后一次真实
// 错误，且总等待不超过预算。
func TestRemoveWithRetryReturnsLastErrorAfterBudget(t *testing.T) {
	calls := 0
	remove := func(string) error {
		calls++
		return pathError(syscall.Errno(32)) // ERROR_SHARING_VIOLATION
	}
	clock := newFakeClock()
	start := clock.now
	policy := testPolicy()
	err := removeWithRetry("probe", "windows", remove, policy, clock.hooks())
	if err == nil {
		t.Fatal("持续瞬时错误在预算耗尽后应返回错误")
	}
	if !errors.Is(err, syscall.Errno(32)) {
		t.Fatalf("应返回最后一次瞬时错误，实际: %v", err)
	}
	if calls < 2 {
		t.Fatalf("预算内应多次重试，实际调用 %d 次", calls)
	}
	if elapsed := clock.now.Sub(start); elapsed != policy.budget {
		t.Fatalf("总等待应恰为预算 %v，实际 %v", policy.budget, elapsed)
	}
}

// TestRemoveWithRetryDoesNotSwallowPermanentError 验证非瞬时错误立即返回且不被
// 重试吞掉：调用次数为 1、不等待，并保留原始错误链。
func TestRemoveWithRetryDoesNotSwallowPermanentError(t *testing.T) {
	permanent := errors.New("权限被永久拒绝")
	calls := 0
	remove := func(string) error {
		calls++
		return pathError(permanent)
	}
	clock := newFakeClock()
	err := removeWithRetry("probe", "windows", remove, testPolicy(), clock.hooks())
	if err == nil {
		t.Fatal("永久错误必须返回失败")
	}
	if !errors.Is(err, permanent) {
		t.Fatalf("应保留原始错误链，实际: %v", err)
	}
	if calls != 1 {
		t.Fatalf("非瞬时错误不应重试，实际调用 %d 次", calls)
	}
	if len(clock.sleeps) != 0 {
		t.Fatalf("非瞬时错误不应等待，实际等待 %v", clock.sleeps)
	}
}

// TestRemoveWithRetryTreatsNotExistAsSuccess 验证注入的删除函数返回“不存在”时
// 视为成功且不重试。
func TestRemoveWithRetryTreatsNotExistAsSuccess(t *testing.T) {
	calls := 0
	remove := func(string) error {
		calls++
		return pathError(fs.ErrNotExist)
	}
	clock := newFakeClock()
	if err := removeWithRetry("probe", "windows", remove, testPolicy(),
		clock.hooks()); err != nil {
		t.Fatalf("不存在的路径应视为成功，实际返回: %v", err)
	}
	if calls != 1 || len(clock.sleeps) != 0 {
		t.Fatalf("不存在路径不应重试：调用 %d 次，等待 %v", calls, clock.sleeps)
	}
}

// TestRemoveWithRetryNonWindowsSingleAttempt 验证非 Windows 平台只尝试一次：
// 即使错误属于 Windows 瞬时错误码也不重试、不吞错。
func TestRemoveWithRetryNonWindowsSingleAttempt(t *testing.T) {
	calls := 0
	remove := func(string) error {
		calls++
		return pathError(syscall.Errno(145))
	}
	clock := newFakeClock()
	err := removeWithRetry("probe", "linux", remove, testPolicy(), clock.hooks())
	if err == nil {
		t.Fatal("非 Windows 平台的删除错误必须返回失败")
	}
	if calls != 1 {
		t.Fatalf("非 Windows 平台应只尝试一次，实际调用 %d 次", calls)
	}
	if len(clock.sleeps) != 0 {
		t.Fatalf("非 Windows 平台不应等待，实际等待 %v", clock.sleeps)
	}
}

// TestTransientWindowsErrnos 记录并校验“按实测”纳入重试的错误码集合，同时确认
// 明显属于永久失败的错误码不会被误判为瞬时错误。
func TestTransientWindowsErrnos(t *testing.T) {
	const errorPrivilegeNotHeld = syscall.Errno(1314)
	transient := []syscall.Errno{5, 16, 32, 33, 145, 1224}
	for _, code := range transient {
		if !isTransientRemoveError(pathError(code)) {
			t.Errorf("错误码 %d 应判为 Windows 瞬时错误", code)
		}
	}
	for _, code := range []syscall.Errno{errorPrivilegeNotHeld, 2, 3} {
		if isTransientRemoveError(pathError(code)) {
			t.Errorf("错误码 %d 不应判为瞬时错误", code)
		}
	}
	if isTransientRemoveError(pathError(fs.ErrPermission)) {
		t.Error("fs.ErrPermission 不应判为瞬时错误")
	}
	if isTransientRemoveError(nil) {
		t.Error("nil 不应判为瞬时错误")
	}
}

// TestJitteredDelayBounds 验证抖动退避落在 [delay/2, delay] 内，且非法输入返回零。
func TestJitteredDelayBounds(t *testing.T) {
	cases := []time.Duration{minRemoveDelay, 2 * minRemoveDelay, maxRemoveDelay}
	for _, base := range cases {
		for attempt := 0; attempt < 50; attempt++ {
			wait := jitteredDelay(base)
			if wait < base/2 || wait > base {
				t.Fatalf("delay=%v 的抖动值 %v 超出 [%v, %v]", base, wait, base/2, base)
			}
		}
	}
	if got := jitteredDelay(0); got != 0 {
		t.Fatalf("零延迟应返回 0，实际 %v", got)
	}
	if got := jitteredDelay(-time.Millisecond); got != 0 {
		t.Fatalf("负延迟应返回 0，实际 %v", got)
	}
}
