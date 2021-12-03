// Package fsutil 提供产品代码共用的文件系统删除辅助。
//
// 背景：Windows 上杀毒软件实时扫描、文件系统过滤驱动或其它进程的短暂占用，
// 会让刚写入/刚关闭的临时文件与暂存目录在删除瞬间返回“拒绝访问/共享冲突/
// 目录非空”等瞬时错误；标准库 os.Remove/os.RemoveAll 只尝试一次。备份、恢复与
// 清理流程若把这些瞬时状态当作最终失败，会出现“明文暂存目录无法删除”“临时文件
// 清理未完成”之类的偶发失败，并可能让已完成的流程保持维护状态。
//
// 本包在 Windows 上对已知的瞬时错误做有界重试（1ms→50ms 抖动退避，总预算 5 秒），
// 其余情况保持标准库语义：非 Windows 平台只尝试一次；非瞬时错误立即返回；预算
// 耗尽返回最后一次真实错误。本包不会吞掉最终失败，调用方原有的错误包装与
// fail-closed 判断保持不变。
//
// 本包只做单次路径的删除，不做递归扫描、不跟随符号链接、不提供无限重试。
package fsutil

import (
	"errors"
	"io/fs"
	"math/rand/v2"
	"os"
	"runtime"
	"syscall"
	"time"
)

const (
	// removeBudget 是单次删除调用最多花费的重试总时间预算。本机安全软件扫描大
	// 目录时的句柄释放延迟通常远小于该值；超过预算仍失败按最终失败返回。
	removeBudget = 5 * time.Second

	// minRemoveDelay/maxRemoveDelay 是抖动退避的起点与上限：每次等待在
	// [base/2, base] 内随机取值，base 从 1ms 起每轮翻倍并封顶 50ms。
	minRemoveDelay = time.Millisecond
	maxRemoveDelay = 50 * time.Millisecond
)

// transientWindowsErrnos 是 Windows 上可能由短暂占用造成、值得重试的文件系统
// 错误码。用数值定义以保持本包可跨平台编译与单元测试；仅 Windows 分支会使用。
var transientWindowsErrnos = []syscall.Errno{
	5,    // ERROR_ACCESS_DENIED：权限或句柄短暂拒绝（例如文件仍被映射/扫描）
	16,   // ERROR_CURRENT_DIRECTORY：目录仍是某进程的当前目录，持有者可能很快切走
	32,   // ERROR_SHARING_VIOLATION：文件仍被其它句柄以不共享方式打开
	33,   // ERROR_LOCK_VIOLATION：文件区域锁尚未释放
	145,  // ERROR_DIR_NOT_EMPTY：目录项在枚举与 RemoveDirectory 之间延迟释放（实测复现）
	1224, // ERROR_USER_MAPPED_FILE：文件仍有用户态内存映射，映射解除后可删
}

// remover 与 os.Remove、os.RemoveAll 的签名一致；测试可注入以覆盖重试路径。
type remover func(path string) error

// retryPolicy 描述一次删除调用的有界重试参数。
type retryPolicy struct {
	budget       time.Duration
	initialDelay time.Duration
	maxDelay     time.Duration
}

// retryHooks 注入时钟与等待实现：生产使用真实时间；单元测试使用假时钟以便
// 覆盖“预算耗尽”路径而无需真实等待，并可断言重试间隔。
type retryHooks struct {
	now   func() time.Time
	sleep func(time.Duration)
}

var (
	// defaultRetryPolicy 是产品调用的固定重试参数。
	defaultRetryPolicy = retryPolicy{
		budget:       removeBudget,
		initialDelay: minRemoveDelay,
		maxDelay:     maxRemoveDelay,
	}
	// realTimeHooks 是生产环境使用的真实时钟与等待。
	realTimeHooks = retryHooks{now: time.Now, sleep: time.Sleep}
)

// RemoveAllRetry 删除 path 及其全部内容。
//
// 语义与 os.RemoveAll 一致：路径不存在视为成功（包括调用前已不存在、以及重试
// 期间被它人删除）；路径是文件或空目录时同样删除。在 Windows 上，若删除返回
// 已知的瞬时错误（杀软扫描、过滤驱动、其它进程短暂持有句柄等），会在 5 秒总预算
// 内以 1ms→50ms 抖动退避重试；其它平台只尝试一次。预算耗尽或遇到非瞬时错误时
// 返回最后一次错误，调用方仍应按原有 fail-closed 逻辑处理。
//
// 本函数只用于临时/暂存/中间产物清理；删除用户原始备份或已发布产物应保留原有
// 单次语义并逐点说明，不得用重试掩盖真实失败。
func RemoveAllRetry(path string) error {
	return removeWithRetry(path, runtime.GOOS, os.RemoveAll, defaultRetryPolicy,
		realTimeHooks)
}

// RemoveRetry 删除单个文件（或空目录），删除语义与 os.Remove 一致：不递归删除
// 非空目录；路径不存在视为成功。
//
// 重试策略与 RemoveAllRetry 相同。用于单个临时文件、状态文件、日志分片等中间
// 产物的清理，避免把“文件已被删除”或“尚未释放句柄”误报为清理失败。
func RemoveRetry(path string) error {
	return removeWithRetry(path, runtime.GOOS, os.Remove, defaultRetryPolicy,
		realTimeHooks)
}

// removeWithRetry 按平台分流执行删除。goos、remove 与 hooks 显式传入以便单元
// 测试注入，从而在本机（Windows）也能验证非 Windows 的单次语义。
func removeWithRetry(path, goos string, remove remover, policy retryPolicy,
	hooks retryHooks) error {
	if goos != "windows" {
		return removeTolerant(path, remove)
	}
	deadline := hooks.now().Add(policy.budget)
	delay := policy.initialDelay
	for {
		err := removeTolerant(path, remove)
		if err == nil {
			return nil
		}
		if !isTransientRemoveError(err) {
			return err
		}
		remaining := deadline.Sub(hooks.now())
		if remaining <= 0 {
			return err
		}
		wait := jitteredDelay(delay)
		if wait > remaining {
			wait = remaining
		}
		hooks.sleep(wait)
		if delay < policy.maxDelay {
			delay *= 2
			if delay > policy.maxDelay {
				delay = policy.maxDelay
			}
		}
	}
}

// removeTolerant 执行一次删除并把“路径不存在”视为成功。os.RemoveAll 本身对
// 不存在的路径返回 nil，这里统一处理 os.Remove 与测试注入的删除函数。
func removeTolerant(path string, remove remover) error {
	err := remove(path)
	if err != nil && errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// isTransientRemoveError 判断错误是否属于 Windows 上值得重试的瞬时文件系统
// 错误。调用方保证只在 Windows 分支使用。
func isTransientRemoveError(err error) bool {
	for _, code := range transientWindowsErrnos {
		if errors.Is(err, code) {
			return true
		}
	}
	return false
}

// jitteredDelay 返回本次等待时长：在 [delay/2, delay] 内随机取值，避免多个清理
// 点在同一时刻重试形成同步删除风暴。delay 非正时返回零。
func jitteredDelay(delay time.Duration) time.Duration {
	if delay <= 0 {
		return 0
	}
	half := delay / 2
	if half <= 0 {
		return delay
	}
	return half + time.Duration(rand.Int64N(int64(half)+1))
}
