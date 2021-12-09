//go:build windows

package serverapp

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// errLockAdapter 表示当前平台文件锁实现不可用。
var errLockAdapter = errors.New("文件锁实现不可用")

// lockFileExclusive 在 Windows 使用 LockFileEx 的排他锁并立即失败（不等待），
// 与同一数据库目录的其它 login-server 进程互斥。
func lockFileExclusive(file *os.File) error {
	if file == nil {
		return errLockAdapter
	}
	overlapped := new(windows.Overlapped)
	return windows.LockFileEx(windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, overlapped)
}

// unlockFile 释放 LockFileEx 锁。
func unlockFile(file *os.File) error {
	if file == nil {
		return fmt.Errorf("%w: 锁文件为空", errLockAdapter)
	}
	overlapped := new(windows.Overlapped)
	return windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, overlapped)
}
