//go:build windows

package rootrecovery

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// lockFileExclusive 在 Windows 使用 LockFileEx 的排他锁并立即失败（不等待），
// 与同一数据库目录的其它恢复进程互斥。
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
