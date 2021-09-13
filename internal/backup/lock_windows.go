//go:build windows

package backup

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// tryFileLock 在 Windows 上使用 LockFileEx 非阻塞排他锁；进程退出/被强杀时系统
// 自动释放文件锁，锁文件随后可被下一次启动的安全清理回收。
func tryFileLock(file *os.File) error {
	var overlapped windows.Overlapped
	err := windows.LockFileEx(windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, &overlapped)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return errLockBusy
	}
	return err
}

// unlockFile 释放 LockFileEx 锁。
func unlockFile(file *os.File) error {
	var overlapped windows.Overlapped
	return windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &overlapped)
}
