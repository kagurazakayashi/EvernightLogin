//go:build !windows

package backup

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// tryFileLock 在 Unix 上使用 flock 非阻塞排他锁；进程退出/被强杀时锁自动释放。
func tryFileLock(file *os.File) error {
	err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return errLockBusy
	}
	return err
}

// unlockFile 释放 flock 锁。
func unlockFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_UN)
}
