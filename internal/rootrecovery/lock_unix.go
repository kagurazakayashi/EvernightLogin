//go:build !windows

package rootrecovery

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// lockFileExclusive 在类 Unix 系统使用 flock 排他非阻塞锁；同进程其它句柄与其它
// 进程都会冲突，进程内注册表另外保证确定性拒绝。
func lockFileExclusive(file *os.File) error {
	if file == nil {
		return errLockAdapter
	}
	return unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}

// unlockFile 释放 flock 锁。
func unlockFile(file *os.File) error {
	if file == nil {
		return fmt.Errorf("%w: 锁文件为空", errLockAdapter)
	}
	return unix.Flock(int(file.Fd()), unix.LOCK_UN)
}
