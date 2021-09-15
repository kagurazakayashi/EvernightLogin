//go:build !windows

// 本文件是 Unix 平台的恢复锁实现：flock 非阻塞排他锁。进程退出/被强杀时锁自动
// 释放；锁文件保留，下一次操作可安全复用。
package maintenance

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// errLockBusy 表示排他锁被其它打开文件描述/进程持有。
var errLockBusy = errors.New("恢复排他锁被占用")

// fileLock 是一个已取得的排他锁；Release 幂等。
type fileLock struct {
	file *os.File
}

// acquireLock 创建/打开锁文件并尝试取得非阻塞 flock 排他锁。
func acquireLock(path string) (*fileLock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	lockErr := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if lockErr != nil {
		_ = file.Close()
		if errors.Is(lockErr, unix.EWOULDBLOCK) || errors.Is(lockErr, unix.EAGAIN) {
			return nil, errLockBusy
		}
		return nil, lockErr
	}
	return &fileLock{file: file}, nil
}

// WriteMetadata 把操作元数据写入锁文件头部（便于本地排障，不含秘密）。
func (l *fileLock) WriteMetadata(text string) error {
	if l == nil || l.file == nil {
		return nil
	}
	if err := l.file.Truncate(0); err != nil {
		return err
	}
	if _, err := l.file.WriteAt([]byte(text), 0); err != nil {
		return err
	}
	return l.file.Sync()
}

// Release 释放锁并关闭文件；重复调用安全。
func (l *fileLock) Release() {
	if l == nil || l.file == nil {
		return
	}
	_ = unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
	_ = l.file.Close()
	l.file = nil
}

// isWindows 报告当前平台是否为 Windows。
func isWindows() bool { return false }

// syncDirectory 对目录执行 fsync，保证 rename 结果在崩溃后仍可见（Unix）。
func syncDirectory(directory string) {
	handle, err := os.Open(directory)
	if err != nil {
		return
	}
	defer handle.Close()
	_ = handle.Sync()
}

// FreeBytes 返回指定目录所在文件系统的可用字节数。
func FreeBytes(path string) (uint64, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, err
	}
	return stat.Bavail * uint64(stat.Bsize), nil
}
