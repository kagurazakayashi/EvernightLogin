//go:build windows

// 本文件是 Windows 平台的恢复锁实现：LockFileEx 非阻塞排他锁。进程退出/被强杀时
// 系统自动释放文件锁；锁文件保留，下一次操作可安全复用。
package maintenance

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// errLockBusy 表示排他锁被其它句柄/进程持有。
var errLockBusy = errors.New("恢复排他锁被占用")

// fileLock 是一个已取得的排他锁；Release 幂等。
type fileLock struct {
	file *os.File
}

// acquireLock 创建/打开锁文件并尝试取得非阻塞排他锁。返回 errLockBusy 表示已有
// 持有者；其它错误表示锁文件不可用，调用方按 fail-closed 处理。
func acquireLock(path string) (*fileLock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	var overlapped windows.Overlapped
	lockErr := windows.LockFileEx(windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, &overlapped)
	if lockErr != nil {
		_ = file.Close()
		if errors.Is(lockErr, windows.ERROR_LOCK_VIOLATION) {
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
	var overlapped windows.Overlapped
	_ = windows.UnlockFileEx(windows.Handle(l.file.Fd()), 0, 1, 0, &overlapped)
	_ = l.file.Close()
	l.file = nil
}

// isWindows 报告当前平台是否为 Windows。
func isWindows() bool { return true }

// syncDirectory 在 Windows 上不提供目录 fsync（Go 不支持），依赖文件本身 fsync 与
// 文件系统语义；README 已声明该边界。
func syncDirectory(_ string) {}

// FreeBytes 返回指定目录所在卷的可用字节数（Windows GetDiskFreeSpaceEx）。
func FreeBytes(path string) (uint64, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var freeToCaller, total, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(pointer, &freeToCaller, &total, &totalFree); err != nil {
		return 0, err
	}
	return freeToCaller, nil
}
