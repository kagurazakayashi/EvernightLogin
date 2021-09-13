package backup

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const (
	// lockFilePrefix/lockFileSuffix 是每次备份运行锁文件命名规则。运行锁在创建
	// 暂存目录前取得，在清理并发布结束后释放；进程被强杀时操作系统释放文件锁，
	// 下一次 Create 可以立即收回残留的明文暂存目录，而不会误删其它活动备份。
	lockFilePrefix = ".elnbak-lock-"
	lockFileSuffix = ".lock"
)

// errLockBusy 表示运行锁被其它活动进程/goroutine 持有。清理逻辑遇到该错误必须
// 跳过对应残留，绝不能强行删除正在写入的暂存目录。
var errLockBusy = errors.New("备份运行锁被占用")

// runLock 是一次备份运行持有的排他文件锁。释放时删除锁文件；进程被强杀时锁由
// 操作系统自动释放，锁文件按“无持有者”处理并在下次安全检查时清理。
type runLock struct {
	file *os.File
	path string
}

// lockFilePath 返回指定备份编号的运行锁路径。
func lockFilePath(outputDir, backupID string) string {
	return filepath.Join(outputDir, lockFilePrefix+backupID+lockFileSuffix)
}

// acquireRunLock 创建并尝试以非阻塞方式取得排他文件锁。返回 errLockBusy 表示已有
// 活动持有者；其它错误表示锁文件创建/加锁失败，调用方应按 fail-closed 处理。
func acquireRunLock(path string) (*runLock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := tryFileLock(file); err != nil {
		_ = file.Close()
		if errors.Is(err, errLockBusy) {
			return nil, errLockBusy
		}
		return nil, err
	}
	return &runLock{file: file, path: path}, nil
}

// Release 释放文件锁并删除锁文件（幂等；删除失败只可能是残留锁文件，不影响安全）。
func (l *runLock) Release() {
	if l == nil || l.file == nil {
		return
	}
	_ = unlockFile(l.file)
	_ = l.file.Close()
	_ = os.Remove(l.path)
	l.file = nil
}

// backupIDFromResidue 从临时文件/暂存目录名解析出备份编号。无法解析的条目不属于
// 本包已知格式，只能按年龄门槛保守清理。
func backupIDFromResidue(name string) string {
	switch {
	case strings.HasPrefix(name, tempFilePrefix) && strings.HasSuffix(name, tempFileSuffix):
		id := strings.TrimSuffix(strings.TrimPrefix(name, tempFilePrefix), tempFileSuffix)
		if validateBackupID(id) == nil {
			return id
		}
	case strings.HasPrefix(name, stagingDirPrefix):
		rest := strings.TrimPrefix(name, stagingDirPrefix)
		if index := strings.IndexByte(rest, '-'); index > 0 {
			id := rest[:index]
			if validateBackupID(id) == nil {
				return id
			}
		}
	}
	return ""
}

// backupIDFromLockName 从运行锁文件名解析备份编号。
func backupIDFromLockName(name string) string {
	if !strings.HasPrefix(name, lockFilePrefix) || !strings.HasSuffix(name, lockFileSuffix) {
		return ""
	}
	id := strings.TrimSuffix(strings.TrimPrefix(name, lockFilePrefix), lockFileSuffix)
	if validateBackupID(id) != nil {
		return ""
	}
	return id
}
