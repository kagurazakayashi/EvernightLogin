package serverapp

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// InstanceLockSuffix 是单实例锁文件名后缀；锁文件与数据库同目录，避免不同数据
// 目录之间误判。锁文件内容只写 PID 与时间等排障元数据，不含秘密。
const InstanceLockSuffix = ".server.lock"

// ErrInstanceLocked 表示同一数据库已被另一个 login-server 进程（或本进程内另一个
// serve 实例）占用。独立服务第一版按单实例部署，不实现多进程共享同一 SQLite。
var ErrInstanceLocked = errors.New("数据库已被另一个 login-server 实例占用（单实例约束）")

// instanceLock 是一个已获取的单实例排他锁。OS 文件锁在进程退出时由操作系统释放，
// 锁文件本身保留（内容为最后一次持有的排障信息），避免删除-重建的跨进程竞态。
type instanceLock struct {
	path     string
	registry string
	file     *os.File
	released bool
	mu       sync.Mutex
}

// heldInstanceLocks 记录本进程已持有的锁路径：同进程内第二次 serve 立即失败，
// 不依赖各平台对同进程多句柄文件锁的差异行为。
var heldInstanceLocks sync.Map

// AcquireInstanceLock 为给定数据库取得单实例排他锁。
//
// databasePath 可以是尚不存在的路径（首次 serve 前由 init 创建，或 serve 先探针
// 连接）；锁文件放在规范化后的数据库父目录中。路径解析使用父目录的真实路径，
// 使同一数据目录的不同写法（相对/符号链接）归一到同一锁。
func AcquireInstanceLock(databasePath string) (*instanceLock, error) {
	if databasePath == "" {
		return nil, fmt.Errorf("单实例锁缺少数据库路径")
	}
	absolutePath, err := filepath.Abs(databasePath)
	if err != nil {
		return nil, fmt.Errorf("单实例锁数据库路径无效: %w", err)
	}
	directory := filepath.Dir(absolutePath)
	if resolved, resolveErr := filepath.EvalSymlinks(directory); resolveErr == nil {
		directory = resolved
	}
	lockPath := filepath.Join(directory, filepath.Base(absolutePath)+InstanceLockSuffix)
	if _, loaded := heldInstanceLocks.LoadOrStore(lockPath, struct{}{}); loaded {
		return nil, fmt.Errorf("%w：本进程已有一个 serve 使用该数据库", ErrInstanceLocked)
	}
	releaseRegistry := func() { heldInstanceLocks.Delete(lockPath) }
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		releaseRegistry()
		return nil, fmt.Errorf("打开单实例锁文件失败: %w", err)
	}
	if err := lockFileExclusive(file); err != nil {
		_ = file.Close()
		releaseRegistry()
		return nil, fmt.Errorf("%w：%v", ErrInstanceLocked, err)
	}
	lock := &instanceLock{path: lockPath, registry: lockPath, file: file}
	_ = file.Truncate(0)
	metadata := fmt.Sprintf("pid=%d started=%s\n", os.Getpid(),
		time.Now().UTC().Format(time.RFC3339))
	_, _ = file.WriteAt([]byte(metadata), 0)
	_ = file.Sync()
	return lock, nil
}

// Path 返回锁文件路径（排障用，不含秘密）。
func (l *instanceLock) Path() string {
	if l == nil {
		return ""
	}
	return l.path
}

// Release 释放单实例锁并关闭文件；可重复调用。
func (l *instanceLock) Release() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.released {
		return
	}
	l.released = true
	_ = unlockFile(l.file)
	if l.file != nil {
		_ = l.file.Close()
		l.file = nil
	}
	heldInstanceLocks.Delete(l.registry)
}
