// Package rootrecovery：数据库目录排他锁（跨进程 + 进程内重入拒绝）。
package rootrecovery

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// heldLocks 记录本进程已持有的锁路径，保证同一进程内两次恢复被拒绝（OS 文件锁
// 在不同实现下对同进程多句柄行为不一致，进程内注册表提供确定语义）。
var heldLocks sync.Map

// lockDirName 是系统临时目录中按数据库文件身份存放互斥锁的子目录名；身份锁用来
// 统一同一底层文件的不同路径（硬链接），目录锁文件满足“数据库目录锁”约定。
const lockDirName = "evernight-login-root-recovery"

// fileLock 是一个已获取的排他锁；Release 幂等。
type fileLock struct {
	path       string
	identityID string
	file       *os.File
	identity   *os.File
	released   bool
	mu         sync.Mutex
}

// acquireLock 在数据库所在目录创建/打开隐藏锁文件并取得排他锁。
//
// 语义：
//   - 同一路径本进程内并发/重入返回 ErrLocked；
//   - 其他进程持有 OS 排他锁时返回 ErrLocked；
//   - 获取后清空并写入操作元数据（PID/时间/操作者），便于本地排障；不写入秘密。
func acquireLock(databasePath string, operator Operator, now time.Time) (*fileLock, error) {
	absolute, err := filepath.Abs(databasePath)
	if err != nil {
		return nil, fmt.Errorf("%w: 无法解析数据库路径", ErrOptionsInvalid)
	}
	// 使用真实路径（解析符号链接/相对路径）确定数据库目录锁位置，并按底层文件身份
	// 生成额外锁：同一数据库的符号链接路径会归一到同一目录锁；硬链接无法通过路径
	// 统一，由文件身份锁（卷序列号+文件索引 / dev+inode）覆盖。
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return nil, fmt.Errorf("%w: 数据库路径无法解析为真实路径（文件缺失或符号链接损坏）",
			ErrInvalidDatabase)
	}
	identityID, err := fileIdentity(resolved)
	if err != nil {
		return nil, fmt.Errorf("%w: 无法识别数据库文件身份", ErrInvalidDatabase)
	}
	identityLockPath := identityLockPath(identityID)
	if _, loaded := heldLocks.LoadOrStore(identityID, struct{}{}); loaded {
		return nil, ErrLocked
	}
	releaseRegistry := func() { heldLocks.Delete(identityID) }

	// 先取得按底层文件身份的锁（系统临时目录，0600），再取得数据库目录锁。
	if err := os.MkdirAll(filepath.Dir(identityLockPath), 0o700); err != nil {
		releaseRegistry()
		return nil, fmt.Errorf("%w: 无法创建恢复身份锁目录", ErrStoreUnavailable)
	}
	identityFile, err := os.OpenFile(identityLockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		releaseRegistry()
		return nil, fmt.Errorf("%w: 无法创建文件身份锁", ErrStoreUnavailable)
	}
	if err := lockFileExclusive(identityFile); err != nil {
		_ = identityFile.Close()
		releaseRegistry()
		return nil, ErrLocked
	}
	lockPath := filepath.Join(filepath.Dir(resolved), LockFileName)
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		_ = unlockFile(identityFile)
		_ = identityFile.Close()
		releaseRegistry()
		return nil, fmt.Errorf("%w: 无法创建恢复锁文件", ErrStoreUnavailable)
	}
	if err := lockFileExclusive(file); err != nil {
		_ = file.Close()
		_ = unlockFile(identityFile)
		_ = identityFile.Close()
		releaseRegistry()
		return nil, ErrLocked
	}
	lock := &fileLock{path: lockPath, identityID: identityID, file: file, identity: identityFile}
	_ = file.Truncate(0)
	metadata := fmt.Sprintf("pid=%d operator=%s time=%s\n", os.Getpid(),
		operator.ID, now.UTC().Format(time.RFC3339))
	_, _ = file.WriteAt([]byte(metadata), 0)
	_ = file.Sync()
	return lock, nil
}

// identityLockPath 返回按数据库文件身份区分的互斥锁文件路径。
func identityLockPath(identityID string) string {
	sum := sha256.Sum256([]byte(identityID))
	name := hex.EncodeToString(sum[:16]) + ".lock"
	return filepath.Join(os.TempDir(), lockDirName, name)
}

// Release 释放锁并关闭文件；重复调用安全。锁文件保留在目录中（内容为最后一次
// 操作元数据），避免删除-重建的跨进程竞态。
func (l *fileLock) Release() {
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
	_ = l.file.Close()
	_ = unlockFile(l.identity)
	_ = l.identity.Close()
	heldLocks.Delete(l.identityID)
}

var errLockAdapter = errors.New("文件锁实现不可用")
