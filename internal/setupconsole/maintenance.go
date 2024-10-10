package setupconsole

// 本地维护身份、排他维护锁与无数据库审计（步骤281）。
//
// 信任边界（AGENTS §14）：
//   - 维护身份只由本地控制台从操作系统事实推导（当前 OS 用户/机器名/实例目录稳定 ID），
//     不来自应用账户、请求参数、环境变量 JSON 或可序列化令牌；
//   - 排他锁 = 实例目录 `.login-setup.lock`（OS 文件锁，两个控制台互斥）+ 数据库同名
//     单实例锁 `<db>.server.lock` 必须可获取（证明主服务未运行）；不靠 PID 文件或
//     回环地址判断安全，也不终止任何进程；
//   - 锁在进程退出/崩溃时由操作系统释放；释放幂等；
//   - 本包只被 cmd/login-setup 本地入口引用，不向 Web/HTTP/普通 Go 门面暴露 local=true
//     通道。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"unicode"

	"github.com/kagurazakayashi/EvernightLogin/internal/maintenance"
)

// 维护锁/身份哨兵错误。
var (
	// ErrMaintenanceLocked 表示另一个本地控制台已持有实例维护锁。
	ErrMaintenanceLocked = errors.New("实例维护锁已被其他控制台占用")
	// ErrServiceRunning 表示主服务正在运行（数据库单实例锁被占用）。
	ErrServiceRunning = errors.New("实例主服务正在运行，不能执行独占维护操作")
	// ErrIdentityInvalid 表示维护身份不是本机可信推导结果。
	ErrIdentityInvalid = errors.New("本地维护身份无效")
	// ErrInstanceMismatch 表示身份/锁与目标实例不一致。
	ErrInstanceMismatch = errors.New("维护身份与目标实例不一致")
)

// serverInstanceLockSuffix 必须与主服务单实例锁后缀一致（测试交叉锁定）。
// 使用共享协议的稳定文件名，而不是 PID/回环判断。
const serverInstanceLockSuffix = ".server.lock"

// setupLockFileName 是控制台之间的排他维护锁文件名。
const setupLockFileName = ".login-setup.lock"

// MaintenanceIdentity 是本地维护操作者身份（仅本地入口装配）。
type MaintenanceIdentity struct {
	// Kind 固定为 local_os：维护权限来自操作系统对实例文件/数据的访问授权。
	Kind string
	// OSUser 是当前操作系统用户标识（不含口令）。
	OSUser string
	// Machine 是机器名标识。
	Machine string
	// InstanceID 是实例目录的稳定指纹（不含路径明文）。
	InstanceID string
}

// LocalMaintenanceIdentity 从操作系统事实推导维护身份；instanceDir 必须存在。
func LocalMaintenanceIdentity(instanceDir string) (MaintenanceIdentity, error) {
	absoluteDir, err := resolveInstanceDir(instanceDir)
	if err != nil {
		return MaintenanceIdentity{}, err
	}
	username := ""
	if current, userErr := user.Current(); userErr == nil {
		username = strings.TrimSpace(current.Username)
	}
	if username == "" {
		username = strings.TrimSpace(os.Getenv("USERNAME"))
	}
	if username == "" {
		username = strings.TrimSpace(os.Getenv("USER"))
	}
	if username == "" {
		return MaintenanceIdentity{}, fmt.Errorf("%w: 无法取得当前操作系统用户", ErrIdentityInvalid)
	}
	machine, hostErr := os.Hostname()
	if hostErr != nil || strings.TrimSpace(machine) == "" {
		machine = "unknown-host"
	}
	return MaintenanceIdentity{Kind: "local_os", OSUser: username,
		Machine: strings.TrimSpace(machine), InstanceID: instanceFingerprint(absoluteDir)}, nil
}

// Validate 校验身份来自当前 OS 且属于目标实例；伪造身份/错误实例 fail-closed。
func (i MaintenanceIdentity) Validate(instanceDir string) error {
	if i.Kind != "local_os" {
		return fmt.Errorf("%w: 身份类别不是 local_os", ErrIdentityInvalid)
	}
	absoluteDir, err := resolveInstanceDir(instanceDir)
	if err != nil {
		return err
	}
	expectedFingerprint := instanceFingerprint(absoluteDir)
	if i.InstanceID == "" || i.InstanceID != expectedFingerprint {
		return fmt.Errorf("%w: 实例指纹不匹配", ErrInstanceMismatch)
	}
	current, err := LocalMaintenanceIdentity(absoluteDir)
	if err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSpace(i.OSUser), current.OSUser) {
		return fmt.Errorf("%w: OS 用户与当前进程不一致", ErrIdentityInvalid)
	}
	if i.Machine != "" && current.Machine != "" &&
		!strings.EqualFold(strings.TrimSpace(i.Machine), current.Machine) {
		return fmt.Errorf("%w: 机器名与当前进程不一致", ErrIdentityInvalid)
	}
	return nil
}

// LockRequest 是取得维护锁的请求。
type LockRequest struct {
	// InstanceDir 是实例目录（配置/数据/日志所在目录）。
	InstanceDir string
	// DatabasePath 是配置中的数据库路径；为空时只加强控制台互斥锁（无数据库状态）。
	DatabasePath string
	// Purpose 是简短维护目的（进入维护日志，不接受秘密）。
	Purpose string
	// Operator 必须是由 LocalMaintenanceIdentity 推导的身份。
	Operator MaintenanceIdentity
}

// MaintenanceLock 是已持有的排他维护锁。
type MaintenanceLock struct {
	mu             sync.Mutex
	setupRelease   func()
	serviceRelease func()
	setupPath      string
	servicePath    string
	operator       MaintenanceIdentity
	instanceDir    string
	released       bool
}

// AcquireMaintenanceLock 取得控制台互斥锁（并在有数据库路径时验证主服务未运行）。
func AcquireMaintenanceLock(ctx context.Context, request LockRequest) (*MaintenanceLock, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	absoluteDir, err := resolveInstanceDir(request.InstanceDir)
	if err != nil {
		return nil, err
	}
	if err := request.Operator.Validate(absoluteDir); err != nil {
		return nil, err
	}
	if strings.TrimSpace(request.Purpose) == "" {
		return nil, fmt.Errorf("%w: 维护目的不能为空", ErrIdentityInvalid)
	}
	lock := &MaintenanceLock{operator: request.Operator, instanceDir: absoluteDir}
	lock.setupPath = filepath.Join(absoluteDir, setupLockFileName)
	releaseSetup, setupErr := maintenance.AcquireFileLock(lock.setupPath)
	if setupErr != nil {
		if errors.Is(setupErr, maintenance.ErrLockBusy) {
			return nil, fmt.Errorf("%w（%s）", ErrMaintenanceLocked, lock.setupPath)
		}
		return nil, fmt.Errorf("取得实例维护锁失败: %w", setupErr)
	}
	lock.setupRelease = releaseSetup
	databasePath := strings.TrimSpace(request.DatabasePath)
	if databasePath == "" {
		return lock, nil
	}
	absoluteDatabase, absErr := filepath.Abs(databasePath)
	if absErr != nil {
		_ = lock.Release()
		return nil, fmt.Errorf("数据库路径无效: %w", absErr)
	}
	lock.servicePath = absoluteDatabase + serverInstanceLockSuffix
	releaseService, serviceErr := maintenance.AcquireFileLock(lock.servicePath)
	if serviceErr != nil {
		_ = lock.Release()
		if errors.Is(serviceErr, maintenance.ErrLockBusy) {
			return nil, fmt.Errorf("%w（%s）", ErrServiceRunning, lock.servicePath)
		}
		return nil, fmt.Errorf("验证主服务运行状态失败: %w", serviceErr)
	}
	lock.serviceRelease = releaseService
	return lock, nil
}

// Release 释放维护锁；幂等且不删除锁文件（避免删除-重建竞态）。
func (l *MaintenanceLock) Release() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.released {
		return nil
	}
	l.released = true
	if l.serviceRelease != nil {
		l.serviceRelease()
		l.serviceRelease = nil
	}
	if l.setupRelease != nil {
		l.setupRelease()
		l.setupRelease = nil
	}
	return nil
}

// Path 返回控制台互斥锁路径（排障用）。
func (l *MaintenanceLock) Path() string {
	if l == nil {
		return ""
	}
	return l.setupPath
}

// Operator 返回锁持有的维护身份。
func (l *MaintenanceLock) Operator() MaintenanceIdentity {
	if l == nil {
		return MaintenanceIdentity{}
	}
	return l.operator
}

// resolveInstanceDir 解析实例目录绝对路径与真实路径（符号链接归一到同一实例）。
func resolveInstanceDir(instanceDir string) (string, error) {
	trimmed := strings.TrimSpace(instanceDir)
	if trimmed == "" {
		return "", fmt.Errorf("%w: 实例目录为空", ErrInstanceMismatch)
	}
	absolute, err := filepath.Abs(trimmed)
	if err != nil {
		return "", fmt.Errorf("实例目录路径无效: %w", err)
	}
	info, statErr := os.Stat(absolute)
	if statErr != nil || !info.IsDir() {
		return "", fmt.Errorf("%w: 实例目录不存在或不是目录", ErrInstanceMismatch)
	}
	if resolved, resolveErr := filepath.EvalSymlinks(absolute); resolveErr == nil {
		absolute = resolved
	}
	return absolute, nil
}

// instanceFingerprint 计算实例目录的稳定指纹（规范化小写路径 + 可选环境标识的摘要）。
func instanceFingerprint(absoluteDir string) string {
	normalized := strings.ToLower(filepath.ToSlash(filepath.Clean(absoluteDir)))
	sum := sha256.Sum256([]byte("setupconsole.instance.v1|" + normalized))
	return "inst_" + hex.EncodeToString(sum[:8])
}

// validateMaintenanceText 拒绝控制字符/过长文本（用于维护日志与锁目的）。
func validateMaintenanceText(value string, maxRunes int, label string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fmt.Errorf("%w: %s不能为空", ErrIdentityInvalid, label)
	}
	runes := []rune(trimmed)
	if len(runes) > maxRunes {
		return fmt.Errorf("%w: %s过长", ErrIdentityInvalid, label)
	}
	if strings.ContainsFunc(trimmed, unicode.IsControl) {
		return fmt.Errorf("%w: %s包含控制字符", ErrIdentityInvalid, label)
	}
	return nil
}
