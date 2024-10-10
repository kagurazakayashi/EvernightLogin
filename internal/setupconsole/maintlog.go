package setupconsole

// 无数据库受控本地维护日志（步骤281）。
//
// 数据库尚未创建/迁移时，关键维护动作仍需可追溯的本地证据：
//   - 日志位于实例目录 `.login-setup-maintenance.jsonl`，0600，行级 JSON + Sync；
//   - 记录 OS 操作者、实例指纹、操作 ID、动作、脱敏目标、请求/结果、错误码、时间；
//   - 不含秘密/口令/令牌/配置值；目标字段只保存经过清洗的稳定标识；
//   - 有界大小：超过上限返回 ErrLogFull（不静默截断/删除历史）；
//   - 不可写时返回错误：调用方必须阻止关键身份修改，允许只读诊断/草稿修复；
//   - 数据库就绪后由后续步骤以稳定 OperationID 关联导入（去重），本文件不做数据库写入。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Windows 语义：os.Chmod(0600) 不映射 NTFS ACL；OpenMaintenanceLog 会显式设置并自检\n// 受保护 DACL（当前用户+SYSTEM+Administrators），发现/无法校验宽泛写权限时 fail-closed。\n// 非 Windows：要求模式位 0600（仅所有者读写），否则拒绝打开。\n\n// 维护日志常量与错误。
const (
	maintenanceLogFileName = ".login-setup-maintenance.jsonl"
	// MaxMaintenanceLogBytes 是本地维护日志大小上限（超出要求显式处置，不自动删除）。
	MaxMaintenanceLogBytes = 8 << 20
	// MaxMaintenanceLogTargetRunes 是脱敏目标字段长度上限。
	MaxMaintenanceLogTargetRunes = 120
)

// ErrLogFull 表示本地维护日志达到有界上限。
var ErrLogFull = errors.New("本地维护日志达到大小上限")

// ErrLogUnavailable 表示维护日志不可写/不可读。
var ErrLogUnavailable = errors.New("本地维护日志不可用")

// MaintLogEntry 是一条维护日志记录。
type MaintLogEntry struct {
	OperationID string
	Identity    MaintenanceIdentity
	InstanceDir string
	Action      string
	Target      string
	Result      string
	ErrorCode   string
	StartedAt   time.Time
	FinishedAt  time.Time
	RequestID   string
}

// MaintLog 是维护日志契约（破坏性只读诊断可继续，关键修改必须先在 Record 成功）。
type MaintLog interface {
	// Record 追加一条维护日志并同步落盘，返回稳定回执（OperationID）。
	Record(ctx context.Context, entry MaintLogEntry) (string, error)
}

type maintenanceLog struct {
	mu   sync.Mutex
	path string
}

// OpenMaintenanceLog 打开（或创建）实例目录内的维护日志；实例目录必须存在。
func OpenMaintenanceLog(instanceDir string) (MaintLog, error) {
	absoluteDir, err := resolveInstanceDir(instanceDir)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(absoluteDir, maintenanceLogFileName)
	log := &maintenanceLog{path: path}
	// 预检可写性（不写入内容）：不可写时立即 fail-closed。
	file, openErr := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if openErr != nil {
		return nil, fmt.Errorf("%w: %v", ErrLogUnavailable, openErr)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLogUnavailable, err)
	}
	// SEC LOW-1：启动时加固并自检文件保护（Windows DACL / POSIX 模式位）。
	if protectErr := prepareMaintenanceLogFile(path); protectErr != nil {
		return nil, protectErr
	}
	return log, nil
}

// Path 返回维护日志文件路径（排障用）。
func (l *maintenanceLog) Path() string {
	if l == nil {
		return ""
	}
	return l.path
}

// Record 校验并追加一条维护日志（行级 fsync）。
func (l *maintenanceLog) Record(ctx context.Context, entry MaintLogEntry) (string, error) {
	if l == nil {
		return "", ErrLogUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := validateLogEntry(entry, l.path); err != nil {
		return "", err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	info, statErr := os.Stat(l.path)
	if statErr != nil {
		return "", fmt.Errorf("%w: %v", ErrLogUnavailable, statErr)
	}
	if info.Size() >= MaxMaintenanceLogBytes {
		return "", fmt.Errorf("%w：请归档/处置后继续（不会自动删除历史）", ErrLogFull)
	}
	payload := map[string]any{
		"version":       1,
		"operation_id":  entry.OperationID,
		"identity_kind": entry.Identity.Kind,
		"os_user":       entry.Identity.OSUser,
		"machine":       entry.Identity.Machine,
		"instance_id":   entry.Identity.InstanceID,
		"action":        entry.Action,
		"target":        entry.Target,
		"result":        entry.Result,
		"error_code":    entry.ErrorCode,
		"request_id":    entry.RequestID,
	}
	if !entry.StartedAt.IsZero() {
		payload["started_at"] = entry.StartedAt.UTC().Format(time.RFC3339Nano)
	}
	if !entry.FinishedAt.IsZero() {
		payload["finished_at"] = entry.FinishedAt.UTC().Format(time.RFC3339Nano)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrLogUnavailable, err)
	}
	file, openErr := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if openErr != nil {
		return "", fmt.Errorf("%w: %v", ErrLogUnavailable, openErr)
	}
	defer func() { _ = file.Close() }()
	if _, writeErr := file.Write(append(encoded, '\n')); writeErr != nil {
		return "", fmt.Errorf("%w: %v", ErrLogUnavailable, writeErr)
	}
	if syncErr := file.Sync(); syncErr != nil {
		return "", fmt.Errorf("%w: %v", ErrLogUnavailable, syncErr)
	}
	return entry.OperationID, nil
}

// validateLogEntry 校验字段格式与禁止内容（不接受秘密/控制字符）。
func validateLogEntry(entry MaintLogEntry, logPath string) error {
	if err := validateMaintenanceText(entry.OperationID, 64, "操作 ID"); err != nil {
		return err
	}
	if !strings.HasPrefix(entry.OperationID, "op_") {
		return fmt.Errorf("%w: 操作 ID 必须以 op_ 开头", ErrIdentityInvalid)
	}
	if err := validateMaintenanceText(entry.Action, 96, "动作"); err != nil {
		return err
	}
	if err := validateMaintenanceText(entry.Target, MaxMaintenanceLogTargetRunes, "目标"); err != nil {
		return err
	}
	switch entry.Result {
	case "started", "success", "failed", "cancelled":
	default:
		return fmt.Errorf("%w: 结果必须是 started/success/failed/cancelled", ErrIdentityInvalid)
	}
	if entry.Identity.Kind != "local_os" || entry.Identity.OSUser == "" ||
		entry.Identity.InstanceID == "" {
		return fmt.Errorf("%w: 维护身份不完整", ErrIdentityInvalid)
	}
	// 实例目录必须与日志所属实例一致（通过打开时的目录指纹校验）。
	if instanceDir := filepath.Dir(logPath); entry.InstanceDir != "" {
		expected := instanceFingerprint(instanceDir)
		if entry.Identity.InstanceID != expected {
			return fmt.Errorf("%w: 身份实例指纹与日志目录不一致", ErrInstanceMismatch)
		}
	}
	if entry.ErrorCode != "" {
		if err := validateMaintenanceText(entry.ErrorCode, 64, "错误码"); err != nil {
			return err
		}
	}
	// 秘密关键词作为防御性拒绝（维护日志只允许稳定标识，不接收配置值）。
	lowerTarget := strings.ToLower(entry.Target)
	for _, forbidden := range []string{"password", "secret", "token=", "authorization:"} {
		if strings.Contains(lowerTarget, forbidden) {
			return fmt.Errorf("%w: 目标字段疑似包含秘密", ErrIdentityInvalid)
		}
	}
	return nil
}
