package setupconsole

// WS4 维护证据与写门控（292–296 收尾）。
//
// 安全审计要求：WS4 的写操作/危险操作必须
//   - 接入 281 的维护日志（MaintLog.Record：operator/实例/action/target/result），
//     日志不可写时阻止关键修改；
//   - 真正写配置/清理实例前取得维护排他锁（主服务运行中直接拒绝，不杀进程）；
//   - 危险操作（重初始化/恢复/导入）留下独立维护证据，且不删除/覆盖自身日志
//     （维护日志与重初始化执行日志都在清除清单之外）。
//
// 本文件只提供证据包装，不实现具体业务；业务仍由 283/292/294/295 的真实实现执行。

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// ws4Maint 是一次 WS4 写操作/危险操作的维护证据上下文。
type ws4Maint struct {
	log         MaintLog
	identity    MaintenanceIdentity
	instanceDir string
	operationID string
	startedAt   time.Time
}

// openWS4Maint 打开实例维护日志并准备证据记录。
//
// 维护日志不可写时返回错误；调用方必须阻止关键修改（只读诊断仍可继续）。
func openWS4Maint(instanceDir string) (*ws4Maint, error) {
	trimmed := strings.TrimSpace(instanceDir)
	if trimmed == "" || !filepath.IsAbs(trimmed) {
		return nil, errors.New("维护证据缺少实例目录绝对路径")
	}
	identity, err := LocalMaintenanceIdentity(trimmed)
	if err != nil {
		return nil, fmt.Errorf("本地维护身份无效：%w", err)
	}
	log, err := OpenMaintenanceLog(trimmed)
	if err != nil {
		return nil, fmt.Errorf("维护日志不可写，已阻止关键修改：%w", err)
	}
	operationID, err := ws4OperationID()
	if err != nil {
		return nil, err
	}
	return &ws4Maint{log: log, identity: identity, instanceDir: filepath.Clean(trimmed),
		operationID: operationID, startedAt: time.Now().UTC()}, nil
}

// record 记录一步维护证据；target 必须是脱敏摘要（不得含秘密/完整口令）。
func (m *ws4Maint) record(ctx context.Context, action, target, result, errorCode string) error {
	if m == nil || m.log == nil {
		return errors.New("维护证据上下文未初始化")
	}
	finished := time.Now().UTC()
	_, err := m.log.Record(ctx, MaintLogEntry{
		OperationID: m.operationID, Identity: m.identity, InstanceDir: m.instanceDir,
		Action: strings.TrimSpace(action), Target: ws4MaintTarget(target),
		Result: result, ErrorCode: strings.TrimSpace(errorCode),
		StartedAt: m.startedAt, FinishedAt: finished,
	})
	return err
}

// runDestructive 在维护排他锁 + 维护日志证据下执行一次写操作。
//
// 顺序：记录 started → 取得维护锁（主服务运行中拒绝）→ 执行 fn → 记录
// success/failed → 释放锁。fn 返回的 target 摘要会用于成功记录。
func (m *ws4Maint) runDestructive(ctx context.Context, databasePath, action string,
	fn func() (string, error)) (string, error) {
	if m == nil || m.log == nil {
		return "", errors.New("维护证据上下文未初始化")
	}
	if err := m.record(ctx, action, action, "started", ""); err != nil {
		return "", fmt.Errorf("写入维护日志失败，已阻止操作：%w", err)
	}
	lock, err := AcquireMaintenanceLock(ctx, LockRequest{
		InstanceDir: m.instanceDir, DatabasePath: strings.TrimSpace(databasePath),
		Purpose: strings.TrimSpace(action), Operator: m.identity,
	})
	if err != nil {
		_ = m.record(ctx, action, action, "failed", "E_LOCK")
		return "", err
	}
	defer func() { _ = lock.Release() }()
	target, actionErr := fn()
	if actionErr != nil {
		_ = m.record(ctx, action, target, "failed", "E_ACTION")
		return target, actionErr
	}
	if err := m.record(ctx, action, target, "success", ""); err != nil {
		// 操作已完成但证据写入失败：返回错误让调用方显示“结果已执行但证据不完整”，
		// 不回头撤销已完成的数据变更。
		return target, fmt.Errorf("操作已执行但维护日志记录失败：%w", err)
	}
	return target, nil
}

// runWithEvidence 只记录维护证据、不额外取锁（用于已由 WS3 WriteGuard 逐事务
// 取锁的领域写操作，例如预设角色恢复）。
func (m *ws4Maint) runWithEvidence(ctx context.Context, action string,
	fn func() (string, error)) (string, error) {
	if m == nil || m.log == nil {
		return "", errors.New("维护证据上下文未初始化")
	}
	if err := m.record(ctx, action, action, "started", ""); err != nil {
		return "", fmt.Errorf("写入维护日志失败，已阻止操作：%w", err)
	}
	target, err := fn()
	if err != nil {
		_ = m.record(ctx, action, target, "failed", "E_ACTION")
		return target, err
	}
	if recordErr := m.record(ctx, action, target, "success", ""); recordErr != nil {
		return target, fmt.Errorf("操作已执行但维护日志记录失败：%w", recordErr)
	}
	return target, nil
}

// ws4InstanceDirForConfig 返回配置文件所在实例目录。
func ws4InstanceDirForConfig(configPath string) (string, error) {
	trimmed := strings.TrimSpace(configPath)
	if trimmed == "" {
		return "", errors.New("未选择配置文件")
	}
	if !filepath.IsAbs(trimmed) {
		return "", fmt.Errorf("配置文件必须是绝对路径：%s", trimmed)
	}
	return filepath.Dir(filepath.Clean(trimmed)), nil
}

// ws4MaintTarget 把目标摘要限制为短 ASCII 文本，不写路径/秘密。
func ws4MaintTarget(target string) string {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return "unknown"
	}
	var builder strings.Builder
	for _, character := range trimmed {
		if character >= 0x20 && character <= 0x7e {
			builder.WriteRune(character)
		} else {
			builder.WriteRune('_')
		}
	}
	cleaned := strings.Trim(builder.String(), "_")
	if cleaned == "" {
		cleaned = "unknown"
	}
	if len(cleaned) > 120 {
		cleaned = cleaned[:120]
	}
	return cleaned
}

// ws4OperationID 生成维护证据操作编号（不含秘密）。
func ws4OperationID() (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("生成维护操作编号失败：%w", err)
	}
	return "op_" + hex.EncodeToString(random), nil
}
