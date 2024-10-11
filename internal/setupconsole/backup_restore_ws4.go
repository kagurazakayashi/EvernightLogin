package setupconsole

// 步骤 292 的受控导出输出路径校验与受控恢复执行接线（WS4）。
//
// 导出：沿用 backup.ExtractEntry（一次性解包+摘要校验+操作记录），输出路径必须
// 位于实例目录内、父目录存在且非符号链接、目标文件不存在（拒绝路径逃逸/覆盖）。
//
// 恢复：复用公开 app.Runtime 的 BackupRecoveryService（与页面/CLI 同一实现）：
//   Configure(库外状态目录/回退备份目录) → LoadBackup(按备份 ID 解析受控产物，
//   不把宿主路径暴露给画面) → Rehearse(只读预演) → Execute(维护锁+维护状态+恢复
//   代际+旧凭证失效+审计合并)。失败默认保持维护状态，不自动对外放行。

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/app"
)

// ws4ExportTarget 校验导出目标：实例目录内、父目录已存在且不是符号链接、目标
// 不存在；任一条不满足都拒绝，避免路径逃逸或覆盖非本次操作文件。
func ws4ExportTarget(instanceDir, outputPath string) (string, error) {
	trimmed := strings.TrimSpace(outputPath)
	if trimmed == "" {
		return "", errors.New("未指定导出目标路径")
	}
	if !filepath.IsAbs(trimmed) {
		return "", fmt.Errorf("导出目标必须是绝对路径：%s", trimmed)
	}
	cleanTarget := filepath.Clean(trimmed)
	instanceAbs, err := filepath.Abs(instanceDir)
	if err != nil {
		return "", fmt.Errorf("实例目录无效：%w", err)
	}
	instanceAbs = filepath.Clean(instanceAbs)
	if !samePathOrInside(cleanTarget, instanceAbs) {
		return "", errors.New("导出目标必须位于实例目录内（拒绝路径逃逸）")
	}
	parent := filepath.Dir(cleanTarget)
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return "", fmt.Errorf("导出目标父目录不可用：%w", err)
	}
	if parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() {
		return "", errors.New("导出目标父目录必须是真实目录（不能是符号链接）")
	}
	if _, statErr := os.Lstat(cleanTarget); statErr == nil {
		return "", errors.New("导出目标已存在：拒绝覆盖非本次导出文件")
	} else if !os.IsNotExist(statErr) {
		return "", fmt.Errorf("检查导出目标失败：%w", statErr)
	}
	return cleanTarget, nil
}

// ws4RestoreRuntimeOptions 从检测结果推导 app.Runtime 装配参数。
type ws4RestoreRuntimeOptions struct {
	ConfigPath    string
	InstanceDir   string
	OperatorID    string
	MasterKeyFile string
}

// ws4OpenRestoreRuntime 打开真实运行时（不监听端口、不启动后台任务），供 292 使用。
func ws4OpenRestoreRuntime(ctx context.Context, configPath, databasePath string) (*app.Runtime, error) {
	trimmed := strings.TrimSpace(configPath)
	if trimmed == "" || !filepath.IsAbs(trimmed) {
		return nil, errors.New("恢复执行需要实例配置绝对路径")
	}
	instanceDir := filepath.Dir(filepath.Clean(trimmed))
	identity, err := LocalMaintenanceIdentity(instanceDir)
	if err != nil {
		return nil, err
	}
	options := app.Options{
		ConfigPath: trimmed, OperatorID: ws4OperatorID(identity),
	}
	for _, candidate := range []string{
		filepath.Join(instanceDir, "master.key"),
		filepath.Join(instanceDir, "secrets", "master.key"),
	} {
		if info, statErr := os.Lstat(candidate); statErr == nil && info.Mode().IsRegular() {
			options.MasterKeyFile = candidate
			break
		}
	}
	return app.Open(ctx, options)
}

// ws4RestoreDefaults 推导库外恢复状态目录与回退备份输出目录。
func ws4RestoreDefaults(databasePath string) (stateDir, backupOutputDir string) {
	clean := filepath.Clean(databasePath)
	dataDir := filepath.Dir(clean)
	stateDir = filepath.Join(filepath.Dir(dataDir), filepath.Base(dataDir)+"-maintenance")
	backupOutputDir = filepath.Join(dataDir, "backups")
	return stateDir, backupOutputDir
}

// runDestructiveRestore 在维护锁+维护证据下执行受控恢复，并返回真实结果。
func (m *ws4Maint) runDestructiveRestore(ctx context.Context, databasePath, action string,
	fn func() (app.BackupRestoreResult, error)) (app.BackupRestoreResult, error) {
	var result app.BackupRestoreResult
	if m == nil || m.log == nil {
		return result, errors.New("维护证据上下文未初始化")
	}
	if err := m.record(ctx, action, action, "started", ""); err != nil {
		return result, fmt.Errorf("写入维护日志失败，已阻止恢复：%w", err)
	}
	lock, err := AcquireMaintenanceLock(ctx, LockRequest{
		InstanceDir: m.instanceDir, DatabasePath: strings.TrimSpace(databasePath),
		Purpose: strings.TrimSpace(action), Operator: m.identity,
	})
	if err != nil {
		_ = m.record(ctx, action, action, "failed", "E_LOCK")
		return result, err
	}
	defer func() { _ = lock.Release() }()
	result, err = fn()
	if err != nil {
		_ = m.record(ctx, action, "backup", "failed", "E_RESTORE")
		return result, err
	}
	if recordErr := m.record(ctx, action, "backup", "success", ""); recordErr != nil {
		return result, fmt.Errorf("恢复已执行但维护日志记录失败：%w", recordErr)
	}
	return result, nil
}

// ExecuteControlledRestore 受控恢复执行：预演通过后用 app.Runtime 的真实恢复服务执行。
//
// confirm 必须是 "RESTORE"（与公开恢复契约一致）；返回脱敏结果摘要。失败时由
// 恢复服务保持维护状态（调用方可展示处置提示），本函数不回滚已完成状态。
func ExecuteControlledRestore(ctx context.Context, configPath, databasePath string,
	backupID, reason, confirm string) (app.BackupRestoreResult, error) {
	if strings.TrimSpace(confirm) != "RESTORE" {
		return app.BackupRestoreResult{}, errors.New("必须显式确认 RESTORE 才能执行恢复")
	}
	if strings.TrimSpace(reason) == "" {
		return app.BackupRestoreResult{}, errors.New("恢复原因必填")
	}
	if strings.TrimSpace(backupID) == "" {
		return app.BackupRestoreResult{}, errors.New("缺少备份编号")
	}
	runtime, err := ws4OpenRestoreRuntime(ctx, configPath, databasePath)
	if err != nil {
		return app.BackupRestoreResult{}, fmt.Errorf("打开实例运行时失败：%w", err)
	}
	defer func() { _ = runtime.Close(ctx) }()
	caller := runtime.LocalAdmin()
	recovery := runtime.Backup().Recovery()
	stateDir, backupOutputDir := ws4RestoreDefaults(databasePath)
	if err := recovery.Configure(ctx, app.BackupRecoveryConfigRequest{
		Caller: caller, StateDir: stateDir, BackupOutputDir: backupOutputDir,
	}); err != nil {
		return app.BackupRestoreResult{}, fmt.Errorf("配置受控恢复目录失败：%w", err)
	}
	source, err := recovery.LoadBackup(ctx, app.BackupRecoveryLoadRequest{
		Caller: caller, BackupID: backupID,
	})
	if err != nil {
		return app.BackupRestoreResult{}, fmt.Errorf("加载备份失败：%w", err)
	}
	_ = source
	rehearsal, err := recovery.Rehearse(ctx, app.BackupRecoveryRestoreRequest{
		Caller: caller, Reason: reason,
	})
	if err != nil {
		return app.BackupRestoreResult{}, fmt.Errorf("恢复预演失败：%w", err)
	}
	if !rehearsal.Restorable {
		blocking := strings.Join(rehearsal.BlockingReasons, "；")
		if blocking == "" {
			blocking = "预演判定不可恢复"
		}
		return app.BackupRestoreResult{}, fmt.Errorf("预演未通过：%s", blocking)
	}
	result, err := recovery.Execute(ctx, app.BackupRecoveryRestoreRequest{
		Caller: caller, Reason: reason, ConfirmToken: "RESTORE",
	})
	if err != nil {
		return app.BackupRestoreResult{}, fmt.Errorf("恢复执行失败：%w", err)
	}
	return result, nil
}
