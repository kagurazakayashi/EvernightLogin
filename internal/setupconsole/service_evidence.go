package setupconsole

// WS4 维护证据包装的可复用导出入口（供本地 CUI 与 WS5 非交互命令共用）。
//
// 背景：WS4 画面里的破坏性动作统一经 ws4Maint.runDestructive 取得 281 排他维护锁、
// 写维护日志（started/success/failed）；WS5 的非交互 `import config` / `recover apply`
// 等命令必须复用同一语义，避免出现“CUI 有证据、CLI 无证据”的双标准。
//
// 使用约束（与 AGENTS §14 一致）：
//   - 仅允许本地受控入口（cmd/login-setup）调用；不得把 MaintenanceIdentity /
//     本 helper 暴露给 Web/HTTP/普通 Go 门面或可序列化令牌；
//   - instanceDir 必须是实例目录绝对路径；维护日志不可写时直接 deny（不静默降级）；
//   - 执行期间持有排他维护锁：另一个控制台占用或主服务仍在运行都会 deny，不杀进程；
//   - action 使用稳定 ASCII 动作名，target 是脱敏摘要（不得包含口令/证明/路径秘密）。

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/config"
)

// MaintenanceEvidenceResult 是一次受维护证据保护的写操作结果。
//
// Result 是业务 fn 返回的结果文本（CLI 可直接写入 JSON 的 result 字段）；
// Receipt 是维护日志返回的收据（可为空）；OperationID 是本次维护操作编号，
// 用于把 CUI/CLI 输出与维护日志关联。
type MaintenanceEvidenceResult struct {
	Result      string `json:"result"`
	Receipt     string `json:"receipt,omitempty"`
	OperationID string `json:"operation_id,omitempty"`
}

// WithMaintenanceEvidence 在维护排他锁 + 维护日志证据下执行一次写操作，返回业务结果。
//
// 语义与 WS4 画面的 runDestructive 一致：
//  1. 记录 started（日志不可写立即返回错误，不执行 fn）；
//  2. 取得实例维护排他锁（另一个控制台占用或主服务运行中返回错误，不杀进程）；
//  3. 执行 fn；失败记录 failed（含错误码）并返回错误；
//  4. 成功记录 success；返回 fn 的业务结果。
//
// 供 CUI 与非交互命令共用；fn 内不得再自行重复取同一把维护锁（会自锁失败）。
// 需要操作收据/操作编号时使用 RunWithMaintenanceEvidence。
func WithMaintenanceEvidence(ctx context.Context, instanceDir, action, target string,
	fn func(context.Context) (string, error)) (string, error) {
	result, err := RunWithMaintenanceEvidence(ctx, instanceDir, action, target, fn)
	return result.Result, err
}

// RunWithMaintenanceEvidence 是 WithMaintenanceEvidence 的完整版本，额外返回维护
// 收据与操作编号，便于 CLI JSON 输出与审计关联。
func RunWithMaintenanceEvidence(ctx context.Context, instanceDir, action, target string,
	fn func(context.Context) (string, error)) (MaintenanceEvidenceResult, error) {
	if fn == nil {
		return MaintenanceEvidenceResult{}, fmt.Errorf("维护证据包装缺少执行函数")
	}
	trimmedAction := strings.TrimSpace(action)
	if trimmedAction == "" {
		return MaintenanceEvidenceResult{}, fmt.Errorf("维护证据包装缺少动作名")
	}
	maint, err := openWS4Maint(instanceDir)
	if err != nil {
		return MaintenanceEvidenceResult{}, err
	}
	cleanTarget := ws4MaintTarget(target)
	if err := maint.record(ctx, trimmedAction, cleanTarget, "started", ""); err != nil {
		return MaintenanceEvidenceResult{}, fmt.Errorf("写入维护日志失败，已阻止操作：%w", err)
	}
	databasePath := ws4InstanceDatabasePath(instanceDir)
	lock, lockErr := AcquireMaintenanceLock(ctx, LockRequest{
		InstanceDir:  maint.instanceDir,
		DatabasePath: databasePath,
		Purpose:      trimmedAction,
		Operator:     maint.identity,
	})
	if lockErr != nil {
		_ = maint.record(ctx, trimmedAction, cleanTarget, "failed", "E_LOCK")
		return MaintenanceEvidenceResult{OperationID: maint.operationID}, lockErr
	}
	defer func() { _ = lock.Release() }()
	resultText, runErr := fn(ctx)
	if runErr != nil {
		_ = maint.record(ctx, trimmedAction, cleanTarget, "failed", "E_ACTION")
		return MaintenanceEvidenceResult{Result: resultText,
			OperationID: maint.operationID}, runErr
	}
	receipt, recordErr := maint.recordWithReceipt(ctx, trimmedAction, cleanTarget, "success", "")
	if recordErr != nil {
		return MaintenanceEvidenceResult{Result: resultText,
				OperationID: maint.operationID},
			fmt.Errorf("操作已执行但维护日志记录失败：%w", recordErr)
	}
	return MaintenanceEvidenceResult{Result: resultText, Receipt: receipt,
		OperationID: maint.operationID}, nil
}

// recordWithReceipt 记录维护证据并返回日志收据（MaintLog.Record 的 receipt）。
func (m *ws4Maint) recordWithReceipt(ctx context.Context, action, target, result,
	errorCode string) (string, error) {
	if m == nil || m.log == nil {
		return "", fmt.Errorf("维护证据上下文未初始化")
	}
	finished := timeNowUTC()
	return m.log.Record(ctx, MaintLogEntry{
		OperationID: m.operationID, Identity: m.identity, InstanceDir: m.instanceDir,
		Action: strings.TrimSpace(action), Target: ws4MaintTarget(target),
		Result: result, ErrorCode: strings.TrimSpace(errorCode),
		StartedAt: m.startedAt, FinishedAt: finished,
	})
}

// ws4InstanceDatabasePath 尽力从实例目录解析数据库绝对路径（用于维护锁的服务占用
// 检查）；解析失败返回空字符串（只加控制台互斥锁），不猜测、不修改任何文件。
func ws4InstanceDatabasePath(instanceDir string) string {
	trimmed := strings.TrimSpace(instanceDir)
	if trimmed == "" || !filepath.IsAbs(trimmed) {
		return ""
	}
	cleanDir := filepath.Clean(trimmed)
	configPath := filepath.Join(cleanDir, "login.yaml")
	if _, err := os.Lstat(configPath); err == nil {
		if cfg, loadErr := config.Load(config.LoadOptions{YAMLFile: configPath}); loadErr == nil {
			databasePath := strings.TrimSpace(cfg.Database.Path)
			if databasePath != "" {
				if !filepath.IsAbs(databasePath) {
					databasePath = filepath.Join(cleanDir, databasePath)
				}
				databasePath = filepath.Clean(databasePath)
				// 数据库目录尚不存在（配置已写、库未初始化）时只持实例互斥锁，
				// 避免把合法的配置导入/恢复误判为主服务占用而拒绝。
				if info, statErr := os.Stat(filepath.Dir(databasePath)); statErr != nil || !info.IsDir() {
					return ""
				}
				return databasePath
			}
		}
	}
	// 无配置时尝试实例目录下常见的受控数据库位置（只检查存在性，不打开数据库）。
	for _, candidate := range []string{
		filepath.Join(cleanDir, "data", "login.db"),
		filepath.Join(cleanDir, "login.db"),
	} {
		if info, err := os.Lstat(candidate); err == nil && info.Mode().IsRegular() {
			return candidate
		}
	}
	return ""
}

// ws4EvidenceJSON 把维护证据结果编码为单行 JSON（供非交互命令输出；不含秘密）。
func ws4EvidenceJSON(result MaintenanceEvidenceResult) string {
	encoded, err := json.Marshal(result)
	if err != nil {
		return `{"result":""}`
	}
	return string(encoded)
}

// timeNowUTC 隔离时钟依赖，便于后续测试替换（默认 time.Now().UTC()）。
var timeNowUTC = func() time.Time { return time.Now().UTC() }
