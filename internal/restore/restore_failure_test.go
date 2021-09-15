package restore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

// seededBackupEnv 构造“已种子 + 已备份 + 已释放数据库句柄”的环境，返回环境与备份。
func seededBackupEnv(t *testing.T) (*testEnv, backupResultForTest) {
	t.Helper()
	env := newTestEnv(t)
	store := env.openStore(t, true)
	env.mustMigrate(t, store)
	env.seedDatabase(t, store)
	return env, backupResultForTest{env: env, store: store}
}

// backupResultForTest 只是持有句柄，便于测试按需关闭。
type backupResultForTest struct {
	env   *testEnv
	store *storagesqlite.Store
}

// close 关闭数据库句柄。
func (b backupResultForTest) close(t *testing.T) { closeStore(t, b.store) }

// TestRehearseStructuredChecksAndCapacity 校验预演输出结构化结果：逐项检查、
// 影响范围、代际与容量检查；容量不足时 fail-closed 且不产生副作用。
func TestRehearseStructuredChecksAndCapacity(t *testing.T) {
	env, holder := seededBackupEnv(t)
	backupResult := env.createBackup(t)
	holder.close(t)
	service := env.newRestoreService(t, nil)
	ctx := context.Background()
	rehearsal, err := service.Rehearse(ctx, Request{Caller: env.caller(t),
		BackupPath: backupResult.Path, Reason: "恢复预演"})
	assertNoError(t, err, "预演失败")
	if !rehearsal.Restorable {
		t.Fatalf("正常备份预演应可恢复，阻塞原因：%v", rehearsal.BlockingReasons)
	}
	if len(rehearsal.Checks) < 8 {
		t.Fatalf("预演检查项 = %d，期望至少 8 项", len(rehearsal.Checks))
	}
	for _, check := range rehearsal.Checks {
		if check.Status != CheckOK {
			t.Fatalf("预演检查 %s 状态 = %s（%s）", check.Name, check.Status, check.Detail)
		}
	}
	if rehearsal.Impact.Sessions != 1 || rehearsal.Impact.RefreshFamilies != 1 ||
		rehearsal.Impact.AuthorizationCodes != 1 || rehearsal.Impact.RecoveryCodes != 1 ||
		rehearsal.Impact.VerificationTickets != 1 || rehearsal.Impact.QRLoginRequests != 1 {
		t.Fatalf("预演影响范围不符合期望：%+v", rehearsal.Impact)
	}
	if rehearsal.Impact.EnabledSchedules != 1 || rehearsal.Impact.ActiveWebhooks != 1 {
		t.Fatalf("预演调度/Webhook 影响不符合期望：%+v", rehearsal.Impact)
	}
	if len(rehearsal.Consequences) == 0 {
		t.Fatal("预演应给出影响范围说明")
	}
	if rehearsal.ExternalGeneration != 0 || rehearsal.DatabaseGeneration != 0 {
		t.Fatalf("预演代际 = %d/%d，期望 0/0",
			rehearsal.ExternalGeneration, rehearsal.DatabaseGeneration)
	}
	if rehearsal.RequiredStateBytes <= 0 || rehearsal.RequiredDatabaseBytes <= 0 ||
		rehearsal.RequiredBackupBytes <= 0 {
		t.Fatalf("预演容量需求未给出：%+v", rehearsal)
	}
	if service.State().Mode != "normal" {
		t.Fatal("预演不得进入维护状态")
	}

	// 容量不足：注入极小可用空间，预演必须 fail-closed 且给出 storage_capacity 失败。
	tight := env.newRestoreService(t, func(options *Options) {
		options.FreeBytes = func(string) (uint64, error) { return 1024, nil }
	})
	tightRehearsal, err := tight.Rehearse(ctx, Request{Caller: env.caller(t),
		BackupPath: backupResult.Path, Reason: "容量不足预演"})
	assertNoError(t, err, "容量不足预演不应返回内部错误")
	if tightRehearsal.Restorable {
		t.Fatal("容量不足时预演必须标记不可恢复")
	}
	foundCapacityFailure := false
	for _, check := range tightRehearsal.Checks {
		if check.Name == "storage_capacity" && check.Status == CheckFailed {
			foundCapacityFailure = true
		}
	}
	if !foundCapacityFailure {
		t.Fatal("容量不足应产生 storage_capacity 失败检查项")
	}
	// 容量探测失败同样 fail-closed。
	failing := env.newRestoreService(t, func(options *Options) {
		options.FreeBytes = func(string) (uint64, error) {
			return 0, errors.New("无法探测")
		}
	})
	failingRehearsal, err := failing.Rehearse(ctx, Request{Caller: env.caller(t),
		BackupPath: backupResult.Path, Reason: "容量探测失败"})
	assertNoError(t, err, "容量探测失败预演不应返回内部错误")
	if failingRehearsal.Restorable {
		t.Fatal("容量探测失败时必须 fail-closed")
	}
}

// TestRestoreRejectsWrongKey 校验错误密钥：预演/执行都在产生任何持久副作用前拒绝，
// 不进入维护状态、不创建回退备份、不修改数据库。
func TestRestoreRejectsWrongKey(t *testing.T) {
	env, holder := seededBackupEnv(t)
	backupResult := env.createBackup(t)
	holder.close(t)
	databaseHash := fileSHA256(t, env.dbPath)
	backupHashes := listDirHashes(t, env.backupDir)
	wrongRing, err := secrets.GenerateKeyring("k2", restoreTestClock)
	assertNoError(t, err, "生成错误密钥环失败")
	service := env.newRestoreService(t, func(options *Options) {
		options.Keyring = secrets.ProviderFunc(func(ctx context.Context) ([]byte, error) {
			return wrongRing.Document()
		})
	})
	ctx := context.Background()
	rehearsal, err := service.Rehearse(ctx, Request{Caller: env.caller(t),
		BackupPath: backupResult.Path, Reason: "错误密钥预演"})
	assertNoError(t, err, "错误密钥预演不应返回内部错误")
	if rehearsal.Restorable {
		t.Fatal("错误密钥时预演必须标记不可恢复")
	}
	if !hasFailedCheck(rehearsal, "keyring") {
		t.Fatalf("错误密钥应产生 keyring 失败检查项：%+v", rehearsal.Checks)
	}
	_, err = service.Execute(ctx, Request{Caller: env.caller(t),
		BackupPath: backupResult.Path, Reason: "错误密钥恢复"})
	if !errors.Is(err, ErrPreflightFailed) {
		t.Fatalf("错误密钥执行应返回预演失败，实际错误 = %v", formatError(err))
	}
	if service.State().Mode != "normal" || service.State().Generation != 0 {
		t.Fatalf("错误密钥不得改变维护/代际状态：%+v", service.State())
	}
	if fileSHA256(t, env.dbPath) != databaseHash {
		t.Fatal("错误密钥不得修改数据库")
	}
	afterBackups := listDirHashes(t, env.backupDir)
	if len(afterBackups) != len(backupHashes) {
		t.Fatal("错误密钥不得创建回退备份文件")
	}
	for name, hash := range backupHashes {
		if afterBackups[name] != hash {
			t.Fatalf("错误密钥场景备份文件 %s 被修改", name)
		}
	}
}

// hasFailedCheck 报告预演中是否存在指定名称的失败检查。
func hasFailedCheck(rehearsal Rehearsal, name string) bool {
	for _, check := range rehearsal.Checks {
		if check.Name == name && check.Status == CheckFailed {
			return true
		}
	}
	return false
}

// TestRestoreRejectsIncompatibleDatabaseVersion 校验数据库版本兼容：高于当前程序的
// 备份（降级）与无法识别的版本都在预演阶段 fail-closed，不修改当前数据库。
func TestRestoreRejectsIncompatibleDatabaseVersion(t *testing.T) {
	t.Run("future-downgrade", func(t *testing.T) {
		env := newTestEnv(t)
		store := env.openStore(t, true)
		env.mustMigrate(t, store)
		env.seedDatabase(t, store)
		if _, err := store.ExecContext(context.Background(), `INSERT INTO schema_history(
version,description,applied_at_ms,source_sha256) VALUES('0099','future',0,?)`,
			strings.Repeat("a", 64)); err != nil {
			t.Fatalf("写入未来迁移记录失败：%v", err)
		}
		backupResult := env.createBackup(t)
		closeStore(t, store)
		service := env.newRestoreService(t, nil)
		rehearsal, err := service.Rehearse(context.Background(), Request{
			Caller: env.caller(t), BackupPath: backupResult.Path, Reason: "未来版本预演"})
		assertNoError(t, err, "未来版本预演不应返回内部错误")
		if rehearsal.Restorable {
			t.Fatal("未来版本备份必须拒绝恢复（禁止降级）")
		}
		if !hasFailedCheck(rehearsal, "database_version") {
			t.Fatalf("应产生 database_version 失败检查项：%+v", rehearsal.Checks)
		}
		if _, err := service.Execute(context.Background(), Request{
			Caller: env.caller(t), BackupPath: backupResult.Path, Reason: "未来版本恢复"}); !errors.Is(err, ErrPreflightFailed) {
			t.Fatalf("未来版本执行应返回预演失败，实际错误 = %v", formatError(err))
		}
		if service.State().Mode != "normal" {
			t.Fatal("版本不兼容不得进入维护状态")
		}
	})
	t.Run("unknown-version", func(t *testing.T) {
		env := newTestEnv(t)
		store := env.openStore(t, true)
		env.mustMigrate(t, store)
		env.seedDatabase(t, store)
		if _, err := store.ExecContext(context.Background(), `INSERT INTO schema_history(
version,description,applied_at_ms,source_sha256) VALUES('zzz-unknown','unknown',0,?)`,
			strings.Repeat("b", 64)); err != nil {
			t.Fatalf("写入未知迁移记录失败：%v", err)
		}
		backupResult := env.createBackup(t)
		closeStore(t, store)
		service := env.newRestoreService(t, nil)
		rehearsal, err := service.Rehearse(context.Background(), Request{
			Caller: env.caller(t), BackupPath: backupResult.Path, Reason: "未知版本预演"})
		assertNoError(t, err, "未知版本预演不应返回内部错误")
		if rehearsal.Restorable {
			t.Fatal("未知版本备份必须拒绝恢复")
		}
		if !hasFailedCheck(rehearsal, "database_version") {
			t.Fatalf("应产生 database_version 失败检查项：%+v", rehearsal.Checks)
		}
	})
}

// faultAt 返回在指定阶段注入一次失败的测试故障注入器（其余阶段返回 nil）。
func faultAt(stage string) func(string) error {
	return func(current string) error {
		if current == stage {
			return errors.New("测试注入故障：" + stage)
		}
		return nil
	}
}

// TestRestoreInterruptBeforeSwitchKeepsDatabase 校验切换前中断：数据库与附件零副作用、
// 保持维护状态、未完成尝试被清除，重新执行可成功完成恢复。
func TestRestoreInterruptBeforeSwitchKeepsDatabase(t *testing.T) {
	stages := []string{"before_rollback_backup", "before_stage", "after_stage_before_switch"}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			env, holder := seededBackupEnv(t)
			backupResult := env.createBackup(t)
			holder.close(t)
			failing := env.newRestoreService(t, func(options *Options) {
				options.Fault = faultAt(stage)
			})
			result, err := failing.Execute(context.Background(), Request{
				Caller: env.caller(t), BackupPath: backupResult.Path, Reason: "切换前中断"})
			if err == nil {
				t.Fatalf("注入故障 %s 后执行应失败", stage)
			}
			if result.RestoreID == "" {
				t.Fatal("失败结果应包含恢复编号")
			}
			state := failing.State()
			if state.Mode != "maintenance" {
				t.Fatalf("切换前中断后应保持维护状态，实际 %q", state.Mode)
			}
			if state.Generation != 0 || state.Pending != nil {
				t.Fatalf("切换前中断不应推进代际/保留 pending：%+v", state)
			}
			// 逻辑内容校验：数据库仍是恢复前内容（会话仍在、代际未推进）。
			store := env.openLive(t)
			if got := tableCount(t, store, "sessions"); got != 1 {
				t.Fatalf("切换前中断后会话数 = %d，期望 1", got)
			}
			if got := queryInt64(t, store,
				`SELECT generation FROM restore_generation WHERE id=1`); got != 0 {
				t.Fatalf("切换前中断后库内代际 = %d，期望 0", got)
			}
			closeStore(t, store)
			// 明确退出维护后可恢复正常服务状态。
			recovered := env.newRestoreService(t, nil)
			if err := recovered.ExitMaintenance(context.Background(), MaintenanceRequest{
				Caller: env.caller(t), Reason: "切换前中断后退出维护", Force: true,
			}); err != nil && !strings.Contains(err.Error(), "审计") {
				t.Fatalf("退出维护失败：%v", formatError(err))
			}
			// 重新执行（无注入故障）应成功完成恢复。
			store = env.openLive(t)
			closeStore(t, store)
			service := env.newRestoreService(t, nil)
			second, err := service.Execute(context.Background(), Request{
				Caller: env.caller(t), BackupPath: backupResult.Path, Reason: "切换前中断后重试"})
			assertNoError(t, err, "切换前中断后重试恢复失败")
			if second.Generation != 1 {
				t.Fatalf("重试成功后代际 = %d，期望 1", second.Generation)
			}
		})
	}
}

// TestRestoreInterruptAfterSwitchRollsBack 校验切换后中断：自动回退到恢复前数据库、
// 保持维护、代际不前进；重新执行可成功完成恢复。
func TestRestoreInterruptAfterSwitchRollsBack(t *testing.T) {
	stages := []string{"after_switch_before_attachments", "after_switch_before_postprocess"}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			env, holder := seededBackupEnv(t)
			backupResult := env.createBackup(t)
			env.mutateAfterBackup(t, holder.store)
			holder.close(t)
			failing := env.newRestoreService(t, func(options *Options) {
				options.Fault = faultAt(stage)
			})
			_, err := failing.Execute(context.Background(), Request{
				Caller: env.caller(t), BackupPath: backupResult.Path, Reason: "切换后中断"})
			if err == nil {
				t.Fatalf("注入故障 %s 后执行应失败", stage)
			}
			state := failing.State()
			if state.Mode != "maintenance" {
				t.Fatalf("切换后中断应保持维护状态，实际 %q", state.Mode)
			}
			if state.Generation != 0 || state.Pending != nil {
				t.Fatalf("回退成功后不应推进代际/保留 pending：%+v", state)
			}
			// 回退后数据库仍是恢复前状态：备份后新增内容仍在。
			store := env.openLive(t)
			if got := queryInt64(t, store,
				`SELECT COUNT(*) FROM users WHERE id='usr_post_backup'`); got != 1 {
				t.Fatal("回退后应保留恢复前数据库内容")
			}
			closeStore(t, store)
			// 重新执行（无故障）成功。
			service := env.newRestoreService(t, nil)
			second, err := service.Execute(context.Background(), Request{
				Caller: env.caller(t), BackupPath: backupResult.Path, Reason: "切换后中断重试"})
			assertNoError(t, err, "切换后中断重试恢复失败")
			if second.Generation != 1 || !second.MaintenanceExited {
				t.Fatalf("重试恢复结果不符合期望：generation=%d exited=%v",
					second.Generation, second.MaintenanceExited)
			}
			live := env.openLive(t)
			defer closeStore(t, live)
			if got := queryInt64(t, live,
				`SELECT COUNT(*) FROM users WHERE id='usr_post_backup'`); got != 0 {
				t.Fatal("重试恢复后应回到备份时间点")
			}
		})
	}
}

// TestRestoreAuditMergeFailureKeepsMaintenanceAndRetries 校验恢复审计合并失败时：
// 数据恢复与凭证失效已完成但保持维护、库外审计完整保留；可独立重试合并后退出维护。
func TestRestoreAuditMergeFailureKeepsMaintenanceAndRetries(t *testing.T) {
	env, holder := seededBackupEnv(t)
	backupResult := env.createBackup(t)
	holder.close(t)
	service := env.newRestoreService(t, func(options *Options) {
		options.Fault = faultAt("before_audit_merge")
	})
	ctx := context.Background()
	result, err := service.Execute(ctx, Request{Caller: env.caller(t),
		BackupPath: backupResult.Path, Reason: "审计合并失败演练"})
	if !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("审计合并失败应返回审计不可用错误，实际 = %v", formatError(err))
	}
	if result.RestoreID == "" {
		t.Fatal("失败结果应包含恢复编号")
	}
	state := service.State()
	if state.Mode != "maintenance" {
		t.Fatalf("审计合并失败后必须保持维护状态，实际 %q", state.Mode)
	}
	if state.Generation != 1 || state.Pending != nil {
		t.Fatalf("数据库侧已提交时库外代际应前进且无 pending：%+v", state)
	}
	// 数据库已恢复且凭证已失效。
	live := env.openLive(t)
	if got := tableCount(t, live, "sessions"); got != 0 {
		t.Fatal("审计合并失败时凭证失效事务应已提交")
	}
	if got := queryInt64(t, live, `SELECT generation FROM restore_generation WHERE id=1`); got != 1 {
		t.Fatal("审计合并失败时库内代际应已前进")
	}
	closeStore(t, live)
	entries, err := service.JournalEntries()
	assertNoError(t, err, "读取库外审计日志失败")
	if len(entries) == 0 {
		t.Fatal("审计合并失败后库外审计日志必须完整保留")
	}
	// 独立重试合并（幂等）。
	mergeService := env.newRestoreService(t, nil)
	merged, err := mergeService.MergeAudit(ctx, env.caller(t))
	assertNoError(t, err, "重试恢复审计合并失败")
	if merged <= 0 {
		t.Fatalf("重试合并条数 = %d，期望大于 0", merged)
	}
	live = env.openLive(t)
	if got := queryInt64(t, live,
		`SELECT COUNT(*) FROM audit_events WHERE action=?`, ActionAuditMerged); got < 1 {
		t.Fatal("重试合并后应存在审计合并结果事件")
	}
	closeStore(t, live)
	// 退出维护恢复正常。
	if err := mergeService.ExitMaintenance(ctx, MaintenanceRequest{
		Caller: env.caller(t), Reason: "审计合并补做后退出维护"}); err != nil {
		t.Fatalf("退出维护失败：%v", formatError(err))
	}
	if mergeService.State().Mode != "normal" {
		t.Fatal("退出维护后状态应为 normal")
	}
}

// TestRestoreRequiresRestoreLock 校验恢复排他锁互斥：另一个流程持锁时执行被拒绝且
// 数据库不变。
func TestRestoreRequiresRestoreLock(t *testing.T) {
	env, holder := seededBackupEnv(t)
	backupResult := env.createBackup(t)
	holder.close(t)
	databaseHash := fileSHA256(t, env.dbPath)
	first := env.newRestoreService(t, nil)
	release, err := first.controller.LockRestore(context.Background())
	assertNoError(t, err, "取得恢复锁失败")
	defer release()
	second := env.newRestoreService(t, nil)
	_, err = second.Execute(context.Background(), Request{
		Caller: env.caller(t), BackupPath: backupResult.Path, Reason: "并发恢复"})
	if !errors.Is(err, ErrRestoreLocked) {
		t.Fatalf("持锁时执行应返回恢复锁占用，实际 = %v", formatError(err))
	}
	if fileSHA256(t, env.dbPath) != databaseHash {
		t.Fatal("持锁拒绝后不得修改数据库")
	}
	if second.State().Mode != "normal" {
		t.Fatal("取锁失败不应进入维护状态")
	}
}

// TestRestoreRequiresRootOrLocalAdmin 校验调用者边界：普通用户调用者（未配置 root
// 校验器）与缺少权限时拒绝，且不产生副作用。
func TestRestoreRequiresRootOrLocalAdmin(t *testing.T) {
	env, holder := seededBackupEnv(t)
	backupResult := env.createBackup(t)
	holder.close(t)
	userCaller, err := account.UserCaller("usr_" + strings.Repeat("ab", 16))
	assertNoError(t, err, "构造用户调用者失败")
	service := env.newRestoreService(t, nil)
	_, err = service.Execute(context.Background(), Request{Caller: userCaller,
		BackupPath: backupResult.Path, Reason: "越权恢复"})
	if !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("普通用户调用者应被拒绝，实际 = %v", formatError(err))
	}
	if service.State().Mode != "normal" {
		t.Fatal("越权拒绝不应进入维护状态")
	}
	// 未配置附件目录但备份包含附件：预演必须拒绝，避免恢复出不完整实例。
	attachmentEnv := newTestEnv(t)
	attachmentEnv.withAttach = true
	store := attachmentEnv.openStore(t, true)
	attachmentEnv.mustMigrate(t, store)
	ids := attachmentEnv.seedDatabase(t, store)
	attachmentEnv.insertAvatar(t, store, ids.userID, []byte("avatar"))
	withAttachments := attachmentEnv.createBackup(t)
	closeStore(t, store)
	noAttachments := attachmentEnv.newRestoreService(t, func(options *Options) {
		options.AttachmentsDir = ""
	})
	rehearsal, err := noAttachments.Rehearse(context.Background(), Request{
		Caller: attachmentEnv.caller(t), BackupPath: withAttachments.Path,
		Reason: "缺少附件目录预演"})
	assertNoError(t, err, "缺少附件目录预演不应返回内部错误")
	if rehearsal.Restorable {
		t.Fatal("备份包含附件但未配置附件目录时必须拒绝恢复")
	}
	if !hasFailedCheck(rehearsal, "attachments_target") {
		t.Fatalf("应产生 attachments_target 失败检查项：%+v", rehearsal.Checks)
	}
}

// TestOutsideStateAndJournalAnchorsFailClosed 覆盖修复轮安全 M1/M2：
// 删除/篡改库外状态或截断/重写审计日志尾部都必须 fail-closed（不静默重建、不通过链校验）。
func TestOutsideStateAndJournalAnchorsFailClosed(t *testing.T) {
	env, holder := seededBackupEnv(t)
	backupResult := env.createBackup(t)
	holder.close(t)
	ctx := context.Background()
	service := env.newRestoreService(t, nil)
	for index := 0; index < 2; index++ {
		if _, err := service.appendJournal(ctx, journalEvent{
			RestoreID: "rst_anchor_test", Actor: audit.Actor{Type: audit.ActorLocalAdmin,
				ID: "os:tester@test-host"},
			Action:     "test.anchor." + fmt.Sprintf("%d", index),
			TargetType: TargetTypeRestore, Outcome: audit.OutcomeSuccess}); err != nil {
			t.Fatalf("追加审计日志失败：%v", err)
		}
	}
	journalPath := service.JournalPath()
	statePath := service.State().OperatorID
	_ = statePath
	fullData, err := os.ReadFile(journalPath)
	assertNoError(t, err, "读取审计日志失败")
	lines := strings.Split(strings.TrimSuffix(string(fullData), "\n"), "\n")
	if len(lines) < 3 {
		t.Fatalf("审计日志行数 = %d，期望至少 3（含初始化事件）", len(lines))
	}
	_ = backupResult
	_ = service.Close()

	// 1) 尾部截断：删除最后一条后重新构造服务必须失败。
	truncated := strings.Join(lines[:len(lines)-1], "\n") + "\n"
	assertNoError(t, os.WriteFile(journalPath, []byte(truncated), 0o600), "写入截断日志失败")
	if _, err := New(env.restoreOptions(t, nil)); err == nil {
		t.Fatal("审计日志尾部截断必须 fail-closed")
	}
	// 恢复完整日志。
	assertNoError(t, os.WriteFile(journalPath, fullData, 0o600), "恢复审计日志失败")

	// 2) 整链重写（尾部换成重新计算哈希链的伪造事件）：锚点哈希不匹配必须失败。
	var second JournalEntry
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &second); err != nil {
		t.Fatalf("解析审计日志行失败：%v", err)
	}
	forged := JournalEntry{RestoreID: second.RestoreID, At: second.At.Add(time.Second),
		ActorType: second.ActorType, ActorID: second.ActorID, Action: "test.forged",
		TargetType: TargetTypeRestore, Outcome: string(audit.OutcomeSuccess),
		Seq: second.Seq + 1, PrevHash: second.Hash}
	hash, err := journalEntryHash(forged)
	assertNoError(t, err, "计算伪造哈希失败")
	forged.Hash = hash
	forgedLine, err := json.Marshal(forged)
	assertNoError(t, err, "序列化伪造事件失败")
	rewritten := strings.Join(lines[:len(lines)-1], "\n") + "\n" + string(forgedLine) + "\n"
	assertNoError(t, os.WriteFile(journalPath, []byte(rewritten), 0o600), "写入重写日志失败")
	if _, err := New(env.restoreOptions(t, nil)); err == nil {
		t.Fatal("审计日志整链重写（锚点不符）必须 fail-closed")
	}
	// 2b) 锚点之后追加 >=2 条自洽伪造事件（无主密钥）：只允许多 1 条崩溃窗口尾，
	// 更多未锚定尾部必须按疑似篡改拒绝。
	forgedEntries := make([]JournalEntry, 0, 2)
	previous := second
	for index := 0; index < 2; index++ {
		item := JournalEntry{RestoreID: second.RestoreID, At: second.At.Add(time.Duration(index+2) * time.Second),
			ActorType: second.ActorType, ActorID: second.ActorID,
			Action: "test.forged.tail", TargetType: TargetTypeRestore,
			Outcome: string(audit.OutcomeSuccess), Seq: previous.Seq + 1,
			PrevHash: previous.Hash}
		hash, hashErr := journalEntryHash(item)
		assertNoError(t, hashErr, "计算伪造尾部哈希失败")
		item.Hash = hash
		forgedEntries = append(forgedEntries, item)
		previous = item
	}
	tailLines := make([]string, 0, len(lines)+2)
	tailLines = append(tailLines, lines...)
	for _, item := range forgedEntries {
		encoded, encodeErr := json.Marshal(item)
		assertNoError(t, encodeErr, "序列化伪造尾部失败")
		tailLines = append(tailLines, string(encoded))
	}
	assertNoError(t, os.WriteFile(journalPath,
		[]byte(strings.Join(tailLines, "\n")+"\n"), 0o600), "写入伪造尾部失败")
	if _, err := New(env.restoreOptions(t, nil)); err == nil {
		t.Fatal("锚点之后 ≥2 条自洽伪造尾部必须 fail-closed")
	}
	// 恢复完整日志并删除库外状态：缺失状态必须 fail-closed，且不得静默重建。
	assertNoError(t, os.WriteFile(journalPath, fullData, 0o600), "恢复审计日志失败")
	stateFile := filepath.Join(env.stateDir, "restore-state.json")
	if err := os.Remove(stateFile); err != nil {
		t.Fatalf("删除库外状态失败：%v", err)
	}
	missingService, err := New(env.restoreOptions(t, nil))
	assertNoError(t, err, "状态缺失时构造服务应成功但标记未初始化")
	if !missingService.StateMissing() {
		t.Fatal("状态文件缺失必须标记未初始化，而不是静默重建")
	}
	if _, err := missingService.Execute(ctx, Request{Caller: env.caller(t),
		BackupPath: backupResult.Path, Reason: "状态缺失恢复"}); err == nil {
		t.Fatal("状态缺失时执行恢复必须 fail-closed")
	}
	// 状态已缺失但审计日志已有历史事件：拒绝重新初始化（防止删除状态重置锚点）。
	if err := missingService.InitState(ctx, InitStateRequest{Caller: env.caller(t),
		Reason: "试图重置状态"}); err == nil {
		t.Fatal("存在审计历史时重新初始化必须被拒绝")
	}
}

// TestInitStateAdoptJournal 覆盖状态文件丢失但有审计历史时的受控破窗重建（N2）。
func TestInitStateAdoptJournal(t *testing.T) {
	env := newTestEnv(t)
	store := env.openStore(t, true)
	env.mustMigrate(t, store)
	env.seedDatabase(t, store)
	closeStore(t, store)
	service := env.newRestoreService(t, nil)
	_ = service.Close()
	statePath := filepath.Join(env.stateDir, "restore-state.json")
	if err := os.Remove(statePath); err != nil {
		t.Fatalf("删除状态文件失败：%v", err)
	}
	missing, err := New(env.restoreOptions(t, nil))
	assertNoError(t, err, "状态缺失时构造服务应成功")
	if !missing.StateMissing() {
		t.Fatal("状态缺失应标记未初始化")
	}
	ctx := context.Background()
	if err := missing.InitState(ctx, InitStateRequest{Caller: env.caller(t),
		Reason: "未确认破窗"}); err == nil {
		t.Fatal("有审计历史且未显式 adopt-journal 时必须拒绝初始化")
	}
	if err := missing.InitState(ctx, InitStateRequest{Caller: env.caller(t),
		Reason: "人工核验后受控破窗", AdoptJournal: true}); err != nil {
		t.Fatalf("受控破窗重建失败：%v", err)
	}
	if missing.StateMissing() {
		t.Fatal("重建后状态不应再标记缺失")
	}
	anchorSeq, _, ok := missing.controller.JournalAnchor()
	if !ok || anchorSeq <= 0 {
		t.Fatalf("破窗重建后锚点未重算：seq=%d ok=%t", anchorSeq, ok)
	}
	if _, err := missing.appendJournal(ctx, journalEvent{
		RestoreID: "rst_adopt_after", Actor: audit.Actor{Type: audit.ActorLocalAdmin,
			ID: "os:tester@test-host"}, Action: "test.after.adopt",
		TargetType: TargetTypeRestore, Outcome: audit.OutcomeSuccess}); err != nil {
		t.Fatalf("破窗重建后继续写审计失败：%v", err)
	}
}
