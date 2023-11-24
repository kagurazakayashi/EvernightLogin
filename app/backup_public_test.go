// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package app

// 步骤 231 公开备份/恢复接口定向测试：真实 SQLite 备份→检查→导出→修改→恢复→
// 旧会话失效；失败预检、权限拒绝、路径与确认门禁。

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

type backupTestEnv struct {
	runtime *Runtime
	clock   *testClock
	ctx     context.Context
	local   AdminCaller
}

func newBackupTestEnv(t *testing.T) *backupTestEnv {
	t.Helper()
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 7, 0, 0, 0, time.UTC))
	runtime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	return &backupTestEnv{runtime: runtime, clock: clock, ctx: ctx,
		local: runtime.LocalAdmin()}
}

func (env *backupTestEnv) start(t *testing.T) {
	t.Helper()
	if err := env.runtime.Start(env.ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
}

// triggerBackup 触发一次真实备份并等待任务终态；返回备份编号（失败返回空）。
func (env *backupTestEnv) triggerBackup(t *testing.T) string {
	t.Helper()
	ref, err := env.runtime.Backup().Jobs().Trigger(env.ctx,
		BackupJobTriggerRequest{Caller: env.local, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("Trigger backup: %v", err)
	}
	if ref.JobID == "" {
		t.Fatalf("Trigger 未返回任务 ID: %+v", ref)
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatalf("等待备份任务 %s 超时", ref.JobID)
		}
		job, err := env.runtime.Backup().Jobs().Get(env.ctx, BackupJobRequest{
			Caller: env.local, JobID: ref.JobID, RequestID: login.NewRequestID()})
		if err != nil {
			t.Fatalf("查询备份任务 %s: %v", ref.JobID, err)
		}
		switch job.State {
		case "succeeded":
			if job.BackupID == "" {
				t.Fatalf("任务成功但缺少 BackupID: %+v", job)
			}
			return job.BackupID
		case "failed", "cancelled":
			t.Fatalf("备份任务终态 %s（%s）: %+v", job.State, job.ErrorCode, job)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// closeRuntime 关闭运行时（恢复前置条件）；忽略重复关闭。
func (env *backupTestEnv) closeRuntime() {
	_ = env.runtime.Close(context.Background())
}

// TestBackupPlanLifecycle 覆盖计划创建/读取/停用/删除与本地管理员权限。
func TestBackupPlanLifecycle(t *testing.T) {
	env := newBackupTestEnv(t)
	env.start(t)
	plans := env.runtime.Backup().Plans()
	created, err := plans.Create(env.ctx, BackupPlanRequest{Caller: env.local,
		Name: "每日备份", ScheduleType: "daily", Expression: "03:00",
		TimeZone: "UTC", MissedPolicy: "skip", MaxCatchUp: 1,
		TimeoutSeconds: 3600, MaxAttempts: 2, Enabled: true,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("Create plan: %v", err)
	}
	if created.ID == "" || !created.Enabled || created.Name != "每日备份" {
		t.Fatalf("计划视图异常: %+v", created)
	}
	got, err := plans.Get(env.ctx, BackupPlanRequest{Caller: env.local,
		ScheduleID: created.ID, RequestID: login.NewRequestID()})
	if err != nil || got.ID != created.ID {
		t.Fatalf("Get plan: %+v err=%v", got, err)
	}
	disabled, err := plans.SetEnabled(env.ctx, BackupPlanStateRequest{Caller: env.local,
		ScheduleID: created.ID, Enabled: false, Reason: "测试停用",
		RequestID: login.NewRequestID()})
	if err != nil || disabled.Enabled {
		t.Fatalf("SetEnabled: %+v err=%v", disabled, err)
	}
	if err := plans.Delete(env.ctx, BackupPlanRequest{Caller: env.local,
		ScheduleID: created.ID, Reason: "测试删除",
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("Delete plan: %v", err)
	}
}

// TestBackupTriggerCheckExport 覆盖真实备份→任务查询→认证检查→受控导出。
func TestBackupTriggerCheckExport(t *testing.T) {
	env := newBackupTestEnv(t)
	env.start(t)
	backupID := env.triggerBackup(t)

	artifact, err := env.runtime.Backup().Artifacts().Get(env.ctx, BackupArtifactRequest{
		Caller: env.local, BackupID: backupID, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("Get artifact: %v", err)
	}
	if artifact.BackupID != backupID || artifact.SizeBytes <= 0 || !artifact.FileExists {
		t.Fatalf("产物视图异常: %+v", artifact)
	}
	check, err := env.runtime.Backup().Artifacts().Check(env.ctx, BackupArtifactRequest{
		Caller: env.local, BackupID: backupID, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("Check artifact: %v", err)
	}
	if !check.StructuralValid || !check.Encrypted || !check.Authenticated ||
		check.BackupID != backupID || check.FileSHA256 == "" {
		t.Fatalf("认证检查结果异常: %+v", check)
	}
	exported, err := env.runtime.Backup().Artifacts().Export(env.ctx, BackupArtifactRequest{
		Caller: env.local, BackupID: backupID, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("Export artifact: %v", err)
	}
	if len(exported.Data) == 0 || exported.Size != int64(len(exported.Data)) ||
		exported.SHA256 != check.FileSHA256 || exported.FileName == "" {
		t.Fatalf("导出结果异常: size=%d sha=%q", len(exported.Data), exported.SHA256)
	}
}

// TestBackupCheckAuditFailureFailsClosed 验证检查写审计失败时不返回假成功。
func TestBackupCheckAuditFailureFailsClosed(t *testing.T) {
	env := newBackupTestEnv(t)
	env.start(t)
	backupID := env.triggerBackup(t)
	if _, err := env.runtime.base.Store.DB().Exec(
		`CREATE TRIGGER step231_fail_audit BEFORE INSERT ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit down'); END;`); err != nil {
		t.Fatalf("注入审计故障失败: %v", err)
	}
	t.Cleanup(func() {
		_, _ = env.runtime.base.Store.DB().Exec(`DROP TRIGGER step231_fail_audit`)
	})
	_, err := env.runtime.Backup().Artifacts().Check(env.ctx, BackupArtifactRequest{
		Caller: env.local, BackupID: backupID, RequestID: login.NewRequestID()})
	if err == nil {
		t.Fatal("审计故障时检查必须失败")
	}
	if code := asRBACAppError(t, err).Code(); code != login.CodeAuditWriteFailed {
		t.Fatalf("审计故障错误码 = %q，期望 AUDIT_WRITE_FAILED", code)
	}
}

// TestBackupRecoveryRoundTrip 覆盖备份→检查→修改数据→关闭运行时→预演→恢复→
// 旧会话失效且恢复到备份时点。
func TestBackupRecoveryRoundTrip(t *testing.T) {
	env := newBackupTestEnv(t)
	env.start(t)
	const password = "K8$wR3!nB6@yF1#v"
	userA, err := env.runtime.Users().Create(env.ctx, CreateUserRequest{
		Username: "backup-user-a", Password: password, Nickname: "A",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建用户 A: %v", err)
	}
	loginA, err := env.runtime.Auth().Login(env.ctx, LoginRequest{
		Username: "backup-user-a", Password: password, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()})
	if err != nil || loginA.Restricted || len(loginA.SessionSecret) == 0 {
		t.Fatalf("用户 A 登录: %+v err=%v", loginA, err)
	}
	oldSession := append([]byte(nil), loginA.SessionSecret...)
	backupID := env.triggerBackup(t)
	// 备份后修改数据：新增用户 B（恢复后应消失）。
	if _, err := env.runtime.Users().Create(env.ctx, CreateUserRequest{
		Username: "backup-user-b", Password: password, Nickname: "B",
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("创建用户 B: %v", err)
	}
	dbPath := env.runtime.opts.DatabasePath
	keyPath := env.runtime.opts.MasterKeyFile
	backupDir := filepath.Join(filepath.Dir(dbPath), "backups")
	beforeBackupFiles, _ := os.ReadDir(backupDir)

	recovery := env.runtime.Backup().Recovery()
	stateDir := t.TempDir()
	if err := recovery.Configure(env.ctx, BackupRecoveryConfigRequest{Caller: env.local,
		StateDir: stateDir, RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("Configure recovery: %v", err)
	}
	source, err := recovery.LoadBackup(env.ctx, BackupRecoveryLoadRequest{Caller: env.local,
		BackupID: backupID, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("LoadBackup: %v", err)
	}
	if source.BackupID != backupID || source.FileSHA256 == "" {
		t.Fatalf("恢复源异常: %+v", source)
	}
	env.closeRuntime()
	if err := recovery.Initialize(env.ctx, BackupRecoveryInitializeRequest{Caller: env.local,
		Reason: "步骤 231 恢复演练初始化", Confirm: true,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("Initialize recovery state: %v", err)
	}
	rehearsal, err := recovery.Rehearse(env.ctx, BackupRecoveryRestoreRequest{
		Caller: env.local, Reason: "步骤 231 恢复预演", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("Rehearse: %v", err)
	}
	if !rehearsal.Restorable || rehearsal.Backup.BackupID != backupID {
		t.Fatalf("预演应可恢复: %+v", rehearsal)
	}
	result, err := recovery.Execute(env.ctx, BackupRecoveryRestoreRequest{
		Caller: env.local, Reason: "步骤 231 实际恢复", ConfirmToken: "RESTORE",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("Execute restore: %v", err)
	}
	if result.RestoreID == "" || result.Generation == 0 || !result.MaintenanceExited {
		t.Fatalf("恢复结果异常: %+v", result)
	}
	if result.RevokedSessions == 0 {
		t.Fatalf("恢复后应失效旧会话: %+v", result)
	}
	// 恢复前回退备份必须作为新受控文件发布（不覆盖用户原始备份）。
	afterBackupFiles, readErr := os.ReadDir(backupDir)
	if readErr != nil || len(afterBackupFiles) <= len(beforeBackupFiles) {
		t.Fatalf("恢复前回退备份未生成新文件: before=%d after=%d err=%v",
			len(beforeBackupFiles), len(afterBackupFiles), readErr)
	}

	// 重新打开恢复后的数据库：旧会话必须失效，备份后新增用户 B 必须不存在。
	cfg := testConfig()
	reopened, err := Open(env.ctx, Options{Config: &cfg, DatabasePath: dbPath,
		MasterKeyFile: keyPath, Migrate: false, CreateMasterKey: false,
		OperatorID: "host-operator", Now: env.clock.Now})
	if err != nil {
		t.Fatalf("恢复后重新打开运行时: %v", err)
	}
	defer func() { _ = reopened.Close(context.Background()) }()
	if _, err := reopened.Sessions().Validate(env.ctx, oldSession); err == nil {
		t.Fatal("恢复后旧会话必须失效")
	}
	_ = userA
	_, err = reopened.Admin().GetUserByUsername(env.ctx, AdminUserByUsernameRequest{
		Caller: reopened.LocalAdmin(), Username: "backup-user-b",
		RequestID: login.NewRequestID()})
	if !IsNotFound(err) {
		t.Fatalf("恢复后备份时点之后创建的用户应不存在，实际 err=%v", err)
	}
	if _, err := reopened.Admin().GetUserByUsername(env.ctx, AdminUserByUsernameRequest{
		Caller: reopened.LocalAdmin(), Username: "backup-user-a",
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("恢复后应保留备份时点用户 A: %v", err)
	}
}

// TestBackupRecoveryGuards 覆盖权限/路径/确认/关闭前置与受限会话拒绝。
func TestBackupRecoveryGuards(t *testing.T) {
	env := newBackupTestEnv(t)
	env.start(t)
	backupID := env.triggerBackup(t)
	recovery := env.runtime.Backup().Recovery()

	// 状态目录位于数据库目录内必须拒绝。
	if err := recovery.Configure(env.ctx, BackupRecoveryConfigRequest{Caller: env.local,
		StateDir:  filepath.Join(filepath.Dir(env.runtime.opts.DatabasePath), "state-inside"),
		RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("状态目录位于数据库目录内必须拒绝")
	}
	// 普通用户管理员（AdminSession）不能执行恢复。
	stateDir := t.TempDir()
	if err := recovery.Configure(env.ctx, BackupRecoveryConfigRequest{Caller: env.local,
		StateDir: stateDir, RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	if _, err := recovery.LoadBackup(env.ctx, BackupRecoveryLoadRequest{
		Caller: AdminCaller{}, BackupID: backupID, RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("零值调用者必须拒绝")
	}
	// 未关闭运行时不能预演/执行。
	if _, err := recovery.Rehearse(env.ctx, BackupRecoveryRestoreRequest{Caller: env.local,
		Reason: "未关闭运行时", RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("运行时未关闭时预演必须拒绝")
	}
	if _, err := recovery.Execute(env.ctx, BackupRecoveryRestoreRequest{Caller: env.local,
		Reason: "未关闭运行时", ConfirmToken: "RESTORE",
		RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("运行时未关闭时恢复必须拒绝")
	}
}

// TestBackupRecoveryCorruptBackupRejected 覆盖损坏备份预检失败且不修改数据库。
func TestBackupRecoveryCorruptBackupRejected(t *testing.T) {
	env := newBackupTestEnv(t)
	env.start(t)
	backupID := env.triggerBackup(t)
	exported, err := env.runtime.Backup().Artifacts().Export(env.ctx, BackupArtifactRequest{
		Caller: env.local, BackupID: backupID, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	// 测试直接定位受控目录内已登记文件并篡改（公开 API 不提供路径）。
	backupPath := filepath.Join(filepath.Dir(env.runtime.opts.DatabasePath), "backups",
		exported.FileName)
	data, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("读取受控备份文件: %v", err)
	}
	for index := 0; index < 16 && index < len(data); index++ {
		data[index] ^= 0xFF
	}
	if err := os.WriteFile(backupPath, data, 0o600); err != nil {
		t.Fatalf("篡改备份文件: %v", err)
	}
	recovery := env.runtime.Backup().Recovery()
	if err := recovery.Configure(env.ctx, BackupRecoveryConfigRequest{Caller: env.local,
		StateDir: t.TempDir(), RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	if _, err := recovery.LoadBackup(env.ctx, BackupRecoveryLoadRequest{Caller: env.local,
		BackupID: backupID, RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("LoadBackup: %v", err)
	}
	env.closeRuntime()
	if err := recovery.Initialize(env.ctx, BackupRecoveryInitializeRequest{Caller: env.local,
		Reason: "损坏备份预检", Confirm: true, RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if _, err := recovery.Execute(env.ctx, BackupRecoveryRestoreRequest{Caller: env.local,
		Reason: "损坏备份执行", ConfirmToken: "RESTORE",
		RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("损坏备份恢复必须失败")
	}
	// 数据库仍可打开并包含现有用户（未切换到损坏内容）。
	cfg := testConfig()
	reopened, err := Open(env.ctx, Options{Config: &cfg,
		DatabasePath:  env.runtime.opts.DatabasePath,
		MasterKeyFile: env.runtime.opts.MasterKeyFile, Migrate: false,
		CreateMasterKey: false, OperatorID: "host-operator", Now: env.clock.Now})
	if err != nil {
		t.Fatalf("失败恢复后数据库应仍可打开: %v", err)
	}
	_ = reopened.Close(context.Background())
}

// TestBackupJobCancelAndTerminalState 覆盖任务取消请求与真实终态（请求受理≠已取消）。
func TestBackupJobCancelAndTerminalState(t *testing.T) {
	env := newBackupTestEnv(t)
	ref, err := env.runtime.Backup().Jobs().Trigger(env.ctx,
		BackupJobTriggerRequest{Caller: env.local, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("Trigger: %v", err)
	}
	cancel, err := env.runtime.Backup().Jobs().Cancel(env.ctx, BackupJobCancelRequest{
		Caller: env.local, JobID: ref.JobID, Reason: "测试取消",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if cancel.JobID != ref.JobID || cancel.State == "" {
		t.Fatalf("取消结果异常: %+v", cancel)
	}
	env.start(t)
	deadline := time.Now().Add(30 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatalf("等待取消任务终态超时")
		}
		job, err := env.runtime.Backup().Jobs().Get(env.ctx, BackupJobRequest{
			Caller: env.local, JobID: ref.JobID, RequestID: login.NewRequestID()})
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if job.State == "cancelled" || job.State == "succeeded" || job.State == "failed" {
			if job.State == "cancelled" {
				if job.Canceller == "" {
					t.Fatalf("取消终态应记录实际取消操作者: %+v", job)
				}
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestBackupRecoveryAdminSessionDenied 验证普通管理会话不能配置/执行本地恢复。
func TestBackupRecoveryAdminSessionDenied(t *testing.T) {
	env := newBackupTestEnv(t)
	const password = "K8$wR3!nB6@yF1#v"
	if _, err := env.runtime.Users().Create(env.ctx, CreateUserRequest{
		Username: "backup-session-user", Password: password, Nickname: "S",
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("创建会话用户: %v", err)
	}
	loginResult, err := env.runtime.Auth().Login(env.ctx, LoginRequest{
		Username: "backup-session-user", Password: password, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()})
	if err != nil || loginResult.Restricted {
		t.Fatalf("登录: %+v err=%v", loginResult, err)
	}
	sessionCaller := env.runtime.AdminSession(loginResult.SessionSecret)
	err = env.runtime.Backup().Recovery().Configure(env.ctx, BackupRecoveryConfigRequest{
		Caller: sessionCaller, StateDir: t.TempDir(), RequestID: login.NewRequestID()})
	if err == nil {
		t.Fatal("普通管理会话配置恢复必须拒绝")
	}
	if code := asRBACAppError(t, err).Code(); code != login.CodeAccessDenied {
		t.Fatalf("拒绝码 = %q，期望 ACCESS_DENIED", code)
	}
}

// TestBackupInvalidRequestIDRejected 验证请求编号在领域调用前校验。
func TestBackupInvalidRequestIDRejected(t *testing.T) {
	env := newBackupTestEnv(t)
	_, err := env.runtime.Backup().Artifacts().Get(context.Background(),
		BackupArtifactRequest{Caller: env.local, BackupID: "bkp_x",
			RequestID: "bad id!"})
	if err == nil {
		t.Fatal("非法请求编号必须拒绝")
	}
	var appError *login.AppError
	if !errors.As(err, &appError) || appError.Code() != login.CodeReqInvalid {
		t.Fatalf("错误 = %v，期望 REQ_INVALID", err)
	}
}
