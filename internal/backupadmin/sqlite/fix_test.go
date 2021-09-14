package sqlite_test

// 步骤 81 修复轮回归测试：管理变更审计 fail-closed、计划管理再次认证、清理批准目标
// 绑定、清理失败通知与真实 InspectFile 对账路径。

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/backupadmin"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// TestAuditFailureRollsBackManagementChanges 验证关键管理变更在审计不可用时拒绝执行：
// 保留策略与计划都不会生效（B1）。
func TestAuditFailureRollsBackManagementChanges(t *testing.T) {
	e := newEnv(t)
	// 保留策略：审计失败 → 保存失败且仍为默认策略。
	e.audit.fail = true
	if _, err := e.admin.SaveRetention(e.ctx, backupadmin.RetentionChange{
		Caller: e.caller, MaxCount: 3, ExpectedVersion: 0, Reason: "收紧策略",
		RequestID: "req-audit-retention"}); !errors.Is(err, backupadmin.ErrAuditUnavailable) {
		t.Fatalf("审计失败时保存策略应拒绝，得到 %v", err)
	}
	view, err := e.admin.Retention(e.ctx, e.caller)
	if err != nil || !view.IsDefault {
		t.Fatalf("审计失败后策略仍应保持默认: %+v err=%v", view, err)
	}
	// 计划：审计失败 → 创建失败且计划未生效。
	if _, err := e.admin.CreateSchedule(e.ctx, backupadmin.ScheduleRequest{
		Caller: e.caller, Name: "审计失败计划", ScheduleType: task.ScheduleTypeDaily,
		Expression: "02:30", TimeZone: "Asia/Shanghai",
		MissedPolicy: task.MissedSkip, MaxCatchUp: 1, Enabled: true,
		RequestID: "req-audit-schedule"}); !errors.Is(err, backupadmin.ErrAuditUnavailable) {
		t.Fatalf("审计失败时创建计划应拒绝，得到 %v", err)
	}
	schedules, err := e.admin.ListSchedules(e.ctx, e.caller)
	if err != nil || len(schedules) != 0 {
		t.Fatalf("审计失败后不应产生计划: %d err=%v", len(schedules), err)
	}
	e.audit.fail = false
	// 审计恢复后可正常保存（证明失败来自审计 fail-closed 而不是参数）。
	if _, err := e.admin.SaveRetention(e.ctx, backupadmin.RetentionChange{
		Caller: e.caller, MaxCount: 3, ExpectedVersion: 0, Reason: "正常保存",
		RequestID: "req-audit-ok"}); err != nil {
		t.Fatalf("审计恢复后保存策略失败: %v", err)
	}
}

// TestScheduleManagementRequiresReauth 验证计划创建/启停/删除都要求强认证敏感操作。
func TestScheduleManagementRequiresReauth(t *testing.T) {
	e := newEnv(t)
	e.sensitive.denied = true
	if _, err := e.admin.CreateSchedule(e.ctx, backupadmin.ScheduleRequest{
		Caller: e.caller, Name: "无强认证计划", ScheduleType: task.ScheduleTypeDaily,
		Expression: "02:30", TimeZone: "Asia/Shanghai",
		MissedPolicy: task.MissedSkip, MaxCatchUp: 1, Enabled: true,
	}); !errors.Is(err, backupadmin.ErrAccessDenied) {
		t.Fatalf("无再次认证时创建计划应拒绝，得到 %v", err)
	}
	e.sensitive.denied = false
	created, err := e.admin.CreateSchedule(e.ctx, backupadmin.ScheduleRequest{
		Caller: e.caller, Name: "正常计划", ScheduleType: task.ScheduleTypeDaily,
		Expression: "02:30", TimeZone: "Asia/Shanghai",
		MissedPolicy: task.MissedSkip, MaxCatchUp: 1, Enabled: true,
	})
	if err != nil {
		t.Fatalf("创建计划失败: %v", err)
	}
	e.sensitive.denied = true
	if _, err := e.admin.SetScheduleEnabled(e.ctx, e.caller, created.ID, false,
		"停用", ""); !errors.Is(err, backupadmin.ErrAccessDenied) {
		t.Fatalf("无再次认证时停用应拒绝，得到 %v", err)
	}
	if err := e.admin.DeleteSchedule(e.ctx, e.caller, created.ID, "删除", ""); !errors.Is(err, backupadmin.ErrAccessDenied) {
		t.Fatalf("无再次认证时删除应拒绝，得到 %v", err)
	}
}

// TestCleanupApprovalBindingRejectsChangedTargets 验证清理任务把再次认证批准的目标
// 集合/策略版本绑定到载荷：执行时集合或策略变化则拒绝删除。
func TestCleanupApprovalBindingRejectsChangedTargets(t *testing.T) {
	e := newEnv(t)
	e.seedArtifact(t, "a", e.now.Add(-40*24*time.Hour), 100, backupadmin.VerificationVerified)
	e.seedArtifact(t, "b", e.now.Add(-1*24*time.Hour), 100, backupadmin.VerificationVerified)
	if _, err := e.admin.SaveRetention(e.ctx, backupadmin.RetentionChange{
		Caller: e.caller, MaxCount: 1, ExpectedVersion: 0, Reason: "只留一份",
		RequestID: "req-bind"}); err != nil {
		t.Fatalf("保存策略失败: %v", err)
	}
	ref, err := e.admin.EnqueueCleanup(e.ctx, e.caller, "req-bind-cleanup")
	if err != nil {
		t.Fatalf("提交清理失败: %v", err)
	}
	// 批准后新增一份校验通过备份 → 待删集合变化，必须拒绝。
	e.seedArtifact(t, "c", e.now.Add(-2*24*time.Hour), 100, backupadmin.VerificationVerified)
	err = e.runHandler(e.job(ref.JobID))
	if !errors.Is(err, backupadmin.ErrConflict) || !task.IsNonRetryable(err) {
		t.Fatalf("目标集合变化后清理应拒绝，得到 %v", err)
	}
	for _, view := range e.artifacts() {
		if view.Cleanup == string(backupadmin.CleanupCleaned) {
			t.Fatalf("拒绝后不应删除任何产物: %+v", view)
		}
	}
	// 批准后放宽策略 → 计划目标清空，与批准集合不一致，同样拒绝。
	if _, err := e.admin.SaveRetention(e.ctx, backupadmin.RetentionChange{
		Caller: e.caller, MaxCount: 10, ExpectedVersion: 1, Reason: "放宽",
		RequestID: "req-bind2"}); err != nil {
		t.Fatalf("放宽策略失败: %v", err)
	}
	if err := e.runHandler(e.job(ref.JobID)); !errors.Is(err, backupadmin.ErrConflict) {
		t.Fatalf("策略变化后清理应拒绝，得到 %v", err)
	}
}

// failCleanStore 包装真实仓储，仅让 MarkArtifactCleaned 失败，用于确定性验证清理
// 失败通知路径（不依赖平台删除语义）。
type failCleanStore struct{ backupadmin.Store }

func (failCleanStore) MarkArtifactCleaned(context.Context, string,
	audit.Actor, time.Time) error {
	return backupadmin.ErrStoreUnavailable
}

// rebuildWithFailClean 用失败仓储重建服务（其余依赖不变）。
func rebuildWithFailClean(t *testing.T, e *env) *backupadmin.Service {
	t.Helper()
	service, err := backupadmin.New(backupadmin.Options{
		Backup: e.creator, Store: failCleanStore{Store: e.store}, Scheduler: e.scheduler,
		SchedulerRelay: e.relay, Enqueuer: e.executor, Canceller: e.executor,
		TaskReader: e.executor, Authorizer: e.authz, Sensitive: e.sensitive,
		Audit: e.audit, Notifier: e.notifier, OutputDir: e.creator.dir,
		DefaultRetention: backupadmin.RetentionPolicy{
			Version: 1, MaxCount: 10, MaxAgeDays: 30, MaxTotalBytes: 1 << 30},
		DefaultNotifyTarget: "owner_mail", DefaultNotifyFailures: true,
		DefaultNotifySuccess: true, DownloadTTL: time.Minute,
		MaxPageDownloadBytes: 1 << 20,
		Now:                  func() time.Time { return e.now },
	})
	if err != nil {
		t.Fatalf("重建服务失败: %v", err)
	}
	return service
}

// TestCleanupFailureSendsNotification 验证清理失败按任务配置发送失败通知，且分项
// 结果如实记录（用失败仓储确定性注入，不依赖平台删除语义）。
func TestCleanupFailureSendsNotification(t *testing.T) {
	e := newEnv(t)
	e.seedArtifact(t, "a", e.now.Add(-40*24*time.Hour), 100, backupadmin.VerificationVerified)
	e.seedArtifact(t, "b", e.now.Add(-1*24*time.Hour), 100, backupadmin.VerificationVerified)
	if _, err := e.admin.SaveRetention(e.ctx, backupadmin.RetentionChange{
		Caller: e.caller, MaxCount: 1, ExpectedVersion: 0, Reason: "只留一份",
		RequestID: "req-cleanup-fail"}); err != nil {
		t.Fatalf("保存策略失败: %v", err)
	}
	ref, err := e.admin.EnqueueCleanup(e.ctx, e.caller, "req-cleanup-fail-job")
	if err != nil {
		t.Fatalf("提交清理失败: %v", err)
	}
	// 执行阶段改用失败仓储：文件删除成功但状态更新失败 → 分项失败并通知。
	e.admin = rebuildWithFailClean(t, e)
	err = e.runHandler(e.job(ref.JobID))
	if err == nil {
		t.Fatal("清理状态更新失败时应返回错误")
	}
	e.notifier.mu.Lock()
	defer e.notifier.mu.Unlock()
	found := false
	for _, message := range e.notifier.messages {
		if message.Kind == backupadmin.NotificationCleanupFailed {
			found = true
		}
	}
	if !found {
		t.Fatalf("清理失败应发送 cleanup_failed 通知，实际 %+v", e.notifier.messages)
	}
}

// TestRetryableBackupFailureNotNonRetryable 验证存储 BUSY 属于可重试失败（任务级
// 重试依赖它），而权限/审计错误仍不可重试。
func TestRetryableBackupFailureNotNonRetryable(t *testing.T) {
	e := newEnv(t)
	ref, err := e.admin.EnqueueBackup(e.ctx, e.caller, "req-retry")
	if err != nil {
		t.Fatalf("提交备份失败: %v", err)
	}
	e.creator.mu.Lock()
	e.creator.fail = storage.ErrBusy
	e.creator.mu.Unlock()
	handlerErr := e.runHandler(e.job(ref.JobID))
	if handlerErr == nil || task.IsNonRetryable(handlerErr) {
		t.Fatalf("存储 BUSY 应返回可重试错误，得到 %v", handlerErr)
	}
	e.creator.mu.Lock()
	e.creator.fail = nil
	e.creator.mu.Unlock()
}

// TestReconcileDefaultInspectRejectsInvalidFile 验证默认真实 InspectFile 路径：损坏/
// 非本格式的 .elnbak 文件不登记为可用备份（不伪造产物）。
func TestReconcileDefaultInspectRejectsInvalidFile(t *testing.T) {
	e := newEnv(t)
	orphanPath := filepath.Join(e.creator.dir, "login-backup_20261118T000000Z_bkp_"+
		strings.Repeat("7", 32)+".elnbak")
	if err := os.WriteFile(orphanPath, []byte("not-a-real-backup"), 0o600); err != nil {
		t.Fatalf("写入损坏文件失败: %v", err)
	}
	result, err := e.admin.Reconcile(e.ctx)
	if err != nil {
		t.Fatalf("对账失败: %v", err)
	}
	if result.Orphans != 0 || len(e.artifacts()) != 0 {
		t.Fatalf("损坏文件不应登记为备份产物: %+v", result)
	}
}

// TestBackupFailureNotificationKinds 验证权限拒绝与普通失败分别发送对应通知类型。
func TestBackupFailureNotificationKinds(t *testing.T) {
	e := newEnv(t)
	// 权限拒绝：任务尝试前失权 → permission_denied 通知。
	ref, err := e.admin.EnqueueBackup(e.ctx, e.caller, "req-kind-perm")
	if err != nil {
		t.Fatalf("提交备份失败: %v", err)
	}
	e.authz.deny(backupadmin.PermissionCreate)
	_ = e.runHandler(e.job(ref.JobID))
	e.authz.allow(backupadmin.PermissionCreate)
	// 普通失败：备份引擎返回不可重试错误 → backup_failed 通知。
	ref2, err := e.admin.EnqueueBackup(e.ctx, e.caller, "req-kind-fail")
	if err != nil {
		t.Fatalf("提交第二个备份失败: %v", err)
	}
	e.creator.mu.Lock()
	e.creator.fail = backupadmin.ErrInvalidRequest
	e.creator.mu.Unlock()
	_ = e.runHandler(e.job(ref2.JobID))
	e.creator.mu.Lock()
	e.creator.fail = nil
	e.creator.mu.Unlock()
	e.notifier.mu.Lock()
	defer e.notifier.mu.Unlock()
	kinds := map[string]bool{}
	for _, message := range e.notifier.messages {
		kinds[message.Kind] = true
	}
	if !kinds[backupadmin.NotificationPermissionDenied] {
		t.Fatalf("缺少 permission_denied 通知: %+v", kinds)
	}
	if !kinds[backupadmin.NotificationBackupFailed] {
		t.Fatalf("缺少 backup_failed 通知: %+v", kinds)
	}
}
