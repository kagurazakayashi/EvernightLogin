// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package serverapp

// 步骤 265：人工恢复通知与真实投递记录的完整关联链路测试。
// 使用真实 SQLite（人工恢复存储 + mailer 投递记录 + 审计）与真实 DeliveryService，
// 但不真实外发 SMTP（发送器只记录调用），验证：
//   - 通知入队返回真实投递记录 ID / 稳定业务去重键，重复触发不产生第二封；
//   - 执行结果与受权读取可投影 queued→succeeded 的实际投递状态；
//   - 通知状态与恢复结果分离，跨用户读取通知投影被拒绝。

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	"github.com/kagurazakayashi/EvernightLogin/internal/manualrecovery"
	manualrecoverysqlite "github.com/kagurazakayashi/EvernightLogin/internal/manualrecovery/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// recoveryExecutorStub 是成功返回的执行器替身（测试不执行真实改密/MFA 重置）。
type recoveryExecutorStub struct {
	outcome manualrecovery.ExecutionOutcome
}

func (s recoveryExecutorStub) Execute(context.Context,
	manualrecovery.ExecutionCommand) (manualrecovery.ExecutionOutcome, error) {
	return s.outcome, nil
}

func (s recoveryExecutorStub) Compensate(context.Context, manualrecovery.ExecutionCommand) error {
	return nil
}

// TestManualRecoveryNotificationDeliveryLink 验证人工恢复通知的投递关联闭环。
func TestManualRecoveryNotificationDeliveryLink(t *testing.T) {
	ctx := context.Background()
	store := openMigratedStore(t)
	recorder := newTestAudit(t, store)
	keyring := newTestKeyring(t)
	now := time.Date(2026, 11, 26, 6, 0, 0, 0, time.UTC)
	const (
		operatorCreate  = "usr_000000000000000000000000000000a1"
		operatorApprove = "usr_000000000000000000000000000000a2"
		operatorRun     = "usr_000000000000000000000000000000a3"
		targetUser      = "usr_000000000000000000000000000000a4"
		targetEmail     = "delivery-link@example.test"
	)
	seedNotifierTarget(t, store, targetUser, "delivery-link-target", targetEmail, now)
	for _, user := range []struct{ id, name string }{
		{operatorCreate, "delivery-link-create"},
		{operatorApprove, "delivery-link-approve"},
		{operatorRun, "delivery-link-run"},
	} {
		if _, err := store.DB().ExecContext(ctx, `INSERT INTO users(
id,username,username_normalized,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'active',0,1,1,?,?)`, user.id, user.name, user.name,
			now.UnixMilli(), now.UnixMilli()); err != nil {
			t.Fatalf("插入用户 %s: %v", user.id, err)
		}
	}
	sender := &recordingMailSender{}
	enqueuer := &realManualEnqueuer{}
	delivery := newNotifierDeliveryService(t, store, sender, enqueuer, now)
	notifier := manualRecoveryNotifier{deliveries: delivery, store: store,
		appName: "测试登录", supportURL: "https://example.test/support"}
	targets := manualRecoveryTargets{store: store, keyring: keyring}
	manualStore, err := manualrecoverysqlite.New(store)
	if err != nil {
		t.Fatalf("人工恢复存储: %v", err)
	}
	policy := manualrecovery.Policy{Enabled: true,
		VerificationBases: []manualrecovery.VerificationBasis{manualrecovery.BasisNotarizedDeclaration},
		DeliveryChannels:  []manualrecovery.DeliveryChannel{manualrecovery.DeliveryVerifiedEmail},
		WaitPeriod:        time.Hour, ApprovalTTL: 2 * time.Hour, RequestTTL: 3 * time.Hour,
		RequireIndependentApproval: true}
	clock := now
	service, err := manualrecovery.New(manualrecovery.Options{
		Store: manualStore, Audit: recorder, Reauth: recoveryReauthStub{},
		Staff: recoveryStaffStub{}, Targets: targets,
		Executor: recoveryExecutorStub{outcome: manualrecovery.ExecutionOutcome{
			Summary: "测试执行完成", SessionsRevoked: 2}},
		Notifier: notifier, NotificationsQueued: true, Deliveries: delivery,
		Policy: policy, Now: func() time.Time { return clock },
	})
	if err != nil {
		t.Fatalf("人工恢复服务: %v", err)
	}
	initiator, err := manualrecovery.UserCaller(operatorCreate)
	if err != nil {
		t.Fatalf("发起者: %v", err)
	}
	approver, err := manualrecovery.UserCaller(operatorApprove)
	if err != nil {
		t.Fatalf("审批人: %v", err)
	}
	runner, err := manualrecovery.UserCaller(operatorRun)
	if err != nil {
		t.Fatalf("执行人: %v", err)
	}
	created, err := service.Create(ctx, initiator, manualrecovery.CreateRequest{
		TargetUserID: targetUser, Operation: manualrecovery.OperationPasswordReset,
		VerificationBasis:     manualrecovery.BasisNotarizedDeclaration,
		VerificationReference: "notary-delivery-265", EvidenceSummary: "线下核验记录摘要",
		Reason: "用户丢失密码", Delivery: manualrecovery.DeliveryVerifiedEmail,
		RequestID: "req-265-create",
	})
	if err != nil {
		t.Fatalf("创建申请: %v", err)
	}
	if _, err := service.Approve(ctx, approver, manualrecovery.ApproveRequest{
		RequestID: created.ID, Note: "独立核验通过", TraceID: "req-265-approve"}); err != nil {
		t.Fatalf("独立审批: %v", err)
	}
	clock = clock.Add(policy.WaitPeriod + time.Second)
	result, err := service.Execute(ctx, runner, manualrecovery.ExecuteRequest{
		RequestID: created.ID, TraceID: "req-265-execute"})
	if err != nil {
		t.Fatalf("执行恢复: %v", err)
	}
	if result.Status != manualrecovery.StatusCompleted {
		t.Fatalf("执行结果状态 = %q", result.Status)
	}
	expectedKey := manualrecovery.NotificationDedupKey(created.ID, manualrecovery.NotificationCompleted)
	if result.Notification.State != manualrecovery.NotificationStateQueued {
		t.Fatalf("通知状态 = %q，期望 queued", result.Notification.State)
	}
	if result.NotificationSent {
		t.Fatal("队列通知不得标记 NotificationSent")
	}
	if !strings.HasPrefix(result.Notification.DeliveryID, "mdl_") {
		t.Fatalf("执行结果缺少真实投递记录 ID: %+v", result.Notification)
	}
	if result.Notification.DedupKey != expectedKey || !result.Notification.Matched ||
		result.Notification.DeliveryState != mailer.DeliveryQueued {
		t.Fatalf("执行结果投递投影异常: %+v", result.Notification)
	}
	if len(enqueuer.requests) != 1 {
		t.Fatalf("投递任务数 = %d，期望 1", len(enqueuer.requests))
	}

	// 重复触发同一业务事件：幂等命中既有投递，不产生第二封邮件。
	completedNotice := manualrecovery.Notification{Kind: manualrecovery.NotificationCompleted,
		RequestID: created.ID, TargetUserID: targetUser,
		Operation: manualrecovery.OperationPasswordReset, OccurredAt: clock}
	duplicate, err := notifier.NotifyWithReceipt(ctx, completedNotice)
	if err != nil {
		t.Fatalf("重复通知: %v", err)
	}
	if !duplicate.Duplicate || duplicate.DeliveryID != result.Notification.DeliveryID {
		t.Fatalf("重复通知未命中同一投递: %+v", duplicate)
	}
	if len(enqueuer.requests) != 1 {
		t.Fatalf("重复通知产生了额外投递任务: %d", len(enqueuer.requests))
	}

	// 执行真实投递任务（真实 DeliveryService + 记录型发送器，不真实外发）。
	request := enqueuer.requests[0]
	if err := delivery.Handler(ctx, task.Job{ID: firstMailTaskID(request),
		Kind: request.Kind, Payload: request.Payload, Initiator: request.Actor,
		Attempt: 1, MaxAttempts: request.MaxAttempts}); err != nil {
		t.Fatalf("执行通知投递任务: %v", err)
	}
	if sender.count() != 1 {
		t.Fatalf("发送器调用数 = %d，期望 1", sender.count())
	}
	system, err := mailer.SystemCaller("manual-recovery-test")
	if err != nil {
		t.Fatalf("系统调用者: %v", err)
	}
	record, err := delivery.Get(ctx, system, result.Notification.DeliveryID)
	if err != nil {
		t.Fatalf("读取投递记录: %v", err)
	}
	if record.State != mailer.DeliverySucceeded || record.IdempotencyKey != expectedKey {
		t.Fatalf("投递记录终态异常: %+v", record)
	}

	// 受权读取：参与人可看到同一投递的 succeeded 实际状态。
	execution, found, err := service.GetExecution(ctx, initiator, created.ID)
	if err != nil || !found {
		t.Fatalf("读取执行记录: found=%v err=%v", found, err)
	}
	if execution.Notification.DeliveryState != mailer.DeliverySucceeded ||
		execution.Notification.DeliveryID != result.Notification.DeliveryID {
		t.Fatalf("读取投影异常: %+v", execution.Notification)
	}
	if execution.Notification.State != manualrecovery.NotificationStateQueued {
		t.Fatalf("业务通知状态被投递状态覆盖: %+v", execution.Notification)
	}
	view, found, err := service.GetExecutionNotification(ctx, runner, created.ID)
	if err != nil || !found {
		t.Fatalf("执行人读取通知投影: found=%v err=%v", found, err)
	}
	if view.DeliveryState != mailer.DeliverySucceeded {
		t.Fatalf("执行人投影异常: %+v", view)
	}
	// 跨用户读取拒绝。
	outsider, err := manualrecovery.UserCaller("usr_000000000000000000000000000000a9")
	if err != nil {
		t.Fatalf("外部调用者: %v", err)
	}
	if _, _, err := service.GetExecutionNotification(ctx, outsider, created.ID); !errors.Is(err, manualrecovery.ErrAccessDenied) {
		t.Fatalf("非参与人读取通知投影应拒绝，得到 %v", err)
	}
	// 通知审计（动作级）落库。
	var notificationAudits int
	if err := store.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_events WHERE action=?`,
		manualrecovery.ActionNotification).Scan(&notificationAudits); err != nil {
		t.Fatalf("读取通知审计: %v", err)
	}
	if notificationAudits == 0 {
		t.Fatal("缺少人工恢复通知审计")
	}
}

// firstMailTaskID 返回固定的投递任务 ID（测试只执行一次任务）。
func firstMailTaskID(task.EnqueueRequest) string { return "manual-delivery-265" }
