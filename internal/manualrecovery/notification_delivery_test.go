// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package manualrecovery_test

// 步骤 265：人工恢复通知的可靠投递关联测试。
// 覆盖：回执/去重键/投递投影、服务重启后仍可投影、关联状态写失败可按去重键恢复、
// 失败执行通知不把恢复标记成功、完成后仍可重复投影投递重试/失败、跨用户查询拒绝。

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	"github.com/kagurazakayashi/EvernightLogin/internal/manualrecovery"
)

// fakeReceiptNotifier 模拟可靠队列通知器：可注入回执与错误，并记录通知。
type fakeReceiptNotifier struct {
	mu            sync.Mutex
	notifications []manualrecovery.Notification
	receipt       manualrecovery.NotificationReceipt
	err           error
}

func (f *fakeReceiptNotifier) Notify(ctx context.Context, notification manualrecovery.Notification) error {
	_, err := f.NotifyWithReceipt(ctx, notification)
	return err
}

func (f *fakeReceiptNotifier) NotifyWithReceipt(_ context.Context,
	notification manualrecovery.Notification) (manualrecovery.NotificationReceipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.notifications = append(f.notifications, notification)
	if f.err != nil {
		return manualrecovery.NotificationReceipt{
			State:    manualrecovery.NotificationStateFailed,
			DedupKey: manualrecovery.NotificationDedupKey(notification.RequestID, notification.Kind),
		}, f.err
	}
	receipt := f.receipt
	if receipt.DedupKey == "" {
		receipt.DedupKey = manualrecovery.NotificationDedupKey(notification.RequestID, notification.Kind)
	}
	if receipt.State == "" {
		receipt.State = manualrecovery.NotificationStateQueued
	}
	return receipt, nil
}

func (f *fakeReceiptNotifier) last() (manualrecovery.Notification, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.notifications) == 0 {
		return manualrecovery.Notification{}, false
	}
	return f.notifications[len(f.notifications)-1], true
}

// fakeDeliveryLookup 模拟 mailer 只读投递投影；按业务去重键返回可控投递记录。
type fakeDeliveryLookup struct {
	mu    sync.Mutex
	byKey map[string]mailer.Record
	err   error
	calls int
}

func (f *fakeDeliveryLookup) LookupDeliveryByIdempotencyKey(_ context.Context,
	key string) (mailer.Record, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return mailer.Record{}, false, f.err
	}
	record, ok := f.byKey[key]
	return record, ok, nil
}

func (f *fakeDeliveryLookup) LookupDeliveryByID(_ context.Context, id string) (mailer.Record, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, record := range f.byKey {
		if record.ID == id {
			return record, true, nil
		}
	}
	return mailer.Record{}, false, nil
}

func (f *fakeDeliveryLookup) put(key string, record mailer.Record) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.byKey == nil {
		f.byKey = map[string]mailer.Record{}
	}
	f.byKey[key] = record
}

func (f *fakeDeliveryLookup) setState(key string, state mailer.DeliveryState) {
	f.mu.Lock()
	defer f.mu.Unlock()
	record := f.byKey[key]
	record.State = state
	f.byKey[key] = record
}

func (f *fakeDeliveryLookup) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// notificationStateFailingStore 包装真实 Store，模拟通知状态回写失败（关联回写失败）。
type notificationStateFailingStore struct {
	manualrecovery.Store
	mu       sync.Mutex
	failNext bool
	failures int
	calls    int
}

func (s *notificationStateFailingStore) SetNotificationState(ctx context.Context,
	requestID, state string) error {
	s.mu.Lock()
	s.calls++
	fail := s.failNext
	if fail {
		s.failNext = false
		s.failures++
	}
	s.mu.Unlock()
	if fail {
		return errors.New("simulated notification state write failure")
	}
	return s.Store.SetNotificationState(ctx, requestID, state)
}

func (s *notificationStateFailingStore) failureCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failures
}

// testNotificationPolicy 返回测试用人工恢复制度（与 newTestEnv 默认一致）。
func testNotificationPolicy() manualrecovery.Policy {
	return manualrecovery.Policy{
		Enabled: true,
		VerificationBases: []manualrecovery.VerificationBasis{
			manualrecovery.BasisInPersonIdentityDocument,
		},
		DeliveryChannels:           []manualrecovery.DeliveryChannel{manualrecovery.DeliveryVerifiedEmail},
		WaitPeriod:                 time.Hour,
		ApprovalTTL:                12 * time.Hour,
		RequestTTL:                 24 * time.Hour,
		RequireIndependentApproval: true,
	}
}

// runCompletedExecution 走完“申请→独立审批→等待期→执行成功”主链路。
func runCompletedExecution(t *testing.T, env *testEnv) (manualrecovery.ExecutionResult,
	manualrecovery.RequestRecord) {
	t.Helper()
	record := env.create()
	env.approve(record.ID)
	env.now = env.now.Add(time.Hour + time.Minute)
	result, err := env.service.Execute(env.ctx, env.caller(executor), manualrecovery.ExecuteRequest{
		RequestID: record.ID, TraceID: "req-exec-notify"})
	if err != nil {
		t.Fatalf("执行恢复: %v", err)
	}
	return result, record
}

// TestExecutionNotificationReceiptAndProjection 验证完成通知返回真实投递关联回执，
// 且受权读取时能从投递记录投影排队/发送后端接受/失败等实际状态。
func TestExecutionNotificationReceiptAndProjection(t *testing.T) {
	notifier := &fakeReceiptNotifier{receipt: manualrecovery.NotificationReceipt{
		State: manualrecovery.NotificationStateQueued, DeliveryID: "mdl_notification000001"}}
	lookup := &fakeDeliveryLookup{}
	env := newTestEnv(t, func(options *manualrecovery.Options) {
		options.Notifier = notifier
		options.NotificationsQueued = true
		options.Deliveries = lookup
	})
	result, record := runCompletedExecution(t, env)
	dedupKey := manualrecovery.NotificationDedupKey(record.ID, manualrecovery.NotificationCompleted)

	if result.NotificationSent {
		t.Fatal("队列通知不得标记为已送达(sent)")
	}
	if result.Notification.State != manualrecovery.NotificationStateQueued {
		t.Fatalf("通知状态 = %q，期望 queued", result.Notification.State)
	}
	if result.Notification.DedupKey != dedupKey {
		t.Fatalf("业务去重键 = %q，期望 %q", result.Notification.DedupKey, dedupKey)
	}
	if result.Notification.DeliveryID != "mdl_notification000001" {
		t.Fatalf("投递关联 = %q，期望投递记录 ID", result.Notification.DeliveryID)
	}
	if result.Notification.Matched {
		t.Fatal("投递记录尚未写入前不应标记 Matched")
	}
	if env.count(`SELECT COUNT(*) FROM manual_recovery_executions WHERE notification_state='queued'`) != 1 {
		t.Fatal("数据库未记录 queued 通知状态")
	}
	if !containsAuditAction(env, manualrecovery.ActionNotification) {
		t.Fatal("缺少通知审计（含投递关联）")
	}

	// 投递记录写入后（队列已受理），受权读取可看到排队状态。
	lookup.put(dedupKey, mailer.Record{ID: "mdl_notification000001",
		IdempotencyKey: dedupKey, State: mailer.DeliveryQueued, TaskID: "tsk_delivery_0001",
		Recipient: "target@example.test"})
	view, found, err := env.service.GetExecutionNotification(env.ctx, env.caller(initiator), record.ID)
	if err != nil || !found {
		t.Fatalf("读取通知投影: found=%v err=%v", found, err)
	}
	if !view.Matched || view.DeliveryState != mailer.DeliveryQueued || view.DeliveryID != "mdl_notification000001" {
		t.Fatalf("排队投影异常: %+v", view)
	}
	if view.DeliveryTaskID != "tsk_delivery_0001" {
		t.Fatalf("投递任务关联异常: %+v", view)
	}

	// 投递任务发送后端接受后，同一读取路径投影 succeeded（不代表用户已读）。
	lookup.setState(dedupKey, mailer.DeliverySucceeded)
	execution, found, err := env.service.GetExecution(env.ctx, env.caller(executor), record.ID)
	if err != nil || !found {
		t.Fatalf("读取执行记录: found=%v err=%v", found, err)
	}
	if execution.Notification.DeliveryState != mailer.DeliverySucceeded {
		t.Fatalf("发送后端接受后投影 = %q", execution.Notification.DeliveryState)
	}
	if execution.Notification.State != manualrecovery.NotificationStateQueued {
		t.Fatalf("业务通知状态被投递投影覆盖: %+v", execution.Notification)
	}

	// 投递终止失败时投影 failed（业务通知状态不变，不把失败夸大为成功）。
	lookup.put(dedupKey, mailer.Record{ID: "mdl_notification000001",
		IdempotencyKey: dedupKey, State: mailer.DeliveryFailed,
		LastErrorCode: mailer.CodeUnavailable})
	view, _, err = env.service.GetExecutionNotification(env.ctx, env.caller(approver), record.ID)
	if err != nil {
		t.Fatalf("读取失败投影: %v", err)
	}
	if view.DeliveryState != mailer.DeliveryFailed || view.DeliveryErrorCode != mailer.CodeUnavailable {
		t.Fatalf("失败投影异常: %+v", view)
	}
	if !containsAuditAction(env, manualrecovery.ActionNotification) {
		t.Fatal("通知审计缺失")
	}
}

// containsAuditAction 报告审计中是否有指定动作。
func containsAuditAction(env *testEnv, action string) bool {
	env.t.Helper()
	rows, err := env.raw.QueryContext(env.ctx, `SELECT COUNT(*) FROM audit_events WHERE action=?`, action)
	if err != nil {
		env.t.Fatalf("读取审计动作: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return false
	}
	var count int
	if err := rows.Scan(&count); err != nil {
		env.t.Fatalf("扫描审计动作: %v", err)
	}
	return count > 0
}

// TestNotificationProjectionAfterServiceRestart 验证服务重启（新 Service 实例）后仍能
// 通过稳定业务去重键投影既有投递记录，不依赖内存回执。
func TestNotificationProjectionAfterServiceRestart(t *testing.T) {
	notifier := &fakeReceiptNotifier{receipt: manualrecovery.NotificationReceipt{
		State: manualrecovery.NotificationStateQueued, DeliveryID: "mdl_restart000000001"}}
	lookup := &fakeDeliveryLookup{}
	env := newTestEnv(t, func(options *manualrecovery.Options) {
		options.Notifier = notifier
		options.NotificationsQueued = true
		options.Deliveries = lookup
	})
	_, record := runCompletedExecution(t, env)
	dedupKey := manualrecovery.NotificationDedupKey(record.ID, manualrecovery.NotificationCompleted)
	lookup.put(dedupKey, mailer.Record{ID: "mdl_restart000000001",
		IdempotencyKey: dedupKey, State: mailer.DeliverySucceeded})

	restarted, err := manualrecovery.New(manualrecovery.Options{
		Store: env.store, Audit: env.audit, Reauth: env.auth, Staff: env.staff,
		Targets: env.targets, Executor: env.executor,
		Notifier: notifier, NotificationsQueued: true, Deliveries: lookup,
		Policy: testNotificationPolicy(),
		Now:    func() time.Time { return env.now },
	})
	if err != nil {
		t.Fatalf("重启后构造服务: %v", err)
	}
	view, found, err := restarted.GetExecutionNotification(env.ctx, env.caller(initiator), record.ID)
	if err != nil || !found {
		t.Fatalf("重启后读取通知投影: found=%v err=%v", found, err)
	}
	if !view.Matched || view.DeliveryState != mailer.DeliverySucceeded ||
		view.DeliveryID != "mdl_restart000000001" || view.DedupKey != dedupKey {
		t.Fatalf("重启后投影异常: %+v", view)
	}
}

// TestNotificationStateWriteFailureRecoverableByDedupKey 验证通知状态回写失败不影响
// 已完成的恢复：业务终态保持成功，读取仍可按稳定业务去重键回看投递终态。
func TestNotificationStateWriteFailureRecoverableByDedupKey(t *testing.T) {
	notifier := &fakeReceiptNotifier{receipt: manualrecovery.NotificationReceipt{
		State: manualrecovery.NotificationStateQueued, DeliveryID: "mdl_linkfail00000001"}}
	lookup := &fakeDeliveryLookup{}
	flaky := &notificationStateFailingStore{failNext: true}
	env := newTestEnv(t, func(options *manualrecovery.Options) {
		// 包装真实 Store：第一次通知状态回写注入失败，其余委托给真实存储。
		flaky.Store = options.Store
		options.Store = flaky
		options.Notifier = notifier
		options.NotificationsQueued = true
		options.Deliveries = lookup
	})
	result, record := runCompletedExecution(t, env)
	dedupKey := manualrecovery.NotificationDedupKey(record.ID, manualrecovery.NotificationCompleted)
	if flaky.failureCount() == 0 {
		t.Fatal("未触发注入的通知状态回写失败")
	}
	if result.Status != manualrecovery.StatusCompleted {
		t.Fatalf("通知状态回写失败不应改变恢复结果: %+v", result)
	}
	if env.count(`SELECT COUNT(*) FROM manual_recovery_executions WHERE status='succeeded'`) != 1 {
		t.Fatal("通知状态回写失败不应把成功执行改成失败")
	}
	if env.count(`SELECT COUNT(*) FROM manual_recovery_executions WHERE notification_state='pending'`) != 1 {
		t.Fatal("预期通知状态保持 pending（回写失败），供读取时按去重键恢复")
	}
	lookup.put(dedupKey, mailer.Record{ID: "mdl_linkfail00000001",
		IdempotencyKey: dedupKey, State: mailer.DeliverySucceeded})
	view, found, err := env.service.GetExecutionNotification(env.ctx, env.caller(initiator), record.ID)
	if err != nil || !found {
		t.Fatalf("读取通知投影: found=%v err=%v", found, err)
	}
	if !view.Matched || view.DeliveryState != mailer.DeliverySucceeded {
		t.Fatalf("回写失败后无法按去重键恢复投递投影: %+v", view)
	}
}

// TestFailedExecutionNotificationNotMarkedRecovered 验证执行失败时通知仍被记录，且绝不
// 把失败的恢复标记为成功；同时验证执行成功但通知失败不回滚业务终态。
func TestFailedExecutionNotificationNotMarkedRecovered(t *testing.T) {
	notifier := &fakeReceiptNotifier{}
	lookup := &fakeDeliveryLookup{}
	failExecutor := &fakeExecutor{err: errors.New("恢复执行失败")}
	env := newTestEnv(t, func(options *manualrecovery.Options) {
		options.Executor = failExecutor
		options.Notifier = notifier
		options.NotificationsQueued = true
		options.Deliveries = lookup
	})
	record := env.create()
	env.approve(record.ID)
	env.now = env.now.Add(time.Hour + time.Minute)
	if _, err := env.service.Execute(env.ctx, env.caller(executor), manualrecovery.ExecuteRequest{
		RequestID: record.ID, TraceID: "req-exec-failed"}); !errors.Is(err, manualrecovery.ErrExecutionFailed) {
		t.Fatalf("执行失败应返回 ErrExecutionFailed，得到 %v", err)
	}
	if env.count(`SELECT COUNT(*) FROM manual_recovery_executions WHERE status='failed'`) != 1 {
		t.Fatal("执行记录应为 failed")
	}
	if env.count(`SELECT COUNT(*) FROM manual_recovery_executions WHERE status='succeeded'`) != 0 {
		t.Fatal("失败执行不得被标记为成功")
	}
	if env.count(`SELECT COUNT(*) FROM manual_recovery_executions WHERE notification_state='queued'`) != 1 {
		t.Fatal("失败执行的通知状态未记录（应可查询）")
	}
	view, found, err := env.service.GetExecutionNotification(env.ctx, env.caller(initiator), record.ID)
	if err != nil || !found {
		t.Fatalf("读取失败执行通知: found=%v err=%v", found, err)
	}
	expectedKey := manualrecovery.NotificationDedupKey(record.ID, manualrecovery.NotificationFailed)
	if view.Kind != manualrecovery.NotificationFailed || view.DedupKey != expectedKey {
		t.Fatalf("失败通知关联异常: %+v", view)
	}
	if view.State == manualrecovery.NotificationStateSent {
		t.Fatal("失败执行不得因通知发送而显示 sent/成功")
	}

	// 执行成功但通知失败：业务终态保持 completed，通知状态 failed。
	successNotifier := &fakeReceiptNotifier{err: errors.New("投递队列不可用")}
	env2 := newTestEnv(t, func(options *manualrecovery.Options) {
		options.Notifier = successNotifier
		options.NotificationsQueued = true
		options.Deliveries = &fakeDeliveryLookup{}
	})
	result, record2 := runCompletedExecution(t, env2)
	if result.Status != manualrecovery.StatusCompleted {
		t.Fatalf("通知失败不应回滚恢复: %+v", result)
	}
	if result.NotificationSent || result.Notification.State != manualrecovery.NotificationStateFailed {
		t.Fatalf("通知失败结果异常: %+v", result)
	}
	if env2.count(`SELECT COUNT(*) FROM manual_recovery_executions WHERE status='succeeded'`) != 1 ||
		env2.count(`SELECT COUNT(*) FROM manual_recovery_requests WHERE id=? AND status='completed'`, record2.ID) != 1 {
		t.Fatal("通知失败不应改变恢复/申请业务终态")
	}
	if env2.count(`SELECT COUNT(*) FROM manual_recovery_executions WHERE notification_state='failed'`) != 1 {
		t.Fatal("完成执行的通知失败状态未记录")
	}
}

// TestExecutionNotificationQueryRejectsNonParticipant 验证通知投影与执行记录一样按
// 参与人/执行人授权，其他用户不能读取（跨用户查询拒绝）。
func TestExecutionNotificationQueryRejectsNonParticipant(t *testing.T) {
	notifier := &fakeReceiptNotifier{receipt: manualrecovery.NotificationReceipt{
		State: manualrecovery.NotificationStateQueued, DeliveryID: "mdl_denied0000000001"}}
	env := newTestEnv(t, func(options *manualrecovery.Options) {
		options.Notifier = notifier
		options.NotificationsQueued = true
		options.Deliveries = &fakeDeliveryLookup{}
	})
	_, record := runCompletedExecution(t, env)
	outsider := "usr_00000000000000000000000000000099"
	caller, err := manualrecovery.UserCaller(outsider)
	if err != nil {
		t.Fatalf("构造外部调用者: %v", err)
	}
	if _, _, err := env.service.GetExecutionNotification(env.ctx, caller, record.ID); !errors.Is(err, manualrecovery.ErrAccessDenied) {
		t.Fatalf("非参与人读取通知投影应拒绝，得到 %v", err)
	}
	if _, _, err := env.service.GetExecution(env.ctx, caller, record.ID); !errors.Is(err, manualrecovery.ErrAccessDenied) {
		t.Fatalf("非参与人读取执行记录应拒绝，得到 %v", err)
	}
}

// TestNotificationDedupKeyStable 验证业务去重键确定、区分类别且满足 mailer 幂等键
// 长度约束（同一事件重复触达得到同一键）。
func TestNotificationDedupKeyStable(t *testing.T) {
	const requestID = "mrr_00000000000000000000000000000001"
	completed := manualrecovery.NotificationDedupKey(requestID, manualrecovery.NotificationCompleted)
	if completed != manualrecovery.NotificationDedupKey(requestID, manualrecovery.NotificationCompleted) {
		t.Fatal("同一申请同一类别去重键必须稳定")
	}
	failed := manualrecovery.NotificationDedupKey(requestID, manualrecovery.NotificationFailed)
	if completed == failed {
		t.Fatal("完成/失败通知去重键必须不同")
	}
	for _, key := range []string{completed, failed} {
		if !manualrecovery.ValidNotificationDedupKey(key) {
			t.Fatalf("去重键不满足 8～128 字节约束: %q", key)
		}
		if key == "" {
			t.Fatal("去重键不能为空")
		}
	}
	if manualrecovery.ValidNotificationDedupKey("short") {
		t.Fatal("过短去重键应判无效")
	}
	long := manualrecovery.NotificationDedupKey(requestID, manualrecovery.NotificationKind(
		"manual_recovery_completed_extra_padding_padding_padding_padding_padding_padding"))
	if manualrecovery.ValidNotificationDedupKey(long) {
		t.Fatalf("超长去重键应判无效: len=%d", len(long))
	}
}
