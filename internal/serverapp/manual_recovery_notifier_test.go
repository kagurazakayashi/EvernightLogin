// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package serverapp

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	mailersqlite "github.com/kagurazakayashi/EvernightLogin/internal/mailer/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailtest"
	"github.com/kagurazakayashi/EvernightLogin/internal/manualrecovery"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// realManualEnqueuer 记录人工恢复通知的投递任务，供测试驱动 Handler。
type realManualEnqueuer struct {
	requests []task.EnqueueRequest
}

func (e *realManualEnqueuer) Enqueue(_ context.Context, request task.EnqueueRequest) (task.Job, error) {
	e.requests = append(e.requests, request)
	return task.Job{ID: "manual-real-job", Kind: request.Kind, Payload: request.Payload,
		Initiator: request.Actor, Attempt: 1, MaxAttempts: request.MaxAttempts}, nil
}

// noopMailAudit 仅满足 mailer.AuditRecorder；测试不需要投递审计入库。
type noopMailAudit struct{}

func (noopMailAudit) Record(context.Context, audit.Event) error { return nil }

// captureManualDeliveries 捕获人工恢复通知入队请求。
type captureManualDeliveries struct {
	mu       sync.Mutex
	requests []mailer.EnqueueRequest
	err      error
}

func (c *captureManualDeliveries) Enqueue(_ context.Context, request mailer.EnqueueRequest) (mailer.EnqueueResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return mailer.EnqueueResult{}, c.err
	}
	c.requests = append(c.requests, request)
	return mailer.EnqueueResult{}, nil
}

func (c *captureManualDeliveries) snapshot() []mailer.EnqueueRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]mailer.EnqueueRequest(nil), c.requests...)
}

// recordingMailSender 记录直接发送调用，不真实外发（用于构造投递服务的测试发送器）。
type recordingMailSender struct {
	mu       sync.Mutex
	messages []mailer.Message
}

func (s *recordingMailSender) Send(_ context.Context, message mailer.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.messages = append(s.messages, message)
	return nil
}

func (s *recordingMailSender) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.messages)
}

// failingTaskEnqueuer 让投递记录创建后任务入队失败（覆盖真实 Enqueue 的失败分支）。
type failingTaskEnqueuer struct{}

func (failingTaskEnqueuer) Enqueue(context.Context, task.EnqueueRequest) (task.Job, error) {
	return task.Job{}, errors.New("task queue unavailable")
}

// failingManualDeliveries 直接让邮件入队失败（覆盖通知器入队失败回执）。
type failingManualDeliveries struct{}

func (failingManualDeliveries) Enqueue(context.Context,
	mailer.EnqueueRequest) (mailer.EnqueueResult, error) {
	return mailer.EnqueueResult{}, errors.New("mail queue unavailable")
}

// seedNotifierTarget 插入一个带已验证邮箱的普通用户。
func seedNotifierTarget(t *testing.T, store *storagesqlite.Store, userID, username, email string,
	now time.Time) {
	t.Helper()
	ctx := context.Background()
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO users(id,username,username_normalized,
status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'active',0,1,1,?,?)`, userID, username, username,
		now.UnixMilli(), now.UnixMilli()); err != nil {
		t.Fatalf("插入用户: %v", err)
	}
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO user_emails(
user_id,email,email_normalized,verified_at_ms,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?)`, userID, email, email, now.UnixMilli(), now.UnixMilli(), now.UnixMilli()); err != nil {
		t.Fatalf("插入邮箱: %v", err)
	}
}

// newNotifierDeliveryService 构造不真实外发的可靠投递服务（真实 SQLite 投递记录）。
func newNotifierDeliveryService(t *testing.T, store *storagesqlite.Store, sender mailer.Sender,
	enqueuer mailer.Enqueuer, now time.Time) *mailer.DeliveryService {
	t.Helper()
	mailerStore, err := mailersqlite.New(store)
	if err != nil {
		t.Fatalf("投递存储: %v", err)
	}
	keyring, err := secrets.GenerateKeyring("Manual265", now)
	if err != nil {
		t.Fatalf("密钥环: %v", err)
	}
	sealer, err := secrets.NewSealer(keyring, nil)
	if err != nil {
		t.Fatalf("加密器: %v", err)
	}
	templates, err := mailer.DefaultTemplateSet()
	if err != nil {
		t.Fatalf("模板: %v", err)
	}
	from, err := mailer.ParseAddress("noreply@example.test")
	if err != nil {
		t.Fatalf("发件地址: %v", err)
	}
	delivery, err := mailer.NewDeliveryService(mailer.DeliveryOptions{
		Store: mailerStore, Sender: sender, Templates: templates, Sealer: sealer,
		Recorder: noopMailAudit{}, Enqueuer: enqueuer, From: from,
		MaxAttempts: 2, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("投递服务: %v", err)
	}
	return delivery
}

// TestManualRecoveryNotifierReceiptIdempotent 验证通知器不再丢弃 Enqueue 返回值（步骤
// 265）：回执含真实投递记录 ID 与稳定业务去重键，重复触发命中同一投递（Duplicate），
// 不产生第二封邮件；回执状态是 queued 而不是 sent。
func TestManualRecoveryNotifierReceiptIdempotent(t *testing.T) {
	ctx := context.Background()
	store := openMigratedStore(t)
	now := time.Date(2026, 11, 26, 5, 0, 0, 0, time.UTC)
	const target = "usr_00000000000000000000000000000077"
	const email = "receipt-target@example.test"
	seedNotifierTarget(t, store, target, "receipt-target", email, now)
	sender := &recordingMailSender{}
	enqueuer := &realManualEnqueuer{}
	delivery := newNotifierDeliveryService(t, store, sender, enqueuer, now)
	notifier := manualRecoveryNotifier{deliveries: delivery, store: store,
		appName: "测试登录", supportURL: "https://example.test/support"}
	notification := manualrecovery.Notification{
		Kind: manualrecovery.NotificationCompleted,
		// 生产是 mrr_ 前缀的申请编号；这里用等价长度的领域编号即可。
		RequestID: "mrr_00000000000000000000000000000065", TargetUserID: target,
		Operation: manualrecovery.OperationPasswordReset, OccurredAt: now,
	}
	expectedKey := manualrecovery.NotificationDedupKey(notification.RequestID, notification.Kind)

	first, err := notifier.NotifyWithReceipt(ctx, notification)
	if err != nil {
		t.Fatalf("首次通知入队: %v", err)
	}
	if first.State != manualrecovery.NotificationStateQueued {
		t.Fatalf("回执状态 = %q，期望 queued（不代表已送达）", first.State)
	}
	if !strings.HasPrefix(first.DeliveryID, "mdl_") {
		t.Fatalf("回执缺少真实投递记录 ID: %+v", first)
	}
	if first.DedupKey != expectedKey {
		t.Fatalf("回执去重键 = %q，期望 %q", first.DedupKey, expectedKey)
	}
	if first.Duplicate {
		t.Fatal("首次入队不应标记 Duplicate")
	}
	if len(enqueuer.requests) != 1 {
		t.Fatalf("投递任务数 = %d，期望 1", len(enqueuer.requests))
	}
	// 同一业务事件重复触发：幂等命中既有投递，不再创建任务/邮件。
	second, err := notifier.NotifyWithReceipt(ctx, notification)
	if err != nil {
		t.Fatalf("重复通知: %v", err)
	}
	if !second.Duplicate {
		t.Fatal("重复触发应命中去重键（Duplicate=true）")
	}
	if second.DeliveryID != first.DeliveryID {
		t.Fatalf("重复触发投递 ID 变化: %q != %q", second.DeliveryID, first.DeliveryID)
	}
	if len(enqueuer.requests) != 1 {
		t.Fatalf("重复触发产生了额外投递任务: %d", len(enqueuer.requests))
	}
	// 兼容旧 Notifier 路径也不重复入队。
	if err := notifier.Notify(ctx, notification); err != nil {
		t.Fatalf("Notify 兼容路径: %v", err)
	}
	if len(enqueuer.requests) != 1 {
		t.Fatalf("Notify 兼容路径产生了额外投递任务: %d", len(enqueuer.requests))
	}
	// 投递记录可按 ID 查询且与业务去重键绑定。
	system, err := mailer.SystemCaller("manual-recovery-test")
	if err != nil {
		t.Fatalf("系统调用者: %v", err)
	}
	record, err := delivery.Get(ctx, system, first.DeliveryID)
	if err != nil {
		t.Fatalf("读取投递记录: %v", err)
	}
	if record.IdempotencyKey != expectedKey || record.State != mailer.DeliveryQueued {
		t.Fatalf("投递记录异常: %+v", record)
	}
	if record.Recipient != email {
		t.Fatalf("投递收件人异常: %q", record.Recipient)
	}

	// 入队失败：返回 failed 回执与错误，调用方据此记录通知失败而不回滚业务。
	failing := manualRecoveryNotifier{deliveries: failingManualDeliveries{}, store: store,
		appName: "测试登录", supportURL: "https://example.test/support"}
	failedReceipt, notifyErr := failing.NotifyWithReceipt(ctx, notification)
	if notifyErr == nil {
		t.Fatal("入队失败应返回错误")
	}
	if failedReceipt.State != manualrecovery.NotificationStateFailed {
		t.Fatalf("入队失败回执状态 = %q，期望 failed", failedReceipt.State)
	}
	if failedReceipt.DedupKey != expectedKey {
		t.Fatalf("入队失败回执缺少业务去重键: %+v", failedReceipt)
	}

	// 投递任务入队失败（DeliveryService.Enqueue 内部失败分支）同样回执 failed。
	failingDelivery := newNotifierDeliveryService(t, store, sender, failingTaskEnqueuer{}, now)
	failingNotifier := manualRecoveryNotifier{deliveries: failingDelivery, store: store,
		appName: "测试登录", supportURL: "https://example.test/support"}
	other := notification
	other.RequestID = "mrr_00000000000000000000000000000066"
	failedReceipt, notifyErr = failingNotifier.NotifyWithReceipt(ctx, other)
	if notifyErr == nil || failedReceipt.State != manualrecovery.NotificationStateFailed {
		t.Fatalf("任务入队失败回执异常: receipt=%+v err=%v", failedReceipt, notifyErr)
	}
	if len(enqueuer.requests) != 1 {
		t.Fatalf("失败路径不应留下已入队任务: %d", len(enqueuer.requests))
	}
}

// TestManualRecoveryNotifierQueue 验证人工恢复完成/失败通知走可靠队列：入队内容
// 不含秘密、幂等键绑定请求实例、失败不回滚（由调用方语义承担）。
func TestManualRecoveryNotifierQueue(t *testing.T) {
	ctx := context.Background()
	store, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(
		filepath.Join(testutil.TempDir(t), "manual-notifier.db")))
	if err != nil {
		t.Fatalf("打开存储: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	list, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移: %v", err)
	}
	if _, err := store.Migrate(ctx, list); err != nil {
		t.Fatalf("执行迁移: %v", err)
	}
	now := time.Date(2026, 11, 23, 5, 0, 0, 0, time.UTC)
	target := "usr_00000000000000000000000000000077"
	const email = "recovery-target@example.test"
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO users(id,username,username_normalized,
status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'active',0,1,1,?,?)`, target, "recovery-target", "recovery-target",
		now.UnixMilli(), now.UnixMilli()); err != nil {
		t.Fatalf("插入用户: %v", err)
	}
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO user_emails(
user_id,email,email_normalized,verified_at_ms,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?)`, target, email, email, now.UnixMilli(), now.UnixMilli(), now.UnixMilli()); err != nil {
		t.Fatalf("插入邮箱: %v", err)
	}
	capture := &captureManualDeliveries{}
	notifier := manualRecoveryNotifier{deliveries: capture, store: store,
		appName: "测试登录", supportURL: "https://example.test/support"}
	notification := manualrecovery.Notification{
		Kind: manualrecovery.NotificationCompleted, RequestID: "rcv_00000000000000000000000000000001",
		TargetUserID: target, Operation: manualrecovery.OperationPasswordReset, OccurredAt: now,
	}
	if err := notifier.Notify(ctx, notification); err != nil {
		t.Fatalf("通知入队: %v", err)
	}
	requests := capture.snapshot()
	if len(requests) != 1 {
		t.Fatalf("入队数 = %d，期望 1", len(requests))
	}
	request := requests[0]
	if request.Kind != mailer.KindSecurityNotice || request.Data.Notice == nil {
		t.Fatalf("通知模板数据 = %+v", request.Data)
	}
	if request.Recipient != email {
		t.Errorf("收件人 = %q，期望已验证邮箱", request.Recipient)
	}
	if !strings.HasPrefix(request.IdempotencyKey, "manual-recovery-rcv_") ||
		len(request.IdempotencyKey) < 8 || len(request.IdempotencyKey) > 128 {
		t.Errorf("幂等键 = %q", request.IdempotencyKey)
	}
	if !strings.Contains(request.Data.Notice.Event, "人工恢复已完成") {
		t.Errorf("通知事件 = %q", request.Data.Notice.Event)
	}
	if strings.Contains(request.Data.Notice.Event, "密码") || strings.Contains(request.Data.Notice.Event, "token") {
		t.Errorf("通知事件不应含敏感信息: %q", request.Data.Notice.Event)
	}

	// 失败通知：事件文案区分，仍入队；入队失败返回错误（业务终态由调用方决定）。
	notification.Kind = manualrecovery.NotificationFailed
	notification.RequestID = "rcv_00000000000000000000000000000002"
	if err := notifier.Notify(ctx, notification); err != nil {
		t.Fatalf("失败通知入队: %v", err)
	}
	requests = capture.snapshot()
	if len(requests) != 2 || !strings.Contains(requests[1].Data.Notice.Event, "人工恢复未完成") {
		t.Fatalf("失败通知 = %+v", requests)
	}
	capture.err = errors.New("queue unavailable")
	if err := notifier.Notify(ctx, notification); err == nil {
		t.Fatal("入队失败应返回错误")
	}
}

// TestManualRecoveryNotifierQueueRealMail 验证人工恢复通知经可靠投递任务真实发送到
// 本地 EvernightMail，且 Mail 只收到 1 封、投递记录 succeeded（queued→delivered 证据）。
func TestManualRecoveryNotifierQueueRealMail(t *testing.T) {
	ctx := context.Background()
	instance := mailtest.Start(t, mailtest.Options{Required: true, SMTPAuthNone: true})
	store, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(
		filepath.Join(testutil.TempDir(t), "manual-notifier-real.db")))
	if err != nil {
		t.Fatalf("打开存储: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	list, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移: %v", err)
	}
	if _, err := store.Migrate(ctx, list); err != nil {
		t.Fatalf("执行迁移: %v", err)
	}
	now := time.Date(2026, 11, 23, 5, 0, 0, 0, time.UTC)
	target := "usr_00000000000000000000000000000088"
	const email = "recovery-real@example.test"
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO users(id,username,username_normalized,
status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'active',0,1,1,?,?)`, target, "recovery-real", "recovery-real",
		now.UnixMilli(), now.UnixMilli()); err != nil {
		t.Fatalf("插入用户: %v", err)
	}
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO user_emails(
user_id,email,email_normalized,verified_at_ms,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?)`, target, email, email, now.UnixMilli(), now.UnixMilli(), now.UnixMilli()); err != nil {
		t.Fatalf("插入邮箱: %v", err)
	}
	sender, err := mailer.NewSMTPSender(mailer.SMTPOptions{
		Addr: instance.Addr().String(), TLSMode: mailer.TLSModeNone, AllowPlaintextLocal: true,
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("SMTP 发送器: %v", err)
	}
	mailerStore, err := mailersqlite.New(store)
	if err != nil {
		t.Fatalf("投递存储: %v", err)
	}
	keyring, err := secrets.GenerateKeyring("Manual197", now)
	if err != nil {
		t.Fatalf("密钥环: %v", err)
	}
	sealer, err := secrets.NewSealer(keyring, nil)
	if err != nil {
		t.Fatalf("加密器: %v", err)
	}
	templates, err := mailer.DefaultTemplateSet()
	if err != nil {
		t.Fatalf("模板: %v", err)
	}
	from, err := mailer.ParseAddress("noreply@example.test")
	if err != nil {
		t.Fatalf("发件地址: %v", err)
	}
	enqueuer := &realManualEnqueuer{}
	delivery, err := mailer.NewDeliveryService(mailer.DeliveryOptions{
		Store: mailerStore, Sender: sender, Templates: templates, Sealer: sealer,
		Recorder: noopMailAudit{}, Enqueuer: enqueuer, From: from,
		MaxAttempts: 2, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("投递服务: %v", err)
	}
	notifier := manualRecoveryNotifier{deliveries: delivery, store: store,
		appName: "测试登录", supportURL: "https://example.test/support"}
	if err := notifier.Notify(ctx, manualrecovery.Notification{
		Kind: manualrecovery.NotificationCompleted, RequestID: "rcv_00000000000000000000000000000011",
		TargetUserID: target, Operation: manualrecovery.OperationPasswordReset, OccurredAt: now,
	}); err != nil {
		t.Fatalf("通知入队: %v", err)
	}
	if len(enqueuer.requests) != 1 {
		t.Fatalf("任务入队数 = %d，期望 1", len(enqueuer.requests))
	}
	request := enqueuer.requests[0]
	if err := delivery.Handler(ctx, task.Job{ID: "manual-real-job", Kind: request.Kind,
		Payload: request.Payload, Initiator: request.Actor, Attempt: 1,
		MaxAttempts: request.MaxAttempts}); err != nil {
		t.Fatalf("通知投递: %v", err)
	}
	var messages []mailtest.Message
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		messages = instance.Snapshot(mailtest.Query{To: email})
		if len(messages) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(messages) != 1 {
		t.Fatalf("Mail 通知数 = %d，期望 1", len(messages))
	}
	records, err := mailerStore.List(ctx, mailer.ListQuery{Recipient: email, Limit: 10})
	if err != nil || len(records) != 1 || records[0].State != mailer.DeliverySucceeded {
		t.Fatalf("投递记录 = %+v, err = %v", records, err)
	}
}
