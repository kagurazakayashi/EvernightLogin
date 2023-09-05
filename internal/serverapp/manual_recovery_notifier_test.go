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
