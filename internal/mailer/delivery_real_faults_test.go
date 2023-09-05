// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package mailer_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	mailersqlite "github.com/kagurazakayashi/EvernightLogin/internal/mailer/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailtest"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// realFaultEnv 是真实 Mail 故障规则下的投递服务夹具（步骤 197：S3/S5 证据）。
type realFaultEnv struct {
	service  *mailer.DeliveryService
	store    mailer.Store
	enqueuer *fakeEnqueuer
	mail     *mailtest.Instance
}

func newRealFaultEnv(t *testing.T, faultsYAML string) *realFaultEnv {
	t.Helper()
	ctx := context.Background()
	instance := mailtest.Start(t, mailtest.Options{
		Required: true, SMTPAuthNone: true, FaultsYAML: faultsYAML,
	})
	storage, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(
		filepath.Join(testutil.TempDir(t), "mailer-real-fault.db")))
	if err != nil {
		t.Fatalf("打开存储: %v", err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	list, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移: %v", err)
	}
	if _, err := storage.Migrate(ctx, list); err != nil {
		t.Fatalf("执行迁移: %v", err)
	}
	store, err := mailersqlite.New(storage)
	if err != nil {
		t.Fatalf("投递存储: %v", err)
	}
	keyring, err := secrets.GenerateKeyring("Mailer197", deliveryStart)
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
	sender, err := mailer.NewSMTPSender(mailer.SMTPOptions{
		Addr: instance.Addr().String(), TLSMode: mailer.TLSModeNone, AllowPlaintextLocal: true,
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("SMTP 发送器: %v", err)
	}
	enqueuer := &fakeEnqueuer{}
	service, err := mailer.NewDeliveryService(mailer.DeliveryOptions{
		Store: store, Sender: sender, Templates: templates, Sealer: sealer,
		Recorder: &fakeAudit{}, Enqueuer: enqueuer, Authorizer: &fakeAuthorizer{allow: true},
		From: from, MaxAttempts: 3, Now: func() time.Time { return deliveryStart },
	})
	if err != nil {
		t.Fatalf("投递服务: %v", err)
	}
	return &realFaultEnv{service: service, store: store, enqueuer: enqueuer, mail: instance}
}

func (e *realFaultEnv) enqueue(t *testing.T, key, recipient string) {
	t.Helper()
	request := verificationRequest(key)
	request.Recipient = recipient
	if _, err := e.service.Enqueue(context.Background(), request); err != nil {
		t.Fatalf("入队 %s: %v", recipient, err)
	}
}

func (e *realFaultEnv) job(attempt int) task.Job {
	request := e.enqueuer.requests[len(e.enqueuer.requests)-1]
	return task.Job{ID: "real-fault-job", Kind: request.Kind, Payload: request.Payload,
		Initiator: request.Actor, Attempt: attempt, MaxAttempts: request.MaxAttempts}
}

func (e *realFaultEnv) record(t *testing.T, recipient string) mailer.Record {
	t.Helper()
	records, err := e.store.List(context.Background(), mailer.ListQuery{Recipient: recipient, Limit: 10})
	if err != nil {
		t.Fatalf("列出投递: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("收件人 %s 的投递记录数 = %d，期望 1", recipient, len(records))
	}
	return records[0]
}

const faultRules197 = `  enabled: true
  rules:
    - id: rcpt-retry-197
      enabled: true
      kind: recipient_reject
      protocol: smtp
      phase: rcpt
      scope: {addresses: ["retry@*"]}
      action: {code: 451, enhanced_status: "4.2.0", message: "Try again later"}
      limits: {max_hits: 1, ttl: 10m}
    - id: rcpt-block-197
      enabled: true
      kind: recipient_reject
      protocol: smtp
      phase: rcpt
      scope: {addresses: ["blocked@*"]}
      action: {code: 550, enhanced_status: "5.1.1", message: "Recipient address rejected"}
      limits: {max_hits: 1, ttl: 10m}
    - id: duplicate-197
      enabled: true
      kind: duplicate
      protocol: smtp
      phase: data_end
      scope: {addresses: ["dup@*"]}
      action: {duplicates: 1, after_accept: true}
      limits: {max_hits: 1, ttl: 10m}
`

// TestRealMailFaultsQueue 验证真实 Mail 故障规则下的队列行为：
// 451 可重试 → 第二次成功；550 永久失败 → 终态 failed；duplicate 规则产生物理副本，
// Login 仍只有 1 条投递记录且重复入队幂等。
func TestRealMailFaultsQueue(t *testing.T) {
	env := newRealFaultEnv(t, faultRules197)
	ctx := context.Background()

	// 451 可重试：首次 Handler 失败（记录仍 queued/attempts=1），第二次成功。
	env.enqueue(t, "verify-retry-197-00000001", "retry@example.test")
	if err := env.service.Handler(ctx, env.job(1)); err == nil {
		t.Fatal("451 首次投递应返回可重试错误")
	}
	record := env.record(t, "retry@example.test")
	if record.State != mailer.DeliveryQueued || record.Attempts != 1 {
		t.Fatalf("451 首次后状态 = %+v，期望 queued/attempts=1", record)
	}
	if err := env.service.Handler(ctx, env.job(2)); err != nil {
		t.Fatalf("451 第二次投递应成功: %v", err)
	}
	record = env.record(t, "retry@example.test")
	if record.State != mailer.DeliverySucceeded || record.Attempts != 2 {
		t.Fatalf("451 重试后状态 = %+v，期望 succeeded/attempts=2", record)
	}
	if messages := env.mail.Snapshot(mailtest.Query{To: "retry@example.test"}); len(messages) != 1 {
		t.Fatalf("451 重试后 Mail 邮件数 = %d，期望 1（不重复投递）", len(messages))
	}

	// 550 永久拒绝：首次即终态 failed，Mail 无邮件。
	env.enqueue(t, "verify-blocked-197-000001", "blocked@example.test")
	if err := env.service.Handler(ctx, env.job(1)); err == nil {
		t.Fatal("550 应返回错误")
	}
	record = env.record(t, "blocked@example.test")
	if record.State != mailer.DeliveryFailed || record.Attempts != 1 {
		t.Fatalf("550 后状态 = %+v，期望 failed/attempts=1", record)
	}
	if messages := env.mail.Snapshot(mailtest.Query{To: "blocked@example.test"}); len(messages) != 0 {
		t.Fatalf("永久拒绝不应产生邮件，得到 %d", len(messages))
	}

	// duplicate 故障：Mail 产生原邮件 + 1 个物理副本，但 Login 只有 1 条 succeeded 记录；
	// 重复入队幂等，且再次 Handler 不重复发送。
	env.enqueue(t, "verify-duplicate-197-00001", "dup@example.test")
	if err := env.service.Handler(ctx, env.job(1)); err != nil {
		t.Fatalf("duplicate 场景投递: %v", err)
	}
	record = env.record(t, "dup@example.test")
	if record.State != mailer.DeliverySucceeded {
		t.Fatalf("duplicate 场景状态 = %+v，期望 succeeded", record)
	}
	messages := env.mail.Snapshot(mailtest.Query{To: "dup@example.test"})
	if len(messages) != 2 {
		t.Fatalf("duplicate 规则应产生 2 封（原+副本），得到 %d", len(messages))
	}
	duplicate, err := env.service.Enqueue(ctx, func() mailer.EnqueueRequest {
		request := verificationRequest("verify-duplicate-197-00001")
		request.Recipient = "dup@example.test"
		return request
	}())
	if err != nil || !duplicate.Duplicate {
		t.Fatalf("重复入队应幂等: duplicate=%+v err=%v", duplicate, err)
	}
	if err := env.service.Handler(ctx, env.job(1)); err != nil {
		t.Fatalf("终态重复 Handler 应幂等成功: %v", err)
	}
	if after := env.mail.Snapshot(mailtest.Query{To: "dup@example.test"}); len(after) != 2 {
		t.Fatalf("重复入队/Handler 不应再发送，Mail 数 = %d", len(after))
	}
}
