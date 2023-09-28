// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package reauth_test

import (
	"context"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	mailersqlite "github.com/kagurazakayashi/EvernightLogin/internal/mailer/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailtest"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// realReauthEnqueuer 记录安全告知任务，供测试驱动 Handler。
type realReauthEnqueuer struct {
	requests []task.EnqueueRequest
}

func (e *realReauthEnqueuer) Enqueue(_ context.Context, request task.EnqueueRequest) (task.Job, error) {
	e.requests = append(e.requests, request)
	return task.Job{ID: "reauth-real-job", Kind: request.Kind, Payload: request.Payload,
		Initiator: request.Actor, Attempt: 1, MaxAttempts: request.MaxAttempts}, nil
}

// noopReauthMailAudit 仅满足 mailer.AuditRecorder；本测试不校验投递审计。
type noopReauthMailAudit struct{}

func (noopReauthMailAudit) Record(context.Context, audit.Event) error { return nil }

// TestNotifyOutcomeQueueRealMail 验证敏感操作告知经可靠投递任务真实发送到本地
// EvernightMail：通知记录 queued、Mail 收到 1 封、投递记录 succeeded（queued→delivered）。
func TestNotifyOutcomeQueueRealMail(t *testing.T) {
	var instance *mailtest.Instance
	var delivery *mailer.DeliveryService
	var enqueuer *realReauthEnqueuer
	// 与生产一致：reauth 存储与 mailer 投递记录共享同一数据库，通知读取才能按
	// delivery_id / 稳定去重键投影投递终态。
	env := newTestEnvWithHooks(t, nil, func(testEnv *testEnv, options *reauth.Options) {
		instance = mailtest.Start(t, mailtest.Options{Required: true, SMTPAuthNone: true})
		mailerStore, err := mailersqlite.New(testEnv.storage)
		if err != nil {
			t.Fatalf("投递存储: %v", err)
		}
		sender, err := mailer.NewSMTPSender(mailer.SMTPOptions{
			Addr: instance.Addr().String(), TLSMode: mailer.TLSModeNone, AllowPlaintextLocal: true,
			Timeout: 5 * time.Second,
		})
		if err != nil {
			t.Fatalf("SMTP 发送器: %v", err)
		}
		keyring, err := secrets.GenerateKeyring("Reauth197", time.Now())
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
		from, err := mailer.ParseAddress("security@example.com")
		if err != nil {
			t.Fatalf("发件地址: %v", err)
		}
		enqueuer = &realReauthEnqueuer{}
		delivery, err = mailer.NewDeliveryService(mailer.DeliveryOptions{
			Store: mailerStore, Sender: sender, Templates: templates, Sealer: sealer,
			Recorder: noopReauthMailAudit{}, Enqueuer: enqueuer, From: from,
			MaxAttempts: 2, Now: func() time.Time { return time.Now().UTC() },
		})
		if err != nil {
			t.Fatalf("投递服务: %v", err)
		}
		options.Deliveries = delivery
	})
	env.now = time.Now().UTC()
	alice := env.userCaller(t, normalUserID)
	result, err := env.service.Authorize(reauth.WithSignals(env.ctx, freshSignals(env.now)), alice,
		request("password.change"))
	if err != nil {
		t.Fatalf("授权: %v", err)
	}
	if err := env.service.NotifyOutcome(env.ctx, result, reauth.OutcomeSuccess); err != nil {
		t.Fatalf("队列告知: %v", err)
	}
	if len(enqueuer.requests) != 1 {
		t.Fatalf("告知任务入队数 = %d，期望 1", len(enqueuer.requests))
	}
	records, err := env.service.Notifications(env.ctx, alice, normalUserID, 10)
	if err != nil || len(records) != 1 || records[0].State != reauth.NotificationQueued {
		t.Fatalf("告知记录 = %+v, err = %v", records, err)
	}
	if records[0].DeliveryID == "" || records[0].DeliveryState != mailer.DeliveryQueued {
		t.Fatalf("告知主记录未关联可靠投递记录: %+v", records[0])
	}
	request := enqueuer.requests[0]
	if err := delivery.Handler(env.ctx, task.Job{ID: "reauth-real-job", Kind: request.Kind,
		Payload: request.Payload, Initiator: request.Actor, Attempt: 1,
		MaxAttempts: request.MaxAttempts}); err != nil {
		t.Fatalf("告知投递: %v", err)
	}
	var messages []mailtest.Message
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		messages = instance.Snapshot(mailtest.Query{To: "alice@example.com"})
		if len(messages) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(messages) != 1 {
		t.Fatalf("Mail 告知数 = %d，期望 1", len(messages))
	}
	// 投递任务终态写回后，通知读取必须投影投递记录当前状态：succeeded 只表示
	// 发送后端已接受（SMTP 接受），主记录本身仍保持 queued（入队受理），不能冒充 sent。
	records, err = env.service.Notifications(env.ctx, alice, normalUserID, 10)
	if err != nil || len(records) != 1 {
		t.Fatalf("投递后告知记录 = %+v, err = %v", records, err)
	}
	if records[0].State != reauth.NotificationQueued {
		t.Errorf("主记录状态 = %q，期望仍为 queued（入队受理）", records[0].State)
	}
	if records[0].DeliveryState != mailer.DeliverySucceeded {
		t.Errorf("投递状态投影 = %q，期望 succeeded（SMTP 接受）", records[0].DeliveryState)
	}
}
