// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package reauth_test

import (
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	mailersqlite "github.com/kagurazakayashi/EvernightLogin/internal/mailer/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailtest"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
)

// faultRules210 是本地 EvernightMail 的真实 SMTP 故障规则（步骤 210 复用步骤 197
// 的故障注入能力）：retry@* 首次 451（可重试），blocked@* 永久 550。
const faultRules210 = `  enabled: true
  rules:
    - id: reauth-retry-210
      enabled: true
      kind: recipient_reject
      protocol: smtp
      phase: rcpt
      scope: {addresses: ["retry@*"]}
      action: {code: 451, enhanced_status: "4.2.0", message: "Try again later"}
      limits: {max_hits: 1, ttl: 10m}
    - id: reauth-block-210
      enabled: true
      kind: recipient_reject
      protocol: smtp
      phase: rcpt
      scope: {addresses: ["blocked@*"]}
      action: {code: 550, enhanced_status: "5.1.1", message: "Recipient address rejected"}
      limits: {max_hits: 1, ttl: 10m}
`

// TestNotificationRealMailFaultsProjection 用真实本地 Mail 故障规则验证安全告知
// 关联投递终态：有限失败（451）后重试成功、永久失败（550）保持失败；两者都通过
// 通知读取投影真实投递状态，不得把失败/排队显示为成功。
func TestNotificationRealMailFaultsProjection(t *testing.T) {
	var instance *mailtest.Instance
	var delivery *mailer.DeliveryService
	var enqueuer *testTaskEnqueuer
	env := newTestEnvWithHooks(t, nil, func(testEnv *testEnv, options *reauth.Options) {
		instance = mailtest.Start(t, mailtest.Options{
			Required: true, SMTPAuthNone: true, FaultsYAML: faultRules210,
		})
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
		keyring, err := secrets.GenerateKeyring("Reauth210", time.Now())
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
		enqueuer = &testTaskEnqueuer{}
		delivery, err = mailer.NewDeliveryService(mailer.DeliveryOptions{
			Store: mailerStore, Sender: sender, Templates: templates, Sealer: sealer,
			Recorder: noopReauthMailAudit{}, Enqueuer: enqueuer, From: from,
			MaxAttempts: 3, Now: func() time.Time { return time.Now().UTC() },
		})
		if err != nil {
			t.Fatalf("投递服务: %v", err)
		}
		options.Deliveries = delivery
	})
	env.now = time.Now().UTC()

	// 有限失败后成功：retry@ 首次 451（投递仍 queued，可重试），第二次成功。
	retryUserID := "usr_00000000000000000000000000000004"
	env.seedUser(retryUserID, "retryuser", false)
	env.seedEmail(retryUserID, "retry@example.test")
	retryCaller := env.userCaller(t, retryUserID)
	result, err := env.service.Authorize(reauth.WithSignals(env.ctx, freshSignals(env.now)),
		retryCaller, request("password.change"))
	if err != nil {
		t.Fatalf("授权(retry): %v", err)
	}
	if err := env.service.NotifyOutcome(env.ctx, result, reauth.OutcomeSuccess); err != nil {
		t.Fatalf("告知(retry): %v", err)
	}
	job, ok := enqueuer.lastJob()
	if !ok {
		t.Fatal("缺少投递任务(retry)")
	}
	if err := delivery.Handler(env.ctx, job); err == nil {
		t.Fatal("451 首次投递应返回可重试错误")
	}
	records, err := env.service.Notifications(env.ctx, retryCaller, retryUserID, 10)
	if err != nil || len(records) != 1 {
		t.Fatalf("451 后告知记录 = %+v, err = %v", records, err)
	}
	if records[0].DeliveryState != mailer.DeliveryQueued {
		t.Fatalf("451 后投递状态投影 = %q，期望 queued（可重试，不是成功）", records[0].DeliveryState)
	}
	// 第二次尝试（任务层重试语义：Attempt=2）应成功。
	retryJob := job
	retryJob.Attempt = 2
	if err := delivery.Handler(env.ctx, retryJob); err != nil {
		t.Fatalf("451 重试应成功: %v", err)
	}
	records, err = env.service.Notifications(env.ctx, retryCaller, retryUserID, 10)
	if err != nil || len(records) != 1 || records[0].DeliveryState != mailer.DeliverySucceeded {
		t.Fatalf("重试成功后告知记录 = %+v, err = %v", records, err)
	}
	if messages := instance.Snapshot(mailtest.Query{To: "retry@example.test"}); len(messages) != 1 {
		t.Fatalf("451 重试后 Mail 邮件数 = %d，期望 1", len(messages))
	}

	// 永久失败：blocked@ 550 首次即终态 failed；Mail 无邮件；通知投影为失败。
	blockedUserID := "usr_00000000000000000000000000000005"
	env.seedUser(blockedUserID, "blockeduser", false)
	env.seedEmail(blockedUserID, "blocked@example.test")
	blockedCaller := env.userCaller(t, blockedUserID)
	blockedResult, err := env.service.Authorize(reauth.WithSignals(env.ctx, freshSignals(env.now)),
		blockedCaller, request("password.change"))
	if err != nil {
		t.Fatalf("授权(blocked): %v", err)
	}
	if err := env.service.NotifyOutcome(env.ctx, blockedResult, reauth.OutcomeSuccess); err != nil {
		t.Fatalf("告知(blocked): %v", err)
	}
	blockedJob, ok := enqueuer.lastJob()
	if !ok {
		t.Fatal("缺少投递任务(blocked)")
	}
	if err := delivery.Handler(env.ctx, blockedJob); err == nil {
		t.Fatal("550 应返回永久失败错误")
	}
	records, err = env.service.Notifications(env.ctx, blockedCaller, blockedUserID, 10)
	if err != nil || len(records) != 1 {
		t.Fatalf("550 后告知记录 = %+v, err = %v", records, err)
	}
	if records[0].DeliveryState != mailer.DeliveryFailed {
		t.Fatalf("550 后投递状态投影 = %q，期望 failed", records[0].DeliveryState)
	}
	if records[0].DeliveryErrorCode == "" {
		t.Errorf("永久失败缺少稳定错误码: %+v", records[0])
	}
	if messages := instance.Snapshot(mailtest.Query{To: "blocked@example.test"}); len(messages) != 0 {
		t.Fatalf("550 永久拒绝不应产生邮件，得到 %d", len(messages))
	}
}
