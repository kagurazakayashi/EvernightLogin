// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package passwordreset_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	mailersqlite "github.com/kagurazakayashi/EvernightLogin/internal/mailer/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailtest"
	"github.com/kagurazakayashi/EvernightLogin/internal/passwordreset"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// decodePlainText 解码测试 Mail 的 text/plain base64 正文（仅测试辅助）。
func decodePlainText(t *testing.T, raw []byte) []byte {
	t.Helper()
	parts := strings.SplitN(string(raw), "\r\n\r\n", 2)
	if len(parts) != 2 {
		return raw
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(strings.TrimSpace(parts[1]), "\r\n", ""))
	if err != nil {
		return raw
	}
	return decoded
}

// realTaskEnqueuer 记录可靠投递任务入队请求，供测试手动驱动 Handler。
type realTaskEnqueuer struct {
	requests []task.EnqueueRequest
}

func (e *realTaskEnqueuer) Enqueue(_ context.Context, request task.EnqueueRequest) (task.Job, error) {
	e.requests = append(e.requests, request)
	return task.Job{ID: fmt.Sprintf("real-197-job-%d", len(e.requests)), Kind: request.Kind,
		Payload: request.Payload, Initiator: request.Actor, Attempt: 1,
		MaxAttempts: request.MaxAttempts}, nil
}

// jobFromEnqueue 把入队请求包装成可交给投递 Handler 的任务。
func jobFromEnqueue(request task.EnqueueRequest, attempt int) task.Job {
	return task.Job{ID: "real-197-job", Kind: request.Kind, Payload: request.Payload,
		Initiator: request.Actor, Attempt: attempt, MaxAttempts: request.MaxAttempts}
}

// TestQueueResetRealMail 验证找回邮件/安全告知经可靠投递任务真实发送到本地
// EvernightMail：queued→succeeded、Mail 收到两封（找回+告知）、投递记录可查。
func TestQueueResetRealMail(t *testing.T) {
	env := newTestEnv(t, nil)
	env.now = time.Now().UTC()

	// 与生产装配同形：mailersqlite + 真实 SMTP Sender + 真实模板/加密器 + 任务入队。
	sender, err := mailer.NewSMTPSender(mailer.SMTPOptions{
		Addr: env.mail.Addr().String(), TLSMode: mailer.TLSModeNone, AllowPlaintextLocal: true,
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("SMTP 发送器: %v", err)
	}
	mailerStore, err := mailersqlite.New(env.raw)
	if err != nil {
		t.Fatalf("投递存储: %v", err)
	}
	sealer, err := secrets.NewSealer(env.keyring, nil)
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
	enqueuer := &realTaskEnqueuer{}
	delivery, err := mailer.NewDeliveryService(mailer.DeliveryOptions{
		Store: mailerStore, Sender: sender, Templates: templates, Sealer: sealer,
		Recorder: env.audit, Enqueuer: enqueuer, From: from,
		MaxAttempts: 3, Now: func() time.Time { return env.now },
	})
	if err != nil {
		t.Fatalf("投递服务: %v", err)
	}
	service, err := passwordreset.New(passwordreset.Options{
		Store: env.resetStore, Audit: env.audit, Credentials: env.creds,
		Passwords: env.pass, Sessions: env.sess, Mailer: sender, Deliveries: delivery,
		Templates: templates, FromAddress: "security@example.com", AppName: "登录服务",
		SupportURL:   "https://example.com/support",
		ResetURLBase: "https://example.com/reset",
		Now:          func() time.Time { return env.now },
	})
	if err != nil {
		t.Fatalf("找回服务: %v", err)
	}

	if _, err := service.SendResetForSupport(env.ctx, passwordreset.SupportResetRequest{
		TargetUserID: userID, RequestID: "req-real-queue-reset",
	}); err != nil {
		t.Fatalf("客服发起找回: %v", err)
	}
	if len(enqueuer.requests) != 1 {
		t.Fatalf("找回任务入队数 = %d，期望 1", len(enqueuer.requests))
	}
	if err := delivery.Handler(env.ctx, jobFromEnqueue(enqueuer.requests[0], 1)); err != nil {
		t.Fatalf("找回任务投递: %v", err)
	}
	var messages []mailtest.Message
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		messages = env.mail.Snapshot(mailtest.Query{To: "alice@example.com"})
		if len(messages) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(messages) == 0 {
		t.Fatal("等待找回邮件超时")
	}
	records, err := mailerStore.List(env.ctx, mailer.ListQuery{Recipient: "alice@example.com", Limit: 10})
	if err != nil || len(records) != 1 || records[0].State != mailer.DeliverySucceeded {
		t.Fatalf("找回投递记录 = %+v, err = %v", records, err)
	}
	token := tokenPattern.FindSubmatch(decodePlainText(t, messages[0].Data))
	if len(token) != 2 {
		t.Fatalf("找回邮件缺少 token: %q", string(messages[0].Data))
	}
	if _, err := service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: string(token[1]), NewPassword: "RealQueue!9876", RequestID: "req-real-queue-complete",
	}); err != nil {
		t.Fatalf("完成找回: %v", err)
	}
	if len(enqueuer.requests) != 2 {
		t.Fatalf("告知任务入队数 = %d，期望 2", len(enqueuer.requests))
	}
	if err := delivery.Handler(env.ctx, jobFromEnqueue(enqueuer.requests[1], 1)); err != nil {
		t.Fatalf("告知任务投递: %v", err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		records, err = mailerStore.List(env.ctx, mailer.ListQuery{Recipient: "alice@example.com", Limit: 10})
		if err == nil && len(records) >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil || len(records) != 2 {
		t.Fatalf("投递记录数 = %d, err = %v", len(records), err)
	}
	for _, record := range records {
		if record.State != mailer.DeliverySucceeded {
			t.Fatalf("投递记录未成功: %+v", record)
		}
	}
}
