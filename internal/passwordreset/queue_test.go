// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package passwordreset_test

import (
	"context"
	"errors"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	"github.com/kagurazakayashi/EvernightLogin/internal/passwordreset"
)

// captureDeliveries 捕获可靠投递入队请求；可注入错误模拟入队失败。
type captureDeliveries struct {
	mu       sync.Mutex
	requests []mailer.EnqueueRequest
	err      error
}

func (c *captureDeliveries) Enqueue(_ context.Context, request mailer.EnqueueRequest) (mailer.EnqueueResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return mailer.EnqueueResult{}, c.err
	}
	c.requests = append(c.requests, request)
	return mailer.EnqueueResult{}, nil
}

func (c *captureDeliveries) snapshot() []mailer.EnqueueRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]mailer.EnqueueRequest(nil), c.requests...)
}

// TestQueueResetMailAndNotice 验证找回邮件/安全告知改走可靠队列：幂等键绑定业务
// 实例、模板数据含一次性入口、enqueue 成功后不再直接发送；完成找回后发送告知。
func TestQueueResetMailAndNotice(t *testing.T) {
	capture := &captureDeliveries{}
	env := newTestEnv(t, func(options *passwordreset.Options) {
		options.Deliveries = capture
	})
	env.now = time.Now().UTC()

	result, err := env.service.SendResetForSupport(env.ctx, passwordreset.SupportResetRequest{
		TargetUserID: userID, RequestID: "req-queue-reset",
	})
	if err != nil || !result.Delivered {
		t.Fatalf("客服发起找回: result=%+v err=%v", result, err)
	}
	requests := capture.snapshot()
	if len(requests) != 1 {
		t.Fatalf("找回邮件入队数 = %d，期望 1", len(requests))
	}
	resetRequest := requests[0]
	if resetRequest.Kind != mailer.KindPasswordReset {
		t.Errorf("找回邮件 Kind = %q", resetRequest.Kind)
	}
	if len(resetRequest.IdempotencyKey) < 8 || len(resetRequest.IdempotencyKey) > 128 ||
		!regexp.MustCompile(`^password-reset-prq_[0-9a-f]{32}$`).MatchString(resetRequest.IdempotencyKey) {
		t.Errorf("找回邮件幂等键 = %q", resetRequest.IdempotencyKey)
	}
	if resetRequest.Recipient != "alice@example.com" {
		t.Errorf("找回邮件收件人 = %q", resetRequest.Recipient)
	}
	if resetRequest.Data.PasswordReset == nil || resetRequest.Data.PasswordReset.ResetURL == "" {
		t.Fatalf("找回邮件模板数据缺少入口: %+v", resetRequest.Data)
	}
	if env.mailSnapshot() != nil && len(env.mailSnapshot()) != 0 {
		t.Errorf("队列路径不应直接发送邮件，Mail 捕获数 = %d", len(env.mailSnapshot()))
	}

	// 从入队的模板数据取一次性 token，完成找回；随后应产生安全告知入队。
	token := tokenPattern.FindStringSubmatch(resetRequest.Data.PasswordReset.ResetURL)
	if len(token) != 2 {
		t.Fatalf("找回入口缺少 token: %q", resetRequest.Data.PasswordReset.ResetURL)
	}
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: token[1], NewPassword: "QueueReset!9876", RequestID: "req-queue-complete",
	}); err != nil {
		t.Fatalf("完成找回: %v", err)
	}
	requests = capture.snapshot()
	if len(requests) != 2 {
		t.Fatalf("入队总数 = %d，期望 2", len(requests))
	}
	notice := requests[1]
	if notice.Kind != mailer.KindSecurityNotice || notice.Data.Notice == nil {
		t.Fatalf("告知入队内容 = %+v", notice)
	}
	if len(notice.IdempotencyKey) < 8 || len(notice.IdempotencyKey) > 128 ||
		!regexp.MustCompile(`^password-reset-notice-prq_[0-9a-f]{32}$`).MatchString(notice.IdempotencyKey) {
		t.Errorf("告知幂等键 = %q", notice.IdempotencyKey)
	}
	if notice.Recipient != "alice@example.com" {
		t.Errorf("告知收件人 = %q", notice.Recipient)
	}
}

// TestQueueResetMailEnqueueFailure 验证入队失败与直接发送失败同语义：不提示已发送。
func TestQueueResetMailEnqueueFailure(t *testing.T) {
	capture := &captureDeliveries{err: errors.New("queue unavailable")}
	env := newTestEnv(t, func(options *passwordreset.Options) {
		options.Deliveries = capture
	})
	env.now = time.Now().UTC()

	if _, err := env.service.SendResetForSupport(env.ctx, passwordreset.SupportResetRequest{
		TargetUserID: userID, RequestID: "req-queue-fail",
	}); !errors.Is(err, passwordreset.ErrMailFailed) {
		t.Fatalf("入队失败错误 = %v，期望 ErrMailFailed", err)
	}
	if count := env.count(
		`SELECT COUNT(*) FROM audit_events WHERE action='password.reset_requested' AND reason_code='mail_failed'`); count != 1 {
		t.Errorf("找回入队失败审计数 = %d，期望 1", count)
	}
}

// TestResetMailFallbackSender 验证 Deliveries=nil 时保持直接 Sender（嵌入/单测兼容）。
func TestResetMailFallbackSender(t *testing.T) {
	env := newTestEnv(t, nil)
	env.now = time.Now().UTC()
	if _, err := env.service.SendResetForSupport(env.ctx, passwordreset.SupportResetRequest{
		TargetUserID: userID, RequestID: "req-fallback",
	}); err != nil {
		t.Fatalf("回退直接发送: %v", err)
	}
	if len(env.mailSnapshot()) == 0 {
		t.Error("Deliveries=nil 时应直接发送并由 Mail 捕获")
	}
}
