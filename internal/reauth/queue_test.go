// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package reauth_test

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
)

// captureDeliveries 捕获安全告知入队请求；可注入错误；按幂等键模拟 mailer 的
// 幂等入队（同一键返回同一投递记录与 Duplicate=true）。
type captureDeliveries struct {
	mu       sync.Mutex
	requests []mailer.EnqueueRequest
	err      error
	nextID   int
	byKey    map[string]string
}

func (c *captureDeliveries) Enqueue(_ context.Context, request mailer.EnqueueRequest) (mailer.EnqueueResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return mailer.EnqueueResult{}, c.err
	}
	c.requests = append(c.requests, request)
	if c.byKey == nil {
		c.byKey = map[string]string{}
	}
	if existing, ok := c.byKey[request.IdempotencyKey]; ok {
		return mailer.EnqueueResult{Record: mailer.Record{ID: existing}, Duplicate: true}, nil
	}
	c.nextID++
	deliveryID := fmt.Sprintf("mdl_fake_%032d", c.nextID)
	c.byKey[request.IdempotencyKey] = deliveryID
	return mailer.EnqueueResult{Record: mailer.Record{ID: deliveryID}}, nil
}

func (c *captureDeliveries) snapshot() []mailer.EnqueueRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]mailer.EnqueueRequest(nil), c.requests...)
}

// TestNotifyOutcomeQueue 验证安全告知走可靠队列：queued 状态、幂等键、模板数据、
// 入队失败不改变业务结果；NotificationRequired=false 时不入队。
func TestNotifyOutcomeQueue(t *testing.T) {
	capture := &captureDeliveries{}
	env := newTestEnv(t, func(options *reauth.Options) {
		options.Deliveries = capture
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
	if env.sentCount() != 0 {
		t.Errorf("队列路径不应直接发送邮件，发送数 = %d", env.sentCount())
	}
	requests := capture.snapshot()
	if len(requests) != 1 {
		t.Fatalf("入队数 = %d，期望 1", len(requests))
	}
	request := requests[0]
	if request.Kind != mailer.KindSecurityNotice || request.Data.Notice == nil {
		t.Fatalf("告知入队内容 = %+v", request)
	}
	if request.Recipient != "alice@example.com" {
		t.Errorf("收件人 = %q", request.Recipient)
	}
	if !regexp.MustCompile(`^security-notice-[0-9a-f]{32}$`).MatchString(request.IdempotencyKey) || len(request.IdempotencyKey) < 8 || len(request.IdempotencyKey) > 128 {
		t.Errorf("告知幂等键 = %q", request.IdempotencyKey)
	}
	records, err := env.service.Notifications(env.ctx, alice, normalUserID, 10)
	if err != nil || len(records) != 1 || records[0].State != reauth.NotificationQueued {
		t.Fatalf("告知记录 = %+v, err = %v（期望 queued，不是 sent）", records, err)
	}
	if records[0].DedupKey != request.IdempotencyKey {
		t.Errorf("主记录稳定去重键 = %q，期望等于入队幂等键 %q",
			records[0].DedupKey, request.IdempotencyKey)
	}
	if !strings.HasPrefix(records[0].DeliveryID, "mdl_fake_") {
		t.Errorf("主记录未保存 Enqueue 返回的投递标识: %+v", records[0])
	}
	if records[0].RecipientMasked != "a***@example.com" {
		t.Errorf("收件人脱敏 = %q", records[0].RecipientMasked)
	}
	if events := env.count(`SELECT COUNT(*) FROM audit_events WHERE action='security.notice' AND outcome='success'`); events != 1 {
		t.Errorf("queued 告知成功审计数 = %d，期望 1", events)
	}

	// 入队失败：状态 failed + 稳定原因，调用方收到错误但业务结果不回滚。
	capture.err = errors.New("queue unavailable")
	if err := env.service.NotifyOutcome(env.ctx, result, reauth.OutcomeSuccess); !errors.Is(err, reauth.ErrNotificationFailed) {
		t.Fatalf("入队失败错误 = %v，期望 ErrNotificationFailed", err)
	}
	// 同一业务事件的重复告知按稳定去重键幂等更新，不产生第二条主记录；
	// 已关联的 delivery_id 不被清空（重试后可继续回看同一投递）。
	records, _ = env.service.Notifications(env.ctx, alice, normalUserID, 10)
	if len(records) != 1 || records[0].State != reauth.NotificationFailed ||
		records[0].ErrorCode != "delivery_enqueue_failed" {
		t.Fatalf("入队失败记录 = %+v（期望同一记录更新为 failed）", records)
	}
	if !strings.HasPrefix(records[0].DeliveryID, "mdl_fake_") {
		t.Errorf("入队失败后已有投递关联不应丢失: %+v", records[0])
	}

	// NotificationRequired=false：不入队、不发送、不记录告知（策略抑制）。
	suppressed := reauth.Result{
		UserID: normalUserID, OperationID: "password.change",
		Decision:  policy.Decision{NotificationRequired: false},
		RequestID: "req_suppressed_0000000000000000000000000000",
	}
	before := len(capture.snapshot())
	if err := env.service.NotifyOutcome(env.ctx, suppressed, reauth.OutcomeSuccess); err != nil {
		t.Fatalf("抑制告知: %v", err)
	}
	if after := len(capture.snapshot()); after != before {
		t.Errorf("NotificationRequired=false 仍入队 %d 条", after-before)
	}
}
