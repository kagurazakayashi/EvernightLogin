// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package reauth_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	mailersqlite "github.com/kagurazakayashi/EvernightLogin/internal/mailer/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// testTaskEnqueuer 捕获 mailer 投递任务（不执行），供测试手动驱动 Handler。
type testTaskEnqueuer struct {
	mu       sync.Mutex
	requests []task.EnqueueRequest
	nextID   int
}

func (e *testTaskEnqueuer) Enqueue(_ context.Context, request task.EnqueueRequest) (task.Job, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.nextID++
	e.requests = append(e.requests, request)
	return task.Job{ID: fmt.Sprintf("job_reauthtest_%06d", e.nextID), Kind: request.Kind,
		Payload: request.Payload, Initiator: request.Actor, Attempt: 1,
		MaxAttempts: request.MaxAttempts}, nil
}

func (e *testTaskEnqueuer) lastJob() (task.Job, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.requests) == 0 {
		return task.Job{}, false
	}
	request := e.requests[len(e.requests)-1]
	return task.Job{ID: fmt.Sprintf("job_reauthtest_%06d", len(e.requests)),
		Kind: request.Kind, Payload: request.Payload, Initiator: request.Actor,
		Attempt: 1, MaxAttempts: request.MaxAttempts}, true
}

func (e *testTaskEnqueuer) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.requests)
}

// countingDeliveryEnqueuer 包装真实投递入队服务，记录每次 Enqueue 调用与幂等键，
// 便于验证“同一业务事件重复回调仍使用同一幂等键”。
type countingDeliveryEnqueuer struct {
	inner mailer.DeliveryEnqueuer
	mu    sync.Mutex
	keys  []string
}

func (e *countingDeliveryEnqueuer) Enqueue(ctx context.Context,
	request mailer.EnqueueRequest) (mailer.EnqueueResult, error) {
	e.mu.Lock()
	e.keys = append(e.keys, request.IdempotencyKey)
	e.mu.Unlock()
	return e.inner.Enqueue(ctx, request)
}

func (e *countingDeliveryEnqueuer) snapshot() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.keys...)
}

// recordingSender 记录成功发送的邮件，并可注入固定发送错误。
type recordingSender struct {
	mu       sync.Mutex
	messages []mailer.Message
	err      error
}

func (s *recordingSender) Send(_ context.Context, message mailer.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.messages = append(s.messages, message)
	return nil
}

func (s *recordingSender) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.messages)
}

// newNotificationDeliveryEnv 构造与生产一致的测试环境：告知主记录与 mailer 投递
// 记录共享同一 SQLite 数据库，因此 Notifications 读取能按 delivery_id / 去重键
// 投影投递终态。extra 在服务构造前注入附加包装（例如制造回写失败的 Store）。
func newNotificationDeliveryEnv(t *testing.T, sender mailer.Sender,
	extra func(*testEnv, *reauth.Options)) (*testEnv, *mailer.DeliveryService, *testTaskEnqueuer,
	*countingDeliveryEnqueuer) {
	t.Helper()
	var delivery *mailer.DeliveryService
	var enqueuer *testTaskEnqueuer
	counter := &countingDeliveryEnqueuer{}
	env := newTestEnvWithHooks(t, nil, func(testEnv *testEnv, options *reauth.Options) {
		mailerStore, err := mailersqlite.New(testEnv.storage)
		if err != nil {
			t.Fatalf("投递存储: %v", err)
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
		counter.inner = delivery
		options.Deliveries = counter
		if extra != nil {
			extra(testEnv, options)
		}
	})
	return env, delivery, enqueuer, counter
}

// countRows 统计测试数据库中的行数（失败即终止测试）。
func countRows(t *testing.T, env *testEnv, query string, args ...any) int {
	t.Helper()
	var count int
	if err := env.storage.DB().QueryRowContext(env.ctx, query, args...).Scan(&count); err != nil {
		t.Fatalf("查询失败 %q: %v", query, err)
	}
	return count
}

// flakyNotificationStore 包装真实 Store：第一次“带投递标识的回写”模拟数据库失败，
// 用于验证“入队成功但关联回写失败”时可读时回看、重试可恢复。
type flakyNotificationStore struct {
	reauth.Store
	mu           sync.Mutex
	failNextLink bool
}

func (s *flakyNotificationStore) UpsertNotification(ctx context.Context,
	record reauth.NotificationRecord) error {
	s.mu.Lock()
	fail := s.failNextLink && record.DeliveryID != ""
	if fail {
		s.failNextLink = false
	}
	s.mu.Unlock()
	if fail {
		return errors.New("simulated notification delivery-link write failure")
	}
	return s.Store.UpsertNotification(ctx, record)
}

// failingIntentStore 模拟“告知主记录写失败”（例如非 dedup_key 约束失败）：仅拦截
// 意图写入（无 delivery_id 且有 dedup_key），其它写入委托真实 Store。
type failingIntentStore struct {
	reauth.Store
	mu       sync.Mutex
	attempts int
}

func (s *failingIntentStore) UpsertNotification(ctx context.Context,
	record reauth.NotificationRecord) error {
	if record.DeliveryID == "" && record.DedupKey != "" {
		s.mu.Lock()
		s.attempts++
		s.mu.Unlock()
		return errors.New("simulated notification intent constraint failure")
	}
	return s.Store.UpsertNotification(ctx, record)
}

func (s *failingIntentStore) attemptCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attempts
}

// TestNotificationIntentWriteFailureBlocksEnqueueAndSuccessAudit 验证 210 SEC N1：
// 告知主记录写失败时必须 fail-closed——不入队、不写成功审计、不产生孤儿邮件。
func TestNotificationIntentWriteFailureBlocksEnqueueAndSuccessAudit(t *testing.T) {
	sender := &recordingSender{}
	failing := &failingIntentStore{}
	env, _, enqueuer, counter := newNotificationDeliveryEnv(t, sender,
		func(_ *testEnv, options *reauth.Options) {
			failing.Store = options.Store
			options.Store = failing
		})
	env.now = time.Now().UTC()
	alice := env.userCaller(t, normalUserID)
	result, err := env.service.Authorize(reauth.WithSignals(env.ctx, freshSignals(env.now)), alice,
		request("password.change"))
	if err != nil {
		t.Fatalf("授权: %v", err)
	}
	if err := env.service.NotifyOutcome(env.ctx, result, reauth.OutcomeSuccess); err == nil {
		t.Fatal("主记录写入失败时 NotifyOutcome 必须返回错误（不得静默成功）")
	}
	if failing.attemptCount() == 0 {
		t.Fatal("未观察到主记录写入尝试")
	}
	if got := len(counter.snapshot()); got != 0 {
		t.Errorf("主记录写失败后仍调用 Enqueue %d 次（会产生孤儿邮件）", got)
	}
	if got := enqueuer.count(); got != 0 {
		t.Errorf("主记录写失败后仍创建投递任务 %d 个", got)
	}
	if got := countRows(t, env,
		`SELECT COUNT(*) FROM audit_events WHERE action='security.notice' AND outcome='success'`); got != 0 {
		t.Errorf("主记录写失败后仍写入成功审计 %d 条", got)
	}
	if got := countRows(t, env, `SELECT COUNT(*) FROM security_notifications`); got != 0 {
		t.Errorf("主记录写失败后残留告知记录 %d 条", got)
	}
	if sender.count() != 0 {
		t.Errorf("主记录写失败后仍发送邮件 %d 封", sender.count())
	}
}

// TestNotificationDeliveryLifecycleAndIdempotentRetry 覆盖状态投影与幂等：
// queued → succeeded（SMTP 接受）、重复回调不产生第二封邮件/第二条主记录、同一
// 业务事件重试复用同一投递、不同业务执行（不同 RequestID）产生独立告知。
func TestNotificationDeliveryLifecycleAndIdempotentRetry(t *testing.T) {
	sender := &recordingSender{}
	env, delivery, enqueuer, counter := newNotificationDeliveryEnv(t, sender, nil)
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
	records, err := env.service.Notifications(env.ctx, alice, normalUserID, 10)
	if err != nil || len(records) != 1 {
		t.Fatalf("告知记录 = %+v, err = %v", records, err)
	}
	first := records[0]
	if first.State != reauth.NotificationQueued {
		t.Errorf("入队后主记录状态 = %q，期望 queued（受理，不是 sent）", first.State)
	}
	if first.DeliveryID == "" || first.DeliveryState != mailer.DeliveryQueued {
		t.Fatalf("主记录未关联/未投影投递记录: %+v", first)
	}
	if len(first.DedupKey) < 8 || len(first.DedupKey) > 128 {
		t.Errorf("稳定去重键长度越界: %q", first.DedupKey)
	}
	if got := countRows(t, env, `SELECT COUNT(*) FROM mail_deliveries`); got != 1 {
		t.Fatalf("投递记录数 = %d，期望 1", got)
	}

	// 重复回调（同一业务事件）：mailer 幂等键命中既有投递，不产生第二封邮件。
	if err := env.service.NotifyOutcome(env.ctx, result, reauth.OutcomeSuccess); err != nil {
		t.Fatalf("重复回调: %v", err)
	}
	keys := counter.snapshot()
	if len(keys) != 2 {
		t.Errorf("投递入队调用数 = %d，期望 2（第二次为幂等命中）", len(keys))
	} else if keys[0] != keys[1] {
		t.Errorf("重复回调的幂等键不一致: %q vs %q", keys[0], keys[1])
	}
	if got := countRows(t, env, `SELECT COUNT(*) FROM security_notifications`); got != 1 {
		t.Errorf("告知主记录数 = %d，期望 1（同一事件幂等更新）", got)
	}
	if got := countRows(t, env, `SELECT COUNT(*) FROM mail_deliveries`); got != 1 {
		t.Errorf("投递记录数 = %d，期望 1（幂等键不重复建投递）", got)
	}
	records, _ = env.service.Notifications(env.ctx, alice, normalUserID, 10)
	if records[0].DeliveryID != first.DeliveryID {
		t.Errorf("重复回调后投递标识 = %q，期望仍为 %q", records[0].DeliveryID, first.DeliveryID)
	}

	// 驱动真实 Handler：投递任务终态 succeeded（SMTP 接受），主记录仍为 queued。
	job, ok := enqueuer.lastJob()
	if !ok {
		t.Fatal("缺少投递任务")
	}
	if err := delivery.Handler(env.ctx, job); err != nil {
		t.Fatalf("投递任务: %v", err)
	}
	if sender.count() != 1 {
		t.Fatalf("实际发送邮件数 = %d，期望 1", sender.count())
	}
	records, err = env.service.Notifications(env.ctx, alice, normalUserID, 10)
	if err != nil || len(records) != 1 {
		t.Fatalf("投递后告知记录 = %+v, err = %v", records, err)
	}
	if records[0].State != reauth.NotificationQueued {
		t.Errorf("投递成功后主记录状态 = %q，期望仍为 queued（succeeded 只表示 SMTP 接受）", records[0].State)
	}
	if records[0].DeliveryState != mailer.DeliverySucceeded {
		t.Errorf("投递状态投影 = %q，期望 succeeded", records[0].DeliveryState)
	}

	// 服务重启：新 Service 实例读取同一数据库仍投影同一投递终态（无内存状态依赖）。
	restarted, err := reauth.New(reauth.Options{
		Store: env.stores, Audit: env.recorder, Policy: env.policyService, Passwords: env.verifier,
		Deliveries: delivery, FromAddress: "security@example.com",
		Now:    func() time.Time { return env.now },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("重启后构造服务: %v", err)
	}
	restartedRecords, err := restarted.Notifications(env.ctx, alice, normalUserID, 10)
	if err != nil || len(restartedRecords) != 1 ||
		restartedRecords[0].DeliveryState != mailer.DeliverySucceeded ||
		restartedRecords[0].DeliveryID != first.DeliveryID {
		t.Fatalf("重启后告知记录 = %+v, err = %v", restartedRecords, err)
	}
	// 乱序/迟到回写：投递已是终态 succeeded 之后，同一业务事件的通知回写（重试回调）
	// 只能幂等更新主记录，读取仍以投递记录终态为准，不得回退为排队/成功冒充。
	if err := env.service.NotifyOutcome(env.ctx, result, reauth.OutcomeSuccess); err != nil {
		t.Fatalf("投递终态后的迟到回写: %v", err)
	}
	records, err = env.service.Notifications(env.ctx, alice, normalUserID, 10)
	if err != nil || len(records) != 1 {
		t.Fatalf("迟到回写后告知记录 = %+v, err = %v", records, err)
	}
	if records[0].DeliveryState != mailer.DeliverySucceeded || records[0].State != reauth.NotificationQueued {
		t.Fatalf("迟到回写不得回退投递终态: %+v", records[0])
	}
	if sender.count() != 1 {
		t.Errorf("迟到回写不应再次发送邮件，发送数 = %d", sender.count())
	}

	// 不同业务执行（不同 RequestID）必须得到独立去重键/独立投递/独立主记录。
	secondResult := result
	secondResult.RequestID = "req_second_execution_0000000000000001"
	if err := env.service.NotifyOutcome(env.ctx, secondResult, reauth.OutcomeSuccess); err != nil {
		t.Fatalf("第二次业务执行告知: %v", err)
	}
	if got := countRows(t, env, `SELECT COUNT(*) FROM security_notifications`); got != 2 {
		t.Errorf("两次业务执行告知主记录数 = %d，期望 2", got)
	}
	if got := countRows(t, env, `SELECT COUNT(*) FROM mail_deliveries`); got != 2 {
		t.Errorf("两次业务执行投递记录数 = %d，期望 2", got)
	}
}

// TestNotificationDeliveryLinkWriteFailureRecoverable 模拟“主记录已写、投递已入队、
// 但关联 delivery_id 的回写失败”：读取时按稳定去重键仍能看到当前投递状态；同一
// 业务事件重试后关联被补写，全程只有 1 条主记录/1 条投递记录/1 封邮件。
func TestNotificationDeliveryLinkWriteFailureRecoverable(t *testing.T) {
	sender := &recordingSender{}
	flaky := &flakyNotificationStore{failNextLink: true}
	env, delivery, enqueuer, _ := newNotificationDeliveryEnv(t, sender,
		func(_ *testEnv, options *reauth.Options) {
			flaky.Store = options.Store
			options.Store = flaky
		})
	env.now = time.Now().UTC()
	alice := env.userCaller(t, normalUserID)
	result, err := env.service.Authorize(reauth.WithSignals(env.ctx, freshSignals(env.now)), alice,
		request("password.change"))
	if err != nil {
		t.Fatalf("授权: %v", err)
	}
	if err := env.service.NotifyOutcome(env.ctx, result, reauth.OutcomeSuccess); err == nil {
		t.Fatal("关联回写失败应返回错误（业务不回滚，但调用方可记录）")
	}
	if enqueuer.count() != 1 {
		t.Fatalf("入队调用数 = %d，期望 1", enqueuer.count())
	}
	records, err := env.service.Notifications(env.ctx, alice, normalUserID, 10)
	if err != nil || len(records) != 1 {
		t.Fatalf("回写失败后告知记录 = %+v, err = %v", records, err)
	}
	if records[0].State != reauth.NotificationQueued {
		t.Errorf("回写失败后主记录状态 = %q，期望 queued", records[0].State)
	}
	// 主记录未存 delivery_id，但读取路径按稳定去重键回看到同一投递记录。
	if records[0].DeliveryState != mailer.DeliveryQueued || records[0].DeliveryID == "" {
		t.Fatalf("回写失败后未按去重键投影投递状态: %+v", records[0])
	}
	// 同一业务事件重试：幂等命中同一投递并补写关联。
	if err := env.service.NotifyOutcome(env.ctx, result, reauth.OutcomeSuccess); err != nil {
		t.Fatalf("重试关联: %v", err)
	}
	records, err = env.service.Notifications(env.ctx, alice, normalUserID, 10)
	if err != nil || len(records) != 1 {
		t.Fatalf("重试后告知记录 = %+v, err = %v", records, err)
	}
	if records[0].DeliveryID == "" || records[0].DeliveryState != mailer.DeliveryQueued {
		t.Fatalf("重试后关联未恢复: %+v", records[0])
	}
	if got := countRows(t, env, `SELECT COUNT(*) FROM mail_deliveries`); got != 1 {
		t.Errorf("重试后投递记录数 = %d，期望 1（幂等）", got)
	}
	// 继续驱动投递成功后读取投影为 succeeded。
	job, ok := enqueuer.lastJob()
	if !ok {
		t.Fatal("缺少投递任务")
	}
	if err := delivery.Handler(env.ctx, job); err != nil {
		t.Fatalf("投递任务: %v", err)
	}
	records, _ = env.service.Notifications(env.ctx, alice, normalUserID, 10)
	if len(records) != 1 || records[0].DeliveryState != mailer.DeliverySucceeded {
		t.Fatalf("最终投递状态投影 = %+v", records)
	}
}

// TestNotificationDeliveryFailureAndCancelledNotSuccess 验证永久失败与取消不会被
// 投影为成功：失败投影 failed + 稳定错误码；取消投影 cancelled；两者都不回报 sent。
func TestNotificationDeliveryFailureAndCancelledNotSuccess(t *testing.T) {
	// 永久失败：发送器返回不可重试错误，任务终态 failed。
	failing := &recordingSender{err: &mailer.SendError{
		Kind: mailer.FailurePermanent, Code: mailer.CodeAuthFailed, Err: errors.New("auth failed")}}
	env, delivery, enqueuer, _ := newNotificationDeliveryEnv(t, failing, nil)
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
	job, ok := enqueuer.lastJob()
	if !ok {
		t.Fatal("缺少投递任务")
	}
	if err := delivery.Handler(env.ctx, job); err == nil {
		t.Fatal("永久失败的投递任务应返回错误")
	}
	records, err := env.service.Notifications(env.ctx, alice, normalUserID, 10)
	if err != nil || len(records) != 1 {
		t.Fatalf("失败告知记录 = %+v, err = %v", records, err)
	}
	if records[0].DeliveryState != mailer.DeliveryFailed {
		t.Errorf("失败投递状态投影 = %q，期望 failed", records[0].DeliveryState)
	}
	if records[0].DeliveryErrorCode == "" {
		t.Errorf("失败投递缺少稳定错误码: %+v", records[0])
	}
	if records[0].State == reauth.NotificationSent {
		t.Errorf("投递失败不得投影为 sent: %+v", records[0])
	}

	// 取消：任务上下文取消，Handler 记录 cancelled 终态。
	sender := &recordingSender{}
	env2, delivery2, enqueuer2, _ := newNotificationDeliveryEnv(t, sender, nil)
	env2.now = time.Now().UTC()
	alice2 := env2.userCaller(t, normalUserID)
	result2, err := env2.service.Authorize(reauth.WithSignals(env2.ctx, freshSignals(env2.now)), alice2,
		request("password.change"))
	if err != nil {
		t.Fatalf("授权(取消场景): %v", err)
	}
	if err := env2.service.NotifyOutcome(env2.ctx, result2, reauth.OutcomeSuccess); err != nil {
		t.Fatalf("队列告知(取消场景): %v", err)
	}
	job2, ok := enqueuer2.lastJob()
	if !ok {
		t.Fatal("缺少投递任务(取消场景)")
	}
	cancelledCtx, cancel := context.WithCancel(env2.ctx)
	cancel()
	_ = delivery2.Handler(cancelledCtx, job2)
	records2, err := env2.service.Notifications(env2.ctx, alice2, normalUserID, 10)
	if err != nil || len(records2) != 1 {
		t.Fatalf("取消告知记录 = %+v, err = %v", records2, err)
	}
	if records2[0].DeliveryState != mailer.DeliveryCancelled {
		t.Errorf("取消投递状态投影 = %q，期望 cancelled", records2[0].DeliveryState)
	}
	if sender.count() != 0 {
		t.Errorf("取消后不应实际发送邮件，发送数 = %d", sender.count())
	}
}

// TestNotificationQueryScopeIsolation 验证告知查询数据范围：用户只能读本人记录，
// 不能借他人 userID 读取（含投递标识/脱敏收件人），root 与管理调用者按既有规则可读。
func TestNotificationQueryScopeIsolation(t *testing.T) {
	env, _, _, _ := newNotificationDeliveryEnv(t, &recordingSender{}, nil)
	env.now = time.Now().UTC()
	alice := env.userCaller(t, normalUserID)
	bob := env.userCaller(t, noMailUserID)
	result, err := env.service.Authorize(reauth.WithSignals(env.ctx, freshSignals(env.now)), alice,
		request("password.change"))
	if err != nil {
		t.Fatalf("授权: %v", err)
	}
	if err := env.service.NotifyOutcome(env.ctx, result, reauth.OutcomeSuccess); err != nil {
		t.Fatalf("告知: %v", err)
	}
	// bob 读本人：没有记录（alice 的记录不串用户）。
	bobRecords, err := env.service.Notifications(env.ctx, bob, noMailUserID, 10)
	if err != nil {
		t.Fatalf("bob 读本人告知: %v", err)
	}
	if len(bobRecords) != 0 {
		t.Fatalf("bob 读到了他人的告知记录: %+v", bobRecords)
	}
	// bob 不能通过传入 alice 的 userID 越权读取。
	if _, err := env.service.Notifications(env.ctx, bob, normalUserID, 10); !errors.Is(err, reauth.ErrAccessDenied) {
		t.Fatalf("bob 读 alice 告知错误 = %v，期望 ErrAccessDenied", err)
	}
	aliceRecords, err := env.service.Notifications(env.ctx, alice, normalUserID, 10)
	if err != nil || len(aliceRecords) != 1 || aliceRecords[0].RecipientMasked != "a***@example.com" {
		t.Fatalf("alice 读本人告知 = %+v, err = %v", aliceRecords, err)
	}
	// root（系统授予的受信身份）按既有规则可读普通用户告知，但仍只返回该用户记录。
	rootCaller := env.userCaller(t, rootUserID)
	rootRecords, err := env.service.Notifications(env.ctx, rootCaller, normalUserID, 10)
	if err != nil || len(rootRecords) != 1 || rootRecords[0].UserID != normalUserID {
		t.Fatalf("root 读 alice 告知 = %+v, err = %v", rootRecords, err)
	}
}
