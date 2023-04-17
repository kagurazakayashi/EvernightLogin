package mailer_test

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	mailersqlite "github.com/kagurazakayashi/EvernightLogin/internal/mailer/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailtest"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
	tasksqlite "github.com/kagurazakayashi/EvernightLogin/internal/task/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

var deliveryStart = time.Date(2026, 11, 16, 8, 0, 0, 0, time.UTC)

// fakeEnqueuer 记录任务入队请求并返回确定性任务。
type fakeEnqueuer struct {
	requests []task.EnqueueRequest
	fail     error
	nextID   int
}

func (f *fakeEnqueuer) Enqueue(_ context.Context, request task.EnqueueRequest) (task.Job, error) {
	if f.fail != nil {
		return task.Job{}, f.fail
	}
	f.requests = append(f.requests, request)
	f.nextID++
	return task.Job{ID: "mailjob-" + string(rune('0'+f.nextID)), Kind: request.Kind, Payload: request.Payload,
		Initiator: request.Actor, MaxAttempts: request.MaxAttempts}, nil
}

// fakeSender 记录发送请求，可按预设返回错误。
type fakeSender struct {
	sent []mailer.Message
	err  error
}

func (f *fakeSender) Send(_ context.Context, message mailer.Message) error {
	if f.err != nil {
		return f.err
	}
	f.sent = append(f.sent, message)
	return nil
}

// fakeAudit 记录审计事件。
type fakeAudit struct{ events []audit.Event }

func (f *fakeAudit) Record(_ context.Context, event audit.Event) error {
	f.events = append(f.events, event)
	return nil
}

// fakeAuthorizer 按允许标志放行，并按归属主体模拟数据范围：普通用户只能操作
// 自己创建的投递记录。
type fakeAuthorizer struct{ allow bool }

func (f *fakeAuthorizer) Authorize(_ context.Context, caller mailer.Caller, _ mailer.Action, record *mailer.Record) error {
	if !f.allow {
		return mailer.ErrAccessDenied
	}
	if record != nil && caller.Actor().Type == audit.ActorUser &&
		(record.OwnerType != audit.ActorUser || record.OwnerID != caller.Actor().ID) {
		return mailer.ErrAccessDenied
	}
	return nil
}

// deliveryEnv 是投递服务测试环境。
type deliveryEnv struct {
	t        *testing.T
	store    mailer.Store
	storage  *storagesqlite.Store
	service  *mailer.DeliveryService
	enqueuer *fakeEnqueuer
	sender   *fakeSender
	audit    *fakeAudit
	authz    *fakeAuthorizer
	keyring  *secrets.Keyring
}

func mustSystemCaller(t *testing.T) mailer.Caller {
	t.Helper()
	caller, err := mailer.SystemCaller("mailer-test")
	if err != nil {
		t.Fatalf("系统调用者: %v", err)
	}
	return caller
}

func mustUserCaller(t *testing.T, id string) mailer.Caller {
	t.Helper()
	caller, err := mailer.UserCaller(id)
	if err != nil {
		t.Fatalf("用户调用者: %v", err)
	}
	return caller
}

// newDeliveryEnv 使用临时 SQLite、真实迁移与真实 secrets.Sealer 构造服务。
func newDeliveryEnv(t *testing.T) *deliveryEnv {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(testutil.TempDir(t), "login-mailer-test.db")
	storage, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(path))
	if err != nil {
		t.Fatalf("打开临时数据库: %v", err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	migrationList, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移: %v", err)
	}
	if _, err := storage.Migrate(ctx, migrationList); err != nil {
		t.Fatalf("执行迁移: %v", err)
	}
	store, err := mailersqlite.New(storage)
	if err != nil {
		t.Fatalf("投递存储: %v", err)
	}
	keyring, err := secrets.GenerateKeyring("k1", deliveryStart)
	if err != nil {
		t.Fatalf("生成密钥环: %v", err)
	}
	sealer, err := secrets.NewSealer(keyring, nil)
	if err != nil {
		t.Fatalf("秘密加密器: %v", err)
	}
	templates, err := mailer.DefaultTemplateSet()
	if err != nil {
		t.Fatalf("模板: %v", err)
	}
	from, err := mailer.ParseAddress("noreply@example.test")
	if err != nil {
		t.Fatalf("发件地址: %v", err)
	}
	env := &deliveryEnv{
		t:        t,
		store:    store,
		storage:  storage,
		enqueuer: &fakeEnqueuer{},
		sender:   &fakeSender{},
		audit:    &fakeAudit{},
		authz:    &fakeAuthorizer{allow: true},
		keyring:  keyring,
	}
	service, err := mailer.NewDeliveryService(mailer.DeliveryOptions{
		Store:       store,
		Sender:      env.sender,
		Templates:   templates,
		Sealer:      sealer,
		Recorder:    env.audit,
		Enqueuer:    env.enqueuer,
		Authorizer:  env.authz,
		From:        from,
		MaxAttempts: 3,
		Now:         func() time.Time { return deliveryStart },
	})
	if err != nil {
		t.Fatalf("投递服务: %v", err)
	}
	env.service = service
	return env
}

// verificationRequest 构造一封验证邮件入队请求。
func verificationRequest(key string) mailer.EnqueueRequest {
	caller, _ := mailer.SystemCaller("mailer-test")
	return mailer.EnqueueRequest{
		Caller:         caller,
		IdempotencyKey: key,
		Kind:           mailer.KindVerification,
		Recipient:      "user@example.test",
		Data: mailer.RenderRequest{
			Kind:         mailer.KindVerification,
			Verification: &mailer.VerificationData{DisplayName: "小明", Code: "654321", ExpiresIn: "10 分钟", AppName: "Login"},
		},
	}
}

// jobFromRequest 把入队请求包装成可交给 Handler 的任务。
func jobFromRequest(t *testing.T, env *deliveryEnv, attempt int) task.Job {
	t.Helper()
	if len(env.enqueuer.requests) == 0 {
		t.Fatal("没有已入队任务")
	}
	request := env.enqueuer.requests[len(env.enqueuer.requests)-1]
	return task.Job{ID: "mailjob-1", Kind: request.Kind, Payload: request.Payload,
		Initiator: request.Actor, Attempt: attempt, MaxAttempts: request.MaxAttempts}
}

// TestDeliveryEnqueueIdempotentAndEncrypted 验证幂等键去重、任务只创建一次、载荷
// 加密落库且服务查询不返回密文。
func TestDeliveryEnqueueIdempotentAndEncrypted(t *testing.T) {
	env := newDeliveryEnv(t)
	ctx := context.Background()

	first, err := env.service.Enqueue(ctx, verificationRequest("verify:user-1:email-1"))
	if err != nil {
		t.Fatalf("首次入队: %v", err)
	}
	if first.Duplicate {
		t.Error("首次入队不应标记重复")
	}
	second, err := env.service.Enqueue(ctx, verificationRequest("verify:user-1:email-1"))
	if err != nil {
		t.Fatalf("重复入队: %v", err)
	}
	if !second.Duplicate || second.Record.ID != first.Record.ID {
		t.Errorf("幂等键重复应返回既有记录: %+v", second)
	}
	if len(env.enqueuer.requests) != 1 {
		t.Errorf("重复入队不应重复创建任务，实际 %d", len(env.enqueuer.requests))
	}
	// 任务载荷只含记录 ID，不含验证码或链接。
	payload := string(env.enqueuer.requests[0].Payload)
	if strings.Contains(payload, "654321") || strings.Contains(payload, "http") {
		t.Errorf("任务载荷泄漏秘密: %q", payload)
	}
	// 数据库中的载荷是密文，明文验证码不落库。
	record, err := env.store.Get(ctx, first.Record.ID)
	if err != nil {
		t.Fatalf("读取投递记录: %v", err)
	}
	if len(record.SealedPayload) == 0 || strings.Contains(string(record.SealedPayload), "654321") {
		t.Errorf("载荷应加密保存: %q", record.SealedPayload)
	}
	// 服务查询接口不返回密文。
	got, err := env.service.Get(ctx, mustSystemCaller(t), first.Record.ID)
	if err != nil {
		t.Fatalf("查询投递: %v", err)
	}
	if len(got.SealedPayload) != 0 {
		t.Error("查询结果不应包含加密载荷")
	}
	if !hasAudit(env.audit, "mail.enqueue") {
		t.Error("缺少入队审计")
	}
}

// TestDeliveryHandlerSuccessAndRestartRecovery 验证成功投递、终态幂等与重启恢复。
func TestDeliveryHandlerSuccessAndRestartRecovery(t *testing.T) {
	env := newDeliveryEnv(t)
	ctx := context.Background()
	_, err := env.service.Enqueue(ctx, verificationRequest("verify:user-2:email-1"))
	if err != nil {
		t.Fatalf("入队: %v", err)
	}
	job := jobFromRequest(t, env, 1)
	if err := env.service.Handler(ctx, job); err != nil {
		t.Fatalf("投递失败: %v", err)
	}
	if len(env.sender.sent) != 1 {
		t.Fatalf("应发送 1 封，实际 %d", len(env.sender.sent))
	}
	message := env.sender.sent[0]
	if !strings.Contains(message.TextBody, "654321") || message.To[0].Spec != "user@example.test" {
		t.Errorf("发送内容异常: %+v", message)
	}
	record, err := env.store.Get(ctx, jobDeliveryID(t, job))
	if err != nil {
		t.Fatalf("读取记录: %v", err)
	}
	if record.State != mailer.DeliverySucceeded {
		t.Errorf("状态 = %s，期望 succeeded", record.State)
	}
	if !hasAudit(env.audit, "mail.delivered") {
		t.Error("缺少成功审计")
	}
	// 模拟任务重复执行（at-least-once）：终态幂等，不重复发送。
	if err := env.service.Handler(ctx, job); err != nil {
		t.Fatalf("重复执行应幂等: %v", err)
	}
	if len(env.sender.sent) != 1 {
		t.Errorf("重复执行不应重复发送，实际 %d", len(env.sender.sent))
	}
	// 重启恢复：新的服务实例（同存储）继续处理 queued 投递。
	_, err = env.service.Enqueue(ctx, verificationRequest("verify:user-3:email-1"))
	if err != nil {
		t.Fatalf("第二次入队: %v", err)
	}
	recovered := newRestartedService(t, env)
	job = jobFromRequest(t, env, 1)
	if err := recovered.Handler(ctx, job); err != nil {
		t.Fatalf("重启恢复投递失败: %v", err)
	}
	if len(env.sender.sent) != 2 {
		t.Errorf("重启恢复后应发送第 2 封，实际 %d", len(env.sender.sent))
	}
}

// TestDeliveryFailureClassification 验证永久/临时失败分类与重试记录。
func TestDeliveryFailureClassification(t *testing.T) {
	env := newDeliveryEnv(t)
	ctx := context.Background()
	_, err := env.service.Enqueue(ctx, verificationRequest("verify:user-4:email-1"))
	if err != nil {
		t.Fatalf("入队: %v", err)
	}
	env.sender.err = &mailer.SendError{Kind: mailer.FailurePermanent, Code: mailer.CodeAuthFailed, Err: mailer.ErrInvalidMessage}
	job := jobFromRequest(t, env, 1)
	err = env.service.Handler(ctx, job)
	if !task.IsNonRetryable(err) {
		t.Errorf("永久失败应返回不可重试错误: %v", err)
	}
	record, err := env.store.Get(ctx, jobDeliveryID(t, job))
	if err != nil {
		t.Fatalf("读取记录: %v", err)
	}
	if record.State != mailer.DeliveryFailed || record.LastErrorCode != mailer.CodeAuthFailed {
		t.Errorf("永久失败记录异常: %+v", record)
	}
	if !hasAudit(env.audit, "mail.failed") {
		t.Error("缺少失败审计")
	}

	// 临时失败在未到上限时保持 queued 并返回可重试错误。
	_, err = env.service.Enqueue(ctx, verificationRequest("verify:user-5:email-1"))
	if err != nil {
		t.Fatalf("入队: %v", err)
	}
	env.sender.err = &mailer.SendError{Kind: mailer.FailureTransient, Code: mailer.CodeTimeout, Err: mailer.ErrInvalidMessage}
	job = jobFromRequest(t, env, 1)
	err = env.service.Handler(ctx, job)
	if err == nil || task.IsNonRetryable(err) {
		t.Errorf("临时失败应返回可重试错误: %v", err)
	}
	record, err = env.store.Get(ctx, jobDeliveryID(t, job))
	if err != nil {
		t.Fatalf("读取记录: %v", err)
	}
	if record.State != mailer.DeliveryQueued || record.LastErrorCode != mailer.CodeTimeout {
		t.Errorf("临时失败记录异常: %+v", record)
	}
	if !hasAudit(env.audit, "mail.retry_scheduled") {
		t.Error("缺少重试计划审计")
	}
}

// TestDeliveryRetryAuthorization 验证受控重试的授权与状态约束。
func TestDeliveryRetryAuthorization(t *testing.T) {
	env := newDeliveryEnv(t)
	ctx := context.Background()
	_, err := env.service.Enqueue(ctx, verificationRequest("verify:user-6:email-1"))
	if err != nil {
		t.Fatalf("入队: %v", err)
	}
	env.sender.err = &mailer.SendError{Kind: mailer.FailurePermanent, Code: mailer.CodeRejected, Err: mailer.ErrInvalidMessage}
	job := jobFromRequest(t, env, 1)
	_ = env.service.Handler(ctx, job)
	id := jobDeliveryID(t, job)

	env.authz.allow = false
	if _, err := env.service.Retry(ctx, mustSystemCaller(t), id, ""); !errors.Is(err, mailer.ErrAccessDenied) {
		t.Errorf("无权限重试应拒绝: %v", err)
	}
	if _, err := env.service.Get(ctx, mustSystemCaller(t), id); !errors.Is(err, mailer.ErrAccessDenied) {
		t.Errorf("无权限查询应拒绝: %v", err)
	}
	env.authz.allow = true
	env.sender.err = nil
	if _, err := env.service.Retry(ctx, mustSystemCaller(t), id, ""); err != nil {
		t.Fatalf("受控重试失败: %v", err)
	}
	record, err := env.store.Get(ctx, id)
	if err != nil {
		t.Fatalf("读取记录: %v", err)
	}
	if record.State != mailer.DeliveryQueued {
		t.Errorf("重试后状态 = %s", record.State)
	}
	if !hasAudit(env.audit, "mail.retry") {
		t.Error("缺少重试审计")
	}
	// 非 failed 状态不允许重试。
	if _, err := env.service.Retry(ctx, mustSystemCaller(t), id, ""); !errors.Is(err, mailer.ErrDeliveryConflict) {
		t.Errorf("queued 状态重试应冲突: %v", err)
	}
}

// TestDeliveryCancelAndInjection 验证取消与地址注入拒绝。
func TestDeliveryCancelAndInjection(t *testing.T) {
	env := newDeliveryEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := env.service.Enqueue(context.Background(), verificationRequest("verify:user-7:email-1"))
	if err != nil {
		t.Fatalf("入队: %v", err)
	}
	job := jobFromRequest(t, env, 1)
	_ = env.service.Handler(ctx, job)
	record, err := env.store.Get(context.Background(), jobDeliveryID(t, job))
	if err != nil {
		t.Fatalf("读取记录: %v", err)
	}
	if record.State != mailer.DeliveryCancelled {
		t.Errorf("取消后状态 = %s", record.State)
	}
	if len(env.sender.sent) != 0 {
		t.Error("取消后不应发送")
	}
	request := verificationRequest("verify:user-8:email-1")
	request.Recipient = "user@example.test\r\nBcc: victim@example.test"
	if _, err := env.service.Enqueue(context.Background(), request); !errors.Is(err, mailer.ErrInvalidMessage) {
		t.Errorf("注入地址应被拒绝: %v", err)
	}
}

// newRestartedService 用同一存储构造新的投递服务，模拟进程重启。
func newRestartedService(t *testing.T, env *deliveryEnv) *mailer.DeliveryService {
	t.Helper()
	return newServiceWithEnqueuer(t, env, env.enqueuer)
}

// newServiceWithEnqueuer 用给定任务入队器构造投递服务（用于真实执行器整链路）。
func newServiceWithEnqueuer(t *testing.T, env *deliveryEnv, enqueuer mailer.Enqueuer) *mailer.DeliveryService {
	t.Helper()
	templates, err := mailer.DefaultTemplateSet()
	if err != nil {
		t.Fatalf("模板: %v", err)
	}
	sealer, err := secrets.NewSealer(env.keyring, nil)
	if err != nil {
		t.Fatalf("加密器: %v", err)
	}
	from, _ := mailer.ParseAddress("noreply@example.test")
	service, err := mailer.NewDeliveryService(mailer.DeliveryOptions{
		Store: env.store, Sender: env.sender, Templates: templates, Sealer: sealer,
		Recorder: env.audit, Enqueuer: enqueuer, Authorizer: env.authz, From: from,
		MaxAttempts: 3, Now: func() time.Time { return deliveryStart },
	})
	if err != nil {
		t.Fatalf("投递服务: %v", err)
	}
	return service
}

// jobDeliveryID 从任务载荷读取投递记录 ID。
func jobDeliveryID(t *testing.T, job task.Job) string {
	t.Helper()
	var payload struct {
		DeliveryID string `json:"delivery_id"`
	}
	if err := json.Unmarshal(job.Payload, &payload); err != nil || payload.DeliveryID == "" {
		t.Fatalf("解析任务载荷: %v", err)
	}
	return payload.DeliveryID
}

// hasAudit 判断是否记录过指定动作。
func hasAudit(recorder *fakeAudit, action string) bool {
	for _, event := range recorder.events {
		if event.Action == action {
			return true
		}
	}
	return false
}

// TestDeliveryEnqueueFailureMarksRecordFailed 验证任务入队失败时记录被标记 failed
// （可诊断错误码 + 审计），不会留下无主 queued 记录。
func TestDeliveryEnqueueFailureMarksRecordFailed(t *testing.T) {
	env := newDeliveryEnv(t)
	env.enqueuer.fail = errors.New("queue unavailable")
	request := verificationRequest("verify:user-9:email-1")
	_, err := env.service.Enqueue(context.Background(), request)
	if err == nil {
		t.Fatal("任务入队失败应返回错误")
	}
	record, err := env.store.GetByIdempotencyKey(context.Background(), request.IdempotencyKey)
	if err != nil {
		t.Fatalf("读取投递记录: %v", err)
	}
	if record.State != mailer.DeliveryFailed || record.LastErrorCode != mailer.CodeQueueFailed {
		t.Errorf("入队失败记录应为 failed/%s，实际 %+v", mailer.CodeQueueFailed, record)
	}
	if !hasAudit(env.audit, "mail.enqueue_failed") {
		t.Error("缺少入队失败审计")
	}
}

// TestDeliveryEndToEndWithTaskExecutor 验证真实 task.Executor 整链路：
// 入队 -> 执行器领取 -> SMTP 适配发送到 testmail -> 记录 succeeded。
func TestDeliveryEndToEndWithTaskExecutor(t *testing.T) {
	env := newDeliveryEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 真实 SMTP 适配 + testmail 本地捕获器作为发送器。
	smtpServer := mailtest.Start(t, mailtest.Options{Required: true, SMTPAuthNone: true})
	sender, err := mailer.NewSMTPSender(mailer.SMTPOptions{
		Addr: smtpServer.Addr().String(), TLSMode: mailer.TLSModeNone, AllowPlaintextLocal: true,
	})
	if err != nil {
		t.Fatalf("SMTP 发送器: %v", err)
	}

	// 先建服务再建执行器：执行器通过闭包持有服务处理器，构造顺序不构成循环。
	var deliverHandler task.Handler
	taskStore, err := tasksqlite.New(env.storage, tasksqlite.Options{})
	if err != nil {
		t.Fatalf("任务存储: %v", err)
	}
	executor, err := task.New(taskStore, task.Options{
		Handlers: map[string]task.Handler{
			mailer.TaskKindMailDelivery: func(ctx context.Context, job task.Job) error {
				return deliverHandler(ctx, job)
			},
		},
		ExecutorID:      "test-executor",
		MaxConcurrent:   1,
		PollInterval:    20 * time.Millisecond,
		ShutdownTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("任务执行器: %v", err)
	}
	service, err := mailer.NewDeliveryService(mailer.DeliveryOptions{
		Store: env.store, Sender: sender, Templates: mustTemplates(t), Sealer: mustSealer(t, env),
		Recorder: env.audit, Enqueuer: executor, Authorizer: env.authz,
		From: mustFrom(t), MaxAttempts: 3, Now: func() time.Time { return deliveryStart },
	})
	if err != nil {
		t.Fatalf("投递服务: %v", err)
	}
	deliverHandler = service.Handler
	if err := executor.Start(ctx); err != nil {
		t.Fatalf("启动执行器: %v", err)
	}
	defer func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer stopCancel()
		_ = executor.Stop(stopCtx)
	}()

	result, err := service.Enqueue(ctx, verificationRequest("verify:user-e2e:email-1"))
	if err != nil {
		t.Fatalf("入队: %v", err)
	}
	deadline := time.Now().Add(8 * time.Second)
	for {
		record, err := env.store.Get(ctx, result.Record.ID)
		if err != nil {
			t.Fatalf("查询记录: %v", err)
		}
		if record.State == mailer.DeliverySucceeded {
			break
		}
		if record.State == mailer.DeliveryFailed {
			t.Fatalf("投递失败: %s %s", record.LastErrorCode, record.LastErrorKind)
		}
		if time.Now().After(deadline) {
			t.Fatalf("投递未在期限内完成，当前状态 %s", record.State)
		}
		time.Sleep(20 * time.Millisecond)
	}
	msgs := smtpServer.Snapshot(mailtest.Query{})
	if len(msgs) != 1 {
		t.Fatalf("testmail 应捕获 1 封，实际 %d", len(msgs))
	}
	if !strings.Contains(msgs[0].Subject, "邮箱验证") {
		t.Errorf("主题 = %q", msgs[0].Subject)
	}
	if !hasAudit(env.audit, "mail.delivered") {
		t.Error("缺少成功审计")
	}
}

// mustTemplates 返回默认模板集合（测试辅助）。
func mustTemplates(t *testing.T) *mailer.TemplateSet {
	t.Helper()
	templates, err := mailer.DefaultTemplateSet()
	if err != nil {
		t.Fatalf("模板: %v", err)
	}
	return templates
}

// mustSealer 返回测试加密器。
func mustSealer(t *testing.T, env *deliveryEnv) *secrets.Sealer {
	t.Helper()
	sealer, err := secrets.NewSealer(env.keyring, nil)
	if err != nil {
		t.Fatalf("加密器: %v", err)
	}
	return sealer
}

// mustFrom 返回测试发件地址。
func mustFrom(t *testing.T) mailer.Address {
	t.Helper()
	from, err := mailer.ParseAddress("noreply@example.test")
	if err != nil {
		t.Fatalf("发件地址: %v", err)
	}
	return from
}

// newServiceWithParts 用给定发送器/入队器/授权器构造投递服务。
func newServiceWithParts(t *testing.T, env *deliveryEnv, sender mailer.Sender, enqueuer mailer.Enqueuer, authorizer mailer.Authorizer) *mailer.DeliveryService {
	t.Helper()
	service, err := mailer.NewDeliveryService(mailer.DeliveryOptions{
		Store: env.store, Sender: sender, Templates: mustTemplates(t), Sealer: mustSealer(t, env),
		Recorder: env.audit, Enqueuer: enqueuer, Authorizer: authorizer, From: mustFrom(t),
		MaxAttempts: 3, Now: func() time.Time { return deliveryStart },
	})
	if err != nil {
		t.Fatalf("投递服务: %v", err)
	}
	return service
}

// userRequest 构造指定调用者的验证邮件入队请求。
func userRequest(t *testing.T, caller mailer.Caller, key string) mailer.EnqueueRequest {
	t.Helper()
	request := verificationRequest(key)
	request.Caller = caller
	return request
}

// TestDeliveryCrossCallerAuthorization 验证跨用户/跨调用者的查询、重试与幂等键
// 归属拒绝，以及受信系统主体在无授权器时仍可操作。
func TestDeliveryCrossCallerAuthorization(t *testing.T) {
	env := newDeliveryEnv(t)
	ctx := context.Background()
	userA := mustUserCaller(t, "user-A")
	userB := mustUserCaller(t, "user-B")

	result, err := env.service.Enqueue(ctx, userRequest(t, userA, "verify:user-A:email-1"))
	if err != nil {
		t.Fatalf("用户 A 入队: %v", err)
	}
	// 跨用户查询与重试按数据范围拒绝。
	if _, err := env.service.Get(ctx, userB, result.Record.ID); !errors.Is(err, mailer.ErrAccessDenied) {
		t.Errorf("跨用户查询应拒绝: %v", err)
	}
	if _, err := env.service.Retry(ctx, userB, result.Record.ID, ""); !errors.Is(err, mailer.ErrAccessDenied) {
		t.Errorf("跨用户重试应拒绝: %v", err)
	}
	// 幂等键归属不匹配：用户 B 复用 A 的键被拒绝，且不泄露 A 的收件人。
	if _, err := env.service.Enqueue(ctx, userRequest(t, userB, "verify:user-A:email-1")); !errors.Is(err, mailer.ErrAccessDenied) {
		t.Errorf("跨调用者幂等键应拒绝: %v", err)
	}
	// 同一调用者重复入队仍幂等。
	duplicate, err := env.service.Enqueue(ctx, userRequest(t, userA, "verify:user-A:email-1"))
	if err != nil || !duplicate.Duplicate || duplicate.Record.ID != result.Record.ID {
		t.Errorf("同调用者重复入队应幂等: %+v %v", duplicate, err)
	}

	// 未配置授权器：普通用户拒绝，受信系统主体允许。
	env.audit.events = nil
	trusted := newServiceWithParts(t, env, env.sender, env.enqueuer, nil)
	systemCaller := mustSystemCaller(t)
	trustedResult, err := trusted.Enqueue(ctx, userRequest(t, systemCaller, "verify:user-C:email-1"))
	if err != nil {
		t.Fatalf("受信系统主体入队: %v", err)
	}
	if _, err := trusted.Get(ctx, systemCaller, trustedResult.Record.ID); err != nil {
		t.Errorf("受信系统主体查询应允许: %v", err)
	}
	if _, err := trusted.Enqueue(ctx, userRequest(t, userA, "verify:user-D:email-1")); !errors.Is(err, mailer.ErrAccessDenied) {
		t.Errorf("无授权器时普通用户入队应拒绝: %v", err)
	}
}

// blockingSender 在发送中阻塞直到 ctx 取消，用于验证"发送中取消"的终态写入。
type blockingSender struct{}

func (b *blockingSender) Send(ctx context.Context, _ mailer.Message) error {
	<-ctx.Done()
	return ctx.Err()
}

// TestDeliveryCancelDuringSendRecordsState 验证发送中途取消时终态可靠写入
// （不再停留在 sending），并记录取消错误码。
func TestDeliveryCancelDuringSendRecordsState(t *testing.T) {
	env := newDeliveryEnv(t)
	service := newServiceWithParts(t, env, &blockingSender{}, env.enqueuer, env.authz)
	if _, err := service.Enqueue(context.Background(), verificationRequest("verify:user-cancel:email-1")); err != nil {
		t.Fatalf("入队: %v", err)
	}
	job := jobFromRequest(t, env, 1)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	_ = service.Handler(ctx, job)
	record, err := env.store.Get(context.Background(), jobDeliveryID(t, job))
	if err != nil {
		t.Fatalf("读取记录: %v", err)
	}
	// 发送中取消：任务不会再重试，必须落终态 failed + 取消码，才能经受控 Retry。
	if record.State != mailer.DeliveryFailed {
		t.Errorf("取消后应落终态 failed，实际 %s: %+v", record.State, record)
	}
	if record.LastErrorCode != mailer.CodeCancelled {
		t.Errorf("取消错误码 = %q，期望 %q", record.LastErrorCode, mailer.CodeCancelled)
	}
	if _, err := env.service.Retry(context.Background(), mustSystemCaller(t), record.ID, ""); err != nil {
		t.Fatalf("取消后受控重试: %v", err)
	}
}

// TestDeliveryListDataScope 验证列表数据范围：普通用户只能看到本人投递，受信系统
// 主体可看全量；跨用户不可枚举他人收件人。
func TestDeliveryListDataScope(t *testing.T) {
	env := newDeliveryEnv(t)
	ctx := context.Background()
	userA := mustUserCaller(t, "user-A")
	userB := mustUserCaller(t, "user-B")
	if _, err := env.service.Enqueue(ctx, userRequest(t, userA, "verify:list-A:email-1")); err != nil {
		t.Fatalf("用户 A 入队: %v", err)
	}
	if _, err := env.service.Enqueue(ctx, userRequest(t, userB, "verify:list-B:email-1")); err != nil {
		t.Fatalf("用户 B 入队: %v", err)
	}
	listA, err := env.service.List(ctx, userA, mailer.ListQuery{})
	if err != nil {
		t.Fatalf("用户 A 查询: %v", err)
	}
	if len(listA) != 1 || listA[0].OwnerID != "user-A" {
		t.Errorf("用户 A 只应看到本人记录，实际 %+v", listA)
	}
	listB, err := env.service.List(ctx, userB, mailer.ListQuery{})
	if err != nil {
		t.Fatalf("用户 B 查询: %v", err)
	}
	if len(listB) != 1 || listB[0].OwnerID != "user-B" {
		t.Errorf("用户 B 只应看到本人记录，实际 %+v", listB)
	}
	all, err := env.service.List(ctx, mustSystemCaller(t), mailer.ListQuery{})
	if err != nil {
		t.Fatalf("受信系统查询: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("受信系统应看到 2 条，实际 %d", len(all))
	}
	// 即使显式按他人收件人查询，普通用户也不能越权枚举。
	filtered, err := env.service.List(ctx, userA, mailer.ListQuery{Recipient: "user@example.test"})
	if err != nil {
		t.Fatalf("按收件人查询: %v", err)
	}
	if len(filtered) != 1 || filtered[0].OwnerID != "user-A" {
		t.Errorf("按收件人过滤仍应限制在本人范围，实际 %+v", filtered)
	}
}

// TestDeliveryRetryThenActualSend 验证失败记录经受控 Retry 后真实执行并经 testmail
// 实际收到邮件，记录终态 succeeded。
func TestDeliveryRetryThenActualSend(t *testing.T) {
	env := newDeliveryEnv(t)
	ctx := context.Background()
	if _, err := env.service.Enqueue(ctx, verificationRequest("verify:retry-send:email-1")); err != nil {
		t.Fatalf("入队: %v", err)
	}
	// 第一次尝试：永久失败 -> failed。
	env.sender.err = &mailer.SendError{Kind: mailer.FailurePermanent, Code: mailer.CodeAuthFailed, Err: mailer.ErrInvalidMessage}
	job := jobFromRequest(t, env, 1)
	if err := env.service.Handler(ctx, job); !task.IsNonRetryable(err) {
		t.Fatalf("首次失败应为不可重试: %v", err)
	}
	// 受控重试 -> queued + 新任务。
	if _, err := env.service.Retry(ctx, mustSystemCaller(t), jobDeliveryID(t, job), ""); err != nil {
		t.Fatalf("受控重试: %v", err)
	}
	// 用真实 SMTP 适配 + testmail 执行重试任务。
	server := startTestMailForDelivery(t)
	sender, err := mailer.NewSMTPSender(mailer.SMTPOptions{
		Addr: server.Addr().String(), TLSMode: mailer.TLSModeNone, AllowPlaintextLocal: true,
	})
	if err != nil {
		t.Fatalf("SMTP 发送器: %v", err)
	}
	retryService := newServiceWithParts(t, env, sender, env.enqueuer, env.authz)
	retryJob := jobFromRequest(t, env, 1)
	if err := retryService.Handler(ctx, retryJob); err != nil {
		t.Fatalf("重试发送失败: %v", err)
	}
	msgs := server.Snapshot(mailtest.Query{})
	if len(msgs) != 1 {
		t.Fatalf("testmail 应收到 1 封，实际 %d", len(msgs))
	}
	record, err := env.store.Get(ctx, jobDeliveryID(t, job))
	if err != nil {
		t.Fatalf("读取记录: %v", err)
	}
	if record.State != mailer.DeliverySucceeded {
		t.Errorf("重试后状态 = %s，期望 succeeded", record.State)
	}
}

// startTestMailForDelivery 启动 Mail 测试夹具作为本地 SMTP 捕获服务器。
func startTestMailForDelivery(t *testing.T) *mailtest.Instance {
	t.Helper()
	return mailtest.Start(t, mailtest.Options{Required: true, SMTPAuthNone: true})
}
