package webhook_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/netguard"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/securityevent"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/internal/webhook"
	webhooksqlite "github.com/kagurazakayashi/EvernightLogin/internal/webhook/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const (
	testAppA  = "app_00000000000000000000000000000001"
	testAppB  = "app_00000000000000000000000000000002"
	testUser  = "usr_00000000000000000000000000000001"
	testUser2 = "usr_00000000000000000000000000000002"
)

// fakeAuthorizer 是 management/query 授权测试替身。
type fakeAuthorizer struct{ deny bool }

func (f *fakeAuthorizer) Authorize(_ context.Context, _ webhook.Caller, _ webhook.Action,
	_ string) error {
	if f.deny {
		return errors.New("denied")
	}
	return nil
}

// fakeSensitive 是敏感策略执行器测试替身（生产为 *reauth.Service）。
type fakeSensitive struct{ deny bool }

func (f *fakeSensitive) Authorize(_ context.Context, _ reauth.Caller,
	request reauth.Request) (reauth.Result, error) {
	if f.deny {
		return reauth.Result{}, reauth.ErrAccessDenied
	}
	return reauth.Result{OperationID: request.OperationID}, nil
}

func (f *fakeSensitive) NotifyOutcome(_ context.Context, _ reauth.Result, _ reauth.Outcome) error {
	return nil
}

// fakeEnqueuer 记录入队请求；测试直接调用 Handler 执行投递。
type fakeEnqueuer struct {
	mu   sync.Mutex
	jobs []task.EnqueueRequest
}

func (f *fakeEnqueuer) Enqueue(_ context.Context, request task.EnqueueRequest) (task.Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.jobs = append(f.jobs, request)
	return task.Job{ID: "job_" + request.Kind, Kind: request.Kind}, nil
}

type fakeCanceller struct{ accepted bool }

func (f *fakeCanceller) RequestCancel(_ context.Context,
	_ task.CancelRequest) (task.CancelResult, error) {
	return task.CancelResult{Accepted: f.accepted, State: task.StateCancelled}, nil
}

type fakeResolver struct{ ips []string }

func (f *fakeResolver) LookupIPAddr(_ context.Context, _ string) ([]net.IPAddr, error) {
	addresses := make([]net.IPAddr, 0, len(f.ips))
	for _, value := range f.ips {
		addresses = append(addresses, net.IPAddr{IP: net.ParseIP(value)})
	}
	return addresses, nil
}

type testEnv struct {
	t          *testing.T
	ctx        context.Context
	raw        *storagesqlite.Store
	service    *webhook.Service
	authorizer *fakeAuthorizer
	sensitive  *fakeSensitive
	enqueuer   *fakeEnqueuer
}

func newTestEnv(t *testing.T, resolver netguard.IPResolver) *testEnv {
	t.Helper()
	ctx := context.Background()
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(
		filepath.Join(testutil.TempDir(t), "webhook-test.db")))
	if err != nil {
		t.Fatalf("打开数据库: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	list, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移: %v", err)
	}
	if _, err := raw.Migrate(ctx, list); err != nil {
		t.Fatalf("执行迁移: %v", err)
	}
	auditStore, err := auditsqlite.New(raw)
	if err != nil {
		t.Fatalf("审计存储: %v", err)
	}
	now := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	recorder, err := audit.New(auditStore, audit.Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("审计: %v", err)
	}
	keyring, err := secrets.GenerateKeyring("webhook-k1", now)
	if err != nil {
		t.Fatalf("密钥环: %v", err)
	}
	sealer, err := secrets.NewSealer(keyring, nil)
	if err != nil {
		t.Fatalf("Sealer: %v", err)
	}
	store, err := webhooksqlite.New(raw)
	if err != nil {
		t.Fatalf("Webhook 存储: %v", err)
	}
	authorizer := &fakeAuthorizer{}
	sensitive := &fakeSensitive{}
	enqueuer := &fakeEnqueuer{}
	service, err := webhook.New(webhook.Options{
		Store: store, Audit: recorder, Authorizer: authorizer, Sensitive: sensitive,
		Sealer: sealer, Enqueuer: enqueuer, Canceller: &fakeCanceller{accepted: true},
		Resolver: resolver, NetworkPolicy: netguard.Policy{Timeout: 5 * time.Second,
			TestOnlyAllowLocalEndpoints: true},
		MaxAttempts: 2, TimeoutSeconds: 5, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("Webhook 服务: %v", err)
	}
	env := &testEnv{t: t, ctx: ctx, raw: raw, service: service,
		authorizer: authorizer, sensitive: sensitive, enqueuer: enqueuer}
	env.seed()
	return env
}

func (e *testEnv) seed() {
	now := time.Now().UTC().UnixMilli()
	for _, app := range []string{testAppA, testAppB} {
		e.exec(`INSERT INTO applications(id,name,status,client_type,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,'active','public',1,?,?)`, app, "app-"+app[len(app)-2:], now, now)
	}
	for _, user := range []string{testUser, testUser2} {
		e.exec(`INSERT INTO users(id,username,username_normalized,nickname,status,is_root,
security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,'active',0,1,1,?,?)`, user, user, strings.ToLower(user), user, now, now)
	}
	// testUser 同时是 A/B 成员；testUser2 只是 B 成员。
	e.exec(`INSERT INTO app_memberships(app_id,user_id,status,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,'active',1,?,?)`, testAppA, testUser, now, now)
	e.exec(`INSERT INTO app_memberships(app_id,user_id,status,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,'active',1,?,?)`, testAppB, testUser, now, now)
	e.exec(`INSERT INTO app_memberships(app_id,user_id,status,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,'active',1,?,?)`, testAppB, testUser2, now, now)
}

func (e *testEnv) exec(query string, args ...any) {
	e.t.Helper()
	if _, err := e.raw.DB().ExecContext(e.ctx, query, args...); err != nil {
		e.t.Fatalf("执行 SQL: %v", err)
	}
}

func (e *testEnv) count(query string, args ...any) int {
	e.t.Helper()
	var value int
	if err := e.raw.DB().QueryRowContext(e.ctx, query, args...).Scan(&value); err != nil {
		e.t.Fatalf("计数: %v", err)
	}
	return value
}

func systemCaller(t *testing.T) webhook.Caller {
	t.Helper()
	caller, err := webhook.SystemCaller("test-system")
	if err != nil {
		t.Fatalf("系统调用者: %v", err)
	}
	return caller
}

func (e *testEnv) registerEndpoint(t *testing.T, appID, url string) (webhook.Endpoint, string) {
	t.Helper()
	result, err := e.service.RegisterEndpoint(e.ctx, systemCaller(t),
		webhook.RegisterEndpointRequest{ApplicationID: appID, URL: url,
			Description: "test", RequestID: "req_register_" + appID[len(appID)-2:]})
	if err != nil {
		t.Fatalf("登记端点: %v", err)
	}
	return result.Endpoint, result.Secret.Reveal()
}

func (e *testEnv) emit(t *testing.T, eventType securityevent.Type, appID, userID, key string) {
	t.Helper()
	if err := e.service.Emit(e.ctx, securityevent.Event{
		Type: eventType, ApplicationID: appID, UserID: userID,
		IdempotencyKey: key, OccurredAt: time.Now().UTC(),
		RequestID: "req_emit",
	}); err != nil {
		t.Fatalf("Emit 失败: %v", err)
	}
}

func (e *testEnv) deliveries(t *testing.T) []webhook.Delivery {
	t.Helper()
	list, err := e.service.ListDeliveries(e.ctx, systemCaller(t),
		webhook.ListDeliveriesQuery{ApplicationID: testAppA})
	if err != nil {
		t.Fatalf("查询投递: %v", err)
	}
	return list
}

func (e *testEnv) getDelivery(t *testing.T, id string) webhook.Delivery {
	t.Helper()
	delivery, err := e.service.GetDelivery(e.ctx, systemCaller(t), id)
	if err != nil {
		t.Fatalf("读取投递: %v", err)
	}
	return delivery
}

func jobFor(t *testing.T, delivery webhook.Delivery, attempt int) task.Job {
	t.Helper()
	payload, err := json.Marshal(map[string]string{"delivery_id": delivery.ID})
	if err != nil {
		t.Fatalf("任务载荷: %v", err)
	}
	return task.Job{ID: delivery.TaskID, Kind: webhook.TaskKindWebhookDelivery,
		Payload: payload, Attempt: attempt,
		Initiator: audit.Actor{Type: audit.ActorSystem, ID: "test"}}
}

func newCaptureServer(t *testing.T, statuses []int) (*httptest.Server, *capture) {
	t.Helper()
	captured := &capture{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		captured.record(r.Header.Clone(), body)
		status := http.StatusOK
		if len(statuses) > 0 {
			status = statuses[0]
			if len(statuses) > 1 {
				statuses = statuses[1:]
			}
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(server.Close)
	return server, captured
}

type capture struct {
	mu      sync.Mutex
	headers []http.Header
	bodies  [][]byte
}

func (c *capture) record(header http.Header, body []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.headers = append(c.headers, header)
	c.bodies = append(c.bodies, body)
}

func (c *capture) last() (http.Header, []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.headers) == 0 {
		return nil, nil
	}
	return c.headers[len(c.headers)-1], c.bodies[len(c.bodies)-1]
}

// ===== 端点与密钥 =====

func TestEndpointAndSecretLifecycle(t *testing.T) {
	server, _ := newCaptureServer(t, nil)
	env := newTestEnv(t, nil)
	endpoint, secret := env.registerEndpoint(t, testAppA, server.URL+"/hook")
	if len(secret) < 40 {
		t.Fatalf("签名密钥长度异常: %q", secret)
	}
	if got := env.count(`SELECT COUNT(*) FROM webhook_endpoint_secrets
WHERE instr(hex(sealed_secret),?)>0`, secret); got != 0 {
		t.Fatal("签名密钥明文出现在数据库密文列中")
	}
	infos, err := env.service.ListSecrets(env.ctx, systemCaller(t), endpoint.ID)
	if err != nil || len(infos) != 1 || infos[0].Prefix != secret[:8] {
		t.Fatalf("密钥元数据异常: %v %+v", err, infos)
	}
	// 轮换：旧密钥退役过渡期，新密钥返回一次；双签名都可验证。
	rotated, err := env.service.RotateSecret(env.ctx, systemCaller(t), endpoint.ID,
		"req_rotate")
	if err != nil || rotated.Reveal() == "" || rotated.Reveal() == secret {
		t.Fatalf("轮换失败: %v", err)
	}
	infos, _ = env.service.ListSecrets(env.ctx, systemCaller(t), endpoint.ID)
	if len(infos) != 2 {
		t.Fatalf("轮换后密钥数 = %d，期望 2", len(infos))
	}
	body := []byte(`{"a":1}`)
	timestamp := time.Now().Unix()
	header := webhook.SignatureHeader(timestamp, []string{
		webhook.Sign([]byte(secret), timestamp, body),
		webhook.Sign([]byte(rotated.Reveal()), timestamp, body),
	})
	if !webhook.VerifySignature([][]byte{[]byte(secret)}, header, body,
		time.Unix(timestamp, 0), 0) ||
		!webhook.VerifySignature([][]byte{[]byte(rotated.Reveal())}, header, body,
			time.Unix(timestamp, 0), 0) {
		t.Fatal("过渡期双签名应均可验证")
	}
	// 未授权管理操作 fail-closed。
	env.sensitive.deny = true
	if err := env.service.RevokeSecret(env.ctx, systemCaller(t), endpoint.ID,
		infos[0].ID, "req_revoke_denied"); !errors.Is(err, webhook.ErrAccessDenied) {
		t.Fatalf("敏感策略拒绝 error = %v，期望拒绝", err)
	}
	env.sensitive.deny = false
	if _, err := env.service.RegisterEndpoint(env.ctx, systemCaller(t),
		webhook.RegisterEndpointRequest{ApplicationID: testAppA,
			URL: "http://localhost:9999/hook", RequestID: "req_ssrf"}); !errors.Is(err,
		webhook.ErrEndpointBlocked) {
		// 测试模式允许回环 http，但生产策略必须拒绝（见 netguard 单测）。
		t.Logf("测试模式回环 http 登记: %v", err)
	}
}

func TestSignatureTamperAndTimeWindow(t *testing.T) {
	secret := []byte("test-signing-secret-0123456789abcdef")
	body := []byte(`{"id":"whev_1","type":"user.disabled"}`)
	now := time.Now()
	header := webhook.SignatureHeader(now.Unix(), []string{webhook.Sign(secret, now.Unix(), body)})
	if !webhook.VerifySignature([][]byte{secret}, header, body, now, 0) {
		t.Fatal("正确签名验证失败")
	}
	if webhook.VerifySignature([][]byte{secret}, header,
		[]byte(`{"id":"whev_1","type":"user.disabled","x":1}`), now, 0) {
		t.Fatal("篡改 body 后验签不应通过")
	}
	if webhook.VerifySignature([][]byte{[]byte("other-secret")}, header, body, now, 0) {
		t.Fatal("错误密钥验签不应通过")
	}
	old := now.Add(-10 * time.Minute)
	oldHeader := webhook.SignatureHeader(old.Unix(), []string{webhook.Sign(secret, old.Unix(), body)})
	if webhook.VerifySignature([][]byte{secret}, oldHeader, body, now, 0) {
		t.Fatal("超时间窗签名不应通过")
	}
	if !webhook.VerifySignature([][]byte{secret}, oldHeader, body, now, 15*time.Minute) {
		t.Fatal("显式放宽容差后应通过")
	}
}

// ===== Emit 幂等与扇出 =====

func TestEmitFanoutAndIdempotency(t *testing.T) {
	serverA, _ := newCaptureServer(t, nil)
	serverB, _ := newCaptureServer(t, nil)
	env := newTestEnv(t, nil)
	env.registerEndpoint(t, testAppA, serverA.URL)
	env.registerEndpoint(t, testAppB, serverB.URL)
	key := "user.disabled:" + testUser + ":req1"
	env.emit(t, securityevent.TypeUserDisabled, "", testUser, key)
	env.emit(t, securityevent.TypeUserDisabled, "", testUser, key)
	if got := env.count(`SELECT COUNT(*) FROM webhook_events`); got != 1 {
		t.Fatalf("事件数 = %d，期望 1（幂等）", got)
	}
	if got := env.count(`SELECT COUNT(*) FROM webhook_deliveries`); got != 2 {
		t.Fatalf("用户级扇出投递数 = %d，期望 2（A/B 成员）", got)
	}
	env.emit(t, securityevent.TypeUserDisabled, "", testUser2, "user.disabled:"+testUser2+":req2")
	// testUser2 只属于 B：不应再向 A 增加投递。
	if got := env.count(`SELECT COUNT(*) FROM webhook_deliveries WHERE application_id=?`,
		testAppA); got != 1 {
		t.Fatalf("应用 A 投递数 = %d，期望 1", got)
	}
	// 未授权查询 fail-closed。
	env.authorizer.deny = true
	if _, err := env.service.ListDeliveries(env.ctx, systemCaller(t),
		webhook.ListDeliveriesQuery{ApplicationID: testAppA}); !errors.Is(err,
		webhook.ErrAccessDenied) {
		t.Fatalf("未授权查询 error = %v，期望拒绝", err)
	}
}

// ===== 投递成功 / 重试耗尽 =====

func TestDeliverSuccessAndRetryExhaustion(t *testing.T) {
	server, captured := newCaptureServer(t, []int{http.StatusInternalServerError,
		http.StatusInternalServerError})
	env := newTestEnv(t, nil)
	endpoint, secret := env.registerEndpoint(t, testAppA, server.URL)
	env.emit(t, securityevent.TypeAppLogout, testAppA, testUser, "app.logout:s1")
	delivery := env.deliveries(t)[0]
	if err := env.service.Handler(env.ctx, jobFor(t, delivery, 1)); err == nil {
		t.Fatal("500 响应应返回可重试错误")
	}
	if got := env.getDelivery(t, delivery.ID); got.State != webhook.DeliveryQueued {
		t.Fatalf("重试排队状态 = %q，期望 queued", got.State)
	}
	header, body := captured.last()
	if header.Get("X-Evernight-Event-Id") == "" ||
		header.Get("X-Evernight-Signature") == "" {
		t.Fatal("投递缺少签名头")
	}
	timestamp := header.Get("X-Evernight-Timestamp")
	var unixTimestamp int64
	if _, err := fmt.Sscan(timestamp, &unixTimestamp); err != nil {
		t.Fatalf("解析时间戳: %v", err)
	}
	// 消费方验证：签名覆盖实际传输字节。
	if !webhook.VerifySignature([][]byte{[]byte(secret)},
		header.Get("X-Evernight-Signature"), body, time.Unix(unixTimestamp, 0), 0) {
		t.Fatal("消费方验签失败")
	}
	// 第二次尝试（maxAttempts=2）耗尽 → failed + WEBHOOK_DELIVERY_FAILED。
	if err := env.service.Handler(env.ctx, jobFor(t, delivery, 2)); err == nil {
		t.Fatal("重试耗尽应返回不可重试错误")
	}
	got := env.getDelivery(t, delivery.ID)
	if got.State != webhook.DeliveryFailed ||
		got.LastErrorCode != string(webhook.CodeWebhookDeliveryFailed) {
		t.Fatalf("终态 = %+v，期望 failed + WEBHOOK_DELIVERY_FAILED", got)
	}
	// 成功路径：新端点返回 200。
	successServer, successCapture := newCaptureServer(t, nil)
	_, successSecret := env.registerEndpoint(t, testAppB, successServer.URL)
	env.emit(t, securityevent.TypeAppLogout, testAppB, testUser, "app.logout:s2")
	list, err := env.service.ListDeliveries(env.ctx, systemCaller(t),
		webhook.ListDeliveriesQuery{ApplicationID: testAppB})
	if err != nil || len(list) == 0 {
		t.Fatalf("应用 B 投递查询失败: %v", err)
	}
	second := list[0]
	if err := env.service.Handler(env.ctx, jobFor(t, second, 1)); err != nil {
		t.Fatalf("成功投递失败: %v", err)
	}
	if got := env.getDelivery(t, second.ID); got.State != webhook.DeliverySucceeded {
		t.Fatalf("成功投递状态 = %q", got.State)
	}
	finalHeader, finalBody := successCapture.last()
	timestamp = finalHeader.Get("X-Evernight-Timestamp")
	if _, err := fmt.Sscan(timestamp, &unixTimestamp); err != nil {
		t.Fatalf("解析成功投递时间戳: %v", err)
	}
	if !webhook.VerifySignature([][]byte{[]byte(successSecret)},
		finalHeader.Get("X-Evernight-Signature"), finalBody, time.Unix(unixTimestamp, 0), 0) {
		t.Fatal("成功投递验签失败")
	}
	_ = endpoint
}

// ===== 取消 =====

func TestCancelDelivery(t *testing.T) {
	server, _ := newCaptureServer(t, nil)
	env := newTestEnv(t, nil)
	env.registerEndpoint(t, testAppA, server.URL)
	env.emit(t, securityevent.TypeAppLogout, testAppA, testUser, "app.logout:cancel")
	delivery := env.deliveries(t)[0]
	env.exec(`UPDATE webhook_deliveries SET task_id='job_cancel' WHERE id=?`, delivery.ID)
	if err := env.service.CancelDelivery(env.ctx, systemCaller(t), delivery.ID,
		"operator_cancel", "req_cancel"); err != nil {
		t.Fatalf("取消投递失败: %v", err)
	}
	if got := env.getDelivery(t, delivery.ID); got.State != webhook.DeliveryCancelled {
		t.Fatalf("取消后状态 = %q，期望 cancelled", got.State)
	}
	if err := env.service.CancelDelivery(env.ctx, systemCaller(t), delivery.ID, "again",
		"req_again"); !errors.Is(err, webhook.ErrDeliveryConflict) {
		t.Fatalf("终态取消 error = %v，期望状态冲突", err)
	}
}

// ===== 应用停用后投递永久失败 =====

func TestDeliveryApplicationDisabled(t *testing.T) {
	server, captured := newCaptureServer(t, nil)
	env := newTestEnv(t, nil)
	env.registerEndpoint(t, testAppA, server.URL)
	env.emit(t, securityevent.TypeAppLogout, testAppA, testUser, "app.logout:disabled")
	delivery := env.deliveries(t)[0]
	env.exec(`UPDATE applications SET status='disabled' WHERE id=?`, testAppA)
	if err := env.service.Handler(env.ctx, jobFor(t, delivery, 1)); err == nil {
		t.Fatal("应用停用后投递应失败")
	}
	if got := env.getDelivery(t, delivery.ID); got.State != webhook.DeliveryFailed {
		t.Fatalf("应用停用后状态 = %q，期望 failed", got.State)
	}
	if header, _ := captured.last(); header != nil {
		t.Fatal("应用停用后不应发出 HTTP 请求")
	}
}

// ===== 事件白名单 =====

func TestEventValidationRejectsUnknownData(t *testing.T) {
	env := newTestEnv(t, nil)
	server, _ := newCaptureServer(t, nil)
	env.registerEndpoint(t, testAppA, server.URL)
	err := env.service.Emit(env.ctx, securityevent.Event{
		Type: securityevent.TypeUserDisabled, UserID: testUser,
		IdempotencyKey: "user.disabled:bad:data", OccurredAt: time.Now().UTC(),
		Data: map[string]string{"free_text": "arbitrary input"},
	})
	if !errors.Is(err, webhook.ErrEventInvalid) {
		t.Fatalf("未知事件字段 error = %v，期望拒绝", err)
	}
	if got := env.count(`SELECT COUNT(*) FROM webhook_events`); got != 0 {
		t.Fatalf("非法事件不应落库，事件数 = %d", got)
	}
}

// ===== 超时语义（B1 修复） =====

// TestDeliveryRequestTimeoutRetryAndControlledRetry 验证慢端点触发单次请求超时：
// 记为超时失败（TASK_TIMEOUT、非取消），未耗尽回 queued/可重试，耗尽后 failed 且
// 可受控 RetryDelivery。
func TestDeliveryRequestTimeoutRetryAndControlledRetry(t *testing.T) {
	blocking := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-blocking // 挂起直到测试结束
	}))
	defer server.Close()
	defer close(blocking)
	env := newTestEnv(t, nil)
	env.registerEndpoint(t, testAppA, server.URL)
	env.emit(t, securityevent.TypeAppLogout, testAppA, testUser, "app.logout:timeout")
	delivery := env.deliveries(t)[0]
	// 第一次尝试：HTTP 请求超时（严格小于任务墙钟）→ queued + TASK_TIMEOUT。
	if err := env.service.Handler(env.ctx, jobFor(t, delivery, 1)); err == nil {
		t.Fatal("慢端点超时应返回可重试错误")
	}
	queued := env.getDelivery(t, delivery.ID)
	if queued.State != webhook.DeliveryQueued {
		t.Fatalf("超时未耗尽状态 = %q，期望 queued", queued.State)
	}
	if queued.LastErrorCode != "TASK_TIMEOUT" || queued.LastErrorKind != "timeout" {
		t.Fatalf("超时原因 = %q/%q，期望 TASK_TIMEOUT/timeout",
			queued.LastErrorCode, queued.LastErrorKind)
	}
	// 第二次尝试：重试耗尽 → failed + TASK_TIMEOUT（可受控重试）。
	if err := env.service.Handler(env.ctx, jobFor(t, delivery, 2)); err == nil {
		t.Fatal("重试耗尽应返回不可重试错误")
	}
	failed := env.getDelivery(t, delivery.ID)
	if failed.State != webhook.DeliveryFailed || failed.LastErrorCode != "TASK_TIMEOUT" {
		t.Fatalf("超时耗尽终态 = %q/%q，期望 failed/TASK_TIMEOUT",
			failed.State, failed.LastErrorCode)
	}
	retried, err := env.service.RetryDelivery(env.ctx, systemCaller(t), delivery.ID,
		"req_timeout_retry")
	if err != nil {
		t.Fatalf("超时 failed 应允许受控重试: %v", err)
	}
	if retried.State != webhook.DeliveryQueued {
		t.Fatalf("受控重试后状态 = %q，期望 queued", retried.State)
	}
}

// TestDeliveryWallClockDeadlineNotCancelled 验证任务墙钟期限到期不会被误记为取消。
func TestDeliveryWallClockDeadlineNotCancelled(t *testing.T) {
	server, _ := newCaptureServer(t, nil)
	env := newTestEnv(t, nil)
	env.registerEndpoint(t, testAppA, server.URL)
	env.emit(t, securityevent.TypeAppLogout, testAppA, testUser, "app.logout:deadline")
	delivery := env.deliveries(t)[0]
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	// 尝试未耗尽（attempt=1）也必须直接 failed：执行器对墙钟超时不再重排，若写
	// queued 会卡住且无法经 RetryDelivery 恢复。
	if err := env.service.Handler(expired, jobFor(t, delivery, 1)); err == nil {
		t.Fatal("墙钟已到期应返回失败错误")
	}
	got := env.getDelivery(t, delivery.ID)
	if got.State == webhook.DeliveryCancelled {
		t.Fatal("任务墙钟超时不得写成 cancelled")
	}
	if got.State != webhook.DeliveryFailed || got.LastErrorCode != "TASK_TIMEOUT" {
		t.Fatalf("墙钟超时终态 = %q/%q，期望 failed/TASK_TIMEOUT",
			got.State, got.LastErrorCode)
	}
	retried, err := env.service.RetryDelivery(env.ctx, systemCaller(t), delivery.ID,
		"req_wallclock_retry")
	if err != nil || retried.State != webhook.DeliveryQueued {
		t.Fatalf("墙钟超时 failed 应可受控重试: state=%q err=%v", retried.State, err)
	}
}

// TestDeliveryTrueCancelIsCancelled 验证只有明确取消才写 cancelled 且不可重试。
func TestDeliveryTrueCancelIsCancelled(t *testing.T) {
	server, _ := newCaptureServer(t, nil)
	env := newTestEnv(t, nil)
	env.registerEndpoint(t, testAppA, server.URL)
	env.emit(t, securityevent.TypeAppLogout, testAppA, testUser, "app.logout:cancel2")
	delivery := env.deliveries(t)[0]
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := env.service.Handler(cancelled, jobFor(t, delivery, 1)); err == nil {
		t.Fatal("取消应返回不可重试错误")
	}
	got := env.getDelivery(t, delivery.ID)
	if got.State != webhook.DeliveryCancelled || got.LastErrorCode != "TASK_CANCELLED" {
		t.Fatalf("明确取消终态 = %q/%q，期望 cancelled/TASK_CANCELLED",
			got.State, got.LastErrorCode)
	}
	if _, err := env.service.RetryDelivery(env.ctx, systemCaller(t), delivery.ID,
		"req_cancel_retry"); !errors.Is(err, webhook.ErrDeliveryConflict) {
		t.Fatalf("取消终态受控重试 error = %v，期望冲突", err)
	}
}
