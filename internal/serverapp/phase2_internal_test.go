package serverapp

// 本文件是 B1/B2 第二阶段的内部（白盒）真实测试：真实 SQLite + 真实领域服务，
// 覆盖访问日志轮转、单实例数据库锁、协议/管理 API 挂载点、后台任务运行时
// （执行器 + 调度器 + 邮件/Webhook 处理器）以及页面会话语义中的强认证管理门禁。
// 所有用例使用 t.TempDir；不读写仓库数据库、不真实外发、不遗留监听端口。

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	accountsqlite "github.com/kagurazakayashi/EvernightLogin/internal/account/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	sessionsqlite "github.com/kagurazakayashi/EvernightLogin/internal/session/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// testNow 是确定性时钟基准。
var testNow = time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC)

// openMigratedStore 打开并迁移一个隔离 SQLite 数据库。
func openMigratedStore(t *testing.T) *storagesqlite.Store {
	t.Helper()
	path := filepath.Join(testutil.TempDir(t), "login.db")
	ctx := context.Background()
	store, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(path))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	migrationSet, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		store.Close()
		t.Fatalf("加载迁移清单失败: %v", err)
	}
	if _, err := store.Migrate(ctx, migrationSet); err != nil {
		store.Close()
		t.Fatalf("迁移测试数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// newTestAudit 构造真实审计写入器。
func newTestAudit(t *testing.T, store *storagesqlite.Store) *audit.Recorder {
	t.Helper()
	auditStore, err := auditsqlite.New(store)
	if err != nil {
		t.Fatalf("构造审计存储失败: %v", err)
	}
	recorder, err := audit.New(auditStore, audit.Options{
		Now:    func() time.Time { return testNow },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("构造审计写入器失败: %v", err)
	}
	return recorder
}

// newTestKeyring 生成测试主密钥环（只存在内存，不落盘）。
func newTestKeyring(t *testing.T) *secrets.Keyring {
	t.Helper()
	ring, err := secrets.GenerateKeyring("k1", testNow)
	if err != nil {
		t.Fatalf("生成测试密钥环失败: %v", err)
	}
	return ring
}

// ===== 访问日志轮转 =====

// TestRotatingLogWriterRotatesAndRetains 验证按大小轮转、历史文件上限与受保护权限。
func TestRotatingLogWriterRotatesAndRetains(t *testing.T) {
	dir := testutil.TempDir(t)
	path := filepath.Join(dir, "logs", "access.log")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	writer, err := NewRotatingLogWriter(path, 1<<20, 3, logger)
	if err != nil {
		t.Fatalf("构造轮转写入器失败: %v", err)
	}
	// 为了在测试里快速触发轮转，用小上限；构造器下限是 1 MiB，直接用 1 MiB
	// 并写入超过 4 个上限的数据。
	chunk := strings.Repeat("x", 256<<10) // 256 KiB
	for index := 0; index < 20; index++ {
		if _, err := writer.Write([]byte(chunk + "\n")); err != nil {
			t.Fatalf("第 %d 次写入失败: %v", index, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("关闭轮转写入器失败: %v", err)
	}
	currentInfo, statErr := os.Stat(path)
	if statErr != nil {
		t.Fatalf("当前访问日志文件不存在: %v", statErr)
	}
	if currentInfo.Size() > 1<<20 {
		t.Fatalf("当前访问日志文件超过上限: %d 字节", currentInfo.Size())
	}
	rotated := 0
	for index := 1; index <= 3; index++ {
		info, statErr := os.Stat(fmt.Sprintf("%s.%d", path, index))
		if statErr != nil {
			continue
		}
		rotated++
		if info.Size() > 1<<20 {
			t.Fatalf("历史访问日志 %d 超过上限: %d 字节", index, info.Size())
		}
	}
	if rotated == 0 {
		t.Fatal("期望发生访问日志轮转，但没有任何历史文件")
	}
	if _, statErr := os.Stat(fmt.Sprintf("%s.4", path)); !os.IsNotExist(statErr) {
		t.Fatalf("历史文件数量超过上限：不应存在 .4 文件（err=%v）", statErr)
	}
	// 关闭后再次写入必须返回明确错误，而不是静默丢日志。
	if _, err := writer.Write([]byte("after-close")); err == nil {
		t.Fatal("关闭后的写入应返回错误")
	}
}

// TestRotatingLogWriterRejectsInvalidBounds 验证非法轮转配置 fail-closed。
func TestRotatingLogWriterRejectsInvalidBounds(t *testing.T) {
	dir := testutil.TempDir(t)
	path := filepath.Join(dir, "access.log")
	if _, err := NewRotatingLogWriter(path, 1, 1, nil); err == nil {
		t.Fatal("过小的单文件上限应被拒绝")
	}
	if _, err := NewRotatingLogWriter(path, 0, 1000, nil); err == nil {
		t.Fatal("过大的历史文件数量应被拒绝")
	}
}

// ===== 单实例锁 =====

// TestInstanceLockExclusive 验证同一数据库只允许一个实例，释放后可重新获取。
func TestInstanceLockExclusive(t *testing.T) {
	databasePath := filepath.Join(testutil.TempDir(t), "data", "login.db")
	if err := os.MkdirAll(filepath.Dir(databasePath), 0o700); err != nil {
		t.Fatalf("创建数据目录失败: %v", err)
	}
	first, err := AcquireInstanceLock(databasePath)
	if err != nil {
		t.Fatalf("首次获取单实例锁失败: %v", err)
	}
	if first.Path() == "" {
		t.Fatal("单实例锁路径为空")
	}
	second, secondErr := AcquireInstanceLock(databasePath)
	if secondErr == nil {
		second.Release()
		first.Release()
		t.Fatal("同一数据库第二次获取单实例锁应失败")
	}
	if !strings.Contains(secondErr.Error(), "单实例") {
		t.Fatalf("单实例冲突错误不明确: %v", secondErr)
	}
	first.Release()
	// Release 幂等。
	first.Release()
	third, err := AcquireInstanceLock(databasePath)
	if err != nil {
		t.Fatalf("释放后重新获取单实例锁失败: %v", err)
	}
	third.Release()
}

// ===== 协议/管理 API 挂载点 =====

// TestComposeHandlerMounts 验证挂载点路由、前缀剥离与非挂载路径回退。
func TestComposeHandlerMounts(t *testing.T) {
	base := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusTeapot)
		_, _ = writer.Write([]byte("base:" + request.URL.Path))
	})
	var seenPath string
	mount := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		seenPath = request.URL.Path
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("protocol"))
	})
	handler, err := ComposeHandler(base, "/base", []HandlerMount{
		{Name: "protocol", Prefix: "/protocol", Handler: mount},
	})
	if err != nil {
		t.Fatalf("构造挂载处理程序失败: %v", err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet,
		"http://127.0.0.1/base/protocol/token", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("挂载路径状态码 = %d，期望 200", recorder.Code)
	}
	if seenPath != "/token" {
		t.Fatalf("挂载处理程序看到路径 %q，期望 /token（前缀已剥离）", seenPath)
	}
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet,
		"http://127.0.0.1/base/login", nil))
	if recorder.Code != http.StatusTeapot {
		t.Fatalf("非挂载路径状态码 = %d，期望回退到基础处理程序（418）", recorder.Code)
	}
	// 相似前缀不能误匹配（/protocolx 不是挂载前缀）。
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet,
		"http://127.0.0.1/base/protocolx", nil))
	if recorder.Code != http.StatusTeapot {
		t.Fatalf("相似前缀状态码 = %d，期望回退到基础处理程序（418）", recorder.Code)
	}
}

// TestComposeHandlerPageFirstRoutes 验证 OAuth 页面与协议挂载共享路径时页面优先，
// 其它路径仍保持挂载点优先（步骤160 真实 serve /oauth/device 404 回归）。
func TestComposeHandlerPageFirstRoutes(t *testing.T) {
	base := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/base/oauth/device" {
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte("page"))
			return
		}
		writer.WriteHeader(http.StatusTeapot)
	})
	mount := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("mount"))
	})
	handler, err := ComposeHandler(base, "/base", []HandlerMount{
		{Name: "oauth", Prefix: "/oauth", Handler: mount},
	})
	if err != nil {
		t.Fatalf("构造挂载处理程序失败: %v", err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet,
		"http://127.0.0.1/base/oauth/device", nil))
	if recorder.Code != http.StatusOK || recorder.Body.String() != "page" {
		t.Fatalf("页面优先状态 = %d %q", recorder.Code, recorder.Body.String())
	}
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost,
		"http://127.0.0.1/base/oauth/token", nil))
	if recorder.Code != http.StatusOK || recorder.Body.String() != "mount" {
		t.Fatalf("协议挂载状态 = %d %q", recorder.Code, recorder.Body.String())
	}
}

// TestComposeHandlerRejectsInvalidMounts 验证非法挂载配置 fail-closed。
func TestComposeHandlerRejectsInvalidMounts(t *testing.T) {
	base := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	ok := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	cases := []struct {
		name   string
		mounts []HandlerMount
	}{
		{"空名称", []HandlerMount{{Prefix: "/a", Handler: ok}}},
		{"缺少处理程序", []HandlerMount{{Name: "a", Prefix: "/a"}}},
		{"非绝对前缀", []HandlerMount{{Name: "a", Prefix: "a", Handler: ok}}},
		{"点段", []HandlerMount{{Name: "a", Prefix: "/../x", Handler: ok}}},
		{"重复前缀", []HandlerMount{
			{Name: "a", Prefix: "/a", Handler: ok},
			{Name: "b", Prefix: "/a", Handler: ok},
		}},
		{"嵌套前缀", []HandlerMount{
			{Name: "a", Prefix: "/a", Handler: ok},
			{Name: "b", Prefix: "/a/b", Handler: ok},
		}},
		{"覆盖健康检查", []HandlerMount{{Name: "a", Prefix: "/healthz", Handler: ok}}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := ComposeHandler(base, "", testCase.mounts); err == nil {
				t.Fatalf("非法挂载配置未被拒绝: %s", testCase.name)
			}
		})
	}
	if handler, err := ComposeHandler(base, "", nil); err != nil || handler == nil {
		t.Fatalf("无挂载时应原样返回基础处理程序: %v", err)
	}
}

// ===== 后台任务运行时 =====

// waitJobTerminal 轮询任务直至进入终态或超时。
func waitJobTerminal(t *testing.T, ctx context.Context, runtime *TaskRuntime,
	jobID string, timeout time.Duration) task.Job {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		job, found, err := runtime.store.Get(ctx, jobID)
		if err != nil {
			t.Fatalf("读取任务状态失败: %v", err)
		}
		if !found {
			t.Fatalf("任务 %s 不存在", jobID)
		}
		switch job.State {
		case task.StateSucceeded, task.StateFailed, task.StateCancelled:
			return job
		}
		if time.Now().After(deadline) {
			t.Fatalf("任务 %s 在 %s 内未进入终态（当前 %s）", jobID, timeout, job.State)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// TestTaskRuntimeRunsMailDeliveryAndFailsClosed 验证任务运行时真实启动、邮件投递
// 处理器被执行，且“未配置真实发送器”的投递以明确失败结束（不真实外发）。
func TestTaskRuntimeRunsMailDeliveryAndFailsClosed(t *testing.T) {
	store := openMigratedStore(t)
	auditRecorder := newTestAudit(t, store)
	keyring := newTestKeyring(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	deps := Deps{Store: store, Keyring: keyring, Audit: auditRecorder,
		Logger: logger, Now: func() time.Time { return testNow }}
	runtime, err := BuildTaskRuntimeLegacy(deps)
	if err != nil {
		t.Fatalf("构造后台任务运行时失败: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := runtime.Start(ctx); err != nil {
		t.Fatalf("启动后台任务运行时失败: %v", err)
	}
	defer func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer closeCancel()
		if err := runtime.Close(closeCtx); err != nil {
			t.Errorf("关闭后台任务运行时失败: %v", err)
		}
	}()
	caller, err := mailer.SystemCaller("test.notifier")
	if err != nil {
		t.Fatalf("构造系统投递操作者失败: %v", err)
	}
	notice := &mailer.SecurityNoticeData{
		DisplayName: "测试用户", Event: "测试事件",
		OccurredAt: testNow.Format(time.RFC3339), ClientInfo: "test", AppName: "EvernightLogin",
		SupportURL: "https://example.test/support",
	}
	enqueued, err := runtime.Mail().Enqueue(ctx, mailer.EnqueueRequest{
		Caller: caller, IdempotencyKey: "test-mail-delivery-1",
		Kind: mailer.KindSecurityNotice, Recipient: "user@example.test",
		Data:      mailer.RenderRequest{Kind: mailer.KindSecurityNotice, Notice: notice},
		RequestID: login.NewRequestID(), MaxAttempts: 1,
	})
	if err != nil {
		t.Fatalf("入队邮件投递失败: %v", err)
	}
	if enqueued.Record.TaskID == "" {
		t.Fatal("邮件投递记录缺少任务 ID")
	}
	job := waitJobTerminal(t, context.Background(), runtime, enqueued.Record.TaskID, 15*time.Second)
	if job.State != task.StateFailed {
		t.Fatalf("未配置真实发送器的邮件投递任务状态 = %s，期望 failed", job.State)
	}
	delivery, err := runtime.Mail().Get(context.Background(), caller, enqueued.Record.ID)
	if err != nil {
		t.Fatalf("读取邮件投递记录失败: %v", err)
	}
	if delivery.State != mailer.DeliveryFailed {
		t.Fatalf("投递记录状态 = %s，期望 failed", delivery.State)
	}
	if delivery.LastErrorCode == "" {
		t.Fatal("投递失败未记录稳定错误码")
	}
	if delivery.LastErrorCode == mailer.CodeCancelled {
		t.Fatalf("未配置发送器不应记为取消：%s", delivery.LastErrorCode)
	}
	// 重复入队同一幂等键返回既有记录（不重复建任务）。
	again, err := runtime.Mail().Enqueue(ctx, mailer.EnqueueRequest{
		Caller: caller, IdempotencyKey: "test-mail-delivery-1",
		Kind: mailer.KindSecurityNotice, Recipient: "user@example.test",
		Data:      mailer.RenderRequest{Kind: mailer.KindSecurityNotice, Notice: notice},
		RequestID: login.NewRequestID(), MaxAttempts: 1,
	})
	if err != nil {
		t.Fatalf("重复入队失败: %v", err)
	}
	if !again.Duplicate || again.Record.ID != enqueued.Record.ID {
		t.Fatal("幂等入队未返回既有记录")
	}
}

// TestTaskRuntimeSchedulerStartsAndStops 验证调度器随运行时启动并可再次创建计划，
// 关闭幂等且 Stop 后可重复 Close。
func TestTaskRuntimeSchedulerStartsAndStops(t *testing.T) {
	store := openMigratedStore(t)
	deps := Deps{Store: store, Keyring: newTestKeyring(t), Audit: newTestAudit(t, store),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:    func() time.Time { return testNow }}
	runtime, err := BuildTaskRuntimeLegacy(deps)
	if err != nil {
		t.Fatalf("构造后台任务运行时失败: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := runtime.Start(ctx); err != nil {
		t.Fatalf("启动后台任务运行时失败: %v", err)
	}
	// 调度器真实可查询计划存储（当前为空）。
	if _, err := runtime.store.ListSchedules(ctx, true); err != nil {
		t.Fatalf("读取计划列表失败: %v", err)
	}
	// 重复启动不应重复创建协程，也不应报错。
	if err := runtime.Start(ctx); err != nil {
		t.Fatalf("重复启动应幂等: %v", err)
	}
	closeCtx, closeCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer closeCancel()
	if err := runtime.Close(closeCtx); err != nil {
		t.Fatalf("关闭后台任务运行时失败: %v", err)
	}
	if err := runtime.Close(closeCtx); err != nil {
		t.Fatalf("重复关闭应幂等: %v", err)
	}
}

// ===== 页面会话强认证管理门禁 =====

// allowAllAccountAuthorizer 是测试替身：仅在本测试内允许账户创建，不属于生产实现。
type allowAllAccountAuthorizer struct{}

// Authorize 实现 account.Authorizer。
func (allowAllAccountAuthorizer) Authorize(context.Context, account.Caller, account.Action) error {
	return nil
}

// newSessionForGateTest 用真实账户/会话服务构造一个测试用户会话。
func newSessionForGateTest(t *testing.T) (*session.Service, string) {
	t.Helper()
	store := openMigratedStore(t)
	auditRecorder := newTestAudit(t, store)
	accountStore, err := accountsqlite.New(store)
	if err != nil {
		t.Fatalf("构造账户存储失败: %v", err)
	}
	accountService, err := account.New(account.Options{
		Store: accountStore, Audit: auditRecorder, Authorizer: allowAllAccountAuthorizer{},
		Now: func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatalf("构造账户服务失败: %v", err)
	}
	caller, err := account.LocalBootstrapCaller("test.local-admin")
	if err != nil {
		t.Fatalf("构造本地账户操作者失败: %v", err)
	}
	created, err := accountService.CreateUser(context.Background(), caller, account.CreateRequest{
		Username: "page-user", Nickname: "页面用户", Language: "zh-CN", Timezone: "Asia/Shanghai",
	})
	if err != nil {
		t.Fatalf("创建测试用户失败: %v", err)
	}
	user, err := accountService.GetUser(context.Background(), caller, created.ID)
	if err != nil {
		t.Fatalf("读取测试用户失败: %v", err)
	}
	sessionStore, err := sessionsqlite.New(store)
	if err != nil {
		t.Fatalf("构造会话存储失败: %v", err)
	}
	service, err := session.New(sessionStore, session.Options{
		Store: sessionStore, Audit: auditRecorder, Keyring: newTestKeyring(t),
		Now: func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatalf("构造会话服务失败: %v", err)
	}
	return service, user.ID
}

// loginForGateTest 用真实会话服务签发会话；strong 决定是否携带强认证时间。
func loginForGateTest(t *testing.T, service *session.Service, userID string,
	strong bool) *http.Request {
	t.Helper()
	result := authn.AuthenticateResult{
		UserID: userID, Username: "page-user", Outcome: authn.OutcomeComplete,
		CompletedMethods: []authn.Method{authn.MethodPassword},
		CompletedAt:      testNow, SecurityVersion: 1,
	}
	if strong {
		result.StrongAuthCompletedAt = testNow
	}
	issued, err := service.Login(context.Background(), session.LoginRequest{
		Result: result, RequestID: login.NewRequestID(),
	})
	if err != nil {
		t.Fatalf("签发测试会话失败（strong=%v）: %v", strong, err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/", nil)
	request.AddCookie(&http.Cookie{
		Name: session.DefaultCookieName, Value: issued.Secret.Reveal()})
	return request
}

// TestPageSessionManagementStrongAuthGate 验证页面会话语义：只有真实完成强认证
// 且在新鲜度窗口内的会话才被标记为 management；普通密码会话不得获得管理访问。
func TestPageSessionManagementStrongAuthGate(t *testing.T) {
	service, userID := newSessionForGateTest(t)
	pages := pageSessions{service: service}
	ctx := context.Background()

	normalRequest := loginForGateTest(t, service, userID, false)
	normalSession, err := pages.ResolvePageSession(ctx, normalRequest)
	if err != nil {
		t.Fatalf("解析普通会话失败: %v", err)
	}
	if normalSession.Kind != "normal" {
		t.Fatalf("未完成强认证的会话 Kind = %q，期望 normal（管理页应 403）", normalSession.Kind)
	}

	// 管理 Kind 只发给管理页面命名空间；同一强认证会话在普通页面上保持 normal
	// （页面框架对 UIAccessUser/UIAccessManagement 的 Kind 判定互斥）。
	strongRequest := loginForGateTest(t, service, userID, true)
	strongRequest.URL.Path = "/admin/users"
	managementSession, err := pages.ResolvePageSession(ctx, strongRequest)
	if err != nil {
		t.Fatalf("解析强认证会话失败: %v", err)
	}
	if managementSession.Kind != "management" {
		t.Fatalf("已完成强认证的会话 Kind = %q，期望 management", managementSession.Kind)
	}
	if managementSession.UserID != userID {
		t.Fatalf("会话用户 ID = %q，期望 %q", managementSession.UserID, userID)
	}

	// 无 Cookie 的请求必须按会话过期处理，不返回匿名管理会话。
	if _, err := pages.ResolvePageSession(ctx,
		httptest.NewRequest(http.MethodGet, "http://127.0.0.1/", nil)); err == nil {
		t.Fatal("无会话 Cookie 的请求应返回会话过期错误")
	}
	// 伪造 Cookie 同样拒绝。
	forged := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/", nil)
	forged.AddCookie(&http.Cookie{Name: session.DefaultCookieName, Value: "forged-value"})
	if _, err := pages.ResolvePageSession(ctx, forged); err == nil {
		t.Fatal("伪造会话 Cookie 应被拒绝")
	}
}

// TestPageSessionStrongAuthExpires 验证强认证新鲜度窗口过期后管理标记消失。
func TestPageSessionStrongAuthExpires(t *testing.T) {
	store := openMigratedStore(t)
	auditRecorder := newTestAudit(t, store)
	keyring := newTestKeyring(t)
	accountStore, err := accountsqlite.New(store)
	if err != nil {
		t.Fatalf("构造账户存储失败: %v", err)
	}
	accountService, err := account.New(account.Options{
		Store: accountStore, Audit: auditRecorder, Authorizer: allowAllAccountAuthorizer{},
		Now: func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatalf("构造账户服务失败: %v", err)
	}
	caller, err := account.LocalBootstrapCaller("test.local-admin")
	if err != nil {
		t.Fatalf("构造本地账户操作者失败: %v", err)
	}
	created, err := accountService.CreateUser(context.Background(), caller, account.CreateRequest{
		Username: "expiry-user", Nickname: "过期用户", Language: "zh-CN", Timezone: "Asia/Shanghai",
	})
	if err != nil {
		t.Fatalf("创建测试用户失败: %v", err)
	}
	user, err := accountService.GetUser(context.Background(), caller, created.ID)
	if err != nil {
		t.Fatalf("读取测试用户失败: %v", err)
	}
	sessionStore, err := sessionsqlite.New(store)
	if err != nil {
		t.Fatalf("构造会话存储失败: %v", err)
	}
	service, err := session.New(sessionStore, session.Options{
		Store: sessionStore, Audit: auditRecorder, Keyring: keyring,
		Now: func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatalf("构造会话服务失败: %v", err)
	}
	issued, err := service.Login(context.Background(), session.LoginRequest{
		Result: authn.AuthenticateResult{
			UserID: user.ID, Username: "expiry-user", Outcome: authn.OutcomeComplete,
			CompletedMethods: []authn.Method{authn.MethodPassword}, CompletedAt: testNow,
			StrongAuthCompletedAt: testNow, SecurityVersion: 1,
		},
		RequestID: login.NewRequestID(),
	})
	if err != nil {
		t.Fatalf("签发强认证会话失败: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/admin/users", nil)
	request.AddCookie(&http.Cookie{Name: session.DefaultCookieName, Value: issued.Secret.Reveal()})
	pages := pageSessions{service: service}
	if resolved, err := pages.ResolvePageSession(context.Background(), request); err != nil {
		t.Fatalf("解析强认证会话失败: %v", err)
	} else if resolved.Kind != "management" {
		t.Fatalf("当前时间应可在管理窗口内，Kind = %q", resolved.Kind)
	}
	// 让真实时钟也前进（服务使用注入时钟，这里通过独立服务以偏移时钟重建）。
	later := testNow.Add(2 * time.Hour)
	laterRequest := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/", nil)
	laterStore, err := sessionsqlite.New(store)
	if err != nil {
		t.Fatalf("构造会话存储失败: %v", err)
	}
	laterService, err := session.New(laterStore, session.Options{
		Store: laterStore, Audit: auditRecorder, Keyring: keyring,
		Now: func() time.Time { return later },
	})
	if err != nil {
		t.Fatalf("构造会话服务失败: %v", err)
	}
	laterIssued, err := laterService.Login(context.Background(), session.LoginRequest{
		Result: authn.AuthenticateResult{
			UserID: user.ID, Username: "expiry-user", Outcome: authn.OutcomeComplete,
			CompletedMethods: []authn.Method{authn.MethodPassword}, CompletedAt: testNow,
			StrongAuthCompletedAt: testNow, SecurityVersion: 1,
		},
		RequestID: login.NewRequestID(),
	})
	if err != nil {
		t.Fatalf("签发过期窗口测试会话失败: %v", err)
	}
	laterRequest.AddCookie(&http.Cookie{Name: session.DefaultCookieName,
		Value: laterIssued.Secret.Reveal()})
	laterPages := pageSessions{service: laterService}
	if resolved, err := laterPages.ResolvePageSession(context.Background(), laterRequest); err != nil {
		t.Fatalf("解析过期窗口会话失败: %v", err)
	} else if resolved.Kind != "normal" {
		t.Fatalf("强认证超过新鲜度窗口后 Kind = %q，期望 normal", resolved.Kind)
	}
}

// ===== 并发写入安全（-count=3 重复执行也稳定） =====

// TestRotatingLogWriterConcurrentWrites 验证多请求并发写入不丢行、不越界。
func TestRotatingLogWriterConcurrentWrites(t *testing.T) {
	dir := testutil.TempDir(t)
	path := filepath.Join(dir, "access.log")
	writer, err := NewRotatingLogWriter(path, 1<<20, 2,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("构造轮转写入器失败: %v", err)
	}
	defer writer.Close()
	var wait sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			line := strings.Repeat("y", 1024)
			for index := 0; index < 100; index++ {
				if _, writeErr := writer.Write([]byte(line + "\n")); writeErr != nil {
					t.Errorf("并发写入失败: %v", writeErr)
					return
				}
			}
		}(worker)
	}
	wait.Wait()
	if err := writer.Close(); err != nil {
		t.Fatalf("关闭轮转写入器失败: %v", err)
	}
}

// TestComposeHandlerKeepPrefixStripsDeploymentPrefix 验证带 KeepPrefix 的处理器
// （如 internal/adminapi 自带 BasePath）在非空部署前缀下收到的是“站内前缀+剩余
// 路径”，而不是带部署前缀的完整路径（否则会全部 404）。
func TestComposeHandlerKeepPrefixStripsDeploymentPrefix(t *testing.T) {
	var seen string
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		seen = request.URL.Path
		writer.WriteHeader(http.StatusOK)
	})
	base := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusNotFound)
	})
	composed, err := ComposeHandler(base, "/login", []HandlerMount{{
		Name: "admin-api", Prefix: "/admin/v1", Handler: handler, KeepPrefix: true,
	}})
	if err != nil {
		t.Fatalf("组合挂载失败: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/login/admin/v1/meta", nil)
	response := httptest.NewRecorder()
	composed.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("挂载处理器状态码 = %d，期望 200", response.Code)
	}
	if seen != "/admin/v1/meta" {
		t.Fatalf("KeepPrefix 处理器看到路径 %q，期望 /admin/v1/meta", seen)
	}
}
