package login

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"
)

// fakeDatabase 模拟宿主拥有的数据库连接：记录 Ping 次数与是否被关闭。
type fakeDatabase struct {
	mu       sync.Mutex
	pings    int
	closed   bool
	pingErr  error
	blocking bool
}

func (d *fakeDatabase) Ping(ctx context.Context) error {
	d.mu.Lock()
	d.pings++
	pingErr := d.pingErr
	blocking := d.blocking
	d.mu.Unlock()
	if blocking {
		<-ctx.Done()
		return ctx.Err()
	}
	return pingErr
}

func (d *fakeDatabase) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	return nil
}

func (d *fakeDatabase) state() (pings int, closed bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.pings, d.closed
}

// recordingNotifier 记录生命周期事件，并可在需要时注入错误。
type recordingNotifier struct {
	mu     sync.Mutex
	events []LifecycleEvent
	err    error
}

func (n *recordingNotifier) Notify(_ context.Context, event LifecycleEvent) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.events = append(n.events, event)
	return n.err
}

func (n *recordingNotifier) snapshot() []LifecycleEvent {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]LifecycleEvent, len(n.events))
	copy(out, n.events)
	return out
}

// recordingAccessController 记录授权判定请求并返回预设决定。
type recordingAccessController struct {
	mu       sync.Mutex
	requests []AccessRequest
	decision AccessDecision
	err      error
}

func (c *recordingAccessController) CheckAccess(_ context.Context, request AccessRequest) (AccessDecision, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requests = append(c.requests, request)
	return c.decision, c.err
}

func (c *recordingAccessController) snapshot() []AccessRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]AccessRequest, len(c.requests))
	copy(out, c.requests)
	return out
}

// embeddedHostOptions 构造带页面与 HTTP 装配的宿主选项：宿主模板覆盖 system.forbidden。
func embeddedHostOptions(t *testing.T) Options {
	t.Helper()
	templates := fstest.MapFS{
		"host/forbidden.html": &fstest.MapFile{Data: []byte(
			`{{define "page-title"}}Host{{end}}{{define "content"}}<p id="host-template">宿主模板</p>{{end}}`)},
	}
	return Options{
		Pages: &WebUIOptions{
			ContractVersion: UIContractVersion,
			Prefix:          "/login",
			Brand:           UIBrand{Name: "嵌入示例"},
			HostTemplates: &UIHostTemplates{FS: templates,
				Overrides: []UITemplateOverride{{RouteName: "system.forbidden",
					TemplatePath: "host/forbidden.html"}}},
		},
		HTTP: &HTTPOptions{Prefix: "/login"},
	}
}

// serve 在内存中把请求交给宿主 mux（不监听端口）。
func serve(mux *http.ServeMux, method, target string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, nil)
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, request)
	return recorder
}

func TestNewAssemblesAndMountsHTTPHandler(t *testing.T) {
	instance, err := New(embeddedHostOptions(t))
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	if got := instance.State(); got != StateNew {
		t.Errorf("New 不应启动实例，状态 = %q", got)
	}
	if instance.Handler() == nil {
		t.Fatal("配置 Pages/HTTP 后 Handler() 不应为 nil")
	}
	if got := instance.HandlerPrefix(); got != "/login" {
		t.Errorf("HandlerPrefix() = %q，期望 %q", got, "/login")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/host/", func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("host route"))
	})
	if err := instance.Mount(mux); err != nil {
		t.Fatalf("Mount() 失败：%v", err)
	}

	page := serve(mux, http.MethodGet, "/login/403")
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "宿主模板") {
		t.Errorf("页面路由 = %d/%q，期望 200 且渲染宿主模板", page.Code, page.Body.String())
	}
	if !strings.Contains(page.Body.String(), "嵌入示例") {
		t.Errorf("页面品牌未生效：%q", page.Body.String())
	}
	for _, apiPath := range []string{"/login/healthz", "/login/openapi.json"} {
		if response := serve(mux, http.MethodGet, apiPath); response.Code != http.StatusOK {
			t.Errorf("%s = %d，期望 200", apiPath, response.Code)
		}
	}
	if hostRoute := serve(mux, http.MethodGet, "/host/probe"); hostRoute.Code != http.StatusOK ||
		!strings.Contains(hostRoute.Body.String(), "host route") {
		t.Errorf("宿主自有路由不应被影响：%d/%q", hostRoute.Code, hostRoute.Body.String())
	}
	if started := serve(mux, http.MethodGet, "/login/403"); started.Code != http.StatusOK {
		t.Errorf("内存请求应可重复执行：%d", started.Code)
	}
	if err := instance.Start(context.Background()); err != nil {
		t.Fatalf("Start() 失败：%v", err)
	}
	if err := instance.Close(context.Background()); err != nil {
		t.Fatalf("Close() 失败：%v", err)
	}
}

func TestAssemblyValidation(t *testing.T) {
	cases := []struct {
		name    string
		options Options
	}{
		{name: "页面缺少 HTTP", options: Options{Pages: &WebUIOptions{Prefix: "/login"}}},
		{name: "前缀不一致", options: Options{
			Pages: &WebUIOptions{Prefix: "/login"},
			HTTP:  &HTTPOptions{Prefix: "/auth"},
		}},
		{name: "页面处理器重复配置", options: Options{
			Pages: &WebUIOptions{Prefix: "/login"},
			HTTP: &HTTPOptions{Prefix: "/login", UI: &UIHTTPOptions{
				Handler: http.NotFoundHandler()}},
		}},
		{name: "非法 HTTP 前缀", options: Options{
			HTTP: &HTTPOptions{Prefix: "/login/"},
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := New(testCase.options); err == nil {
				t.Fatal("非法装配配置应导致 New 失败")
			} else if !IsErrorCode(err, CodeConfigInvalid) {
				t.Errorf("错误码 = %v，期望 CONFIG_INVALID", err)
			}
		})
	}
}

func TestMountWithoutHandlerFails(t *testing.T) {
	instance, err := New(Options{})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	if instance.Handler() != nil {
		t.Fatalf("未配置 HTTP 时 Handler() 应为 nil")
	}
	if instance.HandlerPrefix() != "" {
		t.Errorf("未配置 HTTP 时 HandlerPrefix() 应为空")
	}
	mux := http.NewServeMux()
	if err := instance.Mount(mux); err == nil || !IsErrorCode(err, CodeConfigInvalid) {
		t.Errorf("未配置处理器时 Mount() = %v，期望 CONFIG_INVALID", err)
	}
	configured, err := New(Options{HTTP: &HTTPOptions{Prefix: "/login"}})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	if err := configured.Mount(nil); err == nil || !IsErrorCode(err, CodeConfigInvalid) {
		t.Errorf("mux 为 nil 时 Mount() = %v，期望 CONFIG_INVALID", err)
	}
}

func TestReadyLifecycle(t *testing.T) {
	database := &fakeDatabase{}
	extension := &readyFailingExtension{}
	extension.info = ExtensionInfo{Kind: ExtensionKindAuthentication, Name: "idp", Version: "1.0.0"}
	instance, err := New(Options{
		Database:   database,
		Extensions: []Extension{extension},
	})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}

	if err := instance.Ready(context.Background()); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("未启动时 Ready() = %v，期望 ErrNotRunning", err)
	}
	if pings, _ := database.state(); pings != 0 {
		t.Errorf("未启动时不应检查数据库，实际 Ping %d 次", pings)
	}
	if err := instance.Start(context.Background()); err != nil {
		t.Fatalf("Start() 失败：%v", err)
	}
	if err := instance.Ready(context.Background()); err != nil {
		t.Fatalf("健康扩展与可用数据库下 Ready() 失败：%v", err)
	}
	if pings, _ := database.state(); pings != 1 {
		t.Errorf("Ready() 应检查数据库一次，实际 %d 次", pings)
	}

	extension.readyErr = errors.New("模拟强认证不可用")
	if err := instance.Ready(context.Background()); err == nil ||
		!IsErrorCode(err, CodeInternalError) {
		t.Fatalf("扩展不健康时 Ready() = %v，期望 INTERNAL_ERROR", err)
	}
	extension.readyErr = nil

	database.mu.Lock()
	database.pingErr = errors.New("模拟数据库断连")
	database.mu.Unlock()
	if err := instance.Ready(context.Background()); err == nil ||
		!IsErrorCode(err, CodeDBUnavailable) {
		t.Fatalf("数据库不可用时 Ready() = %v，期望 DB_UNAVAILABLE", err)
	}

	closedErr := instance.Close(context.Background())
	if closedErr != nil {
		t.Fatalf("Close() 失败：%v", closedErr)
	}
	if err := instance.Ready(context.Background()); !errors.Is(err, ErrNotRunning) {
		t.Errorf("关闭后 Ready() = %v，期望 ErrNotRunning", err)
	}
	if _, closed := database.state(); closed {
		t.Error("实例不应关闭宿主数据库")
	}
}

func TestLifecycleNotifications(t *testing.T) {
	notifier := &recordingNotifier{}
	instance, err := New(Options{Notifications: notifier})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	if err := instance.Start(context.Background()); err != nil {
		t.Fatalf("Start() 失败：%v", err)
	}
	if err := instance.Close(context.Background()); err != nil {
		t.Fatalf("Close() 失败：%v", err)
	}
	events := notifier.snapshot()
	if len(events) != 2 {
		t.Fatalf("生命周期事件数量 = %d，期望 2", len(events))
	}
	if events[0].Kind != LifecycleStarted || events[0].State != StateRunning ||
		!events[0].Kind.Valid() || events[0].At.IsZero() {
		t.Errorf("启动事件异常：%+v", events[0])
	}
	if events[1].Kind != LifecycleClosed || events[1].State != StateClosed {
		t.Errorf("关闭事件异常：%+v", events[1])
	}

	// 通知失败不改变生命周期结果。
	failingNotifier := &recordingNotifier{err: errors.New("模拟通知失败")}
	failingInstance, err := New(Options{Notifications: failingNotifier})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	if err := failingInstance.Start(context.Background()); err != nil {
		t.Fatalf("通知失败不应导致 Start 失败：%v", err)
	}
	if err := failingInstance.Close(context.Background()); err != nil {
		t.Fatalf("通知失败不应导致 Close 失败：%v", err)
	}

	// 启动失败事件携带稳定错误码，且实例进入已关闭状态。
	failingExtension := newTestExtension(ExtensionKindMFA, "second")
	failingExtension.startErr = NewAppError(CodeMFARequired, "第二因素扩展不可用",
		WithRequestID(NewRequestID()))
	failingNotifier2 := &recordingNotifier{}
	failingInstance2, err := New(Options{
		Notifications: failingNotifier2,
		Extensions:    []Extension{failingExtension},
	})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	if startErr := failingInstance2.Start(context.Background()); !IsErrorCode(startErr, CodeMFARequired) {
		t.Fatalf("Start() = %v，期望保留 MFA_REQUIRED", startErr)
	}
	failedEvents := failingNotifier2.snapshot()
	if len(failedEvents) != 1 || failedEvents[0].Kind != LifecycleStartFailed ||
		failedEvents[0].State != StateClosed || failedEvents[0].ErrorCode != CodeMFARequired ||
		failedEvents[0].RequestID == "" {
		t.Errorf("启动失败事件异常：%+v", failedEvents)
	}
}

func TestTypedNilInjectedDependenciesRejected(t *testing.T) {
	cases := []struct {
		name    string
		options Options
	}{
		{name: "typed-nil 数据库", options: Options{Database: (*fakeDatabase)(nil)}},
		{name: "typed-nil 通知器", options: Options{Notifications: (*recordingNotifier)(nil)}},
		{name: "typed-nil 授权扩展", options: Options{AccessControl: (*recordingAccessController)(nil)}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := New(testCase.options); err == nil ||
				!IsErrorCode(err, CodeConfigInvalid) {
				t.Fatalf("New() = %v，期望 CONFIG_INVALID", err)
			}
		})
	}
}

func TestCheckAccessFailsClosed(t *testing.T) {
	userIdentity := Identity{Kind: IdentityKindUser, SubjectID: "user-1"}
	systemIdentity := Identity{Kind: IdentityKindSystem, SubjectID: "system"}

	t.Run("未配置授权扩展时拒绝", func(t *testing.T) {
		instance, err := New(Options{})
		if err != nil {
			t.Fatalf("New() 失败：%v", err)
		}
		decision, err := instance.CheckAccess(context.Background(), AccessRequest{
			Identity: userIdentity, Permission: "users.read", Scope: PermissionScopeSystem})
		if err == nil || !IsErrorCode(err, CodeAuthzUnavailable) {
			t.Fatalf("CheckAccess() 错误 = %v，期望 AUTHZ_UNAVAILABLE", err)
		}
		if decision.Allowed {
			t.Error("缺少授权扩展时不应放行")
		}
	})

	t.Run("system 身份没有自动放行", func(t *testing.T) {
		instance, err := New(Options{})
		if err != nil {
			t.Fatalf("New() 失败：%v", err)
		}
		decision, err := instance.CheckAccess(context.Background(), AccessRequest{
			Identity: systemIdentity, Permission: "users.read", Scope: PermissionScopeSystem})
		if err == nil || !IsErrorCode(err, CodeAuthzUnavailable) || decision.Allowed {
			t.Fatalf("system 身份不应绕过判定：decision=%+v err=%v", decision, err)
		}
	})

	t.Run("非法请求被拒绝且不调用扩展", func(t *testing.T) {
		controller := &recordingAccessController{decision: AccessDecision{Allowed: true, Reason: "ok"}}
		instance, err := New(Options{AccessControl: controller})
		if err != nil {
			t.Fatalf("New() 失败：%v", err)
		}
		cases := []AccessRequest{
			{Identity: Identity{}, Permission: "users.read", Scope: PermissionScopeSystem},
			{Identity: userIdentity, Permission: "", Scope: PermissionScopeSystem},
			{Identity: userIdentity, Permission: "users.read", Scope: PermissionScope("其它")},
			{Identity: userIdentity, Permission: "users.read", Scope: PermissionScopeApplication},
			{Identity: Identity{Kind: IdentityKindApplication, SubjectID: "app-1", AppID: "app-a"},
				Permission: "users.read", Scope: PermissionScopeApplication, AppID: "app-b"},
			{Identity: userIdentity, Permission: "users.read", Scope: PermissionScopeSystem,
				ResourceID: strings.Repeat("x", MaxResourceIDLength+1)},
		}
		for index, request := range cases {
			if _, err := instance.CheckAccess(context.Background(), request); err == nil ||
				!IsErrorCode(err, CodeReqInvalid) {
				t.Errorf("用例 %d CheckAccess() = %v，期望 REQ_INVALID", index, err)
			}
		}
		if got := controller.snapshot(); len(got) != 0 {
			t.Errorf("非法请求不应调用授权扩展，实际调用 %d 次", len(got))
		}
	})

	t.Run("扩展放行与拒绝原样返回", func(t *testing.T) {
		controller := &recordingAccessController{decision: AccessDecision{
			Allowed: true, Reason: "permission_granted", DataScope: "all"}}
		instance, err := New(Options{AccessControl: controller})
		if err != nil {
			t.Fatalf("New() 失败：%v", err)
		}
		decision, err := instance.CheckAccess(context.Background(), AccessRequest{
			Identity: userIdentity, Permission: "users.read", Scope: PermissionScopeSystem})
		if err != nil || !decision.Allowed || decision.Reason != "permission_granted" {
			t.Fatalf("CheckAccess() = %+v/%v，期望原样返回放行", decision, err)
		}
		requests := controller.snapshot()
		if len(requests) != 1 || requests[0].Identity != userIdentity ||
			requests[0].Permission != "users.read" {
			t.Errorf("授权扩展收到的请求异常：%+v", requests)
		}

		controller.decision = AccessDecision{Allowed: false, Reason: "permission_missing"}
		decision, err = instance.CheckAccess(context.Background(), AccessRequest{
			Identity: userIdentity, Permission: "users.read", Scope: PermissionScopeSystem})
		if err != nil || decision.Allowed {
			t.Fatalf("正常拒绝不应返回错误：decision=%+v err=%v", decision, err)
		}
	})

	t.Run("扩展错误与异常放行被拒绝", func(t *testing.T) {
		controller := &recordingAccessController{err: errors.New("模拟授权服务故障")}
		instance, err := New(Options{AccessControl: controller})
		if err != nil {
			t.Fatalf("New() 失败：%v", err)
		}
		decision, err := instance.CheckAccess(context.Background(), AccessRequest{
			Identity: userIdentity, Permission: "users.read", Scope: PermissionScopeSystem})
		if err == nil || !IsErrorCode(err, CodeAuthzUnavailable) || decision.Allowed {
			t.Fatalf("授权扩展故障应 fail-closed：decision=%+v err=%v", decision, err)
		}

		// 返回 error 同时声称放行，也必须拒绝。
		controller.err = errors.New("部分失败")
		controller.decision = AccessDecision{Allowed: true, Reason: "unsafe"}
		decision, err = instance.CheckAccess(context.Background(), AccessRequest{
			Identity: userIdentity, Permission: "users.read", Scope: PermissionScopeSystem})
		if err == nil || decision.Allowed {
			t.Fatalf("错误结果不得被解释为放行：decision=%+v err=%v", decision, err)
		}

		// 放行但无稳定原因视为异常，拒绝。
		controller.err = nil
		controller.decision = AccessDecision{Allowed: true}
		decision, err = instance.CheckAccess(context.Background(), AccessRequest{
			Identity: userIdentity, Permission: "users.read", Scope: PermissionScopeSystem})
		if err == nil || !IsErrorCode(err, CodeAuthzUnavailable) || decision.Allowed {
			t.Fatalf("无原因放行应被拒绝：decision=%+v err=%v", decision, err)
		}
	})

	t.Run("取消的上下文被拒绝", func(t *testing.T) {
		controller := &recordingAccessController{decision: AccessDecision{Allowed: true, Reason: "ok"}}
		instance, err := New(Options{AccessControl: controller})
		if err != nil {
			t.Fatalf("New() 失败：%v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := instance.CheckAccess(ctx, AccessRequest{
			Identity: userIdentity, Permission: "users.read",
			Scope: PermissionScopeSystem}); err == nil || !IsErrorCode(err, CodeAuthzUnavailable) {
			t.Errorf("取消的上下文应返回 AUTHZ_UNAVAILABLE，实际 %v", err)
		}
	})
}

func TestNewDoesNotStartInjectedDependencies(t *testing.T) {
	database := &fakeDatabase{}
	extension := newTestExtension(ExtensionKindStorage, "db")
	notifier := &recordingNotifier{}
	instance, err := New(Options{
		Database:      database,
		Notifications: notifier,
		Extensions:    []Extension{extension},
	})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	if got := instance.State(); got != StateNew {
		t.Errorf("New 后状态 = %q，期望 %q", got, StateNew)
	}
	if starts, _ := extension.counts(); starts != 0 {
		t.Errorf("New 不应启动扩展，实际 %d 次", starts)
	}
	if pings, _ := database.state(); pings != 0 {
		t.Errorf("New 不应访问数据库，实际 Ping %d 次", pings)
	}
	if events := notifier.snapshot(); len(events) != 0 {
		t.Errorf("New 不应发送生命周期通知，实际 %d 条", len(events))
	}

	// 直接关闭从未启动的实例：不关闭扩展（未启动过），不关闭宿主数据库。
	if err := instance.Close(context.Background()); err != nil {
		t.Fatalf("Close() 失败：%v", err)
	}
	if _, closes := extension.counts(); closes != 0 {
		t.Errorf("未启动的扩展不应被关闭，实际 %d 次", closes)
	}
	if _, closed := database.state(); closed {
		t.Error("实例不应关闭宿主数据库")
	}
}

func TestDatabasePingCancellationDoesNotReportReady(t *testing.T) {
	database := &fakeDatabase{blocking: true}
	instance, err := New(Options{Database: database})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	if err := instance.Start(context.Background()); err != nil {
		t.Fatalf("Start() 失败：%v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := instance.Ready(ctx); err == nil {
		t.Fatal("数据库 Ping 超时不应报告就绪")
	}
	if err := instance.Close(context.Background()); err != nil {
		t.Fatalf("Close() 失败：%v", err)
	}
}
