// Command external-consumer 是一个独立 Go 模块构成的外部宿主示例（步骤 88）。
//
// 它在仓库之外的位置模拟"另一家公司/另一个仓库"的真实消费方：本目录有自己的
// go.mod，并通过 replace 指向本地仓库。Go 的 internal 规则禁止模块外导入
// github.com/kagurazakayashi/EvernightLogin/internal/...，因此该示例能编译并运行，
// 就证明公开 API 没有暴露不可导入的 internal 类型，宿主只靠公开包即可完成装配。
//
// 覆盖的验收场景：
//   - 直接 Go 调用：配置校验、构建信息、公开错误码与 AppError；
//   - 扩展注册：自定义存储扩展实现 login.Extension 并注册到实例；
//   - HTTP 挂载：实例装配页面/HTTP 处理器后挂到宿主 http.ServeMux，内存中驱动
//     请求（不监听端口）；
//   - 页面替换：宿主模板覆盖内置页面；
//   - 两个实例互不串扰：启动/关闭一个实例不影响另一个；
//   - 扩展失败传播：扩展返回的稳定错误码在 Start 失败后仍可识别，实例 fail-closed；
//   - 取消/关闭生命周期：启动取消回滚、宿主资源不被实例关闭；
//   - fail-closed 授权判定：未注入授权扩展时即使 system 身份也拒绝。
//
// 示例不读取真实配置/数据库、不启动监听端口、不发送真实通知，可安全重复运行。
// 运行方式：cd examples/external-consumer && go run .
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing/fstest"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "external-consumer 示例失败:", err)
		os.Exit(1)
	}
	fmt.Println("external-consumer 示例通过：外部模块仅用公开 API 完成配置、扩展注册、HTTP 挂载、生命周期、失败传播与 fail-closed 判定")
}

// run 依次执行各验收场景，任一断言失败都返回错误。
func run() error {
	fmt.Println("构建信息:", login.CurrentBuildInfo().String())

	// 1) 直接 Go 调用：配置校验与统一错误。宿主的配置文件解析仍由宿主自己完成，
	// 这里用公开的 Default + Validate 验证契约，不需要触碰 internal 包。
	config := login.Default()
	if err := config.Validate(); err != nil {
		return fmt.Errorf("默认配置应有效: %w", err)
	}
	invalid := config
	invalid.Logging.Level = login.LogLevel("verbose")
	if err := invalid.Validate(); err == nil {
		return fmt.Errorf("非法日志级别应被 Validate 拒绝")
	}
	appErr := login.NewAppError(login.CodeDBUnavailable, "宿主数据库不可用",
		login.WithRequestID("external-1"))
	if !login.IsErrorCode(appErr, login.CodeDBUnavailable) ||
		login.FromError(appErr).RequestID() != "external-1" {
		return fmt.Errorf("公开 AppError 行为异常: %v", appErr)
	}

	// 2) 一个完整宿主实例：扩展 + 数据库 + 通知 + 页面替换 + HTTP 挂载。
	hostDatabase := &fakeDatabase{}
	notifier := &captureNotifier{}
	extension := &storageExtension{hostResource: &resource{}, created: &resource{}}
	controller := login.AccessControllerFunc(func(_ context.Context,
		request login.AccessRequest) (login.AccessDecision, error) {
		if request.Permission == "users.read" &&
			request.Identity.Kind == login.IdentityKindUser {
			return login.AccessDecision{Allowed: true, Reason: "permission_granted",
				DataScope: "all"}, nil
		}
		return login.AccessDecision{Allowed: false, Reason: "permission_missing"}, nil
	})

	hostTemplates := fstest.MapFS{
		"host/forbidden.html": &fstest.MapFile{Data: []byte(
			`{{define "page-title"}}Host{{end}}{{define "content"}}<p id="host-page">宿主替换页</p>{{end}}`)},
	}
	instance, err := login.New(login.Options{
		Config:        &config,
		Logger:        nil, // nil 时实例按 Config.Logging 建默认日志器（嵌入模式默认静默）
		Database:      hostDatabase,
		Notifications: notifier,
		Extensions:    []login.Extension{extension},
		AccessControl: controller,
		Pages: &login.WebUIOptions{
			ContractVersion: login.UIContractVersion,
			Prefix:          "/login",
			Brand:           login.UIBrand{Name: "外部宿主"},
			HostTemplates: &login.UIHostTemplates{FS: hostTemplates,
				Overrides: []login.UITemplateOverride{{RouteName: "system.forbidden",
					TemplatePath: "host/forbidden.html"}}},
		},
		HTTP: &login.HTTPOptions{Prefix: "/login"},
	})
	if err != nil {
		return fmt.Errorf("构造宿主实例失败: %w", err)
	}
	if instance.State() != login.StateNew {
		return fmt.Errorf("New 不应启动任何组件，状态=%q", instance.State())
	}
	if starts, _ := extension.counts(); starts != 0 {
		return fmt.Errorf("New 不应启动扩展，实际 %d 次", starts)
	}
	infos := instance.Extensions()
	if len(infos) != 1 || infos[0].Kind != login.ExtensionKindStorage {
		return fmt.Errorf("扩展注册信息异常: %+v", infos)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/host/", func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("host route"))
	})
	if err := instance.Mount(mux); err != nil {
		return fmt.Errorf("挂载到宿主 mux 失败: %w", err)
	}
	if instance.Handler() == nil || instance.HandlerPrefix() != "/login" {
		return fmt.Errorf("HTTP 装配异常: handler=%v prefix=%q",
			instance.Handler() != nil, instance.HandlerPrefix())
	}

	if err := instance.Start(context.Background()); err != nil {
		return fmt.Errorf("启动宿主实例失败: %w", err)
	}
	if err := instance.Ready(context.Background()); err != nil {
		return fmt.Errorf("实例应就绪: %w", err)
	}

	// 页面替换：内置路由仍由框架处理，但渲染使用宿主模板。
	page := request(mux, http.MethodGet, "/login/403")
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "宿主替换页") {
		return fmt.Errorf("页面替换未生效: %d %q", page.Code, page.Body.String())
	}
	if !strings.Contains(page.Body.String(), "外部宿主") {
		return fmt.Errorf("宿主品牌未生效: %q", page.Body.String())
	}
	for _, path := range []string{"/login/healthz", "/login/openapi.json"} {
		if response := request(mux, http.MethodGet, path); response.Code != http.StatusOK {
			return fmt.Errorf("%s 应为 200，实际 %d", path, response.Code)
		}
	}
	if hostRoute := request(mux, http.MethodGet, "/host/probe"); hostRoute.Code != http.StatusOK ||
		!strings.Contains(hostRoute.Body.String(), "host route") {
		return fmt.Errorf("宿主自有路由不应被影响: %d", hostRoute.Code)
	}

	// 3) 直接 Go 调用授权判定（fail-closed 契约 + 注入的真实控制器）。
	user := login.Identity{Kind: login.IdentityKindUser, SubjectID: "user-1"}
	decision, err := instance.CheckAccess(context.Background(), login.AccessRequest{
		Identity: user, Permission: "users.read", Scope: login.PermissionScopeSystem})
	if err != nil || !decision.Allowed || decision.DataScope != "all" {
		return fmt.Errorf("授权放行判定异常: %+v %v", decision, err)
	}
	denied, err := instance.CheckAccess(context.Background(), login.AccessRequest{
		Identity: user, Permission: "users.delete", Scope: login.PermissionScopeSystem})
	if err != nil || denied.Allowed {
		return fmt.Errorf("授权拒绝判定异常: %+v %v", denied, err)
	}

	// 4) 第二个实例：扩展失败必须整体 fail-closed，且不影响第一个实例。
	failingExtension := &storageExtension{startErr: login.NewAppError(
		login.CodeAuthzUnavailable, "存储扩展依赖不可用")}
	failingInstance, err := login.New(login.Options{
		Extensions: []login.Extension{failingExtension},
	})
	if err != nil {
		return fmt.Errorf("构造失败场景实例失败: %w", err)
	}
	startErr := failingInstance.Start(context.Background())
	if !login.IsErrorCode(startErr, login.CodeAuthzUnavailable) {
		return fmt.Errorf("扩展失败未传播稳定错误码: %v", startErr)
	}
	if failingInstance.State() != login.StateClosed {
		return fmt.Errorf("扩展失败后实例应已关闭，实际 %q", failingInstance.State())
	}
	if err := failingInstance.Start(context.Background()); !errors.Is(err, login.ErrClosed) {
		return fmt.Errorf("失败后再次 Start 应返回 ErrClosed，实际 %v", err)
	}
	if instance.State() != login.StateRunning {
		return fmt.Errorf("另一个实例失败不应影响当前实例，状态=%q", instance.State())
	}

	// 5) 未注入授权扩展时一律拒绝：system 身份也没有自动放行（无伪造 root 入口）。
	deniedInstance, err := login.New(login.Options{})
	if err != nil {
		return fmt.Errorf("构造无授权实例失败: %w", err)
	}
	systemIdentity := login.Identity{Kind: login.IdentityKindSystem, SubjectID: "system"}
	if _, err := deniedInstance.CheckAccess(context.Background(), login.AccessRequest{
		Identity: systemIdentity, Permission: "users.read",
		Scope: login.PermissionScopeSystem}); !login.IsErrorCode(err, login.CodeAuthzUnavailable) {
		return fmt.Errorf("未装配授权扩展时 system 身份应被拒绝，实际 %v", err)
	}
	if err := deniedInstance.Close(context.Background()); err != nil {
		return fmt.Errorf("关闭无授权实例失败: %w", err)
	}

	// 6) 取消生命周期：扩展启动阻塞时，宿主取消必须让启动 fail-closed 并回滚。
	blockingExtension := &storageExtension{blockStart: true, created: &resource{}}
	blockedInstance, err := login.New(login.Options{
		Extensions: []login.Extension{blockingExtension},
	})
	if err != nil {
		return fmt.Errorf("构造取消场景实例失败: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	cancelledErr := blockedInstance.Start(ctx)
	if !errors.Is(cancelledErr, context.DeadlineExceeded) {
		return fmt.Errorf("启动取消应返回包装的 DeadlineExceeded，实际 %v", cancelledErr)
	}
	if blockedInstance.State() != login.StateClosed {
		return fmt.Errorf("启动取消后实例应已关闭，实际 %q", blockedInstance.State())
	}
	if opened, closed := blockingExtension.created.counts(); opened != 1 || !closed {
		return fmt.Errorf("被取消的扩展应自行清理资源，实际打开/关闭=%d/%t", opened, closed)
	}

	// 7) 正常关闭：宿主资源不被实例或扩展关闭，生命周期通知可观察。
	if err := instance.Close(context.Background()); err != nil {
		return fmt.Errorf("关闭宿主实例失败: %w", err)
	}
	if hostDatabase.closed {
		return fmt.Errorf("实例不应关闭宿主数据库")
	}
	if extension.hostResource.closed {
		return fmt.Errorf("扩展不应关闭宿主资源")
	}
	if opened, closed := extension.created.counts(); opened != 1 || !closed {
		return fmt.Errorf("扩展自有资源应被关闭，实际打开/关闭=%d/%t", opened, closed)
	}
	events := notifier.snapshot()
	if len(events) != 2 || events[0].Kind != login.LifecycleStarted ||
		events[1].Kind != login.LifecycleClosed {
		return fmt.Errorf("生命周期通知异常: %+v", events)
	}
	if hostDatabase.pings == 0 {
		return fmt.Errorf("Ready 应检查宿主数据库，实际未 Ping")
	}

	// 8) 关闭后不可再启动；重复关闭安全。
	if err := instance.Start(context.Background()); !errors.Is(err, login.ErrClosed) {
		return fmt.Errorf("关闭后 Start 应返回 ErrClosed，实际 %v", err)
	}
	if err := instance.Close(context.Background()); err != nil {
		return fmt.Errorf("重复关闭应安全，实际 %v", err)
	}
	return nil
}

// storageExtension 是宿主在自己的仓库里实现的存储扩展：只依赖公开包类型。
type storageExtension struct {
	hostResource *resource
	created      *resource
	startErr     error
	blockStart   bool

	mu     sync.Mutex
	starts int
	closes int
}

// ExtensionInfo 实现 login.Extension：声明扩展分类、稳定名称与版本。
func (e *storageExtension) ExtensionInfo() login.ExtensionInfo {
	return login.ExtensionInfo{Kind: login.ExtensionKindStorage,
		Name: "host-storage", Version: "0.1.0"}
}

// Start 实现 login.Extension：创建自己的资源，失败时自行清理。
func (e *storageExtension) Start(ctx context.Context) error {
	e.mu.Lock()
	e.starts++
	e.mu.Unlock()
	if e.created != nil {
		e.created.open()
	}
	if e.blockStart {
		<-ctx.Done()
		if e.created != nil {
			e.created.close()
		}
		return ctx.Err()
	}
	if e.startErr != nil {
		if e.created != nil {
			e.created.close()
		}
		return e.startErr
	}
	return nil
}

// Close 实现 login.Extension：只释放扩展自己创建的资源，不关闭宿主资源。
func (e *storageExtension) Close(context.Context) error {
	e.mu.Lock()
	e.closes++
	e.mu.Unlock()
	if e.created != nil {
		e.created.close()
	}
	return nil
}

// counts 返回扩展的启动/关闭次数。
func (e *storageExtension) counts() (starts, closes int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.starts, e.closes
}

// resource 模拟一个带打开/关闭计数的资源，用于验证资源所有权。
type resource struct {
	mu     sync.Mutex
	opened int
	closed bool
}

func (r *resource) open() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.opened++
}

func (r *resource) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
}

// counts 返回资源的打开次数与是否已关闭。
func (r *resource) counts() (opened int, closed bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.opened, r.closed
}

// fakeDatabase 模拟宿主拥有的数据库连接：实现 login.Database，但实例不关闭它。
type fakeDatabase struct {
	mu     sync.Mutex
	pings  int
	closed bool
}

// Ping 实现 login.Database。
func (d *fakeDatabase) Ping(context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pings++
	return nil
}

// Close 只由宿主调用；实例与扩展都不会调用它。
func (d *fakeDatabase) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	return nil
}

// captureNotifier 记录生命周期事件；真实宿主可替换为告警系统或启动审计。
type captureNotifier struct {
	mu     sync.Mutex
	events []login.LifecycleEvent
}

// Notify 实现 login.Notifier。
func (n *captureNotifier) Notify(_ context.Context, event login.LifecycleEvent) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.events = append(n.events, event)
	return nil
}

// snapshot 返回已记录事件副本。
func (n *captureNotifier) snapshot() []login.LifecycleEvent {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]login.LifecycleEvent, len(n.events))
	copy(out, n.events)
	return out
}

// request 在内存中把请求交给宿主 mux，不监听端口。
func request(mux *http.ServeMux, method, target string) *httptest.ResponseRecorder {
	httpRequest := httptest.NewRequest(method, target, nil)
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httpRequest)
	return recorder
}
