package login

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// stalledExtension 模拟忽略 ctx、长时间不返回的扩展，用于验证单扩展启动超时。
type stalledExtension struct {
	info    ExtensionInfo
	release chan struct{}
}

func (e *stalledExtension) ExtensionInfo() ExtensionInfo { return e.info }

func (e *stalledExtension) Start(context.Context) error {
	<-e.release
	return nil
}

func (e *stalledExtension) Close(context.Context) error { return nil }

// panickingExtension 模拟宿主扩展在 Start/Close 中 panic 的编程错误。
type panickingExtension struct {
	info       ExtensionInfo
	panicStart bool
	panicClose bool

	mu     sync.Mutex
	closes int
}

func (e *panickingExtension) ExtensionInfo() ExtensionInfo { return e.info }

func (e *panickingExtension) Start(context.Context) error {
	if e.panicStart {
		panic("模拟扩展启动 panic")
	}
	return nil
}

func (e *panickingExtension) Close(context.Context) error {
	e.mu.Lock()
	e.closes++
	e.mu.Unlock()
	if e.panicClose {
		panic("模拟扩展关闭 panic")
	}
	return nil
}

func (e *panickingExtension) closeCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.closes
}

// queriedNotifier 在通知回调中查询实例公开状态，用于验证通知在锁外执行、不会死锁。
type queriedNotifier struct {
	mu       sync.Mutex
	instance *Instance
	events   []LifecycleEvent
}

func (n *queriedNotifier) Notify(_ context.Context, event LifecycleEvent) error {
	// 这些方法都会获取实例互斥锁；若通知在锁内发送，这里会死锁。
	n.instance.State()
	n.instance.Extensions()
	n.instance.HandlerPrefix()
	n.mu.Lock()
	defer n.mu.Unlock()
	n.events = append(n.events, event)
	return nil
}

func (n *queriedNotifier) snapshot() []LifecycleEvent {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]LifecycleEvent, len(n.events))
	copy(out, n.events)
	return out
}

// slowNotifier 忽略 ctx 并长时间阻塞，用于验证通知超时后生命周期仍能返回。
type slowNotifier struct {
	sleep time.Duration
}

func (n *slowNotifier) Notify(context.Context, LifecycleEvent) error {
	time.Sleep(n.sleep)
	return nil
}

func TestMountDuplicateAndConflictPatternReturnError(t *testing.T) {
	instance, err := New(embeddedHostOptions(t))
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	mux := http.NewServeMux()
	if err := instance.Mount(mux); err != nil {
		t.Fatalf("首次 Mount() 失败：%v", err)
	}
	// 重复挂载同一 mux：http.ServeMux 会 panic，Mount 必须恢复并返回 CONFIG_INVALID。
	if err := instance.Mount(mux); err == nil || !IsErrorCode(err, CodeConfigInvalid) {
		t.Fatalf("重复 Mount() = %v，期望 CONFIG_INVALID", err)
	}

	conflictMux := http.NewServeMux()
	conflictMux.Handle("/login/", http.NotFoundHandler())
	conflictErr := instance.Mount(conflictMux)
	if conflictErr == nil || !IsErrorCode(conflictErr, CodeConfigInvalid) {
		t.Fatalf("冲突 pattern Mount() = %v，期望 CONFIG_INVALID", conflictErr)
	}
	if cause := errors.Unwrap(conflictErr); cause == nil ||
		!strings.Contains(cause.Error(), "/login/") {
		t.Errorf("挂载错误应保留冲突 pattern 信息：%v", conflictErr)
	}
}

func TestHandlerAndMountUsableBeforeStart(t *testing.T) {
	instance, err := New(embeddedHostOptions(t))
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	if instance.State() != StateNew {
		t.Fatalf("状态 = %q，期望 %q", instance.State(), StateNew)
	}
	mux := http.NewServeMux()
	if err := instance.Mount(mux); err != nil {
		t.Fatalf("Start 前 Mount() 失败：%v", err)
	}
	page := serve(mux, http.MethodGet, "/login/403")
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "宿主模板") {
		t.Fatalf("Start 前页面应可渲染：%d %q", page.Code, page.Body.String())
	}
	if err := instance.Start(context.Background()); err != nil {
		t.Fatalf("Start() 失败：%v", err)
	}
	if err := instance.Close(context.Background()); err != nil {
		t.Fatalf("Close() 失败：%v", err)
	}
	// Handler/Mount 与生命周期解耦：关闭后处理器仍可被宿主用于返回页面。
	if page := serve(mux, http.MethodGet, "/login/403"); page.Code != http.StatusOK {
		t.Errorf("Close 后处理器应仍可用：%d", page.Code)
	}
}

func TestNotifierBoundedAndNonBlocking(t *testing.T) {
	notifier := &slowNotifier{sleep: 8 * time.Second}
	instance, err := New(Options{Notifications: notifier})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	started := time.Now()
	if err := instance.Start(context.Background()); err != nil {
		t.Fatalf("Start() 失败：%v", err)
	}
	if elapsed := time.Since(started); elapsed > 6*time.Second {
		t.Errorf("忽略 ctx 的 Notifier 不应长时间阻塞 Start，实际 %v", elapsed)
	}
	closing := time.Now()
	if err := instance.Close(context.Background()); err != nil {
		t.Fatalf("Close() 失败：%v", err)
	}
	if elapsed := time.Since(closing); elapsed > 6*time.Second {
		t.Errorf("忽略 ctx 的 Notifier 不应长时间阻塞 Close，实际 %v", elapsed)
	}
}

func TestNotifierQueryingInstanceDoesNotDeadlock(t *testing.T) {
	notifier := &queriedNotifier{}
	instance, err := New(Options{Notifications: notifier})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	notifier.instance = instance

	done := make(chan error, 1)
	go func() { done <- instance.Start(context.Background()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start() 失败：%v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Notifier 回调实例方法导致 Start 死锁")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- instance.Close(context.Background()) }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close() 失败：%v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Notifier 回调实例方法导致 Close 死锁")
	}
	events := notifier.snapshot()
	if len(events) != 2 || events[0].Kind != LifecycleStarted ||
		events[1].Kind != LifecycleClosed {
		t.Errorf("通知事件异常：%+v", events)
	}
}

func TestCloseFromStateNewNotifiesOnce(t *testing.T) {
	notifier := &recordingNotifier{}
	instance, err := New(Options{Notifications: notifier})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	if err := instance.Close(context.Background()); err != nil {
		t.Fatalf("Close() 失败：%v", err)
	}
	if err := instance.Close(context.Background()); err != nil {
		t.Fatalf("重复 Close() 失败：%v", err)
	}
	events := notifier.snapshot()
	if len(events) != 1 || events[0].Kind != LifecycleClosed || events[0].State != StateClosed {
		t.Errorf("从未启动直接关闭应只发送一次 closed 通知，实际：%+v", events)
	}
}

func TestExtensionStartPanicRecovered(t *testing.T) {
	panicking := &panickingExtension{
		info:       ExtensionInfo{Kind: ExtensionKindStorage, Name: "panic", Version: "1.0.0"},
		panicStart: true,
	}
	instance, err := New(Options{Extensions: []Extension{panicking}})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	startErr := instance.Start(context.Background())
	if startErr == nil || !IsErrorCode(startErr, CodeInternalError) {
		t.Fatalf("扩展 Start panic 应转为 INTERNAL_ERROR，实际 %v", startErr)
	}
	if appErr, ok := AsAppError(startErr); !ok || appErr.Unwrap() == nil ||
		!strings.Contains(appErr.Unwrap().Error(), "panic") {
		t.Errorf("错误原因链应保留 panic 诊断信息：%v", startErr)
	}
	if got := instance.State(); got != StateClosed {
		t.Errorf("panic 后状态 = %q，期望 %q", got, StateClosed)
	}
}

func TestExtensionClosePanicRecoveredAndContinues(t *testing.T) {
	panicking := &panickingExtension{
		info:       ExtensionInfo{Kind: ExtensionKindStorage, Name: "panic-close", Version: "1.0.0"},
		panicClose: true,
	}
	healthy := newTestExtension(ExtensionKindNotification, "mail")
	log := &eventLog{}
	healthy.log = log
	instance, err := New(Options{Extensions: []Extension{panicking, healthy}})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	if err := instance.Start(context.Background()); err != nil {
		t.Fatalf("Start() 失败：%v", err)
	}
	closeErr := instance.Close(context.Background())
	appErr, ok := AsAppError(closeErr)
	if !ok || appErr.Unwrap() == nil || !strings.Contains(appErr.Unwrap().Error(), "panic") {
		t.Fatalf("扩展 Close panic 应转为错误返回，实际 %v", closeErr)
	}
	if got := instance.State(); got != StateClosed {
		t.Errorf("关闭后状态 = %q，期望 %q", got, StateClosed)
	}
	if panicking.closeCount() != 1 {
		t.Errorf("panic 扩展 Close 调用次数 = %d，期望 1", panicking.closeCount())
	}
	if _, closes := healthy.counts(); closes != 1 {
		t.Errorf("panic 后仍应继续逆序关闭其余扩展，healthy 关闭 %d 次", closes)
	}
	want := []string{"start:mail", "close:mail"}
	if got := log.snapshot(); len(got) != len(want) {
		t.Errorf("关闭顺序 = %v，期望 %v", got, want)
	}
}

func TestExtensionStartTimeoutFailsClosed(t *testing.T) {
	first := newTestExtension(ExtensionKindStorage, "first")
	first.owned = &fakeResource{}
	stalled := &stalledExtension{
		info:    ExtensionInfo{Kind: ExtensionKindMFA, Name: "stalled", Version: "1.0.0"},
		release: make(chan struct{}),
	}
	instance, err := New(Options{
		Extensions:            []Extension{first, stalled},
		ExtensionStartTimeout: 150 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	started := time.Now()
	startErr := instance.Start(context.Background())
	elapsed := time.Since(started)
	close(stalled.release) // 释放忽略 ctx 的扩展协程，避免测试遗留 goroutine。
	if startErr == nil || !IsErrorCode(startErr, CodeInternalError) {
		t.Fatalf("扩展启动超时应返回 INTERNAL_ERROR，实际 %v", startErr)
	}
	if !errors.Is(startErr, errExtensionStartTimeout) {
		t.Errorf("错误应保留扩展启动超时原因：%v", startErr)
	}
	if elapsed > 3*time.Second {
		t.Errorf("单扩展超时 %s 不应耗时 %v", 150*time.Millisecond, elapsed)
	}
	if got := instance.State(); got != StateClosed {
		t.Errorf("超时后状态 = %q，期望 %q", got, StateClosed)
	}
	if starts, closes := first.counts(); starts != 1 || closes != 1 {
		t.Errorf("超时后应回滚已启动扩展，实际启动/关闭 = %d/%d", starts, closes)
	}
}

func TestExtensionStartTimeoutValidation(t *testing.T) {
	extension := newTestExtension(ExtensionKindStorage, "db")
	for _, timeout := range []time.Duration{
		time.Millisecond,
		MaxExtensionStartTimeout + time.Second,
	} {
		if _, err := New(Options{Extensions: []Extension{extension},
			ExtensionStartTimeout: timeout}); err == nil || !IsErrorCode(err, CodeConfigInvalid) {
			t.Errorf("ExtensionStartTimeout=%s 应返回 CONFIG_INVALID，实际 %v", timeout, err)
		}
	}
	if _, err := New(Options{Extensions: []Extension{extension},
		ExtensionStartTimeout: time.Second}); err != nil {
		t.Errorf("合法 ExtensionStartTimeout 被拒绝：%v", err)
	}
}

func TestComponentTypedNilRejected(t *testing.T) {
	if _, err := New(Options{Components: []BackgroundComponent{
		(*fakeComponent)(nil)}}); err == nil {
		t.Fatal("typed-nil 后台组件应被拒绝")
	}
}

// panickingComponent 模拟后台组件在 Close 中 panic 的编程错误。
type panickingComponent struct {
	panics bool

	mu     sync.Mutex
	closes int
}

func (c *panickingComponent) Start(context.Context) error { return nil }

func (c *panickingComponent) Close(context.Context) error {
	c.mu.Lock()
	c.closes++
	c.mu.Unlock()
	if c.panics {
		panic("模拟组件关闭 panic")
	}
	return nil
}

func (c *panickingComponent) closeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closes
}

func TestExtensionStartCancelIgnoringContextBounded(t *testing.T) {
	stalled := &stalledExtension{
		info:    ExtensionInfo{Kind: ExtensionKindStorage, Name: "stalled-cancel", Version: "1.0.0"},
		release: make(chan struct{}),
	}
	instance, err := New(Options{
		Extensions:            []Extension{stalled},
		ExtensionStartTimeout: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	startErr := instance.Start(ctx)
	elapsed := time.Since(started)
	close(stalled.release)
	if !errors.Is(startErr, context.DeadlineExceeded) {
		t.Fatalf("Start() = %v，期望包装 DeadlineExceeded", startErr)
	}
	if elapsed > 2*time.Second {
		t.Errorf("忽略 ctx 的扩展不应使取消路径长期阻塞，实际 %v", elapsed)
	}
	appErr, ok := AsAppError(startErr)
	if !ok || appErr.Unwrap() == nil ||
		!strings.Contains(appErr.Unwrap().Error(), "可能遗留资源") {
		t.Errorf("取消后扩展未自清理应明确标记可能遗留资源：%v", startErr)
	}
	if got := instance.State(); got != StateClosed {
		t.Errorf("状态 = %q，期望 %q", got, StateClosed)
	}
}

func TestComponentClosePanicRecoveredAndContinues(t *testing.T) {
	healthy := &panickingComponent{}
	panicking := &panickingComponent{panics: true}
	instance, err := New(Options{Components: []BackgroundComponent{healthy, panicking}})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	if err := instance.Start(context.Background()); err != nil {
		t.Fatalf("Start() 失败：%v", err)
	}
	closeErr := instance.Close(context.Background())
	appErr, ok := AsAppError(closeErr)
	if !ok || appErr.Unwrap() == nil || !strings.Contains(appErr.Unwrap().Error(), "panic") {
		t.Fatalf("组件 Close panic 应转为错误返回，实际 %v", closeErr)
	}
	if got := instance.State(); got != StateClosed {
		t.Errorf("关闭后状态 = %q，期望 %q", got, StateClosed)
	}
	if healthy.closeCount() != 1 || panicking.closeCount() != 1 {
		t.Errorf("panic 后仍应关闭其余组件，实际 healthy=%d panicking=%d",
			healthy.closeCount(), panicking.closeCount())
	}
	if err := instance.Close(context.Background()); err != nil {
		t.Errorf("重复 Close() = %v，期望 nil", err)
	}
}

func TestAccessRequestAppIDValidation(t *testing.T) {
	controller := &recordingAccessController{
		decision: AccessDecision{Allowed: true, Reason: "permission_granted"},
	}
	instance, err := New(Options{AccessControl: controller})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	user := Identity{Kind: IdentityKindUser, SubjectID: "user-1"}
	invalidAppIDs := []string{
		"app id",
		"app/1",
		"应用",
		strings.Repeat("a", MaxCorrelationIDLength+1),
	}
	for index, appID := range invalidAppIDs {
		if _, err := instance.CheckAccess(context.Background(), AccessRequest{
			Identity: user, Permission: "users.read",
			Scope: PermissionScopeApplication, AppID: appID}); err == nil ||
			!IsErrorCode(err, CodeReqInvalid) {
			t.Errorf("非法 AppID 用例 %d 应返回 REQ_INVALID，实际 %v", index, err)
		}
	}
	if len(controller.snapshot()) != 0 {
		t.Errorf("非法 AppID 不应调用授权扩展")
	}
	decision, err := instance.CheckAccess(context.Background(), AccessRequest{
		Identity: user, Permission: "users.read",
		Scope: PermissionScopeApplication, AppID: "app-1"})
	if err != nil || !decision.Allowed {
		t.Fatalf("合法 AppID 应放行：%+v %v", decision, err)
	}
}
