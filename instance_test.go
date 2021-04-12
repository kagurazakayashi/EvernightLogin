package login

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"
)

// fakeResource 模拟数据库、HTTP 服务器等资源，只记录打开/关闭次数，用于验证
// 资源所有权：组件自己创建的资源应被关闭，宿主传入的资源不应被关闭。
type fakeResource struct {
	mu     sync.Mutex
	opened int
	closed int
}

func (r *fakeResource) markOpened() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.opened++
}

func (r *fakeResource) markClosed() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed++
}

func (r *fakeResource) counts() (opened, closed int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.opened, r.closed
}

// eventLog 记录组件生命周期事件，用于断言启动/关闭顺序。
type eventLog struct {
	mu     sync.Mutex
	events []string
}

func (l *eventLog) add(event string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, event)
}

func (l *eventLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.events))
	copy(out, l.events)
	return out
}

// fakeComponent 模拟后续步骤的数据库、HTTP 或后台任务组件。
//
// owned 模拟组件自己创建的资源，在 Close 中释放；host 模拟宿主拥有的资源，
// 组件只使用、不关闭。startErr/closeErr 用于注入失败；blockStart/blockClose
// 用于验证 ctx 取消是否会传给组件。
type fakeComponent struct {
	name       string
	log        *eventLog
	startErr   error
	closeErr   error
	owned      *fakeResource
	host       *fakeResource
	blockStart bool
	blockClose bool

	mu     sync.Mutex
	starts int
	closes int
}

func (c *fakeComponent) Start(ctx context.Context) error {
	c.mu.Lock()
	c.starts++
	c.mu.Unlock()
	if c.log != nil {
		c.log.add("start:" + c.name)
	}
	if c.owned != nil {
		c.owned.markOpened()
	}
	if c.blockStart {
		<-ctx.Done()
		if c.owned != nil {
			// 启动失败的组件必须在返回错误前自行清理。
			c.owned.markClosed()
		}
		return ctx.Err()
	}
	if c.startErr != nil {
		if c.owned != nil {
			c.owned.markClosed()
		}
		return c.startErr
	}
	return nil
}

func (c *fakeComponent) Close(ctx context.Context) error {
	c.mu.Lock()
	c.closes++
	c.mu.Unlock()
	if c.log != nil {
		c.log.add("close:" + c.name)
	}
	if c.owned != nil {
		c.owned.markClosed()
	}
	// 宿主资源（c.host）由宿主关闭；组件 Close 不得关闭它。
	if c.blockClose {
		<-ctx.Done()
		return ctx.Err()
	}
	return c.closeErr
}

func (c *fakeComponent) counts() (starts, closes int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.starts, c.closes
}

func TestNewDoesNotStartComponents(t *testing.T) {
	log := &eventLog{}
	component := &fakeComponent{name: "a", log: log}

	instance, err := New(Options{Components: []BackgroundComponent{component}})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	if got := instance.State(); got != StateNew {
		t.Errorf("构造后状态 = %q，期望 %q", got, StateNew)
	}
	if starts, _ := component.counts(); starts != 0 {
		t.Errorf("构造实例不应启动组件，实际启动 %d 次", starts)
	}
	if events := log.snapshot(); len(events) != 0 {
		t.Errorf("构造实例不应产生组件事件：%v", events)
	}
	if got := instance.Config(); got.Server.ListenAddr != Default().Server.ListenAddr {
		t.Errorf("构造实例不应修改默认配置：%+v", got.Server)
	}
}

func TestLifecycleOrderAndReentry(t *testing.T) {
	log := &eventLog{}
	components := []BackgroundComponent{
		&fakeComponent{name: "a", log: log},
		&fakeComponent{name: "b", log: log},
		&fakeComponent{name: "c", log: log},
	}
	instance, err := New(Options{Components: components})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}

	if err := instance.Start(context.Background()); err != nil {
		t.Fatalf("Start() 失败：%v", err)
	}
	if got := instance.State(); got != StateRunning {
		t.Errorf("启动后状态 = %q，期望 %q", got, StateRunning)
	}
	if err := instance.Start(context.Background()); !errors.Is(err, ErrAlreadyStarted) {
		t.Errorf("重复 Start() = %v，期望 ErrAlreadyStarted", err)
	}

	if err := instance.Close(context.Background()); err != nil {
		t.Fatalf("Close() 失败：%v", err)
	}
	if got := instance.State(); got != StateClosed {
		t.Errorf("关闭后状态 = %q，期望 %q", got, StateClosed)
	}
	for _, component := range components {
		if starts, closes := component.(*fakeComponent).counts(); starts != 1 || closes != 1 {
			t.Errorf("组件 %s 启动/关闭次数 = %d/%d，期望 1/1",
				component.(*fakeComponent).name, starts, closes)
		}
	}
	if err := instance.Close(context.Background()); err != nil {
		t.Errorf("重复 Close() = %v，期望 nil", err)
	}
	for _, component := range components {
		if _, closes := component.(*fakeComponent).counts(); closes != 1 {
			t.Errorf("重复 Close() 不应再次关闭组件，实际 %d 次", closes)
		}
	}
	if err := instance.Start(context.Background()); !errors.Is(err, ErrClosed) {
		t.Errorf("关闭后 Start() = %v，期望 ErrClosed", err)
	}

	want := []string{
		"start:a", "start:b", "start:c",
		"close:c", "close:b", "close:a",
	}
	got := log.snapshot()
	if len(got) != len(want) {
		t.Fatalf("事件顺序 = %v，期望 %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("事件顺序 = %v，期望 %v", got, want)
		}
	}
}

func TestCloseBeforeStart(t *testing.T) {
	component := &fakeComponent{name: "a"}
	instance, err := New(Options{Components: []BackgroundComponent{component}})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}

	if err := instance.Close(context.Background()); err != nil {
		t.Fatalf("未启动直接 Close() 失败：%v", err)
	}
	if got := instance.State(); got != StateClosed {
		t.Errorf("关闭后状态 = %q，期望 %q", got, StateClosed)
	}
	if starts, closes := component.counts(); starts != 0 || closes != 0 {
		t.Errorf("未启动组件不应被启动或关闭，实际 %d/%d", starts, closes)
	}
	if err := instance.Start(context.Background()); !errors.Is(err, ErrClosed) {
		t.Errorf("关闭后 Start() = %v，期望 ErrClosed", err)
	}
	if err := instance.Close(context.Background()); err != nil {
		t.Errorf("重复 Close() = %v，期望 nil", err)
	}
}

func TestStartFailureRollback(t *testing.T) {
	startErr := errors.New("模拟数据库启动失败")
	log := &eventLog{}
	firstOwned := &fakeResource{}
	failedOwned := &fakeResource{}
	first := &fakeComponent{name: "a", log: log, owned: firstOwned}
	failed := &fakeComponent{name: "b", log: log, owned: failedOwned, startErr: startErr}
	neverStarted := &fakeComponent{name: "c", log: log}

	instance, err := New(Options{Components: []BackgroundComponent{first, failed, neverStarted}})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	if err := instance.Start(context.Background()); !errors.Is(err, startErr) {
		t.Fatalf("Start() = %v，期望包装启动错误", err)
	}
	if got := instance.State(); got != StateClosed {
		t.Errorf("启动失败后状态 = %q，期望 %q", got, StateClosed)
	}

	if starts, closes := first.counts(); starts != 1 || closes != 1 {
		t.Errorf("已启动组件应逆序回滚关闭，实际启动/关闭 = %d/%d", starts, closes)
	}
	if opened, closed := firstOwned.counts(); opened != 1 || closed != 1 {
		t.Errorf("已启动组件的自有资源应在回滚时释放，实际打开/关闭 = %d/%d", opened, closed)
	}
	if starts, closes := failed.counts(); starts != 1 || closes != 0 {
		t.Errorf("失败组件应由自己清理，Instance 不应再调用 Close，实际启动/关闭 = %d/%d", starts, closes)
	}
	if opened, closed := failedOwned.counts(); opened != 1 || closed != 1 {
		t.Errorf("失败组件应自行释放资源，实际打开/关闭 = %d/%d", opened, closed)
	}
	if starts, _ := neverStarted.counts(); starts != 0 {
		t.Errorf("失败后不应继续启动后续组件，实际启动 %d 次", starts)
	}

	if err := instance.Start(context.Background()); !errors.Is(err, ErrClosed) {
		t.Errorf("启动失败后再次 Start() = %v，期望 ErrClosed", err)
	}
	if err := instance.Close(context.Background()); err != nil {
		t.Errorf("启动失败后 Close() = %v，期望 nil", err)
	}
	for _, component := range []*fakeComponent{first, failed, neverStarted} {
		if _, closes := component.counts(); closes > 1 {
			t.Errorf("组件 %s 被重复关闭", component.name)
		}
	}

	want := []string{"start:a", "start:b", "close:a"}
	got := log.snapshot()
	if len(got) != len(want) {
		t.Fatalf("事件顺序 = %v，期望 %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("事件顺序 = %v，期望 %v", got, want)
		}
	}
}

func TestStartFailureRollbackJoinsCloseError(t *testing.T) {
	startErr := errors.New("模拟启动失败")
	closeErr := errors.New("模拟回滚关闭失败")
	first := &fakeComponent{name: "a", closeErr: closeErr}
	failed := &fakeComponent{name: "b", startErr: startErr}
	instance, err := New(Options{Components: []BackgroundComponent{first, failed}})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	err = instance.Start(context.Background())
	if !errors.Is(err, startErr) {
		t.Errorf("Start() 错误未包含启动错误：%v", err)
	}
	if !errors.Is(err, closeErr) {
		t.Errorf("Start() 错误未包含回滚关闭错误：%v", err)
	}
}

func TestStartCancellationRollback(t *testing.T) {
	first := &fakeComponent{name: "a"}
	blocked := &fakeComponent{name: "b", blockStart: true, owned: &fakeResource{}}
	instance, err := New(Options{Components: []BackgroundComponent{first, blocked}})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	err = instance.Start(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Start() = %v，期望包装 DeadlineExceeded", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Errorf("启动取消耗时 %v，超出预期", elapsed)
	}
	if starts, closes := first.counts(); starts != 1 || closes != 1 {
		t.Errorf("取消后应回滚已启动组件，实际启动/关闭 = %d/%d", starts, closes)
	}
	if starts, closes := blocked.counts(); starts != 1 || closes != 0 {
		t.Errorf("被取消的组件应自行清理，实际启动/关闭 = %d/%d", starts, closes)
	}
	if got := instance.State(); got != StateClosed {
		t.Errorf("启动取消后状态 = %q，期望 %q", got, StateClosed)
	}
}

func TestStartWithCancelledContext(t *testing.T) {
	component := &fakeComponent{name: "a"}
	instance, err := New(Options{Components: []BackgroundComponent{component}})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := instance.Start(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Start() = %v，期望 context.Canceled", err)
	}
	if starts, _ := component.counts(); starts != 0 {
		t.Errorf("ctx 已取消时不应启动组件，实际启动 %d 次", starts)
	}
	if got := instance.State(); got != StateClosed {
		t.Errorf("启动取消后状态 = %q，期望 %q", got, StateClosed)
	}
}

func TestCloseTimeout(t *testing.T) {
	t.Run("调用方期限优先", func(t *testing.T) {
		component := &fakeComponent{name: "a", blockClose: true}
		instance, err := New(Options{Components: []BackgroundComponent{component}})
		if err != nil {
			t.Fatalf("New() 失败：%v", err)
		}
		if err := instance.Start(context.Background()); err != nil {
			t.Fatalf("Start() 失败：%v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		started := time.Now()
		err = instance.Close(ctx)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Close() = %v，期望包装 DeadlineExceeded", err)
		}
		if elapsed := time.Since(started); elapsed > 2*time.Second {
			t.Errorf("关闭超时耗时 %v，超出预期", elapsed)
		}
		if _, closes := component.counts(); closes != 1 {
			t.Errorf("超时仍应尝试关闭组件一次，实际 %d 次", closes)
		}
		if got := instance.State(); got != StateClosed {
			t.Errorf("超时关闭后状态 = %q，期望 %q", got, StateClosed)
		}
		if err := instance.Close(context.Background()); err != nil {
			t.Errorf("超时后重复 Close() = %v，期望 nil", err)
		}
	})

	t.Run("配置关闭期限上限", func(t *testing.T) {
		config := Default()
		config.Server.ShutdownTimeoutSeconds = 1
		component := &fakeComponent{name: "a", blockClose: true}
		instance, err := New(Options{Config: &config, Components: []BackgroundComponent{component}})
		if err != nil {
			t.Fatalf("New() 失败：%v", err)
		}
		if err := instance.Start(context.Background()); err != nil {
			t.Fatalf("Start() 失败：%v", err)
		}

		started := time.Now()
		err = instance.Close(context.Background())
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Close() = %v，期望按配置期限取消并返回 DeadlineExceeded", err)
		}
		if elapsed := time.Since(started); elapsed < 900*time.Millisecond || elapsed > 2*time.Second {
			t.Errorf("配置关闭期限约 1s，实际 %v", elapsed)
		}
	})
}

func TestCloseErrorAggregation(t *testing.T) {
	errA := errors.New("关闭 A 失败")
	errB := errors.New("关闭 B 失败")
	a := &fakeComponent{name: "a", closeErr: errA}
	b := &fakeComponent{name: "b", closeErr: errB}
	instance, err := New(Options{Components: []BackgroundComponent{a, b}})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	if err := instance.Start(context.Background()); err != nil {
		t.Fatalf("Start() 失败：%v", err)
	}
	closeErr := instance.Close(context.Background())
	if !errors.Is(closeErr, errA) || !errors.Is(closeErr, errB) {
		t.Errorf("Close() = %v，期望同时包含两个组件错误", closeErr)
	}
	if got := instance.State(); got != StateClosed {
		t.Errorf("关闭失败后状态 = %q，期望 %q", got, StateClosed)
	}
	if err := instance.Close(context.Background()); err != nil {
		t.Errorf("重复 Close() = %v，期望 nil（不重复返回旧错误）", err)
	}
}

func TestMultiInstanceIsolation(t *testing.T) {
	configA := Default()
	configB := Default()
	configB.Server.ListenAddr = "127.0.0.1:9999"

	logA := &eventLog{}
	logB := &eventLog{}
	a1 := &fakeComponent{name: "a1", log: logA}
	a2 := &fakeComponent{name: "a2", log: logA}
	b1 := &fakeComponent{name: "b1", log: logB}

	instanceA, err := New(Options{Config: &configA, Components: []BackgroundComponent{a1, a2}})
	if err != nil {
		t.Fatalf("New(A) 失败：%v", err)
	}
	instanceB, err := New(Options{Config: &configB, Components: []BackgroundComponent{b1}})
	if err != nil {
		t.Fatalf("New(B) 失败：%v", err)
	}
	if instanceA.Config().Server.ListenAddr == instanceB.Config().Server.ListenAddr {
		t.Fatal("两个实例的配置不应互相影响")
	}

	if err := instanceA.Start(context.Background()); err != nil {
		t.Fatalf("Start(A) 失败：%v", err)
	}
	if got := instanceB.State(); got != StateNew {
		t.Errorf("启动 A 不应影响 B 的状态，B 状态 = %q", got)
	}
	if starts, _ := b1.counts(); starts != 0 {
		t.Errorf("启动 A 不应启动 B 的组件，实际启动 %d 次", starts)
	}

	if err := instanceB.Start(context.Background()); err != nil {
		t.Fatalf("Start(B) 失败：%v", err)
	}
	if err := instanceA.Close(context.Background()); err != nil {
		t.Fatalf("Close(A) 失败：%v", err)
	}
	if got := instanceB.State(); got != StateRunning {
		t.Errorf("关闭 A 不应影响 B 的状态，B 状态 = %q", got)
	}
	if starts, _ := b1.counts(); starts != 1 {
		t.Errorf("B 组件启动次数 = %d，期望 1", starts)
	}
	if err := instanceB.Close(context.Background()); err != nil {
		t.Fatalf("Close(B) 失败：%v", err)
	}
}

func TestHostResourceNotClosed(t *testing.T) {
	// owned 模拟组件自己创建的资源；host 模拟宿主传入的资源（如宿主数据库）。
	owned := &fakeResource{}
	host := &fakeResource{}
	component := &fakeComponent{name: "db", owned: owned, host: host}

	instance, err := New(Options{Components: []BackgroundComponent{component}})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	if err := instance.Start(context.Background()); err != nil {
		t.Fatalf("Start() 失败：%v", err)
	}
	if err := instance.Close(context.Background()); err != nil {
		t.Fatalf("Close() 失败：%v", err)
	}

	if opened, closed := owned.counts(); opened != 1 || closed != 1 {
		t.Errorf("组件自有资源的打开/关闭次数 = %d/%d，期望 1/1", opened, closed)
	}
	if _, closed := host.counts(); closed != 0 {
		t.Errorf("宿主资源不应被组件或实例关闭，实际关闭 %d 次", closed)
	}
}

func TestOptionsAreCopied(t *testing.T) {
	a := &fakeComponent{name: "a"}
	b := &fakeComponent{name: "b"}
	components := []BackgroundComponent{a}
	instance, err := New(Options{Components: components})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	components[0] = b
	if err := instance.Start(context.Background()); err != nil {
		t.Fatalf("Start() 失败：%v", err)
	}
	if starts, _ := a.counts(); starts != 1 {
		t.Errorf("实例应保留构造时的组件副本，a 启动次数 = %d", starts)
	}
	if starts, _ := b.counts(); starts != 0 {
		t.Errorf("替换调用方切片不应影响实例，b 启动次数 = %d", starts)
	}
}

func TestNewValidation(t *testing.T) {
	t.Run("nil 组件被拒绝", func(t *testing.T) {
		if _, err := New(Options{Components: []BackgroundComponent{nil}}); err == nil {
			t.Fatal("nil 组件应导致 New 失败")
		}
	})

	t.Run("非法配置被拒绝", func(t *testing.T) {
		config := Default()
		config.Logging.Level = LogLevel("verbose")
		_, err := New(Options{Config: &config})
		if err == nil {
			t.Fatal("非法配置应导致 New 失败")
		}
		var configErrs ConfigErrors
		if !errors.As(err, &configErrs) {
			t.Errorf("错误应保留 ConfigErrors 原因链：%v", err)
		}
	})

	t.Run("配置副本隔离", func(t *testing.T) {
		config := Default()
		config.Server.ListenAddr = "127.0.0.1:1234"
		instance, err := New(Options{Config: &config})
		if err != nil {
			t.Fatalf("New() 失败：%v", err)
		}
		config.Server.ListenAddr = "127.0.0.1:5678"
		if got := instance.Config().Server.ListenAddr; got != "127.0.0.1:1234" {
			t.Errorf("修改调用方配置不应影响实例，实际 %q", got)
		}
		returned := instance.Config()
		returned.Server.ListenAddr = "127.0.0.1:9999"
		if got := instance.Config().Server.ListenAddr; got != "127.0.0.1:1234" {
			t.Errorf("修改返回的配置副本不应影响实例，实际 %q", got)
		}
	})
}

func TestNilContextAccepted(t *testing.T) {
	component := &fakeComponent{name: "a"}
	instance, err := New(Options{Components: []BackgroundComponent{component}})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	if err := instance.Start(nil); err != nil {
		t.Fatalf("Start(nil) 失败：%v", err)
	}
	if err := instance.Close(nil); err != nil {
		t.Fatalf("Close(nil) 失败：%v", err)
	}
}

func TestConcurrentStart(t *testing.T) {
	component := &fakeComponent{name: "a"}
	instance, err := New(Options{Components: []BackgroundComponent{component}})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}

	const workers = 8
	results := make([]error, workers)
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			results[index] = instance.Start(context.Background())
		}(worker)
	}
	wait.Wait()

	success := 0
	for _, result := range results {
		switch {
		case result == nil:
			success++
		case errors.Is(result, ErrAlreadyStarted):
		default:
			t.Errorf("并发 Start() 返回意外错误：%v", result)
		}
	}
	if success != 1 {
		t.Errorf("并发 Start() 成功次数 = %d，期望 1", success)
	}
	if starts, _ := component.counts(); starts != 1 {
		t.Errorf("组件启动次数 = %d，期望 1", starts)
	}
}

func TestConcurrentClose(t *testing.T) {
	log := &eventLog{}
	components := []BackgroundComponent{
		&fakeComponent{name: "a", log: log},
		&fakeComponent{name: "b", log: log},
	}
	instance, err := New(Options{Components: components})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	if err := instance.Start(context.Background()); err != nil {
		t.Fatalf("Start() 失败：%v", err)
	}

	const workers = 8
	results := make([]error, workers)
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			results[index] = instance.Close(context.Background())
		}(worker)
	}
	wait.Wait()

	for _, result := range results {
		if result != nil {
			t.Errorf("并发 Close() 返回错误：%v", result)
		}
	}
	for _, component := range components {
		if _, closes := component.(*fakeComponent).counts(); closes != 1 {
			t.Errorf("组件 %s 被关闭 %d 次，期望 1",
				component.(*fakeComponent).name, closes)
		}
	}
	if events := log.snapshot(); len(events) != 4 {
		t.Errorf("并发 Close 应只产生一组事件，实际 %v", events)
	}
}

func TestNoGoroutineLeak(t *testing.T) {
	before := runtime.NumGoroutine()
	for round := 0; round < 20; round++ {
		component := &fakeComponent{name: "a", owned: &fakeResource{}}
		instance, err := New(Options{Components: []BackgroundComponent{component}})
		if err != nil {
			t.Fatalf("New() 失败：%v", err)
		}
		if err := instance.Start(context.Background()); err != nil {
			t.Fatalf("Start() 失败：%v", err)
		}
		if err := instance.Close(context.Background()); err != nil {
			t.Fatalf("Close() 失败：%v", err)
		}
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		runtime.GC()
		if runtime.NumGoroutine() <= before {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("实例创建/关闭后 goroutine 数未回落：before=%d after=%d",
				before, runtime.NumGoroutine())
		}
		time.Sleep(10 * time.Millisecond)
	}
}
