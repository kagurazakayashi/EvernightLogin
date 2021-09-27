package login

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeExtension 模拟宿主注册的扩展：记录自己的启动/关闭次数与顺序，并区分
// "扩展自己创建的资源（owned）"与"宿主拥有的资源（host）"。
type fakeExtension struct {
	info       ExtensionInfo
	log        *eventLog
	startErr   error
	closeErr   error
	owned      *fakeResource
	host       *fakeResource
	blockStart bool

	mu     sync.Mutex
	starts int
	closes int
}

func (e *fakeExtension) ExtensionInfo() ExtensionInfo { return e.info }

func (e *fakeExtension) Start(ctx context.Context) error {
	e.mu.Lock()
	e.starts++
	e.mu.Unlock()
	if e.log != nil {
		e.log.add("start:" + e.info.Name)
	}
	if e.owned != nil {
		e.owned.markOpened()
	}
	if e.blockStart {
		<-ctx.Done()
		if e.owned != nil {
			e.owned.markClosed()
		}
		return ctx.Err()
	}
	if e.startErr != nil {
		if e.owned != nil {
			e.owned.markClosed()
		}
		return e.startErr
	}
	return nil
}

func (e *fakeExtension) Close(ctx context.Context) error {
	e.mu.Lock()
	e.closes++
	e.mu.Unlock()
	if e.log != nil {
		e.log.add("close:" + e.info.Name)
	}
	if e.owned != nil {
		e.owned.markClosed()
	}
	// 宿主资源（e.host）由宿主关闭，扩展不得关闭它。
	return e.closeErr
}

func (e *fakeExtension) counts() (starts, closes int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.starts, e.closes
}

// readyFailingExtension 在 Ready 阶段报告不健康。
type readyFailingExtension struct {
	fakeExtension
	readyErr error
}

func (e *readyFailingExtension) CheckReady(context.Context) error { return e.readyErr }

func newTestExtension(kind ExtensionKind, name string) *fakeExtension {
	return &fakeExtension{info: ExtensionInfo{Kind: kind, Name: name, Version: "1.0.0"}}
}

func TestExtensionRegistrationValidation(t *testing.T) {
	tooLong := make([]byte, MaxExtensionNameLength+1)
	for index := range tooLong {
		tooLong[index] = 'a'
	}
	tooMany := make([]Extension, 0, MaxExtensions+1)
	for index := 0; index <= MaxExtensions; index++ {
		tooMany = append(tooMany, newTestExtension(ExtensionKindComponent,
			extensionName(index)))
	}

	cases := []struct {
		name       string
		extensions []Extension
	}{
		{name: "nil 扩展", extensions: []Extension{nil}},
		{name: "typed-nil 扩展", extensions: []Extension{(*fakeExtension)(nil)}},
		{name: "未定义分类", extensions: []Extension{&fakeExtension{
			info: ExtensionInfo{Kind: ExtensionKind("plugin"), Name: "x", Version: "1"}}}},
		{name: "空名称", extensions: []Extension{&fakeExtension{
			info: ExtensionInfo{Kind: ExtensionKindStorage, Version: "1"}}}},
		{name: "非法名称", extensions: []Extension{&fakeExtension{
			info: ExtensionInfo{Kind: ExtensionKindStorage, Name: "bad name", Version: "1"}}}},
		{name: "超长名称", extensions: []Extension{&fakeExtension{
			info: ExtensionInfo{Kind: ExtensionKindStorage, Name: string(tooLong), Version: "1"}}}},
		{name: "重复分类与名称", extensions: []Extension{
			newTestExtension(ExtensionKindStorage, "db"),
			newTestExtension(ExtensionKindStorage, "db"),
		}},
		{name: "认证扩展缺版本", extensions: []Extension{&fakeExtension{
			info: ExtensionInfo{Kind: ExtensionKindAuthentication, Name: "idp"}}}},
		{name: "第二因素扩展缺版本", extensions: []Extension{&fakeExtension{
			info: ExtensionInfo{Kind: ExtensionKindMFA, Name: "otp"}}}},
		{name: "超过扩展数量上限", extensions: tooMany},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := New(Options{Extensions: testCase.extensions})
			if err == nil {
				t.Fatal("非法扩展注册应导致 New 失败")
			}
			if !IsErrorCode(err, CodeConfigInvalid) {
				t.Errorf("错误码 = %v，期望 CONFIG_INVALID: %v", err, err)
			}
		})
	}

	// 同名称、不同分类不构成重复；安全敏感扩展声明版本后可注册。
	valid := []Extension{
		newTestExtension(ExtensionKindStorage, "db"),
		newTestExtension(ExtensionKindNotification, "db"),
		newTestExtension(ExtensionKindAuthentication, "idp"),
		newTestExtension(ExtensionKindMFA, "second"),
	}
	instance, err := New(Options{Extensions: valid})
	if err != nil {
		t.Fatalf("合法扩展注册失败：%v", err)
	}
	infos := instance.Extensions()
	if len(infos) != len(valid) {
		t.Fatalf("扩展元数据数量 = %d，期望 %d", len(infos), len(valid))
	}
	if infos[0].Kind != ExtensionKindStorage || infos[0].Name != "db" {
		t.Errorf("扩展元数据顺序/内容异常：%+v", infos[0])
	}
}

// extensionName 生成稳定且合法的扩展示例名称。
func extensionName(index int) string {
	return "extension_" + string(rune('a'+index%26)) + "_" + twoDigit(index)
}

// twoDigit 把 0..99 的数字编码为两位 ASCII 数字，避免扩展名称过长或重复。
func twoDigit(value int) string {
	return string([]byte{byte('0' + value/10), byte('0' + value%10)})
}

func TestExtensionLifecycleOrder(t *testing.T) {
	log := &eventLog{}
	first := newTestExtension(ExtensionKindStorage, "storage")
	first.log = log
	second := newTestExtension(ExtensionKindNotification, "mail")
	second.log = log
	component := &fakeComponent{name: "server", log: log}

	instance, err := New(Options{
		Extensions: []Extension{first, second},
		Components: []BackgroundComponent{component},
	})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	if err := instance.Start(context.Background()); err != nil {
		t.Fatalf("Start() 失败：%v", err)
	}
	if got := instance.State(); got != StateRunning {
		t.Errorf("状态 = %q，期望 %q", got, StateRunning)
	}
	if err := instance.Close(context.Background()); err != nil {
		t.Fatalf("Close() 失败：%v", err)
	}

	want := []string{"start:storage", "start:mail", "start:server",
		"close:server", "close:mail", "close:storage"}
	got := log.snapshot()
	if len(got) != len(want) {
		t.Fatalf("生命周期顺序 = %v，期望 %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("生命周期顺序 = %v，期望 %v", got, want)
		}
	}
}

func TestExtensionStartFailureRollsBack(t *testing.T) {
	startErr := errors.New("模拟存储扩展启动失败")
	log := &eventLog{}
	first := newTestExtension(ExtensionKindStorage, "first")
	first.log = log
	first.owned = &fakeResource{}
	failed := newTestExtension(ExtensionKindStorage, "failed")
	failed.log = log
	failed.startErr = startErr
	component := &fakeComponent{name: "server", log: log}

	instance, err := New(Options{
		Extensions: []Extension{first, failed},
		Components: []BackgroundComponent{component},
	})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	startErrOut := instance.Start(context.Background())
	if !errors.Is(startErrOut, startErr) {
		t.Fatalf("Start() = %v，期望包装扩展启动错误", startErrOut)
	}
	if got := instance.State(); got != StateClosed {
		t.Errorf("启动失败后状态 = %q，期望 %q", got, StateClosed)
	}
	if starts, closes := first.counts(); starts != 1 || closes != 1 {
		t.Errorf("已启动扩展应被回滚关闭，实际启动/关闭 = %d/%d", starts, closes)
	}
	if opened, closed := first.owned.counts(); opened != 1 || closed != 1 {
		t.Errorf("回滚应释放扩展自有资源，实际打开/关闭 = %d/%d", opened, closed)
	}
	if starts, closes := failed.counts(); starts != 1 || closes != 0 {
		t.Errorf("失败扩展应自行清理，Instance 不应再关闭它，实际启动/关闭 = %d/%d", starts, closes)
	}
	if starts, _ := component.counts(); starts != 0 {
		t.Errorf("扩展失败后不应启动后台组件，实际启动 %d 次", starts)
	}
	want := []string{"start:first", "start:failed", "close:first"}
	if got := log.snapshot(); len(got) != len(want) {
		t.Fatalf("事件顺序 = %v，期望 %v", got, want)
	}
}

func TestExtensionRolledBackWhenComponentFails(t *testing.T) {
	componentErr := errors.New("模拟 HTTP 组件启动失败")
	extension := newTestExtension(ExtensionKindPage, "page")
	extension.owned = &fakeResource{}
	component := &fakeComponent{name: "server", startErr: componentErr}

	instance, err := New(Options{
		Extensions: []Extension{extension},
		Components: []BackgroundComponent{component},
	})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	startErr := instance.Start(context.Background())
	if !errors.Is(startErr, componentErr) {
		t.Fatalf("Start() = %v，期望包装组件启动错误", startErr)
	}
	if starts, closes := extension.counts(); starts != 1 || closes != 1 {
		t.Errorf("组件失败后扩展也应回滚关闭，实际启动/关闭 = %d/%d", starts, closes)
	}
	if opened, closed := extension.owned.counts(); opened != 1 || closed != 1 {
		t.Errorf("回滚应释放扩展自有资源，实际打开/关闭 = %d/%d", opened, closed)
	}
}

func TestExtensionAppErrorCodePreserved(t *testing.T) {
	sensitive := newTestExtension(ExtensionKindAuthentication, "idp")
	sensitive.startErr = NewAppError(CodeDBUnavailable, "认证扩展依赖不可用",
		WithRequestID(NewRequestID()))
	instance, err := New(Options{Extensions: []Extension{sensitive}})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	startErr := instance.Start(context.Background())
	if !IsErrorCode(startErr, CodeDBUnavailable) {
		t.Fatalf("启动错误应保留扩展的稳定错误码，实际：%v", startErr)
	}
	if got := instance.State(); got != StateClosed {
		t.Errorf("安全敏感扩展失败必须 fail-closed，状态 = %q", got)
	}
	if err := instance.Start(context.Background()); !errors.Is(err, ErrClosed) {
		t.Errorf("失败后再次 Start = %v，期望 ErrClosed", err)
	}
}

func TestExtensionStartCancellation(t *testing.T) {
	blocked := newTestExtension(ExtensionKindStorage, "blocked")
	blocked.blockStart = true
	blocked.owned = &fakeResource{}
	first := newTestExtension(ExtensionKindStorage, "first")
	instance, err := New(Options{Extensions: []Extension{first, blocked}})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	startErr := instance.Start(ctx)
	if !errors.Is(startErr, context.DeadlineExceeded) {
		t.Fatalf("Start() = %v，期望包装 DeadlineExceeded", startErr)
	}
	if starts, closes := first.counts(); starts != 1 || closes != 1 {
		t.Errorf("取消后应回滚已启动扩展，实际启动/关闭 = %d/%d", starts, closes)
	}
	if starts, closes := blocked.counts(); starts != 1 || closes != 0 {
		t.Errorf("被取消的扩展应自行清理，实际启动/关闭 = %d/%d", starts, closes)
	}
	if opened, closed := blocked.owned.counts(); opened != 1 || closed != 1 {
		t.Errorf("被取消扩展应自行释放资源，实际打开/关闭 = %d/%d", opened, closed)
	}
	if got := instance.State(); got != StateClosed {
		t.Errorf("启动取消后状态 = %q，期望 %q", got, StateClosed)
	}
}

func TestExtensionCloseErrorAggregation(t *testing.T) {
	extensionErr := errors.New("扩展关闭失败")
	componentErr := errors.New("组件关闭失败")
	extension := newTestExtension(ExtensionKindStorage, "db")
	extension.closeErr = extensionErr
	component := &fakeComponent{name: "server", closeErr: componentErr}
	instance, err := New(Options{
		Extensions: []Extension{extension},
		Components: []BackgroundComponent{component},
	})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	if err := instance.Start(context.Background()); err != nil {
		t.Fatalf("Start() 失败：%v", err)
	}
	closeErr := instance.Close(context.Background())
	if !errors.Is(closeErr, extensionErr) || !errors.Is(closeErr, componentErr) {
		t.Errorf("Close() = %v，期望同时包含扩展与组件错误", closeErr)
	}
	if got := instance.State(); got != StateClosed {
		t.Errorf("关闭失败后状态 = %q，期望 %q", got, StateClosed)
	}
	if err := instance.Close(context.Background()); err != nil {
		t.Errorf("重复 Close() = %v，期望 nil（不重复返回旧错误）", err)
	}
	if _, closes := extension.counts(); closes != 1 {
		t.Errorf("扩展关闭次数 = %d，期望 1", closes)
	}
}

func TestExtensionHostResourceNotClosed(t *testing.T) {
	owned := &fakeResource{}
	host := &fakeResource{}
	extension := newTestExtension(ExtensionKindStorage, "db")
	extension.owned = owned
	extension.host = host

	instance, err := New(Options{Extensions: []Extension{extension}})
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
		t.Errorf("扩展自有资源打开/关闭 = %d/%d，期望 1/1", opened, closed)
	}
	if _, closed := host.counts(); closed != 0 {
		t.Errorf("宿主资源不应被扩展或实例关闭，实际关闭 %d 次", closed)
	}
}

func TestMultiInstanceExtensionIsolation(t *testing.T) {
	extensionA := newTestExtension(ExtensionKindStorage, "a")
	extensionB := newTestExtension(ExtensionKindStorage, "b")
	instanceA, err := New(Options{Extensions: []Extension{extensionA}})
	if err != nil {
		t.Fatalf("New(A) 失败：%v", err)
	}
	instanceB, err := New(Options{Extensions: []Extension{extensionB}})
	if err != nil {
		t.Fatalf("New(B) 失败：%v", err)
	}

	if err := instanceA.Start(context.Background()); err != nil {
		t.Fatalf("Start(A) 失败：%v", err)
	}
	if starts, _ := extensionB.counts(); starts != 0 {
		t.Errorf("启动 A 不应启动 B 的扩展，实际 %d 次", starts)
	}
	if got := instanceB.State(); got != StateNew {
		t.Errorf("启动 A 不应影响 B 状态，实际 %q", got)
	}
	if err := instanceB.Start(context.Background()); err != nil {
		t.Fatalf("Start(B) 失败：%v", err)
	}
	if err := instanceA.Close(context.Background()); err != nil {
		t.Fatalf("Close(A) 失败：%v", err)
	}
	if _, closes := extensionB.counts(); closes != 0 {
		t.Errorf("关闭 A 不应关闭 B 的扩展，实际 %d 次", closes)
	}
	if got := instanceB.State(); got != StateRunning {
		t.Errorf("关闭 A 不应影响 B，实际 %q", got)
	}
	if err := instanceB.Close(context.Background()); err != nil {
		t.Fatalf("Close(B) 失败：%v", err)
	}
}

func TestExtensionsSnapshotCopied(t *testing.T) {
	instance, err := New(Options{Extensions: []Extension{
		newTestExtension(ExtensionKindStorage, "db"),
	}})
	if err != nil {
		t.Fatalf("New() 失败：%v", err)
	}
	snapshot := instance.Extensions()
	snapshot[0].Name = "tampered"
	again := instance.Extensions()
	if again[0].Name != "db" {
		t.Errorf("修改返回快照不应影响实例，实际 %q", again[0].Name)
	}
}
