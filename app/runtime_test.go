package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

func testConfig() login.Config {
	cfg := login.Default()
	cfg.Registration.Enabled = true
	cfg.Registration.RequireReview = false
	cfg.Registration.RequireEmailVerification = false
	return cfg
}

// openTestRuntime 在独立临时目录打开真实运行时（真实 SQLite + 受保护主密钥）。
func openTestRuntime(t *testing.T, options Options) *Runtime {
	t.Helper()
	dir := t.TempDir()
	cfg := testConfig()
	if options.Config == nil {
		options.Config = &cfg
	}
	options.DatabasePath = filepath.Join(dir, "login.db")
	options.MasterKeyFile = filepath.Join(dir, "master.key")
	options.CreateMasterKey = true
	options.Migrate = true
	if options.OperatorID == "" {
		options.OperatorID = "embedded-test"
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	runtime, err := Open(context.Background(), options)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	return runtime
}

func TestOpenEnsureRootUsersLoginAccessRevokeStartClose(t *testing.T) {
	ctx := context.Background()
	runtime := openTestRuntime(t, Options{})
	if runtime.State() != login.StateNew {
		t.Fatalf("Open 后状态必须为 StateNew，实际 %q", runtime.State())
	}
	if err := runtime.Ready(ctx); !errors.Is(err, login.ErrNotRunning) {
		t.Fatalf("未 Start 时 Ready 应返回 ErrNotRunning，实际 %v", err)
	}
	if runtime.Instance() == nil || runtime.Instance().State() != login.StateNew {
		t.Fatalf("Instance 必须是 StateNew")
	}
	root, err := runtime.Bootstrap().EnsureRoot(ctx, RootRequest{
		DisplayName: "Root", Password: "V7!qZ2#Lm9@Tp4$x", RequestID: login.NewRequestID(),
	})
	if err != nil {
		t.Fatalf("EnsureRoot: %v", err)
	}
	if root.UserID == "" || root.State == "" {
		t.Fatalf("root 结果不完整: %+v", root)
	}
	if _, err := runtime.Bootstrap().EnsureRoot(ctx, RootRequest{Password: "H4%tY7^cN2&mQ9*p"}); err == nil {
		t.Fatal("重复初始化应被拒绝")
	}
	user, err := runtime.Users().Create(ctx, CreateUserRequest{
		Username: "alice", Password: "K8$wR3!nB6@yF1#v", Nickname: "Alice",
		RequestID: login.NewRequestID(),
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if user.ID == "" || user.Status != "active" {
		t.Fatalf("用户结果异常: %+v", user)
	}
	// 显式启动：只有 Start 才启动后台任务；重复 Start 返回 ErrAlreadyStarted。
	if err := runtime.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if runtime.State() != login.StateRunning {
		t.Fatalf("Start 后状态应为 running，实际 %q", runtime.State())
	}
	if err := runtime.Start(ctx); !errors.Is(err, login.ErrAlreadyStarted) {
		t.Fatalf("重复 Start 应返回 ErrAlreadyStarted，实际 %v", err)
	}
	if err := runtime.Ready(ctx); err != nil {
		t.Fatalf("已启动且无宿主数据库依赖时应就绪: %v", err)
	}
	loginResult, err := runtime.Auth().Login(ctx, LoginRequest{
		Username: "alice", Password: "K8$wR3!nB6@yF1#v", ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID(),
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if len(loginResult.SessionSecret) == 0 || loginResult.SessionID == "" {
		t.Fatalf("登录未返回会话秘密")
	}
	decision, err := runtime.Access().Check(ctx, AccessRequest{
		UserID: user.ID, Permission: "authorization.check", Mode: "all",
	})
	if err != nil {
		t.Fatalf("权限检查错误: %v", err)
	}
	if decision.Allowed {
		t.Fatalf("未授权用户不应允许: %+v", decision)
	}
	if decision.Code == "" {
		t.Fatalf("拒绝必须有稳定码: %+v", decision)
	}
	if err := runtime.Sessions().Revoke(ctx, loginResult.SessionSecret); err != nil {
		t.Fatalf("撤销会话: %v", err)
	}
	if err := runtime.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := runtime.Close(ctx); err != nil {
		t.Fatalf("重复 Close 应安全: %v", err)
	}
	if runtime.State() != login.StateClosed {
		t.Fatalf("Close 后状态应为 closed，实际 %q", runtime.State())
	}
	if err := runtime.Start(ctx); !errors.Is(err, login.ErrClosed) {
		t.Fatalf("关闭后 Start 应返回 ErrClosed，实际 %v", err)
	}
}

// TestOpenMigrateFalseFailsAndCleansUpResources 验证未迁移库 fail-closed，且失败
// 路径不遗留数据库句柄（Windows 下仍能删除整个临时目录）。
func TestOpenMigrateFalseFailsAndCleansUpResources(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig()
	_, err := Open(context.Background(), Options{
		Config: &cfg, DatabasePath: filepath.Join(dir, "login.db"),
		MasterKeyFile: filepath.Join(dir, "master.key"), CreateMasterKey: true,
		Migrate: false, OperatorID: "embedded-test",
	})
	if err == nil {
		t.Fatal("未迁移库必须 fail-closed")
	}
	if !login.IsErrorCode(err, login.CodeConfigInvalid) {
		t.Fatalf("未迁移库应返回 CONFIG_INVALID 稳定码，实际 %v", err)
	}
	if removeErr := os.RemoveAll(dir); removeErr != nil {
		t.Fatalf("失败路径不应遗留数据库句柄: %v", removeErr)
	}
}

// TestOpenMissingKeyWithoutCreateFails 验证缺主密钥且不允许创建时 fail-closed。
func TestOpenMissingKeyWithoutCreateFails(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig()
	_, err := Open(context.Background(), Options{
		Config: &cfg, DatabasePath: filepath.Join(dir, "login.db"),
		MasterKeyFile: filepath.Join(dir, "master.key"), CreateMasterKey: false,
		Migrate: true, OperatorID: "embedded-test",
	})
	if err == nil {
		t.Fatal("缺主密钥且不允许创建时必须 fail-closed")
	}
	if removeErr := os.RemoveAll(dir); removeErr != nil {
		t.Fatalf("失败路径不应遗留文件句柄: %v", removeErr)
	}
}

// TestOpenRequiresOperatorID 验证没有本地受信操作者时拒绝构造。
func TestOpenRequiresOperatorID(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig()
	_, err := Open(context.Background(), Options{
		Config: &cfg, DatabasePath: filepath.Join(dir, "login.db"),
		MasterKeyFile: filepath.Join(dir, "master.key"), CreateMasterKey: true,
		Migrate: true,
	})
	if err == nil {
		t.Fatal("缺少 OperatorID 必须拒绝")
	}
}

// TestStartCancelFailsClosedAndCloseIsIdempotent 验证启动前取消：实例 fail-closed、
// 之后只能 Close，重复 Close 安全。
func TestStartCancelFailsClosedAndCloseIsIdempotent(t *testing.T) {
	runtime := openTestRuntime(t, Options{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runtime.Start(ctx); err == nil {
		t.Fatal("启动已取消时必须失败")
	}
	if runtime.State() != login.StateClosed {
		t.Fatalf("启动取消后状态必须为 closed，实际 %q", runtime.State())
	}
	if err := runtime.Start(context.Background()); !errors.Is(err, login.ErrClosed) {
		t.Fatalf("启动失败后再次 Start 应返回 ErrClosed，实际 %v", err)
	}
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatalf("取消后 Close 失败: %v", err)
	}
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatalf("重复 Close 应安全: %v", err)
	}
}

// fakeDatabase 模拟宿主拥有的数据库连接：运行时只 Ping，绝不关闭。
type fakeDatabase struct {
	mu     sync.Mutex
	pings  int
	closed bool
}

func (d *fakeDatabase) Ping(context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pings++
	return nil
}

func (d *fakeDatabase) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	return nil
}

// captureNotifier 记录生命周期事件；运行时不关闭它。
type captureNotifier struct {
	mu     sync.Mutex
	events []login.LifecycleEvent
}

func (n *captureNotifier) Notify(_ context.Context, event login.LifecycleEvent) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.events = append(n.events, event)
	return nil
}

func (n *captureNotifier) snapshot() []login.LifecycleEvent {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]login.LifecycleEvent, len(n.events))
	copy(out, n.events)
	return out
}

// TestHostResourcesAreNotClosedByRuntime 验证宿主注入的数据库与通知器不被运行时
// 关闭，且生命周期事件可观察、Ready 真的执行数据库 Ping。
func TestHostResourcesAreNotClosedByRuntime(t *testing.T) {
	ctx := context.Background()
	database := &fakeDatabase{}
	notifier := &captureNotifier{}
	runtime := openTestRuntime(t, Options{Database: database, Notifier: notifier})
	if err := runtime.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := runtime.Ready(ctx); err != nil {
		t.Fatalf("Ready: %v", err)
	}
	database.mu.Lock()
	pings := database.pings
	database.mu.Unlock()
	if pings == 0 {
		t.Fatal("Ready 应检查宿主数据库（Ping）")
	}
	if err := runtime.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	database.mu.Lock()
	closed := database.closed
	database.mu.Unlock()
	if closed {
		t.Fatal("运行时不关闭宿主数据库")
	}
	events := notifier.snapshot()
	if len(events) != 2 || events[0].Kind != login.LifecycleStarted ||
		events[1].Kind != login.LifecycleClosed {
		t.Fatalf("生命周期通知异常: %+v", events)
	}
}

// TestOpenRejectsNonSQLiteDriver 验证共享配置规则：当前只支持 SQLite 驱动，
// 嵌入入口不会装配出一个打不开的运行时。
func TestOpenRejectsNonSQLiteDriver(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig()
	cfg.Database.Driver = login.DatabaseDriver("postgres")
	_, err := Open(context.Background(), Options{
		Config: &cfg, DatabasePath: filepath.Join(dir, "login.db"),
		MasterKeyFile: filepath.Join(dir, "master.key"), CreateMasterKey: true,
		Migrate: true, OperatorID: "embedded-test",
	})
	if err == nil {
		t.Fatal("非 SQLite 驱动必须拒绝")
	}
}
