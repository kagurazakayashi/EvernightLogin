// Command embedded-runtime 是步骤 138/A01 与步骤 180 的真独立模块验收示例。
//
// 它使用自己的 go.mod（replace 指向仓库根），只导入公开包
// github.com/kagurazakayashi/EvernightLogin 与 .../app；Go 的 internal 规则禁止
// 模块外导入 internal，因此能编译运行即证明公开装配 API 未泄漏 internal 类型。
//
// 覆盖场景：
//   - Open 只构造运行时（StateNew），不启动后台任务；未 Start 时 Ready 报未运行；
//   - 真实临时 SQLite + 临时主密钥完成 root 初始化、创建用户、登录、权限检查、
//     撤销会话；
//   - 显式 Start 启动允许的后台任务；重复 Start 返回 ErrAlreadyStarted；
//   - Close 幂等；宿主注入的数据库/通知器不被运行时关闭；
//   - 启动前取消 fail-closed（实例进入 closed），之后只能 Close；
//   - 迁移未完成时 Open fail-closed，且失败路径不遗留数据库句柄。
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/app"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "embedded-runtime 验收失败:", err)
		os.Exit(1)
	}
	fmt.Println("embedded-runtime 验收通过：公开 app 包完成构造/显式启动/取消/重复关闭/宿主资源所有权/失败清理")
}

func run() error {
	dir, err := os.MkdirTemp("", "evernightlogin-embedded-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	cfg := login.Default()
	cfg.Registration.Enabled = true
	cfg.Registration.RequireReview = false
	cfg.Registration.RequireEmailVerification = false
	ctx := context.Background()
	hostDatabase := &fakeDatabase{}
	notifier := &captureNotifier{}
	runtime, err := app.Open(ctx, app.Options{
		Config: &cfg, DatabasePath: filepath.Join(dir, "login.db"),
		MasterKeyFile: filepath.Join(dir, "master.key"), CreateMasterKey: true,
		Migrate: true, OperatorID: "embedded-example", Now: time.Now,
		Database: hostDatabase, Notifier: notifier,
	})
	if err != nil {
		return fmt.Errorf("Open: %w", err)
	}
	defer func() { _ = runtime.Close(context.Background()) }()
	if runtime.State() != login.StateNew {
		return fmt.Errorf("Open 后状态必须为 new（未启动），实际 %q", runtime.State())
	}
	if err := runtime.Ready(ctx); !errors.Is(err, login.ErrNotRunning) {
		return fmt.Errorf("未 Start 时 Ready 应返回 ErrNotRunning，实际 %v", err)
	}
	if runtime.Instance() == nil || runtime.Instance().State() != login.StateNew {
		return fmt.Errorf("Open 后实例必须为 StateNew（未启动）")
	}
	root, err := runtime.Bootstrap().EnsureRoot(ctx, app.RootRequest{
		DisplayName: "Root", Password: "V7!qZ2#Lm9@Tp4$x", RequestID: login.NewRequestID(),
	})
	if err != nil {
		return fmt.Errorf("EnsureRoot: %w", err)
	}
	if root.UserID == "" {
		return fmt.Errorf("EnsureRoot 未返回 root 用户")
	}
	user, err := runtime.Users().Create(ctx, app.CreateUserRequest{
		Username: "alice", Password: "K8$wR3!nB6@yF1#v", Nickname: "Alice",
		RequestID: login.NewRequestID(),
	})
	if err != nil {
		return fmt.Errorf("Users.Create: %w", err)
	}
	loginResult, err := runtime.Auth().Login(ctx, app.LoginRequest{
		Username: "alice", Password: "K8$wR3!nB6@yF1#v", ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID(),
	})
	if err != nil {
		return fmt.Errorf("Auth.Login: %w", err)
	}
	if len(loginResult.SessionSecret) == 0 {
		return fmt.Errorf("Auth.Login 未返回会话秘密")
	}
	decision, err := runtime.Access().Check(ctx, app.AccessRequest{
		UserID: user.ID, Permission: "authorization.check", Mode: "all",
	})
	if err != nil {
		return fmt.Errorf("Access.Check: %w", err)
	}
	if decision.Allowed || decision.Code == "" {
		return fmt.Errorf("未授权用户应被拒绝并有稳定码: %+v", decision)
	}
	if err := runtime.Sessions().Revoke(ctx, loginResult.SessionSecret); err != nil {
		return fmt.Errorf("Sessions.Revoke: %w", err)
	}
	// 显式启动允许的后台任务；重复启动返回 ErrAlreadyStarted。
	if err := runtime.Start(ctx); err != nil {
		return fmt.Errorf("Start: %w", err)
	}
	if runtime.State() != login.StateRunning {
		return fmt.Errorf("Start 后状态应为 running，实际 %q", runtime.State())
	}
	if err := runtime.Start(ctx); !errors.Is(err, login.ErrAlreadyStarted) {
		return fmt.Errorf("重复 Start 应返回 ErrAlreadyStarted，实际 %v", err)
	}
	if err := runtime.Ready(ctx); err != nil {
		return fmt.Errorf("Ready: %w", err)
	}
	if err := runtime.Close(ctx); err != nil {
		return fmt.Errorf("Close: %w", err)
	}
	if err := runtime.Close(ctx); err != nil {
		return fmt.Errorf("重复 Close 应安全: %v", err)
	}
	// 宿主资源所有权：运行时绝不关闭宿主注入的数据库/通知器。
	if hostDatabase.isClosed() {
		return fmt.Errorf("运行时不关闭宿主数据库")
	}
	if events := notifier.snapshot(); len(events) != 2 ||
		events[0].Kind != login.LifecycleStarted || events[1].Kind != login.LifecycleClosed {
		return fmt.Errorf("生命周期通知异常: %+v", events)
	}

	// 启动前取消：fail-closed 且不遗留资源；之后只能 Close。
	cancelled, err := app.Open(ctx, app.Options{
		Config: &cfg, DatabasePath: filepath.Join(dir, "cancelled.db"),
		MasterKeyFile: filepath.Join(dir, "master.key"), CreateMasterKey: false,
		Migrate: true, OperatorID: "embedded-example", Now: time.Now,
	})
	if err != nil {
		return fmt.Errorf("Open（取消场景）: %w", err)
	}
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := cancelled.Start(cancelledCtx); err == nil {
		return fmt.Errorf("启动已取消时必须失败")
	}
	if cancelled.State() != login.StateClosed {
		return fmt.Errorf("启动取消后状态必须为 closed，实际 %q", cancelled.State())
	}
	if err := cancelled.Start(context.Background()); !errors.Is(err, login.ErrClosed) {
		return fmt.Errorf("启动失败后再次 Start 应返回 ErrClosed，实际 %v", err)
	}
	if err := cancelled.Close(context.Background()); err != nil {
		return fmt.Errorf("取消场景 Close: %v", err)
	}
	if err := cancelled.Close(context.Background()); err != nil {
		return fmt.Errorf("取消场景重复 Close 应安全: %v", err)
	}

	// 迁移未完成：fail-closed，且失败路径不遗留数据库句柄（临时目录可整体删除）。
	failDir, err := os.MkdirTemp("", "evernightlogin-embedded-fail-")
	if err != nil {
		return err
	}
	_, openErr := app.Open(ctx, app.Options{
		Config: &cfg, DatabasePath: filepath.Join(failDir, "login.db"),
		MasterKeyFile: filepath.Join(failDir, "master.key"), CreateMasterKey: true,
		Migrate: false, OperatorID: "embedded-example", Now: time.Now,
	})
	if openErr == nil {
		return fmt.Errorf("迁移未完成时 Open 必须 fail-closed")
	}
	if removeErr := os.RemoveAll(failDir); removeErr != nil {
		return fmt.Errorf("失败路径不应遗留数据库句柄: %v", removeErr)
	}
	return nil
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

func (d *fakeDatabase) isClosed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.closed
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
