package serverapp

// 共享基础装配（OpenBase）的内部测试：真实 SQLite + 真实领域服务/敏感闸门/任务
// 运行时/管理域，但不监听端口、不启动后台任务、不真实外发。

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
)

// baseTestConfig 返回带临时数据库路径的默认配置。
func baseTestConfig(t *testing.T) login.Config {
	t.Helper()
	cfg := login.Default()
	cfg.Database.Path = filepath.Join(testutil.TempDir(t), "login.db")
	return cfg
}

// baseTestLogger 返回丢弃输出的测试日志器。
func baseTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestOpenBaseBuildsSharedAssemblyWithoutStarting 验证 OpenBase 构造出两种运行
// 方式共用的领域服务、敏感闸门、任务运行时与管理域，且构造阶段不启动任务。
func TestOpenBaseBuildsSharedAssemblyWithoutStarting(t *testing.T) {
	ctx := context.Background()
	base, err := OpenBase(ctx, BaseOptions{
		Config: baseTestConfig(t), Keyring: newTestKeyring(t), Migrate: true,
		Logger: baseTestLogger(), Now: func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatalf("OpenBase: %v", err)
	}
	t.Cleanup(func() { _ = base.Close(context.Background()) })
	if base.Store == nil || base.Audit == nil || base.Mail == nil {
		t.Fatalf("基础资源未装配: %+v", base)
	}
	if base.Services == nil || base.Gate == nil || base.Tasks == nil || base.Managed == nil {
		t.Fatalf("领域装配未完成: services=%v gate=%v tasks=%v managed=%v",
			base.Services != nil, base.Gate != nil, base.Tasks != nil, base.Managed != nil)
	}
	if base.Security == nil || base.Security.TOTP == nil || base.Security.MFA == nil ||
		base.Security.Recovery == nil || base.Security.StrongFactors == nil {
		t.Fatalf("认证/安全域未装配（共享运行时必须与独立服务一致）: %+v", base.Security)
	}
	if !base.Uninitialized {
		t.Fatal("全新临时数据库应报告未初始化")
	}
	if base.Services.SessionAuthorizer == nil {
		t.Fatal("管理强制下线授权器未注入（应由共享装配统一完成）")
	}
	// 构造阶段不启动任务：显式 Start 才能成功绑定执行器与调度器。
	if err := base.Tasks.Start(ctx); err != nil {
		t.Fatalf("显式启动任务运行时失败: %v", err)
	}
	if err := base.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := base.Close(ctx); err != nil {
		t.Fatalf("重复 Close 应安全: %v", err)
	}
	if err := base.Store.Ping(ctx); err == nil {
		t.Fatal("Close 后数据库应已关闭")
	}
}

// TestOpenBaseMaintenanceOnlySkipsDomainServices 验证维护模式只装配基础资源。
func TestOpenBaseMaintenanceOnlySkipsDomainServices(t *testing.T) {
	ctx := context.Background()
	base, err := OpenBase(ctx, BaseOptions{
		Config: baseTestConfig(t), Keyring: newTestKeyring(t), Migrate: true,
		Logger: baseTestLogger(), Now: func() time.Time { return testNow },
		MaintenanceOnly: true,
	})
	if err != nil {
		t.Fatalf("OpenBase: %v", err)
	}
	if base.Services != nil || base.Gate != nil || base.Tasks != nil || base.Managed != nil {
		t.Fatalf("维护模式不应装配领域服务: %+v", base)
	}
	if base.Store == nil || base.Audit == nil {
		t.Fatalf("维护模式仍需要存储与审计: %+v", base)
	}
	if err := base.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestOpenBaseMigrationPendingFailsAndReleases 验证迁移未完成时 fail-closed，且
// 失败路径释放数据库句柄（Windows 下仍能删除临时目录）。
func TestOpenBaseMigrationPendingFailsAndReleases(t *testing.T) {
	dir := testutil.TempDir(t)
	cfg := login.Default()
	cfg.Database.Path = filepath.Join(dir, "login.db")
	_, err := OpenBase(context.Background(), BaseOptions{
		Config: cfg, Keyring: newTestKeyring(t), Migrate: false,
		Logger: baseTestLogger(), Now: func() time.Time { return testNow },
	})
	if err == nil {
		t.Fatal("未迁移数据库必须 fail-closed")
	}
	if !errors.Is(err, ErrMigrationPending) {
		t.Fatalf("应返回 ErrMigrationPending，实际 %v", err)
	}
	if removeErr := os.RemoveAll(dir); removeErr != nil {
		t.Fatalf("失败路径不应遗留数据库句柄: %v", removeErr)
	}
}

// TestOpenBaseRequireInitializedFailsClosed 验证独立服务的初始化策略：未初始化库
// 构造失败并返回 ErrUninitialized（嵌入模式默认不启用该检查）。
func TestOpenBaseRequireInitializedFailsClosed(t *testing.T) {
	dir := testutil.TempDir(t)
	cfg := login.Default()
	cfg.Database.Path = filepath.Join(dir, "login.db")
	_, err := OpenBase(context.Background(), BaseOptions{
		Config: cfg, Keyring: newTestKeyring(t), Migrate: true,
		Logger: baseTestLogger(), Now: func() time.Time { return testNow },
		RequireInitialized: true,
	})
	if !errors.Is(err, ErrUninitialized) {
		t.Fatalf("未初始化库应返回 ErrUninitialized，实际 %v", err)
	}
	if removeErr := os.RemoveAll(dir); removeErr != nil {
		t.Fatalf("失败路径不应遗留数据库句柄: %v", removeErr)
	}
}

// TestOpenBaseAssemblyFailureRollsBack 验证领域装配失败时已打开的数据库被回滚关闭。
func TestOpenBaseAssemblyFailureRollsBack(t *testing.T) {
	dir := testutil.TempDir(t)
	cfg := login.Default()
	cfg.Database.Path = filepath.Join(dir, "login.db")
	cfg.Registration.Enabled = true
	cfg.Registration.RequireEmailVerification = true // 邮件未启用时该组合必须拒绝
	_, err := OpenBase(context.Background(), BaseOptions{
		Config: cfg, Keyring: newTestKeyring(t), Migrate: true,
		Logger: baseTestLogger(), Now: func() time.Time { return testNow },
	})
	if err == nil {
		t.Fatal("要求邮箱验证但邮件未启用时必须构造失败")
	}
	if removeErr := os.RemoveAll(dir); removeErr != nil {
		t.Fatalf("构造失败后不应遗留数据库句柄: %v", removeErr)
	}
}
