package main

// main 入口装配的纯辅助函数测试（不打开真实实例/数据库）。

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/setupconsole"
)

// TestLocalOperatorIDASCIIStable 覆盖操作者标识清理/截断与稳定性。
func TestLocalOperatorIDASCIIStable(t *testing.T) {
	identity := setupconsole.MaintenanceIdentity{
		Kind: "local_os", OSUser: "CHENXIAOCHI\\yashi", Machine: "机器名",
		InstanceID: "inst_test",
	}
	operatorID := localOperatorID(identity)
	for _, character := range operatorID {
		if character < 0x20 || character > 0x7e {
			t.Fatalf("操作者标识包含非 ASCII 字符: %q", operatorID)
		}
	}
	if len(operatorID) > 128 {
		t.Fatalf("操作者标识过长: %d", len(operatorID))
	}
	if operatorID != localOperatorID(identity) {
		t.Fatal("相同身份应产生稳定标识")
	}
	empty := localOperatorID(setupconsole.MaintenanceIdentity{})
	if empty != "local-os:unknown@unknown" {
		t.Fatalf("空身份标识 = %q", empty)
	}
}

// TestResolveDatabasePath 覆盖相对/绝对/空数据库路径。
func TestResolveDatabasePath(t *testing.T) {
	dir := t.TempDir()
	if got := resolveDatabasePath("data/login.db", dir); got != filepath.Join(dir, "data/login.db") {
		t.Fatalf("相对路径解析 = %q", got)
	}
	absolute := filepath.Join(dir, "abs.db")
	if got := resolveDatabasePath(absolute, "ignored"); got != absolute {
		t.Fatalf("绝对路径被改写: %q", got)
	}
	if got := resolveDatabasePath("  ", dir); got != "" {
		t.Fatalf("空路径应返回空，实际 %q", got)
	}
}

// TestInstanceDirectory 覆盖配置目录解析与缺失配置。
func TestInstanceDirectory(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "login.yaml")
	if err := os.WriteFile(configPath, []byte("x"), 0o600); err != nil {
		t.Fatalf("写入配置占位: %v", err)
	}
	got, err := instanceDirectory(configPath)
	if err != nil || got != dir {
		t.Fatalf("实例目录 = %q err=%v", got, err)
	}
	if _, err := instanceDirectory("  "); err == nil {
		t.Fatal("未选择配置路径应 fail-closed")
	}
}

// TestMaintenanceWriteGuardLocksOnlyOnWrite 覆盖写门闸即时取锁/释放与互斥。
func TestMaintenanceWriteGuardLocksOnlyOnWrite(t *testing.T) {
	dir := t.TempDir()
	identity, err := setupconsole.LocalMaintenanceIdentity(dir)
	if err != nil {
		t.Fatalf("推导本地身份: %v", err)
	}
	databasePath := filepath.Join(dir, "login.db")
	guard, err := maintenanceWriteGuard(dir, databasePath, identity)
	if err != nil {
		t.Fatalf("构造写门闸: %v", err)
	}
	// 未写入时不持锁：另一控制台可取得同一实例维护锁（只读查看不阻塞）。
	readOnlyLock, err := setupconsole.AcquireMaintenanceLock(context.Background(),
		setupconsole.LockRequest{InstanceDir: dir, DatabasePath: databasePath,
			Operator: identity, Purpose: "read-only view"})
	if err != nil {
		t.Fatalf("只读窗口不应持锁: %v", err)
	}
	if err := readOnlyLock.Release(); err != nil {
		t.Fatalf("释放只读锁: %v", err)
	}
	// 写事务进入时取锁；持锁期间第二次写入必须失败；释放后可重入。
	releaseWrite, err := guard(context.Background())
	if err != nil {
		t.Fatalf("写事务取锁: %v", err)
	}
	if _, err := guard(context.Background()); err == nil {
		t.Fatal("持锁期间第二个写门闸必须失败")
	}
	releaseWrite()
	releaseWrite() // 幂等
	releaseAgain, err := guard(context.Background())
	if err != nil {
		t.Fatalf("写释放后应可再次取锁: %v", err)
	}
	releaseAgain()
}

// TestMaintenanceWriteGuardRequiresInstance 覆盖缺少实例目录 fail-closed。
func TestMaintenanceWriteGuardRequiresInstance(t *testing.T) {
	if _, err := maintenanceWriteGuard("  ", "", setupconsole.MaintenanceIdentity{}); err == nil {
		t.Fatal("缺少实例目录应失败")
	}
}
