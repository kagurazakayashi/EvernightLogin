package setupconsole

// 步骤281：本地维护身份/排他锁/无数据库维护日志定向测试。

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/maintenance"
)

// maintenanceFixture 准备临时实例目录与身份。
func maintenanceFixture(t *testing.T) (string, MaintenanceIdentity) {
	t.Helper()
	dir := t.TempDir()
	identity, err := LocalMaintenanceIdentity(dir)
	if err != nil {
		t.Fatalf("推导本地维护身份: %v", err)
	}
	return dir, identity
}

// TestMaintenanceLockExclusionAndRelease 覆盖双控制台互斥与释放后可重入。
func TestMaintenanceLockExclusionAndRelease(t *testing.T) {
	ctx := context.Background()
	dir, identity := maintenanceFixture(t)
	first, err := AcquireMaintenanceLock(ctx, LockRequest{InstanceDir: dir,
		Operator: identity, Purpose: "配置编辑"})
	if err != nil {
		t.Fatalf("第一个控制台取锁: %v", err)
	}
	if _, err := AcquireMaintenanceLock(ctx, LockRequest{InstanceDir: dir,
		Operator: identity, Purpose: "双开竞争"}); !errors.Is(err, ErrMaintenanceLocked) {
		t.Fatalf("第二个控制台应被拒绝: %v", err)
	}
	if err := first.Release(); err != nil {
		t.Fatalf("释放锁: %v", err)
	}
	if err := first.Release(); err != nil {
		t.Fatalf("重复释放应幂等: %v", err)
	}
	second, err := AcquireMaintenanceLock(ctx, LockRequest{InstanceDir: dir,
		Operator: identity, Purpose: "释放后重入"})
	if err != nil {
		t.Fatalf("释放后应可重新取锁: %v", err)
	}
	_ = second.Release()
}

// TestMaintenanceServiceRunningRejected 覆盖主服务占用数据库锁时拒绝独占维护。
func TestMaintenanceServiceRunningRejected(t *testing.T) {
	ctx := context.Background()
	dir, identity := maintenanceFixture(t)
	databasePath := filepath.Join(dir, "login.db")
	// 模拟主服务持有 <db>.server.lock（与 serverapp 单实例锁同一协议）。
	releaseService, err := maintenance.AcquireFileLock(databasePath + serverInstanceLockSuffix)
	if err != nil {
		t.Fatalf("模拟服务锁: %v", err)
	}
	defer releaseService()
	_, err = AcquireMaintenanceLock(ctx, LockRequest{InstanceDir: dir,
		DatabasePath: databasePath, Operator: identity, Purpose: "服务占用测试"})
	if !errors.Is(err, ErrServiceRunning) {
		t.Fatalf("服务运行中应拒绝独占维护: %v", err)
	}
	// 拒绝后控制台互斥锁也必须被释放（可再次获取）。
	releaseService()
	lock, err := AcquireMaintenanceLock(ctx, LockRequest{InstanceDir: dir,
		DatabasePath: databasePath, Operator: identity, Purpose: "服务停止后维护"})
	if err != nil {
		t.Fatalf("服务锁释放后应可取维护锁: %v", err)
	}
	_ = lock.Release()
}

// TestMaintenanceIdentityForgeryAndWrongInstance 覆盖伪造身份/错误实例拒绝。
func TestMaintenanceIdentityForgeryAndWrongInstance(t *testing.T) {
	ctx := context.Background()
	dir, identity := maintenanceFixture(t)
	forged := identity
	forged.Kind = "http_request"
	if _, err := AcquireMaintenanceLock(ctx, LockRequest{InstanceDir: dir,
		Operator: forged, Purpose: "伪造类别"}); !errors.Is(err, ErrIdentityInvalid) {
		t.Fatalf("伪造身份类别应拒绝: %v", err)
	}
	forged = identity
	forged.OSUser = "administrator-forged"
	if _, err := AcquireMaintenanceLock(ctx, LockRequest{InstanceDir: dir,
		Operator: forged, Purpose: "伪造用户"}); !errors.Is(err, ErrIdentityInvalid) {
		t.Fatalf("伪造 OS 用户应拒绝: %v", err)
	}
	otherDir := t.TempDir()
	if _, err := AcquireMaintenanceLock(ctx, LockRequest{InstanceDir: otherDir,
		Operator: identity, Purpose: "错误实例"}); !errors.Is(err, ErrInstanceMismatch) {
		t.Fatalf("错误实例应拒绝: %v", err)
	}
	// 本地身份只能由 OS 事实推导：Getenv 伪造不参与。
	t.Setenv("SETUP_LOCAL_MAINTENANCE", "true")
	if _, err := AcquireMaintenanceLock(ctx, LockRequest{InstanceDir: dir,
		Operator: MaintenanceIdentity{Kind: "local_os", OSUser: identity.OSUser,
			Machine: identity.Machine, InstanceID: "forged"}, Purpose: "伪造指纹"}); !errors.Is(err, ErrInstanceMismatch) {
		t.Fatalf("伪造实例指纹应拒绝: %v", err)
	}
}

// TestMaintenanceLogRecordAndValidation 覆盖无数据库维护日志追加与字段校验。
func TestMaintenanceLogRecordAndValidation(t *testing.T) {
	dir, identity := maintenanceFixture(t)
	logStore, err := OpenMaintenanceLog(dir)
	if err != nil {
		t.Fatalf("打开维护日志: %v", err)
	}
	logMeta, _ := logStore.(*maintenanceLog)
	now := time.Now().UTC()
	operationID := "op_274_ws1_0001"
	receipt, err := logStore.Record(context.Background(), MaintLogEntry{
		OperationID: operationID, Identity: identity, InstanceDir: dir,
		Action: "config.edit", Target: "field:logging.level", Result: "success",
		StartedAt: now, FinishedAt: now, RequestID: "req_test_0001"})
	if err != nil {
		t.Fatalf("写入维护日志: %v", err)
	}
	if receipt != operationID {
		t.Fatalf("回执 = %q，期望 %q", receipt, operationID)
	}
	content, err := os.ReadFile(logMeta.Path())
	if err != nil {
		t.Fatalf("读取维护日志: %v", err)
	}
	var decoded map[string]any
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &decoded); err != nil {
		t.Fatalf("维护日志不是合法 JSON 行: %v", err)
	}
	for field, want := range map[string]string{"operation_id": operationID,
		"os_user": identity.OSUser, "instance_id": identity.InstanceID,
		"action": "config.edit", "result": "success"} {
		if value, _ := decoded[field].(string); value != want {
			t.Fatalf("维护日志字段 %s = %q，期望 %q", field, value, want)
		}
	}
	// 校验拒绝：控制字符/非法结果/秘密关键词/错误实例指纹。
	if _, err := logStore.Record(context.Background(), MaintLogEntry{
		OperationID: "op_x", Identity: identity, InstanceDir: dir, Action: "a\x1b",
		Target: "t", Result: "success"}); err == nil {
		t.Fatal("控制字符动作应拒绝")
	}
	if _, err := logStore.Record(context.Background(), MaintLogEntry{
		OperationID: "op_x", Identity: identity, InstanceDir: dir, Action: "a",
		Target: "t", Result: "unknown"}); !errors.Is(err, ErrIdentityInvalid) {
		t.Fatalf("非法结果应拒绝: %v", err)
	}
	if _, err := logStore.Record(context.Background(), MaintLogEntry{
		OperationID: "op_x", Identity: identity, InstanceDir: dir, Action: "a",
		Target: "password=hunter2", Result: "success"}); !errors.Is(err, ErrIdentityInvalid) {
		t.Fatalf("疑似秘密目标应拒绝: %v", err)
	}
	wrongIdentity := identity
	wrongIdentity.InstanceID = "inst_forged"
	if _, err := logStore.Record(context.Background(), MaintLogEntry{
		OperationID: "op_y", Identity: wrongIdentity, InstanceDir: dir, Action: "a",
		Target: "t", Result: "success"}); !errors.Is(err, ErrInstanceMismatch) {
		t.Fatalf("错误实例指纹应拒绝: %v", err)
	}
}

// TestMaintenanceLogUnavailable 覆盖实例目录无效时 fail-closed。
func TestMaintenanceLogUnavailable(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatalf("写入文件: %v", err)
	}
	if _, err := OpenMaintenanceLog(filePath); err == nil {
		t.Fatal("文件冒充实例目录应拒绝")
	}
}
