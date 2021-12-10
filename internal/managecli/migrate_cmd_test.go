package managecli

// 本文件覆盖 `loginctl migrate`：只读状态、确认与停服前置、真实迁移执行、
// 幂等重复执行与降级拒绝。

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

// TestMigrateStatusCurrent 验证已迁移数据库返回 current 且退出码 0。
func TestMigrateStatusCurrent(t *testing.T) {
	databasePath, _ := newTestDatabase(t)
	configPath := writeConfigFile(t, t.TempDir(), databasePath)
	stdout, stderr, exit := runCLI(t, "migrate", "status", "--config", configPath, "--json")
	if exit != ExitOK {
		t.Fatalf("migrate status 退出码 = %d，stderr=%s", exit, stderr)
	}
	envelope := decodeEnvelope(t, stdout)
	if envelope["ok"] != true {
		t.Fatalf("状态输出 = %v", envelope)
	}
	data := envelope["data"].(map[string]any)
	if data["current"] != true {
		t.Fatalf("迁移状态 = %v", data)
	}
	if data["applied_count"].(float64) == 0 {
		t.Fatal("已应用迁移数不应为 0")
	}
}

// TestMigrateStatusPending 验证空数据库返回待应用且退出码 1。
func TestMigrateStatusPending(t *testing.T) {
	// 只创建空 SQLite 文件，不执行迁移。
	path := filepath.Join(t.TempDir(), "empty.db")
	store, err := storagesqlite.Open(context.Background(),
		storagesqlite.DefaultOptions(path))
	if err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	configPath := writeConfigFile(t, t.TempDir(), path)
	stdout, _, exit := runCLI(t, "migrate", "status", "--config", configPath, "--json")
	if exit != ExitError {
		t.Fatalf("待应用状态退出码 = %d，期望 %d", exit, ExitError)
	}
	envelope := decodeEnvelope(t, stdout)
	if envelope["ok"] != false {
		t.Fatalf("待应用状态外壳 = %v", envelope)
	}
	if code := envelopeErrorCode(t, envelope); code != "MIGRATION_NOT_CURRENT" {
		t.Fatalf("错误码 = %s", code)
	}
}

// TestMigrateApplyRequiresConfirmationAndStoppedService 验证前置参数缺失时用法错误。
func TestMigrateApplyRequiresConfirmationAndStoppedService(t *testing.T) {
	databasePath, _ := newTestDatabase(t)
	configPath := writeConfigFile(t, t.TempDir(), databasePath)
	_, _, exit := runCLI(t, "migrate", "apply", "--config", configPath)
	if exit != ExitUsage {
		t.Fatalf("缺少确认退出码 = %d，期望 %d", exit, ExitUsage)
	}
	_, _, exit = runCLI(t, "migrate", "apply", "--config", configPath, "--confirm", "MIGRATE")
	if exit != ExitUsage {
		t.Fatalf("缺少停服确认退出码 = %d，期望 %d", exit, ExitUsage)
	}
}

// TestMigrateApplyAppliesPendingMigrations 验证在空库上真实执行迁移并可重复执行。
func TestMigrateApplyAppliesPendingMigrations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.db")
	store, err := storagesqlite.Open(context.Background(),
		storagesqlite.DefaultOptions(path))
	if err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	configPath := writeConfigFile(t, t.TempDir(), path)
	stdout, stderr, exit := runCLI(t, "migrate", "apply", "--config", configPath,
		"--confirm", "MIGRATE", "--service-stopped", "--json")
	if exit != ExitOK {
		t.Fatalf("迁移执行退出码 = %d，stderr=%s", exit, stderr)
	}
	data := decodeEnvelope(t, stdout)["data"].(map[string]any)
	applied, _ := data["applied"].([]any)
	if len(applied) == 0 {
		t.Fatalf("应应用迁移: %v", data)
	}
	// 再次执行应为幂等（up_to_date=true）。
	stdout, _, exit = runCLI(t, "migrate", "apply", "--config", configPath,
		"--confirm", "MIGRATE", "--service-stopped", "--json")
	if exit != ExitOK {
		t.Fatalf("重复执行退出码 = %d", exit)
	}
	data = decodeEnvelope(t, stdout)["data"].(map[string]any)
	if data["up_to_date"] != true {
		t.Fatalf("重复执行应为最新: %v", data)
	}
}

// TestMigrateApplyCreatesMissingDatabase 验证迁移入口允许在目标文件不存在时创建
// 数据库（初始化场景），而只读命令不会创建文件。
func TestMigrateApplyCreatesMissingDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "brand-new.db")
	configPath := writeConfigFile(t, t.TempDir(), path)
	if _, _, exit := runCLI(t, "migrate", "status", "--config", configPath); exit != ExitError {
		t.Fatalf("缺失数据库 status 退出码 = %d，期望 %d", exit, ExitError)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("migrate status 创建了数据库文件")
	}
	stdout, stderr, exit := runCLI(t, "migrate", "apply", "--config", configPath,
		"--confirm", "MIGRATE", "--service-stopped", "--json")
	if exit != ExitOK {
		t.Fatalf("初始化迁移退出码 = %d，stderr=%s", exit, stderr)
	}
	if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("迁移未创建数据库文件: %v", err)
	}
	if len(decodeEnvelope(t, stdout)["data"].(map[string]any)["applied"].([]any)) == 0 {
		t.Fatal("初始化迁移未应用任何迁移")
	}
}

// TestMigrateApplyRefusesDowngrade 验证数据库含未知已应用版本时拒绝执行。
func TestMigrateApplyRefusesDowngrade(t *testing.T) {
	databasePath, store := newTestDatabase(t)
	if _, err := store.DB().ExecContext(context.Background(),
		`INSERT INTO schema_history(version,description,applied_at_ms,source_sha256)
VALUES('9999','future',0,'deadbeef')`); err != nil {
		t.Fatalf("写入未来迁移记录: %v", err)
	}
	configPath := writeConfigFile(t, t.TempDir(), databasePath)
	stdout, _, exit := runCLI(t, "migrate", "apply", "--config", configPath,
		"--confirm", "MIGRATE", "--service-stopped", "--json")
	if exit != ExitConflict {
		t.Fatalf("降级拒绝退出码 = %d，期望 %d", exit, ExitConflict)
	}
	if code := envelopeErrorCode(t, decodeEnvelope(t, stdout)); code != "MIGRATION_DOWNGRADE_REFUSED" {
		t.Fatalf("错误码 = %s", code)
	}
}

// TestMigrateStatusDoesNotTouchDatabase 验证 status 不产生 wal/shm 文件变化。
func TestMigrateStatusReadOnlyFiles(t *testing.T) {
	databasePath, _ := newTestDatabase(t)
	directory := filepath.Dir(databasePath)
	before, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	configPath := writeConfigFile(t, t.TempDir(), databasePath)
	if _, _, exit := runCLI(t, "migrate", "status", "--config", configPath); exit != ExitOK {
		t.Fatalf("migrate status 退出码 = %d", exit)
	}
	after, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("只读状态检查产生了新文件：before=%d after=%d", len(before), len(after))
	}
}
