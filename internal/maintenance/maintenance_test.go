package maintenance_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/maintenance"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
)

// newController 在隔离临时目录中构造控制器：数据库与状态目录分开，模拟“库外状态”。
func newController(t *testing.T) *maintenance.Controller {
	t.Helper()
	root := testutil.TempDir(t)
	databaseDir := filepath.Join(root, "data")
	if err := os.MkdirAll(databaseDir, 0o700); err != nil {
		t.Fatalf("创建测试数据库目录失败：%v", err)
	}
	controller, err := maintenance.New(maintenance.Options{
		StateDir:     filepath.Join(root, "restore-state"),
		DatabasePath: filepath.Join(databaseDir, "login.db"),
		DrainTimeout: 2 * time.Second,
		Keyring:      testKeyringProvider(t),
	})
	if err != nil {
		t.Fatalf("构造维护控制器失败：%v", err)
	}
	t.Cleanup(func() { _ = controller.Close() })
	initializeState(t, controller)
	return controller
}

// testKeyringProvider 生成测试主密钥环提供者（状态 HMAC 封装用）。
func testKeyringProvider(t *testing.T) secrets.Provider {
	t.Helper()
	ring, err := secrets.GenerateKeyring("k1", time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("生成测试密钥环失败：%v", err)
	}
	return secrets.ProviderFunc(func(context.Context) ([]byte, error) {
		return ring.Document()
	})
}

// initializeState 显式初始化控制器库外状态（测试辅助）。
func initializeState(t *testing.T, controller *maintenance.Controller) {
	t.Helper()
	if !controller.Missing() {
		return
	}
	if err := controller.Initialize(context.Background(), maintenance.InitializeRequest{
		Operator: testOperator(), Reason: "测试初始化库外恢复状态"}); err != nil {
		t.Fatalf("初始化库外恢复状态失败：%v", err)
	}
}

func testOperator() maintenance.Operator {
	return maintenance.Operator{Type: "local_admin", ID: "os:tester@host", Machine: "host"}
}

func TestInitialStateIsNormalAndPersisted(t *testing.T) {
	controller := newController(t)
	state := controller.State()
	if state.Mode != maintenance.ModeNormal {
		t.Fatalf("初始模式 = %q，期望 normal", state.Mode)
	}
	if state.Generation != 0 || state.Pending != nil {
		t.Fatalf("初始代际/pending = %d/%v，期望 0/nil", state.Generation, state.Pending)
	}
	if controller.Gate().Active() {
		t.Fatal("初始门闸不应激活")
	}
	// 状态文件必须真实落盘（库外权威副本）。
	if _, err := os.Stat(controller.StatePath()); err != nil {
		t.Fatalf("状态文件未创建：%v", err)
	}
}

func TestEnterMaintenanceBlocksWritesAndExitRestores(t *testing.T) {
	root := testutil.TempDir(t)
	databaseDir := filepath.Join(root, "data")
	if err := os.MkdirAll(databaseDir, 0o700); err != nil {
		t.Fatalf("创建测试数据库目录失败：%v", err)
	}
	options := maintenance.Options{
		StateDir:     filepath.Join(root, "restore-state"),
		DatabasePath: filepath.Join(databaseDir, "login.db"),
		DrainTimeout: 2 * time.Second,
		Keyring:      testKeyringProvider(t),
	}
	controller, err := maintenance.New(options)
	if err != nil {
		t.Fatalf("构造维护控制器失败：%v", err)
	}
	t.Cleanup(func() { _ = controller.Close() })
	initializeState(t, controller)
	release, err := controller.Gate().Guard(context.Background())
	if err != nil {
		t.Fatalf("初始写入应被允许：%v", err)
	}
	release()
	if controller.Gate().Inflight() != 0 {
		t.Fatal("释放后不应有在途写入")
	}

	if err := controller.EnterMaintenance(context.Background(), maintenance.EnterRequest{
		Operator: testOperator(), Reason: "执行恢复演练",
	}); err != nil {
		t.Fatalf("进入维护状态失败：%v", err)
	}
	if controller.Mode() != maintenance.ModeMaintenance || !controller.Gate().Active() {
		t.Fatalf("进入维护后模式=%q 门闸=%v", controller.Mode(), controller.Gate().Active())
	}
	if _, err := controller.Gate().Guard(context.Background()); !errors.Is(err, maintenance.ErrMaintenanceActive) {
		t.Fatalf("维护期间新写入应被拒绝，实际错误 = %v", err)
	}

	// 新控制器从库外状态文件恢复维护状态（进程重启后不会误放行）。
	reloaded, err := maintenance.New(options)
	if err != nil {
		t.Fatalf("重载控制器失败：%v", err)
	}
	t.Cleanup(func() { _ = reloaded.Close() })
	if reloaded.Mode() != maintenance.ModeMaintenance || !reloaded.Gate().Active() {
		t.Fatalf("重载后模式=%q 门闸=%v，期望维护状态",
			reloaded.Mode(), reloaded.Gate().Active())
	}
	if _, err := reloaded.Gate().Guard(context.Background()); !errors.Is(err, maintenance.ErrMaintenanceActive) {
		t.Fatalf("重载后维护期间新写入应被拒绝，实际错误 = %v", err)
	}

	if err := controller.ExitMaintenance(context.Background(), maintenance.ExitRequest{
		Operator: testOperator(), Reason: "恢复演练结束",
	}); err != nil {
		t.Fatalf("退出维护状态失败：%v", err)
	}
	if controller.Mode() != maintenance.ModeNormal || controller.Gate().Active() {
		t.Fatal("退出维护后门闸应关闭且模式恢复 normal")
	}
	if _, err := controller.Gate().Guard(context.Background()); err != nil {
		t.Fatalf("退出维护后写入应被允许：%v", err)
	}
}

func TestDrainTimeoutKeepsMaintenance(t *testing.T) {
	controller := newControllerWithDrain(t, time.Second)
	release, err := controller.Gate().Guard(context.Background())
	if err != nil {
		t.Fatalf("初始写入应被允许：%v", err)
	}
	started := time.Now()
	err = controller.EnterMaintenance(context.Background(), maintenance.EnterRequest{
		Operator: testOperator(), Reason: "在途写入未收束",
	})
	if !errors.Is(err, maintenance.ErrDrainTimeout) {
		t.Fatalf("在途写入未释放时应返回收束超时，实际错误 = %v", err)
	}
	if elapsed := time.Since(started); elapsed < 900*time.Millisecond {
		t.Fatalf("收束等待未被真实执行，耗时 %s", elapsed)
	}
	if controller.Mode() != maintenance.ModeMaintenance {
		t.Fatal("收束超时后必须保持维护状态（不自动放行）")
	}
	release()
	if err := controller.ExitMaintenance(context.Background(), maintenance.ExitRequest{
		Operator: testOperator(), Reason: "人工确认退出",
	}); err != nil {
		t.Fatalf("释放在途写入后退出维护失败：%v", err)
	}
}

// newControllerWithDrain 构造指定收束等待上限的控制器（同 newController，参数化）。
func newControllerWithDrain(t *testing.T, timeout time.Duration) *maintenance.Controller {
	t.Helper()
	root := testutil.TempDir(t)
	databaseDir := filepath.Join(root, "data")
	if err := os.MkdirAll(databaseDir, 0o700); err != nil {
		t.Fatalf("创建测试数据库目录失败：%v", err)
	}
	controller, err := maintenance.New(maintenance.Options{
		StateDir:     filepath.Join(root, "restore-state"),
		DatabasePath: filepath.Join(databaseDir, "login.db"),
		DrainTimeout: timeout,
		Keyring:      testKeyringProvider(t),
	})
	if err != nil {
		t.Fatalf("构造维护控制器失败：%v", err)
	}
	t.Cleanup(func() { _ = controller.Close() })
	initializeState(t, controller)
	return controller
}

func TestRestoreLockIsExclusiveAcrossControllers(t *testing.T) {
	root := testutil.TempDir(t)
	databaseDir := filepath.Join(root, "data")
	if err := os.MkdirAll(databaseDir, 0o700); err != nil {
		t.Fatalf("创建测试数据库目录失败：%v", err)
	}
	options := maintenance.Options{
		StateDir:     filepath.Join(root, "restore-state"),
		DatabasePath: filepath.Join(databaseDir, "login.db"),
		Keyring:      testKeyringProvider(t),
	}
	first, err := maintenance.New(options)
	if err != nil {
		t.Fatalf("构造第一个控制器失败：%v", err)
	}
	t.Cleanup(func() { _ = first.Close() })
	initializeState(t, first)
	second, err := maintenance.New(options)
	if err != nil {
		t.Fatalf("构造第二个控制器失败：%v", err)
	}
	t.Cleanup(func() { _ = second.Close() })

	release, err := first.LockRestore(context.Background())
	if err != nil {
		t.Fatalf("第一个控制器取锁失败：%v", err)
	}
	if _, err := second.LockRestore(context.Background()); !errors.Is(err, maintenance.ErrRestoreLocked) {
		t.Fatalf("第二个控制器应被排他锁拒绝，实际错误 = %v", err)
	}
	release()
	releaseAgain, err := second.LockRestore(context.Background())
	if err != nil {
		t.Fatalf("释放后第二个控制器应能取锁：%v", err)
	}
	releaseAgain()
}

func TestBeginCompleteRestoreAdvancesGeneration(t *testing.T) {
	controller := newController(t)
	if err := controller.EnterMaintenance(context.Background(), maintenance.EnterRequest{
		Operator: testOperator(), Reason: "恢复前维护",
	}); err != nil {
		t.Fatalf("进入维护失败：%v", err)
	}
	operator := testOperator()
	token, err := controller.BeginRestore(context.Background(), maintenance.BeginRequest{
		RestoreID: "rst_20261119_0001", BackupSHA256: strings.Repeat("a", 64), Operator: operator,
	})
	if err != nil {
		t.Fatalf("登记恢复尝试失败：%v", err)
	}
	if token.Generation != 0 || token.NextGeneration != 1 {
		t.Fatalf("恢复代际 = %d/%d，期望 0/1", token.Generation, token.NextGeneration)
	}
	if state := controller.State(); state.Pending == nil || state.Pending.RestoreID != token.RestoreID {
		t.Fatal("登记后状态文件应包含 pending 恢复尝试")
	}
	// pending 未完成时退出维护必须显式 Force。
	if err := controller.ExitMaintenance(context.Background(), maintenance.ExitRequest{
		Operator: operator, Reason: "误退出",
	}); !errors.Is(err, maintenance.ErrPendingRestore) {
		t.Fatalf("存在未完成恢复时退出应被拒绝，实际错误 = %v", err)
	}
	if err := controller.CompleteRestore(context.Background(), token); err != nil {
		t.Fatalf("完成恢复登记失败：%v", err)
	}
	state := controller.State()
	if state.Generation != 1 || state.Pending != nil {
		t.Fatalf("完成后代际/pending = %d/%v，期望 1/nil", state.Generation, state.Pending)
	}
	if state.Mode != maintenance.ModeMaintenance {
		t.Fatal("完成恢复登记后仍应保持维护，等待显式退出")
	}
	if err := controller.ExitMaintenance(context.Background(), maintenance.ExitRequest{
		Operator: operator, Reason: "恢复完成退出维护",
	}); err != nil {
		t.Fatalf("退出维护失败：%v", err)
	}
}

func TestReconcileFinalizesCommittedRestore(t *testing.T) {
	controller := newController(t)
	operator := testOperator()
	if err := controller.EnterMaintenance(context.Background(), maintenance.EnterRequest{
		Operator: operator, Reason: "恢复",
	}); err != nil {
		t.Fatalf("进入维护失败：%v", err)
	}
	token, err := controller.BeginRestore(context.Background(), maintenance.BeginRequest{
		RestoreID: "rst_reconcile_1", Operator: operator,
	})
	if err != nil {
		t.Fatalf("登记恢复失败：%v", err)
	}
	result, err := controller.Reconcile(context.Background(), token.NextGeneration)
	if err != nil {
		t.Fatalf("核对失败：%v", err)
	}
	if !result.Finalized || result.Mismatch {
		t.Fatalf("数据库已提交时应收尾库外代际，实际 = %+v", result)
	}
	if controller.Generation() != token.NextGeneration {
		t.Fatalf("收尾后代际 = %d，期望 %d", controller.Generation(), token.NextGeneration)
	}
	if controller.State().Pending != nil {
		t.Fatal("收尾后 pending 应为空")
	}
}

func TestReconcileIncompleteAndMismatch(t *testing.T) {
	controller := newController(t)
	operator := testOperator()
	if err := controller.EnterMaintenance(context.Background(), maintenance.EnterRequest{
		Operator: operator, Reason: "恢复",
	}); err != nil {
		t.Fatalf("进入维护失败：%v", err)
	}
	if _, err := controller.BeginRestore(context.Background(), maintenance.BeginRequest{
		RestoreID: "rst_reconcile_2", Operator: operator,
	}); err != nil {
		t.Fatalf("登记恢复失败：%v", err)
	}
	result, err := controller.Reconcile(context.Background(), 0)
	if err != nil {
		t.Fatalf("核对失败：%v", err)
	}
	if !result.IncompletePending || result.Mismatch {
		t.Fatalf("数据库仍是恢复前状态时应为“未完成可重跑”，实际 = %+v", result)
	}

	// 模拟带外回滚：库外代际 0、数据库记录 5（没有 pending）。
	fresh := newControllerWithDrain(t, 2*time.Second)
	result, err = fresh.Reconcile(context.Background(), 5)
	if err != nil {
		t.Fatalf("核对失败：%v", err)
	}
	if !result.Mismatch {
		t.Fatalf("代际不一致必须标记 Mismatch，实际 = %+v", result)
	}
}

func TestStateFileTamperRejected(t *testing.T) {
	root := testutil.TempDir(t)
	databaseDir := filepath.Join(root, "data")
	if err := os.MkdirAll(databaseDir, 0o700); err != nil {
		t.Fatalf("创建目录失败：%v", err)
	}
	stateDir := filepath.Join(root, "restore-state")
	provider := testKeyringProvider(t)
	options := maintenance.Options{StateDir: stateDir,
		DatabasePath: filepath.Join(databaseDir, "login.db"), Keyring: provider}
	controller, err := maintenance.New(options)
	if err != nil {
		t.Fatalf("构造控制器失败：%v", err)
	}
	initializeState(t, controller)
	_ = controller.Close()
	path := filepath.Join(stateDir, maintenance.StateFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取状态文件失败：%v", err)
	}
	tampered := strings.Replace(string(data), `"generation":0`, `"generation":9`, 1)
	if tampered == string(data) {
		t.Fatal("测试未修改到状态内容")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatalf("写入篡改状态失败：%v", err)
	}
	if _, err := maintenance.New(options); !errors.Is(err, maintenance.ErrStateInvalid) {
		t.Fatalf("被篡改状态文件必须拒绝，实际错误 = %v", err)
	}
}

func TestStateDirInsideDatabaseDirRejected(t *testing.T) {
	root := testutil.TempDir(t)
	databaseDir := filepath.Join(root, "data")
	if err := os.MkdirAll(databaseDir, 0o700); err != nil {
		t.Fatalf("创建目录失败：%v", err)
	}
	if _, err := maintenance.New(maintenance.Options{
		StateDir:     filepath.Join(databaseDir, "state"),
		DatabasePath: filepath.Join(databaseDir, "login.db"),
	}); !errors.Is(err, maintenance.ErrOptionsInvalid) {
		t.Fatalf("状态目录位于数据库目录内必须拒绝，实际错误 = %v", err)
	}
	if _, err := maintenance.New(maintenance.Options{
		StateDir:     databaseDir,
		DatabasePath: filepath.Join(databaseDir, "login.db"),
	}); !errors.Is(err, maintenance.ErrOptionsInvalid) {
		t.Fatalf("状态目录等于数据库目录必须拒绝，实际错误 = %v", err)
	}
}

func TestOperatorValidation(t *testing.T) {
	if err := (maintenance.Operator{Type: "anonymous", ID: "x"}).Validate(); err == nil {
		t.Fatal("匿名操作者必须拒绝")
	}
	if err := (maintenance.Operator{Type: "user", ID: ""}).Validate(); err == nil {
		t.Fatal("空操作者标识必须拒绝")
	}
	local := maintenance.LocalOperator()
	if err := local.Validate(); err != nil {
		t.Fatalf("本地操作者标识应有效：%v", err)
	}
}

// TestStorageWriteGuardBlocksWritesDuringMaintenance 验证维护状态通过存储写入门闸
// 真实阻止新写入（事务与直接写语句），只读查询不受影响；退出维护后写入恢复。
func TestStorageWriteGuardBlocksWritesDuringMaintenance(t *testing.T) {
	root := testutil.TempDir(t)
	databaseDir := filepath.Join(root, "data")
	if err := os.MkdirAll(databaseDir, 0o700); err != nil {
		t.Fatalf("创建测试数据库目录失败：%v", err)
	}
	databasePath := filepath.Join(databaseDir, "login.db")
	controller, err := maintenance.New(maintenance.Options{
		StateDir:     filepath.Join(root, "restore-state"),
		DatabasePath: databasePath,
		DrainTimeout: 2 * time.Second,
		Keyring:      testKeyringProvider(t),
	})
	if err != nil {
		t.Fatalf("构造维护控制器失败：%v", err)
	}
	t.Cleanup(func() { _ = controller.Close() })
	initializeState(t, controller)
	store, err := storagesqlite.Open(context.Background(), storagesqlite.Options{
		Path:       databasePath,
		WAL:        true,
		WriteGuard: controller.Gate().Guard,
	})
	if err != nil {
		t.Fatalf("打开测试数据库失败：%v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	if _, err := store.ExecContext(ctx, `CREATE TABLE guard_test(id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatalf("维护前写入失败：%v", err)
	}
	if err := controller.EnterMaintenance(ctx, maintenance.EnterRequest{
		Operator: testOperator(), Reason: "写入门闸测试",
	}); err != nil {
		t.Fatalf("进入维护状态失败：%v", err)
	}
	if _, err := store.ExecContext(ctx, `INSERT INTO guard_test(id) VALUES(1)`); !errors.Is(err,
		maintenance.ErrMaintenanceActive) {
		t.Fatalf("维护期间直接写入应被门闸拒绝，实际错误 = %v", err)
	}
	transactionErr := store.Transaction(ctx, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO guard_test(id) VALUES(2)`)
		return err
	})
	if !errors.Is(transactionErr, maintenance.ErrMaintenanceActive) {
		t.Fatalf("维护期间事务写入应被门闸拒绝，实际错误 = %v", transactionErr)
	}
	var count int
	if err := store.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM guard_test`).Scan(&count); err != nil {
		t.Fatalf("维护期间只读查询应可用：%v", err)
	}
	if count != 0 {
		t.Fatalf("维护期间不应有写入落库，实际 %d 行", count)
	}
	if err := controller.ExitMaintenance(ctx, maintenance.ExitRequest{
		Operator: testOperator(), Reason: "写入门闸测试结束",
	}); err != nil {
		t.Fatalf("退出维护失败：%v", err)
	}
	if _, err := store.ExecContext(ctx, `INSERT INTO guard_test(id) VALUES(3)`); err != nil {
		t.Fatalf("退出维护后写入应被允许：%v", err)
	}
}
