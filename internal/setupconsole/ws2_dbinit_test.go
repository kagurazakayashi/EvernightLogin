package setupconsole

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/config"
	"github.com/kagurazakayashi/EvernightLogin/internal/appcore"
)

// assertNoRelativeDBArtifact 断言测试没有在包工作目录的 database/login.db 落库。
func assertNoRelativeDBArtifact(t *testing.T) {
	t.Helper()
	workingDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("读取测试工作目录失败: %v", err)
	}
	artifact := filepath.Join(workingDir, "database", "login.db")
	if _, statErr := os.Stat(artifact); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("测试不得在包目录创建相对路径数据库产物: %s", artifact)
	}
}

// setupWS2TempDB 创建临时实例并完成 SQLite 迁移，返回实例目录和已加载配置。
func setupWS2TempDB(t *testing.T) (string, config.Config) {
	t.Helper()
	instanceDir := t.TempDir()
	cfg := config.Default()
	cfg.Database.Path = filepath.Join(instanceDir, "database", "login.db")
	cfg.Database.WAL = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("默认配置校验失败: %v", err)
	}
	plan, err := BuildDBSetupPlan(filepath.Join(instanceDir, "login.yaml"), cfg,
		dbSetupInputFromConfig(cfg))
	if err != nil {
		t.Fatalf("构建设置计划失败: %v", err)
	}
	if _, err := InitializeDatabase(context.Background(), plan, DBInitOptions{
		InstanceDir: instanceDir, CreateMasterKey: true, OperatorID: "test-operator",
		Purpose: "测试初始化"}); err != nil {
		t.Fatalf("初始化数据库失败: %v", err)
	}
	return instanceDir, cfg
}

func TestBuildDBSetupPlanSQLiteDefaults(t *testing.T) {
	instanceDir := t.TempDir()
	input := DBSetupInput{Driver: config.DatabaseDriverSQLite, SQLitePath: "data/login.db"}
	plan, err := BuildDBSetupPlan(filepath.Join(instanceDir, "login.yaml"), config.Default(), input)
	if err != nil {
		t.Fatalf("构建 SQLite 计划失败: %v", err)
	}
	if !plan.RuntimeSupported {
		t.Fatal("SQLite 应标记为运行时支持")
	}
	if plan.Config.Database.BusyTimeoutMS != 5000 {
		t.Fatalf("默认忙等待应为 5000，得到 %d", plan.Config.Database.BusyTimeoutMS)
	}
	if dbAbsolutePath(plan.InstanceDir, plan.Config.Database.Path) !=
		filepath.Join(instanceDir, "data", "login.db") {
		t.Fatalf("相对路径未按实例目录解析: %s", plan.Config.Database.Path)
	}
}

func TestBuildDBSetupPlanMultiDriverIsConfigOnly(t *testing.T) {
	instanceDir := t.TempDir()
	input := DBSetupInput{Driver: config.DatabaseDriverMySQL, Host: "127.0.0.1",
		Port: 0, Username: "evernightlogin", DatabaseName: "evernightlogin",
		TLSMode: "true"}
	plan, err := BuildDBSetupPlan(filepath.Join(instanceDir, "login.yaml"), config.Default(), input)
	if err != nil {
		t.Fatalf("多驱动配置应可保存/校验: %v", err)
	}
	if plan.RuntimeSupported {
		t.Fatal("MySQL 本轮不得标记为运行时支持")
	}
	if !strings.Contains(strings.Join(plan.Notes, " "), "运行") {
		t.Fatalf("计划说明应明确运行未接入: %v", plan.Notes)
	}
	// 配置可保存，但打开入口必须 fail-closed（appcore 接线在 M1 后按 Lead 通知补）。
	if err := plan.Config.Validate(); err != nil {
		t.Fatalf("多驱动配置校验失败: %v", err)
	}
}

func TestBuildDBSetupPlanRejectsUnsafeSQLitePath(t *testing.T) {
	instanceDir := t.TempDir()
	input := DBSetupInput{Driver: config.DatabaseDriverSQLite, SQLitePath: "bad?name.db"}
	if _, err := BuildDBSetupPlan(filepath.Join(instanceDir, "login.yaml"),
		config.Default(), input); !errors.Is(err, ErrDBPathUnsafe) {
		t.Fatalf("应拒绝含 DSN 分隔符的路径，实际: %v", err)
	}
}

func TestTestDatabaseConnectionDoesNotCreateFile(t *testing.T) {
	instanceDir := t.TempDir()
	cfg := config.Default()
	cfg.Database.Path = filepath.Join(instanceDir, "database", "login.db")
	plan, err := BuildDBSetupPlan(filepath.Join(instanceDir, "login.yaml"), cfg,
		dbSetupInputFromConfig(cfg))
	if err != nil {
		t.Fatalf("构建计划失败: %v", err)
	}
	status, err := TestDatabaseConnection(context.Background(), plan)
	if err != nil {
		t.Fatalf("连接测试失败: %v", err)
	}
	if status.FileExists {
		t.Fatal("连接测试不应创建数据库文件")
	}
	if _, statErr := os.Stat(cfg.Database.Path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("数据库文件不应存在: %v", statErr)
	}
}

func TestInitializeSQLiteDatabaseIdempotent(t *testing.T) {
	instanceDir := t.TempDir()
	cfg := config.Default()
	cfg.Database.Path = filepath.Join(instanceDir, "database", "login.db")
	plan, err := BuildDBSetupPlan(filepath.Join(instanceDir, "login.yaml"), cfg,
		dbSetupInputFromConfig(cfg))
	if err != nil {
		t.Fatalf("构建计划失败: %v", err)
	}
	options := DBInitOptions{InstanceDir: instanceDir, CreateMasterKey: true,
		OperatorID: "test-operator", Purpose: "测试初始化"}
	first, err := InitializeDatabase(context.Background(), plan, options)
	if err != nil {
		t.Fatalf("首次初始化失败: %v", err)
	}
	if first.AppliedCount <= 0 {
		t.Fatalf("首次初始化应应用迁移，实际 %d", first.AppliedCount)
	}
	if !first.MasterKeyCreated {
		t.Fatal("新实例应生成受保护主密钥")
	}
	if _, statErr := os.Stat(first.DatabasePath); statErr != nil {
		t.Fatalf("数据库文件应存在: %v", statErr)
	}
	if _, statErr := os.Stat(first.MasterKeyFile); statErr != nil {
		t.Fatalf("主密钥文件应存在: %v", statErr)
	}
	assertNoRelativeDBArtifact(t)
	second, err := InitializeDatabase(context.Background(), plan, options)
	if err != nil {
		t.Fatalf("重入初始化失败: %v", err)
	}
	if !second.AlreadyMigrated || second.AppliedCount != 0 {
		t.Fatalf("重入应幂等，实际 already=%t applied=%d", second.AlreadyMigrated, second.AppliedCount)
	}
	// 迁移后 store 应可正常打开。
	store, err := appcore.OpenStore(context.Background(), plan.Config, nil)
	if err != nil {
		t.Fatalf("迁移后打开存储失败: %v", err)
	}
	_ = store.Close()
}

func TestInitializeRejectsNonSQLiteRuntime(t *testing.T) {
	instanceDir := t.TempDir()
	input := DBSetupInput{Driver: config.DatabaseDriverPostgreSQL, Host: "127.0.0.1",
		Username: "evernightlogin", DatabaseName: "evernightlogin", TLSMode: "verify-full"}
	plan, err := BuildDBSetupPlan(filepath.Join(instanceDir, "login.yaml"), config.Default(), input)
	if err != nil {
		t.Fatalf("构建计划失败: %v", err)
	}
	if _, err := InitializeDatabase(context.Background(), plan, DBInitOptions{
		InstanceDir: instanceDir, CreateMasterKey: true, OperatorID: "test-operator"}); !errors.Is(err, ErrDBRuntimeUnsupported) {
		t.Fatalf("非 SQLite 初始化必须明确报运行未接入，实际: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(instanceDir, "database", "login.db")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("非 SQLite 不得创建 SQLite 文件: %v", statErr)
	}
}
