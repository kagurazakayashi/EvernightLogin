package setupconsole

// 步骤 282：本地数据库设置、连接测试与幂等初始化。
//
// 边界（AGENTS §14.2 / §9）：
//   - SQLite 是当前唯一接入运行时的驱动：显式初始化在排他维护锁下执行正式迁移，
//     中断后重入只补未应用迁移，不重建表、不覆盖数据；
//   - 新实例生成受保护主密钥；已有数据库缺少主密钥时拒绝自动换新；
//   - MySQL/PostgreSQL/SQL Server 只提供配置校验与既有适配代码线索；实际打开/
//     迁移入口明确 fail-closed（ErrDBRuntimeUnsupported），不得用 SQLite 仿真冒充，
//     也不能显示“已连接/已初始化”；
//   - 本文件不记录/输出连接密码，错误只包含字段名与原因。

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/config"
	"github.com/kagurazakayashi/EvernightLogin/internal/appcore"
)

// 数据库初始化错误。
var (
	// ErrDBRuntimeUnsupported 表示驱动只有配置与适配代码，运行时尚未接入。
	ErrDBRuntimeUnsupported = errors.New("数据库驱动本轮仅支持配置与既有适配代码，运行入口未接入")
	// ErrDBSetupInvalid 表示数据库设置未通过配置校验。
	ErrDBSetupInvalid = errors.New("数据库设置不合法")
	// ErrMasterKeyMissing 表示已有数据库但缺少主密钥，禁止自动生成新密钥覆盖旧材料。
	ErrMasterKeyMissing = errors.New("数据库已有数据但缺少主密钥，拒绝自动生成新密钥")
	// ErrDBPathUnsafe 表示 SQLite 路径不可用于初始化（目录、DSN 分隔符等）。
	ErrDBPathUnsafe = errors.New("SQLite 数据库路径不可用")
)

// DBSetupInput 是数据库设置画面的输入；秘密只允许受保护来源，不接受明文密码。
type DBSetupInput struct {
	Driver        config.DatabaseDriver
	SQLitePath    string
	WAL           bool
	BusyTimeoutMS int
	Host          string
	Port          int
	Username      string
	Password      config.SecretSource
	DatabaseName  string
	TLSMode       string
}

// DBSetupPlan 是校验后的数据库设置计划；Config 可直接交给配置草稿保存。
type DBSetupPlan struct {
	ConfigPath  string
	InstanceDir string
	Config      config.Config
	Input       DBSetupInput
	// RuntimeSupported 为真时才能执行连接测试/初始化；否则只保存配置。
	RuntimeSupported bool
	// Notes 是给操作者的边界说明（例如“配置可用、运行未实测”）。
	Notes []string
	// ConfigIssues 是配置校验问题；只有为空时计划才可应用。
	ConfigIssues []string
}

// DatabaseSetupStatus 是连接测试/初始化前状态（只读，不含连接秘密）。
type DatabaseSetupStatus struct {
	Driver           config.DatabaseDriver
	RuntimeSupported bool
	ConfigValid      bool
	DatabasePath     string
	FileExists       bool
	FileSize         int64
	Migrated         bool
	AppliedCount     int
	LatestCount      int
	Pending          []string
	// Message 是可直接展示的中文结论；RuntimeTested=false 表示未做真实连接。
	Message       string
	RuntimeTested bool
}

// buildDBConfig 把输入合并到基础配置并做正式校验；返回的 Database.Path 保留操作者
// 输入形式（相对路径按实例目录解析在 dbAbsolutePath 中完成）。
func buildDBConfig(base config.Config, instanceDir string, input DBSetupInput) (config.Config, []string) {
	cfg := base
	driver := input.Driver
	if driver == "" {
		driver = config.DatabaseDriverSQLite
	}
	cfg.Database.Driver = driver
	cfg.Database.Path = strings.TrimSpace(input.SQLitePath)
	cfg.Database.WAL = input.WAL
	cfg.Database.BusyTimeoutMS = input.BusyTimeoutMS
	cfg.Database.Host = strings.TrimSpace(input.Host)
	cfg.Database.Port = input.Port
	cfg.Database.Username = strings.TrimSpace(input.Username)
	cfg.Database.Password = input.Password
	cfg.Database.Database = strings.TrimSpace(input.DatabaseName)
	cfg.Database.TLSMode = strings.TrimSpace(input.TLSMode)
	if cfg.Database.Driver == config.DatabaseDriverSQLite {
		// SQLite 默认值：未显式给出时与生产默认一致，避免 0 被后续步骤当作覆盖。
		if cfg.Database.BusyTimeoutMS == 0 {
			cfg.Database.BusyTimeoutMS = 5000
		}
		if cfg.Database.Path == "" {
			cfg.Database.Path = "database/login.db"
		}
	}
	var issues []string
	if err := cfg.Validate(); err != nil {
		issues = append(issues, strings.Split(err.Error(), "\n")...)
	}
	// instanceDir 目前只做相对路径解析与提示，不写入配置。
	_ = instanceDir
	return cfg, issues
}

// dbAbsolutePath 把配置中的数据库路径按实例目录解析。
func dbAbsolutePath(instanceDir, configured string) string {
	path := strings.TrimSpace(configured)
	if path == "" {
		return ""
	}
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	if strings.TrimSpace(instanceDir) == "" {
		return filepath.Clean(path)
	}
	return filepath.Join(instanceDir, path)
}

// BuildDBSetupPlan 校验数据库设置并解析实例目录；不创建数据库/密钥/目录。
func BuildDBSetupPlan(configPath string, base config.Config, input DBSetupInput) (DBSetupPlan, error) {
	configPath = strings.TrimSpace(configPath)
	instanceDir := ""
	if configPath != "" {
		absoluteConfig, err := filepath.Abs(configPath)
		if err != nil {
			return DBSetupPlan{}, fmt.Errorf("%w: 配置路径无效", ErrDBSetupInvalid)
		}
		instanceDir = filepath.Dir(absoluteConfig)
		configPath = absoluteConfig
	}
	cfg, issues := buildDBConfig(base, instanceDir, input)
	plan := DBSetupPlan{ConfigPath: configPath, InstanceDir: instanceDir,
		Config: cfg, Input: input, RuntimeSupported: cfg.Database.Driver.RuntimeSupported(),
		ConfigIssues: issues}
	if !plan.RuntimeSupported {
		plan.Notes = append(plan.Notes,
			"该驱动本轮只提供配置字段与既有适配代码：配置可保存/校验，但主程序与初始化入口会明确拒绝运行，不会显示已连接或已初始化。")
	} else {
		plan.Notes = append(plan.Notes, "SQLite 是本轮唯一接入运行时的驱动。")
	}
	if len(issues) > 0 {
		return plan, fmt.Errorf("%w：%s", ErrDBSetupInvalid, strings.Join(issues, "；"))
	}
	if plan.RuntimeSupported {
		absolute := dbAbsolutePath(instanceDir, cfg.Database.Path)
		if absolute == "" {
			return plan, fmt.Errorf("%w: SQLite 路径为空", ErrDBSetupInvalid)
		}
		if strings.ContainsAny(absolute, "?#") {
			return plan, fmt.Errorf("%w: 路径不能包含 ? 或 #（SQLite DSN 分隔符）", ErrDBPathUnsafe)
		}
		if info, statErr := os.Stat(absolute); statErr == nil && info.IsDir() {
			return plan, fmt.Errorf("%w: 路径是目录", ErrDBPathUnsafe)
		} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			return plan, fmt.Errorf("%w: 无法读取数据库路径状态: %v", ErrDBPathUnsafe, statErr)
		}
	}
	return plan, nil
}

// ApplyDBSetupToDraft 把数据库设置写入配置草稿；非当前驱动的字段被删除，避免保存
// 互相矛盾的残留值。password 只以 env/file 来源映射写入。
func ApplyDBSetupToDraft(draft *ConfigDraft, plan DBSetupPlan) error {
	if draft == nil {
		return errors.New("缺少配置草稿")
	}
	database := plan.Config.Database
	if err := draft.SetValue("database.driver", string(database.Driver)); err != nil {
		return err
	}
	if database.Driver == config.DatabaseDriverSQLite {
		databasePath := strings.TrimSpace(database.Path)
		if databasePath == "" {
			databasePath = "database/login.db"
		}
		if err := draft.SetValue("database.path", databasePath); err != nil {
			return err
		}
		if err := draft.SetValue("database.wal", database.WAL); err != nil {
			return err
		}
		if err := draft.SetValue("database.busy_timeout_ms", database.BusyTimeoutMS); err != nil {
			return err
		}
		for _, field := range []string{"database.host", "database.port", "database.username",
			"database.password", "database.name", "database.tls_mode"} {
			draft.Unset(field)
		}
		return nil
	}
	draft.Unset("database.path")
	draft.Unset("database.wal")
	draft.Unset("database.busy_timeout_ms")
	if err := draft.SetValue("database.host", database.Host); err != nil {
		return err
	}
	if err := draft.SetValue("database.port", database.Port); err != nil {
		return err
	}
	if err := draft.SetValue("database.username", database.Username); err != nil {
		return err
	}
	if err := draft.SetValue("database.name", database.Database); err != nil {
		return err
	}
	if mode := strings.TrimSpace(database.TLSMode); mode != "" {
		if err := draft.SetValue("database.tls_mode", mode); err != nil {
			return err
		}
	} else {
		draft.Unset("database.tls_mode")
	}
	switch database.Password.Kind {
	case config.SecretSourceEnv:
		if err := draft.SetValue("database.password", map[string]any{"env": database.Password.Name}); err != nil {
			return err
		}
	case config.SecretSourceFile:
		if err := draft.SetValue("database.password", map[string]any{"file": database.Password.Name}); err != nil {
			return err
		}
	default:
		draft.Unset("database.password")
	}
	return nil
}

// TestDatabaseConnection 执行一次显式连接测试：
//   - SQLite：数据库文件存在时真实打开并读取迁移状态；文件不存在时不创建，只报告
//     “初始化时将创建”；
//   - 其他驱动：只校验配置，明确返回“配置可用、运行未实测”，不返回 RuntimeTested。
func TestDatabaseConnection(ctx context.Context, plan DBSetupPlan) (DatabaseSetupStatus, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	status := DatabaseSetupStatus{Driver: plan.Config.Database.Driver,
		RuntimeSupported: plan.RuntimeSupported, ConfigValid: len(plan.ConfigIssues) == 0,
		DatabasePath: dbAbsolutePath(plan.InstanceDir, plan.Config.Database.Path)}
	if !plan.RuntimeSupported {
		status.Message = "配置可用、运行未实测：主程序打开与迁移入口会明确 fail-closed（本轮不接入后端）。"
		return status, ErrDBRuntimeUnsupported
	}
	if !status.ConfigValid {
		status.Message = "数据库配置未通过校验，不能连接测试。"
		return status, ErrDBSetupInvalid
	}
	info, statErr := os.Stat(status.DatabasePath)
	switch {
	case errors.Is(statErr, os.ErrNotExist):
		status.Message = "数据库文件尚未创建；执行初始化后会创建并应用正式迁移。"
		return status, nil
	case statErr != nil:
		status.Message = fmt.Sprintf("无法读取数据库文件状态: %v", statErr)
		return status, fmt.Errorf("%w: %v", ErrDBPathUnsafe, statErr)
	case info.IsDir():
		status.Message = "数据库路径是目录，不能作为 SQLite 文件。"
		return status, ErrDBPathUnsafe
	}
	status.FileExists = true
	status.FileSize = info.Size()
	store, err := appcore.OpenStore(ctx, plan.Config, nil)
	if err != nil {
		status.Message = "数据库连接失败；请检查路径与权限。"
		return status, err
	}
	defer func() { _ = store.Close() }()
	pending, err := appcore.CheckMigrated(ctx, store)
	if err != nil {
		status.Message = "数据库已打开但读取迁移状态失败。"
		return status, err
	}
	status.Pending = append([]string(nil), pending...)
	status.AppliedCount = -1
	status.Migrated = len(pending) == 0
	status.RuntimeTested = true
	if status.Migrated {
		status.Message = "连接成功：数据库结构已迁移到最新版本。"
	} else {
		status.Message = fmt.Sprintf("连接成功：数据库结构待迁移（%d 项）。", len(pending))
	}
	return status, nil
}

// DBInitOptions 是数据库初始化的本地维护参数。
type DBInitOptions struct {
	// InstanceDir 是实例目录（配置/数据库/密钥所在目录）；为空时用配置路径目录。
	InstanceDir string
	// MasterKeyFile 是显式主密钥文件路径；空时按配置 secrets.master_key 或实例目录
	// 约定（secrets/master.key、master.key）解析。
	MasterKeyFile string
	// CreateMasterKey 允许新实例在密钥文件缺失时生成受保护主密钥；已有数据库缺密钥
	// 时即使为真也拒绝自动换新。
	CreateMasterKey bool
	// OperatorID 是稳定本地操作者标识（进入维护锁/日志，不是 Evernight 账户）。
	OperatorID string
	// Purpose 是维护锁目的（简短、无秘密）。
	Purpose string
	// Lock 是已持有的排他维护锁；nil 时本函数按 OperatorID/InstanceDir 自行取得。
	Lock *MaintenanceLock
	Now  func() time.Time
	// Logger 只记录结构化状态，不包含连接秘密。
	Logger *slog.Logger
}

// DBInitResult 是初始化结果（不含任何秘密）。
type DBInitResult struct {
	Driver            config.DatabaseDriver
	DatabasePath      string
	AlreadyMigrated   bool
	AppliedCount      int
	Pending           []string
	MasterKeyFile     string
	MasterKeyReused   bool
	MasterKeyCreated  bool
	LockPath          string
	RuntimeTested     bool
	ConfigurationOnly bool
}

// InitializeDatabase 在排他维护锁下执行 SQLite 正式迁移，支持中断重入。
func InitializeDatabase(ctx context.Context, plan DBSetupPlan, options DBInitOptions) (DBInitResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	result := DBInitResult{Driver: plan.Config.Database.Driver,
		ConfigurationOnly: !plan.RuntimeSupported}
	if !plan.RuntimeSupported {
		return result, ErrDBRuntimeUnsupported
	}
	if len(plan.ConfigIssues) > 0 {
		return result, ErrDBSetupInvalid
	}
	instanceDir := strings.TrimSpace(options.InstanceDir)
	if instanceDir == "" {
		instanceDir = plan.InstanceDir
	}
	if instanceDir == "" {
		return result, fmt.Errorf("%w: 缺少实例目录", ErrDBSetupInvalid)
	}
	absoluteInstance, err := filepath.Abs(instanceDir)
	if err != nil {
		return result, fmt.Errorf("%w: 实例目录无效", ErrDBSetupInvalid)
	}
	if err := os.MkdirAll(absoluteInstance, 0o700); err != nil {
		return result, fmt.Errorf("创建实例目录失败: %w", err)
	}
	operatorID := strings.TrimSpace(options.OperatorID)
	if operatorID == "" {
		return result, fmt.Errorf("%w: 缺少本地操作者标识", ErrIdentityInvalid)
	}
	databasePath := dbAbsolutePath(absoluteInstance, plan.Config.Database.Path)
	if databasePath == "" {
		return result, fmt.Errorf("%w: SQLite 路径为空", ErrDBSetupInvalid)
	}
	// 初始化是显式写操作：先创建数据库父目录（0700）再取得排他锁，锁文件
	// 需要父目录存在；不在只读检测/连接测试阶段创建任何目录。
	if err := os.MkdirAll(filepath.Dir(databasePath), 0o700); err != nil {
		return result, fmt.Errorf("创建数据库目录失败: %w", err)
	}
	lock := options.Lock
	if lock == nil {
		identity, identityErr := LocalMaintenanceIdentity(absoluteInstance)
		if identityErr != nil {
			return result, identityErr
		}
		purpose := strings.TrimSpace(options.Purpose)
		if purpose == "" {
			purpose = "初始化数据库结构"
		}
		acquired, lockErr := AcquireMaintenanceLock(ctx, LockRequest{
			InstanceDir:  absoluteInstance,
			DatabasePath: dbAbsolutePath(absoluteInstance, plan.Config.Database.Path),
			Purpose:      purpose, Operator: identity})
		if lockErr != nil {
			return result, lockErr
		}
		lock = acquired
	}
	defer func() { _ = lock.Release() }()
	result.LockPath = lock.Path()

	now := options.Now
	if now == nil {
		now = time.Now
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError + 1}))
	}
	cfg := plan.Config
	// 相对配置路径必须解析为实例目录下的绝对路径后再打开：OpenStore 直接使用
	// cfg.Database.Path，未解析会在进程当前目录误建 database/login.db。
	cfg.Database.Path = databasePath
	result.DatabasePath = databasePath
	if info, statErr := os.Stat(databasePath); statErr == nil && info.IsDir() {
		return result, fmt.Errorf("%w: 路径是目录", ErrDBPathUnsafe)
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return result, fmt.Errorf("%w: %v", ErrDBPathUnsafe, statErr)
	}
	existingData := false
	if info, statErr := os.Stat(databasePath); statErr == nil && info.Size() > 0 {
		existingData = true
	}
	masterKeyFile := strings.TrimSpace(options.MasterKeyFile)
	if !cfg.Secrets.MasterKey.IsSet() {
		if masterKeyFile == "" {
			masterKeyFile = defaultDBMasterKeyFile(absoluteInstance)
		}
		if info, statErr := os.Stat(masterKeyFile); statErr != nil || !info.Mode().IsRegular() {
			if existingData {
				return result, fmt.Errorf("%w: %s", ErrMasterKeyMissing, masterKeyFile)
			}
			if !options.CreateMasterKey {
				return result, fmt.Errorf("主密钥文件不存在: %s；新实例初始化必须显式允许生成主密钥", masterKeyFile)
			}
		} else {
			result.MasterKeyReused = true
		}
	}
	keyFileUsed := ""
	if !cfg.Secrets.MasterKey.IsSet() {
		if _, _, loadErr := appcore.LoadKeyring(ctx, cfg, masterKeyFile,
			options.CreateMasterKey && !existingData, now); loadErr != nil {
			return result, fmt.Errorf("加载/创建主密钥失败: %w", loadErr)
		}
		keyFileUsed = masterKeyFile
		if !result.MasterKeyReused {
			result.MasterKeyCreated = true
		}
	}
	result.MasterKeyFile = keyFileUsed

	store, err := appcore.OpenStore(ctx, cfg, nil)
	if err != nil {
		return result, fmt.Errorf("打开数据库失败: %w", err)
	}
	defer func() { _ = store.Close() }()
	pending, err := appcore.CheckMigrated(ctx, store)
	if err != nil {
		return result, fmt.Errorf("读取迁移状态失败: %w", err)
	}
	if len(pending) == 0 {
		result.AlreadyMigrated = true
		result.RuntimeTested = true
		logger.Info("数据库结构已是最新", "driver", string(cfg.Database.Driver),
			"database", databasePath, "operator", operatorID)
		return result, nil
	}
	applied, err := appcore.ApplyMigrations(ctx, store)
	if err != nil {
		result.Pending = append([]string(nil), pending...)
		return result, fmt.Errorf("应用数据库迁移失败: %w", err)
	}
	remaining, checkErr := appcore.CheckMigrated(ctx, store)
	if checkErr != nil {
		return result, fmt.Errorf("迁移后复核失败: %w", checkErr)
	}
	if len(remaining) != 0 {
		result.Pending = append([]string(nil), remaining...)
		return result, fmt.Errorf("迁移后仍有 %d 项未应用", len(remaining))
	}
	result.AppliedCount = applied
	result.RuntimeTested = true
	logger.Info("数据库迁移完成", "driver", string(cfg.Database.Driver),
		"database", databasePath, "applied", applied, "operator", operatorID)
	return result, nil
}

// defaultDBMasterKeyFile 按独立部署约定返回主密钥文件路径（只返回路径，不创建）。
func defaultDBMasterKeyFile(instanceDir string) string {
	return filepath.Join(instanceDir, "secrets", "master.key")
}

// discardWriter 是 Logger 默认丢弃输出的小适配器。
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
