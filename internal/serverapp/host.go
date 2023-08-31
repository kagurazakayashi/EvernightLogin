package serverapp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/logging"
	"github.com/kagurazakayashi/EvernightLogin/internal/maintenance"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

// ServeOptions 是 login-server serve 的显式参数。所有字段来自命令行或测试，
// 不读取隐式全局状态；秘密只能来自受保护文件或配置中的安全来源。
type ServeOptions struct {
	// ConfigPath 是必需 YAML 配置文件路径。
	ConfigPath string
	// DatabasePath 覆盖配置里的 database.path（便于部署时外置数据目录）。
	DatabasePath string
	// MasterKeyFile 是主密钥环文件路径；配置未设置 secrets.master_key 时使用。
	MasterKeyFile string
	// AccessLogPath 是访问日志文件路径；空表示写 StandardError。
	AccessLogPath string
	// AccessLogMaxBytes/AccessLogMaxFiles 是访问日志文件轮转配置：单文件上限
	// （0 使用默认 64 MiB，允许 1 MiB～1 GiB）与保留历史文件数量（0 使用默认 5，
	// 允许 1～100，不含当前文件）。只在使用文件访问日志时生效。
	AccessLogMaxBytes int64
	AccessLogMaxFiles int
	// ExtraMounts 是协议端点处理程序的显式挂载点；本包不实现协议包，只提供装配
	// 位置（详见 HandlerMount 与 ComposeHandler）。
	ExtraMounts []HandlerMount
	// EnableProtocol 显式启用 OAuth 2.0 / OpenID Connect 协议端点（命令行覆盖
	// 配置 protocol.enabled）；默认关闭。启用后仍要求配置合法协议签发方。
	EnableProtocol bool
	// EnableAdminAPI 显式启用内置管理 JSON API（internal/adminapi）；默认关闭。
	// 启用后管理会话/CSRF 契约复用现有 session.Service，未启用时请求 404。
	EnableAdminAPI bool
	// AdminAPIPrefix 覆盖管理 API 站内前缀；空使用 adminapi.DefaultBasePath。
	AdminAPIPrefix string
	// EnableManagedAPI 显式启用业务应用托管管理 API（internal/managedapi/httpapi，
	// 默认 /api/managed/v1）；默认关闭。认证使用用户普通会话 Bearer 或应用客户端
	// secret/证书，不复用管理强会话；未启用时请求 404。
	EnableManagedAPI bool
	// ManagedAPIPrefix 覆盖业务托管 API 站内前缀；空使用 /api/managed/v1。
	ManagedAPIPrefix string
	// EnableAppSupport 显式启用应用受限客服 API（OAuth 用户委托 Access Token +
	// 应用成员/权限联合判定）；默认关闭。需要同时启用 OAuth 协议端点。
	EnableAppSupport bool
	// AppSupportPrefix 覆盖应用客服 API 站内前缀；空使用 /api/app/v1/support。
	AppSupportPrefix string
	// AppSupportAudience 覆盖应用客服资源 audience；空使用默认
	// urn:evernight:app-support。
	AppSupportAudience string
	// Migrate 为 true（--migrate=apply）时先执行数据库迁移再启动。
	Migrate bool
	// MaintenanceStateDir 覆盖库外维护状态目录；空则使用数据库目录同级的
	// "<数据目录名>-maintenance" 目录。
	MaintenanceStateDir string
	// StandardOutput/StandardError 是进度与结构化日志输出；nil 使用 os 标准流。
	StandardOutput io.Writer
	StandardError  io.Writer
	// AccessLog 是测试注入的访问日志输出；非 nil 时忽略 AccessLogPath。
	AccessLog io.Writer
	// Now 是可注入时钟；nil 使用 time.Now。
	Now func() time.Time
	// OnStarted 在监听绑定成功后回调一次（用于测试获取实际端口与 CLI 诊断）；
	// 回调必须快速返回且不得记录秘密。nil 表示不回调。
	OnStarted func(StartResult)
	// InitMaintenanceState 显式允许在已有数据库上创建缺失的库外维护状态。
	// 默认 false：维护状态缺失时拒绝启动，避免删除/丢失状态目录后绕过维护门禁。
	// 仅本地受控运维在确认状态丢失原因后使用。
	InitMaintenanceState bool
	// AllowUninitialized 显式允许数据库尚未完成首次初始化时启动服务（仅开发/测试）。
	// 默认 false：未初始化数据库拒绝启动，避免在未创建 root 的实例上对外提供页面。
	AllowUninitialized bool
	// AllowLegacyWithoutSensitive 显式允许会话管理访问仅使用旧强认证闸门而未经
	// 敏感操作策略判定（步骤 39 尚未装配的过渡开关）。默认 false（fail-closed）。
	AllowLegacyWithoutSensitive bool
}

// maintenanceStateDir 返回默认库外维护状态目录：数据库目录的同级目录（不能是
// 数据库目录本身或其后代，避免恢复代际随数据库回滚而丢失）。
func defaultMaintenanceStateDir(databasePath string) string {
	dataDir := filepath.Dir(databasePath)
	return filepath.Join(filepath.Dir(dataDir), filepath.Base(dataDir)+"-maintenance")
}

// openMaintenance 加载库外维护状态；allowCreate 为 true 时才允许在状态缺失时
// 创建一次签名初始状态（normal）。
//
// 安全语义：维护状态缺失意味着无法证明当前是否处于维护/恢复代际，默认必须
// fail-closed。自动创建只允许两类明确场景：全新/空数据库的首次部署，或调用方
// 显式传入 --init-maintenance-state 的本地受控运维。损坏（加载/HMAC 校验失败）
// 一律拒绝，不重建、不覆盖。
// 返回 created 表示本次调用创建了状态目录（失败路径清理用）。
func openMaintenance(ctx context.Context, cfg login.Config, keyring *secrets.Keyring,
	stateDir string, logger *slog.Logger, now func() time.Time,
	allowCreate bool) (*maintenance.Controller, bool, error) {
	if stateDir == "" {
		stateDir = defaultMaintenanceStateDir(cfg.Database.Path)
	}
	// maintenance.New 会创建/校验状态目录；记录目录是否原本存在，fail-closed 时
	// 清理本次新建的空目录，避免失败启动留下副作用。
	_, statErr := os.Stat(stateDir)
	stateDirPreexisting := statErr == nil
	provider := secrets.ProviderFunc(func(context.Context) ([]byte, error) {
		return keyring.Document()
	})
	controller, err := maintenance.New(maintenance.Options{
		StateDir:     stateDir,
		DatabasePath: cfg.Database.Path,
		Keyring:      provider,
		Logger:       logger,
		Now:          now,
	})
	if err != nil {
		return nil, false, fmt.Errorf("加载维护状态失败: %w", err)
	}
	if controller.Missing() && !allowCreate {
		_ = controller.Close()
		if !stateDirPreexisting {
			_ = os.RemoveAll(stateDir)
		}
		return nil, false, fmt.Errorf("库外维护状态缺失（%s）：为防止删除状态目录绕过维护门禁，"+
			"默认拒绝启动；请先确认状态丢失原因，再由本地受控运维用 login-server init 初始化，"+
			"或显式使用 --init-maintenance-state 创建", stateDir)
	}
	created := false
	if controller.Missing() {
		if err := controller.Initialize(ctx, maintenance.InitializeRequest{
			Operator: maintenance.LocalOperator(),
			Reason:   "login-server 首次创建/显式初始化库外维护状态",
		}); err != nil {
			_ = controller.Close()
			return nil, false, fmt.Errorf("初始化维护状态失败: %w", err)
		}
		created = true
		logger.Info("已创建库外维护状态", "state_dir", stateDir)
	}
	return controller, created, nil
}

// hasSchemaHistory 判断数据库是否已有迁移记账表：没有该表表示从未执行过迁移，
// 属于全新/空数据库（允许创建初始库外维护状态）；已有表则必须要求维护状态存在。
func hasSchemaHistory(ctx context.Context, store *sqlite.Store) (bool, error) {
	var count int
	if err := store.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_history'`).
		Scan(&count); err != nil {
		return false, fmt.Errorf("读取数据库迁移记账失败: %w", err)
	}
	return count > 0, nil
}

// newLogger 按配置构造结构化运行日志器；日志只写脱敏字段，不写秘密。
func newLogger(cfg login.Config, output io.Writer) (*slog.Logger, error) {
	if output == nil {
		output = io.Discard
	}
	logger, err := logging.New(string(cfg.Logging.Level), string(cfg.Logging.Format), output)
	if err != nil {
		return nil, fmt.Errorf("构造运行日志器失败: %w", err)
	}
	return logger, nil
}

// accessLogTarget 打开访问日志输出；返回 writer 与需要关闭的文件（若为文件）。
//
// 文件访问日志默认启用受控轮转（单文件上限 + 历史文件数量上限），文件按平台
// 受保护权限创建（0600 / 受限 ACL）；配置非法或打开失败时拒绝启动，不静默
// 退化成"无限增长"或"不记录"。
func accessLogTarget(options ServeOptions) (io.Writer, io.Closer, error) {
	if options.AccessLog != nil {
		return options.AccessLog, nil, nil
	}
	if options.StandardError == nil {
		options.StandardError = os.Stderr
	}
	if options.AccessLogPath == "" {
		return options.StandardError, nil, nil
	}
	writer, err := NewRotatingLogWriter(options.AccessLogPath,
		options.AccessLogMaxBytes, options.AccessLogMaxFiles, nil)
	if err != nil {
		return nil, nil, err
	}
	return writer, writer, nil
}

// MaintenanceHealthPath 返回维护模式下仍放行的健康检查路径（含部署前缀）。
func MaintenanceHealthPath(cfg login.Config) string {
	return cfg.Server.PathPrefix + "/healthz"
}

// maintenanceHandler 是维护状态下唯一对外提供的处理程序：健康检查返回 200，
// 其余请求返回 503 与维护提示（不装配任何业务页面/会话/数据库写入）。
func maintenanceHandler(cfg login.Config) http.Handler {
	healthPath := MaintenanceHealthPath(cfg)
	const body = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">` +
		`<title>服务维护中</title></head><body><h1>服务维护中</h1>` +
		`<p>当前实例处于维护状态，业务功能暂不对外提供，请稍后重试。</p></body></html>`
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == healthPath && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok","mode":"maintenance"}`))
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(body))
	})
}

// runServe 是 serve 的完整装配与运行流程（构造 -> 启动 -> 等待关闭）。
//
// 单实例约束：装配一开始就取得与数据库同目录的排他锁（见 AcquireInstanceLock），
// 同一数据库本轮只允许一个 login-server 进程；第二个进程或同进程第二次 serve
// 立即失败，不会出现两个进程各自调度任务/写审计的拆分状态。
//
// 共用装配：数据库/迁移/审计/领域服务/敏感闸门/后台任务/管理域由 OpenBase 统一
// 构造（与公开 app 入口同一实现）；本函数只追加独立服务特有的单实例锁、库外维护
// 状态、访问日志、页面/协议挂载、HTTP 监听与优雅关闭。
//
// 关闭顺序：Instance（逆序停止后台任务与监听）-> 基础运行时（后台任务幂等停止、
// SQLite 存储）-> 维护状态锁 -> 访问日志文件 -> 单实例锁。任何一步关闭失败都会
// 聚合返回，但仍继续释放后续资源，避免遗留端口、文件句柄或数据库连接。
func runServe(ctx context.Context, options ServeOptions) (exitErr error) {
	now := options.Now
	if now == nil {
		now = time.Now
	}
	cfg, err := LoadConfig(options.ConfigPath, options.DatabasePath)
	if err != nil {
		return err
	}
	if options.EnableProtocol {
		cfg.Protocol.Enabled = true
		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("启用协议端点后的配置校验失败: %w", err)
		}
	}
	stdout := options.StandardOutput
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := options.StandardError
	if stderr == nil {
		stderr = os.Stderr
	}
	logger, err := newLogger(cfg, stderr)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "login-server %s\n", login.CurrentBuildInfo().Version)
	fmt.Fprintf(stdout, "配置: %s\n", options.ConfigPath)
	instanceLock, err := AcquireInstanceLock(cfg.Database.Path)
	if err != nil {
		return err
	}
	defer instanceLock.Release()
	logger.Info("已取得单实例数据库锁", "lock_path", instanceLock.Path())
	logger.Info("开始装配独立服务",
		"database", cfg.Database.Path,
		"listen_addresses", cfg.Server.ListenAddresses(),
		"path_prefix", cfg.Server.PathPrefix,
		"tls", cfg.Server.TLSEnabled(),
		"extra_mounts", len(options.ExtraMounts))

	keyring, keyPath, err := LoadKeyring(ctx, cfg, options.MasterKeyFile, false, now)
	if err != nil {
		return err
	}
	if keyPath != "" {
		logger.Info("已加载主密钥环文件", "path", keyPath)
	}
	maintenanceStateDir := options.MaintenanceStateDir
	if maintenanceStateDir == "" {
		maintenanceStateDir = defaultMaintenanceStateDir(cfg.Database.Path)
	}
	// 用只读探针连接判断数据库是否"从未迁移"（没有 schema_history 表）：只有这种
	// 首次部署场景才允许自动创建缺失的维护状态。已有迁移记录的库上状态缺失一律
	// fail-closed，防止删除状态目录后绕过维护/恢复门禁。
	probeStore, err := OpenStore(ctx, cfg, nil)
	if err != nil {
		return err
	}
	hasMigrationBookkeeping, probeErr := hasSchemaHistory(ctx, probeStore)
	closeProbeErr := probeStore.Close()
	if probeErr != nil {
		return probeErr
	}
	if closeProbeErr != nil {
		return fmt.Errorf("关闭数据库探针连接失败: %w", closeProbeErr)
	}
	brandNewDatabase := !hasMigrationBookkeeping
	allowCreateMaintenance := brandNewDatabase || options.InitMaintenanceState
	if brandNewDatabase {
		logger.Info("检测到从未迁移的新数据库，允许创建初始库外维护状态")
	}
	maintenanceController, maintenanceCreated, err := openMaintenance(ctx, cfg, keyring,
		maintenanceStateDir, logger, now, allowCreateMaintenance)
	if err != nil {
		return err
	}
	defer func() {
		closeErr := maintenanceController.Close()
		if closeErr != nil {
			exitErr = errors.Join(exitErr, fmt.Errorf("关闭维护状态失败: %w", closeErr))
		}
		// 失败路径清理本次新建的维护状态目录，避免未迁移/配置错误等失败启动留下
		// 目录副作用（成功启动则保留）。
		if exitErr != nil && maintenanceCreated {
			if removeErr := os.RemoveAll(maintenanceStateDir); removeErr != nil {
				exitErr = errors.Join(exitErr,
					fmt.Errorf("清理本次创建的维护状态目录失败: %w", removeErr))
			}
		}
	}()
	maintenanceMode := maintenanceController.Mode() == maintenance.ModeMaintenance
	// 迁移会写数据库，维护状态下必须先退出维护再迁移，避免绕过维护/恢复门禁。
	if maintenanceMode && options.Migrate {
		return fmt.Errorf("维护状态下禁止执行数据库迁移：请先按运维流程退出维护并重启")
	}

	accessWriter, accessFile, err := accessLogTarget(options)
	if err != nil {
		return err
	}
	if accessFile != nil {
		defer func() {
			if closeErr := accessFile.Close(); closeErr != nil {
				exitErr = errors.Join(exitErr, fmt.Errorf("关闭访问日志失败: %w", closeErr))
			}
		}()
	}

	base, err := OpenBase(ctx, BaseOptions{
		Config: cfg, Keyring: keyring, Migrate: options.Migrate,
		WriteGuard: maintenanceController.Gate().Guard,
		Logger:     logger, Now: now,
		RequireInitialized:          !maintenanceMode && !options.AllowUninitialized,
		AllowLegacyWithoutSensitive: options.AllowLegacyWithoutSensitive,
		MaintenanceOnly:             maintenanceMode,
	})
	if err != nil {
		if errors.Is(err, ErrUninitialized) {
			return fmt.Errorf("数据库尚未完成首次初始化（没有 root）：请先运行 " +
				"login-server init 创建 root；仅开发/测试可显式使用 --allow-uninitialized")
		}
		return err
	}
	defer func() {
		if closeErr := base.Close(context.Background()); closeErr != nil {
			exitErr = errors.Join(exitErr, fmt.Errorf("关闭基础运行时失败: %w", closeErr))
		}
	}()
	if base.Mail.Enabled {
		logger.Info("生产邮件发送已启用", "tls_mode", base.Mail.TLSMode,
			"from_domain", mailDomain(base.Mail.From.Spec),
			"delivery_max_attempts", cfg.Mail.Delivery.MaxAttempts,
			"delivery_timeout_seconds", cfg.Mail.Delivery.TimeoutSeconds)
	} else {
		logger.Info("生产邮件发送未启用：邮件能力将以明确错误拒绝，不访问网络")
	}

	var handler http.Handler
	var server *login.Server
	var instance *login.Instance
	mountPaths := make([]string, 0, len(options.ExtraMounts))
	if maintenanceMode {
		if len(options.ExtraMounts) > 0 {
			logger.Warn("实例处于维护状态：协议/管理 API 挂载点不对外提供（只放行健康检查）",
				"extra_mounts", len(options.ExtraMounts))
		}
		logger.Warn("实例处于维护状态：只提供健康检查与维护提示，不装配业务页面与后台任务")
		handler = maintenanceHandler(cfg)
	} else {
		if base.Uninitialized {
			logger.Warn("数据库尚未完成首次初始化：已按 --allow-uninitialized 显式放行，" +
				"仅用于开发/测试，不要暴露到非回环网络")
		}
		// 协议域/页面/HTTP 防护/挂载点由共享装配构造（与 app.Open 同一实现）。
		httpRuntime, httpErr := BuildHTTPRuntime(base, HTTPRuntimeOptions{
			Prefix:             cfg.Server.PathPrefix,
			AccessLog:          accessWriter,
			ExtraMounts:        options.ExtraMounts,
			EnableProtocol:     options.EnableProtocol,
			EnableAdminAPI:     options.EnableAdminAPI,
			AdminAPIPrefix:     options.AdminAPIPrefix,
			EnableManagedAPI:   options.EnableManagedAPI,
			ManagedAPIPrefix:   options.ManagedAPIPrefix,
			EnableAppSupport:   options.EnableAppSupport,
			AppSupportPrefix:   options.AppSupportPrefix,
			AppSupportAudience: options.AppSupportAudience,
			Logger:             logger,
		})
		if httpErr != nil {
			return httpErr
		}
		handler = httpRuntime.Handler
		mountPaths = append(mountPaths, httpRuntime.Mounts...)
	}

	server, err = login.NewServer(login.ServerOptions{
		Config: cfg, Handler: handler, Prefix: cfg.Server.PathPrefix, Logger: logger})
	if err != nil {
		return fmt.Errorf("构造监听服务失败: %w", err)
	}
	components := []login.BackgroundComponent{server}
	if base.Tasks != nil {
		components = append(components, base.Tasks)
	}
	instance, err = login.New(login.Options{
		Config:     &cfg,
		Logger:     logger,
		Database:   databasePingAdapter{store: base.Store},
		Components: components,
	})
	if err != nil {
		return fmt.Errorf("构造服务实例失败: %w", err)
	}
	if err := instance.Start(ctx); err != nil {
		return fmt.Errorf("启动服务失败: %w", err)
	}
	addrs := server.Addrs()
	printed := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		printed = append(printed, addr.String())
	}
	fmt.Fprintf(stdout, "监听地址: %v（前缀 %q，TLS=%v，维护模式=%v，任务调度=%v，额外挂载=%v）\n",
		printed, cfg.Server.PathPrefix, server.TLSEnabled(), maintenanceMode,
		base.Tasks != nil, mountPaths)
	logger.Info("独立服务已启动",
		"addresses", printed, "path_prefix", cfg.Server.PathPrefix,
		"maintenance", maintenanceMode, "tls", server.TLSEnabled(),
		"task_runtime", base.Tasks != nil, "extra_mounts", mountPaths)
	if options.OnStarted != nil {
		options.OnStarted(StartResult{Addresses: printed,
			TLS: server.TLSEnabled(), Maintenance: maintenanceMode,
			Tasks: base.Tasks != nil, Mounts: mountPaths})
	}

	<-ctx.Done()
	logger.Info("收到关闭信号，开始有界优雅关闭",
		"shutdown_timeout_seconds", cfg.Server.ShutdownTimeoutSeconds)
	shutdownTimeout := time.Duration(cfg.Server.ShutdownTimeoutSeconds) * time.Second
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout+2*time.Second)
	defer cancel()
	if closeErr := instance.Close(shutdownCtx); closeErr != nil {
		return fmt.Errorf("优雅关闭未完全成功: %w", closeErr)
	}
	logger.Info("独立服务已关闭")
	return nil
}

// databasePingAdapter 把 SQLite 存储适配为公开的 login.Database 就绪检查契约。
type databasePingAdapter struct {
	store *sqlite.Store
}

// Ping 实现 login.Database。
func (a databasePingAdapter) Ping(ctx context.Context) error {
	if a.store == nil {
		return fmt.Errorf("数据库未打开")
	}
	return a.store.Ping(ctx)
}

// 保留 sqlite 类型引用（RunServe 内部使用）；避免未来重构时误删导入。
var _ = (*sqlite.Store)(nil)

// RunServe 装配并运行独立 HTTP 服务，直到 ctx 被取消（信号驱动）后执行有界
// 优雅关闭。返回值非 nil 表示装配失败或关闭失败，退出码应由调用方置为非零。
func RunServe(ctx context.Context, options ServeOptions) error {
	if ctx == nil {
		ctx = context.Background()
	}
	return runServe(ctx, options)
}

// StartResult 是 serve 成功绑定后的诊断信息（不含秘密），供测试与 CLI 输出使用。
type StartResult struct {
	// Addresses 是实际绑定的监听地址（含系统分配端口）。
	Addresses []string
	// TLS 表示本地 TLS 是否启用。
	TLS bool
	// Maintenance 表示本次启动是否处于维护模式。
	Maintenance bool
	// Tasks 表示后台任务运行时（执行器 + 调度器）是否随实例启动。
	Tasks bool
	// Mounts 是实际挂载的协议/管理 API 站内路径（含部署前缀）。
	Mounts []string
}
