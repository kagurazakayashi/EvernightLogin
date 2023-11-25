package serverapp

// 基础运行时装配：独立服务（cmd/login-server -> RunServe）与公开嵌入入口
// （app.Open）共用的唯一装配路径。
//
// 分层边界：
//   - internal/appcore 负责配置/密钥/数据库/迁移/审计等基础设施（两种运行方式
//     共用同一实现）；
//   - 本文件负责在基础设施之上构造真实领域服务、敏感操作闸门、后台任务运行时与
//     管理域服务，并把这些资源的所有权收敛到 *Base；
//   - 独立服务额外的单实例锁、库外维护状态、HTTP 监听与页面挂载仍留在
//     serverapp/host.go；嵌入模式的安全域/协议/页面/HTTP 由后续步骤在 *Base 上
//     继续装配，不复制第二套业务逻辑。
//
// 生命周期约定：
//   - OpenBase 只构造对象：不监听端口、不创建协程、不启动任务调度；后台任务
//     运行时只有被显式 Start（独立服务由 login.Instance 组件管理，嵌入模式由
//     app.Runtime.Start）后才会运行。
//   - Close 幂等，只关闭本运行时自己打开的数据库与后台任务；调用方注入的
//     日志器、时钟、密钥环材料等宿主资源不被关闭。
//   - 构造失败时已创建的资源按相反顺序回滚关闭，不遗留数据库句柄或后台协程。

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	appsqlite "github.com/kagurazakayashi/EvernightLogin/internal/app/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

// ErrMigrationPending 表示数据库存在尚未应用的迁移，且调用方没有允许自动迁移。
// 公开入口据此返回稳定的 CONFIG_INVALID 错误，而不是把内部细节暴露给宿主。
var ErrMigrationPending = errors.New("数据库尚未完成迁移")

// ErrUninitialized 表示数据库尚未完成首次初始化（没有 root）。独立服务默认拒绝
// 启动；嵌入模式允许先 Open 再调用首次初始化门面，因此不启用该检查。
var ErrUninitialized = errors.New("数据库尚未完成首次初始化")

// BaseOptions 是独立服务与公开 app 入口共用的基础装配参数。
type BaseOptions struct {
	// Config 是已通过最终校验的配置（数据库路径覆盖已应用）。
	Config login.Config
	// ConfigPath 是加载配置时使用的 YAML 文件路径（可选）；只用于诊断的待重启
	// 字段比较，不用于重新读取秘密或修改运行配置。
	ConfigPath string
	// Keyring 是调用方已加载的主密钥环；nil 时由 OpenBase 按 MasterKeyFile/
	// CreateMasterKey 加载（独立服务在打开库外维护状态前需要先用密钥环，因此
	// 允许由调用方注入，避免重复读取密钥材料）。
	Keyring *secrets.Keyring
	// MasterKeyFile 是主密钥环文件路径；Config.Secrets.MasterKey 优先。
	MasterKeyFile string
	// CreateMasterKey 允许在文件不存在时生成新的受保护主密钥环（仅首次初始化）。
	CreateMasterKey bool
	// Migrate 为 true 时执行未应用的迁移；false 时迁移未完成即 fail-closed。
	Migrate bool
	// WriteGuard 是可选的存储写门闸（独立服务的库外维护状态用它拒绝写事务）。
	WriteGuard func(context.Context) (func(), error)
	// Logger 非 nil 时直接使用（由调用方拥有，不会被关闭）；nil 时按配置创建
	// 一个丢弃输出的静默日志器（嵌入模式默认不污染宿主输出）。
	Logger *slog.Logger
	// Now 是可注入时钟；nil 使用 time.Now。
	Now func() time.Time
	// RequireInitialized 为 true 时要求数据库已完成首次初始化（独立服务默认策略）；
	// 未初始化时构造返回 ErrUninitialized。嵌入模式保持 false，允许先 Open 再由
	// 宿主调用首次初始化门面。
	RequireInitialized bool
	// AllowLegacyWithoutSensitive 是会话服务的过渡开关，见 Deps 同名字段。
	AllowLegacyWithoutSensitive bool
	// MaintenanceOnly 为 true 时只装配密钥/数据库/迁移/审计/邮件运行时，不构造
	// 领域服务、敏感闸门、管理系统与后台任务（独立服务的维护模式不对外提供业务）。
	MaintenanceOnly bool
}

// Base 是两种运行方式共用的基础装配结果。它只持有自己创建的资源；宿主注入的
// 日志器/时钟等不被关闭，也不监听端口或启动后台任务。
type Base struct {
	Options BaseOptions
	Config  login.Config
	Logger  *slog.Logger
	Now     func() time.Time
	Keyring *secrets.Keyring
	Store   *sqlite.Store
	Audit   *audit.Recorder
	Mail    *MailRuntime
	// Uninitialized 表示构造时数据库还没有首次初始化记录（仅非维护模式有效）。
	Uninitialized bool
	// Deps 是领域服务装配使用的显式依赖快照；MaintenanceOnly 时为零值。
	Deps Deps
	// 以下字段仅在非 MaintenanceOnly 时非 nil。
	Services *Services
	Gate     *SecurityGate
	Tasks    *TaskRuntime
	Managed  *ManagedServices
	// Security 是认证/安全域真实服务集合（TOTP/Passkey/MFA/恢复代码/找回/客服等）。
	Security *SecurityDomains
	// Protocol 是 OAuth/OIDC 协议域真实服务集合（配置启用时构造；供 HTTP 装配与
	// 嵌入式宿主公开 Go 查询入口共用同一实例，避免重复构造/重复密钥引导）。
	Protocol *ProtocolDomains

	mu       sync.Mutex
	closed   bool
	closeErr error
}

// resourceCloser 按相反顺序回滚关闭构造中途创建的资源。
type resourceCloser struct {
	items []func() error
}

// push 登记一个关闭函数；只在整体构造失败时执行。
func (c *resourceCloser) push(closeFn func() error) {
	if closeFn != nil {
		c.items = append(c.items, closeFn)
	}
}

// closeAll 逆序执行全部关闭函数并聚合错误。
func (c *resourceCloser) closeAll() error {
	var failures []error
	for index := len(c.items) - 1; index >= 0; index-- {
		if err := c.items[index](); err != nil {
			failures = append(failures, err)
		}
	}
	c.items = nil
	return errors.Join(failures...)
}

// OpenBase 构造基础运行时：密钥环（可选注入）-> 数据库 -> 迁移策略 -> 审计 ->
// 邮件运行时 -> 核心领域服务 -> 初始化检查（可选）-> 敏感闸门 -> 后台任务运行时 ->
// 管理域服务 -> 认证/安全域（TOTP/Passkey/MFA/恢复/客服）-> 任务处理器注册与调度器
// 绑定。
//
// 安全依赖（敏感操作闸门、强因素存在性）由本函数内的延迟 relay 注入，两种运行
// 方式因此共享同一套认证/安全装配；未注入真实实现前相关操作 fail-closed。
// 构造阶段不监听端口、不创建协程、不启动任务调度；任何一步失败都会回滚关闭
// 已创建的资源。MaintenanceOnly 时构造止于邮件运行时。
func OpenBase(ctx context.Context, options BaseOptions) (base *Base, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	cfg := options.Config
	logger := options.Logger
	if logger == nil {
		logger, err = newLogger(cfg, io.Discard)
		if err != nil {
			return nil, err
		}
	}
	closer := &resourceCloser{}
	defer func() {
		if err != nil {
			// 回滚错误不覆盖原始失败原因，但一并返回便于诊断资源泄漏。
			err = errors.Join(err, closer.closeAll())
			base = nil
		}
	}()

	keyring := options.Keyring
	if keyring == nil {
		keyring, _, err = LoadKeyring(ctx, cfg, options.MasterKeyFile,
			options.CreateMasterKey, now)
		if err != nil {
			return nil, fmt.Errorf("加载主密钥环失败: %w", err)
		}
	}
	if keyring == nil {
		return nil, fmt.Errorf("加载主密钥环失败: 主密钥环为空")
	}
	store, err := OpenStore(ctx, cfg, options.WriteGuard)
	if err != nil {
		return nil, fmt.Errorf("打开数据库失败: %w", err)
	}
	closer.push(store.Close)
	pending, err := CheckMigrated(ctx, store)
	if err != nil {
		return nil, fmt.Errorf("检查数据库迁移失败: %w", err)
	}
	if options.Migrate {
		applied, migrateErr := ApplyMigrations(ctx, store)
		if migrateErr != nil {
			return nil, fmt.Errorf("执行数据库迁移失败: %w", migrateErr)
		}
		logger.Info("数据库迁移已应用", "applied_count", applied)
	} else if len(pending) > 0 {
		return nil, fmt.Errorf("%w：%d 个版本待应用（首个 %s）；"+
			"请显式允许迁移或先运行迁移工具", ErrMigrationPending, len(pending), pending[0])
	}
	auditRecorder, err := NewAuditRecorder(ctx, store, logger, now)
	if err != nil {
		return nil, fmt.Errorf("构造安全审计失败: %w", err)
	}
	mailRuntime, err := BuildMailRuntime(cfg)
	if err != nil {
		return nil, fmt.Errorf("邮件运行时启动失败: %w", err)
	}
	if cfg.Mail.Enabled {
		if _, urlErr := buildMailURLs(cfg); urlErr != nil {
			return nil, urlErr
		}
	}
	base = &Base{Options: options, Config: cfg, Logger: logger, Now: now,
		Keyring: keyring, Store: store, Audit: auditRecorder, Mail: mailRuntime}
	if options.MaintenanceOnly {
		return base, nil
	}

	// 延迟投递提供器：任务运行时构造完成后才对域服务可见，避免循环依赖。
	var taskRuntime *TaskRuntime
	deps := Deps{Config: cfg, ConfigPath: options.ConfigPath, Store: store, Keyring: keyring, Mail: mailRuntime,
		MailDeliveryProvider: func() *mailer.DeliveryService {
			if taskRuntime == nil {
				return nil
			}
			return taskRuntime.Mail()
		},
		Audit: auditRecorder, Logger: logger, Now: now,
		AllowLegacyWithoutSensitive: options.AllowLegacyWithoutSensitive}
	// 安全依赖以延迟 relay 装配：核心服务先构造、敏感闸门稍后建立，两者通过同一
	// relay 在请求期生效；未注入真实实现前相关操作仍 fail-closed。
	sensitiveRelay := &sensitiveRelay{}
	strongPresenceRelay := &strongFactorRelay{}
	services, err := BuildServicesWithHooks(deps, SecurityHooks{
		Sensitive: sensitiveRelay, StrongPresence: strongPresenceRelay})
	if err != nil {
		return nil, fmt.Errorf("构造核心服务失败: %w", err)
	}
	uninitialized, err := IsUninitialized(ctx, services)
	if err != nil {
		return nil, fmt.Errorf("读取首次初始化状态失败: %w", err)
	}
	base.Uninitialized = uninitialized
	if uninitialized && options.RequireInitialized {
		return nil, ErrUninitialized
	}
	gate, err := BuildSecurityGate(deps, services.BootstrapStore, services.Authn,
		cfg.Passkey.Enabled)
	if err != nil {
		return nil, fmt.Errorf("构造安全闸门失败: %w", err)
	}
	sensitiveRelay.Set(gate.Reauth)
	taskRuntime, err = NewTaskRuntime(deps, gate)
	if err != nil {
		return nil, fmt.Errorf("构造任务运行时失败: %w", err)
	}
	closer.push(func() error { return taskRuntime.Close(context.Background()) })
	managed, err := BuildManagedServices(deps, services, taskRuntime, gate)
	if err != nil {
		return nil, fmt.Errorf("构造管理域服务失败: %w", err)
	}
	// 会话服务先于权限引擎构造：管理强制下线的真实授权器在这里原子注入，
	// 注入前相关管理动作 fail-closed。
	if services.SessionAuthorizer != nil {
		sessionScopeAuthorizer, authzErr := session.NewAuthzAuthorizer(managed.Checker)
		if authzErr != nil {
			return nil, fmt.Errorf("装配管理强制下线授权器失败: %w", authzErr)
		}
		services.SessionAuthorizer.Set(sessionScopeAuthorizer)
	}
	// 应用范围候选枚举（步骤 184）：应用管理员在应用内管理成员/角色前需要按应用
	// 范围判定可管理范围。两种运行方式在这里共用同一 SQLite 候选实现（页面装配
	// 不再重复注入），缺少时权限层保持 fail-closed 而不是猜测范围。
	if managed.Checker != nil {
		appScopeStore, scopeErr := appsqlite.New(deps.Store)
		if scopeErr != nil {
			return nil, fmt.Errorf("构造应用范围枚举存储失败: %w", scopeErr)
		}
		managed.Checker.SetApplicationScopeLister(appScopeStore)
	}
	// 认证/安全域（TOTP/Passkey/MFA/恢复代码/找回/客服/人工恢复）与独立服务共用
	// 同一装配；它同时把恢复服务接到会话服务的受限恢复会话闸门。
	securityDomains, err := BuildSecurityDomains(deps, services, managed, gate)
	if err != nil {
		return nil, err
	}
	strongPresenceRelay.Set(securityDomains.StrongFactors)
	managed.Support = securityDomains.Support
	// 协议域在配置启用时提前构造：HTTP 装配与嵌入式宿主公开 Go 查询入口复用同一
	// 真实令牌/授权流程服务；构造失败拒绝启动（fail-closed），不发布半可用协议。
	if cfg.Protocol.Enabled {
		protocolDomains, protocolErr := BuildProtocolDomains(deps, services, managed, gate)
		if protocolErr != nil {
			return nil, fmt.Errorf("构造协议域失败: %w", protocolErr)
		}
		base.Protocol = protocolDomains
	}
	// 任务处理器注册：缺少必需处理器时构造失败，不留下“能启动但不会执行”的
	// 半配置运行时。
	if err := taskRuntime.Complete(managed.TaskHandlers()); err != nil {
		return nil, err
	}
	// 报告计划服务在构造时拿不到调度器，注册完成后绑定延迟 relay。
	managed.AttachScheduler(taskRuntime.Scheduler())
	base.Deps = deps
	base.Services = services
	base.Gate = gate
	base.Tasks = taskRuntime
	base.Managed = managed
	base.Security = securityDomains
	return base, nil
}

// Close 幂等关闭本运行时创建的后台任务运行时与数据库连接；不关闭宿主资源
// （日志器、时钟、注入的密钥环材料）也不停止任何宿主自建的 HTTP 服务。
//
// 即使调用方已在 login.Instance 关闭过任务运行时，这里再次关闭仍安全（任务
// 执行器/调度器的 Stop 可重复调用）；所有关闭错误聚合返回，但仍继续释放后续资源。
func (b *Base) Close(ctx context.Context) error {
	if b == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	b.mu.Lock()
	if b.closed {
		err := b.closeErr
		b.mu.Unlock()
		return err
	}
	b.closed = true
	b.mu.Unlock()
	var failures []error
	if b.Tasks != nil {
		if err := b.Tasks.Close(ctx); err != nil {
			failures = append(failures, fmt.Errorf("关闭后台任务运行时失败: %w", err))
		}
	}
	if b.Store != nil {
		if err := b.Store.Close(); err != nil {
			failures = append(failures, fmt.Errorf("关闭数据库失败: %w", err))
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(failures) > 0 {
		b.closeErr = errors.Join(failures...)
	}
	return b.closeErr
}
