package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/appcore"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	"github.com/kagurazakayashi/EvernightLogin/internal/bootstrap"
	"github.com/kagurazakayashi/EvernightLogin/internal/mfa"
	"github.com/kagurazakayashi/EvernightLogin/internal/registration"
	"github.com/kagurazakayashi/EvernightLogin/internal/serverapp"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// Runtime 是嵌入式装配结果。它只持有自己打开的资源；不监听端口。
//
// Open 构造完成时状态为 login.StateNew，后台任务不会自行运行；宿主必须显式调用
// Start 才会启动任务执行器与定时计划调度器。Close 幂等，只关闭本运行时自己打开
// 的数据库与后台任务；宿主注入的 Logger/Database/Notifier 不被关闭。
type Runtime struct {
	opts       Options
	config     login.Config
	logger     *slog.Logger
	nowFn      func() time.Time
	base       *serverapp.Base
	instance   *login.Instance
	boot       *bootstrap.Service
	bootCaller bootstrap.Caller
	// resetLimiters 是找回密码公开入口的来源限流器（有界、进程内单实例）。
	resetLimiters *passwordResetLimiters
	handler       http.Handler
	httpPrefix    string
	httpMounts    []string
	mu            sync.Mutex
	closeErr      error
	closed        bool
}

// Open 构造真实服务运行时：配置/主密钥环/SQLite/迁移策略/审计/领域服务/敏感闸门/
// 后台任务运行时/管理域服务与公开实例，全部走与独立服务相同的共享装配
// （internal/serverapp.OpenBase），不复制第二套业务逻辑。
//
// 生命周期与安全边界：
//   - 不监听端口、不启动后台任务/调度器、不注册信号；任务只能由 Start 显式启动。
//   - Migrate=false 时未迁移库 fail-closed；CreateMasterKey=false 时缺失主密钥
//     fail-closed；不会自动生成隐式默认密钥。
//   - 构造失败时已打开的资源按相反顺序回滚关闭。
//   - 不提供跳过认证/伪造 root/关闭鉴权的入口；业务拒绝统一返回 *login.AppError。
func Open(ctx context.Context, opts Options) (*Runtime, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.OperatorID == "" {
		return nil, configError("OperatorID 必填（本地受信操作者标识）")
	}
	cfg, err := loadConfig(opts)
	if err != nil {
		return nil, err
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard,
			&slog.HandlerOptions{Level: slog.LevelError + 1}))
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	// 找回入口来源限流器：构造只依赖常量策略，失败说明策略常量非法（配置缺陷，
	// fail-closed，不放行无限流的公开入口）。
	resetLimiters, err := newPasswordResetLimiters(now)
	if err != nil {
		return nil, wrapInternal("构造找回密码限流器失败", err)
	}
	base, err := serverapp.OpenBase(ctx, serverapp.BaseOptions{
		Config:          cfg,
		MasterKeyFile:   opts.MasterKeyFile,
		CreateMasterKey: opts.CreateMasterKey,
		Migrate:         opts.Migrate,
		Logger:          logger,
		Now:             now,
	})
	if err != nil {
		if errors.Is(err, serverapp.ErrMigrationPending) {
			return nil, configError("数据库尚未迁移；请显式设置 Migrate=true 或先运行迁移")
		}
		// 诊断日志保留真实装配原因（宿主日志可定位配置/路径/权限问题）；
		// 返回给调用方的 AppError 仍不携带内部原因。
		logger.Error("打开嵌入式运行时失败", "error", err)
		return nil, wrapInternal("打开嵌入式运行时失败", err)
	}
	boot, bootCaller, err := serverapp.BuildBootstrapService(base.Deps, opts.OperatorID)
	if err != nil {
		_ = base.Close(context.Background())
		return nil, wrapInternal("构造首次初始化服务失败", err)
	}
	// HTTP/页面挂载（步骤 183）：与独立服务共用同一装配链；任何缺依赖/非法配置
	// 都在 Open 阶段失败，不会退化为“只有健康页”。
	var handler http.Handler
	var httpPrefix string
	var httpMounts []string
	if opts.HTTP != nil {
		var overrides *serverapp.PageOverrides
		if opts.HTTP.PageOverrides != nil {
			overrides = &serverapp.PageOverrides{
				HostTemplates:       opts.HTTP.PageOverrides.HostTemplates,
				HostRenderer:        opts.HTTP.PageOverrides.HostRenderer,
				Brand:               opts.HTTP.PageOverrides.Brand,
				AssetOverlays:       opts.HTTP.PageOverrides.AssetOverlays,
				Translations:        opts.HTTP.PageOverrides.Translations,
				DisableBuiltinPages: opts.HTTP.PageOverrides.DisableBuiltinPages,
			}
		}
		httpRuntime, httpErr := serverapp.BuildHTTPRuntime(base, serverapp.HTTPRuntimeOptions{
			Prefix:             opts.HTTP.Prefix,
			AccessLog:          opts.HTTP.AccessLog,
			EnableProtocol:     opts.HTTP.EnableProtocol,
			EnableAdminAPI:     opts.HTTP.EnableAdminAPI,
			AdminAPIPrefix:     opts.HTTP.AdminAPIPrefix,
			EnableManagedAPI:   opts.HTTP.EnableManagedAPI,
			ManagedAPIPrefix:   opts.HTTP.ManagedAPIPrefix,
			EnableAppSupport:   opts.HTTP.EnableAppSupport,
			AppSupportPrefix:   opts.HTTP.AppSupportPrefix,
			AppSupportAudience: opts.HTTP.AppSupportAudience,
			Logger:             logger,
			PageOverrides:      overrides,
		})
		if httpErr != nil {
			_ = base.Close(context.Background())
			return nil, wrapInternal("装配嵌入式 HTTP 与页面失败", httpErr)
		}
		handler = httpRuntime.Handler
		httpPrefix = httpRuntime.Prefix
		httpMounts = httpRuntime.Mounts
	}
	// 后台任务运行时作为实例组件登记：只有显式 Start 才会启动，Close 时由实例
	// 逆序停止；宿主注入的 Database/Notifier 只被使用、不被关闭。
	components := make([]login.BackgroundComponent, 0, 1)
	if base.Tasks != nil {
		components = append(components, base.Tasks)
	}
	instance, err := login.New(login.Options{
		Config:        &cfg,
		Logger:        logger,
		Database:      opts.Database,
		Notifications: opts.Notifier,
		Components:    components,
	})
	if err != nil {
		_ = base.Close(context.Background())
		return nil, wrapInternal("构造实例失败", err)
	}
	return &Runtime{opts: opts, config: cfg, logger: logger, nowFn: now,
		base: base, instance: instance, boot: boot, bootCaller: bootCaller,
		resetLimiters: resetLimiters,
		handler:       handler, httpPrefix: httpPrefix, httpMounts: httpMounts}, nil
}

// loadConfig 加载/规范化配置。配置规则与独立服务共用 internal/appcore：只支持
// SQLite 驱动、数据库路径绝对化、覆盖后整体校验。
func loadConfig(opts Options) (login.Config, error) {
	switch {
	case opts.Config != nil:
		cfg, err := appcore.PrepareConfig(*opts.Config, opts.DatabasePath)
		if err != nil {
			return login.Config{}, configError("配置校验失败")
		}
		return cfg, nil
	case opts.ConfigPath != "":
		cfg, err := appcore.LoadConfigFile(opts.ConfigPath, opts.DatabasePath)
		if err != nil {
			return login.Config{}, wrapInternal("加载配置失败", err)
		}
		return cfg, nil
	default:
		return login.Config{}, configError("Config 或 ConfigPath 必须提供")
	}
}

// Instance 返回构造完成但未启动的实例（Open 后 State=StateNew）。
func (r *Runtime) Instance() *login.Instance {
	if r == nil {
		return nil
	}
	return r.instance
}

// Config 返回运行配置快照。
func (r *Runtime) Config() login.Config {
	if r == nil {
		return login.Config{}
	}
	return r.config
}

// State 返回显式生命周期状态：new（已构造未启动）/running（任务已启动）/closed。
func (r *Runtime) State() login.State {
	if r == nil || r.instance == nil {
		return login.StateClosed
	}
	return r.instance.State()
}

// Start 显式启动允许的后台任务（任务执行器与定时计划调度器）。
//
// Open 不启动任何后台任务；宿主决定何时启动。语义与 login.Instance 一致：
// 重复 Start 返回 login.ErrAlreadyStarted；关闭后返回 login.ErrClosed；
// ctx 在启动前结束或启动失败时实例进入 StateClosed 并回滚已启动任务（fail-closed），
// 之后只能 Close。
func (r *Runtime) Start(ctx context.Context) error {
	if r == nil || r.instance == nil {
		return configError("运行时未装配")
	}
	return r.instance.Start(ctx)
}

// Ready 检查运行时是否可以对外服务：必须已成功 Start；宿主注入的 Database 必须
// Ping 成功。未启动返回 login.ErrNotRunning，数据库失败返回 DB_UNAVAILABLE。
func (r *Runtime) Ready(ctx context.Context) error {
	if r == nil || r.instance == nil {
		return login.ErrNotRunning
	}
	return r.instance.Ready(ctx)
}

// Handler 返回与独立服务共用安全链的 HTTP 处理器；未配置 Options.HTTP 时为 nil。
// 宿主负责自己的监听与 http.Server 生命周期；处理器可在 Start 之前挂载。
func (r *Runtime) Handler() http.Handler {
	if r == nil {
		return nil
	}
	return r.handler
}

// HTTPPrefix 返回 HTTP 处理器的规范化站内前缀（根路径为空字符串）。
func (r *Runtime) HTTPPrefix() string {
	if r == nil {
		return ""
	}
	return r.httpPrefix
}

// HTTPMounts 返回已挂载的协议/管理 API 站内路径（含前缀，供诊断/测试）。
func (r *Runtime) HTTPMounts() []string {
	if r == nil {
		return nil
	}
	return append([]string(nil), r.httpMounts...)
}

// Mount 把已装配的 HTTP 处理器挂到宿主 *http.ServeMux 上：按固定前缀注册子树
// （根路径注册 "/"）。未配置 HTTP、mux 为 nil 或 pattern 冲突时返回 CONFIG_INVALID，
// 不向宿主抛 panic。宿主也可以直接使用 Handler() 自行挂载，但必须使用 HTTPPrefix。
func (r *Runtime) Mount(mux *http.ServeMux) (err error) {
	if mux == nil {
		return login.NewAppError(login.CodeConfigInvalid, "挂载 HTTP 处理器需要宿主 mux",
			login.WithRequestID(login.NewRequestID()))
	}
	if r == nil || r.handler == nil {
		return login.NewAppError(login.CodeConfigInvalid, "运行时未配置 HTTP 处理器",
			login.WithRequestID(login.NewRequestID()))
	}
	pattern := "/"
	if r.httpPrefix != "" {
		pattern = r.httpPrefix + "/"
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			err = login.NewAppError(login.CodeConfigInvalid, "挂载 HTTP 处理器失败",
				login.WithCause(fmt.Errorf("宿主 mux 拒绝注册模式 %q: %v", pattern, recovered)),
				login.WithRequestID(login.NewRequestID()))
		}
	}()
	mux.Handle(pattern, r.handler)
	return nil
}

// Close 幂等关闭本 Runtime 打开的资源（实例后台任务、任务运行时、数据库）；
// 不关闭宿主注入的 Logger/Database/Notifier，也不停止宿主自己的 HTTP 服务。
func (r *Runtime) Close(ctx context.Context) error {
	if r == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	r.mu.Lock()
	if r.closed {
		err := r.closeErr
		r.mu.Unlock()
		return err
	}
	r.closed = true
	r.mu.Unlock()
	var failures []error
	if r.instance != nil {
		if err := r.instance.Close(ctx); err != nil {
			failures = append(failures, err)
		}
	}
	if r.base != nil {
		if err := r.base.Close(ctx); err != nil {
			failures = append(failures, err)
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(failures) > 0 {
		r.closeErr = errors.Join(failures...)
	}
	return r.closeErr
}

// Bootstrap 返回首次初始化门面。
func (r *Runtime) Bootstrap() BootstrapService { return &bootstrapFacade{r: r} }

// Users 返回用户门面。
func (r *Runtime) Users() UserService { return &userFacade{r: r} }

// Auth 返回登录门面。
func (r *Runtime) Auth() AuthService { return &authFacade{r: r} }

// Access 返回权限检查门面。
func (r *Runtime) Access() AccessService { return &accessFacade{r: r} }

// Sessions 返回会话撤销门面。
func (r *Runtime) Sessions() SessionService { return &sessionFacade{r: r} }

// Security 返回认证/安全设置门面（TOTP 绑定、恢复代码、能力状态）。
func (r *Runtime) Security() SecurityService { return &securityFacade{r: r} }

// MFA 返回认证因素管理门面（步骤 222）：脱敏因素清单、邮件因素启用/移除、Passkey
// 注册/列表/重命名/撤销与免密码登录、TOTP 绑定撤销、恢复代码概览。所有敏感操作
// 仍由领域服务重新判定会话完整性与近期认证，本门面不发放“已通过 MFA”标记。
func (r *Runtime) MFA() MFAService { return &mfaPublicFacade{r: r} }

// PasswordReset 返回找回密码门面（邮件 token 发起/校验/完成）。
func (r *Runtime) PasswordReset() PasswordResetService { return &passwordResetFacade{r: r} }

// Admin 返回受信管理门面；调用者必须先由 Runtime.LocalAdmin() 或
// Runtime.AdminSession() 建立可信上下文，普通请求参数不能自称管理员。
func (r *Runtime) Admin() AdminService { return &adminFacade{r: r} }

type bootstrapFacade struct{ r *Runtime }

// EnsureRoot 复刻 login-server init 的受限初始化核心：只允许未初始化库，
// 创建 root 并设置正式密码，不签会话、不返回秘密；重复调用拒绝。
func (f *bootstrapFacade) EnsureRoot(ctx context.Context, req RootRequest) (RootResult, error) {
	r := f.r
	if r == nil || r.boot == nil || r.coreServices() == nil {
		return RootResult{}, configError("首次初始化服务未装配")
	}
	status, err := r.boot.Status(ctx, r.bootCaller)
	if err != nil {
		return RootResult{}, wrapInternal("读取首次初始化状态失败", err)
	}
	if status.State != bootstrap.StateUninitialized {
		return RootResult{}, configError("实例已初始化或存在 root，拒绝重复初始化")
	}
	initializeResult, err := r.boot.Initialize(ctx, r.bootCaller, bootstrap.InitializeRequest{
		RootNickname: req.DisplayName, SetupCredentialTTL: 5 * time.Minute,
	})
	if err != nil {
		return RootResult{}, wrapInternal("创建 root 失败", err)
	}
	grant, err := r.boot.RedeemSetupCredential(ctx, r.bootCaller, bootstrap.RedeemSetupCredentialRequest{
		CredentialID: initializeResult.SetupCredential.ID,
		Secret:       initializeResult.SetupCredential.Secret.Reveal(),
	})
	if err != nil {
		return RootResult{}, wrapInternal("兑换初始化凭证失败", err)
	}
	adminCaller, err := authn.LocalAdminCaller(r.opts.OperatorID)
	if err != nil {
		return RootResult{}, wrapInternal("构造本地初始化操作者失败", err)
	}
	requestID := req.RequestID
	if requestID == "" {
		requestID = login.NewRequestID()
	}
	passwordResult, err := r.coreServices().Authn.SetRootPassword(ctx, adminCaller,
		authn.SetRootPasswordRequest{
			RootUserID: grant.RootUserID, NewPassword: req.Password, RequestID: requestID,
		})
	if err != nil {
		return RootResult{}, wrapInternal("写入 root 正式密码失败", err)
	}
	return RootResult{UserID: passwordResult.RootUserID, State: string(passwordResult.State),
		StrongAuthRequired: passwordResult.StrongAuthRequired,
		SecurityVersion:    passwordResult.SecurityVersion}, nil
}

// coreServices 返回共享装配的核心领域服务；运行时未装配或已进入维护模式时 nil。
func (r *Runtime) coreServices() *serverapp.Services {
	if r == nil || r.base == nil {
		return nil
	}
	return r.base.Services
}

// managedServices 返回共享装配的管理域服务；未装配时 nil。
func (r *Runtime) managedServices() *serverapp.ManagedServices {
	if r == nil || r.base == nil {
		return nil
	}
	return r.base.Managed
}

// securityDomains 返回共享装配的认证/安全域服务；未装配时 nil。
func (r *Runtime) securityDomains() *serverapp.SecurityDomains {
	if r == nil || r.base == nil {
		return nil
	}
	return r.base.Security
}

// securityGate 返回共享装配的敏感操作闸门；未装配时 nil。
func (r *Runtime) securityGate() *serverapp.SecurityGate {
	if r == nil || r.base == nil {
		return nil
	}
	return r.base.Gate
}

// mfaService 返回共享装配的 MFA 状态机服务；未装配时 nil。
func (r *Runtime) mfaService() *mfa.Service {
	security := r.securityDomains()
	if security == nil {
		return nil
	}
	return security.MFA
}

type userFacade struct{ r *Runtime }

// Create 通过真实注册流程创建带密码账户（需要注册开关开启）。Phase A 不使用
// 测试替身或直接写库；受信管理员创建（含敏感审批）在后续管理步骤提供。
func (f *userFacade) Create(ctx context.Context, req CreateUserRequest) (User, error) {
	r := f.r
	services := r.coreServices()
	if services == nil {
		return User{}, configError("服务未装配")
	}
	if !r.config.Registration.Enabled {
		return User{}, configError("创建用户需要启用 registration.enabled")
	}
	result, err := services.Registration.Register(ctx, registration.RegisterRequest{
		Username: req.Username, Password: req.Password, Email: req.Email,
		Nickname: req.Nickname, Language: req.Language, Timezone: req.Timezone,
		RequestID: req.RequestID,
	})
	if err != nil {
		return User{}, mapServiceError(err)
	}
	return User{ID: result.UserID, Username: result.Username, Nickname: req.Nickname,
		Email: result.Email, Status: string(result.Status), CreatedAt: result.CreatedAt}, nil
}

type accessFacade struct{ r *Runtime }

// Check 是“受信调用者已经确认用户身份”后的权限检查入口：UserID 必须来自已校验
// 的会话/令牌或宿主可信身份，绝不能来自客户端自填字段。它只做权限判定，不验证
// 会话；需要“会话有效 + 属于当前应用 + 所需权限”的联合判断时使用
// Sessions.Authorize。RequestID 用于关联审计与返回错误。
func (f *accessFacade) Check(ctx context.Context, req AccessRequest) (AccessDecision, error) {
	r := f.r
	requestID, err := resolveRequestID(ctx, req.RequestID)
	if err != nil {
		return AccessDecision{}, err
	}
	managed := r.managedServices()
	if managed == nil || managed.Authz == nil {
		return AccessDecision{}, configError("权限服务未装配", requestID)
	}
	caller, err := authz.UserCaller(req.UserID)
	if err != nil {
		return AccessDecision{}, mapDomainError("访问检查的主体无效", "REQ_INVALID", requestID)
	}
	if caller, err = bindCaller(caller, requestID); err != nil {
		return AccessDecision{}, err
	}
	mode := authz.Mode(req.Mode)
	if mode == "" {
		mode = authz.ModeAll
	}
	scope := "system"
	if req.AppID != "" {
		scope = req.AppID
	}
	result, err := managed.Authz.Check(ctx, caller, authz.CheckRequest{
		SubjectUserID: req.UserID, ScopeID: scope, Permissions: []string{req.Permission}, Mode: mode,
	})
	if err != nil {
		return AccessDecision{}, mapDomainError("权限检查失败",
			string(authz.CodeOf(err)), requestID)
	}
	return AccessDecision{Allowed: result.Allowed, Code: string(result.Code),
		Reason: result.Reason, RequestID: requestID, Application: req.AppID}, nil
}

type sessionFacade struct{ r *Runtime }

// Revoke 撤销当前会话（含该会话的刷新/派生状态），不撤销其他会话。会话秘密必须
// 来自可信边界；失败按会话领域稳定码返回并带本次请求编号。
func (f *sessionFacade) Revoke(ctx context.Context, sessionSecret []byte) error {
	requestID, err := resolveRequestID(ctx, "")
	if err != nil {
		return err
	}
	services := f.r.coreServices()
	if services == nil {
		return configError("服务未装配", requestID)
	}
	if len(sessionSecret) == 0 {
		return login.NewAppError(login.CodeAuthFailed, "会话无效或已失效",
			login.WithRequestID(requestID))
	}
	if _, err := services.Sessions.RevokeAllOwnSessions(ctx, string(sessionSecret), false); err != nil {
		return mapDomainError("撤销会话失败", string(session.CodeOf(err)), requestID)
	}
	return nil
}
