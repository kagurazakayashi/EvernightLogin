package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/appcore"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	"github.com/kagurazakayashi/EvernightLogin/internal/bootstrap"
	"github.com/kagurazakayashi/EvernightLogin/internal/registration"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/serverapp"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

// Runtime 是嵌入式装配结果。它只持有自己打开的资源；不监听端口、不启动后台任务。
type Runtime struct {
	opts       Options
	config     login.Config
	logger     *slog.Logger
	nowFn      func() time.Time
	store      *sqlite.Store
	keyring    *secrets.Keyring
	audit      *audit.Recorder
	services   *serverapp.Services
	managed    *serverapp.ManagedServices
	tasks      *serverapp.TaskRuntime
	instance   *login.Instance
	boot       *bootstrap.Service
	bootCaller bootstrap.Caller
	mu         sync.Mutex
	closeErr   error
	closed     bool
}

// Open 打开数据库/密钥环并构造真实服务；不监听、不启动任务。
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
		logger = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	keyring, _, err := appcore.LoadKeyring(ctx, cfg, opts.MasterKeyFile, opts.CreateMasterKey, now)
	if err != nil {
		return nil, wrapInternal("加载主密钥环失败", err)
	}
	store, err := appcore.OpenStore(ctx, cfg, nil)
	if err != nil {
		return nil, wrapInternal("打开数据库失败", err)
	}
	cleanup := func() { _ = store.Close() }
	pending, err := appcore.CheckMigrated(ctx, store)
	if err != nil {
		cleanup()
		return nil, wrapInternal("检查数据库迁移失败", err)
	}
	if opts.Migrate {
		if _, err := appcore.ApplyMigrations(ctx, store); err != nil {
			cleanup()
			return nil, wrapInternal("执行数据库迁移失败", err)
		}
	} else if len(pending) > 0 {
		cleanup()
		return nil, configError("数据库尚未迁移；请显式设置 Migrate=true 或先运行迁移")
	}
	auditRecorder, err := appcore.NewAuditRecorder(ctx, store, logger, now)
	if err != nil {
		cleanup()
		return nil, wrapInternal("构造安全审计失败", err)
	}
	deps := serverapp.Deps{Config: cfg, Store: store, Keyring: keyring, Audit: auditRecorder, Logger: logger, Now: now}
	services, err := serverapp.BuildServices(deps)
	if err != nil {
		cleanup()
		return nil, wrapInternal("构造核心服务失败", err)
	}
	gate, err := serverapp.BuildSecurityGate(deps, services.BootstrapStore, services.Authn, cfg.Passkey.Enabled)
	if err != nil {
		cleanup()
		return nil, wrapInternal("构造安全闸门失败", err)
	}
	tasks, err := serverapp.NewTaskRuntime(deps, gate)
	if err != nil {
		cleanup()
		return nil, wrapInternal("构造任务运行时失败", err)
	}
	managed, err := serverapp.BuildManagedServices(deps, services, tasks, gate)
	if err != nil {
		_ = tasks.Close(context.Background())
		cleanup()
		return nil, wrapInternal("构造管理域服务失败", err)
	}
	instance, err := login.New(login.Options{Config: &cfg, Logger: logger})
	if err != nil {
		_ = tasks.Close(context.Background())
		cleanup()
		return nil, wrapInternal("构造实例失败", err)
	}
	boot, bootCaller, err := serverapp.BuildBootstrapService(deps, opts.OperatorID)
	if err != nil {
		_ = tasks.Close(context.Background())
		cleanup()
		return nil, wrapInternal("构造首次初始化服务失败", err)
	}
	return &Runtime{opts: opts, config: cfg, logger: logger, nowFn: now, store: store,
		keyring: keyring, audit: auditRecorder, services: services, managed: managed,
		tasks: tasks, instance: instance, boot: boot, bootCaller: bootCaller}, nil
}

func loadConfig(opts Options) (login.Config, error) {
	var cfg login.Config
	switch {
	case opts.Config != nil:
		cfg = *opts.Config
	case opts.ConfigPath != "":
		loaded, err := login.Load(login.LoadOptions{YAMLFile: opts.ConfigPath})
		if err != nil {
			return login.Config{}, wrapInternal("加载配置失败", err)
		}
		cfg = loaded
	default:
		return login.Config{}, configError("Config 或 ConfigPath 必须提供")
	}
	if opts.DatabasePath != "" {
		cfg.Database.Path = opts.DatabasePath
	}
	if err := cfg.Validate(); err != nil {
		return login.Config{}, configError("配置校验失败")
	}
	return cfg, nil
}

// Instance 返回构造完成但未启动的实例（State=StateNew）。
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

// Close 幂等关闭本 Runtime 打开的资源（实例/任务运行时/数据库）；不关闭宿主资源。
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
	if r.tasks != nil {
		if err := r.tasks.Close(ctx); err != nil {
			failures = append(failures, err)
		}
	}
	if r.store != nil {
		if err := r.store.Close(); err != nil {
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

// Admin 返回管理门面（Phase A 明确未实现角色分配）。
func (r *Runtime) Admin() AdminService { return &adminFacade{} }

type bootstrapFacade struct{ r *Runtime }

// EnsureRoot 复刻 login-server init 的受限初始化核心：只允许未初始化库，
// 创建 root 并设置正式密码，不签会话、不返回秘密；重复调用拒绝。
func (f *bootstrapFacade) EnsureRoot(ctx context.Context, req RootRequest) (RootResult, error) {
	r := f.r
	if r == nil || r.boot == nil {
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
	passwordResult, err := r.services.Authn.SetRootPassword(ctx, adminCaller, authn.SetRootPasswordRequest{
		RootUserID: grant.RootUserID, NewPassword: req.Password, RequestID: requestID,
	})
	if err != nil {
		return RootResult{}, wrapInternal("写入 root 正式密码失败", err)
	}
	return RootResult{UserID: passwordResult.RootUserID, State: string(passwordResult.State),
		StrongAuthRequired: passwordResult.StrongAuthRequired,
		SecurityVersion:    passwordResult.SecurityVersion}, nil
}

type userFacade struct{ r *Runtime }

// Create 通过真实注册流程创建带密码账户（需要注册开关开启）。Phase A 不使用
// 测试替身或直接写库；受信管理员创建（含敏感审批）在后续管理步骤提供。
func (f *userFacade) Create(ctx context.Context, req CreateUserRequest) (User, error) {
	r := f.r
	if r == nil || r.services == nil {
		return User{}, configError("服务未装配")
	}
	if !r.config.Registration.Enabled {
		return User{}, configError("创建用户需要启用 registration.enabled")
	}
	result, err := r.services.Registration.Register(ctx, registration.RegisterRequest{
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

type authFacade struct{ r *Runtime }

func (f *authFacade) Login(ctx context.Context, req LoginRequest) (LoginResult, error) {
	r := f.r
	if r == nil || r.services == nil {
		return LoginResult{}, configError("服务未装配")
	}
	authResult, err := r.services.Authn.Authenticate(ctx, authn.AuthenticateRequest{
		Identifier: req.Username, Password: req.Password, ClientIP: req.ClientIP,
		RequestID: req.RequestID,
	})
	if err != nil {
		return LoginResult{}, mapAuthError(err)
	}
	issued, err := r.services.Sessions.Login(ctx, session.LoginRequest{
		Result: authResult, AppID: req.AppID, RequestID: req.RequestID,
	})
	if err != nil {
		return LoginResult{}, mapServiceError(err)
	}
	result := LoginResult{UserID: issued.Session.UserID, SessionID: issued.Session.ID,
		ExpiresAt: issued.Session.AbsoluteExpiresAt, Restricted: issued.Session.IsRestricted()}
	if secret := issued.Secret.Reveal(); secret != "" {
		result.SessionSecret = []byte(secret)
	}
	if csrf := issued.CSRFSecret.Reveal(); csrf != "" {
		result.CSRFSecret = []byte(csrf)
	}
	for _, step := range authResult.RequiredSteps {
		result.RequiredSteps = append(result.RequiredSteps, string(step))
	}
	return result, nil
}

type accessFacade struct{ r *Runtime }

func (f *accessFacade) Check(ctx context.Context, req AccessRequest) (AccessDecision, error) {
	r := f.r
	if r == nil || r.managed == nil || r.managed.Authz == nil {
		return AccessDecision{}, configError("权限服务未装配")
	}
	caller, err := authz.UserCaller(req.UserID)
	if err != nil {
		return AccessDecision{}, mapServiceError(err)
	}
	mode := authz.Mode(req.Mode)
	if mode == "" {
		mode = authz.ModeAll
	}
	scope := "system"
	if req.AppID != "" {
		scope = req.AppID
	}
	result, err := r.managed.Authz.Check(ctx, caller, authz.CheckRequest{
		SubjectUserID: req.UserID, ScopeID: scope, Permissions: []string{req.Permission}, Mode: mode,
	})
	if err != nil {
		return AccessDecision{}, mapServiceError(err)
	}
	return AccessDecision{Allowed: result.Allowed, Code: string(result.Code),
		Reason: result.Reason, Application: req.AppID}, nil
}

type sessionFacade struct{ r *Runtime }

func (f *sessionFacade) Revoke(ctx context.Context, sessionSecret []byte) error {
	if f.r == nil || f.r.services == nil {
		return configError("服务未装配")
	}
	if len(sessionSecret) == 0 {
		return configError("会话秘密为空")
	}
	if _, err := f.r.services.Sessions.RevokeAllOwnSessions(ctx, string(sessionSecret), false); err != nil {
		return mapServiceError(err)
	}
	return nil
}

type adminFacade struct{}

func (f *adminFacade) GrantApplicationRole(ctx context.Context, req GrantRoleRequest) error {
	_ = ctx
	_ = req
	return configError("角色分配门面将在 146-149 提供；Phase A 不提供受信管理写入")
}
