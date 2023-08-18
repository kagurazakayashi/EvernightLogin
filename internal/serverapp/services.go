package serverapp

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/appcore"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	authnsqlite "github.com/kagurazakayashi/EvernightLogin/internal/authn/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/bootstrap"
	bootstrapsqlite "github.com/kagurazakayashi/EvernightLogin/internal/bootstrap/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/credential"
	credentialsqlite "github.com/kagurazakayashi/EvernightLogin/internal/credential/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	"github.com/kagurazakayashi/EvernightLogin/internal/onboarding"
	onboardingsqlite "github.com/kagurazakayashi/EvernightLogin/internal/onboarding/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/registration"
	registrationsqlite "github.com/kagurazakayashi/EvernightLogin/internal/registration/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	sessionsqlite "github.com/kagurazakayashi/EvernightLogin/internal/session/sqlite"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

// Deps 是装配宿主服务所需的显式依赖；所有资源由调用方拥有和关闭。
type Deps struct {
	Config login.Config
	// Mail 是真实邮件运行时（步骤 139）；nil 表示未装配（等价于未配置发送器）。
	Mail *MailRuntime
	// MailDeliveryProvider 延迟返回可靠投递服务（任务运行时构造完成后可用）；
	// 供注册服务在早期装配阶段使用，未装配时返回 nil。
	MailDeliveryProvider func() *mailer.DeliveryService
	Store                *storagesqlite.Store
	Keyring              *secrets.Keyring
	Audit                *audit.Recorder
	Logger               *slog.Logger
	Now                  func() time.Time
	// AllowLegacyWithoutSensitive 显式允许会话管理访问仅走旧强认证闸门而未经敏感
	// 操作策略判定（步骤 39 未装配的过渡开关）。默认 false（fail-closed）。
	AllowLegacyWithoutSensitive bool
}

// OpenStore 按配置打开 SQLite 存储。
//
// writeGuard 非 nil 时接入维护门闸：维护状态激活后所有经存储的写事务被拒绝
// （错误原样返回）。数据库目录不存在时按 0700 创建；已有目录权限不被放宽。
// 实现见 internal/appcore.OpenStore（与公开嵌入入口共用）。
func OpenStore(ctx context.Context, cfg login.Config,
	writeGuard func(context.Context) (func(), error)) (*storagesqlite.Store, error) {
	return appcore.OpenStore(ctx, cfg, writeGuard)
}

// NewAuditRecorder 构造安全审计写入器。审计不可用时装配失败（fail-closed），
// 不存在"先跑起来、审计稍后补"的降级路径。实现见 internal/appcore.NewAuditRecorder。
func NewAuditRecorder(ctx context.Context, store *storagesqlite.Store,
	logger *slog.Logger, now func() time.Time) (*audit.Recorder, error) {
	return appcore.NewAuditRecorder(ctx, store, logger, now)
}

// Services 是内置页面当前可用的真实领域服务集合。
//
// 未装配的服务（角色/权限/委派、应用接入、MFA/Passkey/恢复、OAuth 协议、
// 统计/报告/备份/审计查询、通知投递、后台任务调度）在报告中列为缺口；
// 页面只有在对应服务与适配器都真实装配后才注册，绝不用测试替身填充。
type Services struct {
	BootstrapStore    *bootstrapsqlite.Store
	Credential        *credential.Service
	Authn             *authn.Service
	Sessions          *session.Service
	Registration      *registration.Service
	RegistrationStore *registrationsqlite.Store
	Onboarding        *onboarding.Service
	// Delegation 是共享的真实委派引擎（同时供 managed 侧 group/role/app 等使用）；
	// 只有真实 SQLite + 审计构造成功才存在，nil 时相关 Guard 必须 fail-closed。
	Delegation *delegation.Service
	// SessionAuthorizer 是延迟注入的管理强制下线范围授权器（步骤 151）；
	// managed 授权层构造完成后由宿主 Set，未注入前 fail-closed。
	SessionAuthorizer *lazySessionScopeAuthorizer
}

// SecurityHooks 是宿主提供给认证/会话服务的延迟安全依赖；nil 字段表示该依赖
// 尚未装配（服务侧按其自身 fail-closed 语义处理）。
type SecurityHooks struct {
	// Sensitive 是敏感操作收敛入口（生产实现为 SecurityGate.Reauth）。
	Sensitive reauth.OperationRunner
	// StrongPresence 报告账户是否已绑定强因素（生产实现为 TOTP/Passkey 聚合）。
	StrongPresence authn.StrongFactorPresence
}

// BuildServices 按依赖顺序装配账户入口页所需的最小真实服务集合：
// 审计 -> 凭证/会话/认证 -> 注册 -> 入域。
//
// 所有服务构造只校验依赖、不创建协程、不监听端口、不写数据库；后台任务与
// 外部投递（邮件/Webhook）都不启动也不真实外发。
func BuildServices(deps Deps) (*Services, error) {
	return BuildServicesWithHooks(deps, SecurityHooks{})
}

// BuildServicesWithHooks 与 BuildServices 相同，但注入延迟安全依赖（敏感操作
// 闸门与强因素来源），供独立服务完整装配使用。
func BuildServicesWithHooks(deps Deps, hooks SecurityHooks) (*Services, error) {
	if deps.Store == nil || deps.Keyring == nil || deps.Audit == nil {
		return nil, fmt.Errorf("装配服务缺少存储、主密钥环或审计依赖")
	}
	logger := deps.Logger
	now := deps.Now
	if now == nil {
		now = time.Now
	}
	cfg := deps.Config

	bootstrapStore, err := bootstrapsqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造首次初始化存储失败: %w", err)
	}
	roots, err := newHostRootChecker(bootstrapStore)
	if err != nil {
		return nil, fmt.Errorf("构造 root 识别器失败: %w", err)
	}
	delegationService, err := newDelegationService(deps)
	if err != nil {
		return nil, err
	}
	productionGuard := productionDelegationGuard{roots: roots, engine: delegationService}
	credentialStore, err := credentialsqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造一次性凭证存储失败: %w", err)
	}
	credentialService, err := credential.New(credentialStore, credential.Options{
		Keyring: deps.Keyring, Now: now, Logger: logger})
	if err != nil {
		return nil, fmt.Errorf("构造一次性凭证服务失败: %w", err)
	}
	authnService, err := newAuthnService(deps, bootstrapStore, hooks)
	if err != nil {
		return nil, err
	}
	sessionStore, err := sessionsqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造会话存储失败: %w", err)
	}
	sessionAuthorizer := newLazySessionScopeAuthorizer()
	sessionService, err := session.New(sessionStore, session.Options{
		Authorizer: sessionAuthorizer,
		Store:      sessionStore, Audit: deps.Audit, Keyring: deps.Keyring,
		// 敏感操作策略（步骤 39）尚未装配：默认 fail-closed，管理访问被拒绝。
		// 仅当宿主显式开启 --allow-legacy-without-sensitive 时才允许旧闸门路径，
		// 该开关不改变认证/授权判定本身的强度，只影响未装配策略时的拒绝点。
		AllowLegacyWithoutSensitive: deps.AllowLegacyWithoutSensitive,
		Sensitive:                   hooks.Sensitive,
		// root 管理会话绑定：只有已完成强认证（结果带服务端强认证时间）的 root
		// 才能签发普通会话；未完成强认证时仍只能持有受限会话（fail-closed）。
		AllowRootStrongAuthSessions: true,
		Now:                         now, Logger: logger,
	})
	if err != nil {
		return nil, fmt.Errorf("构造会话服务失败: %w", err)
	}

	// 步骤 140：注册邮箱验证接入真实邮件投递。要求在启动期 fail-closed 检查
	// “要求验证但无邮件能力”和公开链接基址，不能等用户注册时才发现。
	if err := validateMailRegistration(cfg); err != nil {
		return nil, err
	}
	mailURLs, _ := buildMailURLs(cfg)
	var registrationMailer registration.EmailSender
	if cfg.Mail.Enabled {
		registrationMailer = &lazyRegistrationMailer{
			provider: deps.MailDeliveryProvider,
			appName:  deps.Mail.AppDisplayName(),
		}
	}
	_ = mailURLs
	defaultRoles := make([]registration.DefaultRole, 0, len(cfg.Registration.DefaultRoleIDs))
	for _, roleID := range cfg.Registration.DefaultRoleIDs {
		defaultRoles = append(defaultRoles, registration.DefaultRole{
			RoleID: roleID, ScopeID: registration.DefaultRoleScopeSystem})
	}
	registrationStore, err := registrationsqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造注册存储失败: %w", err)
	}
	registrationService, err := registration.New(registration.Options{
		Store: registrationStore, Audit: deps.Audit, Credentials: credentialService,
		Mailer: registrationMailer, VerificationURLBase: mailURLs.VerifyEmail,
		AppName: cfg.Mail.AppName,
		Enabled: cfg.Registration.Enabled, RequireReview: cfg.Registration.RequireReview,
		RequireEmailVerification: cfg.Registration.RequireEmailVerification, DefaultRoles: defaultRoles,
		PasswordPolicy: authn.DefaultPasswordPolicy(), HashParams: authn.DefaultParams(),
		Now: now, Logger: logger,
	})
	if err != nil {
		return nil, fmt.Errorf("构造注册服务失败: %w", err)
	}
	onboardingStore, err := onboardingsqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造入域存储失败: %w", err)
	}
	onboardingService, err := onboarding.New(onboarding.Options{
		Store: onboardingStore, Audit: deps.Audit,
		// 步骤 149：root/受信本地/system 由包装器放行，其余主体交给真实 delegation
		// 引擎；不再使用空 GuardFuncs 的全拒替身。
		Guard: productionGuard, Credentials: credentialService,
		PasswordPolicy: authn.DefaultPasswordPolicy(), HashParams: authn.DefaultParams(),
		Now: now, Logger: logger,
	})
	if err != nil {
		return nil, fmt.Errorf("构造入域服务失败: %w", err)
	}
	return &Services{
		BootstrapStore:    bootstrapStore,
		Credential:        credentialService,
		Authn:             authnService,
		Sessions:          sessionService,
		Registration:      registrationService,
		RegistrationStore: registrationStore,
		Onboarding:        onboardingService,
		Delegation:        delegationService,
		// 延迟授权器必须随服务集合一起交给装配层，否则管理强制下线会永久停留在
		// fail-closed（未注入）状态；真实 AuthzAuthorizer 由共享装配在权限引擎
		// 构造完成后原子注入。
		SessionAuthorizer: sessionAuthorizer,
	}, nil
}

// BuildBootstrapService 构造本地受控首次初始化服务；只允许显式配置的本地
// 操作者，未提供操作者时拒绝构造（不提供"默认放行"或匿名入口）。
func BuildBootstrapService(deps Deps, operatorID string) (*bootstrap.Service, bootstrap.Caller, error) {
	if deps.Store == nil || deps.Audit == nil || deps.Keyring == nil {
		return nil, bootstrap.Caller{}, fmt.Errorf("首次初始化缺少存储、审计或主密钥环依赖")
	}
	logger := deps.Logger
	now := deps.Now
	if now == nil {
		now = time.Now
	}
	bootstrapStore, err := bootstrapsqlite.New(deps.Store)
	if err != nil {
		return nil, bootstrap.Caller{}, fmt.Errorf("构造首次初始化存储失败: %w", err)
	}
	credentialStore, err := credentialsqlite.New(deps.Store)
	if err != nil {
		return nil, bootstrap.Caller{}, fmt.Errorf("构造一次性凭证存储失败: %w", err)
	}
	credentialService, err := credential.New(credentialStore, credential.Options{
		Keyring: deps.Keyring, Now: now, Logger: logger})
	if err != nil {
		return nil, bootstrap.Caller{}, fmt.Errorf("构造一次性凭证服务失败: %w", err)
	}
	authorizer, err := bootstrap.NewLocalBootstrapAuthorizer([]string{operatorID})
	if err != nil {
		return nil, bootstrap.Caller{}, fmt.Errorf("构造本地初始化授权器失败: %w", err)
	}
	service, err := bootstrap.New(bootstrap.Options{
		Store: bootstrapStore, Audit: deps.Audit, Authorizer: authorizer,
		Credentials: credentialService, Now: now, Logger: logger,
	})
	if err != nil {
		return nil, bootstrap.Caller{}, fmt.Errorf("构造首次初始化服务失败: %w", err)
	}
	caller, err := bootstrap.LocalBootstrapCaller(operatorID)
	if err != nil {
		return nil, bootstrap.Caller{}, fmt.Errorf("构造本地初始化操作者失败: %w", err)
	}
	return service, caller, nil
}

// newAuthnService 构造认证服务；root 受限初始化状态存储必须注入真实
// bootstrapsqlite.Store，不允许用测试替身替代（否则会绕过 0008 状态机）。
func newAuthnService(deps Deps, bootstrapStore *bootstrapsqlite.Store,
	hooks SecurityHooks) (*authn.Service, error) {
	authnStore, err := authnsqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造认证存储失败: %w", err)
	}
	now := deps.Now
	if now == nil {
		now = time.Now
	}
	service, err := authn.New(authn.Options{
		Store: authnStore, Audit: deps.Audit, RootInitialization: bootstrapStore,
		StrongFactorPresence: hooks.StrongPresence,
		Sensitive:            hooks.Sensitive,
		PasswordPolicy:       authn.DefaultPasswordPolicy(), Params: authn.DefaultParams(),
		Now: now, Logger: deps.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("构造认证服务失败: %w", err)
	}
	return service, nil
}

// AccountLocalCaller 构造账户域的本地初始化操作者（用于 authn.SetRootPassword）。
func AccountLocalCaller(operatorID string) (account.Caller, error) {
	return account.LocalBootstrapCaller(operatorID)
}
