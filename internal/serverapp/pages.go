package serverapp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/pagecsrf"
	"github.com/kagurazakayashi/EvernightLogin/internal/pagestate"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	"github.com/kagurazakayashi/EvernightLogin/internal/uiaccountadapter"
	"github.com/kagurazakayashi/EvernightLogin/internal/uiadminadapter"
	"github.com/kagurazakayashi/EvernightLogin/internal/uiauthadapter"
	"github.com/kagurazakayashi/EvernightLogin/internal/uisecurityadapter"
)

// pageSessions 用真实会话服务实现内置页面框架的页面会话契约。
//
// 它只读取服务端会话 Cookie 并调用 session.Service 的校验方法，不接受任何客户端
// 自报身份字段；会话失效统一返回 login.ErrUISessionExpired，页面按过期处理。
//
// 强认证门禁（root/高权限管理访问）：
//   - "management" 页面级别只有在 session.Service.AuthorizeManagement 真实通过时
//     才返回 Kind="management"；该调用要求普通会话 + 已完成强认证 + 在
//     StrongAuthMaxAge（默认 15 分钟）新鲜度窗口内。
//   - 普通会话未完成强认证/已过期时只返回 Kind="normal"，管理页由框架按
//     ErrUIForbidden 拒绝（403），不会因为"能登录"就获得管理会话。
//   - 受限初始化/受限恢复会话返回 Kind="restricted"，普通页与管理页都拒绝；
//     这是 fail-closed，不存在降级为高权限密码会话的旁路。
//   - 解析出管理会话时把短时强认证事实登记到 SecurityGate，供敏感策略页的宿主
//     再次认证回调使用；事实只用于同一次页面动作，参数绑定仍由适配器的签名预览
//     令牌完成。
type pageSessions struct {
	service *session.Service
	gate    *SecurityGate
	// pathPrefix 是部署路径前缀；用于判定当前请求是否落在管理页面命名空间。
	pathPrefix string
}

// isManagementPagePath 报告请求路径是否落在管理页面命名空间（/admin/*）。页面框架
// 对 UIAccessUser 与 UIAccessManagement 的会话 Kind 是互斥判定：管理 Kind 不能让
// 普通页面通过，反之亦然。因此这里只为管理命名空间升级为 management，其余页面
// 保持 normal；受限会话永远保持 restricted（不因路径放宽）。
func isManagementPagePath(requestPath, prefix string) bool {
	trimmed := requestPath
	if prefix != "" && strings.HasPrefix(trimmed, prefix) {
		trimmed = strings.TrimPrefix(trimmed, prefix)
	}
	for _, namespace := range []string{"/admin", "/support"} {
		if trimmed == namespace || strings.HasPrefix(trimmed, namespace+"/") {
			return true
		}
	}
	return false
}

// ResolvePageSession 校验请求携带的会话 Cookie 并返回公开安全摘要。
func (p pageSessions) ResolvePageSession(ctx context.Context,
	request *http.Request) (login.UISession, error) {
	secret, ok := p.service.SessionSecretFromRequest(request)
	if !ok {
		return login.UISession{}, login.ErrUISessionExpired
	}
	record, err := p.service.Validate(ctx, secret)
	if err != nil {
		return login.UISession{}, login.ErrUISessionExpired
	}
	kind := "normal"
	if record.IsRestricted() {
		kind = "restricted"
	}
	// 强认证新鲜度只影响"能否获得管理会话"，不影响普通业务访问；未通过时
	// 保持 normal，由页面访问级别判定拒绝管理页。管理 Kind 只发给管理命名空间，
	// 否则强认证用户的普通页面会被页面框架按 Kind 互斥规则拒绝。
	if kind == "normal" {
		if management, authorizeErr := p.service.AuthorizeManagement(ctx, secret); authorizeErr == nil {
			if p.gate != nil {
				p.gate.recordManagementFact(management.UserID,
					sessionManagementFact(management))
			}
			if isManagementPagePath(request.URL.Path, p.pathPrefix) {
				kind = "management"
			}
		}
	}
	return login.UISession{
		Authenticated: true,
		UserID:        record.UserID,
		AppID:         record.AppID,
		Kind:          kind,
		ExpiresAt:     record.AbsoluteExpiresAt,
	}, nil
}

// IssueCSRFToken 为服务端渲染表单签发与会话绑定的页面 CSRF 令牌。
func (p pageSessions) IssueCSRFToken(ctx context.Context, request *http.Request) (string, error) {
	secret, ok := p.service.SessionSecretFromRequest(request)
	if !ok {
		return "", login.ErrUISessionExpired
	}
	token, err := p.service.IssuePageCSRFToken(ctx, secret)
	if err != nil {
		return "", login.ErrUISessionExpired
	}
	return token.Reveal(), nil
}

// Pages 是内置页面装配结果。
type Pages struct {
	WebUI      *login.WebUI
	CSRF       *pagecsrf.Provider
	Sessions   *session.Service
	PublicForm map[string]string
}

// BuildPages 装配内置页面：ui.go 共 14 个页面选项，默认注册 12 个，条件注册 2 个
// （安全中心需 Passkey 与协议端点同时启用、OAuth 页需协议端点启用），全部满足时 14 个。
//
// 已装配（全部使用真实领域服务与生产授权适配层）：
//   - 账户入口页：登录/注册/邀请接受/邮箱验证/退出；
//   - 个人资料页：资料/用户名/头像/应用资料/邮箱变更/密码；
//   - 两步验证页：第二因素、强认证初始化（Passkey）、恢复代码、受限恢复重绑、找回密码；
//   - OAuth 授权/设备确认/扫码登录页（仅在协议端点启用时注册；设备码与扫码当前
//     未启用，页面会显示受控的“能力未启用”状态）；
//   - 安全中心页：MFA/TOTP/Passkey/恢复代码/会话/已授权应用（要求 Passkey 与协议
//     端点都启用，否则不注册，避免半装配）；
//   - 用户/角色权限/审计/统计/报告/备份/应用管理页；
//   - 客服求助与人工恢复页（人工恢复制度默认关闭，页面显示真实关闭状态）；
//   - 敏感操作策略与安全通知页（真实 policy + reauth，写操作要求管理会话强认证）。
//
// 未满足依赖的页面不注册（请求得到 404），绝不用测试替身冒充生产。
func BuildPages(deps Deps, services *Services, managed *ManagedServices,
	securityDomains *SecurityDomains, gate *SecurityGate,
	protocolDomains *ProtocolDomains) (*Pages, error) {
	if services == nil || services.Sessions == nil || services.Authn == nil {
		return nil, fmt.Errorf("装配页面缺少会话或认证服务")
	}
	if securityDomains == nil || gate == nil || managed == nil {
		return nil, fmt.Errorf("装配页面缺少安全域/敏感操作闸门/管理域服务")
	}
	logger := deps.Logger
	now := deps.Now
	if now == nil {
		now = time.Now
	}
	pageState, err := pagestate.New(pagestate.Options{
		Keyring: deps.Keyring, TTL: 15 * time.Minute, Now: now})
	if err != nil {
		return nil, fmt.Errorf("构造页面状态编解码器失败: %w", err)
	}
	authAdapter, err := uiauthadapter.New(uiauthadapter.Options{
		Authn:             services.Authn,
		Sessions:          services.Sessions,
		Registration:      services.Registration,
		Onboarding:        services.Onboarding,
		RegistrationStore: services.RegistrationStore,
		Credential:        services.Credential,
		RequireReview:     deps.Config.Registration.RequireReview,
		ResendComponentID: "login-server-page",
		// 第二因素/Passkey/恢复/找回页面依赖的真实服务。
		MFA:           securityDomains.MFA,
		Passkeys:      securityDomains.Passkey,
		Recovery:      securityDomains.Recovery,
		PasswordReset: securityDomains.PasswordReset,
		PageState:     pageState,
		App:           managed.App,
		Account:       managed.Account,
		Now:           now,
		Logger:        logger,
	})
	if err != nil {
		return nil, fmt.Errorf("构造账户/两步验证页适配器失败: %w", err)
	}
	accountAdapter, err := uiaccountadapter.New(uiaccountadapter.Options{
		Profile:     managed.Profile,
		App:         managed.App,
		Avatar:      securityDomains.Avatar,
		EmailChange: securityDomains.EmailChange,
		Passwords:   securityDomains.PasswordReset,
		Reauth:      gate.Reauth,
		Sessions:    services.Sessions,
		Now:         now,
		Logger:      logger,
	})
	if err != nil {
		return nil, fmt.Errorf("构造个人资料页适配器失败: %w", err)
	}
	csrfProvider, err := pagecsrf.New(pagecsrf.Options{
		Keyring: deps.Keyring, TTL: 15 * time.Minute, Now: now})
	if err != nil {
		return nil, fmt.Errorf("构造页面 CSRF 提供者失败: %w", err)
	}
	validateCSRF := func(ctx context.Context, request *http.Request, token string) error {
		return services.Sessions.ValidateCSRFToken(ctx, request, token)
	}
	webOptions := login.WebUIOptions{
		Prefix: deps.Config.Server.PathPrefix,
		Session: pageSessions{service: services.Sessions, gate: gate,
			pathPrefix: deps.Config.Server.PathPrefix},
		FormTokens: csrfProvider,
		PageAuth: &login.UIPageAuthOptions{
			Backend:       authAdapter,
			PostLoginPath: "/",
		},
		PageAccount: &login.UIPageAccountOptions{Backend: accountAdapter},
		PageMFA: &login.UIPageMFAOptions{
			Backend:       authAdapter,
			LoginPath:     "/login",
			PostLoginPath: "/home",
		},
		Now:    now,
		Logger: logger,
	}
	// 安全中心页：需要 Passkey 服务（TOTP/Passkey/恢复代码管理）与授权流程服务
	// （已授权应用列表/撤销）。任一缺失时不注册，避免把半装配的安全页暴露为可用。
	if securityDomains.Passkey != nil && protocolDomains != nil && protocolDomains.OAuthFlow != nil {
		securityAdapter, securityErr := uisecurityadapter.New(uisecurityadapter.Options{
			MFA:      securityDomains.MFA,
			TOTP:     securityDomains.TOTP,
			Passkeys: securityDomains.Passkey,
			Recovery: securityDomains.Recovery,
			Sessions: services.Sessions,
			OAuth:    protocolDomains.OAuthFlow,
			Reauth:   gate.Reauth,
			Now:      now,
			Logger:   logger,
		})
		if securityErr != nil {
			return nil, fmt.Errorf("构造安全中心页适配器失败: %w", securityErr)
		}
		webOptions.PageSecurity = &login.UIPageSecurityOptions{Backend: securityAdapter}
	}
	if protocolDomains != nil && protocolDomains.OAuthFlow != nil {
		webOptions.PageOAuth = &login.UIPageOAuthOptions{
			Backend:       authAdapter,
			LoginPath:     "/login",
			PostLoginPath: "/home",
		}
	}
	// 用户管理页：真实 account/profile/group/onboarding/userbatch + 生产授权。
	adminAdapter, adminErr := uiadminadapter.New(uiadminadapter.Options{
		Account: managed.Account, Profile: managed.Profile,
		Reviews: managed.Onboarding, Groups: managed.Group,
		Batches:   managed.Batch,
		Authorize: managed.Checker.authorizePageAction,
		Logger:    logger,
	})
	if adminErr != nil {
		return nil, fmt.Errorf("构造用户管理页适配器失败: %w", adminErr)
	}
	webOptions.PageAdmin = &login.UIPageAdminOptions{Backend: adminAdapter}
	rbacAdapter, rbacErr := uiadminadapter.NewRBAC(uiadminadapter.RBACOptions{
		Roles: managed.Role, Permissions: managed.Permission,
		Access: managed.Authz, Delegations: managed.Delegation,
		Authorize:        managed.Checker.authorizePageAction,
		ManageableScopes: managed.Checker.pageManageableScopes,
		Logger:           logger,
	})
	if rbacErr != nil {
		return nil, fmt.Errorf("构造角色权限页适配器失败: %w", rbacErr)
	}
	webOptions.PageRBAC = &login.UIPageRBACOptions{Backend: rbacAdapter}
	// 审计页：真实 auditops 查询/导出/清理 + 生产授权适配器；导出/清理等敏感
	// 动作经真实 reauth/policy 判定（未满足时 fail-closed 拒绝）。
	auditAdapter, auditErr := uiadminadapter.NewAudit(uiadminadapter.AuditOptions{
		Audit:      managed.AuditOps,
		Authorizer: auditScopeAuthorizer{checker: managed.Checker},
		Recorder:   deps.Audit,
		IsRoot: func(ctx context.Context, userID string) (bool, error) {
			return managed.Roots.isRoot(ctx, userID)
		},
		Logger: logger,
	})
	if auditErr != nil {
		return nil, fmt.Errorf("构造审计页适配器失败: %w", auditErr)
	}
	webOptions.PageAudit = &login.UIPageAuditOptions{
		Backend: auditAdapter, ValidateCSRF: validateCSRF, Now: now,
	}
	statsAdapter, statsErr := uiadminadapter.NewStats(uiadminadapter.StatsOptions{
		Stats:      managed.Stats,
		Authorizer: statsScopeAuthorizer{checker: managed.Checker},
		Recorder:   deps.Audit,
		IsRoot: func(ctx context.Context, userID string) (bool, error) {
			return managed.Roots.isRoot(ctx, userID)
		},
		AuditRead: func(ctx context.Context, userID string) (bool, error) {
			return managed.Checker.evaluate(ctx, userID, "audit.read", "system")
		},
		Logger: logger,
	})
	if statsErr != nil {
		return nil, fmt.Errorf("构造统计页适配器失败: %w", statsErr)
	}
	webOptions.PageStats = &login.UIPageStatsOptions{Backend: statsAdapter, Now: now}
	reportsAdapter, reportsErr := uiadminadapter.NewReports(uiadminadapter.ReportsOptions{
		Reports:    managed.Reports,
		Plans:      managed.Plans,
		Authorizer: statsScopeAuthorizer{checker: managed.Checker},
		Root:       statsRootChecker{roots: managed.Roots},
		Recorder:   deps.Audit,
		Now:        now,
	})
	if reportsErr != nil {
		return nil, fmt.Errorf("构造报告页适配器失败: %w", reportsErr)
	}
	webOptions.PageReports = &login.UIPageReportsOptions{
		Backend: reportsAdapter, ValidateCSRF: validateCSRF, Now: now,
	}
	backupsAdapter, backupsErr := uiadminadapter.NewBackups(uiadminadapter.BackupsOptions{
		Admin:    managed.BackupAdmin,
		Recorder: deps.Audit,
		Now:      now,
	})
	if backupsErr != nil {
		return nil, fmt.Errorf("构造备份页适配器失败: %w", backupsErr)
	}
	webOptions.PageBackups = &login.UIPageBackupOptions{
		Backend: backupsAdapter, ValidateCSRF: validateCSRF, Now: now,
	}
	appsAdapter, appsErr := uiadminadapter.NewApps(uiadminadapter.AppOptions{
		Apps: managed.App, OAuth: managed.OAuthClient,
		Authorize: func(ctx context.Context, adminUserID, action,
			applicationID string) error {
			return managed.Checker.authorizePageActionScoped(ctx, adminUserID,
				action, applicationID)
		},
		Now: now, Logger: logger,
	})
	if appsErr != nil {
		return nil, fmt.Errorf("构造应用管理页适配器失败: %w", appsErr)
	}
	webOptions.PageApps = &login.UIPageAppsOptions{Backend: appsAdapter}
	// 客服/人工恢复页：真实 support/manualrecovery 服务；人工恢复制度默认关闭，
	// 页面显示真实关闭状态与受控申请结果，不伪造审批或执行成功。
	supportAdapter, supportErr := uiadminadapter.NewSupport(uiadminadapter.SupportOptions{
		Cases:     securityDomains.Support,
		Recovery:  securityDomains.ManualRecovery,
		Authorize: managed.Checker.authorizePageAction,
	})
	if supportErr != nil {
		return nil, fmt.Errorf("构造客服页适配器失败: %w", supportErr)
	}
	webOptions.PageSupport = &login.UIPageSupportOptions{Backend: supportAdapter}
	// 敏感操作策略/安全通知页：真实 policy 服务 + 宿主再次认证回调（管理会话
	// 强认证事实 + 页面签名预览绑定）+ 真实审计；SMTP 秘密替换能力未配置（nil）。
	policyAdapter, policyErr := uiadminadapter.NewSecurityPolicy(uiadminadapter.SecurityPolicyOptions{
		Policy:    gate.Policy,
		Authorize: managed.Checker.authorizePageAction,
		Reauth: func(ctx context.Context, userID string,
			binding login.UISecurityPolicyActionBinding) error {
			return gate.SecurityPolicyReauth(ctx, userID, binding)
		},
		Audit: deps.Audit,
	})
	if policyErr != nil {
		return nil, fmt.Errorf("构造敏感策略页适配器失败: %w", policyErr)
	}
	webOptions.PageSecurityPolicy = &login.UIPageSecurityPolicyOptions{
		Backend: newPolicyWriteBackend(policyAdapter, gate, deps.Audit), ValidateCSRF: validateCSRF,
	}
	web, err := login.NewWebUI(webOptions)
	if err != nil {
		return nil, fmt.Errorf("构造内置页面失败: %w", err)
	}
	return &Pages{
		WebUI:      web,
		CSRF:       csrfProvider,
		Sessions:   services.Sessions,
		PublicForm: login.UIPageAuthPublicFormPaths(deps.Config.Server.PathPrefix),
	}, nil
}

// BuildHTTPOptions 构造公开 HTTP 处理程序选项：固定前缀、访问日志、可信代理、
// 安全响应头与页面表单 CSRF 防护。
//
// CSRF 同时启用"公开表单匿名令牌"（登录/注册/邀请/邮箱验证）与"会话绑定令牌"
// 两条校验路径，并对所有不安全请求要求精确同源。没有可用来源时返回错误，
// 不降级为关闭校验。
func BuildHTTPOptions(deps Deps, pages *Pages, logger *slog.Logger,
	accessLogWriter io.Writer) (login.HTTPOptions, error) {
	if pages == nil || pages.WebUI == nil || pages.CSRF == nil || pages.Sessions == nil {
		return login.HTTPOptions{}, fmt.Errorf("HTTP 装配缺少页面或 CSRF 依赖")
	}
	origins, err := csrfOrigins(deps.Config)
	if err != nil {
		return login.HTTPOptions{}, err
	}
	publicPaths := make([]string, 0, len(pages.PublicForm))
	for path := range pages.PublicForm {
		publicPaths = append(publicPaths, path)
	}
	return login.HTTPOptions{
		Prefix:          deps.Config.Server.PathPrefix,
		Logger:          logger,
		AccessLogWriter: accessLogWriter,
		Protection: &login.HTTPProtectionOptions{
			TrustedProxies: append([]string(nil), deps.Config.Server.TrustedProxies...),
			CSRF: login.CSRFPolicy{
				Enabled:                     true,
				CookieName:                  session.DefaultCookieName,
				AllowedOrigins:              origins,
				RequireForAllUnsafeRequests: true,
				PublicFormPaths:             publicPaths,
				PublicTokenValidator:        pages.CSRF.Validator(pages.PublicForm),
				TokenValidator: login.CSRFValidatorFunc(func(ctx context.Context,
					request *http.Request, token string) error {
					return pages.Sessions.ValidateCSRFToken(ctx, request, token)
				}),
			},
			SecurityHeaders: &login.SecurityHeaderOptions{
				ContentSecurityPolicy: login.DefaultUIPageContentSecurityPolicy,
			},
		},
		UI: &login.UIHTTPOptions{
			Handler:                   pages.WebUI,
			PageContentSecurityPolicy: login.DefaultUIPageContentSecurityPolicy,
		},
	}, nil
}

// IsUninitialized 报告数据库是否还没有 root 初始化记录（用于启动告警）。
func IsUninitialized(ctx context.Context, services *Services) (bool, error) {
	if services == nil || services.BootstrapStore == nil {
		return false, errors.New("缺少首次初始化存储")
	}
	_, found, err := services.BootstrapStore.GetInitialization(ctx)
	if err != nil {
		return false, err
	}
	return !found, nil
}

// 编译期确认页面会话适配器满足公开契约。
var _ login.UISessionService = pageSessions{}
