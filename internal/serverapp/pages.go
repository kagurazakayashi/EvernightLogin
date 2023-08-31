package serverapp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	appsqlite "github.com/kagurazakayashi/EvernightLogin/internal/app/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
	"github.com/kagurazakayashi/EvernightLogin/internal/pagecsrf"
	"github.com/kagurazakayashi/EvernightLogin/internal/pagestate"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
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
	// 以下适配器同时供管理 API 写路由（步骤 156）复用，避免页面/API 两套授权。
	Admin   *uiadminadapter.Adapter
	RBAC    *uiadminadapter.RBACAdapter
	Apps    *uiadminadapter.AppsAdapter
	Support *uiadminadapter.SupportAdapter
}

// PageBuildOptions 是宿主页面替换/资源覆盖选项（步骤 183）。
// options 为 nil 时行为与既有 BuildPages 完全一致；替换不等于跳过认证/权限/CSRF。
type PageBuildOptions struct {
	// Prefix 必须与宿主 HTTP handler 的固定前缀一致；空使用配置的 server.path_prefix。
	Prefix string
	// HostTemplates 是宿主模板覆盖来源；HostRenderer 是最高优先级单页渲染器。
	HostTemplates *login.UIHostTemplates
	HostRenderer  login.UIPageRenderer
	// Brand 覆盖页面品牌；nil 使用内置品牌。
	Brand *login.UIBrand
	// AssetOverlays 按顺序覆盖内置静态资源（同逻辑路径后者优先）。
	AssetOverlays []fs.FS
	// Translations 追加/覆盖翻译目录；nil 使用内置 zh-CN。
	Translations login.UICatalogProvider
	// DisableBuiltinPages 关闭内置页面，仅由宿主模板/渲染器提供页面。
	DisableBuiltinPages bool
}

// BuildPages 装配内置页面：ui.go 共 14 个页面选项，安全中心随核心安全服务注册，
// OAuth 授权页仍按协议端点条件注册；Passkey/OAuth 子能力在安全中心内按能力位显示。
//
// 已装配（全部使用真实领域服务与生产授权适配层）：
//   - 账户入口页：登录/注册/邀请接受/邮箱验证/退出；
//   - 个人资料页：资料/用户名/头像/应用资料/邮箱变更/密码；
//   - 两步验证页：第二因素、强认证初始化（Passkey）、恢复代码、受限恢复重绑、找回密码；
//   - OAuth 授权/设备确认/扫码登录页（仅在协议端点启用时注册；设备码与扫码当前
//     未启用，页面会显示受控的“能力未启用”状态）；
//   - 安全中心页：MFA/TOTP/恢复代码/会话始终可用（核心服务存在时）；Passkey 与
//     已授权应用按实际子能力显示，未启用时明确不可用；
//   - 用户/角色权限/审计/统计/报告/备份/应用管理页；
//   - 客服求助与人工恢复页（人工恢复制度默认关闭，页面显示真实关闭状态）；
//   - 敏感操作策略与安全通知页（真实 policy + reauth，写操作要求管理会话强认证）。
//
// 未满足依赖的页面不注册（请求得到 404），绝不用测试替身冒充生产。
func BuildPages(deps Deps, services *Services, managed *ManagedServices,
	securityDomains *SecurityDomains, gate *SecurityGate,
	protocolDomains *ProtocolDomains) (*Pages, error) {
	return BuildPagesWithOptions(deps, services, managed, securityDomains, gate,
		protocolDomains, nil)
}

// BuildPagesWithOptions 在 BuildPages 基础上应用宿主页面替换/资源覆盖选项；
// options 为 nil 时与 BuildPages 完全等价。
func BuildPagesWithOptions(deps Deps, services *Services, managed *ManagedServices,
	securityDomains *SecurityDomains, gate *SecurityGate,
	protocolDomains *ProtocolDomains, options *PageBuildOptions) (*Pages, error) {
	if services == nil || services.Sessions == nil || services.Authn == nil {
		return nil, fmt.Errorf("装配页面缺少会话或认证服务")
	}
	if securityDomains == nil || gate == nil || managed == nil {
		return nil, fmt.Errorf("装配页面缺少安全域/敏感操作闸门/管理域服务")
	}
	// 步骤 183：页面前缀必须与宿主 HTTP handler 一致；宿主显式覆盖优先，未覆盖时
	// 沿用配置（options==nil 与旧行为等价）。前缀只影响路由/表单/公开表单路径，
	// 不改变页面 Access 级别、会话/权限判定与 CSRF 校验。
	prefix := deps.Config.Server.PathPrefix
	if options != nil && strings.TrimSpace(options.Prefix) != "" {
		prefix = strings.TrimSpace(options.Prefix)
	}
	logger := deps.Logger
	now := deps.Now
	if now == nil {
		now = time.Now
	}
	// 步骤 184：为生产授权层注入“应用范围候选枚举”能力。它只读取用户角色分配得到
	// 候选应用 ID，最终权限仍由真实权限引擎逐应用判定；存储不可用时构造失败，不能
	// 静默退化为“可管理全部应用”。
	if deps.Store != nil {
		appScopeStore, scopeErr := appsqlite.New(deps.Store)
		if scopeErr != nil {
			return nil, fmt.Errorf("构造应用范围枚举存储失败: %w", scopeErr)
		}
		managed.Checker.SetApplicationScopeLister(appScopeStore)
	}
	pageState, err := pagestate.New(pagestate.Options{
		Keyring: deps.Keyring, TTL: 15 * time.Minute, Now: now})
	if err != nil {
		return nil, fmt.Errorf("构造页面状态编解码器失败: %w", err)
	}
	authOptions := uiauthadapter.Options{
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
		// strong-setup Passkey / 恢复代码等页面级敏感操作必须走真实 reauth；
		// 缺失会导致适配器 nil panic（不能以跳过再次认证继续）。
		Reauth: gate.Reauth,
		Now:    now,
		Logger: logger,
	}
	// 步骤 142/65：OAuth 授权确认、设备码与扫码登录页面共享真实服务；未启用时
	// 页面后端返回受控“未启用”，不伪造成功。协议域整体未装配时保持 nil，不能解引用。
	if protocolDomains != nil {
		authOptions.OAuth = protocolDomains.OAuthFlow
		authOptions.QR = protocolDomains.QRLogin
		authOptions.QRClientID = protocolDomains.QRClientID
		authOptions.ApplicationNames = protocolDomains.QRApplicationNames
	}
	authAdapter, err := uiauthadapter.New(authOptions)
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
		Prefix: prefix,
		Session: pageSessions{service: services.Sessions, gate: gate,
			pathPrefix: prefix},
		FormTokens: csrfProvider,
		PageAuth: &login.UIPageAuthOptions{
			Backend:       authAdapter,
			PostLoginPath: "/",
			PasskeyLoginPath: func() string {
				if securityDomains.Passkey != nil {
					return "/login/passkey"
				}
				return ""
			}(),
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
	// 安全中心按子能力组合：MFA/TOTP/恢复代码/会话/再次认证是核心必需；Passkey
	// 与 OAuth 授权列表是可选子能力（nil 时页面显示“未启用”，后端返回稳定不可用
	// 错误），不再因 Passkey 或 OAuth 单项关闭而整体不注册。隐藏/未启用不是授权。
	if securityDomains.MFA != nil && securityDomains.TOTP != nil &&
		securityDomains.Recovery != nil && services.Sessions != nil && gate.Reauth != nil {
		var oauthService *oauthflow.Service
		if protocolDomains != nil {
			oauthService = protocolDomains.OAuthFlow
		}
		securityAdapter, securityErr := uisecurityadapter.New(uisecurityadapter.Options{
			MFA:      securityDomains.MFA,
			TOTP:     securityDomains.TOTP,
			Passkeys: securityDomains.Passkey,
			Recovery: securityDomains.Recovery,
			Sessions: services.Sessions,
			OAuth:    oauthService,
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
		// 步骤 189：创建/删除自定义权限与内置权限启停属于高风险目录变更，接真实
		// 敏感策略/再次认证闸门；缺任依赖时回调 fail-closed 拒绝，不静默放行。
		Reauth: func(ctx context.Context, adminUserID, action, target,
			requestID string) error {
			return rbacPageReauth(ctx, gate, adminUserID, action, target, requestID)
		},
		Logger: logger,
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
		ManagedAPI: managed.ManagedAPI, ManagedPolicyActor: managed.ManagedPolicyActor,
		Authorize: func(ctx context.Context, adminUserID, action,
			applicationID string) error {
			return managed.Checker.authorizePageActionScoped(ctx, adminUserID,
				action, applicationID)
		},
		// 列表类读取没有单一目标应用：按“系统范围或任一应用范围持有读取权限”判定，
		// 实际返回范围由 app.Service.ApplicationScope 过滤（步骤 184）。
		AuthorizeAnyApp: managed.Checker.authorizePageAction,
		Now:             now, Logger: logger,
	})
	if appsErr != nil {
		return nil, fmt.Errorf("构造应用管理页适配器失败: %w", appsErr)
	}
	webOptions.PageApps = &login.UIPageAppsOptions{
		Backend:       appsAdapter,
		PolicyBackend: appsAdapter,
		// 步骤 190：应用逻辑删除属于高风险生命周期操作，接真实再次认证/敏感策略
		// 闸门；未装配时页面删除入口 fail-closed 拒绝，不静默放行。
		DeleteReauth: func(ctx context.Context, userID string,
			binding login.UIAppDeleteBinding) error {
			return applicationDeleteReauth(ctx, gate, userID, binding)
		},
		// 策略写先经过真实管理强认证（root/管理会话近期事实），再登记一次性
		// app/version/policy-digest/request-id 批准；managedapi.SetPolicy 只消费该批准。
		PolicyReauth: func(ctx context.Context, userID string,
			binding login.UIAppPolicyActionBinding) error {
			if managed.ManagedPolicyApprovals == nil {
				return fmt.Errorf("托管策略一次性批准器未装配")
			}
			if err := gate.ManagedPolicyReauth(ctx, userID, binding); err != nil {
				return err
			}
			return managed.ManagedPolicyApprovals.Register(userID, binding)
		},
	}
	// 步骤 185：业务应用管理员页面（/manage/**，UIAccessUser）复用同一应用范围
	// 判定与真实领域服务；/admin/** 的强认证访问级别保持不变。
	webOptions.PageManage = &login.UIPageManageOptions{
		Apps: appsAdapter, RBAC: rbacAdapter,
	}
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
	// 步骤 183：应用宿主页面替换/资源覆盖。这里只覆盖内容与资源来源；页面路由的
	// Access 级别、会话/权限判定与 CSRF 校验仍由同一 WebUI 契约强制执行，替换不等于
	// 跳过认证。options==nil 时以下分支全部不执行，保持旧行为。
	if options != nil {
		if options.Brand != nil {
			webOptions.Brand = *options.Brand
		}
		if options.HostRenderer != nil {
			webOptions.HostRenderer = options.HostRenderer
		}
		if options.HostTemplates != nil {
			webOptions.HostTemplates = options.HostTemplates
		}
		if len(options.AssetOverlays) > 0 {
			webOptions.AssetOverlays = append(webOptions.AssetOverlays, options.AssetOverlays...)
		}
		if options.Translations != nil {
			webOptions.Translations = options.Translations
		}
		if options.DisableBuiltinPages {
			webOptions.DisableBuiltinPages = true
		}
	}
	web, err := login.NewWebUI(webOptions)
	if err != nil {
		return nil, fmt.Errorf("构造内置页面失败: %w", err)
	}
	return &Pages{
		WebUI:      web,
		CSRF:       csrfProvider,
		Sessions:   services.Sessions,
		PublicForm: publicFormPaths(prefix),
		Admin:      adminAdapter, RBAC: rbacAdapter, Apps: appsAdapter, Support: supportAdapter,
	}, nil
}

// managementSessionRecorder 把管理 JSON API 的真实管理会话校验结果登记为短时管理
// 强认证事实（步骤 189）：同一请求内的高风险权限目录动作（创建/删除/内置权限启停）
// 的再次认证回调需要一个可信的新鲜强认证来源。它不改变认证语义——会话校验仍由
// 真实 session.Service.AuthorizeManagement 完成，这里只登记本次请求的事实。
type managementSessionRecorder struct {
	*session.Service
	gate *SecurityGate
}

// AuthorizeManagement 校验管理会话并在成功后登记短时强认证事实；失败不登记。
func (r managementSessionRecorder) AuthorizeManagement(ctx context.Context,
	secret string) (session.Session, error) {
	record, err := r.Service.AuthorizeManagement(ctx, secret)
	if err != nil {
		return record, err
	}
	if r.gate != nil {
		r.gate.recordManagementFact(record.UserID, sessionManagementFact(record))
	}
	return record, nil
}

// rbacPageReauthOperationID 是权限目录变更对应的敏感操作目录稳定标识。
const rbacPageReauthOperationID = "permission.catalog.change"

// rbacPageReauth 是系统权限管理页（创建/删除自定义权限、内置权限启停）的宿主再次
// 认证回调（步骤 189）。
//
// 绑定关系：页面会话解析时登记的“当前请求持有新鲜管理强认证”短时事实 → 本次动作
// 的策略评估信号（强度 strong、完成完整认证、已显式确认）；再交给真实
// reauth/policy 链按 permission.catalog.change 的目录默认策略复核新鲜度与强度。
// 管理事实缺失/过期、动作名不在白名单或策略拒绝都会 fail-closed 返回错误，页面
// 适配器据此拒绝写入，不存在“跳过策略”的降级路径。
func rbacPageReauth(ctx context.Context, gate *SecurityGate, userID, action, target,
	requestID string) error {
	if gate == nil || gate.Reauth == nil || gate.Policy == nil {
		return reauth.ErrReauthRequired
	}
	if !account.ValidUserID(userID) {
		return reauth.ErrAccessDenied
	}
	if !validRBACPageReauthAction(action) {
		return reauth.ErrAccessDenied
	}
	fact, ok := gate.takeManagementFact(userID)
	if !ok || fact.verifiedAt.IsZero() {
		return reauth.ErrReauthRequired
	}
	caller, err := reauth.UserCaller(userID)
	if err != nil {
		return reauth.ErrAccessDenied
	}
	safeRequestID := ""
	if account.ValidateRequestID(requestID) == nil {
		safeRequestID = requestID
	}
	request := reauth.Request{
		ScopeID: "system", OperationID: rbacPageReauthOperationID,
		TargetType: "permission", TargetID: target,
		Params: map[string]string{"action": action, "target": target,
			"request_id": safeRequestID},
		Description: "变更系统权限目录（创建/删除/内置权限启停）",
		RequestID:   safeRequestID,
	}
	// 敏感确认由页面处理器在调用适配器前校验（checkbox），因此 Confirmed=true；
	// 策略仍会按目录默认要求复核认证强度与新鲜度，不能被页面确认替代。
	signals := reauth.Signals{VerifiedAt: fact.verifiedAt, Strength: policy.StrengthStrong,
		Complete: true, Confirmed: true}
	approved, err := gate.Reauth.Authorize(reauth.WithSignals(ctx, signals), caller, request)
	if err != nil {
		return err
	}
	// 告知失败不改变已成立的授权与写入语义（与敏感策略页一致：失败只留痕）。
	if notifyErr := gate.Reauth.NotifyOutcome(ctx, approved, reauth.OutcomeSuccess); notifyErr != nil {
		_ = notifyErr
	}
	return nil
}

// validRBACPageReauthAction 白名单限制可绑定到权限目录敏感操作的页面/API 动作名，
// 防止适配器把任意字符串透传进再次认证参数绑定。
func validRBACPageReauthAction(action string) bool {
	switch action {
	case "permission.create", "permission.delete", "permission.state.builtin":
		return true
	default:
		return false
	}
}

// publicFormPaths 合并认证页与 MFA/找回页的匿名公开表单路径用途；
// 只取认证页映射会导致真实 serve 下 /login/forgot-password、
// /login/reset-password 等公开表单被当作会话表单校验而恒 403。
func publicFormPaths(prefix string) map[string]string {
	paths := login.UIPageAuthPublicFormPaths(prefix)
	for path, purpose := range login.UIPageMFAPublicFormPaths(prefix) {
		paths[path] = purpose
	}
	// 步骤 162/163 回归：邮箱变更验证是匿名公开表单，漏合并会让真实 serve 的
	// POST 被当作会话表单校验而恒 403 ACCESS_DENIED。
	for path, purpose := range login.UIPageAccountPublicFormPaths(prefix) {
		paths[path] = purpose
	}
	// OAuth 授权同意、设备确认、扫码确认是匿名公开表单；真实 serve 中它们与
	// /oauth 协议挂载共享路径，漏合并会让页面 POST 被当作会话表单 CSRF 校验而恒 403。
	for path, purpose := range login.UIPageOAuthPublicFormPaths(prefix) {
		paths[path] = purpose
	}
	return paths
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
