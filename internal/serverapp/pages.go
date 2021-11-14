package serverapp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/pagecsrf"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	"github.com/kagurazakayashi/EvernightLogin/internal/uiauthadapter"
)

// pageSessions 用真实会话服务实现内置页面框架的页面会话契约。
//
// 它只读取服务端会话 Cookie 并调用 session.Service 的校验方法，不接受任何客户端
// 自报身份字段；会话失效统一返回 login.ErrUISessionExpired，页面按过期处理。
type pageSessions struct {
	service *session.Service
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

// BuildPages 装配当前可用的内置页面。
//
// MVP 只注册账户入口页（登录/注册/邀请接受/邮箱验证/退出），其后端是真实
// authn/session/registration/onboarding 服务；其余页面（个人资料、管理、安全中心、
// MFA/Passkey、OAuth 同意、RBAC、应用、客服、审计、统计、报告、备份）在报告中
// 列为缺口：本 MVP 未装配其域服务或缺少生产适配器，因此不注册，避免出现"页面
// 能打开但后端是测试替身/伪造成功"的假装配。
func BuildPages(deps Deps, services *Services) (*Pages, error) {
	if services == nil || services.Sessions == nil || services.Authn == nil {
		return nil, fmt.Errorf("装配页面缺少会话或认证服务")
	}
	logger := deps.Logger
	now := deps.Now
	if now == nil {
		now = time.Now
	}
	adapter, err := uiauthadapter.New(uiauthadapter.Options{
		Authn:             services.Authn,
		Sessions:          services.Sessions,
		Registration:      services.Registration,
		Onboarding:        services.Onboarding,
		RegistrationStore: services.RegistrationStore,
		Credential:        services.Credential,
		RequireReview:     deps.Config.Registration.RequireReview,
		ResendComponentID: "login-server-page",
		Now:               now,
		Logger:            logger,
	})
	if err != nil {
		return nil, fmt.Errorf("构造账户入口页适配器失败: %w", err)
	}
	csrfProvider, err := pagecsrf.New(pagecsrf.Options{
		Keyring: deps.Keyring, TTL: 15 * time.Minute, Now: now})
	if err != nil {
		return nil, fmt.Errorf("构造页面 CSRF 提供者失败: %w", err)
	}
	web, err := login.NewWebUI(login.WebUIOptions{
		Prefix:     deps.Config.Server.PathPrefix,
		Session:    pageSessions{service: services.Sessions},
		FormTokens: csrfProvider,
		PageAuth: &login.UIPageAuthOptions{
			Backend:       adapter,
			PostLoginPath: "/",
		},
		Now:    now,
		Logger: logger,
	})
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
