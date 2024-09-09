// Package httpassemble 把公开 HTTP 契约（httpapi）转换为内部传输引擎
// （internal/transport）配置并组装 net/http Handler。
//
// 职责边界：
//   - 本包只做「公开选项 → 内部配置」的适配、错误码注册表投影与身份适配，不复制
//     任何限流/CSRF/安全头/路由校验逻辑（唯一实现在 internal/transport）。
//   - 不创建监听、不启动协程；生命周期归 internal/httpsrv 与宿主。
//   - 不 import 根包门面，避免循环依赖；请求编号与错误码使用 errs 叶子包。
package httpassemble

import (
	"context"
	"net/http"

	"github.com/kagurazakayashi/EvernightLogin/errs"
	"github.com/kagurazakayashi/EvernightLogin/httpapi"
	"github.com/kagurazakayashi/EvernightLogin/internal/transport"
)

// NewHTTPHandler 构造标准 net/http Handler。
//
// 公开选项非法时返回 CONFIG_INVALID 统一错误；不创建任何监听、协程或文件。版本
// 号由根门面从构建信息传入（本包不依赖根包）。
func NewHTTPHandler(options httpapi.HTTPOptions, version string) (http.Handler, error) {
	protection, err := normalizeProtection(options.Protection)
	if err != nil {
		return nil, errs.NewAppError(errs.CodeConfigInvalid, "HTTP 防护配置无效",
			errs.WithCause(err))
	}
	handler, err := transport.New(transport.Options{
		Prefix:            options.Prefix,
		MaxBodyBytes:      options.MaxBodyBytes,
		ErrorCodes:        errorCodes(),
		NewRequestID:      errs.NewRequestID,
		ValidateRequestID: errs.ValidateRequestID,
		ResolveIdentity:   resolveIdentity(options.IdentityResolver),
		Logger:            options.Logger,
		AccessLogWriter:   options.AccessLogWriter,
		OnAccessLogError:  options.OnAccessLogError,
		Now:               options.Now,
		Version:           version,
		Protection:        protection,
		UI:                uiConfig(options.UI),
		PageRoutes:        pageRoutes(options.UI),
	})
	if err != nil {
		return nil, errs.NewAppError(errs.CodeConfigInvalid, "HTTP 处理程序配置无效",
			errs.WithCause(err))
	}
	return handler, nil
}

// OpenAPIDocument 生成指定路径前缀的机器可读 OpenAPI 文档；错误码 enum 与
// x-login-error-registry 直接来自错误码注册表，避免新增错误码遗漏。非法前缀返回
// CONFIG_INVALID。
func OpenAPIDocument(prefix, version string) ([]byte, error) {
	document, err := transport.OpenAPIDocument(prefix, errorCodes(), version)
	if err != nil {
		return nil, errs.NewAppError(errs.CodeConfigInvalid, "OpenAPI 文档前缀无效",
			errs.WithCause(err))
	}
	return document, nil
}

// errorCodes 把错误码注册表投影为传输层只读结构，避免内部包反向依赖根包。
func errorCodes() []transport.ErrorCodeInfo {
	registered := errs.RegisteredErrorCodes()
	infos := make([]transport.ErrorCodeInfo, 0, len(registered))
	for _, definition := range registered {
		infos = append(infos, transport.ErrorCodeInfo{
			Code:       string(definition.Code),
			Category:   string(definition.Category),
			Message:    definition.DefaultMessage,
			HTTPStatus: definition.HTTPStatus,
		})
	}
	return infos
}

// normalizeProtection 把公开防护选项转换为内部配置。nil 表示使用内部安全默认值；
// 非 nil 时 CookiePolicy 先做严格校验。这里是唯一转换点，不复制校验逻辑。
func normalizeProtection(options *httpapi.HTTPProtectionOptions) (*transport.ProtectionOptions, error) {
	if options == nil {
		return nil, nil
	}
	if options.CookiePolicy != nil {
		if err := options.CookiePolicy.Validate(); err != nil {
			return nil, err
		}
	}
	protection := &transport.ProtectionOptions{
		TrustedProxies:        append([]string(nil), options.TrustedProxies...),
		RequestTimeout:        options.RequestTimeout,
		MaxConcurrentRequests: options.MaxConcurrentRequests,
		CORS: transport.CORSConfig{
			AllowedOrigins:   append([]string(nil), options.CORS.AllowedOrigins...),
			AllowCredentials: options.CORS.AllowCredentials,
			AllowedMethods:   append([]string(nil), options.CORS.AllowedMethods...),
			AllowedHeaders:   append([]string(nil), options.CORS.AllowedHeaders...),
			ExposedHeaders:   append([]string(nil), options.CORS.ExposedHeaders...),
			MaxAge:           options.CORS.MaxAge,
		},
		ExpensivePaths: append([]string(nil), options.ExpensivePaths...),
	}
	rate := options.RateLimit
	protection.RateLimit = transport.RateLimitConfig{
		Disabled:        rate.Disabled,
		ClientIP:        rateRule(rate.ClientIP),
		User:            rateRule(rate.User),
		Application:     rateRule(rate.Application),
		Endpoint:        rateRule(rate.Endpoint),
		Expensive:       rateRule(rate.Expensive),
		Capacity:        rate.Capacity,
		CleanupInterval: rate.CleanupInterval,
	}
	if options.SecurityHeaders != nil {
		protection.SecurityHeaders = transport.SecurityHeaderConfig{
			ContentSecurityPolicy: options.SecurityHeaders.ContentSecurityPolicy,
			AllowFraming:          options.SecurityHeaders.AllowFraming,
			EnableHSTS:            options.SecurityHeaders.EnableHSTS,
		}
	}
	protection.CSRF = transport.CSRFConfig{
		Enabled:          options.CSRF.Enabled,
		CookieName:       options.CSRF.CookieName,
		TokenHeader:      options.CSRF.TokenHeader,
		TokenFormField:   options.CSRF.TokenFormField,
		AllowedOrigins:   append([]string(nil), options.CSRF.AllowedOrigins...),
		RequireAllUnsafe: options.CSRF.RequireForAllUnsafeRequests,
		PublicFormPaths:  append([]string(nil), options.CSRF.PublicFormPaths...),
	}
	protection.CSRF.ValidatePublicToken = options.CSRF.PublicTokenValidator
	if options.CSRF.TokenValidator != nil {
		protection.CSRF.ValidateToken = func(ctx context.Context, request *http.Request, token string) error {
			return options.CSRF.TokenValidator.ValidateCSRFToken(ctx, request, token)
		}
	}
	return protection, nil
}

// rateRule 把公开限流规则转换为内部限流规则。
func rateRule(rule httpapi.RateLimitPolicy) transport.RateLimitRule {
	return transport.RateLimitRule{Limit: rule.Limit, Window: rule.Window}
}

// uiConfig 把公开 UI 挂载配置转换为传输层内部配置。
func uiConfig(options *httpapi.UIHTTPOptions) *transport.UIConfig {
	if options == nil {
		return nil
	}
	return &transport.UIConfig{Handler: options.Handler,
		PageContentSecurityPolicy: options.PageContentSecurityPolicy}
}

// pageRoutes 从页面处理器提取实际注册的命名路由投影，供 OpenAPI 使用。
//
// 只接受实现 httpapi.UIPageRouteLister 的处理器（内置 *ui.WebUI 实现它）；接口
// 契约放在叶子包 httpapi，装配层不 import ui，避免 ui 同包测试
// （import internal/httpassemble）形成导入环。未实现时返回 nil，文档只含 JSON API。
func pageRoutes(options *httpapi.UIHTTPOptions) []transport.PageRoute {
	if options == nil || options.Handler == nil {
		return nil
	}
	lister, ok := options.Handler.(httpapi.UIPageRouteLister)
	if !ok {
		return nil
	}
	routes := lister.OpenAPIPageRoutes()
	if len(routes) == 0 {
		return nil
	}
	projected := make([]transport.PageRoute, 0, len(routes))
	for _, route := range routes {
		projected = append(projected, transport.PageRoute{
			Name:   route.Name,
			Method: route.Method,
			Path:   route.Path,
			Access: route.Access,
		})
	}
	return projected
}

// resolveIdentity 把公开身份解析契约适配为内部函数，并保证失败时只使用稳定的
// 公开错误码与消息。
func resolveIdentity(resolver httpapi.IdentityResolver) transport.ResolveIdentityFunc {
	if resolver == nil {
		return nil
	}
	return func(ctx context.Context, request *http.Request) (transport.Identity, error) {
		identity, err := resolver.ResolveIdentity(ctx, request)
		if err != nil {
			return transport.Identity{}, identityFailure(err)
		}
		if err := identity.Validate(); err != nil {
			return transport.Identity{}, identityFailure(err)
		}
		return transport.Identity{
			Kind:      string(identity.Kind),
			SubjectID: identity.SubjectID,
			AppID:     identity.AppID,
		}, nil
	}
}

// identityFailure 把身份建立失败映射为内部 IdentityError，保留已注册 AppError 的
// 公开码与状态；其他错误统一 AUTH_FAILED，绝不泄露内部原因。
func identityFailure(err error) *transport.IdentityError {
	if appError, ok := errs.AsAppError(err); ok {
		status := appError.HTTPStatus()
		if status < 400 || status > 599 {
			status = http.StatusUnauthorized
		}
		return &transport.IdentityError{
			Code:    string(appError.Code()),
			Status:  status,
			Message: appError.Message(),
		}
	}
	return &transport.IdentityError{
		Code:    string(errs.CodeAuthFailed),
		Status:  http.StatusUnauthorized,
		Message: "无法完成登录",
	}
}
