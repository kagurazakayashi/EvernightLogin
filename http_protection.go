package login

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/transport"
)

const (
	// DefaultHTTPRequestTimeout 是单请求处理默认期限；超时返回 504。
	DefaultHTTPRequestTimeout = transport.DefaultRequestTimeout
	// MinHTTPRequestTimeout/MaxHTTPRequestTimeout 是请求期限范围。
	MinHTTPRequestTimeout = transport.MinRequestTimeout
	MaxHTTPRequestTimeout = transport.MaxRequestTimeout
	// DefaultHTTPMaxConcurrentRequests 是默认同时处理请求上限。
	DefaultHTTPMaxConcurrentRequests = transport.DefaultMaxConcurrentRequests
	// MinHTTPMaxConcurrentRequests/MaxHTTPMaxConcurrentRequests 是并发上限范围。
	MinHTTPMaxConcurrentRequests = transport.MinConcurrentRequests
	MaxHTTPMaxConcurrentRequests = transport.MaxConcurrentRequests
	// DefaultHTTPRateLimitMaxEntries 是每个限流维度的默认键容量。
	DefaultHTTPRateLimitMaxEntries = transport.DefaultRateLimitMaxEntries
	// DefaultHTTPRateLimitCleanupInterval 是限流过期条目默认清理间隔。
	DefaultHTTPRateLimitCleanupInterval = transport.DefaultRateLimitCleanupAfter
	// MaxHTTPTrustedProxies 是可信代理配置条目上限。
	MaxHTTPTrustedProxies = transport.MaxTrustedProxies
	// DefaultHTTPCSRFCookieName 是未来 Cookie 会话默认 Cookie 名；当前步骤不创建
	// 会话 Cookie，只作为 CSRF 防护契约中的会话 Cookie 识别名。
	DefaultHTTPCSRFCookieName = transport.DefaultCSRFCookieName
	// DefaultHTTPCSRFTokenHeader 是默认 CSRF 令牌请求头。
	DefaultHTTPCSRFTokenHeader = transport.DefaultCSRFTokenHeader
)

// RateLimitPolicy 是固定窗口限流策略：Window 内最多允许 Limit 个请求。两者都
// 为 0 表示该维度不启用；只设置一个值会被 NewHTTPHandler 拒绝。
type RateLimitPolicy struct {
	Limit  int
	Window time.Duration
}

// RateLimitOptions 是多维有界限流配置。
//
// 语义：
//   - Disabled=true 关闭全部限流；
//   - 全部字段为零时使用安全默认规则（地址 600/分钟、用户 300/分钟、应用
//     300/分钟、接口 1200/分钟、昂贵请求 30/分钟）；
//   - 只要显式设置了任一规则/容量/清理间隔，就只启用显式设置了 Limit 和 Window
//     的维度，未设置维度停用；只设置容量/清理间隔而不启用任何维度会被拒绝；
//   - Capacity 是每个维度同时跟踪的最大键数，默认 4096；容量耗尽时清理过期
//     条目，仍不足则拒绝新键（fail-closed）。
//
// 用户与应用维度只使用 IdentityResolver 建立的可信身份；匿名请求绝不按客户端
// 自填的 user_id/app_id 分桶。
type RateLimitOptions struct {
	Disabled        bool
	ClientIP        RateLimitPolicy
	User            RateLimitPolicy
	Application     RateLimitPolicy
	Endpoint        RateLimitPolicy
	Expensive       RateLimitPolicy
	Capacity        int
	CleanupInterval time.Duration
}

// DefaultRateLimitOptions 返回安全默认多维限流配置。
func DefaultRateLimitOptions() RateLimitOptions {
	return RateLimitOptions{
		ClientIP:        RateLimitPolicy{Limit: transport.DefaultClientIPRateLimit.Limit, Window: transport.DefaultClientIPRateLimit.Window},
		User:            RateLimitPolicy{Limit: transport.DefaultUserRateLimit.Limit, Window: transport.DefaultUserRateLimit.Window},
		Application:     RateLimitPolicy{Limit: transport.DefaultApplicationRateLimit.Limit, Window: transport.DefaultApplicationRateLimit.Window},
		Endpoint:        RateLimitPolicy{Limit: transport.DefaultEndpointRateLimit.Limit, Window: transport.DefaultEndpointRateLimit.Window},
		Expensive:       RateLimitPolicy{Limit: transport.DefaultExpensiveRateLimit.Limit, Window: transport.DefaultExpensiveRateLimit.Window},
		Capacity:        transport.DefaultRateLimitMaxEntries,
		CleanupInterval: transport.DefaultRateLimitCleanupAfter,
	}
}

// CORSOptions 是精确来源 CORS 配置。AllowedOrigins 为空表示禁用 CORS；每个来源
// 必须是 scheme://host[:port] 精确匹配，不支持通配符。AllowCredentials 为 true
// 时仍要求精确来源，绝不回显任意 Origin。CORS 只是浏览器读取规则，不代替身份、
// 权限或 CSRF 校验。
type CORSOptions struct {
	AllowedOrigins   []string
	AllowCredentials bool
	AllowedMethods   []string
	AllowedHeaders   []string
	ExposedHeaders   []string
	MaxAge           time.Duration
}

// SecurityHeaderOptions 是安全响应头配置。零值使用 API 默认 CSP、DENY 防嵌入、
// 不输出 HSTS。未来扫码/授权 HTML 页面可通过 ContentSecurityPolicy 显式放宽；
// AllowFraming 只放宽为同源嵌入；EnableHSTS 只在宿主确认走 HTTPS 时启用。
type SecurityHeaderOptions struct {
	ContentSecurityPolicy string
	AllowFraming          bool
	EnableHSTS            bool
}

// CSRFValidator 校验未来 Cookie 会话请求携带的 CSRF 令牌。实现必须完成真正的
// 服务端校验（例如与会话绑定的随机令牌比较）；返回错误表示校验失败。
type CSRFValidator interface {
	ValidateCSRFToken(ctx context.Context, request *http.Request, token string) error
}

// CSRFValidatorFunc 是 CSRFValidator 的函数适配器。
type CSRFValidatorFunc func(ctx context.Context, request *http.Request, token string) error

// ValidateCSRFToken 实现 CSRFValidator。
func (f CSRFValidatorFunc) ValidateCSRFToken(ctx context.Context, request *http.Request, token string) error {
	if f == nil {
		return fmt.Errorf("CSRF 令牌校验器为空")
	}
	return f(ctx, request, token)
}

// CSRFPolicy 是未来 Cookie 会话的 CSRF 防护契约。
//
// 启用后，POST/PUT/PATCH/DELETE 在检测到 CookieName 会话 Cookie（或设置
// RequireForAllUnsafeRequests）时必须同时满足：Origin/Referer 的精确 origin
// 命中 AllowedOrigins，且 TokenHeader 中唯一令牌通过 TokenValidator。安全方法
// GET/HEAD/OPTIONS/TRACE 不要求令牌，以兼容扫码与顶层跨站授权跳转；form_post
// 等跨站写流程必须由协议层显式处理并配置来源，不能借 CORS 或本策略绕过。
type CSRFPolicy struct {
	Enabled     bool
	CookieName  string
	TokenHeader string
	// TokenFormField 是服务端渲染 HTML 表单的 CSRF 隐藏字段名（默认 csrf_token）；
	// 页面框架用它做无 JavaScript 表单提交，仍由同一 TokenValidator 校验并保留
	// Origin/Referer 检查。空字符串使用默认值。
	TokenFormField              string
	AllowedOrigins              []string
	RequireForAllUnsafeRequests bool
	TokenValidator              CSRFValidator
}

// CookiePolicy 是未来会话 Cookie 的安全属性策略。零值不是有效策略；请使用
// DefaultCookiePolicy 或显式设置。默认 Secure/HttpOnly/Lax/Path=/ 适合同站与
// 顶层导航；仅当协议端点确实需要跨站 Cookie 时才可 SameSite=None（仍必须
// Secure），并必须由协议层完成来源/CSRF 校验，不能用 SameSite=None 代替 CSRF。
// __Host- 前缀 Cookie 必须 Secure、Path=/ 且无 Domain。
type CookiePolicy struct {
	Secure   bool
	HttpOnly bool
	SameSite http.SameSite
	Path     string
	Domain   string
	MaxAge   time.Duration
}

// DefaultCookiePolicy 返回会话 Cookie 的安全默认值：Secure、HttpOnly、
// SameSite=Lax、Path=/，适合顶层导航与扫码后的同站流程。
func DefaultCookiePolicy() CookiePolicy {
	return CookiePolicy{
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	}
}

// Validate 校验 Cookie 策略：SameSite 必须明确且合法，SameSite=None 必须 Secure，
// Path 必须是安全的绝对路径，Domain 必须是规范主机名；__Host-/__Secure- 前缀
// 规则强制满足。
func (p CookiePolicy) Validate() error {
	switch p.SameSite {
	case http.SameSiteLaxMode, http.SameSiteStrictMode, http.SameSiteNoneMode:
	default:
		return fmt.Errorf("Cookie SameSite 必须明确设置为 Lax、Strict 或 None")
	}
	if p.SameSite == http.SameSiteNoneMode && !p.Secure {
		return fmt.Errorf("SameSite=None 的 Cookie 必须启用 Secure")
	}
	if len(p.Path) == 0 || p.Path[0] != '/' || len(p.Path) > 256 {
		return fmt.Errorf("Cookie Path 必须是 / 开头的绝对路径")
	}
	for _, character := range p.Path {
		if character < 0x21 || character > 0x7e || character == ';' || character == ',' {
			return fmt.Errorf("Cookie Path 包含不安全字符")
		}
	}
	if err := validateCookieDomain(p.Domain); err != nil {
		return err
	}
	if p.MaxAge < 0 || p.MaxAge > 365*24*time.Hour {
		return fmt.Errorf("Cookie MaxAge 超出允许范围")
	}
	return nil
}

// NewCookie 按策略构造 Cookie。name/value 必须非空；同名 Cookie 的创建仍由未来
// 会话服务负责，本方法只保证属性安全。
func (p CookiePolicy) NewCookie(name, value string) (*http.Cookie, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if !isCookieToken(name) {
		return nil, fmt.Errorf("Cookie 名无效")
	}
	if value == "" || len(value) > 4096 {
		return nil, fmt.Errorf("Cookie 值无效")
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f || character == ';' || character == ',' {
			return nil, fmt.Errorf("Cookie 值包含不安全字符")
		}
	}
	if strings.HasPrefix(name, "__Host-") {
		if !p.Secure || p.Path != "/" || p.Domain != "" {
			return nil, fmt.Errorf("__Host- Cookie 必须 Secure、Path=/ 且不能设置 Domain")
		}
	}
	if strings.HasPrefix(name, "__Secure-") && !p.Secure {
		return nil, fmt.Errorf("__Secure- Cookie 必须启用 Secure")
	}
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     p.Path,
		Domain:   p.Domain,
		MaxAge:   int(p.MaxAge / time.Second),
		Secure:   p.Secure,
		HttpOnly: p.HttpOnly,
		SameSite: p.SameSite,
	}, nil
}

// validateCookieDomain 校验可选 Domain：空表示主机专用 Cookie；非空时不允许带
// 端口、路径或前导点。
func validateCookieDomain(domain string) error {
	if domain == "" {
		return nil
	}
	if len(domain) > 253 || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return fmt.Errorf("Cookie Domain 无效")
	}
	for index := 0; index < len(domain); index++ {
		character := domain[index]
		if character <= 0x20 || character >= 0x7f {
			return fmt.Errorf("Cookie Domain 无效")
		}
		switch character {
		case '/', '\\', ':', ';', ',', '?', '#', '@', '[', ']':
			return fmt.Errorf("Cookie Domain 无效")
		}
	}
	return nil
}

// isCookieToken 报告 Cookie 名是否为 RFC 6265 token。
func isCookieToken(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') {
			continue
		}
		switch character {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}

// HTTPProtectionOptions 是浏览器请求防护配置。HTTPOptions.Protection 为 nil 时
// 使用全部安全默认值；非 nil 时零值字段使用下表中安全默认值，显式值覆盖默认。
//
// 限流默认与 Rates 语义见 RateLimitOptions；请求超时默认 30 秒、并发默认 256。
// CORS 默认关闭；CSRF 默认关闭；安全头始终启用；会话 Cookie 策略仅作为未来契约，
// 本步不创建任何 Cookie。
type HTTPProtectionOptions struct {
	// TrustedProxies 是唯一允许提供 Forwarded/X-Forwarded-For 等转发头的直连
	// 代理 IP/CIDR；为空时完全忽略转发头，防止客户端伪造地址。独立监听服务
	// （NewServer）还会用同源配置做 Host 与协议/域名边界校验；两处应使用同一份
	// 配置（通常来自 ServerConfig.TrustedProxies）。
	TrustedProxies []string
	// RateLimit 是多维限流配置。
	RateLimit RateLimitOptions
	// RequestTimeout 是请求处理期限；0 默认 30 秒。
	RequestTimeout time.Duration
	// MaxConcurrentRequests 是同时处理请求上限；0 默认 256。
	MaxConcurrentRequests int
	// CORS 是精确来源 CORS 配置；AllowedOrigins 为空表示关闭。
	CORS CORSOptions
	// CSRF 是未来 Cookie 会话的 CSRF 防护契约；默认关闭。
	CSRF CSRFPolicy
	// CookiePolicy 是未来会话 Cookie 的安全属性；nil 使用 DefaultCookiePolicy。
	CookiePolicy *CookiePolicy
	// SecurityHeaders 是安全响应头；nil 使用 API 安全默认值。
	SecurityHeaders *SecurityHeaderOptions
	// ExpensivePaths 是标记为昂贵请求的完整路径（包含 Handler Prefix）。只有
	// 启用昂贵请求预算时才能配置，否则构造失败。
	ExpensivePaths []string
}

// normalizeHTTPProtection 把公开防护选项转换为内部配置。nil 表示使用内部安全
// 默认值；非 nil 时 CookiePolicy 会先做严格校验。
func normalizeHTTPProtection(options *HTTPProtectionOptions) (*transport.ProtectionOptions, error) {
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
		ClientIP:        transport.RateLimitRule{Limit: rate.ClientIP.Limit, Window: rate.ClientIP.Window},
		User:            transport.RateLimitRule{Limit: rate.User.Limit, Window: rate.User.Window},
		Application:     transport.RateLimitRule{Limit: rate.Application.Limit, Window: rate.Application.Window},
		Endpoint:        transport.RateLimitRule{Limit: rate.Endpoint.Limit, Window: rate.Endpoint.Window},
		Expensive:       transport.RateLimitRule{Limit: rate.Expensive.Limit, Window: rate.Expensive.Window},
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
	}
	if options.CSRF.TokenValidator != nil {
		protection.CSRF.ValidateToken = func(ctx context.Context, request *http.Request, token string) error {
			return options.CSRF.TokenValidator.ValidateCSRFToken(ctx, request, token)
		}
	}
	return protection, nil
}
