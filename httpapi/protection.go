package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/proxytrust"
)

const (
	// DefaultHTTPRequestTimeout 是单请求处理默认期限；超时返回 504。
	DefaultHTTPRequestTimeout = 30 * time.Second
	// MinHTTPRequestTimeout/MaxHTTPRequestTimeout 是请求期限范围。
	MinHTTPRequestTimeout = 10 * time.Millisecond
	MaxHTTPRequestTimeout = 5 * time.Minute
	// DefaultHTTPMaxConcurrentRequests 是默认同时处理请求上限。
	DefaultHTTPMaxConcurrentRequests = 256
	// MinHTTPMaxConcurrentRequests/MaxHTTPMaxConcurrentRequests 是并发上限范围。
	MinHTTPMaxConcurrentRequests = 1
	MaxHTTPMaxConcurrentRequests = 1024
	// DefaultHTTPRateLimitMaxEntries 是每个限流维度的默认键容量。
	DefaultHTTPRateLimitMaxEntries = 4096
	// DefaultHTTPRateLimitCleanupInterval 是限流过期条目默认清理间隔。
	DefaultHTTPRateLimitCleanupInterval = 30 * time.Second
	// MaxHTTPTrustedProxies 是可信代理配置条目上限。
	MaxHTTPTrustedProxies = proxytrust.MaxTrustedProxies
	// DefaultHTTPCSRFCookieName 是 Cookie 会话默认 Cookie 名；__Host- 前缀要求
	// Secure、Path=/ 且无 Domain。当前步骤不创建会话 Cookie，只作为 CSRF 防护
	// 契约中的会话 Cookie 识别名。
	DefaultHTTPCSRFCookieName = "__Host-login_session"
	// DefaultHTTPCSRFTokenHeader 是默认 CSRF 令牌请求头。
	DefaultHTTPCSRFTokenHeader = "X-CSRF-Token"
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
		ClientIP:        RateLimitPolicy{Limit: 600, Window: time.Minute},
		User:            RateLimitPolicy{Limit: 300, Window: time.Minute},
		Application:     RateLimitPolicy{Limit: 300, Window: time.Minute},
		Endpoint:        RateLimitPolicy{Limit: 1200, Window: time.Minute},
		Expensive:       RateLimitPolicy{Limit: 30, Window: time.Minute},
		Capacity:        DefaultHTTPRateLimitMaxEntries,
		CleanupInterval: DefaultHTTPRateLimitCleanupInterval,
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
// 不输出 HSTS。HTML 页面可通过 ContentSecurityPolicy 显式放宽；AllowFraming 只
// 放宽为同源嵌入；EnableHSTS 只在宿主确认走 HTTPS 时启用。
type SecurityHeaderOptions struct {
	ContentSecurityPolicy string
	AllowFraming          bool
	EnableHSTS            bool
}

// CSRFValidator 校验 Cookie 会话请求携带的 CSRF 令牌。实现必须完成真正的服务端
// 校验（例如与会话绑定的随机令牌比较）；返回错误表示校验失败。
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

// CSRFPolicy 是 Cookie 会话的 CSRF 防护契约。
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
	// PublicFormPaths 是允许匿名 HTML 表单 POST 的路径（已含部署前缀、规范化）。
	// 命中时即使无会话 Cookie 也要求 Origin/Referer 与 PublicTokenValidator。
	PublicFormPaths []string
	// PublicTokenValidator 校验公开表单匿名令牌（参数含规范化路径用于用途绑定）。
	PublicTokenValidator PublicFormTokenValidator
}

// PublicFormTokenValidator 校验公开页面匿名表单令牌。
type PublicFormTokenValidator func(ctx context.Context, request *http.Request,
	path, token string) error

// HTTPProtectionOptions 是浏览器请求防护配置。HTTPOptions.Protection 为 nil 时
// 使用全部安全默认值；非 nil 时零值字段使用默认值，显式值覆盖默认。
//
// 限流默认与语义见 RateLimitOptions；请求超时默认 30 秒、并发默认 256。
// CORS 默认关闭；CSRF 默认关闭；安全头始终启用；会话 Cookie 策略仅作为契约，
// 本步骤不创建任何 Cookie。
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
	// CSRF 是 Cookie 会话的 CSRF 防护契约；默认关闭。
	CSRF CSRFPolicy
	// CookiePolicy 是会话 Cookie 的安全属性；nil 使用 DefaultCookiePolicy。
	CookiePolicy *CookiePolicy
	// SecurityHeaders 是安全响应头；nil 使用 API 安全默认值。
	SecurityHeaders *SecurityHeaderOptions
	// ExpensivePaths 是标记为昂贵请求的完整路径（包含 Handler Prefix）。只有
	// 启用昂贵请求预算时才能配置，否则构造失败。
	ExpensivePaths []string
}
