package login

// 本文件是步骤 213 HTTP/Server 公共包迁移的兼容别名桥。
//
// httpapi 包持有 HTTP 与独立监听契约的唯一实现；internal/httpassemble 负责公开↔
// 内部转换，internal/httpsrv 负责监听/TLS 生命周期。根包保留原有公开符号
// （type/const/var 别名与薄函数转发），保证既有消费方与外部示例无需改动即可编译；
// 根包不对这些契约保留第二套实现或默认值。

import (
	"github.com/kagurazakayashi/EvernightLogin/httpapi"
)

// 可信身份与解析契约（定义与校验见 httpapi）。
type (
	// IdentityKind 是可信身份的类型。
	IdentityKind = httpapi.IdentityKind
	// Identity 是 HTTP 层建立并传递给服务层的可信身份。
	Identity = httpapi.Identity
	// IdentityResolver 从请求建立可信身份。
	IdentityResolver = httpapi.IdentityResolver
	// IdentityResolverFunc 是 IdentityResolver 的函数适配器。
	IdentityResolverFunc = httpapi.IdentityResolverFunc
)

const (
	// IdentityKindUser 表示已认证用户。
	IdentityKindUser = httpapi.IdentityKindUser
	// IdentityKindApplication 表示应用服务身份。
	IdentityKindApplication = httpapi.IdentityKindApplication
	// IdentityKindSystem 表示宿主系统组件身份。
	IdentityKindSystem = httpapi.IdentityKindSystem
)

// ErrIdentityInvalid 表示宿主提供的可信身份结构无效。
var ErrIdentityInvalid = httpapi.ErrIdentityInvalid

// HTTP Handler 选项与上限（定义见 httpapi）。
type (
	// HTTPOptions 是构造标准 net/http Handler 的显式依赖。
	HTTPOptions = httpapi.HTTPOptions
	// UIHTTPOptions 是 HTML 页面挂载配置。
	UIHTTPOptions = httpapi.UIHTTPOptions
)

const (
	// DefaultHTTPMaxBodyBytes 是 HTTP 请求体默认上限（1 MiB）。
	DefaultHTTPMaxBodyBytes = httpapi.DefaultHTTPMaxBodyBytes
	// MinHTTPMaxBodyBytes/MaxHTTPMaxBodyBytes 是 HTTP 请求体上限允许范围。
	MinHTTPMaxBodyBytes = httpapi.MinHTTPMaxBodyBytes
	MaxHTTPMaxBodyBytes = httpapi.MaxHTTPMaxBodyBytes
	// MaxHTTPPrefixBytes 是固定路径前缀最大长度。
	MaxHTTPPrefixBytes = httpapi.MaxHTTPPrefixBytes
	// OAuthReservedPathPrefix 是保留给未来 OAuth/OIDC 标准协议响应的路径前缀。
	OAuthReservedPathPrefix = httpapi.OAuthReservedPathPrefix
)

// HTTP 防护契约（定义与默认值见 httpapi）。
type (
	// RateLimitPolicy 是固定窗口限流策略。
	RateLimitPolicy = httpapi.RateLimitPolicy
	// RateLimitOptions 是多维有界限流配置。
	RateLimitOptions = httpapi.RateLimitOptions
	// CORSOptions 是精确来源 CORS 配置。
	CORSOptions = httpapi.CORSOptions
	// SecurityHeaderOptions 是安全响应头配置。
	SecurityHeaderOptions = httpapi.SecurityHeaderOptions
	// CSRFValidator 校验 Cookie 会话请求携带的 CSRF 令牌。
	CSRFValidator = httpapi.CSRFValidator
	// CSRFValidatorFunc 是 CSRFValidator 的函数适配器。
	CSRFValidatorFunc = httpapi.CSRFValidatorFunc
	// CSRFPolicy 是 Cookie 会话的 CSRF 防护契约。
	CSRFPolicy = httpapi.CSRFPolicy
	// PublicFormTokenValidator 校验公开页面匿名表单令牌。
	PublicFormTokenValidator = httpapi.PublicFormTokenValidator
	// CookiePolicy 是 Cookie 会话的安全属性策略（单一实现，internal/session 复用）。
	CookiePolicy = httpapi.CookiePolicy
	// HTTPProtectionOptions 是浏览器请求防护配置。
	HTTPProtectionOptions = httpapi.HTTPProtectionOptions
)

const (
	// DefaultHTTPRequestTimeout 是单请求处理默认期限。
	DefaultHTTPRequestTimeout = httpapi.DefaultHTTPRequestTimeout
	// MinHTTPRequestTimeout/MaxHTTPRequestTimeout 是请求期限范围。
	MinHTTPRequestTimeout = httpapi.MinHTTPRequestTimeout
	MaxHTTPRequestTimeout = httpapi.MaxHTTPRequestTimeout
	// DefaultHTTPMaxConcurrentRequests 是默认同时处理请求上限。
	DefaultHTTPMaxConcurrentRequests = httpapi.DefaultHTTPMaxConcurrentRequests
	// MinHTTPMaxConcurrentRequests/MaxHTTPMaxConcurrentRequests 是并发上限范围。
	MinHTTPMaxConcurrentRequests = httpapi.MinHTTPMaxConcurrentRequests
	MaxHTTPMaxConcurrentRequests = httpapi.MaxHTTPMaxConcurrentRequests
	// DefaultHTTPRateLimitMaxEntries 是每个限流维度的默认键容量。
	DefaultHTTPRateLimitMaxEntries = httpapi.DefaultHTTPRateLimitMaxEntries
	// DefaultHTTPRateLimitCleanupInterval 是限流过期条目默认清理间隔。
	DefaultHTTPRateLimitCleanupInterval = httpapi.DefaultHTTPRateLimitCleanupInterval
	// MaxHTTPTrustedProxies 是可信代理配置条目上限。
	MaxHTTPTrustedProxies = httpapi.MaxHTTPTrustedProxies
	// DefaultHTTPCSRFCookieName 是 Cookie 会话默认 Cookie 名。
	DefaultHTTPCSRFCookieName = httpapi.DefaultHTTPCSRFCookieName
	// DefaultHTTPCSRFTokenHeader 是默认 CSRF 令牌请求头。
	DefaultHTTPCSRFTokenHeader = httpapi.DefaultHTTPCSRFTokenHeader
)

// DefaultRateLimitOptions 返回安全默认多维限流配置（唯一实现见 httpapi）。
func DefaultRateLimitOptions() RateLimitOptions { return httpapi.DefaultRateLimitOptions() }

// DefaultCookiePolicy 返回会话 Cookie 的安全默认值（唯一实现见 httpapi）。
func DefaultCookiePolicy() CookiePolicy { return httpapi.DefaultCookiePolicy() }

// 独立监听服务契约（定义见 httpapi）。
type (
	// ServerOptions 是构造独立监听服务的显式依赖。
	ServerOptions = httpapi.ServerOptions
	// TLSCertificateStatus 是单张服务器叶证书的脱敏状态。
	TLSCertificateStatus = httpapi.TLSCertificateStatus
	// TLSClientTrustAnchor 是单个客户端信任 CA 的脱敏状态。
	TLSClientTrustAnchor = httpapi.TLSClientTrustAnchor
	// TLSClientAuthStatus 是客户端证书认证的只读状态。
	TLSClientAuthStatus = httpapi.TLSClientAuthStatus
	// TLSStatus 是本地 TLS 证书的只读状态。
	TLSStatus = httpapi.TLSStatus
)
