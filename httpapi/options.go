package httpapi

import (
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/httppolicy"
)

const (
	// DefaultHTTPMaxBodyBytes 是 HTTP 请求体默认上限（1 MiB）。
	DefaultHTTPMaxBodyBytes int64 = 1 << 20
	// MinHTTPMaxBodyBytes/MaxHTTPMaxBodyBytes 是 HTTP 请求体上限允许范围。
	MinHTTPMaxBodyBytes int64 = 1 << 10
	MaxHTTPMaxBodyBytes int64 = 16 << 20
	// MaxHTTPPrefixBytes 是固定路径前缀最大长度（规则见 httppolicy）。
	MaxHTTPPrefixBytes = httppolicy.MaxPrefixBytes
	// OAuthReservedPathPrefix 是保留给未来 OAuth/OIDC 标准协议响应的路径前缀；
	// 该前缀下的响应不使用统一业务错误 JSON。
	OAuthReservedPathPrefix = "/oauth2"
)

// HTTPOptions 是构造标准 net/http Handler 的显式依赖。
//
// Handler 只提供安全的最小能力：健康检查、OpenAPI 文档与默认启用的浏览器
// 请求防护（限流、超时/并发、CORS、安全响应头、Cookie 会话 CSRF 契约）。身份
// 解析函数用于受保护接口与宿主中间件；公开健康端点不依赖它。
type HTTPOptions struct {
	// Prefix 是固定路径前缀：空字符串或 /segment(/segment)*；不能以斜杠结尾。
	// 前缀不匹配的路径一律 404，不做清理重写。
	Prefix string
	// MaxBodyBytes 是请求体上限；0 使用 DefaultHTTPMaxBodyBytes。
	MaxBodyBytes int64
	// IdentityResolver 建立可信身份；nil 表示本 Handler 不建立身份，需要身份的
	// 路由会默认拒绝（fail-closed）。
	IdentityResolver IdentityResolver
	// Logger 是运行日志器；nil 时使用丢弃输出。Logger 与访问日志、审计分开。
	Logger *slog.Logger
	// AccessLogWriter 是 W3C Extended 访问日志输出；nil 表示不写访问日志。
	// 独立服务必须注入，并把输出交给受控的日志轮转/保留流程。
	AccessLogWriter io.Writer
	// OnAccessLogError 接收访问日志写入失败；nil 时通过 Logger.Error 告警。
	// 访问日志写入失败不改变 HTTP 响应，也不影响安全审计语义。
	OnAccessLogError func(error)
	// Now 是可注入时钟；nil 使用 time.Now。访问日志时间、限流窗口与测试使用该时钟。
	Now func() time.Time
	// Protection 是限流、资源预算、请求超时/并发、CORS、安全响应头、Cookie 与
	// CSRF 契约；nil 使用安全默认值。详见 HTTPProtectionOptions。
	Protection *HTTPProtectionOptions
	// UI 是可选的内置 HTML 页面处理器（例如 NewWebUI 的返回值）。挂载后非 API
	// 路径交给页面处理器，并复用同一请求编号、访问日志、客户端 IP 限流与 CSRF
	// 中间件；页面显式使用 PageContentSecurityPolicy（不再使用 API 的
	// default-src 'none'）。nil 表示本 Handler 只提供 API，不服务 HTML。
	UI *UIHTTPOptions
}

// UIHTTPOptions 是 HTML 页面挂载配置。Handler 由宿主提供（通常为 NewWebUI 的
// 返回值），PageContentSecurityPolicy 必须包含页面安全基线，可用根包导出的
// DefaultUIPageContentSecurityPolicy。
type UIHTTPOptions struct {
	Handler                   http.Handler
	PageContentSecurityPolicy string
}
