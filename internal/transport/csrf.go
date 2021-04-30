package transport

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const (
	// DefaultCSRFCookieName 是未来 Cookie 会话使用的默认会话 Cookie 名。__Host-
	// 前缀要求 Secure、Path=/ 且无 Domain；当前步骤不创建会话 Cookie，此名称是
	// CSRF 中间件识别“Cookie 会话请求”的契约。
	DefaultCSRFCookieName = "__Host-login_session"
	// DefaultCSRFTokenHeader 是默认 CSRF 令牌请求头。
	DefaultCSRFTokenHeader = "X-CSRF-Token"
	// maxCSRFTokenBytes 是 CSRF 令牌长度上限，避免超长头放大处理开销。
	maxCSRFTokenBytes = 512
)

// csrfPolicy 是未来 Cookie 会话的 CSRF 防护契约。启用后，不安全方法（POST/
// PUT/PATCH/DELETE）在检测到会话 Cookie（或要求所有不安全请求）时必须同时：
//
//  1. 携带同站精确来源：Origin 或 Referer 的 origin 必须命中 AllowedOrigins；
//  2. 携带唯一 CSRF 令牌，并由宿主注入的 ValidateToken 完成服务端校验。
//
// 安全方法（GET/HEAD/OPTIONS/TRACE）不要求 CSRF 令牌，以兼容顶层跨站授权跳转
// 与扫码授权页面；协议端点若使用 form_post 等跨站写请求，必须由协议层单独校验
// 并显式配置来源，不能借 CORS 或本中间件绕过。CORS 允许某个来源不会跳过 CSRF。
type csrfPolicy struct {
	enabled          bool
	cookieName       string
	tokenHeader      string
	origins          map[string]struct{}
	requireAllUnsafe bool
	validateToken    func(ctx context.Context, request *http.Request, token string) error
}

// newCSRFPolicy 校验并构造 CSRF 策略。未启用时忽略其余字段；启用时来源与校验器
// 必须显式提供，避免“看似受保护但未校验”的静默降级。
func newCSRFPolicy(config CSRFConfig) (*csrfPolicy, error) {
	if !config.Enabled {
		return &csrfPolicy{}, nil
	}
	cookieName := config.CookieName
	if cookieName == "" {
		cookieName = DefaultCSRFCookieName
	}
	if err := validateCSRFCookieName(cookieName); err != nil {
		return nil, fmt.Errorf("CSRF Cookie 名无效")
	}
	tokenHeader := config.TokenHeader
	if tokenHeader == "" {
		tokenHeader = DefaultCSRFTokenHeader
	}
	if !isHTTPToken(tokenHeader) {
		return nil, fmt.Errorf("CSRF 令牌请求头无效")
	}
	if config.ValidateToken == nil {
		return nil, fmt.Errorf("启用 CSRF 时必须提供令牌校验器")
	}
	if len(config.AllowedOrigins) == 0 {
		return nil, fmt.Errorf("启用 CSRF 时必须提供精确允许来源")
	}
	origins := make(map[string]struct{}, len(config.AllowedOrigins))
	for _, raw := range config.AllowedOrigins {
		canonical, err := canonicalOrigin(raw)
		if err != nil {
			return nil, fmt.Errorf("CSRF 允许来源无效: %w", err)
		}
		origins[canonical] = struct{}{}
	}
	return &csrfPolicy{
		enabled:          true,
		cookieName:       cookieName,
		tokenHeader:      tokenHeader,
		origins:          origins,
		requireAllUnsafe: config.RequireAllUnsafe,
		validateToken:    config.ValidateToken,
	}, nil
}

// check 对不安全请求执行来源与令牌校验。它只保护 Cookie 会话请求：没有会话
// Cookie 且未要求全部不安全请求时，令牌认证接口不受影响。任何缺失或失败都
// fail-closed，返回统一的 403 ACCESS_DENIED，不暴露具体失败原因。
func (p *csrfPolicy) check(ctx context.Context, request *http.Request) *problem {
	if p == nil || !p.enabled || request == nil {
		return nil
	}
	if isSafeMethod(request.Method) {
		return nil
	}
	if !p.requireAllUnsafe {
		if _, err := request.Cookie(p.cookieName); err != nil {
			return nil
		}
	}
	origin, ok := requestOrigin(request)
	if !ok {
		return csrfProblem()
	}
	if _, allowed := p.origins[origin]; !allowed {
		return csrfProblem()
	}
	values := request.Header.Values(p.tokenHeader)
	if len(values) != 1 {
		return csrfProblem()
	}
	token, ok := trimCSRFToken(values[0])
	if !ok {
		return csrfProblem()
	}
	if p.validateToken == nil {
		return csrfProblem()
	}
	if err := p.validateToken(ctx, request, token); err != nil {
		return csrfProblem()
	}
	return nil
}

// csrfProblem 返回统一的 CSRF 失败响应。
func csrfProblem() *problem {
	return newProblem(http.StatusForbidden, "ACCESS_DENIED", "请求来源或安全令牌校验失败")
}

// isSafeMethod 报告方法是否无需 CSRF 令牌。
func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

// requestOrigin 从 Origin 或 Referer 得到请求来源的规范化 origin。两者都缺失或
// 无效时返回 false；不把 sec-fetch-site 等客户端可伪造的头当作来源证据。
func requestOrigin(request *http.Request) (string, bool) {
	origins := request.Header.Values("Origin")
	if len(origins) > 1 {
		return "", false
	}
	if len(origins) == 1 && origins[0] != "" {
		canonical, err := canonicalOrigin(origins[0])
		if err != nil {
			return "", false
		}
		return canonical, true
	}
	referers := request.Header.Values("Referer")
	if len(referers) > 1 {
		return "", false
	}
	referer := ""
	if len(referers) == 1 {
		referer = referers[0]
	}
	if referer == "" {
		return "", false
	}
	parsed, err := url.Parse(referer)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil {
		return "", false
	}
	canonical, err := canonicalOrigin(parsed.Scheme + "://" + parsed.Host)
	if err != nil {
		return "", false
	}
	return canonical, true
}

// validateCSRFCookieName 校验 Cookie 名；供公开 Cookie 策略与 CSRF 配置共用。
func validateCSRFCookieName(name string) error {
	if !isHTTPToken(name) {
		return fmt.Errorf("Cookie 名无效")
	}
	return nil
}

// trimCSRFToken 去除令牌首尾空白并拒绝空值与超长值。
func trimCSRFToken(token string) (string, bool) {
	trimmed := strings.TrimSpace(token)
	if trimmed == "" || len(trimmed) > maxCSRFTokenBytes {
		return "", false
	}
	for index := 0; index < len(trimmed); index++ {
		character := trimmed[index]
		if character < 0x21 || character > 0x7e {
			return "", false
		}
	}
	return trimmed, true
}
