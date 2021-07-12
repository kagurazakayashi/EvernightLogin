package transport

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime"
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
	// DefaultCSRFFormField 是服务端渲染 HTML 表单的默认 CSRF 隐藏字段名；
	// 仅用于 application/x-www-form-urlencoded 的不安全请求，仍交给同一
	// ValidateToken 校验并保留 Origin/Referer 检查。
	DefaultCSRFFormField = "csrf_token"
	// maxCSRFBodyBytes 是解析隐藏字段时读取请求体的上限，避免为 CSRF 解析
	// 放大无界请求体开销。
	maxCSRFBodyBytes = 64 * 1024
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
	publicPaths      map[string]struct{}
	validatePublic   func(ctx context.Context, request *http.Request, path, token string) error
	enabled          bool
	cookieName       string
	tokenHeader      string
	tokenFormField   string
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
	publicPaths := make(map[string]struct{}, len(config.PublicFormPaths))
	for _, path := range config.PublicFormPaths {
		if path == "" || path[0] != '/' || strings.Contains(path, "?") ||
			strings.Contains(path, "#") || strings.Contains(path, "..") {
			return nil, fmt.Errorf("CSRF 公开表单路径无效")
		}
		if _, exists := publicPaths[path]; exists {
			return nil, fmt.Errorf("CSRF 公开表单路径重复")
		}
		publicPaths[path] = struct{}{}
	}
	if len(publicPaths) > 0 && config.ValidatePublicToken == nil {
		return nil, fmt.Errorf("启用公开表单路径时必须提供匿名令牌校验器")
	}
	tokenFormField := config.TokenFormField
	if tokenFormField == "" {
		tokenFormField = DefaultCSRFFormField
	}
	if !isHTTPToken(tokenFormField) {
		return nil, fmt.Errorf("CSRF 表单字段名无效")
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
		tokenFormField:   tokenFormField,
		origins:          origins,
		requireAllUnsafe: config.RequireAllUnsafe,
		validateToken:    config.ValidateToken,
		publicPaths:      publicPaths,
		validatePublic:   config.ValidatePublicToken,
	}, nil
}

// check 对不安全请求执行来源与令牌校验（路径取 request.URL.Path；处理器应使用
// checkPath 传入规范化路径）。任何缺失或失败都 fail-closed。
func (p *csrfPolicy) check(ctx context.Context, request *http.Request) *problem {
	if request == nil {
		return nil
	}
	return p.checkPath(ctx, request, request.URL.Path)
}

// checkPath 是 CSRF 校验主体：公开表单路径即使无会话 Cookie 也要求来源与匿名
// 令牌；其余不安全请求维持既有“仅保护 Cookie 会话”的语义。
func (p *csrfPolicy) checkPath(ctx context.Context, request *http.Request, path string) *problem {
	if p == nil || !p.enabled || request == nil {
		return nil
	}
	if isSafeMethod(request.Method) {
		return nil
	}
	publicPath := false
	if len(p.publicPaths) > 0 {
		_, publicPath = p.publicPaths[path]
	}
	if !publicPath && !p.requireAllUnsafe {
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
	// 令牌来源：单一 X-CSRF-Token 头优先；没有头时允许服务端渲染表单提交单一
	// csrf_token 隐藏字段（application/x-www-form-urlencoded）。两种来源最终都
	// 交给同一校验器，不降低校验强度。
	values := request.Header.Values(p.tokenHeader)
	var token string
	switch {
	case len(values) > 1:
		return csrfProblem()
	case len(values) == 1:
		trimmed, ok := trimCSRFToken(values[0])
		if !ok {
			return csrfProblem()
		}
		token = trimmed
	default:
		formToken, ok := readCSRFFormToken(request, p.tokenFormField)
		if !ok {
			return csrfProblem()
		}
		token = formToken
	}
	if publicPath {
		if p.validatePublic == nil {
			return csrfProblem()
		}
		if err := p.validatePublic(ctx, request, path, token); err != nil {
			return csrfProblem()
		}
		return nil
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

// readCSRFFormToken 从 application/x-www-form-urlencoded 请求体的单一隐藏字段读取
// CSRF 令牌。仅用于不安全方法；读取上限 maxCSRFBodyBytes，读取后恢复请求体供
// 后续处理器使用；重复字段、空值、非表单类型、解析失败一律 fail-closed。
func readCSRFFormToken(request *http.Request, field string) (string, bool) {
	if request == nil || field == "" || request.Body == nil {
		return "", false
	}
	contentType := request.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		return "", false
	}
	body, readErr := io.ReadAll(io.LimitReader(request.Body, maxCSRFBodyBytes+1))
	_ = request.Body.Close()
	request.Body = io.NopCloser(bytes.NewReader(body))
	request.ContentLength = int64(len(body))
	if readErr != nil || len(body) > maxCSRFBodyBytes {
		return "", false
	}
	values, parseErr := url.ParseQuery(string(body))
	if parseErr != nil {
		return "", false
	}
	tokens := values[field]
	if len(tokens) != 1 {
		return "", false
	}
	return trimCSRFToken(tokens[0])
}
