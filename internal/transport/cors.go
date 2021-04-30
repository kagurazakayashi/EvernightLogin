package transport

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	// DefaultCORSMaxAge 是浏览器缓存预检结果默认时间。
	DefaultCORSMaxAge = 10 * time.Minute
	// MaxCORSMaxAge 是预检缓存时间上限。
	MaxCORSMaxAge = 24 * time.Hour
	// maxCORSHeaderBytes 是 CORS 配置中单个头/来源的长度上限。
	maxCORSHeaderBytes = 256
)

// corsPolicy 是构造时冻结的精确来源 CORS 策略。来源必须精确匹配 scheme、主机
// 与端口；不支持通配符、正则或后缀匹配，避免来源校验被绕过。CORS 只是浏览器
// 读取规则，绝不代替身份认证、权限或 CSRF 校验。
type corsPolicy struct {
	enabled              bool
	origins              map[string]struct{}
	allowCredentials     bool
	methods              map[string]struct{}
	allowedMethodsHeader string
	headers              map[string]struct{}
	allowedHeadersHeader string
	exposedHeaders       string
	maxAge               time.Duration
}

// newCORSPolicy 校验并构造 CORS 策略。AllowedOrigins 为空表示禁用 CORS；此时
// 其他 CORS 字段必须为空，避免“配置了 CORS 但静默不生效”的误配置。
func newCORSPolicy(config CORSConfig) (*corsPolicy, error) {
	hasOtherConfig := config.AllowCredentials || len(config.AllowedMethods) > 0 ||
		len(config.AllowedHeaders) > 0 || len(config.ExposedHeaders) > 0 || config.MaxAge != 0
	if len(config.AllowedOrigins) == 0 {
		if hasOtherConfig {
			return nil, fmt.Errorf("CORS 配置了来源以外的字段但未提供 AllowedOrigins")
		}
		return &corsPolicy{}, nil
	}
	policy := &corsPolicy{
		enabled:          true,
		origins:          make(map[string]struct{}, len(config.AllowedOrigins)),
		allowCredentials: config.AllowCredentials,
		methods:          make(map[string]struct{}),
		headers:          make(map[string]struct{}),
		maxAge:           config.MaxAge,
	}
	for _, raw := range config.AllowedOrigins {
		canonical, err := canonicalOrigin(raw)
		if err != nil {
			return nil, fmt.Errorf("CORS 来源无效: %w", err)
		}
		if _, exists := policy.origins[canonical]; exists {
			return nil, fmt.Errorf("CORS 来源重复: %q", canonical)
		}
		policy.origins[canonical] = struct{}{}
	}
	methods := config.AllowedMethods
	if len(methods) == 0 {
		methods = []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}
	}
	methodNames := make([]string, 0, len(methods))
	for _, raw := range methods {
		method := strings.ToUpper(strings.TrimSpace(raw))
		if !isHTTPToken(method) {
			return nil, fmt.Errorf("CORS 方法无效: %q", raw)
		}
		if _, exists := policy.methods[method]; exists {
			continue
		}
		policy.methods[method] = struct{}{}
		methodNames = append(methodNames, method)
	}
	if len(methodNames) == 0 {
		return nil, fmt.Errorf("CORS 必须至少允许一个方法")
	}
	sort.Strings(methodNames)
	policy.allowedMethodsHeader = strings.Join(methodNames, ", ")

	headers := config.AllowedHeaders
	if len(headers) == 0 {
		headers = []string{"Content-Type", "Authorization", "X-Request-ID", "X-CSRF-Token"}
	}
	headerNames := make([]string, 0, len(headers))
	for _, raw := range headers {
		header := strings.ToLower(strings.TrimSpace(raw))
		if !isHTTPToken(header) {
			return nil, fmt.Errorf("CORS 请求头无效: %q", raw)
		}
		if _, exists := policy.headers[header]; exists {
			continue
		}
		policy.headers[header] = struct{}{}
		headerNames = append(headerNames, header)
	}
	sort.Strings(headerNames)
	policy.allowedHeadersHeader = strings.Join(headerNames, ", ")

	exposed := config.ExposedHeaders
	if len(exposed) == 0 {
		exposed = []string{"X-Request-ID", "Retry-After"}
	}
	exposedNames := make([]string, 0, len(exposed))
	for _, raw := range exposed {
		header := strings.TrimSpace(raw)
		if !isHTTPToken(header) {
			return nil, fmt.Errorf("CORS 暴露头无效: %q", raw)
		}
		exposedNames = append(exposedNames, header)
	}
	sort.Strings(exposedNames)
	policy.exposedHeaders = strings.Join(exposedNames, ", ")

	if policy.maxAge == 0 {
		policy.maxAge = DefaultCORSMaxAge
	}
	if policy.maxAge < 0 || policy.maxAge > MaxCORSMaxAge {
		return nil, fmt.Errorf("CORS 预检缓存时间必须在 0～%s 之间", MaxCORSMaxAge)
	}
	return policy, nil
}

// canonicalOrigin 把来源规范化为 scheme://host[:port]。只接受 http/https、
// 无用户信息、无路径/查询/片段的精确来源；拒绝通配符与 "null"。
func canonicalOrigin(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("来源不能为空")
	}
	if len(trimmed) > maxCORSHeaderBytes {
		return "", fmt.Errorf("来源过长")
	}
	if trimmed == "*" || strings.Contains(trimmed, "*") {
		return "", fmt.Errorf("不允许通配符来源")
	}
	for _, character := range trimmed {
		if character < 0x21 || character > 0x7e {
			return "", fmt.Errorf("来源只能包含可见 ASCII 字符")
		}
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("来源格式无效")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("来源协议只允许 http/https")
	}
	if parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("来源不能包含用户信息、路径、查询或片段")
	}
	host := strings.ToLower(parsed.Host)
	hostName := strings.ToLower(parsed.Hostname())
	if hostName == "" {
		return "", fmt.Errorf("来源主机为空")
	}
	port := parsed.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	if port != "" {
		if _, err := parsePort(port); err != nil {
			return "", err
		}
		host = hostName + ":" + port
	} else {
		host = hostName
	}
	if strings.Contains(hostName, ":") {
		host = "[" + hostName + "]"
		if port != "" {
			host += ":" + port
		}
	}
	return scheme + "://" + host, nil
}

// parsePort 校验端口范围为 1～65535。
func parsePort(raw string) (int, error) {
	if raw == "" {
		return 0, fmt.Errorf("端口为空")
	}
	value := 0
	for index := 0; index < len(raw); index++ {
		character := raw[index]
		if character < '0' || character > '9' {
			return 0, fmt.Errorf("来源端口无效")
		}
		value = value*10 + int(character-'0')
		if value > 65535 {
			return 0, fmt.Errorf("来源端口无效")
		}
	}
	if value == 0 {
		return 0, fmt.Errorf("来源端口无效")
	}
	return value, nil
}

// checkOrigin 校验请求的实际 Origin。没有 Origin 的请求（同源导航、非浏览器
// 客户端）不产生 CORS 响应头，但也不因缺少 Origin 被拒绝；权限与 CSRF 仍按各自
// 规则检查。
func (p *corsPolicy) checkOrigin(request *http.Request) (string, *problem) {
	if p == nil || !p.enabled {
		return "", nil
	}
	origins := request.Header.Values("Origin")
	if len(origins) == 0 {
		return "", nil
	}
	if len(origins) != 1 {
		return "", newProblem(http.StatusForbidden, "ACCESS_DENIED", "请求来源未获准")
	}
	canonical, err := canonicalOrigin(origins[0])
	if err != nil {
		return "", newProblem(http.StatusForbidden, "ACCESS_DENIED", "请求来源未获准")
	}
	if _, allowed := p.origins[canonical]; !allowed {
		return "", newProblem(http.StatusForbidden, "ACCESS_DENIED", "请求来源未获准")
	}
	return canonical, nil
}

// writeActualHeaders 为普通跨源响应写 CORS 头。
func (p *corsPolicy) writeActualHeaders(header http.Header, origin string) {
	if p == nil || !p.enabled || origin == "" {
		return
	}
	appendVary(header, "Origin")
	header.Set("Access-Control-Allow-Origin", origin)
	if p.allowCredentials {
		header.Set("Access-Control-Allow-Credentials", "true")
	}
	if p.exposedHeaders != "" {
		header.Set("Access-Control-Expose-Headers", p.exposedHeaders)
	}
}

// handlePreflight 处理 CORS 预检请求。返回 handled=true 表示已写出响应；problem
// 非空时表示来源/方法/请求头不合法。
func (p *corsPolicy) handlePreflight(w *responseWriter, request *http.Request) (bool, *problem) {
	if p == nil || !p.enabled || request.Method != http.MethodOptions {
		return false, nil
	}
	origins := request.Header.Values("Origin")
	methods := request.Header.Values("Access-Control-Request-Method")
	if len(origins) == 0 || len(methods) == 0 {
		return false, nil
	}
	if len(origins) != 1 || len(methods) != 1 {
		return true, newProblem(http.StatusForbidden, "ACCESS_DENIED", "请求来源未获准")
	}
	requestedMethod := methods[0]
	origin, originProblem := p.checkOrigin(request)
	if originProblem != nil {
		return true, originProblem
	}
	method := strings.ToUpper(strings.TrimSpace(requestedMethod))
	if _, allowed := p.methods[method]; !allowed {
		return true, newProblem(http.StatusForbidden, "ACCESS_DENIED", "请求来源未获准")
	}
	requestedHeaderValues := request.Header.Values("Access-Control-Request-Headers")
	if len(requestedHeaderValues) > 1 {
		return true, newProblem(http.StatusForbidden, "ACCESS_DENIED", "请求来源未获准")
	}
	requestedHeaders := ""
	if len(requestedHeaderValues) == 1 {
		requestedHeaders = requestedHeaderValues[0]
	}
	if requestedHeaders != "" {
		for _, raw := range strings.Split(requestedHeaders, ",") {
			header := strings.ToLower(strings.TrimSpace(raw))
			if header == "" {
				continue
			}
			if !isHTTPToken(header) {
				return true, newProblem(http.StatusForbidden, "ACCESS_DENIED", "请求来源未获准")
			}
			if _, allowed := p.headers[header]; !allowed {
				return true, newProblem(http.StatusForbidden, "ACCESS_DENIED", "请求来源未获准")
			}
		}
	}
	header := w.Header()
	appendVary(header, "Origin")
	appendVary(header, "Access-Control-Request-Method")
	appendVary(header, "Access-Control-Request-Headers")
	header.Set("Access-Control-Allow-Origin", origin)
	if p.allowCredentials {
		header.Set("Access-Control-Allow-Credentials", "true")
	}
	header.Set("Access-Control-Allow-Methods", p.allowedMethodsHeader)
	if p.allowedHeadersHeader != "" {
		header.Set("Access-Control-Allow-Headers", p.allowedHeadersHeader)
	}
	if p.exposedHeaders != "" {
		header.Set("Access-Control-Expose-Headers", p.exposedHeaders)
	}
	if p.maxAge > 0 {
		header.Set("Access-Control-Max-Age", fmt.Sprintf("%d", int(p.maxAge/time.Second)))
	}
	header.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
	return true, nil
}

// appendVary 向 Vary 头追加字段，避免重复。
func appendVary(header http.Header, value string) {
	for _, existing := range header.Values("Vary") {
		for _, item := range strings.Split(existing, ",") {
			if strings.EqualFold(strings.TrimSpace(item), value) {
				return
			}
		}
	}
	header.Add("Vary", value)
}

// isHTTPToken 报告字符串是否为 RFC 7230 token（用于方法/头名称校验）。
func isHTTPToken(value string) bool {
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
