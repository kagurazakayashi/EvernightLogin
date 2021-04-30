package transport

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/ratelimit"
)

const (
	// DefaultRateLimitMaxEntries/DefaultRateLimitCleanupAfter 是限流器默认容量与
	// 机会式清理最小间隔。
	DefaultRateLimitMaxEntries   = 4096
	DefaultRateLimitCleanupAfter = 30 * time.Second

	// DefaultRequestTimeout 是单个 HTTP 请求的处理期限；超时返回 504。
	DefaultRequestTimeout = 30 * time.Second
	// MinRequestTimeout/MaxRequestTimeout 是请求期限范围（测试可使用短期限）。
	MinRequestTimeout = 10 * time.Millisecond
	MaxRequestTimeout = 5 * time.Minute
	// DefaultMaxConcurrentRequests 是同时处理的 HTTP 请求上限。
	DefaultMaxConcurrentRequests = 256
	// MinConcurrentRequests/MaxConcurrentRequests 是并发上限范围。
	MinConcurrentRequests = 1
	MaxConcurrentRequests = 1024
	// MaxTrustedProxies 是可信代理配置条目上限，避免代理列表无限增长。
	MaxTrustedProxies = 32
	// maxForwardedBytes/maxForwardedHops 限制 X-Forwarded-For 解析放大。
	maxForwardedBytes = 2 << 10
	maxForwardedHops  = 16
)

// 默认固定窗口限流：地址 600/分钟、已认证用户 300/分钟、应用 300/分钟、
// 接口 1200/分钟、昂贵请求 30/分钟。这些值在 nil 防护配置或零值限流配置时使用。
var (
	DefaultClientIPRateLimit    = ratelimit.Policy{Limit: 600, Window: time.Minute}
	DefaultUserRateLimit        = ratelimit.Policy{Limit: 300, Window: time.Minute}
	DefaultApplicationRateLimit = ratelimit.Policy{Limit: 300, Window: time.Minute}
	DefaultEndpointRateLimit    = ratelimit.Policy{Limit: 1200, Window: time.Minute}
	DefaultExpensiveRateLimit   = ratelimit.Policy{Limit: 30, Window: time.Minute}
)

// RateLimitRule 是单维限流规则；零值表示该维度禁用。
type RateLimitRule struct {
	Limit  int
	Window time.Duration
}

// policy 转换为内部限流策略。
func (r RateLimitRule) policy() ratelimit.Policy {
	return ratelimit.Policy{Limit: r.Limit, Window: r.Window}
}

// RateLimitConfig 是多维限流配置。Disabled 为 true 时关闭全部限流；否则若所有
// 规则与容量均为零，使用安全默认规则；只要设置了任一字段，就只启用显式设置的
// 维度（零值规则停用）。容量与清理间隔有默认值。
type RateLimitConfig struct {
	Disabled        bool
	ClientIP        RateLimitRule
	User            RateLimitRule
	Application     RateLimitRule
	Endpoint        RateLimitRule
	Expensive       RateLimitRule
	Capacity        int
	CleanupInterval time.Duration
}

// CORSConfig 是精确来源 CORS 配置；AllowedOrigins 为空时 CORS 关闭。
type CORSConfig struct {
	AllowedOrigins   []string
	AllowCredentials bool
	AllowedMethods   []string
	AllowedHeaders   []string
	ExposedHeaders   []string
	MaxAge           time.Duration
}

// CSRFConfig 是未来 Cookie 会话的 CSRF 防护契约。Enabled 为 true 时必须提供
// 精确来源列表与令牌校验器；校验失败 fail-closed 返回 403。
type CSRFConfig struct {
	Enabled          bool
	CookieName       string
	TokenHeader      string
	AllowedOrigins   []string
	RequireAllUnsafe bool
	ValidateToken    func(ctx context.Context, request *http.Request, token string) error
}

// SecurityHeaderConfig 是安全响应头配置。ContentSecurityPolicy 为空时使用 API
// 默认 CSP；AllowFraming 为 true 时允许同源嵌入；EnableHSTS 为 true 时输出 HSTS。
type SecurityHeaderConfig struct {
	ContentSecurityPolicy string
	AllowFraming          bool
	EnableHSTS            bool
}

// ProtectionOptions 是传输层浏览器请求防护配置；nil 使用安全默认值。由公开包
// 从 HTTPProtectionOptions 转换，内部测试可直接构造。
type ProtectionOptions struct {
	TrustedProxies        []string
	RateLimit             RateLimitConfig
	RequestTimeout        time.Duration
	MaxConcurrentRequests int
	CORS                  CORSConfig
	CSRF                  CSRFConfig
	SecurityHeaders       SecurityHeaderConfig
	ExpensivePaths        []string
}

// protection 是 Handler 构造时冻结的防护运行时；构造后只读，可并发使用。
type protection struct {
	requestTimeout  time.Duration
	maxConcurrent   int
	semaphore       chan struct{}
	trustedProxies  []netip.Prefix
	rateLimits      rateLimitState
	cors            *corsPolicy
	csrf            *csrfPolicy
	securityHeaders securityHeaders
	expensivePaths  map[string]struct{}
	now             func() time.Time
}

// rateLimitState 保存各维度限流器；nil 表示该维度禁用。
type rateLimitState struct {
	clientIP    *ratelimit.Limiter
	user        *ratelimit.Limiter
	application *ratelimit.Limiter
	endpoint    *ratelimit.Limiter
	expensive   *ratelimit.Limiter
}

// newProtection 校验并构造防护运行时。options 为 nil 时使用全部安全默认值。
func newProtection(options *ProtectionOptions, now func() time.Time) (*protection, error) {
	if now == nil {
		now = time.Now
	}
	config := ProtectionOptions{}
	if options != nil {
		config = *options
	}

	requestTimeout := config.RequestTimeout
	if requestTimeout == 0 {
		requestTimeout = DefaultRequestTimeout
	}
	if requestTimeout < MinRequestTimeout || requestTimeout > MaxRequestTimeout {
		return nil, fmt.Errorf("请求处理期限必须在 %s～%s 之间", MinRequestTimeout, MaxRequestTimeout)
	}
	maxConcurrent := config.MaxConcurrentRequests
	if maxConcurrent == 0 {
		maxConcurrent = DefaultMaxConcurrentRequests
	}
	if maxConcurrent < MinConcurrentRequests || maxConcurrent > MaxConcurrentRequests {
		return nil, fmt.Errorf("请求并发上限必须在 %d～%d 之间", MinConcurrentRequests, MaxConcurrentRequests)
	}
	trustedProxies, err := parseTrustedProxies(config.TrustedProxies)
	if err != nil {
		return nil, err
	}
	corsPolicy, err := newCORSPolicy(config.CORS)
	if err != nil {
		return nil, err
	}
	csrfPolicy, err := newCSRFPolicy(config.CSRF)
	if err != nil {
		return nil, err
	}
	securityHeaders, err := newSecurityHeaders(config.SecurityHeaders)
	if err != nil {
		return nil, err
	}
	expensivePaths, err := normalizeExpensivePaths(config.ExpensivePaths)
	if err != nil {
		return nil, err
	}

	rateLimits, err := newRateLimitState(config.RateLimit, now)
	if err != nil {
		return nil, err
	}
	if len(expensivePaths) > 0 && rateLimits.expensive == nil {
		return nil, fmt.Errorf("配置了昂贵请求路径但未启用昂贵请求预算")
	}

	return &protection{
		requestTimeout:  requestTimeout,
		maxConcurrent:   maxConcurrent,
		semaphore:       make(chan struct{}, maxConcurrent),
		trustedProxies:  trustedProxies,
		rateLimits:      rateLimits,
		cors:            corsPolicy,
		csrf:            csrfPolicy,
		securityHeaders: securityHeaders,
		expensivePaths:  expensivePaths,
		now:             now,
	}, nil
}

// newRateLimitState 解析限流配置并构造各维度限流器。
func newRateLimitState(config RateLimitConfig, now func() time.Time) (rateLimitState, error) {
	var state rateLimitState
	if config.Disabled {
		return state, nil
	}
	rules := []RateLimitRule{config.ClientIP, config.User, config.Application, config.Endpoint, config.Expensive}
	explicit := config.Capacity != 0 || config.CleanupInterval != 0
	for _, rule := range rules {
		if !rule.policy().Enabled() && (rule.Limit != 0 || rule.Window != 0) {
			return state, fmt.Errorf("限流规则必须同时设置请求数与窗口")
		}
		if rule.policy().Enabled() {
			explicit = true
		}
	}
	if !explicit {
		config.ClientIP = policyRule(DefaultClientIPRateLimit)
		config.User = policyRule(DefaultUserRateLimit)
		config.Application = policyRule(DefaultApplicationRateLimit)
		config.Endpoint = policyRule(DefaultEndpointRateLimit)
		config.Expensive = policyRule(DefaultExpensiveRateLimit)
	} else if !config.ClientIP.policy().Enabled() && !config.User.policy().Enabled() &&
		!config.Application.policy().Enabled() && !config.Endpoint.policy().Enabled() &&
		!config.Expensive.policy().Enabled() {
		return state, fmt.Errorf("显式限流配置未启用任何维度")
	}
	capacity := config.Capacity
	if capacity == 0 {
		capacity = DefaultRateLimitMaxEntries
	}
	cleanupInterval := config.CleanupInterval
	if cleanupInterval == 0 {
		cleanupInterval = DefaultRateLimitCleanupAfter
	}
	build := func(rule RateLimitRule) (*ratelimit.Limiter, error) {
		policy := rule.policy()
		if !policy.Enabled() {
			return nil, nil
		}
		return ratelimit.New(ratelimit.Options{
			Policy:          policy,
			MaxEntries:      capacity,
			CleanupInterval: cleanupInterval,
			Now:             now,
		})
	}
	var err error
	if state.clientIP, err = build(config.ClientIP); err != nil {
		return state, fmt.Errorf("客户端地址限流配置无效: %w", err)
	}
	if state.user, err = build(config.User); err != nil {
		return state, fmt.Errorf("用户限流配置无效: %w", err)
	}
	if state.application, err = build(config.Application); err != nil {
		return state, fmt.Errorf("应用限流配置无效: %w", err)
	}
	if state.endpoint, err = build(config.Endpoint); err != nil {
		return state, fmt.Errorf("接口限流配置无效: %w", err)
	}
	if state.expensive, err = build(config.Expensive); err != nil {
		return state, fmt.Errorf("昂贵请求预算配置无效: %w", err)
	}
	return state, nil
}

// policyRule 把限流策略转换为规则。
func policyRule(policy ratelimit.Policy) RateLimitRule {
	return RateLimitRule{Limit: policy.Limit, Window: policy.Window}
}

// parseTrustedProxies 解析可信代理 IP 或 CIDR；只信任显式配置的来源。
func parseTrustedProxies(values []string) ([]netip.Prefix, error) {
	if len(values) > MaxTrustedProxies {
		return nil, fmt.Errorf("可信代理数量不能超过 %d", MaxTrustedProxies)
	}
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, raw := range values {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			return nil, fmt.Errorf("可信代理不能为空")
		}
		if strings.Contains(trimmed, "/") {
			prefix, err := netip.ParsePrefix(trimmed)
			if err != nil {
				return nil, fmt.Errorf("可信代理 CIDR 无效: %q", trimmed)
			}
			if prefix.Addr().Is4In6() {
				if prefix.Bits() < 96 {
					return nil, fmt.Errorf("可信代理 CIDR 无效: %q", trimmed)
				}
				prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
			}
			prefixes = append(prefixes, prefix.Masked())
			continue
		}
		address, err := netip.ParseAddr(trimmed)
		if err != nil {
			return nil, fmt.Errorf("可信代理地址无效: %q", trimmed)
		}
		address = address.Unmap()
		prefixes = append(prefixes, netip.PrefixFrom(address, address.BitLen()))
	}
	return prefixes, nil
}

// isTrustedProxy 报告地址是否在显式可信代理列表中。
func (p *protection) isTrustedProxy(address netip.Addr) bool {
	for _, prefix := range p.trustedProxies {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

// clientIP 返回用于限流与访问日志的可信客户端地址。
//
// 只有直连对端本身是显式可信代理时才解析 X-Forwarded-For；否则完全忽略该请求
// 头，防止客户端伪造地址。解析链从右向左跳过可信代理，遇到第一个不可信地址
// 即视为客户端；长度超限、条目数超限或任一地址非法时回退到直连对端地址，避免
// 用畸形头影响限流键。X-Real-IP 等非标准头一律不信任。
func (p *protection) clientIP(request *http.Request) string {
	if request == nil {
		return "unknown"
	}
	peer, ok := parsePeerAddress(request.RemoteAddr)
	if !ok {
		return "unknown"
	}
	if len(p.trustedProxies) == 0 || !p.isTrustedProxy(peer) {
		return peer.String()
	}
	forwarded := strings.Join(request.Header.Values("X-Forwarded-For"), ",")
	if forwarded == "" || len(forwarded) > maxForwardedBytes {
		return peer.String()
	}
	parts := strings.Split(forwarded, ",")
	if len(parts) > maxForwardedHops {
		return peer.String()
	}
	candidate := peer
	for index := len(parts) - 1; index >= 0; index-- {
		if !p.isTrustedProxy(candidate) {
			break
		}
		address, ok := parseForwardedAddress(parts[index])
		if !ok {
			return peer.String()
		}
		candidate = address
	}
	return candidate.String()
}

// parsePeerAddress 从 RemoteAddr 解析直连对端地址；失败时返回 false。
func parsePeerAddress(remoteAddr string) (netip.Addr, bool) {
	trimmed := strings.TrimSpace(remoteAddr)
	if trimmed == "" {
		return netip.Addr{}, false
	}
	host, _, err := net.SplitHostPort(trimmed)
	if err != nil {
		host = trimmed
	}
	host = strings.Trim(host, "[]")
	address, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return address.Unmap(), true
}

// parseForwardedAddress 解析 X-Forwarded-For 中的单个地址；允许可选的端口与
// IPv6 方括号，其他内容一律视为非法。
func parseForwardedAddress(raw string) (netip.Addr, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return netip.Addr{}, false
	}
	value = strings.Trim(value, "\"")
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	value = strings.Trim(value, "[]")
	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, false
	}
	return address.Unmap(), true
}

// normalizeExpensivePaths 校验昂贵请求路径集合；路径必须是已规范化的完整路径
// （包含 Handler 前缀）。
func normalizeExpensivePaths(paths []string) (map[string]struct{}, error) {
	result := make(map[string]struct{}, len(paths))
	for _, raw := range paths {
		if raw == "" || raw[0] != '/' {
			return nil, fmt.Errorf("昂贵请求路径必须以 / 开头: %q", raw)
		}
		if len(raw) > MaxPathBytes {
			return nil, fmt.Errorf("昂贵请求路径过长")
		}
		if strings.ContainsAny(raw, "%\\?#") || strings.HasSuffix(raw, "/") {
			return nil, fmt.Errorf("昂贵请求路径必须是已规范化的完整路径: %q", raw)
		}
		for _, segment := range strings.Split(raw[1:], "/") {
			if segment == "" || segment == "." || segment == ".." {
				return nil, fmt.Errorf("昂贵请求路径必须是已规范化的完整路径: %q", raw)
			}
		}
		result[raw] = struct{}{}
	}
	return result, nil
}

// isExpensivePath 报告路径是否配置为昂贵请求。
func (p *protection) isExpensivePath(path string) bool {
	if len(p.expensivePaths) == 0 {
		return false
	}
	_, ok := p.expensivePaths[path]
	return ok
}

// applySecurityHeaders 在响应写出前设置安全响应头。
func (p *protection) applySecurityHeaders(header http.Header) {
	p.securityHeaders.apply(header)
}
