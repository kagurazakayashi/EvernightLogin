// Package netguard 实现出站 HTTP 目标的安全校验与受限客户端（SSRF 防护）。
//
// 安全不变量：
//   - 目标必须是 https（生产模式仅 443 端口）；只允许回环 http 的测试开关不得在
//     生产启用。拒绝 userinfo、片段、非绝对 URL 与超长地址。
//   - 目标主机名与字面 IP 都要判定为公网单播：拒绝环回、私有、链路本地、组播、
//     未指定、CGNAT 与保留/文档/隧道网段（IPv4 与 IPv6，含 IPv4-mapped）。
//   - 每次真实连接前重新解析 DNS，要求**所有**解析结果均为公网地址，并直接连接
//     已校验的 IP，避免“校验一个地址、连接另一个地址”的 DNS 重绑定。
//   - 默认不跟随重定向；显式允许时逐次重新校验目标。禁用环境代理与自动解压，
//     限制响应字节、超时与 TLS 校验不可关闭。
package netguard

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// 领域错误；调用方据此区分永久拒绝（策略）与可重试的远端不可用。
var (
	// ErrBlocked 表示目标被安全策略拒绝（地址/协议/重定向不安全）。
	ErrBlocked = errors.New("目标地址不被允许")
	// ErrUnavailable 表示远端不可用（连接/DNS/超时），可按策略重试。
	ErrUnavailable = errors.New("远端暂时不可用")
	// ErrInvalidURL 表示 URL 格式不合法。
	ErrInvalidURL = errors.New("目标地址格式无效")
)

const (
	// DefaultTimeout 是单次请求总时限。
	DefaultTimeout = 10 * time.Second
	// MinTimeout/MaxTimeout 是超时边界。
	MinTimeout = 2 * time.Second
	MaxTimeout = 60 * time.Second
	// DefaultMaxResponseBytes 是响应体读取上限（诊断用，不落盘）。
	DefaultMaxResponseBytes = 64 * 1024
	// MaxURLBytes 是目标 URL 长度上限。
	MaxURLBytes = 2048
	// DefaultMaxRedirects 是默认重定向次数（0 = 不跟随，安全默认）。
	DefaultMaxRedirects = 0
	// MaxAllowedRedirects 是允许配置的重定向上限。
	MaxAllowedRedirects = 2
)

// IPResolver 是 DNS 解析契约；测试可注入假解析器验证敏感地址拒绝，不访问真实网络。
type IPResolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// Policy 是出站目标策略。零值使用安全默认。TestOnlyAllowLocalEndpoints 仅供自动化
// 测试访问本地 httptest 捕获端，生产、预生产与任何对外环境禁止启用。
type Policy struct {
	AllowedHosts                []string
	Timeout                     time.Duration
	MaxRedirects                int
	MaxResponseBytes            int64
	TestOnlyAllowLocalEndpoints bool
}

type resolvedPolicy struct {
	allowedHosts []string
	timeout      time.Duration
	maxRedirects int
	maxBytes     int64
	testMode     bool
}

// resolve 合并默认值并校验配置。
func (p Policy) resolve() (resolvedPolicy, error) {
	resolved := resolvedPolicy{
		timeout: DefaultTimeout, maxRedirects: DefaultMaxRedirects,
		maxBytes: DefaultMaxResponseBytes, testMode: p.TestOnlyAllowLocalEndpoints,
	}
	if p.Timeout != 0 {
		if p.Timeout < MinTimeout || p.Timeout > MaxTimeout {
			return resolvedPolicy{}, fmt.Errorf("超时必须在 %s～%s 之间", MinTimeout, MaxTimeout)
		}
		resolved.timeout = p.Timeout
	}
	if p.MaxRedirects != 0 {
		if p.MaxRedirects < 0 || p.MaxRedirects > MaxAllowedRedirects {
			return resolvedPolicy{}, fmt.Errorf("重定向次数必须在 0～%d 之间", MaxAllowedRedirects)
		}
		resolved.maxRedirects = p.MaxRedirects
	}
	if p.MaxResponseBytes != 0 {
		if p.MaxResponseBytes < 1024 || p.MaxResponseBytes > 1<<20 {
			return resolvedPolicy{}, fmt.Errorf("响应字节上限必须在 1024～%d 之间", 1<<20)
		}
		resolved.maxBytes = p.MaxResponseBytes
	}
	for _, host := range p.AllowedHosts {
		value := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
		if value == "" || strings.ContainsAny(value, " /\\?#@") {
			return resolvedPolicy{}, fmt.Errorf("允许的目标主机名无效")
		}
		resolved.allowedHosts = append(resolved.allowedHosts, value)
	}
	return resolved, nil
}

// blockedNets 覆盖 net.IP 判定之外需要显式拒绝的非公网/保留地址段（与
// internal/avatar 的出站防护保持同一保守清单）。
var blockedNets = mustParseNets(
	"100.64.0.0/10",   // 运营商级 NAT
	"192.0.0.0/24",    // IETF 协议分配
	"192.0.2.0/24",    // TEST-NET-1
	"198.18.0.0/15",   // 基准测试
	"198.51.100.0/24", // TEST-NET-2
	"203.0.113.0/24",  // TEST-NET-3
	"192.88.99.0/24",  // 6to4 中继（已废弃）
	"240.0.0.0/4",     // 保留
	"255.255.255.255/32",
	"::/96",          // IPv4-compatible（已废弃）
	"2001::/32",      // Teredo
	"2001:db8::/32",  // 文档示例
	"2002::/16",      // 6to4
	"64:ff9b::/96",   // 公网 NAT64
	"64:ff9b:1::/48", // 本地 NAT64
)

func mustParseNets(values ...string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			panic("netguard: 内置拒绝网段无效: " + value)
		}
		nets = append(nets, network)
	}
	return nets
}

// IsPublicIP 报告地址是否可作为出站目标：必须是全局单播，且不属于环回、私有、
// 链路本地、组播、未指定、CGNAT 与保留/文档网段。
func IsPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	} else if v6 := ip.To16(); v6 != nil {
		// 拒绝 IPv4-mapped IPv6（::ffff:0:0/96）：其真实语义是 IPv4 地址。
		if mapped := ip.To4(); mapped != nil {
			ip = mapped
		}
	}
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	if !ip.IsGlobalUnicast() {
		return false
	}
	for _, network := range blockedNets {
		if network.Contains(ip) {
			return false
		}
	}
	return true
}

// Validator 执行 URL 与 DNS/IP 校验；Resolver 为空时使用 net.DefaultResolver。
type Validator struct {
	policy   resolvedPolicy
	resolver IPResolver
}

// NewValidator 构造校验器。
func NewValidator(policy Policy, resolver IPResolver) (*Validator, error) {
	resolved, err := policy.resolve()
	if err != nil {
		return nil, err
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return &Validator{policy: resolved, resolver: resolver}, nil
}

// Timeout/MaxResponseBytes/MaxRedirects 返回合并默认值后的策略参数。
func (v *Validator) Timeout() time.Duration  { return v.policy.timeout }
func (v *Validator) MaxResponseBytes() int64 { return v.policy.maxBytes }
func (v *Validator) MaxRedirects() int       { return v.policy.maxRedirects }

// ValidateURL 校验目标 URL 的协议、主机、端口与地址分类；返回清理后的 URL。
func (v *Validator) ValidateURL(rawURL string) (*url.URL, error) {
	if rawURL == "" || len(rawURL) > MaxURLBytes {
		return nil, ErrInvalidURL
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Opaque != "" || parsed.Host == "" {
		return nil, ErrInvalidURL
	}
	scheme := strings.ToLower(parsed.Scheme)
	switch {
	case scheme == "https":
	case scheme == "http" && v.policy.testMode:
	default:
		return nil, fmt.Errorf("%w: 只允许 https", ErrBlocked)
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("%w: 不允许 URL 携带凭证", ErrBlocked)
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if host == "" {
		return nil, ErrInvalidURL
	}
	if len(v.policy.allowedHosts) > 0 && !hostAllowed(host, v.policy.allowedHosts) {
		return nil, fmt.Errorf("%w: 主机不在允许列表", ErrBlocked)
	}
	port := parsed.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	if !v.policy.testMode && port != "443" {
		return nil, fmt.Errorf("%w: 只允许 https 默认端口", ErrBlocked)
	}
	if _, err := strconv.Atoi(port); err != nil {
		return nil, ErrInvalidURL
	}
	if literal := net.ParseIP(host); literal != nil && !v.policy.testMode && !IsPublicIP(literal) {
		return nil, fmt.Errorf("%w: 目标地址不是公网地址", ErrBlocked)
	}
	cleaned := *parsed
	cleaned.Fragment = ""
	cleaned.Scheme = scheme
	return &cleaned, nil
}

func hostAllowed(host string, allowed []string) bool {
	for _, candidate := range allowed {
		if host == candidate {
			return true
		}
	}
	return false
}

// NewClient 构造受限 HTTP 客户端：所有连接经校验过的 IP；默认不跟随重定向。
func (v *Validator) NewClient() *http.Client {
	transport := &http.Transport{
		// 明确不使用环境代理：代理会让真实目标绕过本地地址校验。
		Proxy:                 nil,
		DialContext:           v.dial,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          2,
		MaxIdleConnsPerHost:   1,
		IdleConnTimeout:       10 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: v.policy.timeout,
		DisableCompression:    true,
	}
	client := &http.Client{Transport: transport, Timeout: v.policy.timeout}
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) > v.policy.maxRedirects {
			return fmt.Errorf("%w: 重定向次数超过上限", ErrBlocked)
		}
		if _, err := v.ValidateURL(request.URL.String()); err != nil {
			return err
		}
		return nil
	}
	return client
}

// dial 在连接前重新解析并校验目标：任一解析结果不是公网地址即拒绝整个请求，
// 并直接连接已校验的 IP（防 DNS 重绑定）。
func (v *Validator) dial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("%w: 目标地址格式无效", ErrBlocked)
	}
	if !v.policy.testMode && port != "443" {
		return nil, fmt.Errorf("%w: 只允许 https 默认端口", ErrBlocked)
	}
	var ips []net.IP
	if literal := net.ParseIP(host); literal != nil {
		ips = []net.IP{literal}
	} else {
		addresses, lookupErr := v.resolver.LookupIPAddr(ctx, host)
		if lookupErr != nil {
			return nil, fmt.Errorf("%w: DNS 解析失败", ErrUnavailable)
		}
		for _, entry := range addresses {
			ips = append(ips, entry.IP)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: 目标地址无可用 IP", ErrBlocked)
	}
	if !v.policy.testMode {
		for _, ip := range ips {
			if !IsPublicIP(ip) {
				return nil, fmt.Errorf("%w: 目标地址不是公网地址", ErrBlocked)
			}
		}
	}
	dialer := &net.Dialer{Timeout: v.policy.timeout}
	connection, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
	if dialErr != nil {
		return nil, fmt.Errorf("%w: 连接目标失败", ErrUnavailable)
	}
	return connection, nil
}

// ReadLimitedBody 读取响应体上限字节（多读 1 字节用于判定超限）。
func (v *Validator) ReadLimitedBody(body io.Reader) ([]byte, error) {
	limited := io.LimitReader(body, v.policy.maxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("%w: 读取响应失败", ErrUnavailable)
	}
	if int64(len(data)) > v.policy.maxBytes {
		return nil, fmt.Errorf("%w: 响应体超过上限", ErrBlocked)
	}
	return data, nil
}
