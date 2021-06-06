package avatar

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

const (
	// DefaultNetworkTimeout 是网络头像抓取的总时限。
	DefaultNetworkTimeout = 10 * time.Second
	// MaxNetworkTimeout 是允许配置的抓取总时限上限。
	MaxNetworkTimeout = 30 * time.Second
	// MinNetworkTimeout 是允许配置的抓取总时限下限。
	MinNetworkTimeout = time.Second
	// DefaultMaxRedirects 是默认允许的重定向次数。
	DefaultMaxRedirects = 3
	// MaxNetworkRedirects 是允许配置的重定向上限。
	MaxNetworkRedirects = 5
)

// IPResolver 是 DNS 解析契约；默认使用 net.DefaultResolver，测试可注入假解析器
// 验证“解析结果落在非公网地址时拒绝”而不访问真实网络。
type IPResolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// NetworkPolicy 是网络头像抓取策略。零值使用安全默认：仅 https、默认端口、
// 任意公网主机、2 MiB、10 秒、最多 3 次重定向。
type NetworkPolicy struct {
	// AllowedHosts 非空时只允许这些主机名（精确匹配，不含通配符）。
	AllowedHosts []string
	// MaxBytes 是响应字节上限；0 使用 MaxUploadBytes。
	MaxBytes int64
	// Timeout 是抓取总时限；0 使用 DefaultNetworkTimeout。
	Timeout time.Duration
	// MaxRedirects 是允许的重定向次数；0 使用 DefaultMaxRedirects。
	MaxRedirects int
	// TestOnlyAllowLocalAddresses 是仅供本包自动化测试使用的开关：允许 http、
	// 任意端口与回环/私有地址，使测试能访问本地 httptest 服务器。
	// 生产、预生产与任何对外环境都不得启用；默认 false 时所有非公网目标被拒绝。
	TestOnlyAllowLocalAddresses bool
}

// resolvedNetwork 是合并默认值后的网络策略。
type resolvedNetwork struct {
	allowedHosts []string
	maxBytes     int64
	timeout      time.Duration
	maxRedirects int
	testMode     bool
}

// resolve 合并默认值并校验范围；任何非法配置都拒绝构造服务。
func (p NetworkPolicy) resolve() (resolvedNetwork, error) {
	resolved := resolvedNetwork{
		maxBytes:     MaxUploadBytes,
		timeout:      DefaultNetworkTimeout,
		maxRedirects: DefaultMaxRedirects,
		testMode:     p.TestOnlyAllowLocalAddresses,
	}
	if p.MaxBytes != 0 {
		if p.MaxBytes < 1024 || p.MaxBytes > MaxStoredBytes {
			return resolvedNetwork{}, fmt.Errorf("%w: 网络头像字节上限必须在 1024～%d 之间",
				ErrOptionsInvalid, MaxStoredBytes)
		}
		resolved.maxBytes = p.MaxBytes
	}
	if p.Timeout != 0 {
		if p.Timeout < MinNetworkTimeout || p.Timeout > MaxNetworkTimeout {
			return resolvedNetwork{}, fmt.Errorf("%w: 网络头像超时必须在 %s～%s 之间",
				ErrOptionsInvalid, MinNetworkTimeout, MaxNetworkTimeout)
		}
		resolved.timeout = p.Timeout
	}
	if p.MaxRedirects != 0 {
		if p.MaxRedirects < 1 || p.MaxRedirects > MaxNetworkRedirects {
			return resolvedNetwork{}, fmt.Errorf("%w: 重定向次数必须在 1～%d 之间",
				ErrOptionsInvalid, MaxNetworkRedirects)
		}
		resolved.maxRedirects = p.MaxRedirects
	}
	for _, host := range p.AllowedHosts {
		value := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
		if value == "" || strings.ContainsAny(value, " /\\?#@") {
			return resolvedNetwork{}, fmt.Errorf("%w: 允许的网络头像主机名无效", ErrOptionsInvalid)
		}
		resolved.allowedHosts = append(resolved.allowedHosts, value)
	}
	return resolved, nil
}

// blockedNets 覆盖 net.IP 判定之外需要显式拒绝的非公网/保留地址段。
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

// mustParseNets 解析内置 CIDR 清单；解析失败属于编程错误。
func mustParseNets(values ...string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			panic("avatar: 内置拒绝网段无效: " + value)
		}
		nets = append(nets, network)
	}
	return nets
}

// isPublicIP 报告地址是否可作为网络头像目标：必须是全局单播，且不属于环回、
// 私有、链路本地、组播、未指定、CGNAT 与保留/文档网段。
func isPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
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

// networkFetcher 执行受控抓取。所有连接都经过 validateURL + 自定义拨号器，
// 使每次 DNS 解析结果、每次重定向与真实连接目标都被同一策略约束。
type networkFetcher struct {
	policy   resolvedNetwork
	resolver IPResolver
	client   *http.Client
}

// newNetworkFetcher 构造抓取器；resolver 为空时使用 net.DefaultResolver。
func newNetworkFetcher(policy resolvedNetwork, resolver IPResolver) *networkFetcher {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	fetcher := &networkFetcher{policy: policy, resolver: resolver}
	transport := &http.Transport{
		// 明确不使用环境代理：代理会让真实目标绕过本地的地址校验。
		Proxy:                 nil,
		DialContext:           fetcher.dial,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          2,
		MaxIdleConnsPerHost:   1,
		IdleConnTimeout:       10 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: policy.timeout,
		// 关闭自动解压：压缩响应可能被用来绕过字节上限，压缩字节会按原样
		// 交给图片解码并因此被拒绝，而不是在内存里膨胀。
		DisableCompression: true,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   policy.timeout,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) > policy.maxRedirects {
				return fmt.Errorf("%w: 重定向次数超过上限", ErrRemoteBlocked)
			}
			if _, err := fetcher.validateURL(request.URL.String()); err != nil {
				return err
			}
			return nil
		},
	}
	fetcher.client = client
	return fetcher
}

// fetch 抓取一张网络图片并返回原始字节、声明的媒体类型与已校验的主机名；
// 字节仍由调用方送入 ProcessImage 做真实格式校验与重编码。
func (f *networkFetcher) fetch(ctx context.Context, rawURL string) ([]byte, string, string, error) {
	target, err := f.validateURL(rawURL)
	if err != nil {
		return nil, "", "", err
	}
	host := strings.ToLower(strings.TrimSuffix(target.Hostname(), "."))
	fetchCtx, cancel := context.WithTimeout(ctx, f.policy.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, "", "", fmt.Errorf("%w: 无法构建抓取请求", ErrInvalidRequest)
	}
	request.Header.Set("Accept", "image/png,image/jpeg,image/gif")
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("User-Agent", "EvernightLogin-Avatar/1.0")
	response, err := f.client.Do(request)
	if err != nil {
		return nil, "", "", classifyFetchError(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, "", "", fmt.Errorf("%w: 远端返回状态 %d", ErrRemoteUnavailable, response.StatusCode)
	}
	if response.ContentLength > f.policy.maxBytes {
		return nil, "", "", fmt.Errorf("%w: 远端内容超过 %d 字节", ErrImageTooLarge, f.policy.maxBytes)
	}
	declared := normalizeMediaType(response.Header.Get("Content-Type"))
	if declared == "" {
		return nil, "", "", fmt.Errorf("%w: 远端未提供图片类型", ErrUnsupportedMedia)
	}
	if !acceptedMediaTypes[declared] {
		return nil, "", "", fmt.Errorf("%w: 远端类型 %q 不在允许范围", ErrUnsupportedMedia, declared)
	}
	limited := io.LimitReader(response.Body, f.policy.maxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, "", "", fmt.Errorf("%w: 读取远端内容失败", ErrRemoteUnavailable)
	}
	if int64(len(data)) > f.policy.maxBytes {
		return nil, "", "", fmt.Errorf("%w: 远端内容超过 %d 字节", ErrImageTooLarge, f.policy.maxBytes)
	}
	return data, declared, host, nil
}

// classifyFetchError 把传输层错误归类为策略拒绝或远端不可用，不暴露底层主机信息。
func classifyFetchError(err error) error {
	switch {
	case errors.Is(err, ErrRemoteBlocked):
		return err
	case errors.Is(err, ErrRemoteUnavailable), errors.Is(err, ErrInvalidRequest):
		return err
	case errors.Is(err, context.Canceled):
		return err
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("%w: 抓取超时", ErrRemoteUnavailable)
	default:
		return fmt.Errorf("%w: 无法连接远端", ErrRemoteUnavailable)
	}
}

// validateURL 校验网络头像地址：http(s) 协议、无凭证、主机名/主机白名单、
// 端口与地址分类。生产模式只允许 https 默认端口。
func (f *networkFetcher) validateURL(rawURL string) (*url.URL, error) {
	if rawURL == "" {
		return nil, fmt.Errorf("%w: 网络头像地址为空", ErrInvalidRequest)
	}
	if len(rawURL) > MaxURLBytes {
		return nil, fmt.Errorf("%w: 网络头像地址超过 %d 字节", ErrInvalidRequest, MaxURLBytes)
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("%w: 网络头像地址格式无效", ErrInvalidRequest)
	}
	scheme := strings.ToLower(parsed.Scheme)
	switch {
	case scheme == "https":
	case scheme == "http" && f.policy.testMode:
	default:
		return nil, fmt.Errorf("%w: 只允许 https 图片地址", ErrRemoteBlocked)
	}
	if parsed.Opaque != "" || parsed.Host == "" {
		return nil, fmt.Errorf("%w: 网络头像地址必须是绝对 URL", ErrInvalidRequest)
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("%w: 网络头像地址不能包含凭证", ErrRemoteBlocked)
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if host == "" {
		return nil, fmt.Errorf("%w: 网络头像地址缺少主机名", ErrInvalidRequest)
	}
	if len(f.policy.allowedHosts) > 0 && !hostAllowed(host, f.policy.allowedHosts) {
		return nil, fmt.Errorf("%w: 主机不在允许列表", ErrRemoteBlocked)
	}
	port := parsed.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	if !f.policy.testMode {
		if scheme != "https" || port != "443" {
			return nil, fmt.Errorf("%w: 只允许 https 默认端口", ErrRemoteBlocked)
		}
	} else if _, err := strconv.Atoi(port); err != nil {
		return nil, fmt.Errorf("%w: 网络头像地址端口无效", ErrInvalidRequest)
	}
	if literal := net.ParseIP(host); literal != nil && !f.policy.testMode && !isPublicIP(literal) {
		return nil, fmt.Errorf("%w: 目标地址不是公网地址", ErrRemoteBlocked)
	}
	cleaned := *parsed
	cleaned.Fragment = ""
	cleaned.Scheme = scheme
	return &cleaned, nil
}

// hostAllowed 精确匹配允许主机列表（大小写不敏感，已统一小写）。
func hostAllowed(host string, allowed []string) bool {
	for _, candidate := range allowed {
		if host == candidate {
			return true
		}
	}
	return false
}

// dial 在真实连接前解析并校验目标地址；解析结果中任何非公网地址都会拒绝整个
// 请求（防止解析到混合地址时选择敏感目标），并直接向校验过的 IP 建立连接，
// 避免“校验一个地址、连接另一个地址”的 DNS 重绑定问题。
func (f *networkFetcher) dial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("%w: 目标地址格式无效", ErrRemoteBlocked)
	}
	if !f.policy.testMode && port != "443" {
		return nil, fmt.Errorf("%w: 只允许 https 默认端口", ErrRemoteBlocked)
	}
	var ips []net.IP
	if literal := net.ParseIP(host); literal != nil {
		ips = []net.IP{literal}
	} else {
		addresses, lookupErr := f.resolver.LookupIPAddr(ctx, host)
		if lookupErr != nil {
			return nil, fmt.Errorf("%w: DNS 解析失败", ErrRemoteUnavailable)
		}
		for _, entry := range addresses {
			ips = append(ips, entry.IP)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: 目标地址无可用 IP", ErrRemoteBlocked)
	}
	if !f.policy.testMode {
		for _, ip := range ips {
			if !isPublicIP(ip) {
				return nil, fmt.Errorf("%w: 目标地址不是公网地址", ErrRemoteBlocked)
			}
		}
	}
	dialer := &net.Dialer{Timeout: f.policy.timeout}
	connection, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
	if dialErr != nil {
		return nil, fmt.Errorf("%w: 连接目标失败", ErrRemoteUnavailable)
	}
	return connection, nil
}
