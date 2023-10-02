package transport

import (
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/netpolicy"
	"github.com/kagurazakayashi/EvernightLogin/proxytrust"
)

// hostRejectedStatus 是指定 Host 不在允许列表时的标准状态：421 Misdirected
// Request。客户端可以据此判断请求被发到了错误的服务实例。
const hostRejectedStatus = http.StatusMisdirectedRequest

// proxyHeaderNames 是代理边界消费后必须从内层请求删除的头。删除后，业务处理
// 程序无法再读到未经校验或已校验的转发头，只能使用边界放入上下文的可信客户端
// 地址，避免不同模块对同一转发头做出不同解释。
var proxyHeaderNames = []string{
	"Forwarded",
	"X-Forwarded-For",
	"X-Forwarded-Proto",
	"X-Forwarded-Host",
	"X-Forwarded-Port",
	"X-Forwarded-Server",
	"X-Real-Ip",
	"X-Client-Ip",
}

// BoundaryOptions 是传输层代理边界的显式依赖；由公开包的 NewServer 从有效配置
// 构造，其他包不应直接使用。
type BoundaryOptions struct {
	// Next 是内层处理程序（通常是 NewHTTPHandler 的返回值）；必填。
	Next http.Handler
	// PublicBaseURL 是独立配置的公开基础地址；其主机自动加入允许列表。它不随
	// 请求 Host 或转发头变化，不能作为动态签发身份的来源。
	PublicBaseURL string
	// ExpectedScheme 是公开地址期望的外部协议（http/https）；非空时，可信代理
	// 提供的 Forwarded/X-Forwarded-Proto 必须与它一致，否则 fail-closed。它来自
	// 显式配置，不由请求推导。
	ExpectedScheme string
	// AllowedHosts 是显式允许的 Host（host 或 host:port）。
	AllowedHosts []string
	// TrustedProxies 是唯一允许提供 Forwarded/X-Forwarded-* 的直连代理 IP/CIDR；
	// 为空时完全忽略转发头。
	TrustedProxies []string
	// NewRequestID 生成请求编号；nil 时使用内部随机编号。
	NewRequestID func() string
	// ValidateRequestID 校验外部请求编号；nil 时使用内部保守校验。
	ValidateRequestID func(string) error
	// ClientServiceIdentity 把已验证的 TLS 客户端叶证书映射为可信服务身份；nil
	// 表示本边界不建立服务身份。只有独立 Server 在启用 mTLS 时注入该函数。
	ClientServiceIdentity func(*x509.Certificate) (string, bool)
	// Logger 是运行日志器；nil 时丢弃。
	Logger *slog.Logger
}

// boundary 包装内层处理程序，先完成代理信任边界校验，再把经过验证的客户端
// 地址、请求编号与（启用 mTLS 时）可信服务身份放入上下文。构造后只读，可并发
// 使用。
type boundary struct {
	next                  http.Handler
	hosts                 netpolicy.HostSet
	trusted               proxytrust.Trusted
	expectedScheme        string
	newRequestID          func() string
	validateRequestID     func(string) error
	clientServiceIdentity func(*x509.Certificate) (string, bool)
	logger                *slog.Logger
}

// NewBoundary 构造代理边界。配置非法时返回错误，由公开包映射为 CONFIG_INVALID。
// 本函数不监听端口、不创建协程。
func NewBoundary(options BoundaryOptions) (http.Handler, error) {
	if options.Next == nil {
		return nil, fmt.Errorf("代理边界缺少内层处理程序")
	}
	trusted, err := proxytrust.Parse(options.TrustedProxies)
	if err != nil {
		return nil, err
	}
	hosts, err := netpolicy.NewHostSet(options.AllowedHosts)
	if err != nil {
		return nil, err
	}
	expectedScheme := strings.ToLower(strings.TrimSpace(options.ExpectedScheme))
	if expectedScheme == "" && options.PublicBaseURL != "" {
		parsed, err := url.Parse(options.PublicBaseURL)
		if err != nil {
			return nil, fmt.Errorf("公开基础地址不是合法 URL")
		}
		expectedScheme = strings.ToLower(parsed.Scheme)
	}
	if expectedScheme != "" && expectedScheme != "http" && expectedScheme != "https" {
		return nil, fmt.Errorf("期望的公开协议只能是 http 或 https")
	}
	if options.PublicBaseURL != "" {
		parsed, err := url.Parse(options.PublicBaseURL)
		if err != nil {
			return nil, fmt.Errorf("公开基础地址不是合法 URL")
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return nil, fmt.Errorf("公开基础地址必须使用 http 或 https")
		}
		if parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return nil, fmt.Errorf("公开基础地址只能包含协议与主机（可含路径前缀）")
		}
		hosts, err = hosts.WithHost(parsed.Host)
		if err != nil {
			return nil, fmt.Errorf("公开基础地址的主机无效: %w", err)
		}
	}
	if hosts.Empty() {
		// 没有配置公开地址或允许主机时只接受本机回环主机名，避免开发监听
		// 意外响应任意域名。
		hosts = netpolicy.LoopbackHostSet()
	}
	newRequestID := options.NewRequestID
	if newRequestID == nil {
		newRequestID = fallbackRequestID
	}
	validateRequestID := options.ValidateRequestID
	if validateRequestID == nil {
		validateRequestID = validateCorrelationFallback
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
	}
	return &boundary{
		next:                  options.Next,
		hosts:                 hosts,
		trusted:               trusted,
		expectedScheme:        expectedScheme,
		newRequestID:          newRequestID,
		validateRequestID:     validateRequestID,
		clientServiceIdentity: options.ClientServiceIdentity,
		logger:                logger,
	}, nil
}

// ServeHTTP 执行 Host 与转发头校验，再交给内层处理程序。
func (b *boundary) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	tracker := newResponseWriter(writer)
	requestID := b.resolveRequestID(request)
	tracker.Header().Set("X-Request-ID", requestID)
	tracker.Header().Set("X-Content-Type-Options", "nosniff")
	tracker.Header().Set("Cache-Control", "no-store")
	ctx := WithRequestID(request.Context(), requestID)

	if request.Host == "" {
		b.reject(tracker, requestID, newProblem(http.StatusBadRequest, "REQ_INVALID", "请求缺少主机名"),
			"missing_host")
		return
	}
	// 请求自身 Host 必须语法有效；即使可信代理另外提供了转发主机，也不接受
	// 语法歧义的 Host，避免不同层解析出不同主机名。
	if _, err := netpolicy.ParseRequestHost(request.Host); err != nil {
		b.reject(tracker, requestID, newProblem(http.StatusBadRequest, "REQ_INVALID", "请求主机名无效"),
			"invalid_host")
		return
	}

	info := proxytrust.Info{}
	if _, peerOK := proxytrust.Peer(request.RemoteAddr); peerOK {
		resolved, err := b.trusted.Resolve(request.RemoteAddr, request.Header)
		if err != nil {
			// 可信代理提供了畸形转发头：fail-closed，不回退到可能被混淆的头。
			b.reject(tracker, requestID, newProblem(http.StatusBadRequest, "REQ_INVALID", "代理转发信息无效"),
				"forwarded_invalid")
			return
		}
		info = resolved
	}

	// 可信代理声明的协议必须与显式配置的公开地址协议一致；不一致说明代理链
	// 配置错误或存在降级，按 fail-closed 拒绝，而不是继续用互相矛盾的边界信息。
	if info.HasProto && b.expectedScheme != "" && info.Proto != b.expectedScheme {
		b.reject(tracker, requestID, newProblem(http.StatusBadRequest, "REQ_INVALID",
			"代理转发协议与公开地址配置不一致"), "forwarded_scheme_mismatch")
		return
	}

	effectiveHost := request.Host
	if info.HasHost {
		effectiveHost = info.Host
	}
	allowed, err := b.hosts.Allows(effectiveHost)
	if err != nil {
		b.reject(tracker, requestID, newProblem(http.StatusBadRequest, "REQ_INVALID", "请求主机名无效"),
			"invalid_forwarded_host")
		return
	}
	if !allowed {
		// 不回显被拒绝的主机名，避免把攻击者输入写进响应或日志。
		b.reject(tracker, requestID, newProblem(hostRejectedStatus, "REQ_INVALID", "请求的主机名不受信任"),
			"host_not_allowed")
		return
	}
	if info.ClientAddr.IsValid() {
		ctx = WithClientIP(ctx, info.ClientAddr.String())
	}
	// mTLS 已由 TLS 层完成证书链、用途与身份映射校验；这里把已验证叶证书的
	// 映射结果放进上下文，供业务层做授权判断（不携带任何权限）。
	if b.clientServiceIdentity != nil && request.TLS != nil && len(request.TLS.PeerCertificates) > 0 {
		if identity, ok := b.clientServiceIdentity(request.TLS.PeerCertificates[0]); ok {
			ctx = WithClientServiceIdentity(ctx, identity)
		}
	}
	cloned := request.Clone(ctx)
	// 内层只看到经过允许列表校验的有效 Host（可信代理改写时是外部主机），避免
	// 后续 Host 相关逻辑误用未经校验的原始值。
	cloned.Host = effectiveHost
	// 把规范化后的请求编号交给内层，保证错误响应、访问日志与边界使用同一编号。
	cloned.Header.Set("X-Request-ID", requestID)
	stripProxyHeaders(cloned.Header)
	b.next.ServeHTTP(tracker, cloned)
}

// resolveRequestID 返回本次请求编号：客户端合法且唯一的编号可复用，否则生成新
// 编号。非法值不会被回显。
func (b *boundary) resolveRequestID(request *http.Request) string {
	values := request.Header.Values("X-Request-ID")
	if len(values) == 1 {
		candidate := strings.TrimSpace(values[0])
		if len(candidate) <= 64 && b.validateRequestID(candidate) == nil {
			return candidate
		}
	}
	return b.newRequestID()
}

// reject 写出统一错误 JSON 并记录不含请求内容的原因码；不记录被拒绝的 Host、
// 转发头原文或客户端地址，避免日志注入与隐私泄露。
func (b *boundary) reject(w *responseWriter, requestID string, p *problem, reason string) {
	b.logger.Warn("拒绝 HTTP 请求", "request_id", requestID, "reason", reason)
	writeProblem(w, requestID, p)
}

// stripProxyHeaders 删除内层处理程序不应再看到的代理转发头。
func stripProxyHeaders(header http.Header) {
	for _, name := range proxyHeaderNames {
		header.Del(name)
	}
}
