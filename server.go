package login

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/listener"
	"github.com/kagurazakayashi/EvernightLogin/internal/tlscert"
	"github.com/kagurazakayashi/EvernightLogin/internal/transport"
	"github.com/kagurazakayashi/EvernightLogin/netpolicy"
)

// ServerOptions 是构造独立监听服务的显式依赖。
//
// Server 只负责“监听 + 代理信任边界 + Host 校验”，不创建 Handler；Handler 必须
// 由 NewHTTPHandler 构造后传入。这样可以保证嵌入模式与独立服务复用同一套
// HTTP 处理、限流、身份与错误响应逻辑，不存在两套业务入口。
type ServerOptions struct {
	// Config 是有效配置快照；NewServer 会再次调用 Validate。Config.Server 决定
	// 监听地址、公开基础地址、路径前缀、允许 Host、可信代理、TLS 终止代理模式
	// 与关闭超时。零值配置缺少监听地址，会被拒绝。
	Config Config
	// Handler 是内层 HTTP 处理程序；必填。
	Handler http.Handler
	// Prefix 是与 Handler 一致的固定路径前缀（HTTPOptions.Prefix）。配置里设置
	// 了 server.path_prefix 时必须与之一致；公开基础地址带路径时也必须一致。
	Prefix string
	// Logger 是运行日志器；nil 表示静默。它只用于监听与代理边界的生命周期和
	// 拒绝日志，不代替访问日志或安全审计。
	Logger *slog.Logger
}

// Server 是独立监听组件，实现 BackgroundComponent：把它放进 login.Options 的
// Components 后，由 Instance 统一启动、失败回滚与关闭。
//
// 监听语义：
//   - Start 依次绑定 Config.Server.ListenAddresses() 的全部地址；任一失败时关闭
//     已打开的全部监听并整体回滚，不留下占用中的端口。
//   - 非回环明文监听必须显式启用 Config.Server.TLSProxyMode，并配置可信代理与
//     https 公开地址；默认只监听本机回环地址，不偷偷开放所有网卡。
//   - 每个请求先由代理信任边界校验 Host 与转发头，再进入 Handler；限流与访问
//     日志使用边界验证过的客户端地址。
//   - Close 在调用方期限与 Config.Server.ShutdownTimeoutSeconds 的较小值内优雅
//     关闭，必要时强制关闭连接，并释放全部监听端口。
//   - 配置了 server.tls_cert_files/tls_key_files 或 server.tls_pfx_file 时所有
//     监听地址提供 HTTPS；ReloadTLS 在完整校验后原子替换服务器证书，失败保留
//     旧证书；TLSStatus 提供到期状态（不发送通知、不自动续期）。
//   - 配置了 server.tls_client_auth（required/optional）时同时要求客户端证书：
//     证书必须链到独立的客户端信任 CA、处于有效期、具备客户端认证用途，并且
//     叶证书 DNS 名称命中显式身份映射；仅有受信任 CA 签发不足以获准接入。可选
//     模式允许匿名连接，但出示无效证书会直接失败，不会降级为匿名。客户端信任
//     与身份映射只在进程启动时加载；修改它们需要重启，ReloadTLS 不重载。
//
// Server 不打开数据库、不创建 Handler、不启动业务协程；外部公开地址、未来的
// OIDC Issuer 与 WebAuthn RP ID 都必须来自各自独立的显式配置，绝不能由请求
// Host 或转发头动态推导。
type Server struct {
	inner  *listener.Server
	tls    *tlscert.Manager
	config Config
}

// TLSCertificateStatus 是单张服务器叶证书的脱敏状态。
type TLSCertificateStatus struct {
	// Domains 是证书覆盖的规范化 DNS 名称（含 *.example.com 通配）。
	Domains []string
	// NotBefore/NotAfter 是证书有效期边界。
	NotBefore time.Time
	NotAfter  time.Time
	// FingerprintSHA256 是叶证书 DER 的 SHA-256 指纹（小写十六进制）。
	FingerprintSHA256 string
	// SerialNumber 是叶证书序列号（十六进制）。
	SerialNumber string
	// SelfSigned 表示叶证书自签名；不表示客户端自动信任它。
	SelfSigned bool
}

// TLSClientTrustAnchor 是单个客户端信任 CA 的脱敏状态（公共证书信息，不含私钥）。
type TLSClientTrustAnchor struct {
	// Subject 是证书主题的可读文本。
	Subject string
	// FingerprintSHA256 是证书 DER 的 SHA-256 指纹（小写十六进制）。
	FingerprintSHA256 string
	// NotBefore/NotAfter 是信任 CA 的有效期边界。
	NotBefore time.Time
	NotAfter  time.Time
	// SelfSigned 表示证书主题与签发者相同。
	SelfSigned bool
}

// TLSClientAuthStatus 是客户端证书认证的只读状态，用于诊断运行中的 mTLS 配置。
// 它只包含公开信息：模式、信任 CA 的公共证书摘要与身份映射，不含私钥或密码。
type TLSClientAuthStatus struct {
	// Mode 是归一化后的客户端证书认证模式；未启用时为 disabled。
	Mode TLSClientAuthMode
	// TrustAnchors 是已加载的客户端信任 CA。
	TrustAnchors []TLSClientTrustAnchor
	// Identities 是生效中的“证书 DNS 名称 -> 可信服务身份”映射。
	Identities []TLSClientIdentity
}

// TLSStatus 是本地 TLS 证书的只读状态，用于诊断、到期监控与未来调度/通知接入。
// 本步不发送到期通知，也不实现证书自动续期；调用方可按 ExpiringSoon/Expired
// 决定是否告警或触发 ReloadTLS。
type TLSStatus struct {
	// LoadedAt 是当前生效证书的加载时间。
	LoadedAt time.Time
	// Certificates 是各证书身份状态。
	Certificates []TLSCertificateStatus
	// EarliestNotAfter 是最早到期的证书时间。
	EarliestNotAfter time.Time
	// Expired 表示当前时间已晚于最早到期时间。
	Expired bool
	// ExpiringSoon 表示已进入 server.tls_expiry_warning_days 告警窗口。
	ExpiringSoon bool
	// ReloadFailures 是最近一次成功重载之后连续失败的重载次数。
	ReloadFailures int
	// LastReloadAt 是最近一次重载尝试时间；零值表示尚未重载。
	LastReloadAt time.Time
	// LastReloadFailed 表示最近一次重载是否失败。
	LastReloadFailed bool
	// ClientAuth 是客户端证书认证状态；未启用 mTLS 时 Mode 为 disabled。
	// 客户端信任配置不随 ReloadTLS 变化，撤销与信任更新需要重启进程。
	ClientAuth TLSClientAuthStatus
}

// 编译期确认 Server 可以作为 Instance 管理的后台组件。
var _ BackgroundComponent = (*Server)(nil)

// NewServer 校验选项并构造监听服务，但不绑定任何端口、不创建协程。选项或配置
// 非法时返回 CONFIG_INVALID 统一错误。
func NewServer(options ServerOptions) (*Server, error) {
	if options.Handler == nil {
		return nil, NewAppError(CodeConfigInvalid, "独立监听服务缺少 HTTP 处理程序",
			WithCause(fmt.Errorf("Handler 为 nil")))
	}
	if err := options.Config.Validate(); err != nil {
		return nil, NewAppError(CodeConfigInvalid, "独立监听服务配置无效", WithCause(err))
	}

	prefix, err := transport.NormalizePrefix(options.Prefix)
	if err != nil {
		return nil, NewAppError(CodeConfigInvalid, "独立监听服务的路径前缀无效", WithCause(err))
	}
	configPrefix, err := transport.NormalizePrefix(options.Config.Server.PathPrefix)
	if err != nil {
		return nil, NewAppError(CodeConfigInvalid, "配置的路径前缀无效", WithCause(err))
	}
	if configPrefix != "" && configPrefix != prefix {
		return nil, NewAppError(CodeConfigInvalid, "ServerOptions.Prefix 必须与 server.path_prefix 一致",
			WithCause(fmt.Errorf("Prefix=%q server.path_prefix=%q", prefix, configPrefix)))
	}

	publicBaseURL := options.Config.Server.PublicBaseURL
	publicPath := ""
	if publicBaseURL != "" {
		parsed, parseErr := url.Parse(publicBaseURL)
		if parseErr != nil {
			return nil, NewAppError(CodeConfigInvalid, "公开基础地址无效", WithCause(parseErr))
		}
		publicPath = parsed.EscapedPath()
		if publicPath == "/" {
			publicPath = ""
		}
		if publicPath != prefix {
			return nil, NewAppError(CodeConfigInvalid, "公开基础地址的路径必须与路径前缀一致",
				WithCause(fmt.Errorf("公开地址路径=%q 路径前缀=%q", publicPath, prefix)))
		}
	}

	rawAddresses := options.Config.Server.ListenAddresses()
	if len(rawAddresses) == 0 {
		return nil, NewAppError(CodeConfigInvalid, "至少需要一个监听地址",
			WithCause(fmt.Errorf("server.listen_addr 与 server.extra_listen_addrs 都为空")))
	}
	if len(rawAddresses) > MaxServerListenAddresses {
		return nil, NewAppError(CodeConfigInvalid, "监听地址数量超过上限",
			WithCause(fmt.Errorf("最多 %d 个监听地址", MaxServerListenAddresses)))
	}
	addresses := make([]netpolicy.ListenAddress, 0, len(rawAddresses))
	nonLoopback := false
	for _, raw := range rawAddresses {
		address, parseErr := netpolicy.ParseListenAddress(raw, false)
		if parseErr != nil {
			return nil, NewAppError(CodeConfigInvalid, "监听地址无效", WithCause(parseErr))
		}
		if !address.IsLoopback() {
			nonLoopback = true
		}
		addresses = append(addresses, address)
	}

	tlsEnabled := options.Config.Server.TLSEnabled()
	var tlsManager *tlscert.Manager
	if tlsEnabled {
		manager, tlsErr := newTLSManager(options.Config, options.Logger)
		if tlsErr != nil {
			return nil, NewAppError(CodeConfigInvalid, "TLS 证书或客户端证书信任配置无效", WithCause(tlsErr))
		}
		if tlsErr := checkTLSCertificateCoverage(manager, options.Config.Server); tlsErr != nil {
			return nil, NewAppError(CodeConfigInvalid, "TLS 证书未覆盖配置的公开主机", WithCause(tlsErr))
		}
		tlsManager = manager
	}

	// 非回环监听：本地 TLS 可以直接保护传输；否则必须是显式确认的 TLS 终止代理
	// 部署模式（https 公开地址 + 可信代理）。默认开发监听只允许回环地址。
	if nonLoopback && !tlsEnabled {
		if !options.Config.Server.TLSProxyMode {
			return nil, NewAppError(CodeConfigInvalid,
				"非回环明文监听必须显式启用 TLS 终止代理模式或配置本地 TLS 证书",
				WithCause(fmt.Errorf("请配置 server.tls_terminating_proxy=true 或 TLS 证书，或改为监听本机回环地址")))
		}
		if len(options.Config.Server.TrustedProxies) == 0 {
			return nil, NewAppError(CodeConfigInvalid,
				"非回环明文监听必须配置可信代理",
				WithCause(fmt.Errorf("server.trusted_proxies 不能为空")))
		}
		parsed, parseErr := url.Parse(publicBaseURL)
		if parseErr != nil || parsed.Scheme != "https" {
			return nil, NewAppError(CodeConfigInvalid,
				"非回环明文监听必须配置 https 公开地址",
				WithCause(fmt.Errorf("server.public_base_url 必须使用 https")))
		}
	}

	boundaryOptions := transport.BoundaryOptions{
		Next:              options.Handler,
		PublicBaseURL:     publicBaseURL,
		AllowedHosts:      options.Config.Server.AllowedHosts,
		TrustedProxies:    options.Config.Server.TrustedProxies,
		NewRequestID:      NewRequestID,
		ValidateRequestID: ValidateRequestID,
		Logger:            options.Logger,
	}
	if tlsManager != nil {
		boundaryOptions.ClientServiceIdentity = tlsManager.ClientServiceIdentity
	}
	if publicBaseURL != "" {
		if parsed, parseErr := url.Parse(publicBaseURL); parseErr == nil {
			// 可信代理声明的协议必须与显式公开地址一致；本地 TLS 也要求 https。
			boundaryOptions.ExpectedScheme = parsed.Scheme
		}
	}
	boundary, err := transport.NewBoundary(boundaryOptions)
	if err != nil {
		return nil, NewAppError(CodeConfigInvalid, "代理信任边界配置无效", WithCause(err))
	}

	listenerOptions := listener.Options{
		Addresses:       addresses,
		Handler:         boundary,
		Logger:          options.Logger,
		ShutdownTimeout: time.Duration(options.Config.Server.ShutdownTimeoutSeconds) * time.Second,
	}
	if tlsManager != nil {
		listenerOptions.TLSConfig = tlsManager.TLSConfig()
	}
	inner, err := listener.New(listenerOptions)
	if err != nil {
		return nil, NewAppError(CodeConfigInvalid, "监听器配置无效", WithCause(err))
	}
	return &Server{inner: inner, tls: tlsManager, config: options.Config}, nil
}

// newTLSManager 从有效配置构造 TLS 证书管理器。到期告警天数 0 表示使用默认值。
// PFX 密码来自配置秘密，只在内存中传给加载器，不写入日志或错误。客户端证书
// 认证所需的信任 CA 与身份映射一并传入；它们的客户端信任配置在进程生命周期内
// 不变。
func newTLSManager(cfg Config, logger *slog.Logger) (*tlscert.Manager, error) {
	warningDays := cfg.Server.TLSExpiryWarningDays
	if warningDays == 0 {
		warningDays = DefaultServerTLSExpiryWarningDays
	}
	clientAuth := tlscert.ClientAuthOptions{
		Mode:       tlscert.ClientAuthDisabled,
		CAFiles:    append([]string(nil), cfg.Server.TLSClientCAFiles...),
		Identities: make([]tlscert.ClientIdentity, 0, len(cfg.Server.TLSClientIdentities)),
	}
	switch normalizeTLSClientAuthMode(cfg.Server.TLSClientAuthMode) {
	case TLSClientAuthRequired:
		clientAuth.Mode = tlscert.ClientAuthRequired
	case TLSClientAuthOptional:
		clientAuth.Mode = tlscert.ClientAuthOptional
	}
	for _, identity := range cfg.Server.TLSClientIdentities {
		clientAuth.Identities = append(clientAuth.Identities, tlscert.ClientIdentity{
			DNSName: identity.DNSName,
			Service: identity.Service,
		})
	}
	return tlscert.New(tlscert.Options{
		Source: tlscert.Source{
			CertFiles:   append([]string(nil), cfg.Server.TLSCertFiles...),
			KeyFiles:    append([]string(nil), cfg.Server.TLSKeyFiles...),
			CAFile:      cfg.Server.TLSCAFile,
			PFXFile:     cfg.Server.TLSPFXFile,
			PFXPassword: cfg.Secrets.TLSPFXPassword.Value(),
		},
		ClientAuth:    clientAuth,
		ExpiryWarning: time.Duration(warningDays) * 24 * time.Hour,
		Logger:        logger,
	})
}

// checkTLSCertificateCoverage 把显式公开地址与允许 Host 中的主机名同证书 DNS
// 名称交叉检查：某个配置主机没有被任何证书覆盖时，即使 Host 校验通过，客户端
// 也会因证书不匹配而握手失败，因此启动阶段就拒绝。IP 地址不在此检查范围（由
// 证书 IP SAN 与客户端校验负责）。
func checkTLSCertificateCoverage(manager *tlscert.Manager, cfg ServerConfig) error {
	return checkTLSCertificateCoverageStatus(manager.Status(), cfg)
}

// checkTLSCertificateCoverageStatus 用给定的候选状态执行同一套主机覆盖检查；
// 启动与重载共用它，避免“启动被拒但重载放行”的规则不一致。
func checkTLSCertificateCoverageStatus(status tlscert.Status, cfg ServerConfig) error {
	hosts := make([]string, 0, 1+len(cfg.AllowedHosts))
	if cfg.PublicBaseURL != "" {
		if parsed, err := url.Parse(cfg.PublicBaseURL); err == nil {
			if host := parsed.Hostname(); host != "" {
				hosts = append(hosts, host)
			}
		}
	}
	for _, raw := range cfg.AllowedHosts {
		parsed, err := netpolicy.ParseRequestHost(raw)
		if err != nil || parsed.IsIP() {
			continue
		}
		hosts = append(hosts, parsed.Host())
	}
	if len(hosts) == 0 {
		return nil
	}
	for _, host := range hosts {
		covered := false
		for _, certificate := range status.Certificates {
			if certificate.CoversDomain(host) {
				covered = true
				break
			}
		}
		if !covered {
			return fmt.Errorf("证书未覆盖主机 %q", host)
		}
	}
	return nil
}

// Start 绑定全部配置的地址并开始处理请求。任一地址失败时整体回滚并返回错误；
// 启动失败后不能再次 Start。
func (s *Server) Start(ctx context.Context) error {
	if s == nil || s.inner == nil {
		return fmt.Errorf("独立监听服务未初始化")
	}
	return s.inner.Start(ctx)
}

// Close 优雅关闭监听与连接，受调用方期限和配置的关闭超时共同约束；必要时强制
// 关闭并如实返回未完成原因。重复 Close 安全。
func (s *Server) Close(ctx context.Context) error {
	if s == nil || s.inner == nil {
		return nil
	}
	return s.inner.Close(ctx)
}

// Addrs 返回实际绑定的地址（含系统分配端口）；未启动时返回 nil。返回副本，
// 调用方修改不影响监听器。
func (s *Server) Addrs() []net.Addr {
	if s == nil || s.inner == nil {
		return nil
	}
	return s.inner.Addrs()
}

// TLSEnabled 报告该监听服务是否配置并成功加载了本地 TLS 证书。
func (s *Server) TLSEnabled() bool {
	return s != nil && s.tls != nil
}

// TLSStatus 返回本地 TLS 证书状态；未启用 TLS 时返回 false。状态用于诊断与
// 到期监控，未来调度/通知可按 ExpiringSoon/Expired 接入，但本步不发送通知。
func (s *Server) TLSStatus() (TLSStatus, bool) {
	if s == nil || s.tls == nil {
		return TLSStatus{}, false
	}
	status := s.tls.Status()
	result := TLSStatus{
		LoadedAt:         status.LoadedAt,
		EarliestNotAfter: status.EarliestNotAfter,
		Expired:          status.Expired,
		ExpiringSoon:     status.ExpiringSoon,
		ReloadFailures:   status.ReloadFailures,
		LastReloadAt:     status.LastReloadAt,
		LastReloadFailed: status.LastReloadFailed,
	}
	result.Certificates = make([]TLSCertificateStatus, len(status.Certificates))
	for index, certificate := range status.Certificates {
		result.Certificates[index] = TLSCertificateStatus{
			Domains:           append([]string(nil), certificate.Domains...),
			NotBefore:         certificate.NotBefore,
			NotAfter:          certificate.NotAfter,
			FingerprintSHA256: certificate.FingerprintSHA256,
			SerialNumber:      certificate.SerialNumber,
			SelfSigned:        certificate.SelfSigned,
		}
	}
	result.ClientAuth = TLSClientAuthStatus{
		Mode:         TLSClientAuthMode(status.ClientAuth.Mode),
		TrustAnchors: make([]TLSClientTrustAnchor, len(status.ClientAuth.TrustAnchors)),
		Identities:   make([]TLSClientIdentity, len(status.ClientAuth.Identities)),
	}
	if result.ClientAuth.Mode == "" {
		result.ClientAuth.Mode = TLSClientAuthDisabled
	}
	for index, anchor := range status.ClientAuth.TrustAnchors {
		result.ClientAuth.TrustAnchors[index] = TLSClientTrustAnchor{
			Subject:           anchor.Subject,
			FingerprintSHA256: anchor.FingerprintSHA256,
			NotBefore:         anchor.NotBefore,
			NotAfter:          anchor.NotAfter,
			SelfSigned:        anchor.SelfSigned,
		}
	}
	for index, identity := range status.ClientAuth.Identities {
		result.ClientAuth.Identities[index] = TLSClientIdentity{
			DNSName: identity.DNSName,
			Service: identity.Service,
		}
	}
	return result, true
}

// ReloadTLS 重新读取证书文件并完整校验，成功后才原子替换生效证书；失败时保留
// 仍在使用的旧证书并返回 CONFIG_INVALID 错误（内部原因只用于日志/诊断，不写入
// HTTP 响应）。除证书材料校验外，它还会复验候选证书是否覆盖 public_base_url 与
// allowed_hosts 中的主机名，与 NewServer 的启动检查一致，避免出现“重载成功但原
// 主机无法握手”的半更新。它不会中断正在进行的 TLS 握手或 HTTPS 请求。
//
// 本方法只重载服务器证书材料：客户端信任 CA、客户端证书认证模式与身份映射保持
// 启动时配置不变。撤销客户端身份、轮换客户端信任 CA 或改变 mTLS 策略必须更新
// 配置并重启进程；重启会关闭已有连接，不提供在线 OCSP/CRL 撤销。
func (s *Server) ReloadTLS(ctx context.Context) error {
	if s == nil || s.tls == nil {
		return NewAppError(CodeConfigInvalid, "未启用本地 TLS 证书",
			WithCause(fmt.Errorf("server.tls_cert_files 与 server.tls_pfx_file 都未配置")))
	}
	validate := func(candidate tlscert.Status) error {
		return checkTLSCertificateCoverageStatus(candidate, s.config.Server)
	}
	if err := s.tls.ReloadChecked(ctx, validate); err != nil {
		return NewAppError(CodeConfigInvalid, "TLS 证书重载失败", WithCause(err))
	}
	return nil
}
