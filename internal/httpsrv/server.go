// Package httpsrv 实现独立监听的 HTTP 服务生命周期：监听地址绑定、代理信任
// 边界、TLS/mTLS 证书装配、优雅关闭与 TLS 状态投影。
//
// 职责边界：
//   - 只负责「监听 + 边界 + TLS 生命周期」，不创建业务 Handler、不打开数据库、
//     不启动业务协程；Handler 由 internal/httpassemble 构造后传入。
//   - 公开契约（ServerOptions/TLS 状态类型）位于 httpapi 叶子包；本包内部实现
//     不暴露内部类型到公开签名。
//   - 配置来自公共 config 叶子包，地址解析使用公共 netpolicy，代理边界与传输
//     防护使用 internal/transport；不复制其安全逻辑。
package httpsrv

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/config"
	"github.com/kagurazakayashi/EvernightLogin/errs"
	"github.com/kagurazakayashi/EvernightLogin/httpapi"
	"github.com/kagurazakayashi/EvernightLogin/internal/listener"
	"github.com/kagurazakayashi/EvernightLogin/internal/tlscert"
	"github.com/kagurazakayashi/EvernightLogin/internal/transport"
	"github.com/kagurazakayashi/EvernightLogin/netpolicy"
)

// Options 是构造独立监听服务的内部依赖；由公开门面从 httpapi.ServerOptions
// 转换而来。
type Options struct {
	Config  config.Config
	Handler http.Handler
	Prefix  string
	Logger  *slog.Logger
}

// Server 是独立监听引擎；公开门面（根包 Server）包装它并对宿主暴露稳定 API。
//
// 监听语义：
//   - Start 依次绑定 Config.Server.ListenAddresses() 的全部地址；任一失败时关闭
//     已打开的全部监听并整体回滚，不留下占用中的端口。
//   - 非回环明文监听必须显式启用 Config.Server.TLSProxyMode，并配置可信代理与
//     https 公开地址；默认只监听本机回环地址，不偷偷开放所有网卡。
//   - 每个请求先由代理信任边界校验 Host 与转发头，再进入 Handler；限流与访问
//     日志使用边界验证过的客户端地址。
//   - Close 在调用方期限与配置的关闭超时较小值内优雅关闭，必要时强制关闭连接并
//     释放全部监听端口。
type Server struct {
	inner  *listener.Server
	tls    *tlscert.Manager
	config config.Config
}

// configInvalid 构造与公开门面一致的 CONFIG_INVALID 错误（消息与原因链保留，
// 由根门面直接返回给宿主）。
func configInvalid(message string, cause error) error {
	return errs.NewAppError(errs.CodeConfigInvalid, message, errs.WithCause(cause))
}

// New 校验选项并构造监听服务，但不绑定任何端口、不创建协程。选项或配置非法时
// 返回 CONFIG_INVALID 统一错误（消息与迁移前根包 NewServer 保持一致）。
func New(options Options) (*Server, error) {
	if options.Handler == nil {
		return nil, configInvalid("独立监听服务缺少 HTTP 处理程序",
			fmt.Errorf("Handler 为 nil"))
	}
	if err := options.Config.Validate(); err != nil {
		return nil, configInvalid("独立监听服务配置无效", err)
	}

	prefix, err := transport.NormalizePrefix(options.Prefix)
	if err != nil {
		return nil, configInvalid("独立监听服务的路径前缀无效", err)
	}
	configPrefix, err := transport.NormalizePrefix(options.Config.Server.PathPrefix)
	if err != nil {
		return nil, configInvalid("配置的路径前缀无效", err)
	}
	if configPrefix != "" && configPrefix != prefix {
		return nil, configInvalid("ServerOptions.Prefix 必须与 server.path_prefix 一致",
			fmt.Errorf("Prefix=%q server.path_prefix=%q", prefix, configPrefix))
	}

	publicBaseURL := options.Config.Server.PublicBaseURL
	publicPath := ""
	if publicBaseURL != "" {
		parsed, parseErr := url.Parse(publicBaseURL)
		if parseErr != nil {
			return nil, configInvalid("公开基础地址无效", parseErr)
		}
		publicPath = parsed.EscapedPath()
		if publicPath == "/" {
			publicPath = ""
		}
		if publicPath != prefix {
			return nil, configInvalid("公开基础地址的路径必须与路径前缀一致",
				fmt.Errorf("公开地址路径=%q 路径前缀=%q", publicPath, prefix))
		}
	}

	rawAddresses := options.Config.Server.ListenAddresses()
	if len(rawAddresses) == 0 {
		return nil, configInvalid("至少需要一个监听地址",
			fmt.Errorf("server.listen_addr 与 server.extra_listen_addrs 都为空"))
	}
	if len(rawAddresses) > config.MaxServerListenAddresses {
		return nil, configInvalid("监听地址数量超过上限",
			fmt.Errorf("最多 %d 个监听地址", config.MaxServerListenAddresses))
	}
	addresses := make([]netpolicy.ListenAddress, 0, len(rawAddresses))
	nonLoopback := false
	for _, raw := range rawAddresses {
		address, parseErr := netpolicy.ParseListenAddress(raw, false)
		if parseErr != nil {
			return nil, configInvalid("监听地址无效", parseErr)
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
			return nil, configInvalid("TLS 证书或客户端证书信任配置无效", tlsErr)
		}
		if tlsErr := checkTLSCertificateCoverage(manager, options.Config.Server); tlsErr != nil {
			return nil, configInvalid("TLS 证书未覆盖配置的公开主机", tlsErr)
		}
		tlsManager = manager
	}

	// 非回环监听：本地 TLS 可以直接保护传输；否则必须是显式确认的 TLS 终止代理
	// 部署模式（https 公开地址 + 可信代理）。默认开发监听只允许回环地址。
	if nonLoopback && !tlsEnabled {
		if !options.Config.Server.TLSProxyMode {
			return nil, configInvalid(
				"非回环明文监听必须显式启用 TLS 终止代理模式或配置本地 TLS 证书",
				fmt.Errorf("请配置 server.tls_terminating_proxy=true 或 TLS 证书，或改为监听本机回环地址"))
		}
		if len(options.Config.Server.TrustedProxies) == 0 {
			return nil, configInvalid("非回环明文监听必须配置可信代理",
				fmt.Errorf("server.trusted_proxies 不能为空"))
		}
		parsed, parseErr := url.Parse(publicBaseURL)
		if parseErr != nil || parsed.Scheme != "https" {
			return nil, configInvalid("非回环明文监听必须配置 https 公开地址",
				fmt.Errorf("server.public_base_url 必须使用 https"))
		}
	}

	boundaryOptions := transport.BoundaryOptions{
		Next:              options.Handler,
		PublicBaseURL:     publicBaseURL,
		AllowedHosts:      options.Config.Server.AllowedHosts,
		TrustedProxies:    options.Config.Server.TrustedProxies,
		NewRequestID:      errs.NewRequestID,
		ValidateRequestID: errs.ValidateRequestID,
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
		return nil, configInvalid("代理信任边界配置无效", err)
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
		return nil, configInvalid("监听器配置无效", err)
	}
	return &Server{inner: inner, tls: tlsManager, config: options.Config}, nil
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
// 到期监控，本包不发送通知、不自动续期。
func (s *Server) TLSStatus() (httpapi.TLSStatus, bool) {
	if s == nil || s.tls == nil {
		return httpapi.TLSStatus{}, false
	}
	return publicTLSStatus(s.tls.Status()), true
}

// ReloadTLS 重新读取证书文件并完整校验，成功后才原子替换生效证书；失败时保留
// 仍在使用的旧证书并返回 CONFIG_INVALID 错误。它还会复验候选证书是否覆盖
// public_base_url 与 allowed_hosts 中的主机名，与启动检查一致，避免出现“重载
// 成功但原主机无法握手”的半更新；不会中断正在进行的握手。
//
// 本方法只重载服务器证书材料：客户端信任 CA、客户端证书认证模式与身份映射保持
// 启动时配置不变；撤销客户端身份、轮换客户端信任 CA 或改变 mTLS 策略必须更新
// 配置并重启进程。
func (s *Server) ReloadTLS(ctx context.Context) error {
	if s == nil || s.tls == nil {
		return errs.NewAppError(errs.CodeConfigInvalid, "未启用本地 TLS 证书",
			errs.WithCause(fmt.Errorf("server.tls_cert_files 与 server.tls_pfx_file 都未配置")))
	}
	validate := func(candidate tlscert.Status) error {
		return checkTLSCertificateCoverageStatus(candidate, s.config.Server)
	}
	if err := s.tls.ReloadChecked(ctx, validate); err != nil {
		return errs.NewAppError(errs.CodeConfigInvalid, "TLS 证书重载失败",
			errs.WithCause(err))
	}
	return nil
}
