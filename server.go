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
	"github.com/kagurazakayashi/EvernightLogin/internal/netpolicy"
	"github.com/kagurazakayashi/EvernightLogin/internal/transport"
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
//
// Server 不打开数据库、不创建 Handler、不启动业务协程；外部公开地址、未来的
// OIDC Issuer 与 WebAuthn RP ID 都必须来自各自独立的显式配置，绝不能由请求
// Host 或转发头动态推导。
type Server struct {
	inner *listener.Server
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

	// 非回环明文监听只在显式确认的 TLS 终止代理部署模式下允许：必须已声明
	// https 外部地址并配置可信代理。默认开发监听只允许回环地址。
	if nonLoopback {
		if !options.Config.Server.TLSProxyMode {
			return nil, NewAppError(CodeConfigInvalid,
				"非回环明文监听必须显式启用 TLS 终止代理模式",
				WithCause(fmt.Errorf("请配置 server.tls_terminating_proxy=true，或改为监听本机回环地址")))
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

	boundary, err := transport.NewBoundary(transport.BoundaryOptions{
		Next:              options.Handler,
		PublicBaseURL:     publicBaseURL,
		AllowedHosts:      options.Config.Server.AllowedHosts,
		TrustedProxies:    options.Config.Server.TrustedProxies,
		NewRequestID:      NewRequestID,
		ValidateRequestID: ValidateRequestID,
		Logger:            options.Logger,
	})
	if err != nil {
		return nil, NewAppError(CodeConfigInvalid, "代理信任边界配置无效", WithCause(err))
	}

	inner, err := listener.New(listener.Options{
		Addresses:       addresses,
		Handler:         boundary,
		Logger:          options.Logger,
		ShutdownTimeout: time.Duration(options.Config.Server.ShutdownTimeoutSeconds) * time.Second,
	})
	if err != nil {
		return nil, NewAppError(CodeConfigInvalid, "监听器配置无效", WithCause(err))
	}
	return &Server{inner: inner}, nil
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
