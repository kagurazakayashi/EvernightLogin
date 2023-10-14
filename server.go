package login

// 独立监听服务公开门面（步骤 213 迁移后）。
//
// 公开契约（ServerOptions/TLS 状态类型）位于 httpapi 叶子包；监听、代理信任边界、
// TLS/mTLS 装配与关闭实现位于 internal/httpsrv；根包 Server 只保留薄门面与既有
// 公开方法/行为。

import (
	"context"
	"fmt"
	"net"

	"github.com/kagurazakayashi/EvernightLogin/internal/httpsrv"
)

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
	engine *httpsrv.Server
}

// 编译期确认 Server 可以作为 Instance 管理的后台组件。
var _ BackgroundComponent = (*Server)(nil)

// NewServer 校验选项并构造监听服务，但不绑定任何端口、不创建协程。选项或配置
// 非法时返回 CONFIG_INVALID 统一错误（消息与迁移前一致）。
func NewServer(options ServerOptions) (*Server, error) {
	engine, err := httpsrv.New(httpsrv.Options{
		Config: options.Config, Handler: options.Handler,
		Prefix: options.Prefix, Logger: options.Logger,
	})
	if err != nil {
		return nil, err
	}
	return &Server{engine: engine}, nil
}

// Start 绑定全部配置的地址并开始处理请求。任一地址失败时整体回滚并返回错误；
// 启动失败后不能再次 Start。
func (s *Server) Start(ctx context.Context) error {
	if s == nil || s.engine == nil {
		return fmt.Errorf("独立监听服务未初始化")
	}
	return s.engine.Start(ctx)
}

// Close 优雅关闭监听与连接，受调用方期限和配置的关闭超时共同约束；必要时强制
// 关闭并如实返回未完成原因。重复 Close 安全。
func (s *Server) Close(ctx context.Context) error {
	if s == nil || s.engine == nil {
		return nil
	}
	return s.engine.Close(ctx)
}

// Addrs 返回实际绑定的地址（含系统分配端口）；未启动时返回 nil。返回副本，
// 调用方修改不影响监听器。
func (s *Server) Addrs() []net.Addr {
	if s == nil || s.engine == nil {
		return nil
	}
	return s.engine.Addrs()
}

// TLSEnabled 报告该监听服务是否配置并成功加载了本地 TLS 证书。
func (s *Server) TLSEnabled() bool {
	return s != nil && s.engine != nil && s.engine.TLSEnabled()
}

// TLSStatus 返回本地 TLS 证书状态；未启用 TLS 时返回 false。状态用于诊断与
// 到期监控，未来调度/通知可按 ExpiringSoon/Expired 接入，但本步骤不发送通知。
func (s *Server) TLSStatus() (TLSStatus, bool) {
	if s == nil || s.engine == nil {
		return TLSStatus{}, false
	}
	return s.engine.TLSStatus()
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
	if s == nil || s.engine == nil {
		return NewAppError(CodeConfigInvalid, "未启用本地 TLS 证书", WithCause(fmt.Errorf("server.tls_cert_files 与 server.tls_pfx_file 都未配置")))
	}
	return s.engine.ReloadTLS(ctx)
}
