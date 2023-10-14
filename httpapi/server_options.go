package httpapi

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/config"
)

// ServerOptions 是构造独立监听服务的显式依赖。
//
// Server 只负责“监听 + 代理信任边界 + Host 校验”，不创建 Handler；Handler 必须
// 由 NewHTTPHandler 构造后传入。这样可以保证嵌入模式与独立服务复用同一套 HTTP
// 处理、限流、身份与错误响应逻辑，不存在两套业务入口。
type ServerOptions struct {
	// Config 是有效配置快照；NewServer 会再次调用 Validate。Config.Server 决定
	// 监听地址、公开基础地址、路径前缀、允许 Host、可信代理、TLS 终止代理模式
	// 与关闭超时。零值配置缺少监听地址，会被拒绝。
	Config config.Config
	// Handler 是内层 HTTP 处理程序；必填。
	Handler http.Handler
	// Prefix 是与 Handler 一致的固定路径前缀（HTTPOptions.Prefix）。配置里设置
	// 了 server.path_prefix 时必须与之一致；公开基础地址带路径时也必须一致。
	Prefix string
	// Logger 是运行日志器；nil 表示静默。它只用于监听与代理边界的生命周期和
	// 拒绝日志，不代替访问日志或安全审计。
	Logger *slog.Logger
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
	Mode config.TLSClientAuthMode
	// TrustAnchors 是已加载的客户端信任 CA。
	TrustAnchors []TLSClientTrustAnchor
	// Identities 是生效中的“证书 DNS 名称 -> 可信服务身份”映射。
	Identities []config.TLSClientIdentity
}

// TLSStatus 是本地 TLS 证书的只读状态，用于诊断、到期监控与未来调度/通知接入。
// 本步骤不发送到期通知，也不实现证书自动续期；调用方可按 ExpiringSoon/Expired
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
