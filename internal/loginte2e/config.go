package loginte2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// 默认值。
const (
	// DefaultServer 是独立服务默认监听地址（只监听回环）。
	DefaultServer = "http://127.0.0.1:8080"
	// DefaultTimeout 是单个 HTTP 请求超时。
	DefaultTimeout = 15 * time.Second
	// DefaultPollTimeout 是设备码/扫码轮询的总等待上限。
	DefaultPollTimeout = 90 * time.Second
	// DefaultScope 是授权请求默认申请的 scope；offline_access 用于刷新令牌轮换。
	DefaultScope = "openid profile email offline_access"
	// DefaultSessionCookieName 是浏览器会话 Cookie 的默认名字（与 internal/session
	// 契约一致，只在读取浏览器 Cookie 文件时用于挑选 Cookie）。
	DefaultSessionCookieName = "__Host-login_session"
	// maxSecretFileBytes 是会话/令牌秘密文件读取上限，避免误读超大文件。
	maxSecretFileBytes = 64 * 1024
)

// Config 是测试客户端的固定配置。它只从可信本地来源（命令行/受保护文件/测试）
// 构造；Server 与秘密字段不能来自被测服务。
type Config struct {
	// Server 是被测服务的基础地址（可含部署路径前缀，例如
	// http://127.0.0.1:8080 或 https://login.example.test/login）。协议端点按
	// internal/protocolapi 的固定路径常量拼在它后面。
	Server string
	// CAFile 是可选的自签/私有 CA 证书文件（PEM）。只把该 CA 追加进信任池；
	// 不关闭证书链、主机名与有效期校验，也不提供 InsecureSkipVerify。
	CAFile string
	// Timeout 是单个请求超时；0 使用 DefaultTimeout。
	Timeout time.Duration
	// PollTimeout 是设备码/扫码轮询的总等待上限；0 使用 DefaultPollTimeout。
	PollTimeout time.Duration
	// ExpectedIssuer 是期望的 issuer（--issuer）。空表示信任 Discovery 返回的
	// issuer；非空时 Discovery 必须与之完全一致。
	ExpectedIssuer string
	// ClientID 是被测客户端应用 ID（authorization_code/设备码/扫码套件使用）。
	ClientID string
	// ClientSecret 是保密客户端密钥（可选）。设置后令牌端点与管理状态查询使用
	// client_secret_post；内容只能来自受保护文件或测试内存。
	ClientSecret string
	// RedirectURI 是客户端登记的回调地址（authorization_code 必需）。
	RedirectURI string
	// Scopes 是授权请求 scope；空使用 DefaultScope。
	Scopes []string
	// Resources 是 RFC 8707 资源指示；空时授权请求使用 Discovery 的 issuer
	// （UserInfo 需要 issuer 作为 audience）。
	Resources []string
	// SessionSecret 是已登录用户的会话秘密（--session-cookie-file 内容）。它可以
	// 直接是会话秘密，也可以是 Cookie 头 / Netscape cookies.txt；工具统一以
	// Authorization: Bearer 发送（会话服务契约同时接受 Cookie 与 Bearer）。
	SessionSecret string
	// SessionCookieName 读取浏览器 Cookie 文件时使用的 Cookie 名；空使用
	// DefaultSessionCookieName。
	SessionCookieName string
	// AdminSessionSecret 是管理会话秘密（--admin-session-file 内容，Bearer 形式）。
	AdminSessionSecret string
	// AdminBasePath 是管理 API 站内前缀；空使用 adminapi.DefaultBasePath。
	AdminBasePath string
	// DeviceConfirmURL 是宿主设备确认页地址（可选，站内绝对路径或绝对 URL）。
	// 只有协议包之外由宿主页面层实现的确认页存在时才有意义。
	DeviceConfirmURL string
	// DeviceConfirmDecision 是写入确认表单的决定值（默认 approve）。
	DeviceConfirmDecision string
	// DeviceConfirm 是库使用者注入的设备确认函数（集成测试用真实领域服务完成
	// “已登录用户确认”）；非 nil 时优先于 DeviceConfirmURL。
	DeviceConfirm func(ctx context.Context, userCode string) error
	// Now 是可注入时钟；nil 使用 time.Now（测试可固定时间）。
	Now func() time.Time
}

// clone 复制配置，避免调用方在构造后修改切片影响客户端。
func (c Config) clone() Config {
	copied := c
	copied.Scopes = append([]string(nil), c.Scopes...)
	copied.Resources = append([]string(nil), c.Resources...)
	return copied
}

// withDefaults 填充默认值。
func (c Config) withDefaults() Config {
	c = c.clone()
	if strings.TrimSpace(c.Server) == "" {
		c.Server = DefaultServer
	}
	if c.Timeout <= 0 {
		c.Timeout = DefaultTimeout
	}
	if c.PollTimeout <= 0 {
		c.PollTimeout = DefaultPollTimeout
	}
	if len(c.Scopes) == 0 {
		c.Scopes = strings.Fields(DefaultScope)
	}
	if c.SessionCookieName == "" {
		c.SessionCookieName = DefaultSessionCookieName
	}
	if c.AdminBasePath == "" {
		c.AdminBasePath = "/admin/v1"
	}
	if c.DeviceConfirmDecision == "" {
		c.DeviceConfirmDecision = "approve"
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c
}

// 配置错误。CLI 把它们映射为 ExitUsage。
var (
	// ErrConfigInvalid 表示配置/参数非法。
	ErrConfigInvalid = errors.New("测试客户端配置无效")
	// ErrUnavailable 表示测试目标不可达（连接失败/TLS 失败/响应不是预期协议）。
	ErrUnavailable = errors.New("测试目标不可达")
)

// validate 校验配置并规范化 Server。配置错误一律拒绝构造，不静默降级。
func (c *Config) validate() error {
	parsed, err := url.Parse(strings.TrimSpace(c.Server))
	if err != nil {
		return fmt.Errorf("%w: server 地址无法解析", ErrConfigInvalid)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("%w: server 必须是 http/https 绝对地址", ErrConfigInvalid)
	}
	if parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("%w: server 必须是主机地址且不含查询/片段/凭据", ErrConfigInvalid)
	}
	if parsed.Scheme == "http" && !isLoopbackHost(parsed.Hostname()) {
		// 默认值 http://127.0.0.1:8080 只是本机测试便利；非回环明文会把会话秘密/
		// 令牌暴露在网络上。工具不提供“不安全放行”开关：请为真实部署使用 https。
		return fmt.Errorf("%w: 非回环地址必须使用 https（http 仅允许本机回环测试）",
			ErrConfigInvalid)
	}
	path := strings.TrimRight(parsed.Path, "/")
	if strings.Contains(path, "//") {
		return fmt.Errorf("%w: server 路径前缀不能包含重复斜杠", ErrConfigInvalid)
	}
	c.Server = parsed.Scheme + "://" + parsed.Host + path
	if c.CAFile != "" {
		if _, statErr := os.Stat(c.CAFile); statErr != nil {
			return fmt.Errorf("%w: CA 文件不可读", ErrConfigInvalid)
		}
	}
	if c.ExpectedIssuer != "" {
		issuer, parseErr := url.Parse(c.ExpectedIssuer)
		if parseErr != nil || issuer.Host == "" {
			return fmt.Errorf("%w: issuer 必须是绝对地址", ErrConfigInvalid)
		}
	}
	if c.AdminBasePath != "" && !strings.HasPrefix(c.AdminBasePath, "/") {
		return fmt.Errorf("%w: 管理 API 前缀必须以 / 开头", ErrConfigInvalid)
	}
	return nil
}

// newTransport 构造严格 TLS 校验的传输层。CAFile 非空时只追加信任指定 CA，
// 绝不设置 InsecureSkipVerify。
func (c Config) newTransport() (*http.Transport, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CAFile != "" {
		pemBytes, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, fmt.Errorf("%w: 读取 CA 文件失败", ErrConfigInvalid)
		}
		pool, poolErr := x509.SystemCertPool()
		if poolErr != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("%w: CA 文件不含有效 PEM 证书", ErrConfigInvalid)
		}
		tlsConfig.RootCAs = pool
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	transport.TLSHandshakeTimeout = c.Timeout
	transport.ResponseHeaderTimeout = c.Timeout
	transport.Proxy = http.ProxyFromEnvironment
	transport.MaxIdleConnsPerHost = 4
	return transport, nil
}
