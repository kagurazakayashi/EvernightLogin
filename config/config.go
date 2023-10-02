package config

import (
	"fmt"
	"net"
	mailpkg "net/mail"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/appids"
	"github.com/kagurazakayashi/EvernightLogin/httppolicy"
	"github.com/kagurazakayashi/EvernightLogin/netpolicy"
	"github.com/kagurazakayashi/EvernightLogin/passkeypolicy"
	"github.com/kagurazakayashi/EvernightLogin/proxytrust"
)

// 监听与代理信任配置的上限。这些值同时是配置校验与监听构造的边界，避免配置
// 无限增长造成启动阶段资源放大。
const (
	// MaxServerListenAddresses 是最多同时监听的地址数（主地址 + 额外地址）。
	MaxServerListenAddresses = 16
	// MaxServerAllowedHosts 是允许 Host 列表的最大条目数。
	MaxServerAllowedHosts = 32
	// MaxServerTrustedProxies 是可信反向代理 IP/CIDR 的最大条目数。
	MaxServerTrustedProxies = proxytrust.MaxTrustedProxies
	// MaxServerTLSCertificates 是同时配置的 TLS 证书身份数量上限。
	MaxServerTLSCertificates = 8
	// DefaultServerTLSExpiryWarningDays 是证书到期提前告警的默认天数。
	DefaultServerTLSExpiryWarningDays = 30
	// MaxServerTLSClientCAFiles 是客户端信任 CA 文件数量上限。
	MaxServerTLSClientCAFiles = 8
	// MaxServerTLSClientIdentities 是客户端证书身份映射条目数量上限。
	MaxServerTLSClientIdentities = 32
	// MaxServerTLSClientServiceIdentityBytes 是可信服务身份名称长度上限。
	MaxServerTLSClientServiceIdentityBytes = 64
)

// TLSClientAuthMode 是本地 TLS 监听的客户端证书认证模式。
//
// 零值与 TLSClientAuthDisabled 都表示关闭（安全默认）；启用后必须配置独立的
// 客户端信任 CA 和显式身份映射，且客户端信任 CA 与服务器证书链必须分开。
type TLSClientAuthMode string

const (
	// TLSClientAuthDisabled 表示不请求客户端证书，也不建立服务身份（默认值）。
	TLSClientAuthDisabled TLSClientAuthMode = "disabled"
	// TLSClientAuthRequired 表示必须出示并验证客户端证书，且证书身份必须命中
	// 显式映射，否则握手失败。
	TLSClientAuthRequired TLSClientAuthMode = "required"
	// TLSClientAuthOptional 表示允许匿名连接；但一旦客户端出示证书，该证书必须
	// 通过信任链、用途、有效期与身份映射校验，出示无效证书不会降级为匿名。
	TLSClientAuthOptional TLSClientAuthMode = "optional"
)

// Valid 报告客户端证书认证模式是否已定义。空字符串等价于 disabled。
func (m TLSClientAuthMode) Valid() bool {
	switch m {
	case "", TLSClientAuthDisabled, TLSClientAuthRequired, TLSClientAuthOptional:
		return true
	default:
		return false
	}
}

// Enabled 报告该模式是否需要请求并验证客户端证书。
func (m TLSClientAuthMode) Enabled() bool {
	return m == TLSClientAuthRequired || m == TLSClientAuthOptional
}

// normalizeTLSClientAuthMode 把空字符串归一为 disabled，便于比较与诊断。
func normalizeTLSClientAuthMode(mode TLSClientAuthMode) TLSClientAuthMode {
	if mode == "" {
		return TLSClientAuthDisabled
	}
	return mode
}

// NormalizeTLSClientAuthMode 把空字符串归一为 disabled；供根门面与内部服务装配
// 复用（单一实现，避免各处重复判断）。
func NormalizeTLSClientAuthMode(mode TLSClientAuthMode) TLSClientAuthMode {
	return normalizeTLSClientAuthMode(mode)
}

// TLSClientIdentity 是客户端证书身份到可信服务身份的显式映射。客户端证书只
// 由受信任 CA 签发不足以获准接入：叶证书必须包含这里配置的某个 DNS SAN 才能
// 建立 TLS 连接。映射不代表 root、系统资格或任何业务权限。
type TLSClientIdentity struct {
	// DNSName 是客户端叶证书必须包含的 DNS SAN（精确匹配，不区分大小写、
	// 不接受 IP、通配符或端口）。
	DNSName string
	// Service 是映射到的可信服务身份名称：1～64 字节 ASCII 小写标识符，只允许
	// a-z、0-9、点、下划线与连字符，首尾必须是字母或数字。
	Service string
}

// Config 是 login 的完整有效配置快照。
//
// 合并顺序固定为（后者覆盖前者）：
//
//  1. 内置默认值（Default）
//  2. YAML 配置
//  3. 环境变量（LOGIN_ 前缀）
//  4. 宿主显式代码选项（Overrides）
//
// 显式 false、0 与“未设置”通过覆盖层的 *bool、*int 等指针区分；未设置表示
// 保留下一层或默认值。Config 是值类型，复制后互不影响；Secrets 中的秘密在
// 序列化、格式化和诊断输出中始终脱敏。
//
// 本步只定义当前基础模块需要的字段。网络、TLS、注册、MFA、邮件、报告等
// 后续模块的配置字段在对应步骤增加，不提前建立空配置。
type Config struct {
	Server   ServerConfig
	Logging  LoggingConfig
	Database DatabaseConfig
	Secrets  SecretsConfig
	// Registration 是自主注册策略配置（步骤 33）。默认关闭；管理员创建账户
	// 不依赖该配置。
	Registration RegistrationConfig
	// Passkey 是 WebAuthn/Passkey 依赖方配置（步骤 42）。默认关闭；启用时
	// RP ID、允许来源与用户验证策略必须显式配置，非法值拒绝启动。
	Passkey PasskeyConfig
	// AppQRLogin 是已登录 APP 扫码登录网页请求的配置（步骤 58）。默认关闭；
	// 启用时必须显式配置应用白名单，未列入的应用一律拒绝。
	AppQRLogin AppQRLoginConfig
	// Protocol 是 OAuth 2.0 / OpenID Connect 协议端点配置。默认关闭；启用时必须
	// 配置与路径前缀一致的固定 Issuer，非法形状拒绝启动。
	Protocol ProtocolConfig
	// Mail 是生产邮件发送配置（步骤 139）。默认关闭；关闭时不读取密码/证书、
	// 不建立网络连接，邮件能力以明确错误拒绝。启用时配置不全拒绝启动。
	Mail MailConfig
	// ManualRecovery 是人工核验恢复制度配置（步骤 152）。默认关闭；启用时要求
	// 独立审批、核验依据、可信交付渠道与有界等待期/批准/申请期限。修改后需重启。
	ManualRecovery ManualRecoveryConfig
}

// ServerConfig 是独立服务与嵌入模式共用的监听配置。
type ServerConfig struct {
	// ListenAddr 是主监听地址，格式为 host:port；默认仅监听 127.0.0.1:8080。
	// 监听主机只接受 IP 字面量、localhost 或空（所有接口），不接受任意域名。
	// 修改后需要重启进程。
	ListenAddr string
	// ExtraListenAddrs 是在 ListenAddr 之外额外监听的地址列表；与 ListenAddr
	// 一起构成实际监听集合（去重后最多 MaxServerListenAddresses 个）。所有地址
	// 全部成功绑定后才开始服务，任一失败时整体回滚。修改后需要重启进程。
	ExtraListenAddrs []string
	// PublicBaseURL 是独立配置的外部可访问基础地址（例如
	// https://login.example.com 或 https://login.example.com/login），留空表示
	// 尚未配置外部地址。它的主机自动加入允许 Host 列表；配置了 PathPrefix 时
	// 路径必须与之一致，独立服务启动时还会与实际 Handler 前缀核对。外部地址、
	// 未来 OIDC Issuer 与 WebAuthn RP ID 各自使用独立的显式配置，绝不允许从请求
	// Host 或转发头动态推导后用于签发身份。修改后需要重启进程。
	PublicBaseURL string
	// PathPrefix 是独立服务的固定路径前缀：空字符串或 /segment(/segment)*。
	// 嵌入模式直接设置 HTTPOptions.Prefix，并保持与 ServerOptions.Prefix 一致；
	// 独立服务从该字段读取。修改后需要重启进程。
	PathPrefix string
	// AllowedHosts 是显式允许的 HTTP Host（host 或 host:port）。为空且未配置
	// PublicBaseURL 时只接受本机回环主机名（localhost、127.0.0.0/8、::1）；
	// 配置了 PublicBaseURL 时只接受该主机与这里的条目。修改后需要重启进程。
	AllowedHosts []string
	// TrustedProxies 是唯一允许提供 Forwarded/X-Forwarded-* 的直连反向代理
	// IP/CIDR。为空时完全忽略转发头，客户端无法伪造地址、协议或域名。
	// 修改后需要重启进程。
	TrustedProxies []string
	// TLSProxyMode 显式确认“当前明文监听只部署在受信任的 TLS 终止反向代理
	// 后端”。默认 false；非回环明文监听只有在它为 true、而且配置了可信代理与
	// https 公开地址时才允许，避免悄悄把明文服务开放到所有网卡。它与本地 TLS
	// 证书配置互斥。修改后需要重启进程。
	TLSProxyMode bool
	// TLSCertFiles 是 PEM 证书链文件列表：每个文件的第一张证书是叶证书，其后
	// 依次是中间证书。与 TLSKeyFiles 一一对应，最多 MaxServerTLSCertificates 个。
	// 配置后监听地址提供 HTTPS 单向认证。修改后可在不重启进程时通过
	// Server.ReloadTLS 重新加载。
	TLSCertFiles []string
	// TLSKeyFiles 是与 TLSCertFiles 一一对应的私钥 PEM 文件列表。私钥文件必须
	// 是普通文件且通过受保护文件权限检查（仅所有者可读写 / Windows 受限 ACL）。
	TLSKeyFiles []string
	// TLSCAFile 是可选的附加 CA/中间证书 PEM 文件；其证书按顺序追加到每个 PEM
	// 证书身份之后，用于证书文件只含叶证书的部署。PFX 模式下不允许设置。
	TLSCAFile string
	// TLSPFXFile 是 PKCS#12/PFX 证书文件路径；与 TLSCertFiles/TLSKeyFiles 互斥。
	// 其密码必须通过 secrets.tls_pfx_password 从受保护来源配置。
	TLSPFXFile string
	// TLSExpiryWarningDays 是证书到期提前告警窗口天数，范围 0～365；0 表示使用
	// 默认值 30（与 NewServer 的行为一致，显式 0 不会被当作“无告警”）。只影响
	// TLSStatus 的 ExpiringSoon 判断，不发送通知、不自动续期；修改后需要重启。
	TLSExpiryWarningDays int
	// TLSClientAuthMode 是客户端证书认证模式：disabled（默认）、required 或
	// optional。启用后必须同时配置本地 TLS 证书、TLSClientCAFiles 与
	// TLSClientIdentities。可选模式只允许“没有证书”的匿名连接；客户端一旦出示
	// 证书，就必须通过完整校验与身份映射，绝不会因证书无效而降级为匿名。
	// 修改后需要重启进程；Server.ReloadTLS 不重载客户端信任配置。
	TLSClientAuthMode TLSClientAuthMode
	// TLSClientCAFiles 是客户端信任 CA 的 PEM 文件列表，与服务器证书链完全分开
	// （配置文件不同、加载后证书不能重叠）。CA 必须是具备签发能力的证书且处于
	// 有效期内；文件数量最多 MaxServerTLSClientCAFiles 个。客户端证书链只信任
	// 这里的 CA，不使用服务器 TLS 字段或系统根证书。修改后需要重启进程。
	TLSClientCAFiles []string
	// TLSClientIdentities 是客户端证书身份到可信服务身份的显式映射表。客户端
	// 叶证书必须包含某个映射的 DNS SAN 才能建立连接；仅有受信任 CA 签发的证书
	// 不等于获准接入，也不因此获得 root 或全部业务权限。最多
	// MaxServerTLSClientIdentities 条。修改后需要重启进程。
	TLSClientIdentities []TLSClientIdentity
	// ShutdownTimeoutSeconds 是安全关闭的墙钟上限，单位秒，默认 10。
	// 该值在关闭流程读取，因此可以热更新。
	ShutdownTimeoutSeconds int
}

// TLSEnabled 报告是否配置了本地 TLS 证书材料（PEM 或 PFX）。它只判断配置形状，
// 不表示证书文件已经成功加载或校验通过；加载与校验由 NewServer 完成。
func (c ServerConfig) TLSEnabled() bool {
	return len(c.TLSCertFiles) > 0 || len(c.TLSKeyFiles) > 0 ||
		c.TLSCAFile != "" || c.TLSPFXFile != ""
}

// ListenAddresses 返回实际监听地址列表：ListenAddr 在前，ExtraListenAddrs 在
// 后，按规范化结果去重。返回值是副本；该方法是配置与监听组件之间的唯一映射
// 点，避免两处各自拼接地址列表。
func (c ServerConfig) ListenAddresses() []string {
	addresses := make([]string, 0, 1+len(c.ExtraListenAddrs))
	seen := make(map[string]struct{}, 1+len(c.ExtraListenAddrs))
	appendAddress := func(raw string) {
		if strings.TrimSpace(raw) == "" {
			return
		}
		key := raw
		if parsed, err := netpolicy.ParseListenAddress(raw, false); err == nil {
			key = parsed.Key()
		}
		if _, duplicated := seen[key]; duplicated {
			return
		}
		seen[key] = struct{}{}
		addresses = append(addresses, raw)
	}
	appendAddress(c.ListenAddr)
	for _, raw := range c.ExtraListenAddrs {
		appendAddress(raw)
	}
	return addresses
}

// LoggingConfig 是结构化运行日志配置。它只影响运行日志，不代替安全审计。
type LoggingConfig struct {
	// Level 是运行日志级别，默认 info；可热更新。
	Level LogLevel
	// Format 是日志输出格式，默认 text；可热更新。
	Format LogFormat
}

// DatabaseConfig 是数据库连接配置。本步不打开数据库，只校验配置；
// SQLite 连接实现见步骤 07，其他数据库驱动见后续步骤。
type DatabaseConfig struct {
	// Driver 是数据库驱动类型，当前版本只接受 sqlite。
	Driver DatabaseDriver
	// Path 是 SQLite 数据库文件路径。加载配置不会创建该文件。
	Path string
	// WAL 表示是否启用 SQLite 预写日志，默认 true。显式 false 会保留，不会
	// 被默认值覆盖。
	WAL bool
	// BusyTimeoutMS 是 SQLite 锁等待毫秒数，默认 5000，范围 1～600000。
	BusyTimeoutMS int
}

// RegistrationConfig 是自主注册与邮箱验证的策略配置（步骤 33）。它只承载策略，
// 不包含密码、令牌或邮件凭据；注册是否真正可用还取决于宿主是否装配邮件发送与
// 验证入口地址。修改后需要重启进程。
type RegistrationConfig struct {
	// Enabled 是自主注册总开关，默认 false（默认拒绝）。关闭时管理员通过
	// internal/account 创建账户的能力不受影响。
	Enabled bool
	// RequireReview 为 true 时新注册账户以 pending 状态创建，需人工审核后才能
	// 正常登录；审核执行由后续步骤实现。
	RequireReview bool
	// RequireEmailVerification 为 true 时注册必须提供邮箱并完成验证流程；false
	// 时邮箱可选，没有邮件能力的部署仍可完成密码注册。
	RequireEmailVerification bool
	// DefaultRoleIDs 是通过可信策略分配给新注册账户的默认角色 ID 列表，最多
	// MaxRegistrationDefaultRoles 个。存储层只会分配存在、已启用且作用域匹配的
	// 角色，不会自动加入任何应用成员。
	DefaultRoleIDs []string
}

// MaxRegistrationDefaultRoles 是默认角色策略允许的最大条数。
const MaxRegistrationDefaultRoles = 20

// PasskeyConfig 是 WebAuthn/Passkey 的依赖方配置（步骤 42）。
//
// 安全边界：RP ID 是 Passkey 的信任根，通常是可注册域名（不能是 IP、不能带
// 协议/端口/路径）；Passkey 不会跨 RP ID 通用，多域名监听不代表可跨任意域名
// 使用。允许来源必须是完整来源（scheme://host[:port]），只接受 https 或本地
// 开发用的 http://localhost，且来源主机必须是 RP ID 或其子域。UserVerification
// 默认为 required；preferred/discouraged 会降低强度，只应在明确接受风险时设置。
// 修改后需要重启服务。
type PasskeyConfig struct {
	// Enabled 是 Passkey 功能总开关，默认 false（默认拒绝）。关闭时不会创建
	// 注册/认证挑战，也不接受 Passkey 登录。
	Enabled bool
	// RPID 是 WebAuthn Relying Party ID（例如 login.example.com）。
	RPID string
	// RPDisplayName 是浏览器展示的依赖方名称；空时由 Passkey 服务使用默认名。
	RPDisplayName string
	// AllowedOrigins 是允许的浏览器来源完整列表，至少一个。
	AllowedOrigins []string
	// UserVerification 是注册/登录要求的用户验证策略：required（默认）、
	// preferred 或 discouraged。
	UserVerification string
}

// MaxPasskeyOrigins 是允许来源列表的最大条数。
const MaxPasskeyOrigins = 20

// passkeyConfigProblem 校验 Passkey 配置；返回空字符串表示合法。未启用且未配置
// 任何 RP 信息时允许留空（功能关闭），一旦配置了就按完整规则校验，避免半成品
// 配置被静默忽略。
func passkeyConfigProblem(c PasskeyConfig) string {
	if !c.Enabled && strings.TrimSpace(c.RPID) == "" && len(c.AllowedOrigins) == 0 {
		// 功能关闭且没有任何 RP 信息时允许留空（RP 显示名/UV 的默认值不算配置）。
		return ""
	}
	if len(c.AllowedOrigins) > MaxPasskeyOrigins {
		return fmt.Sprintf("允许来源最多 %d 个", MaxPasskeyOrigins)
	}
	if err := passkeypolicy.ValidateRPConfig(c.RPID, c.AllowedOrigins); err != nil {
		return err.Error()
	}
	if c.UserVerification != "" && !passkeypolicy.UserVerification(c.UserVerification).Valid() {
		return "用户验证策略必须是 required、preferred 或 discouraged"
	}
	return ""
}

// AppQRLoginConfig 是"已登录 APP 扫码确认网页登录"的配置（步骤 58）。
//
// 安全边界：默认关闭；全局开关与应用白名单是两道独立开关，二者都满足才允许
// 创建/批准/领取。白名单为空且启用时按配置错误拒绝启动（避免"全开"误解）。
// 领取绑定、二维码内容与确认页展示信息都不是这里的配置字段。
// 修改后需要重启服务。
type AppQRLoginConfig struct {
	// Enabled 是扫码登录总开关，默认 false（默认拒绝）。
	Enabled bool
	// AllowedClientIDs 是允许使用扫码登录的应用白名单（应用 ID = OAuth client_id）。
	// 启用时必须非空；未列入的应用一律拒绝。
	AllowedClientIDs []string
	// RequestTTLSeconds 是扫码请求有效期（秒），默认 120，允许 30～300。
	RequestTTLSeconds int
	// ClaimIntervalSeconds 是发起端查询/领取的最小间隔（秒），默认 1，允许 1～5。
	ClaimIntervalSeconds int
}

// MaxAppQRLoginClients 是应用白名单上限。
const MaxAppQRLoginClients = 200

// appQRLoginConfigProblem 校验扫码登录配置；返回空字符串表示合法。
func appQRLoginConfigProblem(c AppQRLoginConfig) string {
	if c.RequestTTLSeconds < 30 || c.RequestTTLSeconds > 300 {
		return "扫码登录请求有效期必须是 30～300 秒"
	}
	if c.ClaimIntervalSeconds < 1 || c.ClaimIntervalSeconds > 5 {
		return "扫码登录查询间隔必须是 1～5 秒"
	}
	if len(c.AllowedClientIDs) > MaxAppQRLoginClients {
		return fmt.Sprintf("扫码登录应用白名单最多 %d 个", MaxAppQRLoginClients)
	}
	if !c.Enabled {
		return ""
	}
	if len(c.AllowedClientIDs) == 0 {
		return "启用扫码登录时必须配置至少一个允许的应用"
	}
	seen := make(map[string]struct{}, len(c.AllowedClientIDs))
	for _, clientID := range c.AllowedClientIDs {
		if !appids.ValidApplicationID(clientID) {
			return "扫码登录应用白名单包含非法应用 ID"
		}
		if _, duplicated := seen[clientID]; duplicated {
			return "扫码登录应用白名单不能重复"
		}
		seen[clientID] = struct{}{}
	}
	return ""
}

// MailConfig 是生产邮件发送配置（步骤 139）。默认关闭；关闭时不读取密码/
// 证书、不建立网络连接，邮件能力以明确错误拒绝；启用时配置不全拒绝启动。
type MailConfig struct {
	Enabled  bool
	SMTP     MailSMTPConfig
	From     MailFromConfig
	AppName  string
	Delivery MailDeliveryConfig
}

// MailSMTPConfig 是 SMTP 传输配置。
type MailSMTPConfig struct {
	Addr                string
	Host                string
	TLSMode             string
	TrustedRoots        []string
	Username            string
	Password            SecretSource
	TimeoutSeconds      int
	AllowPlaintextLocal bool
}

// MailFromConfig 是发件人配置。
type MailFromConfig struct {
	Address string
	Name    string
}

// MailDeliveryConfig 是可靠投递参数（队列/重试由既有 mailer 任务执行器负责）。
type MailDeliveryConfig struct {
	MaxAttempts    int
	TimeoutSeconds int
}

// ManualRecoveryConfig 是人工核验恢复制度（步骤 152）。默认关闭；启用后只允许
// 普通用户，root/高权限目标由服务与执行器双重拒绝；制度参数修改需要重启，避免
// 运行中临时放宽恢复面。时间字段使用秒，0 表示使用默认值。
type ManualRecoveryConfig struct {
	Enabled            bool
	VerificationBases  []string
	DeliveryChannels   []string
	WaitPeriodSeconds  int
	ApprovalTTLSeconds int
	RequestTTLSeconds  int
	// RebindMethods 是人工恢复 MFA 重置后，用户可在受限初始化会话中重新绑定的强
	// 因素类别（步骤 209）。合法值：passkey、totp；默认 ["passkey"]，保持 188 的
	// Passkey-only 行为。它只决定“允许绑定的类别”，不改变强认证强度：
	//   - passkey 是抗钓鱼建议方式，但只有 passkey.enabled=true 时才会真正可用；
	//   - totp 明确不是抗钓鱼因素，加入它只用于让 Passkey 不可用的普通用户恢复
	//     第二因素；它不会让要求抗钓鱼 Passkey 的管理操作降级（登录强认证仍由
	//     mfa 的 AllowTOTPForStrongAuth 独立控制且默认 false，root/高权限账户的
	//     重绑始终固定为 Passkey）；
	//   - 若列出的类别在运行装配中全部不可用（例如只列 passkey 但未启用 Passkey），
	//     mfa_reset 申请/执行会 fail-closed 拒绝，而不是恢复后锁死或静默降级。
	RebindMethods []string
}

// ProtocolConfig 是 OAuth 2.0 / OpenID Connect 协议端点的宿主配置（步骤 56/57/58
// 的传输层由 internal/protocolapi 提供，独立服务负责发行方与开关接线）。
//
// 安全边界：Issuer 是写入 Discovery 文档与令牌 iss 的固定签发方，必须由配置显式
// 给出，绝不能从请求 Host/转发头推导；它的路径部分必须与 server.path_prefix 完全
// 一致，否则 Discovery 会声明未挂载的端点。启用时缺少 Issuer 或形状非法一律拒绝
// 启动（fail-closed），关闭时协议端点不挂载（请求得到 404）。
// ResourceServiceConfig 是受信资源服务登记项。认证材料复用 OAuth 客户端登记
// 的 secret/证书；audience 必须已在该客户端的 Audiences 中登记。
type ResourceServiceConfig struct {
	ServiceID string
	ClientID  string
	Audience  string
}

type ProtocolConfig struct {
	// Enabled 是协议端点总开关，默认 false（默认拒绝）。独立服务还可以用
	// --enable-protocol 显式打开（命令行覆盖配置）。
	Enabled bool
	// Issuer 是固定公开签发方（例如 https://login.example.com），不得带尾斜杠；
	// 只接受 https，或明确用于本地开发的 http://localhost / 127.0.0.1 回环地址。
	// 路径部分必须与 server.path_prefix 一致（都为空或完全相同）。
	Issuer string
	// EnableIntrospection 显式启用 RFC 7662 令牌状态查询端点。只有宿主装配了真实
	// 资源服务授权器时才允许打开，否则 Discovery 会夸大能力。
	EnableIntrospection bool
	// DeviceCodeEnabled 显式启用 RFC 8628 设备码端点与 Discovery 的 device_code
	// 能力。要求 protocol.enabled 且 server.public_base_url 可派生设备确认页。
	DeviceCodeEnabled bool
	// ResourceServices 是受信资源服务登记：每个条目把 confidential OAuth 客户端
	// 认证材料映射为一个可信资源身份（service_id/client_id/audience）。
	ResourceServices []ResourceServiceConfig
	// LoginPath 是未登录访问授权端点时跳转的站内登录页路径（例如 /login）。为空
	// 时协议端点返回受控 JSON 错误而不是跳转。
	LoginPath string
}

// protocolConfigProblem 校验协议端点配置；返回空字符串表示合法。
func protocolConfigProblem(c Config) string {
	protocol := c.Protocol
	if len(protocol.ResourceServices) > 0 && !protocol.Enabled {
		return "protocol.resource_services 需要先启用 protocol.enabled"
	}
	if protocol.DeviceCodeEnabled {
		if !protocol.Enabled {
			return "protocol.device_code_enabled 需要先启用 protocol.enabled"
		}
		if strings.TrimSpace(c.Server.PublicBaseURL) == "" {
			return "protocol.device_code_enabled 需要配置 server.public_base_url 以生成设备确认页地址"
		}
	}
	if protocol.EnableIntrospection && len(protocol.ResourceServices) == 0 {
		return "protocol.enable_introspection 需要至少一个 protocol.resource_services 登记"
	}
	issuer := strings.TrimSpace(protocol.Issuer)
	if !protocol.Enabled {
		// 关闭时允许预置 Issuer 供后续开启，但预置值同样必须是合法形状，避免
		// 配置层留下“看起来配好了实际不可用”的半成品。
		if issuer == "" {
			return ""
		}
	}
	if issuer == "" {
		return "启用协议端点时必须配置 protocol.issuer（固定公开签发方）"
	}
	if strings.HasSuffix(issuer, "/") {
		return "protocol.issuer 不能以斜杠结尾"
	}
	parsed, err := url.Parse(issuer)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" {
		return "protocol.issuer 必须是绝对 URL"
	}
	if parsed.User != nil {
		return "protocol.issuer 不能包含用户信息"
	}
	if parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "protocol.issuer 不能包含查询字符串或片段"
	}
	switch parsed.Scheme {
	case "https":
	case "http":
		host := parsed.Hostname()
		ip := net.ParseIP(host)
		if !strings.EqualFold(host, "localhost") && (ip == nil || !ip.IsLoopback()) {
			return "protocol.issuer 使用 http 时只能是 localhost 或回环地址"
		}
	default:
		return "protocol.issuer 必须是 https"
	}
	if _, err := netpolicy.ParseRequestHost(parsed.Host); err != nil {
		return "protocol.issuer 的主机名无效"
	}
	normalizedPrefix, prefixErr := httppolicy.NormalizePrefix(c.Server.PathPrefix)
	if prefixErr != nil {
		// 路径前缀本身非法时由 server.path_prefix 校验报告，这里不重复报错。
		return ""
	}
	issuerPath := parsed.EscapedPath()
	if issuerPath == "/" {
		issuerPath = ""
	}
	if issuerPath != normalizedPrefix {
		return "protocol.issuer 的路径必须与 server.path_prefix 一致"
	}
	loginPath := strings.TrimSpace(protocol.LoginPath)
	if loginPath != "" {
		if !strings.HasPrefix(loginPath, "/") || strings.HasPrefix(loginPath, "//") ||
			strings.HasSuffix(loginPath, "/") {
			return "protocol.login_path 必须是以单个斜杠开头的站内绝对路径"
		}
		if c.Server.PathPrefix != "" && !strings.HasPrefix(loginPath, normalizedPrefix+"/") {
			return "protocol.login_path 必须位于 server.path_prefix 之下"
		}
	}
	if problem := resourceServicesProblem(protocol.ResourceServices); problem != "" {
		return problem
	}
	return ""
}

// resourceServicesProblem 校验资源服务登记的配置形状（不读取数据库）。
func resourceServicesProblem(services []ResourceServiceConfig) string {
	seenService := make(map[string]struct{}, len(services))
	seenAudience := make(map[string]struct{}, len(services))
	for _, service := range services {
		if strings.TrimSpace(service.ServiceID) == "" || len(service.ServiceID) > 128 {
			return "protocol.resource_services.service_id 必填且不超过 128 字节"
		}
		if _, exists := seenService[service.ServiceID]; exists {
			return "protocol.resource_services.service_id 不能重复"
		}
		seenService[service.ServiceID] = struct{}{}
		if strings.TrimSpace(service.ClientID) == "" || len(service.ClientID) > 128 {
			return "protocol.resource_services.client_id 必填且不超过 128 字节"
		}
		audience := strings.TrimSpace(service.Audience)
		parsed, err := url.Parse(audience)
		if err != nil || !parsed.IsAbs() || parsed.Host == "" || parsed.Fragment != "" {
			return "protocol.resource_services.audience 必须是 absolute URI（无片段）"
		}
		key := service.ClientID + "\x00" + audience
		if _, exists := seenAudience[key]; exists {
			return "protocol.resource_services 同一客户端的 audience 不能重复"
		}
		seenAudience[key] = struct{}{}
	}
	return ""
}

// SecretsConfig 保存从受保护来源解析出的秘密。秘密值不会出现在 YAML 中，
// 只能来自环境变量、受保护文件或宿主显式选项。
type SecretsConfig struct {
	// MasterKey 是主密钥材料，供步骤 08 的加密服务使用。本步只负责读取和
	// 脱敏，不生成、不轮换、不做格式解释。零值表示未配置。
	MasterKey Secret
	// TLSPFXPassword 是 TLS PFX/P12 文件的密码。秘密只能来自受保护来源
	// （环境变量、受保护文件或宿主显式选项），不能直接写进 YAML；诊断与错误
	// 输出始终脱敏。零值表示未配置。
	TLSPFXPassword Secret
}

// LogLevel 是运行日志级别。
type LogLevel string

const (
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
)

// Valid 报告日志级别是否为已定义值。
func (l LogLevel) Valid() bool {
	switch l {
	case LogLevelDebug, LogLevelInfo, LogLevelWarn, LogLevelError:
		return true
	default:
		return false
	}
}

// LogFormat 是运行日志输出格式。
type LogFormat string

const (
	LogFormatText LogFormat = "text"
	LogFormatJSON LogFormat = "json"
)

// Valid 报告日志格式是否为已定义值。
func (f LogFormat) Valid() bool {
	return f == LogFormatText || f == LogFormatJSON
}

// DatabaseDriver 是数据库驱动标识。
type DatabaseDriver string

const (
	// DatabaseDriverSQLite 是当前唯一接受的驱动；其他数据库的适配在后续步骤
	// 增加，本步不接受未实现的驱动名，避免配置看似生效。
	DatabaseDriverSQLite DatabaseDriver = "sqlite"
)

// Valid 报告驱动是否被当前版本接受。
func (d DatabaseDriver) Valid() bool {
	return d == DatabaseDriverSQLite
}

// ReloadClass 表示配置字段改变后需要如何生效。
type ReloadClass string

const (
	// ReloadRestartRequired 表示修改后必须重启进程才能生效。
	ReloadRestartRequired ReloadClass = "restart-required"
	// ReloadHotReloadable 表示重新加载配置后即可生效，不需要重启。
	// 本步只定义分类；完整的热更新后台在后续步骤实现。
	ReloadHotReloadable ReloadClass = "hot-reloadable"
)

// FieldInfo 描述一个可配置字段的稳定元数据，用于环境变量映射、诊断输出、
// 文档和热更新分类检查。
type FieldInfo struct {
	// Field 是点分隔的字段路径，例如 "database.path"。
	Field string
	// Env 是该字段对应的固定环境变量名。
	Env string
	// Class 是该字段的重载分类。
	Class ReloadClass
	// Secret 表示该字段是秘密；诊断和日志只能显示脱敏状态。
	Secret bool
}

// EnvVarPrefix 是所有配置环境变量的固定前缀，命名不会随版本变化。
const EnvVarPrefix = "LOGIN_"

// 环境变量命名规则：LOGIN_ + 点分字段路径转为大写并用下划线连接。
// 这些名称是稳定契约，测试会锁定；新增字段只能追加，不能改名已有变量。
const (
	envServerListenAddr      = EnvVarPrefix + "SERVER_LISTEN_ADDR"
	envServerExtraListen     = EnvVarPrefix + "SERVER_EXTRA_LISTEN_ADDRS"
	envServerPublicBaseURL   = EnvVarPrefix + "SERVER_PUBLIC_BASE_URL"
	envServerPathPrefix      = EnvVarPrefix + "SERVER_PATH_PREFIX"
	envServerAllowedHosts    = EnvVarPrefix + "SERVER_ALLOWED_HOSTS"
	envServerTrustedProxies  = EnvVarPrefix + "SERVER_TRUSTED_PROXIES"
	envServerTLSProxyMode    = EnvVarPrefix + "SERVER_TLS_TERMINATING_PROXY"
	envServerTLSCertFiles    = EnvVarPrefix + "SERVER_TLS_CERT_FILES"
	envServerTLSKeyFiles     = EnvVarPrefix + "SERVER_TLS_KEY_FILES"
	envServerTLSCAFile       = EnvVarPrefix + "SERVER_TLS_CA_FILE"
	envServerTLSPFXFile      = EnvVarPrefix + "SERVER_TLS_PFX_FILE"
	envServerTLSExpiryDays   = EnvVarPrefix + "SERVER_TLS_EXPIRY_WARNING_DAYS"
	envServerTLSClientAuth   = EnvVarPrefix + "SERVER_TLS_CLIENT_AUTH"
	envServerTLSClientCA     = EnvVarPrefix + "SERVER_TLS_CLIENT_CA_FILES"
	envServerTLSClientMaps   = EnvVarPrefix + "SERVER_TLS_CLIENT_IDENTITIES"
	envServerShutdownTimeout = EnvVarPrefix + "SERVER_SHUTDOWN_TIMEOUT_SECONDS"
	envLoggingLevel          = EnvVarPrefix + "LOGGING_LEVEL"
	envLoggingFormat         = EnvVarPrefix + "LOGGING_FORMAT"
	envDatabaseDriver        = EnvVarPrefix + "DATABASE_DRIVER"
	envDatabasePath          = EnvVarPrefix + "DATABASE_PATH"
	envDatabaseWAL           = EnvVarPrefix + "DATABASE_WAL"
	envDatabaseBusyTimeout   = EnvVarPrefix + "DATABASE_BUSY_TIMEOUT_MS"
	envRegistrationEnabled   = EnvVarPrefix + "REGISTRATION_ENABLED"
	envRegistrationReview    = EnvVarPrefix + "REGISTRATION_REQUIRE_REVIEW"
	envRegistrationEmail     = EnvVarPrefix + "REGISTRATION_REQUIRE_EMAIL_VERIFICATION"
	envRegistrationRoles     = EnvVarPrefix + "REGISTRATION_DEFAULT_ROLE_IDS"
	envPasskeyEnabled        = EnvVarPrefix + "PASSKEY_ENABLED"
	envPasskeyRPID           = EnvVarPrefix + "PASSKEY_RP_ID"
	envPasskeyRPName         = EnvVarPrefix + "PASSKEY_RP_DISPLAY_NAME"
	envPasskeyOrigins        = EnvVarPrefix + "PASSKEY_ALLOWED_ORIGINS"
	envPasskeyUserVerify     = EnvVarPrefix + "PASSKEY_USER_VERIFICATION"
	envAppQRLoginEnabled     = EnvVarPrefix + "APP_QR_LOGIN_ENABLED"
	envAppQRLoginClients     = EnvVarPrefix + "APP_QR_LOGIN_ALLOWED_CLIENT_IDS"
	envAppQRLoginTTL         = EnvVarPrefix + "APP_QR_LOGIN_REQUEST_TTL_SECONDS"
	envAppQRLoginInterval    = EnvVarPrefix + "APP_QR_LOGIN_CLAIM_INTERVAL_SECONDS"
	envProtocolDeviceCode    = EnvVarPrefix + "PROTOCOL_DEVICE_CODE_ENABLED"
	envSecretsMasterKey      = EnvVarPrefix + "SECRETS_MASTER_KEY"
	envSecretsTLSPFXPassword = EnvVarPrefix + "SECRETS_TLS_PFX_PASSWORD"
	envMailEnabled           = EnvVarPrefix + "MAIL_ENABLED"
	envMailSMTPAddr          = EnvVarPrefix + "MAIL_SMTP_ADDR"
	envMailSMTPHost          = EnvVarPrefix + "MAIL_SMTP_HOST"
	envMailSMTPTLSMode       = EnvVarPrefix + "MAIL_SMTP_TLS_MODE"
	envMailSMTPTrustedRoots  = EnvVarPrefix + "MAIL_SMTP_TRUSTED_ROOTS"
	envMailSMTPUsername      = EnvVarPrefix + "MAIL_SMTP_USERNAME"
	envMailSMTPPassword      = EnvVarPrefix + "MAIL_SMTP_PASSWORD"
	envMailSMTPTimeout       = EnvVarPrefix + "MAIL_SMTP_TIMEOUT_SECONDS"
	envMailSMTPAllowPlain    = EnvVarPrefix + "MAIL_SMTP_ALLOW_PLAINTEXT_LOCAL"
	envMailFromAddress       = EnvVarPrefix + "MAIL_FROM_ADDRESS"
	envMailFromName          = EnvVarPrefix + "MAIL_FROM_NAME"
	envMailAppName           = EnvVarPrefix + "MAIL_APP_NAME"
	envMailMaxAttempts       = EnvVarPrefix + "MAIL_DELIVERY_MAX_ATTEMPTS"
	envMailDeliveryTimeout   = EnvVarPrefix + "MAIL_DELIVERY_TIMEOUT_SECONDS"
)

// configFields 是字段元数据的唯一来源。Fields、Diagnostic、环境变量加载和
// 测试都据此保持一致；顺序就是诊断输出顺序。
var configFields = []FieldInfo{
	{Field: "server.listen_addr", Env: envServerListenAddr, Class: ReloadRestartRequired},
	{Field: "server.extra_listen_addrs", Env: envServerExtraListen, Class: ReloadRestartRequired},
	{Field: "server.public_base_url", Env: envServerPublicBaseURL, Class: ReloadRestartRequired},
	{Field: "server.path_prefix", Env: envServerPathPrefix, Class: ReloadRestartRequired},
	{Field: "server.allowed_hosts", Env: envServerAllowedHosts, Class: ReloadRestartRequired},
	{Field: "server.trusted_proxies", Env: envServerTrustedProxies, Class: ReloadRestartRequired},
	{Field: "server.tls_terminating_proxy", Env: envServerTLSProxyMode, Class: ReloadRestartRequired},
	{Field: "server.tls_cert_files", Env: envServerTLSCertFiles, Class: ReloadRestartRequired},
	{Field: "server.tls_key_files", Env: envServerTLSKeyFiles, Class: ReloadRestartRequired},
	{Field: "server.tls_ca_file", Env: envServerTLSCAFile, Class: ReloadRestartRequired},
	{Field: "server.tls_pfx_file", Env: envServerTLSPFXFile, Class: ReloadRestartRequired},
	{Field: "server.tls_expiry_warning_days", Env: envServerTLSExpiryDays, Class: ReloadRestartRequired},
	{Field: "server.tls_client_auth", Env: envServerTLSClientAuth, Class: ReloadRestartRequired},
	{Field: "server.tls_client_ca_files", Env: envServerTLSClientCA, Class: ReloadRestartRequired},
	{Field: "server.tls_client_identities", Env: envServerTLSClientMaps, Class: ReloadRestartRequired},
	{Field: "server.shutdown_timeout_seconds", Env: envServerShutdownTimeout, Class: ReloadHotReloadable},
	{Field: "logging.level", Env: envLoggingLevel, Class: ReloadHotReloadable},
	{Field: "logging.format", Env: envLoggingFormat, Class: ReloadHotReloadable},
	{Field: "database.driver", Env: envDatabaseDriver, Class: ReloadRestartRequired},
	{Field: "database.path", Env: envDatabasePath, Class: ReloadRestartRequired},
	{Field: "database.wal", Env: envDatabaseWAL, Class: ReloadRestartRequired},
	{Field: "database.busy_timeout_ms", Env: envDatabaseBusyTimeout, Class: ReloadRestartRequired},
	{Field: "registration.enabled", Env: envRegistrationEnabled, Class: ReloadRestartRequired},
	{Field: "registration.require_review", Env: envRegistrationReview, Class: ReloadRestartRequired},
	{Field: "registration.require_email_verification", Env: envRegistrationEmail, Class: ReloadRestartRequired},
	{Field: "registration.default_role_ids", Env: envRegistrationRoles, Class: ReloadRestartRequired},
	{Field: "passkey.enabled", Env: envPasskeyEnabled, Class: ReloadRestartRequired},
	{Field: "passkey.rp_id", Env: envPasskeyRPID, Class: ReloadRestartRequired},
	{Field: "passkey.rp_display_name", Env: envPasskeyRPName, Class: ReloadRestartRequired},
	{Field: "passkey.allowed_origins", Env: envPasskeyOrigins, Class: ReloadRestartRequired},
	{Field: "passkey.user_verification", Env: envPasskeyUserVerify, Class: ReloadRestartRequired},
	{Field: "app_qr_login.enabled", Env: envAppQRLoginEnabled, Class: ReloadRestartRequired},
	{Field: "app_qr_login.allowed_client_ids", Env: envAppQRLoginClients, Class: ReloadRestartRequired},
	{Field: "app_qr_login.request_ttl_seconds", Env: envAppQRLoginTTL, Class: ReloadRestartRequired},
	{Field: "app_qr_login.claim_interval_seconds", Env: envAppQRLoginInterval, Class: ReloadRestartRequired},
	{Field: "protocol.device_code_enabled", Env: envProtocolDeviceCode, Class: ReloadRestartRequired},
	{Field: "secrets.master_key", Env: envSecretsMasterKey, Class: ReloadRestartRequired, Secret: true},
	{Field: "secrets.tls_pfx_password", Env: envSecretsTLSPFXPassword, Class: ReloadRestartRequired, Secret: true},
	{Field: "mail.enabled", Env: envMailEnabled, Class: ReloadRestartRequired},
	{Field: "mail.smtp.addr", Env: envMailSMTPAddr, Class: ReloadRestartRequired},
	{Field: "mail.smtp.host", Env: envMailSMTPHost, Class: ReloadRestartRequired},
	{Field: "mail.smtp.tls_mode", Env: envMailSMTPTLSMode, Class: ReloadRestartRequired},
	{Field: "mail.smtp.trusted_roots", Env: envMailSMTPTrustedRoots, Class: ReloadRestartRequired},
	{Field: "mail.smtp.username", Env: envMailSMTPUsername, Class: ReloadRestartRequired},
	{Field: "mail.smtp.password", Env: envMailSMTPPassword, Class: ReloadRestartRequired, Secret: true},
	{Field: "mail.smtp.timeout_seconds", Env: envMailSMTPTimeout, Class: ReloadRestartRequired},
	{Field: "mail.smtp.allow_plaintext_local", Env: envMailSMTPAllowPlain, Class: ReloadRestartRequired},
	{Field: "mail.from.address", Env: envMailFromAddress, Class: ReloadRestartRequired},
	{Field: "mail.from.name", Env: envMailFromName, Class: ReloadRestartRequired},
	{Field: "mail.app_name", Env: envMailAppName, Class: ReloadRestartRequired},
	{Field: "mail.delivery.max_attempts", Env: envMailMaxAttempts, Class: ReloadRestartRequired},
	{Field: "mail.delivery.timeout_seconds", Env: envMailDeliveryTimeout, Class: ReloadRestartRequired},
}

// Fields 返回配置字段元数据的副本。字段顺序与诊断输出顺序一致，并且跨版本
// 保持稳定；环境变量名是公开契约。
func Fields() []FieldInfo {
	fields := make([]FieldInfo, len(configFields))
	copy(fields, configFields)
	return fields
}

// LookupField 按点分字段路径查询字段元数据。
func LookupField(path string) (FieldInfo, bool) {
	for _, field := range configFields {
		if field.Field == path {
			return field, true
		}
	}
	return FieldInfo{}, false
}

// Default 返回内置默认配置。默认值刻意保守：只监听本机回环地址，日志输出
// 到标准输出使用文本格式，SQLite 启用 WAL。
func Default() Config {
	return Config{
		Server: ServerConfig{
			ListenAddr:             "127.0.0.1:8080",
			PublicBaseURL:          "",
			TLSExpiryWarningDays:   DefaultServerTLSExpiryWarningDays,
			TLSClientAuthMode:      TLSClientAuthDisabled,
			ShutdownTimeoutSeconds: 10,
		},
		Logging: LoggingConfig{
			Level:  LogLevelInfo,
			Format: LogFormatText,
		},
		Database: DatabaseConfig{
			Driver:        DatabaseDriverSQLite,
			Path:          "database/login.db",
			WAL:           true,
			BusyTimeoutMS: 5000,
		},
		Secrets: SecretsConfig{},
		Registration: RegistrationConfig{
			Enabled:                  false,
			RequireReview:            false,
			RequireEmailVerification: false,
			DefaultRoleIDs:           nil,
		},
		Passkey: PasskeyConfig{
			Enabled:          false,
			UserVerification: "required",
		},
		AppQRLogin: AppQRLoginConfig{
			Enabled:              false,
			AllowedClientIDs:     nil,
			RequestTTLSeconds:    120,
			ClaimIntervalSeconds: 1,
		},
		Protocol: ProtocolConfig{
			Enabled:             false,
			Issuer:              "",
			EnableIntrospection: false,
			DeviceCodeEnabled:   false,
			LoginPath:           "",
			ResourceServices:    nil,
		},
		Mail: MailConfig{
			Enabled: false,
			SMTP: MailSMTPConfig{
				TLSMode:        "starttls",
				TimeoutSeconds: 10,
			},
			From:    MailFromConfig{},
			AppName: "EvernightLogin",
			Delivery: MailDeliveryConfig{
				MaxAttempts:    3,
				TimeoutSeconds: 120,
			},
		},
		ManualRecovery: ManualRecoveryConfig{
			Enabled:            false,
			WaitPeriodSeconds:  24 * 60 * 60,
			ApprovalTTLSeconds: 48 * 60 * 60,
			RequestTTLSeconds:  7 * 24 * 60 * 60,
			RebindMethods:      []string{"passkey"},
		},
	}
}

// Validate 检查配置的字段值、范围和组合约束。宿主直接构造 Config 时必须先
// 调用 Validate，再产生监听、打开数据库或写文件等副作用。
func (c Config) Validate() error {
	errs := validateMerged(c)
	if len(errs) == 0 {
		return nil
	}
	return errs
}

// Ptr 返回 v 的指针，便于在 Overrides 中表达“显式设置某个值”。显式 false
// 与 0 必须用指针传入；nil 表示未设置，会保留 YAML、环境变量或默认值。
func Ptr[T any](v T) *T {
	return &v
}

// ConfigErrorKind 是可识别的配置错误种类。本步不依赖尚未实现的错误码
// 注册表，先提供稳定种类，步骤 05 再统一映射到公开错误码（如 CONFIG_INVALID）。
type ConfigErrorKind string

const (
	// ConfigErrorYAMLSyntax 表示 YAML 语法错误或多文档等无法解析的问题。
	ConfigErrorYAMLSyntax ConfigErrorKind = "yaml-syntax"
	// ConfigErrorUnknownField 表示出现未定义的字段。
	ConfigErrorUnknownField ConfigErrorKind = "unknown-field"
	// ConfigErrorDuplicateKey 表示同一层内出现重复键。
	ConfigErrorDuplicateKey ConfigErrorKind = "duplicate-key"
	// ConfigErrorType 表示字段类型不对，例如布尔字段写成字符串。
	ConfigErrorType ConfigErrorKind = "invalid-type"
	// ConfigErrorValue 表示字段值不是允许的取值，例如未知日志级别。
	ConfigErrorValue ConfigErrorKind = "invalid-value"
	// ConfigErrorRange 表示数值超出允许范围，例如端口为 0。
	ConfigErrorRange ConfigErrorKind = "out-of-range"
	// ConfigErrorConflict 表示字段组合冲突，例如公开地址使用 http 却监听所有接口。
	ConfigErrorConflict ConfigErrorKind = "conflict"
	// ConfigErrorSecretSource 表示秘密来源缺失、不可读或类型不正确。
	ConfigErrorSecretSource ConfigErrorKind = "secret-source"
	// ConfigErrorOptions 表示调用参数或文件读取等加载器使用错误。
	ConfigErrorOptions ConfigErrorKind = "invalid-options"
)

// ConfigError 是一个结构化的配置错误，包含来源、字段路径和行号，便于
// CLI 与日志精确定位。Detail 永远不包含秘密值。
type ConfigError struct {
	// Kind 是可识别的错误种类，供程序分支和步骤 05 的错误码映射使用。
	Kind ConfigErrorKind
	// Source 是错误来源："yaml"、"env"、"options"、"final" 或 "loader"。
	Source string
	// Field 是点分字段路径；整体错误时为空。
	Field string
	// Line 是 YAML 行号；非 YAML 错误为 0。
	Line int
	// Detail 是可公开的中文说明，不包含秘密值。
	Detail string
	// cause 保留底层原因链，便于程序判断，但不在 Detail 中展开秘密。
	cause error
}

// Error 实现 error。输出包含种类、来源、字段与行号，不包含字段值。
func (e *ConfigError) Error() string {
	var b strings.Builder
	b.WriteString("配置错误")
	if e.Field != "" {
		b.WriteString(" [")
		b.WriteString(e.Field)
		b.WriteString("]")
	}
	b.WriteString("(")
	b.WriteString(e.Kind.String())
	if e.Source != "" {
		b.WriteString("，来源 ")
		b.WriteString(e.Source)
	}
	if e.Line > 0 {
		b.WriteString("，第 ")
		b.WriteString(strconv.Itoa(e.Line))
		b.WriteString(" 行")
	}
	b.WriteString(")：")
	b.WriteString(e.Detail)
	return b.String()
}

// Unwrap 返回底层原因。
func (e *ConfigError) Unwrap() error {
	return e.cause
}

// String 返回错误种类的稳定字符串。
func (k ConfigErrorKind) String() string {
	return string(k)
}

// ConfigErrors 是一次加载中收集到的全部配置错误，实现 error 与
// errors.As/errors.Is 的原因链展开。
type ConfigErrors []*ConfigError

// Error 实现 error，每行一个错误，便于 CLI 逐项修正。
func (es ConfigErrors) Error() string {
	if len(es) == 0 {
		return "配置错误"
	}
	if len(es) == 1 {
		return es[0].Error()
	}
	var b strings.Builder
	b.WriteString("配置检查发现 ")
	b.WriteString(strconv.Itoa(len(es)))
	b.WriteString(" 项错误：")
	for _, e := range es {
		b.WriteString("\n  - ")
		b.WriteString(e.Error())
	}
	return b.String()
}

// Unwrap 让 errors.As/errors.Is 能遍历每一项配置错误。
func (es ConfigErrors) Unwrap() []error {
	out := make([]error, 0, len(es))
	for _, e := range es {
		out = append(out, e)
	}
	return out
}

// configErr 构造一个配置错误。
func configErr(kind ConfigErrorKind, source, field string, line int, detail string) *ConfigError {
	return &ConfigError{Kind: kind, Source: source, Field: field, Line: line, Detail: detail}
}

// configErrWrap 构造带底层原因的配置错误。
func configErrWrap(kind ConfigErrorKind, source, field string, line int, detail string, cause error) *ConfigError {
	return &ConfigError{Kind: kind, Source: source, Field: field, Line: line, Detail: detail, cause: cause}
}

// listenAddrProblem 校验 host:port 监听地址，返回空字符串表示通过。
//
// 监听主机只接受 IP 字面量、localhost 或空（所有接口）；不接受任意域名，避免
// 绑定结果随 DNS 变化而改变实际暴露面。
func listenAddrProblem(addr string) string {
	if addr == "" {
		return "监听地址不能为空"
	}
	if _, err := netpolicy.ParseListenAddress(addr, false); err != nil {
		return err.Error()
	}
	return ""
}

// extraListenAddrsProblem 校验额外监听地址列表；空列表通过。
func extraListenAddrsProblem(values []string) string {
	if len(values) > MaxServerListenAddresses-1 {
		return fmt.Sprintf("额外监听地址不能超过 %d 个", MaxServerListenAddresses-1)
	}
	seen := make(map[string]struct{}, len(values))
	for index, raw := range values {
		address, err := netpolicy.ParseListenAddress(raw, false)
		if err != nil {
			return fmt.Sprintf("额外监听地址第 %d 项无效：%v", index+1, err)
		}
		if _, duplicated := seen[address.Key()]; duplicated {
			return fmt.Sprintf("额外监听地址第 %d 项重复", index+1)
		}
		seen[address.Key()] = struct{}{}
	}
	return ""
}

// combinedListenAddressesProblem 检查主地址与额外地址合并后的重复项。单个字段
// 内部的重复由字段级校验报告；这里覆盖跨字段重复（例如主地址也出现在额外列表）。
func combinedListenAddressesProblem(primary string, extras []string) string {
	addresses := make([]string, 0, 1+len(extras))
	addresses = append(addresses, primary)
	addresses = append(addresses, extras...)
	seen := make(map[string]int, len(addresses))
	for index, raw := range addresses {
		address, err := netpolicy.ParseListenAddress(raw, false)
		if err != nil {
			// 单项格式错误已由字段级校验报告，这里不重复报错。
			continue
		}
		key := address.Key()
		if firstIndex, duplicated := seen[key]; duplicated {
			return fmt.Sprintf("监听地址第 %d 项与第 %d 项重复", index+1, firstIndex+1)
		}
		seen[key] = index
	}
	return ""
}

// pathPrefixProblem 校验固定路径前缀，返回空字符串表示通过。
func pathPrefixProblem(prefix string) string {
	if _, err := httppolicy.NormalizePrefix(prefix); err != nil {
		return err.Error()
	}
	return ""
}

// allowedHostsProblem 校验允许 Host 列表；空列表通过。
func allowedHostsProblem(values []string) string {
	if len(values) > MaxServerAllowedHosts {
		return fmt.Sprintf("允许的主机名不能超过 %d 个", MaxServerAllowedHosts)
	}
	if _, err := netpolicy.NewHostSet(values); err != nil {
		return err.Error()
	}
	return ""
}

// trustedProxiesProblem 校验可信代理 IP/CIDR 列表；空列表通过。
func trustedProxiesProblem(values []string) string {
	if len(values) > MaxServerTrustedProxies {
		return fmt.Sprintf("可信代理不能超过 %d 个", MaxServerTrustedProxies)
	}
	if _, err := proxytrust.Parse(values); err != nil {
		return err.Error()
	}
	return ""
}

// tlsPathProblem 校验证书材料文件路径的文本形状（不访问文件系统）。
func tlsPathProblem(label, path string) string {
	if path == "" {
		return label + "路径不能为空"
	}
	if len(path) > 4096 {
		return label + "路径过长"
	}
	for _, character := range path {
		if character < 0x20 || character == 0x7f {
			return label + "路径包含控制字符"
		}
	}
	return ""
}

// tlsFileListProblem 校验证书/私钥文件列表：数量上限、路径形状与重复项。
func tlsFileListProblem(label string, values []string, max int) string {
	if len(values) > max {
		return fmt.Sprintf("%s不能超过 %d 个", label, max)
	}
	seen := make(map[string]struct{}, len(values))
	for index, raw := range values {
		if problem := tlsPathProblem(label, raw); problem != "" {
			return fmt.Sprintf("%s第 %d 项无效：%s", label, index+1, problem)
		}
		if _, duplicated := seen[raw]; duplicated {
			return fmt.Sprintf("%s第 %d 项重复", label, index+1)
		}
		seen[raw] = struct{}{}
	}
	return ""
}

// tlsClientIdentityDNSName 规范化并校验身份映射中的客户端证书 DNS 名称：必须是
// 合法主机名，不接受 IP、通配符或端口。返回规范名称与非空错误说明。
func tlsClientIdentityDNSName(raw string) (string, string) {
	parsed, err := netpolicy.ParseRequestHost(strings.TrimSpace(raw))
	if err != nil || parsed.IsIP() || parsed.Port() != 0 {
		return "", "客户端证书身份必须使用合法的 DNS 主机名"
	}
	return parsed.Host(), ""
}

// tlsClientServiceNameProblem 校验可信服务身份名称：1～64 字节 ASCII 小写标识符，
// 只允许 a-z、0-9、点、下划线与连字符，首尾必须是字母或数字。
func tlsClientServiceNameProblem(name string) string {
	if name == "" {
		return "可信服务身份名称不能为空"
	}
	if len(name) > MaxServerTLSClientServiceIdentityBytes {
		return fmt.Sprintf("可信服务身份名称不能超过 %d 字节", MaxServerTLSClientServiceIdentityBytes)
	}
	for index := 0; index < len(name); index++ {
		character := name[index]
		switch {
		case character >= 'a' && character <= 'z':
		case character >= '0' && character <= '9':
		case character == '.', character == '_', character == '-':
		default:
			return "可信服务身份名称只能包含小写 ASCII 字母、数字、点、下划线与连字符"
		}
	}
	isAlphaNumeric := func(character byte) bool {
		return (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9')
	}
	if !isAlphaNumeric(name[0]) || !isAlphaNumeric(name[len(name)-1]) {
		return "可信服务身份名称必须以字母或数字开头和结尾"
	}
	return ""
}

// tlsClientIdentitiesProblem 校验客户端证书身份映射列表：数量上限、DNS 名称与
// 服务身份格式、同一 DNS 名称不能映射到多个服务身份。
func tlsClientIdentitiesProblem(values []TLSClientIdentity) string {
	if len(values) > MaxServerTLSClientIdentities {
		return fmt.Sprintf("客户端证书身份映射不能超过 %d 条", MaxServerTLSClientIdentities)
	}
	seen := make(map[string]string, len(values))
	for index, identity := range values {
		dnsName, problem := tlsClientIdentityDNSName(identity.DNSName)
		if problem != "" {
			return fmt.Sprintf("客户端证书身份映射第 %d 项无效：%s", index+1, problem)
		}
		service := strings.TrimSpace(identity.Service)
		if problem := tlsClientServiceNameProblem(service); problem != "" {
			return fmt.Sprintf("客户端证书身份映射第 %d 项无效：%s", index+1, problem)
		}
		if _, duplicated := seen[dnsName]; duplicated {
			return fmt.Sprintf("客户端证书身份映射第 %d 项重复：DNS 名称 %q 已被映射", index+1, dnsName)
		}
		seen[dnsName] = service
	}
	return ""
}

// tlsClientCASharedServerPath 检查客户端信任 CA 文件是否与服务器证书材料使用
// 同一路径。加载证书时还会按证书内容再做一次重叠检查；这里提前按配置路径拒绝，
// 让“客户端信任与服务器证书链分开”在配置加载阶段就暴露。
func tlsClientCASharedServerPath(clientFiles []string, server ServerConfig) string {
	serverPaths := make([]string, 0, len(server.TLSCertFiles)+len(server.TLSKeyFiles)+2)
	serverPaths = append(serverPaths, server.TLSCertFiles...)
	serverPaths = append(serverPaths, server.TLSKeyFiles...)
	if server.TLSCAFile != "" {
		serverPaths = append(serverPaths, server.TLSCAFile)
	}
	if server.TLSPFXFile != "" {
		serverPaths = append(serverPaths, server.TLSPFXFile)
	}
	for _, clientFile := range clientFiles {
		cleanedClient := filepath.Clean(clientFile)
		for _, serverFile := range serverPaths {
			if cleanedClient == filepath.Clean(serverFile) {
				return fmt.Sprintf("客户端信任 CA 文件不能与服务器证书材料共用同一路径")
			}
		}
	}
	return ""
}

// validateTLSServer 校验本地 TLS 配置的形状与组合。它不读取证书文件，文件内容、
// 私钥匹配与证书链由 NewServer 调用 TLS 加载器时校验。
func validateTLSServer(c Config) ConfigErrors {
	var errs ConfigErrors
	add := func(kind ConfigErrorKind, field, detail string) {
		errs = append(errs, configErr(kind, "final", field, 0, detail))
	}

	pemMode := len(c.Server.TLSCertFiles) > 0 || len(c.Server.TLSKeyFiles) > 0 || c.Server.TLSCAFile != ""
	pfxMode := c.Server.TLSPFXFile != ""
	if pemMode && pfxMode {
		add(ConfigErrorConflict, "server.tls_pfx_file", "PEM 证书/私钥与 PFX/P12 不能同时配置")
	}
	if pemMode {
		if len(c.Server.TLSCertFiles) != len(c.Server.TLSKeyFiles) {
			add(ConfigErrorConflict, "server.tls_key_files", "证书文件与私钥文件必须一一对应")
		}
		if len(c.Server.TLSCertFiles) == 0 {
			add(ConfigErrorValue, "server.tls_cert_files", "PEM 模式至少需要一个证书与私钥文件对")
		}
	}
	if pfxMode {
		if c.Server.TLSCAFile != "" {
			add(ConfigErrorConflict, "server.tls_ca_file", "PFX/P12 模式不能同时使用附加 CA 文件")
		}
		if !c.Secrets.TLSPFXPassword.IsSet() || c.Secrets.TLSPFXPassword.Len() == 0 {
			add(ConfigErrorConflict, "server.tls_pfx_file",
				"使用 PFX/P12 必须通过 secrets.tls_pfx_password 从受保护来源提供密码")
		}
	} else if c.Secrets.TLSPFXPassword.IsSet() {
		add(ConfigErrorConflict, "secrets.tls_pfx_password", "未配置 server.tls_pfx_file 时不能设置 PFX 密码")
	}
	if c.Secrets.TLSPFXPassword.IsSet() && c.Secrets.TLSPFXPassword.Len() > MaxSecretBytes {
		add(ConfigErrorRange, "secrets.tls_pfx_password",
			fmt.Sprintf("PFX 密码不能超过 %d 字节", MaxSecretBytes))
	}
	if c.Server.TLSExpiryWarningDays < 0 || c.Server.TLSExpiryWarningDays > 365 {
		add(ConfigErrorRange, "server.tls_expiry_warning_days", "证书到期告警天数必须是 0～365 的整数；0 表示默认 30")
	}
	if c.Server.TLSEnabled() {
		if c.Server.TLSProxyMode {
			add(ConfigErrorConflict, "server.tls_terminating_proxy",
				"本地 TLS 证书配置与 TLS 终止代理模式不能同时启用")
		}
		if c.Server.PublicBaseURL != "" {
			parsed, err := url.Parse(c.Server.PublicBaseURL)
			if err != nil || parsed.Scheme != "https" {
				add(ConfigErrorConflict, "server.public_base_url", "启用本地 TLS 时公开地址必须使用 https")
			}
		}
	}

	// 客户端证书认证（mTLS）：默认关闭；关闭时不接受任何客户端信任材料，启用时
	// 必须具备本地 TLS、独立客户端信任 CA 与显式身份映射，且信任 CA 不与服务器
	// 证书链共用路径。仅有受信任 CA 签发的证书不等于获准接入。
	clientAuthMode := normalizeTLSClientAuthMode(c.Server.TLSClientAuthMode)
	clientAuthValid := c.Server.TLSClientAuthMode.Valid()
	if !clientAuthValid {
		add(ConfigErrorValue, "server.tls_client_auth",
			"客户端证书认证模式必须是 disabled、required 或 optional")
	}
	if problem := tlsFileListProblem("客户端信任 CA 文件", c.Server.TLSClientCAFiles, MaxServerTLSClientCAFiles); problem != "" {
		add(ConfigErrorValue, "server.tls_client_ca_files", problem)
	}
	if problem := tlsClientIdentitiesProblem(c.Server.TLSClientIdentities); problem != "" {
		add(ConfigErrorValue, "server.tls_client_identities", problem)
	}
	if clientAuthValid && clientAuthMode.Enabled() {
		if !c.Server.TLSEnabled() {
			add(ConfigErrorConflict, "server.tls_client_auth",
				"启用客户端证书认证必须同时配置本地 TLS 证书")
		}
		if len(c.Server.TLSClientCAFiles) == 0 {
			add(ConfigErrorConflict, "server.tls_client_ca_files",
				"启用客户端证书认证时必须配置客户端信任 CA 文件")
		}
		if len(c.Server.TLSClientIdentities) == 0 {
			add(ConfigErrorConflict, "server.tls_client_identities",
				"启用客户端证书认证时必须配置显式身份映射")
		}
		if problem := tlsClientCASharedServerPath(c.Server.TLSClientCAFiles, c.Server); problem != "" {
			add(ConfigErrorConflict, "server.tls_client_ca_files", problem)
		}
	} else if clientAuthValid {
		if len(c.Server.TLSClientCAFiles) > 0 {
			add(ConfigErrorConflict, "server.tls_client_ca_files",
				"未启用客户端证书认证时不能配置客户端信任 CA")
		}
		if len(c.Server.TLSClientIdentities) > 0 {
			add(ConfigErrorConflict, "server.tls_client_identities",
				"未启用客户端证书认证时不能配置客户端证书身份映射")
		}
	}
	return errs
}

// publicBaseURLProblem 校验外部公开地址；空字符串表示尚未配置，允许通过。
//
// 公开地址是对外身份的显式来源：必须是 http/https 绝对地址，不能包含用户信息、
// 查询串或片段，主机必须是 LDH 主机名或 IP 字面量；路径必须是已规范化的固定
// 前缀形式（不以斜杠结尾、无点段、无百分号编码），从而与 PathPrefix 可比较。
func publicBaseURLProblem(raw string) string {
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "公开地址不是合法 URL"
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "公开地址必须使用 http 或 https"
	}
	if parsed.Host == "" {
		return "公开地址缺少主机名"
	}
	if parsed.User != nil {
		return "公开地址不能包含用户信息"
	}
	if parsed.RawQuery != "" || parsed.ForceQuery {
		return "公开地址不能包含查询字符串"
	}
	if parsed.Fragment != "" {
		return "公开地址不能包含片段"
	}
	if _, err := netpolicy.ParseRequestHost(parsed.Host); err != nil {
		return "公开地址的主机名无效"
	}
	path := parsed.EscapedPath()
	if path == "" || path == "/" {
		return ""
	}
	if _, err := httppolicy.NormalizePrefix(path); err != nil {
		return "公开地址的路径必须是已规范化的固定前缀"
	}
	return ""
}

// publicBaseURLPath 返回公开地址的规范化路径；根路径返回空字符串。
func publicBaseURLPath(raw string) string {
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	path := parsed.EscapedPath()
	if path == "/" {
		return ""
	}
	return path
}

// listenAddrIsLoopback 报告监听地址是否只绑定本机回环接口。空主机名表示
// 绑定所有接口，按非回环处理；未知主机名也按非回环处理，避免误判。
func listenAddrIsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// registrationDefaultRolesProblem 校验默认角色 ID 列表；返回空字符串表示合法。
func registrationDefaultRolesProblem(roleIDs []string) string {
	if len(roleIDs) > MaxRegistrationDefaultRoles {
		return fmt.Sprintf("默认角色数量不能超过 %d 个", MaxRegistrationDefaultRoles)
	}
	seen := make(map[string]struct{}, len(roleIDs))
	for _, raw := range roleIDs {
		roleID := strings.TrimSpace(raw)
		if roleID == "" || len(roleID) > 64 {
			return "默认角色 ID 不能为空且不能超过 64 字节"
		}
		for index := 0; index < len(roleID); index++ {
			character := roleID[index]
			if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
				(character >= '0' && character <= '9') || character == '_' || character == '-' ||
				character == '.' {
				continue
			}
			return "默认角色 ID 只能包含字母、数字与 . _ -"
		}
		if _, exists := seen[roleID]; exists {
			return "默认角色 ID 不能重复"
		}
		seen[roleID] = struct{}{}
	}
	return ""
}

// validateMerged 校验合并后的完整配置，是 Validate 与 Load 的共同入口。
// manualRecoveryConfigProblem 校验人工恢复制度；关闭状态允许空配置，启用时
// 必须完整、有界且不使用电话口述/安全问题等弱依据。
func manualRecoveryConfigProblem(cfg ManualRecoveryConfig) string {
	allowedBasis := map[string]bool{
		"in_person_identity_document": true,
		"notarized_declaration":       true,
	}
	allowedDelivery := map[string]bool{"verified_email": true}
	// 步骤 209：重绑因素类别显式白名单，任何拼写错误都拒绝启动（不能因为 typo
	// 静默退化为“没有可用重绑方式”）。无论制度是否启用都校验已填写的值。
	allowedRebind := map[string]bool{"passkey": true, "totp": true}
	seenRebind := map[string]bool{}
	for _, method := range cfg.RebindMethods {
		value := strings.TrimSpace(method)
		if !allowedRebind[value] {
			return "重绑方法只允许 passkey 或 totp"
		}
		if seenRebind[value] {
			return "重绑方法不能重复"
		}
		seenRebind[value] = true
	}
	if !cfg.Enabled {
		return ""
	}
	if len(cfg.RebindMethods) == 0 {
		return "启用人工恢复时必须配置至少一种强因素重绑方法"
	}
	if len(cfg.VerificationBases) == 0 {
		return "启用人工恢复时必须配置至少一种核验依据"
	}
	seen := map[string]bool{}
	for _, basis := range cfg.VerificationBases {
		value := strings.TrimSpace(basis)
		if !allowedBasis[value] {
			return "核验依据只允许 in_person_identity_document 或 notarized_declaration"
		}
		if seen[value] {
			return "核验依据不能重复"
		}
		seen[value] = true
	}
	if len(cfg.DeliveryChannels) == 0 {
		return "启用人工恢复时必须配置至少一种可信交付渠道"
	}
	for _, delivery := range cfg.DeliveryChannels {
		if !allowedDelivery[strings.TrimSpace(delivery)] {
			return "可信交付渠道只允许 verified_email"
		}
	}
	const (
		minWait, maxWait         = 60 * 60, 7 * 24 * 60 * 60
		minApproval, maxApproval = 60 * 60, 7 * 24 * 60 * 60
		minRequest, maxRequest   = 60 * 60, 30 * 24 * 60 * 60
	)
	if cfg.WaitPeriodSeconds < minWait || cfg.WaitPeriodSeconds > maxWait {
		return "等待期必须是 1 小时～7 天"
	}
	if cfg.ApprovalTTLSeconds < minApproval || cfg.ApprovalTTLSeconds > maxApproval {
		return "批准有效期必须是 1 小时～7 天"
	}
	if cfg.ApprovalTTLSeconds <= cfg.WaitPeriodSeconds {
		return "批准有效期必须大于等待期"
	}
	if cfg.RequestTTLSeconds < minRequest || cfg.RequestTTLSeconds > maxRequest {
		return "申请有效期必须是 1 小时～30 天"
	}
	if cfg.RequestTTLSeconds < cfg.WaitPeriodSeconds+cfg.ApprovalTTLSeconds {
		return "申请有效期必须不小于等待期与批准有效期之和"
	}
	return ""
}

func validateMerged(c Config) ConfigErrors {
	var errs ConfigErrors

	if problem := listenAddrProblem(c.Server.ListenAddr); problem != "" {
		errs = append(errs, configErr(ConfigErrorValue, "final", "server.listen_addr", 0, problem))
	}
	if problem := extraListenAddrsProblem(c.Server.ExtraListenAddrs); problem != "" {
		errs = append(errs, configErr(ConfigErrorValue, "final", "server.extra_listen_addrs", 0, problem))
	}
	if problem := combinedListenAddressesProblem(c.Server.ListenAddr, c.Server.ExtraListenAddrs); problem != "" {
		errs = append(errs, configErr(ConfigErrorValue, "final", "server.extra_listen_addrs", 0, problem))
	}
	if len(c.Server.ListenAddresses()) > MaxServerListenAddresses {
		errs = append(errs, configErr(ConfigErrorRange, "final", "server.extra_listen_addrs", 0,
			fmt.Sprintf("监听地址总数不能超过 %d 个", MaxServerListenAddresses)))
	}
	if problem := publicBaseURLProblem(c.Server.PublicBaseURL); problem != "" {
		errs = append(errs, configErr(ConfigErrorValue, "final", "server.public_base_url", 0, problem))
	}
	if problem := pathPrefixProblem(c.Server.PathPrefix); problem != "" {
		errs = append(errs, configErr(ConfigErrorValue, "final", "server.path_prefix", 0, problem))
	}
	if problem := allowedHostsProblem(c.Server.AllowedHosts); problem != "" {
		errs = append(errs, configErr(ConfigErrorValue, "final", "server.allowed_hosts", 0, problem))
	}
	if problem := trustedProxiesProblem(c.Server.TrustedProxies); problem != "" {
		errs = append(errs, configErr(ConfigErrorValue, "final", "server.trusted_proxies", 0, problem))
	}
	if c.Server.ShutdownTimeoutSeconds < 1 || c.Server.ShutdownTimeoutSeconds > 300 {
		errs = append(errs, configErr(ConfigErrorRange, "final", "server.shutdown_timeout_seconds", 0,
			"安全关闭超时必须是 1～300 秒"))
	}
	if !c.Logging.Level.Valid() {
		errs = append(errs, configErr(ConfigErrorValue, "final", "logging.level", 0,
			"日志级别必须是 debug、info、warn 或 error"))
	}
	if !c.Logging.Format.Valid() {
		errs = append(errs, configErr(ConfigErrorValue, "final", "logging.format", 0,
			"日志格式必须是 text 或 json"))
	}
	if !c.Database.Driver.Valid() {
		errs = append(errs, configErr(ConfigErrorValue, "final", "database.driver", 0,
			"当前版本只支持 sqlite 驱动，其他驱动尚未实现"))
	}
	if strings.TrimSpace(c.Database.Path) == "" {
		errs = append(errs, configErr(ConfigErrorValue, "final", "database.path", 0,
			"SQLite 数据库路径不能为空"))
	}
	if c.Database.BusyTimeoutMS < 1 || c.Database.BusyTimeoutMS > 600000 {
		errs = append(errs, configErr(ConfigErrorRange, "final", "database.busy_timeout_ms", 0,
			"锁等待超时必须是 1～600000 毫秒"))
	}
	if problem := registrationDefaultRolesProblem(c.Registration.DefaultRoleIDs); problem != "" {
		errs = append(errs, configErr(ConfigErrorValue, "final", "registration.default_role_ids", 0, problem))
	}
	if problem := passkeyConfigProblem(c.Passkey); problem != "" {
		errs = append(errs, configErr(ConfigErrorValue, "final", "passkey", 0, problem))
	}
	if problem := appQRLoginConfigProblem(c.AppQRLogin); problem != "" {
		errs = append(errs, configErr(ConfigErrorValue, "final", "app_qr_login", 0, problem))
	}
	if problem := protocolConfigProblem(c); problem != "" {
		errs = append(errs, configErr(ConfigErrorValue, "final", "protocol", 0, problem))
	}
	if problem := mailConfigProblem(c); problem != "" {
		errs = append(errs, configErr(ConfigErrorValue, "final", "mail", 0, problem))
	}
	if problem := manualRecoveryConfigProblem(c.ManualRecovery); problem != "" {
		errs = append(errs, configErr(ConfigErrorValue, "final", "manual_recovery", 0, problem))
	}

	// 非法组合：公开地址使用明文 http 时，服务不得监听非回环接口（主地址或额外
	// 地址都算）。否则认证页面和令牌会以明文暴露在网络上。反向代理终止 TLS 时
	// 应配置 https 公开地址。
	if c.Server.PublicBaseURL != "" {
		parsed, err := url.Parse(c.Server.PublicBaseURL)
		if err == nil && parsed.Scheme == "http" {
			for _, raw := range c.Server.ListenAddresses() {
				if !listenAddrIsLoopback(raw) {
					errs = append(errs, configErr(ConfigErrorConflict, "final", "server.public_base_url", 0,
						"公开地址使用 http 时只能监听本机回环地址；对外提供服务必须使用 https"))
					break
				}
			}
		}
	}

	// 非法组合：公开地址的路径必须与固定路径前缀一致，否则外部访问地址与实际
	// 路由前缀不符，客户端会拿到 404 或被代理改写到错误路径。路径前缀为空表示
	// 由嵌入模式自行决定，此时只做 URL 形状校验，由 NewServer 在拿到实际
	// Handler 前缀后再做一致性检查。
	if c.Server.PublicBaseURL != "" && c.Server.PathPrefix != "" {
		publicPath := publicBaseURLPath(c.Server.PublicBaseURL)
		normalizedPrefix, prefixErr := httppolicy.NormalizePrefix(c.Server.PathPrefix)
		if prefixErr == nil && publicPath != normalizedPrefix {
			errs = append(errs, configErr(ConfigErrorConflict, "final", "server.public_base_url", 0,
				"公开地址的路径必须与 server.path_prefix 一致"))
		}
	}

	// 非法组合：启用 TLS 终止代理模式时必须明确外部 https 地址与可信代理；否则
	// 既无法判断外部协议，也无法限制哪些代理可以声明转发信息。
	if c.Server.TLSProxyMode {
		parsed, err := url.Parse(c.Server.PublicBaseURL)
		if c.Server.PublicBaseURL == "" || err != nil || parsed.Scheme != "https" {
			errs = append(errs, configErr(ConfigErrorConflict, "final", "server.tls_terminating_proxy", 0,
				"启用 TLS 终止代理模式必须配置 https 公开地址"))
		}
		if len(c.Server.TrustedProxies) == 0 {
			errs = append(errs, configErr(ConfigErrorConflict, "final", "server.tls_terminating_proxy", 0,
				"启用 TLS 终止代理模式必须配置可信代理"))
		}
	}

	errs = append(errs, validateTLSServer(c)...)

	if c.Secrets.MasterKey.IsSet() {
		if c.Secrets.MasterKey.Len() == 0 {
			errs = append(errs, configErr(ConfigErrorValue, "final", "secrets.master_key", 0,
				"主密钥不能为空"))
		} else if c.Secrets.MasterKey.Len() > MaxSecretBytes {
			errs = append(errs, configErr(ConfigErrorRange, "final", "secrets.master_key", 0,
				fmt.Sprintf("主密钥不能超过 %d 字节", MaxSecretBytes)))
		}
	}

	return errs
}

// mailConfigProblem 校验邮件配置，不做任何 IO（秘密/证书文件读取在装配期）。
func mailConfigProblem(c Config) string {
	mail := c.Mail
	// 非启用时仍校验已填写值的范围，避免预置半成品；但不要求必填。
	if mail.SMTP.TimeoutSeconds < 0 || mail.SMTP.TimeoutSeconds > 120 {
		return "邮件发送时限必须在 1～120 秒"
	}
	if mail.Delivery.MaxAttempts < 0 || mail.Delivery.MaxAttempts > 10 {
		return "邮件最大尝试次数必须在 1～10"
	}
	if mail.Delivery.TimeoutSeconds < 0 || mail.Delivery.TimeoutSeconds > 600 {
		return "邮件投递任务超时必须在 30～600 秒"
	}
	if mail.SMTP.Password.Kind != "" {
		if mail.SMTP.Password.Kind != SecretSourceEnv && mail.SMTP.Password.Kind != SecretSourceFile {
			return "邮件密码只能来自 env: 或 file: 秘密来源"
		}
		if strings.TrimSpace(mail.SMTP.Password.Name) == "" {
			return "邮件密码秘密来源不能为空"
		}
	}
	if len(mail.SMTP.TrustedRoots) > 8 {
		return "邮件信任根最多 8 个文件"
	}
	for _, root := range mail.SMTP.TrustedRoots {
		if !filepath.IsAbs(root) {
			return "邮件信任根必须是绝对路径"
		}
	}
	switch mail.SMTP.TLSMode {
	case "", "starttls", "implicit", "none":
	default:
		return "邮件 TLS 模式必须是 starttls、implicit 或 none"
	}
	if !mail.Enabled {
		return ""
	}
	if _, _, err := net.SplitHostPort(strings.TrimSpace(mail.SMTP.Addr)); err != nil {
		return "启用邮件时必须配置合法的 smtp.addr（host:port）"
	}
	if mail.SMTP.TimeoutSeconds < 1 || mail.SMTP.TimeoutSeconds > 120 {
		return "邮件发送时限必须在 1～120 秒"
	}
	if mail.Delivery.MaxAttempts < 1 || mail.Delivery.MaxAttempts > 10 {
		return "邮件最大尝试次数必须在 1～10"
	}
	if mail.Delivery.TimeoutSeconds < 30 || mail.Delivery.TimeoutSeconds > 600 {
		return "邮件投递任务超时必须在 30～600 秒"
	}
	if strings.TrimSpace(mail.From.Address) == "" {
		return "启用邮件时必须配置 mail.from.address"
	}
	parsed, err := mailpkg.ParseAddress(strings.TrimSpace(mail.From.Address))
	if err != nil || parsed.Address != strings.TrimSpace(mail.From.Address) {
		return "mail.from.address 必须是合法的 addr-spec"
	}
	hasUser := strings.TrimSpace(mail.SMTP.Username) != ""
	hasPass := mail.SMTP.Password.Kind != ""
	if hasUser != hasPass {
		return "邮件认证用户名与密码必须同时配置或同时为空"
	}
	mode := mail.SMTP.TLSMode
	if mode == "" {
		mode = "starttls"
	}
	if mode == "none" {
		// 传入完整 host:port（listenAddrIsLoopback 内部按监听地址解析）；此前先
		// SplitHostPort 再传纯 host 会让回环判断恒为 false，错误拒绝文档声明的
		// 本地明文回环组合（211 发现，212 附带修复）。
		if !mail.SMTP.AllowPlaintextLocal ||
			!listenAddrIsLoopback(strings.TrimSpace(mail.SMTP.Addr)) {
			return "tls_mode=none 只允许回环地址且必须显式 allow_plaintext_local"
		}
		if hasUser {
			return "明文邮件连接不得配置认证凭据"
		}
	}
	return ""
}
