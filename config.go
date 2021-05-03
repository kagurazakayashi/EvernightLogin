package login

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/netpolicy"
	"github.com/kagurazakayashi/EvernightLogin/internal/proxytrust"
	"github.com/kagurazakayashi/EvernightLogin/internal/transport"
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
)

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
	envServerShutdownTimeout = EnvVarPrefix + "SERVER_SHUTDOWN_TIMEOUT_SECONDS"
	envLoggingLevel          = EnvVarPrefix + "LOGGING_LEVEL"
	envLoggingFormat         = EnvVarPrefix + "LOGGING_FORMAT"
	envDatabaseDriver        = EnvVarPrefix + "DATABASE_DRIVER"
	envDatabasePath          = EnvVarPrefix + "DATABASE_PATH"
	envDatabaseWAL           = EnvVarPrefix + "DATABASE_WAL"
	envDatabaseBusyTimeout   = EnvVarPrefix + "DATABASE_BUSY_TIMEOUT_MS"
	envSecretsMasterKey      = EnvVarPrefix + "SECRETS_MASTER_KEY"
	envSecretsTLSPFXPassword = EnvVarPrefix + "SECRETS_TLS_PFX_PASSWORD"
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
	{Field: "server.shutdown_timeout_seconds", Env: envServerShutdownTimeout, Class: ReloadHotReloadable},
	{Field: "logging.level", Env: envLoggingLevel, Class: ReloadHotReloadable},
	{Field: "logging.format", Env: envLoggingFormat, Class: ReloadHotReloadable},
	{Field: "database.driver", Env: envDatabaseDriver, Class: ReloadRestartRequired},
	{Field: "database.path", Env: envDatabasePath, Class: ReloadRestartRequired},
	{Field: "database.wal", Env: envDatabaseWAL, Class: ReloadRestartRequired},
	{Field: "database.busy_timeout_ms", Env: envDatabaseBusyTimeout, Class: ReloadRestartRequired},
	{Field: "secrets.master_key", Env: envSecretsMasterKey, Class: ReloadRestartRequired, Secret: true},
	{Field: "secrets.tls_pfx_password", Env: envSecretsTLSPFXPassword, Class: ReloadRestartRequired, Secret: true},
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
	if _, err := transport.NormalizePrefix(prefix); err != nil {
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
	if _, err := transport.NormalizePrefix(path); err != nil {
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

// validateMerged 校验合并后的完整配置，是 Validate 与 Load 的共同入口。
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
		normalizedPrefix, prefixErr := transport.NormalizePrefix(c.Server.PathPrefix)
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
