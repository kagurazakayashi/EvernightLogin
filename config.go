package login

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
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
	// ListenAddr 是监听地址，格式为 host:port；默认仅监听 127.0.0.1:8080。
	// 修改后需要重启进程。
	ListenAddr string
	// PublicBaseURL 是外部可访问的基础地址（例如 https://login.example.com），
	// 留空表示尚未配置外部地址。修改后需要重启进程。
	PublicBaseURL string
	// ShutdownTimeoutSeconds 是安全关闭的墙钟上限，单位秒，默认 10。
	// 该值在关闭流程读取，因此可以热更新。
	ShutdownTimeoutSeconds int
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
	envServerPublicBaseURL   = EnvVarPrefix + "SERVER_PUBLIC_BASE_URL"
	envServerShutdownTimeout = EnvVarPrefix + "SERVER_SHUTDOWN_TIMEOUT_SECONDS"
	envLoggingLevel          = EnvVarPrefix + "LOGGING_LEVEL"
	envLoggingFormat         = EnvVarPrefix + "LOGGING_FORMAT"
	envDatabaseDriver        = EnvVarPrefix + "DATABASE_DRIVER"
	envDatabasePath          = EnvVarPrefix + "DATABASE_PATH"
	envDatabaseWAL           = EnvVarPrefix + "DATABASE_WAL"
	envDatabaseBusyTimeout   = EnvVarPrefix + "DATABASE_BUSY_TIMEOUT_MS"
	envSecretsMasterKey      = EnvVarPrefix + "SECRETS_MASTER_KEY"
)

// configFields 是字段元数据的唯一来源。Fields、Diagnostic、环境变量加载和
// 测试都据此保持一致；顺序就是诊断输出顺序。
var configFields = []FieldInfo{
	{Field: "server.listen_addr", Env: envServerListenAddr, Class: ReloadRestartRequired},
	{Field: "server.public_base_url", Env: envServerPublicBaseURL, Class: ReloadRestartRequired},
	{Field: "server.shutdown_timeout_seconds", Env: envServerShutdownTimeout, Class: ReloadHotReloadable},
	{Field: "logging.level", Env: envLoggingLevel, Class: ReloadHotReloadable},
	{Field: "logging.format", Env: envLoggingFormat, Class: ReloadHotReloadable},
	{Field: "database.driver", Env: envDatabaseDriver, Class: ReloadRestartRequired},
	{Field: "database.path", Env: envDatabasePath, Class: ReloadRestartRequired},
	{Field: "database.wal", Env: envDatabaseWAL, Class: ReloadRestartRequired},
	{Field: "database.busy_timeout_ms", Env: envDatabaseBusyTimeout, Class: ReloadRestartRequired},
	{Field: "secrets.master_key", Env: envSecretsMasterKey, Class: ReloadRestartRequired, Secret: true},
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
func listenAddrProblem(addr string) string {
	if strings.TrimSpace(addr) == "" {
		return "监听地址不能为空"
	}
	if strings.ContainsAny(addr, " \t\r\n") {
		return "监听地址不能包含空白字符"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "监听地址必须为 host:port 形式"
	}
	if strings.Contains(host, "/") {
		return "监听地址不能包含路径"
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "端口必须是 1～65535 的整数"
	}
	return ""
}

// publicBaseURLProblem 校验外部公开地址；空字符串表示尚未配置，允许通过。
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
	return ""
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
	if problem := publicBaseURLProblem(c.Server.PublicBaseURL); problem != "" {
		errs = append(errs, configErr(ConfigErrorValue, "final", "server.public_base_url", 0, problem))
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

	// 非法组合：公开地址使用明文 http 时，服务不得监听非回环接口。否则认证
	// 页面和令牌会以明文暴露在网络上。反向代理终止 TLS 时应配置 https 公开地址。
	if c.Server.PublicBaseURL != "" && !listenAddrIsLoopback(c.Server.ListenAddr) {
		parsed, err := url.Parse(c.Server.PublicBaseURL)
		if err == nil && parsed.Scheme == "http" {
			errs = append(errs, configErr(ConfigErrorConflict, "final", "server.public_base_url", 0,
				"公开地址使用 http 时只能监听本机回环地址；对外提供服务必须使用 https"))
		}
	}

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
