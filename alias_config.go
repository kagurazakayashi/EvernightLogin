package login

// 本文件是步骤 212 公共包迁移的兼容别名桥。
//
// config 包持有配置契约的唯一实现；根包保留原有公开符号（type/const 别名与薄
// 函数转发），保证本仓库消费方、既有宿主代码与外部示例无需改动即可编译。
// 别名桥不复制任何配置解析/校验逻辑；长期保留或移除由步骤 215 依赖检查决定。

import "github.com/kagurazakayashi/EvernightLogin/config"

type AppQRLoginConfig = config.AppQRLoginConfig
type AppQRLoginOverrides = config.AppQRLoginOverrides
type Config = config.Config
type ConfigError = config.ConfigError
type ConfigErrorKind = config.ConfigErrorKind
type ConfigErrors = config.ConfigErrors
type DatabaseConfig = config.DatabaseConfig
type DatabaseDriver = config.DatabaseDriver
type DatabaseOverrides = config.DatabaseOverrides
type FieldInfo = config.FieldInfo
type FieldValue = config.FieldValue
type LoadOptions = config.LoadOptions
type LogFormat = config.LogFormat
type LogLevel = config.LogLevel
type LoggingConfig = config.LoggingConfig
type LoggingOverrides = config.LoggingOverrides
type MailConfig = config.MailConfig
type MailDeliveryConfig = config.MailDeliveryConfig
type MailFromConfig = config.MailFromConfig
type MailSMTPConfig = config.MailSMTPConfig
type ManualRecoveryConfig = config.ManualRecoveryConfig
type Overrides = config.Overrides
type PasskeyConfig = config.PasskeyConfig
type PasskeyOverrides = config.PasskeyOverrides
type ProtocolConfig = config.ProtocolConfig
type ProtocolOverrides = config.ProtocolOverrides
type RegistrationConfig = config.RegistrationConfig
type RegistrationOverrides = config.RegistrationOverrides
type ReloadClass = config.ReloadClass
type ReloadDiff = config.ReloadDiff
type ResourceServiceConfig = config.ResourceServiceConfig
type Secret = config.Secret
type SecretSource = config.SecretSource
type SecretSourceKind = config.SecretSourceKind
type SecretsConfig = config.SecretsConfig
type SecretsOverrides = config.SecretsOverrides
type ServerConfig = config.ServerConfig
type ServerOverrides = config.ServerOverrides
type TLSClientAuthMode = config.TLSClientAuthMode
type TLSClientIdentity = config.TLSClientIdentity

const ConfigErrorConflict = config.ConfigErrorConflict
const ConfigErrorDuplicateKey = config.ConfigErrorDuplicateKey
const ConfigErrorOptions = config.ConfigErrorOptions
const ConfigErrorRange = config.ConfigErrorRange
const ConfigErrorSecretSource = config.ConfigErrorSecretSource
const ConfigErrorType = config.ConfigErrorType
const ConfigErrorUnknownField = config.ConfigErrorUnknownField
const ConfigErrorValue = config.ConfigErrorValue
const ConfigErrorYAMLSyntax = config.ConfigErrorYAMLSyntax
const DatabaseDriverSQLite = config.DatabaseDriverSQLite
const DefaultServerTLSExpiryWarningDays = config.DefaultServerTLSExpiryWarningDays
const EnvVarPrefix = config.EnvVarPrefix
const LogFormatJSON = config.LogFormatJSON
const LogFormatText = config.LogFormatText
const LogLevelDebug = config.LogLevelDebug
const LogLevelError = config.LogLevelError
const LogLevelInfo = config.LogLevelInfo
const LogLevelWarn = config.LogLevelWarn
const MaxAppQRLoginClients = config.MaxAppQRLoginClients
const MaxPasskeyOrigins = config.MaxPasskeyOrigins
const MaxRegistrationDefaultRoles = config.MaxRegistrationDefaultRoles
const MaxSecretBytes = config.MaxSecretBytes
const MaxServerAllowedHosts = config.MaxServerAllowedHosts
const MaxServerListenAddresses = config.MaxServerListenAddresses
const MaxServerTLSCertificates = config.MaxServerTLSCertificates
const MaxServerTLSClientCAFiles = config.MaxServerTLSClientCAFiles
const MaxServerTLSClientIdentities = config.MaxServerTLSClientIdentities
const MaxServerTLSClientServiceIdentityBytes = config.MaxServerTLSClientServiceIdentityBytes
const MaxServerTrustedProxies = config.MaxServerTrustedProxies
const ReloadHotReloadable = config.ReloadHotReloadable
const ReloadRestartRequired = config.ReloadRestartRequired
const SecretSourceEnv = config.SecretSourceEnv
const SecretSourceFile = config.SecretSourceFile
const TLSClientAuthDisabled = config.TLSClientAuthDisabled
const TLSClientAuthOptional = config.TLSClientAuthOptional
const TLSClientAuthRequired = config.TLSClientAuthRequired

// ===== 函数薄转发（唯一实现位于 config 包） =====

// Fields 返回按手册顺序排列的全部配置字段元数据副本。
func Fields() []FieldInfo { return config.Fields() }

// LookupField 按点分字段路径查找字段元数据。
func LookupField(path string) (FieldInfo, bool) { return config.LookupField(path) }

// Default 返回安全默认配置。
func Default() Config { return config.Default() }

// Ptr 返回值的指针，便于表达显式覆盖。
func Ptr[T any](v T) *T { return config.Ptr(v) }

// Load 按默认值→YAML→环境变量→显式覆盖的顺序加载并严格校验配置。
func Load(options LoadOptions) (Config, error) { return config.Load(options) }

// DiffReload 计算两次有效配置之间按热重载分类的差异。
func DiffReload(previous, next Config) ReloadDiff { return config.DiffReload(previous, next) }

// NewSecret 用字节构造可遮盖的秘密值。
func NewSecret(value []byte) Secret { return config.NewSecret(value) }

// NewSecretString 用字符串构造可遮盖的秘密值。
func NewSecretString(value string) Secret { return config.NewSecretString(value) }

// ParseSecretSource 解析秘密来源描述（env:VAR 或 file:PATH）。
func ParseSecretSource(spec string) (SecretSource, error) { return config.ParseSecretSource(spec) }

// NormalizeTLSClientAuthMode 把空字符串归一为 disabled。
func NormalizeTLSClientAuthMode(mode TLSClientAuthMode) TLSClientAuthMode {
	return config.NormalizeTLSClientAuthMode(mode)
}

// normalizeTLSClientAuthMode 是根包内部既有调用口径的薄转发（单一实现）。
func normalizeTLSClientAuthMode(mode TLSClientAuthMode) TLSClientAuthMode {
	return config.NormalizeTLSClientAuthMode(mode)
}
