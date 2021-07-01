package login

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/passkey"
)

// maxConfigFileBytes 是 YAML 配置文件的大小上限，避免误读大文件。
const maxConfigFileBytes = 1 << 20

// LoadOptions 描述一次配置加载的来源。零值表示只使用内置默认值。
type LoadOptions struct {
	// YAML 是 YAML 配置内容；与 YAMLFile 最多设置一个。
	YAML []byte
	// YAMLFile 是 YAML 配置文件路径；文件必须存在且不超过 1 MiB。
	YAMLFile string
	// LookupEnv 读取环境变量，也用于解析 YAML 中 env: 形式的秘密来源；为 nil
	// 时使用 os.LookupEnv。仅用于测试或宿主定制环境读取方式，生产环境保持 nil。
	LookupEnv func(string) (string, bool)
	// Overrides 是宿主显式代码选项，优先级最高；nil 表示未提供。
	Overrides *Overrides
}

// Overrides 是优先级最高的显式代码选项。指针字段用于区分“显式设置为
// false/0/空值”与“未设置”；未设置时保留 YAML、环境变量或默认值。
//
// 示例：
//
//	cfg, err := login.Load(login.LoadOptions{
//		YAMLFile: "login.yaml",
//		Overrides: &login.Overrides{
//			Server: login.ServerOverrides{
//				ListenAddr: login.Ptr("127.0.0.1:9090"),
//			},
//			Database: login.DatabaseOverrides{
//				WAL: login.Ptr(false),
//			},
//		},
//	})
type Overrides struct {
	Server       ServerOverrides
	Logging      LoggingOverrides
	Database     DatabaseOverrides
	Secrets      SecretsOverrides
	Registration RegistrationOverrides
	Passkey      PasskeyOverrides
	AppQRLogin   AppQRLoginOverrides
}

// ServerOverrides 是 ServerConfig 的显式覆盖项。
type ServerOverrides struct {
	ListenAddr             *string
	ExtraListenAddrs       *[]string
	PublicBaseURL          *string
	PathPrefix             *string
	AllowedHosts           *[]string
	TrustedProxies         *[]string
	TLSProxyMode           *bool
	TLSCertFiles           *[]string
	TLSKeyFiles            *[]string
	TLSCAFile              *string
	TLSPFXFile             *string
	TLSExpiryWarningDays   *int
	TLSClientAuthMode      *TLSClientAuthMode
	TLSClientCAFiles       *[]string
	TLSClientIdentities    *[]TLSClientIdentity
	ShutdownTimeoutSeconds *int
}

// LoggingOverrides 是 LoggingConfig 的显式覆盖项。
type LoggingOverrides struct {
	Level  *LogLevel
	Format *LogFormat
}

// DatabaseOverrides 是 DatabaseConfig 的显式覆盖项。
type DatabaseOverrides struct {
	Driver        *DatabaseDriver
	Path          *string
	WAL           *bool
	BusyTimeoutMS *int
}

// SecretsOverrides 是 SecretsConfig 的显式覆盖项。MasterKey 由宿主密钥提供者
// 构造（NewSecret/NewSecretString），属于受保护来源；不要从命令行参数传入。
type SecretsOverrides struct {
	MasterKey      *Secret
	TLSPFXPassword *Secret
}

// RegistrationOverrides 是 RegistrationConfig 的显式覆盖项。
type RegistrationOverrides struct {
	Enabled                  *bool
	RequireReview            *bool
	RequireEmailVerification *bool
	DefaultRoleIDs           *[]string
}

// PasskeyOverrides 是 PasskeyConfig 的显式覆盖项。
type PasskeyOverrides struct {
	Enabled          *bool
	RPID             *string
	RPDisplayName    *string
	AllowedOrigins   *[]string
	UserVerification *string
}

// AppQRLoginOverrides 是 AppQRLoginConfig 的显式覆盖项。
type AppQRLoginOverrides struct {
	Enabled              *bool
	AllowedClientIDs     *[]string
	RequestTTLSeconds    *int
	ClaimIntervalSeconds *int
}

// Load 按“内置默认值 < YAML < 环境变量 < 显式代码选项”的顺序合并并校验配置。
//
// 任一来源出现 YAML 语法、未知字段、重复键、类型、范围或组合错误时，Load
// 返回 ConfigErrors 且不返回部分可用的 Config。调用方必须在监听端口、打开
// 数据库或写文件之前调用 Load；本函数本身只读配置文件与秘密来源，不产生
// 监听、数据库或文件写入副作用。
//
// 秘密只能来自受保护来源：YAML 中只写来源引用（env: 或 file:），环境变量
// LOGIN_SECRETS_MASTER_KEY 或显式代码选项可直接提供值。错误与诊断输出不会
// 包含秘密内容。配置错误种类待步骤 05 统一映射到公开错误码。
func Load(opts LoadOptions) (Config, error) {
	if opts.YAML != nil && opts.YAMLFile != "" {
		return Config{}, ConfigErrors{configErr(ConfigErrorOptions, "loader", "", 0,
			"YAML 内容与 YAMLFile 不能同时设置")}
	}

	layers := make([]configOverrides, 0, 3)

	// 1. YAML 层：结构错误无法安全合并，直接返回。
	if opts.YAML != nil || opts.YAMLFile != "" {
		data := opts.YAML
		if opts.YAMLFile != "" {
			read, err := readConfigFile(opts.YAMLFile)
			if err != nil {
				return Config{}, ConfigErrors{configErrWrap(ConfigErrorOptions, "loader", "", 0,
					"读取 YAML 配置文件失败", err)}
			}
			data = read
		}
		yamlOverrides, yamlErrs := overridesFromYAML(data)
		if len(yamlErrs) > 0 {
			return Config{}, yamlErrs
		}
		layers = append(layers, yamlOverrides)
	}

	lookup := opts.LookupEnv
	if lookup == nil {
		lookup = os.LookupEnv
	}

	// 2. 环境变量层。解析错误会全部收集，不静默跳过。
	var errs ConfigErrors
	envOverrides, envErrs := overridesFromEnv(lookup)
	errs = append(errs, envErrs...)
	layers = append(layers, envOverrides)

	// 3. 显式代码选项层。
	if opts.Overrides != nil {
		optionOverrides, optionErrs := overridesFromOptions(opts.Overrides)
		errs = append(errs, optionErrs...)
		layers = append(layers, optionOverrides)
	}
	if len(errs) > 0 {
		return Config{}, errs
	}

	cfg := Default()
	for i := range layers {
		layers[i].apply(&cfg)
	}

	// 秘密单独合并：越靠后的层优先，直接值会覆盖 YAML 中的来源引用。主密钥与
	// PFX 密码分别合并，避免一个字段的秘密来源覆盖另一个字段。
	masterSource, masterValue := mergeSecretLayer(layers, func(layer *configOverrides) (*SecretSource, *Secret) {
		return layer.secretSource, layer.secretValue
	})
	pfxSource, pfxValue := mergeSecretLayer(layers, func(layer *configOverrides) (*SecretSource, *Secret) {
		return layer.secretPFXSource, layer.secretPFXValue
	})
	if masterValue != nil {
		cfg.Secrets.MasterKey = *masterValue
	} else if masterSource != nil {
		secret, err := masterSource.load(lookup)
		if err != nil {
			return Config{}, ConfigErrors{configErrWrap(ConfigErrorSecretSource, "yaml", "secrets.master_key", 0,
				"无法从受保护来源读取主密钥", err)}
		}
		cfg.Secrets.MasterKey = secret
	}
	if pfxValue != nil {
		cfg.Secrets.TLSPFXPassword = *pfxValue
	} else if pfxSource != nil {
		secret, err := pfxSource.load(lookup)
		if err != nil {
			return Config{}, ConfigErrors{configErrWrap(ConfigErrorSecretSource, "yaml", "secrets.tls_pfx_password", 0,
				"无法从受保护来源读取 TLS PFX 密码", err)}
		}
		cfg.Secrets.TLSPFXPassword = secret
	}

	if finalErrs := validateMerged(cfg); len(finalErrs) > 0 {
		return Config{}, finalErrs
	}
	return cfg, nil
}

// mergeSecretLayer 按层序合并一个秘密字段：越靠后的层优先，直接值覆盖来源引用。
func mergeSecretLayer(layers []configOverrides, access func(*configOverrides) (*SecretSource, *Secret)) (*SecretSource, *Secret) {
	var source *SecretSource
	var value *Secret
	for index := range layers {
		layerSource, layerValue := access(&layers[index])
		if layerSource != nil {
			source = layerSource
			value = nil
		}
		if layerValue != nil {
			value = layerValue
			source = nil
		}
	}
	return source, value
}

// configOverrides 是单层配置的内部表示；指针字段表示“该层显式设置了此字段”。
type configOverrides struct {
	serverListenAddr      *string
	serverExtraListen     *[]string
	serverPublicBaseURL   *string
	serverPathPrefix      *string
	serverAllowedHosts    *[]string
	serverTrustedProxies  *[]string
	serverTLSProxyMode    *bool
	serverTLSCertFiles    *[]string
	serverTLSKeyFiles     *[]string
	serverTLSCAFile       *string
	serverTLSPFXFile      *string
	serverTLSExpiryDays   *int
	serverTLSClientAuth   *TLSClientAuthMode
	serverTLSClientCA     *[]string
	serverTLSClientMaps   *[]TLSClientIdentity
	serverShutdownTimeout *int
	loggingLevel          *LogLevel
	loggingFormat         *LogFormat
	databaseDriver        *DatabaseDriver
	databasePath          *string
	databaseWAL           *bool
	databaseBusyTimeout   *int
	registrationEnabled   *bool
	registrationReview    *bool
	registrationEmail     *bool
	registrationRoles     *[]string
	passkeyEnabled        *bool
	passkeyRPID           *string
	passkeyRPName         *string
	passkeyOrigins        *[]string
	passkeyUserVerify     *string
	appQRLoginEnabled     *bool
	appQRLoginClients     *[]string
	appQRLoginTTL         *int
	appQRLoginInterval    *int
	secretSource          *SecretSource
	secretValue           *Secret
	secretPFXSource       *SecretSource
	secretPFXValue        *Secret
}

// apply 把本层显式设置的值覆盖到配置上；未设置的字段保持原值。切片字段复制后
// 写入，避免多层共享同一底层数组。
func (ov *configOverrides) apply(cfg *Config) {
	if ov.serverListenAddr != nil {
		cfg.Server.ListenAddr = *ov.serverListenAddr
	}
	if ov.serverExtraListen != nil {
		cfg.Server.ExtraListenAddrs = append([]string(nil), (*ov.serverExtraListen)...)
	}
	if ov.serverPublicBaseURL != nil {
		cfg.Server.PublicBaseURL = *ov.serverPublicBaseURL
	}
	if ov.serverPathPrefix != nil {
		cfg.Server.PathPrefix = *ov.serverPathPrefix
	}
	if ov.serverAllowedHosts != nil {
		cfg.Server.AllowedHosts = append([]string(nil), (*ov.serverAllowedHosts)...)
	}
	if ov.serverTrustedProxies != nil {
		cfg.Server.TrustedProxies = append([]string(nil), (*ov.serverTrustedProxies)...)
	}
	if ov.serverTLSProxyMode != nil {
		cfg.Server.TLSProxyMode = *ov.serverTLSProxyMode
	}
	if ov.serverTLSCertFiles != nil {
		cfg.Server.TLSCertFiles = append([]string(nil), (*ov.serverTLSCertFiles)...)
	}
	if ov.serverTLSKeyFiles != nil {
		cfg.Server.TLSKeyFiles = append([]string(nil), (*ov.serverTLSKeyFiles)...)
	}
	if ov.serverTLSCAFile != nil {
		cfg.Server.TLSCAFile = *ov.serverTLSCAFile
	}
	if ov.serverTLSPFXFile != nil {
		cfg.Server.TLSPFXFile = *ov.serverTLSPFXFile
	}
	if ov.serverTLSExpiryDays != nil {
		cfg.Server.TLSExpiryWarningDays = *ov.serverTLSExpiryDays
	}
	if ov.serverTLSClientAuth != nil {
		cfg.Server.TLSClientAuthMode = *ov.serverTLSClientAuth
	}
	if ov.serverTLSClientCA != nil {
		cfg.Server.TLSClientCAFiles = append([]string(nil), (*ov.serverTLSClientCA)...)
	}
	if ov.serverTLSClientMaps != nil {
		cfg.Server.TLSClientIdentities = append([]TLSClientIdentity(nil), (*ov.serverTLSClientMaps)...)
	}
	if ov.serverShutdownTimeout != nil {
		cfg.Server.ShutdownTimeoutSeconds = *ov.serverShutdownTimeout
	}
	if ov.loggingLevel != nil {
		cfg.Logging.Level = *ov.loggingLevel
	}
	if ov.loggingFormat != nil {
		cfg.Logging.Format = *ov.loggingFormat
	}
	if ov.databaseDriver != nil {
		cfg.Database.Driver = *ov.databaseDriver
	}
	if ov.databasePath != nil {
		cfg.Database.Path = *ov.databasePath
	}
	if ov.databaseWAL != nil {
		cfg.Database.WAL = *ov.databaseWAL
	}
	if ov.databaseBusyTimeout != nil {
		cfg.Database.BusyTimeoutMS = *ov.databaseBusyTimeout
	}
	if ov.registrationEnabled != nil {
		cfg.Registration.Enabled = *ov.registrationEnabled
	}
	if ov.registrationReview != nil {
		cfg.Registration.RequireReview = *ov.registrationReview
	}
	if ov.registrationEmail != nil {
		cfg.Registration.RequireEmailVerification = *ov.registrationEmail
	}
	if ov.registrationRoles != nil {
		cfg.Registration.DefaultRoleIDs = append([]string(nil), (*ov.registrationRoles)...)
	}
	if ov.passkeyEnabled != nil {
		cfg.Passkey.Enabled = *ov.passkeyEnabled
	}
	if ov.passkeyRPID != nil {
		cfg.Passkey.RPID = *ov.passkeyRPID
	}
	if ov.passkeyRPName != nil {
		cfg.Passkey.RPDisplayName = *ov.passkeyRPName
	}
	if ov.passkeyOrigins != nil {
		cfg.Passkey.AllowedOrigins = append([]string(nil), (*ov.passkeyOrigins)...)
	}
	if ov.passkeyUserVerify != nil {
		cfg.Passkey.UserVerification = *ov.passkeyUserVerify
	}
	if ov.appQRLoginEnabled != nil {
		cfg.AppQRLogin.Enabled = *ov.appQRLoginEnabled
	}
	if ov.appQRLoginClients != nil {
		cfg.AppQRLogin.AllowedClientIDs = append([]string(nil), (*ov.appQRLoginClients)...)
	}
	if ov.appQRLoginTTL != nil {
		cfg.AppQRLogin.RequestTTLSeconds = *ov.appQRLoginTTL
	}
	if ov.appQRLoginInterval != nil {
		cfg.AppQRLogin.ClaimIntervalSeconds = *ov.appQRLoginInterval
	}
}

// readConfigFile 读取 YAML 配置文件，并限制文件大小与文件类型。
func readConfigFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("无法访问配置文件：%v", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("配置路径必须是普通文件")
	}
	if info.Size() > maxConfigFileBytes {
		return nil, fmt.Errorf("配置文件超过 %d 字节上限", maxConfigFileBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("无法读取配置文件：%v", err)
	}
	if len(data) > maxConfigFileBytes {
		return nil, fmt.Errorf("配置文件超过 %d 字节上限", maxConfigFileBytes)
	}
	return data, nil
}

// yamlConfig 是 YAML 层的严格解码目标。字段全部使用指针以保留“未设置”信息。
type yamlConfig struct {
	Server       *yamlServer       `yaml:"server"`
	Logging      *yamlLogging      `yaml:"logging"`
	Database     *yamlDatabase     `yaml:"database"`
	Secrets      *yamlSecrets      `yaml:"secrets"`
	Registration *yamlRegistration `yaml:"registration"`
	Passkey      *yamlPasskey      `yaml:"passkey"`
	AppQRLogin   *yamlAppQRLogin   `yaml:"app_qr_login"`
}

type yamlServer struct {
	ListenAddr             *string                  `yaml:"listen_addr"`
	ExtraListenAddrs       *[]string                `yaml:"extra_listen_addrs"`
	PublicBaseURL          *string                  `yaml:"public_base_url"`
	PathPrefix             *string                  `yaml:"path_prefix"`
	AllowedHosts           *[]string                `yaml:"allowed_hosts"`
	TrustedProxies         *[]string                `yaml:"trusted_proxies"`
	TLSProxyMode           *bool                    `yaml:"tls_terminating_proxy"`
	TLSCertFiles           *[]string                `yaml:"tls_cert_files"`
	TLSKeyFiles            *[]string                `yaml:"tls_key_files"`
	TLSCAFile              *string                  `yaml:"tls_ca_file"`
	TLSPFXFile             *string                  `yaml:"tls_pfx_file"`
	TLSExpiryWarningDays   *int                     `yaml:"tls_expiry_warning_days"`
	TLSClientAuthMode      *string                  `yaml:"tls_client_auth"`
	TLSClientCAFiles       *[]string                `yaml:"tls_client_ca_files"`
	TLSClientIdentities    *[]yamlTLSClientIdentity `yaml:"tls_client_identities"`
	ShutdownTimeoutSeconds *int                     `yaml:"shutdown_timeout_seconds"`
}

// yamlTLSClientIdentity 是 YAML 中的一条客户端证书身份映射。两个字段都是必填。
type yamlTLSClientIdentity struct {
	DNSName *string `yaml:"dns_name"`
	Service *string `yaml:"service"`
}

type yamlLogging struct {
	Level  *string `yaml:"level"`
	Format *string `yaml:"format"`
}

type yamlDatabase struct {
	Driver        *string `yaml:"driver"`
	Path          *string `yaml:"path"`
	WAL           *bool   `yaml:"wal"`
	BusyTimeoutMS *int    `yaml:"busy_timeout_ms"`
}

type yamlSecrets struct {
	MasterKey      *yamlSecretSource `yaml:"master_key"`
	TLSPFXPassword *yamlSecretSource `yaml:"tls_pfx_password"`
}

// yamlRegistration 是 YAML 中的自主注册策略段（步骤 33）。
type yamlRegistration struct {
	Enabled                  *bool     `yaml:"enabled"`
	RequireReview            *bool     `yaml:"require_review"`
	RequireEmailVerification *bool     `yaml:"require_email_verification"`
	DefaultRoleIDs           *[]string `yaml:"default_role_ids"`
}

// yamlAppQRLogin 是 YAML 中的扫码登录配置段（步骤 58）。
type yamlAppQRLogin struct {
	Enabled              *bool     `yaml:"enabled"`
	AllowedClientIDs     *[]string `yaml:"allowed_client_ids"`
	RequestTTLSeconds    *int      `yaml:"request_ttl_seconds"`
	ClaimIntervalSeconds *int      `yaml:"claim_interval_seconds"`
}

// yamlPasskey 是 YAML 中的 Passkey 依赖方配置段（步骤 42）。
type yamlPasskey struct {
	Enabled          *bool     `yaml:"enabled"`
	RPID             *string   `yaml:"rp_id"`
	RPDisplayName    *string   `yaml:"rp_display_name"`
	AllowedOrigins   *[]string `yaml:"allowed_origins"`
	UserVerification *string   `yaml:"user_verification"`
}

// yamlSecretFields 是允许出现的秘密字段名；每个字段的值只能是 env/file 来源映射。
var yamlSecretFields = map[string]struct{}{
	"master_key":       {},
	"tls_pfx_password": {},
}

type yamlSecretSource struct {
	Env  *string `yaml:"env"`
	File *string `yaml:"file"`
}

// yamlLeafSpec 描述一个标量字段允许的 YAML 标签。
type yamlLeafSpec struct {
	name string
	tag  string
}

var (
	yamlRootKeys = []string{"server", "logging", "database", "secrets", "registration", "passkey", "app_qr_login"}

	yamlSectionFields = map[string][]yamlLeafSpec{
		"server": {
			{name: "listen_addr", tag: "!!str"},
			{name: "public_base_url", tag: "!!str"},
			{name: "path_prefix", tag: "!!str"},
			{name: "tls_terminating_proxy", tag: "!!bool"},
			{name: "tls_ca_file", tag: "!!str"},
			{name: "tls_pfx_file", tag: "!!str"},
			{name: "tls_expiry_warning_days", tag: "!!int"},
			{name: "tls_client_auth", tag: "!!str"},
			{name: "shutdown_timeout_seconds", tag: "!!int"},
		},
		"logging": {
			{name: "level", tag: "!!str"},
			{name: "format", tag: "!!str"},
		},
		"database": {
			{name: "driver", tag: "!!str"},
			{name: "path", tag: "!!str"},
			{name: "wal", tag: "!!bool"},
			{name: "busy_timeout_ms", tag: "!!int"},
		},
		"registration": {
			{name: "enabled", tag: "!!bool"},
			{name: "require_review", tag: "!!bool"},
			{name: "require_email_verification", tag: "!!bool"},
		},
		"passkey": {
			{name: "enabled", tag: "!!bool"},
			{name: "rp_id", tag: "!!str"},
			{name: "rp_display_name", tag: "!!str"},
			{name: "user_verification", tag: "!!str"},
		},
		"app_qr_login": {
			{name: "enabled", tag: "!!bool"},
			{name: "request_ttl_seconds", tag: "!!int"},
			{name: "claim_interval_seconds", tag: "!!int"},
		},
	}

	// yamlSectionListFields 描述字符串列表字段；值是该列表元素允许的 YAML 标签。
	yamlSectionListFields = map[string]map[string]string{
		"server": {
			"extra_listen_addrs":  "!!str",
			"allowed_hosts":       "!!str",
			"trusted_proxies":     "!!str",
			"tls_cert_files":      "!!str",
			"tls_key_files":       "!!str",
			"tls_client_ca_files": "!!str",
		},
		"registration": {
			"default_role_ids": "!!str",
		},
		"passkey": {
			"allowed_origins": "!!str",
		},
		"app_qr_login": {
			"allowed_client_ids": "!!str",
		},
	}

	// yamlSectionObjectListFields 描述“对象列表”字段；每个列表元素必须是映射，且
	// 只能包含这里声明的字段，所有字段都是必填字符串。
	yamlSectionObjectListFields = map[string]map[string][]yamlLeafSpec{
		"server": {
			"tls_client_identities": {
				{name: "dns_name", tag: "!!str"},
				{name: "service", tag: "!!str"},
			},
		},
	}

	yamlSecretSourceFields = []yamlLeafSpec{
		{name: "env", tag: "!!str"},
		{name: "file", tag: "!!str"},
	}
)

// overridesFromYAML 解析 YAML。先做结构检查（未知字段、重复键、类型、null），
// 再解码为强类型结构；不依赖 yaml 库的错误文本识别字段。
func overridesFromYAML(data []byte) (configOverrides, ConfigErrors) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return configOverrides{}, ConfigErrors{configErrWrap(ConfigErrorYAMLSyntax, "yaml", "", 0,
			"YAML 解析失败", err)}
	}
	if root.Kind == 0 {
		return configOverrides{}, nil
	}
	if errs := checkYAMLStructure(&root); len(errs) > 0 {
		return configOverrides{}, errs
	}

	var doc yamlConfig
	if err := root.Decode(&doc); err != nil {
		return configOverrides{}, ConfigErrors{configErrWrap(ConfigErrorType, "yaml", "", 0,
			"YAML 字段类型不正确", err)}
	}
	return convertYAML(&doc)
}

// checkYAMLStructure 遍历 YAML 节点树，报告未知字段、重复键、错误类型与 null。
func checkYAMLStructure(root *yaml.Node) ConfigErrors {
	if root.Kind != yaml.DocumentNode {
		return ConfigErrors{configErr(ConfigErrorType, "yaml", "", root.Line,
			"YAML 根节点必须是映射")}
	}
	if len(root.Content) == 0 {
		return nil
	}
	document := root.Content[0]
	if document.Kind == yaml.AliasNode {
		return ConfigErrors{configErr(ConfigErrorType, "yaml", "", document.Line,
			"不支持 YAML 别名或锚点")}
	}
	if document.Kind != yaml.MappingNode {
		return ConfigErrors{configErr(ConfigErrorType, "yaml", "", document.Line,
			"YAML 根节点必须是映射")}
	}

	var errs ConfigErrors
	seen := make(map[string]int)
	for i := 0; i+1 < len(document.Content); i += 2 {
		key := document.Content[i]
		value := document.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			errs = append(errs, configErr(ConfigErrorType, "yaml", "", key.Line,
				"映射键必须是字符串"))
			continue
		}
		name := key.Value
		if firstLine, duplicated := seen[name]; duplicated {
			errs = append(errs, configErr(ConfigErrorDuplicateKey, "yaml", name, key.Line,
				fmt.Sprintf("重复的顶层键，首次出现在第 %d 行", firstLine)))
			continue
		}
		seen[name] = key.Line

		specs, known := yamlSectionFields[name]
		if !known && name != "secrets" {
			errs = append(errs, configErr(ConfigErrorUnknownField, "yaml", name, key.Line,
				"未定义的顶层配置段"))
			continue
		}
		if value.Kind == yaml.AliasNode {
			errs = append(errs, configErr(ConfigErrorType, "yaml", name, value.Line,
				"不支持 YAML 别名或锚点"))
			continue
		}
		if value.Kind != yaml.MappingNode {
			errs = append(errs, configErr(ConfigErrorType, "yaml", name, value.Line,
				"配置段必须是映射"))
			continue
		}
		if name == "secrets" {
			errs = append(errs, checkYAMLSecrets(value)...)
			continue
		}
		errs = append(errs, checkYAMLMappedSection(value, name, specs, yamlSectionListFields[name], yamlSectionObjectListFields[name])...)
	}
	return errs
}

// checkYAMLMappedSection 检查普通配置段的字段名、重复键、标量类型、字符串列表
// 类型与对象列表类型。
func checkYAMLMappedSection(section *yaml.Node, prefix string, specs []yamlLeafSpec, listSpecs map[string]string, objectListSpecs map[string][]yamlLeafSpec) ConfigErrors {
	allowed := make(map[string]string, len(specs))
	for _, spec := range specs {
		allowed[spec.name] = spec.tag
	}

	var errs ConfigErrors
	seen := make(map[string]int)
	for i := 0; i+1 < len(section.Content); i += 2 {
		key := section.Content[i]
		value := section.Content[i+1]
		fieldPath := prefix
		if key.Kind == yaml.ScalarNode && key.Tag == "!!str" {
			fieldPath = prefix + "." + key.Value
		}
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			errs = append(errs, configErr(ConfigErrorType, "yaml", prefix, key.Line,
				"字段名必须是字符串"))
			continue
		}
		name := key.Value
		if firstLine, duplicated := seen[name]; duplicated {
			errs = append(errs, configErr(ConfigErrorDuplicateKey, "yaml", fieldPath, key.Line,
				fmt.Sprintf("重复字段，首次出现在第 %d 行", firstLine)))
			continue
		}
		seen[name] = key.Line

		tag, known := allowed[name]
		if known {
			if problem := yamlLeafProblem(value, tag); problem != nil {
				problem.Source = "yaml"
				problem.Field = fieldPath
				errs = append(errs, problem)
			}
			continue
		}
		if listTag, listKnown := listSpecs[name]; listKnown {
			if problem := yamlStringListProblem(value, listTag); problem != nil {
				problem.Source = "yaml"
				problem.Field = fieldPath
				errs = append(errs, problem)
			}
			continue
		}
		if itemSpecs, objectKnown := objectListSpecs[name]; objectKnown {
			errs = append(errs, yamlObjectListProblem(value, fieldPath, itemSpecs)...)
			continue
		}
		errs = append(errs, configErr(ConfigErrorUnknownField, "yaml", fieldPath, key.Line,
			"未定义的配置字段"))
	}
	return errs
}

// yamlStringListProblem 检查字符串列表字段：必须是列表，元素必须是期望的标量
// 类型且不能为 null；返回 nil 表示通过。
func yamlStringListProblem(node *yaml.Node, itemTag string) *ConfigError {
	if node.Kind == yaml.AliasNode {
		return configErr(ConfigErrorType, "yaml", "", node.Line, "不支持 YAML 别名或锚点")
	}
	if node.Kind != yaml.SequenceNode {
		return configErr(ConfigErrorType, "yaml", "", node.Line, "字段值必须是字符串列表")
	}
	for _, item := range node.Content {
		if problem := yamlLeafProblem(item, itemTag); problem != nil {
			return problem
		}
	}
	return nil
}

// yamlObjectListProblem 检查对象列表字段：必须是列表，每个元素必须是只包含已声明
// 字符串字段的映射，且所有声明的字段都必须出现。返回的错误逐项收集。
func yamlObjectListProblem(node *yaml.Node, fieldPath string, itemSpecs []yamlLeafSpec) ConfigErrors {
	if node.Kind == yaml.AliasNode {
		return ConfigErrors{configErr(ConfigErrorType, "yaml", fieldPath, node.Line,
			"不支持 YAML 别名或锚点")}
	}
	if node.Kind != yaml.SequenceNode {
		return ConfigErrors{configErr(ConfigErrorType, "yaml", fieldPath, node.Line,
			"字段值必须是对象列表")}
	}
	allowed := make(map[string]string, len(itemSpecs))
	for _, spec := range itemSpecs {
		allowed[spec.name] = spec.tag
	}
	var errs ConfigErrors
	for index, item := range node.Content {
		itemPath := fmt.Sprintf("%s[%d]", fieldPath, index)
		if item.Kind == yaml.AliasNode {
			errs = append(errs, configErr(ConfigErrorType, "yaml", itemPath, item.Line,
				"不支持 YAML 别名或锚点"))
			continue
		}
		if item.Kind != yaml.MappingNode {
			errs = append(errs, configErr(ConfigErrorType, "yaml", itemPath, item.Line,
				"列表元素必须是映射"))
			continue
		}
		seen := make(map[string]int, len(itemSpecs))
		for i := 0; i+1 < len(item.Content); i += 2 {
			key := item.Content[i]
			value := item.Content[i+1]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
				errs = append(errs, configErr(ConfigErrorType, "yaml", itemPath, key.Line,
					"字段名必须是字符串"))
				continue
			}
			name := key.Value
			itemFieldPath := itemPath + "." + name
			if firstLine, duplicated := seen[name]; duplicated {
				errs = append(errs, configErr(ConfigErrorDuplicateKey, "yaml", itemFieldPath, key.Line,
					fmt.Sprintf("重复字段，首次出现在第 %d 行", firstLine)))
				continue
			}
			seen[name] = key.Line
			tag, known := allowed[name]
			if !known {
				errs = append(errs, configErr(ConfigErrorUnknownField, "yaml", itemFieldPath, key.Line,
					"未定义的配置字段"))
				continue
			}
			if problem := yamlLeafProblem(value, tag); problem != nil {
				problem.Source = "yaml"
				problem.Field = itemFieldPath
				errs = append(errs, problem)
			}
		}
		for _, spec := range itemSpecs {
			if _, present := seen[spec.name]; !present {
				errs = append(errs, configErr(ConfigErrorValue, "yaml", itemPath, item.Line,
					"列表元素必须提供 "+spec.name+" 字段"))
			}
		}
	}
	return errs
}

// checkYAMLSecrets 检查 secrets 段：只允许 master_key，其值必须是仅含 env 或
// file 的映射。
func checkYAMLSecrets(section *yaml.Node) ConfigErrors {
	var errs ConfigErrors
	seen := make(map[string]int)
	for i := 0; i+1 < len(section.Content); i += 2 {
		key := section.Content[i]
		value := section.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			errs = append(errs, configErr(ConfigErrorType, "yaml", "secrets", key.Line,
				"字段名必须是字符串"))
			continue
		}
		name := key.Value
		fieldPath := "secrets." + name
		if firstLine, duplicated := seen[name]; duplicated {
			errs = append(errs, configErr(ConfigErrorDuplicateKey, "yaml", fieldPath, key.Line,
				fmt.Sprintf("重复字段，首次出现在第 %d 行", firstLine)))
			continue
		}
		seen[name] = key.Line

		if _, known := yamlSecretFields[name]; !known {
			errs = append(errs, configErr(ConfigErrorUnknownField, "yaml", fieldPath, key.Line,
				"未定义的秘密字段"))
			continue
		}
		if value.Kind == yaml.AliasNode {
			errs = append(errs, configErr(ConfigErrorType, "yaml", fieldPath, value.Line,
				"不支持 YAML 别名或锚点"))
			continue
		}
		// 秘密值不能直接写在 YAML 里；这里只接受 env/file 来源引用。
		if value.Kind != yaml.MappingNode {
			errs = append(errs, configErr(ConfigErrorValue, "yaml", fieldPath, value.Line,
				"秘密必须以 env: 或 file: 来源引用提供，不能直接写入 YAML"))
			continue
		}
		sourceSeen := make(map[string]int)
		for j := 0; j+1 < len(value.Content); j += 2 {
			sourceKey := value.Content[j]
			sourceValue := value.Content[j+1]
			if sourceKey.Kind != yaml.ScalarNode || sourceKey.Tag != "!!str" {
				errs = append(errs, configErr(ConfigErrorType, "yaml", fieldPath, sourceKey.Line,
					"秘密来源键必须是字符串"))
				continue
			}
			sourceName := sourceKey.Value
			sourcePath := fieldPath + "." + sourceName
			if firstLine, duplicated := sourceSeen[sourceName]; duplicated {
				errs = append(errs, configErr(ConfigErrorDuplicateKey, "yaml", sourcePath, sourceKey.Line,
					fmt.Sprintf("重复字段，首次出现在第 %d 行", firstLine)))
				continue
			}
			sourceSeen[sourceName] = sourceKey.Line
			if sourceName != "env" && sourceName != "file" {
				errs = append(errs, configErr(ConfigErrorUnknownField, "yaml", sourcePath, sourceKey.Line,
					"秘密来源只支持 env 或 file"))
				continue
			}
			if problem := yamlLeafProblem(sourceValue, "!!str"); problem != nil {
				problem.Source = "yaml"
				problem.Field = sourcePath
				errs = append(errs, problem)
			}
		}
	}
	return errs
}

// yamlLeafProblem 检查标量节点的类型与 null；返回 nil 表示通过。
func yamlLeafProblem(node *yaml.Node, expectedTag string) *ConfigError {
	if node.Kind == yaml.AliasNode {
		return configErr(ConfigErrorType, "yaml", "", node.Line, "不支持 YAML 别名或锚点")
	}
	if node.Kind != yaml.ScalarNode {
		return configErr(ConfigErrorType, "yaml", "", node.Line, "字段值必须是标量")
	}
	if node.Tag == "!!null" {
		return configErr(ConfigErrorValue, "yaml", "", node.Line,
			"字段值不能为 null；要恢复默认值请删除该字段")
	}
	if node.Tag != expectedTag {
		return configErr(ConfigErrorType, "yaml", "", node.Line,
			"字段类型必须是"+yamlTagDescription(expectedTag))
	}
	return nil
}

// yamlTagDescription 返回 YAML 标签的中文类型名，用于不包含值的错误说明。
func yamlTagDescription(tag string) string {
	switch tag {
	case "!!str":
		return "字符串"
	case "!!int":
		return "整数"
	case "!!bool":
		return "布尔值"
	default:
		return "指定类型"
	}
}

// convertYAML 把已通过结构检查的 YAML 结构转为内部覆盖层，并校验单层取值。
func convertYAML(doc *yamlConfig) (configOverrides, ConfigErrors) {
	var ov configOverrides
	var errs ConfigErrors

	if doc.Server != nil {
		ov.serverListenAddr = doc.Server.ListenAddr
		ov.serverExtraListen = doc.Server.ExtraListenAddrs
		ov.serverPublicBaseURL = doc.Server.PublicBaseURL
		ov.serverPathPrefix = doc.Server.PathPrefix
		ov.serverAllowedHosts = doc.Server.AllowedHosts
		ov.serverTrustedProxies = doc.Server.TrustedProxies
		ov.serverTLSProxyMode = doc.Server.TLSProxyMode
		ov.serverTLSCertFiles = doc.Server.TLSCertFiles
		ov.serverTLSKeyFiles = doc.Server.TLSKeyFiles
		ov.serverTLSCAFile = doc.Server.TLSCAFile
		ov.serverTLSPFXFile = doc.Server.TLSPFXFile
		ov.serverTLSExpiryDays = doc.Server.TLSExpiryWarningDays
		if doc.Server.TLSClientAuthMode != nil {
			mode := TLSClientAuthMode(*doc.Server.TLSClientAuthMode)
			ov.serverTLSClientAuth = &mode
		}
		ov.serverTLSClientCA = doc.Server.TLSClientCAFiles
		if doc.Server.TLSClientIdentities != nil {
			identities := make([]TLSClientIdentity, 0, len(*doc.Server.TLSClientIdentities))
			for _, raw := range *doc.Server.TLSClientIdentities {
				// 结构检查已保证 dns_name 与 service 同时存在且为字符串；这里
				// 仍做防御性判断，避免解码目标与结构检查口径变化时 panic。
				if raw.DNSName == nil || raw.Service == nil {
					continue
				}
				identities = append(identities, TLSClientIdentity{
					DNSName: *raw.DNSName,
					Service: *raw.Service,
				})
			}
			ov.serverTLSClientMaps = &identities
		}
		ov.serverShutdownTimeout = doc.Server.ShutdownTimeoutSeconds
	}
	if doc.Logging != nil {
		if doc.Logging.Level != nil {
			level := LogLevel(*doc.Logging.Level)
			ov.loggingLevel = &level
		}
		if doc.Logging.Format != nil {
			format := LogFormat(*doc.Logging.Format)
			ov.loggingFormat = &format
		}
	}
	if doc.Database != nil {
		if doc.Database.Driver != nil {
			driver := DatabaseDriver(*doc.Database.Driver)
			ov.databaseDriver = &driver
		}
		ov.databasePath = doc.Database.Path
		ov.databaseWAL = doc.Database.WAL
		ov.databaseBusyTimeout = doc.Database.BusyTimeoutMS
	}
	if doc.Registration != nil {
		ov.registrationEnabled = doc.Registration.Enabled
		ov.registrationReview = doc.Registration.RequireReview
		ov.registrationEmail = doc.Registration.RequireEmailVerification
		ov.registrationRoles = doc.Registration.DefaultRoleIDs
	}
	if doc.Passkey != nil {
		ov.passkeyEnabled = doc.Passkey.Enabled
		ov.passkeyRPID = doc.Passkey.RPID
		ov.passkeyRPName = doc.Passkey.RPDisplayName
		ov.passkeyOrigins = doc.Passkey.AllowedOrigins
		ov.passkeyUserVerify = doc.Passkey.UserVerification
	}
	if doc.AppQRLogin != nil {
		ov.appQRLoginEnabled = doc.AppQRLogin.Enabled
		ov.appQRLoginClients = doc.AppQRLogin.AllowedClientIDs
		ov.appQRLoginTTL = doc.AppQRLogin.RequestTTLSeconds
		ov.appQRLoginInterval = doc.AppQRLogin.ClaimIntervalSeconds
	}
	if doc.Secrets != nil {
		if doc.Secrets.MasterKey != nil {
			source, sourceErr := convertYAMLSecretSource("secrets.master_key", doc.Secrets.MasterKey)
			if sourceErr != nil {
				errs = append(errs, sourceErr)
			} else {
				ov.secretSource = source
			}
		}
		if doc.Secrets.TLSPFXPassword != nil {
			source, sourceErr := convertYAMLSecretSource("secrets.tls_pfx_password", doc.Secrets.TLSPFXPassword)
			if sourceErr != nil {
				errs = append(errs, sourceErr)
			} else {
				ov.secretPFXSource = source
			}
		}
	}

	errs = append(errs, validateOverrides(&ov, "yaml")...)
	return ov, errs
}

// convertYAMLSecretSource 把 YAML 中的 env/file 来源映射转为 SecretSource。
func convertYAMLSecretSource(fieldPath string, source *yamlSecretSource) (*SecretSource, *ConfigError) {
	switch {
	case source.Env != nil && source.File != nil:
		return nil, configErr(ConfigErrorConflict, "yaml", fieldPath, 0,
			"env 与 file 来源只能设置一个")
	case source.Env != nil:
		parsed, err := ParseSecretSource("env:" + *source.Env)
		if err != nil {
			return nil, configErrWrap(ConfigErrorSecretSource, "yaml", fieldPath, 0,
				"秘密环境变量来源不合法", err)
		}
		return &parsed, nil
	case source.File != nil:
		parsed, err := ParseSecretSource("file:" + *source.File)
		if err != nil {
			return nil, configErrWrap(ConfigErrorSecretSource, "yaml", fieldPath, 0,
				"秘密文件来源不合法", err)
		}
		return &parsed, nil
	default:
		return nil, configErr(ConfigErrorValue, "yaml", fieldPath, 0,
			"秘密来源必须提供 env 或 file")
	}
}

// overridesFromEnv 读取固定名称的环境变量。布尔值只接受 true/false 小写形式，
// 数字必须是十进制整数；无法解析的值会报错而不是回退默认值。
func overridesFromEnv(lookup func(string) (string, bool)) (configOverrides, ConfigErrors) {
	var ov configOverrides
	var errs ConfigErrors

	if value, ok := lookup(envServerListenAddr); ok {
		ov.serverListenAddr = Ptr(value)
	}
	if value, ok := lookup(envServerExtraListen); ok {
		addresses, err := parseEnvList(value)
		if err != nil {
			errs = append(errs, configErr(ConfigErrorValue, "env", "server.extra_listen_addrs", 0, err.Error()))
		} else {
			ov.serverExtraListen = &addresses
		}
	}
	if value, ok := lookup(envServerPublicBaseURL); ok {
		ov.serverPublicBaseURL = Ptr(value)
	}
	if value, ok := lookup(envServerPathPrefix); ok {
		ov.serverPathPrefix = Ptr(value)
	}
	if value, ok := lookup(envServerAllowedHosts); ok {
		hosts, err := parseEnvList(value)
		if err != nil {
			errs = append(errs, configErr(ConfigErrorValue, "env", "server.allowed_hosts", 0, err.Error()))
		} else {
			ov.serverAllowedHosts = &hosts
		}
	}
	if value, ok := lookup(envServerTrustedProxies); ok {
		proxies, err := parseEnvList(value)
		if err != nil {
			errs = append(errs, configErr(ConfigErrorValue, "env", "server.trusted_proxies", 0, err.Error()))
		} else {
			ov.serverTrustedProxies = &proxies
		}
	}
	if value, ok := lookup(envServerTLSProxyMode); ok {
		flag, err := parseEnvBool(value)
		if err != nil {
			errs = append(errs, configErr(ConfigErrorValue, "env", "server.tls_terminating_proxy", 0, err.Error()))
		} else {
			ov.serverTLSProxyMode = &flag
		}
	}
	if value, ok := lookup(envServerTLSCertFiles); ok {
		files, err := parseEnvList(value)
		if err != nil {
			errs = append(errs, configErr(ConfigErrorValue, "env", "server.tls_cert_files", 0, err.Error()))
		} else {
			ov.serverTLSCertFiles = &files
		}
	}
	if value, ok := lookup(envServerTLSKeyFiles); ok {
		files, err := parseEnvList(value)
		if err != nil {
			errs = append(errs, configErr(ConfigErrorValue, "env", "server.tls_key_files", 0, err.Error()))
		} else {
			ov.serverTLSKeyFiles = &files
		}
	}
	if value, ok := lookup(envServerTLSCAFile); ok {
		ov.serverTLSCAFile = Ptr(value)
	}
	if value, ok := lookup(envServerTLSPFXFile); ok {
		ov.serverTLSPFXFile = Ptr(value)
	}
	if value, ok := lookup(envServerTLSExpiryDays); ok {
		number, err := parseEnvInt(value)
		if err != nil {
			errs = append(errs, configErr(ConfigErrorValue, "env", "server.tls_expiry_warning_days", 0, err.Error()))
		} else {
			ov.serverTLSExpiryDays = &number
		}
	}
	if value, ok := lookup(envServerTLSClientAuth); ok {
		mode := TLSClientAuthMode(value)
		ov.serverTLSClientAuth = &mode
	}
	if value, ok := lookup(envServerTLSClientCA); ok {
		files, err := parseEnvList(value)
		if err != nil {
			errs = append(errs, configErr(ConfigErrorValue, "env", "server.tls_client_ca_files", 0, err.Error()))
		} else {
			ov.serverTLSClientCA = &files
		}
	}
	if value, ok := lookup(envServerTLSClientMaps); ok {
		items, err := parseEnvList(value)
		if err != nil {
			errs = append(errs, configErr(ConfigErrorValue, "env", "server.tls_client_identities", 0, err.Error()))
		} else {
			identities, parseErr := parseEnvTLSClientIdentities(items)
			if parseErr != nil {
				errs = append(errs, configErr(ConfigErrorValue, "env", "server.tls_client_identities", 0, parseErr.Error()))
			} else {
				ov.serverTLSClientMaps = &identities
			}
		}
	}
	if value, ok := lookup(envServerShutdownTimeout); ok {
		number, err := parseEnvInt(value)
		if err != nil {
			errs = append(errs, configErr(ConfigErrorValue, "env", "server.shutdown_timeout_seconds", 0, err.Error()))
		} else {
			ov.serverShutdownTimeout = &number
		}
	}
	if value, ok := lookup(envLoggingLevel); ok {
		level := LogLevel(value)
		ov.loggingLevel = &level
	}
	if value, ok := lookup(envLoggingFormat); ok {
		format := LogFormat(value)
		ov.loggingFormat = &format
	}
	if value, ok := lookup(envDatabaseDriver); ok {
		driver := DatabaseDriver(value)
		ov.databaseDriver = &driver
	}
	if value, ok := lookup(envDatabasePath); ok {
		ov.databasePath = Ptr(value)
	}
	if value, ok := lookup(envDatabaseWAL); ok {
		flag, err := parseEnvBool(value)
		if err != nil {
			errs = append(errs, configErr(ConfigErrorValue, "env", "database.wal", 0, err.Error()))
		} else {
			ov.databaseWAL = &flag
		}
	}
	if value, ok := lookup(envDatabaseBusyTimeout); ok {
		number, err := parseEnvInt(value)
		if err != nil {
			errs = append(errs, configErr(ConfigErrorValue, "env", "database.busy_timeout_ms", 0, err.Error()))
		} else {
			ov.databaseBusyTimeout = &number
		}
	}
	if value, ok := lookup(envRegistrationEnabled); ok {
		flag, err := parseEnvBool(value)
		if err != nil {
			errs = append(errs, configErr(ConfigErrorValue, "env", "registration.enabled", 0, err.Error()))
		} else {
			ov.registrationEnabled = &flag
		}
	}
	if value, ok := lookup(envRegistrationReview); ok {
		flag, err := parseEnvBool(value)
		if err != nil {
			errs = append(errs, configErr(ConfigErrorValue, "env", "registration.require_review", 0, err.Error()))
		} else {
			ov.registrationReview = &flag
		}
	}
	if value, ok := lookup(envRegistrationEmail); ok {
		flag, err := parseEnvBool(value)
		if err != nil {
			errs = append(errs, configErr(ConfigErrorValue, "env", "registration.require_email_verification", 0, err.Error()))
		} else {
			ov.registrationEmail = &flag
		}
	}
	if value, ok := lookup(envRegistrationRoles); ok {
		items, err := parseEnvList(value)
		if err != nil {
			errs = append(errs, configErr(ConfigErrorValue, "env", "registration.default_role_ids", 0, err.Error()))
		} else {
			ov.registrationRoles = &items
		}
	}
	if value, ok := lookup(envPasskeyEnabled); ok {
		flag, err := parseEnvBool(value)
		if err != nil {
			errs = append(errs, configErr(ConfigErrorValue, "env", "passkey.enabled", 0, err.Error()))
		} else {
			ov.passkeyEnabled = &flag
		}
	}
	if value, ok := lookup(envPasskeyRPID); ok {
		ov.passkeyRPID = Ptr(value)
	}
	if value, ok := lookup(envPasskeyRPName); ok {
		ov.passkeyRPName = Ptr(value)
	}
	if value, ok := lookup(envPasskeyOrigins); ok {
		items, err := parseEnvList(value)
		if err != nil {
			errs = append(errs, configErr(ConfigErrorValue, "env", "passkey.allowed_origins", 0, err.Error()))
		} else {
			ov.passkeyOrigins = &items
		}
	}
	if value, ok := lookup(envPasskeyUserVerify); ok {
		ov.passkeyUserVerify = Ptr(value)
	}
	if value, ok := lookup(envAppQRLoginEnabled); ok {
		flag, err := parseEnvBool(value)
		if err != nil {
			errs = append(errs, configErr(ConfigErrorValue, "env", "app_qr_login.enabled", 0, err.Error()))
		} else {
			ov.appQRLoginEnabled = &flag
		}
	}
	if value, ok := lookup(envAppQRLoginClients); ok {
		items, err := parseEnvList(value)
		if err != nil {
			errs = append(errs, configErr(ConfigErrorValue, "env", "app_qr_login.allowed_client_ids", 0, err.Error()))
		} else {
			ov.appQRLoginClients = &items
		}
	}
	if value, ok := lookup(envAppQRLoginTTL); ok {
		number, err := parseEnvInt(value)
		if err != nil {
			errs = append(errs, configErr(ConfigErrorValue, "env", "app_qr_login.request_ttl_seconds", 0, err.Error()))
		} else {
			ov.appQRLoginTTL = &number
		}
	}
	if value, ok := lookup(envAppQRLoginInterval); ok {
		number, err := parseEnvInt(value)
		if err != nil {
			errs = append(errs, configErr(ConfigErrorValue, "env", "app_qr_login.claim_interval_seconds", 0, err.Error()))
		} else {
			ov.appQRLoginInterval = &number
		}
	}
	if value, ok := lookup(envSecretsMasterKey); ok {
		if value == "" {
			errs = append(errs, configErr(ConfigErrorValue, "env", "secrets.master_key", 0,
				"环境变量提供的秘密不能为空"))
		} else if len(value) > MaxSecretBytes {
			errs = append(errs, configErr(ConfigErrorRange, "env", "secrets.master_key", 0,
				fmt.Sprintf("环境变量提供的秘密不能超过 %d 字节", MaxSecretBytes)))
		} else {
			secret := NewSecretString(value)
			ov.secretValue = &secret
		}
	}
	if value, ok := lookup(envSecretsTLSPFXPassword); ok {
		if value == "" {
			errs = append(errs, configErr(ConfigErrorValue, "env", "secrets.tls_pfx_password", 0,
				"环境变量提供的秘密不能为空"))
		} else if len(value) > MaxSecretBytes {
			errs = append(errs, configErr(ConfigErrorRange, "env", "secrets.tls_pfx_password", 0,
				fmt.Sprintf("环境变量提供的秘密不能超过 %d 字节", MaxSecretBytes)))
		} else {
			secret := NewSecretString(value)
			ov.secretPFXValue = &secret
		}
	}

	errs = append(errs, validateOverrides(&ov, "env")...)
	return ov, errs
}

// overridesFromOptions 把宿主显式选项转为覆盖层并校验。
func overridesFromOptions(options *Overrides) (configOverrides, ConfigErrors) {
	ov := configOverrides{
		serverListenAddr:      options.Server.ListenAddr,
		serverExtraListen:     options.Server.ExtraListenAddrs,
		serverPublicBaseURL:   options.Server.PublicBaseURL,
		serverPathPrefix:      options.Server.PathPrefix,
		serverAllowedHosts:    options.Server.AllowedHosts,
		serverTrustedProxies:  options.Server.TrustedProxies,
		serverTLSProxyMode:    options.Server.TLSProxyMode,
		serverTLSCertFiles:    options.Server.TLSCertFiles,
		serverTLSKeyFiles:     options.Server.TLSKeyFiles,
		serverTLSCAFile:       options.Server.TLSCAFile,
		serverTLSPFXFile:      options.Server.TLSPFXFile,
		serverTLSExpiryDays:   options.Server.TLSExpiryWarningDays,
		serverTLSClientAuth:   options.Server.TLSClientAuthMode,
		serverTLSClientCA:     options.Server.TLSClientCAFiles,
		serverTLSClientMaps:   options.Server.TLSClientIdentities,
		serverShutdownTimeout: options.Server.ShutdownTimeoutSeconds,
		secretPFXValue:        options.Secrets.TLSPFXPassword,
		loggingLevel:          options.Logging.Level,
		loggingFormat:         options.Logging.Format,
		databaseDriver:        options.Database.Driver,
		databasePath:          options.Database.Path,
		databaseWAL:           options.Database.WAL,
		databaseBusyTimeout:   options.Database.BusyTimeoutMS,
		registrationEnabled:   options.Registration.Enabled,
		registrationReview:    options.Registration.RequireReview,
		registrationEmail:     options.Registration.RequireEmailVerification,
		registrationRoles:     options.Registration.DefaultRoleIDs,
		passkeyEnabled:        options.Passkey.Enabled,
		passkeyRPID:           options.Passkey.RPID,
		passkeyRPName:         options.Passkey.RPDisplayName,
		passkeyOrigins:        options.Passkey.AllowedOrigins,
		passkeyUserVerify:     options.Passkey.UserVerification,
		appQRLoginEnabled:     options.AppQRLogin.Enabled,
		appQRLoginClients:     options.AppQRLogin.AllowedClientIDs,
		appQRLoginTTL:         options.AppQRLogin.RequestTTLSeconds,
		appQRLoginInterval:    options.AppQRLogin.ClaimIntervalSeconds,
		secretValue:           options.Secrets.MasterKey,
	}
	errs := validateOverrides(&ov, "options")
	return ov, errs
}

// parseEnvList 解析环境变量中的逗号分隔列表。空字符串表示显式空列表；条目会
// 去掉首尾空白，空条目报错而不是静默跳过。
func parseEnvList(value string) ([]string, error) {
	if value == "" {
		return []string{}, nil
	}
	parts := strings.Split(value, ",")
	items := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			return nil, fmt.Errorf("列表值不能包含空条目")
		}
		items = append(items, trimmed)
	}
	return items, nil
}

// parseEnvTLSClientIdentities 解析客户端证书身份映射环境变量：逗号分隔的
// “dns-name=service-identity” 条目；每项必须有且只有一个等号，两侧都不能为空。
// DNS 名称与服务身份的完整校验由 validateOverrides 统一完成。
func parseEnvTLSClientIdentities(items []string) ([]TLSClientIdentity, error) {
	identities := make([]TLSClientIdentity, 0, len(items))
	for index, item := range items {
		if strings.Count(item, "=") != 1 {
			return nil, fmt.Errorf("第 %d 项必须使用 dns-name=service-identity 形式", index+1)
		}
		parts := strings.SplitN(item, "=", 2)
		dnsName := strings.TrimSpace(parts[0])
		service := strings.TrimSpace(parts[1])
		if dnsName == "" || service == "" {
			return nil, fmt.Errorf("第 %d 项必须同时提供 DNS 名称与服务身份", index+1)
		}
		identities = append(identities, TLSClientIdentity{DNSName: dnsName, Service: service})
	}
	return identities, nil
}

// parseEnvBool 只接受小写 true/false，避免 1/0、yes/no 等平台差异。
func parseEnvBool(value string) (bool, error) {
	switch value {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("布尔值只接受小写 true 或 false")
	}
}

// parseEnvInt 解析十进制整数，不接受空值和带空白的文本。
func parseEnvInt(value string) (int, error) {
	if value == "" {
		return 0, fmt.Errorf("整数值不能为空")
	}
	number, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("整数值必须是十进制数字")
	}
	return number, nil
}

// validateOverrides 校验单层显式设置的字段值。跨字段组合规则在合并后由
// validateMerged 检查，因为组合可能来自不同层。
func validateOverrides(ov *configOverrides, source string) ConfigErrors {
	var errs ConfigErrors
	add := func(kind ConfigErrorKind, field, detail string) {
		errs = append(errs, configErr(kind, source, field, 0, detail))
	}

	if ov.serverListenAddr != nil {
		if problem := listenAddrProblem(*ov.serverListenAddr); problem != "" {
			add(ConfigErrorValue, "server.listen_addr", problem)
		}
	}
	if ov.serverExtraListen != nil {
		if problem := extraListenAddrsProblem(*ov.serverExtraListen); problem != "" {
			add(ConfigErrorValue, "server.extra_listen_addrs", problem)
		}
	}
	if ov.serverPublicBaseURL != nil {
		if problem := publicBaseURLProblem(*ov.serverPublicBaseURL); problem != "" {
			add(ConfigErrorValue, "server.public_base_url", problem)
		}
	}
	if ov.serverPathPrefix != nil {
		if problem := pathPrefixProblem(*ov.serverPathPrefix); problem != "" {
			add(ConfigErrorValue, "server.path_prefix", problem)
		}
	}
	if ov.serverAllowedHosts != nil {
		if problem := allowedHostsProblem(*ov.serverAllowedHosts); problem != "" {
			add(ConfigErrorValue, "server.allowed_hosts", problem)
		}
	}
	if ov.serverTrustedProxies != nil {
		if problem := trustedProxiesProblem(*ov.serverTrustedProxies); problem != "" {
			add(ConfigErrorValue, "server.trusted_proxies", problem)
		}
	}
	if ov.serverTLSCertFiles != nil {
		if problem := tlsFileListProblem("证书文件", *ov.serverTLSCertFiles, MaxServerTLSCertificates); problem != "" {
			add(ConfigErrorValue, "server.tls_cert_files", problem)
		}
	}
	if ov.serverTLSKeyFiles != nil {
		if problem := tlsFileListProblem("私钥文件", *ov.serverTLSKeyFiles, MaxServerTLSCertificates); problem != "" {
			add(ConfigErrorValue, "server.tls_key_files", problem)
		}
	}
	if ov.serverTLSCAFile != nil && *ov.serverTLSCAFile != "" {
		if problem := tlsPathProblem("CA 文件", *ov.serverTLSCAFile); problem != "" {
			add(ConfigErrorValue, "server.tls_ca_file", problem)
		}
	}
	if ov.serverTLSPFXFile != nil && *ov.serverTLSPFXFile != "" {
		if problem := tlsPathProblem("PFX/P12 文件", *ov.serverTLSPFXFile); problem != "" {
			add(ConfigErrorValue, "server.tls_pfx_file", problem)
		}
	}
	if ov.serverTLSExpiryDays != nil && (*ov.serverTLSExpiryDays < 0 || *ov.serverTLSExpiryDays > 365) {
		add(ConfigErrorRange, "server.tls_expiry_warning_days",
			"证书到期告警天数必须是 0～365 的整数；0 表示默认 30")
	}
	if ov.serverTLSClientAuth != nil && !ov.serverTLSClientAuth.Valid() {
		add(ConfigErrorValue, "server.tls_client_auth",
			"客户端证书认证模式必须是 disabled、required 或 optional")
	}
	if ov.serverTLSClientCA != nil {
		if problem := tlsFileListProblem("客户端信任 CA 文件", *ov.serverTLSClientCA, MaxServerTLSClientCAFiles); problem != "" {
			add(ConfigErrorValue, "server.tls_client_ca_files", problem)
		}
	}
	if ov.serverTLSClientMaps != nil {
		if problem := tlsClientIdentitiesProblem(*ov.serverTLSClientMaps); problem != "" {
			add(ConfigErrorValue, "server.tls_client_identities", problem)
		}
	}
	if ov.serverTLSProxyMode != nil && *ov.serverTLSProxyMode && ov.serverTrustedProxies != nil &&
		len(*ov.serverTrustedProxies) == 0 {
		// 单层内即可判定的矛盾提前报告；跨层组合在 validateMerged 再检查。
		add(ConfigErrorConflict, "server.tls_terminating_proxy", "启用 TLS 终止代理模式必须配置可信代理")
	}
	if ov.serverShutdownTimeout != nil && (*ov.serverShutdownTimeout < 1 || *ov.serverShutdownTimeout > 300) {
		add(ConfigErrorRange, "server.shutdown_timeout_seconds", "安全关闭超时必须是 1～300 秒")
	}
	if ov.loggingLevel != nil && !ov.loggingLevel.Valid() {
		add(ConfigErrorValue, "logging.level", "日志级别必须是 debug、info、warn 或 error")
	}
	if ov.loggingFormat != nil && !ov.loggingFormat.Valid() {
		add(ConfigErrorValue, "logging.format", "日志格式必须是 text 或 json")
	}
	if ov.databaseDriver != nil && !ov.databaseDriver.Valid() {
		add(ConfigErrorValue, "database.driver", "当前版本只支持 sqlite 驱动，其他驱动尚未实现")
	}
	if ov.databasePath != nil && *ov.databasePath == "" {
		add(ConfigErrorValue, "database.path", "SQLite 数据库路径不能为空")
	}
	if ov.databaseBusyTimeout != nil && (*ov.databaseBusyTimeout < 1 || *ov.databaseBusyTimeout > 600000) {
		add(ConfigErrorRange, "database.busy_timeout_ms", "锁等待超时必须是 1～600000 毫秒")
	}
	if ov.registrationRoles != nil {
		if problem := registrationDefaultRolesProblem(*ov.registrationRoles); problem != "" {
			add(ConfigErrorValue, "registration.default_role_ids", problem)
		}
	}
	if ov.passkeyOrigins != nil && len(*ov.passkeyOrigins) > MaxPasskeyOrigins {
		add(ConfigErrorRange, "passkey.allowed_origins",
			fmt.Sprintf("允许来源最多 %d 个", MaxPasskeyOrigins))
	}
	if ov.passkeyUserVerify != nil && *ov.passkeyUserVerify != "" &&
		!passkey.UserVerification(*ov.passkeyUserVerify).Valid() {
		add(ConfigErrorValue, "passkey.user_verification",
			"用户验证策略必须是 required、preferred 或 discouraged")
	}
	if ov.appQRLoginTTL != nil && (*ov.appQRLoginTTL < 30 || *ov.appQRLoginTTL > 300) {
		add(ConfigErrorRange, "app_qr_login.request_ttl_seconds", "扫码登录请求有效期必须是 30～300 秒")
	}
	if ov.appQRLoginInterval != nil && (*ov.appQRLoginInterval < 1 || *ov.appQRLoginInterval > 5) {
		add(ConfigErrorRange, "app_qr_login.claim_interval_seconds", "扫码登录查询间隔必须是 1～5 秒")
	}
	if ov.appQRLoginClients != nil {
		if len(*ov.appQRLoginClients) > MaxAppQRLoginClients {
			add(ConfigErrorRange, "app_qr_login.allowed_client_ids",
				fmt.Sprintf("扫码登录应用白名单最多 %d 个", MaxAppQRLoginClients))
		}
		for _, clientID := range *ov.appQRLoginClients {
			if !app.ValidApplicationID(clientID) {
				add(ConfigErrorValue, "app_qr_login.allowed_client_ids",
					"扫码登录应用白名单包含非法应用 ID")
				break
			}
		}
	}
	if ov.secretValue != nil {
		if !ov.secretValue.IsSet() {
			add(ConfigErrorValue, "secrets.master_key", "秘密不能为空")
		} else if ov.secretValue.Len() == 0 {
			add(ConfigErrorValue, "secrets.master_key", "秘密不能为空")
		} else if ov.secretValue.Len() > MaxSecretBytes {
			add(ConfigErrorRange, "secrets.master_key",
				fmt.Sprintf("秘密不能超过 %d 字节", MaxSecretBytes))
		}
	}
	if ov.secretPFXValue != nil {
		if !ov.secretPFXValue.IsSet() || ov.secretPFXValue.Len() == 0 {
			add(ConfigErrorValue, "secrets.tls_pfx_password", "PFX 密码不能为空")
		} else if ov.secretPFXValue.Len() > MaxSecretBytes {
			add(ConfigErrorRange, "secrets.tls_pfx_password",
				fmt.Sprintf("PFX 密码不能超过 %d 字节", MaxSecretBytes))
		}
	}
	return errs
}
