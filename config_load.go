package login

import (
	"fmt"
	"os"
	"strconv"

	"go.yaml.in/yaml/v3"
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
	Server   ServerOverrides
	Logging  LoggingOverrides
	Database DatabaseOverrides
	Secrets  SecretsOverrides
}

// ServerOverrides 是 ServerConfig 的显式覆盖项。
type ServerOverrides struct {
	ListenAddr             *string
	PublicBaseURL          *string
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
	MasterKey *Secret
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

	// 秘密单独合并：越靠后的层优先，直接值会覆盖 YAML 中的来源引用。
	var secretSource *SecretSource
	var secretValue *Secret
	for i := range layers {
		if layers[i].secretSource != nil {
			secretSource = layers[i].secretSource
			secretValue = nil
		}
		if layers[i].secretValue != nil {
			secretValue = layers[i].secretValue
			secretSource = nil
		}
	}
	if secretValue != nil {
		cfg.Secrets.MasterKey = *secretValue
	} else if secretSource != nil {
		secret, err := secretSource.load(lookup)
		if err != nil {
			return Config{}, ConfigErrors{configErrWrap(ConfigErrorSecretSource, "yaml", "secrets.master_key", 0,
				"无法从受保护来源读取主密钥", err)}
		}
		cfg.Secrets.MasterKey = secret
	}

	if finalErrs := validateMerged(cfg); len(finalErrs) > 0 {
		return Config{}, finalErrs
	}
	return cfg, nil
}

// configOverrides 是单层配置的内部表示；指针字段表示“该层显式设置了此字段”。
type configOverrides struct {
	serverListenAddr      *string
	serverPublicBaseURL   *string
	serverShutdownTimeout *int
	loggingLevel          *LogLevel
	loggingFormat         *LogFormat
	databaseDriver        *DatabaseDriver
	databasePath          *string
	databaseWAL           *bool
	databaseBusyTimeout   *int
	secretSource          *SecretSource
	secretValue           *Secret
}

// apply 把本层显式设置的值覆盖到配置上；未设置的字段保持原值。
func (ov *configOverrides) apply(cfg *Config) {
	if ov.serverListenAddr != nil {
		cfg.Server.ListenAddr = *ov.serverListenAddr
	}
	if ov.serverPublicBaseURL != nil {
		cfg.Server.PublicBaseURL = *ov.serverPublicBaseURL
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
	Server   *yamlServer   `yaml:"server"`
	Logging  *yamlLogging  `yaml:"logging"`
	Database *yamlDatabase `yaml:"database"`
	Secrets  *yamlSecrets  `yaml:"secrets"`
}

type yamlServer struct {
	ListenAddr             *string `yaml:"listen_addr"`
	PublicBaseURL          *string `yaml:"public_base_url"`
	ShutdownTimeoutSeconds *int    `yaml:"shutdown_timeout_seconds"`
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
	MasterKey *yamlSecretSource `yaml:"master_key"`
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
	yamlRootKeys = []string{"server", "logging", "database", "secrets"}

	yamlSectionFields = map[string][]yamlLeafSpec{
		"server": {
			{name: "listen_addr", tag: "!!str"},
			{name: "public_base_url", tag: "!!str"},
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
		errs = append(errs, checkYAMLMappedSection(value, name, specs)...)
	}
	return errs
}

// checkYAMLMappedSection 检查普通配置段的字段名、重复键与标量类型。
func checkYAMLMappedSection(section *yaml.Node, prefix string, specs []yamlLeafSpec) ConfigErrors {
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
		if !known {
			errs = append(errs, configErr(ConfigErrorUnknownField, "yaml", fieldPath, key.Line,
				"未定义的配置字段"))
			continue
		}
		if problem := yamlLeafProblem(value, tag); problem != nil {
			problem.Source = "yaml"
			problem.Field = fieldPath
			errs = append(errs, problem)
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

		if name != "master_key" {
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
		ov.serverPublicBaseURL = doc.Server.PublicBaseURL
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
	if doc.Secrets != nil && doc.Secrets.MasterKey != nil {
		masterKey := doc.Secrets.MasterKey
		switch {
		case masterKey.Env != nil && masterKey.File != nil:
			errs = append(errs, configErr(ConfigErrorConflict, "yaml", "secrets.master_key", 0,
				"env 与 file 来源只能设置一个"))
		case masterKey.Env != nil:
			source, err := ParseSecretSource("env:" + *masterKey.Env)
			if err != nil {
				errs = append(errs, configErrWrap(ConfigErrorSecretSource, "yaml", "secrets.master_key", 0,
					"秘密环境变量来源不合法", err))
			} else {
				ov.secretSource = &source
			}
		case masterKey.File != nil:
			source, err := ParseSecretSource("file:" + *masterKey.File)
			if err != nil {
				errs = append(errs, configErrWrap(ConfigErrorSecretSource, "yaml", "secrets.master_key", 0,
					"秘密文件来源不合法", err))
			} else {
				ov.secretSource = &source
			}
		default:
			errs = append(errs, configErr(ConfigErrorValue, "yaml", "secrets.master_key", 0,
				"秘密来源必须提供 env 或 file"))
		}
	}

	errs = append(errs, validateOverrides(&ov, "yaml")...)
	return ov, errs
}

// overridesFromEnv 读取固定名称的环境变量。布尔值只接受 true/false 小写形式，
// 数字必须是十进制整数；无法解析的值会报错而不是回退默认值。
func overridesFromEnv(lookup func(string) (string, bool)) (configOverrides, ConfigErrors) {
	var ov configOverrides
	var errs ConfigErrors

	if value, ok := lookup(envServerListenAddr); ok {
		ov.serverListenAddr = Ptr(value)
	}
	if value, ok := lookup(envServerPublicBaseURL); ok {
		ov.serverPublicBaseURL = Ptr(value)
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

	errs = append(errs, validateOverrides(&ov, "env")...)
	return ov, errs
}

// overridesFromOptions 把宿主显式选项转为覆盖层并校验。
func overridesFromOptions(options *Overrides) (configOverrides, ConfigErrors) {
	ov := configOverrides{
		serverListenAddr:      options.Server.ListenAddr,
		serverPublicBaseURL:   options.Server.PublicBaseURL,
		serverShutdownTimeout: options.Server.ShutdownTimeoutSeconds,
		loggingLevel:          options.Logging.Level,
		loggingFormat:         options.Logging.Format,
		databaseDriver:        options.Database.Driver,
		databasePath:          options.Database.Path,
		databaseWAL:           options.Database.WAL,
		databaseBusyTimeout:   options.Database.BusyTimeoutMS,
		secretValue:           options.Secrets.MasterKey,
	}
	errs := validateOverrides(&ov, "options")
	return ov, errs
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
	if ov.serverPublicBaseURL != nil {
		if problem := publicBaseURLProblem(*ov.serverPublicBaseURL); problem != "" {
			add(ConfigErrorValue, "server.public_base_url", problem)
		}
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
	return errs
}
