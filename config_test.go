package login

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// envLookup 构造可控的环境变量读取函数，避免测试依赖真实进程环境。
func envLookup(env map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		value, ok := env[name]
		return value, ok
	}
}

func yamlBytes(text string) []byte {
	return []byte(text)
}

func mustLoad(t *testing.T, opts LoadOptions) Config {
	t.Helper()
	cfg, err := Load(opts)
	if err != nil {
		t.Fatalf("Load() 返回错误：%v", err)
	}
	return cfg
}

func loadErrors(t *testing.T, opts LoadOptions) ConfigErrors {
	t.Helper()
	cfg, err := Load(opts)
	if err == nil {
		t.Fatalf("期望配置错误，实际加载成功：%+v", cfg)
	}
	var errs ConfigErrors
	if !errors.As(err, &errs) {
		t.Fatalf("错误不是 ConfigErrors：%T：%v", err, err)
	}
	return errs
}

func findConfigError(errs ConfigErrors, kind ConfigErrorKind, field string) *ConfigError {
	for _, candidate := range errs {
		if candidate.Kind == kind && candidate.Field == field {
			return candidate
		}
	}
	return nil
}

func requireConfigError(t *testing.T, errs ConfigErrors, kind ConfigErrorKind, field string) *ConfigError {
	t.Helper()
	found := findConfigError(errs, kind, field)
	if found == nil {
		t.Fatalf("缺少配置错误 kind=%s field=%s；实际错误：%v", kind, field, errs)
	}
	return found
}

func TestDefaultConfig(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("默认配置应当有效：%v", err)
	}
	if cfg.Server.ListenAddr != "127.0.0.1:8080" {
		t.Errorf("默认监听地址 = %q", cfg.Server.ListenAddr)
	}
	if cfg.Server.PublicBaseURL != "" {
		t.Errorf("默认公开地址应为空，实际 %q", cfg.Server.PublicBaseURL)
	}
	if cfg.Server.ShutdownTimeoutSeconds != 10 {
		t.Errorf("默认关闭超时 = %d", cfg.Server.ShutdownTimeoutSeconds)
	}
	if cfg.Logging.Level != LogLevelInfo || cfg.Logging.Format != LogFormatText {
		t.Errorf("默认日志配置 = %+v", cfg.Logging)
	}
	if cfg.Database.Driver != DatabaseDriverSQLite || cfg.Database.Path != "database/login.db" {
		t.Errorf("默认数据库配置 = %+v", cfg.Database)
	}
	if !cfg.Database.WAL || cfg.Database.BusyTimeoutMS != 5000 {
		t.Errorf("默认 SQLite 参数 = %+v", cfg.Database)
	}
	if cfg.Secrets.MasterKey.IsSet() {
		t.Error("默认配置不应设置秘密")
	}

	diagnostic := cfg.Diagnostic()
	for _, field := range Fields() {
		if !strings.Contains(diagnostic, field.Field+" = ") {
			t.Errorf("脱敏诊断缺少字段 %s：\n%s", field.Field, diagnostic)
		}
	}
	if !strings.Contains(diagnostic, "secrets.master_key = [UNSET]") {
		t.Errorf("脱敏诊断未标记未设置秘密：\n%s", diagnostic)
	}
}

func TestLoadPrecedence(t *testing.T) {
	yamlConfig := `
server:
  listen_addr: "127.0.0.1:8081"
  shutdown_timeout_seconds: 20
logging:
  level: warn
database:
  busy_timeout_ms: 6000
`
	environment := map[string]string{
		envServerListenAddr:      "127.0.0.1:8082",
		envServerShutdownTimeout: "30",
		envDatabaseBusyTimeout:   "7000",
	}
	cfg := mustLoad(t, LoadOptions{
		YAML:      yamlBytes(yamlConfig),
		LookupEnv: envLookup(environment),
		Overrides: &Overrides{
			Server:   ServerOverrides{ListenAddr: Ptr("127.0.0.1:8083")},
			Database: DatabaseOverrides{WAL: Ptr(false)},
		},
	})

	if cfg.Server.ListenAddr != "127.0.0.1:8083" {
		t.Errorf("显式代码选项应最高优先级，listen_addr = %q", cfg.Server.ListenAddr)
	}
	if cfg.Server.ShutdownTimeoutSeconds != 30 {
		t.Errorf("环境变量应覆盖 YAML，shutdown = %d", cfg.Server.ShutdownTimeoutSeconds)
	}
	if cfg.Database.BusyTimeoutMS != 7000 {
		t.Errorf("环境变量应覆盖 YAML，busy_timeout_ms = %d", cfg.Database.BusyTimeoutMS)
	}
	if cfg.Logging.Level != LogLevelWarn {
		t.Errorf("YAML 应覆盖默认值，level = %q", cfg.Logging.Level)
	}
	if cfg.Database.WAL {
		t.Error("显式 false 应覆盖环境变量与默认值")
	}
	if cfg.Logging.Format != LogFormatText || cfg.Database.Driver != DatabaseDriverSQLite {
		t.Errorf("未设置字段应保留默认值：%+v", cfg)
	}
}

func TestExplicitFalseAndZero(t *testing.T) {
	t.Run("YAML 显式 false", func(t *testing.T) {
		cfg := mustLoad(t, LoadOptions{YAML: yamlBytes("database:\n  wal: false\n")})
		if cfg.Database.WAL {
			t.Error("显式 false 被默认值覆盖")
		}
		if cfg.Server.ShutdownTimeoutSeconds != 10 {
			t.Error("未设置字段应保留默认值")
		}
	})

	t.Run("环境变量显式 false", func(t *testing.T) {
		cfg := mustLoad(t, LoadOptions{LookupEnv: envLookup(map[string]string{envDatabaseWAL: "false"})})
		if cfg.Database.WAL {
			t.Error("环境变量显式 false 未生效")
		}
	})

	t.Run("显式代码选项 false 覆盖环境变量 true", func(t *testing.T) {
		cfg := mustLoad(t, LoadOptions{
			LookupEnv: envLookup(map[string]string{envDatabaseWAL: "true"}),
			Overrides: &Overrides{Database: DatabaseOverrides{WAL: Ptr(false)}},
		})
		if cfg.Database.WAL {
			t.Error("显式代码选项 false 未覆盖环境变量")
		}
	})

	t.Run("显式 0 不退回默认值", func(t *testing.T) {
		cases := []struct {
			name   string
			opts   LoadOptions
			source string
			field  string
		}{
			{
				name:   "YAML 关闭超时 0",
				opts:   LoadOptions{YAML: yamlBytes("server:\n  shutdown_timeout_seconds: 0\n")},
				source: "yaml",
				field:  "server.shutdown_timeout_seconds",
			},
			{
				name:   "环境变量锁等待 0",
				opts:   LoadOptions{LookupEnv: envLookup(map[string]string{envDatabaseBusyTimeout: "0"})},
				source: "env",
				field:  "database.busy_timeout_ms",
			},
			{
				name:   "显式选项锁等待 0",
				opts:   LoadOptions{Overrides: &Overrides{Database: DatabaseOverrides{BusyTimeoutMS: Ptr(0)}}},
				source: "options",
				field:  "database.busy_timeout_ms",
			},
		}
		for _, test := range cases {
			t.Run(test.name, func(t *testing.T) {
				errs := loadErrors(t, test.opts)
				requireConfigError(t, errs, ConfigErrorRange, test.field)
			})
		}
	})
}

func TestEmptyAndNullValues(t *testing.T) {
	t.Run("空字符串字段", func(t *testing.T) {
		cases := []struct {
			name  string
			opts  LoadOptions
			field string
		}{
			{
				name:  "YAML 监听地址为空",
				opts:  LoadOptions{YAML: yamlBytes("server:\n  listen_addr: \"\"\n")},
				field: "server.listen_addr",
			},
			{
				name:  "YAML 数据库路径为空",
				opts:  LoadOptions{YAML: yamlBytes("database:\n  path: \"\"\n")},
				field: "database.path",
			},
			{
				name:  "环境变量监听地址为空",
				opts:  LoadOptions{LookupEnv: envLookup(map[string]string{envServerListenAddr: ""})},
				field: "server.listen_addr",
			},
		}
		for _, test := range cases {
			t.Run(test.name, func(t *testing.T) {
				errs := loadErrors(t, test.opts)
				requireConfigError(t, errs, ConfigErrorValue, test.field)
			})
		}
	})

	t.Run("显式空公开地址允许", func(t *testing.T) {
		cfg := mustLoad(t, LoadOptions{YAML: yamlBytes("server:\n  public_base_url: \"\"\n")})
		if cfg.Server.PublicBaseURL != "" {
			t.Errorf("公开地址 = %q", cfg.Server.PublicBaseURL)
		}
	})

	t.Run("null 被拒绝", func(t *testing.T) {
		cases := []struct {
			name  string
			yaml  string
			field string
		}{
			{"字段 null", "database:\n  path:\n", "database.path"},
			{"配置段 null", "logging:\n", "logging"},
			{"秘密来源 null", "secrets:\n  master_key:\n", "secrets.master_key"},
		}
		for _, test := range cases {
			t.Run(test.name, func(t *testing.T) {
				errs := loadErrors(t, LoadOptions{YAML: yamlBytes(test.yaml)})
				if findConfigError(errs, ConfigErrorValue, test.field) == nil &&
					findConfigError(errs, ConfigErrorType, test.field) == nil {
					t.Fatalf("缺少字段 %s 的错误：%v", test.field, errs)
				}
			})
		}
	})
}

func TestUnknownFields(t *testing.T) {
	cases := []struct {
		name  string
		yaml  string
		field string
	}{
		{"未知顶层段", "cache:\n  size: 1\n", "cache"},
		{"未知字段", "server:\n  timeout: 5\n", "server.timeout"},
		{"未知秘密字段", "secrets:\n  token:\n    env: TEST_TOKEN\n", "secrets.token"},
		{"未知秘密来源", "secrets:\n  master_key:\n    vault: TEST\n", "secrets.master_key.vault"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			cfg, err := Load(LoadOptions{YAML: yamlBytes(test.yaml)})
			if err == nil {
				t.Fatalf("未知字段应导致失败：%+v", cfg)
			}
			if !reflect.DeepEqual(cfg, Config{}) {
				t.Errorf("失败时不应返回部分配置：%+v", cfg)
			}
			var errs ConfigErrors
			if !errors.As(err, &errs) {
				t.Fatalf("错误不是 ConfigErrors：%v", err)
			}
			requireConfigError(t, errs, ConfigErrorUnknownField, test.field)
		})
	}
}

func TestDuplicateKeys(t *testing.T) {
	cases := []struct {
		name  string
		yaml  string
		field string
	}{
		{
			name:  "重复顶层段",
			yaml:  "server:\n  listen_addr: \"127.0.0.1:8080\"\nserver:\n  listen_addr: \"127.0.0.1:8081\"\n",
			field: "server",
		},
		{
			name:  "重复字段",
			yaml:  "server:\n  listen_addr: \"127.0.0.1:8080\"\n  listen_addr: \"127.0.0.1:8081\"\n",
			field: "server.listen_addr",
		},
		{
			name:  "重复秘密来源",
			yaml:  "secrets:\n  master_key:\n    env: A\n    env: B\n",
			field: "secrets.master_key.env",
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			errs := loadErrors(t, LoadOptions{YAML: yamlBytes(test.yaml)})
			found := requireConfigError(t, errs, ConfigErrorDuplicateKey, test.field)
			if found.Line <= 0 {
				t.Errorf("重复键错误应包含行号：%v", found)
			}
		})
	}
}

func TestYAMLTypeErrors(t *testing.T) {
	cases := []struct {
		name  string
		yaml  string
		field string
	}{
		{"监听地址写成整数", "server:\n  listen_addr: 8080\n", "server.listen_addr"},
		{"布尔字段写成字符串", "database:\n  wal: \"true\"\n", "database.wal"},
		{"整数写成浮点数", "server:\n  shutdown_timeout_seconds: 10.5\n", "server.shutdown_timeout_seconds"},
		{"整数写成字符串", "database:\n  busy_timeout_ms: \"5000\"\n", "database.busy_timeout_ms"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			errs := loadErrors(t, LoadOptions{YAML: yamlBytes(test.yaml)})
			found := requireConfigError(t, errs, ConfigErrorType, test.field)
			// 类型错误只描述期望类型，不回显字段值。
			if strings.Contains(found.Error(), "8080") || strings.Contains(found.Error(), "10.5") {
				t.Errorf("类型错误泄露了字段值：%v", found)
			}
		})
	}
}

func TestRangeAndEnumErrors(t *testing.T) {
	cases := []struct {
		name  string
		yaml  string
		kind  ConfigErrorKind
		field string
	}{
		{"锁等待 0", "database:\n  busy_timeout_ms: 0\n", ConfigErrorRange, "database.busy_timeout_ms"},
		{"锁等待过大", "database:\n  busy_timeout_ms: 600001\n", ConfigErrorRange, "database.busy_timeout_ms"},
		{"关闭超时 0", "server:\n  shutdown_timeout_seconds: 0\n", ConfigErrorRange, "server.shutdown_timeout_seconds"},
		{"关闭超时过大", "server:\n  shutdown_timeout_seconds: 301\n", ConfigErrorRange, "server.shutdown_timeout_seconds"},
		{"端口 0", "server:\n  listen_addr: \"127.0.0.1:0\"\n", ConfigErrorValue, "server.listen_addr"},
		{"端口越界", "server:\n  listen_addr: \"127.0.0.1:65536\"\n", ConfigErrorValue, "server.listen_addr"},
		{"监听地址缺端口", "server:\n  listen_addr: \"127.0.0.1\"\n", ConfigErrorValue, "server.listen_addr"},
		{"未知日志级别", "logging:\n  level: verbose\n", ConfigErrorValue, "logging.level"},
		{"未知日志格式", "logging:\n  format: xml\n", ConfigErrorValue, "logging.format"},
		{"未实现驱动", "database:\n  driver: mysql\n", ConfigErrorValue, "database.driver"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			errs := loadErrors(t, LoadOptions{YAML: yamlBytes(test.yaml)})
			requireConfigError(t, errs, test.kind, test.field)
		})
	}

	t.Run("环境变量非法布尔值", func(t *testing.T) {
		for _, value := range []string{"TRUE", "1", "yes", ""} {
			errs := loadErrors(t, LoadOptions{LookupEnv: envLookup(map[string]string{envDatabaseWAL: value})})
			requireConfigError(t, errs, ConfigErrorValue, "database.wal")
		}
	})

	t.Run("环境变量非法整数", func(t *testing.T) {
		for _, value := range []string{"abc", "1.5", ""} {
			errs := loadErrors(t, LoadOptions{LookupEnv: envLookup(map[string]string{envDatabaseBusyTimeout: value})})
			requireConfigError(t, errs, ConfigErrorValue, "database.busy_timeout_ms")
		}
	})
}

func TestPublicBaseURLValidation(t *testing.T) {
	valid := []string{
		"",
		"https://login.example.com",
		"https://login.example.com/prefix",
		"http://127.0.0.1:8080",
	}
	for _, value := range valid {
		t.Run("有效 "+value, func(t *testing.T) {
			cfg := mustLoad(t, LoadOptions{YAML: yamlBytes("server:\n  public_base_url: \"" + value + "\"\n")})
			if cfg.Server.PublicBaseURL != value {
				t.Errorf("公开地址 = %q，期望 %q", cfg.Server.PublicBaseURL, value)
			}
		})
	}

	invalid := []string{
		"ftp://login.example.com",
		"login.example.com",
		"https://",
		"https://user:pass@login.example.com",
		"https://login.example.com/login?a=1",
		"https://login.example.com/#fragment",
	}
	for _, value := range invalid {
		t.Run("无效 "+value, func(t *testing.T) {
			errs := loadErrors(t, LoadOptions{YAML: yamlBytes("server:\n  public_base_url: \"" + value + "\"\n")})
			requireConfigError(t, errs, ConfigErrorValue, "server.public_base_url")
		})
	}
}

func TestPublicURLAndListenConflict(t *testing.T) {
	t.Run("明文公开地址加非回环监听被拒绝", func(t *testing.T) {
		yamlConfig := "server:\n  listen_addr: \"0.0.0.0:8080\"\n  public_base_url: \"http://login.example.com\"\n"
		errs := loadErrors(t, LoadOptions{YAML: yamlBytes(yamlConfig)})
		requireConfigError(t, errs, ConfigErrorConflict, "server.public_base_url")
	})

	t.Run("回环监听允许明文公开地址", func(t *testing.T) {
		yamlConfig := "server:\n  listen_addr: \"127.0.0.1:8080\"\n  public_base_url: \"http://127.0.0.1:8080\"\n"
		mustLoad(t, LoadOptions{YAML: yamlBytes(yamlConfig)})
	})

	t.Run("https 公开地址允许监听所有接口", func(t *testing.T) {
		yamlConfig := "server:\n  listen_addr: \"0.0.0.0:8443\"\n  public_base_url: \"https://login.example.com\"\n"
		mustLoad(t, LoadOptions{YAML: yamlBytes(yamlConfig)})
	})
}

func TestYAMLSyntaxErrors(t *testing.T) {
	t.Run("语法错误", func(t *testing.T) {
		errs := loadErrors(t, LoadOptions{YAML: yamlBytes("server: [\n")})
		requireConfigError(t, errs, ConfigErrorYAMLSyntax, "")
	})
	t.Run("根节点不是映射", func(t *testing.T) {
		errs := loadErrors(t, LoadOptions{YAML: yamlBytes("just-a-string\n")})
		requireConfigError(t, errs, ConfigErrorType, "")
	})
	t.Run("空文档使用默认值", func(t *testing.T) {
		for _, text := range []string{"", "# 只有注释\n"} {
			cfg := mustLoad(t, LoadOptions{YAML: yamlBytes(text)})
			if cfg.Server.ListenAddr != Default().Server.ListenAddr {
				t.Errorf("空文档未使用默认值：%+v", cfg)
			}
		}
	})
}

func TestInvalidConfigHasNoSideEffects(t *testing.T) {
	dir := t.TempDir()
	databasePath := filepath.Join(dir, "login.db")

	validYAML := "database:\n  path: \"" + filepath.ToSlash(databasePath) + "\"\n"
	mustLoad(t, LoadOptions{YAML: yamlBytes(validYAML)})
	if _, err := os.Stat(databasePath); !os.IsNotExist(err) {
		t.Fatalf("加载配置不应创建数据库文件：%v", err)
	}

	invalidYAML := "database:\n  path: \"" + filepath.ToSlash(databasePath) + "\"\n  busy_timeout_ms: 0\n"
	loadErrors(t, LoadOptions{YAML: yamlBytes(invalidYAML)})
	if _, err := os.Stat(databasePath); !os.IsNotExist(err) {
		t.Fatalf("无效配置不应创建数据库文件：%v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读取临时目录失败：%v", err)
	}
	if len(entries) != 0 {
		t.Errorf("加载配置不应产生文件：%v", entries)
	}
}

func TestEnvFieldMetadataStable(t *testing.T) {
	want := []FieldInfo{
		{Field: "server.listen_addr", Env: "LOGIN_SERVER_LISTEN_ADDR", Class: ReloadRestartRequired},
		{Field: "server.extra_listen_addrs", Env: "LOGIN_SERVER_EXTRA_LISTEN_ADDRS", Class: ReloadRestartRequired},
		{Field: "server.public_base_url", Env: "LOGIN_SERVER_PUBLIC_BASE_URL", Class: ReloadRestartRequired},
		{Field: "server.path_prefix", Env: "LOGIN_SERVER_PATH_PREFIX", Class: ReloadRestartRequired},
		{Field: "server.allowed_hosts", Env: "LOGIN_SERVER_ALLOWED_HOSTS", Class: ReloadRestartRequired},
		{Field: "server.trusted_proxies", Env: "LOGIN_SERVER_TRUSTED_PROXIES", Class: ReloadRestartRequired},
		{Field: "server.tls_terminating_proxy", Env: "LOGIN_SERVER_TLS_TERMINATING_PROXY", Class: ReloadRestartRequired},
		{Field: "server.tls_cert_files", Env: "LOGIN_SERVER_TLS_CERT_FILES", Class: ReloadRestartRequired},
		{Field: "server.tls_key_files", Env: "LOGIN_SERVER_TLS_KEY_FILES", Class: ReloadRestartRequired},
		{Field: "server.tls_ca_file", Env: "LOGIN_SERVER_TLS_CA_FILE", Class: ReloadRestartRequired},
		{Field: "server.tls_pfx_file", Env: "LOGIN_SERVER_TLS_PFX_FILE", Class: ReloadRestartRequired},
		{Field: "server.tls_expiry_warning_days", Env: "LOGIN_SERVER_TLS_EXPIRY_WARNING_DAYS", Class: ReloadRestartRequired},
		{Field: "server.shutdown_timeout_seconds", Env: "LOGIN_SERVER_SHUTDOWN_TIMEOUT_SECONDS", Class: ReloadHotReloadable},
		{Field: "logging.level", Env: "LOGIN_LOGGING_LEVEL", Class: ReloadHotReloadable},
		{Field: "logging.format", Env: "LOGIN_LOGGING_FORMAT", Class: ReloadHotReloadable},
		{Field: "database.driver", Env: "LOGIN_DATABASE_DRIVER", Class: ReloadRestartRequired},
		{Field: "database.path", Env: "LOGIN_DATABASE_PATH", Class: ReloadRestartRequired},
		{Field: "database.wal", Env: "LOGIN_DATABASE_WAL", Class: ReloadRestartRequired},
		{Field: "database.busy_timeout_ms", Env: "LOGIN_DATABASE_BUSY_TIMEOUT_MS", Class: ReloadRestartRequired},
		{Field: "secrets.master_key", Env: "LOGIN_SECRETS_MASTER_KEY", Class: ReloadRestartRequired, Secret: true},
		{Field: "secrets.tls_pfx_password", Env: "LOGIN_SECRETS_TLS_PFX_PASSWORD", Class: ReloadRestartRequired, Secret: true},
	}
	got := Fields()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("字段元数据变化：\n得到 %+v\n期望 %+v", got, want)
	}
	for _, field := range got {
		if !strings.HasPrefix(field.Env, EnvVarPrefix) {
			t.Errorf("环境变量 %s 缺少固定前缀 %s", field.Env, EnvVarPrefix)
		}
		if _, ok := LookupField(field.Field); !ok {
			t.Errorf("LookupField 找不到 %s", field.Field)
		}
	}
}

func TestAllEnvFieldsApplied(t *testing.T) {
	environment := map[string]string{
		envServerListenAddr:      "127.0.0.1:9090",
		envServerPublicBaseURL:   "https://login.example.com",
		envServerShutdownTimeout: "45",
		envLoggingLevel:          "debug",
		envLoggingFormat:         "json",
		envDatabaseDriver:        "sqlite",
		envDatabasePath:          "data/login.db",
		envDatabaseWAL:           "false",
		envDatabaseBusyTimeout:   "1234",
		envSecretsMasterKey:      "env-master-key-value",
	}
	cfg := mustLoad(t, LoadOptions{LookupEnv: envLookup(environment)})

	if cfg.Server.ListenAddr != "127.0.0.1:9090" ||
		cfg.Server.PublicBaseURL != "https://login.example.com" ||
		cfg.Server.ShutdownTimeoutSeconds != 45 {
		t.Errorf("服务配置未全部生效：%+v", cfg.Server)
	}
	if cfg.Logging.Level != LogLevelDebug || cfg.Logging.Format != LogFormatJSON {
		t.Errorf("日志配置未全部生效：%+v", cfg.Logging)
	}
	if cfg.Database.Driver != DatabaseDriverSQLite ||
		cfg.Database.Path != "data/login.db" ||
		cfg.Database.WAL ||
		cfg.Database.BusyTimeoutMS != 1234 {
		t.Errorf("数据库配置未全部生效：%+v", cfg.Database)
	}
	if !cfg.Secrets.MasterKey.IsSet() {
		t.Error("环境变量秘密未生效")
	}
	if got := string(cfg.Secrets.MasterKey.Value()); got != "env-master-key-value" {
		t.Errorf("秘密值 = %q", got)
	}
	diagnostic := cfg.Diagnostic()
	if strings.Contains(diagnostic, "env-master-key-value") {
		t.Fatalf("脱敏诊断泄露秘密：\n%s", diagnostic)
	}
	if !strings.Contains(diagnostic, "secrets.master_key = [REDACTED]") {
		t.Errorf("脱敏诊断未标记已设置秘密：\n%s", diagnostic)
	}
}

func TestLookupEnvInjection(t *testing.T) {
	t.Setenv(envServerListenAddr, "127.0.0.1:7777")
	// 注入的 LookupEnv 完全替代进程环境；未读取真实环境变量。
	cfg := mustLoad(t, LoadOptions{LookupEnv: func(string) (string, bool) { return "", false }})
	if cfg.Server.ListenAddr != Default().Server.ListenAddr {
		t.Errorf("未使用注入的环境读取函数：%q", cfg.Server.ListenAddr)
	}
}

func TestErrorsAggregation(t *testing.T) {
	t.Run("YAML 多个字段错误全部报告", func(t *testing.T) {
		yamlConfig := "logging:\n  level: verbose\ndatabase:\n  busy_timeout_ms: 0\nserver:\n  shutdown_timeout_seconds: 0\n"
		errs := loadErrors(t, LoadOptions{YAML: yamlBytes(yamlConfig)})
		if len(errs) < 3 {
			t.Fatalf("应收集至少 3 项错误，实际 %d：%v", len(errs), errs)
		}
		for _, field := range []string{"logging.level", "database.busy_timeout_ms", "server.shutdown_timeout_seconds"} {
			if findConfigError(errs, ConfigErrorValue, field) == nil &&
				findConfigError(errs, ConfigErrorRange, field) == nil {
				t.Errorf("缺少字段 %s 的错误：%v", field, errs)
			}
		}
		if !strings.Contains(errs.Error(), "3 项错误") {
			t.Errorf("聚合错误摘要不正确：%v", errs)
		}
	})

	t.Run("环境变量与显式选项错误合并", func(t *testing.T) {
		opts := LoadOptions{
			LookupEnv: envLookup(map[string]string{
				envServerShutdownTimeout: "0",
				envDatabaseBusyTimeout:   "0",
			}),
			Overrides: &Overrides{Server: ServerOverrides{ListenAddr: Ptr("")}},
		}
		errs := loadErrors(t, opts)
		if len(errs) < 3 {
			t.Fatalf("应合并 3 项错误，实际 %d：%v", len(errs), errs)
		}
		var first *ConfigError
		if !errors.As(errs, &first) || first == nil {
			t.Error("errors.As 无法提取单项 ConfigError")
		}
	})

	t.Run("YAML 与 YAMLFile 冲突", func(t *testing.T) {
		_, err := Load(LoadOptions{YAML: yamlBytes(""), YAMLFile: "unused.yaml"})
		if err == nil {
			t.Fatal("同时设置 YAML 与 YAMLFile 应失败")
		}
		var errs ConfigErrors
		if !errors.As(err, &errs) {
			t.Fatalf("错误不是 ConfigErrors：%v", err)
		}
		requireConfigError(t, errs, ConfigErrorOptions, "")
	})
}

func TestConfigValidateForProgrammaticConfig(t *testing.T) {
	cfg := Default()
	cfg.Logging.Level = LogLevel("verbose")
	cfg.Database.BusyTimeoutMS = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("手工构造的非法配置应校验失败")
	} else {
		var errs ConfigErrors
		if !errors.As(err, &errs) {
			t.Fatalf("错误不是 ConfigErrors：%v", err)
		}
		requireConfigError(t, errs, ConfigErrorValue, "logging.level")
		requireConfigError(t, errs, ConfigErrorRange, "database.busy_timeout_ms")
	}
}

func TestDiffReload(t *testing.T) {
	base := Default()

	t.Run("无差异", func(t *testing.T) {
		diff := DiffReload(base, base)
		if !diff.Empty() {
			t.Errorf("相同配置不应有差异：%+v", diff)
		}
	})

	t.Run("热更新字段", func(t *testing.T) {
		next := base
		next.Logging.Level = LogLevelDebug
		next.Server.ShutdownTimeoutSeconds = 30
		diff := DiffReload(base, next)
		want := []string{"server.shutdown_timeout_seconds", "logging.level"}
		if !reflect.DeepEqual(diff.HotFields, want) {
			t.Errorf("热更新字段 = %v，期望 %v", diff.HotFields, want)
		}
		if len(diff.RestartFields) != 0 {
			t.Errorf("不应有重启字段：%v", diff.RestartFields)
		}
	})

	t.Run("需重启字段", func(t *testing.T) {
		next := base
		next.Database.Path = "data/other.db"
		next.Server.PublicBaseURL = "https://login.example.com"
		next.Secrets.MasterKey = NewSecretString("new-secret")
		diff := DiffReload(base, next)
		if len(diff.HotFields) != 0 {
			t.Errorf("不应有热更新字段：%v", diff.HotFields)
		}
		want := []string{"server.public_base_url", "database.path", "secrets.master_key"}
		if !reflect.DeepEqual(diff.RestartFields, want) {
			t.Errorf("重启字段 = %v，期望 %v", diff.RestartFields, want)
		}
	})
}

func TestExampleConfigLoads(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("examples", "config-load", "login.example.yaml"))
	if err != nil {
		t.Fatalf("读取示例配置失败：%v", err)
	}
	cfg, err := Load(LoadOptions{YAML: data})
	if err != nil {
		t.Fatalf("示例配置应可加载：%v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("示例配置应有效：%v", err)
	}
	if cfg.Database.Driver != DatabaseDriverSQLite || !cfg.Database.WAL {
		t.Errorf("示例配置值不符合预期：%+v", cfg.Database)
	}
}
