package login

import (
	"reflect"
	"strings"
	"testing"
)

// TestTLSConfigYAMLParsing 验证 TLS 证书、附加 CA、PFX 与到期告警字段可以从
// YAML 与受保护秘密来源读取。
func TestTLSConfigYAMLParsing(t *testing.T) {
	yamlConfig := `
server:
  listen_addr: "127.0.0.1:8443"
  public_base_url: "https://login.example.com"
  tls_cert_files:
    - "C:/certs/login.crt"
    - "C:/certs/api.crt"
  tls_key_files:
    - "C:/certs/login.key"
    - "C:/certs/api.key"
  tls_expiry_warning_days: 14
`
	cfg := mustLoad(t, LoadOptions{YAML: yamlBytes(yamlConfig)})
	if !reflect.DeepEqual(cfg.Server.TLSCertFiles, []string{"C:/certs/login.crt", "C:/certs/api.crt"}) {
		t.Errorf("TLS 证书文件 = %v", cfg.Server.TLSCertFiles)
	}
	if !reflect.DeepEqual(cfg.Server.TLSKeyFiles, []string{"C:/certs/login.key", "C:/certs/api.key"}) {
		t.Errorf("TLS 私钥文件 = %v", cfg.Server.TLSKeyFiles)
	}
	if cfg.Server.TLSExpiryWarningDays != 14 {
		t.Errorf("到期告警天数 = %d", cfg.Server.TLSExpiryWarningDays)
	}
	if !cfg.Server.TLSEnabled() {
		t.Error("TLSEnabled 应为 true")
	}
}

// TestTLSConfigPFXSecretSource 验证 PFX 密码只能从受保护来源读取。
func TestTLSConfigPFXSecretSource(t *testing.T) {
	yamlConfig := "server:\n  tls_pfx_file: \"C:/certs/a.pfx\"\nsecrets:\n  tls_pfx_password:\n    env: LOGIN_TEST_PFX_PASSWORD\n"
	env := envLookup(map[string]string{"LOGIN_TEST_PFX_PASSWORD": "pfx-password"})
	cfg := mustLoad(t, LoadOptions{YAML: yamlBytes(yamlConfig), LookupEnv: env})
	if !cfg.Secrets.TLSPFXPassword.IsSet() || string(cfg.Secrets.TLSPFXPassword.Value()) != "pfx-password" {
		t.Error("PFX 密码未从受保护来源加载")
	}
	if !cfg.Server.TLSEnabled() || cfg.Server.TLSPFXFile != "C:/certs/a.pfx" {
		t.Errorf("PFX 配置 = %+v", cfg.Server)
	}

	missing := loadErrors(t, LoadOptions{
		YAML:      yamlBytes("server:\n  tls_pfx_file: \"C:/certs/a.pfx\"\nsecrets:\n  tls_pfx_password:\n    env: LOGIN_TEST_MISSING_PASSWORD\n"),
		LookupEnv: envLookup(map[string]string{}),
	})
	requireConfigError(t, missing, ConfigErrorSecretSource, "secrets.tls_pfx_password")
}

// TestTLSConfigEnvAndOverrides 验证 TLS 环境变量与显式覆盖层。
func TestTLSConfigEnvAndOverrides(t *testing.T) {
	env := envLookup(map[string]string{
		envServerTLSCertFiles:  "C:/certs/a.crt,C:/certs/b.crt",
		envServerTLSKeyFiles:   "C:/certs/a.key,C:/certs/b.key",
		envServerTLSCAFile:     "C:/certs/ca.pem",
		envServerTLSExpiryDays: "21",
	})
	cfg := mustLoad(t, LoadOptions{LookupEnv: env})
	if !reflect.DeepEqual(cfg.Server.TLSCertFiles, []string{"C:/certs/a.crt", "C:/certs/b.crt"}) {
		t.Errorf("证书文件 = %v", cfg.Server.TLSCertFiles)
	}
	if cfg.Server.TLSCAFile != "C:/certs/ca.pem" || cfg.Server.TLSExpiryWarningDays != 21 {
		t.Errorf("CA/告警天数 = %q/%d", cfg.Server.TLSCAFile, cfg.Server.TLSExpiryWarningDays)
	}
	if cfg.Secrets.TLSPFXPassword.IsSet() {
		t.Error("未配置 PFX 时密码环境变量不应出现")
	}

	overridden := mustLoad(t, LoadOptions{
		YAML: yamlBytes("server:\n  tls_expiry_warning_days: 5\n"),
		Overrides: &Overrides{Server: ServerOverrides{
			TLSCertFiles:         Ptr([]string{"C:/override/server.crt"}),
			TLSKeyFiles:          Ptr([]string{"C:/override/server.key"}),
			TLSPFXFile:           Ptr(""),
			TLSExpiryWarningDays: Ptr(45),
		}},
	})
	if !reflect.DeepEqual(overridden.Server.TLSCertFiles, []string{"C:/override/server.crt"}) {
		t.Errorf("覆盖后的证书文件 = %v", overridden.Server.TLSCertFiles)
	}
	if overridden.Server.TLSExpiryWarningDays != 45 {
		t.Errorf("覆盖后的告警天数 = %d", overridden.Server.TLSExpiryWarningDays)
	}
}

// TestTLSConfigTypeErrors 验证 TLS 列表/标量字段的 YAML 类型检查。
func TestTLSConfigTypeErrors(t *testing.T) {
	cases := []struct {
		name  string
		yaml  string
		field string
	}{
		{"证书列表写成标量", "server:\n  tls_cert_files: \"C:/a.crt\"\n", "server.tls_cert_files"},
		{"私钥列表元素不是字符串", "server:\n  tls_key_files: [1]\n", "server.tls_key_files"},
		{"CA 文件写成整数", "server:\n  tls_ca_file: 1\n", "server.tls_ca_file"},
		{"PFX 文件写成列表", "server:\n  tls_pfx_file: [\"a.pfx\"]\n", "server.tls_pfx_file"},
		{"告警天数写成字符串", "server:\n  tls_expiry_warning_days: \"30\"\n", "server.tls_expiry_warning_days"},
		{"PFX 密码直接写字符串", "secrets:\n  tls_pfx_password: \"plaintext\"\n", "secrets.tls_pfx_password"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			errs := loadErrors(t, LoadOptions{YAML: yamlBytes(test.yaml)})
			kind := ConfigErrorType
			if test.name == "PFX 密码直接写字符串" {
				kind = ConfigErrorValue
			}
			requireConfigError(t, errs, kind, test.field)
		})
	}
}

// TestTLSConfigCombinationValidation 验证 TLS 字段之间的组合约束。
func TestTLSConfigCombinationValidation(t *testing.T) {
	env := envLookup(map[string]string{"LOGIN_TEST_PFX_PASSWORD": "secret"})
	cases := []struct {
		name  string
		yaml  string
		kind  ConfigErrorKind
		field string
	}{
		{
			name:  "只有证书没有私钥",
			yaml:  "server:\n  tls_cert_files: [\"C:/a.crt\"]\n",
			kind:  ConfigErrorConflict,
			field: "server.tls_key_files",
		},
		{
			name:  "证书与私钥数量不一致",
			yaml:  "server:\n  tls_cert_files: [\"C:/a.crt\", \"C:/b.crt\"]\n  tls_key_files: [\"C:/a.key\"]\n",
			kind:  ConfigErrorConflict,
			field: "server.tls_key_files",
		},
		{
			name:  "证书数量超过上限",
			yaml:  "server:\n  tls_cert_files: [\"1.crt\",\"2.crt\",\"3.crt\",\"4.crt\",\"5.crt\",\"6.crt\",\"7.crt\",\"8.crt\",\"9.crt\"]\n  tls_key_files: [\"1.key\",\"2.key\",\"3.key\",\"4.key\",\"5.key\",\"6.key\",\"7.key\",\"8.key\",\"9.key\"]\n",
			kind:  ConfigErrorValue,
			field: "server.tls_cert_files",
		},
		{
			name:  "PEM 与 PFX 同时配置",
			yaml:  "server:\n  tls_cert_files: [\"C:/a.crt\"]\n  tls_key_files: [\"C:/a.key\"]\n  tls_pfx_file: \"C:/a.pfx\"\nsecrets:\n  tls_pfx_password:\n    env: LOGIN_TEST_PFX_PASSWORD\n",
			kind:  ConfigErrorConflict,
			field: "server.tls_pfx_file",
		},
		{
			name:  "PFX 缺少密码",
			yaml:  "server:\n  tls_pfx_file: \"C:/a.pfx\"\n",
			kind:  ConfigErrorConflict,
			field: "server.tls_pfx_file",
		},
		{
			name:  "PFX 与附加 CA 同时配置",
			yaml:  "server:\n  tls_pfx_file: \"C:/a.pfx\"\n  tls_ca_file: \"C:/ca.pem\"\nsecrets:\n  tls_pfx_password:\n    env: LOGIN_TEST_PFX_PASSWORD\n",
			kind:  ConfigErrorConflict,
			field: "server.tls_ca_file",
		},
		{
			name:  "未配置 PFX 却设置密码",
			yaml:  "secrets:\n  tls_pfx_password:\n    env: LOGIN_TEST_PFX_PASSWORD\n",
			kind:  ConfigErrorConflict,
			field: "secrets.tls_pfx_password",
		},
		{
			name:  "本地 TLS 与 TLS 终止代理模式互斥",
			yaml:  "server:\n  tls_terminating_proxy: true\n  trusted_proxies: [\"10.0.0.1\"]\n  public_base_url: \"https://login.example.com\"\n  tls_cert_files: [\"C:/a.crt\"]\n  tls_key_files: [\"C:/a.key\"]\n",
			kind:  ConfigErrorConflict,
			field: "server.tls_terminating_proxy",
		},
		{
			name:  "本地 TLS 使用 http 公开地址",
			yaml:  "server:\n  public_base_url: \"http://127.0.0.1:8443\"\n  tls_cert_files: [\"C:/a.crt\"]\n  tls_key_files: [\"C:/a.key\"]\n",
			kind:  ConfigErrorConflict,
			field: "server.public_base_url",
		},
		{
			name:  "告警天数越过上限",
			yaml:  "server:\n  tls_expiry_warning_days: 366\n",
			kind:  ConfigErrorRange,
			field: "server.tls_expiry_warning_days",
		},
		{
			name:  "告警天数为负数",
			yaml:  "server:\n  tls_expiry_warning_days: -1\n",
			kind:  ConfigErrorRange,
			field: "server.tls_expiry_warning_days",
		},
		{
			name:  "证书路径含控制字符",
			yaml:  "server:\n  tls_cert_files: [\"C:/a\\nb.crt\"]\n",
			kind:  ConfigErrorValue,
			field: "server.tls_cert_files",
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			errs := loadErrors(t, LoadOptions{YAML: yamlBytes(test.yaml), LookupEnv: env})
			requireConfigError(t, errs, test.kind, test.field)
		})
	}

	t.Run("告警天数 0 表示默认值并通过", func(t *testing.T) {
		yamlConfig := "server:\n  listen_addr: \"127.0.0.1:8443\"\n  tls_cert_files: [\"C:/certs/a.crt\"]\n  tls_key_files: [\"C:/certs/a.key\"]\n  tls_expiry_warning_days: 0\n"
		cfg := mustLoad(t, LoadOptions{YAML: yamlBytes(yamlConfig)})
		if cfg.Server.TLSExpiryWarningDays != 0 {
			t.Errorf("显式 0 应保留为 0 并由 NewServer 使用默认值，实际 %d", cfg.Server.TLSExpiryWarningDays)
		}
	})

	t.Run("完整 PEM 配置通过", func(t *testing.T) {
		yamlConfig := "server:\n  listen_addr: \"0.0.0.0:8443\"\n  public_base_url: \"https://login.example.com\"\n  tls_cert_files: [\"C:/certs/a.crt\"]\n  tls_key_files: [\"C:/certs/a.key\"]\n"
		cfg := mustLoad(t, LoadOptions{YAML: yamlBytes(yamlConfig)})
		if !cfg.Server.TLSEnabled() || cfg.Server.TLSExpiryWarningDays != DefaultServerTLSExpiryWarningDays {
			t.Errorf("TLS 配置 = %+v", cfg.Server)
		}
	})
}

// TestTLSConfigDiagnosticRedaction 验证 PFX 密码在诊断与差异输出中不泄露。
func TestTLSConfigDiagnosticRedaction(t *testing.T) {
	env := envLookup(map[string]string{"LOGIN_TEST_PFX_PASSWORD": "super-secret-password"})
	cfg := mustLoad(t, LoadOptions{
		YAML:      yamlBytes("server:\n  tls_pfx_file: \"C:/certs/a.pfx\"\nsecrets:\n  tls_pfx_password:\n    env: LOGIN_TEST_PFX_PASSWORD\n"),
		LookupEnv: env,
	})
	diagnostic := cfg.Diagnostic()
	if strings.Contains(diagnostic, "super-secret-password") {
		t.Fatal("诊断输出泄露了 PFX 密码")
	}
	if !strings.Contains(diagnostic, "secrets.tls_pfx_password = [REDACTED]") {
		t.Errorf("诊断输出缺少脱敏 PFX 密码：\n%s", diagnostic)
	}
	if strings.Contains(cfg.Secrets.TLSPFXPassword.String(), "super-secret") {
		t.Fatal("秘密字符串化泄露了内容")
	}

	next := cfg
	next.Secrets.TLSPFXPassword = NewSecretString("another-password")
	diff := DiffReload(cfg, next)
	found := false
	for _, field := range diff.RestartFields {
		if field == "secrets.tls_pfx_password" {
			found = true
		}
	}
	if !found {
		t.Errorf("重载差异缺少 secrets.tls_pfx_password：%+v", diff)
	}
}
