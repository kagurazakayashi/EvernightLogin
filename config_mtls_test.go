package login

import (
	"reflect"
	"strings"
	"testing"
)

// mtlsYAML 返回启用客户端证书认证的最小合法 YAML 片段。
func mtlsYAML(extra string) string {
	return "server:\n" +
		"  listen_addr: \"127.0.0.1:8443\"\n" +
		"  tls_cert_files: [\"C:/certs/server.crt\"]\n" +
		"  tls_key_files: [\"C:/certs/server.key\"]\n" +
		"  tls_client_auth: \"required\"\n" +
		"  tls_client_ca_files: [\"C:/certs/client-ca.pem\"]\n" +
		"  tls_client_identities:\n" +
		"    - dns_name: \"backup.internal\"\n" +
		"      service: \"backup-agent\"\n" +
		extra
}

// TestMTLSConfigYAMLParsing 验证 mTLS 模式、客户端信任 CA 与结构化身份映射可以
// 从 YAML 加载，并进入脱敏诊断。
func TestMTLSConfigYAMLParsing(t *testing.T) {
	cfg := mustLoad(t, LoadOptions{YAML: yamlBytes(mtlsYAML(""))})
	if cfg.Server.TLSClientAuthMode != TLSClientAuthRequired {
		t.Errorf("客户端证书认证模式 = %q", cfg.Server.TLSClientAuthMode)
	}
	if !reflect.DeepEqual(cfg.Server.TLSClientCAFiles, []string{"C:/certs/client-ca.pem"}) {
		t.Errorf("客户端信任 CA = %v", cfg.Server.TLSClientCAFiles)
	}
	wantIdentities := []TLSClientIdentity{{DNSName: "backup.internal", Service: "backup-agent"}}
	if !reflect.DeepEqual(cfg.Server.TLSClientIdentities, wantIdentities) {
		t.Errorf("身份映射 = %+v", cfg.Server.TLSClientIdentities)
	}

	diagnostic := cfg.Diagnostic()
	for _, expected := range []string{
		"server.tls_client_auth = \"required\"",
		"server.tls_client_ca_files = [\"C:/certs/client-ca.pem\"]",
		"server.tls_client_identities = [{\"backup.internal\" -> \"backup-agent\"}]",
	} {
		if !strings.Contains(diagnostic, expected) {
			t.Errorf("诊断输出缺少 %q：\n%s", expected, diagnostic)
		}
	}

	if diff := DiffReload(cfg, cfg); !diff.Empty() {
		t.Errorf("相同配置不应有差异：%+v", diff)
	}
	next := cfg
	next.Server.TLSClientAuthMode = TLSClientAuthOptional
	next.Server.TLSClientCAFiles = []string{"C:/certs/other-ca.pem"}
	next.Server.TLSClientIdentities = []TLSClientIdentity{{DNSName: "monitor.internal", Service: "monitor"}}
	diff := DiffReload(cfg, next)
	restart := strings.Join(diff.RestartFields, ",")
	for _, field := range []string{"server.tls_client_auth", "server.tls_client_ca_files", "server.tls_client_identities"} {
		if !strings.Contains(restart, field) {
			t.Errorf("重载差异缺少需重启字段 %s：%+v", field, diff)
		}
	}
}

// TestMTLSConfigEnvAndOverrides 验证 mTLS 环境变量（列表与 dns=service 映射）和
// 显式代码覆盖层。
func TestMTLSConfigEnvAndOverrides(t *testing.T) {
	env := envLookup(map[string]string{
		envServerTLSCertFiles:  "C:/certs/server.crt",
		envServerTLSKeyFiles:   "C:/certs/server.key",
		envServerTLSClientAuth: "required",
		envServerTLSClientCA:   "C:/certs/ca-a.pem,C:/certs/ca-b.pem",
		envServerTLSClientMaps: "backup.internal=backup-agent,monitor.internal=monitor",
	})
	cfg := mustLoad(t, LoadOptions{LookupEnv: env})
	if cfg.Server.TLSClientAuthMode != TLSClientAuthRequired {
		t.Errorf("环境变量模式 = %q", cfg.Server.TLSClientAuthMode)
	}
	if !reflect.DeepEqual(cfg.Server.TLSClientCAFiles, []string{"C:/certs/ca-a.pem", "C:/certs/ca-b.pem"}) {
		t.Errorf("环境变量客户端信任 CA = %v", cfg.Server.TLSClientCAFiles)
	}
	want := []TLSClientIdentity{
		{DNSName: "backup.internal", Service: "backup-agent"},
		{DNSName: "monitor.internal", Service: "monitor"},
	}
	if !reflect.DeepEqual(cfg.Server.TLSClientIdentities, want) {
		t.Errorf("环境变量身份映射 = %+v", cfg.Server.TLSClientIdentities)
	}

	overridden := mustLoad(t, LoadOptions{
		YAML: yamlBytes("server:\n  tls_client_auth: disabled\n"),
		Overrides: &Overrides{Server: ServerOverrides{
			TLSCertFiles:        Ptr([]string{"C:/override/server.crt"}),
			TLSKeyFiles:         Ptr([]string{"C:/override/server.key"}),
			TLSClientAuthMode:   Ptr(TLSClientAuthOptional),
			TLSClientCAFiles:    Ptr([]string{"C:/override/client-ca.pem"}),
			TLSClientIdentities: Ptr([]TLSClientIdentity{{DNSName: "agent.internal", Service: "agent"}}),
		}},
	})
	if overridden.Server.TLSClientAuthMode != TLSClientAuthOptional {
		t.Errorf("覆盖后的模式 = %q", overridden.Server.TLSClientAuthMode)
	}
	if !reflect.DeepEqual(overridden.Server.TLSClientIdentities,
		[]TLSClientIdentity{{DNSName: "agent.internal", Service: "agent"}}) {
		t.Errorf("覆盖后的身份映射 = %+v", overridden.Server.TLSClientIdentities)
	}
}

// TestMTLSConfigYAMLStructureErrors 验证身份映射的 YAML 结构严格检查。
func TestMTLSConfigYAMLStructureErrors(t *testing.T) {
	cases := []struct {
		name  string
		yaml  string
		field string
	}{
		{
			name:  "身份映射写成字符串列表",
			yaml:  "server:\n  tls_client_identities: [\"backup.internal=backup-agent\"]\n",
			field: "server.tls_client_identities[0]",
		},
		{
			name:  "身份映射缺少 service",
			yaml:  "server:\n  tls_client_identities:\n    - dns_name: \"backup.internal\"\n",
			field: "server.tls_client_identities[0]",
		},
		{
			name:  "身份映射出现未知字段",
			yaml:  "server:\n  tls_client_identities:\n    - dns_name: \"backup.internal\"\n      service: \"backup-agent\"\n      is_root: true\n",
			field: "server.tls_client_identities[0].is_root",
		}, {
			name:  "身份映射元素不是映射",
			yaml:  "server:\n  tls_client_identities:\n    - \"backup.internal\"\n",
			field: "server.tls_client_identities[0]",
		},
		{
			name:  "认证模式写成整数",
			yaml:  "server:\n  tls_client_auth: 1\n",
			field: "server.tls_client_auth",
		},
		{
			name:  "客户端信任 CA 写成标量",
			yaml:  "server:\n  tls_client_ca_files: \"C:/certs/ca.pem\"\n",
			field: "server.tls_client_ca_files",
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			errs := loadErrors(t, LoadOptions{YAML: yamlBytes(test.yaml)})
			if found := findConfigError(errs, ConfigErrorType, test.field); found == nil &&
				findConfigError(errs, ConfigErrorValue, test.field) == nil &&
				findConfigError(errs, ConfigErrorUnknownField, test.field) == nil {
				t.Fatalf("缺少 %s 的结构/取值错误：%v", test.field, errs)
			}
		})
	}
}

// TestMTLSConfigEnvParseErrors 验证映射环境变量的格式错误不会被静默忽略。
func TestMTLSConfigEnvParseErrors(t *testing.T) {
	cases := []struct {
		name  string
		value string
	}{
		{name: "缺少等号", value: "backup.internal"},
		{name: "等号两侧为空", value: "=backup-agent"},
		{name: "DNS 为空", value: " =backup-agent"},
		{name: "多等号", value: "a=b=c"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			errs := loadErrors(t, LoadOptions{LookupEnv: envLookup(map[string]string{
				envServerTLSClientMaps: test.value,
			})})
			requireConfigError(t, errs, ConfigErrorValue, "server.tls_client_identities")
		})
	}
}

// TestMTLSConfigCombinationValidation 验证 mTLS 组合约束：默认关闭、启用必须
// 具备本地 TLS/独立信任 CA/显式映射，且关闭时不能静默配置未使用的信任材料。
func TestMTLSConfigCombinationValidation(t *testing.T) {
	cases := []struct {
		name  string
		yaml  string
		kind  ConfigErrorKind
		field string
	}{
		{
			name:  "关闭模式却配置客户端信任 CA",
			yaml:  "server:\n  tls_client_ca_files: [\"C:/certs/ca.pem\"]\n",
			kind:  ConfigErrorConflict,
			field: "server.tls_client_ca_files",
		},
		{
			name:  "关闭模式却配置身份映射",
			yaml:  "server:\n  tls_client_identities:\n    - dns_name: \"backup.internal\"\n      service: \"backup-agent\"\n",
			kind:  ConfigErrorConflict,
			field: "server.tls_client_identities",
		},
		{
			name:  "启用 mTLS 但没有本地 TLS",
			yaml:  "server:\n  tls_client_auth: required\n  tls_client_ca_files: [\"C:/certs/ca.pem\"]\n  tls_client_identities:\n    - dns_name: \"backup.internal\"\n      service: \"backup-agent\"\n",
			kind:  ConfigErrorConflict,
			field: "server.tls_client_auth",
		},
		{
			name:  "启用 mTLS 但缺少客户端信任 CA",
			yaml:  "server:\n  tls_cert_files: [\"C:/certs/server.crt\"]\n  tls_key_files: [\"C:/certs/server.key\"]\n  tls_client_auth: required\n  tls_client_identities:\n    - dns_name: \"backup.internal\"\n      service: \"backup-agent\"\n",
			kind:  ConfigErrorConflict,
			field: "server.tls_client_ca_files",
		},
		{
			name:  "启用 mTLS 但缺少身份映射",
			yaml:  "server:\n  tls_cert_files: [\"C:/certs/server.crt\"]\n  tls_key_files: [\"C:/certs/server.key\"]\n  tls_client_auth: required\n  tls_client_ca_files: [\"C:/certs/client-ca.pem\"]\n",
			kind:  ConfigErrorConflict,
			field: "server.tls_client_identities",
		},
		{
			name:  "客户端信任 CA 与服务器证书共用路径",
			yaml:  "server:\n  tls_cert_files: [\"C:/certs/server.crt\"]\n  tls_key_files: [\"C:/certs/server.key\"]\n  tls_client_auth: required\n  tls_client_ca_files: [\"C:/certs/server.crt\"]\n  tls_client_identities:\n    - dns_name: \"backup.internal\"\n      service: \"backup-agent\"\n",
			kind:  ConfigErrorConflict,
			field: "server.tls_client_ca_files",
		},
		{
			name:  "未知认证模式",
			yaml:  "server:\n  tls_client_auth: \"on\"\n",
			kind:  ConfigErrorValue,
			field: "server.tls_client_auth",
		},
		{
			name:  "身份 DNS 名称是 IP",
			yaml:  mtlsYAML("") + "",
			kind:  ConfigErrorValue,
			field: "server.tls_client_identities",
		},
	}
	// 最后一例需要替换身份 DNS 名称，单独处理。
	cases[len(cases)-1].yaml = strings.Replace(mtlsYAML(""), "\"backup.internal\"", "\"127.0.0.1\"", 1)

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			errs := loadErrors(t, LoadOptions{YAML: yamlBytes(test.yaml)})
			requireConfigError(t, errs, test.kind, test.field)
		})
	}

	t.Run("mTLS 关闭但零值模式通过", func(t *testing.T) {
		cfg := Default()
		cfg.Server.TLSClientAuthMode = ""
		cfg.Server.TLSClientCAFiles = nil
		cfg.Server.TLSClientIdentities = nil
		if err := cfg.Validate(); err != nil {
			t.Fatalf("零值 mTLS 模式应按 disabled 通过：%v", err)
		}
		if mode := normalizeTLSClientAuthMode(cfg.Server.TLSClientAuthMode); mode != TLSClientAuthDisabled {
			t.Errorf("零值模式归一化 = %q", mode)
		}
		if cfg.Server.TLSClientAuthMode.Enabled() {
			t.Error("零值模式不应启用客户端证书认证")
		}
	})
}

// TestMTLSConfigIdentityValueValidation 验证身份映射条目的 DNS 名称与服务身份
// 取值规则。
func TestMTLSConfigIdentityValueValidation(t *testing.T) {
	base := "server:\n  tls_cert_files: [\"C:/certs/server.crt\"]\n  tls_key_files: [\"C:/certs/server.key\"]\n  tls_client_auth: required\n  tls_client_ca_files: [\"C:/certs/client-ca.pem\"]\n  tls_client_identities:\n"
	cases := []struct {
		name     string
		identity string
	}{
		{name: "DNS 名称通配符", identity: "    - dns_name: \"*.internal\"\n      service: \"agent\"\n"},
		{name: "DNS 名称带端口", identity: "    - dns_name: \"backup.internal:8443\"\n      service: \"agent\"\n"},
		{name: "服务身份大写", identity: "    - dns_name: \"backup.internal\"\n      service: \"Backup-Agent\"\n"},
		{name: "服务身份含空格", identity: "    - dns_name: \"backup.internal\"\n      service: \"backup agent\"\n"},
		{name: "服务身份以符号开头", identity: "    - dns_name: \"backup.internal\"\n      service: \"-agent\"\n"},
		{name: "重复 DNS 名称", identity: "    - dns_name: \"backup.internal\"\n      service: \"agent-a\"\n    - dns_name: \"backup.internal\"\n      service: \"agent-b\"\n"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			errs := loadErrors(t, LoadOptions{YAML: yamlBytes(base + test.identity)})
			requireConfigError(t, errs, ConfigErrorValue, "server.tls_client_identities")
		})
	}

	t.Run("合法映射通过", func(t *testing.T) {
		cfg := mustLoad(t, LoadOptions{YAML: yamlBytes(base +
			"    - dns_name: \"Backup.Internal.\"\n      service: \"agent.b\"\n")})
		if cfg.Server.TLSClientAuthMode != TLSClientAuthRequired {
			t.Errorf("模式 = %q", cfg.Server.TLSClientAuthMode)
		}
	})
}

// TestMTLSConfigHostBuildValidation 验证宿主直接构造 Config（不经过 Load）时
// 也会执行 mTLS 校验。
func TestMTLSConfigHostBuildValidation(t *testing.T) {
	cfg := Default()
	cfg.Server.ListenAddr = "127.0.0.1:8443"
	cfg.Server.TLSCertFiles = []string{"C:/certs/server.crt"}
	cfg.Server.TLSKeyFiles = []string{"C:/certs/server.key"}
	cfg.Server.TLSClientAuthMode = TLSClientAuthRequired
	cfg.Server.TLSClientCAFiles = []string{"C:/certs/client-ca.pem"}
	cfg.Server.TLSClientIdentities = []TLSClientIdentity{{DNSName: "backup.internal", Service: "backup-agent"}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("合法宿主配置应通过：%v", err)
	}

	invalid := cfg
	invalid.Server.TLSClientAuthMode = TLSClientAuthMode("on")
	if err := invalid.Validate(); err == nil {
		t.Fatal("未知 mTLS 模式应被拒绝")
	}
	disabled := cfg
	disabled.Server.TLSClientAuthMode = TLSClientAuthDisabled
	if err := disabled.Validate(); err == nil {
		t.Fatal("关闭 mTLS 却配置信任材料应被拒绝")
	}
}
