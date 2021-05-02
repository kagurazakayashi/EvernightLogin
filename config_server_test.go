package login

import (
	"reflect"
	"strings"
	"testing"
)

// TestServerNetworkConfigYAMLParsing 验证多地址、允许 Host、可信代理、路径前缀与
// TLS 终止代理模式可以从 YAML 读取。
func TestServerNetworkConfigYAMLParsing(t *testing.T) {
	yamlConfig := `
server:
  listen_addr: "127.0.0.1:8080"
  extra_listen_addrs:
    - "[::1]:8081"
    - "127.0.0.1:8082"
  public_base_url: "https://login.example.com/login"
  path_prefix: "/login"
  allowed_hosts:
    - "login.example.com"
  trusted_proxies:
    - "10.0.0.0/8"
    - "192.0.2.10"
  tls_terminating_proxy: true
  shutdown_timeout_seconds: 20
`
	cfg := mustLoad(t, LoadOptions{YAML: yamlBytes(yamlConfig)})
	if !reflect.DeepEqual(cfg.Server.ExtraListenAddrs, []string{"[::1]:8081", "127.0.0.1:8082"}) {
		t.Errorf("额外监听地址 = %v", cfg.Server.ExtraListenAddrs)
	}
	if cfg.Server.PathPrefix != "/login" {
		t.Errorf("路径前缀 = %q", cfg.Server.PathPrefix)
	}
	if !reflect.DeepEqual(cfg.Server.AllowedHosts, []string{"login.example.com"}) {
		t.Errorf("允许 Host = %v", cfg.Server.AllowedHosts)
	}
	if !reflect.DeepEqual(cfg.Server.TrustedProxies, []string{"10.0.0.0/8", "192.0.2.10"}) {
		t.Errorf("可信代理 = %v", cfg.Server.TrustedProxies)
	}
	if !cfg.Server.TLSProxyMode {
		t.Error("TLS 终止代理模式应为 true")
	}
	if cfg.Server.PublicBaseURL != "https://login.example.com/login" {
		t.Errorf("公开地址 = %q", cfg.Server.PublicBaseURL)
	}
}

// TestServerNetworkConfigEnv 验证列表与布尔环境变量解析。
func TestServerNetworkConfigEnv(t *testing.T) {
	env := envLookup(map[string]string{
		envServerExtraListen:    "[::1]:8081, 127.0.0.1:8082",
		envServerPathPrefix:     "/login",
		envServerAllowedHosts:   "login.example.com,api.example.com",
		envServerTrustedProxies: "10.0.0.0/8,::1",
		envServerTLSProxyMode:   "true",
		envServerPublicBaseURL:  "https://login.example.com/login",
	})
	cfg := mustLoad(t, LoadOptions{LookupEnv: env})
	if !reflect.DeepEqual(cfg.Server.ExtraListenAddrs, []string{"[::1]:8081", "127.0.0.1:8082"}) {
		t.Errorf("额外监听地址 = %v", cfg.Server.ExtraListenAddrs)
	}
	if !reflect.DeepEqual(cfg.Server.AllowedHosts, []string{"login.example.com", "api.example.com"}) {
		t.Errorf("允许 Host = %v", cfg.Server.AllowedHosts)
	}
	if !reflect.DeepEqual(cfg.Server.TrustedProxies, []string{"10.0.0.0/8", "::1"}) {
		t.Errorf("可信代理 = %v", cfg.Server.TrustedProxies)
	}
	if !cfg.Server.TLSProxyMode || cfg.Server.PathPrefix != "/login" {
		t.Errorf("TLS 模式/路径前缀 = %v/%q", cfg.Server.TLSProxyMode, cfg.Server.PathPrefix)
	}

	bad := loadErrors(t, LoadOptions{LookupEnv: envLookup(map[string]string{
		envServerTrustedProxies: "10.0.0.0/8,,192.0.2.1",
	})})
	requireConfigError(t, bad, ConfigErrorValue, "server.trusted_proxies")

	badBool := loadErrors(t, LoadOptions{LookupEnv: envLookup(map[string]string{
		envServerTLSProxyMode: "yes",
	})})
	requireConfigError(t, badBool, ConfigErrorValue, "server.tls_terminating_proxy")
}

// TestServerNetworkConfigOverrides 验证显式代码选项优先级最高。
func TestServerNetworkConfigOverrides(t *testing.T) {
	cfg := mustLoad(t, LoadOptions{
		YAML: yamlBytes("server:\n  extra_listen_addrs: [\"127.0.0.1:8081\"]\n  trusted_proxies: [\"10.0.0.1\"]\n  tls_terminating_proxy: false\n"),
		Overrides: &Overrides{Server: ServerOverrides{
			ExtraListenAddrs: Ptr([]string{"127.0.0.1:9091"}),
			TrustedProxies:   Ptr([]string{"192.0.2.0/24"}),
			TLSProxyMode:     Ptr(false),
		}},
	})
	if !reflect.DeepEqual(cfg.Server.ExtraListenAddrs, []string{"127.0.0.1:9091"}) {
		t.Errorf("额外监听地址 = %v", cfg.Server.ExtraListenAddrs)
	}
	if !reflect.DeepEqual(cfg.Server.TrustedProxies, []string{"192.0.2.0/24"}) {
		t.Errorf("可信代理 = %v", cfg.Server.TrustedProxies)
	}
}

// TestServerNetworkConfigTypeErrors 验证列表字段的 YAML 类型检查。
func TestServerNetworkConfigTypeErrors(t *testing.T) {
	cases := []struct {
		name  string
		yaml  string
		field string
	}{
		{"额外地址写成标量", "server:\n  extra_listen_addrs: \"127.0.0.1:8081\"\n", "server.extra_listen_addrs"},
		{"允许 Host 元素不是字符串", "server:\n  allowed_hosts: [1, 2]\n", "server.allowed_hosts"},
		{"可信代理写成整数", "server:\n  trusted_proxies: 10\n", "server.trusted_proxies"},
		{"TLS 模式写成字符串", "server:\n  tls_terminating_proxy: \"true\"\n", "server.tls_terminating_proxy"},
		{"路径前缀写成整数", "server:\n  path_prefix: 123\n", "server.path_prefix"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			errs := loadErrors(t, LoadOptions{YAML: yamlBytes(test.yaml)})
			requireConfigError(t, errs, ConfigErrorType, test.field)
		})
	}
}

// TestServerNetworkConfigValues 验证新字段的取值与组合校验。
func TestServerNetworkConfigValues(t *testing.T) {
	cases := []struct {
		name  string
		yaml  string
		kind  ConfigErrorKind
		field string
	}{
		{
			name:  "额外地址使用域名",
			yaml:  "server:\n  extra_listen_addrs: [\"example.com:8080\"]\n",
			kind:  ConfigErrorValue,
			field: "server.extra_listen_addrs",
		},
		{
			name:  "额外地址重复",
			yaml:  "server:\n  extra_listen_addrs: [\"127.0.0.1:8081\", \"127.0.0.1:8081\"]\n",
			kind:  ConfigErrorValue,
			field: "server.extra_listen_addrs",
		},
		{
			name:  "额外地址与主地址重复",
			yaml:  "server:\n  extra_listen_addrs: [\"127.0.0.1:8080\"]\n",
			kind:  ConfigErrorValue,
			field: "server.extra_listen_addrs",
		},
		{
			name:  "明文公开地址加非回环额外地址被拒绝",
			yaml:  "server:\n  public_base_url: \"http://127.0.0.1:8080\"\n  extra_listen_addrs: [\"0.0.0.0:8081\"]\n",
			kind:  ConfigErrorConflict,
			field: "server.public_base_url",
		},
		{
			name:  "路径前缀以斜杠结尾",
			yaml:  "server:\n  path_prefix: \"/login/\"\n",
			kind:  ConfigErrorValue,
			field: "server.path_prefix",
		},
		{
			name:  "路径前缀含点段",
			yaml:  "server:\n  path_prefix: \"/login/../admin\"\n",
			kind:  ConfigErrorValue,
			field: "server.path_prefix",
		},
		{
			name:  "允许 Host 通配符",
			yaml:  "server:\n  allowed_hosts: [\"*.example.com\"]\n",
			kind:  ConfigErrorValue,
			field: "server.allowed_hosts",
		},
		{
			name:  "可信代理不是 IP",
			yaml:  "server:\n  trusted_proxies: [\"proxy.internal\"]\n",
			kind:  ConfigErrorValue,
			field: "server.trusted_proxies",
		},
		{
			name:  "公开地址路径与前缀不一致",
			yaml:  "server:\n  public_base_url: \"https://login.example.com/admin\"\n  path_prefix: \"/login\"\n",
			kind:  ConfigErrorConflict,
			field: "server.public_base_url",
		},
		{
			name: "TLS 终止代理模式缺少 https 地址",
			yaml: "server:\n  tls_terminating_proxy: true\n  trusted_proxies: [\"10.0.0.1\"]\n",
			kind: ConfigErrorConflict, field: "server.tls_terminating_proxy",
		},
		{
			name: "TLS 终止代理模式使用 http 公开地址",
			yaml: "server:\n  tls_terminating_proxy: true\n  trusted_proxies: [\"10.0.0.1\"]\n  public_base_url: \"http://127.0.0.1:8080\"\n",
			kind: ConfigErrorConflict, field: "server.tls_terminating_proxy",
		},
		{
			name: "公开地址主机名非法",
			yaml: "server:\n  public_base_url: \"https://bad host\"\n",
			kind: ConfigErrorValue, field: "server.public_base_url",
		},
		{
			name: "公开地址路径带编码",
			yaml: "server:\n  public_base_url: \"https://login.example.com/%2Flogin\"\n",
			kind: ConfigErrorValue, field: "server.public_base_url",
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			errs := loadErrors(t, LoadOptions{YAML: yamlBytes(test.yaml)})
			requireConfigError(t, errs, test.kind, test.field)
		})
	}

	t.Run("TLS 终止代理模式配置完整时通过", func(t *testing.T) {
		yamlConfig := "server:\n  tls_terminating_proxy: true\n  trusted_proxies: [\"10.0.0.1\"]\n  public_base_url: \"https://login.example.com\"\n"
		cfg := mustLoad(t, LoadOptions{YAML: yamlBytes(yamlConfig)})
		if !cfg.Server.TLSProxyMode {
			t.Error("TLS 终止代理模式应为 true")
		}
	})

	t.Run("额外监听地址超过上限", func(t *testing.T) {
		extra := make([]string, 0, MaxServerListenAddresses)
		for index := 0; index < MaxServerListenAddresses; index++ {
			extra = append(extra, "\"127.0.0.1:"+itoa(8081+index)+"\"")
		}
		yamlConfig := "server:\n  extra_listen_addrs: [" + strings.Join(extra, ", ") + "]\n"
		errs := loadErrors(t, LoadOptions{YAML: yamlBytes(yamlConfig)})
		requireConfigError(t, errs, ConfigErrorValue, "server.extra_listen_addrs")
	})
}

// itoa 是测试内的十进制转换，避免为了拼测试数据引入额外依赖。
func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	digits := [12]byte{}
	position := len(digits)
	for value > 0 {
		position--
		digits[position] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[position:])
}

// TestListenAddressesMergeAndDedup 验证主地址与额外地址的合并顺序与去重。
func TestListenAddressesMergeAndDedup(t *testing.T) {
	cfg := Default()
	cfg.Server.ListenAddr = "127.0.0.1:8080"
	cfg.Server.ExtraListenAddrs = []string{"[::1]:8080", "127.0.0.1:8080", "[::1]:8081"}
	got := cfg.Server.ListenAddresses()
	want := []string{"127.0.0.1:8080", "[::1]:8080", "[::1]:8081"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("监听地址 = %v，期望 %v", got, want)
	}
}

// TestServerNetworkConfigDiagnosticAndDiff 验证诊断输出与重载分类包含新字段。
func TestServerNetworkConfigDiagnosticAndDiff(t *testing.T) {
	previous := Default()
	next := Default()
	next.Server.ExtraListenAddrs = []string{"[::1]:8081"}
	next.Server.PublicBaseURL = "https://login.example.com"
	next.Server.PathPrefix = "/login"
	next.Server.AllowedHosts = []string{"login.example.com"}
	next.Server.TrustedProxies = []string{"10.0.0.1"}
	next.Server.TLSProxyMode = true

	diagnostic := next.Diagnostic()
	for _, fragment := range []string{
		"server.extra_listen_addrs = [\"[::1]:8081\"]",
		"server.path_prefix = \"/login\"",
		"server.allowed_hosts = [\"login.example.com\"]",
		"server.trusted_proxies = [\"10.0.0.1\"]",
		"server.tls_terminating_proxy = true",
	} {
		if !strings.Contains(diagnostic, fragment) {
			t.Errorf("诊断输出缺少 %q：\n%s", fragment, diagnostic)
		}
	}

	diff := DiffReload(previous, next)
	wantFields := []string{
		"server.extra_listen_addrs",
		"server.public_base_url",
		"server.path_prefix",
		"server.allowed_hosts",
		"server.trusted_proxies",
		"server.tls_terminating_proxy",
	}
	for _, field := range wantFields {
		found := false
		for _, changed := range diff.RestartFields {
			if changed == field {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("重载差异缺少需重启字段 %s：%+v", field, diff)
		}
	}
}
