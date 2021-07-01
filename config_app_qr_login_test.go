package login

import (
	"strings"
	"testing"
)

const (
	testAppQRClientOne = "app_00000000000000000000000000000001"
	testAppQRClientTwo = "app_00000000000000000000000000000002"
)

// TestAppQRLoginConfigDefaults 验证扫码登录配置默认关闭与安全默认值。
func TestAppQRLoginConfigDefaults(t *testing.T) {
	cfg := Default()
	if cfg.AppQRLogin.Enabled {
		t.Fatal("扫码登录默认必须关闭")
	}
	if cfg.AppQRLogin.RequestTTLSeconds != 120 || cfg.AppQRLogin.ClaimIntervalSeconds != 1 {
		t.Fatalf("默认 TTL/查询间隔不正确: %+v", cfg.AppQRLogin)
	}
	if len(cfg.AppQRLogin.AllowedClientIDs) != 0 {
		t.Fatal("默认应用白名单必须为空")
	}
}

// TestAppQRLoginConfigYAMLAndEnv 验证 YAML 与环境变量来源及优先级。
func TestAppQRLoginConfigYAMLAndEnv(t *testing.T) {
	yamlConfig := "app_qr_login:\n" +
		"  enabled: true\n" +
		"  allowed_client_ids:\n" +
		"    - \"" + testAppQRClientOne + "\"\n" +
		"  request_ttl_seconds: 90\n" +
		"  claim_interval_seconds: 2\n"
	cfg := mustLoad(t, LoadOptions{YAML: yamlBytes(yamlConfig)})
	if !cfg.AppQRLogin.Enabled || cfg.AppQRLogin.RequestTTLSeconds != 90 ||
		cfg.AppQRLogin.ClaimIntervalSeconds != 2 ||
		len(cfg.AppQRLogin.AllowedClientIDs) != 1 {
		t.Fatalf("YAML 扫码登录配置未生效: %+v", cfg.AppQRLogin)
	}
	// 环境变量覆盖 YAML，显式选项覆盖环境变量。
	lookup := envLookup(map[string]string{
		envAppQRLoginTTL:      "150",
		envAppQRLoginInterval: "3",
		envAppQRLoginClients:  testAppQRClientTwo,
	})
	overrideClients := []string{testAppQRClientOne, testAppQRClientTwo}
	cfg = mustLoad(t, LoadOptions{
		YAML:      yamlBytes(yamlConfig),
		LookupEnv: lookup,
		Overrides: &Overrides{AppQRLogin: AppQRLoginOverrides{
			AllowedClientIDs: &overrideClients,
		}},
	})
	if cfg.AppQRLogin.RequestTTLSeconds != 150 || cfg.AppQRLogin.ClaimIntervalSeconds != 3 {
		t.Fatalf("环境变量覆盖未生效: %+v", cfg.AppQRLogin)
	}
	if len(cfg.AppQRLogin.AllowedClientIDs) != 2 {
		t.Fatalf("显式选项应覆盖环境变量: %+v", cfg.AppQRLogin.AllowedClientIDs)
	}
}

// TestAppQRLoginConfigValidation 验证启用时必须配置合法非空应用白名单。
func TestAppQRLoginConfigValidation(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{"启用但白名单为空", func(c *Config) { c.AppQRLogin.Enabled = true }, "至少一个允许的应用"},
		{"白名单含非法应用 ID", func(c *Config) {
			c.AppQRLogin.Enabled = true
			c.AppQRLogin.AllowedClientIDs = []string{"app_bad"}
		}, "非法应用 ID"},
		{"白名单重复", func(c *Config) {
			c.AppQRLogin.Enabled = true
			c.AppQRLogin.AllowedClientIDs = []string{testAppQRClientOne, testAppQRClientOne}
		}, "不能重复"},
		{"TTL 越界", func(c *Config) { c.AppQRLogin.RequestTTLSeconds = 10 }, "有效期必须是 30～300 秒"},
		{"查询间隔越界", func(c *Config) { c.AppQRLogin.ClaimIntervalSeconds = 60 }, "查询间隔必须是 1～5 秒"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			cfg := Default()
			test.mutate(&cfg)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("应包含配置错误 %q，实际 %v", test.wantErr, err)
			}
		})
	}
	// 关闭状态下允许白名单为空；诊断输出包含新字段且不泄露秘密。
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("默认配置应合法: %v", err)
	}
	diagnostic := cfg.Diagnostic()
	for _, field := range []string{"app_qr_login.enabled", "app_qr_login.allowed_client_ids",
		"app_qr_login.request_ttl_seconds", "app_qr_login.claim_interval_seconds"} {
		if !strings.Contains(diagnostic, field+" = ") {
			t.Fatalf("诊断输出缺少字段 %s:\n%s", field, diagnostic)
		}
	}
}

// TestAppQRLoginConfigEnvParsing 验证环境变量类型错误被收集。
func TestAppQRLoginConfigEnvParsing(t *testing.T) {
	errs := loadErrors(t, LoadOptions{LookupEnv: envLookup(map[string]string{
		envAppQRLoginEnabled:  "not-bool",
		envAppQRLoginTTL:      "not-int",
		envAppQRLoginInterval: "0",
	})})
	for _, field := range []string{"app_qr_login.enabled", "app_qr_login.request_ttl_seconds",
		"app_qr_login.claim_interval_seconds"} {
		found := false
		for _, configError := range errs {
			if configError.Field == field {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("环境变量错误未包含字段 %s：%v", field, errs)
		}
	}
}
