package config

import (
	"strings"
	"testing"
)

// TestPasskeyConfigDefaults 验证 Passkey 默认关闭、默认要求用户验证。
func TestPasskeyConfigDefaults(t *testing.T) {
	cfg := Default()
	if cfg.Passkey.Enabled {
		t.Error("Passkey 默认必须关闭（默认拒绝）")
	}
	if cfg.Passkey.UserVerification != "required" {
		t.Errorf("Passkey 默认用户验证策略 = %q，期望 required", cfg.Passkey.UserVerification)
	}
	if cfg.Passkey.RPID != "" || len(cfg.Passkey.AllowedOrigins) != 0 {
		t.Errorf("默认不应配置 RP ID/来源：%+v", cfg.Passkey)
	}
	diagnostic := cfg.Diagnostic()
	for _, field := range []string{"passkey.enabled", "passkey.rp_id",
		"passkey.rp_display_name", "passkey.allowed_origins", "passkey.user_verification"} {
		if !strings.Contains(diagnostic, field+" = ") {
			t.Errorf("脱敏诊断缺少 Passkey 字段 %s", field)
		}
	}
}

// TestPasskeyConfigYAMLAndEnv 验证 YAML 与固定环境变量都能加载 Passkey 配置。
func TestPasskeyConfigYAMLAndEnv(t *testing.T) {
	cfg := mustLoad(t, LoadOptions{YAML: yamlBytes(`passkey:
  enabled: true
  rp_id: "login.example.com"
  rp_display_name: "示例登录"
  allowed_origins:
    - "https://login.example.com"
  user_verification: "required"
`)})
	if !cfg.Passkey.Enabled || cfg.Passkey.RPID != "login.example.com" ||
		cfg.Passkey.RPDisplayName != "示例登录" ||
		cfg.Passkey.UserVerification != "required" ||
		len(cfg.Passkey.AllowedOrigins) != 1 ||
		cfg.Passkey.AllowedOrigins[0] != "https://login.example.com" {
		t.Errorf("YAML Passkey 配置未生效：%+v", cfg.Passkey)
	}

	envCfg := mustLoad(t, LoadOptions{LookupEnv: envLookup(map[string]string{
		envPasskeyEnabled:    "true",
		envPasskeyRPID:       "example.com",
		envPasskeyRPName:     "示例登录",
		envPasskeyOrigins:    "https://login.example.com,https://auth.example.com",
		envPasskeyUserVerify: "preferred",
	})})
	if !envCfg.Passkey.Enabled || envCfg.Passkey.RPID != "example.com" ||
		envCfg.Passkey.UserVerification != "preferred" ||
		len(envCfg.Passkey.AllowedOrigins) != 2 {
		t.Errorf("环境变量 Passkey 配置未生效：%+v", envCfg.Passkey)
	}
}

// TestPasskeyConfigRejectsInvalid 验证非法 RP ID/来源/UV 在加载阶段拒绝。
func TestPasskeyConfigRejectsInvalid(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{name: "RP ID 为空", yaml: `passkey:
  enabled: true
  allowed_origins:
    - "https://login.example.com"
`},
		{name: "RP ID 带协议", yaml: `passkey:
  enabled: true
  rp_id: "https://login.example.com"
  allowed_origins:
    - "https://login.example.com"
`},
		{name: "RP ID 是 IP", yaml: `passkey:
  enabled: true
  rp_id: "127.0.0.1"
  allowed_origins:
    - "http://127.0.0.1"
`},
		{name: "没有来源", yaml: `passkey:
  enabled: true
  rp_id: "login.example.com"
`},
		{name: "来源使用 http", yaml: `passkey:
  enabled: true
  rp_id: "login.example.com"
  allowed_origins:
    - "http://login.example.com"
`},
		{name: "来源主机不属于 RP ID", yaml: `passkey:
  enabled: true
  rp_id: "login.example.com"
  allowed_origins:
    - "https://evil.example.net"
`},
		{name: "来源带路径", yaml: `passkey:
  enabled: true
  rp_id: "login.example.com"
  allowed_origins:
    - "https://login.example.com/path"
`},
		{name: "未知用户验证策略", yaml: `passkey:
  enabled: true
  rp_id: "login.example.com"
  allowed_origins:
    - "https://login.example.com"
  user_verification: "sometimes"
`},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Load(LoadOptions{YAML: yamlBytes(test.yaml)}); err == nil {
				t.Fatalf("非法 Passkey 配置应被拒绝：%s", test.name)
			}
		})
	}
	// 关闭且完全未配置时允许（功能默认关闭）。
	if _, err := Load(LoadOptions{YAML: yamlBytes("server:\n  listen_addr: \"127.0.0.1:8080\"\n")}); err != nil {
		t.Fatalf("未启用 Passkey 时应允许空配置: %v", err)
	}
}
