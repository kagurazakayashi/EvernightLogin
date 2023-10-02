package config_test

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/config"
)

const mailYAMLValid = `
mail:
  enabled: true
  smtp:
    addr: "127.0.0.1:2525"
    tls_mode: starttls
    username: "mailer"
    password: {env: "LOGIN_TEST_SMTP_PASSWORD"}
    timeout_seconds: 10
  from:
    address: "no-reply@evernight-config.invalid"
    name: "EvernightLogin"
  delivery:
    max_attempts: 3
    timeout_seconds: 120
`

// TestMailConfigLoadValid 覆盖：合法 mail 节可加载、默认值与环境变量秘密来源。
func TestMailConfigLoadValid(t *testing.T) {
	cfg, err := config.Load(config.LoadOptions{
		YAML: []byte(mailYAMLValid),
		LookupEnv: func(name string) (string, bool) {
			return "", false
		},
	})
	if err != nil {
		t.Fatalf("合法 mail 配置应加载成功: %v", err)
	}
	if !cfg.Mail.Enabled || cfg.Mail.SMTP.Addr != "127.0.0.1:2525" ||
		cfg.Mail.SMTP.Username != "mailer" || cfg.Mail.From.Address != "no-reply@evernight-config.invalid" {
		t.Fatalf("mail 配置字段解析不符: %+v", cfg.Mail)
	}
	if cfg.Mail.SMTP.Password.Kind != config.SecretSourceEnv || cfg.Mail.SMTP.Password.Name != "LOGIN_TEST_SMTP_PASSWORD" {
		t.Fatalf("密码来源解析不符: %+v", cfg.Mail.SMTP.Password)
	}
	// 诊断必须脱敏：不出现明文、环境变量名或文件路径。
	values := cfg.FieldValues()
	for _, value := range values {
		if value.Field == "mail.smtp.password" {
			if !value.Secret || value.Value != "[REDACTED]" {
				t.Fatalf("密码诊断未正确脱敏: %+v", value)
			}
		}
	}
	if strings.Contains(cfg.Diagnostic(), "LOGIN_TEST_SMTP_PASSWORD") {
		t.Fatal("诊断不应显示秘密来源名")
	}
}

// TestMailConfigInvalid 覆盖启用时的必填/范围/组合约束。
func TestMailConfigInvalid(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{"missing-addr", "mail:\n  enabled: true\n  from: {address: no-reply@example.test}\n", "smtp.addr"},
		{"missing-from", "mail:\n  enabled: true\n  smtp: {addr: \"127.0.0.1:2525\"}\n", "mail.from.address"},
		{"half-auth", "mail:\n  enabled: true\n  smtp: {addr: \"127.0.0.1:2525\", username: u}\n  from: {address: no-reply@example.test}\n", "用户名与密码"},
		{"plaintext-nonlocal", "mail:\n  enabled: true\n  smtp: {addr: \"192.0.2.10:25\", tls_mode: none}\n  from: {address: no-reply@example.test}\n", "回环"},
		{"relative-root", "mail:\n  enabled: true\n  smtp: {addr: \"127.0.0.1:2525\", trusted_roots: [cert.pem]}\n  from: {address: no-reply@example.test}\n", "绝对路径"},
		{"bad-tls", "mail:\n  enabled: true\n  smtp: {addr: \"127.0.0.1:2525\", tls_mode: sslv3}\n  from: {address: no-reply@example.test}\n", "TLS"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := config.Load(config.LoadOptions{YAML: []byte(tc.yaml)})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("期望配置错误包含 %q，实际: %v", tc.want, err)
			}
		})
	}
}

// TestMailDisabledDoesNotReadSecrets 覆盖：关闭时密码来源指向不存在文件也合法。
func TestMailDisabledDoesNotReadSecrets(t *testing.T) {
	cfg, err := config.Load(config.LoadOptions{YAML: []byte(`
mail:
  enabled: false
  smtp:
    password: {file: "C:/does-not-exist/mail-password"}
`)})
	if err != nil {
		t.Fatalf("关闭邮件时不应读取秘密: %v", err)
	}
	if cfg.Mail.Enabled {
		t.Fatal("mail.enabled 默认/显式 false 不符")
	}
}

// TestMailEnvOverrides 覆盖步骤 139 M1：14 个 LOGIN_MAIL_* 环境变量真实生效
// （enabled/trusted_roots/password 等），非法值严格拒绝而不是静默忽略。
func TestMailEnvOverrides(t *testing.T) {
	valid := map[string]string{
		"LOGIN_MAIL_ENABLED":                    "true",
		"LOGIN_MAIL_SMTP_ADDR":                  "127.0.0.1:2525",
		"LOGIN_MAIL_SMTP_HOST":                  "mail.example.test",
		"LOGIN_MAIL_SMTP_TLS_MODE":              "starttls",
		"LOGIN_MAIL_SMTP_TRUSTED_ROOTS":         "C:/certs/root-a.pem,C:/certs/root-b.pem",
		"LOGIN_MAIL_SMTP_USERNAME":              "mailer",
		"LOGIN_MAIL_SMTP_PASSWORD":              "env:LOGIN_TEST_SMTP_PASSWORD",
		"LOGIN_MAIL_SMTP_TIMEOUT_SECONDS":       "12",
		"LOGIN_MAIL_SMTP_ALLOW_PLAINTEXT_LOCAL": "false",
		"LOGIN_MAIL_FROM_ADDRESS":               "no-reply@example.test",
		"LOGIN_MAIL_FROM_NAME":                  "EvernightLogin",
		"LOGIN_MAIL_APP_NAME":                   "LoginTest",
		"LOGIN_MAIL_DELIVERY_MAX_ATTEMPTS":      "4",
		"LOGIN_MAIL_DELIVERY_TIMEOUT_SECONDS":   "150",
	}
	lookup := func(name string) (string, bool) {
		value, ok := valid[name]
		return value, ok
	}
	cfg, err := config.Load(config.LoadOptions{LookupEnv: lookup})
	if err != nil {
		t.Fatalf("合法 LOGIN_MAIL_* 环境变量应生效: %v", err)
	}
	if !cfg.Mail.Enabled || cfg.Mail.SMTP.Addr != "127.0.0.1:2525" || cfg.Mail.SMTP.Host != "mail.example.test" ||
		cfg.Mail.SMTP.Username != "mailer" || cfg.Mail.From.Address != "no-reply@example.test" ||
		cfg.Mail.AppName != "LoginTest" || cfg.Mail.Delivery.MaxAttempts != 4 ||
		cfg.Mail.Delivery.TimeoutSeconds != 150 || cfg.Mail.SMTP.TimeoutSeconds != 12 {
		t.Fatalf("环境变量字段未生效: %+v", cfg.Mail)
	}
	if len(cfg.Mail.SMTP.TrustedRoots) != 2 || cfg.Mail.SMTP.TrustedRoots[0] != "C:/certs/root-a.pem" {
		t.Fatalf("trusted_roots 环境变量未生效: %+v", cfg.Mail.SMTP.TrustedRoots)
	}
	if cfg.Mail.SMTP.Password.Kind != config.SecretSourceEnv || cfg.Mail.SMTP.Password.Name != "LOGIN_TEST_SMTP_PASSWORD" {
		t.Fatalf("密码环境变量未按 SecretSource 解析: %+v", cfg.Mail.SMTP.Password)
	}

	cases := []struct {
		name   string
		change map[string]string
		want   string
	}{
		{"bad-enabled", map[string]string{"LOGIN_MAIL_ENABLED": "yes"}, "mail.enabled"},
		{"bad-timeout", map[string]string{"LOGIN_MAIL_SMTP_TIMEOUT_SECONDS": "abc"}, "mail.smtp.timeout_seconds"},
		{"relative-root", map[string]string{"LOGIN_MAIL_SMTP_TRUSTED_ROOTS": "root.pem"}, "绝对路径"},
		{"plaintext-password", map[string]string{"LOGIN_MAIL_SMTP_PASSWORD": "plain-password"}, "mail.smtp.password"},
		{"bad-max-attempts", map[string]string{"LOGIN_MAIL_DELIVERY_MAX_ATTEMPTS": "999"}, "最大尝试次数"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			overridden := map[string]string{}
			for key, value := range valid {
				overridden[key] = value
			}
			for key, value := range tc.change {
				overridden[key] = value
			}
			_, loadErr := config.Load(config.LoadOptions{LookupEnv: func(name string) (string, bool) {
				value, ok := overridden[name]
				return value, ok
			}})
			if loadErr == nil || !strings.Contains(loadErr.Error(), tc.want) {
				t.Fatalf("期望环境变量错误包含 %q，实际: %v", tc.want, loadErr)
			}
		})
	}
}

// TestMailPlaintextLoopbackAccepted 验证文档声明的“本机回环 + 显式
// allow_plaintext_local + tls_mode=none”明文邮件组合被接受（211 发现的既有校验
// bug：此前把已拆出的纯 host 再传入 listenAddrIsLoopback 导致恒 false）。
// 非回环地址仍必须拒绝。
func TestMailPlaintextLoopbackAccepted(t *testing.T) {
	const base = "mail:\n  enabled: true\n  from: {address: no-reply@example.test}\n  delivery: {max_attempts: 3, timeout_seconds: 120}\n"
	cases := []struct {
		name string
		addr string
	}{
		{"ipv4-loopback", "127.0.0.1:2525"},
		{"ipv6-loopback", "[::1]:2525"},
		{"localhost", "localhost:2525"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			yaml := base + "  smtp: {addr: \"" + tc.addr + "\", tls_mode: none, allow_plaintext_local: true, timeout_seconds: 10}\n"
			cfg, err := config.Load(config.LoadOptions{YAML: []byte(yaml)})
			if err != nil {
				t.Fatalf("本机回环明文邮件组合应被接受（%s）: %v", tc.addr, err)
			}
			if cfg.Mail.SMTP.TLSMode != "none" || !cfg.Mail.SMTP.AllowPlaintextLocal {
				t.Fatalf("明文本机邮件字段未生效: %+v", cfg.Mail.SMTP)
			}
		})
	}
	for _, tc := range []struct{ name, addr string }{
		{"non-loopback", "192.0.2.10:25"},
		{"wildcard-host", "0.0.0.0:25"},
	} {
		t.Run(tc.name+"-rejected", func(t *testing.T) {
			yaml := base + "  smtp: {addr: \"" + tc.addr + "\", tls_mode: none, allow_plaintext_local: true, timeout_seconds: 10}\n"
			if _, err := config.Load(config.LoadOptions{YAML: []byte(yaml)}); err == nil ||
				!strings.Contains(err.Error(), "回环") {
				t.Fatalf("非回环明文邮件必须拒绝（%s），实际: %v", tc.addr, err)
			}
		})
	}
	// 回环但未显式允许明文仍需拒绝（默认安全）。
	yaml := base + "  smtp: {addr: \"127.0.0.1:2525\", tls_mode: none, timeout_seconds: 10}\n"
	if _, err := config.Load(config.LoadOptions{YAML: []byte(yaml)}); err == nil ||
		!strings.Contains(err.Error(), "allow_plaintext_local") {
		t.Fatalf("回环但未显式允许明文必须拒绝，实际: %v", err)
	}
}
