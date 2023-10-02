package config_test

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/config"
)

// TestManualRecoveryConfigDefaultDisabled 验证制度默认关闭且默认参数有界。
func TestManualRecoveryConfigDefaultDisabled(t *testing.T) {
	cfg := config.Default()
	if cfg.ManualRecovery.Enabled {
		t.Fatal("人工恢复制度必须默认关闭")
	}
	if cfg.ManualRecovery.WaitPeriodSeconds != 24*60*60 ||
		cfg.ManualRecovery.ApprovalTTLSeconds != 48*60*60 ||
		cfg.ManualRecovery.RequestTTLSeconds != 7*24*60*60 {
		t.Fatalf("人工恢复默认时间参数不符: %+v", cfg.ManualRecovery)
	}
	// 步骤 209：默认保持 188 的 Passkey-only 重绑口径。
	if len(cfg.ManualRecovery.RebindMethods) != 1 ||
		cfg.ManualRecovery.RebindMethods[0] != "passkey" {
		t.Fatalf("重绑方法默认必须只有 passkey: %v", cfg.ManualRecovery.RebindMethods)
	}
}

// TestManualRecoveryConfigLoadValid 验证 YAML 字段真实解析。
func TestManualRecoveryConfigLoadValid(t *testing.T) {
	cfg, err := config.Load(config.LoadOptions{YAML: []byte(`
manual_recovery:
  enabled: true
  verification_bases: [in_person_identity_document, notarized_declaration]
  delivery_channels: [verified_email]
  rebind_methods: [passkey, totp]
  wait_period_seconds: 3600
  approval_ttl_seconds: 7200
  request_ttl_seconds: 36000
`)})
	if err != nil {
		t.Fatalf("合法人工恢复配置应加载: %v", err)
	}
	if !cfg.ManualRecovery.Enabled || len(cfg.ManualRecovery.VerificationBases) != 2 ||
		cfg.ManualRecovery.DeliveryChannels[0] != "verified_email" ||
		cfg.ManualRecovery.WaitPeriodSeconds != 3600 {
		t.Fatalf("人工恢复字段解析不符: %+v", cfg.ManualRecovery)
	}
	// 步骤 209：重绑方法类别列表真实解析且默认值被 YAML 覆盖。
	if len(cfg.ManualRecovery.RebindMethods) != 2 ||
		cfg.ManualRecovery.RebindMethods[0] != "passkey" ||
		cfg.ManualRecovery.RebindMethods[1] != "totp" {
		t.Fatalf("重绑方法解析不符: %v", cfg.ManualRecovery.RebindMethods)
	}
	// 未写 rebind_methods 时保留默认 Passkey-only。
	defaulted, err := config.Load(config.LoadOptions{YAML: []byte(`
manual_recovery:
  enabled: true
  verification_bases: [notarized_declaration]
  delivery_channels: [verified_email]
  wait_period_seconds: 3600
  approval_ttl_seconds: 7200
  request_ttl_seconds: 36000
`)})
	if err != nil {
		t.Fatalf("未配置重绑方法时应使用默认值: %v", err)
	}
	if len(defaulted.ManualRecovery.RebindMethods) != 1 ||
		defaulted.ManualRecovery.RebindMethods[0] != "passkey" {
		t.Fatalf("未配置时重绑方法应保持默认 passkey: %v", defaulted.ManualRecovery.RebindMethods)
	}
}

// TestManualRecoveryConfigInvalid 覆盖启用时的强依据/交付/时间边界。
func TestManualRecoveryConfigInvalid(t *testing.T) {
	cases := []struct {
		name, yaml, want string
	}{
		{"missing-basis", "manual_recovery:\n  enabled: true\n  delivery_channels: [verified_email]\n", "核验依据"},
		{"weak-basis", "manual_recovery:\n  enabled: true\n  verification_bases: [phone_statement]\n  delivery_channels: [verified_email]\n", "核验依据"},
		{"missing-delivery", "manual_recovery:\n  enabled: true\n  verification_bases: [notarized_declaration]\n", "交付渠道"},
		{"weak-delivery", "manual_recovery:\n  enabled: true\n  verification_bases: [notarized_declaration]\n  delivery_channels: [sms]\n", "交付渠道"},
		{"wait-too-long", "manual_recovery:\n  enabled: true\n  verification_bases: [notarized_declaration]\n  delivery_channels: [verified_email]\n  wait_period_seconds: 700000\n  approval_ttl_seconds: 7200\n  request_ttl_seconds: 36000\n", "等待期"},
		{"approval-not-after-wait", "manual_recovery:\n  enabled: true\n  verification_bases: [notarized_declaration]\n  delivery_channels: [verified_email]\n  wait_period_seconds: 3600\n  approval_ttl_seconds: 3600\n  request_ttl_seconds: 36000\n", "批准有效期"},
		{"request-too-short", "manual_recovery:\n  enabled: true\n  verification_bases: [notarized_declaration]\n  delivery_channels: [verified_email]\n  wait_period_seconds: 3600\n  approval_ttl_seconds: 7200\n  request_ttl_seconds: 7200\n", "申请有效期"},
		{"rebind-unknown", "manual_recovery:\n  enabled: true\n  verification_bases: [notarized_declaration]\n  delivery_channels: [verified_email]\n  rebind_methods: [sms]\n  wait_period_seconds: 3600\n  approval_ttl_seconds: 7200\n  request_ttl_seconds: 36000\n", "重绑方法"},
		{"rebind-duplicate", "manual_recovery:\n  enabled: true\n  verification_bases: [notarized_declaration]\n  delivery_channels: [verified_email]\n  rebind_methods: [passkey, passkey]\n  wait_period_seconds: 3600\n  approval_ttl_seconds: 7200\n  request_ttl_seconds: 36000\n", "重绑方法"},
		{"rebind-empty", "manual_recovery:\n  enabled: true\n  verification_bases: [notarized_declaration]\n  delivery_channels: [verified_email]\n  rebind_methods: []\n  wait_period_seconds: 3600\n  approval_ttl_seconds: 7200\n  request_ttl_seconds: 36000\n", "重绑方法"},
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
