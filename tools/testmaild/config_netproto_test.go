package main

import (
	"strings"
	"testing"
)

// TestLoadConfigExampleProtoSections 验证示例配置包含可直接运行的 IMAP/POP3
// 只读收件配置（默认回环随机端口、明文、需要模拟账户）。
func TestLoadConfigExampleProtoSections(t *testing.T) {
	cfg, err := loadConfigFile("config.example.yaml")
	if err != nil {
		t.Fatalf("示例配置解析失败: %v", err)
	}
	if !cfg.IMAP.Enabled {
		t.Error("示例配置应启用 IMAP 只读收件箱")
	}
	if cfg.IMAP.Addr != "127.0.0.1:0" {
		t.Errorf("示例 imap.addr = %q, 期望 127.0.0.1:0", cfg.IMAP.Addr)
	}
	if cfg.IMAP.TLS {
		t.Error("示例 imap.tls 应为 false（明文仅回环）")
	}
	if !cfg.POP3.Enabled {
		t.Error("示例配置应启用 POP3 只读收件箱")
	}
	if cfg.POP3.Addr != "127.0.0.1:0" {
		t.Errorf("示例 pop3.addr = %q, 期望 127.0.0.1:0", cfg.POP3.Addr)
	}
	if cfg.POP3.TLS {
		t.Error("示例 pop3.tls 应为 false")
	}
}

// TestLoadConfigFileProtoErrors 验证 IMAP/POP3 配置的严格错误提示。
func TestLoadConfigFileProtoErrors(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "IMAP明文非回环",
			content: "imap:\n  enabled: true\n  addr: \"0.0.0.0:1143\"\n",
			want:    "明文监听，只允许回环地址",
		},
		{
			name:    "POP3明文空主机名",
			content: "pop3:\n  enabled: true\n  addr: \":1110\"\n",
			want:    "明文监听，只允许回环地址",
		},
		{
			name:    "IMAP地址为空",
			content: "imap:\n  enabled: true\n  addr: \"\"\n",
			want:    "imap.addr 不能为空",
		},
		{
			name:    "IMAP未知字段",
			content: "imap:\n  enabled: true\n  addr: \"127.0.0.1:0\"\n  unknown_field: true\n",
			want:    "unknown_field",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeConfigFile(t, tc.content)
			if _, err := loadConfigFile(path); err == nil {
				t.Fatalf("配置 %q 应返回错误", tc.content)
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("错误信息应包含 %q，实际: %v", tc.want, err)
			}
		})
	}
}

// TestResolveConfigProto 验证 IMAP/POP3 的默认值、配置文件与命令行优先级，
// 以及“需要模拟账户”“明文非回环”两条强制校验。
func TestResolveConfigProto(t *testing.T) {
	// 默认关闭，地址为默认回环随机端口。
	cfg, err := resolveConfig(defaultFileConfig(), cliOverrides{set: map[string]bool{}})
	if err != nil {
		t.Fatalf("默认配置解析失败: %v", err)
	}
	if cfg.IMAP.Enabled || cfg.POP3.Enabled {
		t.Errorf("默认不应启用 IMAP/POP3: %+v %+v", cfg.IMAP, cfg.POP3)
	}
	if cfg.IMAP.Addr == "" || cfg.POP3.Addr == "" {
		t.Errorf("默认 IMAP/POP3 地址不应为空: %+v %+v", cfg.IMAP, cfg.POP3)
	}

	// 配置文件启用（有账户）可通过。
	fileCfg := defaultFileConfig()
	fileCfg.Auth.Accounts = []testAccount{{Username: "tester", Password: "test-pass"}}
	fileCfg.IMAP = protoSection{Enabled: true, Addr: "127.0.0.1:1143"}
	fileCfg.POP3 = protoSection{Enabled: true, Addr: "127.0.0.1:1110", TLS: true}
	cfg, err = resolveConfig(fileCfg, cliOverrides{set: map[string]bool{}})
	if err != nil {
		t.Fatalf("配置文件启用 IMAP/POP3 失败: %v", err)
	}
	if !cfg.IMAP.Enabled || cfg.IMAP.Addr != "127.0.0.1:1143" || cfg.IMAP.TLS {
		t.Errorf("配置文件 IMAP 未生效: %+v", cfg.IMAP)
	}
	if !cfg.POP3.Enabled || cfg.POP3.Addr != "127.0.0.1:1110" || !cfg.POP3.TLS {
		t.Errorf("配置文件 POP3 未生效: %+v", cfg.POP3)
	}

	// 命令行显式覆盖启用状态、地址与 TLS。
	enabled := true
	addr := "127.0.0.1:0"
	tlsOn := true
	cfg, err = resolveConfig(defaultFileConfig(), cliOverrides{
		set: map[string]bool{
			"imap": true, "imap-addr": true, "imap-tls": true,
			"pop3": true, "pop3-addr": true, "pop3-tls": true,
			"auth": true,
		},
		auth:     credentials{"cli-user": "cli-pass"},
		imap:     &enabled,
		imapAddr: &addr,
		imapTLS:  &tlsOn,
		pop3:     &enabled,
		pop3Addr: &addr,
		pop3TLS:  &tlsOn,
	})
	if err != nil {
		t.Fatalf("命令行覆盖 IMAP/POP3 失败: %v", err)
	}
	if !cfg.IMAP.Enabled || cfg.IMAP.Addr != addr || !cfg.IMAP.TLS {
		t.Errorf("命令行 IMAP 覆盖未生效: %+v", cfg.IMAP)
	}
	if !cfg.POP3.Enabled || cfg.POP3.Addr != addr || !cfg.POP3.TLS {
		t.Errorf("命令行 POP3 覆盖未生效: %+v", cfg.POP3)
	}

	// 启用但没有模拟账户必须报错。
	noAccounts := defaultFileConfig()
	noAccounts.IMAP = protoSection{Enabled: true, Addr: "127.0.0.1:0"}
	if _, err := resolveConfig(noAccounts, cliOverrides{set: map[string]bool{}}); err == nil {
		t.Fatal("启用 IMAP 但没有模拟账户应返回错误")
	} else if !strings.Contains(err.Error(), "需要模拟账户") {
		t.Errorf("错误信息不清晰: %v", err)
	}

	// 明文非回环（命令行）必须报错，即使显式允许非回环也不行。
	nonLoopback := "0.0.0.0:1143"
	allowNonLoopback := true
	if _, err := resolveConfig(defaultFileConfig(), cliOverrides{
		set:              map[string]bool{"imap": true, "imap-addr": true, "auth": true, "allow-non-loopback": true},
		auth:             credentials{"cli-user": "cli-pass"},
		imap:             &enabled,
		imapAddr:         &nonLoopback,
		allowNonLoopback: &allowNonLoopback,
	}); err == nil {
		t.Fatal("明文 IMAP 非回环地址应返回错误")
	} else if !strings.Contains(err.Error(), "明文监听只允许回环地址") {
		t.Errorf("错误信息不清晰: %v", err)
	}

	// TLS 显式开启 + 非回环地址可以通过配置合并（实际绑定仍由 testmail 复核）。
	tlsFile := defaultFileConfig()
	tlsFile.Auth.Accounts = []testAccount{{Username: "tester", Password: "test-pass"}}
	tlsFile.IMAP = protoSection{Enabled: true, Addr: "0.0.0.0:1143", TLS: true}
	if _, err := resolveConfig(tlsFile, cliOverrides{set: map[string]bool{}}); err != nil {
		t.Errorf("TLS + 非回环地址不应在合并阶段被拒绝: %v", err)
	}
}
