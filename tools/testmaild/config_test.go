package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/testmail"
)

// writeConfigFile 在测试临时目录写入一个 YAML 配置文件并返回路径。
func writeConfigFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "testmaild.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("写入临时配置文件失败: %v", err)
	}
	return path
}

// TestLoadConfigExampleFile 验证示例配置文件可被严格解析，并与默认值区分开。
func TestLoadConfigExampleFile(t *testing.T) {
	cfg, err := loadConfigFile("config.example.yaml")
	if err != nil {
		t.Fatalf("示例配置解析失败: %v", err)
	}
	if cfg.Listen.Addr != "127.0.0.1:2525" {
		t.Errorf("listen.addr = %q, 期望 127.0.0.1:2525", cfg.Listen.Addr)
	}
	if cfg.Listen.Hostname != "testmail.local" {
		t.Errorf("listen.hostname = %q", cfg.Listen.Hostname)
	}
	if cfg.Listen.AllowNonLoopback {
		t.Error("示例配置不应允许非回环监听")
	}
	if cfg.Limits.MaxMessageBytes != 262144 {
		t.Errorf("limits.max_message_bytes = %d", cfg.Limits.MaxMessageBytes)
	}
	if cfg.Limits.ReadTimeout.Duration != 30*time.Second {
		t.Errorf("limits.read_timeout = %s", cfg.Limits.ReadTimeout.Duration)
	}
	if cfg.Limits.SessionTimeout.Duration != 5*time.Minute {
		t.Errorf("limits.session_timeout = %s", cfg.Limits.SessionTimeout.Duration)
	}
	if cfg.StartTLS.Enabled || cfg.StartTLS.CertFile != "" || cfg.StartTLS.KeyFile != "" {
		t.Errorf("示例配置默认不应启用 STARTTLS: %+v", cfg.StartTLS)
	}
	if cfg.Auth.RequireAuth || len(cfg.Auth.Accounts) != 2 {
		t.Errorf("示例账户配置异常: require_auth=%t accounts=%+v", cfg.Auth.RequireAuth, cfg.Auth.Accounts)
	}
	if cfg.Auth.Accounts[0].Username != "tester" || cfg.Auth.Accounts[0].Password != "test-pass" {
		t.Errorf("示例账户 0 异常: %+v", cfg.Auth.Accounts[0])
	}
	if outputLevel(cfg.Output.Level) != outputDetail {
		t.Errorf("output.level = %q, 期望 detail", cfg.Output.Level)
	}
	if !cfg.Output.PrintBody || cfg.Output.MaxBodyBytes != 8192 || cfg.Output.TraceSMTP {
		t.Errorf("示例输出配置异常: %+v", cfg.Output)
	}

	// 直接与默认值对比，确认示例文件确实覆盖了内置默认值。
	def := defaultFileConfig()
	if cfg.Listen.Addr == def.Listen.Addr {
		t.Error("示例配置的 listen.addr 不应等于默认值")
	}
	if outputLevel(cfg.Output.Level) == outputLevel(def.Output.Level) {
		t.Error("示例配置的 output.level 不应等于默认值")
	}
}

// TestLoadConfigFileDefaults 验证空配置文件等价于全部使用默认值。
func TestLoadConfigFileDefaults(t *testing.T) {
	path := writeConfigFile(t, "# 只有注释的空配置\n")
	cfg, err := loadConfigFile(path)
	if err != nil {
		t.Fatalf("空配置解析失败: %v", err)
	}
	def := defaultFileConfig()
	if cfg.Listen.Addr != def.Listen.Addr || cfg.Limits.MaxMessages != def.Limits.MaxMessages {
		t.Errorf("空配置未使用默认值: %+v", cfg)
	}
	if outputLevel(cfg.Output.Level) != outputSummary || cfg.Output.MaxBodyBytes != defaultMaxBodyBytes {
		t.Errorf("空配置输出默认值异常: %+v", cfg.Output)
	}
}

// TestLoadConfigFileErrors 验证配置解析与校验错误都带清晰中文提示。
func TestLoadConfigFileErrors(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "未知字段",
			content: "listen:\n  addr: \"127.0.0.1:0\"\n  unknown_option: true\n",
			want:    "unknown_option",
		},
		{
			name:    "字段类型错误",
			content: "limits:\n  max_messages: \"many\"\n",
			want:    "解析失败",
		},
		{
			name:    "重复键",
			content: "listen:\n  addr: \"127.0.0.1:0\"\n  addr: \"127.0.0.1:0\"\n",
			want:    "解析失败",
		},
		{
			name:    "时长格式错误",
			content: "limits:\n  read_timeout: \"30\"\n",
			want:    "时长",
		},
		{
			name:    "输出级别非法",
			content: "output:\n  level: verbose\n",
			want:    "output.level 必须是",
		},
		{
			name:    "正文上限非法",
			content: "output:\n  max_body_bytes: -1\n",
			want:    "max_body_bytes 必须在",
		},
		{
			name:    "保留消息数非法",
			content: "limits:\n  max_messages: 0\n",
			want:    "max_messages 必须在",
		},
		{
			name:    "证书文件缺一半",
			content: "starttls:\n  cert_file: \"cert.pem\"\n",
			want:    "必须同时给出",
		},
		{
			name:    "账户密码为空",
			content: "auth:\n  accounts:\n    - username: \"tester\"\n      password: \"\"\n",
			want:    "password 不能为空",
		},
		{
			name:    "账户用户名重复",
			content: "auth:\n  accounts:\n    - username: \"tester\"\n      password: \"a\"\n    - username: \"tester\"\n      password: \"b\"\n",
			want:    "重复",
		},
		{
			name:    "多个 YAML 文档",
			content: "listen:\n  addr: \"127.0.0.1:0\"\n---\nlisten:\n  addr: \"127.0.0.1:0\"\n",
			want:    "只能包含一个 YAML 文档",
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

// TestLoadConfigFileUnreadable 验证路径不存在或不是普通文件时给出中文错误。
func TestLoadConfigFileUnreadable(t *testing.T) {
	if _, err := loadConfigFile(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("不存在的配置文件应返回错误")
	} else if !strings.Contains(err.Error(), "无法访问配置文件") {
		t.Errorf("错误信息不清晰: %v", err)
	}
	if _, err := loadConfigFile(t.TempDir()); err == nil {
		t.Fatal("目录路径应返回错误")
	} else if !strings.Contains(err.Error(), "必须是普通文件") {
		t.Errorf("错误信息不清晰: %v", err)
	}
}

// TestResolveConfigDefaultPriority 验证默认值与命令行覆盖的基本优先级。
func TestResolveConfigDefaultPriority(t *testing.T) {
	base := defaultFileConfig()
	cfg, err := resolveConfig(base, cliOverrides{set: map[string]bool{}})
	if err != nil {
		t.Fatalf("默认配置解析失败: %v", err)
	}
	if cfg.Addr != testmail.DefaultAddr || cfg.Level != outputSummary || cfg.TraceSMTP {
		t.Errorf("默认配置异常: %+v", cfg)
	}
	if cfg.AccountSource != accountSourceNone || len(cfg.Accounts) != 0 {
		t.Errorf("默认配置不应有账户: %+v", cfg.Accounts)
	}

	// 配置文件覆盖默认值。
	fileCfg := base
	fileCfg.Listen.Addr = "127.0.0.1:2525"
	fileCfg.Limits.MaxMessages = 7
	fileCfg.Output.Level = string(outputDetail)
	cfg, err = resolveConfig(fileCfg, cliOverrides{set: map[string]bool{}})
	if err != nil {
		t.Fatalf("配置文件解析失败: %v", err)
	}
	if cfg.Addr != "127.0.0.1:2525" || cfg.MaxMessages != 7 || cfg.Level != outputDetail {
		t.Errorf("配置文件未覆盖默认值: %+v", cfg)
	}

	// 命令行覆盖配置文件。
	addr := "127.0.0.1:0"
	maxMessages := 9
	outputName := "summary"
	cfg, err = resolveConfig(fileCfg, cliOverrides{
		set:         map[string]bool{"addr": true, "max-messages": true, "output": true},
		addr:        &addr,
		maxMessages: &maxMessages,
		output:      &outputName,
	})
	if err != nil {
		t.Fatalf("命令行覆盖解析失败: %v", err)
	}
	if cfg.Addr != addr || cfg.MaxMessages != maxMessages || cfg.Level != outputSummary {
		t.Errorf("命令行未覆盖配置文件: %+v", cfg)
	}
}

// TestResolveConfigAuth 验证模拟账户与 require-auth 的来源优先级和校验。
func TestResolveConfigAuth(t *testing.T) {
	fileCfg := defaultFileConfig()
	fileCfg.Auth.RequireAuth = true
	fileCfg.Auth.Accounts = []testAccount{
		{Username: "file-a", Password: "a"},
		{Username: "file-b", Password: "b"},
	}
	cfg, err := resolveConfig(fileCfg, cliOverrides{set: map[string]bool{}})
	if err != nil {
		t.Fatalf("配置账户解析失败: %v", err)
	}
	if cfg.AccountSource != accountSourceConfig || len(cfg.Accounts) != 2 || !cfg.RequireAuth {
		t.Errorf("配置账户未生效: %+v", cfg)
	}

	// 命令行 -auth 整体替换配置账户。
	cfg, err = resolveConfig(fileCfg, cliOverrides{
		set:  map[string]bool{"auth": true},
		auth: credentials{"cli-a": "x", "cli-b": "y"},
	})
	if err != nil {
		t.Fatalf("命令行账户解析失败: %v", err)
	}
	if cfg.AccountSource != accountSourceCommand || len(cfg.Accounts) != 2 {
		t.Fatalf("命令行账户未生效: %+v", cfg)
	}
	if cfg.Accounts[0].Username != "cli-a" || cfg.Accounts[1].Username != "cli-b" {
		t.Errorf("命令行账户未按名称排序: %+v", cfg.Accounts)
	}

	// 命令行显式 -require-auth=false 覆盖配置文件。
	requireAuth := false
	cfg, err = resolveConfig(fileCfg, cliOverrides{
		set:         map[string]bool{"require-auth": true},
		requireAuth: &requireAuth,
	})
	if err != nil {
		t.Fatalf("require-auth 覆盖解析失败: %v", err)
	}
	if cfg.RequireAuth {
		t.Error("命令行 -require-auth=false 未覆盖配置文件")
	}

	// 要求认证但没有账户时必须报错。
	empty := defaultFileConfig()
	empty.Auth.RequireAuth = true
	if _, err := resolveConfig(empty, cliOverrides{set: map[string]bool{}}); err == nil {
		t.Fatal("require-auth 无账户应返回错误")
	} else if !strings.Contains(err.Error(), "没有配置任何测试账户") {
		t.Errorf("错误信息不清晰: %v", err)
	}
}

// TestResolveConfigStartTLSPrecedence 验证 STARTTLS 三种来源的优先级。
func TestResolveConfigStartTLSPrecedence(t *testing.T) {
	// 配置文件开启 STARTTLS：生成自签证书。
	fileCfg := defaultFileConfig()
	fileCfg.StartTLS.Enabled = true
	cfg, err := resolveConfig(fileCfg, cliOverrides{set: map[string]bool{}})
	if err != nil {
		t.Fatalf("STARTTLS 配置解析失败: %v", err)
	}
	if !cfg.StartTLSEnabled || cfg.TLSCertFile != "" {
		t.Errorf("配置 STARTTLS 未生效: %+v", cfg)
	}

	// 配置文件给出证书文件：视为启用，命令行 -starttls 可以覆盖。
	fileCfg.StartTLS.CertFile = "cert.pem"
	fileCfg.StartTLS.KeyFile = "key.pem"
	cfg, err = resolveConfig(fileCfg, cliOverrides{set: map[string]bool{}})
	if err != nil {
		t.Fatalf("证书文件配置解析失败: %v", err)
	}
	if cfg.TLSCertFile != "cert.pem" || cfg.TLSKeyFile != "key.pem" {
		t.Errorf("证书文件未生效: %+v", cfg)
	}
	disable := false
	cfg, err = resolveConfig(fileCfg, cliOverrides{
		set:      map[string]bool{"starttls": true},
		startTLS: &disable,
	})
	if err != nil {
		t.Fatalf("命令行 -starttls=false 解析失败: %v", err)
	}
	if cfg.StartTLSEnabled || cfg.TLSCertFile != "" {
		t.Errorf("命令行 -starttls=false 未关闭配置 STARTTLS: %+v", cfg)
	}

	// 命令行证书对必须同时给出。
	cert := "cli-cert.pem"
	emptyKey := ""
	if _, err := resolveConfig(defaultFileConfig(), cliOverrides{
		set:     map[string]bool{"tls-cert": true, "tls-key": true},
		tlsCert: &cert,
		tlsKey:  &emptyKey,
	}); err == nil {
		t.Fatal("只有证书没有私钥应返回错误")
	} else if !strings.Contains(err.Error(), "必须同时给出") {
		t.Errorf("错误信息不清晰: %v", err)
	}
}

// TestResolveConfigOutput 验证输出级别、正文上限与 SMTP 轨迹的合并规则。
func TestResolveConfigOutput(t *testing.T) {
	// debug 级别默认开启轨迹。
	fileCfg := defaultFileConfig()
	fileCfg.Output.Level = string(outputDebug)
	cfg, err := resolveConfig(fileCfg, cliOverrides{set: map[string]bool{}})
	if err != nil {
		t.Fatalf("debug 级别解析失败: %v", err)
	}
	if !cfg.TraceSMTP {
		t.Error("debug 级别应默认开启 SMTP 轨迹")
	}

	// 显式 -trace-smtp=false 可以关闭 debug 级别的轨迹。
	traceOff := false
	cfg, err = resolveConfig(fileCfg, cliOverrides{
		set:       map[string]bool{"trace-smtp": true},
		traceSMTP: &traceOff,
	})
	if err != nil {
		t.Fatalf("轨迹关闭解析失败: %v", err)
	}
	if cfg.TraceSMTP {
		t.Error("命令行 -trace-smtp=false 应关闭轨迹")
	}

	// 非法输出级别报错。
	badLevel := "verbose"
	if _, err := resolveConfig(defaultFileConfig(), cliOverrides{
		set:    map[string]bool{"output": true},
		output: &badLevel,
	}); err == nil {
		t.Fatal("非法输出级别应返回错误")
	} else if !strings.Contains(err.Error(), "--output 必须是") {
		t.Errorf("错误信息不清晰: %v", err)
	}

	// 正文上限为 0 表示不限制，负数报错。
	zero := 0
	cfg, err = resolveConfig(defaultFileConfig(), cliOverrides{
		set:       map[string]bool{"body-limit": true},
		bodyLimit: &zero,
	})
	if err != nil {
		t.Fatalf("正文上限 0 解析失败: %v", err)
	}
	if cfg.MaxBodyBytes != 0 {
		t.Errorf("正文上限 0 未生效: %d", cfg.MaxBodyBytes)
	}
	negative := -1
	if _, err := resolveConfig(defaultFileConfig(), cliOverrides{
		set:       map[string]bool{"body-limit": true},
		bodyLimit: &negative,
	}); err == nil {
		t.Fatal("正文上限为负应返回错误")
	}
}

// TestRunRejectsUnreadableConfig 验证 -config 指向不可用文件时在阻塞前报错。
func TestRunRejectsUnreadableConfig(t *testing.T) {
	var stdout, stderr syncBuffer
	err := run(t.Context(), []string{"-config", filepath.Join(t.TempDir(), "missing.yaml")}, &stdout, &stderr)
	if err == nil {
		t.Fatal("-config 指向不存在文件应返回错误")
	}
	if !strings.Contains(err.Error(), "无法访问配置文件") {
		t.Errorf("错误信息不清晰: %v", err)
	}
}
