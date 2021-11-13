package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"

	"github.com/kagurazakayashi/EvernightLogin/internal/testmail"
)

// maxConfigFileBytes 是 testmaild 配置文件大小上限，避免误读大文件或设备文件。
const maxConfigFileBytes = 1 << 20

// defaultMaxBodyBytes 是详细输出中正文默认最多打印的字节数。
const defaultMaxBodyBytes = 4096

// outputLevel 是消息输出详细程度。
type outputLevel string

const (
	// outputSummary 只打印一行摘要，保持工具原有默认行为。
	outputSummary outputLevel = "summary"
	// outputDetail 额外打印完整信封、全部原始头部、解析字段、字节数与可选正文。
	outputDetail outputLevel = "detail"
	// outputDebug 在 detail 基础上默认开启会话级 SMTP 命令轨迹。
	outputDebug outputLevel = "debug"
)

// 账户来源，用于启动信息中决定是否回显配置里的模拟测试密码。
const (
	accountSourceNone    = "无"
	accountSourceConfig  = "配置文件"
	accountSourceCommand = "命令行 -auth"
)

// fileConfig 是 YAML 配置文件的解码目标。
//
// 解码前先写入默认值，因此未出现的字段保留默认值；命令行显式给出的参数在
// resolveConfig 中覆盖解码结果。这样优先级自然是“命令行 > 配置文件 > 默认值”。
type fileConfig struct {
	Listen   listenSection   `yaml:"listen"`
	Limits   limitsSection   `yaml:"limits"`
	StartTLS startTLSSection `yaml:"starttls"`
	Auth     authSection     `yaml:"auth"`
	Output   outputSection   `yaml:"output"`
	IMAP     protoSection    `yaml:"imap"`
	POP3     protoSection    `yaml:"pop3"`
}

// listenSection 是监听相关配置。
type listenSection struct {
	Addr             string `yaml:"addr"`
	Hostname         string `yaml:"hostname"`
	AllowNonLoopback bool   `yaml:"allow_non_loopback"`
}

// limitsSection 是资源与协议限制配置。
type limitsSection struct {
	MaxMessageBytes int          `yaml:"max_message_bytes"`
	MaxRecipients   int          `yaml:"max_recipients"`
	MaxConnections  int          `yaml:"max_connections"`
	MaxMessages     int          `yaml:"max_messages"`
	ReadTimeout     yamlDuration `yaml:"read_timeout"`
	SessionTimeout  yamlDuration `yaml:"session_timeout"`
}

// startTLSSection 是 STARTTLS 配置。
type startTLSSection struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// authSection 是模拟邮件账户配置。
type authSection struct {
	RequireAuth bool          `yaml:"require_auth"`
	Accounts    []testAccount `yaml:"accounts"`
}

// testAccount 是一个模拟测试账户（用户名 + 测试密码，不是真实凭据）。
type testAccount struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// protoSection 是只读收件协议（IMAP/POP3）配置。
//
// 两个协议共用 auth.accounts 中的模拟账户：邮件按信封收件人与 To/Cc/Bcc 的本地
// 部分映射到账户收件箱，非收件账户不可见；服务端拒绝全部写操作。明文监听只允许
// 回环地址；非回环监听必须同时开启 tls 并显式 allow_non_loopback。
type protoSection struct {
	// Enabled 是否启动该协议监听器；默认 false。
	Enabled bool `yaml:"enabled"`
	// Addr 是监听地址 host:port；空字符串表示默认仅回环随机端口。
	Addr string `yaml:"addr"`
	// TLS 是否使用隐式 TLS（整条连接从建立即加密）。证书复用 starttls 段的
	// cert_file/key_file；未提供证书文件时自动生成一次性自签测试证书。
	TLS bool `yaml:"tls"`
}

// outputSection 是输出详细程度配置。
type outputSection struct {
	Level        string `yaml:"level"`
	PrintBody    bool   `yaml:"print_body"`
	MaxBodyBytes int    `yaml:"max_body_bytes"`
	TraceSMTP    bool   `yaml:"trace_smtp"`
}

// yamlDuration 接受 "30s"、"5m" 这类 Go 时长字符串，并在解析失败时给出中文提示。
type yamlDuration struct {
	time.Duration
}

// UnmarshalYAML 实现 YAML 自定义解析，让时长字段能直接写 "30s"。
func (d *yamlDuration) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("必须是时长字符串（示例：30s、5m）")
	}
	parsed, err := time.ParseDuration(strings.TrimSpace(value.Value))
	if err != nil {
		return fmt.Errorf("不是合法的时长（示例：30s、5m、500ms）：%w", err)
	}
	d.Duration = parsed
	return nil
}

// defaultFileConfig 返回与 internal/testmail 默认值一致的配置。
func defaultFileConfig() fileConfig {
	return fileConfig{
		Listen: listenSection{
			Addr:     testmail.DefaultAddr,
			Hostname: testmail.DefaultHostname,
		},
		Limits: limitsSection{
			MaxMessageBytes: testmail.DefaultMaxMessageBytes,
			MaxRecipients:   testmail.DefaultMaxRecipients,
			MaxConnections:  testmail.DefaultMaxConnections,
			MaxMessages:     testmail.DefaultMaxMessages,
			ReadTimeout:     yamlDuration{testmail.DefaultReadTimeout},
			SessionTimeout:  yamlDuration{testmail.DefaultSessionTimeout},
		},
		Output: outputSection{
			Level:        string(outputSummary),
			MaxBodyBytes: defaultMaxBodyBytes,
		},
		IMAP: protoSection{Addr: testmail.DefaultIMAPAddr},
		POP3: protoSection{Addr: testmail.DefaultPOP3Addr},
	}
}

// loadConfigFile 读取并严格解析 YAML 配置文件。
//
// 严格模式拒绝未知字段、重复键与类型不匹配，避免拼写错误被静默忽略；全部错误都
// 带上文件路径与中文说明。空文件等价于全部使用默认值。
func loadConfigFile(path string) (fileConfig, error) {
	cfg := defaultFileConfig()
	info, err := os.Stat(path)
	if err != nil {
		return cfg, fmt.Errorf("无法访问配置文件 %q：%w", path, err)
	}
	if !info.Mode().IsRegular() {
		return cfg, fmt.Errorf("配置文件 %q 必须是普通文件", path)
	}
	if info.Size() > maxConfigFileBytes {
		return cfg, fmt.Errorf("配置文件 %q 超过 %d 字节上限", path, maxConfigFileBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("无法读取配置文件 %q：%w", path, err)
	}
	if len(data) > maxConfigFileBytes {
		return cfg, fmt.Errorf("配置文件 %q 超过 %d 字节上限", path, maxConfigFileBytes)
	}

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return cfg, fmt.Errorf("配置文件 %q 解析失败：%v\n请对照 tools/testmaild/config.example.yaml 检查字段名、缩进与取值类型", path, err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return cfg, fmt.Errorf("配置文件 %q 只能包含一个 YAML 文档，请删除多余的 --- 文档分隔", path)
	} else if !errors.Is(err, io.EOF) {
		return cfg, fmt.Errorf("配置文件 %q 解析失败：%v", path, err)
	}
	if err := validateFileConfig(cfg, path); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// validateFileConfig 校验配置文件中的取值，给出带字段名与文件路径的中文提示。
func validateFileConfig(cfg fileConfig, path string) error {
	fail := func(format string, args ...any) error {
		return fmt.Errorf("配置文件 %q：%s", path, fmt.Sprintf(format, args...))
	}
	if strings.TrimSpace(cfg.Listen.Addr) == "" {
		return fail("listen.addr 不能为空（示例：127.0.0.1:2525）")
	}
	if strings.TrimSpace(cfg.Listen.Hostname) == "" {
		return fail("listen.hostname 不能为空（示例：testmail.local）")
	}
	if cfg.Limits.MaxMessageBytes < testmail.MinMaxMessageBytes || cfg.Limits.MaxMessageBytes > testmail.MaxMaxMessageBytes {
		return fail("limits.max_message_bytes 必须在 %d～%d 之间", testmail.MinMaxMessageBytes, testmail.MaxMaxMessageBytes)
	}
	if cfg.Limits.MaxRecipients < testmail.MinMaxRecipients || cfg.Limits.MaxRecipients > testmail.MaxMaxRecipients {
		return fail("limits.max_recipients 必须在 %d～%d 之间", testmail.MinMaxRecipients, testmail.MaxMaxRecipients)
	}
	if cfg.Limits.MaxConnections < testmail.MinMaxConnections || cfg.Limits.MaxConnections > testmail.MaxMaxConnections {
		return fail("limits.max_connections 必须在 %d～%d 之间", testmail.MinMaxConnections, testmail.MaxMaxConnections)
	}
	if cfg.Limits.MaxMessages < testmail.MinMaxMessages || cfg.Limits.MaxMessages > testmail.MaxMaxMessages {
		return fail("limits.max_messages 必须在 %d～%d 之间", testmail.MinMaxMessages, testmail.MaxMaxMessages)
	}
	if cfg.Limits.ReadTimeout.Duration < testmail.MinTimeout || cfg.Limits.ReadTimeout.Duration > testmail.MaxTimeout {
		return fail("limits.read_timeout 必须在 %s～%s 之间", testmail.MinTimeout, testmail.MaxTimeout)
	}
	if cfg.Limits.SessionTimeout.Duration < testmail.MinTimeout || cfg.Limits.SessionTimeout.Duration > testmail.MaxTimeout {
		return fail("limits.session_timeout 必须在 %s～%s 之间", testmail.MinTimeout, testmail.MaxTimeout)
	}
	switch outputLevel(cfg.Output.Level) {
	case outputSummary, outputDetail, outputDebug:
	default:
		return fail("output.level 必须是 summary、detail 或 debug，实际为 %q", cfg.Output.Level)
	}
	if cfg.Output.MaxBodyBytes < 0 || cfg.Output.MaxBodyBytes > testmail.MaxMaxMessageBytes {
		return fail("output.max_body_bytes 必须在 0～%d 之间（0 表示不限制）", testmail.MaxMaxMessageBytes)
	}
	if (cfg.StartTLS.CertFile == "") != (cfg.StartTLS.KeyFile == "") {
		return fail("starttls.cert_file 与 starttls.key_file 必须同时给出")
	}
	for _, proto := range []struct {
		name    string
		section protoSection
	}{{"imap", cfg.IMAP}, {"pop3", cfg.POP3}} {
		if strings.TrimSpace(proto.section.Addr) == "" {
			return fail("%s.addr 不能为空（默认 %s，示例：127.0.0.1:0 或 127.0.0.1:1143）",
				proto.name, testmail.DefaultIMAPAddr)
		}
		if !proto.section.TLS && !isLoopbackListenAddr(proto.section.Addr) {
			return fail("%s.addr %q 是明文监听，只允许回环地址；如需非回环请设置 %s.tls: true 并在 listen.allow_non_loopback 中显式允许",
				proto.name, proto.section.Addr, proto.name)
		}
	}
	seen := make(map[string]string, len(cfg.Auth.Accounts))
	for i, account := range cfg.Auth.Accounts {
		name := strings.TrimSpace(account.Username)
		if name == "" {
			return fail("auth.accounts[%d].username 不能为空", i)
		}
		if account.Password == "" {
			return fail("auth.accounts[%d].password 不能为空（仅用于本地测试，不要填真实密码）", i)
		}
		key := normalizeTestAccountName(name)
		if existing, dup := seen[key]; dup {
			if existing == name {
				return fail("auth.accounts 中用户名 %q 重复", name)
			}
			return fail("auth.accounts 中用户名 %q 与 %q 在大小写/Unicode 归一化后相同，会导致收件箱归属歧义；请使用互不相同的用户名", name, existing)
		}
		seen[key] = name
	}
	return nil
}

// cliOverrides 记录命令行显式给出的参数。
//
// 只有被 flag 解析器实际访问（fs.Visit）过的参数才视为显式，未显式给出的参数不会
// 覆盖配置文件，从而保留现有 flag 默认值的兼容行为。
type cliOverrides struct {
	set              map[string]bool
	addr             *string
	hostname         *string
	allowNonLoopback *bool
	maxMessageBytes  *int
	maxRecipients    *int
	maxConnections   *int
	maxMessages      *int
	readTimeout      *time.Duration
	sessionTimeout   *time.Duration
	startTLS         *bool
	tlsCert          *string
	tlsKey           *string
	requireAuth      *bool
	auth             credentials
	printBody        *bool
	output           *string
	bodyLimit        *int
	traceSMTP        *bool
	imap             *bool
	imapAddr         *string
	imapTLS          *bool
	pop3             *bool
	pop3Addr         *string
	pop3TLS          *bool
}

// has 报告某个 flag 是否被命令行显式给出。
func (c cliOverrides) has(name string) bool {
	return c.set[name]
}

// runConfig 是合并优先级之后的运行配置。
type runConfig struct {
	Addr             string
	Hostname         string
	AllowNonLoopback bool
	MaxMessageBytes  int
	MaxRecipients    int
	MaxConnections   int
	MaxMessages      int
	ReadTimeout      time.Duration
	SessionTimeout   time.Duration
	StartTLSEnabled  bool
	TLSCertFile      string
	TLSKeyFile       string
	Accounts         []testAccount
	AccountSource    string
	RequireAuth      bool
	Level            outputLevel
	PrintBody        bool
	MaxBodyBytes     int
	TraceSMTP        bool
	ConfigPath       string
	// IMAP/POP3 是只读收件协议运行配置。
	IMAP protoRuntime
	POP3 protoRuntime
}

// protoRuntime 是合并后的 IMAP/POP3 运行配置。
type protoRuntime struct {
	Enabled bool
	Addr    string
	TLS     bool
}

// sourceDescription 返回启动信息中的配置来源说明。
func (c runConfig) sourceDescription() string {
	if c.ConfigPath == "" {
		return "默认值"
	}
	return "配置文件 " + c.ConfigPath + "（命令行显式参数优先）"
}

// resolveConfig 按“命令行 > 配置文件 > 默认值”合并配置，并做与来源无关的最终校验。
func resolveConfig(fileCfg fileConfig, cli cliOverrides) (runConfig, error) {
	cfg := runConfig{
		Addr:             fileCfg.Listen.Addr,
		Hostname:         fileCfg.Listen.Hostname,
		AllowNonLoopback: fileCfg.Listen.AllowNonLoopback,
		MaxMessageBytes:  fileCfg.Limits.MaxMessageBytes,
		MaxRecipients:    fileCfg.Limits.MaxRecipients,
		MaxConnections:   fileCfg.Limits.MaxConnections,
		MaxMessages:      fileCfg.Limits.MaxMessages,
		ReadTimeout:      fileCfg.Limits.ReadTimeout.Duration,
		SessionTimeout:   fileCfg.Limits.SessionTimeout.Duration,
		StartTLSEnabled:  fileCfg.StartTLS.Enabled,
		TLSCertFile:      fileCfg.StartTLS.CertFile,
		TLSKeyFile:       fileCfg.StartTLS.KeyFile,
		RequireAuth:      fileCfg.Auth.RequireAuth,
		Level:            outputLevel(fileCfg.Output.Level),
		PrintBody:        fileCfg.Output.PrintBody,
		MaxBodyBytes:     fileCfg.Output.MaxBodyBytes,
		TraceSMTP:        fileCfg.Output.TraceSMTP,
		IMAP: protoRuntime{
			Enabled: fileCfg.IMAP.Enabled,
			Addr:    fileCfg.IMAP.Addr,
			TLS:     fileCfg.IMAP.TLS,
		},
		POP3: protoRuntime{
			Enabled: fileCfg.POP3.Enabled,
			Addr:    fileCfg.POP3.Addr,
			TLS:     fileCfg.POP3.TLS,
		},
	}

	// 监听与限制：命令行显式值覆盖配置文件。
	if cli.has("addr") {
		cfg.Addr = *cli.addr
	}
	if cli.has("hostname") {
		cfg.Hostname = *cli.hostname
	}
	if cli.has("allow-non-loopback") {
		cfg.AllowNonLoopback = *cli.allowNonLoopback
	}
	if cli.has("max-message-bytes") {
		cfg.MaxMessageBytes = *cli.maxMessageBytes
	}
	if cli.has("max-recipients") {
		cfg.MaxRecipients = *cli.maxRecipients
	}
	if cli.has("max-connections") {
		cfg.MaxConnections = *cli.maxConnections
	}
	if cli.has("max-messages") {
		cfg.MaxMessages = *cli.maxMessages
	}
	if cli.has("read-timeout") {
		cfg.ReadTimeout = *cli.readTimeout
	}
	if cli.has("session-timeout") {
		cfg.SessionTimeout = *cli.sessionTimeout
	}

	// 模拟账户：命令行 -auth 一旦出现就整体替换配置文件中的账户（避免半合并歧义）。
	switch {
	case len(cli.auth) > 0:
		names := make([]string, 0, len(cli.auth))
		for name := range cli.auth {
			names = append(names, name)
		}
		sort.Strings(names)
		cfg.Accounts = make([]testAccount, 0, len(names))
		for _, name := range names {
			cfg.Accounts = append(cfg.Accounts, testAccount{Username: name, Password: cli.auth[name]})
		}
		cfg.AccountSource = accountSourceCommand
	case len(fileCfg.Auth.Accounts) > 0:
		cfg.Accounts = append([]testAccount(nil), fileCfg.Auth.Accounts...)
		cfg.AccountSource = accountSourceConfig
	default:
		cfg.AccountSource = accountSourceNone
	}
	seenAccounts := make(map[string]string, len(cfg.Accounts))
	for _, account := range cfg.Accounts {
		key := normalizeTestAccountName(account.Username)
		if existing, dup := seenAccounts[key]; dup && existing != account.Username {
			return runConfig{}, fmt.Errorf("模拟账户用户名 %q 与 %q 在大小写/Unicode 归一化后相同，会导致收件箱归属歧义；请使用互不相同的用户名",
				account.Username, existing)
		}
		seenAccounts[key] = account.Username
	}
	if cli.has("require-auth") {
		cfg.RequireAuth = *cli.requireAuth
	}
	if cfg.RequireAuth && len(cfg.Accounts) == 0 {
		return runConfig{}, errors.New("要求先认证但没有配置任何测试账户：请用 -auth user:password（可重复）或配置文件 auth.accounts 添加")
	}

	// STARTTLS 来源优先级：命令行证书对 > 命令行 -starttls > 配置文件。
	switch {
	case cli.has("tls-cert") || cli.has("tls-key"):
		cfg.TLSCertFile = *cli.tlsCert
		cfg.TLSKeyFile = *cli.tlsKey
		cfg.StartTLSEnabled = false
		if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
			return runConfig{}, errors.New("--tls-cert 与 --tls-key 必须同时给出")
		}
	case cli.has("starttls"):
		cfg.StartTLSEnabled = *cli.startTLS
		cfg.TLSCertFile = ""
		cfg.TLSKeyFile = ""
	default:
		if cfg.TLSCertFile != "" || cfg.TLSKeyFile != "" {
			if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
				return runConfig{}, errors.New("配置文件 starttls.cert_file 与 starttls.key_file 必须同时给出")
			}
			// 给出证书文件即表示启用 STARTTLS（与命令行行为一致）。
			cfg.StartTLSEnabled = false
		}
	}

	// 只读收件协议（IMAP/POP3）：命令行显式值覆盖配置文件。
	if cli.has("imap") {
		cfg.IMAP.Enabled = *cli.imap
	}
	if cli.has("imap-addr") {
		cfg.IMAP.Addr = *cli.imapAddr
	}
	if cli.has("imap-tls") {
		cfg.IMAP.TLS = *cli.imapTLS
	}
	if cli.has("pop3") {
		cfg.POP3.Enabled = *cli.pop3
	}
	if cli.has("pop3-addr") {
		cfg.POP3.Addr = *cli.pop3Addr
	}
	if cli.has("pop3-tls") {
		cfg.POP3.TLS = *cli.pop3TLS
	}
	for _, proto := range []struct {
		name string
		cfg  protoRuntime
	}{{"IMAP", cfg.IMAP}, {"POP3", cfg.POP3}} {
		if !proto.cfg.Enabled {
			continue
		}
		if len(cfg.Accounts) == 0 {
			return runConfig{}, fmt.Errorf("%s 只读收件箱需要模拟账户：请用 -auth user:password（可重复）或配置文件 auth.accounts 添加", proto.name)
		}
		if !proto.cfg.TLS && !isLoopbackListenAddr(proto.cfg.Addr) {
			return runConfig{}, fmt.Errorf("%s 明文监听只允许回环地址（当前 %q）；如确需非回环监听请启用 TLS 并显式 allow-non-loopback",
				proto.name, proto.cfg.Addr)
		}
	}

	// 输出详细程度。
	if cli.has("output") {
		level := outputLevel(*cli.output)
		switch level {
		case outputSummary, outputDetail, outputDebug:
			cfg.Level = level
		default:
			return runConfig{}, fmt.Errorf("--output 必须是 summary、detail 或 debug，实际为 %q", *cli.output)
		}
	}
	if cfg.Level == "" {
		cfg.Level = outputSummary
	}
	if cli.has("print-body") {
		cfg.PrintBody = *cli.printBody
	}
	if cli.has("body-limit") {
		cfg.MaxBodyBytes = *cli.bodyLimit
	}
	if cfg.MaxBodyBytes < 0 || cfg.MaxBodyBytes > testmail.MaxMaxMessageBytes {
		return runConfig{}, fmt.Errorf("正文长度上限必须在 0～%d 之间（0 表示不限制）", testmail.MaxMaxMessageBytes)
	}
	if cli.has("trace-smtp") {
		cfg.TraceSMTP = *cli.traceSMTP
	}
	if cfg.Level == outputDebug && !cli.has("trace-smtp") {
		cfg.TraceSMTP = true
	}
	return cfg, nil
}

// isLoopbackListenAddr 判断监听地址是否回环（host:port 形式，空主机名不算回环）。
// 只用于在解析配置阶段给出更早、更清晰的中文错误；最终绑定仍由 internal/testmail
// 在 Listen 之后复核，双重校验不可绕过。
func isLoopbackListenAddr(addr string) bool {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil || portText == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return false
	}
	return ip.IsLoopback()
}

// normalizeTestAccountName 返回模拟账户用户名的唯一性比较键：NFKC + 大小写折叠
// + NFC，与 internal/testmail 的配置校验口径一致，用于在工具层提前给出中文错误。
func normalizeTestAccountName(name string) string {
	compatibility := norm.NFKC.String(name)
	folded := cases.Fold().String(compatibility)
	return norm.NFC.String(folded)
}
