// Command testmaild 启动一个本地测试邮件服务器，用于人工验收与调试邮件相关功能。
//
// 它提供 SMTP 收信，并可选用只读 IMAP/POP3 收件箱（按模拟账户隔离），让
// Thunderbird、Outlook、Foxmail 等真实邮件客户端连接查看测试邮件。
//
// 它只做装配与运行：解析命令行参数与可选 YAML 配置文件、构造 internal/testmail
// 服务器、打印实际监听地址、模拟账户清单与各协议客户端连接参数，收到消息时按配置
// 的详细程度打印摘要或完整内容。它不导入任何产品业务逻辑，也不会被
// cmd/login-server 装配；生产服务器不会启动本工具。
//
// 默认只监听 127.0.0.1 的随机端口；不向任何真实地址投递邮件。配置文件的字段与
// 中文注释见同目录的 config.example.yaml，完整使用说明见同目录的 README.md。
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"github.com/kagurazakayashi/EvernightLogin/internal/testmail"
)

func main() {
	// 只处理可捕获的退出信号：Ctrl+C（os.Interrupt）与 SIGTERM。收到后关闭
	// 监听、断开活动会话并释放端口，再返回。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "testmaild: %v\n", err)
		os.Exit(1)
	}
}

// credentials 是 --auth 可重复使用的测试凭据集合。
type credentials map[string]string

func (c credentials) String() string {
	if len(c) == 0 {
		return ""
	}
	names := make([]string, 0, len(c))
	for name := range c {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

// Set 解析 user:password 形式的测试凭据。这里接受明文测试密码是设计前提：服务器
// 只应在回环地址上运行，且这些凭据不是任何真实服务凭据。
func (c credentials) Set(v string) error {
	name, pass, ok := strings.Cut(v, ":")
	if !ok || name == "" || pass == "" {
		return errors.New("格式必须是 user:password，且用户名与密码都不能为空")
	}
	if _, exists := c[name]; exists {
		return fmt.Errorf("用户 %q 重复配置", name)
	}
	c[name] = pass
	return nil
}

// run 是工具的主体（可被测试直接调用）：装配服务器、打印信息、等待 ctx 结束并
// 优雅关闭。stdout/stderr 可注入，便于测试断言输出而不依赖真实终端。
func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("testmaild", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "用法: testmaild [选项]\n\n")
		fmt.Fprintf(stderr, "只用于测试的本地邮件服务器：SMTP 收信，可选只读 IMAP/POP3 收件箱；\n")
		fmt.Fprintf(stderr, "消息只保存在内存中，不投递、不中继。\n")
		fmt.Fprintf(stderr, "优先级：命令行参数 > 配置文件（-config）> 内置默认值。\n\n")
		fmt.Fprintf(stderr, "选项:\n")
		fs.PrintDefaults()
	}

	configPath := fs.String("config", "", "YAML 配置文件路径（字段与中文注释见 config.example.yaml）")
	addr := fs.String("addr", testmail.DefaultAddr, "监听地址；默认仅回环随机端口")
	hostname := fs.String("hostname", testmail.DefaultHostname, "SMTP 问候语使用的主机名")
	allowNonLoopback := fs.Bool("allow-non-loopback", false, "显式允许监听非回环地址（仍然只做本地捕获）")
	maxMessageBytes := fs.Int("max-message-bytes", testmail.DefaultMaxMessageBytes, "单条消息字节上限")
	maxRecipients := fs.Int("max-recipients", testmail.DefaultMaxRecipients, "单条消息收件人上限")
	maxConnections := fs.Int("max-connections", testmail.DefaultMaxConnections, "最大并发连接数")
	maxMessages := fs.Int("max-messages", testmail.DefaultMaxMessages, "内存中最多保留的消息数")
	readTimeout := fs.Duration("read-timeout", testmail.DefaultReadTimeout, "单次读取超时")
	sessionTimeout := fs.Duration("session-timeout", testmail.DefaultSessionTimeout, "单连接总时长上限")
	startsTLS := fs.Bool("starttls", false, "启用 STARTTLS 并生成临时自签测试证书")
	certFile := fs.String("tls-cert", "", "STARTTLS 证书 PEM 文件（与 --tls-key 同时给出时优先于 --starttls）")
	keyFile := fs.String("tls-key", "", "STARTTLS 私钥 PEM 文件")
	requireAuth := fs.Bool("require-auth", false, "要求先通过 AUTH 才能发信（需配合 --auth 或配置文件 auth.accounts）")
	printBody := fs.Bool("print-body", false, "打印收到的消息正文（默认只打印信封与头部摘要）")
	outputFlag := fs.String("output", "", "消息输出级别：summary（默认简洁摘要）、detail（信封/全部头部/正文）、debug（detail + SMTP 命令轨迹）")
	bodyLimit := fs.Int("body-limit", defaultMaxBodyBytes, "详细输出中正文最多打印的字节数，0 表示不限制（默认 4096）")
	traceSMTP := fs.Bool("trace-smtp", false, "打印会话级 SMTP 命令轨迹（调试用；AUTH 凭据不会进入轨迹）")
	imapEnabled := fs.Bool("imap", false, "启用只读 IMAP 收件箱（需要模拟账户，见 -auth 或 auth.accounts）")
	imapAddr := fs.String("imap-addr", testmail.DefaultIMAPAddr, "IMAP 监听地址；默认仅回环随机端口，启动后打印实际端口")
	imapTLS := fs.Bool("imap-tls", false, "IMAP 使用隐式 TLS（复用 STARTTLS 证书或生成自签测试证书）")
	pop3Enabled := fs.Bool("pop3", false, "启用只读 POP3 收件箱（需要模拟账户，见 -auth 或 auth.accounts）")
	pop3Addr := fs.String("pop3-addr", testmail.DefaultPOP3Addr, "POP3 监听地址；默认仅回环随机端口，启动后打印实际端口")
	pop3TLS := fs.Bool("pop3-tls", false, "POP3 使用隐式 TLS（复用 STARTTLS 证书或生成自签测试证书）")
	var users credentials = make(map[string]string)
	fs.Var(users, "auth", "启用 AUTH 并添加测试凭据，格式 user:password，可重复")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("未知参数: %s", strings.Join(fs.Args(), " "))
	}

	// 记录哪些参数被命令行显式给出，用于实现“命令行 > 配置文件 > 默认值”。
	explicit := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
	cli := cliOverrides{
		set:              explicit,
		addr:             addr,
		hostname:         hostname,
		allowNonLoopback: allowNonLoopback,
		maxMessageBytes:  maxMessageBytes,
		maxRecipients:    maxRecipients,
		maxConnections:   maxConnections,
		maxMessages:      maxMessages,
		readTimeout:      readTimeout,
		sessionTimeout:   sessionTimeout,
		startTLS:         startsTLS,
		tlsCert:          certFile,
		tlsKey:           keyFile,
		requireAuth:      requireAuth,
		auth:             users,
		printBody:        printBody,
		output:           outputFlag,
		bodyLimit:        bodyLimit,
		traceSMTP:        traceSMTP,
		imap:             imapEnabled,
		imapAddr:         imapAddr,
		imapTLS:          imapTLS,
		pop3:             pop3Enabled,
		pop3Addr:         pop3Addr,
		pop3TLS:          pop3TLS,
	}

	fileCfg := defaultFileConfig()
	if strings.TrimSpace(*configPath) != "" {
		loaded, err := loadConfigFile(*configPath)
		if err != nil {
			return err
		}
		fileCfg = loaded
	}
	cfg, err := resolveConfig(fileCfg, cli)
	if err != nil {
		return err
	}
	if strings.TrimSpace(*configPath) != "" {
		cfg.ConfigPath = *configPath
	}

	opts := testmail.Options{
		Addr:             cfg.Addr,
		Hostname:         cfg.Hostname,
		AllowNonLoopback: cfg.AllowNonLoopback,
		MaxMessageBytes:  cfg.MaxMessageBytes,
		MaxRecipients:    cfg.MaxRecipients,
		MaxConnections:   cfg.MaxConnections,
		MaxMessages:      cfg.MaxMessages,
		ReadTimeout:      cfg.ReadTimeout,
		SessionTimeout:   cfg.SessionTimeout,
	}
	if len(cfg.Accounts) > 0 {
		authUsers := make(map[string]string, len(cfg.Accounts))
		for _, account := range cfg.Accounts {
			authUsers[account.Username] = account.Password
		}
		opts.Auth = &testmail.AuthOptions{Users: authUsers, RequireAuth: cfg.RequireAuth}
	}

	// TLS 证书来源：SMTP STARTTLS 与 IMAP/POP3 隐式 TLS 共用同一张测试证书。
	// 有证书文件时直接加载；全部为自签场景时生成一次性测试证书（24 小时有效）。
	needCertificate := cfg.StartTLSEnabled || cfg.TLSCertFile != "" ||
		(cfg.IMAP.Enabled && cfg.IMAP.TLS) || (cfg.POP3.Enabled && cfg.POP3.TLS)
	var tlsCert *tls.Certificate
	if needCertificate {
		cert, err := loadCertificate(true, cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return err
		}
		tlsCert = cert
	}
	var tlsDescription string
	if cfg.StartTLSEnabled || cfg.TLSCertFile != "" {
		opts.TLS = &testmail.TLSOptions{Certificate: *tlsCert}
		tlsDescription = describeCertificate(cfg)
	}
	if cfg.IMAP.Enabled {
		imapOptions := &testmail.IMAPOptions{Addr: cfg.IMAP.Addr}
		if cfg.IMAP.TLS {
			imapOptions.TLS = &testmail.TLSOptions{Certificate: *tlsCert}
		}
		opts.IMAP = imapOptions
	}
	if cfg.POP3.Enabled {
		pop3Options := &testmail.POP3Options{Addr: cfg.POP3.Addr}
		if cfg.POP3.TLS {
			pop3Options.TLS = &testmail.TLSOptions{Certificate: *tlsCert}
		}
		opts.POP3 = pop3Options
	}

	logger := log.New(stdout, "", log.LstdFlags)
	opts.OnMessage = func(m testmail.Message) {
		printMessage(logger, cfg, m)
	}
	if cfg.TraceSMTP {
		opts.OnSessionEvent = func(ev testmail.SessionEvent) {
			printSessionEvent(logger, ev)
		}
	}

	srv, err := testmail.New(opts)
	if err != nil {
		if cfg.ConfigPath != "" {
			return fmt.Errorf("合并后的测试服务器配置无效（默认值 + 配置文件 %s + 命令行显式参数）：%w", cfg.ConfigPath, err)
		}
		return err
	}
	if err := srv.Start(); err != nil {
		return err
	}
	defer func() {
		_ = srv.Close()
	}()

	printStartup(stdout, cfg, srv, tlsDescription)

	<-ctx.Done()

	fmt.Fprintf(stdout, "testmaild: 正在关闭，共接收 %d 封邮件（SMTP/IMAP/POP3 端口将一并释放）\n", srv.MessageCount())
	if err := srv.Close(); err != nil {
		return fmt.Errorf("关闭失败: %w", err)
	}
	fmt.Fprintf(stdout, "testmaild: 已关闭并释放端口\n")
	return nil
}

// loadCertificate 根据参数加载或生成 STARTTLS 证书；未启用时返回 nil。
func loadCertificate(startsTLS bool, certFile, keyFile string) (*tls.Certificate, error) {
	if certFile == "" && keyFile == "" {
		if !startsTLS {
			return nil, nil
		}
		cert, err := testmail.GenerateTestCertificate()
		if err != nil {
			return nil, err
		}
		return &cert, nil
	}
	if certFile == "" || keyFile == "" {
		return nil, errors.New("--tls-cert 与 --tls-key 必须同时给出")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("加载 TLS 证书失败: %w", err)
	}
	return &cert, nil
}
