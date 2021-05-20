// Command testmaild 启动一个本地测试 SMTP 服务器，用于人工验收与调试邮件相关功能。
//
// 它只做装配与运行：解析命令行参数、构造 internal/testmail 服务器、打印实际监听
// 地址与能力，收到消息时打印摘要，收到中断信号后优雅退出并释放端口。它不导入任何
// 产品业务逻辑，也不会被 cmd/login-server 装配；生产服务器不会启动本工具。
//
// 默认只监听 127.0.0.1 的随机端口；不向任何真实地址投递邮件。
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
		fmt.Fprintf(stderr, "只用于测试的本地 SMTP 接收服务器：消息只保存在内存中，不投递、不中继。\n\n")
		fmt.Fprintf(stderr, "选项:\n")
		fs.PrintDefaults()
	}

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
	requireAuth := fs.Bool("require-auth", false, "要求先通过 AUTH 才能发信（需配合 --auth）")
	printBody := fs.Bool("print-body", false, "打印收到的消息正文（默认只打印信封与头部摘要）")
	var users credentials = make(map[string]string)
	fs.Var(users, "auth", "启用 AUTH 并添加测试凭据，格式 user:password，可重复")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("未知参数: %s", strings.Join(fs.Args(), " "))
	}

	opts := testmail.Options{
		Addr:             *addr,
		Hostname:         *hostname,
		AllowNonLoopback: *allowNonLoopback,
		MaxMessageBytes:  *maxMessageBytes,
		MaxRecipients:    *maxRecipients,
		MaxConnections:   *maxConnections,
		MaxMessages:      *maxMessages,
		ReadTimeout:      *readTimeout,
		SessionTimeout:   *sessionTimeout,
	}
	if len(users) > 0 {
		opts.Auth = &testmail.AuthOptions{Users: users, RequireAuth: *requireAuth}
	} else if *requireAuth {
		return errors.New("--require-auth 需要至少一个 --auth user:password")
	}

	cert, err := loadCertificate(*startsTLS, *certFile, *keyFile)
	if err != nil {
		return err
	}
	if cert != nil {
		opts.TLS = &testmail.TLSOptions{Certificate: *cert}
	}

	logger := log.New(stdout, "", log.LstdFlags)
	opts.OnMessage = func(m testmail.Message) {
		logger.Printf("收到邮件 id=%s from=<%s> to=%v subject=%q size=%d tls=%t auth=%q",
			m.ID, m.EnvelopeFrom, m.EnvelopeTo, m.Subject, len(m.Data), m.TLS, m.AuthUser)
		if *printBody {
			logger.Printf("--- 消息正文 id=%s ---\n%s", m.ID, m.Body())
		}
	}

	srv, err := testmail.New(opts)
	if err != nil {
		return err
	}
	if err := srv.Start(); err != nil {
		return err
	}
	defer func() {
		_ = srv.Close()
	}()

	// 只打印地址与能力摘要；不打印测试密码。
	fmt.Fprintf(stdout, "testmaild: 监听 %s\n", srv.Addr())
	fmt.Fprintf(stdout, "testmaild: 主机名 %s\n", opts.Hostname)
	fmt.Fprintf(stdout, "testmaild: 限制 消息=%d字节 收件人=%d 连接=%d 保留=%d\n",
		opts.MaxMessageBytes, opts.MaxRecipients, opts.MaxConnections, opts.MaxMessages)
	if opts.Auth != nil {
		names := make([]string, 0, len(opts.Auth.Users))
		for name := range opts.Auth.Users {
			names = append(names, name)
		}
		sort.Strings(names)
		fmt.Fprintf(stdout, "testmaild: AUTH 已启用，测试用户 %v（密码见启动参数；要求先认证=%t）\n", names, opts.Auth.RequireAuth)
	}
	if opts.TLS != nil {
		fmt.Fprintf(stdout, "testmaild: STARTTLS 已启用（自签测试证书，客户端需显式信任或跳过校验）\n")
	}
	fmt.Fprintf(stdout, "testmaild: 等待邮件；按 Ctrl+C 或发送 SIGTERM 优雅退出\n")

	<-ctx.Done()

	fmt.Fprintf(stdout, "testmaild: 正在关闭，共接收 %d 封邮件\n", srv.MessageCount())
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
