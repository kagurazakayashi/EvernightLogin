package mailer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// TLSMode 是 SMTP 连接加密模式。没有"自动降级为明文"的选项：模式必须显式选择，
// 证书校验始终开启（测试自签证书通过 TrustedRoots 注入，不关闭校验）。
type TLSMode string

const (
	// TLSModeStartTLS 是显式 STARTTLS（默认，推荐）。
	TLSModeStartTLS TLSMode = "starttls"
	// TLSModeImplicit 是隐式 TLS（常见于 465 端口）。
	TLSModeImplicit TLSMode = "implicit"
	// TLSModeNone 是明文连接，仅允许配合 AllowPlaintextLocal 且目标为回环地址，
	// 用于本地测试捕获器。
	TLSModeNone TLSMode = "none"
)

const (
	// DefaultSMTPTimeout 是单封邮件发送的默认总时限。
	DefaultSMTPTimeout = 10 * time.Second
	// MinSMTPTimeout/MaxSMTPTimeout 是发送时限允许范围。
	MinSMTPTimeout = time.Second
	MaxSMTPTimeout = 2 * time.Minute
)

// SMTPOptions 是 SMTP 发送适配配置。地址、主机名与 TLS 模式必须显式给出；
// 认证要么同时给出用户名和密码，要么都不给。
type SMTPOptions struct {
	// Addr 是 SMTP 服务器地址（host:port），必填。
	Addr string
	// Host 是 EHLO 使用的主机名，也是 TLS ServerName 的默认值；为空时取 Addr 的主机部分。
	Host string
	// TLSMode 是加密模式；空值按 STARTTLS 处理。TLSModeNone 必须同时设置
	// AllowPlaintextLocal 且 Addr 为回环地址。
	TLSMode TLSMode
	// TrustedRoots 是额外信任的根证书；用于测试自签测试服务器，不能用于绕过
	// 校验（本适配没有 InsecureSkipVerify 途径）。
	TrustedRoots *x509.CertPool
	// Username/Password 是显式认证配置；密码应为秘密来源，不得写入日志。
	Username string
	Password string
	// PasswordProvider 是按需取密的回调（步骤 139）：优先于 Password，二者只能
	// 设置一个；返回的字节在构造本次认证后立即清零，不长期保存明文。
	PasswordProvider func() ([]byte, error)
	// Timeout 是单封发送总时限；0 使用默认值。
	Timeout time.Duration
	// AllowPlaintextLocal 显式允许对回环地址使用明文连接（仅本地测试捕获器）。
	AllowPlaintextLocal bool
	// DialContext 可选注入拨号函数（测试/自定义网络）；nil 使用默认拨号器。
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
}

// SMTPSender 是标准库 net/smtp 的最小适配。
type SMTPSender struct {
	opts      SMTPOptions
	tlsConfig *tls.Config
	auth      smtp.Auth
	loopback  bool
}

// NewSMTPSender 校验配置并创建 SMTP 发送器。
func NewSMTPSender(opts SMTPOptions) (*SMTPSender, error) {
	if strings.TrimSpace(opts.Addr) == "" {
		return nil, fmt.Errorf("%w: SMTP 地址不能为空", ErrOptionsInvalid)
	}
	host, port, err := net.SplitHostPort(opts.Addr)
	if err != nil || host == "" || port == "" {
		return nil, fmt.Errorf("%w: SMTP 地址必须是 host:port", ErrOptionsInvalid)
	}
	if opts.Host == "" {
		opts.Host = host
	}
	if opts.Host == "" {
		return nil, fmt.Errorf("%w: EHLO/TLS 主机名不能为空", ErrOptionsInvalid)
	}
	if opts.Timeout == 0 {
		opts.Timeout = DefaultSMTPTimeout
	}
	if opts.Timeout < MinSMTPTimeout || opts.Timeout > MaxSMTPTimeout {
		return nil, fmt.Errorf("%w: 发送时限必须在 %s～%s", ErrOptionsInvalid, MinSMTPTimeout, MaxSMTPTimeout)
	}
	switch opts.TLSMode {
	case "":
		opts.TLSMode = TLSModeStartTLS
	case TLSModeStartTLS, TLSModeImplicit:
	case TLSModeNone:
		if !opts.AllowPlaintextLocal || !isLoopbackAddr(host) {
			return nil, fmt.Errorf("%w: 明文连接只允许配合 AllowPlaintextLocal 且目标是回环地址", ErrOptionsInvalid)
		}
	default:
		return nil, fmt.Errorf("%w: 不支持的 TLS 模式 %q", ErrOptionsInvalid, opts.TLSMode)
	}
	if opts.Password != "" && opts.PasswordProvider != nil {
		return nil, fmt.Errorf("%w: Password 与 PasswordProvider 只能设置一个", ErrOptionsInvalid)
	}
	hasUser := opts.Username != ""
	hasPass := opts.Password != "" || opts.PasswordProvider != nil
	if hasUser != hasPass {
		return nil, fmt.Errorf("%w: 认证用户名与密码必须同时给出", ErrOptionsInvalid)
	}
	if hasUser && opts.Password != "" {
		// 静态密码在构造期建立认证；PasswordProvider 在每次 Send 时按需构造。
		_ = hasUser
	}
	if hasUser && opts.TLSMode == TLSModeNone {
		return nil, fmt.Errorf("%w: 明文连接不得配置认证凭据", ErrOptionsInvalid)
	}

	s := &SMTPSender{
		opts:     opts,
		loopback: isLoopbackAddr(host),
	}
	if hasUser && opts.Password != "" {
		s.auth = smtp.PlainAuth("", opts.Username, opts.Password, opts.Host)
	}
	if opts.TLSMode != TLSModeNone {
		// 证书校验始终开启：只接受额外根证书，不提供跳过校验的配置入口。
		s.tlsConfig = &tls.Config{
			ServerName: opts.Host,
			MinVersion: tls.VersionTLS12,
			RootCAs:    opts.TrustedRoots,
		}
	}
	return s, nil
}

// Send 实现 Sender：一条连接发一封邮件，含总时限、ctx 取消与失败分类。
func (s *SMTPSender) Send(ctx context.Context, message Message) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := message.Validate(); err != nil {
		return newSendError(FailurePermanent, CodeInvalidMessage, err)
	}
	payload, err := message.Bytes()
	if err != nil {
		return newSendError(FailurePermanent, CodeInvalidMessage, err)
	}

	deadline := time.Now().Add(s.opts.Timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}

	dial := s.opts.DialContext
	if dial == nil {
		dialer := &net.Dialer{Timeout: s.opts.Timeout}
		dial = dialer.DialContext
	}
	conn, err := dial(ctx, "tcp", s.opts.Addr)
	if err != nil {
		return s.sendFailure(ctx, "connect", err)
	}
	defer func() { _ = conn.Close() }()

	// ctx 取消时主动关闭连接，让阻塞中的 SMTP 读写立即返回，而不是等到总时限。
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	if err := conn.SetDeadline(deadline); err != nil {
		return s.sendFailure(ctx, "deadline", err)
	}

	if s.opts.TLSMode == TLSModeImplicit {
		tlsConn := tls.Client(conn, s.tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return s.sendFailure(ctx, "tls", err)
		}
		conn = tlsConn
	}

	client, err := smtp.NewClient(conn, s.opts.Host)
	if err != nil {
		return s.sendFailure(ctx, "greeting", err)
	}
	defer func() { _ = client.Close() }()

	if s.opts.TLSMode == TLSModeStartTLS {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return newSendError(FailurePermanent, CodeTLSFailed,
				fmt.Errorf("mailer: 服务器未提供 STARTTLS"))
		}
		if err := client.StartTLS(s.tlsConfig); err != nil {
			return s.sendFailure(ctx, "starttls", err)
		}
	}
	auth := s.auth
	if s.opts.Username != "" && s.opts.PasswordProvider != nil {
		secret, secretErr := s.opts.PasswordProvider()
		if secretErr != nil {
			return newSendError(FailurePermanent, CodeAuthFailed, fmt.Errorf("读取 SMTP 密码失败: %w", secretErr))
		}
		auth = smtp.PlainAuth("", s.opts.Username, string(secret), s.opts.Host)
		for i := range secret {
			secret[i] = 0
		}
	}
	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return s.sendFailure(ctx, "auth", err)
		}
	}
	if err := client.Mail(message.From.Spec); err != nil {
		return s.sendFailure(ctx, "mail", err)
	}
	for _, to := range message.To {
		if err := client.Rcpt(to.Spec); err != nil {
			return s.sendFailure(ctx, "rcpt", err)
		}
	}
	writer, err := client.Data()
	if err != nil {
		return s.sendFailure(ctx, "data", err)
	}
	if _, err := writer.Write(payload); err != nil {
		_ = writer.Close()
		return s.sendFailure(ctx, "write", err)
	}
	if err := writer.Close(); err != nil {
		return s.sendFailure(ctx, "data-close", err)
	}
	// QUIT 失败不影响"服务器已接受邮件"的事实，只记录但不算发送失败。
	_ = client.Quit()
	return nil
}

// sendFailure 把各阶段错误归类，并把 ctx 取消/期限优先映射为稳定代码。
func (s *SMTPSender) sendFailure(ctx context.Context, stage string, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		if errors.Is(ctxErr, context.DeadlineExceeded) {
			return newSendError(FailureTransient, CodeTimeout, fmt.Errorf("%w: 阶段 %s", ctxErr, stage))
		}
		return newSendError(FailureTransient, CodeCancelled, fmt.Errorf("%w: 阶段 %s", ctxErr, stage))
	}
	return classifySendError(fmt.Errorf("mailer: smtp 阶段 %s: %w", stage, err))
}

// isLoopbackAddr 判断主机是否为回环地址或 localhost。
func isLoopbackAddr(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	trimmed := strings.Trim(host, "[]")
	if ip := net.ParseIP(trimmed); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// Sender 断言。
var _ Sender = (*SMTPSender)(nil)
