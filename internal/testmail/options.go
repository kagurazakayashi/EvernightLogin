package testmail

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// 默认值与硬性上下界。上下界只用于拒绝明显不合理的测试配置，不追求生产级弹性。
const (
	// DefaultAddr 是默认 SMTP 监听地址：仅回环、随机端口。
	DefaultAddr = "127.0.0.1:0"
	// DefaultIMAPAddr 是默认 IMAP 监听地址：仅回环、随机端口。
	DefaultIMAPAddr = "127.0.0.1:0"
	// DefaultPOP3Addr 是默认 POP3 监听地址：仅回环、随机端口。
	DefaultPOP3Addr = "127.0.0.1:0"
	// DefaultHostname 是默认问候语中的主机名。
	DefaultHostname = "testmail.local"

	// DefaultMaxMessageBytes 是单条消息（DATA 内容，含头部）默认上限。
	DefaultMaxMessageBytes = 256 << 10
	// MinMaxMessageBytes 与 MaxMaxMessageBytes 是单条消息上限允许范围。
	MinMaxMessageBytes = 1
	MaxMaxMessageBytes = 16 << 20

	// DefaultMaxRecipients 是单条消息默认最大收件人数。
	DefaultMaxRecipients = 50
	// MinMaxRecipients 与 MaxMaxRecipients 是收件人数上限允许范围。
	MinMaxRecipients = 1
	MaxMaxRecipients = 1000

	// DefaultMaxConnections 是默认最大并发连接数。
	DefaultMaxConnections = 32
	// MinMaxConnections 与 MaxMaxConnections 是并发连接上限允许范围。
	MinMaxConnections = 1
	MaxMaxConnections = 1024

	// DefaultMaxMessages 是内存中默认最多保留的消息数；达到上限后新消息按
	// 452 Insufficient system storage 拒绝，测试必须显式 Clear 或 Take 释放空间。
	DefaultMaxMessages = 500
	// MinMaxMessages 与 MaxMaxMessages 是保留消息数上限允许范围。
	MinMaxMessages = 1
	MaxMaxMessages = 100000

	// DefaultReadTimeout 是单次读取（每条命令/每个 DATA 行）的默认超时；
	// 连接空闲超过该时间会被服务端关闭。
	DefaultReadTimeout = 30 * time.Second
	// DefaultSessionTimeout 是单个连接从建立到强制关闭的默认总时长上限，
	// 防止慢速客户端长期占用连接额度。
	DefaultSessionTimeout = 5 * time.Minute
	// MinTimeout 与 MaxTimeout 是上述两个超时的允许范围。
	MinTimeout = 50 * time.Millisecond
	MaxTimeout = time.Hour

	// defaultMaxAuthAttempts 是单个连接允许的 AUTH 失败次数；超过后服务端
	// 以 421 关闭连接，避免测试凭据被在线穷举。
	defaultMaxAuthAttempts = 3

	// maxLineBytes 是单条协议行（含命令与 DATA 行）的字节上限。
	maxLineBytes = 64 << 10
	// maxAddressBytes 是信封地址长度上限（与常见 SMTP 实现一致）。
	maxAddressBytes = 254
)

// 本包公开的哨兵错误。调用方可用 errors.Is 判断。
var (
	// ErrInvalidOptions 表示 Options 校验失败。
	ErrInvalidOptions = errors.New("testmail: 非法选项")
	// ErrAlreadyStarted 表示服务已经启动，不能重复 Start。
	ErrAlreadyStarted = errors.New("testmail: 服务已启动")
	// ErrClosed 表示服务已经关闭，不能再次启动。
	ErrClosed = errors.New("testmail: 服务已关闭")
	// ErrStoreFull 表示内存中保留的消息数已达上限，消息被拒绝。
	ErrStoreFull = errors.New("testmail: 消息保留数已达上限")
)

// Options 是本地测试 SMTP 服务器的配置。零值配合 New 会填充全部默认值。
type Options struct {
	// Addr 是监听地址，默认 DefaultAddr（仅回环、随机端口）。非回环地址必须
	// 同时设置 AllowNonLoopback，否则 New 返回错误；空主机名（如 ":0"、":2525"）
	// 不会被当作回环静默放行，同样必须显式 AllowNonLoopback。
	Addr string
	// Hostname 是问候语与 EHLO 响应中使用的主机名，默认 DefaultHostname。
	Hostname string
	// AllowNonLoopback 显式允许监听非回环地址。默认 false，避免测试服务
	// 被意外暴露到网络；即使允许，本服务器也只做本地捕获，不中继任何消息。
	AllowNonLoopback bool
	// MaxMessageBytes 是单条消息字节上限，默认 DefaultMaxMessageBytes。
	MaxMessageBytes int
	// MaxRecipients 是单条消息收件人数上限，默认 DefaultMaxRecipients。
	MaxRecipients int
	// MaxConnections 是最大并发连接数，默认 DefaultMaxConnections。
	MaxConnections int
	// MaxMessages 是内存中最多保留的消息数，默认 DefaultMaxMessages。
	MaxMessages int
	// ReadTimeout 是单次读取超时，默认 DefaultReadTimeout。
	ReadTimeout time.Duration
	// SessionTimeout 是单连接总时长上限，默认 DefaultSessionTimeout。
	SessionTimeout time.Duration
	// Auth 配置可选 AUTH PLAIN/LOGIN；nil 表示不支持 AUTH。
	Auth *AuthOptions
	// TLS 配置可选 STARTTLS；nil 表示不支持 STARTTLS。
	TLS *TLSOptions
	// IMAP 配置可选的只读 IMAP4rev1 收件箱监听；nil 表示不启动 IMAP。
	// 启用时必须配置 Auth（模拟账户），收件箱按账户隔离并且只读。
	IMAP *IMAPOptions
	// POP3 配置可选的只读 POP3 收件箱监听；nil 表示不启动 POP3。
	// 启用时必须配置 Auth（模拟账户），收件箱按账户隔离并且只读。
	POP3 *POP3Options
	// OnMessage 在消息成功保存后同步调用（在会话 goroutine 中）。回调不应
	// 长时间阻塞，否则会拖慢该连接；其余连接不受影响。回调拿到的是消息副本。
	OnMessage func(Message)
	// OnSessionEvent 在每条可观察的会话事件（连接建立、命令、应答、STARTTLS、
	// 认证成功、连接关闭）后同步调用，用于调试输出；nil 表示不产生轨迹，此时不会
	// 触发回调、也不会产生输出（会话路径只保留少量 nil 判断与常量参数准备）。
	// 回调在会话 goroutine 中执行，不应长时间阻塞。AUTH 命令参数只保留机制名，
	// AUTH 客户端响应内容与正文内容都不会进入事件。
	OnSessionEvent func(SessionEvent)
}

// AuthOptions 是显式的测试认证配置。
//
// 安全边界：只用于本地测试，凭据直接写在这里，不来自环境变量、配置文件或凭证库；
// 使用弱测试凭据是可以接受的前提是服务器只监听回环地址。本包不会把用户名或密码
// 写入消息记录、错误或日志。
type AuthOptions struct {
	// Users 是允许的用户名到密码的映射，不能为空。
	Users map[string]string
	// RequireAuth 为 true 时，未认证的连接执行 MAIL FROM 会得到 530。
	RequireAuth bool
}

// TLSOptions 是可选 STARTTLS / 隐式 TLS 配置。
type TLSOptions struct {
	// Certificate 是 TLS 使用的证书；测试通常用 GenerateTestCertificate
	// 生成自签证书，客户端需要显式信任或跳过校验。
	Certificate tls.Certificate
}

// IMAPOptions 是只读 IMAP4rev1 收件箱监听配置。
//
// 安全边界：收件箱按模拟账户隔离，登录只接受 AuthOptions 中显式配置的测试凭据；
// 服务端不投递、不中继、不执行邮件内容，仅返回本机内存中的消息。写操作
// （STORE/EXPUNGE/APPEND/COPY/MOVE/DELE）一律被拒绝。
type IMAPOptions struct {
	// Addr 是监听地址，空字符串表示 DefaultIMAPAddr（仅回环、随机端口）。
	Addr string
	// TLS 配置隐式 TLS（整条连接从建立即加密）；nil 表示明文。明文只允许
	// 回环地址，非回环地址必须启用 TLS 并显式 AllowNonLoopback。
	TLS *TLSOptions
}

// POP3Options 是只读 POP3 收件箱监听配置。
//
// 安全边界与 IMAPOptions 相同：按模拟账户隔离、只读；DELE 仅在本会话内隐藏消息，
// QUIT 或断开连接后消息仍在共享内存仓库中（不会真正删除）。
type POP3Options struct {
	// Addr 是监听地址，空字符串表示 DefaultPOP3Addr（仅回环、随机端口）。
	Addr string
	// TLS 配置隐式 TLS；nil 表示明文。明文只允许回环地址。
	TLS *TLSOptions
}

// normalize 填充默认值并校验所有字段，返回一份不与其他调用方共享可变状态的副本。
func (o Options) normalize() (Options, error) {
	if o.Addr == "" {
		o.Addr = DefaultAddr
	}
	if o.Hostname == "" {
		o.Hostname = DefaultHostname
	}
	if o.MaxMessageBytes == 0 {
		o.MaxMessageBytes = DefaultMaxMessageBytes
	}
	if o.MaxRecipients == 0 {
		o.MaxRecipients = DefaultMaxRecipients
	}
	if o.MaxConnections == 0 {
		o.MaxConnections = DefaultMaxConnections
	}
	if o.MaxMessages == 0 {
		o.MaxMessages = DefaultMaxMessages
	}
	if o.ReadTimeout == 0 {
		o.ReadTimeout = DefaultReadTimeout
	}
	if o.SessionTimeout == 0 {
		o.SessionTimeout = DefaultSessionTimeout
	}

	var errs []error
	if err := validateAddr(o.Addr, o.AllowNonLoopback); err != nil {
		errs = append(errs, err)
	}
	if err := validateHostname(o.Hostname); err != nil {
		errs = append(errs, err)
	}
	if o.MaxMessageBytes < MinMaxMessageBytes || o.MaxMessageBytes > MaxMaxMessageBytes {
		errs = append(errs, fmt.Errorf("MaxMessageBytes 必须在 %d～%d 之间", MinMaxMessageBytes, MaxMaxMessageBytes))
	}
	if o.MaxRecipients < MinMaxRecipients || o.MaxRecipients > MaxMaxRecipients {
		errs = append(errs, fmt.Errorf("MaxRecipients 必须在 %d～%d 之间", MinMaxRecipients, MaxMaxRecipients))
	}
	if o.MaxConnections < MinMaxConnections || o.MaxConnections > MaxMaxConnections {
		errs = append(errs, fmt.Errorf("MaxConnections 必须在 %d～%d 之间", MinMaxConnections, MaxMaxConnections))
	}
	if o.MaxMessages < MinMaxMessages || o.MaxMessages > MaxMaxMessages {
		errs = append(errs, fmt.Errorf("MaxMessages 必须在 %d～%d 之间", MinMaxMessages, MaxMaxMessages))
	}
	if o.ReadTimeout < MinTimeout || o.ReadTimeout > MaxTimeout {
		errs = append(errs, fmt.Errorf("ReadTimeout 必须在 %s～%s 之间", MinTimeout, MaxTimeout))
	}
	if o.SessionTimeout < MinTimeout || o.SessionTimeout > MaxTimeout {
		errs = append(errs, fmt.Errorf("SessionTimeout 必须在 %s～%s 之间", MinTimeout, MaxTimeout))
	}
	if o.Auth != nil {
		copied, err := normalizeAuth(o.Auth)
		if err != nil {
			errs = append(errs, err)
		}
		o.Auth = copied
	}
	if o.TLS != nil {
		if len(o.TLS.Certificate.Certificate) == 0 {
			errs = append(errs, fmt.Errorf("TLS.Certificate 为空"))
		}
		tlsCopy := &TLSOptions{Certificate: o.TLS.Certificate}
		o.TLS = tlsCopy
	}
	if o.IMAP != nil {
		addr, tlsOpt, err := normalizeNetProto("IMAP", o.IMAP.Addr, DefaultIMAPAddr, o.IMAP.TLS, o.AllowNonLoopback, o.Auth != nil)
		if err != nil {
			errs = append(errs, err)
		} else {
			o.IMAP = &IMAPOptions{Addr: addr, TLS: tlsOpt}
		}
	}
	if o.POP3 != nil {
		addr, tlsOpt, err := normalizeNetProto("POP3", o.POP3.Addr, DefaultPOP3Addr, o.POP3.TLS, o.AllowNonLoopback, o.Auth != nil)
		if err != nil {
			errs = append(errs, err)
		} else {
			o.POP3 = &POP3Options{Addr: addr, TLS: tlsOpt}
		}
	}
	if len(errs) > 0 {
		return Options{}, fmt.Errorf("%w: %v", ErrInvalidOptions, errors.Join(errs...))
	}
	return o, nil
}

// normalizeNetProto 填充并校验 IMAP/POP3 监听配置（只读收件协议）。
//
// 安全策略：两个协议都要求先认证（必须有模拟账户）；明文监听强制仅回环，因为
// 明文凭据会直接暴露在网络上。监听非回环地址必须同时启用隐式 TLS 并显式设置
// AllowNonLoopback，两道开关缺一不可。
func normalizeNetProto(name, addr, defaultAddr string, protoTLS *TLSOptions, allowNonLoopback, hasAuth bool) (string, *TLSOptions, error) {
	if !hasAuth {
		return "", nil, fmt.Errorf("启用 %s 需要配置 Auth.Users（收件箱按模拟账户认证与隔离，不能匿名读取）", name)
	}
	if addr == "" {
		addr = defaultAddr
	}
	// 先做语法校验（允许任意主机名写法），再按是否有 TLS 套用回环策略。
	if err := validateAddr(addr, true); err != nil {
		return "", nil, fmt.Errorf("%s.Addr: %w", name, err)
	}
	if protoTLS == nil {
		if err := validateAddr(addr, false); err != nil {
			return "", nil, fmt.Errorf("%s 明文监听只允许回环地址（例如 127.0.0.1:0）；如确需监听非回环地址，请启用隐式 TLS 并显式设置 AllowNonLoopback", name)
		}
	} else if err := validateAddr(addr, allowNonLoopback); err != nil {
		return "", nil, fmt.Errorf("%s.Addr: %w", name, err)
	}
	var tlsCopy *TLSOptions
	if protoTLS != nil {
		if len(protoTLS.Certificate.Certificate) == 0 {
			return "", nil, fmt.Errorf("%s.TLS.Certificate 为空", name)
		}
		tlsCopy = &TLSOptions{Certificate: protoTLS.Certificate}
	}
	return addr, tlsCopy, nil
}

func normalizeAuth(a *AuthOptions) (*AuthOptions, error) {
	if len(a.Users) == 0 {
		return nil, fmt.Errorf("Auth.Users 不能为空")
	}
	users := make(map[string]string, len(a.Users))
	// 认证按字节精确比较，而收件箱可见性按 EqualFold 比较本地部分；如果两个
	// 用户名只差大小写或 Unicode 归一化形式，它们会共享同一个收件箱且无法区分
	// 归属。这里在配置校验阶段拒绝这种歧义（与产品 internal/account 的规范化
	// 口径一致：NFKC + 大小写折叠 + NFC）。
	foldedNames := make(map[string]string, len(a.Users))
	for name, pass := range a.Users {
		if err := validateAuthText(name); err != nil {
			return nil, fmt.Errorf("Auth 用户名非法: %w", err)
		}
		if err := validateAuthText(pass); err != nil {
			return nil, fmt.Errorf("Auth 用户 %q 的密码非法: %w", name, err)
		}
		key := normalizeAccountName(name)
		if existing, dup := foldedNames[key]; dup {
			return nil, fmt.Errorf("Auth 用户名 %q 与 %q 在大小写/Unicode 归一化后相同，会导致收件箱归属歧义；请使用互不相同的用户名", name, existing)
		}
		foldedNames[key] = name
		users[name] = pass
	}
	return &AuthOptions{Users: users, RequireAuth: a.RequireAuth}, nil
}

// normalizeAccountName 返回账号唯一性/歧义比较键：NFKC + 大小写折叠 + NFC。
//
// 该口径与产品账户模块（internal/account）一致；这里只用于配置校验阶段拒绝
// “认证精确、可见性大小写不敏感”导致的收件箱共享歧义，不改变认证本身的精确比较。
func normalizeAccountName(name string) string {
	compatibility := norm.NFKC.String(name)
	folded := cases.Fold().String(compatibility)
	return norm.NFC.String(folded)
}

func validateAuthText(v string) error {
	if len(v) == 0 || len(v) > 256 {
		return fmt.Errorf("长度必须在 1～256 字节之间")
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("不能包含控制字符")
		}
	}
	return nil
}

func validateHostname(h string) error {
	if len(h) == 0 || len(h) > 255 {
		return fmt.Errorf("Hostname 长度必须在 1～255 字节之间")
	}
	for _, r := range h {
		if r <= 0x20 || r == 0x7f {
			return fmt.Errorf("Hostname 不能包含空白或控制字符")
		}
	}
	return nil
}

// validateAddr 校验监听地址：必须是 host:port 形式；空主机名不会被当作回环
// 静默放行（net.Listen 会把它绑定到全部接口），未显式 AllowNonLoopback 时直接
// 拒绝；非回环字面量或主机名同样必须得到 AllowNonLoopback 显式允许。
func validateAddr(addr string, allowNonLoopback bool) error {
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("Addr %q 必须是 host:port 形式: %w", addr, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 || port > 65535 {
		return fmt.Errorf("Addr %q 的端口必须是 0～65535 的整数", addr)
	}
	if host == "" {
		if !allowNonLoopback {
			return fmt.Errorf("Addr %q 未给出主机名；请显式使用回环地址（如 127.0.0.1:0）；如确需监听全部接口请显式设置 AllowNonLoopback", addr)
		}
		return nil
	}
	if !isLoopbackHost(host) && !allowNonLoopback {
		return fmt.Errorf("Addr %q 不是回环地址；如确需监听非回环地址请显式设置 AllowNonLoopback", addr)
	}
	return nil
}

// isLoopbackHost 判断监听主机是否为回环地址或 localhost。
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return false
	}
	return ip.IsLoopback()
}
