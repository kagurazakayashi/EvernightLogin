package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kagurazakayashi/EvernightLogin/internal/testmail"
)

// printStartup 打印启动信息：监听地址、资源限制、模拟账户清单与客户端连接参数。
//
// 输出中会回显配置文件里的模拟测试密码，这是有意为之（用户需要用它连接测试
// 服务器），但必须同时显式标注“测试专用、非真实凭据、仅回环使用”。命令行
// -auth 给出的密码不回显，避免用户误把命令行历史当作安全来源。
func printStartup(stdout io.Writer, cfg runConfig, srv *testmail.Server, tlsDescription string) {
	addr := srv.Addr().String()
	fmt.Fprintf(stdout, "testmaild: 监听 %s\n", sanitizeLine(addr))
	fmt.Fprintf(stdout, "testmaild: 主机名 %s\n", sanitizeLine(cfg.Hostname))
	fmt.Fprintf(stdout, "testmaild: 限制 消息=%d字节 收件人=%d 连接=%d 保留=%d\n",
		cfg.MaxMessageBytes, cfg.MaxRecipients, cfg.MaxConnections, cfg.MaxMessages)
	if len(cfg.Accounts) > 0 {
		names := make([]string, 0, len(cfg.Accounts))
		for _, account := range cfg.Accounts {
			names = append(names, sanitizeLine(account.Username))
		}
		fmt.Fprintf(stdout, "testmaild: AUTH 已启用，测试用户 %v（要求先认证=%t）\n", names, cfg.RequireAuth)
	}
	if tlsDescription != "" {
		fmt.Fprintf(stdout, "testmaild: STARTTLS 已启用（%s）\n", sanitizeLine(tlsDescription))
	}
	fmt.Fprintf(stdout, "testmaild: 配置来源 %s\n", sanitizeLine(cfg.sourceDescription()))
	fmt.Fprintf(stdout, "testmaild: 输出 级别=%s 正文=%t 正文上限=%s SMTP轨迹=%t\n",
		cfg.Level, cfg.PrintBody, describeBodyLimit(cfg.MaxBodyBytes), cfg.TraceSMTP)
	printAccounts(stdout, cfg)
	printConnectionParams(stdout, cfg, addr, tlsDescription)
	fmt.Fprintf(stdout, "testmaild: 等待邮件；按 Ctrl+C 或发送 SIGTERM 优雅退出\n")
}

// printAccounts 打印模拟账户清单，并按来源决定是否回显测试密码。
//
// 安全告警放在账户/密码清单之前，避免终端滚屏时先看到密码、后看到警告。
func printAccounts(w io.Writer, cfg runConfig) {
	if len(cfg.Accounts) == 0 {
		fmt.Fprintln(w, "testmaild: 模拟账户 未配置（AUTH 关闭；如需模拟登录请用 -auth user:password 或配置文件 auth.accounts）")
		return
	}
	fmt.Fprintln(w, "testmaild: 模拟账户清单（测试专用、非真实凭据）:")
	if cfg.AllowNonLoopback {
		fmt.Fprintln(w, "testmaild: 警告 已显式允许非回环监听；下列测试凭据可能被网络上其他人看到并使用")
	} else {
		fmt.Fprintln(w, "testmaild: 警告 以下为本地测试凭据、仅回环使用；不要复用任何真实账户密码")
	}
	for _, account := range cfg.Accounts {
		if cfg.AccountSource == accountSourceConfig {
			fmt.Fprintf(w, "testmaild:   - 用户名=%s 密码=%s  [本地测试凭据、仅回环使用]\n",
				sanitizeLine(account.Username), sanitizeLine(account.Password))
			continue
		}
		fmt.Fprintf(w, "testmaild:   - 用户名=%s 密码=<已隐藏，命令行 -auth 不回显>\n",
			sanitizeLine(account.Username))
	}
}

// printConnectionParams 打印客户端连接参数、swaks 示例与产品配置片段样例。
func printConnectionParams(w io.Writer, cfg runConfig, addr, tlsDescription string) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host, port = addr, ""
	}
	safeAddr := sanitizeLine(addr)
	fmt.Fprintln(w, "testmaild: ── 客户端连接参数（供手工测试邮件）──")
	fmt.Fprintf(w, "testmaild:   SMTP 地址（host:port）: %s\n", safeAddr)
	fmt.Fprintf(w, "testmaild:   EHLO 主机名: %s\n", sanitizeLine(cfg.Hostname))
	if tlsDescription != "" {
		fmt.Fprintf(w, "testmaild:   加密: STARTTLS（%s）\n", sanitizeLine(tlsDescription))
		fmt.Fprintln(w, "testmaild:   注意: 客户端需显式信任该证书或临时跳过证书校验；仅用于本地测试")
	} else {
		fmt.Fprintln(w, "testmaild:   加密: 无（明文）；AUTH 凭据会明文传输，仅限回环测试")
	}
	switch {
	case len(cfg.Accounts) == 0:
		fmt.Fprintln(w, "testmaild:   AUTH: 未启用（不需要用户名密码）")
	case cfg.RequireAuth:
		fmt.Fprintf(w, "testmaild:   AUTH: 已启用且必须认证；可用用户名: %s\n", sanitizeLine(accountNames(cfg.Accounts)))
	default:
		fmt.Fprintf(w, "testmaild:   AUTH: 已启用（可选）；可用用户名: %s\n", sanitizeLine(accountNames(cfg.Accounts)))
	}
	if len(cfg.Accounts) > 0 {
		first := cfg.Accounts[0]
		swaks := "swaks --server " + addr + " --to user@example.test --from " + first.Username + "@example.test"
		if tlsDescription != "" {
			swaks += " --tls"
		}
		swaks += " --auth-user " + first.Username + " --auth-password " + displayPassword(cfg, first)
		fmt.Fprintln(w, "testmaild:   swaks 示例:")
		fmt.Fprintf(w, "testmaild:     %s\n", sanitizeLine(swaks))
	}
	if tlsDescription != "" {
		fmt.Fprintln(w, "testmaild:   openssl 示例:")
		fmt.Fprintf(w, "testmaild:     openssl s_client -starttls smtp -crlf -connect %s\n", safeAddr)
	}
	fmt.Fprintln(w, "testmaild:   产品配置片段样例（对应字段 smtp.host / smtp.port / smtp.username / smtp.password；请按宿主实际配置键调整）:")
	fmt.Fprintln(w, "testmaild:     smtp:")
	fmt.Fprintf(w, "testmaild:       host: %q\n", sanitizeLine(host))
	fmt.Fprintf(w, "testmaild:       port: %s\n", sanitizeLine(port))
	if len(cfg.Accounts) > 0 {
		first := cfg.Accounts[0]
		fmt.Fprintf(w, "testmaild:       username: %q\n", sanitizeLine(first.Username))
		fmt.Fprintf(w, "testmaild:       password: %q\n", sanitizeLine(displayPassword(cfg, first)))
	} else {
		fmt.Fprintln(w, "testmaild:       # 未配置模拟账户：如需认证请用 -auth user:password 或配置文件 auth.accounts")
	}
	fmt.Fprintf(w, "testmaild:       starttls: %t\n", tlsDescription != "")
	fmt.Fprintln(w, "testmaild:   说明: 当前仓库根配置尚未提供 SMTP 节；宿主可用 internal/mailer.SMTPOptions 指向上面的地址（明文需 AllowPlaintextLocal=true 且仅回环）")
}

// accountNames 返回逗号分隔的用户名清单，顺序与配置一致。
func accountNames(accounts []testAccount) string {
	names := make([]string, 0, len(accounts))
	for _, account := range accounts {
		names = append(names, account.Username)
	}
	return strings.Join(names, "、")
}

// displayPassword 返回可打印的测试密码：配置文件来源直接显示（启动 banner 已标注
// 测试专用），命令行来源不回显。
func displayPassword(cfg runConfig, account testAccount) string {
	if cfg.AccountSource == accountSourceConfig {
		return account.Password
	}
	return "<命令行 -auth 给出的测试密码>"
}

// describeBodyLimit 把正文上限格式化成便于阅读的说明。
func describeBodyLimit(limit int) string {
	if limit == 0 {
		return "不限制"
	}
	return fmt.Sprintf("%d字节", limit)
}

// printMessage 打印一封收到的邮件。默认（summary）只打印一行摘要，保持与旧版
// 工具一致；detail/debug 额外打印信封、原始头部、解析字段、字节数与可选正文。
func printMessage(logger *log.Logger, cfg runConfig, m testmail.Message) {
	logger.Printf("收到邮件 id=%s from=<%s> to=%v subject=%q size=%d tls=%t auth=%q",
		m.ID, m.EnvelopeFrom, m.EnvelopeTo, m.Subject, len(m.Data), m.TLS, m.AuthUser)
	if cfg.Level != outputDetail && cfg.Level != outputDebug {
		if cfg.PrintBody {
			printSummaryBody(logger, cfg, m)
		}
		return
	}

	logger.Printf("  邮件详情 id=%s", m.ID)
	logger.Printf("  接收时间: %s", m.ReceivedAt.Format(time.RFC3339))
	logger.Printf("  客户端: %s", m.RemoteAddr)
	logger.Printf("  信封 MAIL FROM: <%s>", sanitizeLine(m.EnvelopeFrom))
	logger.Printf("  信封 RCPT TO: %s", sanitizeLine(formatRecipients(m.EnvelopeTo)))
	logger.Printf("  Subject（解码）: %q", sanitizeLine(m.Subject))
	if raw, ok := m.Header("Subject"); ok && raw != m.Subject {
		logger.Printf("  Subject（原始）: %q", sanitizeLine(raw))
	}
	if m.Date.IsZero() {
		logger.Printf("  Date: （缺失或无法解析）")
	} else {
		logger.Printf("  Date: %s", m.Date.Format(time.RFC3339))
	}
	if messageID, ok := m.Header("Message-ID"); ok {
		logger.Printf("  Message-ID: %s", sanitizeLine(messageID))
	} else {
		logger.Printf("  Message-ID: （未提供）")
	}
	if m.TLS {
		logger.Printf("  TLS: 是（经 STARTTLS 加密的连接）")
	} else {
		logger.Printf("  TLS: 否（明文）")
	}
	if m.AuthUser == "" {
		logger.Printf("  AUTH 用户: （未认证）")
	} else {
		logger.Printf("  AUTH 用户: %s（已认证）", m.AuthUser)
	}
	body := m.Body()
	logger.Printf("  大小: %d 字节（正文 %d 字节，头部与分隔空行 %d 字节）",
		len(m.Data), len(body), len(m.Data)-len(body))
	rawLines := rawHeaderLines(m.Data)
	logger.Printf("  头部（原始值；解析出 %d 项，原始 %d 行）:", len(m.Headers), len(rawLines))
	for _, line := range rawLines {
		logger.Printf("    %s", sanitizeLine(line))
	}
	if cfg.PrintBody {
		printDetailBody(logger, cfg, m)
	}
}

// printSummaryBody 在 summary 级别按旧版格式打印正文（受正文长度上限约束）。
func printSummaryBody(logger *log.Logger, cfg runConfig, m testmail.Message) {
	body := m.Body()
	text, truncated := limitBytes(body, cfg.MaxBodyBytes)
	logger.Printf("--- 消息正文 id=%s ---\n%s", m.ID, sanitizeTextBlock(string(text)))
	if truncated {
		logger.Printf("--- 正文已截断：共 %d 字节，仅显示前 %d 字节；调整 -body-limit 或 output.max_body_bytes（0 表示不限制）",
			len(body), len(text))
	}
}

// printDetailBody 在 detail/debug 级别打印正文，并在截断时给出明确提示。
func printDetailBody(logger *log.Logger, cfg runConfig, m testmail.Message) {
	body := m.Body()
	if len(body) == 0 {
		logger.Printf("  正文: （空）")
		return
	}
	text, truncated := limitBytes(body, cfg.MaxBodyBytes)
	logger.Printf("  正文（共 %d 字节）:", len(body))
	for _, line := range strings.Split(strings.ReplaceAll(string(text), "\r\n", "\n"), "\n") {
		logger.Printf("    %s", sanitizeLine(line))
	}
	if truncated {
		logger.Printf("    …（已截断：正文共 %d 字节，仅显示前 %d 字节；调整 output.max_body_bytes 或 -body-limit 查看完整内容，0 表示不限制）",
			len(body), len(text))
	}
}

// printSessionEvent 打印一条会话级 SMTP 调试轨迹。
func printSessionEvent(logger *log.Logger, ev testmail.SessionEvent) {
	var text string
	switch ev.Kind {
	case testmail.SessionEventConnected:
		text = "连接建立"
	case testmail.SessionEventCommand:
		text = "C: " + joinNonEmpty(ev.Command, ev.Parameter)
	case testmail.SessionEventReply:
		text = "S: " + joinNonEmpty(ev.Command, ev.Parameter)
	case testmail.SessionEventTLS:
		text = "TLS: " + firstNonEmpty(ev.Parameter, "握手完成")
	case testmail.SessionEventAuth:
		text = "认证成功: " + ev.Parameter
	case testmail.SessionEventClosed:
		text = "连接关闭"
	default:
		text = string(ev.Kind)
	}
	logger.Printf("SMTP 轨迹 [会话 %d %s] %s", ev.SessionID, sanitizeLine(ev.RemoteAddr), sanitizeLine(text))
}

// joinNonEmpty 用空格连接非空片段。
func joinNonEmpty(parts ...string) string {
	kept := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			kept = append(kept, part)
		}
	}
	return strings.Join(kept, " ")
}

// firstNonEmpty 返回第一个非空字符串。
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// formatRecipients 把信封收件人格式化成 "<a@b> <c@d>"。
func formatRecipients(recipients []string) string {
	if len(recipients) == 0 {
		return "（无）"
	}
	parts := make([]string, 0, len(recipients))
	for _, recipient := range recipients {
		parts = append(parts, "<"+recipient+">")
	}
	return strings.Join(parts, " ")
}

// rawHeaderLines 返回原始消息字节中头部区的原文行（保留折行与原值），供详细输出
// 展示“全部头部原始值”。没有头部/正文分隔空行时按解析器的宽松策略把全部内容
// 视为头部。
func rawHeaderLines(data []byte) []string {
	block := data
	if sep := bytes.Index(data, []byte("\r\n\r\n")); sep >= 0 {
		block = data[:sep]
	}
	block = bytes.TrimSuffix(block, []byte("\r\n"))
	if len(block) == 0 {
		return nil
	}
	return strings.Split(string(block), "\r\n")
}

// limitBytes 按字节上限截断内容，并保证截断后的结果是合法的 UTF-8（避免把一个
// 多字节字符切成两半）。limit 为 0 表示不限制。
func limitBytes(data []byte, limit int) ([]byte, bool) {
	if limit <= 0 || len(data) <= limit {
		return data, false
	}
	truncated := data[:limit]
	for len(truncated) > 0 && !utf8.Valid(truncated) {
		truncated = truncated[:len(truncated)-1]
	}
	return truncated, true
}

// sanitizeLine 把单行文本中的控制字符转义成可见形式。
//
// 消息头部、正文与客户端命令都是不可信输入：其中的 ESC（0x1b）等控制字符可以
// 构造终端转义序列（例如修改标题、清屏、伪造输出）。输出前统一转义，避免本地
// 终端被注入；制表符保留，换行由调用方按行拆分后逐行处理。
func sanitizeLine(s string) string {
	if s == "" {
		return s
	}
	needsEscape := false
	for _, r := range s {
		if isUnsafeRune(r) {
			needsEscape = true
			break
		}
	}
	if !needsEscape {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, r := range s {
		if !isUnsafeRune(r) {
			b.WriteRune(r)
			continue
		}
		if r <= 0xff {
			fmt.Fprintf(&b, `\x%02x`, r)
			continue
		}
		fmt.Fprintf(&b, `\u%04x`, r)
	}
	return b.String()
}

// isUnsafeRune 报告字符是否需要转义：除制表符外的 C0 控制字符、DEL、C1 控制
// 字符与 Unicode 行/段分隔符（可能在部分终端里伪造换行）。
func isUnsafeRune(r rune) bool {
	switch {
	case r == '\t':
		return false
	case r < 0x20 || r == 0x7f:
		return true
	case r >= 0x80 && r <= 0x9f:
		return true
	case r == 0x2028 || r == 0x2029:
		return true
	default:
		return false
	}
}

// sanitizeTextBlock 按行转义整段文本中的控制字符并保留换行，用于正文输出。
func sanitizeTextBlock(s string) string {
	if s == "" {
		return s
	}
	normalized := strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
	lines := strings.Split(normalized, "\n")
	for i := range lines {
		lines[i] = sanitizeLine(lines[i])
	}
	return strings.Join(lines, "\n")
}
