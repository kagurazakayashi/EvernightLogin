package main

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/textproto"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// toolLiteralPattern 匹配 IMAP 响应行末尾的字面量标记 {n}。
var toolLiteralPattern = regexp.MustCompile(`\{(\d+)\}$`)

// toolIMAPClient 是 testmaild 端到端测试用最小 IMAP 客户端（net/textproto）。
type toolIMAPClient struct {
	t    *testing.T
	conn net.Conn
	tp   *textproto.Conn
}

// dialToolIMAP 连接 testmaild 的 IMAP 监听器（可选隐式 TLS）并读取问候语。
func dialToolIMAP(t *testing.T, addr string, useTLS bool) *toolIMAPClient {
	t.Helper()
	raw, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("连接 IMAP %s 失败: %v", addr, err)
	}
	var conn net.Conn = raw
	if useTLS {
		tlsConn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"})
		_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
		if err := tlsConn.Handshake(); err != nil {
			t.Fatalf("IMAP 隐式 TLS 握手失败: %v", err)
		}
		_ = tlsConn.SetDeadline(time.Time{})
		conn = tlsConn
	}
	t.Cleanup(func() { _ = conn.Close() })
	c := &toolIMAPClient{t: t, conn: conn, tp: textproto.NewConn(conn)}
	if greeting := c.readLine(); !strings.HasPrefix(greeting, "* OK") {
		t.Fatalf("IMAP 问候语异常: %q", greeting)
	}
	return c
}

// readLine 读取一行（不含 CRLF）。
func (c *toolIMAPClient) readLine() string {
	c.t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := c.tp.ReadLine()
	if err != nil {
		c.t.Fatalf("读取 IMAP 行失败: %v", err)
	}
	return line
}

// command 发送命令并读取完整响应（含字面量），返回响应行与字面量内容。
func (c *toolIMAPClient) command(line string) ([]string, []string) {
	c.t.Helper()
	tag := strings.Fields(line)[0]
	_ = c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := c.tp.PrintfLine("%s", line); err != nil {
		c.t.Fatalf("发送 IMAP 命令 %q 失败: %v", line, err)
	}
	var lines, literals []string
	for {
		got := c.readLine()
		if strings.HasPrefix(got, tag+" ") {
			lines = append(lines, got)
			return lines, literals
		}
		if match := toolLiteralPattern.FindStringSubmatch(got); len(match) == 2 {
			n, err := strconv.Atoi(match[1])
			if err != nil {
				c.t.Fatalf("无法解析 IMAP 字面量长度 %q: %v", got, err)
			}
			data := make([]byte, n)
			if _, err := io.ReadFull(c.tp.R, data); err != nil {
				c.t.Fatalf("读取 IMAP 字面量失败: %v", err)
			}
			literals = append(literals, string(data))
		}
		lines = append(lines, got)
	}
}

// toolPOP3Client 是 testmaild 端到端测试用最小 POP3 客户端（net/textproto）。
type toolPOP3Client struct {
	t    *testing.T
	conn net.Conn
	tp   *textproto.Conn
}

// dialToolPOP3 连接 testmaild 的 POP3 监听器（可选隐式 TLS）并读取问候语。
func dialToolPOP3(t *testing.T, addr string, useTLS bool) *toolPOP3Client {
	t.Helper()
	raw, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("连接 POP3 %s 失败: %v", addr, err)
	}
	var conn net.Conn = raw
	if useTLS {
		tlsConn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"})
		_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
		if err := tlsConn.Handshake(); err != nil {
			t.Fatalf("POP3 隐式 TLS 握手失败: %v", err)
		}
		_ = tlsConn.SetDeadline(time.Time{})
		conn = tlsConn
	}
	t.Cleanup(func() { _ = conn.Close() })
	c := &toolPOP3Client{t: t, conn: conn, tp: textproto.NewConn(conn)}
	line := c.readLine()
	if !strings.HasPrefix(line, "+OK") {
		t.Fatalf("POP3 问候语异常: %q", line)
	}
	return c
}

// readLine 读取一行（不含 CRLF）。
func (c *toolPOP3Client) readLine() string {
	c.t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := c.tp.ReadLine()
	if err != nil {
		c.t.Fatalf("读取 POP3 行失败: %v", err)
	}
	return line
}

// cmd 发送命令并返回单行响应。
func (c *toolPOP3Client) cmd(line string) string {
	c.t.Helper()
	_ = c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := c.tp.PrintfLine("%s", line); err != nil {
		c.t.Fatalf("发送 POP3 命令 %q 失败: %v", line, err)
	}
	return c.readLine()
}

// multiline 发送命令并读取多行响应（直到 "."）。
func (c *toolPOP3Client) multiline(line string) []string {
	c.t.Helper()
	status := c.cmd(line)
	if !strings.HasPrefix(status, "+OK") {
		c.t.Fatalf("POP3 多行命令 %q 期望 +OK，实际 %q", line, status)
	}
	var lines []string
	for {
		got := c.readLine()
		if got == "." {
			return lines
		}
		lines = append(lines, got)
	}
}

// protocolAddrFromOutput 从启动 banner 中解析某个协议的 host:port。
func protocolAddrFromOutput(t *testing.T, output, name string) string {
	t.Helper()
	marker := name + " 地址（host:port）: "
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		idx := strings.Index(line, marker)
		if idx < 0 {
			continue
		}
		addr := strings.TrimSpace(line[idx+len(marker):])
		if _, _, err := net.SplitHostPort(addr); err == nil {
			return addr
		}
	}
	t.Fatalf("启动输出中没有 %s 地址行:\n%s", name, output)
	return ""
}

// TestRunNetProtoBannerAndClients 端到端验证 testmaild 装配：banner 打印 IMAP/POP3
// 客户端连接参数与配置示例，真实客户端可认证并读取 SMTP 捕获的邮件，只读写操作
// 被拒绝，关闭后两个协议端口都释放。
func TestRunNetProtoBannerAndClients(t *testing.T) {
	rt := startTool(t, []string{
		"-addr", "127.0.0.1:0",
		"-auth", "tester:test-pass",
		"-auth", "tester2:test-pass-2",
		"-imap", "-imap-addr", "127.0.0.1:0",
		"-pop3", "-pop3-addr", "127.0.0.1:0",
		"-output", "detail",
	})
	smtpAddr := rt.addr(t)
	if !rt.stdout.waitFor("IMAP 地址（host:port）: ", 3*time.Second) {
		t.Fatalf("未打印 IMAP 地址: stdout=%q stderr=%q", rt.stdout.String(), rt.stderr.String())
	}
	if !rt.stdout.waitFor("POP3 地址（host:port）: ", 3*time.Second) {
		t.Fatalf("未打印 POP3 地址: stdout=%q", rt.stdout.String())
	}
	out := rt.stdout.String()
	imapAddr := protocolAddrFromOutput(t, out, "IMAP")
	pop3Addr := protocolAddrFromOutput(t, out, "POP3")

	wants := []string{
		"IMAP 只读收件箱（供 Thunderbird/Outlook/Foxmail 等客户端连接）",
		"POP3 只读收件箱（供 Thunderbird/Outlook/Foxmail 等客户端连接）",
		"Thunderbird 设置: 协议 IMAP",
		"Thunderbird 设置: 协议 POP3",
		"Outlook/Foxmail 设置: 账户类型 IMAP",
		"Outlook/Foxmail 设置: 账户类型 POP3",
		"连接安全性 无（明文）",
		"加密: 无（明文）",
		"只读说明: 拒绝 STORE/EXPUNGE/APPEND/COPY/MOVE",
		"测试密码: <命令行 -auth 给出的测试密码不回显>",
	}
	for _, want := range wants {
		if !strings.Contains(out, want) {
			t.Errorf("启动输出缺少 %q\n完整输出:\n%s", want, out)
		}
	}
	// 命令行 -auth 的测试密码只能用于认证，不得出现在任何输出中。
	if strings.Contains(out, "test-pass") {
		t.Errorf("命令行测试密码被回显: %q", out)
	}

	// 通过 SMTP 投递两封邮件（分别给两个账户）。
	if err := sendMail(smtpAddr, "sender@example.test", []string{"tester@example.test"}, "Subject: imap e2e\n\nhello imap"); err != nil {
		t.Fatalf("SMTP 投递 imap 邮件失败: %v", err)
	}
	if err := sendMail(smtpAddr, "sender@example.test", []string{"tester2@example.test"}, "Subject: pop3 e2e\n\nhello pop3"); err != nil {
		t.Fatalf("SMTP 投递 pop3 邮件失败: %v", err)
	}

	// IMAP：tester 登录、SELECT INBOX、FETCH BODY[]，并验证只读拒绝。
	imapClient := dialToolIMAP(t, imapAddr, false)
	lines, _ := imapClient.command(`A1 LOGIN "tester" "test-pass"`)
	if last := lines[len(lines)-1]; !strings.HasPrefix(last, "A1 OK") {
		t.Fatalf("IMAP LOGIN 期望 OK，实际 %q", last)
	}
	selectLines, _ := imapClient.command("A2 SELECT INBOX")
	if joined := strings.Join(selectLines, "\n"); !strings.Contains(joined, "* 1 EXISTS") {
		t.Errorf("IMAP SELECT 期望 1 封，实际: %v", selectLines)
	}
	_, literals := imapClient.command("A3 FETCH 1 (BODY[])")
	if len(literals) != 1 || !strings.Contains(literals[0], "hello imap") {
		t.Fatalf("IMAP FETCH 内容异常: %v", literals)
	}
	if strings.Contains(literals[0], "hello pop3") {
		t.Errorf("IMAP 账户隔离失败：tester 看到了 tester2 的邮件")
	}
	storeLines, _ := imapClient.command(`A4 STORE 1 +FLAGS (\Seen)`)
	if last := storeLines[len(storeLines)-1]; !strings.HasPrefix(last, "A4 NO") {
		t.Errorf("IMAP STORE 应被只读拒绝，实际 %q", last)
	}
	imapClient.command("A5 LOGOUT")

	// POP3：tester2 登录、STAT/RETR，验证账户隔离与内容。
	pop3Client := dialToolPOP3(t, pop3Addr, false)
	if resp := pop3Client.cmd("USER tester2"); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("POP3 USER 期望 +OK，实际 %q", resp)
	}
	if resp := pop3Client.cmd("PASS test-pass-2"); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("POP3 PASS 期望 +OK，实际 %q", resp)
	}
	if resp := pop3Client.cmd("STAT"); !strings.HasPrefix(resp, "+OK 1 ") {
		t.Fatalf("POP3 STAT 期望 1 封，实际 %q", resp)
	}
	retrLines := pop3Client.multiline("RETR 1")
	if joined := strings.Join(retrLines, "\r\n"); !strings.Contains(joined, "hello pop3") {
		t.Fatalf("POP3 RETR 内容异常: %v", retrLines)
	} else if strings.Contains(joined, "hello imap") {
		t.Errorf("POP3 账户隔离失败：tester2 看到了 tester 的邮件")
	}
	if resp := pop3Client.cmd("QUIT"); !strings.HasPrefix(resp, "+OK") {
		t.Errorf("POP3 QUIT 期望 +OK，实际 %q", resp)
	}

	if err := rt.stop(t); err != nil {
		t.Fatalf("优雅关闭返回错误: %v", err)
	}
	if !strings.Contains(rt.stdout.String(), "已关闭并释放端口") {
		t.Error("缺少关闭输出")
	}
	for _, addr := range []string{imapAddr, pop3Addr} {
		if conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond); err == nil {
			_ = conn.Close()
			t.Errorf("工具退出后仍能连接 %s，端口未释放", addr)
		}
	}
}

// TestRunNetProtoImplicitTLS 端到端验证 IMAP/POP3 隐式 TLS（自动生成自签测试证书）
// 的启动提示与真实 TLS 客户端连接。
func TestRunNetProtoImplicitTLS(t *testing.T) {
	rt := startTool(t, []string{
		"-addr", "127.0.0.1:0",
		"-auth", "tester:test-pass",
		"-imap", "-imap-tls",
		"-pop3", "-pop3-tls",
	})
	smtpAddr := rt.addr(t)
	if !rt.stdout.waitFor("IMAP 地址（host:port）: ", 3*time.Second) {
		t.Fatalf("未打印 IMAP 地址: stdout=%q stderr=%q", rt.stdout.String(), rt.stderr.String())
	}
	if !rt.stdout.waitFor("POP3 地址（host:port）: ", 3*time.Second) {
		t.Fatalf("未打印 POP3 地址: stdout=%q", rt.stdout.String())
	}
	out := rt.stdout.String()
	for _, want := range []string{
		"加密: 隐式 TLS",
		"SSL/TLS（隐式 TLS）",
		"信任自签证书",
		"客户端需显式信任或跳过校验",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("隐式 TLS 启动输出缺少 %q\n完整输出:\n%s", want, out)
		}
	}
	imapAddr := protocolAddrFromOutput(t, out, "IMAP")
	pop3Addr := protocolAddrFromOutput(t, out, "POP3")

	if err := sendMail(smtpAddr, "sender@example.test", []string{"tester@example.test"}, "Subject: tls proto\n\nhello tls"); err != nil {
		t.Fatalf("SMTP 投递失败: %v", err)
	}

	imapClient := dialToolIMAP(t, imapAddr, true)
	lines, _ := imapClient.command(`A1 LOGIN "tester" "test-pass"`)
	if last := lines[len(lines)-1]; !strings.HasPrefix(last, "A1 OK") {
		t.Fatalf("IMAP TLS LOGIN 期望 OK，实际 %q", last)
	}
	imapClient.command("A2 SELECT INBOX")
	_, literals := imapClient.command("A3 FETCH 1 (BODY[])")
	if len(literals) != 1 || !strings.Contains(literals[0], "hello tls") {
		t.Fatalf("IMAP TLS FETCH 内容异常: %v", literals)
	}
	imapClient.command("A4 LOGOUT")

	pop3Client := dialToolPOP3(t, pop3Addr, true)
	pop3Client.cmd("USER tester")
	if resp := pop3Client.cmd("PASS test-pass"); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("POP3 TLS PASS 期望 +OK，实际 %q", resp)
	}
	if resp := pop3Client.cmd("STAT"); !strings.HasPrefix(resp, "+OK 1 ") {
		t.Fatalf("POP3 TLS STAT 期望 1 封，实际 %q", resp)
	}
	pop3Client.cmd("QUIT")

	if err := rt.stop(t); err != nil {
		t.Fatalf("优雅关闭返回错误: %v", err)
	}
}

// TestRunNetProtoFromConfigFile 验证配置文件方式启用 IMAP/POP3 后 banner 与客户端
// 连接都可用（命令行未显式给出协议参数）。
func TestRunNetProtoFromConfigFile(t *testing.T) {
	configPath := writeConfig(t, `
listen:
  addr: "127.0.0.1:0"
auth:
  accounts:
    - username: "tester"
      password: "test-pass"
imap:
  enabled: true
  addr: "127.0.0.1:0"
pop3:
  enabled: true
  addr: "127.0.0.1:0"
output:
  level: "detail"
`)
	rt := startTool(t, []string{"-config", configPath})
	smtpAddr := rt.addr(t)
	if !rt.stdout.waitFor("IMAP 地址（host:port）: ", 3*time.Second) {
		t.Fatalf("未打印 IMAP 地址: stdout=%q stderr=%q", rt.stdout.String(), rt.stderr.String())
	}
	if !rt.stdout.waitFor("POP3 地址（host:port）: ", 3*time.Second) {
		t.Fatalf("未打印 POP3 地址: stdout=%q", rt.stdout.String())
	}
	out := rt.stdout.String()
	if !strings.Contains(out, "用户名=tester 密码=test-pass") {
		t.Errorf("配置文件来源的测试密码应按既有格式回显: %q", out)
	}
	if !strings.Contains(out, "测试密码: 见上方模拟账户清单（本地测试凭据、仅回环使用）") {
		t.Errorf("协议段缺少测试密码来源说明: %q", out)
	}
	imapAddr := protocolAddrFromOutput(t, out, "IMAP")
	pop3Addr := protocolAddrFromOutput(t, out, "POP3")

	if err := sendMail(smtpAddr, "sender@example.test", []string{"tester@example.test"}, "Subject: config proto\n\nhello config"); err != nil {
		t.Fatalf("SMTP 投递失败: %v", err)
	}
	imapClient := dialToolIMAP(t, imapAddr, false)
	lines, _ := imapClient.command(`A1 LOGIN "tester" "test-pass"`)
	if last := lines[len(lines)-1]; !strings.HasPrefix(last, "A1 OK") {
		t.Fatalf("配置启用 IMAP 后 LOGIN 期望 OK，实际 %q", last)
	}
	imapClient.command("A2 SELECT INBOX")
	_, literals := imapClient.command("A3 FETCH 1 (BODY[])")
	if len(literals) != 1 || !strings.Contains(literals[0], "hello config") {
		t.Fatalf("配置启用 IMAP 后 FETCH 内容异常: %v", literals)
	}
	pop3Client := dialToolPOP3(t, pop3Addr, false)
	pop3Client.cmd("USER tester")
	pop3Client.cmd("PASS test-pass")
	if resp := pop3Client.cmd("STAT"); !strings.HasPrefix(resp, "+OK 1 ") {
		t.Fatalf("配置启用 POP3 后 STAT 期望 1 封，实际 %q", resp)
	}
	if err := rt.stop(t); err != nil {
		t.Fatalf("优雅关闭返回错误: %v", err)
	}
}

// TestRunNetProtoConfigErrors 验证 IMAP/POP3 的配置错误在阻塞等待前返回。
func TestRunNetProtoConfigErrors(t *testing.T) {
	cases := [][]string{
		{"-imap"}, // 没有模拟账户
		{"-pop3"}, // 没有模拟账户
		{"-imap", "-auth", "tester:test-pass", "-imap-addr", "0.0.0.0:0"},       // 明文非回环
		{"-pop3", "-auth", "tester:test-pass", "-pop3-addr", "0.0.0.0:0"},       // 明文非回环
		{"-imap", "-auth", "tester:test-pass", "-imap-addr", "bad-address"},     // 地址语法错误
		{"-pop3", "-auth", "tester:test-pass", "-pop3-addr", "127.0.0.1:99999"}, // 端口非法
	}
	for _, args := range cases {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var stdout, stderr syncBuffer
			if err := run(context.Background(), args, &stdout, &stderr); err == nil {
				t.Fatalf("参数 %v 应返回错误", args)
			}
		})
	}
}
