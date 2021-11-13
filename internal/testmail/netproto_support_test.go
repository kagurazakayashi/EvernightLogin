package testmail_test

import (
	"crypto/tls"
	"io"
	"net"
	"net/textproto"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/testmail"
)

// netprotoDeadline 是 IMAP/POP3 测试客户端的读写 deadline。
const netprotoDeadline = 5 * time.Second

// imapResponse 是一次 IMAP 命令的完整响应。
type imapResponse struct {
	// Lines 是按顺序收到的全部响应行（不含 tagged 状态行与字面量内容）。
	Lines []string
	// Literals 是按出现顺序收到的字面量内容（{n}）。
	Literals [][]byte
	// Status 是结束本次命令的 tagged 状态行。
	Status string
}

// statusCode 返回 tagged 状态行的状态码（OK/NO/BAD）。
func (r imapResponse) statusCode() string {
	fields := strings.Fields(r.Status)
	if len(fields) < 2 {
		return ""
	}
	return strings.ToUpper(fields[1])
}

// imapTestClient 是用 net/textproto 手写的最小 IMAP 测试客户端（不依赖第三方库）。
type imapTestClient struct {
	t    *testing.T
	conn net.Conn
	tp   *textproto.Conn
}

// dialIMAP 连接服务器的 IMAP 监听器并读取问候语。
func dialIMAP(t *testing.T, srv interface{ IMAPAddr() net.Addr }) *imapTestClient {
	t.Helper()
	return dialIMAPAddr(t, srv.IMAPAddr())
}

// dialIMAPAddr 连接给定 IMAP 地址并读取问候语（* OK）。
func dialIMAPAddr(t *testing.T, addr net.Addr) *imapTestClient {
	t.Helper()
	if addr == nil {
		t.Fatal("IMAP 监听地址为空")
	}
	conn, err := net.DialTimeout("tcp", addr.String(), testDialTimeout)
	if err != nil {
		t.Fatalf("连接 IMAP %s 失败: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return newIMAPTestClient(t, conn)
}

// dialIMAPTLS 用隐式 TLS 连接 IMAP 监听器并读取问候语。
func dialIMAPTLS(t *testing.T, addr net.Addr) *imapTestClient {
	t.Helper()
	if addr == nil {
		t.Fatal("IMAP 监听地址为空")
	}
	raw, err := net.DialTimeout("tcp", addr.String(), testDialTimeout)
	if err != nil {
		t.Fatalf("连接 IMAP %s 失败: %v", addr, err)
	}
	tlsConn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"})
	_ = tlsConn.SetDeadline(time.Now().Add(netprotoDeadline))
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("IMAP 隐式 TLS 握手失败: %v", err)
	}
	_ = tlsConn.SetDeadline(time.Time{})
	t.Cleanup(func() { _ = tlsConn.Close() })
	return newIMAPTestClient(t, tlsConn)
}

// newIMAPTestClient 在已建立的连接上读取问候语并返回客户端。
func newIMAPTestClient(t *testing.T, conn net.Conn) *imapTestClient {
	t.Helper()
	c := &imapTestClient{t: t, conn: conn, tp: textproto.NewConn(conn)}
	line := c.readLine()
	if !strings.HasPrefix(line, "* OK") {
		t.Fatalf("IMAP 问候语异常: %q", line)
	}
	return c
}

// readLine 读取一行（不含 CRLF）。
func (c *imapTestClient) readLine() string {
	c.t.Helper()
	line, err := c.readLineErr()
	if err != nil {
		c.t.Fatalf("读取 IMAP 行失败: %v", err)
	}
	return line
}

// readLineErr 读取一行（不含 CRLF），把读取错误返回给调用方（用于断言连接已关闭）。
func (c *imapTestClient) readLineErr() (string, error) {
	_ = c.conn.SetReadDeadline(time.Now().Add(netprotoDeadline))
	return c.tp.ReadLine()
}

// send 发送一行命令。
func (c *imapTestClient) send(line string) {
	c.t.Helper()
	_ = c.conn.SetWriteDeadline(time.Now().Add(netprotoDeadline))
	if err := c.tp.PrintfLine("%s", line); err != nil {
		c.t.Fatalf("发送 IMAP 命令 %q 失败: %v", line, err)
	}
}

// imapTrailingLiteral 匹配响应行末尾的 IMAP 字面量标记 {n}。
var imapTrailingLiteral = regexp.MustCompile(`\{(\d+)\}$`)

// command 发送一条命令并读取完整响应（含字面量），直到匹配 tag 的状态行。
func (c *imapTestClient) command(line string) imapResponse {
	c.t.Helper()
	fields := strings.Fields(line)
	if len(fields) == 0 {
		c.t.Fatal("IMAP 命令为空")
	}
	tag := fields[0]
	c.send(line)
	var resp imapResponse
	for {
		got := c.readLine()
		if strings.HasPrefix(got, tag+" ") {
			resp.Status = got
			return resp
		}
		if match := imapTrailingLiteral.FindStringSubmatch(got); len(match) == 2 {
			n, err := strconv.Atoi(match[1])
			if err != nil {
				c.t.Fatalf("无法解析字面量长度 %q: %v", got, err)
			}
			data := make([]byte, n)
			if _, err := io.ReadFull(c.tp.R, data); err != nil {
				c.t.Fatalf("读取 IMAP 字面量 %d 字节失败: %v", n, err)
			}
			resp.Literals = append(resp.Literals, data)
		}
		resp.Lines = append(resp.Lines, got)
	}
}

// okCommand 发送命令并断言 tagged 状态为 OK。
func (c *imapTestClient) okCommand(line string) imapResponse {
	c.t.Helper()
	resp := c.command(line)
	if resp.statusCode() != "OK" {
		c.t.Fatalf("命令 %q 期望 OK，实际: %q（响应行 %v）", line, resp.Status, resp.Lines)
	}
	return resp
}

// login 用 LOGIN 命令认证；成功时断言 OK。
func (c *imapTestClient) login(user, pass string) {
	c.t.Helper()
	c.okCommand(`A1 LOGIN "` + user + `" "` + pass + `"`)
}

// selectInbox 用 SELECT/EXAMINE 读取收件箱并返回响应。
func (c *imapTestClient) selectInbox(command string) imapResponse {
	c.t.Helper()
	return c.okCommand("A2 " + command + " INBOX")
}

// existsCount 从 SELECT 响应中解析 EXISTS 条数。
func (c *imapTestClient) existsCount(resp imapResponse) int {
	c.t.Helper()
	for _, line := range resp.Lines {
		if strings.HasSuffix(line, " EXISTS") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				n, err := strconv.Atoi(fields[1])
				if err == nil {
					return n
				}
			}
		}
	}
	c.t.Fatalf("响应中没有 EXISTS 行: %v", resp.Lines)
	return 0
}

// pop3TestClient 是用 net/textproto 手写的最小 POP3 测试客户端。
type pop3TestClient struct {
	t    *testing.T
	conn net.Conn
	tp   *textproto.Conn
}

// dialPOP3 连接服务器的 POP3 监听器并读取问候语。
func dialPOP3(t *testing.T, srv interface{ POP3Addr() net.Addr }) *pop3TestClient {
	t.Helper()
	return dialPOP3Addr(t, srv.POP3Addr())
}

// dialPOP3Addr 连接给定 POP3 地址并读取问候语（+OK）。
func dialPOP3Addr(t *testing.T, addr net.Addr) *pop3TestClient {
	t.Helper()
	if addr == nil {
		t.Fatal("POP3 监听地址为空")
	}
	conn, err := net.DialTimeout("tcp", addr.String(), testDialTimeout)
	if err != nil {
		t.Fatalf("连接 POP3 %s 失败: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return newPOP3TestClient(t, conn)
}

// dialPOP3TLS 用隐式 TLS 连接 POP3 监听器。
func dialPOP3TLS(t *testing.T, addr net.Addr) *pop3TestClient {
	t.Helper()
	if addr == nil {
		t.Fatal("POP3 监听地址为空")
	}
	raw, err := net.DialTimeout("tcp", addr.String(), testDialTimeout)
	if err != nil {
		t.Fatalf("连接 POP3 %s 失败: %v", addr, err)
	}
	tlsConn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"})
	_ = tlsConn.SetDeadline(time.Now().Add(netprotoDeadline))
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("POP3 隐式 TLS 握手失败: %v", err)
	}
	_ = tlsConn.SetDeadline(time.Time{})
	t.Cleanup(func() { _ = tlsConn.Close() })
	return newPOP3TestClient(t, tlsConn)
}

// newPOP3TestClient 在已建立的连接上读取问候语并返回客户端。
func newPOP3TestClient(t *testing.T, conn net.Conn) *pop3TestClient {
	t.Helper()
	c := &pop3TestClient{t: t, conn: conn, tp: textproto.NewConn(conn)}
	line := c.readLine()
	if !strings.HasPrefix(line, "+OK") {
		t.Fatalf("POP3 问候语异常: %q", line)
	}
	return c
}

// readLine 读取一行（不含 CRLF）。
func (c *pop3TestClient) readLine() string {
	c.t.Helper()
	line, err := c.readLineErr()
	if err != nil {
		c.t.Fatalf("读取 POP3 行失败: %v", err)
	}
	return line
}

// readLineErr 读取一行（不含 CRLF），把读取错误返回给调用方（用于断言连接已关闭）。
func (c *pop3TestClient) readLineErr() (string, error) {
	_ = c.conn.SetReadDeadline(time.Now().Add(netprotoDeadline))
	return c.tp.ReadLine()
}

// cmd 发送一条命令并返回单行响应。
func (c *pop3TestClient) cmd(line string) string {
	c.t.Helper()
	_ = c.conn.SetWriteDeadline(time.Now().Add(netprotoDeadline))
	if err := c.tp.PrintfLine("%s", line); err != nil {
		c.t.Fatalf("发送 POP3 命令 %q 失败: %v", line, err)
	}
	return c.readLine()
}

// expectOK 发送命令并断言 +OK。
func (c *pop3TestClient) expectOK(line string) string {
	c.t.Helper()
	resp := c.cmd(line)
	if !strings.HasPrefix(resp, "+OK") {
		c.t.Fatalf("命令 %q 期望 +OK，实际 %q", line, resp)
	}
	return resp
}

// expectErr 发送命令并断言 -ERR。
func (c *pop3TestClient) expectErr(line string) string {
	c.t.Helper()
	resp := c.cmd(line)
	if !strings.HasPrefix(resp, "-ERR") {
		c.t.Fatalf("命令 %q 期望 -ERR，实际 %q", line, resp)
	}
	return resp
}

// multiline 发送命令并读取多行响应（直到 "." 结束行），保持点填充原文。
func (c *pop3TestClient) multiline(line string) (string, []string) {
	c.t.Helper()
	status := c.cmd(line)
	if !strings.HasPrefix(status, "+OK") {
		c.t.Fatalf("多行命令 %q 期望 +OK，实际 %q", line, status)
	}
	var lines []string
	for {
		got := c.readLine()
		if got == "." {
			return status, lines
		}
		lines = append(lines, got)
	}
}

// login 用 USER/PASS 认证；成功时断言 +OK。
func (c *pop3TestClient) login(user, pass string) {
	c.t.Helper()
	c.expectOK("USER " + user)
	c.expectOK("PASS " + pass)
}

// loginExpectErr 用 USER/PASS 认证并断言 PASS 返回 -ERR。
func (c *pop3TestClient) loginExpectErr(user, pass string) {
	c.t.Helper()
	c.expectOK("USER " + user)
	c.expectErr("PASS " + pass)
}

// sendTestMail 通过真实 SMTP 会话向测试服务器投递一封邮件，并返回服务器保存的
// 消息（用于与 IMAP/POP3 读取内容逐字节比对）。headers 每项是一整行头部（不含
// CRLF），body 按 "\n" 分行。
func sendTestMail(t *testing.T, srv *testmail.Server, from string, to []string, headers []string, body string) testmail.Message {
	t.Helper()
	client := dialServer(t, srv)
	client.expectCode(250, "EHLO netproto.test")
	lines := make([]string, 0, len(headers)+2)
	lines = append(lines, headers...)
	lines = append(lines, "")
	if body != "" {
		lines = append(lines, strings.Split(body, "\n")...)
	}
	client.sendMail(from, to, strings.Join(lines, "\n"))
	msgs := srv.Messages(testmail.Query{})
	if len(msgs) == 0 {
		t.Fatal("SMTP 投递后内存仓库没有消息")
	}
	return msgs[len(msgs)-1]
}

// messageBySubject 在服务器内存仓库中按解码后的主题查找唯一一封邮件。
func messageBySubject(t *testing.T, srv *testmail.Server, subject string) testmail.Message {
	t.Helper()
	msgs := srv.Messages(testmail.Query{Subject: subject})
	if len(msgs) != 1 {
		t.Fatalf("按主题 %q 期望 1 封邮件，实际 %d 封", subject, len(msgs))
	}
	return msgs[0]
}
