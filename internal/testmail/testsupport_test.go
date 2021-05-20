package testmail_test

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/testmail"
)

const testDialTimeout = 2 * time.Second

// base64Of 返回 s 的标准 base64 编码，用于 AUTH 测试。
func base64Of(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// startServer 用给定配置启动服务器，并在测试结束时关闭。
func startServer(t *testing.T, opts testmail.Options) *testmail.Server {
	t.Helper()
	srv, err := testmail.New(opts)
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start 失败: %v", err)
	}
	t.Cleanup(func() {
		if err := srv.Close(); err != nil {
			t.Errorf("Close 失败: %v", err)
		}
	})
	return srv
}

// smtpClient 是最小测试用 SMTP 客户端，只依赖标准库。
type smtpClient struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
	w    *bufio.Writer
}

// dialServer 连接服务器并读取 220 问候语。
func dialServer(t *testing.T, srv *testmail.Server) *smtpClient {
	t.Helper()
	conn, err := net.DialTimeout("tcp", srv.Addr().String(), testDialTimeout)
	if err != nil {
		t.Fatalf("连接服务器失败: %v", err)
	}
	c := &smtpClient{t: t, conn: conn, r: bufio.NewReader(conn), w: bufio.NewWriter(conn)}
	t.Cleanup(func() { _ = conn.Close() })
	c.expect(220)
	return c
}

// dialRaw 连接服务器但不读取问候语，供协议边界测试使用。
func dialRaw(t *testing.T, srv *testmail.Server) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", srv.Addr().String(), testDialTimeout)
	if err != nil {
		t.Fatalf("连接服务器失败: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// readResponse 读取一条（可能多行的）响应。
func (c *smtpClient) readResponse() string {
	c.t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var lines []string
	for {
		line, err := c.r.ReadString('\n')
		if err != nil {
			c.t.Fatalf("读取响应失败: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		lines = append(lines, line)
		// 多行响应的续行第 4 个字符是 '-'，最后一行是空格。
		if len(line) < 4 || line[3] != '-' {
			break
		}
	}
	return strings.Join(lines, "\n")
}

// expect 读取一条响应并断言状态码。
func (c *smtpClient) expect(code int) string {
	c.t.Helper()
	resp := c.readResponse()
	if got := codeOf(c.t, resp); got != code {
		c.t.Fatalf("期望 SMTP %d，实际 %d：%q", code, got, resp)
	}
	return resp
}

// command 发送一行命令并读取一条响应。
func (c *smtpClient) command(line string) string {
	c.t.Helper()
	if _, err := io.WriteString(c.conn, line+"\r\n"); err != nil {
		c.t.Fatalf("发送命令 %q 失败: %v", line, err)
	}
	return c.readResponse()
}

// expectCode 发送命令并断言状态码。
func (c *smtpClient) expectCode(code int, line string) string {
	c.t.Helper()
	resp := c.command(line)
	if got := codeOf(c.t, resp); got != code {
		c.t.Fatalf("命令 %q 期望 SMTP %d，实际 %d：%q", line, code, got, resp)
	}
	return resp
}

// writeData 按点填充规则发送 DATA 内容并读取最终响应。data 用 "\n" 分隔行。
func (c *smtpClient) writeData(data string) string {
	c.t.Helper()
	var b strings.Builder
	if data != "" {
		for _, line := range strings.Split(data, "\n") {
			if strings.HasPrefix(line, ".") {
				b.WriteString(".")
			}
			b.WriteString(line)
			b.WriteString("\r\n")
		}
	}
	b.WriteString(".\r\n")
	if _, err := io.WriteString(c.conn, b.String()); err != nil {
		c.t.Fatalf("发送 DATA 内容失败: %v", err)
	}
	return c.readResponse()
}

// sendMail 完成一次完整发信并返回 DATA 之后的响应。
func (c *smtpClient) sendMail(from string, to []string, data string) string {
	c.t.Helper()
	c.expectCode(250, fmt.Sprintf("MAIL FROM:<%s>", from))
	for _, rcpt := range to {
		c.expectCode(250, fmt.Sprintf("RCPT TO:<%s>", rcpt))
	}
	c.expectCode(354, "DATA")
	resp := c.writeData(data)
	if got := codeOf(c.t, resp); got != 250 {
		c.t.Fatalf("DATA 后期望 250，实际 %d：%q", got, resp)
	}
	return resp
}

// startTLS 发送 STARTTLS、完成 TLS 握手并返回包装后的客户端。
func (c *smtpClient) startTLS() *smtpClient {
	c.t.Helper()
	c.expectCode(220, "STARTTLS")
	tlsConn := tls.Client(c.conn, &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"})
	_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		c.t.Fatalf("TLS 握手失败: %v", err)
	}
	_ = tlsConn.SetDeadline(time.Time{})
	return &smtpClient{t: c.t, conn: tlsConn, r: bufio.NewReader(tlsConn), w: bufio.NewWriter(tlsConn)}
}

// codeOf 解析响应首行的三位状态码。
func codeOf(t *testing.T, resp string) int {
	t.Helper()
	if len(resp) < 3 {
		t.Fatalf("响应过短: %q", resp)
	}
	var code int
	if _, err := fmt.Sscanf(resp[:3], "%d", &code); err != nil {
		t.Fatalf("无法解析响应码 %q: %v", resp, err)
	}
	return code
}

// dialAndReadGreeting 连接并返回首行应答；用于并发连接上限与就绪探测。
func dialAndReadGreeting(t *testing.T, addr string) (net.Conn, string, error) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, testDialTimeout)
	if err != nil {
		return nil, "", err
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		_ = conn.Close()
		return nil, "", err
	}
	return conn, strings.TrimRight(line, "\r\n"), nil
}

// drainConn 读取连接剩余内容直到关闭或超时，返回已读内容。
func drainConn(t *testing.T, conn net.Conn, timeout time.Duration) string {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	data, _ := io.ReadAll(conn)
	return string(data)
}
