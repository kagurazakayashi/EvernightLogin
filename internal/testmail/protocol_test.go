package testmail_test

import (
	"bufio"
	"encoding/base64"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/testmail"
)

// wrapRaw 把已有连接包装成测试客户端（用于需要精细控制时序的用例）。
func wrapRaw(t *testing.T, conn net.Conn) *smtpClient {
	t.Helper()
	return &smtpClient{t: t, conn: conn, r: bufio.NewReader(conn), w: bufio.NewWriter(conn)}
}

// TestCommandSequenceErrors 覆盖命令顺序错误、语法错误与未知命令：全部返回标准
// 错误码，连接保持可用。
func TestCommandSequenceErrors(t *testing.T) {
	srv := startServer(t, testmail.Options{})
	c := wrapRaw(t, dialRaw(t, srv))
	c.expect(220)

	c.expectCode(503, "MAIL FROM:<a@example.test>") // 未 HELO/EHLO
	c.expectCode(250, "EHLO client.example.test")
	c.expectCode(503, "RCPT TO:<a@example.test>") // 未 MAIL
	c.expectCode(503, "DATA")

	c.expectCode(500, "XYZZY")
	c.expectCode(500, "")
	c.expectCode(501, "MAIL FROM:")
	c.expectCode(250, "MAIL FROM:<>") // 空发送者（退信）合法
	c.expectCode(501, "RCPT TO:<>")
	c.expectCode(501, "RCPT TO:<bad address>")
	c.expectCode(501, "RCPT TO:") // 有 MAIL 但地址为空
	c.expectCode(250, "RSET")
	c.expectCode(250, "NOOP")
	c.expectCode(502, "VRFY someone")
	c.expectCode(221, "QUIT")
	if _, err := c.r.ReadByte(); err == nil {
		t.Fatal("QUIT 后连接应被关闭")
	}
}

// TestSyntaxVariants 验证大小写与尖括号/空格写法都被接受。
func TestSyntaxVariants(t *testing.T) {
	srv := startServer(t, testmail.Options{})
	c := wrapRaw(t, dialRaw(t, srv))
	c.expect(220)
	c.expectCode(250, "ehlo client.example.test")
	c.expectCode(250, "mail from: <a@example.test> size=100")
	c.expectCode(250, "rcpt to:<b@example.test>")
	c.expectCode(354, "data")
	resp := c.writeData("Subject: x\n\nbody")
	if !strings.Contains(resp, "250") {
		t.Fatalf("DATA 响应异常: %q", resp)
	}
	msgs := srv.Messages(testmail.Query{To: "b@example.test"})
	if len(msgs) != 1 || msgs[0].EnvelopeFrom != "a@example.test" {
		t.Fatalf("消息异常: %+v", msgs)
	}
}

// TestAuthRequiredAndLogin 覆盖"要求认证"、认证失败与 AUTH LOGIN 成功。
func TestAuthRequiredAndLogin(t *testing.T) {
	srv := startServer(t, testmail.Options{
		Auth: &testmail.AuthOptions{
			Users:       map[string]string{"tester": "s3cret-test"},
			RequireAuth: true,
		},
	})
	c := wrapRaw(t, dialRaw(t, srv))
	c.expect(220)
	resp := c.expectCode(250, "EHLO client.example.test")
	if !strings.Contains(resp, "AUTH PLAIN LOGIN") {
		t.Fatalf("配置 AUTH 后应在 EHLO 中公布能力: %q", resp)
	}
	c.expectCode(530, "MAIL FROM:<a@example.test>") // 未认证
	// 失败一次：AUTH LOGIN 初始响应提交用户名 wrong，再提交错误密码。
	c.expectCode(334, "AUTH LOGIN d3Jvbmc=") // base64("wrong")，服务端回 Password: 挑战
	if _, err := io.WriteString(c.conn, base64.StdEncoding.EncodeToString([]byte("nope"))+"\r\n"); err != nil {
		t.Fatalf("发送密码失败: %v", err)
	}
	c.expect(535)

	// 成功：先从 Username: 挑战开始，再提交密码。
	c.expectCode(334, "AUTH LOGIN")
	if _, err := io.WriteString(c.conn, base64.StdEncoding.EncodeToString([]byte("tester"))+"\r\n"); err != nil {
		t.Fatalf("发送用户名失败: %v", err)
	}
	c.expect(334) // Password:
	if _, err := io.WriteString(c.conn, base64.StdEncoding.EncodeToString([]byte("s3cret-test"))+"\r\n"); err != nil {
		t.Fatalf("发送密码失败: %v", err)
	}
	c.expect(235)

	c.sendMail("a@example.test", []string{"b@example.test"}, "Subject: authed\n\nbody")
	msgs := srv.Messages(testmail.Query{})
	if len(msgs) != 1 || msgs[0].AuthUser != "tester" {
		t.Fatalf("认证后的消息应记录 AuthUser: %+v", msgs)
	}
	c.expectCode(503, "AUTH PLAIN") // 已认证
}

// TestAuthPlain 覆盖 AUTH PLAIN（带初始响应与不带初始响应两种）。
func TestAuthPlain(t *testing.T) {
	srv := startServer(t, testmail.Options{
		Auth: &testmail.AuthOptions{Users: map[string]string{"tester": "s3cret-test"}},
	})
	payload := base64.StdEncoding.EncodeToString([]byte("\x00tester\x00s3cret-test"))

	c := wrapRaw(t, dialRaw(t, srv))
	c.expect(220)
	c.expectCode(250, "EHLO client.example.test")
	c.expectCode(235, "AUTH PLAIN "+payload)

	c2 := wrapRaw(t, dialRaw(t, srv))
	c2.expect(220)
	c2.expectCode(250, "EHLO client.example.test")
	c2.expectCode(334, "AUTH PLAIN") // 不带初始响应时服务端发出空挑战
	if _, err := io.WriteString(c2.conn, payload+"\r\n"); err != nil {
		t.Fatalf("发送 PLAIN 响应失败: %v", err)
	}
	c2.expect(235)
}

// TestAuthFailuresCloseConnection 验证连续认证失败后连接被 421 关闭。
func TestAuthFailuresCloseConnection(t *testing.T) {
	srv := startServer(t, testmail.Options{
		Auth: &testmail.AuthOptions{Users: map[string]string{"tester": "s3cret-test"}},
	})
	c := wrapRaw(t, dialRaw(t, srv))
	c.expect(220)
	c.expectCode(250, "EHLO client.example.test")
	bad := "AUTH PLAIN " + base64.StdEncoding.EncodeToString([]byte("\x00tester\x00wrong"))
	c.expectCode(535, bad)
	c.expectCode(535, bad)
	resp := c.command(bad)
	if got := codeOf(t, resp); got != 421 {
		t.Fatalf("第 3 次认证失败应返回 421 关闭连接，实际 %d: %q", got, resp)
	}
	if _, err := c.r.ReadByte(); err == nil {
		t.Fatal("认证失败上限后连接应被关闭")
	}
}

// TestAuthNotConfigured 验证未配置 AUTH 时返回 502。
func TestAuthNotConfigured(t *testing.T) {
	srv := startServer(t, testmail.Options{})
	c := wrapRaw(t, dialRaw(t, srv))
	c.expect(220)
	c.expectCode(250, "EHLO client.example.test")
	c.expectCode(502, "AUTH PLAIN")
	c.expectCode(502, "STARTTLS") // 未配置 TLS
}

// TestSTARTTLS 覆盖 STARTTLS 启用：能力公布、握手、TLS 会话重新 EHLO 与收信标记。
func TestSTARTTLS(t *testing.T) {
	cert, err := testmail.GenerateTestCertificate()
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}
	srv := startServer(t, testmail.Options{TLS: &testmail.TLSOptions{Certificate: cert}})
	c := dialServer(t, srv)
	resp := c.expectCode(250, "EHLO client.example.test")
	if !strings.Contains(resp, "STARTTLS") {
		t.Fatalf("配置 TLS 后应公布 STARTTLS: %q", resp)
	}
	tlsClient := c.startTLS()
	tlsResp := tlsClient.expectCode(250, "EHLO client.example.test")
	if strings.Contains(tlsResp, "STARTTLS") {
		t.Fatalf("TLS 建立后不应再公布 STARTTLS: %q", tlsResp)
	}
	tlsClient.sendMail("a@example.test", []string{"b@example.test"}, "Subject: tls\n\nsecret body")

	msgs := srv.Messages(testmail.Query{})
	if len(msgs) != 1 {
		t.Fatalf("期望 1 封消息，实际 %d", len(msgs))
	}
	if !msgs[0].TLS {
		t.Error("经 STARTTLS 接收的消息应标记 TLS")
	}
}

// TestReadTimeout 验证空闲连接在单次读取超时后收到 421 并被关闭。
func TestReadTimeout(t *testing.T) {
	srv := startServer(t, testmail.Options{ReadTimeout: 100 * time.Millisecond})
	c := wrapRaw(t, dialRaw(t, srv))
	c.expect(220)
	start := time.Now()
	data := drainConn(t, c.conn, 2*time.Second)
	elapsed := time.Since(start)
	if elapsed > time.Second {
		t.Fatalf("读取超时后服务端未及时关闭连接，耗时 %v", elapsed)
	}
	if !strings.Contains(data, "421") {
		t.Errorf("关闭前应发送 421 超时提示，实际 %q", data)
	}
}

// TestSessionTimeout 验证会话总时长上限：即使客户端持续发命令，连接也会在
// SessionTimeout 之后被关闭。
func TestSessionTimeout(t *testing.T) {
	srv := startServer(t, testmail.Options{
		ReadTimeout:    2 * time.Second,
		SessionTimeout: 300 * time.Millisecond,
	})
	c := wrapRaw(t, dialRaw(t, srv))
	c.expect(220)
	start := time.Now()
	deadline := start.Add(2 * time.Second)
	closed := false
	for time.Now().Before(deadline) {
		if _, err := io.WriteString(c.conn, "NOOP\r\n"); err != nil {
			closed = true
			break
		}
		if _, err := c.r.ReadString('\n'); err != nil {
			closed = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !closed {
		t.Fatal("会话总时长上限未生效，连接仍然可用")
	}
	if elapsed := time.Since(start); elapsed > 1500*time.Millisecond {
		t.Errorf("会话持续时间过长（%v），总时长上限可能未生效", elapsed)
	}
}
