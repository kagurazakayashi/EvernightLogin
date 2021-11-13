package testmail_test

import (
	"errors"
	"net"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/testmail"
)

// dialRawProto 直接建立 TCP 连接并返回 textproto 读取器，用于观察连接上限拒绝响应。
func dialRawProto(t *testing.T, addr net.Addr) (net.Conn, *textproto.Conn) {
	t.Helper()
	if addr == nil {
		t.Fatal("监听地址为空")
	}
	conn, err := net.DialTimeout("tcp", addr.String(), testDialTimeout)
	if err != nil {
		t.Fatalf("连接 %s 失败: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, textproto.NewConn(conn)
}

// readFirstLine 读取一行并返回（用于断言超限拒绝响应）。
func readFirstLine(t *testing.T, conn net.Conn, tp *textproto.Conn) string {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(netprotoDeadline))
	line, err := tp.ReadLine()
	if err != nil {
		t.Fatalf("读取协议响应失败: %v", err)
	}
	return line
}

// expectClosed 等待服务端关闭连接；期间允许先收到 BYE/-ERR 等提示行。
func expectClosed(t *testing.T, conn net.Conn, tp *textproto.Conn) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		if _, err := tp.ReadLine(); err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return
		}
	}
	t.Error("连接在预期时间内没有被服务端关闭")
}

// TestNetProtoConnectionLimit 验证 IMAP/POP3 各自的并发连接上限：超限连接会收到
// 协议级拒绝并被关闭，释放额度后可以重新连接。
func TestNetProtoConnectionLimit(t *testing.T) {
	srv := startServer(t, testmail.Options{
		Auth:           &testmail.AuthOptions{Users: map[string]string{"tester": "test-pass"}},
		MaxConnections: 1,
		IMAP:           &testmail.IMAPOptions{},
		POP3:           &testmail.POP3Options{},
	})

	// 占用 IMAP 唯一额度。
	firstIMAP := dialIMAP(t, srv)
	conn, tp := dialRawProto(t, srv.IMAPAddr())
	if line := readFirstLine(t, conn, tp); !strings.HasPrefix(line, "* BYE") {
		t.Errorf("IMAP 超限连接期望 * BYE，实际 %q", line)
	}

	// 占用 POP3 唯一额度。
	firstPOP3 := dialPOP3(t, srv)
	conn, tp = dialRawProto(t, srv.POP3Addr())
	if line := readFirstLine(t, conn, tp); !strings.HasPrefix(line, "-ERR") {
		t.Errorf("POP3 超限连接期望 -ERR，实际 %q", line)
	}

	// 关闭第一个 IMAP 连接释放额度后，新连接可以正常收到问候语。
	_ = firstIMAP.conn.Close()
	_ = firstPOP3.conn.Close()
	reconnected := dialIMAP(t, srv)
	reconnected.okCommand("A1 CAPABILITY")
}

// TestNetProtoReadTimeout 验证 IMAP/POP3 空闲连接会因读取超时被服务端关闭。
func TestNetProtoReadTimeout(t *testing.T) {
	srv := startServer(t, testmail.Options{
		Auth:        &testmail.AuthOptions{Users: map[string]string{"tester": "test-pass"}},
		ReadTimeout: 100 * time.Millisecond,
		IMAP:        &testmail.IMAPOptions{},
		POP3:        &testmail.POP3Options{},
	})

	imapClient := dialIMAP(t, srv)
	expectClosed(t, imapClient.conn, imapClient.tp)

	pop3Client := dialPOP3(t, srv)
	expectClosed(t, pop3Client.conn, pop3Client.tp)
}

// TestNetProtoSessionTimeout 验证单连接总时长上限会强制结束长会话。
func TestNetProtoSessionTimeout(t *testing.T) {
	srv := startServer(t, testmail.Options{
		Auth:           &testmail.AuthOptions{Users: map[string]string{"tester": "test-pass"}},
		ReadTimeout:    time.Second,
		SessionTimeout: 200 * time.Millisecond,
		IMAP:           &testmail.IMAPOptions{},
		POP3:           &testmail.POP3Options{},
	})

	imapClient := dialIMAP(t, srv)
	expectClosed(t, imapClient.conn, imapClient.tp)

	pop3Client := dialPOP3(t, srv)
	expectClosed(t, pop3Client.conn, pop3Client.tp)
}

// TestNetProtoPortsReleasedAfterClose 验证 Close 会关闭活动会话并释放 IMAP/POP3
// 端口，关闭后不能再连接。
func TestNetProtoPortsReleasedAfterClose(t *testing.T) {
	opts := testmail.Options{
		Auth: &testmail.AuthOptions{Users: map[string]string{"tester": "test-pass"}},
		IMAP: &testmail.IMAPOptions{},
		POP3: &testmail.POP3Options{},
	}
	srv, err := testmail.New(opts)
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start 失败: %v", err)
	}
	imapAddr := srv.IMAPAddr().String()
	pop3Addr := srv.POP3Addr().String()

	imapClient := dialIMAP(t, srv)
	pop3Client := dialPOP3(t, srv)

	if err := srv.Close(); err != nil {
		t.Fatalf("Close 失败: %v", err)
	}
	if _, err := imapClient.readLineErr(); err == nil {
		t.Error("Close 后活动 IMAP 会话应被断开")
	}
	if _, err := pop3Client.readLineErr(); err == nil {
		t.Error("Close 后活动 POP3 会话应被断开")
	}
	for _, addr := range []string{imapAddr, pop3Addr} {
		conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			t.Errorf("Close 后端口 %s 仍可连接，端口未释放", addr)
		}
	}
}

// TestNetProtoStartFailureIsAtomic 验证 IMAP 端口被占用时 Start 返回错误，并且不会
// 留下半启动状态（SMTP 监听器被关闭，Addr/IMAPAddr 保持为 nil）。
func TestNetProtoStartFailureIsAtomic(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("占用本地端口失败: %v", err)
	}
	defer func() { _ = occupied.Close() }()

	srv, err := testmail.New(testmail.Options{
		Auth: &testmail.AuthOptions{Users: map[string]string{"tester": "test-pass"}},
		IMAP: &testmail.IMAPOptions{Addr: occupied.Addr().String()},
	})
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	if err := srv.Start(); err == nil {
		_ = srv.Close()
		t.Fatal("IMAP 端口被占用时 Start 应返回错误")
	} else if !strings.Contains(err.Error(), "IMAP") {
		t.Errorf("错误信息应指出 IMAP 监听失败: %v", err)
	}
	if srv.Addr() != nil || srv.IMAPAddr() != nil {
		t.Errorf("Start 失败后不应保留监听器: SMTP=%v IMAP=%v", srv.Addr(), srv.IMAPAddr())
	}
	if err := srv.Close(); err != nil {
		t.Errorf("Start 失败后 Close 应成功: %v", err)
	}
}

// TestIMAPCommandLiteralLimits 验证 IMAP 命令累计字节与字面量个数的上限：
// 未认证客户端用大量小字面量或超大字面量累积内存时，服务端必须返回 BAD 并断开，
// 不能无上限增长内存。
func TestIMAPCommandLiteralLimits(t *testing.T) {
	srv := startServer(t, testmail.Options{
		Auth: &testmail.AuthOptions{Users: map[string]string{"tester": "test-pass"}},
		IMAP: &testmail.IMAPOptions{},
	})

	// 1) 字面量个数上限：反复追加 {1} 字面量，超过上限后必须 BAD 并断开。
	c := dialIMAP(t, srv)
	c.send("A1 NOOP {1}")
	if cont := c.readLine(); !strings.HasPrefix(cont, "+") {
		t.Fatalf("首个字面量期望继续响应，实际 %q", cont)
	}
	c.sendRaw("x")
	var bad string
	for i := 0; i < 40; i++ {
		c.send(" {1}")
		line := c.readLine()
		if strings.HasPrefix(line, "* BAD") {
			bad = line
			break
		}
		if !strings.HasPrefix(line, "+") {
			t.Fatalf("第 %d 个字面量继续响应异常: %q", i, line)
		}
		c.sendRaw("x")
	}
	if bad == "" {
		t.Fatal("超过字面量个数上限后未返回 * BAD")
	}
	if !strings.Contains(bad, "too large") {
		t.Errorf("超限响应应说明命令过大: %q", bad)
	}
	if _, err := c.readLineErr(); err == nil {
		t.Error("字面量个数超限后服务端应关闭连接")
	}

	// 2) 命令累计字节上限：两段 600000 字节字面量累计超过 1 MiB。
	c2 := dialIMAP(t, srv)
	c2.send("A2 NOOP {600000}")
	if cont := c2.readLine(); !strings.HasPrefix(cont, "+") {
		t.Fatalf("大字节字面量期望继续响应，实际 %q", cont)
	}
	c2.sendRaw(strings.Repeat("a", 600000))
	c2.send(" {600000}")
	if line := c2.readLine(); !strings.HasPrefix(line, "* BAD") {
		t.Fatalf("累计字节超限期望 * BAD，实际 %q", line)
	}
	if _, err := c2.readLineErr(); err == nil {
		t.Error("命令字节超限后服务端应关闭连接")
	}

	// 3) 单条声明超过命令累计上限的字面量直接拒绝（在读取内容之前）。
	c3 := dialIMAP(t, srv)
	c3.send("A3 NOOP {1048576}")
	if line := c3.readLine(); !strings.HasPrefix(line, "* BAD") {
		t.Fatalf("超大单字面量期望 * BAD，实际 %q", line)
	}
	if _, err := c3.readLineErr(); err == nil {
		t.Error("超大单字面量后服务端应关闭连接")
	}
}
