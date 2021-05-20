package testmail_test

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/testmail"
)

// expectCodeFrom 从 reader 读取一条（可能多行）响应并断言状态码。
func expectCodeFrom(r *bufio.Reader, want int) error {
	var first string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return fmt.Errorf("读取响应失败: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if first == "" {
			first = line
		}
		if len(line) < 4 || line[3] != '-' {
			break
		}
	}
	var got int
	if _, err := fmt.Sscanf(first[:3], "%d", &got); err != nil {
		return fmt.Errorf("无法解析响应码 %q: %w", first, err)
	}
	if got != want {
		return fmt.Errorf("期望 SMTP %d，实际 %d（%q）", want, got, first)
	}
	return nil
}

// commandFrom 发送一行命令并断言响应码。
func commandFrom(conn net.Conn, r *bufio.Reader, line string, want int) error {
	if _, err := io.WriteString(conn, line+"\r\n"); err != nil {
		return err
	}
	return expectCodeFrom(r, want)
}

// sendOneMail 在独立 goroutine 中完成一次发信，供并发测试使用（不调用 t.Fatalf）。
func sendOneMail(addr, from, to, subject string) error {
	conn, err := net.DialTimeout("tcp", addr, testDialTimeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(conn)
	if err := expectCodeFrom(r, 220); err != nil {
		return err
	}
	steps := []struct {
		line string
		want int
	}{
		{"EHLO concurrent.test", 250},
		{"MAIL FROM:<" + from + ">", 250},
		{"RCPT TO:<" + to + ">", 250},
		{"DATA", 354},
	}
	for _, step := range steps {
		if err := commandFrom(conn, r, step.line, step.want); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(conn, "Subject: "+subject+"\r\n\r\nbody\r\n.\r\n"); err != nil {
		return err
	}
	return expectCodeFrom(r, 250)
}

// TestMessageSizeLimit 验证单消息大小上限返回 552，且同一连接可继续发送小消息。
func TestMessageSizeLimit(t *testing.T) {
	srv := startServer(t, testmail.Options{MaxMessageBytes: 1024})
	c := wrapRaw(t, dialRaw(t, srv))
	c.expect(220)
	c.expectCode(250, "EHLO client.example.test")
	c.expectCode(250, "MAIL FROM:<a@example.test>")
	c.expectCode(250, "RCPT TO:<b@example.test>")
	c.expectCode(354, "DATA")
	big := "Subject: big\n\n" + strings.Repeat("x", 2048)
	if resp := c.writeData(big); !strings.HasPrefix(resp, "552") {
		t.Fatalf("超限消息应返回 552，实际 %q", resp)
	}
	// 超限后事务已重置，可以继续正常发信。
	c.sendMail("a@example.test", []string{"b@example.test"}, "Subject: small\n\nok")
	if got := srv.MessageCount(); got != 1 {
		t.Fatalf("超限消息不应保存，期望 1 封，实际 %d", got)
	}
}

// TestRecipientLimit 验证超限收件人返回 452，且限额内的收件人能正常收信。
func TestRecipientLimit(t *testing.T) {
	srv := startServer(t, testmail.Options{MaxRecipients: 2})
	c := wrapRaw(t, dialRaw(t, srv))
	c.expect(220)
	c.expectCode(250, "EHLO client.example.test")
	c.expectCode(250, "MAIL FROM:<a@example.test>")
	c.expectCode(250, "RCPT TO:<one@example.test>")
	c.expectCode(250, "RCPT TO:<two@example.test>")
	c.expectCode(452, "RCPT TO:<three@example.test>")
	c.expectCode(354, "DATA")
	if resp := c.writeData("Subject: two\n\nbody"); !strings.HasPrefix(resp, "250") {
		t.Fatalf("DATA 响应异常: %q", resp)
	}
	msgs := srv.Messages(testmail.Query{})
	if len(msgs) != 1 || len(msgs[0].EnvelopeTo) != 2 {
		t.Fatalf("消息收件人异常: %+v", msgs)
	}
}

// TestStoreCapacity 验证内存保留上限：满时返回 452，清空后可继续接收。
func TestStoreCapacity(t *testing.T) {
	srv := startServer(t, testmail.Options{MaxMessages: 1})
	c := dialServer(t, srv)
	c.expectCode(250, "EHLO client.example.test")
	c.sendMail("a@example.test", []string{"b@example.test"}, "Subject: first\n\none")

	c.expectCode(250, "MAIL FROM:<a@example.test>")
	c.expectCode(250, "RCPT TO:<b@example.test>")
	c.expectCode(354, "DATA")
	if resp := c.writeData("Subject: second\n\ntwo"); !strings.HasPrefix(resp, "452") {
		t.Fatalf("满容量时应返回 452，实际 %q", resp)
	}
	if got := srv.MessageCount(); got != 1 {
		t.Fatalf("满容量被拒的消息不应保存，实际 %d", got)
	}
	srv.Clear()
	c.sendMail("a@example.test", []string{"b@example.test"}, "Subject: third\n\nthree")
	if got := srv.MessageCount(); got != 1 {
		t.Fatalf("清空后应能继续接收，实际 %d", got)
	}
}

// TestConcurrentConnectionLimit 验证并发连接上限：超限连接收到 421，连接释放后
// 额度恢复。
func TestConcurrentConnectionLimit(t *testing.T) {
	srv := startServer(t, testmail.Options{MaxConnections: 2})
	c1 := dialServer(t, srv)
	_ = dialServer(t, srv)

	conn3, line3, err := dialAndReadGreeting(t, srv.Addr().String())
	if err != nil {
		t.Fatalf("第 3 个连接读取问候失败: %v", err)
	}
	if !strings.HasPrefix(line3, "421") {
		_ = conn3.Close()
		t.Fatalf("超限连接应收到 421，实际 %q", line3)
	}
	_ = conn3.Close()

	// 释放一个额度后，新连接应能正常获得 220 问候。
	_ = c1.conn.Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		conn, line, err := dialAndReadGreeting(t, srv.Addr().String())
		if err == nil {
			_ = conn.Close()
			if strings.HasPrefix(line, "220") {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("关闭连接后并发额度未恢复（最后问候 %q，错误 %v）", line, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestConcurrentSessionsDistinctMessages 验证多连接并发收信互不干扰。
func TestConcurrentSessionsDistinctMessages(t *testing.T) {
	srv := startServer(t, testmail.Options{MaxConnections: 16})
	addr := srv.Addr().String()
	const n = 8
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- sendOneMail(addr, fmt.Sprintf("from%d@example.test", i), "target@example.test", fmt.Sprintf("concurrent-%d", i))
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("并发发信失败: %v", err)
		}
	}
	if got := srv.MessageCount(); got != n {
		t.Fatalf("期望 %d 封消息，实际 %d", n, got)
	}
	for i := 0; i < n; i++ {
		subject := fmt.Sprintf("concurrent-%d", i)
		msgs := srv.Messages(testmail.Query{Subject: subject})
		if len(msgs) != 1 {
			t.Fatalf("主题 %q 应命中 1 封，实际 %d", subject, len(msgs))
		}
		if msgs[0].EnvelopeFrom != fmt.Sprintf("from%d@example.test", i) {
			t.Errorf("消息信封来源异常: %q", msgs[0].EnvelopeFrom)
		}
	}
}
