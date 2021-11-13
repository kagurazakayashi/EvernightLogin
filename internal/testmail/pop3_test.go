package testmail_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/testmail"
)

// newPOP3TestServer 启动带模拟账户与 POP3 监听器的测试服务器。
func newPOP3TestServer(t *testing.T, extra func(*testmail.Options)) *testmail.Server {
	t.Helper()
	opts := testmail.Options{
		Auth: &testmail.AuthOptions{Users: map[string]string{
			"tester":  "test-pass",
			"tester2": "test-pass-2",
		}},
		POP3: &testmail.POP3Options{},
	}
	if extra != nil {
		extra(&opts)
	}
	return startServer(t, opts)
}

// pop3Stat 解析 STAT 应答中的邮件数与总字节数。
func pop3Stat(t *testing.T, response string) (count, size int) {
	t.Helper()
	fields := strings.Fields(response)
	if len(fields) < 3 {
		t.Fatalf("STAT 应答异常: %q", response)
	}
	count, err := strconv.Atoi(fields[1])
	if err != nil {
		t.Fatalf("STAT 邮件数解析失败: %q", response)
	}
	size, err = strconv.Atoi(fields[2])
	if err != nil {
		t.Fatalf("STAT 字节数解析失败: %q", response)
	}
	return count, size
}

// TestPOP3AuthListRetrAndTop 用真实 POP3 协议验证认证、STAT/LIST/RETR/TOP 与
// SMTP 捕获内容一致，并验证 DELE 仅本会话隐藏、RSET 恢复、QUIT 不删除共享存储。
func TestPOP3AuthListRetrAndTop(t *testing.T) {
	srv := newPOP3TestServer(t, nil)
	stored := sendTestMail(t, srv, "sender@example.test", []string{"tester@example.test"}, []string{
		"From: Sender <sender@example.test>",
		"To: Tester <tester@example.test>",
		"Subject: pop3 subject",
		"Date: Thu, 19 Nov 2026 10:00:00 +0800",
	}, "第一行正文\n第二行正文\n第三行正文")

	c := dialPOP3(t, srv)

	// 认证失败返回 -ERR，但连接保持可用；随后正确凭据可以登录。
	c.loginExpectErr("tester", "wrong-pass")
	c.login("tester", "test-pass")

	count, size := pop3Stat(t, c.expectOK("STAT"))
	if count != 1 || size != len(stored.Data) {
		t.Fatalf("STAT 期望 1 封 %d 字节，实际 %d 封 %d 字节", len(stored.Data), count, size)
	}

	listStatus, listLines := c.multiline("LIST")
	if !strings.Contains(listStatus, "1 messages") {
		t.Errorf("LIST 状态异常: %q", listStatus)
	}
	if len(listLines) != 1 || listLines[0] != "1 "+strconv.Itoa(len(stored.Data)) {
		t.Errorf("LIST 行异常: %v", listLines)
	}

	// RETR 内容必须与 SMTP 捕获的原始字节逐字节一致。
	retrStatus, retrLines := c.multiline("RETR 1")
	if !strings.Contains(retrStatus, strconv.Itoa(len(stored.Data))+" octets") {
		t.Errorf("RETR 状态异常: %q", retrStatus)
	}
	if got := strings.Join(retrLines, "\r\n") + "\r\n"; got != string(stored.Data) {
		t.Errorf("RETR 内容与 SMTP 捕获不一致:\nPOP3=%q\nSMTP=%q", got, stored.Data)
	}

	// TOP 1 1 返回全部头部与 1 行正文。
	_, topLines := c.multiline("TOP 1 1")
	top := strings.Join(topLines, "\n")
	if !strings.Contains(top, "Subject: pop3 subject") {
		t.Errorf("TOP 缺少头部: %v", topLines)
	}
	if !strings.Contains(top, "第一行正文") {
		t.Errorf("TOP 缺少正文首行: %v", topLines)
	}
	if strings.Contains(top, "第二行正文") {
		t.Errorf("TOP 只应返回 1 行正文: %v", topLines)
	}

	// CAPA 至少公布 USER 与 TOP。
	_, capaLines := c.multiline("CAPA")
	capa := strings.Join(capaLines, "\n")
	for _, want := range []string{"USER", "TOP"} {
		if !strings.Contains(capa, want) {
			t.Errorf("CAPA 缺少 %q: %v", want, capaLines)
		}
	}

	// DELE 只在本会话隐藏：STAT/LIST 减少，RETR 拒绝。
	c.expectOK("DELE 1")
	if count, _ := pop3Stat(t, c.expectOK("STAT")); count != 0 {
		t.Errorf("DELE 后 STAT 期望 0 封，实际 %d", count)
	}
	c.expectErr("RETR 1")
	c.expectErr("DELE 1")
	// RSET 取消删除标记。
	c.expectOK("RSET")
	if count, _ := pop3Stat(t, c.expectOK("STAT")); count != 1 {
		t.Errorf("RSET 后 STAT 期望 1 封，实际 %d", count)
	}

	// 未支持命令返回 -ERR，不崩溃。
	c.expectErr("XNOOP")

	// QUIT 不删除共享存储：新会话仍能看到同一封邮件。
	c.expectOK("QUIT")
	if _, err := c.readLineErr(); err == nil {
		t.Error("QUIT 后连接应被服务端关闭")
	}
	second := dialPOP3(t, srv)
	second.login("tester", "test-pass")
	if count, _ := pop3Stat(t, second.expectOK("STAT")); count != 1 {
		t.Errorf("QUIT 后新会话 STAT 期望 1 封（DELE 不得真正删除），实际 %d", count)
	}
	if _, retrLines := second.multiline("RETR 1"); strings.Join(retrLines, "\r\n")+"\r\n" != string(stored.Data) {
		t.Error("QUIT 后新会话 RETR 内容异常")
	}
	if count := srv.MessageCount(); count != 1 {
		t.Errorf("POP3 DELE 不得删除共享内存仓库中的消息，实际保留 %d 封", count)
	}
}

// TestPOP3AuthFailureLimit 验证连续认证失败达到上限后服务端关闭连接。
func TestPOP3AuthFailureLimit(t *testing.T) {
	srv := newPOP3TestServer(t, nil)
	c := dialPOP3(t, srv)
	for i := 0; i < 3; i++ {
		c.expectOK("USER tester")
		c.expectErr("PASS wrong-pass")
	}
	if _, err := c.readLineErr(); err == nil {
		t.Error("连续 3 次认证失败后连接应被关闭")
	}

	// 新连接仍可用正确凭据登录（失败计数按会话隔离）。
	fresh := dialPOP3(t, srv)
	fresh.login("tester", "test-pass")
	fresh.expectOK("STAT")
}

// TestPOP3ImplicitTLS 验证 POP3 隐式 TLS 监听器可用（自签测试证书）。
func TestPOP3ImplicitTLS(t *testing.T) {
	cert, err := testmail.GenerateTestCertificate()
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}
	srv := newPOP3TestServer(t, func(opts *testmail.Options) {
		opts.POP3 = &testmail.POP3Options{TLS: &testmail.TLSOptions{Certificate: cert}}
	})
	sendTestMail(t, srv, "sender@example.test", []string{"tester@example.test"},
		[]string{"Subject: pop3 tls", "From: sender@example.test"}, "tls body")

	c := dialPOP3TLS(t, srv.POP3Addr())
	c.login("tester", "test-pass")
	if count, _ := pop3Stat(t, c.expectOK("STAT")); count != 1 {
		t.Fatalf("POP3 隐式 TLS 下 STAT 期望 1 封，实际 %d", count)
	}
}
