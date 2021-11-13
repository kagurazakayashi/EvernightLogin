package testmail_test

import (
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/testmail"
)

// newIMAPTestServer 启动带模拟账户与 IMAP 监听器的测试服务器。
func newIMAPTestServer(t *testing.T, extra func(*testmail.Options)) *testmail.Server {
	t.Helper()
	opts := testmail.Options{
		Auth: &testmail.AuthOptions{Users: map[string]string{
			"tester":  "test-pass",
			"tester2": "test-pass-2",
		}},
		IMAP: &testmail.IMAPOptions{},
	}
	if extra != nil {
		extra(&opts)
	}
	return startServer(t, opts)
}

// TestIMAPLoginListAndLogout 用真实 IMAP 协议客户端验证认证成功/失败、LIST/LSUB、
// 未支持命令返回 BAD、LOGOUT 关闭连接。
func TestIMAPLoginListAndLogout(t *testing.T) {
	srv := newIMAPTestServer(t, nil)
	c := dialIMAP(t, srv)

	// CAPABILITY 在未认证状态即可使用，并公布 IMAP4rev1。
	capability := c.okCommand("A0 CAPABILITY")
	if joined := strings.Join(capability.Lines, "\n"); !strings.Contains(joined, "IMAP4rev1") {
		t.Errorf("CAPABILITY 未公布 IMAP4rev1: %v", capability.Lines)
	}

	// 未认证时 LIST/SELECT 必须是 BAD（状态非法），不能返回数据。
	if resp := c.command(`A1 LIST "" "*"`); resp.statusCode() != "BAD" {
		t.Errorf("未认证 LIST 期望 BAD，实际 %q", resp.Status)
	}

	// 错误密码：认证失败返回 NO，且不崩溃。
	if resp := c.command(`A2 LOGIN "tester" "wrong-pass"`); resp.statusCode() != "NO" {
		t.Errorf("错误密码期望 NO，实际 %q", resp.Status)
	}
	// 正确凭据可以登录。
	c.login("tester", "test-pass")

	// LIST/LSUB 至少返回 INBOX，且带层级分隔符。
	list := c.okCommand(`A3 LIST "" "*"`)
	if joined := strings.Join(list.Lines, "\n"); !strings.Contains(joined, `"INBOX"`) {
		t.Errorf("LIST 未返回 INBOX: %v", list.Lines)
	}
	lsub := c.okCommand(`A4 LSUB "" "*"`)
	if joined := strings.Join(lsub.Lines, "\n"); !strings.Contains(joined, `"INBOX"`) {
		t.Errorf("LSUB 未返回 INBOX: %v", lsub.Lines)
	}

	// 未支持命令返回 BAD，连接保持可用。
	if resp := c.command("A5 FROBNICATE"); resp.statusCode() != "BAD" {
		t.Errorf("未支持命令期望 BAD，实际 %q", resp.Status)
	}
	if resp := c.command("A6 SELECT"); resp.statusCode() != "BAD" {
		t.Errorf("SELECT 缺参数期望 BAD，实际 %q", resp.Status)
	}
	if resp := c.command("A7 EXAMINE NoSuchFolder"); resp.statusCode() != "NO" {
		t.Errorf("不存在的邮箱期望 NO，实际 %q", resp.Status)
	}

	// LOGOUT 先发 BYE 再回 tagged OK，然后关闭连接。
	logout := c.okCommand("A8 LOGOUT")
	if !strings.Contains(strings.Join(logout.Lines, "\n"), "* BYE") {
		t.Errorf("LOGOUT 未发送 BYE: %v", logout.Lines)
	}
	if _, err := c.readLineErr(); err == nil {
		t.Error("LOGOUT 后连接应被服务端关闭")
	}
}

// TestIMAPFetchMatchesSMTPCapture 验证 IMAP 读取到的字节与 SMTP 捕获的原始消息
// 完全一致，并覆盖 SELECT/EXAMINE、UID FETCH、所需 FETCH 数据项与只读拒绝。
func TestIMAPFetchMatchesSMTPCapture(t *testing.T) {
	srv := newIMAPTestServer(t, nil)
	stored := sendTestMail(t, srv, "sender@example.test", []string{"tester@example.test"}, []string{
		"From: Sender <sender@example.test>",
		"To: Tester <tester@example.test>",
		"Subject: alpha secret",
		"Date: Thu, 19 Nov 2026 10:00:00 +0800",
		"Message-ID: <alpha@example.test>",
		"Content-Type: text/plain; charset=utf-8",
	}, "第一行正文\n第二行正文")

	c := dialIMAP(t, srv)
	c.login("tester", "test-pass")

	// SELECT 返回 READ-ONLY、EXISTS 与 UID 相关响应码。
	selected := c.selectInbox("SELECT")
	if got := c.existsCount(selected); got != 1 {
		t.Fatalf("SELECT EXISTS 期望 1，实际 %d", got)
	}
	if !strings.Contains(selected.Status, "[READ-ONLY]") {
		t.Errorf("SELECT 应返回 READ-ONLY: %q", selected.Status)
	}
	joined := strings.Join(selected.Lines, "\n")
	for _, want := range []string{"* OK [UIDVALIDITY 1]", "* OK [UIDNEXT 2]", "* 1 EXISTS", "* FLAGS"} {
		if !strings.Contains(joined, want) {
			t.Errorf("SELECT 响应缺少 %q: %v", want, selected.Lines)
		}
	}

	// 必需数据项：BODY[]/RFC822.HEADER/FLAGS/UID/SIZE/INTERNALDATE。
	fetched := c.okCommand(`A3 FETCH 1 (BODY[] RFC822.HEADER FLAGS UID SIZE INTERNALDATE)`)
	if len(fetched.Literals) != 2 {
		t.Fatalf("FETCH 期望 2 个字面量，实际 %d 个: %v", len(fetched.Literals), fetched.Lines)
	}
	if string(fetched.Literals[0]) != string(stored.Data) {
		t.Errorf("BODY[] 与 SMTP 捕获字节不一致:\nIMAP=%q\nSMTP=%q", fetched.Literals[0], stored.Data)
	}
	if string(fetched.Literals[1]) != string(stored.HeaderBlock()) {
		t.Errorf("RFC822.HEADER 与 SMTP 捕获头部不一致:\nIMAP=%q\nSMTP=%q", fetched.Literals[1], stored.HeaderBlock())
	}
	fetchedText := strings.Join(fetched.Lines, "\n")
	for _, want := range []string{"FLAGS ()", "UID 1", "SIZE ", "INTERNALDATE \""} {
		if !strings.Contains(fetchedText, want) {
			t.Errorf("FETCH 响应缺少 %q: %v", want, fetched.Lines)
		}
	}

	// UID FETCH 等价：UID 1 必须命中，且响应必须带 UID。
	uidFetched := c.okCommand(`A4 UID FETCH 1 (BODY.PEEK[HEADER.FIELDS (Subject From)] FLAGS)`)
	if len(uidFetched.Literals) != 1 {
		t.Fatalf("UID FETCH 期望 1 个字面量，实际 %d", len(uidFetched.Literals))
	}
	headerFields := string(uidFetched.Literals[0])
	for _, want := range []string{"Subject: alpha secret", "From: Sender <sender@example.test>"} {
		if !strings.Contains(headerFields, want) {
			t.Errorf("BODY[HEADER.FIELDS] 缺少 %q: %q", want, headerFields)
		}
	}
	if !strings.Contains(joinedString(uidFetched.Lines), "UID 1") {
		t.Errorf("UID FETCH 响应必须带 UID: %v", uidFetched.Lines)
	}

	// ENVELOPE 使用原始头部值，不伪造缺失字段。
	envelope := c.okCommand(`A5 FETCH 1 (ENVELOPE)`)
	if !strings.Contains(joinedString(envelope.Lines), `ENVELOPE ("Thu, 19 Nov 2026 10:00:00 +0800" "alpha secret"`) {
		t.Errorf("ENVELOPE 响应异常: %v", envelope.Lines)
	}

	// 未支持的 FETCH 数据项在返回数据前给出 BAD。
	for _, command := range []string{
		"A6 FETCH 1 (BODYSTRUCTURE)",
		"A7 FETCH 1 (BODY[1])",
	} {
		if resp := c.command(command); resp.statusCode() != "BAD" {
			t.Errorf("命令 %q 期望 BAD，实际 %q", command, resp.Status)
		}
	}

	// 只读：STORE/EXPUNGE/APPEND/COPY 一律明确拒绝。
	for _, command := range []string{
		`A8 STORE 1 +FLAGS (\Seen)`,
		"A9 EXPUNGE",
		"A10 COPY 1 INBOX",
		"A11 UID STORE 1 +FLAGS (\\Seen)",
		"A12 UID EXPUNGE 1",
	} {
		resp := c.command(command)
		if resp.statusCode() != "NO" {
			t.Errorf("只读命令 %q 期望 NO，实际 %q", command, resp.Status)
		}
		if !strings.Contains(resp.Status, "READ-ONLY") {
			t.Errorf("只读拒绝缺少 READ-ONLY 标记: %q", resp.Status)
		}
	}

	// CLOSE 回到已认证状态，之后不能再 FETCH。
	if resp := c.okCommand("A13 CLOSE"); resp.statusCode() != "OK" {
		t.Errorf("CLOSE 期望 OK，实际 %q", resp.Status)
	}
	if resp := c.command("A14 FETCH 1 (UID)"); resp.statusCode() != "BAD" {
		t.Errorf("CLOSE 后 FETCH 期望 BAD，实际 %q", resp.Status)
	}
}

// TestIMAPExamine 验证 EXAMINE 与 SELECT 一样可读，但明确标记只读。
func TestIMAPExamine(t *testing.T) {
	srv := newIMAPTestServer(t, nil)
	sendTestMail(t, srv, "sender@example.test", []string{"tester@example.test"},
		[]string{"Subject: examine subject", "From: sender@example.test"}, "body")

	c := dialIMAP(t, srv)
	c.login("tester", "test-pass")
	resp := c.selectInbox("EXAMINE")
	if got := c.existsCount(resp); got != 1 {
		t.Fatalf("EXAMINE EXISTS 期望 1，实际 %d", got)
	}
	if !strings.Contains(resp.Status, "READ-ONLY") {
		t.Errorf("EXAMINE 应返回 READ-ONLY: %q", resp.Status)
	}
	fetched := c.okCommand("A3 FETCH 1 (BODY[TEXT])")
	if len(fetched.Literals) != 1 {
		t.Fatalf("EXAMINE 后 FETCH 期望 1 个字面量，实际 %d", len(fetched.Literals))
	}
	if got := string(fetched.Literals[0]); !strings.Contains(got, "body") {
		t.Errorf("BODY[TEXT] 内容异常: %q", got)
	}
}

// TestIMAPImplicitTLS 验证 IMAP 隐式 TLS 监听器可用（自签测试证书）。
func TestIMAPImplicitTLS(t *testing.T) {
	cert, err := testmail.GenerateTestCertificate()
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}
	srv := newIMAPTestServer(t, func(opts *testmail.Options) {
		opts.IMAP = &testmail.IMAPOptions{TLS: &testmail.TLSOptions{Certificate: cert}}
	})
	sendTestMail(t, srv, "sender@example.test", []string{"tester@example.test"},
		[]string{"Subject: tls subject", "From: sender@example.test"}, "tls body")

	c := dialIMAPTLS(t, srv.IMAPAddr())
	c.login("tester", "test-pass")
	c.selectInbox("SELECT")
	fetched := c.okCommand("A3 UID FETCH 1 (BODY[])")
	if len(fetched.Literals) != 1 || !strings.Contains(string(fetched.Literals[0]), "tls body") {
		t.Fatalf("IMAP 隐式 TLS 下 UID FETCH 内容异常: %v", fetched.Literals)
	}
}

// TestIMAPLoginLiteral 验证真实客户端常用的 IMAP 字面量（{n}）形式登录参数。
func TestIMAPLoginLiteral(t *testing.T) {
	srv := newIMAPTestServer(t, nil)
	c := dialIMAP(t, srv)

	// 第一步：LOGIN 命令带两个字面量，服务器回复 "+" 后客户端发送字面量内容。
	c.send("A1 LOGIN {6}")
	if cont := c.readLine(); !strings.HasPrefix(cont, "+") {
		t.Fatalf("字面量登录期望继续响应，实际 %q", cont)
	}
	c.sendRaw("tester")
	c.send(" {9}")
	if cont := c.readLine(); !strings.HasPrefix(cont, "+") {
		t.Fatalf("第二个字面量期望继续响应，实际 %q", cont)
	}
	c.sendRaw("test-pass")
	c.sendRaw("\r\n")
	status := c.readLine()
	if !strings.HasPrefix(status, "A1 OK") {
		t.Fatalf("字面量登录期望 OK，实际 %q", status)
	}
	// 登录后 LIST 应可用。
	c.okCommand(`A2 LIST "" "*"`)
}

// sendRaw 发送不带 CRLF 的原始字节（用于组成带字面量的命令行）。
func (c *imapTestClient) sendRaw(text string) {
	c.t.Helper()
	_ = c.conn.SetWriteDeadline(time.Now().Add(netprotoDeadline))
	if _, err := c.tp.W.WriteString(text); err != nil {
		c.t.Fatalf("发送 IMAP 原始内容失败: %v", err)
	}
	if err := c.tp.W.Flush(); err != nil {
		c.t.Fatalf("刷新 IMAP 连接失败: %v", err)
	}
}

// joinedString 用换行拼接响应行，便于 Contains 断言。
func joinedString(lines []string) string {
	return strings.Join(lines, "\n")
}

// TestIMAPStatusMacroAndBodySections 覆盖 STATUS、FETCH 宏、BODY[HEADER] 与
// RFC822.TEXT 等补充数据项，并验证未支持的 STATUS 项返回 BAD。
func TestIMAPStatusMacroAndBodySections(t *testing.T) {
	srv := newIMAPTestServer(t, nil)
	stored := sendTestMail(t, srv, "sender@example.test", []string{"tester@example.test"}, []string{
		"From: Sender <sender@example.test>",
		"To: Tester <tester@example.test>",
		"Subject: status subject",
		"Date: Thu, 19 Nov 2026 10:00:00 +0800",
	}, "first line\nsecond line")

	c := dialIMAP(t, srv)
	c.login("tester", "test-pass")

	// STATUS 可以在未选择邮箱时使用，返回实时计数。
	status := c.okCommand(`A2 STATUS INBOX (MESSAGES UIDNEXT UIDVALIDITY UNSEEN)`)
	if joined := joinedString(status.Lines); !strings.Contains(joined, "* STATUS INBOX (MESSAGES 1 UIDNEXT 2 UIDVALIDITY 1 UNSEEN 1)") {
		t.Errorf("STATUS 响应异常: %v", status.Lines)
	}
	if resp := c.command(`A3 STATUS INBOX (BOGUSITEM)`); resp.statusCode() != "BAD" {
		t.Errorf("未支持 STATUS 项期望 BAD，实际 %q", resp.Status)
	}

	c.selectInbox("SELECT")

	// ALL 宏展开为 FLAGS/INTERNALDATE/RFC822.SIZE/ENVELOPE。
	all := c.okCommand("A4 FETCH 1 (ALL)")
	allText := joinedString(all.Lines)
	for _, want := range []string{"FLAGS ()", "INTERNALDATE ", "RFC822.SIZE ", "ENVELOPE ("} {
		if !strings.Contains(allText, want) {
			t.Errorf("ALL 宏缺少 %q: %v", want, all.Lines)
		}
	}

	// BODY[HEADER] 与 RFC822.TEXT 必须等于 SMTP 捕获内容的对应部分。
	sections := c.okCommand("A5 FETCH 1 (BODY[HEADER] RFC822.TEXT)")
	if len(sections.Literals) != 2 {
		t.Fatalf("BODY[HEADER]+RFC822.TEXT 期望 2 个字面量，实际 %d", len(sections.Literals))
	}
	if string(sections.Literals[0]) != string(stored.HeaderBlock()) {
		t.Errorf("BODY[HEADER] 与 SMTP 捕获头部不一致")
	}
	if string(sections.Literals[1]) != string(stored.Body()) {
		t.Errorf("RFC822.TEXT 与 SMTP 捕获正文不一致: %q", sections.Literals[1])
	}

	// UID FETCH 即使未显式请求 UID，响应也必须带 UID。
	uidFlags := c.okCommand("A6 UID FETCH 1 (FLAGS)")
	if !strings.Contains(joinedString(uidFlags.Lines), "UID 1") {
		t.Errorf("UID FETCH 响应缺少 UID: %v", uidFlags.Lines)
	}
}

// TestIMAPMalformedLiteralArguments 验证含引号、反斜杠、CR/LF 的畸形字面量参数
// 不会造成命令注入或服务端崩溃：认证失败返回 tagged NO，连接仍可继续使用。
func TestIMAPMalformedLiteralArguments(t *testing.T) {
	srv := newIMAPTestServer(t, nil)
	c := dialIMAP(t, srv)

	// LOGIN 用户名字面量含引号与反斜杠（6 字节：te"st\），密码字面量含 CR/LF
	// （6 字节：pa\r\nss）。服务端必须把它们当普通凭据内容处理并拒绝认证。
	c.send("A1 LOGIN {6}")
	if cont := c.readLine(); !strings.HasPrefix(cont, "+") {
		t.Fatalf("用户名字面量期望继续响应，实际 %q", cont)
	}
	c.sendRaw(`te"st\`)
	c.send(" {6}")
	if cont := c.readLine(); !strings.HasPrefix(cont, "+") {
		t.Fatalf("密码字面量期望继续响应，实际 %q", cont)
	}
	c.sendRaw("pa\r\nss")
	c.sendRaw("\r\n")
	if status := c.readLine(); !strings.HasPrefix(status, "A1 NO") {
		t.Fatalf("畸形字面量凭据期望 tagged NO，实际 %q", status)
	}

	// 连接没有被注入的内容破坏：随后正确 LOGIN 与 LIST 仍可用。
	c.okCommand(`A2 LOGIN "tester" "test-pass"`)
	c.okCommand(`A3 LIST "" "*"`)
}
