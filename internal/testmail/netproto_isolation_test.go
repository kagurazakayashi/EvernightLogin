package testmail_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/testmail"
)

// TestNetProtoAccountIsolation 验证 IMAP/POP3 收件箱严格按模拟账户隔离：
// 账户只能看到信封收件人或 To/Cc/Bcc 命中自己的邮件；其他账户的邮件条数与内容
// 都不会泄露（EXISTS/STAT/RETR/FETCH 均不可见）。
func TestNetProtoAccountIsolation(t *testing.T) {
	srv := startServer(t, testmail.Options{
		Auth: &testmail.AuthOptions{Users: map[string]string{
			"tester":  "test-pass",
			"tester2": "test-pass-2",
		}},
		IMAP: &testmail.IMAPOptions{},
		POP3: &testmail.POP3Options{},
	})

	// m1 只发给 tester；m2 只发给 tester2；m3 信封收件人是无关地址，但头部 To
	// 指向 tester（验证 To/Cc/Bcc 命中规则）。
	sendTestMail(t, srv, "sender@example.test", []string{"tester@example.test"}, []string{
		"From: sender@example.test",
		"To: tester@example.test",
		"Subject: alpha secret",
	}, "alpha body")
	sendTestMail(t, srv, "sender@example.test", []string{"tester2@example.test"}, []string{
		"From: sender@example.test",
		"To: tester2@example.test",
		"Subject: bravo secret",
	}, "bravo body")
	sendTestMail(t, srv, "sender@example.test", []string{"nobody@example.test"}, []string{
		"From: sender@example.test",
		"To: tester@example.test",
		"Subject: charlie header",
	}, "charlie body")

	// tester 的 IMAP 收件箱：只有 alpha 与 charlie。
	alice := dialIMAP(t, srv)
	alice.login("tester", "test-pass")
	selected := alice.selectInbox("SELECT")
	if got := alice.existsCount(selected); got != 2 {
		t.Fatalf("tester IMAP EXISTS 期望 2，实际 %d", got)
	}
	fetched := alice.okCommand("A3 FETCH 1:* (BODY[])")
	aliceBodies := concatLiterals(fetched.Literals)
	for _, want := range []string{"alpha secret", "charlie header", "alpha body", "charlie body"} {
		if !strings.Contains(aliceBodies, want) {
			t.Errorf("tester 收件箱缺少 %q", want)
		}
	}
	if strings.Contains(aliceBodies, "bravo") {
		t.Errorf("tester 不应看到 tester2 的邮件: %q", aliceBodies)
	}

	// tester2 的 IMAP 收件箱：只有 bravo。
	bob := dialIMAP(t, srv)
	bob.login("tester2", "test-pass-2")
	selected = bob.selectInbox("SELECT")
	if got := bob.existsCount(selected); got != 1 {
		t.Fatalf("tester2 IMAP EXISTS 期望 1，实际 %d", got)
	}
	fetched = bob.okCommand("A3 FETCH 1:* (BODY[])")
	bobBodies := concatLiterals(fetched.Literals)
	if !strings.Contains(bobBodies, "bravo secret") {
		t.Errorf("tester2 收件箱缺少自己的邮件: %q", bobBodies)
	}
	for _, secret := range []string{"alpha", "charlie"} {
		if strings.Contains(bobBodies, secret) {
			t.Errorf("tester2 不应看到 %q: %q", secret, bobBodies)
		}
	}

	// tester 的 POP3 收件箱：STAT 2，RETR 内容只有自己的两封。
	alicePOP3 := dialPOP3(t, srv)
	alicePOP3.login("tester", "test-pass")
	if count, _ := pop3Stat(t, alicePOP3.expectOK("STAT")); count != 2 {
		t.Fatalf("tester POP3 STAT 期望 2，实际 %d", count)
	}
	var alicePOP3Bodies strings.Builder
	for i := 1; i <= 2; i++ {
		_, lines := alicePOP3.multiline("RETR " + strconv.Itoa(i))
		alicePOP3Bodies.WriteString(strings.Join(lines, "\r\n"))
	}
	if strings.Contains(alicePOP3Bodies.String(), "bravo") {
		t.Errorf("tester POP3 不应返回 tester2 的邮件")
	}

	// tester2 的 POP3 收件箱：STAT 1，只有 bravo。
	bobPOP3 := dialPOP3(t, srv)
	bobPOP3.login("tester2", "test-pass-2")
	if count, _ := pop3Stat(t, bobPOP3.expectOK("STAT")); count != 1 {
		t.Fatalf("tester2 POP3 STAT 期望 1，实际 %d", count)
	}
	_, lines := bobPOP3.multiline("RETR 1")
	bobPOP3Body := strings.Join(lines, "\r\n")
	if !strings.Contains(bobPOP3Body, "bravo secret") {
		t.Errorf("tester2 POP3 RETR 内容异常: %q", bobPOP3Body)
	}
	for _, secret := range []string{"alpha", "charlie"} {
		if strings.Contains(bobPOP3Body, secret) {
			t.Errorf("tester2 POP3 不应返回 %q", secret)
		}
	}
}

// concatLiterals 按顺序拼接多个 IMAP 字面量，便于断言内容。
func concatLiterals(literals [][]byte) string {
	var b strings.Builder
	for _, literal := range literals {
		b.Write(literal)
		b.WriteString("\n")
	}
	return b.String()
}
