package testmail_test

import (
	"context"
	"mime"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/testmail"
)

// TestReceiveSingleMessage 覆盖完整成功会话：EHLO、单收件人、头部/正文、主题
// 解码、日期解析与查询接口。
func TestReceiveSingleMessage(t *testing.T) {
	srv := startServer(t, testmail.Options{})
	c := dialServer(t, srv)
	c.expectCode(250, "EHLO client.example.test")
	c.expectCode(250, "MAIL FROM:<sender@example.test>")

	encodedSubject := mime.BEncoding.Encode("UTF-8", "测试邮件")
	data := "From: Sender <sender@example.test>\n" +
		"To: user@example.test\n" +
		"Subject: " + encodedSubject + "\n" +
		"Date: Mon, 02 Nov 2026 10:00:00 +0800\n" +
		"X-Test: folded\n" +
		"  continued\n" +
		"\n" +
		"hello\n" +
		"second line"
	c.expectCode(250, "RCPT TO:<user@example.test>")
	c.expectCode(354, "DATA")
	resp := c.writeData(data)
	if !strings.Contains(resp, "250") || !strings.Contains(resp, "queued as 1") {
		t.Fatalf("DATA 响应应包含排队编号，实际 %q", resp)
	}

	msgs := srv.Messages(testmail.Query{To: "USER@example.test"})
	if len(msgs) != 1 {
		t.Fatalf("期望 1 封消息，实际 %d", len(msgs))
	}
	m := msgs[0]
	if m.ID != "1" {
		t.Fatalf("消息编号应为 1，实际 %q", m.ID)
	}
	if m.EnvelopeFrom != "sender@example.test" {
		t.Errorf("EnvelopeFrom = %q", m.EnvelopeFrom)
	}
	if len(m.EnvelopeTo) != 1 || m.EnvelopeTo[0] != "user@example.test" {
		t.Errorf("EnvelopeTo = %v", m.EnvelopeTo)
	}
	if m.Subject != "测试邮件" {
		t.Errorf("Subject 解码 = %q", m.Subject)
	}
	wantDate := time.Date(2026, 11, 2, 10, 0, 0, 0, time.FixedZone("", 8*3600))
	if !m.Date.Equal(wantDate) {
		t.Errorf("Date = %v，期望 %v", m.Date, wantDate)
	}
	if got, ok := m.Header("from"); !ok || got != "Sender <sender@example.test>" {
		t.Errorf("From 头 = %q, ok=%v", got, ok)
	}
	if got, ok := m.Header("X-Test"); !ok || got != "folded continued" {
		t.Errorf("折行头部应为 %q，实际 %q", "folded continued", got)
	}
	if body := string(m.Body()); body != "hello\r\nsecond line\r\n" {
		t.Errorf("正文 = %q", body)
	}
	if !strings.Contains(string(m.Data), encodedSubject) {
		t.Errorf("原始字节应保留编码后的主题")
	}
	if m.ReceivedAt.IsZero() || m.RemoteAddr == "" {
		t.Errorf("接收时间/来源地址缺失: %v %q", m.ReceivedAt, m.RemoteAddr)
	}
	if m.TLS {
		t.Errorf("未使用 TLS 的连接不应标记 TLS")
	}
	if m.AuthUser != "" {
		t.Errorf("未认证连接不应有 AuthUser，实际 %q", m.AuthUser)
	}
}

// TestReceiveMultipleRecipientsAndMessages 覆盖多收件人与同一连接连续多条消息。
func TestReceiveMultipleRecipientsAndMessages(t *testing.T) {
	srv := startServer(t, testmail.Options{MaxRecipients: 5})
	c := dialServer(t, srv)
	c.expectCode(250, "EHLO client.example.test")

	c.sendMail("a@example.test", []string{"one@example.test", "two@example.test"}, "Subject: first\n\nbody 1")
	// 连续第二条：同一连接上重新 MAIL/RCPT/DATA。
	c.sendMail("b@example.test", []string{"three@example.test"}, "Subject: second\n\nbody 2")

	if got := srv.MessageCount(); got != 2 {
		t.Fatalf("期望 2 封消息，实际 %d", got)
	}
	first := srv.Messages(testmail.Query{Subject: "first"})
	if len(first) != 1 {
		t.Fatalf("按主题查询应命中 1 封，实际 %d", len(first))
	}
	if len(first[0].EnvelopeTo) != 2 {
		t.Errorf("第一封应收件人 2 个，实际 %v", first[0].EnvelopeTo)
	}
	second := srv.Messages(testmail.Query{From: "b@example.test"})
	if len(second) != 1 || second[0].Subject != "second" {
		t.Fatalf("第二封查询异常: %+v", second)
	}
	if ids := []string{first[0].ID, second[0].ID}; ids[0] == ids[1] {
		t.Errorf("消息编号应唯一: %v", ids)
	}
}

// TestReceiveDotStuffingAndEmptyBody 覆盖点填充还原与空消息体。
func TestReceiveDotStuffingAndEmptyBody(t *testing.T) {
	srv := startServer(t, testmail.Options{})
	c := dialServer(t, srv)
	c.expectCode(250, "EHLO client.example.test")

	c.sendMail("a@example.test", []string{"b@example.test"}, "Subject: dots\n\n.hidden\n..double\n.\nnormal")

	c.sendMail("a@example.test", []string{"b@example.test"}, "")

	msgs := srv.Messages(testmail.Query{})
	if len(msgs) != 2 {
		t.Fatalf("期望 2 封消息，实际 %d", len(msgs))
	}
	if body := string(msgs[0].Body()); body != ".hidden\r\n..double\r\n.\r\nnormal\r\n" {
		t.Errorf("点填充还原后正文 = %q", body)
	}
	if len(msgs[1].Data) != 0 {
		t.Errorf("空消息体应保存为空字节，实际 %q", msgs[1].Data)
	}
	if msgs[1].Subject != "" {
		t.Errorf("空消息的主题应为空，实际 %q", msgs[1].Subject)
	}
}

// TestHELOSingleLine 验证 HELO 的单行响应。
func TestHELOSingleLine(t *testing.T) {
	srv := startServer(t, testmail.Options{Hostname: "mail.test.local"})
	c := dialServer(t, srv)
	resp := c.expectCode(250, "HELO client.example.test")
	if resp != "250 mail.test.local" {
		t.Errorf("HELO 响应 = %q", resp)
	}
}

// TestEHLOAdvertisesCapabilities 验证 EHLO 能力列表包含大小上限、8BITMIME 与
// 增强状态码，且未配置 AUTH/STARTTLS 时不公布它们。
func TestEHLOAdvertisesCapabilities(t *testing.T) {
	srv := startServer(t, testmail.Options{MaxMessageBytes: 4096})
	c := dialServer(t, srv)
	resp := c.expectCode(250, "EHLO client.example.test")
	for _, want := range []string{"SIZE 4096", "8BITMIME", "ENHANCEDSTATUSCODES", "HELP"} {
		if !strings.Contains(resp, want) {
			t.Errorf("EHLO 能力缺少 %q: %q", want, resp)
		}
	}
	if strings.Contains(resp, "AUTH") {
		t.Errorf("未配置 AUTH 时不应公布 AUTH: %q", resp)
	}
	if strings.Contains(resp, "STARTTLS") {
		t.Errorf("未配置 TLS 时不应公布 STARTTLS: %q", resp)
	}
}

// TestQueryFiltersAndWaiting 覆盖查询条件、Wait、Take 与 Clear。
func TestQueryFiltersAndWaiting(t *testing.T) {
	srv := startServer(t, testmail.Options{})
	c := dialServer(t, srv)
	c.expectCode(250, "EHLO client.example.test")

	c.sendMail("first@example.test", []string{"alpha@example.test"}, "Subject: Alpha report\n\none")
	time.Sleep(5 * time.Millisecond)
	c.sendMail("second@example.test", []string{"beta@example.test"}, "Subject: Beta notice\n\ntwo")
	time.Sleep(5 * time.Millisecond)
	c.sendMail("first@example.test", []string{"alpha@example.test"}, "Subject: Alpha followup\n\nthree")

	if got := len(srv.Messages(testmail.Query{To: "ALPHA@example.test"})); got != 2 {
		t.Errorf("按收件人查询应命中 2 封，实际 %d", got)
	}
	if got := len(srv.Messages(testmail.Query{From: "second@example.test"})); got != 1 {
		t.Errorf("按发件人查询应命中 1 封，实际 %d", got)
	}
	if got := len(srv.Messages(testmail.Query{Subject: "alpha"})); got != 2 {
		t.Errorf("按主题子串查询应命中 2 封，实际 %d", got)
	}
	if got := len(srv.Messages(testmail.Query{Limit: 2})); got != 2 {
		t.Errorf("Limit=2 应返回 2 封，实际 %d", got)
	}
	all := srv.Messages(testmail.Query{})
	if got := len(srv.Messages(testmail.Query{Since: all[1].ReceivedAt})); got != 2 {
		t.Errorf("Since 过滤应命中 2 封，实际 %d", got)
	}
	if got := len(srv.Messages(testmail.Query{Until: all[1].ReceivedAt})); got != 1 {
		t.Errorf("Until 过滤应命中 1 封（不含上界），实际 %d", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	waited, err := srv.Wait(ctx, testmail.Query{Subject: "followup"})
	if err != nil {
		t.Fatalf("Wait 失败: %v", err)
	}
	if len(waited) != 1 || waited[0].Subject != "Alpha followup" {
		t.Errorf("Wait 结果异常: %+v", waited)
	}

	taken := srv.Take(testmail.Query{From: "first@example.test"})
	if len(taken) != 2 {
		t.Errorf("Take 应取出 2 封，实际 %d", len(taken))
	}
	if got := srv.MessageCount(); got != 1 {
		t.Errorf("取出后应剩 1 封，实际 %d", got)
	}
	if remaining := srv.Messages(testmail.Query{}); len(remaining) != 1 || remaining[0].Subject != "Beta notice" {
		t.Errorf("剩余消息异常: %+v", remaining)
	}
	if cleared := srv.Clear(); cleared != 1 {
		t.Errorf("Clear 应清空 1 封，实际 %d", cleared)
	}
	if got := srv.MessageCount(); got != 0 {
		t.Errorf("清空后消息数应为 0，实际 %d", got)
	}
}

// TestOnMessageCallback 验证消息保存后同步回调。
func TestOnMessageCallback(t *testing.T) {
	got := make(chan testmail.Message, 4)
	srv := startServer(t, testmail.Options{OnMessage: func(m testmail.Message) { got <- m }})
	c := dialServer(t, srv)
	c.expectCode(250, "EHLO client.example.test")
	c.sendMail("a@example.test", []string{"b@example.test"}, "Subject: notify\n\nbody")

	select {
	case m := <-got:
		if m.Subject != "notify" || m.ID == "" {
			t.Errorf("回调消息异常: %+v", m)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("等待 OnMessage 回调超时")
	}
	if srv.MessageCount() != 1 {
		t.Errorf("回调后消息数应为 1，实际 %d", srv.MessageCount())
	}
}
