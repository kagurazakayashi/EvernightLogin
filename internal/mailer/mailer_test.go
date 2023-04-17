package mailer_test

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailtest"
)

// startTestMail 启动 Mail 测试夹具；tlsEnabled 时启用 STARTTLS 与临时测试 CA。
func startTestMail(t *testing.T, tlsEnabled bool) *mailtest.Instance {
	t.Helper()
	return mailtest.Start(t, mailtest.Options{Required: true, TLS: tlsEnabled, SMTPAuthNone: !tlsEnabled})
}

// testRoots 把夹具临时 CA 加入根证书池（替代旧 testmail.GenerateTestCertificate）。
func testRoots(t *testing.T, srv *mailtest.Instance) *x509.CertPool {
	t.Helper()
	caData, err := os.ReadFile(srv.CAFile)
	if err != nil {
		t.Fatalf("读取夹具测试 CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caData) {
		t.Fatalf("解析夹具测试 CA 失败")
	}
	return pool
}

// sampleMessage 构造一封合法邮件。
func sampleMessage(t *testing.T) mailer.Message {
	t.Helper()
	from, err := mailer.ParseAddress("noreply@example.test")
	if err != nil {
		t.Fatalf("发件地址: %v", err)
	}
	to1, err := mailer.ParseAddress("user@example.test")
	if err != nil {
		t.Fatalf("收件地址: %v", err)
	}
	to2, err := mailer.ParseAddress("second@example.test")
	if err != nil {
		t.Fatalf("收件地址: %v", err)
	}
	return mailer.Message{
		From:     from,
		To:       []mailer.Address{to1, to2},
		Subject:  "验证码 测试",
		TextBody: "第一行\n第二行 with unicode 中文",
	}
}

// TestAddressValidation 覆盖严格地址校验与注入拒绝。
func TestAddressValidation(t *testing.T) {
	valid := []string{"user@example.test", "User.Name+tag@example.test", "a@b.co"}
	for _, raw := range valid {
		if _, err := mailer.ParseAddress(raw); err != nil {
			t.Errorf("地址 %q 应合法: %v", raw, err)
		}
	}
	invalid := []string{
		"",
		"user",
		"user@",
		"@example.test",
		"user@example",
		"user@@example.test",
		"user@exa mple.test",
		"user@example..test",
		"user@-example.test",
		"user@example.test\r\nBcc: victim@example.test",
		"user@example.test\nBcc: victim@example.test",
		"user\x00@example.test",
		strings.Repeat("a", 65) + "@example.test",
		"user@[127.0.0.1]",
		"a b@example.test",
	}
	for _, raw := range invalid {
		if address, err := mailer.ParseAddress(raw); err == nil {
			t.Errorf("地址 %q 应被拒绝，实际 %q", raw, address.Spec)
		}
	}
	// 显示名被丢弃，不进入头部注入面。
	if address, err := mailer.ParseAddress("显示名 <user@example.test>"); err != nil || address.Spec != "user@example.test" {
		t.Errorf("显示名地址应解析为 addr-spec，实际 %q %v", address.Spec, err)
	}
}

// TestTemplateRenderKinds 验证三种模板各自渲染且内容区分。
func TestTemplateRenderKinds(t *testing.T) {
	set, err := mailer.DefaultTemplateSet()
	if err != nil {
		t.Fatalf("默认模板: %v", err)
	}
	verification, err := set.Render(mailer.RenderRequest{
		Kind:         mailer.KindVerification,
		Verification: &mailer.VerificationData{DisplayName: "小明", Code: "123456", ExpiresIn: "10 分钟", AppName: "Login"},
	})
	if err != nil {
		t.Fatalf("验证模板渲染: %v", err)
	}
	if !strings.Contains(verification.TextBody, "123456") || !strings.Contains(verification.Subject, "邮箱验证") {
		t.Errorf("验证模板内容异常: %+v", verification)
	}
	reset, err := set.Render(mailer.RenderRequest{
		Kind:          mailer.KindPasswordReset,
		PasswordReset: &mailer.PasswordResetData{DisplayName: "小明", ResetURL: "https://login.example.test/reset?token=abc", ExpiresIn: "30 分钟", AppName: "Login"},
	})
	if err != nil {
		t.Fatalf("找回模板渲染: %v", err)
	}
	if strings.Contains(reset.TextBody, "123456") || !strings.Contains(reset.TextBody, "reset?token=abc") {
		t.Errorf("找回模板内容异常: %+v", reset)
	}
	notice, err := set.Render(mailer.RenderRequest{
		Kind:   mailer.KindSecurityNotice,
		Notice: &mailer.SecurityNoticeData{DisplayName: "小明", Event: "密码已修改", OccurredAt: "2026-11-16 10:00", ClientInfo: "Windows / 上海", AppName: "Login", SupportURL: "https://login.example.test/support"},
	})
	if err != nil {
		t.Fatalf("告知模板渲染: %v", err)
	}
	if !strings.Contains(notice.Subject, "密码已修改") || strings.Contains(notice.TextBody, "123456") {
		t.Errorf("告知模板内容异常: %+v", notice)
	}
}

// TestTemplateRejectsInjection 验证模板数据里的换行、控制字符与危险链接被拒绝。
func TestTemplateRejectsInjection(t *testing.T) {
	set, err := mailer.DefaultTemplateSet()
	if err != nil {
		t.Fatalf("默认模板: %v", err)
	}
	cases := []mailer.RenderRequest{
		{Kind: mailer.KindVerification, Verification: &mailer.VerificationData{DisplayName: "a\r\nBcc: victim@example.test", Code: "1", ExpiresIn: "1", AppName: "A"}},
		{Kind: mailer.KindVerification, Verification: &mailer.VerificationData{DisplayName: "a", Code: "1\nX: y", ExpiresIn: "1", AppName: "A"}},
		{Kind: mailer.KindPasswordReset, PasswordReset: &mailer.PasswordResetData{DisplayName: "a", ResetURL: "javascript:alert(1)", ExpiresIn: "1", AppName: "A"}},
		{Kind: mailer.KindPasswordReset, PasswordReset: &mailer.PasswordResetData{DisplayName: "a", ResetURL: "https://user:pass@example.test/x", ExpiresIn: "1", AppName: "A"}},
		{Kind: mailer.KindSecurityNotice, Notice: &mailer.SecurityNoticeData{DisplayName: "a", Event: "e", OccurredAt: "t", ClientInfo: "c", AppName: "A", SupportURL: "ftp://example.test"}},
		{Kind: mailer.Kind("unknown")},
	}
	for i, request := range cases {
		if _, err := set.Render(request); err == nil {
			t.Errorf("用例 %d 应拒绝渲染", i)
		}
	}
}

// TestMessageBytes 验证邮件字节的头部编码、正文 base64 与 CRLF 规范化。
func TestMessageBytes(t *testing.T) {
	message := sampleMessage(t)
	raw, err := message.Bytes()
	if err != nil {
		t.Fatalf("构建邮件字节: %v", err)
	}
	text := string(raw)
	if !strings.Contains(text, "Content-Transfer-Encoding: base64") || !strings.Contains(text, "\r\n\r\n") {
		t.Fatalf("邮件头缺少传输编码或分隔空行: %q", text)
	}
	if strings.Contains(text, "\n\n") {
		t.Errorf("邮件字节应只含 CRLF 行尾")
	}
	// 非 ASCII 主题必须编码，不能原样出现。
	if strings.Contains(text, "验证码 测试") {
		t.Errorf("主题应做 RFC 2047 编码")
	}
	headers, body, ok := strings.Cut(text, "\r\n\r\n")
	if !ok {
		t.Fatal("缺少头部/正文分隔")
	}
	if !strings.Contains(headers, "<user@example.test>, <second@example.test>") {
		t.Errorf("To 头部异常: %q", headers)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(body, "\r\n", ""))
	if err != nil {
		t.Fatalf("正文 base64 解码: %v", err)
	}
	if string(decoded) != "第一行\r\n第二行 with unicode 中文" {
		t.Errorf("正文解码 = %q", decoded)
	}
}

// TestMessageRejectsHeaderInjection 验证主题与附加头部的 CR/LF 被拒绝。
func TestMessageRejectsHeaderInjection(t *testing.T) {
	message := sampleMessage(t)
	message.Subject = "ok\r\nBcc: victim@example.test"
	if _, err := message.Bytes(); err == nil {
		t.Error("主题换行应被拒绝")
	}
	message = sampleMessage(t)
	message.Headers = []mailer.Header{{Name: "X-Test", Value: "value\nInjected: 1"}}
	if _, err := message.Bytes(); err == nil {
		t.Error("附加头部换行应被拒绝")
	}
	message = sampleMessage(t)
	message.Headers = []mailer.Header{{Name: "Bad:Name", Value: "x"}}
	if _, err := message.Bytes(); err == nil {
		t.Error("非法头部名称应被拒绝")
	}
}

// TestSMTPSendPlaintextLocal 验证回环明文发送（显式允许）与 testmail 实际收信。
func TestSMTPSendPlaintextLocal(t *testing.T) {
	srv := startTestMail(t, false)
	sender, err := mailer.NewSMTPSender(mailer.SMTPOptions{
		Addr:                srv.Addr().String(),
		TLSMode:             mailer.TLSModeNone,
		AllowPlaintextLocal: true,
	})
	if err != nil {
		t.Fatalf("创建发送器: %v", err)
	}
	if err := sender.Send(context.Background(), sampleMessage(t)); err != nil {
		t.Fatalf("发送失败: %v", err)
	}
	msgs := srv.Snapshot(mailtest.Query{})
	if len(msgs) != 1 {
		t.Fatalf("期望捕获 1 封，实际 %d", len(msgs))
	}
	if msgs[0].Subject != "验证码 测试" {
		t.Errorf("主题 = %q", msgs[0].Subject)
	}
	if len(msgs[0].EnvelopeTo) != 2 {
		t.Errorf("收件人 = %v", msgs[0].EnvelopeTo)
	}
	body := string(msgs[0].Body())
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(body, "\r\n", ""))
	if err != nil {
		t.Fatalf("正文 base64 解码: %v", err)
	}
	if !strings.Contains(string(decoded), "中文") {
		t.Errorf("正文内容异常: %q", decoded)
	}
}

// TestSMTPStartTLSWithAuth 验证 STARTTLS + 认证使用测试自签根证书成功发送。
func TestSMTPStartTLSWithAuth(t *testing.T) {
	srv := startTestMail(t, true)
	sender, err := mailer.NewSMTPSender(mailer.SMTPOptions{
		Addr:         srv.Addr().String(),
		Host:         "localhost",
		TLSMode:      mailer.TLSModeStartTLS,
		TrustedRoots: testRoots(t, srv),
		Username:     srv.UserLogin,
		Password:     srv.UserPassword,
	})
	if err != nil {
		t.Fatalf("创建发送器: %v", err)
	}
	if err := sender.Send(context.Background(), sampleMessage(t)); err != nil {
		t.Fatalf("STARTTLS 发送失败: %v", err)
	}
	msgs := srv.Snapshot(mailtest.Query{})
	if len(msgs) != 1 || !msgs[0].TLS || msgs[0].AuthUser != srv.UserLogin {
		t.Fatalf("消息状态异常: %+v", msgs)
	}
}

// TestSMTPFailureClassification 验证失败分类：认证失败永久、连接拒绝临时、
// 缺少 STARTTLS 永久、取消可重试。
func TestSMTPFailureClassification(t *testing.T) {
	srv := startTestMail(t, true)
	sender, err := mailer.NewSMTPSender(mailer.SMTPOptions{
		Addr:         srv.Addr().String(),
		Host:         "localhost",
		TLSMode:      mailer.TLSModeStartTLS,
		TrustedRoots: testRoots(t, srv),
		Username:     srv.UserLogin,
		Password:     "wrong-password",
	})
	if err != nil {
		t.Fatalf("创建发送器: %v", err)
	}
	err = sender.Send(context.Background(), sampleMessage(t))
	if got := mailer.CodeOf(err); got != mailer.CodeAuthFailed {
		t.Errorf("认证失败分类 = %q，错误 %v", got, err)
	}
	if mailer.IsRetryable(err) {
		t.Error("认证失败不应可重试")
	}

	// 连接拒绝：临时失败。
	refused, err := mailer.NewSMTPSender(mailer.SMTPOptions{Addr: "127.0.0.1:1", TLSMode: mailer.TLSModeStartTLS, Timeout: time.Second})
	if err != nil {
		t.Fatalf("创建拒绝用例发送器: %v", err)
	}
	err = refused.Send(context.Background(), sampleMessage(t))
	if !mailer.IsRetryable(err) || mailer.CodeOf(err) == "" {
		t.Errorf("连接拒绝应可重试并有代码，实际 %v", err)
	}

	// 服务器不支持 STARTTLS：永久失败。
	plain := startTestMail(t, false)
	noTLS, err := mailer.NewSMTPSender(mailer.SMTPOptions{Addr: plain.Addr().String(), TLSMode: mailer.TLSModeStartTLS, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("创建无 TLS 用例发送器: %v", err)
	}
	err = noTLS.Send(context.Background(), sampleMessage(t))
	if got := mailer.CodeOf(err); got != mailer.CodeTLSFailed || mailer.IsRetryable(err) {
		t.Errorf("缺少 STARTTLS 应为永久 TLS 失败，实际 %q %v", got, err)
	}

	// 已取消的 ctx：可重试的取消/超时分类。
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	err = sender.Send(cancelled, sampleMessage(t))
	if got := mailer.CodeOf(err); got != mailer.CodeCancelled && got != mailer.CodeTimeout {
		t.Errorf("取消分类 = %q，错误 %v", got, err)
	}
}

// TestSMTPOptionsValidation 验证明文/认证/TLS 配置边界。
func TestSMTPOptionsValidation(t *testing.T) {
	invalid := []mailer.SMTPOptions{
		{},
		{Addr: "no-port"},
		{Addr: "127.0.0.1:25", TLSMode: mailer.TLSModeNone},                               // 未显式允许明文
		{Addr: "example.test:25", TLSMode: mailer.TLSModeNone, AllowPlaintextLocal: true}, // 非回环
		{Addr: "127.0.0.1:25", TLSMode: mailer.TLSModeNone, AllowPlaintextLocal: true, Username: "u", Password: "p"},
		{Addr: "127.0.0.1:25", Username: "u"}, // 缺密码
		{Addr: "127.0.0.1:25", TLSMode: "bogus"},
		{Addr: "127.0.0.1:25", Timeout: 100 * time.Millisecond},
	}
	for i, options := range invalid {
		if _, err := mailer.NewSMTPSender(options); err == nil {
			t.Errorf("用例 %d 的配置应被拒绝: %+v", i, options)
		}
	}
	valid := []mailer.SMTPOptions{
		{Addr: "127.0.0.1:25"},
		{Addr: "127.0.0.1:465", TLSMode: mailer.TLSModeImplicit},
		{Addr: "127.0.0.1:25", TLSMode: mailer.TLSModeNone, AllowPlaintextLocal: true},
		{Addr: "127.0.0.1:25", Username: "u", Password: "p"},
	}
	for i, options := range valid {
		if _, err := mailer.NewSMTPSender(options); err != nil {
			t.Errorf("用例 %d 的配置应通过: %v", i, err)
		}
	}
}

// TestSMTPCancelDuringSend 验证发送过程中 ctx 取消会中止（连接被关闭）。
func TestSMTPCancelDuringSend(t *testing.T) {
	// 使用一个只接受连接但从不响应的本地监听器，模拟挂起的 SMTP 服务器。
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听: %v", err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	t.Cleanup(func() {
		select {
		case conn := <-accepted:
			_ = conn.Close()
		default:
		}
	})
	sender, err := mailer.NewSMTPSender(mailer.SMTPOptions{Addr: listener.Addr().String(), Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("创建发送器: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = sender.Send(ctx, sampleMessage(t))
	if err == nil {
		t.Fatal("挂起服务器应导致发送超时/取消")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("取消未及时生效，耗时 %v", elapsed)
	}
	if !errors.Is(err, context.DeadlineExceeded) && mailer.CodeOf(err) != mailer.CodeTimeout && mailer.CodeOf(err) != mailer.CodeCancelled {
		t.Errorf("取消/超时错误分类异常: %v", err)
	}
}
