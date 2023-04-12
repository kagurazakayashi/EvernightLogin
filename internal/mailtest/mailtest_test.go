// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightMail is licensed under Mulan PSL v2.

package mailtest

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMain 在本测试进程结束前删除自动构建的 Mail 临时二进制；导入本夹具的其他
// 测试包可在自己的 TestMain 中调用 CleanupBuiltBinary。
func TestMain(m *testing.M) {
	code := m.Run()
	CleanupBuiltBinary()
	os.Exit(code)
}

// testOptions 返回正向测试默认参数。
func testOptions() Options {
	return Options{Required: true, ReadyTimeout: 20 * time.Second, StopTimeout: 8 * time.Second}
}

func TestStartSendAndWaitMessage(t *testing.T) {
	instance := Start(t, testOptions())
	raw := BuildMessage("sender@example.com", []string{"alice@example.com"}, "mailtest hello", "body text 123")
	if err := instance.SendRaw("sender@example.com", []string{"alice@example.com"}, raw); err != nil {
		t.Fatalf("SMTP 投递失败: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	messages, err := instance.WaitMessage(ctx, Query{To: "alice@example.com", Subject: "mailtest hello"})
	if err != nil {
		t.Fatalf("等待邮件失败: %v", err)
	}
	if len(messages) != 1 {
		t.Fatalf("匹配邮件数 = %d，期望 1", len(messages))
	}
	message := messages[0]
	if message.Subject != "mailtest hello" || !strings.Contains(message.From, "sender@example.com") {
		t.Fatalf("邮件头不匹配: subject=%q from=%q", message.Subject, message.From)
	}
	if !bytes.Equal(message.Data, raw) {
		t.Fatalf("原始 eml 字节与发送内容不一致（len %d vs %d）", len(message.Data), len(raw))
	}
	if !strings.Contains(string(message.Body()), "body text 123") {
		t.Fatalf("正文不匹配: %q", message.Body())
	}
	if func() bool { _, ok := message.Header("Message-ID"); return !ok }() {
		t.Fatalf("缺少 Message-ID")
	}
	if !strings.Contains(string(message.Data), "Subject: mailtest hello") {
		t.Fatalf("HeaderBlock/原文缺少主题")
	}
}

func TestMessagesFilterAndClose(t *testing.T) {
	instance := Start(t, testOptions())
	first := BuildMessage("a@example.com", []string{"bob@example.com"}, "for bob", "one")
	second := BuildMessage("a@example.com", []string{"carol@example.com"}, "for carol", "two")
	if err := instance.SendRaw("a@example.com", []string{"bob@example.com"}, first); err != nil {
		t.Fatalf("投递 1: %v", err)
	}
	if err := instance.SendRaw("a@example.com", []string{"carol@example.com"}, second); err != nil {
		t.Fatalf("投递 2: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := instance.WaitMessage(ctx, Query{To: "carol@example.com"}); err != nil {
		t.Fatalf("等待 carol 邮件: %v", err)
	}
	bobMessages, err := instance.Messages(Query{To: "bob@example.com"})
	if err != nil {
		t.Fatalf("查询 bob: %v", err)
	}
	if len(bobMessages) != 1 || !strings.Contains(string(bobMessages[0].Data), "for bob") {
		t.Fatalf("bob 过滤结果不正确: %#v", bobMessages)
	}
	httpAddr, smtpAddr := instance.HTTPAddr, instance.SMTPAddr
	if err := instance.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := instance.Close(); err != nil {
		t.Fatalf("重复 Close 应幂等: %v", err)
	}
	if !waitDone(instance.done, time.Second) {
		t.Fatalf("Close 后子进程未退出")
	}
	if err := waitPortsReleased([]string{httpAddr, smtpAddr}, time.Second); err != nil {
		t.Fatalf("Close 后端口未释放: %v", err)
	}
}

func TestTLSStartTLSAndPOP3(t *testing.T) {
	opts := testOptions()
	opts.TLS = true
	instance := Start(t, opts)
	raw := BuildMessage("sender@example.com", []string{"alice@example.com"}, "tls subject", "tls body")
	if err := instance.SendRaw("sender@example.com", []string{"alice@example.com"}, raw); err != nil {
		t.Fatalf("STARTTLS 投递失败: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	messages, err := instance.WaitMessage(ctx, Query{Subject: "tls subject"})
	if err != nil {
		t.Fatalf("等待 TLS 邮件: %v", err)
	}
	headers, err := instance.Pop3List()
	if err != nil {
		t.Fatalf("POP3 UIDL: %v", err)
	}
	if len(headers) == 0 {
		t.Fatalf("POP3 列表为空")
	}
	popRaw, err := instance.Pop3FetchRaw(messages[0].ID)
	if err != nil {
		t.Fatalf("POP3 RETR: %v", err)
	}
	if !bytes.Equal(popRaw, messages[0].Data) {
		t.Fatalf("POP3 原始字节与 eml 不一致（len %d vs %d）", len(popRaw), len(messages[0].Data))
	}
}

func TestReadyTimeoutCleansUp(t *testing.T) {
	ports, err := choosePorts(Options{})
	if err != nil {
		t.Fatalf("choosePorts: %v", err)
	}
	opts := testOptions()
	opts.ReadyTimeout = time.Nanosecond
	opts.ForcePorts.SMTP, opts.ForcePorts.POP3, opts.ForcePorts.HTTP = ports.smtp, ports.pop3, ports.http
	if instance, err := startInstance(t, opts); err == nil {
		_ = instance.Close()
		t.Fatalf("极小 ReadyTimeout 应失败")
	}
	if err := waitPortsReleased([]string{addrPort(ports.smtp), addrPort(ports.pop3), addrPort(ports.http)}, 2*time.Second); err != nil {
		t.Fatalf("超时失败后端口未释放: %v", err)
	}
}

func TestPortConflictFailsCleanly(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupied listen: %v", err)
	}
	defer func() { _ = occupied.Close() }()
	ports, err := choosePorts(Options{})
	if err != nil {
		t.Fatalf("choosePorts: %v", err)
	}
	opts := testOptions()
	opts.ForcePorts.SMTP = occupied.Addr().(*net.TCPAddr).Port
	opts.ForcePorts.POP3 = ports.pop3
	opts.ForcePorts.HTTP = ports.http
	_, startErr := startInstance(t, opts)
	if startErr == nil {
		t.Fatalf("SMTP 端口被占用时启动应失败")
	}
	if !strings.Contains(strings.ToLower(startErr.Error()), "evernightmail") && !strings.Contains(strings.ToLower(startErr.Error()), "就绪") {
		t.Fatalf("错误信息应说明启动失败: %v", startErr)
	}
}

func TestStartFailureInvalidConfig(t *testing.T) {
	opts := testOptions()
	opts.ExtraYAML = "listeners: ["
	if instance, err := startInstance(t, opts); err == nil {
		_ = instance.Close()
		t.Fatalf("非法配置应启动失败")
	}
}

func TestStartCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	opts := testOptions()
	opts.Context = ctx
	if instance, err := startInstance(t, opts); err == nil {
		_ = instance.Close()
		t.Fatalf("已取消的 context 应启动失败")
	} else if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "取消") && !strings.Contains(err.Error(), "context") {
		t.Fatalf("取消错误应可识别: %v", err)
	}
}

func TestTwoInstancesIsolation(t *testing.T) {
	first := Start(t, testOptions())
	second := Start(t, testOptions())
	raw := BuildMessage("a@example.com", []string{"alice@example.com"}, "isolation", "first only")
	if err := first.SendRaw("a@example.com", []string{"alice@example.com"}, raw); err != nil {
		t.Fatalf("first 投递: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := first.WaitMessage(ctx, Query{Subject: "isolation"}); err != nil {
		t.Fatalf("first 等待: %v", err)
	}
	secondMessages, err := second.Messages(Query{Subject: "isolation"})
	if err != nil {
		t.Fatalf("second 查询: %v", err)
	}
	if len(secondMessages) != 0 {
		t.Fatalf("两个实例数据串扰: second 收到 %d 封", len(secondMessages))
	}
}

func TestIgnoresPersonalConfigEnvironment(t *testing.T) {
	t.Setenv("EVERNIGHTMAIL_CONFIG", filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	instance := Start(t, testOptions())
	if instance.ConfigPath == "" || !strings.Contains(instance.ConfigPath, "EvernightMail.yaml") {
		t.Fatalf("未使用夹具临时配置: %q", instance.ConfigPath)
	}
}
