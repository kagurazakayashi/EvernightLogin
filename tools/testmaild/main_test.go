package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer 是并发安全的输出缓冲：run 在 goroutine 中写，测试同时轮询读取。
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// waitFor 轮询等待输出包含指定子串。
func (b *syncBuffer) waitFor(sub string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(b.String(), sub) {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// listeningAddr 从输出中解析实际监听地址。
func listeningAddr(t *testing.T, output string) string {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "testmaild: 监听 ") {
			continue
		}
		addr := strings.TrimPrefix(line, "testmaild: 监听 ")
		if _, _, err := net.SplitHostPort(addr); err != nil {
			t.Fatalf("无法解析监听地址 %q: %v", addr, err)
		}
		return addr
	}
	t.Fatalf("输出中没有监听地址行: %q", output)
	return ""
}

// TestRunPrintsAddressReceivesMailAndReleasesPort 端到端验证工具装配：打印实际
// 地址、接收并用标准 SMTP 会话发送邮件、ctx 取消后优雅关闭且端口释放。
func TestRunPrintsAddressReceivesMailAndReleasesPort(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout, stderr syncBuffer
	done := make(chan error, 1)
	go func() { done <- run(ctx, []string{"-addr", "127.0.0.1:0"}, &stdout, &stderr) }()

	if !stdout.waitFor("testmaild: 监听 ", 3*time.Second) {
		t.Fatalf("未打印监听地址: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	addr := listeningAddr(t, stdout.String())

	if err := sendMail(addr, "sender@example.test", []string{"user@example.test", "other@example.test"}, "Subject: tool test\n\nhello from tool test"); err != nil {
		t.Fatalf("通过工具发送邮件失败: %v", err)
	}
	if !stdout.waitFor("收到邮件", 3*time.Second) {
		t.Fatalf("工具未打印收到邮件: stdout=%q", stdout.String())
	}
	if got := stdout.String(); !strings.Contains(got, "subject=\"tool test\"") {
		t.Errorf("收到邮件摘要缺少主题: %q", got)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("优雅关闭返回错误: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ctx 取消后工具未退出")
	}
	if got := stdout.String(); !strings.Contains(got, "已关闭并释放端口") {
		t.Errorf("缺少关闭输出: %q", got)
	}
	if conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Fatalf("工具退出后仍能连接 %s，端口未释放", addr)
	}
}

// TestRunPrintsAuthHintWithoutPassword 验证启动信息提示测试凭据但不回显密码。
func TestRunPrintsAuthHintWithoutPassword(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout, stderr syncBuffer
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"-addr", "127.0.0.1:0", "-auth", "tester:s3cret-test", "-require-auth"}, &stdout, &stderr)
	}()
	if !stdout.waitFor("AUTH 已启用", 3*time.Second) {
		t.Fatalf("未打印 AUTH 提示: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "tester") {
		t.Errorf("应提示测试用户名: %q", out)
	}
	if strings.Contains(out, "s3cret-test") {
		t.Errorf("启动信息不得回显测试密码: %q", out)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("关闭失败: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ctx 取消后工具未退出")
	}
}

// TestRunStartTLSFlag 验证 --starttls 会生成临时测试证书并提示。
func TestRunStartTLSFlag(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout, stderr syncBuffer
	done := make(chan error, 1)
	go func() { done <- run(ctx, []string{"-addr", "127.0.0.1:0", "-starttls"}, &stdout, &stderr) }()
	if !stdout.waitFor("STARTTLS 已启用", 3*time.Second) {
		t.Fatalf("未打印 STARTTLS 提示: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("关闭失败: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ctx 取消后工具未退出")
	}
}

// TestRunRejectsInvalidConfiguration 验证非法参数在阻塞等待之前返回错误。
func TestRunRejectsInvalidConfiguration(t *testing.T) {
	cases := [][]string{
		{"-require-auth"},
		{"-tls-cert", "only-cert.pem"},
		{"-tls-key", "only-key.pem"},
		{"-auth", "no-colon"},
		{"-auth", "tester:"},
		{"-auth", "tester:x", "-auth", "tester:y"},
		{"-addr", "0.0.0.0:0"},
		{"-addr", "bad-address"},
		{"-max-messages", "-1"},
		{"-unknown-flag"},
		{"positional-arg"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var stdout, stderr syncBuffer
			if err := run(context.Background(), args, &stdout, &stderr); err == nil {
				t.Fatalf("参数 %v 应返回错误", args)
			}
		})
	}
}

// sendMail 用最小标准 SMTP 会话发送一封邮件，供工具端到端测试使用。
func sendMail(addr, from string, to []string, data string) error {
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(conn)

	expect := func(want int) error {
		var first string
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return err
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
			return err
		}
		if got != want {
			return fmt.Errorf("期望 SMTP %d，实际 %d（%q）", want, got, first)
		}
		return nil
	}
	send := func(line string) error {
		_, err := io.WriteString(conn, line+"\r\n")
		return err
	}
	steps := []struct {
		line string
		want int
	}{
		{"EHLO tool.test", 250},
		{"MAIL FROM:<" + from + ">", 250},
	}
	for _, rcpt := range to {
		steps = append(steps, struct {
			line string
			want int
		}{"RCPT TO:<" + rcpt + ">", 250})
	}
	steps = append(steps, struct {
		line string
		want int
	}{"DATA", 354})
	if err := expect(220); err != nil {
		return err
	}
	for _, step := range steps {
		if err := send(step.line); err != nil {
			return err
		}
		if err := expect(step.want); err != nil {
			return err
		}
	}
	var b strings.Builder
	for _, line := range strings.Split(data, "\n") {
		if strings.HasPrefix(line, ".") {
			b.WriteString(".")
		}
		b.WriteString(line)
		b.WriteString("\r\n")
	}
	b.WriteString(".\r\n")
	if _, err := io.WriteString(conn, b.String()); err != nil {
		return err
	}
	if err := expect(250); err != nil {
		return err
	}
	if err := send("QUIT"); err != nil {
		return err
	}
	return expect(221)
}
