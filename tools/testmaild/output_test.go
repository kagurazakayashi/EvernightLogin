package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"net"
	"net/smtp"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// runningTool 描述一个在后台运行的 testmaild 实例。
type runningTool struct {
	cancel  context.CancelFunc
	done    chan error
	stdout  *syncBuffer
	stderr  *syncBuffer
	stopped bool
}

// startTool 在后台启动工具并注册清理；测试结束时会取消 ctx 并等待退出。
func startTool(t *testing.T, args []string) *runningTool {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	rt := &runningTool{
		cancel: cancel,
		done:   make(chan error, 1),
		stdout: &syncBuffer{},
		stderr: &syncBuffer{},
	}
	go func() { rt.done <- run(ctx, args, rt.stdout, rt.stderr) }()
	t.Cleanup(func() {
		cancel()
		if rt.stopped {
			return
		}
		select {
		case <-rt.done:
		case <-time.After(5 * time.Second):
			t.Errorf("测试清理时工具未在 5 秒内退出；stdout=%q stderr=%q", rt.stdout.String(), rt.stderr.String())
		}
	})
	return rt
}

// addr 等待监听地址打印后返回实际地址。
func (rt *runningTool) addr(t *testing.T) string {
	t.Helper()
	if !rt.stdout.waitFor("testmaild: 监听 ", 3*time.Second) {
		t.Fatalf("未打印监听地址: stdout=%q stderr=%q", rt.stdout.String(), rt.stderr.String())
	}
	return listeningAddr(t, rt.stdout.String())
}

// stop 取消 ctx 并等待工具优雅退出，返回 run 的错误。
func (rt *runningTool) stop(t *testing.T) error {
	t.Helper()
	if rt.stopped {
		t.Fatal("重复停止工具")
	}
	rt.stopped = true
	rt.cancel()
	select {
	case err := <-rt.done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("ctx 取消后工具未退出")
		return nil
	}
}

// writeConfig 在测试临时目录写入配置文件并返回路径。
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "testmaild-e2e.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("写入临时配置文件失败: %v", err)
	}
	return path
}

// sendSMTPMail 用标准库 net/smtp（真实 SMTP 客户端）发送一封邮件。
// useStartTLS 为 true 时先升级 TLS（自签测试证书跳过校验）；user 为空表示不认证。
func sendSMTPMail(t *testing.T, addr, user, pass string, useStartTLS bool, data string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("连接 %s 失败: %v", addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	client, err := smtp.NewClient(conn, "127.0.0.1")
	if err != nil {
		t.Fatalf("创建 SMTP 客户端失败: %v", err)
	}
	defer func() { _ = client.Close() }()

	if useStartTLS {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			t.Fatal("服务器未在 EHLO 中公布 STARTTLS")
		}
		if err := client.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
			t.Fatalf("STARTTLS 握手失败: %v", err)
		}
	}
	if user != "" {
		if ok, _ := client.Extension("AUTH"); !ok {
			t.Fatal("服务器未在 EHLO 中公布 AUTH")
		}
		if err := client.Auth(smtp.PlainAuth("", user, pass, "127.0.0.1")); err != nil {
			t.Fatalf("AUTH 认证失败: %v", err)
		}
	}
	if err := client.Mail("sender@example.test"); err != nil {
		t.Fatalf("MAIL FROM 失败: %v", err)
	}
	if err := client.Rcpt("user@example.test"); err != nil {
		t.Fatalf("RCPT TO 失败: %v", err)
	}
	writer, err := client.Data()
	if err != nil {
		t.Fatalf("DATA 失败: %v", err)
	}
	if _, err := writer.Write([]byte(data)); err != nil {
		t.Fatalf("写入邮件正文失败: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("结束 DATA 失败: %v", err)
	}
	if err := client.Quit(); err != nil {
		t.Fatalf("QUIT 失败: %v", err)
	}
}

// buildTestMessage 构造一封带常见头部、可验证解析与截断的测试邮件。
func buildTestMessage(subject string) string {
	encodedSubject := mime.BEncoding.Encode("UTF-8", subject)
	return strings.Join([]string{
		"From: \"Sender\" <sender@example.test>",
		"To: <user@example.test>",
		"Subject: " + encodedSubject,
		"Date: Thu, 19 Nov 2026 10:00:00 +0800",
		"Message-ID: <extra03@example.test>",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"第一行正文（用于验证截断）",
		"第二行正文",
		"",
	}, "\r\n")
}

// TestRunConfigFileDetailOutput 端到端验证：配置文件提供的模拟账户可真实认证发信，
// 详细输出包含完整信封、原始头部、解析字段、TLS/AUTH、字节数与截断提示，且 SMTP
// 轨迹中的凭据已脱敏。
func TestRunConfigFileDetailOutput(t *testing.T) {
	configPath := writeConfig(t, `
listen:
  addr: "127.0.0.1:0"
  hostname: "testmail.local"
auth:
  require_auth: true
  accounts:
    - username: "tester"
      password: "test-pass"
output:
  level: "detail"
  print_body: true
  max_body_bytes: 16
  trace_smtp: true
`)
	rt := startTool(t, []string{"-config", configPath})
	addr := rt.addr(t)
	if !rt.stdout.waitFor("客户端连接参数", 3*time.Second) {
		t.Fatalf("未打印客户端连接参数: stdout=%q stderr=%q", rt.stdout.String(), rt.stderr.String())
	}

	sendSMTPMail(t, addr, "tester", "test-pass", false, buildTestMessage("测试邮件"))
	if !rt.stdout.waitFor("邮件详情", 3*time.Second) {
		t.Fatalf("未打印详细输出: stdout=%q", rt.stdout.String())
	}

	out := rt.stdout.String()
	wants := []string{
		// 启动信息：模拟账户清单、测试凭据标注、连接参数、swaks 与产品配置片段。
		"模拟账户清单（测试专用、非真实凭据）",
		"用户名=tester 密码=test-pass",
		"本地测试凭据、仅回环使用",
		"AUTH 已启用",
		"AUTH: 已启用且必须认证",
		"swaks --server ",
		"smtp.host / smtp.port / smtp.username / smtp.password",
		"host: \"127.0.0.1\"",
		"password: \"test-pass\"",
		"配置来源 配置文件",
		configPath,
		// 每条消息的详细输出。
		"收到邮件 id=",
		"信封 MAIL FROM: <sender@example.test>",
		"信封 RCPT TO: <user@example.test>",
		"Subject（解码）: \"测试邮件\"",
		"Date: 2026-11-19T10:00:00+08:00",
		"Message-ID: <extra03@example.test>",
		"TLS: 否（明文）",
		"AUTH 用户: tester（已认证）",
		"大小: ",
		"头部（原始值",
		"Subject: =?UTF-8?b?",
		"正文（共 ",
		"第一行正文",
		"已截断",
		// 会话级 SMTP 轨迹。
		"SMTP 轨迹",
		"C: EHLO",
		"C: AUTH PLAIN [凭据已脱敏]",
		"S: 235",
		"认证成功: tester",
		"连接关闭",
	}
	for _, want := range wants {
		if !strings.Contains(out, want) {
			t.Errorf("输出缺少 %q\n完整输出:\n%s", want, out)
		}
	}
	// 轨迹里绝不能出现 AUTH 初始响应的 base64 凭据。
	base64Credentials := base64.StdEncoding.EncodeToString([]byte("\x00tester\x00test-pass"))
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "SMTP 轨迹") {
			continue
		}
		if strings.Contains(line, base64Credentials) || strings.Contains(line, "test-pass") {
			t.Errorf("SMTP 轨迹泄露凭据: %q", line)
		}
	}
	if !strings.Contains(out, "要求先认证=true") {
		t.Errorf("启动信息缺少 AUTH 要求标记: %q", out)
	}

	if err := rt.stop(t); err != nil {
		t.Fatalf("优雅关闭返回错误: %v", err)
	}
	if !strings.Contains(rt.stdout.String(), "已关闭并释放端口") {
		t.Error("缺少关闭输出")
	}
	if conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Fatalf("工具退出后仍能连接 %s，端口未释放", addr)
	}
}

// TestRunStartTLSDetailOutput 验证 STARTTLS + 认证的真实收信输出，以及命令行来源的
// 测试密码不在启动信息和消息输出中回显。
func TestRunStartTLSDetailOutput(t *testing.T) {
	rt := startTool(t, []string{
		"-addr", "127.0.0.1:0",
		"-starttls",
		"-auth", "tester:tls-secret-pass",
		"-require-auth",
		"-output", "detail",
		"-trace-smtp",
	})
	addr := rt.addr(t)
	if !rt.stdout.waitFor("客户端连接参数", 3*time.Second) {
		t.Fatalf("未打印客户端连接参数: stdout=%q stderr=%q", rt.stdout.String(), rt.stderr.String())
	}

	sendSMTPMail(t, addr, "tester", "tls-secret-pass", true, buildTestMessage("TLS 测试"))
	if !rt.stdout.waitFor("邮件详情", 3*time.Second) {
		t.Fatalf("未打印详细输出: stdout=%q", rt.stdout.String())
	}

	out := rt.stdout.String()
	wants := []string{
		"STARTTLS 已启用（自签测试证书",
		"加密: STARTTLS",
		"客户端需显式信任该证书或临时跳过证书校验",
		"TLS: 是（经 STARTTLS 加密的连接）",
		"AUTH 用户: tester（已认证）",
		"swaks --server ",
		"--tls",
		"starttls: true",
		"SMTP 轨迹",
		"TLS: 握手完成",
	}
	for _, want := range wants {
		if !strings.Contains(out, want) {
			t.Errorf("输出缺少 %q\n完整输出:\n%s", want, out)
		}
	}
	// 命令行 -auth 的密码只能用于认证，不得出现在任何输出中（包括 swaks 示例与
	// 产品配置片段）。
	if strings.Contains(out, "tls-secret-pass") {
		t.Errorf("命令行测试密码被回显: %q", out)
	}
	if !strings.Contains(out, "密码=<已隐藏，命令行 -auth 不回显>") {
		t.Errorf("缺少命令行密码隐藏说明: %q", out)
	}

	if err := rt.stop(t); err != nil {
		t.Fatalf("优雅关闭返回错误: %v", err)
	}
}

// TestRunWithExampleConfigFile 直接使用随仓库提供的 config.example.yaml 启动工具
// （命令行覆盖端口为随机回环端口），验证示例配置可被真实运行，而不是只能解析。
func TestRunWithExampleConfigFile(t *testing.T) {
	rt := startTool(t, []string{"-config", "config.example.yaml", "-addr", "127.0.0.1:0"})
	addr := rt.addr(t)
	if !rt.stdout.waitFor("配置来源 配置文件 config.example.yaml", 3*time.Second) {
		t.Fatalf("未打印配置来源: stdout=%q stderr=%q", rt.stdout.String(), rt.stderr.String())
	}
	if !rt.stdout.waitFor("用户名=tester 密码=test-pass", 3*time.Second) {
		t.Fatalf("示例配置账户未生效: stdout=%q", rt.stdout.String())
	}

	// 示例配置 require_auth 为 false，AUTH 可选；这里用配置中的账户认证发信。
	sendSMTPMail(t, addr, "tester", "test-pass", false, buildTestMessage("示例配置"))
	if !rt.stdout.waitFor("邮件详情", 3*time.Second) {
		t.Fatalf("示例配置未启用 detail 输出: stdout=%q", rt.stdout.String())
	}
	if err := rt.stop(t); err != nil {
		t.Fatalf("优雅关闭返回错误: %v", err)
	}
}

// TestRunDefaultSummaryCompatibility 验证未使用任何新参数时仍保持原来的简洁摘要
// 输出（不打印详情块或 SMTP 轨迹）。
func TestRunDefaultSummaryCompatibility(t *testing.T) {
	rt := startTool(t, []string{"-addr", "127.0.0.1:0"})
	addr := rt.addr(t)
	if !rt.stdout.waitFor("模拟账户 未配置", 3*time.Second) {
		t.Fatalf("未打印账户状态: stdout=%q stderr=%q", rt.stdout.String(), rt.stderr.String())
	}

	sendSMTPMail(t, addr, "", "", false, buildTestMessage("默认摘要"))
	if !rt.stdout.waitFor("收到邮件", 3*time.Second) {
		t.Fatalf("未打印收到邮件摘要: stdout=%q", rt.stdout.String())
	}
	out := rt.stdout.String()
	if !strings.Contains(out, "subject=\"默认摘要\"") {
		t.Errorf("摘要缺少主题: %q", out)
	}
	for _, unwanted := range []string{"邮件详情", "信封 MAIL FROM", "头部（原始值", "SMTP 轨迹", "正文（共"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("默认摘要模式不应包含 %q: %q", unwanted, out)
		}
	}
	if err := rt.stop(t); err != nil {
		t.Fatalf("优雅关闭返回错误: %v", err)
	}
}

// TestLimitBytes 验证正文截断按字节上限并保证 UTF-8 字符边界。
func TestLimitBytes(t *testing.T) {
	cases := []struct {
		name          string
		data          string
		limit         int
		want          string
		wantTruncated bool
	}{
		{name: "零表示不限制", data: "abc", limit: 0, want: "abc", wantTruncated: false},
		{name: "未超过上限", data: "abc", limit: 3, want: "abc", wantTruncated: false},
		{name: "按字节截断", data: "abcdef", limit: 4, want: "abcd", wantTruncated: true},
		{name: "不切断多字节字符", data: "中文", limit: 4, want: "中", wantTruncated: true},
		{name: "空内容", data: "", limit: 8, want: "", wantTruncated: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, truncated := limitBytes([]byte(tc.data), tc.limit)
			if string(got) != tc.want || truncated != tc.wantTruncated {
				t.Errorf("limitBytes(%q, %d) = (%q, %t), 期望 (%q, %t)",
					tc.data, tc.limit, string(got), truncated, tc.want, tc.wantTruncated)
			}
		})
	}
}

// TestRawHeaderLines 验证“全部头部原始值”保留折行与原文，并兼容缺少分隔空行的消息。
func TestRawHeaderLines(t *testing.T) {
	data := []byte("Subject: hello\r\nX-Test: a\r\n b\r\n\r\nbody\r\n")
	lines := rawHeaderLines(data)
	want := []string{"Subject: hello", "X-Test: a", " b"}
	if len(lines) != len(want) {
		t.Fatalf("头部行数 = %d, 期望 %d: %v", len(lines), len(want), lines)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("第 %d 行 = %q, 期望 %q", i, lines[i], want[i])
		}
	}

	// 没有头部/正文分隔空行时，把全部内容当作头部（与解析器的宽松策略一致）。
	noSep := rawHeaderLines([]byte("Subject: only-header\r\n"))
	if len(noSep) != 1 || noSep[0] != "Subject: only-header" {
		t.Errorf("无分隔空行时头部解析异常: %v", noSep)
	}
}

// TestFormattingHelpers 验证启动信息与摘要使用的纯函数输出。
func TestFormattingHelpers(t *testing.T) {
	if got := formatRecipients(nil); got != "（无）" {
		t.Errorf("formatRecipients(nil) = %q", got)
	}
	if got := formatRecipients([]string{"a@b", "c@d"}); got != "<a@b> <c@d>" {
		t.Errorf("formatRecipients = %q", got)
	}
	if got := describeBodyLimit(0); got != "不限制" {
		t.Errorf("describeBodyLimit(0) = %q", got)
	}
	if got := describeBodyLimit(4096); got != "4096字节" {
		t.Errorf("describeBodyLimit(4096) = %q", got)
	}
	if got := accountNames([]testAccount{{Username: "a"}, {Username: "b"}}); got != "a、b" {
		t.Errorf("accountNames = %q", got)
	}
	cfg := runConfig{AccountSource: accountSourceConfig}
	if got := displayPassword(cfg, testAccount{Password: "test-pass"}); got != "test-pass" {
		t.Errorf("配置文件密码应回显: %q", got)
	}
	cfg.AccountSource = accountSourceCommand
	if got := displayPassword(cfg, testAccount{Password: "should-not-print"}); strings.Contains(got, "should-not-print") {
		t.Errorf("命令行密码不应回显: %q", got)
	}
	if got := fmt.Sprint(outputDetail); got != "detail" {
		t.Errorf("outputDetail = %q", got)
	}
}

// readSMTPReply 读取一段 SMTP 应答（合并多行）并返回首行状态码。
func readSMTPReply(t *testing.T, reader *bufio.Reader) int {
	t.Helper()
	code := 0
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("读取 SMTP 应答失败: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) < 3 {
			t.Fatalf("SMTP 应答过短: %q", line)
		}
		if code == 0 {
			if _, err := fmt.Sscanf(line[:3], "%d", &code); err != nil {
				t.Fatalf("解析 SMTP 状态码失败: %q", line)
			}
		}
		if len(line) < 4 || line[3] != '-' {
			return code
		}
	}
}

// expectSMTPReply 读取并断言 SMTP 状态码。
func expectSMTPReply(t *testing.T, reader *bufio.Reader, want int) {
	t.Helper()
	if got := readSMTPReply(t, reader); got != want {
		t.Fatalf("期望 SMTP %d，实际 %d", want, got)
	}
}

// sendWithAuthLogin 用原始 SMTP 会话完成 AUTH LOGIN 认证并投递一封邮件。
// net/smtp 的 PlainAuth 只支持 AUTH PLAIN，这里手工走 LOGIN 以覆盖其轨迹脱敏。
func sendWithAuthLogin(t *testing.T, addr, user, pass, data string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("连接 %s 失败: %v", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)
	send := func(line string) {
		if _, err := io.WriteString(conn, line+"\r\n"); err != nil {
			t.Fatalf("发送 %q 失败: %v", line, err)
		}
	}

	expectSMTPReply(t, reader, 220)
	send("EHLO login.test")
	expectSMTPReply(t, reader, 250)
	send("AUTH LOGIN")
	expectSMTPReply(t, reader, 334)
	send(base64.StdEncoding.EncodeToString([]byte(user)))
	expectSMTPReply(t, reader, 334)
	send(base64.StdEncoding.EncodeToString([]byte(pass)))
	expectSMTPReply(t, reader, 235)
	send("MAIL FROM:<sender@example.test>")
	expectSMTPReply(t, reader, 250)
	send("RCPT TO:<user@example.test>")
	expectSMTPReply(t, reader, 250)
	send("DATA")
	expectSMTPReply(t, reader, 354)
	var payload strings.Builder
	for _, line := range strings.Split(strings.ReplaceAll(data, "\r\n", "\n"), "\n") {
		if strings.HasPrefix(line, ".") {
			payload.WriteString(".")
		}
		payload.WriteString(line)
		payload.WriteString("\r\n")
	}
	payload.WriteString(".\r\n")
	if _, err := io.WriteString(conn, payload.String()); err != nil {
		t.Fatalf("发送 DATA 失败: %v", err)
	}
	expectSMTPReply(t, reader, 250)
	send("QUIT")
	expectSMTPReply(t, reader, 221)
}

// traceLines 返回输出中全部 SMTP 轨迹行。
func traceLines(output string) []string {
	var lines []string
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "SMTP 轨迹") {
			lines = append(lines, line)
		}
	}
	return lines
}

// TestTraceRedactsAuthLoginAndBody 回归验证 AUTH LOGIN 轨迹：凭据（明文与 base64）
// 与邮件正文都不进入轨迹，而认证成功信息与机制名仍可见。
func TestTraceRedactsAuthLoginAndBody(t *testing.T) {
	const (
		user       = "login-user"
		pass       = "login-secret"
		bodyMarker = "BODY-MARKER-不应出现在轨迹中"
	)
	rt := startTool(t, []string{
		"-addr", "127.0.0.1:0",
		"-auth", user + ":" + pass,
		"-require-auth",
		"-output", "debug",
		"-print-body",
	})
	addr := rt.addr(t)
	if !rt.stdout.waitFor("客户端连接参数", 3*time.Second) {
		t.Fatalf("未打印客户端连接参数: stdout=%q stderr=%q", rt.stdout.String(), rt.stderr.String())
	}

	message := strings.Join([]string{
		"From: \"Sender\" <sender@example.test>",
		"To: <user@example.test>",
		"Subject: auth login trace",
		"",
		bodyMarker,
		"",
	}, "\r\n")
	sendWithAuthLogin(t, addr, user, pass, message)
	if !rt.stdout.waitFor("邮件详情", 3*time.Second) {
		t.Fatalf("未打印详细输出: stdout=%q", rt.stdout.String())
	}

	out := rt.stdout.String()
	lines := traceLines(out)
	if len(lines) == 0 {
		t.Fatalf("未产生 SMTP 轨迹: %q", out)
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "C: AUTH LOGIN [凭据已脱敏]") {
		t.Errorf("轨迹缺少脱敏后的 AUTH LOGIN 命令: %q", joined)
	}
	if !strings.Contains(joined, "认证成功: "+user) {
		t.Errorf("轨迹缺少认证成功信息: %q", joined)
	}
	forbidden := []string{
		pass,
		base64.StdEncoding.EncodeToString([]byte(user)),
		base64.StdEncoding.EncodeToString([]byte(pass)),
		bodyMarker,
	}
	for _, secret := range forbidden {
		if strings.Contains(joined, secret) {
			t.Errorf("SMTP 轨迹泄露了 %q: %q", secret, joined)
		}
	}
	if err := rt.stop(t); err != nil {
		t.Fatalf("优雅关闭返回错误: %v", err)
	}
}

// TestDetailOutputEscapesControlChars 验证消息头部与正文中的终端控制字符（尤其
// ESC）在 detail 输出中被转义，不会直接写入终端。
func TestDetailOutputEscapesControlChars(t *testing.T) {
	rt := startTool(t, []string{"-addr", "127.0.0.1:0", "-output", "detail", "-print-body"})
	addr := rt.addr(t)
	if !rt.stdout.waitFor("客户端连接参数", 3*time.Second) {
		t.Fatalf("未打印客户端连接参数: stdout=%q stderr=%q", rt.stdout.String(), rt.stderr.String())
	}

	message := strings.Join([]string{
		"From: \"Sender\" <sender@example.test>",
		"To: <user@example.test>",
		"Subject: \x1b[31mevil\x07",
		"X-Escape: a\x1b]0;pwned\x07b",
		"",
		"正文含 \x1b[2J 与 \x07 控制字符",
		"",
	}, "\r\n")
	sendSMTPMail(t, addr, "", "", false, message)
	if !rt.stdout.waitFor("邮件详情", 3*time.Second) {
		t.Fatalf("未打印详细输出: stdout=%q", rt.stdout.String())
	}
	out := rt.stdout.String()
	if strings.ContainsRune(out, 0x1b) {
		t.Errorf("输出仍含原始 ESC 字节，存在终端转义注入风险: %q", out)
	}
	if strings.ContainsRune(out, 0x07) {
		t.Errorf("输出仍含原始 BEL 字节: %q", out)
	}
	for _, want := range []string{`\x1b`, `\x07`} {
		if !strings.Contains(out, want) {
			t.Errorf("输出缺少转义后的控制字符 %q: %q", want, out)
		}
	}
	if err := rt.stop(t); err != nil {
		t.Fatalf("优雅关闭返回错误: %v", err)
	}
}

// TestSanitizeLine 验证控制字符转义规则。
func TestSanitizeLine(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "普通文本不变", in: "subject 测试", want: "subject 测试"},
		{name: "ESC 转义", in: "a\x1b[31mb", want: `a\x1b[31mb`},
		{name: "BEL 与 DEL 转义", in: "x\x07y\x7fz", want: `x\x07y\x7fz`},
		{name: "C1 控制字符转义", in: "a\u009bb", want: `a\x9bb`},
		{name: "制表符保留", in: "a\tb", want: "a\tb"},
		{name: "行分隔符转义", in: "a\u2028b", want: `a\u2028b`},
		{name: "空字符串", in: "", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeLine(tc.in); got != tc.want {
				t.Errorf("sanitizeLine(%q) = %q, 期望 %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestSanitizeTextBlock 验证整段正文按行转义并保留换行。
func TestSanitizeTextBlock(t *testing.T) {
	got := sanitizeTextBlock("第一行\x1b[1m\n第二行\x07\r\n第三行")
	want := `第一行\x1b[1m` + "\n" + `第二行\x07` + "\n第三行"
	if got != want {
		t.Errorf("sanitizeTextBlock = %q, 期望 %q", got, want)
	}
	if !strings.Contains(got, "\n") {
		t.Error("sanitizeTextBlock 应保留换行")
	}
}
