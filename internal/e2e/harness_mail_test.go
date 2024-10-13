package e2e

// 步骤 274 收尾：受控邮件链路夹具（本机回环 SMTP 捕获器，不访问外网、不外发真实
// 邮件）+ 真实 mail.enabled 装配。
//
// 用途：250（A→B→A 旧找回链接永久拒绝）、265/266（安全告知邮件投递真实终态）。
// 捕获器只监听 127.0.0.1 随机端口，测试结束即关闭；邮件正文与令牌只在内存中用于本次
// 断言，不写入日志/报告/持久文件，测试失败消息不展开令牌内容。

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	loginapp "github.com/kagurazakayashi/EvernightLogin/app"
)

// smtpCapture 是极简本机 SMTP 捕获器（仅支持 EHLO/HELO/MAIL/RCPT/DATA/QUIT）。
type smtpCapture struct {
	listener net.Listener
	mu       sync.Mutex
	messages []string
	closed   bool
	wg       sync.WaitGroup
}

// startSMTPCapture 启动 127.0.0.1 随机端口的捕获器。
func startSMTPCapture(t *testing.T) *smtpCapture {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动本机 SMTP 捕获器: %v", err)
	}
	capture := &smtpCapture{listener: listener}
	capture.wg.Add(1)
	go capture.serve()
	t.Cleanup(capture.Close)
	return capture
}

// Addr 返回监听地址（host:port）。
func (c *smtpCapture) Addr() string { return c.listener.Addr().String() }

func (c *smtpCapture) serve() {
	defer c.wg.Done()
	for {
		conn, err := c.listener.Accept()
		if err != nil {
			return
		}
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			c.handle(conn)
		}()
	}
}

// Close 关闭监听并等待所有连接结束。
func (c *smtpCapture) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.mu.Unlock()
	_ = c.listener.Close()
	c.wg.Wait()
}

// handle 处理一个 SMTP 会话；DATA 内容按原始字节保存（含 MIME 编码）。
func (c *smtpCapture) handle(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	writeLine := func(line string) {
		_, _ = writer.WriteString(line + "\r\n")
		_ = writer.Flush()
	}
	writeLine("220 127.0.0.1 ESMTP step274-capture")
	inData := false
	var data strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if inData {
			if trimmed == "." {
				inData = false
				c.mu.Lock()
				c.messages = append(c.messages, data.String())
				c.mu.Unlock()
				data.Reset()
				writeLine("250 2.0.0 queued")
				continue
			}
			if strings.HasPrefix(trimmed, "..") {
				trimmed = trimmed[1:]
			}
			data.WriteString(trimmed)
			data.WriteString("\r\n")
			continue
		}
		upper := strings.ToUpper(trimmed)
		switch {
		case strings.HasPrefix(upper, "EHLO"):
			writeLine("250-127.0.0.1")
			writeLine("250 8BITMIME")
		case strings.HasPrefix(upper, "HELO"):
			writeLine("250 127.0.0.1")
		case strings.HasPrefix(upper, "DATA"):
			inData = true
			writeLine("354 end with <CRLF>.<CRLF>")
		case strings.HasPrefix(upper, "QUIT"):
			writeLine("221 bye")
			return
		case strings.HasPrefix(upper, "RSET"):
			writeLine("250 2.0.0 reset")
		default:
			writeLine("250 2.0.0 ok")
		}
	}
}

// messageCount 返回已捕获邮件数。
func (c *smtpCapture) messageCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.messages)
}

// snapshot 返回当前全部邮件原始内容副本。
func (c *smtpCapture) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.messages...)
}

// waitMessages 等待至少 want 封邮件（有界轮询）。
func (c *smtpCapture) waitMessages(t *testing.T, want int, timeout time.Duration) []string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		messages := c.snapshot()
		if len(messages) >= want {
			return messages
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("等待邮件超时：已捕获 %d 封，期望至少 %d 封", c.messageCount(), want)
	return nil
}

// openEnvMail 打开启用真实 mail.enabled 与回环 SMTP 捕获器的运行时，并显式启动
// 后台任务（可靠投递 worker），关闭时由 t.Cleanup 逆序停止。
func openEnvMail(t *testing.T, capture *smtpCapture) *harnessEnv {
	t.Helper()
	clock := newTestClock(time.Date(2026, 11, 26, 6, 0, 0, 0, time.UTC))
	dir := t.TempDir()
	cfg := testConfig()
	cfg.Server.PublicBaseURL = "http://127.0.0.1:18080"
	cfg.Mail.Enabled = true
	cfg.Mail.AppName = "EvernightLogin 步骤274"
	cfg.Mail.SMTP.Addr = capture.Addr()
	cfg.Mail.SMTP.Host = "127.0.0.1"
	cfg.Mail.SMTP.TLSMode = "none"
	cfg.Mail.SMTP.AllowPlaintextLocal = true
	cfg.Mail.From.Address = "no-reply@example.test"
	cfg.Mail.From.Name = "EvernightLogin"
	dbPath := dir + "/login.db"
	masterKey := dir + "/master.key"
	runtime, err := loginapp.Open(context.Background(), loginapp.Options{
		Config: &cfg, DatabasePath: dbPath, MasterKeyFile: masterKey,
		CreateMasterKey: true, Migrate: true, OperatorID: "step274-e2e-mail",
		Logger: slog.New(slog.NewTextHandler(io.Discard,
			&slog.HandlerOptions{Level: slog.LevelError + 1})),
		Now:  clock.Now,
		HTTP: &loginapp.HTTPOptions{EnableAdminAPI: true},
	})
	if err != nil {
		t.Fatalf("打开含邮件与 HTTP 的测试运行时: %v", err)
	}
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	if err := runtime.Start(context.Background()); err != nil {
		t.Fatalf("启动后台任务运行时（邮件投递 worker）: %v", err)
	}
	return &harnessEnv{Runtime: runtime, Clock: clock, Dir: dir, DBPath: dbPath,
		MasterKey: masterKey, Config: cfg}
}

// seededVerifiedEmail 直接用只读/夹具 SQL 为目标用户登记已验证邮箱（避免依赖
// 真实邮件验证流程；邮件验证流程本身有 250 定向测试覆盖）。
func seededVerifiedEmail(t *testing.T, dbPath, userID, email string) {
	t.Helper()
	normalized := strings.ToLower(strings.TrimSpace(email))
	nowMS := time.Now().UTC().UnixMilli()
	executeSQL(t, dbPath, `INSERT OR REPLACE INTO user_emails(
email_normalized,user_id,email,verified_at_ms,created_at_ms,updated_at_ms)
VALUES('`+normalized+`','`+userID+`','`+normalized+`',`+
		int64Text(nowMS)+`,`+int64Text(nowMS)+`,`+int64Text(nowMS)+`)`)
}

// int64Text 是 SQL 夹具的小工具。
func int64Text(value int64) string { return strconv.FormatInt(value, 10) }

// decodeCapturedMessage 解码捕获到的原始 MIME 邮件，返回可搜索的正文文本。
//
// 产品邮件模板含中文，传输时正文常为 base64/quoted-printable 或 multipart；
// 直接对原始 DATA 字符串搜索 URL 会因编码而漏检。这里按 MIME 逐部分解码（不改变
// 捕获存储本身），再交给 URL/token 提取；解码失败时退回软换行+base64 片段扫描。
func decodeCapturedMessage(raw string) string {
	message, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		return decodeCapturedFallback(raw)
	}
	return decodeMIMEPart(message.Header, message.Body)
}

// decodeMIMEPart 递归解码一个 MIME 部分。
func decodeMIMEPart(header interface{ Get(string) string }, body io.Reader) string {
	data, readErr := io.ReadAll(body)
	if readErr != nil {
		data = nil
	}
	mediaType, params, parseErr := mime.ParseMediaType(header.Get("Content-Type"))
	if parseErr != nil {
		mediaType = ""
	}
	switch strings.ToLower(strings.TrimSpace(header.Get("Content-Transfer-Encoding"))) {
	case "base64":
		if decoded, decodeErr := base64.StdEncoding.DecodeString(
			strings.Join(strings.Fields(string(data)), "")); decodeErr == nil {
			data = decoded
		}
	case "quoted-printable":
		if decoded, decodeErr := io.ReadAll(quotedprintable.NewReader(bytes.NewReader(data))); decodeErr == nil {
			data = decoded
		}
	}
	if strings.HasPrefix(strings.ToLower(mediaType), "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return string(data)
		}
		var builder strings.Builder
		reader := multipart.NewReader(bytes.NewReader(data), boundary)
		for {
			part, partErr := reader.NextPart()
			if partErr != nil {
				break
			}
			builder.WriteString(decodeMIMEPart(part.Header, part))
			builder.WriteString("\n")
		}
		return builder.String()
	}
	return string(data)
}

// decodeCapturedFallback 在 MIME 解析失败时解码软换行与 base64 片段。
func decodeCapturedFallback(raw string) string {
	decoded := strings.ReplaceAll(raw, "=\r\n", "")
	decoded = strings.ReplaceAll(decoded, "=\n", "")
	var builder strings.Builder
	builder.WriteString(decoded)
	for _, token := range regexp.MustCompile(`[A-Za-z0-9+/=\r\n]{200,}`).FindAllString(raw, -1) {
		binary, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(token), ""))
		if err != nil {
			continue
		}
		builder.WriteString("\n")
		builder.Write(binary)
	}
	return builder.String()
}

// capturedURLList 返回全部匹配的一次性链接（按邮件新到旧、去重）。
func capturedURLList(messages []string, pathFragment string) []string {
	seen := make(map[string]bool)
	var links []string
	for index := len(messages) - 1; index >= 0; index-- {
		decoded := decodeCapturedMessage(messages[index])
		decoded = strings.ReplaceAll(decoded, "&amp;", "&")
		for _, candidate := range strings.Fields(decoded) {
			trimmed := strings.Trim(candidate, "<>\"'()[]{}")
			if !strings.Contains(trimmed, pathFragment) {
				continue
			}
			if !strings.HasPrefix(trimmed, "http://") && !strings.HasPrefix(trimmed, "https://") {
				continue
			}
			parsed, err := url.Parse(trimmed)
			if err != nil || parsed.Scheme == "" {
				continue
			}
			normalized := parsed.String()
			if seen[normalized] {
				continue
			}
			seen[normalized] = true
			links = append(links, normalized)
		}
	}
	return links
}

// capturedURL 从原始邮件中还原指定路径的一次性链接（MIME 解码 + quoted-printable 软换行）。
// 按捕获顺序从新到旧扫描：同一路径多次发送时返回最新一封的链接（避免复用已消费链接）。
func capturedURL(messages []string, pathFragment string) (string, bool) {
	for index := len(messages) - 1; index >= 0; index-- {
		decoded := decodeCapturedMessage(messages[index])
		decoded = strings.ReplaceAll(decoded, "&amp;", "&")
		for _, candidate := range strings.Fields(decoded) {
			trimmed := strings.Trim(candidate, "<>\"'()[]{}")
			if !strings.Contains(trimmed, pathFragment) {
				continue
			}
			if !strings.HasPrefix(trimmed, "http://") && !strings.HasPrefix(trimmed, "https://") {
				continue
			}
			if parsed, err := url.Parse(trimmed); err == nil && parsed.Scheme != "" {
				return parsed.String(), true
			}
		}
	}
	return "", false
}

// linkTokenPattern 提取一次性令牌的保守字符集（base64url/hex）。
var linkTokenPattern = regexp.MustCompile(`[A-Za-z0-9_-]{20,}`)

// linkTokens 返回邮件中所有可能的一次性令牌候选（用于“尝试到成功”的稳健解析）。
func linkTokens(messages []string) []string {
	seen := make(map[string]bool)
	var tokens []string
	for _, message := range messages {
		decoded := decodeCapturedMessage(message)
		for _, candidate := range linkTokenPattern.FindAllString(decoded, -1) {
			if len(candidate) < 24 || seen[candidate] {
				continue
			}
			seen[candidate] = true
			tokens = append(tokens, candidate)
		}
	}
	return tokens
}

// waitDeliveryState 在临时库中轮询等待指定幂等键前缀的投递记录进入目标终态。
func waitDeliveryState(t *testing.T, dbPath, idempotencyPrefix, want string,
	timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastState string
	for time.Now().Before(deadline) {
		lastState = ""
		queryOne(t, dbPath, `SELECT state FROM mail_deliveries
WHERE idempotency_key LIKE ? ORDER BY created_at_ms DESC LIMIT 1`,
			[]any{idempotencyPrefix + "%"}, &lastState)
		if lastState == want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("等待投递终态超时：幂等键前缀 %q 最后状态 = %q，期望 %q",
		idempotencyPrefix, lastState, want)
}
