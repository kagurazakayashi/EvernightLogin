package app

// 步骤 221 P0：注册与邮箱验证公开接口测试。
//   - 使用真实临时 SQLite 与真实注册领域服务；
//   - 验证邮件通过测试内置的最小 SMTP 捕获服务器（回环明文，TLS none 合法）接收，
//     从真实邮件正文提取一次性链接，不伪造令牌；
//   - 覆盖注册成功/重名与规范化冲突/弱密码/注册关闭、验证入口正反路径、
//     匿名防枚举重发与请求编号。

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

// smtpCapture 是最小 SMTP 捕获服务器：只接收一封/多封邮件并保存 DATA 原文，
// 用于从真实验证邮件中提取一次性链接；不访问外网、只监听回环端口。
type smtpCapture struct {
	listener net.Listener
	mu       sync.Mutex
	messages []string
	closed   chan struct{}
}

// startSMTPCapture 启动回环捕获服务器并返回地址与句柄。
func startSMTPCapture(t *testing.T) *smtpCapture {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动 SMTP 捕获服务器失败: %v", err)
	}
	capture := &smtpCapture{listener: listener, closed: make(chan struct{})}
	go capture.serve()
	t.Cleanup(func() {
		close(capture.closed)
		_ = listener.Close()
	})
	return capture
}

// Addr 返回回环监听地址。
func (c *smtpCapture) Addr() string { return c.listener.Addr().String() }

// serve 处理最小 SMTP 会话。
func (c *smtpCapture) serve() {
	for {
		connection, err := c.listener.Accept()
		if err != nil {
			return
		}
		go c.handle(connection)
	}
}

// handle 实现最小 SMTP 命令应答（EHLO/MAIL/RCPT/DATA/QUIT）。
func (c *smtpCapture) handle(connection net.Conn) {
	defer func() { _ = connection.Close() }()
	reader := bufio.NewReader(connection)
	writer := bufio.NewWriter(connection)
	writeLine := func(line string) bool {
		if _, err := writer.WriteString(line + "\r\n"); err != nil {
			return false
		}
		return writer.Flush() == nil
	}
	if !writeLine("220 capture SMTP") {
		return
	}
	var data strings.Builder
	inData := false
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if inData {
			if line == "." {
				inData = false
				c.mu.Lock()
				c.messages = append(c.messages, data.String())
				c.mu.Unlock()
				data.Reset()
				if !writeLine("250 OK queued") {
					return
				}
				continue
			}
			data.WriteString(line)
			data.WriteString("\r\n")
			continue
		}
		command := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(command, "EHLO"), strings.HasPrefix(command, "HELO"):
			if !writeLine("250-capture") || !writeLine("250 AUTH PLAIN") {
				return
			}
		case strings.HasPrefix(command, "MAIL FROM"), strings.HasPrefix(command, "RCPT TO"),
			strings.HasPrefix(command, "RSET"), strings.HasPrefix(command, "NOOP"):
			if !writeLine("250 OK") {
				return
			}
		case strings.HasPrefix(command, "DATA"):
			inData = true
			if !writeLine("354 End data with <CR><LF>.<CR><LF>") {
				return
			}
		case strings.HasPrefix(command, "QUIT"):
			_ = writeLine("221 Bye")
			return
		default:
			if !writeLine("250 OK") {
				return
			}
		}
	}
}

// waitMail 有界等待包含 URL 片段的邮件，返回提取到的链接。
func (c *smtpCapture) waitMail(t *testing.T, pathFragment string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		c.mu.Lock()
		messages := append([]string(nil), c.messages...)
		c.mu.Unlock()
		for _, message := range messages {
			for _, link := range linksInMessage(message) {
				if strings.Contains(link, pathFragment) {
					return link
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("等待包含 %s 的邮件超时", pathFragment)
		}
		select {
		case <-c.closed:
			t.Fatal("SMTP 捕获服务器已关闭")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// linksInMessage 从原始邮件中提取 http(s) 链接：先按 MIME 传输编码解码正文
// （base64/quoted-printable/multipart），避免从密文里找链接。
func linksInMessage(message string) []string {
	decoded := decodeMailBody([]byte(message))
	matches := regexp.MustCompile(`https?://[^\s"'<>]+`).FindAllString(string(decoded), -1)
	return matches
}

// decodeMailBody 最小 MIME 解码：支持 base64/quoted-printable/multipart。
func decodeMailBody(raw []byte) []byte {
	header, body, ok := splitMailParts(raw)
	if !ok {
		return raw
	}
	mediaType, params, _ := mime.ParseMediaType(headerValue(header, "Content-Type"))
	if strings.HasPrefix(strings.ToLower(mediaType), "multipart/") && params["boundary"] != "" {
		var combined bytes.Buffer
		for _, part := range bytes.Split(body, []byte("--"+params["boundary"])) {
			part = bytes.TrimPrefix(part, []byte("\r\n"))
			part = bytes.TrimPrefix(part, []byte("\n"))
			if len(part) == 0 || bytes.HasPrefix(part, []byte("--")) {
				continue
			}
			combined.Write(decodeMailBody(part))
			combined.WriteByte('\n')
		}
		if combined.Len() > 0 {
			return combined.Bytes()
		}
		return body
	}
	switch strings.ToLower(strings.TrimSpace(headerValue(header, "Content-Transfer-Encoding"))) {
	case "base64":
		compact := strings.Join(strings.Fields(string(body)), "")
		if decoded, err := base64.StdEncoding.DecodeString(compact); err == nil {
			return decoded
		}
		if decoded, err := base64.RawStdEncoding.DecodeString(compact); err == nil {
			return decoded
		}
	case "quoted-printable":
		if decoded, err := io.ReadAll(quotedprintable.NewReader(bytes.NewReader(body))); err == nil {
			return decoded
		}
	}
	return body
}

// splitMailParts 以首个空行切分头部与正文。
func splitMailParts(raw []byte) ([]byte, []byte, bool) {
	if index := bytes.Index(raw, []byte("\r\n\r\n")); index >= 0 {
		return raw[:index], raw[index+4:], true
	}
	if index := bytes.Index(raw, []byte("\n\n")); index >= 0 {
		return raw[:index], raw[index+2:], true
	}
	return nil, raw, false
}

// headerValue 读取头部字段值（大小写不敏感）。
func headerValue(header []byte, name string) string {
	for _, line := range strings.Split(string(header), "\n") {
		line = strings.TrimRight(line, "\r")
		key, value, found := strings.Cut(line, ":")
		if !found || !strings.EqualFold(strings.TrimSpace(key), name) {
			continue
		}
		return strings.TrimSpace(value)
	}
	return ""
}

// mailEnabledConfig 返回启用真实邮件投递的测试配置（SMTP 指向捕获服务器）。
func mailEnabledConfig(t *testing.T, capture *smtpCapture) login.Config {
	t.Helper()
	config := testConfig()
	config.Registration.RequireEmailVerification = true
	config.Server.PublicBaseURL = "http://127.0.0.1:9"
	config.Mail.Enabled = true
	config.Mail.SMTP.Addr = capture.Addr()
	config.Mail.SMTP.TLSMode = "none"
	config.Mail.SMTP.AllowPlaintextLocal = true
	config.Mail.SMTP.TimeoutSeconds = 5
	config.Mail.From.Address = "no-reply@example.test"
	config.Mail.Delivery.MaxAttempts = 1
	config.Mail.Delivery.TimeoutSeconds = 30
	return config
}

// openMailRuntime 打开启用邮件投递并启动任务执行器的运行时（验证邮件真实发出）。
func openMailRuntime(t *testing.T, ctx context.Context, capture *smtpCapture,
	clock *testClock) *Runtime {
	t.Helper()
	runtime := adminTestRuntime(t, ctx, mailEnabledConfig(t, capture), t.TempDir(), clock)
	if err := runtime.Start(ctx); err != nil {
		t.Fatalf("启动运行时: %v", err)
	}
	return runtime
}

// TestRegistrationPublicFlow 覆盖注册开关/重名/规范化/弱密码/验证入口正反路径。
func TestRegistrationPublicFlow(t *testing.T) {
	ctx := context.Background()
	capture := startSMTPCapture(t)
	clock := newTestClock(time.Date(2026, 11, 25, 5, 20, 0, 0, time.UTC))
	runtime := openMailRuntime(t, ctx, capture, clock)
	registration := runtime.Registration()
	availability, err := registration.Availability(ctx)
	if err != nil {
		t.Fatalf("Availability: %v", err)
	}
	if !availability.Enabled || !availability.RequireEmailVerification ||
		!availability.EmailCapability {
		t.Fatalf("注册能力概览异常: %+v", availability)
	}

	const password = "K8$wR3!nB6@yF1#v"
	registered, err := registration.RegisterAccount(ctx, RegisterAccountRequest{
		Username: "reg-public", Password: password, Email: "reg-public@example.test",
		Nickname: "注册测试", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("RegisterAccount: %v", err)
	}
	if registered.UserID == "" || registered.Username != "reg-public" ||
		registered.Status != "active" {
		t.Fatalf("注册结果异常: %+v", registered)
	}
	// 重名（大小写/规范化冲突）→ CONFLICT，不泄露具体冲突字段。
	if _, err := registration.RegisterAccount(ctx, RegisterAccountRequest{
		Username: "REG-PUBLIC", Password: password, Email: "other@example.test",
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeConflict) {
		t.Fatalf("规范化重名错误 = %v，期望 CONFLICT", err)
	}
	// 弱密码 → REQ_INVALID。
	if _, err := registration.RegisterAccount(ctx, RegisterAccountRequest{
		Username: "reg-weak", Password: "123456", Email: "reg-weak@example.test",
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("弱密码错误 = %v，期望 REQ_INVALID", err)
	}

	// 真实邮件中的验证链接 → 提取 uid/cid/token → 公开 VerifyEmail。
	verificationLink := capture.waitMail(t, "/email/verify")
	parsed, err := url.Parse(verificationLink)
	if err != nil {
		t.Fatalf("解析验证链接失败: %v", err)
	}
	verified, err := registration.VerifyEmail(ctx, VerifyEmailRequest{
		UserID:       parsed.Query().Get("uid"),
		CredentialID: parsed.Query().Get("cid"),
		Token:        parsed.Query().Get("token"),
		RequestID:    login.NewRequestID()})
	if err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	if verified.Email != "reg-public@example.test" || verified.UserID != registered.UserID {
		t.Fatalf("验证结果异常: %+v", verified)
	}
	// 一次性：重复验证拒绝。
	if _, err := registration.VerifyEmail(ctx, VerifyEmailRequest{
		UserID:       parsed.Query().Get("uid"),
		CredentialID: parsed.Query().Get("cid"),
		Token:        parsed.Query().Get("token"),
		RequestID:    login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeChallengeInvalid) {
		t.Fatalf("重复验证错误 = %v，期望 CHALLENGE_INVALID", err)
	}
	// 伪造 token 拒绝。
	if _, err := registration.VerifyEmail(ctx, VerifyEmailRequest{
		UserID: registered.UserID, CredentialID: "otc_00000000000000000000000000000000",
		Token: "forged", RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeChallengeInvalid) {
		t.Fatalf("伪造验证错误 = %v，期望 CHALLENGE_INVALID", err)
	}
}

// TestRegistrationClosedConfigInvalid 覆盖注册关闭时稳定 CONFIG_INVALID。
func TestRegistrationClosedConfigInvalid(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 5, 30, 0, 0, time.UTC))
	config := testConfig()
	config.Registration.Enabled = false
	runtime := adminTestRuntime(t, ctx, config, t.TempDir(), clock)
	if _, err := runtime.Registration().RegisterAccount(ctx, RegisterAccountRequest{
		Username: "reg-closed", Password: "K8$wR3!nB6@yF1#v",
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeConfigInvalid) {
		t.Fatalf("注册关闭错误 = %v，期望 CONFIG_INVALID", err)
	}
}

// TestRegistrationResendAntiEnumeration 覆盖匿名重发的防枚举与请求编号语义。
func TestRegistrationResendAntiEnumeration(t *testing.T) {
	ctx := context.Background()
	capture := startSMTPCapture(t)
	clock := newTestClock(time.Date(2026, 11, 25, 5, 40, 0, 0, time.UTC))
	runtime := openMailRuntime(t, ctx, capture, clock)
	registration := runtime.Registration()
	const password = "K8$wR3!nB6@yF1#v"
	registered, err := registration.RegisterAccount(ctx, RegisterAccountRequest{
		Username: "reg-resend", Password: password, Email: "reg-resend@example.test",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("RegisterAccount: %v", err)
	}
	// 未知账户/伪造链接/空证明：全部 Accepted=true，不泄露状态。
	unknown, err := registration.ResendEmailVerification(ctx,
		ResendEmailVerificationRequest{UserID: "usr_00000000000000000000000000000000",
			CredentialID: "otc_00000000000000000000000000000000", Token: "forged",
			RequestID: login.NewRequestID()})
	if err != nil || !unknown.Accepted {
		t.Fatalf("未知账户重发 = %+v, %v（应统一 Accepted）", unknown, err)
	}
	forged, err := registration.ResendEmailVerification(ctx,
		ResendEmailVerificationRequest{UserID: registered.UserID,
			CredentialID: "otc_00000000000000000000000000000000", Token: "forged",
			RequestID: login.NewRequestID()})
	if err != nil || !forged.Accepted {
		t.Fatalf("伪造链接重发 = %+v, %v", forged, err)
	}
	if _, err := registration.ResendEmailVerification(ctx,
		ResendEmailVerificationRequest{SessionSecret: []byte("invalid-session"),
			RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("无效会话重发应仍 Accepted: %v", err)
	}
	// 本人会话重发：真实受冷却限制，但对外仍 Accepted。
	session := loginLifecycleUser(t, ctx, runtime, "reg-resend", password)
	accepted, err := registration.ResendEmailVerification(ctx,
		ResendEmailVerificationRequest{SessionSecret: session,
			RequestID: login.NewRequestID()})
	if err != nil || !accepted.Accepted {
		t.Fatalf("本人重发 = %+v, %v", accepted, err)
	}
	// 请求编号非法：匿名重发仍不返回错误（防枚举），但内部不执行；
	// 非匿名 API 的非法 RequestID 必须 REQ_INVALID。
	if _, err := registration.RegisterAccount(ctx, RegisterAccountRequest{
		Username: "reg-invalid-request", Password: password,
		RequestID: "req_invalid!"}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("非法请求编号注册错误 = %v，期望 REQ_INVALID", err)
	}
}
