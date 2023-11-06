// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package main

// 本文件以**真实 EvernightMail 二进制子进程**作为本地邮件接收端（步骤 198 口径）。
//
// 外部模块不能导入 Login 的 internal/mailtest，因此这里只复现夹具的公开行为：
//   - 用临时 YAML、随机回环端口、临时数据目录启动 `evernightmail serve`；
//   - 从 Mail 文件存储中读取“已提交”的 .eml + .json 成对文件（校验 size/sha256），
//     再从邮件正文提取一次性链接；不读取个人配置、不访问公网；
//   - 结束时有界终止本次创建的进程树并等待端口释放，临时目录由调用方删除。
//
// 安全边界：合成管理员密码只在进程内使用且不打印；数据集仅含合成测试邮件。

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	mailReadyTimeout = 20 * time.Second
	mailStopTimeout  = 10 * time.Second
)

// mailMessage 是从 Mail 数据目录读取到的一封已提交邮件（最少字段）。
type mailMessage struct {
	ID         string
	ReceivedAt time.Time
	To         []string
	Subject    string
	Body       []byte
}

// mailbox 是运行中的 EvernightMail 子进程与数据目录句柄。
type mailbox struct {
	BinPath    string
	RootDir    string
	DataDir    string
	ConfigPath string
	SMTPAddr   string
	POP3Addr   string
	HTTPAddr   string
	AdminUser  string

	adminPassword string
	cmd           *exec.Cmd
	done          chan struct{}
	stdout        *tailBuffer
	stderr        *tailBuffer
	closeOnce     sync.Once
	closeErr      error
}

// startMailbox 启动真实 EvernightMail 子进程并等待就绪。
func startMailbox(binPath, workRoot string) (*mailbox, error) {
	absolute, err := filepath.Abs(binPath)
	if err != nil {
		return nil, fmt.Errorf("解析 EvernightMail 二进制路径失败: %w", err)
	}
	if info, statErr := os.Stat(absolute); statErr != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("EvernightMail 二进制不可用（%s）；请设置 -mail 或 EVERNIGHTMAIL_BIN", absolute)
	}
	smtpPort, err := freeLoopbackPort()
	if err != nil {
		return nil, err
	}
	pop3Port, err := freeLoopbackPort()
	if err != nil {
		return nil, err
	}
	httpPort, err := freeLoopbackPort()
	if err != nil {
		return nil, err
	}
	root := filepath.Join(workRoot, "mail")
	dataDir := filepath.Join(root, "data")
	instance := &mailbox{
		BinPath: absolute, RootDir: root, DataDir: dataDir,
		ConfigPath: filepath.Join(root, "EvernightMail.yaml"),
		SMTPAddr:   fmt.Sprintf("127.0.0.1:%d", smtpPort),
		POP3Addr:   fmt.Sprintf("127.0.0.1:%d", pop3Port),
		HTTPAddr:   fmt.Sprintf("127.0.0.1:%d", httpPort),
		AdminUser:  "prc-admin",
		done:       make(chan struct{}),
		stdout:     newTailBuffer(16 << 10),
		stderr:     newTailBuffer(16 << 10),
	}
	password, err := randomToken(18)
	if err != nil {
		return nil, err
	}
	instance.adminPassword = "prc-" + password
	config := renderMailConfig(instance)
	if err := os.MkdirAll(root, 0o750); err != nil {
		return nil, err
	}
	if err := os.WriteFile(instance.ConfigPath, []byte(config), 0o600); err != nil {
		return nil, err
	}
	command := exec.Command(absolute, "serve", "--config", instance.ConfigPath)
	command.Dir = root
	command.Env = sanitizedMailEnv()
	command.Stdout = instance.stdout
	command.Stderr = instance.stderr
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("启动 EvernightMail 失败: %w", err)
	}
	instance.cmd = command
	go func() {
		_ = command.Wait()
		close(instance.done)
	}()
	if err := instance.waitReady(); err != nil {
		tail := strings.TrimSpace(instance.stderr.String())
		if tail == "" {
			tail = strings.TrimSpace(instance.stdout.String())
		}
		tail = strings.ReplaceAll(tail, instance.adminPassword, "******")
		_ = instance.Close()
		return nil, fmt.Errorf("EvernightMail 未在期限内就绪: %w（stderr 尾部: %s）",
			err, truncateText(tail, 1200))
	}
	return instance, nil
}

// renderMailConfig 生成自包含临时 YAML（同 mailtest 口径：SMTP 匿名、本机捕获、
// admin required、POP3/HTTP 回环、Web 关闭、故障注入关闭）。
func renderMailConfig(instance *mailbox) string {
	dataDir := filepath.ToSlash(instance.DataDir)
	userID := "usr_22222222222222222222222222222222"
	userLogin := "prc-tester"
	userPassword := "prc-mail-pass"
	return fmt.Sprintf(`version: 1
server:
  hostname: mailtest.local
  data_dir: '%s'
  log_dir: '%s/logs'
  shutdown_timeout: 5s
  single_instance_lock: false
listeners:
  - id: smtp-main
    protocol: smtp
    address: %s
    tls: disabled
    enabled: true
  - id: pop3-main
    protocol: pop3
    address: %s
    tls: disabled
    enabled: true
  - id: admin
    protocol: http
    address: %s
    tls: disabled
    enabled: true
tls:
  mode: auto
  identities:
    - id: local-test
      mode: auto
      sans:
        dns: [localhost, mailtest.local]
        ip: [127.0.0.1]
      validity: 24h
  ca:
    dir: '%s/certs'
    validity: 24h
storage:
  mail_root: '%s/mail'
  timezone: UTC
  fsync: false
  repair_on_start: true
  max_path_bytes: 320
  index_dir: '%s/index'
logging:
  level: info
  console_format: text
  file_format: jsonl
  server_log: '%s/logs/server.log'
  max_line_bytes: 8192
  max_field_bytes: 2048
  sync_every_write: false
  redact_fields: [password, pass, token, authorization, cookie, secret, private_key, pfx_password]
  protocol_trace: false
admin:
  username: %s
  password: %s
  mode: required
  anonymous:
    allow: false
    allow_non_loopback: false
  session:
    cookie_name: em_admin
    absolute_ttl: 12h
    idle_ttl: 2h
    max_sessions: 16
    secure: never
    same_site: lax
  csrf:
    required: true
  login_rate_limit:
    window: 1m
    max_attempts: 100
users:
  defaults:
    auth:
      smtp: none
      imap: required
      pop3: required
  items:
    - id: %s
      login_name: %s
      display_name: password-reset consumer tester
      password: %s
      enabled: true
      auth:
        smtp: none
        imap: required
        pop3: required
protocols:
  smtp:
    allow_anonymous_mail: true
    max_message_bytes: 1048576
    max_recipients: 20
    max_connections: 20
  pop3:
    max_connections: 20
  imap:
    max_connections: 20
delivery:
  unknown_recipient: capture
  capture_user: %s
  local_domains: [example.com, example.test, test.local, login.test]
faults:
  enabled: false
web:
  enabled: false
`, dataDir, dataDir, instance.SMTPAddr, instance.POP3Addr, instance.HTTPAddr,
		dataDir, dataDir, dataDir, dataDir, instance.AdminUser, instance.adminPassword,
		userID, userLogin, userPassword, userLogin)
}

// waitReady 等待 HTTP /healthz 与 SMTP 欢迎 banner 就绪。
func (m *mailbox) waitReady() error {
	deadline := time.Now().Add(mailReadyTimeout)
	for time.Now().Before(deadline) {
		select {
		case <-m.done:
			return errors.New("子进程已退出")
		default:
		}
		if httpHealthy(m.HTTPAddr) && smtpBannerOK(m.SMTPAddr) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("等待就绪超时")
}

// httpHealthy 检查回环 /healthz。
func httpHealthy(addr string) bool {
	client := &http.Client{Timeout: time.Second}
	response, err := client.Get("http://" + addr + "/healthz")
	if err != nil {
		return false
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
	return response.StatusCode == http.StatusOK
}

// smtpBannerOK 读取 SMTP 欢迎 banner。
func smtpBannerOK(addr string) bool {
	connection, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err != nil {
		return false
	}
	defer func() { _ = connection.Close() }()
	_ = connection.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buffer := make([]byte, 256)
	n, err := connection.Read(buffer)
	if err != nil {
		return false
	}
	return strings.HasPrefix(string(buffer[:n]), "220")
}

// Close 有界终止本次创建的 Mail 进程树并等待端口释放；可重复调用。
func (m *mailbox) Close() error {
	m.closeOnce.Do(func() {
		if m.cmd == nil || m.cmd.Process == nil {
			return
		}
		pid := m.cmd.Process.Pid
		if runtime.GOOS == "windows" {
			_ = exec.Command("taskkill", "/T", "/F", "/PID", fmt.Sprint(pid)).Run()
		} else {
			_ = m.cmd.Process.Signal(os.Interrupt)
			select {
			case <-m.done:
			case <-time.After(mailStopTimeout / 2):
				_ = m.cmd.Process.Kill()
			}
		}
		select {
		case <-m.done:
		case <-time.After(mailStopTimeout):
			m.closeErr = fmt.Errorf("EvernightMail 子进程未在关闭期限内退出（pid=%d）", pid)
		}
		if err := waitTCPPortsReleased([]string{m.SMTPAddr, m.POP3Addr, m.HTTPAddr}, 3*time.Second); err != nil {
			m.closeErr = err
		}
	})
	return m.closeErr
}

// waitTCPPortsReleased 等待回环端口可重新绑定。
func waitTCPPortsReleased(addrs []string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for _, addr := range addrs {
		for {
			listener, err := net.Listen("tcp", addr)
			if err == nil {
				_ = listener.Close()
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("端口未释放: %s (%v)", addr, err)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	return nil
}

// freeLoopbackPort 探测回环随机空闲端口并立即关闭。
func freeLoopbackPort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = listener.Close() }()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

// decodeMailContent 解码已提交 .eml 的正文：处理 base64、quoted-printable 与
// multipart/*（递归解码各部件并拼接文本），使一次性链接可从真实邮件正文提取。
// EvernightMail 默认以 base64 传输编码写出纯文本模板；不解析会得到无链接的密文。
func decodeMailContent(raw []byte) []byte {
	header, body, ok := splitMailParts(raw)
	if !ok {
		return raw
	}
	mediaType, params, _ := mime.ParseMediaType(headerValue(header, "Content-Type"))
	if strings.HasPrefix(strings.ToLower(mediaType), "multipart/") && params["boundary"] != "" {
		var combined bytes.Buffer
		for _, part := range splitMultipart(body, params["boundary"]) {
			decoded := decodeMailContent(part)
			if len(decoded) == 0 {
				continue
			}
			combined.Write(decoded)
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

// splitMailParts 以首个空行切分头部与正文（兼容 CRLF 与 LF）。
func splitMailParts(raw []byte) ([]byte, []byte, bool) {
	if index := bytes.Index(raw, []byte("\r\n\r\n")); index >= 0 {
		return raw[:index], raw[index+4:], true
	}
	if index := bytes.Index(raw, []byte("\n\n")); index >= 0 {
		return raw[:index], raw[index+2:], true
	}
	return nil, raw, false
}

// headerValue 读取头部字段值（大小写不敏感，取首个出现）。
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

// splitMultipart 按 boundary 切分 multipart 正文（忽略前导与结束标记）。
func splitMultipart(body []byte, boundary string) [][]byte {
	delimiter := []byte("--" + boundary)
	parts := make([][]byte, 0, 2)
	segments := bytes.Split(body, delimiter)
	for _, segment := range segments {
		segment = bytes.TrimPrefix(segment, []byte("\r\n"))
		segment = bytes.TrimPrefix(segment, []byte("\n"))
		if bytes.HasPrefix(segment, []byte("--")) || len(bytes.TrimSpace(segment)) == 0 {
			continue
		}
		parts = append(parts, segment)
	}
	return parts
}

// mailFileMeta 是 Mail 已提交邮件 JSON 元数据的最小读取结构。
type mailFileMeta struct {
	MailID       string    `json:"mail_id"`
	UserKey      string    `json:"user_key"`
	Subject      string    `json:"subject"`
	EnvelopeTo   []string  `json:"envelope_to"`
	To           []string  `json:"to"`
	Size         int64     `json:"size"`
	SHA256       string    `json:"sha256"`
	ReceivedAt   time.Time `json:"received_at"`
	OriginMailID string    `json:"origin_mail_id"`
}

// messages 读取 Mail 数据目录中所有已提交邮件（按接收时间升序、校验摘要）。
func (m *mailbox) messages() ([]mailMessage, error) {
	mailRoot := filepath.Join(m.DataDir, "mail")
	messages := make([]mailMessage, 0)
	walkErr := filepath.WalkDir(mailRoot, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			return nil
		}
		rawMetadata, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		var meta mailFileMeta
		if json.Unmarshal(rawMetadata, &meta) != nil || meta.MailID == "" {
			return nil
		}
		emlPath := strings.TrimSuffix(path, ".json") + ".eml"
		raw, emlErr := os.ReadFile(emlPath)
		if emlErr != nil {
			return nil
		}
		if int64(len(raw)) != meta.Size {
			return fmt.Errorf("邮件提交大小不一致（%s）", meta.MailID)
		}
		sum := sha256.Sum256(raw)
		if !strings.EqualFold(hex.EncodeToString(sum[:]), meta.SHA256) {
			return fmt.Errorf("邮件提交摘要不一致（%s）", meta.MailID)
		}
		messages = append(messages, mailMessage{
			ID: meta.MailID, ReceivedAt: meta.ReceivedAt,
			To:      append(append([]string{}, meta.EnvelopeTo...), meta.To...),
			Subject: meta.Subject, Body: decodeMailContent(raw),
		})
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, os.ErrNotExist) {
		return nil, walkErr
	}
	sort.SliceStable(messages, func(left, right int) bool {
		return messages[left].ReceivedAt.Before(messages[right].ReceivedAt)
	})
	return messages, nil
}

// waitForMessages 等待满足条件的邮件出现（有界）；条件为 nil 时等待任意一封。
func (m *mailbox) waitForMessages(ctx context.Context, timeout time.Duration,
	match func(mailMessage) bool) ([]mailMessage, error) {
	deadline := time.Now().Add(timeout)
	interval := 150 * time.Millisecond
	for {
		messages, err := m.messages()
		if err == nil {
			matched := make([]mailMessage, 0, len(messages))
			for _, message := range messages {
				if match == nil || match(message) {
					matched = append(matched, message)
				}
			}
			if len(matched) > 0 {
				return matched, nil
			}
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("等待邮件超时（最后错误: %v）", err)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
	}
}

// mailLinkPattern 匹配邮件正文中的 http(s) 链接。
var mailLinkPattern = regexp.MustCompile(`https?://[^\s"'<>]+`)

// linksContaining 从邮件正文提取包含指定路径片段的链接（去重、按出现顺序）。
func mailMessageLinks(message mailMessage) []string {
	matches := mailLinkPattern.FindAllString(string(message.Body), -1)
	links := make([]string, 0, len(matches))
	seen := map[string]bool{}
	for _, link := range matches {
		link = strings.TrimRight(link, ".,;)")
		if seen[link] {
			continue
		}
		seen[link] = true
		links = append(links, link)
	}
	return links
}

// findLink 在邮件中查找包含 pathFragment 的首个链接。
func findLink(messages []mailMessage, pathFragment string) (string, bool) {
	for _, message := range messages {
		for _, link := range mailMessageLinks(message) {
			if strings.Contains(link, pathFragment) {
				return link, true
			}
		}
	}
	return "", false
}

// randomToken 生成高熵随机十六进制串（合成秘密，不打印）。
func randomToken(bytesCount int) (string, error) {
	buffer := make([]byte, bytesCount)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}

// sanitizedMailEnv 过滤可能指向个人 Mail 配置/二进制/账号的环境变量。
func sanitizedMailEnv() []string {
	env := os.Environ()
	filtered := make([]string, 0, len(env))
	for _, entry := range env {
		name := strings.ToUpper(strings.SplitN(entry, "=", 2)[0])
		if strings.HasPrefix(name, "EVERNIGHTMAIL_") || name == "EVERNIGHTMAIL_CONFIG" {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

// truncateText 截断过长输出用于错误信息。
func truncateText(text string, limit int) string {
	if len(text) <= limit || limit <= 0 {
		if limit <= 0 {
			return ""
		}
		return text
	}
	cut := limit
	for cut > 0 && (text[cut]&0xC0) == 0x80 {
		cut--
	}
	return text[:cut] + "..."
}

// tailBuffer 是保留尾部有限字节的并发安全 writer（用于子进程输出证据）。
type tailBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
	limit  int
}

func newTailBuffer(limit int) *tailBuffer { return &tailBuffer{limit: limit} }

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buffer.Write(p)
	if t.buffer.Len() > t.limit {
		_ = t.buffer.Next(t.buffer.Len() - t.limit)
	}
	return len(p), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.buffer.String()
}

// countMessagesForRecipient 有界等待异步投递队列静默后，统计收件人精确匹配的
// 邮件数量。判定防枚举时不能比较“申请前后全局邮件总数”（前序场景的异步邮件可能
// 落入采样窗口造成假失败）；这里按目标地址精确过滤，并轮询到计数稳定
// quietFor 才返回，仍有总超时上限（超时返回当前计数，由调用方断言）。
func (m *mailbox) countMessagesForRecipient(ctx context.Context, recipient,
	pathFragment string, quietFor, timeout time.Duration) int {
	deadline := time.Now().Add(timeout)
	lastCount := -1
	stableSince := time.Time{}
	for {
		count := 0
		messages, err := m.messages()
		if err == nil {
			for _, message := range messages {
				if !containsAddressFold(message.To, recipient) {
					continue
				}
				if pathFragment != "" {
					if _, found := findLink([]mailMessage{message}, pathFragment); !found {
						continue
					}
				}
				count++
			}
		}
		now := time.Now()
		if err == nil && count == lastCount {
			if stableSince.IsZero() {
				stableSince = now
			} else if now.Sub(stableSince) >= quietFor {
				return count
			}
		} else {
			lastCount = count
			stableSince = time.Time{}
		}
		if now.After(deadline) {
			return count
		}
		select {
		case <-ctx.Done():
			return count
		case <-time.After(150 * time.Millisecond):
		}
	}
}
