// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightMail is licensed under Mulan PSL v2.

// Package mailtest 是父项目 EvernightLogin 的测试专用夹具：以独立子进程启动已验
// 收的 EvernightMail（子模块），通过公开 CLI/HTTP/协议与之交互，不导入 Mail 任何
// internal 包，也不成为生产身份服务的运行时依赖。
//
// 边界与安全：
//   - 仅测试代码可导入本包（见 import_guard_test.go）；生产导入会被测试拒绝。
//   - 只使用临时目录、随机回环端口、合成账号与临时测试 CA；不读取个人配置/邮箱，
//     不安装系统信任库，不发起公网请求。
//   - 子进程失败、超时、取消、端口冲突、启动失败均走统一清理：有界等待 → Windows
//     按 PID 杀进程树（不按名称）→ 等待端口释放；临时目录由 testutil.TempDir 清理。
package mailtest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
)

const (
	// DefaultReadyTimeout 是等待进程/协议就绪的总期限。
	DefaultReadyTimeout = 15 * time.Second
	// DefaultStopTimeout 是关闭子进程的有界等待期限。
	DefaultStopTimeout = 8 * time.Second
	// defaultPortAttempts 是端口冲突时的重试次数（使用固定端口时不重试）。
	defaultPortAttempts = 3
	// testUserID 是夹具合成用户稳定 ID（usr_ + 32 hex）。
	testUserID = "usr_11111111111111111111111111111111"
	// testLogin 是合成用户登录名。
	testLogin = "tester"
	// testUserPassword 是合成用户明文密码（仅临时配置）。
	testUserPassword = "mailtest-pass"
	// adminUsername 是临时管理员用户名。
	adminUsername = "mailtest-admin"
)

// Options 是夹具启动参数。零值使用 SMTP+POP3+HTTP、非 TLS、临时随机端口。
type Options struct {
	// BinPath 显式指定 evernightmail 二进制；空时按 EVERNIGHTMAIL_BIN → 从子模块构建。
	BinPath string
	// Required 为 true 时缺二进制/构建失败直接失败；false 时跳过测试（默认 false）。
	Required bool
	// SMTP/POP3/HTTP 控制启用协议（全零时默认三者均启用）。
	SMTP, POP3, HTTP bool
	// IMAP 为 true 时额外启用 IMAP 监听（Mail 装配缺失时启动失败，由测试显式判定）。
	IMAP bool
	// TLS 为 true 时为 SMTP 启用 STARTTLS 并生成/使用临时测试 CA（POP3 保持明文）。
	TLS bool
	// SMTPAuthNone 为 true 时 SMTP 允许匿名投递（仅测试回环；迁移旧测试用）。
	SMTPAuthNone bool
	// LocalDomains 是额外捕获域；空时使用 defaultCaptureDomains。
	LocalDomains []string
	// ReadyTimeout/StopTimeout 覆盖默认有界期限。
	ReadyTimeout, StopTimeout time.Duration
	// Context 可选：启动/就绪期间取消；取消后返回错误并清理。
	Context context.Context
	// ExtraYAML 追加到生成配置末尾（负向测试用；正常测试应留空）。
	ExtraYAML string
	// FaultsYAML 替换默认 "faults:\n  enabled: false" 段（步骤 197 真实故障注入测试）；
	// 需包含 enabled 与 rules，缩进与 Mail 配置一致。空时保持默认关闭。
	FaultsYAML string
	// ForcePorts 固定端口（负向测试/端口冲突测试用；非零时只尝试一次）。
	ForcePorts struct{ SMTP, POP3, HTTP int }
}

// Instance 是运行中的 Mail 子进程与交互句柄。
type Instance struct {
	DataDir       string
	ConfigPath    string
	CAFile        string
	HTTPAddr      string
	SMTPAddr      string
	POP3Addr      string
	IMAPAddr      string
	AdminUser     string
	AdminPassword string
	UserID        string
	UserLogin     string
	UserPassword  string

	httpBase string
	client   *http.Client
	csrf     string

	cmd       *exec.Cmd
	done      chan struct{}
	stdout    *tailBuffer
	stderr    *tailBuffer
	closeOnce sync.Once
	closeErr  error
	options   Options
	started   bool
}

// Start 启动一个 Mail 实例并注册 t.Cleanup；失败时按 Options.Required 处理。
func Start(t testing.TB, opts Options) *Instance {
	t.Helper()
	instance, err := startInstance(t, opts)
	if err != nil {
		if opts.Required {
			t.Fatalf("启动 EvernightMail 测试实例失败: %v", err)
		}
		t.Skipf("跳过依赖 EvernightMail 的测试: %v", err)
	}
	return instance
}

// startInstance 启动并等待就绪；返回错误供负向测试使用。
func startInstance(t testing.TB, opts Options) (*Instance, error) {
	if !opts.SMTP && !opts.POP3 && !opts.HTTP && !opts.IMAP {
		opts.SMTP, opts.POP3, opts.HTTP = true, true, true
	}
	if opts.ReadyTimeout <= 0 {
		opts.ReadyTimeout = DefaultReadyTimeout
	}
	if opts.StopTimeout <= 0 {
		opts.StopTimeout = DefaultStopTimeout
	}
	if len(opts.LocalDomains) == 0 {
		opts.LocalDomains = []string{"example.com", "example.test", "test.local", "login.test"}
	}
	bin, err := resolveBinary(t, opts)
	if err != nil {
		return nil, err
	}
	var lastErr error
	attempts := defaultPortAttempts
	if opts.ForcePorts.SMTP != 0 || opts.ForcePorts.POP3 != 0 || opts.ForcePorts.HTTP != 0 {
		attempts = 1
	}
	if opts.ExtraYAML != "" {
		attempts = 1
	}
	if opts.Context != nil && opts.Context.Err() != nil {
		return nil, opts.Context.Err()
	}
	for attempt := 0; attempt < attempts; attempt++ {
		instance, attemptErr := startOnce(t, opts, bin)
		if attemptErr == nil {
			return instance, nil
		}
		lastErr = attemptErr
	}
	return nil, lastErr
}

// startOnce 是一次完整启动尝试（端口/配置/进程/就绪）。
func startOnce(t testing.TB, opts Options, bin string) (*Instance, error) {
	root := testutil.TempDir(t)
	dataDir := filepath.Join(root, "data")
	configPath := filepath.Join(root, "EvernightMail.yaml")
	instance := &Instance{
		DataDir: dataDir, ConfigPath: configPath,
		AdminUser: adminUsername, UserID: testUserID, UserLogin: testLogin, UserPassword: testUserPassword,
		options: opts, done: make(chan struct{}),
		stdout: newTailBuffer(16 << 10), stderr: newTailBuffer(16 << 10),
	}
	ports, err := choosePorts(opts)
	if err != nil {
		return nil, err
	}
	instance.SMTPAddr = addrPort(ports.smtp)
	instance.POP3Addr = addrPort(ports.pop3)
	instance.HTTPAddr = addrPort(ports.http)
	if opts.IMAP {
		imapPort, portErr := freePort()
		if portErr != nil {
			return nil, portErr
		}
		instance.IMAPAddr = addrPort(imapPort)
	}
	password, err := randomPassword()
	if err != nil {
		return nil, err
	}
	instance.AdminPassword = password
	instance.CAFile = filepath.Join(dataDir, "certs", "ca.crt")
	config, err := renderConfig(instance, opts)
	if err != nil {
		return nil, err
	}
	if opts.ExtraYAML != "" {
		config += "\n" + opts.ExtraYAML + "\n"
	}
	if err := os.MkdirAll(filepath.Dir(configPath), 0o750); err != nil {
		return nil, err
	}
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		return nil, err
	}
	command := exec.Command(bin, "serve", "--config", configPath)
	command.Dir = root
	command.Env = sanitizedEnv()
	command.Stdout = instance.stdout
	command.Stderr = instance.stderr
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("启动 evernightmail 失败（%s）: %w", bin, err)
	}
	instance.cmd = command
	instance.started = true
	t.Cleanup(func() { _ = instance.Close() })
	go func() {
		_ = command.Wait()
		close(instance.done)
	}()
	readyErr := instance.waitReady(opts.Context, opts.ReadyTimeout, opts.TLS)
	if readyErr != nil {
		tail := strings.TrimSpace(instance.stderr.String())
		if tail == "" {
			tail = strings.TrimSpace(instance.stdout.String())
		}
		tail = sanitizeOutput(tail, password)
		_ = instance.Close()
		return nil, fmt.Errorf("EvernightMail 未在期限内就绪: %w（二进制 %s，stderr 尾部: %s）", readyErr, bin, truncateText(tail, 1200))
	}
	client, err := instance.login()
	if err != nil {
		_ = instance.Close()
		return nil, err
	}
	instance.client = client
	return instance, nil
}

// login 登录临时管理员并保存 Cookie 会话与 CSRF。
func (i *Instance) login() (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	body := fmt.Sprintf(`{"username":%q,"password":%q}`, i.AdminUser, i.AdminPassword)
	request, err := http.NewRequest(http.MethodPost, "http://"+i.HTTPAddr+"/api/v1/admin/login", strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("管理员登录请求失败: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	payload, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("管理员登录失败: HTTP %d: %s", response.StatusCode, truncateText(string(payload), 400))
	}
	var envelope struct {
		Data struct {
			CSRFToken string `json:"csrf_token"`
		} `json:"data"`
		Error any `json:"error"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return nil, fmt.Errorf("管理员登录响应无法解析: %w", err)
	}
	if envelope.Data.CSRFToken == "" {
		return nil, fmt.Errorf("管理员登录响应缺少 csrf_token")
	}
	i.csrf = envelope.Data.CSRFToken
	return client, nil
}

// waitReady 等待 HTTP /healthz 与协议 banner（不要求 ready=true）。
func (i *Instance) waitReady(ctx context.Context, timeout time.Duration, tlsEnabled bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	deadline := time.Now().Add(timeout)
	interval := 100 * time.Millisecond
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if time.Now().After(deadline) {
			return errors.New("等待就绪超时")
		}
		if i.processExited() {
			return errors.New("子进程已退出")
		}
		httpOK := false
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+i.HTTPAddr+"/healthz", nil)
		response, err := http.DefaultClient.Do(request)
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
			_ = response.Body.Close()
			httpOK = response.StatusCode == http.StatusOK
		}
		if httpOK {
			smtpOK := true
			if i.options.SMTP {
				smtpOK = bannerOK(i.SMTPAddr, "220")
			}
			pop3OK := true
			if i.options.POP3 {
				pop3OK = bannerOK(i.POP3Addr, "+OK")
			}
			imapOK := true
			if i.options.IMAP {
				imapOK = bannerOK(i.IMAPAddr, "* OK")
			}
			if smtpOK && pop3OK && imapOK {
				if tlsEnabled {
					if _, err := os.Stat(i.CAFile); err != nil {
						time.Sleep(interval)
						continue
					}
				}
				return nil
			}
		}
		time.Sleep(interval)
	}
}

// processExited 报告子进程是否已退出。
func (i *Instance) processExited() bool {
	select {
	case <-i.done:
		return true
	default:
		return false
	}
}

// Close 有界关闭子进程并等待退出/端口释放；可重复调用。
func (i *Instance) Close() error {
	i.closeOnce.Do(func() {
		if i.cmd == nil || i.cmd.Process == nil {
			i.closeErr = nil
			return
		}
		pid := i.cmd.Process.Pid
		// Windows 上 os.Interrupt 不可靠，直接按 PID 终止本次启动的进程树；
		// 其他平台先发 SIGTERM，失败再有界强杀。
		if runtime.GOOS == "windows" {
			_ = exec.Command("taskkill", "/T", "/F", "/PID", fmt.Sprint(pid)).Run()
		} else {
			_ = i.cmd.Process.Signal(os.Interrupt)
			grace := i.options.StopTimeout / 2
			if grace <= 0 {
				grace = time.Second
			}
			if !waitDone(i.done, grace) {
				_ = i.cmd.Process.Kill()
			}
		}
		if !waitDone(i.done, i.options.StopTimeout) {
			i.closeErr = fmt.Errorf("子进程在关闭期限内未退出（pid=%d）", pid)
		}
		if err := waitPortsReleased([]string{i.SMTPAddr, i.POP3Addr, i.HTTPAddr}, 3*time.Second); err != nil {
			i.closeErr = err
		}
	})
	return i.closeErr
}

// waitDone 有界等待 done 关闭。
func waitDone(done <-chan struct{}, timeout time.Duration) bool {
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// waitPortsReleased 等待给定回环端口可重新绑定。
func waitPortsReleased(addrs []string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for _, addr := range addrs {
		if addr == "" {
			continue
		}
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

// bannerOK 读取协议 banner 前缀。
func bannerOK(addr, prefix string) bool {
	conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buffer := make([]byte, 256)
	n, err := conn.Read(buffer)
	if err != nil {
		return false
	}
	return strings.HasPrefix(string(buffer[:n]), prefix)
}

// addrPort 构造回环地址。
func addrPort(port int) string { return fmt.Sprintf("127.0.0.1:%d", port) }

// choosePorts 选择随机可用端口；ForcePorts 非零时使用指定值。
func choosePorts(opts Options) (struct{ smtp, pop3, http int }, error) {
	var ports struct{ smtp, pop3, http int }
	if opts.ForcePorts.SMTP != 0 {
		ports.smtp = opts.ForcePorts.SMTP
	} else {
		port, err := freePort()
		if err != nil {
			return ports, err
		}
		ports.smtp = port
	}
	if opts.ForcePorts.POP3 != 0 {
		ports.pop3 = opts.ForcePorts.POP3
	} else {
		port, err := freePort()
		if err != nil {
			return ports, err
		}
		ports.pop3 = port
	}
	if opts.ForcePorts.HTTP != 0 {
		ports.http = opts.ForcePorts.HTTP
	} else {
		port, err := freePort()
		if err != nil {
			return ports, err
		}
		ports.http = port
	}
	return ports, nil
}

// freePort 探测回环随机空闲端口并立即关闭。
func freePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = listener.Close() }()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

// renderConfig 生成自包含临时 YAML（不读取个人配置）。
func renderConfig(instance *Instance, opts Options) (string, error) {
	dataDir := filepath.ToSlash(instance.DataDir)
	smtpTLS := "disabled"
	smtpCert := ""
	if opts.TLS {
		smtpTLS = "starttls"
		smtpCert = "\n    cert: local-test"
	}
	smtpAuth := "required"
	anonymousMail := "false"
	if opts.SMTPAuthNone {
		smtpAuth = "none"
		anonymousMail = "true"
	}
	var listeners strings.Builder
	if opts.SMTP {
		fmt.Fprintf(&listeners, "  - id: smtp-main\n    protocol: smtp\n    address: %s\n    tls: %s%s\n    enabled: true\n", instance.SMTPAddr, smtpTLS, smtpCert)
	}
	if opts.POP3 {
		fmt.Fprintf(&listeners, "  - id: pop3-main\n    protocol: pop3\n    address: %s\n    tls: disabled\n    enabled: true\n", instance.POP3Addr)
	}
	if opts.IMAP {
		fmt.Fprintf(&listeners, "  - id: imap-main\n    protocol: imap\n    address: %s\n    tls: implicit\n    cert: local-test\n    enabled: true\n", instance.IMAPAddr)
	}
	fmt.Fprintf(&listeners, "  - id: admin\n    protocol: http\n    address: %s\n    tls: disabled\n    enabled: true\n", instance.HTTPAddr)
	localDomains := make([]string, 0, len(opts.LocalDomains))
	for _, domain := range opts.LocalDomains {
		localDomains = append(localDomains, domain)
	}
	yaml := fmt.Sprintf(`version: 1
server:
  hostname: mailtest.local
  data_dir: '%s'
  log_dir: '%s/logs'
  shutdown_timeout: 5s
  single_instance_lock: false
listeners:
%s
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
    export_path: '%s/certs/ca.crt'
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
      smtp: %s
      imap: required
      pop3: required
  items:
    - id: %s
      login_name: %s
      display_name: mailtest tester
      password: %s
      enabled: true
      auth:
        smtp: %s
        imap: required
        pop3: required
protocols:
  smtp:
    allow_anonymous_mail: %s
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
  local_domains: [%s]
faults:
  enabled: false
web:
  enabled: false
`, dataDir, dataDir, listeners.String(), dataDir, dataDir, dataDir, dataDir, dataDir,
		adminUsername, instance.AdminPassword, smtpAuth,
		instance.UserID, instance.UserLogin, instance.UserPassword, smtpAuth, anonymousMail,
		instance.UserLogin, strings.Join(localDomains, ", "))
	if opts.FaultsYAML != "" {
		yaml = strings.Replace(yaml, "faults:\n  enabled: false",
			"faults:\n"+strings.TrimRight(opts.FaultsYAML, "\n"), 1)
	}
	return yaml, nil
}

// sanitizedEnv 过滤可能指向个人 Mail 配置/二进制/账号的环境变量。
func sanitizedEnv() []string {
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

// randomPassword 生成测试管理员密码（不写日志/报告）。
func randomPassword() (string, error) {
	buffer := make([]byte, 18)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return "mt-" + hex.EncodeToString(buffer), nil
}

// sanitizeOutput 用 "******" 替换管理员密码，避免失败信息泄露临时秘密。
func sanitizeOutput(text, password string) string {
	if password == "" {
		return text
	}
	return strings.ReplaceAll(text, password, "******")
}

// truncateText 截断长文本用于错误信息。
func truncateText(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	if limit <= 0 {
		return ""
	}
	return text[:limit] + "…"
}

// tailBuffer 是保留尾部有限字节的并发安全 writer。
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
		overflow := t.buffer.Len() - t.limit
		_ = t.buffer.Next(overflow)
	}
	return len(p), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.buffer.String()
}
