package serverapp_test

// 本文件是 login-server 宿主装配 MVP 的真实集成测试：临时目录 + 真实 SQLite +
// 真实领域服务 + 真实监听（回环临时端口，不占用固定端口）+ 真实 HTTP 客户端。
// 覆盖：首次初始化、重复初始化拒绝、未迁移库拒绝启动、serve 健康/OpenAPI/登录页
// 200 与未知路径 404、维护状态只放行健康检查、有界优雅关闭、配置错误 fail-closed、
// TLS 配置校验、初始化不落明文秘密。
//
// 所有用例使用 t.TempDir()，结束时关闭服务、取消上下文并等待退出；不读写仓库的
// database/login.db，不真实外发邮件/Webhook，不遗留监听端口与后台协程。

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/bootstrap"
	bootstrapsqlite "github.com/kagurazakayashi/EvernightLogin/internal/bootstrap/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/maintenance"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/serverapp"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

const initTestPassword = "V7#qZ!mR2@tL9$xP-Init"

// safeBuffer 是并发安全的缓冲区（运行日志与访问日志可能来自多个请求协程）。
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// freeListenAddr 返回一个当前空闲的回环端口地址（配置本身拒绝端口 0，测试沿用
// 仓库既有做法：先由系统分配临时端口再交给服务，不占用固定端口）。
func freeListenAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("探测空闲端口失败: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("释放探测端口失败: %v", err)
	}
	return address
}

// testPaths 汇总一个隔离部署目录结构。
type testPaths struct {
	root      string
	config    string
	database  string
	masterKey string
}

// preparePaths 创建临时部署目录并写入最小配置。
func preparePaths(t *testing.T, yamlMutate func(config string) string) testPaths {
	t.Helper()
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatalf("创建数据目录失败: %v", err)
	}
	paths := testPaths{
		root:      root,
		config:    filepath.Join(root, "config", "login.yaml"),
		database:  filepath.Join(dataDir, "login.db"),
		masterKey: filepath.Join(root, "secrets", "master.key"),
	}
	if err := os.MkdirAll(filepath.Dir(paths.config), 0o700); err != nil {
		t.Fatalf("创建配置目录失败: %v", err)
	}
	listenAddr := freeListenAddr(t)
	config := fmt.Sprintf(`server:
  listen_addr: "%s"
  shutdown_timeout_seconds: 5
logging:
  level: error
  format: text
database:
  driver: sqlite
  path: "%s"
  wal: true
  busy_timeout_ms: 5000
`, listenAddr, filepath.ToSlash(paths.database))
	if yamlMutate != nil {
		config = yamlMutate(config)
	}
	if err := os.WriteFile(paths.config, []byte(config), 0o600); err != nil {
		t.Fatalf("写入配置文件失败: %v", err)
	}
	return paths
}

// writeMasterKey 生成受保护测试主密钥环文件（不打印任何密钥材料）。
func writeMasterKey(t *testing.T, path string) {
	t.Helper()
	ring, err := secrets.GenerateKeyring("k1", time.Now().UTC())
	if err != nil {
		t.Fatalf("生成测试密钥环失败: %v", err)
	}
	document, err := ring.Document()
	if err != nil {
		t.Fatalf("序列化测试密钥环失败: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("创建测试密钥目录失败: %v", err)
	}
	if err := secrets.WriteProtectedFile(path, document); err != nil {
		t.Fatalf("写入测试受保护密钥文件失败: %v", err)
	}
}

// runInit 执行首次初始化并返回标准输出。
func runInit(t *testing.T, paths testPaths) (string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	err := serverapp.RunInit(context.Background(), serverapp.InitOptions{
		ConfigPath:     paths.config,
		MasterKeyFile:  paths.masterKey,
		OperatorID:     "test.local-admin",
		StandardInput:  strings.NewReader(initTestPassword + "\n"),
		StandardOutput: &stdout,
		StandardError:  &stderr,
	})
	return stdout.String(), err
}

// startServe 在后台运行 serve 并等待监听就绪，返回监听地址与取消函数。
func startServe(t *testing.T, options serverapp.ServeOptions) (string, *safeBuffer, context.CancelFunc) {
	t.Helper()
	accessLog := &safeBuffer{}
	options.AccessLog = accessLog
	options.StandardOutput = io.Discard
	options.StandardError = &safeBuffer{}
	started := make(chan serverapp.StartResult, 1)
	options.OnStarted = func(result serverapp.StartResult) {
		started <- result
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serverapp.RunServe(ctx, options)
	}()
	select {
	case result := <-started:
		if len(result.Addresses) != 1 {
			cancel()
			t.Fatalf("监听地址数量异常: %v", result.Addresses)
		}
		t.Cleanup(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("serve 退出错误: %v", err)
				}
			case <-time.After(20 * time.Second):
				t.Errorf("serve 未在 20s 内退出")
			}
		})
		return result.Addresses[0], accessLog, cancel
	case err := <-done:
		cancel()
		t.Fatalf("serve 未启动即退出: %v", err)
	case <-time.After(30 * time.Second):
		cancel()
		t.Fatalf("serve 在 30s 内未完成启动")
	}
	return "", accessLog, cancel
}

// httpGet 发起一次 GET 请求。
func httpGet(t *testing.T, client *http.Client, target string) (int, string) {
	t.Helper()
	response, err := client.Get(target)
	if err != nil {
		t.Fatalf("GET %s 失败: %v", target, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		t.Fatalf("读取响应失败: %v", err)
	}
	return response.StatusCode, string(body)
}

// TestInitCreatesRootAndServeLifecycle 覆盖 init 成功创建 root、数据库不含明文
// 密码、重复 init 拒绝、serve 真实启动后 health/OpenAPI/登录页 200、未知路径 404、
// 访问日志写入与有界优雅关闭。
func TestInitCreatesRootAndServeLifecycle(t *testing.T) {
	paths := preparePaths(t, nil)
	stdout, err := runInit(t, paths)
	if err != nil {
		t.Fatalf("首次初始化失败: %v", err)
	}
	for _, expected := range []string{"root 用户 ID", "security_version", "初始化状态"} {
		if !strings.Contains(stdout, expected) {
			t.Fatalf("初始化输出缺少 %q：%s", expected, stdout)
		}
	}
	if strings.Contains(stdout, initTestPassword) {
		t.Fatal("初始化标准输出泄露了明文密码")
	}
	// 主密钥环文件存在且通过受保护文件检查。
	if err := secrets.CheckProtectedFile(paths.masterKey); err != nil {
		t.Fatalf("主密钥文件未按受保护权限写入: %v", err)
	}
	// 数据库文件不包含明文密码（密码只以 Argon2id 哈希形式落库）。
	databaseBytes, err := os.ReadFile(paths.database)
	if err != nil {
		t.Fatalf("读取数据库文件失败: %v", err)
	}
	if bytes.Contains(databaseBytes, []byte(initTestPassword)) {
		t.Fatal("数据库文件中出现明文密码")
	}
	// 初始化状态与 root 安全版本真实落库。
	ctx := context.Background()
	store, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(paths.database))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	bootstrapStore, err := bootstrapsqlite.New(store)
	if err != nil {
		t.Fatalf("构造初始化存储失败: %v", err)
	}
	record, found, err := bootstrapStore.GetInitialization(ctx)
	if err != nil || !found {
		t.Fatalf("初始化记录不存在: found=%v err=%v", found, err)
	}
	if record.State != bootstrap.StateSetupVerified {
		t.Fatalf("初始化后状态应为 setup_verified，实际 %q", record.State)
	}
	root, found, err := bootstrapStore.GetRootAccount(ctx)
	if err != nil || !found {
		t.Fatalf("root 账户不存在: found=%v err=%v", found, err)
	}
	if root.Username != bootstrap.RootUsername || root.SecurityVersion < 2 {
		t.Fatalf("root 账户不符合预期: %+v", root)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("关闭数据库失败: %v", err)
	}

	if _, secondErr := runInit(t, paths); secondErr == nil {
		t.Fatal("重复初始化未被拒绝")
	} else if !strings.Contains(secondErr.Error(), "拒绝重复初始化") {
		t.Fatalf("重复初始化错误信息不明确: %v", secondErr)
	}
	// 重复 init 必须在生成主密钥环之前失败：即使指向不存在的新密钥文件，也不能
	// 顺手生成一份新密钥（那会破坏既有部署的解密材料）。
	secondKey := filepath.Join(paths.root, "secrets", "second.key")
	var secondStdout bytes.Buffer
	secondErr := serverapp.RunInit(context.Background(), serverapp.InitOptions{
		ConfigPath:     paths.config,
		MasterKeyFile:  secondKey,
		OperatorID:     "test.local-admin",
		StandardInput:  strings.NewReader(initTestPassword + "\n"),
		StandardOutput: &secondStdout,
		StandardError:  io.Discard,
	})
	if secondErr == nil || !strings.Contains(secondErr.Error(), "拒绝重复初始化") {
		t.Fatalf("重复初始化未被明确拒绝: %v", secondErr)
	}
	if _, statErr := os.Stat(secondKey); !os.IsNotExist(statErr) {
		t.Fatalf("重复初始化不应生成新的主密钥文件: statErr=%v", statErr)
	}

	address, accessLog, _ := startServe(t, serverapp.ServeOptions{
		ConfigPath:    paths.config,
		MasterKeyFile: paths.masterKey,
	})
	client := &http.Client{Timeout: 10 * time.Second}
	baseURL := "http://" + address
	if status, body := httpGet(t, client, baseURL+"/healthz"); status != http.StatusOK ||
		!strings.Contains(body, `"ok"`) {
		t.Fatalf("healthz 异常: status=%d body=%s", status, body)
	}
	if status, body := httpGet(t, client, baseURL+"/openapi.json"); status != http.StatusOK ||
		!strings.Contains(body, "openapi") {
		t.Fatalf("openapi.json 异常: status=%d body=%.200s", status, body)
	}
	if status, body := httpGet(t, client, baseURL+"/login"); status != http.StatusOK ||
		!strings.Contains(body, "csrf_token") {
		t.Fatalf("内置登录页异常: status=%d body=%.300s", status, body)
	}
	if status, _ := httpGet(t, client, baseURL+"/no-such-page-xyz"); status != http.StatusNotFound {
		t.Fatalf("未知路径应为 404，实际 %d", status)
	}
	if logText := accessLog.String(); !strings.Contains(logText, "GET") ||
		!strings.Contains(logText, "/healthz") {
		t.Fatalf("访问日志未记录请求: %.300s", logText)
	}
}

// TestServeWritesAccessLogFile 覆盖访问日志写入受控文件：文件按受保护权限创建，
// 请求被记录且不包含 Cookie/Authorization 等敏感内容。
func TestServeWritesAccessLogFile(t *testing.T) {
	paths := preparePaths(t, nil)
	if _, err := runInit(t, paths); err != nil {
		t.Fatalf("首次初始化失败: %v", err)
	}
	logPath := filepath.Join(paths.root, "logs", "access.log")
	started := make(chan serverapp.StartResult, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serverapp.RunServe(ctx, serverapp.ServeOptions{
			ConfigPath:     paths.config,
			MasterKeyFile:  paths.masterKey,
			AccessLogPath:  logPath,
			StandardOutput: io.Discard,
			StandardError:  io.Discard,
			OnStarted: func(result serverapp.StartResult) {
				started <- result
			},
		})
	}()
	var address string
	select {
	case result := <-started:
		address = result.Addresses[0]
	case err := <-done:
		t.Fatalf("serve 未启动即退出: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatalf("serve 在 30s 内未完成启动")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	if status, _ := httpGet(t, client, "http://"+address+"/healthz"); status != http.StatusOK {
		t.Fatalf("healthz 状态异常: %d", status)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve 退出错误: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("serve 未在 20s 内退出")
	}
	if err := secrets.CheckProtectedFile(logPath); err != nil {
		t.Fatalf("访问日志文件权限不符合要求: %v", err)
	}
	logBytes, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("读取访问日志失败: %v", err)
	}
	logText := string(logBytes)
	if !strings.Contains(logText, "GET") || !strings.Contains(logText, "/healthz") {
		t.Fatalf("访问日志未记录请求: %.300s", logText)
	}
	if strings.Contains(strings.ToLower(logText), "cookie") ||
		strings.Contains(strings.ToLower(logText), "authorization") {
		t.Fatalf("访问日志出现敏感字段名: %.300s", logText)
	}
}

// TestServeRefusesUnmigratedDatabase 覆盖未迁移数据库 fail-closed：默认拒绝启动，
// 显式 --migrate=apply 时才迁移；迁移后仍未初始化的库默认也拒绝启动（仅
// --allow-uninitialized 显式放行）。
func TestServeRefusesUnmigratedDatabase(t *testing.T) {
	paths := preparePaths(t, nil)
	writeMasterKey(t, paths.masterKey)
	var stderr bytes.Buffer
	err := serverapp.RunServe(context.Background(), serverapp.ServeOptions{
		ConfigPath:     paths.config,
		MasterKeyFile:  paths.masterKey,
		StandardOutput: io.Discard,
		StandardError:  &stderr,
		OnStarted:      func(serverapp.StartResult) { t.Error("未迁移数据库不应启动监听") },
	})
	if err == nil {
		t.Fatal("未迁移数据库未被拒绝启动")
	}
	if !strings.Contains(err.Error(), "尚未完成迁移") {
		t.Fatalf("未迁移错误信息不明确: %v", err)
	}

	// 显式迁移并放行未初始化：开发/测试路径真实启动，健康检查可用。
	address, _, _ := startServe(t, serverapp.ServeOptions{
		ConfigPath:         paths.config,
		MasterKeyFile:      paths.masterKey,
		Migrate:            true,
		AllowUninitialized: true,
	})
	client := &http.Client{Timeout: 10 * time.Second}
	if status, body := httpGet(t, client, "http://"+address+"/healthz"); status != http.StatusOK ||
		!strings.Contains(body, `"ok"`) {
		t.Fatalf("--migrate=apply 启动后 healthz 异常: status=%d body=%s", status, body)
	}
	// 迁移完成且维护状态已存在，但数据库仍无 root：默认 serve 必须拒绝。
	err = serverapp.RunServe(context.Background(), serverapp.ServeOptions{
		ConfigPath:     paths.config,
		MasterKeyFile:  paths.masterKey,
		StandardOutput: io.Discard,
		StandardError:  io.Discard,
		OnStarted:      func(serverapp.StartResult) { t.Error("未初始化数据库不应启动监听") },
	})
	if err == nil || !strings.Contains(err.Error(), "首次初始化") {
		t.Fatalf("未初始化数据库未被默认拒绝: %v", err)
	}
}

// TestServeRefusesMissingMaintenanceState 覆盖安全 M1：维护状态目录被删除后重启
// 必须 fail-closed，不得自动重建 normal 状态绕过维护门禁。
func TestServeRefusesMissingMaintenanceState(t *testing.T) {
	paths := preparePaths(t, nil)
	if _, err := runInit(t, paths); err != nil {
		t.Fatalf("首次初始化失败: %v", err)
	}
	stateDir := filepath.Join(filepath.Dir(filepath.Dir(paths.database)),
		filepath.Base(filepath.Dir(paths.database))+"-maintenance")
	if err := os.RemoveAll(stateDir); err != nil {
		t.Fatalf("删除维护状态目录失败: %v", err)
	}
	started := false
	err := serverapp.RunServe(context.Background(), serverapp.ServeOptions{
		ConfigPath:     paths.config,
		MasterKeyFile:  paths.masterKey,
		StandardOutput: io.Discard,
		StandardError:  io.Discard,
		OnStarted:      func(serverapp.StartResult) { started = true },
	})
	if err == nil || !strings.Contains(err.Error(), "维护状态缺失") {
		t.Fatalf("维护状态缺失未被拒绝启动: %v", err)
	}
	if started {
		t.Fatal("维护状态缺失时不应启动监听")
	}
	if _, statErr := os.Stat(stateDir); !os.IsNotExist(statErr) {
		t.Fatalf("拒绝启动后不应自行重建维护状态目录: statErr=%v", statErr)
	}
}

// TestMaintenanceModeServesOnlyHealth 覆盖维护状态门禁：启动时处于维护状态只
// 提供健康检查与维护提示（503），不放行任何业务页面。
func TestMaintenanceModeServesOnlyHealth(t *testing.T) {
	paths := preparePaths(t, nil)
	if _, err := runInit(t, paths); err != nil {
		t.Fatalf("首次初始化失败: %v", err)
	}
	// 用与 serve 相同的默认状态目录显式进入维护状态。
	stateDir := filepath.Join(filepath.Dir(filepath.Dir(paths.database)),
		filepath.Base(filepath.Dir(paths.database))+"-maintenance")
	ring, err := secrets.LoadKeyring(context.Background(), secrets.ProviderFunc(
		func(context.Context) ([]byte, error) {
			return os.ReadFile(paths.masterKey)
		}))
	if err != nil {
		t.Fatalf("加载测试密钥环失败: %v", err)
	}
	controller, err := maintenance.New(maintenance.Options{
		StateDir: stateDir, DatabasePath: paths.database,
		Keyring: secrets.ProviderFunc(func(context.Context) ([]byte, error) {
			return ring.Document()
		}),
	})
	if err != nil {
		t.Fatalf("构造维护状态控制器失败: %v", err)
	}
	t.Cleanup(func() { _ = controller.Close() })
	if controller.Missing() {
		if err := controller.Initialize(context.Background(), maintenance.InitializeRequest{
			Operator: maintenance.LocalOperator(), Reason: "测试进入维护状态"}); err != nil {
			t.Fatalf("初始化维护状态失败: %v", err)
		}
	}
	if err := controller.EnterMaintenance(context.Background(), maintenance.EnterRequest{
		Operator: maintenance.LocalOperator(), Reason: "测试维护窗口"}); err != nil {
		t.Fatalf("进入维护状态失败: %v", err)
	}

	address, _, _ := startServe(t, serverapp.ServeOptions{
		ConfigPath:    paths.config,
		MasterKeyFile: paths.masterKey,
	})
	client := &http.Client{Timeout: 10 * time.Second}
	baseURL := "http://" + address
	if status, body := httpGet(t, client, baseURL+"/healthz"); status != http.StatusOK ||
		!strings.Contains(body, "maintenance") {
		t.Fatalf("维护模式健康检查异常: status=%d body=%s", status, body)
	}
	if status, body := httpGet(t, client, baseURL+"/login"); status != http.StatusServiceUnavailable ||
		!strings.Contains(body, "维护中") {
		t.Fatalf("维护模式业务页面未被拒绝: status=%d body=%.200s", status, body)
	}
	if status, _ := httpGet(t, client, baseURL+"/openapi.json"); status != http.StatusServiceUnavailable {
		t.Fatalf("维护模式 openapi.json 未被拒绝: status=%d", status)
	}
}

// TestConfigValidationFailsClosed 覆盖配置错误 fail-closed（未知字段）与 TLS 配置
// 校验失败；两者都必须在监听前返回错误。
func TestConfigValidationFailsClosed(t *testing.T) {
	unknownField := preparePaths(t, func(config string) string {
		return config + "unknown_top_level: true\n"
	})
	var stderr bytes.Buffer
	err := serverapp.RunServe(context.Background(), serverapp.ServeOptions{
		ConfigPath:     unknownField.config,
		MasterKeyFile:  unknownField.masterKey,
		StandardOutput: io.Discard,
		StandardError:  &stderr,
	})
	if err == nil || !strings.Contains(err.Error(), "配置") {
		t.Fatalf("未知配置字段未被拒绝: %v", err)
	}

	missingDir := t.TempDir()
	badTLS := preparePaths(t, func(config string) string {
		return withTLS(config,
			filepath.Join(missingDir, "missing-cert.pem"),
			filepath.Join(missingDir, "missing-key.pem"))
	})
	if _, initErr := runInit(t, badTLS); initErr != nil {
		t.Fatalf("初始化阶段不应要求 TLS 证书: %v", initErr)
	}
	err = serverapp.RunServe(context.Background(), serverapp.ServeOptions{
		ConfigPath:     badTLS.config,
		MasterKeyFile:  badTLS.masterKey,
		StandardOutput: io.Discard,
		StandardError:  &stderr,
	})
	if err == nil || !strings.Contains(err.Error(), "TLS") {
		t.Fatalf("缺失 TLS 证书未被拒绝: %v", err)
	}
}

// TestServeWithLocalTLS 覆盖本地 TLS 装配（临时自签名证书）：HTTPS 健康检查可用。
func TestServeWithLocalTLS(t *testing.T) {
	root := t.TempDir()
	certFile, keyFile := writeSelfSignedCertificate(t, root)
	paths := preparePaths(t, func(config string) string {
		return withTLS(config, certFile, keyFile)
	})
	if _, err := runInit(t, paths); err != nil {
		t.Fatalf("首次初始化失败: %v", err)
	}
	address, _, _ := startServe(t, serverapp.ServeOptions{
		ConfigPath:    paths.config,
		MasterKeyFile: paths.masterKey,
	})
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	status, body := httpGet(t, client, "https://"+address+"/healthz")
	if status != http.StatusOK || !strings.Contains(body, `"ok"`) {
		t.Fatalf("TLS 健康检查异常: status=%d body=%s", status, body)
	}
}

// withTLS 把 TLS 证书文件配置插入 server 段（替换关闭超时行后追加字段）。
func withTLS(config, certFile, keyFile string) string {
	replacement := fmt.Sprintf("shutdown_timeout_seconds: 5\n  tls_cert_files:\n    - %q\n  tls_key_files:\n    - %q",
		filepath.ToSlash(certFile), filepath.ToSlash(keyFile))
	return strings.Replace(config, "shutdown_timeout_seconds: 5", replacement, 1)
}

// writeSelfSignedCertificate 生成 127.0.0.1 自签名证书；私钥用受保护文件权限写入。
func writeSelfSignedCertificate(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成测试私钥失败: %v", err)
	}
	now := time.Now().UTC()
	template := x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template,
		&privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("签发测试证书失败: %v", err)
	}
	certFile = filepath.Join(dir, "server-cert.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatalf("写入测试证书失败: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("编码测试私钥失败: %v", err)
	}
	keyFile = filepath.Join(dir, "server-key.pem")
	if err := secrets.WriteProtectedFile(keyFile, pem.EncodeToMemory(&pem.Block{
		Type: "PRIVATE KEY", Bytes: keyDER})); err != nil {
		t.Fatalf("写入受保护测试私钥失败: %v", err)
	}
	return certFile, keyFile
}
