package serverapp_test

// B1/B2 第二阶段 serve 级真实集成测试：真实临时目录 + 真实 SQLite + 真实监听。
// 覆盖：后台任务运行时随 serve 启动、协议/管理 API 挂载点在真实监听上可达、文件
// 访问日志轮转配置生效、单实例锁阻止第二个 serve 实例、关闭后锁释放。
// 不读写仓库数据库、不真实外发、不遗留监听端口。

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/serverapp"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
)

// TestServeStartsTasksMountsAndRotatingLog 验证 serve 正常模式下任务运行时与
// 挂载点生效，访问日志按文件写入并可在关闭后重新取得单实例锁。
func TestServeStartsTasksMountsAndRotatingLog(t *testing.T) {
	paths := preparePaths(t, nil)
	writeMasterKey(t, paths.masterKey)
	if stdout, err := runInit(t, paths); err != nil {
		t.Fatalf("首次初始化失败: %v（stdout=%s）", err, stdout)
	}
	accessLogPath := filepath.Join(paths.root, "logs", "access.log")
	mountRequests := &safeBuffer{}
	options := serverapp.ServeOptions{
		ConfigPath:        paths.config,
		MasterKeyFile:     paths.masterKey,
		AccessLogPath:     accessLogPath,
		AccessLogMaxBytes: 1 << 20,
		AccessLogMaxFiles: 2,
		ExtraMounts: []serverapp.HandlerMount{{
			Name:   "test-protocol",
			Prefix: "/protocol",
			Handler: http.HandlerFunc(func(writer http.ResponseWriter,
				request *http.Request) {
				mountRequests.Write([]byte(request.URL.Path))
				writer.WriteHeader(http.StatusOK)
				_, _ = writer.Write([]byte(`{"protocol":"mounted"}`))
			}),
		}},
	}
	result, _, cancel := startServeResult(t, options)
	address := result.Addresses[0]
	if !result.Tasks {
		t.Fatal("StartResult.Tasks = false，期望后台任务运行时随 serve 启动")
	}
	if len(result.Mounts) != 1 || !strings.HasSuffix(result.Mounts[0], "/protocol") {
		t.Fatalf("StartResult.Mounts = %v，期望包含 /protocol 挂载路径", result.Mounts)
	}
	if result.Maintenance {
		t.Fatal("正常启动不应处于维护模式")
	}
	base := "http://" + address
	client := &http.Client{Timeout: 10 * time.Second}
	// 挂载点真实可达，处理程序收到的是去掉挂载前缀后的路径。
	response, err := client.Get(base + "/protocol/oauth/token")
	if err != nil {
		t.Fatalf("请求协议挂载点失败: %v", err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("协议挂载点状态码 = %d，期望 200", response.StatusCode)
	}
	if !strings.Contains(string(body), "mounted") {
		t.Fatalf("协议挂载点响应异常: %s", string(body))
	}
	if mountRequests.String() != "/oauth/token" {
		t.Fatalf("挂载处理程序看到路径 %q，期望 /oauth/token", mountRequests.String())
	}
	// 健康检查仍由内置处理程序服务。
	health, err := client.Get(base + "/healthz")
	if err != nil {
		t.Fatalf("请求健康检查失败: %v", err)
	}
	health.Body.Close()
	if health.StatusCode != http.StatusOK {
		t.Fatalf("健康检查状态码 = %d，期望 200", health.StatusCode)
	}
	// 已装配的管理页在无管理会话时返回 401（要求登录/强认证），不泄露页面内容。
	admin, err := client.Get(base + "/admin/users")
	if err != nil {
		t.Fatalf("请求管理页失败: %v", err)
	}
	admin.Body.Close()
	if admin.StatusCode != http.StatusUnauthorized {
		t.Fatalf("无管理会话访问已装配管理页状态码 = %d，期望 401", admin.StatusCode)
	}
	// 已装配的个人资料页在无会话时要求登录（401），不泄露页面内容。
	accountPage, err := client.Get(base + "/account/profile")
	if err != nil {
		t.Fatalf("请求个人资料页失败: %v", err)
	}
	accountPage.Body.Close()
	if accountPage.StatusCode != http.StatusUnauthorized {
		t.Fatalf("无会话访问个人资料页状态码 = %d，期望 401", accountPage.StatusCode)
	}
	// 取消 serve 并等待单实例锁释放（startServe 的 Cleanup 会等待退出）。
	cancel()
	deadline := time.Now().Add(20 * time.Second)
	for {
		lock, lockErr := serverapp.AcquireInstanceLock(paths.database)
		if lockErr == nil {
			lock.Release()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("serve 关闭后单实例锁未在 20s 内释放: %v", lockErr)
		}
		time.Sleep(20 * time.Millisecond)
	}
	info, statErr := os.Stat(accessLogPath)
	if statErr != nil {
		t.Fatalf("文件访问日志未创建: %v", statErr)
	}
	if info.Size() == 0 {
		t.Fatal("文件访问日志为空，期望包含本次请求记录")
	}
}

// TestServeRejectsSecondInstanceOnSameDatabase 验证同一数据库的第二个 serve
// 被单实例锁拒绝，且不会开始监听。
func TestServeRejectsSecondInstanceOnSameDatabase(t *testing.T) {
	paths := preparePaths(t, nil)
	writeMasterKey(t, paths.masterKey)
	if stdout, err := runInit(t, paths); err != nil {
		t.Fatalf("首次初始化失败: %v（stdout=%s）", err, stdout)
	}
	_, _, firstCancel := startServe(t, serverapp.ServeOptions{
		ConfigPath: paths.config, MasterKeyFile: paths.masterKey,
	})
	defer firstCancel()
	// 第二个实例使用不同的配置文件（不同监听端口）但同一个数据库。
	secondRoot := testutil.TempDir(t)
	secondConfig := filepath.Join(secondRoot, "login.yaml")
	content := fmt.Sprintf(`server:
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
`, freeListenAddr(t), filepath.ToSlash(paths.database))
	if err := os.WriteFile(secondConfig, []byte(content), 0o600); err != nil {
		t.Fatalf("写入第二个实例配置失败: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	secondStarted := false
	err := serverapp.RunServe(ctx, serverapp.ServeOptions{
		ConfigPath:     secondConfig,
		MasterKeyFile:  paths.masterKey,
		StandardOutput: io.Discard,
		StandardError:  io.Discard,
		OnStarted:      func(serverapp.StartResult) { secondStarted = true },
	})
	if err == nil {
		t.Fatal("同一数据库的第二个 serve 应被拒绝")
	}
	if secondStarted {
		t.Fatal("第二个 serve 不应开始监听")
	}
	if !strings.Contains(err.Error(), "单实例") {
		t.Fatalf("单实例冲突错误不明确: %v", err)
	}
}
