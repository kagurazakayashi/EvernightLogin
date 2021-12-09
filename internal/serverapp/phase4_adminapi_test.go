package serverapp_test

// 管理 JSON API 集成真实测试：真实 SQLite + 真实监听 + 真实 session.Service。
// 覆盖：默认关闭时 404、启用后无会话 401、受限会话 403、强认证 root 会话 200、
// 错误码投影可用、维护模式 503、StartResult 报告挂载路径。

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/maintenance"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/serverapp"
)

// adminAPIGet 发起管理 API GET 请求；cookie 可为 nil。
func adminAPIGet(t *testing.T, client *http.Client, target string,
	cookie *http.Cookie) (int, string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("构造管理 API 请求失败: %v", err)
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("请求管理 API %s 失败: %v", target, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatalf("读取管理 API 响应失败: %v", err)
	}
	return response.StatusCode, string(body)
}

// TestAdminAPIDisabledByDefault 验证未显式启用时管理 API 404。
func TestAdminAPIDisabledByDefault(t *testing.T) {
	paths := preparePaths(t, nil)
	writeMasterKey(t, paths.masterKey)
	if stdout, err := runInit(t, paths); err != nil {
		t.Fatalf("首次初始化失败: %v（stdout=%s）", err, stdout)
	}
	address, _, cancel := startServe(t, serverapp.ServeOptions{
		ConfigPath: paths.config, MasterKeyFile: paths.masterKey,
	})
	defer cancel()
	client := &http.Client{Timeout: 10 * time.Second}
	if status, body := adminAPIGet(t, client, "http://"+address+"/admin/v1/meta", nil); status != http.StatusNotFound {
		t.Fatalf("未启用管理 API 状态码 = %d，期望 404（body 前 80: %.80s）", status, body)
	}
}

// TestAdminAPIEnabledAuthentication 验证启用后的鉴权契约与挂载路径。
func TestAdminAPIEnabledAuthentication(t *testing.T) {
	paths := preparePaths(t, nil)
	writeMasterKey(t, paths.masterKey)
	if stdout, err := runInit(t, paths); err != nil {
		t.Fatalf("首次初始化失败: %v（stdout=%s）", err, stdout)
	}
	result, _, cancel := startServeResult(t, serverapp.ServeOptions{
		ConfigPath: paths.config, MasterKeyFile: paths.masterKey,
		EnableAdminAPI: true,
	})
	defer cancel()
	address := result.Addresses[0]
	base := "http://" + address + "/admin/v1"
	foundMount := false
	for _, mount := range result.Mounts {
		if strings.HasSuffix(mount, "/admin/v1") {
			foundMount = true
		}
	}
	if !foundMount {
		t.Fatalf("StartResult.Mounts = %v，期望包含 /admin/v1", result.Mounts)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	// 无会话：401（AUTH_FAILED），不泄露 API 内容。
	if status, body := adminAPIGet(t, client, base+"/meta", nil); status != http.StatusUnauthorized {
		t.Fatalf("无会话管理 API 状态码 = %d，期望 401（body: %.120s）", status, body)
	}
	// 受限会话（root 未完成强认证）：403。
	restricted := issueRootSession(t, paths.config, paths.database,
		paths.masterKey, "restricted")
	if status, body := adminAPIGet(t, client, base+"/meta", restricted); status != http.StatusForbidden {
		t.Fatalf("受限会话管理 API 状态码 = %d，期望 403（body: %.120s）", status, body)
	}
	// 强认证 root 会话：200，meta 声明 services 装配状态与强认证要求。
	strong := issueRootSession(t, paths.config, paths.database, paths.masterKey, "strong")
	status, body := adminAPIGet(t, client, base+"/meta", strong)
	if status != http.StatusOK {
		t.Fatalf("强认证会话管理 API 状态码 = %d，期望 200（body: %.200s）", status, body)
	}
	var meta struct {
		Data struct {
			APIVersion string `json:"api_version"`
			Services   map[string]bool
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &meta); err != nil {
		t.Fatalf("管理 API meta 响应不是合法 JSON: %v（body: %.120s）", err, body)
	}
	if meta.Data.APIVersion != "v1" {
		t.Fatalf("管理 API 版本 = %q，期望 v1", meta.Data.APIVersion)
	}
	if !meta.Data.Services["tasks"] {
		t.Fatalf("管理 API 未挂载任务只读路由: %v", meta.Data.Services)
	}
	// 错误码投影可用（根包注册表映射）。
	if code, errorBody := adminAPIGet(t, client, base+"/error-codes", strong); code != http.StatusOK {
		t.Fatalf("错误码端点状态码 = %d，期望 200（body: %.120s）", code, errorBody)
	}
	// 审计/报告/备份域服务已装配：对应管理 API 路由真实可用（不再 404）。
	for _, apiPath := range []string{"/audit/events", "/reports", "/backups"} {
		if code, errorBody := adminAPIGet(t, client, base+apiPath, strong); code != http.StatusOK {
			t.Fatalf("已装配管理 API %s 状态码 = %d，期望 200（body: %.160s）",
				apiPath, code, errorBody)
		}
	}
	// 伪造 Cookie 仍 401。
	forged := &http.Cookie{Name: "evernight_login_session", Value: "forged"}
	if code, _ := adminAPIGet(t, client, base+"/meta", forged); code != http.StatusUnauthorized {
		t.Fatalf("伪造会话管理 API 状态码 = %d，期望 401", code)
	}
}

// TestAdminAPIUnavailableInMaintenance 验证维护模式只放行健康检查（管理 API 503）。
func TestAdminAPIUnavailableInMaintenance(t *testing.T) {
	paths := preparePaths(t, nil)
	if _, err := runInit(t, paths); err != nil {
		t.Fatalf("首次初始化失败: %v", err)
	}
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
	address, _, cancel := startServe(t, serverapp.ServeOptions{
		ConfigPath: paths.config, MasterKeyFile: paths.masterKey,
		EnableAdminAPI: true,
	})
	defer cancel()
	client := &http.Client{Timeout: 10 * time.Second}
	if code, _ := adminAPIGet(t, client, "http://"+address+"/admin/v1/meta", nil); code != http.StatusServiceUnavailable {
		t.Fatalf("维护模式管理 API 状态码 = %d，期望 503", code)
	}
	if code, body := httpGet(t, client, "http://"+address+"/healthz"); code != http.StatusOK ||
		!strings.Contains(body, "maintenance") {
		t.Fatalf("维护模式健康检查异常: status=%d body=%.120s", code, body)
	}
}
