package serverapp_test

// 步骤 147：业务托管管理 API 生产挂载测试。默认关闭；显式启用后真实路由可达、
// 未认证请求被 401 拒绝。业务操作/字段/审计由 internal/managedapi/httpapi 与其
// 真实服务测试覆盖；这里验证独立服务的装配与默认关闭边界。

import (
	"net/http"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/serverapp"
)

func TestManagedAPIDisabledByDefault(t *testing.T) {
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
	request, err := http.NewRequest(http.MethodGet, "http://"+address+
		"/api/managed/v1/applications/app_11111111111111111111111111111111", nil)
	if err != nil {
		t.Fatalf("构造请求: %v", err)
	}
	request.Header.Set("X-Evernight-API-Version", "v1")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("默认关闭时托管 API 状态 = %d，期望 404", response.StatusCode)
	}
}

func TestManagedAPIEnabledRequiresAuthentication(t *testing.T) {
	paths := preparePaths(t, nil)
	writeMasterKey(t, paths.masterKey)
	if stdout, err := runInit(t, paths); err != nil {
		t.Fatalf("首次初始化失败: %v（stdout=%s）", err, stdout)
	}
	address, _, cancel := startServe(t, serverapp.ServeOptions{
		ConfigPath: paths.config, MasterKeyFile: paths.masterKey,
		EnableManagedAPI: true,
	})
	defer cancel()
	client := &http.Client{Timeout: 10 * time.Second}
	request, err := http.NewRequest(http.MethodGet, "http://"+address+
		"/api/managed/v1/applications/app_11111111111111111111111111111111", nil)
	if err != nil {
		t.Fatalf("构造请求: %v", err)
	}
	request.Header.Set("X-Evernight-API-Version", "v1")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("未认证托管 API 状态 = %d，期望 401", response.StatusCode)
	}
	// 版本头缺失也必须拒绝，不能因认证失败而先泄露路由细节。
	withoutVersion, err := http.Get("http://" + address +
		"/api/managed/v1/applications/app_11111111111111111111111111111111")
	if err != nil {
		t.Fatalf("构造无版本请求失败: %v", err)
	}
	defer withoutVersion.Body.Close()
	if withoutVersion.StatusCode != http.StatusBadRequest {
		t.Fatalf("无版本托管 API 状态 = %d，期望 400", withoutVersion.StatusCode)
	}
}
