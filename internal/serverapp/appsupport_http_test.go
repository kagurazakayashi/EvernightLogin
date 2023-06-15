package serverapp_test

// 步骤 154：应用客服 API 装配边界。默认关闭 404；启用但未启用 OAuth 协议端点时
// 启动失败（不能在没有真实 Token/撤销服务时暴露客服 API）。

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/serverapp"
)

func TestAppSupportDisabledByDefault(t *testing.T) {
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
	request, err := http.NewRequest(http.MethodGet,
		"http://"+address+"/api/app/v1/support/cases", nil)
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
		t.Fatalf("默认关闭应用客服 API 状态 = %d，期望 404", response.StatusCode)
	}
}

func TestAppSupportRequiresProtocol(t *testing.T) {
	paths := preparePaths(t, nil)
	writeMasterKey(t, paths.masterKey)
	if stdout, err := runInit(t, paths); err != nil {
		t.Fatalf("首次初始化失败: %v（stdout=%s）", err, stdout)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	err := serverapp.RunServe(ctx, serverapp.ServeOptions{
		ConfigPath: paths.config, MasterKeyFile: paths.masterKey,
		EnableAppSupport: true,
	})
	if err == nil || !strings.Contains(err.Error(), "OAuth") {
		t.Fatalf("启用应用客服但未启用协议端点应拒绝启动，实际 err=%v", err)
	}
}
