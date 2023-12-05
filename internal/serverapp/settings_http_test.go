// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package serverapp_test

// 步骤 232 HTTP/页面真实集成测试：真实 SQLite + 临时 YAML + 管理 API 强认证 root
// 会话；验证 settings 路由已挂载、字段读取、原子写入、版本冲突与页面渲染。

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/serverapp"
)

func settingsHTTPDo(t *testing.T, client *http.Client, method, target, bearer,
	body string) (int, map[string]any) {
	t.Helper()
	request, err := http.NewRequest(method, target, bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("构造请求: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("请求 %s %s: %v", method, target, err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	var envelope map[string]any
	_ = json.Unmarshal(raw, &envelope)
	return response.StatusCode, envelope
}

func TestAdminSettingsHTTPRoutesAndPage(t *testing.T) {
	paths := preparePaths(t, nil)
	writeMasterKey(t, paths.masterKey)
	if stdout, err := runInit(t, paths); err != nil {
		t.Fatalf("初始化失败: %v（stdout=%s）", err, stdout)
	}
	result, _, cancel := startServeResult(t, serverapp.ServeOptions{
		ConfigPath: paths.config, MasterKeyFile: paths.masterKey, EnableAdminAPI: true,
	})
	defer cancel()
	base := "http://" + result.Addresses[0] + "/admin/v1"
	client := &http.Client{Timeout: 10 * time.Second}
	cookie := issueRootSession(t, paths.config, paths.database, paths.masterKey, "strong")
	bearer := cookie.Value

	// 未认证不得读取配置字段。
	if status, _ := settingsHTTPDo(t, client, http.MethodGet, base+"/settings", "", ""); status != http.StatusUnauthorized {
		t.Fatalf("未认证 GET settings = %d，期望 401", status)
	}
	status, envelope := settingsHTTPDo(t, client, http.MethodGet, base+"/settings", bearer, "")
	if status != http.StatusOK {
		t.Fatalf("GET settings = %d（%+v）", status, envelope)
	}
	data, _ := envelope["data"].(map[string]any)
	version, _ := data["version"].(string)
	if version == "" || data["fields"] == nil {
		t.Fatalf("设置字段视图异常: %+v", data)
	}
	// 原子写入常规字段。
	status, envelope = settingsHTTPDo(t, client, http.MethodPut, base+"/settings", bearer,
		`{"expected_version":"`+version+`","changes":{"logging.level":"debug"},"reason":"http test"}`)
	if status != http.StatusOK {
		t.Fatalf("PUT settings = %d（%+v）", status, envelope)
	}
	updated := envelope["data"].(map[string]any)
	if updated["version"] == version || updated["applied_now"] != false {
		t.Fatalf("写入结果异常: %+v", updated)
	}
	// 旧版本冲突。
	status, envelope = settingsHTTPDo(t, client, http.MethodPut, base+"/settings", bearer,
		`{"expected_version":"`+version+`","changes":{"logging.format":"json"}}`)
	if status == http.StatusOK {
		t.Fatalf("旧版本写入必须冲突: %+v", envelope)
	}
	// 状态路由报告待重启/待宿主重载字段。
	status, envelope = settingsHTTPDo(t, client, http.MethodGet, base+"/settings/status", bearer, "")
	if status != http.StatusOK {
		t.Fatalf("GET settings/status = %d（%+v）", status, envelope)
	}
	statusData, _ := envelope["data"].(map[string]any)
	if statusData["host_reload_needed"] != true {
		t.Fatalf("状态应报告待宿主重载: %+v", statusData)
	}
	// 内置设置页面渲染（同一 root 强认证会话）。
	request, _ := http.NewRequest(http.MethodGet,
		"http://"+result.Addresses[0]+"/admin/settings", nil)
	request.AddCookie(cookie)
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("GET /admin/settings: %v", err)
	}
	defer response.Body.Close()
	page, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode != http.StatusOK || !strings.Contains(string(page), "配置设置") {
		t.Fatalf("设置页面渲染失败: status=%d", response.StatusCode)
	}
}
