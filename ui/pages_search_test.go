package ui_test

// 步骤 261：用户列表与应用成员列表搜索的页面契约测试。
// 覆盖：搜索参数透传到页面后端、输入框回显、渐进增强模块声明、分页链接携带
// 搜索条件、超长搜索在服务端渲染阶段被拒绝（400 + 中文提示）。真实服务集成见
// internal/serverapp 与 internal/uiadminadapter 的定向测试。

import (
	"net/http"
	"os"
	"strings"
	"testing"
)

// TestAdminUsersListSearchPage 验收用户页搜索输入与参数透传。
func TestAdminUsersListSearchPage(t *testing.T) {
	env := newAdminPageEnv(t)
	page := env.request(http.MethodGet, "/admin/users?search=%E5%BC%A0%E4%B8%89&status=active", nil, "")
	if page.Code != http.StatusOK {
		t.Fatalf("搜索用户列表 = %d", page.Code)
	}
	body := page.Body.String()
	if env.backend.lastUserQuery.Search != "张三" {
		t.Fatalf("页面后端收到搜索 = %q，期望 张三", env.backend.lastUserQuery.Search)
	}
	if env.backend.lastUserQuery.Status != "active" {
		t.Fatalf("搜索不应丢失状态筛选: %+v", env.backend.lastUserQuery)
	}
	if !strings.Contains(body, `name="search"`) || !strings.Contains(body, `value="张三"`) {
		t.Fatal("用户列表缺少搜索输入框或未回显搜索值")
	}
	if !strings.Contains(body, `data-ln-module="list-search"`) {
		t.Fatal("用户列表缺少渐进增强搜索模块声明")
	}
	// hasMore=true，下一页链接必须携带搜索条件（HTML 属性中 & 转义为 &amp;）。
	if !strings.Contains(body, "search=%E5%BC%A0%E4%B8%89") {
		t.Fatal("分页链接未携带搜索条件")
	}
	// 超长搜索在页面层直接拒绝，不进入后端。
	tooLong := env.request(http.MethodGet,
		"/admin/users?search="+strings.Repeat("a", 65), nil, "")
	if tooLong.Code != http.StatusBadRequest {
		t.Fatalf("超长搜索 = %d，期望 400", tooLong.Code)
	}
	if !strings.Contains(tooLong.Body.String(), "搜索条件无效") {
		t.Fatal("超长搜索缺少中文提示")
	}
}

// TestAdminApplicationMembersSearchPage 验收应用成员页搜索输入与参数透传。
func TestAdminApplicationMembersSearchPage(t *testing.T) {
	backend := newAppsFakeBackend()
	ui := newAppsTestUI(t, backend, true)
	members := serveAppsPage(ui, http.MethodGet,
		"/admin/applications/members?app_id="+appsTestAppID+"&search=Alice", nil)
	if members.Code != http.StatusOK {
		t.Fatalf("搜索成员页 = %d", members.Code)
	}
	body := members.Body.String()
	if backend.lastMemberQuery.Search != "Alice" {
		t.Fatalf("成员页后端收到搜索 = %q，期望 Alice", backend.lastMemberQuery.Search)
	}
	if !strings.Contains(body, `name="search"`) || !strings.Contains(body, `value="Alice"`) {
		t.Fatal("成员页缺少搜索输入框或未回显搜索值")
	}
	if !strings.Contains(body, `data-ln-module="list-search"`) {
		t.Fatal("成员页缺少渐进增强搜索模块声明")
	}
	tooLong := serveAppsPage(ui, http.MethodGet,
		"/admin/applications/members?app_id="+appsTestAppID+"&search="+strings.Repeat("a", 65), nil)
	if tooLong.Code != http.StatusBadRequest {
		t.Fatalf("成员页超长搜索 = %d，期望 400", tooLong.Code)
	}
	if !strings.Contains(tooLong.Body.String(), "搜索条件无效") {
		t.Fatal("成员页超长搜索缺少中文提示")
	}
}

// TestListSearchEnhancementAssets 验收渐进增强模块登记：app.mjs 认识 list-search，
// 模块文件存在且包含防抖与中止旧请求的实现（不做真实浏览器执行，属于静态契约）。
func TestListSearchEnhancementAssets(t *testing.T) {
	appScript, err := os.ReadFile("web/assets/js/app.mjs")
	if err != nil {
		t.Fatalf("读取 app.mjs 失败: %v", err)
	}
	if !strings.Contains(string(appScript), `"list-search"`) ||
		!strings.Contains(string(appScript), "__lnMountModules") {
		t.Fatal("app.mjs 未登记 list-search 或缺少局部替换后的重新挂载入口")
	}
	module, err := os.ReadFile("web/assets/js/modules/list-search.mjs")
	if err != nil {
		t.Fatalf("读取 list-search.mjs 失败: %v", err)
	}
	for _, wanted := range []string{"AbortController", "abort()", "DEBOUNCE_MS"} {
		if !strings.Contains(string(module), wanted) {
			t.Fatalf("list-search.mjs 缺少 %q（防抖/取消旧请求契约）", wanted)
		}
	}
}
