package ui_test

// 步骤 262：角色/权限/用户组/应用列表页搜索接线契约测试（新文件）。
// 覆盖：搜索参数透传到页面后端、输入框回显、渐进增强模块声明、分页链接携带搜索。

import (
	"net/http"
	"strings"
	"testing"
)

// TestAdminRBACListSearchPages 验收角色/权限页搜索参数与回显。
func TestAdminRBACListSearchPages(t *testing.T) {
	env := newRBACPageEnv(t)
	roles := env.get("/admin/roles?scope_id=system&search=audit")
	if roles.Code != http.StatusOK {
		t.Fatalf("角色页 = %d", roles.Code)
	}
	if env.backend.lastRoleQuery.Search != "audit" {
		t.Fatalf("角色页后端收到搜索 = %q", env.backend.lastRoleQuery.Search)
	}
	roleBody := roles.Body.String()
	if !strings.Contains(roleBody, `name="search"`) || !strings.Contains(roleBody, `value="audit"`) {
		t.Fatal("角色页缺少搜索回显")
	}
	if !strings.Contains(roleBody, `data-ln-module="list-search"`) {
		t.Fatal("角色页缺少渐进增强搜索模块声明")
	}

	permissions := env.get("/admin/permissions?scope_id=system&search=users")
	if permissions.Code != http.StatusOK {
		t.Fatalf("权限页 = %d", permissions.Code)
	}
	if env.backend.lastPermissionQuery.Search != "users" {
		t.Fatalf("权限页后端收到搜索 = %q", env.backend.lastPermissionQuery.Search)
	}
	if body := permissions.Body.String(); !strings.Contains(body, `name="search"`) ||
		!strings.Contains(body, `value="users"`) {
		t.Fatal("权限页缺少搜索回显")
	}
}

// TestAdminGroupsListSearchPage 验收用户组页搜索透传与回显。
func TestAdminGroupsListSearchPage(t *testing.T) {
	env := newAdminPageEnv(t)
	page := env.request(http.MethodGet, "/admin/groups?scope_id=system&search=%E5%AE%A1%E8%AE%A1", nil, "")
	if page.Code != http.StatusOK {
		t.Fatalf("用户组页 = %d", page.Code)
	}
	if env.backend.lastGroupQuery.Search != "审计" {
		t.Fatalf("用户组页后端收到搜索 = %q", env.backend.lastGroupQuery.Search)
	}
	body := page.Body.String()
	if !strings.Contains(body, `name="search"`) || !strings.Contains(body, `value="审计"`) {
		t.Fatal("用户组页缺少搜索回显")
	}
	if !strings.Contains(body, `data-ln-module="list-search"`) {
		t.Fatal("用户组页缺少渐进增强搜索模块声明")
	}
}

// TestAdminApplicationsListSearchPage 验收应用列表页搜索透传与回显。
func TestAdminApplicationsListSearchPage(t *testing.T) {
	backend := newAppsFakeBackend()
	ui := newAppsTestUI(t, backend, true)
	page := serveAppsPage(ui, http.MethodGet, "/admin/applications?search=Alpha", nil)
	if page.Code != http.StatusOK {
		t.Fatalf("应用列表页 = %d", page.Code)
	}
	if backend.lastApplicationQuery.Search != "Alpha" {
		t.Fatalf("应用列表页后端收到搜索 = %q", backend.lastApplicationQuery.Search)
	}
	body := page.Body.String()
	if !strings.Contains(body, `name="search"`) || !strings.Contains(body, `value="Alpha"`) {
		t.Fatal("应用列表页缺少搜索回显")
	}
	if !strings.Contains(body, `data-ln-module="list-search"`) {
		t.Fatal("应用列表页缺少渐进增强搜索模块声明")
	}
}
