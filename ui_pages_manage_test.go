package login_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
)

// manageTestSessions 以普通业务会话（Kind=normal）访问 /manage/**；管理 Kind 用于
// 验证系统管理会话不会被误用于业务管理员页面。
type manageTestSessions struct {
	userID string
	kind   string
}

func (s manageTestSessions) ResolvePageSession(context.Context,
	*http.Request) (login.UISession, error) {
	kind := s.kind
	if kind == "" {
		kind = "normal"
	}
	return login.UISession{Authenticated: true, UserID: s.userID, Kind: kind,
		ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func (s manageTestSessions) IssueCSRFToken(context.Context, *http.Request) (string, error) {
	return "manage-csrf-token", nil
}

// newManageTestUI 构造带 PageManage 的页面框架。
func newManageTestUI(t *testing.T, apps login.UIAppsBackend, rbac login.UIRBACBackend,
	sessions login.UISessionService) *login.WebUI {
	t.Helper()
	ui, err := login.NewWebUI(login.WebUIOptions{
		Session:    sessions,
		PageManage: &login.UIPageManageOptions{Apps: apps, RBAC: rbac},
	})
	if err != nil {
		t.Fatalf("页面框架: %v", err)
	}
	return ui
}

// serveManagePage 执行页面请求。
func serveManagePage(ui http.Handler, method, target string,
	form url.Values) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "http://example.test"+target, bytes.NewReader(nil))
	if method == http.MethodPost {
		request = httptest.NewRequest(method, "http://example.test"+target,
			bytes.NewReader([]byte(form.Encode())))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	recorder := httptest.NewRecorder()
	ui.ServeHTTP(recorder, request)
	return recorder
}

// newManageFakeRBAC 构造范围与示例应用一致的角色/权限数据。
func newManageFakeRBAC() *fakeRBACBackend {
	role := login.UIRBACRoleView{ID: "role_app_admin", ScopeID: appsTestAppID,
		ScopeKind: "application", ApplicationID: appsTestAppID, Key: "app.admin",
		Name: "应用管理员", Enabled: true, UserAssignments: 1,
		CurrentPermissions: []login.UIRBACPermissionView{{PermissionID: "perm_read",
			ScopeID: appsTestAppID, Key: "applications.read", Name: "读取应用"}}}
	permission := login.UIRBACPermissionView{PermissionID: "perm_read",
		ScopeID: appsTestAppID, ScopeKind: "application", Key: "applications.read",
		Name: "读取应用", Description: "允许查看本应用资料", Enabled: true}
	return &fakeRBACBackend{
		roles:       []login.UIRBACRoleView{role},
		role:        role,
		permissions: []login.UIRBACPermissionView{permission},
		permission:  permission,
		available:   []login.UIRBACPermissionView{permission},
		assignments: login.UIRBACAssignments{Users: []login.UIRBACUserAssignment{
			{UserID: "usr_member", DataScope: "all", DataScopeText: "全部", AssignedBy: "usr_admin"}}},
	}
}

// TestUIPageManageRoutesContract 验证步骤 185 路由与访问级别。
func TestUIPageManageRoutesContract(t *testing.T) {
	ui := newManageTestUI(t, newAppsFakeBackend(), newManageFakeRBAC(),
		manageTestSessions{userID: "usr_admin"})
	routes := map[string]bool{}
	for _, route := range ui.Routes() {
		routes[route.Name] = true
		if strings.HasPrefix(route.Name, "manage.") && route.Access != login.UIAccessUser {
			t.Fatalf("步骤 185 路由 %s 必须是 UIAccessUser", route.Name)
		}
	}
	for _, name := range []string{"manage.apps", "manage.members", "manage.members_submit",
		"manage.roles", "manage.role_detail", "manage.role_state", "manage.role_permissions",
		"manage.role_assignments", "manage.role_assign", "manage.permissions",
		"manage.permission_state"} {
		if !routes[name] {
			t.Fatalf("缺少步骤 185 路由 %s", name)
		}
	}
	if _, err := login.NewWebUI(login.WebUIOptions{
		PageManage: &login.UIPageManageOptions{}}); err == nil {
		t.Fatal("缺少后端的应用管理员页面应拒绝构造")
	}
}

// TestUIPageManageRenderingAndStates 验证列表/空/错误/无权限/写操作重定向。
func TestUIPageManageRenderingAndStates(t *testing.T) {
	apps := newAppsFakeBackend()
	rbac := newManageFakeRBAC()
	ui := newManageTestUI(t, apps, rbac, manageTestSessions{userID: "usr_admin"})

	// 应用列表：只出现假后端允许的应用，且带成员/角色/权限入口。
	list := serveManagePage(ui, http.MethodGet, "/manage/applications", nil)
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), "示例应用") ||
		!strings.Contains(list.Body.String(), "/manage/applications/members") {
		t.Fatalf("应用列表渲染异常: %d", list.Code)
	}
	// 成员页：成员数据、应用内成员与全局账户区别文案、CSRF 隐藏字段。
	members := serveManagePage(ui, http.MethodGet,
		"/manage/applications/members?app_id="+appsTestAppID, nil)
	if members.Code != http.StatusOK || !strings.Contains(members.Body.String(), "usr_member") ||
		!strings.Contains(members.Body.String(), "共享账户") ||
		!strings.Contains(members.Body.String(), `name="csrf_token"`) {
		t.Fatalf("成员页渲染异常: %d", members.Code)
	}
	// 加入成员：成功重定向 303 且跳到成员页。
	add := serveManagePage(ui, http.MethodPost, "/manage/applications/members",
		url.Values{"app_id": {appsTestAppID}, "action": {"add"},
			"user_id": {"usr_new"}, "display_name": {"新成员"}, "csrf_token": {"manage-csrf-token"}})
	if add.Code != http.StatusSeeOther ||
		!strings.Contains(add.Header().Get("Location"), "status=member_added") {
		t.Fatalf("加入成员未成功重定向: %d %s", add.Code, add.Header().Get("Location"))
	}
	// 角色列表/详情：显示应用内角色与权限说明。
	roles := serveManagePage(ui, http.MethodGet,
		"/manage/applications/roles?app_id="+appsTestAppID, nil)
	if roles.Code != http.StatusOK || !strings.Contains(roles.Body.String(), "应用管理员") {
		t.Fatalf("角色列表渲染异常: %d", roles.Code)
	}
	detail := serveManagePage(ui, http.MethodGet,
		"/manage/applications/roles/detail?app_id="+appsTestAppID+"&role_id=role_app_admin", nil)
	if detail.Code != http.StatusOK || !strings.Contains(detail.Body.String(), "读取应用") {
		t.Fatalf("角色详情渲染异常: %d", detail.Code)
	}
	// 权限列表：显示自定义权限与启停表单。
	permissions := serveManagePage(ui, http.MethodGet,
		"/manage/applications/permissions?app_id="+appsTestAppID, nil)
	if permissions.Code != http.StatusOK ||
		!strings.Contains(permissions.Body.String(), "applications.read") {
		t.Fatalf("权限列表渲染异常: %d", permissions.Code)
	}
	// 缺少 app_id：不退化到默认/跨应用读取。
	missing := serveManagePage(ui, http.MethodGet, "/manage/applications/members", nil)
	if missing.Code != http.StatusBadRequest {
		t.Fatalf("缺少 app_id 应 400，实际 %d", missing.Code)
	}

	// 无权限/跨应用：后端返回 ACCESS_DENIED 时页面 403 且不泄露其它应用名称。
	deniedApps := newAppsFakeBackend()
	deniedApps.failCode = "ACCESS_DENIED"
	deniedApps.failOn = "get"
	deniedUI := newManageTestUI(t, deniedApps, rbac, manageTestSessions{userID: "usr_admin"})
	denied := serveManagePage(deniedUI, http.MethodGet,
		"/manage/applications/members?app_id=app_22222222222222222222222222222222", nil)
	if denied.Code != http.StatusForbidden ||
		strings.Contains(denied.Body.String(), "示例应用") {
		t.Fatalf("无权限页面应 403 且不泄露数据: %d", denied.Code)
	}
	// 空状态：假后端没有成员时显示空提示（不伪造数据）。
	emptyMembers := newAppsFakeBackend()
	emptyMembers.members = nil
	emptyUI := newManageTestUI(t, emptyMembers, rbac, manageTestSessions{userID: "usr_admin"})
	empty := serveManagePage(emptyUI, http.MethodGet,
		"/manage/applications/members?app_id="+appsTestAppID, nil)
	if empty.Code != http.StatusOK || !strings.Contains(empty.Body.String(), "暂无成员") {
		t.Fatalf("成员空状态渲染异常: %d", empty.Code)
	}

	// 管理 Kind 会话不能被当作业务管理员页面通过（访问级别隔离）。
	managementUI := newManageTestUI(t, apps, rbac,
		manageTestSessions{userID: "usr_admin", kind: "management"})
	management := serveManagePage(managementUI, http.MethodGet, "/manage/applications", nil)
	if management.Code != http.StatusForbidden {
		t.Fatalf("管理 Kind 会话访问业务管理员页面应 403，实际 %d", management.Code)
	}
}
