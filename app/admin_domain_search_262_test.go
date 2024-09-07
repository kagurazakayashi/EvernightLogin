package app

// 步骤 262：公开管理门面（Go API）角色/权限/应用列表搜索契约测试。
// 新文件，避免在 261 审计期间改动其测试文件。

import (
	"context"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

// TestAdminDomainListSearch 验收 Go 门面角色/权限/应用列表的 Search 透传、
// 字面匹配、字段白名单与非法字段 REQ_INVALID。
func TestAdminDomainListSearch(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 26, 5, 0, 0, 0, time.UTC))
	runtime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	adminAPI := runtime.Admin()
	local := runtime.LocalAdmin()

	// 准备：系统范围角色/权限与应用（名称含中文与特殊字符）。
	for _, item := range []struct{ key, name string }{
		{"audit-helper", "审计助手"},
		{"percent-role", "100%审计"},
	} {
		if _, err := adminAPI.CreateRole(ctx, AdminCreateRoleRequest{
			Caller: local, ScopeID: "system", Key: item.key, Name: item.name,
			RequestID: login.NewRequestID()}); err != nil {
			t.Fatalf("CreateRole(%s): %v", item.key, err)
		}
	}
	for _, item := range []struct{ key, name string }{
		{"test.audit.read", "审计查看"},
		{"test.percent.role", "100%审计"},
	} {
		if _, err := adminAPI.CreatePermission(ctx, AdminCreatePermissionRequest{
			Caller: local, ScopeID: "system", Key: item.key, Name: item.name,
			RequestID: login.NewRequestID()}); err != nil {
			t.Fatalf("CreatePermission(%s): %v", item.key, err)
		}
	}
	for _, name := range []string{"Alpha应用", "Beta应用"} {
		if _, err := adminAPI.CreateApplication(ctx, AdminCreateApplicationRequest{
			Caller: local, Name: name, RequestID: login.NewRequestID()}); err != nil {
			t.Fatalf("CreateApplication(%s): %v", name, err)
		}
	}

	roles, err := adminAPI.ListRoles(ctx, AdminListRolesRequest{
		Caller: local, Search: "审计", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("ListRoles 搜索失败: %v", err)
	}
	if len(roles.Roles) == 0 {
		t.Fatal("角色搜索无结果")
	}
	for _, item := range roles.Roles {
		if item.Name != "审计助手" && item.Name != "100%审计" {
			t.Fatalf("角色搜索结果 = %+v", item)
		}
	}
	// 通配符按字面：% 只命中含 % 的角色。
	percentRoles, err := adminAPI.ListRoles(ctx, AdminListRolesRequest{
		Caller: local, Search: "%", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("ListRoles %% 搜索失败: %v", err)
	}
	if len(percentRoles.Roles) != 1 || percentRoles.Roles[0].Name != "100%审计" {
		t.Fatalf("角色通配符字面结果 = %+v", percentRoles.Roles)
	}
	// 非法字段 REQ_INVALID。
	if _, err := adminAPI.ListRoles(ctx, AdminListRolesRequest{
		Caller: local, Search: "x", SearchFields: []string{"description"},
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("角色非法搜索字段错误 = %v，期望 REQ_INVALID", err)
	}

	permissions, err := adminAPI.ListPermissions(ctx, AdminListPermissionsRequest{
		Caller: local, Search: "审计", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("ListPermissions 搜索失败: %v", err)
	}
	if len(permissions.Permissions) == 0 {
		t.Fatal("权限搜索无结果")
	}
	percentPermissions, err := adminAPI.ListPermissions(ctx, AdminListPermissionsRequest{
		Caller: local, Search: "%", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("ListPermissions %% 搜索失败: %v", err)
	}
	if len(percentPermissions.Permissions) != 1 ||
		percentPermissions.Permissions[0].Name != "100%审计" {
		t.Fatalf("权限通配符字面结果 = %+v", percentPermissions.Permissions)
	}

	applications, err := adminAPI.ListApplications(ctx, AdminListApplicationsRequest{
		Caller: local, Search: "ALPHA", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("ListApplications 搜索失败: %v", err)
	}
	if len(applications.Applications) != 1 ||
		applications.Applications[0].Name != "Alpha应用" {
		t.Fatalf("应用大小写折叠结果 = %+v", applications.Applications)
	}
	if _, err := adminAPI.ListApplications(ctx, AdminListApplicationsRequest{
		Caller: local, Search: "x", SearchFields: []string{"owner"},
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("应用非法搜索字段错误 = %v，期望 REQ_INVALID", err)
	}
}
