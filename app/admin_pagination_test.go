package app

// 步骤 216：公开管理门面分页闭环（用户/用户组/角色/权限/成员/角色分配）。
//   - 统一默认值/最大值/非法输入（REQ_INVALID）与 HasMore/Page 元数据；
//   - 白名单排序（非法字段 REQ_INVALID），同值时按稳定 ID 次序；
//   - 跨 Runtime/无权限调用者按 ACCESS_DENIED fail-closed；
//   - 关联列表（组成员、角色分配）在数据源处分页。
// 说明：跨应用数据范围与 root 保护的详细拒绝路径由领域测试覆盖；本测试聚焦门面
// 分页契约与公开入口。

import (
	"context"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/group"
)

func TestAdminPaginatedListFacades(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 3, 0, 0, 0, time.UTC))
	runtime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	adminAPI := runtime.Admin()
	local := runtime.LocalAdmin()

	// ===== 角色：建 3 个，按名称排序 + 分页 + 非法输入 =====
	roles := make([]AdminRole, 0, 3)
	for _, item := range []struct{ key, name string }{
		{"page-alpha", "Alpha角色"}, {"page-zeta", "Zeta角色"}, {"page-middle", "Middle角色"},
	} {
		created, err := adminAPI.CreateRole(ctx, AdminCreateRoleRequest{
			Caller: local, ScopeID: "system", Key: item.key, Name: item.name,
			RequestID: login.NewRequestID()})
		if err != nil {
			t.Fatalf("CreateRole(%s): %v", item.key, err)
		}
		roles = append(roles, created)
	}
	rolePage, err := adminAPI.ListRoles(ctx, AdminListRolesRequest{
		Caller: local, Page: AdminPage{Limit: 2}, Sort: "name", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	if len(rolePage.Roles) != 2 || !rolePage.HasMore {
		t.Fatalf("角色第一页 = %d, hasMore=%v", len(rolePage.Roles), rolePage.HasMore)
	}
	if rolePage.Page.Limit != 2 || rolePage.Page.Offset != 0 ||
		rolePage.Page.Returned != 2 || rolePage.Page.NextOffset != 2 {
		t.Fatalf("角色分页元数据 = %+v", rolePage.Page)
	}
	if rolePage.Roles[0].Name != "Alpha角色" || rolePage.Roles[1].Name != "Middle角色" {
		t.Fatalf("角色名称升序 = %+v", rolePage.Roles)
	}
	rolePage2, err := adminAPI.ListRoles(ctx, AdminListRolesRequest{
		Caller: local, Page: AdminPage{Limit: 2, Offset: 2}, Sort: "name",
		RequestID: login.NewRequestID()})
	if err != nil || len(rolePage2.Roles) != 1 || rolePage2.HasMore {
		t.Fatalf("角色第二页 = %+v, err=%v", rolePage2, err)
	}
	if _, err := adminAPI.ListRoles(ctx, AdminListRolesRequest{
		Caller: local, Page: AdminPage{Limit: 2}, Sort: "bogus",
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("非法角色排序错误 = %v，期望 REQ_INVALID", err)
	}
	if _, err := adminAPI.ListRoles(ctx, AdminListRolesRequest{
		Caller: local, Page: AdminPage{Limit: 101},
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("非法角色分页错误 = %v，期望 REQ_INVALID", err)
	}

	// ===== 权限：建 3 个，按机器标识排序 =====
	for _, key := range []string{"page.perm.alpha", "page.perm.zeta", "page.perm.middle"} {
		if _, err := adminAPI.CreatePermission(ctx, AdminCreatePermissionRequest{
			Caller: local, ScopeID: "system", Key: key, Name: "权限 " + key,
			RequestID: login.NewRequestID()}); err != nil {
			t.Fatalf("CreatePermission(%s): %v", key, err)
		}
	}
	permissionPage, err := adminAPI.ListPermissions(ctx, AdminListPermissionsRequest{
		Caller: local, Page: AdminPage{Limit: 2}, Sort: "key",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("ListPermissions: %v", err)
	}
	if len(permissionPage.Permissions) != 2 || !permissionPage.HasMore {
		t.Fatalf("权限第一页 = %d, hasMore=%v", len(permissionPage.Permissions),
			permissionPage.HasMore)
	}
	if _, err := adminAPI.ListPermissions(ctx, AdminListPermissionsRequest{
		Caller: local, Page: AdminPage{Limit: 10}, Sort: "bogus",
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("非法权限排序错误 = %v，期望 REQ_INVALID", err)
	}

	// ===== 用户组：通过领域服务创建（公开门面暂未提供创建组），再经门面分页读取 =====
	managed := runtime.managedServices()
	if managed == nil || managed.Group == nil {
		t.Fatal("用户组服务未装配")
	}
	groupCaller, err := group.LocalBootstrapCaller("host-operator")
	if err != nil {
		t.Fatalf("构造用户组调用者失败: %v", err)
	}
	groups := make([]group.Group, 0, 3)
	for _, item := range []struct{ key, name string }{
		{"page-group-alpha", "Alpha组"}, {"page-group-zeta", "Zeta组"},
		{"page-group-middle", "Middle组"},
	} {
		created, createErr := managed.Group.CreateGroup(ctx, groupCaller, group.CreateRequest{
			ScopeID: group.ScopeSystem, GroupKey: item.key, Name: item.name,
			Description: "分页测试"})
		if createErr != nil {
			t.Fatalf("CreateGroup(%s): %v", item.key, createErr)
		}
		groups = append(groups, created)
	}
	groupPage, err := adminAPI.ListGroups(ctx, AdminListGroupsRequest{
		Caller: local, Page: AdminPage{Limit: 2}, Sort: "name",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	if len(groupPage.Groups) != 2 || !groupPage.HasMore {
		t.Fatalf("用户组第一页 = %d, hasMore=%v", len(groupPage.Groups), groupPage.HasMore)
	}
	if groupPage.Groups[0].Name != "Alpha组" {
		t.Fatalf("用户组名称升序 = %+v", groupPage.Groups)
	}
	groupPageDesc, err := adminAPI.ListGroups(ctx, AdminListGroupsRequest{
		Caller: local, Page: AdminPage{Limit: 3}, Sort: "name", Descending: true,
		RequestID: login.NewRequestID()})
	if err != nil || groupPageDesc.Groups[0].Name != "Zeta组" {
		t.Fatalf("用户组降序 = %+v, err=%v", groupPageDesc.Groups, err)
	}
	if _, err := adminAPI.ListGroups(ctx, AdminListGroupsRequest{
		Caller: local, Page: AdminPage{Limit: 10}, Sort: "bogus",
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("非法用户组排序错误 = %v，期望 REQ_INVALID", err)
	}
	// 组成员：加入 3 个真实用户后分页读取。
	users := make([]User, 0, 3)
	for _, username := range []string{"page-user-a", "page-user-b", "page-user-c"} {
		created, createErr := runtime.Users().Create(ctx, CreateUserRequest{
			Username: username, Password: "K8$wR3!nB6@yF1#v", Nickname: username,
			RequestID: login.NewRequestID()})
		if createErr != nil {
			t.Fatalf("CreateUser(%s): %v", username, createErr)
		}
		users = append(users, created)
	}
	userIDs := []string{users[0].ID, users[1].ID, users[2].ID}
	// 直接写入成员关系夹具：成员变更属敏感操作（需真实近期身份验证），本测试
	// 聚焦列表分页契约，不借敏感写路径伪造强认证。
	joinedMS := clock.Now().UnixMilli()
	for _, userID := range userIDs {
		if _, err := runtime.base.Store.DB().Exec(
			`INSERT INTO group_members(group_id,user_id,created_at_ms) VALUES(?,?,?)`,
			groups[0].ID, userID, joinedMS); err != nil {
			t.Fatalf("写入组成员夹具失败: %v", err)
		}
	}
	memberPage, err := adminAPI.ListGroupMembers(ctx, AdminListGroupMembersRequest{
		Caller: local, GroupID: groups[0].ID, Page: AdminPage{Limit: 2},
		Sort: "user_id", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("ListGroupMembers: %v", err)
	}
	if len(memberPage.Members) != 2 || !memberPage.HasMore {
		t.Fatalf("成员第一页 = %d, hasMore=%v", len(memberPage.Members), memberPage.HasMore)
	}
	if memberPage.Members[0].GroupID != groups[0].ID ||
		memberPage.Members[0].JoinedAt.IsZero() {
		t.Fatalf("成员视图字段异常 = %+v", memberPage.Members[0])
	}
	if _, err := adminAPI.ListGroupMembers(ctx, AdminListGroupMembersRequest{
		Caller: local, GroupID: "grp_00000000000000000000000000000000",
		Page: AdminPage{Limit: 10}, RequestID: login.NewRequestID()}); !IsNotFound(err) {
		t.Fatalf("不存在用户组错误 = %v，期望 NOT_FOUND", err)
	}

	// ===== 角色分配：给 2 个用户分配角色后各自分页 =====
	for _, user := range users[:2] {
		if err := adminAPI.GrantApplicationRole(ctx, GrantRoleRequest{
			Caller: local, UserID: user.ID, RoleID: roles[0].ID,
			RequestID: login.NewRequestID()}); err != nil {
			t.Fatalf("GrantApplicationRole(%s): %v", user.ID, err)
		}
	}
	assignmentPage, err := adminAPI.ListRoleAssignments(ctx, AdminListRoleAssignmentsRequest{
		Caller: local, RoleID: roles[0].ID, UserPage: AdminPage{Limit: 1},
		GroupPage: AdminPage{Limit: 1}, Sort: "target_id",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("ListRoleAssignments: %v", err)
	}
	if len(assignmentPage.Users) != 1 || !assignmentPage.UsersHasMore {
		t.Fatalf("角色用户分配第一页 = %d, hasMore=%v", len(assignmentPage.Users),
			assignmentPage.UsersHasMore)
	}
	if assignmentPage.Users[0].ScopeID == "" || assignmentPage.Users[0].AssignedAt.IsZero() {
		t.Fatalf("角色用户分配字段异常 = %+v", assignmentPage.Users[0])
	}
	if len(assignmentPage.Groups) != 0 || assignmentPage.GroupsHasMore {
		t.Fatalf("角色组分配应为空 = %+v", assignmentPage.Groups)
	}
	if _, err := adminAPI.ListRoleAssignments(ctx, AdminListRoleAssignmentsRequest{
		Caller: local, RoleID: roles[0].ID, UserPage: AdminPage{Limit: 101},
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("非法角色分配分页错误 = %v，期望 REQ_INVALID", err)
	}

	// ===== 无权限/跨 Runtime 调用者 fail-closed =====
	if _, err := adminAPI.ListGroups(ctx, AdminListGroupsRequest{
		Page: AdminPage{Limit: 10}, RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeAccessDenied) {
		t.Fatalf("零值调用者错误 = %v，期望 ACCESS_DENIED", err)
	}
	otherRuntime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	if _, err := adminAPI.ListRoles(ctx, AdminListRolesRequest{
		Caller: otherRuntime.LocalAdmin(), Page: AdminPage{Limit: 10},
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeAccessDenied) {
		t.Fatalf("跨 Runtime 调用者错误 = %v，期望 ACCESS_DENIED", err)
	}
}

// TestNormalizeAdminPage 覆盖公共分页输入的默认值/边界/非法值。
func TestNormalizeAdminPage(t *testing.T) {
	normalized, err := NormalizeAdminPage(AdminPage{})
	if err != nil || normalized.Limit != AdminDefaultPageLimit || normalized.Offset != 0 {
		t.Fatalf("零值分页 = %+v, %v", normalized, err)
	}
	if _, err := NormalizeAdminPage(AdminPage{Limit: -1}); !login.IsErrorCode(err,
		login.CodeReqInvalid) {
		t.Fatalf("负 limit 错误 = %v", err)
	}
	if _, err := NormalizeAdminPage(AdminPage{Limit: AdminMaxPageLimit + 1}); !login.IsErrorCode(err,
		login.CodeReqInvalid) {
		t.Fatalf("超限 limit 错误 = %v", err)
	}
	if _, err := NormalizeAdminPage(AdminPage{Offset: -1}); !login.IsErrorCode(err,
		login.CodeReqInvalid) {
		t.Fatalf("负 offset 错误 = %v", err)
	}
	if _, err := NormalizeAdminPage(AdminPage{Offset: AdminMaxPageOffset + 1}); !login.IsErrorCode(err,
		login.CodeReqInvalid) {
		t.Fatalf("超限 offset 错误 = %v", err)
	}
	info := NewAdminPageInfo(AdminPage{Limit: 2, Offset: 4}, 2, true)
	if info.Returned != 2 || info.NextOffset != 6 || !info.HasMore {
		t.Fatalf("分页元数据 = %+v", info)
	}
}
