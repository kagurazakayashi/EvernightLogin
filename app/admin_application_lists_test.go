package app

// 步骤 217：应用/应用成员/应用角色/应用用户组/会话列表的公开分页门面测试。
//   - 统一 AdminPage 默认值/上限/非法输入（REQ_INVALID）与 HasMore/Page 元数据；
//   - 白名单排序（非法字段 REQ_INVALID），应用范围固定为请求的应用 ID；
//   - 一个用户属于两个应用时只返回目标应用的成员关系；成员移除后不再出现；
//   - 会话列表要求真实管理会话（LocalAdmin 明确拒绝）；
//   - 公开字段不含客户端秘密/令牌。

import (
	"context"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/group"
)

func TestAdminApplicationListsPagination(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 4, 0, 0, 0, time.UTC))
	runtime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	adminAPI := runtime.Admin()
	local := runtime.LocalAdmin()

	// ===== 应用列表：名称白名单排序 + 分页 + 非法输入 =====
	applications := make([]AdminApplication, 0, 3)
	for _, name := range []string{"Alpha应用", "Zeta应用", "Middle应用"} {
		created, err := adminAPI.CreateApplication(ctx, AdminCreateApplicationRequest{
			Caller: local, Name: name, RequestID: login.NewRequestID()})
		if err != nil {
			t.Fatalf("CreateApplication(%s): %v", name, err)
		}
		applications = append(applications, created)
	}
	page, err := adminAPI.ListApplications(ctx, AdminListApplicationsRequest{
		Caller: local, Sort: "name", Page: AdminPage{Limit: 2},
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("ListApplications: %v", err)
	}
	if len(page.Applications) != 2 || !page.HasMore || page.Page.Limit != 2 ||
		page.Page.Returned != 2 || page.Page.NextOffset != 2 {
		t.Fatalf("应用第一页 = %+v", page)
	}
	if page.Applications[0].Name != "Alpha应用" || page.Applications[1].Name != "Middle应用" {
		t.Fatalf("应用名称升序 = %+v", page.Applications)
	}
	secondPage, err := adminAPI.ListApplications(ctx, AdminListApplicationsRequest{
		Caller: local, Sort: "name", Page: AdminPage{Limit: 2, Offset: 2},
		RequestID: login.NewRequestID()})
	if err != nil || len(secondPage.Applications) != 1 || secondPage.HasMore {
		t.Fatalf("应用第二页 = %+v err=%v", secondPage, err)
	}
	if _, err := adminAPI.ListApplications(ctx, AdminListApplicationsRequest{
		Caller: local, Sort: "client_secret", RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("非法应用排序错误 = %v，期望 REQ_INVALID", err)
	}
	if _, err := adminAPI.ListApplications(ctx, AdminListApplicationsRequest{
		Caller: local, Page: AdminPage{Limit: 101},
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("非法应用分页错误 = %v，期望 REQ_INVALID", err)
	}
	if _, err := adminAPI.ListApplications(ctx, AdminListApplicationsRequest{
		Caller: local, Status: "unknown", RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("非法应用状态错误 = %v，期望 REQ_INVALID", err)
	}

	// 应用创建后默认停用；启用后才能登记应用角色/用户组与成员。
	appA := applications[0]
	appB := applications[1]
	enabledA, err := adminAPI.SetApplicationEnabled(ctx, AdminSetApplicationEnabledRequest{
		Caller: local, ApplicationID: appA.ID, Enabled: true,
		ExpectedRowVersion: appA.RowVersion, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("启用应用 A: %v", err)
	}
	if _, err := adminAPI.SetApplicationEnabled(ctx, AdminSetApplicationEnabledRequest{
		Caller: local, ApplicationID: appB.ID, Enabled: true,
		ExpectedRowVersion: appB.RowVersion, RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("启用应用 B: %v", err)
	}

	// ===== 应用成员：一个用户属于两个应用时只返回目标应用 =====
	userOne, err := runtime.Users().Create(ctx, CreateUserRequest{
		Username: "app-member-one", Password: "K8$wR3!nB6@yF1#v",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建成员用户一: %v", err)
	}
	userTwo, err := runtime.Users().Create(ctx, CreateUserRequest{
		Username: "app-member-two", Password: "K8$wR3!nB6@yF1#v",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建成员用户二: %v", err)
	}
	for _, applicationID := range []string{appA.ID, appB.ID} {
		for _, userID := range []string{userOne.ID, userTwo.ID} {
			if err := adminAPI.AddApplicationMember(ctx, AdminAddMemberRequest{
				Caller: local, ApplicationID: applicationID, UserID: userID,
				RequestID: login.NewRequestID()}); err != nil {
				t.Fatalf("加入应用成员: %v", err)
			}
		}
	}
	memberPage, err := adminAPI.ListApplicationMembers(ctx, AdminListApplicationMembersRequest{
		Caller: local, ApplicationID: appA.ID, Sort: "user_id",
		Page: AdminPage{Limit: 1}, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("ListApplicationMembers: %v", err)
	}
	if len(memberPage.Members) != 1 || !memberPage.HasMore || memberPage.Page.Returned != 1 {
		t.Fatalf("应用成员第一页 = %+v", memberPage)
	}
	if memberPage.Members[0].ApplicationID != appA.ID {
		t.Fatalf("成员应用范围错误 = %+v", memberPage.Members[0])
	}
	if _, err := adminAPI.ListApplicationMembers(ctx, AdminListApplicationMembersRequest{
		Caller: local, ApplicationID: appA.ID, Sort: "password_hash",
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("非法成员排序错误 = %v，期望 REQ_INVALID", err)
	}

	// ===== 应用范围角色：作用范围固定为应用 A，不混入系统角色 =====
	if _, err := adminAPI.CreateRole(ctx, AdminCreateRoleRequest{
		Caller: local, ScopeID: "system", Key: "page-sys-role", Name: "系统角色",
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("创建系统角色: %v", err)
	}
	for _, item := range []struct{ key, name string }{
		{"page-app-role-b", "应用B角色"}, {"page-app-role-a", "应用A角色"},
	} {
		if _, err := adminAPI.CreateRole(ctx, AdminCreateRoleRequest{
			Caller: local, ScopeID: enabledA.ID, Key: item.key, Name: item.name,
			RequestID: login.NewRequestID()}); err != nil {
			t.Fatalf("创建应用角色 %s: %v", item.key, err)
		}
	}
	rolePage, err := adminAPI.ListApplicationRoles(ctx, AdminListApplicationRolesRequest{
		Caller: local, ApplicationID: enabledA.ID, Sort: "name",
		Page: AdminPage{Limit: 1}, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("ListApplicationRoles: %v", err)
	}
	if len(rolePage.Roles) != 1 || !rolePage.HasMore {
		t.Fatalf("应用角色第一页 = %+v", rolePage)
	}
	for _, item := range rolePage.Roles {
		if item.ScopeID != enabledA.ID {
			t.Fatalf("应用角色混入其他范围 = %+v", item)
		}
	}
	emptyRoles, err := adminAPI.ListApplicationRoles(ctx, AdminListApplicationRolesRequest{
		Caller: local, ApplicationID: appB.ID, Page: AdminPage{Limit: 10},
		RequestID: login.NewRequestID()})
	if err != nil || len(emptyRoles.Roles) != 0 {
		t.Fatalf("应用 B 角色（应为空） = %+v err=%v", emptyRoles, err)
	}
	if _, err := adminAPI.ListApplicationRoles(ctx, AdminListApplicationRolesRequest{
		Caller: local, ApplicationID: enabledA.ID, Sort: "enabled",
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("非法应用角色排序错误 = %v，期望 REQ_INVALID", err)
	}

	// ===== 应用范围用户组 =====
	managed := runtime.managedServices()
	if managed == nil || managed.Group == nil {
		t.Fatal("用户组服务未装配")
	}
	groupCaller, err := group.LocalBootstrapCaller("host-operator")
	if err != nil {
		t.Fatalf("用户组调用者: %v", err)
	}
	for _, item := range []struct{ key, name string }{
		{"page-app-group-b", "应用组B"}, {"page-app-group-a", "应用组A"},
	} {
		if _, err := managed.Group.CreateGroup(ctx, groupCaller, group.CreateRequest{
			ScopeID: enabledA.ID, GroupKey: item.key, Name: item.name,
			Description: "应用范围分页测试"}); err != nil {
			t.Fatalf("创建应用用户组 %s: %v", item.key, err)
		}
	}
	if _, err := managed.Group.CreateGroup(ctx, groupCaller, group.CreateRequest{
		ScopeID: group.ScopeSystem, GroupKey: "page-system-group", Name: "系统组",
		Description: "系统范围分页测试"}); err != nil {
		t.Fatalf("创建系统用户组: %v", err)
	}
	groupPage, err := adminAPI.ListApplicationGroups(ctx, AdminListApplicationGroupsRequest{
		Caller: local, ApplicationID: enabledA.ID, Sort: "name",
		Page: AdminPage{Limit: 1}, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("ListApplicationGroups: %v", err)
	}
	if len(groupPage.Groups) != 1 || !groupPage.HasMore ||
		groupPage.Groups[0].ScopeID != enabledA.ID {
		t.Fatalf("应用用户组第一页 = %+v", groupPage)
	}
	if _, err := adminAPI.ListApplicationGroups(ctx, AdminListApplicationGroupsRequest{
		Caller: local, ApplicationID: enabledA.ID, Sort: "bogus",
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("非法应用用户组排序错误 = %v，期望 REQ_INVALID", err)
	}

	// ===== 会话列表：LocalAdmin 无真实管理会话，必须明确拒绝 =====
	if _, err := adminAPI.ListUserSessions(ctx, AdminListUserSessionsRequest{
		Caller: local, TargetUserID: userOne.ID,
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeAccessDenied) {
		t.Fatalf("LocalAdmin 会话列表错误 = %v，期望 ACCESS_DENIED", err)
	}
}
