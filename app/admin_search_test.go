package app

// 步骤 261：公开管理门面（Go API）用户/应用成员列表搜索契约测试。
//   - AdminListUsersRequest.Search/SearchFields 透传到账户领域：字面子串、NFKC/
//     大小写折叠、通配符字面、空搜索保持原列表、未知字段/超长 REQ_INVALID；
//   - AdminListApplicationMembersRequest.Search 只在目标应用成员范围内匹配成员的
//     全局用户名/昵称，不能跨应用枚举；
//   - 模糊搜索不影响 GetUserByUsername 的精确语义。

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

// TestAdminListUsersSearch 验收公开 Go 门面的用户列表搜索。
func TestAdminListUsersSearch(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 26, 3, 0, 0, 0, time.UTC))
	runtime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	adminAPI := runtime.Admin()
	local := runtime.LocalAdmin()
	alice := step207CreateProblemUser(t, ctx, runtime, "alice")
	step207CreateProblemUser(t, ctx, runtime, "bob")

	search := func(request AdminListUsersRequest) AdminUserList {
		t.Helper()
		request.Caller = local
		request.RequestID = login.NewRequestID()
		page, err := adminAPI.ListUsers(ctx, request)
		if err != nil {
			t.Fatalf("ListUsers(%+v): %v", request.Search, err)
		}
		return page
	}
	page := search(AdminListUsersRequest{Limit: 10, Search: "ALI"})
	if len(page.Users) != 1 || page.Users[0].ID != alice.ID {
		t.Fatalf("大小写折叠搜索结果 = %+v", page.Users)
	}
	// 只搜昵称字段（夹具昵称=用户名）。
	page = search(AdminListUsersRequest{Limit: 10, Search: "bob",
		SearchFields: []string{"nickname"}})
	if len(page.Users) != 1 || page.Users[0].Username != "bob" {
		t.Fatalf("昵称字段搜索结果 = %+v", page.Users)
	}
	// LIKE 通配符按字面：`%` 不会命中所有用户。
	if page = search(AdminListUsersRequest{Limit: 10, Search: "%"}); len(page.Users) != 0 {
		t.Fatalf("通配符字面搜索结果 = %+v", page.Users)
	}
	// 空搜索保持原列表。
	if page = search(AdminListUsersRequest{Limit: 10, Search: "  "}); len(page.Users) != 2 {
		t.Fatalf("空搜索结果数 = %d，期望 2", len(page.Users))
	}
	// 未知字段与超长搜索返回 REQ_INVALID。
	if _, err := adminAPI.ListUsers(ctx, AdminListUsersRequest{
		Caller: local, Limit: 10, Search: "x",
		SearchFields: []string{"email"}, RequestID: login.NewRequestID(),
	}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("邮箱字段错误 = %v，期望 REQ_INVALID", err)
	}
	if _, err := adminAPI.ListUsers(ctx, AdminListUsersRequest{
		Caller: local, Limit: 10, Search: strings.Repeat("a", 65),
		RequestID: login.NewRequestID(),
	}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("超长搜索错误 = %v，期望 REQ_INVALID", err)
	}
	// 精确查询语义不变：ali 是模糊匹配才命中，精确查找必须未找到。
	if _, err := adminAPI.GetUserByUsername(ctx, AdminUserByUsernameRequest{
		Caller: local, Username: "ali", RequestID: login.NewRequestID(),
	}); !IsNotFound(err) {
		t.Fatalf("GetUserByUsername(ali) 错误 = %v，期望 NOT_FOUND（必须保持精确）", err)
	}
	if _, err := adminAPI.GetUserByUsername(ctx, AdminUserByUsernameRequest{
		Caller: local, Username: "ALICE", RequestID: login.NewRequestID(),
	}); err != nil {
		t.Fatalf("GetUserByUsername 精确匹配大小写折叠失败: %v", err)
	}
}

// TestAdminListApplicationMembersSearch 验收公开 Go 门面的应用成员搜索。
func TestAdminListApplicationMembersSearch(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 26, 3, 10, 0, 0, time.UTC))
	runtime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	adminAPI := runtime.Admin()
	local := runtime.LocalAdmin()

	created, err := adminAPI.CreateApplication(ctx, AdminCreateApplicationRequest{
		Caller: local, Name: "SearchApp", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	if _, err := adminAPI.SetApplicationEnabled(ctx, AdminSetApplicationEnabledRequest{
		Caller: local, ApplicationID: created.ID, Enabled: true,
		ExpectedRowVersion: created.RowVersion, RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("启用应用: %v", err)
	}
	memberOne, err := runtime.Users().Create(ctx, CreateUserRequest{
		Username: "app-member-one", Password: "K8$wR3!nB6@yF1#v",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建成员一: %v", err)
	}
	memberTwo, err := runtime.Users().Create(ctx, CreateUserRequest{
		Username: "app-member-two", Password: "K8$wR3!nB6@yF1#v",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建成员二: %v", err)
	}
	for _, userID := range []string{memberOne.ID, memberTwo.ID} {
		if err := adminAPI.AddApplicationMember(ctx, AdminAddMemberRequest{
			Caller: local, ApplicationID: created.ID, UserID: userID,
			RequestID: login.NewRequestID()}); err != nil {
			t.Fatalf("加入应用成员: %v", err)
		}
	}
	search := func(request AdminListApplicationMembersRequest) AdminApplicationMemberList {
		t.Helper()
		request.Caller = local
		request.ApplicationID = created.ID
		request.RequestID = login.NewRequestID()
		page, listErr := adminAPI.ListApplicationMembers(ctx, request)
		if listErr != nil {
			t.Fatalf("ListApplicationMembers(%+v): %v", request.Search, listErr)
		}
		return page
	}
	// 大小写折叠 + 字面子串，只在目标应用成员范围内。
	page := search(AdminListApplicationMembersRequest{Page: AdminPage{Limit: 10}, Search: "MEMBER-ONE"})
	if len(page.Members) != 1 || page.Members[0].UserID != memberOne.ID {
		t.Fatalf("成员搜索结果 = %+v", page.Members)
	}
	// 分页与搜索组合。
	page = search(AdminListApplicationMembersRequest{Page: AdminPage{Limit: 1}, Search: "member"})
	if len(page.Members) != 1 || !page.HasMore {
		t.Fatalf("成员搜索分页 = %+v", page)
	}
	// 通配符按字面、空搜索保持原列表。
	if page = search(AdminListApplicationMembersRequest{Page: AdminPage{Limit: 10}, Search: "%"}); len(page.Members) != 0 {
		t.Fatalf("成员通配符字面搜索 = %+v", page.Members)
	}
	if page = search(AdminListApplicationMembersRequest{Page: AdminPage{Limit: 10}}); len(page.Members) != 2 {
		t.Fatalf("空搜索成员数 = %d，期望 2", len(page.Members))
	}
	// 未知搜索字段 REQ_INVALID。
	if _, err := adminAPI.ListApplicationMembers(ctx, AdminListApplicationMembersRequest{
		Caller: local, ApplicationID: created.ID, Page: AdminPage{Limit: 10}, Search: "x",
		SearchFields: []string{"phone"}, RequestID: login.NewRequestID(),
	}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("成员搜索未知字段错误 = %v，期望 REQ_INVALID", err)
	}
}
