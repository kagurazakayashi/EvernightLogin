package app

// 步骤 220：有界分页迭代在真实运行时/真实 SQLite 上的多域夹具。
//
// 覆盖用户、用户组、角色（应用范围隔离）、应用与会话/设备列表；验证跨应用不
// 泄漏、线程内错误不吞、取消后不再请求下一页。所有资源使用临时目录与真实
// 领域服务，不使用测试替身填充生产装配。

import (
	"context"
	"errors"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/group"
)

// collectStrings 是通用字符串收集访问器。
type collectStrings struct {
	values []string
}

func (c *collectStrings) visit(_ context.Context, _ AdminPageInfo, items []string) error {
	c.values = append(c.values, items...)
	return nil
}

// countVisit 只统计条目数，用于取消/上限测试。
type countVisit struct {
	pages int
	items int
}

func (c *countVisit) visit(_ context.Context, _ AdminPageInfo, items []string) error {
	c.pages++
	c.items += len(items)
	return nil
}

// TestIterateAdminPagesRealRuntimeDomains 用真实临时 SQLite 遍历 216/217 的多个
// 公开列表，验证分页收全、跨应用隔离与请求边界。
func TestIterateAdminPagesRealRuntimeDomains(t *testing.T) {
	ctx := context.Background()
	runtime := openTestRuntime(t, Options{})
	admin := runtime.Admin()
	local := runtime.LocalAdmin()

	// 用户夹具：3 个真实注册用户（密码哈希真实、可登录）。
	users := make([]User, 0, 3)
	for _, username := range []string{"iter-user-a", "iter-user-b", "iter-user-c"} {
		created, err := runtime.Users().Create(ctx, CreateUserRequest{
			Username: username, Password: "K8$wR3!nB6@yF1#v", Nickname: username,
			RequestID: login.NewRequestID()})
		if err != nil {
			t.Fatalf("CreateUser(%s): %v", username, err)
		}
		users = append(users, created)
	}

	// 用户组夹具：3 个系统用户组（真实领域服务；列表只做只读分页）。
	var groups []group.Group
	for _, item := range []struct{ key, name string }{
		{"iter-group-alpha", "迭代 Alpha 组"}, {"iter-group-beta", "迭代 Beta 组"},
		{"iter-group-gamma", "迭代 Gamma 组"},
	} {
		caller, err := group.LocalBootstrapCaller("iter-operator")
		if err != nil {
			t.Fatalf("构造用户组调用者: %v", err)
		}
		created, err := runtime.managedServices().Group.CreateGroup(ctx, caller,
			group.CreateRequest{ScopeID: group.ScopeSystem, GroupKey: item.key,
				Name: item.name, Description: "步骤 220 迭代夹具"})
		if err != nil {
			t.Fatalf("CreateGroup(%s): %v", item.key, err)
		}
		groups = append(groups, created)
	}

	// 应用与角色夹具：应用 A 2 个角色、应用 B 1 个角色、系统 1 个角色。
	applicationA, err := admin.CreateApplication(ctx, AdminCreateApplicationRequest{
		Caller: local, Name: "Iter App A", OwnerUserID: users[0].ID,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("CreateApplication(A): %v", err)
	}
	applicationB, err := admin.CreateApplication(ctx, AdminCreateApplicationRequest{
		Caller: local, Name: "Iter App B", OwnerUserID: users[1].ID,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("CreateApplication(B): %v", err)
	}
	// 应用创建后默认停用；启用后才能登记应用范围角色/用户组。
	applicationA, err = admin.SetApplicationEnabled(ctx, AdminSetApplicationEnabledRequest{
		Caller: local, ApplicationID: applicationA.ID, Enabled: true,
		ExpectedRowVersion: applicationA.RowVersion, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("启用应用 A: %v", err)
	}
	applicationB, err = admin.SetApplicationEnabled(ctx, AdminSetApplicationEnabledRequest{
		Caller: local, ApplicationID: applicationB.ID, Enabled: true,
		ExpectedRowVersion: applicationB.RowVersion, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("启用应用 B: %v", err)
	}
	for _, item := range []struct {
		app  AdminApplication
		key  string
		name string
	}{
		{applicationA, "iter-role-a1", "A 角色一"}, {applicationA, "iter-role-a2", "A 角色二"},
		{applicationB, "iter-role-b1", "B 角色一"},
	} {
		if _, err := admin.CreateRole(ctx, AdminCreateRoleRequest{
			Caller: local, ScopeID: item.app.ID, Key: item.key, Name: item.name,
			RequestID: login.NewRequestID()}); err != nil {
			t.Fatalf("CreateRole(%s): %v", item.key, err)
		}
	}
	if _, err := admin.CreateRole(ctx, AdminCreateRoleRequest{
		Caller: local, ScopeID: "system", Key: "iter-role-sys", Name: "系统角色",
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("CreateRole(system): %v", err)
	}

	// 领域 1：用户列表。页大小 1，迭代器应取回全部 3 个用户且不重复。
	userCollector := &collectStrings{}
	userResult, err := IterateAdminPages(ctx,
		IterationOptions{Page: AdminPage{Limit: 1}},
		func(ctx context.Context, page AdminPage) ([]string, AdminPageInfo, error) {
			list, listErr := admin.ListUsers(ctx, AdminListUsersRequest{
				Caller: local, Limit: page.Limit, Offset: page.Offset,
				Sort: "username", RequestID: login.NewRequestID()})
			if listErr != nil {
				return nil, AdminPageInfo{}, listErr
			}
			ids := make([]string, 0, len(list.Users))
			for _, user := range list.Users {
				ids = append(ids, user.ID)
			}
			return ids, list.Page, nil
		}, userCollector.visit)
	if err != nil {
		t.Fatalf("用户列表迭代: %v", err)
	}
	if !userResult.Complete || userResult.Pages != 3 || len(userCollector.values) != 3 {
		t.Fatalf("用户列表迭代结果异常: %+v values=%+v", userResult, userCollector.values)
	}
	seenUsers := map[string]bool{}
	for _, id := range userCollector.values {
		if seenUsers[id] {
			t.Fatalf("用户列表迭代出现重复 ID: %s", id)
		}
		seenUsers[id] = true
	}

	// 领域 2：用户组列表。同样按 2 条分页，应恰好 3 个组。
	groupCollector := &collectStrings{}
	groupResult, err := IterateAdminPages(ctx,
		IterationOptions{Page: AdminPage{Limit: 2}},
		func(ctx context.Context, page AdminPage) ([]string, AdminPageInfo, error) {
			list, listErr := admin.ListGroups(ctx, AdminListGroupsRequest{
				Caller: local, Page: page, Sort: "key", RequestID: login.NewRequestID()})
			if listErr != nil {
				return nil, AdminPageInfo{}, listErr
			}
			keys := make([]string, 0, len(list.Groups))
			for _, item := range list.Groups {
				keys = append(keys, item.ID)
			}
			return keys, list.Page, nil
		}, groupCollector.visit)
	if err != nil {
		t.Fatalf("用户组列表迭代: %v", err)
	}
	if !groupResult.Complete || len(groupCollector.values) != len(groups) {
		t.Fatalf("用户组列表迭代结果异常: %+v values=%+v", groupResult, groupCollector.values)
	}

	// 领域 3：应用范围角色列表。应用 A 的角色迭代不能混入应用 B 或系统角色。
	roleCollector := &collectStrings{}
	roleResult, err := IterateAdminPages(ctx,
		IterationOptions{Page: AdminPage{Limit: 1}},
		func(ctx context.Context, page AdminPage) ([]string, AdminPageInfo, error) {
			list, listErr := admin.ListRoles(ctx, AdminListRolesRequest{
				Caller: local, ScopeID: applicationA.ID, Page: page, Sort: "key",
				RequestID: login.NewRequestID()})
			if listErr != nil {
				return nil, AdminPageInfo{}, listErr
			}
			keys := make([]string, 0, len(list.Roles))
			for _, item := range list.Roles {
				if item.ScopeID != applicationA.ID {
					t.Fatalf("应用 A 角色列表混入其他范围: %+v", item)
				}
				keys = append(keys, item.Key)
			}
			return keys, list.Page, nil
		}, roleCollector.visit)
	if err != nil {
		t.Fatalf("应用角色列表迭代: %v", err)
	}
	if !roleResult.Complete || len(roleCollector.values) != 2 {
		t.Fatalf("应用 A 角色数 = %+v，期望 2", roleCollector.values)
	}
	for _, key := range roleCollector.values {
		if key == "iter-role-b1" || key == "iter-role-sys" {
			t.Fatalf("应用 A 角色列表跨应用泄漏: %v", roleCollector.values)
		}
	}

	// 领域 4：应用列表（应用 A/B）。
	appCollector := &collectStrings{}
	appResult, err := IterateAdminPages(ctx,
		IterationOptions{Page: AdminPage{Limit: 1}},
		func(ctx context.Context, page AdminPage) ([]string, AdminPageInfo, error) {
			list, listErr := admin.ListApplications(ctx, AdminListApplicationsRequest{
				Caller: local, Page: page, Sort: "name", RequestID: login.NewRequestID()})
			if listErr != nil {
				return nil, AdminPageInfo{}, listErr
			}
			ids := make([]string, 0, len(list.Applications))
			for _, item := range list.Applications {
				ids = append(ids, item.ID)
			}
			return ids, list.Page, nil
		}, appCollector.visit)
	if err != nil {
		t.Fatalf("应用列表迭代: %v", err)
	}
	if !appResult.Complete || len(appCollector.values) != 2 {
		t.Fatalf("应用列表迭代结果异常: %+v values=%+v", appResult, appCollector.values)
	}

	// 领域 5：本人会话/设备列表。登录真实用户后应有 1 个当前设备。
	loginResult, err := runtime.Auth().Login(ctx, LoginRequest{
		Username: users[0].Username, Password: "K8$wR3!nB6@yF1#v",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("登录夹具用户: %v", err)
	}
	deviceCollector := &countVisit{}
	deviceResult, err := IterateAdminPages(ctx,
		IterationOptions{Page: AdminPage{Limit: 1}},
		func(ctx context.Context, page AdminPage) ([]string, AdminPageInfo, error) {
			list, listErr := runtime.Sessions().ListDevices(ctx, SessionDeviceRequest{
				SessionSecret: loginResult.SessionSecret, Page: page})
			if listErr != nil {
				return nil, AdminPageInfo{}, listErr
			}
			ids := make([]string, 0, len(list.Devices))
			for _, item := range list.Devices {
				ids = append(ids, item.ID)
			}
			return ids, list.Page, nil
		}, deviceCollector.visit)
	if err != nil {
		t.Fatalf("设备列表迭代: %v", err)
	}
	if !deviceResult.Complete || deviceCollector.items != 1 {
		t.Fatalf("设备列表迭代结果异常: %+v visit=%+v", deviceResult, deviceCollector)
	}

	// 错误注入：第 2 页读取失败时，第 1 页已交付、错误向上返回、不再继续。
	sentinel := errors.New("注入的用户列表第 2 页故障")
	userFetchCalls := 0
	partialCollector := &countVisit{}
	_, err = IterateAdminPages(ctx, IterationOptions{Page: AdminPage{Limit: 1}},
		func(ctx context.Context, page AdminPage) ([]string, AdminPageInfo, error) {
			userFetchCalls++
			if userFetchCalls == 2 {
				return nil, AdminPageInfo{}, sentinel
			}
			list, listErr := admin.ListUsers(ctx, AdminListUsersRequest{
				Caller: local, Limit: page.Limit, Offset: page.Offset,
				Sort: "username", RequestID: login.NewRequestID()})
			if listErr != nil {
				return nil, AdminPageInfo{}, listErr
			}
			return []string{list.Users[0].ID}, list.Page, nil
		}, partialCollector.visit)
	if !errors.Is(err, sentinel) {
		t.Fatalf("中途错误未向上返回: %v", err)
	}
	if partialCollector.pages != 1 || userFetchCalls != 2 {
		t.Fatalf("错误注入部分语义异常: visit=%+v fetchCalls=%d",
			partialCollector, userFetchCalls)
	}

	// 取消：第 1 页 visit 后取消，不得再请求第 2 页。
	cancelCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cancelFetchCalls := 0
	cancelled, err := IterateAdminPages(cancelCtx,
		IterationOptions{Page: AdminPage{Limit: 1}},
		func(ctx context.Context, page AdminPage) ([]string, AdminPageInfo, error) {
			cancelFetchCalls++
			list, listErr := admin.ListUsers(ctx, AdminListUsersRequest{
				Caller: local, Limit: page.Limit, Offset: page.Offset,
				Sort: "username", RequestID: login.NewRequestID()})
			if listErr != nil {
				return nil, AdminPageInfo{}, listErr
			}
			return []string{list.Users[0].ID}, list.Page, nil
		},
		func(_ context.Context, _ AdminPageInfo, _ []string) error {
			cancel()
			return nil
		})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("取消后错误 = %v，期望 context.Canceled", err)
	}
	if cancelFetchCalls != 1 || cancelled.StopReason != IterationStopContextCanceled {
		t.Fatalf("取消后仍翻页: calls=%d result=%+v", cancelFetchCalls, cancelled)
	}
}
