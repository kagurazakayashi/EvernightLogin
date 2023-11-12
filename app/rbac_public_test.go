// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package app

// 步骤 224 公开 RBAC 服务定向测试（P0：角色/组/权限/授权查询与拒绝路径）。

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

// TestRBACRoleLifecycleAndRootProtection 覆盖角色创建/读取/更新/启停/删除与 root 拒绝。
func TestRBACRoleLifecycleAndRootProtection(t *testing.T) {
	env := newRBACTestEnv(t)
	ctx := context.Background()
	roles := env.runtime.RBAC().Roles()

	role := env.createRole(t, "system", "rbac-lifecycle", "生命周期角色")
	got, err := roles.Get(ctx, RBACRoleRequest{Caller: env.local, RoleID: role.ID,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Key != "rbac-lifecycle" || !got.Enabled || got.ScopeID != "system" {
		t.Fatalf("角色视图异常: %+v", got)
	}
	updated, err := roles.Update(ctx, RBACUpdateRoleRequest{Caller: env.local,
		RoleID: role.ID, Name: "改名角色", Description: "说明", Limits: "限制",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Name != "改名角色" {
		t.Fatalf("更新后名称 = %q", updated.Name)
	}
	disabled, err := roles.Disable(ctx, RBACRoleStateRequest{Caller: env.local,
		RoleID: role.ID, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if disabled.Enabled {
		t.Fatal("停用后 Enabled 应为 false")
	}
	enabled, err := roles.Enable(ctx, RBACRoleStateRequest{Caller: env.local,
		RoleID: role.ID, RequestID: login.NewRequestID()})
	if err != nil || !enabled.Enabled {
		t.Fatalf("Enable: %+v err=%v", enabled, err)
	}

	// root 不能被普通角色分配。
	root, err := env.runtime.Bootstrap().EnsureRoot(ctx, RootRequest{
		DisplayName: "Root", Password: "V7!qZ2#Lm9@Tp4$x",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("EnsureRoot: %v", err)
	}
	assignErr := roles.AssignUser(ctx, GrantRoleRequest{Caller: env.local,
		UserID: root.UserID, RoleID: role.ID, RequestID: login.NewRequestID()})
	if assignErr == nil {
		t.Fatal("把角色分配给 root 必须拒绝")
	}
	if code := asRBACAppError(t, assignErr).Code(); code != login.CodeAccessDenied {
		t.Fatalf("root 分配错误码 = %q，期望 ACCESS_DENIED", code)
	}

	if err := roles.Delete(ctx, RBACRoleRequest{Caller: env.local, RoleID: role.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, err = roles.Get(ctx, RBACRoleRequest{Caller: env.local, RoleID: role.ID,
		RequestID: login.NewRequestID()})
	if !IsNotFound(err) {
		t.Fatalf("删除后 Get 应为 NOT_FOUND，实际 %v", err)
	}
}

// TestRBACRolePermissionCompositionAndRevocation 覆盖组合权限、分配与撤权即时生效。
func TestRBACRolePermissionCompositionAndRevocation(t *testing.T) {
	env := newRBACTestEnv(t)
	ctx := context.Background()
	roles := env.runtime.RBAC().Roles()
	authorization := env.runtime.RBAC().Authorization()

	user := env.createUser(t, "rbac-composed")
	permission := env.createPermission(t, "system", "rbac.composed.read", "组合读取")
	role := env.createRole(t, "system", "rbac-composed", "组合角色")
	env.addPermission(t, role.ID, permission.ID)
	env.grantRole(t, user.ID, role.ID)

	check, err := authorization.Check(ctx, RBACCheckRequest{Caller: env.local,
		SubjectUserID: user.ID, ScopeID: "system",
		Permissions: []string{"rbac.composed.read"}, RequestID: login.NewRequestID()})
	if err != nil || !check.Allowed {
		t.Fatalf("组合授权后 Check 应允许: %+v err=%v", check, err)
	}

	// 移除角色权限后立即拒绝（无缓存旧授权）。
	if err := roles.RemovePermission(ctx, RBACRolePermissionRemoveRequest{Caller: env.local,
		RoleID: role.ID, PermissionID: permission.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("RemovePermission: %v", err)
	}
	check, err = authorization.Check(ctx, RBACCheckRequest{Caller: env.local,
		SubjectUserID: user.ID, ScopeID: "system",
		Permissions: []string{"rbac.composed.read"}, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("撤权后 Check 错误: %v", err)
	}
	if check.Allowed {
		t.Fatalf("移除角色权限后 Check 必须拒绝: %+v", check)
	}

	// 撤销角色分配同样立即生效。
	env.addPermission(t, role.ID, permission.ID)
	env.grantRole(t, user.ID, role.ID)
	if err := roles.RevokeUser(ctx, RevokeRoleRequest{Caller: env.local, UserID: user.ID,
		RoleID: role.ID, RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("RevokeUser: %v", err)
	}
	check, err = authorization.Check(ctx, RBACCheckRequest{Caller: env.local,
		SubjectUserID: user.ID, ScopeID: "system",
		Permissions: []string{"rbac.composed.read"}, RequestID: login.NewRequestID()})
	if err != nil || check.Allowed {
		t.Fatalf("撤销角色分配后 Check 必须拒绝: %+v err=%v", check, err)
	}
}

// TestRBACGroupLifecycleAndMembers 覆盖用户组与成员批量变更。
func TestRBACGroupLifecycleAndMembers(t *testing.T) {
	env := newRBACTestEnv(t)
	ctx := context.Background()
	groups := env.runtime.RBAC().Groups()
	first := env.createUser(t, "rbac-group-a")
	second := env.createUser(t, "rbac-group-b")

	created, err := groups.Create(ctx, RBACCreateGroupRequest{Caller: env.local,
		ScopeID: "system", Key: "rbac-group", Name: "RBAC 用户组", Description: "说明",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.Key != "rbac-group" || created.ScopeID != "system" {
		t.Fatalf("组视图异常: %+v", created)
	}
	result, err := groups.AddMembers(ctx, RBACGroupMemberBatchRequest{Caller: env.local,
		GroupID: created.ID, UserIDs: []string{first.ID, second.ID},
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("AddMembers: %v", err)
	}
	if result.Added != 2 {
		t.Fatalf("加入成员数 = %d，期望 2", result.Added)
	}
	// 重复加入幂等：Skipped 计入，不报错。
	result, err = groups.AddMembers(ctx, RBACGroupMemberBatchRequest{Caller: env.local,
		GroupID: created.ID, UserIDs: []string{first.ID}, RequestID: login.NewRequestID()})
	if err != nil || result.Skipped != 1 {
		t.Fatalf("重复加入应幂等跳过: %+v err=%v", result, err)
	}
	members, err := groups.ListMembers(ctx, AdminListGroupMembersRequest{Caller: env.local,
		GroupID: created.ID, Page: AdminPage{Limit: 10},
		RequestID: login.NewRequestID()})
	if err != nil || len(members.Members) != 2 {
		t.Fatalf("成员列表 = %+v err=%v", members, err)
	}
	if _, err := groups.RemoveMembers(ctx, RBACGroupMemberBatchRequest{Caller: env.local,
		GroupID: created.ID, UserIDs: []string{first.ID},
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("RemoveMembers: %v", err)
	}
	updated, err := groups.Update(ctx, RBACUpdateGroupRequest{Caller: env.local,
		GroupID: created.ID, Name: "改名用户组", Description: "新说明",
		RequestID: login.NewRequestID()})
	if err != nil || updated.Name != "改名用户组" {
		t.Fatalf("Update: %+v err=%v", updated, err)
	}
	if err := groups.Delete(ctx, RBACGroupRequest{Caller: env.local, GroupID: created.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

// TestRBACPermissionScopeIsolation 覆盖自定义权限只能在自己的 scope 生效。
func TestRBACPermissionScopeIsolation(t *testing.T) {
	env := newRBACTestEnv(t)
	ctx := context.Background()
	permissions := env.runtime.RBAC().Permissions()

	appA, err := env.admin.CreateApplication(ctx, AdminCreateApplicationRequest{
		Caller: env.local, Name: "RBAC App A", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建应用 A: %v", err)
	}
	appB, err := env.admin.CreateApplication(ctx, AdminCreateApplicationRequest{
		Caller: env.local, Name: "RBAC App B", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建应用 B: %v", err)
	}
	for _, application := range []AdminApplication{appA, appB} {
		if _, err := env.admin.SetApplicationEnabled(ctx, AdminSetApplicationEnabledRequest{
			Caller: env.local, ApplicationID: application.ID, Enabled: true,
			ExpectedRowVersion: application.RowVersion,
			RequestID:          login.NewRequestID()}); err != nil {
			t.Fatalf("启用应用: %v", err)
		}
	}
	permissionA := env.createPermission(t, appA.ID, "rbac.scoped.read", "A 读取")
	permissionB := env.createPermission(t, appB.ID, "rbac.scoped.read", "B 读取")
	for _, item := range []struct {
		id      string
		scopeID string
	}{{permissionA.ID, appA.ID}, {permissionB.ID, appB.ID}} {
		got, err := permissions.Get(ctx, RBACPermissionRequest{Caller: env.local,
			PermissionID: item.id, RequestID: login.NewRequestID()})
		if err != nil {
			t.Fatalf("Get 权限: %v", err)
		}
		if got.ScopeID != item.scopeID {
			t.Fatalf("权限 %s scope = %q，期望 %q", item.id, got.ScopeID, item.scopeID)
		}
	}
	// 删除自定义权限成功（无引用）。
	if err := permissions.Delete(ctx, RBACPermissionRequest{Caller: env.local,
		PermissionID: permissionA.ID, RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("Delete 自定义权限: %v", err)
	}
}

// TestRBACAuthorizationCrossAppAndRevoke 覆盖跨应用隔离、来源查询、资源判定与撤权。
func TestRBACAuthorizationCrossAppAndRevoke(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 6, 30, 0, 0, time.UTC))
	evidence := setupStep208Evidence(t, ctx, clock, t.TempDir(), testConfig())
	runtime := evidence.runtime
	local := runtime.LocalAdmin()
	authorization := runtime.RBAC().Authorization()

	check, err := authorization.Check(ctx, RBACCheckRequest{Caller: local,
		SubjectUserID: evidence.member.ID, ScopeID: evidence.appA.ID,
		Permissions: []string{"invoice.read"}, RequestID: login.NewRequestID()})
	if err != nil || !check.Allowed {
		t.Fatalf("应用 A 应允许 invoice.read: %+v err=%v", check, err)
	}
	// 应用 B 没有该权限：同名键不得回退到应用 A。
	check, err = authorization.Check(ctx, RBACCheckRequest{Caller: local,
		SubjectUserID: evidence.member.ID, ScopeID: evidence.appB.ID,
		Permissions: []string{"invoice.read"}, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("应用 B Check 错误: %v", err)
	}
	if check.Allowed {
		t.Fatalf("跨应用同名权限必须隔离，应用 B 不允许: %+v", check)
	}

	effective, err := authorization.EffectivePermissions(ctx,
		RBACEffectiveRequest{Caller: local, SubjectUserID: evidence.member.ID,
			ScopeID: evidence.appA.ID, Page: AdminPage{Limit: 20},
			RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("EffectivePermissions: %v", err)
	}
	if len(effective.Permissions) == 0 {
		t.Fatal("应用 A 有效权限不应为空")
	}
	sources, err := authorization.PermissionSources(ctx,
		RBACPermissionSourcesRequest{Caller: local, SubjectUserID: evidence.member.ID,
			ScopeID: evidence.appA.ID, PermissionKey: "invoice.read",
			Page: AdminPage{Limit: 20}, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("PermissionSources: %v", err)
	}
	if !sources.PermissionFound || len(sources.Sources) == 0 {
		t.Fatalf("权限来源异常: %+v", sources)
	}
	resource, err := authorization.CheckResourceAccess(ctx,
		RBACResourceAccessRequest{Caller: local, SubjectUserID: evidence.member.ID,
			ScopeID: evidence.appA.ID, PermissionKey: "invoice.read",
			ResourceID: "invoice-1", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("CheckResourceAccess: %v", err)
	}
	// 历史/未声明数据范围按 fail-closed 拒绝资源访问（不是先允许再过滤）。
	if resource.Allowed || resource.Code != "RESOURCE_FORBIDDEN" {
		t.Fatalf("未声明数据范围必须拒绝资源: %+v", resource)
	}

	// 移除角色权限后，来源/有效权限/资源判定都立即拒绝。
	if err := runtime.RBAC().Roles().RemovePermission(ctx, RBACRolePermissionRemoveRequest{
		Caller: local, RoleID: evidence.role.ID, PermissionID: evidence.permission.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("RemovePermission: %v", err)
	}
	check, err = authorization.Check(ctx, RBACCheckRequest{Caller: local,
		SubjectUserID: evidence.member.ID, ScopeID: evidence.appA.ID,
		Permissions: []string{"invoice.read"}, RequestID: login.NewRequestID()})
	if err != nil || check.Allowed {
		t.Fatalf("撤权后必须拒绝: %+v err=%v", check, err)
	}
}

// TestRBACAuditFailureFailsClosed 覆盖关键写操作审计故障时业务回滚/拒绝。
func TestRBACAuditFailureFailsClosed(t *testing.T) {
	env := newRBACTestEnv(t)
	ctx := context.Background()
	roles := env.runtime.RBAC().Roles()
	env.injectAuditFailure(t)
	t.Cleanup(func() {
		env.clearAuditFailure(t)
	})

	_, err := roles.Create(ctx, AdminCreateRoleRequest{Caller: env.local,
		ScopeID: "system", Key: "rbac-audit-fail", Name: "审计故障角色",
		RequestID: login.NewRequestID()})
	if err == nil {
		t.Fatal("审计故障时创建角色必须失败")
	}
	if code := asRBACAppError(t, err).Code(); code != login.CodeAuditWriteFailed {
		t.Fatalf("审计故障错误码 = %q，期望 AUDIT_WRITE_FAILED", code)
	}
	env.clearAuditFailure(t)
	// 恢复后同名创建成功，证明无部分写入。
	if _, err := roles.Create(ctx, AdminCreateRoleRequest{Caller: env.local,
		ScopeID: "system", Key: "rbac-audit-fail", Name: "审计故障角色",
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("撤销审计故障后创建应成功: %v", err)
	}
}

// TestRBACRestrictedSessionRejected 覆盖受限会话不能执行 RBAC 查询/写操作。
func TestRBACRestrictedSessionRejected(t *testing.T) {
	env := newRBACTestEnv(t)
	ctx := context.Background()
	const password = "K8$wR3!nB6@yF1#v"
	restricted := env.restrictedSession(t, "rbac-restricted", password)
	caller := env.runtime.AdminSession(restricted)
	_, err := env.runtime.RBAC().Roles().List(ctx, AdminListRolesRequest{Caller: caller,
		Page: AdminPage{Limit: 10}, RequestID: login.NewRequestID()})
	if err == nil {
		t.Fatal("受限会话不应能查询角色")
	}
	if code := asRBACAppError(t, err).Code(); code != login.CodeAccessDenied {
		t.Fatalf("受限会话错误码 = %q，期望 ACCESS_DENIED", code)
	}
}

// TestRBACListPaginationAndIterate 覆盖分页边界与 220 有界迭代。
func TestRBACListPaginationAndIterate(t *testing.T) {
	env := newRBACTestEnv(t)
	ctx := context.Background()
	roles := env.runtime.RBAC().Roles()
	for index := 0; index < 3; index++ {
		env.createRole(t, "system",
			fmt.Sprintf("rbac_page_%d", index), "分页角色")
	}
	first, err := roles.List(ctx, AdminListRolesRequest{Caller: env.local,
		Page: AdminPage{Limit: 1}, RequestID: login.NewRequestID()})
	if err != nil || len(first.Roles) != 1 || !first.HasMore {
		t.Fatalf("第一页异常: %+v err=%v", first, err)
	}
	last, err := roles.List(ctx, AdminListRolesRequest{Caller: env.local,
		Page: AdminPage{Limit: 10}, RequestID: login.NewRequestID()})
	if err != nil || last.HasMore {
		t.Fatalf("末页 HasMore 应为 false: %+v err=%v", last, err)
	}
	seen := map[string]struct{}{}
	result, err := IterateAdminPages(ctx, IterationOptions{Page: AdminPage{Limit: 1}},
		func(ctx context.Context, page AdminPage) ([]string, AdminPageInfo, error) {
			list, listErr := roles.List(ctx, AdminListRolesRequest{Caller: env.local,
				Page: page, RequestID: login.NewRequestID()})
			if listErr != nil {
				return nil, AdminPageInfo{}, listErr
			}
			ids := make([]string, 0, len(list.Roles))
			for _, item := range list.Roles {
				ids = append(ids, item.ID)
			}
			return ids, list.Page, nil
		},
		func(_ context.Context, _ AdminPageInfo, items []string) error {
			for _, id := range items {
				seen[id] = struct{}{}
			}
			return nil
		})
	if err != nil {
		t.Fatalf("IterateAdminPages: %v", err)
	}
	if result.StopReason != IterationStopComplete || len(seen) < 3 {
		t.Fatalf("迭代结果异常: %+v seen=%d", result, len(seen))
	}
}

// TestRBACPermissionBuiltinProtection 验证内置权限不可删除、只能按规则停用，且
// root_only 内置权限不能被普通管理会话启停。
func TestRBACPermissionBuiltinProtection(t *testing.T) {
	env := newRBACTestEnv(t)
	ctx := context.Background()
	permissions := env.runtime.RBAC().Permissions()
	builtinID := env.seedBuiltinPermission(t, "builtin.demo.read", false)
	rootOnlyID := env.seedBuiltinPermission(t, "builtin.root.read", true)

	got, err := permissions.Get(ctx, RBACPermissionRequest{Caller: env.local,
		PermissionID: builtinID, RequestID: login.NewRequestID()})
	if err != nil || !got.IsBuiltin {
		t.Fatalf("内置权限视图异常: %+v err=%v", got, err)
	}
	if err := permissions.Delete(ctx, RBACPermissionRequest{Caller: env.local,
		PermissionID: builtinID, RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("删除内置权限必须拒绝")
	} else if code := asRBACAppError(t, err).Code(); code != login.CodeAccessDenied {
		t.Fatalf("删除内置权限错误码 = %q，期望 ACCESS_DENIED", code)
	}
	disabled, err := permissions.Disable(ctx, RBACPermissionRequest{Caller: env.local,
		PermissionID: builtinID, RequestID: login.NewRequestID()})
	if err != nil || disabled.Enabled {
		t.Fatalf("内置权限按规则停用失败: %+v err=%v", disabled, err)
	}
	if _, err := permissions.Enable(ctx, RBACPermissionRequest{Caller: env.local,
		PermissionID: builtinID, RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("内置权限重新启用失败: %v", err)
	}

	// root_only 内置权限：普通管理会话（只持有权限目录读取）不能停用。
	adminCaller := env.systemAdminSession(t, "rbac-rootonly-admin", "permissions.read")
	if _, err := permissions.Disable(ctx, RBACPermissionRequest{Caller: adminCaller,
		PermissionID: rootOnlyID, RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("普通管理会话停用 root_only 内置权限必须拒绝")
	}
}

// TestRBACInvalidRequestIDRejected 验证请求编号非法时在任何领域调用前拒绝。
func TestRBACInvalidRequestIDRejected(t *testing.T) {
	env := newRBACTestEnv(t)
	_, err := env.runtime.RBAC().Roles().List(context.Background(),
		AdminListRolesRequest{Caller: env.local, Page: AdminPage{Limit: 10},
			RequestID: "bad id!"})
	if err == nil {
		t.Fatal("非法请求编号必须拒绝")
	}
	var appError *login.AppError
	if !errors.As(err, &appError) || appError.Code() != login.CodeReqInvalid {
		t.Fatalf("非法请求编号错误 = %v，期望 REQ_INVALID", err)
	}
}
