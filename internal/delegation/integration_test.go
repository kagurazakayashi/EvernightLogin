package delegation_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	appsqlite "github.com/kagurazakayashi/EvernightLogin/internal/app/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
	"github.com/kagurazakayashi/EvernightLogin/internal/group"
	groupsqlite "github.com/kagurazakayashi/EvernightLogin/internal/group/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/permission"
	permissionsqlite "github.com/kagurazakayashi/EvernightLogin/internal/permission/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/role"
	rolesqlite "github.com/kagurazakayashi/EvernightLogin/internal/role/sqlite"
)

// integrationEnv 用真实委派检查器装配四个可能改变有效权限的领域服务，验证每条
// 写入路径都经过同一检查。
type integrationEnv struct {
	*testEnv
	roleService       *role.Service
	groupService      *group.Service
	appService        *app.Service
	permissionService *permission.Service

	roleAdmin       role.Caller
	roleLocal       role.Caller
	groupAdmin      group.Caller
	groupLocal      group.Caller
	appAdmin        app.Caller
	appLocal        app.Caller
	permissionAdmin permission.Caller
	permissionLocal permission.Caller
}

func prepareIntegrationEnv(t *testing.T) *integrationEnv {
	t.Helper()
	env := &integrationEnv{testEnv: prepareEnv(t)}
	discard := slog.New(slog.NewTextHandler(io.Discard, nil))

	roleAuthorizer, err := role.NewStaticAuthorizer(role.AuthorizerOptions{
		LocalAdminIDs: []string{"operator-1"}, SystemIDs: []string{"system-1"},
	})
	if err != nil {
		t.Fatalf("构造角色授权器失败: %v", err)
	}
	if err := roleAuthorizer.AssignApplicationAdmin(testAppOne, testAdmin); err != nil {
		t.Fatalf("分配应用角色管理员失败: %v", err)
	}
	roleStore, err := rolesqlite.New(env.raw)
	if err != nil {
		t.Fatalf("构造角色存储失败: %v", err)
	}
	env.roleService, err = role.New(role.Options{
		Store: roleStore, Audit: env.recorder, Authorizer: roleAuthorizer, Transfers: env.service,
		Now: env.clock.Now, Logger: discard,
	})
	if err != nil {
		t.Fatalf("构造角色服务失败: %v", err)
	}

	groupAuthorizer, err := group.NewStaticAuthorizer(group.AuthorizerOptions{
		LocalAdminIDs: []string{"operator-1"}, SystemIDs: []string{"system-1"},
	})
	if err != nil {
		t.Fatalf("构造用户组授权器失败: %v", err)
	}
	if err := groupAuthorizer.AssignApplicationAdmin(testAppOne, testAdmin); err != nil {
		t.Fatalf("分配应用用户组管理员失败: %v", err)
	}
	groupStore, err := groupsqlite.New(env.raw)
	if err != nil {
		t.Fatalf("构造用户组存储失败: %v", err)
	}
	env.groupService, err = group.New(group.Options{
		Store: groupStore, Audit: env.recorder, Authorizer: groupAuthorizer, Transfers: env.service,
		Now: env.clock.Now, Logger: discard,
	})
	if err != nil {
		t.Fatalf("构造用户组服务失败: %v", err)
	}

	appAuthorizer, err := app.NewStaticAuthorizer(app.AuthorizerOptions{
		LocalAdminIDs: []string{"operator-1"}, SystemIDs: []string{"system-1"},
	})
	if err != nil {
		t.Fatalf("构造应用授权器失败: %v", err)
	}
	if err := appAuthorizer.AssignApplicationAdmin(testAppOne, testAdmin); err != nil {
		t.Fatalf("分配应用管理员失败: %v", err)
	}
	// 应用二同样指派管理员，供启用应用的正向用例使用。
	if err := appAuthorizer.AssignApplicationAdmin(testAppTwo, testAdmin); err != nil {
		t.Fatalf("分配应用二管理员失败: %v", err)
	}
	appStore, err := appsqlite.New(env.raw)
	if err != nil {
		t.Fatalf("构造应用存储失败: %v", err)
	}
	env.appService, err = app.New(app.Options{
		Store: appStore, Audit: env.recorder, Authorizer: appAuthorizer, Transfers: env.service,
		Now: env.clock.Now, Logger: discard,
	})
	if err != nil {
		t.Fatalf("构造应用服务失败: %v", err)
	}

	permissionAuthorizer, err := permission.NewStaticAuthorizer(permission.AuthorizerOptions{
		LocalAdminIDs: []string{"operator-1"}, SystemIDs: []string{"system-1"},
	})
	if err != nil {
		t.Fatalf("构造权限授权器失败: %v", err)
	}
	if err := permissionAuthorizer.AssignApplicationAdmin(testAppOne, testAdmin); err != nil {
		t.Fatalf("分配应用权限管理员失败: %v", err)
	}
	permissionStore, err := permissionsqlite.New(env.raw)
	if err != nil {
		t.Fatalf("构造权限存储失败: %v", err)
	}
	env.permissionService, err = permission.New(permission.Options{
		Store: permissionStore, Audit: env.recorder, Authorizer: permissionAuthorizer, Transfers: env.service,
		Now: env.clock.Now, Logger: discard,
	})
	if err != nil {
		t.Fatalf("构造权限服务失败: %v", err)
	}

	env.roleAdmin, err = role.UserCaller(testAdmin)
	if err != nil {
		t.Fatalf("构造角色用户调用者失败: %v", err)
	}
	env.roleLocal, err = role.LocalBootstrapCaller("operator-1")
	if err != nil {
		t.Fatalf("构造角色本地调用者失败: %v", err)
	}
	env.groupAdmin, err = group.UserCaller(testAdmin)
	if err != nil {
		t.Fatalf("构造用户组用户调用者失败: %v", err)
	}
	env.groupLocal, err = group.LocalBootstrapCaller("operator-1")
	if err != nil {
		t.Fatalf("构造用户组本地调用者失败: %v", err)
	}
	env.appAdmin, err = app.UserCaller(testAdmin)
	if err != nil {
		t.Fatalf("构造应用用户调用者失败: %v", err)
	}
	env.appLocal, err = app.LocalBootstrapCaller("operator-1")
	if err != nil {
		t.Fatalf("构造应用本地调用者失败: %v", err)
	}
	env.permissionAdmin, err = permission.UserCaller(testAdmin)
	if err != nil {
		t.Fatalf("构造权限用户调用者失败: %v", err)
	}
	env.permissionLocal, err = permission.LocalBootstrapCaller("operator-1")
	if err != nil {
		t.Fatalf("构造权限本地调用者失败: %v", err)
	}
	return env
}

// createRole 由受信本地操作者创建应用角色。
func (e *integrationEnv) createRole(key string) role.Role {
	e.t.Helper()
	record, err := e.roleService.CreateRole(context.Background(), e.roleLocal, role.CreateRequest{
		ScopeID: testAppOne, Key: key, Name: key, Description: "说明", Limits: "限制",
	})
	if err != nil {
		e.t.Fatalf("创建角色失败: %v", err)
	}
	return record
}

// grantOne 签发 permOne 的委派资格（管理员可用权限基础）。
func (e *integrationEnv) grantOne() {
	e.t.Helper()
	e.grantPerm("invoices.read")
}

// TestRoleWritePathsRequireDelegation 验证角色编辑、赋角色、启用角色三条路径。
func TestRoleWritePathsRequireDelegation(t *testing.T) {
	env := prepareIntegrationEnv(t)
	ctx := context.Background()
	env.grantOne()
	roleNew := env.createRole("delegated-reader")

	// 正向：有委派资格且持有 permOne，可以把 permOne 组合进新角色。
	changed, err := env.roleService.AddRolePermission(ctx, env.roleAdmin, roleNew.ID, testPermOne)
	if err != nil || !changed {
		t.Fatalf("正向组合权限失败: changed=%v err=%v", changed, err)
	}
	// 越权：没有 permTwo 的委派资格（即使应用管理员可管理本应用角色）。
	_, denyErr := env.roleService.AddRolePermission(ctx, env.roleAdmin, roleNew.ID, testPermTwo)
	if !errors.Is(denyErr, delegation.ErrTransferNotGranted) {
		t.Fatalf("角色编辑越权错误 = %v", denyErr)
	}
	if delegation.CodeOf(denyErr) != delegation.CodePermissionRequired {
		t.Fatalf("拒绝错误码 = %v，期望 PERMISSION_REQUIRED", delegation.CodeOf(denyErr))
	}
	if env.rowCount(`SELECT COUNT(*) FROM role_permissions WHERE role_id=? AND permission_id=?`, roleNew.ID, testPermTwo) != 0 {
		t.Fatal("越权组合被写入")
	}

	// 正向：把只含 permOne 的角色分配给成员。
	if changed, err := env.roleService.AssignUserRole(ctx, env.roleAdmin, roleNew.ID, testMember); err != nil || !changed {
		t.Fatalf("正向分配角色失败: changed=%v err=%v", changed, err)
	}
	// 越权：把含 permTwo 的角色分配给成员。
	roleBad := env.createRole("approver-role")
	if _, err := env.roleService.AddRolePermission(ctx, env.roleLocal, roleBad.ID, testPermTwo); err != nil {
		t.Fatalf("受信组合 permTwo 失败: %v", err)
	}
	if _, err := env.roleService.AssignUserRole(ctx, env.roleAdmin, roleBad.ID, testMember); !errors.Is(err, delegation.ErrTransferNotGranted) {
		t.Fatalf("赋角色越权错误 = %v", err)
	}
	if env.rowCount(`SELECT COUNT(*) FROM user_roles WHERE role_id=? AND user_id=?`, roleBad.ID, testMember) != 0 {
		t.Fatal("越权角色分配被写入")
	}
	// 自我提权：不能把角色分配给自己（即使只含可转授权限）。
	if _, err := env.roleService.AssignUserRole(ctx, env.roleAdmin, roleNew.ID, testAdmin); !errors.Is(err, delegation.ErrSelfTransferDenied) {
		t.Fatalf("自我分配角色错误 = %v", err)
	}
	// 用户组分配同样检查：含 permTwo 的角色不能分配给应用用户组。
	if _, err := env.roleService.AssignGroupRole(ctx, env.roleAdmin, roleBad.ID, testGroupTwo); !errors.Is(err, delegation.ErrTransferNotGranted) {
		t.Fatalf("组赋角色越权错误 = %v", err)
	}
	if changed, err := env.roleService.AssignGroupRole(ctx, env.roleAdmin, roleNew.ID, testGroupTwo); err != nil || !changed {
		t.Fatalf("正向组赋角色失败: changed=%v err=%v", changed, err)
	}

	// 启用角色：角色停用后再启用等于让其权限重新生效，需要委派资格。
	roleDisabled := env.createRole("disabled-role")
	if _, err := env.roleService.AddRolePermission(ctx, env.roleLocal, roleDisabled.ID, testPermOne); err != nil {
		t.Fatalf("受信组合 permOne 失败: %v", err)
	}
	if _, _, err := env.roleService.DisableRole(ctx, env.roleLocal, roleDisabled.ID); err != nil {
		t.Fatalf("受信停用角色失败: %v", err)
	}
	// 角色停用后管理员已不持有 permOne（唯一来源被停用），但启用检查只要求资格。
	if _, changed, err := env.roleService.EnableRole(ctx, env.roleAdmin, roleDisabled.ID); err != nil || !changed {
		t.Fatalf("启用角色失败: changed=%v err=%v", changed, err)
	}
	roleDisabledBad := env.createRole("disabled-bad-role")
	if _, err := env.roleService.AddRolePermission(ctx, env.roleLocal, roleDisabledBad.ID, testPermTwo); err != nil {
		t.Fatalf("受信组合 permTwo 失败: %v", err)
	}
	if _, _, err := env.roleService.DisableRole(ctx, env.roleLocal, roleDisabledBad.ID); err != nil {
		t.Fatalf("受信停用角色失败: %v", err)
	}
	if _, _, err := env.roleService.EnableRole(ctx, env.roleAdmin, roleDisabledBad.ID); !errors.Is(err, delegation.ErrTransferNotGranted) {
		t.Fatalf("启用含未授权权限角色错误 = %v", err)
	}
	if env.rowCount(`SELECT COUNT(*) FROM roles WHERE id=? AND enabled=1`, roleDisabledBad.ID) != 0 {
		t.Fatal("越权启用角色被写入")
	}
}

// TestGroupMemberPathRequiresDelegation 验证“先配角色再拉人”的间接提权路径。
func TestGroupMemberPathRequiresDelegation(t *testing.T) {
	env := prepareIntegrationEnv(t)
	ctx := context.Background()
	env.grantOne()
	roleNew := env.createRole("member-reader")
	if _, err := env.roleService.AddRolePermission(ctx, env.roleLocal, roleNew.ID, testPermOne); err != nil {
		t.Fatalf("受信组合 permOne 失败: %v", err)
	}
	// 受信操作者先把角色分配给用户组（组当前没有成员）。
	if _, err := env.roleService.AssignGroupRole(ctx, env.roleLocal, roleNew.ID, testGroupTwo); err != nil {
		t.Fatalf("受信组赋角色失败: %v", err)
	}
	// 正向：组成员变更前检查组当前有效权限，管理员可转授 permOne 给成员。
	result, err := env.groupService.AddMembers(ctx, env.groupAdmin, group.MemberBatchRequest{
		GroupID: testGroupTwo, UserIDs: []string{testMember},
	})
	if err != nil || result.Added != 1 {
		t.Fatalf("正向加入组成员失败: %+v err=%v", result, err)
	}
	// 自我提权：不能把自己加入已含权限的用户组。
	if _, err := env.groupService.AddMembers(ctx, env.groupAdmin, group.MemberBatchRequest{
		GroupID: testGroupTwo, UserIDs: []string{testAdmin},
	}); !errors.Is(err, delegation.ErrSelfTransferDenied) {
		t.Fatalf("自我加入组错误 = %v", err)
	}
	// 组内出现未获转授资格的权限后，新成员加入必须拒绝。
	roleBad := env.createRole("member-approver")
	if _, err := env.roleService.AddRolePermission(ctx, env.roleLocal, roleBad.ID, testPermTwo); err != nil {
		t.Fatalf("受信组合 permTwo 失败: %v", err)
	}
	if _, err := env.roleService.AssignGroupRole(ctx, env.roleLocal, roleBad.ID, testGroupTwo); err != nil {
		t.Fatalf("受信组赋角色失败: %v", err)
	}
	if _, err := env.groupService.AddMembers(ctx, env.groupAdmin, group.MemberBatchRequest{
		GroupID: testGroupTwo, UserIDs: []string{testOther},
	}); !errors.Is(err, delegation.ErrTransferNotGranted) {
		t.Fatalf("组间接提权错误 = %v", err)
	}
	if env.rowCount(`SELECT COUNT(*) FROM group_members WHERE group_id=? AND user_id=?`, testGroupTwo, testOther) != 0 {
		t.Fatal("越权组成员被写入")
	}
}

// TestPermissionEnableRequiresDelegation 验证启用权限路径；停用仍是安全收缩路径。
func TestPermissionEnableRequiresDelegation(t *testing.T) {
	env := prepareIntegrationEnv(t)
	ctx := context.Background()
	env.grantPerm("users.read")
	// 受信操作者停用后，管理员凭既有委派资格可以重新启用。
	if _, _, err := env.permissionService.DisablePermission(ctx, env.permissionLocal, testPermFour); err != nil {
		t.Fatalf("受信停用权限失败: %v", err)
	}
	if _, changed, err := env.permissionService.EnablePermission(ctx, env.permissionAdmin, testPermFour); err != nil || !changed {
		t.Fatalf("正向启用权限失败: changed=%v err=%v", changed, err)
	}
	// 应用管理员新建权限（默认启用），受信停用后没有委派资格则不能启用。
	created, err := env.permissionService.CreatePermission(ctx, env.permissionAdmin, permission.CreateRequest{
		ScopeID: testAppOne, Key: "invoices.export", Name: "导出", Description: "说明", Limits: "限制",
	})
	if err != nil {
		t.Fatalf("创建权限失败: %v", err)
	}
	if _, _, err := env.permissionService.DisablePermission(ctx, env.permissionLocal, created.ID); err != nil {
		t.Fatalf("受信停用权限失败: %v", err)
	}
	if _, _, err := env.permissionService.EnablePermission(ctx, env.permissionAdmin, created.ID); !errors.Is(err, delegation.ErrTransferNotGranted) {
		t.Fatalf("启用未授权权限错误 = %v", err)
	}
	if env.rowCount(`SELECT COUNT(*) FROM permissions WHERE id=? AND enabled=1`, created.ID) != 0 {
		t.Fatal("越权启用权限被写入")
	}
	// 停用（收缩路径）不需要额外委派资格。
	if _, _, err := env.permissionService.DisablePermission(ctx, env.permissionAdmin, testPermFour); err != nil {
		t.Fatalf("停用权限失败: %v", err)
	}
}

// TestApplicationMemberPathsRequireDelegation 验证加入成员与重新启用成员会恢复既有
// 角色权限，因此同样需要可转授检查。
func TestApplicationMemberPathsRequireDelegation(t *testing.T) {
	env := prepareIntegrationEnv(t)
	ctx := context.Background()
	env.grantOne()
	roleNew := env.createRole("dormant-reader")
	if _, err := env.roleService.AddRolePermission(ctx, env.roleLocal, roleNew.ID, testPermOne); err != nil {
		t.Fatalf("受信组合 permOne 失败: %v", err)
	}
	roleBad := env.createRole("dormant-approver")
	if _, err := env.roleService.AddRolePermission(ctx, env.roleLocal, roleBad.ID, testPermTwo); err != nil {
		t.Fatalf("受信组合 permTwo 失败: %v", err)
	}

	// 受信操作者先把 testDormant 加入应用并授予含 permOne 的角色，再移除成员关系；
	// 角色分配保留，重新加入会让 permOne 恢复生效。
	if _, err := env.appService.AddApplicationMember(ctx, env.appLocal, app.AddMemberRequest{
		ApplicationID: testAppOne, UserID: testDormant,
	}); err != nil {
		t.Fatalf("受信加入成员失败: %v", err)
	}
	if _, err := env.roleService.AssignUserRole(ctx, env.roleLocal, roleNew.ID, testDormant); err != nil {
		t.Fatalf("受信分配角色失败: %v", err)
	}
	membership, err := env.appService.GetApplicationMember(ctx, env.appLocal, testAppOne, testDormant)
	if err != nil {
		t.Fatalf("读取成员关系失败: %v", err)
	}
	if err := env.appService.RemoveApplicationMember(ctx, env.appLocal, app.RemoveMemberRequest{
		ApplicationID: testAppOne, UserID: testDormant, ExpectedRowVersion: membership.RowVersion,
	}); err != nil {
		t.Fatalf("受信移除成员失败: %v", err)
	}
	// 正向：重新加入成员（恢复 permOne）需要并满足委派检查。
	if _, err := env.appService.AddApplicationMember(ctx, env.appAdmin, app.AddMemberRequest{
		ApplicationID: testAppOne, UserID: testDormant,
	}); err != nil {
		t.Fatalf("正向重新加入成员失败: %v", err)
	}

	// 越权：testOther 既有成员关系被移除后，重新加入会恢复 permTwo（无委派资格）。
	if _, err := env.roleService.AssignUserRole(ctx, env.roleLocal, roleBad.ID, testOther); err != nil {
		t.Fatalf("受信分配角色失败: %v", err)
	}
	otherMembership, err := env.appService.GetApplicationMember(ctx, env.appLocal, testAppOne, testOther)
	if err != nil {
		t.Fatalf("读取成员关系失败: %v", err)
	}
	if _, err := env.appService.DisableApplicationMember(ctx, env.appLocal, app.MemberStatusRequest{
		ApplicationID: testAppOne, UserID: testOther, ExpectedRowVersion: otherMembership.RowVersion,
	}); err != nil {
		t.Fatalf("受信停用成员失败: %v", err)
	}
	// 停用后重新启用同样会恢复 permTwo：管理员不能启用。
	if _, err := env.appService.EnableApplicationMember(ctx, env.appAdmin, app.MemberStatusRequest{
		ApplicationID: testAppOne, UserID: testOther, ExpectedRowVersion: otherMembership.RowVersion + 1,
	}); !errors.Is(err, delegation.ErrTransferNotGranted) {
		t.Fatalf("越权启用成员错误 = %v", err)
	}
	// 清空成员关系后重新加入同样拒绝。
	disabledMembership, err := env.appService.GetApplicationMember(ctx, env.appLocal, testAppOne, testOther)
	if err != nil {
		t.Fatalf("读取成员关系失败: %v", err)
	}
	if err := env.appService.RemoveApplicationMember(ctx, env.appLocal, app.RemoveMemberRequest{
		ApplicationID: testAppOne, UserID: testOther, ExpectedRowVersion: disabledMembership.RowVersion,
	}); err != nil {
		t.Fatalf("受信移除成员失败: %v", err)
	}
	if _, err := env.appService.AddApplicationMember(ctx, env.appAdmin, app.AddMemberRequest{
		ApplicationID: testAppOne, UserID: testOther,
	}); !errors.Is(err, delegation.ErrTransferNotGranted) {
		t.Fatalf("越权重新加入成员错误 = %v", err)
	}
	if env.rowCount(`SELECT COUNT(*) FROM app_memberships WHERE app_id=? AND user_id=?`, testAppOne, testOther) != 0 {
		t.Fatal("越权成员关系被写入")
	}
}

// TestTrustedChannelStillWorks 验证受信通道行为不变（仍写审计）。
func TestTrustedChannelStillWorks(t *testing.T) {
	env := prepareIntegrationEnv(t)
	ctx := context.Background()
	roleNew := env.createRole("trusted-role")
	if _, err := env.roleService.AddRolePermission(ctx, env.roleLocal, roleNew.ID, testPermTwo); err != nil {
		t.Fatalf("受信通道组合权限失败: %v", err)
	}
	if changed, err := env.roleService.AssignUserRole(ctx, env.roleLocal, roleNew.ID, testMember); err != nil || !changed {
		t.Fatalf("受信通道分配角色失败: changed=%v err=%v", changed, err)
	}
	if env.rowCount(`SELECT COUNT(*) FROM audit_events WHERE action='role.permission.add' AND target_id=?`, roleNew.ID) == 0 {
		t.Fatal("受信通道缺少审计")
	}
}

// TestEnableRoleCannotRestoreSelfHeldPermission 验证阻断级自我提权：管理员可以用被
// 停用的含权角色，不能通过“停用后再启用”恢复自己（或自己所在用户组）的权限；
// 拒绝后角色仍保持停用，数据库不变。
func TestEnableRoleCannotRestoreSelfHeldPermission(t *testing.T) {
	env := prepareIntegrationEnv(t)
	ctx := context.Background()
	env.grantOne()

	// 含 permOne 的角色被分配给管理员本人，再由受信操作者停用。
	roleSelf := env.createRole("self-reader")
	if _, err := env.roleService.AddRolePermission(ctx, env.roleLocal, roleSelf.ID, testPermOne); err != nil {
		t.Fatalf("受信组合 permOne 失败: %v", err)
	}
	if _, err := env.roleService.AssignUserRole(ctx, env.roleLocal, roleSelf.ID, testAdmin); err != nil {
		t.Fatalf("受信分配角色失败: %v", err)
	}
	if _, _, err := env.roleService.DisableRole(ctx, env.roleLocal, roleSelf.ID); err != nil {
		t.Fatalf("受信停用角色失败: %v", err)
	}
	if _, _, err := env.roleService.EnableRole(ctx, env.roleAdmin, roleSelf.ID); !errors.Is(err, delegation.ErrSelfTransferDenied) {
		t.Fatalf("启用自身含权角色错误 = %v，期望拒绝自我提权", err)
	}
	if delegation.CodeOf(delegation.ErrSelfTransferDenied) != delegation.CodeAccessDenied {
		t.Fatalf("自我提权拒绝错误码 = %v，期望 ACCESS_DENIED", delegation.CodeOf(delegation.ErrSelfTransferDenied))
	}
	if env.rowCount(`SELECT COUNT(*) FROM roles WHERE id=? AND enabled=1`, roleSelf.ID) != 0 {
		t.Fatal("越权启用角色被写入")
	}

	// 角色分配给管理员所在的用户组（testGroupOne）同样不能启用。
	roleGroup := env.createRole("group-self-reader")
	if _, err := env.roleService.AddRolePermission(ctx, env.roleLocal, roleGroup.ID, testPermOne); err != nil {
		t.Fatalf("受信组合 permOne 失败: %v", err)
	}
	if _, err := env.roleService.AssignGroupRole(ctx, env.roleLocal, roleGroup.ID, testGroupOne); err != nil {
		t.Fatalf("受信组赋角色失败: %v", err)
	}
	if _, _, err := env.roleService.DisableRole(ctx, env.roleLocal, roleGroup.ID); err != nil {
		t.Fatalf("受信停用角色失败: %v", err)
	}
	if _, _, err := env.roleService.EnableRole(ctx, env.roleAdmin, roleGroup.ID); !errors.Is(err, delegation.ErrSelfTransferDenied) {
		t.Fatalf("启用自身所在组角色错误 = %v，期望拒绝自我提权", err)
	}
	if env.rowCount(`SELECT COUNT(*) FROM roles WHERE id=? AND enabled=1`, roleGroup.ID) != 0 {
		t.Fatal("越权启用用户组角色被写入")
	}
}

// TestEnablePermissionCannotRestoreSelfHeldPermission 验证启用权限路径同样按持有目标
// 校验：被委派者不能自行启用已停用、持有者是自身或自身所在用户组的权限。
func TestEnablePermissionCannotRestoreSelfHeldPermission(t *testing.T) {
	env := prepareIntegrationEnv(t)
	ctx := context.Background()
	env.grantOne()

	// permOne 由已分配给管理员的 roleOne 组合（seed）；另建一个“分配给管理员所在
	// 用户组”的角色，两者都在受信停用 permOne 后成为持有者路径。
	roleGroup := env.createRole("perm-holder-group")
	if _, err := env.roleService.AddRolePermission(ctx, env.roleLocal, roleGroup.ID, testPermOne); err != nil {
		t.Fatalf("受信组合 permOne 失败: %v", err)
	}
	if _, err := env.roleService.AssignGroupRole(ctx, env.roleLocal, roleGroup.ID, testGroupOne); err != nil {
		t.Fatalf("受信组赋角色失败: %v", err)
	}
	if _, _, err := env.permissionService.DisablePermission(ctx, env.permissionLocal, testPermOne); err != nil {
		t.Fatalf("受信停用权限失败: %v", err)
	}
	// 自身（经 roleOne）与其所在用户组（经 roleGroup）都会重新获得该权限。
	if _, _, err := env.permissionService.EnablePermission(ctx, env.permissionAdmin, testPermOne); !errors.Is(err, delegation.ErrSelfTransferDenied) {
		t.Fatalf("启用自身持有权限错误 = %v，期望拒绝自我提权", err)
	}
	if env.rowCount(`SELECT COUNT(*) FROM permissions WHERE id=? AND enabled=1`, testPermOne) != 0 {
		t.Fatal("越权启用权限被写入")
	}
}

// TestRolePermissionCombineChecksRoleHolders 验证高白名单失效缺陷：把权限组合进
// “已分配给白名单外用户或操作者自身”的角色必须拒绝，不能借角色绕过赋角色检查。
func TestRolePermissionCombineChecksRoleHolders(t *testing.T) {
	env := prepareIntegrationEnv(t)
	ctx := context.Background()
	// 委派资格只允许把 invoices.read 转授给 testMember。
	env.grantPerm("invoices.read", func(request *delegation.GrantRequest) {
		request.AllowedTargets = delegation.AllowedTargets{Users: []string{testMember}}
	})

	// 受信操作者先把空角色分配给白名单外用户 testOther。
	roleOutsider := env.createRole("held-by-outsider")
	if _, err := env.roleService.AssignUserRole(ctx, env.roleLocal, roleOutsider.ID, testOther); err != nil {
		t.Fatalf("受信分配角色失败: %v", err)
	}
	if _, err := env.roleService.AddRolePermission(ctx, env.roleAdmin, roleOutsider.ID, testPermOne); !errors.Is(err, delegation.ErrTargetNotAllowed) {
		t.Fatalf("向白名单外持有者组合权限错误 = %v，期望 ErrTargetNotAllowed", err)
	}
	if env.rowCount(`SELECT COUNT(*) FROM role_permissions WHERE role_id=? AND permission_id=?`, roleOutsider.ID, testPermOne) != 0 {
		t.Fatal("越权权限组合被写入")
	}

	// 角色已分配给管理员本人时，组合权限等于自我提权，默认拒绝。
	roleSelf := env.createRole("held-by-self")
	if _, err := env.roleService.AssignUserRole(ctx, env.roleLocal, roleSelf.ID, testAdmin); err != nil {
		t.Fatalf("受信分配角色失败: %v", err)
	}
	if _, err := env.roleService.AddRolePermission(ctx, env.roleAdmin, roleSelf.ID, testPermOne); !errors.Is(err, delegation.ErrSelfTransferDenied) {
		t.Fatalf("向自身持有角色组合权限错误 = %v，期望期望拒绝自我提权", err)
	}
	if env.rowCount(`SELECT COUNT(*) FROM role_permissions WHERE role_id=? AND permission_id=?`, roleSelf.ID, testPermOne) != 0 {
		t.Fatal("向自身角色越权组合权限被写入")
	}

	// 白名单内持有者仍可通过：角色已分配给 testMember 时可以组合。
	roleAllowed := env.createRole("held-by-allowed")
	if _, err := env.roleService.AssignUserRole(ctx, env.roleLocal, roleAllowed.ID, testMember); err != nil {
		t.Fatalf("受信分配角色失败: %v", err)
	}
	if changed, err := env.roleService.AddRolePermission(ctx, env.roleAdmin, roleAllowed.ID, testPermOne); err != nil || !changed {
		t.Fatalf("白名单内组合权限失败: changed=%v err=%v", changed, err)
	}
}

// TestApplicationEnableRequiresDelegation 验证应用启用接入 Guard：无委派资格的应用
// 管理员不能通过重新启用应用恢复全应用权限；有资格且目标合法时可通过。
func TestApplicationEnableRequiresDelegation(t *testing.T) {
	env := prepareIntegrationEnv(t)
	ctx := context.Background()

	// 负向：应用一含 roleOne/roleTwo 的 pemOne、permTwo（持有者含管理员本人且无资格）。
	appOne, err := env.appService.GetApplication(ctx, env.appLocal, testAppOne)
	if err != nil {
		t.Fatalf("读取应用失败: %v", err)
	}
	if _, err := env.appService.DisableApplication(ctx, env.appLocal, app.StatusRequest{
		ApplicationID: testAppOne, ExpectedRowVersion: appOne.RowVersion,
	}); err != nil {
		t.Fatalf("受信停用应用失败: %v", err)
	}
	if _, err := env.appService.EnableApplication(ctx, env.appAdmin, app.StatusRequest{
		ApplicationID: testAppOne, ExpectedRowVersion: appOne.RowVersion + 1,
	}); !errors.Is(err, delegation.ErrTransferNotGranted) {
		t.Fatalf("无资格启用应用错误 = %v，期望 ErrTransferNotGranted", err)
	}
	if env.rowCount(`SELECT COUNT(*) FROM applications WHERE id=? AND status='active'`, testAppOne) != 0 {
		t.Fatal("越权启用应用被写入")
	}

	// 正向：应用二只有一项权限，持有者是 testMember（非自身、无白名单限制）。
	appTwo, err := env.appService.GetApplication(ctx, env.appLocal, testAppTwo)
	if err != nil {
		t.Fatalf("读取应用二失败: %v", err)
	}
	if _, err := env.appService.AddApplicationMember(ctx, env.appLocal, app.AddMemberRequest{
		ApplicationID: testAppTwo, UserID: testAdmin,
	}); err != nil {
		t.Fatalf("受信加入应用二成员失败: %v", err)
	}
	if _, err := env.appService.AddApplicationMember(ctx, env.appLocal, app.AddMemberRequest{
		ApplicationID: testAppTwo, UserID: testMember,
	}); err != nil {
		t.Fatalf("受信加入应用二成员失败: %v", err)
	}
	createdPermission, err := env.permissionService.CreatePermission(ctx, env.permissionLocal, permission.CreateRequest{
		ScopeID: testAppTwo, Key: "reports.export", Name: "导出报表", Description: "说明", Limits: "限制",
	})
	if err != nil {
		t.Fatalf("受信创建应用二权限失败: %v", err)
	}
	appTwoRole, err := env.roleService.CreateRole(ctx, env.roleLocal, role.CreateRequest{
		ScopeID: testAppTwo, Key: "reports-exporter-app2", Name: "导出", Description: "说明", Limits: "限制",
	})
	if err != nil {
		t.Fatalf("受信创建应用二角色失败: %v", err)
	}
	if _, err := env.roleService.AddRolePermission(ctx, env.roleLocal, appTwoRole.ID, createdPermission.ID); err != nil {
		t.Fatalf("受信组合应用二权限失败: %v", err)
	}
	if _, err := env.roleService.AssignUserRole(ctx, env.roleLocal, appTwoRole.ID, testMember); err != nil {
		t.Fatalf("受信分配应用二角色失败: %v", err)
	}
	env.grantPerm("reports.export", func(request *delegation.GrantRequest) {
		request.ScopeID = testAppTwo
	})
	if _, err := env.appService.DisableApplication(ctx, env.appLocal, app.StatusRequest{
		ApplicationID: testAppTwo, ExpectedRowVersion: appTwo.RowVersion,
	}); err != nil {
		t.Fatalf("受信停用应用二失败: %v", err)
	}
	result, err := env.appService.EnableApplication(ctx, env.appAdmin, app.StatusRequest{
		ApplicationID: testAppTwo, ExpectedRowVersion: appTwo.RowVersion + 1,
	})
	if err != nil || !result.Changed {
		t.Fatalf("有资格启用应用失败: changed=%v err=%v", result.Changed, err)
	}
	if env.rowCount(`SELECT COUNT(*) FROM applications WHERE id=? AND status='active'`, testAppTwo) != 1 {
		t.Fatal("有资格启用应用未写入")
	}
}

// TestConcurrentGuardedWriteAndRevoke 验证受 Guard 保护的写入路径在并发撤回下不
// 产生半更新：每次组合要么在撤回前成功，要么在撤回后明确拒绝；最终组合关系与
// 审计保持一致，不存在重复行或成功写入却无审计的情况。
func TestConcurrentGuardedWriteAndRevoke(t *testing.T) {
	env := prepareIntegrationEnv(t)
	ctx := context.Background()
	grant := env.grantPerm("invoices.read")
	roleConcurrent := env.createRole("concurrent-reader")

	const workers = 4
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := env.roleService.AddRolePermission(ctx, env.roleAdmin, roleConcurrent.ID, testPermOne)
			errs <- err
		}()
	}
	// 与并发写入同时撤回委派资格：写入要么先成功，要么因资格已撤回而拒绝。
	time.Sleep(5 * time.Millisecond)
	if changed, err := env.service.Revoke(ctx, env.local, grant.ID); err != nil || !changed {
		t.Fatalf("并发撤回失败: changed=%v err=%v", changed, err)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err == nil {
			continue
		}
		if errors.Is(err, delegation.ErrTransferRevoked) || errors.Is(err, delegation.ErrTransferNotGranted) || errors.Is(err, delegation.ErrTransferExpired) {
			continue
		}
		t.Fatalf("并发受保护写入出现非预期错误: %v", err)
	}
	count := env.rowCount(`SELECT COUNT(*) FROM role_permissions WHERE role_id=? AND permission_id=?`,
		roleConcurrent.ID, testPermOne)
	if count > 1 {
		t.Fatalf("并发写入产生重复组合行: %d", count)
	}
	if count == 1 && env.rowCount(`SELECT COUNT(*) FROM audit_events WHERE action='role.permission.add' AND target_id=?`, roleConcurrent.ID) == 0 {
		t.Fatal("并发写入成功但缺少安全审计")
	}
}
