package app

// 步骤 208 / 207 安全审计 N1 回归测试：只有部分应用范围 roles.read 的调用者
// 不能以 NOT_FOUND 与 ACCESS_DENIED 的差异枚举其他应用的角色是否存在。
// 修复位于 internal/role.getAuthorizedRole 的部分范围分支；这里通过真实公开管理
// 门面（真实权限内核）端到端验证修复后的统一拒绝语义与合法未找到的边界。

import (
	"context"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/role"
)

func TestAdminRoleQueryHidesOtherApplicationExistence(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 7, 0, 0, 0, time.UTC))
	runtime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	adminAPI := runtime.Admin()
	local := runtime.LocalAdmin()
	reader := step207CreateProblemUser(t, ctx, runtime, "roleadmin208")

	createApplication := func(name string) AdminApplication {
		t.Helper()
		created, err := adminAPI.CreateApplication(ctx, AdminCreateApplicationRequest{
			Caller: local, Name: name, RequestID: login.NewRequestID()})
		if err != nil {
			t.Fatalf("创建应用 %s 失败: %v", name, err)
		}
		enabled, err := adminAPI.SetApplicationEnabled(ctx, AdminSetApplicationEnabledRequest{
			Caller: local, ApplicationID: created.ID, Enabled: true,
			ExpectedRowVersion: created.RowVersion, RequestID: login.NewRequestID()})
		if err != nil {
			t.Fatalf("启用应用 %s 失败: %v", name, err)
		}
		return enabled
	}
	appA := createApplication("应用 A")
	appB := createApplication("应用 B")
	rolesRead, err := adminAPI.CreatePermission(ctx, AdminCreatePermissionRequest{
		Caller: local, ScopeID: appA.ID, Key: "roles.read", Name: "读取角色",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建 roles.read 权限失败: %v", err)
	}
	readerRole, err := adminAPI.CreateRole(ctx, AdminCreateRoleRequest{
		Caller: local, ScopeID: appA.ID, Key: "role-reader", Name: "角色读取员",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建应用 A 角色失败: %v", err)
	}
	if err := adminAPI.AddRolePermission(ctx, AdminRolePermissionRequest{
		Caller: local, RoleID: readerRole.ID, PermissionID: rolesRead.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("角色添加 roles.read 失败: %v", err)
	}
	otherRole, err := adminAPI.CreateRole(ctx, AdminCreateRoleRequest{
		Caller: local, ScopeID: appB.ID, Key: "other-reader", Name: "应用 B 角色",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建应用 B 角色失败: %v", err)
	}
	if err := adminAPI.AddApplicationMember(ctx, AdminAddMemberRequest{
		Caller: local, ApplicationID: appA.ID, UserID: reader.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("加入应用 A 成员失败: %v", err)
	}
	if err := adminAPI.GrantApplicationRole(ctx, GrantRoleRequest{
		Caller: local, UserID: reader.ID, RoleID: readerRole.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("分配应用 A 角色失败: %v", err)
	}

	loginResult := step208Login(t, ctx, runtime, "roleadmin208", "K8$wR3!nB6@yF1#v", "")
	adminSession := runtime.AdminSession(loginResult.SessionSecret)
	missingRoleID, err := role.NewRoleID(nil)
	if err != nil {
		t.Fatalf("生成测试角色 ID 失败: %v", err)
	}

	// 授权范围内真实角色：合法读取成功。
	inScope, err := adminAPI.ListRolePermissions(ctx, AdminRoleRequest{
		Caller: adminSession, RoleID: readerRole.ID, RequestID: login.NewRequestID()})
	if err != nil || len(inScope) != 1 || inScope[0].Key != "roles.read" {
		t.Fatalf("范围内角色权限读取异常: %+v err=%v", inScope, err)
	}

	// 其他应用的真实角色与完全不存在的角色必须返回同一个 ACCESS_DENIED，且不带
	// NOT_FOUND 语义（否则可按 ID 枚举其他应用的角色是否存在）。
	outOfScopeID := "req_208_role_out_of_scope"
	_, outOfScopeErr := adminAPI.ListRolePermissions(ctx, AdminRoleRequest{
		Caller: adminSession, RoleID: otherRole.ID, RequestID: outOfScopeID})
	outOfScope := step207AppError(t, outOfScopeErr)
	if outOfScope.Code() != login.CodeAccessDenied {
		t.Fatalf("范围外角色应返回 ACCESS_DENIED，实际 %v", outOfScope)
	}
	if IsNotFound(outOfScopeErr) {
		t.Fatalf("范围外角色不能返回未找到语义: %v", outOfScopeErr)
	}
	if outOfScope.RequestID() != outOfScopeID {
		t.Fatalf("范围外拒绝请求编号 = %q，期望 %q", outOfScope.RequestID(), outOfScopeID)
	}

	missingID := "req_208_role_missing"
	_, missingErr := adminAPI.ListRolePermissions(ctx, AdminRoleRequest{
		Caller: adminSession, RoleID: missingRoleID, RequestID: missingID})
	missing := step207AppError(t, missingErr)
	if missing.Code() != login.CodeAccessDenied {
		t.Fatalf("部分范围调用者查询不存在角色应统一返回 ACCESS_DENIED，实际 %v", missing)
	}
	if IsNotFound(missingErr) {
		t.Fatalf("部分范围调用者不应得到未找到语义（存在性泄露）: %v", missingErr)
	}
	if missing.Code() != outOfScope.Code() {
		t.Fatalf("范围外与不存在必须返回同一错误码: %v vs %v", outOfScope, missing)
	}
	if missing.RequestID() != missingID {
		t.Fatalf("不存在角色拒绝请求编号 = %q，期望 %q", missing.RequestID(), missingID)
	}

	// 受信全范围调用者（本机受信通道）仍能区分合法未找到：修复只在部分范围分支
	// 折叠存在性差异，不改变“已授权且范围内目标确实不存在”的 NOT_FOUND 语义。
	_, localMissingErr := adminAPI.ListRolePermissions(ctx, AdminRoleRequest{
		Caller: local, RoleID: missingRoleID, RequestID: "req_208_role_local_missing"})
	step207NotFound(t, localMissingErr, "role", "req_208_role_local_missing")
}
