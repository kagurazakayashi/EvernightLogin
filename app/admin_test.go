package app

// 受信管理门面测试（步骤 182）：真实临时 SQLite + 真实领域服务。
//   - 本机受信操作者完成自举（应用/权限/角色/首次管理员分配），每次敏感引导都有
//     独立审计事件；
//   - 真实管理用户会话在关闭自主注册时创建用户、读写资料、分配/撤回应用角色、
//     查询有效权限；越权转授、跨应用写入、自我提权、普通用户伪造管理员均拒绝；
//   - 撤销角色后权限检查立即失效；审计记录真实操作者。

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

// adminTestRuntime 在指定目录打开真实运行时（复用同一数据库与时钟）。
func adminTestRuntime(t *testing.T, ctx context.Context, config login.Config,
	dir string, clock *testClock) *Runtime {
	t.Helper()
	runtime, err := Open(ctx, Options{
		Config: &config, DatabasePath: filepath.Join(dir, "login.db"),
		MasterKeyFile: filepath.Join(dir, "master.key"), CreateMasterKey: true,
		Migrate: true, OperatorID: "host-operator", Now: clock.Now,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	return runtime
}

// auditCount 统计指定动作/操作者的成功审计事件数量。
func auditCount(t *testing.T, runtime *Runtime, action, actorType, actorID string) int {
	t.Helper()
	var count int
	query := `SELECT COUNT(*) FROM audit_events WHERE action=? AND actor_type=? AND actor_id=? AND outcome='success'`
	if err := runtime.base.Store.DB().QueryRow(query, action, actorType, actorID).Scan(&count); err != nil {
		// *sql.DB 关闭后查询返回 sql.ErrConnDone 等错误，直接失败便于定位。
		t.Fatalf("查询审计计数失败: %v", err)
	}
	return count
}

// auditRowCount 统计任意结果的审计事件数量（用于拒绝路径）。
func auditRowCount(t *testing.T, runtime *Runtime, action string) int {
	t.Helper()
	var count int
	if err := runtime.base.Store.DB().QueryRow(
		`SELECT COUNT(*) FROM audit_events WHERE action=?`, action).Scan(&count); err != nil {
		t.Fatalf("查询审计行数失败: %v", err)
	}
	return count
}

// TestAdminFacadeBootstrapAndApplicationRoleAssignment 覆盖步骤 182 验收主链。
func TestAdminFacadeBootstrapAndApplicationRoleAssignment(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	clock := newTestClock(time.Date(2026, 11, 23, 7, 0, 0, 0, time.UTC))
	cfg := testConfig()
	runtime := adminTestRuntime(t, ctx, cfg, dir, clock)
	if _, err := runtime.Bootstrap().EnsureRoot(ctx, RootRequest{
		DisplayName: "Root", Password: "V7!qZ2#Lm9@Tp4$x",
		RequestID: login.NewRequestID(),
	}); err != nil {
		t.Fatalf("EnsureRoot: %v", err)
	}
	const adminPassword = "A7$dK3!mQ9@xR2#v"
	const normalPassword = "N4!rT8#xW2@qL6$z"
	adminUser, err := runtime.Users().Create(ctx, CreateUserRequest{
		Username: "admin-a", Password: adminPassword, Nickname: "Admin A",
		RequestID: login.NewRequestID(),
	})
	if err != nil {
		t.Fatalf("创建管理员用户失败: %v", err)
	}
	_, err = runtime.Users().Create(ctx, CreateUserRequest{
		Username: "normal-b", Password: normalPassword, Nickname: "Normal B",
		RequestID: login.NewRequestID(),
	})
	if err != nil {
		t.Fatalf("创建普通用户失败: %v", err)
	}
	// 管理员绑定 TOTP（复用 181 真实敏感操作再次认证），用于后续强认证敏感操作。
	adminLogin, err := runtime.Auth().Login(ctx, LoginRequest{
		Username: "admin-a", Password: adminPassword, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID(),
	})
	if err != nil || adminLogin.Restricted {
		t.Fatalf("管理员首次登录应得到完整会话: %+v err=%v", adminLogin, err)
	}
	totpStart, err := runtime.Security().BeginTOTPBinding(ctx, TOTPBindingBeginRequest{
		SessionSecret: adminLogin.SessionSecret, Password: adminPassword,
		RequestID: login.NewRequestID(),
	})
	if err != nil {
		t.Fatalf("管理员开始绑定 TOTP 失败: %v", err)
	}
	if _, err := runtime.Security().ConfirmTOTPBinding(ctx, TOTPBindingConfirmRequest{
		SessionSecret: adminLogin.SessionSecret, BindingID: totpStart.BindingID,
		Code: currentTOTP(t, clock, totpStart.Secret), RequestID: login.NewRequestID(),
	}); err != nil {
		t.Fatalf("管理员确认 TOTP 绑定失败: %v", err)
	}
	normalLogin, err := runtime.Auth().Login(ctx, LoginRequest{
		Username: "normal-b", Password: normalPassword, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID(),
	})
	if err != nil || normalLogin.Restricted {
		t.Fatalf("普通用户登录异常: %+v err=%v", normalLogin, err)
	}

	// ===== 本机受信操作者自举：应用/权限/角色/首次管理员 =====
	local := runtime.LocalAdmin()
	adminAPI := runtime.Admin()
	appA, err := adminAPI.CreateApplication(ctx, AdminCreateApplicationRequest{
		Caller: local, Name: "应用 A", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建应用 A 失败: %v", err)
	}
	appB, err := adminAPI.CreateApplication(ctx, AdminCreateApplicationRequest{
		Caller: local, Name: "应用 B", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建应用 B 失败: %v", err)
	}
	// 应用创建后默认停用；启用后才能登记应用角色/权限并作为授权范围。
	for _, application := range []AdminApplication{appA, appB} {
		if _, enableErr := adminAPI.SetApplicationEnabled(ctx, AdminSetApplicationEnabledRequest{
			Caller: local, ApplicationID: application.ID, Enabled: true,
			ExpectedRowVersion: application.RowVersion, RequestID: login.NewRequestID(),
		}); enableErr != nil {
			t.Fatalf("启用应用 %s 失败: %v", application.ID, enableErr)
		}
	}
	createPermission := func(scopeID, key, name string) AdminPermission {
		t.Helper()
		created, permErr := adminAPI.CreatePermission(ctx, AdminCreatePermissionRequest{
			Caller: local, ScopeID: scopeID, Key: key, Name: name,
			RequestID: login.NewRequestID()})
		if permErr != nil {
			t.Fatalf("创建权限 %s 失败: %v", key, permErr)
		}
		return created
	}
	sysUsersCreate := createPermission("system", "users.create", "创建用户")
	sysUsersRead := createPermission("system", "users.read", "读取用户")
	sysUsersUpdate := createPermission("system", "users.update", "更新用户资料")
	sysRole, err := adminAPI.CreateRole(ctx, AdminCreateRoleRequest{
		Caller: local, ScopeID: "system", Key: "bootstrap-user-admin",
		Name: "自举用户管理员", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建系统角色失败: %v", err)
	}
	for _, item := range []AdminPermission{sysUsersCreate, sysUsersRead, sysUsersUpdate} {
		if err := adminAPI.AddRolePermission(ctx, AdminRolePermissionRequest{
			Caller: local, RoleID: sysRole.ID, PermissionID: item.ID,
			RequestID: login.NewRequestID()}); err != nil {
			t.Fatalf("系统角色添加权限失败: %v", err)
		}
	}
	// 管理员加入应用 A 后才可被分配应用角色。
	if err := adminAPI.AddApplicationMember(ctx, AdminAddMemberRequest{
		Caller: local, ApplicationID: appA.ID, UserID: adminUser.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("管理员加入应用 A 失败: %v", err)
	}
	if err := adminAPI.GrantApplicationRole(ctx, GrantRoleRequest{
		Caller: local, UserID: adminUser.ID, RoleID: sysRole.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("本机受信操作者分配系统角色失败: %v", err)
	}
	appMembers := createPermission(appA.ID, "applications.members.manage", "管理应用成员")
	appRolesAssign := createPermission(appA.ID, "roles.assign", "分配应用角色")
	appRolesRead := createPermission(appA.ID, "roles.read", "读取应用角色")
	appPermsRead := createPermission(appA.ID, "permissions.read", "读取权限目录")
	appRead := createPermission(appA.ID, "app.a.read", "应用 A 业务读取")
	appDelete := createPermission(appA.ID, "users.delete", "删除用户（高权）")
	appAdminRole, err := adminAPI.CreateRole(ctx, AdminCreateRoleRequest{
		Caller: local, ScopeID: appA.ID, Key: "app-a-admin",
		Name: "应用 A 管理员", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建应用 A 管理员角色失败: %v", err)
	}
	for _, item := range []AdminPermission{appMembers, appRolesAssign, appRolesRead,
		appPermsRead, appRead} {
		if err := adminAPI.AddRolePermission(ctx, AdminRolePermissionRequest{
			Caller: local, RoleID: appAdminRole.ID, PermissionID: item.ID,
			RequestID: login.NewRequestID()}); err != nil {
			t.Fatalf("应用 A 管理员角色添加权限失败: %v", err)
		}
	}
	if err := adminAPI.GrantApplicationRole(ctx, GrantRoleRequest{
		Caller: local, UserID: adminUser.ID, RoleID: appAdminRole.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("本机受信操作者分配应用 A 管理员角色失败: %v", err)
	}
	// 为管理员签发可转授资格（受信通道）：管理员持有权限后，仍需“可转授资格”才能
	// 把该权限组合进角色再分配；越权/自我提权由委派引擎事务内复核拒绝。
	for _, permission := range []AdminPermission{appRead} {
		if _, err := adminAPI.GrantDelegation(ctx, AdminDelegationGrantRequest{
			Caller: local, DelegatorUserID: adminUser.ID, ScopeID: appA.ID,
			PermissionKey: permission.Key, RequestID: login.NewRequestID(),
		}); err != nil {
			t.Fatalf("签发委派资格 %s 失败: %v", permission.Key, err)
		}
	}
	appUserRole, err := adminAPI.CreateRole(ctx, AdminCreateRoleRequest{
		Caller: local, ScopeID: appA.ID, Key: "app-a-user",
		Name: "应用 A 普通用户", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建应用 A 用户角色失败: %v", err)
	}
	if err := adminAPI.AddRolePermission(ctx, AdminRolePermissionRequest{
		Caller: local, RoleID: appUserRole.ID, PermissionID: appRead.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("应用 A 用户角色添加权限失败: %v", err)
	}
	// 高权角色：包含管理员自身并不持有的 users.delete，用于越权转授/自我提权拒绝。
	powerfulRole, err := adminAPI.CreateRole(ctx, AdminCreateRoleRequest{
		Caller: local, ScopeID: appA.ID, Key: "app-a-powerful",
		Name: "应用 A 高权角色", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建高权角色失败: %v", err)
	}
	if err := adminAPI.AddRolePermission(ctx, AdminRolePermissionRequest{
		Caller: local, RoleID: powerfulRole.ID, PermissionID: appDelete.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("高权角色添加权限失败: %v", err)
	}

	// ===== 关闭自主注册后：管理员建用户与资料/角色/权限操作 =====
	closedConfig := runtime.Config()
	closedConfig.Registration.Enabled = false
	if err := runtime.Close(ctx); err != nil {
		t.Fatalf("关闭自举运行时失败: %v", err)
	}
	runtime = adminTestRuntime(t, ctx, closedConfig, dir, clock)
	if _, err := runtime.Users().Create(ctx, CreateUserRequest{
		Username: "self-register", Password: "P3@dF7$hJ1%kM5&n",
		RequestID: login.NewRequestID(),
	}); !login.IsErrorCode(err, login.CodeConfigInvalid) {
		t.Fatalf("关闭注册后自主注册入口应返回 CONFIG_INVALID，实际 %v", err)
	}
	// 管理员登录：TOTP 第二因素 -> 完整会话。
	clock.Advance(30 * time.Second)
	adminRestricted, err := runtime.Auth().Login(ctx, LoginRequest{
		Username: "admin-a", Password: adminPassword, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()})
	if err != nil || !adminRestricted.Restricted || adminRestricted.SecondFactor == nil {
		t.Fatalf("管理员登录应返回 TOTP 受限状态: %+v err=%v", adminRestricted, err)
	}
	adminVerified, err := runtime.Auth().VerifySecondFactor(ctx, VerifySecondFactorRequest{
		SessionSecret: adminRestricted.SessionSecret,
		ChallengeID:   adminRestricted.SecondFactor.ChallengeID,
		AttemptToken:  adminRestricted.SecondFactor.AttemptToken,
		Code:          currentTOTP(t, clock, totpStart.Secret),
		RequestID:     login.NewRequestID()})
	if err != nil {
		t.Fatalf("管理员第二因素验证失败: %v", err)
	}
	adminCall := runtime.AdminSession(adminVerified.SessionSecret)
	adminAPI = runtime.Admin()
	createdUser, err := adminAPI.CreateUser(ctx, AdminCreateUserRequest{
		Caller: adminCall, Username: "created-by-admin", Nickname: "被创建用户",
		ApplicationIDs: []string{appA.ID}, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("关闭注册时管理员建用户失败: %v", err)
	}
	// 资料读取/修改。
	profileBefore, err := adminAPI.GetUserProfile(ctx, AdminUserRequest{
		Caller: adminCall, UserID: createdUser.ID})
	if err != nil {
		t.Fatalf("读取用户资料失败: %v", err)
	}
	newNickname := "改名后的昵称"
	profileAfter, err := adminAPI.UpdateUserProfile(ctx, AdminUpdateProfileRequest{
		Caller: adminCall, UserID: createdUser.ID, Nickname: &newNickname,
		ExpectedRowVersion: profileBefore.RowVersion, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("更新用户资料失败: %v", err)
	}
	if profileAfter.Nickname != newNickname {
		t.Fatalf("资料更新未生效: %+v", profileAfter)
	}
	// 分配应用角色（敏感操作：密码 + TOTP 真实再次认证）。
	clock.Advance(30 * time.Second)
	if err := adminAPI.GrantApplicationRole(ctx, GrantRoleRequest{
		Caller: adminCall, UserID: createdUser.ID, RoleID: appUserRole.ID,
		Password: adminPassword, TOTPCode: currentTOTP(t, clock, totpStart.Secret),
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("管理员分配应用角色失败: %v", err)
	}
	local = runtime.LocalAdmin()
	effective, err := adminAPI.EffectivePermissions(ctx, AdminPermissionQuery{
		Caller: local, UserID: createdUser.ID, ScopeID: appA.ID})
	if err != nil {
		t.Fatalf("查询有效权限失败: %v", err)
	}
	if effective.DeniedCode != "" || !containsAdminPermission(effective.Permissions, "app.a.read") {
		t.Fatalf("分配后有效权限应包含 app.a.read: %+v", effective)
	}
	decision, err := adminAPI.CheckPermission(ctx, AdminPermissionCheck{
		Caller: local, UserID: createdUser.ID, ScopeID: appA.ID, Permission: "app.a.read"})
	if err != nil || !decision.Allowed {
		t.Fatalf("联合权限检查应允许 app.a.read: %+v err=%v", decision, err)
	}
	rolePermissions, err := adminAPI.ListRolePermissions(ctx, AdminRoleRequest{
		Caller: adminCall, RoleID: appUserRole.ID})
	if err != nil || len(rolePermissions) != 1 || rolePermissions[0].Key != "app.a.read" {
		t.Fatalf("角色权限组合异常: %+v err=%v", rolePermissions, err)
	}
	// 管理员自查自己（用户主体只能查询自己）也应成功。
	selfEffective, err := adminAPI.EffectivePermissions(ctx, AdminPermissionQuery{
		Caller: adminCall, UserID: adminUser.ID, ScopeID: appA.ID})
	if err != nil || selfEffective.DeniedCode != "" {
		t.Fatalf("管理员自查有效权限失败: %+v err=%v", selfEffective, err)
	}
	// 跨应用 B 写入：管理员在 B 没有任何权限，必须拒绝。
	if err := adminAPI.AddApplicationMember(ctx, AdminAddMemberRequest{
		Caller: adminCall, ApplicationID: appB.ID, UserID: createdUser.ID,
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeAccessDenied) {
		t.Fatalf("跨应用 B 加入成员应返回 ACCESS_DENIED，实际 %v", err)
	}
	// 自我/越权提权：分配包含管理员自身不持有权限（users.delete）的角色必须拒绝。
	clock.Advance(30 * time.Second)
	if err := adminAPI.GrantApplicationRole(ctx, GrantRoleRequest{
		Caller: adminCall, UserID: createdUser.ID, RoleID: powerfulRole.ID,
		Password: adminPassword, TOTPCode: currentTOTP(t, clock, totpStart.Secret),
		RequestID: login.NewRequestID()}); !isDeniedByPolicy(err) {
		t.Fatalf("越权转授高权角色应返回 ACCESS_DENIED/PERMISSION_REQUIRED，实际 %v", err)
	}
	// 普通用户伪造管理员：真实会话但无管理权限，必须拒绝。
	normalSession, err := runtime.Auth().Login(ctx, LoginRequest{
		Username: "normal-b", Password: normalPassword, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()})
	if err != nil || normalSession.Restricted {
		t.Fatalf("普通用户登录异常: %+v err=%v", normalSession, err)
	}
	if _, err := adminAPI.CreateUser(ctx, AdminCreateUserRequest{
		Caller:   runtime.AdminSession(normalSession.SessionSecret),
		Username: "forged-user", RequestID: login.NewRequestID(),
	}); !login.IsErrorCode(err, login.CodeAccessDenied) {
		t.Fatalf("普通用户伪造管理员应返回 ACCESS_DENIED，实际 %v", err)
	}
	// 伪造/零值调用上下文直接拒绝。
	if _, err := adminAPI.CreateUser(ctx, AdminCreateUserRequest{
		Caller: AdminCaller{}, Username: "zero-caller", RequestID: login.NewRequestID(),
	}); !login.IsErrorCode(err, login.CodeAccessDenied) {
		t.Fatalf("零值管理调用者应返回 ACCESS_DENIED，实际 %v", err)
	}
	// 撤销角色后权限立即失效。
	if err := adminAPI.RevokeApplicationRole(ctx, RevokeRoleRequest{
		Caller: adminCall, UserID: createdUser.ID, RoleID: appUserRole.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("撤回角色失败: %v", err)
	}
	afterRevoke, err := adminAPI.CheckPermission(ctx, AdminPermissionCheck{
		Caller: local, UserID: createdUser.ID, ScopeID: appA.ID, Permission: "app.a.read"})
	if err != nil {
		t.Fatalf("撤销后权限检查失败: %v", err)
	}
	if afterRevoke.Allowed {
		t.Fatalf("撤销角色后不应再有 app.a.read: %+v", afterRevoke)
	}
	effectiveAfterRevoke, err := adminAPI.EffectivePermissions(ctx, AdminPermissionQuery{
		Caller: local, UserID: createdUser.ID, ScopeID: appA.ID})
	if err != nil {
		t.Fatalf("撤销后有效权限查询失败: %v", err)
	}
	if containsAdminPermission(effectiveAfterRevoke.Permissions, "app.a.read") {
		t.Fatalf("撤销后有效权限仍包含 app.a.read: %+v", effectiveAfterRevoke)
	}

	// ===== 真实审计：操作者与关键动作可追踪 =====
	if count := auditCount(t, runtime, "user.create", "user", adminUser.ID); count < 1 {
		t.Fatalf("管理员建用户缺少真实审计（user.create, actor=admin-a）")
	}
	if count := auditCount(t, runtime, "role.assignment.user.assign", "user", adminUser.ID); count < 1 {
		t.Fatalf("管理员分配角色缺少真实审计（role.assignment.user.assign）")
	}
	if count := auditCount(t, runtime, "role.assignment.user.revoke", "user", adminUser.ID); count < 1 {
		t.Fatalf("管理员撤回角色缺少真实审计（role.assignment.user.revoke）")
	}
	if count := auditCount(t, runtime, "admin.local_operator.sensitive_approved", "local_admin", "host-operator"); count < 1 {
		t.Fatalf("本机受信操作者敏感引导缺少独立审计")
	}
	if rows := auditRowCount(t, runtime, "role.assignment.user.assign"); rows < 1 {
		t.Fatalf("角色分配审计表为空")
	}
	if _, err := runtime.base.Store.DB().Exec(`SELECT 1`); err != nil && err != sql.ErrNoRows {
		t.Fatalf("数据库句柄异常: %v", err)
	}
}

// isDeniedByPolicy 判断错误是否为权限/委派拒绝（不同层可能返回 ACCESS_DENIED 或
// PERMISSION_REQUIRED，都是稳定的默认拒绝语义）。
func isDeniedByPolicy(err error) bool {
	return login.IsErrorCode(err, login.CodeAccessDenied) ||
		login.IsErrorCode(err, login.CodePermissionRequired) ||
		login.IsErrorCode(err, login.CodeAppScopeMismatch)
}

// containsAdminPermission 判断权限组合是否包含指定键。
func containsAdminPermission(permissions []AdminPermission, key string) bool {
	for _, item := range permissions {
		if item.Key == key {
			return true
		}
	}
	return false
}
