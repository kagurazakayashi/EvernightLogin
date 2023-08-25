package main

// 受信管理门面验收（步骤 182，外部 module 只使用公开 app 包）：
//   - 本机受信操作者自举应用/权限/角色/委派资格与首个应用管理员；
//   - 真实管理员用户会话建用户、读写资料、分配/撤回应用角色、查询权限；
//   - 跨应用写入、越权转授与普通用户伪造管理员被稳定拒绝；撤销立即生效。

import (
	"context"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/app"
)

// advanceTOTP 推进一个 TOTP 时间步并返回当前验证码（等价验证器 App）。
func advanceTOTP(clock *exampleClock, encodedSecret string) (string, error) {
	clock.Advance(30 * time.Second)
	return totpCode(encodedSecret, clock.Now())
}

// isDenied 判断错误是否为稳定的默认拒绝（权限不足/委派拒绝）。
func isDenied(err error) bool {
	return login.IsErrorCode(err, login.CodeAccessDenied) ||
		login.IsErrorCode(err, login.CodePermissionRequired) ||
		login.IsErrorCode(err, login.CodeAppScopeMismatch)
}

// runAdminScenario 完成步骤 182 的外部 module 验收场景。
func runAdminScenario(ctx context.Context, runtime *app.Runtime, clock *exampleClock,
	totpSecret, adminUserID, adminPassword string) error {
	adminAPI := runtime.Admin()
	local := runtime.LocalAdmin()
	createApp := func(name string) (app.AdminApplication, error) {
		created, err := adminAPI.CreateApplication(ctx, app.AdminCreateApplicationRequest{
			Caller: local, Name: name, ClientType: "confidential",
			RequestID: login.NewRequestID()})
		if err != nil {
			return app.AdminApplication{}, err
		}
		return adminAPI.SetApplicationEnabled(ctx, app.AdminSetApplicationEnabledRequest{
			Caller: local, ApplicationID: created.ID, Enabled: true,
			ExpectedRowVersion: created.RowVersion, RequestID: login.NewRequestID()})
	}
	createPermission := func(scopeID, key, name string) (app.AdminPermission, error) {
		return adminAPI.CreatePermission(ctx, app.AdminCreatePermissionRequest{
			Caller: local, ScopeID: scopeID, Key: key, Name: name,
			RequestID: login.NewRequestID()})
	}
	createRole := func(scopeID, key, name string) (app.AdminRole, error) {
		return adminAPI.CreateRole(ctx, app.AdminCreateRoleRequest{
			Caller: local, ScopeID: scopeID, Key: key, Name: name,
			RequestID: login.NewRequestID()})
	}
	addPermission := func(roleID string, permission app.AdminPermission) error {
		return adminAPI.AddRolePermission(ctx, app.AdminRolePermissionRequest{
			Caller: local, RoleID: roleID, PermissionID: permission.ID,
			RequestID: login.NewRequestID()})
	}
	grant := func(userID, roleID string) error {
		return adminAPI.GrantApplicationRole(ctx, app.GrantRoleRequest{
			Caller: local, UserID: userID, RoleID: roleID, RequestID: login.NewRequestID()})
	}

	appA, err := createApp("管理验收应用 A")
	if err != nil {
		return fmt.Errorf("创建应用 A 失败: %w", err)
	}
	appB, err := createApp("管理验收应用 B")
	if err != nil {
		return fmt.Errorf("创建应用 B 失败: %w", err)
	}
	// 系统范围权限与角色：全局账户资格（建用户/读改资料）。
	sysPermissions := make([]app.AdminPermission, 0, 3)
	for _, spec := range []struct{ key, name string }{
		{"users.create", "创建用户"}, {"users.read", "读取用户"}, {"users.update", "更新资料"},
	} {
		permission, permErr := createPermission("system", spec.key, spec.name)
		if permErr != nil {
			return fmt.Errorf("创建系统权限 %s 失败: %w", spec.key, permErr)
		}
		sysPermissions = append(sysPermissions, permission)
	}
	sysRole, err := createRole("system", "app-admin-global", "全局用户管理员")
	if err != nil {
		return fmt.Errorf("创建系统角色失败: %w", err)
	}
	for _, permission := range sysPermissions {
		if err := addPermission(sysRole.ID, permission); err != nil {
			return fmt.Errorf("系统角色添加权限失败: %w", err)
		}
	}
	if err := grant(adminUserID, sysRole.ID); err != nil {
		return fmt.Errorf("分配系统角色失败: %w", err)
	}
	// 应用 A 内权限与角色：成员/角色管理 + 业务读取 + 一个高权权限用于拒绝验证。
	appPermissions := make(map[string]app.AdminPermission)
	for _, spec := range []struct{ key, name string }{
		{"applications.members.manage", "管理应用成员"},
		{"roles.assign", "分配应用角色"},
		{"roles.read", "读取应用角色"},
		{"app.a.read", "应用 A 业务读取"},
		{"users.delete", "高权删除用户"},
	} {
		permission, permErr := createPermission(appA.ID, spec.key, spec.name)
		if permErr != nil {
			return fmt.Errorf("创建应用权限 %s 失败: %w", spec.key, permErr)
		}
		appPermissions[spec.key] = permission
	}
	if err := adminAPI.AddApplicationMember(ctx, app.AdminAddMemberRequest{
		Caller: local, ApplicationID: appA.ID, UserID: adminUserID,
		RequestID: login.NewRequestID()}); err != nil {
		return fmt.Errorf("管理员加入应用 A 失败: %w", err)
	}
	appAdminRole, err := createRole(appA.ID, "app-a-admin", "应用 A 管理员")
	if err != nil {
		return fmt.Errorf("创建应用 A 管理员角色失败: %w", err)
	}
	for _, key := range []string{"applications.members.manage", "roles.assign",
		"roles.read", "app.a.read"} {
		if err := addPermission(appAdminRole.ID, appPermissions[key]); err != nil {
			return fmt.Errorf("应用 A 管理员角色添加权限失败: %w", err)
		}
	}
	if err := grant(adminUserID, appAdminRole.ID); err != nil {
		return fmt.Errorf("分配应用 A 管理员角色失败: %w", err)
	}
	appUserRole, err := createRole(appA.ID, "app-a-user", "应用 A 普通用户")
	if err != nil {
		return fmt.Errorf("创建应用 A 用户角色失败: %w", err)
	}
	if err := addPermission(appUserRole.ID, appPermissions["app.a.read"]); err != nil {
		return fmt.Errorf("应用 A 用户角色添加权限失败: %w", err)
	}
	powerfulRole, err := createRole(appA.ID, "app-a-powerful", "应用 A 高权角色")
	if err != nil {
		return fmt.Errorf("创建高权角色失败: %w", err)
	}
	if err := addPermission(powerfulRole.ID, appPermissions["users.delete"]); err != nil {
		return fmt.Errorf("高权角色添加权限失败: %w", err)
	}
	// 管理员要转授 app.a.read，需要对应“可转授资格”（受信通道签发）。
	if _, err := adminAPI.GrantDelegation(ctx, app.AdminDelegationGrantRequest{
		Caller: local, DelegatorUserID: adminUserID, ScopeID: appA.ID,
		PermissionKey: "app.a.read", RequestID: login.NewRequestID()}); err != nil {
		return fmt.Errorf("签发委派资格失败: %w", err)
	}

	// 真实管理员会话：重新以密码 + TOTP 完成登录，再执行管理操作。
	clock.Advance(30 * time.Second)
	restricted, err := runtime.Auth().Login(ctx, app.LoginRequest{
		Username: "alice", Password: adminPassword, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()})
	if err != nil || !restricted.Restricted || restricted.SecondFactor == nil {
		return fmt.Errorf("管理员重新登录异常: %+v err=%v", restricted, err)
	}
	code, err := totpCode(totpSecret, clock.Now())
	if err != nil {
		return err
	}
	verified, err := runtime.Auth().VerifySecondFactor(ctx, app.VerifySecondFactorRequest{
		SessionSecret: restricted.SessionSecret,
		ChallengeID:   restricted.SecondFactor.ChallengeID,
		AttemptToken:  restricted.SecondFactor.AttemptToken,
		Code:          code, RequestID: login.NewRequestID()})
	if err != nil {
		return fmt.Errorf("管理员第二因素验证失败: %w", err)
	}
	adminSession := runtime.AdminSession(verified.SessionSecret)
	createdStaff, err := adminAPI.CreateUser(ctx, app.AdminCreateUserRequest{
		Caller: adminSession, Username: "staff-1", Nickname: "员工一",
		ApplicationIDs: []string{appA.ID}, RequestID: login.NewRequestID()})
	if err != nil {
		return fmt.Errorf("管理员建用户失败: %w", err)
	}
	profileBefore, err := adminAPI.GetUserProfile(ctx, app.AdminUserRequest{
		Caller: adminSession, UserID: createdStaff.ID})
	if err != nil {
		return fmt.Errorf("读取用户资料失败: %w", err)
	}
	nickname := "员工一改名"
	profileAfter, err := adminAPI.UpdateUserProfile(ctx, app.AdminUpdateProfileRequest{
		Caller: adminSession, UserID: createdStaff.ID, Nickname: &nickname,
		ExpectedRowVersion: profileBefore.RowVersion, RequestID: login.NewRequestID()})
	if err != nil {
		return fmt.Errorf("更新用户资料失败: %w", err)
	}
	if profileAfter.Nickname != nickname {
		return fmt.Errorf("资料更新未生效: %+v", profileAfter)
	}
	// 分配应用角色（敏感操作：密码 + TOTP 真实再次认证）。
	code, err = advanceTOTP(clock, totpSecret)
	if err != nil {
		return err
	}
	if err := adminAPI.GrantApplicationRole(ctx, app.GrantRoleRequest{
		Caller: adminSession, UserID: createdStaff.ID, RoleID: appUserRole.ID,
		Password: adminPassword, TOTPCode: code,
		RequestID: login.NewRequestID()}); err != nil {
		return fmt.Errorf("管理员分配应用角色失败: %w", err)
	}
	effective, err := adminAPI.EffectivePermissions(ctx, app.AdminPermissionQuery{
		Caller: local, UserID: createdStaff.ID, ScopeID: appA.ID})
	if err != nil {
		return fmt.Errorf("查询有效权限失败: %w", err)
	}
	if effective.DeniedCode != "" || !hasPermission(effective.Permissions, "app.a.read") {
		return fmt.Errorf("分配后有效权限应包含 app.a.read: %+v", effective)
	}
	decision, err := adminAPI.CheckPermission(ctx, app.AdminPermissionCheck{
		Caller: local, UserID: createdStaff.ID, ScopeID: appA.ID, Permission: "app.a.read"})
	if err != nil || !decision.Allowed {
		return fmt.Errorf("联合权限检查应允许 app.a.read: %+v err=%v", decision, err)
	}
	// 跨应用 B 写入：管理员在 B 无任何权限，必须拒绝。
	if err := adminAPI.AddApplicationMember(ctx, app.AdminAddMemberRequest{
		Caller: adminSession, ApplicationID: appB.ID, UserID: createdStaff.ID,
		RequestID: login.NewRequestID()}); !isDenied(err) {
		return fmt.Errorf("跨应用写入必须被拒绝，实际 %v", err)
	}
	// 越权转授：高权角色含管理员自身不持有的 users.delete，必须拒绝。
	code, err = advanceTOTP(clock, totpSecret)
	if err != nil {
		return err
	}
	if err := adminAPI.GrantApplicationRole(ctx, app.GrantRoleRequest{
		Caller: adminSession, UserID: createdStaff.ID, RoleID: powerfulRole.ID,
		Password: adminPassword, TOTPCode: code,
		RequestID: login.NewRequestID()}); !isDenied(err) {
		return fmt.Errorf("越权转授必须被拒绝，实际 %v", err)
	}
	// 普通用户伪造管理员：真实会话但无管理权限，必须拒绝。
	const malloryPassword = "M5!vB9#tG3@hN7$r"
	if _, err := runtime.Users().Create(ctx, app.CreateUserRequest{
		Username: "mallory", Password: malloryPassword, Nickname: "Mallory",
		RequestID: login.NewRequestID()}); err != nil {
		return fmt.Errorf("创建普通用户失败: %w", err)
	}
	malloryLogin, err := runtime.Auth().Login(ctx, app.LoginRequest{
		Username: "mallory", Password: malloryPassword, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()})
	if err != nil || malloryLogin.Restricted {
		return fmt.Errorf("普通用户登录异常: %+v err=%v", malloryLogin, err)
	}
	if _, err := adminAPI.CreateUser(ctx, app.AdminCreateUserRequest{
		Caller:   runtime.AdminSession(malloryLogin.SessionSecret),
		Username: "forged-user", RequestID: login.NewRequestID(),
	}); !isDenied(err) {
		return fmt.Errorf("普通用户伪造管理员必须被拒绝，实际 %v", err)
	}
	if _, err := adminAPI.CreateUser(ctx, app.AdminCreateUserRequest{
		Caller: app.AdminCaller{}, Username: "zero-caller",
		RequestID: login.NewRequestID(),
	}); !isDenied(err) {
		return fmt.Errorf("零值管理调用者必须被拒绝，实际 %v", err)
	}
	// 撤销角色后权限立即失效。
	if err := adminAPI.RevokeApplicationRole(ctx, app.RevokeRoleRequest{
		Caller: adminSession, UserID: createdStaff.ID, RoleID: appUserRole.ID,
		RequestID: login.NewRequestID()}); err != nil {
		return fmt.Errorf("撤回角色失败: %w", err)
	}
	afterRevoke, err := adminAPI.CheckPermission(ctx, app.AdminPermissionCheck{
		Caller: local, UserID: createdStaff.ID, ScopeID: appA.ID, Permission: "app.a.read"})
	if err != nil {
		return fmt.Errorf("撤销后权限检查失败: %w", err)
	}
	if afterRevoke.Allowed {
		return fmt.Errorf("撤销角色后不应再有 app.a.read: %+v", afterRevoke)
	}
	return nil
}

// hasPermission 判断权限组合是否包含指定键。
func hasPermission(permissions []app.AdminPermission, key string) bool {
	for _, permission := range permissions {
		if permission.Key == key {
			return true
		}
	}
	return false
}

// adminCreateUserWhileRegistrationDisabled 验证关闭自主注册后管理员仍可建用户。
func adminCreateUserWhileRegistrationDisabled(ctx context.Context, runtime *app.Runtime,
	clock *exampleClock, totpSecret, adminPassword string) error {
	clock.Advance(30 * time.Second)
	restricted, err := runtime.Auth().Login(ctx, app.LoginRequest{
		Username: "alice", Password: adminPassword, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()})
	if err != nil || !restricted.Restricted || restricted.SecondFactor == nil {
		return fmt.Errorf("关闭注册场景管理员登录异常: %+v err=%v", restricted, err)
	}
	code, err := totpCode(totpSecret, clock.Now())
	if err != nil {
		return err
	}
	verified, err := runtime.Auth().VerifySecondFactor(ctx, app.VerifySecondFactorRequest{
		SessionSecret: restricted.SessionSecret,
		ChallengeID:   restricted.SecondFactor.ChallengeID,
		AttemptToken:  restricted.SecondFactor.AttemptToken,
		Code:          code, RequestID: login.NewRequestID()})
	if err != nil {
		return fmt.Errorf("关闭注册场景第二因素验证失败: %w", err)
	}
	if _, err := runtime.Admin().CreateUser(ctx, app.AdminCreateUserRequest{
		Caller:   runtime.AdminSession(verified.SessionSecret),
		Username: "staff-closed-registration", RequestID: login.NewRequestID(),
	}); err != nil {
		return fmt.Errorf("关闭自主注册时管理员建用户失败: %w", err)
	}
	return nil
}
