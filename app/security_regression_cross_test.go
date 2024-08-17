package app

// 步骤 246：身份恢复与应用隔离跨步骤安全回归。
//
// 本文件只补“单个步骤测试之外”的交叉场景：
//   - 找回预检查不消费 → 完成改密 → 旧会话/旧密码/旧链接/重放全部按安全代际失效；
//   - 正常改密（另一入口）使仍 pending 的找回链接失效；
//   - 找回改密不解除 MFA：新密码登录仍必须完成 TOTP 第二步；
//   - 同一账户加入两个应用：成员移除/角色撤销后权限立即失效，另一应用不受影响。

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

// resetTokenFromMail 从找回邮件链接提取 token。
func resetTokenFromMail(t *testing.T, link string) string {
	t.Helper()
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatalf("解析找回链接失败: %v", err)
	}
	token := parsed.Query().Get("token")
	if token == "" {
		t.Fatal("找回链接缺少 token")
	}
	return token
}

// TestSecurityRegressionPasswordResetFullLifecycle 覆盖找回全链与安全代际失效。
func TestSecurityRegressionPasswordResetFullLifecycle(t *testing.T) {
	ctx := context.Background()
	capture := startSMTPCapture(t)
	clock := newTestClock(time.Date(2026, 11, 25, 6, 30, 0, 0, time.UTC))
	runtime := openMailRuntime(t, ctx, capture, clock)
	const oldPassword = "K8$wR3!nB6@yF1#v"
	const newPassword = "S9!kR4#mW7@qB2$x"
	const email = "reset-full@example.test"
	userID := supportRegisterVerifiedUser(t, ctx, runtime, capture, "reset-full", email, oldPassword)
	oldSession := supportLogin(t, ctx, runtime, "reset-full", oldPassword)

	// 发起找回（真实邮件投递），预检查不消费。
	if err := runtime.PasswordReset().Request(ctx, RequestPasswordResetRequest{
		Identifier: email, ClientIP: "127.0.0.1", RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("Request: %v", err)
	}
	token := resetTokenFromMail(t, capture.waitMail(t, "/login/reset-password"))
	if err := runtime.PasswordReset().ValidateTokenWithSource(ctx,
		ValidatePasswordResetTokenRequest{Token: token, ClientIP: "127.0.0.1",
			RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("预检查: %v", err)
	}
	result, err := runtime.PasswordReset().Complete(ctx, CompletePasswordResetRequest{
		Token: token, NewPassword: newPassword, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if result.UserID != userID || !result.RequiresRelogin || result.SessionsRevoked < 0 {
		t.Fatalf("找回结果异常: %+v", result)
	}
	// 旧会话、旧密码、旧链接重放、预检查重放全部失效。
	if _, err := runtime.Sessions().Validate(ctx, oldSession); err == nil {
		t.Fatal("找回后旧会话仍有效")
	}
	if _, err := runtime.Auth().Login(ctx, LoginRequest{Username: "reset-full",
		Password: oldPassword, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("找回后旧密码仍可登录")
	}
	if _, err := runtime.PasswordReset().Complete(ctx, CompletePasswordResetRequest{
		Token: token, NewPassword: "K8$wR3!nB6@yF1#v", ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeChallengeInvalid) {
		t.Fatalf("旧链接重放错误 = %v，期望 CHALLENGE_INVALID", err)
	}
	if err := runtime.PasswordReset().ValidateTokenWithSource(ctx,
		ValidatePasswordResetTokenRequest{Token: token, ClientIP: "127.0.0.1",
			RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeChallengeInvalid) {
		t.Fatalf("旧链接预检查错误 = %v，期望 CHALLENGE_INVALID", err)
	}
	// 新密码可以登录；旧会话不会复活。
	if _, err := runtime.Auth().Login(ctx, LoginRequest{Username: "reset-full",
		Password: newPassword, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("新密码登录失败: %v", err)
	}
	if _, err := runtime.Sessions().Validate(ctx, oldSession); err == nil {
		t.Fatal("旧会话在找回后仍可校验")
	}
}

// TestSecurityRegressionPasswordChangeInvalidatesPendingReset 覆盖另一入口改密后
// 仍 pending 的找回链接立即失效。
func TestSecurityRegressionPasswordChangeInvalidatesPendingReset(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 6, 40, 0, 0, time.UTC))
	runtime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	const oldPassword = "K8$wR3!nB6@yF1#v"
	const newPassword = "S9!kR4#mW7@qB2$x"
	user, err := runtime.Users().Create(ctx, CreateUserRequest{Username: "reset-invalidate",
		Password: oldPassword, Nickname: "重置失效测试", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建用户: %v", err)
	}
	seedVerifiedEmail(t, runtime, user.ID, "reset-invalidate@example.test")
	_, _, token := insertPendingReset(t, runtime, user.ID)
	session := loginLifecycleUser(t, ctx, runtime, "reset-invalidate", oldPassword)
	if _, err := runtime.Passwords().ChangeOwnPassword(ctx, ChangeOwnPasswordRequest{
		SessionSecret: session, CurrentPassword: oldPassword, NewPassword: newPassword,
		ClientIP: "127.0.0.1", RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("ChangeOwnPassword: %v", err)
	}
	// 改密后旧找回链接（预检查与完成）都必须失效。
	if err := runtime.PasswordReset().ValidateTokenWithSource(ctx,
		ValidatePasswordResetTokenRequest{Token: token, ClientIP: "127.0.0.1",
			RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeChallengeInvalid) {
		t.Fatalf("改密后旧找回预检查错误 = %v，期望 CHALLENGE_INVALID", err)
	}
	if _, err := runtime.PasswordReset().Complete(ctx, CompletePasswordResetRequest{
		Token: token, NewPassword: "T7!qZ2#Lm9@Tp4$x", ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeChallengeInvalid) {
		t.Fatalf("改密后旧找回完成错误 = %v，期望 CHALLENGE_INVALID", err)
	}
	if _, err := runtime.Sessions().Validate(ctx, session); err == nil {
		t.Fatal("改密后旧会话仍有效")
	}
}

// TestSecurityRegressionPasswordResetPreservesMFA 覆盖找回改密不解除 MFA。
func TestSecurityRegressionPasswordResetPreservesMFA(t *testing.T) {
	ctx := context.Background()
	capture := startSMTPCapture(t)
	clock := newTestClock(time.Date(2026, 11, 25, 6, 50, 0, 0, time.UTC))
	runtime := openMailRuntime(t, ctx, capture, clock)
	const oldPassword = "K8$wR3!nB6@yF1#v"
	const newPassword = "S9!kR4#mW7@qB2$x"
	userID := supportRegisterVerifiedUser(t, ctx, runtime, capture, "reset-mfa",
		"reset-mfa@example.test", oldPassword)
	_ = userID
	session := supportLogin(t, ctx, runtime, "reset-mfa", oldPassword)
	secret := supportBindTOTP(t, ctx, runtime, clock, session, oldPassword)
	// 绑定 TOTP 后旧会话仍可用；发起找回并完成改密。
	if err := runtime.PasswordReset().Request(ctx, RequestPasswordResetRequest{
		Identifier: "reset-mfa@example.test", ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("Request: %v", err)
	}
	token := resetTokenFromMail(t, capture.waitMail(t, "/login/reset-password"))
	if _, err := runtime.PasswordReset().Complete(ctx, CompletePasswordResetRequest{
		Token: token, NewPassword: newPassword, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	// 新密码登录仍要求 TOTP，证明找回没有解除 MFA。绑定确认已使用当前时间步的
	// TOTP 码，推进一个时间步避免正常的一次性重放保护干扰本回归。
	clock.Advance(30 * time.Second)
	restricted, err := runtime.Auth().Login(ctx, LoginRequest{Username: "reset-mfa",
		Password: newPassword, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("新密码登录: %v", err)
	}
	if !restricted.Restricted || restricted.SecondFactor == nil ||
		restricted.SecondFactor.FactorType != "totp" {
		t.Fatalf("找回后应仍要求 TOTP: %+v", restricted)
	}
	verified, err := runtime.Auth().VerifySecondFactor(ctx, VerifySecondFactorRequest{
		SessionSecret: restricted.SessionSecret,
		ChallengeID:   restricted.SecondFactor.ChallengeID,
		AttemptToken:  restricted.SecondFactor.AttemptToken,
		Code:          currentTOTP(t, clock, secret), RequestID: login.NewRequestID()})
	if err != nil || verified.SessionSecret == nil {
		t.Fatalf("TOTP 第二步失败: %+v err=%v", verified, err)
	}
}

// TestSecurityRegressionApplicationMembershipAndRoleRevocation 覆盖同一账户在多个
// 应用中的即时隔离：成员移除/应用角色撤销后权限立即失效，另一应用不受影响。
func TestSecurityRegressionApplicationMembershipAndRoleRevocation(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 7, 0, 0, 0, time.UTC))
	runtime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	local := runtime.LocalAdmin()
	user, err := runtime.Users().Create(ctx, CreateUserRequest{Username: "isolation-user",
		Password: "K8$wR3!nB6@yF1#v", Nickname: "共享账户", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建共享账户: %v", err)
	}
	makeApp := func(name string) (string, int64) {
		t.Helper()
		application, appErr := runtime.Admin().CreateApplication(ctx,
			AdminCreateApplicationRequest{Caller: local, Name: name, OwnerUserID: user.ID,
				ClientType: "public", RequestID: login.NewRequestID()})
		if appErr != nil {
			t.Fatalf("创建应用 %s: %v", name, appErr)
		}
		if _, appErr = runtime.Admin().SetApplicationEnabled(ctx,
			AdminSetApplicationEnabledRequest{Caller: local, ApplicationID: application.ID,
				Enabled: true, ExpectedRowVersion: application.RowVersion,
				RequestID: login.NewRequestID()}); appErr != nil {
			t.Fatalf("启用应用 %s: %v", name, appErr)
		}
		return application.ID, application.RowVersion
	}
	appA, _ := makeApp("隔离应用 A")
	appB, _ := makeApp("隔离应用 B")
	// 同一账户加入两个应用，并在各自范围获得同名权限。
	for _, appID := range []string{appA, appB} {
		if err := runtime.Admin().AddApplicationMember(ctx, AdminAddMemberRequest{
			Caller: local, ApplicationID: appID, UserID: user.ID,
			RequestID: login.NewRequestID()}); err != nil {
			t.Fatalf("加入应用: %v", err)
		}
		permission, err := runtime.Admin().CreatePermission(ctx, AdminCreatePermissionRequest{
			Caller: local, ScopeID: appID, Key: "inventory.read", Name: "库存只读",
			RequestID: login.NewRequestID()})
		if err != nil {
			t.Fatalf("创建应用权限: %v", err)
		}
		role, err := runtime.Admin().CreateRole(ctx, AdminCreateRoleRequest{Caller: local,
			ScopeID: appID, Key: "inventory-reader", Name: "库存只读角色",
			RequestID: login.NewRequestID()})
		if err != nil {
			t.Fatalf("创建应用角色: %v", err)
		}
		if err := runtime.Admin().AddRolePermission(ctx, AdminRolePermissionRequest{
			Caller: local, RoleID: role.ID, PermissionID: permission.ID,
			RequestID: login.NewRequestID()}); err != nil {
			t.Fatalf("角色绑定权限: %v", err)
		}
		if err := runtime.Admin().GrantApplicationRole(ctx, GrantRoleRequest{
			Caller: local, UserID: user.ID, RoleID: role.ID,
			RequestID: login.NewRequestID()}); err != nil {
			t.Fatalf("授予应用角色: %v", err)
		}
	}
	check := func(scopeID string) bool {
		t.Helper()
		result, checkErr := runtime.RBAC().Authorization().Check(ctx, RBACCheckRequest{
			Caller: local, SubjectUserID: user.ID, ScopeID: scopeID,
			Permissions: []string{"inventory.read"}, RequestID: login.NewRequestID()})
		if checkErr != nil {
			t.Fatalf("RBAC 检查 %s: %v", scopeID, checkErr)
		}
		return result.Allowed
	}
	if !check(appA) || !check(appB) {
		t.Fatal("同一账户在加入的两个应用中都应有权限")
	}
	// 从 A 移除成员：A 的权限立即拒绝，B 不受影响。
	member, err := runtime.Applications().GetApplicationMember(ctx,
		AdminApplicationMemberRequest{Caller: local, ApplicationID: appA, UserID: user.ID,
			RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("读取 A 成员: %v", err)
	}
	if err := runtime.Applications().RemoveApplicationMember(ctx,
		AdminApplicationMemberChangeRequest{Caller: local, ApplicationID: appA,
			UserID: user.ID, ExpectedRowVersion: member.RowVersion,
			RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("移除 A 成员: %v", err)
	}
	if check(appA) {
		t.Fatal("移除应用 A 成员后仍获得 A 权限")
	}
	if !check(appB) {
		t.Fatal("移除应用 A 成员不应影响应用 B 权限")
	}
	// 重新加入 A 并恢复角色后撤销应用角色：A 权限再次立即失效。
	if err := runtime.Admin().AddApplicationMember(ctx, AdminAddMemberRequest{
		Caller: local, ApplicationID: appA, UserID: user.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("重新加入 A: %v", err)
	}
	// 应用角色分配会随成员移除清理；重新获取 A 的角色并授予。
	roleList, err := runtime.Admin().ListRoles(ctx, AdminListRolesRequest{
		Caller: local, ScopeID: appA, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("列出 A 角色: %v", err)
	}
	var roleID string
	for _, item := range roleList.Roles {
		if item.Key == "inventory-reader" {
			roleID = item.ID
			break
		}
	}
	if roleID == "" {
		t.Fatal("未找到 A 应用角色")
	}
	if err := runtime.Admin().GrantApplicationRole(ctx, GrantRoleRequest{
		Caller: local, UserID: user.ID, RoleID: roleID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("恢复 A 角色: %v", err)
	}
	if !check(appA) {
		t.Fatal("恢复角色后 A 权限应生效")
	}
	if err := runtime.Admin().RevokeApplicationRole(ctx, RevokeRoleRequest{
		Caller: local, UserID: user.ID, RoleID: roleID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("撤销 A 角色: %v", err)
	}
	if check(appA) {
		t.Fatal("撤销应用 A 角色后权限仍生效")
	}
	if !check(appB) {
		t.Fatal("撤销应用 A 角色不应影响应用 B 权限")
	}
}
