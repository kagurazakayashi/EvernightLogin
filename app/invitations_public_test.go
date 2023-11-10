package app

// 步骤 223：邀请与注册审核公开接口测试（LocalAdmin 管理路径 + 普通用户拒绝 +
// 脱敏/未发信语义 + NOT_FOUND 契约）。应用范围邀请的完整权限链由生产
// InviteAuthorizer 装配覆盖，测试用普通用户无权限路径验证 fail-closed。

import (
	"context"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

// grantInvitePermission 给真实邀请发起者分配含 onboarding.invite.create 的系统角色。
func grantInvitePermission(t *testing.T, ctx context.Context, runtime *Runtime,
	userID string) {
	t.Helper()
	local := runtime.LocalAdmin()
	adminAPI := runtime.Admin()
	role, err := adminAPI.CreateRole(ctx, AdminCreateRoleRequest{
		Caller: local, ScopeID: "system", Key: "step223-inviter",
		Name: "邀请测试发起者", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建邀请角色失败: %v", err)
	}
	permission, err := adminAPI.CreatePermission(ctx, AdminCreatePermissionRequest{
		Caller: local, ScopeID: "system", Key: "onboarding.invite.create",
		Name: "创建受控邀请", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建邀请权限失败: %v", err)
	}
	if err := adminAPI.AddRolePermission(ctx, AdminRolePermissionRequest{
		Caller: local, RoleID: role.ID, PermissionID: permission.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("组合邀请权限失败: %v", err)
	}
	if err := adminAPI.GrantApplicationRole(ctx, GrantRoleRequest{
		Caller: local, UserID: userID, RoleID: role.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("分配邀请角色失败: %v", err)
	}
}

// loginSessionWithTOTP 用已绑定 TOTP 的账户登录并完成第二因素（若需要）。
func loginSessionWithTOTP(t *testing.T, ctx context.Context, runtime *Runtime,
	clock *testClock, username, password, totpSecret string) []byte {
	t.Helper()
	clock.Advance(30 * time.Second)
	loginResult, err := runtime.Auth().Login(ctx, LoginRequest{
		Username: username, Password: password, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("登录 %s 失败: %v", username, err)
	}
	if !loginResult.Restricted && len(loginResult.SessionSecret) > 0 {
		return loginResult.SessionSecret
	}
	if loginResult.SecondFactor == nil {
		t.Fatalf("登录 %s 受限但缺少第二因素挑战: %+v", username, loginResult)
	}
	verified, err := runtime.Auth().VerifySecondFactor(ctx, VerifySecondFactorRequest{
		SessionSecret: loginResult.SessionSecret,
		ChallengeID:   loginResult.SecondFactor.ChallengeID,
		AttemptToken:  loginResult.SecondFactor.AttemptToken,
		Code:          currentTOTP(t, clock, totpSecret), RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("验证 %s 第二因素失败: %v", username, err)
	}
	return verified.SessionSecret
}

// TestInvitationAdminLifecycle 覆盖邀请创建/读取/列表/取消与未发信语义。
// 创建必须由真实用户发起（数据库外键约束），LocalAdmin 负责读取/取消。
func TestInvitationAdminLifecycle(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 4, 30, 0, 0, time.UTC))
	runtime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	const password = "K8$wR3!nB6@yF1#v"
	inviterID, _, totpSecret := setupUserWithTOTP(t, runtime, clock, "invite-owner", password)
	grantInvitePermission(t, ctx, runtime, inviterID)
	inviterSession := loginSessionWithTOTP(t, ctx, runtime, clock, "invite-owner", password,
		totpSecret)
	inviterCaller := runtime.AdminSession(inviterSession)

	// LocalAdmin 不能作为邀请发起者：明确拒绝，不返回误导性存储错误。
	if _, err := runtime.Invitations().CreateInvitation(ctx,
		AdminCreateInvitationRequest{Caller: runtime.LocalAdmin(),
			TargetEmail: "local-denied@example.test", TTL: time.Hour,
			RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeConfigInvalid) {
		t.Fatalf("LocalAdmin 创建邀请错误 = %v，期望 CONFIG_INVALID", err)
	}

	created, err := runtime.Invitations().CreateInvitation(ctx,
		AdminCreateInvitationRequest{Caller: inviterCaller,
			TargetEmail: "invitee@example.test", TTL: time.Hour,
			RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}
	if created.Invitation.ID == "" || created.Invitation.Status != "pending" ||
		created.Invitation.TargetEmail != "invitee@example.test" ||
		created.Invitation.InviterUserID != inviterID {
		t.Fatalf("邀请视图异常: %+v", created.Invitation)
	}
	// 未配置邮件发送器：显式 TokenSent=false + 稳定错误码，不伪造已发送。
	if created.TokenSent || created.ErrorCode == "" {
		t.Fatalf("未配置邮件时语义异常: %+v", created)
	}

	local := runtime.LocalAdmin()
	got, err := runtime.Invitations().GetInvitation(ctx, AdminInvitationRequest{
		Caller: local, InvitationID: created.Invitation.ID,
		RequestID: login.NewRequestID()})
	if err != nil || got.ID != created.Invitation.ID {
		t.Fatalf("GetInvitation: %+v, %v", got, err)
	}
	list, err := runtime.Invitations().ListInvitations(ctx, AdminListInvitationsRequest{
		Caller: local, Status: "pending", Page: AdminPage{Limit: 10},
		RequestID: login.NewRequestID()})
	if err != nil || len(list.Invitations) != 1 || list.HasMore ||
		list.Page.Returned != 1 || list.Page.NextOffset != 1 {
		t.Fatalf("邀请列表异常: %+v, %v", list, err)
	}
	cancelled, err := runtime.Invitations().CancelInvitation(ctx,
		AdminCancelInvitationRequest{Caller: local,
			InvitationID: created.Invitation.ID, Reason: "测试取消",
			RequestID: login.NewRequestID()})
	if err != nil || !cancelled.Cancelled ||
		cancelled.Invitation.Status != "cancelled" {
		t.Fatalf("取消结果异常: %+v, %v", cancelled, err)
	}
	// 重复取消幂等：不报错、Cancelled=false。
	again, err := runtime.Invitations().CancelInvitation(ctx,
		AdminCancelInvitationRequest{Caller: local,
			InvitationID: created.Invitation.ID, RequestID: login.NewRequestID()})
	if err != nil || again.Cancelled {
		t.Fatalf("重复取消应幂等成功: %+v, %v", again, err)
	}
	if _, err := runtime.Invitations().GetInvitation(ctx, AdminInvitationRequest{
		Caller: local, InvitationID: "inv_00000000000000000000000000000000",
		RequestID: login.NewRequestID()}); !IsNotFound(err) {
		t.Fatalf("不存在邀请错误 = %v，期望 NOT_FOUND", err)
	}
}

// TestInvitationAdminDeniedForNormalUser 覆盖普通用户无邀请创建权限时 fail-closed。
func TestInvitationAdminDeniedForNormalUser(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 4, 40, 0, 0, time.UTC))
	runtime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	const password = "K8$wR3!nB6@yF1#v"
	createLifecycleUser(t, ctx, runtime, "invite-normal", password)
	session := loginLifecycleUser(t, ctx, runtime, "invite-normal", password)
	normalCaller := runtime.AdminSession(session)

	if _, err := runtime.Invitations().CreateInvitation(ctx,
		AdminCreateInvitationRequest{Caller: normalCaller,
			TargetEmail: "denied@example.test", TTL: time.Hour,
			RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeAccessDenied) {
		t.Fatalf("普通用户创建邀请错误 = %v，期望 ACCESS_DENIED", err)
	}
	// 普通用户可以列出“自己发起的”邀请（空列表），不是全局泄露。
	list, err := runtime.Invitations().ListInvitations(ctx,
		AdminListInvitationsRequest{Caller: normalCaller,
			Page: AdminPage{Limit: 10}, RequestID: login.NewRequestID()})
	if err != nil || len(list.Invitations) != 0 {
		t.Fatalf("普通用户自己的邀请列表 = %+v, %v", list, err)
	}
}

// TestRegistrationReviewAdminSurface 覆盖注册审核列表/详情在受信管理通道可用，
// 并对不存在目标返回 NOT_FOUND；待审核账户的完整通过/拒绝链依赖注册入口创建
// pending 账户（公开注册 Go 接口属步骤 221），本测试如实不伪造 pending 账户。
func TestRegistrationReviewAdminSurface(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 4, 50, 0, 0, time.UTC))
	runtime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	local := runtime.LocalAdmin()
	list, err := runtime.Invitations().ListPendingRegistrations(ctx,
		AdminListRegistrationsRequest{Caller: local, Page: AdminPage{Limit: 10},
			RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("ListPendingRegistrations: %v", err)
	}
	if len(list.Registrations) != 0 || list.HasMore {
		t.Fatalf("空待审核列表异常: %+v", list)
	}
	if _, err := runtime.Invitations().GetRegistration(ctx, AdminRegistrationRequest{
		Caller: local, UserID: "usr_00000000000000000000000000000000",
		RequestID: login.NewRequestID()}); !IsNotFound(err) {
		t.Fatalf("不存在待审核账户错误 = %v，期望 NOT_FOUND", err)
	}
}
