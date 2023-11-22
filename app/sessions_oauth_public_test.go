package app

// 步骤 226：会话管理公开接口测试。
//   - 本人设备查询/指定设备退出/退出其他设备（幂等、非本人不泄露、无会话拒绝）；
//   - 管理员按范围强制下线（真实管理会话 + 强再次认证；LocalAdmin 拒绝）；
//   - 审计失败回滚：撤销失败时目标会话仍有效。

import (
	"context"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

// loginForSessions 用真实密码登录并返回会话结果（用于多设备场景）。
func loginForSessions(t *testing.T, ctx context.Context, runtime *Runtime,
	username, password string) LoginResult {
	t.Helper()
	result, err := runtime.Auth().Login(ctx, LoginRequest{
		Username: username, Password: password, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("登录 %s 失败: %v", username, err)
	}
	if result.Restricted {
		t.Fatalf("用户 %s 登录不应要求第二因素", username)
	}
	return result
}

// TestSessionDeviceManagementPublicFlow 覆盖本人会话查询/指定退出/退出其他设备。
func TestSessionDeviceManagementPublicFlow(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 8, 0, 0, 0, time.UTC))
	runtime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	const password = "K8$wR3!nB6@yF1#v"
	createLifecycleUser(t, ctx, runtime, "session-device-user", password)
	sessions := runtime.Sessions()

	first := loginForSessions(t, ctx, runtime, "session-device-user", password)
	second := loginForSessions(t, ctx, runtime, "session-device-user", password)
	third := loginForSessions(t, ctx, runtime, "session-device-user", password)

	list, err := sessions.ListDevices(ctx, SessionDeviceRequest{
		SessionSecret: first.SessionSecret})
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if list.Total != 3 || len(list.Devices) != 3 {
		t.Fatalf("设备列表数量异常: total=%d len=%d", list.Total, len(list.Devices))
	}
	current := 0
	for _, device := range list.Devices {
		if device.Current {
			current++
			if device.ID != first.SessionID {
				t.Fatalf("当前会话标记错误: %+v", device)
			}
		}
	}
	if current != 1 {
		t.Fatalf("当前会话标记数量 = %d，期望 1", current)
	}
	// 指定退出另一台设备：成功且立即失效；当前会话仍有效。
	revoked, err := sessions.RevokeDevice(ctx, SessionDeviceRevokeRequest{
		SessionSecret: first.SessionSecret, TargetSessionID: second.SessionID,
		RequestID: login.NewRequestID()})
	if err != nil || !revoked.Revoked {
		t.Fatalf("RevokeDevice(second): %+v, %v", revoked, err)
	}
	if _, err := sessions.Validate(ctx, second.SessionSecret); !login.IsErrorCode(err,
		login.CodeAuthFailed) {
		t.Fatalf("被退出会话仍有效: %v", err)
	}
	if _, err := sessions.Validate(ctx, first.SessionSecret); err != nil {
		t.Fatalf("当前会话不应被影响: %v", err)
	}
	// 重复退出：幂等 Revoked=false。
	again, err := sessions.RevokeDevice(ctx, SessionDeviceRevokeRequest{
		SessionSecret: first.SessionSecret, TargetSessionID: second.SessionID,
		RequestID: login.NewRequestID()})
	if err != nil || again.Revoked {
		t.Fatalf("重复退出应幂等: %+v, %v", again, err)
	}
	// 非本人会话：幂等 false，不泄露且不影响他人会话。
	createLifecycleUser(t, ctx, runtime, "session-device-other", password)
	other := loginForSessions(t, ctx, runtime, "session-device-other", password)
	foreign, err := sessions.RevokeDevice(ctx, SessionDeviceRevokeRequest{
		SessionSecret: first.SessionSecret, TargetSessionID: other.SessionID,
		RequestID: login.NewRequestID()})
	if err != nil || foreign.Revoked {
		t.Fatalf("退出他人会话结果异常: %+v, %v", foreign, err)
	}
	if _, err := sessions.Validate(ctx, other.SessionSecret); err != nil {
		t.Fatalf("他人会话不应受影响: %v", err)
	}
	// 非法会话：稳定拒绝。
	if _, err := sessions.RevokeDevice(ctx, SessionDeviceRevokeRequest{
		SessionSecret: []byte("invalid-session"), TargetSessionID: third.SessionID,
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeAuthFailed) {
		t.Fatalf("非法会话退出错误 = %v，期望 AUTH_FAILED", err)
	}
	// 退出其他设备（保留当前）：撤销 third，当前 first 仍有效。
	removed, err := sessions.RevokeOtherDevices(ctx, SessionRevokeOthersRequest{
		SessionSecret: first.SessionSecret, KeepCurrent: true,
		RequestID: login.NewRequestID()})
	if err != nil || removed.Revoked < 1 || !removed.KeptCurrent {
		t.Fatalf("RevokeOtherDevices(keep): %+v, %v", removed, err)
	}
	if _, err := sessions.Validate(ctx, third.SessionSecret); !login.IsErrorCode(err,
		login.CodeAuthFailed) {
		t.Fatalf("其他设备未失效: %v", err)
	}
	if _, err := sessions.Validate(ctx, first.SessionSecret); err != nil {
		t.Fatalf("保留的当前会话不应失效: %v", err)
	}
	// 退出全部（含当前）：当前会话立即失效。
	if _, err := sessions.RevokeOtherDevices(ctx, SessionRevokeOthersRequest{
		SessionSecret: first.SessionSecret, KeepCurrent: false,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("RevokeOtherDevices(all): %v", err)
	}
	if _, err := sessions.Validate(ctx, first.SessionSecret); !login.IsErrorCode(err,
		login.CodeAuthFailed) {
		t.Fatalf("退出全部后当前会话仍有效: %v", err)
	}
}

// TestSessionRevokeAuditFailureRollsBack 覆盖审计失败时不撤销会话。
func TestSessionRevokeAuditFailureRollsBack(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 8, 20, 0, 0, time.UTC))
	runtime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	const password = "K8$wR3!nB6@yF1#v"
	createLifecycleUser(t, ctx, runtime, "session-audit-user", password)
	first := loginForSessions(t, ctx, runtime, "session-audit-user", password)
	second := loginForSessions(t, ctx, runtime, "session-audit-user", password)
	db := runtime.base.Store.DB()
	if _, err := db.Exec(`CREATE TRIGGER step226_audit_failure BEFORE INSERT ON audit_events
WHEN NEW.action='session.revoke_own' BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END;`); err != nil {
		t.Fatalf("注入审计失败触发器: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DROP TRIGGER IF EXISTS step226_audit_failure`) })
	if _, err := runtime.Sessions().RevokeDevice(ctx, SessionDeviceRevokeRequest{
		SessionSecret: first.SessionSecret, TargetSessionID: second.SessionID,
		RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("审计失败时撤销不应成功")
	}
	if _, err := runtime.Sessions().Validate(ctx, second.SessionSecret); err != nil {
		t.Fatalf("审计失败后目标会话不应被撤销: %v", err)
	}
}

// TestAdminRevokeSessionsPublicFlow 覆盖管理员强制下线的公开边界。
//
// 成功路径需要“真实强认证管理会话”（Passkey UV；测试运行时未启用 Passkey，TOTP
// 默认不满足管理强认证），因此本测试只覆盖公开门面的稳定拒绝与参数契约；内部
// internal/session 已有 AdminRevoke 成功/范围/root 保护测试，公开门面只是同一服务
// 的薄映射 + 真实再次认证上下文。
func TestAdminRevokeSessionsPublicFlow(t *testing.T) {
	ctx := context.Background()
	runtime, ctx, clock := lifecycleRuntimeWithClock(t)
	local := runtime.LocalAdmin()
	adminAPI := runtime.Admin()
	const password = "K8$wR3!nB6@yF1#v"
	adminUserID, _, totpSecret := setupUserWithTOTP(t, runtime, clock, "session-admin", password)
	adminSession := loginSessionWithTOTP(t, ctx, runtime, clock, "session-admin", password,
		totpSecret)
	// 授予系统范围 sessions.revoke 权限（用于验证授权拒绝不是“缺权限”误判）。
	permission, err := adminAPI.CreatePermission(ctx, AdminCreatePermissionRequest{
		Caller: local, ScopeID: "system", Key: "sessions.revoke", Name: "强制会话退出",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建 sessions.revoke 权限失败: %v", err)
	}
	role, err := adminAPI.CreateRole(ctx, AdminCreateRoleRequest{
		Caller: local, ScopeID: "system", Key: "step226-session-admin",
		Name: "会话管理员测试角色", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建会话管理员角色失败: %v", err)
	}
	if err := adminAPI.AddRolePermission(ctx, AdminRolePermissionRequest{
		Caller: local, RoleID: role.ID, PermissionID: permission.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("组合会话管理员权限失败: %v", err)
	}
	if err := adminAPI.GrantApplicationRole(ctx, GrantRoleRequest{
		Caller: local, UserID: adminUserID, RoleID: role.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("分配会话管理员角色失败: %v", err)
	}
	targetUser := createLifecycleUser(t, ctx, runtime, "session-target", password)
	targetSession := loginForSessions(t, ctx, runtime, "session-target", password)
	adminCaller := runtime.AdminSession(adminSession)
	// 缺少真实再次认证：拒绝，目标会话不变。
	if _, err := adminAPI.RevokeUserSessions(ctx, AdminRevokeSessionsRequest{
		Caller: adminCaller, TargetUserID: targetUser.ID, Reason: "无再次认证测试",
		RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("缺少再次认证不应允许强制下线")
	}
	if _, err := runtime.Sessions().Validate(ctx, targetSession.SessionSecret); err != nil {
		t.Fatalf("拒绝后目标会话不应被撤销: %v", err)
	}
	// 有权限但无强认证管理会话（TOTP 不满足管理强认证）：仍拒绝且不撤销目标。
	clock.Advance(30 * time.Second)
	if _, err := adminAPI.RevokeUserSessions(ctx, AdminRevokeSessionsRequest{
		Caller: adminCaller, TargetUserID: targetUser.ID, Reason: "强认证缺失测试",
		Password: password, TOTPCode: currentTOTP(t, clock, totpSecret),
		RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("缺少管理强认证时不应允许强制下线")
	}
	if _, err := runtime.Sessions().Validate(ctx, targetSession.SessionSecret); err != nil {
		t.Fatalf("强认证拒绝后目标会话不应被撤销: %v", err)
	}
	// LocalAdmin 没有真实管理会话，不能强制下线。
	if _, err := adminAPI.RevokeUserSessions(ctx, AdminRevokeSessionsRequest{
		Caller: local, TargetUserID: targetUser.ID, Reason: "本地旁路测试",
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeAccessDenied) {
		t.Fatalf("LocalAdmin 强制下线错误 = %v，期望 ACCESS_DENIED", err)
	}
	// 参数契约：必须且只能指定一个目标、理由必填（先于再次认证失败）。
	if _, err := adminAPI.RevokeUserSessions(ctx, AdminRevokeSessionsRequest{
		Caller: adminCaller, Reason: "空目标", Password: password,
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeReqInvalid) {
		t.Fatalf("空目标错误 = %v，期望 REQ_INVALID", err)
	}
	if _, err := adminAPI.RevokeUserSessions(ctx, AdminRevokeSessionsRequest{
		Caller: adminCaller, TargetUserID: targetUser.ID, Password: password,
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeReqInvalid) {
		t.Fatalf("空理由错误 = %v，期望 REQ_INVALID", err)
	}
}
