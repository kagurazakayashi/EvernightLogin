package app

// 步骤 230：跨应用隔离的公开证据。
// 使用真实应用、应用范围权限与角色，验证普通管理会话只能读取被授权的应用范围：
//   - 应用 A 的 reports.read 授权允许 A 的统计，但 B 与 system 明确拒绝；
//   - 应用 B 的请求不会因拥有 A 的权限而成功；
//   - 拒绝为 ACCESS_DENIED，不泄露范围外数据是否存在。

import (
	"context"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

func TestAuditErrorStatsCrossApplicationIsolation(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC))
	runtime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	if err := runtime.Start(ctx); err != nil {
		t.Fatalf("启动运行时: %v", err)
	}
	local := runtime.LocalAdmin()
	adminAPI := runtime.Admin()
	user, err := runtime.Users().Create(ctx, CreateUserRequest{
		Username: "cross-app-user", Password: "T4!kR8#wQ2@mN6$z",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建跨应用用户: %v", err)
	}
	appA, err := adminAPI.CreateApplication(ctx, AdminCreateApplicationRequest{
		Caller: local, Name: "跨应用A", OwnerUserID: user.ID, ClientType: "public",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建应用 A: %v", err)
	}
	appB, err := adminAPI.CreateApplication(ctx, AdminCreateApplicationRequest{
		Caller: local, Name: "跨应用B", OwnerUserID: user.ID, ClientType: "public",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建应用 B: %v", err)
	}
	if _, err := adminAPI.SetApplicationEnabled(ctx, AdminSetApplicationEnabledRequest{
		Caller: local, ApplicationID: appA.ID, Enabled: true,
		ExpectedRowVersion: appA.RowVersion, RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("启用应用 A: %v", err)
	}
	if err := adminAPI.AddApplicationMember(ctx, AdminAddMemberRequest{Caller: local,
		ApplicationID: appA.ID, UserID: user.ID, RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("加入应用 A: %v", err)
	}
	permission, err := adminAPI.CreatePermission(ctx, AdminCreatePermissionRequest{
		Caller: local, ScopeID: appA.ID, Key: "reports.read", Name: "跨应用只读统计",
		Description: "仅用于跨应用隔离验收", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建应用 A 权限: %v", err)
	}
	role, err := adminAPI.CreateRole(ctx, AdminCreateRoleRequest{Caller: local,
		ScopeID: appA.ID, Key: "cross-app-reader", Name: "跨应用只读",
		Description: "仅用于跨应用隔离验收", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建应用 A 角色: %v", err)
	}
	if err := adminAPI.AddRolePermission(ctx, AdminRolePermissionRequest{
		Caller: local, RoleID: role.ID, PermissionID: permission.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("角色绑定权限: %v", err)
	}
	if err := adminAPI.GrantApplicationRole(ctx, GrantRoleRequest{Caller: local,
		UserID: user.ID, RoleID: role.ID, RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("授予应用角色: %v", err)
	}
	session, err := runtime.Auth().Login(ctx, LoginRequest{Username: user.Username,
		Password: "T4!kR8#wQ2@mN6$z", ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()})
	if err != nil || session.Restricted {
		t.Fatalf("登录跨应用用户: %+v err=%v", session, err)
	}
	caller := runtime.AdminSession(session.SessionSecret)
	window := AdminErrorStatsRequest{Caller: caller,
		Start: clock.Now().Add(-24 * time.Hour), End: clock.Now(), TimeZone: "UTC",
		Granularity: "day", Limit: 20, RequestID: login.NewRequestID()}
	// 应用 A：拥有 reports.read，应成功。
	allowed := window
	allowed.ScopeID = appA.ID
	if _, err := runtime.Audit().ErrorStats(ctx, allowed); err != nil {
		t.Fatalf("应用 A 统计应允许: %v", err)
	}
	// 应用 B：无权限，必须拒绝而不是返回空/全量。
	deniedB := window
	deniedB.ScopeID = appB.ID
	if _, err := runtime.Audit().ErrorStats(ctx, deniedB); !login.IsErrorCode(err,
		login.CodeAccessDenied) {
		t.Fatalf("应用 B 统计错误 = %v，期望 ACCESS_DENIED", err)
	}
	// system：普通用户没有系统范围权限，也必须拒绝。
	deniedSystem := window
	deniedSystem.ScopeID = "system"
	if _, err := runtime.Audit().ErrorStats(ctx, deniedSystem); !login.IsErrorCode(err,
		login.CodeAccessDenied) {
		t.Fatalf("system 统计错误 = %v，期望 ACCESS_DENIED", err)
	}
}
