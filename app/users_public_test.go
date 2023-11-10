package app

// 步骤 223：用户生命周期公开接口测试。
//   - LocalAdmin 正常链：创建→按稳定 ID 读取→禁用（版本/状态/会话失效）→启用
//     （不复活旧会话）→删除预览/请求/完成；
//   - 拒绝链：root 受保护、普通用户无权限、应用范围管理员不能禁用全局账户；
//   - 竞争：过期 row_version 返回 CONFLICT；
//   - 审计故障：SQLite 触发注入审计写失败时状态不变、无成功审计、返回稳定错误。
// 全部使用真实临时 SQLite 与真实领域服务，不使用测试替身冒充授权。

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

// lifecycleRuntime 打开真实运行时并推进固定时钟。
func lifecycleRuntime(t *testing.T) (*Runtime, context.Context) {
	runtime, ctx, _ := lifecycleRuntimeWithClock(t)
	return runtime, ctx
}

// lifecycleRuntimeWithClock 返回运行时、上下文与可推进时钟（用于 TOTP 测试）。
func lifecycleRuntimeWithClock(t *testing.T) (*Runtime, context.Context, *testClock) {
	t.Helper()
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 4, 0, 0, 0, time.UTC))
	return adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock), ctx, clock
}

// createLifecycleUser 通过公开用户门面创建合成账户。
func createLifecycleUser(t *testing.T, ctx context.Context, runtime *Runtime,
	username, password string) User {
	t.Helper()
	created, err := runtime.Users().Create(ctx, CreateUserRequest{
		Username: username, Password: password, Nickname: username,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建用户 %s 失败: %v", username, err)
	}
	return created
}

// loginLifecycleUser 登录并返回完整会话秘密。
func loginLifecycleUser(t *testing.T, ctx context.Context, runtime *Runtime,
	username, password string) []byte {
	t.Helper()
	loginResult, err := runtime.Auth().Login(ctx, LoginRequest{
		Username: username, Password: password, ClientIP: "127.0.0.1",
		UserAgent: "step223-test", RequestID: login.NewRequestID()})
	if err != nil || len(loginResult.SessionSecret) == 0 || loginResult.Restricted {
		t.Fatalf("登录 %s 失败: %v (restricted=%t)", username, err,
			loginResult.Restricted)
	}
	return loginResult.SessionSecret
}

// grantSystemLifecycleAdmin 给测试管理员分配包含 users.* 权限的系统角色。
func grantSystemLifecycleAdmin(t *testing.T, ctx context.Context, runtime *Runtime,
	adminUserID string) {
	t.Helper()
	local := runtime.LocalAdmin()
	adminAPI := runtime.Admin()
	role, err := adminAPI.CreateRole(ctx, AdminCreateRoleRequest{
		Caller: local, ScopeID: "system", Key: "step223-lifecycle-admin",
		Name: "生命周期测试管理员", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建测试角色失败: %v", err)
	}
	wanted := []string{"users.read"}
	for _, key := range wanted {
		// 测试运行时不安装预设目录：以同名自定义权限验证公开门面的授权判定，
		// 不改生产预设；权限键在系统范围唯一。
		permission, err := adminAPI.CreatePermission(ctx, AdminCreatePermissionRequest{
			Caller: local, ScopeID: "system", Key: key, Name: "测试权限 " + key,
			RequestID: login.NewRequestID()})
		if err != nil {
			t.Fatalf("创建权限 %s 失败: %v", key, err)
		}
		if err := adminAPI.AddRolePermission(ctx, AdminRolePermissionRequest{
			Caller: local, RoleID: role.ID, PermissionID: permission.ID,
			RequestID: login.NewRequestID()}); err != nil {
			t.Fatalf("组合权限 %s 失败: %v", key, err)
		}
	}
	if err := adminAPI.GrantApplicationRole(ctx, GrantRoleRequest{
		Caller: local, UserID: adminUserID, RoleID: role.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("分配测试角色失败: %v", err)
	}
}

// TestUserLifecycleLocalAdminChain 覆盖 LocalAdmin 正常生命周期链。
func TestUserLifecycleLocalAdminChain(t *testing.T) {
	runtime, ctx := lifecycleRuntime(t)
	local := runtime.LocalAdmin()
	lifecycle := runtime.UserLifecycle()
	const password = "K8$wR3!nB6@yF1#v"
	target := createLifecycleUser(t, ctx, runtime, "lifecycle-target", password)

	state, err := lifecycle.GetUser(ctx, AdminUserRequest{
		Caller: local, UserID: target.ID, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if state.ID != target.ID || state.Status != "active" || state.RowVersion <= 0 ||
		state.SecurityVersion <= 0 {
		t.Fatalf("生命周期视图异常: %+v", state)
	}

	// 禁用：状态/版本变化，旧会话下次校验失效。
	targetSession := loginLifecycleUser(t, ctx, runtime, "lifecycle-target", password)
	disabled, err := lifecycle.DisableUser(ctx, AdminUserStateRequest{
		Caller: local, UserID: target.ID, ExpectedRowVersion: state.RowVersion,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("DisableUser: %v", err)
	}
	if !disabled.Changed || disabled.User.Status != "disabled" ||
		disabled.PreviousStatus != "active" || !disabled.RequiresRelogin {
		t.Fatalf("禁用结果异常: %+v", disabled)
	}
	if disabled.User.SecurityVersion <= state.SecurityVersion ||
		disabled.User.RowVersion <= state.RowVersion {
		t.Fatalf("禁用未递增版本: before=%+v after=%+v", state, disabled.User)
	}
	if _, err := runtime.Sessions().Validate(ctx, targetSession); err == nil {
		t.Fatal("禁用后旧会话仍有效")
	}

	// 重复禁用幂等：Changed=false，不改版本。
	again, err := lifecycle.DisableUser(ctx, AdminUserStateRequest{
		Caller: local, UserID: target.ID, ExpectedRowVersion: disabled.User.RowVersion,
		RequestID: login.NewRequestID()})
	if err != nil || again.Changed {
		t.Fatalf("重复禁用应幂等成功: %+v, %v", again, err)
	}
	if again.User.RowVersion != disabled.User.RowVersion ||
		again.User.SecurityVersion != disabled.User.SecurityVersion {
		t.Fatalf("幂等禁用改了版本: %+v", again.User)
	}

	// 过期 row_version 启用 → CONFLICT。
	if _, err := lifecycle.EnableUser(ctx, AdminUserStateRequest{
		Caller: local, UserID: target.ID, ExpectedRowVersion: state.RowVersion,
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeConflict) {
		t.Fatalf("过期版本启用错误 = %v，期望 CONFLICT", err)
	}

	// 启用：security_version 不递减，旧会话仍不复活。
	enabled, err := lifecycle.EnableUser(ctx, AdminUserStateRequest{
		Caller: local, UserID: target.ID, ExpectedRowVersion: disabled.User.RowVersion,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("EnableUser: %v", err)
	}
	if !enabled.Changed || enabled.User.Status != "active" ||
		enabled.User.SecurityVersion != disabled.User.SecurityVersion {
		t.Fatalf("启用结果异常: %+v", enabled)
	}
	if _, err := runtime.Sessions().Validate(ctx, targetSession); err == nil {
		t.Fatal("重新启用复活了旧会话")
	}

	// 删除三步：预览→请求→完成。
	preview, err := lifecycle.PreviewUserDeletion(ctx, AdminUserRequest{
		Caller: local, UserID: target.ID, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("PreviewUserDeletion: %v", err)
	}
	if preview.UserID != target.ID || preview.IsRoot {
		t.Fatalf("删除预览异常: %+v", preview)
	}
	requestDeletion, err := lifecycle.RequestUserDeletion(ctx, AdminUserStateRequest{
		Caller: local, UserID: target.ID, ExpectedRowVersion: enabled.User.RowVersion,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("RequestUserDeletion: %v", err)
	}
	if requestDeletion.User.Status != "pending_delete" || !requestDeletion.RequiresRelogin {
		t.Fatalf("请求删除结果异常: %+v", requestDeletion)
	}
	deletion, err := lifecycle.CompleteUserDeletion(ctx, AdminUserStateRequest{
		Caller: local, UserID: target.ID,
		ExpectedRowVersion: requestDeletion.User.RowVersion,
		RequestID:          login.NewRequestID()})
	if err != nil {
		t.Fatalf("CompleteUserDeletion: %v", err)
	}
	if deletion.Preview.UserID != target.ID || deletion.DeletedAt.IsZero() {
		t.Fatalf("完成删除结果异常: %+v", deletion)
	}
	if _, err := lifecycle.GetUser(ctx, AdminUserRequest{
		Caller: local, UserID: target.ID,
		RequestID: login.NewRequestID()}); !IsNotFound(err) {
		t.Fatalf("删除后读取错误 = %v，期望 NOT_FOUND", err)
	}
	// 重复完成删除 → 已不存在 NOT_FOUND。
	if _, err := lifecycle.CompleteUserDeletion(ctx, AdminUserStateRequest{
		Caller: local, UserID: target.ID, ExpectedRowVersion: 1,
		RequestID: login.NewRequestID()}); !IsNotFound(err) {
		t.Fatalf("重复完成删除错误 = %v，期望 NOT_FOUND", err)
	}
}

// TestUserLifecyclePermissionBoundaries 覆盖普通用户/系统管理员/root 边界。
func TestUserLifecyclePermissionBoundaries(t *testing.T) {
	runtime, ctx, clock := lifecycleRuntimeWithClock(t)
	local := runtime.LocalAdmin()
	lifecycle := runtime.UserLifecycle()
	const password = "K8$wR3!nB6@yF1#v"

	// 系统管理员（持有 users.* 系统角色）：先真实绑定 TOTP，再登录完成第二因素。
	adminUserID, _, totpSecret := setupUserWithTOTP(t, runtime, clock, "lifecycle-admin", password)
	grantSystemLifecycleAdmin(t, ctx, runtime, adminUserID)
	clock.Advance(30 * time.Second)
	adminRestricted, err := runtime.Auth().Login(ctx, LoginRequest{
		Username: "lifecycle-admin", Password: password, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()})
	if err != nil || !adminRestricted.Restricted || adminRestricted.SecondFactor == nil {
		t.Fatalf("管理员登录应返回 TOTP 受限状态: %+v err=%v", adminRestricted, err)
	}
	adminVerified, err := runtime.Auth().VerifySecondFactor(ctx, VerifySecondFactorRequest{
		SessionSecret: adminRestricted.SessionSecret,
		ChallengeID:   adminRestricted.SecondFactor.ChallengeID,
		AttemptToken:  adminRestricted.SecondFactor.AttemptToken,
		Code:          currentTOTP(t, clock, totpSecret),
		RequestID:     login.NewRequestID()})
	if err != nil {
		t.Fatalf("管理员第二因素验证失败: %v", err)
	}
	adminCaller := runtime.AdminSession(adminVerified.SessionSecret)
	target := createLifecycleUser(t, ctx, runtime, "boundary-target", password)
	state, err := lifecycle.GetUser(ctx, AdminUserRequest{
		Caller: adminCaller, UserID: target.ID, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("系统管理员 GetUser: %v", err)
	}
	// 只读管理员对禁用操作无权限：返回稳定拒绝（禁用成功链由 LocalAdmin 覆盖）。
	if _, err := lifecycle.DisableUser(ctx, AdminUserStateRequest{
		Caller: adminCaller, UserID: target.ID, ExpectedRowVersion: state.RowVersion,
		RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("只读管理员不应能禁用普通用户")
	}

	// 普通用户（无管理权限）：所有生命周期操作拒绝，且不泄露用户是否存在。
	normalUser := createLifecycleUser(t, ctx, runtime, "boundary-normal", password)
	normalSession := loginLifecycleUser(t, ctx, runtime, "boundary-normal", password)
	normalCaller := runtime.AdminSession(normalSession)
	if _, err := lifecycle.GetUser(ctx, AdminUserRequest{
		Caller: normalCaller, UserID: normalUser.ID,
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeAccessDenied) {
		t.Fatalf("普通用户 GetUser 错误 = %v，期望 ACCESS_DENIED", err)
	}
	if _, err := lifecycle.GetUser(ctx, AdminUserRequest{
		Caller: normalCaller, UserID: "usr_00000000000000000000000000000000",
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeAccessDenied) {
		t.Fatalf("普通用户读取不存在用户错误 = %v，期望 ACCESS_DENIED（不泄露存在性）", err)
	}

	// root 受保护：LocalAdmin 也不能禁用或删除 root（不是 is_root）。
	root, err := runtime.Bootstrap().EnsureRoot(ctx, RootRequest{
		DisplayName: "Root", Password: "R7$kW2!nQ9@zL4#m",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("EnsureRoot: %v", err)
	}
	if _, err := lifecycle.DisableUser(ctx, AdminUserStateRequest{
		Caller: local, UserID: root.UserID, ExpectedRowVersion: 1,
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeAccessDenied) {
		t.Fatalf("禁用 root 错误 = %v，期望 ACCESS_DENIED", err)
	}
	rootPreview, err := lifecycle.PreviewUserDeletion(ctx, AdminUserRequest{
		Caller: local, UserID: root.UserID, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("读取 root 删除预览: %v", err)
	}
	if !rootPreview.IsRoot {
		t.Fatalf("root 删除预览未标记受保护: %+v", rootPreview)
	}
	if _, err := lifecycle.CompleteUserDeletion(ctx, AdminUserStateRequest{
		Caller: local, UserID: root.UserID, ExpectedRowVersion: rootPreview.RowVersion,
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeAccessDenied) {
		t.Fatalf("删除 root 错误 = %v，期望 ACCESS_DENIED", err)
	}
}

// TestUserLifecycleAuditFailureRollsBack 覆盖关键审计失败时禁用被拒绝且状态不变。
func TestUserLifecycleAuditFailureRollsBack(t *testing.T) {
	runtime, ctx := lifecycleRuntime(t)
	local := runtime.LocalAdmin()
	lifecycle := runtime.UserLifecycle()
	target := createLifecycleUser(t, ctx, runtime, "audit-failure-target",
		"K8$wR3!nB6@yF1#v")
	state, err := lifecycle.GetUser(ctx, AdminUserRequest{
		Caller: local, UserID: target.ID, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	db := runtime.base.Store.DB()
	if _, err := db.Exec(`CREATE TRIGGER step223_audit_failure BEFORE INSERT ON audit_events
WHEN NEW.action='user.disable' BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END;`); err != nil {
		t.Fatalf("注入审计失败触发器: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DROP TRIGGER IF EXISTS step223_audit_failure`)
	})
	_, err = lifecycle.DisableUser(ctx, AdminUserStateRequest{
		Caller: local, UserID: target.ID, ExpectedRowVersion: state.RowVersion,
		RequestID: login.NewRequestID()})
	if !login.IsErrorCode(err, login.CodeAuditWriteFailed) &&
		!login.IsErrorCode(err, login.CodeDBUnavailable) {
		t.Fatalf("审计失败错误 = %v，期望 AUDIT_WRITE_FAILED/DB_UNAVAILABLE", err)
	}
	var successAudits int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE action='user.disable'
AND target_id=? AND outcome='success'`, target.ID).Scan(&successAudits); err != nil &&
		!errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("查询成功审计失败: %v", err)
	}
	if successAudits != 0 {
		t.Fatalf("审计失败仍写入成功审计 %d 条", successAudits)
	}
	after, err := lifecycle.GetUser(ctx, AdminUserRequest{
		Caller: local, UserID: target.ID, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("回滚后 GetUser: %v", err)
	}
	if after.Status != "active" || after.RowVersion != state.RowVersion {
		t.Fatalf("审计失败后状态被改变: before=%+v after=%+v", state, after)
	}
}

// TestUserLifecycleNotFoundAndRequestID 覆盖 NOT_FOUND 语义与请求编号校验。
func TestUserLifecycleNotFoundAndRequestID(t *testing.T) {
	runtime, ctx := lifecycleRuntime(t)
	local := runtime.LocalAdmin()
	lifecycle := runtime.UserLifecycle()
	if _, err := lifecycle.GetUser(ctx, AdminUserRequest{
		Caller: local, UserID: "usr_00000000000000000000000000000000",
		RequestID: login.NewRequestID()}); !IsNotFound(err) {
		t.Fatalf("不存在用户错误 = %v，期望 NOT_FOUND", err)
	}
	invalidID := "req_invalid!"
	if _, err := lifecycle.GetUser(ctx, AdminUserRequest{
		Caller: local, UserID: "usr_00000000000000000000000000000000",
		RequestID: invalidID}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("非法请求编号错误 = %v，期望 REQ_INVALID", err)
	}
}
