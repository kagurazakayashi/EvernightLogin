package app

// 步骤 221 P0：个人资料与受控用户名更名公开接口测试。
//   - 会话派生身份：不接受 userID 传参，无效会话拒绝；
//   - 白名单资料更新 + 乐观并发冲突；
//   - 受控更名真实再次认证（密码）、错误密码拒绝、冷却期拒绝。

import (
	"context"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

// grantSelfProfilePermissions 给测试用户分配 self.profile.* 权限（测试运行时不安装
// 预设目录，用同名自定义权限验证真实授权判定）。
func grantSelfProfilePermissions(t *testing.T, ctx context.Context, runtime *Runtime,
	userID string) {
	t.Helper()
	local := runtime.LocalAdmin()
	adminAPI := runtime.Admin()
	role, err := adminAPI.CreateRole(ctx, AdminCreateRoleRequest{
		Caller: local, ScopeID: "system", Key: "step221-self-profile",
		Name: "自助资料测试角色", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建自助资料角色失败: %v", err)
	}
	for _, key := range []string{"self.profile.read", "self.profile.update"} {
		permission, err := adminAPI.CreatePermission(ctx, AdminCreatePermissionRequest{
			Caller: local, ScopeID: "system", Key: key, Name: "测试权限 " + key,
			RequestID: login.NewRequestID()})
		if err != nil {
			t.Fatalf("创建自助资料权限 %s 失败: %v", key, err)
		}
		if err := adminAPI.AddRolePermission(ctx, AdminRolePermissionRequest{
			Caller: local, RoleID: role.ID, PermissionID: permission.ID,
			RequestID: login.NewRequestID()}); err != nil {
			t.Fatalf("组合自助资料权限失败: %v", err)
		}
	}
	if err := adminAPI.GrantApplicationRole(ctx, GrantRoleRequest{
		Caller: local, UserID: userID, RoleID: role.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("分配自助资料角色失败: %v", err)
	}
}

// TestProfilePublicFlow 覆盖资料读取/更新与并发冲突。
func TestProfilePublicFlow(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 5, 0, 0, 0, time.UTC))
	runtime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	const password = "K8$wR3!nB6@yF1#v"
	user := createLifecycleUser(t, ctx, runtime, "profile-public", password)
	grantSelfProfilePermissions(t, ctx, runtime, user.ID)
	session := loginLifecycleUser(t, ctx, runtime, "profile-public", password)
	profiles := runtime.Profile()

	view, err := profiles.GetProfile(ctx, OwnProfileRequest{
		SessionSecret: session, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("GetProfile: %v", err)
	}
	if view.UserID != user.ID || view.Username != "profile-public" || view.RowVersion <= 0 {
		t.Fatalf("资料视图异常: %+v", view)
	}

	nickname := "新昵称"
	biography := "新的个人简介"
	updated, err := profiles.UpdateProfile(ctx, UpdateOwnProfileRequest{
		SessionSecret: session, Nickname: &nickname, Biography: &biography,
		ExpectedRowVersion: view.RowVersion, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}
	if updated.Nickname != nickname || updated.Biography != biography ||
		updated.RowVersion <= view.RowVersion {
		t.Fatalf("资料更新结果异常: %+v", updated)
	}
	// 过期 row_version → CONFLICT。
	other := "并发"
	if _, err := profiles.UpdateProfile(ctx, UpdateOwnProfileRequest{
		SessionSecret: session, Nickname: &other,
		ExpectedRowVersion: view.RowVersion, RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeConflict) {
		t.Fatalf("过期版本更新错误 = %v，期望 CONFLICT", err)
	}
	// 无白名单字段 → REQ_INVALID。
	if _, err := profiles.UpdateProfile(ctx, UpdateOwnProfileRequest{
		SessionSecret: session, ExpectedRowVersion: updated.RowVersion,
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("空资料更新错误 = %v，期望 REQ_INVALID", err)
	}
	// 无效会话 → AUTH_FAILED，不泄露身份。
	if _, err := profiles.GetProfile(ctx, OwnProfileRequest{
		SessionSecret: []byte("invalid-session"), RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeAuthFailed) {
		t.Fatalf("无效会话读取资料错误 = %v，期望 AUTH_FAILED", err)
	}
}

// TestProfileChangeUsername 覆盖受控更名成功、错误密码与冷却。
func TestProfileChangeUsername(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 5, 10, 0, 0, time.UTC))
	runtime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	const password = "K8$wR3!nB6@yF1#v"
	renamer := createLifecycleUser(t, ctx, runtime, "rename-public", password)
	grantSelfProfilePermissions(t, ctx, runtime, renamer.ID)
	session := loginLifecycleUser(t, ctx, runtime, "rename-public", password)
	profiles := runtime.Profile()
	view, err := profiles.GetProfile(ctx, OwnProfileRequest{
		SessionSecret: session, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("GetProfile: %v", err)
	}
	// 错误密码：真实再次认证失败，不改名。
	if _, err := profiles.ChangeUsername(ctx, ChangeOwnUsernameRequest{
		SessionSecret: session, NewUsername: "rename-denied", Password: "Wrong!Passw0rd",
		ExpectedRowVersion: view.RowVersion, RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("错误密码不应允许改名")
	}
	// 正确密码 + 期望版本：成功改名。
	renamed, err := profiles.ChangeUsername(ctx, ChangeOwnUsernameRequest{
		SessionSecret: session, NewUsername: "rename-success", Password: password,
		ExpectedRowVersion: view.RowVersion, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("ChangeUsername: %v", err)
	}
	if renamed.Username != "rename-success" || renamed.UsernameChangedAt == "" ||
		renamed.RowVersion <= view.RowVersion {
		t.Fatalf("改名结果异常: %+v", renamed)
	}
	// 冷却期再次改名 → RATE_LIMITED（真实领域冷却），不能绕过。
	if _, err := profiles.ChangeUsername(ctx, ChangeOwnUsernameRequest{
		SessionSecret: session, NewUsername: "rename-too-soon", Password: password,
		ExpectedRowVersion: renamed.RowVersion, RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeRateLimited) {
		t.Fatalf("冷却期改名错误 = %v，期望 RATE_LIMITED", err)
	}
}
