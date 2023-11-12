// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package app

// 步骤 224 P1：委派资格与预设恢复公开接口测试（含普通管理会话拒绝）。

import (
	"context"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/preset"
	presetsqlite "github.com/kagurazakayashi/EvernightLogin/internal/preset/sqlite"
)

// installSystemPresets 通过宿主受信通道初始化系统预设（生产装配由宿主完成；
// 本步公开接口只暴露 Catalog/Preview/Restore，不暴露 Install）。
func (env *rbacTestEnv) installSystemPresets(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	store, err := presetsqlite.New(env.runtime.base.Store)
	if err != nil {
		t.Fatalf("预设存储: %v", err)
	}
	service, err := preset.New(preset.Options{Store: store, Audit: env.runtime.base.Audit,
		Transfers: env.runtime.managedServices().Delegation, Now: env.clock.Now,
		Logger: env.runtime.logger})
	if err != nil {
		t.Fatalf("预设服务: %v", err)
	}
	caller, err := preset.LocalBootstrapCaller("host-operator")
	if err != nil {
		t.Fatalf("预设受信调用者: %v", err)
	}
	if _, err := service.Install(ctx, caller, preset.InstallRequest{ScopeID: "system"}); err != nil {
		t.Fatalf("初始化系统预设: %v", err)
	}
}

// TestRBACPresetCatalogImplementedFlags 验证目录中文说明与真实 Implemented 标记。
func TestRBACPresetCatalogImplementedFlags(t *testing.T) {
	env := newRBACTestEnv(t)
	ctx := context.Background()
	catalog, err := env.runtime.RBAC().Permissions().Catalog(ctx, RBACCatalogRequest{
		Caller: env.local, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	if catalog.Version == "" || len(catalog.Permissions) == 0 {
		t.Fatalf("目录为空: %+v", catalog)
	}
	implemented, unimplemented := 0, 0
	for _, item := range catalog.Permissions {
		if item.Key == "" || item.Name == "" || item.Scope == "" || item.Limits == "" {
			t.Fatalf("目录条目缺少直白中文说明: %+v", item)
		}
		if item.Implemented {
			implemented++
		} else {
			unimplemented++
		}
	}
	if implemented == 0 {
		t.Fatal("目录应至少有一个已实现权限")
	}
	// 不凭“枚举里有键”声称已实现：目录必须如实出现未实现项。
	if unimplemented == 0 {
		t.Fatal("预设目录应如实包含未实现权限（Implemented=false）")
	}
}

// TestRBACPresetAdminSessionDenied 验证普通管理会话不能预览/恢复高权限预设。
func TestRBACPresetAdminSessionDenied(t *testing.T) {
	env := newRBACTestEnv(t)
	ctx := context.Background()
	adminCaller := env.systemAdminSession(t, "rbac-preset-admin", "roles.read")
	presets := env.runtime.RBAC().Presets()

	_, err := presets.Preview(ctx, RBACPresetPreviewRequest{Caller: adminCaller,
		All: true, RequestID: login.NewRequestID()})
	if err == nil {
		t.Fatal("普通管理会话 Preview 必须拒绝")
	}
	if code := asRBACAppError(t, err).Code(); code != login.CodeAccessDenied {
		t.Fatalf("Preview 拒绝码 = %q，期望 ACCESS_DENIED", code)
	}
	_, err = presets.Restore(ctx, RBACPresetRestoreRequest{Caller: adminCaller,
		Token: "forged-token", RequestID: login.NewRequestID()})
	if err == nil {
		t.Fatal("普通管理会话 Restore 必须拒绝")
	}
	if code := asRBACAppError(t, err).Code(); code != login.CodeAccessDenied {
		t.Fatalf("Restore 拒绝码 = %q，期望 ACCESS_DENIED", code)
	}
}

// TestRBACPresetLocalAdminPreviewRestore 验证 LocalAdmin 预览→令牌→恢复链路与令牌单次性。
func TestRBACPresetLocalAdminPreviewRestore(t *testing.T) {
	env := newRBACTestEnv(t)
	ctx := context.Background()
	env.installSystemPresets(t)
	presets := env.runtime.RBAC().Presets()

	preview, err := presets.Preview(ctx, RBACPresetPreviewRequest{Caller: env.local,
		All: true, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("LocalAdmin Preview: %v", err)
	}
	if preview.Token == "" || preview.CatalogVersion == "" || preview.ExpiresAt.IsZero() {
		t.Fatalf("预览结果不完整: %+v", preview)
	}
	if !preview.ExpiresAt.After(preview.GeneratedAt) {
		t.Fatalf("预览令牌有效期异常: %+v", preview)
	}
	if _, err := presets.Restore(ctx, RBACPresetRestoreRequest{Caller: env.local,
		Token: preview.Token, RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("LocalAdmin Restore: %v", err)
	}
	// 令牌单次使用：复用/伪造必须拒绝。
	_, err = presets.Restore(ctx, RBACPresetRestoreRequest{Caller: env.local,
		Token: preview.Token, RequestID: login.NewRequestID()})
	if err == nil {
		t.Fatal("已使用的预览令牌必须拒绝")
	}
	_, err = presets.Restore(ctx, RBACPresetRestoreRequest{Caller: env.local,
		Token: "forged-token", RequestID: login.NewRequestID()})
	if err == nil {
		t.Fatal("伪造令牌必须拒绝")
	}
	// 过期令牌拒绝。
	env.clock.Advance(2 * time.Hour)
	expired, err := presets.Preview(ctx, RBACPresetPreviewRequest{Caller: env.local,
		All: true, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("第二次 Preview: %v", err)
	}
	env.clock.Advance(2 * time.Hour)
	if _, err := presets.Restore(ctx, RBACPresetRestoreRequest{Caller: env.local,
		Token: expired.Token, RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("过期预览令牌必须拒绝")
	}
}

// TestRBACDelegationLocalAdminAndUserRead 验证签发/读取/列表/撤回与普通用户只能读自己。
func TestRBACDelegationLocalAdminAndUserRead(t *testing.T) {
	env := newRBACTestEnv(t)
	ctx := context.Background()
	delegations := env.runtime.RBAC().Delegations()
	user := env.createUser(t, "rbac-delegate")
	permission := env.createPermission(t, "system", "rbac.delegated.read", "可转授读取")
	role := env.createRole(t, "system", "rbac-delegate", "被委派角色")
	env.addPermission(t, role.ID, permission.ID)
	env.grantRole(t, user.ID, role.ID)

	granted, err := delegations.Grant(ctx, AdminDelegationGrantRequest{Caller: env.local,
		DelegatorUserID: user.ID, ScopeID: "system",
		PermissionKey: "rbac.delegated.read", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	got, err := delegations.Get(ctx, RBACDelegationRequest{Caller: env.local,
		GrantID: granted.ID, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.PermissionKey != "rbac.delegated.read" || got.DelegatorUserID != user.ID {
		t.Fatalf("委派视图异常: %+v", got)
	}
	list, err := delegations.List(ctx, RBACDelegationListRequest{Caller: env.local,
		Page: AdminPage{Limit: 10}, RequestID: login.NewRequestID()})
	if err != nil || len(list.Grants) == 0 {
		t.Fatalf("List: %+v err=%v", list, err)
	}
	// 普通管理会话只读自己的资格与可转授权限。
	loginResult, err := env.runtime.Auth().Login(ctx, LoginRequest{
		Username: "rbac-delegate", Password: "K8$wR3!nB6@yF1#v",
		ClientIP: "127.0.0.1", RequestID: login.NewRequestID()})
	if err != nil || loginResult.Restricted {
		t.Fatalf("被委派用户登录: %+v err=%v", loginResult, err)
	}
	userCaller := env.runtime.AdminSession(loginResult.SessionSecret)
	own, err := delegations.List(ctx, RBACDelegationListRequest{Caller: userCaller,
		Page: AdminPage{Limit: 10}, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("普通用户 List: %v", err)
	}
	if len(own.Grants) != 1 || own.Grants[0].DelegatorUserID != user.ID {
		t.Fatalf("普通用户只能读取自己的资格: %+v", own)
	}
	delegatable, err := delegations.DelegatablePermissions(ctx, RBACDelegatableRequest{
		Caller: userCaller, ScopeID: "system", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("DelegatablePermissions: %v", err)
	}
	found := false
	for _, item := range delegatable {
		if item.Key == "rbac.delegated.read" {
			found = true
		}
	}
	if !found {
		t.Fatalf("可转授权限未包含已签发权限: %+v", delegatable)
	}

	if changed, err := delegations.Revoke(ctx, RBACDelegationRequest{Caller: env.local,
		GrantID: granted.ID, RequestID: login.NewRequestID()}); err != nil || !changed {
		t.Fatalf("Revoke: changed=%t err=%v", changed, err)
	}
	revoked, err := delegations.Get(ctx, RBACDelegationRequest{Caller: env.local,
		GrantID: granted.ID, RequestID: login.NewRequestID()})
	if err != nil || revoked.RevokedAt == nil {
		t.Fatalf("撤回后视图应含 RevokedAt: %+v err=%v", revoked, err)
	}
}

// TestRBACDelegationAdminSessionCannotGrant 验证普通管理会话不能签发委派资格。
func TestRBACDelegationAdminSessionCannotGrant(t *testing.T) {
	env := newRBACTestEnv(t)
	ctx := context.Background()
	adminCaller := env.systemAdminSession(t, "rbac-delegation-admin", "roles.read")
	_, err := env.runtime.RBAC().Delegations().Grant(ctx, AdminDelegationGrantRequest{
		Caller: adminCaller, DelegatorUserID: "usr_00000000000000000000000000000001",
		ScopeID: "system", PermissionKey: "roles.read",
		RequestID: login.NewRequestID()})
	if err == nil {
		t.Fatal("普通管理会话签发委派必须拒绝")
	}
	if code := asRBACAppError(t, err).Code(); code != login.CodeAccessDenied {
		t.Fatalf("签发拒绝码 = %q，期望 ACCESS_DENIED", code)
	}
}
