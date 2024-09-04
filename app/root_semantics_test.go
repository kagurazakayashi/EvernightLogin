package app

// 步骤 252（阶段2）公开 Go 门面的 root 全权限一致性定向测试：
//   - 全新运行时（未执行预设安装，permissions 表为空）真实 root 即可管理：Access.Check、
//     RBAC.Authorization.*、Admin.CheckPermission/EffectivePermissions 与
//     Sessions.Authorize 采用同一内核结论，来源显式标记 root。
//   - 未知权限 → PERMISSION_UNKNOWN；目录登记但未实现 → ACCESS_DENIED +
//     permission_not_implemented；DB 显式停用覆盖目录默认 → PERMISSION_DISABLED；
//     资源级 root 数据范围 all 但非法 ResourceID 仍 REQ_INVALID。
//   - root 在全新库可创建应用作用域权限（旧语义下 app 范围权限目录为空会形成
//     鸡生蛋，root 一律放行掩盖了该缺口）。
//   - root-only 权限属于 root 专属通道；非 root 仍按原语义拒绝。

import (
	"context"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// issueRootStrongSession 通过共享会话服务为真实 root 签发完整强认证会话；仅供测试
// 夹具使用（生产 root 管理会话由真实登录 + 第二步因素产生），不是生产旁路。
func issueRootStrongSession(t *testing.T, runtime *Runtime, rootUserID string,
	securityVersion int64) []byte {
	t.Helper()
	now := time.Now().UTC()
	issued, err := runtime.coreServices().Sessions.Login(context.Background(),
		session.LoginRequest{
			Result: authn.AuthenticateResult{UserID: rootUserID, Username: "root",
				Outcome:          authn.OutcomeComplete,
				CompletedMethods: []authn.Method{authn.MethodPassword, authn.MethodSecurityKey},
				CompletedAt:      now, StrongAuthCompletedAt: now,
				SecurityVersion: securityVersion},
			RequestID: login.NewRequestID(),
		})
	if err != nil {
		t.Fatalf("签发 root 强认证测试会话失败: %v", err)
	}
	secret := issued.Secret.Reveal()
	if secret == "" {
		t.Fatal("root 测试会话秘密为空")
	}
	return []byte(secret)
}

// openRootFacadeRuntime 打开全新运行时并创建 root，返回 root 用户与强认证测试会话。
func openRootFacadeRuntime(t *testing.T) (*Runtime, RootResult, []byte) {
	t.Helper()
	ctx := context.Background()
	runtime := openTestRuntime(t, Options{})
	root, err := runtime.Bootstrap().EnsureRoot(ctx, RootRequest{
		DisplayName: "Root", Password: "V7!qZ2#Lm9@Tp4$x",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("EnsureRoot: %v", err)
	}
	return runtime, root, issueRootStrongSession(t, runtime, root.UserID, root.SecurityVersion)
}

// accessAllowed 断言 Access.Check 决策为允许并回显请求编号。
func accessAllowed(t *testing.T, name string, decision AccessDecision, requestID string) {
	t.Helper()
	if !decision.Allowed {
		t.Fatalf("%s: root 应允许（拒绝码 %s/%s）", name, decision.Code, decision.Reason)
	}
	if decision.RequestID != requestID {
		t.Fatalf("%s: 请求编号 = %q，期望 %q", name, decision.RequestID, requestID)
	}
}

// TestRootFacadeConsistencyOnFreshRuntime 验证公开门面在新库上的 root 一致语义。
func TestRootFacadeConsistencyOnFreshRuntime(t *testing.T) {
	ctx := context.Background()
	runtime, root, rootSecret := openRootFacadeRuntime(t)
	rootAdmin := runtime.AdminSession(rootSecret)
	access := runtime.Access()

	// 1) 全新库（无 permissions 行）：root 拥有目录已实现权限，功能级/root-only 允许。
	const rootAccessRequestID = "req_252_root_users_read"
	decision, err := access.Check(ctx, AccessRequest{
		UserID: root.UserID, Permission: "users.read", RequestID: rootAccessRequestID})
	if err != nil {
		t.Fatalf("Access.Check(root, users.read): %v", err)
	}
	accessAllowed(t, "root users.read", decision, rootAccessRequestID)
	if decision.ResourceChecked || decision.ResourceID != "" {
		t.Fatalf("功能权限决策不应声称资源已校验: %+v", decision)
	}
	rootOnly, err := access.Check(ctx, AccessRequest{
		UserID: root.UserID, Permission: "security.policy.manage",
		RequestID: login.NewRequestID()})
	if err != nil || !rootOnly.Allowed {
		t.Fatalf("root 应可使用 root_only 权限: %+v err=%v", rootOnly, err)
	}

	// 2) 未知权限 → PERMISSION_UNKNOWN（不能因 root 身份一律 Allowed）。
	unknown, err := access.Check(ctx, AccessRequest{
		UserID: root.UserID, Permission: "never.registered.permission",
		RequestID: login.NewRequestID()})
	if err != nil || unknown.Allowed || unknown.Code != string(login.CodePermissionUnknown) {
		t.Fatalf("root 未知权限应 PERMISSION_UNKNOWN: %+v err=%v", unknown, err)
	}

	// 3) 目录登记但未实现 → ACCESS_DENIED + permission_not_implemented。
	presetCatalog, err := runtime.RBAC().Presets().Catalog(ctx, RBACCatalogRequest{
		Caller: rootAdmin, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("读取预设目录失败: %v", err)
	}
	unimplementedKey := ""
	for _, permission := range presetCatalog.Permissions {
		if !permission.Implemented {
			unimplementedKey = permission.Key
			break
		}
	}
	if unimplementedKey == "" {
		t.Log("预设目录当前无未实现权限，跳过未实现拒绝断言（由内核/适配层测试覆盖）")
	} else {
		notImplemented, err := access.Check(ctx, AccessRequest{
			UserID: root.UserID, Permission: unimplementedKey,
			RequestID: login.NewRequestID()})
		if err != nil || notImplemented.Allowed ||
			notImplemented.Code != string(login.CodeAccessDenied) ||
			notImplemented.Reason != "permission_not_implemented" {
			t.Fatalf("root 未实现权限应拒绝: %+v err=%v", notImplemented, err)
		}
	}

	// 4) 创建应用并使用 root 会话做业务授权：新库无需预设权限行/成员关系。
	createdApp, err := runtime.Admin().CreateApplication(ctx, AdminCreateApplicationRequest{
		Caller: runtime.LocalAdmin(), Name: "root 语义应用",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建应用失败: %v", err)
	}
	enabledApp, err := runtime.Admin().SetApplicationEnabled(ctx,
		AdminSetApplicationEnabledRequest{Caller: runtime.LocalAdmin(),
			ApplicationID: createdApp.ID, Enabled: true,
			ExpectedRowVersion: createdApp.RowVersion, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("启用应用失败: %v", err)
	}
	sessionDecision, err := runtime.Sessions().Authorize(ctx, SessionAccessRequest{
		SessionSecret: rootSecret, AppID: enabledApp.ID,
		Permissions: []string{"users.read"}, RequestID: login.NewRequestID()})
	if err != nil || !sessionDecision.Allowed ||
		sessionDecision.ResourceChecked {
		t.Fatalf("root 会话业务授权应允许: %+v err=%v", sessionDecision, err)
	}
	resourceSession, err := runtime.Sessions().Authorize(ctx, SessionAccessRequest{
		SessionSecret: rootSecret, AppID: enabledApp.ID,
		Permissions: []string{"users.read"}, ResourceID: "resource-1",
		RequestID: login.NewRequestID()})
	if err != nil || !resourceSession.Allowed || !resourceSession.ResourceChecked {
		t.Fatalf("root 会话资源级授权应允许: %+v err=%v", resourceSession, err)
	}

	// 5) 资源级 Access：数据范围 all；非法 ResourceID 仍 REQ_INVALID。
	resourceDecision, err := access.Check(ctx, AccessRequest{
		UserID: root.UserID, Permission: "users.read", ResourceID: "resource-1",
		RequestID: login.NewRequestID()})
	if err != nil || !resourceDecision.Allowed || !resourceDecision.ResourceChecked {
		t.Fatalf("root 资源级检查应允许: %+v err=%v", resourceDecision, err)
	}
	if _, err := access.Check(ctx, AccessRequest{
		UserID: root.UserID, Permission: "users.read", ResourceID: "bad\nresource",
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("root 非法 ResourceID 应 REQ_INVALID: %v", err)
	}

	// 6) RBAC 授权查询门面与 Access.Check 结论一致，来源标记 root。
	rbacCheck, err := runtime.RBAC().Authorization().Check(ctx, RBACCheckRequest{
		Caller: rootAdmin, SubjectUserID: root.UserID, ScopeID: "system",
		Permissions: []string{"users.read"}, RequestID: login.NewRequestID()})
	if err != nil || !rbacCheck.Allowed {
		t.Fatalf("RBAC.Check(root) 应允许: %+v err=%v", rbacCheck, err)
	}
	rbacResource, err := runtime.RBAC().Authorization().CheckResourceAccess(ctx,
		RBACResourceAccessRequest{Caller: rootAdmin, SubjectUserID: root.UserID,
			ScopeID: "system", PermissionKey: "users.read", ResourceID: "resource-1",
			RequestID: login.NewRequestID()})
	if err != nil || !rbacResource.Allowed || rbacResource.DataScopeMode != "all" {
		t.Fatalf("RBAC.CheckResourceAccess(root) 应允许且数据范围 all: %+v err=%v",
			rbacResource, err)
	}
	rbacEffective, err := runtime.RBAC().Authorization().EffectivePermissions(ctx,
		RBACEffectiveRequest{Caller: rootAdmin, SubjectUserID: root.UserID,
			ScopeID: "system", Page: AdminPage{Limit: 100}, RequestID: login.NewRequestID()})
	if err != nil || rbacEffective.DeniedCode != "" || len(rbacEffective.Permissions) == 0 {
		t.Fatalf("RBAC.EffectivePermissions(root) = %+v err=%v", rbacEffective, err)
	}
	foundUsersRead := false
	for _, permission := range rbacEffective.Permissions {
		if len(permission.Sources) != 1 || permission.Sources[0].Kind != "root" ||
			!permission.Sources[0].Included {
			t.Fatalf("root 有效权限来源应标记 root: %+v", permission.Sources)
		}
		if permission.Key == "users.read" {
			foundUsersRead = true
		}
	}
	if !foundUsersRead {
		t.Fatalf("root 有效权限应包含 users.read: %+v", rbacEffective.Permissions)
	}
	rootSources, err := runtime.RBAC().Authorization().PermissionSources(ctx,
		RBACPermissionSourcesRequest{Caller: rootAdmin, SubjectUserID: root.UserID,
			ScopeID: "system", PermissionKey: "users.read",
			RequestID: login.NewRequestID()})
	if err != nil || !rootSources.PermissionFound || len(rootSources.Sources) != 1 ||
		rootSources.Sources[0].Kind != "root" || !rootSources.Sources[0].Included {
		t.Fatalf("root 来源查询 = %+v err=%v", rootSources, err)
	}

	// 7) Admin 门面一致性：CheckPermission/EffectivePermissions。
	adminCheck, err := runtime.Admin().CheckPermission(ctx, AdminPermissionCheck{
		Caller: rootAdmin, UserID: root.UserID, ScopeID: "system",
		Permission: "users.read", RequestID: login.NewRequestID()})
	if err != nil || !adminCheck.Allowed {
		t.Fatalf("Admin.CheckPermission(root) 应允许: %+v err=%v", adminCheck, err)
	}
	adminEffective, err := runtime.Admin().EffectivePermissions(ctx, AdminPermissionQuery{
		Caller: rootAdmin, UserID: root.UserID, ScopeID: "system", Limit: 100,
		RequestID: login.NewRequestID()})
	if err != nil || adminEffective.DeniedCode != "" ||
		len(adminEffective.Permissions) == 0 {
		t.Fatalf("Admin.EffectivePermissions(root) = %+v err=%v", adminEffective, err)
	}

	// 8) 新库 root 可创建应用作用域权限（旧语义下会被 app 空范围目录拒绝）。
	createdPermission, err := runtime.Admin().CreatePermission(ctx,
		AdminCreatePermissionRequest{Caller: rootAdmin, ScopeID: enabledApp.ID,
			Key: "root.bootstrap.read", Name: "root 自举应用权限",
			RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("root 在新库创建应用作用域权限失败: %v", err)
	}
	appPermissionDecision, err := access.Check(ctx, AccessRequest{
		UserID: root.UserID, AppID: enabledApp.ID, Permission: createdPermission.Key,
		ResourceID: "resource-1", RequestID: login.NewRequestID()})
	if err != nil || !appPermissionDecision.Allowed ||
		!appPermissionDecision.ResourceChecked {
		t.Fatalf("root 应用作用域权限资源检查应允许: %+v err=%v",
			appPermissionDecision, err)
	}

	// 9) DB 显式停用覆盖目录默认：root 同样被拒绝（不能绕过权限关停）。
	if _, err := runtime.base.Store.DB().ExecContext(ctx, `INSERT INTO permissions(
id,scope_id,permission_key,name,description,limits_text,is_builtin,root_only,enabled,
created_at_ms,updated_at_ms) VALUES(?,?,?,?,?,?,1,0,0,?,?)`,
		"perm_252_disabled_users_read", "system", "users.read", "读取用户",
		"测试停用", "测试", time.Now().UnixMilli(), time.Now().UnixMilli()); err != nil {
		t.Fatalf("写入停用权限失败: %v", err)
	}
	disabled, err := access.Check(ctx, AccessRequest{
		UserID: root.UserID, Permission: "users.read", RequestID: login.NewRequestID()})
	if err != nil || disabled.Allowed ||
		disabled.Code != string(login.CodePermissionDisabled) {
		t.Fatalf("root 停用权限应 PERMISSION_DISABLED: %+v err=%v", disabled, err)
	}
	adminDisabled, err := runtime.Admin().CheckPermission(ctx, AdminPermissionCheck{
		Caller: rootAdmin, UserID: root.UserID, ScopeID: "system",
		Permission: "users.read", RequestID: login.NewRequestID()})
	if err != nil || adminDisabled.Allowed {
		t.Fatalf("Admin 门面 root 停用权限也应拒绝: %+v err=%v", adminDisabled, err)
	}

	// 10) 非 root 在同一新库不因 root 语义被放大：普通用户既有权限仍为空。
	ordinary, err := runtime.Users().Create(ctx, CreateUserRequest{
		Username: "root-scope-ordinary", Password: "K8$wR3!nB6@yF1#v",
		Nickname: "普通用户", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建普通用户失败: %v", err)
	}
	ordinaryDecision, err := access.Check(ctx, AccessRequest{
		UserID: ordinary.ID, Permission: "users.read", RequestID: login.NewRequestID()})
	if err != nil || ordinaryDecision.Allowed {
		t.Fatalf("普通用户不应获得 root 全权限: %+v err=%v", ordinaryDecision, err)
	}
}
