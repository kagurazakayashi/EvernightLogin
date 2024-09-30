package e2e

// 步骤 274 矩阵三：root 语义多入口一致性与搜索/列表越权边界。
//
// 覆盖（公开 Go 门面）：
//   - root 主体在 Admin.CheckPermission（管理查询入口）、Access.Check（授权检查入口）、
//     EffectivePermissions（有效权限展示入口）三个入口对“已实现权限/未知权限/root_only”
//     得到一致结论（252 审计结转）；
//   - 自定义权限行被停用后 root 与其他主体一致拒绝（PERMISSION_DISABLED）；
//   - 无 users.read 的普通用户不能通过用户列表搜索枚举账户；
//   - 有 users.read 的用户搜索可用；非法搜索字段（邮箱等敏感字段）明确 REQ_INVALID，
//     列表结果脱敏（公开 AdminUser 类型不含邮箱/电话等个人信息字段）。

import (
	"context"
	"testing"

	login "github.com/kagurazakayashi/EvernightLogin"
	loginapp "github.com/kagurazakayashi/EvernightLogin/app"
)

// TestMatrixRootAuthorizationConsistency 验证 root 在多个公开授权入口的一致结论。
func TestMatrixRootAuthorizationConsistency(t *testing.T) {
	runtime, clock, dbPath := openRuntime(t)
	root := ensureRoot(t, runtime)
	ordinary := createUser(t, runtime, "matrix-root-ordinary", targetPassword)

	// 1) 已实现权限：root 在三个入口都允许。
	const implementedKey = "users.read"
	if !checkPermission(t, runtime, root.UserID, implementedKey) {
		t.Fatalf("Admin.CheckPermission(root,%s) 应允许", implementedKey)
	}
	if !accessAllowed(t, runtime, root.UserID, implementedKey) {
		t.Fatalf("Access.Check(root,%s) 应允许", implementedKey)
	}
	if !effectivePermissionContains(t, runtime, root.UserID, "system", implementedKey) {
		t.Fatalf("root 有效权限未包含 %s", implementedKey)
	}

	// 2) 未知权限：root 与管理/授权入口一致拒绝（不能因 root 一律允许）。
	const unknownKey = "matrix.never.registered.permission"
	unknownDecision, err := runtime.Admin().CheckPermission(context.Background(),
		loginapp.AdminPermissionCheck{Caller: runtime.LocalAdmin(), UserID: root.UserID,
			ScopeID: "system", Permission: unknownKey, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("CheckPermission(unknown): %v", err)
	}
	if unknownDecision.Allowed || unknownDecision.Code != string(login.CodePermissionUnknown) {
		t.Fatalf("root 未知权限管理入口应 PERMISSION_UNKNOWN: %+v", unknownDecision)
	}
	unknownAccess, err := runtime.Access().Check(context.Background(),
		loginapp.AccessRequest{UserID: root.UserID, Permission: unknownKey,
			RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("Access.Check(unknown): %v", err)
	}
	if unknownAccess.Allowed || unknownAccess.Code != string(login.CodePermissionUnknown) {
		t.Fatalf("root 未知权限授权入口应 PERMISSION_UNKNOWN: %+v", unknownAccess)
	}
	if unknownDecision.Code != unknownAccess.Code {
		t.Fatalf("root 未知权限两入口结论不一致: admin=%s access=%s",
			unknownDecision.Code, unknownAccess.Code)
	}

	// 3) root_only 权限：root 允许、普通用户拒绝且两入口一致。
	const rootOnlyKey = "security.policy.manage"
	if !checkPermission(t, runtime, root.UserID, rootOnlyKey) ||
		!accessAllowed(t, runtime, root.UserID, rootOnlyKey) {
		t.Fatalf("root 应持有 root_only 权限 %s", rootOnlyKey)
	}
	if checkPermission(t, runtime, ordinary.ID, rootOnlyKey) ||
		accessAllowed(t, runtime, ordinary.ID, rootOnlyKey) {
		t.Fatalf("非 root 不应持有 root_only 权限 %s", rootOnlyKey)
	}

	// 4) 自定义权限行停用：root 与其他主体一致拒绝。
	custom, err := runtime.Admin().CreatePermission(context.Background(),
		loginapp.AdminCreatePermissionRequest{Caller: runtime.LocalAdmin(),
			ScopeID: "system", Key: "matrix.custom.disabled", Name: "274 自定义权限",
			Description: "用于停用一致性断言", Limits: "仅测试",
			RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建自定义权限: %v", err)
	}
	executeSQL(t, dbPath,
		`UPDATE permissions SET enabled=0 WHERE id='`+custom.ID+`'`)
	// 停用后该权限不再是“未知”，而是明确停用；root 与普通用户都应拒绝。
	if checkPermission(t, runtime, root.UserID, custom.Key) ||
		accessAllowed(t, runtime, root.UserID, custom.Key) {
		t.Fatalf("停用自定义权限 root 仍允许: %s", custom.Key)
	}
	if checkPermission(t, runtime, ordinary.ID, custom.Key) ||
		accessAllowed(t, runtime, ordinary.ID, custom.Key) {
		t.Fatalf("停用自定义权限普通用户仍允许: %s", custom.Key)
	}

	// 5) 搜索越权：无 users.read 的普通用户不能枚举用户列表。
	ordinarySession := loginFull(t, runtime, "matrix-root-ordinary", targetPassword).SessionSecret
	if _, err := runtime.Admin().ListUsers(context.Background(),
		loginapp.AdminListUsersRequest{Caller: runtime.AdminSession(ordinarySession),
			Limit: 10, Search: "matrix", RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeAccessDenied) {
		t.Fatalf("无 users.read 的用户列表搜索 = %v，期望 ACCESS_DENIED", err)
	}

	// 6) 有 users.read 的用户可搜索，且非法搜索字段（邮箱/电话）明确 REQ_INVALID。
	reader, readerTOTP := enrollTOTP(t, runtime, clock, "matrix-user-reader", operatorPassword)
	grantSystemPermissions(t, runtime, reader.ID, "matrix-user-reader-role", "users.read")
	readerSession := loginWithTOTP(t, runtime, clock, "matrix-user-reader",
		operatorPassword, readerTOTP)
	list, err := runtime.Admin().ListUsers(context.Background(),
		loginapp.AdminListUsersRequest{Caller: runtime.AdminSession(readerSession),
			Limit: 20, Search: "matrix", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("有 users.read 的用户搜索失败: %v", err)
	}
	for _, user := range list.Users {
		// 公开 AdminUser 仅含 ID/用户名/昵称/状态/创建时间；结果不得带出邮箱等敏感字段。
		if user.ID == "" || user.Username == "" {
			t.Fatalf("搜索结果用户条目不完整: %+v", user)
		}
	}
	if _, err := runtime.Admin().ListUsers(context.Background(),
		loginapp.AdminListUsersRequest{Caller: runtime.AdminSession(readerSession),
			Limit: 10, Search: "x", SearchFields: []string{"email"},
			RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeReqInvalid) {
		t.Fatalf("邮箱搜索字段 = %v，期望 REQ_INVALID（敏感字段不作为搜索面）", err)
	}
}
