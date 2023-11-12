// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package app

// 步骤 224 测试 helper：真实 Runtime/SQLite、LocalAdmin 与真实管理会话。
// 本文件只新增 helper，不修改既有测试文件。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

// rbacTestEnv 是一次 RBAC 测试的真实装配。
type rbacTestEnv struct {
	runtime *Runtime
	clock   *testClock
	local   AdminCaller
	admin   AdminService
}

// newRBACTestEnv 打开真实临时运行时（迁移 + SQLite + 真实领域服务/审计）。
func newRBACTestEnv(t *testing.T) *rbacTestEnv {
	t.Helper()
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 6, 0, 0, 0, time.UTC))
	runtime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	return &rbacTestEnv{runtime: runtime, clock: clock, local: runtime.LocalAdmin(),
		admin: runtime.Admin()}
}

// createPermission 用 LocalAdmin 登记系统/应用权限并返回管理视图。
func (env *rbacTestEnv) createPermission(t *testing.T, scopeID, key, name string) AdminPermission {
	t.Helper()
	ctx := context.Background()
	created, err := env.admin.CreatePermission(ctx, AdminCreatePermissionRequest{
		Caller: env.local, ScopeID: scopeID, Key: key, Name: name,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建权限 %s 失败: %v", key, err)
	}
	return created
}

// createRole 用 LocalAdmin 登记角色并返回管理视图。
func (env *rbacTestEnv) createRole(t *testing.T, scopeID, key, name string) AdminRole {
	t.Helper()
	ctx := context.Background()
	created, err := env.admin.CreateRole(ctx, AdminCreateRoleRequest{
		Caller: env.local, ScopeID: scopeID, Key: key, Name: name,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建角色 %s 失败: %v", key, err)
	}
	return created
}

// addPermission 用 LocalAdmin 向角色组合权限。
func (env *rbacTestEnv) addPermission(t *testing.T, roleID, permissionID string) {
	t.Helper()
	ctx := context.Background()
	if err := env.admin.AddRolePermission(ctx, AdminRolePermissionRequest{
		Caller: env.local, RoleID: roleID, PermissionID: permissionID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("角色组合权限失败: %v", err)
	}
}

// grantRole 用 LocalAdmin 把角色分配给用户。
func (env *rbacTestEnv) grantRole(t *testing.T, userID, roleID string) {
	t.Helper()
	ctx := context.Background()
	if err := env.admin.GrantApplicationRole(ctx, GrantRoleRequest{
		Caller: env.local, UserID: userID, RoleID: roleID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("分配角色失败: %v", err)
	}
}

// createUser 创建真实注册用户。
func (env *rbacTestEnv) createUser(t *testing.T, username string) User {
	t.Helper()
	created, err := env.runtime.Users().Create(context.Background(), CreateUserRequest{
		Username: username, Password: "K8$wR3!nB6@yF1#v", Nickname: username,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建用户 %s 失败: %v", username, err)
	}
	return created
}

// systemAdminSession 创建一个拥有指定系统权限的真实管理会话（普通管理员路径）。
// 高权限权限键会触发强认证策略，因此统一绑定 TOTP 并完成第二因素，得到完整会话。
func (env *rbacTestEnv) systemAdminSession(t *testing.T, username string,
	permissionKeys ...string) AdminCaller {
	t.Helper()
	ctx := context.Background()
	const password = "K8$wR3!nB6@yF1#v"
	userID, _, totpSecret := setupUserWithTOTP(t, env.runtime, env.clock, username, password)
	role := env.createRole(t, "system", "rbac_admin_"+sanitizeKey(username), "RBAC 管理会话")
	for _, key := range permissionKeys {
		permission := env.createPermission(t, "system", key, key)
		env.addPermission(t, role.ID, permission.ID)
	}
	env.grantRole(t, userID, role.ID)
	secret := loginSessionWithTOTP(t, ctx, env.runtime, env.clock, username, password, totpSecret)
	return env.runtime.AdminSession(secret)
}

// sanitizeKey 把测试用户名转成合法角色机器标识片段。
func sanitizeKey(value string) string {
	var builder strings.Builder
	for _, character := range value {
		switch {
		case character >= 'a' && character <= 'z':
			builder.WriteRune(character)
		case character >= 'A' && character <= 'Z':
			builder.WriteRune(character + ('a' - 'A'))
		case character >= '0' && character <= '9':
			builder.WriteRune(character)
		default:
			builder.WriteByte('_')
		}
	}
	return builder.String()
}

// restrictedSession 返回一个未完成第二因素的受限会话秘密。
func (env *rbacTestEnv) restrictedSession(t *testing.T, username, password string) []byte {
	t.Helper()
	// 绑定 TOTP 后再登录即进入受限状态（等待第二因素）。
	_, _, totpSecret := setupUserWithTOTP(t, env.runtime, env.clock, username, password)
	env.clock.Advance(30 * time.Second)
	loginResult, err := env.runtime.Auth().Login(context.Background(), LoginRequest{
		Username: username, Password: password, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("受限会话登录失败: %v", err)
	}
	if !loginResult.Restricted || loginResult.SecondFactor == nil ||
		loginResult.SecondFactor.ChallengeID == "" {
		t.Fatalf("绑定 TOTP 后登录应为受限会话: %+v (totp=%t)",
			loginResult, totpSecret != "")
	}
	return loginResult.SessionSecret
}

// injectAuditFailure 让 audit_events 插入失败（关键操作审计故障）。
func (env *rbacTestEnv) injectAuditFailure(t *testing.T) {
	t.Helper()
	if _, err := env.runtime.base.Store.DB().Exec(
		`CREATE TRIGGER step224_fail_audit BEFORE INSERT ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit down'); END;`); err != nil {
		t.Fatalf("注入审计故障失败: %v", err)
	}
}

// clearAuditFailure 撤销注入（幂等，供 defer 清理与显式恢复共用）。
func (env *rbacTestEnv) clearAuditFailure(t *testing.T) {
	t.Helper()
	_, _ = env.runtime.base.Store.DB().Exec(`DROP TRIGGER step224_fail_audit`)
}

// asRBACAppError 断言错误为 *login.AppError 并返回。
func asRBACAppError(t *testing.T, err error) *login.AppError {
	t.Helper()
	appError, ok := err.(*login.AppError)
	if !ok {
		t.Fatalf("期望公开 AppError，实际 %T: %v", err, err)
	}
	return appError
}

// seedBuiltinPermission 直接写入一条内置权限（生产由预设初始化创建；本步公开
// 接口只读/启停/删除，不提供“创建内置权限”，测试需真实内置记录验证保护）。
func (env *rbacTestEnv) seedBuiltinPermission(t *testing.T, key string, rootOnly bool) string {
	t.Helper()
	digest := sha256.Sum256([]byte(key))
	permissionID := "perm_" + hex.EncodeToString(digest[:16])
	now := env.clock.Now().UTC().UnixMilli()
	rootOnlyValue := 0
	if rootOnly {
		rootOnlyValue = 1
	}
	if _, err := env.runtime.base.Store.DB().Exec(`INSERT INTO permissions(
id,scope_id,permission_key,name,description,limits_text,is_builtin,root_only,enabled,
created_at_ms,updated_at_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		permissionID, "system", key, "内置权限", "内置权限说明", "不能删除，只能按规则停用",
		1, rootOnlyValue, 1, now, now); err != nil {
		t.Fatalf("写入内置权限失败: %v", err)
	}
	return permissionID
}
