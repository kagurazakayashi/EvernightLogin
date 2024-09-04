package authz_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	authzsqlite "github.com/kagurazakayashi/EvernightLogin/internal/authz/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const (
	testActiveUser   = "usr_00000000000000000000000000000001"
	testOtherUser    = "usr_00000000000000000000000000000002"
	testBothUser     = "usr_00000000000000000000000000000003"
	testDisabledUser = "usr_00000000000000000000000000000004"
	testPendingUser  = "usr_00000000000000000000000000000005"
	testRootUser     = "usr_00000000000000000000000000000006"
	testUnrelated    = "usr_00000000000000000000000000000007"

	testAppOne      = "app_00000000000000000000000000000001"
	testAppTwo      = "app_00000000000000000000000000000002"
	testAppDisabled = "app_00000000000000000000000000000003"

	testPermissionApprove  = "perm_00000000000000000000000000000001"
	testPermissionRead     = "perm_00000000000000000000000000000002"
	testPermissionBApprove = "perm_00000000000000000000000000000003"
	testPermissionExport   = "perm_00000000000000000000000000000004"
	testPermissionSystem   = "perm_00000000000000000000000000000005"
	testPermissionRootOnly = "perm_00000000000000000000000000000006"

	testGroupAppOne = "grp_00000000000000000000000000000001"
	testGroupSystem = "grp_00000000000000000000000000000002"

	testLocalAdmin = "operator-1"
	testSystemID   = "system-1"
)

type testEnv struct {
	t          *testing.T
	raw        *storagesqlite.Store
	service    *authz.Service
	authorizer *authz.StaticAuthorizer
	catalog    *fakePermissionCatalog
	system     authz.Caller
	local      authz.Caller
}

// prepareEnv 创建临时数据库并插入授权计算所需的账户/应用/成员/权限/组/角色数据。
func prepareEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(filepath.Join(testutil.TempDir(t), "authz.sqlite")))
	if err != nil {
		t.Fatalf("打开临时数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	migrationSet, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移失败: %v", err)
	}
	if _, err := raw.Migrate(ctx, migrationSet); err != nil {
		t.Fatalf("执行迁移失败: %v", err)
	}
	store, err := authzsqlite.New(raw)
	if err != nil {
		t.Fatalf("构造授权存储失败: %v", err)
	}
	authorizer, err := authz.NewStaticAuthorizer(authz.AuthorizerOptions{
		LocalAdminIDs:     []string{testLocalAdmin},
		SystemIDs:         []string{testSystemID},
		ApplicationAdmins: map[string][]string{testAppOne: {testActiveUser}},
	})
	if err != nil {
		t.Fatalf("构造查询授权器失败: %v", err)
	}
	// 测试目录：只登记两条系统内置权限按已实现处理；invoices.* 是宿主自定义权限
	//（目录未登记 → 按已实现）。测试可按需改写单项来验证“未实现/新增已实现权限自动
	// 包含”的 root 语义（目录只影响 root，不改变普通用户判定）。
	catalog := newFakePermissionCatalog(map[string]bool{
		"users.read":             true,
		"security.policy.manage": true,
	})
	service, err := authz.New(authz.Options{
		Store: store, Authorizer: authorizer, Catalog: catalog,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("构造授权引擎失败: %v", err)
	}
	system, err := authz.SystemCaller(testSystemID)
	if err != nil {
		t.Fatalf("构造系统调用者失败: %v", err)
	}
	local, err := authz.LocalBootstrapCaller(testLocalAdmin)
	if err != nil {
		t.Fatalf("构造本地调用者失败: %v", err)
	}
	env := &testEnv{t: t, raw: raw, service: service, authorizer: authorizer,
		catalog: catalog, system: system, local: local}
	env.insertFixtures()
	return env
}

// insertFixtures 直接插入合成账户、应用、成员、权限与用户组。
func (e *testEnv) insertFixtures() {
	e.t.Helper()
	now := int64(1_700_000_000_000)
	insertUser := func(userID, username, status string, isRoot int) {
		if _, err := e.raw.ExecContext(context.Background(),
			`INSERT INTO users(id,username,username_normalized,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,1,1,?,?)`, userID, username, username, status, isRoot, now, now); err != nil {
			e.t.Fatalf("插入测试用户失败: %v", err)
		}
	}
	insertUser(testActiveUser, "activeuser", "active", 0)
	insertUser(testOtherUser, "otheruser", "active", 0)
	insertUser(testBothUser, "bothuser", "active", 0)
	insertUser(testDisabledUser, "disableduser", "disabled", 0)
	insertUser(testPendingUser, "pendinguser", "pending_delete", 0)
	insertUser(testRootUser, "rootuser", "active", 1)
	insertUser(testUnrelated, "unrelated", "active", 0)

	insertApplication := func(applicationID, name, status string) {
		if _, err := e.raw.ExecContext(context.Background(),
			`INSERT INTO applications(id,name,description,status,client_type,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,'',?,'confidential',1,?,?)`, applicationID, name, status, now, now); err != nil {
			e.t.Fatalf("插入测试应用失败: %v", err)
		}
		if _, err := e.raw.ExecContext(context.Background(),
			`INSERT INTO scopes(id,kind,app_id) VALUES(?,'application',?)`, applicationID, applicationID); err != nil {
			e.t.Fatalf("插入测试作用范围失败: %v", err)
		}
	}
	insertApplication(testAppOne, "应用一", "active")
	insertApplication(testAppTwo, "应用二", "active")
	insertApplication(testAppDisabled, "停用应用", "disabled")

	insertMembership := func(applicationID, userID, status string) {
		if _, err := e.raw.ExecContext(context.Background(),
			`INSERT INTO app_memberships(app_id,user_id,status,profile_json,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'{"v":1}',1,?,?)`, applicationID, userID, status, now, now); err != nil {
			e.t.Fatalf("插入测试成员关系失败: %v", err)
		}
	}
	insertMembership(testAppOne, testActiveUser, "active")
	insertMembership(testAppOne, testDisabledUser, "active")
	insertMembership(testAppTwo, testOtherUser, "active")
	insertMembership(testAppOne, testBothUser, "active")
	insertMembership(testAppTwo, testBothUser, "active")

	insertPermission := func(permissionID, scopeID, key, name string, enabled, rootOnly bool) {
		if _, err := e.raw.ExecContext(context.Background(),
			`INSERT INTO permissions(id,scope_id,permission_key,name,description,limits_text,is_builtin,root_only,enabled,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,'','',0,?,?,?,?)`, permissionID, scopeID, key, name, boolInt(rootOnly), boolInt(enabled), now, now); err != nil {
			e.t.Fatalf("插入测试权限失败: %v", err)
		}
	}
	insertPermission(testPermissionApprove, testAppOne, "invoices.approve", "应用一审批", true, false)
	insertPermission(testPermissionRead, testAppOne, "invoices.read", "应用一查看", true, false)
	insertPermission(testPermissionBApprove, testAppTwo, "invoices.approve", "应用二审批", true, false)
	insertPermission(testPermissionExport, testAppOne, "invoices.export", "应用一导出", false, false)
	insertPermission(testPermissionSystem, "system", "users.read", "查看用户", true, false)
	insertPermission(testPermissionRootOnly, "system", "security.policy.manage", "修改敏感策略", true, true)

	insertGroup := func(groupID, scopeID, groupKey, name string) {
		if _, err := e.raw.ExecContext(context.Background(),
			`INSERT INTO user_groups(id,scope_id,group_key,name,description,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,'',?,?)`, groupID, scopeID, groupKey, name, now, now); err != nil {
			e.t.Fatalf("插入测试用户组失败: %v", err)
		}
	}
	insertGroup(testGroupAppOne, testAppOne, "finance.review", "应用一财务组")
	insertGroup(testGroupSystem, "system", "system.ops", "系统运维组")
}

// boolInt 把布尔值转为 SQLite 0/1。
func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

// insertRole 插入角色。
func (e *testEnv) insertRole(roleID, scopeID, key string, enabled bool) {
	e.t.Helper()
	now := int64(1_700_000_000_000)
	if _, err := e.raw.ExecContext(context.Background(),
		`INSERT INTO roles(id,scope_id,role_key,name,description,limits_text,is_builtin,enabled,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,'','',0,?,?,?)`, roleID, scopeID, key, key, boolInt(enabled), now, now); err != nil {
		e.t.Fatalf("插入测试角色失败: %v", err)
	}
}

// addRolePermission 组合角色权限。
func (e *testEnv) addRolePermission(roleID, permissionID, scopeID string) {
	e.t.Helper()
	if _, err := e.raw.ExecContext(context.Background(),
		`INSERT INTO role_permissions(role_id,permission_id,scope_id) VALUES(?,?,?)`,
		roleID, permissionID, scopeID); err != nil {
		e.t.Fatalf("组合角色权限失败: %v", err)
	}
}

// assignUserRole 分配用户角色并设置数据范围。
func (e *testEnv) assignUserRole(userID, roleID, scopeID, dataScopeJSON string) {
	e.t.Helper()
	now := int64(1_700_000_000_000)
	if _, err := e.raw.ExecContext(context.Background(),
		`INSERT INTO user_roles(user_id,role_id,scope_id,data_scope_json,assigned_by,created_at_ms)
VALUES(?,?,?,?,?,?)`, userID, roleID, scopeID, dataScopeJSON, testSystemID, now); err != nil {
		e.t.Fatalf("分配用户角色失败: %v", err)
	}
}

// assignGroupRole 分配用户组角色。
func (e *testEnv) assignGroupRole(groupID, roleID, scopeID, dataScopeJSON string) {
	e.t.Helper()
	now := int64(1_700_000_000_000)
	if _, err := e.raw.ExecContext(context.Background(),
		`INSERT INTO group_roles(group_id,role_id,scope_id,data_scope_json,created_at_ms)
VALUES(?,?,?,?,?)`, groupID, roleID, scopeID, dataScopeJSON, now); err != nil {
		e.t.Fatalf("分配用户组角色失败: %v", err)
	}
}

// addGroupMember 把用户加入组。
func (e *testEnv) addGroupMember(groupID, userID string) {
	e.t.Helper()
	if _, err := e.raw.ExecContext(context.Background(),
		`INSERT INTO group_members(group_id,user_id,created_at_ms) VALUES(?,?,?)`,
		groupID, userID, int64(1_700_000_000_000)); err != nil {
		e.t.Fatalf("加入用户组成员失败: %v", err)
	}
}

// userCaller 构造用户调用者。
func (e *testEnv) userCaller(userID string) authz.Caller {
	e.t.Helper()
	caller, err := authz.UserCaller(userID)
	if err != nil {
		e.t.Fatalf("构造用户调用者失败: %v", err)
	}
	return caller
}

// checkSelf 用系统调用者检查指定账户在指定 scope 的权限。
func (e *testEnv) check(subject, scopeID string, permissions []string, mode authz.Mode) authz.CheckResult {
	e.t.Helper()
	result, err := e.service.Check(context.Background(), e.system, authz.CheckRequest{
		SubjectUserID: subject, ScopeID: scopeID, Permissions: permissions, Mode: mode,
	})
	if err != nil {
		e.t.Fatalf("权限检查失败: %v", err)
	}
	return result
}

// effective 查询有效权限。
func (e *testEnv) effective(subject, scopeID string, options authz.ListOptions) authz.EffectiveResult {
	e.t.Helper()
	result, err := e.service.EffectivePermissions(context.Background(), e.system, subject, scopeID, options)
	if err != nil {
		e.t.Fatalf("有效权限查询失败: %v", err)
	}
	return result
}

// TestDirectAndGroupRoleMerge 验证直接用户角色、用户组角色合并、来源说明与 all/any。
func TestDirectAndGroupRoleMerge(t *testing.T) {
	env := prepareEnv(t)
	// 直接角色：审批权限，数据范围 all。
	env.insertRole("role_00000000000000000000000000000001", testAppOne, "direct.approver", true)
	env.addRolePermission("role_00000000000000000000000000000001", testPermissionApprove, testAppOne)
	env.assignUserRole(testActiveUser, "role_00000000000000000000000000000001", testAppOne, `{"v":1,"mode":"all"}`)
	// 组成员角色：审批 + 查看，数据范围 resources。
	env.insertRole("role_00000000000000000000000000000002", testAppOne, "group.reviewer", true)
	env.addRolePermission("role_00000000000000000000000000000002", testPermissionApprove, testAppOne)
	env.addRolePermission("role_00000000000000000000000000000002", testPermissionRead, testAppOne)
	env.assignGroupRole(testGroupAppOne, "role_00000000000000000000000000000002", testAppOne,
		`{"v":1,"mode":"resources","resources":["inv-b","inv-a"]}`)
	env.addGroupMember(testGroupAppOne, testActiveUser)

	effective := env.effective(testActiveUser, testAppOne, authz.ListOptions{})
	if effective.DeniedCode != "" {
		t.Fatalf("有效权限被拒绝: %+v", effective)
	}
	if len(effective.Permissions) != 2 {
		t.Fatalf("有效权限数量 = %d: %+v", len(effective.Permissions), effective.Permissions)
	}
	byKey := make(map[string]authz.EffectivePermission, len(effective.Permissions))
	for _, permission := range effective.Permissions {
		byKey[permission.Key] = permission
	}
	approve, ok := byKey["invoices.approve"]
	if !ok || len(approve.Sources) != 2 {
		t.Fatalf("审批权限来源 = %+v", approve)
	}
	// 数据范围：all ∩ resources = resources（排序去重）。
	if approve.DataScope.Mode != authz.DataScopeResources || len(approve.DataScope.Resources) != 2 ||
		approve.DataScope.Resources[0] != "inv-a" || approve.DataScope.Resources[1] != "inv-b" {
		t.Fatalf("审批数据范围 = %+v", approve.DataScope)
	}
	read, ok := byKey["invoices.read"]
	if !ok || len(read.Sources) != 1 || read.Sources[0].Kind != authz.SourceKindGroupRole {
		t.Fatalf("查看权限来源 = %+v", read)
	}

	// all：全部满足。
	result := env.check(testActiveUser, testAppOne, []string{"invoices.approve", "invoices.read"}, authz.ModeAll)
	if !result.Allowed {
		t.Fatalf("all 检查应允许: %+v", result)
	}
	// any：至少一个满足。
	if result := env.check(testActiveUser, testAppOne, []string{"invoices.approve", "invoices.export"}, authz.ModeAny); !result.Allowed {
		t.Fatalf("any 检查应允许（审批存在；导出停用不参与）: %+v", result)
	}
	// any 中出现未知权限按硬拒绝。
	if result := env.check(testActiveUser, testAppOne, []string{"invoices.approve", "unknown.permission"}, authz.ModeAny); result.Allowed || result.Code != authz.CodePermissionUnknown {
		t.Fatalf("any 未知权限应拒绝: %+v", result)
	}
	// all 中缺少已登记但未分配的权限。
	if result := env.check(testActiveUser, testAppOne, []string{"invoices.approve", "invoices.export"}, authz.ModeAll); result.Allowed || result.Code != authz.CodePermissionDisabled {
		t.Fatalf("all 停用权限应拒绝: %+v", result)
	}
	// 同 scope 下存在但未分配的权限。
	env.insertRole("role_00000000000000000000000000000003", testAppOne, "other.role", true)
	if result := env.check(testActiveUser, testAppOne, []string{"users.read"}, authz.ModeAll); result.Allowed || result.Code != authz.CodePermissionUnknown {
		// users.read 属于 system scope；在应用 scope 查询即未知权限。
		t.Fatalf("跨 scope 权限查询应未知: %+v", result)
	}

	// 来源查询：直接/组来源、包含数据范围与角色信息。
	sources, err := env.service.PermissionSources(context.Background(), env.system, testActiveUser, testAppOne, "invoices.approve", authz.ListOptions{})
	if err != nil {
		t.Fatalf("来源查询失败: %v", err)
	}
	if !sources.PermissionFound || len(sources.Sources) != 2 {
		t.Fatalf("来源 = %+v", sources)
	}
	for _, source := range sources.Sources {
		if !source.Included || source.RoleID == "" || source.DataScope.Mode == "" {
			t.Fatalf("来源说明不完整: %+v", source)
		}
		if source.Kind == authz.SourceKindGroupRole && source.GroupID != testGroupAppOne {
			t.Fatalf("组来源缺少组信息: %+v", source)
		}
	}
}

// TestDisabledPriority 验证账户、应用、成员、角色、权限与 root 的禁用优先语义。
func TestDisabledPriority(t *testing.T) {
	env := prepareEnv(t)
	roleID := "role_00000000000000000000000000000011"
	env.insertRole(roleID, testAppOne, "appone.role", true)
	env.addRolePermission(roleID, testPermissionApprove, testAppOne)
	env.assignUserRole(testActiveUser, roleID, testAppOne, `{"v":1,"mode":"all"}`)

	// 账户停用/待删除优先于应用与权限。
	for _, subject := range []string{testDisabledUser, testPendingUser} {
		result := env.check(subject, testAppOne, []string{"invoices.approve"}, authz.ModeAll)
		if result.Allowed || result.Code != authz.CodeUserDisabled {
			t.Fatalf("账户 %s 应 USER_DISABLED: %+v", subject, result)
		}
		effective := env.effective(subject, testAppOne, authz.ListOptions{})
		if effective.DeniedCode != authz.CodeUserDisabled || len(effective.Permissions) != 0 {
			t.Fatalf("账户 %s 有效权限 = %+v", subject, effective)
		}
	}
	// 停用应用优先于成员/权限。
	disabledAppRole := "role_00000000000000000000000000000012"
	env.insertRole(disabledAppRole, testAppDisabled, "disabled.role", true)
	result := env.check(testActiveUser, testAppDisabled, []string{"invoices.approve"}, authz.ModeAll)
	if result.Allowed || result.Code != authz.CodeClientDisabled {
		t.Fatalf("停用应用应 CLIENT_DISABLED: %+v", result)
	}
	// 未加入成员 → APP_MEMBERSHIP_REQUIRED。
	result = env.check(testUnrelated, testAppOne, []string{"invoices.approve"}, authz.ModeAll)
	if result.Allowed || result.Code != authz.CodeAppMembershipRequired {
		t.Fatalf("非成员应 APP_MEMBERSHIP_REQUIRED: %+v", result)
	}
	// 成员关系停用。
	if _, err := env.raw.ExecContext(context.Background(),
		`UPDATE app_memberships SET status='disabled' WHERE app_id=? AND user_id=?`,
		testAppOne, testBothUser); err != nil {
		t.Fatalf("停用成员关系失败: %v", err)
	}
	result = env.check(testBothUser, testAppOne, []string{"invoices.approve"}, authz.ModeAll)
	if result.Allowed || result.Code != authz.CodeAppMembershipRequired {
		t.Fatalf("停用成员应 APP_MEMBERSHIP_REQUIRED: %+v", result)
	}
	// 角色停用：权限不再生效，来源说明 role_disabled。
	if _, err := env.raw.ExecContext(context.Background(),
		`UPDATE roles SET enabled=0 WHERE id=?`, roleID); err != nil {
		t.Fatalf("停用角色失败: %v", err)
	}
	result = env.check(testActiveUser, testAppOne, []string{"invoices.approve"}, authz.ModeAll)
	if result.Allowed || result.Code != authz.CodePermissionRequired {
		t.Fatalf("停用角色后应 PERMISSION_REQUIRED: %+v", result)
	}
	sources, err := env.service.PermissionSources(context.Background(), env.system, testActiveUser, testAppOne, "invoices.approve", authz.ListOptions{})
	if err != nil {
		t.Fatalf("来源查询失败: %v", err)
	}
	if len(sources.Sources) != 1 || sources.Sources[0].Included || sources.Sources[0].ExcludedReason != "role_disabled" {
		t.Fatalf("停用角色来源 = %+v", sources.Sources)
	}
	if _, err := env.raw.ExecContext(context.Background(),
		`UPDATE roles SET enabled=1 WHERE id=?`, roleID); err != nil {
		t.Fatalf("恢复角色失败: %v", err)
	}

	// 权限停用：即使有角色组合也拒绝 PERMISSION_DISABLED。
	if result := env.check(testActiveUser, testAppOne, []string{"invoices.export"}, authz.ModeAll); result.Allowed || result.Code != authz.CodePermissionDisabled {
		t.Fatalf("停用权限应 PERMISSION_DISABLED: %+v", result)
	}
	// root_only 权限不能通过普通引擎获得。
	if result := env.check(testActiveUser, "system", []string{"security.policy.manage"}, authz.ModeAll); result.Allowed || result.Code != authz.CodeAccessDenied {
		t.Fatalf("root_only 权限应 ACCESS_DENIED: %+v", result)
	}
	// root 账户按“全权限受保护主体”语义：应用范围不要求成员关系，拥有全部已启用
	// 且已实现的权限，来源标记为 root。
	rootResult := env.check(testRootUser, testAppOne, []string{"invoices.approve"}, authz.ModeAll)
	if !rootResult.Allowed || len(rootResult.Permissions) != 1 ||
		rootResult.Permissions[0].DataScope.Mode != authz.DataScopeAll {
		t.Fatalf("root 账户应允许已实现权限: %+v", rootResult)
	}
	if len(rootResult.Permissions[0].Sources) != 1 ||
		rootResult.Permissions[0].Sources[0].Kind != authz.SourceKindRoot {
		t.Fatalf("root 权限来源应标记 root: %+v", rootResult.Permissions[0].Sources)
	}
	rootEffective := env.effective(testRootUser, testAppOne, authz.ListOptions{})
	// 应用范围 = 该范围数据库已启用权限（invoices.approve、invoices.read）∪ 只读
	// 目录已实现的内置权限（users.read、security.policy.manage，root 在任意有效
	// scope 生效）。
	if rootEffective.DeniedCode != "" || len(rootEffective.Permissions) != 4 {
		keys := make([]string, 0, len(rootEffective.Permissions))
		for _, permission := range rootEffective.Permissions {
			keys = append(keys, permission.Key)
		}
		t.Fatalf("root 有效权限 = %+v keys=%v", rootEffective, keys)
	}
	for _, permission := range rootEffective.Permissions {
		if len(permission.Sources) != 1 || permission.Sources[0].Kind != authz.SourceKindRoot ||
			permission.DataScope.Mode != authz.DataScopeAll {
			t.Fatalf("root 有效权限条目 = %+v", permission)
		}
	}
	rootSources, err := env.service.PermissionSources(context.Background(), env.system,
		testRootUser, testAppOne, "invoices.approve", authz.ListOptions{})
	if err != nil || !rootSources.PermissionFound || len(rootSources.Sources) != 1 ||
		rootSources.Sources[0].Kind != authz.SourceKindRoot || !rootSources.Sources[0].Included {
		t.Fatalf("root 来源查询 = %+v err=%v", rootSources, err)
	}
}

// TestSameNameCrossApplicationIsolation 验证同名权限跨应用隔离。
func TestSameNameCrossApplicationIsolation(t *testing.T) {
	env := prepareEnv(t)
	roleAppOne := "role_00000000000000000000000000000021"
	roleAppTwo := "role_00000000000000000000000000000022"
	env.insertRole(roleAppOne, testAppOne, "appone.approver", true)
	env.addRolePermission(roleAppOne, testPermissionApprove, testAppOne)
	env.assignUserRole(testBothUser, roleAppOne, testAppOne, `{"v":1,"mode":"all"}`)
	env.insertRole(roleAppTwo, testAppTwo, "apptwo.approver", true)
	env.addRolePermission(roleAppTwo, testPermissionBApprove, testAppTwo)
	env.assignUserRole(testBothUser, roleAppTwo, testAppTwo, `{"v":1,"mode":"all"}`)

	appOne := env.effective(testBothUser, testAppOne, authz.ListOptions{})
	if len(appOne.Permissions) != 1 || appOne.Permissions[0].Name != "应用一审批" {
		t.Fatalf("应用一有效权限 = %+v", appOne)
	}
	appTwo := env.effective(testBothUser, testAppTwo, authz.ListOptions{})
	if len(appTwo.Permissions) != 1 || appTwo.Permissions[0].Name != "应用二审批" {
		t.Fatalf("应用二有效权限 = %+v", appTwo)
	}
	// 应用二角色不会让用户获得应用一的同名权限（权限 ID 不同、scope 不同）。
	appOneOther := env.effective(testOtherUser, testAppOne, authz.ListOptions{})
	if len(appOneOther.Permissions) != 0 {
		t.Fatalf("应用二成员不应获得应用一权限: %+v", appOneOther)
	}
}

// TestDataScopeIntersectionAndResourceCheck 验证多来源数据范围交集与显式资源检查。
func TestDataScopeIntersectionAndResourceCheck(t *testing.T) {
	env := prepareEnv(t)
	// 三个角色都授予同一权限，数据范围分别为 all / [a,b] / [b,c]，交集为 [b]。
	dataScopes := []string{
		`{"v":1,"mode":"all"}`,
		`{"v":1,"mode":"resources","resources":["a","b"]}`,
		`{"v":1,"mode":"resources","resources":["b","c"]}`,
	}
	for index, dataScope := range dataScopes {
		roleID := "role_0000000000000000000000000000003" + string(rune('1'+index))
		env.insertRole(roleID, testAppOne, "scope.role"+string(rune('1'+index)), true)
		env.addRolePermission(roleID, testPermissionApprove, testAppOne)
		env.assignUserRole(testActiveUser, roleID, testAppOne, dataScope)
	}
	result := env.check(testActiveUser, testAppOne, []string{"invoices.approve"}, authz.ModeAll)
	if !result.Allowed {
		t.Fatalf("功能权限应允许：%+v", result)
	}
	dataScope := result.Permissions[0].DataScope
	if dataScope.Mode != authz.DataScopeResources || len(dataScope.Resources) != 1 || dataScope.Resources[0] != "b" {
		t.Fatalf("数据范围交集 = %+v", dataScope)
	}
	allowed, err := env.service.CheckResourceAccess(context.Background(), env.system, testActiveUser, testAppOne, "invoices.approve", "b")
	if err != nil || !allowed.Allowed {
		t.Fatalf("资源 b 应允许 = %+v err=%v", allowed, err)
	}
	denied, err := env.service.CheckResourceAccess(context.Background(), env.system, testActiveUser, testAppOne, "invoices.approve", "a")
	if err != nil || denied.Allowed || denied.Code != authz.CodeResourceForbidden {
		t.Fatalf("资源 a 应拒绝 = %+v err=%v", denied, err)
	}
	// 功能权限不存在时资源检查沿用 PERMISSION_UNKNOWN / REQUIRED。
	if decision, err := env.service.CheckResourceAccess(context.Background(), env.system, testUnrelated, testAppOne, "invoices.approve", "b"); err != nil || decision.Code != authz.CodeAppMembershipRequired {
		t.Fatalf("非成员资源检查 = %+v err=%v", decision, err)
	}

	// 历史 `{}`（undefined）功能权限允许但资源级默认拒绝。
	legacyRole := "role_00000000000000000000000000000041"
	env.insertRole(legacyRole, testAppOne, "legacy.role", true)
	env.addRolePermission(legacyRole, testPermissionRead, testAppOne)
	env.assignUserRole(testUnrelated, legacyRole, testAppOne, `{}`)
	// testUnrelated 不是 appOne 成员，先补齐成员关系再测。
	if _, err := env.raw.ExecContext(context.Background(),
		`INSERT INTO app_memberships(app_id,user_id,status,profile_json,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,'active','{"v":1}',1,1700000000000,1700000000000)`, testAppOne, testUnrelated); err != nil {
		t.Fatalf("插入成员关系失败: %v", err)
	}
	legacy := env.check(testUnrelated, testAppOne, []string{"invoices.read"}, authz.ModeAll)
	if !legacy.Allowed || legacy.Permissions[0].DataScope.Mode != authz.DataScopeUndefined {
		t.Fatalf("历史数据范围功能权限 = %+v", legacy)
	}
	resourceDecision, err := env.service.CheckResourceAccess(context.Background(), env.system, testUnrelated, testAppOne, "invoices.read", "b")
	if err != nil || resourceDecision.Allowed || resourceDecision.Reason != "data_scope_undefined" {
		t.Fatalf("历史数据范围资源检查 = %+v err=%v", resourceDecision, err)
	}
	// 非法数据范围来源被排除（fail-closed），PermissionSources 给出原因。
	invalidRole := "role_00000000000000000000000000000042"
	env.insertRole(invalidRole, testAppOne, "invalid.role", true)
	env.addRolePermission(invalidRole, testPermissionExport, testAppOne)
	// 先启用 export 权限，再写入非法数据范围（export 默认停用）。
	if _, err := env.raw.ExecContext(context.Background(), `UPDATE permissions SET enabled=1 WHERE id=?`, testPermissionExport); err != nil {
		t.Fatalf("启用权限失败: %v", err)
	}
	env.assignUserRole(testUnrelated, invalidRole, testAppOne, `{"v":1,"mode":"resources","resources":["a","a"]}`)
	invalidSources, err := env.service.PermissionSources(context.Background(), env.system, testUnrelated, testAppOne, "invoices.export", authz.ListOptions{})
	if err != nil {
		t.Fatalf("非法数据范围来源查询失败: %v", err)
	}
	if len(invalidSources.Sources) != 1 || invalidSources.Sources[0].Included || invalidSources.Sources[0].ExcludedReason != "data_scope_invalid" {
		t.Fatalf("非法数据范围来源 = %+v", invalidSources.Sources)
	}
	if result := env.check(testUnrelated, testAppOne, []string{"invoices.export"}, authz.ModeAll); result.Allowed || result.Code != authz.CodePermissionRequired {
		t.Fatalf("非法数据范围不应授予权限: %+v", result)
	}
	// 资源标识非法。
	if _, err := env.service.CheckResourceAccess(context.Background(), env.system, testActiveUser, testAppOne, "invoices.approve", "bad\nresource"); !errors.Is(err, authz.ErrInvalidRequest) {
		t.Fatalf("非法资源标识错误 = %v", err)
	}
}

// TestQueryAuthorizationAndNoLeak 验证查询他人的权限必须授权，且不泄露未获准对象。
func TestQueryAuthorizationAndNoLeak(t *testing.T) {
	env := prepareEnv(t)
	roleID := "role_00000000000000000000000000000051"
	env.insertRole(roleID, testAppOne, "appone.role", true)
	env.addRolePermission(roleID, testPermissionApprove, testAppOne)
	env.assignUserRole(testActiveUser, roleID, testAppOne, `{"v":1,"mode":"all"}`)
	activeCaller := env.userCaller(testActiveUser)
	otherCaller := env.userCaller(testOtherUser)

	// 用户可查询自己的有效权限与来源。
	if _, err := env.service.EffectivePermissions(context.Background(), activeCaller, testActiveUser, testAppOne, authz.ListOptions{}); err != nil {
		t.Fatalf("查询自己有效权限失败: %v", err)
	}
	if _, err := env.service.PermissionSources(context.Background(), activeCaller, testActiveUser, testAppOne, "invoices.approve", authz.ListOptions{}); err != nil {
		t.Fatalf("查询自己权限来源失败: %v", err)
	}
	// 用户不能查询他人，也不能用 Check 检查他人。
	if _, err := env.service.EffectivePermissions(context.Background(), otherCaller, testActiveUser, testAppOne, authz.ListOptions{}); !errors.Is(err, authz.ErrAccessDenied) {
		t.Fatalf("用户查询他人有效权限错误 = %v", err)
	}
	if _, err := env.service.Check(context.Background(), otherCaller, authz.CheckRequest{
		SubjectUserID: testActiveUser, ScopeID: testAppOne, Permissions: []string{"invoices.approve"},
	}); !errors.Is(err, authz.ErrAccessDenied) {
		t.Fatalf("用户检查他人权限错误 = %v", err)
	}
	// 应用管理员可查询本应用成员，但不可查询其他应用成员。
	adminCaller := env.userCaller(testActiveUser) // 已在 StaticAuthorizer 中配置为 appOne 管理员
	if _, err := env.service.EffectivePermissions(context.Background(), adminCaller, testBothUser, testAppOne, authz.ListOptions{}); err != nil {
		t.Fatalf("应用管理员查询本应用成员失败: %v", err)
	}
	if _, err := env.service.EffectivePermissions(context.Background(), adminCaller, testOtherUser, testAppTwo, authz.ListOptions{}); !errors.Is(err, authz.ErrAccessDenied) {
		t.Fatalf("应用管理员查询其他应用错误 = %v", err)
	}
	// 非本应用成员不能被应用管理员借查询探测：返回 ACCESS_DENIED。
	if _, err := env.service.EffectivePermissions(context.Background(), adminCaller, testUnrelated, testAppOne, authz.ListOptions{}); !errors.Is(err, authz.ErrAccessDenied) {
		t.Fatalf("应用管理员查询非成员错误 = %v", err)
	}
	// 本地/系统操作者可以查询任意普通主体。
	if _, err := env.service.EffectivePermissions(context.Background(), env.local, testUnrelated, testAppOne, authz.ListOptions{}); err != nil {
		t.Fatalf("本地管理员查询失败: %v", err)
	}
	// 缺少授权器不可构造；拒绝策略不放行。
	if _, err := authz.New(authz.Options{Store: nil, Authorizer: env.authorizer}); !errors.Is(err, authz.ErrOptionsInvalid) {
		t.Fatalf("空存储构造错误 = %v", err)
	}
	denyAuthorizer := denyQueryAuthorizer{}
	denyService, err := authz.New(authz.Options{Store: mustStore(env), Authorizer: denyAuthorizer})
	if err != nil {
		t.Fatalf("构造拒绝授权服务失败: %v", err)
	}
	if _, err := denyService.EffectivePermissions(context.Background(), env.system, testActiveUser, testAppOne, authz.ListOptions{}); !errors.Is(err, authz.ErrAccessDenied) {
		t.Fatalf("拒绝策略错误 = %v", err)
	}
	// 系统 scope 的有效权限查询：普通用户只能查自己；应用管理员不能查他人系统权限。
	if _, err := env.service.EffectivePermissions(context.Background(), activeCaller, testActiveUser, "system", authz.ListOptions{}); err != nil {
		t.Fatalf("查询自己系统 scope 失败: %v", err)
	}
	if _, err := env.service.EffectivePermissions(context.Background(), adminCaller, testBothUser, "system", authz.ListOptions{}); !errors.Is(err, authz.ErrAccessDenied) {
		t.Fatalf("应用管理员查询他人系统权限错误 = %v", err)
	}
}

// denyQueryAuthorizer 模拟缺少可信查询授权策略。
type denyQueryAuthorizer struct{}

func (denyQueryAuthorizer) AuthorizeQuery(context.Context, authz.Caller, string, authz.Scope) error {
	return authz.ErrAccessDenied
}

// mustStore 返回测试环境中的 Store 包装（用于构造拒绝授权服务）。
func mustStore(env *testEnv) authz.Store {
	store, err := authzsqlite.New(env.raw)
	if err != nil {
		env.t.Fatalf("构造授权存储失败: %v", err)
	}
	return store
}

// TestImmediateEffectNoStaleCache 验证角色/权限/成员/应用变更立即影响判定，不使用陈旧缓存。
func TestImmediateEffectNoStaleCache(t *testing.T) {
	env := prepareEnv(t)
	roleID := "role_00000000000000000000000000000061"
	env.insertRole(roleID, testAppOne, "appone.role", true)
	env.addRolePermission(roleID, testPermissionApprove, testAppOne)
	env.assignUserRole(testActiveUser, roleID, testAppOne, `{"v":1,"mode":"all"}`)

	check := func() bool {
		return env.check(testActiveUser, testAppOne, []string{"invoices.approve"}, authz.ModeAll).Allowed
	}
	if !check() {
		t.Fatal("初始应允许")
	}
	execute := func(query string, args ...any) {
		t.Helper()
		if _, err := env.raw.ExecContext(context.Background(), query, args...); err != nil {
			t.Fatalf("执行变更失败: %v", err)
		}
	}
	execute(`UPDATE roles SET enabled=0 WHERE id=?`, roleID)
	if check() {
		t.Fatal("角色停用后不应允许")
	}
	execute(`UPDATE roles SET enabled=1 WHERE id=?`, roleID)
	if !check() {
		t.Fatal("角色恢复后应允许")
	}
	execute(`UPDATE permissions SET enabled=0 WHERE id=?`, testPermissionApprove)
	if result := env.check(testActiveUser, testAppOne, []string{"invoices.approve"}, authz.ModeAll); result.Allowed || result.Code != authz.CodePermissionDisabled {
		t.Fatalf("权限停用后应拒绝: %+v", result)
	}
	execute(`UPDATE permissions SET enabled=1 WHERE id=?`, testPermissionApprove)
	if !check() {
		t.Fatal("权限恢复后应允许")
	}
	execute(`UPDATE app_memberships SET status='disabled' WHERE app_id=? AND user_id=?`, testAppOne, testActiveUser)
	if result := env.check(testActiveUser, testAppOne, []string{"invoices.approve"}, authz.ModeAll); result.Allowed || result.Code != authz.CodeAppMembershipRequired {
		t.Fatalf("成员停用后应拒绝: %+v", result)
	}
	execute(`UPDATE app_memberships SET status='active' WHERE app_id=? AND user_id=?`, testAppOne, testActiveUser)
	if !check() {
		t.Fatal("成员恢复后应允许")
	}
	execute(`UPDATE applications SET status='disabled' WHERE id=?`, testAppOne)
	if result := env.check(testActiveUser, testAppOne, []string{"invoices.approve"}, authz.ModeAll); result.Allowed || result.Code != authz.CodeClientDisabled {
		t.Fatalf("应用停用后应拒绝: %+v", result)
	}
	execute(`UPDATE applications SET status='active' WHERE id=?`, testAppOne)
	if !check() {
		t.Fatal("应用恢复后应允许")
	}
}

// TestPaginationAndValidation 验证分页边界与输入校验。
func TestPaginationAndValidation(t *testing.T) {
	env := prepareEnv(t)
	// 一个角色授予三个权限，验证有效权限分页。
	roleID := "role_00000000000000000000000000000071"
	env.insertRole(roleID, testAppOne, "multi.role", true)
	env.addRolePermission(roleID, testPermissionApprove, testAppOne)
	env.addRolePermission(roleID, testPermissionRead, testAppOne)
	env.addRolePermission(roleID, testPermissionExport, testAppOne)
	env.assignUserRole(testActiveUser, roleID, testAppOne, `{"v":1,"mode":"all"}`)
	// 启用停用权限，让它出现在有效权限中。
	if _, err := env.raw.ExecContext(context.Background(), `UPDATE permissions SET enabled=1 WHERE id=?`, testPermissionExport); err != nil {
		t.Fatalf("启用权限失败: %v", err)
	}
	page, err := env.service.EffectivePermissions(context.Background(), env.system, testActiveUser, testAppOne, authz.ListOptions{Limit: 2})
	if err != nil || len(page.Permissions) != 2 || !page.HasMore {
		t.Fatalf("有效权限分页 = %+v err=%v", page, err)
	}
	second, err := env.service.EffectivePermissions(context.Background(), env.system, testActiveUser, testAppOne, authz.ListOptions{Limit: 2, Offset: 2})
	if err != nil || len(second.Permissions) != 1 || second.HasMore {
		t.Fatalf("有效权限第二页 = %+v err=%v", second, err)
	}
	sources, err := env.service.PermissionSources(context.Background(), env.system, testActiveUser, testAppOne, "invoices.approve", authz.ListOptions{Limit: 1})
	if err != nil || len(sources.Sources) != 1 {
		t.Fatalf("来源分页 = %+v err=%v", sources, err)
	}
	// 校验边界。
	invalidChecks := []authz.CheckRequest{
		{SubjectUserID: testActiveUser, ScopeID: "not-a-scope", Permissions: []string{"invoices.approve"}},
		{SubjectUserID: "bad-user", ScopeID: testAppOne, Permissions: []string{"invoices.approve"}},
		{SubjectUserID: testActiveUser, ScopeID: testAppOne, Permissions: nil},
		{SubjectUserID: testActiveUser, ScopeID: testAppOne, Permissions: []string{"invoices.approve"}, Mode: "some"},
		{SubjectUserID: testActiveUser, ScopeID: testAppOne, Permissions: []string{"bad"}},
	}
	for index, request := range invalidChecks {
		if _, err := env.service.Check(context.Background(), env.system, request); !errors.Is(err, authz.ErrInvalidRequest) {
			t.Errorf("非法检查请求 %d 错误 = %v", index, err)
		}
	}
	tooMany := make([]string, authz.MaxRequirements+1)
	for index := range tooMany {
		tooMany[index] = "invoices.approve"
	}
	if _, err := env.service.Check(context.Background(), env.system, authz.CheckRequest{
		SubjectUserID: testActiveUser, ScopeID: testAppOne, Permissions: tooMany,
	}); !errors.Is(err, authz.ErrInvalidRequest) {
		t.Fatalf("超权限数量错误 = %v", err)
	}
	if _, err := env.service.EffectivePermissions(context.Background(), env.system, testActiveUser, testAppOne, authz.ListOptions{Limit: authz.MaxListLimit + 1}); !errors.Is(err, authz.ErrInvalidRequest) {
		t.Fatalf("分页上限错误 = %v", err)
	}
	// 未知权限不泄露为允许；来源查询可明确 PermissionFound=false。
	if result := env.check(testActiveUser, testAppOne, []string{"unknown.permission"}, authz.ModeAll); result.Allowed || result.Code != authz.CodePermissionUnknown {
		t.Fatalf("未知权限检查 = %+v", result)
	}
	unknownSources, err := env.service.PermissionSources(context.Background(), env.system, testActiveUser, testAppOne, "unknown.permission", authz.ListOptions{})
	if err != nil || unknownSources.PermissionFound || len(unknownSources.Sources) != 0 {
		t.Fatalf("未知权限来源 = %+v err=%v", unknownSources, err)
	}
}

// TestSourceLimitTruncationFailsClosed 验证候选来源超过 MaxSourceRows 时 Check/
// 资源检查/有效权限查询一律 fail-closed，不因只读到前 512 个来源而错误放行。
func TestSourceLimitTruncationFailsClosed(t *testing.T) {
	env := prepareEnv(t)
	// 前 512 个来源允许 r1，第 513 个来源只允许 r2；真实数据范围交集为空。
	for index := 0; index < authz.MaxSourceRows+1; index++ {
		roleID := fmt.Sprintf("role_%032x", index+1)
		env.insertRole(roleID, testAppOne, fmt.Sprintf("truncate.role.%03d", index), true)
		env.addRolePermission(roleID, testPermissionApprove, testAppOne)
		dataScope := `{"v":1,"mode":"resources","resources":["r1"]}`
		if index == authz.MaxSourceRows {
			dataScope = `{"v":1,"mode":"resources","resources":["r2"]}`
		}
		env.assignUserRole(testActiveUser, roleID, testAppOne, dataScope)
	}
	result := env.check(testActiveUser, testAppOne, []string{"invoices.approve"}, authz.ModeAll)
	if result.Allowed || result.Code != authz.CodeAuthzUnavailable || !result.SourceLimitReached {
		t.Fatalf("来源截断检查必须 fail-closed: %+v", result)
	}
	if len(result.Permissions) != 1 || result.Permissions[0].Allowed || !result.Permissions[0].SourceLimitReached {
		t.Fatalf("来源截断单权限结果 = %+v", result.Permissions)
	}
	for _, resource := range []string{"r1", "r2"} {
		decision, err := env.service.CheckResourceAccess(context.Background(), env.system, testActiveUser, testAppOne, "invoices.approve", resource)
		if err != nil {
			t.Fatalf("资源 %s 检查失败: %v", resource, err)
		}
		if decision.Allowed || decision.Code != authz.CodeAuthzUnavailable {
			t.Fatalf("截断时资源 %s 必须拒绝: %+v", resource, decision)
		}
	}
	effective := env.effective(testActiveUser, testAppOne, authz.ListOptions{})
	if effective.DeniedCode != authz.CodeAuthzUnavailable || !effective.SourceLimitReached || len(effective.Permissions) != 0 {
		t.Fatalf("来源截断有效权限必须拒绝/为空: %+v", effective)
	}
}

// TestStaticAuthorizerConcurrentReadWrite 验证查询授权器并发读写 map 安全。
func TestStaticAuthorizerConcurrentReadWrite(t *testing.T) {
	authorizer, err := authz.NewStaticAuthorizer(authz.AuthorizerOptions{
		LocalAdminIDs:     []string{testLocalAdmin},
		SystemIDs:         []string{testSystemID},
		ApplicationAdmins: map[string][]string{testAppOne: {testActiveUser}},
	})
	if err != nil {
		t.Fatalf("构造授权器失败: %v", err)
	}
	caller, err := authz.UserCaller(testActiveUser)
	if err != nil {
		t.Fatalf("构造用户调用者失败: %v", err)
	}
	appOneScope, err := authz.ParseScope(testAppOne)
	if err != nil {
		t.Fatalf("解析应用 scope 失败: %v", err)
	}
	appTwoScope, err := authz.ParseScope(testAppTwo)
	if err != nil {
		t.Fatalf("解析应用二 scope 失败: %v", err)
	}
	const workers = 8
	var waitGroup sync.WaitGroup
	for index := 0; index < workers; index++ {
		waitGroup.Add(1)
		go func(worker int) {
			defer waitGroup.Done()
			for iteration := 0; iteration < 100; iteration++ {
				if worker%2 == 0 {
					// 读：应用一管理员查询应用一（subject 可为他人）。
					if err := authorizer.AuthorizeQuery(context.Background(), caller, testBothUser, appOneScope); err != nil {
						t.Errorf("并发授权查询错误: %v", err)
						return
					}
					continue
				}
				// 写：并发分配应用二管理员。
				if err := authorizer.AssignApplicationAdmin(testAppTwo, testOtherUser); err != nil {
					t.Errorf("并发分配应用管理员错误: %v", err)
					return
				}
			}
		}(index)
	}
	waitGroup.Wait()
	// 写后的授权立即生效。
	if err := authorizer.AuthorizeQuery(context.Background(), caller, testUnrelated, appTwoScope); !errors.Is(err, authz.ErrAccessDenied) {
		t.Fatalf("未分配用户不应获准应用二: %v", err)
	}
	otherCaller, err := authz.UserCaller(testOtherUser)
	if err != nil {
		t.Fatalf("构造其他用户调用者失败: %v", err)
	}
	if err := authorizer.AuthorizeQuery(context.Background(), otherCaller, testUnrelated, appTwoScope); err != nil {
		t.Fatalf("新分配应用管理员应获准: %v", err)
	}
}

// TestDataScopeParsing 验证数据范围契约解析与交集规则。
func TestDataScopeParsing(t *testing.T) {
	valid := []struct {
		raw  string
		mode authz.DataScopeMode
	}{
		{"{}", authz.DataScopeUndefined},
		{``, authz.DataScopeUndefined},
		{`{"v":1,"mode":"all"}`, authz.DataScopeAll},
		{`{"v":1,"mode":"none"}`, authz.DataScopeNone},
		{`{"v":1,"mode":"resources","resources":["b","a"]}`, authz.DataScopeResources},
	}
	for _, test := range valid {
		scope, err := authz.ParseDataScope(test.raw)
		if err != nil || scope.Mode != test.mode {
			t.Errorf("ParseDataScope(%q) = %+v err=%v", test.raw, scope, err)
		}
	}
	invalid := []string{
		`{"v":2,"mode":"all"}`,
		`{"v":1,"mode":"custom"}`,
		`{"v":1,"mode":"all","resources":["a"]}`,
		`{"v":1,"mode":"resources"}`,
		`{"v":1,"mode":"resources","resources":[]}`,
		`{"v":1,"mode":"resources","resources":["a","a"]}`,
		`{"v":1,"mode":"resources","resources":["a\nb"]}`,
		`{"v":1,"mode":"all","extra":1}`,
		`not-json`,
	}
	for _, raw := range invalid {
		if _, err := authz.ParseDataScope(raw); err == nil {
			t.Errorf("ParseDataScope(%q) 应失败", raw)
		}
	}
	// 交集规则。
	intersection := []authz.DataScope{
		{Mode: authz.DataScopeAll},
		{Mode: authz.DataScopeResources, Resources: []string{"a", "b"}},
		{Mode: authz.DataScopeResources, Resources: []string{"b", "c"}},
	}
	merged := authz.IntersectDataScopes(intersection...)
	if merged.Mode != authz.DataScopeResources || len(merged.Resources) != 1 || merged.Resources[0] != "b" {
		t.Fatalf("数据范围交集 = %+v", merged)
	}
	undefined := authz.IntersectDataScopes(authz.DataScope{Mode: authz.DataScopeResources, Resources: []string{"a"}}, authz.DataScope{Mode: authz.DataScopeUndefined})
	if undefined.Mode != authz.DataScopeUndefined {
		t.Fatalf("undefined 交集 = %+v", undefined)
	}
	none := authz.IntersectDataScopes(authz.DataScope{Mode: authz.DataScopeAll}, authz.DataScope{Mode: authz.DataScopeNone})
	if none.Mode != authz.DataScopeNone {
		t.Fatalf("none 交集 = %+v", none)
	}
	// 资源检查规则。
	if !(authz.DataScope{Mode: authz.DataScopeAll}).AllowsResource("x") {
		t.Fatal("all 应允许任意资源")
	}
	if (authz.DataScope{Mode: authz.DataScopeNone}).AllowsResource("x") {
		t.Fatal("none 不应允许资源")
	}
	if (authz.DataScope{Mode: authz.DataScopeUndefined}).AllowsResource("x") {
		t.Fatal("undefined 不应允许资源")
	}
	if !(authz.DataScope{Mode: authz.DataScopeResources, Resources: []string{"x"}}).AllowsResource("x") {
		t.Fatal("resources 命中应允许")
	}
}

// TestSnapshotConcurrentMutationConsistency 验证并发启停期间检查结果始终对应某一
// 快照状态，不出现错误或超时。
func TestSnapshotConcurrentMutationConsistency(t *testing.T) {
	env := prepareEnv(t)
	roleID := "role_00000000000000000000000000000081"
	env.insertRole(roleID, testAppOne, "appone.role", true)
	env.addRolePermission(roleID, testPermissionApprove, testAppOne)
	env.assignUserRole(testActiveUser, roleID, testAppOne, `{"v":1,"mode":"all"}`)

	const workers = 4
	var waitGroup sync.WaitGroup
	stop := make(chan struct{})
	for index := 0; index < workers; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				result, err := env.service.Check(context.Background(), env.system, authz.CheckRequest{
					SubjectUserID: testActiveUser, ScopeID: testAppOne,
					Permissions: []string{"invoices.approve"},
				})
				if err != nil {
					t.Errorf("并发检查错误: %v", err)
					return
				}
				if result.Allowed && result.Code != "" {
					t.Errorf("允许结果不应带错误码: %+v", result)
					return
				}
				if !result.Allowed && result.Code == "" {
					t.Errorf("拒绝结果应带错误码: %+v", result)
					return
				}
			}
		}()
	}
	for index := 0; index < 20; index++ {
		enabled := index%2 == 0
		if _, err := env.raw.ExecContext(context.Background(),
			`UPDATE roles SET enabled=? WHERE id=?`, boolInt(enabled), roleID); err != nil {
			t.Fatalf("并发切换角色失败: %v", err)
		}
	}
	close(stop)
	waitGroup.Wait()
}

// TestSystemScopeEffectivePermissions 验证系统 scope 的有效权限、直接角色与用户
// 自查系统权限的授权边界。
func TestSystemScopeEffectivePermissions(t *testing.T) {
	env := prepareEnv(t)
	roleID := "role_000000000000000000000000000000a1"
	env.insertRole(roleID, "system", "system.reader", true)
	env.addRolePermission(roleID, testPermissionSystem, "system")
	env.assignUserRole(testActiveUser, roleID, "system", `{"v":1,"mode":"all"}`)

	effective := env.effective(testActiveUser, "system", authz.ListOptions{})
	if effective.DeniedCode != "" || len(effective.Permissions) != 1 {
		t.Fatalf("系统 scope 有效权限 = %+v", effective)
	}
	if effective.Permissions[0].Key != "users.read" || len(effective.Permissions[0].Sources) != 1 {
		t.Fatalf("系统 scope 权限来源 = %+v", effective.Permissions[0])
	}
	// 用户自查系统权限；系统 scope 不要求应用成员关系。
	caller := env.userCaller(testActiveUser)
	result, err := env.service.Check(context.Background(), caller, authz.CheckRequest{
		SubjectUserID: testActiveUser, ScopeID: "system", Permissions: []string{"users.read"},
	})
	if err != nil || !result.Allowed {
		t.Fatalf("系统权限自有检查 = %+v err=%v", result, err)
	}
	// 普通用户不能查他人系统权限。
	otherCaller := env.userCaller(testOtherUser)
	if _, err := env.service.EffectivePermissions(context.Background(), otherCaller, testActiveUser, "system", authz.ListOptions{}); !errors.Is(err, authz.ErrAccessDenied) {
		t.Fatalf("用户查询他人系统权限错误 = %v", err)
	}
}

// TestPermissionSourcesStatusExclusions 验证来源查询会标注账户/应用/成员状态限制。
func TestPermissionSourcesStatusExclusions(t *testing.T) {
	env := prepareEnv(t)
	roleID := "role_000000000000000000000000000000b1"
	env.insertRole(roleID, testAppOne, "status.role", true)
	env.addRolePermission(roleID, testPermissionApprove, testAppOne)
	env.assignUserRole(testActiveUser, roleID, testAppOne, `{"v":1,"mode":"all"}`)

	query := func() authz.SourceResult {
		t.Helper()
		result, err := env.service.PermissionSources(context.Background(), env.system, testActiveUser, testAppOne, "invoices.approve", authz.ListOptions{})
		if err != nil {
			t.Fatalf("来源查询失败: %v", err)
		}
		return result
	}
	applied := query()
	if len(applied.Sources) != 1 || !applied.Sources[0].Included {
		t.Fatalf("初始来源 = %+v", applied.Sources)
	}
	if _, err := env.raw.ExecContext(context.Background(), `UPDATE applications SET status='disabled' WHERE id=?`, testAppOne); err != nil {
		t.Fatalf("停用应用失败: %v", err)
	}
	appDisabled := query()
	if appDisabled.ApplicationStatus != "disabled" || len(appDisabled.Sources) != 1 ||
		appDisabled.Sources[0].Included || appDisabled.Sources[0].ExcludedReason != "application_inactive" {
		t.Fatalf("停用应用来源 = %+v", appDisabled)
	}
	if _, err := env.raw.ExecContext(context.Background(), `UPDATE applications SET status='active' WHERE id=?`, testAppOne); err != nil {
		t.Fatalf("恢复应用失败: %v", err)
	}
	if _, err := env.raw.ExecContext(context.Background(),
		`UPDATE app_memberships SET status='disabled' WHERE app_id=? AND user_id=?`, testAppOne, testActiveUser); err != nil {
		t.Fatalf("停用成员失败: %v", err)
	}
	memberDisabled := query()
	if memberDisabled.MembershipStatus != "disabled" || len(memberDisabled.Sources) != 1 ||
		memberDisabled.Sources[0].ExcludedReason != "membership_required" {
		t.Fatalf("停用成员来源 = %+v", memberDisabled)
	}
	if _, err := env.raw.ExecContext(context.Background(),
		`UPDATE app_memberships SET status='active' WHERE app_id=? AND user_id=?`, testAppOne, testActiveUser); err != nil {
		t.Fatalf("恢复成员失败: %v", err)
	}
	if _, err := env.raw.ExecContext(context.Background(), `UPDATE users SET status='disabled' WHERE id=?`, testActiveUser); err != nil {
		t.Fatalf("停用账户失败: %v", err)
	}
	accountDisabled := query()
	if accountDisabled.AccountStatus != "disabled" || len(accountDisabled.Sources) != 1 ||
		accountDisabled.Sources[0].ExcludedReason != "account_disabled" {
		t.Fatalf("停用账户来源 = %+v", accountDisabled)
	}
}

// TestEffectiveDeniedStatusesExposeReason 验证有效权限查询会报告被状态限制的原因，
// 且不返回伪造的权限集合。
func TestEffectiveDeniedStatusesExposeReason(t *testing.T) {
	env := prepareEnv(t)
	roleID := "role_00000000000000000000000000000091"
	env.insertRole(roleID, testAppOne, "appone.role", true)
	env.addRolePermission(roleID, testPermissionApprove, testAppOne)
	env.assignUserRole(testActiveUser, roleID, testAppOne, `{"v":1,"mode":"all"}`)

	// 停用应用：有效权限返回 CLIENT_DISABLED，不返回角色授予的权限。
	if _, err := env.raw.ExecContext(context.Background(),
		`UPDATE applications SET status='disabled' WHERE id=?`, testAppOne); err != nil {
		t.Fatalf("停用应用失败: %v", err)
	}
	effective := env.effective(testActiveUser, testAppOne, authz.ListOptions{})
	if effective.DeniedCode != authz.CodeClientDisabled || len(effective.Permissions) != 0 {
		t.Fatalf("停用应用有效权限 = %+v", effective)
	}
	if _, err := env.raw.ExecContext(context.Background(),
		`UPDATE applications SET status='active' WHERE id=?`, testAppOne); err != nil {
		t.Fatalf("恢复应用失败: %v", err)
	}
	// 停用成员：APP_MEMBERSHIP_REQUIRED。
	if _, err := env.raw.ExecContext(context.Background(),
		`UPDATE app_memberships SET status='disabled' WHERE app_id=? AND user_id=?`,
		testAppOne, testActiveUser); err != nil {
		t.Fatalf("停用成员失败: %v", err)
	}
	effective = env.effective(testActiveUser, testAppOne, authz.ListOptions{})
	if effective.DeniedCode != authz.CodeAppMembershipRequired || len(effective.Permissions) != 0 {
		t.Fatalf("停用成员有效权限 = %+v", effective)
	}
	if !strings.HasPrefix(string(effective.DeniedReason), "membership") {
		t.Fatalf("停用成员原因 = %q", effective.DeniedReason)
	}
}
