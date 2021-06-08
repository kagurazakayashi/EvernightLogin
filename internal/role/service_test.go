package role_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
	"github.com/kagurazakayashi/EvernightLogin/internal/role"
	rolesqlite "github.com/kagurazakayashi/EvernightLogin/internal/role/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const (
	testUserActive   = "usr_00000000000000000000000000000001"
	testUserOther    = "usr_00000000000000000000000000000002"
	testUserDisabled = "usr_00000000000000000000000000000003"
	testUserRoot     = "usr_00000000000000000000000000000004"
	testUserPending  = "usr_00000000000000000000000000000005"

	testApplicationOne      = "app_00000000000000000000000000000001"
	testApplicationTwo      = "app_00000000000000000000000000000002"
	testApplicationDisabled = "app_00000000000000000000000000000003"

	testPermissionSystem   = "perm_00000000000000000000000000000001"
	testPermissionCommApp  = "perm_00000000000000000000000000000002"
	testPermissionAppTwo   = "perm_00000000000000000000000000000003"
	testPermissionDisabled = "perm_00000000000000000000000000000004"
	testPermissionRootOnly = "perm_00000000000000000000000000000005"

	testGroupSystem = "grp_00000000000000000000000000000001"
	testGroupAppOne = "grp_00000000000000000000000000000002"
	testGroupAppTwo = "grp_00000000000000000000000000000003"

	testLocalAdminID = "operator-1"
	testSystemID     = "system-1"
	testAppTwoAdmin  = "usr_00000000000000000000000000000006"
)

// allowAllTransfers 是测试用可转授检查器：既有角色/用户组/权限/成员用例只关注
// 领域语义，委派限制的拒绝与允许由 internal/delegation 的定向测试和集成测试覆盖。
func allowAllTransfers() delegation.GuardFuncs {
	return delegation.GuardFuncs{
		Access: func(context.Context, audit.Tx, audit.Actor, string, []delegation.PermissionRef, []delegation.Target) error {
			return nil
		},
		Assignment: func(context.Context, audit.Tx, audit.Actor, string, []delegation.PermissionRef, delegation.Target) error {
			return nil
		},
		Activation: func(context.Context, audit.Tx, audit.Actor, string, []delegation.PermissionRef, []delegation.Target) error {
			return nil
		},
		Restoration: func(context.Context, audit.Tx, audit.Actor, string) error {
			return nil
		},
	}
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

type testEnv struct {
	t          *testing.T
	raw        *storagesqlite.Store
	store      *rolesqlite.Store
	auditStore *auditsqlite.Store
	recorder   *audit.Recorder
	service    *role.Service
	authorizer *role.StaticAuthorizer
	clock      *fakeClock
	system     role.Caller
	local      role.Caller
}

func prepareEnv(t *testing.T, mutations ...func(*role.Options)) *testEnv {
	t.Helper()
	ctx := context.Background()
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(filepath.Join(t.TempDir(), "role.sqlite")))
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
	store, err := rolesqlite.New(raw)
	if err != nil {
		t.Fatalf("构造角色仓储失败: %v", err)
	}
	auditStore, err := auditsqlite.New(raw)
	if err != nil {
		t.Fatalf("构造审计仓储失败: %v", err)
	}
	clock := &fakeClock{now: time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)}
	recorder, err := audit.New(auditStore, audit.Options{Now: clock.Now})
	if err != nil {
		t.Fatalf("构造审计写入器失败: %v", err)
	}
	authorizer, err := role.NewStaticAuthorizer(role.AuthorizerOptions{
		LocalAdminIDs: []string{testLocalAdminID},
		SystemIDs:     []string{testSystemID},
	})
	if err != nil {
		t.Fatalf("构造授权器失败: %v", err)
	}
	options := role.Options{AllowLegacyWithoutSensitive: true,
		Store: store, Audit: recorder, Authorizer: authorizer,
		Transfers: allowAllTransfers(), Now: clock.Now,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	for _, mutation := range mutations {
		mutation(&options)
	}
	service, err := role.New(options)
	if err != nil {
		t.Fatalf("构造角色服务失败: %v", err)
	}
	system, err := role.SystemCaller(testSystemID)
	if err != nil {
		t.Fatalf("构造系统调用者失败: %v", err)
	}
	local, err := role.LocalBootstrapCaller(testLocalAdminID)
	if err != nil {
		t.Fatalf("构造本地管理员调用者失败: %v", err)
	}
	env := &testEnv{t: t, raw: raw, store: store, auditStore: auditStore, recorder: recorder,
		service: service, authorizer: authorizer, clock: clock, system: system, local: local}
	env.insertFixtures()
	return env
}

// insertFixtures 直接插入角色测试所需的账户、应用、成员、权限与用户组。
func (e *testEnv) insertFixtures() {
	e.t.Helper()
	now := e.clock.Now().UnixMilli()
	insertUser := func(userID, username string, status string, isRoot int) {
		if _, err := e.raw.ExecContext(context.Background(),
			`INSERT INTO users(id,username,username_normalized,nickname,biography,language,timezone,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'','','zh-CN','Asia/Shanghai',?,?,1,1,?,?)`,
			userID, username, username, status, isRoot, now, now); err != nil {
			e.t.Fatalf("插入测试用户失败: %v", err)
		}
	}
	insertUser(testUserActive, "activeuser", "active", 0)
	insertUser(testUserOther, "otheruser", "active", 0)
	insertUser(testUserDisabled, "disableduser", "disabled", 0)
	insertUser(testUserRoot, "rootuser", "active", 1)
	insertUser(testUserPending, "pendinguser", "pending_delete", 0)
	insertUser(testAppTwoAdmin, "apptwoadmin", "active", 0)

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
	insertApplication(testApplicationOne, "应用一", "active")
	insertApplication(testApplicationTwo, "应用二", "active")
	insertApplication(testApplicationDisabled, "停用应用", "disabled")

	insertMembership := func(applicationID, userID, status string) {
		if _, err := e.raw.ExecContext(context.Background(),
			`INSERT INTO app_memberships(app_id,user_id,status,profile_json,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'{"v":1}',1,?,?)`, applicationID, userID, status, now, now); err != nil {
			e.t.Fatalf("插入测试应用成员失败: %v", err)
		}
	}
	insertMembership(testApplicationOne, testUserActive, "active")
	insertMembership(testApplicationTwo, testUserOther, "active")
	insertMembership(testApplicationOne, testUserDisabled, "active")

	insertPermission := func(permissionID, scopeID, key, name string, enabled, rootOnly, builtin bool) {
		if _, err := e.raw.ExecContext(context.Background(),
			`INSERT INTO permissions(id,scope_id,permission_key,name,description,limits_text,is_builtin,root_only,enabled,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,'','',?,?,?,?,?)`,
			permissionID, scopeID, key, name, boolInt(builtin), boolInt(rootOnly), boolInt(enabled), now, now); err != nil {
			e.t.Fatalf("插入测试权限失败: %v", err)
		}
	}
	insertPermission(testPermissionSystem, "system", "users.read", "查看用户", true, false, false)
	insertPermission(testPermissionCommApp, testApplicationOne, "invoices.approve", "审批报销", true, false, false)
	insertPermission(testPermissionAppTwo, testApplicationTwo, "devices.restart", "重启设备", true, false, false)
	insertPermission(testPermissionDisabled, "system", "users.export", "导出用户", false, false, false)
	insertPermission(testPermissionRootOnly, "system", "security.policy.manage", "修改敏感策略", true, true, true)

	insertGroup := func(groupID, scopeID, groupKey, name string) {
		if _, err := e.raw.ExecContext(context.Background(),
			`INSERT INTO user_groups(id,scope_id,group_key,name,description,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,'',?,?)`, groupID, scopeID, groupKey, name, now, now); err != nil {
			e.t.Fatalf("插入测试用户组失败: %v", err)
		}
	}
	insertGroup(testGroupSystem, "system", "system.ops", "系统运维组")
	insertGroup(testGroupAppOne, testApplicationOne, "appone.review", "应用一审批组")
	insertGroup(testGroupAppTwo, testApplicationTwo, "apptwo.ops", "应用二运维组")
}

// boolInt 把布尔值映射为 SQLite 的 0/1。
func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

// createRole 用系统操作者创建角色。
func (e *testEnv) createRole(scopeID, key, name string) role.Role {
	e.t.Helper()
	record, err := e.service.CreateRole(context.Background(), e.system, role.CreateRequest{
		ScopeID: scopeID, Key: key, Name: name,
		Description: "角色说明", Limits: "仅用于测试范围",
	})
	if err != nil {
		e.t.Fatalf("创建角色 %s/%s 失败: %v", scopeID, key, err)
	}
	return record
}

// createAppRole 用系统操作者创建应用角色。
func (e *testEnv) createAppRole(applicationID, key, name string) role.Role {
	return e.createRole(applicationID, key, name)
}

// createRoleInDisabledAppFixture 临时启用应用创建角色后再停用，供“角色存在但应用
// 已停用”的边界测试使用。
func (e *testEnv) createRoleInDisabledAppFixture(applicationID, key, name string) role.Role {
	e.t.Helper()
	if _, err := e.raw.ExecContext(context.Background(), `UPDATE applications SET status='active' WHERE id=?`, applicationID); err != nil {
		e.t.Fatalf("临时启用应用失败: %v", err)
	}
	record := e.createAppRole(applicationID, key, name)
	if _, err := e.raw.ExecContext(context.Background(), `UPDATE applications SET status='disabled' WHERE id=?`, applicationID); err != nil {
		e.t.Fatalf("恢复停用应用失败: %v", err)
	}
	return record
}

// appAdminCaller 显式分配应用管理员并返回用户调用者。
func (e *testEnv) appAdminCaller(applicationID, userID string) role.Caller {
	e.t.Helper()
	if err := e.authorizer.AssignApplicationAdmin(applicationID, userID); err != nil {
		e.t.Fatalf("分配应用管理员失败: %v", err)
	}
	caller, err := role.UserCaller(userID)
	if err != nil {
		e.t.Fatalf("构造应用管理员调用者失败: %v", err)
	}
	return caller
}

// queryInt 执行单值整数查询。
func (e *testEnv) queryInt(query string, args ...any) int {
	e.t.Helper()
	rows, err := e.raw.QueryContext(context.Background(), query, args...)
	if err != nil {
		e.t.Fatalf("查询失败: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		e.t.Fatalf("查询没有结果: %s", query)
	}
	var value int
	if err := rows.Scan(&value); err != nil {
		e.t.Fatalf("读取查询结果失败: %v", err)
	}
	return value
}

// auditCount 统计指定动作/结果的审计数量（roleID 为空表示不按目标过滤）。
func (e *testEnv) auditCount(action, outcome, roleID string) int {
	e.t.Helper()
	if roleID == "" {
		return e.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action=? AND outcome=?`, action, outcome)
	}
	return e.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action=? AND outcome=? AND target_id=?`,
		action, outcome, roleID)
}

// TestRoleCreateValidationAndIsolation 验证角色创建白名单、root 语义拒绝、同 scope
// 唯一、内置保护与跨应用隔离。
func TestRoleCreateValidationAndIsolation(t *testing.T) {
	env := prepareEnv(t)

	systemRole := env.createRole("system", "ops.manage", "运维管理")
	if systemRole.ScopeKind != role.ScopeKindSystem || systemRole.ScopeID != "system" {
		t.Fatalf("系统角色范围 = %+v", systemRole)
	}
	appRole := env.createAppRole(testApplicationOne, "billing.approve", "报销审批")
	if appRole.ScopeKind != role.ScopeKindApplication || appRole.ApplicationID != testApplicationOne {
		t.Fatalf("应用角色范围 = %+v", appRole)
	}
	// 不同 scope 可以使用相同机器标识。
	if other := env.createAppRole(testApplicationTwo, "billing.approve", "应用二审批"); other.ScopeID != testApplicationTwo {
		t.Fatalf("跨 scope 同名角色 = %+v", other)
	}

	// 同 scope 重复机器标识 CONFLICT。
	if _, err := env.service.CreateRole(context.Background(), env.system, role.CreateRequest{
		ScopeID: "system", Key: "ops.manage", Name: "重复角色", Description: "说明", Limits: "限制",
	}); !errors.Is(err, role.ErrRoleKeyTaken) {
		t.Fatalf("重复角色键错误 = %v", err)
	}

	// root 语义机器标识拒绝。
	for _, key := range []string{"root", "root.admin", "system_root", "root.ops"} {
		if _, err := env.service.CreateRole(context.Background(), env.system, role.CreateRequest{
			ScopeID: "system", Key: key, Name: "非法角色", Description: "说明", Limits: "限制",
		}); !errors.Is(err, role.ErrInvalidRequest) {
			t.Errorf("root 语义角色键 %q 错误 = %v，期望 ErrInvalidRequest", key, err)
		}
	}
	// 字段边界。
	invalidRequests := []role.CreateRequest{
		{ScopeID: "system", Key: "a", Name: "名", Description: "说明", Limits: "限制"},
		{ScopeID: "system", Key: "a.b", Name: "", Description: "说明", Limits: "限制"},
		{ScopeID: "system", Key: "a.b", Name: "名", Description: "", Limits: "限制"},
		{ScopeID: "system", Key: "a.b", Name: "名", Description: "说明", Limits: ""},
		{ScopeID: "system", Key: "非法键", Name: "名", Description: "说明", Limits: "限制"},
		{ScopeID: "not-a-scope", Key: "a.b", Name: "名", Description: "说明", Limits: "限制"},
	}
	for index, request := range invalidRequests {
		if _, err := env.service.CreateRole(context.Background(), env.system, request); !errors.Is(err, role.ErrInvalidRequest) &&
			!errors.Is(err, role.ErrScopeInvalid) {
			t.Errorf("非法角色请求 %d 错误 = %v", index, err)
		}
	}
	// 停用应用不能创建应用角色。
	if _, err := env.service.CreateRole(context.Background(), env.system, role.CreateRequest{
		ScopeID: testApplicationDisabled, Key: "disabled.role", Name: "停用应用角色",
		Description: "说明", Limits: "限制",
	}); !errors.Is(err, role.ErrApplicationInactive) {
		t.Fatalf("停用应用创建角色错误 = %v", err)
	}
	// 应用范围不能创建内置角色；应用管理员不能创建系统角色。
	appAdmin := env.appAdminCaller(testApplicationOne, testUserActive)
	if _, err := env.service.CreateRole(context.Background(), appAdmin, role.CreateRequest{
		ScopeID: testApplicationOne, Key: "app.builtin", Name: "内置", Description: "说明", Limits: "限制",
		IsBuiltin: true,
	}); !errors.Is(err, role.ErrAccessDenied) {
		t.Fatalf("应用创建内置角色错误 = %v", err)
	}
	if _, err := env.service.CreateRole(context.Background(), appAdmin, role.CreateRequest{
		ScopeID: "system", Key: "system.admin", Name: "系统角色", Description: "说明", Limits: "限制",
	}); !errors.Is(err, role.ErrAccessDenied) {
		t.Fatalf("应用管理员创建系统角色错误 = %v", err)
	}

	// 内置系统角色：系统操作者可创建；应用管理员不可修改/删除；可停用。
	builtin := env.createRole("system", "preset.reader", "预置只读")
	if _, err := env.service.CreateRole(context.Background(), env.system, role.CreateRequest{
		ScopeID: "system", Key: "preset.operator", Name: "预置操作", Description: "说明", Limits: "限制",
		IsBuiltin: true,
	}); err != nil {
		t.Fatalf("创建内置角色失败: %v", err)
	}
	// 读取与列表：系统操作者可见全部；应用管理员只能看到分配应用的角色。
	appOneAdmin := env.appAdminCaller(testApplicationOne, testAppTwoAdmin)
	if _, err := env.service.GetRole(context.Background(), appOneAdmin, appRole.ID); err != nil {
		t.Fatalf("应用管理员读取本应用角色失败: %v", err)
	}
	if _, err := env.service.GetRole(context.Background(), appOneAdmin, systemRole.ID); !errors.Is(err, role.ErrAccessDenied) {
		t.Fatalf("应用管理员读取系统角色错误 = %v", err)
	}
	appTwoRole := env.createAppRole(testApplicationTwo, "other.role", "其他应用角色")
	if _, err := env.service.GetRole(context.Background(), appOneAdmin, appTwoRole.ID); !errors.Is(err, role.ErrAccessDenied) {
		t.Fatalf("应用管理员读取其他应用角色错误 = %v", err)
	}
	listResult, err := env.service.ListRoles(context.Background(), appOneAdmin, role.ListRequest{})
	if err != nil {
		t.Fatalf("应用管理员列表失败: %v", err)
	}
	if len(listResult.Roles) != 1 || listResult.Roles[0].ApplicationID != testApplicationOne {
		t.Fatalf("应用管理员角色列表范围 = %+v", listResult.Roles)
	}
	if _, err := env.service.ListRoles(context.Background(), appOneAdmin, role.ListRequest{ScopeID: testApplicationTwo}); !errors.Is(err, role.ErrAccessDenied) {
		t.Fatalf("应用管理员跨应用列表错误 = %v", err)
	}
	systemList, err := env.service.ListRoles(context.Background(), env.system, role.ListRequest{})
	if err != nil || len(systemList.Roles) < 4 {
		t.Fatalf("系统操作者角色列表 = %+v err=%v", systemList, err)
	}
	_ = builtin
}

// TestRoleUpdateEnableDisableAndBuiltin 验证角色资料更新、启停幂等、内置保护与删除。
func TestRoleUpdateEnableDisableAndBuiltin(t *testing.T) {
	env := prepareEnv(t)
	record := env.createRole("system", "ops.manage", "旧名称")

	updated, err := env.service.UpdateRole(context.Background(), env.system, record.ID, role.UpdateRequest{
		Name: "新名称", Description: "新说明", Limits: "新限制说明",
	})
	if err != nil {
		t.Fatalf("更新角色失败: %v", err)
	}
	if updated.Name != "新名称" || updated.Key != record.Key || updated.ScopeID != record.ScopeID {
		t.Fatalf("更新后角色 = %+v", updated)
	}
	// 内置角色资料不可修改、不可删除。
	builtin, err := env.service.CreateRole(context.Background(), env.system, role.CreateRequest{
		ScopeID: "system", Key: "preset.reader", Name: "预置只读", Description: "说明", Limits: "限制", IsBuiltin: true,
	})
	if err != nil {
		t.Fatalf("创建内置角色失败: %v", err)
	}
	if _, err := env.service.UpdateRole(context.Background(), env.system, builtin.ID, role.UpdateRequest{
		Name: "改名", Description: "说明", Limits: "限制",
	}); !errors.Is(err, role.ErrBuiltinProtected) {
		t.Fatalf("修改内置角色错误 = %v", err)
	}
	if err := env.service.DeleteRole(context.Background(), env.system, builtin.ID); !errors.Is(err, role.ErrBuiltinProtected) {
		t.Fatalf("删除内置角色错误 = %v", err)
	}

	// 启停幂等与最终状态。
	disabled, changed, err := env.service.DisableRole(context.Background(), env.system, record.ID)
	if err != nil || !changed || disabled.Enabled {
		t.Fatalf("停用角色 = %+v changed=%v err=%v", disabled, changed, err)
	}
	again, changed, err := env.service.DisableRole(context.Background(), env.system, record.ID)
	if err != nil || changed || again.Enabled {
		t.Fatalf("重复停用角色 = %+v changed=%v err=%v", again, changed, err)
	}
	enabled, changed, err := env.service.EnableRole(context.Background(), env.system, record.ID)
	if err != nil || !changed || !enabled.Enabled {
		t.Fatalf("启用角色 = %+v changed=%v err=%v", enabled, changed, err)
	}

	// 删除无引用自定义角色。
	if err := env.service.DeleteRole(context.Background(), env.system, record.ID); err != nil {
		t.Fatalf("删除角色失败: %v", err)
	}
	if count := env.queryInt(`SELECT COUNT(*) FROM roles WHERE id=?`, record.ID); count != 0 {
		t.Fatalf("删除后角色行数 = %d", count)
	}
	if _, err := env.service.GetRole(context.Background(), env.system, record.ID); !errors.Is(err, role.ErrRoleNotFound) {
		t.Fatalf("删除后读取错误 = %v", err)
	}
	// 非内置删除可写审计；读取审计在失败路径不产生成功事件。
	if count := env.auditCount("role.delete", "success", record.ID); count != 1 {
		t.Fatalf("删除角色成功审计 = %d", count)
	}
}

// TestRolePermissionComposition 验证同范围权限组合、跨范围/停用/root_only 拒绝与
// 幂等组合。
func TestRolePermissionComposition(t *testing.T) {
	env := prepareEnv(t)
	systemRole := env.createRole("system", "ops.manage", "运维管理")
	appRole := env.createAppRole(testApplicationOne, "billing.approve", "报销审批")

	changed, err := env.service.AddRolePermission(context.Background(), env.system, systemRole.ID, testPermissionSystem)
	if err != nil || !changed {
		t.Fatalf("加入系统权限 = %v changed=%v", err, changed)
	}
	changed, err = env.service.AddRolePermission(context.Background(), env.system, systemRole.ID, testPermissionSystem)
	if err != nil || changed {
		t.Fatalf("重复加入权限 = %v changed=%v", err, changed)
	}
	permissions, err := env.service.ListRolePermissions(context.Background(), env.system, systemRole.ID)
	if err != nil || len(permissions) != 1 || permissions[0].PermissionID != testPermissionSystem {
		t.Fatalf("角色权限列表 = %+v err=%v", permissions, err)
	}
	// 跨范围权限拒绝。
	if _, err := env.service.AddRolePermission(context.Background(), env.system, systemRole.ID, testPermissionCommApp); !errors.Is(err, role.ErrPermissionScope) {
		t.Fatalf("跨范围组合错误 = %v", err)
	}
	if _, err := env.service.AddRolePermission(context.Background(), env.appAdminCaller(testApplicationOne, testUserActive), appRole.ID, testPermissionSystem); !errors.Is(err, role.ErrPermissionScope) {
		t.Fatalf("应用角色组合系统权限错误 = %v", err)
	}
	// 不存在/停用/root_only 权限拒绝。
	if _, err := env.service.AddRolePermission(context.Background(), env.system, systemRole.ID, "perm_ffffffffffffffffffffffffffffffff"); !errors.Is(err, role.ErrPermissionNotFound) {
		t.Fatalf("不存在权限组合错误 = %v", err)
	}
	if _, err := env.service.AddRolePermission(context.Background(), env.system, systemRole.ID, testPermissionDisabled); !errors.Is(err, role.ErrPermissionInactive) {
		t.Fatalf("停用权限组合错误 = %v", err)
	}
	if _, err := env.service.AddRolePermission(context.Background(), env.system, systemRole.ID, testPermissionRootOnly); !errors.Is(err, role.ErrRootOnlyPermission) {
		t.Fatalf("root_only 权限组合错误 = %v", err)
	}
	// 移除幂等。
	removed, err := env.service.RemoveRolePermission(context.Background(), env.system, systemRole.ID, testPermissionSystem)
	if err != nil || !removed {
		t.Fatalf("移除权限 = %v removed=%v", err, removed)
	}
	removed, err = env.service.RemoveRolePermission(context.Background(), env.system, systemRole.ID, testPermissionSystem)
	if err != nil || removed {
		t.Fatalf("重复移除权限 = %v removed=%v", err, removed)
	}
	if permissions, _ := env.service.ListRolePermissions(context.Background(), env.system, systemRole.ID); len(permissions) != 0 {
		t.Fatalf("移除后角色权限 = %+v", permissions)
	}

	// 应用角色组合同应用权限成功。
	if changed, err := env.service.AddRolePermission(context.Background(), env.system, appRole.ID, testPermissionCommApp); err != nil || !changed {
		t.Fatalf("应用角色组合应用权限 = %v changed=%v", err, changed)
	}
	// 权限在组合后被停用：关系保留，后续有效权限计算必须按当前 enabled 过滤。
	if _, err := env.raw.ExecContext(context.Background(), `UPDATE permissions SET enabled=0 WHERE id=?`, testPermissionCommApp); err != nil {
		t.Fatalf("停用权限失败: %v", err)
	}
	permissions, err = env.service.ListRolePermissions(context.Background(), env.system, appRole.ID)
	if err != nil || len(permissions) != 1 || permissions[0].Enabled {
		t.Fatalf("组合后权限停用状态 = %+v err=%v", permissions, err)
	}
}

// TestRoleUserAssignmentEligibility 验证用户角色分配的账户状态、root 保护、应用
// 成员资格与应用状态检查。
func TestRoleUserAssignmentEligibility(t *testing.T) {
	env := prepareEnv(t)
	systemRole := env.createRole("system", "ops.manage", "运维管理")
	appRole := env.createAppRole(testApplicationOne, "billing.approve", "报销审批")
	appAdmin := env.appAdminCaller(testApplicationOne, testUserActive)

	// 系统角色分配给 active 用户。
	changed, err := env.service.AssignUserRole(context.Background(), env.system, systemRole.ID, testUserActive)
	if err != nil || !changed {
		t.Fatalf("分配系统角色 = %v changed=%v", err, changed)
	}
	changed, err = env.service.AssignUserRole(context.Background(), env.system, systemRole.ID, testUserActive)
	if err != nil || changed {
		t.Fatalf("重复分配系统角色 = %v changed=%v", err, changed)
	}
	assignments, err := env.service.ListRoleAssignments(context.Background(), env.system, systemRole.ID)
	if err != nil || len(assignments.Users) != 1 || assignments.Users[0].UserID != testUserActive ||
		assignments.Users[0].AssignedBy != testSystemID {
		t.Fatalf("系统角色分配快照 = %+v err=%v", assignments, err)
	}
	// 禁用/待删除账户、root、不存在账户拒绝。
	for _, userID := range []string{testUserDisabled, testUserPending} {
		if _, err := env.service.AssignUserRole(context.Background(), env.system, systemRole.ID, userID); !errors.Is(err, role.ErrUserNotEligible) {
			t.Errorf("非 active 账户 %s 分配错误 = %v", userID, err)
		}
	}
	if _, err := env.service.AssignUserRole(context.Background(), env.system, systemRole.ID, testUserRoot); !errors.Is(err, role.ErrRootProtected) {
		t.Fatalf("root 分配角色错误 = %v", err)
	}
	// root 分配拒绝必须留失败审计，且不产生角色分配行。
	if count := env.queryInt(`SELECT COUNT(*) FROM audit_events
WHERE action=? AND outcome='failure' AND error_code='ACCESS_DENIED' AND reason_code='root_account_protected' AND target_id=?`,
		string(role.ActionAssignUserRole), testUserRoot); count != 1 {
		t.Errorf("root 分配拒绝失败审计数 = %d，期望 1", count)
	}
	if count := env.queryInt(`SELECT COUNT(*) FROM user_roles WHERE user_id=?`, testUserRoot); count != 0 {
		t.Errorf("root 不应获得角色分配，行数 = %d", count)
	}
	if _, err := env.service.AssignUserRole(context.Background(), env.system, systemRole.ID, "usr_ffffffffffffffffffffffffffffffff"); !errors.Is(err, role.ErrUserNotFound) {
		t.Fatalf("不存在账户分配错误 = %v", err)
	}

	// 应用角色：必须是该应用 active 成员；其他应用成员/非成员/停用成员/停用应用拒绝。
	if changed, err := env.service.AssignUserRole(context.Background(), appAdmin, appRole.ID, testUserActive); err != nil || !changed {
		t.Fatalf("应用角色分配有效成员 = %v changed=%v", err, changed)
	}
	if _, err := env.service.AssignUserRole(context.Background(), appAdmin, appRole.ID, testUserOther); !errors.Is(err, role.ErrUserNotMember) {
		t.Fatalf("非本应用成员分配错误 = %v", err)
	}
	// 成员关系停用。
	if _, err := env.raw.ExecContext(context.Background(),
		`UPDATE app_memberships SET status='disabled' WHERE app_id=? AND user_id=?`, testApplicationOne, testUserActive); err != nil {
		t.Fatalf("停用应用成员失败: %v", err)
	}
	if _, err := env.service.AssignUserRole(context.Background(), appAdmin, appRole.ID, testUserActive); !errors.Is(err, role.ErrUserNotMember) {
		t.Fatalf("停用成员分配错误 = %v", err)
	}
	if _, err := env.raw.ExecContext(context.Background(),
		`UPDATE app_memberships SET status='active' WHERE app_id=? AND user_id=?`, testApplicationOne, testUserActive); err != nil {
		t.Fatalf("恢复应用成员失败: %v", err)
	}
	// 停用应用拒绝新分配。
	disabledAppRole := env.createRoleInDisabledAppFixture(testApplicationDisabled, "disabled.role", "停用应用角色")
	if _, err := env.service.AssignUserRole(context.Background(), env.system, disabledAppRole.ID, testUserActive); !errors.Is(err, role.ErrApplicationInactive) {
		t.Fatalf("停用应用分配角色错误 = %v", err)
	}
	// 停用角色拒绝新分配。
	disabledRole, _, err := env.service.DisableRole(context.Background(), env.system, systemRole.ID)
	if err != nil {
		t.Fatalf("停用角色失败: %v", err)
	}
	if _, err := env.service.AssignUserRole(context.Background(), env.system, disabledRole.ID, testUserOther); !errors.Is(err, role.ErrRoleDisabled) {
		t.Fatalf("停用角色分配错误 = %v", err)
	}
	// 撤回在角色/应用/账户停用时仍允许安全清理。
	if changed, err := env.service.RevokeUserRole(context.Background(), env.system, systemRole.ID, testUserActive); err != nil || !changed {
		t.Fatalf("撤回用户角色 = %v changed=%v", err, changed)
	}
	if changed, err := env.service.RevokeUserRole(context.Background(), env.system, systemRole.ID, testUserActive); err != nil || changed {
		t.Fatalf("重复撤回用户角色 = %v changed=%v", err, changed)
	}
	if assignments, _ := env.service.ListRoleAssignments(context.Background(), env.system, systemRole.ID); len(assignments.Users) != 0 {
		t.Fatalf("撤回后用户分配 = %+v", assignments.Users)
	}
}

// TestRoleGroupAssignmentScope 验证用户组角色分配的范围一致性。
func TestRoleGroupAssignmentScope(t *testing.T) {
	env := prepareEnv(t)
	systemRole := env.createRole("system", "ops.manage", "运维管理")
	appRole := env.createAppRole(testApplicationOne, "billing.approve", "报销审批")
	appAdmin := env.appAdminCaller(testApplicationOne, testUserActive)

	if changed, err := env.service.AssignGroupRole(context.Background(), env.system, systemRole.ID, testGroupSystem); err != nil || !changed {
		t.Fatalf("系统角色分配系统组 = %v changed=%v", err, changed)
	}
	if changed, err := env.service.AssignGroupRole(context.Background(), appAdmin, appRole.ID, testGroupAppOne); err != nil || !changed {
		t.Fatalf("应用角色分配本应用组 = %v changed=%v", err, changed)
	}
	// 跨范围拒绝。
	if _, err := env.service.AssignGroupRole(context.Background(), env.system, systemRole.ID, testGroupAppOne); !errors.Is(err, role.ErrGroupScope) {
		t.Fatalf("系统角色分配应用组错误 = %v", err)
	}
	if _, err := env.service.AssignGroupRole(context.Background(), appAdmin, appRole.ID, testGroupSystem); !errors.Is(err, role.ErrGroupScope) {
		t.Fatalf("应用角色分配系统组错误 = %v", err)
	}
	if _, err := env.service.AssignGroupRole(context.Background(), env.system, appRole.ID, testGroupAppTwo); !errors.Is(err, role.ErrGroupScope) {
		t.Fatalf("应用角色分配其他应用组错误 = %v", err)
	}
	if _, err := env.service.AssignGroupRole(context.Background(), env.system, systemRole.ID, "grp_ffffffffffffffffffffffffffffffff"); !errors.Is(err, role.ErrGroupNotFound) {
		t.Fatalf("不存在用户组分配错误 = %v", err)
	}
	// 停用应用拒绝新分配。
	disabledAppRole := env.createRoleInDisabledAppFixture(testApplicationDisabled, "disabled.role", "停用应用角色")
	if _, err := env.service.AssignGroupRole(context.Background(), env.system, disabledAppRole.ID, testGroupAppTwo); !errors.Is(err, role.ErrGroupScope) {
		// 停用应用组尚未创建；用同 scope 组验证应用停用路径需要先建组。
		t.Fatalf("停用应用角色分配跨范围错误 = %v", err)
	}
	if _, err := env.raw.ExecContext(context.Background(),
		`INSERT INTO user_groups(id,scope_id,group_key,name,description,created_at_ms,updated_at_ms)
VALUES('grp_00000000000000000000000000000009',?,'disabled.group','停用应用组','',?,?)`,
		testApplicationDisabled, env.clock.Now().UnixMilli(), env.clock.Now().UnixMilli()); err != nil {
		t.Fatalf("插入停用应用组失败: %v", err)
	}
	if _, err := env.service.AssignGroupRole(context.Background(), env.system, disabledAppRole.ID,
		"grp_00000000000000000000000000000009"); !errors.Is(err, role.ErrApplicationInactive) {
		t.Fatalf("停用应用分配用户组角色错误 = %v", err)
	}
	// 幂等与撤回。
	if changed, err := env.service.AssignGroupRole(context.Background(), env.system, systemRole.ID, testGroupSystem); err != nil || changed {
		t.Fatalf("重复分配用户组 = %v changed=%v", err, changed)
	}
	if changed, err := env.service.RevokeGroupRole(context.Background(), env.system, systemRole.ID, testGroupSystem); err != nil || !changed {
		t.Fatalf("撤回用户组角色 = %v changed=%v", err, changed)
	}
	if changed, err := env.service.RevokeGroupRole(context.Background(), env.system, systemRole.ID, testGroupSystem); err != nil || changed {
		t.Fatalf("重复撤回用户组角色 = %v changed=%v", err, changed)
	}
	assignments, err := env.service.ListRoleAssignments(context.Background(), env.system, appRole.ID)
	if err != nil || len(assignments.Groups) != 1 || assignments.Groups[0].GroupID != testGroupAppOne {
		t.Fatalf("应用角色组分配快照 = %+v err=%v", assignments, err)
	}
}

// TestRoleDeleteReferenceProtection 验证有权限组合/用户/用户组引用时拒绝删除角色。
func TestRoleDeleteReferenceProtection(t *testing.T) {
	env := prepareEnv(t)
	record := env.createRole("system", "ops.manage", "运维管理")
	if _, err := env.service.AddRolePermission(context.Background(), env.system, record.ID, testPermissionSystem); err != nil {
		t.Fatalf("组合权限失败: %v", err)
	}
	if _, err := env.service.AssignUserRole(context.Background(), env.system, record.ID, testUserActive); err != nil {
		t.Fatalf("分配用户失败: %v", err)
	}
	if _, err := env.service.AssignGroupRole(context.Background(), env.system, record.ID, testGroupSystem); err != nil {
		t.Fatalf("分配用户组失败: %v", err)
	}
	if err := env.service.DeleteRole(context.Background(), env.system, record.ID); !errors.Is(err, role.ErrRoleInUse) {
		t.Fatalf("有引用删除角色错误 = %v", err)
	}
	if count := env.queryInt(`SELECT COUNT(*) FROM roles WHERE id=?`, record.ID); count != 1 {
		t.Fatalf("拒绝删除后角色仍应存在，行数 = %d", count)
	}
	// 逐个解除引用后删除成功。
	if _, err := env.service.RemoveRolePermission(context.Background(), env.system, record.ID, testPermissionSystem); err != nil {
		t.Fatalf("移除权限失败: %v", err)
	}
	if _, err := env.service.RevokeUserRole(context.Background(), env.system, record.ID, testUserActive); err != nil {
		t.Fatalf("撤回用户失败: %v", err)
	}
	if _, err := env.service.RevokeGroupRole(context.Background(), env.system, record.ID, testGroupSystem); err != nil {
		t.Fatalf("撤回用户组失败: %v", err)
	}
	if err := env.service.DeleteRole(context.Background(), env.system, record.ID); err != nil {
		t.Fatalf("解除引用后删除角色失败: %v", err)
	}
	if err := env.service.DeleteRole(context.Background(), env.system, record.ID); !errors.Is(err, role.ErrRoleNotFound) {
		t.Fatalf("重复删除角色错误 = %v", err)
	}
}

// denyAllAuthorizer 模拟缺少可信授权策略：任何调用都拒绝。
type denyAllAuthorizer struct{}

func (denyAllAuthorizer) Authorize(context.Context, role.Caller, role.Action, string) error {
	return role.ErrAccessDenied
}

func (denyAllAuthorizer) ManageableScopes(context.Context, role.Caller) (bool, []string, error) {
	return false, nil, role.ErrAccessDenied
}

// TestRoleAuthorizationDefaultDeny 验证缺少/拒绝策略时不放行，且应用管理员范围严格。
func TestRoleAuthorizationDefaultDeny(t *testing.T) {
	env := prepareEnv(t)
	// 构造时缺少依赖直接失败。
	if _, err := role.New(role.Options{AllowLegacyWithoutSensitive: true, Audit: env.recorder, Authorizer: env.authorizer}); !errors.Is(err, role.ErrOptionsInvalid) {
		t.Fatalf("缺少 Store 构造错误 = %v", err)
	}
	if _, err := role.New(role.Options{AllowLegacyWithoutSensitive: true, Store: env.store, Authorizer: env.authorizer}); !errors.Is(err, role.ErrOptionsInvalid) {
		t.Fatalf("缺少审计构造错误 = %v", err)
	}
	if _, err := role.New(role.Options{AllowLegacyWithoutSensitive: true, Store: env.store, Audit: env.recorder}); !errors.Is(err, role.ErrOptionsInvalid) {
		t.Fatalf("缺少授权器构造错误 = %v", err)
	}
	denyService, err := role.New(role.Options{AllowLegacyWithoutSensitive: true, Store: env.store, Audit: env.recorder, Authorizer: denyAllAuthorizer{}, Transfers: allowAllTransfers()})
	if err != nil {
		t.Fatalf("构造拒绝授权服务失败: %v", err)
	}
	before := env.queryInt(`SELECT COUNT(*) FROM roles`)
	if _, err := denyService.CreateRole(context.Background(), env.local, role.CreateRequest{
		ScopeID: "system", Key: "deny.role", Name: "拒绝", Description: "说明", Limits: "限制",
	}); !errors.Is(err, role.ErrAccessDenied) {
		t.Fatalf("策略拒绝时创建错误 = %v", err)
	}
	if _, err := denyService.ListRoles(context.Background(), env.local, role.ListRequest{}); !errors.Is(err, role.ErrAccessDenied) {
		t.Fatalf("策略拒绝时列表错误 = %v", err)
	}
	if after := env.queryInt(`SELECT COUNT(*) FROM roles`); after != before {
		t.Fatalf("策略拒绝后角色行数 = %d，期望 %d", after, before)
	}
	// 应用管理员不能操作系统角色/其他应用角色。
	appAdmin := env.appAdminCaller(testApplicationOne, testUserActive)
	systemRole := env.createRole("system", "ops.manage", "运维管理")
	if _, _, err := env.service.DisableRole(context.Background(), appAdmin, systemRole.ID); !errors.Is(err, role.ErrAccessDenied) {
		t.Fatalf("应用管理员停用系统角色错误 = %v", err)
	}
	// 非应用管理员用户被拒绝。
	otherCaller, err := role.UserCaller(testUserOther)
	if err != nil {
		t.Fatalf("构造普通用户调用者失败: %v", err)
	}
	if _, err := env.service.ListRoles(context.Background(), otherCaller, role.ListRequest{}); !errors.Is(err, role.ErrAccessDenied) {
		t.Fatalf("普通用户列表错误 = %v", err)
	}
}

// TestRoleConcurrency 验证并发创建/组合/分配/启停/删除的单一终态与幂等语义。
func TestRoleConcurrency(t *testing.T) {
	env := prepareEnv(t)
	const workers = 4

	// 并发创建同 scope 同机器标识：仅 1 成功。
	type createResult struct {
		record role.Role
		err    error
	}
	createResults := make(chan createResult, workers)
	var createWG sync.WaitGroup
	for index := 0; index < workers; index++ {
		createWG.Add(1)
		go func() {
			defer createWG.Done()
			record, err := env.service.CreateRole(context.Background(), env.system, role.CreateRequest{
				ScopeID: "system", Key: "concurrent.role", Name: "并发角色", Description: "说明", Limits: "限制",
			})
			createResults <- createResult{record: record, err: err}
		}()
	}
	createWG.Wait()
	close(createResults)
	created := 0
	conflicts := 0
	var concurrentRole role.Role
	for result := range createResults {
		switch {
		case result.err == nil:
			created++
			concurrentRole = result.record
		case errors.Is(result.err, role.ErrRoleKeyTaken):
			conflicts++
		default:
			t.Fatalf("并发创建角色意外错误 = %v", result.err)
		}
	}
	if created != 1 || conflicts != workers-1 {
		t.Fatalf("并发创建角色结果 = 成功%d 冲突%d", created, conflicts)
	}
	if count := env.queryInt(`SELECT COUNT(*) FROM roles WHERE role_key='concurrent.role'`); count != 1 {
		t.Fatalf("并发创建后角色行数 = %d", count)
	}

	// 并发组合同一权限：一次新增，其余幂等未变化，最终 1 行。
	changes := make(chan bool, workers)
	var composeWG sync.WaitGroup
	for index := 0; index < workers; index++ {
		composeWG.Add(1)
		go func() {
			defer composeWG.Done()
			changed, err := env.service.AddRolePermission(context.Background(), env.system, concurrentRole.ID, testPermissionSystem)
			if err != nil {
				t.Errorf("并发组合权限错误: %v", err)
			}
			changes <- changed
		}()
	}
	composeWG.Wait()
	close(changes)
	inserted := 0
	for changed := range changes {
		if changed {
			inserted++
		}
	}
	if inserted != 1 {
		t.Fatalf("并发组合权限 Changed 次数 = %d", inserted)
	}
	if count := env.queryInt(`SELECT COUNT(*) FROM role_permissions WHERE role_id=?`, concurrentRole.ID); count != 1 {
		t.Fatalf("并发组合后权限关系行数 = %d", count)
	}

	// 并发分配同一用户：一次新增，其余幂等未变化，最终 1 行。
	userChanges := make(chan bool, workers)
	var userWG sync.WaitGroup
	for index := 0; index < workers; index++ {
		userWG.Add(1)
		go func() {
			defer userWG.Done()
			changed, err := env.service.AssignUserRole(context.Background(), env.system, concurrentRole.ID, testUserActive)
			if err != nil {
				t.Errorf("并发分配用户错误: %v", err)
			}
			userChanges <- changed
		}()
	}
	userWG.Wait()
	close(userChanges)
	userInserted := 0
	for changed := range userChanges {
		if changed {
			userInserted++
		}
	}
	if userInserted != 1 {
		t.Fatalf("并发分配用户 Changed 次数 = %d", userInserted)
	}
	if count := env.queryInt(`SELECT COUNT(*) FROM user_roles WHERE role_id=?`, concurrentRole.ID); count != 1 {
		t.Fatalf("并发分配后用户角色行数 = %d", count)
	}

	// 并发停用：仅一个实际变更，其余 CONFLICT/幂等，最终 disabled。
	type statusResult struct {
		changed bool
		err     error
	}
	statusResults := make(chan statusResult, workers)
	var statusWG sync.WaitGroup
	for index := 0; index < workers; index++ {
		statusWG.Add(1)
		go func() {
			defer statusWG.Done()
			_, changed, err := env.service.DisableRole(context.Background(), env.system, concurrentRole.ID)
			statusResults <- statusResult{changed: changed, err: err}
		}()
	}
	statusWG.Wait()
	close(statusResults)
	statusChanged := 0
	statusConflicts := 0
	for result := range statusResults {
		switch {
		case result.err == nil && result.changed:
			statusChanged++
		case result.err == nil:
			// 幂等成功（读到已停用状态）。
		case errors.Is(result.err, role.ErrStateConflict):
			statusConflicts++
		default:
			t.Fatalf("并发停用角色意外错误 = %v", result.err)
		}
	}
	if statusChanged != 1 {
		t.Fatalf("并发停用实际 Changed 次数 = %d", statusChanged)
	}
	if statusChanged+statusConflicts == 0 {
		t.Fatal("并发停用没有任何实际变更")
	}
	if enabled := env.queryInt(`SELECT enabled FROM roles WHERE id=?`, concurrentRole.ID); enabled != 0 {
		t.Fatalf("并发停用后 enabled = %d", enabled)
	}

	// 并发删除（先解除引用）：仅 1 成功删除，其余 CONFLICT/NOT_FOUND，最终无行。
	if _, err := env.service.RemoveRolePermission(context.Background(), env.system, concurrentRole.ID, testPermissionSystem); err != nil {
		t.Fatalf("解除权限引用失败: %v", err)
	}
	if _, err := env.service.RevokeUserRole(context.Background(), env.system, concurrentRole.ID, testUserActive); err != nil {
		t.Fatalf("解除用户引用失败: %v", err)
	}
	deleteResults := make(chan error, workers)
	var deleteWG sync.WaitGroup
	for index := 0; index < workers; index++ {
		deleteWG.Add(1)
		go func() {
			defer deleteWG.Done()
			deleteResults <- env.service.DeleteRole(context.Background(), env.system, concurrentRole.ID)
		}()
	}
	deleteWG.Wait()
	close(deleteResults)
	deleteSuccesses := 0
	for err := range deleteResults {
		switch {
		case err == nil:
			deleteSuccesses++
		case errors.Is(err, role.ErrRoleNotFound), errors.Is(err, role.ErrRoleInUse), errors.Is(err, role.ErrStateConflict):
		default:
			t.Fatalf("并发删除角色意外错误 = %v", err)
		}
	}
	if deleteSuccesses != 1 {
		t.Fatalf("并发删除成功次数 = %d", deleteSuccesses)
	}
	if count := env.queryInt(`SELECT COUNT(*) FROM roles WHERE id=?`, concurrentRole.ID); count != 0 {
		t.Fatalf("并发删除后角色行数 = %d", count)
	}
}

// TestRoleAuditFailClosedAndRootBoundaries 验证审计故障 fail-closed、失败审计错误码、
// root_only 权限与 root 账户边界。
func TestRoleAuditFailClosedAndRootBoundaries(t *testing.T) {
	env := prepareEnv(t)
	// 审计故障时创建角色失败且不落库。
	if _, err := env.raw.ExecContext(context.Background(),
		`CREATE TRIGGER fail_role_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'audit blocked'); END;`); err != nil {
		t.Fatalf("创建审计故障触发器失败: %v", err)
	}
	if _, err := env.service.CreateRole(context.Background(), env.system, role.CreateRequest{
		ScopeID: "system", Key: "audit.role", Name: "审计角色", Description: "说明", Limits: "限制",
	}); !errors.Is(err, role.ErrAuditUnavailable) {
		t.Fatalf("审计故障创建角色错误 = %v", err)
	}
	if count := env.queryInt(`SELECT COUNT(*) FROM roles WHERE role_key='audit.role'`); count != 0 {
		t.Fatalf("审计故障后角色行数 = %d", count)
	}
	if _, err := env.raw.ExecContext(context.Background(), `DROP TRIGGER fail_role_audit;`); err != nil {
		t.Fatalf("删除审计故障触发器失败: %v", err)
	}

	// 角色权限关系写入故障：业务失败、失败审计 error_code=DB_UNAVAILABLE。
	record := env.createRole("system", "ops.manage", "运维管理")
	if _, err := env.raw.ExecContext(context.Background(),
		`CREATE TRIGGER fail_role_permission BEFORE INSERT ON role_permissions BEGIN SELECT RAISE(ABORT,'role permission blocked'); END;`); err != nil {
		t.Fatalf("创建角色权限故障触发器失败: %v", err)
	}
	if _, err := env.service.AddRolePermission(context.Background(), env.system, record.ID, testPermissionSystem); !errors.Is(err, role.ErrStoreUnavailable) {
		t.Fatalf("角色权限写入故障错误 = %v", err)
	}
	if count := env.queryInt(`SELECT COUNT(*) FROM role_permissions WHERE role_id=?`, record.ID); count != 0 {
		t.Fatalf("写入故障后角色权限行数 = %d", count)
	}
	if count := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action='role.permission.add' AND outcome='failure' AND error_code='DB_UNAVAILABLE'`); count != 1 {
		t.Errorf("角色权限故障失败审计 DB_UNAVAILABLE 数量 = %d", count)
	}
	if _, err := env.raw.ExecContext(context.Background(), `DROP TRIGGER fail_role_permission;`); err != nil {
		t.Fatalf("删除角色权限故障触发器失败: %v", err)
	}

	// root_only 权限不能加入角色；root 账户不能分配角色（再次显式验证）。
	if _, err := env.service.AddRolePermission(context.Background(), env.system, record.ID, testPermissionRootOnly); !errors.Is(err, role.ErrRootOnlyPermission) {
		t.Fatalf("root_only 权限组合错误 = %v", err)
	}
	if _, err := env.service.AssignUserRole(context.Background(), env.system, record.ID, testUserRoot); !errors.Is(err, role.ErrRootProtected) {
		t.Fatalf("root 账户角色分配错误 = %v", err)
	}
	// 审计记录包含角色目标、操作者与应用快照。
	if _, err := env.service.AddRolePermission(context.Background(), env.system, record.ID, testPermissionSystem); err != nil {
		t.Fatalf("加入权限失败: %v", err)
	}
	if count := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action='role.permission.add' AND outcome='success' AND target_type='role' AND target_id=?`, record.ID); count != 1 {
		t.Fatalf("角色权限审计数量 = %d", count)
	}
	if count := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action='role.permission.add' AND outcome='success' AND actor_type='system' AND actor_id=?`, testSystemID); count != 1 {
		t.Fatalf("角色权限审计操作者数量 = %d", count)
	}
}

// TestRoleBuiltinAssignmentAndDisabledCleanup 验证内置角色的系统分配、应用角色在
// 应用停用后的安全清理语义。
func TestRoleDisabledCleanupAndBuiltinAssignment(t *testing.T) {
	env := prepareEnv(t)
	builtin, err := env.service.CreateRole(context.Background(), env.system, role.CreateRequest{
		ScopeID: "system", Key: "preset.reader", Name: "预置只读", Description: "说明", Limits: "限制", IsBuiltin: true,
	})
	if err != nil {
		t.Fatalf("创建内置角色失败: %v", err)
	}
	if changed, err := env.service.AssignUserRole(context.Background(), env.system, builtin.ID, testUserActive); err != nil || !changed {
		t.Fatalf("内置角色分配用户 = %v changed=%v", err, changed)
	}
	if changed, err := env.service.AssignGroupRole(context.Background(), env.system, builtin.ID, testGroupSystem); err != nil || !changed {
		t.Fatalf("内置角色分配用户组 = %v changed=%v", err, changed)
	}
	// 应用停用后允许撤回用户组/用户角色。
	appRole := env.createAppRole(testApplicationOne, "billing.approve", "报销审批")
	if _, err := env.service.AssignUserRole(context.Background(), env.system, appRole.ID, testUserActive); err != nil {
		t.Fatalf("分配应用角色用户失败: %v", err)
	}
	if _, err := env.service.AssignGroupRole(context.Background(), env.system, appRole.ID, testGroupAppOne); err != nil {
		t.Fatalf("分配应用角色用户组失败: %v", err)
	}
	if _, err := env.raw.ExecContext(context.Background(),
		`UPDATE applications SET status='disabled' WHERE id=?`, testApplicationOne); err != nil {
		t.Fatalf("停用应用失败: %v", err)
	}
	if changed, err := env.service.RevokeUserRole(context.Background(), env.system, appRole.ID, testUserActive); err != nil || !changed {
		t.Fatalf("停用应用撤回用户角色 = %v changed=%v", err, changed)
	}
	if changed, err := env.service.RevokeGroupRole(context.Background(), env.system, appRole.ID, testGroupAppOne); err != nil || !changed {
		t.Fatalf("停用应用撤回用户组角色 = %v changed=%v", err, changed)
	}
	// 停用角色后仍可撤回既有分配。
	disabled, _, err := env.service.DisableRole(context.Background(), env.system, builtin.ID)
	if err != nil || disabled.Enabled {
		t.Fatalf("停用内置角色 = %+v err=%v", disabled, err)
	}
	if changed, err := env.service.RevokeUserRole(context.Background(), env.system, builtin.ID, testUserActive); err != nil || !changed {
		t.Fatalf("停用角色撤回用户 = %v changed=%v", err, changed)
	}
}

// TestRoleGroupWithRootCannotReceiveRole 验证含 root 账户的用户组不能分配普通角色，
// 避免通过组间接给 root 赋角色。
func TestRoleGroupWithRootCannotReceiveRole(t *testing.T) {
	env := prepareEnv(t)
	systemRole := env.createRole("system", "ops.manage", "运维管理")
	now := env.clock.Now().UnixMilli()
	if _, err := env.raw.ExecContext(context.Background(),
		`INSERT INTO group_members(group_id,user_id,created_at_ms) VALUES(?,?,?)`,
		testGroupSystem, testUserRoot, now); err != nil {
		t.Fatalf("插入 root 组成员失败: %v", err)
	}
	if _, err := env.service.AssignGroupRole(context.Background(), env.system, systemRole.ID, testGroupSystem); !errors.Is(err, role.ErrRootProtected) {
		t.Fatalf("含 root 组成员分配角色错误 = %v", err)
	}
	if count := env.queryInt(`SELECT COUNT(*) FROM group_roles WHERE role_id=?`, systemRole.ID); count != 0 {
		t.Fatalf("拒绝后组角色行数 = %d", count)
	}
	// 含 root 组的角色分配拒绝必须留失败审计（普通管理员反复尝试不能无痕）。
	if count := env.queryInt(`SELECT COUNT(*) FROM audit_events
WHERE action=? AND outcome='failure' AND error_code='ACCESS_DENIED' AND reason_code='root_group_member_protected' AND target_id=?`,
		string(role.ActionAssignGroupRole), testGroupSystem); count != 1 {
		t.Errorf("含 root 组拒绝失败审计数 = %d，期望 1", count)
	}
	// 移除 root 组成员后可分配。
	if _, err := env.raw.ExecContext(context.Background(),
		`DELETE FROM group_members WHERE group_id=? AND user_id=?`, testGroupSystem, testUserRoot); err != nil {
		t.Fatalf("移除 root 组成员失败: %v", err)
	}
	if changed, err := env.service.AssignGroupRole(context.Background(), env.system, systemRole.ID, testGroupSystem); err != nil || !changed {
		t.Fatalf("移除 root 后分配组角色 = %v changed=%v", err, changed)
	}
}

// TestRoleListPaginationAndFilters 验证角色列表分页、状态/内置过滤与非法参数。
func TestRoleListPaginationAndFilters(t *testing.T) {
	env := prepareEnv(t)
	for index := 0; index < 3; index++ {
		env.createRole("system", "system.role"+string(rune('a'+index)), "系统角色")
	}
	disabled := env.createRole("system", "system.disabled", "停用角色")
	if _, _, err := env.service.DisableRole(context.Background(), env.system, disabled.ID); err != nil {
		t.Fatalf("停用角色失败: %v", err)
	}
	builtin, err := env.service.CreateRole(context.Background(), env.system, role.CreateRequest{
		ScopeID: "system", Key: "preset.reader", Name: "预置只读", Description: "说明", Limits: "限制", IsBuiltin: true,
	})
	if err != nil {
		t.Fatalf("创建内置角色失败: %v", err)
	}
	page, err := env.service.ListRoles(context.Background(), env.system, role.ListRequest{Limit: 2})
	if err != nil || len(page.Roles) != 2 || !page.HasMore {
		t.Fatalf("角色分页第一页 = %+v err=%v", page, err)
	}
	disabledFilter := false
	page, err = env.service.ListRoles(context.Background(), env.system, role.ListRequest{Enabled: &disabledFilter})
	if err != nil || len(page.Roles) != 1 || page.Roles[0].ID != disabled.ID {
		t.Fatalf("停用角色过滤 = %+v err=%v", page, err)
	}
	builtinFilter := true
	page, err = env.service.ListRoles(context.Background(), env.system, role.ListRequest{Builtin: &builtinFilter})
	if err != nil || len(page.Roles) != 1 || page.Roles[0].ID != builtin.ID {
		t.Fatalf("内置角色过滤 = %+v err=%v", page, err)
	}
	invalid := []role.ListRequest{
		{Limit: role.MaxListLimit + 1},
		{Offset: -1},
		{Offset: role.MaxListOffset + 1},
		{ScopeID: "not-a-scope"},
	}
	for index, request := range invalid {
		if _, err := env.service.ListRoles(context.Background(), env.system, request); !errors.Is(err, role.ErrInvalidRequest) &&
			!errors.Is(err, role.ErrScopeInvalid) {
			t.Errorf("非法列表请求 %d 错误 = %v", index, err)
		}
	}
	// 内置角色名说明含控制字符等非法更新已在 UpdateRole 拒绝，这里验证空名称。
	if _, err := env.service.UpdateRole(context.Background(), env.system, disabled.ID, role.UpdateRequest{
		Name: "", Description: "说明", Limits: "限制",
	}); !errors.Is(err, role.ErrInvalidRequest) {
		t.Fatalf("空名称更新错误 = %v", err)
	}
}
