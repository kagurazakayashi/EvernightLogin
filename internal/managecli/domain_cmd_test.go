package managecli

// 本文件覆盖步骤 84 第二轮：默认数据库安全拒绝、组/角色/应用只读命令、
// 受控建组、未开放写动作的明确拒绝、权限目录与通知状态。

import (
	"context"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	appsqlite "github.com/kagurazakayashi/EvernightLogin/internal/app/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
	"github.com/kagurazakayashi/EvernightLogin/internal/group"
	groupsqlite "github.com/kagurazakayashi/EvernightLogin/internal/group/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/role"
	rolesqlite "github.com/kagurazakayashi/EvernightLogin/internal/role/sqlite"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

// TestDefaultDatabaseRefusedWithoutConfirmation 验证未显式配置时拒绝默认
// database/login.db，避免误触真实/基线库。
func TestDefaultDatabaseRefusedWithoutConfirmation(t *testing.T) {
	// 不传 --config：有效配置使用默认 database.path。
	stdout, _, exit := runCLI(t, "diag", "database", "--json")
	if exit != ExitError {
		t.Fatalf("diag database 退出码 = %d，期望 %d", exit, ExitError)
	}
	checks := diagChecks(t, stdout)
	if checks["database"]["code"] != "CONFIG_DEFAULT_DATABASE_REFUSED" {
		t.Fatalf("数据库检查 = %v", checks["database"])
	}
	// migrate status 直接拒绝，错误码明确。
	stdout, _, exit = runCLI(t, "migrate", "status", "--json")
	if exit != ExitUsage {
		t.Fatalf("migrate status 退出码 = %d，期望 %d", exit, ExitUsage)
	}
	if code := envelopeErrorCode(t, decodeEnvelope(t, stdout)); code != "CONFIG_DEFAULT_DATABASE_REFUSED" {
		t.Fatalf("错误码 = %s", code)
	}
	// task list 同样拒绝。
	stdout, _, exit = runCLI(t, "task", "list", "--json")
	if exit != ExitUsage {
		t.Fatalf("task list 退出码 = %d，期望 %d", exit, ExitUsage)
	}
	if code := envelopeErrorCode(t, decodeEnvelope(t, stdout)); code != "CONFIG_DEFAULT_DATABASE_REFUSED" {
		t.Fatalf("错误码 = %s", code)
	}
	// 显式 --config 指向临时库时正常（不是默认路径）。
	databasePath, _ := newTestDatabase(t)
	configPath := writeConfigFile(t, t.TempDir(), databasePath)
	if _, _, exit := runCLI(t, "task", "list", "--config", configPath, "--json"); exit != ExitOK {
		t.Fatalf("显式配置 task list 退出码 = %d", exit)
	}
}

// allowAllGroupAuthorizer 是测试夹具授权器（仅用于构造种子数据，不是生产授权）。
type allowAllGroupAuthorizer struct{}

func (allowAllGroupAuthorizer) Authorize(context.Context, group.Caller,
	group.Action, string) error {
	return nil
}

func (allowAllGroupAuthorizer) ManageableScopes(context.Context,
	group.Caller) (bool, []string, error) {
	return true, nil, nil
}

// allowAllRoleAuthorizer 是测试夹具授权器。
type allowAllRoleAuthorizer struct{}

func (allowAllRoleAuthorizer) Authorize(context.Context, role.Caller,
	role.Action, string) error {
	return nil
}

func (allowAllRoleAuthorizer) ManageableScopes(context.Context,
	role.Caller) (bool, []string, error) {
	return true, nil, nil
}

// allowAllAppAuthorizer 是测试夹具授权器。
type allowAllAppAuthorizer struct{}

func (allowAllAppAuthorizer) Authorize(context.Context, app.Caller,
	app.Action, string) error {
	return nil
}

func (allowAllAppAuthorizer) ApplicationScope(context.Context,
	app.Caller) (bool, []string, error) {
	return true, nil, nil
}

// domainFixture 是组/角色/应用只读命令的测试环境。
type domainFixture struct {
	configPath string
	raw        *storagesqlite.Store
	groupID    string
	roleID     string
	appID      string
}

// newDomainFixture 用真实服务构造种子用户、组、角色与应用（授权器为测试夹具）。
func newDomainFixture(t *testing.T) *domainFixture {
	t.Helper()
	databasePath, raw := newTestDatabase(t)
	seedUser(t, raw, testUserID(1), "user1", false)
	auditStore, err := auditsqlite.New(raw)
	if err != nil {
		t.Fatalf("审计存储: %v", err)
	}
	recorder, err := audit.New(auditStore, audit.Options{
		Now: func() time.Time { return testNow }})
	if err != nil {
		t.Fatalf("审计写入器: %v", err)
	}
	now := func() time.Time { return testNow }
	groupStore, err := groupsqlite.New(raw)
	if err != nil {
		t.Fatalf("组存储: %v", err)
	}
	groupService, err := group.New(group.Options{Store: groupStore, Audit: recorder,
		Authorizer: allowAllGroupAuthorizer{}, Transfers: delegation.GuardFuncs{},
		AllowLegacyWithoutSensitive: true, Now: now})
	if err != nil {
		t.Fatalf("组服务: %v", err)
	}
	groupCaller, _ := group.SystemCaller("fixture")
	createdGroup, err := groupService.CreateGroup(context.Background(), groupCaller,
		group.CreateRequest{ScopeID: "system", GroupKey: "test-group", Name: "测试组"})
	if err != nil {
		t.Fatalf("创建组: %v", err)
	}
	if _, err := groupService.AddMembers(context.Background(), groupCaller,
		group.MemberBatchRequest{GroupID: createdGroup.ID,
			UserIDs: []string{testUserID(1)}}); err != nil {
		// 成员写入需要委派 Guard；夹具无 Guard 时跳过成员种子。
		_ = err
	}
	roleStore, err := rolesqlite.New(raw)
	if err != nil {
		t.Fatalf("角色存储: %v", err)
	}
	roleService, err := role.New(role.Options{Store: roleStore, Audit: recorder,
		Authorizer: allowAllRoleAuthorizer{}, Transfers: delegation.GuardFuncs{},
		AllowLegacyWithoutSensitive: true, Now: now})
	if err != nil {
		t.Fatalf("角色服务: %v", err)
	}
	roleCaller, _ := role.SystemCaller("fixture")
	createdRole, err := roleService.CreateRole(context.Background(), roleCaller,
		role.CreateRequest{ScopeID: "system", Key: "test-role", Name: "测试角色",
			Description: "测试角色说明",
			Limits:      "不能绕过用户管理范围"})
	if err != nil {
		t.Fatalf("创建角色: %v", err)
	}
	appStore, err := appsqlite.New(raw)
	if err != nil {
		t.Fatalf("应用存储: %v", err)
	}
	appService, err := app.New(app.Options{Store: appStore, Audit: recorder,
		Authorizer: allowAllAppAuthorizer{}, Transfers: delegation.GuardFuncs{},
		Now: now})
	if err != nil {
		t.Fatalf("应用服务: %v", err)
	}
	appCaller, _ := app.SystemCaller("fixture")
	createdApp, err := appService.CreateApplication(context.Background(), appCaller,
		app.CreateRequest{Name: "测试应用", ClientType: app.ClientTypePublic,
			OwnerUserID: testUserID(1)})
	if err != nil {
		t.Fatalf("创建应用: %v", err)
	}
	return &domainFixture{configPath: writeConfigFile(t, t.TempDir(), databasePath),
		raw: raw, groupID: createdGroup.ID, roleID: createdRole.ID,
		appID: createdApp.ID}
}

// TestGroupCommands 验证用户组只读命令与受控建组。
func TestGroupCommands(t *testing.T) {
	fixture := newDomainFixture(t)
	stdout, stderr, exit := runCLI(t, "group", "list", "--operator", "local-admin",
		"--config", fixture.configPath, "--json")
	if exit != ExitOK {
		t.Fatalf("group list 退出码 = %d，stderr=%s", exit, stderr)
	}
	data := decodeEnvelope(t, stdout)["data"].(map[string]any)
	if len(data["groups"].([]any)) != 1 {
		t.Fatalf("组列表 = %v", data)
	}
	stdout, _, exit = runCLI(t, "group", "get", fixture.groupID, "--operator",
		"local-admin", "--config", fixture.configPath, "--json")
	if exit != ExitOK || decodeEnvelope(t, stdout)["data"].(map[string]any)["group_key"] != "test-group" {
		t.Fatalf("group get = %s", stdout)
	}
	if _, _, exit := runCLI(t, "group", "members", fixture.groupID, "--operator",
		"local-admin", "--config", fixture.configPath, "--json"); exit != ExitOK {
		t.Fatalf("group members 退出码 = %d", exit)
	}
	// 受控建组：缺确认拒绝，确认后成功并写审计。
	if _, _, exit := runCLI(t, "group", "create", "--operator", "local-admin",
		"--scope", "system", "--key", "new-group", "--name", "新组",
		"--config", fixture.configPath); exit != ExitUsage {
		t.Fatalf("缺确认建组退出码 = %d，期望 %d", exit, ExitUsage)
	}
	stdout, stderr, exit = runCLI(t, "group", "create", "--operator", "local-admin",
		"--scope", "system", "--key", "new-group", "--name", "新组",
		"--confirm", "CREATE", "--config", fixture.configPath, "--json")
	if exit != ExitOK {
		t.Fatalf("建组退出码 = %d，stderr=%s", exit, stderr)
	}
	if decodeEnvelope(t, stdout)["data"].(map[string]any)["group_key"] != "new-group" {
		t.Fatalf("建组输出 = %s", stdout)
	}
	// 未开放的写动作明确拒绝。
	stdout, _, exit = runCLI(t, "group", "delete", fixture.groupID, "--operator",
		"local-admin", "--config", fixture.configPath, "--json")
	if exit != ExitForbidden {
		t.Fatalf("未开放写动作退出码 = %d，期望 %d", exit, ExitForbidden)
	}
	if code := envelopeErrorCode(t, decodeEnvelope(t, stdout)); code != "MANAGEMENT_WRITE_NOT_EXPOSED" {
		t.Fatalf("错误码 = %s", code)
	}
}

// TestRoleAndAppReadCommands 验证角色/应用只读命令与写拒绝。
func TestRoleAndAppReadCommands(t *testing.T) {
	fixture := newDomainFixture(t)
	stdout, _, exit := runCLI(t, "role", "list", "--operator", "local-admin",
		"--config", fixture.configPath, "--json")
	if exit != ExitOK {
		t.Fatalf("role list 退出码 = %d", exit)
	}
	if len(decodeEnvelope(t, stdout)["data"].(map[string]any)["roles"].([]any)) != 1 {
		t.Fatalf("角色列表 = %s", stdout)
	}
	if _, _, exit := runCLI(t, "role", "permissions", fixture.roleID, "--operator",
		"local-admin", "--config", fixture.configPath, "--json"); exit != ExitOK {
		t.Fatalf("role permissions 退出码 = %d", exit)
	}
	stdout, _, exit = runCLI(t, "app", "list", "--operator", "local-admin",
		"--config", fixture.configPath, "--json")
	if exit != ExitOK {
		t.Fatalf("app list 退出码 = %d", exit)
	}
	if len(decodeEnvelope(t, stdout)["data"].(map[string]any)["applications"].([]any)) != 1 {
		t.Fatalf("应用列表 = %s", stdout)
	}
	if _, _, exit := runCLI(t, "app", "get", fixture.appID, "--operator", "local-admin",
		"--config", fixture.configPath, "--json"); exit != ExitOK {
		t.Fatalf("app get 退出码 = %d", exit)
	}
	// 角色分配/应用启停等写动作明确拒绝。
	stdout, _, exit = runCLI(t, "role", "assign", fixture.roleID, "--operator",
		"local-admin", "--config", fixture.configPath, "--json")
	if exit != ExitForbidden {
		t.Fatalf("角色分配退出码 = %d，期望 %d", exit, ExitForbidden)
	}
	if code := envelopeErrorCode(t, decodeEnvelope(t, stdout)); code != "MANAGEMENT_WRITE_NOT_EXPOSED" {
		t.Fatalf("错误码 = %s", code)
	}
}

// TestPermissionCatalogAndNotify 验证权限目录只读与通知状态/禁止真实外发。
func TestPermissionCatalogAndNotify(t *testing.T) {
	stdout, _, exit := runCLI(t, "permission", "list", "--json")
	if exit != ExitOK {
		t.Fatalf("permission list 退出码 = %d", exit)
	}
	data := decodeEnvelope(t, stdout)["data"].(map[string]any)
	permissions, _ := data["permissions"].([]any)
	found := false
	for _, raw := range permissions {
		if raw.(map[string]any)["key"] == "users.read" {
			found = true
		}
	}
	if !found {
		t.Fatal("权限目录缺少 users.read")
	}
	stdout, _, exit = runCLI(t, "notify", "status", "--json")
	if exit != ExitError {
		t.Fatalf("notify status 退出码 = %d，期望 %d", exit, ExitError)
	}
	if code := envelopeErrorCode(t, decodeEnvelope(t, stdout)); code != "NOTIFICATION_UNAVAILABLE" {
		t.Fatalf("错误码 = %s", code)
	}
	stdout, _, exit = runCLI(t, "notify", "test", "--to", "someone@example.test", "--json")
	if exit != ExitForbidden {
		t.Fatalf("notify test 退出码 = %d，期望 %d", exit, ExitForbidden)
	}
	if code := envelopeErrorCode(t, decodeEnvelope(t, stdout)); code != "NOTIFICATION_TEST_DISABLED" {
		t.Fatalf("错误码 = %s", code)
	}
}
