package permission_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
	"github.com/kagurazakayashi/EvernightLogin/internal/permission"
	permissionsqlite "github.com/kagurazakayashi/EvernightLogin/internal/permission/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const (
	appOne = "app_00000000000000000000000000000001"
	appTwo = "app_00000000000000000000000000000002"
	appOff = "app_00000000000000000000000000000003"

	adminOne = "usr_00000000000000000000000000000010"
	adminTwo = "usr_00000000000000000000000000000011"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(duration)
}

type testEnv struct {
	t          *testing.T
	raw        *storagesqlite.Store
	store      *permissionsqlite.Store
	auditStore *auditsqlite.Store
	recorder   *audit.Recorder
	service    *permission.Service
	authorizer *permission.StaticAuthorizer
	clock      *fakeClock
	system     permission.Caller
	local      permission.Caller
}

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

func prepareEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(filepath.Join(t.TempDir(), "permission.sqlite")))
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
	store, err := permissionsqlite.New(raw)
	if err != nil {
		t.Fatalf("构造权限仓储失败: %v", err)
	}
	auditStore, err := auditsqlite.New(raw)
	if err != nil {
		t.Fatalf("构造审计仓储失败: %v", err)
	}
	clock := &fakeClock{now: time.Date(2026, 11, 15, 16, 0, 0, 0, time.UTC)}
	recorder, err := audit.New(auditStore, audit.Options{Now: clock.Now})
	if err != nil {
		t.Fatalf("构造审计写入器失败: %v", err)
	}
	authorizer, err := permission.NewStaticAuthorizer(permission.AuthorizerOptions{
		LocalAdminIDs: []string{"operator-1"},
		SystemIDs:     []string{"system-1"},
	})
	if err != nil {
		t.Fatalf("构造授权器失败: %v", err)
	}
	service, err := permission.New(permission.Options{Store: store, Audit: recorder, Authorizer: authorizer,
		Transfers: allowAllTransfers(), Now: clock.Now,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatalf("构造权限服务失败: %v", err)
	}
	system, err := permission.SystemCaller("system-1")
	if err != nil {
		t.Fatalf("构造系统调用者失败: %v", err)
	}
	local, err := permission.LocalBootstrapCaller("operator-1")
	if err != nil {
		t.Fatalf("构造本地调用者失败: %v", err)
	}
	env := &testEnv{t: t, raw: raw, store: store, auditStore: auditStore, recorder: recorder,
		service: service, authorizer: authorizer, clock: clock, system: system, local: local}
	env.seedApplication(appOne, "active")
	env.seedApplication(appTwo, "active")
	env.seedApplication(appOff, "disabled")
	if err := authorizer.AssignApplicationAdmin(appOne, adminOne); err != nil {
		t.Fatalf("分配应用管理员失败: %v", err)
	}
	return env
}

func (e *testEnv) seedApplication(appID, status string) {
	e.t.Helper()
	now := e.clock.Now().UnixMilli()
	if _, err := e.raw.ExecContext(context.Background(),
		`INSERT INTO applications(id,name,description,icon_ref,homepage,owner_user_id,contact_info,status,client_type,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,'',NULL,NULL,NULL,NULL,?,'public',1,?,?)`, appID, appID, status, now, now); err != nil {
		e.t.Fatalf("插入测试应用失败: %v", err)
	}
	if _, err := e.raw.ExecContext(context.Background(),
		`INSERT INTO scopes(id,kind,app_id) VALUES(?,'application',?)`, appID, appID); err != nil {
		e.t.Fatalf("插入应用 scope 失败: %v", err)
	}
}

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

func (e *testEnv) createSystemPermission(key string, builtin, rootOnly bool) permission.Permission {
	e.t.Helper()
	record, err := e.service.CreatePermission(context.Background(), e.system, permission.CreateRequest{
		ScopeID: permission.ScopeSystem, Key: key, Name: "系统权限 " + key,
		Description: "说明 " + key, Limits: "限制 " + key, IsBuiltin: builtin, RootOnly: rootOnly,
	})
	if err != nil {
		e.t.Fatalf("创建系统权限失败: %v", err)
	}
	return record
}

func TestCreatePermissionCategoriesAndDefinition(t *testing.T) {
	env := prepareEnv(t)
	builtin := env.createSystemPermission("users.read", true, false)
	if builtin.ScopeKind != permission.ScopeKindSystem || builtin.ApplicationID != "" ||
		!builtin.IsBuiltin || builtin.RootOnly || !builtin.Enabled {
		t.Fatalf("系统内置权限 = %+v", builtin)
	}
	definition := builtin.Definition()
	if definition.Key != "users.read" || definition.Group != "users" || definition.ScopeKind != permission.ScopeKindSystem ||
		definition.Target != "system" || !definition.Builtin || definition.Sensitive || !definition.DefaultEnabled ||
		!definition.Enabled || definition.Name == "" || definition.Description == "" || definition.Limits == "" {
		t.Fatalf("机器可读定义不完整: %+v", definition)
	}
	custom := env.createSystemPermission("reports.custom.read", false, false)
	if custom.IsBuiltin || custom.Group != "reports" {
		t.Fatalf("系统自定义权限 = %+v", custom)
	}
	// 应用管理员创建本应用权限；同 key 可跨应用/跨 scope 存在。
	appAdmin, err := permission.UserCaller(adminOne)
	if err != nil {
		t.Fatal(err)
	}
	appPermission, err := env.service.CreatePermission(context.Background(), appAdmin, permission.CreateRequest{
		ScopeID: appOne, Key: "users.read", Name: "应用一读取用户", Description: "仅应用一", Limits: "仅应用一成员",
	})
	if err != nil {
		t.Fatalf("应用管理员创建应用权限失败: %v", err)
	}
	if appPermission.ScopeKind != permission.ScopeKindApplication || appPermission.ApplicationID != appOne ||
		appPermission.ScopeID != appOne || appPermission.IsBuiltin || !appPermission.Enabled {
		t.Fatalf("应用权限 = %+v", appPermission)
	}
	appDefinition := appPermission.Definition()
	if appDefinition.Target != "application:"+appOne || appDefinition.ScopeKind != permission.ScopeKindApplication {
		t.Fatalf("应用权限定义 = %+v", appDefinition)
	}
	if _, err := env.service.CreatePermission(context.Background(), env.system, permission.CreateRequest{
		ScopeID: appTwo, Key: "users.read", Name: "应用二读取用户", Description: "仅应用二", Limits: "仅应用二成员",
	}); err != nil {
		t.Fatalf("跨应用同名标识应允许: %v", err)
	}

	// 应用管理员不能创建系统权限或 builtin/root_only 应用权限。
	if _, err := env.service.CreatePermission(context.Background(), appAdmin, permission.CreateRequest{
		ScopeID: permission.ScopeSystem, Key: "users.delete", Name: "系统删除", Description: "说明", Limits: "限制",
	}); !errors.Is(err, permission.ErrAccessDenied) {
		t.Fatalf("应用管理员创建系统权限错误 = %v", err)
	}
	if _, err := env.service.CreatePermission(context.Background(), appAdmin, permission.CreateRequest{
		ScopeID: appOne, Key: "users.builtin", Name: "应用内置", Description: "说明", Limits: "限制", IsBuiltin: true,
	}); !errors.Is(err, permission.ErrAccessDenied) {
		t.Fatalf("应用创建 builtin 错误 = %v", err)
	}
	if _, err := env.service.CreatePermission(context.Background(), appAdmin, permission.CreateRequest{
		ScopeID: appOne, Key: "users.rootonly", Name: "应用 root", Description: "说明", Limits: "限制", RootOnly: true,
	}); !errors.Is(err, permission.ErrInvalidRequest) {
		t.Fatalf("应用创建 root_only 错误 = %v", err)
	}
	if _, err := env.service.CreatePermission(context.Background(), env.system, permission.CreateRequest{
		ScopeID: appOff, Key: "reports.read", Name: "停用应用权限", Description: "说明", Limits: "限制",
	}); !errors.Is(err, permission.ErrApplicationInactive) {
		t.Fatalf("停用应用创建权限错误 = %v", err)
	}
	if value := permission.CodeOf(permission.ErrApplicationInactive); value != permission.CodeClientDisabled {
		t.Errorf("应用停用错误码 = %q", value)
	}
}

func TestCreateValidation(t *testing.T) {
	env := prepareEnv(t)
	cases := []struct {
		name    string
		request permission.CreateRequest
	}{
		{name: "空 key", request: permission.CreateRequest{ScopeID: permission.ScopeSystem, Key: "", Name: "名", Description: "说明", Limits: "限制"}},
		{name: "key 无分段", request: permission.CreateRequest{ScopeID: permission.ScopeSystem, Key: "usersread", Name: "名", Description: "说明", Limits: "限制"}},
		{name: "key 大写", request: permission.CreateRequest{ScopeID: permission.ScopeSystem, Key: "Users.read", Name: "名", Description: "说明", Limits: "限制"}},
		{name: "key 非法字符", request: permission.CreateRequest{ScopeID: permission.ScopeSystem, Key: "users.re-ad", Name: "名", Description: "说明", Limits: "限制"}},
		{name: "空名称", request: permission.CreateRequest{ScopeID: permission.ScopeSystem, Key: "users.read", Name: " ", Description: "说明", Limits: "限制"}},
		{name: "名称过长", request: permission.CreateRequest{ScopeID: permission.ScopeSystem, Key: "users.read", Name: strings.Repeat("名", permission.MaxNameRunes+1), Description: "说明", Limits: "限制"}},
		{name: "空说明", request: permission.CreateRequest{ScopeID: permission.ScopeSystem, Key: "users.read", Name: "名", Description: " ", Limits: "限制"}},
		{name: "空限制", request: permission.CreateRequest{ScopeID: permission.ScopeSystem, Key: "users.read", Name: "名", Description: "说明", Limits: " "}},
		{name: "限制过长", request: permission.CreateRequest{ScopeID: permission.ScopeSystem, Key: "users.read", Name: "名", Description: "说明", Limits: strings.Repeat("限", permission.MaxLimitsRunes+1)}},
		{name: "非法 scope", request: permission.CreateRequest{ScopeID: "not-a-scope", Key: "users.read", Name: "名", Description: "说明", Limits: "限制"}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := env.service.CreatePermission(context.Background(), env.system, test.request)
			if test.request.ScopeID == "not-a-scope" {
				if !errors.Is(err, permission.ErrAccessDenied) {
					t.Fatalf("非法 scope 错误 = %v", err)
				}
				return
			}
			if !errors.Is(err, permission.ErrInvalidRequest) {
				t.Fatalf("错误 = %v，期望 ErrInvalidRequest", err)
			}
		})
	}
}

func TestBuiltinProtectionAndRootOnly(t *testing.T) {
	env := prepareEnv(t)
	builtin := env.createSystemPermission("users.disable", true, false)
	if _, err := env.service.UpdatePermission(context.Background(), env.system, builtin.ID,
		permission.UpdateRequest{Name: "改内置", Description: "改", Limits: "改"}); !errors.Is(err, permission.ErrBuiltinProtected) {
		t.Fatalf("修改内置权限错误 = %v", err)
	}
	if err := env.service.DeletePermission(context.Background(), env.system, builtin.ID); !errors.Is(err, permission.ErrBuiltinProtected) {
		t.Fatalf("删除内置权限错误 = %v", err)
	}
	// 内置权限可停用/启用，重复请求幂等。
	disabled, changed, err := env.service.DisablePermission(context.Background(), env.system, builtin.ID)
	if err != nil || !changed || disabled.Enabled {
		t.Fatalf("停用内置权限 = %+v, changed=%v, err=%v", disabled, changed, err)
	}
	if again, changed, err := env.service.DisablePermission(context.Background(), env.system, builtin.ID); err != nil || changed || again.Enabled {
		t.Fatalf("重复停用应幂等: %+v, changed=%v, err=%v", again, changed, err)
	}
	if enabled, changed, err := env.service.EnablePermission(context.Background(), env.system, builtin.ID); err != nil || !changed || !enabled.Enabled {
		t.Fatalf("启用内置权限 = %+v, changed=%v, err=%v", enabled, changed, err)
	}

	// root_only 敏感权限（内置或自定义）只能由本地初始化操作者启停。
	rootOnly := env.createSystemPermission("backups.export", true, true)
	if !rootOnly.RootOnly {
		t.Fatal("root_only 未生效")
	}
	if _, _, err := env.service.DisablePermission(context.Background(), env.system, rootOnly.ID); !errors.Is(err, permission.ErrAccessDenied) {
		t.Fatalf("系统操作者停用 root_only 错误 = %v", err)
	}
	if disabled, changed, err := env.service.DisablePermission(context.Background(), env.local, rootOnly.ID); err != nil || !changed || disabled.Enabled {
		t.Fatalf("本地操作者停用 root_only = %+v, changed=%v, err=%v", disabled, changed, err)
	}
	// 内置权限审计保留。
	if value := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE target_id=? AND action IN ('permission.create','permission.disable','permission.enable')`, builtin.ID); value < 4 {
		t.Errorf("内置权限审计数量 = %d", value)
	}
}

func TestCrossScopeIsolationAndList(t *testing.T) {
	env := prepareEnv(t)
	builtin := env.createSystemPermission("users.read", true, false)
	appAdmin, err := permission.UserCaller(adminOne)
	if err != nil {
		t.Fatal(err)
	}
	appOnePermission, err := env.service.CreatePermission(context.Background(), appAdmin, permission.CreateRequest{
		ScopeID: appOne, Key: "reports.read", Name: "应用一报表", Description: "应用一", Limits: "应用一成员",
	})
	if err != nil {
		t.Fatalf("应用一创建权限失败: %v", err)
	}
	appTwoPermission, err := env.service.CreatePermission(context.Background(), env.system, permission.CreateRequest{
		ScopeID: appTwo, Key: "reports.read", Name: "应用二报表", Description: "应用二", Limits: "应用二成员",
	})
	if err != nil {
		t.Fatalf("应用二创建同名权限失败: %v", err)
	}
	// 应用管理员不能读取/更新/删除其他应用或系统权限。
	if _, err := env.service.GetPermission(context.Background(), appAdmin, appTwoPermission.ID); !errors.Is(err, permission.ErrAccessDenied) {
		t.Fatalf("跨应用读取错误 = %v", err)
	}
	if _, err := env.service.UpdatePermission(context.Background(), appAdmin, appTwoPermission.ID,
		permission.UpdateRequest{Name: "越权", Description: "越权", Limits: "越权"}); !errors.Is(err, permission.ErrAccessDenied) {
		t.Fatalf("跨应用更新错误 = %v", err)
	}
	if err := env.service.DeletePermission(context.Background(), appAdmin, appTwoPermission.ID); !errors.Is(err, permission.ErrAccessDenied) {
		t.Fatalf("跨应用删除错误 = %v", err)
	}
	if _, err := env.service.GetPermission(context.Background(), appAdmin, builtin.ID); !errors.Is(err, permission.ErrAccessDenied) {
		t.Fatalf("应用管理员读取系统权限错误 = %v", err)
	}
	// 默认列表范围：应用管理员只看到分配应用；系统操作者看到全部。
	appScoped, err := env.service.ListPermissions(context.Background(), appAdmin, permission.ListRequest{})
	if err != nil {
		t.Fatalf("应用管理员默认列表失败: %v", err)
	}
	if len(appScoped.Permissions) != 1 || appScoped.Permissions[0].ID != appOnePermission.ID {
		t.Fatalf("应用管理员列表 = %+v", appScoped.Permissions)
	}
	all, err := env.service.ListPermissions(context.Background(), env.system, permission.ListRequest{Limit: 2})
	if err != nil || len(all.Permissions) != 2 || !all.HasMore {
		t.Fatalf("系统分页列表 = %+v, hasMore=%v, err=%v", all.Permissions, all.HasMore, err)
	}
	if _, err := env.service.ListPermissions(context.Background(), appAdmin, permission.ListRequest{ScopeID: appTwo}); !errors.Is(err, permission.ErrAccessDenied) {
		t.Fatalf("应用管理员过滤其他应用错误 = %v", err)
	}
	if result, err := env.service.ListPermissions(context.Background(), appAdmin, permission.ListRequest{ScopeID: appOne}); err != nil || len(result.Permissions) != 1 {
		t.Fatalf("应用管理员过滤本应用 = %+v, %v", result.Permissions, err)
	}
	// 启用状态过滤。
	enabled := true
	onlyEnabled, err := env.service.ListPermissions(context.Background(), env.system, permission.ListRequest{Enabled: &enabled, Limit: 10})
	if err != nil || len(onlyEnabled.Permissions) != 3 {
		t.Fatalf("enabled 过滤 = %+v, %v", onlyEnabled.Permissions, err)
	}
}

func TestUpdateStateAndDeleteReferences(t *testing.T) {
	env := prepareEnv(t)
	custom, err := env.service.CreatePermission(context.Background(), env.system, permission.CreateRequest{
		ScopeID: permission.ScopeSystem, Key: "reports.custom.download", Name: "报表下载", Description: "下载报表", Limits: "仅授权用户",
	})
	if err != nil {
		t.Fatalf("创建自定义权限失败: %v", err)
	}
	updated, err := env.service.UpdatePermission(context.Background(), env.system, custom.ID,
		permission.UpdateRequest{Name: "报表导出", Description: "导出报表", Limits: "仅审计员"})
	if err != nil {
		t.Fatalf("更新自定义权限失败: %v", err)
	}
	if updated.Key != custom.Key || updated.ScopeID != custom.ScopeID || updated.Name != "报表导出" {
		t.Fatalf("更新结果 = %+v", updated)
	}
	if value := env.queryInt(`SELECT COUNT(*) FROM permissions WHERE id=? AND permission_key=? AND scope_id=?`,
		custom.ID, custom.Key, custom.ScopeID); value != 1 {
		t.Error("更新改变了 key/scope")
	}
	// 启停幂等与状态可见。
	if disabled, changed, err := env.service.DisablePermission(context.Background(), env.system, custom.ID); err != nil || !changed || disabled.Enabled {
		t.Fatalf("停用自定义权限 = %+v, %v", disabled, err)
	}
	if _, changed, err := env.service.DisablePermission(context.Background(), env.system, custom.ID); err != nil || changed {
		t.Fatalf("重复停用应幂等: changed=%v, err=%v", changed, err)
	}
	if enabled, changed, err := env.service.EnablePermission(context.Background(), env.system, custom.ID); err != nil || !changed || !enabled.Enabled {
		t.Fatalf("启用自定义权限 = %+v, %v", enabled, err)
	}
	// 被角色引用时拒绝删除。
	now := env.clock.Now().UnixMilli()
	if _, err := env.raw.ExecContext(context.Background(),
		`INSERT INTO roles(id,scope_id,role_key,name,description,limits_text,is_builtin,enabled,created_at_ms,updated_at_ms)
VALUES('role_perm_test','system','role_perm_test','测试角色','','',0,1,?,?)`, now, now); err != nil {
		t.Fatalf("插入角色失败: %v", err)
	}
	if _, err := env.raw.ExecContext(context.Background(),
		`INSERT INTO role_permissions(role_id,permission_id,scope_id) VALUES('role_perm_test',?,? )`, custom.ID, permission.ScopeSystem); err != nil {
		t.Fatalf("插入角色权限引用失败: %v", err)
	}
	if err := env.service.DeletePermission(context.Background(), env.system, custom.ID); !errors.Is(err, permission.ErrPermissionInUse) {
		t.Fatalf("被引用权限删除错误 = %v", err)
	}
	if value := env.queryInt(`SELECT COUNT(*) FROM permissions WHERE id=?`, custom.ID); value != 1 {
		t.Fatal("被引用权限不应被删除")
	}
	if _, err := env.raw.ExecContext(context.Background(),
		`DELETE FROM role_permissions WHERE role_id='role_perm_test'`); err != nil {
		t.Fatalf("删除引用失败: %v", err)
	}
	if err := env.service.DeletePermission(context.Background(), env.system, custom.ID); err != nil {
		t.Fatalf("解除引用后删除失败: %v", err)
	}
	if _, err := env.service.GetPermission(context.Background(), env.system, custom.ID); !errors.Is(err, permission.ErrPermissionNotFound) {
		t.Fatalf("删除后读取错误 = %v", err)
	}
	if value := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action='permission.delete' AND outcome='success'`); value != 1 {
		t.Errorf("删除审计数量 = %d", value)
	}
}

func TestConcurrentCreateAndDuplicateKey(t *testing.T) {
	env := prepareEnv(t)
	const workers = 4
	var waitGroup sync.WaitGroup
	errorsSeen := make([]error, workers)
	for index := 0; index < workers; index++ {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			_, err := env.service.CreatePermission(context.Background(), env.system, permission.CreateRequest{
				ScopeID: permission.ScopeSystem, Key: "users.concurrent", Name: "并发权限", Description: "说明", Limits: "限制",
			})
			errorsSeen[index] = err
		}(index)
	}
	waitGroup.Wait()
	success := 0
	conflicts := 0
	for _, err := range errorsSeen {
		switch {
		case err == nil:
			success++
		case errors.Is(err, permission.ErrPermissionKeyTaken):
			conflicts++
		default:
			t.Errorf("并发创建错误 = %v", err)
		}
	}
	if success != 1 || conflicts != workers-1 {
		t.Fatalf("并发创建成功=%d 冲突=%d", success, conflicts)
	}
	if value := env.queryInt(`SELECT COUNT(*) FROM permissions WHERE permission_key='users.concurrent'`); value != 1 {
		t.Errorf("并发后权限行数 = %d", value)
	}
}

func TestAuditFailureFailClosed(t *testing.T) {
	env := prepareEnv(t)
	record := env.createSystemPermission("users.read", true, false)
	custom := env.createSystemPermission("users.custom", false, false)
	if _, err := env.raw.ExecContext(context.Background(),
		`CREATE TRIGGER fail_audit_events BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'audit unavailable'); END;`); err != nil {
		t.Fatalf("创建审计故障触发器失败: %v", err)
	}
	if _, err := env.service.CreatePermission(context.Background(), env.system, permission.CreateRequest{
		ScopeID: permission.ScopeSystem, Key: "users.fail", Name: "失败", Description: "说明", Limits: "限制",
	}); !errors.Is(err, permission.ErrAuditUnavailable) {
		t.Fatalf("审计故障创建错误 = %v", err)
	}
	if _, err := env.service.GetPermission(context.Background(), env.system, record.ID); !errors.Is(err, permission.ErrAuditUnavailable) {
		t.Fatalf("审计故障读取错误 = %v", err)
	}
	if _, err := env.service.ListPermissions(context.Background(), env.system, permission.ListRequest{}); !errors.Is(err, permission.ErrAuditUnavailable) {
		t.Fatalf("审计故障列表错误 = %v", err)
	}
	if _, err := env.service.UpdatePermission(context.Background(), env.system, custom.ID, permission.UpdateRequest{
		Name: "改名", Description: "说明", Limits: "限制",
	}); !errors.Is(err, permission.ErrAuditUnavailable) {
		t.Fatalf("审计故障更新错误 = %v", err)
	}
	if _, _, err := env.service.DisablePermission(context.Background(), env.system, custom.ID); !errors.Is(err, permission.ErrAuditUnavailable) {
		t.Fatalf("审计故障启停错误 = %v", err)
	}
	if _, err := env.raw.ExecContext(context.Background(), `DROP TRIGGER fail_audit_events`); err != nil {
		t.Fatalf("删除触发器失败: %v", err)
	}
}

func TestOptionsAuthorizationAndErrors(t *testing.T) {
	if _, err := permission.New(permission.Options{}); !errors.Is(err, permission.ErrOptionsInvalid) {
		t.Fatalf("空依赖构造错误 = %v", err)
	}
	env := prepareEnv(t)
	if _, err := env.service.CreatePermission(context.Background(), permission.Caller{}, permission.CreateRequest{
		ScopeID: permission.ScopeSystem, Key: "users.read", Name: "名", Description: "说明", Limits: "限制",
	}); !errors.Is(err, permission.ErrAccessDenied) {
		t.Fatalf("零值调用者错误 = %v", err)
	}
	if _, err := env.service.GetPermission(context.Background(), env.system, "not-a-permission-id"); !errors.Is(err, permission.ErrInvalidRequest) {
		t.Fatalf("非法权限 ID 错误 = %v", err)
	}
	if _, err := env.service.GetPermission(context.Background(), env.system, "perm_ffffffffffffffffffffffffffffffff"); !errors.Is(err, permission.ErrPermissionNotFound) {
		t.Fatalf("不存在权限错误 = %v", err)
	}
	if _, err := permission.NewStaticAuthorizer(permission.AuthorizerOptions{}); !errors.Is(err, permission.ErrOptionsInvalid) {
		t.Fatalf("空授权器配置错误 = %v", err)
	}
	if value := permission.CodeOf(permission.ErrBuiltinProtected); value != permission.CodeAccessDenied {
		t.Errorf("内置保护错误码 = %q", value)
	}
	if value := permission.CodeOf(permission.ErrPermissionInUse); value != permission.CodeConflict {
		t.Errorf("引用冲突错误码 = %q", value)
	}
}
