package serverapp

// 步骤 252（阶段1）生产授权适配层的 root 语义定向测试：
//   - permissionChecker 不再对 root 无条件 Allowed=true；root 与普通主体一样经
//     internal/authz 内核判定：只读预设目录已实现权限（任意有效 scope）+ DB 中已启用
//     的自定义/应用范围权限。
//   - 全新空库（permissions 表为空，模拟 preset.Install 未接线的真实启动状态）root
//     仍可管理：check/pageAction/EffectivePermissions 一致允许目录已实现权限；
//     显式停用权限（DB enabled=0）覆盖目录默认 → 拒绝；未实现权限 → 拒绝；未知权限
//     → PERMISSION_UNKNOWN；目录/存储依赖失败 → fail-closed。
//   - 「同一权限在多入口结果一致」：checker.Check / checker.check / checker.evaluate /
//     checker.authorizePageAction / checker.EffectivePermissions 采用同一内核结论。

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	authzsqlite "github.com/kagurazakayashi/EvernightLogin/internal/authz/sqlite"
	bootstrapsqlite "github.com/kagurazakayashi/EvernightLogin/internal/bootstrap/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const (
	rootSemanticsRootID     = "usr_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"
	rootSemanticsOrdinaryID = "usr_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb2"
	rootSemanticsAppID      = "app_ccccccccccccccccccccccccccccccc3"
)

// rootTestCatalog 是可控的只读实现目录，用于覆盖停用/未实现/未知组合。
type rootTestCatalog struct {
	implemented map[string]bool
	rootOnly    map[string]bool
}

// IsImplemented 实现 authz.PermissionCatalog。
func (c rootTestCatalog) IsImplemented(key string) (bool, bool) {
	implemented, known := c.implemented[key]
	return implemented, known
}

// ImplementedPermissions 实现 authz.PermissionCatalog（稳定排序）。
func (c rootTestCatalog) ImplementedPermissions() []authz.CatalogPermission {
	keys := make([]string, 0, len(c.implemented))
	for key, implemented := range c.implemented {
		if implemented {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	permissions := make([]authz.CatalogPermission, 0, len(keys))
	for _, key := range keys {
		permissions = append(permissions, authz.CatalogPermission{
			Key: key, Name: key, RootOnly: c.rootOnly[key]})
	}
	return permissions
}

// ImplementedPermission 实现 authz.PermissionCatalog。
func (c rootTestCatalog) ImplementedPermission(key string) (authz.CatalogPermission, bool) {
	if !c.implemented[key] {
		return authz.CatalogPermission{}, false
	}
	return authz.CatalogPermission{Key: key, Name: key, RootOnly: c.rootOnly[key]}, true
}

// rootSemanticsEnv 是适配层测试环境（真实 SQLite + 真实 authz 内核 + 生产适配器）。
type rootSemanticsEnv struct {
	t       *testing.T
	ctx     context.Context
	raw     *storagesqlite.Store
	access  *authz.Service
	checker *permissionChecker
	roots   *hostRootChecker
}

// newRootSemanticsEnv 打开真实临时库（迁移后 permissions 表为空），插入 root/普通
// 用户与一个启用应用；catalog 为 nil 时使用生产预设目录适配器。
func newRootSemanticsEnv(t *testing.T, catalog authz.PermissionCatalog) *rootSemanticsEnv {
	t.Helper()
	ctx := context.Background()
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(
		filepath.Join(testutil.TempDir(t), "root-semantics.sqlite")))
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
	nowMS := time.Now().UTC().UnixMilli()
	insertUser := func(userID, username string, isRoot int) {
		if _, err := raw.DB().ExecContext(ctx, `INSERT INTO users(
id,username,username_normalized,status,is_root,security_version,row_version,
created_at_ms,updated_at_ms) VALUES(?,?,?,'active',?,2,1,?,?)`,
			userID, username, username, isRoot, nowMS, nowMS); err != nil {
			t.Fatalf("插入用户 %s 失败: %v", username, err)
		}
	}
	insertUser(rootSemanticsRootID, "root", 1)
	insertUser(rootSemanticsOrdinaryID, "ordinary", 0)
	if _, err := raw.DB().ExecContext(ctx, `INSERT INTO applications(
id,name,description,status,client_type,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'active','confidential',1,?,?)`,
		rootSemanticsAppID, "root 语义应用", "", nowMS, nowMS); err != nil {
		t.Fatalf("插入应用失败: %v", err)
	}
	if _, err := raw.DB().ExecContext(ctx,
		`INSERT INTO scopes(id,kind,app_id) VALUES(?,'application',?)`,
		rootSemanticsAppID, rootSemanticsAppID); err != nil {
		t.Fatalf("插入应用作用范围失败: %v", err)
	}
	if catalog == nil {
		productionCatalog, err := newPresetPermissionCatalog()
		if err != nil {
			t.Fatalf("构造生产预设目录适配器失败: %v", err)
		}
		catalog = productionCatalog
	}
	bootstrapStore, err := bootstrapsqlite.New(raw)
	if err != nil {
		t.Fatalf("构造初始化存储失败: %v", err)
	}
	roots, err := newHostRootChecker(bootstrapStore)
	if err != nil {
		t.Fatalf("构造 root 识别器失败: %v", err)
	}
	authzStore, err := authzsqlite.New(raw)
	if err != nil {
		t.Fatalf("构造授权存储失败: %v", err)
	}
	access, err := authz.New(authz.Options{Store: authzStore,
		Authorizer: selfQueryAuthorizer{roots: roots}, Catalog: catalog,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatalf("构造授权引擎失败: %v", err)
	}
	checker := newPermissionChecker(access, roots)
	return &rootSemanticsEnv{t: t, ctx: ctx, raw: raw, access: access,
		checker: checker, roots: roots}
}

// insertPermission 直接写入一条权限目录行（模拟预设安装/管理员登记）。
func (e *rootSemanticsEnv) insertPermission(scopeID, key string, enabled, rootOnly bool) {
	e.t.Helper()
	rootOnlyValue, enabledValue := 0, 0
	if rootOnly {
		rootOnlyValue = 1
	}
	if enabled {
		enabledValue = 1
	}
	nowMS := time.Now().UTC().UnixMilli()
	if _, err := e.raw.DB().ExecContext(e.ctx, `INSERT INTO permissions(
id,scope_id,permission_key,name,description,limits_text,is_builtin,root_only,enabled,
created_at_ms,updated_at_ms) VALUES(?,?,?,?,'','',1,?,?,?,?)`,
		fmt.Sprintf("perm_%032x", nowMS+int64(len(key))), scopeID, key, key,
		rootOnlyValue, enabledValue, nowMS, nowMS); err != nil {
		e.t.Fatalf("插入权限 %s 失败: %v", key, err)
	}
}

// rootCaller 返回真实 root 的授权调用者。
func (e *rootSemanticsEnv) rootCaller() authz.Caller {
	e.t.Helper()
	caller, err := authz.UserCaller(rootSemanticsRootID)
	if err != nil {
		e.t.Fatalf("构造 root 调用者失败: %v", err)
	}
	return caller
}

// pageActionForPermission 返回映射到指定权限键的页面动作名；无映射时返回空串
// （部分权限没有页面动作入口，页面入口一致性断言只覆盖有映射的权限）。
func pageActionForPermission(permissionKey string) string {
	actions := make([]string, 0, len(pageActionPermissions))
	for action := range pageActionPermissions {
		actions = append(actions, action)
	}
	sort.Strings(actions)
	for _, action := range actions {
		if pageActionPermissions[action] == permissionKey {
			return action
		}
	}
	return ""
}

// assertEntries 断言同一权限在多个入口得到一致结论；allowed 表示期望允许。
func (e *rootSemanticsEnv) assertEntries(key, scopeID string, allowed bool) {
	e.t.Helper()
	rootCaller := e.rootCaller()
	checkResult, err := e.checker.Check(e.ctx, rootCaller, authz.CheckRequest{
		SubjectUserID: rootSemanticsRootID, ScopeID: scopeID,
		Permissions: []string{key}, Mode: authz.ModeAll})
	if err != nil {
		e.t.Fatalf("%s: checker.Check 返回错误: %v", key, err)
	}
	checkErr := e.checker.check(e.ctx, rootSemanticsRootID, key, scopeID)
	allowedByEvaluate, evaluateErr := e.checker.evaluate(e.ctx,
		rootSemanticsRootID, key, scopeID)
	effective, err := e.access.EffectivePermissions(e.ctx, rootCaller,
		rootSemanticsRootID, scopeID, authz.ListOptions{Limit: authz.MaxListLimit})
	if err != nil {
		e.t.Fatalf("%s: EffectivePermissions 返回错误: %v", key, err)
	}
	present := false
	for _, permission := range effective.Permissions {
		if permission.Key == key {
			present = true
			if len(permission.Sources) != 1 ||
				permission.Sources[0].Kind != authz.SourceKindRoot ||
				!permission.Sources[0].Included {
				e.t.Fatalf("%s: root 来源说明异常: %+v", key, permission.Sources)
			}
		}
	}
	if checkResult.Allowed != allowed {
		e.t.Fatalf("%s: checker.Check Allowed=%v，期望 %v（%+v）",
			key, checkResult.Allowed, allowed, checkResult)
	}
	if (checkErr == nil) != allowed {
		e.t.Fatalf("%s: checker.check err=%v，期望 allowed=%v", key, checkErr, allowed)
	}
	if evaluateErr != nil || allowedByEvaluate != allowed {
		e.t.Fatalf("%s: checker.evaluate=%v err=%v，期望 %v",
			key, allowedByEvaluate, evaluateErr, allowed)
	}
	if action := pageActionForPermission(key); action != "" {
		actionErr := e.checker.authorizePageActionScoped(e.ctx, rootSemanticsRootID,
			action, scopeID)
		if (actionErr == nil) != allowed {
			e.t.Fatalf("%s: pageAction(%s) err=%v，期望 allowed=%v",
				key, action, actionErr, allowed)
		}
	}
	if present != allowed {
		e.t.Fatalf("%s: EffectivePermissions 包含=%v，期望 %v", key, present, allowed)
	}
	if !allowed && checkResult.Code == "" {
		e.t.Fatalf("%s: 拒绝决策缺少稳定码: %+v", key, checkResult)
	}
}

// TestRootSemanticsAdapterConsistency 验证适配层各入口对 root 结论一致，且停用/
// 未实现/未知权限不会被无条件放行（覆盖 Lead 要求的空库可管理 + DB 覆盖 + 拒绝矩阵）。
func TestRootSemanticsAdapterConsistency(t *testing.T) {
	catalog := rootTestCatalog{
		implemented: map[string]bool{
			"users.read":                  true,
			"roles.read":                  true,
			"security.policy.manage":      true,
			"applications.members.manage": true,
			// 目录登记但业务未实现。
			"users.password.reset.other": false,
		},
		rootOnly: map[string]bool{"security.policy.manage": true},
	}
	env := newRootSemanticsEnv(t, catalog)

	// 全新空库（permissions 表为空）：root 仍可管理目录已实现权限。
	env.assertEntries("users.read", "system", true)
	env.assertEntries("security.policy.manage", "system", true)
	// 应用作用域无需成员关系/预置权限行即可管理（避免鸡生蛋）。
	env.assertEntries("applications.members.manage", rootSemanticsAppID, true)

	// 未知权限：所有入口一致拒绝且为 PERMISSION_UNKNOWN。
	env.assertEntries("never.registered.permission", "system", false)
	unknownCheck, err := env.checker.Check(env.ctx, env.rootCaller(), authz.CheckRequest{
		SubjectUserID: rootSemanticsRootID, ScopeID: "system",
		Permissions: []string{"never.registered.permission"}, Mode: authz.ModeAll})
	if err != nil || unknownCheck.Allowed ||
		unknownCheck.Code != authz.CodePermissionUnknown {
		t.Fatalf("root 未知权限应 PERMISSION_UNKNOWN: %+v err=%v", unknownCheck, err)
	}

	// 未实现权限：DB 已启用行也不能让 root 使用，Effective 排除且原因明确。
	env.insertPermission("system", "users.password.reset.other", true, false)
	env.assertEntries("users.password.reset.other", "system", false)
	notImplemented, err := env.checker.Check(env.ctx, env.rootCaller(), authz.CheckRequest{
		SubjectUserID: rootSemanticsRootID, ScopeID: "system",
		Permissions: []string{"users.password.reset.other"}, Mode: authz.ModeAll})
	if err != nil || notImplemented.Allowed ||
		notImplemented.Code != authz.CodeAccessDenied ||
		notImplemented.Reason != "permission_not_implemented" {
		t.Fatalf("root 未实现权限应拒绝: %+v err=%v", notImplemented, err)
	}

	// DB 显式停用覆盖目录默认：所有入口一致拒绝为 PERMISSION_DISABLED。
	env.insertPermission("system", "users.read", false, false)
	env.assertEntries("users.read", "system", false)
	disabled, err := env.checker.Check(env.ctx, env.rootCaller(), authz.CheckRequest{
		SubjectUserID: rootSemanticsRootID, ScopeID: "system",
		Permissions: []string{"users.read"}, Mode: authz.ModeAll})
	if err != nil || disabled.Allowed || disabled.Code != authz.CodePermissionDisabled {
		t.Fatalf("root 停用权限应 PERMISSION_DISABLED: %+v err=%v", disabled, err)
	}

	// 恢复启用后立即允许（不缓存旧结论）。
	if _, err := env.raw.DB().ExecContext(env.ctx,
		`UPDATE permissions SET enabled=1 WHERE scope_id='system' AND permission_key='users.read'`); err != nil {
		t.Fatalf("恢复启用权限失败: %v", err)
	}
	env.assertEntries("users.read", "system", true)

	// 管理范围：root 在有效范围返回“全部”，但仍以内核读权限为准。
	all, _, err := env.checker.manageableScopes(env.ctx,
		audit.Actor{Type: audit.ActorUser, ID: rootSemanticsRootID}, "roles.read")
	if err != nil || !all {
		t.Fatalf("root 管理范围 = %v err=%v，期望全部", all, err)
	}
	pageScopes, err := env.checker.pageManageableScopes(env.ctx, rootSemanticsRootID)
	if err != nil || len(pageScopes) != 1 || pageScopes[0] != "system" {
		t.Fatalf("root 页面管理范围 = %v err=%v", pageScopes, err)
	}
	env.insertPermission("system", "applications.read", false, false)
	if _, _, err := env.checker.manageableScopes(env.ctx,
		audit.Actor{Type: audit.ActorUser, ID: rootSemanticsRootID}, "applications.read"); err == nil {
		t.Fatal("root 读取权限被停用时管理范围必须拒绝")
	}
}

// TestRootSemanticsProductionCatalogFreshDatabase 验证生产预设目录适配器在全新空库
// 上让 root 立即可用，且未实现目录项不会出现（不依赖 preset.Install 接线）。
func TestRootSemanticsProductionCatalogFreshDatabase(t *testing.T) {
	env := newRootSemanticsEnv(t, nil)
	env.assertEntries("users.read", "system", true)
	env.assertEntries("roles.read", "system", true)
	env.assertEntries("security.policy.manage", "system", true)
	env.assertEntries("applications.members.manage", rootSemanticsAppID, true)

	// 生产目录中仍标记未实现的权限（254 新增直接管理权限等）在空库上也不可用。
	adapter, err := newPresetPermissionCatalog()
	if err != nil {
		t.Fatalf("构造生产目录失败: %v", err)
	}
	unimplementedKey := ""
	for key, implemented := range adapter.implemented {
		if !implemented {
			unimplementedKey = key
			break
		}
	}
	if unimplementedKey == "" {
		// 若后续步骤把全部目录权限实现，则本断言自动跳过（不是产品缺陷）。
		t.Log("生产预设目录当前无未实现权限，跳过未实现拒绝断言")
		return
	}
	env.insertPermission("system", unimplementedKey, true, false)
	env.assertEntries(unimplementedKey, "system", false)
}

// TestRootSemanticsProductionCatalogUnimplemented 验证生产目录中未实现的权限键
// 即使数据库有启用行也不能被 root 使用（不把 root 全权限实现为一律放行）。
func TestRootSemanticsProductionCatalogUnimplemented(t *testing.T) {
	adapter, err := newPresetPermissionCatalog()
	if err != nil {
		t.Fatalf("构造生产目录失败: %v", err)
	}
	unimplementedKey := ""
	for key, implemented := range adapter.implemented {
		if !implemented {
			unimplementedKey = key
			break
		}
	}
	if unimplementedKey == "" {
		t.Skip("生产预设目录当前无未实现权限；未实现拒绝矩阵由 kernel/适配层测试目录覆盖")
	}
	env := newRootSemanticsEnv(t, adapter)
	env.insertPermission("system", unimplementedKey, true, false)
	env.assertEntries(unimplementedKey, "system", false)
	result, err := env.checker.Check(env.ctx, env.rootCaller(), authz.CheckRequest{
		SubjectUserID: rootSemanticsRootID, ScopeID: "system",
		Permissions: []string{unimplementedKey}, Mode: authz.ModeAll})
	if err != nil || result.Allowed || result.Code != authz.CodeAccessDenied ||
		result.Reason != "permission_not_implemented" {
		t.Fatalf("生产目录未实现权限应拒绝: %+v err=%v", result, err)
	}
}

// TestRootSemanticsFailClosedOnStoreError 验证存储依赖失败时适配层 fail-closed。
func TestRootSemanticsFailClosedOnStoreError(t *testing.T) {
	env := newRootSemanticsEnv(t, rootTestCatalog{
		implemented: map[string]bool{"users.read": true}})
	if err := env.raw.Close(); err != nil {
		t.Fatalf("关闭存储失败: %v", err)
	}
	result, err := env.checker.Check(env.ctx, env.rootCaller(), authz.CheckRequest{
		SubjectUserID: rootSemanticsRootID, ScopeID: "system",
		Permissions: []string{"users.read"}, Mode: authz.ModeAll})
	if err != nil {
		t.Fatalf("依赖失败应是拒绝决策而非内部错误: %v", err)
	}
	if result.Allowed || result.Code != authz.CodeAuthzUnavailable {
		t.Fatalf("依赖失败时 root 检查必须 fail-closed: %+v", result)
	}
	if err := env.checker.check(env.ctx, rootSemanticsRootID, "users.read", "system"); err == nil {
		t.Fatal("依赖失败时 check 必须返回错误")
	}
	if _, err := env.access.EffectivePermissions(env.ctx, env.rootCaller(),
		rootSemanticsRootID, "system", authz.ListOptions{}); !errors.Is(err, authz.ErrStoreUnavailable) {
		t.Fatalf("依赖失败时有效权限应返回 ErrStoreUnavailable: %v", err)
	}
}
