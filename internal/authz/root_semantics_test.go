package authz_test

// 步骤 252（阶段1）root 全权限语义定向测试：
//   - 真实 root（账户快照 is_root，来源为唯一 bootstrap 记录）在有效作用范围内拥有
//     全部「已启用且已实现」权限，不依赖角色分配/应用成员关系；root_only 权限属于
//     root 专属通道；权限来源显式标记 root。
//   - 未知权限仍 PERMISSION_UNKNOWN、停用权限 PERMISSION_DISABLED、未实现权限
//     ACCESS_DENIED + permission_not_implemented、停用/不存在应用拒绝；root 不受
//     普通账户期限限制，但账户必须 active。
//   - root 资源级数据范围按 all；非法资源标识仍 REQ_INVALID。
//   - root 作为可信调用者可查询他人（内核快照兜底复核），普通用户跨主体 Check 仍拒。
//   - 未装配实现目录时 root 判定 fail-closed（AUTHZ_UNAVAILABLE），不猜测全部已实现。

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	authzsqlite "github.com/kagurazakayashi/EvernightLogin/internal/authz/sqlite"
)

// fakeCatalogEntry 是测试目录中的一条权限定义。
type fakeCatalogEntry struct {
	implemented bool
	name        string
	rootOnly    bool
}

// fakePermissionCatalog 是测试用权限实现状态目录：known 中的键按给定实现状态
// 处理；未登记键（宿主自定义权限）IsImplemented 返回 known=false，内核按已实现处理。
type fakePermissionCatalog struct {
	mu    sync.RWMutex
	known map[string]fakeCatalogEntry
}

// newFakePermissionCatalog 从 key→implemented 映射构造测试目录（名称默认取键）。
func newFakePermissionCatalog(known map[string]bool) *fakePermissionCatalog {
	copied := make(map[string]fakeCatalogEntry, len(known))
	for key, implemented := range known {
		copied[key] = fakeCatalogEntry{implemented: implemented, name: key}
	}
	return &fakePermissionCatalog{known: copied}
}

// IsImplemented 实现 authz.PermissionCatalog。
func (c *fakePermissionCatalog) IsImplemented(key string) (bool, bool) {
	if c == nil {
		return false, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, known := c.known[key]
	return entry.implemented, known
}

// ImplementedPermissions 实现 authz.PermissionCatalog：返回已实现权限定义副本。
func (c *fakePermissionCatalog) ImplementedPermissions() []authz.CatalogPermission {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	keys := make([]string, 0, len(c.known))
	for key, entry := range c.known {
		if entry.implemented {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	permissions := make([]authz.CatalogPermission, 0, len(keys))
	for _, key := range keys {
		entry := c.known[key]
		permissions = append(permissions, authz.CatalogPermission{
			Key: key, Name: entry.name, RootOnly: entry.rootOnly})
	}
	return permissions
}

// ImplementedPermission 实现 authz.PermissionCatalog。
func (c *fakePermissionCatalog) ImplementedPermission(key string) (authz.CatalogPermission, bool) {
	if c == nil {
		return authz.CatalogPermission{}, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, known := c.known[key]
	if !known || !entry.implemented {
		return authz.CatalogPermission{}, false
	}
	return authz.CatalogPermission{Key: key, Name: entry.name, RootOnly: entry.rootOnly}, true
}

// set 在测试中改写单个权限的实现状态（模拟目录升级：先未实现、后实现）。
func (c *fakePermissionCatalog) set(key string, implemented, known bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !known {
		delete(c.known, key)
		return
	}
	entry, exists := c.known[key]
	if !exists {
		entry = fakeCatalogEntry{name: key}
	}
	entry.implemented = implemented
	c.known[key] = entry
}

// allowAllQueryAuthorizer 是测试用最宽松查询授权器，用于验证内核自身的跨主体
// 兜底（生产由 serverapp 的 root-aware 授权器把关）。
type allowAllQueryAuthorizer struct{}

// AuthorizeQuery 实现 authz.Authorizer。
func (allowAllQueryAuthorizer) AuthorizeQuery(context.Context, authz.Caller, string, authz.Scope) error {
	return nil
}

// insertExtraPermission 直接写入一条测试权限（不经过服务层）。
func (e *testEnv) insertExtraPermission(permissionID, scopeID, key string, enabled, rootOnly bool) {
	e.t.Helper()
	now := int64(1_700_000_000_000)
	if _, err := e.raw.ExecContext(context.Background(), `INSERT INTO permissions(
id,scope_id,permission_key,name,description,limits_text,is_builtin,root_only,enabled,
created_at_ms,updated_at_ms) VALUES(?,?,?,?,'','',0,?,?,?,?)`,
		permissionID, scopeID, key, key, boolInt(rootOnly), boolInt(enabled), now, now); err != nil {
		e.t.Fatalf("插入测试权限 %s 失败: %v", key, err)
	}
}

// newServiceWithoutCatalog 用同一存储/授权器构造未装配实现目录的引擎，验证 root
// 判定 fail-closed。
func (e *testEnv) newServiceWithoutCatalog(t *testing.T) *authz.Service {
	t.Helper()
	store, err := authzsqlite.New(e.raw)
	if err != nil {
		t.Fatalf("构造授权存储失败: %v", err)
	}
	service, err := authz.New(authz.Options{Store: store, Authorizer: e.authorizer})
	if err != nil {
		t.Fatalf("构造无目录授权引擎失败: %v", err)
	}
	return service
}

// TestRootOwnsImplementedEnabledPermissions 验证 root 全权限的允许/拒绝边界。
func TestRootOwnsImplementedEnabledPermissions(t *testing.T) {
	env := prepareEnv(t)
	ctx := context.Background()

	// system 范围：普通已实现权限允许，来源 root。
	result := env.check(testRootUser, "system", []string{"users.read"}, authz.ModeAll)
	if !result.Allowed || len(result.Permissions) != 1 {
		t.Fatalf("root 系统权限应允许: %+v", result)
	}
	if len(result.Permissions[0].Sources) != 1 ||
		result.Permissions[0].Sources[0].Kind != authz.SourceKindRoot ||
		!result.Permissions[0].Sources[0].Included {
		t.Fatalf("root 来源应标记 root: %+v", result.Permissions[0].Sources)
	}
	// root_only 权限属于 root 专属通道。
	if rootOnly := env.check(testRootUser, "system",
		[]string{"security.policy.manage"}, authz.ModeAll); !rootOnly.Allowed {
		t.Fatalf("root 应可使用 root_only 权限: %+v", rootOnly)
	}
	// 应用范围不要求成员关系或角色分配。
	appResult := env.check(testRootUser, testAppOne,
		[]string{"invoices.read", "invoices.approve"}, authz.ModeAll)
	if !appResult.Allowed || len(appResult.Permissions) != 2 {
		t.Fatalf("root 应用权限应允许: %+v", appResult)
	}

	// 未知权限仍拒绝。
	if unknown := env.check(testRootUser, testAppOne,
		[]string{"invoices.never.registered"}, authz.ModeAll); unknown.Allowed ||
		unknown.Code != authz.CodePermissionUnknown {
		t.Fatalf("root 未知权限应 PERMISSION_UNKNOWN: %+v", unknown)
	}
	// 停用权限仍拒绝。
	if disabled := env.check(testRootUser, testAppOne,
		[]string{"invoices.export"}, authz.ModeAll); disabled.Allowed ||
		disabled.Code != authz.CodePermissionDisabled {
		t.Fatalf("root 停用权限应 PERMISSION_DISABLED: %+v", disabled)
	}
	// 目录登记但业务未实现：拒绝，且不能伪装成已允许。
	if _, err := env.raw.ExecContext(ctx,
		`UPDATE permissions SET enabled=1 WHERE id=?`, testPermissionExport); err != nil {
		t.Fatalf("启用导出权限失败: %v", err)
	}
	env.catalog.set("invoices.export", false, true)
	notImplemented := env.check(testRootUser, testAppOne, []string{"invoices.export"}, authz.ModeAll)
	if notImplemented.Allowed || notImplemented.Code != authz.CodeAccessDenied ||
		notImplemented.Reason != "permission_not_implemented" {
		t.Fatalf("root 未实现权限应拒绝: %+v", notImplemented)
	}
	// 目录升级为已实现后自动包含（不缓存旧结论）。
	env.catalog.set("invoices.export", true, true)
	if upgraded := env.check(testRootUser, testAppOne,
		[]string{"invoices.export"}, authz.ModeAll); !upgraded.Allowed {
		t.Fatalf("root 应在权限实现后自动获得: %+v", upgraded)
	}

	// 停用应用：即使 root 也拒绝。
	env.insertExtraPermission("perm_0000000000000000000000000000a1", testAppDisabled,
		"invoices.read", true, false)
	if disabledApp := env.check(testRootUser, testAppDisabled,
		[]string{"invoices.read"}, authz.ModeAll); disabledApp.Allowed ||
		disabledApp.Code != authz.CodeClientDisabled {
		t.Fatalf("root 在停用应用应 CLIENT_DISABLED: %+v", disabledApp)
	}
	// 不存在的应用范围：REQ_INVALID。
	if missingApp := env.check(testRootUser,
		"app_00000000000000000000000000000099", []string{"invoices.read"},
		authz.ModeAll); missingApp.Allowed || missingApp.Code != authz.CodeReqInvalid {
		t.Fatalf("root 在未知应用应 REQ_INVALID: %+v", missingApp)
	}

	// root 账户必须 active；停用后即使身份记录存在也拒绝。
	if _, err := env.raw.ExecContext(ctx,
		`UPDATE users SET status='disabled' WHERE id=?`, testRootUser); err != nil {
		t.Fatalf("停用 root 账户失败: %v", err)
	}
	if inactive := env.check(testRootUser, "system", []string{"users.read"},
		authz.ModeAll); inactive.Allowed || inactive.Code != authz.CodeUserDisabled {
		t.Fatalf("停用 root 账户应 USER_DISABLED: %+v", inactive)
	}
	if _, err := env.raw.ExecContext(ctx,
		`UPDATE users SET status='active' WHERE id=?`, testRootUser); err != nil {
		t.Fatalf("恢复 root 账户失败: %v", err)
	}
	// root 不受普通账户期限限制。
	if _, err := env.raw.ExecContext(ctx,
		`UPDATE users SET valid_from_ms=NULL, valid_until_ms=? WHERE id=?`,
		int64(1_600_000_000_000), testRootUser); err != nil {
		t.Fatalf("写入 root 过期期限失败: %v", err)
	}
	if expired := env.check(testRootUser, "system", []string{"users.read"},
		authz.ModeAll); !expired.Allowed {
		t.Fatalf("root 不应受普通账户期限限制: %+v", expired)
	}
}

// TestRootEffectivePermissionsAndSources 验证 root 有效权限列表、分页与来源说明。
func TestRootEffectivePermissionsAndSources(t *testing.T) {
	env := prepareEnv(t)
	ctx := context.Background()

	// system 范围包含普通权限与 root_only 权限，来源均为 root。
	systemEffective := env.effective(testRootUser, "system", authz.ListOptions{Limit: authz.MaxListLimit})
	if systemEffective.DeniedCode != "" || len(systemEffective.Permissions) != 2 {
		t.Fatalf("root 系统有效权限 = %+v", systemEffective)
	}
	for _, permission := range systemEffective.Permissions {
		if len(permission.Sources) != 1 ||
			permission.Sources[0].Kind != authz.SourceKindRoot {
			t.Fatalf("root 系统来源 = %+v", permission.Sources)
		}
	}

	// 应用范围同样不依赖角色分配；停用权限不进入列表。
	appEffective := env.effective(testRootUser, testAppOne, authz.ListOptions{Limit: authz.MaxListLimit})
	if appEffective.DeniedCode != "" || len(appEffective.Permissions) != 4 {
		keys := make([]string, 0, len(appEffective.Permissions))
		for _, permission := range appEffective.Permissions {
			keys = append(keys, permission.Key)
		}
		t.Fatalf("root 应用有效权限 = %+v keys=%v", appEffective, keys)
	}
	for _, permission := range appEffective.Permissions {
		if permission.DataScope.Mode != authz.DataScopeAll {
			t.Fatalf("root 数据范围应为 all: %+v", permission)
		}
	}
	// 分页稳定：按 permission_key 排序，limit=1 的相邻两页互补、不重复；后续页仍有项。
	pageOne := env.effective(testRootUser, testAppOne, authz.ListOptions{Limit: 1})
	pageTwo := env.effective(testRootUser, testAppOne, authz.ListOptions{Limit: 1, Offset: 1})
	if !pageOne.HasMore || len(pageOne.Permissions) != 1 ||
		len(pageTwo.Permissions) != 1 {
		t.Fatalf("root 有效权限分页 = %+v / %+v", pageOne, pageTwo)
	}
	if pageOne.Permissions[0].Key != "invoices.approve" ||
		pageTwo.Permissions[0].Key != "invoices.read" {
		t.Fatalf("root 有效权限分页顺序 = %+v / %+v",
			pageOne.Permissions, pageTwo.Permissions)
	}
	lastPage := env.effective(testRootUser, testAppOne, authz.ListOptions{Limit: 1, Offset: 3})
	if lastPage.HasMore || len(lastPage.Permissions) != 1 ||
		lastPage.Permissions[0].Key != "users.read" {
		t.Fatalf("root 有效权限最后一页 = %+v", lastPage)
	}

	// 未实现权限从有效列表排除；标记为已实现后立即出现（不缓存）。
	if _, err := env.raw.ExecContext(ctx,
		`UPDATE permissions SET enabled=1 WHERE id=?`, testPermissionExport); err != nil {
		t.Fatalf("启用导出权限失败: %v", err)
	}
	env.catalog.set("invoices.export", false, true)
	beforeImplement := env.effective(testRootUser, testAppOne, authz.ListOptions{Limit: authz.MaxListLimit})
	// 数据库已启用的未实现权限被排除；目录已实现的内置权限仍作为 root 全权限出现。
	if len(beforeImplement.Permissions) != 4 {
		t.Fatalf("未实现权限不应进入 root 有效列表: %+v", beforeImplement)
	}
	env.catalog.set("invoices.export", true, true)
	afterImplement := env.effective(testRootUser, testAppOne, authz.ListOptions{Limit: authz.MaxListLimit})
	if len(afterImplement.Permissions) != 5 {
		t.Fatalf("已实现权限应自动进入 root 有效列表: %+v", afterImplement)
	}

	// 来源说明：root 来源 Included；停用/未实现给明确原因；未知键 PermissionFound=false。
	rootSource, err := env.service.PermissionSources(ctx, env.system, testRootUser,
		testAppOne, "invoices.read", authz.ListOptions{})
	if err != nil || !rootSource.PermissionFound || len(rootSource.Sources) != 1 ||
		rootSource.Sources[0].Kind != authz.SourceKindRoot || !rootSource.Sources[0].Included {
		t.Fatalf("root 来源说明 = %+v err=%v", rootSource, err)
	}
	if _, err := env.raw.ExecContext(ctx,
		`UPDATE permissions SET enabled=0 WHERE id=?`, testPermissionExport); err != nil {
		t.Fatalf("停用导出权限失败: %v", err)
	}
	disabledSource, err := env.service.PermissionSources(ctx, env.system, testRootUser,
		testAppOne, "invoices.export", authz.ListOptions{})
	if err != nil || len(disabledSource.Sources) != 1 ||
		disabledSource.Sources[0].Included ||
		disabledSource.Sources[0].ExcludedReason != "permission_disabled" {
		t.Fatalf("root 停用权限来源 = %+v err=%v", disabledSource, err)
	}
	if _, err := env.raw.ExecContext(ctx,
		`UPDATE permissions SET enabled=1 WHERE id=?`, testPermissionExport); err != nil {
		t.Fatalf("恢复导出权限失败: %v", err)
	}
	env.catalog.set("invoices.export", false, true)
	notImplementedSource, err := env.service.PermissionSources(ctx, env.system, testRootUser,
		testAppOne, "invoices.export", authz.ListOptions{})
	if err != nil || len(notImplementedSource.Sources) != 1 ||
		notImplementedSource.Sources[0].Included ||
		notImplementedSource.Sources[0].ExcludedReason != "permission_not_implemented" {
		t.Fatalf("root 未实现权限来源 = %+v err=%v", notImplementedSource, err)
	}
	unknownSource, err := env.service.PermissionSources(ctx, env.system, testRootUser,
		testAppOne, "invoices.never.registered", authz.ListOptions{})
	if err != nil || unknownSource.PermissionFound || len(unknownSource.Sources) != 0 {
		t.Fatalf("root 未知权限来源 = %+v err=%v", unknownSource, err)
	}

	// 未装配实现目录：root 判定 fail-closed。
	noCatalog := env.newServiceWithoutCatalog(t)
	failedClosed, err := noCatalog.Check(ctx, env.system, authz.CheckRequest{
		SubjectUserID: testRootUser, ScopeID: "system", Permissions: []string{"users.read"},
		Mode: authz.ModeAll})
	if err != nil || failedClosed.Allowed ||
		failedClosed.Code != authz.CodeAuthzUnavailable ||
		failedClosed.Reason != "implementation_catalog_unavailable" {
		t.Fatalf("未装配目录时 root 检查应 fail-closed: %+v err=%v", failedClosed, err)
	}
	failedEffective, err := noCatalog.EffectivePermissions(ctx, env.system, testRootUser,
		"system", authz.ListOptions{})
	if err != nil || failedEffective.DeniedCode != authz.CodeAuthzUnavailable ||
		failedEffective.DeniedReason != "implementation_catalog_unavailable" ||
		len(failedEffective.Permissions) != 0 {
		t.Fatalf("未装配目录时 root 有效权限应 fail-closed: %+v err=%v",
			failedEffective, err)
	}
}

// TestRootResourceAccess 验证 root 资源级数据范围 all 与非法资源标识拒绝。
func TestRootResourceAccess(t *testing.T) {
	env := prepareEnv(t)
	ctx := context.Background()

	allowed, err := env.service.CheckResourceAccess(ctx, env.system, testRootUser,
		testAppOne, "invoices.approve", "any-invoice")
	if err != nil || !allowed.Allowed || allowed.DataScope.Mode != authz.DataScopeAll {
		t.Fatalf("root 资源级应允许任意合法资源: %+v err=%v", allowed, err)
	}
	// root_only 权限 + 资源。
	rootOnly, err := env.service.CheckResourceAccess(ctx, env.system, testRootUser,
		"system", "security.policy.manage", "policy-1")
	if err != nil || !rootOnly.Allowed {
		t.Fatalf("root root_only 资源级应允许: %+v err=%v", rootOnly, err)
	}
	// 非法资源标识仍 REQ_INVALID。
	for name, resourceID := range map[string]string{
		"空资源":    "",
		"控制字符资源": "bad\nresource",
	} {
		if _, err := env.service.CheckResourceAccess(ctx, env.system, testRootUser,
			testAppOne, "invoices.approve", resourceID); !errors.Is(err, authz.ErrInvalidRequest) {
			t.Fatalf("%s 应 ErrInvalidRequest: %v", name, err)
		}
	}
	// 未知/停用/未实现权限在资源级同样拒绝。
	if unknown, err := env.service.CheckResourceAccess(ctx, env.system, testRootUser,
		testAppOne, "invoices.never.registered", "any-invoice"); err != nil ||
		unknown.Allowed || unknown.Code != authz.CodePermissionUnknown {
		t.Fatalf("root 未知权限资源级 = %+v err=%v", unknown, err)
	}
	if disabled, err := env.service.CheckResourceAccess(ctx, env.system, testRootUser,
		testAppOne, "invoices.export", "any-invoice"); err != nil ||
		disabled.Allowed || disabled.Code != authz.CodePermissionDisabled {
		t.Fatalf("root 停用权限资源级 = %+v err=%v", disabled, err)
	}
	if _, err := env.raw.ExecContext(ctx,
		`UPDATE permissions SET enabled=1 WHERE id=?`, testPermissionExport); err != nil {
		t.Fatalf("启用导出权限失败: %v", err)
	}
	env.catalog.set("invoices.export", false, true)
	if notImplemented, err := env.service.CheckResourceAccess(ctx, env.system, testRootUser,
		testAppOne, "invoices.export", "any-invoice"); err != nil ||
		notImplemented.Allowed || notImplemented.Code != authz.CodeAccessDenied ||
		notImplemented.Reason != "permission_not_implemented" {
		t.Fatalf("root 未实现权限资源级 = %+v err=%v", notImplemented, err)
	}
}

// TestRootCallerQueryAuthorizationAndSpoof 验证 root 作为可信调用者可查询他人，普通
// 用户跨主体检查仍拒绝，且不能靠“用户名叫 root”伪造 root 资格。
func TestRootCallerQueryAuthorizationAndSpoof(t *testing.T) {
	env := prepareEnv(t)
	ctx := context.Background()
	store, err := authzsqlite.New(env.raw)
	if err != nil {
		t.Fatalf("构造授权存储失败: %v", err)
	}
	permissive, err := authz.New(authz.Options{Store: store,
		Authorizer: allowAllQueryAuthorizer{}, Catalog: env.catalog})
	if err != nil {
		t.Fatalf("构造宽松授权引擎失败: %v", err)
	}
	rootCaller := env.userCaller(testRootUser)
	otherCaller := env.userCaller(testOtherUser)

	// root 作为可信调用者可在快照内复核后检查他人。
	crossResult, err := permissive.Check(ctx, rootCaller, authz.CheckRequest{
		SubjectUserID: testActiveUser, ScopeID: testAppOne,
		Permissions: []string{"invoices.approve"}, Mode: authz.ModeAll})
	if err != nil || crossResult.SubjectUserID != testActiveUser {
		t.Fatalf("root 跨主体检查 = %+v err=%v", crossResult, err)
	}
	// 非 root 用户即使 Authorizer 误放行，内核仍拒绝跨主体 Check。
	if _, err := permissive.Check(ctx, otherCaller, authz.CheckRequest{
		SubjectUserID: testActiveUser, ScopeID: testAppOne,
		Permissions: []string{"invoices.approve"}, Mode: authz.ModeAll}); !errors.Is(err, authz.ErrAccessDenied) {
		t.Fatalf("非 root 跨主体 Check 应 ErrAccessDenied: %v", err)
	}
	// root 查询他人有效权限：返回目标真实状态（此目标不是 appOne 成员 → 拒绝码）。
	crossEffective, err := permissive.EffectivePermissions(ctx, rootCaller,
		testOtherUser, testAppOne, authz.ListOptions{})
	if err != nil || crossEffective.DeniedCode != authz.CodeAppMembershipRequired {
		t.Fatalf("root 查询他人有效权限 = %+v err=%v", crossEffective, err)
	}
	// 非 root 查询他人：接口查询授权由 Authorizer 把关；应用范围下非成员目标仍按
	// 存在性保护拒绝（内核兜底，不返回空成功）。
	if _, err := permissive.EffectivePermissions(ctx, otherCaller,
		testUnrelated, testAppOne, authz.ListOptions{}); !errors.Is(err, authz.ErrAccessDenied) {
		t.Fatalf("非 root 跨主体有效权限应 ErrAccessDenied: %v", err)
	}

	// 伪造：用户名 root 但不是真实 root 记录，不能获得 root 全权限。
	const spoofUser = "usr_00000000000000000000000000000099"
	now := int64(1_700_000_000_000)
	if _, err := env.raw.ExecContext(ctx, `INSERT INTO users(
id,username,username_normalized,status,is_root,security_version,row_version,
created_at_ms,updated_at_ms) VALUES(?,'root','root','active',0,1,1,?,?)`,
		spoofUser, now, now); err != nil {
		t.Fatalf("插入伪造 root 用户失败: %v", err)
	}
	spoofResult := env.check(spoofUser, testAppOne, []string{"invoices.approve"}, authz.ModeAll)
	if spoofResult.Allowed || spoofResult.Code != authz.CodeAppMembershipRequired {
		t.Fatalf("非 root 的 root 用户名不应获得全权限: %+v", spoofResult)
	}
	spoofEffective := env.effective(spoofUser, testAppOne, authz.ListOptions{})
	if len(spoofEffective.Permissions) != 0 ||
		(spoofEffective.DeniedCode != "" &&
			spoofEffective.DeniedCode != authz.CodeAppMembershipRequired) {
		t.Fatalf("非 root 不应得到目录级有效权限: %+v", spoofEffective)
	}
}

// failingStore 是总是返回依赖错误的测试 Store，用于验证 root 判定 fail-closed。
type failingStore struct{ err error }

// Snapshot 实现 authz.Store。
func (s failingStore) Snapshot(context.Context, func(context.Context, authz.Reader) error) error {
	return s.err
}

// catalogOnlyReader 是只提供权限目录分页与 root 账户信息的测试 Reader。
type catalogOnlyReader struct {
	rootID string
	rows   []authz.PermissionInfo
}

func (r catalogOnlyReader) Account(_ context.Context, userID string) (authz.AccountInfo, bool, error) {
	if userID != r.rootID {
		return authz.AccountInfo{}, false, nil
	}
	return authz.AccountInfo{UserID: userID, Status: account.StatusActive, IsRoot: true}, true, nil
}

func (r catalogOnlyReader) Application(context.Context, string) (authz.ApplicationInfo, bool, error) {
	return authz.ApplicationInfo{}, false, nil
}

func (r catalogOnlyReader) Membership(context.Context, string, string) (authz.MembershipInfo, error) {
	return authz.MembershipInfo{}, nil
}

func (r catalogOnlyReader) Permission(context.Context, string, string) (authz.PermissionInfo, bool, error) {
	return authz.PermissionInfo{}, false, nil
}

func (r catalogOnlyReader) GrantedPermissions(context.Context, string, string, int, int) ([]authz.PermissionInfo, bool, error) {
	return nil, false, nil
}

func (r catalogOnlyReader) PermissionSources(context.Context, string, string, []string, int, int) ([]authz.GrantSource, bool, error) {
	return nil, false, nil
}

func (r catalogOnlyReader) ScopePermissions(_ context.Context, _ string, limit, offset int) ([]authz.PermissionInfo, bool, error) {
	if offset >= len(r.rows) {
		return nil, false, nil
	}
	end := offset + limit
	if end > len(r.rows) {
		end = len(r.rows)
	}
	page := append([]authz.PermissionInfo(nil), r.rows[offset:end]...)
	return page, end < len(r.rows), nil
}

// catalogStore 把固定 Reader 包装为 Store。
type catalogStore struct{ reader catalogOnlyReader }

// Snapshot 实现 authz.Store。
func (s catalogStore) Snapshot(ctx context.Context, fn func(context.Context, authz.Reader) error) error {
	return fn(ctx, s.reader)
}

// TestRootFailClosedAndDirectoryScanLimit 验证 root 判定在依赖失败/目录过大时
// fail-closed，不返回截断伪造的有效权限结果。
func TestRootFailClosedAndDirectoryScanLimit(t *testing.T) {
	ctx := context.Background()
	const rootID = "usr_00000000000000000000000000000006"
	catalog := newFakePermissionCatalog(map[string]bool{"users.read": true})
	authorizer := allowAllQueryAuthorizer{}

	// 依赖失败：Check 返回 AUTHZ_UNAVAILABLE 拒绝决策；EffectivePermissions 返回
	// 可识别的存储不可用错误；资源级沿用拒绝决策。
	failing, err := authz.New(authz.Options{Store: failingStore{err: errors.New("依赖失败")},
		Authorizer: authorizer, Catalog: catalog})
	if err != nil {
		t.Fatalf("构造失败存储引擎: %v", err)
	}
	system, err := authz.SystemCaller("system-root-test")
	if err != nil {
		t.Fatalf("构造系统调用者: %v", err)
	}
	failedCheck, err := failing.Check(ctx, system, authz.CheckRequest{
		SubjectUserID: rootID, ScopeID: "system",
		Permissions: []string{"users.read"}, Mode: authz.ModeAll})
	if err != nil || failedCheck.Allowed || failedCheck.Code != authz.CodeAuthzUnavailable {
		t.Fatalf("依赖失败时 root 检查应 fail-closed: %+v err=%v", failedCheck, err)
	}
	if _, err := failing.EffectivePermissions(ctx, system, rootID, "system",
		authz.ListOptions{}); !errors.Is(err, authz.ErrStoreUnavailable) {
		t.Fatalf("依赖失败时 root 有效权限应返回 ErrStoreUnavailable: %v", err)
	}
	resourceDecision, err := failing.CheckResourceAccess(ctx, system, rootID,
		"system", "users.read", "resource-1")
	if err != nil || resourceDecision.Allowed ||
		resourceDecision.Code != authz.CodeAuthzUnavailable {
		t.Fatalf("依赖失败时 root 资源检查应 fail-closed: %+v err=%v", resourceDecision, err)
	}

	// 目录过大：大量不可用目录行导致合并分页扫描超过上限 → AUTHZ_UNAVAILABLE，
	// 不返回截断结果或空成功。
	rows := make([]authz.PermissionInfo, 0, authz.MaxPermissionDirectoryRows+64)
	for index := 0; index < authz.MaxPermissionDirectoryRows+64; index++ {
		rows = append(rows, authz.PermissionInfo{
			PermissionID: fmt.Sprintf("perm_%032d", index),
			ScopeID:      "system",
			Key:          fmt.Sprintf("custom.permission.%04d", index),
			Name:         "停用自定义权限",
			Enabled:      false,
		})
	}
	oversized, err := authz.New(authz.Options{Store: catalogStore{reader: catalogOnlyReader{
		rootID: rootID, rows: rows}}, Authorizer: authorizer, Catalog: catalog})
	if err != nil {
		t.Fatalf("构造大目录引擎: %v", err)
	}
	oversizedResult, err := oversized.EffectivePermissions(ctx, system, rootID,
		"system", authz.ListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("大目录有效权限查询应返回拒绝结果: %v", err)
	}
	if oversizedResult.DeniedCode != authz.CodeAuthzUnavailable ||
		oversizedResult.DeniedReason != "permission_directory_too_large" ||
		len(oversizedResult.Permissions) != 0 {
		t.Fatalf("目录过大应 fail-closed: %+v", oversizedResult)
	}
}
