package preset_test

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
	delegationsqlite "github.com/kagurazakayashi/EvernightLogin/internal/delegation/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/preset"
	presetsqlite "github.com/kagurazakayashi/EvernightLogin/internal/preset/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const (
	appA   = "app_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	appB   = "app_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	appOff = "app_cccccccccccccccccccccccccccccccc"
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

type testEnv struct {
	t        *testing.T
	raw      *storagesqlite.Store
	store    *presetsqlite.Store
	recorder *audit.Recorder
	clock    *fakeClock
	service  *preset.Service
	catalog  *preset.Catalog
	local    preset.Caller
	system   preset.Caller
}

// prepareEnv 打开临时 SQLite、执行全部迁移并构造预设服务（真实委派 Guard）。
func prepareEnv(t *testing.T, mutate func(*preset.Catalog)) *testEnv {
	t.Helper()
	ctx := context.Background()
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(filepath.Join(testutil.TempDir(t), "preset.sqlite")))
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
	store, err := presetsqlite.New(raw)
	if err != nil {
		t.Fatalf("构造预设仓储失败: %v", err)
	}
	auditStore, err := auditsqlite.New(raw)
	if err != nil {
		t.Fatalf("构造审计仓储失败: %v", err)
	}
	clock := &fakeClock{now: time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)}
	recorder, err := audit.New(auditStore, audit.Options{Now: clock.Now})
	if err != nil {
		t.Fatalf("构造审计写入器失败: %v", err)
	}
	delegationStore, err := delegationsqlite.New(raw)
	if err != nil {
		t.Fatalf("构造委派仓储失败: %v", err)
	}
	delegationService, err := delegation.New(delegation.Options{
		Store: delegationStore, Audit: recorder, Now: clock.Now,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("构造委派服务失败: %v", err)
	}
	catalog := preset.DefaultCatalog()
	if mutate != nil {
		mutate(catalog)
	}
	service, err := preset.New(preset.Options{
		Store: store, Audit: recorder, Transfers: delegationService, Catalog: catalog,
		Now: clock.Now, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("构造预设服务失败: %v", err)
	}
	local, err := preset.LocalBootstrapCaller("operator-1")
	if err != nil {
		t.Fatalf("构造本地调用者失败: %v", err)
	}
	system, err := preset.SystemCaller("system-1")
	if err != nil {
		t.Fatalf("构造系统调用者失败: %v", err)
	}
	return &testEnv{t: t, raw: raw, store: store, recorder: recorder, clock: clock,
		service: service, catalog: catalog, local: local, system: system}
}

// exec 执行测试用 SQL。
func (e *testEnv) exec(query string, args ...any) {
	e.t.Helper()
	if _, err := e.raw.ExecContext(context.Background(), query, args...); err != nil {
		e.t.Fatalf("执行 SQL 失败: %v\n%s", err, query)
	}
}

// queryInt 读取单个整数。
func (e *testEnv) queryInt(query string, args ...any) int {
	e.t.Helper()
	rows, err := e.raw.QueryContext(context.Background(), query, args...)
	if err != nil {
		e.t.Fatalf("查询失败: %v\n%s", err, query)
	}
	defer rows.Close()
	var value int
	if !rows.Next() {
		e.t.Fatalf("查询无结果: %s", query)
	}
	if err := rows.Scan(&value); err != nil {
		e.t.Fatalf("扫描失败: %v", err)
	}
	return value
}

// createApplication 在临时库登记合成应用与对应 scope。
func (e *testEnv) createApplication(appID, status string) {
	e.t.Helper()
	now := e.clock.Now().UnixMilli()
	e.exec(`INSERT INTO applications(id,name,status,client_type,created_at_ms,updated_at_ms) VALUES(?,?,?,?,?,?)`,
		appID, "合成应用", status, "confidential", now, now)
	e.exec(`INSERT INTO scopes(id,kind,app_id) VALUES(?,?,?)`, appID, "application", appID)
}

// roleID 读取指定作用范围预设角色的稳定 ID。
func (e *testEnv) roleID(scopeID, roleKey string) string {
	e.t.Helper()
	rows, err := e.raw.QueryContext(context.Background(),
		`SELECT id FROM roles WHERE scope_id=? AND role_key=?`, scopeID, roleKey)
	if err != nil {
		e.t.Fatalf("读取角色 ID 失败: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		e.t.Fatalf("角色 %s/%s 不存在", scopeID, roleKey)
	}
	var id string
	if err := rows.Scan(&id); err != nil {
		e.t.Fatalf("扫描角色 ID 失败: %v", err)
	}
	return id
}

// permissionID 读取指定作用范围权限的稳定 ID。
func (e *testEnv) permissionID(scopeID, key string) string {
	e.t.Helper()
	rows, err := e.raw.QueryContext(context.Background(),
		`SELECT id FROM permissions WHERE scope_id=? AND permission_key=?`, scopeID, key)
	if err != nil {
		e.t.Fatalf("读取权限 ID 失败: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		e.t.Fatalf("权限 %s/%s 不存在", scopeID, key)
	}
	var id string
	if err := rows.Scan(&id); err != nil {
		e.t.Fatalf("扫描权限 ID 失败: %v", err)
	}
	return id
}

// rolePermissionKeys 返回角色当前组合的权限键（排序后逗号连接）。
func (e *testEnv) rolePermissionKeys(roleID string) string {
	e.t.Helper()
	rows, err := e.raw.QueryContext(context.Background(),
		`SELECT p.permission_key FROM role_permissions rp JOIN permissions p ON p.id=rp.permission_id
WHERE rp.role_id=? ORDER BY p.permission_key ASC`, roleID)
	if err != nil {
		e.t.Fatalf("读取角色权限失败: %v", err)
	}
	defer rows.Close()
	keys := make([]string, 0, 16)
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			e.t.Fatalf("扫描权限键失败: %v", err)
		}
		keys = append(keys, key)
	}
	return strings.Join(keys, ",")
}

// permissionText 读取指定作用范围权限的名称与说明，用于验证文案同步。
func (e *testEnv) permissionText(scopeID, key string) (string, string) {
	e.t.Helper()
	rows, err := e.raw.QueryContext(context.Background(),
		`SELECT name, description FROM permissions WHERE scope_id=? AND permission_key=?`, scopeID, key)
	if err != nil {
		e.t.Fatalf("读取权限文案失败: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		e.t.Fatalf("权限 %s/%s 不存在", scopeID, key)
	}
	var name, description string
	if err := rows.Scan(&name, &description); err != nil {
		e.t.Fatalf("扫描权限文案失败: %v", err)
	}
	return name, description
}

// chain 把字符串切片连接为逗号分隔，便于比较。
func chain(values []string) string {
	return strings.Join(values, ",")
}

// TestCatalogIntegrity 验收“说明完整性”：每条权限有中文名称、能做什么、范围与不能
// 做什么；逐条独立登记；没有 root 角色；root_only 权限不进入普通角色；应用模板
// 不带系统权限；机器可读 JSON 可导出。
func TestCatalogIntegrity(t *testing.T) {
	catalog := preset.DefaultCatalog()
	if err := catalog.Validate(); err != nil {
		t.Fatalf("默认预设目录不合法: %v", err)
	}
	if catalog.Version != "1.0.0" {
		t.Fatalf("目录版本 = %q，期望 1.0.0", catalog.Version)
	}
	if len(catalog.Permissions) < 40 {
		t.Fatalf("预设权限数量 = %d，明显少于需求基线", len(catalog.Permissions))
	}
	keys := make(map[string]struct{}, len(catalog.Permissions))
	for _, definition := range catalog.Permissions {
		if _, exists := keys[definition.Key]; exists {
			t.Fatalf("预设权限 %q 重复", definition.Key)
		}
		keys[definition.Key] = struct{}{}
		if definition.Name == "" || definition.Summary == "" || definition.Scope == "" || definition.Limits == "" {
			t.Fatalf("权限 %q 说明不完整: %+v", definition.Key, definition)
		}
		// “不能做什么”必须是真实说明，而不是只要非空就通过。
		if !strings.Contains(definition.Limits, "不") {
			t.Fatalf("权限 %q 的限制说明未明确写出不能做什么: %q", definition.Key, definition.Limits)
		}
		if strings.Contains(definition.Key, "root") {
			t.Fatalf("普通权限 %q 不得含 root 语义", definition.Key)
		}
	}
	for _, template := range catalog.Roles {
		if strings.Contains(template.Key, "root") {
			t.Fatalf("预设角色 %q 不得含 root 语义", template.Key)
		}
	}
	// 内置角色默认权限必须都在目录中且没有 root_only 权限。
	for _, template := range catalog.Roles {
		for _, key := range template.DefaultPermissions {
			if _, ok := keys[key]; !ok {
				t.Fatalf("角色 %q 默认权限 %q 不在目录中", template.Key, key)
			}
		}
	}
	// 应用模板不得自带系统权限。
	for _, template := range catalog.ApplicationRoles {
		if len(template.DefaultPermissions) != 0 {
			t.Fatalf("应用模板角色 %q 不应默认组合系统权限", template.Key)
		}
	}
	data, err := catalog.JSON()
	if err != nil {
		t.Fatalf("导出机器可读目录失败: %v", err)
	}
	if !strings.Contains(string(data), `"version": "1.0.0"`) {
		t.Fatalf("机器可读目录缺少版本: %s", string(data))
	}
	// 未实现的权限必须显式标记，不能伪装成功。逐键核对代码后：权限键对应的真实
	// 服务端执行路径已实现的标 true；下列键没有真实执行路径，必须保持 false 且不
	// 授予任何预设角色：
	//   settings.manage（仍无服务端执行路径）；diagnostics.read 已在步骤 233 接通。
	notImplemented := map[string]struct{}{
		"settings.manage": {},
	}
	for _, definition := range catalog.Permissions {
		want := true
		if _, missing := notImplemented[definition.Key]; missing {
			want = false
		}
		if definition.Implemented != want {
			t.Fatalf("权限 %q Implemented = %v，期望 %v（未实现能力不得标记为已实现）",
				definition.Key, definition.Implemented, want)
		}
	}
	// authorization.check 有真实联合判定端点（/oauth/token/authorize，登记资源服务时
	// 挂载），因此 Implemented=true；但作为资源服务能力标记不授予预设角色。
	byKey := make(map[string]preset.PermissionDefinition, len(catalog.Permissions))
	for _, definition := range catalog.Permissions {
		byKey[definition.Key] = definition
	}
	authorization, ok := byKey["authorization.check"]
	if !ok || !authorization.Implemented || len(authorization.DefaultRoles) != 0 {
		t.Fatalf("authorization.check 应有实现且不授予预设角色: %+v", authorization)
	}
	for key := range notImplemented {
		definition := byKey[key]
		if definition.Implemented || len(definition.DefaultRoles) != 0 {
			t.Fatalf("未实现权限 %q 必须保持 false 且不授予预设角色: %+v", key, definition)
		}
		for _, template := range catalog.Roles {
			for _, granted := range template.DefaultPermissions {
				if granted == key {
					t.Fatalf("未实现权限 %q 不得出现在预设角色 %q 的默认权限中", key, template.Key)
				}
			}
		}
	}
}

// TestInstallInitialAndIdempotent 验收第一次初始化与重复运行：初始化只登记目录、
// 不创建账户、不做角色分配；重复运行不产生重复行或覆盖。
func TestInstallInitialAndIdempotent(t *testing.T) {
	env := prepareEnv(t, nil)
	ctx := context.Background()

	first, err := env.service.Install(ctx, env.local, preset.InstallRequest{})
	if err != nil {
		t.Fatalf("首次初始化失败: %v", err)
	}
	if !first.Initialized || !first.Changed {
		t.Fatalf("首次初始化结果 = %+v", first)
	}
	if len(first.CreatedPermissions) != len(env.catalog.Permissions) {
		t.Fatalf("创建权限数 = %d，期望 %d", len(first.CreatedPermissions), len(env.catalog.Permissions))
	}
	if len(first.CreatedRoles) != len(env.catalog.Roles) {
		t.Fatalf("创建角色数 = %d，期望 %d", len(first.CreatedRoles), len(env.catalog.Roles))
	}
	if len(first.CreatedGroups) != len(env.catalog.Groups) {
		t.Fatalf("创建用户组数 = %d，期望 %d", len(first.CreatedGroups), len(env.catalog.Groups))
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM permissions WHERE scope_id='system'`); got != len(env.catalog.Permissions) {
		t.Fatalf("系统权限行数 = %d", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM roles WHERE scope_id='system'`); got != len(env.catalog.Roles) {
		t.Fatalf("系统角色行数 = %d", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM user_groups WHERE scope_id='system'`); got != len(env.catalog.Groups) {
		t.Fatalf("系统用户组行数 = %d", got)
	}
	// 预设不创建带固定密码的工作人员账户，也不做任何角色分配。
	if got := env.queryInt(`SELECT COUNT(*) FROM users`); got != 0 {
		t.Fatalf("初始化不应创建账户，实际 %d 个", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM user_roles`); got != 0 {
		t.Fatalf("初始化不应分配角色，实际 %d 行", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM group_roles`); got != 0 {
		t.Fatalf("初始化不应分配组角色，实际 %d 行", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM group_members`); got != 0 {
		t.Fatalf("初始化不应加入组成员，实际 %d 行", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM preset_installations WHERE scope_id='system' AND catalog_version='1.0.0'`); got != 1 {
		t.Fatalf("初始化版本记录缺失")
	}
	// 系统管理员默认组合应等于目录定义，且不含 root_only 权限。
	systemAdminRole := env.roleID("system", "system_admin")
	defaultTemplate := findRole(t, env.catalog.Roles, "system_admin")
	if got := env.rolePermissionKeys(systemAdminRole); got != chain(sortedCopy(defaultTemplate.DefaultPermissions)) {
		t.Fatalf("系统管理员默认权限 = %q，期望 %q", got, chain(sortedCopy(defaultTemplate.DefaultPermissions)))
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM role_permissions rp JOIN permissions p ON p.id=rp.permission_id
WHERE p.root_only=1`); got != 0 {
		t.Fatalf("预设角色组合了 %d 个 root_only 权限", got)
	}

	// 重复运行：幂等，不产生重复行、不覆盖。
	second, err := env.service.Install(ctx, env.local, preset.InstallRequest{ScopeID: "system"})
	if err != nil {
		t.Fatalf("重复初始化失败: %v", err)
	}
	if second.Initialized || second.Changed || !second.UpToDate {
		t.Fatalf("重复初始化结果 = %+v", second)
	}
	if len(second.CreatedPermissions)+len(second.CreatedRoles)+len(second.CreatedGroups) != 0 {
		t.Fatalf("重复初始化不应创建新项: %+v", second)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM permissions WHERE scope_id='system'`); got != len(env.catalog.Permissions) {
		t.Fatalf("重复初始化后权限行数 = %d", got)
	}
	// 审计：两次初始化都有成功记录。
	if got := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action='preset.install' AND outcome='success'`); got < 2 {
		t.Fatalf("初始化审计记录 = %d，期望至少 2", got)
	}
}

// TestInstallUpgradeDoesNotOverwriteUserAdjustments 验收“已有自定义修改”与“升级不覆盖
// 用户已调整的非核心角色”：更高版本只补缺失权限，不改写既有角色组合，并给出待恢复提示。
func TestInstallUpgradeDoesNotOverwriteUserAdjustments(t *testing.T) {
	env := prepareEnv(t, func(catalog *preset.Catalog) {
		catalog.Version = "1.1.0"
		catalog.Permissions = append(catalog.Permissions, preset.PermissionDefinition{
			Key: "support.cases.export", Name: "导出求助单", Summary: "按许可导出求助记录。",
			Scope: "仅获准的客服范围。", Limits: "不能导出未脱敏资料或范围外记录。",
		})
		for index := range catalog.Roles {
			if catalog.Roles[index].Key == "support" {
				catalog.Roles[index].DefaultPermissions = append(catalog.Roles[index].DefaultPermissions, "support.cases.export")
			}
		}
	})
	ctx := context.Background()
	// 先用 1.0.0 目录初始化同一数据库。
	v10 := prepareLegacyEnv(t, env, "1.0.0")
	if _, err := v10.service.Install(ctx, v10.local, preset.InstallRequest{}); err != nil {
		t.Fatalf("1.0.0 初始化失败: %v", err)
	}
	// 用户自定义：从 support 角色移除一个默认权限。
	supportRole := v10.roleID("system", "support")
	v10.exec(`DELETE FROM role_permissions WHERE role_id=? AND permission_id=?`,
		supportRole, v10.permissionID("system", "support.cases.read"))
	before := v10.rolePermissionKeys(supportRole)

	// 用 1.1.0 目录重新初始化：新增权限被创建，但既有角色组合不被改写。
	result, err := env.service.Install(ctx, env.local, preset.InstallRequest{})
	if err != nil {
		t.Fatalf("升级初始化失败: %v", err)
	}
	if !result.Upgraded || result.PreviousVersion != "1.0.0" || result.CatalogVersion != "1.1.0" {
		t.Fatalf("升级结果 = %+v", result)
	}
	if len(result.CreatedPermissions) != 1 || result.CreatedPermissions[0] != "support.cases.export" {
		t.Fatalf("升级创建权限 = %v，期望只新增 support.cases.export", result.CreatedPermissions)
	}
	if len(result.CreatedRoles) != 0 {
		t.Fatalf("升级不应重建角色: %v", result.CreatedRoles)
	}
	if got := env.rolePermissionKeys(supportRole); got != before {
		t.Fatalf("升级改写了用户已调整的角色组合: %q -> %q", before, got)
	}
	foundDeferred := false
	for _, item := range result.DeferredRolePermissionAdds {
		if item == "support:support.cases.export" {
			foundDeferred = true
		}
	}
	if !foundDeferred {
		t.Fatalf("升级应提示待恢复权限，实际 %v", result.DeferredRolePermissionAdds)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM preset_installations WHERE scope_id='system' AND catalog_version='1.1.0'`); got != 1 {
		t.Fatalf("升级后版本记录未更新")
	}
}

// prepareLegacyEnv 在同一条临时数据库上构造使用指定目录版本的预设服务。
func prepareLegacyEnv(t *testing.T, env *testEnv, version string) *testEnv {
	t.Helper()
	catalog := preset.DefaultCatalog()
	catalog.Version = version
	service, err := preset.New(preset.Options{
		Store: env.store, Audit: env.recorder, Transfers: allowTransfersForTest(),
		Catalog: catalog, Now: env.clock.Now, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("构造历史版本预设服务失败: %v", err)
	}
	return &testEnv{t: t, raw: env.raw, store: env.store, recorder: env.recorder,
		clock: env.clock, service: service, catalog: catalog, local: env.local, system: env.system}
}

// allowTransfersForTest 返回测试用放行 Guard（仅用于构造历史版本服务）。
func allowTransfersForTest() delegation.GuardFuncs {
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
		Restoration: func(context.Context, audit.Tx, audit.Actor, string) error { return nil },
	}
}

// TestPreviewAndRestoreLocal 验收局部恢复：预览展示差异、再次授权、审计，并只恢复
// 明确选择的角色；自定义角色与自定义权限保留。
func TestPreviewAndRestoreLocal(t *testing.T) {
	env := prepareEnv(t, nil)
	ctx := context.Background()
	if _, err := env.service.Install(ctx, env.local, preset.InstallRequest{}); err != nil {
		t.Fatalf("初始化失败: %v", err)
	}
	// 用户调整：support 角色移除一个默认权限、加入一个自定义权限；停用一个预设权限。
	supportRole := env.roleID("system", "support")
	env.exec(`DELETE FROM role_permissions WHERE role_id=? AND permission_id=?`,
		supportRole, env.permissionID("system", "support.cases.read"))
	// 自定义权限与自定义角色（不属于预设目录，恢复不得删除）。
	now := env.clock.Now().UnixMilli()
	env.exec(`INSERT INTO permissions(id,scope_id,permission_key,name,description,limits_text,is_builtin,root_only,enabled,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?,?,?,?,?,?)`, "perm_55555555555555555555555555555555", "system", "custom.audit.note",
		"自定义审计备注", "自定义权限说明｜范围：仅测试", "自定义限制", 0, 0, 1, now, now)
	env.exec(`INSERT INTO roles(id,scope_id,role_key,name,description,limits_text,is_builtin,enabled,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?,?,?,?,?)`, "role_55555555555555555555555555555555", "system", "custom_role",
		"自定义角色", "自定义角色说明", "自定义限制", 0, 1, now, now)
	env.exec(`INSERT INTO role_permissions(role_id,permission_id,scope_id) VALUES(?,?,?)`,
		"role_55555555555555555555555555555555", "perm_55555555555555555555555555555555", "system")
	env.exec(`UPDATE permissions SET enabled=0 WHERE scope_id='system' AND permission_key='reports.read'`)

	preview, err := env.service.Preview(ctx, env.local, preset.PreviewRequest{
		Selections: []preset.RoleSelection{{ScopeID: "system", RoleKeys: []string{"support"}}},
	})
	if err != nil {
		t.Fatalf("预览失败: %v", err)
	}
	if preview.Token == "" || preview.Digest == "" {
		t.Fatalf("预览缺少令牌或摘要")
	}
	if preview.Summary.AddRolePermissions != 1 || preview.Summary.RemoveRolePermissions != 0 {
		t.Fatalf("预览差异 = %+v，期望补回 1 个默认权限", preview.Summary)
	}
	reenableFound := false
	for _, scope := range preview.Scopes {
		for _, change := range scope.ReenablePermissions {
			if change.Key == "reports.read" {
				reenableFound = true
			}
		}
	}
	if !reenableFound {
		t.Fatalf("预览未展示停用权限的恢复项: %+v", preview.Scopes)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action='preset.preview' AND outcome='success'`); got != 1 {
		t.Fatalf("预览读取审计 = %d", got)
	}

	// 再次授权：无令牌、伪造令牌都拒绝。
	if _, err := env.service.Restore(ctx, env.local, preset.RestoreRequest{Token: "deadbeef"}); !errors.Is(err, preset.ErrPreviewRequired) {
		t.Fatalf("伪造令牌错误 = %v，期望 ErrPreviewRequired", err)
	}
	restored, err := env.service.Restore(ctx, env.local, preset.RestoreRequest{Token: preview.Token})
	if err != nil {
		t.Fatalf("恢复失败: %v", err)
	}
	if restored.Digest != preview.Digest || restored.Summary.TotalChanges() == 0 {
		t.Fatalf("恢复结果 = %+v", restored)
	}
	supportAfter := env.rolePermissionKeys(supportRole)
	if !strings.Contains(supportAfter, "support.cases.read") {
		t.Fatalf("恢复后 support 角色缺少默认权限: %q", supportAfter)
	}
	if !strings.HasPrefix(supportAfter, "recovery.request,self.credentials.manage,self.grants.manage,self.profile.read,self.profile.update,self.sessions.manage,support.cases.create,support.cases.read,support.cases.update") {
		t.Fatalf("恢复后 support 角色权限 = %q", supportAfter)
	}
	if got := env.queryInt(`SELECT enabled FROM permissions WHERE scope_id='system' AND permission_key='reports.read'`); got != 1 {
		t.Fatalf("恢复后 reports.read 未重新启用")
	}
	// 自定义内容保留：自定义角色、自定义权限与角色组合未被删除。
	if got := env.queryInt(`SELECT COUNT(*) FROM roles WHERE scope_id='system' AND role_key='custom_role'`); got != 1 {
		t.Fatalf("恢复删除了自定义角色")
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM permissions WHERE scope_id='system' AND permission_key='custom.audit.note'`); got != 1 {
		t.Fatalf("恢复删除了自定义权限")
	}
	// 未选择的角色不被改写（system_admin 保持初始化默认）。
	systemAdminRole := env.roleID("system", "system_admin")
	adminTemplate := findRole(t, env.catalog.Roles, "system_admin")
	if got := env.rolePermissionKeys(systemAdminRole); got != chain(sortedCopy(adminTemplate.DefaultPermissions)) {
		t.Fatalf("未选择角色被改写: %q", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action='preset.restore' AND outcome='success'`); got != 1 {
		t.Fatalf("恢复审计 = %d", got)
	}
	// 令牌单次使用。
	if _, err := env.service.Restore(ctx, env.local, preset.RestoreRequest{Token: preview.Token}); !errors.Is(err, preset.ErrPreviewRequired) {
		t.Fatalf("重复使用令牌错误 = %v，期望 ErrPreviewRequired", err)
	}
}

// TestPreviewStaleAndGuardRejectionKeepDataUnchanged 验收拒绝路径：预览后状态变化
// 需重新预览；委派 Guard 拒绝时整次恢复回滚，业务数据不变（只有失败审计）。
func TestPreviewStaleAndGuardRejectionKeepDataUnchanged(t *testing.T) {
	env := prepareEnv(t, nil)
	ctx := context.Background()
	if _, err := env.service.Install(ctx, env.local, preset.InstallRequest{}); err != nil {
		t.Fatalf("初始化失败: %v", err)
	}
	supportRole := env.roleID("system", "support")
	env.exec(`DELETE FROM role_permissions WHERE role_id=? AND permission_id=?`,
		supportRole, env.permissionID("system", "support.cases.create"))

	preview, err := env.service.Preview(ctx, env.local, preset.PreviewRequest{
		Selections: []preset.RoleSelection{{ScopeID: "system", RoleKeys: []string{"support"}}},
	})
	if err != nil {
		t.Fatalf("预览失败: %v", err)
	}
	// 预览后人为再改动状态 → 摘要不一致，恢复必须要求重新预览。
	env.exec(`DELETE FROM role_permissions WHERE role_id=? AND permission_id=?`,
		supportRole, env.permissionID("system", "support.cases.read"))
	before := env.rolePermissionKeys(supportRole)
	if _, err := env.service.Restore(ctx, env.local, preset.RestoreRequest{Token: preview.Token}); !errors.Is(err, preset.ErrPreviewStale) {
		t.Fatalf("状态变化后的恢复错误 = %v，期望 ErrPreviewStale", err)
	}
	if got := env.rolePermissionKeys(supportRole); got != before {
		t.Fatalf("过期预览的拒绝路径改动了角色组合: %q", got)
	}

	// 重新预览后，用拒绝一切转授的 Guard 构造服务的恢复：整次事务回滚。
	if _, err := env.service.Preview(ctx, env.local, preset.PreviewRequest{
		Selections: []preset.RoleSelection{{ScopeID: "system", RoleKeys: []string{"support"}}},
	}); err != nil {
		t.Fatalf("重新预览失败: %v", err)
	}
	denyService, err := preset.New(preset.Options{
		Store: env.store, Audit: env.recorder, Transfers: denyTransfersForTest(),
		Catalog: env.catalog, Now: env.clock.Now, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("构造拒绝 Guard 服务失败: %v", err)
	}
	denyPreview, err := denyService.Preview(ctx, env.local, preset.PreviewRequest{
		Selections: []preset.RoleSelection{{ScopeID: "system", RoleKeys: []string{"support"}}},
	})
	if err != nil {
		t.Fatalf("拒绝服务预览失败: %v", err)
	}
	_, restoreErr := denyService.Restore(ctx, env.local, preset.RestoreRequest{Token: denyPreview.Token})
	if !errors.Is(restoreErr, delegation.ErrAccessDenied) {
		t.Fatalf("Guard 拒绝错误 = %v，期望 delegation.ErrAccessDenied", restoreErr)
	}
	if code := preset.CodeOf(restoreErr); code != preset.CodeAccessDenied {
		t.Fatalf("Guard 拒绝错误码 = %q，期望 ACCESS_DENIED", code)
	}
	if got := env.rolePermissionKeys(supportRole); got != before {
		t.Fatalf("Guard 拒绝路径改动了角色组合: %q -> %q", before, got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action='preset.restore' AND outcome='failure'`); got < 1 {
		t.Fatalf("Guard 拒绝未留下失败审计")
	}
}

// denyTransfersForTest 是全部拒绝的 Guard，用于证明恢复写入路径确实接入同一 Guard。
func denyTransfersForTest() delegation.GuardFuncs {
	deny := func(context.Context, audit.Tx, audit.Actor, string, []delegation.PermissionRef, []delegation.Target) error {
		return delegation.ErrAccessDenied
	}
	return delegation.GuardFuncs{
		Access: deny,
		Assignment: func(context.Context, audit.Tx, audit.Actor, string, []delegation.PermissionRef, delegation.Target) error {
			return delegation.ErrAccessDenied
		},
		Activation:  deny,
		Restoration: func(context.Context, audit.Tx, audit.Actor, string) error { return delegation.ErrAccessDenied },
	}
}

// TestApplicationTemplatesIsolatedAndWholeRestore 验收按应用模板生成、不同应用隔离
// 以及显式整体恢复（多个作用范围各自恢复，不共用跨应用记录）。
func TestApplicationTemplatesIsolatedAndWholeRestore(t *testing.T) {
	env := prepareEnv(t, nil)
	ctx := context.Background()
	env.createApplication(appA, "active")
	env.createApplication(appB, "active")
	env.createApplication(appOff, "disabled")

	if _, err := env.service.Install(ctx, env.local, preset.InstallRequest{}); err != nil {
		t.Fatalf("系统初始化失败: %v", err)
	}
	resultA, err := env.service.InstallApplicationScope(ctx, env.local, appA)
	if err != nil {
		t.Fatalf("应用 A 模板初始化失败: %v", err)
	}
	resultB, err := env.service.InstallApplicationScope(ctx, env.local, appB)
	if err != nil {
		t.Fatalf("应用 B 模板初始化失败: %v", err)
	}
	if len(resultA.CreatedRoles) != len(env.catalog.ApplicationRoles) || len(resultB.CreatedRoles) != len(env.catalog.ApplicationRoles) {
		t.Fatalf("应用角色模板生成数量 = %d/%d", len(resultA.CreatedRoles), len(resultB.CreatedRoles))
	}
	if resultA.ScopeID != appA || resultB.ScopeID != appB {
		t.Fatalf("应用模板作用范围错误: %s/%s", resultA.ScopeID, resultB.ScopeID)
	}
	// 不同应用各自独立记录，不共用跨应用记录。
	roleA := env.roleID(appA, "app_admin")
	roleB := env.roleID(appB, "app_admin")
	if roleA == roleB {
		t.Fatalf("应用 A/B 共用了同一个角色记录")
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM roles WHERE scope_id IN (?,?)`, appA, appB); got != 2*len(env.catalog.ApplicationRoles) {
		t.Fatalf("应用角色行数 = %d", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM user_groups WHERE scope_id IN (?,?)`, appA, appB); got != 2*len(env.catalog.ApplicationGroups) {
		t.Fatalf("应用用户组行数 = %d", got)
	}
	// 应用范围不创建系统权限，也没有任何角色分配。
	if got := env.queryInt(`SELECT COUNT(*) FROM permissions WHERE scope_id=?`, appA); got != 0 {
		t.Fatalf("应用范围不应预置权限，实际 %d", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM user_roles`); got != 0 {
		t.Fatalf("应用模板不应分配角色")
	}
	// 停用应用拒绝初始化模板且不写入任何行。
	before := env.queryInt(`SELECT COUNT(*) FROM roles WHERE scope_id=?`, appOff)
	if _, err := env.service.InstallApplicationScope(ctx, env.local, appOff); !errors.Is(err, preset.ErrApplicationInactive) {
		t.Fatalf("停用应用初始化错误 = %v，期望 ErrApplicationInactive", err)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM roles WHERE scope_id=?`, appOff); got != before {
		t.Fatalf("停用应用拒绝路径写入了角色行")
	}

	// 整体恢复：显式 All 展开为已初始化的三个作用范围，并各自恢复。
	env.exec(`DELETE FROM role_permissions WHERE role_id=?`, roleA)
	env.exec(`DELETE FROM role_permissions WHERE role_id=?`, env.roleID("system", "auditor"))
	preview, err := env.service.Preview(ctx, env.local, preset.PreviewRequest{All: true})
	if err != nil {
		t.Fatalf("整体恢复预览失败: %v", err)
	}
	if !preview.All || len(preview.Selections) != 3 {
		t.Fatalf("整体恢复选择 = %d 个作用范围，期望 3", len(preview.Selections))
	}
	if _, err := env.service.Restore(ctx, env.local, preset.RestoreRequest{Token: preview.Token}); err != nil {
		t.Fatalf("整体恢复失败: %v", err)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM preset_installations`); got != 3 {
		t.Fatalf("整体恢复后版本记录 = %d，期望 3", got)
	}
	// 应用 A 模板角色没有默认权限，恢复不改变其组合（保持空）。
	if got := env.rolePermissionKeys(roleA); got != "" {
		t.Fatalf("应用角色恢复后不应有系统权限: %q", got)
	}
}

// TestRestoreRequiresExplicitSelection 验收“只恢复明确选择的目录/角色”：既不显式
// 选择也不显式整体恢复时拒绝；预览与整体恢复互斥。
func TestRestoreRequiresExplicitSelection(t *testing.T) {
	env := prepareEnv(t, nil)
	ctx := context.Background()
	if _, err := env.service.Preview(ctx, env.local, preset.PreviewRequest{}); !errors.Is(err, preset.ErrInvalidRequest) {
		t.Fatalf("空选择预览错误 = %v，期望 ErrInvalidRequest", err)
	}
	if _, err := env.service.Preview(ctx, env.local, preset.PreviewRequest{All: true,
		Selections: []preset.RoleSelection{{ScopeID: "system", RoleKeys: []string{"support"}}}}); !errors.Is(err, preset.ErrInvalidRequest) {
		t.Fatalf("整体+显式选择错误 = %v，期望 ErrInvalidRequest", err)
	}
	// 未初始化时恢复被拒绝，提示先初始化。
	if _, err := env.service.Preview(ctx, env.local, preset.PreviewRequest{
		Selections: []preset.RoleSelection{{ScopeID: "system", RoleKeys: []string{"support"}}},
	}); !errors.Is(err, preset.ErrInvalidRequest) {
		t.Fatalf("未初始化恢复预览错误 = %v，期望 ErrInvalidRequest", err)
	}
}

// TestCallerAndOptionGuards 验收 fail-closed：非受信调用者、缺少依赖或缺少委派检查器
// 的服务不可用。
func TestCallerAndOptionGuards(t *testing.T) {
	env := prepareEnv(t, nil)
	ctx := context.Background()
	if _, err := env.service.Install(ctx, preset.Caller{}, preset.InstallRequest{}); !errors.Is(err, preset.ErrInvalidRequest) {
		t.Fatalf("空调用者错误 = %v，期望 ErrInvalidRequest", err)
	}
	if _, err := env.service.Install(ctx, env.system, preset.InstallRequest{ScopeID: "bad_scope"}); !errors.Is(err, preset.ErrInvalidRequest) {
		t.Fatalf("非法作用范围错误 = %v，期望 ErrInvalidRequest", err)
	}
	if _, err := preset.New(preset.Options{}); !errors.Is(err, preset.ErrOptionsInvalid) {
		t.Fatalf("空选项错误 = %v，期望 ErrOptionsInvalid", err)
	}
	if _, err := preset.New(preset.Options{Store: env.store, Audit: env.recorder}); !errors.Is(err, preset.ErrOptionsInvalid) {
		t.Fatalf("缺少委派 Guard 错误 = %v，期望 ErrOptionsInvalid", err)
	}
}

// TestNewRejectsCatalogIncomplete 验收不完整目录不得发布：缺少说明或 root_only 权限
// 被组合进普通角色时必须拒绝构造。
func TestNewRejectsCatalogIncomplete(t *testing.T) {
	env := prepareEnv(t, nil)
	cases := []struct {
		name   string
		mutate func(*preset.Catalog)
	}{
		{"缺少说明", func(catalog *preset.Catalog) {
			catalog.Permissions[0].Limits = ""
		}},
		{"root_only 权限进入普通角色", func(catalog *preset.Catalog) {
			catalog.Roles[0].DefaultPermissions = append(catalog.Roles[0].DefaultPermissions, "backups.restore")
		}},
		{"root 角色", func(catalog *preset.Catalog) {
			catalog.Roles[0].Key = "root_admin"
		}},
		{"版本非法", func(catalog *preset.Catalog) {
			catalog.Version = "1.0"
		}},
		{"默认用户组不存在", func(catalog *preset.Catalog) {
			catalog.Roles[0].DefaultGroupKey = "missing-group"
		}},
		{"应用角色默认组不存在", func(catalog *preset.Catalog) {
			catalog.ApplicationRoles[0].DefaultGroupKey = "missing-app-group"
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			catalog := preset.DefaultCatalog()
			test.mutate(catalog)
			if _, err := preset.New(preset.Options{Store: env.store, Audit: env.recorder,
				Transfers: allowTransfersForTest(), Catalog: catalog}); err == nil {
				t.Fatalf("不完整目录构造成功，期望拒绝")
			}
		})
	}
}

// TestInstallSyncsPermissionTextIdempotently 验收权限说明随版本同步：升级到改过
// 文案的目录后必须真实写入新说明；重复安装收敛为“无变化”，不得永远报说明更新。
func TestInstallSyncsPermissionTextIdempotently(t *testing.T) {
	const newName = "查看求助单（新版名称）"
	const newSummary = "按获准范围查看脱敏求助单（新版说明）。"
	env := prepareEnv(t, func(catalog *preset.Catalog) {
		catalog.Version = "1.1.0"
		for index := range catalog.Permissions {
			if catalog.Permissions[index].Key == "support.cases.read" {
				catalog.Permissions[index].Name = newName
				catalog.Permissions[index].Summary = newSummary
			}
		}
	})
	ctx := context.Background()
	legacy := prepareLegacyEnv(t, env, "1.0.0")
	if _, err := legacy.service.Install(ctx, legacy.local, preset.InstallRequest{}); err != nil {
		t.Fatalf("1.0.0 初始化失败: %v", err)
	}
	oldName, oldDescription := env.permissionText("system", "support.cases.read")
	if oldName == newName {
		t.Fatalf("准备阶段旧文案未生效")
	}
	// 升级到 1.1.0：只改文案，必须真实写入；角色组合不因文案改动而变化。
	upgraded, err := env.service.Install(ctx, env.local, preset.InstallRequest{})
	if err != nil {
		t.Fatalf("1.1.0 升级失败: %v", err)
	}
	if !upgraded.Upgraded || !upgraded.Changed {
		t.Fatalf("升级结果 = %+v，期望 Upgraded/Changed", upgraded)
	}
	name, description := env.permissionText("system", "support.cases.read")
	if name != newName {
		t.Fatalf("升级后权限名称 = %q，期望 %q", name, newName)
	}
	definition := findPermission(t, env.catalog.Permissions, "support.cases.read")
	wantDescription := definition.Summary + "｜范围：" + definition.Scope
	if description != wantDescription {
		t.Fatalf("升级后权限说明 = %q，期望 %q（原 %q）", description, wantDescription, oldDescription)
	}
	// 重复安装：无变化、幂等收敛，且预览不再报告说明更新。
	again, err := env.service.Install(ctx, env.local, preset.InstallRequest{})
	if err != nil {
		t.Fatalf("重复安装失败: %v", err)
	}
	if again.Changed || !again.UpToDate || len(again.CreatedPermissions) != 0 {
		t.Fatalf("重复安装结果 = %+v，期望无变化且 UpToDate", again)
	}
	preview, err := env.service.Preview(ctx, env.local, preset.PreviewRequest{
		Selections: []preset.RoleSelection{{ScopeID: "system", RoleKeys: []string{"support"}}},
	})
	if err != nil {
		t.Fatalf("预览失败: %v", err)
	}
	if preview.Summary.UpdatePermissionTexts != 0 || preview.Summary.TotalChanges() != 0 {
		t.Fatalf("重复安装后预览仍报告变化: %+v", preview.Summary)
	}
}

// TestRestoreEarlyRejectionsWriteFailureAudit 验收事务前拒绝也留失败审计：令牌缺失、
// 伪造、过期、不属于当前操作者、摘要过期都必须写 preset.restore_failed，且不写成功
// 审计、不改变业务数据。
func TestRestoreEarlyRejectionsWriteFailureAudit(t *testing.T) {
	env := prepareEnv(t, nil)
	ctx := context.Background()
	if _, err := env.service.Install(ctx, env.local, preset.InstallRequest{}); err != nil {
		t.Fatalf("初始化失败: %v", err)
	}
	failureCount := func(reason string) int {
		return env.queryInt(`SELECT COUNT(*) FROM audit_events
WHERE action='preset.restore_failed' AND outcome='failure' AND reason_code=?`, reason)
	}
	successCount := func() int {
		return env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action='preset.restore' AND outcome='success'`)
	}
	selection := preset.PreviewRequest{
		Selections: []preset.RoleSelection{{ScopeID: "system", RoleKeys: []string{"support"}}},
	}
	// 1. 空令牌。
	if _, err := env.service.Restore(ctx, env.local, preset.RestoreRequest{}); !errors.Is(err, preset.ErrPreviewRequired) {
		t.Fatalf("空令牌错误 = %v，期望 ErrPreviewRequired", err)
	}
	if got := failureCount("preview_token_missing"); got != 1 {
		t.Fatalf("空令牌失败审计 = %d，期望 1", got)
	}
	// 2. 伪造令牌。
	if _, err := env.service.Restore(ctx, env.local, preset.RestoreRequest{Token: "deadbeef"}); !errors.Is(err, preset.ErrPreviewRequired) {
		t.Fatalf("伪造令牌错误 = %v，期望 ErrPreviewRequired", err)
	}
	if got := failureCount("preview_token_unknown"); got != 1 {
		t.Fatalf("伪造令牌失败审计 = %d，期望 1", got)
	}
	// 3. 过期令牌。
	expired, err := env.service.Preview(ctx, env.local, selection)
	if err != nil {
		t.Fatalf("预览失败: %v", err)
	}
	env.clock.now = env.clock.now.Add(preset.DefaultPreviewTTL + time.Minute)
	if _, err := env.service.Restore(ctx, env.local, preset.RestoreRequest{Token: expired.Token}); !errors.Is(err, preset.ErrPreviewRequired) {
		t.Fatalf("过期令牌错误 = %v，期望 ErrPreviewRequired", err)
	}
	if got := failureCount("preview_token_expired"); got != 1 {
		t.Fatalf("过期令牌失败审计 = %d，期望 1", got)
	}
	env.clock.now = env.clock.now.Add(-(preset.DefaultPreviewTTL + time.Minute))
	// 4. 他人令牌。
	otherActorPreview, err := env.service.Preview(ctx, env.local, selection)
	if err != nil {
		t.Fatalf("预览失败: %v", err)
	}
	if _, err := env.service.Restore(ctx, env.system, preset.RestoreRequest{Token: otherActorPreview.Token}); !errors.Is(err, preset.ErrPreviewRequired) {
		t.Fatalf("他人令牌错误 = %v，期望 ErrPreviewRequired", err)
	}
	if got := failureCount("preview_token_other_actor"); got != 1 {
		t.Fatalf("他人令牌失败审计 = %d，期望 1", got)
	}
	// 5. 摘要过期（预览后状态变化）。
	stalePreview, err := env.service.Preview(ctx, env.local, selection)
	if err != nil {
		t.Fatalf("预览失败: %v", err)
	}
	env.exec(`UPDATE permissions SET name='并发改名' WHERE scope_id='system' AND permission_key='reports.read'`)
	if _, err := env.service.Restore(ctx, env.local, preset.RestoreRequest{Token: stalePreview.Token}); !errors.Is(err, preset.ErrPreviewStale) {
		t.Fatalf("摘要过期错误 = %v，期望 ErrPreviewStale", err)
	}
	if got := failureCount("preview_digest_stale"); got != 1 {
		t.Fatalf("摘要过期失败审计 = %d，期望 1", got)
	}
	// 所有拒绝都不产生成功恢复审计，且并发改名未被覆盖。
	if got := successCount(); got != 0 {
		t.Fatalf("拒绝路径出现了 %d 条成功恢复审计", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM permissions WHERE scope_id='system' AND permission_key='reports.read' AND name='并发改名'`); got != 1 {
		t.Fatalf("拒绝路径覆盖了并发修改")
	}
}

// racingStore 在恢复计划读取用户组之后模拟另一个事务提交的并发修改：先按旧状态
// 返回计划读取结果，再直接改库，用于验证恢复的事务内条件校验会拒绝旧计划。
type racingStore struct {
	*presetsqlite.Store
	raw             *storagesqlite.Store
	mu              sync.Mutex
	listGroupsCalls int
	mutateSQL       string
}

// ListGroups 在第 2 次调用（恢复计划读取）之后执行注入的并发修改 SQL。
func (s *racingStore) ListGroups(ctx context.Context, scopeID string) ([]preset.GroupRecord, error) {
	records, err := s.Store.ListGroups(ctx, scopeID)
	s.mu.Lock()
	s.listGroupsCalls++
	call := s.listGroupsCalls
	s.mu.Unlock()
	if err == nil && call >= 2 && s.mutateSQL != "" {
		if _, execErr := s.raw.ExecContext(context.Background(), s.mutateSQL); execErr != nil {
			return nil, execErr
		}
	}
	return records, err
}

// TestRestoreRejectsConcurrentModificationInsideTransaction 验收 TOCTOU 修复：恢复
// 计划复核之后、事务写入之前的并发修改必须在事务内被指纹校验拒绝，不能由旧计划
// 覆盖新状态；拒绝后业务数据保持并发修改结果并留下失败审计。
func TestRestoreRejectsConcurrentModificationInsideTransaction(t *testing.T) {
	env := prepareEnv(t, func(catalog *preset.Catalog) {
		catalog.Version = "1.1.0"
		for index := range catalog.Permissions {
			if catalog.Permissions[index].Key == "audit.read" {
				catalog.Permissions[index].Name = "查看安全记录（新版名称）"
			}
		}
	})
	ctx := context.Background()
	legacy := prepareLegacyEnv(t, env, "1.0.0")
	if _, err := legacy.service.Install(ctx, legacy.local, preset.InstallRequest{}); err != nil {
		t.Fatalf("1.0.0 初始化失败: %v", err)
	}
	store := &racingStore{Store: env.store, raw: env.raw}
	service, err := preset.New(preset.Options{
		Store: store, Audit: env.recorder, Transfers: allowTransfersForTest(),
		Catalog: env.catalog, Now: env.clock.Now, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("构造服务失败: %v", err)
	}
	preview, err := service.Preview(ctx, env.local, preset.PreviewRequest{
		Selections: []preset.RoleSelection{{ScopeID: "system", RoleKeys: []string{"support"}}},
	})
	if err != nil {
		t.Fatalf("预览失败: %v", err)
	}
	before := env.queryInt(`SELECT COUNT(*) FROM audit_events
WHERE action='preset.restore' AND outcome='failure'`)
	// 恢复计划读取用户组后，另一事务把 audit.read 改成自定义名称；计划里仍持有
	// 目录新文案（textUpdates），旧实现会在写入时覆盖该并发修改。
	store.mutateSQL = `UPDATE permissions SET name='并发自定义名称'
WHERE scope_id='system' AND permission_key='audit.read'`
	_, err = service.Restore(ctx, env.local, preset.RestoreRequest{Token: preview.Token})
	if !errors.Is(err, preset.ErrPreviewStale) {
		t.Fatalf("并发修改后的恢复错误 = %v，期望 ErrPreviewStale", err)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM permissions
WHERE scope_id='system' AND permission_key='audit.read' AND name='并发自定义名称'`); got != 1 {
		t.Fatalf("旧计划覆盖了事务前提交的并发修改")
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM audit_events
WHERE action='preset.restore' AND outcome='failure'`); got != before+1 {
		t.Fatalf("事务内拒绝的失败审计 = %d，期望 %d", got, before+1)
	}
}

// TestRestoreRootOnlyReenableOnlyForLocalAdmin 验收 root_only 重启用通道规则：与
// internal/permission 一致，只有受限本地受控操作者可重新启用 root_only 权限（备份
// 恢复、审计清理、敏感策略）；系统与其他通道一律跳过并在差异/审计中明确记录。
func TestRestoreRootOnlyReenableOnlyForLocalAdmin(t *testing.T) {
	env := prepareEnv(t, nil)
	ctx := context.Background()
	if _, err := env.service.Install(ctx, env.local, preset.InstallRequest{}); err != nil {
		t.Fatalf("初始化失败: %v", err)
	}
	env.exec(`UPDATE permissions SET enabled=0
WHERE scope_id='system' AND permission_key IN ('backups.restore','reports.read')`)
	selection := preset.PreviewRequest{
		Selections: []preset.RoleSelection{{ScopeID: "system", RoleKeys: []string{"support"}}},
	}
	// 本地受控操作者：root_only 与其他预设权限都按既有 Guard 路径计划恢复启用。
	localPreview, err := env.service.Preview(ctx, env.local, selection)
	if err != nil {
		t.Fatalf("本地预览失败: %v", err)
	}
	localReenable := map[string]bool{}
	for _, scope := range localPreview.Scopes {
		if len(scope.SkippedRootOnlyReenables) != 0 {
			t.Fatalf("本地受控操作者不应跳过 root_only 重启用: %+v", scope.SkippedRootOnlyReenables)
		}
		for _, change := range scope.ReenablePermissions {
			localReenable[change.Key] = true
		}
	}
	if !localReenable["backups.restore"] || !localReenable["reports.read"] {
		t.Fatalf("本地预览恢复项 = %+v，期望含 root_only 与普通权限", localReenable)
	}
	if _, err := env.service.Restore(ctx, env.local, preset.RestoreRequest{Token: localPreview.Token}); err != nil {
		t.Fatalf("本地恢复失败: %v", err)
	}
	if got := env.queryInt(`SELECT enabled FROM permissions WHERE scope_id='system' AND permission_key='backups.restore'`); got != 1 {
		t.Fatalf("本地受控操作者未能恢复 root_only 权限启用状态")
	}
	// 系统通道：按 permission 规则不得启停 root_only，预览必须展示跳过且恢复不启用。
	env.exec(`UPDATE permissions SET enabled=0 WHERE scope_id='system' AND permission_key='backups.restore'`)
	systemPreview, err := env.service.Preview(ctx, env.system, selection)
	if err != nil {
		t.Fatalf("系统预览失败: %v", err)
	}
	hasSkipped := false
	for _, scope := range systemPreview.Scopes {
		for _, change := range scope.ReenablePermissions {
			if change.Key == "backups.restore" {
				t.Fatalf("系统通道预览不应计划重新启用 root_only 权限")
			}
		}
		for _, change := range scope.SkippedRootOnlyReenables {
			if change.Key == "backups.restore" {
				hasSkipped = true
			}
		}
	}
	if !hasSkipped {
		t.Fatalf("系统通道预览未展示被跳过的 root_only 恢复项")
	}
	if _, err := env.service.Restore(ctx, env.system, preset.RestoreRequest{Token: systemPreview.Token}); err != nil {
		t.Fatalf("系统恢复失败: %v", err)
	}
	if got := env.queryInt(`SELECT enabled FROM permissions WHERE scope_id='system' AND permission_key='backups.restore'`); got != 0 {
		t.Fatalf("系统通道恢复重新启用了 root_only 权限，违反 permission 规则")
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action='preset.restore'
AND outcome='success' AND detail_json LIKE '%root_only_reenable_skipped%'`); got < 1 {
		t.Fatalf("恢复审计未记录被跳过的 root_only 权限")
	}
}

// TestWholeRestoreSkipsInactiveApplication 验收整体恢复跳过已停用应用并报告，不因
// 单个停用应用失败；显式选择停用应用仍明确拒绝且错误文本带应用标识、不重复。
func TestWholeRestoreSkipsInactiveApplication(t *testing.T) {
	env := prepareEnv(t, nil)
	ctx := context.Background()
	env.createApplication(appA, "active")
	if _, err := env.service.Install(ctx, env.local, preset.InstallRequest{}); err != nil {
		t.Fatalf("系统初始化失败: %v", err)
	}
	if _, err := env.service.InstallApplicationScope(ctx, env.local, appA); err != nil {
		t.Fatalf("应用初始化失败: %v", err)
	}
	env.exec(`UPDATE applications SET status='disabled' WHERE id=?`, appA)

	preview, err := env.service.Preview(ctx, env.local, preset.PreviewRequest{All: true})
	if err != nil {
		t.Fatalf("整体恢复预览不应因停用应用失败: %v", err)
	}
	if len(preview.SkippedScopes) != 1 || preview.SkippedScopes[0].ScopeID != appA ||
		preview.SkippedScopes[0].Reason != "application_inactive" {
		t.Fatalf("整体恢复跳过清单 = %+v", preview.SkippedScopes)
	}
	if len(preview.Selections) != 1 || preview.Selections[0].ScopeID != "system" {
		t.Fatalf("整体恢复选择 = %+v，期望只含系统范围", preview.Selections)
	}
	restored, err := env.service.Restore(ctx, env.local, preset.RestoreRequest{Token: preview.Token})
	if err != nil {
		t.Fatalf("整体恢复失败: %v", err)
	}
	if len(restored.SkippedScopes) != 1 || restored.SkippedScopes[0].ScopeID != appA {
		t.Fatalf("恢复结果跳过清单 = %+v", restored.SkippedScopes)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM preset_installations WHERE scope_id=?`, appA); got != 1 {
		t.Fatalf("停用应用初始化记录异常 = %d", got)
	}
	// 显式选择停用应用：拒绝，错误文本带具体应用且不重复。
	_, err = env.service.Preview(ctx, env.local, preset.PreviewRequest{
		Selections: []preset.RoleSelection{{ScopeID: appA, RoleKeys: []string{"app_admin"}}},
	})
	if !errors.Is(err, preset.ErrApplicationInactive) {
		t.Fatalf("显式选择停用应用错误 = %v，期望 ErrApplicationInactive", err)
	}
	if !strings.Contains(err.Error(), appA) {
		t.Fatalf("停用应用错误未带应用标识: %v", err)
	}
	if got := strings.Count(err.Error(), "已停用"); got != 1 {
		t.Fatalf("停用应用错误文本重复 %d 次: %v", got, err)
	}
}

// findPermission 在权限目录中查找机器标识。
func findPermission(t *testing.T, definitions []preset.PermissionDefinition, key string) preset.PermissionDefinition {
	t.Helper()
	for _, definition := range definitions {
		if definition.Key == key {
			return definition
		}
	}
	t.Fatalf("权限定义 %q 不存在", key)
	return preset.PermissionDefinition{}
}

// findRole 在角色模板中查找机器标识。
func findRole(t *testing.T, templates []preset.RoleTemplate, key string) preset.RoleTemplate {
	t.Helper()
	for _, template := range templates {
		if template.Key == key {
			return template
		}
	}
	t.Fatalf("角色模板 %q 不存在", key)
	return preset.RoleTemplate{}
}

// sortedCopy 返回排序后的字符串副本。
func sortedCopy(values []string) []string {
	result := append([]string(nil), values...)
	for i := 0; i < len(result); i++ {
		for j := i + 1; j < len(result); j++ {
			if result[j] < result[i] {
				result[i], result[j] = result[j], result[i]
			}
		}
	}
	return result
}
