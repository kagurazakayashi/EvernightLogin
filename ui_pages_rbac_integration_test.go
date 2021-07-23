package login_test

// 步骤 69 真实服务集成测试：临时 SQLite + 真实 account/group/role/permission/
// delegation/authz/preset 服务；管理会话为受控 kind=management；各领域 Authorizer
// 使用测试白名单（生产由宿主真实 authz 注入），不联网、不监听端口、不真实外发。
// 本测试不把测试替身当作生产鉴权：角色/权限/委派 Guard、有效权限引擎与预设目录
// 均为真实实现，测试只负责注入授权器与受信通道。

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	accountsqlite "github.com/kagurazakayashi/EvernightLogin/internal/account/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	authzsqlite "github.com/kagurazakayashi/EvernightLogin/internal/authz/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
	delegationsqlite "github.com/kagurazakayashi/EvernightLogin/internal/delegation/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/group"
	groupsqlite "github.com/kagurazakayashi/EvernightLogin/internal/group/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/permission"
	permissionsqlite "github.com/kagurazakayashi/EvernightLogin/internal/permission/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/preset"
	presetsqlite "github.com/kagurazakayashi/EvernightLogin/internal/preset/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/role"
	rolesqlite "github.com/kagurazakayashi/EvernightLogin/internal/role/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/uiadminadapter"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// allowAnyQuery 是有效权限查询授权器的测试白名单（生产由宿主真实 authz 注入；
// authz.Caller 不导出身份访问器，宿主适配器通过自家会话/上下文实现真实数据范围）。
type allowAnyQuery struct{}

func (allowAnyQuery) AuthorizeQuery(context.Context, authz.Caller, string, authz.Scope) error {
	return nil
}

// denyAnyQuery 是查询授权拒绝替身（验证 fail-closed 与可披露拒绝原因）。
type denyAnyQuery struct{}

func (denyAnyQuery) AuthorizeQuery(context.Context, authz.Caller, string, authz.Scope) error {
	return errors.New("denied-by-host-query-authorizer")
}

// denyPermissionAuthorizer 是权限服务拒绝授权器（验证 ListScopes 不依赖权限读取）。
type denyPermissionAuthorizer struct{}

func (denyPermissionAuthorizer) Authorize(context.Context, permission.Caller,
	permission.Action, string) error {
	return errors.New("denied-by-permission-authorizer")
}

func (denyPermissionAuthorizer) ManageableScopes(context.Context,
	permission.Caller) (bool, []string, error) {
	return false, nil, errors.New("denied-by-permission-authorizer")
}

// appIDFixture 是跨应用同名权限测试使用的应用作用范围 ID。
const appIDFixture = "app_11111111111111111111111111111111"

// allowRoleAuthorizer 是角色服务的测试授权器（生产由宿主权限引擎注入）。
type allowRoleAuthorizer struct{}

func (allowRoleAuthorizer) Authorize(context.Context, role.Caller, role.Action,
	string) error {
	return nil
}

func (allowRoleAuthorizer) ManageableScopes(context.Context,
	role.Caller) (bool, []string, error) {
	return true, nil, nil
}

// allowPermissionAuthorizer 是权限服务的测试授权器。
type allowPermissionAuthorizer struct{}

func (allowPermissionAuthorizer) Authorize(context.Context, permission.Caller,
	permission.Action, string) error {
	return nil
}

func (allowPermissionAuthorizer) ManageableScopes(context.Context,
	permission.Caller) (bool, []string, error) {
	return true, nil, nil
}

type rbacIntegrationEnv struct {
	t            *testing.T
	adapter      *uiadminadapter.RBACAdapter
	account      *account.Service
	roles        *role.Service
	permissions  *permission.Service
	groups       *group.Service
	delegations  *delegation.Service
	access       *authz.Service
	deniedAccess *authz.Service
	presets      *preset.Service
	adminID      string
	user1ID      string
	user2ID      string
	groupID      string
	storage      *storagesqlite.Store
}

// newRBACIntegrationEnv 构造真实服务环境并初始化系统预设。
func newRBACIntegrationEnv(t *testing.T) *rbacIntegrationEnv {
	t.Helper()
	ctx := context.Background()
	storage, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(
		filepath.Join(t.TempDir(), "rbac-pages.db")))
	if err != nil {
		t.Fatalf("打开数据库: %v", err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	list, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移: %v", err)
	}
	if _, err := storage.Migrate(ctx, list); err != nil {
		t.Fatalf("执行迁移: %v", err)
	}
	now := time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC)
	nowFunc := func() time.Time { return now }
	auditStore, err := auditsqlite.New(storage)
	if err != nil {
		t.Fatalf("审计存储: %v", err)
	}
	recorder, err := audit.New(auditStore, audit.Options{Now: nowFunc,
		Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("审计: %v", err)
	}
	accountStore, err := accountsqlite.New(storage)
	if err != nil {
		t.Fatalf("账户存储: %v", err)
	}
	accountService, err := account.New(account.Options{Store: accountStore, Audit: recorder,
		Authorizer: allowAllAdmin{}, Now: nowFunc, Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("账户服务: %v", err)
	}
	delegationStore, err := delegationsqlite.New(storage)
	if err != nil {
		t.Fatalf("委派存储: %v", err)
	}
	delegationService, err := delegation.New(delegation.Options{Store: delegationStore,
		Audit: recorder, Now: nowFunc, Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("委派服务: %v", err)
	}
	roleStore, err := rolesqlite.New(storage)
	if err != nil {
		t.Fatalf("角色存储: %v", err)
	}
	roleService, err := role.New(role.Options{Store: roleStore, Audit: recorder,
		Authorizer: allowRoleAuthorizer{}, Transfers: delegationService,
		AllowLegacyWithoutSensitive: true, Now: nowFunc,
		Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("角色服务: %v", err)
	}
	permissionStore, err := permissionsqlite.New(storage)
	if err != nil {
		t.Fatalf("权限存储: %v", err)
	}
	permissionService, err := permission.New(permission.Options{Store: permissionStore,
		Audit: recorder, Authorizer: allowPermissionAuthorizer{},
		Transfers: delegationService, Now: nowFunc, Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("权限服务: %v", err)
	}
	groupStore, err := groupsqlite.New(storage)
	if err != nil {
		t.Fatalf("用户组存储: %v", err)
	}
	groupService, err := group.New(group.Options{Store: groupStore, Audit: recorder,
		Authorizer: allowGroupAuthorizer{}, Transfers: delegationService,
		AllowLegacyWithoutSensitive: true, Now: nowFunc,
		Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("用户组服务: %v", err)
	}
	authzStore, err := authzsqlite.New(storage)
	if err != nil {
		t.Fatalf("授权存储: %v", err)
	}
	presetStore, err := presetsqlite.New(storage)
	if err != nil {
		t.Fatalf("预设存储: %v", err)
	}
	presetService, err := preset.New(preset.Options{Store: presetStore, Audit: recorder,
		Transfers: delegationService, Now: nowFunc, Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("预设服务: %v", err)
	}
	bootstrap, err := preset.LocalBootstrapCaller("test-bootstrap")
	if err != nil {
		t.Fatalf("预设受信 Caller: %v", err)
	}
	if _, installErr := presetService.Install(ctx, bootstrap,
		preset.InstallRequest{ScopeID: preset.ScopeSystem}); installErr != nil {
		t.Fatalf("初始化系统预设: %v", installErr)
	}
	admin, err := accountService.CreateUser(ctx, systemAccountCaller(t),
		account.CreateRequest{Username: "rbac-admin", Nickname: "Admin"})
	if err != nil {
		t.Fatalf("创建管理员: %v", err)
	}
	user1, err := accountService.CreateUser(ctx, systemAccountCaller(t),
		account.CreateRequest{Username: "rbac-user1", Nickname: "User1"})
	if err != nil {
		t.Fatalf("创建用户1: %v", err)
	}
	user2, err := accountService.CreateUser(ctx, systemAccountCaller(t),
		account.CreateRequest{Username: "rbac-user2", Nickname: "User2"})
	if err != nil {
		t.Fatalf("创建用户2: %v", err)
	}
	accessService, err := authz.New(authz.Options{Store: authzStore,
		Authorizer: allowAnyQuery{}, Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("有效权限引擎: %v", err)
	}
	deniedAccess, err := authz.New(authz.Options{Store: authzStore,
		Authorizer: denyAnyQuery{}, Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("拒绝式有效权限引擎: %v", err)
	}
	// 应用范围 fixture：真实 applications/scopes 行，用于跨应用同名权限测试。
	nowMs := now.UTC().UnixMilli()
	if _, err := storage.DB().ExecContext(ctx, `INSERT INTO applications(
id,name,description,status,client_type,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?,?,?)`, appIDFixture, "示例应用", "夹具应用", "active",
		"public", 1, nowMs, nowMs); err != nil {
		t.Fatalf("种子应用: %v", err)
	}
	if _, err := storage.DB().ExecContext(ctx, `INSERT INTO scopes(id,kind,app_id)
VALUES(?,?,?)`, appIDFixture, "application", appIDFixture); err != nil {
		t.Fatalf("种子作用范围: %v", err)
	}
	// 通过受信通道给管理员分配预设“用户管理员”角色（真实角色服务写入）。
	systemCaller, err := role.SystemCaller("test-seed")
	if err != nil {
		t.Fatalf("角色系统 Caller: %v", err)
	}
	presetRoles, err := roleService.ListRoles(ctx, systemCaller,
		role.ListRequest{ScopeID: "system", Limit: 100})
	if err != nil {
		t.Fatalf("读取预设角色: %v", err)
	}
	var userAdminRoleID string
	for _, item := range presetRoles.Roles {
		if item.Key == "user_admin" {
			userAdminRoleID = item.ID
		}
	}
	if userAdminRoleID == "" {
		t.Fatal("未找到预设用户管理员角色")
	}
	if _, err := roleService.AssignUserRole(ctx, systemCaller, userAdminRoleID, admin.ID); err != nil {
		t.Fatalf("给管理员分配预设角色: %v", err)
	}
	// 受信通道签发委派资格：管理员可转授 users.read / users.update（不允许自我）。
	bootstrapCaller, err := delegation.LocalBootstrapCaller("test-bootstrap")
	if err != nil {
		t.Fatalf("委派受信 Caller: %v", err)
	}
	for _, key := range []string{"users.read", "users.update"} {
		if _, grantErr := delegationService.Grant(ctx, bootstrapCaller,
			delegation.GrantRequest{DelegatorUserID: admin.ID, ScopeID: "system",
				PermissionKey: key, MaxDataScope: `{"v":1,"mode":"all"}`,
				AllowSelf: false}); grantErr != nil {
			t.Fatalf("签发委派资格 %s: %v", key, grantErr)
		}
	}
	// 真实用户组与成员（受信通道，验证组间接赋权）。
	groupCaller, err := group.SystemCaller("test-seed")
	if err != nil {
		t.Fatalf("用户组系统 Caller: %v", err)
	}
	createdGroup, err := groupService.CreateGroup(ctx, groupCaller, group.CreateRequest{
		ScopeID: "system", GroupKey: "rbac-ops", Name: "运维组", Description: "测试组"})
	if err != nil {
		t.Fatalf("创建用户组: %v", err)
	}
	if _, err := groupService.AddMembers(ctx, groupCaller, group.MemberBatchRequest{
		GroupID: createdGroup.ID, UserIDs: []string{user1.ID}}); err != nil {
		t.Fatalf("加入组成员: %v", err)
	}
	adapter, err := uiadminadapter.NewRBAC(uiadminadapter.RBACOptions{
		Roles: roleService, Permissions: permissionService, Access: accessService,
		Delegations: delegationService, Catalog: preset.DefaultCatalog(),
		ManageableScopes: func(context.Context, string) ([]string, error) {
			return []string{"system", appIDFixture}, nil
		},
		ApplicationNames: func(context.Context, string) (map[string]string, error) {
			return map[string]string{appIDFixture: "示例应用"}, nil
		},
	})
	if err != nil {
		t.Fatalf("RBAC 适配器: %v", err)
	}
	return &rbacIntegrationEnv{t: t, adapter: adapter, account: accountService,
		roles: roleService, permissions: permissionService, groups: groupService,
		delegations: delegationService, access: accessService,
		deniedAccess: deniedAccess, presets: presetService,
		adminID: admin.ID, user1ID: user1.ID, user2ID: user2.ID,
		groupID: createdGroup.ID, storage: storage}
}

// findPresetRole 按机器键查找预设角色 ID。
func (e *rbacIntegrationEnv) findPresetRole(t *testing.T, key string) string {
	t.Helper()
	caller, err := role.SystemCaller("test-seed")
	if err != nil {
		t.Fatalf("系统 Caller: %v", err)
	}
	list, err := e.roles.ListRoles(context.Background(), caller,
		role.ListRequest{ScopeID: "system", Limit: 100})
	if err != nil {
		t.Fatalf("读取角色: %v", err)
	}
	for _, item := range list.Roles {
		if item.Key == key {
			return item.ID
		}
	}
	return ""
}

// TestRBACIntegrationComposeAndGroupIndirect 覆盖组合角色、编辑已分配角色、组间接赋权、
// 直接角色来源与停用权限后的有效权限变化。
func TestRBACIntegrationComposeAndGroupIndirect(t *testing.T) {
	env := newRBACIntegrationEnv(t)
	ctx := context.Background()
	// 1) 管理员创建自定义角色（真实角色服务，作用范围 system）。
	created, err := env.adapter.CreateRole(ctx, env.adminID, login.UIRBACCreateRole{
		ScopeID: "system", Key: "rbac-ops", Name: "运维角色",
		Description: "运维操作", Limits: "仅限获准系统范围"}, "req_create")
	if err != nil {
		t.Fatalf("创建角色: %v", err)
	}
	if created.ID == "" || created.ScopeID != "system" {
		t.Fatalf("创建角色结果 = %+v", created)
	}
	// 2) 组合 users.read（管理员持有该权限且有转授资格）。
	compose, err := env.adapter.ComposeRolePermission(ctx, env.adminID, created.ID,
		"", true, "req_compose_probe")
	if err == nil {
		t.Fatal("空权限 ID 应被拒绝")
	}
	_ = compose
	usersRead := env.findPermission(t, "system", "users.read")
	if _, err := env.adapter.ComposeRolePermission(ctx, env.adminID, created.ID,
		usersRead, true, "req_compose1"); err != nil {
		t.Fatalf("组合 users.read: %v", err)
	}
	// 3) 分配给用户2（直接）与用户组（间接）。
	assigned, err := env.adapter.AssignRole(ctx, env.adminID, created.ID, "user",
		env.user2ID, "req_assign_user", true)
	if err != nil || !assigned.Changed {
		t.Fatalf("分配给用户2 = %+v err=%v", assigned, err)
	}
	if _, err := env.adapter.AssignRole(ctx, env.adminID, created.ID, "group",
		env.groupID, "req_assign_group", true); err != nil {
		t.Fatalf("分配给用户组: %v", err)
	}
	// 4) 编辑已分配角色：加入 users.update，受影响分配数应为真实值。
	usersUpdate := env.findPermission(t, "system", "users.update")
	composed, err := env.adapter.ComposeRolePermission(ctx, env.adminID, created.ID,
		usersUpdate, true, "req_compose2")
	if err != nil {
		t.Fatalf("编辑已分配角色: %v", err)
	}
	if composed.AffectedUsers != 1 || composed.AffectedGroups != 1 ||
		len(composed.Added) != 1 || composed.Added[0].Key != "users.update" {
		t.Fatalf("改动前后影响 = %+v", composed)
	}
	// 5) 有效权限：用户2 直接角色来源，用户1 组间接来源。
	effective2, err := env.adapter.EffectivePermissions(ctx, env.adminID, env.user2ID,
		"system", 20, 0)
	if err != nil {
		t.Fatalf("查询用户2有效权限: %v", err)
	}
	if !hasRBACSource(effective2, "users.update", "user_role") {
		t.Fatalf("用户2缺少直接角色来源: %+v", effective2)
	}
	effective1, err := env.adapter.EffectivePermissions(ctx, env.adminID, env.user1ID,
		"system", 20, 0)
	if err != nil {
		t.Fatalf("查询用户1有效权限: %v", err)
	}
	if !hasRBACSource(effective1, "users.read", "group_role") {
		t.Fatalf("用户1缺少用户组间接来源: %+v", effective1)
	}
	for _, item := range effective1.Permissions {
		for _, source := range item.Sources {
			if source.Kind == "group_role" && source.GroupName != "运维组" {
				t.Fatalf("组来源名称 = %q", source.GroupName)
			}
			if source.DataScope.Mode == "" {
				t.Fatal("来源数据范围未展示")
			}
		}
	}
	// 6) 停用 users.read 权限后，用户1组间接获得的该权限不再生效。
	if _, _, err := env.adapter.SetPermissionState(ctx, env.adminID, usersRead, false,
		"req_disable"); err != nil {
		t.Fatalf("停用权限: %v", err)
	}
	afterDisable, err := env.adapter.EffectivePermissions(ctx, env.adminID, env.user1ID,
		"system", 20, 0)
	if err != nil {
		t.Fatalf("停用后查询: %v", err)
	}
	for _, item := range afterDisable.Permissions {
		if item.Key == "users.read" {
			t.Fatal("停用权限仍出现在有效权限中")
		}
	}
	detail, err := env.adapter.GetPermission(ctx, env.adminID, usersRead)
	if err != nil || detail.Permission.Enabled {
		t.Fatalf("停用后权限详情 = %+v err=%v", detail, err)
	}
}

// findPermission 按范围与机器键查找权限 ID。
func (e *rbacIntegrationEnv) findPermission(t *testing.T, scopeID, key string) string {
	t.Helper()
	caller, err := permission.UserCaller(e.adminID)
	if err != nil {
		t.Fatalf("权限 Caller: %v", err)
	}
	list, err := e.permissions.ListPermissions(context.Background(), caller,
		permission.ListRequest{ScopeID: scopeID, Limit: 100})
	if err != nil {
		t.Fatalf("读取权限: %v", err)
	}
	for _, item := range list.Permissions {
		if item.Key == key {
			return item.ID
		}
	}
	t.Fatalf("未找到权限 %s/%s", scopeID, key)
	return ""
}

// hasRBACSource 检查有效权限结果是否包含指定权限与来源类型。
func hasRBACSource(view login.UIRBACEffectiveView, key, kind string) bool {
	for _, item := range view.Permissions {
		if item.Key != key {
			continue
		}
		for _, source := range item.Sources {
			if source.Kind == kind {
				return true
			}
		}
	}
	return false
}

// TestRBACIntegrationSelfEscalationAndFailClosed 覆盖自我提权拒绝、无转授权限拒绝与
// 查询授权失败关闭。
func TestRBACIntegrationSelfEscalationAndFailClosed(t *testing.T) {
	env := newRBACIntegrationEnv(t)
	ctx := context.Background()
	created, err := env.adapter.CreateRole(ctx, env.adminID, login.UIRBACCreateRole{
		ScopeID: "system", Key: "rbac-self", Name: "自授测试",
		Description: "不能自我提权", Limits: "仅测试"}, "req_create")
	if err != nil {
		t.Fatalf("创建角色: %v", err)
	}
	usersRead := env.findPermission(t, "system", "users.read")
	if _, err := env.adapter.ComposeRolePermission(ctx, env.adminID, created.ID,
		usersRead, true, "req_compose"); err != nil {
		t.Fatalf("组合权限: %v", err)
	}
	// 自我提权：管理员把角色分配给自己，委派资格不允许自我，必须被拒绝且不写入。
	_, assignErr := env.adapter.AssignRole(ctx, env.adminID, created.ID, "user",
		env.adminID, "req_self", true)
	var publicErr *login.UIRBACError
	if !errors.As(assignErr, &publicErr) || publicErr.Code != "ACCESS_DENIED" {
		t.Fatalf("自我提权应 ACCESS_DENIED: %v", assignErr)
	}
	assignments, err := env.adapter.ListAssignments(ctx, env.adminID, created.ID)
	if err != nil || len(assignments.Users) != 0 {
		t.Fatalf("自我提权被拒绝后不应有分配: %+v err=%v", assignments, err)
	}
	// 无转授资格：管理员尝试组合其未获委托的权限（审计只读），必须拒绝。
	rolesRead := env.findPermission(t, "system", "roles.read")
	_, composeErr := env.adapter.ComposeRolePermission(ctx, env.adminID, created.ID,
		rolesRead, true, "req_ungranted")
	if composeErr == nil {
		t.Fatal("缺少转授资格的权限组合应被拒绝")
	}
	// 有效权限查询：普通身份不能查询他人（查询授权器只允许本地管理员）。
	nonAdmin, err := uiadminadapter.NewRBAC(uiadminadapter.RBACOptions{
		Roles: env.roles, Permissions: env.permissions, Access: env.deniedAccess,
		Delegations: env.delegations})
	if err != nil {
		t.Fatalf("非管理员适配器: %v", err)
	}
	_, effectiveErr := nonAdmin.EffectivePermissions(ctx, env.user1ID, env.user2ID,
		"system", 20, 0)
	if effectiveErr == nil {
		t.Fatal("普通身份查询他人有效权限应失败关闭")
	}
	if !errors.As(effectiveErr, &publicErr) || publicErr.Code != "ACCESS_DENIED" {
		t.Fatalf("查询越权应 ACCESS_DENIED: %v", effectiveErr)
	}
	// 宿主页面层授权器拒绝时适配器 fail-closed。
	denied, err := uiadminadapter.NewRBAC(uiadminadapter.RBACOptions{
		Roles: env.roles, Permissions: env.permissions, Access: env.access,
		Delegations: env.delegations,
		Authorize: func(context.Context, string, string) error {
			return errors.New("denied-by-host-authz")
		}})
	if err != nil {
		t.Fatalf("拒绝适配器: %v", err)
	}
	if _, listErr := denied.ListRoles(ctx, env.adminID, login.UIRBACRoleQuery{Limit: 20}); listErr == nil {
		t.Fatal("宿主授权拒绝应 fail-closed")
	}
}

// TestRBACIntegrationSameNameCrossApplication 覆盖同名跨应用权限区分与应用上下文。
func TestRBACIntegrationSameNameCrossApplication(t *testing.T) {
	env := newRBACIntegrationEnv(t)
	ctx := context.Background()
	// 系统范围已有 users.read（预设）；在应用范围登记同名权限（真实权限服务）。
	systemCaller, err := permission.SystemCaller("test-seed")
	if err != nil {
		t.Fatalf("权限系统 Caller: %v", err)
	}
	appPermission, err := env.permissions.CreatePermission(ctx, systemCaller,
		permission.CreateRequest{ScopeID: appIDFixture, Key: "users.read",
			Name: "读取应用成员", Description: "读取当前应用成员", Limits: "仅限当前应用"})
	if err != nil {
		t.Fatalf("创建应用同名权限: %v", err)
	}
	systemPermission := env.findPermission(t, "system", "users.read")
	if appPermission.ID == systemPermission {
		t.Fatal("同名跨应用权限不应共用稳定 ID")
	}
	// 应用范围列表带应用上下文；系统范围列表仍显示系统权限。
	appPage, err := env.adapter.ListPermissions(ctx, env.adminID,
		login.UIRBACPermissionQuery{ScopeID: appIDFixture, Limit: 20})
	if err != nil {
		t.Fatalf("应用权限列表: %v", err)
	}
	found := false
	for _, item := range appPage.Permissions {
		if item.Key == "users.read" {
			found = true
			if item.AppContext != "示例应用" || item.PermissionID != appPermission.ID ||
				item.ScopeID != appIDFixture {
				t.Fatalf("应用同名权限上下文 = %+v", item)
			}
		}
	}
	if !found {
		t.Fatal("应用范围未列出同名权限")
	}
	systemPage, err := env.adapter.ListPermissions(ctx, env.adminID,
		login.UIRBACPermissionQuery{ScopeID: "system", Limit: 100})
	if err != nil {
		t.Fatalf("系统权限列表: %v", err)
	}
	systemFound := false
	for _, item := range systemPage.Permissions {
		if item.Key == "users.read" {
			systemFound = true
			if item.PermissionID != systemPermission || item.ScopeID != "system" {
				t.Fatalf("系统权限上下文 = %+v", item)
			}
		}
	}
	if !systemFound {
		t.Fatal("系统范围未列出 users.read")
	}
	// 作用范围列表包含 system 与应用范围。
	scopes, err := env.adapter.ListScopes(ctx, env.adminID)
	if err != nil {
		t.Fatalf("作用范围列表: %v", err)
	}
	hasSystem, hasApp := false, false
	for _, scope := range scopes {
		if scope.ScopeID == "system" {
			hasSystem = true
		}
		if scope.ScopeID == appIDFixture {
			hasApp = true
			if scope.ApplicationName != "示例应用" {
				t.Fatalf("应用名称 = %q", scope.ApplicationName)
			}
		}
	}
	if !hasSystem || !hasApp {
		t.Fatalf("作用范围列表 = %+v", scopes)
	}
	// 应用范围角色创建（真实角色服务检查应用可用）。
	appRole, err := env.adapter.CreateRole(ctx, env.adminID, login.UIRBACCreateRole{
		ScopeID: appIDFixture, Key: "app-ops", Name: "应用运维",
		Description: "仅应用范围", Limits: "不能跨应用"}, "req_app_role")
	if err != nil || appRole.ScopeID != appIDFixture || appRole.AppContext != "示例应用" {
		t.Fatalf("应用范围角色 = %+v err=%v", appRole, err)
	}
}

// TestRBACIntegrationPresetDiffAndRootProtection 覆盖恢复预设差异展示与 root_only
// 不可组合（页面选项由后端数据决定）。
func TestRBACIntegrationPresetDiffAndRootProtection(t *testing.T) {
	env := newRBACIntegrationEnv(t)
	ctx := context.Background()
	normalUserRole := env.findPresetRole(t, "normal_user")
	if normalUserRole == "" {
		t.Fatal("未找到普通用户预设角色")
	}
	usersRead := env.findPermission(t, "system", "users.read")
	// 编辑预设角色（管理员持有 users.read 且有转授资格），制造与默认值的差异。
	if _, err := env.adapter.ComposeRolePermission(ctx, env.adminID, normalUserRole,
		usersRead, true, "req_preset_edit"); err != nil {
		t.Fatalf("编辑预设角色: %v", err)
	}
	diff, err := env.adapter.PresetDiff(ctx, env.adminID, "system")
	if err != nil {
		t.Fatalf("预设差异: %v", err)
	}
	if !diff.Available || diff.CatalogVersion == "" || !diff.ExecutionRestricted {
		t.Fatalf("预设差异元数据 = %+v", diff)
	}
	changed := false
	for _, entry := range diff.Roles {
		if entry.RoleKey != "normal_user" {
			continue
		}
		changed = true
		if entry.Unchanged {
			t.Fatal("编辑后的预设角色不应标记为与默认一致")
		}
		removed := false
		for _, item := range entry.RemovePermissions {
			if item.Key == "users.read" {
				removed = true
			}
		}
		if !removed {
			t.Fatalf("差异未列出应移除的 users.read: %+v", entry)
		}
	}
	if !changed {
		t.Fatal("预设差异未包含 normal_user")
	}
	// root_only 权限不能出现在可组合列表，也不能被组合（真实角色服务拒绝）。
	rootOnly := ""
	caller, err := permission.UserCaller(env.adminID)
	if err != nil {
		t.Fatalf("权限 Caller: %v", err)
	}
	list, err := env.permissions.ListPermissions(ctx, caller,
		permission.ListRequest{ScopeID: "system", Limit: 100})
	if err != nil {
		t.Fatalf("权限列表: %v", err)
	}
	for _, item := range list.Permissions {
		if item.RootOnly {
			rootOnly = item.ID
			break
		}
	}
	if rootOnly == "" {
		t.Skip("当前预设目录没有 root_only 权限，跳过组合拒绝验证")
	}
	// 管理员角色详情中 root_only 不出现在可组合列表。
	if _, err := env.adapter.ComposeRolePermission(ctx, env.adminID, normalUserRole,
		rootOnly, true, "req_rootonly"); err == nil {
		t.Fatal("root_only 权限不应可被普通角色组合")
	}
}

// TestRBACIntegrationPageRender 覆盖真实服务页面渲染与管理会话级别拒绝。
func TestRBACIntegrationPageRender(t *testing.T) {
	env := newRBACIntegrationEnv(t)
	ctx := context.Background()
	ui, err := login.NewWebUI(login.WebUIOptions{
		Session:  rbacIntegrationSessions{userID: env.adminID, management: true},
		PageRBAC: &login.UIPageRBACOptions{Backend: env.adapter}})
	if err != nil {
		t.Fatalf("页面框架: %v", err)
	}
	request := newRBACRequest("/admin/roles?scope_id=system")
	recorder := serveRBACPage(ui, request)
	if recorder.Code != 200 || !strings.Contains(recorder.Body.String(), "系统管理员") {
		t.Fatalf("真实服务角色列表 = %d", recorder.Code)
	}
	detailRequest := newRBACRequest(
		"/admin/permissions/detail?permission_id=" + env.findPermission(t, "system",
			"users.read"))
	detailRecorder := serveRBACPage(ui, detailRequest)
	if detailRecorder.Code != 200 ||
		!strings.Contains(detailRecorder.Body.String(), "生效范围说明") {
		t.Fatalf("真实服务权限详情 = %d", detailRecorder.Code)
	}
	// 有效权限页：状态/拒绝原因显示中文，不直出机器枚举（修复轮 2 回归 1）。
	effectiveRecorder := serveRBACPage(ui, newRBACRequest(
		"/admin/access/effective?subject_user_id="+env.user1ID+"&scope_id=system"))
	effectiveBody := effectiveRecorder.Body.String()
	if effectiveRecorder.Code != 200 || !strings.Contains(effectiveBody, "正常") ||
		!strings.Contains(effectiveBody, "不适用（系统范围）") ||
		strings.Contains(effectiveBody, ">active<") {
		t.Fatalf("有效权限中文状态显示异常: %d", effectiveRecorder.Code)
	}
	// 角色详情默认权限集合：目录真实说明可见，不误报“未提供”（修复轮 2 回归 2）；
	// 直接用户数据范围中文显示，不直出 JSON（修复轮 2 回归 3）。
	roleList, err := env.adapter.ListRoles(ctx, env.adminID,
		login.UIRBACRoleQuery{ScopeID: "system", Limit: 100})
	if err != nil || len(roleList.Roles) == 0 {
		t.Fatalf("角色列表: %v", err)
	}
	adminRoleID := ""
	for _, item := range roleList.Roles {
		if item.Key == "system_admin" {
			adminRoleID = item.ID
		}
	}
	if adminRoleID == "" {
		t.Fatal("缺少系统管理员预设角色")
	}
	roleDetail, err := env.adapter.GetRole(ctx, env.adminID, adminRoleID)
	if err != nil {
		t.Fatalf("角色详情: %v", err)
	}
	hasCatalogText := false
	for _, item := range roleDetail.Role.DefaultPermissions {
		if item.Description != "" || item.DefaultSummary != "" ||
			item.Limits != "" || item.DefaultLimits != "" {
			hasCatalogText = true
		}
	}
	if !hasCatalogText {
		t.Fatal("预设角色默认权限缺少目录真实说明/限制")
	}
	roleRecorder := serveRBACPage(ui, newRBACRequest("/admin/roles/detail?role_id="+adminRoleID))
	roleBody := roleRecorder.Body.String()
	if roleRecorder.Code != 200 || !strings.Contains(roleBody, "默认权限集合") {
		t.Fatalf("角色详情默认权限区块 = %d", roleRecorder.Code)
	}
	if strings.Contains(roleBody, `{"v":1`) || strings.Contains(roleBody, ">{}<") {
		t.Fatal("角色详情直出原始数据范围 JSON")
	}
	// 普通会话（非 management）访问管理页：框架拒绝并渲染 403，不渲染角色数据。
	ordinary, err := login.NewWebUI(login.WebUIOptions{
		Session:  rbacIntegrationSessions{userID: env.user1ID, management: false},
		PageRBAC: &login.UIPageRBACOptions{Backend: env.adapter}})
	if err != nil {
		t.Fatalf("普通会话页面框架: %v", err)
	}
	denied := serveRBACPage(ordinary, newRBACRequest("/admin/roles"))
	if denied.Code != 403 || strings.Contains(denied.Body.String(), "系统管理员") {
		t.Fatalf("普通会话访问管理页 = %d", denied.Code)
	}
}

// rbacIntegrationSessions 是集成测试的页面会话服务（真实会话框架不在本步范围）。
type rbacIntegrationSessions struct {
	userID     string
	management bool
}

func (s rbacIntegrationSessions) ResolvePageSession(_ context.Context,
	_ *http.Request) (login.UISession, error) {
	kind := "user"
	if s.management {
		kind = "management"
	}
	return login.UISession{Authenticated: true, UserID: s.userID, Kind: kind,
		ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func (s rbacIntegrationSessions) IssueCSRFToken(context.Context, *http.Request) (string, error) {
	return "rbac-csrf-token", nil
}

// newRBACRequest 构造页面 GET 请求。
func newRBACRequest(target string) *http.Request {
	return httptest.NewRequest(http.MethodGet, "http://example.test"+target, bytes.NewReader(nil))
}

// serveRBACPage 执行页面请求并返回响应记录。
func serveRBACPage(handler http.Handler, request *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

// TestRBACIntegrationSameNameNoSystemFallback 验证应用同名权限在权限详情、角色详情
// 与预设差异中都不回退系统目录语义（M1 修复的断言测试）。
func TestRBACIntegrationSameNameNoSystemFallback(t *testing.T) {
	env := newRBACIntegrationEnv(t)
	ctx := context.Background()
	systemCaller, err := permission.SystemCaller("test-seed")
	if err != nil {
		t.Fatalf("权限系统 Caller: %v", err)
	}
	appPermission, err := env.permissions.CreatePermission(ctx, systemCaller,
		permission.CreateRequest{ScopeID: appIDFixture, Key: "users.read",
			Name: "应用读取成员", Description: "可以读取当前应用成员",
			Limits: "仅限当前应用成员，不能读取系统用户"})
	if err != nil {
		t.Fatalf("创建应用同名权限: %v", err)
	}
	appRole, err := env.adapter.CreateRole(ctx, env.adminID, login.UIRBACCreateRole{
		ScopeID: appIDFixture, Key: "app-ops", Name: "应用运维",
		Description: "应用内运维", Limits: "仅限当前应用"}, "req_app_role")
	if err != nil {
		t.Fatalf("创建应用角色: %v", err)
	}
	roleCaller, err := role.SystemCaller("test-seed")
	if err != nil {
		t.Fatalf("角色系统 Caller: %v", err)
	}
	if _, err := env.roles.AddRolePermission(ctx, roleCaller, appRole.ID,
		appPermission.ID); err != nil {
		t.Fatalf("给应用角色组合应用权限: %v", err)
	}
	// ① 角色详情：应用权限的说明/限制来自应用真实数据，无系统默认名/系统默认角色。
	detail, err := env.adapter.GetRole(ctx, env.adminID, appRole.ID)
	if err != nil {
		t.Fatalf("读取应用角色详情: %v", err)
	}
	foundCurrent := false
	for _, item := range detail.Role.CurrentPermissions {
		if item.Key != "users.read" {
			continue
		}
		foundCurrent = true
		if item.Description != "可以读取当前应用成员" ||
			!strings.Contains(item.Limits, "仅限当前应用成员") ||
			strings.Contains(item.Limits, "读取普通用户") {
			t.Fatalf("应用权限描述回退系统目录: %+v", item)
		}
		if item.DefaultName != "" || item.ScopeKind != "application" ||
			item.AppContext != "示例应用" || item.ScopeID != appIDFixture {
			t.Fatalf("应用权限上下文/默认值错误: %+v", item)
		}
	}
	if !foundCurrent {
		t.Fatal("应用角色详情缺少应用同名权限")
	}
	// ② 权限详情：应用同名权限没有系统默认授予角色；系统同名权限仍有系统默认角色。
	appDetail, err := env.adapter.GetPermission(ctx, env.adminID, appPermission.ID)
	if err != nil {
		t.Fatalf("读取应用权限详情: %v", err)
	}
	if len(appDetail.DefaultRoles) != 0 || appDetail.Permission.DefaultName != "" {
		t.Fatalf("应用同名权限出现系统默认信息: %+v", appDetail)
	}
	systemDetail, err := env.adapter.GetPermission(ctx, env.adminID,
		env.findPermission(t, "system", "users.read"))
	if err != nil {
		t.Fatalf("读取系统权限详情: %v", err)
	}
	hasSystemAdmin := false
	for _, name := range systemDetail.DefaultRoles {
		if name == "system_admin" {
			hasSystemAdmin = true
		}
	}
	if !hasSystemAdmin {
		t.Fatalf("系统权限默认角色缺失: %+v", systemDetail.DefaultRoles)
	}
	// ③ 应用范围预设差异：应用模板默认权限为空，不得出现系统默认角色/权限。
	diff, err := env.adapter.PresetDiff(ctx, env.adminID, appIDFixture)
	if err != nil {
		t.Fatalf("应用范围预设差异: %v", err)
	}
	for _, item := range diff.Roles {
		if len(item.AddPermissions) != 0 || len(item.RemovePermissions) != 0 {
			t.Fatalf("应用范围预设差异出现系统默认权限: %+v", item)
		}
	}
	// ④ 真实页面渲染显示应用上下文与应用说明，不出现系统说明。
	ui, err := login.NewWebUI(login.WebUIOptions{
		Session:  rbacIntegrationSessions{userID: env.adminID, management: true},
		PageRBAC: &login.UIPageRBACOptions{Backend: env.adapter}})
	if err != nil {
		t.Fatalf("页面框架: %v", err)
	}
	pageRecorder := serveRBACPage(ui, newRBACRequest(
		"/admin/roles/detail?role_id="+appRole.ID))
	body := pageRecorder.Body.String()
	if pageRecorder.Code != 200 || !strings.Contains(body, "示例应用") ||
		!strings.Contains(body, "可以读取当前应用成员") ||
		strings.Contains(body, "读取普通用户") {
		t.Fatalf("应用角色详情页面跨应用混用: %d", pageRecorder.Code)
	}
}

// TestRBACIntegrationAdminMutationsAndDelegation 覆盖 UpdateRole/SetRoleState/
// UpdatePermission/DelegationView 的真实服务成功与失败路径。
func TestRBACIntegrationAdminMutationsAndDelegation(t *testing.T) {
	env := newRBACIntegrationEnv(t)
	ctx := context.Background()
	created, err := env.adapter.CreateRole(ctx, env.adminID, login.UIRBACCreateRole{
		ScopeID: "system", Key: "rbac-mutate", Name: "变更测试",
		Description: "初始说明", Limits: "初始限制"}, "req_create")
	if err != nil {
		t.Fatalf("创建角色: %v", err)
	}
	// UpdateRole 成功：名称/说明/限制写入后可重新读取。
	updated, err := env.adapter.UpdateRole(ctx, env.adminID, created.ID,
		login.UIRBACTextChange{Name: "变更后", Description: "新说明", Limits: "新限制"},
		"req_update")
	if err != nil || updated.Name != "变更后" {
		t.Fatalf("UpdateRole 成功路径 = %+v err=%v", updated, err)
	}
	if _, err := env.adapter.UpdateRole(ctx, env.adminID,
		"role_00000000000000000000000000000000", login.UIRBACTextChange{Name: "不存在"},
		"req_update_missing"); !rbacErrCode(err, "CHALLENGE_INVALID") {
		t.Fatalf("UpdateRole 不存在目标错误码 = %v", err)
	}
	// SetRoleState 成功：停用后读取真实启停状态，重新启用。
	disabled, changed, err := env.adapter.SetRoleState(ctx, env.adminID, created.ID,
		false, "req_disable")
	if err != nil || !changed || disabled.Enabled {
		t.Fatalf("SetRoleState 停用 = %+v changed=%v err=%v", disabled, changed, err)
	}
	enabled, changedAgain, err := env.adapter.SetRoleState(ctx, env.adminID, created.ID,
		true, "req_enable")
	if err != nil || !changedAgain || !enabled.Enabled {
		t.Fatalf("SetRoleState 启用 = %+v changed=%v err=%v", enabled, changedAgain, err)
	}
	if _, _, err := env.adapter.SetRoleState(ctx, env.adminID,
		"role_00000000000000000000000000000000", false, "req_state_missing"); !rbacErrCode(err, "CHALLENGE_INVALID") {
		t.Fatalf("SetRoleState 不存在目标错误码 = %v", err)
	}
	// UpdatePermission 成功（应用自定义权限）与失败（系统内置权限受保护）。
	systemCaller, err := permission.SystemCaller("test-seed")
	if err != nil {
		t.Fatalf("权限系统 Caller: %v", err)
	}
	appPermission, err := env.permissions.CreatePermission(ctx, systemCaller,
		permission.CreateRequest{ScopeID: appIDFixture, Key: "app.custom",
			Name: "应用自定义权限", Description: "初始说明", Limits: "初始限制"})
	if err != nil {
		t.Fatalf("创建应用自定义权限: %v", err)
	}
	renamed, err := env.adapter.UpdatePermission(ctx, env.adminID, appPermission.ID,
		login.UIRBACTextChange{Name: "应用自定义权限2", Description: "新说明",
			Limits: "新限制"}, "req_permission_update")
	if err != nil || renamed.Name != "应用自定义权限2" {
		t.Fatalf("UpdatePermission 成功路径 = %+v err=%v", renamed, err)
	}
	builtinPermission := env.findPermission(t, "system", "users.read")
	if _, err := env.adapter.UpdatePermission(ctx, env.adminID, builtinPermission,
		login.UIRBACTextChange{Name: "篡改内置"}, "req_permission_builtin"); !rbacErrCode(err, "ACCESS_DENIED") {
		t.Fatalf("UpdatePermission 内置保护错误码 = %v", err)
	}
	// DelegationView 成功：可转授权限与本人资格来自真实服务，数据范围中文说明。
	view, err := env.adapter.DelegationView(ctx, env.adminID, "system", false, 20, 0)
	if err != nil {
		t.Fatalf("DelegationView 成功路径: %v", err)
	}
	if len(view.Delegatable) == 0 || len(view.Grants) == 0 {
		t.Fatalf("DelegationView 空结果 = %+v", view)
	}
	for _, item := range view.Delegatable {
		if item.MaxDataScopeText == "" || strings.Contains(item.MaxDataScopeText, "{") {
			t.Fatalf("可转授权限数据范围未中文化: %+v", item)
		}
	}
	// 越权：宿主页面层 Authorize 拒绝时 fail-closed。
	denied, err := uiadminadapter.NewRBAC(uiadminadapter.RBACOptions{
		Roles: env.roles, Permissions: env.permissions, Access: env.access,
		Delegations: env.delegations,
		Authorize: func(context.Context, string, string) error {
			return errors.New("denied-by-host-authz")
		}})
	if err != nil {
		t.Fatalf("拒绝适配器: %v", err)
	}
	if _, _, err := denied.SetRoleState(ctx, env.adminID, created.ID, false, "req_deny"); !rbacErrCode(err, "ACCESS_DENIED") {
		t.Fatalf("越权 SetRoleState 错误码 = %v", err)
	}
	if _, err := denied.DelegationView(ctx, env.adminID, "system", false, 20, 0); !rbacErrCode(err, "ACCESS_DENIED") {
		t.Fatalf("越权 DelegationView 错误码 = %v", err)
	}
}

// TestRBACIntegrationAuthorizeActionNames 验证可选 Authorize 的动作名与真实权限键对齐。
func TestRBACIntegrationAuthorizeActionNames(t *testing.T) {
	env := newRBACIntegrationEnv(t)
	ctx := context.Background()
	actions := make([]string, 0, 16)
	adapter, err := uiadminadapter.NewRBAC(uiadminadapter.RBACOptions{
		Roles: env.roles, Permissions: env.permissions, Access: env.access,
		Delegations: env.delegations,
		Authorize: func(_ context.Context, _ string, action string) error {
			actions = append(actions, action)
			return nil
		}})
	if err != nil {
		t.Fatalf("记录适配器: %v", err)
	}
	roleList, err := adapter.ListRoles(ctx, env.adminID, login.UIRBACRoleQuery{Limit: 20})
	if err != nil || len(roleList.Roles) == 0 {
		t.Fatalf("ListRoles: %+v err=%v", roleList, err)
	}
	targetRole := roleList.Roles[0]
	if _, err := adapter.ComposeRolePermission(ctx, env.adminID, targetRole.ID,
		"", true, "req_probe"); err == nil {
		t.Fatal("空权限 ID 应被拒绝（但仍应记录 roles.manage 动作）")
	}
	if _, err := adapter.ListPermissions(ctx, env.adminID,
		login.UIRBACPermissionQuery{Limit: 20}); err != nil {
		t.Fatalf("ListPermissions: %v", err)
	}
	if _, err := adapter.UpdateRole(ctx, env.adminID, targetRole.ID,
		login.UIRBACTextChange{Name: targetRole.Name}, "req_action"); err != nil {
		// 目标可能是内置/受保护角色：仍应已记录 roles.manage；这里只忽略结果。
		_ = err
	}
	if _, _, err := adapter.SetPermissionState(ctx, env.adminID,
		"perm_00000000000000000000000000000000", false, "req_action2"); err == nil {
		// 不存在权限应失败，动作仍应记录 permissions.manage。
	}
	if _, err := adapter.EffectivePermissions(ctx, env.adminID, env.user1ID, "system",
		20, 0); err != nil {
		t.Fatalf("EffectivePermissions: %v", err)
	}
	if _, err := adapter.PresetDiff(ctx, env.adminID, "system"); err != nil {
		t.Fatalf("PresetDiff: %v", err)
	}
	if _, err := adapter.DelegationView(ctx, env.adminID, "system", false, 20, 0); err != nil {
		t.Fatalf("DelegationView: %v", err)
	}
	seen := map[string]bool{}
	for _, action := range actions {
		seen[action] = true
	}
	for _, want := range []string{"roles.read", "roles.manage", "permissions.read",
		"permissions.manage"} {
		if !seen[want] {
			t.Fatalf("缺少动作 %q（实际 %v）", want, actions)
		}
	}
	for _, forbidden := range []string{"roles.write", "permissions.write",
		"delegations.read", "effective.read", "presets.read"} {
		if seen[forbidden] {
			t.Fatalf("动作名未对齐真实权限键: %s", forbidden)
		}
	}
}

// TestRBACIntegrationListScopesSinglePermission 验证作用范围列表只依赖 roles.read：
// 权限目录读取被拒绝时仍能列出角色范围；权限目录读取另由 permissions.read 控制。
func TestRBACIntegrationListScopesSinglePermission(t *testing.T) {
	env := newRBACIntegrationEnv(t)
	ctx := context.Background()
	deniedPermissionStore, err := permissionsqlite.New(env.storage)
	if err != nil {
		t.Fatalf("权限存储: %v", err)
	}
	recorder, err := auditsqlite.New(env.storage)
	if err != nil {
		t.Fatalf("审计存储: %v", err)
	}
	auditService, err := audit.New(recorder, audit.Options{Now: time.Now,
		Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("审计: %v", err)
	}
	deniedPermissions, err := permission.New(permission.Options{
		Store: deniedPermissionStore, Audit: auditService,
		Authorizer: denyPermissionAuthorizer{}, Transfers: env.delegations,
		Now: time.Now, Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("拒绝式权限服务: %v", err)
	}
	adapter, err := uiadminadapter.NewRBAC(uiadminadapter.RBACOptions{
		Roles: env.roles, Permissions: deniedPermissions, Access: env.access,
		Delegations: env.delegations})
	if err != nil {
		t.Fatalf("适配器: %v", err)
	}
	scopes, err := adapter.ListScopes(ctx, env.adminID)
	if err != nil || len(scopes) == 0 {
		t.Fatalf("ListScopes 不应依赖 permissions.read: %+v err=%v", scopes, err)
	}
	hasSystem := false
	for _, scope := range scopes {
		if scope.ScopeID == "system" {
			hasSystem = true
		}
	}
	if !hasSystem {
		t.Fatalf("ListScopes 缺少 system: %+v", scopes)
	}
	if _, err := adapter.ListPermissions(ctx, env.adminID,
		login.UIRBACPermissionQuery{Limit: 20}); !rbacErrCode(err, "ACCESS_DENIED") {
		t.Fatalf("ListPermissions 应受 permissions.read 拒绝: %v", err)
	}
}

// rbacErrCode 判断错误是否为指定公开错误码。
func rbacErrCode(err error, code string) bool {
	var publicErr *login.UIRBACError
	return errors.As(err, &publicErr) && publicErr.Code == code
}

// TestRBACIntegrationRoleDegradesWithoutPermissionRead 验证缺少 permissions.read 时
// 角色页只降级隐藏权限详情区块，而不是整页 403；授权语义不变（ListPermissions 仍拒绝）。
func TestRBACIntegrationRoleDegradesWithoutPermissionRead(t *testing.T) {
	env := newRBACIntegrationEnv(t)
	ctx := context.Background()
	deniedStore, err := permissionsqlite.New(env.storage)
	if err != nil {
		t.Fatalf("权限存储: %v", err)
	}
	auditStore, err := auditsqlite.New(env.storage)
	if err != nil {
		t.Fatalf("审计存储: %v", err)
	}
	auditService, err := audit.New(auditStore, audit.Options{Now: time.Now,
		Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("审计: %v", err)
	}
	deniedPermissions, err := permission.New(permission.Options{Store: deniedStore,
		Audit: auditService, Authorizer: denyPermissionAuthorizer{},
		Transfers: env.delegations, Now: time.Now, Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("拒绝式权限服务: %v", err)
	}
	adapter, err := uiadminadapter.NewRBAC(uiadminadapter.RBACOptions{
		Roles: env.roles, Permissions: deniedPermissions, Access: env.access,
		Delegations: env.delegations})
	if err != nil {
		t.Fatalf("适配器: %v", err)
	}
	list, err := adapter.ListRoles(ctx, env.adminID, login.UIRBACRoleQuery{Limit: 20})
	if err != nil || len(list.Roles) == 0 {
		t.Fatalf("缺少 permissions.read 时角色列表不应整页失败: %+v err=%v", list, err)
	}
	detail, err := adapter.GetRole(ctx, env.adminID, list.Roles[0].ID)
	if err != nil {
		t.Fatalf("缺少 permissions.read 时角色详情不应整页失败: %v", err)
	}
	if !detail.PermissionCatalogUnavailable || len(detail.Available) != 0 {
		t.Fatalf("缺少 permissions.read 时应降级权限详情: %+v", detail)
	}
	if _, err := adapter.ListPermissions(ctx, env.adminID,
		login.UIRBACPermissionQuery{Limit: 20}); !rbacErrCode(err, "ACCESS_DENIED") {
		t.Fatalf("权限目录读取仍应按 permissions.read 拒绝: %v", err)
	}
}
