// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package serverapp

// 步骤 184 真实服务集成测试：临时 SQLite + 真实 authz 引擎 + 真实 app 服务 +
// 真实页面适配器。覆盖 R06 关闭条件：A/B 应用管理员仅见本应用、跨范围详情/成员
// 读写拒绝、普通用户拒绝、列表分页不泄露范围外应用、撤销角色立即失效、只有读取
// 权限时可读不可写。测试不启动监听端口、不联网、不读写生产数据库。

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	appsqlite "github.com/kagurazakayashi/EvernightLogin/internal/app/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	authzsqlite "github.com/kagurazakayashi/EvernightLogin/internal/authz/sqlite"
	bootstrapsqlite "github.com/kagurazakayashi/EvernightLogin/internal/bootstrap/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
	oauthclientsqlite "github.com/kagurazakayashi/EvernightLogin/internal/oauthclient/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/role"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/internal/uiadminadapter"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const (
	scopeTestAdminA   = "usr_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	scopeTestAdminB   = "usr_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	scopeTestReaderA  = "usr_cccccccccccccccccccccccccccccccc"
	scopeTestOrdinary = "usr_dddddddddddddddddddddddddddddddd"
	scopeTestMember   = "usr_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	scopeTestAppA     = "app_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	scopeTestAppB     = "app_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// allowAllDelegation 是测试用委派 Guard 适配器：本测试不验证转授链路（由 149
// 自身测试覆盖），只验证应用范围读取/写入授权；生产装配使用真实 delegation.Service。
type allowAllDelegation struct{}

func (allowAllDelegation) CheckPermissionAccess(context.Context, audit.Tx, audit.Actor, string, []delegation.PermissionRef, []delegation.Target) error {
	return nil
}
func (allowAllDelegation) CheckAssignment(context.Context, audit.Tx, audit.Actor, string, []delegation.PermissionRef, delegation.Target) error {
	return nil
}
func (allowAllDelegation) CheckPermissionActivation(context.Context, audit.Tx, audit.Actor, string, []delegation.PermissionRef, []delegation.Target) error {
	return nil
}
func (allowAllDelegation) CheckScopeRestoration(context.Context, audit.Tx, audit.Actor, string) error {
	return nil
}

// denyOAuthClientAuthorizer 是客户端域测试替身：本测试不涉及 OAuth 凭证操作。
type denyOAuthClientAuthorizer struct{}

func (denyOAuthClientAuthorizer) AuthorizeClient(context.Context, oauthclient.Caller,
	string, oauthclient.Action) error {
	return oauthclient.ErrAccessDenied
}

// allowSensitiveTestRunner 是敏感策略测试替身：本测试不触发客户端安全设置写入；
// 生产装配使用真实 reauth.Service（此处只满足构造契约，不当作生产鉴权）。
type allowSensitiveTestRunner struct{}

func (allowSensitiveTestRunner) Authorize(_ context.Context, caller reauth.Caller,
	request reauth.Request) (reauth.Result, error) {
	return reauth.Result{OperationID: request.OperationID, TargetType: request.TargetType,
		TargetID: request.TargetID, UserID: caller.Actor().ID,
		Decision: policy.Decision{Sensitive: true}}, nil
}

func (allowSensitiveTestRunner) NotifyOutcome(context.Context, reauth.Result,
	reauth.Outcome) error {
	return nil
}

// scopeTestSessions 是页面框架的测试会话实现（固定管理会话；生产使用真实
// session.Service 的强认证门禁，本测试只验证应用范围授权链）。
type scopeTestSessions struct{ userID string }

func (s scopeTestSessions) ResolvePageSession(context.Context,
	*http.Request) (login.UISession, error) {
	return login.UISession{Authenticated: true, UserID: s.userID, Kind: "management",
		ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func (s scopeTestSessions) IssueCSRFToken(context.Context, *http.Request) (string, error) {
	return "test-csrf-token", nil
}

// appScopeTestEnv 是真实服务测试环境。
type appScopeTestEnv struct {
	checker *permissionChecker
	apps    *app.Service
	adapter *uiadminadapter.AppsAdapter
	storage *storagesqlite.Store
}

// execScope 执行一条测试夹具 SQL。
func execScope(t *testing.T, storage *storagesqlite.Store, statement string, args ...any) {
	t.Helper()
	if _, err := storage.DB().ExecContext(context.Background(), statement, args...); err != nil {
		t.Fatalf("夹具 SQL 失败: %v", err)
	}
}

// seedAppScopeFixtures 写入 A/B 应用、权限、角色、成员与用户角色分配。
func seedAppScopeFixtures(t *testing.T, storage *storagesqlite.Store) {
	t.Helper()
	nowMS := time.Now().UTC().UnixMilli()
	for _, user := range []struct{ id, username string }{
		{scopeTestAdminA, "scope-admin-a"},
		{scopeTestAdminB, "scope-admin-b"},
		{scopeTestReaderA, "scope-reader-a"},
		{scopeTestOrdinary, "scope-ordinary"},
		{scopeTestMember, "scope-member"},
	} {
		execScope(t, storage, `INSERT INTO users(
id,username,username_normalized,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'active',0,1,1,?,?)`, user.id, user.username, user.username, nowMS, nowMS)
	}
	for _, application := range []struct{ id, name, owner string }{
		{scopeTestAppA, "应用甲", scopeTestAdminA},
		{scopeTestAppB, "应用乙", scopeTestAdminB},
	} {
		execScope(t, storage, `INSERT INTO applications(
id,name,description,owner_user_id,status,client_type,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,'active','confidential',1,?,?)`, application.id, application.name, "范围测试应用", application.owner, nowMS, nowMS)
		execScope(t, storage, `INSERT INTO scopes(id,kind,app_id) VALUES(?,'application',?)`, application.id, application.id)
	}
	// 管理员必须是应用有效成员（authz 引擎对应用范围校验成员关系）。
	profileJSON, err := app.EncodeMemberProfile(app.MemberProfile{})
	if err != nil {
		t.Fatalf("编码成员资料: %v", err)
	}
	for _, membership := range []struct{ app, user string }{
		{scopeTestAppA, scopeTestAdminA}, {scopeTestAppB, scopeTestAdminB},
		{scopeTestAppA, scopeTestReaderA}, {scopeTestAppA, scopeTestMember},
	} {
		execScope(t, storage, `INSERT INTO app_memberships(
app_id,user_id,status,profile_json,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,'active',?,1,?,?)`, membership.app, membership.user, profileJSON, nowMS, nowMS)
	}
	// A/B 各自的权限目录与角色：管理员角色持有 read/update/members.manage/roles.read；
	// 只读角色只有 applications.read。
	type permission struct{ app, key, name string }
	permissions := []permission{
		{scopeTestAppA, "applications.read", "读取应用甲"},
		{scopeTestAppA, "applications.update", "修改应用甲"},
		{scopeTestAppA, "applications.members.manage", "管理应用甲成员"},
		{scopeTestAppA, "roles.read", "读取应用甲角色"},
		{scopeTestAppB, "applications.read", "读取应用乙"},
		{scopeTestAppB, "applications.update", "修改应用乙"},
		{scopeTestAppB, "applications.members.manage", "管理应用乙成员"},
		{scopeTestAppB, "roles.read", "读取应用乙角色"},
	}
	permID := func(appID, key string) string {
		return "perm_" + appID[4:8] + "_" + strings.ReplaceAll(key, ".", "_")
	}
	for _, item := range permissions {
		execScope(t, storage, `INSERT INTO permissions(
id,scope_id,permission_key,name,description,limits_text,is_builtin,root_only,enabled,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?,0,0,1,?,?)`, permID(item.app, item.key), item.app, item.key,
			item.name, item.name, "测试", nowMS, nowMS)
	}
	roleID := func(appID string) string { return "role_" + appID[4:8] + "_admin" }
	readerRoleID := "role_" + "aaaa" + "_reader"
	for _, appID := range []string{scopeTestAppA, scopeTestAppB} {
		execScope(t, storage, `INSERT INTO roles(
id,scope_id,role_key,name,description,limits_text,is_builtin,enabled,created_at_ms,updated_at_ms)
VALUES(?,?,?,'应用管理员','测试角色','无限',0,1,?,?)`,
			roleID(appID), appID, "app.admin", nowMS, nowMS)
		for _, key := range []string{"applications.read", "applications.update",
			"applications.members.manage", "roles.read"} {
			execScope(t, storage, `INSERT INTO role_permissions(role_id,permission_id,scope_id)
VALUES(?,?,?)`, roleID(appID), permID(appID, key), appID)
		}
	}
	execScope(t, storage, `INSERT INTO roles(
id,scope_id,role_key,name,description,limits_text,is_builtin,enabled,created_at_ms,updated_at_ms)
VALUES(?,?,'app.reader','应用只读','测试角色','无限',0,1,?,?)`,
		readerRoleID, scopeTestAppA, nowMS, nowMS)
	execScope(t, storage, `INSERT INTO role_permissions(role_id,permission_id,scope_id)
VALUES(?,?,?)`, readerRoleID, permID(scopeTestAppA, "applications.read"), scopeTestAppA)
	assignments := []struct{ user, roleID, scopeID string }{
		{scopeTestAdminA, roleID(scopeTestAppA), scopeTestAppA},
		{scopeTestAdminB, roleID(scopeTestAppB), scopeTestAppB},
		{scopeTestReaderA, readerRoleID, scopeTestAppA},
	}
	for _, assignment := range assignments {
		execScope(t, storage, `INSERT INTO user_roles(
user_id,role_id,scope_id,data_scope_json,assigned_by,created_at_ms) VALUES(?,?,?,'{}','test',?)`,
			assignment.user, assignment.roleID, assignment.scopeID, nowMS)
	}
}

// newAppScopeTestEnv 构造真实 SQLite + authz + app.Service + 页面适配器。
func newAppScopeTestEnv(t *testing.T) *appScopeTestEnv {
	t.Helper()
	ctx := context.Background()
	storage, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(
		filepath.Join(testutil.TempDir(t), "app-scope.db")))
	if err != nil {
		t.Fatalf("打开临时数据库: %v", err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	migrationSet, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移: %v", err)
	}
	if _, err := storage.Migrate(ctx, migrationSet); err != nil {
		t.Fatalf("执行迁移: %v", err)
	}
	seedAppScopeFixtures(t, storage)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	auditStore, err := auditsqlite.New(storage)
	if err != nil {
		t.Fatalf("审计存储: %v", err)
	}
	recorder, err := audit.New(auditStore, audit.Options{Now: time.Now, Logger: logger})
	if err != nil {
		t.Fatalf("审计记录器: %v", err)
	}
	authzReader, err := authzsqlite.New(storage)
	if err != nil {
		t.Fatalf("权限引擎存储: %v", err)
	}
	access, err := authz.New(authz.Options{Store: authzReader, Authorizer: selfQueryAuthorizer{}, Logger: logger})
	if err != nil {
		t.Fatalf("权限引擎: %v", err)
	}
	bootstrapStore, err := bootstrapsqlite.New(storage)
	if err != nil {
		t.Fatalf("初始化存储: %v", err)
	}
	roots, err := newHostRootChecker(bootstrapStore)
	if err != nil {
		t.Fatalf("root 识别器: %v", err)
	}
	checker := newPermissionChecker(access, roots)
	appStore, err := appsqlite.New(storage)
	if err != nil {
		t.Fatalf("应用存储: %v", err)
	}
	checker.SetApplicationScopeLister(appStore)
	appService, err := app.New(app.Options{
		Store: appStore, Audit: recorder, Authorizer: appAuthorizer{checker: checker},
		Transfers: allowAllDelegation{}, Now: time.Now, Logger: logger,
	})
	if err != nil {
		t.Fatalf("应用服务: %v", err)
	}
	oauthStore, err := oauthclientsqlite.New(storage)
	if err != nil {
		t.Fatalf("客户端存储: %v", err)
	}
	oauthService, err := oauthclient.New(oauthclient.Options{
		Store: oauthStore, Audit: recorder, Authorizer: denyOAuthClientAuthorizer{},
		Sensitive: allowSensitiveTestRunner{}, Now: time.Now, Logger: logger,
	})
	if err != nil {
		t.Fatalf("客户端服务: %v", err)
	}
	adapter, err := uiadminadapter.NewApps(uiadminadapter.AppOptions{
		Apps: appService, OAuth: oauthService,
		Authorize: func(ctx context.Context, adminUserID, action, applicationID string) error {
			return checker.authorizePageActionScoped(ctx, adminUserID, action, applicationID)
		},
		AuthorizeAnyApp: checker.authorizePageAction,
		Now:             time.Now, Logger: logger,
	})
	if err != nil {
		t.Fatalf("页面适配器: %v", err)
	}
	return &appScopeTestEnv{checker: checker, apps: appService, adapter: adapter, storage: storage}
}

// appIDs 返回适配器列表中的应用 ID 集合。
func appIDs(page login.UIAppPage) map[string]bool {
	ids := make(map[string]bool, len(page.Applications))
	for _, item := range page.Applications {
		ids[item.ID] = true
	}
	return ids
}

// TestApplicationScopeIsolationAndReadWrite 覆盖 A/B 隔离、跨范围拒绝、普通用户
// 拒绝、只读权限、撤销角色立即失效与分页范围不泄露。
func TestApplicationScopeIsolationAndReadWrite(t *testing.T) {
	env := newAppScopeTestEnv(t)
	ctx := context.Background()

	// 应用甲管理员：只看到甲；详情/成员仅本应用可读。
	pageA, err := env.adapter.ListApplications(ctx, scopeTestAdminA, login.UIAppQuery{Limit: 20})
	if err != nil {
		t.Fatalf("甲列表失败: %v", err)
	}
	ids := appIDs(pageA)
	if !ids[scopeTestAppA] || ids[scopeTestAppB] || len(ids) != 1 {
		t.Fatalf("甲列表泄露/缺少应用: %v", ids)
	}
	if pageA.HasMore {
		t.Fatal("甲列表范围外应用不应影响 HasMore")
	}
	if _, err := env.adapter.GetApplication(ctx, scopeTestAdminA, scopeTestAppA); err != nil {
		t.Fatalf("甲读取本应用详情失败: %v", err)
	}
	if _, err := env.adapter.GetApplication(ctx, scopeTestAdminA, scopeTestAppB); err == nil {
		t.Fatal("甲读取乙应用详情必须拒绝")
	}
	if _, err := env.adapter.UpdateApplication(ctx, scopeTestAdminA, scopeTestAppB,
		login.UIApplicationChange{Name: "越权改名"}, 1, "req-cross-write"); err == nil {
		t.Fatal("甲修改乙应用必须拒绝")
	}
	// 管理 API（/admin/v1 域路由）复用同一页面动作复核：列表读取按“任一应用范围”
	// 放行（随后由 app.Service 过滤），跨应用写仍须目标应用范围权限。
	if err := env.checker.authorizePageAction(ctx, scopeTestAdminA, "applications.read"); err != nil {
		t.Fatalf("甲管理 API 列表读取复核失败: %v", err)
	}
	if err := env.checker.authorizePageAction(ctx, scopeTestOrdinary, "applications.read"); err == nil {
		t.Fatal("普通用户管理 API 列表读取复核必须拒绝")
	}
	if err := env.checker.authorizePageActionScoped(ctx, scopeTestAdminA,
		"applications.update", scopeTestAppA); err != nil {
		t.Fatalf("甲本应用写复核失败: %v", err)
	}
	if err := env.checker.authorizePageActionScoped(ctx, scopeTestAdminA,
		"applications.update", scopeTestAppB); err == nil {
		t.Fatal("甲跨应用写复核必须拒绝")
	}
	if _, err := env.adapter.ListMembers(ctx, scopeTestAdminA, scopeTestAppA,
		login.UIAppMemberQuery{Limit: 20}); err != nil {
		t.Fatalf("甲读取本应用成员失败: %v", err)
	}
	if _, err := env.adapter.ListMembers(ctx, scopeTestAdminA, scopeTestAppB,
		login.UIAppMemberQuery{Limit: 20}); err == nil {
		t.Fatal("甲读取乙应用成员必须拒绝")
	}

	// 应用乙管理员对称验证。
	pageB, err := env.adapter.ListApplications(ctx, scopeTestAdminB, login.UIAppQuery{Limit: 20})
	if err != nil {
		t.Fatalf("乙列表失败: %v", err)
	}
	idsB := appIDs(pageB)
	if !idsB[scopeTestAppB] || idsB[scopeTestAppA] || len(idsB) != 1 {
		t.Fatalf("乙列表泄露/缺少应用: %v", idsB)
	}
	if _, err := env.adapter.ListMembers(ctx, scopeTestAdminB, scopeTestAppA,
		login.UIAppMemberQuery{Limit: 20}); err == nil {
		t.Fatal("乙读取甲应用成员必须拒绝")
	}

	// 分页：甲把 offset 推到 1 时不泄露乙应用（范围内仅 1 项 → 空页）。
	watermark, err := env.adapter.ListApplications(ctx, scopeTestAdminA,
		login.UIAppQuery{Limit: 1, Offset: 1})
	if err != nil {
		t.Fatalf("甲分页失败: %v", err)
	}
	if len(watermark.Applications) != 0 || watermark.HasMore {
		t.Fatalf("分页越界泄露范围外数据: %+v", watermark)
	}

	// 普通用户：列表与详情都拒绝。
	if _, err := env.adapter.ListApplications(ctx, scopeTestOrdinary, login.UIAppQuery{Limit: 20}); err == nil {
		t.Fatal("普通用户列表应用必须拒绝")
	}
	if _, err := env.adapter.GetApplication(ctx, scopeTestOrdinary, scopeTestAppA); err == nil {
		t.Fatal("普通用户读取应用详情必须拒绝")
	}

	// 只读权限：可读甲应用，但不能修改/停用（写路径要求 applications.update）。
	readOnly, err := env.adapter.GetApplication(ctx, scopeTestReaderA, scopeTestAppA)
	if err != nil {
		t.Fatalf("只读用户读取本应用失败: %v", err)
	}
	if _, err := env.adapter.UpdateApplication(ctx, scopeTestReaderA, scopeTestAppA,
		login.UIApplicationChange{Name: readOnly.Name}, readOnly.RowVersion, "req-readonly"); err == nil {
		t.Fatal("只有读取权限的用户修改应用必须拒绝")
	}
	if _, _, err := env.adapter.SetApplicationState(ctx, scopeTestReaderA, scopeTestAppA,
		false, readOnly.RowVersion, "req-readonly-state"); err == nil {
		t.Fatal("只有读取权限的用户停用应用必须拒绝")
	}

	// 角色范围：甲只在甲范围持有 roles.read；乙同理；普通用户拒绝。
	all, list, err := env.checker.manageableScopes(ctx,
		audit.Actor{Type: audit.ActorUser, ID: scopeTestAdminA}, "roles.read")
	if err != nil || all || len(list) != 1 || list[0] != scopeTestAppA {
		t.Fatalf("甲角色范围 = %v/%v err=%v", all, list, err)
	}
	all, list, err = env.checker.manageableScopes(ctx,
		audit.Actor{Type: audit.ActorUser, ID: scopeTestAdminB}, "roles.read")
	if err != nil || all || len(list) != 1 || list[0] != scopeTestAppB {
		t.Fatalf("乙角色范围 = %v/%v err=%v", all, list, err)
	}
	if _, _, err := env.checker.manageableScopes(ctx,
		audit.Actor{Type: audit.ActorUser, ID: scopeTestOrdinary}, "roles.read"); err == nil {
		t.Fatal("普通用户角色范围必须拒绝")
	}
	// 角色服务授权器同样按目标应用范围判定：甲可在甲范围列角色，不能用乙范围。
	if err := (roleAuthorizer{checker: env.checker}).Authorize(ctx,
		mustRoleCaller(t, scopeTestAdminA), role.ActionListRoles, scopeTestAppA); err != nil {
		t.Fatalf("甲列本应用角色失败: %v", err)
	}
	if err := (roleAuthorizer{checker: env.checker}).Authorize(ctx,
		mustRoleCaller(t, scopeTestAdminA), role.ActionListRoles, scopeTestAppB); err == nil {
		t.Fatal("甲在乙范围列角色必须拒绝")
	}

	// 撤销甲的角色分配后立即失效（不缓存授权）。
	execScope(t, env.storage, `DELETE FROM user_roles WHERE user_id=? AND scope_id=?`,
		scopeTestAdminA, scopeTestAppA)
	if _, err := env.adapter.ListApplications(ctx, scopeTestAdminA, login.UIAppQuery{Limit: 20}); err == nil {
		t.Fatal("撤销角色后应用列表必须立即拒绝")
	}
	if _, err := env.adapter.GetApplication(ctx, scopeTestAdminA, scopeTestAppA); err == nil {
		t.Fatal("撤销角色后应用详情必须立即拒绝")
	}
}

// mustRoleCaller 构造角色域用户调用者。
func mustRoleCaller(t *testing.T, userID string) role.Caller {
	t.Helper()
	caller, err := role.UserCaller(userID)
	if err != nil {
		t.Fatalf("角色调用者: %v", err)
	}
	return caller
}

// TestApplicationPageScopeRendering 覆盖网页层：甲的应用列表页只渲染甲应用，直接
// 访问乙应用资料页返回 403；普通用户应用页 403。页面使用真实适配器与真实服务。
func TestApplicationPageScopeRendering(t *testing.T) {
	env := newAppScopeTestEnv(t)
	pageFor := func(userID string) *login.WebUI {
		t.Helper()
		ui, err := login.NewWebUI(login.WebUIOptions{
			Session:  scopeTestSessions{userID: userID},
			PageApps: &login.UIPageAppsOptions{Backend: env.adapter},
		})
		if err != nil {
			t.Fatalf("页面框架: %v", err)
		}
		return ui
	}
	get := func(ui *login.WebUI, target string) *httptest.ResponseRecorder {
		t.Helper()
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, target, nil)
		ui.ServeHTTP(recorder, request)
		return recorder
	}

	listA := get(pageFor(scopeTestAdminA), "/admin/applications")
	if listA.Code != http.StatusOK {
		t.Fatalf("甲应用列表页状态 = %d", listA.Code)
	}
	body := listA.Body.String()
	if !strings.Contains(body, "应用甲") || !strings.Contains(body, scopeTestAppA) {
		t.Fatal("甲应用列表页缺少本应用")
	}
	if strings.Contains(body, "应用乙") || strings.Contains(body, scopeTestAppB) {
		t.Fatal("甲应用列表页泄露乙应用")
	}
	crossDetail := get(pageFor(scopeTestAdminA),
		"/admin/applications/profile?app_id="+scopeTestAppB)
	if crossDetail.Code != http.StatusForbidden {
		t.Fatalf("甲直接访问乙资料页应 403，实际 %d", crossDetail.Code)
	}
	if strings.Contains(crossDetail.Body.String(), "应用乙") {
		t.Fatal("跨范围 403 页面泄露乙应用名称")
	}
	ordinary := get(pageFor(scopeTestOrdinary), "/admin/applications")
	if ordinary.Code != http.StatusForbidden {
		t.Fatalf("普通用户应用列表页应 403，实际 %d", ordinary.Code)
	}
	// 空白/无 app_id 的资料页请求不能退化为跨应用读取。
	noAppID := get(pageFor(scopeTestAdminA), "/admin/applications/profile")
	if noAppID.Code != http.StatusBadRequest && noAppID.Code != http.StatusForbidden {
		t.Fatalf("缺少 app_id 的资料页应 4xx，实际 %d", noAppID.Code)
	}
}
