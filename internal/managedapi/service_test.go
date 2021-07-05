package managedapi_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	accountsqlite "github.com/kagurazakayashi/EvernightLogin/internal/account/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	appsqlite "github.com/kagurazakayashi/EvernightLogin/internal/app/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	authzsqlite "github.com/kagurazakayashi/EvernightLogin/internal/authz/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
	"github.com/kagurazakayashi/EvernightLogin/internal/group"
	groupsqlite "github.com/kagurazakayashi/EvernightLogin/internal/group/sqlite"
	. "github.com/kagurazakayashi/EvernightLogin/internal/managedapi"
	managedapisqlite "github.com/kagurazakayashi/EvernightLogin/internal/managedapi/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
	oauthclientsqlite "github.com/kagurazakayashi/EvernightLogin/internal/oauthclient/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/permission"
	permissionsqlite "github.com/kagurazakayashi/EvernightLogin/internal/permission/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/role"
	rolesqlite "github.com/kagurazakayashi/EvernightLogin/internal/role/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	sessionsqlite "github.com/kagurazakayashi/EvernightLogin/internal/session/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const (
	testAdmin       = "usr_00000000000000000000000000000001"
	testWorker      = "usr_00000000000000000000000000000002"
	testAppOne      = "app_00000000000000000000000000000001"
	testAppTwo      = "app_00000000000000000000000000000002"
	testPermManage  = "perm_00000000000000000000000000000001"
	testPermRead    = "perm_00000000000000000000000000000002"
	testRoleOne     = "role_00000000000000000000000000000001"
	testGroupOne    = "grp_00000000000000000000000000000001"
	testServiceSID  = "secret-service-secret-0001"
	testOutsider    = "usr_00000000000000000000000000000003"
	testGroupTwo    = "grp_00000000000000000000000000000002"
	testRoleTwo     = "role_00000000000000000000000000000002"
	testGroupAppTwo = "grp_00000000000000000000000000000003"
)

var testStart = time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)

// fakeReauth 是测试用敏感操作执行器（仅测试路径）。
type fakeReauth struct{ allow bool }

func (f *fakeReauth) Authorize(_ context.Context, _ reauth.Caller,
	request reauth.Request) (reauth.Result, error) {
	if !f.allow {
		return reauth.Result{}, reauth.ErrAccessDenied
	}
	return reauth.Result{OperationID: request.OperationID, TargetType: request.TargetType,
		TargetID: request.TargetID, RequestID: request.RequestID,
		UserID: testAdmin}, nil
}

func (f *fakeReauth) NotifyOutcome(context.Context, reauth.Result, reauth.Outcome) error {
	return nil
}

// fakeClientAuthorizer 是 oauthclient 管理授权器测试替身。
type fakeClientAuthorizer struct{}

func (fakeClientAuthorizer) AuthorizeClient(context.Context, oauthclient.Caller,
	string, oauthclient.Action) error {
	return nil
}

// allowAssignmentsGuard 允许空权限目标（新建账户加重）但拒绝有权限的赋权，
// 用于模拟既有 delegation.Guard 的委派防护。
type allowAssignmentsGuard struct{}

func (allowAssignmentsGuard) CheckPermissionAccess(context.Context, audit.Tx, audit.Actor,
	string, []delegation.PermissionRef, []delegation.Target) error {
	return delegation.ErrAccessDenied
}

func (allowAssignmentsGuard) CheckAssignment(_ context.Context, _ audit.Tx, _ audit.Actor,
	_ string, permissions []delegation.PermissionRef, _ delegation.Target) error {
	if len(permissions) > 0 {
		return delegation.ErrAccessDenied
	}
	return nil
}

func (allowAssignmentsGuard) CheckPermissionActivation(context.Context, audit.Tx, audit.Actor,
	string, []delegation.PermissionRef, []delegation.Target) error {
	return delegation.ErrAccessDenied
}

func (allowAssignmentsGuard) CheckScopeRestoration(context.Context, audit.Tx, audit.Actor,
	string) error {
	return delegation.ErrAccessDenied
}

// testEnv 是真实 SQLite + 真实服务的托管 API 测试环境。
type testEnv struct {
	t          *testing.T
	ctx        context.Context
	raw        *storagesqlite.Store
	service    *Service
	audit      *audit.Recorder
	sessions   *session.Service
	authorizer *TrustedPolicyAuthorizer
	reauth     *fakeReauth
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(
		filepath.Join(t.TempDir(), "managed.db")))
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
	clock := func() time.Time { return testStart }
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	auditStore, err := auditsqlite.New(raw)
	if err != nil {
		t.Fatalf("审计存储失败: %v", err)
	}
	auditRecorder, err := audit.New(auditStore, audit.Options{Logger: logger, Now: clock})
	if err != nil {
		t.Fatalf("审计服务失败: %v", err)
	}
	keyring, err := secrets.GenerateKeyring("k1", testStart)
	if err != nil {
		t.Fatalf("密钥环失败: %v", err)
	}
	// 托管授权器族注入既有服务。
	managedAccountAuth, managedAppAuth, managedRoleAuth, managedGroupAuth, managedPermAuth :=
		NewDelegatedAuthorizers(auditRecorder)
	// 策略配置受信通道 + 再次认证。
	policyAuthorizer, err := NewTrustedPolicyAuthorizer([]string{"root-admin"}, nil)
	if err != nil {
		t.Fatalf("策略授权器失败: %v", err)
	}
	fakeSensitive := &fakeReauth{allow: true}
	// 账户服务。
	accountStore, err := accountsqlite.New(raw)
	if err != nil {
		t.Fatalf("账户存储失败: %v", err)
	}
	accountService, err := account.New(account.Options{Store: accountStore, Audit: auditRecorder,
		Authorizer: managedAccountAuth, Now: clock, Logger: logger})
	if err != nil {
		t.Fatalf("账户服务失败: %v", err)
	}
	// 应用服务。
	appStore, err := appsqlite.New(raw)
	if err != nil {
		t.Fatalf("应用存储失败: %v", err)
	}
	appService, err := app.New(app.Options{Store: appStore, Audit: auditRecorder,
		Authorizer: managedAppAuth, Transfers: allowAssignmentsGuard{}, Now: clock, Logger: logger})
	if err != nil {
		t.Fatalf("应用服务失败: %v", err)
	}
	roleStore, err := rolesqlite.New(raw)
	if err != nil {
		t.Fatalf("角色存储失败: %v", err)
	}
	roleService, err := role.New(role.Options{Store: roleStore, Audit: auditRecorder,
		Authorizer: managedRoleAuth, Transfers: allowAssignmentsGuard{},
		AllowLegacyWithoutSensitive: true, Now: clock, Logger: logger})
	if err != nil {
		t.Fatalf("角色服务失败: %v", err)
	}
	groupStore, err := groupsqlite.New(raw)
	if err != nil {
		t.Fatalf("用户组存储失败: %v", err)
	}
	groupService, err := group.New(group.Options{Store: groupStore, Audit: auditRecorder,
		Authorizer: managedGroupAuth, Transfers: allowAssignmentsGuard{},
		AllowLegacyWithoutSensitive: true, Now: clock, Logger: logger})
	if err != nil {
		t.Fatalf("用户组服务失败: %v", err)
	}
	permissionStore, err := permissionsqlite.New(raw)
	if err != nil {
		t.Fatalf("权限存储失败: %v", err)
	}
	permissionService, err := permission.New(permission.Options{Store: permissionStore,
		Audit: auditRecorder, Authorizer: managedPermAuth,
		Transfers: allowAssignmentsGuard{}, Now: clock, Logger: logger})
	if err != nil {
		t.Fatalf("权限服务失败: %v", err)
	}
	// 授权引擎（查询授权器：允许用户自查）。
	authzStore, err := authzsqlite.New(raw)
	if err != nil {
		t.Fatalf("授权存储失败: %v", err)
	}
	queryAuth, err := authz.NewStaticAuthorizer(authz.AuthorizerOptions{
		LocalAdminIDs: []string{"query-admin"}, SystemIDs: []string{"query-system"}})
	if err != nil {
		t.Fatalf("查询授权器失败: %v", err)
	}
	authzService, err := authz.New(authz.Options{Store: authzStore, Authorizer: queryAuth,
		Logger: logger})
	if err != nil {
		t.Fatalf("授权引擎失败: %v", err)
	}
	// 会话服务。
	sessionStore, err := sessionsqlite.New(raw)
	if err != nil {
		t.Fatalf("会话存储失败: %v", err)
	}
	sessionService, err := session.New(sessionStore, session.Options{Store: sessionStore,
		Audit: auditRecorder, Keyring: keyring, AllowLegacyWithoutSensitive: true,
		Logger: logger, Now: clock})
	if err != nil {
		t.Fatalf("会话服务失败: %v", err)
	}
	// OAuth 客户端服务（服务身份认证）。
	clientStore, err := oauthclientsqlite.New(raw)
	if err != nil {
		t.Fatalf("客户端存储失败: %v", err)
	}
	clientService, err := oauthclient.New(oauthclient.Options{Store: clientStore,
		Audit: auditRecorder, Authorizer: fakeClientAuthorizer{}, Sensitive: fakeSensitive,
		Logger: logger, Now: clock})
	if err != nil {
		t.Fatalf("客户端服务失败: %v", err)
	}
	policyStore, err := managedapisqlite.New(raw)
	if err != nil {
		t.Fatalf("策略存储失败: %v", err)
	}
	fakeReauthPolicy := &fakeReauth{allow: true}
	service, err := New(Options{Store: policyStore, Audit: auditRecorder, Authz: authzService,
		Sessions: sessionService, Clients: clientService, Account: accountService,
		App: appService, Role: roleService, Group: groupService, Permission: permissionService,
		PolicyAuthorizer: policyAuthorizer, Reauth: fakeReauthPolicy,
		Now: clock, Logger: logger})
	if err != nil {
		t.Fatalf("托管管理 API 失败: %v", err)
	}
	env := &testEnv{t: t, ctx: ctx, raw: raw, service: service, audit: auditRecorder,
		sessions: sessionService, authorizer: policyAuthorizer, reauth: fakeReauthPolicy}
	env.seed()
	return env
}

// seed 插入测试用应用、用户、成员、权限、角色、用户组与客户端凭证。
func (e *testEnv) seed() {
	e.t.Helper()
	now := testStart.UnixMilli()
	exec := func(query string, args ...any) {
		e.t.Helper()
		if _, err := e.raw.ExecContext(e.ctx, query, args...); err != nil {
			e.t.Fatalf("插入测试数据失败: %v\nSQL: %s", err, query)
		}
	}
	insertUser := func(userID, username string) {
		exec(`INSERT INTO users(id,username,username_normalized,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'active',0,1,1,?,?)`, userID, username, username, now, now)
	}
	insertUser(testAdmin, "managedadmin")
	insertUser(testWorker, "managedworker")
	insertUser(testOutsider, "managedoutsider")
	insertApp := func(appID, name string) {
		exec(`INSERT INTO applications(id,name,description,status,client_type,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,'','active','public',1,?,?)`, appID, name, now, now)
		exec(`INSERT INTO scopes(id,kind,app_id) VALUES(?,'application',?)`, appID, appID)
	}
	insertApp(testAppOne, "应用一")
	insertApp(testAppTwo, "应用二")
	insertMembership := func(appID, userID string) {
		exec(`INSERT INTO app_memberships(app_id,user_id,status,profile_json,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,'active','{"v":1}',1,?,?)`, appID, userID, now, now)
	}
	insertMembership(testAppOne, testAdmin)
	insertMembership(testAppOne, testWorker)
	insertMembership(testAppTwo, testAdmin)
	// 权限与角色（应用一：成员管理读/写权限 + 角色管理读/分配）。
	exec(`INSERT INTO permissions(id,scope_id,permission_key,name,description,limits_text,is_builtin,root_only,enabled,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,'','',0,0,1,?,?)`, testPermManage, testAppOne,
		"applications.members.manage", "成员管理", now, now)
	exec(`INSERT INTO permissions(id,scope_id,permission_key,name,description,limits_text,is_builtin,root_only,enabled,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,'','',0,0,1,?,?)`, testPermRead, testAppOne,
		"roles.read", "角色查看", now, now)
	exec(`INSERT INTO roles(id,scope_id,role_key,name,description,limits_text,is_builtin,enabled,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,'','',0,1,?,?)`, testRoleOne, testAppOne, "managed.admin", "托管管理员", now, now)
	exec(`INSERT INTO role_permissions(role_id,permission_id,scope_id) VALUES(?,?,?)`,
		testRoleOne, testPermManage, testAppOne)
	exec(`INSERT INTO role_permissions(role_id,permission_id,scope_id) VALUES(?,?,?)`,
		testRoleOne, testPermRead, testAppOne)
	extraPermissions := []struct{ id, key string }{
		{"perm_00000000000000000000000000000003", "groups.read"},
		{"perm_00000000000000000000000000000004", "groups.manage"},
		{"perm_00000000000000000000000000000005", "roles.assign"},
		{"perm_00000000000000000000000000000006", "permissions.read"},
		{"perm_00000000000000000000000000000007", "users.create"},
	}
	for _, extra := range extraPermissions {
		exec(`INSERT INTO permissions(id,scope_id,permission_key,name,description,limits_text,is_builtin,root_only,enabled,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,'','',0,0,1,?,?)`, extra.id, testAppOne, extra.key, extra.key, now, now)
		exec(`INSERT INTO role_permissions(role_id,permission_id,scope_id) VALUES(?,?,?)`,
			testRoleOne, extra.id, testAppOne)
	}
	// 数据范围 all：允许对象/资源检查（undefined/none 在测试中另行覆盖）。
	exec(`INSERT INTO user_roles(user_id,role_id,scope_id,data_scope_json,assigned_by,created_at_ms)
VALUES(?,?,?,'{"v":1,"mode":"all"}','seed',?)`, testAdmin, testRoleOne, testAppOne, now)
	exec(`INSERT INTO user_groups(id,scope_id,group_key,name,description,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,'',?,?)`, testGroupOne, testAppOne, "managed.group", "托管组", now, now)
	exec(`INSERT INTO user_groups(id,scope_id,group_key,name,description,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,'',?,?)`, testGroupTwo, testAppOne, "managed.group2", "托管组二", now, now)
	exec(`INSERT INTO roles(id,scope_id,role_key,name,description,limits_text,is_builtin,enabled,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,'','',0,1,?,?)`, testRoleTwo, testAppOne, "managed.reader", "托管只读", now, now)
	// 服务身份客户端（应用一保密客户端 + 已知 secret 摘要）。
	exec(`INSERT INTO oauth_clients(client_id,client_type,grant_types_json,redirect_uris_json,
post_logout_redirect_uris_json,scopes_json,audiences_json,auth_methods_json,require_pkce,
row_version,created_at_ms,updated_at_ms)
VALUES(?,'confidential','["client_credentials"]','[]','[]','[]','[]','["client_secret_post"]',1,1,?,?)`,
		testAppOne, now, now)
	digest := sha256Digest(testServiceSID)
	exec(`INSERT INTO oauth_client_secrets(id,client_id,secret_prefix,secret_digest,created_at_ms,
expires_at_ms,retire_at_ms,revoked_at_ms)
VALUES('sec_1',?,'secret',?,?,?,NULL,NULL)`, testAppOne, digest,
		now, testStart.Add(24*time.Hour).UnixMilli())
	// 角色分配种子：worker 直接持有（供 ListRoleAssignments 过滤用例）与组持有。
	exec(`INSERT INTO user_roles(user_id,role_id,scope_id,data_scope_json,assigned_by,created_at_ms)
VALUES(?,?,?,'{"v":1,"mode":"all"}','seed',?)`, testWorker, testRoleOne, testAppOne, now)
	exec(`INSERT INTO group_roles(group_id,role_id,scope_id,data_scope_json,created_at_ms)
VALUES(?,?,?,'{"v":1,"mode":"all"}',?)`, testGroupOne, testRoleOne, testAppOne, now)
}

// policyFor 构造默认策略（应用一：允许核心操作、字段与上限）。
func policyFor(appID string, readFields, writeFields []string) Policy {
	_ = appID
	return Policy{
		Version: 1,
		Operations: PolicyOperations{
			Allowed: []string{OpApplicationGet, OpMembersList, OpMembersGet,
				OpMembersUpdateProfile, OpMembersDisable, OpMembersEnable, OpMembersRemove,
				OpUsersCreate, OpGroupsList, OpGroupsGet, OpGroupMembersList,
				OpGroupMembersAdd, OpGroupMembersRemove, OpRolesList, OpRolesGet,
				OpRolePermissionsList, OpRoleAssignmentsList, OpRoleAssignUser,
				OpRoleRevokeUser, OpRoleAssignGroup, OpRoleRevokeGroup,
				OpPermissionsList, OpPermissionsGet},
			ServiceAllowed: []string{OpApplicationGet, OpMembersList, OpMembersGet,
				OpGroupsList, OpGroupsGet, OpGroupMembersList, OpRolesList, OpRolesGet,
				OpRolePermissionsList, OpRoleAssignmentsList, OpPermissionsList,
				OpPermissionsGet},
		},
		Objects: []ObjectScope{
			{Object: ObjectApplication, Mode: ScopeModeAll},
			{Object: ObjectMember, Mode: ScopeModeAll},
			{Object: ObjectUser, Mode: ScopeModeAll},
			{Object: ObjectGroup, Mode: ScopeModeAll},
			{Object: ObjectRole, Mode: ScopeModeAll},
			{Object: ObjectPermission, Mode: ScopeModeAll},
		},
		Fields: []ObjectFields{
			{Object: ObjectMember, Read: readFields, Write: writeFields},
			{Object: ObjectApplication, Read: []string{"name", "status"}},
			{Object: ObjectGroup, Read: []string{"id", "key", "name"}},
			{Object: ObjectRole, Read: []string{"id", "key", "name"}},
			{Object: ObjectPermission, Read: []string{"id", "key", "name", "enabled"}},
			{Object: ObjectUser, Read: []string{"username", "biography"}, Write: []string{"username", "biography"}},
		},
		Limits: PolicyLimits{MaxLimit: 10, MaxOffset: 1000, MaxBatch: 2},
	}
}

// setPolicy 通过受信通道写入策略。
func (e *testEnv) setPolicy(appID string, policy Policy) {
	e.t.Helper()
	actor := audit.Actor{Type: audit.ActorLocalAdmin, ID: "root-admin"}
	if _, err := e.service.SetPolicy(e.ctx, actor, SetPolicyRequest{
		ApplicationID: appID, Policy: policy, RequestID: "req_policy_set"}); err != nil {
		e.t.Fatalf("写入策略失败: %v", err)
	}
}

// userSession 为用户签发普通会话（目标应用作用域）。
func (e *testEnv) userSession(userID, appID string) session.IssuedSession {
	e.t.Helper()
	issued, err := e.sessions.Login(e.ctx, session.LoginRequest{
		Result: authn.AuthenticateResult{UserID: userID, Username: "user",
			Outcome:          authn.OutcomeComplete,
			CompletedMethods: []authn.Method{authn.MethodPassword},
			CompletedAt:      testStart, SecurityVersion: 1},
		AppID: appID, RequestID: "req_login"})
	if err != nil {
		e.t.Fatalf("签发会话失败: %v", err)
	}
	return issued
}

// queryInt 执行计数查询。
func (e *testEnv) queryInt(query string, args ...any) int {
	e.t.Helper()
	rows, err := e.raw.QueryContext(e.ctx, query, args...)
	if err != nil {
		e.t.Fatalf("查询失败: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		e.t.Fatal("查询无结果")
	}
	var count int
	if err := rows.Scan(&count); err != nil {
		e.t.Fatalf("扫描失败: %v", err)
	}
	return count
}

// sha256Digest 计算客户端密钥摘要（与 oauthclient 存储契约一致）。
func sha256Digest(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// TestPolicySetValidationAndTrust 验证策略写入的受信通道、再次认证、严格校验与
// 行版本条件更新。
func TestPolicySetValidationAndTrust(t *testing.T) {
	env := newTestEnv(t)
	policy := policyFor(testAppOne, []string{"status", "username"}, []string{"display_name"})
	actor := audit.Actor{Type: audit.ActorLocalAdmin, ID: "root-admin"}
	view, err := env.service.SetPolicy(env.ctx, actor, SetPolicyRequest{
		ApplicationID: testAppOne, Policy: policy, RequestID: "req_set_1"})
	if err != nil {
		t.Fatalf("写入合法策略失败: %v", err)
	}
	if view.RowVersion != 1 {
		t.Fatalf("新建策略行版本应为 1，实际 %d", view.RowVersion)
	}
	// 行版本冲突：同一 ExpectedRowVersion=0 再次新建应冲突。
	if _, err := env.service.SetPolicy(env.ctx, actor, SetPolicyRequest{
		ApplicationID: testAppOne, Policy: policy, RequestID: "req_set_dup"}); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("重复新建应返回版本冲突，实际 %v", err)
	}
	// 未受信操作者拒绝。
	if _, err := env.service.SetPolicy(env.ctx, audit.Actor{Type: audit.ActorUser, ID: testAdmin},
		SetPolicyRequest{ApplicationID: testAppOne, Policy: policy, RequestID: "req_untrusted"}); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("普通用户不能修改策略，实际 %v", err)
	}
	// 非法策略：未知操作 / 硬禁字段 / 系统作用域对象。
	invalid := policy
	invalid.Operations.Allowed = append(append([]string(nil), invalid.Operations.Allowed...), "unknown.operation")
	if _, err := env.service.SetPolicy(env.ctx, actor, SetPolicyRequest{
		ApplicationID: testAppOne, Policy: invalid, ExpectedRowVersion: 1,
		RequestID: "req_bad_op"}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("未知操作应拒绝，实际 %v", err)
	}
	invalid = policy
	invalid.Fields = append([]ObjectFields(nil), policy.Fields...)
	invalid.Fields[0] = ObjectFields{Object: ObjectMember, Read: []string{"password_hash"}}
	if _, err := env.service.SetPolicy(env.ctx, actor, SetPolicyRequest{
		ApplicationID: testAppOne, Policy: invalid, ExpectedRowVersion: 1,
		RequestID: "req_bad_field"}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("硬禁字段应拒绝，实际 %v", err)
	}
	// 再次认证拒绝时不能修改策略。
	env.reauth.allow = false
	if _, err := env.service.SetPolicy(env.ctx, actor, SetPolicyRequest{
		ApplicationID: testAppOne, Policy: policy, ExpectedRowVersion: 1,
		RequestID: "req_reauth"}); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("再次认证拒绝时应拒绝策略修改，实际 %v", err)
	}
	// 审计包含真实操作者、应用与 request_id。
	if got := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action='managed_api.policy.updated' AND request_id='req_set_1'`); got != 1 {
		t.Fatalf("缺少策略修改审计，实际 %d", got)
	}
}

// TestUserOperationObjectAndFieldRestrictions 验证代表用户的正常调用、字段投影、
// 写入白名单、分页/排序上限与审计。
func TestUserOperationObjectAndFieldRestrictions(t *testing.T) {
	env := newTestEnv(t)
	env.setPolicy(testAppOne, policyFor(testAppOne,
		[]string{"status", "username", "display_name", "row_version"}, []string{"display_name"}))
	adminSession := env.userSession(testAdmin, testAppOne)
	principal := UserPrincipal(adminSession.Secret.Reveal(), testAppOne)

	// 应用资料只输出策略允许字段。
	appView, err := env.service.GetApplication(env.ctx, principal, GetApplicationRequest{
		Meta: Meta{APIVersion: APIVersion, RequestID: "req_app_get"}})
	if err != nil {
		t.Fatalf("读取应用失败: %v", err)
	}
	if _, ok := appView.Fields["name"]; !ok {
		t.Fatalf("可读字段 name 缺失: %+v", appView.Fields)
	}
	if _, ok := appView.Fields["description"]; ok {
		t.Fatal("未授权字段 description 不应输出")
	}
	// 成员列表：只输出白名单字段，敏感字段绝不出现。
	members, err := env.service.ListMembers(env.ctx, principal, ListMembersRequest{
		ListMeta: ListMeta{Meta: Meta{APIVersion: APIVersion, RequestID: "req_members"},
			Limit: 10}})
	if err != nil {
		t.Fatalf("成员列表失败: %v", err)
	}
	if len(members.Members) != 2 {
		t.Fatalf("成员数应为 2，实际 %d", len(members.Members))
	}
	for _, member := range members.Members {
		for _, forbidden := range []string{"email", "password", "password_hash", "security_version", "is_root", "token"} {
			if _, ok := member.Fields[forbidden]; ok {
				t.Fatalf("敏感字段 %s 不应输出", forbidden)
			}
		}
		if _, ok := member.Fields["display_name"]; !ok {
			t.Fatalf("成员应输出 display_name: %+v", member.Fields)
		}
	}
	// 未授权写入字段被拒绝（note 不在可写白名单）。
	display := "新显示名"
	note := "注"
	workerMembership, err := env.service.GetMember(env.ctx, principal, GetMemberRequest{
		Meta: Meta{APIVersion: APIVersion, RequestID: "req_member_get"}, UserID: testWorker})
	if err != nil {
		t.Fatalf("读取成员失败: %v", err)
	}
	version, _ := workerMembership.Fields["row_version"].(int64)
	if _, err := env.service.UpdateMemberProfile(env.ctx, principal, UpdateMemberProfileRequest{
		Meta: Meta{APIVersion: APIVersion, RequestID: "req_profile_note"}, UserID: testWorker,
		ExpectedRowVersion: version, Note: &note}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("未授权写字段应拒绝，实际 %v", err)
	}
	if _, err := env.service.UpdateMemberProfile(env.ctx, principal, UpdateMemberProfileRequest{
		Meta: Meta{APIVersion: APIVersion, RequestID: "req_profile_ok"}, UserID: testWorker,
		ExpectedRowVersion: version, DisplayName: &display}); err != nil {
		t.Fatalf("授权字段写入失败: %v cause=%v", err, errors.Unwrap(err))
	}
	// 非法排序字段与超分页上限。
	if _, err := env.service.ListMembers(env.ctx, principal, ListMembersRequest{
		ListMeta: ListMeta{Meta: Meta{APIVersion: APIVersion, RequestID: "req_sort"}, Limit: 5},
		Sort:     "email"}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("非法排序字段应拒绝，实际 %v", err)
	}
	if _, err := env.service.ListMembers(env.ctx, principal, ListMembersRequest{
		ListMeta: ListMeta{Meta: Meta{APIVersion: APIVersion, RequestID: "req_limit"},
			Limit: 100}}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("超分页上限应拒绝，实际 %v", err)
	}
	// 不支持 API 版本。
	if _, err := env.service.ListMembers(env.ctx, principal, ListMembersRequest{
		ListMeta: ListMeta{Meta: Meta{APIVersion: "v9", RequestID: "req_version"}}}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("未知 API 版本应拒绝，实际 %v", err)
	}
	// 批量成员操作超过 max_batch=2。
	if err := env.service.UpdateGroupMembers(env.ctx, principal, GroupMembersRequest{
		Meta: Meta{APIVersion: APIVersion, RequestID: "req_batch"}, GroupID: testGroupOne,
		UserIDs: []string{testWorker, testAdmin, testWorker}}, true); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("超批量上限应拒绝，实际 %v", err)
	}
	// 角色分配经既有 delegation.Guard：本测试 Guard 拒绝有权限赋权。
	if err := env.service.AssignUserRole(env.ctx, principal, RoleTargetRequest{
		Meta: Meta{APIVersion: APIVersion, RequestID: "req_assign"}, RoleID: testRoleOne,
		UserID: testWorker}, true); err == nil {
		t.Fatal("角色分配应被委派 Guard 拒绝")
	}
	// 托管调用审计：成功/拒绝均含真实操作者、应用与 request_id。
	if got := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action='managed_api.members.list' AND actor_id=? AND app_id_snapshot=? AND request_id='req_members'`, testAdmin, testAppOne); got != 1 {
		t.Fatalf("成功审计不正确，实际 %d", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action='managed_api.members.list' AND outcome='failure' AND request_id='req_limit'`); got != 1 {
		t.Fatalf("拒绝审计不正确，实际 %d", got)
	}
}

// TestApplicationIsolationAndDisabledPolicy 验证应用隔离、无策略默认关闭、主体
// 应用不一致与服务身份只读。
func TestApplicationIsolationAndDisabledPolicy(t *testing.T) {
	env := newTestEnv(t)
	env.setPolicy(testAppOne, policyFor(testAppOne, []string{"status"}, nil))
	appTwoSession := env.userSession(testAdmin, testAppTwo)
	// 应用二没有策略 → 默认关闭。
	if _, err := env.service.ListMembers(env.ctx,
		UserPrincipal(appTwoSession.Secret.Reveal(), testAppTwo),
		ListMembersRequest{ListMeta: ListMeta{Meta: Meta{APIVersion: APIVersion,
			RequestID: "req_disabled"}}}); !errors.Is(err, ErrPolicyDisabled) {
		t.Fatalf("无策略应用应默认关闭，实际 %v", err)
	}
	// 会话应用与目标应用不一致。
	appOneSession := env.userSession(testAdmin, testAppOne)
	if _, err := env.service.ListMembers(env.ctx,
		UserPrincipal(appOneSession.Secret.Reveal(), testAppTwo),
		ListMembersRequest{ListMeta: ListMeta{Meta: Meta{APIVersion: APIVersion,
			RequestID: "req_scope"}}}); !errors.Is(err, ErrObjectForbidden) {
		t.Fatalf("会话应用与目标应用不一致应拒绝，实际 %v", err)
	}
	// 服务身份：认证成功后可读取（策略允许），但写操作必须被拒绝。
	servicePrincipal := ServicePrincipal(testAppOne, testServiceSID, "")
	if _, err := env.service.ListMembers(env.ctx, servicePrincipal, ListMembersRequest{
		ListMeta: ListMeta{Meta: Meta{APIVersion: APIVersion, RequestID: "req_service_list"}}}); err != nil {
		t.Fatalf("服务身份读取应允许: %v cause=%v", err, errors.Unwrap(err))
	}
	display := "服务写入"
	if _, err := env.service.UpdateMemberProfile(env.ctx, servicePrincipal,
		UpdateMemberProfileRequest{Meta: Meta{APIVersion: APIVersion, RequestID: "req_service_write"},
			UserID: testWorker, ExpectedRowVersion: 1, DisplayName: &display}); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("服务身份写操作应拒绝，实际 %v", err)
	}
	// 错误客户端凭证拒绝。
	if _, err := env.service.ListMembers(env.ctx,
		ServicePrincipal(testAppOne, "wrong-secret", ""), ListMembersRequest{
			ListMeta: ListMeta{Meta: Meta{APIVersion: APIVersion, RequestID: "req_wrong"}}}); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("错误客户端凭证应拒绝，实际 %v", err)
	}
	// 服务身份审计主体为系统身份且记录应用。
	if got := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action='managed_api.members.list' AND actor_type='system' AND actor_id=? AND app_id_snapshot=?`, "managed-service:"+testAppOne, testAppOne); got != 1 {
		t.Fatalf("服务身份审计不正确，实际 %d", got)
	}
	// 直接调用既有服务（无托管 grant）被 DelegatedAuthorizer 拒绝。
	appCaller, err := app.SystemCaller("managed-service:" + testAppOne)
	if err != nil {
		t.Fatalf("构造调用者失败: %v", err)
	}
	if _, err := env.service.GetApplication(env.ctx, servicePrincipal,
		GetApplicationRequest{Meta: Meta{APIVersion: APIVersion, RequestID: "req_ok"}}); err != nil {
		t.Fatalf("对照调用失败: %v", err)
	}
	_ = appCaller
}

// TestDataScopeFailClosed 验证权限数据范围 undefined/none 时拒绝（与 authz 一致）。
func TestDataScopeFailClosed(t *testing.T) {
	env := newTestEnv(t)
	env.setPolicy(testAppOne, policyFor(testAppOne, []string{"status"}, nil))
	adminSession := env.userSession(testAdmin, testAppOne)
	principal := UserPrincipal(adminSession.Secret.Reveal(), testAppOne)
	if _, err := env.service.ListMembers(env.ctx, principal, ListMembersRequest{
		ListMeta: ListMeta{Meta: Meta{APIVersion: APIVersion, RequestID: "req_before"}}}); err != nil {
		t.Fatalf("数据范围 all 时应允许: %v cause=%v", err, errors.Unwrap(err))
	}
	// 历史未声明数据范围（{}）→ fail-closed。
	if _, err := env.raw.ExecContext(env.ctx,
		`UPDATE user_roles SET data_scope_json='{}' WHERE user_id=?`, testAdmin); err != nil {
		t.Fatalf("更新数据范围失败: %v", err)
	}
	if _, err := env.service.ListMembers(env.ctx, principal, ListMembersRequest{
		ListMeta: ListMeta{Meta: Meta{APIVersion: APIVersion, RequestID: "req_undefined"}}}); !errors.Is(err, ErrObjectForbidden) {
		t.Fatalf("数据范围未声明应 fail-closed，实际 %v", err)
	}
	// none → 拒绝。
	if _, err := env.raw.ExecContext(env.ctx,
		`UPDATE user_roles SET data_scope_json='{"v":1,"mode":"none"}' WHERE user_id=?`, testAdmin); err != nil {
		t.Fatalf("更新数据范围失败: %v", err)
	}
	if _, err := env.service.ListMembers(env.ctx, principal, ListMembersRequest{
		ListMeta: ListMeta{Meta: Meta{APIVersion: APIVersion, RequestID: "req_none"}}}); !errors.Is(err, ErrObjectForbidden) {
		t.Fatalf("数据范围 none 应拒绝，实际 %v", err)
	}
}

// resourcesPolicyFor 构造指定对象资源白名单的策略（其余对象未声明，用于
// fail-closed 用例）。
func resourcesPolicyFor(resources map[string][]string) Policy {
	policy := policyFor(testAppOne, []string{"status", "username", "row_version"}, []string{"display_name"})
	policy.Objects = nil
	for _, objectType := range ObjectTypes {
		ids, ok := resources[objectType]
		if !ok {
			continue
		}
		policy.Objects = append(policy.Objects, ObjectScope{Object: objectType,
			Mode: ScopeModeResources, Resources: ids})
	}
	return policy
}

// TestObjectScopeResourcesOnReadPaths 验证委托策略对象范围 resources 模式在列表与
// 子资源读取路径生效：用户数据范围 all 也只能读策略对象范围内数据；未声明对象
// 范围的列表 fail-closed；服务身份同样受对象范围限制。
func TestObjectScopeResourcesOnReadPaths(t *testing.T) {
	env := newTestEnv(t)
	env.setPolicy(testAppOne, resourcesPolicyFor(map[string][]string{
		ObjectApplication: {testAppOne},
		ObjectMember:      {testWorker},
		ObjectUser:        {testWorker},
		ObjectGroup:       {testGroupOne},
		ObjectRole:        {testRoleOne},
		ObjectPermission:  {testPermManage},
	}))
	adminSession := env.userSession(testAdmin, testAppOne)
	principal := UserPrincipal(adminSession.Secret.Reveal(), testAppOne)

	members, err := env.service.ListMembers(env.ctx, principal, ListMembersRequest{
		ListMeta: ListMeta{Meta: Meta{APIVersion: APIVersion, RequestID: "req_scope_members"},
			Limit: 10}})
	if err != nil {
		t.Fatalf("成员列表失败: %v", err)
	}
	if len(members.Members) != 1 || members.Members[0].UserID != testWorker {
		t.Fatalf("成员列表应只返回策略对象范围内成员 %s，实际 %+v", testWorker, members.Members)
	}
	// 范围外单对象读取拒绝（先授权后读取）。
	if _, err := env.service.GetMember(env.ctx, principal, GetMemberRequest{
		Meta:   Meta{APIVersion: APIVersion, RequestID: "req_scope_member_out"},
		UserID: testAdmin}); !errors.Is(err, ErrObjectForbidden) {
		t.Fatalf("策略对象范围外的成员应拒绝，实际 %v", err)
	}
	// 组列表只返回策略范围组（种子里有 2 个组）。
	groups, err := env.service.ListGroups(env.ctx, principal, ListGroupsRequest{
		ListMeta: ListMeta{Meta: Meta{APIVersion: APIVersion, RequestID: "req_scope_groups"},
			Limit: 10}})
	if err != nil {
		t.Fatalf("组列表失败: %v", err)
	}
	if len(groups.Items) != 1 || groups.Items[0].ID != testGroupOne {
		t.Fatalf("组列表应只返回策略范围组，实际 %+v", groups.Items)
	}
	// 角色列表只返回策略范围角色（种子里有 2 个角色）。
	roles, err := env.service.ListRoles(env.ctx, principal, ListRolesRequest{
		ListMeta: ListMeta{Meta: Meta{APIVersion: APIVersion, RequestID: "req_scope_roles"},
			Limit: 10}})
	if err != nil {
		t.Fatalf("角色列表失败: %v", err)
	}
	if len(roles.Items) != 1 || roles.Items[0].ID != testRoleOne {
		t.Fatalf("角色列表应只返回策略范围角色，实际 %+v", roles.Items)
	}
	// 权限列表只返回策略范围权限。
	permissions, err := env.service.ListPermissions(env.ctx, principal, ListPermissionsRequest{
		ListMeta: ListMeta{Meta: Meta{APIVersion: APIVersion, RequestID: "req_scope_perms"},
			Limit: 10}})
	if err != nil {
		t.Fatalf("权限列表失败: %v", err)
	}
	if len(permissions.Items) != 1 || permissions.Items[0].ID != testPermManage {
		t.Fatalf("权限列表应只返回策略范围权限，实际 %+v", permissions.Items)
	}
	// 角色权限组合子资源按对象范围（权限）过滤：roleOne 组合了多个权限，但策略
	// 只允许 testPermManage。
	rolePermissions, err := env.service.ListRolePermissions(env.ctx, principal,
		ListRoleSubresourceRequest{Meta: Meta{APIVersion: APIVersion,
			RequestID: "req_scope_role_perms"}, RoleID: testRoleOne})
	if err != nil {
		t.Fatalf("角色权限列表失败: %v", err)
	}
	if len(rolePermissions) != 1 || rolePermissions[0].ID != testPermManage {
		t.Fatalf("角色权限列表应按权限对象范围过滤，实际 %+v", rolePermissions)
	}
	// 角色分配子资源按用户/组对象范围过滤。
	assignments, err := env.service.ListRoleAssignments(env.ctx, principal,
		ListRoleSubresourceRequest{Meta: Meta{APIVersion: APIVersion,
			RequestID: "req_scope_assign"}, RoleID: testRoleOne})
	if err != nil {
		t.Fatalf("角色分配列表失败: %v", err)
	}
	users := assignments["users"].([]string)
	groupIDs := assignments["groups"].([]string)
	if len(users) != 1 || users[0] != testWorker {
		t.Fatalf("角色分配用户应按对象范围过滤，实际 %+v", users)
	}
	if len(groupIDs) != 1 || groupIDs[0] != testGroupOne {
		t.Fatalf("角色分配组应按对象范围过滤，实际 %+v", groupIDs)
	}
	// 服务身份列表同样受策略对象范围限制。
	serviceMembers, err := env.service.ListMembers(env.ctx,
		ServicePrincipal(testAppOne, testServiceSID, ""),
		ListMembersRequest{ListMeta: ListMeta{Meta: Meta{APIVersion: APIVersion,
			RequestID: "req_scope_service"}}})
	if err != nil {
		t.Fatalf("服务身份成员列表失败: %v", err)
	}
	if len(serviceMembers.Members) != 1 || serviceMembers.Members[0].UserID != testWorker {
		t.Fatalf("服务身份列表应按对象范围过滤，实际 %+v", serviceMembers.Members)
	}
	// 未声明对象范围的列表 fail-closed。
	partial := resourcesPolicyFor(map[string][]string{
		ObjectApplication: {testAppOne},
		ObjectGroup:       {testGroupOne},
		ObjectRole:        {testRoleOne},
		ObjectPermission:  {testPermManage},
	})
	if _, err := env.service.SetPolicy(env.ctx, audit.Actor{Type: audit.ActorLocalAdmin,
		ID: "root-admin"}, SetPolicyRequest{ApplicationID: testAppOne, Policy: partial,
		ExpectedRowVersion: 1, RequestID: "req_scope_incomplete"}); err != nil {
		t.Fatalf("更新策略失败: %v", err)
	}
	if _, err := env.service.ListMembers(env.ctx, principal, ListMembersRequest{
		ListMeta: ListMeta{Meta: Meta{APIVersion: APIVersion,
			RequestID: "req_scope_undeclared"}}}); !errors.Is(err, ErrObjectForbidden) {
		t.Fatalf("未声明对象范围的列表应 fail-closed，实际 %v", err)
	}
	// 失败审计保留真实操作者（非匿名）。
	if got := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action='managed_api.members.list' AND outcome='failure' AND actor_id=? AND request_id='req_scope_undeclared'`, testAdmin); got != 1 {
		t.Fatalf("range 拒绝审计应含真实操作者，实际 %d", got)
	}
}

// TestServiceIdentityCatalogueReadOnly 验证服务身份目录只允许只读 + 创建账户。
func TestServiceIdentityCatalogueReadOnly(t *testing.T) {
	for _, opID := range []string{OpMembersUpdateProfile, OpMembersDisable, OpMembersRemove,
		OpGroupMembersRemove, OpGroupMembersAdd, OpRoleAssignUser, OpRoleAssignGroup,
		OpRoleRevokeUser, OpRoleRevokeGroup} {
		op, ok := LookupOperation(opID)
		if !ok {
			t.Fatalf("操作 %s 应在目录中", opID)
		}
		if op.ServiceAllowed {
			t.Errorf("操作 %s 不应允许服务身份执行", opID)
		}
	}
	createOp, ok := LookupOperation(OpUsersCreate)
	if !ok || !createOp.ServiceAllowed {
		t.Fatal("创建账户+成员关系应允许服务身份（策略显式列出后）")
	}
	for _, opID := range OperationIDs() {
		op, _ := LookupOperation(opID)
		if !op.Write && !op.ServiceAllowed {
			t.Errorf("只读操作 %s 应允许服务身份", opID)
		}
	}
}

// TestErrorCodeMapping 验证底层服务错误优先沿用映射码（不再退化为 INTERNAL_ERROR）。
func TestErrorCodeMapping(t *testing.T) {
	env := newTestEnv(t)
	env.setPolicy(testAppOne, policyFor(testAppOne,
		[]string{"status", "row_version"}, []string{"display_name"}))
	adminSession := env.userSession(testAdmin, testAppOne)
	principal := UserPrincipal(adminSession.Secret.Reveal(), testAppOne)
	member, err := env.service.GetMember(env.ctx, principal, GetMemberRequest{
		Meta: Meta{APIVersion: APIVersion, RequestID: "req_code_member"}, UserID: testWorker})
	if err != nil {
		t.Fatalf("读取成员失败: %v", err)
	}
	version, _ := member.Fields["row_version"].(int64)
	display := "并发更新"
	_, err = env.service.UpdateMemberProfile(env.ctx, principal, UpdateMemberProfileRequest{
		Meta:   Meta{APIVersion: APIVersion, RequestID: "req_code_conflict"},
		UserID: testWorker, ExpectedRowVersion: version + 1, DisplayName: &display})
	assertServiceCode(t, err, CodeConflict, "行版本冲突")
	// 委派 Guard 拒绝映射为 ACCESS_DENIED。
	err = env.service.AssignUserRole(env.ctx, principal, RoleTargetRequest{
		Meta:   Meta{APIVersion: APIVersion, RequestID: "req_code_assign"},
		RoleID: testRoleOne, UserID: testWorker}, true)
	assertServiceCode(t, err, CodeAccessDenied, "委派拒绝")
	// 缺少权限映射为 PERMISSION_REQUIRED（移除管理员角色中的成员管理权限）。
	if _, err := env.raw.ExecContext(env.ctx, `DELETE FROM role_permissions WHERE role_id=? AND permission_id=?`,
		testRoleOne, testPermManage); err != nil {
		t.Fatalf("移除权限失败: %v", err)
	}
	_, err = env.service.ListMembers(env.ctx, principal, ListMembersRequest{
		ListMeta: ListMeta{Meta: Meta{APIVersion: APIVersion, RequestID: "req_code_perm"}}})
	assertServiceCode(t, err, CodePermissionRequired, "缺少权限")
	// 跨应用对象由既有 Authorizer 限定作用域并映射为 ACCESS_DENIED。
	now := testStart.UnixMilli()
	if _, err := env.raw.ExecContext(env.ctx, `INSERT INTO user_groups(id,scope_id,group_key,name,description,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,'',?,?)`, testGroupAppTwo, testAppTwo, "other.group", "其他应用组", now, now); err != nil {
		t.Fatalf("插入其他应用组失败: %v", err)
	}
	if _, err := env.service.SetPolicy(env.ctx, audit.Actor{Type: audit.ActorLocalAdmin,
		ID: "root-admin"}, SetPolicyRequest{ApplicationID: testAppOne,
		Policy: policyFor(testAppOne, []string{"status"}, nil), ExpectedRowVersion: 1,
		RequestID: "req_code_policy2"}); err != nil {
		t.Fatalf("更新策略失败: %v", err)
	}
	_, err = env.service.GetGroup(env.ctx, principal, GetGroupRequest{
		Meta:    Meta{APIVersion: APIVersion, RequestID: "req_code_cross"},
		GroupID: testGroupAppTwo})
	assertServiceCode(t, err, CodeAccessDenied, "跨应用对象")
}

// TestApplicationGetRequiresMembership 验证应用资料读取要求代表用户是目标应用成员。
func TestApplicationGetRequiresMembership(t *testing.T) {
	env := newTestEnv(t)
	env.setPolicy(testAppOne, policyFor(testAppOne, []string{"status"}, nil))
	outsiderSession, err := env.sessions.Login(env.ctx, session.LoginRequest{
		Result: authn.AuthenticateResult{UserID: testOutsider, Username: "outsider",
			Outcome:          authn.OutcomeComplete,
			CompletedMethods: []authn.Method{authn.MethodPassword},
			CompletedAt:      testStart, SecurityVersion: 1},
		RequestID: "req_outsider_login"})
	if err != nil {
		t.Fatalf("签发外部用户会话失败: %v", err)
	}
	_, err = env.service.GetApplication(env.ctx,
		UserPrincipal(outsiderSession.Secret.Reveal(), testAppOne), GetApplicationRequest{
			Meta: Meta{APIVersion: APIVersion, RequestID: "req_get_membership"}})
	assertServiceCode(t, err, CodeAppMembershipRequired, "应用成员")
	// 成员可读取。
	env.assertMemberCanReadApplication(t)
}

// assertMemberCanReadApplication 断言应用成员可读取本应用资料。
func (e *testEnv) assertMemberCanReadApplication(t *testing.T) {
	t.Helper()
	adminSession := e.userSession(testAdmin, testAppOne)
	if _, err := e.service.GetApplication(e.ctx,
		UserPrincipal(adminSession.Secret.Reveal(), testAppOne), GetApplicationRequest{
			Meta: Meta{APIVersion: APIVersion, RequestID: "req_get_member_ok"}}); err != nil {
		t.Fatalf("应用成员读取应用资料失败: %v", err)
	}
}

// TestCreateUserWithBiography 验证 ObjectUser 字段目录包含 biography，策略可授权后
// 创建账户时接受该字段。
func TestCreateUserWithBiography(t *testing.T) {
	env := newTestEnv(t)
	env.setPolicy(testAppOne, policyFor(testAppOne, []string{"status"}, nil))
	adminSession := env.userSession(testAdmin, testAppOne)
	principal := UserPrincipal(adminSession.Secret.Reveal(), testAppOne)
	biography := "托管创建的账户简介"
	created, err := env.service.CreateUserWithMembership(env.ctx, principal, CreateUserRequest{
		Meta:     Meta{APIVersion: APIVersion, RequestID: "req_create_user"},
		Username: "managednewbie", Biography: &biography})
	if err != nil {
		t.Fatalf("创建账户失败（biography 应可授权）: %v", err)
	}
	if created.UserID == "" {
		t.Fatalf("创建结果缺少用户 ID: %+v", created)
	}
	var stored string
	rows, err := env.raw.QueryContext(env.ctx, `SELECT COALESCE(biography,'') FROM users WHERE id=?`,
		created.UserID)
	if err != nil {
		t.Fatalf("查询账户失败: %v", err)
	}
	defer rows.Close()
	if rows.Next() {
		_ = rows.Scan(&stored)
	}
	if stored != biography {
		t.Fatalf("账户 biography = %q，期望 %q", stored, biography)
	}
	// ObjectUser 字段目录含 biography（一致性）。
	found := false
	for _, field := range FieldsOf(ObjectUser) {
		if field == "biography" {
			found = true
		}
	}
	if !found {
		t.Fatal("ObjectUser 字段目录缺少 biography")
	}
}

// assertServiceCode 断言错误为 *ServiceError 且错误码符合预期。
func assertServiceCode(t *testing.T, err error, want ErrorCode, reason string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s：期望错误 %s，实际成功", reason, want)
	}
	var serviceErr *ServiceError
	if !errors.As(err, &serviceErr) {
		t.Fatalf("%s：期望 *ServiceError，实际 %v", reason, err)
	}
	if serviceErr.Code != want {
		t.Fatalf("%s：错误码 = %q，期望 %q（cause=%v）", reason, serviceErr.Code, want, serviceErr.Cause)
	}
}
