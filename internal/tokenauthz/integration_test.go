package tokenauthz_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	authzsqlite "github.com/kagurazakayashi/EvernightLogin/internal/authz/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/token"
	tokensqlite "github.com/kagurazakayashi/EvernightLogin/internal/token/sqlite"
	. "github.com/kagurazakayashi/EvernightLogin/internal/tokenauthz"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// 真实 SQLite + 真实令牌服务 + 真实权限引擎的集成测试常量。
const (
	testRoleAppOne = "rol_00000000000000000000000000000001"
	testRoleAppTwo = "rol_00000000000000000000000000000002"
	testPermOne    = "perm_00000000000000000000000000000001"
	testPermTwo    = "perm_00000000000000000000000000000002"
	testOtherUser  = "usr_00000000000000000000000000000002"
)

// integrationEnv 是真实依赖装配的测试环境。
type integrationEnv struct {
	t           *testing.T
	ctx         context.Context
	raw         *storagesqlite.Store
	closed      bool
	tokens      *token.Service
	clients     *fakeClients
	revocation  *fakeRevocations
	combined    *Service
	appOneToken string
	appTwoToken string
}

// newIntegrationEnv 创建临时数据库、执行全部迁移并装配令牌/授权/判定服务。
func newIntegrationEnv(t *testing.T) *integrationEnv {
	t.Helper()
	ctx := context.Background()
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(
		filepath.Join(t.TempDir(), "tokenauthz.db")))
	if err != nil {
		t.Fatalf("打开临时数据库失败: %v", err)
	}
	env := &integrationEnv{t: t, ctx: ctx, raw: raw, clients: &fakeClients{}, revocation: &fakeRevocations{}}
	t.Cleanup(func() {
		if !env.closed {
			_ = env.raw.Close()
		}
	})
	migrationSet, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移失败: %v", err)
	}
	if _, err := raw.Migrate(ctx, migrationSet); err != nil {
		t.Fatalf("执行迁移失败: %v", err)
	}
	env.insertFixtures()

	// 真实安全审计（令牌签发/拒绝审计）。
	auditStore, err := auditsqlite.New(raw)
	if err != nil {
		t.Fatalf("审计存储失败: %v", err)
	}
	auditRecorder, err := audit.New(auditStore, audit.Options{Now: time.Now})
	if err != nil {
		t.Fatalf("审计服务失败: %v", err)
	}
	keyring, err := secrets.GenerateKeyring("k1", time.Now())
	if err != nil {
		t.Fatalf("密钥环失败: %v", err)
	}
	sealer, err := secrets.NewSealer(keyring, nil)
	if err != nil {
		t.Fatalf("Sealer 失败: %v", err)
	}
	tokenStore, err := tokensqlite.New(raw)
	if err != nil {
		t.Fatalf("令牌存储失败: %v", err)
	}
	env.tokens, err = token.New(token.Options{
		Store: tokenStore, Audit: auditRecorder, Sealer: sealer,
		Issuer: "https://issuer.example.test", Clients: env.clients,
		Authorizer: token.IssuanceAuthorizerFunc(func(context.Context, token.Caller, token.IssuanceRequest) error {
			return nil
		}),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("令牌服务失败: %v", err)
	}

	// 真实权限引擎（读同一临时库的当前账户/成员/角色/权限状态）。
	authzStore, err := authzsqlite.New(raw)
	if err != nil {
		t.Fatalf("权限存储失败: %v", err)
	}
	queryAuthorizer, err := authz.NewStaticAuthorizer(authz.AuthorizerOptions{LocalAdminIDs: []string{"integration-admin"}})
	if err != nil {
		t.Fatalf("权限查询授权器失败: %v", err)
	}
	engine, err := authz.New(authz.Options{Store: authzStore, Authorizer: queryAuthorizer,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatalf("权限引擎失败: %v", err)
	}
	env.combined, err = New(Options{
		Verifier: env.tokens, Clients: env.clients, Revocations: env.revocation,
		Permissions: engine, Audit: auditRecorder,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("联合判定服务失败: %v", err)
	}
	env.appOneToken = env.issueUserToken(testAppOne)
	env.appTwoToken = env.issueUserToken(testAppTwo)
	return env
}

// insertFixtures 直接插入合成账户/应用/成员/权限/角色数据。
func (e *integrationEnv) insertFixtures() {
	e.t.Helper()
	now := time.Now().UnixMilli()
	exec := func(query string, args ...any) {
		e.t.Helper()
		if _, err := e.raw.ExecContext(context.Background(), query, args...); err != nil {
			e.t.Fatalf("插入测试数据失败: %v\nSQL: %s", err, query)
		}
	}
	insertUser := func(userID, username, status string) {
		exec(`INSERT INTO users(id,username,username_normalized,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,0,1,1,?,?)`, userID, username, username, status, now, now)
	}
	insertUser(testUser, "tokenuser", "active")
	insertUser(testOtherUser, "otheruser", "active")
	insertApplication := func(applicationID, name, status, clientType string) {
		exec(`INSERT INTO applications(id,name,description,status,client_type,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,'',?,?,1,?,?)`, applicationID, name, status, clientType, now, now)
		exec(`INSERT INTO scopes(id,kind,app_id) VALUES(?,'application',?)`, applicationID, applicationID)
	}
	insertApplication(testAppOne, "应用一", "active", "confidential")
	insertApplication(testAppTwo, "应用二", "active", "confidential")
	insertMembership := func(applicationID, userID, status string) {
		exec(`INSERT INTO app_memberships(app_id,user_id,status,profile_json,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'{"v":1}',1,?,?)`, applicationID, userID, status, now, now)
	}
	insertMembership(testAppOne, testUser, "active")
	insertMembership(testAppTwo, testUser, "active")
	insertPermission := func(permissionID, scopeID, key string) {
		exec(`INSERT INTO permissions(id,scope_id,permission_key,name,description,limits_text,is_builtin,root_only,enabled,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,'','',0,0,1,?,?)`, permissionID, scopeID, key, key, now, now)
	}
	insertPermission(testPermOne, testAppOne, testPermission)
	insertPermission(testPermTwo, testAppTwo, testPermission)
	insertRole := func(roleID, scopeID, roleKey string) {
		exec(`INSERT INTO roles(id,scope_id,role_key,name,description,limits_text,is_builtin,enabled,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,'','',0,1,?,?)`, roleID, scopeID, roleKey, roleKey, now, now)
	}
	insertRole(testRoleAppOne, testAppOne, "invoices.approver")
	insertRole(testRoleAppTwo, testAppTwo, "invoices.approver")
	// 两个应用都有同名权限 invoices.approve；用户只在应用一被授予。
	exec(`INSERT INTO role_permissions(role_id,permission_id,scope_id) VALUES(?,?,?)`,
		testRoleAppOne, testPermOne, testAppOne)
	exec(`INSERT INTO user_roles(user_id,role_id,scope_id,data_scope_json,assigned_by,created_at_ms)
VALUES(?,?,?,'{}','integration-admin',?)`, testUser, testRoleAppOne, testAppOne, now)

	e.clients.set(testAppOne, token.ClientInfo{
		ClientID: testAppOne, ApplicationID: testAppOne, ClientType: "confidential", AppActive: true,
		GrantTypes: []string{string(token.GrantAuthorizationCode)},
		Scopes:     nil, Audiences: []string{testAudience},
	})
	e.clients.set(testAppTwo, token.ClientInfo{
		ClientID: testAppTwo, ApplicationID: testAppTwo, ClientType: "confidential", AppActive: true,
		GrantTypes: []string{string(token.GrantAuthorizationCode)},
		Scopes:     nil, Audiences: []string{testAudience},
	})
}

// issueUserToken 用真实令牌服务签发代表 testUser 的 Access Token。
func (e *integrationEnv) issueUserToken(clientID string) string {
	e.t.Helper()
	caller, err := token.SystemCaller("tokenauthz-integration")
	if err != nil {
		e.t.Fatalf("构造签发调用者失败: %v", err)
	}
	issued, err := e.tokens.IssueAccessToken(e.ctx, caller, token.IssueAccessTokenRequest{
		ClientID: clientID, SubjectUserID: testUser,
		GrantType: token.GrantAuthorizationCode,
		Audiences: []string{testAudience}, RequestID: "req_issue_" + clientID[len(clientID)-4:],
	})
	if err != nil {
		e.t.Fatalf("签发 Access Token 失败: %v", err)
	}
	return issued.Token.Reveal()
}

// resourceFor 构造指定应用+audience 的可信资源服务身份。
func resourceFor(t *testing.T, applicationID string) ResourceService {
	t.Helper()
	service, err := NewResourceService("billing-api", applicationID, testAudience)
	if err != nil {
		t.Fatalf("构造资源服务身份失败: %v", err)
	}
	return service
}

// TestIntegrationRealTokenAndPermission 验证真实 JWT + 真实 SQLite 权限的联合判定，
// 并验证权限撤销后立即生效（无缓存失效窗口）。
func TestIntegrationRealTokenAndPermission(t *testing.T) {
	env := newIntegrationEnv(t)
	req := Request{AccessToken: env.appOneToken, Permissions: []string{testPermission}, RequestID: "req_it_1"}
	decision, err := env.combined.Decide(env.ctx, resourceFor(t, testAppOne), req)
	if err != nil {
		t.Fatalf("真实令牌联合判定失败: %v", err)
	}
	if !decision.Allow || decision.Subject != testUser || decision.ClientID != testAppOne {
		t.Fatalf("真实令牌应允许（用户有应用一审批权限）: %+v", decision)
	}
	// 撤销角色组合（删除角色权限关联）后下一次判定必须立即拒绝。
	if _, err := env.raw.ExecContext(env.ctx,
		`DELETE FROM role_permissions WHERE role_id=? AND permission_id=?`, testRoleAppOne, testPermOne); err != nil {
		t.Fatalf("撤销权限失败: %v", err)
	}
	decision, err = env.combined.Decide(env.ctx, resourceFor(t, testAppOne), req)
	if err != nil {
		t.Fatalf("撤销后判定失败: %v", err)
	}
	if decision.Allow || decision.Code != CodePermissionRequired {
		t.Fatalf("权限撤销后应立即拒绝（无缓存失效窗口），实际 %+v", decision)
	}
}

// TestIntegrationSameNamePermissionIsolation 验证同名应用权限隔离：
// 令牌来自应用二且用户不是应用二审批人时，同名 invoices.approve 不能借用应用一授权。
func TestIntegrationSameNamePermissionIsolation(t *testing.T) {
	env := newIntegrationEnv(t)
	req := Request{AccessToken: env.appTwoToken, Permissions: []string{testPermission}, RequestID: "req_it_2"}
	decision, err := env.combined.Decide(env.ctx, resourceFor(t, testAppTwo), req)
	if err != nil {
		t.Fatalf("应用二判定失败: %v", err)
	}
	if decision.Allow || decision.Code != CodePermissionRequired {
		t.Fatalf("应用二同名权限不应借用应用一授权: %+v", decision)
	}
	// 跨应用令牌被可信应用映射拒绝（应用一的令牌不能用于应用二资源判定）。
	crossReq := Request{AccessToken: env.appOneToken,
		Permissions: []string{testPermission}, RequestID: "req_it_3"}
	crossDecision, err := env.combined.Decide(env.ctx, resourceFor(t, testAppTwo), crossReq)
	if err != nil {
		t.Fatalf("跨应用判定失败: %v", err)
	}
	if crossDecision.Allow || crossDecision.Code != CodeAppScopeMismatch {
		t.Fatalf("跨应用令牌应返回 APP_SCOPE_MISMATCH: %+v", crossDecision)
	}
}

// TestIntegrationMembershipAndAccountState 验证成员移除/账户禁用即时反映。
func TestIntegrationMembershipAndAccountState(t *testing.T) {
	env := newIntegrationEnv(t)
	req := Request{AccessToken: env.appOneToken, Permissions: []string{testPermission}, RequestID: "req_it_4"}
	if _, err := env.raw.ExecContext(env.ctx,
		`UPDATE app_memberships SET status='disabled' WHERE app_id=? AND user_id=?`,
		testAppOne, testUser); err != nil {
		t.Fatalf("移除成员失败: %v", err)
	}
	decision, err := env.combined.Decide(env.ctx, resourceFor(t, testAppOne), req)
	if err != nil {
		t.Fatalf("成员移除后判定失败: %v", err)
	}
	if decision.Allow || decision.Code != CodeAppMembershipRequired {
		t.Fatalf("成员移除后应拒绝: %+v", decision)
	}
	if _, err := env.raw.ExecContext(env.ctx,
		`UPDATE users SET status='disabled' WHERE id=?`, testUser); err != nil {
		t.Fatalf("禁用账户失败: %v", err)
	}
	decision, err = env.combined.Decide(env.ctx, resourceFor(t, testAppOne), req)
	if err != nil {
		t.Fatalf("账户禁用后判定失败: %v", err)
	}
	if decision.Allow || decision.Code != CodeUserDisabled {
		t.Fatalf("账户禁用后应拒绝: %+v", decision)
	}
}

// TestIntegrationDataScopeResource 验证真实数据范围契约下的资源判定。
func TestIntegrationDataScopeResource(t *testing.T) {
	env := newIntegrationEnv(t)
	if _, err := env.raw.ExecContext(env.ctx,
		`UPDATE user_roles SET data_scope_json='{"v":1,"mode":"resources","resources":["invoice-1"]}'
WHERE user_id=? AND role_id=?`, testUser, testRoleAppOne); err != nil {
		t.Fatalf("设置数据范围失败: %v", err)
	}
	req := Request{AccessToken: env.appOneToken, Permissions: []string{testPermission},
		ResourceID: "invoice-1", RequestID: "req_it_5"}
	decision, err := env.combined.Decide(env.ctx, resourceFor(t, testAppOne), req)
	if err != nil || !decision.Allow || !decision.ResourceAllowed {
		t.Fatalf("资源在数据范围内应允许: %+v err=%v", decision, err)
	}
	req.ResourceID = "invoice-2"
	req.RequestID = "req_it_6"
	decision, err = env.combined.Decide(env.ctx, resourceFor(t, testAppOne), req)
	if err != nil {
		t.Fatalf("资源判定失败: %v", err)
	}
	if decision.Allow || decision.Code != CodeResourceForbidden || decision.Reason != "resource_not_in_scope" {
		t.Fatalf("资源超出数据范围应拒绝: %+v", decision)
	}
	// 历史未声明数据范围（{}）时资源检查 fail-closed。
	if _, err := env.raw.ExecContext(env.ctx,
		`UPDATE user_roles SET data_scope_json='{}' WHERE user_id=? AND role_id=?`,
		testUser, testRoleAppOne); err != nil {
		t.Fatalf("恢复数据范围失败: %v", err)
	}
	req.ResourceID = "invoice-1"
	req.RequestID = "req_it_7"
	decision, err = env.combined.Decide(env.ctx, resourceFor(t, testAppOne), req)
	if err != nil {
		t.Fatalf("资源判定失败: %v", err)
	}
	if decision.Allow || decision.Code != CodeResourceForbidden || decision.Reason != "data_scope_undefined" {
		t.Fatalf("未声明数据范围时资源检查应拒绝: %+v", decision)
	}
}

// TestIntegrationIDTokenAndSessionSecretRejected 验证 ID Token 与会话秘密不能冒充
// 业务 Access Token（ID Token 混用、受限会话访问普通业务）。
func TestIntegrationIDTokenAndSessionSecretRejected(t *testing.T) {
	env := newIntegrationEnv(t)
	caller, err := token.SystemCaller("tokenauthz-integration")
	if err != nil {
		t.Fatalf("构造签发调用者失败: %v", err)
	}
	idToken, err := env.tokens.IssueIDToken(env.ctx, caller, token.IssueIDTokenRequest{
		ClientID: testAppOne, SubjectUserID: testUser, RequestID: "req_it_id1",
	})
	if err != nil {
		t.Fatalf("签发 ID Token 失败: %v", err)
	}
	// 受限会话秘密形状（本服务只接受 Access Token，绝不把会话当业务凭证）。
	sessionSecret := "ses_00000000000000000000000000000000000001.0123456789012345678901234567890123456789012"
	for name, raw := range map[string]string{
		"ID Token": idToken.Token.Reveal(),
		"会话秘密":     sessionSecret,
	} {
		decision, err := env.combined.Decide(env.ctx, resourceFor(t, testAppOne), Request{
			AccessToken: raw, Permissions: []string{testPermission}, RequestID: "req_it_mix",
		})
		if err != nil {
			t.Fatalf("%s 混用应为业务拒绝: %v", name, err)
		}
		if decision.Allow || decision.Code != CodeTokenInvalid {
			t.Fatalf("%s 冒充 Access Token 应返回 TOKEN_INVALID: %+v", name, decision)
		}
	}
}

// TestIntegrationDatabaseOutageDenies 验证断库时返回不可用错误（业务默认拒绝）。
func TestIntegrationDatabaseOutageDenies(t *testing.T) {
	env := newIntegrationEnv(t)
	env.closed = true
	if err := env.raw.Close(); err != nil {
		t.Fatalf("关闭数据库失败: %v", err)
	}
	decision, err := env.combined.Decide(env.ctx, resourceFor(t, testAppOne), Request{
		AccessToken: env.appOneToken, Permissions: []string{testPermission}, RequestID: "req_it_down",
	})
	if err == nil {
		t.Fatalf("断库时必须返回错误（业务视为拒绝），实际 allow=%v", decision.Allow)
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("断库应返回 ErrUnavailable，实际 %v", err)
	}
	if CodeOf(err) != CodeAuthzUnavailable {
		t.Fatalf("断库错误码应为 AUTHZ_UNAVAILABLE，实际 %q", CodeOf(err))
	}
}
