package delegation_test

import (
	"context"
	"database/sql"
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
	delegationsqlite "github.com/kagurazakayashi/EvernightLogin/internal/delegation/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// 合成稳定 ID，只用于临时数据库。
const (
	testAdmin        = "usr_11111111111111111111111111111111"
	testMember       = "usr_22222222222222222222222222222222"
	testOther        = "usr_33333333333333333333333333333333"
	testRoot         = "usr_44444444444444444444444444444444"
	testDormant      = "usr_55555555555555555555555555555555"
	testDisabledUser = "usr_66666666666666666666666666666666"

	testAppOne      = "app_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testAppTwo      = "app_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testAppDisabled = "app_cccccccccccccccccccccccccccccccc"

	testPermOne      = "perm_11111111111111111111111111111111"
	testPermTwo      = "perm_22222222222222222222222222222222"
	testPermDisabled = "perm_33333333333333333333333333333333"
	testPermRootOnly = "perm_44444444444444444444444444444444"
	testPermFour     = "perm_55555555555555555555555555555555"

	testRoleOne  = "role_11111111111111111111111111111111"
	testRoleTwo  = "role_22222222222222222222222222222222"
	testGroupOne = "grp_11111111111111111111111111111111"
	testGroupTwo = "grp_22222222222222222222222222222222"
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

func (c *fakeClock) Advance(delta time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(delta)
}

type testEnv struct {
	t          *testing.T
	raw        *storagesqlite.Store
	store      *delegationsqlite.Store
	auditStore *auditsqlite.Store
	recorder   *audit.Recorder
	service    *delegation.Service
	clock      *fakeClock
	system     delegation.Caller
	local      delegation.Caller
	adminUser  delegation.Caller
	memberUser delegation.Caller
}

// prepareEnv 打开临时 SQLite、执行全部迁移并构造委派服务。
func prepareEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(filepath.Join(testutil.TempDir(t), "delegation.sqlite")))
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
	store, err := delegationsqlite.New(raw)
	if err != nil {
		t.Fatalf("构造委派存储失败: %v", err)
	}
	auditStore, err := auditsqlite.New(raw)
	if err != nil {
		t.Fatalf("构造审计存储失败: %v", err)
	}
	clock := &fakeClock{now: time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)}
	recorder, err := audit.New(auditStore, audit.Options{Now: clock.Now})
	if err != nil {
		t.Fatalf("构造审计记录器失败: %v", err)
	}
	service, err := delegation.New(delegation.Options{
		Store: store, Audit: recorder, Now: clock.Now,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("构造委派服务失败: %v", err)
	}
	system, err := delegation.SystemCaller("system-1")
	if err != nil {
		t.Fatalf("构造系统调用者失败: %v", err)
	}
	local, err := delegation.LocalBootstrapCaller("operator-1")
	if err != nil {
		t.Fatalf("构造本地调用者失败: %v", err)
	}
	adminUser, err := delegation.UserCaller(testAdmin)
	if err != nil {
		t.Fatalf("构造管理员调用者失败: %v", err)
	}
	memberUser, err := delegation.UserCaller(testMember)
	if err != nil {
		t.Fatalf("构造成员调用者失败: %v", err)
	}
	env := &testEnv{t: t, raw: raw, store: store, auditStore: auditStore, recorder: recorder,
		service: service, clock: clock, system: system, local: local,
		adminUser: adminUser, memberUser: memberUser}
	env.seed()
	return env
}

// seed 写入合成账户、应用、应用成员、权限、角色、用户组与分配。
func (e *testEnv) seed() {
	now := e.clock.Now().UnixMilli()
	exec := func(statement string, args ...any) {
		e.t.Helper()
		if _, err := e.raw.ExecContext(context.Background(), statement, args...); err != nil {
			e.t.Fatalf("种子数据写入失败: %v", err)
		}
	}
	insertUser := func(id, username, status string, isRoot int) {
		exec(`INSERT INTO users(id,username,username_normalized,nickname,status,is_root,created_at_ms,updated_at_ms)
VALUES(?,?,?,'',?,?,?,?)`, id, username, username, status, isRoot, now, now)
	}
	insertUser(testAdmin, "admin", "active", 0)
	insertUser(testMember, "member", "active", 0)
	insertUser(testOther, "other", "active", 0)
	insertUser(testDormant, "dormant", "active", 0)
	insertUser(testDisabledUser, "disabled", "disabled", 0)
	insertUser(testRoot, "rootuser", "active", 1)

	insertApp := func(id, name, status string) {
		exec(`INSERT INTO applications(id,name,status,client_type,created_at_ms,updated_at_ms)
VALUES(?,?,?,'confidential',?,?)`, id, name, status, now, now)
		exec(`INSERT INTO scopes(id,kind,app_id) VALUES(?,'application',?)`, id, id)
	}
	insertApp(testAppOne, "应用一", "active")
	insertApp(testAppTwo, "应用二", "active")
	insertApp(testAppDisabled, "停用应用", "disabled")

	insertMembership := func(appID, userID, status string) {
		// profile_json 必须符合步骤 21 的版本化白名单结构，否则成员读取 fail-closed。
		exec(`INSERT INTO app_memberships(app_id,user_id,status,profile_json,created_at_ms,updated_at_ms)
VALUES(?,?,?,'{"v":1}',?,?)`, appID, userID, status, now, now)
	}
	insertMembership(testAppOne, testAdmin, "active")
	insertMembership(testAppOne, testMember, "active")
	insertMembership(testAppOne, testOther, "active")

	insertPermission := func(id, scopeID, key string, enabled, rootOnly int) {
		exec(`INSERT INTO permissions(id,scope_id,permission_key,name,description,limits_text,enabled,root_only,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?,?,?,?,?)`, id, scopeID, key, key, "说明", "限制", enabled, rootOnly, now, now)
	}
	insertPermission(testPermOne, testAppOne, "invoices.read", 1, 0)
	insertPermission(testPermTwo, testAppOne, "invoices.approve", 1, 0)
	insertPermission(testPermDisabled, testAppOne, "invoices.disabled", 0, 0)
	insertPermission(testPermRootOnly, "system", "system.admin.root", 1, 1)
	insertPermission(testPermFour, testAppOne, "users.read", 1, 0)

	insertRole := func(id, scopeID, key string) {
		exec(`INSERT INTO roles(id,scope_id,role_key,name,description,limits_text,enabled,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?,1,?,?)`, id, scopeID, key, key, "说明", "限制", now, now)
	}
	insertRole(testRoleOne, testAppOne, "invoices-reader")
	insertRole(testRoleTwo, testAppOne, "invoices-approver")
	exec(`INSERT INTO role_permissions(role_id,permission_id,scope_id) VALUES(?,?,?)`,
		testRoleOne, testPermOne, testAppOne)
	exec(`INSERT INTO role_permissions(role_id,permission_id,scope_id) VALUES(?,?,?)`,
		testRoleTwo, testPermTwo, testAppOne)
	// 管理员通过两个直接角色分别持有 permOne 与 permTwo（可使用权限）。
	exec(`INSERT INTO user_roles(user_id,role_id,scope_id,data_scope_json,assigned_by,created_at_ms)
VALUES(?,?,?,'{}','operator-1',?)`, testAdmin, testRoleOne, testAppOne, now)
	exec(`INSERT INTO user_roles(user_id,role_id,scope_id,data_scope_json,assigned_by,created_at_ms)
VALUES(?,?,?,'{}','operator-1',?)`, testAdmin, testRoleTwo, testAppOne, now)

	insertGroup := func(id, scopeID, key string) {
		exec(`INSERT INTO user_groups(id,scope_id,group_key,name,description,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?,?)`, id, scopeID, key, key, "说明", now, now)
	}
	insertGroup(testGroupOne, testAppOne, "group-one")
	insertGroup(testGroupTwo, testAppOne, "group-two")
	exec(`INSERT INTO group_members(group_id,user_id,created_at_ms) VALUES(?,?,?)`, testGroupOne, testAdmin, now)
}

// withTx 在真实 SQLite 事务中执行检查回调（模拟服务写入事务边界）。
func (e *testEnv) withTx(fn func(ctx context.Context, tx audit.Tx) error) error {
	e.t.Helper()
	return e.raw.Transaction(context.Background(), func(ctx context.Context, tx *sql.Tx) error {
		return fn(ctx, testAuditTx{tx: tx})
	})
}

// testAuditTx 是只读检查用的事务适配器；Guard 不写审计。
type testAuditTx struct {
	tx *sql.Tx
}

func (t testAuditTx) AppendEvent(context.Context, audit.Event) error { return nil }

func (t testAuditTx) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return t.tx.ExecContext(ctx, query, args...)
}

func (t testAuditTx) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return t.tx.QueryContext(ctx, query, args...)
}

// checkAccess 在事务内执行 CheckPermissionAccess（无受影响目标）。
func (e *testEnv) checkAccess(caller delegation.Caller, scopeID string, refs ...delegation.PermissionRef) error {
	e.t.Helper()
	return e.checkAccessTargets(caller, scopeID, nil, refs...)
}

// checkAccessTargets 在事务内执行带受影响目标集合的 CheckPermissionAccess。
func (e *testEnv) checkAccessTargets(caller delegation.Caller, scopeID string, targets []delegation.Target, refs ...delegation.PermissionRef) error {
	e.t.Helper()
	var result error
	if err := e.withTx(func(ctx context.Context, tx audit.Tx) error {
		result = e.service.CheckPermissionAccess(ctx, tx, callerActor(e.t, caller), scopeID, refs, targets)
		return nil
	}); err != nil {
		e.t.Fatalf("执行转授检查失败: %v", err)
	}
	return result
}

// checkAssignment 在事务内执行 CheckAssignment。
func (e *testEnv) checkAssignment(caller delegation.Caller, scopeID string, target delegation.Target, refs ...delegation.PermissionRef) error {
	e.t.Helper()
	var result error
	if err := e.withTx(func(ctx context.Context, tx audit.Tx) error {
		result = e.service.CheckAssignment(ctx, tx, callerActor(e.t, caller), scopeID, refs, target)
		return nil
	}); err != nil {
		e.t.Fatalf("执行目标转授检查失败: %v", err)
	}
	return result
}

// checkActivation 在事务内执行 CheckPermissionActivation（无受影响目标）。
func (e *testEnv) checkActivation(caller delegation.Caller, scopeID string, refs ...delegation.PermissionRef) error {
	e.t.Helper()
	return e.checkActivationTargets(caller, scopeID, nil, refs...)
}

// checkActivationTargets 在事务内执行带受影响目标的启用检查。
func (e *testEnv) checkActivationTargets(caller delegation.Caller, scopeID string, targets []delegation.Target, refs ...delegation.PermissionRef) error {
	e.t.Helper()
	var result error
	if err := e.withTx(func(ctx context.Context, tx audit.Tx) error {
		result = e.service.CheckPermissionActivation(ctx, tx, callerActor(e.t, caller), scopeID, refs, targets)
		return nil
	}); err != nil {
		e.t.Fatalf("执行启用检查失败: %v", err)
	}
	return result
}

// checkRestoration 在事务内执行 CheckScopeRestoration（应用启用检查）。
func (e *testEnv) checkRestoration(caller delegation.Caller, scopeID string) error {
	e.t.Helper()
	var result error
	if err := e.withTx(func(ctx context.Context, tx audit.Tx) error {
		result = e.service.CheckScopeRestoration(ctx, tx, callerActor(e.t, caller), scopeID)
		return nil
	}); err != nil {
		e.t.Fatalf("执行应用启用检查失败: %v", err)
	}
	return result
}

// callerActor 返回调用者的只读审计身份；Guard 只依据 actor 类型与 ID 判断。
func callerActor(t *testing.T, caller delegation.Caller) audit.Actor {
	t.Helper()
	return caller.Actor()
}

// grant 由受信操作者签发委派资格。
func (e *testEnv) grant(request delegation.GrantRequest) delegation.Grant {
	e.t.Helper()
	grant, err := e.service.Grant(context.Background(), e.local, request)
	if err != nil {
		e.t.Fatalf("签发委派资格失败: %v", err)
	}
	return grant
}

// grantPerm 是常用签发：应用一范围、指定权限机器标识。
func (e *testEnv) grantPerm(key string, mutators ...func(*delegation.GrantRequest)) delegation.Grant {
	e.t.Helper()
	request := delegation.GrantRequest{
		DelegatorUserID: testAdmin, ScopeID: testAppOne, PermissionKey: key,
	}
	for _, mutate := range mutators {
		mutate(&request)
	}
	return e.grant(request)
}

// rowCount 执行单值计数查询。
func (e *testEnv) rowCount(query string, args ...any) int {
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
		e.t.Fatalf("读取计数失败: %v", err)
	}
	return value
}

// TestNewValidation 验证缺少存储/审计时不可构造。
func TestNewValidation(t *testing.T) {
	if _, err := delegation.New(delegation.Options{}); !errors.Is(err, delegation.ErrOptionsInvalid) {
		t.Fatalf("缺少依赖构造错误 = %v", err)
	}
	env := prepareEnv(t)
	if _, err := delegation.New(delegation.Options{Store: env.store}); !errors.Is(err, delegation.ErrOptionsInvalid) {
		t.Fatalf("缺少审计构造错误 = %v", err)
	}
	if _, err := delegation.New(delegation.Options{Audit: env.recorder}); !errors.Is(err, delegation.ErrOptionsInvalid) {
		t.Fatalf("缺少存储构造错误 = %v", err)
	}
}

// TestGrantIssuanceAndValidation 验证只有受信操作者能签发，且签发前校验账户、
// 范围、权限、数据范围上限、有效期与目标白名单。
func TestGrantIssuanceAndValidation(t *testing.T) {
	env := prepareEnv(t)
	ctx := context.Background()
	valid := delegation.GrantRequest{DelegatorUserID: testAdmin, ScopeID: testAppOne, PermissionKey: "invoices.read"}

	// 普通用户不能自行签发委派资格（受信通道之外一律拒绝）。
	if _, err := env.service.Grant(ctx, env.adminUser, valid); !errors.Is(err, delegation.ErrAccessDenied) {
		t.Fatalf("普通用户签发错误 = %v，期望 ACCESS_DENIED", err)
	}
	if delegation.CodeOf(delegation.ErrAccessDenied) != delegation.CodeAccessDenied {
		t.Fatal("ACCESS_DENIED 映射错误")
	}

	// 非法委派对象：root 账户不能被授予委派资格。
	rootRequest := valid
	rootRequest.DelegatorUserID = testRoot
	if _, err := env.service.Grant(ctx, env.local, rootRequest); !errors.Is(err, delegation.ErrDelegatorInvalid) {
		t.Fatalf("root 委派对象错误 = %v", err)
	}
	disabledUserRequest := valid
	disabledUserRequest.DelegatorUserID = testDisabledUser
	if _, err := env.service.Grant(ctx, env.local, disabledUserRequest); !errors.Is(err, delegation.ErrDelegatorInvalid) {
		t.Fatalf("停用账户委派错误 = %v", err)
	}

	// 权限不存在、停用或 root_only 都不能签发委派资格。
	unknown := valid
	unknown.PermissionKey = "invoices.unknown"
	if _, err := env.service.Grant(ctx, env.local, unknown); !errors.Is(err, delegation.ErrPermissionNotFound) {
		t.Fatalf("未知权限委派错误 = %v", err)
	}
	disabled := valid
	disabled.PermissionKey = "invoices.disabled"
	if _, err := env.service.Grant(ctx, env.local, disabled); !errors.Is(err, delegation.ErrPermissionUnavailable) {
		t.Fatalf("停用权限委派错误 = %v", err)
	}
	rootOnly := delegation.GrantRequest{DelegatorUserID: testAdmin, ScopeID: "system", PermissionKey: "system.admin.root"}
	if _, err := env.service.Grant(ctx, env.local, rootOnly); !errors.Is(err, delegation.ErrPermissionUnavailable) {
		t.Fatalf("root_only 权限委派错误 = %v", err)
	}

	// 应用停用时不能签发该应用范围的委派资格。
	disabledApp := valid
	disabledApp.ScopeID = testAppDisabled
	if _, err := env.service.Grant(ctx, env.local, disabledApp); !errors.Is(err, delegation.ErrApplicationInactive) {
		t.Fatalf("停用应用委派错误 = %v", err)
	}

	// 数据范围上限必须是显式 all/none/resources，不接受未声明。
	badScope := valid
	badScope.MaxDataScope = "{}"
	if _, err := env.service.Grant(ctx, env.local, badScope); !errors.Is(err, delegation.ErrInvalidRequest) {
		t.Fatalf("未声明数据范围上限错误 = %v", err)
	}
	badTargets := valid
	badTargets.AllowedTargets = delegation.AllowedTargets{Users: []string{"not-a-user-id"}}
	if _, err := env.service.Grant(ctx, env.local, badTargets); !errors.Is(err, delegation.ErrInvalidRequest) {
		t.Fatalf("非法目标白名单错误 = %v", err)
	}
	past := env.clock.Now().Add(-time.Minute)
	pastExpiry := valid
	pastExpiry.ExpiresAt = &past
	if _, err := env.service.Grant(ctx, env.local, pastExpiry); !errors.Is(err, delegation.ErrInvalidRequest) {
		t.Fatalf("过去有效期错误 = %v", err)
	}

	// 正常签发：写入一行，并记录签发审计。
	grant := env.grant(valid)
	if env.rowCount(`SELECT COUNT(*) FROM permission_delegations WHERE id=?`, grant.ID) != 1 {
		t.Fatal("委派资格未落库")
	}
	if env.rowCount(`SELECT COUNT(*) FROM audit_events WHERE action='delegation.grant' AND target_id=?`, grant.ID) != 1 {
		t.Fatal("缺少签发审计事件")
	}

	// 重复签发同 (委派对象,范围,权限) 覆盖原记录：仍只有一行，并记录被替换事件。
	replaced := env.grant(valid)
	if env.rowCount(`SELECT COUNT(*) FROM permission_delegations WHERE delegator_user_id=? AND scope_id=? AND permission_id=?`,
		testAdmin, testAppOne, testPermOne) != 1 {
		t.Fatal("重复签发产生多行")
	}
	if env.rowCount(`SELECT COUNT(*) FROM audit_events WHERE action='delegation.grant.replaced' AND target_id=?`, grant.ID) != 1 {
		t.Fatal("缺少替换审计事件")
	}
	// 覆盖后原 ID 不再有效，新 ID 可读取。
	if _, err := env.service.Get(ctx, env.local, grant.ID); !errors.Is(err, delegation.ErrGrantNotFound) {
		t.Fatalf("被覆盖资格仍可读取错误 = %v", err)
	}
	if _, err := env.service.Get(ctx, env.local, replaced.ID); err != nil {
		t.Fatalf("新资格读取失败: %v", err)
	}
}

// TestGuardHeldButNotDelegatable 验证“持有但不可转授”：仅有可使用权限没有委派
// 资格时拒绝；受信操作者直接放行。
func TestGuardHeldButNotDelegatable(t *testing.T) {
	env := prepareEnv(t)
	refOne := delegation.PermissionRef{PermissionID: testPermOne}
	refTwo := delegation.PermissionRef{PermissionID: testPermTwo}

	// 管理员持有 permOne/permTwo，但没有委派资格：可使用但不可转授。
	if err := env.checkAccess(env.adminUser, testAppOne, refOne); !errors.Is(err, delegation.ErrTransferNotGranted) {
		t.Fatalf("无资格组合权限错误 = %v", err)
	}
	if delegation.CodeOf(delegation.ErrTransferNotGranted) != delegation.CodePermissionRequired {
		t.Fatal("缺少转授资格映射应为 PERMISSION_REQUIRED")
	}
	if err := env.checkAssignment(env.adminUser, testAppOne, delegation.Target{Kind: delegation.TargetUser, ID: testMember}, refTwo); !errors.Is(err, delegation.ErrTransferNotGranted) {
		t.Fatalf("无资格转授权限错误 = %v", err)
	}

	// 只签发 permOne 的委派资格：permOne 可转授，permTwo 仍不可。
	env.grantPerm("invoices.read")
	if err := env.checkAccess(env.adminUser, testAppOne, refOne); err != nil {
		t.Fatalf("已获资格组合权限失败: %v", err)
	}
	if err := env.checkAssignment(env.adminUser, testAppOne, delegation.Target{Kind: delegation.TargetUser, ID: testMember}, refOne); err != nil {
		t.Fatalf("已获资格转授失败: %v", err)
	}
	if err := env.checkAccess(env.adminUser, testAppOne, refTwo); !errors.Is(err, delegation.ErrTransferNotGranted) {
		t.Fatalf("未获资格权限错误 = %v", err)
	}
	if err := env.checkAccess(env.adminUser, testAppOne, refOne, refTwo); !errors.Is(err, delegation.ErrTransferNotGranted) {
		t.Fatalf("混合权限检查错误 = %v", err)
	}

	// 受信通道（本地初始化/系统组件）不受委派资格限制。
	if err := env.checkAccess(env.local, testAppOne, refTwo); err != nil {
		t.Fatalf("本地管理员受信检查失败: %v", err)
	}
	if err := env.checkAccess(env.system, testAppOne, refTwo); err != nil {
		t.Fatalf("系统操作者受信检查失败: %v", err)
	}
}

// TestGuardDataScopeShrinkAndExpiryRevoke 验证数据范围收缩、过期与撤回委派。
func TestGuardDataScopeShrinkAndExpiryRevoke(t *testing.T) {
	env := prepareEnv(t)
	memberTarget := delegation.Target{Kind: delegation.TargetUser, ID: testMember}
	expiry := env.clock.Now().Add(time.Minute)
	env.grantPerm("invoices.read", func(request *delegation.GrantRequest) { request.ExpiresAt = &expiry })
	ref := delegation.PermissionRef{PermissionID: testPermOne}
	if err := env.checkAssignment(env.adminUser, testAppOne, memberTarget, ref); err != nil {
		t.Fatalf("有效期内转授失败: %v", err)
	}
	env.clock.Advance(2 * time.Minute)
	if err := env.checkAssignment(env.adminUser, testAppOne, memberTarget, ref); !errors.Is(err, delegation.ErrTransferExpired) {
		t.Fatalf("过期委派错误 = %v", err)
	}
	if delegation.CodeOf(delegation.ErrTransferExpired) != delegation.CodePermissionRequired {
		t.Fatal("过期委派映射应为 PERMISSION_REQUIRED")
	}

	// 撤回后立即失效；重新签发恢复并清除撤回状态。
	fresh := env.grantPerm("invoices.read")
	changed, err := env.service.Revoke(context.Background(), env.local, fresh.ID)
	if err != nil || !changed {
		t.Fatalf("撤回委派失败: changed=%v err=%v", changed, err)
	}
	if err := env.checkAssignment(env.adminUser, testAppOne, memberTarget, ref); !errors.Is(err, delegation.ErrTransferRevoked) {
		t.Fatalf("已撤回委派错误 = %v", err)
	}
	// 重复撤回幂等。
	if changed, err := env.service.Revoke(context.Background(), env.local, fresh.ID); err != nil || changed {
		t.Fatalf("重复撤回应幂等: changed=%v err=%v", changed, err)
	}
	// 没有委派资格的用户不能撤回。
	if _, err := env.service.Revoke(context.Background(), env.adminUser, fresh.ID); !errors.Is(err, delegation.ErrAccessDenied) {
		t.Fatalf("用户撤回错误 = %v", err)
	}
	env.grantPerm("invoices.read")
	if err := env.checkAssignment(env.adminUser, testAppOne, memberTarget, ref); err != nil {
		t.Fatalf("重新签发后转授失败: %v", err)
	}

	// 数据范围收缩：资源级上限只能转授其子集，不能转授未声明范围。
	env.grantPerm("invoices.read", func(request *delegation.GrantRequest) {
		request.MaxDataScope = `{"v":1,"mode":"resources","resources":["r2","r1"]}`
	})
	allowed := delegation.PermissionRef{PermissionID: testPermOne, DataScopeJSON: `{"v":1,"mode":"resources","resources":["r1"]}`}
	if err := env.checkAssignment(env.adminUser, testAppOne, memberTarget, allowed); err != nil {
		t.Fatalf("资源子集转授失败: %v", err)
	}
	broad := delegation.PermissionRef{PermissionID: testPermOne, DataScopeJSON: `{"v":1,"mode":"resources","resources":["r1","r3"]}`}
	if err := env.checkAssignment(env.adminUser, testAppOne, memberTarget, broad); !errors.Is(err, delegation.ErrDataScopeTooBroad) {
		t.Fatalf("超范围转授错误 = %v", err)
	}
	undefined := delegation.PermissionRef{PermissionID: testPermOne}
	if err := env.checkAssignment(env.adminUser, testAppOne, memberTarget, undefined); !errors.Is(err, delegation.ErrDataScopeTooBroad) {
		t.Fatalf("未声明范围转授错误 = %v", err)
	}
	none := delegation.PermissionRef{PermissionID: testPermOne, DataScopeJSON: `{"v":1,"mode":"none"}`}
	if err := env.checkAssignment(env.adminUser, testAppOne, memberTarget, none); err != nil {
		t.Fatalf("none 数据范围转授失败: %v", err)
	}
	// 上限为 all 时允许未声明范围（当前角色分配全部是未声明）。
	env.grantPerm("invoices.read")
	if err := env.checkAssignment(env.adminUser, testAppOne, memberTarget, undefined); err != nil {
		t.Fatalf("all 上限下未声明范围转授失败: %v", err)
	}
}

// TestGuardSelfAndTargetRestrictions 验证默认禁止自我提权与目标白名单限制。
func TestGuardSelfAndTargetRestrictions(t *testing.T) {
	env := prepareEnv(t)
	ref := delegation.PermissionRef{PermissionID: testPermOne}
	env.grantPerm("invoices.read")
	selfTarget := delegation.Target{Kind: delegation.TargetUser, ID: testAdmin}
	memberTarget := delegation.Target{Kind: delegation.TargetUser, ID: testMember}
	otherTarget := delegation.Target{Kind: delegation.TargetUser, ID: testOther}
	groupOneTarget := delegation.Target{Kind: delegation.TargetGroup, ID: testGroupOne}
	groupTwoTarget := delegation.Target{Kind: delegation.TargetGroup, ID: testGroupTwo}

	if err := env.checkAssignment(env.adminUser, testAppOne, selfTarget, ref); !errors.Is(err, delegation.ErrSelfTransferDenied) {
		t.Fatalf("自我转授错误 = %v", err)
	}
	if delegation.CodeOf(delegation.ErrSelfTransferDenied) != delegation.CodeAccessDenied {
		t.Fatal("自我转授权映射应为 ACCESS_DENIED")
	}
	if err := env.checkAssignment(env.adminUser, testAppOne, memberTarget, ref); err != nil {
		t.Fatalf("向成员转授失败: %v", err)
	}
	// 管理员是 groupOne 成员：默认不允许通过用户组间接给自己赋权。
	if err := env.checkAssignment(env.adminUser, testAppOne, groupOneTarget, ref); !errors.Is(err, delegation.ErrSelfTransferDenied) {
		t.Fatalf("向自身所在组转授错误 = %v", err)
	}
	if err := env.checkAssignment(env.adminUser, testAppOne, groupTwoTarget, ref); err != nil {
		t.Fatalf("向非自身所在组转授失败: %v", err)
	}

	// 显式 allow_self 后才允许转授给自己或自身所在用户组。
	env.grantPerm("invoices.read", func(request *delegation.GrantRequest) { request.AllowSelf = true })
	if err := env.checkAssignment(env.adminUser, testAppOne, selfTarget, ref); err != nil {
		t.Fatalf("allow_self 自我转授失败: %v", err)
	}
	if err := env.checkAssignment(env.adminUser, testAppOne, groupOneTarget, ref); err != nil {
		t.Fatalf("allow_self 组转授失败: %v", err)
	}

	// 用户白名单：只能转授给列出的用户。
	env.grantPerm("invoices.read", func(request *delegation.GrantRequest) {
		request.AllowedTargets = delegation.AllowedTargets{Users: []string{testMember}}
	})
	if err := env.checkAssignment(env.adminUser, testAppOne, memberTarget, ref); err != nil {
		t.Fatalf("白名单内用户转授失败: %v", err)
	}
	if err := env.checkAssignment(env.adminUser, testAppOne, otherTarget, ref); !errors.Is(err, delegation.ErrTargetNotAllowed) {
		t.Fatalf("白名单外用户转授错误 = %v", err)
	}
	// 白名单不影响自我提权禁令。
	env.grantPerm("invoices.read", func(request *delegation.GrantRequest) {
		request.AllowedTargets = delegation.AllowedTargets{Users: []string{testAdmin}}
	})
	if err := env.checkAssignment(env.adminUser, testAppOne, selfTarget, ref); !errors.Is(err, delegation.ErrSelfTransferDenied) {
		t.Fatalf("白名单内自我转授错误 = %v", err)
	}

	// 用户组白名单：先把管理员移出 groupOne，避免同时触发自我提权禁令。
	if _, err := env.raw.ExecContext(context.Background(),
		`DELETE FROM group_members WHERE group_id=? AND user_id=?`, testGroupOne, testAdmin); err != nil {
		t.Fatalf("移除组成员失败: %v", err)
	}
	env.grantPerm("invoices.read", func(request *delegation.GrantRequest) {
		request.AllowedTargets = delegation.AllowedTargets{Groups: []string{testGroupTwo}}
	})
	if err := env.checkAssignment(env.adminUser, testAppOne, groupTwoTarget, ref); err != nil {
		t.Fatalf("白名单内用户组转授失败: %v", err)
	}
	if err := env.checkAssignment(env.adminUser, testAppOne, groupOneTarget, ref); !errors.Is(err, delegation.ErrTargetNotAllowed) {
		t.Fatalf("白名单外用户组转授错误 = %v", err)
	}
}

// TestGuardAccountAppMembershipAndLostPermission 验证自身权限变化与范围状态变化
// 会立即影响可转授判断（无陈旧缓存）。
func TestGuardAccountAppMembershipAndLostPermission(t *testing.T) {
	env := prepareEnv(t)
	ctx := context.Background()
	env.grantPerm("invoices.read")
	ref := delegation.PermissionRef{PermissionID: testPermOne}
	update := func(statement string, args ...any) {
		t.Helper()
		if _, err := env.raw.ExecContext(ctx, statement, args...); err != nil {
			t.Fatalf("更新状态失败: %v", err)
		}
	}
	// 应用停用。
	update(`UPDATE applications SET status='disabled' WHERE id=?`, testAppOne)
	if err := env.checkAccess(env.adminUser, testAppOne, ref); !errors.Is(err, delegation.ErrApplicationInactive) {
		t.Fatalf("停用应用检查错误 = %v", err)
	}
	update(`UPDATE applications SET status='active' WHERE id=?`, testAppOne)

	// 应用成员停用。
	update(`UPDATE app_memberships SET status='disabled' WHERE app_id=? AND user_id=?`, testAppOne, testAdmin)
	if err := env.checkAccess(env.adminUser, testAppOne, ref); !errors.Is(err, delegation.ErrTransferNotGranted) {
		t.Fatalf("停用成员检查错误 = %v", err)
	}
	update(`UPDATE app_memberships SET status='active' WHERE app_id=? AND user_id=?`, testAppOne, testAdmin)

	// 账户停用。
	update(`UPDATE users SET status='disabled' WHERE id=?`, testAdmin)
	if err := env.checkAccess(env.adminUser, testAppOne, ref); !errors.Is(err, delegation.ErrDelegatorInvalid) {
		t.Fatalf("停用账户检查错误 = %v", err)
	}
	if delegation.CodeOf(delegation.ErrDelegatorInvalid) != delegation.CodeUserDisabled {
		t.Fatal("停用账户映射应为 USER_DISABLED")
	}
	update(`UPDATE users SET status='active' WHERE id=?`, testAdmin)

	// 权限停用：普通组合/转授拒绝；启用类检查只要求委派资格仍有效。
	update(`UPDATE permissions SET enabled=0 WHERE id=?`, testPermOne)
	if err := env.checkAccess(env.adminUser, testAppOne, ref); !errors.Is(err, delegation.ErrPermissionUnavailable) {
		t.Fatalf("停用权限检查错误 = %v", err)
	}
	if err := env.checkActivation(env.adminUser, testAppOne, ref); err != nil {
		t.Fatalf("停用权限的启用检查失败: %v", err)
	}
	update(`UPDATE permissions SET enabled=1 WHERE id=?`, testPermOne)

	// 角色停用导致管理员不再实际持有该权限：随即失去转授资格（实时读取）。
	update(`UPDATE roles SET enabled=0 WHERE id=?`, testRoleOne)
	if err := env.checkAccess(env.adminUser, testAppOne, ref); !errors.Is(err, delegation.ErrPermissionNotHeld) {
		t.Fatalf("自身权限被收回后检查错误 = %v", err)
	}
	if delegation.CodeOf(delegation.ErrPermissionNotHeld) != delegation.CodePermissionRequired {
		t.Fatal("不持有权限映射应为 PERMISSION_REQUIRED")
	}
	if err := env.checkActivation(env.adminUser, testAppOne, ref); err != nil {
		t.Fatalf("角色停用时的启用检查失败: %v", err)
	}
	update(`UPDATE roles SET enabled=1 WHERE id=?`, testRoleOne)
	if err := env.checkAccess(env.adminUser, testAppOne, ref); err != nil {
		t.Fatalf("权限恢复后检查失败: %v", err)
	}
}

// TestDelegatablePermissionsAndListing 验证“可使用权限”与“可转授权限”分开查询，
// 以及委派列表的可见范围与分页校验。
func TestDelegatablePermissionsAndListing(t *testing.T) {
	env := prepareEnv(t)
	ctx := context.Background()
	// 管理员实际持有 permOne/permTwo，但只有 permOne 的委派资格。
	env.grantPerm("invoices.read")
	permissions, err := env.service.DelegatablePermissions(ctx, env.adminUser, testAppOne)
	if err != nil {
		t.Fatalf("查询可转授权限失败: %v", err)
	}
	if len(permissions) != 1 || permissions[0].Key != "invoices.read" {
		t.Fatalf("可转授权限 = %+v，期望只有 invoices.read", permissions)
	}
	// 受信操作者不使用该自我查询入口；只有普通用户查询自己的可转授权限。
	if _, err := env.service.DelegatablePermissions(ctx, env.local, testAppOne); !errors.Is(err, delegation.ErrAccessDenied) {
		t.Fatalf("受信操作者自我查询错误 = %v", err)
	}
	// 权限停用后不再计入可转授（即使资格还在）。
	if _, err := env.raw.ExecContext(ctx, `UPDATE permissions SET enabled=0 WHERE id=?`, testPermOne); err != nil {
		t.Fatalf("停用权限失败: %v", err)
	}
	permissions, err = env.service.DelegatablePermissions(ctx, env.adminUser, testAppOne)
	if err != nil || len(permissions) != 0 {
		t.Fatalf("停用权限后的可转授权限 = %+v, err=%v", permissions, err)
	}
	if _, err := env.raw.ExecContext(ctx, `UPDATE permissions SET enabled=1 WHERE id=?`, testPermOne); err != nil {
		t.Fatalf("恢复权限失败: %v", err)
	}

	// 列表：普通用户只能读自己的资格。
	grants, err := env.service.List(ctx, env.adminUser, delegation.ListRequest{})
	if err != nil || len(grants) != 1 {
		t.Fatalf("普通用户列表 = %d, err=%v", len(grants), err)
	}
	if _, err := env.service.List(ctx, env.adminUser, delegation.ListRequest{DelegatorUserID: testMember}); !errors.Is(err, delegation.ErrAccessDenied) {
		t.Fatalf("普通用户读取他人资格错误 = %v", err)
	}
	if _, err := env.service.List(ctx, env.local, delegation.ListRequest{}); err != nil {
		t.Fatalf("受信操作者列表失败: %v", err)
	}
	if _, err := env.service.List(ctx, env.local, delegation.ListRequest{Limit: 999}); !errors.Is(err, delegation.ErrInvalidRequest) {
		t.Fatalf("非法分页错误 = %v", err)
	}
	// 非法 ID 与不存在资格。
	if _, err := env.service.Get(ctx, env.local, "dlg_bad"); !errors.Is(err, delegation.ErrInvalidRequest) {
		t.Fatalf("非法资格 ID 错误 = %v", err)
	}
	if _, err := env.service.Get(ctx, env.local, "dlg_00000000000000000000000000000000"); !errors.Is(err, delegation.ErrGrantNotFound) {
		t.Fatalf("不存在资格错误 = %v", err)
	}
}

// TestGuardInputValidation 验证作用范围、权限 ID、目标与数量上限的输入边界。
func TestGuardInputValidation(t *testing.T) {
	env := prepareEnv(t)
	ctx := context.Background()
	actor := env.adminUser.Actor()
	if err := env.service.CheckAssignment(ctx, nil, actor, testAppOne, nil, delegation.Target{Kind: delegation.TargetUser, ID: testMember}); !errors.Is(err, delegation.ErrOptionsInvalid) {
		t.Fatalf("缺少事务视图错误 = %v", err)
	}
	ref := delegation.PermissionRef{PermissionID: testPermOne}
	if err := env.withTx(func(ctx context.Context, tx audit.Tx) error {
		if err := env.service.CheckPermissionAccess(ctx, tx, actor, "bad-scope", []delegation.PermissionRef{ref}, nil); !errors.Is(err, delegation.ErrInvalidRequest) {
			return err
		}
		badPermission := []delegation.PermissionRef{{PermissionID: "perm_bad"}}
		if err := env.service.CheckPermissionAccess(ctx, tx, actor, testAppOne, badPermission, nil); !errors.Is(err, delegation.ErrInvalidRequest) {
			return err
		}
		many := make([]delegation.PermissionRef, delegation.MaxPermissionRefs+1)
		for index := range many {
			many[index] = ref
		}
		if err := env.service.CheckPermissionAccess(ctx, tx, actor, testAppOne, many, nil); !errors.Is(err, delegation.ErrInvalidRequest) {
			return err
		}
		badTarget := delegation.Target{Kind: "tenant", ID: testMember}
		if err := env.service.CheckAssignment(ctx, tx, actor, testAppOne, []delegation.PermissionRef{ref}, badTarget); !errors.Is(err, delegation.ErrInvalidRequest) {
			return err
		}
		// 受损或超限的受影响目标集合不得静默缩小校验范围。
		badTargets := []delegation.Target{{Kind: "tenant", ID: testMember}}
		if err := env.service.CheckPermissionActivation(ctx, tx, actor, testAppOne, []delegation.PermissionRef{ref}, badTargets); !errors.Is(err, delegation.ErrInvalidRequest) {
			return err
		}
		tooManyTargets := make([]delegation.Target, delegation.MaxAffectedTargets+1)
		for index := range tooManyTargets {
			tooManyTargets[index] = delegation.Target{Kind: delegation.TargetUser, ID: testMember}
		}
		if err := env.service.CheckPermissionActivation(ctx, tx, actor, testAppOne, []delegation.PermissionRef{ref}, tooManyTargets); !errors.Is(err, delegation.ErrInvalidRequest) {
			return err
		}
		return nil
	}); err != nil {
		t.Fatalf("边界校验失败: %v", err)
	}
}

// TestConcurrentTransferAndRevoke 验证并发转授检查与撤回不会出现半更新或放行：
// 每次检查要么在撤回前明确允许，要么在撤回后明确拒绝。
func TestConcurrentTransferAndRevoke(t *testing.T) {
	env := prepareEnv(t)
	grant := env.grantPerm("invoices.read")
	ctx := context.Background()
	const workers = 4
	const attempts = 5
	errs := make(chan error, workers*attempts)
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for attempt := 0; attempt < attempts; attempt++ {
				txErr := env.raw.Transaction(ctx, func(txCtx context.Context, tx *sql.Tx) error {
					return env.service.CheckAssignment(txCtx, testAuditTx{tx: tx}, env.adminUser.Actor(), testAppOne,
						[]delegation.PermissionRef{{PermissionID: testPermOne}},
						delegation.Target{Kind: delegation.TargetUser, ID: testMember})
				})
				errs <- txErr
			}
		}()
	}
	// 与并发检查同时撤回委派资格。
	time.Sleep(5 * time.Millisecond)
	if changed, err := env.service.Revoke(ctx, env.local, grant.ID); err != nil || !changed {
		t.Fatalf("并发撤回失败: changed=%v err=%v", changed, err)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err == nil {
			continue
		}
		if errors.Is(err, delegation.ErrTransferRevoked) || errors.Is(err, delegation.ErrTransferNotGranted) || errors.Is(err, delegation.ErrTransferExpired) {
			continue
		}
		t.Fatalf("并发检查出现非预期错误: %v", err)
	}
	// 撤回完成后一律拒绝，不存在半更新放行。
	if err := env.checkAssignment(env.adminUser, testAppOne, delegation.Target{Kind: delegation.TargetUser, ID: testMember},
		delegation.PermissionRef{PermissionID: testPermOne}); !errors.Is(err, delegation.ErrTransferRevoked) {
		t.Fatalf("撤回后转授错误 = %v", err)
	}
	if env.rowCount(`SELECT COUNT(*) FROM permission_delegations WHERE id=? AND revoked_at_ms IS NOT NULL`, grant.ID) != 1 {
		t.Fatal("撤回状态未持久化")
	}
}
