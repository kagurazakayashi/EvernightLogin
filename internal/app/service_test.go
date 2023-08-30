package app_test

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

	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	appsqlite "github.com/kagurazakayashi/EvernightLogin/internal/app/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const (
	testOwnerOne = "usr_00000000000000000000000000000001"
	testOwnerTwo = "usr_00000000000000000000000000000002"
	testAppAdmin = "usr_00000000000000000000000000000003"
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
	store      *appsqlite.Store
	auditStore *auditsqlite.Store
	recorder   *audit.Recorder
	service    *app.Service
	authorizer *app.StaticAuthorizer
	clock      *fakeClock
	system     app.Caller
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
	return prepareEnvWithRetention(t, 0)
}

// prepareEnvWithRetention 允许测试指定物理清理保留期（0 使用默认 30 天）。
func prepareEnvWithRetention(t *testing.T, purgeRetention time.Duration) *testEnv {
	t.Helper()
	ctx := context.Background()
	// 用 internal/testutil.TempDir（带重试清理）替代 t.TempDir：Windows 上目录删除可能被安全
	// 软件/文件过滤驱动瞬时延迟，标准库清理不重试 ERROR_DIR_NOT_EMPTY。
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(filepath.Join(testutil.TempDir(t), "app.sqlite")))
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
	store, err := appsqlite.New(raw)
	if err != nil {
		t.Fatalf("构造应用仓储失败: %v", err)
	}
	auditStore, err := auditsqlite.New(raw)
	if err != nil {
		t.Fatalf("构造审计仓储失败: %v", err)
	}
	clock := &fakeClock{now: time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)}
	recorder, err := audit.New(auditStore, audit.Options{Now: clock.Now})
	if err != nil {
		t.Fatalf("构造审计写入器失败: %v", err)
	}
	authorizer, err := app.NewStaticAuthorizer(app.AuthorizerOptions{
		LocalAdminIDs: []string{"operator-1"},
		SystemIDs:     []string{"system-1"},
	})
	if err != nil {
		t.Fatalf("构造授权器失败: %v", err)
	}
	service, err := app.New(app.Options{
		Store: store, Audit: recorder, Authorizer: authorizer,
		Transfers: allowAllTransfers(), Now: clock.Now,
		PurgeRetention: purgeRetention,
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("构造应用服务失败: %v", err)
	}
	system, err := app.SystemCaller("system-1")
	if err != nil {
		t.Fatalf("构造系统调用者失败: %v", err)
	}
	env := &testEnv{t: t, raw: raw, store: store, auditStore: auditStore,
		recorder: recorder, service: service, authorizer: authorizer, clock: clock, system: system}
	env.insertActiveUser(testOwnerOne, "ownerone")
	env.insertActiveUser(testOwnerTwo, "ownertwo")
	env.insertActiveUser(testAppAdmin, "appadmin")
	return env
}

// insertActiveUser 直接插入注册用途外的可用账户，供负责人/应用管理员引用。
func (e *testEnv) insertActiveUser(userID, username string) {
	e.t.Helper()
	now := e.clock.Now().UnixMilli()
	if _, err := e.raw.ExecContext(context.Background(),
		`INSERT INTO users(id,username,username_normalized,nickname,biography,language,timezone,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'','','zh-CN','Asia/Shanghai','active',0,1,1,?,?)`,
		userID, username, username, now, now); err != nil {
		e.t.Fatalf("插入测试用户失败: %v", err)
	}
}

func (e *testEnv) userCaller(userID string) app.Caller {
	e.t.Helper()
	caller, err := app.UserCaller(userID)
	if err != nil {
		e.t.Fatalf("构造用户调用者失败: %v", err)
	}
	return caller
}

func (e *testEnv) createApp(request app.CreateRequest) app.Application {
	e.t.Helper()
	application, err := e.service.CreateApplication(context.Background(), e.system, request)
	if err != nil {
		e.t.Fatalf("创建应用失败: %v", err)
	}
	return application
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

func (e *testEnv) queryString(query string, args ...any) string {
	e.t.Helper()
	rows, err := e.raw.QueryContext(context.Background(), query, args...)
	if err != nil {
		e.t.Fatalf("查询失败: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		e.t.Fatalf("查询没有结果: %s", query)
	}
	var value string
	if err := rows.Scan(&value); err != nil {
		e.t.Fatalf("读取查询结果失败: %v", err)
	}
	return value
}

func validCreateRequest(clientType app.ClientType) app.CreateRequest {
	return app.CreateRequest{
		Name:        "示例应用",
		Description: "用于测试的应用",
		IconRef:     "icons/example.png",
		Homepage:    "https://example.com/app",
		ContactInfo: "admin@example.com",
		ClientType:  clientType,
	}
}

func TestCreateApplicationAndScopeConsistency(t *testing.T) {
	env := prepareEnv(t)
	request := validCreateRequest(app.ClientTypeConfidential)
	request.OwnerUserID = testOwnerOne
	application, err := env.service.CreateApplication(context.Background(), env.system, request)
	if err != nil {
		t.Fatalf("创建应用失败: %v", err)
	}
	if !app.ValidApplicationID(application.ID) {
		t.Fatalf("应用 ID 格式无效: %q", application.ID)
	}
	if application.Status != app.StatusDisabled || application.RowVersion != 1 {
		t.Errorf("创建默认状态/版本 = %q/%d", application.Status, application.RowVersion)
	}
	if application.ScopeID != app.ScopeID(application.ID) {
		t.Errorf("scope ID = %q，期望与应用 ID 一致", application.ScopeID)
	}
	if application.ClientType != app.ClientTypeConfidential {
		t.Errorf("客户端类型 = %q", application.ClientType)
	}
	if value := env.queryInt(`SELECT COUNT(*) FROM applications WHERE id=?`, application.ID); value != 1 {
		t.Fatal("应用行未写入")
	}
	if value := env.queryString(`SELECT kind FROM scopes WHERE id=? AND app_id=?`, application.ScopeID, application.ID); value != "application" {
		t.Fatalf("应用 scope = %q", value)
	}
	if value := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action='application.create' AND outcome='success' AND target_id=?`, application.ID); value != 1 {
		t.Errorf("创建审计数量 = %d", value)
	}
	if value := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE detail_json LIKE '%scope_id%' AND target_id=?`, application.ID); value != 1 {
		t.Errorf("创建审计未记录 scope_id")
	}

	// scope 写入失败时应用行必须一起回滚。
	before := env.queryInt(`SELECT COUNT(*) FROM applications`)
	if _, err := env.raw.ExecContext(context.Background(),
		`CREATE TRIGGER fail_app_scope BEFORE INSERT ON scopes BEGIN SELECT RAISE(ABORT,'scope blocked'); END;`); err != nil {
		t.Fatalf("创建 scope 故障触发器失败: %v", err)
	}
	if _, err := env.service.CreateApplication(context.Background(), env.system, validCreateRequest(app.ClientTypePublic)); !errors.Is(err, app.ErrStoreUnavailable) {
		t.Fatalf("scope 故障创建错误 = %v，期望 ErrStoreUnavailable", err)
	}
	if value := env.queryInt(`SELECT COUNT(*) FROM applications`); value != before {
		t.Errorf("scope 故障后应用行数 = %d，期望 %d（应整体回滚）", value, before)
	}
	if value := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action='application.create' AND outcome='failure'`); value != 1 {
		t.Errorf("scope 故障失败审计数量 = %d", value)
	}
}

func TestCreateApplicationValidation(t *testing.T) {
	env := prepareEnv(t)
	cases := []struct {
		name    string
		mutate  func(*app.CreateRequest)
		wantErr error
	}{
		{name: "空名称", mutate: func(r *app.CreateRequest) { r.Name = "  " }, wantErr: app.ErrInvalidRequest},
		{name: "名称过长", mutate: func(r *app.CreateRequest) { r.Name = strings.Repeat("名", app.MaxNameRunes+1) }, wantErr: app.ErrInvalidRequest},
		{name: "描述含控制字符", mutate: func(r *app.CreateRequest) { r.Description = "bad\x00" }, wantErr: app.ErrInvalidRequest},
		{name: "图标绝对路径", mutate: func(r *app.CreateRequest) { r.IconRef = "/etc/passwd" }, wantErr: app.ErrInvalidRequest},
		{name: "图标路径穿越", mutate: func(r *app.CreateRequest) { r.IconRef = "icons/../secret" }, wantErr: app.ErrInvalidRequest},
		{name: "主页协议非法", mutate: func(r *app.CreateRequest) { r.Homepage = "javascript:alert(1)" }, wantErr: app.ErrInvalidRequest},
		{name: "主页含用户信息", mutate: func(r *app.CreateRequest) { r.Homepage = "https://user:pass@example.com" }, wantErr: app.ErrInvalidRequest},
		{name: "联系方式含换行", mutate: func(r *app.CreateRequest) { r.ContactInfo = "line1\nline2" }, wantErr: app.ErrInvalidRequest},
		{name: "客户端类型非法", mutate: func(r *app.CreateRequest) { r.ClientType = "desktop" }, wantErr: app.ErrInvalidRequest},
		{name: "负责人 ID 非法", mutate: func(r *app.CreateRequest) { r.OwnerUserID = "not-a-user" }, wantErr: app.ErrInvalidRequest},
		{name: "负责人不存在", mutate: func(r *app.CreateRequest) { r.OwnerUserID = "usr_ffffffffffffffffffffffffffffffff" }, wantErr: app.ErrInvalidRequest},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			request := validCreateRequest(app.ClientTypePublic)
			test.mutate(&request)
			if _, err := env.service.CreateApplication(context.Background(), env.system, request); !errors.Is(err, test.wantErr) {
				t.Fatalf("错误 = %v，期望 %v", err, test.wantErr)
			}
			if code := app.CodeOf(test.wantErr); code != app.CodeReqInvalid {
				t.Errorf("错误码 = %q", code)
			}
		})
	}
}

func TestUpdateApplicationWhitelistAndOwnerPolicy(t *testing.T) {
	env := prepareEnv(t)
	request := validCreateRequest(app.ClientTypeConfidential)
	request.OwnerUserID = testOwnerOne
	application := env.createApp(request)

	// 应用管理员可以改普通资料，但不能改负责人。
	if err := env.authorizer.AssignApplicationAdmin(application.ID, testAppAdmin); err != nil {
		t.Fatalf("分配应用管理员失败: %v", err)
	}
	admin := env.userCaller(testAppAdmin)
	update := app.UpdateRequest{
		Name:               "新名称",
		Description:        "新描述",
		IconRef:            "icons/new.png",
		Homepage:           "https://example.com/new",
		OwnerUserID:        testOwnerOne,
		ContactInfo:        "new-contact@example.com",
		ExpectedRowVersion: 1,
	}
	updated, err := env.service.UpdateApplication(context.Background(), admin, application.ID, update)
	if err != nil {
		t.Fatalf("应用管理员更新普通资料失败: %v", err)
	}
	if updated.ID != application.ID || updated.ScopeID != application.ScopeID ||
		updated.ClientType != application.ClientType || updated.Status != application.Status {
		t.Errorf("更新不应改变 ID/scope/client_type/status: %+v", updated)
	}
	if updated.RowVersion != 2 || updated.Name != "新名称" {
		t.Errorf("更新结果 = %+v", updated)
	}
	// 联系方式不得以明文写入审计明细。
	if value := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action='application.update' AND detail_json LIKE '%new-contact@example.com%'`); value != 0 {
		t.Error("审计明细泄露了联系方式")
	}
	if value := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action='application.update' AND detail_json LIKE '%[REDACTED]%'`); value != 1 {
		t.Errorf("联系方式变更未以 REDACTED 记录")
	}

	// 应用管理员改负责人被拒绝。
	ownerChange := update
	ownerChange.OwnerUserID = testOwnerTwo
	ownerChange.ExpectedRowVersion = updated.RowVersion
	if _, err := env.service.UpdateApplication(context.Background(), admin, application.ID, ownerChange); !errors.Is(err, app.ErrAccessDenied) {
		t.Fatalf("应用管理员改负责人错误 = %v，期望 ErrAccessDenied", err)
	}
	// 系统调用者可以改负责人；负责人变化不自动转移管理权限。
	ownerChange.Name = updated.Name
	ownerChange.Description = updated.Description
	ownerChange.IconRef = updated.IconRef
	ownerChange.Homepage = updated.Homepage
	ownerChange.ContactInfo = updated.ContactInfo
	afterOwner, err := env.service.UpdateApplication(context.Background(), env.system, application.ID, ownerChange)
	if err != nil {
		t.Fatalf("系统更新负责人失败: %v", err)
	}
	if afterOwner.OwnerUserID != testOwnerTwo {
		t.Errorf("负责人 = %q", afterOwner.OwnerUserID)
	}
	// 新负责人没有自动获得管理员资格。
	newOwner := env.userCaller(testOwnerTwo)
	noop := app.UpdateRequest{
		Name: afterOwner.Name, Description: afterOwner.Description, IconRef: afterOwner.IconRef,
		Homepage: afterOwner.Homepage, ContactInfo: afterOwner.ContactInfo, OwnerUserID: testOwnerTwo,
		ExpectedRowVersion: afterOwner.RowVersion,
	}
	if _, err := env.service.UpdateApplication(context.Background(), newOwner, application.ID, noop); !errors.Is(err, app.ErrAccessDenied) {
		t.Fatalf("新负责人不应自动获得管理权限: %v", err)
	}
	// 原应用管理员仍被显式分配，可以继续更新。
	noop.ExpectedRowVersion = afterOwner.RowVersion
	if _, err := env.service.UpdateApplication(context.Background(), admin, application.ID, noop); err != nil {
		t.Fatalf("原应用管理员应可继续更新: %v", err)
	}

	// 旧行版本更新冲突。
	stale := noop
	stale.ExpectedRowVersion = 1
	if _, err := env.service.UpdateApplication(context.Background(), env.system, application.ID, stale); !errors.Is(err, app.ErrStateConflict) {
		t.Fatalf("旧版本更新错误 = %v，期望 ErrStateConflict", err)
	}
}

func TestApplicationStatusLifecycle(t *testing.T) {
	env := prepareEnv(t)
	application := env.createApp(validCreateRequest(app.ClientTypePublic))
	if err := env.authorizer.AssignApplicationAdmin(application.ID, testAppAdmin); err != nil {
		t.Fatal(err)
	}
	admin := env.userCaller(testAppAdmin)
	enabled, err := env.service.EnableApplication(context.Background(), admin, app.StatusRequest{ApplicationID: application.ID, ExpectedRowVersion: 1})
	if err != nil {
		t.Fatalf("启用应用失败: %v", err)
	}
	if !enabled.Changed || enabled.Application.Status != app.StatusActive || enabled.Application.RowVersion != 2 {
		t.Fatalf("启用结果 = %+v", enabled)
	}
	// 状态对读取可见。
	got, err := env.service.GetApplication(context.Background(), env.system, application.ID)
	if err != nil || got.Status != app.StatusActive {
		t.Fatalf("启用后读取 = %+v, %v", got, err)
	}
	// 重复启用幂等。
	repeated, err := env.service.EnableApplication(context.Background(), admin, app.StatusRequest{ApplicationID: application.ID, ExpectedRowVersion: 2})
	if err != nil || repeated.Changed {
		t.Fatalf("重复启用应幂等: %+v, %v", repeated, err)
	}
	disabled, err := env.service.DisableApplication(context.Background(), admin, app.StatusRequest{ApplicationID: application.ID, ExpectedRowVersion: 2})
	if err != nil || !disabled.Changed || disabled.Application.Status != app.StatusDisabled {
		t.Fatalf("停用结果 = %+v, %v", disabled, err)
	}
	if value := env.queryString(`SELECT status FROM applications WHERE id=?`, application.ID); value != "disabled" {
		t.Errorf("数据库状态 = %q", value)
	}
	if value := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE target_id=? AND action IN ('application.enable','application.disable') AND outcome='success'`, application.ID); value < 3 {
		t.Errorf("启停审计数量 = %d", value)
	}
	// 旧版本启用冲突（当前为 disabled，启用会改变状态但版本不匹配）。
	if _, err := env.service.EnableApplication(context.Background(), admin, app.StatusRequest{ApplicationID: application.ID, ExpectedRowVersion: 1}); !errors.Is(err, app.ErrStateConflict) {
		t.Fatalf("旧版本启用错误 = %v", err)
	}
	// 未知应用/非法参数。
	if _, err := env.service.EnableApplication(context.Background(), env.system, app.StatusRequest{ApplicationID: "app_ffffffffffffffffffffffffffffffff", ExpectedRowVersion: 1}); !errors.Is(err, app.ErrApplicationNotFound) {
		t.Fatalf("未知应用错误 = %v", err)
	}
	if _, err := env.service.EnableApplication(context.Background(), env.system, app.StatusRequest{ApplicationID: application.ID, ExpectedRowVersion: 0}); !errors.Is(err, app.ErrInvalidRequest) {
		t.Fatalf("零版本错误 = %v", err)
	}
}

func TestConcurrentStatusChange(t *testing.T) {
	env := prepareEnv(t)
	application := env.createApp(validCreateRequest(app.ClientTypePublic))
	const workers = 4
	var waitGroup sync.WaitGroup
	results := make([]error, workers)
	changed := make([]bool, workers)
	for index := 0; index < workers; index++ {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			result, err := env.service.EnableApplication(context.Background(), env.system, app.StatusRequest{ApplicationID: application.ID, ExpectedRowVersion: 1})
			results[index] = err
			changed[index] = result.Changed
		}(index)
	}
	waitGroup.Wait()
	successChanged := 0
	for index, err := range results {
		switch {
		case err == nil && changed[index]:
			successChanged++
		case err == nil:
		case errors.Is(err, app.ErrStateConflict):
		default:
			t.Errorf("并发启停错误 = %v", err)
		}
	}
	if successChanged != 1 {
		t.Fatalf("并发启停成功数 = %d，期望 1", successChanged)
	}
	if value := env.queryString(`SELECT status FROM applications WHERE id=?`, application.ID); value != "active" {
		t.Errorf("最终状态 = %q", value)
	}
	if value := env.queryInt(`SELECT row_version FROM applications WHERE id=?`, application.ID); value != 2 {
		t.Errorf("row_version = %d，期望 2", value)
	}
}

func TestListApplicationsRespectsApplicationAdminScope(t *testing.T) {
	env := prepareEnv(t)
	first := env.createApp(validCreateRequest(app.ClientTypePublic))
	env.clock.Advance(time.Minute)
	second := env.createApp(validCreateRequest(app.ClientTypeConfidential))
	env.clock.Advance(time.Minute)
	third := env.createApp(validCreateRequest(app.ClientTypePublic))
	for _, id := range []string{first.ID, third.ID} {
		if err := env.authorizer.AssignApplicationAdmin(id, testAppAdmin); err != nil {
			t.Fatal(err)
		}
	}
	all, err := env.service.ListApplications(context.Background(), env.system, app.ListRequest{Limit: 2})
	if err != nil {
		t.Fatalf("系统列表失败: %v", err)
	}
	if len(all.Applications) != 2 || !all.HasMore {
		t.Fatalf("系统列表 = %d, hasMore=%v", len(all.Applications), all.HasMore)
	}
	if all.Applications[0].ID != first.ID || all.Applications[1].ID != second.ID {
		t.Errorf("默认创建时间排序不符: %+v", all.Applications)
	}
	admin := env.userCaller(testAppAdmin)
	scoped, err := env.service.ListApplications(context.Background(), admin, app.ListRequest{})
	if err != nil {
		t.Fatalf("应用管理员列表失败: %v", err)
	}
	if len(scoped.Applications) != 2 || scoped.Applications[0].ID != first.ID || scoped.Applications[1].ID != third.ID {
		t.Fatalf("应用管理员列表 = %+v", scoped.Applications)
	}
	// 未分配应用读取被拒绝。
	if _, err := env.service.GetApplication(context.Background(), admin, second.ID); !errors.Is(err, app.ErrAccessDenied) {
		t.Fatalf("未分配应用读取错误 = %v", err)
	}
	// 无分配用户列表为空且不泄露其他应用存在性。
	noAdmin := env.userCaller(testOwnerOne)
	empty, err := env.service.ListApplications(context.Background(), noAdmin, app.ListRequest{})
	if err != nil || len(empty.Applications) != 0 {
		t.Fatalf("无分配用户列表 = %+v, %v", empty, err)
	}
	// 应用管理员不能创建应用。
	if _, err := env.service.CreateApplication(context.Background(), admin, validCreateRequest(app.ClientTypePublic)); !errors.Is(err, app.ErrAccessDenied) {
		t.Fatalf("应用管理员创建应用错误 = %v", err)
	}
	// 分页/排序边界。
	for _, request := range []app.ListRequest{
		{Limit: -1}, {Limit: app.MaxListLimit + 1}, {Offset: -1},
		{Offset: app.MaxListOffset + 1}, {Sort: "client_type"}, {Status: "deleted"},
	} {
		if _, err := env.service.ListApplications(context.Background(), env.system, request); !errors.Is(err, app.ErrInvalidRequest) {
			t.Errorf("非法列表请求 %+v 错误 = %v", request, err)
		}
	}
}

func TestAuditFailureFailClosed(t *testing.T) {
	env := prepareEnv(t)
	application := env.createApp(validCreateRequest(app.ClientTypePublic))
	if _, err := env.raw.ExecContext(context.Background(),
		`CREATE TRIGGER fail_audit_events BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'audit unavailable'); END;`); err != nil {
		t.Fatalf("创建审计故障触发器失败: %v", err)
	}
	if _, err := env.service.CreateApplication(context.Background(), env.system, validCreateRequest(app.ClientTypePublic)); !errors.Is(err, app.ErrAuditUnavailable) {
		t.Fatalf("审计故障创建错误 = %v", err)
	}
	if _, err := env.service.GetApplication(context.Background(), env.system, application.ID); !errors.Is(err, app.ErrAuditUnavailable) {
		t.Fatalf("审计故障读取错误 = %v", err)
	}
	if _, err := env.service.ListApplications(context.Background(), env.system, app.ListRequest{}); !errors.Is(err, app.ErrAuditUnavailable) {
		t.Fatalf("审计故障列表错误 = %v", err)
	}
	if err := env.authorizer.AssignApplicationAdmin(application.ID, testAppAdmin); err != nil {
		t.Fatal(err)
	}
	admin := env.userCaller(testAppAdmin)
	update := app.UpdateRequest{Name: "名称", ExpectedRowVersion: 1}
	if _, err := env.service.UpdateApplication(context.Background(), admin, application.ID, update); !errors.Is(err, app.ErrAuditUnavailable) {
		t.Fatalf("审计故障更新错误 = %v", err)
	}
	if _, err := env.raw.ExecContext(context.Background(), `DROP TRIGGER fail_audit_events`); err != nil {
		t.Fatalf("删除触发器失败: %v", err)
	}
	if _, err := env.service.EnableApplication(context.Background(), admin, app.StatusRequest{ApplicationID: application.ID, ExpectedRowVersion: 1}); err != nil {
		t.Fatalf("恢复后启用失败: %v", err)
	}
}

func TestOptionsAndUnauthorizedCaller(t *testing.T) {
	if _, err := app.New(app.Options{}); !errors.Is(err, app.ErrOptionsInvalid) {
		t.Fatalf("空依赖构造错误 = %v", err)
	}
	env := prepareEnv(t)
	if _, err := env.service.CreateApplication(context.Background(), app.Caller{}, validCreateRequest(app.ClientTypePublic)); !errors.Is(err, app.ErrAccessDenied) {
		t.Fatalf("零值调用者错误 = %v", err)
	}
	if _, err := app.NewStaticAuthorizer(app.AuthorizerOptions{}); !errors.Is(err, app.ErrOptionsInvalid) {
		t.Fatalf("空授权器配置错误 = %v", err)
	}
	if _, err := app.LocalBootstrapCaller(""); !errors.Is(err, app.ErrInvalidRequest) {
		t.Fatalf("空本地操作者错误 = %v", err)
	}
	if _, err := env.service.GetApplication(context.Background(), env.system, "not-an-app-id"); !errors.Is(err, app.ErrInvalidRequest) {
		t.Fatalf("非法应用 ID 错误 = %v", err)
	}
	if _, err := env.service.UpdateApplication(context.Background(), env.system, "app_ffffffffffffffffffffffffffffffff", app.UpdateRequest{Name: "x", ExpectedRowVersion: 1}); !errors.Is(err, app.ErrApplicationNotFound) {
		t.Fatalf("未知应用更新错误 = %v", err)
	}
}
