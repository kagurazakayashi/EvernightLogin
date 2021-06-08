package group_test

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
	"github.com/kagurazakayashi/EvernightLogin/internal/group"
	groupsqlite "github.com/kagurazakayashi/EvernightLogin/internal/group/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const (
	appOne = "app_00000000000000000000000000000001"
	appTwo = "app_00000000000000000000000000000002"

	userOne   = "usr_00000000000000000000000000000001"
	userTwo   = "usr_00000000000000000000000000000002"
	userThree = "usr_00000000000000000000000000000003"
	userFour  = "usr_00000000000000000000000000000004"
	adminOne  = "usr_00000000000000000000000000000010"
	adminTwo  = "usr_00000000000000000000000000000011"
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
	t          *testing.T
	raw        *storagesqlite.Store
	store      *groupsqlite.Store
	auditStore *auditsqlite.Store
	recorder   *audit.Recorder
	service    *group.Service
	authorizer *group.StaticAuthorizer
	clock      *fakeClock
	system     group.Caller
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

func prepareEnv(t *testing.T, mutations ...func(*group.Options)) *testEnv {
	t.Helper()
	ctx := context.Background()
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(filepath.Join(t.TempDir(), "group.sqlite")))
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
	store, err := groupsqlite.New(raw)
	if err != nil {
		t.Fatalf("构造用户组仓储失败: %v", err)
	}
	auditStore, err := auditsqlite.New(raw)
	if err != nil {
		t.Fatalf("构造审计仓储失败: %v", err)
	}
	clock := &fakeClock{now: time.Date(2026, 11, 15, 14, 0, 0, 0, time.UTC)}
	recorder, err := audit.New(auditStore, audit.Options{Now: clock.Now})
	if err != nil {
		t.Fatalf("构造审计写入器失败: %v", err)
	}
	authorizer, err := group.NewStaticAuthorizer(group.AuthorizerOptions{
		LocalAdminIDs: []string{"operator-1"},
		SystemIDs:     []string{"system-1"},
	})
	if err != nil {
		t.Fatalf("构造授权器失败: %v", err)
	}
	options := group.Options{AllowLegacyWithoutSensitive: true, Store: store, Audit: recorder, Authorizer: authorizer,
		Transfers: allowAllTransfers(), Now: clock.Now,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	for _, mutation := range mutations {
		mutation(&options)
	}
	service, err := group.New(options)

	if err != nil {
		t.Fatalf("构造用户组服务失败: %v", err)
	}
	system, err := group.SystemCaller("system-1")
	if err != nil {
		t.Fatalf("构造系统调用者失败: %v", err)
	}
	env := &testEnv{t: t, raw: raw, store: store, auditStore: auditStore, recorder: recorder,
		service: service, authorizer: authorizer, clock: clock, system: system}
	env.seedUser(userOne, "userone", "active")
	env.seedUser(userTwo, "usertwo", "active")
	env.seedUser(userThree, "userthree", "active")
	env.seedUser(userFour, "userfour", "disabled")
	env.seedUser(adminOne, "adminone", "active")
	env.seedApplication(appOne, "active")
	env.seedApplication(appTwo, "active")
	env.seedAppMembership(appOne, userOne, "active")
	env.seedAppMembership(appTwo, userTwo, "active")
	env.seedAppMembership(appOne, userThree, "disabled")
	env.seedAppMembership(appOne, userFour, "active")
	return env
}

func (e *testEnv) seedUser(userID, username, status string) {
	e.t.Helper()
	now := e.clock.Now().UnixMilli()
	if _, err := e.raw.ExecContext(context.Background(),
		`INSERT INTO users(id,username,username_normalized,nickname,biography,language,timezone,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'','','zh-CN','Asia/Shanghai',?,0,1,1,?,?)`, userID, username, username, status, now, now); err != nil {
		e.t.Fatalf("插入测试用户失败: %v", err)
	}
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

func (e *testEnv) seedAppMembership(appID, userID, status string) {
	e.t.Helper()
	now := e.clock.Now().UnixMilli()
	if _, err := e.raw.ExecContext(context.Background(),
		`INSERT INTO app_memberships(app_id,user_id,status,profile_json,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'{}',1,?,?)`, appID, userID, status, now, now); err != nil {
		e.t.Fatalf("插入测试应用成员失败: %v", err)
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

func (e *testEnv) createGroup(scopeID, key string) group.Group {
	e.t.Helper()
	record, err := e.service.CreateGroup(context.Background(), e.system, group.CreateRequest{
		ScopeID: scopeID, GroupKey: key, Name: "测试组", Description: "说明",
	})
	if err != nil {
		e.t.Fatalf("创建用户组失败: %v", err)
	}
	return record
}

func TestGroupCRUDAndScopeUniqueness(t *testing.T) {
	env := prepareEnv(t)
	record := env.createGroup(group.ScopeSystem, "system-ops")
	if !group.ValidGroupID(record.ID) || record.ScopeKind != group.ScopeKindSystem || record.ApplicationID != "" {
		t.Fatalf("系统组 = %+v", record)
	}
	// 同 scope 相同 group_key 冲突；不同 scope 可同 key/同名。
	if _, err := env.service.CreateGroup(context.Background(), env.system, group.CreateRequest{
		ScopeID: group.ScopeSystem, GroupKey: "system-ops", Name: "另一名称",
	}); !errors.Is(err, group.ErrGroupKeyTaken) {
		t.Fatalf("重复 group_key 错误 = %v", err)
	}
	appGroup := env.createGroup(appOne, "system-ops")
	if appGroup.ScopeKind != group.ScopeKindApplication || appGroup.ApplicationID != appOne ||
		appGroup.ScopeID != appOne {
		t.Fatalf("应用组 = %+v", appGroup)
	}
	got, err := env.service.GetGroup(context.Background(), env.system, record.ID)
	if err != nil || got.GroupKey != "system-ops" {
		t.Fatalf("读取系统组 = %+v, %v", got, err)
	}
	updated, err := env.service.UpdateGroup(context.Background(), env.system, record.ID,
		group.UpdateRequest{Name: "新名称", Description: "新说明"})
	if err != nil {
		t.Fatalf("更新用户组失败: %v", err)
	}
	if updated.Name != "新名称" || updated.ScopeID != record.ScopeID || updated.GroupKey != record.GroupKey {
		t.Errorf("更新不应改变 scope/key: %+v", updated)
	}
	if value := env.queryInt(`SELECT COUNT(*) FROM user_groups WHERE id=? AND scope_id=? AND group_key=?`,
		record.ID, record.ScopeID, record.GroupKey); value != 1 {
		t.Error("更新后 scope/group_key 被改变")
	}
	// 系统组不允许应用管理员管理。
	env.authorizer.AssignApplicationAdmin(appOne, adminOne)
	appAdmin, err := group.UserCaller(adminOne)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.service.CreateGroup(context.Background(), appAdmin, group.CreateRequest{
		ScopeID: group.ScopeSystem, GroupKey: "app-admin-system",
	}); !errors.Is(err, group.ErrAccessDenied) {
		t.Fatalf("应用管理员创建系统组错误 = %v", err)
	}
	// 应用管理员不能管理其他应用组。
	if _, err := env.service.UpdateGroup(context.Background(), appAdmin, env.createGroup(appTwo, "other").ID,
		group.UpdateRequest{Name: "越权"}); !errors.Is(err, group.ErrAccessDenied) {
		t.Fatalf("跨应用更新错误 = %v", err)
	}
	if err := env.service.DeleteGroup(context.Background(), env.system, record.ID); err != nil {
		t.Fatalf("删除用户组失败: %v", err)
	}
	if _, err := env.service.GetGroup(context.Background(), env.system, record.ID); !errors.Is(err, group.ErrGroupNotFound) {
		t.Fatalf("删除后读取错误 = %v", err)
	}
	if value := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE target_id=? AND action IN ('group.create','group.update','group.delete')`, record.ID); value != 3 {
		t.Errorf("组 CRUD 审计数量 = %d", value)
	}
}

// TestListGroupsDefaultScopeAndPagination 验证空 ScopeID 默认列表、范围过滤、
// 分页/HasMore，以及跨范围过滤拒绝；覆盖系统、本地管理员、应用管理员与无分配用户。
func TestListGroupsDefaultScopeAndPagination(t *testing.T) {
	env := prepareEnv(t)
	systemOne := env.createGroup(group.ScopeSystem, "list-system-1")
	env.clock.mu.Lock()
	env.clock.now = env.clock.now.Add(time.Minute)
	env.clock.mu.Unlock()
	systemTwo := env.createGroup(group.ScopeSystem, "list-system-2")
	env.clock.mu.Lock()
	env.clock.now = env.clock.now.Add(time.Minute)
	env.clock.mu.Unlock()
	appOneGroup := env.createGroup(appOne, "list-app-one")
	appTwoGroup := env.createGroup(appTwo, "list-app-two")
	env.authorizer.AssignApplicationAdmin(appOne, adminOne)
	appAdmin, err := group.UserCaller(adminOne)
	if err != nil {
		t.Fatal(err)
	}

	// 系统操作者空 ScopeID：全部可管理组，分页与 HasMore。
	firstPage, err := env.service.ListGroups(context.Background(), env.system, group.ListRequest{Limit: 2})
	if err != nil {
		t.Fatalf("系统操作者默认列表失败: %v", err)
	}
	if len(firstPage.Groups) != 2 || !firstPage.HasMore {
		t.Fatalf("系统默认第一页 = %d, hasMore=%v", len(firstPage.Groups), firstPage.HasMore)
	}
	secondPage, err := env.service.ListGroups(context.Background(), env.system, group.ListRequest{Limit: 2, Offset: 2})
	if err != nil || len(secondPage.Groups) != 2 || secondPage.HasMore {
		t.Fatalf("系统默认第二页 = %d, hasMore=%v, err=%v", len(secondPage.Groups), secondPage.HasMore, err)
	}
	// 显式系统 scope 过滤只返回系统组。
	systemOnly, err := env.service.ListGroups(context.Background(), env.system, group.ListRequest{ScopeID: group.ScopeSystem, Limit: 10})
	if err != nil || len(systemOnly.Groups) != 2 || systemOnly.Groups[0].ID != systemOne.ID || systemOnly.Groups[1].ID != systemTwo.ID {
		t.Fatalf("系统 scope 过滤 = %+v, %v", systemOnly.Groups, err)
	}

	// 本地管理员空 ScopeID 默认用法必须可用（审计问题 1 回归）。
	localAdmin, err := group.LocalBootstrapCaller("operator-1")
	if err != nil {
		t.Fatal(err)
	}
	localPage, err := env.service.ListGroups(context.Background(), localAdmin, group.ListRequest{Limit: 1})
	if err != nil {
		t.Fatalf("本地管理员默认列表失败: %v", err)
	}
	if len(localPage.Groups) != 1 || !localPage.HasMore {
		t.Fatalf("本地管理员列表 = %d, hasMore=%v", len(localPage.Groups), localPage.HasMore)
	}

	// 应用管理员空 ScopeID 只返回分配应用组。
	appScoped, err := env.service.ListGroups(context.Background(), appAdmin, group.ListRequest{Limit: 10})
	if err != nil {
		t.Fatalf("应用管理员默认列表失败: %v", err)
	}
	if len(appScoped.Groups) != 1 || appScoped.Groups[0].ID != appOneGroup.ID {
		t.Fatalf("应用管理员默认列表 = %+v", appScoped.Groups)
	}
	// 应用管理员过滤本应用可用；过滤其他应用/系统范围拒绝。
	if result, err := env.service.ListGroups(context.Background(), appAdmin, group.ListRequest{ScopeID: appOne, Limit: 10}); err != nil || len(result.Groups) != 1 {
		t.Fatalf("应用管理员本应用过滤 = %+v, %v", result.Groups, err)
	}
	for _, scopeID := range []string{appTwo, group.ScopeSystem} {
		if _, err := env.service.ListGroups(context.Background(), appAdmin, group.ListRequest{ScopeID: scopeID}); !errors.Is(err, group.ErrAccessDenied) {
			t.Fatalf("应用管理员过滤 %s 错误 = %v", scopeID, err)
		}
	}

	// 无任何管理范围的用户：默认列表为空成功，读取任意既有组/不存在组均拒绝，
	// 不先读取完整记录。
	noScope, err := group.UserCaller(userOne)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := env.service.ListGroups(context.Background(), noScope, group.ListRequest{})
	if err != nil || len(empty.Groups) != 0 {
		t.Fatalf("无分配用户列表 = %+v, %v", empty, err)
	}
	if _, err := env.service.GetGroup(context.Background(), noScope, appTwoGroup.ID); !errors.Is(err, group.ErrAccessDenied) {
		t.Fatalf("无分配用户读取现有组错误 = %v", err)
	}
	// 应用管理员读取未分配应用的组：拒绝，而不是返回组数据。
	if _, err := env.service.GetGroup(context.Background(), appAdmin, appTwoGroup.ID); !errors.Is(err, group.ErrAccessDenied) {
		t.Fatalf("应用管理员读取未分配组错误 = %v", err)
	}
	_ = systemOne
}

func TestApplicationGroupEligibility(t *testing.T) {
	env := prepareEnv(t)
	env.authorizer.AssignApplicationAdmin(appOne, adminOne)
	appAdmin, _ := group.UserCaller(adminOne)
	record, err := env.service.CreateGroup(context.Background(), appAdmin, group.CreateRequest{
		ScopeID: appOne, GroupKey: "app-one-team", Name: "应用一组",
	})
	if err != nil {
		t.Fatalf("应用管理员创建应用组失败: %v", err)
	}
	// 合格：全局 active 且 appOne 成员 active。
	result, err := env.service.AddMembers(context.Background(), appAdmin, group.MemberBatchRequest{GroupID: record.ID, UserIDs: []string{userOne}})
	if err != nil || result.Added != 1 {
		t.Fatalf("加入合格成员 = %+v, %v", result, err)
	}
	// 跨应用成员（仅 appTwo）被拒。
	if _, err := env.service.AddMembers(context.Background(), appAdmin, group.MemberBatchRequest{GroupID: record.ID, UserIDs: []string{userTwo}}); !errors.Is(err, group.ErrMemberNotEligible) {
		t.Fatalf("跨应用成员错误 = %v", err)
	}
	// 应用成员 disabled 被拒。
	if _, err := env.service.AddMembers(context.Background(), appAdmin, group.MemberBatchRequest{GroupID: record.ID, UserIDs: []string{userThree}}); !errors.Is(err, group.ErrMemberNotEligible) {
		t.Fatalf("应用成员停用错误 = %v", err)
	}
	// 全局 disabled 被拒。
	if _, err := env.service.AddMembers(context.Background(), appAdmin, group.MemberBatchRequest{GroupID: record.ID, UserIDs: []string{userFour}}); !errors.Is(err, group.ErrMemberNotEligible) {
		t.Fatalf("全局停用成员错误 = %v", err)
	}
	// 系统组允许任意 active 用户（不代表获得权限，仅成员关系）。
	systemGroup := env.createGroup(group.ScopeSystem, "all-active")
	if result, err := env.service.AddMembers(context.Background(), env.system, group.MemberBatchRequest{GroupID: systemGroup.ID, UserIDs: []string{userTwo}}); err != nil || result.Added != 1 {
		t.Fatalf("系统组加入 active 用户 = %+v, %v", result, err)
	}
	if _, err := env.service.AddMembers(context.Background(), env.system, group.MemberBatchRequest{GroupID: systemGroup.ID, UserIDs: []string{userFour}}); !errors.Is(err, group.ErrMemberNotEligible) {
		t.Fatalf("系统组加入 disabled 用户错误 = %v", err)
	}
	// 停用应用后不能创建组或加入成员，但仍可移除成员。
	if _, err := env.raw.ExecContext(context.Background(), `UPDATE applications SET status='disabled' WHERE id=?`, appOne); err != nil {
		t.Fatalf("停用测试应用失败: %v", err)
	}
	if _, err := env.service.CreateGroup(context.Background(), appAdmin, group.CreateRequest{ScopeID: appOne, GroupKey: "after-disable"}); !errors.Is(err, group.ErrApplicationInactive) {
		t.Fatalf("停用后创建组错误 = %v", err)
	}
	if _, err := env.service.AddMembers(context.Background(), appAdmin, group.MemberBatchRequest{GroupID: record.ID, UserIDs: []string{userOne}}); !errors.Is(err, group.ErrApplicationInactive) {
		t.Fatalf("停用后加入成员错误 = %v", err)
	}
	if result, err := env.service.RemoveMembers(context.Background(), appAdmin, group.MemberBatchRequest{GroupID: record.ID, UserIDs: []string{userOne}}); err != nil || result.Removed != 1 {
		t.Fatalf("停用后移除成员 = %+v, %v", result, err)
	}
	// 跨应用组创建被拒绝。
	if _, err := env.service.CreateGroup(context.Background(), appAdmin, group.CreateRequest{ScopeID: appTwo, GroupKey: "cross-app"}); !errors.Is(err, group.ErrAccessDenied) {
		t.Fatalf("跨应用创建组错误 = %v", err)
	}
}

// TestAddMembersRejectsRoot 验证 root 账户不能加入任何用户组：否则“组已配置角色
// 后再加入 root”会给 root 间接分配普通角色，绕开角色分配时的 root 保护。
func TestAddMembersRejectsRoot(t *testing.T) {
	env := prepareEnv(t)
	rootID := "usr_11111111111111111111111111111111"
	now := env.clock.Now().UnixMilli()
	if _, err := env.raw.ExecContext(context.Background(),
		`INSERT INTO users(id,username,username_normalized,nickname,biography,language,timezone,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'','','zh-CN','Asia/Shanghai','active',1,1,1,?,?)`,
		rootID, "root", "root", now, now); err != nil {
		t.Fatalf("插入 root 测试用户失败: %v", err)
	}
	systemGroup := env.createGroup(group.ScopeSystem, "root-guard")
	if _, err := env.service.AddMembers(context.Background(), env.system,
		group.MemberBatchRequest{GroupID: systemGroup.ID, UserIDs: []string{rootID}}); !errors.Is(err, group.ErrMemberNotEligible) {
		t.Fatalf("向用户组加入 root 错误 = %v，期望 ErrMemberNotEligible", err)
	}
	if value := env.queryInt(`SELECT COUNT(*) FROM group_members WHERE user_id=?`, rootID); value != 0 {
		t.Errorf("root 组成员行数 = %d，期望 0", value)
	}
	// 拒绝必须留失败审计（普通管理员反复尝试把 root 拉进已配角色的组不能无痕），
	// 且错误码仍是既有 USER_DISABLED。
	if code := group.CodeOf(group.ErrMemberNotEligible); code != group.CodeUserDisabled {
		t.Errorf("成员资格错误码 = %q，期望 USER_DISABLED", code)
	}
	if value := env.queryInt(`SELECT COUNT(*) FROM audit_events
WHERE action=? AND outcome='failure' AND error_code='USER_DISABLED' AND reason_code='member_not_eligible' AND target_id=?`,
		string(group.ActionAddMembers), systemGroup.ID); value != 1 {
		t.Errorf("root 组成员拒绝失败审计数 = %d，期望 1", value)
	}
}

func TestBatchMemberLimitsAndAtomicity(t *testing.T) {
	env := prepareEnv(t)
	systemGroup := env.createGroup(group.ScopeSystem, "batch")
	if _, err := env.service.AddMembers(context.Background(), env.system, group.MemberBatchRequest{GroupID: systemGroup.ID}); !errors.Is(err, group.ErrInvalidRequest) {
		t.Fatalf("空成员列表错误 = %v", err)
	}
	tooMany := make([]string, group.MaxBatchMembers+1)
	for index := range tooMany {
		tooMany[index] = userOne
	}
	if _, err := env.service.AddMembers(context.Background(), env.system, group.MemberBatchRequest{GroupID: systemGroup.ID, UserIDs: tooMany}); !errors.Is(err, group.ErrInvalidRequest) {
		t.Fatalf("超批量上限错误 = %v", err)
	}
	// 重复 ID 去重后加入一次。
	result, err := env.service.AddMembers(context.Background(), env.system, group.MemberBatchRequest{
		GroupID: systemGroup.ID, UserIDs: []string{userOne, userOne, userTwo},
	})
	if err != nil || result.Added != 2 {
		t.Fatalf("去重批量加入 = %+v, %v", result, err)
	}
	// 原子性：合格与不合格混合时整批失败且不新增。
	before := env.queryInt(`SELECT COUNT(*) FROM group_members WHERE group_id=?`, systemGroup.ID)
	if _, err := env.service.AddMembers(context.Background(), env.system, group.MemberBatchRequest{
		GroupID: systemGroup.ID, UserIDs: []string{userThree, userFour},
	}); !errors.Is(err, group.ErrMemberNotEligible) {
		t.Fatalf("混合批量错误 = %v", err)
	}
	if value := env.queryInt(`SELECT COUNT(*) FROM group_members WHERE group_id=?`, systemGroup.ID); value != before {
		t.Errorf("失败批量不应新增成员: %d -> %d", before, value)
	}
	// 审计故障 fail-closed。
	if _, err := env.raw.ExecContext(context.Background(),
		`CREATE TRIGGER fail_audit_events BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'audit unavailable'); END;`); err != nil {
		t.Fatalf("创建审计故障触发器失败: %v", err)
	}
	if _, err := env.service.AddMembers(context.Background(), env.system, group.MemberBatchRequest{GroupID: systemGroup.ID, UserIDs: []string{userThree}}); !errors.Is(err, group.ErrAuditUnavailable) {
		t.Fatalf("审计故障加入错误 = %v", err)
	}
	if _, err := env.service.ListMembers(context.Background(), env.system, group.MemberListRequest{GroupID: systemGroup.ID}); !errors.Is(err, group.ErrAuditUnavailable) {
		t.Fatalf("审计故障成员列表错误 = %v", err)
	}
	if _, err := env.raw.ExecContext(context.Background(), `DROP TRIGGER fail_audit_events`); err != nil {
		t.Fatalf("删除触发器失败: %v", err)
	}
}

func TestMemberRemoveIdempotentAndPagination(t *testing.T) {
	env := prepareEnv(t)
	systemGroup := env.createGroup(group.ScopeSystem, "members")
	if _, err := env.service.AddMembers(context.Background(), env.system, group.MemberBatchRequest{
		GroupID: systemGroup.ID, UserIDs: []string{userOne, userTwo},
	}); err != nil {
		t.Fatalf("加入成员失败: %v", err)
	}
	firstPage, err := env.service.ListMembers(context.Background(), env.system, group.MemberListRequest{GroupID: systemGroup.ID, Limit: 1})
	if err != nil || len(firstPage.Members) != 1 || !firstPage.HasMore {
		t.Fatalf("第一页成员 = %+v, %v", firstPage, err)
	}
	secondPage, err := env.service.ListMembers(context.Background(), env.system, group.MemberListRequest{GroupID: systemGroup.ID, Limit: 1, Offset: 1})
	if err != nil || len(secondPage.Members) != 1 || secondPage.HasMore {
		t.Fatalf("第二页成员 = %+v, %v", secondPage, err)
	}
	result, err := env.service.RemoveMembers(context.Background(), env.system, group.MemberBatchRequest{GroupID: systemGroup.ID, UserIDs: []string{userOne, userThree}})
	if err != nil || result.Removed != 1 || result.Skipped != 1 {
		t.Fatalf("移除结果 = %+v, %v", result, err)
	}
	// 重复移除幂等：不存在成员 skipped。
	again, err := env.service.RemoveMembers(context.Background(), env.system, group.MemberBatchRequest{GroupID: systemGroup.ID, UserIDs: []string{userOne}})
	if err != nil || again.Removed != 0 || again.Skipped != 1 {
		t.Fatalf("重复移除 = %+v, %v", again, err)
	}
}

func TestConcurrentDuplicateMembers(t *testing.T) {
	env := prepareEnv(t)
	systemGroup := env.createGroup(group.ScopeSystem, "concurrent")
	const workers = 4
	var waitGroup sync.WaitGroup
	results := make([]group.MemberBatchResult, workers)
	errorsSeen := make([]error, workers)
	for index := 0; index < workers; index++ {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			result, err := env.service.AddMembers(context.Background(), env.system, group.MemberBatchRequest{
				GroupID: systemGroup.ID, UserIDs: []string{userOne},
			})
			errorsSeen[index] = err
			results[index] = result
		}(index)
	}
	waitGroup.Wait()
	added := 0
	for index, err := range errorsSeen {
		switch {
		case err == nil:
			if results[index].Added+results[index].Skipped != 1 {
				t.Errorf("并发结果计数异常")
			}
			added += results[index].Added
		case errors.Is(err, group.ErrStateConflict):
		default:
			t.Errorf("并发加入错误 = %v", err)
		}
	}
	if added != 1 {
		t.Fatalf("并发加入实际新增 = %d，期望 1", added)
	}
	if value := env.queryInt(`SELECT COUNT(*) FROM group_members WHERE group_id=? AND user_id=?`, systemGroup.ID, userOne); value != 1 {
		t.Errorf("并发后成员行数 = %d，期望 1", value)
	}
}

func TestDeleteGroupCascadesAssociationsNotUsers(t *testing.T) {
	env := prepareEnv(t)
	systemGroup := env.createGroup(group.ScopeSystem, "to-delete")
	if _, err := env.service.AddMembers(context.Background(), env.system, group.MemberBatchRequest{GroupID: systemGroup.ID, UserIDs: []string{userOne}}); err != nil {
		t.Fatalf("加入成员失败: %v", err)
	}
	// 预置角色与组角色关联，验证删除组级联删除关联但不删除用户。
	now := env.clock.Now().UnixMilli()
	if _, err := env.raw.ExecContext(context.Background(),
		`INSERT INTO roles(id,scope_id,role_key,name,description,limits_text,is_builtin,enabled,created_at_ms,updated_at_ms)
VALUES('role_group_test','system','role_group_test','测试角色','','',0,1,?,?)`, now, now); err != nil {
		t.Fatalf("插入测试角色失败: %v", err)
	}
	if _, err := env.raw.ExecContext(context.Background(),
		`INSERT INTO group_roles(group_id,role_id,scope_id,data_scope_json,created_at_ms) VALUES(?,?, 'system','{}',?)`,
		systemGroup.ID, "role_group_test", now); err != nil {
		t.Fatalf("插入组角色失败: %v", err)
	}
	if err := env.service.DeleteGroup(context.Background(), env.system, systemGroup.ID); err != nil {
		t.Fatalf("删除用户组失败: %v", err)
	}
	if value := env.queryInt(`SELECT COUNT(*) FROM group_members WHERE group_id=?`, systemGroup.ID); value != 0 {
		t.Error("组成员关系未级联删除")
	}
	if value := env.queryInt(`SELECT COUNT(*) FROM group_roles WHERE group_id=?`, systemGroup.ID); value != 0 {
		t.Error("组角色关联未级联删除")
	}
	if value := env.queryInt(`SELECT COUNT(*) FROM users WHERE id=?`, userOne); value != 1 {
		t.Error("删除组不应删除用户")
	}
	if value := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE target_id=?`, systemGroup.ID); value < 3 {
		t.Errorf("删除组后审计历史 = %d，应保留创建/加入/删除记录", value)
	}
}

func TestValidationAndAuthorization(t *testing.T) {
	if _, err := group.New(group.Options{AllowLegacyWithoutSensitive: true}); !errors.Is(err, group.ErrOptionsInvalid) {
		t.Fatalf("空依赖构造错误 = %v", err)
	}
	env := prepareEnv(t)
	if _, err := env.service.CreateGroup(context.Background(), group.Caller{}, group.CreateRequest{ScopeID: group.ScopeSystem, GroupKey: "x", Name: "x"}); !errors.Is(err, group.ErrAccessDenied) {
		t.Fatalf("零值调用者错误 = %v", err)
	}
	invalid := []group.CreateRequest{
		{ScopeID: "not-a-scope", GroupKey: "valid", Name: "x"},
		{ScopeID: group.ScopeSystem, GroupKey: "UPPER", Name: "x"},
		{ScopeID: group.ScopeSystem, GroupKey: "a", Name: "x"},
		{ScopeID: group.ScopeSystem, GroupKey: "valid", Name: ""},
		{ScopeID: group.ScopeSystem, GroupKey: "valid", Name: strings.Repeat("名", group.MaxNameRunes+1)},
	}
	for _, request := range invalid {
		_, err := env.service.CreateGroup(context.Background(), env.system, request)
		if request.ScopeID == "not-a-scope" {
			// 未通过授权器作用范围判定时默认拒绝，不泄露非法 scope 细节。
			if !errors.Is(err, group.ErrAccessDenied) {
				t.Errorf("非法 scope 创建错误 = %v", err)
			}
			continue
		}
		if !errors.Is(err, group.ErrInvalidRequest) {
			t.Errorf("非法创建请求 %+v 错误 = %v", request, err)
		}
	}
	if _, err := env.service.GetGroup(context.Background(), env.system, "not-a-group-id"); !errors.Is(err, group.ErrInvalidRequest) {
		t.Fatalf("非法组 ID 错误 = %v", err)
	}
	if _, err := env.service.GetGroup(context.Background(), env.system, "grp_ffffffffffffffffffffffffffffffff"); !errors.Is(err, group.ErrGroupNotFound) {
		t.Fatalf("不存在组错误 = %v", err)
	}
	if value := group.CodeOf(group.ErrGroupKeyTaken); value != group.CodeConflict {
		t.Errorf("组键冲突错误码 = %q", value)
	}
	if value := group.CodeOf(group.ErrMemberNotEligible); value != group.CodeUserDisabled {
		t.Errorf("成员资格错误码 = %q，期望 USER_DISABLED", value)
	}
	if value := group.CodeOf(group.ErrApplicationInactive); value != group.CodeClientDisabled {
		t.Errorf("应用停用错误码 = %q，期望 CLIENT_DISABLED", value)
	}
}
