package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/group"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const (
	testAppID  = "app_00000000000000000000000000000001"
	testUserID = "usr_00000000000000000000000000000001"
)

func openMigratedStore(t *testing.T) *storagesqlite.Store {
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
	return raw
}

func TestNewValidation(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("空存储应被拒绝")
	}
}

func TestScopeAndGroupQueries(t *testing.T) {
	raw := openMigratedStore(t)
	store, err := New(raw)
	if err != nil {
		t.Fatalf("构造仓储失败: %v", err)
	}
	ctx := context.Background()
	now := int64(1_700_000_000_000)
	// 系统 scope 存在；未知应用 scope 拒绝。
	if info, err := store.GetScope(ctx, group.ScopeSystem); err != nil || info.Kind != group.ScopeKindSystem {
		t.Fatalf("系统 scope = %+v, %v", info, err)
	}
	if _, err := store.GetScope(ctx, testAppID); !errors.Is(err, group.ErrScopeInvalid) {
		t.Fatalf("未知应用 scope 错误 = %v", err)
	}
	// 插入应用与应用 scope。
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO applications(id,name,description,icon_ref,homepage,owner_user_id,contact_info,status,client_type,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,'',NULL,NULL,NULL,NULL,'active','public',1,?,?)`, testAppID, "测试应用", now, now); err != nil {
		t.Fatalf("插入应用失败: %v", err)
	}
	if _, err := raw.ExecContext(ctx, `INSERT INTO scopes(id,kind,app_id) VALUES(?,'application',?)`, testAppID, testAppID); err != nil {
		t.Fatalf("插入 scope 失败: %v", err)
	}
	if info, err := store.GetScope(ctx, testAppID); err != nil || info.Kind != group.ScopeKindApplication ||
		info.ApplicationID != testAppID || !info.ApplicationActive {
		t.Fatalf("应用 scope = %+v, %v", info, err)
	}
	// 插入系统组与应用组；列表按 scope 过滤。
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO user_groups(id,scope_id,group_key,name,description,created_at_ms,updated_at_ms)
VALUES('grp_00000000000000000000000000000001','system','sys-group','系统组','',?,?)`, now, now); err != nil {
		t.Fatalf("插入系统组失败: %v", err)
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO user_groups(id,scope_id,group_key,name,description,created_at_ms,updated_at_ms)
VALUES('grp_00000000000000000000000000000002',?, 'app-group','应用组','',?,?)`, testAppID, now, now); err != nil {
		t.Fatalf("插入应用组失败: %v", err)
	}
	groupRecord, err := store.GetGroup(ctx, "grp_00000000000000000000000000000002")
	if err != nil || groupRecord.ScopeID != testAppID || groupRecord.ScopeKind != group.ScopeKindApplication ||
		groupRecord.ApplicationID != testAppID {
		t.Fatalf("读取应用组 = %+v, %v", groupRecord, err)
	}
	if _, err := store.GetGroup(ctx, "grp_ffffffffffffffffffffffffffffffff"); !errors.Is(err, group.ErrGroupNotFound) {
		t.Fatalf("不存在组错误 = %v", err)
	}
	all, hasMore, err := store.ListGroups(ctx, group.ListQuery{Limit: 10, AllScopes: true})
	if err != nil || hasMore || len(all) != 2 {
		t.Fatalf("全部组列表 = %+v, hasMore=%v, err=%v", all, hasMore, err)
	}
	filtered, _, err := store.ListGroups(ctx, group.ListQuery{Limit: 10, ScopeFilter: group.ScopeSystem})
	if err != nil || len(filtered) != 1 || filtered[0].ScopeID != group.ScopeSystem {
		t.Fatalf("系统 scope 列表 = %+v, %v", filtered, err)
	}
}

func TestMemberEligibilityQueries(t *testing.T) {
	raw := openMigratedStore(t)
	store, err := New(raw)
	if err != nil {
		t.Fatalf("构造仓储失败: %v", err)
	}
	ctx := context.Background()
	now := int64(1_700_000_000_000)
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO applications(id,name,description,icon_ref,homepage,owner_user_id,contact_info,status,client_type,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,'',NULL,NULL,NULL,NULL,'active','public',1,?,?)`, testAppID, "测试应用", now, now); err != nil {
		t.Fatalf("插入应用失败: %v", err)
	}
	if _, err := raw.ExecContext(ctx, `INSERT INTO scopes(id,kind,app_id) VALUES(?,'application',?)`, testAppID, testAppID); err != nil {
		t.Fatalf("插入 scope 失败: %v", err)
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO users(id,username,username_normalized,nickname,biography,language,timezone,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'','','zh-CN','Asia/Shanghai','active',0,1,1,?,?)`, testUserID, "user", "user", now, now); err != nil {
		t.Fatalf("插入用户失败: %v", err)
	}
	// 系统组只要求全局 active。
	ineligible, err := store.ValidateMembers(ctx, group.GroupScope{ScopeID: group.ScopeSystem, Kind: group.ScopeKindSystem}, []string{testUserID})
	if err != nil || len(ineligible) != 0 {
		t.Fatalf("系统组合格成员 = %+v, %v", ineligible, err)
	}
	// 应用组还要求有效应用成员关系。
	appScope := group.GroupScope{ScopeID: testAppID, Kind: group.ScopeKindApplication, ApplicationID: testAppID}
	ineligible, err = store.ValidateMembers(ctx, appScope, []string{testUserID})
	if err != nil || len(ineligible) != 1 {
		t.Fatalf("未加入应用成员应不合格 = %+v, %v", ineligible, err)
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO app_memberships(app_id,user_id,status,profile_json,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,'active','{}',1,?,?)`, testAppID, testUserID, now, now); err != nil {
		t.Fatalf("插入应用成员失败: %v", err)
	}
	ineligible, err = store.ValidateMembers(ctx, appScope, []string{testUserID})
	if err != nil || len(ineligible) != 0 {
		t.Fatalf("应用成员应合格 = %+v, %v", ineligible, err)
	}
	// 冻结成员查询：不存在时返回空。
	existing, err := store.ExistingMembers(ctx, "grp_00000000000000000000000000000001", []string{testUserID})
	if err != nil || len(existing) != 0 {
		t.Fatalf("冻结成员查询 = %+v, %v", existing, err)
	}
}
