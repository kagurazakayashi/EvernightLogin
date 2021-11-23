package profile_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/profile"
	profilesqlite "github.com/kagurazakayashi/EvernightLogin/internal/profile/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

var testStart = time.Date(2026, 11, 16, 13, 0, 0, 0, time.UTC)

type testEnv struct {
	t        *testing.T
	ctx      context.Context
	storage  *storagesqlite.Store
	service  *profile.Service
	store    profile.Store
	recorder *audit.Recorder
	now      time.Time
}

// serviceStore 返回同一数据库上的资料存储。
func (e *testEnv) serviceStore() profile.Store { return e.store }

// auditForTest 返回真实审计写入器。
func (e *testEnv) auditForTest() profile.AuditRecorder { return e.recorder }

func newTestEnv(t *testing.T, mutate func(*profile.Options)) *testEnv {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(testutil.TempDir(t), "profile-test.db")
	storage, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(path))
	if err != nil {
		t.Fatalf("打开数据库: %v", err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	migrationList, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移: %v", err)
	}
	if _, err := storage.Migrate(ctx, migrationList); err != nil {
		t.Fatalf("执行迁移: %v", err)
	}
	auditStore, err := auditsqlite.New(storage)
	if err != nil {
		t.Fatalf("审计存储: %v", err)
	}
	recorder, err := audit.New(auditStore, audit.Options{Now: func() time.Time { return testStart }})
	if err != nil {
		t.Fatalf("审计: %v", err)
	}
	store, err := profilesqlite.New(storage)
	if err != nil {
		t.Fatalf("资料存储: %v", err)
	}
	env := &testEnv{t: t, ctx: ctx, storage: storage, store: store, recorder: recorder, now: testStart}
	options := profile.Options{AllowLegacyWithoutSensitive: true,
		Store: store, Audit: recorder,
		Policy: profile.DefaultPolicy(),
		Now:    func() time.Time { return env.now },
	}
	if mutate != nil {
		mutate(&options)
	}
	service, err := profile.New(options)
	if err != nil {
		t.Fatalf("资料服务: %v", err)
	}
	env.service = service
	return env
}

// seedUser 插入合成用户并返回稳定 ID。
func (e *testEnv) seedUser(t *testing.T, id, username string) {
	t.Helper()
	now := testStart.UnixMilli()
	if _, err := e.storage.DB().ExecContext(e.ctx, `INSERT INTO users(
id,username,username_normalized,nickname,biography,avatar_ref,language,timezone,status,is_root,
security_version,row_version,created_at_ms,updated_at_ms
) VALUES(?,?,?,'','',NULL,'zh-CN','Asia/Shanghai','active',0,1,1,?,?)`,
		id, username, username, now, now); err != nil {
		t.Fatalf("用户: %v", err)
	}
}

func (e *testEnv) userCaller(t *testing.T, id string) profile.Caller {
	t.Helper()
	caller, err := profile.UserCaller(id)
	if err != nil {
		t.Fatalf("用户调用者: %v", err)
	}
	return caller
}

func (e *testEnv) count(query string, args ...any) int {
	e.t.Helper()
	var value int
	if err := e.storage.DB().QueryRowContext(e.ctx, query, args...).Scan(&value); err != nil {
		e.t.Fatalf("计数: %v", err)
	}
	return value
}

func stringPtr(value string) *string { return &value }

// TestSelfUpdateProfileAndApplicationIsolation 验证本人资料更新、电话规范化为未验证、
// 版本递增、审计稳定关联，以及全局资料与应用专属资料互不覆盖。
func TestSelfUpdateProfileAndApplicationIsolation(t *testing.T) {
	env := newTestEnv(t, nil)
	const userID = "usr_00000000000000000000000000000001"
	const appID = "app_00000000000000000000000000000001"
	env.seedUser(t, userID, "alice")
	now := testStart.UnixMilli()
	if _, err := env.storage.DB().ExecContext(env.ctx, `INSERT INTO applications(
id,name,description,status,client_type,row_version,created_at_ms,updated_at_ms
) VALUES(?,'demo','','active','confidential',1,?,?)`, appID, now, now); err != nil {
		t.Fatalf("应用: %v", err)
	}
	if _, err := env.storage.DB().ExecContext(env.ctx, `INSERT INTO app_memberships(
app_id,user_id,status,profile_json,row_version,created_at_ms,updated_at_ms
) VALUES(?,?,'active','{"nickname":"应用昵称"}',1,?,?)`, appID, userID, now, now); err != nil {
		t.Fatalf("应用成员: %v", err)
	}
	caller := env.userCaller(t, userID)
	updated, err := env.service.UpdateSelf(env.ctx, caller, profile.ProfileChange{
		Nickname:  stringPtr("全局昵称"),
		Biography: stringPtr("简介"),
		Language:  stringPtr("en-US"),
		Timezone:  stringPtr("Europe/London"),
		Phone:     stringPtr("13800138000"),
	}, 1, "req-1")
	if err != nil {
		t.Fatalf("本人更新资料: %v", err)
	}
	if updated.Nickname != "全局昵称" || updated.Language != "en-US" ||
		updated.Timezone != "Europe/London" || updated.Phone != "+8613800138000" {
		t.Fatalf("更新结果 = %+v", updated)
	}
	if updated.PhoneVerified {
		t.Error("本版电话始终不应为已验证")
	}
	if updated.RowVersion != 2 {
		t.Errorf("行版本 = %d，期望 2", updated.RowVersion)
	}
	if got := env.count(`SELECT COUNT(*) FROM users WHERE id=? AND phone_verified_at_ms IS NULL`, userID); got != 1 {
		t.Errorf("phone_verified_at_ms 应保持 NULL，实际 %d", got)
	}
	// 全局资料更新不得覆盖应用专属昵称。
	var appProfile string
	if err := env.storage.DB().QueryRowContext(env.ctx,
		`SELECT profile_json FROM app_memberships WHERE app_id=? AND user_id=?`, appID, userID).Scan(&appProfile); err != nil {
		t.Fatalf("读取应用资料: %v", err)
	}
	if !strings.Contains(appProfile, "应用昵称") {
		t.Errorf("应用专属资料被全局更新覆盖: %s", appProfile)
	}
	// 应用资料更新也不得覆盖全局资料。
	if _, err := env.storage.DB().ExecContext(env.ctx,
		`UPDATE app_memberships SET profile_json='{"nickname":"改应用名"}' WHERE app_id=? AND user_id=?`,
		appID, userID); err != nil {
		t.Fatalf("更新应用资料: %v", err)
	}
	current, err := env.service.GetProfile(env.ctx, caller, userID)
	if err != nil || current.Nickname != "全局昵称" {
		t.Fatalf("应用资料更新不应覆盖全局资料: %+v %v", current, err)
	}
	// 审计以稳定用户 ID 关联。
	if got := env.count(`SELECT COUNT(*) FROM audit_events WHERE target_id=? AND action='profile.update'`, userID); got != 1 {
		t.Errorf("应写入 1 条资料更新审计，实际 %d", got)
	}
	if got := env.count(`SELECT COUNT(*) FROM audit_events WHERE detail_json LIKE ?`, "%13800138000%"); got != 0 {
		t.Errorf("审计不应保存完整电话号码，实际匹配 %d", got)
	}
}

// TestVersionConflictConcurrentUpdate 验证并发资料更新只有一个成功，另一个返回冲突。
func TestVersionConflictConcurrentUpdate(t *testing.T) {
	env := newTestEnv(t, nil)
	const userID = "usr_00000000000000000000000000000002"
	env.seedUser(t, userID, "bob")
	caller := env.userCaller(t, userID)
	var wg sync.WaitGroup
	results := make([]error, 2)
	for index := 0; index < 2; index++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := env.service.UpdateSelf(env.ctx, caller, profile.ProfileChange{
				Nickname: stringPtr("并发昵称" + string(rune('A'+i))),
			}, 1, "")
			results[i] = err
		}(index)
	}
	wg.Wait()
	successes, conflicts := 0, 0
	for _, err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, profile.ErrVersionConflict):
			conflicts++
		default:
			t.Fatalf("并发更新错误: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("并发更新 = 成功 %d 冲突 %d", successes, conflicts)
	}
}

// TestMaliciousAndInvalidFields 验证恶意额外字段与非法输入被拒绝。
func TestMaliciousAndInvalidFields(t *testing.T) {
	for _, payload := range []string{
		`{"nickname":"x","is_root":true}`,
		`{"nickname":"x","password":"x"}`,
		`{"nickname":"x","email_verified":true}`,
		`{"nickname":"x","mfa_enabled":true}`,
		`{"nickname":"x","roles":["system_admin"]}`,
		`{"nickname":"x","status":"active"}`,
		`{"nickname":"x","username":"newname"}`,
	} {
		if _, err := profile.ParseProfileJSON([]byte(payload)); !errors.Is(err, profile.ErrInvalidRequest) {
			t.Errorf("恶意字段应被拒绝 %s，实际 %v", payload, err)
		}
	}
	if _, err := profile.ParseProfileJSON([]byte(`{"nickname":"a"} {"nickname":"b"}`)); err == nil {
		t.Error("多个 JSON 对象应被拒绝")
	}
	env := newTestEnv(t, nil)
	const userID = "usr_00000000000000000000000000000003"
	env.seedUser(t, userID, "carol")
	caller := env.userCaller(t, userID)
	cases := []profile.ProfileChange{
		{Nickname: stringPtr("bad\x00name")},
		{Biography: stringPtr(strings.Repeat("长", 1001))},
		{Language: stringPtr("not a language!")},
		{Timezone: stringPtr("Not/AZone")},
		{Phone: stringPtr("12ab")},
		{Phone: stringPtr("+1")},
	}
	for _, change := range cases {
		if _, err := env.service.UpdateSelf(env.ctx, caller, change, 1, ""); err == nil {
			t.Errorf("非法资料 %+v 应被拒绝", change)
		}
	}
}

// TestAuthorizationAndAdminUpdate 验证默认情况下普通用户不能改他人资料；注入
// Authorizer 后管理员可改；系统通道可直接改。
func TestAuthorizationAndAdminUpdate(t *testing.T) {
	env := newTestEnv(t, nil)
	userA := "usr_00000000000000000000000000000004"
	userB := "usr_00000000000000000000000000000005"
	env.seedUser(t, userA, "dave")
	env.seedUser(t, userB, "erin")
	if _, err := env.service.UpdateUser(env.ctx, env.userCaller(t, userA), profile.UpdateRequest{
		TargetUserID: userB, Change: profile.ProfileChange{Nickname: stringPtr("越权")}, ExpectedRowVersion: 1,
	}); !errors.Is(err, profile.ErrAccessDenied) {
		t.Fatalf("普通用户改他人资料应被拒绝，实际 %v", err)
	}
	if got := env.count(`SELECT COUNT(*) FROM users WHERE id=? AND nickname='越权'`, userB); got != 0 {
		t.Errorf("越权更新不应生效")
	}
	// 注入受控管理员授权器。
	adminEnv := newTestEnv(t, func(options *profile.Options) {
		options.Authorizer = profile.AuthorizerFunc(func(_ context.Context, caller profile.Caller, target profile.UserProfile, write bool) error {
			if caller.IsUser() && caller.Actor().ID == "usr_00000000000000000000000000000099" {
				return nil
			}
			if caller.Actor().Type == audit.ActorSystem || caller.Actor().Type == audit.ActorLocalAdmin {
				return nil
			}
			return profile.ErrAccessDenied
		})
	})
	adminEnv.seedUser(t, userA, "dave")
	adminEnv.seedUser(t, userB, "erin")
	adminEnv.seedUser(t, "usr_00000000000000000000000000000099", "admin")
	updated, err := adminEnv.service.UpdateUser(adminEnv.ctx, adminEnv.userCaller(t, "usr_00000000000000000000000000000099"),
		profile.UpdateRequest{TargetUserID: userB, Change: profile.ProfileChange{Nickname: stringPtr("管理员改名")}, ExpectedRowVersion: 1})
	if err != nil {
		t.Fatalf("授权管理员更新他人资料失败: %v", err)
	}
	if updated.Nickname != "管理员改名" {
		t.Errorf("管理员更新结果 = %+v", updated)
	}
	systemCaller, _ := profile.SystemCaller("maintenance")
	if _, err := adminEnv.service.UpdateUser(adminEnv.ctx, systemCaller, profile.UpdateRequest{
		TargetUserID: userB, Change: profile.ProfileChange{Timezone: stringPtr("Asia/Tokyo")}, ExpectedRowVersion: updated.RowVersion,
	}); err != nil {
		t.Fatalf("系统通道更新资料失败: %v", err)
	}
}

// TestControlledRename 验证更名规范化/唯一性/保留名/冷却/再次验证/版本冲突与稳定 ID。
func TestControlledRename(t *testing.T) {
	env := newTestEnv(t, func(options *profile.Options) {
		options.ReauthVerifier = profile.ReauthVerifierFunc(func(context.Context, profile.Caller, string) error { return nil })
	})
	const userID = "usr_00000000000000000000000000000006"
	env.seedUser(t, userID, "frank")
	env.seedUser(t, "usr_00000000000000000000000000000007", "taken")
	caller := env.userCaller(t, userID)
	if _, err := env.service.ChangeUsername(env.ctx, caller, profile.ChangeUsernameRequest{
		TargetUserID: userID, NewUsername: "Taken", ExpectedRowVersion: 1,
	}); !errors.Is(err, profile.ErrUsernameTaken) {
		t.Fatalf("规范化重名应被拒绝，实际 %v", err)
	}
	if _, err := env.service.ChangeUsername(env.ctx, caller, profile.ChangeUsernameRequest{
		TargetUserID: userID, NewUsername: "root", ExpectedRowVersion: 1,
	}); err == nil {
		t.Fatal("保留用户名应被拒绝")
	}
	renamed, err := env.service.ChangeUsername(env.ctx, caller, profile.ChangeUsernameRequest{
		TargetUserID: userID, NewUsername: "Frank.New", ExpectedRowVersion: 1, RequestID: "rename-1",
	})
	if err != nil {
		t.Fatalf("受控更名失败: %v", err)
	}
	if renamed.UserID != userID || renamed.Username != "Frank.New" || renamed.RowVersion != 2 {
		t.Fatalf("更名结果 = %+v", renamed)
	}
	if got := env.count(`SELECT COUNT(*) FROM audit_events WHERE action='profile.username_change' AND outcome='success' AND target_id=?`, userID); got != 1 {
		t.Errorf("应写入更名审计，实际 %d", got)
	}
	// 冷却期内再次更名被拒绝。
	if _, err := env.service.ChangeUsername(env.ctx, caller, profile.ChangeUsernameRequest{
		TargetUserID: userID, NewUsername: "Frank.Third", ExpectedRowVersion: renamed.RowVersion,
	}); !errors.Is(err, profile.ErrRenameTooSoon) {
		t.Fatalf("冷却期内更名应被拒绝，实际 %v", err)
	}
	// 冷却结束后允许；再次验证通过才可更名。
	env.now = env.now.Add(25 * time.Hour)
	if _, err := env.service.ChangeUsername(env.ctx, caller, profile.ChangeUsernameRequest{
		TargetUserID: userID, NewUsername: "Frank.Third", ExpectedRowVersion: renamed.RowVersion,
	}); err != nil {
		t.Fatalf("冷却后更名失败: %v", err)
	}
	// 未注入再次验证器时普通用户更名 fail-closed。
	noReauth := newTestEnv(t, nil)
	noReauth.seedUser(t, userID, "frank")
	if _, err := noReauth.service.ChangeUsername(noReauth.ctx, noReauth.userCaller(t, userID),
		profile.ChangeUsernameRequest{TargetUserID: userID, NewUsername: "Frank.NoReauth", ExpectedRowVersion: 1}); !errors.Is(err, profile.ErrRenameReauthRequired) {
		t.Fatalf("缺少再次验证时应拒绝更名，实际 %v", err)
	}
}

func durationPtr(value time.Duration) *time.Duration { return &value }
func boolPtr(value bool) *bool                       { return &value }

// TestPolicyPartialConfigDoesNotSilentlyDisable 验证只配置策略的一个字段时，其余
// 安全默认（再次验证/冷却）不会被静默关闭。
func TestPolicyPartialConfigDoesNotSilentlyDisable(t *testing.T) {
	// 只配冷却：再次验证仍默认开启，缺少 ReauthVerifier 时必须拒绝。
	cooldownOnly := newTestEnv(t, func(options *profile.Options) {
		options.Policy = profile.Policy{RenameCooldown: durationPtr(48 * time.Hour)}
	})
	const userID = "usr_00000000000000000000000000000010"
	cooldownOnly.seedUser(t, userID, "policytest")
	if _, err := cooldownOnly.service.ChangeUsername(cooldownOnly.ctx, cooldownOnly.userCaller(t, userID),
		profile.ChangeUsernameRequest{TargetUserID: userID, NewUsername: "policy.new", ExpectedRowVersion: 1}); !errors.Is(err, profile.ErrRenameReauthRequired) {
		t.Fatalf("只配冷却时再次验证不应被关闭，实际 %v", err)
	}
	// 只配 RequireReauth=true：冷却仍默认 24 小时，连续更名必须被冷却拒绝。
	reauthOnly := newTestEnv(t, func(options *profile.Options) {
		options.Policy = profile.Policy{RequireReauth: boolPtr(true)}
		options.ReauthVerifier = profile.ReauthVerifierFunc(func(context.Context, profile.Caller, string) error { return nil })
	})
	reauthOnly.seedUser(t, userID, "policytest")
	renamed, err := reauthOnly.service.ChangeUsername(reauthOnly.ctx, reauthOnly.userCaller(t, userID),
		profile.ChangeUsernameRequest{TargetUserID: userID, NewUsername: "policy.first", ExpectedRowVersion: 1})
	if err != nil {
		t.Fatalf("默认冷却下首次更名失败: %v", err)
	}
	if _, err := reauthOnly.service.ChangeUsername(reauthOnly.ctx, reauthOnly.userCaller(t, userID),
		profile.ChangeUsernameRequest{TargetUserID: userID, NewUsername: "policy.second", ExpectedRowVersion: renamed.RowVersion}); !errors.Is(err, profile.ErrRenameTooSoon) {
		t.Fatalf("只配 RequireReauth 时冷却不应被关闭，实际 %v", err)
	}
}

// TestBiographyMultilineAndBoundary 验证多行简介与 1000 码点边界可保存，审计只记录
// 脱敏摘要（不因换行/长度被误拒为存储故障）。
func TestBiographyMultilineAndBoundary(t *testing.T) {
	env := newTestEnv(t, nil)
	const userID = "usr_00000000000000000000000000000011"
	env.seedUser(t, userID, "biography")
	caller := env.userCaller(t, userID)
	multiline := "第一行\n第二行\t缩进\n第三行"
	updated, err := env.service.UpdateSelf(env.ctx, caller,
		profile.ProfileChange{Biography: &multiline}, 1, "")
	if err != nil {
		t.Fatalf("多行简介保存失败: %v", err)
	}
	if updated.Biography != multiline {
		t.Errorf("多行简介被改写: %q", updated.Biography)
	}
	boundary := strings.Repeat("长", 1000)
	updated, err = env.service.UpdateSelf(env.ctx, caller,
		profile.ProfileChange{Biography: &boundary}, updated.RowVersion, "")
	if err != nil {
		t.Fatalf("1000 码点简介保存失败: %v", err)
	}
	if len([]rune(updated.Biography)) != 1000 {
		t.Errorf("简介长度 = %d", len([]rune(updated.Biography)))
	}
	if got := env.count(`SELECT COUNT(*) FROM audit_events WHERE detail_json LIKE ?`, "%第一行%"); got != 0 {
		t.Errorf("审计不应保存简介原文，实际 %d", got)
	}
	if got := env.count(`SELECT COUNT(*) FROM audit_events WHERE detail_json LIKE '%[REDACTED]%'`); got == 0 {
		t.Error("审计应记录简介脱敏摘要")
	}
}

// TestReservedNamesPolicy 验证保留名默认、追加自定义保留名与显式禁用标志。
func TestReservedNamesPolicy(t *testing.T) {
	base := func() (*testEnv, string) {
		env := newTestEnv(t, func(options *profile.Options) {
			options.ReauthVerifier = profile.ReauthVerifierFunc(func(context.Context, profile.Caller, string) error { return nil })
		})
		const userID = "usr_00000000000000000000000000000012"
		env.seedUser(t, userID, "reserved")
		return env, userID
	}
	env, userID := base()
	if _, err := env.service.ChangeUsername(env.ctx, env.userCaller(t, userID),
		profile.ChangeUsernameRequest{TargetUserID: userID, NewUsername: "admin", ExpectedRowVersion: 1}); err == nil {
		t.Fatal("默认保留名应被拒绝")
	}
	custom, userID2 := base()
	customService, err := profile.New(profile.Options{AllowLegacyWithoutSensitive: true,
		Store: custom.serviceStore(), Audit: custom.auditForTest(), ReauthVerifier: profile.ReauthVerifierFunc(func(context.Context, profile.Caller, string) error { return nil }),
		Policy: profile.Policy{ReservedNames: []string{"customname"}},
		Now:    func() time.Time { return custom.now },
	})
	if err != nil {
		t.Fatalf("自定义保留名服务: %v", err)
	}
	if _, err := customService.ChangeUsername(custom.ctx, custom.userCaller(t, userID2),
		profile.ChangeUsernameRequest{TargetUserID: userID2, NewUsername: "customname", ExpectedRowVersion: 1}); err == nil {
		t.Fatal("配置追加的保留名应被拒绝")
	}
	disabled, userID3 := base()
	disabledService, err := profile.New(profile.Options{AllowLegacyWithoutSensitive: true,
		Store: disabled.serviceStore(), Audit: disabled.auditForTest(),
		ReauthVerifier: profile.ReauthVerifierFunc(func(context.Context, profile.Caller, string) error { return nil }),
		Policy:         profile.Policy{DisableReservedNames: true},
		Now:            func() time.Time { return disabled.now },
	})
	if err != nil {
		t.Fatalf("禁用保留名服务: %v", err)
	}
	if _, err := disabledService.ChangeUsername(disabled.ctx, disabled.userCaller(t, userID3),
		profile.ChangeUsernameRequest{TargetUserID: userID3, NewUsername: "root", ExpectedRowVersion: 1}); err != nil {
		t.Fatalf("显式禁用保留名检查时应允许: %v", err)
	}
}

// TestPhoneChangeClearsVerification 验证改电话清空验证状态，改其他字段不清空。
func TestPhoneChangeClearsVerification(t *testing.T) {
	env := newTestEnv(t, nil)
	const userID = "usr_00000000000000000000000000000013"
	env.seedUser(t, userID, "phonechange")
	caller := env.userCaller(t, userID)
	if _, err := env.storage.DB().ExecContext(env.ctx,
		`UPDATE users SET phone='+8613800138000', phone_verified_at_ms=12345 WHERE id=?`, userID); err != nil {
		t.Fatalf("预置电话验证状态: %v", err)
	}
	updated, err := env.service.UpdateSelf(env.ctx, caller,
		profile.ProfileChange{Nickname: stringPtr("改名不改电话")}, 1, "")
	if err != nil {
		t.Fatalf("更新昵称失败: %v", err)
	}
	if got := env.count(`SELECT COUNT(*) FROM users WHERE id=? AND phone_verified_at_ms IS NOT NULL`, userID); got != 1 {
		t.Errorf("未改电话不应清空验证状态，实际 %d", got)
	}
	if _, err := env.service.UpdateSelf(env.ctx, caller,
		profile.ProfileChange{Phone: stringPtr("+8613900139000")}, updated.RowVersion, ""); err != nil {
		t.Fatalf("更新电话失败: %v", err)
	}
	if got := env.count(`SELECT COUNT(*) FROM users WHERE id=? AND phone_verified_at_ms IS NULL`, userID); got != 1 {
		t.Errorf("改电话应清空验证状态，实际 %d", got)
	}
}

// TestRenameConcurrencyRootAndSystem 验证并发更名唯一成功、root 目标拒绝、system
// 通道可更名且稳定 ID 不变。
func TestRenameConcurrencyRootAndSystem(t *testing.T) {
	env := newTestEnv(t, func(options *profile.Options) {
		options.ReauthVerifier = profile.ReauthVerifierFunc(func(context.Context, profile.Caller, string) error { return nil })
	})
	const userID = "usr_00000000000000000000000000000014"
	env.seedUser(t, userID, "concurrent")
	caller := env.userCaller(t, userID)
	var wg sync.WaitGroup
	results := make([]error, 2)
	for index := 0; index < 2; index++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := env.service.ChangeUsername(env.ctx, caller, profile.ChangeUsernameRequest{
				TargetUserID: userID, NewUsername: "concurrent." + string(rune('a'+i)), ExpectedRowVersion: 1,
			})
			results[i] = err
		}(index)
	}
	wg.Wait()
	successes, conflicts := 0, 0
	for _, err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, profile.ErrVersionConflict):
			conflicts++
		default:
			t.Fatalf("并发更名错误: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("并发更名 = 成功 %d 冲突 %d", successes, conflicts)
	}
	if got := env.count(`SELECT COUNT(*) FROM users WHERE id=?`, userID); got != 1 {
		t.Errorf("更名后稳定 ID 应唯一存在")
	}
	// root 目标更名被拒绝。
	const rootID = "usr_00000000000000000000000000000015"
	env.seedUser(t, rootID, "rootuser")
	if _, err := env.storage.DB().ExecContext(env.ctx, `UPDATE users SET is_root=1 WHERE id=?`, rootID); err != nil {
		t.Fatalf("设置 root: %v", err)
	}
	systemCaller, _ := profile.SystemCaller("maintenance")
	if _, err := env.service.ChangeUsername(env.ctx, systemCaller, profile.ChangeUsernameRequest{
		TargetUserID: rootID, NewUsername: "rootrenamed", ExpectedRowVersion: 1,
	}); !errors.Is(err, profile.ErrAccessDenied) {
		t.Fatalf("root 目标更名应被拒绝，实际 %v", err)
	}
	// system 通道可更名普通用户（冷却结束后；冷却对受信通道同样生效）。
	env.now = env.now.Add(25 * time.Hour)
	renamed, err := env.service.ChangeUsername(env.ctx, systemCaller, profile.ChangeUsernameRequest{
		TargetUserID: userID, NewUsername: "system.renamed", ExpectedRowVersion: 2,
	})
	if err != nil {
		t.Fatalf("system 通道更名失败: %v", err)
	}
	if renamed.UserID != userID || renamed.Username != "system.renamed" {
		t.Errorf("system 更名结果 = %+v", renamed)
	}
}

// TestUnauthorizedReadDoesNotLeakExistence 验证无权的普通用户先判权再读，统一
// 返回 ACCESS_DENIED，不因目标不存在而出现存在性差异。
func TestUnauthorizedReadDoesNotLeakExistence(t *testing.T) {
	env := newTestEnv(t, nil)
	const userID = "usr_00000000000000000000000000000016"
	env.seedUser(t, userID, "reader")
	caller := env.userCaller(t, userID)
	otherValid := "usr_00000000000000000000000000000099"
	if _, err := env.service.GetProfile(env.ctx, caller, otherValid); !errors.Is(err, profile.ErrAccessDenied) {
		t.Fatalf("读取不存在他人应为 ACCESS_DENIED，实际 %v", err)
	}
	if _, err := env.service.UpdateUser(env.ctx, caller, profile.UpdateRequest{
		TargetUserID: otherValid, Change: profile.ProfileChange{Nickname: stringPtr("x")}, ExpectedRowVersion: 1,
	}); !errors.Is(err, profile.ErrAccessDenied) {
		t.Fatalf("修改不存在他人应为 ACCESS_DENIED，实际 %v", err)
	}
}

// fakeInvalidAudit 让关键变更审计返回 ErrInvalidEvent，验证错误映射不是 DB 错误。
type fakeInvalidAudit struct{}

func (fakeInvalidAudit) Record(context.Context, audit.Event) error { return nil }
func (fakeInvalidAudit) RecordFailure(context.Context, audit.Event) error {
	return nil
}
func (fakeInvalidAudit) ExecuteCritical(context.Context, audit.CriticalRequest, audit.Change) error {
	return audit.ErrInvalidEvent
}

// TestAuditInvalidEventMapsToInternal 验证审计事件无效映射为 INTERNAL_ERROR 而非
// DB_UNAVAILABLE。
func TestAuditInvalidEventMapsToInternal(t *testing.T) {
	env := newTestEnv(t, nil)
	const userID = "usr_00000000000000000000000000000017"
	env.seedUser(t, userID, "auditerr")
	service, err := profile.New(profile.Options{AllowLegacyWithoutSensitive: true, Store: env.serviceStore(), Audit: fakeInvalidAudit{},
		Policy: profile.DefaultPolicy(), Now: func() time.Time { return env.now }})
	if err != nil {
		t.Fatalf("构造服务: %v", err)
	}
	if _, err := service.UpdateSelf(env.ctx, env.userCaller(t, userID),
		profile.ProfileChange{Nickname: stringPtr("x")}, 1, ""); err == nil {
		t.Fatal("审计事件无效应失败")
	} else if errors.Is(err, profile.ErrStoreUnavailable) {
		t.Errorf("审计事件无效不应映射为存储不可用: %v", err)
	}
}
