package sqlite_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	authnsqlite "github.com/kagurazakayashi/EvernightLogin/internal/authn/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

var testBaseTime = time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)

// testEnv 汇总临时 SQLite、认证仓储与审计写入器。
type testEnv struct {
	t        *testing.T
	raw      *storagesqlite.Store
	store    *authnsqlite.Store
	recorder *audit.Recorder
	counter  int
}

// newTestEnv 在临时数据库执行全部迁移并构造真实仓储。
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(filepath.Join(testutil.TempDir(t), "authn-store.sqlite")))
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
	store, err := authnsqlite.New(raw)
	if err != nil {
		t.Fatalf("构造认证仓储失败: %v", err)
	}
	auditStore, err := auditsqlite.New(raw)
	if err != nil {
		t.Fatalf("构造审计仓储失败: %v", err)
	}
	recorder, err := audit.New(auditStore, audit.Options{Now: func() time.Time { return testBaseTime }})
	if err != nil {
		t.Fatalf("构造审计写入器失败: %v", err)
	}
	return &testEnv{t: t, raw: raw, store: store, recorder: recorder}
}

// insertUser 插入合成账户并返回用户 ID；isRoot 时使用保留名 root。
func (e *testEnv) insertUser(username string, isRoot bool) string {
	e.t.Helper()
	e.counter++
	var display, normalized string
	if isRoot {
		display, normalized = "root", "root"
	} else {
		var err error
		display, normalized, err = account.NormalizeUsername(username)
		if err != nil {
			e.t.Fatalf("规范化用户名失败: %v", err)
		}
	}
	userID := fmt.Sprintf("usr_%032x", e.counter)
	nowMS := testBaseTime.UnixMilli()
	_, err := e.raw.ExecContext(context.Background(),
		`INSERT INTO users(id,username,username_normalized,nickname,biography,avatar_ref,language,timezone,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'','',NULL,'zh-CN','Asia/Shanghai','active',?,1,1,?,?)`,
		userID, display, normalized, boolToInt(isRoot), nowMS, nowMS)
	if err != nil {
		e.t.Fatalf("插入账户失败: %v", err)
	}
	return userID
}

// runCritical 在真实审计事务中执行仓储写入。
func (e *testEnv) runCritical(change audit.Change) error {
	e.t.Helper()
	event := audit.Event{
		Actor:  audit.Actor{Type: audit.ActorSystem, ID: "test-system"},
		Action: "test.authn.store",
		Target: audit.Target{Type: "user", ID: "usr_00000000000000000000000000000001"},
	}
	return e.recorder.ExecuteCritical(context.Background(), audit.CriticalRequest{Event: event}, change)
}

// queryInt 执行单值整数查询。
func (e *testEnv) queryInt(query string, args ...any) int {
	e.t.Helper()
	rows, err := e.raw.QueryContext(context.Background(), query, args...)
	if err != nil {
		e.t.Fatalf("查询失败: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		e.t.Fatalf("查询没有结果: %v", rows.Err())
	}
	var value int
	if err := rows.Scan(&value); err != nil {
		e.t.Fatalf("扫描整数失败: %v", err)
	}
	return value
}

// boolToInt 把布尔值转成 SQLite 0/1。
func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

// TestPasswordTraceLifecycle 验证凭证写入、历史裁剪、安全版本递增、读取与条件
// 哈希升级/冲突。
func TestPasswordTraceLifecycle(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	userID := env.insertUser("storeuser", false)

	if _, found, err := env.store.GetPasswordCredential(ctx, userID); err != nil || found {
		t.Fatalf("无凭证时 = (%v,%v)，期望 found=false", found, err)
	}
	hash1, err := authn.HashPassword("Store-Password-9-A", authn.Params{
		MemoryKiB: 8192, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	}, nil)
	if err != nil {
		t.Fatalf("生成哈希失败: %v", err)
	}
	var result authn.PasswordChangeResult
	if err := env.runCritical(func(txCtx context.Context, tx audit.Tx) error {
		changed, setErr := env.store.SetPassword(txCtx, tx, authn.PasswordChange{
			UserID: userID, PasswordHash: hash1, HistoryLimit: 2, Now: testBaseTime,
		})
		result = changed
		return setErr
	}); err != nil {
		t.Fatalf("首次写入密码失败: %v", err)
	}
	if result.SecurityVersion != 2 || result.RowVersion != 1 {
		t.Fatalf("首次写入结果 = %+v，期望安全版本 2、行版本 1", result)
	}
	credential, found, err := env.store.GetPasswordCredential(ctx, userID)
	if err != nil || !found || credential.PasswordHash != hash1 || credential.MustChange {
		t.Fatalf("读取凭证 = (%+v,%v,%v)", credential, found, err)
	}

	// 第二次写入：旧哈希进入历史，历史上限 1 → 只保留最新一条。
	hash2, err := authn.HashPassword("Store-Password-9-B", authn.Params{
		MemoryKiB: 8192, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	}, nil)
	if err != nil {
		t.Fatalf("生成哈希失败: %v", err)
	}
	if err := env.runCritical(func(txCtx context.Context, tx audit.Tx) error {
		_, setErr := env.store.SetPassword(txCtx, tx, authn.PasswordChange{
			UserID: userID, PasswordHash: hash2, HistoryLimit: 1,
			Now: testBaseTime.Add(time.Minute),
		})
		return setErr
	}); err != nil {
		t.Fatalf("第二次写入密码失败: %v", err)
	}
	if count := env.queryInt(`SELECT COUNT(*) FROM password_history WHERE user_id=?`, userID); count != 1 {
		t.Fatalf("历史条数 = %d，期望 1", count)
	}
	history, err := env.store.ListPasswordHistoryHashes(ctx, userID, 10)
	if err != nil || len(history) != 1 || history[0] != hash1 {
		t.Fatalf("历史哈希 = (%v,%v)，期望旧哈希", history, err)
	}
	if credential, found, _ := env.store.GetPasswordCredential(ctx, userID); !found || credential.PasswordHash != hash2 ||
		credential.RowVersion != 2 {
		t.Fatalf("第二次读取凭证 = (%+v,%v)", credential, found)
	}

	// 条件哈希升级成功；用过期的旧哈希再升级返回状态冲突。
	upgraded, err := authn.HashPassword("Store-Password-9-B", authn.Params{
		MemoryKiB: 10240, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	}, nil)
	if err != nil {
		t.Fatalf("生成升级哈希失败: %v", err)
	}
	if err := env.runCritical(func(txCtx context.Context, tx audit.Tx) error {
		return env.store.UpgradePasswordHash(txCtx, tx, authn.HashUpgrade{
			UserID: userID, OldHash: hash2, NewHash: upgraded,
			Now: testBaseTime.Add(2 * time.Minute),
		})
	}); err != nil {
		t.Fatalf("条件升级失败: %v", err)
	}
	if err := env.runCritical(func(txCtx context.Context, tx audit.Tx) error {
		return env.store.UpgradePasswordHash(txCtx, tx, authn.HashUpgrade{
			UserID: userID, OldHash: hash2, NewHash: upgraded,
			Now: testBaseTime.Add(3 * time.Minute),
		})
	}); !errors.Is(err, authn.ErrSetupStateConflict) {
		t.Fatalf("陈旧哈希升级错误 = %v，期望 ErrSetupStateConflict", err)
	}
}

// TestUserLookupsAndVerifiedEmail 验证按 ID/规范化用户名/已验证邮箱查询，以及
// 非 ASCII 大写邮箱按服务层 Unicode 折叠规范化后可正常存取（不依赖 SQLite
// lower()）。
func TestUserLookupsAndVerifiedEmail(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	userID := env.insertUser("ÜserName", false)

	found, ok, err := env.store.FindUserByID(ctx, userID)
	if err != nil || !ok || found.UserID != userID {
		t.Fatalf("FindUserByID = (%+v,%v,%v)", found, ok, err)
	}
	display, normalized, err := authn.NormalizeLoginUsername("üsername")
	if err != nil {
		t.Fatalf("规范化用户名失败: %v", err)
	}
	_ = display
	if found, ok, err := env.store.FindUserByUsernameNormalized(ctx, normalized); err != nil || !ok {
		t.Fatalf("按规范化用户名查询失败: (%v,%v)", ok, err)
	} else if found.UserID != userID {
		t.Fatalf("按规范化用户名查询用户 = %q", found.UserID)
	}

	// 未验证邮箱不参与登录查询。
	emailDisplay, emailNormalized, err := authn.NormalizeEmail("ÜSER@Example.COM")
	if err != nil {
		t.Fatalf("规范化邮箱失败: %v", err)
	}
	if _, ok, err := env.store.FindUserByVerifiedEmail(ctx, emailNormalized); err != nil || ok {
		t.Fatalf("未验证邮箱查询 = (%v,%v)，期望未找到", ok, err)
	}
	if _, err := env.raw.ExecContext(ctx,
		`INSERT INTO user_emails(email_normalized,user_id,email,verified_at_ms,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?)`, emailNormalized, userID, emailDisplay, testBaseTime.UnixMilli(),
		testBaseTime.UnixMilli(), testBaseTime.UnixMilli()); err != nil {
		t.Fatalf("写入非 ASCII 大写规范化邮箱失败: %v", err)
	}
	foundUser, ok, err := env.store.FindUserByVerifiedEmail(ctx, emailNormalized)
	if err != nil || !ok || foundUser.UserID != userID {
		t.Fatalf("已验证邮箱查询 = (%+v,%v,%v)", foundUser, ok, err)
	}
	// 查询口径是服务层规范化值；大小写/全角变体先经 NormalizeEmail 归一。
	_, otherNormalized, err := authn.NormalizeEmail("üser@example.com")
	if err != nil {
		t.Fatalf("规范化邮箱失败: %v", err)
	}
	if _, ok, _ := env.store.FindUserByVerifiedEmail(ctx, otherNormalized); !ok {
		t.Fatal("大小写变体邮箱未命中同一规范化记录")
	}
}

// TestStrongAuthByPermissionSensitivity 验证强认证按权限敏感度判定：root、持有
// 高敏感权限（含自定义系统角色）为 true，无害权限为 false，不存在账户报错。
func TestStrongAuthByPermissionSensitivity(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	rootID := env.insertUser("root", true)
	if required, err := env.store.StrongAuthRequired(ctx, rootID); err != nil || !required {
		t.Fatalf("root 强认证 = (%v,%v)，期望 true", required, err)
	}
	userID := env.insertUser("roleuser", false)
	if required, err := env.store.StrongAuthRequired(ctx, userID); err != nil || required {
		t.Fatalf("无角色用户强认证 = (%v,%v)，期望 false", required, err)
	}
	// 自定义系统角色 + 高敏感权限（audit.read）。
	roleID := "role_00000000000000000000000000000101"
	permissionID := "perm_00000000000000000000000000000101"
	nowMS := testBaseTime.UnixMilli()
	if _, err := env.raw.ExecContext(ctx,
		`INSERT INTO permissions(id,scope_id,permission_key,name,description,limits_text,is_builtin,root_only,enabled,created_at_ms,updated_at_ms)
VALUES(?, 'system', 'audit.read', '查看安全记录', '', '', 0, 0, 1, ?, ?)`, permissionID, nowMS, nowMS); err != nil {
		t.Fatalf("插入权限失败: %v", err)
	}
	if _, err := env.raw.ExecContext(ctx,
		`INSERT INTO roles(id,scope_id,role_key,name,description,limits_text,is_builtin,enabled,created_at_ms,updated_at_ms)
VALUES(?, 'system', 'custom_audit', '自定义审计', '', '', 0, 1, ?, ?)`, roleID, nowMS, nowMS); err != nil {
		t.Fatalf("插入角色失败: %v", err)
	}
	if _, err := env.raw.ExecContext(ctx,
		`INSERT INTO role_permissions(role_id,permission_id,scope_id) VALUES(?,?,'system')`, roleID, permissionID); err != nil {
		t.Fatalf("插入角色权限失败: %v", err)
	}
	if _, err := env.raw.ExecContext(ctx,
		`INSERT INTO user_roles(user_id,role_id,scope_id,data_scope_json,assigned_by,created_at_ms)
VALUES(?,?,'system','{}','test',?)`, userID, roleID, nowMS); err != nil {
		t.Fatalf("插入角色分配失败: %v", err)
	}
	if required, err := env.store.StrongAuthRequired(ctx, userID); err != nil || !required {
		t.Fatalf("自定义高敏感角色强认证 = (%v,%v)，期望 true", required, err)
	}
	// 停用角色后不再要求。
	if _, err := env.raw.ExecContext(ctx, `UPDATE roles SET enabled=0 WHERE id=?`, roleID); err != nil {
		t.Fatalf("停用角色失败: %v", err)
	}
	if required, err := env.store.StrongAuthRequired(ctx, userID); err != nil || required {
		t.Fatalf("停用角色后强认证 = (%v,%v)，期望 false", required, err)
	}
	if _, err := env.store.StrongAuthRequired(ctx, "usr_00000000000000000000000000000099"); err == nil {
		t.Fatal("不存在的账户未返回存储错误")
	}
}
