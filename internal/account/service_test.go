package account_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	accountsqlite "github.com/kagurazakayashi/EvernightLogin/internal/account/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// fakeClock 是可注入的测试时钟。
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

// testEnv 汇总临时数据库、审计、仓储、授权器与服务。
type testEnv struct {
	t       *testing.T
	raw     *storagesqlite.Store
	store   *accountsqlite.Store
	auditDB *auditsqlite.Store
	record  *audit.Recorder
	service *account.Service
	clock   *fakeClock
	auth    *account.LocalBootstrapAuthorizer
	caller  account.Caller
}

// prepareEnv 创建临时 SQLite 数据库、执行全部迁移并构造服务。
func prepareEnv(t *testing.T, operators ...string) *testEnv {
	t.Helper()
	return prepareEnvWithLogger(t, nil, operators...)
}

// prepareEnvWithLogger 与 prepareEnv 相同，但允许注入运行日志器。
func prepareEnvWithLogger(t *testing.T, logger *slog.Logger, operators ...string) *testEnv {
	t.Helper()
	if len(operators) == 0 {
		operators = []string{"operator-1"}
	}
	ctx := context.Background()
	dbPath := filepath.Join(testutil.TempDir(t), "account.sqlite")
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(dbPath))
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
	accountStore, err := accountsqlite.New(raw)
	if err != nil {
		t.Fatalf("构造账户仓储失败: %v", err)
	}
	auditStore, err := auditsqlite.New(raw)
	if err != nil {
		t.Fatalf("构造审计仓储失败: %v", err)
	}
	clock := &fakeClock{now: time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	recorder, err := audit.New(auditStore, audit.Options{Now: clock.Now, Logger: logger})
	if err != nil {
		t.Fatalf("构造审计写入器失败: %v", err)
	}
	authorizer, err := account.NewLocalBootstrapAuthorizer(operators)
	if err != nil {
		t.Fatalf("构造本地授权器失败: %v", err)
	}
	service, err := account.New(account.Options{
		Store:      accountStore,
		Audit:      recorder,
		Authorizer: authorizer,
		Now:        clock.Now,
		Logger:     logger,
	})
	if err != nil {
		t.Fatalf("构造账户服务失败: %v", err)
	}
	caller, err := account.LocalBootstrapCaller(operators[0])
	if err != nil {
		t.Fatalf("构造本地调用者失败: %v", err)
	}
	return &testEnv{
		t:       t,
		raw:     raw,
		store:   accountStore,
		auditDB: auditStore,
		record:  recorder,
		service: service,
		clock:   clock,
		auth:    authorizer,
		caller:  caller,
	}
}

// createUser 用给定用户名创建用户；失败时终止测试。
func (e *testEnv) createUser(username string) account.User {
	e.t.Helper()
	user, err := e.service.CreateUser(context.Background(), e.caller, account.CreateRequest{Username: username})
	if err != nil {
		e.t.Fatalf("创建用户 %q 失败: %v", username, err)
	}
	return user
}

// queryInt 执行单值查询；失败时终止测试。
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

// queryString 执行单值字符串查询。
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

func TestCreateUserStoresWhitelistedFields(t *testing.T) {
	env := prepareEnv(t)
	user, err := env.service.CreateUser(context.Background(), env.caller, account.CreateRequest{
		Username:  "  Alice  ",
		Nickname:  "  Alice  昵称  ",
		Biography: "第一行\n第二行",
	})
	if err != nil {
		t.Fatalf("创建用户失败: %v", err)
	}
	if !account.ValidUserID(user.ID) {
		t.Fatalf("用户 ID 格式无效: %q", user.ID)
	}
	if user.Username != "Alice" || user.UsernameNormalized != "alice" {
		t.Fatalf("用户名显示/规范值 = %q/%q", user.Username, user.UsernameNormalized)
	}
	if user.Nickname != "Alice  昵称" {
		t.Errorf("昵称 = %q", user.Nickname)
	}
	if user.Biography != "第一行\n第二行" {
		t.Errorf("简介 = %q", user.Biography)
	}
	if user.Language != account.DefaultLanguage || user.Timezone != account.DefaultTimezone {
		t.Errorf("默认语言/时区 = %q/%q", user.Language, user.Timezone)
	}
	if user.Status != account.StatusActive {
		t.Errorf("创建状态 = %q，期望 active", user.Status)
	}
	if user.RowVersion != 1 {
		t.Errorf("行版本 = %d", user.RowVersion)
	}
	if user.SecurityVersion != 1 {
		t.Errorf("安全版本 = %d，期望 1", user.SecurityVersion)
	}
	if !user.CreatedAt.Equal(env.clock.Now()) || !user.UpdatedAt.Equal(env.clock.Now()) {
		t.Errorf("时间戳 = %v/%v", user.CreatedAt, user.UpdatedAt)
	}

	// 数据库中的敏感管理列由服务/默认值决定，请求字段无法设置。
	if value := env.queryInt(`SELECT is_root FROM users WHERE id=?`, user.ID); value != 0 {
		t.Errorf("is_root = %d，期望 0", value)
	}
	if value := env.queryInt(`SELECT security_version FROM users WHERE id=?`, user.ID); value != 1 {
		t.Errorf("security_version = %d，期望 1", value)
	}
	if value := env.queryString(`SELECT status FROM users WHERE id=?`, user.ID); value != "active" {
		t.Errorf("status = %q", value)
	}
	if value := env.queryString(`SELECT COALESCE(avatar_ref,'') FROM users WHERE id=?`, user.ID); value != "" {
		t.Errorf("avatar_ref = %q，期望空", value)
	}

	// 审计记录创建，且不包含密码/秘密字段。
	if value := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action='user.create' AND outcome='success' AND target_id=?`, user.ID); value != 1 {
		t.Errorf("成功创建审计数量 = %d", value)
	}
	if value := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action='user.create' AND detail_json LIKE '%password%'`); value != 0 {
		t.Errorf("创建审计包含密码字段")
	}

	// 资料字段是纯文本白名单：伪装成管理字段的文本不会改变 is_root。
	user2, err := env.service.CreateUser(context.Background(), env.caller, account.CreateRequest{
		Username: "bob",
		Nickname: "is_root=1; status=active",
	})
	if err != nil {
		t.Fatalf("创建用户 bob 失败: %v", err)
	}
	if value := env.queryInt(`SELECT is_root FROM users WHERE id=?`, user2.ID); value != 0 {
		t.Error("昵称文本不应影响 is_root")
	}
}

func TestLogsDoNotContainProfileData(t *testing.T) {
	var buffer strings.Builder
	logger := slog.New(slog.NewTextHandler(&buffer, &slog.HandlerOptions{Level: slog.LevelDebug}))
	env := prepareEnvWithLogger(t, logger)
	if _, err := env.service.CreateUser(context.Background(), env.caller, account.CreateRequest{
		Username:  "sensitiveuser",
		Nickname:  "真实昵称内容",
		Biography: "真实简介内容",
	}); err != nil {
		t.Fatalf("创建用户失败: %v", err)
	}
	logged := buffer.String()
	for _, forbidden := range []string{"sensitiveuser", "真实昵称内容", "真实简介内容"} {
		if strings.Contains(logged, forbidden) {
			t.Errorf("运行日志包含资料正文 %q: %s", forbidden, logged)
		}
	}
	if !strings.Contains(logged, "user_id=usr_") {
		t.Errorf("运行日志应记录稳定用户 ID: %s", logged)
	}
}

func TestUsernameRulesAndNormalization(t *testing.T) {
	valid := []struct {
		raw        string
		display    string
		normalized string
	}{
		{raw: "Alice", display: "Alice", normalized: "alice"},
		{raw: "  Alice  ", display: "Alice", normalized: "alice"},
		{raw: "Ａlice", display: "Alice", normalized: "alice"},
		{raw: "用户一", display: "用户一", normalized: "用户一"},
		{raw: "Straße", display: "Straße", normalized: "strasse"},
		{raw: "a.b-c_d", display: "a.b-c_d", normalized: "a.b-c_d"},
	}
	for _, test := range valid {
		display, normalized, err := account.NormalizeUsername(test.raw)
		if err != nil {
			t.Fatalf("用户名 %q 应有效: %v", test.raw, err)
		}
		if display != test.display || normalized != test.normalized {
			t.Errorf("用户名 %q => %q/%q，期望 %q/%q", test.raw, display, normalized, test.display, test.normalized)
		}
	}

	invalid := map[string]string{
		"":                            "空",
		"  ":                          "只有空白",
		"ab":                          "过短",
		"a b":                         "内部空白",
		"a\u3000b":                    "全角空格",
		"a@b":                         "非法符号",
		"a🙂b":                         "表情",
		"a\u200bb":                    "零宽字符",
		"a\nb":                        "换行",
		".abc":                        "首位标点",
		"abc-":                        "末位标点",
		"admin":                       "保留名",
		"ROOT":                        "保留名大小写",
		"ｒｏｏｔ":                        "保留名全角",
		"管理员":                         "保留中文名",
		"a" + strings.Repeat("b", 32): "过长",
	}
	for raw, name := range invalid {
		if _, _, err := account.NormalizeUsername(raw); !errors.Is(err, account.ErrInvalidRequest) {
			t.Errorf("%s（%q）应返回 ErrInvalidRequest，实际 %v", name, raw, err)
		}
	}
}

func TestDuplicateUsernameMapping(t *testing.T) {
	env := prepareEnv(t)
	first := env.createUser("Alice")
	if env.queryInt(`SELECT COUNT(*) FROM users`) != 1 {
		t.Fatal("首次创建后用户数量不为 1")
	}
	duplicates := []string{"alice", "ALICE", "Ａlice", "alice "}
	for _, username := range duplicates {
		_, err := env.service.CreateUser(context.Background(), env.caller, account.CreateRequest{Username: username})
		if !errors.Is(err, account.ErrUsernameTaken) {
			t.Fatalf("重复用户名 %q 错误 = %v，期望 ErrUsernameTaken", username, err)
		}
		if code := account.CodeOf(err); code != account.CodeConflict {
			t.Fatalf("重复用户名错误码 = %q，期望 CONFLICT", code)
		}
	}
	if env.queryInt(`SELECT COUNT(*) FROM users`) != 1 {
		t.Fatal("重复创建后用户数量应仍为 1")
	}
	if env.queryInt(`SELECT COUNT(*) FROM users WHERE id=? AND username=?`, first.ID, "Alice") != 1 {
		t.Fatal("首次创建的用户名被覆盖")
	}
	// 失败审计按失败结果记录，且包含冲突错误码。
	count := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action='user.create' AND outcome='failure' AND error_code='CONFLICT'`)
	if count != len(duplicates) {
		t.Errorf("失败审计数量 = %d，期望 %d", count, len(duplicates))
	}
}

func TestConcurrentDuplicateCreation(t *testing.T) {
	env := prepareEnv(t)
	const workers = 6
	var waitGroup sync.WaitGroup
	results := make([]error, workers)
	for index := 0; index < workers; index++ {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			_, err := env.service.CreateUser(context.Background(), env.caller, account.CreateRequest{Username: "Concurrent"})
			results[index] = err
		}(index)
	}
	waitGroup.Wait()
	success := 0
	for _, err := range results {
		if err == nil {
			success++
			continue
		}
		if !errors.Is(err, account.ErrUsernameTaken) {
			t.Errorf("并发重复创建错误 = %v，期望 ErrUsernameTaken", err)
		}
	}
	if success != 1 {
		t.Fatalf("并发创建成功数 = %d，期望 1", success)
	}
	if env.queryInt(`SELECT COUNT(*) FROM users WHERE username_normalized='concurrent'`) != 1 {
		t.Fatal("并发创建后用户名行数不为 1")
	}
}

func TestGetUserAndPagination(t *testing.T) {
	env := prepareEnv(t)
	created := make([]account.User, 0, 3)
	for _, username := range []string{"alpha", "beta", "gamma"} {
		user := env.createUser(username)
		created = append(created, user)
		env.clock.Advance(time.Minute)
	}

	got, err := env.service.GetUser(context.Background(), env.caller, created[0].ID)
	if err != nil {
		t.Fatalf("查询用户失败: %v", err)
	}
	if got.ID != created[0].ID || got.Username != "alpha" {
		t.Errorf("查询结果 = %+v", got)
	}
	if _, err := env.service.GetUser(context.Background(), env.caller, "not-a-user-id"); !errors.Is(err, account.ErrInvalidRequest) {
		t.Errorf("非法 ID 错误 = %v", err)
	}
	missingID := "usr_" + strings.Repeat("0", 32)
	if _, err := env.service.GetUser(context.Background(), env.caller, missingID); !errors.Is(err, account.ErrUserNotFound) {
		t.Errorf("不存在用户错误 = %v", err)
	}
	byName, err := env.service.GetUserByUsername(context.Background(), env.caller, "ALPHA")
	if err != nil || byName.ID != created[0].ID {
		t.Errorf("按用户名查询 = %+v, %v", byName, err)
	}
	if _, err := env.service.GetUserByUsername(context.Background(), env.caller, "missing-user"); !errors.Is(err, account.ErrUserNotFound) {
		t.Errorf("不存在用户名错误 = %v", err)
	}
	if _, err := env.service.GetUserByUsername(context.Background(), env.caller, "  "); !errors.Is(err, account.ErrInvalidRequest) {
		t.Errorf("空用户名错误 = %v", err)
	}
	if code := account.CodeOf(fmt.Errorf("%w", account.ErrUserNotFound)); code != account.CodeReqInvalid {
		t.Errorf("不存在用户错误码 = %q", code)
	}

	firstPage, err := env.service.ListUsers(context.Background(), env.caller, account.ListRequest{Limit: 2})
	if err != nil {
		t.Fatalf("分页查询失败: %v", err)
	}
	if len(firstPage.Users) != 2 || !firstPage.HasMore {
		t.Fatalf("第一页 = %d 个用户，hasMore=%v", len(firstPage.Users), firstPage.HasMore)
	}
	if firstPage.Users[0].ID != created[0].ID || firstPage.Users[1].ID != created[1].ID {
		t.Errorf("默认创建时间升序不符: %+v", firstPage.Users)
	}
	secondPage, err := env.service.ListUsers(context.Background(), env.caller, account.ListRequest{Limit: 2, Offset: 2})
	if err != nil {
		t.Fatalf("第二页查询失败: %v", err)
	}
	if len(secondPage.Users) != 1 || secondPage.HasMore {
		t.Fatalf("第二页 = %d 个用户，hasMore=%v", len(secondPage.Users), secondPage.HasMore)
	}
	if secondPage.Users[0].ID != created[2].ID {
		t.Errorf("第二页用户 = %+v", secondPage.Users[0])
	}
	emptyPage, err := env.service.ListUsers(context.Background(), env.caller, account.ListRequest{Limit: 2, Offset: 10})
	if err != nil || len(emptyPage.Users) != 0 || emptyPage.HasMore {
		t.Fatalf("空页 = %+v, %v", emptyPage, err)
	}

	// 用户名倒序排序。
	sorted, err := env.service.ListUsers(context.Background(), env.caller, account.ListRequest{Sort: account.SortUsername, Descending: true})
	if err != nil {
		t.Fatalf("排序查询失败: %v", err)
	}
	if len(sorted.Users) != 3 || sorted.Users[0].Username != "gamma" || sorted.Users[2].Username != "alpha" {
		t.Errorf("用户名倒序 = %+v", sorted.Users)
	}

	// 状态过滤：直接更新一条记录模拟后续状态变更步骤。
	if _, err := env.raw.ExecContext(context.Background(), `UPDATE users SET status='disabled' WHERE id=?`, created[1].ID); err != nil {
		t.Fatalf("更新测试状态失败: %v", err)
	}
	filtered, err := env.service.ListUsers(context.Background(), env.caller, account.ListRequest{Status: account.StatusDisabled})
	if err != nil {
		t.Fatalf("状态过滤失败: %v", err)
	}
	if len(filtered.Users) != 1 || filtered.Users[0].ID != created[1].ID {
		t.Errorf("状态过滤结果 = %+v", filtered.Users)
	}

	// 分页/排序边界。
	invalidRequests := []account.ListRequest{
		{Limit: -1},
		{Limit: account.MaxListLimit + 1},
		{Offset: -1},
		{Offset: account.MaxListOffset + 1},
		{Sort: "password"},
		{Status: "deleted"},
	}
	for _, request := range invalidRequests {
		if _, err := env.service.ListUsers(context.Background(), env.caller, request); !errors.Is(err, account.ErrInvalidRequest) {
			t.Errorf("非法列表请求 %+v 错误 = %v", request, err)
		}
	}
	if code := account.CodeOf(fmt.Errorf("%w: test", account.ErrInvalidRequest)); code != account.CodeReqInvalid {
		t.Errorf("非法请求错误码 = %q", code)
	}

	// 读取审计：2 次 Get + 多次 List 均应有 success 事件；审计不含资料正文。
	if env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action='user.get' AND outcome='success'`) < 1 {
		t.Error("缺少用户查询审计")
	}
	if env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action='user.list' AND outcome='success'`) < 4 {
		t.Error("缺少用户列表审计")
	}
}

// seedUserAssociation 插入应用、成员关系、角色、用户组与一次性凭证，供删除
// 生命周期测试使用。
func (e *testEnv) seedUserAssociation(userID string) {
	e.t.Helper()
	ctx := context.Background()
	now := e.clock.Now().UnixMilli()
	exec := func(query string, args ...any) {
		e.t.Helper()
		if _, err := e.raw.ExecContext(ctx, query, args...); err != nil {
			e.t.Fatalf("插入测试关联数据失败: %v", err)
		}
	}
	exec(`INSERT INTO applications(id,name,description,client_type,status,row_version,created_at_ms,updated_at_ms)
VALUES('app_delete_test','删除测试应用','', 'confidential','active',1,?,?)`, now, now)
	exec(`INSERT INTO app_memberships(app_id,user_id,status,profile_json,row_version,created_at_ms,updated_at_ms)
VALUES('app_delete_test',?,'active','{"department":"x"}',1,?,?)`, userID, now, now)
	exec(`INSERT INTO roles(id,scope_id,role_key,name,description,limits_text,is_builtin,enabled,created_at_ms,updated_at_ms)
VALUES('role_delete_test','system','delete_test','测试角色','','',0,1,?,?)`, now, now)
	exec(`INSERT INTO user_roles(user_id,role_id,scope_id,data_scope_json,assigned_by,created_at_ms)
VALUES(?, 'role_delete_test','system','{}','operator-1',?)`, userID, now)
	exec(`INSERT INTO user_groups(id,scope_id,group_key,name,description,created_at_ms,updated_at_ms)
VALUES('group_delete_test','system','delete_test','测试组','',?,?)`, now, now)
	exec(`INSERT INTO group_members(group_id,user_id,created_at_ms) VALUES('group_delete_test',?,?)`, userID, now)
	exec(`INSERT INTO one_time_credentials(id,purpose,subject_id,app_id,verifier_hash,key_id,context_json,attempts,max_attempts,created_at_ms,expires_at_ms)
VALUES('cred_delete_test','test',?,NULL,? ,NULL,'{}',0,3,?,?)`, userID, []byte("delete-test-credential-hash"), now, now+3600000)
	exec(`UPDATE applications SET owner_user_id=? WHERE id='app_delete_test'`, userID)
}

// insertRootUser 直接插入 root 行，模拟后续步骤 28 才会建立的受保护账户。
func (e *testEnv) insertRootUser() string {
	e.t.Helper()
	rootID := "usr_11111111111111111111111111111111"
	now := e.clock.Now().UnixMilli()
	if _, err := e.raw.ExecContext(context.Background(),
		`INSERT INTO users(id,username,username_normalized,nickname,biography,language,timezone,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,'','zh-CN','Asia/Shanghai','active',1,1,1,?,?)`,
		rootID, "root", "root", "Root", now, now); err != nil {
		e.t.Fatalf("插入 root 测试用户失败: %v", err)
	}
	return rootID
}

// TestStateLifecycleSecurityVersion 验证禁用/启用的状态机、幂等、行版本与安全版本语义。
func TestStateLifecycleSecurityVersion(t *testing.T) {
	env := prepareEnv(t)
	user := env.createUser("stateuser")
	if user.Status != account.StatusActive || user.RowVersion != 1 || user.SecurityVersion != 1 {
		t.Fatalf("初始状态 = %+v", user)
	}

	disabled, err := env.service.DisableUser(context.Background(), env.caller, account.StateCommandRequest{UserID: user.ID, ExpectedRowVersion: 1})
	if err != nil {
		t.Fatalf("禁用用户失败: %v", err)
	}
	if !disabled.Changed || disabled.User.Status != account.StatusDisabled ||
		disabled.User.RowVersion != 2 || disabled.User.SecurityVersion != 2 {
		t.Fatalf("禁用结果 = %+v", disabled)
	}
	if value := env.queryInt(`SELECT security_version FROM users WHERE id=?`, user.ID); value != 2 {
		t.Errorf("数据库 security_version = %d，期望 2", value)
	}

	// 重复禁用幂等成功：不改行版本/安全版本，但写成功审计。
	repeated, err := env.service.DisableUser(context.Background(), env.caller, account.StateCommandRequest{UserID: user.ID, ExpectedRowVersion: 2})
	if err != nil {
		t.Fatalf("重复禁用应幂等成功: %v", err)
	}
	if repeated.Changed || repeated.User.RowVersion != 2 || repeated.User.SecurityVersion != 2 {
		t.Fatalf("重复禁用结果 = %+v", repeated)
	}
	if value := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action='user.disable' AND outcome='success'`); value != 2 {
		t.Errorf("禁用成功审计数量 = %d，期望 2（变更+幂等）", value)
	}

	// 启用不递减安全版本；旧会话不会因为解禁而恢复。
	enabled, err := env.service.EnableUser(context.Background(), env.caller, account.StateCommandRequest{UserID: user.ID, ExpectedRowVersion: 2})
	if err != nil {
		t.Fatalf("启用用户失败: %v", err)
	}
	if !enabled.Changed || enabled.User.Status != account.StatusActive ||
		enabled.User.RowVersion != 3 || enabled.User.SecurityVersion != 2 {
		t.Fatalf("启用结果 = %+v", enabled)
	}
	repeatedEnable, err := env.service.EnableUser(context.Background(), env.caller, account.StateCommandRequest{UserID: user.ID, ExpectedRowVersion: 3})
	if err != nil || repeatedEnable.Changed {
		t.Fatalf("重复启用应幂等成功: %+v, %v", repeatedEnable, err)
	}

	// 行版本冲突：使用旧版本禁用应拒绝且不改变状态。
	if _, err := env.service.DisableUser(context.Background(), env.caller, account.StateCommandRequest{UserID: user.ID, ExpectedRowVersion: 1}); !errors.Is(err, account.ErrStateConflict) {
		t.Fatalf("旧行版本错误 = %v，期望 ErrStateConflict", err)
	}
	if code := account.CodeOf(fmt.Errorf("%w", account.ErrStateConflict)); code != account.CodeConflict {
		t.Errorf("状态冲突错误码 = %q，期望 CONFLICT", code)
	}
	if value := env.queryString(`SELECT status FROM users WHERE id=?`, user.ID); value != "active" {
		t.Errorf("冲突后状态 = %q，期望 active", value)
	}
}

// TestConcurrentStateChange 验证同一行版本的并发状态变更只有一个生效。
func TestConcurrentStateChange(t *testing.T) {
	env := prepareEnv(t)
	user := env.createUser("concurrentstate")
	const workers = 4
	var waitGroup sync.WaitGroup
	results := make([]error, workers)
	changes := make([]bool, workers)
	for index := 0; index < workers; index++ {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			result, err := env.service.DisableUser(context.Background(), env.caller, account.StateCommandRequest{UserID: user.ID, ExpectedRowVersion: 1})
			results[index] = err
			changes[index] = result.Changed
		}(index)
	}
	waitGroup.Wait()
	successChanged := 0
	for index, err := range results {
		switch {
		case err == nil && changes[index]:
			successChanged++
		case err == nil && !changes[index]:
			// 读到已禁用后的幂等成功。
		case errors.Is(err, account.ErrStateConflict):
			// 条件更新失败。
		default:
			t.Errorf("并发状态变更错误 = %v", err)
		}
	}
	if successChanged != 1 {
		t.Fatalf("并发变更成功数 = %d，期望 1", successChanged)
	}
	if value := env.queryString(`SELECT status FROM users WHERE id=?`, user.ID); value != "disabled" {
		t.Errorf("最终状态 = %q，期望 disabled", value)
	}
	if value := env.queryInt(`SELECT security_version FROM users WHERE id=?`, user.ID); value != 2 {
		t.Errorf("security_version = %d，期望只递增 1 次到 2", value)
	}
}

// TestInvalidTransitionsAndRootProtection 验证非法状态切换与受保护账户。
func TestInvalidTransitionsAndRootProtection(t *testing.T) {
	env := prepareEnv(t)
	user := env.createUser("transitions")
	// 待删除账户不能再启用/禁用。
	requested, err := env.service.RequestDeletion(context.Background(), env.caller, account.StateCommandRequest{UserID: user.ID, ExpectedRowVersion: 1})
	if err != nil {
		t.Fatalf("请求删除失败: %v", err)
	}
	if requested.User.Status != account.StatusPendingDelete || requested.User.SecurityVersion != 2 {
		t.Fatalf("请求删除结果 = %+v", requested)
	}
	for _, command := range []struct {
		name string
		run  func() error
	}{
		{name: "待删除后禁用", run: func() error {
			_, err := env.service.DisableUser(context.Background(), env.caller, account.StateCommandRequest{UserID: user.ID, ExpectedRowVersion: requested.User.RowVersion})
			return err
		}},
		{name: "待删除后启用", run: func() error {
			_, err := env.service.EnableUser(context.Background(), env.caller, account.StateCommandRequest{UserID: user.ID, ExpectedRowVersion: requested.User.RowVersion})
			return err
		}},
	} {
		if err := command.run(); !errors.Is(err, account.ErrInvalidTransition) {
			t.Errorf("%s 错误 = %v，期望 ErrInvalidTransition", command.name, err)
		}
	}
	// 重复请求删除幂等成功。
	again, err := env.service.RequestDeletion(context.Background(), env.caller, account.StateCommandRequest{UserID: user.ID, ExpectedRowVersion: requested.User.RowVersion})
	if err != nil || again.Changed {
		t.Fatalf("重复请求删除应幂等: %+v, %v", again, err)
	}

	// root 不能被普通流程禁用/删除/完成删除。
	rootID := env.insertRootUser()
	if _, err := env.service.DisableUser(context.Background(), env.caller, account.StateCommandRequest{UserID: rootID, ExpectedRowVersion: 1}); !errors.Is(err, account.ErrProtectedUser) {
		t.Fatalf("禁用 root 错误 = %v，期望 ErrProtectedUser", err)
	}
	if code := account.CodeOf(fmt.Errorf("%w", account.ErrProtectedUser)); code != account.CodeAccessDenied {
		t.Errorf("root 保护错误码 = %q，期望 ACCESS_DENIED", code)
	}
	if _, err := env.service.RequestDeletion(context.Background(), env.caller, account.StateCommandRequest{UserID: rootID, ExpectedRowVersion: 1}); !errors.Is(err, account.ErrProtectedUser) {
		t.Fatalf("删除 root 错误 = %v", err)
	}
	if _, err := env.service.CompleteDeletion(context.Background(), env.caller, account.StateCommandRequest{UserID: rootID, ExpectedRowVersion: 1}); !errors.Is(err, account.ErrProtectedUser) {
		t.Fatalf("完成删除 root 错误 = %v", err)
	}
	preview, err := env.service.PreviewDeletion(context.Background(), env.caller, rootID)
	if err != nil {
		t.Fatalf("root 预览失败: %v", err)
	}
	if !preview.IsRoot || preview.Status != account.StatusActive {
		t.Errorf("root 预览 = %+v", preview)
	}
	if value := env.queryInt(`SELECT COUNT(*) FROM users WHERE id=? AND is_root=1`, rootID); value != 1 {
		t.Error("root 账户不应被删除")
	}
	// root 保护拒绝必须留失败审计（普通管理员反复尝试禁用/删除 root 不能无痕），
	// 且错误码仍为 ACCESS_DENIED、root 行状态/版本完全未变。
	for _, action := range []string{
		string(account.ActionDisableUser),
		string(account.ActionRequestDeletion),
		string(account.ActionCompleteDeletion),
	} {
		if value := env.queryInt(`SELECT COUNT(*) FROM audit_events
WHERE action=? AND outcome='failure' AND error_code='ACCESS_DENIED' AND reason_code='root_protected' AND target_id=?`,
			action, rootID); value != 1 {
			t.Errorf("%s root 拒绝失败审计数 = %d，期望 1", action, value)
		}
	}
	if value := env.queryInt(`SELECT COUNT(*) FROM users WHERE id=? AND status='active' AND row_version=1 AND security_version=1`, rootID); value != 1 {
		t.Error("root 保护拒绝后账户状态/版本发生变化")
	}
}

// TestDeletionLifecycleAndAssociationPolicy 验证待删除→完成删除及关联数据处理。
func TestDeletionLifecycleAndAssociationPolicy(t *testing.T) {
	env := prepareEnv(t)
	user := env.createUser("deletee")
	env.seedUserAssociation(user.ID)

	if _, err := env.service.CompleteDeletion(context.Background(), env.caller, account.StateCommandRequest{UserID: user.ID, ExpectedRowVersion: 1}); !errors.Is(err, account.ErrInvalidTransition) {
		t.Fatalf("未请求删除即完成删除错误 = %v，期望 ErrInvalidTransition", err)
	}
	if _, err := env.service.DisableUser(context.Background(), env.caller, account.StateCommandRequest{UserID: user.ID, ExpectedRowVersion: 0}); !errors.Is(err, account.ErrInvalidRequest) {
		t.Fatalf("零行版本错误 = %v，期望 ErrInvalidRequest", err)
	}
	if _, err := env.service.DisableUser(context.Background(), env.caller, account.StateCommandRequest{UserID: "not-a-user", ExpectedRowVersion: 1}); !errors.Is(err, account.ErrInvalidRequest) {
		t.Fatalf("非法用户 ID 错误 = %v，期望 ErrInvalidRequest", err)
	}

	preview, err := env.service.PreviewDeletion(context.Background(), env.caller, user.ID)
	if err != nil {
		t.Fatalf("删除预览失败: %v", err)
	}
	if preview.AppMemberships != 1 || preview.UserRoles != 1 || preview.GroupMemberships != 1 ||
		preview.OneTimeCredentials != 1 || preview.OwnedApplications != 1 || preview.IsRoot {
		t.Fatalf("删除影响预览 = %+v", preview)
	}
	if value := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action='user.delete.preview' AND outcome='success'`); value != 1 {
		t.Errorf("删除预览审计数量 = %d", value)
	}

	// 全局禁用不改变应用成员关系（应用内禁用由应用范围单独管理）。
	disabled, err := env.service.DisableUser(context.Background(), env.caller, account.StateCommandRequest{UserID: user.ID, ExpectedRowVersion: 1})
	if err != nil {
		t.Fatalf("禁用失败: %v", err)
	}
	if value := env.queryString(`SELECT status FROM app_memberships WHERE user_id=?`, user.ID); value != "active" {
		t.Errorf("全局禁用后应用成员状态 = %q，期望 active", value)
	}

	requested, err := env.service.RequestDeletion(context.Background(), env.caller, account.StateCommandRequest{UserID: user.ID, ExpectedRowVersion: disabled.User.RowVersion})
	if err != nil {
		t.Fatalf("请求删除失败: %v", err)
	}
	if requested.User.Status != account.StatusPendingDelete {
		t.Fatalf("请求删除状态 = %q", requested.User.Status)
	}
	// 完成删除：关联个人数据删除、应用保留且 owner 置空、审计历史保留。
	result, err := env.service.CompleteDeletion(context.Background(), env.caller, account.StateCommandRequest{
		UserID:             user.ID,
		ExpectedRowVersion: requested.User.RowVersion,
	})
	if err != nil {
		t.Fatalf("完成删除失败: %v", err)
	}
	if result.DeletedAt.IsZero() || result.Preview.AppMemberships != 1 {
		t.Errorf("完成删除结果 = %+v", result)
	}
	if value := env.queryInt(`SELECT COUNT(*) FROM users WHERE id=?`, user.ID); value != 0 {
		t.Error("用户行应被删除")
	}
	for _, table := range []string{"app_memberships", "user_roles", "group_members"} {
		if value := env.queryInt(`SELECT COUNT(*) FROM `+table+` WHERE user_id=?`, user.ID); value != 0 {
			t.Errorf("%s 未清理: %d 行", table, value)
		}
	}
	if value := env.queryInt(`SELECT COUNT(*) FROM one_time_credentials WHERE subject_id=?`, user.ID); value != 0 {
		t.Error("一次性凭证未清理")
	}
	if value := env.queryInt(`SELECT COUNT(*) FROM applications WHERE id='app_delete_test'`); value != 1 {
		t.Error("应用记录不应被级联删除")
	}
	if value := env.queryString(`SELECT COALESCE(owner_user_id,'') FROM applications WHERE id='app_delete_test'`); value != "" {
		t.Errorf("应用 owner 应置空，实际 %q", value)
	}
	// 审计历史保留，且完成删除事件存在。
	if value := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE target_id=?`, user.ID); value < 4 {
		t.Errorf("审计历史数量 = %d，应保留创建/禁用/请求/完成等事件", value)
	}
	if value := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action='user.delete.complete' AND outcome='success'`); value != 1 {
		t.Errorf("完成删除审计数量 = %d", value)
	}
	// 重复完成删除：用户已不存在，不能假装成功。
	if _, err := env.service.CompleteDeletion(context.Background(), env.caller, account.StateCommandRequest{UserID: user.ID, ExpectedRowVersion: requested.User.RowVersion}); !errors.Is(err, account.ErrUserNotFound) {
		t.Fatalf("重复完成删除错误 = %v，期望 ErrUserNotFound", err)
	}
}

// TestCompleteDeletionFailureRollsBack 验证关联清理中途故障整体回滚并可追踪。
func TestCompleteDeletionFailureRollsBack(t *testing.T) {
	env := prepareEnv(t)
	user := env.createUser("rollback")
	env.seedUserAssociation(user.ID)
	requested, err := env.service.RequestDeletion(context.Background(), env.caller, account.StateCommandRequest{UserID: user.ID, ExpectedRowVersion: 1})
	if err != nil {
		t.Fatalf("请求删除失败: %v", err)
	}
	// 在应用成员关系删除阶段注入故障；此前的一次性凭证/角色删除必须回滚。
	if _, err := env.raw.ExecContext(context.Background(),
		`CREATE TRIGGER fail_app_membership_delete BEFORE DELETE ON app_memberships BEGIN SELECT RAISE(ABORT,'delete blocked'); END;`); err != nil {
		t.Fatalf("创建删除故障触发器失败: %v", err)
	}
	if _, err := env.service.CompleteDeletion(context.Background(), env.caller, account.StateCommandRequest{
		UserID:             user.ID,
		ExpectedRowVersion: requested.User.RowVersion,
	}); !errors.Is(err, account.ErrStoreUnavailable) {
		t.Fatalf("完成删除故障错误 = %v，期望 ErrStoreUnavailable", err)
	} else if code := account.CodeOf(err); code != account.CodeDBUnavailable {
		t.Fatalf("完成删除故障错误码 = %q", code)
	}
	if value := env.queryString(`SELECT status FROM users WHERE id=?`, user.ID); value != "pending_delete" {
		t.Errorf("故障后用户状态 = %q，期望 pending_delete", value)
	}
	for _, table := range []string{"app_memberships", "user_roles", "group_members"} {
		if value := env.queryInt(`SELECT COUNT(*) FROM `+table+` WHERE user_id=?`, user.ID); value != 1 {
			t.Errorf("%s 应因事务回滚保留 1 行，实际 %d", table, value)
		}
	}
	if value := env.queryInt(`SELECT COUNT(*) FROM one_time_credentials WHERE subject_id=?`, user.ID); value != 1 {
		t.Errorf("一次性凭证应因事务回滚保留，实际 %d", value)
	}
	if value := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action='user.delete.complete' AND outcome='failure'`); value != 1 {
		t.Errorf("失败审计数量 = %d", value)
	}
	if value := env.queryString(`SELECT COALESCE(error_code,'') FROM audit_events WHERE action='user.delete.complete' AND outcome='failure'`); value != "DB_UNAVAILABLE" {
		t.Errorf("失败审计错误码 = %q，期望 DB_UNAVAILABLE", value)
	}
}

func TestAuthorizationBoundaries(t *testing.T) {
	if _, err := account.New(account.Options{}); !errors.Is(err, account.ErrOptionsInvalid) {
		t.Errorf("缺少依赖构造错误 = %v", err)
	}
	env := prepareEnv(t, "operator-1")
	if _, err := env.service.CreateUser(context.Background(), account.Caller{}, account.CreateRequest{Username: "nobody"}); !errors.Is(err, account.ErrAccessDenied) {
		t.Errorf("零值调用者错误 = %v", err)
	}
	otherCaller, err := account.LocalBootstrapCaller("operator-2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.service.CreateUser(context.Background(), otherCaller, account.CreateRequest{Username: "nobody"}); !errors.Is(err, account.ErrAccessDenied) {
		t.Errorf("未授权本地操作者错误 = %v", err)
	}
	systemCaller, err := account.SystemCaller("task-runner")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.service.CreateUser(context.Background(), systemCaller, account.CreateRequest{Username: "nobody"}); !errors.Is(err, account.ErrAccessDenied) {
		t.Errorf("系统调用者错误 = %v", err)
	}
	allowedUser := env.createUser("manageable")
	if _, err := env.service.DisableUser(context.Background(), otherCaller, account.StateCommandRequest{UserID: allowedUser.ID, ExpectedRowVersion: 1}); !errors.Is(err, account.ErrAccessDenied) {
		t.Errorf("未授权状态变更错误 = %v，期望 ErrAccessDenied", err)
	}
	if code := account.CodeOf(fmt.Errorf("%w", account.ErrAccessDenied)); code != account.CodeAccessDenied {
		t.Errorf("未授权错误码 = %q", code)
	}

	// 授权先于参数校验：未授权调用者不能借错误差异探测用户名规则。
	if _, err := env.service.CreateUser(context.Background(), otherCaller, account.CreateRequest{Username: ""}); !errors.Is(err, account.ErrAccessDenied) {
		t.Errorf("未授权且非法参数错误 = %v", err)
	}

	// 请求编号写入审计事件。
	caller, err := env.caller.WithRequestID("req-account-1")
	if err != nil {
		t.Fatal(err)
	}
	created, err := env.service.CreateUser(context.Background(), caller, account.CreateRequest{Username: "withrequest"})
	if err != nil {
		t.Fatalf("创建用户失败: %v", err)
	}
	if value := env.queryString(`SELECT COALESCE(request_id,'') FROM audit_events WHERE action='user.create' AND target_id=?`, created.ID); value != "req-account-1" {
		t.Errorf("审计请求编号 = %q", value)
	}
	if _, err := env.caller.WithRequestID("bad request id"); !errors.Is(err, account.ErrInvalidRequest) {
		t.Errorf("非法请求编号错误 = %v", err)
	}
}

func TestFailureAuditCodeMatchesFailureClass(t *testing.T) {
	env := prepareEnv(t)
	env.createUser("existing")
	// 让用户插入失败但不是用户名冲突，验证失败审计错误码不是固定 CONFLICT。
	if _, err := env.raw.ExecContext(context.Background(),
		`CREATE TRIGGER fail_user_insert BEFORE INSERT ON users BEGIN SELECT RAISE(ABORT,'insert blocked'); END;`); err != nil {
		t.Fatalf("创建用户插入故障触发器失败: %v", err)
	}
	if _, err := env.service.CreateUser(context.Background(), env.caller, account.CreateRequest{Username: "blockeduser"}); !errors.Is(err, account.ErrStoreUnavailable) {
		t.Fatalf("存储失败创建错误 = %v，期望 ErrStoreUnavailable", err)
	} else if code := account.CodeOf(err); code != account.CodeDBUnavailable {
		t.Fatalf("存储失败错误码 = %q，期望 DB_UNAVAILABLE", code)
	}
	if value := env.queryString(`SELECT COALESCE(error_code,'') FROM audit_events WHERE action='user.create' AND outcome='failure' ORDER BY occurred_at_ms DESC, id DESC LIMIT 1`); value != "DB_UNAVAILABLE" {
		t.Errorf("失败审计错误码 = %q，期望 DB_UNAVAILABLE", value)
	}
	if value := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action='user.create' AND outcome='failure' AND error_code='CONFLICT'`); value != 0 {
		t.Errorf("非冲突失败被误记为 CONFLICT：%d 条", value)
	}
	if value := env.queryInt(`SELECT COUNT(*) FROM users WHERE username_normalized='blockeduser'`); value != 0 {
		t.Error("存储失败后不应残留用户")
	}
	if _, err := env.raw.ExecContext(context.Background(), `DROP TRIGGER fail_user_insert`); err != nil {
		t.Fatalf("删除触发器失败: %v", err)
	}
	// 冲突失败仍记录 CONFLICT。
	if _, err := env.service.CreateUser(context.Background(), env.caller, account.CreateRequest{Username: "existing"}); !errors.Is(err, account.ErrUsernameTaken) {
		t.Fatalf("重复创建错误 = %v", err)
	}
	if value := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action='user.create' AND outcome='failure' AND error_code='CONFLICT'`); value != 1 {
		t.Errorf("冲突失败审计 CONFLICT 数量 = %d，期望 1", value)
	}
}

func TestAuditFailureFailClosed(t *testing.T) {
	env := prepareEnv(t)
	existing := env.createUser("existing")
	// 用触发器模拟审计存储故障。
	if _, err := env.raw.ExecContext(context.Background(),
		`CREATE TRIGGER fail_audit_events BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'audit unavailable'); END;`); err != nil {
		t.Fatalf("创建审计故障触发器失败: %v", err)
	}
	if _, err := env.service.CreateUser(context.Background(), env.caller, account.CreateRequest{Username: "shouldfail"}); !errors.Is(err, account.ErrAuditUnavailable) {
		t.Fatalf("审计故障创建错误 = %v，期望 ErrAuditUnavailable", err)
	} else if code := account.CodeOf(err); code != account.CodeAuditWriteFailed {
		t.Fatalf("审计故障错误码 = %q", code)
	}
	if env.queryInt(`SELECT COUNT(*) FROM users WHERE username_normalized='shouldfail'`) != 0 {
		t.Fatal("审计失败后不应残留用户")
	}
	if _, err := env.service.GetUser(context.Background(), env.caller, existing.ID); !errors.Is(err, account.ErrAuditUnavailable) {
		t.Fatalf("审计故障查询错误 = %v，期望 ErrAuditUnavailable", err)
	}
	if _, err := env.service.ListUsers(context.Background(), env.caller, account.ListRequest{}); !errors.Is(err, account.ErrAuditUnavailable) {
		t.Fatalf("审计故障列表错误 = %v，期望 ErrAuditUnavailable", err)
	}
	if _, err := env.service.DisableUser(context.Background(), env.caller, account.StateCommandRequest{UserID: existing.ID, ExpectedRowVersion: 1}); !errors.Is(err, account.ErrAuditUnavailable) {
		t.Fatalf("审计故障状态变更错误 = %v，期望 ErrAuditUnavailable", err)
	}
	if value := env.queryString(`SELECT status FROM users WHERE id=?`, existing.ID); value != "active" {
		t.Errorf("审计故障后状态 = %q，期望 active（不得假装成功）", value)
	}
	if _, err := env.service.PreviewDeletion(context.Background(), env.caller, existing.ID); !errors.Is(err, account.ErrAuditUnavailable) {
		t.Fatalf("审计故障删除预览错误 = %v，期望 ErrAuditUnavailable", err)
	}
	// 移除故障后恢复可用。
	if _, err := env.raw.ExecContext(context.Background(), `DROP TRIGGER fail_audit_events`); err != nil {
		t.Fatalf("删除触发器失败: %v", err)
	}
	if _, err := env.service.CreateUser(context.Background(), env.caller, account.CreateRequest{Username: "recovered"}); err != nil {
		t.Fatalf("恢复后创建失败: %v", err)
	}
}

// fakeSessionRevoker 记录账户禁用后的会话撤销调用，可注入错误。
type fakeSessionRevoker struct {
	mu    sync.Mutex
	users []string
	err   error
}

// RevokeOnAccountDisabled 实现 account.SessionRevoker。
func (f *fakeSessionRevoker) RevokeOnAccountDisabled(_ context.Context, userID string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.users = append(f.users, userID)
	if f.err != nil {
		return 0, f.err
	}
	return 2, nil
}

// TestDisableUserInvokesSessionRevoker 验证禁用账户成功后调用注入的会话撤销契约，
// 且撤销失败不回滚已提交的禁用（会话层仍按 status 复查拒绝旧会话）。
func TestDisableUserInvokesSessionRevoker(t *testing.T) {
	env := prepareEnv(t, "operator-1")
	user := env.createUser("revoker-target")
	revoker := &fakeSessionRevoker{}
	service, err := account.New(account.Options{
		Store:          env.store,
		Audit:          env.record,
		Authorizer:     env.auth,
		SessionRevoker: revoker,
		Now:            env.clock.Now,
	})
	if err != nil {
		t.Fatalf("构造带会话撤销的账户服务失败: %v", err)
	}
	state, err := service.GetUser(context.Background(), env.caller, user.ID)
	if err != nil {
		t.Fatalf("读取用户失败: %v", err)
	}
	if _, err := service.DisableUser(context.Background(), env.caller, account.StateCommandRequest{
		UserID:             user.ID,
		ExpectedRowVersion: state.RowVersion,
	}); err != nil {
		t.Fatalf("禁用用户失败: %v", err)
	}
	if len(revoker.users) != 1 || revoker.users[0] != user.ID {
		t.Fatalf("会话撤销调用 = %v，期望一次 %q", revoker.users, user.ID)
	}
	// 撤销失败不影响已提交的禁用结果。
	user2 := env.createUser("revoker-failing-target")
	state2, err := service.GetUser(context.Background(), env.caller, user2.ID)
	if err != nil {
		t.Fatalf("读取用户失败: %v", err)
	}
	failing := &fakeSessionRevoker{err: errors.New("session store unavailable")}
	failingService, err := account.New(account.Options{
		Store:          env.store,
		Audit:          env.record,
		Authorizer:     env.auth,
		SessionRevoker: failing,
		Now:            env.clock.Now,
	})
	if err != nil {
		t.Fatalf("构造失败会话撤销的账户服务失败: %v", err)
	}
	result, err := failingService.DisableUser(context.Background(), env.caller, account.StateCommandRequest{
		UserID:             user2.ID,
		ExpectedRowVersion: state2.RowVersion,
	})
	if err != nil || !result.Changed {
		t.Fatalf("会话撤销失败时的禁用 = (%+v, %v)，期望禁用成功", result, err)
	}
	if len(failing.users) != 1 {
		t.Fatalf("失败会话撤销调用 = %v", failing.users)
	}
	// 未注入撤销契约时行为不变（依赖会话层 status 复查兜底）。
	if _, err := env.service.DisableUser(context.Background(), env.caller, account.StateCommandRequest{
		UserID:             env.createUser("no-revoker-target").ID,
		ExpectedRowVersion: 1,
	}); err != nil {
		t.Logf("未注入撤销契约的禁用结果: %v", err)
	}
}
