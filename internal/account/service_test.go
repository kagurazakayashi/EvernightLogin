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
	dbPath := filepath.Join(t.TempDir(), "account.sqlite")
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
	// 移除故障后恢复可用。
	if _, err := env.raw.ExecContext(context.Background(), `DROP TRIGGER fail_audit_events`); err != nil {
		t.Fatalf("删除触发器失败: %v", err)
	}
	if _, err := env.service.CreateUser(context.Background(), env.caller, account.CreateRequest{Username: "recovered"}); err != nil {
		t.Fatalf("恢复后创建失败: %v", err)
	}
}
