package authn_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	authnsqlite "github.com/kagurazakayashi/EvernightLogin/internal/authn/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/bootstrap"
	bootstrapsqlite "github.com/kagurazakayashi/EvernightLogin/internal/bootstrap/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/credential"
	credentialsqlite "github.com/kagurazakayashi/EvernightLogin/internal/credential/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/ratelimit"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const (
	testOperator = "local-admin-1"
	testSystem   = "test-system"
	// testPassword 是满足默认策略的合成强密码。
	testPassword = "Correct-Horse-9-Battery"
)

var testBaseTime = time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)

// fakeClock 是可注入测试时钟。
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

// Now 返回当前测试时间。
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance 前进测试时间。
func (c *fakeClock) Advance(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(duration)
}

// sleepRecorder 记录渐进延迟而不真实等待。
type sleepRecorder struct {
	mu     sync.Mutex
	delays []time.Duration
}

// Sleep 记录一次延迟。
func (r *sleepRecorder) Sleep(_ context.Context, duration time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.delays = append(r.delays, duration)
	return nil
}

// Delays 返回已记录的延迟副本。
func (r *sleepRecorder) Delays() []time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]time.Duration(nil), r.delays...)
}

// testParams 是测试用低成本 Argon2id 参数。
func testParams() authn.Params {
	return authn.Params{MemoryKiB: 8192, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}
}

// testEnv 汇总临时 SQLite、真实审计、真实凭证服务与认证服务。
type testEnv struct {
	t             *testing.T
	raw           *storagesqlite.Store
	recorder      *audit.Recorder
	auditStore    *auditsqlite.Store
	store         *authnsqlite.Store
	bootstrapDB   *bootstrapsqlite.Store
	bootstrapSvc  *bootstrap.Service
	credentials   *credential.Service
	clock         *fakeClock
	sleep         *sleepRecorder
	service       *authn.Service
	systemCaller  authn.Caller
	localCaller   authn.Caller
	bootstrapUser bootstrap.Caller
	logBuffer     *bytes.Buffer
	counter       int
}

// newTestEnv 在临时数据库上执行全部迁移并构造真实生产依赖。
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(filepath.Join(testutil.TempDir(t), "authn.sqlite")))
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
	clock := &fakeClock{now: testBaseTime}
	sleep := &sleepRecorder{}
	auditStore, err := auditsqlite.New(raw)
	if err != nil {
		t.Fatalf("构造审计仓储失败: %v", err)
	}
	recorder, err := audit.New(auditStore, audit.Options{Now: clock.Now})
	if err != nil {
		t.Fatalf("构造审计写入器失败: %v", err)
	}
	ring, err := secrets.GenerateKeyring("k1", testBaseTime)
	if err != nil {
		t.Fatalf("GenerateKeyring 失败: %v", err)
	}
	credentialStore, err := credentialsqlite.New(raw)
	if err != nil {
		t.Fatalf("构造凭证仓储失败: %v", err)
	}
	credentialService, err := credential.New(credentialStore, credential.Options{
		Keyring: ring,
		Now:     clock.Now,
	})
	if err != nil {
		t.Fatalf("构造凭证服务失败: %v", err)
	}
	bootstrapDB, err := bootstrapsqlite.New(raw)
	if err != nil {
		t.Fatalf("构造初始化仓储失败: %v", err)
	}
	bootstrapAuthorizer, err := bootstrap.NewLocalBootstrapAuthorizer([]string{testOperator})
	if err != nil {
		t.Fatalf("构造初始化授权器失败: %v", err)
	}
	bootstrapCaller, err := bootstrap.LocalBootstrapCaller(testOperator)
	if err != nil {
		t.Fatalf("构造初始化调用者失败: %v", err)
	}
	bootstrapSvc, err := bootstrap.New(bootstrap.Options{
		Store:       bootstrapDB,
		Audit:       recorder,
		Authorizer:  bootstrapAuthorizer,
		Credentials: credentialService,
		Now:         clock.Now,
	})
	if err != nil {
		t.Fatalf("构造初始化服务失败: %v", err)
	}
	store, err := authnsqlite.New(raw)
	if err != nil {
		t.Fatalf("构造认证仓储失败: %v", err)
	}
	systemCaller, err := authn.SystemCaller(testSystem)
	if err != nil {
		t.Fatalf("构造系统调用者失败: %v", err)
	}
	localCaller, err := authn.LocalAdminCaller(testOperator)
	if err != nil {
		t.Fatalf("构造本地调用者失败: %v", err)
	}
	logBuffer := &bytes.Buffer{}
	env := &testEnv{
		t:             t,
		raw:           raw,
		recorder:      recorder,
		auditStore:    auditStore,
		store:         store,
		bootstrapDB:   bootstrapDB,
		bootstrapSvc:  bootstrapSvc,
		credentials:   credentialService,
		clock:         clock,
		sleep:         sleep,
		systemCaller:  systemCaller,
		localCaller:   localCaller,
		bootstrapUser: bootstrapCaller,
		logBuffer:     logBuffer,
	}
	env.service = env.newService(nil)
	return env
}

// newService 用同一数据库构造认证服务；mutate 可覆盖选项，用于限流/审计故障
// 等场景，不影响已构造的主服务。
func (e *testEnv) newService(mutate func(*authn.Options)) *authn.Service {
	e.t.Helper()
	options := authn.Options{AllowLegacyWithoutSensitive: true,
		Store:              e.store,
		Audit:              e.recorder,
		RootInitialization: e.bootstrapDB,
		Params:             testParams(),
		FailurePolicy: authn.FailurePolicy{
			Window: time.Minute, MaxFailures: 3, LockDuration: 2 * time.Minute,
			MaxLockDuration: 10 * time.Minute, DelayBase: 20 * time.Millisecond,
			DelayMax: 80 * time.Millisecond, MaxEntries: 32,
		},
		RateLimitPolicy: authn.RateLimitPolicy{
			IP:        ratelimitPolicy(1000, time.Minute),
			Operation: ratelimitPolicy(10000, time.Minute),
		},
		EmailLoginEnabled: true,
		Now:               e.clock.Now,
		Sleep:             e.sleep.Sleep,
		Logger: slog.New(slog.NewJSONHandler(e.logBuffer, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		})),
	}
	if mutate != nil {
		mutate(&options)
	}
	service, err := authn.New(options)
	if err != nil {
		e.t.Fatalf("构造认证服务失败: %v", err)
	}
	return service
}

// ratelimitPolicy 构造固定窗口策略。
func ratelimitPolicy(limit int, window time.Duration) ratelimit.Policy {
	return ratelimit.Policy{Limit: limit, Window: window}
}

// nowMS 返回测试时钟当前毫秒。
func (e *testEnv) nowMS() int64 {
	return e.clock.Now().UTC().UnixMilli()
}

// insertUser 直接插入合成账户，返回稳定用户 ID。
func (e *testEnv) insertUser(username string, status account.Status, isRoot bool) string {
	e.t.Helper()
	e.counter++
	var (
		display    string
		normalized string
	)
	if isRoot {
		display, normalized = bootstrap.RootUsername, bootstrap.RootUsernameNormalized
	} else {
		var err error
		display, normalized, err = account.NormalizeUsername(username)
		if err != nil {
			e.t.Fatalf("规范化测试用户名失败: %v", err)
		}
	}
	userID := fmt.Sprintf("usr_%032x", e.counter)
	nowMS := e.nowMS()
	_, err := e.raw.ExecContext(context.Background(),
		`INSERT INTO users(id,username,username_normalized,nickname,biography,avatar_ref,language,timezone,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'','',NULL,'zh-CN','Asia/Shanghai',?,?,1,1,?,?)`,
		userID, display, normalized, string(status), boolToInt(isRoot), nowMS, nowMS)
	if err != nil {
		e.t.Fatalf("插入测试账户失败: %v", err)
	}
	return userID
}

// insertEmail 插入邮箱登录标识（可选已验证）。
func (e *testEnv) insertEmail(userID, email string, verified bool) {
	e.t.Helper()
	display, normalized, err := authn.NormalizeEmail(email)
	if err != nil {
		e.t.Fatalf("规范化测试邮箱失败: %v", err)
	}
	var verifiedAt any
	if verified {
		verifiedAt = e.nowMS()
	}
	nowMS := e.nowMS()
	if _, err := e.raw.ExecContext(context.Background(),
		`INSERT INTO user_emails(email_normalized,user_id,email,verified_at_ms,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?)`, normalized, userID, display, verifiedAt, nowMS, nowMS); err != nil {
		e.t.Fatalf("插入测试邮箱失败: %v", err)
	}
}

// assignRole 直接为账户插入一个系统角色分配。
func (e *testEnv) assignRole(userID, roleKey string) {
	e.t.Helper()
	e.counter++
	roleID := fmt.Sprintf("role_%032x", e.counter)
	nowMS := e.nowMS()
	if _, err := e.raw.ExecContext(context.Background(),
		`INSERT INTO roles(id,scope_id,role_key,name,description,limits_text,is_builtin,enabled,created_at_ms,updated_at_ms)
VALUES(?, 'system', ?, ?, '', '', 1, 1, ?, ?)`,
		roleID, roleKey, "测试角色 "+roleKey, nowMS, nowMS); err != nil {
		e.t.Fatalf("插入测试角色失败: %v", err)
	}
	if _, err := e.raw.ExecContext(context.Background(),
		`INSERT INTO user_roles(user_id,role_id,scope_id,data_scope_json,assigned_by,created_at_ms)
VALUES(?,?,'system','{}','test',?)`, userID, roleID, nowMS); err != nil {
		e.t.Fatalf("插入测试角色分配失败: %v", err)
	}
}

// insertCredential 直接写入指定哈希的正式密码凭证（用于构造旧参数哈希）。
func (e *testEnv) insertCredential(userID, hash string) {
	e.t.Helper()
	nowMS := e.nowMS()
	if _, err := e.raw.ExecContext(context.Background(),
		`INSERT INTO password_credentials(user_id,hash_scheme,hash_version,password_hash,must_change,row_version,created_at_ms,updated_at_ms,changed_at_ms)
VALUES(?,?,?,?,0,1,?,?,?)`,
		userID, authn.PasswordScheme, authn.PasswordSchemeVersion, hash, nowMS, nowMS, nowMS); err != nil {
		e.t.Fatalf("插入测试密码凭证失败: %v", err)
	}
}

// setPassword 通过系统通道设置测试密码。
func (e *testEnv) setPassword(userID, password string, mustChange bool) authn.SetPasswordResult {
	e.t.Helper()
	result, err := e.service.SetPassword(context.Background(), e.systemCaller, authn.SetPasswordRequest{
		TargetUserID:  userID,
		NewPassword:   password,
		RequireChange: mustChange,
		RequestID:     "req-password-set",
	})
	if err != nil {
		e.t.Fatalf("设置测试密码失败: %v", err)
	}
	return result
}

// authenticate 执行一次密码认证。
func (e *testEnv) authenticate(identifier, password, clientIP string) (authn.AuthenticateResult, error) {
	e.t.Helper()
	return e.service.Authenticate(context.Background(), authn.AuthenticateRequest{
		Identifier: identifier,
		Password:   password,
		ClientIP:   clientIP,
		RequestID:  "req-auth",
	})
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

// queryString 执行单值文本查询。
func (e *testEnv) queryString(query string, args ...any) string {
	e.t.Helper()
	rows, err := e.raw.QueryContext(context.Background(), query, args...)
	if err != nil {
		e.t.Fatalf("查询失败: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		e.t.Fatalf("查询没有结果: %v", rows.Err())
	}
	var value string
	if err := rows.Scan(&value); err != nil {
		e.t.Fatalf("扫描文本失败: %v", err)
	}
	return value
}

// countEvents 统计指定动作与结果的审计事件数。
func (e *testEnv) countEvents(action string, outcome audit.Outcome) int {
	e.t.Helper()
	return e.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action=? AND outcome=?`,
		action, string(outcome))
}

// latestReason 返回指定动作最近一条审计的内部原因码。
func (e *testEnv) latestReason(action string) string {
	e.t.Helper()
	return e.queryString(`SELECT COALESCE(reason_code,'') FROM audit_events WHERE action=?
ORDER BY rowid DESC LIMIT 1`, action)
}

// allAuditText 把所有审计可见文本拼成一个字符串，用于脱敏断言。
func (e *testEnv) allAuditText() string {
	e.t.Helper()
	rows, err := e.raw.QueryContext(context.Background(),
		`SELECT COALESCE(actor_id,'')||'|'||COALESCE(target_id,'')||'|'||COALESCE(error_code,'')||
'|'||COALESCE(reason_code,'')||'|'||COALESCE(detail_json,'') FROM audit_events`)
	if err != nil {
		e.t.Fatalf("读取审计文本失败: %v", err)
	}
	defer rows.Close()
	var builder strings.Builder
	for rows.Next() {
		var text string
		if err := rows.Scan(&text); err != nil {
			e.t.Fatalf("扫描审计文本失败: %v", err)
		}
		builder.WriteString(text)
		builder.WriteByte('\n')
	}
	return builder.String()
}

// boolToInt 把布尔值转成 SQLite 0/1。
func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

// TestAuthenticateSuccessAndUniformFailure 验证正常登录、统一公开失败提示与内部
// 诊断原因分离：错误密码与未知用户对外错误完全相同，审计原因不同。
func TestAuthenticateSuccessAndUniformFailure(t *testing.T) {
	env := newTestEnv(t)
	userID := env.insertUser("alice", account.StatusActive, false)
	env.setPassword(userID, testPassword, false)

	result, err := env.authenticate("alice", testPassword, "203.0.113.10")
	if err != nil {
		t.Fatalf("正常登录失败: %v", err)
	}
	if result.Outcome != authn.OutcomeComplete || !result.IsComplete() {
		t.Fatalf("认证结论 = %q，期望 complete", result.Outcome)
	}
	if len(result.CompletedMethods) != 1 || result.CompletedMethods[0] != authn.MethodPassword {
		t.Fatalf("已完成方法 = %v", result.CompletedMethods)
	}
	if len(result.RequiredSteps) != 0 || result.Restricted {
		t.Fatalf("完整登录仍有额外步骤或受限标记: %+v", result)
	}
	if result.UserID != userID || result.CompletedAt.IsZero() {
		t.Fatalf("结果缺少用户/时间: %+v", result)
	}
	if result.SecurityVersion != 2 {
		t.Fatalf("安全版本 = %d，期望密码设置后为 2", result.SecurityVersion)
	}
	// 账户大小写折叠：用户名比较使用 NFKC + 大小写折叠。
	if _, err := env.authenticate("ALICE", testPassword, "203.0.113.11"); err != nil {
		t.Fatalf("大写用户名登录失败: %v", err)
	}

	wrongErr := func() error {
		_, err := env.authenticate("alice", "Wrong-Password-9-Battery", "203.0.113.12")
		return err
	}()
	unknownErr := func() error {
		_, err := env.authenticate("nobody", testPassword, "203.0.113.13")
		return err
	}()
	if !errors.Is(wrongErr, authn.ErrAuthenticationFailed) ||
		!errors.Is(unknownErr, authn.ErrAuthenticationFailed) {
		t.Fatalf("失败错误 = (%v,%v)，期望统一 ErrAuthenticationFailed", wrongErr, unknownErr)
	}
	if wrongErr.Error() != unknownErr.Error() {
		t.Fatalf("错误密码与未知用户公开文本不同: %q vs %q", wrongErr.Error(), unknownErr.Error())
	}
	if code := authn.CodeOf(wrongErr); code != authn.CodeAuthFailed {
		t.Fatalf("错误码 = %q，期望 AUTH_FAILED", code)
	}
	if reason := env.latestReason(string(authn.ActionPasswordVerify)); reason != "unknown_user" {
		t.Fatalf("最近失败原因 = %q，期望 unknown_user（未知用户最后执行）", reason)
	}
	if env.countEvents(string(authn.ActionPasswordVerify), audit.OutcomeSuccess) != 2 {
		t.Errorf("成功认证审计数 = %d，期望 2", env.countEvents(string(authn.ActionPasswordVerify), audit.OutcomeSuccess))
	}
	if env.countEvents(string(authn.ActionPasswordVerify), audit.OutcomeFailure) != 2 {
		t.Errorf("失败认证审计数 = %d，期望 2", env.countEvents(string(authn.ActionPasswordVerify), audit.OutcomeFailure))
	}
}

// TestAuthenticateUnicodeAndEmailIdentifiers 验证 Unicode 用户名与“配置允许的
// 已验证邮箱”登录：未验证邮箱、关闭邮箱登录与非验证邮箱一律统一失败。
func TestAuthenticateUnicodeAndEmailIdentifiers(t *testing.T) {
	env := newTestEnv(t)
	// 全角字母经 NFKC 归一后与 ASCII 用户名匹配。
	userID := env.insertUser("Alice用户", account.StatusActive, false)
	env.setPassword(userID, testPassword, false)
	if _, err := env.authenticate("Ａlice用户", testPassword, "203.0.113.20"); err != nil {
		t.Fatalf("Unicode 用户名登录失败: %v", err)
	}
	env.insertEmail(userID, "User@Example.COM", true)
	// 邮箱比较大小写不敏感；大小写变体必须命中同一条已验证记录。
	if result, err := env.authenticate("user@example.com", testPassword, "203.0.113.21"); err != nil {
		t.Fatalf("已验证邮箱登录失败: %v", err)
	} else if result.UserID != userID {
		t.Fatalf("邮箱登录用户 = %q，期望 %q", result.UserID, userID)
	}
	if _, err := env.authenticate("USER@EXAMPLE.COM", testPassword, "203.0.113.22"); err != nil {
		t.Fatalf("大写邮箱登录失败: %v", err)
	}

	// 未验证邮箱不能登录。
	otherID := env.insertUser("bob", account.StatusActive, false)
	env.setPassword(otherID, testPassword, false)
	env.insertEmail(otherID, "bob@example.com", false)
	if _, err := env.authenticate("bob@example.com", testPassword, "203.0.113.23"); !errors.Is(err, authn.ErrAuthenticationFailed) {
		t.Fatalf("未验证邮箱登录错误 = %v，期望 ErrAuthenticationFailed", err)
	}

	// 配置关闭邮箱登录时，即使邮箱已验证也统一失败。
	disabledService := env.newService(func(options *authn.Options) {
		options.EmailLoginEnabled = false
	})
	if _, err := disabledService.Authenticate(context.Background(), authn.AuthenticateRequest{
		Identifier: "user@example.com", Password: testPassword, ClientIP: "203.0.113.24",
	}); !errors.Is(err, authn.ErrAuthenticationFailed) {
		t.Fatalf("邮箱登录关闭时错误 = %v，期望统一认证失败", err)
	}
	// 畸形邮箱与未知账户同样统一失败。
	if _, err := env.authenticate("not-an-email@", testPassword, "203.0.113.25"); !errors.Is(err, authn.ErrAuthenticationFailed) {
		t.Fatalf("畸形邮箱错误 = %v，期望统一认证失败", err)
	}
}

// TestAuthenticateDisabledAccountGenericFailure 验证禁用账户即使密码正确也只得到
// 统一公开失败，内部审计记录真实原因。
func TestAuthenticateDisabledAccountGenericFailure(t *testing.T) {
	env := newTestEnv(t)
	userID := env.insertUser("carol", account.StatusDisabled, false)
	env.setPassword(userID, testPassword, false)
	_, err := env.authenticate("carol", testPassword, "203.0.113.30")
	if !errors.Is(err, authn.ErrAuthenticationFailed) {
		t.Fatalf("禁用账户登录错误 = %v，期望统一认证失败", err)
	}
	if reason := env.latestReason(string(authn.ActionPasswordVerify)); reason != "account_disabled" {
		t.Fatalf("内部原因 = %q，期望 account_disabled", reason)
	}
	// 账户不存在时不能出现 USER_DISABLED 之类可探测的公开码。
	if code := authn.CodeOf(err); code != authn.CodeAuthFailed {
		t.Fatalf("公开错误码 = %q，期望 AUTH_FAILED", code)
	}
}

// TestTemporaryLockAndRecovery 验证渐进延迟、临时锁定、成功后重置与锁定到期
// 自动恢复（不永久锁号）；未知标识也按同一维度计数。
func TestTemporaryLockAndRecovery(t *testing.T) {
	env := newTestEnv(t)
	userID := env.insertUser("dave", account.StatusActive, false)
	env.setPassword(userID, testPassword, false)

	const attackIP = "203.0.113.40"
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := env.authenticate("dave", "Wrong-Password-9-Battery", attackIP); !errors.Is(err, authn.ErrAuthenticationFailed) {
			t.Fatalf("第 %d 次错误密码错误 = %v", attempt+1, err)
		}
	}
	delays := env.sleep.Delays()
	if len(delays) != 2 || delays[0] != 20*time.Millisecond || delays[1] != 40*time.Millisecond {
		t.Fatalf("渐进延迟 = %v，期望 [20ms 40ms]", delays)
	}
	// 第三次失败触发“账户 + 来源”临时锁定，并直接返回限流错误。
	_, err := env.authenticate("dave", "Wrong-Password-9-Battery", attackIP)
	retryAfter, reason, limited := authn.AsRateLimit(err)
	if !limited || retryAfter != 2*time.Minute || reason != "identifier_locked" {
		t.Fatalf("第三次失败 = (%v,%v,%v)，期望 2 分钟临时锁定", retryAfter, reason, limited)
	}
	if code := authn.CodeOf(err); code != authn.CodeRateLimited {
		t.Fatalf("限流错误码 = %q，期望 RATE_LIMITED", code)
	}

	// 同一来源锁定期间即使密码正确也拒绝，并返回剩余等待时间。
	if _, err := env.authenticate("dave", testPassword, attackIP); !errors.Is(err, authn.ErrRateLimited) {
		t.Fatalf("锁定期间正确密码错误 = %v，期望 RATE_LIMITED", err)
	}

	// 锁定到期后自动恢复：正确密码成功，且失败状态被重置。
	env.clock.Advance(2 * time.Minute)
	if _, err := env.authenticate("dave", testPassword, attackIP); err != nil {
		t.Fatalf("锁定到期后正确密码登录失败: %v", err)
	}
	before := len(env.sleep.Delays())
	if _, err := env.authenticate("dave", "Wrong-Password-9-Battery", attackIP); !errors.Is(err, authn.ErrAuthenticationFailed) {
		t.Fatalf("重置后错误密码错误 = %v", err)
	}
	after := env.sleep.Delays()
	if len(after) != before+1 || after[len(after)-1] != 20*time.Millisecond {
		t.Fatalf("成功认证后失败状态未重置: 延迟 = %v", after)
	}

	// 未知标识同样按“标识 + 来源”锁定，避免用限流差异探测账户存在性。
	for attempt := 0; attempt < 3; attempt++ {
		env.authenticate("nobody", testPassword, "203.0.113.45")
	}
	if _, err := env.authenticate("nobody", testPassword, "203.0.113.45"); !errors.Is(err, authn.ErrRateLimited) {
		t.Fatalf("未知标识第三次失败错误 = %v，期望 RATE_LIMITED", err)
	}
}

// TestConcurrentFailuresBounded 验证并发失败下的限流状态安全与有界终态。
func TestConcurrentFailuresBounded(t *testing.T) {
	env := newTestEnv(t)
	service := env.newService(func(options *authn.Options) {
		options.FailurePolicy = authn.FailurePolicy{
			Window: time.Minute, MaxFailures: 4, LockDuration: time.Minute,
			MaxLockDuration: 5 * time.Minute, DelayBase: time.Millisecond,
			DelayMax: 2 * time.Millisecond, MaxEntries: 16,
		}
	})
	userID := env.insertUser("erin", account.StatusActive, false)
	if _, err := service.SetPassword(context.Background(), env.systemCaller, authn.SetPasswordRequest{
		TargetUserID: userID, NewPassword: testPassword, RequestID: "req-set",
	}); err != nil {
		t.Fatalf("设置密码失败: %v", err)
	}
	const workers = 8
	var waitGroup sync.WaitGroup
	errorsSeen := make(chan error, workers)
	for worker := 0; worker < workers; worker++ {
		waitGroup.Add(1)
		go func(worker int) {
			defer waitGroup.Done()
			_, err := service.Authenticate(context.Background(), authn.AuthenticateRequest{
				Identifier: "erin",
				Password:   fmt.Sprintf("Wrong-Password-9-Battery-%d", worker),
				ClientIP:   "203.0.113.50",
			})
			errorsSeen <- err
		}(worker)
	}
	waitGroup.Wait()
	close(errorsSeen)
	limited := 0
	for err := range errorsSeen {
		switch {
		case errors.Is(err, authn.ErrRateLimited):
			limited++
		case errors.Is(err, authn.ErrAuthenticationFailed):
		default:
			t.Fatalf("并发失败出现未预期错误: %v", err)
		}
	}
	if limited == 0 {
		t.Fatal("并发失败没有触发临时锁定")
	}
	// 攻击来源锁定后正确密码也拒绝；其他来源不受影响（不会锁死账户）。
	if _, err := service.Authenticate(context.Background(), authn.AuthenticateRequest{
		Identifier: "erin", Password: testPassword, ClientIP: "203.0.113.50",
	}); !errors.Is(err, authn.ErrRateLimited) {
		t.Fatalf("并发锁定后同来源正确密码错误 = %v，期望 RATE_LIMITED", err)
	}
	if _, err := service.Authenticate(context.Background(), authn.AuthenticateRequest{
		Identifier: "erin", Password: testPassword, ClientIP: "203.0.113.52",
	}); err != nil {
		t.Fatalf("其他来源正确密码登录失败: %v", err)
	}
	env.clock.Advance(time.Minute)
	if _, err := service.Authenticate(context.Background(), authn.AuthenticateRequest{
		Identifier: "erin", Password: testPassword, ClientIP: "203.0.113.50",
	}); err != nil {
		t.Fatalf("锁定到期后恢复登录失败: %v", err)
	}
}

// TestHashUpgradeOnLogin 验证登录成功后旧参数哈希被条件升级，第二次登录不再升级。
func TestHashUpgradeOnLogin(t *testing.T) {
	env := newTestEnv(t)
	elevatedParams := authn.Params{MemoryKiB: 10240, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32}
	service := env.newService(func(options *authn.Options) {
		options.Params = elevatedParams
	})
	userID := env.insertUser("frank", account.StatusActive, false)
	oldHash, err := authn.HashPassword(testPassword, testParams(), nil)
	if err != nil {
		t.Fatalf("生成旧参数哈希失败: %v", err)
	}
	env.insertCredential(userID, oldHash)
	result, err := service.Authenticate(context.Background(), authn.AuthenticateRequest{
		Identifier: "frank", Password: testPassword, ClientIP: "203.0.113.60",
	})
	if err != nil {
		t.Fatalf("升级登录失败: %v", err)
	}
	if !result.PasswordUpgradeApplied {
		t.Fatal("旧参数哈希登录后未升级")
	}
	if result.Outcome != authn.OutcomeComplete {
		t.Fatalf("升级后认证结论 = %q，期望 complete", result.Outcome)
	}
	newHash := env.queryString(`SELECT password_hash FROM password_credentials WHERE user_id=?`, userID)
	if !strings.HasPrefix(newHash, "$argon2id$v=19$m=10240,t=2,p=1$") {
		t.Fatalf("升级后的哈希参数 = %q，期望 m=10240,t=2,p=1", hashPrefix(newHash))
	}
	if env.countEvents(string(authn.ActionPasswordUpgrade), audit.OutcomeSuccess) != 1 {
		t.Errorf("哈希升级审计数 = %d，期望 1",
			env.countEvents(string(authn.ActionPasswordUpgrade), audit.OutcomeSuccess))
	}
	// 第二次登录使用当前参数，不应再次升级。
	result, err = service.Authenticate(context.Background(), authn.AuthenticateRequest{
		Identifier: "frank", Password: testPassword, ClientIP: "203.0.113.61",
	})
	if err != nil {
		t.Fatalf("第二次登录失败: %v", err)
	}
	if result.PasswordUpgradeApplied {
		t.Fatal("当前参数哈希被重复升级")
	}
}

// hashPrefix 截取 PHC 编码前缀，避免在测试失败信息中打印完整哈希。
func hashPrefix(hash string) string {
	if len(hash) > 40 {
		return hash[:40]
	}
	return hash
}

// TestSetPasswordPolicyHistoryAndAuthorization 验证密码策略、可选历史与调用边界。
func TestSetPasswordPolicyHistoryAndAuthorization(t *testing.T) {
	env := newTestEnv(t)
	service := env.newService(func(options *authn.Options) {
		policy := authn.DefaultPasswordPolicy()
		policy.HistoryLimit = 2
		options.PasswordPolicy = policy
	})
	aliceID := env.insertUser("alice", account.StatusActive, false)
	bobID := env.insertUser("bob2", account.StatusActive, false)
	// 弱密码被拒绝且不写凭证。
	if _, err := service.SetPassword(context.Background(), env.systemCaller, authn.SetPasswordRequest{
		TargetUserID: aliceID, NewPassword: "short",
	}); !errors.Is(err, authn.ErrWeakPassword) {
		t.Fatalf("弱密码错误 = %v，期望 ErrWeakPassword", err)
	}
	if env.queryInt(`SELECT COUNT(*) FROM password_credentials WHERE user_id=?`, aliceID) != 0 {
		t.Fatal("弱密码被写入凭证")
	}
	if reason := env.latestReason(string(authn.ActionPasswordSet)); reason != "weak_password" {
		t.Fatalf("弱密码审计原因 = %q", reason)
	}

	// 系统通道首次设置 P1。
	if _, err := service.SetPassword(context.Background(), env.systemCaller, authn.SetPasswordRequest{
		TargetUserID: aliceID, NewPassword: "First-Credential-9-A", RequestID: "r1",
	}); err != nil {
		t.Fatalf("首次设置密码失败: %v", err)
	}
	aliceCaller, err := authn.UserCaller(aliceID)
	if err != nil {
		t.Fatalf("构造用户调用者失败: %v", err)
	}
	// 普通用户不能改他人密码。
	if _, err := service.SetPassword(context.Background(), aliceCaller, authn.SetPasswordRequest{
		TargetUserID: bobID, NewPassword: "Second-Credential-9-B", CurrentPassword: "First-Credential-9-A",
	}); !errors.Is(err, authn.ErrAccessDenied) {
		t.Fatalf("跨用户改密错误 = %v，期望 ErrAccessDenied", err)
	}
	// 本人改密必须提供当前密码。
	if _, err := service.SetPassword(context.Background(), aliceCaller, authn.SetPasswordRequest{
		TargetUserID: aliceID, NewPassword: "Second-Credential-9-B",
	}); !errors.Is(err, authn.ErrAccessDenied) {
		t.Fatalf("缺少当前密码错误 = %v，期望 ErrAccessDenied", err)
	}
	if _, err := service.SetPassword(context.Background(), aliceCaller, authn.SetPasswordRequest{
		TargetUserID: aliceID, NewPassword: "Second-Credential-9-B", CurrentPassword: "Wrong-Password-9-A",
	}); !errors.Is(err, authn.ErrAuthenticationFailed) {
		t.Fatalf("当前密码错误错误 = %v，期望 ErrAuthenticationFailed", err)
	}
	// 本人带正确当前密码修改成功。
	if _, err := service.SetPassword(context.Background(), aliceCaller, authn.SetPasswordRequest{
		TargetUserID: aliceID, NewPassword: "Second-Credential-9-B", CurrentPassword: "First-Credential-9-A",
		RequestID: "r2",
	}); err != nil {
		t.Fatalf("本人改密失败: %v", err)
	}
	// 管理员继续改密，历史保留最近两条。
	if _, err := service.SetPassword(context.Background(), env.systemCaller, authn.SetPasswordRequest{
		TargetUserID: aliceID, NewPassword: "Third-Credential-9-C", RequestID: "r3",
	}); err != nil {
		t.Fatalf("管理员改密失败: %v", err)
	}
	if count := env.queryInt(`SELECT COUNT(*) FROM password_history WHERE user_id=?`, aliceID); count != 2 {
		t.Fatalf("历史条数 = %d，期望 2", count)
	}
	// 当前密码与历史密码都不能复用。
	if _, err := service.SetPassword(context.Background(), env.systemCaller, authn.SetPasswordRequest{
		TargetUserID: aliceID, NewPassword: "Third-Credential-9-C",
	}); !errors.Is(err, authn.ErrPasswordReused) {
		t.Fatalf("复用当前密码错误 = %v，期望 ErrPasswordReused", err)
	}
	if _, err := service.SetPassword(context.Background(), env.systemCaller, authn.SetPasswordRequest{
		TargetUserID: aliceID, NewPassword: "First-Credential-9-A",
	}); !errors.Is(err, authn.ErrPasswordReused) {
		t.Fatalf("复用历史密码错误 = %v，期望 ErrPasswordReused", err)
	}
	// 新密码可用。
	if _, err := service.SetPassword(context.Background(), env.systemCaller, authn.SetPasswordRequest{
		TargetUserID: aliceID, NewPassword: "Fourth-Credential-9-D",
	}); err != nil {
		t.Fatalf("设置新密码失败: %v", err)
	}
	// root 不能通过普通 SetPassword 设置。
	rootID := env.insertUser("root", account.StatusActive, true)
	if _, err := service.SetPassword(context.Background(), env.localCaller, authn.SetPasswordRequest{
		TargetUserID: rootID, NewPassword: "Owner-Credential-9-A",
	}); !errors.Is(err, authn.ErrAccessDenied) {
		t.Fatalf("SetPassword 设置 root 密码错误 = %v，期望 ErrAccessDenied", err)
	}
}

// TestAdminAccountRequiresStrongAuth 验证管理账户不跳过强认证：root 与高权限系统
// 角色即使密码正确也只得到受限待第二因素结果；普通角色可完整登录。
func TestAdminAccountRequiresStrongAuth(t *testing.T) {
	env := newTestEnv(t)
	adminID := env.insertUser("adminuser", account.StatusActive, false)
	env.assignCustomPermissionRole(adminID, "system_admin_like", "users.disable")
	env.setPassword(adminID, testPassword, false)
	adminResult, err := env.authenticate("adminuser", testPassword, "203.0.113.70")
	if err != nil {
		t.Fatalf("管理员密码认证错误: %v", err)
	}
	if adminResult.Outcome != authn.OutcomePendingSecondFactor || !adminResult.Restricted {
		t.Fatalf("管理员认证结果 = %+v，期望待第二因素且受限", adminResult)
	}
	if adminResult.IsComplete() {
		t.Fatal("管理员密码正确被当成完整登录")
	}
	if !hasStep(adminResult.RequiredSteps, authn.StepStrongAuthSetup) ||
		!hasStep(adminResult.RequiredSteps, authn.StepSecondFactor) {
		t.Fatalf("管理员待完成步骤 = %v，期望同时含强因素绑定与第二因素", adminResult.RequiredSteps)
	}
	// 按实际已绑定强因素动态给出步骤：已绑定强因素时只需第二因素（不再要求初始化）。
	withStrong := env.newService(func(options *authn.Options) {
		options.StrongFactorPresence = &fakeStrongFactorPresence{has: true}
	})
	resultWithStrong, err := withStrong.Authenticate(context.Background(), authn.AuthenticateRequest{
		Identifier: "adminuser", Password: testPassword, ClientIP: "203.0.113.73", RequestID: "req-strong-step",
	})
	if err != nil {
		t.Fatalf("已绑定强因素的管理员认证错误: %v", err)
	}
	if hasStep(resultWithStrong.RequiredSteps, authn.StepStrongAuthSetup) ||
		!hasStep(resultWithStrong.RequiredSteps, authn.StepSecondFactor) {
		t.Fatalf("已绑定强因素时待完成步骤 = %v，期望只需要第二因素", resultWithStrong.RequiredSteps)
	}
	if len(adminResult.CompletedMethods) != 1 || adminResult.CompletedMethods[0] != authn.MethodPassword {
		t.Fatalf("管理员已完成方法 = %v", adminResult.CompletedMethods)
	}

	supportID := env.insertUser("supportuser", account.StatusActive, false)
	env.assignCustomPermissionRole(supportID, "support_like", "recovery.request")
	env.setPassword(supportID, testPassword, false)
	if result, err := env.authenticate("supportuser", testPassword, "203.0.113.71"); err != nil {
		t.Fatalf("客服密码认证错误: %v", err)
	} else if result.Outcome != authn.OutcomePendingSecondFactor || !result.Restricted {
		t.Fatalf("客服认证结果 = %+v，期望待第二因素", result)
	}

	normalID := env.insertUser("normaluser", account.StatusActive, false)
	env.assignRole(normalID, "normal_user")
	env.setPassword(normalID, testPassword, false)
	if result, err := env.authenticate("normaluser", testPassword, "203.0.113.72"); err != nil {
		t.Fatalf("普通用户密码认证错误: %v", err)
	} else if result.Outcome != authn.OutcomeComplete || result.Restricted {
		t.Fatalf("普通用户认证结果 = %+v，期望完整登录", result)
	}

	// must_change 账户密码正确但必须改密，同样不是完整登录。
	changeID := env.insertUser("changeuser", account.StatusActive, false)
	env.setPassword(changeID, testPassword, true)
	if result, err := env.authenticate("changeuser", testPassword, "203.0.113.73"); err != nil {
		t.Fatalf("待改密账户认证错误: %v", err)
	} else if result.Outcome != authn.OutcomePendingPasswordChange || !result.Restricted ||
		len(result.RequiredSteps) != 1 || result.RequiredSteps[0] != authn.StepPasswordChange {
		t.Fatalf("待改密认证结果 = %+v", result)
	}
}

// TestRootSetupSharedPasswordFlow 验证 root 受限初始化与正式密码服务共用实现：
// pending_setup 不能直接设密码，兑换一次性凭证后可设置正式密码；写入与状态/
// 审计同事务；强认证未配置前不进入 ready、不签会话；ready 后入口关闭。
func TestRootSetupSharedPasswordFlow(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	initialized, err := env.bootstrapSvc.Initialize(ctx, env.bootstrapUser, bootstrap.InitializeRequest{})
	if err != nil {
		t.Fatalf("root 初始化失败: %v", err)
	}
	rootID := initialized.Root.ID

	// pending_setup 直接设置正式密码必须被拒绝（不能跳过一次性配置凭证）。
	if _, err := env.service.SetRootPassword(ctx, env.localCaller, authn.SetRootPasswordRequest{
		RootUserID: rootID, NewPassword: "Owner-Credential-9-A",
	}); !errors.Is(err, authn.ErrSetupVerificationRequired) {
		t.Fatalf("pending_setup 设置密码错误 = %v，期望 ErrSetupVerificationRequired", err)
	}
	if env.queryInt(`SELECT COUNT(*) FROM password_credentials WHERE user_id=?`, rootID) != 0 {
		t.Fatal("pending_setup 阶段写入了密码凭证")
	}
	// 非本地管理员不能设置 root 密码。
	if _, err := env.service.SetRootPassword(ctx, env.systemCaller, authn.SetRootPasswordRequest{
		RootUserID: rootID, NewPassword: "Owner-Credential-9-A",
	}); !errors.Is(err, authn.ErrAccessDenied) {
		t.Fatalf("非本地管理员设置 root 密码错误 = %v，期望 ErrAccessDenied", err)
	}

	// 兑换一次性配置凭证（进入 setup_verified，仍不是会话）。
	if _, err := env.bootstrapSvc.RedeemSetupCredential(ctx, env.bootstrapUser, bootstrap.RedeemSetupCredentialRequest{
		CredentialID: initialized.SetupCredential.ID,
		Secret:       initialized.SetupCredential.Secret.Reveal(),
	}); err != nil {
		t.Fatalf("兑换一次性配置凭证失败: %v", err)
	}

	result, err := env.service.SetRootPassword(ctx, env.localCaller, authn.SetRootPasswordRequest{
		RootUserID: rootID, NewPassword: "Owner-Credential-9-A", RequestID: "req-root-set",
	})
	if err != nil {
		t.Fatalf("设置 root 正式密码失败: %v", err)
	}
	if result.State != bootstrap.StateSetupVerified {
		t.Fatalf("密码设置后 root 状态 = %q，期望仍为 setup_verified（等待强认证）", result.State)
	}
	if !result.StrongAuthRequired {
		t.Fatal("root 应始终要求强认证")
	}
	if !hasStep(result.RequiredSteps, authn.StepStrongAuthSetup) ||
		!hasStep(result.RequiredSteps, authn.StepSecondFactor) {
		t.Fatalf("root 待完成步骤 = %v，期望同时含强因素绑定与第二因素", result.RequiredSteps)
	}
	if result.SecurityVersion != 2 {
		t.Fatalf("root 安全版本 = %d，期望 2", result.SecurityVersion)
	}
	// 数据库只保存 Argon2id PHC 编码，不保存明文。
	hash := env.queryString(`SELECT password_hash FROM password_credentials WHERE user_id=?`, rootID)
	if !strings.HasPrefix(hash, "$argon2id$") || strings.Contains(hash, "Owner-Credential-9-A") {
		t.Fatalf("root 密码存储格式异常: %q", hashPrefix(hash))
	}
	if state := env.queryString(`SELECT state FROM root_initializations WHERE singleton=1`); state != "setup_verified" {
		t.Fatalf("root 初始化状态 = %q，期望 setup_verified", state)
	}
	if env.countEvents(string(authn.ActionRootPasswordSet), audit.OutcomeSuccess) != 1 {
		t.Errorf("root 密码设置成功审计数 = %d，期望 1",
			env.countEvents(string(authn.ActionRootPasswordSet), audit.OutcomeSuccess))
	}

	// root 密码登录：密码正确但不是完整登录，等待第二因素；不返回会话或 Token。
	authResult, err := env.authenticate("root", "Owner-Credential-9-A", "127.0.0.1")
	if err != nil {
		t.Fatalf("root 密码登录错误: %v", err)
	}
	if authResult.Outcome != authn.OutcomePendingSecondFactor || !authResult.Restricted ||
		authResult.IsComplete() {
		t.Fatalf("root 认证结果 = %+v，期望待第二因素且受限", authResult)
	}

	// 模拟后续步骤完成强认证配置后进入 ready，配置阶段密码入口关闭。
	if _, err := env.raw.ExecContext(ctx,
		`UPDATE root_initializations SET state='ready',ready_at_ms=? WHERE singleton=1`,
		env.nowMS()); err != nil {
		t.Fatalf("模拟 ready 状态失败: %v", err)
	}
	if _, err := env.service.SetRootPassword(ctx, env.localCaller, authn.SetRootPasswordRequest{
		RootUserID: rootID, NewPassword: "Owner-Credential-9-B",
	}); !errors.Is(err, authn.ErrSetupCompleted) {
		t.Fatalf("ready 后设置 root 密码错误 = %v，期望 ErrSetupCompleted", err)
	}
}

// TestRateLimitDimensions 验证地址与操作两个限流维度独立生效。
func TestRateLimitDimensions(t *testing.T) {
	env := newTestEnv(t)
	userID := env.insertUser("gina", account.StatusActive, false)
	env.setPassword(userID, testPassword, false)
	ipLimited := env.newService(func(options *authn.Options) {
		options.RateLimitPolicy = authn.RateLimitPolicy{
			IP:        ratelimitPolicy(2, time.Minute),
			Operation: ratelimitPolicy(1000, time.Minute),
		}
	})
	// 地址维度只统计失败：两次错误密码消耗预算，第三次失败被限流。
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := ipLimited.Authenticate(context.Background(), authn.AuthenticateRequest{
			Identifier: "gina", Password: "Wrong-Password-9-Z", ClientIP: "198.51.100.10",
		}); !errors.Is(err, authn.ErrAuthenticationFailed) {
			t.Fatalf("地址维度第 %d 次失败错误 = %v", attempt+1, err)
		}
	}
	_, err := ipLimited.Authenticate(context.Background(), authn.AuthenticateRequest{
		Identifier: "gina", Password: "Wrong-Password-9-Z", ClientIP: "198.51.100.10",
	})
	retryAfter, reason, limited := authn.AsRateLimit(err)
	if !limited || reason != "ip_limit" || retryAfter <= 0 {
		t.Fatalf("地址维度限流 = (%v,%v,%v)，期望 ip_limit", retryAfter, reason, limited)
	}
	// 其他地址不受影响，成功登录不消耗失败预算。
	if _, err := ipLimited.Authenticate(context.Background(), authn.AuthenticateRequest{
		Identifier: "gina", Password: testPassword, ClientIP: "198.51.100.11",
	}); err != nil {
		t.Fatalf("其他地址请求失败: %v", err)
	}

	operationLimited := env.newService(func(options *authn.Options) {
		options.RateLimitPolicy = authn.RateLimitPolicy{
			IP:        ratelimitPolicy(1000, time.Minute),
			Operation: ratelimitPolicy(1, time.Minute),
		}
	})
	if _, err := operationLimited.Authenticate(context.Background(), authn.AuthenticateRequest{
		Identifier: "gina", Password: "Wrong-Password-9-Z", ClientIP: "198.51.100.12",
	}); !errors.Is(err, authn.ErrAuthenticationFailed) {
		t.Fatalf("操作维度首次失败错误: %v", err)
	}
	_, err = operationLimited.Authenticate(context.Background(), authn.AuthenticateRequest{
		Identifier: "gina", Password: testPassword, ClientIP: "198.51.100.13",
	})
	if _, reason, limited := authn.AsRateLimit(err); !limited || reason != "operation_limit" {
		t.Fatalf("操作维度限流原因 = %q，期望 operation_limit", reason)
	}
}

// TestNewOptionValidation 验证构造时缺依赖或策略越界一律拒绝。
func TestNewOptionValidation(t *testing.T) {
	env := newTestEnv(t)
	valid := func() authn.Options {
		return authn.Options{AllowLegacyWithoutSensitive: true,
			Store:              env.store,
			Audit:              env.recorder,
			RootInitialization: env.bootstrapDB,
		}
	}
	if _, err := authn.New(authn.Options{AllowLegacyWithoutSensitive: true}); !errors.Is(err, authn.ErrOptionsInvalid) {
		t.Fatalf("空选项错误 = %v，期望 ErrOptionsInvalid", err)
	}
	badStore := valid()
	badStore.Store = nil
	if _, err := authn.New(badStore); !errors.Is(err, authn.ErrOptionsInvalid) {
		t.Fatalf("空存储错误 = %v", err)
	}
	badAudit := valid()
	badAudit.Audit = nil
	if _, err := authn.New(badAudit); !errors.Is(err, authn.ErrOptionsInvalid) {
		t.Fatalf("空审计错误 = %v", err)
	}
	badRoot := valid()
	badRoot.RootInitialization = nil
	if _, err := authn.New(badRoot); !errors.Is(err, authn.ErrOptionsInvalid) {
		t.Fatalf("空 root 状态存储错误 = %v", err)
	}
	badParams := valid()
	badParams.Params = authn.Params{MemoryKiB: 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}
	if _, err := authn.New(badParams); !errors.Is(err, authn.ErrOptionsInvalid) {
		t.Fatalf("非法 Argon2 参数错误 = %v", err)
	}
	badPolicy := valid()
	badPolicy.PasswordPolicy = authn.PasswordPolicy{MinRunes: 1}
	if _, err := authn.New(badPolicy); !errors.Is(err, authn.ErrOptionsInvalid) {
		t.Fatalf("非法密码策略错误 = %v", err)
	}
	badFailure := valid()
	badFailure.FailurePolicy = authn.FailurePolicy{MaxFailures: 1}
	if _, err := authn.New(badFailure); !errors.Is(err, authn.ErrOptionsInvalid) {
		t.Fatalf("非法失败策略错误 = %v", err)
	}
	badRate := valid()
	badRate.RateLimitPolicy = authn.RateLimitPolicy{
		IP:        ratelimitPolicy(0, time.Second),
		Operation: ratelimitPolicy(10, time.Minute),
	}
	if _, err := authn.New(badRate); !errors.Is(err, authn.ErrOptionsInvalid) {
		t.Fatalf("非法限流策略错误 = %v", err)
	}
	badConcurrency := valid()
	badConcurrency.MaxConcurrentPasswordWork = authn.MaxMaxConcurrentPasswordWork + 1
	if _, err := authn.New(badConcurrency); !errors.Is(err, authn.ErrOptionsInvalid) {
		t.Fatalf("非法密码计算并发上限错误 = %v", err)
	}
	badQueueTimeout := valid()
	badQueueTimeout.PasswordWorkQueueTimeout = 5 * time.Millisecond
	if _, err := authn.New(badQueueTimeout); !errors.Is(err, authn.ErrOptionsInvalid) {
		t.Fatalf("非法密码计算排队超时错误 = %v", err)
	}
}

// failingRecordAudit 让独立审计写入失败，用于验证认证成功路径 fail-closed。
type failingRecordAudit struct {
	*audit.Recorder
}

// Record 始终返回审计不可用。
func (f failingRecordAudit) Record(context.Context, audit.Event) error {
	return fmt.Errorf("%w: 注入的审计故障", audit.ErrAuditUnavailable)
}

// failingCriticalAudit 让关键事务失败，用于验证密码写入整体回滚。
type failingCriticalAudit struct {
	*audit.Recorder
}

// ExecuteCritical 始终返回审计不可用。
func (f failingCriticalAudit) ExecuteCritical(context.Context, audit.CriticalRequest, audit.Change) error {
	return fmt.Errorf("%w: 注入的审计故障", audit.ErrAuditUnavailable)
}

// TestAuditFailureFailClosed 验证审计不可用时认证成功与密码写入都被拒绝，
// 不返回未记录的成功，也不留下半写状态。
func TestAuditFailureFailClosed(t *testing.T) {
	env := newTestEnv(t)
	userID := env.insertUser("helen", account.StatusActive, false)
	env.setPassword(userID, testPassword, false)

	recordFailing := env.newService(func(options *authn.Options) {
		options.Audit = failingRecordAudit{Recorder: env.recorder}
	})
	result, err := recordFailing.Authenticate(context.Background(), authn.AuthenticateRequest{
		Identifier: "helen", Password: testPassword, ClientIP: "203.0.113.80",
	})
	if !errors.Is(err, authn.ErrAuditUnavailable) {
		t.Fatalf("审计不可用认证错误 = %v，期望 ErrAuditUnavailable", err)
	}
	if result.Outcome != "" || result.UserID != "" {
		t.Fatalf("审计失败仍返回认证结果: %+v", result)
	}
	if code := authn.CodeOf(err); code != authn.CodeAuditWriteFailed {
		t.Fatalf("审计失败错误码 = %q，期望 AUDIT_WRITE_FAILED", code)
	}

	criticalFailing := env.newService(func(options *authn.Options) {
		options.Audit = failingCriticalAudit{Recorder: env.recorder}
	})
	if _, err := criticalFailing.SetPassword(context.Background(), env.systemCaller, authn.SetPasswordRequest{
		TargetUserID: userID, NewPassword: "Another-Credential-9-B",
	}); !errors.Is(err, authn.ErrAuditUnavailable) {
		t.Fatalf("审计不可用密码写入错误 = %v，期望 ErrAuditUnavailable", err)
	}
	// 旧密码保持有效，证明写事务已整体回滚。
	if _, err := env.authenticate("helen", testPassword, "203.0.113.81"); err != nil {
		t.Fatalf("回滚后旧密码登录失败: %v", err)
	}
}

// TestLogAndAuditRedaction 验证密码、哈希与盐不会出现在运行日志、错误文本或
// 审计记录中；数据库也只保存 Argon2id PHC 编码。
func TestLogAndAuditRedaction(t *testing.T) {
	env := newTestEnv(t)
	userID := env.insertUser("irene", account.StatusActive, false)
	env.setPassword(userID, testPassword, false)
	const wrongPassword = "Wrong-Secret-Password-9-Z"
	env.authenticate("irene", wrongPassword, "203.0.113.90")
	env.authenticate("nobody", wrongPassword, "203.0.113.91")
	env.authenticate("irene", testPassword, "203.0.113.92")

	storedHash := env.queryString(`SELECT password_hash FROM password_credentials WHERE user_id=?`, userID)
	if strings.Contains(storedHash, testPassword) || !strings.HasPrefix(storedHash, "$argon2id$") {
		t.Fatalf("数据库密码存储格式异常: %q", hashPrefix(storedHash))
	}
	auditText := env.allAuditText()
	logText := env.logBuffer.String()
	for _, forbidden := range []string{testPassword, wrongPassword, storedHash, "$argon2id$"} {
		if strings.Contains(auditText, forbidden) {
			t.Errorf("审计记录泄露敏感内容 %q", hashPrefix(forbidden))
		}
		if strings.Contains(logText, forbidden) {
			t.Errorf("运行日志泄露敏感内容 %q", hashPrefix(forbidden))
		}
	}
	// 访问日志/运行日志脱敏测试同时确认错误文本不含密码。
	errText := func() string {
		_, err := env.authenticate("irene", wrongPassword, "203.0.113.93")
		return err.Error()
	}()
	if strings.Contains(errText, wrongPassword) {
		t.Error("公开错误文本包含密码")
	}
	if strings.Contains(env.logBuffer.String(), wrongPassword) {
		t.Error("认证失败日志包含密码")
	}
	// 步骤 29 不签发会话或令牌；后续步骤 50/54 的迁移会建立签名密钥与刷新令牌表，
	// 因此这里断言认证流程不写入任何令牌/密钥记录（而不是断言表不存在）。
	for _, table := range []string{"token_signing_keys", "refresh_token_families", "refresh_tokens"} {
		if got := env.queryInt(`SELECT COUNT(*) FROM ` + table); got != 0 {
			t.Fatalf("认证流程写入了令牌/密钥表 %s 的行数 = %d", table, got)
		}
	}
	// 等价断言：认证包不写会话行，也不依赖步骤 30 的 internal/session（认证成功
	// 不等于登录，会话签发必须由调用方显式完成）。
	if got := env.queryInt(`SELECT COUNT(*) FROM sessions`); got != 0 {
		t.Fatalf("认证流程写入了 %d 条会话行", got)
	}
	if importsSessionPackage(t) {
		t.Error("internal/authn 生产代码不应依赖 internal/session（认证不签发会话）")
	}
}

// importsSessionPackage 检查 internal/authn 的生产 Go 文件是否引用 internal/session。
func importsSessionPackage(t *testing.T) bool {
	t.Helper()
	found := false
	err := filepath.WalkDir(".", func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") ||
			strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(data), "EvernightLogin/internal/session") {
			found = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("扫描认证包源码失败: %v", err)
	}
	return found
}

// TestRootReadyTransitionStoreRule 验证 0008 ready 转换的数据库条件：只有
// setup_verified 且同一事务内已有正式密码凭证才能进入 ready；越级、无密码与重复
// 转换都返回状态冲突且失败事务不改变状态。
func TestRootReadyTransitionStoreRule(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	initialized, err := env.bootstrapSvc.Initialize(ctx, env.bootstrapUser, bootstrap.InitializeRequest{})
	if err != nil {
		t.Fatalf("root 初始化失败: %v", err)
	}
	rootID := initialized.Root.ID
	readyEvent := audit.Event{
		Actor:  audit.Actor{Type: audit.ActorLocalAdmin, ID: testOperator},
		Action: "root.ready.test",
		Target: audit.Target{Type: "root", ID: rootID},
	}
	markReady := func() error {
		return env.recorder.ExecuteCritical(ctx, audit.CriticalRequest{Event: readyEvent},
			func(txCtx context.Context, tx audit.Tx) error {
				return env.bootstrapDB.MarkReady(txCtx, tx, bootstrap.RootReadyChange{
					RootUserID: rootID, Now: env.clock.Now(),
				})
			})
	}
	// pending_setup 不能越级进入 ready。
	if err := markReady(); !errors.Is(err, bootstrap.ErrSetupStateConflict) {
		t.Fatalf("pending_setup 转 ready 错误 = %v，期望 ErrSetupStateConflict", err)
	}
	if state := env.queryString(`SELECT state FROM root_initializations WHERE singleton=1`); state != "pending_setup" {
		t.Fatalf("越级失败后状态 = %q，期望不变", state)
	}
	if _, err := env.bootstrapSvc.RedeemSetupCredential(ctx, env.bootstrapUser, bootstrap.RedeemSetupCredentialRequest{
		CredentialID: initialized.SetupCredential.ID,
		Secret:       initialized.SetupCredential.Secret.Reveal(),
	}); err != nil {
		t.Fatalf("兑换一次性配置凭证失败: %v", err)
	}
	// setup_verified 但没有正式密码凭证时仍拒绝 ready（防止无密码置 ready）。
	if err := markReady(); !errors.Is(err, bootstrap.ErrSetupStateConflict) {
		t.Fatalf("无密码转 ready 错误 = %v，期望 ErrSetupStateConflict", err)
	}
	if state := env.queryString(`SELECT state FROM root_initializations WHERE singleton=1`); state != "setup_verified" {
		t.Fatalf("无密码失败后状态 = %q，期望 setup_verified", state)
	}
	// 写入正式密码凭证后允许条件转换（强认证判断由正式密码服务在调用前完成）。
	hash, err := authn.HashPassword("Owner-Credential-9-A", testParams(), nil)
	if err != nil {
		t.Fatalf("生成测试哈希失败: %v", err)
	}
	env.insertCredential(rootID, hash)
	if err := markReady(); err != nil {
		t.Fatalf("有密码转 ready 失败: %v", err)
	}
	if state := env.queryString(`SELECT state FROM root_initializations WHERE singleton=1`); state != "ready" {
		t.Fatalf("ready 转换后状态 = %q", state)
	}
	if env.queryInt(`SELECT COUNT(*) FROM root_initializations WHERE singleton=1 AND ready_at_ms IS NOT NULL`) != 1 {
		t.Fatal("ready 转换缺少 ready_at_ms")
	}
	// 重复转换被条件更新拒绝，状态保持 ready。
	if err := markReady(); !errors.Is(err, bootstrap.ErrSetupStateConflict) {
		t.Fatalf("重复转 ready 错误 = %v，期望 ErrSetupStateConflict", err)
	}
}

// hasStep 报告步骤列表是否包含指定步骤。
func hasStep(steps []authn.Step, want authn.Step) bool {
	for _, step := range steps {
		if step == want {
			return true
		}
	}
	return false
}

// assignCustomPermissionRole 为系统范围自定义角色组合一个自定义权限并分配给用户，
// 用于验证强认证按“权限敏感度”而不是固定角色键判定。
func (e *testEnv) assignCustomPermissionRole(userID, roleKey, permissionKey string) {
	e.t.Helper()
	e.counter++
	permissionID := fmt.Sprintf("perm_%032x", e.counter)
	roleID := fmt.Sprintf("role_%032x", e.counter)
	nowMS := e.nowMS()
	if _, err := e.raw.ExecContext(context.Background(),
		`INSERT INTO permissions(id,scope_id,permission_key,name,description,limits_text,is_builtin,root_only,enabled,created_at_ms,updated_at_ms)
VALUES(?, 'system', ?, ?, '', '', 0, 0, 1, ?, ?)`,
		permissionID, permissionKey, "测试权限 "+permissionKey, nowMS, nowMS); err != nil {
		e.t.Fatalf("插入测试权限失败: %v", err)
	}
	if _, err := e.raw.ExecContext(context.Background(),
		`INSERT INTO roles(id,scope_id,role_key,name,description,limits_text,is_builtin,enabled,created_at_ms,updated_at_ms)
VALUES(?, 'system', ?, ?, '', '', 0, 1, ?, ?)`,
		roleID, roleKey, "测试角色 "+roleKey, nowMS, nowMS); err != nil {
		e.t.Fatalf("插入测试角色失败: %v", err)
	}
	if _, err := e.raw.ExecContext(context.Background(),
		`INSERT INTO role_permissions(role_id,permission_id,scope_id) VALUES(?,?,'system')`,
		roleID, permissionID); err != nil {
		e.t.Fatalf("插入测试角色权限失败: %v", err)
	}
	if _, err := e.raw.ExecContext(context.Background(),
		`INSERT INTO user_roles(user_id,role_id,scope_id,data_scope_json,assigned_by,created_at_ms)
VALUES(?,?,'system','{}','test',?)`, userID, roleID, nowMS); err != nil {
		e.t.Fatalf("插入测试角色分配失败: %v", err)
	}
}

// TestCustomSystemRoleRequiresStrongAuth 验证强认证按权限敏感度判定：持有高敏感
// 系统权限的自定义角色同样不得完整登录；只有无害权限的自定义角色不受影响。
func TestCustomSystemRoleRequiresStrongAuth(t *testing.T) {
	env := newTestEnv(t)
	highRiskID := env.insertUser("customadmin", account.StatusActive, false)
	env.assignCustomPermissionRole(highRiskID, "custom_audit_role", "audit.read")
	env.setPassword(highRiskID, testPassword, false)
	result, err := env.authenticate("customadmin", testPassword, "203.0.113.110")
	if err != nil {
		t.Fatalf("自定义高敏感角色登录错误: %v", err)
	}
	if result.Outcome != authn.OutcomePendingSecondFactor || !result.Restricted {
		t.Fatalf("自定义高敏感角色结果 = %+v，期望待第二因素受限", result)
	}
	if !hasStep(result.RequiredSteps, authn.StepStrongAuthSetup) {
		t.Fatalf("自定义高敏感角色待完成步骤 = %v，缺少强因素绑定", result.RequiredSteps)
	}

	harmlessID := env.insertUser("customuser", account.StatusActive, false)
	env.assignCustomPermissionRole(harmlessID, "custom_self_role", "self.profile.read")
	env.setPassword(harmlessID, testPassword, false)
	if result, err := env.authenticate("customuser", testPassword, "203.0.113.111"); err != nil {
		t.Fatalf("自定义无害角色登录错误: %v", err)
	} else if result.Outcome != authn.OutcomeComplete || result.Restricted {
		t.Fatalf("自定义无害角色结果 = %+v，期望完整登录", result)
	}
}

// TestIPv6AggregationAndSourceScopedLock 验证来源按 IPv6 /64 聚合：同一 /64 内
// 地址变体共享临时锁定，不同 /64 的来源不受影响。
func TestIPv6AggregationAndSourceScopedLock(t *testing.T) {
	env := newTestEnv(t)
	userID := env.insertUser("ivan", account.StatusActive, false)
	env.setPassword(userID, testPassword, false)
	for attempt := 0; attempt < 3; attempt++ {
		_, err := env.authenticate("ivan", "Wrong-Password-9-Z", "2001:db8:1:2::1")
		if attempt < 2 && !errors.Is(err, authn.ErrAuthenticationFailed) {
			t.Fatalf("第 %d 次失败错误 = %v", attempt+1, err)
		}
		if attempt == 2 && !errors.Is(err, authn.ErrRateLimited) {
			t.Fatalf("第三次失败错误 = %v，期望触发临时锁定", err)
		}
	}
	// 同一 /64 内的其他地址应共享锁定。
	_, err := env.authenticate("ivan", testPassword, "2001:db8:1:2::99")
	retryAfter, reason, limited := authn.AsRateLimit(err)
	if !limited || reason != "identifier_locked" || retryAfter <= 0 {
		t.Fatalf("同一 /64 变体 = (%v,%q,%v)，期望 identifier_locked", retryAfter, reason, limited)
	}
	// 不同 /64 来源不被该锁定阻止（账户维度只有渐进延迟）。
	if _, err := env.authenticate("ivan", testPassword, "2001:db8:1:3::1"); err != nil {
		t.Fatalf("不同 /64 来源登录失败: %v", err)
	}
}

// TestRootAccountNotLockedBySingleSource 验证单个来源无法锁死 root 账户：锁定只
// 作用于该来源组合，其他来源仍可用正确密码认证（root 仍受强认证限制）。
func TestRootAccountNotLockedBySingleSource(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	initialized, err := env.bootstrapSvc.Initialize(ctx, env.bootstrapUser, bootstrap.InitializeRequest{})
	if err != nil {
		t.Fatalf("root 初始化失败: %v", err)
	}
	if _, err := env.bootstrapSvc.RedeemSetupCredential(ctx, env.bootstrapUser, bootstrap.RedeemSetupCredentialRequest{
		CredentialID: initialized.SetupCredential.ID,
		Secret:       initialized.SetupCredential.Secret.Reveal(),
	}); err != nil {
		t.Fatalf("兑换一次性配置凭证失败: %v", err)
	}
	const rootPassword = "Owner-Credential-9-A"
	if _, err := env.service.SetRootPassword(ctx, env.localCaller, authn.SetRootPasswordRequest{
		NewPassword: rootPassword,
	}); err != nil {
		t.Fatalf("设置 root 密码失败: %v", err)
	}
	for attempt := 0; attempt < 3; attempt++ {
		_, err := env.authenticate("root", "Wrong-Password-9-Z", "198.51.100.60")
		if attempt < 2 && !errors.Is(err, authn.ErrAuthenticationFailed) {
			t.Fatalf("攻击来源第 %d 次失败错误 = %v", attempt+1, err)
		}
		if attempt == 2 && !errors.Is(err, authn.ErrRateLimited) {
			t.Fatalf("攻击来源第三次失败错误 = %v，期望触发临时锁定", err)
		}
	}
	if _, err := env.authenticate("root", rootPassword, "198.51.100.60"); !errors.Is(err, authn.ErrRateLimited) {
		t.Fatalf("攻击来源锁定期错误 = %v，期望 RATE_LIMITED", err)
	}
	// 其他来源不受影响：root 密码正确，但仍只能得到待强认证结果。
	result, err := env.authenticate("root", rootPassword, "198.51.100.61")
	if err != nil {
		t.Fatalf("其他来源 root 登录错误: %v", err)
	}
	if result.Outcome != authn.OutcomePendingSecondFactor || result.IsComplete() {
		t.Fatalf("其他来源 root 结果 = %+v，期望待第二因素", result)
	}
}

// TestSweepGuardDeniesIdentifierFanout 验证单一来源对大量不同标识失败会被限流，
// 防止用唯一标识灌入失败跟踪表。
func TestSweepGuardDeniesIdentifierFanout(t *testing.T) {
	env := newTestEnv(t)
	service := env.newService(func(options *authn.Options) {
		options.FailurePolicy = authn.FailurePolicy{
			Window: time.Minute, MaxFailures: 100, LockDuration: time.Minute,
			MaxLockDuration: time.Minute, DelayBase: time.Microsecond,
			DelayMax: time.Microsecond, MaxEntries: 64,
			MaxSweepIdentifiers: 5, MaxSweepEntries: 16,
		}
		options.RateLimitPolicy = authn.RateLimitPolicy{
			IP:        ratelimitPolicy(1000, time.Minute),
			Operation: ratelimitPolicy(10000, time.Minute),
		}
	})
	for index := 0; index < 5; index++ {
		_, err := service.Authenticate(context.Background(), authn.AuthenticateRequest{
			Identifier: fmt.Sprintf("sweep-%d", index),
			Password:   testPassword,
			ClientIP:   "203.0.113.120",
		})
		if !errors.Is(err, authn.ErrAuthenticationFailed) {
			t.Fatalf("第 %d 个标识错误 = %v", index+1, err)
		}
	}
	_, err := service.Authenticate(context.Background(), authn.AuthenticateRequest{
		Identifier: "sweep-overflow",
		Password:   testPassword,
		ClientIP:   "203.0.113.120",
	})
	retryAfter, reason, limited := authn.AsRateLimit(err)
	if !limited || reason != "identifier_sweep" || retryAfter <= 0 {
		t.Fatalf("标识扫描超限 = (%v,%q,%v)，期望 identifier_sweep", retryAfter, reason, limited)
	}
	// 其他来源不受该来源的扫描阈值影响。
	if _, err := service.Authenticate(context.Background(), authn.AuthenticateRequest{
		Identifier: "sweep-other",
		Password:   testPassword,
		ClientIP:   "203.0.113.121",
	}); !errors.Is(err, authn.ErrAuthenticationFailed) {
		t.Fatalf("其他来源错误 = %v", err)
	}
}

// TestSelfChangeReauthThrottled 验证普通用户自助改密的当前密码复核与登录共用
// 失败限制：同一来源多次错误后临时锁定，其他来源与正确密码不受影响。
func TestSelfChangeReauthThrottled(t *testing.T) {
	env := newTestEnv(t)
	userID := env.insertUser("judy", account.StatusActive, false)
	env.setPassword(userID, testPassword, false)
	userCaller, err := authn.UserCaller(userID)
	if err != nil {
		t.Fatalf("构造用户调用者失败: %v", err)
	}
	const attackIP = "203.0.113.130"
	for attempt := 0; attempt < 3; attempt++ {
		_, err := env.service.SetPassword(context.Background(), userCaller, authn.SetPasswordRequest{
			TargetUserID:    userID,
			NewPassword:     "New-Credential-9-B",
			CurrentPassword: "Wrong-Current-9-Z",
			ClientIP:        attackIP,
		})
		if attempt < 2 && !errors.Is(err, authn.ErrAuthenticationFailed) {
			t.Fatalf("第 %d 次复核失败错误 = %v", attempt+1, err)
		}
		if attempt == 2 && !errors.Is(err, authn.ErrRateLimited) {
			t.Fatalf("第三次复核失败错误 = %v，期望触发临时锁定", err)
		}
	}
	_, err = env.service.SetPassword(context.Background(), userCaller, authn.SetPasswordRequest{
		TargetUserID:    userID,
		NewPassword:     "New-Credential-9-B",
		CurrentPassword: testPassword,
		ClientIP:        attackIP,
	})
	if _, reason, limited := authn.AsRateLimit(err); !limited || reason != "identifier_locked" {
		t.Fatalf("锁定期正确当前密码 = (%q,%v)，期望 identifier_locked", reason, limited)
	}
	// 其他来源可用正确当前密码完成改密。
	if _, err := env.service.SetPassword(context.Background(), userCaller, authn.SetPasswordRequest{
		TargetUserID:    userID,
		NewPassword:     "New-Credential-9-B",
		CurrentPassword: testPassword,
		ClientIP:        "203.0.113.131",
	}); err != nil {
		t.Fatalf("其他来源改密失败: %v", err)
	}
}

// TestSuccessfulLoginDoesNotConsumeIPBudget 验证地址/操作维度只统计失败：多次成功
// 登录不消耗失败预算，而超限后的失败请求返回 RATE_LIMITED。
func TestSuccessfulLoginDoesNotConsumeIPBudget(t *testing.T) {
	env := newTestEnv(t)
	userID := env.insertUser("kate", account.StatusActive, false)
	env.setPassword(userID, testPassword, false)
	service := env.newService(func(options *authn.Options) {
		options.RateLimitPolicy = authn.RateLimitPolicy{
			IP:        ratelimitPolicy(2, time.Minute),
			Operation: ratelimitPolicy(10000, time.Minute),
		}
		options.FailurePolicy = authn.FailurePolicy{
			Window: time.Minute, MaxFailures: 100, LockDuration: time.Minute,
			MaxLockDuration: time.Minute, DelayBase: time.Microsecond,
			DelayMax: time.Microsecond, MaxEntries: 64,
			MaxSweepIdentifiers: 100, MaxSweepEntries: 16,
		}
	})
	const ip = "203.0.113.140"
	for attempt := 0; attempt < 5; attempt++ {
		if _, err := service.Authenticate(context.Background(), authn.AuthenticateRequest{
			Identifier: "kate", Password: testPassword, ClientIP: ip,
		}); err != nil {
			t.Fatalf("第 %d 次成功登录被拒绝: %v", attempt+1, err)
		}
	}
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := service.Authenticate(context.Background(), authn.AuthenticateRequest{
			Identifier: "kate", Password: "Wrong-Password-9-Z", ClientIP: ip,
		}); !errors.Is(err, authn.ErrAuthenticationFailed) {
			t.Fatalf("第 %d 次失败错误 = %v", attempt+1, err)
		}
	}
	_, err := service.Authenticate(context.Background(), authn.AuthenticateRequest{
		Identifier: "kate", Password: "Wrong-Password-9-Z", ClientIP: ip,
	})
	if _, reason, limited := authn.AsRateLimit(err); !limited || reason != "ip_limit" {
		t.Fatalf("失败预算耗尽 = (%q,%v)，期望 ip_limit", reason, limited)
	}
}

// TestPasswordWorkConcurrencyBounded 验证 Argon2 工作槽位有界：单槽位 + 短排队
// 超时下并发认证会出现 fail-closed 的 RATE_LIMITED（password_work_busy）。
func TestPasswordWorkConcurrencyBounded(t *testing.T) {
	env := newTestEnv(t)
	service := env.newService(func(options *authn.Options) {
		options.Params = authn.Params{MemoryKiB: 19456, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32}
		options.MaxConcurrentPasswordWork = 1
		options.PasswordWorkQueueTimeout = 10 * time.Millisecond
	})
	const workers = 8
	var waitGroup sync.WaitGroup
	results := make(chan error, workers)
	for worker := 0; worker < workers; worker++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			_, err := service.Authenticate(context.Background(), authn.AuthenticateRequest{
				Identifier: "nobody",
				Password:   testPassword,
				ClientIP:   "203.0.113.150",
			})
			results <- err
		}()
	}
	waitGroup.Wait()
	close(results)
	busy := 0
	for err := range results {
		if _, reason, limited := authn.AsRateLimit(err); limited && reason == "password_work_busy" {
			busy++
			continue
		}
		if !errors.Is(err, authn.ErrAuthenticationFailed) {
			t.Fatalf("并发认证出现未预期错误: %v", err)
		}
	}
	if busy == 0 {
		t.Fatal("单槽位 + 10ms 排队超时下没有出现 password_work_busy，并发上限可能未生效")
	}
}

// fakeStrongFactorPresence 是强因素存在性测试替身。
type fakeStrongFactorPresence struct{ has bool }

func (f *fakeStrongFactorPresence) HasStrongFactor(ctx context.Context, userID string) (bool, error) {
	return f.has, nil
}
