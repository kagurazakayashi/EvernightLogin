package bootstrap_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	accountsqlite "github.com/kagurazakayashi/EvernightLogin/internal/account/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/bootstrap"
	bootstrapsqlite "github.com/kagurazakayashi/EvernightLogin/internal/bootstrap/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/credential"
	credentialsqlite "github.com/kagurazakayashi/EvernightLogin/internal/credential/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const (
	testOperator = "local-admin-1"
	testOther    = "local-admin-2"
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

// testEnv 汇总一次测试使用的临时 SQLite 数据库、生产仓储、真实凭证服务与审计。
type testEnv struct {
	t           *testing.T
	dbPath      string
	raw         *storagesqlite.Store
	store       *bootstrapsqlite.Store
	credentials *credential.Service
	auditStore  *auditsqlite.Store
	recorder    *audit.Recorder
	service     *bootstrap.Service
	caller      bootstrap.Caller
	clock       *fakeClock
	ring        *secrets.Keyring
}

// newTestEnv 在临时目录创建数据库并执行全部迁移，然后构造真实生产依赖。
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	return newTestEnvAtPath(t, filepath.Join(t.TempDir(), "bootstrap.sqlite"))
}

// newTestEnvAtPath 在指定数据库路径上构造测试环境，用于模拟进程重启。
func newTestEnvAtPath(t *testing.T, dbPath string) *testEnv {
	t.Helper()
	ctx := context.Background()
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(dbPath))
	if err != nil {
		t.Fatalf("打开临时 SQLite 数据库失败: %v", err)
	}
	t.Cleanup(func() {
		_ = raw.Close()
	})
	migrationSet, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移失败: %v", err)
	}
	if _, err := raw.Migrate(ctx, migrationSet); err != nil {
		t.Fatalf("执行迁移失败: %v", err)
	}
	clock := &fakeClock{now: testBaseTime}
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
	auditStore, err := auditsqlite.New(raw)
	if err != nil {
		t.Fatalf("构造审计仓储失败: %v", err)
	}
	recorder, err := audit.New(auditStore, audit.Options{Now: clock.Now})
	if err != nil {
		t.Fatalf("构造审计写入器失败: %v", err)
	}
	store, err := bootstrapsqlite.New(raw)
	if err != nil {
		t.Fatalf("构造初始化仓储失败: %v", err)
	}
	authorizer, err := bootstrap.NewLocalBootstrapAuthorizer([]string{testOperator})
	if err != nil {
		t.Fatalf("构造本地授权器失败: %v", err)
	}
	caller, err := bootstrap.LocalBootstrapCaller(testOperator)
	if err != nil {
		t.Fatalf("构造本地调用者失败: %v", err)
	}
	service, err := bootstrap.New(bootstrap.Options{
		Store:       store,
		Audit:       recorder,
		Authorizer:  authorizer,
		Credentials: credentialService,
		Now:         clock.Now,
	})
	if err != nil {
		t.Fatalf("构造初始化服务失败: %v", err)
	}
	return &testEnv{
		t:           t,
		dbPath:      dbPath,
		raw:         raw,
		store:       store,
		credentials: credentialService,
		auditStore:  auditStore,
		recorder:    recorder,
		service:     service,
		caller:      caller,
		clock:       clock,
		ring:        ring,
	}
}

// newServiceWith 用同一数据库但可替换存储/审计构造新服务，用于故障注入与重启。
func (e *testEnv) newServiceWith(store bootstrap.Store, recorder bootstrap.AuditRecorder) *bootstrap.Service {
	e.t.Helper()
	authorizer, err := bootstrap.NewLocalBootstrapAuthorizer([]string{testOperator})
	if err != nil {
		e.t.Fatalf("构造本地授权器失败: %v", err)
	}
	service, err := bootstrap.New(bootstrap.Options{
		Store:       store,
		Audit:       recorder,
		Authorizer:  authorizer,
		Credentials: e.credentials,
		Now:         e.clock.Now,
	})
	if err != nil {
		e.t.Fatalf("构造初始化服务失败: %v", err)
	}
	return service
}

// initialize 执行一次成功的首次初始化。
func (e *testEnv) initialize(request bootstrap.InitializeRequest) bootstrap.InitializeResult {
	e.t.Helper()
	result, err := e.service.Initialize(context.Background(), e.caller, request)
	if err != nil {
		e.t.Fatalf("Initialize 失败: %v", err)
	}
	return result
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

// insertRootDirectly 直接插入 is_root=1 的 root 行，模拟旧版本/人工数据留下的
// “有 root 但无初始化记录”场景。
func (e *testEnv) insertRootDirectly() string {
	e.t.Helper()
	rootID := "usr_11111111111111111111111111111111"
	now := testBaseTime.UnixMilli()
	_, err := e.raw.ExecContext(context.Background(),
		`INSERT INTO users(id,username,username_normalized,nickname,biography,language,timezone,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'','','zh-CN','Asia/Shanghai','active',1,1,1,?,?)`,
		rootID, bootstrap.RootUsername, bootstrap.RootUsernameNormalized, now, now)
	if err != nil {
		e.t.Fatalf("插入 root 行失败: %v", err)
	}
	return rootID
}

// TestInitializeCreatesSinglePendingRoot 验证首次初始化只创建一个受限待配置 root，
// 不存密码、不签发会话，且配置凭证只保存摘要。
func TestInitializeCreatesSinglePendingRoot(t *testing.T) {
	env := newTestEnv(t)
	result := env.initialize(bootstrap.InitializeRequest{SetupCredentialTTL: 10 * time.Minute})

	if result.State != bootstrap.StatePendingSetup {
		t.Errorf("初始化状态 = %q，期望 pending_setup", result.State)
	}
	if !account.ValidUserID(result.Root.ID) || result.Root.Username != bootstrap.RootUsername {
		t.Errorf("root 快照 = %+v", result.Root)
	}
	if result.Root.Status != account.StatusActive {
		t.Errorf("root 状态 = %q，期望 active", result.Root.Status)
	}
	if !result.SetupCredential.Secret.IsSet() {
		t.Error("初始化结果缺少一次性配置凭证秘密")
	}
	if result.SetupCredential.Purpose != bootstrap.PurposeRootSetup {
		t.Errorf("凭证用途 = %q", result.SetupCredential.Purpose)
	}
	if result.SetupCredential.Target != result.Root.ID {
		t.Error("配置凭证目标未绑定到新 root 用户 ID")
	}
	if result.SetupCredential.ExpiresAt.Sub(testBaseTime) != 10*time.Minute {
		t.Errorf("凭证有效期 = %v", result.SetupCredential.ExpiresAt.Sub(testBaseTime))
	}

	// 数据库：唯一 root、单例初始化记录、无密码材料/会话表。
	if got := env.queryInt(`SELECT COUNT(*) FROM users`); got != 1 {
		t.Errorf("用户数 = %d，期望 1", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM users WHERE is_root=1`); got != 1 {
		t.Errorf("root 用户数 = %d，期望 1", got)
	}
	if got := env.queryString(`SELECT status FROM users WHERE is_root=1`); got != "active" {
		t.Errorf("root 状态 = %q", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM root_initializations`); got != 1 {
		t.Errorf("初始化记录数 = %d，期望 1", got)
	}
	if got := env.queryString(`SELECT state FROM root_initializations WHERE singleton=1`); got != "pending_setup" {
		t.Errorf("初始化记录状态 = %q", got)
	}
	if got := env.queryString(`SELECT root_user_id FROM root_initializations WHERE singleton=1`); got != result.Root.ID {
		t.Errorf("初始化记录 root ID = %q", got)
	}
	// 凭证只保存 32 字节摘要，明文不得落库。
	if got := env.queryInt(`SELECT COUNT(*) FROM one_time_credentials WHERE purpose=? AND subject_id=?`,
		bootstrap.PurposeRootSetup, result.Root.ID); got != 1 {
		t.Errorf("配置凭证行数 = %d，期望 1", got)
	}
	if got := env.queryInt(`SELECT length(verifier_hash) FROM one_time_credentials WHERE purpose=?`,
		bootstrap.PurposeRootSetup); got != 32 {
		t.Errorf("凭证摘要长度 = %d，期望 32", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM one_time_credentials WHERE instr(CAST(verifier_hash AS TEXT), ?)>0`,
		result.SetupCredential.Secret.Reveal()); got != 0 {
		t.Error("凭证明文出现在 verifier_hash 中")
	}
	// 本步不允许 root 初始化自身写入密码材料，也不提前创建会话表；密码凭证表
	// 由迁移 0009 建立但初始化必须保持为空（正式密码由步骤 29 的密码服务写入）。
	if got := env.queryInt(`SELECT COUNT(*) FROM pragma_table_info('users') WHERE name LIKE '%password%'`); got != 0 {
		t.Error("users 表提前出现密码列")
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM password_credentials`); got != 0 {
		t.Errorf("root 初始化写入了密码凭证行数 = %d，期望 0", got)
	}
	// root 初始化不得写入会话行（会话表由后续步骤的迁移建立，例如步骤 30 的
	// sessions），也不得提前创建令牌表。
	for _, table := range []string{"refresh_tokens", "oauth_grants"} {
		if got := env.queryInt(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table); got != 0 {
			t.Errorf("提前创建了表 %s", table)
		}
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='sessions'`); got == 1 {
		if rows := env.queryInt(`SELECT COUNT(*) FROM sessions`); rows != 0 {
			t.Errorf("root 初始化写入了会话行 = %d，期望 0", rows)
		}
	}
	// 成功审计存在且不含凭证明文。
	if got := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action=? AND outcome='success'`,
		string(bootstrap.ActionInitialize)); got != 1 {
		t.Errorf("初始化成功审计数 = %d，期望 1", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE instr(detail_json, ?)>0`,
		result.SetupCredential.Secret.Reveal()); got != 0 {
		t.Error("安全审计泄露了凭证明文")
	}
}

// TestInitializeRejectsRepeatRun 验证重复运行被拒绝且不产生第二个 root 或凭证。
func TestInitializeRejectsRepeatRun(t *testing.T) {
	env := newTestEnv(t)
	env.initialize(bootstrap.InitializeRequest{})

	_, err := env.service.Initialize(context.Background(), env.caller, bootstrap.InitializeRequest{})
	if !errors.Is(err, bootstrap.ErrAlreadyInitialized) {
		t.Fatalf("重复初始化错误 = %v，期望 ErrAlreadyInitialized", err)
	}
	if code := bootstrap.CodeOf(err); code != bootstrap.CodeConflict {
		t.Errorf("重复初始化错误码 = %q，期望 CONFLICT", code)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM users`); got != 1 {
		t.Errorf("重复初始化后用户数 = %d，期望 1", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM root_initializations`); got != 1 {
		t.Errorf("重复初始化后记录数 = %d，期望 1", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM one_time_credentials`); got != 1 {
		t.Errorf("重复初始化后凭证数 = %d，期望 1", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE outcome='failure' AND error_code='CONFLICT'`); got != 1 {
		t.Errorf("重复初始化失败审计数 = %d，期望 1", got)
	}
}

// TestInitializeRejectsExistingRootWithoutRecord 验证已有 root（无初始化记录）时
// 不自动接管、不重复创建，并如实报告 existing_root 诊断状态。
func TestInitializeRejectsExistingRootWithoutRecord(t *testing.T) {
	env := newTestEnv(t)
	rootID := env.insertRootDirectly()

	_, err := env.service.Initialize(context.Background(), env.caller, bootstrap.InitializeRequest{})
	if !errors.Is(err, bootstrap.ErrAlreadyInitialized) {
		t.Fatalf("已有 root 时初始化错误 = %v，期望 ErrAlreadyInitialized", err)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM users`); got != 1 {
		t.Errorf("用户数 = %d，期望 1", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM root_initializations`); got != 0 {
		t.Errorf("初始化记录数 = %d，期望 0（不自动接管）", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM one_time_credentials`); got != 0 {
		t.Errorf("凭证数 = %d，期望 0（失败不遗留）", got)
	}

	status, err := env.service.Status(context.Background(), env.caller)
	if err != nil {
		t.Fatalf("Status 失败: %v", err)
	}
	if status.State != bootstrap.StateExistingRoot || !status.Initialized() || status.RootUserID != rootID {
		t.Errorf("状态 = %+v，期望 existing_root 且带 root ID", status)
	}
	if !strings.Contains(status.Explanation(), "旧版本") {
		t.Errorf("诊断说明缺少原因提示: %s", status.Explanation())
	}
}

// TestConcurrentInitializeSingleRoot 验证多 goroutine 并发初始化只有一个成功，
// 数据库始终最多一个 root 与一条初始化记录。
func TestConcurrentInitializeSingleRoot(t *testing.T) {
	env := newTestEnv(t)
	const workers = 6
	var wait sync.WaitGroup
	results := make([]error, workers)
	wait.Add(workers)
	for index := 0; index < workers; index++ {
		go func(index int) {
			defer wait.Done()
			_, err := env.service.Initialize(context.Background(), env.caller, bootstrap.InitializeRequest{})
			results[index] = err
		}(index)
	}
	wait.Wait()

	success := 0
	for index, err := range results {
		switch {
		case err == nil:
			success++
		case errors.Is(err, bootstrap.ErrAlreadyInitialized):
			// 预期失败。
		default:
			t.Errorf("并发初始化 %d 错误 = %v", index, err)
		}
	}
	if success != 1 {
		t.Fatalf("并发初始化成功数 = %d，期望 1", success)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM users WHERE is_root=1`); got != 1 {
		t.Errorf("并发初始化后 root 数 = %d，期望 1", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM root_initializations`); got != 1 {
		t.Errorf("并发初始化后记录数 = %d，期望 1", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM one_time_credentials WHERE purpose=?`,
		bootstrap.PurposeRootSetup); got != 1 {
		t.Errorf("并发初始化后配置凭证数 = %d，期望 1（失败者不签发凭证）", got)
	}
}

// TestConcurrentInitializeAcrossServices 验证两个独立 Store/Service 实例（同一
// 临时 SQLite 数据库、各自连接与进程内互斥）并发初始化时，数据库条件插入与唯一
// 约束仍保证仅一个成功，不会产生两个 root。
func TestConcurrentInitializeAcrossServices(t *testing.T) {
	first := newTestEnv(t)
	second := newTestEnvAtPath(t, first.dbPath)
	if first.dbPath != second.dbPath {
		t.Fatalf("两个测试环境未共用同一数据库: %q != %q", first.dbPath, second.dbPath)
	}

	var wait sync.WaitGroup
	errs := make([]error, 2)
	wait.Add(2)
	go func() {
		defer wait.Done()
		_, errs[0] = first.service.Initialize(context.Background(), first.caller, bootstrap.InitializeRequest{})
	}()
	go func() {
		defer wait.Done()
		_, errs[1] = second.service.Initialize(context.Background(), second.caller, bootstrap.InitializeRequest{})
	}()
	wait.Wait()

	success := 0
	for index, err := range errs {
		switch {
		case err == nil:
			success++
		case errors.Is(err, bootstrap.ErrAlreadyInitialized),
			errors.Is(err, bootstrap.ErrStoreUnavailable):
			// 多实例并发路径允许两种可诊断结果：明确发现已初始化，或 SQLite
			// 写冲突被映射为可重试的存储不可用（调用方重试后会得到已初始化）。
		default:
			t.Errorf("独立实例并发初始化 %d 错误 = %v，期望成功/已初始化/存储忙", index, err)
		}
	}
	if success != 1 {
		t.Fatalf("独立实例并发初始化成功数 = %d，期望 1", success)
	}
	// 两个连接都只看到唯一 root、单例记录与一条可用配置凭证。
	if got := second.queryInt(`SELECT COUNT(*) FROM users WHERE is_root=1`); got != 1 {
		t.Errorf("root 数 = %d，期望 1", got)
	}
	if got := second.queryInt(`SELECT COUNT(*) FROM root_initializations`); got != 1 {
		t.Errorf("初始化记录数 = %d，期望 1", got)
	}
	if got := second.queryInt(`SELECT COUNT(*) FROM one_time_credentials
WHERE purpose=? AND consumed_at_ms IS NULL AND revoked_at_ms IS NULL AND expires_at_ms>?`,
		bootstrap.PurposeRootSetup, testBaseTime.UnixMilli()); got != 1 {
		t.Errorf("可用配置凭证数 = %d，期望 1（失败实例凭证应被撤销/未落库）", got)
	}
	if got := second.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action=? AND outcome='success'`,
		string(bootstrap.ActionInitialize)); got != 1 {
		t.Errorf("初始化成功审计数 = %d，期望 1", got)
	}
}

// TestRedeemSetupCredential 覆盖一次性配置凭证的兑换、错误秘密、重放与状态推进。
func TestRedeemSetupCredential(t *testing.T) {
	env := newTestEnv(t)
	issued := env.initialize(bootstrap.InitializeRequest{})

	status, err := env.service.Status(context.Background(), env.caller)
	if err != nil {
		t.Fatalf("Status 失败: %v", err)
	}
	if status.State != bootstrap.StatePendingSetup || !status.SetupCredentialUsable ||
		status.SetupCredentialID != issued.SetupCredential.ID {
		t.Errorf("初始化后状态 = %+v", status)
	}
	if strings.Contains(fmt.Sprintf("%+v", status), issued.SetupCredential.Secret.Reveal()) {
		t.Error("状态快照泄露凭证明文")
	}

	// 错误秘密：统一凭证无效，状态不变，不消耗高熵令牌尝试次数。
	_, err = env.service.RedeemSetupCredential(context.Background(), env.caller,
		bootstrap.RedeemSetupCredentialRequest{CredentialID: issued.SetupCredential.ID, Secret: "wrong-secret"})
	if !errors.Is(err, bootstrap.ErrSetupCredentialInvalid) {
		t.Fatalf("错误秘密兑换错误 = %v", err)
	}
	if code := bootstrap.CodeOf(err); code != bootstrap.CodeTokenInvalid {
		t.Errorf("凭证无效错误码 = %q，期望 TOKEN_INVALID", code)
	}
	status, err = env.service.Status(context.Background(), env.caller)
	if err != nil {
		t.Fatalf("错误尝试后 Status 失败: %v", err)
	}
	if status.State != bootstrap.StatePendingSetup || !status.SetupCredentialUsable {
		t.Errorf("错误尝试后状态 = %+v", status)
	}

	// 正确兑换。
	grant, err := env.service.RedeemSetupCredential(context.Background(), env.caller,
		bootstrap.RedeemSetupCredentialRequest{
			CredentialID: issued.SetupCredential.ID,
			Secret:       issued.SetupCredential.Secret.Reveal(),
		})
	if err != nil {
		t.Fatalf("兑换失败: %v", err)
	}
	if grant.State != bootstrap.StateSetupVerified || grant.RootUserID != issued.Root.ID ||
		grant.RootUsername != bootstrap.RootUsername || grant.CredentialID != issued.SetupCredential.ID {
		t.Errorf("兑换结果 = %+v", grant)
	}
	status, err = env.service.Status(context.Background(), env.caller)
	if err != nil {
		t.Fatalf("兑换后 Status 失败: %v", err)
	}
	if status.State != bootstrap.StateSetupVerified || status.VerifiedAt == nil ||
		status.SetupCredentialUsable || status.SetupCredentialConsumedAt == nil {
		t.Errorf("兑换后状态 = %+v", status)
	}
	if !strings.Contains(status.Explanation(), "会话") {
		t.Errorf("兑换后说明未声明不是会话: %s", status.Explanation())
	}

	// 重放兑换：状态已推进，返回状态冲突且不重复消费。
	_, err = env.service.RedeemSetupCredential(context.Background(), env.caller,
		bootstrap.RedeemSetupCredentialRequest{
			CredentialID: issued.SetupCredential.ID,
			Secret:       issued.SetupCredential.Secret.Reveal(),
		})
	if !errors.Is(err, bootstrap.ErrSetupStateConflict) {
		t.Fatalf("重放兑换错误 = %v，期望 ErrSetupStateConflict", err)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM users WHERE is_root=1`); got != 1 {
		t.Errorf("root 数 = %d", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM root_initializations WHERE state='setup_verified'`); got != 1 {
		t.Errorf("setup_verified 记录数 = %d", got)
	}
}

// TestCredentialExpiryAndReissue 验证受限初始化凭证过期后拒绝兑换，并可通过本地
// 重新签发恢复；重签会撤销旧凭证，不重建 root。
func TestCredentialExpiryAndReissue(t *testing.T) {
	env := newTestEnv(t)
	issued := env.initialize(bootstrap.InitializeRequest{SetupCredentialTTL: 5 * time.Minute})

	env.clock.Advance(6 * time.Minute)
	status, err := env.service.Status(context.Background(), env.caller)
	if err != nil {
		t.Fatalf("Status 失败: %v", err)
	}
	if status.SetupCredentialUsable || !status.NeedsSetupCredential() {
		t.Errorf("过期后状态 = %+v，期望不可用且需要重签", status)
	}
	_, err = env.service.RedeemSetupCredential(context.Background(), env.caller,
		bootstrap.RedeemSetupCredentialRequest{
			CredentialID: issued.SetupCredential.ID,
			Secret:       issued.SetupCredential.Secret.Reveal(),
		})
	if !errors.Is(err, bootstrap.ErrSetupCredentialInvalid) {
		t.Fatalf("过期凭证兑换错误 = %v", err)
	}

	reissued, err := env.service.ReissueSetupCredential(context.Background(), env.caller,
		bootstrap.ReissueSetupCredentialRequest{SetupCredentialTTL: 5 * time.Minute})
	if err != nil {
		t.Fatalf("重新签发失败: %v", err)
	}
	if reissued.SetupCredential.ID == issued.SetupCredential.ID {
		t.Error("重签凭证 ID 未变化")
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM one_time_credentials WHERE id=? AND revoked_at_ms IS NOT NULL`,
		issued.SetupCredential.ID); got != 1 {
		t.Errorf("旧凭证未撤销，行数 = %d", got)
	}
	// 旧凭证即使未过期也已被替换撤销。
	if _, err := env.service.RedeemSetupCredential(context.Background(), env.caller,
		bootstrap.RedeemSetupCredentialRequest{
			CredentialID: issued.SetupCredential.ID,
			Secret:       issued.SetupCredential.Secret.Reveal(),
		}); !errors.Is(err, bootstrap.ErrSetupCredentialInvalid) {
		t.Fatalf("旧凭证兑换错误 = %v", err)
	}
	// 新凭证可用，且 root 仍然只有一个。
	if _, err := env.service.RedeemSetupCredential(context.Background(), env.caller,
		bootstrap.RedeemSetupCredentialRequest{
			CredentialID: reissued.SetupCredential.ID,
			Secret:       reissued.SetupCredential.Secret.Reveal(),
		}); err != nil {
		t.Fatalf("新凭证兑换失败: %v", err)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM users WHERE is_root=1`); got != 1 {
		t.Errorf("root 数 = %d，期望 1", got)
	}
}

// TestReissueRejectsUninitializedAndReady 验证未初始化与已完成初始化后重签均被拒绝。
func TestReissueRejectsUninitializedAndReady(t *testing.T) {
	env := newTestEnv(t)
	if _, err := env.service.ReissueSetupCredential(context.Background(), env.caller,
		bootstrap.ReissueSetupCredentialRequest{}); !errors.Is(err, bootstrap.ErrNotInitialized) {
		t.Fatalf("未初始化重签错误 = %v，期望 ErrNotInitialized", err)
	}
	issued := env.initialize(bootstrap.InitializeRequest{})

	// 模拟后续正式密码服务完成初始化：状态推进为 ready（本步不提供转换方法）。
	now := testBaseTime.UnixMilli()
	if _, err := env.raw.ExecContext(context.Background(),
		`UPDATE root_initializations SET state='ready',verified_at_ms=?,ready_at_ms=?,updated_at_ms=? WHERE singleton=1`,
		now, now, now); err != nil {
		t.Fatalf("模拟 ready 状态失败: %v", err)
	}
	if _, err := env.service.ReissueSetupCredential(context.Background(), env.caller,
		bootstrap.ReissueSetupCredentialRequest{}); !errors.Is(err, bootstrap.ErrAlreadyInitialized) {
		t.Fatalf("ready 后重签错误 = %v，期望 ErrAlreadyInitialized", err)
	}
	if _, err := env.service.Initialize(context.Background(), env.caller,
		bootstrap.InitializeRequest{}); !errors.Is(err, bootstrap.ErrAlreadyInitialized) {
		t.Fatalf("ready 后初始化错误 = %v", err)
	}
	status, err := env.service.Status(context.Background(), env.caller)
	if err != nil {
		t.Fatalf("Status 失败: %v", err)
	}
	if status.State != bootstrap.StateReady || status.ReadyAt == nil {
		t.Errorf("ready 状态快照 = %+v", status)
	}
	// 凭证仍保留引用但不可再用（兑换已在 ready 前被拒绝）。
	if issued.SetupCredential.ID == "" {
		t.Fatal("签发结果为空")
	}
}

// TestInitializeRollsBackOnStoreFailure 验证 root 创建中途失败整体回滚，且失败后
// 可重新初始化；失败尝试的凭证被撤销。
func TestInitializeRollsBackOnStoreFailure(t *testing.T) {
	env := newTestEnv(t)
	failingStore := &failingCreateStore{Store: env.store}
	failingService := env.newServiceWith(failingStore, env.recorder)

	_, err := failingService.Initialize(context.Background(), env.caller, bootstrap.InitializeRequest{})
	if err == nil {
		t.Fatal("注入失败的初始化应返回错误")
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM users`); got != 0 {
		t.Errorf("失败后用户数 = %d，期望 0（事务回滚）", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM root_initializations`); got != 0 {
		t.Errorf("失败后初始化记录数 = %d，期望 0", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE outcome='failure' AND action=?`,
		string(bootstrap.ActionInitialize)); got != 1 {
		t.Errorf("失败审计数 = %d，期望 1", got)
	}
	// 失败尝试签发的一次性凭证应被尽力撤销，不能留下可用入口。
	if got := env.queryInt(`SELECT COUNT(*) FROM one_time_credentials WHERE purpose=? AND revoked_at_ms IS NOT NULL`,
		bootstrap.PurposeRootSetup); got != 1 {
		t.Errorf("失败尝试凭证撤销数 = %d，期望 1", got)
	}

	// 使用真实存储的新服务重试成功（初始化入口未因部分失败而永久关闭）。
	retryService := env.newServiceWith(env.store, env.recorder)
	result, err := retryService.Initialize(context.Background(), env.caller, bootstrap.InitializeRequest{})
	if err != nil {
		t.Fatalf("失败后重试 Initialize 失败: %v", err)
	}
	if result.State != bootstrap.StatePendingSetup {
		t.Errorf("重试状态 = %q", result.State)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM users WHERE is_root=1`); got != 1 {
		t.Errorf("重试后 root 数 = %d", got)
	}
}

// TestInitializeAuditFailureRejects 验证审计不可用时初始化被拒绝且库不变。
func TestInitializeAuditFailureRejects(t *testing.T) {
	env := newTestEnv(t)
	failingService := env.newServiceWith(env.store, failingAudit{Recorder: env.recorder})

	_, err := failingService.Initialize(context.Background(), env.caller, bootstrap.InitializeRequest{})
	if !errors.Is(err, bootstrap.ErrAuditUnavailable) {
		t.Fatalf("审计故障初始化错误 = %v，期望 ErrAuditUnavailable", err)
	}
	if code := bootstrap.CodeOf(err); code != bootstrap.CodeAuditWriteFailed {
		t.Errorf("审计故障错误码 = %q，期望 AUDIT_WRITE_FAILED", code)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM users`); got != 0 {
		t.Errorf("审计故障后用户数 = %d，期望 0", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM root_initializations`); got != 0 {
		t.Errorf("审计故障后记录数 = %d，期望 0", got)
	}
}

// TestStatusReadAuditFailClosed 验证状态读取审计失败时拒绝返回数据。
func TestStatusReadAuditFailClosed(t *testing.T) {
	env := newTestEnv(t)
	failingService := env.newServiceWith(env.store, failingRecordAudit{Recorder: env.recorder})
	if _, err := failingService.Status(context.Background(), env.caller); !errors.Is(err, bootstrap.ErrAuditUnavailable) {
		t.Fatalf("审计故障 Status 错误 = %v，期望 ErrAuditUnavailable", err)
	}
}

// TestRestartDoesNotRecreateRoot 验证重启（新连接/新服务实例）只读取已有状态，
// 不重新生成默认账户，也不重新签发凭证。
func TestRestartDoesNotRecreateRoot(t *testing.T) {
	env := newTestEnv(t)
	issued := env.initialize(bootstrap.InitializeRequest{})
	credentialCount := env.queryInt(`SELECT COUNT(*) FROM one_time_credentials`)

	restarted := newTestEnvAtPath(t, env.dbPath)
	status, err := restarted.service.Status(context.Background(), restarted.caller)
	if err != nil {
		t.Fatalf("重启后 Status 失败: %v", err)
	}
	if status.State != bootstrap.StatePendingSetup || status.RootUserID != issued.Root.ID ||
		status.SetupCredentialID != issued.SetupCredential.ID {
		t.Errorf("重启后状态 = %+v", status)
	}
	if _, err := restarted.service.Initialize(context.Background(), restarted.caller,
		bootstrap.InitializeRequest{}); !errors.Is(err, bootstrap.ErrAlreadyInitialized) {
		t.Fatalf("重启后初始化错误 = %v，期望 ErrAlreadyInitialized", err)
	}
	if got := restarted.queryInt(`SELECT COUNT(*) FROM users`); got != 1 {
		t.Errorf("重启后用户数 = %d，期望 1", got)
	}
	if got := restarted.queryInt(`SELECT COUNT(*) FROM users WHERE is_root=1`); got != 1 {
		t.Errorf("重启后 root 数 = %d", got)
	}
	if got := restarted.queryInt(`SELECT COUNT(*) FROM one_time_credentials`); got != credentialCount {
		t.Errorf("重启后凭证数 = %d，期望 %d（不重复签发）", got, credentialCount)
	}
}

// TestConstructorAndRequestValidation 验证构造 fail-closed、授权拒绝与参数边界。
func TestConstructorAndRequestValidation(t *testing.T) {
	env := newTestEnv(t)
	if _, err := bootstrap.New(bootstrap.Options{}); !errors.Is(err, bootstrap.ErrOptionsInvalid) {
		t.Fatalf("空选项构造错误 = %v", err)
	}
	otherAuthorizer, err := bootstrap.NewLocalBootstrapAuthorizer([]string{testOther})
	if err != nil {
		t.Fatalf("构造授权器失败: %v", err)
	}
	if _, err := env.caller.WithRequestID("req-1"); err != nil {
		t.Fatalf("WithRequestID 失败: %v", err)
	}
	if _, err := bootstrap.LocalBootstrapCaller(""); err == nil {
		t.Error("空本地操作者标识应被拒绝")
	}
	// 未获准操作者：服务返回 ACCESS_DENIED，不产生初始化数据。
	deniedService, err := bootstrap.New(bootstrap.Options{
		Store: env.store, Audit: env.recorder, Authorizer: otherAuthorizer, Credentials: env.credentials, Now: env.clock.Now,
	})
	if err != nil {
		t.Fatalf("构造拒绝授权服务失败: %v", err)
	}
	if _, err := deniedService.Initialize(context.Background(), env.caller, bootstrap.InitializeRequest{}); !errors.Is(err, bootstrap.ErrAccessDenied) {
		t.Fatalf("未授权初始化错误 = %v", err)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM users`); got != 0 {
		t.Errorf("未授权调用后用户数 = %d", got)
	}
	// 有效期边界。
	for _, ttl := range []time.Duration{30 * time.Second, 2 * time.Hour} {
		if _, err := env.service.Initialize(context.Background(), env.caller,
			bootstrap.InitializeRequest{SetupCredentialTTL: ttl}); !errors.Is(err, bootstrap.ErrInvalidRequest) {
			t.Errorf("非法 TTL %v 错误 = %v", ttl, err)
		}
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM users`); got != 0 {
		t.Errorf("非法参数后用户数 = %d", got)
	}
}

// TestRootProtectedFromOrdinaryManagement 验证普通账户管理路径不能删除、禁用、
// 降格或通过状态命令操作 root，库中 root 行保持不变。
func TestRootProtectedFromOrdinaryManagement(t *testing.T) {
	env := newTestEnv(t)
	issued := env.initialize(bootstrap.InitializeRequest{})

	accountStore, err := accountsqlite.New(env.raw)
	if err != nil {
		t.Fatalf("构造账户仓储失败: %v", err)
	}
	authorizer, err := account.NewLocalBootstrapAuthorizer([]string{testOperator})
	if err != nil {
		t.Fatalf("构造账户授权器失败: %v", err)
	}
	accountService, err := account.New(account.Options{
		Store: accountStore, Audit: env.recorder, Authorizer: authorizer, Now: env.clock.Now,
	})
	if err != nil {
		t.Fatalf("构造账户服务失败: %v", err)
	}
	accountCaller, err := account.LocalBootstrapCaller(testOperator)
	if err != nil {
		t.Fatalf("构造账户调用者失败: %v", err)
	}
	commands := []struct {
		name    string
		request account.StateCommandRequest
		call    func(context.Context, account.Caller, account.StateCommandRequest) error
	}{
		{"禁用", account.StateCommandRequest{UserID: issued.Root.ID, ExpectedRowVersion: 1}, func(ctx context.Context, caller account.Caller, request account.StateCommandRequest) error {
			_, err := accountService.DisableUser(ctx, caller, request)
			return err
		}},
		{"启用", account.StateCommandRequest{UserID: issued.Root.ID, ExpectedRowVersion: 1}, func(ctx context.Context, caller account.Caller, request account.StateCommandRequest) error {
			_, err := accountService.EnableUser(ctx, caller, request)
			return err
		}},
		{"请求删除", account.StateCommandRequest{UserID: issued.Root.ID, ExpectedRowVersion: 1}, func(ctx context.Context, caller account.Caller, request account.StateCommandRequest) error {
			_, err := accountService.RequestDeletion(ctx, caller, request)
			return err
		}},
		{"完成删除", account.StateCommandRequest{UserID: issued.Root.ID, ExpectedRowVersion: 1}, func(ctx context.Context, caller account.Caller, request account.StateCommandRequest) error {
			_, err := accountService.CompleteDeletion(ctx, caller, request)
			return err
		}},
	}
	for _, command := range commands {
		if err := command.call(context.Background(), accountCaller, command.request); !errors.Is(err, account.ErrProtectedUser) {
			t.Errorf("%s root 错误 = %v，期望 ErrProtectedUser", command.name, err)
		} else if code := account.CodeOf(err); code != account.CodeAccessDenied {
			t.Errorf("%s root 错误码 = %q，期望 ACCESS_DENIED", command.name, code)
		}
	}
	// 删除预览允许只读查询，但明确标记受保护。
	preview, err := accountService.PreviewDeletion(context.Background(), accountCaller, issued.Root.ID)
	if err != nil {
		t.Fatalf("PreviewDeletion 失败: %v", err)
	}
	if !preview.IsRoot {
		t.Error("删除预览未标记 root 受保护")
	}
	// root 行完全未变：状态/行版本/安全版本/is_root/唯一性。
	if got := env.queryString(`SELECT status FROM users WHERE is_root=1`); got != "active" {
		t.Errorf("root 状态 = %q，期望 active", got)
	}
	if got := env.queryInt(`SELECT row_version FROM users WHERE is_root=1`); got != 1 {
		t.Errorf("root row_version = %d，期望 1", got)
	}
	if got := env.queryInt(`SELECT security_version FROM users WHERE is_root=1`); got != 1 {
		t.Errorf("root security_version = %d，期望 1", got)
	}
	if got := env.queryInt(`SELECT is_root FROM users WHERE id=?`, issued.Root.ID); got != 1 {
		t.Errorf("root is_root = %d，期望 1（不可降格）", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM users WHERE is_root=1`); got != 1 {
		t.Errorf("root 数 = %d，期望 1", got)
	}
}

// failingCreateStore 在事务内插入 root 后故意返回错误，用于验证整体回滚。
type failingCreateStore struct {
	*bootstrapsqlite.Store
}

// Create 模拟“root 已写入但初始化记录写入失败”的部分失败。
func (s *failingCreateStore) Create(ctx context.Context, tx audit.Tx, root account.User, record bootstrap.Record) error {
	_, err := tx.ExecContext(ctx,
		`INSERT INTO users(id,username,username_normalized,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'active',1,1,1,?,?)`,
		root.ID, root.Username, root.UsernameNormalized,
		root.CreatedAt.UTC().UnixMilli(), root.UpdatedAt.UTC().UnixMilli())
	if err != nil {
		return err
	}
	return errors.New("注入的初始化记录写入失败")
}

// failingAudit 让所有关键事务失败，用于验证审计不可用时拒绝初始化。
type failingAudit struct {
	*audit.Recorder
}

// ExecuteCritical 始终返回审计不可用。
func (f failingAudit) ExecuteCritical(context.Context, audit.CriticalRequest, audit.Change) error {
	return fmt.Errorf("%w: 注入的审计故障", audit.ErrAuditUnavailable)
}

// failingRecordAudit 让独立读取审计失败，用于验证状态读取 fail-closed。
type failingRecordAudit struct {
	*audit.Recorder
}

// Record 始终返回审计不可用。
func (f failingRecordAudit) Record(context.Context, audit.Event) error {
	return fmt.Errorf("%w: 注入的审计故障", audit.ErrAuditUnavailable)
}
