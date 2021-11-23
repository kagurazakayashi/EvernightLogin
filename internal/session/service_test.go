package session_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
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
	bootstrapsqlite "github.com/kagurazakayashi/EvernightLogin/internal/bootstrap/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	sessionsqlite "github.com/kagurazakayashi/EvernightLogin/internal/session/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// testStart 是测试时钟的固定起点。
var testStart = time.Date(2026, 11, 16, 2, 0, 0, 0, time.UTC)

// testParams 是降低成本的 Argon2id 参数，仅用于测试（仍满足模块下限）。
func testParams() authn.Params {
	return authn.Params{MemoryKiB: 8192, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}
}

// testClock 是可手动推进的并发安全测试时钟。
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

// Now 返回当前测试时间。
func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance 推进测试时间。
func (c *testClock) Advance(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(duration)
}

// testEnv 是会话测试的完整依赖环境：临时 SQLite（执行 0001～0010）、真实审计
// 写入器、真实密钥环、真实认证服务与受控时钟。
type testEnv struct {
	t            *testing.T
	ctx          context.Context
	storage      *storagesqlite.Store
	sessionStore *sessionsqlite.Store
	session      *session.Service
	authn        *authn.Service
	audit        *audit.Recorder
	keyring      *secrets.Keyring
	clock        *testClock
	logs         *bytes.Buffer
}

// newTestEnv 构造测试环境。
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()
	clock := &testClock{now: testStart}
	path := filepath.Join(testutil.TempDir(t), "login-session-test.db")
	storage, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(path))
	if err != nil {
		t.Fatalf("打开临时数据库失败: %v", err)
	}
	t.Cleanup(func() {
		_ = storage.Close()
	})
	migrationList, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移失败: %v", err)
	}
	if _, err := storage.Migrate(ctx, migrationList); err != nil {
		t.Fatalf("执行迁移失败: %v", err)
	}
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	auditStore, err := auditsqlite.New(storage)
	if err != nil {
		t.Fatalf("构造审计存储失败: %v", err)
	}
	recorder, err := audit.New(auditStore, audit.Options{Logger: logger, Now: clock.Now})
	if err != nil {
		t.Fatalf("构造审计写入器失败: %v", err)
	}
	keyring, err := secrets.GenerateKeyring("k1", testStart)
	if err != nil {
		t.Fatalf("生成测试密钥环失败: %v", err)
	}
	sessionStore, err := sessionsqlite.New(storage)
	if err != nil {
		t.Fatalf("构造会话存储失败: %v", err)
	}
	sessionService, err := session.New(sessionStore, session.Options{AllowLegacyWithoutSensitive: true,
		Store:           sessionStore,
		Audit:           recorder,
		Keyring:         keyring,
		IdleTimeout:     10 * time.Minute,
		AbsoluteTimeout: 2 * time.Hour,
		Logger:          logger,
		Now:             clock.Now,
	})
	if err != nil {
		t.Fatalf("构造会话服务失败: %v", err)
	}
	authnStore, err := authnsqlite.New(storage)
	if err != nil {
		t.Fatalf("构造认证存储失败: %v", err)
	}
	bootstrapStore, err := bootstrapsqlite.New(storage)
	if err != nil {
		t.Fatalf("构造初始化存储失败: %v", err)
	}
	authnService, err := authn.New(authn.Options{
		Store:              authnStore,
		Audit:              recorder,
		RootInitialization: bootstrapStore,
		Params:             testParams(),
		Logger:             logger,
		Now:                clock.Now,
	})
	if err != nil {
		t.Fatalf("构造认证服务失败: %v", err)
	}
	return &testEnv{
		t:            t,
		ctx:          ctx,
		storage:      storage,
		sessionStore: sessionStore,
		session:      sessionService,
		authn:        authnService,
		audit:        recorder,
		keyring:      keyring,
		clock:        clock,
		logs:         logs,
	}
}

// newSessionService 用同一测试环境依赖构造会话服务（用于注入测试用存储装饰器）。
func (e *testEnv) newSessionService(store session.Store) *session.Service {
	e.t.Helper()
	service, err := session.New(store, session.Options{AllowLegacyWithoutSensitive: true,
		Store:           store,
		Audit:           e.audit,
		Keyring:         e.keyring,
		IdleTimeout:     10 * time.Minute,
		AbsoluteTimeout: 2 * time.Hour,
		Logger:          slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Now:             e.clock.Now,
	})
	if err != nil {
		e.t.Fatalf("构造测试会话服务失败: %v", err)
	}
	return service
}

// revokeFailureStore 是让首条会话撤销返回“未生效”的存储装饰器，用于验证轮换
// fail-closed 逻辑（生产存储不会人为返回该结果）。
type revokeFailureStore struct {
	session.Store
	failed bool
}

// Revoke 首次调用返回未生效（模拟并发撤销/状态竞争），随后保持真实行为。
func (s *revokeFailureStore) Revoke(ctx context.Context, tx audit.Tx, condition session.RevokeCondition) (bool, error) {
	if !s.failed {
		s.failed = true
		return false, nil
	}
	return s.Store.Revoke(ctx, tx, condition)
}

// exec 执行测试用 SQL。
func (e *testEnv) exec(query string, args ...any) {
	e.t.Helper()
	if _, err := e.storage.ExecContext(e.ctx, query, args...); err != nil {
		e.t.Fatalf("执行 SQL 失败: %v", err)
	}
}

// queryInt 读取单个整数结果。
func (e *testEnv) queryInt(query string, args ...any) int {
	e.t.Helper()
	rows, err := e.storage.QueryContext(e.ctx, query, args...)
	if err != nil {
		e.t.Fatalf("查询失败: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		e.t.Fatalf("查询没有结果")
	}
	var value int
	if err := rows.Scan(&value); err != nil {
		e.t.Fatalf("扫描失败: %v", err)
	}
	return value
}

// queryString 读取单个字符串结果。
func (e *testEnv) queryString(query string, args ...any) string {
	e.t.Helper()
	rows, err := e.storage.QueryContext(e.ctx, query, args...)
	if err != nil {
		e.t.Fatalf("查询失败: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		e.t.Fatalf("查询没有结果")
	}
	var value string
	if err := rows.Scan(&value); err != nil {
		e.t.Fatalf("扫描失败: %v", err)
	}
	return value
}

// insertUser 插入合成活跃用户；securityVersion 通常为 1。
func (e *testEnv) insertUser(userID, username string, status account.Status, securityVersion int64) {
	e.t.Helper()
	nowMS := testStart.UnixMilli()
	e.exec(`INSERT INTO users(id,username,username_normalized,nickname,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'',?,0,?,1,?,?)`, userID, username, strings.ToLower(username), string(status), securityVersion, nowMS, nowMS)
}

// insertPassword 直接写入正式密码凭证（仅测试用；生产必须走 authn.SetPassword）。
func (e *testEnv) insertPassword(userID, password string) {
	e.t.Helper()
	hash, err := authn.HashPassword(password, testParams(), nil)
	if err != nil {
		e.t.Fatalf("生成密码哈希失败: %v", err)
	}
	nowMS := testStart.UnixMilli()
	e.exec(`INSERT INTO password_credentials(user_id,hash_scheme,hash_version,password_hash,must_change,row_version,created_at_ms,updated_at_ms,changed_at_ms)
VALUES(?,'argon2id',19,?,0,1,?,?,?)`, userID, hash, nowMS, nowMS, nowMS)
}

// insertApplication 插入测试应用。
func (e *testEnv) insertApplication(appID string, status string) {
	e.t.Helper()
	nowMS := testStart.UnixMilli()
	e.exec(`INSERT INTO applications(id,name,status,client_type,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'public',1,?,?)`, appID, appID, status, nowMS, nowMS)
}

// insertMembership 插入应用成员关系。
func (e *testEnv) insertMembership(appID, userID, status string) {
	e.t.Helper()
	nowMS := testStart.UnixMilli()
	e.exec(`INSERT INTO app_memberships(app_id,user_id,status,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,1,?,?)`, appID, userID, status, nowMS, nowMS)
}

// completeResult 构造完整认证结果。
func completeResult(userID string, securityVersion int64) authn.AuthenticateResult {
	return authn.AuthenticateResult{
		UserID:           userID,
		Username:         "alice",
		Outcome:          authn.OutcomeComplete,
		CompletedMethods: []authn.Method{authn.MethodPassword},
		CompletedAt:      testStart,
		SecurityVersion:  securityVersion,
	}
}

// pendingSecondFactorResult 构造待第二因素的受限认证结果。
func pendingSecondFactorResult(userID string, securityVersion int64) authn.AuthenticateResult {
	return authn.AuthenticateResult{
		UserID:           userID,
		Username:         "alice",
		Outcome:          authn.OutcomePendingSecondFactor,
		CompletedMethods: []authn.Method{authn.MethodPassword},
		CompletedAt:      testStart,
		RequiredSteps:    []authn.Step{authn.StepStrongAuthSetup, authn.StepSecondFactor},
		Restricted:       true,
		SecurityVersion:  securityVersion,
	}
}

// pendingPasswordChangeResult 构造待强制改密的受限认证结果。
func pendingPasswordChangeResult(userID string, securityVersion int64) authn.AuthenticateResult {
	return authn.AuthenticateResult{
		UserID:           userID,
		Username:         "alice",
		Outcome:          authn.OutcomePendingPasswordChange,
		CompletedMethods: []authn.Method{authn.MethodPassword},
		CompletedAt:      testStart,
		RequiredSteps:    []authn.Step{authn.StepPasswordChange},
		Restricted:       true,
		SecurityVersion:  securityVersion,
	}
}

// loginComplete 在测试环境中签发普通会话。
func (e *testEnv) loginComplete(userID string, securityVersion int64) session.IssuedSession {
	e.t.Helper()
	issued, err := e.session.Login(e.ctx, session.LoginRequest{Result: completeResult(userID, securityVersion)})
	if err != nil {
		e.t.Fatalf("签发普通会话失败: %v", err)
	}
	return issued
}

// TestLoginAuthenticateRenewLogout 验证“登录 → 认证请求 → 续期 → 退出”闭环，使用
// 真实认证服务的密码验证结果接入会话，并确认数据库只保存验证摘要。
func TestLoginAuthenticateRenewLogout(t *testing.T) {
	env := newTestEnv(t)
	userID := "usr_00000000000000000000000000000001"
	env.insertUser(userID, "alice", account.StatusActive, 1)
	env.insertPassword(userID, "Correct-Horse-Battery-9")

	result, err := env.authn.Authenticate(env.ctx, authn.AuthenticateRequest{
		Identifier: "Alice",
		Password:   "Correct-Horse-Battery-9",
		ClientIP:   "203.0.113.7",
	})
	if err != nil {
		t.Fatalf("密码认证失败: %v", err)
	}
	if !result.IsComplete() || result.Restricted {
		t.Fatalf("认证结果不是完整认证: %+v", result)
	}

	issued, err := env.session.Login(env.ctx, session.LoginRequest{Result: result})
	if err != nil {
		t.Fatalf("签发会话失败: %v", err)
	}
	if !issued.Secret.IsSet() || !issued.CSRFSecret.IsSet() {
		t.Fatal("签发结果缺少会话秘密或 CSRF 令牌")
	}
	if issued.Session.Kind != session.KindNormal || issued.Session.Reason != session.ReasonNone {
		t.Fatalf("会话类别 = %s/%s，期望普通会话", issued.Session.Kind, issued.Session.Reason)
	}
	if issued.Session.CanAccessManagement() {
		t.Error("MFA 未实现时普通会话不得访问管理接口")
	}

	// 数据库只保存 32 字节验证摘要，不保存会话秘密或 CSRF 令牌原文。
	if got := env.queryInt(`SELECT length(secret_digest) FROM sessions WHERE id=?`, issued.Session.ID); got != 32 {
		t.Fatalf("会话秘密摘要长度 = %d，期望 32", got)
	}
	if got := env.queryInt(`SELECT length(csrf_digest) FROM sessions WHERE id=?`, issued.Session.ID); got != 32 {
		t.Fatalf("CSRF 摘要长度 = %d，期望 32", got)
	}
	if got := env.queryString(`SELECT CAST(secret_digest AS TEXT) || CAST(csrf_digest AS TEXT) FROM sessions WHERE id=?`, issued.Session.ID); strings.Contains(got, issued.Secret.Reveal()) {
		t.Error("数据库摘要字段包含会话秘密明文")
	}

	// 认证请求：校验通过并返回服务端会话快照。
	current, err := env.session.Validate(env.ctx, issued.Secret.Reveal())
	if err != nil {
		t.Fatalf("会话校验失败: %v", err)
	}
	if current.UserID != userID || current.ID != issued.Session.ID {
		t.Fatalf("会话快照 = %+v", current)
	}

	// 续期：空闲到期被延长，但绝对到期不变。
	env.clock.Advance(9 * time.Minute)
	renewed, err := env.session.Renew(env.ctx, issued.Secret.Reveal())
	if err != nil {
		t.Fatalf("会话续期失败: %v", err)
	}
	if !renewed.IdleExpiresAt.After(current.IdleExpiresAt) {
		t.Error("续期没有延长空闲到期")
	}
	if !renewed.AbsoluteExpiresAt.Equal(current.AbsoluteExpiresAt) {
		t.Error("续期改变了绝对到期")
	}
	env.clock.Advance(9 * time.Minute)
	if _, err := env.session.Validate(env.ctx, issued.Secret.Reveal()); err != nil {
		t.Fatalf("续期后会话应仍有效: %v", err)
	}

	// 退出：立即失效，重复退出幂等。
	if err := env.session.Logout(env.ctx, issued.Secret.Reveal()); err != nil {
		t.Fatalf("退出失败: %v", err)
	}
	if _, err := env.session.Validate(env.ctx, issued.Secret.Reveal()); !errors.Is(err, session.ErrSessionInvalid) {
		t.Fatalf("退出后校验错误 = %v，期望 ErrSessionInvalid", err)
	}
	if err := env.session.Logout(env.ctx, issued.Secret.Reveal()); err != nil {
		t.Errorf("重复退出应幂等成功: %v", err)
	}

	// 审计记录存在且不含秘密。
	auditText := env.queryString(`SELECT COALESCE(group_concat(detail_json,'|'),'') FROM audit_events`)
	if strings.Contains(auditText, issued.Secret.Reveal()) || strings.Contains(auditText, issued.CSRFSecret.Reveal()) {
		t.Error("安全审计泄露会话秘密或 CSRF 令牌")
	}
	if strings.Contains(env.logs.String(), issued.Secret.Reveal()) || strings.Contains(env.logs.String(), issued.CSRFSecret.Reveal()) {
		t.Error("运行日志泄露会话秘密或 CSRF 令牌")
	}
}

// TestIdleAndAbsoluteExpiry 验证空闲到期与绝对到期两道约束：空闲到期可续期恢复，
// 绝对到期不可被续期越过。
func TestIdleAndAbsoluteExpiry(t *testing.T) {
	env := newTestEnv(t)
	userID := "usr_00000000000000000000000000000002"
	env.insertUser(userID, "bob", account.StatusActive, 1)
	issued := env.loginComplete(userID, 1)

	// 空闲到期边界：到期时刻起失效。
	env.clock.Advance(10 * time.Minute)
	if _, err := env.session.Renew(env.ctx, issued.Secret.Reveal()); !errors.Is(err, session.ErrSessionInvalid) {
		t.Fatalf("空闲到期后续期错误 = %v，期望 ErrSessionInvalid", err)
	}
	if _, err := env.session.Validate(env.ctx, issued.Secret.Reveal()); !errors.Is(err, session.ErrSessionInvalid) {
		t.Fatalf("空闲到期后校验错误 = %v，期望 ErrSessionInvalid", err)
	}

	// 绝对到期：持续续期只能延到绝对到期，不能越过。
	issued = env.loginComplete(userID, 1)
	for step := 0; step < 23; step++ {
		env.clock.Advance(5 * time.Minute)
		if _, err := env.session.Renew(env.ctx, issued.Secret.Reveal()); err != nil {
			t.Fatalf("第 %d 次续期失败: %v", step, err)
		}
	}
	renewed, err := env.session.Validate(env.ctx, issued.Secret.Reveal())
	if err != nil {
		t.Fatalf("绝对到期前校验失败: %v", err)
	}
	if !renewed.IdleExpiresAt.Equal(renewed.AbsoluteExpiresAt) {
		t.Fatalf("续期后空闲到期 = %s，绝对到期 = %s，期望空闲到期不越过绝对到期",
			renewed.IdleExpiresAt, renewed.AbsoluteExpiresAt)
	}
	// 到达绝对到期时刻（签发后 2 小时）后，任何续期都必须失败。
	env.clock.Advance(5 * time.Minute)
	if _, err := env.session.Renew(env.ctx, issued.Secret.Reveal()); !errors.Is(err, session.ErrSessionInvalid) {
		t.Fatalf("绝对到期后续期错误 = %v，期望 ErrSessionInvalid", err)
	}
}

// TestSessionFixationRotation 验证登录成功轮换会话 ID：出示的旧会话在签发事务中
// 被撤销，旧秘密不能再通过校验，新会话使用不同 ID 与秘密。
func TestSessionFixationRotation(t *testing.T) {
	env := newTestEnv(t)
	userID := "usr_00000000000000000000000000000003"
	env.insertUser(userID, "carol", account.StatusActive, 1)
	first := env.loginComplete(userID, 1)

	fixed, err := env.session.Login(env.ctx, session.LoginRequest{
		Result:          completeResult(userID, 1),
		ExistingSession: first.Secret.Reveal(),
	})
	if err != nil {
		t.Fatalf("携带旧会话登录失败: %v", err)
	}
	if fixed.Session.ID == first.Session.ID {
		t.Fatal("登录轮换没有更新会话 ID（会话固定风险）")
	}
	if fixed.Secret.Reveal() == first.Secret.Reveal() {
		t.Fatal("登录轮换没有更新会话秘密")
	}
	if fixed.RotatedSessionID != first.Session.ID {
		t.Fatalf("轮换旧会话 ID = %q，期望 %q", fixed.RotatedSessionID, first.Session.ID)
	}
	if _, err := env.session.Validate(env.ctx, first.Secret.Reveal()); !errors.Is(err, session.ErrSessionInvalid) {
		t.Fatalf("旧会话在轮换后仍可用: %v", err)
	}
	if _, err := env.session.Validate(env.ctx, fixed.Secret.Reveal()); err != nil {
		t.Fatalf("新会话校验失败: %v", err)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM sessions WHERE id=? AND revoked_at_ms IS NOT NULL AND revoked_reason='rotated'`, first.Session.ID); got != 1 {
		t.Errorf("旧会话未被标记轮换撤销，计数 = %d", got)
	}
	if got := env.queryString(`SELECT COALESCE(group_concat(detail_json,'|'),'') FROM audit_events WHERE action='session.issue'`); !strings.Contains(got, "session_rotation") {
		t.Error("审计没有记录会话轮换")
	}
}

// TestRootSessionMustBeRestricted 验证 root 在 MFA/管理强认证未实现前只能持受限
// 会话：即使调用方给出“完整认证”结果，也拒绝签发普通会话；受限结果仍可签发。
func TestRootSessionMustBeRestricted(t *testing.T) {
	env := newTestEnv(t)
	rootID := "usr_00000000000000000000000000000016"
	env.insertUser(rootID, "root", account.StatusActive, 1)
	env.exec(`UPDATE users SET is_root=1 WHERE id=?`, rootID)

	if _, err := env.session.Login(env.ctx, session.LoginRequest{Result: completeResult(rootID, 1)}); !errors.Is(err, session.ErrAccountNotEligible) {
		t.Fatalf("root 普通会话签发错误 = %v，期望 ErrAccountNotEligible", err)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM sessions`); got != 0 {
		t.Fatalf("root 普通会话被拒绝后仍写入 %d 条会话", got)
	}
	issued, err := env.session.Login(env.ctx, session.LoginRequest{Result: pendingSecondFactorResult(rootID, 1)})
	if err != nil {
		t.Fatalf("root 受限会话签发失败: %v", err)
	}
	if issued.Session.Kind != session.KindRestricted || issued.Session.CanAccessBusiness() {
		t.Fatalf("root 会话类别 = %s，期望受限会话", issued.Session.Kind)
	}
	if got := env.queryString(`SELECT COALESCE(group_concat(reason_code,'|'),'') FROM audit_events WHERE outcome='failure'`); !strings.Contains(got, "root_requires_restricted_session") {
		t.Error("root 普通会话拒绝未写失败审计原因")
	}
}

// TestConcurrentLoginRotationRevokesOldSession 验证并发双登录轮换同一旧会话时最多
// 一个成功：撤销未生效的一方 fail-closed 拒绝签发，且旧会话确实失效。
func TestConcurrentLoginRotationRevokesOldSession(t *testing.T) {
	env := newTestEnv(t)
	userID := "usr_00000000000000000000000000000017"
	env.insertUser(userID, "peggy", account.StatusActive, 1)
	existing := env.loginComplete(userID, 1)

	const workers = 2
	type outcome struct {
		issued session.IssuedSession
		err    error
	}
	results := make([]outcome, workers)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func(slot int) {
			defer wait.Done()
			results[slot].issued, results[slot].err = env.session.Login(env.ctx, session.LoginRequest{
				Result:          completeResult(userID, 1),
				ExistingSession: existing.Secret.Reveal(),
			})
		}(index)
	}
	wait.Wait()
	successes := 0
	failures := 0
	var successful []session.IssuedSession
	for index, result := range results {
		switch {
		case result.err == nil:
			successes++
			successful = append(successful, result.issued)
		case errors.Is(result.err, session.ErrRotationFailed):
			failures++
		default:
			t.Fatalf("并发登录 %d 错误 = %v，期望 ErrRotationFailed", index, result.err)
		}
	}
	if successes < 1 || successes+failures != workers {
		t.Fatalf("并发登录结果 成功=%d 失败=%d，期望至少 1 成功且其余为 rotation 失败", successes, failures)
	}
	// 核心不变量：无论并发调度如何，旧会话必须失效，成功签发的会话必须可用，
	// 且“轮换撤销”最多记录一次（不会出现同一旧会话被重复轮换的虚假审计）。
	if _, err := env.session.Validate(env.ctx, existing.Secret.Reveal()); !errors.Is(err, session.ErrSessionInvalid) {
		t.Fatalf("轮换后旧会话仍可用: %v", err)
	}
	for index, issued := range successful {
		if _, err := env.session.Validate(env.ctx, issued.Secret.Reveal()); err != nil {
			t.Errorf("并发登录成功会话 %d 校验失败: %v", index, err)
		}
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM sessions WHERE user_id=? AND revoked_reason='rotated'`, userID); got > 1 {
		t.Errorf("旧会话轮换撤销计数 = %d，期望最多 1", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM sessions WHERE user_id=? AND revoked_at_ms IS NULL`, userID); got != successes {
		t.Errorf("活动会话数 = %d，期望 %d", got, successes)
	}
}

// TestRotationRevokeFailureFailsClosed 验证旧会话撤销未生效时拒绝签发新会话：
// 业务整体回滚、不留下新会话行，旧会话保持原状以便可信重试。
func TestRotationRevokeFailureFailsClosed(t *testing.T) {
	env := newTestEnv(t)
	userID := "usr_00000000000000000000000000000019"
	env.insertUser(userID, "rupert", account.StatusActive, 1)
	current := env.loginComplete(userID, 1)

	wrapper := &revokeFailureStore{Store: env.sessionStore}
	service := env.newSessionService(wrapper)
	if _, err := service.Login(env.ctx, session.LoginRequest{
		Result:          completeResult(userID, 1),
		ExistingSession: current.Secret.Reveal(),
	}); !errors.Is(err, session.ErrRotationFailed) {
		t.Fatalf("撤销未生效的登录错误 = %v，期望 ErrRotationFailed", err)
	}
	if code := session.CodeOf(session.ErrRotationFailed); code != session.CodeAuthFailed {
		t.Errorf("轮换失败错误码 = %s，期望 %s", code, session.CodeAuthFailed)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM sessions`); got != 1 {
		t.Fatalf("轮换失败后会话行数 = %d，期望仅保留旧会话 1 条", got)
	}
	// 失败回滚后旧会话仍有效，重试（存储恢复正常）可完成轮换。
	if _, err := env.session.Validate(env.ctx, current.Secret.Reveal()); err != nil {
		t.Fatalf("轮换失败不应撤销旧会话: %v", err)
	}
	issued, err := service.Login(env.ctx, session.LoginRequest{
		Result:          completeResult(userID, 1),
		ExistingSession: current.Secret.Reveal(),
	})
	if err != nil {
		t.Fatalf("存储恢复后重试轮换失败: %v", err)
	}
	if issued.RotatedSessionID != current.Session.ID {
		t.Fatalf("重试轮换旧会话 ID = %q，期望 %q", issued.RotatedSessionID, current.Session.ID)
	}
	if _, err := env.session.Validate(env.ctx, current.Secret.Reveal()); !errors.Is(err, session.ErrSessionInvalid) {
		t.Fatalf("重试轮换后旧会话仍可用: %v", err)
	}
}

// TestCSRFValidationRechecksState 验证撤销/账户状态变化后 CSRF 令牌同样失效：
// 禁用账户或递增安全版本后，未撤销旧会话的 CSRF 校验必须失败。
func TestCSRFValidationRechecksState(t *testing.T) {
	env := newTestEnv(t)
	userID := "usr_00000000000000000000000000000018"
	env.insertUser(userID, "quinn", account.StatusActive, 1)
	issued := env.loginComplete(userID, 1)
	cookie, err := env.session.NewCookie(issued)
	if err != nil {
		t.Fatalf("构造 Cookie 失败: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://login.example.com/api/action", nil)
	request.AddCookie(cookie)
	if err := env.session.ValidateCSRFToken(env.ctx, request, issued.CSRFSecret.Reveal()); err != nil {
		t.Fatalf("账户正常时 CSRF 校验失败: %v", err)
	}
	env.exec(`UPDATE users SET status='disabled' WHERE id=?`, userID)
	if err := env.session.ValidateCSRFToken(env.ctx, request, issued.CSRFSecret.Reveal()); !errors.Is(err, session.ErrSessionInvalid) {
		t.Fatalf("禁用账户后 CSRF 校验错误 = %v，期望 ErrSessionInvalid", err)
	}
	env.exec(`UPDATE users SET status='active' WHERE id=?`, userID)
	if err := env.session.ValidateCSRFToken(env.ctx, request, issued.CSRFSecret.Reveal()); err != nil {
		t.Fatalf("账户恢复后 CSRF 校验失败: %v", err)
	}
	env.exec(`UPDATE users SET security_version=security_version+1 WHERE id=?`, userID)
	if err := env.session.ValidateCSRFToken(env.ctx, request, issued.CSRFSecret.Reveal()); !errors.Is(err, session.ErrSessionInvalid) {
		t.Fatalf("安全版本变化后 CSRF 校验错误 = %v，期望 ErrSessionInvalid", err)
	}
}

// TestCookieAndCSRFIntegration 验证 Cookie 安全属性、CSRF 令牌与会话绑定，以及
// 会话秘密只能来自 Cookie/Authorization（绝不来自 URL）。
func TestCookieAndCSRFIntegration(t *testing.T) {
	env := newTestEnv(t)
	userID := "usr_00000000000000000000000000000004"
	env.insertUser(userID, "dave", account.StatusActive, 1)
	issued := env.loginComplete(userID, 1)

	cookie, err := env.session.NewCookie(issued)
	if err != nil {
		t.Fatalf("构造会话 Cookie 失败: %v", err)
	}
	if cookie.Name != session.DefaultCookieName {
		t.Errorf("Cookie 名 = %q，期望 %q", cookie.Name, session.DefaultCookieName)
	}
	if !cookie.Secure || !cookie.HttpOnly {
		t.Error("Cookie 必须 Secure 且 HttpOnly")
	}
	if cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" {
		t.Errorf("Cookie 属性 = SameSite %v Path %q", cookie.SameSite, cookie.Path)
	}
	if cookie.MaxAge != 0 {
		t.Errorf("默认会话 Cookie 应是浏览器会话 Cookie，MaxAge = %d", cookie.MaxAge)
	}
	clear := env.session.ClearCookie()
	if clear.MaxAge >= 0 || clear.Value != "" {
		t.Error("清除 Cookie 应使用 MaxAge<0 且空值")
	}

	// 合法 Cookie + 正确 CSRF 令牌通过。
	request := httptest.NewRequest(http.MethodPost, "https://login.example.com/api/session/logout", nil)
	request.AddCookie(cookie)
	request.Header.Set("Origin", "https://login.example.com")
	if err := env.session.ValidateCSRFToken(env.ctx, request, issued.CSRFSecret.Reveal()); err != nil {
		t.Fatalf("合法 CSRF 令牌校验失败: %v", err)
	}
	// 错误令牌、缺少会话、把秘密放 URL 都必须失败。
	badToken := httptest.NewRequest(http.MethodPost, "https://login.example.com/api/session/logout", nil)
	badToken.AddCookie(cookie)
	if err := env.session.ValidateCSRFToken(env.ctx, badToken, "not-the-token"); !errors.Is(err, session.ErrSessionInvalid) {
		t.Fatalf("错误 CSRF 令牌错误 = %v，期望 ErrSessionInvalid", err)
	}
	noSession := httptest.NewRequest(http.MethodPost, "https://login.example.com/api/session/logout", nil)
	if err := env.session.ValidateCSRFToken(env.ctx, noSession, issued.CSRFSecret.Reveal()); !errors.Is(err, session.ErrSessionInvalid) {
		t.Fatalf("无会话 CSRF 错误 = %v，期望 ErrSessionInvalid", err)
	}
	querySecret := httptest.NewRequest(http.MethodPost,
		"https://login.example.com/api/session/logout?session="+issued.Secret.Reveal(), nil)
	if _, ok := env.session.SessionSecretFromRequest(querySecret); ok {
		t.Error("SessionSecretFromRequest 不应接受 URL 查询参数中的会话秘密")
	}
	// Authorization: Bearer 供嵌入式 API 使用，共享同一会话与 CSRF 语义。
	bearer := httptest.NewRequest(http.MethodPost, "https://login.example.com/api/session/logout", nil)
	bearer.Header.Set("Authorization", "Bearer "+issued.Secret.Reveal())
	if secret, ok := env.session.SessionSecretFromRequest(bearer); !ok || secret != issued.Secret.Reveal() {
		t.Fatal("未从 Authorization: Bearer 读取到会话秘密")
	}
	if err := env.session.ValidateCSRFToken(env.ctx, bearer, issued.CSRFSecret.Reveal()); err != nil {
		t.Fatalf("Bearer 会话 CSRF 校验失败: %v", err)
	}

	// 退出后 CSRF 令牌同样失效。
	if err := env.session.Logout(env.ctx, issued.Secret.Reveal()); err != nil {
		t.Fatalf("退出失败: %v", err)
	}
	if err := env.session.ValidateCSRFToken(env.ctx, request, issued.CSRFSecret.Reveal()); !errors.Is(err, session.ErrSessionInvalid) {
		t.Fatalf("退出后 CSRF 校验错误 = %v，期望 ErrSessionInvalid", err)
	}
}

// TestRestrictedSessionCannotAccessBusinessOrManagement 验证受限会话（待第二因素 /
// 待改密 / 恢复 / 初始化）不能访问普通业务或管理接口。
func TestRestrictedSessionCannotAccessBusinessOrManagement(t *testing.T) {
	env := newTestEnv(t)
	userID := "usr_00000000000000000000000000000005"
	env.insertUser(userID, "erin", account.StatusActive, 1)

	cases := []struct {
		name       string
		result     authn.AuthenticateResult
		wantReason session.Reason
		wantStep   authn.Step
	}{
		{
			name:       "待第二因素",
			result:     pendingSecondFactorResult(userID, 1),
			wantReason: session.ReasonPendingSecondFactor,
			wantStep:   authn.StepSecondFactor,
		},
		{
			name:       "待强制改密",
			result:     pendingPasswordChangeResult(userID, 1),
			wantReason: session.ReasonPendingPasswordChange,
			wantStep:   authn.StepPasswordChange,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			issued, err := env.session.Login(env.ctx, session.LoginRequest{Result: testCase.result})
			if err != nil {
				t.Fatalf("签发受限会话失败: %v", err)
			}
			if issued.Session.Kind != session.KindRestricted || issued.Session.Reason != testCase.wantReason {
				t.Fatalf("受限会话类别 = %s/%s，期望 restricted/%s",
					issued.Session.Kind, issued.Session.Reason, testCase.wantReason)
			}
			if !issued.Session.IsRestricted() || issued.Session.CanAccessBusiness() || issued.Session.CanAccessManagement() {
				t.Error("受限会话的访问判定错误")
			}
			found := false
			for _, step := range issued.Session.RequiredSteps {
				if step == testCase.wantStep {
					found = true
				}
			}
			if !found {
				t.Errorf("受限会话缺少剩余步骤 %s", testCase.wantStep)
			}
			if _, err := env.session.Validate(env.ctx, issued.Secret.Reveal()); err != nil {
				t.Fatalf("受限会话本身应可通过校验: %v", err)
			}
			if _, err := env.session.AuthorizeBusiness(env.ctx, issued.Secret.Reveal()); !errors.Is(err, session.ErrRestrictedSession) {
				t.Fatalf("受限会话访问业务错误 = %v，期望 ErrRestrictedSession", err)
			}
			if _, err := env.session.AuthorizeManagement(env.ctx, issued.Secret.Reveal()); !errors.Is(err, session.ErrRestrictedSession) {
				t.Fatalf("受限会话访问管理错误 = %v，期望 ErrRestrictedSession", err)
			}
			if code := session.CodeOf(session.ErrRestrictedSession); code != session.CodeAccessDenied {
				t.Errorf("受限会话错误码 = %s，期望 %s", code, session.CodeAccessDenied)
			}
		})
	}

	// 恢复/初始化受限状态只有稳定标识与访问拒绝语义，本步没有签发入口。
	for _, reason := range []session.Reason{session.ReasonRecovery, session.ReasonInitialization} {
		current := session.Session{Kind: session.KindRestricted, Reason: reason}
		if current.CanAccessBusiness() || current.CanAccessManagement() {
			t.Errorf("受限原因 %s 不应允许访问", reason)
		}
		if !session.ValidCombination(session.KindRestricted, reason) {
			t.Errorf("受限原因 %s 应是合法组合", reason)
		}
	}
	if session.ValidCombination(session.KindNormal, session.ReasonPendingSecondFactor) {
		t.Error("普通会话不得携带受限原因")
	}
}

// TestNormalSessionManagementRequiresStrongAuth 验证管理访问额外要求强认证：MFA
// 未实现时普通会话也不能通过 AuthorizeManagement。
func TestNormalSessionManagementRequiresStrongAuth(t *testing.T) {
	env := newTestEnv(t)
	userID := "usr_00000000000000000000000000000006"
	env.insertUser(userID, "frank", account.StatusActive, 1)
	issued := env.loginComplete(userID, 1)

	if _, err := env.session.AuthorizeBusiness(env.ctx, issued.Secret.Reveal()); err != nil {
		t.Fatalf("普通会话访问业务失败: %v", err)
	}
	if _, err := env.session.AuthorizeManagement(env.ctx, issued.Secret.Reveal()); !errors.Is(err, session.ErrStrongAuthRequired) {
		t.Fatalf("普通会话访问管理错误 = %v，期望 ErrStrongAuthRequired", err)
	}
	if code := session.CodeOf(session.ErrStrongAuthRequired); code != session.CodeAccessDenied {
		t.Errorf("强认证要求错误码 = %s，期望 %s", code, session.CodeAccessDenied)
	}
}

// TestUserStateAndSecurityVersionInvalidateSession 验证账户禁用与安全版本变化会立即
// 让既有会话失效（覆盖禁用与密码变更后的服务端失效语义）。
func TestUserStateAndSecurityVersionInvalidateSession(t *testing.T) {
	t.Run("用户禁用", func(t *testing.T) {
		env := newTestEnv(t)
		userID := "usr_00000000000000000000000000000007"
		env.insertUser(userID, "grace", account.StatusActive, 1)
		issued := env.loginComplete(userID, 1)
		env.exec(`UPDATE users SET status='disabled' WHERE id=?`, userID)
		if _, err := env.session.Validate(env.ctx, issued.Secret.Reveal()); !errors.Is(err, session.ErrSessionInvalid) {
			t.Fatalf("禁用账户后校验错误 = %v，期望 ErrSessionInvalid", err)
		}
		if _, err := env.session.Renew(env.ctx, issued.Secret.Reveal()); !errors.Is(err, session.ErrSessionInvalid) {
			t.Fatalf("禁用账户后续期错误 = %v，期望 ErrSessionInvalid", err)
		}
	})
	t.Run("安全版本变化", func(t *testing.T) {
		env := newTestEnv(t)
		userID := "usr_00000000000000000000000000000008"
		env.insertUser(userID, "heidi", account.StatusActive, 1)
		issued := env.loginComplete(userID, 1)
		env.exec(`UPDATE users SET security_version=security_version+1 WHERE id=?`, userID)
		if _, err := env.session.Validate(env.ctx, issued.Secret.Reveal()); !errors.Is(err, session.ErrSessionInvalid) {
			t.Fatalf("安全版本变化后校验错误 = %v，期望 ErrSessionInvalid", err)
		}
	})
}

// TestApplicationMembershipAndStatusInvalidateSession 验证应用状态与成员状态变化会
// 立即影响应用绑定会话；无有效成员时拒绝签发。
func TestApplicationMembershipAndStatusInvalidateSession(t *testing.T) {
	env := newTestEnv(t)
	userID := "usr_00000000000000000000000000000009"
	appID := "app_00000000000000000000000000000009"
	env.insertUser(userID, "ivan", account.StatusActive, 1)
	env.insertApplication(appID, "active")

	// 非成员：拒绝签发应用会话。
	if _, err := env.session.Login(env.ctx, session.LoginRequest{
		Result: completeResult(userID, 1),
		AppID:  appID,
	}); !errors.Is(err, session.ErrAccountNotEligible) {
		t.Fatalf("非成员签发错误 = %v，期望 ErrAccountNotEligible", err)
	}

	env.insertMembership(appID, userID, "active")
	issued, err := env.session.Login(env.ctx, session.LoginRequest{
		Result: completeResult(userID, 1),
		AppID:  appID,
	})
	if err != nil {
		t.Fatalf("应用会话签发失败: %v", err)
	}
	if issued.Session.AppID != appID {
		t.Fatalf("会话应用 ID = %q，期望 %q", issued.Session.AppID, appID)
	}
	if _, err := env.session.Validate(env.ctx, issued.Secret.Reveal()); err != nil {
		t.Fatalf("应用会话校验失败: %v", err)
	}

	// 成员停用 -> 会话失效。
	env.exec(`UPDATE app_memberships SET status='disabled' WHERE app_id=? AND user_id=?`, appID, userID)
	if _, err := env.session.Validate(env.ctx, issued.Secret.Reveal()); !errors.Is(err, session.ErrSessionInvalid) {
		t.Fatalf("成员停用后校验错误 = %v，期望 ErrSessionInvalid", err)
	}

	// 成员恢复但应用停用 -> 会话仍失效。
	env.exec(`UPDATE app_memberships SET status='active' WHERE app_id=? AND user_id=?`, appID, userID)
	env.exec(`UPDATE applications SET status='disabled' WHERE id=?`, appID)
	if _, err := env.session.Validate(env.ctx, issued.Secret.Reveal()); !errors.Is(err, session.ErrSessionInvalid) {
		t.Fatalf("应用停用后校验错误 = %v，期望 ErrSessionInvalid", err)
	}
}

// TestConcurrentRenewAndRevoke 验证并发续期安全，以及撤销后并发续期全部失败。
func TestConcurrentRenewAndRevoke(t *testing.T) {
	env := newTestEnv(t)
	userID := "usr_00000000000000000000000000000010"
	env.insertUser(userID, "judy", account.StatusActive, 1)
	issued := env.loginComplete(userID, 1)

	const workers = 4
	var wait sync.WaitGroup
	errorsByWorker := make([]error, workers)
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func(slot int) {
			defer wait.Done()
			_, err := env.session.Renew(env.ctx, issued.Secret.Reveal())
			errorsByWorker[slot] = err
		}(index)
	}
	wait.Wait()
	for index, err := range errorsByWorker {
		if err != nil {
			t.Fatalf("并发续期 %d 失败: %v", index, err)
		}
	}
	if _, err := env.session.Validate(env.ctx, issued.Secret.Reveal()); err != nil {
		t.Fatalf("并发续期后会话应有效: %v", err)
	}

	// 撤销与续期并发：撤销返回后会话必然失效，之后的续期全部失败。
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for attempt := 0; attempt < 3; attempt++ {
				_, _ = env.session.Renew(env.ctx, issued.Secret.Reveal())
			}
		}()
	}
	if err := env.session.Logout(env.ctx, issued.Secret.Reveal()); err != nil {
		t.Fatalf("并发撤销失败: %v", err)
	}
	wait.Wait()
	if _, err := env.session.Validate(env.ctx, issued.Secret.Reveal()); !errors.Is(err, session.ErrSessionInvalid) {
		t.Fatalf("撤销后校验错误 = %v，期望 ErrSessionInvalid", err)
	}
	if _, err := env.session.Renew(env.ctx, issued.Secret.Reveal()); !errors.Is(err, session.ErrSessionInvalid) {
		t.Fatalf("撤销后续期错误 = %v，期望 ErrSessionInvalid", err)
	}
}

// TestRevokeAllForUser 验证服务端批量撤销共享同一撤销语义。
func TestRevokeAllForUser(t *testing.T) {
	env := newTestEnv(t)
	userID := "usr_00000000000000000000000000000011"
	env.insertUser(userID, "karl", account.StatusActive, 1)
	first := env.loginComplete(userID, 1)
	second := env.loginComplete(userID, 1)

	revoked, err := env.session.RevokeAllForUser(env.ctx, userID, session.RevokeReasonUserSessions)
	if err != nil {
		t.Fatalf("批量撤销失败: %v", err)
	}
	if revoked != 2 {
		t.Fatalf("批量撤销数量 = %d，期望 2", revoked)
	}
	for index, secret := range []string{first.Secret.Reveal(), second.Secret.Reveal()} {
		if _, err := env.session.Validate(env.ctx, secret); !errors.Is(err, session.ErrSessionInvalid) {
			t.Fatalf("批量撤销后会话 %d 校验错误 = %v，期望 ErrSessionInvalid", index, err)
		}
	}
	if _, err := env.session.RevokeAllForUser(env.ctx, userID, "bad reason with space"); !errors.Is(err, session.ErrInvalidRequest) {
		t.Fatalf("非法撤销原因错误 = %v，期望 ErrInvalidRequest", err)
	}
}

// TestIssuanceRejectsInconsistentOrIneligible 验证签发前的交叉校验：账户不可用、
// 安全版本不一致与自相矛盾的认证结果都不能签发会话。
func TestIssuanceRejectsInconsistentOrIneligible(t *testing.T) {
	env := newTestEnv(t)
	userID := "usr_00000000000000000000000000000012"
	env.insertUser(userID, "laura", account.StatusActive, 1)

	// 安全版本不一致（认证后账户安全版本已变化）。
	if _, err := env.session.Login(env.ctx, session.LoginRequest{Result: completeResult(userID, 9)}); !errors.Is(err, session.ErrAccountNotEligible) {
		t.Fatalf("安全版本不一致签发错误 = %v，期望 ErrAccountNotEligible", err)
	}
	// 禁用账户。
	env.exec(`UPDATE users SET status='disabled' WHERE id=?`, userID)
	if _, err := env.session.Login(env.ctx, session.LoginRequest{Result: completeResult(userID, 1)}); !errors.Is(err, session.ErrAccountNotEligible) {
		t.Fatalf("禁用账户签发错误 = %v，期望 ErrAccountNotEligible", err)
	}
	env.exec(`UPDATE users SET status='active' WHERE id=?`, userID)

	// 自相矛盾的结果：complete 但标记受限 / pending 但未标记受限。
	contradictory := completeResult(userID, 1)
	contradictory.Restricted = true
	if _, err := env.session.Login(env.ctx, session.LoginRequest{Result: contradictory}); !errors.Is(err, session.ErrInvalidRequest) {
		t.Fatalf("complete+受限签发错误 = %v，期望 ErrInvalidRequest", err)
	}
	notRestricted := pendingSecondFactorResult(userID, 1)
	notRestricted.Restricted = false
	if _, err := env.session.Login(env.ctx, session.LoginRequest{Result: notRestricted}); !errors.Is(err, session.ErrInvalidRequest) {
		t.Fatalf("pending+非受限签发错误 = %v，期望 ErrInvalidRequest", err)
	}
	// 非法用户 ID、非法应用 ID、非法请求编号。
	badUser := completeResult(userID, 1)
	badUser.UserID = "not-a-user-id"
	if _, err := env.session.Login(env.ctx, session.LoginRequest{Result: badUser}); !errors.Is(err, session.ErrInvalidRequest) {
		t.Fatalf("非法用户 ID 签发错误 = %v，期望 ErrInvalidRequest", err)
	}
	if _, err := env.session.Login(env.ctx, session.LoginRequest{Result: completeResult(userID, 1), AppID: "app with space"}); !errors.Is(err, session.ErrInvalidRequest) {
		t.Fatalf("非法应用 ID 签发错误 = %v，期望 ErrInvalidRequest", err)
	}
	if _, err := env.session.Login(env.ctx, session.LoginRequest{Result: completeResult(userID, 1), RequestID: "bad id"}); !errors.Is(err, session.ErrInvalidRequest) {
		t.Fatalf("非法请求编号签发错误 = %v，期望 ErrInvalidRequest", err)
	}

	// 被拒绝的签发不留下会话行。
	if got := env.queryInt(`SELECT COUNT(*) FROM sessions`); got != 0 {
		t.Fatalf("被拒绝的签发留下了 %d 条会话记录", got)
	}
}

// TestTamperedSecretRejected 验证任何对会话秘密的篡改都被拒绝（摘要比较 + 会话
// ID 绑定）。
func TestTamperedSecretRejected(t *testing.T) {
	env := newTestEnv(t)
	userID := "usr_00000000000000000000000000000013"
	env.insertUser(userID, "mallory", account.StatusActive, 1)
	issued := env.loginComplete(userID, 1)

	id, secret, ok := strings.Cut(issued.Secret.Reveal(), ".")
	if !ok {
		t.Fatal("会话秘密格式异常")
	}
	tampered := map[string]string{
		"改秘密":   id + "." + flipLast(secret),
		"改ID":   flipLast(id) + "." + secret,
		"空秘密":   id + ".",
		"纯ID":   id,
		"错误前缀":  "ses_x" + id[5:] + "." + secret,
		"另一个ID": id,
	}
	for name, value := range tampered {
		if _, err := env.session.Validate(env.ctx, value); !errors.Is(err, session.ErrSessionInvalid) {
			t.Errorf("%s 校验错误 = %v，期望 ErrSessionInvalid", name, err)
		}
	}
	// 两个会话 ID 的摘要不能互换：把第二个会话秘密拼到第一个 ID 上必须失败。
	other := env.loginComplete(userID, 1)
	otherID, otherSecret, _ := strings.Cut(other.Secret.Reveal(), ".")
	if _, err := env.session.Validate(env.ctx, id+"."+otherSecret); !errors.Is(err, session.ErrSessionInvalid) {
		t.Errorf("跨会话拼接的校验错误 = %v，期望 ErrSessionInvalid", err)
	}
	if _, err := env.session.Validate(env.ctx, otherID+"."+secret); !errors.Is(err, session.ErrSessionInvalid) {
		t.Errorf("跨会话拼接的校验错误 = %v，期望 ErrSessionInvalid", err)
	}
}

// flipLast 翻转字符串最后一个字符，制造被篡改的秘密。
func flipLast(value string) string {
	if value == "" {
		return "x"
	}
	last := value[len(value)-1]
	if last == 'a' {
		return value[:len(value)-1] + "b"
	}
	return value[:len(value)-1] + "a"
}

// TestCleanup 验证过期会话清理只删除已到期/已撤销且早于保留期的记录。
func TestCleanup(t *testing.T) {
	env := newTestEnv(t)
	userID := "usr_00000000000000000000000000000014"
	env.insertUser(userID, "nina", account.StatusActive, 1)
	issued := env.loginComplete(userID, 1)
	if err := env.session.Logout(env.ctx, issued.Secret.Reveal()); err != nil {
		t.Fatalf("退出失败: %v", err)
	}
	deleted, err := env.session.Cleanup(env.ctx, 0)
	if err != nil {
		t.Fatalf("清理失败: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("清理数量 = %d，期望 1", deleted)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM sessions`); got != 0 {
		t.Fatalf("清理后会话行数 = %d", got)
	}
	if _, err := env.session.Cleanup(env.ctx, time.Hour*24*40); !errors.Is(err, session.ErrInvalidRequest) {
		t.Fatalf("非法保留期错误 = %v，期望 ErrInvalidRequest", err)
	}
}

// TestNewRejectsInvalidOptions 验证构造会话服务时默认拒绝缺失/非法依赖。
func TestNewRejectsInvalidOptions(t *testing.T) {
	env := newTestEnv(t)
	keyring, err := secrets.GenerateKeyring("k2", testStart)
	if err != nil {
		t.Fatalf("生成密钥环失败: %v", err)
	}
	store, err := sessionsqlite.New(env.storage)
	if err != nil {
		t.Fatalf("构造存储失败: %v", err)
	}
	valid := session.Options{AllowLegacyWithoutSensitive: true, Store: store, Audit: env.audit, Keyring: keyring, Now: env.clock.Now}
	if _, err := session.New(nil, valid); !errors.Is(err, session.ErrOptionsInvalid) {
		t.Errorf("空存储构造错误 = %v，期望 ErrOptionsInvalid", err)
	}
	missingAudit := valid
	missingAudit.Audit = nil
	if _, err := session.New(store, missingAudit); !errors.Is(err, session.ErrOptionsInvalid) {
		t.Errorf("空审计构造错误 = %v，期望 ErrOptionsInvalid", err)
	}
	missingKeyring := valid
	missingKeyring.Keyring = nil
	if _, err := session.New(store, missingKeyring); !errors.Is(err, session.ErrOptionsInvalid) {
		t.Errorf("空密钥环构造错误 = %v，期望 ErrOptionsInvalid", err)
	}
	badIdle := valid
	badIdle.IdleTimeout = time.Second
	if _, err := session.New(store, badIdle); !errors.Is(err, session.ErrOptionsInvalid) {
		t.Errorf("过短空闲期限构造错误 = %v，期望 ErrOptionsInvalid", err)
	}
	badAbsolute := valid
	badAbsolute.AbsoluteTimeout = 2 * time.Minute
	if _, err := session.New(store, badAbsolute); !errors.Is(err, session.ErrOptionsInvalid) {
		t.Errorf("过短绝对期限构造错误 = %v，期望 ErrOptionsInvalid", err)
	}
	absoluteLessThanIdle := valid
	absoluteLessThanIdle.IdleTimeout = time.Hour
	absoluteLessThanIdle.AbsoluteTimeout = 10 * time.Minute
	if _, err := session.New(store, absoluteLessThanIdle); !errors.Is(err, session.ErrOptionsInvalid) {
		t.Errorf("绝对期限小于空闲期限构造错误 = %v，期望 ErrOptionsInvalid", err)
	}
	badCookieName := valid
	badCookieName.CookieName = "bad cookie name"
	if _, err := session.New(store, badCookieName); !errors.Is(err, session.ErrOptionsInvalid) {
		t.Errorf("非法 Cookie 名构造错误 = %v，期望 ErrOptionsInvalid", err)
	}
	insecureCookie := valid
	insecureCookie.CookiePolicy = &session.CookiePolicy{SameSite: http.SameSiteNoneMode, Path: "/"}
	if _, err := session.New(store, insecureCookie); !errors.Is(err, session.ErrOptionsInvalid) {
		t.Errorf("SameSite=None 且非 Secure 构造错误 = %v，期望 ErrOptionsInvalid", err)
	}
}

// TestSecretRedaction 验证会话秘密类型的字符串化/JSON/日志都脱敏。
func TestSecretRedaction(t *testing.T) {
	env := newTestEnv(t)
	userID := "usr_00000000000000000000000000000015"
	env.insertUser(userID, "oscar", account.StatusActive, 1)
	issued := env.loginComplete(userID, 1)
	for name, text := range map[string]string{
		"String":   issued.Secret.String(),
		"GoString": issued.Secret.GoString(),
		"CSRF":     issued.CSRFSecret.String(),
	} {
		if text != "[REDACTED]" {
			t.Errorf("%s = %q，期望 [REDACTED]", name, text)
		}
	}
	if !strings.Contains(env.logs.String(), "会话已签发") {
		t.Error("运行日志缺少会话签发记录")
	}
}
