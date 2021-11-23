package recovery_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/ratelimit"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/recovery"
	recoverysqlite "github.com/kagurazakayashi/EvernightLogin/internal/recovery/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	sessionsqlite "github.com/kagurazakayashi/EvernightLogin/internal/session/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// seedTime 只用于密钥环/审计时间基准的确定性，不用于模拟“未来时间”；测试服务时钟
// 默认取真实 time.Now()，按需相对推进（DEV_CHECKLIST A1）。
var seedTime = time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)

const (
	userID = "usr_00000000000000000000000000000001"
	userB  = "usr_00000000000000000000000000000002"
	rootID = "usr_00000000000000000000000000000003"
)

var codeFormat = regexp.MustCompile(`^[A-Z2-7]{4}(-[A-Z2-7]{4}){3}$`)

// gateHolder 解决 session.Options.RecoveryGate 与 recovery.Service 的构造循环依赖：
// 会话服务先构造，随后注入恢复服务指针。
type gateHolder struct {
	service *recovery.Service
}

// AuthorizeRecoverySession 实现 session.RecoverySessionGate。
func (g *gateHolder) AuthorizeRecoverySession(ctx context.Context, request session.RecoverySessionRequest) error {
	if g.service == nil {
		return errors.New("恢复服务尚未装配")
	}
	return g.service.AuthorizeRecoverySession(ctx, request)
}

// fakeReauth 是 reauth.OperationRunner 的测试替身，只验证恢复流程是否正确调用近期
// 认证与执行后告知；不模拟真实密码校验（真实路径在 internal/reauth 测试覆盖）。
type fakeReauth struct {
	mu       sync.Mutex
	err      error
	requests []reauth.Request
	notified []reauth.Outcome
}

func (f *fakeReauth) Authorize(_ context.Context, _ reauth.Caller, request reauth.Request) (reauth.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, request)
	if f.err != nil {
		return reauth.Result{}, f.err
	}
	return reauth.Result{UserID: request.TargetID, OperationID: request.OperationID, TargetID: request.TargetID}, nil
}

func (f *fakeReauth) NotifyOutcome(_ context.Context, _ reauth.Result, outcome reauth.Outcome) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.notified = append(f.notified, outcome)
	return nil
}

// fakeBinder 是新安全方式绑定适配器的测试替身。它模拟“真实因素服务验证成功/失败”的
// 结果：生产装配必须调用 internal/totp / internal/passkey 完成真实校验；本替身不
// 证明真实验证器兼容性，只验证恢复流程的接口契约与失败语义。
type fakeBinder struct {
	mu          sync.Mutex
	beginErr    error
	verifyErr   error
	verifyProof *recovery.FactorProof
	begins      []recovery.FactorBindRequest
	verifies    []recovery.FactorVerifyRequest
	clock       func() time.Time
}

func (f *fakeBinder) BeginRebind(_ context.Context, request recovery.FactorBindRequest) (recovery.FactorBindStart, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.begins = append(f.begins, request)
	if f.beginErr != nil {
		return recovery.FactorBindStart{}, f.beginErr
	}
	return recovery.FactorBindStart{
		Method:     request.Method,
		BindingID:  "bind_" + string(request.Method),
		PublicData: []byte(`{"test":"binding"}`),
		ExpiresAt:  f.clock().Add(10 * time.Minute),
	}, nil
}

func (f *fakeBinder) VerifyRebind(_ context.Context, request recovery.FactorVerifyRequest) (recovery.FactorProof, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verifies = append(f.verifies, request)
	if f.verifyErr != nil {
		return recovery.FactorProof{}, f.verifyErr
	}
	if f.verifyProof != nil {
		return *f.verifyProof, nil
	}
	return recovery.FactorProof{
		Method:       request.Method,
		FactorRef:    "factor_ref_1",
		UserVerified: request.Method == recovery.MethodPasskey,
		VerifiedAt:   f.clock(),
	}, nil
}

// fakeRevoker 记录旧因素撤销请求。
type fakeRevoker struct {
	mu      sync.Mutex
	calls   []recovery.LegacyFactorRevocation
	failErr error
}

func (f *fakeRevoker) RevokeLegacyFactors(_ context.Context, request recovery.LegacyFactorRevocation) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, request)
	return f.failErr
}

// captureNotifier 记录安全告知。
type captureNotifier struct {
	mu            sync.Mutex
	notifications []recovery.Notification
	failErr       error
}

func (c *captureNotifier) Notify(_ context.Context, notification recovery.Notification) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.notifications = append(c.notifications, notification)
	return c.failErr
}

// failingAudit 注入审计事务失败，用于验证“事务失败整体回滚、代码不丢”。
type failingAudit struct {
	inner        recovery.AuditRecorder
	mu           sync.Mutex
	failCritical int
}

func (f *failingAudit) Record(ctx context.Context, event audit.Event) error {
	return f.inner.Record(ctx, event)
}

func (f *failingAudit) RecordFailure(ctx context.Context, event audit.Event) error {
	return f.inner.RecordFailure(ctx, event)
}

func (f *failingAudit) ExecuteCritical(ctx context.Context, request audit.CriticalRequest, change audit.Change) error {
	f.mu.Lock()
	if f.failCritical > 0 {
		f.failCritical--
		f.mu.Unlock()
		return fmt.Errorf("%w: 注入审计失败", recovery.ErrAuditUnavailable)
	}
	f.mu.Unlock()
	return f.inner.ExecuteCritical(ctx, request, change)
}

type testEnv struct {
	t            *testing.T
	ctx          context.Context
	storage      *storagesqlite.Store
	recorder     *audit.Recorder
	keyring      *secrets.Keyring
	store        *recoverysqlite.Store
	sessions     *session.Service
	service      *recovery.Service
	reauth       *fakeReauth
	binder       *fakeBinder
	revoker      *fakeRevoker
	notifier     *captureNotifier
	now          time.Time
	strength     recovery.Strength
	strengthErr  error
	authLevel    recovery.AuthLevel
	authLevelErr error
}

func newTestEnv(t *testing.T, mutate func(*recovery.Options)) *testEnv {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(testutil.TempDir(t), "recovery-test.db")
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
	env := &testEnv{t: t, ctx: ctx, storage: storage, now: time.Now().UTC().Truncate(time.Millisecond),
		strength: recovery.StrengthStrong, authLevel: recovery.AuthLevelPassword}
	env.recorder, err = audit.New(auditStore, audit.Options{Now: func() time.Time { return env.now }})
	if err != nil {
		t.Fatalf("审计: %v", err)
	}
	keyring, err := secrets.GenerateKeyring("k1", seedTime)
	if err != nil {
		t.Fatalf("密钥环: %v", err)
	}
	env.keyring = keyring
	sessionStore, err := sessionsqlite.New(storage)
	if err != nil {
		t.Fatalf("会话存储: %v", err)
	}
	holder := &gateHolder{}
	sessionService, err := session.New(sessionStore, session.Options{
		Audit: env.recorder, Keyring: keyring, Now: func() time.Time { return env.now },
		RecoveryGate: holder,
	})
	if err != nil {
		t.Fatalf("会话服务: %v", err)
	}
	env.sessions = sessionService
	recoveryStore, err := recoverysqlite.New(storage)
	if err != nil {
		t.Fatalf("恢复存储: %v", err)
	}
	env.store = recoveryStore
	env.reauth = &fakeReauth{}
	env.binder = &fakeBinder{clock: func() time.Time { return env.now }}
	env.revoker = &fakeRevoker{}
	env.notifier = &captureNotifier{}
	options := recovery.Options{
		Store: recoveryStore, Audit: env.recorder, Keyring: keyring, Sessions: sessionService,
		Reauth: env.reauth,
		Requirements: recovery.RequirementsFunc(func(context.Context, string) (recovery.Strength, error) {
			return env.strength, env.strengthErr
		}),
		AuthLevels: recovery.AuthLevelRequirementsFunc(func(context.Context, string) (recovery.AuthLevel, error) {
			return env.authLevel, env.authLevelErr
		}),
		Binder: env.binder, FactorRevoker: env.revoker, Notifier: env.notifier,
		Now: func() time.Time { return env.now },
	}
	if mutate != nil {
		mutate(&options)
	}
	service, err := recovery.New(options)
	if err != nil {
		t.Fatalf("恢复服务: %v", err)
	}
	env.service = service
	holder.service = service
	return env
}

// seedUser 插入合成用户（可选已验证邮箱）并返回安全版本。
func (env *testEnv) seedUser(user string, isRoot bool, email string) int64 {
	env.t.Helper()
	nowMS := env.now.UnixMilli()
	username := "user-" + user[len(user)-2:]
	_, err := env.storage.ExecContext(env.ctx,
		`INSERT INTO users(id,username,username_normalized,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
		 VALUES(?,?,?,?,?,?,?,?,?)`,
		user, username, username, "active", boolInt(isRoot), 1, 1, nowMS, nowMS)
	if err != nil {
		env.t.Fatalf("插入用户 %s: %v", user, err)
	}
	if email != "" {
		_, err = env.storage.ExecContext(env.ctx,
			`INSERT INTO user_emails(email_normalized,user_id,email,verified_at_ms,created_at_ms,updated_at_ms)
			 VALUES(?,?,?,?,?,?)`,
			email, user, email, nowMS, nowMS, nowMS)
		if err != nil {
			env.t.Fatalf("插入已验证邮箱: %v", err)
		}
	}
	return 1
}

// boolInt 把布尔值转换为 SQLite 整数。
func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

// pendingSecondFactorResult 构造第一步密码已通过、仍待第二因素的受限认证结果。
func (env *testEnv) pendingSecondFactorResult(user string, securityVersion int64) authn.AuthenticateResult {
	return authn.AuthenticateResult{
		UserID:           user,
		Username:         "user",
		Outcome:          authn.OutcomePendingSecondFactor,
		CompletedMethods: []authn.Method{authn.MethodPassword},
		CompletedAt:      env.now,
		RequiredSteps:    []authn.Step{authn.StepSecondFactor},
		Restricted:       true,
		SecurityVersion:  securityVersion,
	}
}

// strongAuthContext 返回携带“近期强认证”可信事实的上下文（模拟宿主会话中间件
// 把 session.StrongAuthVerifiedAt/Strength 映射为 reauth.Signals）。
func (env *testEnv) strongAuthContext() context.Context {
	return reauth.WithSignals(env.ctx, reauth.Signals{
		VerifiedAt: env.now,
		Strength:   policy.StrengthStrong,
		Complete:   true,
		Confirmed:  false,
	})
}

// generate 生成一组恢复代码并返回明文。
func (env *testEnv) generate() []recovery.Code {
	env.t.Helper()
	caller, err := recovery.UserCaller(userID)
	if err != nil {
		env.t.Fatalf("用户调用者: %v", err)
	}
	result, err := env.service.Generate(env.ctx, caller, recovery.GenerateRequest{RequestID: "req-gen-1"})
	if err != nil {
		env.t.Fatalf("生成恢复代码: %v", err)
	}
	return result.Codes
}

// beginWith 使用给定代码开始恢复。
func (env *testEnv) beginWith(code recovery.Code, securityVersion int64) (recovery.BeginResult, error) {
	env.t.Helper()
	return env.service.Begin(env.ctx, recovery.BeginRequest{
		Result:    env.pendingSecondFactorResult(userID, securityVersion),
		Code:      code.Reveal(),
		RequestID: "req-begin-1",
	})
}

// rebindAndComplete 完成 BeginRebind + Complete 的成功路径。
func (env *testEnv) rebindAndComplete(begin recovery.BeginResult, method recovery.FactorMethod) recovery.CompletionResult {
	env.t.Helper()
	secret := begin.Session.Secret.Reveal()
	if _, err := env.service.BeginRebind(env.ctx, secret, recovery.BeginRebindRequest{Method: method, RequestID: "req-rebind-1"}); err != nil {
		env.t.Fatalf("开始重新绑定: %v", err)
	}
	result, err := env.service.Complete(env.ctx, secret, recovery.CompleteRequest{
		BindingID: "bind_" + string(method), Response: []byte(`{"verified":true}`), RequestID: "req-complete-1",
	})
	if err != nil {
		env.t.Fatalf("完成恢复: %v", err)
	}
	return result
}

// auditDetails 返回审计事件明细 JSON 拼接（用于断言不含恢复代码明文）。
func (env *testEnv) auditDetails() string {
	env.t.Helper()
	rows, err := env.storage.QueryContext(env.ctx, `SELECT action,COALESCE(detail_json,''),COALESCE(error_code,''),COALESCE(reason_code,'') FROM audit_events`)
	if err != nil {
		env.t.Fatalf("读取审计: %v", err)
	}
	defer rows.Close()
	var builder strings.Builder
	for rows.Next() {
		var action, detail, errorCode, reasonCode string
		if err := rows.Scan(&action, &detail, &errorCode, &reasonCode); err != nil {
			env.t.Fatalf("扫描审计: %v", err)
		}
		builder.WriteString(action)
		builder.WriteString(detail)
		builder.WriteString(errorCode)
		builder.WriteString(reasonCode)
		builder.WriteString("\n")
	}
	if err := rows.Err(); err != nil {
		env.t.Fatalf("审计行: %v", err)
	}
	return builder.String()
}

// countRows 统计简单计数查询。
func (env *testEnv) countRows(query string, args ...any) int {
	env.t.Helper()
	var count int
	rows, err := env.storage.QueryContext(env.ctx, query, args...)
	if err != nil {
		env.t.Fatalf("计数查询失败: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		env.t.Fatalf("计数查询没有结果")
	}
	if err := rows.Scan(&count); err != nil {
		env.t.Fatalf("计数查询失败: %v", err)
	}
	return count
}

// scalarInt64 读取单个整数。
func (env *testEnv) scalarInt64(query string, args ...any) int64 {
	env.t.Helper()
	var value int64
	rows, err := env.storage.QueryContext(env.ctx, query, args...)
	if err != nil {
		env.t.Fatalf("标量查询失败: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		env.t.Fatalf("标量查询没有结果")
	}
	if err := rows.Scan(&value); err != nil {
		env.t.Fatalf("标量查询失败: %v", err)
	}
	return value
}

// TestGenerateCodesLifecycle 验证：高熵一次性代码、只存摘要、按组管理、重新生成使
// 旧组失效、root 拒绝、未接 reauth 时 fail-closed。
func TestGenerateCodesLifecycle(t *testing.T) {
	env := newTestEnv(t, nil)
	env.seedUser(userID, false, "user@example.test")
	codes := env.generate()
	if len(codes) != recovery.DefaultCodeCount {
		t.Fatalf("代码数量 = %d，期望 %d", len(codes), recovery.DefaultCodeCount)
	}
	for _, code := range codes {
		if !codeFormat.MatchString(code.Reveal()) {
			t.Fatalf("代码格式异常: %q", code.Reveal())
		}
		if strings.Contains(fmt.Sprint(code), "REDACTED") == false {
			t.Errorf("代码默认字符串化应脱敏")
		}
	}
	// 数据库只保存 32 字节 HMAC 摘要，不出现任何代码明文。
	if count := env.countRows(`SELECT COUNT(*) FROM recovery_codes`); count != recovery.DefaultCodeCount {
		t.Fatalf("代码行数 = %d", count)
	}
	rows, err := env.storage.QueryContext(env.ctx, `SELECT hex(digest),key_id FROM recovery_codes`)
	if err != nil {
		t.Fatalf("读取摘要: %v", err)
	}
	defer rows.Close()
	digests := make(map[string]bool)
	for rows.Next() {
		var digestHex, keyID string
		if err := rows.Scan(&digestHex, &keyID); err != nil {
			t.Fatalf("扫描摘要: %v", err)
		}
		if len(digestHex) != 64 {
			t.Fatalf("摘要长度 = %d，期望 64 个十六进制字符", len(digestHex))
		}
		if keyID != "k1" {
			t.Fatalf("key_id = %q", keyID)
		}
		digests[digestHex] = true
	}
	if len(digests) != recovery.DefaultCodeCount {
		t.Fatalf("摘要去重后数量 = %d", len(digests))
	}
	auditDetails := env.auditDetails()
	for _, code := range codes {
		if strings.Contains(auditDetails, strings.ReplaceAll(code.Reveal(), "-", "")) ||
			strings.Contains(auditDetails, code.Reveal()) {
			t.Fatalf("审计泄露了恢复代码明文")
		}
	}
	if !strings.Contains(auditDetails, string(recovery.ActionCodesGenerated)) {
		t.Fatalf("缺少生成恢复代码审计")
	}
	if env.countRows(`SELECT COUNT(*) FROM recovery_code_groups WHERE status='active'`) != 1 {
		t.Fatalf("活动代码组数量不为 1")
	}
	// 重新生成：旧组立即失效，新组为 generation 2。
	second := env.generate()
	if env.countRows(`SELECT COUNT(*) FROM recovery_code_groups WHERE status='superseded'`) != 1 {
		t.Fatalf("旧代码组未被作废")
	}
	if env.countRows(`SELECT COUNT(*) FROM recovery_code_groups WHERE status='active' AND generation=2`) != 1 {
		t.Fatalf("新代码组 generation 不为 2")
	}
	// 旧代码在新组生成后不可再用。
	if _, err := env.beginWith(codes[0], 1); !errors.Is(err, recovery.ErrCodeInvalid) {
		t.Fatalf("旧代码仍可用: %v", err)
	}
	// 新代码可用。
	if _, err := env.beginWith(second[0], 1); err != nil {
		t.Fatalf("新代码不可用: %v", err)
	}
	// 未装配 reauth 时重新生成 fail-closed（REAUTH_REQUIRED）。
	envNoReauth := newTestEnv(t, func(options *recovery.Options) { options.Reauth = nil })
	envNoReauth.seedUser(userID, false, "")
	caller, _ := recovery.UserCaller(userID)
	if _, err := envNoReauth.service.Generate(envNoReauth.ctx, caller, recovery.GenerateRequest{RequestID: "req-x"}); !errors.Is(err, recovery.ErrReauthRequired) {
		t.Fatalf("未接 reauth 应 fail-closed，得到 %v", err)
	}
	// root 生成恢复代码被拒绝。
	envRoot := newTestEnv(t, nil)
	envRoot.seedUser(rootID, true, "")
	callerRoot, _ := recovery.UserCaller(rootID)
	if _, err := envRoot.service.Generate(envRoot.ctx, callerRoot, recovery.GenerateRequest{RequestID: "req-root"}); !errors.Is(err, recovery.ErrRootProtected) {
		t.Fatalf("root 应被拒绝，得到 %v", err)
	}
}

// TestGenerateReauthDenied 验证近期认证失败时不生成代码且留失败审计。
func TestGenerateReauthDenied(t *testing.T) {
	env := newTestEnv(t, func(options *recovery.Options) {
		options.Reauth = &fakeReauth{err: reauth.ErrReauthRequired}
	})
	env.seedUser(userID, false, "")
	caller, _ := recovery.UserCaller(userID)
	if _, err := env.service.Generate(env.ctx, caller, recovery.GenerateRequest{RequestID: "req-deny"}); !errors.Is(err, recovery.ErrReauthRequired) {
		t.Fatalf("期望 ErrReauthRequired，得到 %v", err)
	}
	if env.countRows(`SELECT COUNT(*) FROM recovery_codes`) != 0 {
		t.Fatalf("近期认证失败仍创建了恢复代码")
	}
	if !strings.Contains(env.auditDetails(), "reauth_denied") {
		t.Fatalf("缺少拒绝路径失败审计")
	}
}

// TestBeginConsumesCodeAndCreatesRestrictedSession 验证代码原子消费、受限恢复会话、
// 重复使用被拒绝、已有进行中尝试时不同代码不被烧掉、业务/管理访问被拒绝。
func TestBeginConsumesCodeAndCreatesRestrictedSession(t *testing.T) {
	env := newTestEnv(t, nil)
	env.seedUser(userID, false, "user@example.test")
	codes := env.generate()
	begin, err := env.beginWith(codes[0], 1)
	if err != nil {
		t.Fatalf("开始恢复: %v", err)
	}
	if begin.Session.Session.Kind != session.KindRestricted || begin.Session.Session.Reason != session.ReasonRecovery {
		t.Fatalf("恢复会话类别错误: %+v", begin.Session.Session)
	}
	if begin.CodesRemaining != recovery.DefaultCodeCount-1 {
		t.Fatalf("剩余代码 = %d", begin.CodesRemaining)
	}
	if len(begin.AllowedMethods) != 1 || begin.AllowedMethods[0] != recovery.MethodPasskey {
		t.Fatalf("强认证要求下允许方式错误: %v", begin.AllowedMethods)
	}
	if env.countRows(`SELECT COUNT(*) FROM recovery_attempts WHERE status='pending_binding'`) != 1 {
		t.Fatalf("未创建待绑定尝试")
	}
	if env.countRows(`SELECT COUNT(*) FROM recovery_codes WHERE used_at_ms IS NOT NULL`) != 1 {
		t.Fatalf("代码未被消费")
	}
	// 同一代码重放。
	secret := begin.Session.Secret.Reveal()
	if _, err := env.beginWith(codes[0], 1); !errors.Is(err, recovery.ErrCodeInvalid) {
		t.Fatalf("同一代码重放应拒绝，得到 %v", err)
	}
	// 已有进行中尝试时使用另一枚代码：事务回滚，代码不被烧掉。
	if _, err := env.beginWith(codes[1], 1); !errors.Is(err, recovery.ErrAttemptInProgress) {
		t.Fatalf("期望 ErrAttemptInProgress，得到 %v", err)
	}
	if env.countRows(`SELECT COUNT(*) FROM recovery_codes WHERE used_at_ms IS NOT NULL`) != 1 {
		t.Fatalf("并发尝试失败时代码被误消费")
	}
	// 受限恢复会话不能访问业务/管理接口。
	if _, err := env.sessions.AuthorizeBusiness(env.ctx, secret); !errors.Is(err, session.ErrRestrictedSession) {
		t.Fatalf("恢复会话可访问业务接口: %v", err)
	}
	if _, err := env.sessions.AuthorizeManagement(env.ctx, secret); !errors.Is(err, session.ErrRestrictedSession) {
		t.Fatalf("恢复会话可访问管理接口: %v", err)
	}
	// 普通完整会话不能替代恢复会话调用恢复接口。
	if _, err := env.service.Snapshot(env.ctx, "ses_invalid.invalid"); !errors.Is(err, recovery.ErrSessionRequired) {
		t.Fatalf("无效会话应拒绝，得到 %v", err)
	}
	if !strings.Contains(env.auditDetails(), string(recovery.ActionCodeUsed)) {
		t.Fatalf("缺少代码使用审计")
	}
}

// TestConcurrentDuplicateCodeSingleWinner 验证并发重复使用同一代码只有一个成功。
func TestConcurrentDuplicateCodeSingleWinner(t *testing.T) {
	env := newTestEnv(t, nil)
	env.seedUser(userID, false, "")
	codes := env.generate()
	const workers = 8
	var wait sync.WaitGroup
	results := make([]error, workers)
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			_, err := env.beginWith(codes[0], 1)
			results[index] = err
		}(index)
	}
	wait.Wait()
	successes := 0
	for _, err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("并发重复使用成功次数 = %d，期望 1（错误：%v）", successes, results)
	}
	if env.countRows(`SELECT COUNT(*) FROM recovery_codes WHERE used_at_ms IS NOT NULL`) != 1 {
		t.Fatalf("并发消费出现多次消费")
	}
	if env.countRows(`SELECT COUNT(*) FROM recovery_attempts`) != 1 {
		t.Fatalf("并发消费产生多个恢复尝试")
	}
}

// TestBeginRejectsInvalidFirstStep 验证恢复代码不能替代密码，也不能作用于 root。
func TestBeginRejectsInvalidFirstStep(t *testing.T) {
	env := newTestEnv(t, nil)
	env.seedUser(userID, false, "")
	codes := env.generate()
	complete := env.pendingSecondFactorResult(userID, 1)
	complete.Outcome = authn.OutcomeComplete
	complete.Restricted = false
	complete.RequiredSteps = nil
	if _, err := env.service.Begin(env.ctx, recovery.BeginRequest{Result: complete, Code: codes[0].Reveal(), RequestID: "req-complete"}); !errors.Is(err, recovery.ErrAccessDenied) {
		t.Fatalf("完整认证结果应拒绝，得到 %v", err)
	}
	noPassword := env.pendingSecondFactorResult(userID, 1)
	noPassword.CompletedMethods = []authn.Method{authn.MethodTOTP}
	if _, err := env.service.Begin(env.ctx, recovery.BeginRequest{Result: noPassword, Code: codes[0].Reveal(), RequestID: "req-nopass"}); !errors.Is(err, recovery.ErrAccessDenied) {
		t.Fatalf("没有密码方法应拒绝，得到 %v", err)
	}
	if _, err := env.beginWith(codes[0], 99); !errors.Is(err, recovery.ErrAccessDenied) {
		t.Fatalf("安全版本不一致应拒绝，得到 %v", err)
	}
	rootEnv := newTestEnv(t, nil)
	rootEnv.seedUser(rootID, true, "")
	if _, err := rootEnv.service.Begin(rootEnv.ctx, recovery.BeginRequest{
		Result: rootEnv.pendingSecondFactorResult(rootID, 1), Code: "AAAA-BBBB-CCCC-DDDD",
		RequestID: "req-root",
	}); !errors.Is(err, recovery.ErrRootProtected) {
		t.Fatalf("root 恢复应拒绝，得到 %v", err)
	}
	// 没有代码组时拒绝。
	emptyEnv := newTestEnv(t, nil)
	emptyEnv.seedUser(userID, false, "")
	if _, err := emptyEnv.service.Begin(emptyEnv.ctx, recovery.BeginRequest{
		Result: emptyEnv.pendingSecondFactorResult(userID, 1), Code: "AAAA-BBBB-CCCC-DDDD", RequestID: "req-none",
	}); !errors.Is(err, recovery.ErrNoActiveGroup) {
		t.Fatalf("无代码组应拒绝，得到 %v", err)
	}
}

// TestRebindCompleteLifecycle 验证完整恢复：强度约束、绑定 ID 绑定、新因素验证、
// 旧组作废并生成新组、安全版本递增、会话撤销、旧因素撤销、告知与审计。
func TestRebindCompleteLifecycle(t *testing.T) {
	env := newTestEnv(t, nil)
	env.seedUser(userID, false, "user@example.test")
	// 恢复前已存在的普通会话：完成后必须被撤销/失效。
	normalResult := authn.AuthenticateResult{
		UserID: userID, Username: "user", Outcome: authn.OutcomeComplete,
		CompletedMethods: []authn.Method{authn.MethodPassword}, CompletedAt: env.now,
		SecurityVersion: 1,
	}
	normalSession, err := env.sessions.Login(env.ctx, session.LoginRequest{Result: normalResult, RequestID: "req-normal"})
	if err != nil {
		t.Fatalf("签发恢复前普通会话: %v", err)
	}
	codes := env.generate()
	begin, err := env.beginWith(codes[0], 1)
	if err != nil {
		t.Fatalf("开始恢复: %v", err)
	}
	secret := begin.Session.Secret.Reveal()
	snapshot, err := env.service.Snapshot(env.ctx, secret)
	if err != nil {
		t.Fatalf("核对恢复状态: %v", err)
	}
	if snapshot.RequiredStrength != recovery.StrengthStrong || snapshot.CodesRemaining != recovery.DefaultCodeCount-1 {
		t.Fatalf("快照内容异常: %+v", snapshot)
	}
	// 强认证要求下 TOTP 不允许降级。
	if _, err := env.service.BeginRebind(env.ctx, secret, recovery.BeginRebindRequest{Method: recovery.MethodTOTP, RequestID: "req-totp"}); !errors.Is(err, recovery.ErrMethodNotAllowed) {
		t.Fatalf("强认证下 TOTP 应拒绝，得到 %v", err)
	}
	start, err := env.service.BeginRebind(env.ctx, secret, recovery.BeginRebindRequest{Method: recovery.MethodPasskey, RequestID: "req-passkey"})
	if err != nil {
		t.Fatalf("开始绑定 Passkey: %v", err)
	}
	if start.BindingID != "bind_passkey" {
		t.Fatalf("绑定 ID = %q", start.BindingID)
	}
	// 绑定 ID 不一致时拒绝。
	if _, err := env.service.Complete(env.ctx, secret, recovery.CompleteRequest{BindingID: "other", RequestID: "req-bad"}); !errors.Is(err, recovery.ErrRebindFailed) {
		t.Fatalf("绑定 ID 不一致应拒绝，得到 %v", err)
	}
	// 真实验证失败：进度不变、尝试仍待绑定。
	env.binder.verifyErr = errors.New("authenticator rejected")
	if _, err := env.service.Complete(env.ctx, secret, recovery.CompleteRequest{BindingID: start.BindingID, Response: []byte(`{}`), RequestID: "req-fail"}); !errors.Is(err, recovery.ErrRebindFailed) {
		t.Fatalf("验证失败应拒绝，得到 %v", err)
	}
	attempt := env.loadAttempt()
	if attempt.Status != recovery.AttemptPendingBinding || attempt.Attempts != 1 {
		t.Fatalf("验证失败后尝试状态异常: %+v", attempt)
	}
	if env.scalarInt64(`SELECT security_version FROM users WHERE id=?`, userID) != 1 {
		t.Fatalf("验证失败不应递增安全版本")
	}
	env.binder.verifyErr = nil
	result := env.rebindAndComplete(begin, recovery.MethodPasskey)
	if !result.ReloginRequired {
		t.Fatalf("完成后必须要求重新登录")
	}
	if len(result.Codes) != recovery.DefaultCodeCount || result.Generation != 2 {
		t.Fatalf("新代码组异常: %+v", result)
	}
	if result.SessionsRevoked < 1 {
		t.Fatalf("完成后应撤销既有会话，实际撤销 %d", result.SessionsRevoked)
	}
	if _, err := env.sessions.Validate(env.ctx, normalSession.Secret.Reveal()); !errors.Is(err, session.ErrSessionInvalid) {
		t.Fatalf("恢复前普通会话完成后应失效，得到 %v", err)
	}
	for _, code := range result.Codes {
		if code.Reveal() == codes[1].Reveal() {
			t.Fatalf("新代码组复用了旧代码")
		}
	}
	if env.scalarInt64(`SELECT security_version FROM users WHERE id=?`, userID) != 2 {
		t.Fatalf("完成后安全版本未递增")
	}
	if env.countRows(`SELECT COUNT(*) FROM recovery_code_groups WHERE status='superseded'`) != 1 {
		t.Fatalf("旧代码组未作废")
	}
	if env.countRows(`SELECT COUNT(*) FROM recovery_code_groups WHERE status='active' AND generation=2`) != 1 {
		t.Fatalf("未生成新代码组")
	}
	if attempt = env.loadAttempt(); attempt.Status != recovery.AttemptCompleted || attempt.FactorMethod != recovery.MethodPasskey {
		t.Fatalf("尝试未完成: %+v", attempt)
	}
	if len(env.revoker.calls) != 1 || env.revoker.calls[0].KeepMethod != recovery.MethodPasskey {
		t.Fatalf("旧因素撤销调用异常: %+v", env.revoker.calls)
	}
	if !result.LegacyFactorsRevoked {
		t.Fatalf("旧因素撤销未成功")
	}
	// 恢复会话在完成后失效（安全版本已变化）。
	if _, err := env.service.Snapshot(env.ctx, secret); !errors.Is(err, recovery.ErrSessionRequired) {
		t.Fatalf("完成后恢复会话应失效，得到 %v", err)
	}
	// 旧代码全部失效：完成时安全版本已递增，旧版本结果被拒绝；使用当前版本时
	// 旧组代码不再存在。
	if _, err := env.beginWith(codes[1], 1); !errors.Is(err, recovery.ErrAccessDenied) {
		t.Fatalf("旧安全版本应拒绝，得到 %v", err)
	}
	if _, err := env.beginWith(codes[1], 2); !errors.Is(err, recovery.ErrCodeInvalid) {
		t.Fatalf("完成后旧代码仍可用: %v", err)
	}
	// 通知与审计齐全且不含代码明文。
	if len(env.notifier.notifications) < 3 {
		t.Fatalf("安全告知数量不足: %d", len(env.notifier.notifications))
	}
	details := env.auditDetails()
	for _, code := range append(append([]recovery.Code{}, codes...), result.Codes...) {
		if strings.Contains(details, code.Reveal()) {
			t.Fatalf("审计泄露恢复代码")
		}
	}
	if !strings.Contains(details, string(recovery.ActionRecoveryComplete)) {
		t.Fatalf("缺少完成审计")
	}
}

// TestCompleteRequiresStrongProof 验证高权限账户恢复不得降级：无 UV 的 Passkey 证明
// 与 TOTP 证明都不能完成强认证恢复。
func TestCompleteRequiresStrongProof(t *testing.T) {
	env := newTestEnv(t, nil)
	env.seedUser(userID, false, "")
	codes := env.generate()
	begin, err := env.beginWith(codes[0], 1)
	if err != nil {
		t.Fatalf("开始恢复: %v", err)
	}
	secret := begin.Session.Secret.Reveal()
	if _, err := env.service.BeginRebind(env.ctx, secret, recovery.BeginRebindRequest{Method: recovery.MethodPasskey, RequestID: "req-b"}); err != nil {
		t.Fatalf("开始绑定: %v", err)
	}
	proof := recovery.FactorProof{Method: recovery.MethodPasskey, FactorRef: "ref", UserVerified: false, VerifiedAt: env.now}
	env.binder.verifyProof = &proof
	if _, err := env.service.Complete(env.ctx, secret, recovery.CompleteRequest{BindingID: "bind_passkey", Response: []byte(`{}`), RequestID: "req-c"}); !errors.Is(err, recovery.ErrStrengthNotMet) {
		t.Fatalf("无 UV 证明应拒绝，得到 %v", err)
	}
	if env.loadAttempt().Status != recovery.AttemptPendingBinding {
		t.Fatalf("强度不足时恢复被错误完成")
	}
	// 普通用户（要求第二因素）允许 TOTP。
	env.strength = recovery.StrengthSecondFactor
	if _, err := env.service.BeginRebind(env.ctx, secret, recovery.BeginRebindRequest{Method: recovery.MethodTOTP, RequestID: "req-t"}); err != nil {
		t.Fatalf("普通用户开始绑定 TOTP: %v", err)
	}
	env.binder.verifyProof = nil
	result, err := env.service.Complete(env.ctx, secret, recovery.CompleteRequest{BindingID: "bind_totp", Response: []byte(`{}`), RequestID: "req-ct"})
	if err != nil {
		t.Fatalf("普通用户 TOTP 恢复失败: %v", err)
	}
	if result.LegacyFactorsRevoked != true {
		t.Fatalf("普通用户恢复结果异常")
	}
}

// TestCancelPreservesOldState 验证取消只结束尝试与恢复会话，不删除旧因素、不生成
// 新组，旧代码组内其他代码仍然有效。
func TestCancelPreservesOldState(t *testing.T) {
	env := newTestEnv(t, nil)
	env.seedUser(userID, false, "")
	codes := env.generate()
	begin, err := env.beginWith(codes[0], 1)
	if err != nil {
		t.Fatalf("开始恢复: %v", err)
	}
	secret := begin.Session.Secret.Reveal()
	if err := env.service.Cancel(env.ctx, secret, recovery.CancelRequest{RequestID: "req-cancel"}); err != nil {
		t.Fatalf("取消恢复: %v", err)
	}
	if attempt := env.loadAttempt(); attempt.Status != recovery.AttemptCancelled {
		t.Fatalf("尝试状态 = %s", attempt.Status)
	}
	if len(env.revoker.calls) != 0 {
		t.Fatalf("取消不应撤销旧因素")
	}
	if env.countRows(`SELECT COUNT(*) FROM recovery_code_groups WHERE status='active'`) != 1 {
		t.Fatalf("取消不应作废旧代码组")
	}
	if env.scalarInt64(`SELECT security_version FROM users WHERE id=?`, userID) != 1 {
		t.Fatalf("取消不应递增安全版本")
	}
	// 恢复会话已退出。
	if _, err := env.service.Snapshot(env.ctx, secret); !errors.Is(err, recovery.ErrSessionRequired) {
		t.Fatalf("取消后恢复会话应不可用，得到 %v", err)
	}
	// 另一枚代码仍可使用。
	if _, err := env.beginWith(codes[1], 1); err != nil {
		t.Fatalf("取消后另一枚代码不可用: %v", err)
	}
}

// TestExpiredAttemptAndSession 验证短时过期：尝试过期后拒绝并迁移状态；恢复会话到期
// 后拒绝。
func TestExpiredAttemptAndSession(t *testing.T) {
	env := newTestEnv(t, func(options *recovery.Options) {
		options.AttemptTTL = 5 * time.Minute
	})
	env.seedUser(userID, false, "")
	codes := env.generate()
	begin, err := env.beginWith(codes[0], 1)
	if err != nil {
		t.Fatalf("开始恢复: %v", err)
	}
	secret := begin.Session.Secret.Reveal()
	// 尝试有效期 5 分钟、恢复会话 15 分钟：先推进到尝试过期，验证惰性状态迁移。
	env.now = env.now.Add(6 * time.Minute)
	if _, err := env.service.Snapshot(env.ctx, secret); !errors.Is(err, recovery.ErrAttemptExpired) {
		t.Fatalf("过期尝试应拒绝，得到 %v", err)
	}
	if env.countRows(`SELECT COUNT(*) FROM recovery_attempts WHERE status='pending_binding'`) != 0 {
		t.Fatalf("过期尝试未被处理")
	}
	// 重新开始一次恢复，再推进到恢复会话过期（尝试内新会话）。
	codes2 := env.generate()
	begin2, err := env.beginWith(codes2[0], 1)
	if err != nil {
		t.Fatalf("重新开始恢复: %v", err)
	}
	env.now = env.now.Add(session.DefaultRecoverySessionTTL + time.Minute)
	if _, err := env.service.Snapshot(env.ctx, begin2.Session.Secret.Reveal()); !errors.Is(err, recovery.ErrSessionRequired) {
		t.Fatalf("过期恢复会话应拒绝，得到 %v", err)
	}
}

// TestTransactionFailureRollsBack 注入审计事务失败，验证代码不被烧掉、恢复状态不变。
func TestTransactionFailureRollsBack(t *testing.T) {
	var inject *failingAudit
	env := newTestEnv(t, func(options *recovery.Options) {
		inject = &failingAudit{inner: options.Audit}
		options.Audit = inject
	})
	env.seedUser(userID, false, "")
	// 用真实审计写入一组代码：临时把失败注入关掉。
	codes := env.generate()
	begin, err := env.beginWith(codes[0], 1)
	if err != nil {
		t.Fatalf("开始恢复: %v", err)
	}
	secret := begin.Session.Secret.Reveal()
	if _, err := env.service.BeginRebind(env.ctx, secret, recovery.BeginRebindRequest{Method: recovery.MethodPasskey, RequestID: "req-b"}); err != nil {
		t.Fatalf("开始绑定: %v", err)
	}
	inject.mu.Lock()
	inject.failCritical = 1
	inject.mu.Unlock()
	if _, err := env.service.Complete(env.ctx, secret, recovery.CompleteRequest{BindingID: "bind_passkey", Response: []byte(`{}`), RequestID: "req-fail"}); !errors.Is(err, recovery.ErrAuditUnavailable) {
		t.Fatalf("审计失败应拒绝完成，得到 %v", err)
	}
	if attempt := env.loadAttempt(); attempt.Status != recovery.AttemptPendingBinding {
		t.Fatalf("事务失败后尝试状态被改变: %s", attempt.Status)
	}
	if env.scalarInt64(`SELECT security_version FROM users WHERE id=?`, userID) != 1 {
		t.Fatalf("事务失败后安全版本被改变")
	}
	if env.countRows(`SELECT COUNT(*) FROM recovery_code_groups WHERE status='active'`) != 1 {
		t.Fatalf("事务失败后旧代码组被作废")
	}
	// 恢复会话仍可用，重试成功。
	if _, err := env.service.Snapshot(env.ctx, secret); err != nil {
		t.Fatalf("事务失败后恢复会话应仍可用: %v", err)
	}
	if _, err := env.service.Complete(env.ctx, secret, recovery.CompleteRequest{BindingID: "bind_passkey", Response: []byte(`{}`), RequestID: "req-retry"}); err != nil {
		t.Fatalf("重试完成失败: %v", err)
	}
}

// TestCompletionRequiresPlannedRebind 验证未开始绑定就不能完成恢复。
func TestCompletionRequiresPlannedRebind(t *testing.T) {
	env := newTestEnv(t, nil)
	env.seedUser(userID, false, "")
	codes := env.generate()
	begin, err := env.beginWith(codes[0], 1)
	if err != nil {
		t.Fatalf("开始恢复: %v", err)
	}
	if _, err := env.service.Complete(env.ctx, begin.Session.Secret.Reveal(), recovery.CompleteRequest{BindingID: "x", Response: []byte(`{}`), RequestID: "req-c"}); !errors.Is(err, recovery.ErrRebindNotStarted) {
		t.Fatalf("未开始绑定应拒绝，得到 %v", err)
	}
}

// TestRequirementsFailClosed 验证强度要求不可用时 fail-closed 且不烧代码。
func TestRequirementsFailClosed(t *testing.T) {
	env := newTestEnv(t, nil)
	env.seedUser(userID, false, "")
	codes := env.generate()
	env.strengthErr = errors.New("authz unavailable")
	if _, err := env.beginWith(codes[0], 1); !errors.Is(err, recovery.ErrRequirementsUnavail) {
		t.Fatalf("要求不可用应拒绝，得到 %v", err)
	}
	if env.countRows(`SELECT COUNT(*) FROM recovery_codes WHERE used_at_ms IS NOT NULL`) != 0 {
		t.Fatalf("要求不可用时代码被消费")
	}
	env.strengthErr = nil
	// 未注入 Requirements 时默认按强认证要求（fail-closed）。
	envDefault := newTestEnv(t, func(options *recovery.Options) { options.Requirements = nil })
	envDefault.seedUser(userID, false, "")
	// 默认强度不可从外部读取；用 TOTP 绑定被拒绝证明默认要求强认证。
	begin, err := envDefault.beginWith(envDefault.generateCodes()[0], 1)
	if err == nil {
		if _, err := envDefault.service.BeginRebind(envDefault.ctx, begin.Session.Secret.Reveal(), recovery.BeginRebindRequest{Method: recovery.MethodTOTP, RequestID: "req-t"}); !errors.Is(err, recovery.ErrMethodNotAllowed) {
			t.Fatalf("默认强度应拒绝 TOTP，得到 %v", err)
		}
	}
}

// generateCodes 生成新代码并返回（供默认强度用例）。
func (env *testEnv) generateCodes() []recovery.Code {
	env.t.Helper()
	caller, _ := recovery.UserCaller(userID)
	result, err := env.service.Generate(env.ctx, caller, recovery.GenerateRequest{RequestID: "req-gen-x"})
	if err != nil {
		env.t.Fatalf("生成恢复代码: %v", err)
	}
	return result.Codes
}

// loadAttempt 读取唯一恢复尝试。
func (env *testEnv) loadAttempt() recovery.Attempt {
	env.t.Helper()
	rows, err := env.storage.QueryContext(env.ctx, `SELECT id FROM recovery_attempts ORDER BY created_at_ms DESC LIMIT 1`)
	if err != nil {
		env.t.Fatalf("读取尝试: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		env.t.Fatalf("没有恢复尝试")
	}
	var id string
	if err := rows.Scan(&id); err != nil {
		env.t.Fatalf("扫描尝试: %v", err)
	}
	attempt, found, err := env.store.GetAttempt(env.ctx, id)
	if err != nil || !found {
		env.t.Fatalf("读取尝试详情: %v", err)
	}
	return attempt
}

// TestMailNotifier 验证邮件安全告知只向已验证邮箱发送、正文不含恢复代码明文。
func TestMailNotifier(t *testing.T) {
	env := newTestEnv(t, nil)
	env.seedUser(userID, false, "user@example.test")
	var captured []mailer.Message
	sender := mailer.SenderFunc(func(_ context.Context, message mailer.Message) error {
		captured = append(captured, message)
		return nil
	})
	notifier, err := recovery.NewMailNotifier(env.store, sender, "noreply@example.test", "EvernightLogin", "https://example.test/support")
	if err != nil {
		t.Fatalf("构造邮件告知器: %v", err)
	}
	codes := env.generateCodes()
	if err := notifier.Notify(env.ctx, recovery.Notification{
		Kind: recovery.NotificationCodesGenerated, UserID: userID, Username: "user",
		Event: "恢复代码已重新生成。", OccurredAt: env.now,
	}); err != nil {
		t.Fatalf("发送告知: %v", err)
	}
	if len(captured) != 1 {
		t.Fatalf("邮件数量 = %d", len(captured))
	}
	message := captured[0]
	if len(message.To) != 1 || message.To[0].Spec != "user@example.test" {
		t.Fatalf("收件人错误: %+v", message.To)
	}
	for _, code := range codes {
		if strings.Contains(message.Subject, code.Reveal()) || strings.Contains(message.TextBody, code.Reveal()) {
			t.Fatalf("安全告知泄露恢复代码")
		}
	}
	// 无已验证邮箱时告知失败但不影响业务（本方法只返回错误，由调用方不回滚）。
	envNoEmail := newTestEnv(t, nil)
	envNoEmail.seedUser(userB, false, "")
	notifier2, err := recovery.NewMailNotifier(envNoEmail.store, sender, "noreply@example.test", "EvernightLogin", "https://example.test/support")
	if err != nil {
		t.Fatalf("构造邮件告知器: %v", err)
	}
	if err := notifier2.Notify(envNoEmail.ctx, recovery.Notification{Kind: recovery.NotificationRecoveryStarted, UserID: userB, Event: "x", OccurredAt: envNoEmail.now}); !errors.Is(err, recovery.ErrNotificationFailed) {
		t.Fatalf("无邮箱应失败，得到 %v", err)
	}
}

// TestGenerateStrongLevelRequiresStrongAuth 验证 44-FIX 的 MFA 绕过修复：已绑定强
// 因素/高权限账户更新恢复代码必须持有近期强认证，否则拒绝且旧组保持有效。
func TestGenerateStrongLevelRequiresStrongAuth(t *testing.T) {
	env := newTestEnv(t, nil)
	env.seedUser(userID, false, "user@example.test")
	codes := env.generate()
	caller, _ := recovery.UserCaller(userID)
	// 账户要求强认证：仅“完整会话+密码”（无强认证事实）不能重新生成恢复代码。
	env.authLevel = recovery.AuthLevelStrong
	if _, err := env.service.Generate(env.ctx, caller, recovery.GenerateRequest{RequestID: "req-strong-1"}); !errors.Is(err, recovery.ErrStrongAuthRequired) {
		t.Fatalf("仅密码级会话应拒绝，得到 %v", err)
	}
	if env.countRows(`SELECT COUNT(*) FROM recovery_code_groups WHERE status='active' AND generation=1`) != 1 {
		t.Fatalf("拒绝后旧代码组不应失效")
	}
	if !strings.Contains(env.auditDetails(), "strong_auth_incomplete") {
		t.Fatalf("拒绝路径缺少失败审计")
	}
	// 过旧强认证事实同样拒绝。
	staleCtx := reauth.WithSignals(env.ctx, reauth.Signals{
		VerifiedAt: env.now.Add(-16 * time.Minute), Strength: policy.StrengthStrong, Complete: true,
	})
	if _, err := env.service.Generate(staleCtx, caller, recovery.GenerateRequest{RequestID: "req-strong-2"}); !errors.Is(err, recovery.ErrStrongAuthRequired) {
		t.Fatalf("过旧强认证应拒绝，得到 %v", err)
	}
	// 近期强认证事实存在时允许，且旧组失效、生成新组并发送告知。
	notificationsBefore := len(env.notifier.notifications)
	result, err := env.service.Generate(env.strongAuthContext(), caller, recovery.GenerateRequest{RequestID: "req-strong-3"})
	if err != nil {
		t.Fatalf("近期强认证下应允许更新恢复代码: %v", err)
	}
	if result.Generation != 2 || len(result.Codes) != recovery.DefaultCodeCount {
		t.Fatalf("新代码组异常: %+v", result)
	}
	if env.countRows(`SELECT COUNT(*) FROM recovery_code_groups WHERE status='superseded' AND generation=1`) != 1 {
		t.Fatalf("旧代码组未失效")
	}
	if len(env.notifier.notifications) <= notificationsBefore {
		t.Fatalf("更新恢复代码后缺少安全告知")
	}
	// 旧代码不可再用。
	if _, err := env.beginWith(codes[0], 1); !errors.Is(err, recovery.ErrCodeInvalid) {
		t.Fatalf("旧代码仍可用: %v", err)
	}
}

// TestGenerateAuthLevelFailClosed 验证未注入所需强度契约/契约报错时 fail-closed。
func TestGenerateAuthLevelFailClosed(t *testing.T) {
	envDefault := newTestEnv(t, func(options *recovery.Options) { options.AuthLevels = nil })
	envDefault.seedUser(userID, false, "")
	caller, _ := recovery.UserCaller(userID)
	// 未注入契约默认要求强认证，普通上下文（无信号）被拒绝。
	if _, err := envDefault.service.Generate(envDefault.ctx, caller, recovery.GenerateRequest{RequestID: "req-default"}); !errors.Is(err, recovery.ErrStrongAuthRequired) {
		t.Fatalf("未注入强度契约应 fail-closed，得到 %v", err)
	}
	// 契约错误 → 要求不可用，不生成代码。
	envErr := newTestEnv(t, nil)
	envErr.seedUser(userID, false, "")
	envErr.authLevelErr = errors.New("authz unavailable")
	if _, err := envErr.service.Generate(envErr.ctx, caller, recovery.GenerateRequest{RequestID: "req-err"}); !errors.Is(err, recovery.ErrRequirementsUnavail) {
		t.Fatalf("强度契约错误应 fail-closed，得到 %v", err)
	}
	if envErr.countRows(`SELECT COUNT(*) FROM recovery_codes`) != 0 {
		t.Fatalf("契约错误时不应生成恢复代码")
	}
}

// TestBeginRateLimited 验证恢复代码尝试的账户维度有界限流。
func TestBeginRateLimited(t *testing.T) {
	env := newTestEnv(t, func(options *recovery.Options) {
		options.BeginRatePolicy = ratelimit.Policy{Limit: 3, Window: time.Minute}
	})
	env.seedUser(userID, false, "")
	env.generate()
	// 三次错误代码尝试（均计入限流）。
	for index := 0; index < 3; index++ {
		if _, err := env.service.Begin(env.ctx, recovery.BeginRequest{
			Result:    env.pendingSecondFactorResult(userID, 1),
			Code:      "AAAA-BBBB-CCCC-DDDD",
			RequestID: "req-rate",
		}); !errors.Is(err, recovery.ErrCodeInvalid) {
			t.Fatalf("第 %d 次错误代码应返回 CHALLENGE_INVALID，得到 %v", index+1, err)
		}
	}
	// 第 4 次被限流拒绝并写失败审计。
	if _, err := env.service.Begin(env.ctx, recovery.BeginRequest{
		Result: env.pendingSecondFactorResult(userID, 1), Code: "AAAA-BBBB-CCCC-DDDD", RequestID: "req-rate",
	}); !errors.Is(err, recovery.ErrRateLimited) {
		t.Fatalf("超过限流应拒绝，得到 %v", err)
	}
	if !strings.Contains(env.auditDetails(), "begin_rate_limited") {
		t.Fatalf("限流拒绝缺少失败审计")
	}
}

// TestCompleteFailsWhenOldGroupInvalidated 验证 44-FIX：旧代码组已被并发撤销/取代时
// 完成恢复 fail-closed，不插入新的 active 组、不改变安全版本。
func TestCompleteFailsWhenOldGroupInvalidated(t *testing.T) {
	env := newTestEnv(t, nil)
	env.seedUser(userID, false, "")
	codes := env.generate()
	begin, err := env.beginWith(codes[0], 1)
	if err != nil {
		t.Fatalf("开始恢复: %v", err)
	}
	secret := begin.Session.Secret.Reveal()
	if _, err := env.service.BeginRebind(env.ctx, secret, recovery.BeginRebindRequest{Method: recovery.MethodPasskey, RequestID: "req-b"}); err != nil {
		t.Fatalf("开始绑定: %v", err)
	}
	if _, err := env.storage.ExecContext(env.ctx, `UPDATE recovery_code_groups SET status='revoked',invalidated_at_ms=? WHERE user_id=? AND status='active'`, env.now.UnixMilli(), userID); err != nil {
		t.Fatalf("模拟旧组被撤销: %v", err)
	}
	if _, err := env.service.Complete(env.ctx, secret, recovery.CompleteRequest{BindingID: "bind_passkey", Response: []byte(`{}`), RequestID: "req-c"}); !errors.Is(err, recovery.ErrConcurrentRotation) {
		t.Fatalf("旧组被撤销时应 fail-closed，得到 %v", err)
	}
	if attempt := env.loadAttempt(); attempt.Status != recovery.AttemptPendingBinding {
		t.Fatalf("失败后尝试状态被改变: %s", attempt.Status)
	}
	if env.countRows(`SELECT COUNT(*) FROM recovery_code_groups WHERE status='active'`) != 0 {
		t.Fatalf("失败后仍插入新 active 组")
	}
	if env.scalarInt64(`SELECT security_version FROM users WHERE id=?`, userID) != 1 {
		t.Fatalf("失败后安全版本被改变")
	}
}

// TestCodeOfReusesRegisteredCodes 验证恢复领域只投影既有错误码。
func TestCodeOfReusesRegisteredCodes(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want recovery.ErrorCode
	}{
		{name: "非法请求", err: recovery.ErrInvalidRequest, want: recovery.CodeReqInvalid},
		{name: "越权", err: recovery.ErrAccessDenied, want: recovery.CodeAccessDenied},
		{name: "root", err: recovery.ErrRootProtected, want: recovery.CodeAccessDenied},
		{name: "近期认证", err: recovery.ErrReauthRequired, want: recovery.CodeReauthRequired},
		{name: "需要重新绑定", err: recovery.ErrSessionRequired, want: recovery.CodeMFARebindRequired},
		{name: "强度不足", err: recovery.ErrStrengthNotMet, want: recovery.CodeMFARebindRequired},
		{name: "方法不允许", err: recovery.ErrMethodNotAllowed, want: recovery.CodeMFARebindRequired},
		{name: "代码无效", err: recovery.ErrCodeInvalid, want: recovery.CodeChallengeInvalid},
		{name: "尝试过期", err: recovery.ErrAttemptExpired, want: recovery.CodeChallengeInvalid},
		{name: "并发", err: recovery.ErrAttemptInProgress, want: recovery.CodeConflict},
		{name: "存储", err: recovery.ErrStoreUnavailable, want: recovery.CodeDBUnavailable},
		{name: "审计", err: recovery.ErrAuditUnavailable, want: recovery.CodeAuditWriteFailed},
		{name: "告知", err: recovery.ErrNotificationFailed, want: recovery.CodeMailDeliveryFailed},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := recovery.CodeOf(test.err); got != test.want {
				t.Fatalf("CodeOf(%v) = %s，期望 %s", test.err, got, test.want)
			}
		})
	}
}
