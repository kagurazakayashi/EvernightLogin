package reauth_test

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailtest"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	policysqlite "github.com/kagurazakayashi/EvernightLogin/internal/policy/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/profile"
	profilesqlite "github.com/kagurazakayashi/EvernightLogin/internal/profile/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	reauthsqlite "github.com/kagurazakayashi/EvernightLogin/internal/reauth/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

var seedTime = time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)

const (
	rootUserID   = "usr_00000000000000000000000000000001"
	normalUserID = "usr_00000000000000000000000000000002"
	noMailUserID = "usr_00000000000000000000000000000003"
)

// fakeVerifier 是受控的密码验证替身：只用于本包单元测试，生产适配为
// authn.ReauthPasswordVerifier（真实密码校验、限流与审计）。
type fakeVerifier struct {
	mu          sync.Mutex
	secret      string
	complete    bool
	completedAt time.Time
	err         error
	calls       int
}

func (f *fakeVerifier) VerifyPassword(ctx context.Context, request reauth.PasswordVerifyRequest) (reauth.PasswordVerifyResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return reauth.PasswordVerifyResult{}, f.err
	}
	if request.Password != f.secret {
		return reauth.PasswordVerifyResult{}, errors.New("密码错误")
	}
	completedAt := f.completedAt
	if completedAt.IsZero() {
		completedAt = time.Now().UTC()
	}
	return reauth.PasswordVerifyResult{UserID: request.UserID, CompletedAt: completedAt,
		Complete: f.complete}, nil
}

type testEnv struct {
	t             *testing.T
	ctx           context.Context
	storage       *storagesqlite.Store
	policyService *policy.Service
	service       *reauth.Service
	stores        reauth.Store
	recorder      *audit.Recorder
	now           time.Time
	verifier      *fakeVerifier
	mu            sync.Mutex
	sent          []mailer.Message
	senderErr     error
}

func newTestEnv(t *testing.T, mutate func(*reauth.Options)) *testEnv {
	t.Helper()
	return newTestEnvWithHooks(t, mutate, nil)
}

// newTestEnvWithHooks 与 newTestEnv 相同，但在构造服务前额外执行 after 钩子，
// 便于测试注入与 reauth 共享同一数据库的 mailer 投递服务（步骤 210 的关联读取）。
func newTestEnvWithHooks(t *testing.T, mutate func(*reauth.Options),
	after func(*testEnv, *reauth.Options)) *testEnv {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(testutil.TempDir(t), "reauth-test.db")
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
	recorder, err := audit.New(auditStore, audit.Options{Now: func() time.Time { return seedTime }})
	if err != nil {
		t.Fatalf("审计: %v", err)
	}
	policyStore, err := policysqlite.New(storage)
	if err != nil {
		t.Fatalf("策略存储: %v", err)
	}
	env := &testEnv{t: t, ctx: ctx, storage: storage, recorder: recorder, now: time.Now().UTC(),
		verifier: &fakeVerifier{secret: "correct-password", complete: true, completedAt: time.Now().UTC()}}
	policyService, err := policy.New(policy.Options{
		Store: policyStore, Audit: recorder,
		ReauthVerifier: policy.ReauthVerifierFunc(func(ctx context.Context, caller policy.Caller, operationID string) error {
			return nil
		}),
		Now: func() time.Time { return env.now },
	})
	if err != nil {
		t.Fatalf("策略服务: %v", err)
	}
	env.policyService = policyService
	reauthStore, err := reauthsqlite.New(storage)
	if err != nil {
		t.Fatalf("再次认证存储: %v", err)
	}
	env.stores = reauthStore
	options := reauth.Options{
		Store: reauthStore, Audit: recorder, Policy: policyService,
		Passwords: env.verifier,
		Mailer: mailer.SenderFunc(func(ctx context.Context, message mailer.Message) error {
			env.mu.Lock()
			defer env.mu.Unlock()
			if env.senderErr != nil {
				return env.senderErr
			}
			env.sent = append(env.sent, message)
			return nil
		}),
		FromAddress: "security@example.com", AppName: "登录服务", SupportURL: "https://example.com/support",
		Now:    func() time.Time { return env.now },
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}
	if mutate != nil {
		mutate(&options)
	}
	if after != nil {
		after(env, &options)
	}
	service, err := reauth.New(options)
	if err != nil {
		t.Fatalf("再次认证服务: %v", err)
	}
	env.service = service
	env.seedUser(rootUserID, "root", true)
	env.seedUser(normalUserID, "alice", false)
	env.seedUser(noMailUserID, "bob", false)
	env.seedEmail(normalUserID, "alice@example.com")
	return env
}

func (e *testEnv) seedUser(id, username string, root bool) {
	e.t.Helper()
	now := seedTime.UnixMilli()
	isRoot := 0
	if root {
		isRoot = 1
	}
	if _, err := e.storage.DB().ExecContext(e.ctx, `INSERT INTO users(
id,username,username_normalized,nickname,biography,avatar_ref,language,timezone,status,is_root,
security_version,row_version,created_at_ms,updated_at_ms
) VALUES(?,?,?,'','',NULL,'zh-CN','Asia/Shanghai','active',?,1,1,?,?)`,
		id, username, username, isRoot, now, now); err != nil {
		e.t.Fatalf("用户: %v", err)
	}
}

func (e *testEnv) seedEmail(userID, address string) {
	e.t.Helper()
	now := seedTime.UnixMilli()
	if _, err := e.storage.DB().ExecContext(e.ctx, `INSERT INTO user_emails(
email_normalized,user_id,email,verified_at_ms,created_at_ms,updated_at_ms
) VALUES(?,?,?,?,?,?)`, strings.ToLower(address), userID, address, now, now, now); err != nil {
		e.t.Fatalf("邮箱: %v", err)
	}
}

func (e *testEnv) userCaller(t *testing.T, userID string) reauth.Caller {
	t.Helper()
	caller, err := reauth.UserCaller(userID)
	if err != nil {
		t.Fatalf("用户调用者: %v", err)
	}
	return caller
}

func (e *testEnv) rootCaller(t *testing.T) reauth.Caller { return e.userCaller(t, rootUserID) }

func (e *testEnv) count(query string, args ...any) int {
	e.t.Helper()
	var value int
	if err := e.storage.DB().QueryRowContext(e.ctx, query, args...).Scan(&value); err != nil {
		e.t.Fatalf("计数: %v", err)
	}
	return value
}

func (e *testEnv) sentCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.sent)
}

func (e *testEnv) lastMessage() mailer.Message {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.sent) == 0 {
		e.t.Fatal("没有捕获到邮件")
	}
	return e.sent[len(e.sent)-1]
}

// setPolicy 通过真实策略服务（root + 再次验证）修改覆盖值。
func (e *testEnv) setPolicy(t *testing.T, operationID string, change policy.PolicyChange, expected int64) {
	t.Helper()
	caller, err := policy.UserCaller(rootUserID)
	if err != nil {
		t.Fatalf("root 策略调用者: %v", err)
	}
	if _, err := e.policyService.Set(e.ctx, caller, policy.SetRequest{
		ScopeID: "system", OperationID: operationID, Change: change,
		ExpectedVersion: expected, RequestID: "req-policy-set"}); err != nil {
		t.Fatalf("设置策略 %s: %v", operationID, err)
	}
}

func request(operationID string) reauth.Request {
	return reauth.Request{ScopeID: "system", OperationID: operationID,
		TargetType: "user", TargetID: normalUserID,
		Params: map[string]string{"expected_row_version": "1"}, Description: "测试敏感操作"}
}

func freshSignals(now time.Time) reauth.Signals {
	return reauth.Signals{VerifiedAt: now.Add(-time.Minute), Strength: policy.StrengthPassword,
		Complete: true, Confirmed: true}
}

// TestAuthorizeFreshStaleWeakAndConfirmed 覆盖近期/过期认证、弱认证拒绝与确认要求。
func TestAuthorizeFreshStaleWeakAndConfirmed(t *testing.T) {
	env := newTestEnv(t, nil)
	caller := env.userCaller(t, normalUserID)
	env.now = time.Now().UTC()

	ctx := reauth.WithSignals(env.ctx, freshSignals(env.now))
	result, err := env.service.Authorize(ctx, caller, request("profile.username.change"))
	if err != nil {
		t.Fatalf("近期密码认证应通过: %v", err)
	}
	if result.Method != "direct" || !result.Decision.Sensitive {
		t.Fatalf("授权结果异常: %+v", result)
	}
	// 过期认证：默认新鲜度 600 秒，20 分钟前视为过期。
	stale := freshSignals(env.now)
	stale.VerifiedAt = env.now.Add(-20 * time.Minute)
	if _, err := env.service.Authorize(reauth.WithSignals(env.ctx, stale), caller,
		request("profile.username.change")); !errors.Is(err, reauth.ErrReauthRequired) {
		t.Errorf("过期认证错误 = %v，期望 ErrReauthRequired", err)
	}
	// 弱认证（未达到策略要求强度）拒绝，且不降级。
	weak := freshSignals(env.now)
	weak.Strength = policy.StrengthNone
	if _, err := env.service.Authorize(reauth.WithSignals(env.ctx, weak), caller,
		request("profile.username.change")); !errors.Is(err, reauth.ErrMFARequired) {
		t.Errorf("弱认证错误 = %v，期望 ErrMFARequired", err)
	}
	// 缺少确认。
	unconfirmed := freshSignals(env.now)
	unconfirmed.Confirmed = false
	if _, err := env.service.Authorize(reauth.WithSignals(env.ctx, unconfirmed), caller,
		request("profile.username.change")); !errors.Is(err, reauth.ErrConfirmationRequired) {
		t.Errorf("缺少确认错误 = %v，期望 ErrConfirmationRequired", err)
	}
	// 未知操作 fail-closed 为请求错误，并留执行前失败审计。
	if _, err := env.service.Authorize(reauth.WithSignals(env.ctx, freshSignals(env.now)), caller,
		request("unknown.operation")); !errors.Is(err, reauth.ErrInvalidRequest) {
		t.Errorf("未知操作错误 = %v，期望 ErrInvalidRequest", err)
	}
	if events := env.count(`SELECT COUNT(*) FROM audit_events WHERE action='reauth.authorize' AND outcome<>'success'`); events == 0 {
		t.Error("执行前拒绝没有写失败审计")
	}
}

// TestChallengeApprovalBindingReplayAndExpiry 覆盖挑战、对象替换、参数替换、重放与过期。
func TestChallengeApprovalBindingReplayAndExpiry(t *testing.T) {
	env := newTestEnv(t, nil)
	caller := env.userCaller(t, normalUserID)
	env.now = time.Now().UTC()
	env.verifier.completedAt = env.now

	challenge, err := env.service.BeginChallenge(env.ctx, caller, reauth.ChallengeRequest{
		ScopeID: "system", OperationID: "profile.username.change",
		TargetType: "user", TargetID: normalUserID,
		Params: map[string]string{"expected_row_version": "1"}, Description: "修改用户名"})
	if err != nil {
		t.Fatalf("创建挑战: %v", err)
	}
	if !challenge.Required || challenge.RequiredStrength != policy.StrengthPassword {
		t.Fatalf("挑战异常: %+v", challenge)
	}
	// 错误密码：拒绝、递增尝试、写失败审计。
	if _, err := env.service.VerifyChallenge(env.ctx, caller, reauth.VerifyChallengeRequest{
		ChallengeID: challenge.ID, Password: "wrong-password", RequestID: "req-verify-bad"}); !errors.Is(err, reauth.ErrAuthenticationFailed) {
		t.Fatalf("错误密码错误 = %v，期望 ErrAuthenticationFailed", err)
	}
	if attempts := env.count(`SELECT attempts FROM reauth_challenges WHERE id=?`, challenge.ID); attempts != 1 {
		t.Errorf("尝试次数 = %d，期望 1", attempts)
	}
	if events := env.count(`SELECT COUNT(*) FROM audit_events WHERE action='reauth.verify_failed' AND outcome<>'success'`); events != 1 {
		t.Errorf("密码失败审计数 = %d，期望 1", events)
	}
	// 正确密码：一次性批准；执行前授权成功。
	grant, err := env.service.VerifyChallenge(env.ctx, caller, reauth.VerifyChallengeRequest{
		ChallengeID: challenge.ID, Password: "correct-password", RequestID: "req-verify-ok"})
	if err != nil {
		t.Fatalf("正确密码验证: %v", err)
	}
	if grant.Token == "" || grant.GrantedStrength != policy.StrengthPassword {
		t.Fatalf("批准异常: %+v", grant)
	}
	signals := reauth.Signals{ApprovalToken: grant.Token, Confirmed: true}
	result, err := env.service.Authorize(reauth.WithSignals(env.ctx, signals), caller,
		request("profile.username.change"))
	if err != nil {
		t.Fatalf("使用批准授权: %v", err)
	}
	if result.Method != "approval" || result.ApprovalID == "" {
		t.Fatalf("批准授权结果异常: %+v", result)
	}
	// 重放同一批准：拒绝。
	if _, err := env.service.Authorize(reauth.WithSignals(env.ctx, signals), caller,
		request("profile.username.change")); !errors.Is(err, reauth.ErrApprovalConsumed) {
		t.Errorf("重复批准错误 = %v，期望 ErrApprovalConsumed", err)
	}
	// 对象替换：为目标 A 创建批准，尝试用于目标 B。
	challenge2, err := env.service.BeginChallenge(env.ctx, caller, reauth.ChallengeRequest{
		ScopeID: "system", OperationID: "profile.username.change",
		TargetType: "user", TargetID: normalUserID, Params: map[string]string{"expected_row_version": "1"}})
	if err != nil {
		t.Fatalf("第二个挑战: %v", err)
	}
	grant2, err := env.service.VerifyChallenge(env.ctx, caller, reauth.VerifyChallengeRequest{
		ChallengeID: challenge2.ID, Password: "correct-password", RequestID: "req-verify-2"})
	if err != nil {
		t.Fatalf("第二个批准: %v", err)
	}
	replaced := request("profile.username.change")
	replaced.TargetID = rootUserID
	if _, err := env.service.Authorize(reauth.WithSignals(env.ctx,
		reauth.Signals{ApprovalToken: grant2.Token, Confirmed: true}), caller, replaced); !errors.Is(err, reauth.ErrApprovalInvalid) {
		t.Errorf("对象替换错误 = %v，期望 ErrApprovalInvalid", err)
	}
	// 参数替换：同一批准换参数摘要同样拒绝（对象未变）。
	challenge3, err := env.service.BeginChallenge(env.ctx, caller, reauth.ChallengeRequest{
		ScopeID: "system", OperationID: "profile.username.change",
		TargetType: "user", TargetID: normalUserID, Params: map[string]string{"expected_row_version": "2"}})
	if err != nil {
		t.Fatalf("第三个挑战: %v", err)
	}
	grant3, err := env.service.VerifyChallenge(env.ctx, caller, reauth.VerifyChallengeRequest{
		ChallengeID: challenge3.ID, Password: "correct-password", RequestID: "req-verify-3"})
	if err != nil {
		t.Fatalf("第三个批准: %v", err)
	}
	if _, err := env.service.Authorize(reauth.WithSignals(env.ctx,
		reauth.Signals{ApprovalToken: grant3.Token, Confirmed: true}), caller,
		request("profile.username.change")); !errors.Is(err, reauth.ErrApprovalInvalid) {
		t.Errorf("参数替换错误 = %v，期望 ErrApprovalInvalid", err)
	}
	// 批准过期：新建批准后把时钟推进到有效期之后。
	challenge4, err := env.service.BeginChallenge(env.ctx, caller, reauth.ChallengeRequest{
		ScopeID: "system", OperationID: "profile.username.change",
		TargetType: "user", TargetID: normalUserID, Params: map[string]string{"expected_row_version": "1"}})
	if err != nil {
		t.Fatalf("第四个挑战: %v", err)
	}
	grant4, err := env.service.VerifyChallenge(env.ctx, caller, reauth.VerifyChallengeRequest{
		ChallengeID: challenge4.ID, Password: "correct-password", RequestID: "req-verify-4"})
	if err != nil {
		t.Fatalf("第四个批准: %v", err)
	}
	env.now = env.now.Add(reauth.DefaultApprovalTTL + time.Minute)
	if _, err := env.service.Authorize(reauth.WithSignals(env.ctx,
		reauth.Signals{ApprovalToken: grant4.Token, Confirmed: true}), caller,
		request("profile.username.change")); !errors.Is(err, reauth.ErrApprovalExpired) {
		t.Errorf("过期批准错误 = %v，期望 ErrApprovalExpired", err)
	}
}

// TestStrengthUnavailableFailClosed 验证未实现强认证的操作不被降级为密码挑战。
func TestStrengthUnavailableFailClosed(t *testing.T) {
	env := newTestEnv(t, nil)
	caller := env.userCaller(t, normalUserID)
	env.now = time.Now().UTC()
	if _, err := env.service.BeginChallenge(env.ctx, caller, reauth.ChallengeRequest{
		ScopeID: "system", OperationID: "backup.restore", TargetType: "user", TargetID: normalUserID,
		Params: map[string]string{"backup_id": "b1"}}); !errors.Is(err, reauth.ErrMFARequired) {
		t.Errorf("强认证不可满足时挑战错误 = %v，期望 ErrMFARequired", err)
	}
	if _, err := env.service.Authorize(reauth.WithSignals(env.ctx, freshSignals(env.now)), caller,
		request("backup.restore")); !errors.Is(err, reauth.ErrMFARequired) {
		t.Errorf("强认证不可满足时授权错误 = %v，期望 ErrMFARequired", err)
	}
	if challenges := env.count(`SELECT COUNT(*) FROM reauth_challenges`); challenges != 0 {
		t.Errorf("强认证不可满足时不应创建密码挑战，实际 %d", challenges)
	}
}

// TestPolicyChangeTakesEffect 验证步骤 38 覆盖值变化后执行前判定立即生效。
func TestPolicyChangeTakesEffect(t *testing.T) {
	env := newTestEnv(t, nil)
	caller := env.userCaller(t, normalUserID)
	env.now = time.Now().UTC()
	// 60 秒前的验证在默认新鲜度 600 秒内通过。
	signals := freshSignals(env.now)
	signals.VerifiedAt = env.now.Add(-60 * time.Second)
	if _, err := env.service.Authorize(reauth.WithSignals(env.ctx, signals), caller,
		request("profile.username.change")); err != nil {
		t.Fatalf("默认策略下应通过: %v", err)
	}
	// root 把新鲜度收紧到 40 秒后，同一验证立即被拒绝。
	env.setPolicy(t, "profile.username.change", policy.PolicyChange{
		MaxAuthAgeSeconds: intPtr(40)}, 0)
	if _, err := env.service.Authorize(reauth.WithSignals(env.ctx, signals), caller,
		request("profile.username.change")); !errors.Is(err, reauth.ErrReauthRequired) {
		t.Errorf("收紧后错误 = %v，期望 ErrReauthRequired", err)
	}
	// 恢复默认后重新通过。
	env.now = time.Now().UTC()
	rootPolicyCaller, _ := policy.UserCaller(rootUserID)
	if _, err := env.policyService.Restore(env.ctx, rootPolicyCaller, policy.RestoreRequest{
		ScopeID: "system", OperationID: "profile.username.change", ExpectedVersion: 1,
		RequestID: "req-policy-restore"}); err != nil {
		t.Fatalf("恢复默认: %v", err)
	}
	env.now = time.Now().UTC()
	signals = freshSignals(env.now)
	signals.VerifiedAt = env.now.Add(-60 * time.Second)
	if _, err := env.service.Authorize(reauth.WithSignals(env.ctx, signals), caller,
		request("profile.username.change")); err != nil {
		t.Errorf("恢复默认后应通过: %v", err)
	}
}

// TestNotificationsStates 覆盖告知成功、无已验证邮箱、投递失败、未配置发送器。
func TestNotificationsStates(t *testing.T) {
	env := newTestEnv(t, nil)
	env.now = time.Now().UTC()
	alice := env.userCaller(t, normalUserID)
	bob := env.userCaller(t, noMailUserID)
	signals := freshSignals(env.now)

	// 成功告知：写入记录、捕获邮件、审计，收件地址只存脱敏值。
	result, err := env.service.Authorize(reauth.WithSignals(env.ctx, signals), alice,
		request("password.change"))
	if err != nil {
		t.Fatalf("授权: %v", err)
	}
	if err := env.service.NotifyOutcome(env.ctx, result, reauth.OutcomeSuccess); err != nil {
		t.Fatalf("成功告知: %v", err)
	}
	if env.sentCount() != 1 {
		t.Fatalf("邮件数 = %d，期望 1", env.sentCount())
	}
	message := env.lastMessage()
	if !strings.Contains(message.Subject, "安全提醒") {
		t.Errorf("邮件主题 = %q，期望含安全提醒", message.Subject)
	}
	if message.To[0].Spec != "alice@example.com" {
		t.Errorf("收件人 = %q，期望已验证邮箱", message.To[0].Spec)
	}
	records, err := env.service.Notifications(env.ctx, alice, normalUserID, 10)
	if err != nil || len(records) != 1 || records[0].State != reauth.NotificationSent {
		t.Fatalf("告知记录 = %+v, err = %v", records, err)
	}
	if records[0].RecipientMasked != "a***@example.com" {
		t.Errorf("收件人脱敏 = %q", records[0].RecipientMasked)
	}
	if events := env.count(`SELECT COUNT(*) FROM audit_events WHERE action='security.notice' AND outcome='success'`); events != 1 {
		t.Errorf("告知成功审计数 = %d，期望 1", events)
	}
	// 无已验证邮箱：记录 no_verified_email，不当作发送成功。
	bobResult, err := env.service.Authorize(reauth.WithSignals(env.ctx, freshSignals(env.now)), bob,
		reauth.Request{ScopeID: "system", OperationID: "password.change",
			TargetType: "user", TargetID: noMailUserID, Params: map[string]string{"x": "1"}})
	if err != nil {
		t.Fatalf("bob 授权: %v", err)
	}
	if err := env.service.NotifyOutcome(env.ctx, bobResult, reauth.OutcomeSuccess); !errors.Is(err, reauth.ErrNotificationFailed) {
		t.Errorf("无邮箱告知错误 = %v，期望 ErrNotificationFailed", err)
	}
	records, _ = env.service.Notifications(env.ctx, bob, noMailUserID, 10)
	if len(records) != 1 || records[0].State != reauth.NotificationNoVerifiedEmail {
		t.Fatalf("无邮箱记录 = %+v", records)
	}
	// 投递失败：状态 failed 并记录错误码，不影响业务结果。
	env.senderErr = errors.New("smtp unavailable")
	if err := env.service.NotifyOutcome(env.ctx, result, reauth.OutcomeSuccess); err == nil {
		t.Error("投递失败应返回错误（调用方可记录但不得回滚）")
	}
	records, _ = env.service.Notifications(env.ctx, alice, normalUserID, 10)
	if len(records) < 2 || records[0].State != reauth.NotificationFailed {
		t.Fatalf("投递失败记录 = %+v", records)
	}
	// 未配置发送器。
	noMailerEnv := newTestEnv(t, func(options *reauth.Options) { options.Mailer = nil })
	noMailerEnv.now = time.Now().UTC()
	noMailerCaller := noMailerEnv.userCaller(t, normalUserID)
	noMailerResult, err := noMailerEnv.service.Authorize(reauth.WithSignals(noMailerEnv.ctx,
		freshSignals(noMailerEnv.now)), noMailerCaller, request("password.change"))
	if err != nil {
		t.Fatalf("未配置发送器环境授权: %v", err)
	}
	if err := noMailerEnv.service.NotifyOutcome(noMailerEnv.ctx, noMailerResult, reauth.OutcomeSuccess); err == nil {
		t.Error("未配置发送器应返回错误")
	}
	records, _ = noMailerEnv.service.Notifications(noMailerEnv.ctx, noMailerCaller, normalUserID, 5)
	if len(records) != 1 || records[0].State != reauth.NotificationNotConfigured {
		t.Fatalf("未配置发送器记录 = %+v", records)
	}
}

// TestFailureNotificationRateLimit 覆盖失败高风险告知限频与窗口恢复。
func TestFailureNotificationRateLimit(t *testing.T) {
	env := newTestEnv(t, func(options *reauth.Options) { options.FailureNotifyLimit = 2 })
	env.now = time.Now().UTC()
	caller := env.userCaller(t, normalUserID)
	result, err := env.service.Authorize(reauth.WithSignals(env.ctx, freshSignals(env.now)), caller,
		request("profile.username.change"))
	if err != nil {
		t.Fatalf("授权: %v", err)
	}
	for index := 0; index < 2; index++ {
		if err := env.service.NotifyOutcome(env.ctx, result, reauth.OutcomeFailure); err != nil {
			t.Fatalf("第 %d 次失败告知: %v", index+1, err)
		}
	}
	if err := env.service.NotifyOutcome(env.ctx, result, reauth.OutcomeFailure); err == nil {
		t.Error("超过限频应返回错误")
	}
	records, _ := env.service.Notifications(env.ctx, caller, normalUserID, 10)
	rateLimited := 0
	for _, record := range records {
		if record.State == reauth.NotificationRateLimited {
			rateLimited++
		}
	}
	if rateLimited != 1 {
		t.Errorf("限频记录数 = %d，期望 1", rateLimited)
	}
	// 窗口过后重新允许。
	env.now = env.now.Add(2 * time.Hour)
	env.verifier.completedAt = env.now
	if err := env.service.NotifyOutcome(env.ctx, result, reauth.OutcomeFailure); err != nil {
		t.Errorf("窗口后失败告知: %v", err)
	}
	// 告知正文不包含密码/令牌等敏感内容。
	for _, message := range env.sent {
		body := strings.ToLower(message.Subject + "\n" + message.TextBody)
		if strings.Contains(body, "correct-password") || strings.Contains(body, "token") {
			t.Errorf("告知邮件含敏感内容: %q", body)
		}
	}
}

// TestRootOnlyRequiresCompleteAuthentication 验证高权限操作在未完成强认证时继续拒绝。
func TestRootOnlyRequiresCompleteAuthentication(t *testing.T) {
	env := newTestEnv(t, nil)
	env.now = time.Now().UTC()
	// 临时把 root 恢复的新鲜度/强度调整为密码级，以便检查“完整认证”闸门。
	env.setPolicy(t, "backup.restore", policy.PolicyChange{
		ReauthRequired:    boolPtr(true),
		MaxAuthAgeSeconds: intPtr(300),
		RequiredStrength:  strengthPtr(policy.StrengthPassword),
	}, 0)
	root := env.rootCaller(t)
	incomplete := freshSignals(env.now)
	incomplete.Complete = false
	if _, err := env.service.Authorize(reauth.WithSignals(env.ctx, incomplete), root,
		reauth.Request{ScopeID: "system", OperationID: "backup.restore",
			TargetType: "user", TargetID: rootUserID, Params: map[string]string{"backup_id": "b1"}}); !errors.Is(err, reauth.ErrMFARequired) {
		t.Errorf("未完成强认证错误 = %v，期望 ErrMFARequired", err)
	}
	complete := freshSignals(env.now)
	if _, err := env.service.Authorize(reauth.WithSignals(env.ctx, complete), root,
		reauth.Request{ScopeID: "system", OperationID: "backup.restore",
			TargetType: "user", TargetID: rootUserID, Params: map[string]string{"backup_id": "b1"}}); err != nil {
		t.Errorf("完成认证后应通过: %v", err)
	}
}

// TestNotificationViaLocalTestmail 使用项目内本地 SMTP 捕获器验证告知真实投递路径。
func TestNotificationViaLocalTestmail(t *testing.T) {
	server := mailtest.Start(t, mailtest.Options{Required: true, SMTPAuthNone: true})
	sender, err := mailer.NewSMTPSender(mailer.SMTPOptions{
		Addr: server.Addr().String(), TLSMode: mailer.TLSModeNone, AllowPlaintextLocal: true,
	})
	if err != nil {
		t.Fatalf("SMTP 发送器: %v", err)
	}
	env := newTestEnv(t, func(options *reauth.Options) { options.Mailer = sender })
	env.now = time.Now().UTC()
	caller := env.userCaller(t, normalUserID)
	result, err := env.service.Authorize(reauth.WithSignals(env.ctx, freshSignals(env.now)), caller,
		request("password.change"))
	if err != nil {
		t.Fatalf("授权: %v", err)
	}
	if err := env.service.NotifyOutcome(env.ctx, result, reauth.OutcomeSuccess); err != nil {
		t.Fatalf("告知: %v", err)
	}
	ctx, cancel := context.WithTimeout(env.ctx, 5*time.Second)
	defer cancel()
	messages, err := server.Wait(ctx, mailtest.Query{To: "alice@example.com"})
	if err != nil || len(messages) == 0 {
		t.Fatalf("本地捕获器未收到告知: %v", err)
	}
}

func intPtr(value int64) *int64                          { return &value }
func boolPtr(value bool) *bool                           { return &value }
func strengthPtr(value policy.Strength) *policy.Strength { return &value }

// TestProfileUsernameChangeWithSensitiveGuard 用真实资料模块验证接入：未提供近期
// 认证事实时更名被拒绝且库不变；提供后更名成功并产生安全告知。
func TestProfileUsernameChangeWithSensitiveGuard(t *testing.T) {
	env := newTestEnv(t, nil)
	env.now = time.Now().UTC()
	profileStore, err := profilesqlite.New(env.storage)
	if err != nil {
		t.Fatalf("资料存储: %v", err)
	}
	profileService, err := profile.New(profile.Options{
		Store: profileStore, Audit: env.recorder, Sensitive: env.service,
		ReauthVerifier: profile.ReauthVerifierFunc(func(ctx context.Context, caller profile.Caller, targetUserID string) error {
			return nil
		}),
		Now: func() time.Time { return env.now },
	})
	if err != nil {
		t.Fatalf("资料服务: %v", err)
	}
	caller, err := profile.UserCaller(normalUserID)
	if err != nil {
		t.Fatalf("资料调用者: %v", err)
	}
	change := profile.ChangeUsernameRequest{TargetUserID: normalUserID, NewUsername: "alice_renamed",
		ExpectedRowVersion: 1, RequestID: "req-int-1"}
	if _, err := profileService.ChangeUsername(env.ctx, caller, change); !errors.Is(err, profile.ErrRenameReauthRequired) {
		t.Fatalf("未提供近期认证时更名错误 = %v，期望 ErrRenameReauthRequired", err)
	}
	username := ""
	_ = env.storage.DB().QueryRowContext(env.ctx, `SELECT username FROM users WHERE id=?`, normalUserID).Scan(&username)
	if username != "alice" {
		t.Errorf("被拒绝后用户名 = %q，期望保持不变", username)
	}
	change.RequestID = "req-int-2"
	ctx := reauth.WithSignals(env.ctx, freshSignals(env.now))
	updated, err := profileService.ChangeUsername(ctx, caller, change)
	if err != nil {
		t.Fatalf("提供近期认证后更名: %v", err)
	}
	if updated.Username != "alice_renamed" {
		t.Errorf("更名后用户名 = %q", updated.Username)
	}
	if env.sentCount() != 1 {
		t.Errorf("更名成功告知邮件数 = %d，期望 1", env.sentCount())
	}
	records, err := env.service.Notifications(env.ctx, env.userCaller(t, normalUserID), normalUserID, 10)
	if err != nil || len(records) == 0 || records[0].State != reauth.NotificationSent {
		t.Fatalf("更名告知记录 = %+v, err = %v", records, err)
	}
}

// TestApprovalConcurrentConsumeSingleWinner 验证同一批准被并发消费时只有一个成功。
func TestApprovalConcurrentConsumeSingleWinner(t *testing.T) {
	env := newTestEnv(t, nil)
	caller := env.userCaller(t, normalUserID)
	env.now = time.Now().UTC()
	env.verifier.completedAt = env.now
	challenge, err := env.service.BeginChallenge(env.ctx, caller, reauth.ChallengeRequest{
		ScopeID: "system", OperationID: "profile.username.change",
		TargetType: "user", TargetID: normalUserID,
		Params: map[string]string{"expected_row_version": "1"}})
	if err != nil {
		t.Fatalf("创建挑战: %v", err)
	}
	grant, err := env.service.VerifyChallenge(env.ctx, caller, reauth.VerifyChallengeRequest{
		ChallengeID: challenge.ID, Password: "correct-password", RequestID: "req-race-verify"})
	if err != nil {
		t.Fatalf("验证挑战: %v", err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for index := 0; index < 2; index++ {
		go func() {
			<-start
			_, authorizeErr := env.service.Authorize(reauth.WithSignals(env.ctx,
				reauth.Signals{ApprovalToken: grant.Token, Confirmed: true}), caller,
				request("profile.username.change"))
			results <- authorizeErr
		}()
	}
	close(start)
	successes, consumed := 0, 0
	for index := 0; index < 2; index++ {
		switch err := <-results; {
		case err == nil:
			successes++
		case errors.Is(err, reauth.ErrApprovalConsumed):
			consumed++
		default:
			t.Fatalf("并发消费未知错误: %v", err)
		}
	}
	if successes != 1 || consumed != 1 {
		t.Errorf("并发消费结果 = 成功 %d / 已消费 %d，期望 1/1", successes, consumed)
	}
}

// TestBeginChallengeRejectsUnknownOperationFailClosed 验证挑战入口对未知操作/策略
// 错误返回错误，而不是 fail-open 的 Required=false。
func TestBeginChallengeRejectsUnknownOperationFailClosed(t *testing.T) {
	env := newTestEnv(t, nil)
	caller := env.userCaller(t, normalUserID)
	env.now = time.Now().UTC()
	if _, err := env.service.BeginChallenge(env.ctx, caller, reauth.ChallengeRequest{
		ScopeID: "system", OperationID: "unknown.operation",
		TargetType: "user", TargetID: normalUserID, Params: map[string]string{"x": "1"},
	}); !errors.Is(err, reauth.ErrInvalidRequest) {
		t.Fatalf("未知操作挑战错误 = %v，期望 ErrInvalidRequest（不得 fail-open）", err)
	}
}

// TestApprovalCrossBindingDirectionAndMemberSet 验证批准绑定参数集合/方向：为“加成员”
// 签发的批准不能用于“减成员”或不同成员集合（交叉绑定拒绝）。
func TestApprovalCrossBindingDirectionAndMemberSet(t *testing.T) {
	env := newTestEnv(t, nil)
	caller := env.userCaller(t, normalUserID)
	env.now = time.Now().UTC()
	env.verifier.completedAt = env.now
	baseRequest := reauth.Request{ScopeID: "system", OperationID: "profile.username.change",
		TargetType: "group", TargetID: "grp_00000000000000000000000000000001",
		Params: map[string]string{"direction": "add", "members": "usr_1,usr_2"}}
	challenge, err := env.service.BeginChallenge(env.ctx, caller, reauth.ChallengeRequest{
		ScopeID: baseRequest.ScopeID, OperationID: baseRequest.OperationID,
		TargetType: baseRequest.TargetType, TargetID: baseRequest.TargetID, Params: baseRequest.Params})
	if err != nil {
		t.Fatalf("创建挑战: %v", err)
	}
	grant, err := env.service.VerifyChallenge(env.ctx, caller, reauth.VerifyChallengeRequest{
		ChallengeID: challenge.ID, Password: "correct-password", RequestID: "req-cross-verify"})
	if err != nil {
		t.Fatalf("验证挑战: %v", err)
	}
	// 换方向（remove）使用同一批准：拒绝。
	wrongDirection := baseRequest
	wrongDirection.Params = map[string]string{"direction": "remove", "members": "usr_1,usr_2"}
	if _, err := env.service.Authorize(reauth.WithSignals(env.ctx,
		reauth.Signals{ApprovalToken: grant.Token, Confirmed: true}), caller, wrongDirection); !errors.Is(err, reauth.ErrApprovalInvalid) {
		t.Errorf("换方向批准错误 = %v，期望 ErrApprovalInvalid", err)
	}
	// 换成员集合使用同一批准：拒绝。
	wrongMembers := baseRequest
	wrongMembers.Params = map[string]string{"direction": "add", "members": "usr_1,usr_3"}
	if _, err := env.service.Authorize(reauth.WithSignals(env.ctx,
		reauth.Signals{ApprovalToken: grant.Token, Confirmed: true}), caller, wrongMembers); !errors.Is(err, reauth.ErrApprovalInvalid) {
		t.Errorf("换成员集合批准错误 = %v，期望 ErrApprovalInvalid", err)
	}
	// 原参数仍可使用（一次性）。
	if _, err := env.service.Authorize(reauth.WithSignals(env.ctx,
		reauth.Signals{ApprovalToken: grant.Token, Confirmed: true}), caller, baseRequest); err != nil {
		t.Errorf("原参数使用批准: %v", err)
	}
}
