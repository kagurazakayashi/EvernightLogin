package mfa_test

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/authfact"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/credential"
	credentialsqlite "github.com/kagurazakayashi/EvernightLogin/internal/credential/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	"github.com/kagurazakayashi/EvernightLogin/internal/mfa"
	mfasqlite "github.com/kagurazakayashi/EvernightLogin/internal/mfa/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/passkey"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	sessionsqlite "github.com/kagurazakayashi/EvernightLogin/internal/session/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testmail"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/internal/totp"
	totpsqlite "github.com/kagurazakayashi/EvernightLogin/internal/totp/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

var seedTime = time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)

const userID = "usr_00000000000000000000000000000001"

var codePattern = regexp.MustCompile(`\b[0-9]{8}\b`)

type testEnv struct {
	t       *testing.T
	ctx     context.Context
	storage *storagesqlite.Store
	service *mfa.Service
	store   mfa.Store
	audit   *audit.Recorder
	session *session.Service
	mail    *testmail.Server
	totp    *totp.Service
	now     time.Time
}

func newTestEnv(t *testing.T, mutate func(*mfa.Options)) *testEnv {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(testutil.TempDir(t), "mfa-test.db")
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
	keyring, err := secrets.GenerateKeyring("k1", seedTime)
	if err != nil {
		t.Fatalf("密钥环: %v", err)
	}
	credentialStore, err := credentialsqlite.New(storage)
	if err != nil {
		t.Fatalf("凭证存储: %v", err)
	}
	env := &testEnv{t: t, ctx: ctx, storage: storage, audit: recorder, now: time.Now().UTC()}
	credentialService, err := credential.New(credentialStore, credential.Options{
		Keyring: keyring, Now: func() time.Time { return env.now },
	})
	if err != nil {
		t.Fatalf("凭证服务: %v", err)
	}
	sessionStore, err := sessionsqlite.New(storage)
	if err != nil {
		t.Fatalf("会话存储: %v", err)
	}
	sessionService, err := session.New(sessionStore, session.Options{
		Audit: recorder, Keyring: keyring, Now: func() time.Time { return env.now },
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	})
	if err != nil {
		t.Fatalf("会话服务: %v", err)
	}
	env.session = sessionService
	mailServer, err := testmail.New(testmail.Options{Addr: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("本地邮件捕获器: %v", err)
	}
	if err := mailServer.Start(); err != nil {
		t.Fatalf("启动本地邮件捕获器: %v", err)
	}
	t.Cleanup(func() { _ = mailServer.Close() })
	env.mail = mailServer
	sender, err := mailer.NewSMTPSender(mailer.SMTPOptions{
		Addr: mailServer.Addr().String(), TLSMode: mailer.TLSModeNone, AllowPlaintextLocal: true,
	})
	if err != nil {
		t.Fatalf("SMTP 发送器: %v", err)
	}
	mfaStore, err := mfasqlite.New(storage)
	if err != nil {
		t.Fatalf("MFA 存储: %v", err)
	}
	env.store = mfaStore
	sealer, err := secrets.NewSealer(keyring, nil)
	if err != nil {
		t.Fatalf("TOTP 加密器: %v", err)
	}
	totpStore, err := totpsqlite.New(storage)
	if err != nil {
		t.Fatalf("TOTP 存储: %v", err)
	}
	totpService, err := totp.New(totp.Options{
		Store: totpStore, Audit: recorder, Sealer: sealer, Reauth: totpAllowRunner{},
		IssuerName: "登录服务", Now: func() time.Time { return env.now },
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	})
	if err != nil {
		t.Fatalf("TOTP 服务: %v", err)
	}
	env.totp = totpService
	options := mfa.Options{
		Store: mfaStore, Audit: recorder, Credentials: credentialService,
		Sessions: sessionService, Mailer: sender, TOTP: totpService,
		FromAddress: "security@example.com", AppName: "登录服务", SupportURL: "https://example.com/support",
		Now:    func() time.Time { return env.now },
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}
	if mutate != nil {
		mutate(&options)
	}
	service, err := mfa.New(options)
	if err != nil {
		t.Fatalf("MFA 服务: %v", err)
	}
	env.service = service
	env.seedUser(userID, "alice")
	env.seedEmail(userID, "alice@example.com")
	return env
}

func (e *testEnv) seedUser(id, username string) {
	e.t.Helper()
	now := seedTime.UnixMilli()
	if _, err := e.storage.DB().ExecContext(e.ctx, `INSERT INTO users(
id,username,username_normalized,nickname,biography,avatar_ref,language,timezone,status,is_root,
security_version,row_version,created_at_ms,updated_at_ms
) VALUES(?,?,?,'','',NULL,'zh-CN','Asia/Shanghai','active',0,1,1,?,?)`,
		id, username, username, now, now); err != nil {
		e.t.Fatalf("用户: %v", err)
	}
}

func (e *testEnv) seedEmail(id, address string) {
	e.t.Helper()
	now := seedTime.UnixMilli()
	if _, err := e.storage.DB().ExecContext(e.ctx, `INSERT INTO user_emails(
email_normalized,user_id,email,verified_at_ms,created_at_ms,updated_at_ms
) VALUES(?,?,?,?,?,?)`, strings.ToLower(address), id, address, now, now, now); err != nil {
		e.t.Fatalf("邮箱: %v", err)
	}
}

func (e *testEnv) caller() mfa.Caller {
	e.t.Helper()
	caller, err := mfa.UserCaller(userID)
	if err != nil {
		e.t.Fatalf("调用者: %v", err)
	}
	return caller
}

// completeAuthn 构造可信密码认证结果（mfa 从 authn 结果开始，测试不重复验证密码）。
func (e *testEnv) completeAuthn() authn.AuthenticateResult {
	return authn.AuthenticateResult{UserID: userID, Username: "alice",
		Outcome: authn.OutcomeComplete, CompletedMethods: []authn.Method{authn.MethodPassword},
		CompletedAt: e.now.Add(-time.Minute), SecurityVersion: 1}
}

// pendingStrongAuth 构造高权限账户“需要强认证”的认证结果。
func (e *testEnv) pendingStrongAuth() authn.AuthenticateResult {
	return authn.AuthenticateResult{UserID: userID, Username: "alice",
		Outcome:          authn.OutcomePendingSecondFactor,
		CompletedMethods: []authn.Method{authn.MethodPassword},
		CompletedAt:      e.now, RequiredSteps: []authn.Step{authn.StepStrongAuthSetup, authn.StepSecondFactor},
		Restricted: true, SecurityVersion: 1}
}

// waitCode 从本地捕获器读取发给 alice 的最新验证码。
func (e *testEnv) waitCode() string {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(e.ctx, 5*time.Second)
	defer cancel()
	messages, err := e.mail.Wait(ctx, testmail.Query{To: "alice@example.com"})
	if err != nil || len(messages) == 0 {
		e.t.Fatalf("未收到验证码邮件: %v", err)
	}
	body := ""
	for _, message := range messages {
		raw := strings.ReplaceAll(string(message.Data), "\r\n", "\n")
		parts := strings.SplitN(raw, "\n\n", 2)
		encoded := raw
		if len(parts) == 2 {
			encoded = parts[1]
		}
		encoded = strings.ReplaceAll(strings.ReplaceAll(encoded, "\n", ""), "\r", "")
		decoded, decodeErr := base64.StdEncoding.DecodeString(encoded)
		if decodeErr == nil {
			body = string(decoded)
		} else {
			body = raw
		}
	}
	code := codePattern.FindString(body)
	if code == "" {
		e.t.Fatalf("邮件正文缺少验证码: %q", body)
	}
	return code
}

func (e *testEnv) queryString(query string, args ...any) string {
	e.t.Helper()
	var value string
	if err := e.storage.DB().QueryRowContext(e.ctx, query, args...).Scan(&value); err != nil {
		e.t.Fatalf("查询: %v", err)
	}
	return value
}

func (e *testEnv) count(query string, args ...any) int {
	e.t.Helper()
	var value int
	if err := e.storage.DB().QueryRowContext(e.ctx, query, args...).Scan(&value); err != nil {
		e.t.Fatalf("计数: %v", err)
	}
	return value
}

func (e *testEnv) enableEmailFactor() {
	e.t.Helper()
	enrollment, err := e.service.BeginEmailFactorEnrollment(e.ctx, e.caller(), mfa.FactorEnrollmentRequest{RequestID: "req-enroll"})
	if err != nil {
		e.t.Fatalf("开始新增因素: %v", err)
	}
	code := e.waitCode()
	if _, err := e.service.ConfirmEmailFactorEnrollment(e.ctx, e.caller(), mfa.FactorVerifyRequest{
		ChallengeID: enrollment.ChallengeID, AttemptToken: enrollment.AttemptToken,
		Code: code, RequestID: "req-enroll-confirm"}); err != nil {
		e.t.Fatalf("确认新增因素: %v", err)
	}
}

// TestPasswordEmailSecondFactorFullSession 覆盖：启用邮件因素 → 第一步只拿受限会话 →
// 邮件验证码第二步 → 轮换为完整普通会话；旧受限会话失效。
func TestPasswordEmailSecondFactorFullSession(t *testing.T) {
	env := newTestEnv(t, nil)
	env.now = time.Now().UTC()
	env.enableEmailFactor()
	env.now = time.Now().UTC()
	start, err := env.service.BeginLogin(env.ctx, mfa.BeginLoginRequest{
		Result: env.completeAuthn(), RequestID: "req-login-1"})
	if err != nil {
		t.Fatalf("第一步: %v", err)
	}
	if !start.RequiresSecondFactor || start.ChallengeID == "" || start.AttemptToken == "" {
		t.Fatalf("第二步启动结果异常: %+v", start)
	}
	if !start.RestrictedSession.Session.IsRestricted() {
		t.Fatal("第一步只能签发受限会话")
	}
	code := env.waitCode()
	// 错误验证码不产生完整会话。
	if _, err := env.service.Verify(env.ctx, mfa.VerifyRequest{
		ChallengeID: start.ChallengeID, AttemptToken: start.AttemptToken,
		Code: "00000000", ExistingSession: start.RestrictedSession.Secret.Reveal(),
		RequestID: "req-login-bad"}); !errors.Is(err, mfa.ErrCodeInvalid) {
		t.Fatalf("错误验证码错误 = %v，期望 ErrCodeInvalid", err)
	}
	result, err := env.service.Verify(env.ctx, mfa.VerifyRequest{
		ChallengeID: start.ChallengeID, AttemptToken: start.AttemptToken, Code: code,
		ExistingSession: start.RestrictedSession.Secret.Reveal(), RequestID: "req-login-2"})
	if err != nil {
		t.Fatalf("第二步验证: %v", err)
	}
	if result.Session.Session.IsRestricted() {
		t.Fatal("第二步成功后应签发完整普通会话")
	}
	if _, err := env.session.Validate(env.ctx, result.Session.Secret.Reveal()); err != nil {
		t.Fatalf("完整会话应可校验: %v", err)
	}
	if _, err := env.session.Validate(env.ctx, start.RestrictedSession.Secret.Reveal()); err == nil {
		t.Error("旧受限会话应在轮换后失效")
	}
	// 重放同一验证码/挑战：拒绝。
	if _, err := env.service.Verify(env.ctx, mfa.VerifyRequest{
		ChallengeID: start.ChallengeID, AttemptToken: start.AttemptToken, Code: code,
		ExistingSession: start.RestrictedSession.Secret.Reveal(), RequestID: "req-login-replay"}); !errors.Is(err, mfa.ErrChallengeInvalid) {
		t.Errorf("重放错误 = %v，期望 ErrChallengeInvalid", err)
	}
}

// TestHighPrivilegeEmailFactorFailClosed 验证高权限账户不能用邮件因素满足强认证。
func TestHighPrivilegeEmailFactorFailClosed(t *testing.T) {
	env := newTestEnv(t, nil)
	env.now = time.Now().UTC()
	env.enableEmailFactor()
	env.now = time.Now().UTC()
	if _, err := env.service.BeginLogin(env.ctx, mfa.BeginLoginRequest{
		Result: env.pendingStrongAuth(), RequestID: "req-strong"}); !errors.Is(err, mfa.ErrStrongAuthRequired) {
		t.Fatalf("高权限账户错误 = %v，期望 ErrStrongAuthRequired", err)
	}
	if count := env.count(`SELECT COUNT(*) FROM mfa_challenges WHERE purpose='login'`); count != 0 {
		t.Errorf("高权限拒绝后不应创建登录挑战，实际 %d", count)
	}
	if count := env.count(`SELECT COUNT(*) FROM sessions`); count != 0 {
		t.Errorf("高权限拒绝后不应签发会话，实际 %d", count)
	}
}

// TestNoVerifiedEmailFailClosed 验证没有已验证邮箱时不发未验证地址、不签会话。
func TestNoVerifiedEmailFailClosed(t *testing.T) {
	env := newTestEnv(t, nil)
	env.now = time.Now().UTC()
	// 直接插入活动因素并删除已验证邮箱，模拟邮件渠道不可用。
	if _, err := env.storage.DB().ExecContext(env.ctx,
		`INSERT INTO mfa_factors(id,user_id,factor_type,status,created_at_ms,updated_at_ms)
VALUES('mft_testaaaaaaaaaaaaaaaaaaaaaaaaaaaa',?, 'email','active',?,?)`,
		userID, env.now.UnixMilli(), env.now.UnixMilli()); err != nil {
		t.Fatalf("插入因素: %v", err)
	}
	if _, err := env.storage.DB().ExecContext(env.ctx, `UPDATE user_emails SET verified_at_ms=NULL`); err != nil {
		t.Fatalf("清除邮箱验证: %v", err)
	}
	if _, err := env.service.BeginLogin(env.ctx, mfa.BeginLoginRequest{
		Result: env.completeAuthn(), RequestID: "req-noemail"}); !errors.Is(err, mfa.ErrNoVerifiedEmail) {
		t.Fatalf("无已验证邮箱错误 = %v，期望 ErrNoVerifiedEmail", err)
	}
	if count := env.count(`SELECT COUNT(*) FROM sessions`); count != 0 {
		t.Errorf("无邮箱路径不应签发会话，实际 %d", count)
	}
}

// TestExpiredAndResendCooldown 覆盖挑战过期、重发冷却、重发使旧码失效。
func TestExpiredAndResendCooldown(t *testing.T) {
	env := newTestEnv(t, nil)
	env.now = time.Now().UTC()
	env.enableEmailFactor()
	env.now = time.Now().UTC()
	start, err := env.service.BeginLogin(env.ctx, mfa.BeginLoginRequest{
		Result: env.completeAuthn(), RequestID: "req-expire"})
	if err != nil {
		t.Fatalf("第一步: %v", err)
	}
	oldCode := env.waitCode()
	if _, err := env.service.Resend(env.ctx, mfa.ResendRequest{
		ChallengeID: start.ChallengeID, AttemptToken: start.AttemptToken,
		RequestID: "req-resend-cooldown"}); !errors.Is(err, mfa.ErrRateLimited) {
		t.Fatalf("冷却期重发错误 = %v，期望 ErrRateLimited", err)
	}
	env.now = env.now.Add(env.mfaResendCooldown())
	resend, err := env.service.Resend(env.ctx, mfa.ResendRequest{
		ChallengeID: start.ChallengeID, AttemptToken: start.AttemptToken, RequestID: "req-resend"})
	if err != nil {
		t.Fatalf("冷却后重发: %v", err)
	}
	if resend.ExpiresAt.IsZero() {
		t.Fatal("重发结果缺少新有效期")
	}
	newCode := env.waitCode()
	if newCode == oldCode {
		t.Fatalf("重发后验证码未变化")
	}
	// 旧码失效，新码有效。
	if _, err := env.service.Verify(env.ctx, mfa.VerifyRequest{
		ChallengeID: start.ChallengeID, AttemptToken: start.AttemptToken, Code: oldCode,
		ExistingSession: start.RestrictedSession.Secret.Reveal(), RequestID: "req-old"}); !errors.Is(err, mfa.ErrCodeInvalid) {
		t.Fatalf("旧验证码错误 = %v，期望 ErrCodeInvalid", err)
	}
	if _, err := env.service.Verify(env.ctx, mfa.VerifyRequest{
		ChallengeID: start.ChallengeID, AttemptToken: start.AttemptToken, Code: newCode,
		ExistingSession: start.RestrictedSession.Secret.Reveal(), RequestID: "req-new"}); err != nil {
		t.Fatalf("新验证码验证: %v", err)
	}
	// 过期的挑战拒绝（使用新挑战并把时钟推进过期）。
	env.now = time.Now().UTC()
	second, err := env.service.BeginLogin(env.ctx, mfa.BeginLoginRequest{
		Result: env.completeAuthn(), RequestID: "req-expire-2"})
	if err != nil {
		t.Fatalf("第二个挑战: %v", err)
	}
	env.now = env.now.Add(20 * time.Minute)
	if _, err := env.service.Verify(env.ctx, mfa.VerifyRequest{
		ChallengeID: second.ChallengeID, AttemptToken: second.AttemptToken, Code: "12345678",
		ExistingSession: second.RestrictedSession.Secret.Reveal(), RequestID: "req-expired"}); !errors.Is(err, mfa.ErrChallengeExpired) {
		t.Fatalf("过期挑战错误 = %v，期望 ErrChallengeExpired", err)
	}
}

// mfaResendCooldown 返回测试服务的重发冷却（默认值）。
func (e *testEnv) mfaResendCooldown() time.Duration {
	return mfa.DefaultResendCooldown + time.Second
}

// TestConcurrentVerifySingleWinner 验证同一验证码并发消费只有一个成功。
func TestConcurrentVerifySingleWinner(t *testing.T) {
	env := newTestEnv(t, nil)
	env.now = time.Now().UTC()
	env.enableEmailFactor()
	env.now = time.Now().UTC()
	start, err := env.service.BeginLogin(env.ctx, mfa.BeginLoginRequest{
		Result: env.completeAuthn(), RequestID: "req-concurrent"})
	if err != nil {
		t.Fatalf("第一步: %v", err)
	}
	code := env.waitCode()
	startChannel := make(chan struct{})
	results := make(chan error, 2)
	var waitGroup sync.WaitGroup
	for index := 0; index < 2; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-startChannel
			_, verifyErr := env.service.Verify(env.ctx, mfa.VerifyRequest{
				ChallengeID: start.ChallengeID, AttemptToken: start.AttemptToken, Code: code,
				ExistingSession: start.RestrictedSession.Secret.Reveal(), RequestID: "req-concurrent"})
			results <- verifyErr
		}()
	}
	close(startChannel)
	waitGroup.Wait()
	close(results)
	successes, rejected := 0, 0
	for verifyErr := range results {
		switch {
		case verifyErr == nil:
			successes++
		case errors.Is(verifyErr, mfa.ErrCodeInvalid), errors.Is(verifyErr, mfa.ErrChallengeInvalid):
			rejected++
		default:
			t.Fatalf("并发验证未知错误: %v", verifyErr)
		}
	}
	if successes != 1 || rejected != 1 {
		t.Errorf("并发验证结果 = 成功 %d / 拒绝 %d，期望 1/1", successes, rejected)
	}
}

// TestFactorPolicyAndRemoval 验证新增因素需渠道控制权、重复新增冲突、强制策略禁止
// 移除最后因素、未强制时可移除且不可重复移除。
func TestFactorPolicyAndRemoval(t *testing.T) {
	forced := newTestEnv(t, func(options *mfa.Options) {
		options.Policy = mfa.PolicyFunc(func(ctx context.Context, userID string) (bool, error) {
			return true, nil
		})
	})
	forced.now = time.Now().UTC()
	forced.enableEmailFactor()
	if err := forced.service.RemoveEmailFactor(forced.ctx, forced.caller(), "req-remove-forced"); !errors.Is(err, mfa.ErrFactorRequired) {
		t.Fatalf("强制策略移除错误 = %v，期望 ErrFactorRequired", err)
	}
	if factors, err := forced.service.Factors(forced.ctx, forced.caller()); err != nil || len(factors) != 1 {
		t.Fatalf("强制移除后因素应保留: %+v err=%v", factors, err)
	}
	if _, err := forced.service.BeginEmailFactorEnrollment(forced.ctx, forced.caller(),
		mfa.FactorEnrollmentRequest{RequestID: "req-dup"}); !errors.Is(err, mfa.ErrFactorExists) {
		t.Fatalf("重复新增因素错误 = %v，期望 ErrFactorExists", err)
	}
	free := newTestEnv(t, nil)
	free.now = time.Now().UTC()
	free.enableEmailFactor()
	if err := free.service.RemoveEmailFactor(free.ctx, free.caller(), "req-remove"); err != nil {
		t.Fatalf("移除因素: %v", err)
	}
	if factors, err := free.service.Factors(free.ctx, free.caller()); err != nil || len(factors) != 0 {
		t.Fatalf("移除后因素 = %+v err=%v", factors, err)
	}
	if err := free.service.RemoveEmailFactor(free.ctx, free.caller(), "req-remove-again"); !errors.Is(err, mfa.ErrFactorNotFound) {
		t.Errorf("重复移除错误 = %v，期望 ErrFactorNotFound", err)
	}
}

// TestPlaintextCodeNotInAuditOrErrors 验证验证码不出现在审计事件、错误文本与库中。
func TestPlaintextCodeNotInAuditOrErrors(t *testing.T) {
	env := newTestEnv(t, nil)
	env.now = time.Now().UTC()
	env.enableEmailFactor()
	env.now = time.Now().UTC()
	start, err := env.service.BeginLogin(env.ctx, mfa.BeginLoginRequest{
		Result: env.completeAuthn(), RequestID: "req-leak"})
	if err != nil {
		t.Fatalf("第一步: %v", err)
	}
	code := env.waitCode()
	_, verifyErr := env.service.Verify(env.ctx, mfa.VerifyRequest{
		ChallengeID: start.ChallengeID, AttemptToken: start.AttemptToken, Code: code,
		ExistingSession: start.RestrictedSession.Secret.Reveal(), RequestID: "req-leak-ok"})
	if verifyErr != nil {
		t.Fatalf("验证: %v", verifyErr)
	}
	rows, err := env.storage.DB().QueryContext(env.ctx,
		`SELECT action,COALESCE(reason_code,''),COALESCE(error_code,''),detail_json FROM audit_events`)
	if err != nil {
		t.Fatalf("读取审计: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var action, reason, codeValue, detail string
		if err := rows.Scan(&action, &reason, &codeValue, &detail); err != nil {
			t.Fatalf("扫描审计: %v", err)
		}
		joined := action + reason + codeValue + detail
		if strings.Contains(joined, code) {
			t.Errorf("审计事件泄露验证码: %s", joined)
		}
	}
	var credentialRows int
	if err := env.storage.DB().QueryRowContext(env.ctx,
		`SELECT COUNT(*) FROM one_time_credentials`).Scan(&credentialRows); err != nil {
		t.Fatalf("凭证计数: %v", err)
	}
	// 数据库只保存摘要：不允许任何列等于明文验证码。
	plaintextRows := env.count(
		`SELECT COUNT(*) FROM one_time_credentials WHERE CAST(verifier_hash AS TEXT)=?`, code)
	if plaintextRows != 0 {
		t.Errorf("数据库出现明文验证码")
	}
	if verifyErr != nil && strings.Contains(verifyErr.Error(), code) {
		t.Errorf("错误文本泄露验证码: %v", verifyErr)
	}
}

// TestWrongCodeAttemptsExceeded 验证错误验证码尝试用尽后拒绝，且不签发完整会话。
func TestWrongCodeAttemptsExceeded(t *testing.T) {
	env := newTestEnv(t, nil)
	env.now = time.Now().UTC()
	env.enableEmailFactor()
	env.now = time.Now().UTC()
	start, err := env.service.BeginLogin(env.ctx, mfa.BeginLoginRequest{
		Result: env.completeAuthn(), RequestID: "req-attempts"})
	if err != nil {
		t.Fatalf("第一步: %v", err)
	}
	for attempt := 0; attempt < mfa.DefaultMaxAttempts+1; attempt++ {
		_, verifyErr := env.service.Verify(env.ctx, mfa.VerifyRequest{
			ChallengeID: start.ChallengeID, AttemptToken: start.AttemptToken, Code: "11111111",
			ExistingSession: start.RestrictedSession.Secret.Reveal(), RequestID: "req-attempts-bad"})
		if verifyErr == nil {
			t.Fatalf("第 %d 次错误验证码不应成功", attempt+1)
		}
	}
	if count := env.count(`SELECT COUNT(*) FROM sessions WHERE revoked_at_ms IS NULL`); count > 1 {
		t.Errorf("错误尝试后活动会话数 = %d，期望仅受限会话", count)
	}
}

// seedApplication 插入启用应用与 active 成员关系（供应用作用域会话用例）。
func (e *testEnv) seedApplication(appID string) {
	e.t.Helper()
	now := seedTime.UnixMilli()
	if _, err := e.storage.DB().ExecContext(e.ctx, `INSERT INTO applications(
id,name,description,status,client_type,row_version,created_at_ms,updated_at_ms
) VALUES(?,?,'','active','confidential',1,?,?)`, appID, "app", now, now); err != nil {
		e.t.Fatalf("应用: %v", err)
	}
	if _, err := e.storage.DB().ExecContext(e.ctx, `INSERT INTO app_memberships(
app_id,user_id,status,profile_json,row_version,created_at_ms,updated_at_ms
) VALUES(?,?,'active','{}',1,?,?)`, appID, userID, now, now); err != nil {
		e.t.Fatalf("应用成员: %v", err)
	}
}

// TestAppScopedLoginKeepsScopeAcrossSecondFactor 验证应用作用域登录在第二步后仍是
// 应用会话，不会升级成全局完整会话。
func TestAppScopedLoginKeepsScopeAcrossSecondFactor(t *testing.T) {
	env := newTestEnv(t, nil)
	env.now = time.Now().UTC()
	env.enableEmailFactor()
	const appID = "app_00000000000000000000000000000001"
	env.seedApplication(appID)
	env.now = time.Now().UTC()
	start, err := env.service.BeginLogin(env.ctx, mfa.BeginLoginRequest{
		Result: env.completeAuthn(), AppID: appID, RequestID: "req-app-login"})
	if err != nil {
		t.Fatalf("应用第一步: %v", err)
	}
	if !start.RestrictedSession.Session.IsRestricted() || start.RestrictedSession.Session.AppID != appID {
		t.Fatalf("应用受限会话异常: kind=%s app=%q", start.RestrictedSession.Session.Kind, start.RestrictedSession.Session.AppID)
	}
	code := env.waitCode()
	result, err := env.service.Verify(env.ctx, mfa.VerifyRequest{
		ChallengeID: start.ChallengeID, AttemptToken: start.AttemptToken, Code: code,
		ExistingSession: start.RestrictedSession.Secret.Reveal(), RequestID: "req-app-verify"})
	if err != nil {
		t.Fatalf("应用第二步: %v", err)
	}
	if result.Session.Session.IsRestricted() || result.Session.Session.AppID != appID {
		t.Fatalf("第二步后会话作用域异常: kind=%s app=%q", result.Session.Session.Kind, result.Session.Session.AppID)
	}
}

// TestForcedMFAWithoutFactorFailClosed 验证强制 MFA 但无可用因素时拒绝密码完整登录。
func TestForcedMFAWithoutFactorFailClosed(t *testing.T) {
	env := newTestEnv(t, func(options *mfa.Options) {
		options.Policy = mfa.PolicyFunc(func(ctx context.Context, userID string) (bool, error) {
			return true, nil
		})
	})
	env.now = time.Now().UTC()
	if _, err := env.service.BeginLogin(env.ctx, mfa.BeginLoginRequest{
		Result: env.completeAuthn(), RequestID: "req-forced"}); !errors.Is(err, mfa.ErrSecondFactorRequired) {
		t.Fatalf("强制 MFA 无因素错误 = %v，期望 ErrSecondFactorRequired", err)
	}
	if count := env.count(`SELECT COUNT(*) FROM sessions`); count != 0 {
		t.Errorf("强制 MFA 无因素时不应签发会话，实际 %d", count)
	}
}

// TestChallengeBoundToSpecificRestrictedSession 验证挑战只能由第一步为其签发的受限
// 会话完成，其他受限会话（另一次登录尝试）不能完成。
func TestChallengeBoundToSpecificRestrictedSession(t *testing.T) {
	env := newTestEnv(t, nil)
	env.now = time.Now().UTC()
	env.enableEmailFactor()
	env.now = time.Now().UTC()
	first, err := env.service.BeginLogin(env.ctx, mfa.BeginLoginRequest{
		Result: env.completeAuthn(), RequestID: "req-bind-1"})
	if err != nil {
		t.Fatalf("第一次登录: %v", err)
	}
	second, err := env.service.BeginLogin(env.ctx, mfa.BeginLoginRequest{
		Result: env.completeAuthn(), RequestID: "req-bind-2"})
	if err != nil {
		t.Fatalf("第二次登录: %v", err)
	}
	if _, err := env.service.Verify(env.ctx, mfa.VerifyRequest{
		ChallengeID: first.ChallengeID, AttemptToken: first.AttemptToken, Code: "00000000",
		ExistingSession: second.RestrictedSession.Secret.Reveal(), RequestID: "req-bind-wrong"}); !errors.Is(err, mfa.ErrChallengeInvalid) {
		t.Fatalf("用其他受限会话完成挑战错误 = %v，期望 ErrChallengeInvalid", err)
	}
}

// TestRateLimits 验证账户维度挑战与验证预算。
func TestRateLimits(t *testing.T) {
	env := newTestEnv(t, func(options *mfa.Options) {
		options.RatePolicy = mfa.RatePolicy{
			ChallengeLimit: 1, ChallengeWindow: time.Hour,
			VerifyLimit: 1, VerifyWindow: time.Minute,
			ResendLimit: 1, ResendWindow: time.Hour,
		}
	})
	env.now = time.Now().UTC()
	env.enableEmailFactor()
	env.now = time.Now().UTC()
	// 已消耗 1 次挑战预算（因素新增），登录挑战应被限流。
	if _, err := env.service.BeginLogin(env.ctx, mfa.BeginLoginRequest{
		Result: env.completeAuthn(), RequestID: "req-rate"}); !errors.Is(err, mfa.ErrRateLimited) {
		t.Fatalf("挑战预算错误 = %v，期望 ErrRateLimited", err)
	}
}

// TestCancelRevokesRestrictedSession 验证取消第二步同时撤销受限会话。
func TestCancelRevokesRestrictedSession(t *testing.T) {
	env := newTestEnv(t, nil)
	env.now = time.Now().UTC()
	env.enableEmailFactor()
	env.now = time.Now().UTC()
	start, err := env.service.BeginLogin(env.ctx, mfa.BeginLoginRequest{
		Result: env.completeAuthn(), RequestID: "req-cancel"})
	if err != nil {
		t.Fatalf("第一步: %v", err)
	}
	if err := env.service.CancelLogin(env.ctx, mfa.CancelRequest{
		ChallengeID: start.ChallengeID, AttemptToken: start.AttemptToken,
		ExistingSession: start.RestrictedSession.Secret.Reveal(), RequestID: "req-cancel"}); err != nil {
		t.Fatalf("取消: %v", err)
	}
	if state := env.queryString(`SELECT state FROM mfa_challenges WHERE id=?`, start.ChallengeID); state != string(mfa.StateCancelled) {
		t.Errorf("取消后挑战状态 = %q，期望 cancelled", state)
	}
	// 取消后旧验证码不可再用（凭据已撤销）。
	env.now = time.Now().UTC()
	if _, err := env.service.Verify(env.ctx, mfa.VerifyRequest{
		ChallengeID: start.ChallengeID, AttemptToken: start.AttemptToken, Code: "00000000",
		ExistingSession: start.RestrictedSession.Secret.Reveal(), RequestID: "req-cancel-verify"}); err == nil {
		t.Error("取消后挑战不应再可验证")
	}
}

// TestAttemptsExhaustedMarksChallengeFailed 验证挑战自身尝试用尽后迁移 failed。
func TestAttemptsExhaustedMarksChallengeFailed(t *testing.T) {
	env := newTestEnv(t, nil)
	env.now = time.Now().UTC()
	env.enableEmailFactor()
	env.now = time.Now().UTC()
	start, err := env.service.BeginLogin(env.ctx, mfa.BeginLoginRequest{
		Result: env.completeAuthn(), RequestID: "req-exhaust"})
	if err != nil {
		t.Fatalf("第一步: %v", err)
	}
	var lastErr error
	for attempt := 0; attempt < mfa.DefaultMaxAttempts; attempt++ {
		_, lastErr = env.service.Verify(env.ctx, mfa.VerifyRequest{
			ChallengeID: start.ChallengeID, AttemptToken: start.AttemptToken, Code: "11111111",
			ExistingSession: start.RestrictedSession.Secret.Reveal(), RequestID: "req-exhaust-bad"})
	}
	if !errors.Is(lastErr, mfa.ErrAttemptsExceeded) {
		t.Fatalf("尝试用尽错误 = %v，期望 ErrAttemptsExceeded", lastErr)
	}
	if state := env.queryString(`SELECT state FROM mfa_challenges WHERE id=?`, start.ChallengeID); state != string(mfa.StateFailed) {
		t.Errorf("挑战状态 = %q，期望 failed", state)
	}
}

// totpAllowRunner 是测试用“近期认证通过”的步骤 39 收敛入口，仅用于 TOTP 绑定。
type totpAllowRunner struct{}

func (totpAllowRunner) Authorize(ctx context.Context, caller reauth.Caller, request reauth.Request) (reauth.Result, error) {
	return reauth.Result{OperationID: request.OperationID, TargetID: request.TargetID}, nil
}

func (totpAllowRunner) NotifyOutcome(ctx context.Context, result reauth.Result, outcome reauth.Outcome) error {
	return nil
}

// enableTOTP 为测试用户绑定并激活 TOTP，返回种子。
func (e *testEnv) enableTOTP() []byte {
	e.t.Helper()
	e.now = time.Now().UTC()
	caller, err := totp.UserCaller(userID)
	if err != nil {
		e.t.Fatalf("TOTP 调用者: %v", err)
	}
	start, err := e.totp.BeginBinding(e.ctx, caller, "req-totp-bind")
	if err != nil {
		e.t.Fatalf("开始绑定 TOTP: %v", err)
	}
	secret, err := totp.DecodeSecret(start.Secret)
	if err != nil {
		e.t.Fatalf("解码 TOTP 种子: %v", err)
	}
	code, _, err := totp.GenerateCode(secret, e.now, 30, 6)
	if err != nil {
		e.t.Fatalf("生成 TOTP 验证码: %v", err)
	}
	if _, err := e.totp.ConfirmBinding(e.ctx, caller, totp.BindConfirm{
		BindingID: start.BindingID, Code: code, RequestID: "req-totp-confirm"}); err != nil {
		e.t.Fatalf("确认 TOTP 绑定: %v", err)
	}
	// 确认步已被消费（写入 last_accepted_step），推进到下一时间步供登录使用。
	e.now = e.now.Add(30 * time.Second)
	return secret
}

func (e *testEnv) totpCode(secret []byte) string {
	e.t.Helper()
	code, _, err := totp.GenerateCode(secret, e.now, 30, 6)
	if err != nil {
		e.t.Fatalf("生成 TOTP 验证码: %v", err)
	}
	return code
}

// TestPasswordTOTPFullSession 覆盖：密码→TOTP 第二步→完整会话，且同一步重放拒绝；
// 邮件因素未启用时不发送邮件、不消费邮件验证码。
func TestPasswordTOTPFullSession(t *testing.T) {
	env := newTestEnv(t, nil)
	secret := env.enableTOTP()
	start, err := env.service.BeginLogin(env.ctx, mfa.BeginLoginRequest{
		Result: env.completeAuthn(), RequestID: "req-totp-login"})
	if err != nil {
		t.Fatalf("TOTP 第一步: %v", err)
	}
	if start.FactorType != mfa.FactorTOTP || start.MaskedEmail != "" {
		t.Fatalf("因素选择异常: %+v", start)
	}
	if !start.RestrictedSession.Session.IsRestricted() {
		t.Fatal("第一步只能签发受限会话")
	}
	code := env.totpCode(secret)
	result, err := env.service.Verify(env.ctx, mfa.VerifyRequest{
		ChallengeID: start.ChallengeID, AttemptToken: start.AttemptToken, Code: code,
		ExistingSession: start.RestrictedSession.Secret.Reveal(), RequestID: "req-totp-verify"})
	if err != nil {
		t.Fatalf("TOTP 第二步: %v", err)
	}
	if result.Session.Session.IsRestricted() {
		t.Fatal("第二步成功后应签发完整会话")
	}
	if result.Session.Session.AppID != "" {
		t.Errorf("非应用登录不应绑定应用: %q", result.Session.Session.AppID)
	}
	// 同一时间步在新挑战中重放：拒绝（totp 已接受时间步记录）。
	second, err := env.service.BeginLogin(env.ctx, mfa.BeginLoginRequest{
		Result: env.completeAuthn(), RequestID: "req-totp-login-2"})
	if err != nil {
		t.Fatalf("第二个 TOTP 挑战: %v", err)
	}
	if _, err := env.service.Verify(env.ctx, mfa.VerifyRequest{
		ChallengeID: second.ChallengeID, AttemptToken: second.AttemptToken, Code: code,
		ExistingSession: second.RestrictedSession.Secret.Reveal(), RequestID: "req-totp-replay"}); !errors.Is(err, mfa.ErrCodeInvalid) {
		t.Fatalf("TOTP 同一步重放错误 = %v，期望 ErrCodeInvalid", err)
	}
}

// TestTOTPPreferredOverEmailWhenBothEnabled 验证两者共存时默认 TOTP 优先。
func TestTOTPPreferredOverEmailWhenBothEnabled(t *testing.T) {
	env := newTestEnv(t, nil)
	env.enableEmailFactor()
	env.enableTOTP()
	start, err := env.service.BeginLogin(env.ctx, mfa.BeginLoginRequest{
		Result: env.completeAuthn(), RequestID: "req-both"})
	if err != nil {
		t.Fatalf("双因素第一步: %v", err)
	}
	if start.FactorType != mfa.FactorTOTP {
		t.Fatalf("默认应优先 TOTP，实际 %q", start.FactorType)
	}
}

// TestAppScopedTOTPLoginKeepsScope 验证应用作用域 TOTP 第二步后仍是应用会话。
func TestAppScopedTOTPLoginKeepsScope(t *testing.T) {
	env := newTestEnv(t, nil)
	secret := env.enableTOTP()
	const appID = "app_00000000000000000000000000000001"
	env.seedApplication(appID)
	start, err := env.service.BeginLogin(env.ctx, mfa.BeginLoginRequest{
		Result: env.completeAuthn(), AppID: appID, RequestID: "req-totp-app"})
	if err != nil {
		t.Fatalf("应用 TOTP 第一步: %v", err)
	}
	if start.FactorType != mfa.FactorTOTP || start.RestrictedSession.Session.AppID != appID {
		t.Fatalf("应用 TOTP 受限会话异常: %+v", start)
	}
	code := env.totpCode(secret)
	result, err := env.service.Verify(env.ctx, mfa.VerifyRequest{
		ChallengeID: start.ChallengeID, AttemptToken: start.AttemptToken, Code: code,
		ExistingSession: start.RestrictedSession.Secret.Reveal(), RequestID: "req-totp-app-verify"})
	if err != nil {
		t.Fatalf("应用 TOTP 第二步: %v", err)
	}
	if result.Session.Session.IsRestricted() || result.Session.Session.AppID != appID {
		t.Fatalf("TOTP 应用会话作用域异常: kind=%s app=%q",
			result.Session.Session.Kind, result.Session.Session.AppID)
	}
}

// TestTOTPWrongCodeAttemptsExceeded 验证 TOTP 错误码计入尝试上限并迁移 failed。
func TestTOTPWrongCodeAttemptsExceeded(t *testing.T) {
	env := newTestEnv(t, nil)
	env.enableTOTP()
	start, err := env.service.BeginLogin(env.ctx, mfa.BeginLoginRequest{
		Result: env.completeAuthn(), RequestID: "req-totp-attempts"})
	if err != nil {
		t.Fatalf("TOTP 第一步: %v", err)
	}
	var lastErr error
	for attempt := 0; attempt < mfa.DefaultMaxAttempts; attempt++ {
		_, lastErr = env.service.Verify(env.ctx, mfa.VerifyRequest{
			ChallengeID: start.ChallengeID, AttemptToken: start.AttemptToken, Code: "000000",
			ExistingSession: start.RestrictedSession.Secret.Reveal(), RequestID: "req-totp-bad"})
	}
	if !errors.Is(lastErr, mfa.ErrAttemptsExceeded) {
		t.Fatalf("TOTP 尝试用尽错误 = %v，期望 ErrAttemptsExceeded", lastErr)
	}
	if state := env.queryString(`SELECT state FROM mfa_challenges WHERE id=?`, start.ChallengeID); state != string(mfa.StateFailed) {
		t.Errorf("TOTP 挑战状态 = %q，期望 failed", state)
	}
}

// TestNewRequiresTOTPAdapter 验证装配契约：mfa 未配对注入 TOTP 适配器时拒绝构造，
// 避免已绑定 TOTP 的账户被当作“没有因素”而只凭密码登录。
func TestNewRequiresTOTPAdapter(t *testing.T) {
	var captured mfa.Options
	_ = newTestEnv(t, func(options *mfa.Options) { captured = *options })
	captured.TOTP = nil
	if _, err := mfa.New(captured); !errors.Is(err, mfa.ErrOptionsInvalid) {
		t.Fatalf("未注入 TOTP 适配器错误 = %v，期望 ErrOptionsInvalid", err)
	}
}

// ===== 步骤 43：FIDO2 第二步与认证方式选择策略 =====

// fakeSecondFactorPasskey 是测试用的安全密钥第二步替身；真实 WebAuthn 校验在
// internal/passkey 测试中用模拟认证器覆盖。它只验证 mfa 侧的挑战绑定/会话/策略。
type fakeSecondFactorPasskey struct {
	has           bool
	userVerified  bool
	failVerify    error
	userID        string
	lastContextID string
	beginCalls    int
	finishCalls   int
}

func (f *fakeSecondFactorPasskey) HasSecondFactor(ctx context.Context, userID string) (bool, error) {
	return f.has, nil
}

func (f *fakeSecondFactorPasskey) BeginSecondFactor(ctx context.Context, userID, contextID, requestID string) (passkey.SecondFactorStart, error) {
	f.beginCalls++
	f.userID = userID
	f.lastContextID = contextID
	return passkey.SecondFactorStart{
		CeremonyID: "pkc_fake_security_key",
		PublicKey:  []byte(`{"publicKey":{"challenge":"fake-challenge"}}`),
		ExpiresAt:  time.Now().UTC().Add(time.Minute),
		RPID:       "login.example.com",
	}, nil
}

func (f *fakeSecondFactorPasskey) FinishSecondFactor(ctx context.Context, request passkey.SecondFactorFinishRequest) (passkey.SecondFactorResult, error) {
	f.finishCalls++
	if f.failVerify != nil {
		return passkey.SecondFactorResult{}, f.failVerify
	}
	return passkey.SecondFactorResult{
		UserID: f.userID, AuthenticatorID: "cred_fake", UserVerified: f.userVerified,
		VerifiedAt: time.Now().UTC(),
	}, nil
}

type fakeStrongSetupAuthorizer struct {
	allow bool
	calls int
}

func (f *fakeStrongSetupAuthorizer) AuthorizeStrongSetup(ctx context.Context, userID, requestID string) error {
	f.calls++
	if !f.allow {
		return errors.New("初始化未获授权")
	}
	return nil
}

type fakeStrongFactorSource struct{ has bool }

func (f *fakeStrongFactorSource) HasStrongFactor(ctx context.Context, userID string) (bool, error) {
	return f.has, nil
}

type realSessionRevoker struct {
	session *session.Service
	calls   int
}

func (r *realSessionRevoker) Logout(ctx context.Context, secret string) error {
	r.calls++
	return r.session.Logout(ctx, secret)
}

// TestFIDO2SecurityKeySecondFactorFullSession 覆盖：密码 + 安全密钥（WebAuthn UV）
// 完成登录；安全密钥 ceremony 绑定 MFA 挑战上下文；会话获得强认证标记；重放拒绝。
func TestFIDO2SecurityKeySecondFactorFullSession(t *testing.T) {
	adapter := &fakeSecondFactorPasskey{has: true, userVerified: true}
	env := newTestEnv(t, func(options *mfa.Options) { options.Passkeys = adapter })
	start, err := env.service.BeginLogin(env.ctx, mfa.BeginLoginRequest{
		Result: env.completeAuthn(), RequestID: "req-fido2-1"})
	if err != nil {
		t.Fatalf("第一步: %v", err)
	}
	if start.FactorType != mfa.FactorPasskey || start.PasskeyCeremonyID == "" ||
		len(start.PasskeyOptions) == 0 || !start.RequiresSecondFactor {
		t.Fatalf("安全密钥第二步启动结果异常: %+v", start)
	}
	if adapter.lastContextID != start.ChallengeID {
		t.Fatalf("WebAuthn ceremony 上下文应绑定 MFA 挑战: %q != %q",
			adapter.lastContextID, start.ChallengeID)
	}
	result, err := env.service.Verify(env.ctx, mfa.VerifyRequest{
		ChallengeID: start.ChallengeID, AttemptToken: start.AttemptToken,
		PasskeyCeremonyID: start.PasskeyCeremonyID, PasskeyResponse: []byte(`{"id":"fake"}`),
		ExistingSession: start.RestrictedSession.Secret.Reveal(), RequestID: "req-fido2-2"})
	if err != nil {
		t.Fatalf("安全密钥第二步验证: %v", err)
	}
	if result.Session.Session.IsRestricted() {
		t.Fatal("第二步成功后应签发完整会话")
	}
	if result.Authenticated.StrongAuthCompletedAt.IsZero() {
		t.Fatal("安全密钥 UV 完成应在认证结果记录强认证时间")
	}
	if result.Strength != "strong" || result.ACR != "urn:evernight:acr:strong" {
		t.Fatalf("认证事实强度/ACR 异常: %q %q", result.Strength, result.ACR)
	}
	amr := strings.Join(result.AMR, ",")
	if !strings.Contains(amr, "hwk") || !strings.Contains(amr, "user") || !strings.Contains(amr, "mfa") {
		t.Fatalf("AMR 映射缺少安全密钥/UV/MFA: %v", result.AMR)
	}
	validated, err := env.session.Validate(env.ctx, result.Session.Secret.Reveal())
	if err != nil || !validated.CanAccessManagement() {
		t.Fatalf("安全密钥强认证会话应满足管理访问强认证闸门: %+v err=%v", validated, err)
	}
	// 重放同一挑战/assertion 拒绝。
	if _, err := env.service.Verify(env.ctx, mfa.VerifyRequest{
		ChallengeID: start.ChallengeID, AttemptToken: start.AttemptToken,
		PasskeyCeremonyID: start.PasskeyCeremonyID, PasskeyResponse: []byte(`{"id":"fake"}`),
		ExistingSession: start.RestrictedSession.Secret.Reveal(), RequestID: "req-fido2-replay"}); !errors.Is(err, mfa.ErrChallengeInvalid) {
		t.Fatalf("安全密钥第二步重放应拒绝: %v", err)
	}
	// ceremony 上下文不符（跨挑战挪用）拒绝。
	second, err := env.service.BeginLogin(env.ctx, mfa.BeginLoginRequest{
		Result: env.completeAuthn(), RequestID: "req-fido2-3"})
	if err != nil {
		t.Fatalf("第一步: %v", err)
	}
	if _, err := env.service.Verify(env.ctx, mfa.VerifyRequest{
		ChallengeID: second.ChallengeID, AttemptToken: second.AttemptToken,
		PasskeyCeremonyID: "pkc_other_context", PasskeyResponse: []byte(`{"id":"fake"}`),
		ExistingSession: second.RestrictedSession.Secret.Reveal(), RequestID: "req-fido2-4"}); !errors.Is(err, mfa.ErrChallengeInvalid) {
		t.Fatalf("跨挑战 ceremony 应拒绝: %v", err)
	}
}

// TestStrongRequirementRejectsSecurityKeyWithoutUV 验证管理账户强认证策略下没有 UV
// 的安全密钥断言被拒绝，不会降级为完整会话。
func TestStrongRequirementRejectsSecurityKeyWithoutUV(t *testing.T) {
	adapter := &fakeSecondFactorPasskey{has: true, userVerified: false}
	env := newTestEnv(t, func(options *mfa.Options) { options.Passkeys = adapter })
	start, err := env.service.BeginLogin(env.ctx, mfa.BeginLoginRequest{
		Result: env.pendingStrongAuth(), RequestID: "req-uv-1"})
	if err != nil {
		t.Fatalf("强认证账户第一步: %v", err)
	}
	if start.FactorType != mfa.FactorPasskey {
		t.Fatalf("应选择安全密钥因素: %v", start.FactorType)
	}
	if _, err := env.service.Verify(env.ctx, mfa.VerifyRequest{
		ChallengeID: start.ChallengeID, AttemptToken: start.AttemptToken,
		PasskeyCeremonyID: start.PasskeyCeremonyID, PasskeyResponse: []byte(`{}`),
		ExistingSession: start.RestrictedSession.Secret.Reveal(), RequestID: "req-uv-2"}); !errors.Is(err, mfa.ErrStrongAuthRequired) {
		t.Fatalf("缺少 UV 的强认证第二步应拒绝: %v", err)
	}
}

// TestStrongRequirementDoesNotDowngradeToEmail 验证只有邮件因素的管理账户不会被
// 降级到邮件第二步，而是明确返回需要强认证。
func TestStrongRequirementDoesNotDowngradeToEmail(t *testing.T) {
	env := newTestEnv(t, nil)
	env.enableEmailFactor()
	if _, err := env.service.BeginLogin(env.ctx, mfa.BeginLoginRequest{
		Result: env.pendingStrongAuth(), RequestID: "req-nodowngrade-1"}); !errors.Is(err, mfa.ErrStrongAuthRequired) {
		t.Fatalf("只有邮件时强认证账户应拒绝而不是降级: %v", err)
	}
	if got := env.count(`SELECT COUNT(*) FROM mfa_challenges WHERE user_id=? AND purpose='login'`, userID); got != 0 {
		t.Fatalf("拒绝降级时不应创建第二步挑战: %d", got)
	}
}

// TestStrongRequirementPrefersSecurityKeyThenTOTP 验证选择器优先返回安全密钥，
// 没有安全密钥时回退 TOTP，且邮件永远不会被选中满足强认证。
func TestStrongRequirementPrefersSecurityKeyThenTOTP(t *testing.T) {
	adapter := &fakeSecondFactorPasskey{has: true, userVerified: true}
	env := newTestEnv(t, func(options *mfa.Options) { options.Passkeys = adapter })
	env.enableEmailFactor()
	env.enableTOTP()
	start, err := env.service.BeginLogin(env.ctx, mfa.BeginLoginRequest{
		Result: env.pendingStrongAuth(), RequestID: "req-pref-1"})
	if err != nil || start.FactorType != mfa.FactorPasskey {
		t.Fatalf("有安全密钥时应优先选择: factor=%v err=%v", start.FactorType, err)
	}
	// 没有安全密钥时选择 TOTP（而不是邮件）。
	env2 := newTestEnv(t, func(options *mfa.Options) {
		options.Passkeys = &fakeSecondFactorPasskey{has: false}
		options.AllowTOTPForStrongAuth = true
	})
	env2.enableEmailFactor()
	env2.enableTOTP()
	start2, err := env2.service.BeginLogin(env2.ctx, mfa.BeginLoginRequest{
		Result: env2.pendingStrongAuth(), RequestID: "req-pref-2"})
	if err != nil || start2.FactorType != mfa.FactorTOTP {
		t.Fatalf("无安全密钥时应回退 TOTP 而不是邮件: factor=%v err=%v", start2.FactorType, err)
	}
}

// TestStrongAuthDefaultRejectsTOTPOnly 验证默认策略下“密码+TOTP”不能满足管理
// 强认证（要求 Passkey/安全密钥 UV）；无可用强因素时明确报 MFA_REQUIRED，而不是
// 静默接受较弱方式。
func TestStrongAuthDefaultRejectsTOTPOnly(t *testing.T) {
	env := newTestEnv(t, func(options *mfa.Options) {
		options.Passkeys = &fakeSecondFactorPasskey{has: false}
	})
	env.enableTOTP()
	if _, err := env.service.BeginLogin(env.ctx, mfa.BeginLoginRequest{
		Result: env.pendingStrongAuth(), RequestID: "req-totp-only-1"}); !errors.Is(err, mfa.ErrStrongAuthRequired) {
		t.Fatalf("默认要求 UV 时密码+TOTP 不应满足管理强认证: %v", err)
	}
}

// TestStrongAuthSetupRequiresControlledAuthorization 验证普通受限会话不能自助进入
// 强认证初始化：授权器缺失/拒绝时 fail-closed 返回 MFA_REQUIRED，不创建挑战。
func TestStrongAuthSetupRequiresControlledAuthorization(t *testing.T) {
	deny := &fakeStrongSetupAuthorizer{allow: false}
	env := newTestEnv(t, func(options *mfa.Options) {
		options.Passkeys = &fakeSecondFactorPasskey{has: false}
		options.AllowStrongAuthSetup = true
		options.StrongFactorSource = &fakeStrongFactorSource{has: false}
		options.Revoker = &realSessionRevoker{}
		options.StrongSetupAuthorizer = deny
	})
	if _, err := env.service.BeginLogin(env.ctx, mfa.BeginLoginRequest{
		Result: env.pendingStrongAuth(), RequestID: "req-setup-deny-1"}); !errors.Is(err, mfa.ErrStrongAuthRequired) {
		t.Fatalf("初始化未获授权时应拒绝: %v", err)
	}
	if deny.calls != 1 {
		t.Fatalf("应调用受控初始化授权器: %d", deny.calls)
	}
	if got := env.count(`SELECT COUNT(*) FROM mfa_challenges WHERE user_id=? AND purpose='strong_setup'`, userID); got != 0 {
		t.Fatalf("未获授权时不应创建初始化挑战: %d", got)
	}
}

// TestStrongAuthInitializationClosure 验证管理账户强认证初始化闭环：受限会话 +
// 初始化挑战 → 绑定强因素 → 完成初始化（撤销受限会话）→ 必须重新登录；未绑定
// 强因素时不能完成。
func TestStrongAuthInitializationClosure(t *testing.T) {
	strongSource := &fakeStrongFactorSource{has: false}
	revoker := &realSessionRevoker{}
	authorizer := &fakeStrongSetupAuthorizer{allow: true}
	env := newTestEnv(t, func(options *mfa.Options) {
		options.Passkeys = &fakeSecondFactorPasskey{has: false}
		options.AllowStrongAuthSetup = true
		options.StrongFactorSource = strongSource
		options.Revoker = revoker
		options.StrongSetupAuthorizer = authorizer
	})
	revoker.session = env.session
	start, err := env.service.BeginLogin(env.ctx, mfa.BeginLoginRequest{
		Result: env.pendingStrongAuth(), RequestID: "req-setup-1"})
	if err != nil {
		t.Fatalf("强认证初始化启动: %v", err)
	}
	if !start.SetupRequired || len(start.AllowedSetupMethods) == 0 ||
		start.AllowedSetupMethods[0] != authfact.MethodPasskey {
		t.Fatalf("初始化启动结果异常: %+v", start)
	}
	if !start.RestrictedSession.Session.IsRestricted() {
		t.Fatal("初始化流程只能签发受限会话")
	}
	// 尚未绑定强因素时不能完成初始化。
	if _, err := env.service.CompleteStrongSetup(env.ctx, mfa.StrongSetupCompleteRequest{
		ChallengeID: start.ChallengeID, AttemptToken: start.AttemptToken,
		ExistingSession: start.RestrictedSession.Secret.Reveal(), RequestID: "req-setup-2"}); !errors.Is(err, mfa.ErrStrongSetupIncomplete) {
		t.Fatalf("未绑定强因素时完成初始化应拒绝: %v", err)
	}
	// 宿主通过受限流程完成强因素绑定后，完成初始化：撤销受限会话并要求重新登录。
	strongSource.has = true
	result, err := env.service.CompleteStrongSetup(env.ctx, mfa.StrongSetupCompleteRequest{
		ChallengeID: start.ChallengeID, AttemptToken: start.AttemptToken,
		ExistingSession: start.RestrictedSession.Secret.Reveal(), RequestID: "req-setup-3"})
	if err != nil {
		t.Fatalf("完成强认证初始化: %v", err)
	}
	if !result.MustReauthenticate || result.UserID != userID {
		t.Fatalf("初始化完成结果异常: %+v", result)
	}
	if revoker.calls != 1 {
		t.Fatalf("初始化完成后应撤销受限会话: revoker=%d", revoker.calls)
	}
	if _, err := env.session.Validate(env.ctx, start.RestrictedSession.Secret.Reveal()); err == nil {
		t.Fatal("初始化完成后受限会话必须失效")
	}
	// 同一初始化挑战不能重复完成。
	if _, err := env.service.CompleteStrongSetup(env.ctx, mfa.StrongSetupCompleteRequest{
		ChallengeID: start.ChallengeID, AttemptToken: start.AttemptToken,
		ExistingSession: start.RestrictedSession.Secret.Reveal(), RequestID: "req-setup-4"}); !errors.Is(err, mfa.ErrChallengeInvalid) {
		t.Fatalf("重复完成初始化应拒绝: %v", err)
	}
}

// TestAvailableSecondFactorMethodsOnlyReturnsEnabled 验证认证方式选择器只返回实际
// 启用且满足策略的方式；没有因素时返回空列表而不是报错或猜测。
func TestAvailableSecondFactorMethodsOnlyReturnsEnabled(t *testing.T) {
	adapter := &fakeSecondFactorPasskey{has: false, userVerified: true}
	env := newTestEnv(t, func(options *mfa.Options) { options.Passkeys = adapter })
	methods, err := env.service.AvailableSecondFactorMethods(env.ctx, env.caller(), userID)
	if err != nil {
		t.Fatalf("可用方式: %v", err)
	}
	if len(methods) != 0 {
		t.Fatalf("没有启用因素时应返回空列表: %v", methods)
	}
	adapter.has = true
	env.enableEmailFactor()
	env.enableTOTP()
	methods, err = env.service.AvailableSecondFactorMethods(env.ctx, env.caller(), userID)
	if err != nil {
		t.Fatalf("可用方式: %v", err)
	}
	joined := ""
	for _, method := range methods {
		joined += string(method) + ","
	}
	for _, want := range []string{"security_key,", "totp,", "email_otp,"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("可用方式缺少 %q: %v", want, methods)
		}
	}
	// 未强制 MFA 时允许本人移除邮件因素。
	if err := env.service.RemoveEmailFactor(env.ctx, env.caller(), "req-remove-1"); err != nil {
		t.Fatalf("未强制 MFA 时允许移除邮件因素: %v", err)
	}
	// 删除最后一个因素保护：强制 MFA 且没有其他可用因素时拒绝移除。
	forcedEnv := newTestEnv(t, func(options *mfa.Options) {
		options.Policy = &fakeMFARequiredPolicy{forced: true}
	})
	forcedEnv.enableEmailFactor()
	if err := forcedEnv.service.RemoveEmailFactor(forcedEnv.ctx, forcedEnv.caller(),
		"req-remove-2"); !errors.Is(err, mfa.ErrFactorRequired) {
		t.Fatalf("强制 MFA 时移除最后可用因素应被拒绝: %v", err)
	}
}

// fakeMFARequiredPolicy 模拟宿主强制 MFA 策略。
type fakeMFARequiredPolicy struct{ forced bool }

func (f *fakeMFARequiredPolicy) MFARequired(ctx context.Context, userID string) (bool, error) {
	return f.forced, nil
}

// TestTOTPStrongAuthGatedByPolicy 验证 TOTP 强认证时间门控：挑战要求强认证且宿主
// 显式允许密码+TOTP 时才记录强认证时间；普通账户的 TOTP 第二步只完成登录，不授予
// 管理访问强认证。
func TestTOTPStrongAuthGatedByPolicy(t *testing.T) {
	// 允许密码+TOTP 作为强认证备用：管理账户验证成功后应记录强认证时间。
	env := newTestEnv(t, func(options *mfa.Options) {
		options.AllowTOTPForStrongAuth = true
	})
	secret := env.enableTOTP()
	start, err := env.service.BeginLogin(env.ctx, mfa.BeginLoginRequest{
		Result: env.pendingStrongAuth(), RequestID: "req-totp-gate-1"})
	if err != nil || start.FactorType != mfa.FactorTOTP {
		t.Fatalf("允许 TOTP 强认证备用时应选择 TOTP: factor=%v err=%v", start.FactorType, err)
	}
	code, _, err := totp.GenerateCode(secret, env.now, 30, 6)
	if err != nil {
		t.Fatalf("生成 TOTP 码: %v", err)
	}
	strongResult, err := env.service.Verify(env.ctx, mfa.VerifyRequest{
		ChallengeID: start.ChallengeID, AttemptToken: start.AttemptToken, Code: code,
		ExistingSession: start.RestrictedSession.Secret.Reveal(), RequestID: "req-totp-gate-2"})
	if err != nil {
		t.Fatalf("TOTP 强认证第二步: %v", err)
	}
	if strongResult.Authenticated.StrongAuthCompletedAt.IsZero() {
		t.Fatal("允许密码+TOTP 满足强认证时应记录强认证时间")
	}
	// 普通账户（无强认证要求）的 TOTP 第二步：完整会话但不记录强认证时间。
	normal := newTestEnv(t, nil)
	normalSecret := normal.enableTOTP()
	normalStart, err := normal.service.BeginLogin(normal.ctx, mfa.BeginLoginRequest{
		Result: normal.completeAuthn(), RequestID: "req-totp-gate-3"})
	if err != nil || normalStart.FactorType != mfa.FactorTOTP {
		t.Fatalf("普通账户应选择已启用 TOTP: factor=%v err=%v", normalStart.FactorType, err)
	}
	normalCode, _, err := totp.GenerateCode(normalSecret, normal.now, 30, 6)
	if err != nil {
		t.Fatalf("生成 TOTP 码: %v", err)
	}
	normalResult, err := normal.service.Verify(normal.ctx, mfa.VerifyRequest{
		ChallengeID: normalStart.ChallengeID, AttemptToken: normalStart.AttemptToken,
		Code: normalCode, ExistingSession: normalStart.RestrictedSession.Secret.Reveal(),
		RequestID: "req-totp-gate-4"})
	if err != nil {
		t.Fatalf("普通账户 TOTP 第二步: %v", err)
	}
	if !normalResult.Authenticated.StrongAuthCompletedAt.IsZero() {
		t.Fatal("普通账户的 TOTP 第二步不应记录管理强认证时间")
	}
	if normalResult.Session.Session.IsRestricted() {
		t.Fatal("普通账户 TOTP 第二步应签发完整会话")
	}
}

// TestRecoveryAuthenticationHandoff 验证恢复代码前的只读交接：只接受一致且活动的
// 第二因素挑战/受限会话，不消费挑战、不签发会话。
func TestRecoveryAuthenticationHandoff(t *testing.T) {
	env := newTestEnv(t, nil)
	env.enableEmailFactor()
	start, err := env.service.BeginLogin(env.ctx, mfa.BeginLoginRequest{
		Result: env.completeAuthn(), RequestID: "req-handoff"})
	if err != nil {
		t.Fatalf("第二步: %v", err)
	}
	result, err := env.service.RecoveryAuthentication(env.ctx, mfa.RecoveryAuthenticationRequest{
		ChallengeID: start.ChallengeID, AttemptToken: start.AttemptToken,
		ExistingSession: start.RestrictedSession.Secret.Reveal(), RequestID: "req-handoff"})
	if err != nil {
		t.Fatalf("只读交接失败: %v", err)
	}
	if result.Outcome != authn.OutcomePendingSecondFactor || !result.Restricted ||
		len(result.RequiredSteps) != 1 || result.RequiredSteps[0] != authn.StepSecondFactor ||
		result.SecurityVersion <= 0 || result.UserID == "" {
		t.Fatalf("交接结果不满足恢复前置契约: %+v", result)
	}
	// 只读：挑战仍为 pending，可用正确验证码继续完成登录。
	if state := env.queryString(`SELECT state FROM mfa_challenges WHERE id=?`, start.ChallengeID); state != string(mfa.StatePending) {
		t.Fatalf("只读交接不应改变挑战状态，实际 %s", state)
	}
	// 错误会话/错误令牌/过期都应 fail-closed。
	other, err := env.session.Login(env.ctx, session.LoginRequest{Result: env.completeAuthn(),
		RequestID: "req-other-session"})
	if err != nil {
		t.Fatalf("签发其他会话: %v", err)
	}
	_ = other
	if _, err := env.service.RecoveryAuthentication(env.ctx, mfa.RecoveryAuthenticationRequest{
		ChallengeID: start.ChallengeID, AttemptToken: "00", ExistingSession: start.RestrictedSession.Secret.Reveal()}); !errors.Is(err, mfa.ErrChallengeInvalid) {
		t.Fatalf("短令牌应拒绝，实际 %v", err)
	}
	if _, err := env.service.RecoveryAuthentication(env.ctx, mfa.RecoveryAuthenticationRequest{
		ChallengeID: start.ChallengeID, AttemptToken: start.AttemptToken,
		ExistingSession: "wrong-session"}); !errors.Is(err, mfa.ErrChallengeInvalid) {
		t.Fatalf("错误会话应拒绝，实际 %v", err)
	}
	// 成功后挑战一次性消费，交接不可再用。
	code := env.waitCode()
	if _, err := env.service.Verify(env.ctx, mfa.VerifyRequest{ChallengeID: start.ChallengeID,
		AttemptToken: start.AttemptToken, Code: code,
		ExistingSession: start.RestrictedSession.Secret.Reveal(), RequestID: "req-handoff-verify"}); err != nil {
		t.Fatalf("验证失败: %v", err)
	}
	if _, err := env.service.RecoveryAuthentication(env.ctx, mfa.RecoveryAuthenticationRequest{
		ChallengeID: start.ChallengeID, AttemptToken: start.AttemptToken,
		ExistingSession: start.RestrictedSession.Secret.Reveal()}); !errors.Is(err, mfa.ErrChallengeInvalid) {
		t.Fatalf("已消费挑战不应再交接，实际 %v", err)
	}
}
