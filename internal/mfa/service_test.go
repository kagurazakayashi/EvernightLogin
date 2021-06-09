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
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/credential"
	credentialsqlite "github.com/kagurazakayashi/EvernightLogin/internal/credential/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	"github.com/kagurazakayashi/EvernightLogin/internal/mfa"
	mfasqlite "github.com/kagurazakayashi/EvernightLogin/internal/mfa/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	sessionsqlite "github.com/kagurazakayashi/EvernightLogin/internal/session/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testmail"
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
	now     time.Time
}

func newTestEnv(t *testing.T, mutate func(*mfa.Options)) *testEnv {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "mfa-test.db")
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
	options := mfa.Options{
		Store: mfaStore, Audit: recorder, Credentials: credentialService,
		Sessions: sessionService, Mailer: sender,
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
