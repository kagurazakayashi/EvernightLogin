package passwordreset_test

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/url"
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
	"github.com/kagurazakayashi/EvernightLogin/internal/passwordreset"
	passwordresetsqlite "github.com/kagurazakayashi/EvernightLogin/internal/passwordreset/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testmail"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

var seedTime = time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)

const userID = "usr_00000000000000000000000000000001"
const otherUserID = "usr_00000000000000000000000000000002"

var tokenPattern = regexp.MustCompile(`token=([^"&\s]+)`)

type stubPasswords struct {
	mu          sync.Mutex
	changeCalls int
	resetCalls  int
	changeErr   error
	resetErr    error
	lastNew     string
	lastUser    string
}

func (s *stubPasswords) SetPassword(ctx context.Context, caller authn.Caller, request authn.SetPasswordRequest) (authn.SetPasswordResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.changeCalls++
	s.lastUser = request.TargetUserID
	s.lastNew = request.NewPassword
	if s.changeErr != nil {
		return authn.SetPasswordResult{}, s.changeErr
	}
	return authn.SetPasswordResult{UserID: request.TargetUserID, SecurityVersion: 2,
		PasswordChangedAt: seedTime}, nil
}

func (s *stubPasswords) ResetPasswordForRecovery(ctx context.Context, caller authn.Caller, request authn.RecoveryResetRequest) (authn.SetPasswordResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resetCalls++
	s.lastUser = request.UserID
	s.lastNew = request.NewPassword
	if s.resetErr != nil {
		return authn.SetPasswordResult{}, s.resetErr
	}
	return authn.SetPasswordResult{UserID: request.UserID, SecurityVersion: 3,
		PasswordChangedAt: seedTime}, nil
}

type stubSessions struct {
	mu      sync.Mutex
	revoked []string
}

func (s *stubSessions) RevokeAllForUser(ctx context.Context, userID, reason string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked = append(s.revoked, userID+":"+reason)
	return 1, nil
}

type testEnv struct {
	t       *testing.T
	ctx     context.Context
	raw     *storagesqlite.Store
	audit   *audit.Recorder
	mail    *testmail.Server
	now     time.Time
	pass    *stubPasswords
	sess    *stubSessions
	service *passwordreset.Service
}

func newTestEnv(t *testing.T, mutate func(*passwordreset.Options)) *testEnv {
	t.Helper()
	ctx := context.Background()
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(filepath.Join(testutil.TempDir(t), "pwreset.db")))
	if err != nil {
		t.Fatalf("打开数据库: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	list, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移: %v", err)
	}
	if _, err := raw.Migrate(ctx, list); err != nil {
		t.Fatalf("执行迁移: %v", err)
	}
	auditStore, err := auditsqlite.New(raw)
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
	credentialStore, err := credentialsqlite.New(raw)
	if err != nil {
		t.Fatalf("凭证存储: %v", err)
	}
	env := &testEnv{t: t, ctx: ctx, raw: raw, audit: recorder,
		pass: &stubPasswords{}, sess: &stubSessions{}, now: time.Now().UTC()}
	credentialService, err := credential.New(credentialStore, credential.Options{
		Keyring: keyring, Now: func() time.Time { return env.now },
	})
	if err != nil {
		t.Fatalf("凭证服务: %v", err)
	}
	mailServer, err := testmail.New(testmail.Options{Addr: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("邮件捕获器: %v", err)
	}
	if err := mailServer.Start(); err != nil {
		t.Fatalf("启动邮件捕获器: %v", err)
	}
	t.Cleanup(func() { _ = mailServer.Close() })
	env.mail = mailServer
	sender, err := mailer.NewSMTPSender(mailer.SMTPOptions{
		Addr: mailServer.Addr().String(), TLSMode: mailer.TLSModeNone, AllowPlaintextLocal: true,
	})
	if err != nil {
		t.Fatalf("SMTP 发送器: %v", err)
	}
	store, err := passwordresetsqlite.New(raw)
	if err != nil {
		t.Fatalf("找回存储: %v", err)
	}
	options := passwordreset.Options{
		Store: store, Audit: recorder, Credentials: credentialService,
		Passwords: env.pass, Sessions: env.sess, Mailer: sender,
		FromAddress: "security@example.com", AppName: "登录服务",
		SupportURL:   "https://example.com/support",
		ResetURLBase: "https://example.com/reset",
		Now:          func() time.Time { return env.now },
		Logger:       slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}
	if mutate != nil {
		mutate(&options)
	}
	service, err := passwordreset.New(options)
	if err != nil {
		t.Fatalf("找回服务: %v", err)
	}
	env.service = service
	env.seedUser(userID, "alice", "active", false)
	env.seedUser(otherUserID, "bob", "disabled", false)
	env.seedEmail(userID, "alice@example.com")
	env.seedEmail(otherUserID, "bob@example.com")
	env.seedPassword(userID)
	return env
}

func (e *testEnv) seedUser(id, username, status string, isRoot bool) {
	e.t.Helper()
	now := seedTime.UnixMilli()
	rootInt := 0
	if isRoot {
		rootInt = 1
	}
	if _, err := e.raw.DB().ExecContext(e.ctx, `INSERT INTO users(
id,username,username_normalized,nickname,biography,avatar_ref,language,timezone,status,is_root,
security_version,row_version,created_at_ms,updated_at_ms
) VALUES(?,?,?,'','',NULL,'zh-CN','Asia/Shanghai',?,?,1,1,?,?)`,
		id, username, strings.ToLower(username), status, rootInt, now, now); err != nil {
		e.t.Fatalf("用户: %v", err)
	}
}

func (e *testEnv) seedEmail(id, address string) {
	e.t.Helper()
	now := seedTime.UnixMilli()
	if _, err := e.raw.DB().ExecContext(e.ctx, `INSERT INTO user_emails(
email_normalized,user_id,email,verified_at_ms,created_at_ms,updated_at_ms
) VALUES(?,?,?,?,?,?)`, strings.ToLower(address), id, address, now, now, now); err != nil {
		e.t.Fatalf("邮箱: %v", err)
	}
}

func (e *testEnv) seedPassword(id string) {
	e.t.Helper()
	now := seedTime.UnixMilli()
	if _, err := e.raw.DB().ExecContext(e.ctx, `INSERT INTO password_credentials(
user_id,hash_scheme,hash_version,password_hash,must_change,row_version,created_at_ms,updated_at_ms,changed_at_ms
) VALUES(?,'argon2id',19,?,0,1,?,?,?)`, id,
		"$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHRzYWx0$"+
			strings.Repeat("a", 43), now, now, now); err != nil {
		e.t.Fatalf("密码凭证: %v", err)
	}
}

func (e *testEnv) count(query string, args ...any) int {
	e.t.Helper()
	var value int
	if err := e.raw.DB().QueryRowContext(e.ctx, query, args...).Scan(&value); err != nil {
		e.t.Fatalf("计数: %v", err)
	}
	return value
}

// waitToken 从本地捕获器取找回 token。
func (e *testEnv) waitToken() string {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(e.ctx, time.Second)
		messages, err := e.mail.Wait(ctx, testmail.Query{To: "alice@example.com"})
		cancel()
		if err == nil && len(messages) > 0 {
			body := decodeMessageBody(messages[0])
			match := tokenPattern.FindStringSubmatch(body)
			if len(match) == 2 {
				decoded, decodeErr := url.QueryUnescape(match[1])
				if decodeErr == nil {
					return decoded
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	e.t.Errorf("未收到找回邮件 token（reset_requests=%d, audit_fail=%d, mail=%d）",
		e.count(`SELECT COUNT(*) FROM password_reset_requests`),
		e.count(`SELECT COUNT(*) FROM audit_events WHERE action='password.reset_requested' AND outcome='failure'`),
		len(e.mailSnapshot()))
	return ""
}

// TestChangePasswordRevokesSessionsAndEnqueuesOutbox 覆盖本人改密：敏感策略与密码
// 策略由 authn 执行，服务再撤销会话、返回需重登、写 outbox，且不泄露密码。
func TestChangePasswordRevokesSessionsAndEnqueuesOutbox(t *testing.T) {
	env := newTestEnv(t, nil)
	env.now = time.Now().UTC()
	caller, err := passwordreset.UserCaller(userID)
	if err != nil {
		t.Fatalf("调用者: %v", err)
	}
	result, err := env.service.ChangePassword(env.ctx, caller, passwordreset.ChangeRequest{
		CurrentPassword: "old-password", NewPassword: "NewSecret!12345",
		ClientIP: "203.0.113.7", RequestID: "req-change"})
	if err != nil {
		t.Fatalf("改密: %v", err)
	}
	if !result.RequiresRelogin || result.SecurityVersion < 2 {
		t.Fatalf("改密结果异常: %+v", result)
	}
	if len(env.sess.revoked) != 1 || !strings.HasPrefix(env.sess.revoked[0], userID+":") {
		t.Errorf("会话撤销 = %v", env.sess.revoked)
	}
	if env.count(`SELECT COUNT(*) FROM oauth_revocation_events WHERE user_id=? AND processed_at_ms IS NULL`, userID) != 1 {
		t.Error("缺少 OAuth 撤销 outbox 事件")
	}
	// 密码不得出现在审计中。
	rows, err := env.raw.DB().QueryContext(env.ctx, `SELECT action,COALESCE(detail_json,'') FROM audit_events`)
	if err != nil {
		t.Fatalf("读取审计: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var action, detail string
		if err := rows.Scan(&action, &detail); err != nil {
			t.Fatalf("扫描审计: %v", err)
		}
		if strings.Contains(action+detail, "NewSecret!12345") {
			t.Error("审计泄露新密码")
		}
	}
}

// TestBeginResetUniformResponse 覆盖邮件找回：存在/不存在/禁用账户公开响应一致；
// 只为存在且可找回账户发送邮件，邮件包含一次性入口。
func TestBeginResetUniformResponse(t *testing.T) {
	env := newTestEnv(t, nil)
	env.now = time.Now().UTC()
	// 存在账户：同样返回空结果，但发送邮件。
	if _, err := env.service.BeginReset(env.ctx, passwordreset.BeginResetRequest{Identifier: "alice@example.com", RequestID: "req-reset-a"}); err != nil {
		t.Fatalf("开始找回（存在）: %v", err)
	}
	token := env.waitToken()
	if token == "" {
		t.Fatal("缺少找回 token")
	}
	// 不存在/禁用账户：返回同样零值且不产生新请求/邮件。
	if _, err := env.service.BeginReset(env.ctx, passwordreset.BeginResetRequest{Identifier: "nobody@example.com", RequestID: "req-reset-b"}); err != nil {
		t.Fatalf("开始找回（不存在）: %v", err)
	}
	if _, err := env.service.BeginReset(env.ctx, passwordreset.BeginResetRequest{Identifier: "bob@example.com", RequestID: "req-reset-c"}); err != nil {
		t.Fatalf("开始找回（禁用）: %v", err)
	}
	if count := env.count(`SELECT COUNT(*) FROM password_reset_requests`); count != 1 {
		t.Errorf("找回请求数 = %d，期望 1", count)
	}
	// 页面预检查不消费 token。
	if err := env.service.ValidateResetToken(env.ctx, token); err != nil {
		t.Fatalf("预检查 token: %v", err)
	}
}

// TestCompleteResetConcurrentSingleWinnerAndMFAKept 覆盖找回完成：并发同一 token
// 只有一个成功、过期/重放拒绝、MFA 因素保持不变、无会话签发。
func TestCompleteResetConcurrentSingleWinnerAndMFAKept(t *testing.T) {
	env := newTestEnv(t, nil)
	env.now = time.Now().UTC()
	// 预置一个 MFA 因素，重置后必须保持。
	if _, err := env.raw.DB().ExecContext(env.ctx, `INSERT INTO mfa_factors(
id,user_id,factor_type,status,created_at_ms,updated_at_ms
) VALUES('mft_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',?,'email','active',?,?)`,
		userID, env.now.UnixMilli(), env.now.UnixMilli()); err != nil {
		t.Fatalf("插入 MFA 因素: %v", err)
	}
	if _, err := env.service.BeginReset(env.ctx, passwordreset.BeginResetRequest{Identifier: "alice@example.com", RequestID: "req-reset-1"}); err != nil {
		t.Fatalf("开始找回: %v", err)
	}
	token := env.waitToken()
	startChannel := make(chan struct{})
	results := make(chan error, 2)
	var waitGroup sync.WaitGroup
	for index := 0; index < 2; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-startChannel
			_, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
				Token: token, NewPassword: "ResetSecret!9876", RequestID: "req-complete"})
			results <- err
		}()
	}
	close(startChannel)
	waitGroup.Wait()
	close(results)
	successes, rejected := 0, 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, passwordreset.ErrTokenInvalid):
			rejected++
		default:
			t.Fatalf("并发找回未知错误: %v", err)
		}
	}
	if successes != 1 || rejected != 1 {
		t.Errorf("并发找回 = 成功 %d / 拒绝 %d，期望 1/1", successes, rejected)
	}
	if env.pass.resetCalls != 1 {
		t.Errorf("密码重置调用 = %d，期望 1", env.pass.resetCalls)
	}
	if count := env.count(`SELECT COUNT(*) FROM mfa_factors WHERE user_id=? AND status='active'`, userID); count != 1 {
		t.Errorf("MFA 因素被清除: %d", count)
	}
	if len(env.sess.revoked) == 0 || !strings.Contains(env.sess.revoked[len(env.sess.revoked)-1], "password_reset") {
		t.Errorf("找回后未撤销会话: %v", env.sess.revoked)
	}
	// 安全告知已发送，且不含新密码/token。
	sawNotice := false
	for _, message := range env.mailSnapshot() {
		body := decodeMessageBody(message)
		if !strings.Contains(body, "密码已通过邮件找回被重置") {
			continue
		}
		sawNotice = true
		if strings.Contains(body, "ResetSecret!9876") || strings.Contains(body, token) {
			t.Error("安全告知泄露新密码或原始 token")
		}
	}
	if !sawNotice {
		t.Error("找回重置后缺少安全告知")
	}
	// 重放同一 token 拒绝。
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: token, NewPassword: "ResetSecret!9876", RequestID: "req-replay"}); !errors.Is(err, passwordreset.ErrTokenInvalid) {
		t.Fatalf("重放错误 = %v，期望 ErrTokenInvalid", err)
	}
}

// TestResetExpiredAndMailFailure 覆盖入口过期与邮件失败路径（公开响应一致、不泄密）。
func TestResetExpiredAndMailFailure(t *testing.T) {
	env := newTestEnv(t, nil)
	env.now = time.Now().UTC()
	if _, err := env.service.BeginReset(env.ctx, passwordreset.BeginResetRequest{Identifier: "alice@example.com", RequestID: "req-expire"}); err != nil {
		t.Fatalf("开始找回: %v", err)
	}
	token := env.waitToken()
	env.now = env.now.Add(16 * time.Minute)
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: token, NewPassword: "ResetSecret!9876", RequestID: "req-expired"}); !errors.Is(err, passwordreset.ErrTokenExpired) {
		t.Fatalf("过期错误 = %v，期望 ErrTokenExpired", err)
	}
	// 新的找回请求 + 邮件失败：公开仍统一返回成功，不泄露。
	failEnv := newTestEnv(t, func(options *passwordreset.Options) {
		options.Mailer = failingSender{}
	})
	failEnv.now = time.Now().UTC()
	if _, err := failEnv.service.BeginReset(failEnv.ctx, passwordreset.BeginResetRequest{Identifier: "alice@example.com", RequestID: "req-mailfail"}); err != nil {
		t.Fatalf("邮件失败公开响应不应报错: %v", err)
	}
	if count := failEnv.count(`SELECT COUNT(*) FROM audit_events WHERE action='password.reset_requested' AND outcome='failure'`); count < 1 {
		t.Error("邮件失败缺少失败审计")
	}
}

func decodeMessageBody(message testmail.Message) string {
	raw := strings.ReplaceAll(string(message.Data), "\r\n", "\n")
	parts := strings.SplitN(raw, "\n\n", 2)
	encoded := raw
	if len(parts) == 2 {
		encoded = parts[1]
	}
	encoded = strings.ReplaceAll(strings.ReplaceAll(encoded, "\n", ""), "\r", "")
	if decoded, err := base64.StdEncoding.DecodeString(encoded); err == nil {
		return string(decoded)
	}
	return raw
}

func (e *testEnv) mailSnapshot() []testmail.Message {
	return e.mail.Messages(testmail.Query{})
}

type failingSender struct{}

func (failingSender) Send(ctx context.Context, message mailer.Message) error {
	return errors.New("smtp unavailable")
}

// TestBeginResetUniformIneligible 验证无密码/root 账户公开响应与普通未命中一致，
// 不发送邮件、不创建找回请求。
func TestBeginResetUniformIneligible(t *testing.T) {
	env := newTestEnv(t, nil)
	env.now = time.Now().UTC()
	// root 账户：有已验证邮箱与密码。
	env.seedUser("usr_00000000000000000000000000000003", "rootuser", "active", true)
	env.seedEmail("usr_00000000000000000000000000000003", "root@example.com")
	env.seedPassword("usr_00000000000000000000000000000003")
	// 无密码账户：有已验证邮箱但没有密码凭证。
	env.seedUser("usr_00000000000000000000000000000004", "nopass", "active", false)
	env.seedEmail("usr_00000000000000000000000000000004", "nopass@example.com")
	for _, identifier := range []string{"root@example.com", "nopass@example.com"} {
		if _, err := env.service.BeginReset(env.ctx, passwordreset.BeginResetRequest{
			Identifier: identifier, RequestID: "req-ineligible"}); err != nil {
			t.Fatalf("不可找回账户公开响应不应报错: %v", err)
		}
	}
	if count := env.count(`SELECT COUNT(*) FROM password_reset_requests`); count != 0 {
		t.Errorf("不可找回账户不应创建请求，实际 %d", count)
	}
	if len(env.mailSnapshot()) != 0 {
		t.Error("不可找回账户不应发送邮件")
	}
}

// TestCompleteRejectsDisabledAfterIssue 验证 token 发出后账户被禁用，Complete 拒绝。
func TestCompleteRejectsDisabledAfterIssue(t *testing.T) {
	env := newTestEnv(t, nil)
	env.now = time.Now().UTC()
	if _, err := env.service.BeginReset(env.ctx, passwordreset.BeginResetRequest{
		Identifier: "alice@example.com", RequestID: "req-disabled"}); err != nil {
		t.Fatalf("开始找回: %v", err)
	}
	token := env.waitToken()
	if _, err := env.raw.DB().ExecContext(env.ctx,
		`UPDATE users SET status='disabled' WHERE id=?`, userID); err != nil {
		t.Fatalf("禁用账户: %v", err)
	}
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: token, NewPassword: "ResetSecret!9876", RequestID: "req-disabled-complete"}); !errors.Is(err, passwordreset.ErrAccountDisabled) {
		t.Fatalf("禁用账户找回错误 = %v，期望 ErrAccountDisabled", err)
	}
	if env.pass.resetCalls != 0 {
		t.Error("禁用账户不应调用密码重置")
	}
}

// TestNewRequestInvalidatesOldToken 验证新找回请求作废旧入口；主动改密也作废找回。
func TestNewRequestInvalidatesOldToken(t *testing.T) {
	env := newTestEnv(t, nil)
	env.now = time.Now().UTC()
	if _, err := env.service.BeginReset(env.ctx, passwordreset.BeginResetRequest{
		Identifier: "alice@example.com", RequestID: "req-old"}); err != nil {
		t.Fatalf("首个找回: %v", err)
	}
	oldToken := env.waitToken()
	if _, err := env.service.BeginReset(env.ctx, passwordreset.BeginResetRequest{
		Identifier: "alice@example.com", RequestID: "req-new"}); err != nil {
		t.Fatalf("新找回: %v", err)
	}
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: oldToken, NewPassword: "ResetSecret!9876", RequestID: "req-old-complete"}); !errors.Is(err, passwordreset.ErrTokenInvalid) {
		t.Fatalf("旧入口错误 = %v，期望 ErrTokenInvalid", err)
	}
	// 主动改密作废 pending 找回入口。
	if _, err := env.service.BeginReset(env.ctx, passwordreset.BeginResetRequest{
		Identifier: "alice@example.com", RequestID: "req-before-change"}); err != nil {
		t.Fatalf("改密前找回: %v", err)
	}
	pendingToken := env.waitToken()
	caller, err := passwordreset.UserCaller(userID)
	if err != nil {
		t.Fatalf("调用者: %v", err)
	}
	if _, err := env.service.ChangePassword(env.ctx, caller, passwordreset.ChangeRequest{
		CurrentPassword: "old", NewPassword: "NewSecret!12345", RequestID: "req-change-invalidate"}); err != nil {
		t.Fatalf("改密: %v", err)
	}
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: pendingToken, NewPassword: "ResetSecret!9876", RequestID: "req-after-change"}); !errors.Is(err, passwordreset.ErrTokenInvalid) {
		t.Fatalf("改密后旧找回入口错误 = %v，期望 ErrTokenInvalid", err)
	}
}

// TestBeginResetRateLimited 验证公开入口每邮箱限流（统一响应 + 失败审计）。
func TestBeginResetRateLimited(t *testing.T) {
	env := newTestEnv(t, func(options *passwordreset.Options) {
		options.RatePolicy = passwordreset.RatePolicy{Limit: 1, Window: time.Hour}
	})
	env.now = time.Now().UTC()
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := env.service.BeginReset(env.ctx, passwordreset.BeginResetRequest{
			Identifier: "alice@example.com", ClientIP: "203.0.113.9",
			RequestID: "req-rate"}); err != nil {
			t.Fatalf("限流公开响应不应报错: %v", err)
		}
	}
	if count := env.count(`SELECT COUNT(*) FROM password_reset_requests`); count != 1 {
		t.Errorf("限流后请求数 = %d，期望 1", count)
	}
	if count := env.count(`SELECT COUNT(*) FROM audit_events WHERE action='password.reset_requested' AND outcome='failure' AND reason_code='rate_limited'`); count < 1 {
		t.Error("限流缺少失败审计")
	}
}
