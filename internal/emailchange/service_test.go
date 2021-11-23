package emailchange_test

import (
	"context"
	"errors"
	"net/url"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/credential"
	credentialsqlite "github.com/kagurazakayashi/EvernightLogin/internal/credential/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/emailchange"
	emailchangesqlite "github.com/kagurazakayashi/EvernightLogin/internal/emailchange/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

var testStart = time.Date(2026, 11, 16, 14, 0, 0, 0, time.UTC)

type captureMail struct {
	mu       sync.Mutex
	verifies []emailchange.VerificationEmail
	notices  []emailchange.SecurityNoticeEmail
	fail     bool
}

func (m *captureMail) SendVerification(_ context.Context, message emailchange.VerificationEmail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return errors.New("注入发送失败")
	}
	m.verifies = append(m.verifies, message)
	return nil
}

func (m *captureMail) SendSecurityNotice(_ context.Context, message emailchange.SecurityNoticeEmail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return errors.New("注入发送失败")
	}
	m.notices = append(m.notices, message)
	return nil
}

func (m *captureMail) lastVerify(t *testing.T) emailchange.VerificationEmail {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.verifies) == 0 {
		t.Fatal("未捕获验证邮件")
	}
	return m.verifies[len(m.verifies)-1]
}

type testEnv struct {
	t       *testing.T
	ctx     context.Context
	storage *storagesqlite.Store
	service *emailchange.Service
	mail    *captureMail
	now     time.Time
}

func newTestEnv(t *testing.T, withReauth bool, mutations ...func(*emailchange.Options)) *testEnv {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(testutil.TempDir(t), "emailchange-test.db")
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
	recorder, err := audit.New(auditStore, audit.Options{Now: func() time.Time { return testStart }})
	if err != nil {
		t.Fatalf("审计: %v", err)
	}
	keyring, err := secrets.GenerateKeyring("k1", testStart)
	if err != nil {
		t.Fatalf("密钥环: %v", err)
	}
	credentialStore, err := credentialsqlite.New(storage)
	if err != nil {
		t.Fatalf("凭证存储: %v", err)
	}
	env := &testEnv{t: t, ctx: ctx, storage: storage, mail: &captureMail{}, now: testStart}
	credentialService, err := credential.New(credentialStore, credential.Options{
		Keyring: keyring, Now: func() time.Time { return env.now },
	})
	if err != nil {
		t.Fatalf("凭证服务: %v", err)
	}
	store, err := emailchangesqlite.New(storage)
	if err != nil {
		t.Fatalf("变更存储: %v", err)
	}
	options := emailchange.Options{AllowLegacyWithoutSensitive: true,
		Store: store, Audit: recorder, Credentials: credentialService, Mailer: env.mail,
		VerificationURLBase: "https://login.example.test/email-change",
		SupportURL:          "https://login.example.test/support",
		AppName:             "EvernightLogin",
		TTL:                 5 * time.Minute,
		Now:                 func() time.Time { return env.now },
	}
	if withReauth {
		options.ReauthVerifier = emailchange.ReauthVerifierFunc(func(context.Context, emailchange.Caller, string) error { return nil })
	}
	for _, mutation := range mutations {
		mutation(&options)
	}
	service, err := emailchange.New(options)
	if err != nil {
		t.Fatalf("变更服务: %v", err)
	}
	env.service = service
	return env
}

func (e *testEnv) seedUser(t *testing.T, id, username string) {
	t.Helper()
	now := testStart.UnixMilli()
	if _, err := e.storage.DB().ExecContext(e.ctx, `INSERT INTO users(
id,username,username_normalized,nickname,biography,avatar_ref,language,timezone,status,is_root,
security_version,row_version,created_at_ms,updated_at_ms
) VALUES(?,?,?,'','',NULL,'zh-CN','Asia/Shanghai','active',0,1,1,?,?)`,
		id, username, username, now, now); err != nil {
		t.Fatalf("用户: %v", err)
	}
}

func (e *testEnv) seedEmail(t *testing.T, userID, email string) {
	t.Helper()
	now := testStart.UnixMilli()
	if _, err := e.storage.DB().ExecContext(e.ctx, `INSERT INTO user_emails(
email_normalized,user_id,email,verified_at_ms,created_at_ms,updated_at_ms
) VALUES(?,?,?,?,?,?)`, email, userID, email, now, now, now); err != nil {
		t.Fatalf("邮箱: %v", err)
	}
}

func (e *testEnv) caller(t *testing.T, id string) emailchange.Caller {
	t.Helper()
	caller, err := emailchange.UserCaller(id)
	if err != nil {
		t.Fatalf("用户调用者: %v", err)
	}
	return caller
}

func (e *testEnv) count(query string, args ...any) int {
	e.t.Helper()
	var value int
	if err := e.storage.DB().QueryRowContext(e.ctx, query, args...).Scan(&value); err != nil {
		e.t.Fatalf("计数: %v", err)
	}
	return value
}

func linkParts(t *testing.T, message emailchange.VerificationEmail) (string, string, string) {
	t.Helper()
	parsed, err := url.Parse(message.VerificationURL)
	if err != nil {
		t.Fatalf("验证链接: %v", err)
	}
	return parsed.Query().Get("rid"), parsed.Query().Get("cid"), parsed.Query().Get("token")
}

// TestFirstAddEmail 验证无旧邮箱的首次添加流程与旧邮箱告知跳过。
func TestFirstAddEmail(t *testing.T) {
	env := newTestEnv(t, true)
	const userID = "usr_00000000000000000000000000000001"
	env.seedUser(t, userID, "firstadd")
	result, err := env.service.RequestChange(env.ctx, env.caller(t, userID), "new@example.test", "req-1")
	if err != nil {
		t.Fatalf("首次添加申请: %v", err)
	}
	if !result.VerificationSent || result.Request.Status != emailchange.StatusPending {
		t.Fatalf("申请结果 = %+v", result)
	}
	if result.Request.OldEmail != "" {
		t.Errorf("首次添加不应有旧邮箱: %+v", result.Request)
	}
	rid, cid, token := linkParts(t, env.mail.lastVerify(t))
	verified, err := env.service.Verify(env.ctx, emailchange.VerifyRequest{RequestID: rid, CredentialID: cid, Token: token})
	if err != nil {
		t.Fatalf("验证新地址: %v", err)
	}
	if verified.Notified || verified.OldEmail != "" {
		t.Errorf("首次添加没有旧邮箱，告知应跳过: %+v", verified)
	}
	if got := env.count(`SELECT COUNT(*) FROM email_change_requests WHERE id=? AND notify_state='skipped'`, rid); got != 1 {
		t.Errorf("首次添加告知状态应为 skipped，实际 %d", got)
	}
	if got := env.count(`SELECT COUNT(*) FROM user_emails WHERE user_id=? AND email_normalized='new@example.test' AND verified_at_ms IS NOT NULL`, userID); got != 1 {
		t.Errorf("新地址应写入已验证行，实际 %d", got)
	}
}

// TestNormalChangeKeepsOldUntilVerifyAndNotifiesOld 验证旧地址保留到验证成功、切换后
// 删除旧行、向旧邮箱发送不含敏感凭证的告知。
func TestNormalChangeKeepsOldUntilVerifyAndNotifiesOld(t *testing.T) {
	env := newTestEnv(t, true)
	const userID = "usr_00000000000000000000000000000002"
	env.seedUser(t, userID, "normalchange")
	env.seedEmail(t, userID, "old@example.test")
	result, err := env.service.RequestChange(env.ctx, env.caller(t, userID), "New@Example.TEST", "req-2")
	if err != nil {
		t.Fatalf("申请变更: %v", err)
	}
	if result.Request.OldEmail != "old@example.test" {
		t.Errorf("绑定旧邮箱 = %q", result.Request.OldEmail)
	}
	// 验证前旧地址与原验证状态保留，新地址不存在。
	if got := env.count(`SELECT COUNT(*) FROM user_emails WHERE user_id=? AND email_normalized='old@example.test' AND verified_at_ms IS NOT NULL`, userID); got != 1 {
		t.Errorf("验证前旧邮箱应保留，实际 %d", got)
	}
	if got := env.count(`SELECT COUNT(*) FROM user_emails WHERE email_normalized='new@example.test'`); got != 0 {
		t.Errorf("验证前新邮箱不应存在，实际 %d", got)
	}
	rid, cid, token := linkParts(t, env.mail.lastVerify(t))
	verified, err := env.service.Verify(env.ctx, emailchange.VerifyRequest{RequestID: rid, CredentialID: cid, Token: token})
	if err != nil {
		t.Fatalf("验证切换: %v", err)
	}
	if !verified.Notified {
		t.Errorf("应向旧邮箱发送告知: %+v", verified)
	}
	if got := env.count(`SELECT COUNT(*) FROM user_emails WHERE user_id=? AND email_normalized='old@example.test'`, userID); got != 0 {
		t.Errorf("切换后旧邮箱行应移除，实际 %d", got)
	}
	if got := env.count(`SELECT COUNT(*) FROM user_emails WHERE user_id=? AND email_normalized='new@example.test' AND verified_at_ms IS NOT NULL`, userID); got != 1 {
		t.Errorf("切换后新邮箱应已验证，实际 %d", got)
	}
	env.mail.mu.Lock()
	notices := append([]emailchange.SecurityNoticeEmail(nil), env.mail.notices...)
	env.mail.mu.Unlock()
	if len(notices) != 1 || notices[0].Recipient != "old@example.test" {
		t.Fatalf("旧邮箱告知 = %+v", notices)
	}
	// 告知不含校验链接/令牌字段（结构体本身没有 URL/token 字段，这里做内容断言）。
	if notices[0].Event == "" || notices[0].OccurredAt == "" {
		t.Errorf("告知字段不完整: %+v", notices[0])
	}
	// 重复点击：令牌已消费，统一失效。
	if _, err := env.service.Verify(env.ctx, emailchange.VerifyRequest{RequestID: rid, CredentialID: cid, Token: token}); !errors.Is(err, emailchange.ErrRequestNotFound) {
		t.Fatalf("重复验证应失败，实际 %v", err)
	}
}

// TestReauthMissingAndConflict 验证缺少再次验证时拒绝，以及新邮箱被占用。
func TestReauthMissingAndConflict(t *testing.T) {
	noReauth := newTestEnv(t, false)
	const userID = "usr_00000000000000000000000000000003"
	noReauth.seedUser(t, userID, "noreauth")
	if _, err := noReauth.service.RequestChange(noReauth.ctx, noReauth.caller(t, userID), "x@example.test", ""); !errors.Is(err, emailchange.ErrReauthRequired) {
		t.Fatalf("缺少再次验证应拒绝，实际 %v", err)
	}
	env := newTestEnv(t, true)
	const otherID = "usr_00000000000000000000000000000004"
	env.seedUser(t, userID, "conflict")
	env.seedUser(t, otherID, "other")
	env.seedEmail(t, otherID, "taken@example.test")
	if _, err := env.service.RequestChange(env.ctx, env.caller(t, userID), "taken@example.test", ""); !errors.Is(err, emailchange.ErrInvalidRequest) {
		t.Fatalf("已占用新邮箱应冲突，实际 %v", err)
	}
}

// TestConcurrentRequestsAndCancel 验证并发申请只保留一个 pending、旧链接失效、取消后
// 不可验证。
func TestConcurrentRequestsAndCancel(t *testing.T) {
	env := newTestEnv(t, true)
	const userID = "usr_00000000000000000000000000000005"
	env.seedUser(t, userID, "concurrent")
	caller := env.caller(t, userID)
	var wg sync.WaitGroup
	for index := 0; index < 2; index++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _ = env.service.RequestChange(env.ctx, caller, "concurrent"+string(rune('a'+i))+"@example.test", "")
		}(index)
	}
	wg.Wait()
	if got := env.count(`SELECT COUNT(*) FROM email_change_requests WHERE user_id=? AND status='pending'`, userID); got != 1 {
		t.Fatalf("并发申请后应只有 1 条 pending，实际 %d", got)
	}
	// 取消当前 pending 后不可验证。
	env.mail.mu.Lock()
	latest := env.mail.verifies[len(env.mail.verifies)-1]
	env.mail.mu.Unlock()
	rid, cid, token := linkParts(t, latest)
	if err := env.service.Cancel(env.ctx, caller, emailchange.CancelRequest{RequestID: rid}); err != nil {
		t.Fatalf("取消申请: %v", err)
	}
	if _, err := env.service.Verify(env.ctx, emailchange.VerifyRequest{RequestID: rid, CredentialID: cid, Token: token}); !errors.Is(err, emailchange.ErrRequestNotFound) {
		t.Fatalf("取消后验证应失败，实际 %v", err)
	}
}

// TestExpiredRequest 验证过期申请不可切换。
func TestExpiredRequest(t *testing.T) {
	env := newTestEnv(t, true)
	const userID = "usr_00000000000000000000000000000006"
	env.seedUser(t, userID, "expired")
	env.seedEmail(t, userID, "old.expired@example.test")
	if _, err := env.service.RequestChange(env.ctx, env.caller(t, userID), "new.expired@example.test", ""); err != nil {
		t.Fatalf("申请: %v", err)
	}
	rid, cid, token := linkParts(t, env.mail.lastVerify(t))
	env.now = env.now.Add(10 * time.Minute)
	if _, err := env.service.Verify(env.ctx, emailchange.VerifyRequest{RequestID: rid, CredentialID: cid, Token: token}); !errors.Is(err, emailchange.ErrRequestNotFound) {
		t.Fatalf("过期验证应失败，实际 %v", err)
	}
	if got := env.count(`SELECT COUNT(*) FROM user_emails WHERE user_id=? AND email_normalized='old.expired@example.test' AND verified_at_ms IS NOT NULL`, userID); got != 1 {
		t.Errorf("过期后旧邮箱应保留，实际 %d", got)
	}
}

// TestAuditRedactionAndInvalidEmail 验证审计不含令牌/完整邮箱，非法新邮箱被拒绝。
func TestAuditRedactionAndInvalidEmail(t *testing.T) {
	env := newTestEnv(t, true)
	const userID = "usr_00000000000000000000000000000007"
	env.seedUser(t, userID, "auditredact")
	env.seedEmail(t, userID, "aurora@example.test")
	if _, err := env.service.RequestChange(env.ctx, env.caller(t, userID), "not-an-email", ""); err == nil {
		t.Fatal("非法新邮箱应被拒绝")
	}
	result, err := env.service.RequestChange(env.ctx, env.caller(t, userID), "new.audit@example.test", "")
	if err != nil {
		t.Fatalf("申请: %v", err)
	}
	_ = result
	rid, cid, token := linkParts(t, env.mail.lastVerify(t))
	if _, err := env.service.Verify(env.ctx, emailchange.VerifyRequest{RequestID: rid, CredentialID: cid, Token: token}); err != nil {
		t.Fatalf("验证: %v", err)
	}
	if got := env.count(`SELECT COUNT(*) FROM audit_events WHERE detail_json LIKE ?`, "%"+token+"%"); got != 0 {
		t.Errorf("审计不应包含验证令牌，实际 %d", got)
	}
	if got := env.count(`SELECT COUNT(*) FROM audit_events WHERE detail_json LIKE '%aurora@example.test%'`); got != 0 {
		t.Errorf("审计不应包含完整旧邮箱，实际 %d", got)
	}
	if got := env.count(`SELECT COUNT(*) FROM audit_events WHERE action IN('email.change.request','email.change.verify')`); got == 0 {
		t.Error("应写入邮箱变更审计")
	}
}

// TestDisabledAccountCannotVerify 验证禁用账户不能完成切换且库不变。
func TestDisabledAccountCannotVerify(t *testing.T) {
	env := newTestEnv(t, true)
	const userID = "usr_00000000000000000000000000000008"
	env.seedUser(t, userID, "disabledchange")
	env.seedEmail(t, userID, "old.disabled@example.test")
	if _, err := env.service.RequestChange(env.ctx, env.caller(t, userID), "new.disabled@example.test", ""); err != nil {
		t.Fatalf("申请: %v", err)
	}
	rid, cid, token := linkParts(t, env.mail.lastVerify(t))
	if _, err := env.storage.DB().ExecContext(env.ctx, `UPDATE users SET status='disabled' WHERE id=?`, userID); err != nil {
		t.Fatalf("禁用账户: %v", err)
	}
	if _, err := env.service.Verify(env.ctx, emailchange.VerifyRequest{RequestID: rid, CredentialID: cid, Token: token}); !errors.Is(err, emailchange.ErrAccessDenied) {
		t.Fatalf("禁用账户验证应被拒绝，实际 %v", err)
	}
	if got := env.count(`SELECT COUNT(*) FROM user_emails WHERE user_id=? AND email_normalized='old.disabled@example.test' AND verified_at_ms IS NOT NULL`, userID); got != 1 {
		t.Errorf("禁用账户失败后旧邮箱应保留，实际 %d", got)
	}
	if got := env.count(`SELECT COUNT(*) FROM email_change_requests WHERE id=? AND status='pending'`, rid); got != 1 {
		t.Errorf("失败后申请应保持 pending，实际 %d", got)
	}
}

// TestVerifyOccupiedRollbackAndRetry 验证切换时新邮箱被占用整体回滚并返回补偿令牌，
// 释放占用后可用补偿令牌重试成功。
func TestVerifyOccupiedRollbackAndRetry(t *testing.T) {
	env := newTestEnv(t, true)
	const userID = "usr_00000000000000000000000000000009"
	const otherID = "usr_00000000000000000000000000000010"
	env.seedUser(t, userID, "occupied")
	env.seedUser(t, otherID, "occupier")
	env.seedEmail(t, userID, "old.occupied@example.test")
	if _, err := env.service.RequestChange(env.ctx, env.caller(t, userID), "race.occupied@example.test", ""); err != nil {
		t.Fatalf("申请: %v", err)
	}
	rid, cid, token := linkParts(t, env.mail.lastVerify(t))
	// 申请后他人占用该新邮箱。
	env.seedEmail(t, otherID, "race.occupied@example.test")
	retried, err := env.service.Verify(env.ctx, emailchange.VerifyRequest{RequestID: rid, CredentialID: cid, Token: token})
	if !errors.Is(err, emailchange.ErrEmailInUse) {
		t.Fatalf("新邮箱被占用应 CONFLICT，实际 %v", err)
	}
	if retried.RetryCredentialID == "" || retried.RetryToken == "" || retried.RetryURL == "" {
		t.Fatalf("事务失败应返回补偿令牌: %+v", retried)
	}
	// 整体回滚：旧邮箱保留、新邮箱未写入。
	if got := env.count(`SELECT COUNT(*) FROM user_emails WHERE user_id=? AND email_normalized='old.occupied@example.test' AND verified_at_ms IS NOT NULL`, userID); got != 1 {
		t.Errorf("失败后旧邮箱应保留，实际 %d", got)
	}
	if got := env.count(`SELECT COUNT(*) FROM user_emails WHERE user_id=? AND email_normalized='race.occupied@example.test'`, userID); got != 0 {
		t.Errorf("失败后不应写入新邮箱，实际 %d", got)
	}
	// 释放占用后用补偿令牌完成同一申请。
	if _, err := env.storage.DB().ExecContext(env.ctx, `DELETE FROM user_emails WHERE email_normalized='race.occupied@example.test'`); err != nil {
		t.Fatalf("释放占用: %v", err)
	}
	if _, err := env.service.Verify(env.ctx, emailchange.VerifyRequest{RequestID: rid,
		CredentialID: retried.RetryCredentialID, Token: retried.RetryToken}); err != nil {
		t.Fatalf("补偿令牌重试失败: %v", err)
	}
	if got := env.count(`SELECT COUNT(*) FROM user_emails WHERE user_id=? AND email_normalized='race.occupied@example.test' AND verified_at_ms IS NOT NULL`, userID); got != 1 {
		t.Errorf("重试后新邮箱应已验证，实际 %d", got)
	}
}

// TestOldEmailVersionChangedAndNoticeFailure 验证申请后旧邮箱版本变化则拒绝切换；切换
// 成功但旧邮箱告知失败时只记录状态、不回滚。
func TestOldEmailVersionChangedAndNoticeFailure(t *testing.T) {
	env := newTestEnv(t, true)
	const userID = "usr_00000000000000000000000000000011"
	env.seedUser(t, userID, "versionchange")
	env.seedEmail(t, userID, "old.version@example.test")
	if _, err := env.service.RequestChange(env.ctx, env.caller(t, userID), "new.version@example.test", ""); err != nil {
		t.Fatalf("申请: %v", err)
	}
	rid, cid, token := linkParts(t, env.mail.lastVerify(t))
	// 旧邮箱在申请后被其他流程替换（版本变化）。
	if _, err := env.storage.DB().ExecContext(env.ctx, `UPDATE user_emails SET email_normalized='other.version@example.test',
email='other.version@example.test' WHERE user_id=? AND verified_at_ms IS NOT NULL`, userID); err != nil {
		t.Fatalf("变更旧邮箱版本: %v", err)
	}
	if _, err := env.service.Verify(env.ctx, emailchange.VerifyRequest{RequestID: rid, CredentialID: cid, Token: token}); !errors.Is(err, emailchange.ErrRequestNotFound) {
		t.Fatalf("旧邮箱版本变化应拒绝切换，实际 %v", err)
	}
	// 新申请 + 告知失败：切换仍成功，notify_state=failed 可追踪。
	if _, err := env.storage.DB().ExecContext(env.ctx, `UPDATE email_change_requests SET status='cancelled' WHERE user_id=? AND status='pending'`, userID); err != nil {
		t.Fatalf("清理旧申请: %v", err)
	}
	result, err := env.service.RequestChange(env.ctx, env.caller(t, userID), "new2.version@example.test", "")
	if err != nil {
		t.Fatalf("第二次申请: %v", err)
	}
	rid2, cid2, token2 := linkParts(t, env.mail.lastVerify(t))
	env.mail.fail = true
	verified, err := env.service.Verify(env.ctx, emailchange.VerifyRequest{RequestID: rid2, CredentialID: cid2, Token: token2})
	if err != nil {
		t.Fatalf("告知失败不应导致切换回滚: %v", err)
	}
	if verified.Notified || verified.ErrorCode != string(emailchange.CodeMailDeliveryFailed) {
		t.Errorf("告知失败应可追踪: %+v", verified)
	}
	if got := env.count(`SELECT COUNT(*) FROM user_emails WHERE user_id=? AND email_normalized='new2.version@example.test' AND verified_at_ms IS NOT NULL`, userID); got != 1 {
		t.Errorf("切换应已生效，实际 %d", got)
	}
	if got := env.count(`SELECT COUNT(*) FROM email_change_requests WHERE id=? AND notify_state='failed'`, rid2); got != 1 {
		t.Errorf("告知状态应为 failed，实际 %d", got)
	}
	_ = result
}

// TestUnverifiedSameAddressRowCleaned 验证同用户同地址未验证行不会误报 CONFLICT。
func TestUnverifiedSameAddressRowCleaned(t *testing.T) {
	env := newTestEnv(t, true)
	const userID = "usr_00000000000000000000000000000012"
	env.seedUser(t, userID, "unverifiedrow")
	now := testStart.UnixMilli()
	if _, err := env.storage.DB().ExecContext(env.ctx, `INSERT INTO user_emails(
email_normalized,user_id,email,verified_at_ms,created_at_ms,updated_at_ms
) VALUES('same.pending@example.test',?,'same.pending@example.test',NULL,?,?)`, userID, now, now); err != nil {
		t.Fatalf("预置未验证行: %v", err)
	}
	if _, err := env.service.RequestChange(env.ctx, env.caller(t, userID), "same.pending@example.test", ""); err != nil {
		t.Fatalf("申请: %v", err)
	}
	rid, cid, token := linkParts(t, env.mail.lastVerify(t))
	if _, err := env.service.Verify(env.ctx, emailchange.VerifyRequest{RequestID: rid, CredentialID: cid, Token: token}); err != nil {
		t.Fatalf("验证应清理未验证行并成功: %v", err)
	}
	if got := env.count(`SELECT COUNT(*) FROM user_emails WHERE user_id=? AND email_normalized='same.pending@example.test' AND verified_at_ms IS NOT NULL`, userID); got != 1 {
		t.Errorf("应只有一条已验证行，实际 %d", got)
	}
}
