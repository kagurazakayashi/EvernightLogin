package registration_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
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
	"github.com/kagurazakayashi/EvernightLogin/internal/credential"
	credentialsqlite "github.com/kagurazakayashi/EvernightLogin/internal/credential/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	mailersqlite "github.com/kagurazakayashi/EvernightLogin/internal/mailer/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailtest"
	"github.com/kagurazakayashi/EvernightLogin/internal/registration"
	registrationsqlite "github.com/kagurazakayashi/EvernightLogin/internal/registration/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
	tasksqlite "github.com/kagurazakayashi/EvernightLogin/internal/task/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const (
	testPassword        = "correct-horse-battery-9"
	testVerificationURL = "https://login.example.test/verify-email"
)

var testStart = time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)

// captureMailer 捕获验证邮件；可注入发送失败。
type captureMailer struct {
	mu       sync.Mutex
	messages []registration.EmailMessage
	fail     bool
	log      *bytes.Buffer
}

func (m *captureMailer) SendEmailVerification(_ context.Context, message registration.EmailMessage) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return errors.New("注入的邮件发送失败")
	}
	m.messages = append(m.messages, message)
	return nil
}

func (m *captureMailer) last(t *testing.T) registration.EmailMessage {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.messages) == 0 {
		t.Fatal("没有捕获到验证邮件")
	}
	return m.messages[len(m.messages)-1]
}

// failingAudit 模拟审计不可用，用于验证 fail-closed。
type failingAudit struct{}

func (failingAudit) Record(context.Context, audit.Event) error { return audit.ErrAuditUnavailable }
func (failingAudit) RecordFailure(context.Context, audit.Event) error {
	return audit.ErrAuditUnavailable
}
func (failingAudit) ExecuteCritical(context.Context, audit.CriticalRequest, audit.Change) error {
	return fmt.Errorf("%w: 注入的审计失败", audit.ErrAuditUnavailable)
}

type testEnv struct {
	t       *testing.T
	ctx     context.Context
	storage *storagesqlite.Store
	reg     *registration.Service
	creds   *credential.Service
	mail    *captureMailer
	audit   *audit.Recorder
	authn   *authn.Service
	now     time.Time
	logBuf  *bytes.Buffer
}

// newTestEnv 使用临时 SQLite、真实迁移与真实审计/凭证/认证服务构造注册服务。
func newTestEnv(t *testing.T, mutate func(*registration.Options)) *testEnv {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(testutil.TempDir(t), "login-registration-test.db")
	storage, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(path))
	if err != nil {
		t.Fatalf("打开临时数据库: %v", err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	migrationList, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移: %v", err)
	}
	if _, err := storage.Migrate(ctx, migrationList); err != nil {
		t.Fatalf("执行迁移: %v", err)
	}
	// env 在服务构造前声明，使注入时钟闭包共享同一 testEnv；服务构造过程不会
	// 调用时钟，因此赋值前不会被解引用。
	var env *testEnv
	auditStore, err := auditsqlite.New(storage)
	if err != nil {
		t.Fatalf("审计存储: %v", err)
	}
	recorder, err := audit.New(auditStore, audit.Options{Now: func() time.Time { return testStart }})
	if err != nil {
		t.Fatalf("审计写入器: %v", err)
	}
	keyring, err := secrets.GenerateKeyring("k1", testStart)
	if err != nil {
		t.Fatalf("生成密钥环: %v", err)
	}
	credentialStore, err := credentialsqlite.New(storage)
	if err != nil {
		t.Fatalf("凭证存储: %v", err)
	}
	credentialService, err := credential.New(credentialStore, credential.Options{
		Keyring: keyring,
		Now:     func() time.Time { return envNow(env) },
	})
	if err != nil {
		t.Fatalf("凭证服务: %v", err)
	}
	registrationStore, err := registrationsqlite.New(storage)
	if err != nil {
		t.Fatalf("注册存储: %v", err)
	}
	bootstrapStore, err := bootstrapsqlite.New(storage)
	if err != nil {
		t.Fatalf("初始化存储: %v", err)
	}
	authnStore, err := authnsqlite.New(storage)
	if err != nil {
		t.Fatalf("认证存储: %v", err)
	}
	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	authnService, err := authn.New(authn.Options{
		Store:              authnStore,
		Audit:              recorder,
		RootInitialization: bootstrapStore,
		EmailLoginEnabled:  true,
		Now:                func() time.Time { return envNow(env) },
		Logger:             logger,
		Sleep:              func(context.Context, time.Duration) error { return nil },
	})
	if err != nil {
		t.Fatalf("认证服务: %v", err)
	}
	mail := &captureMailer{log: logBuf}
	env = &testEnv{
		t:       t,
		ctx:     ctx,
		storage: storage,
		creds:   credentialService,
		mail:    mail,
		audit:   recorder,
		authn:   authnService,
		now:     testStart,
		logBuf:  logBuf,
	}
	options := registration.Options{
		Store:               registrationStore,
		Audit:               recorder,
		Credentials:         credentialService,
		Mailer:              mail,
		VerificationURLBase: testVerificationURL,
		Enabled:             true,
		VerificationTTL:     time.Hour,
		ResendCooldown:      time.Minute,
		AppName:             "EvernightLogin",
		Now:                 func() time.Time { return envNow(env) },
		Logger:              logger,
	}
	if mutate != nil {
		mutate(&options)
	}
	service, err := registration.New(options)
	if err != nil {
		t.Fatalf("注册服务: %v", err)
	}
	env.reg = service
	return env
}

// envNow 返回注入时钟的当前值。
func envNow(env *testEnv) time.Time { return env.now }

// advance 前进注入时钟。
func (e *testEnv) advance(d time.Duration) { e.now = e.now.Add(d) }

// count 读取单值计数。
func (e *testEnv) count(query string, args ...any) int {
	e.t.Helper()
	var value int
	if err := e.storage.DB().QueryRowContext(e.ctx, query, args...).Scan(&value); err != nil {
		e.t.Fatalf("查询计数失败: %v", err)
	}
	return value
}

// register 用默认密码注册并返回结果。
func (e *testEnv) register(request registration.RegisterRequest) (registration.RegisterResult, error) {
	e.t.Helper()
	if request.Password == "" {
		request.Password = testPassword
	}
	return e.reg.Register(e.ctx, request)
}

// mustRegister 注册并断言成功。
func (e *testEnv) mustRegister(request registration.RegisterRequest) registration.RegisterResult {
	e.t.Helper()
	result, err := e.register(request)
	if err != nil {
		e.t.Fatalf("注册失败: %v", err)
	}
	return result
}

// link 解析捕获邮件中的验证入口参数。
func (e *testEnv) link(t *testing.T) (registration.VerifyEmailRequest, *url.URL) {
	t.Helper()
	message := e.mail.last(t)
	parsed, err := url.Parse(message.VerificationURL)
	if err != nil {
		t.Fatalf("验证入口 URL 非法: %v", err)
	}
	query := parsed.Query()
	return registration.VerifyEmailRequest{
		UserID:       query.Get("uid"),
		CredentialID: query.Get("cid"),
		Token:        query.Get("token"),
	}, parsed
}

// authenticate 调用真实认证服务。
func (e *testEnv) authenticate(identifier string) (authn.AuthenticateResult, error) {
	return e.authn.Authenticate(e.ctx, authn.AuthenticateRequest{
		Identifier: identifier,
		Password:   testPassword,
		ClientIP:   "203.0.113.40",
	})
}

// insertSystemRole 插入一个已启用的系统角色。
func (e *testEnv) insertSystemRole(t *testing.T, roleID string, enabled bool) {
	t.Helper()
	value := 0
	if enabled {
		value = 1
	}
	if _, err := e.storage.DB().ExecContext(e.ctx, `INSERT INTO roles(
id,scope_id,role_key,name,description,limits_text,is_builtin,enabled,created_at_ms,updated_at_ms
) VALUES(?, 'system', ?, ?, '', '', 0, ?, ?, ?)`,
		roleID, roleID, roleID, value, testStart.UnixMilli(), testStart.UnixMilli()); err != nil {
		t.Fatalf("插入系统角色失败: %v", err)
	}
}

// TestParseRegisterJSONWhitelist 验证注册 JSON 只接受白名单字段：客户端提交
// is_root、系统角色、已验证邮箱或应用成员等恶意字段一律拒绝。
func TestParseRegisterJSONWhitelist(t *testing.T) {
	valid := []byte(`{"username":"alice","password":"correct-horse-battery-9","email":"a@example.test","nickname":"A","language":"zh-CN","timezone":"Asia/Shanghai"}`)
	request, err := registration.ParseRegisterJSON(valid)
	if err != nil {
		t.Fatalf("合法注册 JSON 解析失败: %v", err)
	}
	if request.Username != "alice" || request.Email != "a@example.test" {
		t.Errorf("解析结果不正确: %+v", request)
	}
	malicious := []string{
		`{"username":"alice","password":"correct-horse-battery-9","is_root":true}`,
		`{"username":"alice","password":"correct-horse-battery-9","roles":["system_admin"]}`,
		`{"username":"alice","password":"correct-horse-battery-9","email_verified":true}`,
		`{"username":"alice","password":"correct-horse-battery-9","app_memberships":[{"app_id":"app_x"}]}`,
		`{"username":"alice","password":"correct-horse-battery-9","status":"active"}`,
	}
	for _, payload := range malicious {
		if _, err := registration.ParseRegisterJSON([]byte(payload)); !errors.Is(err, registration.ErrInvalidRequest) {
			t.Errorf("恶意字段应被拒绝 %s，实际错误 %v", payload, err)
		}
	}
	if _, err := registration.ParseRegisterJSON([]byte(`{"username":"a"} {"username":"b"}`)); err == nil {
		t.Error("多个 JSON 对象应被拒绝")
	}
	if _, err := registration.ParseRegisterJSON(make([]byte, registration.MaxRegisterJSONBytes+1)); err == nil {
		t.Error("超大请求体应被拒绝")
	}
}

// TestRegisterDisabled 验证自主注册关闭时拒绝且不写入用户；管理员创建路径不受
// 影响（internal/account 独立，本测试只断言注册关闭没有副作用）。
func TestRegisterDisabled(t *testing.T) {
	env := newTestEnv(t, func(options *registration.Options) { options.Enabled = false })
	if _, err := env.register(registration.RegisterRequest{Username: "alice"}); !errors.Is(err, registration.ErrRegistrationClosed) {
		t.Fatalf("注册关闭时错误 = %v，期望 ErrRegistrationClosed", err)
	}
	if got := env.count(`SELECT COUNT(*) FROM users`); got != 0 {
		t.Fatalf("注册关闭不应创建用户，实际 %d", got)
	}
}

// TestRegisterWithoutEmailAndPasswordLogin 验证无邮箱注册不被无条件拒绝、账户
// 为 active、未写入邮箱行、未自动加入应用，并能通过真实 authn 完成密码登录。
func TestRegisterWithoutEmailAndPasswordLogin(t *testing.T) {
	env := newTestEnv(t, nil)
	result, err := env.register(registration.RegisterRequest{Username: "Alice.NoEmail", Nickname: "Alice"})
	if err != nil {
		t.Fatalf("无邮箱注册失败: %v", err)
	}
	if result.Status != account.StatusActive {
		t.Errorf("默认注册状态 = %q，期望 active", result.Status)
	}
	if result.VerificationSent || result.VerificationErrorCode != "" || !result.VerificationExpiresAt.IsZero() {
		t.Errorf("无邮箱注册的验证状态应为空: %+v", result)
	}
	if got := env.count(`SELECT COUNT(*) FROM users WHERE id=? AND status='active' AND is_root=0`,
		result.UserID); got != 1 {
		t.Errorf("应创建 1 个 active 非 root 用户，实际 %d", got)
	}
	if got := env.count(`SELECT COUNT(*) FROM password_credentials WHERE user_id=?`, result.UserID); got != 1 {
		t.Errorf("应写入 1 条密码凭证，实际 %d", got)
	}
	if got := env.count(`SELECT COUNT(*) FROM user_emails WHERE user_id=?`, result.UserID); got != 0 {
		t.Errorf("无邮箱注册不应写入邮箱行，实际 %d", got)
	}
	if got := env.count(`SELECT COUNT(*) FROM app_memberships WHERE user_id=?`, result.UserID); got != 0 {
		t.Errorf("注册不应自动加入应用，实际 %d", got)
	}
	authResult, err := env.authenticate("Alice.NoEmail")
	if err != nil {
		t.Fatalf("注册后密码登录失败: %v", err)
	}
	if authResult.Outcome != authn.OutcomeComplete || len(authResult.RequiredSteps) != 0 {
		t.Errorf("登录结果 = %+v，期望完整认证", authResult)
	}
}

// TestRegisterWithEmailVerification 验证提供邮箱时发送验证入口、验证成功后邮箱
// 才可用于登录、重复消费被拒绝，且令牌不写入审计与普通日志。
func TestRegisterWithEmailVerification(t *testing.T) {
	env := newTestEnv(t, nil)
	result, err := env.register(registration.RegisterRequest{
		Username: "verified.user",
		Email:    "Verified.User@Example.TEST",
	})
	if err != nil {
		t.Fatalf("邮箱注册失败: %v", err)
	}
	if !result.VerificationSent || result.VerificationErrorCode != "" || result.VerificationExpiresAt.IsZero() {
		t.Fatalf("应发送验证入口: %+v", result)
	}
	if got := env.count(`SELECT COUNT(*) FROM user_emails WHERE user_id=? AND verified_at_ms IS NULL`,
		result.UserID); got != 1 {
		t.Fatalf("注册后邮箱应保持未验证，实际 %d", got)
	}
	if got := env.count(`SELECT COUNT(*) FROM email_verification_tickets WHERE user_id=?`, result.UserID); got != 1 {
		t.Fatalf("应写入 1 条验证票据，实际 %d", got)
	}
	// 邮箱登录在验证前不可用。
	if _, err := env.authenticate("verified.user@example.test"); !errors.Is(err, authn.ErrAuthenticationFailed) {
		t.Fatalf("未验证邮箱登录应失败，实际 %v", err)
	}
	request, parsed := env.link(t)
	if parsed.Scheme != "https" || parsed.Path != "/verify-email" {
		t.Errorf("验证入口地址不正确: %s", parsed.String())
	}
	if request.UserID != result.UserID || !strings.HasPrefix(request.CredentialID, credential.CredentialIDPrefix) ||
		request.Token == "" {
		t.Fatalf("验证入口参数不完整: %+v", request)
	}
	// 令牌错误与用户绑定不匹配都统一拒绝，且不消耗正确入口。
	tampered := request
	tampered.Token = request.Token + "x"
	if _, err := env.reg.VerifyEmail(env.ctx, tampered); !errors.Is(err, registration.ErrVerificationInvalid) {
		t.Fatalf("错误令牌应被拒绝，实际 %v", err)
	}
	tampered = request
	tampered.UserID = "usr_00000000000000000000000000000088"
	if _, err := env.reg.VerifyEmail(env.ctx, tampered); !errors.Is(err, registration.ErrVerificationInvalid) {
		t.Fatalf("用户绑定不匹配应被拒绝，实际 %v", err)
	}
	verifyResult, err := env.reg.VerifyEmail(env.ctx, request)
	if err != nil {
		t.Fatalf("邮箱验证失败: %v", err)
	}
	if verifyResult.UserID != result.UserID || verifyResult.Email != "Verified.User@Example.TEST" {
		t.Errorf("验证结果 = %+v", verifyResult)
	}
	if got := env.count(`SELECT COUNT(*) FROM user_emails WHERE user_id=? AND verified_at_ms IS NOT NULL`,
		result.UserID); got != 1 {
		t.Errorf("验证后邮箱应为已验证，实际 %d", got)
	}
	if got := env.count(`SELECT COUNT(*) FROM email_verification_tickets WHERE user_id=?`, result.UserID); got != 0 {
		t.Errorf("验证后票据应删除，实际 %d", got)
	}
	if _, err := env.reg.VerifyEmail(env.ctx, request); !errors.Is(err, registration.ErrVerificationInvalid) {
		t.Errorf("重复消费应失败，实际 %v", err)
	}
	authResult, err := env.authenticate("verified.user@example.test")
	if err != nil {
		t.Fatalf("验证后邮箱登录失败: %v", err)
	}
	if authResult.UserID != result.UserID || authResult.Outcome != authn.OutcomeComplete {
		t.Errorf("邮箱登录结果 = %+v", authResult)
	}
	// 令牌只能出现在邮件链接中：不得进入审计明细与运行日志。
	auditText := env.auditDetailText()
	if strings.Contains(auditText, request.Token) {
		t.Error("审计明细不应包含验证令牌明文")
	}
	if strings.Contains(env.logBuf.String(), request.Token) {
		t.Error("运行日志不应包含验证令牌明文")
	}
	if got := env.count(`SELECT COUNT(*) FROM one_time_credentials WHERE id=? AND context_json LIKE ?`,
		request.CredentialID, "%"+request.Token+"%"); got != 0 {
		t.Errorf("凭证上下文不应包含令牌明文，实际 %d", got)
	}
}

// auditDetailText 汇总审计差异文本用于泄漏检查。
func (e *testEnv) auditDetailText() string {
	e.t.Helper()
	rows, err := e.storage.DB().QueryContext(e.ctx, `SELECT action || ' ' || detail_json FROM audit_events`)
	if err != nil {
		e.t.Fatalf("读取审计: %v", err)
	}
	defer rows.Close()
	var builder strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			e.t.Fatalf("扫描审计: %v", err)
		}
		builder.WriteString(line)
		builder.WriteString("\n")
	}
	return builder.String()
}

// TestResendAndReplaceEmailInvalidatesOldLink 验证重发冷却、重发使旧链接失效，
// 以及替换待验证邮箱后旧地址被移除、新地址验证成功。
func TestResendAndReplaceEmailInvalidatesOldLink(t *testing.T) {
	env := newTestEnv(t, nil)
	result, err := env.register(registration.RegisterRequest{Username: "resend.user", Email: "old@example.test"})
	if err != nil {
		t.Fatalf("注册失败: %v", err)
	}
	oldLink, _ := env.link(t)
	// 冷却期内重发被拒绝。
	caller, err := registration.SelfCaller(result.UserID)
	if err != nil {
		t.Fatalf("用户调用者: %v", err)
	}
	if _, err := env.reg.SendEmailVerification(env.ctx, caller,
		registration.SendVerificationRequest{UserID: result.UserID}); !errors.Is(err, registration.ErrResendTooSoon) {
		t.Fatalf("冷却期内重发应被拒绝，实际 %v", err)
	}
	// 另一个用户不能替目标账户触发重发。
	other, _ := registration.SelfCaller("usr_00000000000000000000000000000099")
	if _, err := env.reg.SendEmailVerification(env.ctx, other,
		registration.SendVerificationRequest{UserID: result.UserID}); !errors.Is(err, registration.ErrAccessDenied) {
		t.Fatalf("非本人重发应被拒绝，实际 %v", err)
	}
	env.advance(2 * time.Minute)
	replaced, err := env.reg.SendEmailVerification(env.ctx, caller, registration.SendVerificationRequest{
		UserID: result.UserID,
		Email:  "new@example.test",
	})
	if err != nil {
		t.Fatalf("替换待验证邮箱失败: %v", err)
	}
	if !replaced.Sent || replaced.Email != "new@example.test" {
		t.Fatalf("替换发送结果 = %+v", replaced)
	}
	// 旧链接失效：旧票据被覆盖、旧凭证被撤销。
	if _, err := env.reg.VerifyEmail(env.ctx, oldLink); !errors.Is(err, registration.ErrVerificationInvalid) {
		t.Fatalf("旧链接应失效，实际 %v", err)
	}
	newLink, _ := env.link(t)
	if newLink.CredentialID == oldLink.CredentialID {
		t.Fatal("重发应签发新的凭证 ID")
	}
	if _, err := env.reg.VerifyEmail(env.ctx, newLink); err != nil {
		t.Fatalf("新链接验证失败: %v", err)
	}
	if got := env.count(`SELECT COUNT(*) FROM user_emails WHERE user_id=? AND email_normalized='old@example.test'`,
		result.UserID); got != 0 {
		t.Errorf("旧地址应被移除，实际 %d", got)
	}
	if got := env.count(`SELECT COUNT(*) FROM user_emails WHERE user_id=? AND email_normalized='new@example.test' AND verified_at_ms IS NOT NULL`,
		result.UserID); got != 1 {
		t.Errorf("新地址应已验证，实际 %d", got)
	}
}

// TestMailFailureDoesNotClaimVerified 验证邮件发送失败时不宣称已验证、账户仍创建，
// 并可在冷却后重发成功。
func TestMailFailureDoesNotClaimVerified(t *testing.T) {
	env := newTestEnv(t, nil)
	env.mail.fail = true
	result, err := env.register(registration.RegisterRequest{Username: "mail.fail", Email: "fail@example.test"})
	if err != nil {
		t.Fatalf("邮件失败不应导致注册失败: %v", err)
	}
	if result.VerificationSent {
		t.Fatal("邮件失败时不应宣称验证入口已发送")
	}
	if result.VerificationErrorCode != string(registration.CodeMailDeliveryFailed) {
		t.Errorf("发送失败错误码 = %q，期望 %q", result.VerificationErrorCode, registration.CodeMailDeliveryFailed)
	}
	if got := env.count(`SELECT COUNT(*) FROM user_emails WHERE user_id=? AND verified_at_ms IS NULL`,
		result.UserID); got != 1 {
		t.Errorf("邮件失败后邮箱应仍未验证，实际 %d", got)
	}
	env.advance(2 * time.Minute)
	env.mail.fail = false
	caller, _ := registration.SelfCaller(result.UserID)
	resend, err := env.reg.SendEmailVerification(env.ctx, caller, registration.SendVerificationRequest{UserID: result.UserID})
	if err != nil {
		t.Fatalf("冷却后重发失败: %v", err)
	}
	if !resend.Sent {
		t.Fatalf("重发应成功: %+v", resend)
	}
	request, _ := env.link(t)
	if _, err := env.reg.VerifyEmail(env.ctx, request); err != nil {
		t.Fatalf("重发后验证失败: %v", err)
	}
}

// TestConcurrentDuplicateUsernameAndEmail 验证并发重名/重邮箱只允许一个成功，
// 另一个返回统一冲突错误（不区分具体字段）。
func TestConcurrentDuplicateUsernameAndEmail(t *testing.T) {
	env := newTestEnv(t, nil)
	t.Run("并发重名", func(t *testing.T) {
		var wg sync.WaitGroup
		results := make([]error, 2)
		for index := 0; index < 2; index++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_, err := env.reg.Register(env.ctx, registration.RegisterRequest{
					Username: "dup.user",
					Password: testPassword,
					Email:    fmt.Sprintf("dup%d@example.test", i),
				})
				results[i] = err
			}(index)
		}
		wg.Wait()
		successes, conflicts := 0, 0
		for _, err := range results {
			switch {
			case err == nil:
				successes++
			case errors.Is(err, registration.ErrRegistrationConflict):
				conflicts++
			default:
				t.Fatalf("并发重名错误 = %v", err)
			}
		}
		if successes != 1 || conflicts != 1 {
			t.Fatalf("并发重名结果 = 成功 %d 冲突 %d，期望 1/1", successes, conflicts)
		}
	})
	t.Run("并发重邮箱", func(t *testing.T) {
		var wg sync.WaitGroup
		results := make([]error, 2)
		for index := 0; index < 2; index++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_, err := env.reg.Register(env.ctx, registration.RegisterRequest{
					Username: fmt.Sprintf("same.mail.%d", i),
					Password: testPassword,
					Email:    "same@example.test",
				})
				results[i] = err
			}(index)
		}
		wg.Wait()
		successes, conflicts := 0, 0
		for _, err := range results {
			switch {
			case err == nil:
				successes++
			case errors.Is(err, registration.ErrRegistrationConflict):
				conflicts++
			default:
				t.Fatalf("并发重邮箱错误 = %v", err)
			}
		}
		if successes != 1 || conflicts != 1 {
			t.Fatalf("并发重邮箱结果 = 成功 %d 冲突 %d，期望 1/1", successes, conflicts)
		}
		if got := env.count(`SELECT COUNT(*) FROM user_emails WHERE email_normalized='same@example.test'`); got != 1 {
			t.Errorf("同一邮箱只应保留 1 行，实际 %d", got)
		}
	})
}

// TestRequireReviewBlocksLogin 验证需要审核时账户以 pending 创建，且真实认证
// 服务拒绝正常登录（不伪造成功）。
func TestRequireReviewBlocksLogin(t *testing.T) {
	env := newTestEnv(t, func(options *registration.Options) { options.RequireReview = true })
	result, err := env.register(registration.RegisterRequest{Username: "pending.user"})
	if err != nil {
		t.Fatalf("待审核注册失败: %v", err)
	}
	if result.Status != account.StatusPending {
		t.Errorf("注册状态 = %q，期望 pending", result.Status)
	}
	if _, err := env.authenticate("pending.user"); !errors.Is(err, authn.ErrAuthenticationFailed) {
		t.Fatalf("未审核用户不应能正常登录，实际错误 %v", err)
	}
	if got := env.count(`SELECT COUNT(*) FROM users WHERE id=? AND status='pending'`, result.UserID); got != 1 {
		t.Errorf("账户应保持 pending，实际 %d", got)
	}
}

// TestDefaultRolePolicy 验证默认角色来自可信策略且不会自动加入应用；无效默认
// 角色导致整体回滚。
func TestDefaultRolePolicy(t *testing.T) {
	env := newTestEnv(t, nil)
	env.insertSystemRole(t, "role_default_member", true)
	newService := func(t *testing.T, roles []registration.DefaultRole) *registration.Service {
		t.Helper()
		service, err := registration.New(registration.Options{
			Store:               newRegistrationStoreFor(t, env),
			Audit:               env.audit,
			Credentials:         env.creds,
			Enabled:             true,
			VerificationURLBase: testVerificationURL,
			Mailer:              &captureMailer{},
			DefaultRoles:        roles,
			Now:                 func() time.Time { return env.now },
		})
		if err != nil {
			t.Fatalf("构造注册服务: %v", err)
		}
		return service
	}
	validService := newService(t, []registration.DefaultRole{{RoleID: "role_default_member", ScopeID: "system"}})
	result, err := validService.Register(env.ctx, registration.RegisterRequest{
		Username: "role.user", Password: testPassword,
	})
	if err != nil {
		t.Fatalf("带默认角色注册失败: %v", err)
	}
	if got := env.count(`SELECT COUNT(*) FROM user_roles WHERE user_id=? AND role_id='role_default_member'`,
		result.UserID); got != 1 {
		t.Errorf("应分配 1 个默认角色，实际 %d", got)
	}
	if got := env.count(`SELECT COUNT(*) FROM app_memberships WHERE user_id=?`, result.UserID); got != 0 {
		t.Errorf("默认角色不应加入应用，实际 %d", got)
	}
	// 无效默认角色：整体回滚，不留下半创建用户。
	invalidService := newService(t, []registration.DefaultRole{{RoleID: "role_missing", ScopeID: "system"}})
	before := env.count(`SELECT COUNT(*) FROM users`)
	if _, err := invalidService.Register(env.ctx, registration.RegisterRequest{
		Username: "role.invalid", Password: testPassword,
	}); err == nil {
		t.Fatal("无效默认角色应导致注册失败")
	} else if errors.Is(err, registration.ErrRegistrationConflict) {
		t.Fatalf("无效默认角色错误不应伪装成冲突: %v", err)
	}
	if after := env.count(`SELECT COUNT(*) FROM users`); after != before {
		t.Errorf("无效默认角色不应创建用户，%d → %d", before, after)
	}
}

// TestAuditFailureFailsClosed 验证审计不可用时注册被拒绝且不创建用户。
func TestAuditFailureFailsClosed(t *testing.T) {
	env := newTestEnv(t, nil)
	failing, err := registration.New(registration.Options{
		Store:               newRegistrationStoreFor(t, env),
		Audit:               failingAudit{},
		Credentials:         env.creds,
		Enabled:             true,
		VerificationURLBase: testVerificationURL,
		Now:                 func() time.Time { return testStart },
	})
	if err != nil {
		t.Fatalf("构造失败审计注册服务: %v", err)
	}
	if _, err := failing.Register(env.ctx, registration.RegisterRequest{
		Username: "audit.fail", Password: testPassword,
	}); !errors.Is(err, registration.ErrAuditUnavailable) {
		t.Fatalf("审计失败时错误 = %v，期望 ErrAuditUnavailable", err)
	}
	if got := env.count(`SELECT COUNT(*) FROM users WHERE username_normalized='audit.fail'`); got != 0 {
		t.Errorf("审计失败不应创建用户，实际 %d", got)
	}
}

// TestEmailLoginDisabledByDefaultConfig 验证邮箱验证完成前/邮箱验证关闭时邮箱
// 不作为登录标识（authn 只在 EmailLoginEnabled 且已验证时匹配）。
func TestEmailLoginDisabledByDefaultConfig(t *testing.T) {
	env := newTestEnv(t, nil)
	result, err := env.register(registration.RegisterRequest{Username: "email.off", Email: "off@example.test"})
	if err != nil {
		t.Fatalf("注册失败: %v", err)
	}
	if _, err := env.authenticate("off@example.test"); !errors.Is(err, authn.ErrAuthenticationFailed) {
		t.Fatalf("未验证邮箱不应可用于登录，实际 %v", err)
	}
	request, _ := env.link(t)
	if _, err := env.reg.VerifyEmail(env.ctx, request); err != nil {
		t.Fatalf("验证失败: %v", err)
	}
	if authResult, err := env.authenticate("off@example.test"); err != nil || authResult.UserID != result.UserID {
		t.Fatalf("验证后邮箱应可登录，实际 %v %+v", err, authResult)
	}
}

// newRegistrationStoreFor 在同一数据库上构造注册存储。
func newRegistrationStoreFor(t *testing.T, env *testEnv) registration.Store {
	t.Helper()
	store, err := registrationsqlite.New(env.storage)
	if err != nil {
		t.Fatalf("注册存储: %v", err)
	}
	return store
}

// TestVerificationURLAndSenderOptions 验证验证入口地址与邮件适配器选项校验。
func TestVerificationURLAndSenderOptions(t *testing.T) {
	env := newTestEnv(t, nil)
	cases := []string{
		"",
		"ftp://login.example.test/verify",
		"https://",
		"https://user:pass@login.example.test/verify",
		"https://login.example.test/verify#fragment",
	}
	for _, raw := range cases {
		_, err := registration.New(registration.Options{
			Store:               newRegistrationStoreFor(t, env),
			Audit:               env.audit,
			Credentials:         env.creds,
			Mailer:              &captureMailer{},
			VerificationURLBase: raw,
			Enabled:             true,
		})
		if err == nil {
			t.Errorf("非法验证入口地址 %q 应被拒绝", raw)
		}
	}
	if _, err := registration.NewDeliveryEmailSender(nil, "Login"); err == nil {
		t.Error("空投递服务应被拒绝")
	}
	if _, err := registration.NewDeliveryEmailSender(&fakeEnqueuer{}, ""); err == nil {
		t.Error("空服务名应被拒绝")
	}
	// 要求邮箱验证但未配置邮件能力属于配置错误，必须在构造时 fail-closed。
	if _, err := registration.New(registration.Options{
		Store:                    newRegistrationStoreFor(t, env),
		Audit:                    env.audit,
		Credentials:              env.creds,
		RequireEmailVerification: true,
		Enabled:                  true,
	}); err == nil {
		t.Error("要求邮箱验证但未配置邮件能力应被拒绝")
	}
}

// fakeEnqueuer 捕获投递入队请求。
type fakeEnqueuer struct {
	mu       sync.Mutex
	requests []mailer.EnqueueRequest
}

func (f *fakeEnqueuer) Enqueue(_ context.Context, request mailer.EnqueueRequest) (mailer.EnqueueResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, request)
	return mailer.EnqueueResult{}, nil
}

// TestDeliveryEmailSenderEnqueuesVerification 验证生产适配器把一次性验证入口作为
// 验证模板数据入队，幂等键使用凭证 ID，且渲染后的正文包含入口链接与有效期。
func TestDeliveryEmailSenderEnqueuesVerification(t *testing.T) {
	enqueuer := &fakeEnqueuer{}
	sender, err := registration.NewDeliveryEmailSender(enqueuer, "EvernightLogin")
	if err != nil {
		t.Fatalf("构造投递适配器: %v", err)
	}
	message := registration.EmailMessage{
		UserID:          "usr_00000000000000000000000000000001",
		Recipient:       "user@example.test",
		DisplayName:     "测试用户",
		VerificationURL: "https://login.example.test/verify-email?uid=usr_x&cid=otc_x&token=SECRET-TOKEN",
		ExpiresIn:       "1 小时",
		AppName:         "EvernightLogin",
		CredentialID:    "otc_0123456789abcdef0123456789abcdef",
		RequestID:       "req-1",
	}
	if err := sender.SendEmailVerification(context.Background(), message); err != nil {
		t.Fatalf("发送验证邮件: %v", err)
	}
	enqueuer.mu.Lock()
	defer enqueuer.mu.Unlock()
	if len(enqueuer.requests) != 1 {
		t.Fatalf("应入队 1 封邮件，实际 %d", len(enqueuer.requests))
	}
	request := enqueuer.requests[0]
	if request.Kind != mailer.KindVerification {
		t.Errorf("模板用途 = %q，期望 verification", request.Kind)
	}
	if request.IdempotencyKey != "email-verify-"+message.CredentialID {
		t.Errorf("幂等键 = %q", request.IdempotencyKey)
	}
	if request.Data.Verification == nil || request.Data.Verification.VerifyURL != message.VerificationURL {
		t.Errorf("验证模板数据未包含入口链接: %+v", request.Data.Verification)
	}
	templates, err := mailer.DefaultTemplateSet()
	if err != nil {
		t.Fatalf("模板集合: %v", err)
	}
	content, err := templates.Render(request.Data)
	if err != nil {
		t.Fatalf("渲染验证邮件: %v", err)
	}
	if !strings.Contains(content.TextBody, message.VerificationURL) {
		t.Errorf("渲染正文缺少验证入口链接:\n%s", content.TextBody)
	}
	if !strings.Contains(content.TextBody, "1 小时") {
		t.Errorf("渲染正文缺少有效期:\n%s", content.TextBody)
	}
}

// decodeMailTextBody 解码邮件正文的 base64 传输编码。
func decodeMailTextBody(t *testing.T, message mailtest.Message) string {
	t.Helper()
	encoded := strings.ReplaceAll(string(message.Body()), "\r\n", "")
	encoded = strings.ReplaceAll(encoded, "\n", "")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("解码邮件正文失败: %v", err)
	}
	return string(decoded)
}

// TestRegistrationEmailEndToEndWithTestmail 验证注册 -> 可靠投递任务 -> SMTP ->
// testmail 本地捕获 -> 从邮件正文取回一次性入口 -> 完成邮箱验证的整链路，且不
// 真实外发。
func TestRegistrationEmailEndToEndWithTestmail(t *testing.T) {
	env := newTestEnv(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	smtpServer := mailtest.Start(t, mailtest.Options{Required: true, SMTPAuthNone: true})
	sender, err := mailer.NewSMTPSender(mailer.SMTPOptions{
		Addr: smtpServer.Addr().String(), TLSMode: mailer.TLSModeNone, AllowPlaintextLocal: true,
	})
	if err != nil {
		t.Fatalf("SMTP 发送器: %v", err)
	}
	mailerStore, err := mailersqlite.New(env.storage)
	if err != nil {
		t.Fatalf("投递存储: %v", err)
	}
	keyring, err := secrets.GenerateKeyring("k1", testStart)
	if err != nil {
		t.Fatalf("密钥环: %v", err)
	}
	sealer, err := secrets.NewSealer(keyring, nil)
	if err != nil {
		t.Fatalf("秘密加密器: %v", err)
	}
	templates, err := mailer.DefaultTemplateSet()
	if err != nil {
		t.Fatalf("模板: %v", err)
	}
	from, err := mailer.ParseAddress("noreply@example.test")
	if err != nil {
		t.Fatalf("发件地址: %v", err)
	}
	taskStore, err := tasksqlite.New(env.storage, tasksqlite.Options{})
	if err != nil {
		t.Fatalf("任务存储: %v", err)
	}
	var deliverHandler task.Handler
	executor, err := task.New(taskStore, task.Options{
		Handlers: map[string]task.Handler{
			mailer.TaskKindMailDelivery: func(ctx context.Context, job task.Job) error {
				return deliverHandler(ctx, job)
			},
		},
		ExecutorID:      "registration-test-executor",
		MaxConcurrent:   1,
		PollInterval:    20 * time.Millisecond,
		ShutdownTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("任务执行器: %v", err)
	}
	deliveryService, err := mailer.NewDeliveryService(mailer.DeliveryOptions{
		Store:       mailerStore,
		Sender:      sender,
		Templates:   templates,
		Sealer:      sealer,
		Recorder:    env.audit,
		Enqueuer:    executor,
		From:        from,
		MaxAttempts: 3,
		Now:         func() time.Time { return env.now },
	})
	if err != nil {
		t.Fatalf("投递服务: %v", err)
	}
	deliverHandler = deliveryService.Handler
	if err := executor.Start(ctx); err != nil {
		t.Fatalf("启动执行器: %v", err)
	}
	defer func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer stopCancel()
		_ = executor.Stop(stopCtx)
	}()
	deliverySender, err := registration.NewDeliveryEmailSender(deliveryService, "EvernightLogin")
	if err != nil {
		t.Fatalf("注册邮件适配器: %v", err)
	}
	regService, err := registration.New(registration.Options{
		Store:               newRegistrationStoreFor(t, env),
		Audit:               env.audit,
		Credentials:         env.creds,
		Mailer:              deliverySender,
		VerificationURLBase: testVerificationURL,
		Enabled:             true,
		VerificationTTL:     time.Hour,
		ResendCooldown:      time.Minute,
		AppName:             "EvernightLogin",
		Now:                 func() time.Time { return env.now },
	})
	if err != nil {
		t.Fatalf("注册服务: %v", err)
	}
	result, err := regService.Register(ctx, registration.RegisterRequest{
		Username: "e2e.mail", Password: testPassword, Email: "e2e@example.test",
	})
	if err != nil {
		t.Fatalf("注册失败: %v", err)
	}
	if !result.VerificationSent {
		t.Fatalf("验证邮件应已入队: %+v", result)
	}
	waitCtx, waitCancel := context.WithTimeout(ctx, 8*time.Second)
	defer waitCancel()
	messages, err := smtpServer.Wait(waitCtx, mailtest.Query{To: "e2e@example.test"})
	if err != nil || len(messages) == 0 {
		t.Fatalf("testmail 未捕获验证邮件: %v", err)
	}
	if !strings.Contains(messages[0].Subject, "邮箱验证") {
		t.Errorf("邮件主题 = %q", messages[0].Subject)
	}
	bodyText := decodeMailTextBody(t, messages[0])
	fields := strings.Fields(bodyText)
	var link string
	for _, field := range fields {
		if strings.HasPrefix(field, testVerificationURL+"?") {
			link = field
			break
		}
	}
	if link == "" {
		t.Fatalf("邮件正文缺少验证入口链接:\n%s", bodyText)
	}
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatalf("验证链接解析失败: %v", err)
	}
	query := parsed.Query()
	request := registration.VerifyEmailRequest{
		UserID:       query.Get("uid"),
		CredentialID: query.Get("cid"),
		Token:        query.Get("token"),
	}
	if request.UserID != result.UserID || request.Token == "" {
		t.Fatalf("验证链接参数不完整: %+v", request)
	}
	if _, err := regService.VerifyEmail(ctx, request); err != nil {
		t.Fatalf("邮箱验证失败: %v", err)
	}
	if got := env.count(`SELECT COUNT(*) FROM user_emails WHERE user_id=? AND verified_at_ms IS NOT NULL`,
		result.UserID); got != 1 {
		t.Errorf("邮箱应已完成验证，实际 %d", got)
	}
}

// TestVerifyEmailRejectsDisabledAccount 验证账户被禁用后旧验证入口不再可用。
func TestVerifyEmailRejectsDisabledAccount(t *testing.T) {
	env := newTestEnv(t, nil)
	result, err := env.register(registration.RegisterRequest{
		Username: "disabled.user", Email: "disabled@example.test",
	})
	if err != nil {
		t.Fatalf("注册失败: %v", err)
	}
	request, _ := env.link(t)
	if _, err := env.storage.DB().ExecContext(env.ctx,
		`UPDATE users SET status='disabled', security_version=security_version+1, row_version=row_version+1 WHERE id=?`,
		result.UserID); err != nil {
		t.Fatalf("禁用账户失败: %v", err)
	}
	if _, err := env.reg.VerifyEmail(env.ctx, request); !errors.Is(err, registration.ErrVerificationInvalid) {
		t.Fatalf("禁用账户的旧入口应被拒绝，实际 %v", err)
	}
	if got := env.count(`SELECT COUNT(*) FROM user_emails WHERE user_id=? AND verified_at_ms IS NOT NULL`,
		result.UserID); got != 0 {
		t.Errorf("禁用账户不应完成邮箱验证，实际 %d", got)
	}
}

// TestRegisterEmailWithoutMailCapability 验证未配置邮件能力时不接受邮箱注册，
// 且无邮箱密码注册仍可用（邮箱可选、不能被无条件拒绝）。
func TestRegisterEmailWithoutMailCapability(t *testing.T) {
	env := newTestEnv(t, func(options *registration.Options) {
		options.Mailer = nil
		options.VerificationURLBase = ""
	})
	if env.reg.EmailCapabilityEnabled() {
		t.Fatal("未配置邮件发送接口时不应报告邮箱能力可用")
	}
	if _, err := env.register(registration.RegisterRequest{
		Username: "nomail.user", Email: "nomail@example.test",
	}); !errors.Is(err, registration.ErrInvalidRequest) {
		t.Fatalf("无邮件能力时提供邮箱应返回请求错误，实际 %v", err)
	}
	if got := env.count(`SELECT COUNT(*) FROM users WHERE username_normalized='nomail.user'`); got != 0 {
		t.Errorf("失败的邮箱注册不应创建用户，实际 %d", got)
	}
	result, err := env.register(registration.RegisterRequest{Username: "nomail.ok"})
	if err != nil {
		t.Fatalf("无邮箱注册失败: %v", err)
	}
	if result.Status != account.StatusActive || result.VerificationSent {
		t.Errorf("无邮箱注册结果 = %+v", result)
	}
}

// TestReplaceEmailConflictKeepsOldLink 验证替换目标邮箱因占用冲突失败时不会先
// 撤销旧凭证：旧的有效验证链接仍然可用（不留下"失败但旧链接被误废"的状态）。
func TestReplaceEmailConflictKeepsOldLink(t *testing.T) {
	env := newTestEnv(t, nil)
	if _, err := env.register(registration.RegisterRequest{
		Username: "email.occupier", Email: "taken@example.test",
	}); err != nil {
		t.Fatalf("占用邮箱账户注册失败: %v", err)
	}
	victim, err := env.register(registration.RegisterRequest{
		Username: "email.victim", Email: "victim@example.test",
	})
	if err != nil {
		t.Fatalf("受害账户注册失败: %v", err)
	}
	oldLink, _ := env.link(t)
	env.advance(2 * time.Minute)
	caller, err := registration.SelfCaller(victim.UserID)
	if err != nil {
		t.Fatalf("用户调用者: %v", err)
	}
	if _, err := env.reg.SendEmailVerification(env.ctx, caller, registration.SendVerificationRequest{
		UserID: victim.UserID,
		Email:  "taken@example.test",
	}); !errors.Is(err, registration.ErrRegistrationConflict) {
		t.Fatalf("占用邮箱替换应返回统一冲突，实际 %v", err)
	}
	// 失败后旧票据与旧凭证保持原样：旧链接必须仍能完成验证。
	if _, err := env.reg.VerifyEmail(env.ctx, oldLink); err != nil {
		t.Fatalf("替换失败后旧有效链接被误废: %v", err)
	}
	if got := env.count(`SELECT COUNT(*) FROM user_emails WHERE user_id=? AND verified_at_ms IS NOT NULL`,
		victim.UserID); got != 1 {
		t.Errorf("旧邮箱应验证成功，实际 %d", got)
	}
}

// TestResendAfterReplaceConflictCooldown 验证替换冲突后票据未被覆盖，冷却后仍可
// 向新的空闲地址重发并完成验证，且旧链接失效。
func TestResendAfterReplaceConflictCooldown(t *testing.T) {
	env := newTestEnv(t, nil)
	if _, err := env.register(registration.RegisterRequest{
		Username: "conflict.occupier", Email: "conflict.taken@example.test",
	}); err != nil {
		t.Fatalf("占用邮箱账户注册失败: %v", err)
	}
	victim, err := env.register(registration.RegisterRequest{
		Username: "conflict.victim", Email: "conflict.old@example.test",
	})
	if err != nil {
		t.Fatalf("受害账户注册失败: %v", err)
	}
	oldLink, _ := env.link(t)
	caller, _ := registration.SelfCaller(victim.UserID)
	env.advance(2 * time.Minute)
	if _, err := env.reg.SendEmailVerification(env.ctx, caller, registration.SendVerificationRequest{
		UserID: victim.UserID, Email: "conflict.taken@example.test",
	}); !errors.Is(err, registration.ErrRegistrationConflict) {
		t.Fatalf("占用邮箱替换应失败，实际 %v", err)
	}
	// 失败的替换没有刷新票据；冷却仍然满足，可向空闲地址重发。
	resend, err := env.reg.SendEmailVerification(env.ctx, caller, registration.SendVerificationRequest{
		UserID: victim.UserID, Email: "conflict.new@example.test",
	})
	if err != nil {
		t.Fatalf("冲突后重发失败: %v", err)
	}
	if !resend.Sent || resend.Email != "conflict.new@example.test" {
		t.Fatalf("重发结果 = %+v", resend)
	}
	newLink, _ := env.link(t)
	if newLink.CredentialID == oldLink.CredentialID {
		t.Fatal("重发应签发新的凭证 ID")
	}
	if _, err := env.reg.VerifyEmail(env.ctx, oldLink); !errors.Is(err, registration.ErrVerificationInvalid) {
		t.Fatalf("旧链接应失效，实际 %v", err)
	}
	if _, err := env.reg.VerifyEmail(env.ctx, newLink); err != nil {
		t.Fatalf("新链接验证失败: %v", err)
	}
}

// TestRegistrationClosedStillAllowsExistingVerification 验证关闭注册只阻止新注册，
// 既有待验证链接的验证与重发仍可用。
func TestRegistrationClosedStillAllowsExistingVerification(t *testing.T) {
	env := newTestEnv(t, nil)
	_, err := env.register(registration.RegisterRequest{
		Username: "closed.first", Email: "closed.first@example.test",
	})
	if err != nil {
		t.Fatalf("注册失败: %v", err)
	}
	firstLink, _ := env.link(t)
	second, err := env.register(registration.RegisterRequest{
		Username: "closed.second", Email: "closed.second@example.test",
	})
	if err != nil {
		t.Fatalf("注册失败: %v", err)
	}
	secondLink, _ := env.link(t)
	env.advance(2 * time.Minute)
	closed, err := registration.New(registration.Options{
		Store:               newRegistrationStoreFor(t, env),
		Audit:               env.audit,
		Credentials:         env.creds,
		Mailer:              env.mail,
		VerificationURLBase: testVerificationURL,
		Enabled:             false,
		VerificationTTL:     time.Hour,
		ResendCooldown:      time.Minute,
		AppName:             "EvernightLogin",
		Now:                 func() time.Time { return env.now },
	})
	if err != nil {
		t.Fatalf("构造关闭注册服务: %v", err)
	}
	if _, err := closed.Register(env.ctx, registration.RegisterRequest{
		Username: "closed.new", Password: testPassword,
	}); !errors.Is(err, registration.ErrRegistrationClosed) {
		t.Fatalf("关闭注册应拒绝新注册，实际 %v", err)
	}
	if _, err := closed.VerifyEmail(env.ctx, firstLink); err != nil {
		t.Fatalf("关闭注册后既有链接验证失败: %v", err)
	}
	secondCaller, _ := registration.SelfCaller(second.UserID)
	resend, err := closed.SendEmailVerification(env.ctx, secondCaller,
		registration.SendVerificationRequest{UserID: second.UserID})
	if err != nil {
		t.Fatalf("关闭注册后重发失败: %v", err)
	}
	if !resend.Sent {
		t.Fatalf("关闭注册后重发应成功: %+v", resend)
	}
	newLink, _ := env.link(t)
	if newLink.CredentialID == secondLink.CredentialID {
		t.Fatal("重发应签发新凭证")
	}
	if _, err := closed.VerifyEmail(env.ctx, newLink); err != nil {
		t.Fatalf("关闭注册后新链接验证失败: %v", err)
	}
}

// TestDefaultRolesRejectApplicationScope 验证默认角色策略只接受 system 作用域，
// 应用角色必须走 role/delegation 赋权路径（注册流程不绕过）。
func TestDefaultRolesRejectApplicationScope(t *testing.T) {
	env := newTestEnv(t, nil)
	if _, err := registration.New(registration.Options{
		Store:       newRegistrationStoreFor(t, env),
		Audit:       env.audit,
		Credentials: env.creds,
		Enabled:     true,
		DefaultRoles: []registration.DefaultRole{
			{RoleID: "role_app_admin", ScopeID: "app_00000000000000000000000000000001"},
		},
	}); err == nil {
		t.Fatal("应用作用域的默认角色应被拒绝")
	}
	if _, err := registration.New(registration.Options{
		Store:        newRegistrationStoreFor(t, env),
		Audit:        env.audit,
		Credentials:  env.creds,
		Enabled:      true,
		DefaultRoles: []registration.DefaultRole{{RoleID: "", ScopeID: "system"}},
	}); err == nil {
		t.Fatal("空默认角色 ID 应被拒绝")
	}
}
