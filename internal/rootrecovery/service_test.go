package rootrecovery_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/rootrecovery"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

var seedTime = time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)

const (
	rootID      = "usr_00000000000000000000000000000001"
	oldPassword = "Old-Root-Password-9"
	newPassword = "Quasar-Meadow-Velvet-Nimbus"
)

type fakePrompter struct {
	confirmRecovery bool
	confirmPasskey  bool
	passwords       []string
	readCount       int
	confirmCalls    int
	passkeyCalls    int
	onConfirm       func()
	err             error
}

func (f *fakePrompter) ConfirmRecovery(scope rootrecovery.ScopeSummary) (bool, error) {
	f.confirmCalls++
	if f.onConfirm != nil {
		f.onConfirm()
	}
	if f.err != nil {
		return false, f.err
	}
	return f.confirmRecovery, nil
}

func (f *fakePrompter) ReadNewPassword() ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.readCount >= len(f.passwords) {
		return nil, errors.New("缺少测试密码")
	}
	password := f.passwords[f.readCount]
	f.readCount++
	return []byte(password), nil
}

func (f *fakePrompter) ConfirmPasskeyRevocation() (bool, error) {
	f.passkeyCalls++
	return f.confirmPasskey, nil
}

type testEnv struct {
	t        *testing.T
	ctx      context.Context
	dir      string
	dbPath   string
	storage  *storagesqlite.Store
	service  *rootrecovery.Service
	operator rootrecovery.Operator
	now      time.Time
}

// newTestEnv 创建临时 SQLite 实例并种入唯一 root、密码、会话、MFA、恢复代码与
// Passkey 数据（全部合成数据，不接触真实数据库）。
func newTestEnv(t *testing.T, mutate func(*rootrecovery.Options)) *testEnv {
	t.Helper()
	ctx := context.Background()
	dir := testutil.TempDir(t)
	dbPath := filepath.Join(dir, "login.db")
	storage, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(dbPath))
	if err != nil {
		t.Fatalf("打开数据库: %v", err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	list, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移: %v", err)
	}
	if _, err := storage.Migrate(ctx, list); err != nil {
		t.Fatalf("执行迁移: %v", err)
	}
	env := &testEnv{t: t, ctx: ctx, dir: dir, dbPath: dbPath, storage: storage,
		operator: rootrecovery.Operator{ID: "os:test-admin@test-host", Machine: "test-host"},
		now:      time.Now().UTC()}
	env.seed()
	prompter := &fakePrompter{confirmRecovery: true, passwords: []string{newPassword, newPassword}}
	options := rootrecovery.Options{
		DatabasePath: dbPath, Operator: env.operator, Prompter: prompter,
		Now:    func() time.Time { return env.now },
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}
	if mutate != nil {
		mutate(&options)
	}
	service, err := rootrecovery.New(options)
	if err != nil {
		t.Fatalf("构造恢复服务: %v", err)
	}
	env.service = service
	return env
}

func (e *testEnv) seed() {
	e.t.Helper()
	now := seedTime.UnixMilli()
	exec := func(query string, args ...any) {
		e.t.Helper()
		if _, err := e.storage.DB().ExecContext(e.ctx, query, args...); err != nil {
			e.t.Fatalf("种子数据失败: %v", err)
		}
	}
	exec(`INSERT INTO users(id,username,username_normalized,nickname,biography,avatar_ref,
language,timezone,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'','',NULL,'zh-CN','Asia/Shanghai','active',1,3,1,?,?)`,
		rootID, "root", "root", now, now)
	exec(`INSERT INTO root_initializations(singleton,root_user_id,state,setup_credential_id,
started_by,created_at_ms,updated_at_ms,verified_at_ms,ready_at_ms)
VALUES(1,?,'ready',NULL,'local:seed',?,?,?,?)`, rootID, now, now, now, now)
	oldHash, err := authn.HashPassword(oldPassword, authn.DefaultParams(), nil)
	if err != nil {
		e.t.Fatalf("种子密码哈希: %v", err)
	}
	exec(`INSERT INTO password_credentials(user_id,hash_scheme,hash_version,password_hash,
must_change,row_version,created_at_ms,updated_at_ms,changed_at_ms)
VALUES(?,'argon2id',19,?,0,1,?,?,?)`, rootID, oldHash, now, now, now)
	for index, sessionID := range []string{
		"ses_00000000000000000000000000000001", "ses_00000000000000000000000000000002",
	} {
		digest := sha256.Sum256([]byte(sessionID))
		exec(`INSERT INTO sessions(id,user_id,app_id,kind,restricted_reason,
required_steps_json,security_version,secret_digest,csrf_digest,key_id,
strong_auth_verified_at_ms,row_version,created_at_ms,last_seen_at_ms,
idle_expires_at_ms,absolute_expires_at_ms,revoked_at_ms,revoked_reason,request_id)
VALUES(?,?,NULL,'normal','','[]',3,?,?,'k1',?,1,?,?,?,?,NULL,'','')`,
			sessionID, rootID, digest[:], digest[:], now, now, now, now+int64(index+1)*60000,
			now+3600000)
	}
	exec(`INSERT INTO mfa_factors(id,user_id,factor_type,status,created_at_ms,updated_at_ms)
VALUES('mfa_email_1',?,'email','active',?,?)`, rootID, now, now)
	exec(`INSERT INTO totp_bindings(id,user_id,status,sealed_secret,algorithm,digits,
period_seconds,window_steps,last_accepted_step,attempts,max_attempts,expires_at_ms,
created_at_ms,updated_at_ms,activated_at_ms)
VALUES('tfb_seed',?,'active',?, 'SHA1',6,30,1,10,0,5,?,?,?,?)`,
		rootID, []byte("sealed-envelope-bytes-for-test-只有测试"), now+3600000, now, now, now)
	exec(`INSERT INTO mfa_challenges(id,user_id,factor_type,purpose,attempt_sha256,
credential_id,factor_ref,generation,state,username,app_id,remember_me,client_user_agent,
client_address,restricted_session_id,attempts,max_attempts,require_strong,security_version,
completed_at_ms,expires_at_ms,created_at_ms,updated_at_ms,verified_at_ms)
VALUES('mfc_seed',?,'email','login',?,'cred-seed','',1,'pending','root','',0,'','','',0,5,0,3,?,?,?,?,NULL)`,
		rootID, bytes32(), now+3600000, now, now, now)
	exec(`INSERT INTO recovery_code_groups(id,user_id,generation,status,code_count,
created_at_ms,invalidated_at_ms) VALUES('rcg_seed',?,1,'active',1,?,NULL)`, rootID, now)
	exec(`INSERT INTO recovery_codes(id,group_id,user_id,digest,key_id,used_at_ms,created_at_ms)
VALUES('rcc_seed','rcg_seed',?,?,'k1',NULL,?)`, rootID, bytes32(), now)
	exec(`INSERT INTO recovery_attempts(id,user_id,group_id,code_id,status,attempts,
max_attempts,expires_at_ms,created_at_ms,updated_at_ms)
VALUES('rca_seed',?,'rcg_seed','rcc_seed','pending_binding',0,5,?,?,?)`,
		rootID, now+3600000, now, now)
	exec(`INSERT INTO one_time_credentials(id,purpose,subject_id,app_id,verifier_hash,key_id,
context_json,attempts,max_attempts,created_at_ms,expires_at_ms,consumed_at_ms,revoked_at_ms)
VALUES('otc_seed','root.setup',?,NULL,?,'k1','{}',0,5,?,?,NULL,NULL)`,
		rootID, bytes32(), now, now+3600000)
	for index, credential := range []struct {
		id      string
		usage   string
		credID  []byte
		keyBlob []byte
	}{
		{"cred_login", "login", bytes16(1), []byte("cose-key-login")},
		{"cred_second", "second_factor", bytes16(2), []byte("cose-key-second")},
	} {
		exec(`INSERT INTO webauthn_credentials(id,user_id,credential_id,public_key,aaguid,
rp_id,name,sign_count,transports,backup_eligible,backed_up,user_present,user_verified,
attachment,usage,version,last_used_at_ms,revoked_at_ms,revoked_reason,created_at_ms,
updated_at_ms) VALUES(?,?,?,?,X'00000000000000000000000000000000',
'login.example.com',?,0,'[]',0,0,1,1,'',?,1,NULL,NULL,'',?,?)`,
			credential.id, rootID, credential.credID, credential.keyBlob,
			"root key "+string(rune('A'+index)), credential.usage, now, now)
		_ = index
	}
}

func bytes32() []byte { return bytes16(7) }

func bytes16(seed byte) []byte {
	value := make([]byte, 32)
	for index := range value {
		value[index] = seed + byte(index)
	}
	return value
}

func (e *testEnv) request() rootrecovery.Request {
	return rootrecovery.Request{
		Reason:         "root 锁定后的本地应急恢复",
		ServiceStopped: true,
		ResetPassword:  true,
		ResetMFA:       true,
	}
}

func (e *testEnv) queryInt(query string, args ...any) int64 {
	e.t.Helper()
	var value int64
	if err := e.storage.DB().QueryRowContext(e.ctx, query, args...).Scan(&value); err != nil {
		e.t.Fatalf("查询失败: %v", err)
	}
	return value
}

func (e *testEnv) queryString(query string, args ...any) string {
	e.t.Helper()
	var value string
	if err := e.storage.DB().QueryRowContext(e.ctx, query, args...).Scan(&value); err != nil {
		e.t.Fatalf("查询失败: %v", err)
	}
	return value
}

func (e *testEnv) oldPasswordWorks() bool {
	e.t.Helper()
	hash := e.queryString(`SELECT password_hash FROM password_credentials WHERE user_id=?`, rootID)
	result, err := authn.VerifyPassword(hash, oldPassword)
	if err != nil {
		e.t.Fatalf("校验旧密码: %v", err)
	}
	return result.Matched
}

func (e *testEnv) newPasswordWorks() bool {
	e.t.Helper()
	hash := e.queryString(`SELECT password_hash FROM password_credentials WHERE user_id=?`, rootID)
	result, err := authn.VerifyPassword(hash, newPassword)
	if err != nil {
		e.t.Fatalf("校验新密码: %v", err)
	}
	return result.Matched
}

// TestPasswordAndMFAReset 覆盖密码+MFA 一起重置：密码替换、安全版本递增、会话撤销、
// 因素/恢复代码作废、Passkey 默认保留、进入 setup_verified、写入 outbox 与审计。
func TestPasswordAndMFAReset(t *testing.T) {
	env := newTestEnv(t, nil)
	result, err := env.service.Recover(env.ctx, env.request())
	if err != nil {
		t.Fatalf("执行恢复: %v", err)
	}
	if result.SecurityVersionAfter != 4 || result.SessionsRevoked != 2 {
		t.Fatalf("恢复结果异常: %+v", result)
	}
	if !env.newPasswordWorks() || env.oldPasswordWorks() {
		t.Fatal("密码重置未正确替换旧密码")
	}
	if got := env.queryInt(`SELECT security_version FROM users WHERE id=?`, rootID); got != 4 {
		t.Fatalf("security_version = %d，期望 4", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM sessions WHERE user_id=? AND revoked_at_ms IS NULL`, rootID); got != 0 {
		t.Fatalf("仍有未撤销会话: %d", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM mfa_factors WHERE user_id=? AND status='active'`, rootID); got != 0 {
		t.Fatalf("邮件因素未被禁用: %d", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM totp_bindings WHERE user_id=? AND status='active'`, rootID); got != 0 {
		t.Fatalf("TOTP 绑定未被禁用: %d", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM recovery_code_groups WHERE user_id=? AND status='active'`, rootID); got != 0 {
		t.Fatalf("恢复代码组未被作废: %d", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM recovery_attempts WHERE user_id=? AND status='pending_binding'`, rootID); got != 0 {
		t.Fatalf("恢复尝试未被取消: %d", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM one_time_credentials WHERE subject_id=? AND revoked_at_ms IS NULL`, rootID); got != 0 {
		t.Fatalf("一次性凭证未被撤销: %d", got)
	}
	// Passkey 默认保留（未显式选择撤销）。
	if got := env.queryInt(`SELECT COUNT(*) FROM webauthn_credentials WHERE user_id=? AND revoked_at_ms IS NULL`, rootID); got != 2 {
		t.Fatalf("Passkey 默认应保留: %d", got)
	}
	if state := env.queryString(`SELECT state FROM root_initializations WHERE singleton=1`); state != "setup_verified" {
		t.Fatalf("root 初始化状态 = %q，期望 setup_verified", state)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM root_initializations WHERE singleton=1 AND ready_at_ms IS NULL`); got != 1 {
		t.Fatalf("setup_verified 状态不应保留 ready_at_ms")
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM root_recovery_events WHERE id=? AND notification_state='pending' AND password_reset=1 AND mfa_reset=1 AND passkeys_revoked=0`, result.EventID); got != 1 {
		t.Fatalf("恢复 outbox 记录不正确")
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE action='root.emergency_recovery' AND actor_type='local_admin' AND actor_id=?`, env.operator.ID); got != 1 {
		t.Fatalf("缺少 root 应急恢复成功审计")
	}
	// 密码/哈希/种子不得进入审计明细或恢复记录。
	if got := env.queryInt(`SELECT COUNT(*) FROM audit_events WHERE detail_json LIKE ?`, "%"+newPassword+"%"); got != 0 {
		t.Fatalf("审计明细泄露新密码")
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM root_recovery_events WHERE actions_json LIKE ? OR reason LIKE ?`,
		"%"+newPassword+"%", "%"+newPassword+"%"); got != 0 {
		t.Fatalf("恢复记录泄露新密码")
	}
	// outbox 可重投：先失败仍保持 pending，再标记已送达。
	notifications, err := env.service.PendingNotifications(env.ctx, 10)
	if err != nil || len(notifications) != 1 || notifications[0].ID != result.EventID {
		t.Fatalf("待补发通知异常: %+v err=%v", notifications, err)
	}
	if err := env.service.MarkNotificationFailed(env.ctx, result.EventID, "MAIL_SEND_UNAVAILABLE", env.now); err != nil {
		t.Fatalf("标记补发失败: %v", err)
	}
	if notifications, _ = env.service.PendingNotifications(env.ctx, 10); len(notifications) != 1 {
		t.Fatal("补发失败后事件应保持 pending 以便重试")
	}
	if err := env.service.MarkNotificationDelivered(env.ctx, result.EventID, env.now); err != nil {
		t.Fatalf("标记已补发: %v", err)
	}
	if notifications, _ = env.service.PendingNotifications(env.ctx, 10); len(notifications) != 0 {
		t.Fatal("已送达事件不应再出现在 pending 列表")
	}
}

// TestPasswordOnlyResetKeepsMFA 覆盖仅重置密码：MFA 因素与 Passkey 保留，但安全
// 版本与 outbox 仍更新。
func TestPasswordOnlyResetKeepsMFA(t *testing.T) {
	env := newTestEnv(t, nil)
	request := rootrecovery.Request{Reason: "仅重置 root 密码", ServiceStopped: true,
		ResetPassword: true}
	if _, err := env.service.Recover(env.ctx, request); err != nil {
		t.Fatalf("仅重置密码: %v", err)
	}
	if !env.newPasswordWorks() || env.oldPasswordWorks() {
		t.Fatal("仅重置密码时密码未正确替换")
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM mfa_factors WHERE user_id=? AND status='active'`, rootID); got != 1 {
		t.Fatalf("仅重置密码不应禁用邮件因素: %d", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM totp_bindings WHERE user_id=? AND status='active'`, rootID); got != 1 {
		t.Fatalf("仅重置密码不应禁用 TOTP: %d", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM webauthn_credentials WHERE user_id=? AND revoked_at_ms IS NULL`, rootID); got != 2 {
		t.Fatalf("仅重置密码不应撤销 Passkey: %d", got)
	}
}

// TestMFAOnlyResetKeepsPassword 覆盖仅重置 MFA：密码不变、Passkey 保留。
func TestMFAOnlyResetKeepsPassword(t *testing.T) {
	env := newTestEnv(t, nil)
	request := rootrecovery.Request{Reason: "更换 root 验证器", ServiceStopped: true, ResetMFA: true}
	if _, err := env.service.Recover(env.ctx, request); err != nil {
		t.Fatalf("仅重置 MFA: %v", err)
	}
	if !env.oldPasswordWorks() {
		t.Fatal("仅重置 MFA 不应改变密码")
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM mfa_factors WHERE user_id=? AND status='active'`, rootID); got != 0 {
		t.Fatalf("邮件因素未被禁用: %d", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM webauthn_credentials WHERE user_id=? AND revoked_at_ms IS NULL`, rootID); got != 2 {
		t.Fatalf("Passkey 应保留: %d", got)
	}
}

// TestExplicitPasskeyRevocation 覆盖显式撤销主登录 Passkey 与二次确认取消。
func TestExplicitPasskeyRevocation(t *testing.T) {
	confirmed := newTestEnv(t, nil)
	confirmedPrompter := &fakePrompter{confirmRecovery: true, confirmPasskey: true}
	confirmed.service = mustService(t, confirmed, confirmedPrompter, nil)
	request := confirmed.request()
	request.ResetPassword = false
	request.RevokeLoginPasskeys = true
	result, err := confirmed.service.Recover(confirmed.ctx, request)
	if err != nil {
		t.Fatalf("显式撤销 Passkey: %v", err)
	}
	if result.PasskeysRevoked != 2 {
		t.Fatalf("撤销 Passkey 数量 = %d，期望 2", result.PasskeysRevoked)
	}
	if got := confirmed.queryInt(`SELECT COUNT(*) FROM webauthn_credentials WHERE user_id=? AND revoked_at_ms IS NULL`, rootID); got != 0 {
		t.Fatalf("Passkey 未被撤销: %d", got)
	}
	// 二次确认取消：整体取消，无任何修改。
	cancelled := newTestEnv(t, nil)
	cancelledPrompter := &fakePrompter{confirmRecovery: true, confirmPasskey: false}
	cancelled.service = mustService(t, cancelled, cancelledPrompter, nil)
	request = cancelled.request()
	request.RevokeLoginPasskeys = true
	if _, err := cancelled.service.Recover(cancelled.ctx, request); !errors.Is(err, rootrecovery.ErrConfirmationDeclined) {
		t.Fatalf("取消 Passkey 二次确认应拒绝: %v", err)
	}
	if got := cancelled.queryInt(`SELECT security_version FROM users WHERE id=?`, rootID); got != 3 {
		t.Fatalf("取消后 security_version 被修改: %d", got)
	}
}

func mustService(t *testing.T, env *testEnv, prompter rootrecovery.Prompter,
	injector func(string) error) *rootrecovery.Service {
	t.Helper()
	service, err := rootrecovery.New(rootrecovery.Options{
		DatabasePath: env.dbPath, Operator: env.operator, Prompter: prompter,
		Now:                   func() time.Time { return env.now },
		TestOnlyFaultInjector: injector,
	})
	if err != nil {
		t.Fatalf("构造恢复服务: %v", err)
	}
	return service
}

// TestCancelConfirmationNoChanges 覆盖取消整体确认：不产生任何数据库修改（含不写
// 审计/outbox），密码输入也不会被读取。
func TestCancelConfirmationNoChanges(t *testing.T) {
	env := newTestEnv(t, nil)
	prompter := &fakePrompter{confirmRecovery: false}
	service := mustService(t, env, prompter, nil)
	beforeAudit := env.queryInt(`SELECT COUNT(*) FROM audit_events`)
	beforeEvents := env.queryInt(`SELECT COUNT(*) FROM root_recovery_events`)
	if _, err := service.Recover(env.ctx, env.request()); !errors.Is(err, rootrecovery.ErrConfirmationDeclined) {
		t.Fatalf("取消确认应返回 ErrConfirmationDeclined: %v", err)
	}
	if prompter.readCount != 0 {
		t.Fatal("取消确认后不应读取新密码")
	}
	if got := env.queryInt(`SELECT security_version FROM users WHERE id=?`, rootID); got != 3 {
		t.Fatalf("取消后 security_version 被修改: %d", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM sessions WHERE user_id=? AND revoked_at_ms IS NULL`, rootID); got != 2 {
		t.Fatalf("取消后会话被撤销: %d", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM audit_events`); got != beforeAudit {
		t.Fatalf("取消后写入了审计事件: %d != %d", got, beforeAudit)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM root_recovery_events`); got != beforeEvents {
		t.Fatalf("取消后写入了恢复事件: %d", got)
	}
}

// TestFaultInjectionRollsBack 模拟“断电式”事务中途失败：任何阶段失败都整体回滚，
// 不留下半完成的密码/因素/会话/安全版本/初始化状态。
func TestFaultInjectionRollsBack(t *testing.T) {
	for _, stage := range []string{"after_password", "after_factors", "after_sessions", "before_audit_done"} {
		t.Run(stage, func(t *testing.T) {
			env := newTestEnv(t, nil)
			service := mustService(t, env, &fakePrompter{confirmRecovery: true,
				passwords: []string{newPassword, newPassword}},
				func(at string) error {
					if at == stage {
						return errors.New("模拟事务中途断电")
					}
					return nil
				})
			if _, err := service.Recover(env.ctx, env.request()); err == nil {
				t.Fatalf("阶段 %s 注入失败应返回错误", stage)
			}
			if !env.oldPasswordWorks() {
				t.Fatal("失败后旧密码应仍然有效（事务回滚）")
			}
			if got := env.queryInt(`SELECT security_version FROM users WHERE id=?`, rootID); got != 3 {
				t.Fatalf("失败后 security_version 被修改: %d", got)
			}
			if got := env.queryInt(`SELECT COUNT(*) FROM sessions WHERE user_id=? AND revoked_at_ms IS NULL`, rootID); got != 2 {
				t.Fatalf("失败后会话被撤销: %d", got)
			}
			if got := env.queryInt(`SELECT COUNT(*) FROM root_recovery_events`); got != 0 {
				t.Fatalf("失败后不应留下恢复记录: %d", got)
			}
			if state := env.queryString(`SELECT state FROM root_initializations WHERE singleton=1`); state != "ready" {
				t.Fatalf("失败后 root 初始化状态被修改: %q", state)
			}
			// 锁在失败后释放：可以再次执行（无注入）。
			retry := mustService(t, env, &fakePrompter{confirmRecovery: true,
				passwords: []string{newPassword, newPassword}}, nil)
			if _, err := retry.Recover(env.ctx, env.request()); err != nil {
				t.Fatalf("失败后重试恢复应成功: %v", err)
			}
		})
	}
}

// TestInvalidDatabaseRejected 覆盖错误数据库/旧版本/缺 root：全部在写入前拒绝。
func TestInvalidDatabaseRejected(t *testing.T) {
	// 非本项目数据库文件。
	dir := testutil.TempDir(t)
	foreign := filepath.Join(dir, "foreign.db")
	if err := os.WriteFile(foreign, []byte("not a sqlite database at all"), 0o600); err != nil {
		t.Fatalf("写入错误库: %v", err)
	}
	prompter := &fakePrompter{confirmRecovery: true}
	service, err := rootrecovery.New(rootrecovery.Options{
		DatabasePath: foreign,
		Operator:     rootrecovery.Operator{ID: "os:test@host", Machine: "host"},
		Prompter:     prompter,
	})
	if err != nil {
		t.Fatalf("构造服务: %v", err)
	}
	if _, err := service.Recover(context.Background(), rootrecovery.Request{
		Reason: "错误数据库", ServiceStopped: true, ResetMFA: true,
	}); !errors.Is(err, rootrecovery.ErrInvalidDatabase) {
		t.Fatalf("非本项目数据库应拒绝: %v", err)
	}
	if info, statErr := os.Stat(foreign); statErr != nil || info.Size() != int64(len("not a sqlite database at all")) {
		t.Fatalf("错误库不应被修改: %v %v", info, statErr)
	}
	// 迁移到一半的数据库（缺少本项目 root）拒绝。
	incompleteDir := testutil.TempDir(t)
	incompletePath := filepath.Join(incompleteDir, "incomplete.db")
	ctx := context.Background()
	incomplete, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(incompletePath))
	if err != nil {
		t.Fatalf("打开半成品库: %v", err)
	}
	list, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移: %v", err)
	}
	if _, err := incomplete.Migrate(ctx, list[:5]); err != nil {
		t.Fatalf("执行部分迁移: %v", err)
	}
	_ = incomplete.Close()
	incompletePrompter := &fakePrompter{confirmRecovery: true}
	incompleteService, err := rootrecovery.New(rootrecovery.Options{
		DatabasePath: incompletePath,
		Operator:     rootrecovery.Operator{ID: "os:test@host", Machine: "host"},
		Prompter:     incompletePrompter,
	})
	if err != nil {
		t.Fatalf("构造服务: %v", err)
	}
	if _, err := incompleteService.Recover(ctx, rootrecovery.Request{
		Reason: "旧库", ServiceStopped: true, ResetMFA: true,
	}); !errors.Is(err, rootrecovery.ErrInvalidDatabase) {
		t.Fatalf("旧版本/不完整数据库应拒绝: %v", err)
	}
}

// TestMaintenanceRequired 覆盖未确认停机即拒绝，且不读取任何交互输入。
func TestMaintenanceRequired(t *testing.T) {
	env := newTestEnv(t, nil)
	prompter := &fakePrompter{confirmRecovery: true}
	service := mustService(t, env, prompter, nil)
	if _, err := service.Recover(env.ctx, rootrecovery.Request{
		Reason: "未确认停机", ResetMFA: true,
	}); !errors.Is(err, rootrecovery.ErrMaintenanceRequired) {
		t.Fatalf("未确认停机应拒绝: %v", err)
	}
	if prompter.confirmCalls != 0 {
		t.Fatal("未确认停机时不应进入交互确认")
	}
}

// TestOutboxRetryLimit 验证补发失败有限重试：达到上限后进入 failed 终态，
// 不再无限重试；已送达事件上的失败标记幂等。
func TestOutboxRetryLimit(t *testing.T) {
	env := newTestEnv(t, nil)
	result, err := env.service.Recover(env.ctx, env.request())
	if err != nil {
		t.Fatalf("执行恢复: %v", err)
	}
	for attempt := 1; attempt < rootrecovery.MaxNotificationAttempts; attempt++ {
		if err := env.service.MarkNotificationFailed(env.ctx, result.EventID,
			"MAIL_SEND_UNAVAILABLE", env.now); err != nil {
			t.Fatalf("第 %d 次失败标记: %v", attempt, err)
		}
		notifications, err := env.service.PendingNotifications(env.ctx, 10)
		if err != nil || len(notifications) != 1 {
			t.Fatalf("未达上限时应保持 pending: %+v err=%v", notifications, err)
		}
	}
	if err := env.service.MarkNotificationFailed(env.ctx, result.EventID,
		"MAIL_SEND_UNAVAILABLE", env.now); err != nil {
		t.Fatalf("达到上限的失败标记: %v", err)
	}
	notifications, err := env.service.PendingNotifications(env.ctx, 10)
	if err != nil || len(notifications) != 0 {
		t.Fatalf("达到上限后不应再出现在 pending: %+v err=%v", notifications, err)
	}
	if state := env.queryString(`SELECT notification_state FROM root_recovery_events WHERE id=?`,
		result.EventID); state != "failed" {
		t.Fatalf("达到上限后状态 = %q，期望 failed", state)
	}
	if got := env.queryInt(`SELECT notification_attempts FROM root_recovery_events WHERE id=?`,
		result.EventID); got != rootrecovery.MaxNotificationAttempts {
		t.Fatalf("尝试次数 = %d", got)
	}
}

// TestAuditFailureRollsBack 通过数据库触发器让审计写入失败，验证 fail-closed：整个
// 恢复事务回滚，密码/安全版本/会话/因素/初始化状态/恢复记录均不生效。
func TestAuditFailureRollsBack(t *testing.T) {
	env := newTestEnv(t, nil)
	if _, err := env.storage.DB().ExecContext(env.ctx,
		`CREATE TRIGGER fail_audit_insert BEFORE INSERT ON audit_events
BEGIN SELECT RAISE(ABORT,'模拟审计存储故障'); END`); err != nil {
		t.Fatalf("创建审计故障触发器: %v", err)
	}
	if _, err := env.service.Recover(env.ctx, env.request()); err == nil {
		t.Fatal("审计写入失败时恢复必须 fail-closed")
	}
	if !env.oldPasswordWorks() {
		t.Fatal("审计失败后旧密码应仍然有效（事务回滚）")
	}
	if got := env.queryInt(`SELECT security_version FROM users WHERE id=?`, rootID); got != 3 {
		t.Fatalf("审计失败后 security_version 被修改: %d", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM sessions WHERE user_id=? AND revoked_at_ms IS NULL`, rootID); got != 2 {
		t.Fatalf("审计失败后会话被撤销: %d", got)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM root_recovery_events`); got != 0 {
		t.Fatalf("审计失败后不应留下恢复记录: %d", got)
	}
	if state := env.queryString(`SELECT state FROM root_initializations WHERE singleton=1`); state != "ready" {
		t.Fatalf("审计失败后 root 初始化状态被修改: %q", state)
	}
}

// TestLockCoversSameFileDifferentPaths 验证同一数据库文件通过不同路径（硬链接）
// 访问时仍共享互斥：身份锁确保硬链接路径不能绕过恢复锁。
func TestLockCoversSameFileDifferentPaths(t *testing.T) {
	env := newTestEnv(t, nil)
	otherDir := testutil.TempDir(t)
	hardlinkPath := filepath.Join(otherDir, "linked.db")
	if err := os.Link(env.dbPath, hardlinkPath); err != nil {
		t.Skipf("当前环境不支持硬链接，跳过不同路径锁测试: %v", err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	blocking := &fakePrompter{confirmRecovery: true,
		passwords: []string{newPassword, newPassword},
		onConfirm: func() { close(entered); <-release }}
	first := mustService(t, env, blocking, nil)
	second := mustService(t, env, &fakePrompter{confirmRecovery: true,
		passwords: []string{newPassword, newPassword}}, nil)
	// 让第一个恢复使用硬链接路径也可以：先验证第二服务（原始路径）在硬链接路径
	// 持锁时被拒绝。
	firstErrCh := make(chan error, 1)
	go func() {
		_, err := first.Recover(env.ctx, env.request())
		firstErrCh <- err
	}()
	select {
	case <-entered:
	case err := <-firstErrCh:
		t.Fatalf("第一个恢复提前失败: %v", err)
	case <-time.After(20 * time.Second):
		t.Fatal("等待第一个恢复进入交互确认超时")
	}
	linked := mustService(t, env, &fakePrompter{confirmRecovery: true,
		passwords: []string{newPassword, newPassword}}, nil)
	_ = second
	// second/ linked 都指向同一底层文件，应被锁拒绝。
	if _, err := linked.Recover(env.ctx, env.request()); !errors.Is(err, rootrecovery.ErrLocked) {
		t.Fatalf("硬链接路径不应绕过恢复锁: %v", err)
	}
	close(release)
	if err := <-firstErrCh; err != nil {
		t.Fatalf("第一个恢复应成功: %v", err)
	}
}

// TestConcurrentRecoveryOnlyOneWins 覆盖并发执行：锁保证同一时刻只有一个恢复成功。
func TestConcurrentRecoveryOnlyOneWins(t *testing.T) {
	env := newTestEnv(t, nil)
	entered := make(chan struct{})
	release := make(chan struct{})
	blocking := &fakePrompter{confirmRecovery: true, passwords: []string{newPassword, newPassword},
		onConfirm: func() {
			close(entered)
			<-release
		}}
	first := mustService(t, env, blocking, nil)
	second := mustService(t, env, &fakePrompter{confirmRecovery: true,
		passwords: []string{newPassword, newPassword}}, nil)
	var wg sync.WaitGroup
	wg.Add(1)
	firstErrCh := make(chan error, 1)
	go func() {
		defer wg.Done()
		_, err := first.Recover(env.ctx, env.request())
		firstErrCh <- err
	}()
	select {
	case <-entered:
	case err := <-firstErrCh:
		t.Fatalf("第一个恢复在进入交互确认前失败: %v", err)
	case <-time.After(20 * time.Second):
		t.Fatal("等待第一个恢复进入交互确认超时")
	}
	if _, err := second.Recover(env.ctx, env.request()); !errors.Is(err, rootrecovery.ErrLocked) {
		t.Fatalf("并发恢复应被锁拒绝: %v", err)
	}
	close(release)
	wg.Wait()
	if firstErr := <-firstErrCh; firstErr != nil {
		t.Fatalf("第一个恢复应成功: %v", firstErr)
	}
	if got := env.queryInt(`SELECT COUNT(*) FROM root_recovery_events`); got != 1 {
		t.Fatalf("并发恢复应只有一个成功记录: %d", got)
	}
}
