package reauth_test

// 步骤 255：目标绑定的一次性两步验证操作证明（direct management proof）定向测试。
//
// 覆盖：
//   - 操作者与目标不同：绑定操作者、会话、操作、目标、范围与本次新值意图；
//   - 密码+TOTP 路径与 WebAuthn 第二步路径都签发一次性证明（无密码 Passkey 账户
//     不被强制要求密码）；
//   - 换目标/换会话/换新用户名/换新口令/权限撤销/会话失效一律拒绝；
//   - 意图以密封密文保存（数据库无明文、无无密钥摘要），审计/日志不含新值；
//   - 证明有用途、TTL、单次消费；提交失败整体回滚后同一证明可重试，成功后重放
//     不二次执行；并发消费只有一个赢家；
//   - 旧路径（无会话/意图绑定的旧批准、伪造 context 信号 Authorize）对直接管理
//     操作 fail-closed。
//
// 使用真实 SQLite/审计/策略/加密器 + 受控密码/强因素/WebAuthn/会话/权限替身；
// 生产装配（app 门面 + serverapp 晚接线）由 app 层测试另行覆盖。

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	policysqlite "github.com/kagurazakayashi/EvernightLogin/internal/policy/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	reauthsqlite "github.com/kagurazakayashi/EvernightLogin/internal/reauth/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const (
	proofPassword = "correct-password"
	proofTOTP     = "123456"
	// directTargetUserID 是被管理的目标用户（不是操作者）。
	directTargetUserID = noMailUserID
)

func newSessionID(t *testing.T) string {
	t.Helper()
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		t.Fatalf("生成会话 ID: %v", err)
	}
	return "ses_" + hex.EncodeToString(buffer)
}

// fakeStrongFactor 是受控 TOTP 强因素替身（真实生产实现由 internal/totp 适配）。
type fakeStrongFactor struct {
	code string
	mu   sync.Mutex
	last string
}

func (f *fakeStrongFactor) VerifyStrongFactor(_ context.Context,
	request reauth.StrongFactorVerifyRequest) (reauth.StrongFactorVerifyResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.last = request.TOTPCode
	if request.TOTPCode != f.code {
		return reauth.StrongFactorVerifyResult{}, errors.New("动态码错误")
	}
	return reauth.StrongFactorVerifyResult{UserID: request.UserID,
		CompletedAt: time.Now().UTC(), Method: "totp", UserVerified: true}, nil
}

// fakeWebAuthnFactor 是受控 WebAuthn 第二步替身（真实生产实现适配 internal/passkey）。
type fakeWebAuthnFactor struct {
	mu         sync.Mutex
	userID     string
	contextID  string
	ceremonyID string
	verified   bool
	beginErr   error
	finishErr  error
	finishes   int
}

func (f *fakeWebAuthnFactor) BeginStrongWebAuthn(_ context.Context, userID, contextID,
	_ string) (reauth.StrongWebAuthnStart, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.beginErr != nil {
		return reauth.StrongWebAuthnStart{}, f.beginErr
	}
	f.userID, f.contextID = userID, contextID
	f.ceremonyID = "pkc_" + strings.Repeat("a", 32)
	return reauth.StrongWebAuthnStart{CeremonyID: f.ceremonyID,
		PublicKey: []byte(`{"challenge":"x"}`), RPID: "login.example.test",
		ExpiresAt: time.Now().UTC().Add(5 * time.Minute)}, nil
}

func (f *fakeWebAuthnFactor) FinishStrongWebAuthn(_ context.Context, userID, contextID,
	ceremonyID string, _ []byte, _ string) (reauth.StrongFactorVerifyResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.finishes++
	if f.finishErr != nil {
		return reauth.StrongFactorVerifyResult{}, f.finishErr
	}
	if f.userID != userID || f.contextID != contextID || f.ceremonyID != ceremonyID {
		return reauth.StrongFactorVerifyResult{}, errors.New("上下文不符")
	}
	return reauth.StrongFactorVerifyResult{UserID: userID, CompletedAt: time.Now().UTC(),
		Method: "passkey", UserVerified: f.verified}, nil
}

// fakeSessionVerifier 是会话有效性替身。
type fakeSessionVerifier struct {
	mu      sync.Mutex
	active  bool
	err     error
	calls   int
	session string
}

func (f *fakeSessionVerifier) VerifyActiveSession(_ context.Context, _, sessionID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.session = sessionID
	if f.err != nil {
		return f.err
	}
	if !f.active {
		return errors.New("会话已失效")
	}
	return nil
}

// fakePermissionChecker 是操作者权限复核替身；allowed 控制事务外判定，
// txDenied 控制事务内终检（模拟“准备后撤销权限”）。
type fakePermissionChecker struct {
	mu         sync.Mutex
	allowed    bool
	err        error
	txDenied   bool
	calls      int
	permission string
}

func (f *fakePermissionChecker) CheckOperationPermission(_ context.Context,
	_, permissionKey string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.permission = permissionKey
	if f.err != nil {
		return f.err
	}
	if !f.allowed {
		return errors.New("未授予该权限")
	}
	return nil
}

// CheckOperationPermissionTx 模拟事务内权限终检（默认允许；txDenied 可注入拒绝）。
func (f *fakePermissionChecker) CheckOperationPermissionTx(_ context.Context, _ audit.Tx,
	_, permissionKey string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.permission = permissionKey
	if f.err != nil {
		return f.err
	}
	if f.txDenied {
		return errors.New("权限已被撤销")
	}
	return nil
}

type proofTestEnv struct {
	*testEnv
	session  *fakeSessionVerifier
	perm     *fakePermissionChecker
	webauthn *fakeWebAuthnFactor
	sealer   *secrets.Sealer
	options  reauth.Options
}

// newProofTestEnv 构造启用 strong 强度、真实加密器与受控强因素/会话/权限替身的
// reauth 测试环境；不改动生产代码路径。
func newProofTestEnv(t *testing.T, mutate func(*reauth.Options)) *proofTestEnv {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(testutil.TempDir(t), "reauth-proof-test.db")
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
	sealer, err := secrets.NewSealer(keyring,
		slog.New(slog.NewTextHandler(discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError})))
	if err != nil {
		t.Fatalf("加密器: %v", err)
	}
	policyStore, err := policysqlite.New(storage)
	if err != nil {
		t.Fatalf("策略存储: %v", err)
	}
	env := &testEnv{t: t, ctx: ctx, storage: storage, recorder: recorder,
		now: time.Now().UTC(), verifier: &fakeVerifier{secret: proofPassword,
			complete: true, completedAt: time.Now().UTC()}}
	strengths := []policy.Strength{policy.StrengthNone, policy.StrengthPassword, policy.StrengthStrong}
	policyService, err := policy.New(policy.Options{
		Store: policyStore, Audit: recorder, AvailableStrengths: strengths,
		ReauthVerifier: policy.ReauthVerifierFunc(func(context.Context, policy.Caller, string) error {
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
	strong := &fakeStrongFactor{code: proofTOTP}
	options := reauth.Options{
		Store: reauthStore, Audit: recorder, Policy: policyService,
		Passwords: env.verifier, StrongFactors: strong,
		IntentSealer:       sealer,
		AvailableStrengths: strengths,
		Mailer: mailer.SenderFunc(func(context.Context, mailer.Message) error {
			return nil
		}),
		FromAddress: "security@example.com", AppName: "登录服务",
		SupportURL: "https://example.com/support",
		Now:        func() time.Time { return env.now },
		Logger:     slog.New(slog.NewTextHandler(discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError})),
	}
	if mutate != nil {
		mutate(&options)
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
	session := &fakeSessionVerifier{active: true}
	perm := &fakePermissionChecker{allowed: true}
	webauthn := &fakeWebAuthnFactor{verified: true}
	service.SetSessionVerifier(session)
	service.SetPermissionChecker(perm)
	service.SetStrongWebAuthn(webauthn)
	return &proofTestEnv{testEnv: env, session: session, perm: perm,
		webauthn: webauthn, sealer: sealer, options: options}
}

// discardWriter 丢弃日志输出。
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// beginUsernameProof 为“直接修改他人用户名”创建并完成密码+TOTP 两步验证。
func (e *proofTestEnv) beginUsernameProof(t *testing.T, sessionID, username string) (
	reauth.ApprovalGrant, string) {
	t.Helper()
	caller := e.userCaller(t, normalUserID)
	challenge, err := e.service.BeginChallenge(e.ctx, caller, reauth.ChallengeRequest{
		ScopeID: "system", OperationID: policy.OperationDirectUsernameChange,
		TargetType: "user", TargetID: directTargetUserID,
		Description: "直接修改他人用户名", RequestID: "req-255-begin",
		MinimumStrength: policy.StrengthStrong,
		SessionID:       sessionID,
		Intent:          &reauth.Intent{Kind: reauth.IntentUsername, Username: username},
	})
	if err != nil {
		t.Fatalf("创建直接管理挑战: %v", err)
	}
	if !challenge.Required || challenge.RequiredStrength != policy.StrengthStrong {
		t.Fatalf("挑战要求强度 = %q，期望 strong", challenge.RequiredStrength)
	}
	grant, err := e.service.VerifyChallenge(e.ctx, caller, reauth.VerifyChallengeRequest{
		ChallengeID: challenge.ID, Password: proofPassword, TOTPCode: proofTOTP,
		SessionID: sessionID, RequestID: "req-255-verify",
	})
	if err != nil {
		t.Fatalf("完成两步验证: %v", err)
	}
	// 事务内会话终检读取真实 sessions 行（与生产一致），测试在共享库中写入合成会话；
	// 只用于本用例的 deterministic 会话状态，不改变会话服务生产路径。
	e.seedSession(t, normalUserID, sessionID)
	return grant, challenge.ID
}

// seedSession 在测试库写入一条与账户安全版本一致的正常会话行（合成会话，不含秘密）。
func (e *proofTestEnv) seedSession(t *testing.T, userID, sessionID string) {
	t.Helper()
	var securityVersion int64
	if err := e.storage.DB().QueryRowContext(e.ctx,
		`SELECT security_version FROM users WHERE id=?`, userID).Scan(&securityVersion); err != nil {
		t.Fatalf("读取账户安全版本: %v", err)
	}
	nowMS := e.now.UTC().UnixMilli()
	digest := make([]byte, 32)
	if _, err := rand.Read(digest); err != nil {
		t.Fatalf("生成会话摘要: %v", err)
	}
	if _, err := e.storage.DB().ExecContext(e.ctx, `INSERT INTO sessions(
id,user_id,kind,security_version,secret_digest,csrf_digest,key_id,
created_at_ms,last_seen_at_ms,idle_expires_at_ms,absolute_expires_at_ms
) VALUES(?,?,'normal',?,?,?,'k1',?,?,?,?)`,
		sessionID, userID, securityVersion, digest, digest, nowMS, nowMS,
		nowMS+int64(time.Hour/time.Millisecond), nowMS+int64(24*time.Hour/time.Millisecond)); err != nil {
		t.Fatalf("写入合成会话: %v", err)
	}
}

// prepareUsernameProof 在事务外准备“直接修改他人用户名”的证明消费。
func (e *proofTestEnv) prepareUsernameProof(t *testing.T, sessionID, token, username,
	targetID, paramsDigestSalt string) (reauth.PreparedProof, error) {
	t.Helper()
	caller := e.userCaller(t, normalUserID)
	params := map[string]string{}
	if paramsDigestSalt != "" {
		params["salt"] = paramsDigestSalt
	}
	return e.service.PrepareProof(e.ctx, caller, reauth.ConsumeProofRequest{
		ProofToken: token, ScopeID: "system",
		OperationID: policy.OperationDirectUsernameChange,
		TargetType:  "user", TargetID: targetID, Params: params,
		SessionID: sessionID,
		Intent:    &reauth.Intent{Kind: reauth.IntentUsername, Username: username},
		RequestID: "req-255-consume",
	})
}

// consumeUsernameProof 在同一审计事务内消费已准备好的证明并写入一条合成业务变更。
func (e *proofTestEnv) consumeUsernameProof(t *testing.T, sessionID, token, username,
	targetID, paramsDigestSalt string) (reauth.ProofResult, error) {
	t.Helper()
	caller := e.userCaller(t, normalUserID)
	prepared, prepareErr := e.prepareUsernameProof(t, sessionID, token, username,
		targetID, paramsDigestSalt)
	if prepareErr != nil {
		return reauth.ProofResult{}, prepareErr
	}
	var result reauth.ProofResult
	err := e.recorder.ExecuteCritical(e.ctx, audit.CriticalRequest{
		Event: audit.Event{
			Actor: caller.Actor(), Action: "test.direct_username_change",
			Target:    audit.Target{Type: "user", ID: targetID},
			RequestID: "req-255-consume",
		},
		FailureReasonCode: "test.direct_username_change_failed",
	}, func(txCtx context.Context, tx audit.Tx) error {
		consumed, consumeErr := e.service.ConsumePreparedProofTx(txCtx, tx, caller, prepared)
		if consumeErr != nil {
			return consumeErr
		}
		result = consumed
		// 合成业务写入：证明消费与业务变更同事务提交/回滚。
		if _, err := tx.ExecContext(txCtx,
			`UPDATE users SET nickname=? WHERE id=?`, "renamed-by-proof", targetID); err != nil {
			return err
		}
		return nil
	})
	return result, err
}

// TestDirectProofHappyPathSingleUseAndNoSecretLeak 覆盖直接管理证明的成功链：
// 绑定与签发、密封存储、同事务消费、单次使用、合成业务写入与审计不泄漏新值。
func TestDirectProofHappyPathSingleUseAndNoSecretLeak(t *testing.T) {
	env := newProofTestEnv(t, nil)
	sessionID := newSessionID(t)
	grant, challengeID := env.beginUsernameProof(t, sessionID, "new.username")
	if grant.SessionID != sessionID || grant.GrantedStrength != policy.StrengthStrong {
		t.Fatalf("批准绑定异常: %+v", grant)
	}
	// 挑战与批准上的意图只保存密封密文：数据库无明文、无无密钥摘要。
	var challengeSealed, approvalSealed []byte
	if err := env.storage.DB().QueryRowContext(env.ctx,
		`SELECT intent_sealed FROM reauth_challenges WHERE id=?`, challengeID).
		Scan(&challengeSealed); err != nil {
		t.Fatalf("读取挑战密文: %v", err)
	}
	if len(challengeSealed) == 0 || bytes.Contains(challengeSealed, []byte("new.username")) {
		t.Fatalf("挑战意图未正确密封（len=%d）", len(challengeSealed))
	}
	var approvalID string
	if err := env.storage.DB().QueryRowContext(env.ctx,
		`SELECT id,intent_sealed FROM reauth_approvals WHERE challenge_id=?`, challengeID).
		Scan(&approvalID, &approvalSealed); err != nil {
		t.Fatalf("读取批准密文: %v", err)
	}
	if len(approvalSealed) == 0 || bytes.Contains(approvalSealed, []byte("new.username")) {
		t.Fatalf("批准意图未正确密封（len=%d）", len(approvalSealed))
	}
	result, err := env.consumeUsernameProof(t, sessionID, grant.Token, "new.username",
		directTargetUserID, "")
	if err != nil {
		t.Fatalf("消费目标绑定证明: %v", err)
	}
	if result.Intent.Kind != reauth.IntentUsername || result.Intent.Username != "new.username" {
		t.Fatalf("证明返回意图异常: %+v", result.Intent)
	}
	if result.TargetID != directTargetUserID || result.SessionID != sessionID {
		t.Fatalf("证明返回绑定异常: %+v", result)
	}
	// 合成业务写入与证明消费一起提交。
	var nickname string
	if err := env.storage.DB().QueryRowContext(env.ctx,
		`SELECT nickname FROM users WHERE id=?`, directTargetUserID).Scan(&nickname); err != nil {
		t.Fatalf("读取业务写入: %v", err)
	}
	if nickname != "renamed-by-proof" {
		t.Fatalf("业务写入未提交: %q", nickname)
	}
	// 消费后密文被清空。
	var cleared []byte
	if err := env.storage.DB().QueryRowContext(env.ctx,
		`SELECT intent_sealed FROM reauth_approvals WHERE id=?`, approvalID).Scan(&cleared); err != nil {
		t.Fatalf("读取消费后密文: %v", err)
	}
	if len(cleared) != 0 {
		t.Fatalf("消费后意图密文未清空（len=%d）", len(cleared))
	}
	// 审计含证明消费事件且不含新值明文。
	if count := env.count(`SELECT COUNT(*) FROM audit_events
WHERE action='reauth.operation_proof_consumed' AND outcome='success'`); count != 1 {
		t.Errorf("证明消费成功审计数 = %d，期望 1", count)
	}
	rows, err := env.storage.DB().QueryContext(env.ctx, `SELECT COALESCE(detail_json,'') FROM audit_events`)
	if err != nil {
		t.Fatalf("读取审计: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var detail string
		if err := rows.Scan(&detail); err != nil {
			t.Fatalf("扫描审计: %v", err)
		}
		if strings.Contains(detail, "new.username") || strings.Contains(detail, proofPassword) {
			t.Error("审计泄露新值/口令明文")
		}
	}
	// 成功后重放：不二次执行。
	if _, replayErr := env.consumeUsernameProof(t, sessionID, grant.Token, "new.username",
		directTargetUserID, ""); !errors.Is(replayErr, reauth.ErrApprovalConsumed) {
		t.Fatalf("重放错误 = %v，期望 ErrApprovalConsumed", replayErr)
	}
	if count := env.count(`SELECT COUNT(*) FROM audit_events
WHERE action='test.direct_username_change' AND outcome='success'`); count != 1 {
		t.Errorf("重放不得产生第二次业务成功审计，实际 %d", count)
	}
}

// TestDirectProofBindingRejections 覆盖换会话/换目标/换新值/参数不符/权限撤销/
// 会话失效/过期/取消等拒绝边界。
func TestDirectProofBindingRejections(t *testing.T) {
	type testCase struct {
		name       string
		mutate     func(t *testing.T, env *proofTestEnv, sessionID string, grant *reauth.ApprovalGrant)
		consume    func(t *testing.T, env *proofTestEnv, sessionID string, grant reauth.ApprovalGrant) error
		wantErr    error
		wantErrAlt error
	}
	cases := []testCase{
		{
			name: "换会话",
			consume: func(t *testing.T, env *proofTestEnv, _ string, grant reauth.ApprovalGrant) error {
				_, err := env.consumeUsernameProof(t, newSessionID(t), grant.Token,
					"new.username", directTargetUserID, "")
				return err
			},
			wantErr: reauth.ErrSessionMismatch,
		},
		{
			name: "换目标",
			consume: func(t *testing.T, env *proofTestEnv, sessionID string, grant reauth.ApprovalGrant) error {
				_, err := env.consumeUsernameProof(t, sessionID, grant.Token,
					"new.username", rootUserID, "")
				return err
			},
			wantErr: reauth.ErrProofBindingMismatch,
		},
		{
			name: "换新用户名",
			consume: func(t *testing.T, env *proofTestEnv, sessionID string, grant reauth.ApprovalGrant) error {
				_, err := env.consumeUsernameProof(t, sessionID, grant.Token,
					"other.username", directTargetUserID, "")
				return err
			},
			wantErr: reauth.ErrProofBindingMismatch,
		},
		{
			name: "换参数摘要",
			consume: func(t *testing.T, env *proofTestEnv, sessionID string, grant reauth.ApprovalGrant) error {
				_, err := env.consumeUsernameProof(t, sessionID, grant.Token,
					"new.username", directTargetUserID, "different")
				return err
			},
			wantErr: reauth.ErrProofBindingMismatch,
		},
		{
			name: "权限撤销",
			mutate: func(_ *testing.T, env *proofTestEnv, _ string, _ *reauth.ApprovalGrant) {
				env.perm.mu.Lock()
				env.perm.allowed = false
				env.perm.mu.Unlock()
			},
			consume: func(t *testing.T, env *proofTestEnv, sessionID string, grant reauth.ApprovalGrant) error {
				_, err := env.consumeUsernameProof(t, sessionID, grant.Token,
					"new.username", directTargetUserID, "")
				return err
			},
			wantErr: reauth.ErrAccessDenied,
		},
		{
			name: "会话失效",
			mutate: func(_ *testing.T, env *proofTestEnv, _ string, _ *reauth.ApprovalGrant) {
				env.session.mu.Lock()
				env.session.active = false
				env.session.mu.Unlock()
			},
			consume: func(t *testing.T, env *proofTestEnv, sessionID string, grant reauth.ApprovalGrant) error {
				_, err := env.consumeUsernameProof(t, sessionID, grant.Token,
					"new.username", directTargetUserID, "")
				return err
			},
			wantErr: reauth.ErrSessionMismatch,
		},
		{
			name: "批准过期",
			mutate: func(_ *testing.T, env *proofTestEnv, _ string, _ *reauth.ApprovalGrant) {
				env.now = env.now.Add(3 * time.Minute)
			},
			consume: func(t *testing.T, env *proofTestEnv, sessionID string, grant reauth.ApprovalGrant) error {
				_, err := env.consumeUsernameProof(t, sessionID, grant.Token,
					"new.username", directTargetUserID, "")
				return err
			},
			wantErr: reauth.ErrApprovalExpired,
		},
		{
			name: "旧行缺少会话绑定",
			mutate: func(t *testing.T, env *proofTestEnv, _ string, _ *reauth.ApprovalGrant) {
				if _, err := env.storage.DB().ExecContext(env.ctx,
					`UPDATE reauth_approvals SET session_id=NULL`); err != nil {
					t.Fatalf("注入旧行: %v", err)
				}
			},
			consume: func(t *testing.T, env *proofTestEnv, sessionID string, grant reauth.ApprovalGrant) error {
				_, err := env.consumeUsernameProof(t, sessionID, grant.Token,
					"new.username", directTargetUserID, "")
				return err
			},
			wantErr: reauth.ErrSessionMismatch,
		},
		{
			name: "旧行缺少意图绑定",
			mutate: func(t *testing.T, env *proofTestEnv, _ string, _ *reauth.ApprovalGrant) {
				if _, err := env.storage.DB().ExecContext(env.ctx,
					`UPDATE reauth_approvals SET intent_sealed=NULL`); err != nil {
					t.Fatalf("注入旧行: %v", err)
				}
			},
			consume: func(t *testing.T, env *proofTestEnv, sessionID string, grant reauth.ApprovalGrant) error {
				_, err := env.consumeUsernameProof(t, sessionID, grant.Token,
					"new.username", directTargetUserID, "")
				return err
			},
			wantErr: reauth.ErrApprovalInvalid,
		},
	}
	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			env := newProofTestEnv(t, nil)
			sessionID := newSessionID(t)
			grant, _ := env.beginUsernameProof(t, sessionID, "new.username")
			if testCase.mutate != nil {
				testCase.mutate(t, env, sessionID, &grant)
			}
			err := testCase.consume(t, env, sessionID, grant)
			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("拒绝错误 = %v，期望 %v", err, testCase.wantErr)
			}
		})
	}
}

// TestDirectProofWrongFactors 覆盖错误密码/错误动态码/缺少第二因素：不产生可用证明。
func TestDirectProofWrongFactors(t *testing.T) {
	env := newProofTestEnv(t, nil)
	sessionID := newSessionID(t)
	caller := env.userCaller(t, normalUserID)
	challenge, err := env.service.BeginChallenge(env.ctx, caller, reauth.ChallengeRequest{
		ScopeID: "system", OperationID: policy.OperationDirectUsernameChange,
		TargetType: "user", TargetID: directTargetUserID, SessionID: sessionID,
		Intent:          &reauth.Intent{Kind: reauth.IntentUsername, Username: "new.username"},
		MinimumStrength: policy.StrengthStrong, RequestID: "req-255-factor",
	})
	if err != nil {
		t.Fatalf("创建挑战: %v", err)
	}
	if _, err := env.service.VerifyChallenge(env.ctx, caller, reauth.VerifyChallengeRequest{
		ChallengeID: challenge.ID, Password: "wrong-password", TOTPCode: proofTOTP,
		SessionID: sessionID}); !errors.Is(err, reauth.ErrAuthenticationFailed) {
		t.Fatalf("错误密码 = %v，期望 ErrAuthenticationFailed", err)
	}
	if _, err := env.service.VerifyChallenge(env.ctx, caller, reauth.VerifyChallengeRequest{
		ChallengeID: challenge.ID, Password: proofPassword, TOTPCode: "000000",
		SessionID: sessionID}); !errors.Is(err, reauth.ErrAuthenticationFailed) {
		t.Fatalf("错误动态码 = %v，期望 ErrAuthenticationFailed", err)
	}
	if _, err := env.service.VerifyChallenge(env.ctx, caller, reauth.VerifyChallengeRequest{
		ChallengeID: challenge.ID, Password: proofPassword, TOTPCode: "",
		SessionID: sessionID}); !errors.Is(err, reauth.ErrMFARequired) {
		t.Fatalf("缺少第二因素 = %v，期望 ErrMFARequired", err)
	}
	// 尝试次数仍在上限内，正确因素后仍可完成（不因失败被误烧）。
	if _, err := env.service.VerifyChallenge(env.ctx, caller, reauth.VerifyChallengeRequest{
		ChallengeID: challenge.ID, Password: proofPassword, TOTPCode: proofTOTP,
		SessionID: sessionID}); err != nil {
		t.Fatalf("恢复正确因素后完成验证失败: %v", err)
	}
}

// TestDirectProofSessionMismatchOnVerify 覆盖验证阶段会话不符：即使凭证正确也拒绝。
func TestDirectProofSessionMismatchOnVerify(t *testing.T) {
	env := newProofTestEnv(t, nil)
	sessionID := newSessionID(t)
	caller := env.userCaller(t, normalUserID)
	challenge, err := env.service.BeginChallenge(env.ctx, caller, reauth.ChallengeRequest{
		ScopeID: "system", OperationID: policy.OperationDirectUsernameChange,
		TargetType: "user", TargetID: directTargetUserID, SessionID: sessionID,
		Intent:          &reauth.Intent{Kind: reauth.IntentUsername, Username: "new.username"},
		MinimumStrength: policy.StrengthStrong, RequestID: "req-255-session",
	})
	if err != nil {
		t.Fatalf("创建挑战: %v", err)
	}
	if _, err := env.service.VerifyChallenge(env.ctx, caller, reauth.VerifyChallengeRequest{
		ChallengeID: challenge.ID, Password: proofPassword, TOTPCode: proofTOTP,
		SessionID: newSessionID(t)}); !errors.Is(err, reauth.ErrSessionMismatch) {
		t.Fatalf("验证会话不符 = %v，期望 ErrSessionMismatch", err)
	}
}

// TestDirectProofPermissionRevokedAtBegin 覆盖发起阶段缺少权限：不创建挑战。
func TestDirectProofPermissionRevokedAtBegin(t *testing.T) {
	env := newProofTestEnv(t, nil)
	env.perm.mu.Lock()
	env.perm.allowed = false
	env.perm.mu.Unlock()
	sessionID := newSessionID(t)
	caller := env.userCaller(t, normalUserID)
	_, err := env.service.BeginChallenge(env.ctx, caller, reauth.ChallengeRequest{
		ScopeID: "system", OperationID: policy.OperationDirectUsernameChange,
		TargetType: "user", TargetID: directTargetUserID, SessionID: sessionID,
		Intent:          &reauth.Intent{Kind: reauth.IntentUsername, Username: "new.username"},
		MinimumStrength: policy.StrengthStrong, RequestID: "req-255-noperm",
	})
	if !errors.Is(err, reauth.ErrAccessDenied) {
		t.Fatalf("缺权限发起 = %v，期望 ErrAccessDenied", err)
	}
	if count := env.count(`SELECT COUNT(*) FROM reauth_challenges`); count != 0 {
		t.Errorf("缺权限不应创建挑战，实际 %d", count)
	}
}

// TestDirectProofMissingDependenciesFailClosed 覆盖意图加密/会话/权限依赖未接线时的
// fail-closed：直接管理证明不可用，普通敏感操作不受影响。
func TestDirectProofMissingDependenciesFailClosed(t *testing.T) {
	// 未配置意图加密器：发起阶段拒绝。
	noSealer := newProofTestEnv(t, func(options *reauth.Options) {
		options.IntentSealer = nil
	})
	sessionID := newSessionID(t)
	caller := noSealer.userCaller(t, normalUserID)
	if _, err := noSealer.service.BeginChallenge(noSealer.ctx, caller, reauth.ChallengeRequest{
		ScopeID: "system", OperationID: policy.OperationDirectUsernameChange,
		TargetType: "user", TargetID: directTargetUserID, SessionID: sessionID,
		Intent:          &reauth.Intent{Kind: reauth.IntentUsername, Username: "new.username"},
		MinimumStrength: policy.StrengthStrong, RequestID: "req-255-nosealer",
	}); !errors.Is(err, reauth.ErrProofUnavailable) {
		t.Fatalf("未配置加密器发起 = %v，期望 ErrProofUnavailable", err)
	}
	// 未接线会话校验：消费阶段拒绝（证明不被烧毁）。
	env := newProofTestEnv(t, nil)
	env.service.SetSessionVerifier(nil)
	sessionID = newSessionID(t)
	grant, _ := env.beginUsernameProof(t, sessionID, "new.username")
	if _, err := env.consumeUsernameProof(t, sessionID, grant.Token, "new.username",
		directTargetUserID, ""); !errors.Is(err, reauth.ErrProofUnavailable) {
		t.Fatalf("未接线会话校验消费 = %v，期望 ErrProofUnavailable", err)
	}
	if count := env.count(`SELECT COUNT(*) FROM reauth_approvals WHERE consumed_at_ms IS NOT NULL`); count != 0 {
		t.Errorf("依赖缺失时证明不应被消费，实际 %d", count)
	}
}

// TestDirectProofLegacyPathsFailClosed 覆盖旧路径兜底：
//   - Authorize 收到伪造 context 信号对直接管理操作一律拒绝；
//   - 直接管理操作不能使用旧的“免会话/意图”批准消费路径。
func TestDirectProofLegacyPathsFailClosed(t *testing.T) {
	env := newProofTestEnv(t, nil)
	caller := env.userCaller(t, normalUserID)
	signals := reauth.WithSignals(env.ctx, reauth.Signals{
		VerifiedAt: env.now.Add(-time.Second), Strength: policy.StrengthStrong,
		Complete: true, Confirmed: true,
	})
	if _, err := env.service.Authorize(signals, caller, reauth.Request{
		ScopeID: "system", OperationID: policy.OperationDirectUsernameChange,
		TargetType: "user", TargetID: directTargetUserID, RequestID: "req-255-forged",
	}); !errors.Is(err, reauth.ErrReauthRequired) {
		t.Fatalf("伪造上下文信号错误 = %v，期望 ErrReauthRequired", err)
	}
	// 旧批准路径不能消费直接管理操作的证明（必须走 ConsumeProofTx）。
	if _, err := env.service.Authorize(reauth.WithSignals(env.ctx, reauth.Signals{
		VerifiedAt: env.now, Strength: policy.StrengthStrong, Complete: true,
		Confirmed: true, ApprovalToken: strings.Repeat("a", 64),
	}), caller, reauth.Request{
		ScopeID: "system", OperationID: policy.OperationDirectPasswordReset,
		TargetType: "user", TargetID: directTargetUserID, RequestID: "req-255-legacy",
	}); !errors.Is(err, reauth.ErrReauthRequired) {
		t.Fatalf("旧批准路径错误 = %v，期望 ErrReauthRequired", err)
	}
}

// TestDirectProofCommitFailureKeepsProofRetryable 验证消费所在的业务事务回滚后，
// 证明未被烧毁、可重试成功；成功后重放被拒绝。
func TestDirectProofCommitFailureKeepsProofRetryable(t *testing.T) {
	env := newProofTestEnv(t, nil)
	sessionID := newSessionID(t)
	grant, _ := env.beginUsernameProof(t, sessionID, "new.username")
	caller := env.userCaller(t, normalUserID)
	prepared, prepareErr := env.prepareUsernameProof(t, sessionID, grant.Token,
		"new.username", directTargetUserID, "")
	if prepareErr != nil {
		t.Fatalf("事务外准备证明: %v", prepareErr)
	}
	// 第一次：消费后主动返回错误，整笔事务回滚。
	commitErr := errors.New("注入的业务提交失败")
	firstErr := env.recorder.ExecuteCritical(env.ctx, audit.CriticalRequest{
		Event: audit.Event{Actor: caller.Actor(), Action: "test.direct_username_change",
			Target:    audit.Target{Type: "user", ID: directTargetUserID},
			RequestID: "req-255-commitfail"},
		FailureReasonCode: "test_failed",
	}, func(txCtx context.Context, tx audit.Tx) error {
		if _, err := env.service.ConsumePreparedProofTx(txCtx, tx, caller, prepared); err != nil {
			return err
		}
		return commitErr
	})
	if !errors.Is(firstErr, commitErr) {
		t.Fatalf("注入提交失败错误 = %v，期望包裹注入错误", firstErr)
	}
	// 回滚后批准仍可用、密文仍在。
	var consumed bool
	var sealedLen int
	if err := env.storage.DB().QueryRowContext(env.ctx,
		`SELECT consumed_at_ms IS NOT NULL,COALESCE(length(intent_sealed),0)
		 FROM reauth_approvals WHERE challenge_id IN
		 (SELECT id FROM reauth_challenges WHERE operation_id=?) ORDER BY rowid DESC LIMIT 1`,
		policy.OperationDirectUsernameChange).Scan(&consumed, &sealedLen); err != nil {
		t.Fatalf("读取批准状态: %v", err)
	}
	if consumed || sealedLen == 0 {
		t.Fatalf("提交失败后批准被烧毁: consumed=%v sealedLen=%d", consumed, sealedLen)
	}
	// 重试同一证明成功。
	if _, err := env.consumeUsernameProof(t, sessionID, grant.Token, "new.username",
		directTargetUserID, ""); err != nil {
		t.Fatalf("提交失败后重试成功路径: %v", err)
	}
	if _, err := env.consumeUsernameProof(t, sessionID, grant.Token, "new.username",
		directTargetUserID, ""); !errors.Is(err, reauth.ErrApprovalConsumed) {
		t.Fatalf("重试成功后重放 = %v，期望 ErrApprovalConsumed", err)
	}
}

// TestDirectProofConcurrentConsumeSingleWinner 验证并发消费同一证明只有一个赢家。
func TestDirectProofConcurrentConsumeSingleWinner(t *testing.T) {
	env := newProofTestEnv(t, nil)
	sessionID := newSessionID(t)
	grant, _ := env.beginUsernameProof(t, sessionID, "new.username")
	caller := env.userCaller(t, normalUserID)
	prepared, prepareErr := env.prepareUsernameProof(t, sessionID, grant.Token,
		"new.username", directTargetUserID, "")
	if prepareErr != nil {
		t.Fatalf("事务外准备证明: %v", prepareErr)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var waitGroup sync.WaitGroup
	for index := 0; index < 2; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			_, err := func() (reauth.ProofResult, error) {
				var result reauth.ProofResult
				err := env.recorder.ExecuteCritical(env.ctx, audit.CriticalRequest{
					Event: audit.Event{Actor: caller.Actor(),
						Action:    "test.direct_username_change",
						Target:    audit.Target{Type: "user", ID: directTargetUserID},
						RequestID: "req-255-concurrent"},
					FailureReasonCode: "test_failed",
				}, func(txCtx context.Context, tx audit.Tx) error {
					consumed, consumeErr := env.service.ConsumePreparedProofTx(txCtx, tx,
						caller, prepared)
					if consumeErr != nil {
						return consumeErr
					}
					result = consumed
					return nil
				})
				return result, err
			}()
			results <- err
		}()
	}
	close(start)
	waitGroup.Wait()
	close(results)
	successes, consumed := 0, 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, reauth.ErrApprovalConsumed), errors.Is(err, reauth.ErrApprovalInvalid):
			consumed++
		default:
			t.Fatalf("并发消费未知错误: %v", err)
		}
	}
	if successes != 1 || consumed != 1 {
		t.Fatalf("并发消费 = 成功 %d / 已消费 %d，期望 1/1", successes, consumed)
	}
}

// TestDirectProofCancelChallenge 验证取消后不能完成验证、不产生证明。
func TestDirectProofCancelChallenge(t *testing.T) {
	env := newProofTestEnv(t, nil)
	sessionID := newSessionID(t)
	caller := env.userCaller(t, normalUserID)
	challenge, err := env.service.BeginChallenge(env.ctx, caller, reauth.ChallengeRequest{
		ScopeID: "system", OperationID: policy.OperationDirectPasswordReset,
		TargetType: "user", TargetID: directTargetUserID, SessionID: sessionID,
		Intent:          &reauth.Intent{Kind: reauth.IntentPassword, Password: "NewSecret!9876"},
		MinimumStrength: policy.StrengthStrong, RequestID: "req-255-cancel",
	})
	if err != nil {
		t.Fatalf("创建挑战: %v", err)
	}
	if err := env.service.CancelChallenge(env.ctx, caller, challenge.ID); err != nil {
		t.Fatalf("取消挑战: %v", err)
	}
	if _, err := env.service.VerifyChallenge(env.ctx, caller, reauth.VerifyChallengeRequest{
		ChallengeID: challenge.ID, Password: proofPassword, TOTPCode: proofTOTP,
		SessionID: sessionID}); !errors.Is(err, reauth.ErrChallengeInvalid) {
		t.Fatalf("取消后验证 = %v，期望 ErrChallengeInvalid", err)
	}
	if count := env.count(`SELECT COUNT(*) FROM reauth_approvals`); count != 0 {
		t.Errorf("取消后不应产生批准，实际 %d", count)
	}
}

// TestDirectProofPasswordIntentSealedAndMatched 覆盖密码意图：
//   - 密码只以密封密文保存（数据库无明文）；
//   - 提交不同新口令拒绝；
//   - 正确新口令可完成证明消费。
func TestDirectProofPasswordIntentSealedAndMatched(t *testing.T) {
	env := newProofTestEnv(t, nil)
	sessionID := newSessionID(t)
	const newPassword = "Qz7!vN9#Lp2@Rm5"
	caller := env.userCaller(t, rootUserID) // root 作为操作者：同样走真实两步验证
	challenge, err := env.service.BeginChallenge(env.ctx, caller, reauth.ChallengeRequest{
		ScopeID: "system", OperationID: policy.OperationDirectPasswordReset,
		TargetType: "user", TargetID: directTargetUserID, SessionID: sessionID,
		Intent:          &reauth.Intent{Kind: reauth.IntentPassword, Password: newPassword},
		MinimumStrength: policy.StrengthStrong, RequestID: "req-255-password",
	})
	if err != nil {
		t.Fatalf("root 创建直接重置挑战: %v", err)
	}
	grant, err := env.service.VerifyChallenge(env.ctx, caller, reauth.VerifyChallengeRequest{
		ChallengeID: challenge.ID, Password: proofPassword, TOTPCode: proofTOTP,
		SessionID: sessionID, RequestID: "req-255-password-verify",
	})
	if err != nil {
		t.Fatalf("root 完成两步验证: %v", err)
	}
	env.seedSession(t, rootUserID, sessionID)
	// 数据库无口令明文；密文长度非零。
	var sealed []byte
	if err := env.storage.DB().QueryRowContext(env.ctx,
		`SELECT intent_sealed FROM reauth_approvals WHERE challenge_id=?`,
		challenge.ID).Scan(&sealed); err != nil {
		t.Fatalf("读取密码意图密文: %v", err)
	}
	if len(sealed) == 0 || bytes.Contains(sealed, []byte(newPassword)) {
		t.Fatalf("密码意图未正确密封（len=%d）", len(sealed))
	}
	// 换新口令拒绝。
	var result reauth.ProofResult
	consume := func(password string) error {
		prepared, prepareErr := env.service.PrepareProof(env.ctx, caller,
			reauth.ConsumeProofRequest{
				ProofToken: grant.Token, ScopeID: "system",
				OperationID: policy.OperationDirectPasswordReset,
				TargetType:  "user", TargetID: directTargetUserID,
				SessionID: sessionID,
				Intent: &reauth.Intent{Kind: reauth.IntentPassword,
					Password: password},
				RequestID: "req-255-password-consume",
			})
		if prepareErr != nil {
			return prepareErr
		}
		err := env.recorder.ExecuteCritical(env.ctx, audit.CriticalRequest{
			Event: audit.Event{Actor: caller.Actor(), Action: "test.direct_password_reset",
				Target:    audit.Target{Type: "user", ID: directTargetUserID},
				RequestID: "req-255-password-consume"},
			FailureReasonCode: "test_failed",
		}, func(txCtx context.Context, tx audit.Tx) error {
			consumed, consumeErr := env.service.ConsumePreparedProofTx(txCtx, tx,
				caller, prepared)
			if consumeErr != nil {
				return consumeErr
			}
			result = consumed
			return nil
		})
		return err
	}
	if err := consume("Different!Pass99"); !errors.Is(err, reauth.ErrProofBindingMismatch) {
		t.Fatalf("换新口令 = %v，期望 ErrProofBindingMismatch", err)
	}
	if err := consume(newPassword); err != nil {
		t.Fatalf("正确新口令消费证明: %v", err)
	}
	if result.Intent.Password != newPassword || result.Intent.Kind != reauth.IntentPassword {
		t.Fatalf("证明意图异常: %+v", result.Intent)
	}
}

// TestDirectProofWebAuthnPath 覆盖 WebAuthn 第二步路径（无密码 Passkey 账户不必提供
// 密码）：开始/完成断言后签发强认证批准并可消费。
func TestDirectProofWebAuthnPath(t *testing.T) {
	env := newProofTestEnv(t, nil)
	sessionID := newSessionID(t)
	caller := env.userCaller(t, normalUserID)
	challenge, err := env.service.BeginChallenge(env.ctx, caller, reauth.ChallengeRequest{
		ScopeID: "system", OperationID: policy.OperationDirectPasswordReset,
		TargetType: "user", TargetID: directTargetUserID, SessionID: sessionID,
		Intent:          &reauth.Intent{Kind: reauth.IntentPassword, Password: "NewSecret!9876"},
		MinimumStrength: policy.StrengthStrong, RequestID: "req-255-webauthn",
	})
	if err != nil {
		t.Fatalf("创建挑战: %v", err)
	}
	start, err := env.service.BeginWebAuthnChallenge(env.ctx, caller,
		reauth.BeginWebAuthnChallengeRequest{
			ChallengeID: challenge.ID, SessionID: sessionID, RequestID: "req-255-webauthn-begin",
		})
	if err != nil {
		t.Fatalf("开始 WebAuthn 第二步: %v", err)
	}
	if start.CeremonyID == "" || len(start.PublicKey) == 0 {
		t.Fatalf("WebAuthn 开始结果异常: %+v", start)
	}
	grant, err := env.service.FinishWebAuthnChallenge(env.ctx, caller,
		reauth.FinishWebAuthnChallengeRequest{
			ChallengeID: challenge.ID, SessionID: sessionID,
			CeremonyID: start.CeremonyID, Response: []byte(`{"id":"x"}`),
			RequestID: "req-255-webauthn-finish",
		})
	if err != nil {
		t.Fatalf("完成 WebAuthn 第二步: %v", err)
	}
	if grant.GrantedStrength != policy.StrengthStrong || grant.SessionID != sessionID {
		t.Fatalf("WebAuthn 批准异常: %+v", grant)
	}
	env.seedSession(t, normalUserID, sessionID)
	var result reauth.ProofResult
	prepared, prepareErr := env.service.PrepareProof(env.ctx, caller,
		reauth.ConsumeProofRequest{
			ProofToken: grant.Token, ScopeID: "system",
			OperationID: policy.OperationDirectPasswordReset,
			TargetType:  "user", TargetID: directTargetUserID,
			SessionID: sessionID,
			Intent: &reauth.Intent{Kind: reauth.IntentPassword,
				Password: "NewSecret!9876"},
			RequestID: "req-255-webauthn-consume",
		})
	if prepareErr != nil {
		t.Fatalf("事务外准备 WebAuthn 证明: %v", prepareErr)
	}
	err = env.recorder.ExecuteCritical(env.ctx, audit.CriticalRequest{
		Event: audit.Event{Actor: caller.Actor(), Action: "test.direct_password_reset",
			Target:    audit.Target{Type: "user", ID: directTargetUserID},
			RequestID: "req-255-webauthn-consume"},
		FailureReasonCode: "test_failed",
	}, func(txCtx context.Context, tx audit.Tx) error {
		consumed, consumeErr := env.service.ConsumePreparedProofTx(txCtx, tx,
			caller, prepared)
		if consumeErr != nil {
			return consumeErr
		}
		result = consumed
		return nil
	})
	if err != nil || result.Intent.Kind != reauth.IntentPassword {
		t.Fatalf("WebAuthn 证明消费失败: %v result=%+v", err, result)
	}
}

// TestDirectProofWebAuthnRejects 覆盖 WebAuthn 路径的会话不符、非 UV、未接线拒绝。
func TestDirectProofWebAuthnRejects(t *testing.T) {
	// 会话不符：开始阶段拒绝。
	env := newProofTestEnv(t, nil)
	sessionID := newSessionID(t)
	caller := env.userCaller(t, normalUserID)
	challenge, err := env.service.BeginChallenge(env.ctx, caller, reauth.ChallengeRequest{
		ScopeID: "system", OperationID: policy.OperationDirectPasswordReset,
		TargetType: "user", TargetID: directTargetUserID, SessionID: sessionID,
		Intent:          &reauth.Intent{Kind: reauth.IntentPassword, Password: "NewSecret!9876"},
		MinimumStrength: policy.StrengthStrong, RequestID: "req-255-webauthn-reject",
	})
	if err != nil {
		t.Fatalf("创建挑战: %v", err)
	}
	if _, err := env.service.BeginWebAuthnChallenge(env.ctx, caller,
		reauth.BeginWebAuthnChallengeRequest{ChallengeID: challenge.ID,
			SessionID: newSessionID(t)}); !errors.Is(err, reauth.ErrSessionMismatch) {
		t.Fatalf("WebAuthn 会话不符 = %v，期望 ErrSessionMismatch", err)
	}
	// 非 UV：完成阶段拒绝且不产生批准。
	start, err := env.service.BeginWebAuthnChallenge(env.ctx, caller,
		reauth.BeginWebAuthnChallengeRequest{ChallengeID: challenge.ID, SessionID: sessionID})
	if err != nil {
		t.Fatalf("开始 WebAuthn: %v", err)
	}
	env.webauthn.mu.Lock()
	env.webauthn.verified = false
	env.webauthn.mu.Unlock()
	if _, err := env.service.FinishWebAuthnChallenge(env.ctx, caller,
		reauth.FinishWebAuthnChallengeRequest{ChallengeID: challenge.ID,
			SessionID: sessionID, CeremonyID: start.CeremonyID,
			Response: []byte(`{"id":"x"}`)}); !errors.Is(err, reauth.ErrAuthenticationFailed) {
		t.Fatalf("WebAuthn 非 UV = %v，期望 ErrAuthenticationFailed", err)
	}
	if count := env.count(`SELECT COUNT(*) FROM reauth_approvals`); count != 0 {
		t.Errorf("非 UV 不应产生批准，实际 %d", count)
	}
	// 未接线：fail-closed。
	unwired := newProofTestEnv(t, nil)
	unwired.service.SetStrongWebAuthn(nil)
	sessionID = newSessionID(t)
	caller = unwired.userCaller(t, normalUserID)
	challenge, err = unwired.service.BeginChallenge(unwired.ctx, caller, reauth.ChallengeRequest{
		ScopeID: "system", OperationID: policy.OperationDirectPasswordReset,
		TargetType: "user", TargetID: directTargetUserID, SessionID: sessionID,
		Intent:          &reauth.Intent{Kind: reauth.IntentPassword, Password: "NewSecret!9876"},
		MinimumStrength: policy.StrengthStrong, RequestID: "req-255-webauthn-unwired",
	})
	if err != nil {
		t.Fatalf("未接线环境创建挑战: %v", err)
	}
	if _, err := unwired.service.BeginWebAuthnChallenge(unwired.ctx, caller,
		reauth.BeginWebAuthnChallengeRequest{ChallengeID: challenge.ID,
			SessionID: sessionID}); !errors.Is(err, reauth.ErrMFARequired) {
		t.Fatalf("未接线 WebAuthn = %v，期望 ErrMFARequired", err)
	}
}

// TestDirectProofOperationMappingMatchesPolicyCatalog 验证证明层使用的直接管理操作 ID
// 与权限键与步骤 254 的敏感操作目录一致（防止两处常量漂移导致授权/验证错配）。
func TestDirectProofOperationMappingMatchesPolicyCatalog(t *testing.T) {
	env := newProofTestEnv(t, nil)
	cases := []struct {
		operationID   string
		permissionKey string
		kind          reauth.IntentKind
	}{
		{policy.OperationDirectUsernameChange, "users.username.change.other", reauth.IntentUsername},
		{policy.OperationDirectPasswordReset, "users.password.reset.other", reauth.IntentPassword},
	}
	for _, item := range cases {
		operation, found := env.policyService.Operation(item.operationID)
		if !found {
			t.Fatalf("策略目录缺少直接管理操作 %s", item.operationID)
		}
		if operation.ID != item.operationID || operation.PermissionKey != item.permissionKey {
			t.Fatalf("策略目录操作映射不一致: id=%q permission=%q（期望 %q/%q）",
				operation.ID, operation.PermissionKey, item.operationID, item.permissionKey)
		}
		if !operation.ImmutableSensitive || !operation.ImmutableMinimum ||
			operation.MinimumStrength != policy.StrengthStrong {
			t.Fatalf("直接管理操作 %s 的安全下限被削弱: %+v", item.operationID, operation)
		}
		_ = item.kind
	}
}

// TestDirectProofPurgesExpiredIntent 覆盖过期密文的有界清理。
func TestDirectProofPurgesExpiredIntent(t *testing.T) {
	env := newProofTestEnv(t, nil)
	sessionID := newSessionID(t)
	_, challengeID := env.beginUsernameProof(t, sessionID, "new.username")
	// 清理前：批准/挑战上的密文存在。
	if count := env.count(`SELECT COUNT(*) FROM reauth_approvals
WHERE intent_sealed IS NOT NULL AND challenge_id=?`, challengeID); count != 1 {
		t.Fatalf("批准意图密文数 = %d，期望 1", count)
	}
	// 推进时钟超过批准与挑战有效期后执行 cleanup。
	env.now = env.now.Add(30 * time.Minute)
	if err := env.stores.ClearExpiredIntents(env.ctx, env.now); err != nil {
		t.Fatalf("清理过期意图密文: %v", err)
	}
	if count := env.count(`SELECT COUNT(*) FROM reauth_approvals
WHERE intent_sealed IS NOT NULL AND challenge_id=?`, challengeID); count != 0 {
		t.Errorf("过期批准意图密文未清理，剩余 %d", count)
	}
	if count := env.count(`SELECT COUNT(*) FROM reauth_challenges
WHERE intent_sealed IS NOT NULL AND id=?`, challengeID); count != 0 {
		t.Errorf("过期挑战意图密文未清理，剩余 %d", count)
	}
}

// TestDirectProofTxRevalidationClosesPrepareCommitWindow 是步骤 255 修复（HIGH）的
// 核心回归：PrepareProof 之后、最终提交事务内，任何权限撤销/会话失效/账户状态或
// 安全版本变化都必须被同一事务连接上的终检拒绝；证明不被烧毁、业务不落库；
// 准备→提交间隔超过硬上限（<=5s）时确定性拒绝。
func TestDirectProofTxRevalidationClosesPrepareCommitWindow(t *testing.T) {
	type mutation func(t *testing.T, env *proofTestEnv, sessionID string)
	cases := []struct {
		name   string
		mutate mutation
		want   error
	}{
		{
			name: "权限准备后撤销",
			mutate: func(_ *testing.T, env *proofTestEnv, _ string) {
				env.perm.mu.Lock()
				env.perm.txDenied = true
				env.perm.mu.Unlock()
			},
			want: reauth.ErrAccessDenied,
		},
		{
			name: "会话准备后撤销",
			mutate: func(t *testing.T, env *proofTestEnv, sessionID string) {
				if _, err := env.storage.DB().ExecContext(env.ctx,
					`UPDATE sessions SET revoked_at_ms=? WHERE id=?`,
					env.now.UnixMilli(), sessionID); err != nil {
					t.Fatalf("撤销合成会话: %v", err)
				}
			},
			want: reauth.ErrSessionMismatch,
		},
		{
			name: "会话准备后空闲过期",
			mutate: func(t *testing.T, env *proofTestEnv, sessionID string) {
				if _, err := env.storage.DB().ExecContext(env.ctx,
					`UPDATE sessions SET idle_expires_at_ms=? WHERE id=?`,
					env.now.Add(-time.Second).UnixMilli(), sessionID); err != nil {
					t.Fatalf("设置会话空闲过期: %v", err)
				}
			},
			want: reauth.ErrSessionMismatch,
		},
		{
			name: "账户安全版本准备后变化",
			mutate: func(t *testing.T, env *proofTestEnv, _ string) {
				if _, err := env.storage.DB().ExecContext(env.ctx,
					`UPDATE users SET security_version=security_version+1 WHERE id=?`,
					normalUserID); err != nil {
					t.Fatalf("递增账户安全版本: %v", err)
				}
			},
			want: reauth.ErrSessionMismatch,
		},
		{
			name: "账户准备后禁用",
			mutate: func(t *testing.T, env *proofTestEnv, _ string) {
				if _, err := env.storage.DB().ExecContext(env.ctx,
					`UPDATE users SET status='disabled' WHERE id=?`, normalUserID); err != nil {
					t.Fatalf("禁用账户: %v", err)
				}
			},
			want: reauth.ErrAccessDenied,
		},
		{
			name: "账户准备后到期",
			mutate: func(t *testing.T, env *proofTestEnv, _ string) {
				if _, err := env.storage.DB().ExecContext(env.ctx,
					`UPDATE users SET valid_until_ms=? WHERE id=?`,
					env.now.Add(-time.Minute).UnixMilli(), normalUserID); err != nil {
					t.Fatalf("设置账户到期: %v", err)
				}
			},
			want: reauth.ErrAccessDenied,
		},
		{
			name: "准备到提交超硬上限",
			mutate: func(_ *testing.T, env *proofTestEnv, _ string) {
				// 默认上限 5s；推进 6s 后必须确定性拒绝（不得靠批准 TTL 兜底）。
				env.now = env.now.Add(6 * time.Second)
			},
			want: reauth.ErrProofExpired,
		},
	}
	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			env := newProofTestEnv(t, nil)
			sessionID := newSessionID(t)
			grant, challengeID := env.beginUsernameProof(t, sessionID, "new.username")
			prepared, prepareErr := env.prepareUsernameProof(t, sessionID, grant.Token,
				"new.username", directTargetUserID, "")
			if prepareErr != nil {
				t.Fatalf("事务外准备证明: %v", prepareErr)
			}
			testCase.mutate(t, env, sessionID)
			caller := env.userCaller(t, normalUserID)
			err := env.recorder.ExecuteCritical(env.ctx, audit.CriticalRequest{
				Event: audit.Event{Actor: caller.Actor(), Action: "test.direct_username_change",
					Target:    audit.Target{Type: "user", ID: directTargetUserID},
					RequestID: "req-255fix-tx"},
				FailureReasonCode: "test_failed",
			}, func(txCtx context.Context, tx audit.Tx) error {
				if _, consumeErr := env.service.ConsumePreparedProofTx(txCtx, tx,
					caller, prepared); consumeErr != nil {
					return consumeErr
				}
				// 业务写入：必须与证明消费同事务；任何拒绝都不得落库。
				if _, writeErr := tx.ExecContext(txCtx,
					`UPDATE users SET nickname=? WHERE id=?`, "must-not-commit",
					directTargetUserID); writeErr != nil {
					return writeErr
				}
				return nil
			})
			if !errors.Is(err, testCase.want) {
				t.Fatalf("事务内终检错误 = %v，期望 %v", err, testCase.want)
			}
			// 拒绝后：证明未被烧毁（仍可重试）、业务未落库。
			var consumed int
			var sealedLen int
			if err := env.storage.DB().QueryRowContext(env.ctx,
				`SELECT (consumed_at_ms IS NOT NULL),COALESCE(length(intent_sealed),0)
				 FROM reauth_approvals WHERE challenge_id=? ORDER BY rowid DESC LIMIT 1`,
				challengeID).Scan(&consumed, &sealedLen); err != nil {
				t.Fatalf("读取批准状态: %v", err)
			}
			if consumed != 0 || sealedLen == 0 {
				t.Fatalf("终止检拒绝后证明被烧毁: consumed=%d sealedLen=%d", consumed, sealedLen)
			}
			var nickname string
			if err := env.storage.DB().QueryRowContext(env.ctx,
				`SELECT nickname FROM users WHERE id=?`, directTargetUserID).Scan(&nickname); err != nil {
				t.Fatalf("读取业务写入: %v", err)
			}
			if nickname == "must-not-commit" {
				t.Fatal("事务内终检拒绝后业务写入仍落库")
			}
		})
	}
}

// TestDirectProofConsumeWithinMaxAge 验证准备→提交在硬上限内仍可正常消费。
func TestDirectProofConsumeWithinMaxAge(t *testing.T) {
	env := newProofTestEnv(t, nil)
	sessionID := newSessionID(t)
	grant, _ := env.beginUsernameProof(t, sessionID, "new.username")
	prepared, prepareErr := env.prepareUsernameProof(t, sessionID, grant.Token,
		"new.username", directTargetUserID, "")
	if prepareErr != nil {
		t.Fatalf("事务外准备证明: %v", prepareErr)
	}
	// 4s < 默认 5s 硬上限：允许消费（直接使用本次 prepared，不重新准备；
	// 重新 Prepare 会刷新 PreparedAt，不能用来验证窗口）。
	env.now = env.now.Add(4 * time.Second)
	caller := env.userCaller(t, normalUserID)
	if err := env.recorder.ExecuteCritical(env.ctx, audit.CriticalRequest{
		Event: audit.Event{Actor: caller.Actor(), Action: "test.direct_username_change",
			Target:    audit.Target{Type: "user", ID: directTargetUserID},
			RequestID: "req-255fix-window"},
		FailureReasonCode: "test_failed",
	}, func(txCtx context.Context, tx audit.Tx) error {
		_, consumeErr := env.service.ConsumePreparedProofTx(txCtx, tx, caller, prepared)
		return consumeErr
	}); err != nil {
		t.Fatalf("硬上限内应允许消费: %v", err)
	}
}

// TestProofMaxAgeHardCap 验证 ProofMaxAge 不能配置到分钟级。
func TestProofMaxAgeHardCap(t *testing.T) {
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("构造非法选项不应 panic: %v", recovered)
		}
	}()
	env := newProofTestEnv(t, nil)
	options := env.options
	options.ProofMaxAge = time.Minute
	if _, err := reauth.New(options); err == nil {
		t.Fatal("ProofMaxAge=1 分钟必须被拒绝（硬上限 5 秒）")
	}
}
