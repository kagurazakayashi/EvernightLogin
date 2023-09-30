package passwordreset_test

// 步骤 205：找回改密的单事务提交边界与失败可重试行为测试。
//
// 覆盖目标：
//   - 弱密码 / 历史复用 / 哈希资源忙失败不消费仍有效令牌，可用同一链接重试成功；
//   - 凭证条件消费、请求终态、其他入口作废、密码+历史+安全版本、关键审计、
//     OAuth 撤销 outbox 在同一事务：outbox/审计/凭证撤销失败均整体回滚（无半提交）；
//   - 并发同一 token 只有一个赢家；成功响应丢失后重试不重复改密；
//   - 准备到提交之间的并发安全状态变化被事务内复核发现（CONFLICT），令牌未消费。
//
// 除“哈希资源忙”用受控替身故障点外，其余成功/失败链使用真实 authn 服务（真实
// Argon2、密码策略/历史/安全版本）与真实 SQLite，避免把替身行为当成生产行为。

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	authnsqlite "github.com/kagurazakayashi/EvernightLogin/internal/authn/sqlite"
	bootstrapsqlite "github.com/kagurazakayashi/EvernightLogin/internal/bootstrap/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/credential"
	credentialsqlite "github.com/kagurazakayashi/EvernightLogin/internal/credential/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/passwordreset"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

const (
	realInitialPassword = "OldPass!Tr9x"
	strongNewPassword   = "Qz7!vN9#Lp2@Rm5"
	strongNewPassword2  = "Zx8$mK4!wR2@Nt7"
	historyNewPassword  = "Hy5!pL2#vQ8@Bn4"
)

// testArgon2Params 使用允许范围内的最低成本参数：仍走真实 Argon2 派生/校验路径，
// 但避免默认参数拖长定向测试时间。
func testArgon2Params() authn.Params {
	return authn.Params{
		MemoryKiB: authn.MinMemoryKiB, Iterations: authn.MinIterations,
		Parallelism: authn.MinParallelism, SaltLength: authn.MinSaltBytes,
		KeyLength: authn.MinKeyBytes,
	}
}

// newRealAuthnTestEnv 在既有 testEnv 基础上把密码服务替换为真实 authn.Service，并用
// 真实 authn 设置初始密码（替换 seed 的合成哈希），以便覆盖真实密码策略/历史/安全版本。
func newRealAuthnTestEnv(t *testing.T, mutateAuthn func(*authn.Options),
	mutateReset func(*passwordreset.Options)) *testEnv {
	t.Helper()
	env := newTestEnv(t, mutateReset)
	authnStore, err := authnsqlite.New(env.raw)
	if err != nil {
		t.Fatalf("认证存储: %v", err)
	}
	bootstrapStore, err := bootstrapsqlite.New(env.raw)
	if err != nil {
		t.Fatalf("初始化存储: %v", err)
	}
	options := authn.Options{
		AllowLegacyWithoutSensitive: true,
		Store:                       authnStore,
		Audit:                       env.audit,
		RootInitialization:          bootstrapStore,
		Params:                      testArgon2Params(),
		EmailLoginEnabled:           true,
		Now:                         func() time.Time { return env.now },
		Logger:                      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if mutateAuthn != nil {
		mutateAuthn(&options)
	}
	authnService, err := authn.New(options)
	if err != nil {
		t.Fatalf("真实认证服务: %v", err)
	}
	systemCaller, err := authn.SystemCaller("passwordreset-205-test")
	if err != nil {
		t.Fatalf("系统调用者: %v", err)
	}
	env.realAuthn = authnService
	env.systemCaller = systemCaller
	if _, err := authnService.SetPassword(env.ctx, systemCaller, authn.SetPasswordRequest{
		TargetUserID: userID, NewPassword: realInitialPassword, RequestID: "req-205-initial-password",
	}); err != nil {
		t.Fatalf("设置初始密码: %v", err)
	}
	resetOptions := env.options
	resetOptions.Passwords = authnService
	env.options = resetOptions
	service, err := passwordreset.New(resetOptions)
	if err != nil {
		t.Fatalf("重建找回服务: %v", err)
	}
	env.service = service
	return env
}

// securityVersion 读取账户当前安全版本。
func (e *testEnv) securityVersion(userID string) int64 {
	e.t.Helper()
	var version int64
	if err := e.raw.DB().QueryRowContext(e.ctx,
		`SELECT security_version FROM users WHERE id=?`, userID).Scan(&version); err != nil {
		e.t.Fatalf("读取安全版本: %v", err)
	}
	return version
}

// passwordHash 读取账户当前密码哈希（只用于测试等价性比较，不记录）。
func (e *testEnv) passwordHash(userID string) string {
	e.t.Helper()
	var hash string
	if err := e.raw.DB().QueryRowContext(e.ctx,
		`SELECT password_hash FROM password_credentials WHERE user_id=?`, userID).Scan(&hash); err != nil {
		e.t.Fatalf("读取密码哈希: %v", err)
	}
	return hash
}

// insertExtraPendingReset 直接写入另一个仍 pending 的找回入口与其凭证，模拟并发窗口
// 中出现的第二个入口（正常 BeginReset 会作废旧入口，测试需要两个同时 pending）。
func (e *testEnv) insertExtraPendingReset() (resetID, credentialID, token string) {
	e.t.Helper()
	issued, err := e.creds.Issue(e.ctx, credential.IssueRequest{
		Purpose: resetPurposeValue, Target: userID, Kind: credential.KindToken,
		TTL: 15 * time.Minute,
	})
	if err != nil {
		e.t.Fatalf("签发额外找回凭证: %v", err)
	}
	secret := issued.Secret.Reveal()
	digest := sha256.Sum256([]byte(secret))
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		e.t.Fatalf("生成额外找回请求 ID: %v", err)
	}
	resetID = "prq_" + hex.EncodeToString(randomBytes)
	now := e.now.UTC().Truncate(time.Millisecond)
	if _, err := e.raw.DB().ExecContext(e.ctx, `INSERT INTO password_reset_requests(
id,user_id,masked_email,credential_id,token_sha256,state,created_at_ms,expires_at_ms,consumed_at_ms
) VALUES(?,?,?,?,?,'pending',?,?,NULL)`,
		resetID, userID, "a***@example.com", issued.ID, digest[:],
		now.UnixMilli(), now.Add(15*time.Minute).UnixMilli()); err != nil {
		e.t.Fatalf("写入额外找回请求: %v", err)
	}
	return resetID, issued.ID, resetID + "." + secret
}

// TestCompleteResetWeakPasswordRetryKeepsToken 验证弱密码失败发生在凭证消费之前：
// 同一找回链接仍有效，换强密码后重试成功。
func TestCompleteResetWeakPasswordRetryKeepsToken(t *testing.T) {
	env := newRealAuthnTestEnv(t, nil, nil)
	env.now = time.Now().UTC()
	resetID, token := env.beginResetWithToken("req-205-weak-begin")
	request, found, err := env.resetStore.GetRequest(env.ctx, resetID)
	if err != nil || !found {
		t.Fatalf("读取找回请求: found=%v err=%v", found, err)
	}
	beforeVersion := env.securityVersion(userID)
	beforeHash := env.passwordHash(userID)
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: token, NewPassword: "short", RequestID: "req-205-weak"}); !errors.Is(err, authn.ErrWeakPassword) {
		t.Fatalf("弱密码错误 = %v，期望 ErrWeakPassword", err)
	}
	// 弱密码失败不得烧令牌：请求仍 pending、凭证未消费、密码与安全版本不变。
	env.assertRequestPending(resetID)
	env.assertCredentialActive(request.CredentialID)
	if env.securityVersion(userID) != beforeVersion || env.passwordHash(userID) != beforeHash {
		t.Fatal("弱密码失败不应改变密码或安全版本")
	}
	// 同一链接换强密码重试成功。
	result, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: token, NewPassword: strongNewPassword, RequestID: "req-205-weak-retry"})
	if err != nil {
		t.Fatalf("强密码重试失败: %v", err)
	}
	if result.SecurityVersion != beforeVersion+1 {
		t.Errorf("安全版本 = %d，期望 %d", result.SecurityVersion, beforeVersion+1)
	}
	if _, authErr := env.realAuthn.Authenticate(env.ctx, authn.AuthenticateRequest{
		Identifier: "alice", Password: strongNewPassword, ClientIP: "203.0.113.10",
		RequestID: "req-205-weak-login"}); authErr != nil {
		t.Fatalf("重置后新密码认证失败: %v", authErr)
	}
}

// TestCompleteResetHistoryReuseRetryKeepsToken 验证历史复用失败同样不烧令牌：
// 历史密码与当前密码都被拒绝，换新密码重试成功。
func TestCompleteResetHistoryReuseRetryKeepsToken(t *testing.T) {
	env := newRealAuthnTestEnv(t, func(options *authn.Options) {
		options.PasswordPolicy = authn.PasswordPolicy{
			MinRunes: 12, MaxRunes: 128, HistoryLimit: 3,
		}
	}, nil)
	env.now = time.Now().UTC()
	// 第一次找回把密码从 realInitialPassword 改成 historyNewPassword（旧哈希进入历史）。
	_, firstToken := env.beginResetWithToken("req-205-history-first")
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: firstToken, NewPassword: historyNewPassword, RequestID: "req-205-history-first-complete"}); err != nil {
		t.Fatalf("首次找回改密: %v", err)
	}
	// 新入口：历史密码与当前密码都拒绝，且不消费令牌。
	resetID, token := env.beginResetWithToken("req-205-history-second")
	request, found, err := env.resetStore.GetRequest(env.ctx, resetID)
	if err != nil || !found {
		t.Fatalf("读取找回请求: found=%v err=%v", found, err)
	}
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: token, NewPassword: realInitialPassword, RequestID: "req-205-history-reuse-old"}); !errors.Is(err, authn.ErrPasswordReused) {
		t.Fatalf("历史密码错误 = %v，期望 ErrPasswordReused", err)
	}
	env.assertRequestPending(resetID)
	env.assertCredentialActive(request.CredentialID)
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: token, NewPassword: historyNewPassword, RequestID: "req-205-history-reuse-current"}); !errors.Is(err, authn.ErrPasswordReused) {
		t.Fatalf("当前密码错误 = %v，期望 ErrPasswordReused", err)
	}
	env.assertCredentialActive(request.CredentialID)
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: token, NewPassword: strongNewPassword, RequestID: "req-205-history-retry"}); err != nil {
		t.Fatalf("换新密码重试失败: %v", err)
	}
}

// TestCompleteResetHashWorkBusyKeepsToken 用受控替身故障点覆盖“Argon2 资源忙”：
// 等价错误返回时令牌仍 pending，可重试成功。真实槽位行为由 authn 既有测试覆盖。
func TestCompleteResetHashWorkBusyKeepsToken(t *testing.T) {
	env := newTestEnv(t, nil)
	env.now = time.Now().UTC()
	resetID, token := env.beginResetWithToken("req-205-busy")
	request, found, err := env.resetStore.GetRequest(env.ctx, resetID)
	if err != nil || !found {
		t.Fatalf("读取找回请求: found=%v err=%v", found, err)
	}
	env.pass.prepareErr = &authn.RateLimitError{RetryAfter: time.Second, Reason: "password_work_busy"}
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: token, NewPassword: strongNewPassword, RequestID: "req-205-busy-1"}); !errors.Is(err, authn.ErrRateLimited) {
		t.Fatalf("哈希资源忙错误 = %v，期望 ErrRateLimited", err)
	}
	env.assertRequestPending(resetID)
	env.assertCredentialActive(request.CredentialID)
	env.pass.prepareErr = nil
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: token, NewPassword: strongNewPassword, RequestID: "req-205-busy-2"}); err != nil {
		t.Fatalf("资源恢复后重试失败: %v", err)
	}
}

// TestCompleteResetOutboxFailureRollsBack 验证 OAuth 撤销 outbox 写入失败时整笔事务
// 回滚：请求/凭证/密码/安全版本均保持原状，令牌可重试成功（无半提交）。
func TestCompleteResetOutboxFailureRollsBack(t *testing.T) {
	var flaky *flakyResetStore
	env := newRealAuthnTestEnv(t, nil, func(options *passwordreset.Options) {
		flaky = &flakyResetStore{inner: options.Store}
		options.Store = flaky
	})
	env.now = time.Now().UTC()
	resetID, token := env.beginResetWithToken("req-205-outbox")
	request, found, err := env.resetStore.GetRequest(env.ctx, resetID)
	if err != nil || !found {
		t.Fatalf("读取找回请求: found=%v err=%v", found, err)
	}
	beforeVersion := env.securityVersion(userID)
	beforeHash := env.passwordHash(userID)
	flaky.setFailInsertOutbox(true)
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: token, NewPassword: strongNewPassword, RequestID: "req-205-outbox-1"}); !errors.Is(err, passwordreset.ErrStoreUnavailable) {
		t.Fatalf("outbox 失败错误 = %v，期望 ErrStoreUnavailable", err)
	}
	// 无半提交：请求/凭证仍可用，密码与安全版本未变，成功审计未产生。
	env.assertRequestPending(resetID)
	env.assertCredentialActive(request.CredentialID)
	if env.securityVersion(userID) != beforeVersion || env.passwordHash(userID) != beforeHash {
		t.Fatal("outbox 失败不应留下已改密的半提交")
	}
	if count := env.count(`SELECT COUNT(*) FROM oauth_revocation_events WHERE user_id=?`, userID); count != 0 {
		t.Errorf("outbox 事件数 = %d，期望 0（事务已回滚）", count)
	}
	if count := env.count(
		`SELECT COUNT(*) FROM audit_events WHERE action='password.reset_completed' AND outcome='success'`,
	); count != 0 {
		t.Errorf("成功审计数 = %d，期望 0（事务已回滚）", count)
	}
	// 故障恢复后同一令牌重试成功。
	flaky.setFailInsertOutbox(false)
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: token, NewPassword: strongNewPassword, RequestID: "req-205-outbox-2"}); err != nil {
		t.Fatalf("outbox 恢复后重试失败: %v", err)
	}
	if env.securityVersion(userID) != beforeVersion+1 {
		t.Errorf("重试成功后的安全版本 = %d，期望 %d", env.securityVersion(userID), beforeVersion+1)
	}
}

// TestCompleteResetOtherPendingRevokeFailureRollsBack 验证“其他入口凭证撤销”也在同一
// 事务：撤销失败时当前令牌与其他 pending 入口都不变，重试成功后其他入口被作废。
func TestCompleteResetOtherPendingRevokeFailureRollsBack(t *testing.T) {
	env := newRealAuthnTestEnv(t, nil, nil)
	env.now = time.Now().UTC()
	credentialStore, err := credentialsqlite.New(env.raw)
	if err != nil {
		t.Fatalf("凭证存储: %v", err)
	}
	flaky := &flakyCredentialStore{inner: credentialStore}
	credentialService, err := credential.New(flaky, credential.Options{
		Keyring: env.keyring, Now: func() time.Time { return env.now }})
	if err != nil {
		t.Fatalf("故障凭证服务: %v", err)
	}
	options := env.options
	options.Credentials = credentialService
	service, err := passwordreset.New(options)
	if err != nil {
		t.Fatalf("重建找回服务: %v", err)
	}
	env.service = service
	_, token := env.beginResetWithToken("req-205-other-pending")
	otherResetID, otherCredentialID, _ := env.insertExtraPendingReset()
	beforeVersion := env.securityVersion(userID)
	beforeHash := env.passwordHash(userID)
	flaky.setFailRevokeTx(true)
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: token, NewPassword: strongNewPassword, RequestID: "req-205-other-1"}); !errors.Is(err, passwordreset.ErrStoreUnavailable) {
		t.Fatalf("其他入口撤销失败错误 = %v，期望 ErrStoreUnavailable", err)
	}
	// 当前入口与其他入口都未被改变，密码未改。
	env.assertRequestPending(otherResetID)
	env.assertCredentialActive(otherCredentialID)
	if env.securityVersion(userID) != beforeVersion || env.passwordHash(userID) != beforeHash {
		t.Fatal("撤销失败不应留下已改密的半提交")
	}
	// 恢复后重试当前 token 成功，其他 pending 入口被作废且凭证撤销。
	flaky.setFailRevokeTx(false)
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: token, NewPassword: strongNewPassword, RequestID: "req-205-other-2"}); err != nil {
		t.Fatalf("恢复后重试失败: %v", err)
	}
	var state string
	if err := env.raw.DB().QueryRowContext(env.ctx,
		`SELECT state FROM password_reset_requests WHERE id=?`, otherResetID).Scan(&state); err != nil {
		t.Fatalf("读取其他入口状态: %v", err)
	}
	if state != "cancelled" {
		t.Errorf("其他入口状态 = %s，期望 cancelled", state)
	}
	var consumedAt, revokedAt *int64
	if err := env.raw.DB().QueryRowContext(env.ctx,
		`SELECT consumed_at_ms,revoked_at_ms FROM one_time_credentials WHERE id=?`, otherCredentialID).
		Scan(&consumedAt, &revokedAt); err != nil {
		t.Fatalf("读取其他入口凭证: %v", err)
	}
	if revokedAt == nil {
		t.Error("其他入口凭证应已在同一事务内撤销")
	}
}

// TestCompleteResetAuditFailureRollsBack 模拟“关键成功审计写入失败”：业务变更先执行，
// 审计写入失败使整笔事务回滚，令牌仍可用，重试成功（无半提交）。
func TestCompleteResetAuditFailureRollsBack(t *testing.T) {
	env := newRealAuthnTestEnv(t, nil, nil)
	env.now = time.Now().UTC()
	resetID, token := env.beginResetWithToken("req-205-audit")
	request, found, err := env.resetStore.GetRequest(env.ctx, resetID)
	if err != nil || !found {
		t.Fatalf("读取找回请求: found=%v err=%v", found, err)
	}
	failingAudit := &failingCompletedAudit{inner: env.options.Audit, store: env.raw}
	failingAudit.setFail(true)
	options := env.options
	options.Audit = failingAudit
	service, err := passwordreset.New(options)
	if err != nil {
		t.Fatalf("重建找回服务: %v", err)
	}
	env.service = service
	beforeVersion := env.securityVersion(userID)
	beforeHash := env.passwordHash(userID)
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: token, NewPassword: strongNewPassword, RequestID: "req-205-audit-1"}); !errors.Is(err, passwordreset.ErrAuditUnavailable) {
		t.Fatalf("审计失败错误 = %v，期望 ErrAuditUnavailable", err)
	}
	env.assertRequestPending(resetID)
	env.assertCredentialActive(request.CredentialID)
	if env.securityVersion(userID) != beforeVersion || env.passwordHash(userID) != beforeHash {
		t.Fatal("审计失败不应留下已改密的半提交")
	}
	failingAudit.setFail(false)
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: token, NewPassword: strongNewPassword, RequestID: "req-205-audit-2"}); err != nil {
		t.Fatalf("审计恢复后重试失败: %v", err)
	}
}

// TestCompleteResetConcurrentSingleWinnerAndResponseLossRetry 验证并发同一 token 只有
// 一个赢家，且成功响应“丢失”后重试不会重复改密。
func TestCompleteResetConcurrentSingleWinnerAndResponseLossRetry(t *testing.T) {
	env := newRealAuthnTestEnv(t, nil, nil)
	env.now = time.Now().UTC()
	_, token := env.beginResetWithToken("req-205-concurrent")
	beforeVersion := env.securityVersion(userID)
	passwords := []string{strongNewPassword, strongNewPassword2}
	startChannel := make(chan struct{})
	results := make(chan error, 2)
	var waitGroup sync.WaitGroup
	for index := 0; index < 2; index++ {
		waitGroup.Add(1)
		go func(candidate string) {
			defer waitGroup.Done()
			<-startChannel
			_, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
				Token: token, NewPassword: candidate, RequestID: "req-205-concurrent-" + candidate[:3]})
			results <- err
		}(passwords[index])
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
		t.Fatalf("并发找回 = 成功 %d / 拒绝 %d，期望 1/1", successes, rejected)
	}
	if version := env.securityVersion(userID); version != beforeVersion+1 {
		t.Errorf("并发后安全版本 = %d，期望只递增一次到 %d", version, beforeVersion+1)
	}
	// 只有赢家的密码能登录。
	winner := ""
	for _, candidate := range passwords {
		if _, authErr := env.realAuthn.Authenticate(env.ctx, authn.AuthenticateRequest{
			Identifier: "alice", Password: candidate, ClientIP: "203.0.113.11",
			RequestID: "req-205-concurrent-login"}); authErr == nil {
			if winner != "" {
				t.Fatal("两个候选密码都能登录，说明发生双赢家")
			}
			winner = candidate
		}
	}
	if winner == "" {
		t.Fatal("赢家密码无法登录")
	}
	// 成功响应丢失后的重试：同一 token 拒绝，密码与安全版本不再变化。
	hashAfterSuccess := env.passwordHash(userID)
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: token, NewPassword: strongNewPassword2, RequestID: "req-205-concurrent-retry"}); !errors.Is(err, passwordreset.ErrTokenInvalid) {
		t.Fatalf("成功后重试错误 = %v，期望 ErrTokenInvalid", err)
	}
	if env.securityVersion(userID) != beforeVersion+1 || env.passwordHash(userID) != hashAfterSuccess {
		t.Fatal("成功响应丢失后的重试不应再次改密")
	}
}

// TestCompleteResetConflictKeepsToken 验证 Prepare 与事务提交之间的并发安全状态变化会
// 被事务内复核发现（CONFLICT），令牌未被消费，可重试成功。
func TestCompleteResetConflictKeepsToken(t *testing.T) {
	env := newRealAuthnTestEnv(t, nil, nil)
	env.now = time.Now().UTC()
	resetID, token := env.beginResetWithToken("req-205-conflict")
	request, found, err := env.resetStore.GetRequest(env.ctx, resetID)
	if err != nil || !found {
		t.Fatalf("读取找回请求: found=%v err=%v", found, err)
	}
	racing := &racingRecoveryPasswords{
		service:   env.options.Passwords,
		committer: env.options.Passwords.(passwordreset.RecoveryCommitter),
		env:       env,
	}
	racing.setFire(true)
	options := env.options
	options.Passwords = racing
	service, err := passwordreset.New(options)
	if err != nil {
		t.Fatalf("重建找回服务: %v", err)
	}
	env.service = service
	beforeHash := env.passwordHash(userID)
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: token, NewPassword: strongNewPassword, RequestID: "req-205-conflict-1"}); !errors.Is(err, passwordreset.ErrConflict) {
		t.Fatalf("并发冲突错误 = %v，期望 ErrConflict", err)
	}
	env.assertRequestPending(resetID)
	env.assertCredentialActive(request.CredentialID)
	if env.passwordHash(userID) != beforeHash {
		t.Fatal("并发冲突不应写入新密码")
	}
	// 去掉模拟并发变化后，同一令牌重试成功。
	racing.setFire(false)
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: token, NewPassword: strongNewPassword, RequestID: "req-205-conflict-2"}); err != nil {
		t.Fatalf("冲突后重试失败: %v", err)
	}
}

// failingCompletedAudit 模拟关键成功审计写入失败：在真实数据库事务内执行 change 后
// 返回 audit.ErrAuditUnavailable，使整笔事务回滚（与 internal/audit 的失败语义一致）。
type failingCompletedAudit struct {
	inner passwordreset.AuditRecorder
	store *storagesqlite.Store
	mu    sync.Mutex
	fail  bool
}

func (f *failingCompletedAudit) setFail(value bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail = value
}

func (f *failingCompletedAudit) shouldFail() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fail
}

func (f *failingCompletedAudit) Record(ctx context.Context, event audit.Event) error {
	return f.inner.Record(ctx, event)
}

func (f *failingCompletedAudit) RecordFailure(ctx context.Context, event audit.Event) error {
	return f.inner.RecordFailure(ctx, event)
}

func (f *failingCompletedAudit) ExecuteCritical(ctx context.Context, request audit.CriticalRequest,
	change audit.Change) error {
	if !f.shouldFail() || request.Event.Action != "password.reset_completed" {
		return f.inner.ExecuteCritical(ctx, request, change)
	}
	return f.store.Transaction(ctx, func(txCtx context.Context, tx *sql.Tx) error {
		if err := change(txCtx, rawAuditTx{tx: tx}); err != nil {
			return err
		}
		return fmt.Errorf("%w: injected audit success write failure", audit.ErrAuditUnavailable)
	})
}

// rawAuditTx 让测试事务满足 audit.Tx；业务回调不使用 AppendEvent（由失败注入点承担）。
type rawAuditTx struct{ tx *sql.Tx }

func (t rawAuditTx) AppendEvent(context.Context, audit.Event) error { return nil }

func (t rawAuditTx) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return t.tx.ExecContext(ctx, query, args...)
}

func (t rawAuditTx) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return t.tx.QueryContext(ctx, query, args...)
}

// racingRecoveryPasswords 在 PrepareRecoveryReset 成功后模拟并发安全状态变化
// （安全版本 +1），用于验证事务内复核与 CONFLICT 语义。
type racingRecoveryPasswords struct {
	service   passwordreset.PasswordService
	committer passwordreset.RecoveryCommitter
	env       *testEnv
	mu        sync.Mutex
	fire      bool
}

func (r *racingRecoveryPasswords) setFire(value bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fire = value
}

func (r *racingRecoveryPasswords) shouldFire() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.fire
}

func (r *racingRecoveryPasswords) SetPassword(ctx context.Context, caller authn.Caller,
	request authn.SetPasswordRequest) (authn.SetPasswordResult, error) {
	return r.service.SetPassword(ctx, caller, request)
}

func (r *racingRecoveryPasswords) ResetPasswordForRecovery(ctx context.Context, caller authn.Caller,
	request authn.RecoveryResetRequest) (authn.SetPasswordResult, error) {
	return r.service.ResetPasswordForRecovery(ctx, caller, request)
}

func (r *racingRecoveryPasswords) PrepareRecoveryReset(ctx context.Context, caller authn.Caller,
	request authn.RecoveryResetRequest) (authn.PreparedRecoveryReset, error) {
	prepared, err := r.committer.PrepareRecoveryReset(ctx, caller, request)
	if err == nil && r.shouldFire() {
		if _, bumpErr := r.env.raw.DB().ExecContext(ctx,
			`UPDATE users SET security_version=security_version+1 WHERE id=?`, request.UserID); bumpErr != nil {
			return nil, bumpErr
		}
	}
	return prepared, err
}

func (r *racingRecoveryPasswords) ApplyRecoveryResetTx(ctx context.Context, caller authn.Caller,
	prepared authn.PreparedRecoveryReset, tx audit.Tx) (authn.SetPasswordResult, error) {
	return r.committer.ApplyRecoveryResetTx(ctx, caller, prepared, tx)
}

var (
	_ passwordreset.PasswordService   = (*racingRecoveryPasswords)(nil)
	_ passwordreset.RecoveryCommitter = (*racingRecoveryPasswords)(nil)
	_ passwordreset.AuditRecorder     = (*failingCompletedAudit)(nil)
)
