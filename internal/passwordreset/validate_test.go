package passwordreset_test

// 步骤 204：找回入口只读预检查（ValidateResetToken）的状态一致性测试。
//
// 覆盖目标：
//   - 正常链接可预检查且不消费（请求仍 pending、凭证未消费/未撤销、密码未改）；
//   - 成功使用后、被新申请替代后、显式取消后、凭证撤销后均拒绝；
//   - 过期、错误摘要、底层存储故障与账户不可找回状态默认拒绝；
//   - 预检查结果不是最终授权：预检查通过后再发生变化，最终提交仍重新验证。
//
// 全部使用真实 SQLite + 真实一次性凭证服务 + 本地 SMTP 捕获器，不修改生产装配。

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/credential"
	credentialsqlite "github.com/kagurazakayashi/EvernightLogin/internal/credential/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailtest"
	"github.com/kagurazakayashi/EvernightLogin/internal/passwordreset"
)

// resetPurposeValue 是找回领域内部用途常量 "password.reset" 的测试镜像：只在
// 受控本地入口（直接撤销凭证）中用于构造绑定参数，不参与产品判断。
const resetPurposeValue = "password.reset"

// beginResetWithToken 通过公开 BeginReset 发起找回，并取回“本次”请求的 token。
// 邮件捕获里可能保留历史找回邮件，必须按最新 reset ID 精确匹配，避免误用旧 token。
func (e *testEnv) beginResetWithToken(requestID string) (string, string) {
	e.t.Helper()
	if _, err := e.service.BeginReset(e.ctx, passwordreset.BeginResetRequest{
		Identifier: "alice@example.com", RequestID: requestID}); err != nil {
		e.t.Fatalf("开始找回: %v", err)
	}
	var resetID string
	if err := e.raw.DB().QueryRowContext(e.ctx,
		`SELECT id FROM password_reset_requests ORDER BY rowid DESC LIMIT 1`).Scan(&resetID); err != nil {
		e.t.Fatalf("读取最新找回请求: %v", err)
	}
	token := e.tokenFor(resetID)
	if token == "" {
		e.t.Fatalf("未从邮件取出找回 token（reset=%s）", resetID)
	}
	return resetID, token
}

// tokenFor 等待并返回指定找回请求 ID 对应的邮件 token。
func (e *testEnv) tokenFor(resetID string) string {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, message := range e.mail.Snapshot(mailtest.Query{To: "alice@example.com"}) {
			body := decodeMessageBody(message)
			for _, match := range tokenPattern.FindAllStringSubmatch(body, -1) {
				decoded, err := url.QueryUnescape(match[1])
				if err == nil && strings.HasPrefix(decoded, resetID+".") {
					return decoded
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return ""
}

// assertRequestPending 断言找回请求仍为 pending 且未被消费。
func (e *testEnv) assertRequestPending(resetID string) {
	e.t.Helper()
	var state string
	var consumed *int64
	if err := e.raw.DB().QueryRowContext(e.ctx,
		`SELECT state,consumed_at_ms FROM password_reset_requests WHERE id=?`, resetID).
		Scan(&state, &consumed); err != nil {
		e.t.Fatalf("读取找回请求状态: %v", err)
	}
	if state != "pending" || consumed != nil {
		e.t.Fatalf("预检查改变了请求状态: state=%s consumed=%v", state, consumed)
	}
}

// assertCredentialActive 断言一次性凭证仍活动（未消费、未撤销、无失败尝试）。
func (e *testEnv) assertCredentialActive(credentialID string) {
	e.t.Helper()
	var consumed, revoked *int64
	var attempts int
	if err := e.raw.DB().QueryRowContext(e.ctx,
		`SELECT consumed_at_ms,revoked_at_ms,attempts FROM one_time_credentials WHERE id=?`,
		credentialID).Scan(&consumed, &revoked, &attempts); err != nil {
		e.t.Fatalf("读取凭证状态: %v", err)
	}
	if consumed != nil || revoked != nil || attempts != 0 {
		e.t.Fatalf("预检查改变了凭证状态: consumed=%v revoked=%v attempts=%d",
			consumed, revoked, attempts)
	}
}

// TestValidateResetTokenPrecheckDoesNotConsume 覆盖：正常链接可预检查、可重复预检查，
// 且不消费请求/凭证、不调用密码服务；预检查后正式提交仍成功。
func TestValidateResetTokenPrecheckDoesNotConsume(t *testing.T) {
	env := newTestEnv(t, nil)
	env.now = time.Now().UTC()
	resetID, token := env.beginResetWithToken("req-precheck")
	request, found, err := env.resetStore.GetRequest(env.ctx, resetID)
	if err != nil || !found {
		t.Fatalf("读取找回请求: found=%v err=%v", found, err)
	}
	for attempt := 1; attempt <= 2; attempt++ {
		if err := env.service.ValidateResetToken(env.ctx, token); err != nil {
			t.Fatalf("第 %d 次预检查: %v", attempt, err)
		}
	}
	if env.pass.resetCalls != 0 || env.pass.changeCalls != 0 {
		t.Errorf("预检查不应调用密码服务: reset=%d change=%d",
			env.pass.resetCalls, env.pass.changeCalls)
	}
	env.assertRequestPending(resetID)
	env.assertCredentialActive(request.CredentialID)
	// 预检查不使入口失效：同一 token 随后正式提交成功。
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: token, NewPassword: "ResetSecret!9876", RequestID: "req-precheck-complete"}); err != nil {
		t.Fatalf("预检查后正式提交失败: %v", err)
	}
	if env.pass.resetCalls != 1 {
		t.Errorf("密码重置调用 = %d，期望 1", env.pass.resetCalls)
	}
}

// TestValidateResetTokenRejectsAfterUsed 覆盖：成功使用同一 token 后，预检查与再次
// 提交都拒绝，且密码只改一次。
func TestValidateResetTokenRejectsAfterUsed(t *testing.T) {
	env := newTestEnv(t, nil)
	env.now = time.Now().UTC()
	_, token := env.beginResetWithToken("req-used-begin")
	if err := env.service.ValidateResetToken(env.ctx, token); err != nil {
		t.Fatalf("使用前预检查: %v", err)
	}
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: token, NewPassword: "ResetSecret!9876", RequestID: "req-used-complete"}); err != nil {
		t.Fatalf("首次提交: %v", err)
	}
	if err := env.service.ValidateResetToken(env.ctx, token); !errors.Is(err, passwordreset.ErrTokenInvalid) {
		t.Fatalf("已使用后预检查错误 = %v，期望 ErrTokenInvalid", err)
	}
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: token, NewPassword: "ResetSecret!9876", RequestID: "req-used-replay"}); !errors.Is(err, passwordreset.ErrTokenInvalid) {
		t.Fatalf("已使用后重复提交错误 = %v，期望 ErrTokenInvalid", err)
	}
	if env.pass.resetCalls != 1 {
		t.Errorf("密码重置调用 = %d，期望 1", env.pass.resetCalls)
	}
}

// TestValidateResetTokenRejectsAfterReplaced 覆盖：新找回申请替代旧请求后，旧链接
// 预检查与最终提交都拒绝；新链接仍可正常预检查。
func TestValidateResetTokenRejectsAfterReplaced(t *testing.T) {
	env := newTestEnv(t, nil)
	env.now = time.Now().UTC()
	_, oldToken := env.beginResetWithToken("req-replace-old")
	if err := env.service.ValidateResetToken(env.ctx, oldToken); err != nil {
		t.Fatalf("旧入口被替代前预检查: %v", err)
	}
	_, newToken := env.beginResetWithToken("req-replace-new")
	if err := env.service.ValidateResetToken(env.ctx, oldToken); !errors.Is(err, passwordreset.ErrTokenInvalid) {
		t.Fatalf("被替代后旧入口预检查错误 = %v，期望 ErrTokenInvalid", err)
	}
	if err := env.service.ValidateResetToken(env.ctx, newToken); err != nil {
		t.Fatalf("新入口预检查: %v", err)
	}
	// 预检查通过过的旧 token 在最终提交时必须重新验证并拒绝。
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: oldToken, NewPassword: "ResetSecret!9876", RequestID: "req-replace-complete"}); !errors.Is(err, passwordreset.ErrTokenInvalid) {
		t.Fatalf("被替代后旧入口提交错误 = %v，期望 ErrTokenInvalid", err)
	}
	if env.pass.resetCalls != 0 {
		t.Errorf("被替代的入口不得重置密码，resetCalls=%d", env.pass.resetCalls)
	}
}

// TestValidateResetTokenRejectsAfterExplicitCancel 覆盖：受控本地取消入口（审计事务内
// 标记 cancelled 并撤销凭证）后，预检查与最终提交都拒绝。
func TestValidateResetTokenRejectsAfterExplicitCancel(t *testing.T) {
	env := newTestEnv(t, nil)
	env.now = time.Now().UTC()
	resetID, token := env.beginResetWithToken("req-cancel")
	request, found, err := env.resetStore.GetRequest(env.ctx, resetID)
	if err != nil || !found {
		t.Fatalf("读取找回请求: found=%v err=%v", found, err)
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:  audit.Actor{Type: audit.ActorSystem, ID: "passwordreset"},
			Action: "password.reset_requests_cancelled",
			Target: audit.Target{Type: "user", ID: userID},
			Changes: []audit.FieldChange{
				{Field: "reason", After: "explicit_cancel"},
			},
		},
		FailureReasonCode: "password.reset_cancel_failed",
	}
	if err := env.audit.ExecuteCritical(env.ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		_, cancelErr := env.resetStore.CancelPendingTx(txCtx, tx, userID, env.now)
		return cancelErr
	}); err != nil {
		t.Fatalf("显式取消找回请求: %v", err)
	}
	if err := env.creds.Cancel(env.ctx, credential.CancelRequest{
		ID: request.CredentialID, Purpose: resetPurposeValue, Target: userID}); err != nil {
		t.Fatalf("撤销找回凭证: %v", err)
	}
	if err := env.service.ValidateResetToken(env.ctx, token); !errors.Is(err, passwordreset.ErrTokenInvalid) {
		t.Fatalf("显式取消后预检查错误 = %v，期望 ErrTokenInvalid", err)
	}
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: token, NewPassword: "ResetSecret!9876", RequestID: "req-cancel-complete"}); !errors.Is(err, passwordreset.ErrTokenInvalid) {
		t.Fatalf("显式取消后提交错误 = %v，期望 ErrTokenInvalid", err)
	}
	if env.pass.resetCalls != 0 {
		t.Errorf("显式取消的入口不得重置密码，resetCalls=%d", env.pass.resetCalls)
	}
}

// TestValidateResetTokenRejectsAfterCredentialRevoked 覆盖：请求状态仍是 pending 但
// 底层一次性凭证被撤销时，预检查必须依据凭证状态拒绝（不能只看请求状态）。
func TestValidateResetTokenRejectsAfterCredentialRevoked(t *testing.T) {
	env := newTestEnv(t, nil)
	env.now = time.Now().UTC()
	resetID, token := env.beginResetWithToken("req-revoked")
	request, found, err := env.resetStore.GetRequest(env.ctx, resetID)
	if err != nil || !found {
		t.Fatalf("读取找回请求: found=%v err=%v", found, err)
	}
	if err := env.creds.Cancel(env.ctx, credential.CancelRequest{
		ID: request.CredentialID, Purpose: resetPurposeValue, Target: request.UserID}); err != nil {
		t.Fatalf("撤销找回凭证: %v", err)
	}
	// 请求仍 pending：拒绝只能来自凭证维度的非消费校验。
	env.assertRequestPending(resetID)
	if err := env.service.ValidateResetToken(env.ctx, token); !errors.Is(err, passwordreset.ErrTokenInvalid) {
		t.Fatalf("凭证撤销后预检查错误 = %v，期望 ErrTokenInvalid", err)
	}
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: token, NewPassword: "ResetSecret!9876", RequestID: "req-revoked-complete"}); !errors.Is(err, passwordreset.ErrTokenInvalid) {
		t.Fatalf("凭证撤销后提交错误 = %v，期望 ErrTokenInvalid", err)
	}
	if env.pass.resetCalls != 0 {
		t.Errorf("凭证已撤销的入口不得重置密码，resetCalls=%d", env.pass.resetCalls)
	}
}

// TestValidateResetTokenRejectsExpiredAndWrongDigest 覆盖：错误摘要与过期都拒绝；
// 错误摘要不会让请求/凭证状态发生变化。
func TestValidateResetTokenRejectsExpiredAndWrongDigest(t *testing.T) {
	env := newTestEnv(t, nil)
	env.now = time.Now().UTC()
	resetID, token := env.beginResetWithToken("req-digest")
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		t.Fatalf("token 结构异常: %q", token)
	}
	tampered := parts[0] + "." + mutateSecret(parts[1])
	if err := env.service.ValidateResetToken(env.ctx, tampered); !errors.Is(err, passwordreset.ErrTokenInvalid) {
		t.Fatalf("错误摘要预检查错误 = %v，期望 ErrTokenInvalid", err)
	}
	env.assertRequestPending(resetID)
	// 过期：有效期 15 分钟，时钟推进 16 分钟后拒绝。
	env.now = env.now.Add(16 * time.Minute)
	if err := env.service.ValidateResetToken(env.ctx, token); !errors.Is(err, passwordreset.ErrTokenExpired) {
		t.Fatalf("过期预检查错误 = %v，期望 ErrTokenExpired", err)
	}
}

// TestValidateResetTokenRejectsUnrecoverableAccount 覆盖：token 发出后账户被禁用、
// 移除密码或改为 root 时，预检查按“账户可找回状态”拒绝。
func TestValidateResetTokenRejectsUnrecoverableAccount(t *testing.T) {
	env := newTestEnv(t, nil)
	env.now = time.Now().UTC()
	_, token := env.beginResetWithToken("req-account")
	if err := env.service.ValidateResetToken(env.ctx, token); err != nil {
		t.Fatalf("账户可找回时预检查: %v", err)
	}
	if _, err := env.raw.DB().ExecContext(env.ctx,
		`UPDATE users SET status='disabled' WHERE id=?`, userID); err != nil {
		t.Fatalf("禁用账户: %v", err)
	}
	if err := env.service.ValidateResetToken(env.ctx, token); !errors.Is(err, passwordreset.ErrAccountDisabled) {
		t.Fatalf("禁用账户预检查错误 = %v，期望 ErrAccountDisabled", err)
	}
	if _, err := env.raw.DB().ExecContext(env.ctx,
		`UPDATE users SET status='active' WHERE id=?`, userID); err != nil {
		t.Fatalf("恢复账户: %v", err)
	}
	if _, err := env.raw.DB().ExecContext(env.ctx,
		`DELETE FROM password_credentials WHERE user_id=?`, userID); err != nil {
		t.Fatalf("移除密码: %v", err)
	}
	if err := env.service.ValidateResetToken(env.ctx, token); !errors.Is(err, passwordreset.ErrNoPassword) {
		t.Fatalf("无密码账户预检查错误 = %v，期望 ErrNoPassword", err)
	}
	env.seedPassword(userID)
	if _, err := env.raw.DB().ExecContext(env.ctx,
		`UPDATE users SET is_root=1 WHERE id=?`, userID); err != nil {
		t.Fatalf("改为 root: %v", err)
	}
	if err := env.service.ValidateResetToken(env.ctx, token); !errors.Is(err, passwordreset.ErrAccessDenied) {
		t.Fatalf("root 账户预检查错误 = %v，期望 ErrAccessDenied", err)
	}
}

// TestValidateResetTokenFailsClosedOnStoreErrors 覆盖：请求/账户存储故障按默认拒绝
// 返回 ErrStoreUnavailable，绝不把读取失败当作有效入口；恢复后仍可正常预检查。
func TestValidateResetTokenFailsClosedOnStoreErrors(t *testing.T) {
	var flaky *flakyResetStore
	env := newTestEnv(t, func(options *passwordreset.Options) {
		flaky = &flakyResetStore{inner: options.Store}
		options.Store = flaky
	})
	env.now = time.Now().UTC()
	_, token := env.beginResetWithToken("req-store")
	flaky.setFailGetRequest(true)
	if err := env.service.ValidateResetToken(env.ctx, token); !errors.Is(err, passwordreset.ErrStoreUnavailable) {
		t.Fatalf("请求存储故障预检查错误 = %v，期望 ErrStoreUnavailable", err)
	}
	flaky.setFailGetRequest(false)
	flaky.setFailGetTarget(true)
	if err := env.service.ValidateResetToken(env.ctx, token); !errors.Is(err, passwordreset.ErrStoreUnavailable) {
		t.Fatalf("账户存储故障预检查错误 = %v，期望 ErrStoreUnavailable", err)
	}
	flaky.setFailGetTarget(false)
	if err := env.service.ValidateResetToken(env.ctx, token); err != nil {
		t.Fatalf("存储恢复后预检查: %v", err)
	}
}

// TestValidateResetTokenFailsClosedOnCredentialStoreErrors 覆盖：一次性凭证存储故障
// 按默认拒绝返回 ErrStoreUnavailable，不会被当作“凭证有效”。
func TestValidateResetTokenFailsClosedOnCredentialStoreErrors(t *testing.T) {
	env := newTestEnv(t, nil)
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
	_, token := env.beginResetWithToken("req-credstore")
	flaky.setFailLoadByID(true)
	if err := env.service.ValidateResetToken(env.ctx, token); !errors.Is(err, passwordreset.ErrStoreUnavailable) {
		t.Fatalf("凭证存储故障预检查错误 = %v，期望 ErrStoreUnavailable", err)
	}
	flaky.setFailLoadByID(false)
	if err := env.service.ValidateResetToken(env.ctx, token); err != nil {
		t.Fatalf("凭证存储恢复后预检查: %v", err)
	}
}

// flakyResetStore 是找回存储的故障注入包装：只让指定读取方法返回存储错误，其余
// 委托真实 SQLite 存储。仅用于测试，不进入生产装配。
type flakyResetStore struct {
	inner            passwordreset.Store
	mu               sync.Mutex
	failGet          bool
	failGetTarget    bool
	failInsertOutbox bool
}

func (s *flakyResetStore) setFailInsertOutbox(value bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failInsertOutbox = value
}

func (s *flakyResetStore) shouldFailInsertOutbox() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failInsertOutbox
}

func (s *flakyResetStore) setFailGetRequest(value bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failGet = value
}

func (s *flakyResetStore) setFailGetTarget(value bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failGetTarget = value
}

func (s *flakyResetStore) shouldFailGet() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failGet
}

func (s *flakyResetStore) shouldFailGetTarget() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failGetTarget
}

func (s *flakyResetStore) FindUserByEmail(ctx context.Context, email string) (passwordreset.Candidate, bool, error) {
	return s.inner.FindUserByEmail(ctx, email)
}

func (s *flakyResetStore) CreateRequestTx(ctx context.Context, tx audit.Tx, request passwordreset.ResetRequest) error {
	return s.inner.CreateRequestTx(ctx, tx, request)
}

func (s *flakyResetStore) GetRequest(ctx context.Context, id string) (passwordreset.ResetRequest, bool, error) {
	if s.shouldFailGet() {
		return passwordreset.ResetRequest{}, false, errors.New("injected store failure")
	}
	return s.inner.GetRequest(ctx, id)
}

func (s *flakyResetStore) ConsumeRequestTx(ctx context.Context, tx audit.Tx, id string, now time.Time) (bool, error) {
	return s.inner.ConsumeRequestTx(ctx, tx, id, now)
}

func (s *flakyResetStore) InsertOutboxTx(ctx context.Context, tx audit.Tx, userID, reason string, now time.Time) (string, error) {
	if s.shouldFailInsertOutbox() {
		return "", errors.New("injected outbox store failure")
	}
	return s.inner.InsertOutboxTx(ctx, tx, userID, reason, now)
}

func (s *flakyResetStore) VerifiedEmail(ctx context.Context, userID string) (string, bool, error) {
	return s.inner.VerifiedEmail(ctx, userID)
}

func (s *flakyResetStore) ListPending(ctx context.Context, userID string) ([]passwordreset.ResetRequest, error) {
	return s.inner.ListPending(ctx, userID)
}

func (s *flakyResetStore) ListPendingTx(ctx context.Context, tx audit.Tx, userID string) ([]passwordreset.ResetRequest, error) {
	return s.inner.ListPendingTx(ctx, tx, userID)
}

func (s *flakyResetStore) CancelPendingTx(ctx context.Context, tx audit.Tx, userID string, now time.Time) (int64, error) {
	return s.inner.CancelPendingTx(ctx, tx, userID, now)
}

func (s *flakyResetStore) GetResetTarget(ctx context.Context, userID string) (passwordreset.Candidate, bool, error) {
	if s.shouldFailGetTarget() {
		return passwordreset.Candidate{}, false, errors.New("injected store failure")
	}
	return s.inner.GetResetTarget(ctx, userID)
}

// flakyCredentialStore 是一次性凭证存储的故障注入包装：可让独立读取与事务内撤销失败。
type flakyCredentialStore struct {
	inner        credential.Store
	mu           sync.Mutex
	failLoadBy   bool
	failRevokeTx bool
}

func (s *flakyCredentialStore) setFailLoadByID(value bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failLoadBy = value
}

func (s *flakyCredentialStore) shouldFailLoadByID() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failLoadBy
}

func (s *flakyCredentialStore) Insert(ctx context.Context, record credential.Record) error {
	return s.inner.Insert(ctx, record)
}

func (s *flakyCredentialStore) ReplaceActiveAndInsert(ctx context.Context, record credential.Record, now time.Time) error {
	return s.inner.ReplaceActiveAndInsert(ctx, record, now)
}

func (s *flakyCredentialStore) LoadByID(ctx context.Context, id string) (credential.Record, bool, error) {
	if s.shouldFailLoadByID() {
		return credential.Record{}, false, errors.New("injected credential store failure")
	}
	return s.inner.LoadByID(ctx, id)
}

func (s *flakyCredentialStore) Consume(ctx context.Context, condition credential.ConsumeCondition) (bool, error) {
	return s.inner.Consume(ctx, condition)
}

func (s *flakyCredentialStore) RecordFailedAttempt(ctx context.Context, id string, now time.Time) (credential.FailedAttemptResult, error) {
	return s.inner.RecordFailedAttempt(ctx, id, now)
}

func (s *flakyCredentialStore) Revoke(ctx context.Context, condition credential.RevokeCondition) (bool, error) {
	return s.inner.Revoke(ctx, condition)
}

func (s *flakyCredentialStore) DeleteExpired(ctx context.Context, cutoff time.Time) (int64, error) {
	return s.inner.DeleteExpired(ctx, cutoff)
}

// transactionStore 返回内层存储的事务扩展；flakyCredentialStore 只在测试中包装真实
// SQLite 存储，因此内层必然实现 credential.TransactionStore。
func (s *flakyCredentialStore) transactionStore() credential.TransactionStore {
	txStore, ok := s.inner.(credential.TransactionStore)
	if !ok {
		panic("测试包装的内层凭证存储必须实现 credential.TransactionStore")
	}
	return txStore
}

func (s *flakyCredentialStore) setFailRevokeTx(value bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failRevokeTx = value
}

func (s *flakyCredentialStore) shouldFailRevokeTx() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failRevokeTx
}

func (s *flakyCredentialStore) LoadByIDTx(ctx context.Context, tx credential.Transaction,
	id string) (credential.Record, bool, error) {
	return s.transactionStore().LoadByIDTx(ctx, tx, id)
}

func (s *flakyCredentialStore) ConsumeTx(ctx context.Context, tx credential.Transaction,
	condition credential.ConsumeCondition) (bool, error) {
	return s.transactionStore().ConsumeTx(ctx, tx, condition)
}

func (s *flakyCredentialStore) RevokeTx(ctx context.Context, tx credential.Transaction,
	condition credential.RevokeCondition) (bool, error) {
	if s.shouldFailRevokeTx() {
		return false, errors.New("injected credential revoke failure")
	}
	return s.transactionStore().RevokeTx(ctx, tx, condition)
}

var _ credential.TransactionStore = (*flakyCredentialStore)(nil)

// mutateSecret 翻转 token secret 的首字符，构造“格式合法但摘要错误”的 token。
func mutateSecret(secret string) string {
	buffer := []byte(secret)
	if buffer[0] == 'A' {
		buffer[0] = 'B'
	} else {
		buffer[0] = 'A'
	}
	return string(buffer)
}
