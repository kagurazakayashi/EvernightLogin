package passwordreset_test

// 步骤 206：旧找回链接随密码/邮箱安全变更失效的定向测试。
//
// 覆盖：
//   - 签发时写入安全代际（users.security_version）与已验证邮箱身份绑定；
//   - 迁移前未绑定旧行保守失效（Validate/Complete 均拒绝且不消费）；
//   - 正常/管理员强制改密、验证邮箱切换、禁用→启用、删除后旧链接失效且不复活；
//   - 签发/完成提交边界上的并发变化（邮箱切换、版本变化）按安全失败/回滚处理；
//   - 找回完成不解除 MFA（可重置密码不等于绕过 MFA 登录）。
//
// 除受控故障点外均使用真实 authn/emailchange/account 服务与真实 SQLite。

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/url"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	accountsqlite "github.com/kagurazakayashi/EvernightLogin/internal/account/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/credential"
	"github.com/kagurazakayashi/EvernightLogin/internal/emailchange"
	emailchangesqlite "github.com/kagurazakayashi/EvernightLogin/internal/emailchange/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailtest"
	"github.com/kagurazakayashi/EvernightLogin/internal/passwordreset"
)

// captureEmailChangeSender 捕获邮箱变更验证邮件（含一次性验证入口）与安全告知。
type captureEmailChangeSender struct {
	verifications []emailchange.VerificationEmail
	notices       []emailchange.SecurityNoticeEmail
}

func (s *captureEmailChangeSender) SendVerification(_ context.Context,
	message emailchange.VerificationEmail) error {
	s.verifications = append(s.verifications, message)
	return nil
}

func (s *captureEmailChangeSender) SendSecurityNotice(_ context.Context,
	message emailchange.SecurityNoticeEmail) error {
	s.notices = append(s.notices, message)
	return nil
}

// newEmailChangeService 用同一真实数据库/凭证/审计装配邮箱变更服务（测试专用接线，
// 不进入生产装配）。
func newEmailChangeService(t *testing.T, env *testEnv) (*emailchange.Service, *captureEmailChangeSender) {
	t.Helper()
	store, err := emailchangesqlite.New(env.raw)
	if err != nil {
		t.Fatalf("邮箱变更存储: %v", err)
	}
	sender := &captureEmailChangeSender{}
	service, err := emailchange.New(emailchange.Options{
		Store: store, Audit: env.audit, Credentials: env.creds,
		ReauthVerifier: emailchange.ReauthVerifierFunc(func(context.Context,
			emailchange.Caller, string) error {
			return nil
		}),
		AllowLegacyWithoutSensitive: true,
		Mailer:                      sender,
		VerificationURLBase:         "http://127.0.0.1/change-email",
		SupportURL:                  "http://127.0.0.1/support",
		AppName:                     "test",
		Now:                         func() time.Time { return env.now },
		Logger:                      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("邮箱变更服务: %v", err)
	}
	return service, sender
}

// newAccountService 用同一真实数据库/审计装配账户服务（测试专用接线）。
func newAccountService(t *testing.T, env *testEnv) (*account.Service, account.Caller) {
	t.Helper()
	store, err := accountsqlite.New(env.raw)
	if err != nil {
		t.Fatalf("账户存储: %v", err)
	}
	authorizer, err := account.NewLocalBootstrapAuthorizer([]string{"test-operator"})
	if err != nil {
		t.Fatalf("账户授权器: %v", err)
	}
	service, err := account.New(account.Options{
		Store: store, Audit: env.audit, Authorizer: authorizer,
		Now:    func() time.Time { return env.now },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("账户服务: %v", err)
	}
	caller, err := account.LocalBootstrapCaller("test-operator")
	if err != nil {
		t.Fatalf("本地操作者: %v", err)
	}
	return service, caller
}

// insertLegacyUnboundReset 插入迁移前形态的 pending 找回请求（两绑定列为 NULL），
// 用于验证“未绑定旧行保守失效”。
func (e *testEnv) insertLegacyUnboundReset() (resetID, credentialID, token string) {
	e.t.Helper()
	issued, err := e.creds.Issue(e.ctx, credential.IssueRequest{
		Purpose: resetPurposeValue, Target: userID, Kind: credential.KindToken,
		TTL: 15 * time.Minute,
	})
	if err != nil {
		e.t.Fatalf("签发旧行凭证: %v", err)
	}
	secret := issued.Secret.Reveal()
	digest := sha256.Sum256([]byte(secret))
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		e.t.Fatalf("生成请求 ID: %v", err)
	}
	resetID = "prq_" + hex.EncodeToString(randomBytes)
	now := e.now.UTC().Truncate(time.Millisecond)
	if _, err := e.raw.DB().ExecContext(e.ctx, `INSERT INTO password_reset_requests(
id,user_id,masked_email,credential_id,token_sha256,state,created_at_ms,expires_at_ms,consumed_at_ms
) VALUES(?,?,?,?,?,'pending',?,?,NULL)`,
		resetID, userID, "a***@example.com", issued.ID, digest[:],
		now.UnixMilli(), now.Add(15*time.Minute).UnixMilli()); err != nil {
		e.t.Fatalf("写入旧行请求: %v", err)
	}
	return resetID, issued.ID, resetID + "." + secret
}

// activeResetCredentialCount 统计仍活动（未消费/未撤销/未过期）的找回用途一次性凭证。
func (e *testEnv) activeResetCredentialCount() int {
	e.t.Helper()
	return e.count(`SELECT COUNT(*) FROM one_time_credentials
WHERE purpose=? AND consumed_at_ms IS NULL AND revoked_at_ms IS NULL AND expires_at_ms>?`,
		resetPurposeValue, e.now.UTC().UnixMilli())
}

// TestResetRequestBindsSecurityGenerationAndEmail 验证公开找回与客服通道签发的请求
// 都写入当前安全版本、最近已验证邮箱身份与已验证邮箱身份代际（步骤 250）。
func TestResetRequestBindsSecurityGenerationAndEmail(t *testing.T) {
	env := newRealAuthnTestEnv(t, nil, nil)
	env.now = time.Now().UTC()
	resetID, _ := env.beginResetWithToken("req-206-bind")
	request, found, err := env.resetStore.GetRequest(env.ctx, resetID)
	if err != nil || !found {
		t.Fatalf("读取请求: found=%v err=%v", found, err)
	}
	target, targetFound, err := env.resetStore.GetResetTarget(env.ctx, userID)
	if err != nil || !targetFound {
		t.Fatalf("读取目标: found=%v err=%v", targetFound, err)
	}
	if !request.Bound || request.SecurityVersion != target.SecurityVersion ||
		request.BoundEmailNormalized != target.EmailNormalized ||
		request.BoundEmailIdentityVersion != target.EmailIdentityVersion {
		t.Fatalf("签发绑定不正确: bound=%v version=%d email=%q identity=%d（期望 %d/%q/%d）",
			request.Bound, request.SecurityVersion, request.BoundEmailNormalized,
			request.BoundEmailIdentityVersion, target.SecurityVersion,
			target.EmailNormalized, target.EmailIdentityVersion)
	}
	// 客服通道签发同样绑定。
	if _, err := env.service.SendResetForSupport(env.ctx, passwordreset.SupportResetRequest{
		TargetUserID: userID, RequestID: "req-206-bind-support"}); err != nil {
		t.Fatalf("客服通道签发: %v", err)
	}
	pending, err := env.resetStore.ListPending(env.ctx, userID)
	if err != nil || len(pending) != 1 {
		t.Fatalf("客服通道 pending 数 = %d err=%v", len(pending), err)
	}
	if !pending[0].Bound || pending[0].SecurityVersion != target.SecurityVersion ||
		pending[0].BoundEmailNormalized != target.EmailNormalized ||
		pending[0].BoundEmailIdentityVersion != target.EmailIdentityVersion {
		t.Fatalf("客服通道绑定不正确: %+v", pending[0])
	}
}

// TestLegacyUnboundResetRequestRejected 验证迁移前未绑定旧行保守失效：预检查与完成
// 都拒绝，且不消费凭证、不改变请求状态。
func TestLegacyUnboundResetRequestRejected(t *testing.T) {
	env := newRealAuthnTestEnv(t, nil, nil)
	env.now = time.Now().UTC()
	resetID, credentialID, token := env.insertLegacyUnboundReset()
	if err := env.service.ValidateResetToken(env.ctx, token); !errors.Is(err, passwordreset.ErrTokenInvalid) {
		t.Fatalf("未绑定旧行预检查错误 = %v，期望 ErrTokenInvalid", err)
	}
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: token, NewPassword: strongNewPassword, RequestID: "req-206-legacy"}); !errors.Is(err, passwordreset.ErrTokenInvalid) {
		t.Fatalf("未绑定旧行完成错误 = %v，期望 ErrTokenInvalid", err)
	}
	env.assertRequestPending(resetID)
	env.assertCredentialActive(credentialID)
}

// TestResetLinkInvalidAfterPasswordChange 验证管理员/系统强制改密后旧链接失效。
func TestResetLinkInvalidAfterPasswordChange(t *testing.T) {
	env := newRealAuthnTestEnv(t, nil, nil)
	env.now = time.Now().UTC()
	resetID, token := env.beginResetWithToken("req-206-password-change")
	request, found, err := env.resetStore.GetRequest(env.ctx, resetID)
	if err != nil || !found {
		t.Fatalf("读取请求: found=%v err=%v", found, err)
	}
	if _, err := env.realAuthn.SetPassword(env.ctx, env.systemCaller, authn.SetPasswordRequest{
		TargetUserID: userID, NewPassword: strongNewPassword2,
		RequestID: "req-206-admin-change"}); err != nil {
		t.Fatalf("管理员强制改密: %v", err)
	}
	if err := env.service.ValidateResetToken(env.ctx, token); !errors.Is(err, passwordreset.ErrTokenInvalid) {
		t.Fatalf("改密后旧链接预检查错误 = %v，期望 ErrTokenInvalid", err)
	}
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: token, NewPassword: strongNewPassword, RequestID: "req-206-old-after-change"}); !errors.Is(err, passwordreset.ErrTokenInvalid) {
		t.Fatalf("改密后旧链接完成错误 = %v，期望 ErrTokenInvalid", err)
	}
	env.assertRequestPending(resetID)
	env.assertCredentialActive(request.CredentialID)
}

// TestResetLinkInvalidAfterEmailSwitch 验证验证邮箱切换后旧邮箱链接失效，而新邮箱
// 签发的新链接可用（绑定正确）。
func TestResetLinkInvalidAfterEmailSwitch(t *testing.T) {
	env := newRealAuthnTestEnv(t, nil, nil)
	env.now = time.Now().UTC()
	_, oldToken := env.beginResetWithToken("req-206-email-old")
	emailService, sender := newEmailChangeService(t, env)
	caller, err := emailchange.UserCaller(userID)
	if err != nil {
		t.Fatalf("邮箱变更调用者: %v", err)
	}
	const newEmail = "alice.new@example.test"
	if _, err := emailService.RequestChange(env.ctx, caller, newEmail,
		"req-206-email-change"); err != nil {
		t.Fatalf("发起邮箱变更: %v", err)
	}
	if len(sender.verifications) != 1 {
		t.Fatalf("验证邮件数 = %d，期望 1", len(sender.verifications))
	}
	parsed, err := url.Parse(sender.verifications[0].VerificationURL)
	if err != nil {
		t.Fatalf("解析验证入口: %v", err)
	}
	query := parsed.Query()
	if _, err := emailService.Verify(env.ctx, emailchange.VerifyRequest{
		RequestID: query.Get("rid"), CredentialID: query.Get("cid"),
		Token: query.Get("token"), RequestIDLog: "req-206-email-verify",
	}); err != nil {
		t.Fatalf("确认邮箱切换: %v", err)
	}
	// 旧邮箱链接：绑定邮箱已被替换 → 确定性失效。
	if err := env.service.ValidateResetToken(env.ctx, oldToken); !errors.Is(err, passwordreset.ErrTokenInvalid) {
		t.Fatalf("换邮箱后旧链接预检查错误 = %v，期望 ErrTokenInvalid", err)
	}
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: oldToken, NewPassword: strongNewPassword, RequestID: "req-206-email-old-complete"}); !errors.Is(err, passwordreset.ErrTokenInvalid) {
		t.Fatalf("换邮箱后旧链接完成错误 = %v，期望 ErrTokenInvalid", err)
	}
	// 旧邮箱不再能发起新找回（emailchange 已删除旧验证行）。
	if _, err := env.service.BeginReset(env.ctx, passwordreset.BeginResetRequest{
		Identifier: "alice@example.com", RequestID: "req-206-old-email-begin"}); err != nil {
		t.Fatalf("旧邮箱发起不应暴露错误: %v", err)
	}
	// 新邮箱签发的新链接可用：完成成功。
	env2Token := beginResetWithEmail(t, env, newEmail, "req-206-email-new")
	if err := env.service.ValidateResetToken(env.ctx, env2Token); err != nil {
		t.Fatalf("新邮箱链接预检查失败: %v", err)
	}
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: env2Token, NewPassword: strongNewPassword, RequestID: "req-206-email-new-complete"}); err != nil {
		t.Fatalf("新邮箱链接完成失败: %v", err)
	}
}

// TestResetLinkInvalidAfterDisableAndEnable 验证禁用→启用后旧链接不复活。
func TestResetLinkInvalidAfterDisableAndEnable(t *testing.T) {
	env := newRealAuthnTestEnv(t, nil, nil)
	env.now = time.Now().UTC()
	_, token := env.beginResetWithToken("req-206-disable")
	accountService, caller := newAccountService(t, env)
	user, err := accountService.GetUser(env.ctx, caller, userID)
	if err != nil {
		t.Fatalf("读取账户: %v", err)
	}
	disabled, err := accountService.DisableUser(env.ctx, caller, account.StateCommandRequest{
		UserID: userID, ExpectedRowVersion: user.RowVersion})
	if err != nil {
		t.Fatalf("禁用账户: %v", err)
	}
	if _, err := accountService.EnableUser(env.ctx, caller, account.StateCommandRequest{
		UserID: userID, ExpectedRowVersion: disabled.User.RowVersion}); err != nil {
		t.Fatalf("启用账户: %v", err)
	}
	if err := env.service.ValidateResetToken(env.ctx, token); !errors.Is(err, passwordreset.ErrTokenInvalid) {
		t.Fatalf("禁用再启用后旧链接预检查错误 = %v，期望 ErrTokenInvalid", err)
	}
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: token, NewPassword: strongNewPassword, RequestID: "req-206-disable-complete"}); !errors.Is(err, passwordreset.ErrTokenInvalid) {
		t.Fatalf("禁用再启用后旧链接完成错误 = %v，期望 ErrTokenInvalid", err)
	}
}

// TestResetLinkInvalidAfterUserDeletion 验证账户删除后请求被级联删除、旧链接失效。
func TestResetLinkInvalidAfterUserDeletion(t *testing.T) {
	env := newRealAuthnTestEnv(t, nil, nil)
	env.now = time.Now().UTC()
	resetID, token := env.beginResetWithToken("req-206-delete")
	accountService, caller := newAccountService(t, env)
	user, err := accountService.GetUser(env.ctx, caller, userID)
	if err != nil {
		t.Fatalf("读取账户: %v", err)
	}
	if _, err := accountService.RequestDeletion(env.ctx, caller, account.StateCommandRequest{
		UserID: userID, ExpectedRowVersion: user.RowVersion}); err != nil {
		t.Fatalf("请求删除账户: %v", err)
	}
	pendingUser, err := accountService.GetUser(env.ctx, caller, userID)
	if err != nil {
		t.Fatalf("读取待删除账户: %v", err)
	}
	if _, err := accountService.CompleteDeletion(env.ctx, caller, account.StateCommandRequest{
		UserID: userID, ExpectedRowVersion: pendingUser.RowVersion}); err != nil {
		t.Fatalf("完成删除账户: %v", err)
	}
	if _, found, err := env.resetStore.GetRequest(env.ctx, resetID); err != nil || found {
		t.Fatalf("删除后找回请求仍存在: found=%v err=%v", found, err)
	}
	if err := env.service.ValidateResetToken(env.ctx, token); !errors.Is(err, passwordreset.ErrTokenInvalid) {
		t.Fatalf("删除后旧链接预检查错误 = %v，期望 ErrTokenInvalid", err)
	}
}

// TestBeginResetRaceChannelChangedFailsSafely 验证签发提交边界检测到邮箱/目标变化时
// 安全失败：不产生新请求、不发送邮件、已签发凭证被撤销。
func TestBeginResetRaceChannelChangedFailsSafely(t *testing.T) {
	var flaky *flakyResetStore
	env := newRealAuthnTestEnv(t, nil, func(options *passwordreset.Options) {
		flaky = &flakyResetStore{inner: options.Store}
		options.Store = flaky
	})
	env.now = time.Now().UTC()
	target, found, err := env.resetStore.GetResetTarget(env.ctx, userID)
	if err != nil || !found {
		t.Fatalf("读取目标: found=%v err=%v", found, err)
	}
	channels := []struct {
		name    string
		mutate  func(*passwordreset.Candidate)
		request string
	}{
		{"邮箱已切换", func(c *passwordreset.Candidate) { c.EmailNormalized = "other@example.test" },
			"req-206-race-channel"},
		{"账户已禁用", func(c *passwordreset.Candidate) { c.Active = false }, "req-206-race-target"},
	}
	for _, item := range channels {
		flaky.setOverrideTargetTx(nil)
		requestsBefore := env.count(`SELECT COUNT(*) FROM password_reset_requests`)
		mailBefore := len(env.mailSnapshot())
		candidate := target
		item.mutate(&candidate)
		flaky.setOverrideTargetTx(&candidate)
		if _, err := env.service.BeginReset(env.ctx, passwordreset.BeginResetRequest{
			Identifier: "alice@example.com", RequestID: item.request}); err != nil {
			t.Fatalf("%s: 公开响应不应暴露错误: %v", item.name, err)
		}
		flaky.setOverrideTargetTx(nil)
		if env.count(`SELECT COUNT(*) FROM password_reset_requests`) != requestsBefore {
			t.Errorf("%s: 不应写入找回请求", item.name)
		}
		if len(env.mailSnapshot()) != mailBefore {
			t.Errorf("%s: 不应发送邮件", item.name)
		}
		if active := env.activeResetCredentialCount(); active != 0 {
			t.Errorf("%s: 已签发未交付凭证应被撤销，活动数 = %d", item.name, active)
		}
	}
}

// TestCompleteResetRaceBindingChangedRollsBack 验证完成的提交边界检测到绑定变化时
// 整体回滚：请求仍 pending、凭证未消费、密码未改。
func TestCompleteResetRaceBindingChangedRollsBack(t *testing.T) {
	var flaky *flakyResetStore
	env := newRealAuthnTestEnv(t, nil, func(options *passwordreset.Options) {
		flaky = &flakyResetStore{inner: options.Store}
		options.Store = flaky
	})
	env.now = time.Now().UTC()
	resetID, token := env.beginResetWithToken("req-206-complete-race")
	request, found, err := env.resetStore.GetRequest(env.ctx, resetID)
	if err != nil || !found {
		t.Fatalf("读取请求: found=%v err=%v", found, err)
	}
	beforeHash := env.passwordHash(userID)
	target, found, err := env.resetStore.GetResetTarget(env.ctx, userID)
	if err != nil || !found {
		t.Fatalf("读取目标: found=%v err=%v", found, err)
	}
	changed := target
	changed.SecurityVersion++
	flaky.setOverrideTargetTx(&changed)
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: token, NewPassword: strongNewPassword, RequestID: "req-206-complete-race-1"}); !errors.Is(err, passwordreset.ErrTokenInvalid) {
		t.Fatalf("提交边界绑定变化错误 = %v，期望 ErrTokenInvalid", err)
	}
	flaky.setOverrideTargetTx(nil)
	env.assertRequestPending(resetID)
	env.assertCredentialActive(request.CredentialID)
	if env.passwordHash(userID) != beforeHash {
		t.Fatal("绑定变化时不应写入新密码")
	}
	// 恢复正常后同一令牌可完成（绑定仍有效）。
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: token, NewPassword: strongNewPassword, RequestID: "req-206-complete-race-2"}); err != nil {
		t.Fatalf("恢复后完成失败: %v", err)
	}
}

// TestSupportResetRaceTargetChangedFailsClosed 验证客服通道签发事务内目标变化时
// 安全失败：返回显式不可用错误、不发送邮件、不写入请求。
func TestSupportResetRaceTargetChangedFailsClosed(t *testing.T) {
	var flaky *flakyResetStore
	env := newRealAuthnTestEnv(t, nil, func(options *passwordreset.Options) {
		flaky = &flakyResetStore{inner: options.Store}
		options.Store = flaky
	})
	env.now = time.Now().UTC()
	target, found, err := env.resetStore.GetResetTarget(env.ctx, userID)
	if err != nil || !found {
		t.Fatalf("读取目标: found=%v err=%v", found, err)
	}
	changed := target
	changed.Active = false
	flaky.setOverrideTargetTx(&changed)
	requestsBefore := env.count(`SELECT COUNT(*) FROM password_reset_requests`)
	mailBefore := len(env.mailSnapshot())
	if _, err := env.service.SendResetForSupport(env.ctx, passwordreset.SupportResetRequest{
		TargetUserID: userID, RequestID: "req-206-support-race"}); !errors.Is(err, passwordreset.ErrAccountDisabled) {
		t.Fatalf("客服通道并发变化错误 = %v，期望 ErrAccountDisabled", err)
	}
	flaky.setOverrideTargetTx(nil)
	if env.count(`SELECT COUNT(*) FROM password_reset_requests`) != requestsBefore {
		t.Error("客服通道安全失败时不应写入请求")
	}
	if len(env.mailSnapshot()) != mailBefore {
		t.Error("客服通道安全失败时不应发送邮件")
	}
	if active := env.activeResetCredentialCount(); active != 0 {
		t.Errorf("客服通道安全失败时已签发凭证应被撤销，活动数 = %d", active)
	}
}

// TestCompleteResetPreservesMFAFactors 验证找回完成改密不解除 MFA/强因素：可重置密码
// 不等于已绕过 MFA 登录。
func TestCompleteResetPreservesMFAFactors(t *testing.T) {
	env := newRealAuthnTestEnv(t, nil, nil)
	env.now = time.Now().UTC()
	if _, err := env.raw.DB().ExecContext(env.ctx, `INSERT INTO mfa_factors(
id,user_id,factor_type,status,created_at_ms,updated_at_ms
) VALUES('mft_2060000000000000000000000000001',?,'email','active',?,?)`,
		userID, env.now.UnixMilli(), env.now.UnixMilli()); err != nil {
		t.Fatalf("插入 MFA 因素: %v", err)
	}
	_, token := env.beginResetWithToken("req-206-mfa")
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: token, NewPassword: strongNewPassword, RequestID: "req-206-mfa-complete"}); err != nil {
		t.Fatalf("完成找回改密: %v", err)
	}
	if count := env.count(
		`SELECT COUNT(*) FROM mfa_factors WHERE user_id=? AND status='active'`, userID); count != 1 {
		t.Errorf("找回改密后 MFA 因素数 = %d，期望 1（不得解除 MFA）", count)
	}
}

// beginResetWithEmail 以指定邮箱发起找回并取回本次 token。
func beginResetWithEmail(t *testing.T, env *testEnv, email, requestID string) string {
	t.Helper()
	if _, err := env.service.BeginReset(env.ctx, passwordreset.BeginResetRequest{
		Identifier: email, RequestID: requestID}); err != nil {
		t.Fatalf("以 %s 发起找回: %v", email, err)
	}
	var resetID string
	if err := env.raw.DB().QueryRowContext(env.ctx,
		`SELECT id FROM password_reset_requests ORDER BY rowid DESC LIMIT 1`).Scan(&resetID); err != nil {
		t.Fatalf("读取最新请求: %v", err)
	}
	token := env.tokenForAny(resetID)
	if token == "" {
		t.Fatalf("未从邮件取出 token（reset=%s）", resetID)
	}
	return token
}

// tokenForAny 等待并返回指定找回请求 ID 对应的邮件 token（不限定收件邮箱，用于
// 邮箱切换后的新地址）。历史邮件可能保留旧 token，必须按 reset ID 前缀精确匹配。
func (e *testEnv) tokenForAny(resetID string) string {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, message := range e.mail.Snapshot(mailtest.Query{}) {
			body := decodeMessageBody(message)
			for _, match := range tokenPattern.FindAllStringSubmatch(body, -1) {
				decoded, err := url.QueryUnescape(match[1])
				if err == nil && len(decoded) > len(resetID) &&
					decoded[:len(resetID)] == resetID && decoded[len(resetID)] == '.' {
					return decoded
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return ""
}
