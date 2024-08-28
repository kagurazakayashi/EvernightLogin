package passwordreset_test

// 步骤 250：防止邮箱往返变更（A→B→A）复活旧找回链接的定向测试。
//
// 覆盖：
//   - 签发绑定“安全版本 + 已验证邮箱文本 + 已验证邮箱身份代际”三者；
//   - A→B→A 往返换绑（含两次切换使用同一可控时钟时间戳、地址先删除后重新新增）后，
//     旧链接在预检查与最终提交都永久拒绝且不消费凭证/不改密码；新申请可用；
//   - 首次绑定（无已验证邮箱 → 首次添加）使代际从 0 前进，新申请绑定新代际；
//   - 0053 之前已绑定（0051 时代）但缺少邮箱身份代际的旧行保守失效、不回填；
//   - 预检查通过后在 Prepare 与最终提交事务之间完成 A→B→A，提交边界复核拒绝并整体
//     回滚（ErrTokenInvalid，非可重试冲突）；
//   - 并发换绑与找回提交：写入事务串行化，任一顺序都不产生“旧链接在其失效后被消费”
//     或“双赢家”，且换绑完成后旧链接不可用、新申请可用。
//
// 除受控注入点外均使用真实 authn/emailchange 服务与真实 SQLite；邮箱代际来自
// migration 0053 与各真实写入口的事务内递增，不通过测试旁路伪造“有效旧链接”。

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/credential"
	"github.com/kagurazakayashi/EvernightLogin/internal/emailchange"
	"github.com/kagurazakayashi/EvernightLogin/internal/passwordreset"
)

// emailIdentityVersion 读取账户当前已验证邮箱身份代际（users.email_identity_version）。
func (e *testEnv) emailIdentityVersion(id string) int64 {
	e.t.Helper()
	var version int64
	if err := e.raw.DB().QueryRowContext(e.ctx,
		`SELECT email_identity_version FROM users WHERE id=?`, id).Scan(&version); err != nil {
		e.t.Fatalf("读取邮箱身份代际: %v", err)
	}
	return version
}

// switchVerifiedEmail 通过真实 emailchange 服务完成一次“申请 + 确认”的邮箱切换
// （targetUserID 无已验证邮箱时即首次添加）。返回切换后的邮箱身份代际。
func switchVerifiedEmail(t *testing.T, env *testEnv, service *emailchange.Service,
	sender *captureEmailChangeSender, targetUserID, newEmail, requestID string) int64 {
	t.Helper()
	caller, err := emailchange.UserCaller(targetUserID)
	if err != nil {
		t.Fatalf("邮箱变更调用者: %v", err)
	}
	if _, err := service.RequestChange(env.ctx, caller, newEmail, requestID); err != nil {
		t.Fatalf("发起邮箱变更 %s: %v", newEmail, err)
	}
	if len(sender.verifications) == 0 {
		t.Fatal("未捕获邮箱变更验证邮件")
	}
	message := sender.verifications[len(sender.verifications)-1]
	parsed, err := url.Parse(message.VerificationURL)
	if err != nil {
		t.Fatalf("解析验证入口: %v", err)
	}
	query := parsed.Query()
	if _, err := service.Verify(env.ctx, emailchange.VerifyRequest{
		RequestID: query.Get("rid"), CredentialID: query.Get("cid"),
		Token: query.Get("token"), RequestIDLog: requestID + "-verify",
	}); err != nil {
		t.Fatalf("确认邮箱变更 %s: %v", newEmail, err)
	}
	return env.emailIdentityVersion(targetUserID)
}

// insertBoundResetWithoutEmailIdentity 直接写入“0051 时代已绑定但缺少邮箱身份代际”的
// pending 找回请求（security_version/bound_email_normalized 有值，
// bound_email_identity_version 为 NULL），用于证明迁移前旧行保守失效。
func (e *testEnv) insertBoundResetWithoutEmailIdentity(requestID string) (resetID, credentialID, token string) {
	e.t.Helper()
	issued, err := e.creds.Issue(e.ctx, credential.IssueRequest{
		Purpose: resetPurposeValue, Target: userID, Kind: credential.KindToken,
		TTL: 15 * time.Minute,
	})
	if err != nil {
		e.t.Fatalf("签发旧行凭证: %v", err)
	}
	target, found, err := e.resetStore.GetResetTarget(e.ctx, userID)
	if err != nil || !found {
		e.t.Fatalf("读取目标: found=%v err=%v", found, err)
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
id,user_id,masked_email,credential_id,token_sha256,state,created_at_ms,expires_at_ms,consumed_at_ms,
security_version,bound_email_normalized,bound_email_identity_version
) VALUES(?,?,?,?,?,'pending',?,?,NULL,?,?,NULL)`,
		resetID, userID, target.MaskedEmail, issued.ID, digest[:],
		now.UnixMilli(), now.Add(15*time.Minute).UnixMilli(),
		target.SecurityVersion, target.EmailNormalized); err != nil {
		e.t.Fatalf("写入无代际旧行请求: %v", err)
	}
	return resetID, issued.ID, resetID + "." + secret
}

// TestResetRequestBindsEmailIdentityVersion 验证公开找回与客服通道签发都写入当前
// 已验证邮箱身份代际，且与账户当前值一致（安全版本 + 邮箱文本 + 代际三者绑定）。
func TestResetRequestBindsEmailIdentityVersion(t *testing.T) {
	env := newRealAuthnTestEnv(t, nil, nil)
	env.now = time.Now().UTC()
	if got := env.emailIdentityVersion(userID); got != 0 {
		t.Fatalf("初始邮箱身份代际 = %d，期望 0", got)
	}
	resetID, _ := env.beginResetWithToken("req-250-bind")
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
	// 客服通道签发同样绑定当前代际。
	if _, err := env.service.SendResetForSupport(env.ctx, passwordreset.SupportResetRequest{
		TargetUserID: userID, RequestID: "req-250-bind-support"}); err != nil {
		t.Fatalf("客服通道签发: %v", err)
	}
	pending, err := env.resetStore.ListPending(env.ctx, userID)
	if err != nil || len(pending) != 1 {
		t.Fatalf("客服通道 pending 数 = %d err=%v", len(pending), err)
	}
	if !pending[0].Bound || pending[0].BoundEmailIdentityVersion != target.EmailIdentityVersion {
		t.Fatalf("客服通道绑定不正确: %+v", pending[0])
	}
}

// TestResetLinkNotRevivedByRoundTripEmailChange 是本步核心回归：同一 TTL 内
// A→B→A 往返换绑（两次切换使用同一时间戳，地址被删除后重新新增）不得复活旧链接。
func TestResetLinkNotRevivedByRoundTripEmailChange(t *testing.T) {
	env := newRealAuthnTestEnv(t, nil, nil)
	env.now = time.Now().UTC()
	emailService, sender := newEmailChangeService(t, env)
	const emailA = "alice@example.com"
	const emailB = "alice.roundtrip@example.test"
	generation0 := env.emailIdentityVersion(userID)

	resetID, oldToken := env.beginResetWithToken("req-250-roundtrip-old")
	oldRequest, found, err := env.resetStore.GetRequest(env.ctx, resetID)
	if err != nil || !found {
		t.Fatalf("读取原请求: found=%v err=%v", found, err)
	}
	if oldRequest.BoundEmailIdentityVersion != generation0 {
		t.Fatalf("原请求代际 = %d，期望 %d", oldRequest.BoundEmailIdentityVersion, generation0)
	}
	beforeHash := env.passwordHash(userID)
	beforeSecurityVersion := env.securityVersion(userID)

	// A→B：旧地址的已验证行在此事务内被删除。切换时钟不变，模拟“同时间戳”。
	generation1 := switchVerifiedEmail(t, env, emailService, sender, userID, emailB, "req-250-switch-ab")
	if generation1 != generation0+1 {
		t.Fatalf("A→B 后邮箱身份代际 = %d，期望 %d", generation1, generation0+1)
	}
	// 旧链接在第一次换绑后已失效（既有 206 行为）。
	if err := env.service.ValidateResetToken(env.ctx, oldToken); !errors.Is(err, passwordreset.ErrTokenInvalid) {
		t.Fatalf("A→B 后旧链接预检查错误 = %v，期望 ErrTokenInvalid", err)
	}
	// B→A：重新新增与签发时文本完全相同的地址，两次切换时间戳相同。
	if err := env.service.ValidateResetToken(env.ctx, oldToken); !errors.Is(err, passwordreset.ErrTokenInvalid) {
		t.Fatalf("B→A 前旧链接预检查错误 = %v，期望 ErrTokenInvalid", err)
	}
	generation2 := switchVerifiedEmail(t, env, emailService, sender, userID, emailA, "req-250-switch-ba")
	if generation2 != generation1+1 {
		t.Fatalf("B→A 后邮箱身份代际 = %d，期望 %d", generation2, generation1+1)
	}
	// 关键断言：邮箱文本回到 A、安全版本未变，但代际已前进，旧链接不得复活。
	current, currentFound, err := env.resetStore.GetResetTarget(env.ctx, userID)
	if err != nil || !currentFound {
		t.Fatalf("读取当前目标: found=%v err=%v", currentFound, err)
	}
	if current.EmailNormalized != emailA || current.SecurityVersion != beforeSecurityVersion ||
		current.EmailIdentityVersion != generation2 {
		t.Fatalf("往返后状态异常: email=%q version=%d identity=%d（期望 %q/%d/%d）",
			current.EmailNormalized, current.SecurityVersion, current.EmailIdentityVersion,
			emailA, beforeSecurityVersion, generation2)
	}
	if err := env.service.ValidateResetToken(env.ctx, oldToken); !errors.Is(err, passwordreset.ErrTokenInvalid) {
		t.Fatalf("A→B→A 后旧链接预检查错误 = %v，期望 ErrTokenInvalid（不得复活）", err)
	}
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: oldToken, NewPassword: strongNewPassword, RequestID: "req-250-roundtrip-old-complete"}); !errors.Is(err, passwordreset.ErrTokenInvalid) {
		t.Fatalf("A→B→A 后旧链接完成错误 = %v，期望 ErrTokenInvalid（不得复活）", err)
	}
	// 拒绝是确定性的：请求仍 pending、凭证未被消费、密码与安全版本未变。
	env.assertRequestPending(resetID)
	env.assertCredentialActive(oldRequest.CredentialID)
	if env.passwordHash(userID) != beforeHash || env.securityVersion(userID) != beforeSecurityVersion {
		t.Fatal("旧链接拒绝不应改密码或安全版本")
	}
	// 新申请可用：当前身份（A、新代际）签发的新链接完成成功。
	newID, newToken := env.beginResetWithToken("req-250-roundtrip-new")
	newRequest, found, err := env.resetStore.GetRequest(env.ctx, newID)
	if err != nil || !found {
		t.Fatalf("读取新请求: found=%v err=%v", found, err)
	}
	if newRequest.BoundEmailIdentityVersion != generation2 {
		t.Fatalf("新请求代际 = %d，期望 %d", newRequest.BoundEmailIdentityVersion, generation2)
	}
	if err := env.service.ValidateResetToken(env.ctx, newToken); err != nil {
		t.Fatalf("新链接预检查失败: %v", err)
	}
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: newToken, NewPassword: strongNewPassword, RequestID: "req-250-roundtrip-new-complete"}); err != nil {
		t.Fatalf("新链接完成失败: %v", err)
	}
}

// TestResetFirstEmailBindingAdvancesIdentityVersion 验证首次绑定（无已验证邮箱 →
// 首次添加）使代际从 0 前进，新申请绑定新代际且可用；绑定前形态的旧行仍失效。
func TestResetFirstEmailBindingAdvancesIdentityVersion(t *testing.T) {
	env := newRealAuthnTestEnv(t, nil, nil)
	env.now = time.Now().UTC()
	const firstUserID = "usr_00000000000000000000000000000005"
	env.seedUser(firstUserID, "firstbind", "active", false)
	// 用真实 authn 写入可用的真实密码凭证，避免合成哈希影响提交路径。
	if _, err := env.realAuthn.SetPassword(env.ctx, env.systemCaller, authn.SetPasswordRequest{
		TargetUserID: firstUserID, NewPassword: realInitialPassword,
		RequestID: "req-250-first-initial-password"}); err != nil {
		t.Fatalf("设置初始密码: %v", err)
	}
	if got := env.emailIdentityVersion(firstUserID); got != 0 {
		t.Fatalf("首次绑定前代际 = %d，期望 0", got)
	}
	// 首次绑定前无已验证邮箱：找回入口不可用且不产生请求。
	if _, err := env.service.BeginReset(env.ctx, passwordreset.BeginResetRequest{
		Identifier: "first.bind@example.test", RequestID: "req-250-first-before"}); err != nil {
		t.Fatalf("首次绑定前发起找回不应暴露错误: %v", err)
	}
	if count := env.count(`SELECT COUNT(*) FROM password_reset_requests WHERE user_id=?`, firstUserID); count != 0 {
		t.Fatalf("首次绑定前不应创建找回请求，实际 %d", count)
	}
	emailService, sender := newEmailChangeService(t, env)
	generation := switchVerifiedEmail(t, env, emailService, sender, firstUserID,
		"first.bind@example.test", "req-250-first-add")
	if generation != 1 {
		t.Fatalf("首次绑定后代际 = %d，期望 1", generation)
	}
	token := beginResetWithEmail(t, env, "first.bind@example.test", "req-250-first-reset")
	if err := env.service.ValidateResetToken(env.ctx, token); err != nil {
		t.Fatalf("首次绑定后新链接预检查失败: %v", err)
	}
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: token, NewPassword: strongNewPassword, RequestID: "req-250-first-complete"}); err != nil {
		t.Fatalf("首次绑定后新链接完成失败: %v", err)
	}
}

// TestResetLegacyBoundWithoutEmailIdentityRejected 验证 0053 之前已绑定（仅安全版本 +
// 邮箱文本）的旧行保守失效：预检查与完成都拒绝且不消费；新请求带完整绑定可完成。
func TestResetLegacyBoundWithoutEmailIdentityRejected(t *testing.T) {
	env := newRealAuthnTestEnv(t, nil, nil)
	env.now = time.Now().UTC()
	resetID, credentialID, token := env.insertBoundResetWithoutEmailIdentity("req-250-legacy")
	if err := env.service.ValidateResetToken(env.ctx, token); !errors.Is(err, passwordreset.ErrTokenInvalid) {
		t.Fatalf("无邮箱身份代际旧行预检查错误 = %v，期望 ErrTokenInvalid", err)
	}
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: token, NewPassword: strongNewPassword, RequestID: "req-250-legacy-complete"}); !errors.Is(err, passwordreset.ErrTokenInvalid) {
		t.Fatalf("无邮箱身份代际旧行完成错误 = %v，期望 ErrTokenInvalid", err)
	}
	env.assertRequestPending(resetID)
	env.assertCredentialActive(credentialID)
	// 旧行未被回填：数据库中该列仍为 NULL（迁移不做不安全兼容）。
	var identityVersion *int64
	if err := env.raw.DB().QueryRowContext(env.ctx,
		`SELECT bound_email_identity_version FROM password_reset_requests WHERE id=?`,
		resetID).Scan(&identityVersion); err != nil {
		t.Fatalf("读取旧行绑定列: %v", err)
	}
	if identityVersion != nil {
		t.Fatalf("旧行绑定列应保持 NULL（不回填），实际 %d", *identityVersion)
	}
	// 新申请具有完整绑定并可完成。
	newID, newToken := env.beginResetWithToken("req-250-legacy-new")
	request, found, err := env.resetStore.GetRequest(env.ctx, newID)
	if err != nil || !found {
		t.Fatalf("读取新请求: found=%v err=%v", found, err)
	}
	if !request.Bound {
		t.Fatal("新请求缺少完整绑定")
	}
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: newToken, NewPassword: strongNewPassword, RequestID: "req-250-legacy-new-complete"}); err != nil {
		t.Fatalf("新请求完成失败: %v", err)
	}
}

// racingIdentityPasswords 在真实密码服务 PrepareRecoveryReset 成功后同步执行一次
// A→B→A 往返换绑，模拟“事务外准备与最终提交之间邮箱身份发生变化”的竞争窗口。
// 仅用于测试，不进入生产装配。
type racingIdentityPasswords struct {
	service   passwordreset.PasswordService
	committer passwordreset.RecoveryCommitter
	env       *testEnv
	email     *emailchange.Service
	sender    *captureEmailChangeSender
	mu        sync.Mutex
	fire      bool
	switched  bool
}

func (r *racingIdentityPasswords) setFire(value bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fire = value
}

func (r *racingIdentityPasswords) shouldFire() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.fire
}

func (r *racingIdentityPasswords) didSwitch() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.switched
}

func (r *racingIdentityPasswords) SetPassword(ctx context.Context, caller authn.Caller,
	request authn.SetPasswordRequest) (authn.SetPasswordResult, error) {
	return r.service.SetPassword(ctx, caller, request)
}

func (r *racingIdentityPasswords) ResetPasswordForRecovery(ctx context.Context, caller authn.Caller,
	request authn.RecoveryResetRequest) (authn.SetPasswordResult, error) {
	return r.service.ResetPasswordForRecovery(ctx, caller, request)
}

func (r *racingIdentityPasswords) PrepareRecoveryReset(ctx context.Context, caller authn.Caller,
	request authn.RecoveryResetRequest) (authn.PreparedRecoveryReset, error) {
	prepared, err := r.committer.PrepareRecoveryReset(ctx, caller, request)
	if err != nil || !r.shouldFire() {
		return prepared, err
	}
	// 事务外准备完成、最终提交事务尚未开始时完成 A→B→A（真实 emailchange 服务）。
	switchVerifiedEmail(r.env.t, r.env, r.email, r.sender, userID,
		"alice.race@example.test", "req-250-race-ab")
	switchVerifiedEmail(r.env.t, r.env, r.email, r.sender, userID,
		"alice@example.com", "req-250-race-ba")
	r.mu.Lock()
	r.switched = true
	r.mu.Unlock()
	return prepared, nil
}

func (r *racingIdentityPasswords) ApplyRecoveryResetTx(ctx context.Context, caller authn.Caller,
	prepared authn.PreparedRecoveryReset, tx audit.Tx) (authn.SetPasswordResult, error) {
	return r.committer.ApplyRecoveryResetTx(ctx, caller, prepared, tx)
}

var (
	_ passwordreset.PasswordService   = (*racingIdentityPasswords)(nil)
	_ passwordreset.RecoveryCommitter = (*racingIdentityPasswords)(nil)
)

// TestCompleteResetEmailIdentityChangedAtCommitBoundaryRollsBack 验证：准备阶段之后、
// 最终提交事务之前完成 A→B→A，事务内绑定复核（邮箱文本相同、安全版本相同、代际不同）
// 返回确定性失效 ErrTokenInvalid 并整体回滚；同一入口不产生半提交，新链接可用。
func TestCompleteResetEmailIdentityChangedAtCommitBoundaryRollsBack(t *testing.T) {
	env := newRealAuthnTestEnv(t, nil, nil)
	env.now = time.Now().UTC()
	emailService, sender := newEmailChangeService(t, env)
	resetID, token := env.beginResetWithToken("req-250-boundary-begin")
	request, found, err := env.resetStore.GetRequest(env.ctx, resetID)
	if err != nil || !found {
		t.Fatalf("读取请求: found=%v err=%v", found, err)
	}
	beforeHash := env.passwordHash(userID)
	beforeSecurityVersion := env.securityVersion(userID)
	racing := &racingIdentityPasswords{
		service:   env.options.Passwords,
		committer: env.options.Passwords.(passwordreset.RecoveryCommitter),
		env:       env,
		email:     emailService,
		sender:    sender,
	}
	racing.setFire(true)
	options := env.options
	options.Passwords = racing
	service, err := passwordreset.New(options)
	if err != nil {
		t.Fatalf("重建找回服务: %v", err)
	}
	env.service = service
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: token, NewPassword: strongNewPassword, RequestID: "req-250-boundary-complete"}); !errors.Is(err, passwordreset.ErrTokenInvalid) {
		t.Fatalf("提交边界邮箱身份变化错误 = %v，期望 ErrTokenInvalid", err)
	}
	if !racing.didSwitch() {
		t.Fatal("测试注入的换绑未执行")
	}
	// 事务整体回滚：请求仍 pending、凭证未消费、密码/安全版本未变。
	env.assertRequestPending(resetID)
	env.assertCredentialActive(request.CredentialID)
	if env.passwordHash(userID) != beforeHash || env.securityVersion(userID) != beforeSecurityVersion {
		t.Fatal("提交边界拒绝不应留下已改密/已消费的半提交")
	}
	// 关键审计记录了本次确定性失败（事务内绑定复核失败走关键审计的失败事件）。
	if count := env.count(`SELECT COUNT(*) FROM audit_events
WHERE action='password.reset_completed' AND outcome='failure' AND reason_code='password.reset_completed_failed'`); count < 1 {
		t.Error("缺少提交边界绑定复核失败的审计事件")
	}
	// 换绑完成后旧代际链接仍不可用，新代际链接可完成。
	if err := env.service.ValidateResetToken(env.ctx, token); !errors.Is(err, passwordreset.ErrTokenInvalid) {
		t.Fatalf("换绑后旧链接预检查错误 = %v，期望 ErrTokenInvalid", err)
	}
	// 关闭注入的竞争换绑后，新代际链接正常完成。
	racing.setFire(false)
	_, newToken := env.beginResetWithToken("req-250-boundary-new")
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: newToken, NewPassword: strongNewPassword, RequestID: "req-250-boundary-new-complete"}); err != nil {
		t.Fatalf("新代际链接完成失败: %v", err)
	}
}

// TestResetThenEmailSwitchKeepsSingleApplyAndNoRevival 覆盖并发测试的另一种合法顺序：
// 找回提交先成功（令牌已消费、密码已改变），随后发生 A→B→A 换绑。旧令牌仍拒绝重放，
// 密码不会被二次修改，换绑后的新身份可正常发起新找回。
func TestResetThenEmailSwitchKeepsSingleApplyAndNoRevival(t *testing.T) {
	env := newRealAuthnTestEnv(t, nil, nil)
	env.now = time.Now().UTC()
	emailService, sender := newEmailChangeService(t, env)
	resetID, token := env.beginResetWithToken("req-250-order-reset-first")
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: token, NewPassword: strongNewPassword, RequestID: "req-250-order-reset-complete"}); err != nil {
		t.Fatalf("找回提交: %v", err)
	}
	versionAfterReset := env.securityVersion(userID)
	hashAfterReset := env.passwordHash(userID)
	// 成功后换绑 A→B→A（同一时间戳）。
	if got := switchVerifiedEmail(t, env, emailService, sender, userID,
		"alice.after.reset@example.test", "req-250-order-ab"); got != 1 {
		t.Fatalf("A→B 后代际 = %d，期望 1", got)
	}
	if got := switchVerifiedEmail(t, env, emailService, sender, userID,
		"alice@example.com", "req-250-order-ba"); got != 2 {
		t.Fatalf("B→A 后代际 = %d，期望 2", got)
	}
	// 已消费令牌不得复活/重放，密码与安全版本不得再次变化。
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: token, NewPassword: strongNewPassword2, RequestID: "req-250-order-replay"}); !errors.Is(err, passwordreset.ErrTokenInvalid) {
		t.Fatalf("换绑后已消费令牌重放错误 = %v，期望 ErrTokenInvalid", err)
	}
	if err := env.service.ValidateResetToken(env.ctx, token); !errors.Is(err, passwordreset.ErrTokenInvalid) {
		t.Fatalf("换绑后已消费令牌预检查错误 = %v，期望 ErrTokenInvalid", err)
	}
	if env.passwordHash(userID) != hashAfterReset || env.securityVersion(userID) != versionAfterReset {
		t.Fatal("换绑后重放不得再次修改密码或安全版本")
	}
	var state string
	if err := env.raw.DB().QueryRowContext(env.ctx,
		`SELECT state FROM password_reset_requests WHERE id=?`, resetID).Scan(&state); err != nil {
		t.Fatalf("读取请求状态: %v", err)
	}
	if state != "consumed" {
		t.Fatalf("请求状态 = %s，期望 consumed", state)
	}
	// 往返换绑后的当前身份可正常发起并完成新找回。
	newToken := beginResetWithEmail(t, env, "alice@example.com", "req-250-order-new")
	if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
		Token: newToken, NewPassword: strongNewPassword2, RequestID: "req-250-order-new-complete"}); err != nil {
		t.Fatalf("换绑后新链接完成失败: %v", err)
	}
}

// TestConcurrentEmailSwitchAndResetStaysConsistent 验证并发换绑与找回提交：SQLite 写
// 事务串行化，任意合法顺序都不产生双赢家或“旧链接在失效后被消费”。换绑成功后旧链接
// 一定不可用、新申请可用；若提交先赢，则其请求已消费且重放被拒绝。
func TestConcurrentEmailSwitchAndResetStaysConsistent(t *testing.T) {
	env := newRealAuthnTestEnv(t, nil, nil)
	env.now = time.Now().UTC()
	emailService, sender := newEmailChangeService(t, env)
	const emailA = "alice@example.com"
	const emailB = "alice.concurrent@example.test"
	resetID, token := env.beginResetWithToken("req-250-concurrent-begin")
	request, found, err := env.resetStore.GetRequest(env.ctx, resetID)
	if err != nil || !found {
		t.Fatalf("读取请求: found=%v err=%v", found, err)
	}
	// 预创建换绑申请，使两个 goroutine 只需各自完成最终提交（验证/找回）。
	caller, err := emailchange.UserCaller(userID)
	if err != nil {
		t.Fatalf("邮箱变更调用者: %v", err)
	}
	if _, err := emailService.RequestChange(env.ctx, caller, emailB, "req-250-concurrent-change"); err != nil {
		t.Fatalf("发起并发换绑: %v", err)
	}
	parsed, err := url.Parse(sender.verifications[len(sender.verifications)-1].VerificationURL)
	if err != nil {
		t.Fatalf("解析验证入口: %v", err)
	}
	query := parsed.Query()
	startChannel := make(chan struct{})
	verifyErr := make(chan error, 1)
	resetErr := make(chan error, 1)
	var waitGroup sync.WaitGroup
	waitGroup.Add(2)
	go func() {
		defer waitGroup.Done()
		<-startChannel
		_, err := emailService.Verify(env.ctx, emailchange.VerifyRequest{
			RequestID: query.Get("rid"), CredentialID: query.Get("cid"),
			Token: query.Get("token"), RequestIDLog: "req-250-concurrent-verify",
		})
		verifyErr <- err
	}()
	go func() {
		defer waitGroup.Done()
		<-startChannel
		_, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
			Token: token, NewPassword: strongNewPassword, RequestID: "req-250-concurrent-complete"})
		resetErr <- err
	}()
	close(startChannel)
	waitGroup.Wait()
	close(verifyErr)
	close(resetErr)
	if err := <-verifyErr; err != nil {
		t.Fatalf("并发换绑验证失败: %v", err)
	}
	if current := env.emailIdentityVersion(userID); current != 1 {
		t.Fatalf("并发换绑后代际 = %d，期望 1", current)
	}
	switch err := <-resetErr; {
	case err == nil:
		// 找回先于换绑提交：请求已消费，重放必须拒绝，旧密码入口已失效。
		t.Log("并发顺序：找回提交先赢，随后换绑提交")
		var state string
		if err := env.raw.DB().QueryRowContext(env.ctx,
			`SELECT state FROM password_reset_requests WHERE id=?`, resetID).Scan(&state); err != nil {
			t.Fatalf("读取找回请求状态: %v", err)
		}
		if state != "consumed" {
			t.Fatalf("并发成功请求状态 = %s，期望 consumed", state)
		}
		if _, replayErr := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
			Token: token, NewPassword: strongNewPassword2, RequestID: "req-250-concurrent-replay"}); !errors.Is(replayErr, passwordreset.ErrTokenInvalid) {
			t.Fatalf("并发成功后重放错误 = %v，期望 ErrTokenInvalid", replayErr)
		}
	case errors.Is(err, passwordreset.ErrTokenInvalid):
		// 换绑先提交：旧链接确定性失效，凭证未被消费，新代际链接可用。
		t.Log("并发顺序：换绑提交先赢，旧链接在最终提交边界被拒绝")
		env.assertRequestPending(resetID)
		env.assertCredentialActive(request.CredentialID)
		if err := env.service.ValidateResetToken(env.ctx, token); !errors.Is(err, passwordreset.ErrTokenInvalid) {
			t.Fatalf("并发换绑后旧链接预检查错误 = %v，期望 ErrTokenInvalid", err)
		}
		newToken := beginResetWithEmail(t, env, emailB, "req-250-concurrent-new")
		if _, err := env.service.CompleteReset(env.ctx, passwordreset.CompleteRequest{
			Token: newToken, NewPassword: strongNewPassword, RequestID: "req-250-concurrent-new-complete"}); err != nil {
			t.Fatalf("并发换绑后新链接完成失败: %v", err)
		}
	default:
		t.Fatalf("并发找回未知错误: %v", err)
	}
}
