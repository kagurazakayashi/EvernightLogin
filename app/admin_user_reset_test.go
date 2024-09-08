package app

// 步骤 257：直接重置他人密码的公开 Go 门面端到端测试（真实临时 SQLite + 真实
// 会话/权限/两步验证/TOTP/密码策略与历史/审计装配）。
//
// 覆盖：成功链（must_change、旧会话失效、旧找回失效、OAuth 撤销 outbox、审计与证明
// 单次消费）、绑定换口令/换目标/重放拒绝、弱口令与历史复用后可修正重试、无密码账户
// 拒绝、LocalAdmin/无权限/权限撤回拒绝、非 root 不能重置 root、root 作为操作者成功、
// 并发单赢家、MustChange 受限登录后完成本人改密、频率限制。
//
// 测试只使用合成口令且不把口令写入失败消息或日志。

import (
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

// 合成测试口令（测试失败消息只引用变量名，不展开口令值）。
var (
	resetPasswordCurrent  = "K8$wR3!nB6@yF1#v" // proofReadyRuntime 创建账户时使用的口令
	resetPasswordDirectA  = "Qz7!vN9#Lp2@Rm5"
	resetPasswordDirectB  = "Ht5!cK8#Wn3@Pv6"
	resetPasswordWeak     = "password"
	resetPasswordFinal    = "Jr9!xB4#Ms7@Qd2"
	resetPasswordInvalidA = "Wm2!qT6#Yh9@Lc4" // 仅用于“换口令”绑定拒绝
)

// resetTestTOTP 返回操作者下一个时间步动态码（推进可控时钟避免重放保护拒绝）。
func resetTestTOTP(t *testing.T, clock *testClock, secret string) string {
	t.Helper()
	clock.Advance(30 * time.Second)
	return currentTOTP(t, clock, secret)
}

// beginResetProof 通过 255 证明门面完成一次“直接重置口令”两步验证，返回证明令牌。
func beginResetProof(t *testing.T, runtime *Runtime, clock *testClock, session []byte,
	totpSecret, targetUserID, newPassword string) string {
	t.Helper()
	ctx := context.Background()
	proof := runtime.OperationProof()
	caller := runtime.AdminSession(session)
	challenge, err := proof.Begin(ctx, OperationProofBeginRequest{
		Caller: caller, TargetUserID: targetUserID, Operation: OperationProofPasswordReset,
		NewPassword: newPassword, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("发起直接重置口令证明: %v", err)
	}
	grant, err := proof.Confirm(ctx, OperationProofConfirmRequest{
		Caller: caller, ChallengeID: challenge.ChallengeID, Password: resetPasswordCurrent,
		TOTPCode: resetTestTOTP(t, clock, totpSecret), RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("完成直接重置口令两步验证: %v", err)
	}
	return grant.ProofToken
}

// resetTargetUsername 读取目标显示用户名（用于登录）。
func resetTargetUsername(t *testing.T, runtime *Runtime, userID string) string {
	t.Helper()
	var username string
	if err := runtime.base.Store.DB().QueryRow(
		`SELECT username FROM users WHERE id=?`, userID).Scan(&username); err != nil {
		t.Fatalf("读取目标用户名: %v", err)
	}
	return username
}

// resetLogin 用口令登录并把错误交给调用方断言。
func resetLogin(t *testing.T, runtime *Runtime, username, password string) (LoginResult, error) {
	t.Helper()
	return runtime.Auth().Login(context.Background(), LoginRequest{
		Username: username, Password: password, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()})
}

// resetSecurityVersion 读取账户安全版本。
func resetSecurityVersion(t *testing.T, runtime *Runtime, userID string) int64 {
	t.Helper()
	var version int64
	if err := runtime.base.Store.DB().QueryRow(
		`SELECT security_version FROM users WHERE id=?`, userID).Scan(&version); err != nil {
		t.Fatalf("读取安全版本: %v", err)
	}
	return version
}

// resetCredentialMustChange 读取目标密码凭证的 must_change 标记。
func resetCredentialMustChange(t *testing.T, runtime *Runtime, userID string) bool {
	t.Helper()
	var mustChange int
	if err := runtime.base.Store.DB().QueryRow(
		`SELECT must_change FROM password_credentials WHERE user_id=?`, userID).
		Scan(&mustChange); err != nil {
		t.Fatalf("读取密码凭证: %v", err)
	}
	return mustChange == 1
}

// resetProofConsumedCount 统计已消费的直接管理证明数。
func resetProofConsumedCount(t *testing.T, runtime *Runtime) int {
	t.Helper()
	var count int
	if err := runtime.base.Store.DB().QueryRow(
		`SELECT COUNT(*) FROM reauth_approvals WHERE consumed_at_ms IS NOT NULL`).Scan(&count); err != nil {
		t.Fatalf("读取证明消费数: %v", err)
	}
	return count
}

// TestDirectPasswordResetSuccessAndMustChangeFlow 覆盖成功链与 must_change 完成流程。
func TestDirectPasswordResetSuccessAndMustChangeFlow(t *testing.T) {
	ctx := context.Background()
	runtime, clock, operatorID, targetUserID, session, totpSecret := proofReadyRuntime(t, ctx)
	targetName := resetTargetUsername(t, runtime, targetUserID)
	// 目标先有一个正常会话：重置后必须失效。
	targetLogin, err := resetLogin(t, runtime, targetName, resetPasswordCurrent)
	if err != nil || len(targetLogin.SessionSecret) == 0 {
		t.Fatalf("目标登录: %v", err)
	}
	// 目标预先有一个 pending 找回入口：同一事务内必须作废。
	nowMS := clock.Now().UTC().UnixMilli()
	credentialID := "otc_0000000000000000000000000000f001"
	verifierHash := make([]byte, 32)
	if _, err := rand.Read(verifierHash); err != nil {
		t.Fatalf("生成找回凭证摘要: %v", err)
	}
	if _, err := runtime.base.Store.DB().Exec(`INSERT INTO one_time_credentials(
id,purpose,subject_id,verifier_hash,max_attempts,created_at_ms,expires_at_ms)
VALUES(?,'password.reset',?,?,1,?,?)`, credentialID, targetUserID, verifierHash,
		nowMS, nowMS+10*60*1000); err != nil {
		t.Fatalf("插入 pending 找回凭证: %v", err)
	}
	if _, err := runtime.base.Store.DB().Exec(`INSERT INTO password_reset_requests(
id,user_id,masked_email,credential_id,token_sha256,state,created_at_ms,expires_at_ms)
VALUES(?,?,?,?,?,'pending',?,?)`, "prr_0000000000000000000000000000f001",
		targetUserID, "t***@example.test", credentialID, verifierHash, nowMS, nowMS+10*60*1000); err != nil {
		t.Fatalf("插入 pending 找回请求: %v", err)
	}
	outboxBefore := countRows(t, runtime, `SELECT COUNT(*) FROM oauth_revocation_events
WHERE user_id=?`, targetUserID)
	token := beginResetProof(t, runtime, clock, session, totpSecret, targetUserID,
		resetPasswordDirectA)
	result, err := runtime.DirectPasswordManagement().ResetUserPassword(ctx,
		AdminResetUserPasswordRequest{
			Caller: runtime.AdminSession(session), TargetUserID: targetUserID,
			NewPassword: resetPasswordDirectA, Reason: "工单 #257：用户忘记口令",
			ProofToken: token, RequestID: login.NewRequestID(),
		})
	if err != nil {
		t.Fatalf("直接重置口令: %v", err)
	}
	if result.UserID != targetUserID || !result.MustChange ||
		result.SecurityVersion != 2 || result.OutboxEventID == "" {
		t.Fatalf("重置结果异常: %+v", result)
	}
	if !resetCredentialMustChange(t, runtime, targetUserID) {
		t.Fatal("重置后密码凭证必须带 must_change")
	}
	if got := resetSecurityVersion(t, runtime, targetUserID); got != 2 {
		t.Fatalf("安全版本 = %d，期望 2", got)
	}
	// 旧会话失效。
	if _, err := runtime.coreServices().Sessions.Validate(ctx,
		string(targetLogin.SessionSecret)); err == nil {
		t.Fatal("重置后目标旧会话仍有效")
	}
	// 旧找回入口作废 + OAuth 撤销事件同事务提交。
	var resetState string
	if err := runtime.base.Store.DB().QueryRow(
		`SELECT state FROM password_reset_requests WHERE id=?`,
		"prr_0000000000000000000000000000f001").Scan(&resetState); err != nil {
		t.Fatalf("读取找回请求状态: %v", err)
	}
	if resetState != "cancelled" {
		t.Fatalf("旧找回请求状态 = %q，期望 cancelled", resetState)
	}
	if got := countRows(t, runtime, `SELECT COUNT(*) FROM oauth_revocation_events
WHERE user_id=?`, targetUserID); got != outboxBefore+1 {
		t.Fatalf("OAuth 撤销事件数 = %d，期望 %d", got, outboxBefore+1)
	}
	// 关键审计与证明消费。
	var auditCount int
	if err := runtime.base.Store.DB().QueryRow(`SELECT COUNT(*) FROM audit_events
WHERE action='admin.direct_password_reset' AND outcome='success' AND actor_id=?`,
		operatorID).Scan(&auditCount); err != nil {
		t.Fatalf("读取审计: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("直接重置成功审计数 = %d，期望 1", auditCount)
	}
	if consumed := resetProofConsumedCount(t, runtime); consumed != 1 {
		t.Fatalf("证明消费数 = %d，期望 1", consumed)
	}
	// 用新口令登录 → 必须进入 restricted 强制改密（不是完整会话）。
	restricted, err := resetLogin(t, runtime, targetName, resetPasswordDirectA)
	if err != nil {
		t.Fatalf("新口令登录: %v", err)
	}
	if !restricted.Restricted || len(restricted.SessionSecret) == 0 {
		t.Fatalf("must_change 登录应为受限会话: %+v", restricted)
	}
	hasPasswordChangeStep := false
	for _, step := range restricted.RequiredSteps {
		if step == "password_change" {
			hasPasswordChangeStep = true
		}
	}
	if !hasPasswordChangeStep {
		t.Fatalf("受限会话 required steps 缺少 password_change: %+v", restricted.RequiredSteps)
	}
	// 受限会话完成本人改密。
	changeResult, err := runtime.RequiredPasswordChanges().Complete(ctx,
		RequiredPasswordChangeRequest{SessionSecret: restricted.SessionSecret,
			CurrentPassword: resetPasswordDirectA, NewPassword: resetPasswordFinal,
			ClientIP: "127.0.0.1", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("受限会话完成改密: %v", err)
	}
	if changeResult.SecurityVersion <= result.SecurityVersion {
		t.Fatalf("改密后安全版本未递增: %+v", changeResult)
	}
	// 旧受限会话作废；用最终口令可完整登录。
	if _, err := runtime.coreServices().Sessions.Validate(ctx,
		string(restricted.SessionSecret)); err == nil {
		t.Fatal("完成改密后受限会话仍有效")
	}
	finalLogin, err := resetLogin(t, runtime, targetName, resetPasswordFinal)
	if err != nil || finalLogin.Restricted {
		t.Fatalf("最终口令应可完整登录: err=%v restricted=%v", err, finalLogin.Restricted)
	}
	// 证明重放：不再次执行、不新增成功审计。
	replayErr := func() error {
		_, replayResetErr := runtime.DirectPasswordManagement().ResetUserPassword(ctx,
			AdminResetUserPasswordRequest{Caller: runtime.AdminSession(session),
				TargetUserID: targetUserID, NewPassword: resetPasswordDirectB,
				Reason: "重放", ProofToken: token, RequestID: login.NewRequestID()})
		return replayResetErr
	}()
	if !login.IsErrorCode(replayErr, login.CodeTokenInvalid) {
		t.Fatalf("重置证明重放错误 = %v，期望 TOKEN_INVALID", replayErr)
	}
	if err := runtime.base.Store.DB().QueryRow(`SELECT COUNT(*) FROM audit_events
WHERE action='admin.direct_password_reset' AND outcome='success'`).Scan(&auditCount); err != nil {
		t.Fatalf("读取审计数: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("重放后成功审计数 = %d，期望 1", auditCount)
	}
}

// countRows 执行单值计数查询。
func countRows(t *testing.T, runtime *Runtime, query string, args ...any) int {
	t.Helper()
	var value int
	if err := runtime.base.Store.DB().QueryRow(query, args...).Scan(&value); err != nil {
		t.Fatalf("计数查询: %v", err)
	}
	return value
}

// TestDirectPasswordResetProofBindingRejected 覆盖换口令/换目标/本人目标拒绝且不烧证明。
func TestDirectPasswordResetProofBindingRejected(t *testing.T) {
	ctx := context.Background()
	runtime, clock, operatorID, targetUserID, session, totpSecret := proofReadyRuntime(t, ctx)
	beforeVersion := resetSecurityVersion(t, runtime, targetUserID)
	token := beginResetProof(t, runtime, clock, session, totpSecret, targetUserID,
		resetPasswordDirectA)
	// 换新口令：证明绑定 A，提交 B → TOKEN_INVALID。
	if _, err := runtime.DirectPasswordManagement().ResetUserPassword(ctx,
		AdminResetUserPasswordRequest{Caller: runtime.AdminSession(session),
			TargetUserID: targetUserID, NewPassword: resetPasswordInvalidA,
			Reason: "换口令", ProofToken: token, RequestID: login.NewRequestID()},
	); !login.IsErrorCode(err, login.CodeTokenInvalid) {
		t.Fatalf("换新口令错误 = %v，期望 TOKEN_INVALID", err)
	}
	// 换目标：另一个用户 → TOKEN_INVALID。
	other, err := runtime.Users().Create(ctx, CreateUserRequest{
		Username: "reset-other-target", Password: resetPasswordDirectB,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建另一目标: %v", err)
	}
	if _, err := runtime.DirectPasswordManagement().ResetUserPassword(ctx,
		AdminResetUserPasswordRequest{Caller: runtime.AdminSession(session),
			TargetUserID: other.ID, NewPassword: resetPasswordDirectA,
			Reason: "换目标", ProofToken: token, RequestID: login.NewRequestID()},
	); !login.IsErrorCode(err, login.CodeTokenInvalid) {
		t.Fatalf("换目标错误 = %v，期望 TOKEN_INVALID", err)
	}
	// 本人目标：REQ_INVALID。
	if _, err := runtime.DirectPasswordManagement().ResetUserPassword(ctx,
		AdminResetUserPasswordRequest{Caller: runtime.AdminSession(session),
			TargetUserID: operatorID, NewPassword: resetPasswordDirectA,
			Reason: "本人", ProofToken: token, RequestID: login.NewRequestID()},
	); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("本人目标错误 = %v，期望 REQ_INVALID", err)
	}
	// 拒绝均未消费证明、未改变安全版本；同一证明正确绑定仍可用。
	if consumed := resetProofConsumedCount(t, runtime); consumed != 0 {
		t.Fatalf("绑定拒绝后证明消费数 = %d，期望 0", consumed)
	}
	if resetSecurityVersion(t, runtime, targetUserID) != beforeVersion {
		t.Fatal("绑定拒绝后安全版本被修改")
	}
	if _, err := runtime.DirectPasswordManagement().ResetUserPassword(ctx,
		AdminResetUserPasswordRequest{Caller: runtime.AdminSession(session),
			TargetUserID: targetUserID, NewPassword: resetPasswordDirectA,
			Reason: "正确绑定重试", ProofToken: token, RequestID: login.NewRequestID()},
	); err != nil {
		t.Fatalf("绑定拒绝后正确重试: %v", err)
	}
}

// TestDirectPasswordResetPolicyAndHistory 覆盖弱口令/历史复用失败后修正重试（新证明）。
func TestDirectPasswordResetPolicyAndHistory(t *testing.T) {
	ctx := context.Background()
	runtime, clock, _, targetUserID, session, totpSecret := proofReadyRuntime(t, ctx)
	caller := runtime.AdminSession(session)
	beforeVersion := resetSecurityVersion(t, runtime, targetUserID)
	// 弱口令：REQ_INVALID，证明未消费、未改密。
	weakToken := beginResetProof(t, runtime, clock, session, totpSecret, targetUserID,
		resetPasswordWeak)
	if _, err := runtime.DirectPasswordManagement().ResetUserPassword(ctx,
		AdminResetUserPasswordRequest{Caller: caller, TargetUserID: targetUserID,
			NewPassword: resetPasswordWeak, Reason: "弱口令", ProofToken: weakToken,
			RequestID: login.NewRequestID()},
	); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("弱口令错误 = %v，期望 REQ_INVALID", err)
	}
	if resetProofConsumedCount(t, runtime) != 0 ||
		resetSecurityVersion(t, runtime, targetUserID) != beforeVersion {
		t.Fatal("弱口令失败后消费了证明或修改了安全版本")
	}
	// 历史复用：与当前口令相同 → REQ_INVALID。
	reuseToken := beginResetProof(t, runtime, clock, session, totpSecret, targetUserID,
		resetPasswordCurrent)
	if _, err := runtime.DirectPasswordManagement().ResetUserPassword(ctx,
		AdminResetUserPasswordRequest{Caller: caller, TargetUserID: targetUserID,
			NewPassword: resetPasswordCurrent, Reason: "历史复用", ProofToken: reuseToken,
			RequestID: login.NewRequestID()},
	); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("历史复用错误 = %v，期望 REQ_INVALID", err)
	}
	if resetProofConsumedCount(t, runtime) != 0 ||
		resetSecurityVersion(t, runtime, targetUserID) != beforeVersion {
		t.Fatal("历史复用失败后消费了证明或修改了安全版本")
	}
	// 修正为合规新口令（新证明）成功。
	goodToken := beginResetProof(t, runtime, clock, session, totpSecret, targetUserID,
		resetPasswordDirectA)
	if _, err := runtime.DirectPasswordManagement().ResetUserPassword(ctx,
		AdminResetUserPasswordRequest{Caller: caller, TargetUserID: targetUserID,
			NewPassword: resetPasswordDirectA, Reason: "修正后重试", ProofToken: goodToken,
			RequestID: login.NewRequestID()},
	); err != nil {
		t.Fatalf("修正后重试: %v", err)
	}
}

// TestDirectPasswordResetAuthorization 覆盖 LocalAdmin/无权限/权限撤回/root 目标与 root 操作者。
func TestDirectPasswordResetAuthorization(t *testing.T) {
	ctx := context.Background()
	runtime, clock, operatorID, targetUserID, session, totpSecret := proofReadyRuntime(t, ctx)
	caller := runtime.AdminSession(session)
	needsProof := func() string {
		return beginResetProof(t, runtime, clock, session, totpSecret, targetUserID,
			resetPasswordDirectA)
	}
	// LocalAdmin：拒绝。
	if _, err := runtime.DirectPasswordManagement().ResetUserPassword(ctx,
		AdminResetUserPasswordRequest{Caller: runtime.LocalAdmin(),
			TargetUserID: targetUserID, NewPassword: resetPasswordDirectA,
			Reason: "local", ProofToken: needsProof(), RequestID: login.NewRequestID()},
	); !login.IsErrorCode(err, login.CodeAccessDenied) {
		t.Fatalf("LocalAdmin 错误 = %v，期望 ACCESS_DENIED", err)
	}
	// 无权限普通用户：拒绝（权限检查先于证明消费）。
	noPerm, err := runtime.Users().Create(ctx, CreateUserRequest{
		Username: "reset-no-perm", Password: resetPasswordDirectB,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建无权限用户: %v", err)
	}
	_ = noPerm
	noPermLogin, err := resetLogin(t, runtime, "reset-no-perm", resetPasswordDirectB)
	if err != nil {
		t.Fatalf("无权限用户登录: %v", err)
	}
	if _, err := runtime.DirectPasswordManagement().ResetUserPassword(ctx,
		AdminResetUserPasswordRequest{Caller: runtime.AdminSession(noPermLogin.SessionSecret),
			TargetUserID: targetUserID, NewPassword: resetPasswordDirectA,
			Reason: "no-perm", ProofToken: "dummy", RequestID: login.NewRequestID()},
	); !login.IsErrorCode(err, login.CodeAccessDenied) {
		t.Fatalf("无权限用户错误 = %v，期望 ACCESS_DENIED", err)
	}
	// 证明在权限仍有效时取得（权限撤回后不能也不应再获取证明）；随后停用权限行，
	// 由门面的真实权限判定拒绝。
	proofForDenied := beginResetProof(t, runtime, clock, session, totpSecret, targetUserID,
		resetPasswordDirectA)
	// 权限撤回：停用权限行后拒绝。
	if _, err := runtime.base.Store.DB().Exec(
		`UPDATE permissions SET enabled=0 WHERE scope_id='system' AND permission_key=?`,
		"users.password.reset.other"); err != nil {
		t.Fatalf("停用权限: %v", err)
	}
	if _, err := runtime.DirectPasswordManagement().ResetUserPassword(ctx,
		AdminResetUserPasswordRequest{Caller: caller, TargetUserID: targetUserID,
			NewPassword: resetPasswordDirectA, Reason: "权限撤回",
			ProofToken: proofForDenied, RequestID: login.NewRequestID()},
	); !login.IsErrorCode(err, login.CodeAccessDenied) {
		t.Fatalf("权限撤回错误 = %v，期望 ACCESS_DENIED", err)
	}
	if _, err := runtime.base.Store.DB().Exec(
		`UPDATE permissions SET enabled=1 WHERE scope_id='system' AND permission_key=?`,
		"users.password.reset.other"); err != nil {
		t.Fatalf("恢复权限: %v", err)
	}
	// root 目标：非 root 操作者拒绝（root 密码只走本人/本地应急流程）。
	if _, err := runtime.base.Store.DB().Exec(
		`UPDATE users SET is_root=1 WHERE id=?`, targetUserID); err != nil {
		t.Fatalf("设置 root 目标: %v", err)
	}
	// root 目标在领域准备阶段即拒绝（不需要也不应该为 root 目标获取证明）。
	if _, err := runtime.DirectPasswordManagement().ResetUserPassword(ctx,
		AdminResetUserPasswordRequest{Caller: caller, TargetUserID: targetUserID,
			NewPassword: resetPasswordDirectA, Reason: "root target",
			ProofToken: strings.Repeat("r", 32), RequestID: login.NewRequestID()},
	); !login.IsErrorCode(err, login.CodeAccessDenied) {
		t.Fatalf("root 目标错误 = %v，期望 ACCESS_DENIED", err)
	}
	_ = operatorID

	// root 作为操作者：另一个运行时，合成 root 后重置非 root 目标成功。
	rootRuntime, rootClock, rootOperatorID, rootTargetID, rootSession, rootTOTP :=
		proofReadyRuntime(t, ctx)
	if _, err := rootRuntime.base.Store.DB().Exec(
		`UPDATE users SET is_root=1 WHERE id=?`, rootOperatorID); err != nil {
		t.Fatalf("设置 root 操作者: %v", err)
	}
	rootToken := beginResetProof(t, rootRuntime, rootClock, rootSession, rootTOTP,
		rootTargetID, resetPasswordDirectA)
	if _, err := rootRuntime.DirectPasswordManagement().ResetUserPassword(ctx,
		AdminResetUserPasswordRequest{Caller: rootRuntime.AdminSession(rootSession),
			TargetUserID: rootTargetID, NewPassword: resetPasswordDirectA,
			Reason: "root operator", ProofToken: rootToken,
			RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("root 作为操作者直接重置口令: %v", err)
	}
}

// TestDirectPasswordResetNoPasswordTargetRejected 覆盖无密码账户拒绝（不得添加密码）。
func TestDirectPasswordResetNoPasswordTargetRejected(t *testing.T) {
	ctx := context.Background()
	runtime, clock, _, _, session, totpSecret := proofReadyRuntime(t, ctx)
	passwordless, err := runtime.Users().Create(ctx, CreateUserRequest{
		Username: "reset-passwordless", Password: resetPasswordDirectB,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建无密码候选: %v", err)
	}
	// 删除密码凭证模拟无密码账户（其他登录方式账户）。
	if _, err := runtime.base.Store.DB().Exec(
		`DELETE FROM password_credentials WHERE user_id=?`, passwordless.ID); err != nil {
		t.Fatalf("删除密码凭证: %v", err)
	}
	token := beginResetProof(t, runtime, clock, session, totpSecret, passwordless.ID,
		resetPasswordDirectA)
	if _, err := runtime.DirectPasswordManagement().ResetUserPassword(ctx,
		AdminResetUserPasswordRequest{Caller: runtime.AdminSession(session),
			TargetUserID: passwordless.ID, NewPassword: resetPasswordDirectA,
			Reason: "无密码账户", ProofToken: token, RequestID: login.NewRequestID()},
	); !login.IsErrorCode(err, login.CodeAccessDenied) {
		t.Fatalf("无密码账户错误 = %v，期望 ACCESS_DENIED", err)
	}
	if got := countRows(t, runtime,
		`SELECT COUNT(*) FROM password_credentials WHERE user_id=?`, passwordless.ID); got != 0 {
		t.Fatalf("无密码账户被添加了密码凭证（%d 条）", got)
	}
	if consumed := resetProofConsumedCount(t, runtime); consumed != 0 {
		t.Fatalf("无密码拒绝后证明消费数 = %d，期望 0", consumed)
	}
}

// TestDirectPasswordResetConcurrentSingleWinner 覆盖同目标并发只允许一个赢家。
func TestDirectPasswordResetConcurrentSingleWinner(t *testing.T) {
	ctx := context.Background()
	runtime, clock, _, targetUserID, session, totpSecret := proofReadyRuntime(t, ctx)
	tokenA := beginResetProof(t, runtime, clock, session, totpSecret, targetUserID,
		resetPasswordDirectA)
	tokenB := beginResetProof(t, runtime, clock, session, totpSecret, targetUserID,
		resetPasswordDirectB)
	caller := runtime.AdminSession(session)
	type outcome struct {
		password string
		err      error
	}
	results := make(chan outcome, 2)
	var start sync.WaitGroup
	start.Add(1)
	run := func(password, token string) {
		defer func() { recover() }()
		start.Wait()
		_, err := runtime.DirectPasswordManagement().ResetUserPassword(ctx,
			AdminResetUserPasswordRequest{Caller: caller, TargetUserID: targetUserID,
				NewPassword: password, Reason: "并发单赢家", ProofToken: token,
				RequestID: login.NewRequestID()})
		results <- outcome{password: password, err: err}
	}
	go run(resetPasswordDirectA, tokenA)
	go run(resetPasswordDirectB, tokenB)
	start.Done()
	first := <-results
	second := <-results
	close(results)
	successes, failures := 0, 0
	winnerPassword := ""
	for _, item := range []outcome{first, second} {
		if item.err == nil {
			successes++
			winnerPassword = item.password
		} else {
			failures++
			if !login.IsErrorCode(item.err, login.CodeConflict) &&
				!login.IsErrorCode(item.err, login.CodeAccessDenied) {
				t.Fatalf("并发失败方错误 = %v，期望 CONFLICT", item.err)
			}
		}
	}
	if successes != 1 || failures != 1 {
		t.Fatalf("并发结果 = %d 成功 / %d 失败，期望单赢家", successes, failures)
	}
	// 仅赢家口令可登录（受限 must_change），安全版本只递增一次，只消费一份证明。
	winnerLogin, err := resetLogin(t, runtime, resetTargetUsername(t, runtime, targetUserID),
		winnerPassword)
	if err != nil {
		t.Fatalf("赢家口令登录: %v", err)
	}
	if !winnerLogin.Restricted {
		t.Fatal("并发赢家重置后应为 must_change 受限登录")
	}
	if got := resetSecurityVersion(t, runtime, targetUserID); got != 2 {
		t.Fatalf("并发后安全版本 = %d，期望 2", got)
	}
	if consumed := resetProofConsumedCount(t, runtime); consumed != 1 {
		t.Fatalf("并发后证明消费数 = %d，期望 1", consumed)
	}
}

// TestDirectPasswordResetRateLimited 验证进程内防滥用窗口（非授权依据）。
func TestDirectPasswordResetRateLimited(t *testing.T) {
	ctx := context.Background()
	runtime, _, _, targetUserID, session, _ := proofReadyRuntime(t, ctx)
	caller := runtime.AdminSession(session)
	for attempt := 0; attempt < directPasswordResetLimit; attempt++ {
		_, err := runtime.DirectPasswordManagement().ResetUserPassword(ctx,
			AdminResetUserPasswordRequest{Caller: caller, TargetUserID: targetUserID,
				NewPassword: resetPasswordDirectA, Reason: "限流测试",
				ProofToken: strings.Repeat("a", 32), RequestID: login.NewRequestID()})
		if err == nil {
			t.Fatalf("第 %d 次尝试不应成功", attempt+1)
		}
	}
	_, err := runtime.DirectPasswordManagement().ResetUserPassword(ctx,
		AdminResetUserPasswordRequest{Caller: caller, TargetUserID: targetUserID,
			NewPassword: resetPasswordDirectA, Reason: "限流测试",
			ProofToken: strings.Repeat("a", 32), RequestID: login.NewRequestID()})
	if !login.IsErrorCode(err, login.CodeRateLimited) {
		t.Fatalf("超限错误 = %v，期望 RATE_LIMITED", err)
	}
}

// TestDirectPasswordResetErrorMapping 验证证明错误映射为稳定公开码。
func TestDirectPasswordResetErrorMapping(t *testing.T) {
	ctx := context.Background()
	runtime, _, _, targetUserID, session, _ := proofReadyRuntime(t, ctx)
	_, err := runtime.DirectPasswordManagement().ResetUserPassword(ctx,
		AdminResetUserPasswordRequest{Caller: runtime.AdminSession(session),
			TargetUserID: targetUserID, NewPassword: resetPasswordDirectA,
			Reason: "无效证明", ProofToken: strings.Repeat("b", 40),
			RequestID: login.NewRequestID()})
	if err == nil {
		t.Fatal("无效证明必须拒绝")
	}
	if !login.IsErrorCode(err, login.CodeTokenInvalid) &&
		!login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("无效证明错误码 = %v，期望 TOKEN_INVALID/REQ_INVALID", err)
	}
	var appErr *login.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("公开错误应为 *login.AppError，实际 %T", err)
	}
}
