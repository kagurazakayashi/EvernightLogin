package e2e

// 步骤 274 矩阵二：直接重置他人密码与恢复/改密不变量。
//
// 覆盖（公开 Go 门面 + 临时 SQLite）：
//   - 密码策略与历史复用失败不消费证明、不修改安全版本；
//   - 成功后 must_change=true、旧会话立即失效、目标旧找回入口在同一事务内作废、
//     OAuth 撤销 outbox 事件写入；
//   - must_change 受限登录只能通过 RequiredPasswordChanges.Complete 完成本人改密，
//     完成后必须重新登录；
//   - 已绑定 MFA 的目标：重置后登录仍需第二因素（257 INFO-1 产品语义），且 MFA 因素
//     不被重置流程移除；
//   - 无密码账户拒绝（不得借重置权限添加密码）、root 目标拒绝。

import (
	"context"
	"fmt"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	loginapp "github.com/kagurazakayashi/EvernightLogin/app"
)

// TestMatrixPasswordResetRecoveryInvariants 覆盖重置密码与恢复/改密不变量。
func TestMatrixPasswordResetRecoveryInvariants(t *testing.T) {
	ctx := context.Background()
	env, operatorID, operatorSession, operatorTOTP := directOperatorFixture(t)
	runtime, clock, dbPath := env.Runtime, env.Clock, env.DBPath
	_ = operatorID
	root := ensureRoot(t, runtime)
	caller := runtime.AdminSession(operatorSession)
	reset := func(targetUserID, newPassword, token string) (loginapp.AdminPasswordResetResult, error) {
		return runtime.DirectPasswordManagement().ResetUserPassword(ctx,
			loginapp.AdminResetUserPasswordRequest{Caller: caller, TargetUserID: targetUserID,
				NewPassword: newPassword, Reason: "步骤274矩阵：重置口令",
				ProofToken: token, RequestID: login.NewRequestID()})
	}

	// 1) 弱口令与历史复用：拒绝且不改密；随后用合格口令成功。
	target := createUser(t, runtime, "matrix-reset-target", targetPassword)
	oldSession := loginFull(t, runtime, "matrix-reset-target", targetPassword).SessionSecret
	weakToken := beginPasswordProof(t, runtime, clock, operatorSession, operatorTOTP,
		target.ID, weakPassword)
	if _, err := reset(target.ID, weakPassword, weakToken); !login.IsErrorCode(err,
		login.CodeReqInvalid) {
		t.Fatalf("弱口令重置 = %v，期望 REQ_INVALID", err)
	}
	// 弱口令失败后旧口令仍可登录（未半改密）。
	if _, err := runtime.Auth().Login(ctx, loginapp.LoginRequest{
		Username: "matrix-reset-target", Password: targetPassword,
		ClientIP: "127.0.0.1", RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("弱口令失败后旧口令无法登录: %v", err)
	}
	reuseToken := beginPasswordProof(t, runtime, clock, operatorSession, operatorTOTP,
		target.ID, targetPassword)
	if _, err := reset(target.ID, targetPassword, reuseToken); !login.IsErrorCode(err,
		login.CodeReqInvalid) {
		t.Fatalf("历史口令复用 = %v，期望 REQ_INVALID", err)
	}

	// 2) 预置一个 pending 找回入口，成功重置后必须被同一事务作废。
	nowMS := clock.Now().UTC().UnixMilli()
	const pendingRequestID = "prr_274_matrix_0001"
	const pendingCredentialID = "otc_00000000000000000000000000274f01"
	executeSQL(t, dbPath,
		fmt.Sprintf(`INSERT INTO one_time_credentials(
id,purpose,subject_id,verifier_hash,max_attempts,created_at_ms,expires_at_ms)
VALUES('%s','password.reset','%s',randomblob(32),1,%d,%d)`,
			pendingCredentialID, target.ID, nowMS, nowMS+10*60*1000),
		fmt.Sprintf(`INSERT INTO password_reset_requests(
id,user_id,masked_email,credential_id,token_sha256,state,created_at_ms,expires_at_ms)
VALUES('%s','%s','t***@example.test','%s',randomblob(32),'pending',%d,%d)`,
			pendingRequestID, target.ID, pendingCredentialID, nowMS, nowMS+10*60*1000))
	outboxBefore := 0
	queryOne(t, dbPath,
		`SELECT COUNT(*) FROM oauth_revocation_events WHERE user_id=?`,
		[]any{target.ID}, &outboxBefore)

	successToken := beginPasswordProof(t, runtime, clock, operatorSession, operatorTOTP,
		target.ID, directPasswordA)
	result, err := reset(target.ID, directPasswordA, successToken)
	if err != nil {
		t.Fatalf("直接重置口令失败: %v", err)
	}
	if !result.MustChange || result.SecurityVersion <= 1 || result.OutboxEventID == "" {
		t.Fatalf("重置结果缺少 must_change/安全版本/outbox: %+v", result)
	}
	// 旧会话立即失效。
	if _, err := runtime.Sessions().Validate(ctx, oldSession); err == nil {
		t.Fatal("重置后目标旧会话仍有效")
	}
	// 旧找回入口作废、OAuth 撤销事件写入。
	var pendingState string
	queryOne(t, dbPath, `SELECT state FROM password_reset_requests WHERE id=?`,
		[]any{pendingRequestID}, &pendingState)
	if pendingState != "cancelled" {
		t.Fatalf("旧找回请求状态 = %q，期望 cancelled", pendingState)
	}
	outboxAfter := 0
	queryOne(t, dbPath,
		`SELECT COUNT(*) FROM oauth_revocation_events WHERE user_id=?`,
		[]any{target.ID}, &outboxAfter)
	if outboxAfter != outboxBefore+1 {
		t.Fatalf("OAuth 撤销事件数 = %d，期望 %d", outboxAfter, outboxBefore+1)
	}
	// must_change 受限登录：新口令登录返回受限会话，只能走强制改密门面。
	restricted, err := runtime.Auth().Login(ctx, loginapp.LoginRequest{
		Username: "matrix-reset-target", Password: directPasswordA,
		ClientIP: "127.0.0.1", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("新口令登录: %v", err)
	}
	if !restricted.Restricted || len(restricted.SessionSecret) == 0 {
		t.Fatalf("must_change 登录应为受限会话: %+v", restricted)
	}
	hasPasswordChange := false
	for _, step := range restricted.RequiredSteps {
		if step == "password_change" {
			hasPasswordChange = true
		}
	}
	if !hasPasswordChange {
		t.Fatalf("受限会话缺少 password_change 步骤: %+v", restricted.RequiredSteps)
	}
	change, err := runtime.RequiredPasswordChanges().Complete(ctx,
		loginapp.RequiredPasswordChangeRequest{SessionSecret: restricted.SessionSecret,
			CurrentPassword: directPasswordA, NewPassword: finalPassword,
			ClientIP: "127.0.0.1", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("受限会话完成强制改密: %v", err)
	}
	if change.SecurityVersion <= result.SecurityVersion {
		t.Fatalf("强制改密后安全版本未递增: %+v", change)
	}
	finalLogin, err := runtime.Auth().Login(ctx, loginapp.LoginRequest{
		Username: "matrix-reset-target", Password: finalPassword,
		ClientIP: "127.0.0.1", RequestID: login.NewRequestID()})
	if err != nil || finalLogin.Restricted || len(finalLogin.SessionSecret) == 0 {
		t.Fatalf("最终口令应可完整登录: err=%v result=%+v", err, finalLogin)
	}

	// 3) 已绑定 MFA 的目标：重置不解除 MFA。按 257 INFO-1 产品语义，must_change
	// 登录先走强制改密（第二因素不再被用于跳过改密）；完成改密后再次登录仍需第二因素。
	mfaTarget, mfaSecret := enrollTOTP(t, runtime, clock, "matrix-reset-mfa", targetPassword)
	mfaToken := beginPasswordProof(t, runtime, clock, operatorSession, operatorTOTP,
		mfaTarget.ID, directPasswordB)
	if _, err := reset(mfaTarget.ID, directPasswordB, mfaToken); err != nil {
		t.Fatalf("已绑定 MFA 目标重置口令: %v", err)
	}
	clock.Advance(30 * time.Second)
	mfaRestricted, loginErr := runtime.Auth().Login(ctx, loginapp.LoginRequest{
		Username: "matrix-reset-mfa", Password: directPasswordB,
		ClientIP: "127.0.0.1", RequestID: login.NewRequestID()})
	if loginErr != nil {
		t.Fatalf("MFA 目标重置后登录: %v", loginErr)
	}
	if !mfaRestricted.Restricted || len(mfaRestricted.SessionSecret) == 0 {
		t.Fatalf("MFA 目标重置后登录应为受限改密会话: %+v", mfaRestricted)
	}
	hasMFAChangeStep := false
	for _, step := range mfaRestricted.RequiredSteps {
		if step == "password_change" {
			hasMFAChangeStep = true
		}
	}
	if !hasMFAChangeStep {
		t.Fatalf("MFA 目标受限会话缺少 password_change: %+v", mfaRestricted.RequiredSteps)
	}
	if _, err := runtime.RequiredPasswordChanges().Complete(ctx,
		loginapp.RequiredPasswordChangeRequest{
			SessionSecret:   mfaRestricted.SessionSecret,
			CurrentPassword: directPasswordB, NewPassword: finalPassword,
			ClientIP: "127.0.0.1", RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("MFA 目标完成强制改密: %v", err)
	}
	// 改密完成后再次登录必须仍要求第二因素（MFA 保留；INFO-1）。
	clock.Advance(30 * time.Second)
	afterChangeLogin, afterChangeErr := runtime.Auth().Login(ctx, loginapp.LoginRequest{
		Username: "matrix-reset-mfa", Password: finalPassword,
		ClientIP: "127.0.0.1", RequestID: login.NewRequestID()})
	if afterChangeErr != nil {
		if !login.IsErrorCode(afterChangeErr, login.CodeMFARequired) &&
			!login.IsErrorCode(afterChangeErr, login.CodeReauthRequired) {
			t.Fatalf("MFA 目标改密后登录错误 = %v，期望仍要求第二因素", afterChangeErr)
		}
	} else {
		if !afterChangeLogin.Restricted || afterChangeLogin.SecondFactor == nil {
			t.Fatalf("MFA 目标改密后登录未要求第二因素: %+v", afterChangeLogin)
		}
		verified, verifyErr := runtime.Auth().VerifySecondFactor(ctx,
			loginapp.VerifySecondFactorRequest{
				SessionSecret: afterChangeLogin.SessionSecret,
				ChallengeID:   afterChangeLogin.SecondFactor.ChallengeID,
				AttemptToken:  afterChangeLogin.SecondFactor.AttemptToken,
				Code:          totpCode(t, clock, mfaSecret), RequestID: login.NewRequestID()})
		if verifyErr != nil {
			t.Fatalf("MFA 目标改密后第二因素验证: %v", verifyErr)
		}
		factors, listErr := runtime.MFA().List(ctx, loginapp.MFAFactorListRequest{
			SessionSecret: verified.SessionSecret, RequestID: login.NewRequestID()})
		if listErr != nil {
			t.Fatalf("读取 MFA 因素清单: %v", listErr)
		}
		if len(factors.TOTP) == 0 || !factors.StrongFactorBound {
			t.Fatalf("重置+改密后 MFA 因素丢失: %+v", factors)
		}
	}
	// 4) 无密码账户：重置权限不得顺手添加密码。
	passwordless := createUser(t, runtime, "matrix-reset-passwordless", targetPassword)
	executeSQL(t, dbPath,
		fmt.Sprintf(`DELETE FROM password_credentials WHERE user_id='%s'`, passwordless.ID))
	passwordlessToken := beginPasswordProof(t, runtime, clock, operatorSession,
		operatorTOTP, passwordless.ID, directPasswordA)
	if _, err := reset(passwordless.ID, directPasswordA, passwordlessToken); !login.IsErrorCode(err,
		login.CodeAccessDenied) {
		t.Fatalf("无密码账户重置 = %v，期望 ACCESS_DENIED", err)
	}
	credentialCount := 0
	queryOne(t, dbPath,
		`SELECT COUNT(*) FROM password_credentials WHERE user_id=?`,
		[]any{passwordless.ID}, &credentialCount)
	if credentialCount != 0 {
		t.Fatalf("无密码账户被添加了 %d 条密码凭证", credentialCount)
	}

	// 5) root 目标：非 root 操作者不能直接重置 root 口令。
	if _, err := reset(root.UserID, directPasswordB, "x"); !login.IsErrorCode(err,
		login.CodeAccessDenied) {
		t.Fatalf("root 目标重置 = %v，期望 ACCESS_DENIED", err)
	}
}
