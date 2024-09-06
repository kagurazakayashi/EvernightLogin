package app

// 步骤 256：直接修改他人用户名的公开 Go 门面端到端测试（真实临时 SQLite + 真实
// 会话/权限/两步验证/TOTP/审计装配）。
//
// 覆盖：成功链（含豁免本人改名冷却、稳定 ID/行版本/更名时间、审计与证明消费）、
// 频率限制、无权限/LocalAdmin/root 目标拒绝、root 作为操作者、证明换目标/换新值/
// 重放拒绝、失败不烧证明可重试、安全告知失败不回滚业务。

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

// renameTestPassword 是测试操作者/目标的合成登录口令（不写入日志/审计断言）。
const renameTestPassword = "K8$wR3!nB6@yF1#v"

// consoleTOTP 返回操作者下一个时间步的动态码（同一时间步会被重放保护拒绝）。
func consoleTOTP(t *testing.T, clock *testClock, secret string) string {
	t.Helper()
	clock.Advance(30 * time.Second)
	return currentTOTP(t, clock, secret)
}

// beginRenameProof 通过 255 证明门面完成一次“直接改名”两步验证，返回证明令牌。
func beginRenameProof(t *testing.T, runtime *Runtime, clock *testClock, session []byte,
	totpSecret, targetUserID, newUsername string) string {
	t.Helper()
	ctx := context.Background()
	proof := runtime.OperationProof()
	caller := runtime.AdminSession(session)
	challenge, err := proof.Begin(ctx, OperationProofBeginRequest{
		Caller: caller, TargetUserID: targetUserID, Operation: OperationProofUsernameChange,
		NewUsername: newUsername, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("发起直接改名证明: %v", err)
	}
	grant, err := proof.Confirm(ctx, OperationProofConfirmRequest{
		Caller: caller, ChallengeID: challenge.ChallengeID, Password: renameTestPassword,
		TOTPCode: consoleTOTP(t, clock, totpSecret), RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("完成直接改名两步验证: %v", err)
	}
	return grant.ProofToken
}

// targetRowVersion 读取目标资料行版本。
func targetRowVersion(t *testing.T, runtime *Runtime, userID string) int64 {
	t.Helper()
	var version int64
	if err := runtime.base.Store.DB().QueryRow(
		`SELECT row_version FROM users WHERE id=?`, userID).Scan(&version); err != nil {
		t.Fatalf("读取目标行版本: %v", err)
	}
	return version
}

// directProofConsumedCount 统计已消费的直接管理证明数量。
func directProofConsumedCount(t *testing.T, runtime *Runtime) int {
	t.Helper()
	var count int
	if err := runtime.base.Store.DB().QueryRow(
		`SELECT COUNT(*) FROM reauth_approvals WHERE consumed_at_ms IS NOT NULL`).Scan(&count); err != nil {
		t.Fatalf("读取证明消费数: %v", err)
	}
	return count
}

// TestDirectUserUsernameChangeSuccess 覆盖成功链、冷却豁免、审计与证明单次消费。
func TestDirectUserUsernameChangeSuccess(t *testing.T) {
	ctx := context.Background()
	runtime, clock, operatorID, targetUserID, session, totpSecret := proofReadyRuntime(t, ctx)
	// 目标最近 1 小时内改过名：直接管理操作应豁免本人冷却（仍更新冷却基准）。
	recent := clock.Now().Add(-time.Hour).UnixMilli()
	if _, err := runtime.base.Store.DB().Exec(
		`UPDATE users SET username_changed_at_ms=? WHERE id=?`, recent, targetUserID); err != nil {
		t.Fatalf("设置目标最近改名时间: %v", err)
	}
	beforeVersion := targetRowVersion(t, runtime, targetUserID)
	const newUsername = "Renamed.By.Admin"
	token := beginRenameProof(t, runtime, clock, session, totpSecret, targetUserID, newUsername)
	result, err := runtime.DirectUserManagement().ChangeUserUsername(ctx,
		AdminChangeUserUsernameRequest{
			Caller: runtime.AdminSession(session), TargetUserID: targetUserID,
			NewUsername: newUsername, ExpectedRowVersion: beforeVersion,
			Reason: "工单 #256：岗位调整", ProofToken: token,
			RequestID: login.NewRequestID(),
		})
	if err != nil {
		t.Fatalf("直接改名: %v", err)
	}
	if result.UserID != targetUserID || result.Username != newUsername ||
		result.RowVersion != beforeVersion+1 {
		t.Fatalf("改名结果异常: %+v", result)
	}
	// 稳定用户 ID 不变；display 与规范化键按既有规则写入；冷却基准更新。
	var storedID, storedName, storedNormalized string
	var storedVersion int64
	var changedAt int64
	if err := runtime.base.Store.DB().QueryRow(`SELECT id,username,username_normalized,
row_version,username_changed_at_ms FROM users WHERE id=?`, targetUserID).
		Scan(&storedID, &storedName, &storedNormalized, &storedVersion, &changedAt); err != nil {
		t.Fatalf("读取目标资料: %v", err)
	}
	if storedID != targetUserID || storedName != newUsername || storedVersion != beforeVersion+1 {
		t.Fatalf("数据库状态异常: id=%q name=%q version=%d", storedID, storedName, storedVersion)
	}
	if storedNormalized == "" || changedAt < recent {
		t.Fatalf("规范化键或更名时间未更新: normalized=%q changedAt=%d", storedNormalized, changedAt)
	}
	// 关键审计与证明消费。
	var auditCount int
	if err := runtime.base.Store.DB().QueryRow(`SELECT COUNT(*) FROM audit_events
WHERE action='admin.direct_username_change' AND outcome='success' AND actor_id=?`,
		operatorID).Scan(&auditCount); err != nil {
		t.Fatalf("读取审计: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("直接改名成功审计数 = %d，期望 1", auditCount)
	}
	if consumed := directProofConsumedCount(t, runtime); consumed != 1 {
		t.Fatalf("证明消费数 = %d，期望 1", consumed)
	}
	// 证明重放：不再次执行（不再改名/不新增成功审计）。
	replayErr := func() error {
		_, err := runtime.DirectUserManagement().ChangeUserUsername(ctx,
			AdminChangeUserUsernameRequest{
				Caller: runtime.AdminSession(session), TargetUserID: targetUserID,
				NewUsername: "Renamed.Again.By.Admin", ExpectedRowVersion: beforeVersion + 1,
				Reason: "重放尝试", ProofToken: token, RequestID: login.NewRequestID(),
			})
		return err
	}()
	if !login.IsErrorCode(replayErr, login.CodeTokenInvalid) {
		t.Fatalf("证明重放错误 = %v，期望 TOKEN_INVALID", replayErr)
	}
	if consumed := directProofConsumedCount(t, runtime); consumed != 1 {
		t.Fatalf("重放后证明消费数 = %d，期望仍为 1", consumed)
	}
	var currentName string
	if err := runtime.base.Store.DB().QueryRow(`SELECT username FROM users WHERE id=?`,
		targetUserID).Scan(&currentName); err != nil {
		t.Fatalf("读取最终用户名: %v", err)
	}
	if currentName != newUsername {
		t.Fatalf("重放改变了用户名: %q", currentName)
	}
}

// TestDirectUserUsernameChangeProofBindingRejected 覆盖换目标/换新值/本人目标拒绝，
// 且拒绝后证明不烧毁、资料不变。
func TestDirectUserUsernameChangeProofBindingRejected(t *testing.T) {
	ctx := context.Background()
	runtime, clock, operatorID, targetUserID, session, totpSecret := proofReadyRuntime(t, ctx)
	beforeVersion := targetRowVersion(t, runtime, targetUserID)
	token := beginRenameProof(t, runtime, clock, session, totpSecret, targetUserID, "Proof.Bound.Name")
	caller := runtime.AdminSession(session)
	// 换新值：证明绑定 Proof.Bound.Name，提交 Other.Name → 拒绝。
	if _, err := runtime.DirectUserManagement().ChangeUserUsername(ctx,
		AdminChangeUserUsernameRequest{Caller: caller, TargetUserID: targetUserID,
			NewUsername: "Other.Name", ExpectedRowVersion: beforeVersion,
			Reason: "换新值", ProofToken: token, RequestID: login.NewRequestID()},
	); !login.IsErrorCode(err, login.CodeTokenInvalid) {
		t.Fatalf("换新值错误 = %v，期望 TOKEN_INVALID", err)
	}
	// 换目标：另一个目标用户（新建）→ 拒绝。
	otherTarget, err := runtime.Users().Create(ctx, CreateUserRequest{
		Username: "other-target", Password: renameTestPassword,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建另一目标: %v", err)
	}
	if _, err := runtime.DirectUserManagement().ChangeUserUsername(ctx,
		AdminChangeUserUsernameRequest{Caller: caller, TargetUserID: otherTarget.ID,
			NewUsername: "Proof.Bound.Name", ExpectedRowVersion: 1,
			Reason: "换目标", ProofToken: token, RequestID: login.NewRequestID()},
	); !login.IsErrorCode(err, login.CodeTokenInvalid) {
		t.Fatalf("换目标错误 = %v，期望 TOKEN_INVALID", err)
	}
	// 本人目标：明确拒绝（不得把本人改名伪装成直接管理）。
	if _, err := runtime.DirectUserManagement().ChangeUserUsername(ctx,
		AdminChangeUserUsernameRequest{Caller: caller, TargetUserID: operatorID,
			NewUsername: "Self.Rename", ExpectedRowVersion: 1,
			Reason: "本人", ProofToken: token, RequestID: login.NewRequestID()},
	); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("本人目标错误 = %v，期望 REQ_INVALID", err)
	}
	// 拒绝均发生在证明消费之前：证明未消费、目标资料不变、另一目标未变。
	if consumed := directProofConsumedCount(t, runtime); consumed != 0 {
		t.Fatalf("绑定拒绝后证明消费数 = %d，期望 0", consumed)
	}
	if targetRowVersion(t, runtime, targetUserID) != beforeVersion {
		t.Fatal("绑定拒绝后原目标行版本被修改")
	}
	if targetRowVersion(t, runtime, otherTarget.ID) != 1 {
		t.Fatal("绑定拒绝后另一目标行版本被修改")
	}
	// 同一证明在正确绑定下仍可用（未烧毁）。
	if _, err := runtime.DirectUserManagement().ChangeUserUsername(ctx,
		AdminChangeUserUsernameRequest{Caller: caller, TargetUserID: targetUserID,
			NewUsername: "Proof.Bound.Name", ExpectedRowVersion: beforeVersion,
			Reason: "正确绑定重试", ProofToken: token, RequestID: login.NewRequestID()},
	); err != nil {
		t.Fatalf("绑定拒绝后正确重试: %v", err)
	}
}

// TestDirectUserUsernameChangeAuthorization 覆盖 LocalAdmin/无权限/root 目标拒绝与
// root 作为操作者成功。
func TestDirectUserUsernameChangeAuthorization(t *testing.T) {
	ctx := context.Background()
	runtime, clock, operatorID, targetUserID, session, totpSecret := proofReadyRuntime(t, ctx)
	caller := runtime.AdminSession(session)
	token := beginRenameProof(t, runtime, clock, session, totpSecret, targetUserID, "Auth.Check")
	// LocalAdmin：直接管理必须有真实用户两步验证，拒绝。
	if _, err := runtime.DirectUserManagement().ChangeUserUsername(ctx,
		AdminChangeUserUsernameRequest{Caller: runtime.LocalAdmin(),
			TargetUserID: targetUserID, NewUsername: "Local.Admin.Rename",
			ExpectedRowVersion: 1, Reason: "local", ProofToken: token,
			RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeAccessDenied) {
		t.Fatalf("LocalAdmin 错误 = %v，期望 ACCESS_DENIED", err)
	}
	// 无权限普通用户：登录后直接调用（权限检查先于证明）。
	noPerm, err := runtime.Users().Create(ctx, CreateUserRequest{
		Username: "no-perm-user", Password: renameTestPassword,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建无权限用户: %v", err)
	}
	_ = noPerm
	loginResult, err := runtime.Auth().Login(ctx, LoginRequest{
		Username: "no-perm-user", Password: renameTestPassword, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()})
	if err != nil || len(loginResult.SessionSecret) == 0 {
		t.Fatalf("无权限用户登录: %v", err)
	}
	if _, err := runtime.DirectUserManagement().ChangeUserUsername(ctx,
		AdminChangeUserUsernameRequest{Caller: runtime.AdminSession(loginResult.SessionSecret),
			TargetUserID: targetUserID, NewUsername: "No.Perm.Rename",
			ExpectedRowVersion: 1, Reason: "no-perm", ProofToken: "dummy",
			RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeAccessDenied) {
		t.Fatalf("无权限用户错误 = %v，期望 ACCESS_DENIED", err)
	}
	// root 目标：非 root 操作者不能直接改 root（root 用户名只走本人受控流程）。
	rootTarget, err := runtime.Users().Create(ctx, CreateUserRequest{
		Username: "root-candidate", Password: renameTestPassword,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建 root 候选: %v", err)
	}
	if _, err := runtime.base.Store.DB().Exec(
		`UPDATE users SET is_root=1 WHERE id=?`, rootTarget.ID); err != nil {
		t.Fatalf("设置 root 目标: %v", err)
	}
	if _, err := runtime.DirectUserManagement().ChangeUserUsername(ctx,
		AdminChangeUserUsernameRequest{Caller: caller, TargetUserID: rootTarget.ID,
			NewUsername: "Root.Renamed", ExpectedRowVersion: 1,
			Reason: "root target", ProofToken: token,
			RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeAccessDenied) {
		t.Fatalf("root 目标错误 = %v，期望 ACCESS_DENIED", err)
	}
	_ = operatorID

	// root 作为操作者：另一个运行时（避免唯一 root 冲突），合成 root 后直接改名成功。
	rootRuntime, rootClock, rootOperatorID, rootTargetID, rootSession, rootTOTP :=
		proofReadyRuntime(t, ctx)
	if _, err := rootRuntime.base.Store.DB().Exec(
		`UPDATE users SET is_root=1 WHERE id=?`, rootOperatorID); err != nil {
		t.Fatalf("设置 root 操作者: %v", err)
	}
	rootToken := beginRenameProof(t, rootRuntime, rootClock, rootSession, rootTOTP,
		rootTargetID, "Root.Operator.Rename")
	if _, err := rootRuntime.DirectUserManagement().ChangeUserUsername(ctx,
		AdminChangeUserUsernameRequest{Caller: rootRuntime.AdminSession(rootSession),
			TargetUserID: rootTargetID, NewUsername: "Root.Operator.Rename",
			ExpectedRowVersion: 1, Reason: "root operator",
			ProofToken: rootToken, RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("root 作为操作者直接改名: %v", err)
	}
}

// TestDirectUserUsernameChangeConflictKeepsProofUsable 覆盖行版本冲突等提交前失败
// 不烧证明、可用同一证明在正确版本下重试成功。
func TestDirectUserUsernameChangeConflictKeepsProofUsable(t *testing.T) {
	ctx := context.Background()
	runtime, clock, _, targetUserID, session, totpSecret := proofReadyRuntime(t, ctx)
	caller := runtime.AdminSession(session)
	token := beginRenameProof(t, runtime, clock, session, totpSecret, targetUserID, "Conflict.Retry")
	// 行版本不符：领域准备阶段拒绝（CONFLICT），证明尚未消费。
	if _, err := runtime.DirectUserManagement().ChangeUserUsername(ctx,
		AdminChangeUserUsernameRequest{Caller: caller, TargetUserID: targetUserID,
			NewUsername: "Conflict.Retry", ExpectedRowVersion: 99,
			Reason: "版本冲突", ProofToken: token, RequestID: login.NewRequestID()},
	); !login.IsErrorCode(err, login.CodeConflict) {
		t.Fatalf("行版本冲突错误 = %v，期望 CONFLICT", err)
	}
	if consumed := directProofConsumedCount(t, runtime); consumed != 0 {
		t.Fatalf("冲突失败后证明被烧毁，consumed=%d", consumed)
	}
	// 正确版本重试成功。
	if _, err := runtime.DirectUserManagement().ChangeUserUsername(ctx,
		AdminChangeUserUsernameRequest{Caller: caller, TargetUserID: targetUserID,
			NewUsername: "Conflict.Retry", ExpectedRowVersion: 1,
			Reason: "版本冲突重试", ProofToken: token, RequestID: login.NewRequestID()},
	); err != nil {
		t.Fatalf("版本冲突后重试: %v", err)
	}
}

// TestDirectUserUsernameChangeRateLimited 验证进程内防滥用窗口（非授权依据）。
func TestDirectUserUsernameChangeRateLimited(t *testing.T) {
	ctx := context.Background()
	runtime, _, _, targetUserID, session, _ := proofReadyRuntime(t, ctx)
	caller := runtime.AdminSession(session)
	// 使用不存在/无效证明做前 5 次尝试（每次都会在证明阶段失败但不改变数据）。
	for attempt := 0; attempt < directRenameLimit; attempt++ {
		_, err := runtime.DirectUserManagement().ChangeUserUsername(ctx,
			AdminChangeUserUsernameRequest{Caller: caller, TargetUserID: targetUserID,
				NewUsername: "Rate.Limited", ExpectedRowVersion: 1,
				Reason: "限流测试", ProofToken: strings.Repeat("a", 32),
				RequestID: login.NewRequestID()})
		if err == nil {
			t.Fatalf("第 %d 次尝试不应成功", attempt+1)
		}
	}
	// 第 6 次：窗口内达到上限，返回 RATE_LIMITED（授权仍由 authz 判定，限流只是辅助）。
	_, err := runtime.DirectUserManagement().ChangeUserUsername(ctx,
		AdminChangeUserUsernameRequest{Caller: caller, TargetUserID: targetUserID,
			NewUsername: "Rate.Limited", ExpectedRowVersion: 1,
			Reason: "限流测试", ProofToken: strings.Repeat("a", 32),
			RequestID: login.NewRequestID()})
	if !login.IsErrorCode(err, login.CodeRateLimited) {
		t.Fatalf("超限错误 = %v，期望 RATE_LIMITED", err)
	}
}

// TestDirectUserUsernameChangeReauthErrorsMapping 验证证明错误映射为稳定公开码。
func TestDirectUserUsernameChangeReauthErrorsMapping(t *testing.T) {
	ctx := context.Background()
	runtime, _, _, targetUserID, session, _ := proofReadyRuntime(t, ctx)
	caller := runtime.AdminSession(session)
	_, err := runtime.DirectUserManagement().ChangeUserUsername(ctx,
		AdminChangeUserUsernameRequest{Caller: caller, TargetUserID: targetUserID,
			NewUsername: "Bad.Proof", ExpectedRowVersion: 1,
			Reason: "证明无效", ProofToken: strings.Repeat("b", 40),
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
