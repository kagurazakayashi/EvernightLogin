package app

// 步骤 229：人工核验恢复公开接口测试（真实 SQLite + 真实邮件投递）。
//   - 申请→独立审批→等待期→一次性执行 的完整正常链（发起者/审批人/执行者三权分离）；
//   - 自批、越权、受保护目标、状态非法、重复执行、批准过期拒绝；
//   - 发起者取消与审计失败回滚。

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

// manualRecoveryRuntime 打开启用人工恢复制度的真实运行时。
func manualRecoveryRuntime(t *testing.T, ctx context.Context,
	clock *testClock) *Runtime {
	t.Helper()
	return supportMailRuntime(t, ctx, clock, func(cfg *login.Config) {
		cfg.ManualRecovery = login.ManualRecoveryConfig{Enabled: true,
			VerificationBases: []string{"in_person_identity_document"},
			DeliveryChannels:  []string{"verified_email"},
			WaitPeriodSeconds: 3600, ApprovalTTLSeconds: 7200,
			RequestTTLSeconds: 86400, RebindMethods: []string{"totp"}}
	})
}

// manualStaff 创建一名可强认证的工作人员并返回用户 ID/会话/TOTP 种子。
func manualStaff(t *testing.T, ctx context.Context, runtime *Runtime,
	clock *testClock, capture *smtpCapture, username, roleKey, password string,
	permissions ...string) (string, []byte, string, string) {
	t.Helper()
	userID := supportRegisterVerifiedUser(t, ctx, runtime, capture,
		username, username+"@example.test", password)
	session := supportLogin(t, ctx, runtime, username, password)
	totp := supportBindTOTP(t, ctx, runtime, clock, session, password)
	roleID := supportGrantPermissions(t, ctx, runtime, userID, roleKey, permissions...)
	return userID, session, totp, roleID
}

// TestManualRecoveryPublicFlow 覆盖人工恢复完整正常链与三权分离。
func TestManualRecoveryPublicFlow(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 13, 0, 0, 0, time.UTC))
	runtime := manualRecoveryRuntime(t, ctx, clock)
	capture := supportCaptureRegistry.Load(runtime)
	const password = "K8$wR3!nB6@yF1#v"
	manual := runtime.ManualRecovery()
	policy, err := manual.Policy(ctx)
	if err != nil || !policy.Enabled || policy.WaitPeriod != time.Hour {
		t.Fatalf("Policy: %+v, %v", policy, err)
	}
	targetID := supportRegisterVerifiedUser(t, ctx, runtime, capture,
		"mr-flow-target", "mr-flow-target@example.test", password)
	initiatorID, initiatorSession, initiatorTOTP, initiatorRole := manualStaff(t, ctx, runtime,
		clock, capture, "mr-flow-initiator", "step229-mr-init", password,
		"recovery.request", "recovery.approve", "recovery.execute")
	approverUserID, approverSession, approverTOTP, approverRole := manualStaff(t, ctx, runtime, clock, capture,
		"mr-flow-approver", "step229-mr-approver", password,
		"recovery.approve", "recovery.execute")
	executorUserID, executorSession, executorTOTP, executorRole := manualStaff(t, ctx, runtime, clock, capture,
		"mr-flow-executor", "step229-mr-executor", password, "recovery.execute")
	initiator := runtime.AdminSession(initiatorSession)
	approver := runtime.AdminSession(approverSession)
	executor := runtime.AdminSession(executorSession)

	// 发起申请（强认证）。
	clock.Advance(30 * time.Second)
	request, err := manual.Create(ctx, ManualRecoveryCreateRequest{Caller: initiator,
		TargetUserID: targetID, Operation: "password_reset",
		VerificationBasis:     "in_person_identity_document",
		VerificationReference: "verification-record-229", EvidenceSummary: "identity verified in person",
		Reason: "user lost access", Delivery: "verified_email",
		SupportCaseID: "sup_229_flow", Password: password,
		TOTPCode: currentTOTP(t, clock, initiatorTOTP), RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if request.ID == "" || request.Status != "pending_approval" ||
		request.InitiatorUserID != initiatorID || request.TargetUserID != targetID {
		t.Fatalf("申请视图异常: %+v", request)
	}
	detail, err := manual.GetRequest(ctx, ManualRecoveryRequestRef{Caller: initiator,
		TargetRequestID: request.ID, TraceID: login.NewRequestID()})
	if err != nil || detail.ID != request.ID {
		t.Fatalf("GetRequest: %+v, %v", detail, err)
	}
	list, err := manual.List(ctx, ManualRecoveryListRequest{Caller: initiator,
		Mode: "initiated", Page: AdminPage{Limit: 20}, RequestID: login.NewRequestID()})
	if err != nil || len(list.Items) != 1 || list.Items[0].RequestID != request.ID {
		t.Fatalf("List: %+v, %v", list, err)
	}
	// 自批拒绝（即使发起者具备审批权限）。
	clock.Advance(30 * time.Second)
	if _, err := manual.Approve(ctx, ManualRecoveryDecisionRequest{Caller: initiator,
		TargetRequestID: request.ID, Note: "self approve", Password: password,
		TOTPCode: currentTOTP(t, clock, initiatorTOTP),
		TraceID:  login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeAccessDenied) {
		t.Fatalf("自批错误 = %v，期望 ACCESS_DENIED", err)
	}
	// 独立审批人批准。
	clock.Advance(30 * time.Second)
	approval, err := manual.Approve(ctx, ManualRecoveryDecisionRequest{Caller: approver,
		TargetRequestID: request.ID, Note: "approved after review", Password: password,
		TOTPCode: currentTOTP(t, clock, approverTOTP), TraceID: login.NewRequestID()})
	if err != nil || approval.ID == "" || approval.RequestID != request.ID {
		t.Fatalf("Approve: %+v, %v", approval, err)
	}
	// 等待期未满：拒绝执行。
	clock.Advance(30 * time.Second)
	if _, err := manual.Execute(ctx, ManualRecoveryExecuteRequest{Caller: executor,
		TargetRequestID: request.ID, Password: password,
		TOTPCode: currentTOTP(t, clock, executorTOTP),
		TraceID:  login.NewRequestID()}); !login.IsErrorCode(err, login.CodeConflict) {
		t.Fatalf("等待期未满执行错误 = %v，期望 CONFLICT", err)
	}
	// 等待期结束后：会话已空闲过期。高权限账户直接重登会要求强因素登录（默认
	// Passkey）；测试通过“临时撤回角色→普通登录→恢复角色”获得真实有效会话，
	// 随后每次操作的强认证仍由公开门面真实发起密码+TOTP 挑战，不绕过授权。
	clock.Advance(time.Hour + 5*time.Minute)
	local := runtime.LocalAdmin()
	adminAPI := runtime.Admin()
	for _, item := range []struct {
		userID string
		roleID string
	}{
		{initiatorID, initiatorRole},
		{approverUserID, approverRole},
		{executorUserID, executorRole},
	} {
		if err := adminAPI.RevokeApplicationRole(ctx, RevokeRoleRequest{Caller: local,
			UserID: item.userID, RoleID: item.roleID,
			RequestID: login.NewRequestID()}); err != nil {
			t.Fatalf("临时撤回角色失败: %v", err)
		}
	}
	initiatorSession = loginSessionWithTOTP(t, ctx, runtime, clock,
		"mr-flow-initiator", password, initiatorTOTP)
	approverSession = loginSessionWithTOTP(t, ctx, runtime, clock,
		"mr-flow-approver", password, approverTOTP)
	executorSession = loginSessionWithTOTP(t, ctx, runtime, clock,
		"mr-flow-executor", password, executorTOTP)
	for _, item := range []struct {
		userID string
		roleID string
	}{
		{initiatorID, initiatorRole},
		{approverUserID, approverRole},
		{executorUserID, executorRole},
	} {
		if err := adminAPI.GrantApplicationRole(ctx, GrantRoleRequest{Caller: local,
			UserID: item.userID, RoleID: item.roleID,
			RequestID: login.NewRequestID()}); err != nil {
			t.Fatalf("恢复角色失败: %v", err)
		}
	}
	initiator = runtime.AdminSession(initiatorSession)
	approver = runtime.AdminSession(approverSession)
	executor = runtime.AdminSession(executorSession)
	clock.Advance(30 * time.Second)
	if _, err := manual.Execute(ctx, ManualRecoveryExecuteRequest{Caller: initiator,
		TargetRequestID: request.ID, Password: password,
		TOTPCode: currentTOTP(t, clock, initiatorTOTP),
		TraceID:  login.NewRequestID()}); !login.IsErrorCode(err, login.CodeAccessDenied) {
		t.Fatalf("发起者执行错误 = %v，期望 ACCESS_DENIED", err)
	}
	clock.Advance(30 * time.Second)
	if _, err := manual.Execute(ctx, ManualRecoveryExecuteRequest{Caller: approver,
		TargetRequestID: request.ID, Password: password,
		TOTPCode: currentTOTP(t, clock, approverTOTP),
		TraceID:  login.NewRequestID()}); !login.IsErrorCode(err, login.CodeAccessDenied) {
		t.Fatalf("审批人执行错误 = %v，期望 ACCESS_DENIED", err)
	}
	// 独立执行人执行成功。
	clock.Advance(30 * time.Second)
	result, err := manual.Execute(ctx, ManualRecoveryExecuteRequest{Caller: executor,
		TargetRequestID: request.ID, Password: password,
		TOTPCode: currentTOTP(t, clock, executorTOTP),
		TraceID:  login.NewRequestID()})
	if err != nil || result.RequestID != request.ID || result.Status != "completed" {
		t.Fatalf("Execute: %+v, %v", result, err)
	}
	execution, found, err := manual.GetExecution(ctx,
		ManualRecoveryRequestRef{Caller: executor, TargetRequestID: request.ID,
			TraceID: login.NewRequestID()})
	if err != nil || !found || execution.ID != result.ExecutionID {
		t.Fatalf("GetExecution: %+v, %v, found=%v", execution, err, found)
	}
	// 恢复完成后目标必须重新认证：旧密码不被直接替换为可用新会话；重置入口真实发出。
	resetLink := capture.takeMail(t, "/login/reset-password")
	if resetLink == "" {
		t.Fatal("恢复执行未发出重置入口")
	}
	if _, err := url.Parse(resetLink); err != nil {
		t.Fatalf("重置入口解析失败: %v", err)
	}
	// 重复执行：申请已终结，不得再次执行。
	clock.Advance(30 * time.Second)
	if _, err := manual.Execute(ctx, ManualRecoveryExecuteRequest{Caller: executor,
		TargetRequestID: request.ID, Password: password,
		TOTPCode: currentTOTP(t, clock, executorTOTP),
		TraceID:  login.NewRequestID()}); err == nil {
		t.Fatal("重复执行不应成功")
	}
	// 发起者取消：新建申请后取消成功；非发起者取消拒绝。
	clock.Advance(30 * time.Second)
	second, err := manual.Create(ctx, ManualRecoveryCreateRequest{Caller: initiator,
		TargetUserID: targetID, Operation: "password_reset",
		VerificationBasis:     "in_person_identity_document",
		VerificationReference: "verification-record-229b", EvidenceSummary: "identity verified in person",
		Reason: "second request", Delivery: "verified_email",
		Password: password, TOTPCode: currentTOTP(t, clock, initiatorTOTP),
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("Create(second): %v", err)
	}
	if err := manual.Cancel(ctx, ManualRecoveryCancelRequest{Caller: approver,
		TargetRequestID: second.ID, Reason: "not initiator",
		TraceID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeAccessDenied) {
		t.Fatalf("非发起者取消失败码 = %v", err)
	}
	if err := manual.Cancel(ctx, ManualRecoveryCancelRequest{Caller: initiator,
		TargetRequestID: second.ID, Reason: "changed mind",
		TraceID: login.NewRequestID()}); err != nil {
		t.Fatalf("发起者取消失败: %v", err)
	}
	// 批准过期：新建申请、批准后越过批准有效期再执行 → CHALLENGE_INVALID。
	clock.Advance(30 * time.Second)
	third, err := manual.Create(ctx, ManualRecoveryCreateRequest{Caller: initiator,
		TargetUserID: targetID, Operation: "password_reset",
		VerificationBasis:     "in_person_identity_document",
		VerificationReference: "verification-record-229c", EvidenceSummary: "identity verified in person",
		Reason: "third request", Delivery: "verified_email",
		Password: password, TOTPCode: currentTOTP(t, clock, initiatorTOTP),
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("Create(third): %v", err)
	}
	clock.Advance(30 * time.Second)
	if _, err := manual.Approve(ctx, ManualRecoveryDecisionRequest{Caller: approver,
		TargetRequestID: third.ID, Note: "approve expired case", Password: password,
		TOTPCode: currentTOTP(t, clock, approverTOTP),
		TraceID:  login.NewRequestID()}); err != nil {
		t.Fatalf("Approve(third): %v", err)
	}
	clock.Advance(3 * time.Hour)
	// 刷新执行人会话（空闲过期），再验证批准过期拒绝。
	if err := adminAPI.RevokeApplicationRole(ctx, RevokeRoleRequest{Caller: runtime.LocalAdmin(),
		UserID: executorUserID, RoleID: executorRole,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("临时撤回执行人角色失败: %v", err)
	}
	executorSession = loginSessionWithTOTP(t, ctx, runtime, clock,
		"mr-flow-executor", password, executorTOTP)
	if err := adminAPI.GrantApplicationRole(ctx, GrantRoleRequest{Caller: runtime.LocalAdmin(),
		UserID: executorUserID, RoleID: executorRole,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("恢复执行人角色失败: %v", err)
	}
	executor = runtime.AdminSession(executorSession)
	clock.Advance(30 * time.Second)
	if _, err := manual.Execute(ctx, ManualRecoveryExecuteRequest{Caller: executor,
		TargetRequestID: third.ID, Password: password,
		TOTPCode: currentTOTP(t, clock, executorTOTP),
		TraceID:  login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeChallengeInvalid) {
		t.Fatalf("批准过期执行错误 = %v，期望 CHALLENGE_INVALID", err)
	}
}

// TestManualRecoveryPublicDenials 覆盖受保护目标、无权限与审计失败回滚。
func TestManualRecoveryPublicDenials(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 14, 0, 0, 0, time.UTC))
	runtime := manualRecoveryRuntime(t, ctx, clock)
	capture := supportCaptureRegistry.Load(runtime)
	const password = "K8$wR3!nB6@yF1#v"
	manual := runtime.ManualRecovery()
	_, initiatorSession, initiatorTOTP, _ := manualStaff(t, ctx, runtime,
		clock, capture, "mr-deny-initiator", "step229-mr-deny", password,
		"recovery.request")
	initiator := runtime.AdminSession(initiatorSession)
	// LocalAdmin 不是真实工作人员用户。
	if _, err := manual.Create(ctx, ManualRecoveryCreateRequest{
		Caller: runtime.LocalAdmin(), TargetUserID: "usr_00000000000000000000000000000000",
		Operation: "password_reset", VerificationBasis: "in_person_identity_document",
		VerificationReference: "x", EvidenceSummary: "x", Reason: "x",
		Delivery: "verified_email", RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeAccessDenied) {
		t.Fatalf("LocalAdmin 发起错误 = %v，期望 ACCESS_DENIED", err)
	}
	// 无 recovery.request 权限的普通用户不能发起。
	noPermID := supportRegisterVerifiedUser(t, ctx, runtime, capture,
		"mr-deny-noperm", "mr-deny-noperm@example.test", password)
	noPermSession := supportLogin(t, ctx, runtime, "mr-deny-noperm", password)
	clock.Advance(30 * time.Second)
	if _, err := manual.Create(ctx, ManualRecoveryCreateRequest{
		Caller: runtime.AdminSession(noPermSession), TargetUserID: noPermID,
		Operation: "password_reset", VerificationBasis: "in_person_identity_document",
		VerificationReference: "x", EvidenceSummary: "x", Reason: "x",
		Delivery: "verified_email", Password: password,
		RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("无权限用户发起不应成功")
	}
	// 受保护目标（高权限）拒绝。
	protectedID := supportRegisterVerifiedUser(t, ctx, runtime, capture,
		"mr-deny-protected", "mr-deny-protected@example.test", password)
	supportGrantPermissions(t, ctx, runtime, protectedID, "step229-mr-protected",
		"users.update")
	clock.Advance(30 * time.Second)
	if _, err := manual.Create(ctx, ManualRecoveryCreateRequest{Caller: initiator,
		TargetUserID: protectedID, Operation: "password_reset",
		VerificationBasis:     "in_person_identity_document",
		VerificationReference: "x", EvidenceSummary: "x", Reason: "x",
		Delivery: "verified_email", Password: password,
		TOTPCode:  currentTOTP(t, clock, initiatorTOTP),
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeSupportTargetProtected) {
		t.Fatalf("受保护目标发起错误 = %v，期望 SUPPORT_TARGET_PROTECTED", err)
	}
	// 审计失败回滚：不留下申请。
	targetID := supportRegisterVerifiedUser(t, ctx, runtime, capture,
		"mr-deny-target", "mr-deny-target@example.test", password)
	db := runtime.base.Store.DB()
	if _, err := db.Exec(`CREATE TRIGGER step229_mr_audit_failure BEFORE INSERT ON audit_events
WHEN NEW.action='manual_recovery.requested' BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END;`); err != nil {
		t.Fatalf("注入审计失败触发器: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DROP TRIGGER IF EXISTS step229_mr_audit_failure`) })
	clock.Advance(30 * time.Second)
	if _, err := manual.Create(ctx, ManualRecoveryCreateRequest{Caller: initiator,
		TargetUserID: targetID, Operation: "password_reset",
		VerificationBasis:     "in_person_identity_document",
		VerificationReference: "x", EvidenceSummary: "x", Reason: "x",
		Delivery: "verified_email", Password: password,
		TOTPCode:  currentTOTP(t, clock, initiatorTOTP),
		RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("审计失败时发起申请不应成功")
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM manual_recovery_requests`).Scan(&count); err != nil {
		t.Fatalf("统计申请失败: %v", err)
	}
	if count != 0 {
		t.Fatalf("审计失败后仍留下 %d 条申请", count)
	}
}
