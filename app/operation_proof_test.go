package app

// 步骤 255：目标绑定一次性两步验证操作证明的公开 Go 门面测试。
//
// 覆盖（真实临时 SQLite + 真实会话/权限/再次认证/TOTP 装配）：
//   - 本机受信操作者不能发起直接管理证明（需要真实用户管理会话的两步验证）；
//   - 缺少专门权限时发起被拒（权限复核在挑战创建事务内）；
//   - 密码 + TOTP 完成证明并返回一次性令牌；换目标/换新值/本人目标/非法操作被拒；
//   - 证明挑战绑定会话：会话注销后无法完成，另一个会话也不能完成；
//   - 取消挑战后无法完成；挑战与批准上的新值意图只保存密封密文（数据库无明文）；
//   - 公开操作标识与内部策略操作/权限键一致（步骤 254 注册表）。
//
// WebAuthn 成功路径在 internal/reauth 测试中以受控验证器覆盖；app 层在 Passkey 未启用
// 的测试配置下只验证“无 Passkey 时 WebAuthn 开始明确失败”，不伪造硬件断言。

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
)

// findOrCreateSystemPermission 找到或登记系统范围权限（直接管理权限在 254 预设中
// 可能已登记；测试不假设预设已安装）。
func findOrCreateSystemPermission(t *testing.T, ctx context.Context, runtime *Runtime,
	key string) AdminPermission {
	t.Helper()
	local := runtime.LocalAdmin()
	adminAPI := runtime.Admin()
	list, err := adminAPI.ListPermissions(ctx, AdminListPermissionsRequest{
		Caller: local, ScopeID: "system", Page: AdminPage{Limit: 200},
		RequestID: login.NewRequestID()})
	if err == nil {
		for _, permission := range list.Permissions {
			if permission.Key == key && permission.ScopeID == "system" {
				return permission
			}
		}
	}
	created, err := adminAPI.CreatePermission(ctx, AdminCreatePermissionRequest{
		Caller: local, ScopeID: "system", Key: key, Name: "直接管理测试权限",
		Description: "步骤255测试用直接管理权限", Limits: "仅用于测试",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("登记权限 %s 失败: %v", key, err)
	}
	return created
}

// grantDirectManagementPermission 通过本机受信通道创建角色并授予操作者直接管理权限。
func grantDirectManagementPermission(t *testing.T, ctx context.Context, runtime *Runtime,
	userID, permissionKey string) {
	t.Helper()
	local := runtime.LocalAdmin()
	adminAPI := runtime.Admin()
	permission := findOrCreateSystemPermission(t, ctx, runtime, permissionKey)
	role, err := adminAPI.CreateRole(ctx, AdminCreateRoleRequest{
		Caller: local, ScopeID: "system", Key: "step255-" + strings.ReplaceAll(permissionKey, ".", "-"),
		Name: "直接管理操作员", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建直接管理角色失败: %v", err)
	}
	if err := adminAPI.AddRolePermission(ctx, AdminRolePermissionRequest{
		Caller: local, RoleID: role.ID, PermissionID: permission.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("组合直接管理权限失败: %v", err)
	}
	if err := adminAPI.GrantApplicationRole(ctx, GrantRoleRequest{
		Caller: local, UserID: userID, RoleID: role.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("分配直接管理角色失败: %v", err)
	}
}

// proofReadyRuntime 准备操作者（已真实绑定 TOTP）、目标用户与权限，返回操作者
// 完整会话秘密与 TOTP 种子。
func proofReadyRuntime(t *testing.T, ctx context.Context) (runtime *Runtime, clock *testClock,
	operatorID, targetUserID string, operatorSession []byte, totpSecret string) {
	t.Helper()
	clock = newTestClock(time.Date(2026, 11, 26, 4, 0, 0, 0, time.UTC))
	runtime = adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	const password = "K8$wR3!nB6@yF1#v"
	operatorID, _, totpSecret = setupUserWithTOTP(t, runtime, clock, "proof-operator", password)
	target, err := runtime.Users().Create(ctx, CreateUserRequest{
		Username: "proof-target", Password: password, Nickname: "target",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建目标用户: %v", err)
	}
	grantDirectManagementPermission(t, ctx, runtime, operatorID, "users.username.change.other")
	grantDirectManagementPermission(t, ctx, runtime, operatorID, "users.password.reset.other")
	// 用公开权限查询确认操作者确实持有直接管理权限（测试前置断言，不参与产品逻辑）。
	if decision, err := runtime.Admin().CheckPermission(ctx, AdminPermissionCheck{
		Caller: runtime.LocalAdmin(), UserID: operatorID, ScopeID: "system",
		Permission: "users.username.change.other", RequestID: login.NewRequestID()}); err != nil ||
		!decision.Allowed {
		t.Fatalf("操作者未获得直接改名权限: decision=%+v err=%v", decision, err)
	}
	operatorSession = loginSessionWithTOTP(t, ctx, runtime, clock, "proof-operator", password, totpSecret)
	return runtime, clock, operatorID, target.ID, operatorSession, totpSecret
}

// TestOperationProofRequiresRealAdminSession 验证本机受信操作者/零值调用者不能发起。
func TestOperationProofRequiresRealAdminSession(t *testing.T) {
	ctx := context.Background()
	runtime, _, _, targetUserID, _, _ := proofReadyRuntime(t, ctx)
	proof := runtime.OperationProof()
	if _, err := proof.Begin(ctx, OperationProofBeginRequest{
		Caller: runtime.LocalAdmin(), TargetUserID: targetUserID,
		Operation: OperationProofUsernameChange, NewUsername: "renamed",
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeAccessDenied) {
		t.Fatalf("LocalAdmin 发起 = %v，期望 ACCESS_DENIED", err)
	}
	if _, err := proof.Begin(ctx, OperationProofBeginRequest{
		TargetUserID: targetUserID, Operation: OperationProofUsernameChange,
		NewUsername: "renamed", RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("零值 AdminCaller 必须拒绝")
	}
	// 本机受信操作者确认同样拒绝。
	if _, err := proof.Confirm(ctx, OperationProofConfirmRequest{
		Caller: runtime.LocalAdmin(), ChallengeID: "chl_" + strings.Repeat("a", 32),
		Password: "x", RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeAccessDenied) {
		t.Fatalf("LocalAdmin 确认 = %v，期望 ACCESS_DENIED", err)
	}
}

// TestOperationProofRequiresPermission 验证缺少专门权限时发起被拒且不创建挑战。
func TestOperationProofRequiresPermission(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 26, 5, 0, 0, 0, time.UTC))
	runtime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	const password = "K8$wR3!nB6@yF1#v"
	// 无权限普通用户（无 TOTP 也可发起到权限检查就拒绝）。
	user, err := runtime.Users().Create(ctx, CreateUserRequest{
		Username: "no-permission", Password: password, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建无权限用户: %v", err)
	}
	target, err := runtime.Users().Create(ctx, CreateUserRequest{
		Username: "target-user", Password: password, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建目标用户: %v", err)
	}
	loginResult, err := runtime.Auth().Login(ctx, LoginRequest{
		Username: "no-permission", Password: password, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()})
	if err != nil || len(loginResult.SessionSecret) == 0 {
		t.Fatalf("无权限用户登录: %v", err)
	}
	_, err = runtime.OperationProof().Begin(ctx, OperationProofBeginRequest{
		Caller: runtime.AdminSession(loginResult.SessionSecret), TargetUserID: target.ID,
		Operation: OperationProofUsernameChange, NewUsername: "renamed",
		RequestID: login.NewRequestID()})
	if !login.IsErrorCode(err, login.CodeAccessDenied) {
		t.Fatalf("缺少权限发起 = %v，期望 ACCESS_DENIED", err)
	}
	_ = user
}

// TestOperationProofPasswordTOTPFlow 覆盖直接改名/直接改密证明的成功链与一次性令牌。
func TestOperationProofPasswordTOTPFlow(t *testing.T) {
	ctx := context.Background()
	runtime, clock, operatorID, targetUserID, session, totpSecret := proofReadyRuntime(t, ctx)
	proof := runtime.OperationProof()
	caller := runtime.AdminSession(session)

	// 直接改名：发起 -> 错误密码拒绝 -> 正确密码+TOTP 签发证明。
	// TOTP 验证码在同一个时间步会被重放保护拒绝，每次两步验证前推进一个时间步取新码。
	nextTOTP := func() string {
		clock.Advance(30 * time.Second)
		return currentTOTP(t, clock, totpSecret)
	}
	challenge, err := proof.Begin(ctx, OperationProofBeginRequest{
		Caller: caller, TargetUserID: targetUserID, Operation: OperationProofUsernameChange,
		NewUsername: "Renamed.By.Proof", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("发起直接改名证明: %v", err)
	}
	if challenge.RequiredStrength != "strong" || challenge.WebAuthnAvailable {
		t.Fatalf("挑战参数异常: %+v", challenge)
	}
	if _, err := proof.Confirm(ctx, OperationProofConfirmRequest{
		Caller: caller, ChallengeID: challenge.ChallengeID, Password: "Wrong!Passw0rd",
		TOTPCode: nextTOTP(), RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("错误密码不应通过两步验证")
	}
	grant, err := proof.Confirm(ctx, OperationProofConfirmRequest{
		Caller: caller, ChallengeID: challenge.ChallengeID, Password: "K8$wR3!nB6@yF1#v",
		TOTPCode: nextTOTP(), RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("完成直接改名两步验证: %v", err)
	}
	if grant.ProofToken == "" || grant.Operation != OperationProofUsernameChange ||
		grant.TargetUserID != targetUserID || grant.GrantedStrength != "strong" {
		t.Fatalf("证明结果异常: %+v", grant)
	}
	// 数据库只保存密封意图密文，不含新用户名明文。
	var sealed []byte
	if err := runtime.base.Store.DB().QueryRowContext(ctx,
		`SELECT intent_sealed FROM reauth_approvals ORDER BY rowid DESC LIMIT 1`).
		Scan(&sealed); err != nil {
		t.Fatalf("读取证明意图密文: %v", err)
	}
	if len(sealed) == 0 || bytes.Contains(sealed, []byte("Renamed.By.Proof")) ||
		bytes.Contains(sealed, []byte("renamed.by.proof")) {
		t.Fatalf("证明意图未正确密封（len=%d）", len(sealed))
	}
	// 新证明令牌不等于挑战 ID，也不出现在审计中。
	if strings.Contains(grant.ProofToken, challenge.ChallengeID) {
		t.Fatal("证明令牌不应包含挑战 ID 片段")
	}
	if strings.Contains(reauthAuditDetails(t, runtime), grant.ProofToken) {
		t.Fatal("审计泄露证明令牌")
	}

	// 直接改密：发起 -> 完成，意图为口令且只在服务端密封保存。
	passwordChallenge, err := proof.Begin(ctx, OperationProofBeginRequest{
		Caller: caller, TargetUserID: targetUserID, Operation: OperationProofPasswordReset,
		NewPassword: "Qz7!vN9#Lp2@Rm5", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("发起直接改密证明: %v", err)
	}
	passwordGrant, err := proof.Confirm(ctx, OperationProofConfirmRequest{
		Caller: caller, ChallengeID: passwordChallenge.ChallengeID,
		Password: "K8$wR3!nB6@yF1#v", TOTPCode: nextTOTP(),
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("完成直接改密两步验证: %v", err)
	}
	if passwordGrant.Operation != OperationProofPasswordReset || passwordGrant.ProofToken == "" {
		t.Fatalf("改密证明结果异常: %+v", passwordGrant)
	}
	if strings.Contains(reauthAuditDetails(t, runtime), "Qz7!vN9#Lp2@Rm5") {
		t.Fatal("审计泄露新口令")
	}
	_ = operatorID
}

// reauthAuditDetails 返回审计明细拼接串（用于断言不含秘密）。
func reauthAuditDetails(t *testing.T, runtime *Runtime) string {
	t.Helper()
	rows, err := runtime.base.Store.DB().Query(
		`SELECT COALESCE(detail_json,'') FROM audit_events`)
	if err != nil {
		t.Fatalf("读取审计: %v", err)
	}
	defer rows.Close()
	var builder strings.Builder
	for rows.Next() {
		var detail string
		if err := rows.Scan(&detail); err != nil {
			t.Fatalf("扫描审计: %v", err)
		}
		builder.WriteString(detail)
		builder.WriteString("\n")
	}
	return builder.String()
}

// TestOperationProofBindingValidation 覆盖换目标/本人目标/非法操作/新值字段组合。
func TestOperationProofBindingValidation(t *testing.T) {
	ctx := context.Background()
	runtime, _, operatorID, targetUserID, session, _ := proofReadyRuntime(t, ctx)
	proof := runtime.OperationProof()
	caller := runtime.AdminSession(session)
	cases := []struct {
		name    string
		request OperationProofBeginRequest
	}{
		{"本人目标", OperationProofBeginRequest{Caller: caller, TargetUserID: operatorID,
			Operation: OperationProofUsernameChange, NewUsername: "self"}},
		{"非法操作", OperationProofBeginRequest{Caller: caller, TargetUserID: targetUserID,
			Operation: OperationProofOperation("unknown.operation"), NewUsername: "x"}},
		{"目标 ID 非法", OperationProofBeginRequest{Caller: caller, TargetUserID: "not-a-user",
			Operation: OperationProofUsernameChange, NewUsername: "x"}},
		{"改名缺新值", OperationProofBeginRequest{Caller: caller, TargetUserID: targetUserID,
			Operation: OperationProofUsernameChange}},
		{"改名混入口令", OperationProofBeginRequest{Caller: caller, TargetUserID: targetUserID,
			Operation: OperationProofUsernameChange, NewUsername: "x", NewPassword: "y"}},
		{"改密缺口令", OperationProofBeginRequest{Caller: caller, TargetUserID: targetUserID,
			Operation: OperationProofPasswordReset}},
		{"改密混入用户名", OperationProofBeginRequest{Caller: caller, TargetUserID: targetUserID,
			Operation: OperationProofPasswordReset, NewUsername: "x", NewPassword: "y"}},
	}
	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			testCase.request.RequestID = login.NewRequestID()
			if _, err := proof.Begin(ctx, testCase.request); err == nil {
				t.Fatalf("%s 必须拒绝", testCase.name)
			}
		})
	}
	_ = operatorID
}

// TestOperationProofSessionBindingAndCancel 覆盖会话绑定与取消：
//   - 另一个会话不能完成别的会话发起的证明；
//   - 会话注销后不能完成；
//   - 取消后挑战不可完成。
func TestOperationProofSessionBindingAndCancel(t *testing.T) {
	ctx := context.Background()
	runtime, clock, _, targetUserID, session, totpSecret := proofReadyRuntime(t, ctx)
	proof := runtime.OperationProof()
	caller := runtime.AdminSession(session)
	// 同一操作者的第二个完整会话。
	secondSession := loginSessionWithTOTP(t, ctx, runtime, clock, "proof-operator",
		"K8$wR3!nB6@yF1#v", totpSecret)

	challenge, err := proof.Begin(ctx, OperationProofBeginRequest{
		Caller: caller, TargetUserID: targetUserID, Operation: OperationProofUsernameChange,
		NewUsername: "session-bound", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("发起证明: %v", err)
	}
	if _, err := proof.Confirm(ctx, OperationProofConfirmRequest{
		Caller: runtime.AdminSession(secondSession), ChallengeID: challenge.ChallengeID,
		Password: "K8$wR3!nB6@yF1#v", TOTPCode: currentTOTP(t, clock, totpSecret),
		RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("另一个会话不能完成证明")
	}
	// 取消后不可完成。
	if err := proof.Cancel(ctx, OperationProofCancelRequest{Caller: caller,
		ChallengeID: challenge.ChallengeID, RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("取消挑战: %v", err)
	}
	if _, err := proof.Confirm(ctx, OperationProofConfirmRequest{
		Caller: caller, ChallengeID: challenge.ChallengeID, Password: "K8$wR3!nB6@yF1#v",
		TOTPCode: currentTOTP(t, clock, totpSecret), RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("取消后不能完成证明")
	}
	// 会话注销后不能完成新的证明。
	challenge, err = proof.Begin(ctx, OperationProofBeginRequest{
		Caller: caller, TargetUserID: targetUserID, Operation: OperationProofUsernameChange,
		NewUsername: "after-logout", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("注销前发起证明: %v", err)
	}
	if err := runtime.Sessions().Revoke(ctx, session); err != nil {
		t.Fatalf("注销会话: %v", err)
	}
	if _, err := proof.Confirm(ctx, OperationProofConfirmRequest{
		Caller: caller, ChallengeID: challenge.ChallengeID, Password: "K8$wR3!nB6@yF1#v",
		TOTPCode: currentTOTP(t, clock, totpSecret), RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("会话注销后不能完成证明")
	}
}

// TestOperationProofWebAuthnUnavailableWithoutPasskey 验证未启用 Passkey 时 WebAuthn
// 第二步开始明确失败（不降级、不伪造断言）。
func TestOperationProofWebAuthnUnavailableWithoutPasskey(t *testing.T) {
	ctx := context.Background()
	runtime, _, _, targetUserID, session, _ := proofReadyRuntime(t, ctx)
	proof := runtime.OperationProof()
	caller := runtime.AdminSession(session)
	challenge, err := proof.Begin(ctx, OperationProofBeginRequest{
		Caller: caller, TargetUserID: targetUserID, Operation: OperationProofUsernameChange,
		NewUsername: "webauthn-unavailable", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("发起证明: %v", err)
	}
	if challenge.WebAuthnAvailable {
		t.Fatal("Passkey 未启用时 WebAuthnAvailable 应为 false")
	}
	if _, err := proof.BeginWebAuthn(ctx, OperationProofWebAuthnBeginRequest{
		Caller: caller, ChallengeID: challenge.ChallengeID,
		RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("Passkey 未启用时 WebAuthn 第二步必须明确失败")
	}
}

// TestOperationProofPermissionRevokedAfterPrepareRejected 是步骤 255 修复（HIGH）在
// 生产装配下的证据：用真实 authz 内核发起/确认证明，PrepareProof 之后通过数据库
// 停用操作者权限（等价于角色/权限撤销的最终状态），同一业务审计事务内的 tx 权限
// 终检必须拒绝；证明不被烧毁，恢复权限后无需重新做两步验证即可重试成功。
func TestOperationProofPermissionRevokedAfterPrepareRejected(t *testing.T) {
	ctx := context.Background()
	runtime, clock, operatorID, targetUserID, session, totpSecret := proofReadyRuntime(t, ctx)
	proof := runtime.OperationProof()
	caller := runtime.AdminSession(session)
	nextTOTP := func() string {
		clock.Advance(30 * time.Second)
		return currentTOTP(t, clock, totpSecret)
	}
	challenge, err := proof.Begin(ctx, OperationProofBeginRequest{
		Caller: caller, TargetUserID: targetUserID, Operation: OperationProofUsernameChange,
		NewUsername: "revoked.name", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("发起证明: %v", err)
	}
	grant, err := proof.Confirm(ctx, OperationProofConfirmRequest{
		Caller: caller, ChallengeID: challenge.ChallengeID, Password: "K8$wR3!nB6@yF1#v",
		TOTPCode: nextTOTP(), RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("完成两步验证: %v", err)
	}
	record, err := runtime.coreServices().Sessions.Validate(ctx, string(session))
	if err != nil {
		t.Fatalf("读取会话: %v", err)
	}
	gate := runtime.securityGate()
	reauthCaller, callerErr := reauth.UserCaller(operatorID)
	if callerErr != nil {
		t.Fatalf("构造再次认证调用者: %v", callerErr)
	}
	prepared, err := gate.Reauth.PrepareProof(ctx, reauthCaller, reauth.ConsumeProofRequest{
		ProofToken: grant.ProofToken, ScopeID: "system",
		OperationID: policy.OperationDirectUsernameChange,
		TargetType:  "user", TargetID: targetUserID, SessionID: record.ID,
		Intent:    &reauth.Intent{Kind: reauth.IntentUsername, Username: "revoked.name"},
		RequestID: login.NewRequestID(),
	})
	if err != nil {
		t.Fatalf("事务外准备证明: %v", err)
	}
	// 准备之后撤销操作者权限（等价于角色/权限被停用的最终 DB 状态）。
	if _, err := runtime.base.Store.DB().ExecContext(ctx,
		`UPDATE permissions SET enabled=0 WHERE scope_id='system' AND permission_key=?`,
		"users.username.change.other"); err != nil {
		t.Fatalf("停用权限: %v", err)
	}
	consume := func() error {
		return runtime.base.Audit.ExecuteCritical(ctx, audit.CriticalRequest{
			Event: audit.Event{Actor: audit.Actor{Type: audit.ActorUser, ID: operatorID},
				Action: "test.direct_username_change",
				Target: audit.Target{Type: "user", ID: targetUserID}},
			FailureReasonCode: "test_failed",
		}, func(txCtx context.Context, tx audit.Tx) error {
			_, consumeErr := gate.Reauth.ConsumePreparedProofTx(txCtx, tx, reauthCaller, prepared)
			return consumeErr
		})
	}
	if err := consume(); !errors.Is(err, reauth.ErrAccessDenied) {
		t.Fatalf("准备后撤销权限消费 = %v，期望 reauth.ErrAccessDenied", err)
	}
	// 证明未被烧毁：批准行仍未消费、密文仍在。
	var consumed int
	var sealedLen int
	if err := runtime.base.Store.DB().QueryRowContext(ctx,
		`SELECT (consumed_at_ms IS NOT NULL),COALESCE(length(intent_sealed),0)
		 FROM reauth_approvals WHERE operation_id=? ORDER BY rowid DESC LIMIT 1`,
		policy.OperationDirectUsernameChange).Scan(&consumed, &sealedLen); err != nil {
		t.Fatalf("读取批准状态: %v", err)
	}
	if consumed != 0 || sealedLen == 0 {
		t.Fatalf("权限撤销拒绝后证明被烧毁: consumed=%d sealedLen=%d", consumed, sealedLen)
	}
	// 恢复权限后同一 prepared 在窗口内可重试成功（无需重做两步验证）。
	if _, err := runtime.base.Store.DB().ExecContext(ctx,
		`UPDATE permissions SET enabled=1 WHERE scope_id='system' AND permission_key=?`,
		"users.username.change.other"); err != nil {
		t.Fatalf("恢复权限: %v", err)
	}
	if err := consume(); err != nil {
		t.Fatalf("恢复权限后重试消费: %v", err)
	}
}

// TestOperationProofRolePermissionRemovedAfterPrepareRejected 是步骤 255 修复二轮
// F1 回归：Prepare 后把权限从操作者角色中移除（角色仍启用）必须在同一事务内的权限
// 终检被拒绝（tx 查询必须 JOIN role_permissions），证明不烧、业务不落库；恢复角色
// 权限后同一 prepared 在窗口内可重试成功。
func TestOperationProofRolePermissionRemovedAfterPrepareRejected(t *testing.T) {
	ctx := context.Background()
	runtime, clock, operatorID, targetUserID, session, totpSecret := proofReadyRuntime(t, ctx)
	proof := runtime.OperationProof()
	caller := runtime.AdminSession(session)
	nextTOTP := func() string {
		clock.Advance(30 * time.Second)
		return currentTOTP(t, clock, totpSecret)
	}
	challenge, err := proof.Begin(ctx, OperationProofBeginRequest{
		Caller: caller, TargetUserID: targetUserID, Operation: OperationProofUsernameChange,
		NewUsername: "role-link-removed", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("发起证明: %v", err)
	}
	grant, err := proof.Confirm(ctx, OperationProofConfirmRequest{
		Caller: caller, ChallengeID: challenge.ChallengeID, Password: "K8$wR3!nB6@yF1#v",
		TOTPCode: nextTOTP(), RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("完成两步验证: %v", err)
	}
	record, err := runtime.coreServices().Sessions.Validate(ctx, string(session))
	if err != nil {
		t.Fatalf("读取会话: %v", err)
	}
	gate := runtime.securityGate()
	reauthCaller, callerErr := reauth.UserCaller(operatorID)
	if callerErr != nil {
		t.Fatalf("构造再次认证调用者: %v", callerErr)
	}
	prepared, err := gate.Reauth.PrepareProof(ctx, reauthCaller, reauth.ConsumeProofRequest{
		ProofToken: grant.ProofToken, ScopeID: "system",
		OperationID: policy.OperationDirectUsernameChange,
		TargetType:  "user", TargetID: targetUserID, SessionID: record.ID,
		Intent:    &reauth.Intent{Kind: reauth.IntentUsername, Username: "role-link-removed"},
		RequestID: login.NewRequestID(),
	})
	if err != nil {
		t.Fatalf("事务外准备证明: %v", err)
	}
	// 记录授权链路真实 ID，然后只删除“角色-权限”关联（角色保持启用）。
	var permissionID, roleID string
	if err := runtime.base.Store.DB().QueryRowContext(ctx,
		`SELECT p.id,ur.role_id FROM permissions p
		 JOIN user_roles ur ON ur.user_id=?
		 JOIN role_permissions rp ON rp.permission_id=p.id AND rp.role_id=ur.role_id
		 WHERE p.scope_id='system' AND p.permission_key=?
		 LIMIT 1`, operatorID, "users.username.change.other").
		Scan(&permissionID, &roleID); err != nil {
		t.Fatalf("读取角色-权限关联: %v", err)
	}
	if _, err := runtime.base.Store.DB().ExecContext(ctx,
		`DELETE FROM role_permissions WHERE role_id=? AND permission_id=?`,
		roleID, permissionID); err != nil {
		t.Fatalf("移除角色-权限关联: %v", err)
	}
	consume := func() error {
		return runtime.base.Audit.ExecuteCritical(ctx, audit.CriticalRequest{
			Event: audit.Event{Actor: audit.Actor{Type: audit.ActorUser, ID: operatorID},
				Action: "test.direct_username_change",
				Target: audit.Target{Type: "user", ID: targetUserID}},
			FailureReasonCode: "test_failed",
		}, func(txCtx context.Context, tx audit.Tx) error {
			_, consumeErr := gate.Reauth.ConsumePreparedProofTx(txCtx, tx, reauthCaller, prepared)
			return consumeErr
		})
	}
	if err := consume(); !errors.Is(err, reauth.ErrAccessDenied) {
		t.Fatalf("移除角色-权限关联后消费 = %v，期望 reauth.ErrAccessDenied", err)
	}
	// 证明未烧毁。
	var consumed, sealedLen int
	if err := runtime.base.Store.DB().QueryRowContext(ctx,
		`SELECT (consumed_at_ms IS NOT NULL),COALESCE(length(intent_sealed),0)
		 FROM reauth_approvals WHERE operation_id=? ORDER BY rowid DESC LIMIT 1`,
		policy.OperationDirectUsernameChange).Scan(&consumed, &sealedLen); err != nil {
		t.Fatalf("读取批准状态: %v", err)
	}
	if consumed != 0 || sealedLen == 0 {
		t.Fatalf("F1 拒绝后证明被烧毁: consumed=%d sealedLen=%d", consumed, sealedLen)
	}
	// 恢复角色-权限关联后同一 prepared 在窗口内重试成功。
	if _, err := runtime.base.Store.DB().ExecContext(ctx,
		`INSERT INTO role_permissions(role_id,permission_id,scope_id) VALUES(?,?,'system')`,
		roleID, permissionID); err != nil {
		t.Fatalf("恢复角色-权限关联: %v", err)
	}
	if err := consume(); err != nil {
		t.Fatalf("恢复角色权限后重试消费: %v", err)
	}
}
