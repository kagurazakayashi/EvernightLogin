// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package serverapp

// 步骤 209 组件级集成证据：人工恢复 MFA 重置后的 TOTP 安全重绑闭环。
//
// 使用真实 OpenBase（SQLite/authn/mfa/totp/session/audit/reauth 与生产装配的
// StrongSetupMethodSource / StrongSetupBindingVerifier）、真实 manualrecovery
// 审批服务与真实 uiauthadapter 页面适配器（程序生成 TOTP，不需要扫码/手机/硬件）：
//   - 完整客服申请→独立审批（审批人≠申请人）→等待期→真实执行 MFA 重置→撤会话；
//   - 登录只得到受限强认证初始化；服务端只下发策略允许的 TOTP（Passkey 未启用）；
//   - 页面密码复核 + 真实 TOTP 验证码完成新绑定后清除重绑需求、撤销受限会话；
//   - 重新登录必须完成新的 TOTP 第二步并获得完整会话；旧受限会话/旧验证码失效；
//   - 失败路径：空/错误密码、错误验证码、枚举方法、重复提交、未绑定即完成均拒绝；
//   - 未配置可用重绑类别时 mfa_reset 申请 fail-closed 拒绝。
// 未覆盖：真实浏览器/手机验证器/硬件安全密钥（本步不需要）、真实 SMTP 外发
// （通知进入可靠队列，未实际投递）。

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/authfact"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/manualrecovery"
	manualrecoverysqlite "github.com/kagurazakayashi/EvernightLogin/internal/manualrecovery/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/mfa"
	"github.com/kagurazakayashi/EvernightLogin/internal/pagestate"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/internal/totp"
	"github.com/kagurazakayashi/EvernightLogin/internal/uiauthadapter"
)

// step209Config 构造启用人工恢复、关闭 Passkey 并显式允许 TOTP 重绑的配置。
// 邮件启用只是为了满足“人工恢复启用需要真实邮件通道”的装配约束；本测试不真实
// 外发（通知进入可靠队列），SMTP 地址是回环明文占位，启动期不建立连接。
func step209Config(t *testing.T, rebindMethods []string) login.Config {
	t.Helper()
	cfg := login.Default()
	cfg.Database.Path = filepath.Join(testutil.TempDir(t), "login.db")
	cfg.Server.PublicBaseURL = "https://login.example.test"
	cfg.Mail.Enabled = true
	cfg.Mail.SMTP.Addr = "127.0.0.1:2525"
	cfg.Mail.SMTP.TLSMode = "none"
	cfg.Mail.SMTP.AllowPlaintextLocal = true
	cfg.Mail.SMTP.TimeoutSeconds = 2
	cfg.Mail.From.Address = "noreply@example.test"
	cfg.ManualRecovery.Enabled = true
	cfg.ManualRecovery.VerificationBases = []string{"notarized_declaration"}
	cfg.ManualRecovery.DeliveryChannels = []string{"verified_email"}
	cfg.ManualRecovery.WaitPeriodSeconds = 3600
	cfg.ManualRecovery.ApprovalTTLSeconds = 7200
	cfg.ManualRecovery.RequestTTLSeconds = 36000
	cfg.ManualRecovery.RebindMethods = append([]string(nil), rebindMethods...)
	return cfg
}

// step209ManualRecoveryService 用真实领域服务与生产执行器装配人工恢复审批链；
// 工作人员权限/再认证用包内既有替身（真实链接线在 188/196 已覆盖），其余全部真实。
func step209ManualRecoveryService(t *testing.T, base *Base,
	targets manualRecoveryTargets) *manualrecovery.Service {
	t.Helper()
	manualStore, err := manualrecoverysqlite.New(base.Store)
	if err != nil {
		t.Fatalf("人工恢复存储: %v", err)
	}
	executor := manualRecoveryExecutor{
		passwordReset: base.Security.PasswordReset,
		mfa:           base.Security.MFA,
		sessions:      base.Services.Sessions,
		targets:       targets,
		// 生产装配在本配置下会得到同样的 [TOTP]（Passkey 未启用、配置仅 totp）。
		rebindMethods: []authfact.Method{authfact.MethodTOTP},
	}
	notifier := manualRecoveryNotifier{sender: base.Mail.Sender, store: base.Store,
		from: base.Mail.FromAddress(), appName: "Step209"}
	service, err := manualrecovery.New(manualrecovery.Options{
		Store: manualStore, Audit: base.Audit, Reauth: recoveryReauthStub{},
		Staff: recoveryStaffStub{}, Targets: targets, Executor: executor,
		Notifier: notifier,
		Policy: manualrecovery.Policy{Enabled: true,
			VerificationBases: []manualrecovery.VerificationBasis{manualrecovery.BasisNotarizedDeclaration},
			DeliveryChannels:  []manualrecovery.DeliveryChannel{manualrecovery.DeliveryVerifiedEmail},
			WaitPeriod:        time.Hour, ApprovalTTL: 2 * time.Hour, RequestTTL: 10 * time.Hour,
			RequireIndependentApproval: true},
		OperationGuard: func(operation manualrecovery.OperationType) error {
			if operation == manualrecovery.OperationMFAReset {
				// 与生产装配一致：本测试配置允许 TOTP 重绑，因此不额外拒绝。
			}
			return nil
		},
		Now: func() time.Time { return step209Clock },
	})
	if err != nil {
		t.Fatalf("人工恢复服务: %v", err)
	}
	return service
}

// step209Clock 是可推进的测试时钟（审批等待期/验证码时间步需要前进）。
var step209Clock = testNow

// expectPageAuthCode 断言错误是页面公开错误且错误码匹配。
func expectPageAuthCode(t *testing.T, err error, want string) {
	t.Helper()
	var publicErr *login.UIPageAuthError
	if !errors.As(err, &publicErr) || publicErr.Code != want {
		t.Fatalf("期望页面错误码 %s，实际 %v", want, err)
	}
}

// TestStep209TOTPRebindAfterManualRecovery 覆盖正向闭环与关键失败路径。
func TestStep209TOTPRebindAfterManualRecovery(t *testing.T) {
	ctx := context.Background()
	step209Clock = testNow
	base, err := OpenBase(ctx, BaseOptions{
		Config: step209Config(t, []string{"totp"}), Keyring: newTestKeyring(t), Migrate: true,
		Logger: baseTestLogger(), Now: func() time.Time { return step209Clock },
	})
	if err != nil {
		t.Fatalf("OpenBase: %v", err)
	}
	t.Cleanup(func() { _ = base.Close(context.Background()) })

	const (
		initiatorID = "usr_00000000000000000000000000000a01"
		approverID  = "usr_00000000000000000000000000000a02"
		executorID  = "usr_00000000000000000000000000000a03"
		targetID    = "usr_00000000000000000000000000000a04"
		password    = "Hx4!bW8#Tq3@Zn7"
		targetMail  = "step209-target@example.test"
	)
	nowMS := step209Clock.UnixMilli()
	insertUser := func(id, name string) {
		t.Helper()
		if _, insertErr := base.Store.DB().ExecContext(ctx, `INSERT INTO users(
id,username,username_normalized,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'active',0,1,1,?,?)`, id, name, name, nowMS, nowMS); insertErr != nil {
			t.Fatalf("插入用户 %s: %v", id, insertErr)
		}
	}
	insertUser(initiatorID, "step209-initiator")
	insertUser(approverID, "step209-approver")
	insertUser(executorID, "step209-executor")
	insertUser(targetID, "step209-target")
	if _, err := base.Store.DB().ExecContext(ctx, `INSERT INTO user_emails(
user_id,email,email_normalized,verified_at_ms,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?)`, targetID, targetMail, strings.ToLower(targetMail), nowMS, nowMS, nowMS); err != nil {
		t.Fatalf("插入已验证邮箱: %v", err)
	}
	systemCaller, err := authn.SystemCaller("step209")
	if err != nil {
		t.Fatalf("系统调用者: %v", err)
	}
	setCtx := reauth.WithSignals(ctx, reauth.Signals{VerifiedAt: step209Clock,
		Strength: policy.StrengthStrong, Complete: true, Confirmed: true})
	if _, err := base.Services.Authn.SetPassword(setCtx, systemCaller, authn.SetPasswordRequest{
		TargetUserID: targetID, NewPassword: password, RequestID: "req-209-password"}); err != nil {
		t.Fatalf("设置初始密码: %v", err)
	}
	// 模拟“用户原本有 TOTP、丢失验证器”：先真实绑定一个旧 TOTP，记录旧种子/密文；
	// 人工恢复重置后旧绑定必须失效且旧秘密不能复活。
	oldBinding, err := base.Security.TOTP.BeginBinding(
		step209ApproveMFAAdd(t, ctx, base, targetID, password, "req-209-old-bind"),
		step209TOTPCaller(t, targetID), "req-209-old-bind")
	if err != nil {
		t.Fatalf("绑定旧 TOTP: %v", err)
	}
	oldSecret, err := totp.DecodeSecret(oldBinding.Secret)
	if err != nil {
		t.Fatalf("旧 TOTP 种子: %v", err)
	}
	oldCode, _, err := totp.GenerateCode(oldSecret, step209Clock, oldBinding.PeriodSeconds, oldBinding.Digits)
	if err != nil {
		t.Fatalf("旧 TOTP 验证码: %v", err)
	}
	if _, err := base.Security.TOTP.ConfirmBinding(ctx, step209TOTPCaller(t, targetID),
		totp.BindConfirm{BindingID: oldBinding.BindingID, Code: oldCode,
			RequestID: "req-209-old-confirm"}); err != nil {
		t.Fatalf("确认旧 TOTP: %v", err)
	}
	oldSealed := step209TOTPSealedSecret(t, ctx, base, oldBinding.BindingID)

	roots, err := newHostRootChecker(base.Services.BootstrapStore)
	if err != nil {
		t.Fatalf("root 识别器: %v", err)
	}
	targets := manualRecoveryTargets{store: base.Store, keyring: base.Keyring, roots: roots}
	service := step209ManualRecoveryService(t, base, targets)

	// ===== 完整客服申请/独立审批/等待期/执行 =====
	initiator, err := manualrecovery.UserCaller(initiatorID)
	if err != nil {
		t.Fatalf("发起者: %v", err)
	}
	created, err := service.Create(ctx, initiator, manualrecovery.CreateRequest{
		TargetUserID: targetID, Operation: manualrecovery.OperationMFAReset,
		VerificationBasis:     manualrecovery.BasisNotarizedDeclaration,
		VerificationReference: "notary-209-001", EvidenceSummary: "线下核验记录摘要",
		Reason: "用户丢失验证器且无法联系到原设备", Delivery: manualrecovery.DeliveryVerifiedEmail,
		RequestID: "req-209-create"})
	if err != nil {
		t.Fatalf("创建 MFA 恢复申请: %v", err)
	}
	// 审批人等于申请人（同一身份）必须拒绝。
	if _, err := service.Approve(ctx, initiator, manualrecovery.ApproveRequest{
		RequestID: created.ID, TraceID: "req-209-self-approve"}); err == nil {
		t.Fatal("发起人不得审批自己的恢复申请")
	}
	approver, _ := manualrecovery.UserCaller(approverID)
	if _, err := service.Approve(ctx, approver, manualrecovery.ApproveRequest{
		RequestID: created.ID, Note: "独立核验通过", TraceID: "req-209-approve"}); err != nil {
		t.Fatalf("独立审批: %v", err)
	}
	executorCaller, _ := manualrecovery.UserCaller(executorID)
	// 等待期未满不得执行。
	if _, err := service.Execute(ctx, executorCaller, manualrecovery.ExecuteRequest{
		RequestID: created.ID, TraceID: "req-209-execute-early"}); err == nil {
		t.Fatal("等待期未满不得执行 MFA 恢复")
	}
	step209Clock = step209Clock.Add(time.Hour + time.Second)
	executed, err := service.Execute(ctx, executorCaller, manualrecovery.ExecuteRequest{
		RequestID: created.ID, TraceID: "req-209-execute"})
	if err != nil {
		t.Fatalf("执行 MFA 恢复: %v", err)
	}
	if executed.Status != manualrecovery.StatusCompleted || !executed.FactorsReset {
		t.Fatalf("MFA 恢复执行结果异常: %+v", executed)
	}
	// 重复执行必须拒绝（幂等/终态），不产生第二次重置。
	if _, err := service.Execute(ctx, executorCaller, manualrecovery.ExecuteRequest{
		RequestID: created.ID, TraceID: "req-209-execute-replay"}); err == nil {
		t.Fatal("重复执行 MFA 恢复应被拒绝")
	}
	// 重绑需求已登记、旧 TOTP 已停用、安全版本递增使旧会话失效。
	var pendingRebind, activeTOTP, securityVersion int
	if err := base.Store.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM mfa_rebind_requirements WHERE user_id=? AND cleared_at_ms IS NULL`,
		targetID).Scan(&pendingRebind); err != nil {
		t.Fatalf("查询重绑需求: %v", err)
	}
	if pendingRebind != 1 {
		t.Fatalf("MFA 重置后应存在未清除重绑需求: %d", pendingRebind)
	}
	if err := base.Store.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM totp_bindings WHERE user_id=? AND status='active'`,
		targetID).Scan(&activeTOTP); err != nil {
		t.Fatalf("查询 TOTP: %v", err)
	}
	if activeTOTP != 0 {
		t.Fatalf("MFA 重置后不应残留活动 TOTP: %d", activeTOTP)
	}
	if err := base.Store.DB().QueryRowContext(ctx,
		`SELECT security_version FROM users WHERE id=?`, targetID).Scan(&securityVersion); err != nil {
		t.Fatalf("查询安全版本: %v", err)
	}
	if securityVersion < 2 {
		t.Fatalf("MFA 重置应递增安全版本: %d", securityVersion)
	}

	// ===== 页面适配器：登录受限 → TOTP 重绑 =====
	pageState, err := pagestate.New(pagestate.Options{
		Keyring: base.Keyring, TTL: 15 * time.Minute, Now: func() time.Time { return step209Clock }})
	if err != nil {
		t.Fatalf("页面状态编解码器: %v", err)
	}
	adapter, err := uiauthadapter.New(uiauthadapter.Options{
		Authn: base.Services.Authn, Sessions: base.Services.Sessions,
		MFA: base.Security.MFA, TOTP: base.Security.TOTP, PageState: pageState,
		Reauth: base.Gate.Reauth, Now: func() time.Time { return step209Clock },
		Logger: baseTestLogger()})
	if err != nil {
		t.Fatalf("页面适配器: %v", err)
	}
	loginRequest := httptest.NewRequest(http.MethodPost, "/login", nil)
	loginRequest.RemoteAddr = "127.0.0.1:23456"
	loginResult, err := adapter.PasswordLogin(ctx, loginRequest, login.UIPasswordLoginRequest{
		Identifier: "step209-target", Password: password, RequestID: "req-209-login-1"})
	if err != nil {
		t.Fatalf("受限登录: %v", err)
	}
	if !loginResult.Restricted || loginResult.Complete || loginResult.SecondFactor == nil ||
		!loginResult.SecondFactor.SetupRequired || loginResult.Cookie == nil ||
		loginResult.StateCookie == nil {
		t.Fatalf("MFA 重置后登录必须只得到受限初始化会话: %+v", loginResult)
	}
	allowed := loginResult.SecondFactor.AllowedMethods
	if len(allowed) != 1 || allowed[0] != string(authfact.MethodTOTP) {
		t.Fatalf("只应下发策略允许的 TOTP 重绑类别: %v", allowed)
	}
	restrictedSecret := loginResult.Cookie.Value
	stateCookie := loginResult.StateCookie

	setupRequest := func() *http.Request {
		request := httptest.NewRequest(http.MethodGet, "/login/strong-setup", nil)
		request.AddCookie(&http.Cookie{Name: loginResult.Cookie.Name, Value: restrictedSecret})
		request.AddCookie(&http.Cookie{Name: stateCookie.Name, Value: stateCookie.Value})
		return request
	}
	// 空密码/错误密码的页面密码复核失败，不得开始 TOTP 绑定。
	if _, err := adapter.BeginStrongSetupTOTP(ctx, setupRequest(), "  "); err == nil {
		t.Fatal("空密码不得开始 TOTP 绑定")
	} else {
		expectPageAuthCode(t, err, "REAUTH_REQUIRED")
	}
	if _, err := adapter.BeginStrongSetupTOTP(ctx, setupRequest(), "Wrong!pass123"); err == nil {
		t.Fatal("错误密码不得通过页面再认证")
	} else {
		expectPageAuthCode(t, err, "AUTH_FAILED")
	}
	start, err := adapter.BeginStrongSetupTOTP(ctx, setupRequest(), password)
	if err != nil {
		t.Fatalf("开始 TOTP 重绑: %v", err)
	}
	if start.BindingID == "" || start.Secret == "" || !strings.HasPrefix(start.URI, "otpauth://totp/") ||
		start.PeriodSeconds <= 0 || start.Digits <= 0 {
		t.Fatalf("TOTP 绑定开始结果异常: %+v", start)
	}
	// 错误验证码不得激活新因素。
	finishRequest := func() *http.Request { return setupRequest() }
	if _, err := adapter.FinishStrongSetupTOTP(ctx, finishRequest(), start.BindingID, "000000", password); err == nil {
		t.Fatal("错误 TOTP 验证码不得完成绑定")
	} else {
		expectPageAuthCode(t, err, "CHALLENGE_INVALID")
	}
	secretBytes, err := totp.DecodeSecret(start.Secret)
	if err != nil {
		t.Fatalf("解码 TOTP 种子: %v", err)
	}
	// 新种子必须与旧种子不同（旧 TOTP 秘密不得在新绑定中复活）。
	if string(secretBytes) == string(oldSecret) {
		t.Fatal("重绑后的 TOTP 种子不得与旧种子相同")
	}
	// 旧绑定已停用，旧 TOTP 秘密不能用于登录验证。
	var oldStatus string
	if err := base.Store.DB().QueryRowContext(ctx,
		`SELECT status FROM totp_bindings WHERE id=?`, oldBinding.BindingID).Scan(&oldStatus); err != nil {
		t.Fatalf("查询旧 TOTP 状态: %v", err)
	}
	if oldStatus != "disabled" {
		t.Fatalf("MFA 重置后旧 TOTP 必须停用: %s", oldStatus)
	}
	oldCodeAfterReset, _, err := totp.GenerateCode(oldSecret, step209Clock,
		oldBinding.PeriodSeconds, oldBinding.Digits)
	if err != nil {
		t.Fatalf("生成旧种子验证码: %v", err)
	}
	if err := base.Security.TOTP.VerifyLoginCode(ctx, targetID, oldCodeAfterReset); err == nil {
		t.Fatal("旧 TOTP 秘密在重置后不得通过登录验证")
	}
	code, _, err := totp.GenerateCode(secretBytes, step209Clock, start.PeriodSeconds, start.Digits)
	if err != nil {
		t.Fatalf("生成 TOTP 验证码: %v", err)
	}
	completed, err := adapter.FinishStrongSetupTOTP(ctx, finishRequest(), start.BindingID, code, password)
	if err != nil {
		t.Fatalf("完成 TOTP 重绑: %v", err)
	}
	if !completed.ReloginRequired || completed.UserID != targetID || completed.SessionCookie == nil {
		t.Fatalf("TOTP 重绑完成结果异常: %+v", completed)
	}
	// 重绑需求已清除、新 TOTP 已激活、受限会话已失效。
	var cleared int
	if err := base.Store.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM mfa_rebind_requirements WHERE user_id=? AND cleared_at_ms IS NOT NULL`,
		targetID).Scan(&cleared); err != nil {
		t.Fatalf("查询重绑需求清除: %v", err)
	}
	if cleared != 1 {
		t.Fatalf("TOTP 重绑完成后应清除重绑需求: %d", cleared)
	}
	if err := base.Store.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM totp_bindings WHERE user_id=? AND status='active'`,
		targetID).Scan(&activeTOTP); err != nil {
		t.Fatalf("查询新 TOTP: %v", err)
	}
	if activeTOTP != 1 {
		t.Fatalf("TOTP 重绑应持久化恰好一个活动绑定: %d", activeTOTP)
	}
	// 新旧绑定使用不同的加密种子信封（旧秘密未被复用为“新因素”）。
	newSealed := step209TOTPSealedSecret(t, ctx, base, start.BindingID)
	if string(newSealed) == string(oldSealed) {
		t.Fatal("重绑后的 TOTP 加密种子不得与旧绑定相同")
	}
	if _, err := base.Services.Sessions.Validate(ctx, restrictedSecret); err == nil {
		t.Fatal("重绑完成后受限会话必须失效")
	}
	// 重复提交同一绑定/验证码必须拒绝，不产生第二个活动因素。
	if _, err := adapter.FinishStrongSetupTOTP(ctx, finishRequest(), start.BindingID, code, password); err == nil {
		t.Fatal("重复提交 TOTP 重绑完成应被拒绝")
	}

	// ===== 重新正常登录：必须完成新的 TOTP 第二步并获得完整会话 =====
	step209Clock = step209Clock.Add(31 * time.Second)
	loginResult2, err := adapter.PasswordLogin(ctx, httptest.NewRequest(http.MethodPost, "/login", nil),
		login.UIPasswordLoginRequest{Identifier: "step209-target", Password: password,
			RequestID: "req-209-login-2"})
	if err != nil {
		t.Fatalf("重新登录: %v", err)
	}
	if loginResult2.SecondFactor == nil || loginResult2.SecondFactor.SetupRequired ||
		!loginResult2.Restricted || loginResult2.Cookie == nil {
		t.Fatalf("重绑后登录应要求 TOTP 第二步而不是再次初始化: %+v", loginResult2)
	}
	if loginResult2.SecondFactor.FactorType != string(mfa.FactorTOTP) {
		t.Fatalf("重绑后第二因素应为 TOTP: %s", loginResult2.SecondFactor.FactorType)
	}
	code2, _, err := totp.GenerateCode(secretBytes, step209Clock, start.PeriodSeconds, start.Digits)
	if err != nil {
		t.Fatalf("生成新的 TOTP 验证码: %v", err)
	}
	verifyRequest := httptest.NewRequest(http.MethodPost, "/login/second-factor", nil)
	verifyRequest.AddCookie(&http.Cookie{Name: loginResult2.Cookie.Name, Value: loginResult2.Cookie.Value})
	if loginResult2.StateCookie != nil {
		verifyRequest.AddCookie(&http.Cookie{Name: loginResult2.StateCookie.Name,
			Value: loginResult2.StateCookie.Value})
	}
	verified, err := adapter.VerifySecondFactor(ctx, verifyRequest, login.UIPageSecondFactorVerify{
		ChallengeID:  loginResult2.SecondFactor.ChallengeID,
		AttemptToken: loginResult2.SecondFactor.AttemptToken,
		Code:         code2, RequestID: "req-209-login-2-verify"})
	if err != nil {
		t.Fatalf("TOTP 第二步: %v", err)
	}
	if verified.SessionCookie == nil {
		t.Fatal("TOTP 第二步成功应签发完整会话 Cookie")
	}
	record, err := base.Services.Sessions.Validate(ctx, verified.SessionCookie.Value)
	if err != nil || record.IsRestricted() {
		t.Fatalf("重新登录应得到完整非受限会话: %+v err=%v", record, err)
	}
	// 重放同一 TOTP 第二步挑战必须拒绝（不重复签发完整会话）。
	replayRequest := httptest.NewRequest(http.MethodPost, "/login/second-factor", nil)
	replayRequest.AddCookie(&http.Cookie{Name: loginResult2.Cookie.Name,
		Value: loginResult2.Cookie.Value})
	if loginResult2.StateCookie != nil {
		replayRequest.AddCookie(&http.Cookie{Name: loginResult2.StateCookie.Name,
			Value: loginResult2.StateCookie.Value})
	}
	if _, err := adapter.VerifySecondFactor(ctx, replayRequest, login.UIPageSecondFactorVerify{
		ChallengeID:  loginResult2.SecondFactor.ChallengeID,
		AttemptToken: loginResult2.SecondFactor.AttemptToken,
		Code:         code2, RequestID: "req-209-login-2-replay"}); err == nil {
		t.Fatal("重放 TOTP 第二步必须被拒绝")
	} else {
		expectPageAuthCode(t, err, "CHALLENGE_INVALID")
	}

	// ===== 未绑定即完成（会话已失效场景）必须拒绝 =====
	if _, err := adapter.FinishStrongSetupTOTP(ctx, setupRequest(), start.BindingID, code, password); err == nil {
		t.Fatal("失效受限会话不得完成初始化")
	}
}

// step209ApproveMFAAdd 通过真实 reauth 完成页面密码复核对应的 mfa.add 近期认证，
// 返回带一次性批准信号的上下文；与生产页面适配器的证据路径一致。
func step209ApproveMFAAdd(t *testing.T, ctx context.Context, base *Base,
	userID, password, requestID string) context.Context {
	t.Helper()
	caller, err := reauth.UserCaller(userID)
	if err != nil {
		t.Fatalf("reauth 调用者: %v", err)
	}
	challenge, err := base.Gate.Reauth.BeginChallenge(ctx, caller, reauth.ChallengeRequest{
		ScopeID: "system", OperationID: "mfa.add", TargetType: "user", TargetID: userID,
		Params: map[string]string{"factor": "totp"}, Description: "绑定 TOTP 验证器",
		RequestID: requestID})
	if err != nil {
		t.Fatalf("mfa.add 再次认证挑战: %v", err)
	}
	if !challenge.Required {
		return ctx
	}
	grant, err := base.Gate.Reauth.VerifyChallenge(ctx, caller, reauth.VerifyChallengeRequest{
		ChallengeID: challenge.ID, Password: password, RequestID: requestID})
	if err != nil {
		t.Fatalf("mfa.add 再次认证: %v", err)
	}
	return reauth.WithSignals(ctx, reauth.Signals{VerifiedAt: step209Clock,
		Strength: policy.StrengthPassword, Complete: true, Confirmed: true,
		ApprovalToken: grant.Token})
}

// step209TOTPCaller 构造 TOTP 领域用户调用者。
func step209TOTPCaller(t *testing.T, userID string) totp.Caller {
	t.Helper()
	caller, err := totp.UserCaller(userID)
	if err != nil {
		t.Fatalf("TOTP 调用者: %v", err)
	}
	return caller
}

// step209TOTPSealedSecret 读取指定绑定的加密信封（只比较密文是否不同，不解密）。
func step209TOTPSealedSecret(t *testing.T, ctx context.Context, base *Base,
	bindingID string) []byte {
	t.Helper()
	var sealed []byte
	if err := base.Store.DB().QueryRowContext(ctx,
		`SELECT sealed_secret FROM totp_bindings WHERE id=?`, bindingID).Scan(&sealed); err != nil {
		t.Fatalf("读取 TOTP 加密信封: %v", err)
	}
	return sealed
}

// TestStep209MFAResetFailClosedWithoutRebindMethod 验证配置列出的重绑类别全部
// 不可用（只列 passkey 但 Passkey 未启用）时，mfa_reset 申请被 OperationGuard
// fail-closed 拒绝，避免恢复后锁死的“看似可用”入口。
func TestStep209MFAResetFailClosedWithoutRebindMethod(t *testing.T) {
	ctx := context.Background()
	step209Clock = testNow
	base, err := OpenBase(ctx, BaseOptions{
		Config: step209Config(t, []string{"passkey"}), Keyring: newTestKeyring(t), Migrate: true,
		Logger: baseTestLogger(), Now: func() time.Time { return step209Clock },
	})
	if err != nil {
		t.Fatalf("OpenBase: %v", err)
	}
	t.Cleanup(func() { _ = base.Close(context.Background()) })
	const (
		initiatorID = "usr_00000000000000000000000000000b01"
		targetID    = "usr_00000000000000000000000000000b02"
	)
	nowMS := step209Clock.UnixMilli()
	for _, user := range []struct{ id, name string }{
		{initiatorID, "step209b-initiator"}, {targetID, "step209b-target"}} {
		if _, err := base.Store.DB().ExecContext(ctx, `INSERT INTO users(
id,username,username_normalized,status,is_root,security_version,row_version,created_at_ms,updated_at_ms)
VALUES(?,?,?,'active',0,1,1,?,?)`, user.id, user.name, user.name, nowMS, nowMS); err != nil {
			t.Fatalf("插入用户: %v", err)
		}
	}
	if _, err := base.Store.DB().ExecContext(ctx, `INSERT INTO user_emails(
user_id,email,email_normalized,verified_at_ms,created_at_ms,updated_at_ms)
VALUES(?,?,?,?,?,?)`, targetID, "step209b@example.test", "step209b@example.test",
		nowMS, nowMS, nowMS); err != nil {
		t.Fatalf("插入邮箱: %v", err)
	}
	roots, err := newHostRootChecker(base.Services.BootstrapStore)
	if err != nil {
		t.Fatalf("root 识别器: %v", err)
	}
	targets := manualRecoveryTargets{store: base.Store, keyring: base.Keyring, roots: roots}
	// 用与生产一致的 OperationGuard 语义：没有可用重绑类别时拒绝 mfa_reset。
	rebindMethods, err := manualRecoveryRebindMethods(base.Config.ManualRecovery, false)
	if err != nil {
		t.Fatalf("解析重绑方法: %v", err)
	}
	if len(rebindMethods) != 0 {
		t.Fatalf("Passkey 未启用时 passkey 类别应不可用: %v", rebindMethods)
	}
	manualStore, err := manualrecoverysqlite.New(base.Store)
	if err != nil {
		t.Fatalf("人工恢复存储: %v", err)
	}
	service, err := manualrecovery.New(manualrecovery.Options{
		Store: manualStore, Audit: base.Audit, Reauth: recoveryReauthStub{},
		Staff: recoveryStaffStub{}, Targets: targets,
		Executor: manualRecoveryExecutor{passwordReset: base.Security.PasswordReset,
			mfa: base.Security.MFA, sessions: base.Services.Sessions, targets: targets,
			rebindMethods: rebindMethods},
		Notifier: manualRecoveryNotifier{sender: base.Mail.Sender, store: base.Store,
			from: base.Mail.FromAddress(), appName: "Step209"},
		Policy: manualrecovery.Policy{Enabled: true,
			VerificationBases: []manualrecovery.VerificationBasis{manualrecovery.BasisNotarizedDeclaration},
			DeliveryChannels:  []manualrecovery.DeliveryChannel{manualrecovery.DeliveryVerifiedEmail},
			WaitPeriod:        time.Hour, ApprovalTTL: 2 * time.Hour, RequestTTL: 10 * time.Hour,
			RequireIndependentApproval: true},
		OperationGuard: func(operation manualrecovery.OperationType) error {
			if operation == manualrecovery.OperationMFAReset && len(rebindMethods) == 0 {
				return errors.New("没有可用的强因素重绑方法")
			}
			return nil
		},
		Now: func() time.Time { return step209Clock },
	})
	if err != nil {
		t.Fatalf("人工恢复服务: %v", err)
	}
	initiator, _ := manualrecovery.UserCaller(initiatorID)
	_, err = service.Create(ctx, initiator, manualrecovery.CreateRequest{
		TargetUserID: targetID, Operation: manualrecovery.OperationMFAReset,
		VerificationBasis:     manualrecovery.BasisNotarizedDeclaration,
		VerificationReference: "notary-209b-001", EvidenceSummary: "核验摘要",
		Reason: "用户丢失验证器", Delivery: manualrecovery.DeliveryVerifiedEmail,
		RequestID: "req-209b-create"})
	if err == nil || !errors.Is(err, manualrecovery.ErrAccessDenied) {
		t.Fatalf("无可用重绑类别时 mfa_reset 申请应 fail-closed: %v", err)
	}
	// 普通密码恢复不受该限制。
	if _, err := service.Create(ctx, initiator, manualrecovery.CreateRequest{
		TargetUserID: targetID, Operation: manualrecovery.OperationPasswordReset,
		VerificationBasis:     manualrecovery.BasisNotarizedDeclaration,
		VerificationReference: "notary-209b-002", EvidenceSummary: "核验摘要",
		Reason: "用户丢失密码", Delivery: manualrecovery.DeliveryVerifiedEmail,
		RequestID: "req-209b-create-password"}); err != nil {
		t.Fatalf("密码恢复不应受重绑类别限制: %v", err)
	}
}
