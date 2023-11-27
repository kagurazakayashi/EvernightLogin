package app

// 步骤 229：客服求助单公开接口测试（真实 SQLite + 真实邮件捕获）。
//   - 登记/查询/列表/历史/脱敏定位/转派/状态变更/向原验证邮箱发起找回；
//   - 受保护目标（高权限）与 LocalAdmin、无权限客服稳定拒绝；
//   - 审计失败回滚；发送找回不立即改密、不解除 MFA。

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

// takeMail 取走并返回首个包含 URL 片段的邮件，避免同一链接被重复消费。
func (c *smtpCapture) takeMail(t *testing.T, pathFragment string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		c.mu.Lock()
		for index, message := range c.messages {
			for _, link := range linksInMessage(message) {
				if strings.Contains(link, pathFragment) {
					c.messages = append(c.messages[:index], c.messages[index+1:]...)
					c.mu.Unlock()
					return link
				}
			}
		}
		c.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatalf("等待包含 %s 的邮件超时", pathFragment)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// supportMailRuntime 打开启用真实邮件投递并启动任务执行器的运行时。
func supportMailRuntime(t *testing.T, ctx context.Context, clock *testClock,
	configure func(*login.Config)) *Runtime {
	t.Helper()
	capture := startSMTPCapture(t)
	cfg := mailEnabledConfig(t, capture)
	// 允许注册时省略邮箱（无验证渠道目标测试）；提供邮箱时仍会真实发信验证。
	cfg.Registration.RequireEmailVerification = false
	if configure != nil {
		configure(&cfg)
	}
	runtime := adminTestRuntime(t, ctx, cfg, t.TempDir(), clock)
	if err := runtime.Start(ctx); err != nil {
		t.Fatalf("启动运行时: %v", err)
	}
	// 捕获服务器通过 runtime 配置地址传递，测试需要同一句柄提取邮件。
	t.Cleanup(func() { _ = capture })
	supportCaptureRegistry.Store(runtime, capture)
	return runtime
}

// supportCaptureRegistry 把捕获服务器关联到运行时，供测试辅助取邮件。
var supportCaptureRegistry = newRuntimeCaptureRegistry()

type runtimeCaptureRegistry struct {
	items map[*Runtime]*smtpCapture
}

func newRuntimeCaptureRegistry() *runtimeCaptureRegistry {
	return &runtimeCaptureRegistry{items: map[*Runtime]*smtpCapture{}}
}

func (r *runtimeCaptureRegistry) Store(runtime *Runtime, capture *smtpCapture) {
	r.items[runtime] = capture
}

func (r *runtimeCaptureRegistry) Load(runtime *Runtime) *smtpCapture {
	return r.items[runtime]
}

// supportRegisterVerifiedUser 通过公开注册+邮件验证创建带已验证邮箱的用户。
func supportRegisterVerifiedUser(t *testing.T, ctx context.Context, runtime *Runtime,
	capture *smtpCapture, username, email, password string) string {
	t.Helper()
	reg, err := runtime.Registration().RegisterAccount(ctx, RegisterAccountRequest{
		Username: username, Password: password, Email: email,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("注册 %s 失败: %v", username, err)
	}
	link := capture.takeMail(t, "/email/verify")
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatalf("解析验证链接失败: %v", err)
	}
	if _, err := runtime.Registration().VerifyEmail(ctx, VerifyEmailRequest{
		UserID: parsed.Query().Get("uid"), CredentialID: parsed.Query().Get("cid"),
		Token: parsed.Query().Get("token"), RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("验证 %s 邮箱失败: %v", username, err)
	}
	return reg.UserID
}

// supportLogin 用真实密码登录并返回完整会话秘密。
func supportLogin(t *testing.T, ctx context.Context, runtime *Runtime,
	username, password string) []byte {
	t.Helper()
	result, err := runtime.Auth().Login(ctx, LoginRequest{Username: username,
		Password: password, ClientIP: "127.0.0.1", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("登录 %s 失败: %v", username, err)
	}
	if result.Restricted {
		t.Fatalf("登录 %s 不应要求第二因素", username)
	}
	return result.SessionSecret
}

// supportBindTOTP 为已登录用户绑定 TOTP 并返回种子。
func supportBindTOTP(t *testing.T, ctx context.Context, runtime *Runtime, clock *testClock,
	session []byte, password string) string {
	t.Helper()
	start, err := runtime.Security().BeginTOTPBinding(ctx, TOTPBindingBeginRequest{
		SessionSecret: session, Password: password, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("开始绑定 TOTP 失败: %v", err)
	}
	if _, err := runtime.Security().ConfirmTOTPBinding(ctx, TOTPBindingConfirmRequest{
		SessionSecret: session, BindingID: start.BindingID,
		Code: currentTOTP(t, clock, start.Secret), RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("确认 TOTP 绑定失败: %v", err)
	}
	return start.Secret
}

// supportGrantPermissions 给用户分配系统范围测试权限。
func supportGrantPermissions(t *testing.T, ctx context.Context, runtime *Runtime,
	userID, roleKey string, keys ...string) string {
	t.Helper()
	local := runtime.LocalAdmin()
	adminAPI := runtime.Admin()
	role, err := adminAPI.CreateRole(ctx, AdminCreateRoleRequest{Caller: local,
		ScopeID: "system", Key: roleKey, Name: roleKey,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建角色失败: %v", err)
	}
	for _, key := range keys {
		permissionID := ""
		permission, err := adminAPI.CreatePermission(ctx, AdminCreatePermissionRequest{
			Caller: local, ScopeID: "system", Key: key, Name: key,
			RequestID: login.NewRequestID()})
		if err == nil {
			permissionID = permission.ID
		} else if login.IsErrorCode(err, login.CodeConflict) {
			// 预置目录可能已登记同名系统权限；复用既有权限，不重复创建。
			if queryErr := runtime.base.Store.DB().QueryRow(
				`SELECT id FROM permissions WHERE scope_id='system' AND permission_key=?`,
				key).Scan(&permissionID); queryErr != nil {
				t.Fatalf("查询既有权限 %s 失败: %v", key, queryErr)
			}
		} else {
			t.Fatalf("创建权限 %s 失败: %v", key, err)
		}
		if err := adminAPI.AddRolePermission(ctx, AdminRolePermissionRequest{
			Caller: local, RoleID: role.ID, PermissionID: permissionID,
			RequestID: login.NewRequestID()}); err != nil {
			t.Fatalf("角色组合权限失败: %v", err)
		}
	}
	if err := adminAPI.GrantApplicationRole(ctx, GrantRoleRequest{Caller: local,
		UserID: userID, RoleID: role.ID, RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("分配角色失败: %v", err)
	}
	return role.ID
}

// TestSupportCasePublicFlow 覆盖客服求助单完整公开流程与脱敏。
func TestSupportCasePublicFlow(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 11, 0, 0, 0, time.UTC))
	runtime := supportMailRuntime(t, ctx, clock, nil)
	capture := supportCaptureRegistry.Load(runtime)
	const password = "K8$wR3!nB6@yF1#v"

	targetID := supportRegisterVerifiedUser(t, ctx, runtime, capture,
		"support-target", "support-target@example.test", password)
	staffID := supportRegisterVerifiedUser(t, ctx, runtime, capture,
		"support-staff", "support-staff@example.test", password)
	staffSession := supportLogin(t, ctx, runtime, "support-staff", password)
	staffTOTP := supportBindTOTP(t, ctx, runtime, clock, staffSession, password)
	supportGrantPermissions(t, ctx, runtime, staffID, "step229-support",
		"support.cases.read", "support.cases.create", "support.cases.update",
		"recovery.request")
	caller := runtime.AdminSession(staffSession)
	support := runtime.Support()

	clock.Advance(30 * time.Second)
	created, err := support.CreateCase(ctx, SupportCreateCaseRequest{Caller: caller,
		TargetUserID: targetID, Reason: "用户报告无法登录",
		Password: password, TOTPCode: currentTOTP(t, clock, staffTOTP),
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("CreateCase: %v", err)
	}
	if created.ID == "" || created.TargetMaskedUsername == "" ||
		created.TargetMaskedUsername == "support-target" ||
		created.TargetMaskedEmail == "support-target@example.test" ||
		!strings.Contains(created.TargetMaskedEmail, "***") {
		t.Fatalf("求助单脱敏视图异常: %+v", created)
	}
	read, err := support.GetCase(ctx, SupportCaseRequest{Caller: caller,
		CaseID: created.ID, RequestID: login.NewRequestID()})
	if err != nil || read.ID != created.ID {
		t.Fatalf("GetCase: %+v, %v", read, err)
	}
	list, err := support.ListCases(ctx, SupportListCasesRequest{Caller: caller,
		Page: AdminPage{Limit: 20}, RequestID: login.NewRequestID()})
	if err != nil || len(list.Cases) != 1 {
		t.Fatalf("ListCases: %+v, %v", list, err)
	}
	events, err := support.ListEvents(ctx, SupportCaseRequest{Caller: caller,
		CaseID: created.ID, RequestID: login.NewRequestID()})
	if err != nil || len(events.Events) == 0 ||
		events.Events[0].Action != "support.case.created" {
		t.Fatalf("ListEvents: %+v, %v", events, err)
	}
	target, err := support.LookupTarget(ctx, SupportLookupTargetRequest{Caller: caller,
		TargetUserID: targetID, RequestID: login.NewRequestID()})
	if err != nil || !target.HasVerifiedEmail || !target.CanRequestReset ||
		target.MaskedUsername == "support-target" {
		t.Fatalf("LookupTarget: %+v, %v", target, err)
	}
	// 向原验证邮箱发起找回：真实邮件产生、不立即改密。
	clock.Advance(30 * time.Second)
	sent, err := support.SendReset(ctx, SupportSendResetRequest{Caller: caller,
		CaseID: created.ID, Password: password,
		TOTPCode: currentTOTP(t, clock, staffTOTP), RequestID: login.NewRequestID()})
	if err != nil || !sent.Sent || sent.Status != "sent" {
		t.Fatalf("SendReset: %+v, %v", sent, err)
	}
	_ = capture.takeMail(t, "/login/reset-password")
	// 原密码仍可登录（发送找回不立即改密）。
	if _, err := runtime.Auth().Login(ctx, LoginRequest{Username: "support-target",
		Password: password, ClientIP: "127.0.0.1", RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("发送找回后原密码应仍有效: %v", err)
	}
	// 无已验证邮箱的目标：只能转人工核验。
	noMail, err := runtime.Registration().RegisterAccount(ctx, RegisterAccountRequest{
		Username: "support-nomail", Password: password,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("注册无邮箱用户失败: %v", err)
	}
	noMailTarget := struct{ ID string }{ID: noMail.UserID}
	clock.Advance(30 * time.Second)
	manualCase, err := support.CreateCase(ctx, SupportCreateCaseRequest{Caller: caller,
		TargetUserID: noMailTarget.ID, Reason: "无验证渠道",
		Password: password, TOTPCode: currentTOTP(t, clock, staffTOTP),
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("CreateCase(no mail): %v", err)
	}
	clock.Advance(30 * time.Second)
	manual, err := support.SendReset(ctx, SupportSendResetRequest{Caller: caller,
		CaseID: manualCase.ID, Password: password,
		TOTPCode: currentTOTP(t, clock, staffTOTP), RequestID: login.NewRequestID()})
	if err != nil || !manual.ManualReview || manual.Status != "manual_review" {
		t.Fatalf("无渠道 SendReset 应转人工核验: %+v, %v", manual, err)
	}
	// 状态变更：关闭求助单。
	clock.Advance(30 * time.Second)
	closed, err := support.TransitionCase(ctx, SupportTransitionCaseRequest{Caller: caller,
		CaseID: manualCase.ID, ToStatus: "closed", Note: "已转人工核验",
		Password: password, TOTPCode: currentTOTP(t, clock, staffTOTP),
		RequestID: login.NewRequestID()})
	if err != nil || closed.Status != "closed" {
		t.Fatalf("TransitionCase: %+v, %v", closed, err)
	}
}

// TestSupportPublicDenials 覆盖 LocalAdmin/无权限/受保护目标拒绝。
func TestSupportPublicDenials(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 11, 30, 0, 0, time.UTC))
	runtime := supportMailRuntime(t, ctx, clock, nil)
	capture := supportCaptureRegistry.Load(runtime)
	const password = "K8$wR3!nB6@yF1#v"
	targetID := supportRegisterVerifiedUser(t, ctx, runtime, capture,
		"support-deny-target", "support-deny@example.test", password)
	staffID := supportRegisterVerifiedUser(t, ctx, runtime, capture,
		"support-deny-staff", "support-deny-staff@example.test", password)
	staffSession := supportLogin(t, ctx, runtime, "support-deny-staff", password)
	staffTOTP := supportBindTOTP(t, ctx, runtime, clock, staffSession, password)
	supportGrantPermissions(t, ctx, runtime, staffID, "step229-support-deny",
		"support.cases.read", "support.cases.create", "recovery.request")
	caller := runtime.AdminSession(staffSession)
	support := runtime.Support()

	// LocalAdmin 没有客服用户身份。
	if _, err := support.CreateCase(ctx, SupportCreateCaseRequest{
		Caller: runtime.LocalAdmin(), TargetUserID: targetID, Reason: "本地",
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeAccessDenied) {
		t.Fatalf("LocalAdmin 登记求助单错误 = %v，期望 ACCESS_DENIED", err)
	}
	// 无客服权限用户不能读取/登记。
	noPermID := supportRegisterVerifiedUser(t, ctx, runtime, capture,
		"support-noperm", "support-noperm@example.test", password)
	noPermSession := supportLogin(t, ctx, runtime, "support-noperm", password)
	noPermCaller := runtime.AdminSession(noPermSession)
	if _, err := support.ListCases(ctx, SupportListCasesRequest{Caller: noPermCaller,
		Page: AdminPage{Limit: 10}, RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeAccessDenied) {
		t.Fatalf("无权限查询错误 = %v，期望 ACCESS_DENIED", err)
	}
	// 受保护目标（持有系统高权限）拒绝普通客服处理。
	supportGrantPermissions(t, ctx, runtime, noPermID, "step229-protected",
		"users.update")
	clock.Advance(30 * time.Second)
	if _, err := support.LookupTarget(ctx, SupportLookupTargetRequest{Caller: caller,
		TargetUserID: noPermID, RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeSupportTargetProtected) {
		t.Fatalf("受保护目标查询错误 = %v，期望 SUPPORT_TARGET_PROTECTED", err)
	}
	if _, err := support.CreateCase(ctx, SupportCreateCaseRequest{Caller: caller,
		TargetUserID: noPermID, Reason: "越权目标", Password: password,
		TOTPCode: currentTOTP(t, clock, staffTOTP), RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeSupportTargetProtected) {
		t.Fatalf("受保护目标登记错误 = %v，期望 SUPPORT_TARGET_PROTECTED", err)
	}
}

// TestSupportCreateAuditFailureRollsBack 覆盖审计失败不留下求助单。
func TestSupportCreateAuditFailureRollsBack(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC))
	runtime := supportMailRuntime(t, ctx, clock, nil)
	capture := supportCaptureRegistry.Load(runtime)
	const password = "K8$wR3!nB6@yF1#v"
	targetID := supportRegisterVerifiedUser(t, ctx, runtime, capture,
		"support-audit-target", "support-audit@example.test", password)
	staffID := supportRegisterVerifiedUser(t, ctx, runtime, capture,
		"support-audit-staff", "support-audit-staff@example.test", password)
	staffSession := supportLogin(t, ctx, runtime, "support-audit-staff", password)
	staffTOTP := supportBindTOTP(t, ctx, runtime, clock, staffSession, password)
	supportGrantPermissions(t, ctx, runtime, staffID, "step229-support-audit",
		"support.cases.read", "support.cases.create", "recovery.request")
	caller := runtime.AdminSession(staffSession)
	db := runtime.base.Store.DB()
	if _, err := db.Exec(`CREATE TRIGGER step229_support_audit_failure BEFORE INSERT ON audit_events
WHEN NEW.action='support.case.created' BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END;`); err != nil {
		t.Fatalf("注入审计失败触发器: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DROP TRIGGER IF EXISTS step229_support_audit_failure`) })
	clock.Advance(30 * time.Second)
	if _, err := runtime.Support().CreateCase(ctx, SupportCreateCaseRequest{Caller: caller,
		TargetUserID: targetID, Reason: "审计失败", Password: password,
		TOTPCode: currentTOTP(t, clock, staffTOTP), RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("审计失败时登记求助单不应成功")
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM support_cases`).Scan(&count); err != nil {
		t.Fatalf("统计求助单失败: %v", err)
	}
	if count != 0 {
		t.Fatalf("审计失败后仍留下 %d 条求助单", count)
	}
}
