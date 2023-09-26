package app

// 步骤 208 会话联合授权入口测试（直接 Go 调用）：
//   - 会话有效 ≠ 属于当前应用 ≠ 具备当前操作权限：Authorize 同时检查应用绑定与
//     权限内核，跨应用/无权限/受限会话都被拒绝，CSRF 通过不提升权限；
//   - 请求编号贯穿：拒绝决策与错误都带同一编号；
//   - 与 HTTP 边界的差异由 http_source_trust_test.go 的反向代理/宿主服务器验证。

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

// step208Evidence 是会话授权测试所需的真实装配：两个应用、应用 A 的一个权限与
// 角色、以及一个已被授予该角色的成员用户。
type step208Evidence struct {
	runtime    *Runtime
	appA       AdminApplication
	appB       AdminApplication
	member     User
	permission AdminPermission
	role       AdminRole
}

// setupStep208Evidence 通过公开管理门面（LocalAdmin 受信宿主通道）建立真实权限链。
func setupStep208Evidence(t *testing.T, ctx context.Context, clock *testClock,
	dir string, cfg login.Config) *step208Evidence {
	t.Helper()
	runtime := adminTestRuntime(t, ctx, cfg, dir, clock)
	adminAPI := runtime.Admin()
	local := runtime.LocalAdmin()
	member := step207CreateProblemUser(t, ctx, runtime, "member208")

	createApplication := func(name string) AdminApplication {
		t.Helper()
		created, err := adminAPI.CreateApplication(ctx, AdminCreateApplicationRequest{
			Caller: local, Name: name, RequestID: login.NewRequestID()})
		if err != nil {
			t.Fatalf("创建应用 %s 失败: %v", name, err)
		}
		enabled, err := adminAPI.SetApplicationEnabled(ctx, AdminSetApplicationEnabledRequest{
			Caller: local, ApplicationID: created.ID, Enabled: true,
			ExpectedRowVersion: created.RowVersion, RequestID: login.NewRequestID()})
		if err != nil {
			t.Fatalf("启用应用 %s 失败: %v", name, err)
		}
		return enabled
	}
	appA := createApplication("应用 A")
	appB := createApplication("应用 B")
	permission, err := adminAPI.CreatePermission(ctx, AdminCreatePermissionRequest{
		Caller: local, ScopeID: appA.ID, Key: "invoice.read", Name: "读取发票",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建应用 A 权限失败: %v", err)
	}
	role, err := adminAPI.CreateRole(ctx, AdminCreateRoleRequest{
		Caller: local, ScopeID: appA.ID, Key: "invoice-reader", Name: "发票读取员",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建应用 A 角色失败: %v", err)
	}
	if err := adminAPI.AddRolePermission(ctx, AdminRolePermissionRequest{
		Caller: local, RoleID: role.ID, PermissionID: permission.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("角色添加权限失败: %v", err)
	}
	if err := adminAPI.AddApplicationMember(ctx, AdminAddMemberRequest{
		Caller: local, ApplicationID: appA.ID, UserID: member.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("加入应用成员失败: %v", err)
	}
	if err := adminAPI.GrantApplicationRole(ctx, GrantRoleRequest{
		Caller: local, UserID: member.ID, RoleID: role.ID,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("分配应用角色失败: %v", err)
	}
	return &step208Evidence{runtime: runtime, appA: appA, appB: appB,
		member: member, permission: permission, role: role}
}

// step208Login 用真实密码登录并返回会话结果。
func step208Login(t *testing.T, ctx context.Context, runtime *Runtime,
	username, password, appID string) LoginResult {
	t.Helper()
	result, err := runtime.Auth().Login(ctx, LoginRequest{
		Username: username, Password: password, ClientIP: "127.0.0.1", AppID: appID,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("登录 %s（app=%q）失败: %v", username, appID, err)
	}
	if result.Restricted {
		t.Fatalf("用户 %s 登录不应要求第二因素", username)
	}
	return result
}

// TestSessionAuthorizeBindsApplicationAndPermission 覆盖会话有效、应用绑定与权限
// 三个层次的联合判定（成功与全部拒绝路径）。
func TestSessionAuthorizeBindsApplicationAndPermission(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 5, 30, 0, 0, time.UTC))
	evidence := setupStep208Evidence(t, ctx, clock, t.TempDir(), testConfig())
	runtime := evidence.runtime
	sessions := runtime.Sessions()
	const password = "K8$wR3!nB6@yF1#v"

	globalLogin := step208Login(t, ctx, runtime, "member208", password, "")
	if len(globalLogin.SessionSecret) == 0 {
		t.Fatal("登录未返回会话秘密")
	}

	// 全局会话 + 应用 A + 已授予权限：允许，并返回一致的会话/应用/编号。
	const allowedRequestID = "req_208_session_allowed"
	allowed, err := sessions.Authorize(ctx, SessionAccessRequest{
		SessionSecret: globalLogin.SessionSecret, AppID: evidence.appA.ID,
		Permissions: []string{"invoice.read"}, RequestID: allowedRequestID})
	if err != nil {
		t.Fatalf("联合授权应成功: %v", err)
	}
	if !allowed.Allowed || allowed.Code != "" || allowed.Reason != "" {
		t.Fatalf("联合授权决策异常: %+v", allowed)
	}
	if allowed.UserID != evidence.member.ID || allowed.AppID != evidence.appA.ID ||
		allowed.SessionID != globalLogin.SessionID {
		t.Fatalf("联合授权回显异常: %+v", allowed)
	}
	if allowed.RequestID != allowedRequestID {
		t.Fatalf("联合授权请求编号 = %q，期望 %q", allowed.RequestID, allowedRequestID)
	}

	// 跨应用：同一权限键在应用 B 未登记 → 拒绝（不泄露内部原因），且不返回 error。
	const crossAppRequestID = "req_208_session_cross_app"
	crossApp, err := sessions.Authorize(ctx, SessionAccessRequest{
		SessionSecret: globalLogin.SessionSecret, AppID: evidence.appB.ID,
		Permissions: []string{"invoice.read"}, RequestID: crossAppRequestID})
	if err != nil {
		t.Fatalf("跨应用判定不应返回内部错误: %v", err)
	}
	if crossApp.Allowed {
		t.Fatalf("跨应用不应被允许: %+v", crossApp)
	}
	if crossApp.Code == "" || crossApp.RequestID != crossAppRequestID {
		t.Fatalf("跨应用拒绝缺少稳定码/编号: %+v", crossApp)
	}

	// 缺少应用范围 / 缺少权限 / 空会话秘密都是输入错误（REQ_INVALID/AUTH_FAILED），
	// 不是“允许”。
	for name, request := range map[string]SessionAccessRequest{
		"缺少应用": {SessionSecret: globalLogin.SessionSecret,
			Permissions: []string{"invoice.read"}, RequestID: "req_208_no_app"},
		"缺少权限": {SessionSecret: globalLogin.SessionSecret,
			AppID: evidence.appA.ID, RequestID: "req_208_no_perm"},
		"非法编号": {SessionSecret: globalLogin.SessionSecret,
			AppID: evidence.appA.ID, Permissions: []string{"invoice.read"},
			RequestID: "req 208\ninject"},
	} {
		if _, err := sessions.Authorize(ctx, request); err == nil {
			t.Fatalf("%s 应返回错误", name)
		}
	}
	if _, err := sessions.Authorize(ctx, SessionAccessRequest{
		SessionSecret: globalLogin.SessionSecret, AppID: evidence.appA.ID,
		Permissions: []string{"invoice.read"}, RequestID: "req_208_bad_id\n"}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("非法请求编号应返回 REQ_INVALID，实际 %v", err)
	}
	if _, err := sessions.Authorize(ctx, SessionAccessRequest{
		AppID: evidence.appA.ID, Permissions: []string{"invoice.read"},
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeAuthFailed) {
		t.Fatalf("缺少会话秘密应返回 AUTH_FAILED，实际 %v", err)
	}
	if _, err := sessions.Authorize(ctx, SessionAccessRequest{
		SessionSecret: []byte("invalid-session-secret"), AppID: evidence.appA.ID,
		Permissions: []string{"invoice.read"},
		RequestID:   "req_208_invalid_session"}); !login.IsErrorCode(err, login.CodeAuthFailed) {
		t.Fatalf("无效会话应返回 AUTH_FAILED，实际 %v", err)
	} else if appError := step207AppError(t, err); appError.RequestID() != "req_208_invalid_session" {
		t.Fatalf("无效会话错误请求编号 = %q", appError.RequestID())
	}

	// 应用绑定：会话登录时绑定应用 A 后，访问应用 B 即使有权限也被拒绝。
	appBoundLogin := step208Login(t, ctx, runtime, "member208", password, evidence.appA.ID)
	boundA, err := sessions.Authorize(ctx, SessionAccessRequest{
		SessionSecret: appBoundLogin.SessionSecret, AppID: evidence.appA.ID,
		Permissions: []string{"invoice.read"},
		RequestID:   "req_208_bound_a"})
	if err != nil || !boundA.Allowed {
		t.Fatalf("绑定应用 A 的会话访问应用 A 应允许: %+v err=%v", boundA, err)
	}
	boundB, err := sessions.Authorize(ctx, SessionAccessRequest{
		SessionSecret: appBoundLogin.SessionSecret, AppID: evidence.appB.ID,
		Permissions: []string{"invoice.read"},
		RequestID:   "req_208_bound_b"})
	if err != nil {
		t.Fatalf("绑定跨应用判定不应返回内部错误: %v", err)
	}
	if boundB.Allowed || boundB.Code != string(login.CodeAppScopeMismatch) ||
		boundB.Reason != "session_app_mismatch" {
		t.Fatalf("绑定应用 A 的会话访问应用 B 应返回 APP_SCOPE_MISMATCH: %+v", boundB)
	}

	// 撤销角色后同一全局会话立即失去权限（不缓存）。
	if err := runtime.Admin().RevokeApplicationRole(ctx, RevokeRoleRequest{
		Caller: runtime.LocalAdmin(), UserID: evidence.member.ID,
		RoleID: evidence.role.ID, RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("撤回角色失败: %v", err)
	}
	revoked, err := sessions.Authorize(ctx, SessionAccessRequest{
		SessionSecret: globalLogin.SessionSecret, AppID: evidence.appA.ID,
		Permissions: []string{"invoice.read"},
		RequestID:   "req_208_revoked"})
	if err != nil {
		t.Fatalf("撤销后判定不应返回内部错误: %v", err)
	}
	if revoked.Allowed || revoked.Code == "" {
		t.Fatalf("撤销角色后不应再允许: %+v", revoked)
	}
}

// TestSessionAuthorizeRejectsRestrictedSessionDespiteCSRF 验证受限会话即使 CSRF
// 校验通过也不能访问业务；CSRF 不会提升会话权限。
func TestSessionAuthorizeRejectsRestrictedSessionDespiteCSRF(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 6, 0, 0, 0, time.UTC))
	evidence := setupStep208Evidence(t, ctx, clock, t.TempDir(), testConfig())
	runtime := evidence.runtime
	const password = "K8$wR3!nB6@yF1#v"

	// 同一成员账户绑定 TOTP 后重新登录会得到受限会话。
	firstLogin := step208Login(t, ctx, runtime, "member208", password, "")
	totpStart, err := runtime.Security().BeginTOTPBinding(ctx, TOTPBindingBeginRequest{
		SessionSecret: firstLogin.SessionSecret, Password: password,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("开始绑定 TOTP 失败: %v", err)
	}
	if _, err := runtime.Security().ConfirmTOTPBinding(ctx, TOTPBindingConfirmRequest{
		SessionSecret: firstLogin.SessionSecret, BindingID: totpStart.BindingID,
		Code:      currentTOTP(t, clock, totpStart.Secret),
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("确认 TOTP 绑定失败: %v", err)
	}
	clock.Advance(30 * time.Second)
	restricted, err := runtime.Auth().Login(ctx, LoginRequest{
		Username: "member208", Password: password, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("受限登录失败: %v", err)
	}
	if !restricted.Restricted || restricted.SecondFactor == nil {
		t.Fatalf("绑定 TOTP 后登录应为受限会话: %+v", restricted)
	}

	// 受限会话的 CSRF 校验（若通过）也不能提升业务权限。
	csrfValid := len(restricted.CSRFSecret) > 0
	if csrfValid {
		if err := runtime.Sessions().ValidateCSRF(ctx, restricted.SessionSecret,
			string(restricted.CSRFSecret)); err != nil {
			csrfValid = false
		}
	}
	request := SessionAccessRequest{
		SessionSecret: restricted.SessionSecret, AppID: evidence.appA.ID,
		Permissions: []string{"invoice.read"}, RequestID: "req_208_restricted"}
	if csrfValid {
		request.CSRFToken = string(restricted.CSRFSecret)
	}
	decision, err := runtime.Sessions().Authorize(ctx, request)
	if err != nil {
		t.Fatalf("受限会话判定不应返回内部错误: %v", err)
	}
	if decision.Allowed {
		t.Fatalf("受限会话不能访问业务（CSRF 通过也不提升）: csrfValid=%v %+v",
			csrfValid, decision)
	}
	if decision.Code != string(login.CodeAccessDenied) ||
		decision.Reason != "restricted_session" {
		t.Fatalf("受限会话拒绝语义异常: %+v", decision)
	}
	if decision.RequestID != "req_208_restricted" {
		t.Fatalf("受限会话拒绝请求编号 = %q", decision.RequestID)
	}

	// 受限会话 + 错误 CSRF 令牌：在权限判定前就拒绝，不能靠错误 CSRF 得到允许。
	if _, err := runtime.Sessions().Authorize(ctx, SessionAccessRequest{
		SessionSecret: restricted.SessionSecret, AppID: evidence.appA.ID,
		Permissions: []string{"invoice.read"}, CSRFToken: "wrong-csrf-token",
		RequestID: "req_208_bad_csrf"}); err == nil {
		t.Fatal("错误 CSRF 令牌必须拒绝")
	}
}

// TestSessionAuthorizeRequestIDPlumbing 验证 Authorize 的请求编号生成/非法拒绝
// 与拒绝决策编号一致。
func TestSessionAuthorizeRequestIDPlumbing(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 6, 30, 0, 0, time.UTC))
	evidence := setupStep208Evidence(t, ctx, clock, t.TempDir(), testConfig())
	runtime := evidence.runtime
	loginResult := step208Login(t, ctx, runtime, "member208", "K8$wR3!nB6@yF1#v", "")

	// 空编号：拒绝决策也带统一生成的合法编号。
	decision, err := runtime.Sessions().Authorize(ctx, SessionAccessRequest{
		SessionSecret: loginResult.SessionSecret, AppID: evidence.appB.ID,
		Permissions: []string{"invoice.read"}})
	if err != nil {
		t.Fatalf("空编号判定不应返回内部错误: %v", err)
	}
	if decision.Allowed || decision.RequestID == "" {
		t.Fatalf("空编号拒绝决策应带生成编号: %+v", decision)
	}
	if validateErr := login.ValidateRequestID(decision.RequestID); validateErr != nil {
		t.Fatalf("生成的编号非法 %q: %v", decision.RequestID, validateErr)
	}

	// 非法编号：在会话/权限判定前拒绝，且不回显非法值。
	_, err = runtime.Sessions().Authorize(ctx, SessionAccessRequest{
		SessionSecret: loginResult.SessionSecret, AppID: evidence.appA.ID,
		Permissions: []string{"invoice.read"}, RequestID: "请求编号"})
	appError := step207AppError(t, err)
	if appError.Code() != login.CodeReqInvalid || appError.RequestID() != "" {
		t.Fatalf("非法编号应返回不带编号的 REQ_INVALID，实际 %v", appError)
	}

	// context 取消：不执行判定、不消耗限流，错误码稳定且原因链保留 context 错误。
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = runtime.Sessions().Authorize(canceled, SessionAccessRequest{
		SessionSecret: loginResult.SessionSecret, AppID: evidence.appA.ID,
		Permissions: []string{"invoice.read"}, RequestID: "req_208_canceled"})
	if err == nil {
		t.Fatal("已取消的 context 必须拒绝")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("取消错误应保留 context.Canceled 原因链，实际 %v", err)
	}
}
