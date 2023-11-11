package app

// 步骤 221 P0：邮箱变更公开接口测试（真实邮件捕获 + 206 旧找回失效链）。
//   - State/Request/Cancel/Verify 全部经公开门面；
//   - 变更请求走真实再次认证（当前密码）；
//   - 邮箱切换成功后，切换前签发的找回链接必须失效（206）。

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

// TestEmailChangePublicFlow 覆盖邮箱变更状态/发起/验证与旧找回失效。
func TestEmailChangePublicFlow(t *testing.T) {
	ctx := context.Background()
	capture := startSMTPCapture(t)
	clock := newTestClock(time.Date(2026, 11, 25, 5, 50, 0, 0, time.UTC))
	runtime := openMailRuntime(t, ctx, capture, clock)
	const password = "K8$wR3!nB6@yF1#v"
	const oldEmail = "email-old@example.test"
	const newEmail = "email-new@example.test"

	// 注册并验证初始邮箱（复用公开门面）。
	registered, err := runtime.Registration().RegisterAccount(ctx, RegisterAccountRequest{
		Username: "email-change-user", Password: password, Email: oldEmail,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("RegisterAccount: %v", err)
	}
	verificationLink := capture.waitMail(t, "/email/verify")
	parsed, err := url.Parse(verificationLink)
	if err != nil {
		t.Fatalf("解析验证链接失败: %v", err)
	}
	if _, err := runtime.Registration().VerifyEmail(ctx, VerifyEmailRequest{
		UserID: parsed.Query().Get("uid"), CredentialID: parsed.Query().Get("cid"),
		Token: parsed.Query().Get("token"), RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}

	// 切换前签发一枚找回链接（应随邮箱安全变更失效）。
	if err := runtime.PasswordReset().Request(ctx, RequestPasswordResetRequest{
		Identifier: oldEmail, ClientIP: "127.0.0.1", RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("发起找回失败: %v", err)
	}
	resetLink := capture.waitMail(t, "/login/reset-password")
	resetURL, err := url.Parse(resetLink)
	if err != nil {
		t.Fatalf("解析找回链接失败: %v", err)
	}
	staleResetToken := resetURL.Query().Get("token")
	if staleResetToken == "" {
		t.Fatal("找回链接缺少 token")
	}

	session := loginLifecycleUser(t, ctx, runtime, "email-change-user", password)
	emailChange := runtime.EmailChange()
	state, err := emailChange.State(ctx, EmailChangeStateRequest{
		SessionSecret: session, RequestID: login.NewRequestID()})
	if err != nil || state.Pending {
		t.Fatalf("初始邮箱变更状态异常: %+v, %v", state, err)
	}

	// 错误密码：真实再次认证失败，不创建 pending 申请。
	if _, err := emailChange.Request(ctx, RequestEmailChangeRequest{
		SessionSecret: session, NewEmail: newEmail, Password: "Wrong!Passw0rd",
		RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("错误密码不应允许发起邮箱变更")
	}
	requested, err := emailChange.Request(ctx, RequestEmailChangeRequest{
		SessionSecret: session, NewEmail: newEmail, Password: password,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if !requested.Pending || requested.NewEmail != newEmail ||
		!requested.VerificationSent {
		t.Fatalf("邮箱变更申请状态异常: %+v", requested)
	}
	changeLink := capture.waitMail(t, "/email/change/verify")
	changeURL, err := url.Parse(changeLink)
	if err != nil {
		t.Fatalf("解析邮箱变更链接失败: %v", err)
	}
	verified, err := emailChange.Verify(ctx, VerifyEmailChangeRequest{
		ChangeRequestID: changeURL.Query().Get("rid"),
		CredentialID:    changeURL.Query().Get("cid"),
		Token:           changeURL.Query().Get("token"),
		RequestID:       login.NewRequestID()})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.Email != newEmail || verified.UserID != registered.UserID {
		t.Fatalf("邮箱切换结果异常: %+v", verified)
	}

	// 206：切换前签发的找回链接必须失效。
	if err := runtime.PasswordReset().ValidateTokenWithSource(ctx,
		ValidatePasswordResetTokenRequest{Token: staleResetToken, ClientIP: "127.0.0.1",
			RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("邮箱切换后旧找回链接仍有效")
	}

	// 取消路径：再次发起后取消，状态回到无 pending。
	if _, err := emailChange.Request(ctx, RequestEmailChangeRequest{
		SessionSecret: session, NewEmail: "email-cancel@example.test", Password: password,
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("第二次 Request: %v", err)
	}
	if err := emailChange.Cancel(ctx, CancelEmailChangeRequest{
		SessionSecret: session, RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	afterCancel, err := emailChange.State(ctx, EmailChangeStateRequest{
		SessionSecret: session, RequestID: login.NewRequestID()})
	if err != nil || afterCancel.Pending {
		t.Fatalf("取消后状态异常: %+v, %v", afterCancel, err)
	}
	// 无效会话：拒绝且不泄露身份。
	if _, err := emailChange.State(ctx, EmailChangeStateRequest{
		SessionSecret: []byte("invalid-session"), RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeAuthFailed) {
		t.Fatalf("无效会话读取状态错误 = %v，期望 AUTH_FAILED", err)
	}
}
