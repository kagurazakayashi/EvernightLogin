package app

// 步骤 223：本人受控改密公开接口测试（无管理员改他人密码旁路）。

import (
	"context"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

// TestChangeOwnPassword 覆盖本人改密成功链、旧会话失效与新密码登录。
func TestChangeOwnPassword(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 4, 10, 0, 0, time.UTC))
	runtime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	const password = "K8$wR3!nB6@yF1#v"
	user := createLifecycleUser(t, ctx, runtime, "password-target", password)
	session := loginLifecycleUser(t, ctx, runtime, "password-target", password)

	newPassword := "S9!kR4#mW7@qB2$x"
	result, err := runtime.Passwords().ChangeOwnPassword(ctx, ChangeOwnPasswordRequest{
		SessionSecret: session, CurrentPassword: password, NewPassword: newPassword,
		ClientIP: "127.0.0.1", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("ChangeOwnPassword: %v", err)
	}
	if result.UserID != user.ID || !result.RequiresRelogin ||
		result.SecurityVersion <= 0 {
		t.Fatalf("改密结果异常: %+v", result)
	}
	if _, err := runtime.Sessions().Validate(ctx, session); err == nil {
		t.Fatal("改密后旧会话仍有效")
	}
	// 旧密码拒绝、新密码可登录。
	if _, err := runtime.Auth().Login(ctx, LoginRequest{
		Username: "password-target", Password: password, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("旧密码仍可登录")
	}
	if _, err := runtime.Auth().Login(ctx, LoginRequest{
		Username: "password-target", Password: newPassword, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("新密码登录失败: %v", err)
	}
}

// TestChangeOwnPasswordRejections 覆盖弱密码与无效会话拒绝；失败不撤销会话。
func TestChangeOwnPasswordRejections(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 4, 20, 0, 0, time.UTC))
	runtime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	const password = "K8$wR3!nB6@yF1#v"
	createLifecycleUser(t, ctx, runtime, "password-weak", password)
	session := loginLifecycleUser(t, ctx, runtime, "password-weak", password)

	if _, err := runtime.Passwords().ChangeOwnPassword(ctx, ChangeOwnPasswordRequest{
		SessionSecret: session, CurrentPassword: password, NewPassword: "123456",
		ClientIP: "127.0.0.1", RequestID: login.NewRequestID()}); err == nil {
		t.Fatal("弱密码被接受")
	}
	// 失败不撤销会话，也不改密码。
	if _, err := runtime.Sessions().Validate(ctx, session); err != nil {
		t.Fatalf("弱密码失败后会话不应被撤销: %v", err)
	}
	if _, err := runtime.Auth().Login(ctx, LoginRequest{
		Username: "password-weak", Password: password, ClientIP: "127.0.0.1",
		RequestID: login.NewRequestID()}); err != nil {
		t.Fatalf("弱密码失败后原密码应仍可登录: %v", err)
	}
	if _, err := runtime.Passwords().ChangeOwnPassword(ctx, ChangeOwnPasswordRequest{
		SessionSecret: []byte("invalid-session"), CurrentPassword: password,
		NewPassword: "S9!kR4#mW7@qB2$x", RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeAuthFailed) {
		t.Fatalf("无效会话改密错误 = %v，期望 AUTH_FAILED", err)
	}
}
