package app

import (
	"context"
	"testing"
)

func TestPasswordResetRequiresMailAndRejectsInvalidToken(t *testing.T) {
	ctx := context.Background()
	runtime := openTestRuntime(t, Options{})

	if err := runtime.PasswordReset().Request(ctx, RequestPasswordResetRequest{
		Identifier: "alice@example.test", ClientIP: "127.0.0.1",
	}); err == nil {
		t.Fatal("未启用邮件时 Request 必须返回配置错误")
	}
	if err := runtime.PasswordReset().ValidateToken(ctx, "not-a-real-token"); err == nil {
		t.Fatal("无效 token 必须拒绝")
	}
	if _, err := runtime.PasswordReset().Complete(ctx, CompletePasswordResetRequest{
		Token: "not-a-real-token", NewPassword: "K8$wR3!nB6@yF1#v",
	}); err == nil {
		t.Fatal("无效 token 必须拒绝")
	}
}
