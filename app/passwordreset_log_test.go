package app

// 步骤 208 日志脱敏测试：找回入口失败/成功路径不得把完整 token、密码或找回链接写进
// 运行日志（审计按领域规则记录脱敏/摘要信息，不属运行日志）。

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin"
)

func TestPasswordResetFacadeLogsNoSecrets(t *testing.T) {
	var logBuffer bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuffer, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	runtime := openTestRuntime(t, Options{Logger: logger})
	ctx := context.Background()
	facade := runtime.PasswordReset()

	const token = "prq_step208_token_secret_must_not_appear"
	const password = "P7!sT4@xB9#mQ2$v"
	const identifier = "step208-log@example.test"

	_ = facade.ValidateTokenWithSource(ctx, ValidatePasswordResetTokenRequest{
		Token: token, ClientIP: "203.0.113.9", RequestID: login.NewRequestID()})
	_, _ = facade.Complete(ctx, CompletePasswordResetRequest{
		Token: token, NewPassword: password, ClientIP: "203.0.113.9",
		RequestID: login.NewRequestID()})
	_ = facade.Request(ctx, RequestPasswordResetRequest{
		Identifier: identifier, ClientIP: "203.0.113.9", RequestID: login.NewRequestID()})
	// 超限路径也不能把 token 写入日志。
	for index := 0; index < passwordResetValidateSourceLimit+2; index++ {
		_ = facade.ValidateTokenWithSource(ctx, ValidatePasswordResetTokenRequest{
			Token: token + "-limit", ClientIP: "198.51.100.44",
			RequestID: login.NewRequestID()})
	}

	logs := logBuffer.String()
	for _, secret := range []string{token, password, "reset-password?token="} {
		if strings.Contains(logs, secret) {
			t.Fatalf("运行日志包含不应出现的秘密/链接片段 %q:\n%s", secret, logs)
		}
	}
}
