package app

// 步骤 208 找回入口来源限流测试：
//   - 来源键来自可信边界的单一 IP（空 → 共享无来源桶；伪造转发头链/任意字符串拒绝），
//     不以每次可更换的 token secret 作为唯一计数键；
//   - Validate/Complete 公开入口超限返回 RATE_LIMITED（带同一请求编号），不同来源互不
//     影响；非法来源与已取消的 context 不消耗限流预算；
//   - 限流器键容量有界（fail-closed），不是无限增长的 map。

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/transport"
)

// TestPasswordResetValidateSourceLimit 验证 Validate 入口的来源限流与拒绝语义。
func TestPasswordResetValidateSourceLimit(t *testing.T) {
	ctx := context.Background()
	runtime := openTestRuntime(t, Options{})
	facade := runtime.PasswordReset()

	const source = "203.0.113.7"
	// 前 Limit 次（无效 token）统一 CHALLENGE_INVALID，证明限流前正常走领域判断。
	for index := 0; index < passwordResetValidateSourceLimit; index++ {
		err := facade.ValidateTokenWithSource(ctx, ValidatePasswordResetTokenRequest{
			Token: fmt.Sprintf("invalid-token-%d", index), ClientIP: source,
			RequestID: fmt.Sprintf("req_208_validate_%d", index)})
		if !login.IsErrorCode(err, login.CodeChallengeInvalid) {
			t.Fatalf("第 %d 次预检查错误 = %v，期望 CHALLENGE_INVALID", index+1, err)
		}
	}
	// 超限：RATE_LIMITED，带同一请求编号；不再调用领域判断（仍不泄露 token 状态）。
	const limitedRequestID = "req_208_validate_limited"
	err := facade.ValidateTokenWithSource(ctx, ValidatePasswordResetTokenRequest{
		Token: "invalid-token-over-limit", ClientIP: source, RequestID: limitedRequestID})
	appError := step207AppError(t, err)
	if appError.Code() != login.CodeRateLimited {
		t.Fatalf("超限错误码 = %q，期望 RATE_LIMITED", appError.Code())
	}
	if appError.RequestID() != limitedRequestID {
		t.Fatalf("超限错误请求编号 = %q，期望 %q", appError.RequestID(), limitedRequestID)
	}
	// 不同来源有独立预算：同一时刻另一个来源仍可正常判断。
	if err := facade.ValidateTokenWithSource(ctx, ValidatePasswordResetTokenRequest{
		Token: "invalid-token-other-source", ClientIP: "198.51.100.9",
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeChallengeInvalid) {
		t.Fatalf("不同来源不应被同一预算限流，实际 %v", err)
	}
}

// TestPasswordResetCompleteSourceLimit 验证 Complete 入口的来源限流。
func TestPasswordResetCompleteSourceLimit(t *testing.T) {
	ctx := context.Background()
	runtime := openTestRuntime(t, Options{})
	facade := runtime.PasswordReset()
	const source = "192.0.2.55"
	for index := 0; index < passwordResetCompleteSourceLimit; index++ {
		_, err := facade.Complete(ctx, CompletePasswordResetRequest{
			Token: fmt.Sprintf("invalid-token-%d", index), NewPassword: "K8$wR3!nB6@yF1#v",
			ClientIP: source, RequestID: fmt.Sprintf("req_208_complete_%d", index)})
		if !login.IsErrorCode(err, login.CodeChallengeInvalid) {
			t.Fatalf("第 %d 次完成失败错误 = %v，期望 CHALLENGE_INVALID", index+1, err)
		}
	}
	const limitedRequestID = "req_208_complete_limited"
	_, err := facade.Complete(ctx, CompletePasswordResetRequest{
		Token: "invalid-token-over-limit", NewPassword: "K8$wR3!nB6@yF1#v",
		ClientIP: source, RequestID: limitedRequestID})
	appError := step207AppError(t, err)
	if appError.Code() != login.CodeRateLimited {
		t.Fatalf("Complete 超限错误码 = %q，期望 RATE_LIMITED", appError.Code())
	}
	if appError.RequestID() != limitedRequestID {
		t.Fatalf("Complete 超限请求编号 = %q，期望 %q", appError.RequestID(), limitedRequestID)
	}
}

// TestPasswordResetSourceKeyTrustBoundary 验证来源键只接受可信边界的单一 IP：伪造
// 转发头链/任意字符串被拒绝且不生成限流键；空来源共享同一个有界桶。
func TestPasswordResetSourceKeyTrustBoundary(t *testing.T) {
	ctx := context.Background()
	runtime := openTestRuntime(t, Options{})
	facade := runtime.PasswordReset()

	// 伪造/未解析的转发头值不是单一 IP：拒绝且不消耗任何来源预算。
	for _, spoofed := range []string{
		"203.0.113.7, 198.51.100.9", "unknown", "client.example.test",
		"http://203.0.113.7", "::1%zone",
	} {
		err := facade.ValidateTokenWithSource(ctx, ValidatePasswordResetTokenRequest{
			Token: "invalid-token", ClientIP: spoofed, RequestID: login.NewRequestID()})
		if !login.IsErrorCode(err, login.CodeReqInvalid) {
			t.Fatalf("伪造来源 %q 错误 = %v，期望 REQ_INVALID", spoofed, err)
		}
	}

	// 空来源：使用共享的无来源桶并正常获得独立预算（不被伪造来源影响）。
	for index := 0; index < passwordResetValidateSourceLimit; index++ {
		if err := facade.ValidateTokenWithSource(ctx, ValidatePasswordResetTokenRequest{
			Token: fmt.Sprintf("invalid-empty-source-%d", index)}); !login.IsErrorCode(err, login.CodeChallengeInvalid) {
			t.Fatalf("空来源第 %d 次预检查错误 = %v", index+1, err)
		}
	}
	if err := facade.ValidateTokenWithSource(ctx, ValidatePasswordResetTokenRequest{
		Token: "invalid-empty-source-over-limit"}); !login.IsErrorCode(err, login.CodeRateLimited) {
		t.Fatalf("空来源超限应返回 RATE_LIMITED，实际 %v", err)
	}
	// 合法不同 IP 写法归一：先填满 IPv4 来源预算，再用 IPv4 映射 IPv6 写法访问，
	// 必须共享同一键（不因写法差异放大预算）。
	for index := 0; index < passwordResetValidateSourceLimit; index++ {
		if err := facade.ValidateTokenWithSource(ctx, ValidatePasswordResetTokenRequest{
			Token:    fmt.Sprintf("invalid-ipv4-source-%d", index),
			ClientIP: "203.0.113.7"}); !login.IsErrorCode(err, login.CodeChallengeInvalid) {
			t.Fatalf("IPv4 来源第 %d 次预检查错误 = %v", index+1, err)
		}
	}
	if err := facade.ValidateTokenWithSource(ctx, ValidatePasswordResetTokenRequest{
		Token: "invalid-normalized", ClientIP: "::ffff:203.0.113.7"}); !login.IsErrorCode(err, login.CodeRateLimited) {
		t.Fatalf("同一地址不同写法应共享预算，实际 %v", err)
	}
}

// TestPasswordResetValidateTokenRequestID 验证兼容入口 ValidateToken 的返回错误带
// 请求编号：显式未提供时生成合法编号；context 中已有 HTTP 层编号时复用同一编号。
func TestPasswordResetValidateTokenRequestID(t *testing.T) {
	ctx := context.Background()
	runtime := openTestRuntime(t, Options{})
	facade := runtime.PasswordReset()

	err := facade.ValidateToken(ctx, "invalid-token")
	appError := step207AppError(t, err)
	if appError.Code() != login.CodeChallengeInvalid {
		t.Fatalf("无效 token 错误码 = %q，期望 CHALLENGE_INVALID", appError.Code())
	}
	if appError.RequestID() == "" {
		t.Fatal("ValidateToken 返回错误必须带统一生成的请求编号")
	}
	if validateErr := login.ValidateRequestID(appError.RequestID()); validateErr != nil {
		t.Fatalf("生成的请求编号非法 %q: %v", appError.RequestID(), validateErr)
	}

	// context 中已有可信请求编号（HTTP 防护层解析）时原样复用，不重新生成。
	ctxWithID := transport.WithRequestID(ctx, "req_ctx_208_validate")
	err = facade.ValidateToken(ctxWithID, "invalid-token")
	appError = step207AppError(t, err)
	if appError.RequestID() != "req_ctx_208_validate" {
		t.Fatalf("context 请求编号未复用: %q", appError.RequestID())
	}
}

// TestPasswordResetLimiterCancelAndCapacity 验证已取消 context 不消耗预算，且限流器
// 键容量有界（fail-closed）。
func TestPasswordResetLimiterCancelAndCapacity(t *testing.T) {
	ctx := context.Background()
	runtime := openTestRuntime(t, Options{})
	facade := runtime.PasswordReset()

	// 已取消 context：不执行领域判断、不消耗预算，错误链保留 context.Canceled。
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	for index := 0; index < passwordResetValidateSourceLimit+5; index++ {
		err := facade.ValidateTokenWithSource(canceled, ValidatePasswordResetTokenRequest{
			Token: fmt.Sprintf("invalid-canceled-%d", index), ClientIP: "198.51.100.77",
			RequestID: fmt.Sprintf("req_208_canceled_%d", index)})
		if err == nil {
			t.Fatalf("已取消 context 第 %d 次调用必须失败", index+1)
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("取消错误应保留 context.Canceled，实际 %v", err)
		}
	}
	// 取消没有消耗预算：同来源随后仍可完整获得 Limit 次正常判断。
	for index := 0; index < passwordResetValidateSourceLimit; index++ {
		if err := facade.ValidateTokenWithSource(ctx, ValidatePasswordResetTokenRequest{
			Token:    fmt.Sprintf("invalid-after-cancel-%d", index),
			ClientIP: "198.51.100.77"}); !login.IsErrorCode(err, login.CodeChallengeInvalid) {
			t.Fatalf("取消后第 %d 次正常判断错误 = %v", index+1, err)
		}
	}

	// 键容量有界：填入超过容量的唯一来源后，新来源被 fail-closed 拒绝，条目数不
	// 超过配置上限（不会因伪造大量来源无限增长）。
	limiters, err := newPasswordResetLimiters(runtime.nowFn)
	if err != nil {
		t.Fatalf("构造限流器失败: %v", err)
	}
	uniqueSources := passwordResetLimiterMaxEntries + 32
	for index := 0; index < uniqueSources; index++ {
		// 10.a.b.c 形式生成互不相同的 IPv4 地址。
		source := fmt.Sprintf("10.%d.%d.%d", (index>>16)&0xff, (index>>8)&0xff, index&0xff)
		allowSource(limiters.validate, source)
	}
	if entries := limiters.validate.Len(); entries > passwordResetLimiterMaxEntries {
		t.Fatalf("限流器键数量 = %d，超过上限 %d", entries, passwordResetLimiterMaxEntries)
	}
	decision := limiters.validate.Allow("10.250.250.250")
	if decision.Allowed {
		t.Fatalf("容量耗尽后新键必须 fail-closed 拒绝: %+v", decision)
	}
	if decision.Reason != "capacity" {
		t.Fatalf("容量拒绝原因 = %q，期望 capacity", decision.Reason)
	}
}
