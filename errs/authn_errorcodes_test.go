package errs

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
)

// TestAuthnErrorCodesRegistered 验证认证/密码领域复用根包已登记错误码：
// 统一认证失败映射 AUTH_FAILED，限流映射 RATE_LIMITED，非法/弱密码映射
// REQ_INVALID，root 初始化状态冲突映射 CONFLICT，未授权映射 ACCESS_DENIED，
// 存储不可用映射 DB_UNAVAILABLE，审计失败映射 AUDIT_WRITE_FAILED；不新增注册码。
func TestAuthnErrorCodesRegistered(t *testing.T) {
	limitErr := &authn.RateLimitError{RetryAfter: time.Minute, Reason: "ip_limit"}
	cases := []struct {
		name     string
		err      error
		wantCode authn.ErrorCode
		wantHTTP int
	}{
		{name: "统一认证失败", err: authn.ErrAuthenticationFailed, wantCode: authn.CodeAuthFailed, wantHTTP: 401},
		{name: "限流", err: limitErr, wantCode: authn.CodeRateLimited, wantHTTP: 429},
		{name: "非法请求", err: fmt.Errorf("%w: bad", authn.ErrInvalidRequest), wantCode: authn.CodeReqInvalid, wantHTTP: 400},
		{name: "弱密码", err: authn.ErrWeakPassword, wantCode: authn.CodeReqInvalid, wantHTTP: 400},
		{name: "密码复用", err: authn.ErrPasswordReused, wantCode: authn.CodeReqInvalid, wantHTTP: 400},
		{name: "用户不存在", err: authn.ErrUserNotFound, wantCode: authn.CodeReqInvalid, wantHTTP: 400},
		{name: "尚未初始化", err: authn.ErrNotInitialized, wantCode: authn.CodeReqInvalid, wantHTTP: 400},
		{name: "需先兑换配置凭证", err: authn.ErrSetupVerificationRequired, wantCode: authn.CodeConflict, wantHTTP: 409},
		{name: "初始化已完成", err: authn.ErrSetupCompleted, wantCode: authn.CodeConflict, wantHTTP: 409},
		{name: "初始化状态冲突", err: authn.ErrSetupStateConflict, wantCode: authn.CodeConflict, wantHTTP: 409},
		{name: "未获准操作", err: authn.ErrAccessDenied, wantCode: authn.CodeAccessDenied, wantHTTP: 403},
		{name: "存储不可用", err: authn.ErrStoreUnavailable, wantCode: authn.CodeDBUnavailable, wantHTTP: 503},
		{name: "审计不可用", err: authn.ErrAuditUnavailable, wantCode: authn.CodeAuditWriteFailed, wantHTTP: 503},
		{name: "服务选项无效", err: authn.ErrOptionsInvalid, wantCode: authn.CodeInternalError, wantHTTP: 500},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := authn.CodeOf(test.err)
			if got != test.wantCode {
				t.Fatalf("CodeOf(%v) = %q，期望 %q", test.err, got, test.wantCode)
			}
			definition, ok := LookupErrorCode(ErrorCode(got))
			if !ok {
				t.Fatalf("错误码 %q 未在根包注册表登记", got)
			}
			if definition.HTTPStatus != test.wantHTTP {
				t.Errorf("错误码 %q HTTP 状态 = %d，期望 %d", got, definition.HTTPStatus, test.wantHTTP)
			}
		})
	}
	// 限流错误必须可提取等待时间并包装 ErrRateLimited。
	retryAfter, reason, ok := authn.AsRateLimit(errors.Join(fmt.Errorf("wrapped: %w", limitErr)))
	if !ok || retryAfter != time.Minute || reason != "ip_limit" {
		t.Fatalf("AsRateLimit = (%v,%q,%v)，期望 1 分钟/ip_limit", retryAfter, reason, ok)
	}
	if !errors.Is(limitErr, authn.ErrRateLimited) {
		t.Fatal("RateLimitError 未包装 ErrRateLimited")
	}
	// 未分类内部错误映射为 INTERNAL_ERROR（不进入任何具体错误码）。
	if got := authn.CodeOf(errors.New("unclassified")); got != authn.CodeInternalError {
		t.Fatalf("CodeOf(未分类错误) = %q，期望 INTERNAL_ERROR", got)
	}
}
