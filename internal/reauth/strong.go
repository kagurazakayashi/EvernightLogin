package reauth

import (
	"context"
	"time"
)

// StrongFactorVerifyRequest 是再次认证的强因素验证请求。密码已由 reauth 在
// VerifyChallenge 中独立验证；本接口只校验第二条强因素，不允许把密码重复当作
// 强认证。
type StrongFactorVerifyRequest struct {
	UserID    string
	TOTPCode  string
	RequestID string
}

// StrongFactorVerifyResult 是一次成功的强因素验证事实。
type StrongFactorVerifyResult struct {
	UserID      string
	CompletedAt time.Time
	// Method 是稳定方法标识（例如 totp/passkey），仅用于审计/展示，不参与策略。
	Method string
	// UserVerified 表示强因素完成用户验证（TOTP 视为已验证）。
	UserVerified bool
}

// StrongFactorVerifier 是强因素再次验证契约；生产实现由 internal/totp（或后续
// Passkey ceremony 适配器）提供。未注入时必须对 strong 要求 fail-closed。
type StrongFactorVerifier interface {
	VerifyStrongFactor(ctx context.Context, request StrongFactorVerifyRequest) (StrongFactorVerifyResult, error)
}
