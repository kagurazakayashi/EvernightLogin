package ui

// 步骤 259：管理员直接重置他人密码的管理页页面契约。
//
// 与 258 直接改名相同的安全边界：页面会话摘要不含真实会话秘密；秘密由宿主注入的
// `UIPageAdminOptions.ManagementSession` 回调在处理器代码内取得，只作为参数传给
// 后端方法，不进入模板上下文/渲染数据/响应/日志。授权、证明绑定/消费、密码策略与
// 历史、事务一致提交仍由后端门面执行；按钮显示只是体验。

import (
	"context"
	"time"
)

// UIDirectPasswordResetChallenge 是两步验证挑战投影。
type UIDirectPasswordResetChallenge struct {
	ChallengeID       string
	TargetUserID      string
	RequiredStrength  string
	ExpiresAt         time.Time
	MaxAttempts       int
	WebAuthnAvailable bool
}

// UIDirectPasswordResetGrant 是一次性证明（只在处理器内存，立即用于提交）。
type UIDirectPasswordResetGrant struct {
	ProofToken string
	ExpiresAt  time.Time
}

// UIDirectPasswordResetResult 是重置成功的脱敏结果（不含密码/哈希/证明）。
type UIDirectPasswordResetResult struct {
	UserID                     string
	SecurityVersion            int64
	PasswordChangedAt          time.Time
	MustChange                 bool
	SessionsRevoked            int64
	OldResetRequestsCancelled  int64
	OldResetCredentialsRevoked int64
}

// UIDirectPasswordResetBackend 是管理页直接重置密码的可选后端契约。
type UIDirectPasswordResetBackend interface {
	CanResetPassword(ctx context.Context, adminUserID string) (bool, error)
	BeginDirectPasswordReset(ctx context.Context, adminUserID, sessionSecret,
		targetUserID, newPassword, requestID string) (UIDirectPasswordResetChallenge, error)
	ConfirmDirectPasswordReset(ctx context.Context, adminUserID, sessionSecret,
		challengeID, password, totpCode, requestID string) (UIDirectPasswordResetGrant, error)
	ApplyDirectPasswordReset(ctx context.Context, adminUserID, sessionSecret,
		targetUserID, newPassword, reason, proofToken, requestID string) (UIDirectPasswordResetResult, error)
}
