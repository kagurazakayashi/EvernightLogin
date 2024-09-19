package serverapp

// 步骤 259：直接重置他人密码的 HTTP 桥接契约。
//
// 与 258 直接改名同构：授权、目标/密码策略校验、两步验证证明绑定与消费、
// 事务一致提交（密码/历史/安全版本、旧找回失效、OAuth 撤销 outbox、关键审计）、
// 提交后撤销会话与安全告知全部由宿主（根包 257 门面）执行；本包只定义管理 JSON API
// 与宿主实现之间的最小协议，不复制安全判定、不保存密码/证明。
//
// 桥接实现由宿主在 OpenBase 之后、HTTP 组装之前注入 Deps.DirectPasswordReset；
// 未注入时不挂载相关路由（fail-closed 404，不返回占位成功）。

import (
	"context"
	"time"
)

// DirectPasswordResetRequest 是直接重置密码提交请求；操作者身份来自可信会话，
// 新口令只用于门面策略/哈希与密封证明意图，不落日志/响应。
type DirectPasswordResetRequest struct {
	OperatorUserID string
	TargetUserID   string
	NewPassword    string
	Reason         string
	ProofToken     string
	RequestID      string
}

// DirectPasswordResetResult 是直接重置密码的脱敏结果（不含密码/哈希/种子）。
type DirectPasswordResetResult struct {
	UserID                     string
	SecurityVersion            int64
	PasswordChangedAt          time.Time
	MustChange                 bool
	SessionsRevoked            int64
	OldResetRequestsCancelled  int64
	OldResetCredentialsRevoked int64
	OutboxEventID              string
}

// DirectPasswordResetBridge 是宿主必须实现的直接重置密码桥接能力。所有方法都必须
// 使用 ctx 中由管理 API 中间件注入的真实管理会话秘密构造可信 AdminCaller；不得信任
// 请求体中的操作者字段；证明绑定本次目标与新口令（换目标/换口令/换会话/重放拒绝）。
type DirectPasswordResetBridge interface {
	BeginPasswordResetVerification(ctx context.Context, operatorUserID, targetUserID,
		newPassword, requestID string) (DirectProofChallenge, error)
	ConfirmPasswordResetVerification(ctx context.Context, operatorUserID,
		challengeID, password, totpCode, requestID string) (DirectProofGrant, error)
	BeginPasswordResetWebAuthnVerification(ctx context.Context, operatorUserID,
		challengeID, requestID string) (DirectWebAuthnStart, error)
	ConfirmPasswordResetWebAuthnVerification(ctx context.Context, operatorUserID,
		challengeID, ceremonyID string, response []byte,
		requestID string) (DirectProofGrant, error)
	CancelPasswordResetVerification(ctx context.Context, operatorUserID,
		challengeID, requestID string) error
	ResetPassword(ctx context.Context,
		request DirectPasswordResetRequest) (DirectPasswordResetResult, error)
}
