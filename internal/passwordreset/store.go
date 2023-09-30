package passwordreset

import (
	"context"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// Candidate 是按已验证邮箱查到的找回候选账户快照（只在服务内部使用）。
type Candidate struct {
	UserID      string
	Username    string
	Email       string
	MaskedEmail string
	HasPassword bool
	Active      bool
	IsRoot      bool
}

// ResetRequest 是一次找回请求的持久化状态；不保存 token 明文。
type ResetRequest struct {
	ID           string
	UserID       string
	MaskedEmail  string
	CredentialID string
	State        string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	ConsumedAt   time.Time
	// TokenSHA256 是找回入口秘密的 SHA-256（不含明文），用于不消费的预检查。
	TokenSHA256 []byte
}

// Store 是找回请求与 OAuth 撤销 outbox 的持久化契约，由 internal/passwordreset/sqlite
// 实现。状态迁移使用条件更新，凭证消费由 internal/credential 保证原子单赢家。
type Store interface {
	// FindUserByEmail 按规范化邮箱（小写）查已验证邮箱的候选账户；不存在返回 false。
	FindUserByEmail(ctx context.Context, normalizedEmail string) (Candidate, bool, error)
	// CreateRequestTx 在审计事务内创建 pending 找回请求。
	CreateRequestTx(ctx context.Context, tx audit.Tx, request ResetRequest) error
	// GetRequest 按找回请求 ID 读取状态。
	GetRequest(ctx context.Context, id string) (ResetRequest, bool, error)
	// ConsumeRequestTx 条件把 pending 且未过期的请求标记 consumed；返回是否成功。
	ConsumeRequestTx(ctx context.Context, tx audit.Tx, id string, now time.Time) (bool, error)
	// InsertOutboxTx 在审计事务内写入 OAuth 撤销可靠事件（outbox），返回事件 ID。
	InsertOutboxTx(ctx context.Context, tx audit.Tx, userID, reason string, now time.Time) (string, error)
	// VerifiedEmail 返回用户最近一个已验证邮箱（安全告知收件人）。
	VerifiedEmail(ctx context.Context, userID string) (string, bool, error)
	// ListPending 列出用户 pending 找回请求（用于作废旧入口与撤销凭证）。
	ListPending(ctx context.Context, userID string) ([]ResetRequest, error)
	// ListPendingTx 在审计事务内列出用户 pending 找回请求，用于把“作废其他入口
	// 并撤销其凭证”与请求消费/密码写入放进同一提交边界（步骤 205）。
	ListPendingTx(ctx context.Context, tx audit.Tx, userID string) ([]ResetRequest, error)
	// CancelPendingTx 在审计事务内把用户所有 pending 请求标记 cancelled，返回行数。
	CancelPendingTx(ctx context.Context, tx audit.Tx, userID string, now time.Time) (int64, error)
	// GetResetTarget 按用户 ID 重新确认账户可找回（active/非 root/有密码）。
	GetResetTarget(ctx context.Context, userID string) (Candidate, bool, error)
}
