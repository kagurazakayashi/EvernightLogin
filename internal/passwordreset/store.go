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
	// EmailNormalized 是账户当前最近已验证邮箱的规范化值；签发绑定与完成复核使用。
	EmailNormalized string
	// SecurityVersion 是账户当前安全版本（统一安全代际）；密码/MFA/账户状态等安全
	// 变更在各自事务内原子递增，旧找回入口据此失效。
	SecurityVersion int64
	// EmailIdentityVersion 是账户当前已验证邮箱身份代际（users.email_identity_version，
	// 0053 迁移引入）。它在每次真实改变已验证邮箱身份时于同一审计事务内单调递增：
	// 本人换绑/首次添加、注册首次验证、邀请新用户预验证邮箱等。与 EmailNormalized
	// 不同，代际不会因邮箱文本 A→B→A 往返复原而回退，因此签发时绑定该代际可让旧
	// 找回入口永久失效，不因“当前邮箱文本又等于签发值”而复活。
	EmailIdentityVersion int64
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
	// SecurityVersion 是签发时账户的安全版本（统一安全代际）；完成/预检查必须与
	// 账户当前值一致，否则说明签发后发生过密码/MFA/账户状态等安全变更。
	SecurityVersion int64
	// BoundEmailNormalized 是签发时账户的最近已验证邮箱（规范化）；完成/预检查必须
	// 与账户当前最近已验证邮箱一致，否则说明验证邮箱已切换。
	BoundEmailNormalized string
	// BoundEmailIdentityVersion 是签发时账户的已验证邮箱身份代际（可选，0053 引入）。
	// 完成/预检查必须与账户当前代际一致：邮箱 A→B→A 往返后文本复原但代际已前进，
	// 旧入口据此永久失效。0053 之前已绑定（0051）但无代际的旧行为 NULL，按未绑定
	// 保守失效（不回填）。
	BoundEmailIdentityVersion int64
	// Bound 表示该请求是否带有完整绑定（安全代际 + 已验证邮箱文本 + 已验证邮箱身份
	// 代际，缺一不可）。迁移前旧行与 0051～0052 期间未写代际的旧行为 false，一律按
	// 失效处理（保守拒绝，不做回填）。
	Bound bool
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
	// GetResetTarget 按用户 ID 重新确认账户可找回（active/非 root/有密码），并返回
	// 当前安全版本与最近已验证邮箱（用于核对签发绑定）。
	GetResetTarget(ctx context.Context, userID string) (Candidate, bool, error)
	// GetResetTargetTx 在审计事务内按用户 ID 重新确认账户可找回并读取当前安全版本与
	// 最近已验证邮箱；用于把安全代际/邮箱绑定核对放进签发与完成的事务提交边界（步骤 206）。
	GetResetTargetTx(ctx context.Context, tx audit.Tx, userID string) (Candidate, bool, error)
}
