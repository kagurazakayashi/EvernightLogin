package reauth

import (
	"context"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
)

// ChallengeState 是认证挑战状态。
type ChallengeState string

const (
	ChallengePending   ChallengeState = "pending"
	ChallengeVerified  ChallengeState = "verified"
	ChallengeCancelled ChallengeState = "cancelled"
	ChallengeExpired   ChallengeState = "expired"
)

// ChallengeRecord 是持久化的操作绑定认证挑战。
type ChallengeRecord struct {
	ID               string
	UserID           string
	ScopeID          string
	OperationID      string
	TargetType       string
	TargetID         string
	ParamsSHA256     []byte
	RequiredStrength policy.Strength
	State            ChallengeState
	Attempts         int
	MaxAttempts      int
	ExpiresAt        time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
	VerifiedAt       time.Time
}

// ApprovalRecord 是持久化的一次性操作批准（令牌只存摘要）。
type ApprovalRecord struct {
	ID              string
	ChallengeID     string
	TokenSHA256     []byte
	UserID          string
	ScopeID         string
	OperationID     string
	TargetType      string
	TargetID        string
	ParamsSHA256    []byte
	GrantedStrength policy.Strength
	Complete        bool
	GrantedAt       time.Time
	ExpiresAt       time.Time
	ConsumedAt      time.Time
	CreatedAt       time.Time
}

// NotificationState 是安全告知结果状态（区分“未发送原因”，不能把未发送当成功）。
type NotificationState string

const (
	NotificationSent            NotificationState = "sent"
	NotificationFailed          NotificationState = "failed"
	NotificationNoVerifiedEmail NotificationState = "no_verified_email"
	NotificationRateLimited     NotificationState = "rate_limited"
	NotificationNotConfigured   NotificationState = "not_configured"
	NotificationSuppressed      NotificationState = "suppressed"
)

// NotificationRecord 是一条安全告知结果；收件地址只保存脱敏值。
type NotificationRecord struct {
	ID              string
	UserID          string
	OperationID     string
	TargetType      string
	TargetID        string
	Outcome         Outcome
	State           NotificationState
	ErrorCode       string
	ReasonCode      string
	RecipientMasked string
	CreatedAt       time.Time
}

// Store 是再次认证持久化契约，由 internal/reauth/sqlite 实现。挑战与批准的状态
// 迁移必须使用条件更新，保证一次性消费与状态竞争下只有一方成功。
type Store interface {
	// CreateChallengeTx 在审计事务内创建挑战。
	CreateChallengeTx(ctx context.Context, tx audit.Tx, record ChallengeRecord) error
	// GetChallenge 读取挑战；不存在返回 found=false。
	GetChallenge(ctx context.Context, id string) (ChallengeRecord, bool, error)
	// IncreaseAttempts 原子递增尝试次数并返回新值。
	IncreaseAttempts(ctx context.Context, id string, now time.Time) (int, error)
	// ApproveTx 在审计事务内把挑战从 pending 条件迁移为 verified 并写入批准行。
	// 挑战已不是 pending、已过期或写入批准失败时返回 ok=false。
	ApproveTx(ctx context.Context, tx audit.Tx, challengeID string, now time.Time, approval ApprovalRecord) (bool, error)
	// GetApprovalByTokenDigest 按令牌摘要读取批准。
	GetApprovalByTokenDigest(ctx context.Context, digest []byte) (ApprovalRecord, bool, error)
	// ConsumeApprovalTx 在审计事务内一次性消费批准；已消费/过期返回 ok=false。
	ConsumeApprovalTx(ctx context.Context, tx audit.Tx, approvalID string, now time.Time) (bool, error)
	// InsertNotification 记录一次告知结果（非关键路径，失败不回滚业务操作）。
	InsertNotification(ctx context.Context, record NotificationRecord) error
	// ListNotifications 按用户读取最近的告知记录（最多 limit 条）。
	ListNotifications(ctx context.Context, userID string, limit int) ([]NotificationRecord, error)
	// VerifiedEmail 返回用户最近一个已验证邮箱；没有时返回 found=false。
	VerifiedEmail(ctx context.Context, userID string) (string, bool, error)
	// Username 返回用户显示用户名。
	Username(ctx context.Context, userID string) (string, bool, error)
	// IsRoot 报告用户是否为真实 root 账户。
	IsRoot(ctx context.Context, userID string) (bool, error)
}
