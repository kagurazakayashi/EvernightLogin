package reauth

import (
	"context"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
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
	// SessionID 是步骤 255 直接管理挑战绑定的操作者会话 ID；空表示 0019 兼容的
	// “操作者即目标”旧挑战（不能用于直接管理证明）。
	SessionID string
	// IntentSealed 是步骤 255 密封的新值意图密文（internal/secrets AES-GCM）；
	// 空表示没有意图绑定。挑战表不保存意图明文。
	IntentSealed []byte
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
	// SessionID / IntentSealed 是步骤 255 从挑战复制的一次性证明绑定；消费时
	// 同一事务把 IntentSealed 清空，过期未消费的密文由有界清理擦除。
	SessionID    string
	IntentSealed []byte
}

// NotificationState 是安全告知结果状态（区分“未发送原因”，不能把未发送当成功）。
type NotificationState string

const (
	// NotificationSent 表示直接发送成功（送达由发送器确认）；队列路径不写该状态。
	NotificationSent NotificationState = "sent"
	// NotificationQueued 表示告知已入可靠投递队列（enqueue 成功），不代表已送达；
	// 真实送达/失败以 mailer 投递记录与任务终态为准（步骤 197）。
	NotificationQueued          NotificationState = "queued"
	NotificationFailed          NotificationState = "failed"
	NotificationNoVerifiedEmail NotificationState = "no_verified_email"
	NotificationRateLimited     NotificationState = "rate_limited"
	NotificationNotConfigured   NotificationState = "not_configured"
	NotificationSuppressed      NotificationState = "suppressed"
)

// NotificationRecord 是一条安全告知结果；收件地址只保存脱敏值。
//
// 可靠投递关联（步骤 210）：
//   - DeliveryID 是 mailer 投递记录 ID（mail_deliveries.id）；空表示没有关联投递
//     （历史记录、未配置/无邮箱等未入队状态、直接发送回退路径，或入队前失败）。
//   - DedupKey 是稳定业务去重键：同一业务事件同一结果的重复告知/重试/服务重启
//     复用同一键，既作为邮件入队幂等键，也让告知主记录幂等更新而不是重复插入。
//   - DeliveryState/DeliveryErrorCode/DeliveryUpdatedAt 是**读取时**从投递记录投影的
//     当前状态；它们不是本表快照，随 mailer 投递重试/重启恢复变化。DeliveryState
//     为空表示当前未关联到投递记录（不能当作成功）。mailer.DeliverySucceeded 只表示
//     发送后端已接受，不代表用户已读或最终送达。
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

	DeliveryID        string
	DedupKey          string
	DeliveryState     mailer.DeliveryState
	DeliveryErrorCode string
	DeliveryUpdatedAt time.Time
}

// SessionState 是证明消费事务内重读的最小会话状态（步骤 255 修复）。
//
// 只读取 commit-boundary 必需字段：归属用户、会话种类、签发时安全版本、撤销与
// 到期时间。它与 internal/session 的完整校验语义对齐（revoked/空闲/绝对到期 +
// users.security_version 一致性），但用**调用方事务连接**读取，避免在 SQLite 写事务
// 内另开连接导致互锁。这里不复制会话秘密/CSRF 等敏感数据，也不修改会话。
type SessionState struct {
	UserID            string
	Kind              string
	SecurityVersion   int64
	Revoked           bool
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
}

// UserAuthState 是证明消费事务内重读的最小账户状态（步骤 255 修复）。
type UserAuthState struct {
	Status          string
	SecurityVersion int64
	IsRoot          bool
	// ValidFrom/ValidUntil 是账户有效期的可空端点（半开区间）；nil 表示不限制。
	ValidFrom  *time.Time
	ValidUntil *time.Time
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
	// CancelChallenge 把 pending 挑战条件迁移为 cancelled；已过期/已确认/已取消时
	// 返回 ok=false（取消不是批准，不产生任何可执行能力）。
	CancelChallengeTx(ctx context.Context, tx audit.Tx, id string, now time.Time) (bool, error)
	// ApproveTx 在审计事务内把挑战从 pending 条件迁移为 verified 并写入批准行。
	// 挑战已不是 pending、已过期或写入批准失败时返回 ok=false。
	ApproveTx(ctx context.Context, tx audit.Tx, challengeID string, now time.Time, approval ApprovalRecord) (bool, error)
	// GetApprovalByTokenDigest 按令牌摘要读取批准。
	GetApprovalByTokenDigest(ctx context.Context, digest []byte) (ApprovalRecord, bool, error)
	// GetApprovalByTokenDigestTx 在调用方审计事务内按令牌摘要读取批准：供步骤 255
	// 的目标绑定证明在同一事务内完成绑定复核与条件消费。
	GetApprovalByTokenDigestTx(ctx context.Context, tx audit.Tx, digest []byte) (ApprovalRecord, bool, error)
	// ConsumeApprovalTx 在审计事务内一次性消费批准；已消费/过期返回 ok=false。
	// 实现必须同时把 intent_sealed 清空（已消费证明不再保留密封意图）。
	ConsumeApprovalTx(ctx context.Context, tx audit.Tx, approvalID string, now time.Time) (bool, error)
	// ClearExpiredIntents 有界擦除过期或已消费批准上的意图密文（只清密文，不改状态
	// 与审计）。返回清理行数；实现不得删除批准/挑战行本身。
	ClearExpiredIntents(ctx context.Context, now time.Time) error
	// GetSessionStateTx 在调用方审计事务内只读重读会话状态（步骤 255 修复）。
	GetSessionStateTx(ctx context.Context, tx audit.Tx, sessionID string) (SessionState, bool, error)
	// GetUserAuthStateTx 在调用方审计事务内只读重读账户状态与安全版本（步骤 255 修复）。
	GetUserAuthStateTx(ctx context.Context, tx audit.Tx, userID string) (UserAuthState, bool, error)
	// UpsertNotification 记录/更新一次告知结果（非关键路径，失败不回滚业务操作）。
	// 幂等语义：dedup_key 非空且已存在同键记录时更新该记录（状态/错误码/脱敏收件
	// 人，并在传入非空 delivery_id 时补写投递关联），否则插入新记录。dedup_key 为
	// 空（历史/直接发送回退路径）时按新记录插入。实现不得把已存在的 delivery_id
	// 清空，保证“关联回写失败后重试可恢复”不会丢失投递标识。
	UpsertNotification(ctx context.Context, record NotificationRecord) error
	// ListNotifications 按用户读取最近的告知记录（最多 limit 条），并为每条记录
	// 投影关联投递记录的当前状态（只读；不修改投递记录）。
	ListNotifications(ctx context.Context, userID string, limit int) ([]NotificationRecord, error)
	// ListNotificationsPage 按用户做 keyset 分页读取（步骤 266）：排序固定
	// created_at_ms DESC, id DESC；afterCreatedAt/afterID 为上一页最后一条的位置
	// （零值表示第一页）；返回最多 limit 条（服务层以 limit+1 探测 has_more），并
	// 为每条记录投影关联投递记录的当前状态。只读，不修改投递状态。
	ListNotificationsPage(ctx context.Context, userID string, afterCreatedAt time.Time,
		afterID string, limit int) ([]NotificationRecord, error)
	// VerifiedEmail 返回用户最近一个已验证邮箱；没有时返回 found=false。
	VerifiedEmail(ctx context.Context, userID string) (string, bool, error)
	// Username 返回用户显示用户名。
	Username(ctx context.Context, userID string) (string, bool, error)
	// IsRoot 报告用户是否为真实 root 账户。
	IsRoot(ctx context.Context, userID string) (bool, error)
}
