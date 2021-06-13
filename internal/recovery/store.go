package recovery

import (
	"context"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// AttemptStatus 是一次恢复尝试的持久化状态。
type AttemptStatus string

const (
	// AttemptPendingBinding 表示代码已消费、等待/进行新安全方式绑定。
	AttemptPendingBinding AttemptStatus = "pending_binding"
	// AttemptCompleted 表示新因素已验证、恢复完成并进入强制重新登录。
	AttemptCompleted AttemptStatus = "completed"
	// AttemptCancelled 表示用户主动取消恢复（旧因素保持不变）。
	AttemptCancelled AttemptStatus = "cancelled"
	// AttemptExpired 表示恢复尝试超过短时有效期。
	AttemptExpired AttemptStatus = "expired"
	// AttemptFailed 表示验证失败次数用尽或流程故障，尝试作废。
	AttemptFailed AttemptStatus = "failed"
)

// Valid 报告尝试状态是否已定义。
func (s AttemptStatus) Valid() bool {
	switch s {
	case AttemptPendingBinding, AttemptCompleted, AttemptCancelled, AttemptExpired, AttemptFailed:
		return true
	default:
		return false
	}
}

// GroupStatus 是恢复代码组状态。
type GroupStatus string

const (
	// GroupActive 是当前可用组（同一用户最多一个）。
	GroupActive GroupStatus = "active"
	// GroupSuperseded 表示被重新生成覆盖，整组代码失效。
	GroupSuperseded GroupStatus = "superseded"
	// GroupExhausted 表示组内代码已全部使用。
	GroupExhausted GroupStatus = "exhausted"
	// GroupRevoked 表示组被受控撤销。
	GroupRevoked GroupStatus = "revoked"
)

// UserState 是恢复流程需要的账户状态快照。
type UserState struct {
	Status          account.Status
	IsRoot          bool
	SecurityVersion int64
}

// Group 是恢复代码组元数据（不含任何代码或摘要）。
type Group struct {
	ID         string
	UserID     string
	Generation int64
	Status     GroupStatus
	CodeCount  int
	CreatedAt  time.Time
}

// CodeRecord 是恢复代码的持久化记录；Digest 是 HMAC 验证摘要，不含明文。
type CodeRecord struct {
	ID        string
	GroupID   string
	UserID    string
	Digest    []byte
	KeyID     string
	UsedAt    time.Time
	CreatedAt time.Time
}

// Attempt 是一次恢复尝试的持久化快照（不含恢复代码或会话秘密）。
type Attempt struct {
	ID               string
	UserID           string
	GroupID          string
	CodeID           string
	Status           AttemptStatus
	SessionID        string
	PlannedMethod    FactorMethod
	PlannedBindingID string
	FactorMethod     FactorMethod
	FactorRef        string
	Attempts         int
	MaxAttempts      int
	ExpiresAt        time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
	FinishedAt       time.Time
}

// Store 是恢复流程持久化契约，由 internal/recovery/sqlite 提供 SQLite 实现。
//
// 实现约束：
//   - 所有 *Tx 方法必须使用调用方给出的 audit.Tx，与成功审计在同一事务提交；
//     失败整体回滚，不得返回成功。
//   - ConsumeCodeTx 必须使用条件更新（used_at_ms IS NULL）从 NULL 置为非空，
//     并发重复使用同一代码只有一方返回 true。
//   - 状态迁移使用条件更新（匹配当前状态与未过期），并发完成/取消只有一方成功。
//   - 不返回恢复代码明文；Digest 只用于服务内部常量时间比较。
type Store interface {
	// UserState 读取账户状态（active/root/安全版本）。
	UserState(ctx context.Context, userID string) (UserState, bool, error)
	// Username 读取账户显示用户名（用于安全告知，不含敏感数据）。
	Username(ctx context.Context, userID string) (string, bool, error)
	// VerifiedEmail 返回用户最近一个已验证邮箱；只用于安全告知。
	VerifiedEmail(ctx context.Context, userID string) (string, bool, error)
	// ActiveGroup 返回用户当前 active 代码组；没有时 found=false。
	ActiveGroup(ctx context.Context, userID string) (Group, bool, error)
	// Group 按 ID 读取代码组。
	Group(ctx context.Context, groupID string) (Group, bool, error)
	// ListUnusedCodes 返回用户当前 active 组内未使用代码记录（最多一组的条数）。
	ListUnusedCodes(ctx context.Context, userID string) ([]CodeRecord, error)
	// CountUnusedCodesTx 在审计事务内统计组内未使用代码数量。
	CountUnusedCodesTx(ctx context.Context, tx audit.Tx, groupID string) (int, error)
	// InsertGroupTx 在审计事务内插入代码组（唯一约束拒绝重复/并发冲突）。
	InsertGroupTx(ctx context.Context, tx audit.Tx, group Group) error
	// InsertCodesTx 在审计事务内批量插入代码记录。
	InsertCodesTx(ctx context.Context, tx audit.Tx, codes []CodeRecord) error
	// InvalidateGroupTx 条件把 active/exhausted 组迁移为指定终态；返回是否成功。
	InvalidateGroupTx(ctx context.Context, tx audit.Tx, groupID string, status GroupStatus, now time.Time) (bool, error)
	// ConsumeCodeTx 原子消费代码：只有从未使用才置为已使用；返回是否赢家。
	ConsumeCodeTx(ctx context.Context, tx audit.Tx, codeID string, now time.Time) (bool, error)
	// CreateAttemptTx 在审计事务内创建待绑定尝试（同一用户唯一 pending）。
	CreateAttemptTx(ctx context.Context, tx audit.Tx, attempt Attempt) error
	// GetAttempt 按 ID 读取尝试。
	GetAttempt(ctx context.Context, attemptID string) (Attempt, bool, error)
	// GetAttemptBySession 按受限恢复会话 ID 读取尝试。
	GetAttemptBySession(ctx context.Context, sessionID string) (Attempt, bool, error)
	// BindSessionTx 条件把恢复会话 ID 绑定到待绑定且未过期的尝试（只允许一次）。
	BindSessionTx(ctx context.Context, tx audit.Tx, attemptID, sessionID string, now time.Time) (bool, error)
	// PlanRebindTx 条件记录本次尝试计划绑定的新因素方法与绑定 ID（待绑定且未过期）。
	PlanRebindTx(ctx context.Context, tx audit.Tx, attemptID string, method FactorMethod, bindingID string, now time.Time) (bool, error)
	// RecordRebindFailureTx 条件递增验证失败次数；达到上限时同事务迁移 failed。
	// 返回最新失败次数、是否已用尽与是否成功迁移。
	RecordRebindFailureTx(ctx context.Context, tx audit.Tx, attemptID string, maxAttempts int, now time.Time) (int, bool, bool, error)
	// CompleteAttemptTx 条件迁移 completed 并写入新因素证明字段。
	CompleteAttemptTx(ctx context.Context, tx audit.Tx, attemptID string, proof FactorProof, now time.Time) (bool, error)
	// CancelAttemptTx 条件迁移 cancelled。
	CancelAttemptTx(ctx context.Context, tx audit.Tx, attemptID string, now time.Time) (bool, error)
	// ExpireAttemptTx 条件迁移 expired（惰性过期）。
	ExpireAttemptTx(ctx context.Context, tx audit.Tx, attemptID string, now time.Time) (bool, error)
	// IncrementSecurityVersionTx 在同一事务内递增账户安全版本并返回新值。
	IncrementSecurityVersionTx(ctx context.Context, tx audit.Tx, userID string, now time.Time) (int64, error)
}
