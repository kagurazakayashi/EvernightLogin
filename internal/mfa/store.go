package mfa

import (
	"context"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// Store 是 MFA 持久化契约，由 internal/mfa/sqlite 实现。所有状态迁移必须使用条件
// 更新：挑战只能从 pending 迁移一次，重发代数必须匹配，保证并发/重放下只有一方成功。
type Store interface {
	// GetFactors 读取用户全部因素（活动与停用）。
	GetFactors(ctx context.Context, userID string) ([]Factor, error)
	// CountActiveFactors 统计某类型活动因素数量。
	CountActiveFactors(ctx context.Context, userID string, factorType FactorType) (int, error)
	// InsertFactorTx 在审计事务内插入活动因素；唯一约束冲突返回错误。
	InsertFactorTx(ctx context.Context, tx audit.Tx, factor Factor) error
	// RemoveFactorTx 在审计事务内停用并删除因素行；不存在返回 false。
	RemoveFactorTx(ctx context.Context, tx audit.Tx, userID string, factorType FactorType) (bool, error)
	// CreateChallengeTx 在审计事务内创建挑战。
	CreateChallengeTx(ctx context.Context, tx audit.Tx, challenge Challenge) error
	// GetChallenge 按 ID 读取挑战。
	GetChallenge(ctx context.Context, id string) (Challenge, bool, error)
	// UpdateChallengeStateTx 条件迁移挑战状态：必须匹配 pending 起始状态、尝试摘要、
	// 代数与未过期；成功返回 true。
	UpdateChallengeStateTx(ctx context.Context, tx audit.Tx, challengeID string, attemptDigest []byte,
		generation int, from, to ChallengeState, now time.Time) (bool, error)
	// BindRestrictedSessionTx 条件把第一步签发的受限会话 ID 绑定到挑战（必须尚未
	// 绑定、状态 pending、尝试摘要与代数匹配）；防止挑战与会话错配。
	BindRestrictedSessionTx(ctx context.Context, tx audit.Tx, challengeID string, attemptDigest []byte,
		generation int, sessionID string, now time.Time) (bool, error)
	// RecordAttemptTx 条件递增挑战自身的验证尝试计数；返回新计数与是否成功。
	RecordAttemptTx(ctx context.Context, tx audit.Tx, challengeID string, attemptDigest []byte,
		generation int, now time.Time) (int, bool, error)
	// RotateChallengeTx 条件替换验证码凭证并递增重发代数；返回新代数与是否成功。
	RotateChallengeTx(ctx context.Context, tx audit.Tx, challengeID string, attemptDigest []byte,
		generation int, newCredentialID string, expiresAt, now time.Time) (int, bool, error)
	// VerifiedEmail 返回用户最近一个已验证邮箱。
	VerifiedEmail(ctx context.Context, userID string) (string, bool, error)
	// Username 返回用户显示用户名。
	Username(ctx context.Context, userID string) (string, bool, error)
}

// Challenge 时间字段由服务统一截断到 UTC 毫秒；存储不返回明文验证码或尝试令牌。
var _ = time.Time{}
