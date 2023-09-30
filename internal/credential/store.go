package credential

import (
	"context"
	"database/sql"
	"time"
)

// Record 是存储层的一条一次性凭证记录。VerifierHash 是摘要（高熵令牌的
// SHA-256 或低熵验证码的受密钥保护 HMAC-SHA256），不是明文凭证。
type Record struct {
	// ID 是签发时生成的稳定不透明标识（otc_ + 十六进制随机串）。
	ID string
	// Purpose 是用途绑定。
	Purpose string
	// Target 是接收方/目标对象标识，对应表列 subject_id。
	Target string
	// AppID 是可选应用绑定；空字符串表示系统范围（表列 NULL）。
	AppID string
	// VerifierHash 是 32 字节验证摘要。
	VerifierHash []byte
	// KeyID 记录低熵验证码摘要使用的主密钥编号；空字符串表示高熵令牌摘要，
	// 不依赖密钥环。
	KeyID string
	// ContextJSON 是不含秘密的诊断元数据 JSON。
	ContextJSON string
	// Attempts 是已消耗的失败尝试次数。
	Attempts int
	// MaxAttempts 是允许的失败尝试上限。
	MaxAttempts int
	// CreatedAt 是签发时间（UTC）。
	CreatedAt time.Time
	// ExpiresAt 是过期时间（UTC，严格大于 CreatedAt）。
	ExpiresAt time.Time
	// ConsumedAt 非空表示已成功消费。
	ConsumedAt *time.Time
	// RevokedAt 非空表示已被取消或替换。
	RevokedAt *time.Time
}

// ConsumeCondition 是条件消费的参数：只有仍活动、未过期、未达尝试上限且绑定
// 信息一致的记录才会被置为已消费。条件更新是防止验证与消费之间重放窗口的
// 关键，存储实现必须在一条语句中完成判断与更新。
type ConsumeCondition struct {
	ID      string
	Purpose string
	Target  string
	AppID   string
	Now     time.Time
}

// RevokeCondition 是条件撤销的参数。
type RevokeCondition struct {
	ID      string
	Purpose string
	Target  string
	AppID   string
	Now     time.Time
}

// FailedAttemptResult 汇总一次失败尝试登记后的状态；Remaining 是剩余尝试次数，
// Active 表示记录仍处于可继续验证的状态。它只用于内部诊断，不影响“验证失败”
// 这一对外结果。
type FailedAttemptResult struct {
	Remaining int
	Active    bool
}

// Store 是一次性凭证的持久化契约，由 internal/credential/sqlite 提供生产
// SQLite 实现，测试可以使用替身。
//
// 实现约定：
//   - 所有方法必须传播 context；存储不可用时返回安全的错误（不得包含 SQL、
//     路径、凭证明文或摘要原文）。
//   - Insert 在 verifier_hash 冲突时返回唯一性错误，不得静默覆盖。
//   - ReplaceActiveAndInsert 必须在同一事务内撤销同作用域活动凭证并插入新记录，
//     中途失败时整体回滚。
//   - LoadByID 找不到记录时返回 (Record{}, false, nil)，而不是错误。
//   - Consume/Revoke 必须用一条带条件的 UPDATE 原子判断并更新；条件不满足时
//     返回 false，绝不能把失败当成成功。
//   - RecordFailedAttempt 只对仍活动、未过期且 attempts < max_attempts 的记录
//     增加一次尝试；结果只用于诊断。
//   - DeleteExpired 删除 expires_at_ms <= cutoff 的记录并返回删除数量。
type Store interface {
	Insert(ctx context.Context, record Record) error
	ReplaceActiveAndInsert(ctx context.Context, record Record, now time.Time) error
	LoadByID(ctx context.Context, id string) (Record, bool, error)
	Consume(ctx context.Context, condition ConsumeCondition) (bool, error)
	RecordFailedAttempt(ctx context.Context, id string, now time.Time) (FailedAttemptResult, error)
	Revoke(ctx context.Context, condition RevokeCondition) (bool, error)
	DeleteExpired(ctx context.Context, cutoff time.Time) (int64, error)
}

// Transaction 是调用方提供的数据库事务视图，与 internal/audit.Tx 结构兼容（后者
// 直接满足本接口）。凭证服务不拥有该事务的生命周期，也不在事务内开启子事务。
type Transaction interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// TransactionStore 是 Store 的可选事务扩展，用于把“凭证条件消费/撤销”与调用方
// 其他领域的写入放进同一提交边界（步骤 205 找回改密）。它不在 Store 中强制，
// 以保持既有存储替身兼容；服务在需要事务内操作时做运行期断言，缺失能力一律
// fail-closed，不会退化为独立事务或“先校验后消费”的非原子路径。
//
// 实现约定与 Store 对应方法一致：找不到记录返回 (Record{}, false, nil)；
// ConsumeTx/RevokeTx 必须用一条带条件的 UPDATE 原子判断并更新，条件不满足返回
// false；任何错误都不得被当作成功。
type TransactionStore interface {
	LoadByIDTx(ctx context.Context, tx Transaction, id string) (Record, bool, error)
	ConsumeTx(ctx context.Context, tx Transaction, condition ConsumeCondition) (bool, error)
	RevokeTx(ctx context.Context, tx Transaction, condition RevokeCondition) (bool, error)
}
