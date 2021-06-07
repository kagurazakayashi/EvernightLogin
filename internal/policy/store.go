package policy

import (
	"context"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// OverrideRecord 是持久化的覆盖行或应用声明行。它只保存与默认值不同的可配置
// 字段；基础权限/root 专属/审计要求不在本表，避免被策略覆盖。
type OverrideRecord struct {
	ScopeID     string
	OperationID string
	Policy      Policy
	// SourceKind 是 "override" 或 "application"。
	SourceKind  SourceKind
	Name        string
	Description string
	RowVersion  int64
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// ScopeInfo 是作用域快照。
type ScopeInfo struct {
	// ID 是作用域标识（"system" 或应用 ID）。
	ID string
	// Application 表示这是应用作用域。
	Application bool
}

// Store 是敏感策略持久化契约，由 internal/policy/sqlite 实现。所有写方法必须在
// 调用方的审计事务内执行，并通过作用域版本做乐观并发：expectedVersion 不匹配时
// 返回 ok=false 且不产生任何修改。
type Store interface {
	// GetScope 读取作用域是否存在及其类型。
	GetScope(ctx context.Context, scopeID string) (ScopeInfo, bool, error)
	// GetVersion 读取作用域策略版本；没有变更记录时为 0。
	GetVersion(ctx context.Context, scopeID string) (int64, error)
	// GetOverrides 读取作用域内的全部覆盖/声明行。
	GetOverrides(ctx context.Context, scopeID string) ([]OverrideRecord, error)
	// GetUserRoot 读取调用者是否为真实 root 账户。
	GetUserRoot(ctx context.Context, userID string) (exists bool, isRoot bool, err error)
	// SaveTx 在审计事务内保存/更新一行并递增作用域版本。版本不匹配返回 ok=false。
	SaveTx(ctx context.Context, tx audit.Tx, scopeID string, record OverrideRecord,
		expectedVersion int64, now time.Time) (newVersion int64, ok bool, err error)
	// DeleteTx 在审计事务内删除覆盖行并递增作用域版本。operationIDs 为空且
	// allOverrides=true 时删除该作用域全部 override 行（保留应用声明）。
	// 没有匹配行时返回 removed=0 且不递增版本。
	DeleteTx(ctx context.Context, tx audit.Tx, scopeID string, operationIDs []string,
		allOverrides bool, expectedVersion int64, now time.Time) (newVersion int64, removed int, ok bool, err error)
}
