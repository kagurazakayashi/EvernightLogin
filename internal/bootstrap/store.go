package bootstrap

import (
	"context"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// Record 是 root_initializations 单例记录的只读快照。它不包含凭证明文、摘要或
// 密码材料，只引用最近一次签发的一次性配置凭证 ID。
type Record struct {
	// RootUserID 是唯一 root 账户的稳定 ID。
	RootUserID string
	// State 是受限初始化状态（持久化值）。
	State State
	// SetupCredentialID 是最近一次签发的配置凭证 ID；空字符串表示已被清理或
	// 从未签发（正常初始化后不会为空）。
	SetupCredentialID string
	// StartedBy 是创建初始化记录的本地受控操作者标识。
	StartedBy string
	// CreatedAt/UpdatedAt 是毫秒精度 UTC 时间。
	CreatedAt time.Time
	UpdatedAt time.Time
	// VerifiedAt 非空表示配置凭证已兑换。
	VerifiedAt *time.Time
	// ReadyAt 非空表示正式密码/强认证已配置（后续步骤）。
	ReadyAt *time.Time
}

// RootAccount 是 root 账户的只读快照，用于状态诊断与保护路径确认。它不是普通
// 用户查询接口，不包含密码/会话字段（本步也没有这些字段）。
type RootAccount struct {
	// UserID 是 root 稳定 ID。
	UserID string
	// Username 是 root 显示用户名（固定为 RootUsername）。
	Username string
	// Status 是账户全局状态；root 初始化后为 active，但这不是登录能力。
	Status account.Status
	// SecurityVersion 是安全版本，供未来会话/令牌失效与 root 保护使用。
	SecurityVersion int64
	// CreatedAt/UpdatedAt 是账户时间。
	CreatedAt time.Time
	UpdatedAt time.Time
}

// SetupVerifiedChange 是「一次性配置凭证已兑换」的条件状态更新。
type SetupVerifiedChange struct {
	// RootUserID 是 root 账户 ID。
	RootUserID string
	// CredentialID 是本次成功消费的凭证 ID。
	CredentialID string
	// Now 是状态更新时间。
	Now time.Time
}

// CredentialReissueChange 是「重新签发一次性配置凭证」的条件状态更新。
type CredentialReissueChange struct {
	// RootUserID 是 root 账户 ID。
	RootUserID string
	// PreviousCredentialID 是调用方读取到的当前凭证 ID，用于乐观并发；并发重签
	// 或兑换后条件更新失败，不会覆盖新状态。
	PreviousCredentialID string
	// NewCredentialID 是新签发的凭证 ID。
	NewCredentialID string
	// Now 是状态更新时间。
	Now time.Time
}

// Store 是首次初始化的持久化契约，由 internal/bootstrap/sqlite 提供生产 SQLite
// 实现，测试可以使用受控替身（替身只用于故障注入，不是生产旁路）。
//
// 实现约定：
//   - 所有方法必须传播 context；存储不可用时返回 ErrStoreUnavailable，错误文本
//     不得包含 SQL、路径、凭证明文或摘要。
//   - GetInitialization 找不到记录时返回 (Record{}, false, nil)。
//   - GetRootAccount 找不到 root 时返回 (RootAccount{}, false, nil)。
//   - GetSetupCredentialStatus 找不到凭证行时返回 Found=false 的状态，不返回错误
//     （过期清理删除行属于正常情况）；不返回 verifier_hash 或任何秘密材料。
//   - Create 必须在调用方审计事务中完成「条件插入 root + 条件插入初始化记录」：
//     root 或初始化记录已存在时返回 ErrAlreadyInitialized，root 保留用户名被非
//     root 账户占用时返回 ErrRootUsernameTaken；任一步失败整体回滚，不得留下
//     半个 root。
//   - MarkSetupVerified/UpdateSetupCredential 必须用一条条件 UPDATE 原子判断并
//     更新；状态或凭证 ID 已被并发修改时返回 ErrSetupStateConflict，绝不能把
//     失败当成功。
type Store interface {
	GetInitialization(ctx context.Context) (Record, bool, error)
	GetRootAccount(ctx context.Context) (RootAccount, bool, error)
	GetSetupCredentialStatus(ctx context.Context, credentialID string) (SetupCredentialStatus, error)
	Create(ctx context.Context, tx audit.Tx, root account.User, record Record) error
	MarkSetupVerified(ctx context.Context, tx audit.Tx, change SetupVerifiedChange) error
	UpdateSetupCredential(ctx context.Context, tx audit.Tx, change CredentialReissueChange) error
}
