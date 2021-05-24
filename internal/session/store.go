package session

import (
	"context"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
)

// Record 是会话的持久化快照，供存储实现与测试使用。
//
// SecretDigest/CSRFDigest 是 HMAC-SHA256 验证摘要，不是秘密原文；KeyID 标识
// 派生摘要所用密钥环密钥，密钥轮换后旧会话仍按原 key_id 验证，直到被撤销或
// 到期。RequiredSteps 与 Session.RequiredSteps 一致。
type Record struct {
	ID                string
	UserID            string
	AppID             string
	Kind              Kind
	Reason            Reason
	RequiredSteps     []authn.Step
	SecurityVersion   int64
	SecretDigest      []byte
	CSRFDigest        []byte
	KeyID             string
	StrongAuthAt      time.Time
	RowVersion        int64
	CreatedAt         time.Time
	LastSeenAt        time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	RevokedAt         time.Time
	RevokeReason      string
	RequestID         string
}

// UserState 是校验时重读的账户状态快照。
type UserState struct {
	// Status 是全局账户状态；只有 active 允许会话使用。
	Status account.Status
	// SecurityVersion 是当前安全版本；低于或高于会话快照都视为失效（版本只增
	// 不减，不相等意味着期间发生过安全相关变更）。
	SecurityVersion int64
	// IsRoot 表示受保护 root 账户；root 只能持有受限会话（强认证未完成）。
	IsRoot bool
}

// MembershipState 是校验时重读的应用与成员状态快照。
type MembershipState struct {
	// ApplicationActive 表示应用当前启用。
	ApplicationActive bool
	// MemberActive 表示账户是该应用的启用成员。
	MemberActive bool
}

// TouchCondition 是空闲续期的条件参数。续期只在会话仍活动时生效，且空闲到期
// 不得越过绝对到期。
type TouchCondition struct {
	ID            string
	Now           time.Time
	IdleExpiresAt time.Time
}

// RevokeCondition 是单条会话撤销的条件参数。
type RevokeCondition struct {
	ID     string
	Now    time.Time
	Reason string
}

// RevokeUserCondition 撤销某账户全部活动会话。
type RevokeUserCondition struct {
	UserID string
	Now    time.Time
	Reason string
}

// Store 是会话持久化契约，由 internal/session/sqlite 提供生产实现。
//
// 实现约束：
//   - Insert/Revoke/RevokeUser 必须使用调用方给出的 audit.Tx，以便与成功审计
//     在同一事务一致提交；失败时整体回滚，不得返回成功。
//   - Load 只按不可预测的会话 ID 读取，不提供按秘密、用户名或邮箱读取的接口。
//   - Touch 使用条件 UPDATE：只有未撤销且未到期时才更新最后活动与空闲到期；
//     并发续期是安全的（多次续期都成功、以最后一次为准），与撤销竞争时以撤销
//     优先（撤销之后条件更新影响 0 行）。
//   - LoadUserState/LoadMembership 是校验时的实时读取，不得返回过期缓存。
//   - 任何失败都返回可被 errors.Is(err, ErrStoreUnavailable) 识别的安全错误，
//     不得把原始驱动错误文本暴露给调用方。
type Store interface {
	Insert(ctx context.Context, tx audit.Tx, record Record) error
	Load(ctx context.Context, id string) (Record, bool, error)
	Touch(ctx context.Context, condition TouchCondition) (Record, bool, error)
	Revoke(ctx context.Context, tx audit.Tx, condition RevokeCondition) (bool, error)
	RevokeUser(ctx context.Context, tx audit.Tx, condition RevokeUserCondition) (int64, error)
	LoadUserState(ctx context.Context, userID string) (UserState, bool, error)
	LoadMembership(ctx context.Context, appID, userID string) (MembershipState, bool, error)
	DeleteExpired(ctx context.Context, cutoff time.Time) (int64, error)
}
