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
	ID            string
	UserID        string
	AppID         string
	Kind          Kind
	Reason        Reason
	RequiredSteps []authn.Step
	// AuthMethods 是登录时真实完成的认证方法稳定标识，用于 OIDC amr/acr。
	AuthMethods       []authn.Method
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
	// RememberMe 表示签发时使用了更长的记住我绝对到期（仅展示/排障，不参与
	// 续期判断）。
	RememberMe bool
	// ClientUserAgent/ClientAddress 是展示用客户端描述：UserAgent 由客户端自称、
	// 可伪造；Address 来自可信边界。两者都不是授权依据。
	ClientUserAgent string
	ClientAddress   string
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
	// ValidFrom/ValidUntil 是全局账户有效期 UTC 半开区间；nil 表示该端不限制。
	ValidFrom  *time.Time
	ValidUntil *time.Time
}

// AvailableAt 报告账户在 now 是否允许身份生效。到期是计算出的不可用原因，
// 不改写 users.status；root 忽略普通期限约束；手动禁用/待删除仍拒绝。
func (s UserState) AvailableAt(now time.Time) bool {
	if s.Status != account.StatusActive {
		return false
	}
	if s.IsRoot {
		return true
	}
	now = now.UTC()
	if s.ValidFrom != nil && now.Before(s.ValidFrom.UTC()) {
		return false
	}
	if s.ValidUntil != nil && !now.Before(s.ValidUntil.UTC()) {
		return false
	}
	return true
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

// RevokeUserCondition 撤销某账户全部活动会话，可按应用范围与保留会话过滤。
type RevokeUserCondition struct {
	UserID string
	Now    time.Time
	Reason string
	// AppID 非空时只撤销绑定该应用的会话（应用范围管理员强制下线使用）。
	AppID string
	// ExceptSessionID 非空时保留该会话不撤销（“退出其他设备”使用）。
	ExceptSessionID string
}

// RevokeOldestCondition 保留最近活动的若干会话，撤销其余活动会话。用于“最大在线
// 数”策略在登录事务内的自动淘汰；Keep 为保留数量（0 表示全部撤销）。
type RevokeOldestCondition struct {
	UserID string
	Now    time.Time
	Keep   int
	Reason string
}

// UserSessionQuery 是设备列表查询条件。只返回未撤销且未到期的活动会话。
type UserSessionQuery struct {
	UserID   string
	AppID    string
	Now      time.Time
	Offset   int
	PageSize int
}

// UserSessionPage 是设备列表查询结果：Records 是当前页活动会话，Total 是满足
// 条件的活动会话总数。
type UserSessionPage struct {
	Records []Record
	Total   int64
}

// Store 是会话持久化契约，由 internal/session/sqlite 提供生产实现。
//
// 实现约束：
//   - Insert/Revoke/RevokeUser/RevokeOldest 必须使用调用方给出的 audit.Tx，以便
//     与成功审计在同一事务一致提交；失败时整体回滚，不得返回成功。
//   - Load 只按不可预测的会话 ID 读取，不提供按秘密、用户名或邮箱读取的接口。
//   - Touch 使用条件 UPDATE：只有未撤销且未到期时才更新最后活动与空闲到期；
//     并发续期是安全的（多次续期都成功、以最后一次为准），与撤销竞争时以撤销
//     优先（撤销之后条件更新影响 0 行）。
//   - ListUserSessions 只返回未撤销且未到期的活动会话摘要记录，按最近活动倒序
//     分页；它不得返回会话秘密、CSRF 令牌或摘要原文之外的展示所需字段（摘要在
//     Record 中仅供服务内部校验，不得进入对外响应）。
//   - RevokeOldest 在调用方事务内以原子条件更新实现“保留最近 N 条、撤销其余”，
//     供并发登录上限与单设备策略使用；实现不得拆成“先查后写”的两条独立语句。
//   - LoadUserState/LoadMembership 是校验时的实时读取，不得返回过期缓存。
//   - 任何失败都返回可被 errors.Is(err, ErrStoreUnavailable) 识别的安全错误，
//     不得把原始驱动错误文本暴露给调用方。
type Store interface {
	Insert(ctx context.Context, tx audit.Tx, record Record) error
	Load(ctx context.Context, id string) (Record, bool, error)
	Touch(ctx context.Context, condition TouchCondition) (Record, bool, error)
	Revoke(ctx context.Context, tx audit.Tx, condition RevokeCondition) (bool, error)
	RevokeUser(ctx context.Context, tx audit.Tx, condition RevokeUserCondition) (int64, error)
	RevokeOldest(ctx context.Context, tx audit.Tx, condition RevokeOldestCondition) (int64, error)
	// CountActiveSessions 在调用方事务内统计账户当前活动会话数，供登录时对数量
	// 约束做插入后的复核；它必须与 RevokeOldest/RevokeUser/Insert 处于同一事务。
	CountActiveSessions(ctx context.Context, tx audit.Tx, userID string, now time.Time) (int64, error)
	ListUserSessions(ctx context.Context, query UserSessionQuery) (UserSessionPage, error)
	LoadUserState(ctx context.Context, userID string) (UserState, bool, error)
	LoadMembership(ctx context.Context, appID, userID string) (MembershipState, bool, error)
	DeleteExpired(ctx context.Context, cutoff time.Time) (int64, error)
}
