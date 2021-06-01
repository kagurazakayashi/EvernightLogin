package onboarding

import (
	"context"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
)

// InvitationRecord 是创建邀请的事务内记录。
type InvitationRecord struct {
	ID            string
	InviterUserID string
	TargetKind    TargetKind
	TargetEmail   string
	TargetUserID  string
	AppID         string
	Roles         []Role
	MaxUses       int
	ExpiresAt     time.Time
	Now           time.Time
	RequestID     string
}

// CancelParams 是取消邀请的事务内参数。
type CancelParams struct {
	InvitationID string
	Reason       string
	Actor        audit.Actor
	Now          time.Time
	RequestID    string
}

// UserState 是账户最小状态快照。
type UserState struct {
	UserID string
	Status account.Status
	IsRoot bool
}

// AcceptParams 是接受邀请的事务内参数。NewUser 非空时在同一事务内创建账户。
type AcceptParams struct {
	InvitationID string
	UserID       string
	NewUser      *NewUserRecord
	Now          time.Time
	RequestID    string
}

// NewUserRecord 是由邀请创建账户的已校验参数（密码已是 Argon2id PHC 哈希）。
type NewUserRecord struct {
	UserID             string
	Username           string
	UsernameNormalized string
	Nickname           string
	Language           string
	Timezone           string
	PasswordHash       string
	Email              string
	EmailNormalized    string
	VerifiedAt         time.Time
}

// ReviewDecision 是审核决定的事务内参数。
type ReviewDecision struct {
	UserID    string
	Approve   bool
	Reason    string
	AppID     string
	Roles     []Role
	Actor     audit.Actor
	Now       time.Time
	RequestID string
}

// Store 是入驻领域（邀请 + 注册审核）的持久化契约，由 internal/onboarding/sqlite 实现。
//
// 约定：事务方法使用调用方 audit.Tx 与成功审计一致提交，失败整体回滚；找不到记录
// 返回 (zero,false,nil)；错误文本不得包含令牌、邮件正文或 SQL。
type Store interface {
	// CreateInvitation 在审计事务内写邀请与允许角色；角色不存在/停用/作用域不符
	// 或应用不存在时返回 ErrInvalidRequest。
	CreateInvitation(ctx context.Context, tx audit.Tx, record InvitationRecord) error
	// GetInvitation 读取邀请快照（含角色）。
	GetInvitation(ctx context.Context, id string) (Invitation, bool, error)
	// ListInvitations 分页列出邀请；inviterUserID 非空时只列该发起者。
	ListInvitations(ctx context.Context, inviterUserID string, request ListRequest) (ListResult, error)
	// LoadInvitationTx 在审计事务内读取邀请（含角色）。
	LoadInvitationTx(ctx context.Context, tx audit.Tx, id string) (Invitation, bool, error)
	// CancelInvitation 条件把 pending 邀请改为 cancelled；状态不符返回 false。
	CancelInvitation(ctx context.Context, tx audit.Tx, params CancelParams) (bool, error)
	// UserStateTx 在审计事务内读取账户状态。
	UserStateTx(ctx context.Context, tx audit.Tx, userID string) (UserState, bool, error)
	// UserState 在无事务路径读取账户状态（创建邀请前快速校验）。
	UserState(ctx context.Context, userID string) (UserState, bool, error)
	// NotificationEmail 返回账户可用于通知的邮箱（优先已验证），没有返回 false。
	NotificationEmail(ctx context.Context, userID string) (string, bool, error)
	// VerifiedEmailTx 报告账户是否拥有该规范化已验证邮箱。
	VerifiedEmailTx(ctx context.Context, tx audit.Tx, userID, normalizedEmail string) (bool, error)
	// AppStatusTx 在审计事务内读取应用状态。
	AppStatusTx(ctx context.Context, tx audit.Tx, appID string) (string, bool, error)
	// RolePermissionsTx 在审计事务内读取角色权限引用（停用权限不返回），用于
	// delegation.Guard.CheckAssignment 的当前权限复核。
	RolePermissionsTx(ctx context.Context, tx audit.Tx, roles []Role) (map[string][]delegation.PermissionRef, error)
	// AcceptInvitationTx 在审计事务内原子扣减使用次数、写接受记录、可选创建账户、
	// 写应用成员与角色；任一失败整体回滚。重复接受返回 ErrInvitationConflict。
	AcceptInvitationTx(ctx context.Context, tx audit.Tx, params AcceptParams) error
	// MarkInvitationNotify 记录邀请通知结果（非主事务，失败不回滚邀请）。
	MarkInvitationNotify(ctx context.Context, id string, state NotifyState, errorCode string, now time.Time) error

	// ListPendingReviews 分页列出 users.status='pending' 的账户及审核状态。
	ListPendingReviews(ctx context.Context, query ReviewQuery) (ReviewQueryResult, error)
	// GetReviewUser 读取单个待审核账户/审核记录。
	GetReviewUser(ctx context.Context, userID string) (ReviewUser, bool, error)
	// LoadReviewUserTx 在审计事务内读取待审核账户/审核记录。
	LoadReviewUserTx(ctx context.Context, tx audit.Tx, userID string) (ReviewUser, bool, error)
	// DecideReviewTx 在审计事务内条件更新账户状态并写审核决定与可选成员/角色；
	// 账户已不是 pending 时返回 false。
	DecideReviewTx(ctx context.Context, tx audit.Tx, decision ReviewDecision) (bool, error)
	// MarkReviewNotify 记录审核通知结果（非主事务，失败不回滚审核）。
	MarkReviewNotify(ctx context.Context, userID string, state NotifyState, errorCode string, now time.Time) error
}

// VerifiedEmailReader 是接受前快速身份复核所需的无事务读取（由 SQLite 实现额外提供）。
type VerifiedEmailReader interface {
	// VerifiedEmail 报告账户是否拥有该规范化已验证邮箱。
	VerifiedEmail(ctx context.Context, userID, normalizedEmail string) (bool, error)
}

// RoleAssignableReader 是接受/审批前角色可分配性校验（由 SQLite 实现提供）。
type RoleAssignableReader interface {
	// RoleAssignableTx 校验角色存在、启用且作用域匹配；不满足返回 ErrInvalidRequest。
	RoleAssignableTx(ctx context.Context, tx audit.Tx, roles []Role) error
	// MemberEffectivePermissionRefsTx 返回目标用户在该范围当前有效权限（直接角色与
	// 用户组角色、启用角色/权限、非 root_only），用于接受/审批前的可转授复核。
	MemberEffectivePermissionRefsTx(ctx context.Context, tx audit.Tx, scopeID, userID string) ([]delegation.PermissionRef, error)
}
