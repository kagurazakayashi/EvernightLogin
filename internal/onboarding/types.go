package onboarding

import (
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// CreateRequest 是创建邀请的参数。邮箱与目标用户二选一；角色只能来自可信配置。
type CreateRequest struct {
	// TargetEmail 是邮箱邀请目标（未规范化也行，服务层统一规范化）。
	TargetEmail string
	// TargetUserID 是已有用户邀请目标（稳定用户 ID）。
	TargetUserID string
	// AppID 是适用应用；空表示系统范围。非空时角色作用域必须等于该应用。
	AppID string
	// Roles 是允许分配给接受者的默认角色。
	Roles []Role
	// MaxUses 是最大可使用次数；0 使用默认 1。
	MaxUses int
	// TTL 是邀请有效期；0 使用 Options.InvitationTTL。
	TTL time.Duration
	// RequestID 可选，写入审计用于关联查询。
	RequestID string
}

// Invitation 是邀请只读快照（不含令牌或邮件正文）。
type Invitation struct {
	ID            string
	InviterUserID string
	TargetKind    TargetKind
	TargetEmail   string
	TargetUserID  string
	AppID         string
	Status        InvitationStatus
	MaxUses       int
	UsedCount     int
	ExpiresAt     time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
	CancelledAt   time.Time
	CancelReason  string
	Roles         []Role
	NotifyState   NotifyState
	NotifyError   string
	NotifiedAt    time.Time
}

// CreateResult 是邀请创建结果。
type CreateResult struct {
	Invitation Invitation
	// TokenSent 表示邀请邮件是否交给发送方；false 时 ErrorCode 说明失败类别。
	TokenSent bool
	ErrorCode string
}

// CancelRequest 是取消邀请参数（仅发起者或受信系统/本地管理员可取消）。
type CancelRequest struct {
	InvitationID string
	Reason       string
	RequestID    string
}

// CancelResult 是取消结果。
type CancelResult struct {
	Invitation Invitation
	Cancelled  bool
}

// ListRequest 是邀请列表参数；用户身份只能看自己发起的邀请，系统/本地管理员可看全部。
type ListRequest struct {
	Status InvitationStatus
	Limit  int
	Offset int
}

// ListResult 是邀请列表结果。
type ListResult struct {
	Invitations []Invitation
	HasMore     bool
}

// NewUserRequest 是由邀请创建新账户的字段白名单；不接受 is_root/角色/已验证状态等字段。
type NewUserRequest struct {
	Username string
	Password string
	Nickname string
	Language string
	Timezone string
}

// AcceptRequest 是接受邀请参数。Token 是邀请邮件中的一次性令牌；NewUser 非空表示
// 由该邀请创建新账户，否则按已登录用户（Caller）身份接受。
type AcceptRequest struct {
	InvitationID string
	// CredentialID 是邀请邮件链接中的一次性凭证 ID（与令牌一起构成完整证明）。
	CredentialID string
	Token        string
	NewUser      *NewUserRequest
	RequestID    string
}

// AcceptResult 是接受邀请结果。
type AcceptResult struct {
	InvitationID string
	UserID       string
	NewUser      bool
	AppID        string
	Roles        []Role
	AcceptedAt   time.Time
}

// ReviewRequest 是管理员批准/拒绝注册的参数。AppID/Roles 可选，批准时在同一事务
// 内加入应用成员并分配角色。
type ReviewRequest struct {
	UserID    string
	Reason    string
	AppID     string
	Roles     []Role
	RequestID string
}

// ReviewQuery 是待审核账户列表参数。
type ReviewQuery struct {
	Limit  int
	Offset int
}

// ReviewUser 是待审核账户与审核决定快照（不含密码或隐私资料）。
type ReviewUser struct {
	UserID        string
	Username      string
	Status        account.Status
	ReviewStatus  ReviewStatus
	Reason        string
	DecidedByType audit.ActorKind
	DecidedByID   string
	DecidedAt     time.Time
	CreatedAt     time.Time
	NotifyState   NotifyState
	NotifyError   string
	NotifiedAt    time.Time
}

// ReviewResult 是审核结果。
type ReviewResult struct {
	Review ReviewUser
	// Notified 表示通知邮件是否交给发送方；false 时 ErrorCode 说明失败类别。
	Notified  bool
	ErrorCode string
}

// ReviewQueryResult 是待审核列表结果。
type ReviewQueryResult struct {
	Users   []ReviewUser
	HasMore bool
}
