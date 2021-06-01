package onboarding

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

const (
	// PurposeInvitationAccept 是邀请接受一次性令牌的固定用途。
	PurposeInvitationAccept = "invitation.accept"
	// DefaultInvitationTTL 是邀请未显式配置时的默认有效期。
	DefaultInvitationTTL = 24 * time.Hour
	// MinInvitationTTL/MaxInvitationTTL 是邀请有效期范围（上限与 credential.MaxTTL 一致）。
	MinInvitationTTL = 5 * time.Minute
	MaxInvitationTTL = 24 * time.Hour
	// DefaultMaxUses/MinMaxUses/MaxMaxUses 是邀请可使用次数范围。
	DefaultMaxUses = 1
	MinMaxUses     = 1
	MaxMaxUses     = 50
	// MaxInvitationRoles 是单次邀请允许的默认角色数上限。
	MaxInvitationRoles = 10
	// DefaultListLimit/MaxListLimit 是邀请与审核列表分页范围。
	DefaultListLimit = 20
	MaxListLimit     = 100
)

// InvitationStatus 是邀请生命周期状态。
type InvitationStatus string

const (
	InvitationPending   InvitationStatus = "pending"
	InvitationAccepted  InvitationStatus = "accepted"
	InvitationCancelled InvitationStatus = "cancelled"
	InvitationExpired   InvitationStatus = "expired"
)

// Valid 报告邀请状态是否为已定义值。
func (s InvitationStatus) Valid() bool {
	switch s {
	case InvitationPending, InvitationAccepted, InvitationCancelled, InvitationExpired:
		return true
	}
	return false
}

// TargetKind 是邀请目标类型。
type TargetKind string

const (
	TargetEmail TargetKind = "email"
	TargetUser  TargetKind = "user"
)

// NotifyState 是通知投递结果状态（只记录结果类别，不含邮件正文或令牌）。
type NotifyState string

const (
	NotifyPending NotifyState = "pending"
	NotifySent    NotifyState = "sent"
	NotifyFailed  NotifyState = "failed"
)

// Valid 报告通知状态是否合法。
func (s NotifyState) Valid() bool {
	return s == NotifyPending || s == NotifySent || s == NotifyFailed
}

// ReviewStatus 是注册审核状态。
type ReviewStatus string

const (
	ReviewPending  ReviewStatus = "pending"
	ReviewApproved ReviewStatus = "approved"
	ReviewRejected ReviewStatus = "rejected"
)

// Role 是邀请/审核允许分配的默认角色（角色 ID 与应用/系统作用域绑定）。
type Role struct {
	RoleID  string
	ScopeID string
}

// 领域错误哨兵。调用方用 errors.Is 判断，并可用 CodeOf 映射到根包错误码。
var (
	ErrOptionsInvalid             = errors.New("入驻服务选项无效")
	ErrInvalidRequest             = errors.New("入驻请求无效")
	ErrAccessDenied               = errors.New("未获准执行该操作")
	ErrManagementAuthRequired     = errors.New("管理操作需要强认证")
	ErrInvitationNotFound         = errors.New("邀请不存在或已失效")
	ErrInvitationExpired          = errors.New("邀请已过期")
	ErrInvitationCancelled        = errors.New("邀请已取消")
	ErrInvitationExhausted        = errors.New("邀请使用次数已用尽")
	ErrInvitationNotAcceptable    = errors.New("邀请当前不可接受")
	ErrInvitationIdentityMismatch = errors.New("受邀身份不匹配")
	ErrInvitationConflict         = errors.New("邀请已被接受或状态冲突")
	ErrReviewNotFound             = errors.New("待审核账户不存在")
	ErrReviewStateConflict        = errors.New("审核状态已变化")
	ErrSelfApproval               = errors.New("申请人不能批准自己的注册")
	ErrWeakPassword               = errors.New("密码强度不足")
	ErrStoreUnavailable           = errors.New("入驻数据存储暂时不可用")
	ErrAuditUnavailable           = errors.New("关键操作未能可靠记录")
	ErrMailUnavailable            = errors.New("通知邮件发送不可用")
)

// ErrorCode 是本包对根包错误码注册表的投影（只复用既有码）。
type ErrorCode string

const (
	CodeReqInvalid         ErrorCode = "REQ_INVALID"
	CodeAccessDenied       ErrorCode = "ACCESS_DENIED"
	CodeChallengeInvalid   ErrorCode = "CHALLENGE_INVALID"
	CodeConflict           ErrorCode = "CONFLICT"
	CodeReauthRequired     ErrorCode = "REAUTH_REQUIRED"
	CodeDBUnavailable      ErrorCode = "DB_UNAVAILABLE"
	CodeAuditWriteFailed   ErrorCode = "AUDIT_WRITE_FAILED"
	CodeMailDeliveryFailed ErrorCode = "MAIL_DELIVERY_FAILED"
	CodeInternalError      ErrorCode = "INTERNAL_ERROR"
)

// CodeOf 把入驻领域错误映射为根包已登记错误码；未识别错误按内部错误处理。
func CodeOf(err error) ErrorCode {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrWeakPassword):
		return CodeReqInvalid
	case errors.Is(err, ErrInvitationNotFound), errors.Is(err, ErrInvitationExpired),
		errors.Is(err, ErrInvitationCancelled), errors.Is(err, ErrInvitationExhausted),
		errors.Is(err, ErrReviewNotFound):
		return CodeChallengeInvalid
	case errors.Is(err, ErrInvitationConflict), errors.Is(err, ErrReviewStateConflict):
		return CodeConflict
	case errors.Is(err, ErrAccessDenied), errors.Is(err, ErrInvitationIdentityMismatch),
		errors.Is(err, ErrInvitationNotAcceptable), errors.Is(err, ErrSelfApproval):
		return CodeAccessDenied
	case errors.Is(err, ErrManagementAuthRequired):
		return CodeReauthRequired
	case errors.Is(err, ErrMailUnavailable):
		return CodeMailDeliveryFailed
	case errors.Is(err, ErrStoreUnavailable):
		return CodeDBUnavailable
	case errors.Is(err, ErrAuditUnavailable):
		return CodeAuditWriteFailed
	case errors.Is(err, ErrOptionsInvalid):
		return CodeInternalError
	default:
		return CodeInternalError
	}
}

// Caller 是可信调用身份；邀请者/审批者只能由可信边界构造，不能由请求参数自称。
type Caller struct {
	actor     audit.Actor
	requestID string
}

// UserCaller 构造已认证普通用户调用者。
func UserCaller(userID string) (Caller, error) {
	actor := audit.Actor{Type: audit.ActorUser, ID: userID}
	if err := actor.Validate(); err != nil {
		return Caller{}, fmt.Errorf("%w: 用户标识无效", ErrInvalidRequest)
	}
	return Caller{actor: actor}, nil
}

// SystemCaller 构造系统组件调用者。
func SystemCaller(componentID string) (Caller, error) {
	actor := audit.Actor{Type: audit.ActorSystem, ID: componentID}
	if err := actor.Validate(); err != nil {
		return Caller{}, fmt.Errorf("%w: 系统组件标识无效", ErrInvalidRequest)
	}
	return Caller{actor: actor}, nil
}

// LocalAdminCaller 构造本地受信管理员调用者。
func LocalAdminCaller(operatorID string) (Caller, error) {
	actor := audit.Actor{Type: audit.ActorLocalAdmin, ID: operatorID}
	if err := actor.Validate(); err != nil {
		return Caller{}, fmt.Errorf("%w: 本地操作者标识无效", ErrInvalidRequest)
	}
	return Caller{actor: actor}, nil
}

// Actor 返回调用者审计身份副本。
func (c Caller) Actor() audit.Actor { return c.actor }

// IsUser/IsSystem 报告调用者类别。
func (c Caller) IsUser() bool   { return c.actor.Type == audit.ActorUser }
func (c Caller) IsSystem() bool { return c.actor.Type == audit.ActorSystem }

// WithRequestID 返回带请求编号的副本。
func (c Caller) WithRequestID(requestID string) (Caller, error) {
	if err := account.ValidateRequestID(requestID); err != nil {
		return Caller{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	c.requestID = requestID
	return c, nil
}

// AppActive 报告应用是否 active（appID 为空表示系统范围，恒为 true）。
func appActive(appID string, status string) bool {
	return appID == "" || status == "active"
}

// validRole 校验角色 ID/作用域形状。
func validRole(role Role) bool {
	id := strings.TrimSpace(role.RoleID)
	scope := strings.TrimSpace(role.ScopeID)
	return id != "" && len(id) <= 64 && scope != "" && len(scope) <= 64
}
