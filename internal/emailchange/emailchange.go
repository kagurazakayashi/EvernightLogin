// Package emailchange 实现已验证邮箱的受控变更：申请、验证新地址、切换生效（步骤 36）。
//
// 安全边界：
//   - 变更申请必须由已认证用户本人发起，并通过注入的 ReauthVerifier 证明近期身份验证；
//     未接线或验证失败一律拒绝（无可信身份时留给恢复流程，绝不能用新地址自证接管）。
//   - 申请绑定用户、旧已验证邮箱（首次添加时为空）与规范化新邮箱；新地址验证成功前
//     旧 user_emails 行与其 verified_at_ms 保持不变。
//   - 验证凭证是一次性高熵令牌（用途 email.change.verify、目标为请求 ID），由服务层
//     在审计事务内再次校验请求状态/到期/旧邮箱版本/新邮箱唯一性后消费并切换；任何失败
//     整体回滚，旧请求同时失效。
//   - 切换成功后按策略向旧已验证邮箱发送安全告知（不含令牌/校验链接），投递失败不回滚
//     已完成切换，只记录可追踪状态。
//   - 无旧邮箱时走首次添加流程；不解除或绕过 MFA，本包不签发会话、不注册 HTTP 路由。
package emailchange

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

const (
	// PurposeEmailChangeVerify 是邮箱变更验证令牌的固定用途。
	PurposeEmailChangeVerify = "email.change.verify"
	// DefaultTTL 是变更申请有效期默认值。
	DefaultTTL = 24 * time.Hour
	// MinTTL/MaxTTL 是申请有效期范围（与 credential.MaxTTL 一致）。
	MinTTL = 5 * time.Minute
	MaxTTL = 24 * time.Hour
)

// Status 是申请状态。
type Status string

const (
	StatusPending   Status = "pending"
	StatusCompleted Status = "completed"
	StatusCancelled Status = "cancelled"
	StatusExpired   Status = "expired"
)

// NotifyState 是通知结果状态；sent 表示已交给可靠投递（入队成功），不代表送达。
type NotifyState string

const (
	NotifyPending NotifyState = "pending"
	NotifySent    NotifyState = "sent"
	NotifyFailed  NotifyState = "failed"
	NotifySkipped NotifyState = "skipped"
)

// 领域错误哨兵。
var (
	ErrOptionsInvalid   = errors.New("邮箱变更服务选项无效")
	ErrInvalidRequest   = errors.New("邮箱变更请求无效")
	ErrAccessDenied     = errors.New("未获准变更邮箱")
	ErrReauthRequired   = errors.New("邮箱变更需要再次验证")
	ErrEmailInUse       = errors.New("新邮箱已被使用")
	ErrRequestNotFound  = errors.New("邮箱变更申请不存在或已失效")
	ErrRequestExpired   = errors.New("邮箱变更申请已过期")
	ErrRequestCancelled = errors.New("邮箱变更申请已取消")
	ErrStoreUnavailable = errors.New("邮箱变更存储暂时不可用")
	ErrAuditUnavailable = errors.New("关键操作未能可靠记录")
	ErrMailUnavailable  = errors.New("通知邮件发送不可用")
)

// ErrorCode 是本包对根包错误码注册表的投影（只复用既有码）。
type ErrorCode string

const (
	CodeReqInvalid         ErrorCode = "REQ_INVALID"
	CodeAccessDenied       ErrorCode = "ACCESS_DENIED"
	CodeConflict           ErrorCode = "CONFLICT"
	CodeReauthRequired     ErrorCode = "REAUTH_REQUIRED"
	CodeChallengeInvalid   ErrorCode = "CHALLENGE_INVALID"
	CodeDBUnavailable      ErrorCode = "DB_UNAVAILABLE"
	CodeAuditWriteFailed   ErrorCode = "AUDIT_WRITE_FAILED"
	CodeMailDeliveryFailed ErrorCode = "MAIL_DELIVERY_FAILED"
	CodeInternalError      ErrorCode = "INTERNAL_ERROR"
)

// CodeOf 把领域错误映射为根包已登记错误码。
func CodeOf(err error) ErrorCode {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrInvalidRequest):
		return CodeReqInvalid
	case errors.Is(err, ErrAccessDenied):
		return CodeAccessDenied
	case errors.Is(err, ErrEmailInUse):
		return CodeConflict
	case errors.Is(err, ErrReauthRequired):
		return CodeReauthRequired
	case errors.Is(err, ErrRequestNotFound), errors.Is(err, ErrRequestExpired),
		errors.Is(err, ErrRequestCancelled):
		return CodeChallengeInvalid
	case errors.Is(err, ErrMailUnavailable):
		return CodeMailDeliveryFailed
	case errors.Is(err, ErrStoreUnavailable):
		return CodeDBUnavailable
	case errors.Is(err, ErrAuditUnavailable):
		return CodeAuditWriteFailed
	default:
		return CodeInternalError
	}
}

// Caller 是可信调用身份；不能由请求参数自称。
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

// Actor 返回审计身份副本。
func (c Caller) Actor() audit.Actor { return c.actor }

// IsUser 报告是否为普通用户身份。
func (c Caller) IsUser() bool { return c.actor.Type == audit.ActorUser }

// WithRequestID 返回带请求编号的副本。
func (c Caller) WithRequestID(requestID string) (Caller, error) {
	if err := account.ValidateRequestID(requestID); err != nil {
		return Caller{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	c.requestID = requestID
	return c, nil
}

// EmailRecord 是用户当前已验证邮箱快照。
type EmailRecord struct {
	Email      string
	Normalized string
}

// Request 是邮箱变更申请快照（不含令牌或校验链接）。
type Request struct {
	ID                 string
	UserID             string
	OldEmail           string
	OldEmailNormalized string
	NewEmail           string
	NewEmailNormalized string
	Status             Status
	CredentialID       string
	CreatedAt          time.Time
	ExpiresAt          time.Time
	CompletedAt        time.Time
	CancelledAt        time.Time
	VerifyState        NotifyState
	VerifyError        string
	VerifyNotifiedAt   time.Time
	NotifyState        NotifyState
	NotifyError        string
	NotifiedAt         time.Time
}

// RequestResult 是申请结果；VerificationSent 表示验证邮件是否已交给发送方。
type RequestResult struct {
	Request          Request
	VerificationSent bool
	ErrorCode        string
}

// VerifyRequest 是提交新地址验证入口的参数。
type VerifyRequest struct {
	RequestID    string
	CredentialID string
	Token        string
	RequestIDLog string
}

// VerifyResult 是切换成功结果。
type VerifyResult struct {
	UserID     string
	Email      string
	SwitchedAt time.Time
	OldEmail   string
	Notified   bool
	ErrorCode  string
	// 事务失败补偿：旧令牌已被消费时，服务在同一 pending 申请上重新签发凭证并把
	// 新凭证 ID/令牌/入口地址返回给本次调用方，避免用户白烧链接。宿主应立即重新
	// 投递，且不得把令牌写入日志/审计/数据库明文。
	RetryCredentialID string
	RetryToken        string
	RetryURL          string
}

// CancelRequest 是取消申请参数（本人或受信系统）。
type CancelRequest struct {
	RequestID    string
	RequestIDLog string
}

// ReauthVerifier 是近期身份验证契约；返回 nil 表示验证通过。未注入时普通用户邮箱
// 变更一律拒绝（不默认免检）。
type ReauthVerifier interface {
	VerifyReauth(ctx context.Context, caller Caller, userID string) error
}

// ReauthVerifierFunc 是 ReauthVerifier 的函数适配器。
type ReauthVerifierFunc func(ctx context.Context, caller Caller, userID string) error

// VerifyReauth 实现 ReauthVerifier。
func (f ReauthVerifierFunc) VerifyReauth(ctx context.Context, caller Caller, userID string) error {
	if f == nil {
		return ErrReauthRequired
	}
	return f(ctx, caller, userID)
}

// MaskEmail 把邮箱脱敏为审计可用值（首字符 + 域名）。
func MaskEmail(email string) string {
	if email == "" {
		return ""
	}
	at := strings.LastIndexByte(email, '@')
	if at <= 0 || at == len(email)-1 {
		return "[REDACTED]"
	}
	return email[:1] + "***" + email[at:]
}
