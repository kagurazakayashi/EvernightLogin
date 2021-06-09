// Package mfa 实现两步验证（MFA）公共状态机与邮件第二步验证。
//
// 范围与安全不变量：
//   - 第一步密码认证由 internal/authn 完成；只有密码正确且账户不受“必须强认证”
//     限制时才允许以邮件第二步继续。高权限账户（root 与持有高敏感系统权限的账户）
//     密码正确后 authn 返回 pending_second_factor/受限状态，邮件因素**不能**满足
//     其强认证要求，本包 fail-closed 返回 MFA_REQUIRED，不签发任何会话，账户保持
//     受限配置状态。
//   - 普通账户启用邮件因素后，第一步成功只能拿到 internal/session 的**受限会话**；
//     第二步验证成功后再用同一受限会话秘密轮换为完整普通会话（复用会话服务，不另
//     建会话体系）。
//   - 挑战统一绑定用户、当前登录尝试（客户端持有的一次性尝试令牌摘要）、用途、
//     因素类型、验证码凭证 ID 与重发代数；状态 pending 只能条件迁移一次，并发消费
//     与重放只有一方成功。
//   - 验证码复用 internal/credential 的受密钥保护低熵验证码：数据库只存 HMAC 摘要、
//     有尝试上限、有效期与原子消费；重发使用 ReplaceActive 使旧验证码失效。明文
//     验证码只出现在发给已验证邮箱的邮件正文中，绝不写入日志、审计、错误或队列。
//   - 邮件只发到用户已验证邮箱（user_emails.verified_at_ms 非空）；没有已验证邮箱
//     时拒绝，不降级到未验证地址。发送失败 fail-closed（不签发受限会话完成第二步），
//     并写失败审计。
//   - 因素新增必须先向已验证邮箱发送验证码并验证成功（证明渠道控制权）；移除需检查
//     强制策略：被 Policy 要求 MFA 时不能移除最后一个可用因素。当前只实现 email
//     因素；TOTP/Passkey/FIDO2 后续按同一 FactorType/Store 接口接入，本包不预置
//     空实现或假装已支持。
//   - 本包不做页面、不暴露 HTTP 路由；会话签发通过注入的 SessionIssuer 完成，宿主
//     装配时传入 *internal/session.Service。
package mfa

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/credential"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// 领域错误哨兵。错误文本不包含验证码、尝试令牌或会话秘密。
var (
	ErrOptionsInvalid       = errors.New("MFA 服务选项无效")
	ErrInvalidRequest       = errors.New("MFA 请求无效")
	ErrAccessDenied         = errors.New("未获准执行该 MFA 操作")
	ErrStrongAuthRequired   = errors.New("高权限账户需要强认证，邮件因素不可满足")
	ErrSecondFactorRequired = errors.New("需要完成第二因素验证")
	ErrChallengeInvalid     = errors.New("MFA 挑战无效")
	ErrChallengeExpired     = errors.New("MFA 挑战已过期")
	ErrCodeInvalid          = errors.New("验证码无效或已失效")
	ErrAttemptsExceeded     = errors.New("验证码尝试次数已用尽")
	ErrRateLimited          = errors.New("MFA 请求过于频繁")
	ErrNoVerifiedEmail      = errors.New("账户没有已验证邮箱，无法使用邮件因素")
	ErrFactorExists         = errors.New("该类型 MFA 因素已启用")
	ErrFactorNotFound       = errors.New("未找到可用的 MFA 因素")
	ErrFactorRequired       = errors.New("策略要求 MFA，不能移除最后一个可用因素")
	ErrMailFailed           = errors.New("验证码邮件发送失败")
	ErrSessionUnavailable   = errors.New("会话服务暂时不可用")
	ErrPolicyUnavailable    = errors.New("MFA 策略检查暂时不可用")
	ErrStoreUnavailable     = errors.New("MFA 存储暂时不可用")
	ErrAuditUnavailable     = errors.New("关键操作未能可靠记录")
)

// ErrorCode 是 MFA 领域对根包错误码注册表的投影（只复用既有码）。
type ErrorCode string

const (
	CodeReqInvalid         ErrorCode = "REQ_INVALID"
	CodeMFARequired        ErrorCode = "MFA_REQUIRED"
	CodeAccessDenied       ErrorCode = "ACCESS_DENIED"
	CodeChallengeInvalid   ErrorCode = "CHALLENGE_INVALID"
	CodeRateLimited        ErrorCode = "RATE_LIMITED"
	CodeConflict           ErrorCode = "CONFLICT"
	CodeAuthzUnavailable   ErrorCode = "AUTHZ_UNAVAILABLE"
	CodeDBUnavailable      ErrorCode = "DB_UNAVAILABLE"
	CodeAuditWriteFailed   ErrorCode = "AUDIT_WRITE_FAILED"
	CodeMailDeliveryFailed ErrorCode = "MAIL_DELIVERY_FAILED"
	CodeInternalError      ErrorCode = "INTERNAL_ERROR"
)

// CodeOf 把 MFA 领域错误映射为根包已登记错误码（不新增错误码）。
func CodeOf(err error) ErrorCode {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrFactorNotFound),
		errors.Is(err, ErrFactorExists):
		return CodeReqInvalid
	case errors.Is(err, ErrAccessDenied):
		return CodeAccessDenied
	case errors.Is(err, ErrStrongAuthRequired), errors.Is(err, ErrSecondFactorRequired),
		errors.Is(err, ErrNoVerifiedEmail):
		return CodeMFARequired
	case errors.Is(err, ErrChallengeInvalid), errors.Is(err, ErrChallengeExpired),
		errors.Is(err, ErrCodeInvalid), errors.Is(err, ErrAttemptsExceeded):
		return CodeChallengeInvalid
	case errors.Is(err, ErrRateLimited):
		return CodeRateLimited
	case errors.Is(err, ErrFactorRequired):
		return CodeConflict
	case errors.Is(err, ErrPolicyUnavailable):
		return CodeAuthzUnavailable
	case errors.Is(err, ErrStoreUnavailable), errors.Is(err, ErrSessionUnavailable):
		return CodeDBUnavailable
	case errors.Is(err, ErrAuditUnavailable):
		return CodeAuditWriteFailed
	case errors.Is(err, ErrMailFailed):
		return CodeMailDeliveryFailed
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

// FactorType 是 MFA 因素稳定标识；当前只实现 email，后续 TOTP/Passkey 复用同一
// 接口与状态机。
type FactorType string

const (
	// FactorEmail 是邮件验证码第二步因素。
	FactorEmail FactorType = "email"
)

// Purpose 是挑战用途。
type Purpose string

const (
	// PurposeLogin 是登录第二步验证。
	PurposeLogin Purpose = "login"
	// PurposeFactorEnroll 是新增因素时的渠道控制权验证。
	PurposeFactorEnroll Purpose = "factor_enroll"
)

// ChallengeState 是统一 MFA 状态机。
type ChallengeState string

const (
	StatePending   ChallengeState = "pending"
	StateVerified  ChallengeState = "verified"
	StateFailed    ChallengeState = "failed"
	StateExpired   ChallengeState = "expired"
	StateCancelled ChallengeState = "cancelled"
)

// Factor 是已启用的 MFA 因素快照。
type Factor struct {
	ID        string
	UserID    string
	Type      FactorType
	State     string
	CreatedAt time.Time
}

// Challenge 是持久化的 MFA 挑战。
type Challenge struct {
	ID            string
	UserID        string
	FactorType    FactorType
	Purpose       Purpose
	AttemptSHA256 []byte
	CredentialID  string
	Generation    int
	State         ChallengeState
	Username      string
	// AppID/RememberMe/Client 是第一步签发受限会话时使用的环境，第二步必须用同值
	// 签发完整会话，避免应用作用域登录在第二步后变成全局会话。
	AppID           string
	RememberMe      bool
	ClientUserAgent string
	ClientAddress   string
	// RestrictedSessionID 是第一步签发并绑定到本挑战的受限会话 ID；Verify 必须
	// 使用同一会话完成，其他受限会话（如待改密）不能完成本挑战。
	RestrictedSessionID string
	Attempts            int
	MaxAttempts         int
	SecurityVersion     int64
	CompletedAt         time.Time
	ExpiresAt           time.Time
	CreatedAt           time.Time
	UpdatedAt           time.Time
	VerifiedAt          time.Time
}

// Policy 是宿主的 MFA 强制策略；实现应默认拒绝/保守。nil 表示没有外部强制策略，
// 因素管理完全由本人决定（仅已验证渠道与审计约束）。
type Policy interface {
	// MFARequired 报告账户是否被策略强制要求 MFA（例如高权限账户强制策略）。
	MFARequired(ctx context.Context, userID string) (bool, error)
}

// PolicyFunc 是 Policy 的函数适配器。
type PolicyFunc func(ctx context.Context, userID string) (bool, error)

// MFARequired 实现 Policy。
func (f PolicyFunc) MFARequired(ctx context.Context, userID string) (bool, error) {
	if f == nil {
		return false, nil
	}
	return f(ctx, userID)
}

// SessionIssuer 是会话签发契约；生产实现为 *internal/session.Service（其 Login 与
// Validate 方法签名与下面一致）。本包不复制会话逻辑。
type SessionIssuer interface {
	Login(ctx context.Context, request session.LoginRequest) (session.IssuedSession, error)
	Validate(ctx context.Context, secret string) (session.Session, error)
}

// AuditRecorder 是安全审计写入契约；实现必须 fail-closed。
type AuditRecorder interface {
	Record(ctx context.Context, event audit.Event) error
	RecordFailure(ctx context.Context, event audit.Event) error
	ExecuteCritical(ctx context.Context, request audit.CriticalRequest, change audit.Change) error
}

// 内部辅助：安全随机、摘要、规范化。

func newSecret(random io.Reader, size int) ([]byte, error) {
	buffer := make([]byte, size)
	if _, err := io.ReadFull(random, buffer); err != nil {
		return nil, fmt.Errorf("%w: 安全随机源不可用", ErrStoreUnavailable)
	}
	return buffer, nil
}

func secretDigest(value []byte) []byte {
	sum := sha256.Sum256(value)
	return sum[:]
}

func newID(random io.Reader, prefix string) (string, error) {
	buffer, err := newSecret(random, 16)
	if err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(buffer), nil
}

func newAttemptToken(random io.Reader) (string, []byte, error) {
	buffer, err := newSecret(random, 32)
	if err != nil {
		return "", nil, err
	}
	return hex.EncodeToString(buffer), secretDigest(buffer), nil
}

func hexAttemptToken(value string) ([]byte, error) {
	if len(value) != 64 {
		return nil, ErrChallengeInvalid
	}
	buffer := make([]byte, 32)
	for index := 0; index < 32; index++ {
		high, ok := hexNibble(value[index*2])
		if !ok {
			return nil, ErrChallengeInvalid
		}
		low, ok := hexNibble(value[index*2+1])
		if !ok {
			return nil, ErrChallengeInvalid
		}
		buffer[index] = high<<4 | low
	}
	// 数据库保存的是尝试令牌的摘要；客户端用十六进制令牌验证时同样计算摘要。
	return secretDigest(buffer), nil
}

func hexNibble(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	default:
		return 0, false
	}
}

func equalDigest(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	result := byte(0)
	for index := range left {
		result |= left[index] ^ right[index]
	}
	return result == 0
}

// maskAddress 把邮箱脱敏为可展示/可审计值。
func maskAddress(address string) string {
	at := strings.Index(address, "@")
	if at <= 0 || at == len(address)-1 {
		return "[REDACTED]"
	}
	return string(address[0]) + "***@" + address[at+1:]
}

// pendingSecondFactorResult 由可信密码认证结果构造“待第二因素”受限认证结果；它
// 只用于签发受限会话，绝不能被当作完整登录。
func pendingSecondFactorResult(base authn.AuthenticateResult) authn.AuthenticateResult {
	return authn.AuthenticateResult{
		UserID: base.UserID, Username: base.Username,
		Outcome:          authn.OutcomePendingSecondFactor,
		CompletedMethods: []authn.Method{authn.MethodPassword},
		CompletedAt:      base.CompletedAt,
		RequiredSteps:    []authn.Step{authn.StepSecondFactor},
		Restricted:       true,
		SecurityVersion:  base.SecurityVersion,
	}
}

// completeResult 在第二因素真实通过后构造完整认证结果（内部可信边界）。
func completeResult(challenge Challenge, completedAt time.Time) authn.AuthenticateResult {
	return authn.AuthenticateResult{
		UserID: challenge.UserID, Username: challenge.Username,
		Outcome:          authn.OutcomeComplete,
		CompletedMethods: []authn.Method{authn.MethodPassword, authn.MethodSecondFactor},
		CompletedAt:      completedAt,
		Restricted:       false,
		SecurityVersion:  challenge.SecurityVersion,
	}
}

// credential.VerifyRequest/Purpose 常量在本包集中定义，避免字符串漂移。
const (
	purposeLoginCode        = "mfa.email.login"
	purposeFactorEnrollCode = "mfa.email.enroll"
)

// VerifyRequest 是第二步验证请求。
type VerifyRequest struct {
	ChallengeID     string
	AttemptToken    string
	Code            string
	ExistingSession string
	RequestID       string
}

// VerifyResult 是第二因素通过后的完整会话与认证结果。
type VerifyResult struct {
	Session       session.IssuedSession
	Authenticated authn.AuthenticateResult
	ChallengeID   string
}

// 合同：credential 服务类型在接口中直接使用，避免再包一层不受控发送接口。
var _ = credential.KindCode

// MailSender 邮件发送接口别名（内部使用 mailer.Sender）。
type MailSender = mailer.Sender
