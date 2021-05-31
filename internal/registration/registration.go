package registration

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// PurposeEmailVerify 是邮箱验证一次性凭证的固定用途。它与 internal/credential
// 的用途绑定共同保证验证入口不能被改用为其他流程。
const PurposeEmailVerify = "email.verify"

const (
	// DefaultVerificationTTL 是验证入口未显式配置时的默认有效期。
	DefaultVerificationTTL = 24 * time.Hour // MinVerificationTTL/MaxVerificationTTL 是验证入口有效期的允许范围，上限与
	// internal/credential.MaxTTL 一致。
	MinVerificationTTL = 5 * time.Minute
	MaxVerificationTTL = 24 * time.Hour
	// DefaultResendCooldown 是重新发送验证入口的默认冷却时间。
	DefaultResendCooldown = 5 * time.Minute
	// MinResendCooldown/MaxResendCooldown 是重发冷却的允许范围。
	MinResendCooldown = 30 * time.Second
	MaxResendCooldown = 24 * time.Hour
	// MaxRegisterJSONBytes 是注册 JSON 请求体的大小上限，防止解析超大输入。
	MaxRegisterJSONBytes = 8192
	// DefaultRoleScopeSystem 是默认角色策略当前唯一接受的作用域。应用角色需要走
	// internal/role 与 internal/delegation 的赋权校验，本步不支持作为默认角色。
	DefaultRoleScopeSystem = "system"
)

// 领域错误哨兵。调用方用 errors.Is 判断，并可用 CodeOf 映射到根包错误码。
var (
	// ErrOptionsInvalid 表示服务构造选项无效。
	ErrOptionsInvalid = errors.New("注册服务选项无效")
	// ErrRegistrationClosed 表示当前配置未开放自主注册。
	ErrRegistrationClosed = errors.New("自主注册未开放")
	// ErrInvalidRequest 表示注册/验证请求字段不合法。
	ErrInvalidRequest = errors.New("注册请求无效")
	// ErrWeakPassword 表示密码不符合当前密码策略。
	ErrWeakPassword = errors.New("密码强度不足")
	// ErrRegistrationConflict 表示用户名或邮箱已被占用。两种情况共用同一错误，
	// 避免调用方据此枚举已注册账户。
	ErrRegistrationConflict = errors.New("用户名或邮箱已被占用")
	// ErrUserNotFound 表示目标账户不存在。
	ErrUserNotFound = errors.New("用户不存在")
	// ErrEmailNotAvailable 表示账户没有待验证邮箱可用。
	ErrEmailNotAvailable = errors.New("账户没有可验证的邮箱")
	// ErrEmailAlreadyVerified 表示邮箱已经验证，不能再次验证或替换。
	ErrEmailAlreadyVerified = errors.New("邮箱已经验证")
	// ErrVerificationInvalid 表示验证入口无效、过期、已消费、已替换或绑定不匹配。
	// 所有原因共用同一对外错误，不暴露具体状态。
	ErrVerificationInvalid = errors.New("验证入口无效或已失效")
	// ErrResendTooSoon 表示验证入口重新发送过于频繁。
	ErrResendTooSoon = errors.New("验证入口发送过于频繁")
	// ErrMailUnavailable 表示验证邮件发送接口不可用或投递入队失败。
	ErrMailUnavailable = errors.New("验证邮件发送不可用")
	// ErrAccessDenied 表示调用身份无权执行该操作。
	ErrAccessDenied = errors.New("未获准执行该操作")
	// ErrStoreUnavailable 表示注册数据存储暂时不可用。
	ErrStoreUnavailable = errors.New("注册数据存储暂时不可用")
	// ErrAuditUnavailable 表示安全审计未能可靠写入，操作被拒绝。
	ErrAuditUnavailable = errors.New("关键操作未能可靠记录")
)

// ErrorCode 是本包对根包错误码注册表的投影。只使用已登记码，不新增公开码。
type ErrorCode string

const (
	// CodeReqInvalid 对应 REQ_INVALID。
	CodeReqInvalid ErrorCode = "REQ_INVALID"
	// CodeConflict 对应 CONFLICT，用于统一的注册占用冲突。
	CodeConflict ErrorCode = "CONFLICT"
	// CodeChallengeInvalid 对应 CHALLENGE_INVALID，用于验证入口失效。
	CodeChallengeInvalid ErrorCode = "CHALLENGE_INVALID"
	// CodeRateLimited 对应 RATE_LIMITED，用于重发冷却。
	CodeRateLimited ErrorCode = "RATE_LIMITED"
	// CodeAccessDenied 对应 ACCESS_DENIED。
	CodeAccessDenied ErrorCode = "ACCESS_DENIED"
	// CodeMailDeliveryFailed 对应 MAIL_DELIVERY_FAILED，用于验证邮件发送失败状态。
	CodeMailDeliveryFailed ErrorCode = "MAIL_DELIVERY_FAILED"
	// CodeAuthFailed 对应 AUTH_FAILED，用于注册关闭/不可用等拒绝。
	CodeAuthFailed ErrorCode = "AUTH_FAILED"
	// CodeDBUnavailable 对应 DB_UNAVAILABLE。
	CodeDBUnavailable ErrorCode = "DB_UNAVAILABLE"
	// CodeAuditWriteFailed 对应 AUDIT_WRITE_FAILED。
	CodeAuditWriteFailed ErrorCode = "AUDIT_WRITE_FAILED"
	// CodeInternalError 对应 INTERNAL_ERROR。
	CodeInternalError ErrorCode = "INTERNAL_ERROR"
)

// CodeOf 把注册领域错误映射为根包已登记错误码。未识别错误按内部错误处理，绝不
// 回显底层数据库或审计细节。
func CodeOf(err error) ErrorCode {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrWeakPassword):
		return CodeReqInvalid
	case errors.Is(err, ErrRegistrationConflict):
		return CodeConflict
	case errors.Is(err, ErrVerificationInvalid):
		return CodeChallengeInvalid
	case errors.Is(err, ErrResendTooSoon):
		return CodeRateLimited
	case errors.Is(err, ErrMailUnavailable):
		return CodeMailDeliveryFailed
	case errors.Is(err, ErrAccessDenied):
		return CodeAccessDenied
	case errors.Is(err, ErrRegistrationClosed):
		return CodeAuthFailed
	case errors.Is(err, ErrUserNotFound), errors.Is(err, ErrEmailNotAvailable),
		errors.Is(err, ErrEmailAlreadyVerified):
		return CodeChallengeInvalid
	case errors.Is(err, ErrOptionsInvalid):
		return CodeInternalError
	case errors.Is(err, ErrStoreUnavailable):
		return CodeDBUnavailable
	case errors.Is(err, ErrAuditUnavailable):
		return CodeAuditWriteFailed
	default:
		return CodeInternalError
	}
}

// Caller 是可信调用身份。注册入口本身是公开未认证端点；重新发送验证入口要求
// 已认证用户本人或受信系统组件，不能由普通请求参数自称。
type Caller struct {
	actor     audit.Actor
	requestID string
}

// SelfCaller 构造“用户本人”调用者。userID 必须是稳定用户 ID。
func SelfCaller(userID string) (Caller, error) {
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

// Actor 返回调用者审计身份副本。
func (c Caller) Actor() audit.Actor { return c.actor }

// WithRequestID 返回带请求编号的副本；请求编号会进入审计用于关联排查。
func (c Caller) WithRequestID(requestID string) (Caller, error) {
	if err := account.ValidateRequestID(requestID); err != nil {
		return Caller{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	c.requestID = requestID
	return c, nil
}

// RegisterRequest 是公开注册请求的字段白名单。它刻意不包含 status、is_root、
// security_version、system roles、app memberships、email_verified 等字段；这些
// 值只能由服务端可信策略决定。
type RegisterRequest struct {
	// Username 是显示用户名；规范化与保留名检查由 account.NormalizeUsername 负责。
	Username string `json:"username"`
	// Password 是明文密码，只用于本次哈希计算，不保存、不记录。
	Password string `json:"password"`
	// Email 是可选密码登录/恢复邮箱；空字符串表示不提供。
	Email string `json:"email"`
	// Nickname 是可选显示昵称。
	Nickname string `json:"nickname"`
	// Language 是可选 BCP 47 语言标签；空字符串使用服务端默认。
	Language string `json:"language"`
	// Timezone 是可选 IANA 时区名称；空字符串使用服务端默认。
	Timezone string `json:"timezone"`
	// RequestID 由传输层在可信边界填充，不接受客户端 JSON 字段。
	RequestID string `json:"-"`
}

// ParseRegisterJSON 严格解析注册 JSON：拒绝未知字段（例如客户端提交 is_root、
// roles、email_verified）与多余内容，并限制请求体大小。返回错误只描述格式问题，
// 不回显用户输入。
func ParseRegisterJSON(data []byte) (RegisterRequest, error) {
	if len(data) == 0 {
		return RegisterRequest{}, fmt.Errorf("%w: 请求体为空", ErrInvalidRequest)
	}
	if len(data) > MaxRegisterJSONBytes {
		return RegisterRequest{}, fmt.Errorf("%w: 注册请求超过 %d 字节", ErrInvalidRequest, MaxRegisterJSONBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var request RegisterRequest
	if err := decoder.Decode(&request); err != nil {
		return RegisterRequest{}, fmt.Errorf("%w: 注册请求包含未知字段或类型错误", ErrInvalidRequest)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return RegisterRequest{}, fmt.Errorf("%w: 注册请求只能包含一个 JSON 对象", ErrInvalidRequest)
	}
	return request, nil
}

// RegisterResult 是注册结果。它不包含密码、哈希、令牌或验证链接；邮箱验证状态由
// 独立字段明确表达，不会把“已发送验证邮件”表述为“邮箱已验证”。
type RegisterResult struct {
	// UserID 是新建账户的稳定 ID。
	UserID string
	// Username 是规范化后的显示用户名。
	Username string
	// Email 是保存的待验证邮箱显示值；未提供时为空。
	Email string
	// Status 是创建时的账户状态：默认 active，需要人工审核时为 pending。
	Status account.Status
	// CreatedAt 是创建时间（UTC）。
	CreatedAt time.Time
	// VerificationSent 表示本次是否成功把验证入口交给邮件发送方。
	VerificationSent bool
	// VerificationExpiresAt 是验证入口有效期；VerificationSent 为 false 时为零值。
	VerificationExpiresAt time.Time
	// VerificationErrorCode 是发送失败时的稳定错误码（例如 MAIL_DELIVERY_FAILED）；
	// 账户与待验证邮箱仍然创建成功，可稍后重新发送。
	VerificationErrorCode string
}

// SendVerificationRequest 是重新发送（或替换待验证地址后发送）邮箱验证入口的
// 请求。Email 为空表示沿用当前待验证邮箱；非空表示替换尚未验证的邮箱。
type SendVerificationRequest struct {
	// UserID 是目标账户稳定 ID。
	UserID string
	// Email 是可选的新待验证邮箱；已存在已验证邮箱时不允许替换（返回
	// ErrEmailAlreadyVerified），验证过的地址变更留给后续个人资料步骤。
	Email string
	// RequestID 可选，写入审计用于关联查询。
	RequestID string
}

// SendVerificationResult 是验证入口发送结果。Sent=false 时错误码说明邮件侧失败，
// 调用方应按 ResendAllowedAt 重试，而不是宣称邮箱已验证。
type SendVerificationResult struct {
	// UserID 是目标账户 ID。
	UserID string
	// Email 是本次绑定的待验证邮箱显示值。
	Email string
	// Sent 表示是否成功交给邮件发送方。
	Sent bool
	// ExpiresAt 是验证入口有效期；未签发成功时为零值。
	ExpiresAt time.Time
	// ResendAllowedAt 是下次允许重新发送的时间。
	ResendAllowedAt time.Time
	// ErrorCode 是发送失败时的稳定错误码。
	ErrorCode string
}

// VerifyEmailRequest 是提交验证入口的请求。UID/CredentialID/Token 通常来自邮件
// 链接；Token 是高熵一次性秘密，调用方不得写入日志、URL 之外的地方或错误信息。
type VerifyEmailRequest struct {
	// UserID 是链接中绑定的账户稳定 ID。
	UserID string
	// CredentialID 是一次性凭证 ID（otc_ 前缀）。
	CredentialID string
	// Token 是邮件中的一次性令牌明文；只用于本次验证与消费。
	Token string
	// RequestID 可选，写入审计用于关联查询。
	RequestID string
}

// VerifyEmailResult 是邮箱验证成功结果。
type VerifyEmailResult struct {
	// UserID 是账户 ID。
	UserID string
	// Email 是完成验证的邮箱显示值。
	Email string
	// VerifiedAt 是验证完成时间（UTC）。
	VerifiedAt time.Time
}
