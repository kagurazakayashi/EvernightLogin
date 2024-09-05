package reauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
)

// 领域错误哨兵。错误文本不包含密码、令牌、参数值或本机路径。
var (
	ErrOptionsInvalid       = errors.New("再次认证服务选项无效")
	ErrInvalidRequest       = errors.New("再次认证请求无效")
	ErrAccessDenied         = errors.New("未获准执行该敏感操作")
	ErrAuthenticationFailed = errors.New("再次认证失败")
	ErrReauthRequired       = errors.New("需要完成近期身份验证")
	ErrConfirmationRequired = errors.New("敏感操作需要显式确认")
	ErrMFARequired          = errors.New("需要强认证但当前环境不可满足")
	ErrChallengeInvalid     = errors.New("认证挑战无效或已失效")
	ErrChallengeExpired     = errors.New("认证挑战已过期")
	ErrAttemptsExceeded     = errors.New("认证挑战尝试次数已用尽")
	ErrApprovalInvalid      = errors.New("操作批准无效")
	ErrApprovalExpired      = errors.New("操作批准已过期")
	ErrApprovalConsumed     = errors.New("操作批准已被使用")
	ErrRateLimited          = errors.New("请求过于频繁")
	ErrPolicyUnavailable    = errors.New("敏感策略服务暂时不可用")
	ErrStoreUnavailable     = errors.New("再次认证存储暂时不可用")
	ErrAuditUnavailable     = errors.New("关键操作未能可靠记录")
	ErrNotificationFailed   = errors.New("安全告知发送失败")
)

// ErrorCode 是再次认证领域对根包错误码注册表的投影（只复用既有码）。
type ErrorCode string

const (
	CodeReqInvalid         ErrorCode = "REQ_INVALID"
	CodeAuthFailed         ErrorCode = "AUTH_FAILED"
	CodeTokenInvalid       ErrorCode = "TOKEN_INVALID"
	CodeAccessDenied       ErrorCode = "ACCESS_DENIED"
	CodeReauthRequired     ErrorCode = "REAUTH_REQUIRED"
	CodeMFARequired        ErrorCode = "MFA_REQUIRED"
	CodeChallengeInvalid   ErrorCode = "CHALLENGE_INVALID"
	CodeRateLimited        ErrorCode = "RATE_LIMITED"
	CodeAuthzUnavailable   ErrorCode = "AUTHZ_UNAVAILABLE"
	CodeDBUnavailable      ErrorCode = "DB_UNAVAILABLE"
	CodeAuditWriteFailed   ErrorCode = "AUDIT_WRITE_FAILED"
	CodeMailDeliveryFailed ErrorCode = "MAIL_DELIVERY_FAILED"
	CodeInternalError      ErrorCode = "INTERNAL_ERROR"
)

// CodeOf 把再次认证领域错误映射为根包已登记错误码（不新增错误码）。
func CodeOf(err error) ErrorCode {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrInvalidRequest):
		return CodeReqInvalid
	case errors.Is(err, ErrAccessDenied):
		return CodeAccessDenied
	case errors.Is(err, ErrAuthenticationFailed):
		return CodeAuthFailed
	case errors.Is(err, ErrReauthRequired), errors.Is(err, ErrConfirmationRequired):
		return CodeReauthRequired
	case errors.Is(err, ErrMFARequired):
		return CodeMFARequired
	case errors.Is(err, ErrChallengeInvalid), errors.Is(err, ErrChallengeExpired),
		errors.Is(err, ErrAttemptsExceeded):
		return CodeChallengeInvalid
	case errors.Is(err, ErrApprovalInvalid), errors.Is(err, ErrApprovalExpired),
		errors.Is(err, ErrApprovalConsumed), errors.Is(err, ErrIntentInvalid),
		errors.Is(err, ErrProofBindingMismatch), errors.Is(err, ErrSessionMismatch),
		errors.Is(err, ErrProofExpired):
		return CodeTokenInvalid
	case errors.Is(err, ErrProofUnavailable):
		return CodeInternalError
	case errors.Is(err, ErrRateLimited):
		return CodeRateLimited
	case errors.Is(err, ErrPolicyUnavailable):
		return CodeAuthzUnavailable
	case errors.Is(err, ErrStoreUnavailable):
		return CodeDBUnavailable
	case errors.Is(err, ErrAuditUnavailable):
		return CodeAuditWriteFailed
	case errors.Is(err, ErrNotificationFailed):
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

// LocalAdminCaller 构造本地受信管理员调用者。
func LocalAdminCaller(operatorID string) (Caller, error) {
	actor := audit.Actor{Type: audit.ActorLocalAdmin, ID: operatorID}
	if err := actor.Validate(); err != nil {
		return Caller{}, fmt.Errorf("%w: 本地操作者标识无效", ErrInvalidRequest)
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

// Signals 是执行上下文提供的客观认证事实与操作批准。它们必须由可信边界（会话/
// 本包 VerifyChallenge 结果）写入，不能由普通请求参数自称。
type Signals struct {
	// VerifiedAt 是最近一次真实验证完成时间；零值表示没有可用验证。
	VerifiedAt time.Time
	// Strength 是那次验证实际达到的强度。
	Strength policy.Strength
	// Complete 表示该认证是完整认证（无待完成第二因素/改密等步骤）。
	Complete bool
	// Confirmed 表示用户已针对本次操作内容完成确认步骤。
	Confirmed bool
	// ApprovalToken 是一次性操作批准令牌；只在需要批准时使用。
	ApprovalToken string
}

type signalsKey struct{}

// WithSignals 把认证事实写入上下文。调用方必须是可信装配层（会话中间件/测试）。
func WithSignals(ctx context.Context, signals Signals) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, signalsKey{}, signals)
}

// SignalsFromContext 读取上下文中的认证事实；缺失时返回零值（fail-closed）。
func SignalsFromContext(ctx context.Context) Signals {
	if ctx == nil {
		return Signals{}
	}
	signals, _ := ctx.Value(signalsKey{}).(Signals)
	return signals
}

// Outcome 是操作结果类别，用于决定成功告知或失败高风险告知。
type Outcome string

const (
	// OutcomeSuccess 表示业务操作已成功完成。
	OutcomeSuccess Outcome = "success"
	// OutcomeFailure 表示业务操作失败（不改变已成立的授权与审计语义）。
	OutcomeFailure Outcome = "failure"
)

// Request 是执行前校验请求。Params 是由业务模块提供的服务端字段（例如新用户名、
// 目标行版本）；本包对排序后的键值计算摘要，调用方不能自述摘要。
type Request struct {
	ScopeID     string
	OperationID string
	TargetType  string
	TargetID    string
	Params      map[string]string
	// Description 是可选的中文事件名，仅用于安全告知正文；不含秘密。
	Description string
	RequestID   string
}

// Result 是通过执行前校验后的操作上下文，供执行后告知使用。
type Result struct {
	// OperationID/Target/Description 来自请求，供通知使用。
	OperationID string
	TargetType  string
	TargetID    string
	Description string
	// UserID 是操作的认证主体（通常是调用者本人）。
	UserID string
	// Decision 是策略评估结果（含不可覆盖约束与告知要求）。
	Decision policy.Decision
	// Method 是本次满足策略的方式：direct（近期验证事实）或 approval（一次性批准）。
	Method string
	// ApprovalID 是被消费的批准 ID（Method=approval 时非空）。
	ApprovalID string
	RequestID  string
}

// ParamsDigest 计算操作参数摘要：按键排序的“长度:键长度:值”编码后 SHA-256，
// 避免简单拼接的歧义（例如 a=bc 与 ab=c）。返回值是 32 字节摘要。
func ParamsDigest(params map[string]string) [32]byte {
	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	hasher := sha256.New()
	for _, key := range keys {
		value := params[key]
		writeFrame(hasher, key)
		writeFrame(hasher, value)
	}
	var digest [32]byte
	copy(digest[:], hasher.Sum(nil))
	return digest
}

// writeFrame 写入“长度:内容”帧，消除拼接歧义。
func writeFrame(writer io.Writer, value string) {
	_, _ = io.WriteString(writer, strconv.Itoa(len(value)))
	_, _ = io.WriteString(writer, ":")
	_, _ = io.WriteString(writer, value)
}

// ParamsDigestHex 返回参数摘要的十六进制形式（仅用于日志/测试，不写入批准目标）。
func ParamsDigestHex(params map[string]string) string {
	digest := ParamsDigest(params)
	return hex.EncodeToString(digest[:])
}

// newSecret 生成 n 字节安全随机秘密。
func newSecret(random io.Reader, n int) ([]byte, error) {
	buffer := make([]byte, n)
	if _, err := io.ReadFull(random, buffer); err != nil {
		return nil, fmt.Errorf("%w: 安全随机源不可用", ErrStoreUnavailable)
	}
	return buffer, nil
}

// secretDigest 计算秘密的 SHA-256 摘要（数据库只保存摘要）。
func secretDigest(secret []byte) []byte {
	sum := sha256.Sum256(secret)
	return sum[:]
}

// newDatabaseID 生成带前缀的 128 位随机 ID。
func newDatabaseID(random io.Reader, prefix string) (string, error) {
	buffer, err := newSecret(random, 16)
	if err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(buffer), nil
}

// newApprovalToken 生成一次性批准令牌（返回给调用方一次，数据库只存摘要）。
func newApprovalToken(random io.Reader) (string, []byte, error) {
	buffer, err := newSecret(random, 32)
	if err != nil {
		return "", nil, err
	}
	return hex.EncodeToString(buffer), secretDigest(buffer), nil
}

// validTargetType 校验审计/绑定使用的目标类型标识。
func validTargetType(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
			character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

// validTargetID 校验目标稳定 ID（允许常见稳定 ID 字符集）。
func validTargetID(value string) bool {
	if len(value) > 128 {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '_' ||
			character == '-' || character == ':' || character == '/' {
			continue
		}
		return false
	}
	return true
}

// maskAddress 把邮箱脱敏为可展示/可审计的值（只保留首字符与域名）。
func maskAddress(address string) string {
	at := strings.Index(address, "@")
	if at <= 0 || at == len(address)-1 {
		return "[REDACTED]"
	}
	local := address[:at]
	domain := address[at+1:]
	return string(local[0]) + "***@" + domain
}
