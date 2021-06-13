// Package recovery 实现恢复代码的完整生命周期、受限恢复会话与强制重新绑定。
//
// 背景与安全不变量（对应步骤 44）：
//   - 恢复代码是高熵一次性代码，只在生成/重新生成时向当前用户显示一次；数据库
//     只保存 internal/secrets.Keyring 派生的 HMAC-SHA256 验证摘要（绑定账户 ID），
//     因此无法从数据库、日志或审计中还原代码本身。代码按组管理：同一用户最多一个
//     active 组，重新生成会在同一审计事务内作废旧组并插入新组。
//   - 代码验证与消费原子化：消费使用条件更新（used_at_ms 从 NULL 置为非空），并发
//     重复使用同一代码只有一个赢家；任何失败都不改变代码可用性或恢复状态。
//   - 恢复代码只替代第二步（MFA），不替代密码：Begin 必须携带 internal/authn 的
//     第一步真实认证结果，且该结果必须是“密码已通过、仍待第二因素”的受限结论。
//     完整认证结果、非受限结果、root 账户一律拒绝。
//   - 代码成功消费后创建短时受限恢复会话（session.KindRestricted / ReasonRecovery），
//     只允许核对状态、开始/完成新安全方式绑定与取消退出；该会话不能访问普通业务
//     或管理接口（由 internal/session 的既有守卫拒绝），也不签发任何 OAuth/Token。
//   - 在新因素真实验证成功前保留旧因素与旧会话的既有状态，不提前删除或降级。完成
//     流程要求宿主注入的 FactorBinder 调用真实因素服务完成验证；本包不信任客户端
//     自述的“验证成功”。高权限账户必须恢复到允许的强度（默认 fail-closed 要求
//     StrengthStrong，即 WebAuthn 用户验证；邮件永远不是恢复流程允许的新因素）。
//   - 完成时在同一个审计事务内：结束恢复尝试、作废旧代码组、生成新代码组、递增账户
//     安全版本（使恢复前建立的会话立即失效）并写审计；提交后按策略撤销全部会话、
//     尽力撤销旧因素并发送不含代码明文的安全告知，最后要求用户重新正常登录。
//     取消/中断可安全处理：取消只结束尝试与恢复会话，不删除旧因素、不生成新组。
//   - 本包不暴露 HTTP 路由、不直接装配进 cmd/login-server；宿主装配时必须注入真实
//     Store、Audit、Keyring、Sessions、Reauth、Requirements、FactorBinder 与 Notifier。
package recovery

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

const (
	// DefaultCodeCount 是每次生成的恢复代码数量。
	DefaultCodeCount = 10
	// MinCodeCount/MaxCodeCount 是单组代码数量的允许范围。
	MinCodeCount = 6
	MaxCodeCount = 20

	// codeAlphabetLength 是每个代码的 base32 字符数：10 字节安全随机数编码为
	// 16 个 base32 字符（80 位熵），分 4 组展示。
	codeRandomBytes    = 10
	codeAlphabetLength = 16
	codeGroupSize      = 4

	// DefaultAttemptTTL/最小最大 是一次恢复尝试（从代码消费到新因素绑定完成）的
	// 有效期；恢复会话必须短时，避免长期停留于受限恢复态。
	DefaultAttemptTTL = 15 * time.Minute
	MinAttemptTTL     = 5 * time.Minute
	MaxAttemptTTL     = 30 * time.Minute

	// DefaultMaxAttempts 是新因素验证失败允许的次数（达到上限后尝试作废）。
	DefaultMaxAttempts = 5
	// MinMaxAttempts/MaxMaxAttempts 是失败次数上限的允许范围。
	MinMaxAttempts = 3
	MaxMaxAttempts = 10

	// DefaultStrongAuthMaxAge 是更新恢复代码时“近期强认证”的默认新鲜度窗口。
	DefaultStrongAuthMaxAge = 15 * time.Minute
	// MinStrongAuthMaxAge/MaxStrongAuthMaxAge 是新鲜度窗口的允许范围。
	MinStrongAuthMaxAge = time.Minute
	MaxStrongAuthMaxAge = 24 * time.Hour

	// DefaultBeginFailureLimit/DefaultBeginFailureWindow 是恢复代码尝试的账户维度
	// 默认限流（10 次/10 分钟）：80 位熵下不可爆破，主要用于降噪与防滥用。
	DefaultBeginFailureLimit  = 10
	DefaultBeginFailureWindow = 10 * time.Minute
	// MinBeginFailureLimit/MaxBeginFailureLimit 与 MinBeginFailureWindow/
	// MaxBeginFailureWindow 是限流参数允许范围。
	MinBeginFailureLimit  = 1
	MaxBeginFailureLimit  = 100
	MinBeginFailureWindow = time.Minute
	MaxBeginFailureWindow = time.Hour

	// MaxCodeInputBytes 是客户端提交代码文本的输入上限。
	MaxCodeInputBytes = 64
	// MaxFactorRefBytes/MaxBindingIDBytes/MaxFactorResponseBytes 是绑定期数据的
	// 有界长度，避免无界输入进入审计或内存。
	MaxFactorRefBytes      = 128
	MaxBindingIDBytes      = 128
	MaxFactorResponseBytes = 16 * 1024

	// 领域内稳定 ID 前缀。恢复尝试 ID 同时被 internal/session 的恢复会话签发
	// 契约校验（rca_ + 32 位小写十六进制），客户端不可构造/自称。
	groupIDPrefix   = "rcg_"
	codeIDPrefix    = "rcd_"
	attemptIDPrefix = "rca_"
	idRandomBytes   = 16

	// digestDomain 是恢复代码验证摘要的密钥派生域；摘要消息绑定账户 ID 与规范化
	// 代码，避免跨账户或跨域复用。
	digestDomain = "recovery-code-v1"

	// 恢复代码相关审计动作。动作名稳定，供审计检索与排障。
	ActionCodesGenerated   = "recovery.codes.generated"
	ActionCodesRejected    = "recovery.codes.rejected"
	ActionCodeUsed         = "recovery.code.used"
	ActionRecoveryStarted  = "recovery.started"
	ActionRebindAttempt    = "recovery.rebind_attempt"
	ActionRebindStarted    = "recovery.rebind_started"
	ActionRebindFailed     = "recovery.rebind_failed"
	ActionRecoveryComplete = "recovery.completed"
	ActionRecoveryCancel   = "recovery.cancelled"
	ActionRecoveryExpired  = "recovery.expired"
	ActionRecoveryFailed   = "recovery.failed"
	ActionSessionRevoke    = "recovery.session_revoke_failed"
	ActionFactorRevokeFail = "recovery.factor_revoke_failed"

	// OperationCodesRotate 是步骤 38 敏感操作目录中的“更新恢复代码”操作 ID。
	OperationCodesRotate = "recovery.codes.rotate"
)

// 领域错误哨兵。错误文本不包含恢复代码、验证摘要、会话秘密或绑定秘密。
var (
	ErrOptionsInvalid       = errors.New("恢复服务选项无效")
	ErrInvalidRequest       = errors.New("恢复请求无效")
	ErrAccessDenied         = errors.New("未获准执行该恢复操作")
	ErrReauthRequired       = errors.New("更新恢复代码需要近期身份验证")
	ErrStrongAuthRequired   = errors.New("更新恢复代码需要近期强认证")
	ErrMFARequired          = errors.New("高权限账户需要强认证")
	ErrRootProtected        = errors.New("root 恢复必须走受控本地通道")
	ErrNoActiveGroup        = errors.New("当前没有可用的恢复代码组")
	ErrCodeInvalid          = errors.New("恢复代码无效或已使用")
	ErrCodeExhausted        = errors.New("恢复代码已全部使用")
	ErrAttemptNotActive     = errors.New("恢复尝试不存在或已结束")
	ErrAttemptExpired       = errors.New("恢复尝试已过期")
	ErrAttemptsExceeded     = errors.New("恢复尝试验证次数已用尽")
	ErrSessionRequired      = errors.New("需要有效的受限恢复会话")
	ErrMethodNotAllowed     = errors.New("该安全方式不满足恢复要求")
	ErrStrengthNotMet       = errors.New("新因素强度不满足账户要求")
	ErrRebindNotStarted     = errors.New("尚未开始新安全方式绑定")
	ErrRebindFailed         = errors.New("新安全方式验证失败")
	ErrBinderUnavailable    = errors.New("未装配新安全方式绑定服务")
	ErrFactorRevokerUnavail = errors.New("未装配旧因素撤销服务")
	ErrRequirementsUnavail  = errors.New("恢复强度要求不可用")
	ErrStoreUnavailable     = errors.New("恢复存储暂时不可用")
	ErrSessionUnavailable   = errors.New("恢复会话服务暂时不可用")
	ErrAuditUnavailable     = errors.New("关键操作未能可靠记录")
	ErrNotificationFailed   = errors.New("安全告知发送失败")
	ErrPolicyUnavailable    = errors.New("恢复策略检查暂时不可用")
	ErrRateLimited          = errors.New("恢复请求过于频繁")
	ErrConcurrentRotation   = errors.New("恢复代码正在被其他请求更新")
	ErrAttemptInProgress    = errors.New("该账户已有进行中的恢复尝试")
)

// ErrorCode 是恢复领域对根包错误码注册表的投影（只复用既有 46 个错误码）。
type ErrorCode string

const (
	CodeReqInvalid         ErrorCode = "REQ_INVALID"
	CodeAuthFailed         ErrorCode = "AUTH_FAILED"
	CodeAccessDenied       ErrorCode = "ACCESS_DENIED"
	CodeReauthRequired     ErrorCode = "REAUTH_REQUIRED"
	CodeMFARequired        ErrorCode = "MFA_REQUIRED"
	CodeMFARebindRequired  ErrorCode = "MFA_REBIND_REQUIRED"
	CodeChallengeInvalid   ErrorCode = "CHALLENGE_INVALID"
	CodeConflict           ErrorCode = "CONFLICT"
	CodeRateLimited        ErrorCode = "RATE_LIMITED"
	CodeAuthzUnavailable   ErrorCode = "AUTHZ_UNAVAILABLE"
	CodeDBUnavailable      ErrorCode = "DB_UNAVAILABLE"
	CodeAuditWriteFailed   ErrorCode = "AUDIT_WRITE_FAILED"
	CodeMailDeliveryFailed ErrorCode = "MAIL_DELIVERY_FAILED"
	CodeInternalError      ErrorCode = "INTERNAL_ERROR"
)

// CodeOf 把恢复领域错误映射为根包已登记错误码（不新增错误码）。
func CodeOf(err error) ErrorCode {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrInvalidRequest):
		return CodeReqInvalid
	case errors.Is(err, ErrAccessDenied), errors.Is(err, ErrRootProtected):
		return CodeAccessDenied
	case errors.Is(err, ErrReauthRequired):
		return CodeReauthRequired
	case errors.Is(err, ErrStrongAuthRequired), errors.Is(err, ErrMFARequired):
		return CodeMFARequired
	case errors.Is(err, ErrStrengthNotMet), errors.Is(err, ErrMethodNotAllowed),
		errors.Is(err, ErrSessionRequired), errors.Is(err, ErrRebindNotStarted),
		errors.Is(err, ErrBinderUnavailable):
		return CodeMFARebindRequired
	case errors.Is(err, ErrNoActiveGroup), errors.Is(err, ErrCodeInvalid),
		errors.Is(err, ErrCodeExhausted), errors.Is(err, ErrAttemptNotActive),
		errors.Is(err, ErrAttemptExpired), errors.Is(err, ErrAttemptsExceeded),
		errors.Is(err, ErrRebindFailed):
		return CodeChallengeInvalid
	case errors.Is(err, ErrRateLimited):
		return CodeRateLimited
	case errors.Is(err, ErrConcurrentRotation), errors.Is(err, ErrAttemptInProgress):
		return CodeConflict
	case errors.Is(err, ErrRequirementsUnavail), errors.Is(err, ErrPolicyUnavailable):
		return CodeAuthzUnavailable
	case errors.Is(err, ErrStoreUnavailable), errors.Is(err, ErrSessionUnavailable):
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
	actor audit.Actor
}

// UserCaller 构造已认证普通用户调用者。
func UserCaller(userID string) (Caller, error) {
	actor := audit.Actor{Type: audit.ActorUser, ID: userID}
	if err := actor.Validate(); err != nil {
		return Caller{}, fmt.Errorf("%w: 用户标识无效", ErrInvalidRequest)
	}
	return Caller{actor: actor}, nil
}

// SystemCaller 构造系统组件调用者（仅供宿主受信装配层用于诊断/管理只读操作）。
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

// Strength 是恢复完成后必须达到的新因素强度。
type Strength string

const (
	// StrengthSecondFactor 要求至少绑定一个第二因素（TOTP 或 Passkey）。
	StrengthSecondFactor Strength = "mfa"
	// StrengthStrong 要求强认证因素：WebAuthn 完成用户验证（UV）的 Passkey/安全
	// 密钥；TOTP 与邮件都不满足。root 与高权限账户必须使用该强度（默认要求）。
	StrengthStrong Strength = "strong"
)

// Valid 报告强度是否已定义。
func (s Strength) Valid() bool { return s == StrengthSecondFactor || s == StrengthStrong }

// AuthLevel 是“更新/重新生成恢复代码”要求的最低认证级别。
//
// 恢复代码是绕过第二因素的唯一自助通道，若持有“完整会话 + 密码”就能静默重新生成
// 代码，则已绑定强因素/高权限账户可被降级绕过 MFA。因此对这类账户必须要求近期
// **强认证**（服务端会话强认证时间在新鲜窗口内，或等价的可信认证事实），只有未绑定
// 强因素的普通账户才允许仅凭近期主密码更新（避免“没有强因素就无法恢复代码”的死锁）。
type AuthLevel string

const (
	// AuthLevelPassword 要求近期主密码认证（未绑定强因素的普通账户）。
	AuthLevelPassword AuthLevel = "password"
	// AuthLevelStrong 要求近期强认证（已绑定强因素或高权限账户；仅密码不满足）。
	AuthLevelStrong AuthLevel = "strong"
)

// Valid 报告认证级别是否已定义。
func (l AuthLevel) Valid() bool { return l == AuthLevelPassword || l == AuthLevelStrong }

// AuthLevelRequirements 按账户真实权限返回更新恢复代码所需的最低认证级别。
//
// 实现必须基于可信授权数据实时计算（例如：root、系统管理角色、已绑定 TOTP/Passkey
// 的账户返回 AuthLevelStrong），不能信任客户端参数；错误视为要求不可用并 fail-closed。
// 未注入实现时默认 AuthLevelStrong（fail-closed）。
type AuthLevelRequirements interface {
	RequiredLevel(ctx context.Context, userID string) (AuthLevel, error)
}

// AuthLevelRequirementsFunc 是 AuthLevelRequirements 的函数适配器。
type AuthLevelRequirementsFunc func(ctx context.Context, userID string) (AuthLevel, error)

// RequiredLevel 实现 AuthLevelRequirements；nil 函数按 fail-closed 返回错误。
func (f AuthLevelRequirementsFunc) RequiredLevel(ctx context.Context, userID string) (AuthLevel, error) {
	if f == nil {
		return "", ErrRequirementsUnavail
	}
	return f(ctx, userID)
}

// FactorMethod 是恢复流程允许重新绑定的新安全方式。
type FactorMethod string

const (
	// MethodPasskey 是 WebAuthn Passkey/安全密钥（可满足 StrengthStrong）。
	MethodPasskey FactorMethod = "passkey"
	// MethodTOTP 是 TOTP 验证器（只满足 StrengthSecondFactor，绝不满足强认证）。
	MethodTOTP FactorMethod = "totp"
)

// Valid 报告新因素方法是否已定义。
func (m FactorMethod) Valid() bool { return m == MethodPasskey || m == MethodTOTP }

// Allows 报告该恢复强度是否接受指定方法（邮件等其他方式永远不允许）。
func (s Strength) Allows(method FactorMethod) bool {
	switch s {
	case StrengthSecondFactor:
		return method == MethodTOTP || method == MethodPasskey
	case StrengthStrong:
		return method == MethodPasskey
	default:
		return false
	}
}

// Code 是一条只展示一次的恢复代码明文。
//
// 默认字符串化/格式化/JSON/slog 全部脱敏；宿主必须在一次性展示时显式调用
// Reveal()。本类型不是内存清零承诺，也不应被复制到日志、URL 或普通存储。
type Code struct {
	value string
}

// Reveal 返回代码明文副本，只用于一次性展示给当前用户。
func (c Code) Reveal() string { return c.value }

// IsSet 报告代码是否有值；不暴露内容。
func (c Code) IsSet() bool { return c.value != "" }

// String 实现 fmt.Stringer，固定输出脱敏标记。
func (c Code) String() string {
	if c.value == "" {
		return "[UNSET]"
	}
	return "[REDACTED]"
}

// GoString 实现 fmt.GoStringer。
func (c Code) GoString() string { return c.String() }

// Format 实现 fmt.Formatter，覆盖 %v/%s/%q/%x 等。
func (c Code) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte(c.String()))
}

// MarshalJSON 实现 json.Marshaler，输出脱敏标记。
func (c Code) MarshalJSON() ([]byte, error) { return []byte(`"` + c.String() + `"`), nil }

// base32Codec 是恢复代码文本编码（无填充大写 base32）。
var base32Codec = base32.StdEncoding.WithPadding(base32.NoPadding)

// newCode 用安全随机源生成一条高熵恢复代码，并格式化为 4 组便于人工转录。
func newCode(random io.Reader) (Code, error) {
	if random == nil {
		random = rand.Reader
	}
	buffer := make([]byte, codeRandomBytes)
	if _, err := io.ReadFull(random, buffer); err != nil {
		return Code{}, fmt.Errorf("%w: 无法生成恢复代码", ErrOptionsInvalid)
	}
	encoded := base32Codec.EncodeToString(buffer)
	var builder strings.Builder
	builder.Grow(codeAlphabetLength + codeAlphabetLength/codeGroupSize)
	for index, r := range encoded {
		if index > 0 && index%codeGroupSize == 0 {
			builder.WriteByte('-')
		}
		builder.WriteRune(r)
	}
	return Code{value: builder.String()}, nil
}

// normalizeCode 校验并规范化客户端提交的恢复代码：去除非 ASCII 字母/数字/连字符
// 的干扰字符（空白），统一大写，去除分组连字符。非法输入返回 false。
func normalizeCode(input string) (string, bool) {
	if input == "" || len(input) > MaxCodeInputBytes || !utf8.ValidString(input) {
		return "", false
	}
	var builder strings.Builder
	builder.Grow(codeAlphabetLength)
	for _, r := range input {
		switch {
		case unicode.IsSpace(r), r == '-', r == '_':
			continue
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r - 'a' + 'A')
		case r >= 'A' && r <= 'Z', r >= '2' && r <= '7':
			builder.WriteRune(r)
		default:
			return "", false
		}
	}
	normalized := builder.String()
	if len(normalized) != codeAlphabetLength {
		return "", false
	}
	for _, r := range normalized {
		if (r < 'A' || r > 'Z') && (r < '2' || r > '7') {
			return "", false
		}
	}
	return normalized, true
}

// codeDigest 计算恢复代码的验证摘要：HMAC-SHA256(用户 ID || 规范化代码)。摘要
// 只在数据库保存，不能反推代码；key_id 随行保存以支持密钥轮换后的历史验证。
func codeDigest(ring *secrets.Keyring, keyID, userID, normalizedCode string) ([]byte, error) {
	if ring == nil {
		return nil, fmt.Errorf("%w: 主密钥环为空", ErrOptionsInvalid)
	}
	message := make([]byte, 0, len(userID)+1+len(normalizedCode))
	message = append(message, userID...)
	message = append(message, 0)
	message = append(message, normalizedCode...)
	digest, err := ring.HMACDigest(keyID, digestDomain, message)
	if err != nil {
		return nil, fmt.Errorf("%w: 无法计算恢复代码摘要", ErrOptionsInvalid)
	}
	return digest, nil
}

// matchCode 用常量时间比较候选代码摘要与已存摘要。
func matchCode(expected, actual []byte) bool {
	if len(expected) != len(actual) || len(expected) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare(expected, actual) == 1
}

// validateAuthResult 校验恢复流程的第一步认证结果：必须是密码已真实通过、仍待
// 第二因素的受限结论；完整认证、非受限、没有密码方法或携带强认证时间的结果一律
// 拒绝（恢复代码不能替代密码，也不能绕过第二步策略）。
func validateAuthResult(result authn.AuthenticateResult) error {
	if !account.ValidUserID(result.UserID) {
		return fmt.Errorf("%w: 认证结果的用户 ID 无效", ErrInvalidRequest)
	}
	if result.SecurityVersion <= 0 {
		return fmt.Errorf("%w: 认证结果缺少账户安全版本", ErrInvalidRequest)
	}
	if result.Outcome != authn.OutcomePendingSecondFactor {
		return fmt.Errorf("%w: 恢复代码只替代第二步，必须处于待第二因素状态", ErrAccessDenied)
	}
	if !result.Restricted || len(result.RequiredSteps) == 0 {
		return fmt.Errorf("%w: 认证结果必须标记受限并带剩余步骤", ErrInvalidRequest)
	}
	hasPassword := false
	hasSecondFactorStep := false
	for _, method := range result.CompletedMethods {
		if method == authn.MethodPassword {
			hasPassword = true
		}
	}
	if !hasPassword {
		return fmt.Errorf("%w: 认证结果没有真实完成的密码方法", ErrAccessDenied)
	}
	for _, step := range result.RequiredSteps {
		if !step.Valid() {
			return fmt.Errorf("%w: 认证结果包含未知剩余步骤", ErrInvalidRequest)
		}
		if step == authn.StepSecondFactor {
			hasSecondFactorStep = true
		}
	}
	if !hasSecondFactorStep {
		return fmt.Errorf("%w: 认证结果没有待第二因素步骤", ErrInvalidRequest)
	}
	if !result.StrongAuthCompletedAt.IsZero() {
		return fmt.Errorf("%w: 恢复前的受限结果不得携带强认证时间", ErrInvalidRequest)
	}
	return nil
}

// validateAttemptTTL / validateCodeCount / validateMaxAttempts 是装配参数边界。
func validateAttemptTTL(ttl time.Duration) (time.Duration, error) {
	if ttl == 0 {
		return DefaultAttemptTTL, nil
	}
	if ttl < MinAttemptTTL || ttl > MaxAttemptTTL {
		return 0, fmt.Errorf("%w: 恢复尝试有效期必须在 %s～%s 之间",
			ErrOptionsInvalid, MinAttemptTTL, MaxAttemptTTL)
	}
	return ttl, nil
}

func validateCodeCount(count int) (int, error) {
	if count == 0 {
		return DefaultCodeCount, nil
	}
	if count < MinCodeCount || count > MaxCodeCount {
		return 0, fmt.Errorf("%w: 代码数量必须在 %d～%d 之间", ErrOptionsInvalid, MinCodeCount, MaxCodeCount)
	}
	return count, nil
}

func validateMaxAttempts(maxAttempts int) (int, error) {
	if maxAttempts == 0 {
		return DefaultMaxAttempts, nil
	}
	if maxAttempts < MinMaxAttempts || maxAttempts > MaxMaxAttempts {
		return 0, fmt.Errorf("%w: 失败次数上限必须在 %d～%d 之间",
			ErrOptionsInvalid, MinMaxAttempts, MaxMaxAttempts)
	}
	return maxAttempts, nil
}

// newDomainID 生成领域内稳定 ID（前缀 + 128 位安全随机十六进制）。
func newDomainID(random io.Reader, prefix string) (string, error) {
	if random == nil {
		random = rand.Reader
	}
	buffer := make([]byte, idRandomBytes)
	if _, err := io.ReadFull(random, buffer); err != nil {
		return "", fmt.Errorf("%w: 安全随机源不可用", ErrOptionsInvalid)
	}
	return prefix + hex.EncodeToString(buffer), nil
}

// validDomainID 校验领域内稳定 ID 格式。
func validDomainID(id, prefix string) bool {
	if len(id) != len(prefix)+2*idRandomBytes || !strings.HasPrefix(id, prefix) {
		return false
	}
	for _, r := range id[len(prefix):] {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// GetRecoveryStrength 是默认恢复强度决策器：返回 StrengthStrong（fail-closed）。
// 宿主必须注入 Requirements 实现，才能按账户真实权限给出普通用户 StrengthSecondFactor
// 的例外；未注入时任何账户都按强认证要求恢复。
func GetRecoveryStrength(context.Context, string) (Strength, error) {
	return StrengthStrong, nil
}

// 编译期断言：internal/reauth 的操作执行器接口被本包使用；避免未来签名漂移。
var _ reauth.OperationRunner = (*reauth.Service)(nil)

// 编译期断言：internal/session 的恢复会话签发方法签名由本包依赖。
var _ interface {
	IssueRecoverySession(context.Context, session.RecoverySessionRequest) (session.IssuedSession, error)
	Validate(context.Context, string) (session.Session, error)
	Logout(context.Context, string) error
	RevokeAllForUser(context.Context, string, string) (int64, error)
} = (*session.Service)(nil)

// scopeSystem 是敏感操作策略的系统作用域 ID（与步骤 38 一致）。
const scopeSystem = "system"

// 编译期断言：reauth.OperationRunner 的返回类型 Result/Outcome 被 service.go 使用。
var _ reauth.OperationRunner = (*reauth.Service)(nil)
