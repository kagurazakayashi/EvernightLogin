// Package mfa 实现两步验证（MFA）公共状态机与邮件第二步验证。
//
// 范围与安全不变量：
//   - 第一步密码认证由 internal/authn 完成。第二步因素由统一选择器按“用户实际启用
//     且满足策略”选择：Passkey/安全密钥（WebAuthn UV）优先，其次 TOTP，最后邮件；
//     强认证要求下邮件永远不会被选中，也不存在“降级到邮件”的路径。高权限账户
//     （root 与持有高敏感系统权限的账户）密码正确后 authn 返回
//     pending_second_factor/受限状态：有可用强因素时走 Passkey/安全密钥或 TOTP
//     第二步；没有可用强因素时默认 fail-closed 返回 MFA_REQUIRED，只有宿主显式
//     启用 AllowStrongAuthSetup 才进入受限初始化闭环（仅签发受限会话、绑定强因素、
//     撤销受限会话并要求重新登录，绝不签发完整会话）。
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
//     强制策略：被 Policy 要求 MFA 时不能移除最后一个可用因素。已实现的第二步因素
//     包括 email、TOTP（适配器）与 Passkey/安全密钥（适配器，步骤 43）；安全密钥
//     第二步要求凭证用途允许 second_factor，且策略要求强认证时必须有 UV。
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
	"github.com/kagurazakayashi/EvernightLogin/internal/authfact"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/credential"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	"github.com/kagurazakayashi/EvernightLogin/internal/passkey"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// 领域错误哨兵。错误文本不包含验证码、尝试令牌或会话秘密。
var (
	ErrOptionsInvalid        = errors.New("MFA 服务选项无效")
	ErrInvalidRequest        = errors.New("MFA 请求无效")
	ErrAccessDenied          = errors.New("未获准执行该 MFA 操作")
	ErrStrongAuthRequired    = errors.New("高权限账户需要强认证，邮件因素不可满足")
	ErrSecondFactorRequired  = errors.New("需要完成第二因素验证")
	ErrChallengeInvalid      = errors.New("MFA 挑战无效")
	ErrChallengeExpired      = errors.New("MFA 挑战已过期")
	ErrCodeInvalid           = errors.New("验证码无效或已失效")
	ErrAttemptsExceeded      = errors.New("验证码尝试次数已用尽")
	ErrRateLimited           = errors.New("MFA 请求过于频繁")
	ErrNoVerifiedEmail       = errors.New("账户没有已验证邮箱，无法使用邮件因素")
	ErrFactorExists          = errors.New("该类型 MFA 因素已启用")
	ErrFactorNotFound        = errors.New("未找到可用的 MFA 因素")
	ErrFactorRequired        = errors.New("策略要求 MFA，不能移除最后一个可用因素")
	ErrMailFailed            = errors.New("验证码邮件发送失败")
	ErrSessionUnavailable    = errors.New("会话服务暂时不可用")
	ErrPolicyUnavailable     = errors.New("MFA 策略检查暂时不可用")
	ErrStoreUnavailable      = errors.New("MFA 存储暂时不可用")
	ErrAuditUnavailable      = errors.New("关键操作未能可靠记录")
	ErrNoAvailableMethod     = errors.New("没有可用且满足策略的第二因素")
	ErrStrongSetupIncomplete = errors.New("强认证初始化尚未完成")
	ErrStrongSetupDenied     = errors.New("不允许强认证初始化")
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
		errors.Is(err, ErrNoVerifiedEmail), errors.Is(err, ErrNoAvailableMethod),
		errors.Is(err, ErrStrongSetupIncomplete), errors.Is(err, ErrStrongSetupDenied):
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
	// FactorTOTP 是 TOTP 验证器第二步因素（步骤 41）。
	FactorTOTP FactorType = "totp"
	// FactorPasskey 是 WebAuthn/FIDO2 安全密钥第二步因素（步骤 43）；凭证用途必须
	// 允许第二步，与主登录 Passkey 凭证区分。
	FactorPasskey FactorType = "passkey"
)

// Purpose 是挑战用途。
type Purpose string

const (
	// PurposeLogin 是登录第二步验证。
	PurposeLogin Purpose = "login"
	// PurposeFactorEnroll 是新增因素时的渠道控制权验证。
	PurposeFactorEnroll Purpose = "factor_enroll"
	// PurposeStrongSetup 是“要求强认证但尚未绑定强因素”的管理账户的受限初始化：
	// 只签发受限会话、绑定允许的强因素，完成后撤销受限会话并要求重新登录。
	PurposeStrongSetup Purpose = "strong_setup"
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
	// FactorRef 是第二步 WebAuthn ceremony ID（FactorPasskey 使用），与邮件/TOTP
	// 验证码凭证分开，避免借用 credential_id 的语义。
	FactorRef  string
	Generation int
	State      ChallengeState
	Username   string
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
	// RequireStrong 表示本挑战所属账户被策略要求强认证：安全密钥第二步必须完成
	// 用户验证（UV）才能满足，否则拒绝（不能把无 UV 的断言当强认证）。
	RequireStrong   bool
	SecurityVersion int64
	CompletedAt     time.Time
	ExpiresAt       time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
	VerifiedAt      time.Time
}

// SecondFactorTOTP 是 TOTP 第二步因素适配器；生产实现为 *internal/totp.Service，
// 其 HasActive 与 VerifyLoginCode 方法签名与下面一致。mfa 只负责挑战/会话/限流，
// 时间步防重放由 totp 实现负责。
type SecondFactorTOTP interface {
	// HasActive 报告用户是否有已激活的 TOTP 绑定。
	HasActive(ctx context.Context, userID string) (bool, error)
	// VerifyLoginCode 校验登录第二步 TOTP 码；同一步/旧步重放必须返回错误。
	VerifyLoginCode(ctx context.Context, userID, code string) error
}

// SecondFactorPasskey 是 WebAuthn/FIDO2 安全密钥第二步适配器；生产实现为
// *internal/passkey.Service（其 BeginSecondFactor/FinishSecondFactor/HasSecondFactor
// 语义与下面一致）。mfa 只负责挑战/会话/限流，WebAuthn 校验由 passkey 实现负责。
type SecondFactorPasskey interface {
	// HasSecondFactor 报告用户是否有用途允许第二步的有效凭证。
	HasSecondFactor(ctx context.Context, userID string) (bool, error)
	// BeginSecondFactor 为指定 MFA 挑战创建第二步认证挑战（allowCredentials 只含
	// 第二步用途凭证）；contextID 由服务端挑战得出。
	BeginSecondFactor(ctx context.Context, userID, contextID, requestID string) (passkey.SecondFactorStart, error)
	// FinishSecondFactor 校验第二步断言；成功返回用户验证结果与凭证元数据。
	FinishSecondFactor(ctx context.Context, request passkey.SecondFactorFinishRequest) (passkey.SecondFactorResult, error)
}

// StrongFactorSource 报告账户当前是否已绑定可用于强认证的因素（TOTP 或用途允许
// 第二步的 Passkey/安全密钥）；用于“最后一个可用因素”等存在性判定。nil 时视为
// 未就绪（fail-closed）。
type StrongFactorSource interface {
	HasStrongFactor(ctx context.Context, userID string) (bool, error)
}

// StrongSetupMethodSource 可选：按用户返回本次“受限强认证初始化”（root 首次绑定
// 强因素、人工恢复 MFA 重置后的强制重绑）允许绑定的强因素类别。生产装配用它把
// root/高权限账户固定为抗钓鱼的 Passkey，只对存在未清除重绑需求的普通账户按显式
// 配置下发 Passkey/TOTP 类别；返回空列表表示不允许该用户进入初始化（fail-closed）。
// 未实现时退化为 Options.StrongSetupMethods。
type StrongSetupMethodSource interface {
	AllowedStrongSetupMethods(ctx context.Context, userID string) ([]authfact.Method, error)
}

// StrongSetupBindingVerifier 可选：确认指定强因素是在 since 之后由该账户真实新绑定
// 的，防止用账户既有因素（例如历史遗留的 TOTP/Passkey 凭证）冒充本次受限初始化
// 完成的“新绑定”，从而在完成判定上降级抗钓鱼要求。生产装配必须实现；未实现时退化
// 为“该因素当前存在”的检查（仅限没有既有因素的受控宿主/测试）。
type StrongSetupBindingVerifier interface {
	StrongFactorBoundAfter(ctx context.Context, userID string,
		method authfact.Method, since time.Time) (bool, error)
}

// RebindRequirementSnapshot 是“人工恢复 MFA 重置后强制重绑需求”的当前代际快照
// （步骤 253）：Present=false 表示当前没有未清除的需求；Present=true 时
// RequiredAtMS/SourceRequestID 唯一标识需求代际，用于完成初始化时条件清除，
// 防止旧完成请求清掉更新的恢复要求。快照不含秘密。
type RebindRequirementSnapshot struct {
	Present         bool
	RequiredAtMS    int64
	SourceRequestID string
}

// StrongSetupFinalizer 可选：由宿主在强认证初始化完成的同一审计事务内完成最终
// 一致性复核与条件清除（步骤 253）：
//   - 最终复核当前账户仍为 active 且 security_version 与挑战创建时一致（身份/安全
//     代际在完成期间未变化）；
//   - 按 expected 快照条件清除未清除的重绑需求：需求代际被新的恢复申请替换时
//     返回错误（fail-closed，不静默清掉新需求）。
//
// 实现必须只使用同一审计事务（tx）内的读写；返回错误必须让整个事务回滚。
type StrongSetupFinalizer interface {
	// RebindRequirementSnapshot 读取当前未清除需求快照（事务外只读；只用于审计
	// 字段与条件清除的期望代际，最终以 FinalizeStrongSetupTx 的事务内校验为准）。
	RebindRequirementSnapshot(ctx context.Context, userID string) (RebindRequirementSnapshot, error)
	// FinalizeStrongSetupTx 在同一审计事务内复核账户状态/安全版本并按快照条件清除
	// 需求；不匹配、已被替换或存储失败返回错误，调用方整体回滚。
	FinalizeStrongSetupTx(ctx context.Context, tx audit.Tx, userID string,
		expected RebindRequirementSnapshot, challengeSecurityVersion int64) error
}

// StrongSetupBindingVerifierTx 可选：StrongSetupBindingVerifier 的事务版本，供完成
// 初始化时在同一审计事务内复核“本次新绑定”仍然有效（因素可能在预检查后、提交前
// 被移除/撤销）。实现只能用 tx 读取；返回错误按策略不可用 fail-closed。
type StrongSetupBindingVerifierTx interface {
	StrongFactorBoundAfterTx(ctx context.Context, tx audit.Tx, userID string,
		method authfact.Method, since time.Time) (bool, error)
}

// StrongSetupAuthorizer 授权强认证初始化（受控状态）：必须是可信来源确认该用户
// 处于初始化/受邀状态（如 root pending_setup 状态）或已获管理员一次性凭证/审批；
// 未注入或拒绝时不允许初始化。mfa 本身不验证审批，宿主必须提供可信实现。
type StrongSetupAuthorizer interface {
	AuthorizeStrongSetup(ctx context.Context, userID, requestID string) error
}

// SessionRevoker 是撤销受限会话的契约；强认证初始化完成后必须撤销受限会话，避免
// 留下临时受限通道。启用 AllowStrongAuthSetup 时必须注入（构造期校验）。
type SessionRevoker interface {
	Logout(ctx context.Context, secret string) error
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

// completeResult 在第二因素真实通过后构造完整认证结果（内部可信边界）。factorMethod
// 是具体第二因素方法（邮件/TOTP/安全密钥），strongAuthAt 只在该因素满足强认证时
// 非零；受限结果不会携带强认证时间（会话服务会拒绝）。
func completeResult(challenge Challenge, completedAt time.Time,
	factorMethod authfact.Method, strongAuthAt time.Time) authn.AuthenticateResult {
	return authn.AuthenticateResult{
		UserID: challenge.UserID, Username: challenge.Username,
		Outcome:               authn.OutcomeComplete,
		CompletedMethods:      []authn.Method{authn.MethodPassword, authnMethodOf(factorMethod)},
		CompletedAt:           completedAt,
		StrongAuthCompletedAt: strongAuthAt,
		Restricted:            false,
		SecurityVersion:       challenge.SecurityVersion,
	}
}

// strongSetupResult 构造“强认证未就绪、进入受限初始化”的认证结果；只能签发受限
// 会话，不得当作完整登录。
func strongSetupResult(base authn.AuthenticateResult) authn.AuthenticateResult {
	return authn.AuthenticateResult{
		UserID: base.UserID, Username: base.Username,
		Outcome:          authn.OutcomePendingSecondFactor,
		CompletedMethods: []authn.Method{authn.MethodPassword},
		CompletedAt:      base.CompletedAt,
		RequiredSteps:    []authn.Step{authn.StepStrongAuthSetup},
		Restricted:       true,
		SecurityVersion:  base.SecurityVersion,
	}
}

// factorTypeOf 把认证事实方法映射为 MFA 因素类型。
func factorTypeOf(method authfact.Method) FactorType {
	switch method {
	case authfact.MethodSecurityKey, authfact.MethodPasskey:
		return FactorPasskey
	case authfact.MethodTOTP:
		return FactorTOTP
	case authfact.MethodEmailOTP:
		return FactorEmail
	default:
		return ""
	}
}

// authnMethodOf 把认证事实方法映射为 authn 认证方法标识。
func authnMethodOf(method authfact.Method) authn.Method {
	switch method {
	case authfact.MethodPassword:
		return authn.MethodPassword
	case authfact.MethodEmailOTP:
		return authn.MethodEmailOTP
	case authfact.MethodTOTP:
		return authn.MethodTOTP
	case authfact.MethodSecurityKey:
		return authn.MethodSecurityKey
	case authfact.MethodPasskey:
		return authn.MethodPasskey
	default:
		return authn.MethodSecondFactor
	}
}

// credential.VerifyRequest/Purpose 常量在本包集中定义，避免字符串漂移。
const (
	purposeLoginCode        = "mfa.email.login"
	purposeFactorEnrollCode = "mfa.email.enroll"
)

// VerifyRequest 是第二步验证请求。
type VerifyRequest struct {
	ChallengeID  string
	AttemptToken string
	// Code 是邮件/TOTP 验证码；安全密钥第二步不使用该字段。
	Code string
	// PasskeyCeremonyID/PasskeyResponse 是安全密钥第二步的 WebAuthn ceremony 与
	// 断言响应 JSON；其他因素不使用。
	PasskeyCeremonyID string
	PasskeyResponse   []byte
	ExistingSession   string
	RequestID         string
}

// VerifyResult 是第二因素通过后的完整会话与认证结果。
type VerifyResult struct {
	Session       session.IssuedSession
	Authenticated authn.AuthenticateResult
	ChallengeID   string
	// Method 是本次完成的第二因素方法；AMR/ACR/Strength 是认证事实的未来 OAuth/
	// OIDC 映射（本步骤只提供内部事实与映射，不实现协议端点）。
	Method   string
	AMR      []string
	ACR      string
	Strength string
}

// 合同：credential 服务类型在接口中直接使用，避免再包一层不受控发送接口。
var _ = credential.KindCode

// MailSender 邮件发送接口别名（内部使用 mailer.Sender）。
type MailSender = mailer.Sender

// RootReadyMarker 在强认证完成的审计事务内把 root 初始化状态从 setup_verified
// 推进到 ready。只有真正完成强因素绑定后才调用；非 root/已 ready/普通用户由实现
// 自行判定并返回 nil。
type RootReadyMarker interface {
	MarkRootReady(ctx context.Context, tx audit.Tx, userID string, now time.Time) error
}
