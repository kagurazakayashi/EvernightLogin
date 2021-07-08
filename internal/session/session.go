// Package session 把密码认证结果接入服务端会话，形成普通用户登录与退出闭环。
//
// 背景与边界（对应步骤 30）：
//   - 会话秘密由 crypto/rand 生成 256 位随机值，只在签发结果中返回一次；数据库
//     只保存 internal/secrets.Keyring 以当前写密钥派生的 HMAC-SHA256 验证摘要，
//     比较使用常量时间，秘密原文不进入日志、审计、错误或 URL。
//   - 会话分普通（normal）与受限（restricted）两类。只有
//     authn.AuthenticateResult.Outcome == complete 且 Restricted == false 且
//     RequiredSteps 为空时才签发普通会话；待补充第二因素、待强制改密只能得到
//     受限会话。受限会话不得访问普通业务或管理接口。
//   - 每次校验都会重读账户状态与安全版本，以及应用状态与应用成员状态；账户被
//     禁用/请求删除、密码变更（递增安全版本）、应用停用、成员移除/停用都会让
//     既有会话立即失效。签发时同样重读，绝不把认证结果里的快照当作当前状态。
//   - 空闲到期与绝对到期两道约束；续期只延长空闲到期且不越过绝对到期。登录
//     成功会轮换会话 ID：出示的旧会话在签发事务中被撤销，新会话使用新的随机
//     ID 与秘密，防止会话固定（session fixation）。退出/管理撤销写服务端状态，
//     立即生效，不依赖客户端删除 Cookie。
//   - 嵌入式 Go API 直接使用 Validate/Login/Logout，不强迫调用方使用浏览器
//     Cookie；浏览器 Cookie 只是宿主可选的投递方式（NewCookie），与嵌入式 API
//     共享同一撤销语义。Cookie 默认 __Host- 前缀、Secure、HttpOnly、
//     SameSite=Lax、Path=/，名字与 internal/transport 的 CSRF 契约一致；CSRF
//     令牌与会话绑定并由 ValidateCSRFToken 校验，来源规则仍由既有 HTTP 防护
//     中间件负责。
//   - 管理访问额外要求强认证（strong_auth_verified_at_ms 非空）。MFA 尚未实现，
//     本包没有任何写入该字段的通道，因此即使普通会话也不能访问管理接口。
//   - 会话不是 OAuth Access Token / ID Token / Refresh Token；后续 OAuth 模块
//     另行实现，不能用本包的会话秘密冒充任何令牌。
package session

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
)

const (
	// SessionIDPrefix 是会话公开标识的固定前缀。
	SessionIDPrefix = "ses_"
	// sessionIDRandomBytes 是会话 ID 的随机字节数（128 位）；加上前缀与十六进制
	// 编码后长度为 36。会话 ID 不是秘密，但仍必须不可预测。
	sessionIDRandomBytes = 16
	// sessionIDLength 是会话 ID 的完整长度。
	sessionIDLength = len(SessionIDPrefix) + 2*sessionIDRandomBytes
	// SecretSize 是会话秘密的随机字节数（256 位）。
	SecretSize = 32
	// SecretTextLength 是会话秘密 base64url（无填充）文本长度。
	SecretTextLength = 43
	// CSRFSecretSize 是与会话绑定的 CSRF 令牌随机字节数（256 位）。
	CSRFSecretSize = 32
	// secretSeparator 分隔 Cookie/API 秘密中的会话 ID 与秘密值。
	secretSeparator = "."
	// maxSecretInputBytes 是解析客户端提交会话秘密时的输入上限。
	maxSecretInputBytes = 128

	// DefaultIdleTimeout 是未指定时的空闲到期期限。
	DefaultIdleTimeout = 30 * time.Minute
	// DefaultStrongAuthMaxAge 是强认证事实默认有效期（管理访问的新鲜度窗口）。
	DefaultStrongAuthMaxAge = 15 * time.Minute
	// MinStrongAuthMaxAge/MaxStrongAuthMaxAge 是有效期边界。
	MinStrongAuthMaxAge = time.Minute
	MaxStrongAuthMaxAge = 24 * time.Hour
	// MinIdleTimeout/MaxIdleTimeout 是允许配置的空闲期限范围。
	MinIdleTimeout = time.Minute
	MaxIdleTimeout = 24 * time.Hour
	// DefaultAbsoluteTimeout 是未指定时的绝对到期期限。
	DefaultAbsoluteTimeout = 12 * time.Hour
	// MinAbsoluteTimeout/MaxAbsoluteTimeout 是允许配置的绝对期限范围。
	MinAbsoluteTimeout = 5 * time.Minute
	MaxAbsoluteTimeout = 30 * 24 * time.Hour

	// DefaultRememberMeTimeout 是“记住我”登录未指定时的更长绝对到期期限。
	DefaultRememberMeTimeout = 7 * 24 * time.Hour

	// DefaultRecoverySessionTTL 是受限恢复会话的默认绝对到期期限（短时）。
	DefaultRecoverySessionTTL = 15 * time.Minute
	// MinRecoverySessionTTL/MaxRecoverySessionTTL 是受限恢复会话期限的允许范围。
	// 恢复代码成功后的会话只能是短时受限会话，不得像普通登录那样长期有效。
	MinRecoverySessionTTL = 5 * time.Minute
	MaxRecoverySessionTTL = 30 * time.Minute

	// MaxActiveSessionsLimit 是“最大在线数”可配置上限；0 表示不限制。
	MaxActiveSessionsLimit = 100

	// DefaultListPageSize/MaxListPageSize 是设备列表分页边界。
	DefaultListPageSize = 20
	MaxListPageSize     = 100

	// PermissionSessionsRevoke 是既有权限目录中“强制会话退出”的机器标识；
	// 管理员强制下线必须经既有授权语义（internal/authz）判定该权限，不能由
	// 客户端自称范围。系统范围使用系统权限，应用范围使用该应用作用范围内的
	// 同名应用独有权限。
	PermissionSessionsRevoke = "sessions.revoke"

	// 摘要域：会话秘密与 CSRF 令牌使用不同域，防止两类摘要互相冒用。HMAC 子
	// 密钥由 internal/secrets.Keyring.HMACDigest 按域派生，本包不自造密码学。
	secretDigestDomain = "session-v1"
	csrfDigestDomain   = "session-csrf-v1"
	// pageCSRFDomain 是"服务端页面表单"所需的确定性 CSRF 令牌派生域；与随机
	// CSRF 令牌摘要域分开，避免两类令牌互相推导/冒充。
	pageCSRFDomain = "session-page-csrf-v1"

	// maxRevokeReasonBytes 是撤销原因码长度上限（写入审计与数据库）。
	maxRevokeReasonBytes = 64
	// maxRequestIDBytes 是请求编号长度上限。
	maxRequestIDBytes = 64
	// maxAppIDBytes 是应用 ID 长度上限（与迁移 0001 的应用 ID 约定一致）。
	maxAppIDBytes = 64
	// maxClientUserAgentBytes/maxClientAddressBytes 是客户端描述列的写入上限，
	// 与迁移 0011 的列 CHECK 上限一致；超长内容截断而不是拒绝。
	maxClientUserAgentBytes = 256
	maxClientAddressBytes   = 128
)

// Kind 是会话类别。只有 normal 允许访问普通业务；restricted 一律拒绝。
type Kind string

const (
	// KindNormal 表示密码与当前策略要求的全部认证方法都已完成。
	KindNormal Kind = "normal"
	// KindRestricted 表示认证不完整：必须按 Reason 区分待补充认证、受限恢复或
	// 受限初始化，且不得访问普通业务或管理接口。
	KindRestricted Kind = "restricted"
)

// Valid 报告会话类别是否已定义。
func (k Kind) Valid() bool {
	return k == KindNormal || k == KindRestricted
}

// Reason 是受限会话的细分原因；普通会话为空。
type Reason string

const (
	// ReasonNone 表示没有受限原因（只用于普通会话）。
	ReasonNone Reason = ""
	// ReasonPendingSecondFactor 表示密码已通过但还缺强认证/第二因素。
	ReasonPendingSecondFactor Reason = "pending_second_factor"
	// ReasonPendingPasswordChange 表示密码已通过但必须先完成强制改密。
	ReasonPendingPasswordChange Reason = "pending_password_change"
	// ReasonRecovery 表示受限恢复会话。恢复代码/客服恢复流程由后续步骤实现，
	// 本步只定义稳定标识与访问拒绝语义，没有签发入口。
	ReasonRecovery Reason = "recovery"
	// ReasonInitialization 表示受限初始化/首次配置会话。root 受限初始化流程由
	// 后续步骤实现，本步只定义稳定标识与访问拒绝语义，没有签发入口。
	ReasonInitialization Reason = "initialization"
)

// Valid 报告受限原因是否已定义；空值只在普通会话中合法。
func (r Reason) Valid() bool {
	switch r {
	case ReasonPendingSecondFactor, ReasonPendingPasswordChange, ReasonRecovery, ReasonInitialization:
		return true
	default:
		return false
	}
}

// validFor 报告受限原因是否与类别组合一致。
func (r Reason) validFor(kind Kind) bool {
	if kind == KindNormal {
		return r == ReasonNone
	}
	return kind == KindRestricted && r.Valid()
}

// ValidCombination 报告会话类别与受限原因的合法组合：普通会话原因必须为空，
// 受限会话原因必须是已定义的受限原因。存储实现用它拒绝损坏/手工写入的非法组合。
func ValidCombination(kind Kind, reason Reason) bool {
	if !kind.Valid() {
		return false
	}
	return reason.validFor(kind)
}

// reasonFromAuthn 把认证结果的待完成状态映射为受限原因。MFA 与恢复流程未实现
// 时只有第二因素与强制改密两种来源；恢复/初始化原因没有签发入口。
func reasonFromAuthn(result authn.AuthenticateResult) (Reason, error) {
	switch result.Outcome {
	case authn.OutcomeComplete:
		return ReasonNone, nil
	case authn.OutcomePendingSecondFactor:
		return ReasonPendingSecondFactor, nil
	case authn.OutcomePendingPasswordChange:
		return ReasonPendingPasswordChange, nil
	default:
		return ReasonNone, fmt.Errorf("%w: 认证结论未知", ErrInvalidRequest)
	}
}

// Session 是校验通过后返回给调用方的会话快照。它不含会话秘密，也不含 CSRF
// 令牌；秘密只在 IssuedSession 中返回一次。字段是校验时刻的服务端事实，调用方
// 不得把它们写进 URL、localStorage 或日志。
type Session struct {
	// ID 是会话公开标识（ses_ 前缀），可写入日志与审计关联，但不能单独用于
	// 认证。
	ID string
	// UserID 是会话所属账户稳定 ID。
	UserID string
	// AppID 是可选的应用上下文；空表示不绑定具体应用。
	AppID string
	// Kind/Reason 是会话类别与受限原因。
	Kind   Kind
	Reason Reason
	// SecurityVersion 是签发时账户安全版本快照；校验时已与当前值比对。
	SecurityVersion int64
	// RequiredSteps 是受限会话仍需完成的认证步骤。
	RequiredSteps []authn.Step
	// AuthMethods 是登录时真实完成的认证方法（来自服务端认证结果，只存稳定标识）。
	// OIDC ID Token 的 amr/acr 必须由它映射，不能由调用方自述；不包含秘密。
	AuthMethods []authn.Method
	// StrongAuthVerifiedAt 是强认证完成时间；零值表示尚未完成强认证。管理访问
	// 由 Service.AuthorizeManagement 按 Options.StrongAuthMaxAge 校验新鲜度，本字段
	// 只表达“最近一次强认证时间”，不是永久授权。
	// 必须拒绝。MFA 未实现前不会出现非零值。
	StrongAuthVerifiedAt time.Time
	// CreatedAt/LastSeenAt/IdleExpiresAt/AbsoluteExpiresAt 是服务端时间线。
	CreatedAt         time.Time
	LastSeenAt        time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	// RowVersion 是会话行版本，供诊断与条件更新使用。
	RowVersion int64
}

// IsNormal 报告会话是否为完整认证会话。
func (s Session) IsNormal() bool {
	return s.Kind == KindNormal
}

// IsRestricted 报告会话是否为受限会话。
func (s Session) IsRestricted() bool {
	return s.Kind != KindNormal
}

// CanAccessBusiness 报告会话能否访问普通业务接口：只有完整认证会话可以。
func (s Session) CanAccessBusiness() bool {
	return s.IsNormal()
}

// CanAccessManagement 报告会话能否访问管理接口：必须是完整认证会话且已完成
// 强认证。MFA 未实现前该条件恒不成立，管理访问保持拒绝。
func (s Session) CanAccessManagement() bool {
	return s.IsNormal() && !s.StrongAuthVerifiedAt.IsZero()
}

// RecoverySessionRequest 是签发受限恢复会话（restricted/recovery）的请求。
//
// 安全边界：本结构只能由可信恢复流程（internal/recovery）在成功原子消费一枚恢复
// 代码之后构造。签发前必须通过注入的 RecoverySessionGate 复核恢复尝试仍然有效；
// 未注入 gate 时一律拒绝签发（fail-closed）。恢复会话不绑定应用、不携带强认证
// 时间、不允许记住我，绝对到期期限固定为短时（Options.RecoverySessionTTL）。
type RecoverySessionRequest struct {
	// UserID 是第一步密码认证已确认的账户稳定 ID。
	UserID string
	// SecurityVersion 是第一步认证结果携带的账户安全版本；签发前会与当前值
	// 交叉校验。
	SecurityVersion int64
	// AttemptID 是恢复流程的服务端尝试 ID（客户端不可见、不可自称）。
	AttemptID string
	// ExistingSession 是本次请求携带的旧会话秘密（可选，用于防会话固定轮换）。
	ExistingSession string
	// RequestID 可选，写入审计用于关联查询。
	RequestID string
	// Client 是设备列表展示用客户端描述；不参与授权。
	Client ClientInfo
}

// RecoverySessionGate 授权签发受限恢复会话。生产实现为 internal/recovery.Service：
// 只有恢复代码已原子消费且恢复尝试处于待绑定、未过期、尚未绑定会话时返回 nil。
// nil gate 表示未装配恢复流程，签发一律拒绝。
type RecoverySessionGate interface {
	AuthorizeRecoverySession(ctx context.Context, request RecoverySessionRequest) error
}

// IssuedSession 是签发结果。Secret 是“会话ID.秘密”形式的完整会话凭据（浏览器
// Cookie 值或嵌入式 API 令牌），CSRFSecret 是与会话绑定的 CSRF 令牌；两者都只在
// 本结果中出现一次，调用方必须立即投递（写 Cookie 或交给嵌入式调用方），不得写入
// 日志或普通存储。
type IssuedSession struct {
	Session    Session
	Secret     Secret
	CSRFSecret Secret
	// RotatedSessionID 是被本次登录轮换撤销的旧会话 ID（没有旧会话时为空）。
	RotatedSessionID string
}

// Secret 保存签发结果中只展示一次的会话秘密或 CSRF 令牌明文。
//
// 默认的字符串化、格式化与 JSON 序列化只输出脱敏标记；投递代码必须显式调用
// Reveal 取得副本，并自行限制副本在内存、日志与错误中的生命周期。本类型不是
// 内存清零或防内存取证的承诺。
type Secret struct {
	value string
}

// newSecret 构造已设置的秘密；只允许包内从安全随机源生成后调用。
func newSecret(value string) Secret {
	return Secret{value: value}
}

// IsSet 报告秘密是否有值；不暴露内容。
func (s Secret) IsSet() bool {
	return s.value != ""
}

// Reveal 返回秘密明文副本，用于写入 Cookie 或交给嵌入式调用方。调用方不得
// 记录、放入 URL、持久化到普通位置或转发给无必要的组件。
func (s Secret) Reveal() string {
	return s.value
}

// String 实现 fmt.Stringer，固定输出脱敏标记。
func (s Secret) String() string {
	if s.value == "" {
		return "[UNSET]"
	}
	return "[REDACTED]"
}

// GoString 实现 fmt.GoStringer，覆盖 %#v 输出。
func (s Secret) GoString() string {
	return s.String()
}

// Format 实现 fmt.Formatter，覆盖 %v、%s、%q、%x 等格式化动词。
func (s Secret) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte(s.String()))
}

// MarshalJSON 实现 json.Marshaler，输出脱敏标记。
func (s Secret) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

// LogValue 实现 slog.LogValuer，避免结构化日志泄露会话秘密。
func (s Secret) LogValue() slog.Value {
	return slog.StringValue(s.String())
}

// LoginRequest 是一次会话签发请求。
//
// Result 必须来自 internal/authn 的真实认证结果，不能由客户端标记伪造；本包会
// 重读账户状态与应用成员状态，并与 Result.SecurityVersion 交叉校验。
// ExistingSession 是客户端本次出示的旧会话秘密（浏览器 Cookie 值或嵌入式 API
// 等效值），用于登录成功后的会话固定防护：旧会话会在签发事务中被撤销。为空表示
// 没有旧会话。
type LoginRequest struct {
	Result authn.AuthenticateResult
	// AppID 是可选的应用上下文；非空时要求应用启用且目标账户是该应用的有效
	// 成员，并在每次校验时重新检查。
	AppID string
	// ExistingSession 是客户端出示的旧会话秘密。
	ExistingSession string
	// RequestID 可选，写入审计用于关联查询。
	RequestID string
	// RememberMe 表示使用更长的绝对到期（Options.RememberMeTimeout）。它只影响
	// 本次会话自身的绝对到期，不改变空闲到期，也不会越过服务端配置上限。
	RememberMe bool
	// Client 是可选的客户端描述，仅用于设备列表展示；其中 UserAgent 由客户端
	// 自称，Address 必须来自可信边界。两者都不是授权依据。
	Client ClientInfo
}

// LoginGrantRequest 是一次已由可信登录确认流程批准登录的**服务端事实**。它只能由
// 可信流程（如扫码登录领取）在验证一次性批准记录并原子消费后构造；客户端参数不能
// 直接填充这些字段。
//
// 安全边界：AuthMethods 必须来自确认端真实会话的认证方法快照；本类型不携带强认证
// 时间，领取登录结果不会继承确认端的强认证新鲜度（管理访问仍需本会话自己的强认证）。
type LoginGrantRequest struct {
	// GrantID 是服务端批准记录标识（如扫码请求 ID），用于审计关联与防重放。
	GrantID string
	// UserID 是批准用户的稳定 ID（来自确认端真实会话，不是客户端自述）。
	UserID string
	// SecurityVersion 是批准时账户安全版本快照；签发前重新核对。
	SecurityVersion int64
	// AppID 是登录结果的目标应用（必须与批准记录一致且非空）。
	AppID string
	// AuthMethods 是确认端会话真实完成的认证方法快照。
	AuthMethods []authn.Method
	// ExistingSession 是浏览器旧会话秘密（可选，用于防会话固定轮换）；
	// 领取流程通常不带旧会话。
	ExistingSession string
	// RequestID 是领取请求编号（用于审计关联）。
	RequestID string
	// Client 是设备列表展示用描述，不参与授权。
	Client ClientInfo
}

// LoginGrantGate 判定一次登录批准是否仍然有效并授权本次领取。实现必须：
//   - 重新读取服务端批准记录并核对 UserID/SecurityVersion/AppID/认证方法快照；
//   - 校验记录状态为已批准、未过期、未被领取/取消/拒绝；
//   - 复核确认端会话仍然有效（撤销/过期/账户/应用/成员变化即拒绝）；
//   - 以条件更新**原子消费**批准（并发领取只允许一个成功），并写安全审计。
//
// gate 返回非 nil 时签发一律拒绝；未提供 gate 时同样拒绝（fail-closed）。
type LoginGrantGate interface {
	AuthorizeLoginGrant(ctx context.Context, request LoginGrantRequest) error
}

// ClientInfo 是设备列表展示用的客户端描述。
//
// 安全边界：UserAgent 完全由客户端控制、可任意伪造，不能当作可信设备身份、设备
// 指纹或任何授权/风控依据；Address 是调用方从可信连接边界（或既有可信代理链）
// 取得的来源地址提示，不是绝对地理位置，也不能用于授权判断。服务端在写入前会
// 截断并去除控制字符；返回给用户时同样只作参考展示。
type ClientInfo struct {
	// UserAgent 是客户端自称的 User-Agent 摘要（已截断）。
	UserAgent string
	// Address 是可信边界给出的来源地址提示（已截断）。
	Address string
}

// DevicePolicy 是同一账户并发登录的设备策略。
type DevicePolicy string

const (
	// DevicePolicyMultiple 是默认多设备策略：允许同一账户在多个设备/会话并存，
	// 受 Options.MaxActiveSessions 数量约束。
	DevicePolicyMultiple DevicePolicy = "multiple"
	// DevicePolicySingle 是单设备策略：每次成功登录都会在同一审计事务中撤销该
	// 账户此前全部活动会话（撤销原因 replaced_single_device），再签发新会话。
	DevicePolicySingle DevicePolicy = "single"
)

// Valid 报告设备策略是否已定义。
func (p DevicePolicy) Valid() bool {
	return p == DevicePolicyMultiple || p == DevicePolicySingle
}

// ListOptions 是设备列表分页参数。Page 从 1 开始；PageSize 为 0 使用默认值。
type ListOptions struct {
	Page     int
	PageSize int
}

// SessionSummary 是设备列表返回的一条会话摘要。它绝不包含会话秘密、CSRF 令牌、
// 验证摘要或 Cookie 原文；Client 字段只作展示参考，不是可信设备身份。
type SessionSummary struct {
	// ID 是会话公开标识（ses_ 前缀），可用于指定退出。
	ID string
	// AppID 是会话绑定的应用上下文；空表示身份服务会话（不限于某个应用）。
	AppID string
	// Kind/Reason 是会话类别与受限原因。
	Kind   Kind
	Reason Reason
	// CreatedAt/LastSeenAt/IdleExpiresAt/AbsoluteExpiresAt 是服务端时间线。
	CreatedAt         time.Time
	LastSeenAt        time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	// RememberMe 表示签发时使用了更长的记住我绝对到期。
	RememberMe bool
	// Current 表示该条就是调用方当前出示的会话。
	Current bool
	// Client 是展示用客户端描述（UserAgent 不可信、Address 无地理含义）。
	Client ClientInfo
}

// SessionPage 是设备列表的一页结果。HasMore 表示还有下一页；Total 是当前筛选
// 条件下活动会话总数（用于分页指示，不含秘密）。
type SessionPage struct {
	Sessions []SessionSummary
	Page     int
	PageSize int
	Total    int64
	HasMore  bool
}

// AdminRevokeRequest 是管理员强制下线请求。
//
// ScopeAppID 为空表示系统范围（依据系统权限会话强制退出）；非空表示仅在该应用
// 范围强制下线，只能作用于绑定该应用的会话。TargetUserID 与 TargetSessionID
// 必须且只能给出一个。范围由服务端根据已授权的操作者与目标会话事实判定，绝不
// 采用客户端自称的额外范围字段。
type AdminRevokeRequest struct {
	ScopeAppID      string
	TargetUserID    string
	TargetSessionID string
	RequestID       string
}

// AdminRevokeResult 是管理员强制下线结果。Revoked 是实际撤销的活动会话数量；
// 目标不存在、已失效或超出作用范围时按幂等成功返回 0。
type AdminRevokeResult struct {
	Revoked int64
}

// Action 是可审计的会话操作动作。
type Action string

const (
	// ActionSessionIssue 是普通/受限会话签发（含登录轮换）。
	ActionSessionIssue Action = "session.issue"
	// ActionSessionLoginGrantIssued 是可信登录确认流程（如扫码登录）批准后签发会话。
	// 记录批准来源 ID 与用户/应用稳定 ID，不记录任何秘密。
	ActionSessionLoginGrantIssued Action = "session.login_grant_issued"
	// ActionSessionRevoke 是退出当前会话。
	ActionSessionRevoke Action = "session.revoke"
	// ActionSessionRevokeOwn 是用户指定退出自己的其他会话或退出全部自己的会话。
	ActionSessionRevokeOwn Action = "session.revoke_own"
	// ActionSessionAdminRevoke 是管理员按授权范围强制下线。
	ActionSessionAdminRevoke Action = "session.admin_revoke"
	// ActionSessionEviction 是并发登录上限或单设备策略触发的自动淘汰。
	ActionSessionEviction Action = "session.eviction"
	// ActionSessionAccountDisabledRevoke 是账户禁用流程触发的服务端批量退出。
	ActionSessionAccountDisabledRevoke Action = "session.account_disabled_revoke"
	// ActionSessionRestrictedDenied 是受限恢复会话尝试访问普通业务/管理接口被拒绝
	// 的失败审计动作（步骤 44）：越权必须拒绝且留痕，审计不可用不改变拒绝结果。
	ActionSessionRestrictedDenied Action = "session.restricted_denied"
)

// Valid 报告动作是否已定义。
func (a Action) Valid() bool {
	switch a {
	case ActionSessionIssue, ActionSessionLoginGrantIssued, ActionSessionRevoke,
		ActionSessionRevokeOwn, ActionSessionAdminRevoke, ActionSessionEviction,
		ActionSessionAccountDisabledRevoke, ActionSessionRestrictedDenied:
		return true
	default:
		return false
	}
}

// 领域错误哨兵。调用方用 errors.Is 判断，并可用 CodeOf 映射到根包错误码。
var (
	// ErrOptionsInvalid 表示服务或策略构造依赖不合法。
	ErrOptionsInvalid = errors.New("会话服务选项无效")
	// ErrInvalidRequest 表示请求参数、认证结果组合或目标标识不合法。
	ErrInvalidRequest = errors.New("会话请求无效")
	// ErrSessionInvalid 是统一的会话无效提示：未知、被撤销、空闲/绝对到期、
	// 秘密不匹配、账户禁用、安全版本变化、应用停用或成员失效都返回它；对外不
	// 区分具体原因，避免会话存在性与账户状态探测。
	ErrSessionInvalid = errors.New("会话无效或已过期")
	// ErrAccountNotEligible 表示签发时重读发现账户已不可用或安全版本已变化；
	// 对外与登录失败一致，不泄露账户状态。
	ErrAccountNotEligible = errors.New("无法完成登录")
	// ErrRestrictedSession 表示受限会话尝试访问普通业务或管理接口。
	ErrRestrictedSession = errors.New("会话权限不足")
	// ErrStrongAuthRequired 表示管理访问要求强认证但尚未完成（本步未实现 MFA）。
	ErrStrongAuthRequired = errors.New("需要完成强认证")
	// ErrRotationFailed 表示登录时旧会话的撤销未生效（并发撤销/状态竞争），
	// 为避免在未确认旧会话失效的情况下签发新会话而 fail-closed 拒绝本次登录。
	ErrRotationFailed = errors.New("无法安全轮换旧会话")
	// ErrAccessDenied 表示操作者无权执行会话管理操作（越权范围、受保护目标或
	// 缺少授权实现）。对调用方不说明目标是否存在。
	ErrAccessDenied = errors.New("无权执行会话管理操作")
	// ErrConcurrentLimit 表示并发登录数量约束在事务内复核失败；为避免突破上限
	// 而整体回滚、拒绝签发。
	ErrConcurrentLimit = errors.New("并发会话数量约束未满足")
	// ErrRecoveryNotAllowed 表示受限恢复会话签发被拒绝（未装配恢复流程、
	// 恢复尝试无效/过期/已绑定会话，或账户不允许恢复）。
	ErrRecoveryNotAllowed = errors.New("不允许签发受限恢复会话")
	// ErrLoginGrantDenied 表示登录批准缺失、已失效、已被领取或未通过验证；
	// 对外与普通登录失败一致（ACCESS_DENIED），不泄露批准记录状态细节。
	ErrLoginGrantDenied = errors.New("登录批准无效或已失效")
	// ErrStoreUnavailable 表示会话存储暂时不可用。
	ErrStoreUnavailable = errors.New("会话存储暂时不可用")
	// ErrAuditUnavailable 表示安全审计未能可靠写入，操作被拒绝。
	ErrAuditUnavailable = errors.New("关键操作未能可靠记录")
)

// ErrorCode 是根包错误码注册表中的稳定字符串值。internal 包不能 import 根包，
// 因此这里只保存与注册表一致的字面值；根包测试会核对它们确实已登记。
type ErrorCode string

const (
	// CodeReqInvalid 对应已登记的 REQ_INVALID。
	CodeReqInvalid ErrorCode = "REQ_INVALID"
	// CodeAuthFailed 对应已登记的 AUTH_FAILED。
	CodeAuthFailed ErrorCode = "AUTH_FAILED"
	// CodeAccessDenied 对应已登记的 ACCESS_DENIED。
	CodeAccessDenied ErrorCode = "ACCESS_DENIED"
	// CodeDBUnavailable 对应已登记的 DB_UNAVAILABLE。
	CodeDBUnavailable ErrorCode = "DB_UNAVAILABLE"
	// CodeAuditWriteFailed 对应已登记的 AUDIT_WRITE_FAILED。
	CodeAuditWriteFailed ErrorCode = "AUDIT_WRITE_FAILED"
	// CodeInternalError 对应已登记的 INTERNAL_ERROR。
	CodeInternalError ErrorCode = "INTERNAL_ERROR"
)

// CodeOf 把会话领域错误映射到已登记错误码。审计失败优先判定；未知错误一律视为
// 内部错误，避免把原始错误文本或数据库细节暴露成新的对外码。
func CodeOf(err error) ErrorCode {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrAuditUnavailable):
		return CodeAuditWriteFailed
	case errors.Is(err, ErrInvalidRequest):
		return CodeReqInvalid
	case errors.Is(err, ErrSessionInvalid), errors.Is(err, ErrAccountNotEligible),
		errors.Is(err, ErrRotationFailed), errors.Is(err, ErrConcurrentLimit):
		return CodeAuthFailed
	case errors.Is(err, ErrRestrictedSession), errors.Is(err, ErrStrongAuthRequired),
		errors.Is(err, ErrAccessDenied), errors.Is(err, ErrRecoveryNotAllowed),
		errors.Is(err, ErrLoginGrantDenied):
		return CodeAccessDenied
	case errors.Is(err, ErrStoreUnavailable):
		return CodeDBUnavailable
	default:
		return CodeInternalError
	}
}
