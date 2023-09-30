// Package authn 实现正式密码凭证、密码验证与认证结果。
//
// 背景与边界（对应步骤 29）：
//   - 密码使用成熟库 golang.org/x/crypto/argon2 生成的 Argon2id PHC 编码字符串
//     保存，包含算法版本、参数、随机盐与摘要；本包不自造密码学，也不保存明文
//     密码、可逆密文或与登录无关的秘密。参数有硬上下界并可随部署升级：登录成功
//     后发现旧哈希参数弱于当前策略时，会在审计事务中条件升级为新参数。
//   - 支持用户名登录，以及“配置允许”的已验证邮箱登录。邮箱登录标识必须存在
//     user_emails 行且 verified_at_ms 非空；未验证邮箱永远不能登录。邮箱注册与
//     验证入口由后续步骤实现，本包提供统一的规范化口径 NormalizeEmail 供写入方
//     复用，避免读写两套规则。
//   - 密码正确不等于完整登录：root 与持有高敏感系统权限（用户/应用/角色/权限/
//     审计/策略/恢复/会话管理等，含任意 root_only 权限）的账户要求强认证（MFA）；
//     自定义系统角色只要组合了这些权限同样命中，不依赖固定角色键。MFA 尚未实现，
//     因此这些账户的密码认证结果固定为 OutcomePendingSecondFactor、Restricted=true，
//     RequiredSteps 同时含“绑定强因素”与“完成第二因素”，只表示“已完成密码方法”，
//     不得据此发放完整业务或管理会话，也不返回任何伪造 Token。会话签发由下一步的
//     会话服务消费 AuthenticateResult 完成。
//   - 公开失败提示统一：账户不存在、密码错误、账户禁用/待删除、未设置密码、邮箱
//     未验证全部返回同一个 ErrAuthenticationFailed（AUTH_FAILED），只有内部审计
//     记录具体诊断原因；失败计数同样作用于不存在的标识，避免用限流差异探测账户
//     存在性。
//   - 失败限制：地址/操作维度使用 internal/ratelimit 的固定窗口失败预算（成功认证
//     不消耗）；账户维度使用有界的渐进延迟，临时锁定按“账户 + 来源前缀”生效且只
//     影响同一 IPv4/IPv6 /64 来源，成功认证后重置、锁定到期自动恢复，绝不永久锁号；
//     单一来源对不同标识的失败数还有上限，避免用唯一标识灌满跟踪表。失败状态只在
//     进程内保存（重启即恢复），第一版不承诺多实例共享。
//   - Argon2 派生与校验受有界并发槽位限制并有排队超时，HTTP 暴露后不会因并发密码
//     请求耗尽内存；超时按 RATE_LIMITED fail-closed。
//   - 不记录密码、哈希、盐或任何可复用秘密到日志/错误/审计：运行日志只记录账户
//     ID、内部原因码与计数；审计差异只记录安全版本、状态与哈希参数摘要。
//   - 调用者身份只能由可信边界通过 Caller 构造器建立；普通请求参数不能自称用户。
package authn

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

const (
	// MaxIdentifierBytes 是登录标识（用户名或邮箱）输入的字节上限。
	MaxIdentifierBytes = 320
	// MaxPasswordBytes 是密码输入与哈希输入的字节上限。它防止把超大输入带进
	// Argon2 计算；正常密码远小于该值。
	MaxPasswordBytes = 512
	// maxEmailLocalBytes/maxEmailDomainBytes 是邮箱两段的字节上限。
	maxEmailLocalBytes  = 64
	maxEmailDomainBytes = 253
)

// Method 是认证方法稳定标识。本步只实现 password；其余方法由后续步骤实现，
// 结果结构先保留稳定标识，但绝不能凭客户端传入的标记伪造完成状态。
type Method string

const (
	// MethodPassword 表示已通过正式密码验证。
	MethodPassword Method = "password"
	// MethodSecondFactor 是通用第二因素标识；新代码应按具体因素使用
	// MethodEmailOTP/MethodTOTP/MethodSecurityKey 以便强度与 amr 映射，不要再用
	// 本标识表达具体因素。
	MethodSecondFactor Method = "second_factor"
	// MethodPasskey 表示 Passkey/WebAuthn 凭证（主登录或第二步）通过。
	MethodPasskey Method = "passkey"
	// MethodEmailOTP 表示邮件验证码（弱持有因素，不构成强认证）。
	MethodEmailOTP Method = "email_otp"
	// MethodTOTP 表示 TOTP 验证器第二步通过（与密码组合为受控强认证）。
	MethodTOTP Method = "totp"
	// MethodSecurityKey 表示 FIDO2 安全密钥第二步通过（WebAuthn UV 时为强认证）。
	MethodSecurityKey Method = "security_key"
	// MethodRecoveryCode 表示恢复代码替代第二因素；后续步骤实现。
	MethodRecoveryCode Method = "recovery_code"
)

// Valid 报告方法标识是否已定义。
func (m Method) Valid() bool {
	switch m {
	case MethodPassword, MethodSecondFactor, MethodPasskey, MethodEmailOTP,
		MethodTOTP, MethodSecurityKey, MethodRecoveryCode:
		return true
	default:
		return false
	}
}

// StrongFactorPresence 报告账户是否已绑定可满足强认证的因素（TOTP 或
// Passkey/安全密钥）。authn 用它动态决定 RequiredSteps：已绑定强因素只需要完成
// 第二因素；未绑定才要求强因素初始化。nil 表示未知，按未绑定处理（保守，但不会
// 降级——初始化流程仍需受控授权）。
type StrongFactorPresence interface {
	HasStrongFactor(ctx context.Context, userID string) (bool, error)
}

// Step 是“完成登录前仍必须完成”的步骤稳定标识。会话服务据此降级为受限会话，
// 不得把不完整的认证结果当完整登录处理。
type Step string

const (
	// StepSecondFactor 表示还需要完成第二因素验证。
	StepSecondFactor Step = "second_factor"
	// StepPasswordChange 表示首次登录必须修改密码（must_change）。
	StepPasswordChange Step = "password_change"
	// StepStrongAuthSetup 表示账户要求强认证但尚未绑定可用的强因素。MFA 实现前
	// root 与持有高敏感系统权限（或自定义系统角色）的账户在密码正确后同时返回
	// 该步骤与 StepSecondFactor：必须先完成强因素绑定，再完成第二因素验证；绝不
	// 代表可以跳过强认证，也不得据此签发完整会话。
	StepStrongAuthSetup Step = "strong_auth_setup"
)

// Valid 报告步骤标识是否已定义。
func (s Step) Valid() bool {
	switch s {
	case StepSecondFactor, StepPasswordChange, StepStrongAuthSetup:
		return true
	default:
		return false
	}
}

// Outcome 是一次密码认证的结论类别。
type Outcome string

const (
	// OutcomeComplete 表示密码与当前策略要求的全部认证方法均已完成；会话服务
	// 仍需按自身规则签发会话，本包不直接返回 Token。
	OutcomeComplete Outcome = "complete"
	// OutcomePendingSecondFactor 表示密码正确但还缺强认证：账户要么尚未绑定强因素
	// （StepStrongAuthSetup），要么需要完成第二因素（StepSecondFactor）。MFA 尚未
	// 实现时管理账户只能停留在此状态，不能当完整登录。
	OutcomePendingSecondFactor Outcome = "pending_second_factor"
	// OutcomePendingPasswordChange 表示密码正确但账户要求先修改密码。
	OutcomePendingPasswordChange Outcome = "pending_password_change"
)

// Valid 报告结论类别是否已定义。
func (o Outcome) Valid() bool {
	switch o {
	case OutcomeComplete, OutcomePendingSecondFactor, OutcomePendingPasswordChange:
		return true
	default:
		return false
	}
}

// AuthenticateRequest 是一次密码认证请求。
//
// Identifier 是用户名或邮箱；ClientIP 必须由传输层从可信边界解析后传入（例如
// Forwarded 信任链校验后的客户端地址），绝不能直接取普通请求参数中的自称地址。
// 空 ClientIP 归入共享的 unknown 计数键，不会绕过限流；非法地址归入 invalid 键。
type AuthenticateRequest struct {
	// Identifier 是用户名或邮箱登录标识。
	Identifier string
	// Password 是明文密码，只用于本次验证；本包不保存、不记录。
	Password string
	// ClientIP 是可信客户端地址（IPv4/IPv6 文本）；用于地址维度限流。
	ClientIP string
	// RequestID 可选，写入审计用于关联查询。
	RequestID string
}

// AuthenticateResult 是密码认证结果。它不包含会话或 Token：会话签发由下一步
// 的会话服务根据 Outcome/RequiredSteps/Restricted 决定。
type AuthenticateResult struct {
	// UserID/Username 是已通过密码验证（或密码正确但尚未完整登录）的账户。
	UserID string
	// Username 是账户显示用户名。
	Username string
	// Outcome 是结论类别；调用方必须检查它，不能只看是否返回错误。
	Outcome Outcome
	// CompletedMethods 是本次已真实验证完成的认证方法（当前只可能是 password）。
	CompletedMethods []Method
	// CompletedAt 是完成这些方法的服务端时间。
	CompletedAt time.Time
	// RequiredSteps 是完成登录前仍必须完成的步骤；为空表示没有额外步骤。
	RequiredSteps []Step
	// Restricted 为 true 表示结果不得用于完整业务或管理访问，会话服务只能签发
	// 受限会话（例如等待 MFA 或强制改密）；本步不签发任何会话。
	Restricted bool
	// StrongAuthCompletedAt 是本次认证完成强认证（Passkey/安全密钥 UV，或
	// 密码+TOTP 受控组合）的服务端时间；零值表示未完成强认证。会话服务据此决定
	// 管理访问是否满足强认证要求；受限结果不得携带该时间。
	StrongAuthCompletedAt time.Time
	// PasswordUpgradeApplied 表示本次登录顺带把旧参数哈希升级为当前参数成功。
	PasswordUpgradeApplied bool
	// SecurityVersion 是认证时的账户安全版本，供会话服务绑定与失效判断。
	SecurityVersion int64
}

// IsComplete 报告结果是否为完整认证（仍不代表已签发会话）。
func (r AuthenticateResult) IsComplete() bool {
	return r.Outcome == OutcomeComplete
}

// IdentifierKind 是登录标识类别。
type IdentifierKind string

const (
	// IdentifierUsername 表示用户名登录。
	IdentifierUsername IdentifierKind = "username"
	// IdentifierEmail 表示已验证邮箱登录。
	IdentifierEmail IdentifierKind = "email"
)

// Identifier 是规范化后的登录标识。Display 保留便于审计/日志的最小展示形式
// （邮箱做脱敏后使用），Normalized 是唯一性比较口径。
type Identifier struct {
	// Kind 是标识类别。
	Kind IdentifierKind
	// Display 是展示值；写入日志/审计前仍需脱敏。
	Display string
	// Normalized 是 NFKC + Unicode 大小写折叠 + NFC 后的比较值。
	Normalized string
}

// ParseIdentifier 解析并规范化登录标识。包含 "@" 的标识按邮箱处理，否则按
// 用户名处理；格式不合法返回 ErrInvalidRequest。
//
// 认证服务对格式错误也按统一失败处理（不区分“格式错”与“不存在”），本函数
// 只负责边界校验，供内部规范化与测试使用。
func ParseIdentifier(raw string) (Identifier, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return Identifier{}, fmt.Errorf("%w: 登录标识不能为空", ErrInvalidRequest)
	}
	if len(trimmed) > MaxIdentifierBytes {
		return Identifier{}, fmt.Errorf("%w: 登录标识过长", ErrInvalidRequest)
	}
	if strings.Contains(trimmed, "@") {
		display, normalized, err := NormalizeEmail(trimmed)
		if err != nil {
			return Identifier{}, err
		}
		return Identifier{Kind: IdentifierEmail, Display: display, Normalized: normalized}, nil
	}
	display, normalized, err := NormalizeLoginUsername(trimmed)
	if err != nil {
		return Identifier{}, err
	}
	return Identifier{Kind: IdentifierUsername, Display: display, Normalized: normalized}, nil
}

// NormalizeLoginUsername 规范化登录用用户名：NFKC + 去首尾空白 + 长度 1～32 个
// 码点 + 禁止空白/控制字符；比较值再经过 Unicode 大小写折叠与 NFC。
//
// 它与账户创建的 NormalizeUsername 使用同一比较口径（NFKC + 大小写折叠 + NFC），
// 但不拒绝 root 等保留名：保留名只限制创建，不限制登录（root 必须能登录）。
func NormalizeLoginUsername(raw string) (display, normalized string, err error) {
	if !utf8.ValidString(raw) {
		return "", "", fmt.Errorf("%w: 用户名不是合法 UTF-8", ErrInvalidRequest)
	}
	trimmed := strings.TrimSpace(raw)
	canonical := strings.TrimSpace(norm.NFKC.String(trimmed))
	if canonical == "" {
		return "", "", fmt.Errorf("%w: 用户名不能为空", ErrInvalidRequest)
	}
	runes := []rune(canonical)
	if len(runes) > account.MaxUsernameRunes {
		return "", "", fmt.Errorf("%w: 用户名过长", ErrInvalidRequest)
	}
	for _, character := range runes {
		if character < 0x20 || character == 0x7f {
			return "", "", fmt.Errorf("%w: 用户名包含控制字符", ErrInvalidRequest)
		}
	}
	return canonical, normalizeKey(canonical), nil
}

// NormalizeEmail 规范化并校验邮箱登录标识。
//
// 规则（稳定契约，后续邮箱验证/变更步骤必须复用）：
//   - 先做 NFKC 兼容规范化并去掉首尾空白；总长度 ≤ 254 字节；
//   - 恰好一个 "@"；本地部分 1～64 字节，不以下划线以外的首尾点号开头/结尾，
//     不含连续点号与控制/空白字符；
//   - 域名部分 1～253 字节，由点号分隔的标签组成，标签非空、不以连字符开头/
//     结尾，允许 Unicode 字母与数字（国际化域名）；
//   - 比较值 = NFKC + Unicode 大小写折叠 + NFC；展示值保留规范化后的大小写。
func NormalizeEmail(raw string) (display, normalized string, err error) {
	if !utf8.ValidString(raw) {
		return "", "", fmt.Errorf("%w: 邮箱不是合法 UTF-8", ErrInvalidRequest)
	}
	canonical := strings.TrimSpace(norm.NFKC.String(strings.TrimSpace(raw)))
	if len(canonical) > 254 {
		return "", "", fmt.Errorf("%w: 邮箱过长", ErrInvalidRequest)
	}
	if strings.Count(canonical, "@") != 1 {
		return "", "", fmt.Errorf("%w: 邮箱格式无效", ErrInvalidRequest)
	}
	local, domain, _ := strings.Cut(canonical, "@")
	if err := validateEmailLocalPart(local); err != nil {
		return "", "", err
	}
	if err := validateEmailDomain(domain); err != nil {
		return "", "", err
	}
	return canonical, normalizeKey(canonical), nil
}

// validateEmailLocalPart 校验邮箱本地部分；规则见 NormalizeEmail。
func validateEmailLocalPart(local string) error {
	if local == "" || len(local) > maxEmailLocalBytes {
		return fmt.Errorf("%w: 邮箱本地部分长度无效", ErrInvalidRequest)
	}
	if strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") {
		return fmt.Errorf("%w: 邮箱本地部分点号位置无效", ErrInvalidRequest)
	}
	for _, character := range local {
		switch {
		case character >= 'a' && character <= 'z', character >= 'A' && character <= 'Z',
			character >= '0' && character <= '9':
			continue
		case strings.ContainsRune("!#$%&'*+/=?^_`{|}~.-", character):
			continue
		case character >= 0x80 && !isControlOrSpace(character):
			continue
		default:
			return fmt.Errorf("%w: 邮箱本地部分包含不允许的字符", ErrInvalidRequest)
		}
	}
	return nil
}

// validateEmailDomain 校验邮箱域名部分；不允许空白、控制字符与空标签。
func validateEmailDomain(domain string) error {
	if domain == "" || len(domain) > maxEmailDomainBytes {
		return fmt.Errorf("%w: 邮箱域名长度无效", ErrInvalidRequest)
	}
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if label == "" {
			return fmt.Errorf("%w: 邮箱域名包含空标签", ErrInvalidRequest)
		}
		runes := []rune(label)
		if runes[0] == '-' || runes[len(runes)-1] == '-' {
			return fmt.Errorf("%w: 邮箱域名标签不能以连字符开头或结尾", ErrInvalidRequest)
		}
		for _, character := range runes {
			switch {
			case character >= 'a' && character <= 'z', character >= 'A' && character <= 'Z',
				character >= '0' && character <= '9', character == '-':
				continue
			case character >= 0x80 && !isControlOrSpace(character):
				continue
			default:
				return fmt.Errorf("%w: 邮箱域名包含不允许的字符", ErrInvalidRequest)
			}
		}
	}
	return nil
}

// isControlOrSpace 报告字符是否为控制字符、空白或格式字符（禁止出现在标识中）。
func isControlOrSpace(character rune) bool {
	return character < 0x20 || character == 0x7f ||
		character == ' ' || character == '\t' || character == '\u00a0' ||
		character == '\u200b' || character == '\ufeff'
}

// normalizeKey 是登录标识比较值的统一口径：NFKC + Unicode 大小写折叠 + NFC。
// 它与 internal/account 的用户名唯一性口径一致，登录查询必须使用同一结果。
func normalizeKey(raw string) string {
	compatibility := norm.NFKC.String(raw)
	folded := cases.Fold().String(compatibility)
	return norm.NFC.String(folded)
}

// Action 是可审计的认证/密码操作动作。
type Action string

const (
	// ActionPasswordVerify 是密码认证尝试（成功、失败与限流拒绝都写审计）。
	ActionPasswordVerify Action = "auth.password.verify"
	// ActionPasswordSet 是可信管理员/系统/本人（带当前密码复核）设置密码。
	ActionPasswordSet Action = "auth.password.set"
	// ActionRootPasswordSet 是本地受控 root 首次设置正式密码。
	ActionRootPasswordSet Action = "auth.root.password.set"
	// ActionPasswordUpgrade 是登录时旧参数哈希的条件升级。
	ActionPasswordUpgrade Action = "auth.password.upgrade"
)

// Valid 报告动作是否已定义。
func (a Action) Valid() bool {
	switch a {
	case ActionPasswordVerify, ActionPasswordSet, ActionRootPasswordSet, ActionPasswordUpgrade:
		return true
	default:
		return false
	}
}

// 领域错误哨兵。调用方用 errors.Is 判断，并可用 CodeOf 映射到根包错误码。
var (
	// ErrOptionsInvalid 表示服务或策略构造依赖不合法。
	ErrOptionsInvalid = errors.New("认证服务选项无效")
	// ErrInvalidRequest 表示请求字段、标识、密码输入或目标用户 ID 不合法。
	ErrInvalidRequest = errors.New("认证请求无效")
	// ErrAuthenticationFailed 是统一公开失败提示：账户不存在、密码错误、账户
	// 不可用、未设置密码、邮箱未验证等一律返回它，对外不细分原因。
	ErrAuthenticationFailed = errors.New("无法完成登录")
	// ErrRateLimited 表示失败限制/限流拒绝；具体等待时间由 *RateLimitError 携带。
	ErrRateLimited = errors.New("请求过于频繁")
	// ErrWeakPassword 表示密码不满足长度/弱密码/包含标识信息等策略要求。
	ErrWeakPassword = errors.New("密码不符合安全策略")
	// ErrPasswordReused 表示新密码与当前或近期历史密码相同。
	ErrPasswordReused = errors.New("不能重复使用近期密码")
	// ErrUserNotFound 表示可信管理调用按稳定用户 ID 找不到用户。
	ErrUserNotFound = errors.New("用户不存在")
	// ErrAccessDenied 表示可信调用身份未获准执行该操作。
	ErrAccessDenied = errors.New("未获准执行该操作")
	// ErrNotInitialized 表示实例尚未完成 root 初始化，不能设置 root 密码。
	ErrNotInitialized = errors.New("实例尚未完成 root 初始化")
	// ErrSetupVerificationRequired 表示 root 仍处于 pending_setup：必须先通过
	// 一次性配置凭证完成受限配置校验，不能直接设置正式密码。
	ErrSetupVerificationRequired = errors.New("root 尚未完成一次性配置凭证兑换")
	// ErrSetupCompleted 表示 root 初始化已完成（ready），配置阶段的密码入口关闭。
	ErrSetupCompleted = errors.New("root 初始化已完成")
	// ErrSetupStateConflict 表示 root 受限状态不允许该操作或已被并发修改。
	ErrSetupStateConflict = errors.New("root 初始化状态不允许该操作")
	// ErrRecoveryStateConflict 表示找回改密在“事务外准备”与“事务内提交”之间账户或
	// 密码凭证状态已被并发修改（安全版本/凭据行版本变化、账户被禁用/删除/改为 root、
	// 密码被移除等），本次提交被拒绝。令牌未被消费，调用方可重试；对外映射 CONFLICT。
	ErrRecoveryStateConflict = errors.New("找回改密期间账户或密码凭证已被并发修改")
	// ErrStoreUnavailable 表示认证存储暂时不可用。
	ErrStoreUnavailable = errors.New("认证存储暂时不可用")
	// ErrAuditUnavailable 表示安全审计未能可靠写入，操作被拒绝。
	ErrAuditUnavailable = errors.New("关键操作未能可靠记录")
)

// RateLimitError 是带等待建议的限流/失败限制错误。它包装 ErrRateLimited，
// 调用方用 errors.As 读取 RetryAfter；Reason 是内部诊断原因，不得直接暴露。
type RateLimitError struct {
	// RetryAfter 是建议等待时间。
	RetryAfter time.Duration
	// Reason 是内部原因码（ip_limit/operation_limit/identifier_locked 等）。
	Reason string
}

// Error 实现 error；不包含账户存在性或限流维度细节。
func (e *RateLimitError) Error() string {
	return "认证尝试过于频繁，请稍后再试"
}

// Unwrap 返回 ErrRateLimited，便于 errors.Is 判断。
func (e *RateLimitError) Unwrap() error {
	return ErrRateLimited
}

// AsRateLimit 从错误链中提取等待时间与原因；非限流错误返回 (0, false)。
func AsRateLimit(err error) (time.Duration, string, bool) {
	var limitErr *RateLimitError
	if !errors.As(err, &limitErr) || limitErr == nil {
		return 0, "", false
	}
	return limitErr.RetryAfter, limitErr.Reason, true
}

// ErrorCode 是根包错误码注册表中的稳定字符串值。internal 包不能 import 根包，
// 因此这里只保存与注册表一致的字面值；根包测试会核对它们确实已登记。
type ErrorCode string

const (
	// CodeReqInvalid 对应已登记的 REQ_INVALID。
	CodeReqInvalid ErrorCode = "REQ_INVALID"
	// CodeConflict 对应已登记的 CONFLICT。
	CodeConflict ErrorCode = "CONFLICT"
	// CodeAuthFailed 对应已登记的 AUTH_FAILED。
	CodeAuthFailed ErrorCode = "AUTH_FAILED"
	// CodeRateLimited 对应已登记的 RATE_LIMITED。
	CodeRateLimited ErrorCode = "RATE_LIMITED"
	// CodeAccessDenied 对应已登记的 ACCESS_DENIED。
	CodeAccessDenied ErrorCode = "ACCESS_DENIED"
	// CodeDBUnavailable 对应已登记的 DB_UNAVAILABLE。
	CodeDBUnavailable ErrorCode = "DB_UNAVAILABLE"
	// CodeAuditWriteFailed 对应已登记的 AUDIT_WRITE_FAILED。
	CodeAuditWriteFailed ErrorCode = "AUDIT_WRITE_FAILED"
	// CodeInternalError 对应已登记的 INTERNAL_ERROR。
	CodeInternalError ErrorCode = "INTERNAL_ERROR"
)

// CodeOf 把认证领域错误映射到已登记错误码。审计失败优先判定；未知错误一律视为
// 内部错误，避免把原始错误文本或数据库细节暴露成新的对外码。
func CodeOf(err error) ErrorCode {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrAuditUnavailable):
		return CodeAuditWriteFailed
	case errors.Is(err, ErrRateLimited):
		return CodeRateLimited
	case errors.Is(err, ErrAuthenticationFailed):
		return CodeAuthFailed
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrWeakPassword),
		errors.Is(err, ErrPasswordReused), errors.Is(err, ErrUserNotFound),
		errors.Is(err, ErrNotInitialized):
		return CodeReqInvalid
	case errors.Is(err, ErrSetupVerificationRequired), errors.Is(err, ErrSetupCompleted),
		errors.Is(err, ErrSetupStateConflict), errors.Is(err, ErrRecoveryStateConflict):
		return CodeConflict
	case errors.Is(err, ErrAccessDenied):
		return CodeAccessDenied
	case errors.Is(err, ErrStoreUnavailable):
		return CodeDBUnavailable
	default:
		return CodeInternalError
	}
}

// Caller 是通过可信边界建立的操作者上下文。字段不导出：调用方只能通过构造器
// 建立，不能从请求参数或客户端字段直接伪造身份。
type Caller struct {
	actor     audit.Actor
	requestID string
}

// LocalAdminCaller 构造受限本地管理员操作者（audit.ActorLocalAdmin）。它用于
// root 初始密码设置与本地受控维护，不代表远程管理权限。
func LocalAdminCaller(operatorID string) (Caller, error) {
	actor := audit.Actor{Type: audit.ActorLocalAdmin, ID: operatorID}
	if err := actor.Validate(); err != nil {
		return Caller{}, fmt.Errorf("%w: 本地操作者标识无效", ErrInvalidRequest)
	}
	return Caller{actor: actor}, nil
}

// SystemCaller 构造系统组件操作者（audit.ActorSystem），用于受控创建账户时设置
// 初始密码等宿主内部流程；不能由普通请求参数构造。
func SystemCaller(componentID string) (Caller, error) {
	actor := audit.Actor{Type: audit.ActorSystem, ID: componentID}
	if err := actor.Validate(); err != nil {
		return Caller{}, fmt.Errorf("%w: 系统组件标识无效", ErrInvalidRequest)
	}
	return Caller{actor: actor}, nil
}

// UserCaller 构造已认证普通用户操作者（audit.ActorUser）。它只能用于变更本人
// 密码且必须提供当前密码复核；跨用户目标一律拒绝。
func UserCaller(userID string) (Caller, error) {
	if !account.ValidUserID(userID) {
		return Caller{}, fmt.Errorf("%w: 用户 ID 格式无效", ErrInvalidRequest)
	}
	actor := audit.Actor{Type: audit.ActorUser, ID: userID}
	if err := actor.Validate(); err != nil {
		return Caller{}, fmt.Errorf("%w: 用户标识无效", ErrInvalidRequest)
	}
	return Caller{actor: actor}, nil
}

// WithRequestID 返回带请求编号的调用者副本；非法编号返回 ErrInvalidRequest。
func (c Caller) WithRequestID(requestID string) (Caller, error) {
	if err := account.ValidateRequestID(requestID); err != nil {
		return Caller{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	c.requestID = requestID
	return c, nil
}

// actorKind 返回可信操作者类型，供服务内部判定调用通道（不导出，避免调用方以
// 类型比较代替授权）。
func (c Caller) actorKind() audit.ActorKind {
	return c.actor.Type
}

// actorID 返回可信操作者稳定 ID。
func (c Caller) actorID() string {
	return c.actor.ID
}
