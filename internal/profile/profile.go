package profile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

const (
	// MaxProfileJSONBytes 是资料 JSON 请求体大小上限。
	MaxProfileJSONBytes = 16 * 1024
	// DefaultRenameCooldown 是更名默认冷却时间。
	DefaultRenameCooldown = 24 * time.Hour
	// MaxRenameCooldown 是更名冷却时间上限（90 天）。
	MaxRenameCooldown = 90 * 24 * time.Hour
	// DefaultPhoneRegion 是电话默认国家/地区（ISO 3166-1 alpha-2）。
	DefaultPhoneRegion = "CN"
	// MaxPhoneDigits 是 E.164 号码最大位数。
	MaxPhoneDigits = 15
	// MinPhoneDigits 是 E.164 号码最小位数。
	MinPhoneDigits = 8
)

// 领域错误哨兵。
var (
	ErrOptionsInvalid       = errors.New("资料服务选项无效")
	ErrInvalidRequest       = errors.New("资料请求无效")
	ErrAccessDenied         = errors.New("未获准修改该资料")
	ErrUserNotFound         = errors.New("用户不存在")
	ErrVersionConflict      = errors.New("资料已被其他操作修改")
	ErrUsernameTaken        = errors.New("用户名已被占用")
	ErrRenameTooSoon        = errors.New("更名过于频繁")
	ErrRenameReauthRequired = errors.New("更名需要再次验证")
	ErrPhoneInvalid         = errors.New("电话号码格式无效")
	ErrStoreUnavailable     = errors.New("资料存储暂时不可用")
	ErrAuditUnavailable     = errors.New("关键操作未能可靠记录")
)

// ErrorCode 是资料领域对根包错误码注册表的投影（只复用既有码）。
type ErrorCode string

const (
	CodeReqInvalid       ErrorCode = "REQ_INVALID"
	CodeAccessDenied     ErrorCode = "ACCESS_DENIED"
	CodeConflict         ErrorCode = "CONFLICT"
	CodeReauthRequired   ErrorCode = "REAUTH_REQUIRED"
	CodeChallengeInvalid ErrorCode = "CHALLENGE_INVALID"
	CodeRateLimited      ErrorCode = "RATE_LIMITED"
	CodeDBUnavailable    ErrorCode = "DB_UNAVAILABLE"
	CodeAuditWriteFailed ErrorCode = "AUDIT_WRITE_FAILED"
	CodeInternalError    ErrorCode = "INTERNAL_ERROR"
)

// CodeOf 把资料领域错误映射为根包已登记错误码。
func CodeOf(err error) ErrorCode {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrPhoneInvalid):
		return CodeReqInvalid
	case errors.Is(err, ErrAccessDenied):
		return CodeAccessDenied
	case errors.Is(err, ErrVersionConflict), errors.Is(err, ErrUsernameTaken):
		return CodeConflict
	case errors.Is(err, ErrRenameTooSoon):
		return CodeRateLimited
	case errors.Is(err, ErrRenameReauthRequired):
		return CodeReauthRequired
	case errors.Is(err, ErrUserNotFound):
		return CodeChallengeInvalid
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

// UserProfile 是用户全局资料快照（不含邮箱验证/密码/MFA/角色等敏感字段）。
type UserProfile struct {
	UserID string
	// IsRoot 表示唯一 root 账户；更名等受保护操作据此拒绝普通资料流程。
	IsRoot             bool
	Username           string
	UsernameNormalized string
	Nickname           string
	Biography          string
	Language           string
	Timezone           string
	Phone              string
	// PhoneVerified 在本版恒为 false：电话从不作为已验证登录或恢复依据。
	PhoneVerified bool
	RowVersion    int64
	// UsernameChangedAt 是最近一次更名时间；零值表示从未更名。
	UsernameChangedAt time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// ProfileChange 是资料更新字段白名单；nil 表示该字段不变，Phone 指向空字符串表示
// 清除电话。它刻意不包含 username/password/status/is_root/email_verified/mfa/roles。
type ProfileChange struct {
	Nickname  *string `json:"nickname"`
	Biography *string `json:"biography"`
	Language  *string `json:"language"`
	Timezone  *string `json:"timezone"`
	Phone     *string `json:"phone"`
}

// HasChanges 报告是否至少设置了一个字段。
func (c ProfileChange) HasChanges() bool {
	return c.Nickname != nil || c.Biography != nil || c.Language != nil ||
		c.Timezone != nil || c.Phone != nil
}

// ParseProfileJSON 严格解析资料更新 JSON：拒绝未知字段（例如 is_root、password、
// email_verified、mfa、roles、status）与多余内容，并限制请求体大小。
func ParseProfileJSON(data []byte) (ProfileChange, error) {
	if len(data) == 0 {
		return ProfileChange{}, fmt.Errorf("%w: 请求体为空", ErrInvalidRequest)
	}
	if len(data) > MaxProfileJSONBytes {
		return ProfileChange{}, fmt.Errorf("%w: 资料请求超过 %d 字节", ErrInvalidRequest, MaxProfileJSONBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var change ProfileChange
	if err := decoder.Decode(&change); err != nil {
		return ProfileChange{}, fmt.Errorf("%w: 资料请求包含未知字段或类型错误", ErrInvalidRequest)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ProfileChange{}, fmt.Errorf("%w: 资料请求只能包含一个 JSON 对象", ErrInvalidRequest)
	}
	return change, nil
}

// ChangeUsernameRequest 是受控更名请求。ExpectedRowVersion 是并发保护。
type ChangeUsernameRequest struct {
	TargetUserID       string
	NewUsername        string
	ExpectedRowVersion int64
	RequestID          string
}

// UpdateRequest 是资料更新请求（本人或管理员）。
type UpdateRequest struct {
	TargetUserID       string
	Change             ProfileChange
	ExpectedRowVersion int64
	RequestID          string
}

// Policy 是更名与电话策略配置。三个敏感项使用显式三态：nil 表示沿用安全默认，
// 显式值（包括 false/0）才覆盖默认，避免“只配了一个字段就静默关掉另一个保护”。
type Policy struct {
	// RenameCooldown 为 nil 时使用 DefaultRenameCooldown；显式 0 表示关闭冷却。
	RenameCooldown *time.Duration
	// RequireReauth 为 nil 时默认 true（要求再次验证）；显式 false 才关闭。
	RequireReauth *bool
	// PhoneRegion 为空时使用 DefaultPhoneRegion。
	PhoneRegion string
	// ReservedNames 是追加到默认保留名之上的自定义保留名（规范化后比较）。
	// 只有显式 DisableReservedNames 才会完全不检查默认保留名。
	ReservedNames []string
	// DisableReservedNames 为 true 时完全关闭保留名检查（受控配置，不推荐）。
	DisableReservedNames bool
}

// DefaultPolicy 返回安全默认策略（24 小时冷却、要求再次验证、CN 电话地区）。
func DefaultPolicy() Policy {
	cooldown := DefaultRenameCooldown
	requireReauth := true
	return Policy{RenameCooldown: &cooldown, RequireReauth: &requireReauth, PhoneRegion: DefaultPhoneRegion}
}

// resolvedPolicy 是合并默认值后的有效策略。
type resolvedPolicy struct {
	renameCooldown time.Duration
	requireReauth  bool
	phoneRegion    string
	// reserved 为 nil 表示沿用 account 默认保留名；非 nil 为完整规范集合。
	reserved []string
}

// resolve 逐字段合并默认值并校验；任一非法配置返回 ErrOptionsInvalid。
func (p Policy) resolve() (resolvedPolicy, error) {
	cooldown := DefaultRenameCooldown
	if p.RenameCooldown != nil {
		cooldown = *p.RenameCooldown
	}
	requireReauth := true
	if p.RequireReauth != nil {
		requireReauth = *p.RequireReauth
	}
	region := p.PhoneRegion
	if region == "" {
		region = DefaultPhoneRegion
	}
	if cooldown < 0 || cooldown > MaxRenameCooldown {
		return resolvedPolicy{}, fmt.Errorf("%w: 更名冷却必须在 0～%s 之间", ErrOptionsInvalid, MaxRenameCooldown)
	}
	if _, ok := callingCodes[region]; !ok {
		return resolvedPolicy{}, fmt.Errorf("%w: 不支持的电话默认地区 %q", ErrOptionsInvalid, region)
	}
	resolved := resolvedPolicy{
		renameCooldown: cooldown,
		requireReauth:  requireReauth,
		phoneRegion:    region,
	}
	switch {
	case p.DisableReservedNames:
		resolved.reserved = []string{}
	case p.ReservedNames == nil:
		resolved.reserved = nil
	default:
		reserved := account.ReservedUsernames()
		for _, raw := range p.ReservedNames {
			_, normalized, err := account.NormalizeUsernameWithReserved(raw, []string{})
			if err != nil {
				return resolvedPolicy{}, fmt.Errorf("%w: 自定义保留名 %q 不是合法用户名", ErrOptionsInvalid, raw)
			}
			reserved = append(reserved, normalized)
		}
		resolved.reserved = reserved
	}
	return resolved, nil
}

// Validate 校验策略范围与保留名配置；失败保守，不使用未经验证的宽松解释。
func (p Policy) Validate() error {
	_, err := p.resolve()
	return err
}

// callingCodes 是受支持的 ISO 3166-1 alpha-2 到国际电话区号映射。
var callingCodes = map[string]string{
	"CN": "+86", "US": "+1", "CA": "+1", "GB": "+44", "JP": "+81",
	"KR": "+82", "HK": "+852", "TW": "+886", "SG": "+65", "AU": "+61",
	"DE": "+49", "FR": "+33",
}

// NormalizePhone 把号码规范化为 E.164（+国家码 + 数字，8～15 位）。空字符串表示
// 清除电话，返回 ("", nil)。本函数只做格式规范化，不代表号码已验证。
func NormalizePhone(raw, region string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", nil
	}
	if region == "" {
		region = DefaultPhoneRegion
	}
	var builder strings.Builder
	for _, character := range value {
		switch {
		case character >= '0' && character <= '9':
			builder.WriteRune(character)
		case character == '+' || character == '-' || character == ' ' || character == '.' ||
			character == '(' || character == ')':
			if character == '+' {
				builder.WriteRune('+')
			}
		default:
			return "", fmt.Errorf("%w: 号码包含非法字符", ErrPhoneInvalid)
		}
	}
	cleaned := builder.String()
	if strings.Count(cleaned, "+") > 1 {
		return "", fmt.Errorf("%w: 号码包含多个 +", ErrPhoneInvalid)
	}
	switch {
	case strings.HasPrefix(cleaned, "+"):
		cleaned = "+" + strings.TrimPrefix(cleaned, "+")
	case strings.HasPrefix(cleaned, "00"):
		cleaned = "+" + strings.TrimPrefix(cleaned, "00")
	default:
		code, ok := callingCodes[region]
		if !ok {
			return "", fmt.Errorf("%w: 无法确定默认地区区号", ErrPhoneInvalid)
		}
		cleaned = code + strings.TrimPrefix(cleaned, "0")
	}
	digits := strings.TrimPrefix(cleaned, "+")
	if len(digits) < MinPhoneDigits || len(digits) > MaxPhoneDigits {
		return "", fmt.Errorf("%w: 号码长度必须在 %d～%d 位数字之间", ErrPhoneInvalid,
			MinPhoneDigits, MaxPhoneDigits)
	}
	if digits[0] == '0' {
		return "", fmt.Errorf("%w: 号码不能以 0 开头", ErrPhoneInvalid)
	}
	for index := 0; index < len(digits); index++ {
		if digits[index] < '0' || digits[index] > '9' {
			return "", fmt.Errorf("%w: 号码包含非法字符", ErrPhoneInvalid)
		}
	}
	return "+" + digits, nil
}

// MaskPhone 把电话脱敏为审计可用值；号码只保留不可逆的 [REDACTED]，避免审计
// 差异成为电话明文副本。
func MaskPhone(phone string) string {
	if phone == "" {
		return ""
	}
	return "[REDACTED]"
}

// Authorizer 判定调用者能否读取/修改目标资料。实现应默认拒绝；未注入时服务使用
// 仅允许本人与受信 system/local_admin 的默认口径。
type Authorizer interface {
	AuthorizeProfile(ctx context.Context, caller Caller, target UserProfile, write bool) error
}

// ReauthVerifier 是更名前的再次验证契约（密码/强认证由宿主实现）。返回 nil 表示
// 验证通过；未注入时普通用户更名在 RequireReauth 下一律拒绝。
type ReauthVerifier interface {
	VerifyReauth(ctx context.Context, caller Caller, targetUserID string) error
}

// AuthorizerFunc 是 Authorizer 的函数适配器（宿主装配或测试）。
type AuthorizerFunc func(ctx context.Context, caller Caller, target UserProfile, write bool) error

// AuthorizeProfile 实现 Authorizer。
func (f AuthorizerFunc) AuthorizeProfile(ctx context.Context, caller Caller, target UserProfile, write bool) error {
	if f == nil {
		return ErrAccessDenied
	}
	return f(ctx, caller, target, write)
}

// ReauthVerifierFunc 是 ReauthVerifier 的函数适配器（宿主装配或测试）。
type ReauthVerifierFunc func(ctx context.Context, caller Caller, targetUserID string) error

// VerifyReauth 实现 ReauthVerifier。
func (f ReauthVerifierFunc) VerifyReauth(ctx context.Context, caller Caller, targetUserID string) error {
	if f == nil {
		return ErrRenameReauthRequired
	}
	return f(ctx, caller, targetUserID)
}
