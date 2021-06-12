// Package authfact 统一定义认证方法、认证事实（facts）与强度/组合语义，并提供
// 未来 OAuth/OIDC amr/acr 映射与“只选实际启用且满足策略的方式”的选择器。
//
// 背景与安全不变量：
//   - 认证方式包括密码、邮件验证码、TOTP、Passkey 主登录与 FIDO2 安全密钥（第二步）。
//     这些方式强度不同：邮件验证码只是弱持有因素，不能单独满足高权限账户的强认证；
//     Passkey/安全密钥完成用户验证（UV）时同时具备持有与用户在场/验证，可作为强
//     认证；密码+TOTP（两个不同因素类别）可作为强认证的受控备用，但邮件不得作为
//     强认证的唯一第二因素，也不得用于降级。
//   - “同一因素验证两遍不计为两个独立因素”：事实集合按稳定因素标识去重（密码/邮件/
//     TOTP 按方法，Passkey/安全密钥按调用方提供的认证器引用摘要），重复验证只更新
//     时间，不增加独立因素数量。
//   - 认证强度不机械相加：Strength 由“已完成的真实方法集合”推导，单次 Passkey UV
//     已可满足强认证；不存在“两个弱邮件验证码等于强认证”的组合。
//   - 本包只做内部事实与映射函数，不实现 OAuth/OIDC 端点，不读取数据库，不信任
//     客户端传入的“已完成”标记（调用方必须只把真实验证结果写入 Fact）。
package authfact

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// 领域错误哨兵。
var (
	// ErrNoAvailableMethod 表示没有用户实际启用且满足策略的认证方式。
	ErrNoAvailableMethod = errors.New("没有可用且满足策略的认证方式")
	// ErrUnsupportedMethod 表示方法未实现/不被策略允许。
	ErrUnsupportedMethod = errors.New("不支持的认证方式")
	// ErrInvalidFact 表示事实缺少可信来源或时间。
	ErrInvalidFact = errors.New("认证事实无效")
)

// Method 是认证方法稳定标识。
type Method string

const (
	// MethodPassword 是正式密码验证。
	MethodPassword Method = "password"
	// MethodEmailOTP 是邮件验证码第二步。
	MethodEmailOTP Method = "email_otp"
	// MethodTOTP 是 TOTP 验证器第二步。
	MethodTOTP Method = "totp"
	// MethodPasskey 是 Passkey（主登录或第二步的 WebAuthn 凭证）。
	MethodPasskey Method = "passkey"
	// MethodSecurityKey 是 FIDO2 安全密钥第二步验证（硬件/外部认证器）。
	MethodSecurityKey Method = "security_key"
	// MethodRecoveryCode 是恢复代码（后续步骤实现，标识保留）。
	MethodRecoveryCode Method = "recovery_code"
)

// Valid 报告方法是否已定义。
func (m Method) Valid() bool {
	switch m {
	case MethodPassword, MethodEmailOTP, MethodTOTP, MethodPasskey,
		MethodSecurityKey, MethodRecoveryCode:
		return true
	default:
		return false
	}
}

// FactorCategory 是因素类别（知识/持有/固有），用于“独立因素”计数。
type FactorCategory string

const (
	// CategoryKnowledge 是用户知道的东西（密码）。
	CategoryKnowledge FactorCategory = "knowledge"
	// CategoryPossession 是用户持有的东西（验证器、安全密钥、邮箱）。
	CategoryPossession FactorCategory = "possession"
	// CategoryInherence 是用户本身的特征（平台生物识别）。
	CategoryInherence FactorCategory = "inherence"
)

// CategoryOf 返回方法的因素类别。
func CategoryOf(method Method) (FactorCategory, bool) {
	switch method {
	case MethodPassword:
		return CategoryKnowledge, true
	case MethodEmailOTP, MethodTOTP:
		return CategoryPossession, true
	case MethodPasskey, MethodSecurityKey:
		return CategoryPossession, true
	case MethodRecoveryCode:
		return CategoryPossession, true
	default:
		return "", false
	}
}

// Strength 是认证事实组合达到的强度等级。
type Strength int

const (
	// StrengthNone 表示没有有效认证事实。
	StrengthNone Strength = iota
	// StrengthSingle 表示单因素（如仅密码或仅邮件）。
	StrengthSingle
	// StrengthMFA 表示两个独立因素（如密码+邮件/TOTP）。
	StrengthMFA
	// StrengthStrong 是强认证：Passkey/安全密钥完成 UV，或密码+TOTP 的
	// 受控备用组合；邮件不能单独构成强认证。
	StrengthStrong
)

// Valid 报告强度等级是否已定义。
func (s Strength) Valid() bool { return s >= StrengthNone && s <= StrengthStrong }

// String 返回稳定文本标识（用于审计/诊断）。
func (s Strength) String() string {
	switch s {
	case StrengthNone:
		return "none"
	case StrengthSingle:
		return "single"
	case StrengthMFA:
		return "mfa"
	case StrengthStrong:
		return "strong"
	default:
		return "unknown"
	}
}

// Fact 是一条真实完成的认证事实。调用方只能把服务端真实验证结果写入本结构；
// 客户端提交的“已完成”标记不能构造 Fact。
type Fact struct {
	// Method 是认证方法。
	Method Method
	// VerifiedAt 是该次真实验证完成时间（服务端时钟）。
	VerifiedAt time.Time
	// UserVerified 表示该方法本次是否完成用户验证（Passkey/安全密钥 UV）；
	// 密码/TOTP/邮件为 false。
	UserVerified bool
	// AuthenticatorID 是 Passkey/安全密钥认证器的稳定不可逆引用（调用方用
	// 摘要/随机凭证 ID，而不是原始凭证 ID），用于“同一认证器不重复计因素”。
	AuthenticatorID string
}

// Valid 报告事实是否具备可信时间与已定义方法。
func (f Fact) Valid() bool {
	return f.Method.Valid() && !f.VerifiedAt.IsZero()
}

// factorKey 返回因素去重键：密码/邮件/TOTP 按方法，Passkey/安全密钥按认证器引用；
// 缺少认证器引用时退回方法级去重（保守，不增加独立因素）。
func (f Fact) factorKey() string {
	switch f.Method {
	case MethodPasskey, MethodSecurityKey:
		if f.AuthenticatorID != "" {
			return "authenticator:" + f.AuthenticatorID
		}
		return string(f.Method)
	default:
		return string(f.Method)
	}
}

// Set 是一次认证会话中已完成的事实集合；重复同因素只保留最近时间。
type Set struct {
	facts []Fact
}

// NewSet 校验并构造事实集合；非法事实被拒绝（fail-closed）。
func NewSet(facts ...Fact) (Set, error) {
	set := Set{facts: make([]Fact, 0, len(facts))}
	for _, fact := range facts {
		if !fact.Valid() {
			return Set{}, ErrInvalidFact
		}
		set = set.added(fact)
	}
	return set, nil
}

// MustSet 是测试/内部可信路径的便捷构造；非法事实 panic，仅供已校验来源使用。
func MustSet(facts ...Fact) Set {
	set, err := NewSet(facts...)
	if err != nil {
		panic(err)
	}
	return set
}

// Added 返回加入一条事实后的新集合（不改原集合）。
func (s Set) Added(fact Fact) (Set, error) {
	if !fact.Valid() {
		return Set{}, ErrInvalidFact
	}
	return s.added(fact), nil
}

func (s Set) added(fact Fact) Set {
	key := fact.factorKey()
	result := make([]Fact, 0, len(s.facts)+1)
	replaced := false
	for _, existing := range s.facts {
		if existing.factorKey() == key {
			// 同一因素重复验证只更新时间/UV，不增加独立因素。
			merged := existing
			if fact.VerifiedAt.After(existing.VerifiedAt) || existing.VerifiedAt.IsZero() {
				merged.VerifiedAt = fact.VerifiedAt
			}
			merged.UserVerified = existing.UserVerified || fact.UserVerified
			result = append(result, merged)
			replaced = true
			continue
		}
		result = append(result, existing)
	}
	if !replaced {
		result = append(result, fact)
	}
	return Set{facts: result}
}

// Facts 返回事实副本。
func (s Set) Facts() []Fact { return append([]Fact(nil), s.facts...) }

// Empty 报告集合是否为空。
func (s Set) Empty() bool { return len(s.facts) == 0 }

// Methods 返回去重后的方法列表（稳定顺序：按首次出现）。
func (s Set) Methods() []Method {
	seen := make(map[Method]bool, len(s.facts))
	methods := make([]Method, 0, len(s.facts))
	for _, fact := range s.facts {
		if seen[fact.Method] {
			continue
		}
		seen[fact.Method] = true
		methods = append(methods, fact.Method)
	}
	return methods
}

// Has 报告是否包含指定方法的有效事实。
func (s Set) Has(method Method) bool {
	for _, fact := range s.facts {
		if fact.Method == method {
			return true
		}
	}
	return false
}

// DistinctFactors 返回独立因素数量：按因素去重键统计，同一因素两遍仍为 1。
func (s Set) DistinctFactors() int {
	seen := make(map[string]bool, len(s.facts))
	for _, fact := range s.facts {
		seen[fact.factorKey()] = true
	}
	return len(seen)
}

// DistinctCategories 返回已完成的因素类别集合。
func (s Set) DistinctCategories() []FactorCategory {
	seen := make(map[FactorCategory]bool, 3)
	for _, fact := range s.facts {
		if category, ok := CategoryOf(fact.Method); ok {
			seen[category] = true
		}
	}
	categories := make([]FactorCategory, 0, len(seen))
	for _, category := range []FactorCategory{CategoryKnowledge, CategoryPossession, CategoryInherence} {
		if seen[category] {
			categories = append(categories, category)
		}
	}
	return categories
}

// Strength 按事实集合推导实际强度。
//
// 规则（刻意保守，不机械相加）：
//   - 空集合 none；只有一个独立因素单因素 single；
//   - Passkey/安全密钥本次完成 UV → 强认证（单凭证即多因素：持有+用户验证）；
//   - 密码 + TOTP 两个类别 → 强认证的受控备用（TOTP 是真实持有因素）；
//   - 其余两个及以上独立因素 → MFA；任何包含邮件验证码的组合最多 MFA，永不
//     单独构成强认证。
func (s Set) Strength() Strength {
	if len(s.facts) == 0 {
		return StrengthNone
	}
	if s.hasVerifiedWebAuthn() {
		return StrengthStrong
	}
	if s.Has(MethodPassword) && s.Has(MethodTOTP) {
		return StrengthStrong
	}
	if s.DistinctFactors() >= 2 {
		return StrengthMFA
	}
	return StrengthSingle
}

// hasVerifiedWebAuthn 报告是否存在本次完成 UV 的 Passkey/安全密钥事实。
func (s Set) hasVerifiedWebAuthn() bool {
	for _, fact := range s.facts {
		if (fact.Method == MethodPasskey || fact.Method == MethodSecurityKey) && fact.UserVerified {
			return true
		}
	}
	return false
}

// Requirement 是策略对认证方式的要求。
type Requirement struct {
	// Minimum 是要求的最低组合强度。
	Minimum Strength
	// RequireUserVerification 表示要求 WebAuthn 类方法完成用户验证（UV）才可
	// 作为满足项；仅对要求强认证的策略有意义。
	RequireUserVerification bool
}

// Satisfies 报告事实集合是否满足策略要求。
func (s Set) Satisfies(requirement Requirement) bool {
	if requirement.Minimum == StrengthNone {
		return true
	}
	strength := s.Strength()
	if strength < requirement.Minimum {
		return false
	}
	if requirement.RequireUserVerification && requirement.Minimum >= StrengthStrong && !s.hasVerifiedWebAuthn() {
		return false
	}
	return true
}

// Available 是用户当前“实际启用”的一种认证方式（由可信服务查询得出）。
type Available struct {
	// Method 是方式标识。
	Method Method
	// Enabled 表示该方式当前对该用户可用（已绑定/已启用，不含仅保留标识）。
	Enabled bool
	// SupportsUserVerification 表示该方式本次可完成 UV（Passkey/安全密钥）。
	SupportsUserVerification bool
	// Reference 是方式的稳定引用（如凭证/绑定 ID 摘要），用于诊断，不包含秘密。
	Reference string
}

// Select 从用户实际启用的方式中选择满足策略的一个，优先级按传入顺序；不会返回
// 未启用、未实现或会让策略降级的方式。facts 是“已经完成”的事实（例如密码），
// 用于计算加入候选后的组合强度。
//
// 明确规则：
//   - 要求强认证（StrengthStrong）时，邮件验证码不是合格方式；
//   - 要求 UV 的强认证只接受能完成 UV 的 WebAuthn 方式；
//   - 没有候选满足时返回 ErrNoAvailableMethod（不降级、不猜测）。
func Select(facts Set, available []Available, requirement Requirement) (Available, error) {
	if !requirement.Minimum.Valid() {
		return Available{}, ErrUnsupportedMethod
	}
	for _, candidate := range available {
		if !candidate.Enabled || !candidate.Method.Valid() {
			continue
		}
		if candidate.Method == MethodRecoveryCode {
			// 恢复代码流程属后续步骤，不在选择器里假装可用。
			continue
		}
		if requirement.Minimum >= StrengthStrong {
			if candidate.Method == MethodEmailOTP {
				continue
			}
			if requirement.RequireUserVerification && !candidate.SupportsUserVerification {
				// 显式要求 UV 时只接受能完成用户验证的 WebAuthn 方式；密码+TOTP
				// 只有在策略未要求 UV 时才可作为受控备用。
				continue
			}
		}
		if !wouldSatisfy(facts, candidate, requirement) {
			continue
		}
		return candidate, nil
	}
	return Available{}, ErrNoAvailableMethod
}

// Eligible 返回可用且不会导致策略降级的候选列表（顺序保持传入顺序）；供认证方式
// 列表/备用方式展示使用。规则与 Select 一致：强认证不接受邮件；显式 UV 要求只接受
// 可完成 UV 的方式（密码+TOTP 受控组合除外）。
func Eligible(facts Set, available []Available, requirement Requirement) []Available {
	result := make([]Available, 0, len(available))
	for _, candidate := range available {
		if !candidate.Enabled || !candidate.Method.Valid() {
			continue
		}
		if candidate.Method == MethodRecoveryCode {
			continue
		}
		if requirement.Minimum >= StrengthStrong {
			if candidate.Method == MethodEmailOTP {
				continue
			}
			if requirement.RequireUserVerification && !candidate.SupportsUserVerification {
				continue
			}
		}
		if !wouldSatisfy(facts, candidate, requirement) {
			continue
		}
		result = append(result, candidate)
	}
	return result
}

// wouldSatisfy 计算把候选方法加入已完成事实后是否满足策略（不复用真实时间）。
func wouldSatisfy(facts Set, candidate Available, requirement Requirement) bool {
	hypothetical := facts
	fact := Fact{Method: candidate.Method, VerifiedAt: time.Unix(1, 0),
		UserVerified:    candidate.SupportsUserVerification,
		AuthenticatorID: candidate.Reference}
	hypothetical = hypothetical.added(fact)
	if !hypothetical.Satisfies(requirement) {
		return false
	}
	if requirement.Minimum >= StrengthStrong && candidate.Method == MethodTOTP &&
		!facts.Has(MethodPassword) {
		// TOTP 只有在已有密码事实时才构成“密码+TOTP”的受控强组合。
		return false
	}
	return true
}

// AMR 把事实集合映射为 OIDC `amr` 取值列表（RFC 8176 稳定标识，去重排序）。
// 本步骤只提供映射，不实现 OAuth/OIDC 端点。
func AMR(set Set) []string {
	values := make(map[string]bool, 6)
	for _, fact := range set.facts {
		switch fact.Method {
		case MethodPassword:
			values["pwd"] = true
		case MethodEmailOTP:
			values["otp"] = true
			values["email"] = true
		case MethodTOTP:
			values["otp"] = true
			values["totp"] = true
		case MethodPasskey:
			values["swk"] = true
			if fact.UserVerified {
				values["user"] = true
			}
		case MethodSecurityKey:
			values["hwk"] = true
			if fact.UserVerified {
				values["user"] = true
			}
		case MethodRecoveryCode:
			values["otp"] = true
			values["recovery"] = true
		}
	}
	if set.DistinctFactors() >= 2 || set.hasVerifiedWebAuthn() {
		values["mfa"] = true
	}
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

// ACR 把事实集合映射为内部 ACR 标识字符串，供未来 OIDC `acr` 声明使用。
// 返回值不是生产协议值承诺，只是稳定内部映射，便于后续接入时统一口径。
func ACR(set Set) string {
	switch set.Strength() {
	case StrengthStrong:
		return "urn:evernight:acr:strong"
	case StrengthMFA:
		return "urn:evernight:acr:mfa"
	case StrengthSingle:
		return "urn:evernight:acr:single"
	default:
		return "urn:evernight:acr:none"
	}
}

// MethodLabel 返回方法的中文直白名称（错误/页面展示用，不含敏感信息）。
func MethodLabel(method Method) string {
	switch method {
	case MethodPassword:
		return "密码"
	case MethodEmailOTP:
		return "邮件验证码"
	case MethodTOTP:
		return "TOTP 验证器"
	case MethodPasskey:
		return "Passkey"
	case MethodSecurityKey:
		return "安全密钥"
	case MethodRecoveryCode:
		return "恢复代码"
	default:
		return "未知方式"
	}
}

// ParseMethod 把稳定文本解析为方法；未知值返回错误（不静默接受客户端输入）。
func ParseMethod(value string) (Method, error) {
	method := Method(strings.TrimSpace(value))
	if !method.Valid() {
		return "", fmt.Errorf("%w: %q", ErrUnsupportedMethod, value)
	}
	return method, nil
}
