package authn

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// MinPasswordRunes/MaxPasswordRunes 是密码长度策略的绝对范围（按 Unicode
	// 码点计数）。默认最短 12 个码点，比常见 8 位建议更保守；上限防止超长输入
	// 造成不必要的计算与存储开销。
	MinPasswordRunes = 8
	MaxPasswordRunes = 256
	// DefaultMinPasswordRunes/DefaultMaxPasswordRunes 是默认长度策略。
	DefaultMinPasswordRunes = 12
	DefaultMaxPasswordRunes = 128
	// MaxPasswordHistoryLimit 是可选密码历史的最大保留条数。
	MaxPasswordHistoryLimit = 10
	// DefaultPasswordHistoryLimit 表示默认不启用历史限制。是否启用历史属于部署
	// 策略，本包不强制过期改密，也不把历史限制当作唯一强度来源。
	DefaultPasswordHistoryLimit = 0
)

// weakPasswords 是内置的高频弱密码基线筛查表（小写比较）。它不是完整的泄露
// 密码库，只用于拦截最常见的“先试这些”的密码；部署方可在 Validate 后通过
// WeakExtraWords 追加自有词表。绝不能把它宣传成完整的弱密码检测。
var weakPasswords = func() map[string]struct{} {
	values := []string{
		"password", "password1", "password123", "passw0rd", "p@ssw0rd",
		"123456", "1234567", "12345678", "123456789", "1234567890",
		"qwerty", "qwertyuiop", "qwerty123", "abc123", "abcd1234",
		"letmein", "iloveyou", "welcome", "welcome1", "monkey", "dragon",
		"football", "master", "sunshine", "princess", "login", "admin",
		"admin123", "administrator", "root", "root1234", "changeme",
		"evernight", "evernightlogin", "woaini1314", "5201314",
		"密码密码", "密码123456", "administrator123",
	}
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}()

// weakSequences 是内置的递增/键盘模式片段；密码包含这些片段时视为弱密码。
var weakSequences = []string{
	"0123456789", "9876543210",
	"abcdefghijklmnopqrstuvwxyz", "zyxwvutsrqponmlkjihgfedcba",
	"qwertyuiop", "asdfghjkl", "zxcvbnm", "qazwsx", "password", "passw0rd",
}

// PasswordPolicy 是密码长度、弱密码筛查与可选历史限制策略。零值使用
// DefaultPasswordPolicy；它不强制定期改密（没有依据的强制定期换密不可取），
// 也不要求复杂字符组合，而是依靠长度、弱密码筛查、标识信息排除与登录限流。
type PasswordPolicy struct {
	// MinRunes 是最短码点数；0 使用默认 12。
	MinRunes int
	// MaxRunes 是最长码点数；0 使用默认 128。
	MaxRunes int
	// HistoryLimit 是可选的近期密码历史检查条数；0 表示不启用历史限制，
	// 但仍始终拒绝“新密码与当前密码相同”。
	HistoryLimit int
	// WeakExtraWords 是部署方追加的弱密码词（小写比较，长度 ≥ 3）。
	WeakExtraWords []string
}

// DefaultPasswordPolicy 返回默认密码策略：至少 12 个码点、最多 128 个码点、
// 不启用历史限制。
func DefaultPasswordPolicy() PasswordPolicy {
	return PasswordPolicy{
		MinRunes:     DefaultMinPasswordRunes,
		MaxRunes:     DefaultMaxPasswordRunes,
		HistoryLimit: DefaultPasswordHistoryLimit,
	}
}

// normalize 填充默认值并返回副本，不修改调用方值。
func (p PasswordPolicy) normalize() PasswordPolicy {
	if p.MinRunes == 0 {
		p.MinRunes = DefaultMinPasswordRunes
	}
	if p.MaxRunes == 0 {
		p.MaxRunes = DefaultMaxPasswordRunes
	}
	if p.HistoryLimit < 0 {
		p.HistoryLimit = 0
	}
	return p
}

// Validate 校验策略范围：长度在绝对范围内且 MinRunes ≤ MaxRunes，历史条数
// 不超过 MaxPasswordHistoryLimit，追加词表不包含空/超长词。
func (p PasswordPolicy) Validate() error {
	normalized := p.normalize()
	if normalized.MinRunes < MinPasswordRunes || normalized.MinRunes > 64 {
		return fmt.Errorf("%w: 密码最短长度必须在 %d～64 个码点之间",
			ErrOptionsInvalid, MinPasswordRunes)
	}
	if normalized.MaxRunes < normalized.MinRunes || normalized.MaxRunes > MaxPasswordRunes {
		return fmt.Errorf("%w: 密码最长长度必须在最短长度～%d 个码点之间",
			ErrOptionsInvalid, MaxPasswordRunes)
	}
	if normalized.HistoryLimit < 0 || normalized.HistoryLimit > MaxPasswordHistoryLimit {
		return fmt.Errorf("%w: 密码历史条数必须在 0～%d 之间",
			ErrOptionsInvalid, MaxPasswordHistoryLimit)
	}
	for _, word := range normalized.WeakExtraWords {
		if len([]rune(word)) < 3 || len([]rune(word)) > 64 {
			return fmt.Errorf("%w: 追加弱密码词长度必须在 3～64 个码点之间", ErrOptionsInvalid)
		}
	}
	return nil
}

// Check 校验新密码是否满足策略。identifiers 是账户展示名、昵称、邮箱等不可
// 出现在密码中的标识（长度 ≥ 3 才检查）；错误信息只描述规则，绝不回显密码。
//
// 返回 ErrInvalidRequest 表示输入本身不合法（非法 UTF-8、控制字符、超长）；
// 返回 ErrWeakPassword 表示密码可解析但强度不足。
func (p PasswordPolicy) Check(password string, identifiers []string) error {
	normalized := p.normalize()
	if !utf8.ValidString(password) {
		return fmt.Errorf("%w: 密码不是合法 UTF-8", ErrInvalidRequest)
	}
	if len(password) > MaxPasswordBytes {
		return fmt.Errorf("%w: 密码输入过长", ErrInvalidRequest)
	}
	if strings.TrimSpace(password) == "" {
		return fmt.Errorf("%w: 密码不能为空或全空白", ErrWeakPassword)
	}
	runes := []rune(password)
	if len(runes) < normalized.MinRunes {
		return fmt.Errorf("%w: 密码至少需要 %d 个字符", ErrWeakPassword, normalized.MinRunes)
	}
	if len(runes) > normalized.MaxRunes {
		return fmt.Errorf("%w: 密码不能超过 %d 个字符", ErrWeakPassword, normalized.MaxRunes)
	}
	for _, character := range runes {
		if unicode.IsControl(character) {
			return fmt.Errorf("%w: 密码不能包含控制字符", ErrInvalidRequest)
		}
	}
	lower := strings.ToLower(password)
	if _, weak := weakPasswords[lower]; weak {
		return fmt.Errorf("%w: 密码过于常见", ErrWeakPassword)
	}
	for _, word := range normalized.WeakExtraWords {
		if strings.EqualFold(word, strings.TrimSpace(password)) {
			return fmt.Errorf("%w: 密码过于常见", ErrWeakPassword)
		}
	}
	if isRepeatedRune(password) {
		return fmt.Errorf("%w: 密码不能是单一字符重复", ErrWeakPassword)
	}
	for _, sequence := range weakSequences {
		if strings.Contains(lower, sequence) {
			return fmt.Errorf("%w: 密码不能包含连续字符或键盘序列", ErrWeakPassword)
		}
		// 反向判断拦截“从长序列中截取一段”的密码（例如 abcdefghij）。
		if len([]rune(lower)) >= MinPasswordRunes && strings.Contains(sequence, lower) {
			return fmt.Errorf("%w: 密码不能是连续字符或键盘序列", ErrWeakPassword)
		}
	}
	for _, identifier := range identifiers {
		token := strings.ToLower(strings.TrimSpace(identifier))
		if len([]rune(token)) < 3 {
			continue
		}
		if strings.Contains(lower, token) {
			return fmt.Errorf("%w: 密码不能包含用户名、昵称或邮箱等账户信息", ErrWeakPassword)
		}
	}
	return nil
}

// isRepeatedRune 报告密码是否由同一个字符重复组成。
func isRepeatedRune(password string) bool {
	runes := []rune(password)
	if len(runes) < 2 {
		return false
	}
	for _, character := range runes[1:] {
		if character != runes[0] {
			return false
		}
	}
	return true
}
