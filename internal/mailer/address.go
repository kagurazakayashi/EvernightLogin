package mailer

import (
	"fmt"
	"net/mail"
	"strings"
	"unicode/utf8"
)

const (
	// MaxAddressBytes 是单个邮件地址的最大字节数（与常见 SMTP 实现一致）。
	MaxAddressBytes = 254
	// MaxSubjectRunes 是主题最大码点数。
	MaxSubjectRunes = 200
	// MaxBodyBytes 是正文编码前的最大字节数。
	MaxBodyBytes = 512 << 10
	// MaxRecipientsPerMessage 是单封邮件收件人上限。
	MaxRecipientsPerMessage = 50
	// maxHeaderLineBytes 是单个头部值展开后的最大字节数。
	maxHeaderLineBytes = 998
)

// Address 是严格校验后的邮件地址。它只保存 addr-spec（不含显示名），并保证
// 不含空白、控制字符与 CR/LF，可直接用于 SMTP 信封与头部。
type Address struct {
	// Spec 是标准地址，例如 user@example.test。
	Spec string
}

// String 返回地址文本。
func (a Address) String() string { return a.Spec }

// ParseAddress 严格解析并校验邮件地址。
//
// 规则：只接受 addr-spec 或 "显示名 <addr>" 形式但丢弃显示名（显示名不进入头部，
// 避免注入面）；拒绝 CR/LF、所有控制字符、空白、超长地址、缺少或多余 '@'、
// 非法域名（含连续点、空标签、非法字符）。域名不要求真实存在——测试收件人
// 使用保留测试域名是允许的。
func ParseAddress(raw string) (Address, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return Address{}, fmt.Errorf("%w: 地址为空", ErrInvalidMessage)
	}
	if len(trimmed) > MaxAddressBytes {
		return Address{}, fmt.Errorf("%w: 地址超过 %d 字节", ErrInvalidMessage, MaxAddressBytes)
	}
	if strings.ContainsAny(trimmed, "\r\n") {
		return Address{}, fmt.Errorf("%w: 地址包含换行", ErrInvalidMessage)
	}
	for _, r := range trimmed {
		if r < 0x20 || r == 0x7f {
			return Address{}, fmt.Errorf("%w: 地址包含控制字符", ErrInvalidMessage)
		}
	}
	if !utf8.ValidString(trimmed) {
		return Address{}, fmt.Errorf("%w: 地址不是合法 UTF-8", ErrInvalidMessage)
	}
	parsed, err := mail.ParseAddress(trimmed)
	if err != nil {
		return Address{}, fmt.Errorf("%w: 无法解析地址: %v", ErrInvalidMessage, err)
	}
	spec := parsed.Address
	if spec == "" || strings.ContainsAny(spec, " \t<>") {
		return Address{}, fmt.Errorf("%w: 地址格式非法", ErrInvalidMessage)
	}
	if err := validateAddrSpec(spec); err != nil {
		return Address{}, err
	}
	return Address{Spec: spec}, nil
}

// validateAddrSpec 校验 addr-spec：本地部分与域名分别检查。
func validateAddrSpec(spec string) error {
	at := strings.IndexByte(spec, '@')
	if at <= 0 || at == len(spec)-1 || strings.Count(spec, "@") != 1 {
		return fmt.Errorf("%w: 地址必须形如 local@domain", ErrInvalidMessage)
	}
	local := spec[:at]
	domain := spec[at+1:]
	if len(local) > 64 {
		return fmt.Errorf("%w: 本地部分超过 64 字节", ErrInvalidMessage)
	}
	if strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") {
		return fmt.Errorf("%w: 本地部分点号位置非法", ErrInvalidMessage)
	}
	for _, r := range local {
		// 允许 RFC 5322 atext 与点号；允许非 ASCII（SMTPUTF8 场景由适配层决定），
		// 但拒绝分隔符与括号等结构字符，防止信封地址注入。
		if r > 0x7e {
			continue
		}
		if isAtext(byte(r)) || r == '.' {
			continue
		}
		return fmt.Errorf("%w: 本地部分包含非法字符", ErrInvalidMessage)
	}
	if strings.HasPrefix(domain, "[") || strings.HasSuffix(domain, "]") {
		return fmt.Errorf("%w: 不接受地址字面量域名", ErrInvalidMessage)
	}
	if len(domain) > 253 {
		return fmt.Errorf("%w: 域名超过 253 字节", ErrInvalidMessage)
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return fmt.Errorf("%w: 域名必须包含至少一个点", ErrInvalidMessage)
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("%w: 域名标签长度非法", ErrInvalidMessage)
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("%w: 域名标签不能以连字符开头或结尾", ErrInvalidMessage)
		}
		for _, r := range label {
			if r > 0x7e {
				// 国际化域名必须先用 punycode 转换，这里不接受原始非 ASCII 域名。
				return fmt.Errorf("%w: 域名必须是 ASCII（请使用 punycode）", ErrInvalidMessage)
			}
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return fmt.Errorf("%w: 域名包含非法字符", ErrInvalidMessage)
			}
		}
	}
	return nil
}

// isAtext 判断 RFC 5322 atext 字符。
func isAtext(r byte) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	}
	return strings.IndexByte("!#$%&'*+-/=?^_`{|}~", r) >= 0
}

// SanitizeHeaderValue 检查并返回可安全写入邮件头部的值。
//
// 拒绝任何 CR/LF、NUL 与其他控制字符（含制表符），并限制长度。主题等头部值在
// 编码（RFC 2047）之前必须通过本函数，防止数据里的换行被解释为额外头部。
func SanitizeHeaderValue(name, value string) (string, error) {
	if name == "" || len(name) > 64 {
		return "", fmt.Errorf("%w: 头部名称非法", ErrInvalidMessage)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("%w: 头部 %s 包含控制字符", ErrInvalidMessage, name)
		}
	}
	if len(value) > maxHeaderLineBytes {
		return "", fmt.Errorf("%w: 头部 %s 超过 %d 字节", ErrInvalidMessage, name, maxHeaderLineBytes)
	}
	return value, nil
}
