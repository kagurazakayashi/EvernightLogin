package secrets

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	// MaxPurposeBytes 是用途标识的最大长度。
	MaxPurposeBytes = 64
	// MaxBindingFieldBytes 是对象 ID 与所属范围 ID 的最大长度。
	MaxBindingFieldBytes = 128
	// ScopeSystem 是全局（系统范围）数据的所属范围 ID，与数据库迁移中的
	// system scope 保持一致。用户级 TOTP 秘密等不归属具体应用的数据使用它。
	ScopeSystem = "system"
)

// Binding 是一条密文必须绑定的上下文：这条秘密的用途、所属对象和所属范围。
//
// 这三个字段全部作为 AEAD 关联数据参与认证，解密时必须提供完全相同的值。
// 因此把一条密文复制到另一条记录、另一个用途或另一个应用范围后，解密会失败，
// 而不是悄悄返回原明文。字段只允许可见 ASCII 字符（0x21-0x7E），避免跨数据库、
// 日志和诊断输出时出现编码歧义。
type Binding struct {
	// Purpose 是用途标识，例如 "mfa.totp"。不同用途会派生不同的加密子密钥。
	Purpose string
	// ObjectID 是稳定的对象标识，例如 MFA 方法 ID。创建后不应修改。
	ObjectID string
	// ScopeID 是所属范围，例如 "system" 或应用 scope ID。
	ScopeID string
}

// Validate 检查绑定字段非空、长度受限且只包含可见 ASCII 字符。Seal 与 Open
// 都会先调用它，避免用空上下文或含控制字符的上下文派生密文。
func (b Binding) Validate() error {
	if err := validateBindingField("用途", b.Purpose, MaxPurposeBytes); err != nil {
		return err
	}
	if err := validateBindingField("对象 ID", b.ObjectID, MaxBindingFieldBytes); err != nil {
		return err
	}
	if err := validateBindingField("所属范围", b.ScopeID, MaxBindingFieldBytes); err != nil {
		return err
	}
	return nil
}

// validateBindingField 校验单个绑定字段。错误信息只包含字段名和长度/字符类别，
// 不回显字段值，避免把对象 ID 等内容写入不合适的错误响应。
func validateBindingField(name, value string, max int) error {
	if value == "" {
		return fmt.Errorf("%w: %s不能为空", ErrBindingInvalid, name)
	}
	if len(value) > max {
		return fmt.Errorf("%w: %s超过 %d 字节", ErrBindingInvalid, name, max)
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return fmt.Errorf("%w: %s只能包含可见 ASCII 字符", ErrBindingInvalid, name)
		}
	}
	return nil
}

// String 返回用于日志与诊断的短描述。对象 ID 与用途不是秘密，可以出现在受限
// 日志中；本方法不会输出任何密文或明文。
func (b Binding) String() string {
	return fmt.Sprintf("%s/%s/%s", b.Purpose, b.ScopeID, b.ObjectID)
}

// marshalBinding 把绑定信息编码为确定性的关联数据。使用 4 字节大端长度前缀，
// 使字段边界明确，不会因分隔符选择产生 "a:b" 与 "a" + "b:c" 之类的歧义。
// 调用前必须已通过 Validate。
func marshalBinding(b Binding) []byte {
	buf := make([]byte, 0, 12+len(b.Purpose)+len(b.ObjectID)+len(b.ScopeID))
	buf = appendLengthPrefixed(buf, b.Purpose)
	buf = appendLengthPrefixed(buf, b.ObjectID)
	buf = appendLengthPrefixed(buf, b.ScopeID)
	return buf
}

// appendLengthPrefixed 追加 4 字节大端长度与内容。
func appendLengthPrefixed(dst []byte, value string) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(value)))
	return append(dst, value...)
}

// validateToken 校验 key_id 之类的短标识：非空、长度受限、只含 ASCII 字母、
// 数字与 ". _ -"。密钥编号不是秘密，但仍使用受限字符集以便安全写入日志和 SQL。
func validateToken(name, value string, max int) error {
	if value == "" {
		return fmt.Errorf("%w: %s不能为空", ErrKeyringInvalid, name)
	}
	if len(value) > max {
		return fmt.Errorf("%w: %s超过 %d 字节", ErrKeyringInvalid, name, max)
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-'
		if !ok {
			return fmt.Errorf("%w: %s只能包含 ASCII 字母、数字和 . _ -", ErrKeyringInvalid, name)
		}
	}
	return nil
}

// maskKeyID 返回适合写入日志的密钥编号；编号本身不是秘密，但截断过长的输入
// 可避免日志被异常内容撑大。
func maskKeyID(keyID string) string {
	if len(keyID) > MaxKeyIDBytes {
		return strings.Repeat("?", MaxKeyIDBytes)
	}
	return keyID
}
