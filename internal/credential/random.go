package credential

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

// credentialMaxRandomRetries 限制生成短码时拒绝采样与随机源异常情况下的重试
// 次数，避免异常 Reader 造成无界循环。
const credentialMaxRandomRetries = 64

// newCredentialID 生成凭证 ID：固定前缀加 16 字节安全随机数的十六进制表示。
func newCredentialID(random io.Reader) (string, error) {
	buffer := make([]byte, credentialIDRandomBytes)
	if _, err := io.ReadFull(random, buffer); err != nil {
		return "", fmt.Errorf("%w: 无法生成凭证 ID", ErrRandomSource)
	}
	return CredentialIDPrefix + hex.EncodeToString(buffer), nil
}

// newTokenSecret 生成高熵令牌：32 字节安全随机数的 base64url（无填充）文本。
func newTokenSecret(random io.Reader) (string, error) {
	buffer := make([]byte, TokenSize)
	if _, err := io.ReadFull(random, buffer); err != nil {
		return "", fmt.Errorf("%w: 无法生成令牌", ErrRandomSource)
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

// newCodeSecret 生成固定长度的十进制验证码（允许前导零），使用安全随机源与
// 拒绝采样保证每个数字等概率。
func newCodeSecret(random io.Reader) (string, error) {
	code := make([]byte, CodeLength)
	for i := range code {
		digit, err := randomDigit(random)
		if err != nil {
			return "", err
		}
		code[i] = digit
	}
	return string(code), nil
}

// randomDigit 使用安全随机字节与拒绝采样生成均匀分布的十进制数字字符。
func randomDigit(random io.Reader) (byte, error) {
	var buffer [1]byte
	for attempt := 0; attempt < credentialMaxRandomRetries; attempt++ {
		if _, err := io.ReadFull(random, buffer[:]); err != nil {
			return 0, fmt.Errorf("%w: 无法生成验证码", ErrRandomSource)
		}
		// 250 = 25*10：只接受 0～249，避免取模偏差。
		if buffer[0] < 250 {
			return '0' + buffer[0]%10, nil
		}
	}
	return 0, fmt.Errorf("%w: 验证码随机生成重试次数过多", ErrRandomSource)
}

// defaultRandomReader 返回生产使用的 crypto/rand 读取器；单独抽成函数便于
// 测试替换，生产路径不得改用弱随机源。
func defaultRandomReader() io.Reader {
	return rand.Reader
}
