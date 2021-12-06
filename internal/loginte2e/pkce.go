package loginte2e

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// PKCE 只允许 S256（RFC 7636）。plain 与缺失由服务端拒绝，工具也从不发送。
const (
	// PKCEMethodS256 是唯一支持的 code_challenge_method。
	PKCEMethodS256 = "S256"
	// pkceVerifierBytes 是随机 verifier 的熵（32 字节 → 43 字符 base64url，
	// 处于 RFC 7636 要求的 43～128 字符范围）。
	pkceVerifierBytes = 32
	// stateBytes/nonceBytes 是 state 与 nonce 的随机字节数。
	stateBytes = 24
	nonceBytes = 24
)

// PKCEPair 是一次 PKCE 的 verifier/challenge 对。Verifier 是秘密：只放内存、
// 只提交给令牌端点，绝不写日志/报告。
type PKCEPair struct {
	Verifier  string
	Challenge string
}

// NewPKCE 生成随机 verifier 与其 S256 challenge。
func NewPKCE() (PKCEPair, error) {
	verifier, err := randomURLSafe(pkceVerifierBytes)
	if err != nil {
		return PKCEPair{}, err
	}
	return PKCEPair{Verifier: verifier, Challenge: ChallengeForVerifier(verifier)}, nil
}

// ChallengeForVerifier 计算 S256 challenge（RFC 7636 附录 B 向量可验证）。
func ChallengeForVerifier(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// NewState 生成授权请求 state。
func NewState() (string, error) { return randomURLSafe(stateBytes) }

// NewNonce 生成 OIDC nonce。
func NewNonce() (string, error) { return randomURLSafe(nonceBytes) }

// randomURLSafe 生成 n 字节密码学随机值并做无填充 base64url 编码。
func randomURLSafe(n int) (string, error) {
	buffer := make([]byte, n)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("%w: 生成随机值失败", ErrConfigInvalid)
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}
