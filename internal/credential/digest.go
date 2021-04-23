package credential

import (
	"crypto/sha256"
	"encoding/binary"
)

// appendLengthPrefixed 追加 4 字节大端长度与内容，使字段边界明确，不会产生
// "a/b" 与 "a"+"b" 之类的歧义。
func appendLengthPrefixed(dst []byte, value string) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(value)))
	return append(dst, value...)
}

// encodeDigestMessage 构造确定性的摘要输入：域标识、凭证 ID、用途、目标、
// 应用绑定与秘密全部以长度前缀编码参与，任何一项不同都会得到不同摘要。
func encodeDigestMessage(domain, id, purpose, target, appID, secret string) []byte {
	buf := make([]byte, 0, 4*6+len(domain)+len(id)+len(purpose)+len(target)+len(appID)+len(secret))
	buf = appendLengthPrefixed(buf, domain)
	buf = appendLengthPrefixed(buf, id)
	buf = appendLengthPrefixed(buf, purpose)
	buf = appendLengthPrefixed(buf, target)
	buf = appendLengthPrefixed(buf, appID)
	buf = appendLengthPrefixed(buf, secret)
	return buf
}

// tokenVerifierHash 计算高熵令牌的 SHA-256 验证摘要。令牌本身是高熵随机值，
// 数据库只保存该摘要即可防止从摘要恢复令牌；绑定字段参与摘要，搬移后失效。
func tokenVerifierHash(id, purpose, target, appID, secret string) []byte {
	sum := sha256.Sum256(encodeDigestMessage(tokenDigestDomain, id, purpose, target, appID, secret))
	digest := make([]byte, sha256.Size)
	copy(digest, sum[:])
	return digest
}

// codeDigestMessage 返回低熵验证码的摘要输入；实际摘要由密钥环派生 HMAC 计算，
// 域标识与全部绑定字段同样参与，防止摘要被跨用途/对象复用。
func codeDigestMessage(id, purpose, target, appID, secret string) []byte {
	return encodeDigestMessage(codeDigestDomain, id, purpose, target, appID, secret)
}
