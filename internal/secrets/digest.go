package secrets

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

const (
	// MaxDigestDomainBytes 是密钥保护摘要域标识的最大长度。
	MaxDigestDomainBytes = 64
	// KeyedDigestSize 是 HMAC-SHA256 验证摘要的字节数。
	KeyedDigestSize = sha256.Size
	// keyedDigestSalt 是派生 HMAC 密钥时使用的固定域分隔盐，与秘密信封的
	// HKDF 盐分开，避免不同用途共用派生密钥。
	keyedDigestSalt = "evernight-login/keyed-digest/v1"
)

// HMACDigest 使用密钥环中 keyID 对应的密钥材料派生 HMAC-SHA256 验证摘要。
//
// domain 用于区分不同验证用途（例如 "one-time-credential/v1"）；message 是要
// 绑定到摘要的上下文与秘密内容。子密钥由 HKDF-SHA256 以固定域分隔盐、keyID
// 与 domain 派生，不向调用方暴露密钥材料。keyID 不存在时返回 ErrKeyNotFound，
// 明确失败而不是尝试其它密钥；空密钥环或非法 domain 也会失败。
//
// 返回 32 字节摘要，不包含任何明文或密钥信息；调用方应使用常量时间比较，
// 并且不得把密钥材料、摘要原文之外的秘密写入日志或数据库普通文本列。
func (k *Keyring) HMACDigest(keyID, domain string, message []byte) ([]byte, error) {
	if k == nil {
		return nil, fmt.Errorf("%w: 密钥环为空", ErrKeyMaterialMissing)
	}
	if err := validateToken("摘要域", domain, MaxDigestDomainBytes); err != nil {
		return nil, err
	}
	material, ok := k.keyMaterial(keyID)
	if !ok {
		return nil, fmt.Errorf("%w: key_id=%s", ErrKeyNotFound, maskKeyID(keyID))
	}
	subkey, err := hkdf.Key(sha256.New, material, []byte(keyedDigestSalt), "hmac:"+domain, KeyMaterialSize)
	if err != nil {
		return nil, fmt.Errorf("%w: 无法派生 HMAC 密钥", ErrKeyMaterialMissing)
	}
	defer wipeBytes(subkey)
	mac := hmac.New(sha256.New, subkey)
	// hash.Hash.Write 的接口约定是永不返回错误；仍显式使用返回值以保持可读性。
	_, _ = mac.Write(message)
	return mac.Sum(nil), nil
}
