package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
)

const (
	// EnvelopeMagic 是密文信封的魔数，用于尽早拒绝非本包产生的数据。
	EnvelopeMagic = "LNS1"
	// EnvelopeVersion 是当前支持的密文信封版本。
	EnvelopeVersion = 1
	// NonceSize 是 AES-GCM 使用的 96 位随机 nonce 长度。
	NonceSize = 12
	// TagSize 是 AES-GCM 认证标签长度。
	TagSize = 16
	// MaxPlaintextBytes 是单条秘密明文的大小上限；TOTP 种子远小于该值，限制
	// 上限是为了避免把本服务当成通用大文件加密接口。
	MaxPlaintextBytes = 64 * 1024
	// MaxSealedBytes 是单条信封的大小上限（信封头 + 随机 nonce + 密文 + 标签）。
	MaxSealedBytes = len(EnvelopeMagic) + 2 + MaxKeyIDBytes + NonceSize + MaxPlaintextBytes + TagSize
	// envelopeHeaderFixedSize 是魔数、版本号与 key_id 长度字段的固定长度。
	envelopeHeaderFixedSize = len(EnvelopeMagic) + 2
	// hkdfSalt 是派生用途子密钥时使用的固定域分隔盐。
	hkdfSalt = "evernight-login/secret-envelope/v1"
)

// Sealer 使用密钥环中的当前写密钥加密、使用任一密钥解密。它不持有全局状态，
// 可以被多个 goroutine 并发使用；轮换密钥时创建新的 Sealer，不要在运行中修改
// 同一个密钥环。
type Sealer struct {
	ring   *Keyring
	logger *slog.Logger
	// random 是 nonce 的随机源，默认 crypto/rand.Reader。测试可以替换它来验证
	// 随机源失败路径；生产不得替换为弱随机源。
	random io.Reader
}

// NewSealer 基于已加载的密钥环创建 Sealer。密钥环为空、当前写密钥缺失时返回
// 错误，不会自动生成新密钥。logger 为 nil 时只记录到丢弃输出。
func NewSealer(ring *Keyring, logger *slog.Logger) (*Sealer, error) {
	if ring == nil || len(ring.keys) == 0 {
		return nil, fmt.Errorf("%w: 未加载密钥环", ErrKeyMaterialMissing)
	}
	if ring.CurrentKeyID() == "" || !ring.HasKey(ring.CurrentKeyID()) {
		return nil, fmt.Errorf("%w: 当前写密钥缺失", ErrKeyMaterialMissing)
	}
	if logger == nil {
		logger = discardLogger()
	}
	return &Sealer{ring: ring, logger: logger, random: rand.Reader}, nil
}

// CurrentKeyID 返回当前写密钥编号。新建密文时该编号会写入信封头。
func (s *Sealer) CurrentKeyID() string {
	if s == nil || s.ring == nil {
		return ""
	}
	return s.ring.CurrentKeyID()
}

// Seal 使用当前写密钥加密 plaintext，并把 binding 绑定到密文上。
//
// 输出信封格式：魔数 "LNS1"（4 字节）、版本号（1 字节）、key_id 长度（1 字节）、
// key_id（1-64 字节）、12 字节随机 nonce、AES-256-GCM 密文与标签。用途、对象与
// 所属范围不写入信封，而是在解密时作为关联数据参与认证。
//
// 每次调用都从安全随机源读取新的 nonce；随机源失败时返回 ErrRandomSource 且
// 不产出密文。明文超过 MaxPlaintextBytes、绑定信息非法或当前密钥缺失时失败。
func (s *Sealer) Seal(binding Binding, plaintext []byte) ([]byte, error) {
	if s == nil || s.ring == nil {
		return nil, fmt.Errorf("%w: Sealer 未初始化", ErrKeyMaterialMissing)
	}
	if err := binding.Validate(); err != nil {
		return nil, err
	}
	if len(plaintext) > MaxPlaintextBytes {
		return nil, fmt.Errorf("%w: 明文超过 %d 字节", ErrPlaintextTooLarge, MaxPlaintextBytes)
	}
	keyID := s.ring.CurrentKeyID()
	aead, err := s.aeadFor(keyID, binding.Purpose)
	if err != nil {
		return nil, err
	}
	header := buildEnvelopeHeader(keyID)
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(s.random, nonce); err != nil {
		return nil, fmt.Errorf("%w: 无法生成 nonce", ErrRandomSource)
	}
	aad := append(append([]byte(nil), header...), marshalBinding(binding)...)
	sealed := make([]byte, 0, len(header)+NonceSize+len(plaintext)+TagSize)
	sealed = append(sealed, header...)
	sealed = append(sealed, nonce...)
	sealed = aead.Seal(sealed, nonce, plaintext, aad)
	return sealed, nil
}

// Open 使用密文信封中的 key_id 选择历史读密钥或当前写密钥解密，并校验
// binding 与密文是否匹配。以下情况统一返回 ErrDecryptFailed，不向调用方区分
// 错误密钥、密文篡改或绑定不匹配：key_id 对应密钥材料错误、密文/标签被修改、
// 用途/对象/所属范围与加密时不同。
//
// key_id 在密钥环中不存在时返回 ErrKeyNotFound（主密钥文件被替换或丢失），不会
// 退回到其它密钥猜测解密。信封结构损坏返回 ErrSealedMalformed。
func (s *Sealer) Open(binding Binding, sealed []byte) ([]byte, error) {
	if s == nil || s.ring == nil {
		return nil, fmt.Errorf("%w: Sealer 未初始化", ErrKeyMaterialMissing)
	}
	if err := binding.Validate(); err != nil {
		return nil, err
	}
	header, keyID, nonce, ciphertext, err := splitEnvelope(sealed)
	if err != nil {
		return nil, err
	}
	aead, err := s.aeadFor(keyID, binding.Purpose)
	if err != nil {
		return nil, err
	}
	aad := append(append([]byte(nil), header...), marshalBinding(binding)...)
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	return plaintext, nil
}

// KeyIDOf 只解析信封头并返回 key_id，不接触密钥环、不解密。存储层可以用它
// 判断一条记录是否需要重加密；返回值不是秘密。
func KeyIDOf(sealed []byte) (string, error) {
	_, keyID, _, _, err := splitEnvelope(sealed)
	if err != nil {
		return "", err
	}
	return keyID, nil
}

// aeadFor 由密钥材料按“用途”派生 AES-256-GCM AEAD。HKDF-SHA256 以固定域分隔
// 串为 salt、key_id 与 purpose 为 info，使不同用途得到不同实际密钥；即使同一
// 主密钥用于 TOTP 与其它可还原秘密，也不会共用同一把 AEAD 密钥。
func (s *Sealer) aeadFor(keyID, purpose string) (cipher.AEAD, error) {
	material, ok := s.ring.keyMaterial(keyID)
	if !ok {
		return nil, fmt.Errorf("%w: key_id=%s", ErrKeyNotFound, maskKeyID(keyID))
	}
	info := "key:" + keyID + ";purpose:" + purpose
	subkey, err := hkdf.Key(sha256.New, material, []byte(hkdfSalt), info, KeyMaterialSize)
	if err != nil {
		return nil, fmt.Errorf("%w: 无法派生用途子密钥", ErrKeyMaterialMissing)
	}
	block, err := aes.NewCipher(subkey)
	if err != nil {
		return nil, fmt.Errorf("%w: 无法初始化 AES", ErrKeyMaterialMissing)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: 无法初始化 GCM", ErrKeyMaterialMissing)
	}
	return aead, nil
}

// buildEnvelopeHeader 构造信封头：魔数、版本、key_id 长度与 key_id。
func buildEnvelopeHeader(keyID string) []byte {
	header := make([]byte, 0, envelopeHeaderFixedSize+len(keyID))
	header = append(header, EnvelopeMagic...)
	header = append(header, EnvelopeVersion, byte(len(keyID)))
	header = append(header, keyID...)
	return header
}

// splitEnvelope 校验信封结构并拆出头部、key_id、nonce 与密文。所有长度检查都
// 在建立切片之前完成，避免越界和超大输入。
func splitEnvelope(sealed []byte) (header []byte, keyID string, nonce, ciphertext []byte, err error) {
	if len(sealed) > MaxSealedBytes {
		return nil, "", nil, nil, fmt.Errorf("%w: 密文超过 %d 字节", ErrSealedTooLarge, MaxSealedBytes)
	}
	if len(sealed) < envelopeHeaderFixedSize+NonceSize+TagSize {
		return nil, "", nil, nil, fmt.Errorf("%w: 密文过短", ErrSealedMalformed)
	}
	if string(sealed[:len(EnvelopeMagic)]) != EnvelopeMagic {
		return nil, "", nil, nil, fmt.Errorf("%w: 魔数不匹配", ErrSealedMalformed)
	}
	version := sealed[len(EnvelopeMagic)]
	if version != EnvelopeVersion {
		return nil, "", nil, nil, fmt.Errorf("%w: 版本号 %d", ErrSealedVersionUnsupported, version)
	}
	keyIDLen := int(sealed[len(EnvelopeMagic)+1])
	if keyIDLen < 1 || keyIDLen > MaxKeyIDBytes {
		return nil, "", nil, nil, fmt.Errorf("%w: key_id 长度不合法", ErrSealedMalformed)
	}
	headerLen := envelopeHeaderFixedSize + keyIDLen
	if len(sealed) < headerLen+NonceSize+TagSize {
		return nil, "", nil, nil, fmt.Errorf("%w: 密文长度与 key_id 长度不匹配", ErrSealedMalformed)
	}
	keyID = string(sealed[envelopeHeaderFixedSize:headerLen])
	if !validKeyID(keyID) {
		return nil, "", nil, nil, fmt.Errorf("%w: key_id 字符不合法", ErrSealedMalformed)
	}
	header = sealed[:headerLen]
	nonce = sealed[headerLen : headerLen+NonceSize]
	ciphertext = sealed[headerLen+NonceSize:]
	// 单条明文上限不能因为信封里 key_id 较短而放宽：密文长度必须同时满足
	// MaxPlaintextBytes + TagSize，否则拒绝解密。
	if len(ciphertext) > MaxPlaintextBytes+TagSize {
		return nil, "", nil, nil, fmt.Errorf("%w: 密文超过 %d 字节", ErrSealedTooLarge, MaxPlaintextBytes+TagSize)
	}
	return header, keyID, nonce, ciphertext, nil
}

// validKeyID 校验信封中的 key_id 字符集合，与密钥环文档使用同一规则。
func validKeyID(keyID string) bool {
	if keyID == "" || len(keyID) > MaxKeyIDBytes {
		return false
	}
	for i := 0; i < len(keyID); i++ {
		c := keyID[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-'
		if !ok {
			return false
		}
	}
	return true
}

// discardLogger 返回写入丢弃输出的日志器，用于未注入日志器的内部调用。
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}
