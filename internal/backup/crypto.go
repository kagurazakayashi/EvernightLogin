package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
)

const (
	// backupIDPrefix 是备份编号固定前缀。
	backupIDPrefix = "bkp_"
	// backupIDRandomBytes 是备份编号随机字节数（128 位）。
	backupIDRandomBytes = 16
	// backupPurpose 是载荷密钥经 secrets.Sealer 封装时的用途绑定；不同用途
	// 派生不同子密钥，防止备份密钥信封被移植到其它秘密类型。
	backupPurpose = "backup.payload"
	// aeadTagBytes 是 AES-GCM 认证标签长度。
	aeadTagBytes = 16
)

// newBackupID 生成备份编号：bkp_ 加 128 位安全随机数的十六进制表示。
func newBackupID(random io.Reader) (string, error) {
	if random == nil {
		random = rand.Reader
	}
	buffer := make([]byte, backupIDRandomBytes)
	if _, err := io.ReadFull(random, buffer); err != nil {
		return "", fmt.Errorf("%w: 无法生成备份编号", ErrInternal)
	}
	return backupIDPrefix + hex.EncodeToString(buffer), nil
}

// generateDataKey 生成每份备份独立的随机 AES-256 载荷密钥。
func generateDataKey(random io.Reader) ([]byte, error) {
	if random == nil {
		random = rand.Reader
	}
	key := make([]byte, DataKeyBytes)
	if _, err := io.ReadFull(random, key); err != nil {
		return nil, fmt.Errorf("%w: 无法生成备份载荷密钥", ErrInternal)
	}
	return key, nil
}

// headerHash 计算头部绑定摘要。它作为每个数据块 AEAD 的 AAD 起点：头部任意
// 字节变化都会使全部块认证失败。使用原始头部字节（不重新序列化），保证不同
// 工具按字节读取即可校验。
func headerHash(headerRaw []byte) [32]byte {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(headerHashDomain))
	_, _ = hasher.Write(headerRaw)
	var result [32]byte
	copy(result[:], hasher.Sum(nil))
	return result
}

// backupBinding 返回打包载荷密钥使用的 secrets 绑定。备份编号是稳定对象 ID，
// 主密钥环轮换后可继续用历史密钥解密。
func backupBinding(backupID string) secrets.Binding {
	return secrets.Binding{Purpose: backupPurpose, ObjectID: backupID,
		ScopeID: secrets.ScopeSystem}
}

// wrapDataKey 用主密钥环认证加密载荷数据密钥，返回当前写密钥编号与信封。
func wrapDataKey(ring *secrets.Keyring, backupID string, dataKey []byte) (string, []byte, error) {
	if ring == nil {
		return "", nil, fmt.Errorf("%w: 未提供主密钥环", ErrOptionsInvalid)
	}
	if len(dataKey) != DataKeyBytes {
		return "", nil, fmt.Errorf("%w: 载荷密钥长度非法", ErrOptionsInvalid)
	}
	sealer, err := secrets.NewSealer(ring, nil)
	if err != nil {
		return "", nil, fmt.Errorf("%w: 无法使用主密钥环", ErrOptionsInvalid)
	}
	envelope, err := sealer.Seal(backupBinding(backupID), dataKey)
	if err != nil {
		return "", nil, fmt.Errorf("%w: 无法封装备份载荷密钥", err)
	}
	return sealer.CurrentKeyID(), envelope, nil
}

// unwrapDataKey 用主密钥环解开封装的载荷数据密钥。错误密钥、缺失 key_id 与头部
// 篡改统一返回 ErrDecryptFailed，不向调用方细分可利用的失败类别。
func unwrapDataKey(ring *secrets.Keyring, backupID string, keyID string,
	envelope []byte) ([]byte, error) {
	if ring == nil {
		return nil, fmt.Errorf("%w: 未提供主密钥环", ErrDecryptFailed)
	}
	envelopeKeyID, envelopeErr := secrets.KeyIDOf(envelope)
	if envelopeErr != nil {
		return nil, fmt.Errorf("%w: 载荷密钥信封格式无效", ErrFormatInvalid)
	}
	if envelopeKeyID != keyID {
		return nil, fmt.Errorf("%w: 载荷密钥编号与头部不一致", ErrDecryptFailed)
	}
	sealer, err := secrets.NewSealer(ring, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: 无法使用主密钥环", ErrDecryptFailed)
	}
	dataKey, err := sealer.Open(backupBinding(backupID), envelope)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecryptFailed, err)
	}
	if len(dataKey) != DataKeyBytes {
		return nil, fmt.Errorf("%w: 载荷密钥长度非法", ErrDecryptFailed)
	}
	return dataKey, nil
}

// buildNonce 构造块 nonce：8 字节随机前缀 + 4 字节大端块序号。每份备份使用独立
// 随机载荷密钥，块序号单调递增，因此同一密钥下 nonce 不会重复。
func buildNonce(prefix []byte, index uint32) []byte {
	nonce := make([]byte, 12)
	copy(nonce, prefix)
	binary.BigEndian.PutUint32(nonce[len(prefix):], index)
	return nonce
}

// buildChunkAAD 构造单块 AEAD 关联数据：头部摘要、载荷总长、块大小、块序号与
// 是否最后一块。最后一块标记与总长共同阻止在块边界截断后伪造成功。
func buildChunkAAD(headerDigest [32]byte, chunkSize int, plainBytes int64,
	index int64, totalChunks int64) []byte {
	aad := make([]byte, 0, 32+8+4+8+1)
	aad = append(aad, headerDigest[:]...)
	var numbers [8]byte
	binary.BigEndian.PutUint64(numbers[:], uint64(plainBytes))
	aad = append(aad, numbers[:]...)
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(chunkSize))
	aad = append(aad, size[:]...)
	var indexBytes [8]byte
	binary.BigEndian.PutUint64(indexBytes[:], uint64(index))
	aad = append(aad, indexBytes[:]...)
	final := byte(0)
	if index == totalChunks-1 {
		final = 1
	}
	aad = append(aad, final)
	return aad
}

// newChunkAEAD 由随机载荷密钥创建 AES-256-GCM。
func newChunkAEAD(dataKey []byte) (cipher.AEAD, error) {
	if len(dataKey) != DataKeyBytes {
		return nil, fmt.Errorf("%w: 载荷密钥长度非法", ErrInternal)
	}
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return nil, fmt.Errorf("%w: 无法初始化备份加密", ErrInternal)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: 无法初始化备份加密", ErrInternal)
	}
	return aead, nil
}

// normalizeNoncePrefix 把头部中的 base64 nonce 前缀解码为 8 字节。
func normalizeNoncePrefix(encoded string) ([]byte, error) {
	prefix, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(prefix) != NoncePrefixBytes {
		return nil, fmt.Errorf("%w: nonce 前缀格式非法", ErrFormatInvalid)
	}
	return prefix, nil
}

// encryptPayload 从 src 读取恰好 plainBytes 字节，按 chunkSize 分块认证加密后
// 写入 dst，并返回密文字节数与密文 SHA-256。
//
// 安全不变量：每块 nonce 由独立随机载荷密钥 + 单调块序号保证唯一；AAD 绑定头部
// 摘要、总长、块大小、块序号与最后一块标记，任何截断/拼接/重排都会导致认证失败。
func encryptPayload(dst io.Writer, src io.Reader, plainBytes int64, chunkSize int,
	dataKey, noncePrefix []byte, headerDigest [32]byte) (int64, [32]byte, error) {
	var digest [32]byte
	if dst == nil || src == nil {
		return 0, digest, fmt.Errorf("%w: 加密输入输出为空", ErrInternal)
	}
	aead, err := newChunkAEAD(dataKey)
	if err != nil {
		return 0, digest, err
	}
	chunks := PayloadChunks(plainBytes, chunkSize)
	if chunks <= 0 {
		return 0, digest, fmt.Errorf("%w: 载荷长度非法", ErrInternal)
	}
	cipherHasher := sha256.New()
	tee := io.MultiWriter(dst, cipherHasher)
	buffer := make([]byte, chunkSize)
	var written int64
	for index := int64(0); index < chunks; index++ {
		want := int64(chunkSize)
		if index == chunks-1 {
			want = plainBytes - index*int64(chunkSize)
		}
		if want <= 0 || want > int64(chunkSize) {
			return 0, digest, fmt.Errorf("%w: 载荷分块长度非法", ErrInternal)
		}
		if _, readErr := io.ReadFull(src, buffer[:want]); readErr != nil {
			return 0, digest, fmt.Errorf("%w: 读取备份内容失败", ErrBackupIO)
		}
		nonce := buildNonce(noncePrefix, uint32(index))
		aad := buildChunkAAD(headerDigest, chunkSize, plainBytes, index, chunks)
		sealed := aead.Seal(nil, nonce, buffer[:want], aad)
		if _, writeErr := tee.Write(sealed); writeErr != nil {
			return 0, digest, fmt.Errorf("%w: 写入备份密文失败", ErrBackupIO)
		}
		written += int64(len(sealed))
	}
	// 载荷长度声明必须与实际来源严格一致：多出的字节说明来源在快照后变化或
	// 清单计算错误，必须拒绝而不是静默丢弃。
	var extra [1]byte
	if n, readErr := src.Read(extra[:]); n != 0 || readErr == nil {
		return 0, digest, fmt.Errorf("%w: 内容长度与清单不一致", ErrIntegrityFailed)
	}
	copy(digest[:], cipherHasher.Sum(nil))
	return written, digest, nil
}

// decryptPayload 从 src 读取恰好 PayloadCipherBytes 字节，按块认证解密并把明文
// 交给 consume 处理（调用方负责解析清单帧与条目摘要）。它同时返回密文 SHA-256
// 供与头部记录交叉校验。任何认证失败、长度不符或多余字节都返回明确错误。
func decryptPayload(src io.Reader, info EncryptionInfo, dataKey []byte,
	headerDigest [32]byte, consume func([]byte) error) ([32]byte, error) {
	var digest [32]byte
	if src == nil || consume == nil {
		return digest, fmt.Errorf("%w: 解密输入为空", ErrInternal)
	}
	aead, err := newChunkAEAD(dataKey)
	if err != nil {
		return digest, err
	}
	prefix, err := normalizeNoncePrefix(info.NoncePrefix)
	if err != nil {
		return digest, err
	}
	chunks := PayloadChunks(info.PayloadPlainBytes, info.ChunkSizeBytes)
	limited := io.LimitReader(src, info.PayloadCipherBytes)
	cipherHasher := sha256.New()
	tee := io.TeeReader(limited, cipherHasher)
	chunkBuffer := make([]byte, info.ChunkSizeBytes+aeadTagBytes)
	for index := int64(0); index < chunks; index++ {
		want := int64(info.ChunkSizeBytes)
		if index == chunks-1 {
			want = info.PayloadPlainBytes - index*int64(info.ChunkSizeBytes)
		}
		cipherLength := want + int64(aeadTagBytes)
		if _, readErr := io.ReadFull(tee, chunkBuffer[:cipherLength]); readErr != nil {
			return digest, fmt.Errorf("%w: 备份密文被截断", ErrIntegrityFailed)
		}
		nonce := buildNonce(prefix, uint32(index))
		aad := buildChunkAAD(headerDigest, info.ChunkSizeBytes,
			info.PayloadPlainBytes, index, chunks)
		plain, openErr := aead.Open(nil, nonce, chunkBuffer[:cipherLength], aad)
		if openErr != nil {
			return digest, fmt.Errorf("%w: 备份载荷认证失败", ErrDecryptFailed)
		}
		if consumeErr := consume(plain); consumeErr != nil {
			return digest, consumeErr
		}
	}
	// 密文总长必须与头部声明一致（少读/多读都拒绝）。LimitReader 读完后
	// 再多读 1 字节确认没有尾随数据。
	var extra [1]byte
	if n, readErr := tee.Read(extra[:]); n != 0 || readErr == nil {
		return digest, fmt.Errorf("%w: 备份载荷长度与头部不一致", ErrIntegrityFailed)
	}
	copy(digest[:], cipherHasher.Sum(nil))
	return digest, nil
}
