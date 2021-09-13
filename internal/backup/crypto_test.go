package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testCryptoHeaderDigest 返回固定头部摘要，模拟加密写入时的 AAD 起点。
func testCryptoHeaderDigest() [32]byte {
	return sha256.Sum256([]byte("test-header"))
}

// TestEncryptDecryptPayloadMultiChunk 验证跨多个块（含非整块尾块）的加密/解密
// 往返，以及字节数与密文摘要一致。
func TestEncryptDecryptPayloadMultiChunk(t *testing.T) {
	plain := bytes.Repeat([]byte("evernight-login-backup-payload-"), 70000) // > 1 块
	key, err := generateDataKey(nil)
	if err != nil {
		t.Fatalf("生成载荷密钥失败：%v", err)
	}
	noncePrefix := []byte("12345678")
	digest := testCryptoHeaderDigest()
	var cipher bytes.Buffer
	written, cipherSHA, err := encryptPayload(&cipher, bytes.NewReader(plain),
		int64(len(plain)), DefaultChunkSize, key, noncePrefix, digest)
	if err != nil {
		t.Fatalf("加密失败：%v", err)
	}
	chunks := PayloadChunks(int64(len(plain)), DefaultChunkSize)
	if written != int64(len(plain))+chunks*aeadTagBytes {
		t.Fatalf("密文字节数 = %d，期望 %d", written, int64(len(plain))+chunks*aeadTagBytes)
	}
	info := EncryptionInfo{Algorithm: EncryptionAlgorithm, Format: EncryptionFormat,
		ChunkSizeBytes:     DefaultChunkSize,
		NoncePrefix:        encodeBase64(noncePrefix),
		KeyID:              "k1",
		WrappedDataKey:     "AA==",
		PayloadPlainBytes:  int64(len(plain)),
		PayloadCipherBytes: written}
	var decrypted bytes.Buffer
	decryptSHA, err := decryptPayload(&cipher, info, key, digest,
		func(chunk []byte) error {
			decrypted.Write(chunk)
			return nil
		})
	if err != nil {
		t.Fatalf("解密失败：%v", err)
	}
	if !bytes.Equal(decrypted.Bytes(), plain) {
		t.Fatal("解密结果与原文不一致")
	}
	if !bytes.Equal(decryptSHA[:], cipherSHA[:]) {
		t.Fatal("密文摘要不一致")
	}
}

// encodeBase64 是测试用标准 base64 编码。
func encodeBase64(value []byte) string {
	return base64.StdEncoding.EncodeToString(value)
}

// TestDecryptRejectsWrongKeyTamperAndTruncate 验证错误密钥、密文位翻转与截断都
// 明确失败（认证加密的核心不变量）。
func TestDecryptRejectsWrongKeyTamperAndTruncate(t *testing.T) {
	plain := bytes.Repeat([]byte("x"), DefaultChunkSize*2+123)
	key, _ := generateDataKey(nil)
	noncePrefix := []byte("abcdefgh")
	digest := testCryptoHeaderDigest()
	var cipher bytes.Buffer
	written, _, err := encryptPayload(&cipher, bytes.NewReader(plain),
		int64(len(plain)), DefaultChunkSize, key, noncePrefix, digest)
	if err != nil {
		t.Fatalf("加密失败：%v", err)
	}
	info := EncryptionInfo{Algorithm: EncryptionAlgorithm, Format: EncryptionFormat,
		ChunkSizeBytes: DefaultChunkSize, NoncePrefix: encodeBase64(noncePrefix),
		KeyID: "k1", WrappedDataKey: "AA==",
		PayloadPlainBytes: int64(len(plain)), PayloadCipherBytes: written}
	wrongKey, _ := generateDataKey(nil)
	if _, err := decryptPayload(bytes.NewReader(cipher.Bytes()), info, wrongKey, digest,
		func([]byte) error { return nil }); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("错误密钥错误 = %v，期望 ErrDecryptFailed", err)
	}
	tampered := append([]byte(nil), cipher.Bytes()...)
	tampered[10] ^= 0xff
	if _, err := decryptPayload(bytes.NewReader(tampered), info, key, digest,
		func([]byte) error { return nil }); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("篡改密文错误 = %v，期望 ErrDecryptFailed", err)
	}
	truncated := cipher.Bytes()[:len(cipher.Bytes())-1]
	if _, err := decryptPayload(bytes.NewReader(truncated), info, key, digest,
		func([]byte) error { return nil }); err == nil {
		t.Fatal("截断密文未被拒绝")
	}
}

// TestContainerHeaderValidation 验证版本、未知字段与非法条目标识在解析时被拒绝。
func TestContainerHeaderValidation(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	header := Header{
		FormatVersion: FormatVersion,
		BackupID:      "bkp_" + "0123456789abcdef0123456789abcdef",
		CreatedAt:     formatTime(now),
		Host:          "host",
		AppVersion:    "v1",
		Database: DatabaseMeta{Engine: "sqlite", SchemaVersion: "0042_report",
			SchemaVersionNumber: 42, SizeBytes: 4096,
			SHA256: hex.EncodeToString(make([]byte, 32))},
		Content: ContentMeta{Database: true,
			Attachments: ContentStatus{Status: ContentNotConfigured},
			Config:      ContentStatus{Status: ContentNotConfigured},
			Keyring:     ContentStatus{Status: ContentExcluded}},
		EntriesCount:   1,
		ManifestSHA256: hex.EncodeToString(make([]byte, 32)),
		Encryption: EncryptionInfo{Algorithm: EncryptionAlgorithm,
			Format:             EncryptionFormat,
			ChunkSizeBytes:     DefaultChunkSize,
			NoncePrefix:        encodeBase64([]byte("12345678")),
			KeyID:              "k1",
			WrappedDataKey:     encodeBase64([]byte("envelope")),
			PayloadPlainBytes:  int64(4 + 2 + 4096),
			PayloadCipherBytes: int64(4+2+4096) + aeadTagBytes},
	}
	encoded, err := marshalHeader(header)
	if err != nil {
		t.Fatalf("序列化头部失败：%v", err)
	}
	if _, err := decodeHeader(encoded); err != nil {
		t.Fatalf("合法头部被拒绝：%v", err)
	}
	unknown := append([]byte(nil), encoded[:len(encoded)-1]...)
	unknown = append(unknown, []byte(`,"unknown_field":1}`)...)
	if _, err := decodeHeader(unknown); err == nil {
		t.Fatal("含未知字段的头部未被拒绝")
	}
	badVersion := bytes.Replace(encoded, []byte(`"format_version":1`),
		[]byte(`"format_version":2`), 1)
	if bytes.Equal(badVersion, encoded) {
		t.Fatal("未替换到版本字段")
	}
	if _, err := decodeHeader(badVersion); !errors.Is(err, ErrVersionUnsupported) {
		t.Fatalf("不支持版本错误 = %v，期望 ErrVersionUnsupported", err)
	}
}

// TestValidateEntryName 验证路径穿越与非法条目名被拒绝。
func TestValidateEntryName(t *testing.T) {
	valid := []string{
		databaseEntryName,
		"attachments/ab/0123456789abcdef0123456789abcdef.png",
		configEntryName,
	}
	kinds := []string{EntryKindDatabase, EntryKindAttachment, EntryKindConfig}
	for index, name := range valid {
		if err := validateEntryName(kinds[index], name); err != nil {
			t.Fatalf("合法条目名 %q 被拒绝：%v", name, err)
		}
	}
	invalid := []struct {
		kind string
		name string
	}{
		{EntryKindAttachment, "attachments/../escape.png"},
		{EntryKindAttachment, "attachments//empty.png"},
		{EntryKindAttachment, "/attachments/abs.png"},
		{EntryKindAttachment, `attachments\windows.png`},
		{EntryKindAttachment, "attachments/a b.png"},
		{EntryKindConfig, "config/other.yaml"},
		{EntryKindDatabase, "database/other.sqlite"},
		{"unknown", "unknown/item"},
	}
	for _, entry := range invalid {
		if err := validateEntryName(entry.kind, entry.name); err == nil {
			t.Fatalf("非法条目名 %q 未被拒绝", entry.name)
		}
	}
}

// TestVerifyFailsWithoutKey 验证认证校验必须提供主密钥环，不能用无密钥结构检查
// 冒充完整校验。
func TestVerifyFailsWithoutKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.elnbak")
	if err := os.WriteFile(path, []byte("not-a-backup"), 0o600); err != nil {
		t.Fatalf("写入测试文件失败：%v", err)
	}
	if _, err := VerifyFile(context.Background(), path, nil); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatalf("缺少密钥错误 = %v，期望 ErrOptionsInvalid", err)
	}
	if _, err := InspectFile(context.Background(), path); !errors.Is(err, ErrFormatInvalid) {
		t.Fatalf("非法文件错误 = %v，期望 ErrFormatInvalid", err)
	}
}

// 编译期断言：SQLiteSnapshotter 实现 Snapshotter。
var _ Snapshotter = (*SQLiteSnapshotter)(nil)
