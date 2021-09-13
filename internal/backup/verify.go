package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
)

// EntryReport 是校验通过后的清单条目投影（不含内容正文）。
type EntryReport struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	SizeBytes int64  `json:"size_bytes"`
	SHA256    string `json:"sha256"`
}

// EncryptionSummary 是校验报告中的加密参数摘要。
type EncryptionSummary struct {
	Algorithm          string `json:"algorithm"`
	Format             string `json:"format"`
	ChunkSizeBytes     int    `json:"chunk_size_bytes"`
	KeyID              string `json:"key_id"`
	PayloadPlainBytes  int64  `json:"payload_plain_bytes"`
	PayloadCipherBytes int64  `json:"payload_cipher_bytes"`
}

// VerifyReport 是备份文件独立校验结果。Authenticated 为 true 表示已用主密钥环
// 完成认证解密并验证全部清单条目摘要；InspectFile 无密钥时 Authenticated=false，
// 只做结构与密文摘要检查，不能替代认证校验。
type VerifyReport struct {
	StructuralValid   bool              `json:"structural_valid"`
	Encrypted         bool              `json:"encrypted"`
	Authenticated     bool              `json:"authenticated"`
	ManifestAvailable bool              `json:"manifest_available"`
	FormatVersion     int               `json:"format_version"`
	BackupID          string            `json:"backup_id"`
	CreatedAt         time.Time         `json:"created_at"`
	Host              string            `json:"host"`
	AppVersion        string            `json:"app_version"`
	Database          DatabaseMeta      `json:"database"`
	Content           ContentMeta       `json:"content"`
	Entries           []EntryReport     `json:"entries,omitempty"`
	ManifestSHA256    string            `json:"manifest_sha256"`
	FileSHA256        string            `json:"file_sha256"`
	FileSize          int64             `json:"file_size"`
	CiphertextSHA256  string            `json:"ciphertext_sha256"`
	Encryption        EncryptionSummary `json:"encryption"`
}

// InspectFile 只读取备份明文头部并检查文件结构/密文摘要，不需要主密钥。
//
// 它明确不声称认证通过：任何人可以替换文件、明文头部与密文摘要，因此结果只能
// 用于快速发现截断/位翻转与展示格式版本、来源、内容范围、大小和加密状态。完整
// 验证必须调用 VerifyFile 并提供正确的主密钥环。
func InspectFile(ctx context.Context, path string) (VerifyReport, error) {
	ctx = normalizeContext(ctx)
	file, fileSize, err := openBackupFile(path)
	if err != nil {
		return VerifyReport{}, err
	}
	defer file.Close()
	fileHasher := sha256.New()
	tee := io.TeeReader(file, fileHasher)
	header, _, headerEnd, err := readHeaderFrom(tee)
	if err != nil {
		return VerifyReport{}, err
	}
	if err := ctx.Err(); err != nil {
		return VerifyReport{}, err
	}
	expectedSize := int64(headerEnd) + header.Encryption.PayloadCipherBytes + TrailerBytes
	if fileSize != expectedSize {
		return VerifyReport{}, fmt.Errorf("%w: 备份文件大小 %d 与头部声明 %d 不一致",
			ErrIntegrityFailed, fileSize, expectedSize)
	}
	limited := &io.LimitedReader{R: tee, N: header.Encryption.PayloadCipherBytes}
	cipherHasher := sha256.New()
	if _, err := io.Copy(cipherHasher, limited); err != nil {
		return VerifyReport{}, fmt.Errorf("%w: 读取备份密文失败", ErrFormatInvalid)
	}
	if limited.N != 0 {
		return VerifyReport{}, fmt.Errorf("%w: 备份密文被截断", ErrIntegrityFailed)
	}
	cipherDigest := hex.EncodeToString(cipherHasher.Sum(nil))
	if err := checkTrailer(tee, cipherHasher.Sum(nil)); err != nil {
		return VerifyReport{}, err
	}
	report := reportFromHeader(header, fileSize)
	report.StructuralValid = true
	report.Encrypted = true
	report.Authenticated = false
	report.ManifestAvailable = false
	report.CiphertextSHA256 = cipherDigest
	report.FileSHA256 = hex.EncodeToString(fileHasher.Sum(nil))
	return report, nil
}

// VerifyFile 使用主密钥环认证解密备份文件，独立校验清单、条目大小与 SHA-256、
// 数据库版本记录、载荷与文件长度，并返回可审计的校验报告。
//
// 错误失败必须明确：错误密钥/缺失 key_id/头部或载荷被篡改返回 ErrDecryptFailed
// 或 ErrIntegrityFailed；格式/版本不支持返回 ErrFormatInvalid/ErrVersionUnsupported。
// 本函数只读取备份文件，不修改文件、不执行其中内容、不连接生产数据库。
func VerifyFile(ctx context.Context, path string, keyring *secrets.Keyring) (VerifyReport, error) {
	ctx = normalizeContext(ctx)
	if keyring == nil {
		return VerifyReport{}, fmt.Errorf("%w: 未提供主密钥环，无法认证校验加密备份",
			ErrOptionsInvalid)
	}
	file, fileSize, err := openBackupFile(path)
	if err != nil {
		return VerifyReport{}, err
	}
	defer file.Close()
	fileHasher := sha256.New()
	tee := io.TeeReader(file, fileHasher)
	header, headerRaw, headerEnd, err := readHeaderFrom(tee)
	if err != nil {
		return VerifyReport{}, err
	}
	if err := ctx.Err(); err != nil {
		return VerifyReport{}, err
	}
	expectedSize := int64(headerEnd) + header.Encryption.PayloadCipherBytes + TrailerBytes
	if fileSize != expectedSize {
		return VerifyReport{}, fmt.Errorf("%w: 备份文件大小 %d 与头部声明 %d 不一致",
			ErrIntegrityFailed, fileSize, expectedSize)
	}
	wrappedKey, decodeErr := base64.StdEncoding.DecodeString(header.Encryption.WrappedDataKey)
	if decodeErr != nil {
		return VerifyReport{}, fmt.Errorf("%w: 受保护载荷密钥格式非法", ErrFormatInvalid)
	}
	dataKey, err := unwrapDataKey(keyring, header.BackupID,
		header.Encryption.KeyID, wrappedKey)
	if err != nil {
		return VerifyReport{}, err
	}
	digest := headerHash(headerRaw)
	limited := &io.LimitedReader{R: tee, N: header.Encryption.PayloadCipherBytes}
	parser := newPayloadParser(header, digest)
	cipherDigest, err := decryptPayload(limited, header.Encryption, dataKey, digest,
		parser.consume)
	if err != nil {
		return VerifyReport{}, err
	}
	if limited.N != 0 {
		return VerifyReport{}, fmt.Errorf("%w: 备份密文未被完整读取", ErrIntegrityFailed)
	}
	if err := checkTrailer(tee, cipherDigest[:]); err != nil {
		return VerifyReport{}, err
	}
	cipherHex := hex.EncodeToString(cipherDigest[:])
	entries, manifestSHA, err := parser.finish()
	if err != nil {
		return VerifyReport{}, err
	}
	report := reportFromHeader(header, fileSize)
	report.StructuralValid = true
	report.Encrypted = true
	report.Authenticated = true
	report.ManifestAvailable = true
	report.CiphertextSHA256 = cipherHex
	report.ManifestSHA256 = manifestSHA
	report.FileSHA256 = hex.EncodeToString(fileHasher.Sum(nil))
	report.Entries = entries
	return report, nil
}

// openBackupFile 打开备份文件并校验普通文件与大小上限。
func openBackupFile(path string) (*os.File, int64, error) {
	if path == "" {
		return nil, 0, fmt.Errorf("%w: 备份文件路径为空", ErrInvalidRequest)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: 无法打开备份文件", ErrFormatInvalid)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, 0, fmt.Errorf("%w: 无法读取备份文件状态", ErrFormatInvalid)
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, 0, fmt.Errorf("%w: 备份必须是普通文件", ErrFormatInvalid)
	}
	size := info.Size()
	if size < int64(containerPrefixBytes) || size > MaxBackupFileBytes {
		_ = file.Close()
		return nil, 0, fmt.Errorf("%w: 备份文件大小非法", ErrFormatInvalid)
	}
	return file, size, nil
}

// readHeaderFrom 从读取器读取容器前缀与头部 JSON，返回头部、原始头部字节与载荷
// 起始偏移。它不读取载荷。
func readHeaderFrom(reader io.Reader) (Header, []byte, int, error) {
	prefix := make([]byte, containerPrefixBytes)
	if _, err := io.ReadFull(reader, prefix); err != nil {
		return Header{}, nil, 0, fmt.Errorf("%w: 备份文件过短", ErrFormatInvalid)
	}
	if string(prefix[:len(Magic)]) != Magic {
		return Header{}, nil, 0, fmt.Errorf("%w: 备份文件魔数不匹配", ErrFormatInvalid)
	}
	version := binary.BigEndian.Uint16(prefix[len(Magic) : len(Magic)+2])
	if version != FormatVersion {
		return Header{}, nil, 0, fmt.Errorf("%w: 备份格式版本 %d",
			ErrVersionUnsupported, version)
	}
	headerLength := int(binary.BigEndian.Uint32(prefix[len(Magic)+2:]))
	if headerLength <= 0 || headerLength > MaxHeaderBytes {
		return Header{}, nil, 0, fmt.Errorf("%w: 头部长度非法", ErrFormatInvalid)
	}
	headerRaw := make([]byte, headerLength)
	if _, err := io.ReadFull(reader, headerRaw); err != nil {
		return Header{}, nil, 0, fmt.Errorf("%w: 备份文件头部被截断", ErrFormatInvalid)
	}
	header, err := decodeHeader(headerRaw)
	if err != nil {
		return Header{}, nil, 0, err
	}
	return header, headerRaw, containerPrefixBytes + headerLength, nil
}

// reportFromHeader 把头部转换为校验报告公共字段。
func reportFromHeader(header Header, fileSize int64) VerifyReport {
	createdAt, _ := parseFormatTime(header.CreatedAt)
	return VerifyReport{
		FormatVersion:  header.FormatVersion,
		BackupID:       header.BackupID,
		CreatedAt:      createdAt,
		Host:           header.Host,
		AppVersion:     header.AppVersion,
		Database:       header.Database,
		Content:        header.Content,
		FileSize:       fileSize,
		ManifestSHA256: header.ManifestSHA256,
		Encryption: EncryptionSummary{
			Algorithm:          header.Encryption.Algorithm,
			Format:             header.Encryption.Format,
			ChunkSizeBytes:     header.Encryption.ChunkSizeBytes,
			KeyID:              header.Encryption.KeyID,
			PayloadPlainBytes:  header.Encryption.PayloadPlainBytes,
			PayloadCipherBytes: header.Encryption.PayloadCipherBytes,
		},
	}
}

// payloadParser 是解密明文的流式解析器：先读清单帧（4 字节大端长度 + 清单
// JSON），再按清单顺序逐条流式校验条目大小与 SHA-256，最后要求恰好消费完毕。
type payloadParser struct {
	header       Header
	headerDigest [32]byte

	lengthBuffer   []byte
	manifestLength int
	manifestBuffer []byte
	manifest       Manifest
	manifestSHA    string
	manifestDone   bool

	entryIndex  int
	entrySize   int64
	entryHasher hash.Hash
	entriesSeen int
	consumed    int64
	finishedOK  bool
}

// newPayloadParser 构造解析器。
func newPayloadParser(header Header, headerDigest [32]byte) *payloadParser {
	return &payloadParser{header: header, headerDigest: headerDigest}
}

// consume 接收一块解密明文并推进解析状态。任何顺序/长度/摘要错误立即失败。
func (p *payloadParser) consume(data []byte) error {
	for len(data) > 0 {
		switch {
		case p.finishedOK:
			return fmt.Errorf("%w: 载荷尾部包含多余数据", ErrIntegrityFailed)
		case p.manifestLength == 0:
			// 清单帧长度（4 字节大端）。
			take := 4 - len(p.lengthBuffer)
			if len(data) < take {
				take = len(data)
			}
			p.lengthBuffer = append(p.lengthBuffer, data[:take]...)
			data = data[take:]
			p.consumed += int64(take)
			if len(p.lengthBuffer) < 4 {
				continue
			}
			length := int(binary.BigEndian.Uint32(p.lengthBuffer))
			if length <= 0 || length > MaxManifestBytes {
				return fmt.Errorf("%w: 清单长度非法", ErrIntegrityFailed)
			}
			p.manifestLength = length
			p.manifestBuffer = make([]byte, 0, length)
			p.lengthBuffer = nil
		case !p.manifestDone:
			take := p.manifestLength - len(p.manifestBuffer)
			if len(data) < take {
				take = len(data)
			}
			p.manifestBuffer = append(p.manifestBuffer, data[:take]...)
			data = data[take:]
			p.consumed += int64(take)
			if len(p.manifestBuffer) < p.manifestLength {
				continue
			}
			if err := p.startEntries(); err != nil {
				return err
			}
		default:
			entry := p.manifest.Entries[p.entryIndex]
			remaining := entry.SizeBytes - p.entrySize
			take := int64(len(data))
			if take > remaining {
				take = remaining
			}
			if p.entryHasher == nil {
				p.entryHasher = sha256.New()
			}
			if _, err := p.entryHasher.Write(data[:take]); err != nil {
				return fmt.Errorf("%w: 计算条目摘要失败", ErrInternal)
			}
			p.entrySize += take
			p.consumed += take
			data = data[take:]
			if p.entrySize == entry.SizeBytes {
				sum := p.entryHasher.Sum(nil)
				if hex.EncodeToString(sum) != entry.SHA256 {
					return fmt.Errorf("%w: 条目 %s 摘要不一致", ErrIntegrityFailed, entry.Name)
				}
				p.entriesSeen++
				p.entryIndex++
				p.entrySize = 0
				p.entryHasher = nil
				if p.entryIndex == len(p.manifest.Entries) {
					p.finishedOK = true
				}
			}
		}
	}
	return nil
}

// startEntries 解析并校验清单，准备按条目顺序消费正文。
func (p *payloadParser) startEntries() error {
	manifest, err := decodeManifest(p.manifestBuffer)
	if err != nil {
		return err
	}
	manifestSHA, err := validateManifest(p.header, manifest, p.manifestBuffer)
	if err != nil {
		return err
	}
	p.manifest = manifest
	p.manifestDone = true
	p.manifestSHA = manifestSHA
	if len(manifest.Entries) == 0 {
		return fmt.Errorf("%w: 清单没有条目", ErrIntegrityFailed)
	}
	return nil
}

// finish 在解密完成后校验消费长度并把解析结果转换为报告条目。
func (p *payloadParser) finish() ([]EntryReport, string, error) {
	if !p.finishedOK {
		return nil, "", fmt.Errorf("%w: 备份载荷在条目中途结束", ErrIntegrityFailed)
	}
	if p.entriesSeen != len(p.manifest.Entries) {
		return nil, "", fmt.Errorf("%w: 条目数量与清单不一致", ErrIntegrityFailed)
	}
	if p.consumed != p.header.Encryption.PayloadPlainBytes {
		return nil, "", fmt.Errorf("%w: 载荷明文字节数与头部不一致", ErrIntegrityFailed)
	}
	entries := make([]EntryReport, 0, len(p.manifest.Entries))
	for _, entry := range p.manifest.Entries {
		entries = append(entries, EntryReport{Name: entry.Name, Kind: entry.Kind,
			SizeBytes: entry.SizeBytes, SHA256: entry.SHA256})
	}
	return entries, p.manifestSHA, nil
}

// validateManifest 交叉校验认证清单与明文头部，并返回清单 SHA-256 十六进制。
// 头部只含摘要与少量元数据；清单重复这些元数据，任何不一致都按完整性失败处理。
func validateManifest(header Header, manifest Manifest, manifestRaw []byte) (string, error) {
	digest := sha256.Sum256(manifestRaw)
	manifestSHA := hex.EncodeToString(digest[:])
	if manifestSHA != header.ManifestSHA256 {
		return "", fmt.Errorf("%w: 清单摘要与头部不一致", ErrIntegrityFailed)
	}
	if manifest.FormatVersion != FormatVersion {
		return "", fmt.Errorf("%w: 清单格式版本不支持", ErrVersionUnsupported)
	}
	if manifest.BackupID != header.BackupID || manifest.CreatedAt != header.CreatedAt ||
		manifest.Host != header.Host || manifest.AppVersion != header.AppVersion {
		return "", fmt.Errorf("%w: 清单元数据与头部不一致", ErrIntegrityFailed)
	}
	if manifest.Content != header.Content {
		return "", fmt.Errorf("%w: 清单内容范围与头部不一致", ErrIntegrityFailed)
	}
	expectedDatabase := ManifestDatabase{Engine: header.Database.Engine,
		SchemaVersion:       header.Database.SchemaVersion,
		SchemaVersionNumber: header.Database.SchemaVersionNumber}
	if manifest.Database != expectedDatabase {
		return "", fmt.Errorf("%w: 清单数据库版本与头部不一致", ErrIntegrityFailed)
	}
	if len(manifest.Entries) != header.EntriesCount {
		return "", fmt.Errorf("%w: 清单条目数量与头部不一致", ErrIntegrityFailed)
	}
	for _, field := range []struct {
		label string
		value string
	}{
		{"数据库快照开始时间", manifest.Capture.DatabaseSnapshotStartedAt},
		{"数据库快照结束时间", manifest.Capture.DatabaseSnapshotFinishedAt},
	} {
		if _, err := parseFormatTime(field.value); err != nil {
			return "", fmt.Errorf("%w: %s非法", ErrInvalidRequest, field.label)
		}
	}
	if _, err := parseFormatTime(manifest.Capture.AttachmentsCapturedAt); err != nil &&
		header.Content.Attachments.Status == ContentIncluded {
		return "", fmt.Errorf("%w: 附件捕获时间非法", ErrInvalidRequest)
	}
	if _, err := parseFormatTime(manifest.Capture.ConfigCapturedAt); err != nil &&
		header.Content.Config.Status == ContentIncluded {
		return "", fmt.Errorf("%w: 配置捕获时间非法", ErrInvalidRequest)
	}
	seen := make(map[string]struct{}, len(manifest.Entries))
	databaseEntries := 0
	attachments := 0
	configs := 0
	var totalBytes int64
	for _, entry := range manifest.Entries {
		if err := validateEntryKind(entry.Kind); err != nil {
			return "", err
		}
		if err := validateEntryName(entry.Kind, entry.Name); err != nil {
			return "", err
		}
		if _, exists := seen[entry.Name]; exists {
			return "", fmt.Errorf("%w: 清单条目名重复", ErrIntegrityFailed)
		}
		seen[entry.Name] = struct{}{}
		if entry.SizeBytes <= 0 || !validHexDigest(entry.SHA256) {
			return "", fmt.Errorf("%w: 清单条目大小或摘要非法", ErrIntegrityFailed)
		}
		switch entry.Kind {
		case EntryKindDatabase:
			databaseEntries++
			if entry.Name != databaseEntryName ||
				entry.SizeBytes != header.Database.SizeBytes ||
				entry.SHA256 != header.Database.SHA256 {
				return "", fmt.Errorf("%w: 数据库条目与头部不一致", ErrIntegrityFailed)
			}
		case EntryKindAttachment:
			attachments++
		case EntryKindConfig:
			configs++
		}
		totalBytes += entry.SizeBytes
	}
	if databaseEntries != 1 {
		return "", fmt.Errorf("%w: 数据库条目缺失或重复", ErrIntegrityFailed)
	}
	switch header.Content.Attachments.Status {
	case ContentIncluded:
		if attachments != header.Content.Attachments.Count {
			return "", fmt.Errorf("%w: 附件条目数量与头部不一致", ErrIntegrityFailed)
		}
	case ContentNoReferences, ContentNotConfigured:
		if attachments != 0 {
			return "", fmt.Errorf("%w: 未包含附件时不应有附件条目", ErrIntegrityFailed)
		}
	}
	switch header.Content.Config.Status {
	case ContentIncluded:
		if configs != header.Content.Config.Count {
			return "", fmt.Errorf("%w: 配置条目数量与头部不一致", ErrIntegrityFailed)
		}
	case ContentNotConfigured:
		if configs != 0 {
			return "", fmt.Errorf("%w: 未包含配置时不应有配置条目", ErrIntegrityFailed)
		}
	}
	expectedPlain := int64(4) + int64(len(manifestRaw)) + totalBytes
	if expectedPlain != header.Encryption.PayloadPlainBytes {
		return "", fmt.Errorf("%w: 载荷长度与清单条目不一致", ErrIntegrityFailed)
	}
	return manifestSHA, nil
}

// checkTrailer 读取密文后固定 32 字节 SHA-256 尾字段并与实际密文摘要比较。
// 尾字段不承担认证职责（认证由分块 AEAD 完成），只用于无密钥结构检查与发现
// 位翻转/截断；不匹配按完整性失败处理。
func checkTrailer(reader io.Reader, cipherDigest []byte) error {
	trailer := make([]byte, TrailerBytes)
	if _, err := io.ReadFull(reader, trailer); err != nil {
		return fmt.Errorf("%w: 备份密文摘要尾字段被截断", ErrIntegrityFailed)
	}
	if !bytes.Equal(trailer, cipherDigest) {
		return fmt.Errorf("%w: 备份密文摘要尾字段不一致", ErrIntegrityFailed)
	}
	return nil
}

// normalizeContext 把 nil ctx 当成 Background，避免调用方漏传时 panic；取消与
// 期限语义由非 nil ctx 提供。
func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
