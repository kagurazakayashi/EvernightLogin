package backup

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// 容器格式常量。备份文件是自包含的单一文件：固定魔数 + 版本 + 明文头部 JSON +
// 分块认证加密的载荷；载荷内部是清单帧与各条目原文。清单（条目名/大小/SHA-256、
// 数据库版本与内容范围）位于认证加密载荷中，头部重复少量关键元数据以便无密钥时
// 只做结构检查（明确标记未认证）。修改布局必须提升 FormatVersion。
const (
	// Magic 是备份文件魔数（8 字节 ASCII）。
	Magic = "LNBACKUP"
	// FormatVersion 是当前备份容器/清单格式版本。
	FormatVersion = 1
	// containerPrefixBytes 是魔数 + 版本(2) + 头部长度(4)。
	containerPrefixBytes = len(Magic) + 2 + 4
	// MaxHeaderBytes 是明文头部 JSON 上限；头部只含元数据，不含条目正文。
	MaxHeaderBytes = 64 * 1024
	// MaxManifestBytes 是认证加密载荷内清单 JSON 上限。
	MaxManifestBytes = 8 * 1024 * 1024
	// MaxEntries 是单份备份的条目数上限，防止清单/解包膨胀。
	MaxEntries = 100000
	// MaxBackupFileBytes 是读取备份文件时接受的最大字节数（1 TiB）。写入侧由
	// 服务容量上限约束；读取侧只需防止把异常值当成有效长度。
	MaxBackupFileBytes = int64(1) << 40
	// MaxEntryNameBytes 是条目安全相对名上限。
	MaxEntryNameBytes = 200
	// 数据库条目的固定安全相对名；`/` 为容器内统一分隔符。
	databaseEntryName = "database/main.sqlite"
	// attachmentEntryPrefix 是头像等附件条目的固定前缀。
	attachmentEntryPrefix = "attachments/"
	// configEntryPrefix 是配置条目的固定前缀。
	configEntryPrefix = "config/"
	// configEntryName 是配置条目的固定名（本项目配置为 YAML）。
	configEntryName = "config/config.yaml"
	// DefaultChunkSize 是分块 AES-256-GCM 的默认块大小（1 MiB）。
	DefaultChunkSize = 1 << 20
	// MinChunkSize/MaxChunkSize 是读取时接受的块大小范围；写入固定使用
	// DefaultChunkSize。上下界限制单块内存与 GCM 调用规模。
	MinChunkSize = 64 * 1024
	MaxChunkSize = 16 * 1024 * 1024
	// NoncePrefixBytes 是每份备份随机 nonce 前缀长度；nonce = 前缀(8) + 块序号(4)。
	NoncePrefixBytes = 8
	// TrailerBytes 是密文后固定 32 字节 SHA-256 尾字段长度。它不经认证，只供无
	// 密钥时发现位翻转/截断；认证完整性由分块 AEAD 保证。
	TrailerBytes = 32
	// 内容状态稳定取值。
	ContentIncluded      = "included"
	ContentNoReferences  = "no_references"
	ContentNotConfigured = "not_configured"
	ContentExcluded      = "excluded"
	// 条目类型稳定取值。
	EntryKindDatabase   = "database"
	EntryKindAttachment = "attachment"
	EntryKindConfig     = "config"
	// 加密算法与分块格式稳定标识；升级算法/分块方案必须提升 FormatVersion。
	EncryptionAlgorithm = "AES-256-GCM"
	EncryptionFormat    = "chunked-v1"
	// DataKeyBytes 是每份备份随机生成的载荷数据密钥长度（AES-256）。
	DataKeyBytes = 32
	// 头部/载荷域分隔串，确保同一钥匙在不同用途下 AAD 不重叠。
	headerHashDomain = "evernight-login/backup/header/v1"
)

// Header 是备份文件的明文头部。它只含元数据与加密参数，不含数据库内容、清单
// 正文或任何秘密；完整性由载荷分块 AEAD 的 AAD 绑定（任何头部字节被修改都会
// 导致认证解密失败）。同名结构也写入认证加密清单，用于交叉校验。
type Header struct {
	FormatVersion  int            `json:"format_version"`
	BackupID       string         `json:"backup_id"`
	CreatedAt      string         `json:"created_at"`
	Host           string         `json:"host"`
	AppVersion     string         `json:"app_version"`
	Database       DatabaseMeta   `json:"database"`
	Content        ContentMeta    `json:"content"`
	EntriesCount   int            `json:"entries_count"`
	ManifestSHA256 string         `json:"manifest_sha256"`
	Encryption     EncryptionInfo `json:"encryption"`
}

// DatabaseMeta 是数据库快照元数据（引擎、schema_history 最高迁移、字节数、摘要）。
type DatabaseMeta struct {
	Engine              string `json:"engine"`
	SchemaVersion       string `json:"schema_version"`
	SchemaVersionNumber int    `json:"schema_version_number"`
	SizeBytes           int64  `json:"size_bytes"`
	SHA256              string `json:"sha256"`
}

// ContentStatus 是某一类内容的包含状态与数量/格式。状态必须显式，未配置的内容
// 记为 not_configured，不得用空对象伪装成已包含。
type ContentStatus struct {
	Status string `json:"status"`
	Count  int    `json:"count,omitempty"`
	Format string `json:"format,omitempty"`
}

// ContentMeta 是备份内容范围。Database 固定为 true（本工具只产出数据库备份）。
type ContentMeta struct {
	Database    bool          `json:"database"`
	Attachments ContentStatus `json:"attachments"`
	Config      ContentStatus `json:"config"`
	Keyring     ContentStatus `json:"keyring"`
}

// EncryptionInfo 是载荷加密参数。WrappedDataKey 是随机载荷密钥经主密钥环
// （secrets.Sealer）认证加密后的信封；主密钥材料本身绝不进入备份文件。
type EncryptionInfo struct {
	Algorithm          string `json:"algorithm"`
	Format             string `json:"format"`
	ChunkSizeBytes     int    `json:"chunk_size_bytes"`
	NoncePrefix        string `json:"nonce_prefix"`
	KeyID              string `json:"key_id"`
	WrappedDataKey     string `json:"wrapped_data_key"`
	PayloadPlainBytes  int64  `json:"payload_plain_bytes"`
	PayloadCipherBytes int64  `json:"payload_cipher_bytes"`
}

// Manifest 是受认证加密保护的完整清单。它在载荷内部，条目正文紧随其后，因此
// 无密钥无法枚举条目，也无法在保留认证的前提下修改条目名、大小或摘要。
type Manifest struct {
	FormatVersion int              `json:"format_version"`
	BackupID      string           `json:"backup_id"`
	CreatedAt     string           `json:"created_at"`
	Host          string           `json:"host"`
	AppVersion    string           `json:"app_version"`
	Database      ManifestDatabase `json:"database"`
	Capture       CaptureInfo      `json:"capture"`
	Content       ContentMeta      `json:"content"`
	Entries       []ManifestEntry  `json:"entries"`
}

// ManifestDatabase 是清单中的数据库版本信息。
type ManifestDatabase struct {
	Engine              string `json:"engine"`
	SchemaVersion       string `json:"schema_version"`
	SchemaVersionNumber int    `json:"schema_version_number"`
}

// CaptureInfo 记录各内容的捕获时间点，说明它们不是同一瞬间的原子快照：
// 数据库是 T0 的一致性在线快照；附件按该快照中的引用在 T1 读取并逐个校验摘要，
// 缺失或不一致会使备份失败；配置是独立文件，在 T2 读取。三者时间点都进入清单。
type CaptureInfo struct {
	DatabaseSnapshotStartedAt  string `json:"database_snapshot_started_at"`
	DatabaseSnapshotFinishedAt string `json:"database_snapshot_finished_at"`
	AttachmentsCapturedAt      string `json:"attachments_captured_at"`
	ConfigCapturedAt           string `json:"config_captured_at"`
}

// ManifestEntry 是清单中的一个内容条目。Name 是容器内安全相对名（固定 `/`
// 分隔），SizeBytes 与 SHA256 是条目原文的大小与摘要。
type ManifestEntry struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	SizeBytes int64  `json:"size_bytes"`
	SHA256    string `json:"sha256"`
}

// formatTime 把时间统一格式化为 UTC RFC3339（毫秒精度），保证同一时刻在不同
// 时区输入下清单文本确定。
func formatTime(value time.Time) string {
	return value.UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
}

// parseFormatTime 解析 formatTime 产出的时间；非法值返回错误。
func parseFormatTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, fmt.Errorf("%w: 时间字段为空", ErrInvalidRequest)
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: 时间字段不是 RFC3339", ErrInvalidRequest)
	}
	return parsed.UTC(), nil
}

// filePrefix 构造容器前缀：魔数 + 版本 + 头部长度 + 头部 JSON。
func filePrefix(headerRaw []byte) []byte {
	prefix := make([]byte, 0, containerPrefixBytes+len(headerRaw))
	prefix = append(prefix, Magic...)
	version := make([]byte, 2)
	binary.BigEndian.PutUint16(version, FormatVersion)
	prefix = append(prefix, version...)
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(headerRaw)))
	prefix = append(prefix, length...)
	prefix = append(prefix, headerRaw...)
	return prefix
}

// parseFilePrefix 解析容器前缀并返回头部原始 JSON 字节与载荷起始偏移。
func parseFilePrefix(raw []byte) ([]byte, int, error) {
	if len(raw) < containerPrefixBytes {
		return nil, 0, fmt.Errorf("%w: 备份文件过短", ErrFormatInvalid)
	}
	if string(raw[:len(Magic)]) != Magic {
		return nil, 0, fmt.Errorf("%w: 备份文件魔数不匹配", ErrFormatInvalid)
	}
	version := binary.BigEndian.Uint16(raw[len(Magic) : len(Magic)+2])
	if version != FormatVersion {
		return nil, 0, fmt.Errorf("%w: 备份容器版本 %d", ErrVersionUnsupported, version)
	}
	headerLength := int(binary.BigEndian.Uint32(raw[len(Magic)+2 : containerPrefixBytes]))
	if headerLength <= 0 || headerLength > MaxHeaderBytes {
		return nil, 0, fmt.Errorf("%w: 头部长度非法", ErrFormatInvalid)
	}
	if len(raw) < containerPrefixBytes+headerLength {
		return nil, 0, fmt.Errorf("%w: 备份文件头部被截断", ErrFormatInvalid)
	}
	return raw[containerPrefixBytes : containerPrefixBytes+headerLength],
		containerPrefixBytes + headerLength, nil
}

// marshalHeader 确定性序列化头部（结构体字段顺序固定，不使用 map）。
func marshalHeader(header Header) ([]byte, error) {
	encoded, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("%w: 无法序列化备份头部", ErrInternal)
	}
	return encoded, nil
}

// decodeHeader 解析头部并严格校验字段（拒绝未知字段，避免版本漂移时静默忽略
// 安全相关字段）。版本不受支持时返回 ErrVersionUnsupported。
func decodeHeader(raw []byte) (Header, error) {
	if len(raw) == 0 || len(raw) > MaxHeaderBytes {
		return Header{}, fmt.Errorf("%w: 头部长度非法", ErrFormatInvalid)
	}
	var probe struct {
		FormatVersion int `json:"format_version"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return Header{}, fmt.Errorf("%w: 头部不是合法 JSON", ErrFormatInvalid)
	}
	if probe.FormatVersion != FormatVersion {
		return Header{}, fmt.Errorf("%w: 备份格式版本 %d", ErrVersionUnsupported,
			probe.FormatVersion)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var header Header
	if err := decoder.Decode(&header); err != nil {
		return Header{}, fmt.Errorf("%w: 头部字段不合法", ErrInvalidRequest)
	}
	if err := validateHeader(header); err != nil {
		return Header{}, err
	}
	return header, nil
}

// marshalManifest 确定性序列化清单。
func marshalManifest(manifest Manifest) ([]byte, error) {
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("%w: 无法序列化备份清单", ErrInternal)
	}
	if len(encoded) > MaxManifestBytes {
		return nil, fmt.Errorf("%w: 备份清单超过 %d 字节", ErrTooLarge, MaxManifestBytes)
	}
	return encoded, nil
}

// decodeManifest 解析清单并严格校验；任何未知字段视为格式错误。
func decodeManifest(raw []byte) (Manifest, error) {
	if len(raw) == 0 || len(raw) > MaxManifestBytes {
		return Manifest{}, fmt.Errorf("%w: 清单长度非法", ErrFormatInvalid)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("%w: 清单字段不合法", ErrInvalidRequest)
	}
	return manifest, nil
}

// validateHeader 校验头部字段的内部一致性与取值边界。它不接触密钥，用于任何
// 读取路径（含无密钥结构检查）。
func validateHeader(header Header) error {
	if header.FormatVersion != FormatVersion {
		return fmt.Errorf("%w: 备份格式版本 %d", ErrVersionUnsupported, header.FormatVersion)
	}
	if err := validateBackupID(header.BackupID); err != nil {
		return err
	}
	if _, err := parseFormatTime(header.CreatedAt); err != nil {
		return err
	}
	if err := validateDisplayField("主机名", header.Host, 128); err != nil {
		return err
	}
	if err := validateDisplayField("应用版本", header.AppVersion, 128); err != nil {
		return err
	}
	if err := validateDatabaseMeta(header.Database); err != nil {
		return err
	}
	if err := validateContentMeta(header.Content); err != nil {
		return err
	}
	if header.EntriesCount < 1 || header.EntriesCount > MaxEntries {
		return fmt.Errorf("%w: 条目数量非法", ErrInvalidRequest)
	}
	if !validHexDigest(header.ManifestSHA256) {
		return fmt.Errorf("%w: 清单摘要格式非法", ErrInvalidRequest)
	}
	if err := validateEncryptionInfo(header.Encryption); err != nil {
		return err
	}
	return nil
}

// validateDatabaseMeta 校验数据库元数据。
func validateDatabaseMeta(meta DatabaseMeta) error {
	if meta.Engine != "sqlite" {
		return fmt.Errorf("%w: 不支持的数据库引擎", ErrInvalidRequest)
	}
	if err := validateDisplayField("数据库版本", meta.SchemaVersion, 128); err != nil {
		return err
	}
	if meta.SchemaVersionNumber < 0 || meta.SchemaVersionNumber > 1_000_000 {
		return fmt.Errorf("%w: 数据库版本号非法", ErrInvalidRequest)
	}
	if meta.SizeBytes <= 0 {
		return fmt.Errorf("%w: 数据库快照大小非法", ErrInvalidRequest)
	}
	if !validHexDigest(meta.SHA256) {
		return fmt.Errorf("%w: 数据库快照摘要格式非法", ErrInvalidRequest)
	}
	return nil
}

// validateContentMeta 校验内容范围状态。数据库必须包含；附件/配置状态只能是
// 明确列出的几个值；密钥环固定为 excluded（主密钥与备份分离）。
func validateContentMeta(meta ContentMeta) error {
	if !meta.Database {
		return fmt.Errorf("%w: 备份内容未包含数据库", ErrInvalidRequest)
	}
	if err := validateContentStatus("附件", meta.Attachments,
		ContentIncluded, ContentNoReferences, ContentNotConfigured); err != nil {
		return err
	}
	if err := validateContentStatus("配置", meta.Config,
		ContentIncluded, ContentNotConfigured); err != nil {
		return err
	}
	if meta.Config.Status == ContentIncluded && meta.Config.Format != "yaml" {
		return fmt.Errorf("%w: 配置格式只支持 yaml", ErrInvalidRequest)
	}
	if err := validateContentStatus("密钥环", meta.Keyring, ContentExcluded); err != nil {
		return err
	}
	return nil
}

// validateContentStatus 校验单一内容状态与数量边界。
func validateContentStatus(label string, status ContentStatus, allowed ...string) error {
	for _, value := range allowed {
		if status.Status == value {
			if status.Status == ContentIncluded && status.Count <= 0 {
				return fmt.Errorf("%w: %s已包含但数量为空", ErrInvalidRequest, label)
			}
			if status.Count < 0 || status.Count > MaxEntries {
				return fmt.Errorf("%w: %s数量非法", ErrInvalidRequest, label)
			}
			return nil
		}
	}
	return fmt.Errorf("%w: %s状态未定义", ErrInvalidRequest, label)
}

// validateEncryptionInfo 校验加密参数并核对分块长度数学关系。任何不自洽的头部
// 都在解密前被拒绝，避免用错误块数读取或分配内存。
func validateEncryptionInfo(info EncryptionInfo) error {
	if info.Algorithm != EncryptionAlgorithm {
		return fmt.Errorf("%w: 不支持的加密算法", ErrInvalidRequest)
	}
	if info.Format != EncryptionFormat {
		return fmt.Errorf("%w: 不支持的加密分块格式", ErrInvalidRequest)
	}
	if info.ChunkSizeBytes < MinChunkSize || info.ChunkSizeBytes > MaxChunkSize {
		return fmt.Errorf("%w: 加密块大小超出范围", ErrInvalidRequest)
	}
	prefix, err := base64.StdEncoding.DecodeString(info.NoncePrefix)
	if err != nil || len(prefix) != NoncePrefixBytes {
		return fmt.Errorf("%w: nonce 前缀格式非法", ErrInvalidRequest)
	}
	if err := validateDisplayField("密钥编号", info.KeyID, 64); err != nil {
		return err
	}
	if info.WrappedDataKey == "" {
		return fmt.Errorf("%w: 缺少受保护载荷密钥", ErrInvalidRequest)
	}
	dataKeyEnvelope, err := base64.StdEncoding.DecodeString(info.WrappedDataKey)
	if err != nil || len(dataKeyEnvelope) == 0 || len(dataKeyEnvelope) > 512 {
		return fmt.Errorf("%w: 受保护载荷密钥格式非法", ErrInvalidRequest)
	}
	if info.PayloadPlainBytes <= 0 {
		return fmt.Errorf("%w: 载荷长度非法", ErrInvalidRequest)
	}
	chunks := PayloadChunks(info.PayloadPlainBytes, info.ChunkSizeBytes)
	if chunks <= 0 || chunks > 1<<31 {
		return fmt.Errorf("%w: 载荷块数非法", ErrInvalidRequest)
	}
	expectedCipher := info.PayloadPlainBytes +
		int64(chunks)*int64(aeadTagBytes)
	if info.PayloadCipherBytes != expectedCipher {
		return fmt.Errorf("%w: 载荷密文长度与块数不一致", ErrInvalidRequest)
	}
	return nil
}

// PayloadChunks 返回给定明文字节数与块大小时的分块数量（至少 1 块）。
func PayloadChunks(plainBytes int64, chunkSize int) int64 {
	if plainBytes <= 0 || chunkSize <= 0 {
		return 0
	}
	chunks := plainBytes / int64(chunkSize)
	if plainBytes%int64(chunkSize) != 0 {
		chunks++
	}
	if chunks <= 0 {
		chunks = 1
	}
	return chunks
}

// validateEntryName 校验条目安全相对名：只允许固定 ASCII 字符与 `/` 分隔，
// 拒绝空段、`.`、`..`、反斜杠、绝对路径与控制字符、Windows 保留设备名与尾随
// 点/空格，并按类型检查固定前缀。
func validateEntryName(kind, name string) error {
	if err := validateEntryNameShape(name); err != nil {
		return err
	}
	switch kind {
	case EntryKindDatabase:
		if name != databaseEntryName {
			return fmt.Errorf("%w: 数据库条目名非法", ErrInvalidRequest)
		}
	case EntryKindAttachment:
		if !strings.HasPrefix(name, attachmentEntryPrefix) ||
			len(name) == len(attachmentEntryPrefix) {
			return fmt.Errorf("%w: 附件条目名非法", ErrInvalidRequest)
		}
	case EntryKindConfig:
		if name != configEntryName {
			return fmt.Errorf("%w: 配置条目名非法", ErrInvalidRequest)
		}
	default:
		return fmt.Errorf("%w: 条目类型未定义", ErrInvalidRequest)
	}
	return nil
}

// validateEntryKind 报告条目类型是否已定义。
func validateEntryKind(kind string) error {
	switch kind {
	case EntryKindDatabase, EntryKindAttachment, EntryKindConfig:
		return nil
	default:
		return fmt.Errorf("%w: 条目类型未定义", ErrInvalidRequest)
	}
}

// validateBackupID 校验备份编号格式（bkp_ + 128 位随机十六进制）。
func validateBackupID(id string) error {
	if !strings.HasPrefix(id, backupIDPrefix) {
		return fmt.Errorf("%w: 备份编号前缀非法", ErrInvalidRequest)
	}
	rest := id[len(backupIDPrefix):]
	if len(rest) != 2*backupIDRandomBytes {
		return fmt.Errorf("%w: 备份编号长度非法", ErrInvalidRequest)
	}
	if _, err := hex.DecodeString(rest); err != nil {
		return fmt.Errorf("%w: 备份编号编码非法", ErrInvalidRequest)
	}
	return nil
}

// validateDisplayField 校验短元数据文本：非空、长度受限、可见 UTF-8、无控制字符。
func validateDisplayField(label, value string, maxBytes int) error {
	if value == "" {
		return fmt.Errorf("%w: %s为空", ErrInvalidRequest, label)
	}
	if len(value) > maxBytes {
		return fmt.Errorf("%w: %s超过 %d 字节", ErrInvalidRequest, label, maxBytes)
	}
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return fmt.Errorf("%w: %s包含控制字符", ErrInvalidRequest, label)
		}
	}
	return nil
}

// validHexDigest 报告是否为 32 字节 SHA-256 的小写十六进制文本。
func validHexDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}

// validateEntryNameShape 校验条目名的通用形状（不校验 kind 固定前缀），供清单
// 校验与离线单项提取的用户输入共用：只允许受控 ASCII 相对路径；拒绝空段、
// `.`/`..`、反斜杠、绝对路径、控制字符、Windows 保留设备名（CON/PRN/AUX/NUL/
// COM1-9/LPT1-9，含带扩展名形式）以及尾随点/空格（Windows 会静默去除，可能
// 造成同名覆盖/别名绕过）。主机平台无关地统一拒绝，避免同类备份跨平台行为不同。
func validateEntryNameShape(name string) error {
	if name == "" || len(name) > MaxEntryNameBytes {
		return fmt.Errorf("%w: 条目名长度非法", ErrInvalidRequest)
	}
	if strings.Contains(name, `\`) || strings.HasPrefix(name, "/") {
		return fmt.Errorf("%w: 条目名包含非法分隔符", ErrInvalidRequest)
	}
	for i := 0; i < len(name); i++ {
		char := name[i]
		allowed := char == '/' || char == '.' || char == '_' || char == '-' ||
			(char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9')
		if !allowed {
			return fmt.Errorf("%w: 条目名包含不允许的字符", ErrInvalidRequest)
		}
	}
	if strings.HasSuffix(name, "/") || strings.Contains(name, "//") {
		return fmt.Errorf("%w: 条目名包含空路径段", ErrInvalidRequest)
	}
	for _, segment := range strings.Split(name, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return fmt.Errorf("%w: 条目名包含危险路径段", ErrInvalidRequest)
		}
		if err := validateWindowsSafeSegment(segment); err != nil {
			return err
		}
	}
	return nil
}

// validateWindowsSafeSegment 拒绝 Windows 保留设备名与尾随点/空格。保留名匹配
// 不区分大小写，且按“第一个点之前的主名”判断（CON.txt 同样是设备名）。
func validateWindowsSafeSegment(segment string) error {
	if segment == "" {
		return fmt.Errorf("%w: 条目名包含空路径段", ErrInvalidRequest)
	}
	if strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, " ") {
		return fmt.Errorf("%w: 条目名包含尾随点或空格", ErrInvalidRequest)
	}
	base := segment
	if index := strings.IndexByte(segment, '.'); index >= 0 {
		base = segment[:index]
	}
	upper := strings.ToUpper(base)
	switch upper {
	case "CON", "PRN", "AUX", "NUL":
		return fmt.Errorf("%w: 条目名是 Windows 保留设备名", ErrInvalidRequest)
	}
	if len(upper) == 4 && (strings.HasPrefix(upper, "COM") ||
		strings.HasPrefix(upper, "LPT")) && upper[3] >= '1' && upper[3] <= '9' {
		return fmt.Errorf("%w: 条目名是 Windows 保留设备名", ErrInvalidRequest)
	}
	return nil
}
