package backup

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/fsutil"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
)

// ExtractOptions 是一次受控解包（恢复暂存/离线查看）的参数。
//
// 安全边界：只接受绝对路径的已存在受控目录（非符号链接，非 Windows 不向组/其他
// 用户开放写权限）；条目名在清单校验阶段已通过 validateEntryName 白名单校验，本
// 流程再按“解析后仍位于目标目录内”复核；父目录逐级用 Lstat 校验（已存在必须是
// 真实目录，拒绝符号链接/普通文件），条目文件以 O_CREATE|O_EXCL|O_WRONLY 0600
// 独占创建（不覆盖已有文件、不跟随预置符号链接）。本函数不执行备份中的任何内容、
// 不连接数据库、不修改备份文件。
type ExtractOptions struct {
	// Path 是备份文件路径。
	Path string
	// Keyring 是主密钥环（必须与备份文件分离保管）。
	Keyring *secrets.Keyring
	// Destination 是已存在的受控暂存目录（恢复流程/离线查看使用 0700 独立目录）。
	Destination string
	// OnlyEntries 可选条目过滤：返回 false 的条目只校验不落盘；nil 表示全部解包。
	OnlyEntries func(entry ManifestEntry) bool
	// MaxSelectedBytes 是所选条目（真正落盘）的合计字节上限，防止异常备份把
	// 受控暂存目录写满；0 表示使用 MaxBackupFileBytes。
	MaxSelectedBytes int64
	// MaxSelectedEntries 是所选条目数量上限；0 表示使用 MaxEntries。
	MaxSelectedEntries int
}

// ExtractedEntry 是一个已落盘并通过摘要校验的解包条目。
type ExtractedEntry struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	SizeBytes int64  `json:"size_bytes"`
	SHA256    string `json:"sha256"`
	Path      string `json:"path"`
}

// ExtractResult 是认证解包结果：VerifyReport 与 VerifyFile 同语义（Authenticated=true
// 表示已完成认证解密且全部条目摘要通过），并给出数据库/附件/配置条目的落盘路径。
type ExtractResult struct {
	Report       VerifyReport
	DatabasePath string
	Attachments  []ExtractedEntry
	ConfigPath   string
	Entries      []ExtractedEntry
}

// Extract 认证解密备份文件并把条目流式写入受控暂存目录。错误密钥/篡改返回
// ErrDecryptFailed/ErrIntegrityFailed；目标目录或条目路径不安全返回 ErrInvalidRequest/
// ErrOutputDirUnsafe，不落盘或按调用方清理暂存目录。
func Extract(ctx context.Context, options ExtractOptions) (ExtractResult, error) {
	ctx = normalizeContext(ctx)
	if options.Keyring == nil {
		return ExtractResult{}, fmt.Errorf("%w: 未提供主密钥环，无法解包加密备份",
			ErrOptionsInvalid)
	}
	destination, err := validateExtractDestination(options.Destination)
	if err != nil {
		return ExtractResult{}, err
	}
	file, fileSize, err := openBackupFile(options.Path)
	if err != nil {
		return ExtractResult{}, err
	}
	defer file.Close()
	fileHasher := sha256.New()
	tee := io.TeeReader(file, fileHasher)
	header, headerRaw, headerEnd, err := readHeaderFrom(tee)
	if err != nil {
		return ExtractResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return ExtractResult{}, err
	}
	expectedSize := int64(headerEnd) + header.Encryption.PayloadCipherBytes + TrailerBytes
	if fileSize != expectedSize {
		return ExtractResult{}, fmt.Errorf("%w: 备份文件大小 %d 与头部声明 %d 不一致",
			ErrIntegrityFailed, fileSize, expectedSize)
	}
	wrappedKey, decodeErr := base64.StdEncoding.DecodeString(header.Encryption.WrappedDataKey)
	if decodeErr != nil {
		return ExtractResult{}, fmt.Errorf("%w: 受保护载荷密钥格式非法", ErrFormatInvalid)
	}
	dataKey, err := unwrapDataKey(options.Keyring, header.BackupID,
		header.Encryption.KeyID, wrappedKey)
	if err != nil {
		return ExtractResult{}, err
	}
	sink := &extractSink{destination: destination, only: options.OnlyEntries,
		maxBytes: options.MaxSelectedBytes, maxEntries: options.MaxSelectedEntries,
		ctx: ctx}
	digest := headerHash(headerRaw)
	limited := &io.LimitedReader{R: tee, N: header.Encryption.PayloadCipherBytes}
	parser := newPayloadParser(header, digest, sink)
	// 每解密出一块（默认 1 MiB）都检查一次取消，使大数据库条目解包也能在
	// Ctrl+C 后尽快停止；失败时由 sink.abort 与调用方清理暂存目录。
	consume := func(data []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return parser.consume(data)
	}
	cipherDigest, err := decryptPayload(limited, header.Encryption, dataKey, digest,
		consume)
	if err != nil {
		sink.abort()
		return ExtractResult{}, err
	}
	if limited.N != 0 {
		sink.abort()
		return ExtractResult{}, fmt.Errorf("%w: 备份密文未被完整读取", ErrIntegrityFailed)
	}
	if err := checkTrailer(tee, cipherDigest[:]); err != nil {
		sink.abort()
		return ExtractResult{}, err
	}
	entries, manifestSHA, err := parser.finish()
	if err != nil {
		sink.abort()
		return ExtractResult{}, err
	}
	report := reportFromHeader(header, fileSize)
	report.StructuralValid = true
	report.Encrypted = true
	report.Authenticated = true
	report.ManifestAvailable = true
	report.CiphertextSHA256 = hex.EncodeToString(cipherDigest[:])
	report.ManifestSHA256 = manifestSHA
	report.FileSHA256 = hex.EncodeToString(fileHasher.Sum(nil))
	report.Entries = entries
	result := ExtractResult{Report: report, DatabasePath: sink.databasePath,
		Attachments: sink.attachments, ConfigPath: sink.configPath, Entries: sink.entries}
	return result, nil
}

// extractSink 把认证解密的条目正文写入受控暂存目录；未通过过滤的条目只校验不落盘。
type extractSink struct {
	destination string
	only        func(ManifestEntry) bool
	maxBytes    int64
	maxEntries  int
	ctx         context.Context

	current     *os.File
	currentPath string
	currentName string

	selectedCount int
	selectedBytes int64

	entries      []ExtractedEntry
	attachments  []ExtractedEntry
	databasePath string
	configPath   string
}

// OnManifest 在清单校验通过后调用，本实现无需额外准备。
func (s *extractSink) OnManifest(_ Manifest) error { return nil }

// BeginEntry 为条目创建独占文件；过滤掉的条目返回 nil 写入器（只校验摘要）。
func (s *extractSink) BeginEntry(entry ManifestEntry) (io.Writer, error) {
	if s.only != nil && !s.only(entry) {
		return nil, nil
	}
	if s.ctx != nil {
		if err := s.ctx.Err(); err != nil {
			return nil, err
		}
	}
	if entry.SizeBytes <= 0 || entry.SizeBytes > MaxBackupFileBytes {
		return nil, fmt.Errorf("%w: 条目大小非法", ErrIntegrityFailed)
	}
	maxBytes := s.maxBytes
	if maxBytes <= 0 || maxBytes > MaxBackupFileBytes {
		maxBytes = MaxBackupFileBytes
	}
	maxEntries := s.maxEntries
	if maxEntries <= 0 || maxEntries > MaxEntries {
		maxEntries = MaxEntries
	}
	// 解压膨胀防护：容器不压缩条目正文，但异常/恶意备份仍可能声明超大条目或
	// 海量条目；超过调用方授权上限时立刻失败，而不是先写满暂存目录。
	if s.selectedCount+1 > maxEntries {
		return nil, fmt.Errorf("%w: 所选条目数量超过上限 %d", ErrTooLarge, maxEntries)
	}
	if s.selectedBytes+entry.SizeBytes > maxBytes {
		return nil, fmt.Errorf("%w: 所选条目合计 %d 字节超过上限 %d",
			ErrTooLarge, s.selectedBytes+entry.SizeBytes, maxBytes)
	}
	target := filepath.Join(s.destination, filepath.FromSlash(entry.Name))
	relative, err := filepath.Rel(s.destination, target)
	if err != nil || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("%w: 条目路径逃逸受控暂存目录", ErrOutputDirUnsafe)
	}
	// 逐级创建父目录并拒绝已存在的符号链接/非目录组件（步骤 82 审计 L5）：
	// 不能使用 MkdirAll，否则目标目录内预置的符号链接会被跟随并越出暂存目录。
	if err := ensureSafeEntryParent(s.destination, entry.Name); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("%w: 无法创建条目文件", ErrBackupIO)
	}
	s.current = file
	s.currentPath = target
	s.currentName = entry.Name
	s.selectedCount++
	s.selectedBytes += entry.SizeBytes
	return file, nil
}

// EndEntry 在条目摘要校验通过后落盘同步并归档路径信息。
func (s *extractSink) EndEntry(entry ManifestEntry) error {
	if s.current == nil {
		// 被过滤的条目：只校验不落盘。
		return nil
	}
	file := s.current
	s.current = nil
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("%w: 条目 fsync 失败", ErrBackupIO)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("%w: 条目关闭失败", ErrBackupIO)
	}
	extracted := ExtractedEntry{Name: entry.Name, Kind: entry.Kind,
		SizeBytes: entry.SizeBytes, SHA256: entry.SHA256, Path: s.currentPath}
	s.entries = append(s.entries, extracted)
	switch entry.Kind {
	case EntryKindDatabase:
		s.databasePath = s.currentPath
	case EntryKindAttachment:
		s.attachments = append(s.attachments, extracted)
	case EntryKindConfig:
		s.configPath = s.currentPath
	}
	return nil
}

// abort 清理未完成的当前条目文件；已完成的条目由调用方清理整个暂存目录。
// 当前条目文件属于本次解包的中间产物，瞬时占用用有界重试吸收（失败仍忽略，
// 因为整个暂存目录随后由调用方删除）。
func (s *extractSink) abort() {
	if s.current == nil {
		return
	}
	path := s.currentPath
	_ = s.current.Close()
	_ = fsutil.RemoveRetry(path)
	s.current = nil
}

// validateExtractDestination 校验暂存目录是绝对路径、已存在的真实目录，且非 Windows
// 不向组/其他用户开放写权限。
func validateExtractDestination(path string) (string, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" || !filepath.IsAbs(trimmed) {
		return "", fmt.Errorf("%w: 解包目标必须是绝对路径目录", ErrOptionsInvalid)
	}
	info, err := os.Lstat(trimmed)
	if err != nil {
		return "", fmt.Errorf("%w: 解包目标目录不可用", ErrOutputDirUnsafe)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("%w: 解包目标必须是非符号链接目录", ErrOutputDirUnsafe)
	}
	if !isWindowsPlatform() && info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%w: 解包目标不能向组/其他用户开放权限", ErrOutputDirUnsafe)
	}
	absolute, err := filepath.Abs(trimmed)
	if err != nil {
		return "", fmt.Errorf("%w: 解包目标路径无效", ErrInvalidRequest)
	}
	return absolute, nil
}

// ensureSafeEntryParent 逐级创建条目父目录。已存在的每一级必须是真实目录：拒绝
// 符号链接、普通文件或其他特殊文件；不存在的目录以 0700 单独创建。这样即使攻击
// 者能预置暂存目录内容，也无法让后续条目文件越过暂存目录根（步骤 82 审计 L5：
// MkdirAll 会跟随已存在的符号链接组件，必须改为逐级 Lstat + 单级 Mkdir）。
func ensureSafeEntryParent(root, entryName string) error {
	segments := strings.Split(entryName, "/")
	for index := 0; index < len(segments)-1; index++ {
		segment := segments[index]
		if segment == "" || segment == "." || segment == ".." {
			return fmt.Errorf("%w: 条目名包含危险路径段", ErrOutputDirUnsafe)
		}
		parent := filepath.Join(root, filepath.FromSlash(strings.Join(segments[:index+1], "/")))
		info, err := os.Lstat(parent)
		switch {
		case err == nil:
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("%w: 条目父目录是符号链接", ErrOutputDirUnsafe)
			}
			if !info.IsDir() {
				return fmt.Errorf("%w: 条目父路径不是目录", ErrOutputDirUnsafe)
			}
		case errors.Is(err, os.ErrNotExist):
			if mkErr := os.Mkdir(parent, 0o700); mkErr != nil {
				return fmt.Errorf("%w: 无法创建条目子目录", ErrBackupIO)
			}
		default:
			return fmt.Errorf("%w: 无法检查条目父目录", ErrBackupIO)
		}
	}
	return nil
}
