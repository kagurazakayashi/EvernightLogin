package avatar

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// storageKeyPattern 是受控存储键格式：两字符分片目录 + 32 位十六进制文件名 +
// 服务端决定的扩展名。任何不符合该格式的键都不会被拼接成本机路径。
var storageKeyPattern = regexp.MustCompile(`^[0-9a-f]{2}/[0-9a-f]{32}\.(png|jpg)$`)

// storageShardPattern 是分片目录名格式。
var storageShardPattern = regexp.MustCompile(`^[0-9a-f]{2}$`)

// maxScanEntries 是 GC 扫描的目录项上限，超过则返回错误而不是部分清理。
const maxScanEntries = 50000

// StoredFile 是受控目录内的一个文件条目及其修改时间；修改时间供 GC 安全窗口判断
// 文件是否可能正被尚未提交的写入使用。
type StoredFile struct {
	Key        string
	ModifiedAt time.Time
}

// Storage 是受控头像文件存储契约，由 LocalStorage 提供生产实现。键由服务端生成，
// 调用方不能传入任意路径或文件名。
type Storage interface {
	// Save 在受控目录内以服务端生成的文件名创建新文件（O_EXCL，不覆盖），
	// 返回存储键；创建失败时不得留下残留文件。
	Save(ctx context.Context, data []byte, extension string) (string, error)
	// Open 按存储键读取文件内容；键非法、路径逃逸、符号链接或非普通文件时拒绝，
	// 读取后不跟随符号链接（os.Lstat 先判类型，打开后再 Fstat 复核）。
	Open(ctx context.Context, key string) ([]byte, error)
	// Remove 删除存储键对应文件；文件已不存在按幂等成功处理。
	Remove(ctx context.Context, key string) error
	// ListFiles 列出受控目录内所有合法存储键及其修改时间（符号链接与非法文件名
	// 被忽略），供旧文件/孤儿文件清理与安全窗口判断。
	ListFiles(ctx context.Context) ([]StoredFile, error)
}

// LocalStorage 是基于宿主指定目录的受控本地头像存储。目录必须由宿主提供且
// 只用于头像；本实现不创建通用文件管理能力。
type LocalStorage struct {
	root string
}

// NewLocalStorage 校验并准备受控目录。只接受已存在目录或可创建的新目录；
// 符号链接目录一律拒绝，避免把写入导向未预期位置。
func NewLocalStorage(directory string) (*LocalStorage, error) {
	value := strings.TrimSpace(directory)
	if value == "" {
		return nil, fmt.Errorf("%w: 头像存储目录为空", ErrOptionsInvalid)
	}
	absolute, err := filepath.Abs(value)
	if err != nil {
		return nil, fmt.Errorf("%w: 头像存储目录无效", ErrOptionsInvalid)
	}
	info, err := os.Lstat(absolute)
	switch {
	case err == nil:
		if info.Mode()&fs.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: 头像存储目录不能是符号链接", ErrOptionsInvalid)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("%w: 头像存储路径不是目录", ErrOptionsInvalid)
		}
	case errors.Is(err, os.ErrNotExist):
		if mkdirErr := os.MkdirAll(absolute, 0o700); mkdirErr != nil {
			return nil, fmt.Errorf("%w: 无法创建头像存储目录", ErrOptionsInvalid)
		}
	default:
		return nil, fmt.Errorf("%w: 无法检查头像存储目录", ErrOptionsInvalid)
	}
	return &LocalStorage{root: absolute}, nil
}

// Save 生成随机存储键并以排他方式创建文件；失败时尽力删除已写入的残留文件。
func (s *LocalStorage) Save(ctx context.Context, data []byte, extension string) (string, error) {
	if s == nil {
		return "", fmt.Errorf("%w: 头像存储为空", ErrStorageUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	switch extension {
	case "png", "jpg":
	default:
		return "", fmt.Errorf("%w: 不允许的存储扩展名", ErrOptionsInvalid)
	}
	if len(data) == 0 || len(data) > MaxStoredBytes {
		return "", fmt.Errorf("%w: 待存储内容大小异常", ErrImageTooLarge)
	}
	// 17 字节随机数：前 2 个十六进制字符作为分片目录，其余 32 个作为文件名。
	random := make([]byte, 17)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("%w: 无法生成存储文件名", ErrStorageUnavailable)
	}
	encoded := hex.EncodeToString(random)
	key := encoded[:2] + "/" + encoded[2:] + "." + extension
	path, err := s.join(key)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("%w: 无法创建存储分片目录", ErrStorageUnavailable)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("%w: 无法创建头像文件", ErrStorageUnavailable)
	}
	written, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil || written != len(data) {
		_ = os.Remove(path)
		return "", fmt.Errorf("%w: 写入头像文件失败", ErrStorageUnavailable)
	}
	return key, nil
}

// Open 按存储键读取文件；先校验键格式与路径未逃逸，再用 os.Lstat 拒绝符号链接，
// 打开后 Fstat 复核确实是普通文件并限制读取大小，避免经由存储目录内的符号链接
// 读取受控目录之外的内容。
func (s *LocalStorage) Open(ctx context.Context, key string) ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("%w: 头像存储为空", ErrStorageUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path, err := s.join(key)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: 头像文件不存在", ErrStorageCorrupt)
		}
		return nil, fmt.Errorf("%w: 无法读取头像文件", ErrStorageUnavailable)
	}
	if !info.Mode().IsRegular() {
		// 符号链接、设备文件或目录一律拒绝，不跟随链接读取目录外内容。
		return nil, fmt.Errorf("%w: 头像路径不是普通文件", ErrStorageCorrupt)
	}
	if info.Size() <= 0 || info.Size() > MaxStoredBytes {
		return nil, fmt.Errorf("%w: 头像文件大小异常", ErrStorageCorrupt)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: 无法读取头像文件", ErrStorageUnavailable)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("%w: 无法检查头像文件", ErrStorageUnavailable)
	}
	if !opened.Mode().IsRegular() || opened.Size() <= 0 || opened.Size() > MaxStoredBytes {
		return nil, fmt.Errorf("%w: 头像路径不是普通文件", ErrStorageCorrupt)
	}
	// Lstat 与 Open 之间仍可能被替换为符号链接；打开后的 Fstat 结果必须与 Lstat
	// 是同一个文件（os.SameFile 在 Windows 与 Unix 均可用），否则拒绝读取。
	if !os.SameFile(info, opened) {
		return nil, fmt.Errorf("%w: 头像文件在读取期间被替换", ErrStorageCorrupt)
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxStoredBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: 无法读取头像文件", ErrStorageUnavailable)
	}
	if len(data) == 0 || len(data) > MaxStoredBytes {
		return nil, fmt.Errorf("%w: 头像文件大小异常", ErrStorageCorrupt)
	}
	return data, nil
}

// Remove 删除存储键对应文件；不存在按幂等成功处理，其余失败如实返回。
func (s *LocalStorage) Remove(ctx context.Context, key string) error {
	if s == nil {
		return fmt.Errorf("%w: 头像存储为空", ErrStorageUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	path, err := s.join(key)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: 无法删除头像文件", ErrStorageUnavailable)
	}
	return nil
}

// ListFiles 扫描受控目录内的合法存储键与修改时间；符号链接与非法文件名被忽略
// （不会被 GC 删除，也不参与引用判断）。
func (s *LocalStorage) ListFiles(ctx context.Context) ([]StoredFile, error) {
	if s == nil {
		return nil, fmt.Errorf("%w: 头像存储为空", ErrStorageUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	shards, err := os.ReadDir(s.root)
	if err != nil {
		return nil, fmt.Errorf("%w: 无法列出头像目录", ErrStorageUnavailable)
	}
	filesByKey := make([]StoredFile, 0, 32)
	scanned := 0
	for _, shard := range shards {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		scanned++
		if scanned > maxScanEntries {
			return nil, fmt.Errorf("%w: 头像目录项过多，拒绝部分扫描", ErrStorageUnavailable)
		}
		if !shard.IsDir() || !storageShardPattern.MatchString(shard.Name()) {
			continue
		}
		files, err := os.ReadDir(filepath.Join(s.root, shard.Name()))
		if err != nil {
			return nil, fmt.Errorf("%w: 无法列出分片目录", ErrStorageUnavailable)
		}
		for _, file := range files {
			scanned++
			if scanned > maxScanEntries {
				return nil, fmt.Errorf("%w: 头像目录项过多，拒绝部分扫描", ErrStorageUnavailable)
			}
			if !file.Type().IsRegular() {
				continue
			}
			key := shard.Name() + "/" + file.Name()
			if !storageKeyPattern.MatchString(key) {
				continue
			}
			info, infoErr := file.Info()
			if infoErr != nil {
				return nil, fmt.Errorf("%w: 无法读取头像文件信息", ErrStorageUnavailable)
			}
			filesByKey = append(filesByKey, StoredFile{Key: key, ModifiedAt: info.ModTime()})
		}
	}
	sort.Slice(filesByKey, func(left, right int) bool {
		return filesByKey[left].Key < filesByKey[right].Key
	})
	return filesByKey, nil
}

// join 校验存储键格式并把受控相对键解析为绝对路径，确保结果仍位于受控目录内。
func (s *LocalStorage) join(key string) (string, error) {
	if !storageKeyPattern.MatchString(key) {
		return "", fmt.Errorf("%w: 头像存储键格式非法", ErrInvalidRequest)
	}
	path := filepath.Join(s.root, filepath.FromSlash(key))
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("%w: 头像存储路径无效", ErrStorageUnavailable)
	}
	relative, err := filepath.Rel(s.root, absolute)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: 头像存储路径逃逸受控目录", ErrAccessDenied)
	}
	return absolute, nil
}
