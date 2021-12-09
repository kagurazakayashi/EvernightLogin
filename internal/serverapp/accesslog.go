package serverapp

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
)

// 访问日志轮转默认值与边界。
//
// 访问日志是 W3C 格式的单行记录，轮转在每次 Write 开始时按“写入后是否会超过上限”
// 判断，因此一条记录不会被拆到两个文件里（只保证单次 Write 不跨界，不保证 W3C
// 头字段跨文件延续，查看时按文件首行判断即可）。
const (
	// DefaultAccessLogMaxBytes 是单个访问日志文件默认上限（64 MiB）。
	DefaultAccessLogMaxBytes int64 = 64 << 20
	// DefaultAccessLogMaxFiles 是默认保留的历史文件数量（不含当前文件）。
	DefaultAccessLogMaxFiles = 5
	// MinAccessLogMaxBytes/MaxAccessLogMaxBytes 是单文件上限的允许范围。
	MinAccessLogMaxBytes int64 = 1 << 20
	MaxAccessLogMaxBytes int64 = 1 << 30
	// MinAccessLogMaxFiles/MaxAccessLogMaxFiles 是历史文件数量的允许范围。
	MinAccessLogMaxFiles = 1
	MaxAccessLogMaxFiles = 100
)

// errAccessLogClosed 表示访问日志写入器已关闭。
var errAccessLogClosed = errors.New("访问日志写入器已关闭")

// RotatingLogWriter 是受控的访问日志写入器：按大小轮转、限制历史文件数量、
// 文件使用受保护权限创建，轮转失败时不阻塞业务请求。
//
// 安全与可靠性：
//   - 只写访问日志（W3C 行），不写请求体、Cookie、Authorization 或秘密；
//   - 轮转失败时退化为继续写当前文件或标准错误，绝不因此让 HTTP 请求失败；
//   - 历史文件数量有上限，避免磁盘被无限增长的访问日志耗尽；
//   - Close 幂等，关闭后 Write 返回明确错误。
type RotatingLogWriter struct {
	path     string
	maxBytes int64
	maxFiles int
	logger   *slog.Logger

	mu       sync.Mutex
	file     *os.File
	size     int64
	fallback io.Writer
	closed   bool
	warned   bool
}

// NewRotatingLogWriter 打开（必要时创建）访问日志文件并构造轮转写入器。
//
// maxBytes 为 0 时使用 DefaultAccessLogMaxBytes；maxFiles 为 0 时使用
// DefaultAccessLogMaxFiles（不含当前文件）。取值超出允许范围时返回错误，
// 由调用方拒绝启动，避免静默退化成“不轮转”。
func NewRotatingLogWriter(path string, maxBytes int64, maxFiles int,
	logger *slog.Logger) (*RotatingLogWriter, error) {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if maxBytes == 0 {
		maxBytes = DefaultAccessLogMaxBytes
	}
	if maxBytes < MinAccessLogMaxBytes || maxBytes > MaxAccessLogMaxBytes {
		return nil, fmt.Errorf("访问日志单文件上限必须在 %d～%d 字节之间",
			MinAccessLogMaxBytes, MaxAccessLogMaxBytes)
	}
	if maxFiles == 0 {
		maxFiles = DefaultAccessLogMaxFiles
	}
	if maxFiles < MinAccessLogMaxFiles || maxFiles > MaxAccessLogMaxFiles {
		return nil, fmt.Errorf("访问日志历史文件数量必须在 %d～%d 之间",
			MinAccessLogMaxFiles, MaxAccessLogMaxFiles)
	}
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("访问日志路径无效: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(absolutePath), 0o700); err != nil {
		return nil, fmt.Errorf("创建访问日志目录失败: %w", err)
	}
	file, err := openAccessLogFile(absolutePath)
	if err != nil {
		return nil, err
	}
	size := int64(0)
	if info, statErr := file.Stat(); statErr == nil {
		size = info.Size()
	}
	return &RotatingLogWriter{
		path: absolutePath, maxBytes: maxBytes, maxFiles: maxFiles,
		logger: logger, file: file, size: size, fallback: os.Stderr,
	}, nil
}

// openAccessLogFile 以追加方式打开访问日志文件并收紧权限。
func openAccessLogFile(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("打开访问日志文件失败: %w", err)
	}
	if err := secrets.ProtectFile(path); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("收紧访问日志文件权限失败: %w", err)
	}
	return file, nil
}

// Write 写入一行（或一段）访问日志；超过单文件上限时先轮转。
func (w *RotatingLogWriter) Write(p []byte) (int, error) {
	if w == nil {
		return 0, errAccessLogClosed
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, errAccessLogClosed
	}
	if w.maxBytes > 0 && w.size > 0 && w.size+int64(len(p)) > w.maxBytes {
		w.rotateLocked()
	}
	if w.file == nil {
		// 轮转后重新打开失败：退化为标准错误，保证请求处理不受影响。
		if w.fallback != nil {
			return w.fallback.Write(p)
		}
		return 0, fmt.Errorf("%w: 访问日志文件不可用", errAccessLogClosed)
	}
	written, err := w.file.Write(p)
	w.size += int64(written)
	return written, err
}

// rotateLocked 关闭当前文件、顺延历史文件并重新打开新文件。
//
// 任何一步失败都只记录告警：优先保持“继续可写”而不是让访问日志错误升级为请求
// 错误。历史文件按 path.1 最新、path.N 最旧排列。
func (w *RotatingLogWriter) rotateLocked() {
	if w.file != nil {
		_ = w.file.Close()
		w.file = nil
	}
	_ = os.Remove(w.path + "." + strconv.Itoa(w.maxFiles))
	for index := w.maxFiles - 1; index >= 1; index-- {
		source := w.path + "." + strconv.Itoa(index)
		destination := w.path + "." + strconv.Itoa(index+1)
		if _, statErr := os.Stat(source); statErr != nil {
			continue
		}
		if renameErr := os.Rename(source, destination); renameErr != nil {
			w.warnOnce("访问日志历史文件顺延失败", renameErr)
		}
	}
	if renameErr := os.Rename(w.path, w.path+".1"); renameErr != nil {
		w.warnOnce("访问日志当前文件轮转失败", renameErr)
	}
	file, err := openAccessLogFile(w.path)
	if err != nil {
		w.warnOnce("访问日志轮转后重新打开失败，后续写入标准错误", err)
		return
	}
	w.file = file
	w.size = 0
}

// warnOnce 每条写入器只告警一次，避免破坏性故障刷屏日志。
func (w *RotatingLogWriter) warnOnce(message string, err error) {
	if w.warned {
		return
	}
	w.warned = true
	w.logger.Warn(message, "error", err)
}

// Close 关闭当前文件；可重复调用。关闭后不删除日志文件（保留给运维查看）。
func (w *RotatingLogWriter) Close() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	if w.file == nil {
		return nil
	}
	closeErr := w.file.Close()
	w.file = nil
	if closeErr != nil {
		return fmt.Errorf("关闭访问日志失败: %w", closeErr)
	}
	return nil
}

// 编译期确认 io.WriteCloser/io.Writer 契约。
var (
	_ io.Writer = (*RotatingLogWriter)(nil)
	_ io.Closer = (*RotatingLogWriter)(nil)
)
