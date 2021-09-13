package backup

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"
)

const (
	// DefaultConfigBytes 是配置快照默认字节上限。
	DefaultConfigBytes = 1 << 20
	// MaxConfigBytes 是配置快照硬上限，避免把大文件伪装成配置塞进备份。
	MaxConfigBytes = 8 << 20
)

// SnapshotInfo 是一致性数据库快照的版本元数据。
type SnapshotInfo struct {
	// Engine 是数据库引擎稳定标识；当前实现只支持 sqlite。
	Engine string
	// SchemaVersion 是 schema_history 中最高的迁移版本文本。
	SchemaVersion string
	// SchemaVersionNumber 是迁移版本文本的数字前缀（如 0042 → 42）；无法解析时
	// 使用 0 并在清单中保留原始文本。
	SchemaVersionNumber int
	// PageSize/PageCount 是 SQLite 快照页信息，仅供诊断与进度核对。
	PageSize  int
	PageCount int
}

// Snapshotter 生成数据库的一致性快照。生产实现必须使用数据库驱动的在线备份/
// 一致性快照机制，禁止复制运行中的主文件；实现必须在 ctx 取消时尽快停止，并在
// 失败时清理目的地文件（调用方也会兜底清理）。
type Snapshotter interface {
	Snapshot(ctx context.Context, destination string, progress func(donePages, totalPages int)) (SnapshotInfo, error)
}

// AttachmentInfo 是数据库快照中引用的一个附件。EntryName 是容器内安全相对名；
// SizeBytes/SHA256 来自实际读取的附件字节（实现必须与数据库记录交叉校验）。
type AttachmentInfo struct {
	EntryName string
	SizeBytes int64
	SHA256    [32]byte
}

// AttachmentSource 按数据库快照中的引用枚举并读取附件。
//
// List 必须基于给定快照文件（而不是活动数据库）枚举被引用的附件，使清单与
// 数据库快照对应；Open 可能被调用两次（清单摘要阶段与载荷写入阶段），实现必须
// 重新读取并允许调用方再次校验摘要，检测快照后附件被替换/删除。
type AttachmentSource interface {
	List(ctx context.Context, snapshotPath string) ([]AttachmentInfo, error)
	Open(ctx context.Context, entryName string) (io.ReadCloser, error)
}

// ConfigSnapshot 是宿主提供的配置快照。配置里的秘密应只以 env:/file: 引用形式
// 存在；本包不解析配置内容，也不把主密钥或明文秘密加入备份。
type ConfigSnapshot struct {
	EntryName string
	Format    string
	Data      []byte
}

// ConfigSource 提供待备份的配置快照。未配置时不备份配置，并在清单中显式记录
// not_configured，不得把“没有配置”伪装成已包含。
type ConfigSource interface {
	SnapshotConfig(ctx context.Context) (ConfigSnapshot, error)
}

// FileConfigSource 从本地 YAML 配置文件读取配置快照。它只接受普通文件、限制
// 字节数并在读取后复核大小，避免文件在读取期间增长绕过上限。
type FileConfigSource struct {
	path     string
	maxBytes int64
}

// NewFileConfigSource 校验配置文件路径与上限。路径必须是绝对路径；扩展名必须是
// .yaml 或 .yml（本项目配置格式固定为 YAML）。
func NewFileConfigSource(path string, maxBytes int64) (*FileConfigSource, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: 配置文件路径为空", ErrOptionsInvalid)
	}
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%w: 配置文件必须使用绝对路径", ErrOptionsInvalid)
	}
	extension := filepath.Ext(path)
	if extension != ".yaml" && extension != ".yml" {
		return nil, fmt.Errorf("%w: 配置文件必须是 YAML", ErrOptionsInvalid)
	}
	if maxBytes == 0 {
		maxBytes = DefaultConfigBytes
	}
	if maxBytes < 1 || maxBytes > MaxConfigBytes {
		return nil, fmt.Errorf("%w: 配置快照上限超出范围", ErrOptionsInvalid)
	}
	return &FileConfigSource{path: path, maxBytes: maxBytes}, nil
}

// SnapshotConfig 读取配置快照。文件不存在、不是普通文件、为空或超过上限时明确
// 失败；返回的数据是配置原文（不含被解析出的秘密值）。
func (s *FileConfigSource) SnapshotConfig(ctx context.Context) (ConfigSnapshot, error) {
	if s == nil || s.path == "" {
		return ConfigSnapshot{}, fmt.Errorf("%w: 配置快照源未初始化", ErrOptionsInvalid)
	}
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return ConfigSnapshot{}, err
	}
	file, err := os.Open(s.path)
	if err != nil {
		return ConfigSnapshot{}, fmt.Errorf("%w: 无法打开配置文件", ErrOptionsInvalid)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return ConfigSnapshot{}, fmt.Errorf("%w: 无法读取配置文件状态", ErrOptionsInvalid)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > s.maxBytes {
		return ConfigSnapshot{}, fmt.Errorf("%w: 配置文件必须是大小合规的普通文件", ErrOptionsInvalid)
	}
	limited := io.LimitReader(file, s.maxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return ConfigSnapshot{}, fmt.Errorf("%w: 读取配置文件失败", ErrOptionsInvalid)
	}
	if int64(len(data)) > s.maxBytes || int64(len(data)) != info.Size() {
		// 文件在检查与读取之间变化时拒绝，避免备份到不一致的配置。
		return ConfigSnapshot{}, fmt.Errorf("%w: 配置文件在读取期间变化", ErrAttachmentInconsistent)
	}
	return ConfigSnapshot{EntryName: configEntryName, Format: "yaml", Data: data}, nil
}

// isNilDependency 检测 nil 接口与 typed nil 指针，避免把 typed nil 当成可调用
// 依赖而 panic。服务构造时对所有注入依赖执行该检查（fail-closed）。
func isNilDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

// errTimeoutCause 是服务内部墙钟超时的 context cause，用于把“超时”与调用方
// 主动取消、已接受的取消请求区分开。
var errTimeoutCause = fmt.Errorf("backup wall clock timeout")

// contextSleep 是可被 ctx 取消的等待，用于重试间隔。
func contextSleep(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// runRegistry 是进程内活动备份登记表，用于把“取消请求”关联到真实执行并记录
// 真实取消者。它不持久化，也不跨进程协调；步骤 81 的持久任务/计划接入时再扩展。
type runRegistry struct {
	mu   sync.Mutex
	runs map[string]*runState
}

// newRunRegistry 创建空登记表。
func newRunRegistry() *runRegistry {
	return &runRegistry{runs: make(map[string]*runState)}
}

// register 登记一次运行；备份编号由安全随机源生成，重复登记属于内部错误。
func (r *runRegistry) register(state *runState) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.runs[state.id]; exists {
		return fmt.Errorf("%w: 备份编号重复", ErrInternal)
	}
	r.runs[state.id] = state
	return nil
}

// unregister 在运行结束后移除登记。
func (r *runRegistry) unregister(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.runs, id)
}

// lookup 返回活动运行；不存在返回 nil。
func (r *runRegistry) lookup(id string) *runState {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.runs[id]
}
