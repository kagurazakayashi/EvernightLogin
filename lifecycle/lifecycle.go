// Package lifecycle 定义嵌入式运行时的公开生命周期契约（步骤 215）。
//
// 根包 login 保留 Instance 实现与 New 构造门面，并通过类型别名继续暴露这些
// 契约；internal 装配与服务只依赖本包，不再 import 根包，避免“根包 import
// internal 实现、internal 又反向 import 根包”的循环。
//
// 边界：
//   - 本包不实现实例、不打开数据库、不监听端口、不启动协程；
//   - 不提供伪造 root、跳过授权或关闭鉴权的入口；
//   - 只依赖公共叶子包与标准库，不依赖 internal/ 或根包。
package lifecycle

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/access"
	"github.com/kagurazakayashi/EvernightLogin/config"
	"github.com/kagurazakayashi/EvernightLogin/errs"
	"github.com/kagurazakayashi/EvernightLogin/extension"
	"github.com/kagurazakayashi/EvernightLogin/httpapi"
	"github.com/kagurazakayashi/EvernightLogin/ui"
)

// State 是 Instance 的生命周期状态。
type State string

const (
	// StateNew 表示实例已构造，尚未启动任何后台组件。
	StateNew State = "new"
	// StateRunning 表示后台组件已全部成功启动。
	StateRunning State = "running"
	// StateClosed 表示实例已关闭或启动失败；不能再启动。
	StateClosed State = "closed"
)

// String 返回状态的稳定字符串。
func (s State) String() string { return string(s) }

// BackgroundComponent 是可由 Instance 管理生命周期的后台组件。
type BackgroundComponent interface {
	// Start 启动组件；失败时必须自行清理已创建资源。
	Start(ctx context.Context) error
	// Close 停止组件并释放组件自己创建的资源，必须遵守 ctx 期限。
	Close(ctx context.Context) error
}

// Database 是宿主注入的数据库连接就绪检查契约；实例不关闭它。
type Database interface {
	Ping(ctx context.Context) error
}

// DatabaseFunc 是 Database 的函数适配器。
type DatabaseFunc func(ctx context.Context) error

// Ping 实现 Database。
func (f DatabaseFunc) Ping(ctx context.Context) error {
	if f == nil {
		return fmt.Errorf("数据库检查函数为空")
	}
	return f(ctx)
}

// LifecycleEventKind 是生命周期通知的事件分类。
type LifecycleEventKind string

const (
	// LifecycleStarted 表示实例与全部扩展/组件启动成功。
	LifecycleStarted LifecycleEventKind = "started"
	// LifecycleStartFailed 表示启动失败、取消或回滚。
	LifecycleStartFailed LifecycleEventKind = "start_failed"
	// LifecycleClosed 表示实例正常关闭完成。
	LifecycleClosed LifecycleEventKind = "closed"
	// LifecycleCloseFailed 表示关闭过程中出现错误。
	LifecycleCloseFailed LifecycleEventKind = "close_failed"
)

// Valid 报告事件分类是否已定义。
func (k LifecycleEventKind) Valid() bool {
	switch k {
	case LifecycleStarted, LifecycleStartFailed, LifecycleClosed, LifecycleCloseFailed:
		return true
	default:
		return false
	}
}

// LifecycleEvent 是发送给宿主 Notifier 的生命周期事件。
type LifecycleEvent struct {
	Kind         LifecycleEventKind
	State        State
	At           time.Time
	RequestID    string
	ErrorCode    errs.ErrorCode
	ErrorSummary string
}

// Notifier 是宿主注入的生命周期通知扩展；通知失败不影响生命周期结果。
type Notifier interface {
	Notify(ctx context.Context, event LifecycleEvent) error
}

// NotifierFunc 是 Notifier 的函数适配器。
type NotifierFunc func(ctx context.Context, event LifecycleEvent) error

// Notify 实现 Notifier。
func (f NotifierFunc) Notify(ctx context.Context, event LifecycleEvent) error {
	if f == nil {
		return fmt.Errorf("通知函数为空")
	}
	return f(ctx, event)
}

// ReadyChecker 是扩展可选的健康检查能力；失败按未就绪处理。
type ReadyChecker interface {
	CheckReady(ctx context.Context) error
}

// Options 是构造 Instance 的显式依赖。
//
// 构造本身不启动组件、不监听端口、不打开数据库、不创建协程；宿主可以只 New
// 后使用核心能力而不调用 Start。
type Options struct {
	// Config 为 nil 时使用 Default()；非 nil 时先通过 Validate 校验。
	Config *config.Config
	// Components 是 Instance 接管生命周期的后台组件。
	Components []BackgroundComponent
	// Logger 是宿主注入的结构化日志器；实例不关闭或替换它。
	Logger *slog.Logger
	// LogOutput 只在 Logger 为 nil 时使用；nil 表示 io.Discard。
	LogOutput io.Writer
	// Extensions 是宿主注册的扩展；由实例管理启动/关闭。
	Extensions []extension.Extension
	// Pages 是可选的内置页面装配；设置时必须同时设置 HTTP。
	Pages *ui.WebUIOptions
	// HTTP 是可选的 HTTP 处理器装配；实例不监听端口。
	HTTP *httpapi.HTTPOptions
	// Database 是宿主拥有的数据库就绪检查依赖；实例绝不关闭它。
	Database Database
	// Notifications 是宿主拥有的生命周期通知器；实例不关闭它。
	Notifications Notifier
	// AccessControl 是宿主注入的真实授权判定扩展；未注入时 CheckAccess 拒绝。
	AccessControl access.AccessController
	// ExtensionStartTimeout 是单个扩展 Start 的墙钟上限；0 使用根包默认。
	ExtensionStartTimeout time.Duration
}

// Runner 是宿主/独立服务需要的运行生命周期最小契约；根包 Instance 实现它。
type Runner interface {
	Start(ctx context.Context) error
	Close(ctx context.Context) error
}

// Factory 根据公开 Options 构造 Runner；由宿主或进程入口注入根包构造器，
// 使 internal 装配无需 import 根包。
type Factory func(options Options) (Runner, error)
