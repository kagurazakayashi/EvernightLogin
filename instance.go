package login

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/logging"
)

// State 表示 Instance 的生命周期状态。
//
// 状态转换只有一条路径：New 后为 StateNew；Start 成功后为 StateRunning；
// Close 或启动失败后为 StateClosed。实例不会从 StateClosed 回到其他状态，
// 避免反复启动产生多套资源。
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
func (s State) String() string {
	return string(s)
}

// ErrAlreadyStarted 表示实例已经成功启动；Start 不会重复启动组件。
var ErrAlreadyStarted = errors.New("实例已经启动")

// ErrClosed 表示实例已经关闭或启动失败，不能再启动。
var ErrClosed = errors.New("实例已经关闭")

// BackgroundComponent 是可由 Instance 管理生命周期的后台组件。
//
// 生命周期约定：
//
//   - Start 按 Options.Components 的声明顺序调用；返回错误表示启动失败，实现
//     必须在返回错误前清理自己已创建的资源，Instance 不会对启动失败的组件
//     调用 Close。
//   - Close 按启动顺序的逆序调用，只对成功启动过的组件各调用一次；必须响应
//     ctx 取消，不得在取消后继续阻塞。
//   - 组件只释放自己创建的资源。宿主传入的数据库连接、HTTP 服务器、日志器、
//     密钥文件句柄、页面 FS 等由宿主关闭，组件不得关闭。
//
// 本步没有内置后台组件，也不实现任务队列；测试用替身模拟后续数据库、HTTP
// 和任务组件，测试替身不是生产服务。
type BackgroundComponent interface {
	// Start 启动组件。它可以使用 ctx 的超时与取消，并在失败时自行清理。
	Start(ctx context.Context) error
	// Close 停止组件并释放组件自己创建的资源。它可以被 Instance 在启动
	// 失败回滚或正常关闭时调用，必须遵守 ctx 的期限。
	Close(ctx context.Context) error
}

// Options 是构造 Instance 的显式依赖。
//
// 构造本身不启动组件、不监听端口、不打开数据库、不创建协程；宿主可以只
// New 后使用核心能力而不调用 Start，后台组件在后续步骤接入。
type Options struct {
	// Config 为 nil 时使用 Default()；非 nil 时先通过 Config.Validate 校验，
	// 校验失败时 New 返回 CONFIG_INVALID 的统一错误。
	Config *Config
	// Components 是 Instance 接管生命周期的后台组件，按声明顺序启动、按启动
	// 顺序的逆序关闭。组件对象可以由宿主构造（扩展或测试），但一旦传入就由
	// Instance 管理启动与关闭；同一组件不得同时交给多个 Instance。
	Components []BackgroundComponent
	// Logger 是宿主注入的结构化日志器。非 nil 时实例直接使用，由宿主负责其
	// 级别、格式与生命周期，实例不会关闭或替换它；此时 Config.Logging 的级别
	// 与格式不生效。nil 时实例按 Config.Logging 创建默认日志器。
	Logger *slog.Logger
	// LogOutput 只在 Logger 为 nil 时使用，作为默认日志器的输出目标；nil 表示
	// io.Discard，让嵌入模式默认静默。独立服务器在后续步骤会传入标准错误输出。
	LogOutput io.Writer
}

// Instance 是 login 的隔离实例。
//
// 同一进程可以创建多个 Instance；实例之间不共享状态、组件或全局单例。
// Instance 的方法并发安全：Start、Close 由内部互斥锁串行化，重复 Close 安全，
// 启动成功后再次 Start 返回 ErrAlreadyStarted。
//
// 组件回调执行期间 Instance 持有内部锁；组件不得在 Start/Close 中同步调用
// 同一实例的 Start/Close/State/Config/Logger，否则会阻塞或死锁。
type Instance struct {
	mu           sync.Mutex
	state        State
	config       Config
	components   []BackgroundComponent
	started      []startedComponent
	logger       *slog.Logger
	closeTimeout time.Duration
}

// startedComponent 记录成功启动的组件及其在 Options 中的原始下标，用于逆序
// 关闭和错误信息定位。
type startedComponent struct {
	index     int
	component BackgroundComponent
}

// New 构造一个 Instance，但不启动任何组件、不监听端口、不打开数据库、不创建
// 协程。Options.Config 为 nil 时使用 Default()；传入非法配置时返回
// CONFIG_INVALID 的统一错误并保留配置校验原因链；nil 组件会被拒绝。
//
// 宿主可以只构造实例并使用核心能力；只有需要后台组件时才调用 Start。多个
// Instance 可以在同一进程内并存且互不影响。
func New(opts Options) (*Instance, error) {
	config := Default()
	if opts.Config != nil {
		if err := opts.Config.Validate(); err != nil {
			return nil, NewAppError(CodeConfigInvalid, "",
				WithCause(err), WithRequestID(NewRequestID()))
		}
		config = *opts.Config
	}

	logger := opts.Logger
	if logger == nil {
		created, err := logging.New(string(config.Logging.Level), string(config.Logging.Format), opts.LogOutput)
		if err != nil {
			return nil, NewAppError(CodeInternalError, "无法创建运行日志器",
				WithCause(err), WithRequestID(NewRequestID()))
		}
		logger = created
	}

	components := make([]BackgroundComponent, len(opts.Components))
	for index, component := range opts.Components {
		if component == nil {
			return nil, fmt.Errorf("Options.Components[%d] 为 nil", index)
		}
		components[index] = component
	}

	return &Instance{
		state:        StateNew,
		config:       config,
		components:   components,
		logger:       logger,
		closeTimeout: time.Duration(config.Server.ShutdownTimeoutSeconds) * time.Second,
	}, nil
}

// State 返回当前生命周期状态。
func (i *Instance) State() State {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.state
}

// Config 返回构造时配置的副本。修改返回值不会影响实例；热更新配置的后台在
// 后续步骤实现。
func (i *Instance) Config() Config {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.config
}

// Logger 返回实例使用的结构化日志器：宿主注入时返回宿主日志器，否则返回按
// Config.Logging 创建的默认日志器。宿主日志器由宿主管理，实例不关闭它。
func (i *Instance) Logger() *slog.Logger {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.logger
}

// Start 按声明顺序启动所有后台组件。
//
// Start 只能成功调用一次：成功后再次调用返回 ErrAlreadyStarted；实例关闭后
// 调用返回 ErrClosed；启动失败或启动前 ctx 已结束时实例进入 StateClosed，
// 之后不能再启动。任一组件启动失败时，已成功启动的组件按逆序关闭，失败组件
// 由它自己清理；回滚关闭错误会与启动错误一起返回。
//
// 返回的生命周期错误是统一 AppError（未分类组件错误回退为 INTERNAL_ERROR），
// 带 request_id 并写入结构化运行日志；组件返回的具体 AppError 会保留错误码。
// 组件在 ctx 取消时仍应尽快返回错误，Instance 不启动后台协程等它结束。
func (i *Instance) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	switch i.state {
	case StateRunning:
		return ErrAlreadyStarted
	case StateClosed:
		return ErrClosed
	}

	if err := ctx.Err(); err != nil {
		requestID := NewRequestID()
		appError := NewAppError(CodeInternalError, "实例启动已取消",
			WithCause(err), WithRequestID(requestID))
		i.logger.Warn("实例启动已取消", "request_id", requestID, "error", appError)
		i.state = StateClosed
		return appError
	}

	i.logger.Debug("实例开始启动", "component_count", len(i.components))
	i.started = make([]startedComponent, 0, len(i.components))
	for index, component := range i.components {
		if err := ctx.Err(); err != nil {
			requestID := NewRequestID()
			appError := NewAppError(CodeInternalError, "实例启动已取消",
				WithCause(err), WithRequestID(requestID))
			errs := []error{appError}
			for _, rollbackErr := range i.rollbackStarted() {
				errs = append(errs, classifyLifecycleError("启动取消后回滚关闭组件失败", rollbackErr, requestID))
			}
			i.logger.Error("实例启动已取消", "request_id", requestID, "error", appError)
			i.state = StateClosed
			return errors.Join(errs...)
		}
		i.logger.Debug("启动后台组件",
			"component_index", index, "component_type", fmt.Sprintf("%T", component))
		if err := component.Start(ctx); err != nil {
			requestID := NewRequestID()
			appError := classifyLifecycleError("后台组件启动失败", err, requestID)
			errs := []error{appError}
			for _, rollbackErr := range i.rollbackStarted() {
				errs = append(errs, classifyLifecycleError("启动失败后回滚关闭组件失败", rollbackErr, requestID))
			}
			i.logger.Error("后台组件启动失败",
				"component_index", index,
				"component_type", fmt.Sprintf("%T", component),
				"request_id", requestID, "error", appError)
			i.state = StateClosed
			return errors.Join(errs...)
		}
		i.started = append(i.started, startedComponent{index: index, component: component})
	}

	i.state = StateRunning
	i.logger.Info("实例启动完成", "component_count", len(i.started))
	return nil
}

// Close 按启动顺序的逆序关闭已启动组件，并释放 Instance 自己创建的内部资源。
//
// 关闭受两重期限约束：调用方 ctx 的期限，以及构造时配置的
// Server.ShutdownTimeoutSeconds。Close 可以安全重复调用；第一次关闭后后续
// 调用直接返回 nil。从未启动直接 Close 也会使实例进入 StateClosed。
//
// 关闭错误会聚合返回（未分类组件错误回退为 INTERNAL_ERROR，带 request_id 并
// 写入结构化运行日志），但实例仍标记为已关闭；后续 Close 不重复返回旧错误。
// 组件关闭期间 Instance 持有内部锁，因此并发 Close 会串行化。
func (i *Instance) Close(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	switch i.state {
	case StateNew:
		i.state = StateClosed
		i.logger.Debug("实例在启动前关闭")
		return nil
	case StateClosed:
		return nil
	}

	closeCtx, cancel := context.WithTimeout(ctx, i.closeTimeout)
	defer cancel()
	requestID := NewRequestID()
	closeErrors := i.closeStarted(closeCtx)
	i.started = nil
	i.state = StateClosed

	if len(closeErrors) == 0 {
		i.logger.Info("实例已关闭", "request_id", requestID)
		return nil
	}
	wrapped := make([]error, 0, len(closeErrors))
	for _, closeErr := range closeErrors {
		appError := classifyLifecycleError("关闭后台组件失败", closeErr, requestID)
		wrapped = append(wrapped, appError)
		i.logger.Error("关闭后台组件失败", "request_id", requestID, "error", appError)
	}
	return errors.Join(wrapped...)
}

// classifyLifecycleError 把生命周期错误转为统一 AppError。已经是 AppError 的
// 组件错误保留错误码；如果没有请求编号则补上本次生命周期操作编号。未分类错误
// 回退为 INTERNAL_ERROR，并保留原因链供受限诊断。
func classifyLifecycleError(message string, err error, requestID string) *AppError {
	if appError, ok := AsAppError(err); ok {
		if appError.RequestID() != "" {
			return appError
		}
		cloned := *appError
		cloned.requestID = requestID
		return &cloned
	}
	return NewAppError(CodeInternalError, message,
		WithCause(err), WithRequestID(requestID))
}

// rollbackStarted 在启动失败时逆序关闭已启动组件。它使用独立于启动 ctx 的
// 有期限上下文，确保启动被取消时仍尝试释放已创建资源。
func (i *Instance) rollbackStarted() []error {
	if len(i.started) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), i.closeTimeout)
	defer cancel()
	errs := i.closeStarted(ctx)
	i.started = nil
	return errs
}

// closeStarted 逆序关闭已启动组件并返回全部错误。ctx 已结束时仍会对剩余组件
// 调用 Close，由组件自行遵守取消；Instance 不创建额外协程强制执行。
func (i *Instance) closeStarted(ctx context.Context) []error {
	var errs []error
	for position := len(i.started) - 1; position >= 0; position-- {
		started := i.started[position]
		if err := started.component.Close(ctx); err != nil {
			errs = append(errs, fmt.Errorf("组件 %d（%T）关闭失败: %w",
				started.index, started.component, err))
		}
	}
	return errs
}
