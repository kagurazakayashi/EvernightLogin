package login

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/logging"
)

// ErrAlreadyStarted 表示实例已经成功启动；Start 不会重复启动组件。
var ErrAlreadyStarted = errors.New("实例已经启动")

// ErrClosed 表示实例已经关闭或启动失败，不能再启动。
var ErrClosed = errors.New("实例已经关闭")

// Instance 是 login 的隔离实例。
//
// 同一进程可以创建多个 Instance；实例之间不共享状态、组件或全局单例。
// Instance 的方法并发安全：Start、Close 由内部互斥锁串行化，重复 Close 安全，
// 启动成功后再次 Start 返回 ErrAlreadyStarted。
//
// 组件与扩展回调执行期间 Instance 持有内部锁，因此组件/扩展不得在 Start/Close
// 中同步调用同一实例的 Start/Close/State/Config/Logger，否则会阻塞或死锁。
// 生命周期通知（Notifier）在锁外带着有界超时发送，宿主通知器可以查询实例状态，
// 但不得依赖锁内语义或反向驱动生命周期。
type Instance struct {
	mu                    sync.Mutex
	state                 State
	config                Config
	components            []BackgroundComponent
	extensions            []Extension
	extensionInfos        []ExtensionInfo
	started               []startedComponent
	startedExtensions     []startedExtension
	logger                *slog.Logger
	closeTimeout          time.Duration
	extensionStartTimeout time.Duration
	// pendingNotification 是本次生命周期操作在锁内挂起、释放锁后发送的通知。
	pendingNotification *lifecycleNotification
	// embedded 保存宿主注入的依赖与 HTTP 装配产物（见 embed.go）。
	embedded embeddedHost
}

// startedExtension 记录成功启动的扩展及其在 Options.Extensions 中的原始下标，
// 用于逆序关闭和诊断信息定位。
type startedExtension struct {
	index     int
	extension Extension
}

// startedComponent 记录成功启动的组件及其在 Options 中的原始下标，用于逆序
// 关闭和错误信息定位。
type startedComponent struct {
	index     int
	component BackgroundComponent
}

// New 构造一个 Instance，但不启动任何组件、不监听端口、不打开数据库、不创建
// 协程。Options.Config 为 nil 时使用 Default()；传入非法配置时返回
// CONFIG_INVALID 的统一错误并保留配置校验原因链；nil 组件、非法扩展注册与
// typed-nil 注入依赖会被拒绝。
//
// 宿主可以只构造实例并使用核心能力；只有需要后台组件或扩展时才调用 Start。
// 多个 Instance 可以在同一进程内并存且互不影响。设置 Options.HTTP/Options.Pages
// 时 New 只构造处理器与页面（不监听端口），宿主随后用 Instance.Mount 挂载。
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
		if component == nil || isNilInterface(component) {
			return nil, fmt.Errorf("Options.Components[%d] 为 nil", index)
		}
		components[index] = component
	}

	extensionStartTimeout := opts.ExtensionStartTimeout
	if extensionStartTimeout == 0 {
		extensionStartTimeout = DefaultExtensionStartTimeout
	}
	if extensionStartTimeout < MinExtensionStartTimeout ||
		extensionStartTimeout > MaxExtensionStartTimeout {
		return nil, NewAppError(CodeConfigInvalid, "扩展启动超时配置无效",
			WithCause(fmt.Errorf("Options.ExtensionStartTimeout=%s 超出允许范围 [%s, %s]",
				extensionStartTimeout, MinExtensionStartTimeout, MaxExtensionStartTimeout)),
			WithRequestID(NewRequestID()))
	}

	extensions, extensionInfos, readyCheckers, err := normalizeExtensions(opts.Extensions)
	if err != nil {
		return nil, NewAppError(CodeConfigInvalid, "扩展注册信息无效",
			WithCause(err), WithRequestID(NewRequestID()))
	}
	for name, injected := range map[string]any{
		"Options.Database":      opts.Database,
		"Options.Notifications": opts.Notifications,
		"Options.AccessControl": opts.AccessControl,
	} {
		if injected != nil && isNilInterface(injected) {
			return nil, NewAppError(CodeConfigInvalid, "宿主注入的依赖无效",
				WithCause(fmt.Errorf("%s 是 typed-nil", name)),
				WithRequestID(NewRequestID()))
		}
	}

	instance := &Instance{
		state:                 StateNew,
		config:                config,
		components:            components,
		extensions:            extensions,
		extensionInfos:        extensionInfos,
		logger:                logger,
		closeTimeout:          time.Duration(config.Server.ShutdownTimeoutSeconds) * time.Second,
		extensionStartTimeout: extensionStartTimeout,
	}
	instance.embedded = embeddedHost{
		database:      opts.Database,
		notifier:      opts.Notifications,
		accessControl: opts.AccessControl,
		readyCheckers: readyCheckers,
	}
	if err := instance.assemble(opts); err != nil {
		return nil, err
	}
	return instance, nil
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

// Start 按声明顺序启动所有扩展与后台组件。
//
// Start 只能成功调用一次：成功后再次调用返回 ErrAlreadyStarted；实例关闭后
// 调用返回 ErrClosed；启动失败或启动前 ctx 已结束时实例进入 StateClosed，
// 之后不能再启动。任一扩展或组件启动失败时，已成功启动的对象按逆序关闭，失败
// 对象由它自己清理；回滚关闭错误会与启动错误一起返回。
//
// 扩展启动带 panic 恢复与单扩展墙钟上限（Options.ExtensionStartTimeout，默认
// 30s）：扩展 panic 或超时按启动失败处理（fail-closed）。父 ctx 取消或扩展启动
// 超时后，Instance 会额外等待扩展在 min(ExtensionStartTimeout,
// ExtensionStartCancelWait)（最多 2s）内自行返回并完成资源清理，才返回失败；
// 扩展忽略 ctx 且超过该窗口仍未返回时，错误明确标记「可能遗留资源」，Instance
// 不永久阻塞、不强制终止宿主协程（扩展契约要求遵守 ctx）。
//
// 返回的生命周期错误是统一 AppError（未分类扩展/组件错误回退为 INTERNAL_ERROR），
// 带 request_id 并写入结构化运行日志；扩展/组件返回的具体 AppError 会保留错误码。
// 生命周期通知在释放实例锁后发送且带超时，不会阻塞 Start 返回。
func (i *Instance) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	i.mu.Lock()
	defer i.finishLifecycleLocked()

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
		i.pendingLifecycleLocked(LifecycleStartFailed, appError)
		return appError
	}

	i.logger.Debug("实例开始启动",
		"extension_count", len(i.extensions), "component_count", len(i.components))
	i.started = make([]startedComponent, 0, len(i.components))
	i.startedExtensions = make([]startedExtension, 0, len(i.extensions))

	for index, extension := range i.extensions {
		if err := ctx.Err(); err != nil {
			return i.failStartLocked(NewAppError(CodeInternalError, "实例启动已取消",
				WithCause(err), WithRequestID(NewRequestID())))
		}
		info := i.extensionInfos[index]
		i.logger.Debug("启动扩展",
			"extension_index", index, "extension_kind", string(info.Kind),
			"extension_name", info.Name)
		if err := i.startExtensionSafely(ctx, extension, info); err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				// 保留 err 原因链：取消后扩展未及时自清理时其中带有“可能遗留资源”说明。
				return i.failStartLocked(NewAppError(CodeInternalError, "实例启动已取消",
					WithCause(err), WithRequestID(NewRequestID())),
					"extension_index", index, "extension_kind", string(info.Kind),
					"extension_name", info.Name)
			}
			message := "后台扩展启动失败"
			if errors.Is(err, errExtensionStartTimeout) {
				message = "后台扩展启动超时"
			}
			return i.failStartLocked(classifyLifecycleError(message, err, NewRequestID()),
				"extension_index", index, "extension_kind", string(info.Kind),
				"extension_name", info.Name)
		}
		i.startedExtensions = append(i.startedExtensions,
			startedExtension{index: index, extension: extension})
	}

	for index, component := range i.components {
		if err := ctx.Err(); err != nil {
			return i.failStartLocked(NewAppError(CodeInternalError, "实例启动已取消",
				WithCause(err), WithRequestID(NewRequestID())),
				"component_index", index, "component_type", fmt.Sprintf("%T", component))
		}
		i.logger.Debug("启动后台组件",
			"component_index", index, "component_type", fmt.Sprintf("%T", component))
		if err := component.Start(ctx); err != nil {
			return i.failStartLocked(classifyLifecycleError("后台组件启动失败", err, NewRequestID()),
				"component_index", index, "component_type", fmt.Sprintf("%T", component))
		}
		i.started = append(i.started, startedComponent{index: index, component: component})
	}

	i.state = StateRunning
	i.logger.Info("实例启动完成",
		"component_count", len(i.started), "extension_count", len(i.startedExtensions))
	i.pendingLifecycleLocked(LifecycleStarted, nil)
	return nil
}

// errExtensionStartTimeout 标记单扩展启动超时，用于区分扩展自身返回的
// context.DeadlineExceeded 与 Instance 施加的墙钟上限。
var errExtensionStartTimeout = errors.New("扩展启动超时")

// startExtensionSafely 带 panic 恢复与单扩展墙钟上限地启动扩展（调用方必须持有
// 实例锁）。
//
// 取消/超时语义：父 ctx 取消或扩展启动超时后，Instance 会再等待扩展协程在
// min(ExtensionStartTimeout, ExtensionStartCancelWait) 内返回，确保扩展有机会
// 自行清理已创建资源后才返回错误；若扩展忽略 ctx 且在该窗口内仍不返回，错误会
// 明确标记「可能遗留资源」，Instance 不永久阻塞、也不强制终止宿主协程。扩展
// panic 转为可诊断错误。
func (i *Instance) startExtensionSafely(ctx context.Context, extension Extension,
	info ExtensionInfo) error {
	startCtx, cancel := context.WithTimeout(ctx, i.extensionStartTimeout)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				result <- fmt.Errorf("扩展 %s（%s）Start 发生 panic: %v",
					extensionKey(info), info.Name, recovered)
			}
		}()
		result <- extension.Start(startCtx)
	}()
	select {
	case err := <-result:
		return err
	case <-startCtx.Done():
	}

	parentErr := ctx.Err()
	grace := i.extensionStartTimeout
	if grace > ExtensionStartCancelWait {
		grace = ExtensionStartCancelWait
	}
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case extensionErr := <-result:
		// 扩展已在取消/超时后返回，自行清理完成；仍按失败处理。
		if parentErr != nil {
			return parentErr
		}
		if extensionErr != nil {
			return fmt.Errorf("%w: 扩展 %s（%s）超过 %s 后返回: %w",
				errExtensionStartTimeout, extensionKey(info), info.Name, i.extensionStartTimeout, extensionErr)
		}
		return fmt.Errorf("%w: 扩展 %s（%s）超过 %s（返回时未报告错误）",
			errExtensionStartTimeout, extensionKey(info), info.Name, i.extensionStartTimeout)
	case <-timer.C:
		if parentErr != nil {
			return fmt.Errorf("%w：实例启动已取消，但扩展 %s（%s）未在 %s 内返回，可能遗留资源",
				parentErr, extensionKey(info), info.Name, grace)
		}
		return fmt.Errorf("%w: 扩展 %s（%s）超过 %s 且未在 %s 内返回，可能遗留资源",
			errExtensionStartTimeout, extensionKey(info), info.Name, i.extensionStartTimeout, grace)
	}
}

// failStartLocked 统一处理启动失败：回滚关闭已成功启动的扩展与组件，把实例置为
// StateClosed，写运行日志并挂起生命周期通知（释放锁后发送），最后聚合返回启动
// 错误与回滚错误。调用方必须已持有实例互斥锁。
func (i *Instance) failStartLocked(primary *AppError, attrs ...any) error {
	errs := []error{primary}
	for _, rollbackErr := range i.rollbackAllLocked() {
		errs = append(errs, classifyLifecycleError("启动失败后回滚关闭已启动对象失败",
			rollbackErr, primary.RequestID()))
	}
	i.state = StateClosed
	logArgs := append([]any{}, attrs...)
	logArgs = append(logArgs, "request_id", primary.RequestID(), "error", primary)
	i.logger.Error(primary.Message(), logArgs...)
	i.pendingLifecycleLocked(LifecycleStartFailed, primary)
	return errors.Join(errs...)
}

// Close 按启动顺序的逆序关闭已启动组件与扩展，并释放 Instance 自己创建的内部
// 资源。
//
// 关闭受两重期限约束：调用方 ctx 的期限，以及构造时配置的
// Server.ShutdownTimeoutSeconds。Close 可以安全重复调用；第一次关闭后后续
// 调用直接返回 nil。从未启动直接 Close 也会使实例进入 StateClosed，并在配置了
// 通知器时发送一次 LifecycleClosed 通知（State 为 closed）。
//
// 关闭错误会聚合返回（未分类错误回退为 INTERNAL_ERROR，带 request_id 并写入
// 结构化运行日志），但实例仍标记为已关闭；后续 Close 不重复返回旧错误，也不重复
// 发送通知。关闭期间 Instance 持有内部锁，因此并发 Close 会串行化；生命周期通知
// 在释放锁后发送且带超时，不会阻塞 Close 返回。
func (i *Instance) Close(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	i.mu.Lock()
	defer i.finishLifecycleLocked()

	switch i.state {
	case StateNew:
		i.state = StateClosed
		i.logger.Debug("实例在启动前关闭")
		i.pendingLifecycleLocked(LifecycleClosed, nil)
		return nil
	case StateClosed:
		return nil
	}

	closeCtx, cancel := context.WithTimeout(ctx, i.closeTimeout)
	defer cancel()
	requestID := NewRequestID()
	closeErrors := i.closeStarted(closeCtx)
	closeErrors = append(closeErrors, i.closeExtensions(closeCtx)...)
	i.started = nil
	i.startedExtensions = nil
	i.state = StateClosed

	if len(closeErrors) == 0 {
		i.logger.Info("实例已关闭", "request_id", requestID,
			"extension_count", len(i.extensions))
		i.pendingLifecycleLocked(LifecycleClosed, nil)
		return nil
	}
	wrapped := make([]error, 0, len(closeErrors))
	var primary *AppError
	detail := summarizeLifecycleFailures(closeErrors)
	message := "关闭已启动对象失败"
	if detail != "" {
		message += ": " + detail
	}
	for _, closeErr := range closeErrors {
		appError := classifyLifecycleError(message, closeErr, requestID)
		wrapped = append(wrapped, appError)
		if primary == nil {
			primary = appError
		}
		i.logger.Error("关闭已启动对象失败", "request_id", requestID, "error", appError)
	}
	i.pendingLifecycleLocked(LifecycleCloseFailed, primary)
	return errors.Join(wrapped...)
}

// componentCloseFailure 是组件关闭失败的安全错误视图：Error()/公开日志只包含
// 组件序号与类型（不含底层原因/路径/秘密），完整原因通过 Unwrap 保留给调用方
// 用 errors.Is/errors.As 做程序化诊断，不进入公开错误消息或结构化日志。
type componentCloseFailure struct {
	index         int
	componentType string
	cause         error
}

// Error 返回可公开的关闭失败摘要（不含底层原因）。
func (e *componentCloseFailure) Error() string {
	if e == nil {
		return "组件关闭失败"
	}
	return fmt.Sprintf("组件 %d（%s）关闭失败", e.index, e.componentType)
}

// Unwrap 保留底层原因链，供调用方程序化判断；不用于渲染公开消息/日志。
func (e *componentCloseFailure) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// summarizeLifecycleFailures 汇总关闭失败的安全标签（组件序号/类型），不拼接
// 底层错误文本，避免文件路径/秘密进入公开错误与日志。非组件类型统一给固定摘要。
func summarizeLifecycleFailures(errs []error) string {
	if len(errs) == 0 {
		return ""
	}
	parts := make([]string, 0, len(errs))
	for _, err := range errs {
		if err == nil {
			continue
		}
		var failure *componentCloseFailure
		if errors.As(err, &failure) {
			parts = append(parts, failure.Error())
			continue
		}
		parts = append(parts, "组件/扩展关闭失败")
	}
	return strings.Join(parts, "; ")
}

// classifyLifecycleError 把生命周期错误转为统一 AppError。已经是 AppError 的
// 组件错误保留错误码；如果没有请求编号则补上本次生命周期操作编号。未分类错误
// 回退为 INTERNAL_ERROR，并保留原因链供受限诊断。
func classifyLifecycleError(message string, err error, requestID string) *AppError {
	if appError, ok := AsAppError(err); ok {
		if appError.RequestID() != "" {
			return appError
		}
		return appError.CloneWithRequestID(requestID)
	}
	return NewAppError(CodeInternalError, message,
		WithCause(err), WithRequestID(requestID))
}

// rollbackAllLocked 在启动失败时逆序关闭已启动的后台组件，再逆序关闭已启动的
// 扩展。它使用独立于启动 ctx 的有期限上下文，确保启动被取消时仍尝试释放已创建
// 资源。调用方必须已持有实例互斥锁。
func (i *Instance) rollbackAllLocked() []error {
	if len(i.started) == 0 && len(i.startedExtensions) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), i.closeTimeout)
	defer cancel()
	errs := i.closeStarted(ctx)
	errs = append(errs, i.closeExtensions(ctx)...)
	i.started = nil
	i.startedExtensions = nil
	return errs
}

// closeExtensions 逆序关闭已启动扩展并返回全部错误。ctx 已结束时仍会对剩余扩展
// 调用 Close，由扩展自行遵守取消；Instance 不创建额外协程强制执行。扩展 Close
// 的 panic 会被恢复为错误并继续关闭剩余扩展。调用方必须已持有实例互斥锁。
func (i *Instance) closeExtensions(ctx context.Context) []error {
	var errs []error
	for position := len(i.startedExtensions) - 1; position >= 0; position-- {
		started := i.startedExtensions[position]
		info := i.extensionInfos[started.index]
		if err := i.closeExtensionSafely(ctx, started.extension, info); err != nil {
			errs = append(errs, fmt.Errorf("扩展 %s（%s）关闭失败: %w",
				extensionKey(info), info.Name, err))
		}
	}
	return errs
}

// closeExtensionSafely 调用扩展 Close 并把 panic 恢复为错误，避免宿主扩展的编程
// 错误使宿主进程崩溃；调用方必须已持有实例锁。
func (i *Instance) closeExtensionSafely(ctx context.Context, extension Extension,
	info ExtensionInfo) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("扩展 %s（%s）Close 发生 panic: %v",
				extensionKey(info), info.Name, recovered)
		}
	}()
	return extension.Close(ctx)
}

// closeStarted 逆序关闭已启动组件并返回全部错误。ctx 已结束时仍会对剩余组件
// 调用 Close，由组件自行遵守取消；Instance 不创建额外协程强制执行。组件 Close
// 的 panic 会被恢复为错误并继续关闭剩余组件，避免宿主组件编程错误破坏关闭循环。
func (i *Instance) closeStarted(ctx context.Context) []error {
	var errs []error
	for position := len(i.started) - 1; position >= 0; position-- {
		started := i.started[position]
		if err := i.closeComponentSafely(ctx, started); err != nil {
			errs = append(errs, &componentCloseFailure{
				index:         started.index,
				componentType: fmt.Sprintf("%T", started.component),
				cause:         err,
			})
		}
	}
	return errs
}

// closeComponentSafely 调用组件 Close 并把 panic 恢复为错误。
func (i *Instance) closeComponentSafely(ctx context.Context, started startedComponent) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("组件 %d（%T）Close 发生 panic: %v",
				started.index, started.component, recovered)
		}
	}()
	return started.component.Close(ctx)
}
