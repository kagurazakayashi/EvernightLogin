// 本文件定义嵌入宿主时的公开装配契约（步骤 88）：注入依赖、挂载 HTTP 处理器、
// 就绪检查与生命周期通知。它把"宿主装配"需要的最小公开面固定下来，避免宿主为了
// 嵌入而导入 internal/ 包（Go 的 internal 规则不允许模块外导入）。
//
// 嵌入不变量（与 AGENTS.md 一致，测试与外部示例共同验证）：
//   - 没有隐式全局实例：所有状态在 *Instance 上，多个实例互不共享；本包没有
//     init() 启动协程、打开数据库、监听端口或读取运行环境。
//   - 导入包不启动任何后台任务：New 只校验配置并构造对象；Start 才启动扩展与
//     后台组件；不调用 Start 就永远不会运行后台逻辑。
//   - 宿主拥有的资源由宿主关闭：Database、Notifier、AccessController、日志器、
//     页面 FS、HTTP 服务器等都不会被实例关闭；实例只关闭自己管理的扩展与组件
//     所创建的资源（扩展/组件负责释放自己的资源）。
//   - fail-closed：授权判定、认证/MFA 扩展、数据库就绪检查失败时一律拒绝或报告
//     未就绪，不会因为依赖缺失而跳过安全校验；本包不提供伪造 root、关闭鉴权或
//     用请求参数提升身份的公开入口。
//   - 只承诺标准 net/http 契约（http.Handler / http.ServeMux）；未对所有第三方
//     HTTP 框架做实测，宿主可自行用 http.Handler 适配。
package login

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/transport"
)

// ErrNotRunning 表示实例尚未成功启动（StateNew 或已关闭）。Ready 与依赖运行
// 状态的操作会返回该错误。
var ErrNotRunning = errors.New("实例尚未运行")

// Database 是宿主注入的数据库连接契约。
//
// 资源所有权：连接由宿主打开与关闭，实例与扩展只使用、绝不关闭它；宿主可以在
// 多个实例之间共享同一个连接。当前公开面只使用 Ping 做就绪检查，业务查询仍由
// 宿主在模块内装配的真实服务完成（公开仓储包装尚未提供，不能把本契约当作业务
// 数据访问接口）。
type Database interface {
	// Ping 检查连接可用性；必须遵守 ctx 期限并在失败时返回错误。
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
	// LifecycleStartFailed 表示启动失败、取消或回滚；实例已进入 StateClosed。
	LifecycleStartFailed LifecycleEventKind = "start_failed"
	// LifecycleClosed 表示实例正常关闭完成。
	LifecycleClosed LifecycleEventKind = "closed"
	// LifecycleCloseFailed 表示关闭过程中出现错误；实例仍标记为已关闭。
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

// LifecycleEvent 是发送给宿主 Notifier 的生命周期事件。它只包含公开状态与稳定的
// 错误码/摘要，不包含配置秘密、凭证、请求体或内部堆栈。
type LifecycleEvent struct {
	Kind  LifecycleEventKind
	State State
	At    time.Time
	// RequestID 是本次生命周期操作的查询编号（用于关联日志），不是凭证。
	RequestID string
	// ErrorCode 是失败时的稳定错误码；成功事件为空。
	ErrorCode ErrorCode
	// ErrorSummary 是失败时的公开摘要；不包含内部细节。
	ErrorSummary string
}

// Notifier 是宿主注入的生命周期通知扩展（例如告警系统、启动审计）。
//
// 通知是尽力而为的旁路能力，不参与认证、授权或生命周期成败判定：通知失败或超时
// 只会记录运行日志告警，不会改变 Start/Close 的返回结果，也不会回滚已经完成的
// 操作。实现必须快速返回并遵守 ctx，不得在通知中记录秘密。
//
// 线程边界：通知在实例生命周期操作释放内部锁之后发送，并受
// LifecycleNotifyTimeout 有界超时约束；通知器可以读取 Instance.State/Extensions
// 等公开状态，但不得依赖生命周期操作的锁内时序，也不得在通知中同步调用同一实例
// 的 Start/Close 并期待其阻塞语义（生命周操作已在进行/完成）。通知器忽略 ctx 且
// 永不返回时，实例会在超时后放弃等待并继续返回（该通知器协程由宿主负责）。
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

// ReadyChecker 是扩展可选的健康检查能力：实现该接口的扩展会在 Ready 时被再次
// 检查。检查失败表示实例未就绪（fail-closed），不会降级为"跳过该扩展"。
type ReadyChecker interface {
	// CheckReady 检查扩展依赖是否可用；必须遵守 ctx 期限。
	CheckReady(ctx context.Context) error
}

// embeddedHost 汇总 New 时注入的宿主依赖与装配产物。零值表示"未注入/未配置"，
// 因此 Instance 零值语义仍然安全（虽然外部只能通过 New 构造）。
type embeddedHost struct {
	database      Database
	notifier      Notifier
	accessControl AccessController
	readyCheckers []ReadyChecker
	handler       http.Handler
	httpPrefix    string
}

// Extensions 返回实例注册的扩展元数据快照（注册顺序）。修改返回值不会影响实例。
// 元数据只用于诊断与展示，不代表扩展当前一定健康；健康状态用 Ready 检查。
func (i *Instance) Extensions() []ExtensionInfo {
	i.mu.Lock()
	defer i.mu.Unlock()
	infos := make([]ExtensionInfo, len(i.extensionInfos))
	copy(infos, i.extensionInfos)
	return infos
}

// Handler 返回 New 时按 Options.HTTP/Options.Pages 装配的 HTTP 处理器；未配置时
// 返回 nil。宿主负责把它挂到自己的 mux（可直接调用 Mount），实例不监听端口。
//
// Handler/Mount 与生命周期解耦：处理器在 Start 之前即可构造和挂载（页面与健康
// 端点本身不依赖后台组件），Close 之后返回的处理器仍可被宿主用于返回明确错误或
// 停机页；业务就绪判断必须使用 Ready，而不是靠 Handler 是否为 nil。
func (i *Instance) Handler() http.Handler {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.embedded.handler
}

// HandlerPrefix 返回装配处理器时使用的规范化固定路径前缀；根路径返回空字符串。
// 未配置 HTTP 处理器时同样返回空字符串。
func (i *Instance) HandlerPrefix() string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.embedded.httpPrefix
}

// Mount 把实例装配的 HTTP 处理器挂到宿主 *http.ServeMux 上。
//
// 挂载路径必须与处理器固定前缀一致（HandlerPrefix），否则请求会被处理器按前缀
// 拒绝而全部 404；因此本方法统一按前缀注册子树（根路径注册 "/"）。宿主也可以
// 不调用本方法而自行挂载，但同样必须使用该前缀。
//
// 与生命周期解耦：Start 之前或 Close 之后都可以挂载（见 Handler 文档）；重复
// 挂载不会绕过生命周期校验，宿主应自行保证每个 mux 只挂载一次。未配置处理器、
// mux 为 nil、或 mux 已有冲突 pattern（http.ServeMux 会 panic）时返回
// CONFIG_INVALID，并把底层冲突信息保留在原因链中；本方法不吞掉冲突，也不让宿主
// 因重复注册而 panic。
func (i *Instance) Mount(mux *http.ServeMux) (err error) {
	if mux == nil {
		return NewAppError(CodeConfigInvalid, "挂载 HTTP 处理器需要宿主 mux",
			WithCause(fmt.Errorf("mux 为 nil")), WithRequestID(NewRequestID()))
	}
	i.mu.Lock()
	handler := i.embedded.handler
	prefix := i.embedded.httpPrefix
	i.mu.Unlock()
	if handler == nil {
		return NewAppError(CodeConfigInvalid, "实例未配置 HTTP 处理器",
			WithCause(fmt.Errorf("Options.HTTP 与 Options.Pages 均为空")),
			WithRequestID(NewRequestID()))
	}
	pattern := "/"
	if prefix != "" {
		pattern = prefix + "/"
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			err = NewAppError(CodeConfigInvalid, "挂载 HTTP 处理器失败",
				WithCause(fmt.Errorf("宿主 mux 拒绝注册模式 %q: %v", pattern, recovered)),
				WithRequestID(NewRequestID()))
		}
	}()
	mux.Handle(pattern, handler)
	return nil
}

// Ready 检查实例是否可以对外服务：必须已成功启动；注入的 Database 必须 Ping
// 成功；实现了 ReadyChecker 的扩展必须检查通过。
//
// 失败返回错误（未启动为 ErrNotRunning，数据库失败为 DB_UNAVAILABLE，扩展检查
// 失败为 INTERNAL_ERROR），不会因为依赖缺失而报告就绪。通知器不参与就绪判定。
func (i *Instance) Ready(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	i.mu.Lock()
	state := i.state
	database := i.embedded.database
	checkers := make([]ReadyChecker, len(i.embedded.readyCheckers))
	copy(checkers, i.embedded.readyCheckers)
	i.mu.Unlock()

	if state != StateRunning {
		return ErrNotRunning
	}
	if err := ctx.Err(); err != nil {
		return NewAppError(CodeInternalError, "就绪检查已取消",
			WithCause(err), WithRequestID(NewRequestID()))
	}
	for _, checker := range checkers {
		if err := checker.CheckReady(ctx); err != nil {
			return NewAppError(CodeInternalError, "扩展未就绪",
				WithCause(err), WithRequestID(NewRequestID()))
		}
	}
	if database != nil {
		if err := database.Ping(ctx); err != nil {
			return NewAppError(CodeDBUnavailable, "数据库不可用",
				WithCause(err), WithRequestID(NewRequestID()))
		}
	}
	return nil
}

// assemble 按 Options.Pages/Options.HTTP 装配内置页面与 HTTP 处理器。它只在 New
// 中调用，不监听端口、不创建协程；任何配置错误都返回 CONFIG_INVALID 统一错误。
func (i *Instance) assemble(options Options) error {
	if options.Pages != nil && options.HTTP == nil {
		return NewAppError(CodeConfigInvalid, "内置页面需要 HTTP 处理器",
			WithCause(fmt.Errorf("Options.Pages 已配置但 Options.HTTP 为 nil 时页面无法对外提供")),
			WithRequestID(NewRequestID()))
	}

	var web *WebUI
	if options.Pages != nil {
		built, err := NewWebUI(*options.Pages)
		if err != nil {
			return NewAppError(CodeConfigInvalid, "内置页面配置无效",
				WithCause(err), WithRequestID(NewRequestID()))
		}
		web = built
	}
	if options.HTTP == nil {
		return nil
	}

	httpOptions := *options.HTTP
	if httpOptions.UI != nil {
		uiCopy := *httpOptions.UI
		httpOptions.UI = &uiCopy
	}
	if web != nil {
		if httpOptions.Prefix != options.Pages.Prefix {
			return NewAppError(CodeConfigInvalid, "页面与 HTTP 处理器路径前缀不一致",
				WithCause(fmt.Errorf("Options.Pages.Prefix=%q，Options.HTTP.Prefix=%q",
					options.Pages.Prefix, httpOptions.Prefix)),
				WithRequestID(NewRequestID()))
		}
		switch {
		case httpOptions.UI == nil:
			httpOptions.UI = &UIHTTPOptions{
				Handler:                   web,
				PageContentSecurityPolicy: DefaultUIPageContentSecurityPolicy,
			}
		case httpOptions.UI.Handler == nil:
			httpOptions.UI.Handler = web
			if httpOptions.UI.PageContentSecurityPolicy == "" {
				httpOptions.UI.PageContentSecurityPolicy = DefaultUIPageContentSecurityPolicy
			}
		default:
			return NewAppError(CodeConfigInvalid, "页面处理器重复配置",
				WithCause(fmt.Errorf("Options.HTTP.UI 与 Options.Pages 不能同时提供页面处理器")),
				WithRequestID(NewRequestID()))
		}
	}

	prefix, err := transport.NormalizePrefix(httpOptions.Prefix)
	if err != nil {
		return NewAppError(CodeConfigInvalid, "HTTP 处理器路径前缀无效",
			WithCause(err), WithRequestID(NewRequestID()))
	}
	handler, err := NewHTTPHandler(httpOptions)
	if err != nil {
		return err
	}
	i.embedded.handler = handler
	i.embedded.httpPrefix = prefix
	return nil
}

// LifecycleNotifyTimeout 是单次生命周期通知的墙钟上限。通知在实例锁外发送，
// 超时后实例放弃等待并继续返回，避免慢/挂起的通知器阻塞 Start/Close。
const LifecycleNotifyTimeout = 2 * time.Second

// lifecycleNotification 是一次挂起的生命周期通知。它由生命周期操作在锁内登记、
// 释放锁后由 finishLifecycleLocked 发送。
type lifecycleNotification struct {
	notifier Notifier
	event    LifecycleEvent
}

// pendingLifecycleLocked 在持有实例互斥锁时登记生命周期通知；实际发送延迟到
// finishLifecycleLocked（释放锁之后）。nil 通知器直接跳过。
func (i *Instance) pendingLifecycleLocked(kind LifecycleEventKind, cause *AppError) {
	notifier := i.embedded.notifier
	if notifier == nil {
		return
	}
	event := LifecycleEvent{
		Kind:  kind,
		State: i.state,
		At:    time.Now(),
	}
	if cause != nil {
		event.RequestID = cause.RequestID()
		event.ErrorCode = cause.Code()
		event.ErrorSummary = cause.Message()
	}
	i.pendingNotification = &lifecycleNotification{notifier: notifier, event: event}
}

// finishLifecycleLocked 释放实例互斥锁，并在锁外发送挂起的生命周期通知。它必须
// 且只能由 Start/Close 的 defer 调用（此时调用方仍持有锁）。
func (i *Instance) finishLifecycleLocked() {
	pending := i.pendingNotification
	i.pendingNotification = nil
	i.mu.Unlock()
	i.deliverLifecycleEvent(pending)
}

// deliverLifecycleEvent 在锁外发送一次通知，并受 LifecycleNotifyTimeout 约束：
// 通知器忽略 ctx 且不返回时，实例在超时后放弃等待并记录告警，不阻塞生命周期返回。
func (i *Instance) deliverLifecycleEvent(pending *lifecycleNotification) {
	if pending == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), LifecycleNotifyTimeout)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				done <- fmt.Errorf("生命周期通知发生 panic: %v", recovered)
			}
		}()
		done <- pending.notifier.Notify(ctx, pending.event)
	}()
	select {
	case err := <-done:
		if err != nil {
			i.logger.Warn("生命周期通知失败",
				"event", string(pending.event.Kind),
				"request_id", pending.event.RequestID, "error", slog.Any("error", err))
		}
	case <-ctx.Done():
		i.logger.Warn("生命周期通知超时，已放弃等待",
			"event", string(pending.event.Kind),
			"request_id", pending.event.RequestID,
			"timeout", LifecycleNotifyTimeout.String())
	}
}
