package serverapp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/auditops"
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	authzsqlite "github.com/kagurazakayashi/EvernightLogin/internal/authz/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/backupadmin"
	bootstrapsqlite "github.com/kagurazakayashi/EvernightLogin/internal/bootstrap/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
	mailersqlite "github.com/kagurazakayashi/EvernightLogin/internal/mailer/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
	tasksqlite "github.com/kagurazakayashi/EvernightLogin/internal/task/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/webhook"
	webhooksqlite "github.com/kagurazakayashi/EvernightLogin/internal/webhook/sqlite"
)

// 后台任务运行时边界。
const (
	// taskExecutorID/taskSchedulerID 是本进程稳定身份，写入任务/计划审计，不含秘密。
	taskExecutorID  = "login-server"
	taskSchedulerID = "login-server"
	// taskMaxConcurrent 是独立服务允许同时执行的任务数上限（有界，避免占满 SQLite）。
	taskMaxConcurrent = 2
	// taskPollInterval 是队列轮询间隔。
	taskPollInterval = 200 * time.Millisecond
	// taskTickInterval 是定时计划检查间隔。
	taskTickInterval = 30 * time.Second
	// taskShutdownTimeout 是执行器停止等待窗口上限。
	taskShutdownTimeout = 10 * time.Second
	// TaskRuntimeShutdownTimeout 是优雅关闭时整个任务运行时（调度器+执行器）的
	// 墙钟上限；调用方期限更短时以调用方为准。
	TaskRuntimeShutdownTimeout = 15 * time.Second
	// notificationFromAddress 是本地禁用发送器的占位发件人；不会真实外发。
	notificationFromAddress = "no-reply@evernight-login.invalid"
)

// TaskRuntime 是独立服务的后台任务运行时：任务执行器 + 定时计划调度器，并在其中
// 注册本阶段真实存在的任务处理器（邮件投递、Webhook 投递）。
//
// 安全边界：
//   - 不在装配阶段启动协程/访问数据库；只有 Instance.Start/显式 Start 才启动；
//   - 邮件发送器是“未配置真实发送器”的显式失败实现：任何投递尝试都会以永久失败
//     记录，不访问网络、不真实外发；本地测试捕获器由测试注入，生产不使用；
//   - Webhook 投递处理器使用真实出站网络策略（默认 https/443/默认不重定向）与
//     受控签名密钥加解密，但端点登记/轮换入口由管理页/管理 API 装配后再开放；
//   - 关闭时先停调度器再停执行器，遗留 queued 任务保留给下次启动。
type TaskRuntime struct {
	store        *tasksqlite.Store
	executor     *task.Executor
	scheduler    *task.Scheduler
	mailer       *mailer.DeliveryService
	webhook      *webhook.Service
	enqueuer     *taskEnqueuerRelay
	logger       *slog.Logger
	now          func() time.Time
	handlerKinds []string
	// deps 保留装配依赖，供运行前权限复验惰性构造真实权限判定器（不改变构造顺序）。
	deps Deps
	// permissionOnce 保证权限判定器只构造一次；失败后保持 fail-closed。
	permissionOnce    sync.Once
	permissionChecker *permissionChecker
	permissionErr     error

	hookMu      sync.Mutex
	enqueueHook func(ctx context.Context, schedule task.Schedule, jobID string)
}

// Mail 返回邮件投递服务（供后续页面/通知域装配使用；本阶段不真实外发）。
func (r *TaskRuntime) Mail() *mailer.DeliveryService {
	if r == nil {
		return nil
	}
	return r.mailer
}

// Webhook 返回 Webhook 服务（供后续页面/管理 API 装配使用）。
func (r *TaskRuntime) Webhook() *webhook.Service {
	if r == nil {
		return nil
	}
	return r.webhook
}

// Executor 返回任务执行器（供管理域入队/取消任务）。
func (r *TaskRuntime) Executor() *task.Executor {
	if r == nil {
		return nil
	}
	return r.executor
}

// Scheduler 返回定时计划调度器（供报告/备份计划管理使用）。
func (r *TaskRuntime) Scheduler() *task.Scheduler {
	if r == nil {
		return nil
	}
	return r.scheduler
}

// taskEnqueuerRelay 把构造顺序解耦：邮件/Webhook 服务先于执行器构造，而真正的
// 入队器是执行器本身。未 Set 前 Enqueue fail-closed，不会静默丢任务。
type taskEnqueuerRelay struct {
	mu       sync.RWMutex
	executor *task.Executor
}

// Set 绑定真实执行器。
func (r *taskEnqueuerRelay) Set(executor *task.Executor) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.executor = executor
}

// Enqueue 实现 mailer.Enqueuer / webhook.Enqueuer。
func (r *taskEnqueuerRelay) Enqueue(ctx context.Context,
	request task.EnqueueRequest) (task.Job, error) {
	r.mu.RLock()
	executor := r.executor
	r.mu.RUnlock()
	if executor == nil {
		return task.Job{}, fmt.Errorf("任务执行器尚未启动，拒绝入队")
	}
	return executor.Enqueue(ctx, request)
}

// RequestCancel 让同一个 relay 同时满足 webhook.Canceller 与 userbatch.Canceller；
// 未绑定执行器时明确拒绝。
func (r *taskEnqueuerRelay) RequestCancel(ctx context.Context,
	request task.CancelRequest) (task.CancelResult, error) {
	r.mu.RLock()
	executor := r.executor
	r.mu.RUnlock()
	if executor == nil {
		return task.CancelResult{}, fmt.Errorf("任务执行器尚未启动，拒绝取消请求")
	}
	return executor.RequestCancel(ctx, request)
}

// hostMailAuthorizer 是独立服务的邮件投递授权实现：只允许受信系统/本地管理员
// 主体入队与查询投递（例如将来的邮箱验证、找回、安全通知系统流程）；普通用户与
// 匿名主体一律拒绝。本阶段没有页面/API 暴露投递管理入口，该授权器只为后续装配
// 提供安全的默认边界，不放宽任何用户权限。
type hostMailAuthorizer struct{}

// Authorize 实现 mailer.Authorizer。
func (hostMailAuthorizer) Authorize(_ context.Context, caller mailer.Caller,
	_ mailer.Action, _ *mailer.Record) error {
	actor := caller.Actor()
	if actor.Type == audit.ActorSystem || actor.Type == audit.ActorLocalAdmin {
		return nil
	}
	return fmt.Errorf("邮件投递仅允许系统或本地管理员主体：拒绝访问")
}

// failClosedWebhookAuthorizer 是 Webhook 管理面未装配时的授权实现：一律拒绝。
type failClosedWebhookAuthorizer struct{}

// Authorize 实现 webhook.Authorizer。
func (failClosedWebhookAuthorizer) Authorize(context.Context, webhook.Caller,
	webhook.Action, string) error {
	return fmt.Errorf("Webhook 管理授权未装配：拒绝访问")
}

// failClosedSensitiveRunner 是敏感操作执行器的 fail-closed 实现：Webhook 的安全
// 设置与签名密钥变更必须经近期认证，本阶段未装配 reauth 服务，因此一律拒绝。
type failClosedSensitiveRunner struct{}

// Authorize 实现 reauth.OperationRunner。
func (failClosedSensitiveRunner) Authorize(context.Context, reauth.Caller,
	reauth.Request) (reauth.Result, error) {
	return reauth.Result{}, fmt.Errorf("敏感操作再次认证未装配：拒绝执行")
}

// NotifyOutcome 实现 reauth.OperationRunner；拒绝路径没有已批准结果可通知。
func (failClosedSensitiveRunner) NotifyOutcome(context.Context, reauth.Result,
	reauth.Outcome) error {
	return nil
}

// NewTaskRuntime 构造后台任务运行时的第一阶段：任务存储、加密器、邮件/Webhook
// 投递服务、入队 relay 与定时计划调度器。此阶段不创建任务执行器、不启动任何
// 协程、不访问网络；唯一的数据访问是对本地 SQLite 的残留投递修复（Reconcile，
// 只读写本机数据库）。两阶段构造用于解开“域服务需要任务入队器、执行器又需要
// 域服务处理器”的循环：域服务（如 userbatch）用 Enqueuer/Canceller 构造完成后，
// 调用 Complete 注册全部处理器并创建执行器。
func NewTaskRuntime(deps Deps, gate *SecurityGate) (*TaskRuntime, error) {
	if deps.Store == nil || deps.Audit == nil || deps.Keyring == nil {
		return nil, fmt.Errorf("后台任务运行时缺少存储、审计或主密钥环依赖")
	}
	logger := deps.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	now := deps.Now
	if now == nil {
		now = time.Now
	}
	taskStore, err := tasksqlite.New(deps.Store, tasksqlite.Options{Now: now, Logger: logger})
	if err != nil {
		return nil, fmt.Errorf("构造任务存储失败: %w", err)
	}
	sealer, err := secrets.NewSealer(deps.Keyring, logger)
	if err != nil {
		return nil, fmt.Errorf("构造通知投递加密器失败: %w", err)
	}
	relay := &taskEnqueuerRelay{}

	// 邮件投递服务：Sender 使用 mailer.SenderFunc(nil) 的显式“未配置发送器”语义，
	// 每次发送以永久失败返回，不产生网络连接。
	mailerStore, err := mailersqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造邮件投递存储失败: %w", err)
	}
	templates, err := mailer.DefaultTemplateSet()
	if err != nil {
		return nil, fmt.Errorf("构造邮件模板失败: %w", err)
	}
	mailDelivery, err := mailer.NewDeliveryService(mailer.DeliveryOptions{
		Store: mailerStore, Sender: deps.Mail.SenderOrDisabled(), Templates: templates,
		Sealer: sealer, Recorder: deps.Audit, Enqueuer: relay,
		Authorizer:     hostMailAuthorizer{},
		From:           deps.Mail.FromAddress(),
		MaxAttempts:    deps.Config.Mail.Delivery.MaxAttempts,
		TimeoutSeconds: deps.Config.Mail.Delivery.TimeoutSeconds,
		Now:            now,
	})
	if err != nil {
		return nil, fmt.Errorf("构造邮件投递服务失败: %w", err)
	}

	webhookStore, err := webhooksqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造 Webhook 存储失败: %w", err)
	}
	webhookSensitive := reauth.OperationRunner(failClosedSensitiveRunner{})
	if gate != nil && gate.Reauth != nil {
		webhookSensitive = gate.Reauth
	}
	webhookService, err := webhook.New(webhook.Options{
		Store: webhookStore, Audit: deps.Audit,
		Authorizer: failClosedWebhookAuthorizer{},
		Sensitive:  webhookSensitive,
		Sealer:     sealer, Enqueuer: relay, Canceller: relay,
		Now: now, Logger: logger,
	})
	if err != nil {
		return nil, fmt.Errorf("构造 Webhook 服务失败: %w", err)
	}
	runtime := &TaskRuntime{
		store: taskStore, mailer: mailDelivery, webhook: webhookService,
		enqueuer: relay, logger: logger, now: now, deps: deps,
	}
	// 调度器不依赖执行器/处理器，先创建以便备份管理等域服务在处理器注册前就能
	// 持有真实调度器；成功入队回调通过动态 hook 转发（Start 前由宿主设置）。
	if repaired, reconcileErr := mailDelivery.Reconcile(context.Background(), 200); reconcileErr != nil {
		return nil, fmt.Errorf("修复中断投递记录失败: %w", reconcileErr)
	} else if repaired > 0 {
		logger.Warn("检测到进程重启前的残留 sending 投递，已标记永久失败（不自动重发）",
			"repaired_count", repaired)
	}
	scheduler, err := task.NewScheduler(task.SchedulerOptions{
		Store: taskStore, SchedulerID: taskSchedulerID,
		PermissionCheck: runtime.checkTaskPermission,
		OnJobEnqueued:   runtime.dispatchEnqueueHook,
		TickInterval:    taskTickInterval, Now: now, Logger: logger,
	})
	if err != nil {
		return nil, fmt.Errorf("构造任务调度器失败: %w", err)
	}
	runtime.scheduler = scheduler
	return runtime, nil
}

// dispatchEnqueueHook 把调度器成功入队回调转发给宿主注册的 hook（如备份管理索引）。
func (r *TaskRuntime) dispatchEnqueueHook(ctx context.Context,
	schedule task.Schedule, jobID string) {
	r.hookMu.Lock()
	hook := r.enqueueHook
	r.hookMu.Unlock()
	if hook != nil {
		hook(ctx, schedule, jobID)
	}
}

// SetSchedulerEnqueueHook 注册调度器成功入队回调（必须在 Start 前调用；只保留一个）。
func (r *TaskRuntime) SetSchedulerEnqueueHook(
	hook func(ctx context.Context, schedule task.Schedule, jobID string)) {
	if r == nil {
		return
	}
	r.hookMu.Lock()
	defer r.hookMu.Unlock()
	r.enqueueHook = hook
}

// taskStore 返回任务只读存储（满足 auditops.TaskReader 的 Get 契约）。
func (r *TaskRuntime) taskStore() *tasksqlite.Store {
	if r == nil {
		return nil
	}
	return r.store
}

// Enqueuer 返回任务入队 relay，供域服务（userbatch/通知等）构造使用。执行器未
// Complete 前调用 Enqueue 会 fail-closed 返回明确错误，不会静默丢任务。
func (r *TaskRuntime) Enqueuer() *taskEnqueuerRelay {
	if r == nil {
		return nil
	}
	return r.enqueuer
}

// checkTaskPermission 是任务运行前的可信权限复验回调，注入 task.Options。
//
// 语义：
//   - 系统/local_admin 是宿主受信主体，允许执行（与既有 host authorizer 的受信
//     主体边界一致）；
//   - 普通用户必须按任务类型映射到真实权限键，并在系统范围经真实权限引擎判定；
//   - 未映射的任务类型、非法/非用户主体或权限引擎不可用一律拒绝（fail-closed），
//     不默认放行。
//
// 该回调只做运行前复验；处理器自身仍会重新授权/复核数据范围，二者不互相替代。
func (r *TaskRuntime) checkTaskPermission(ctx context.Context,
	request task.PermissionRequest) error {
	if r == nil {
		return fmt.Errorf("任务运行时未构造：拒绝运行前权限复验")
	}
	if err := request.Actor.Validate(); err != nil {
		return fmt.Errorf("任务发起者无效：拒绝运行前权限复验")
	}
	switch request.Actor.Type {
	case audit.ActorSystem, audit.ActorLocalAdmin:
		return nil
	case audit.ActorUser:
		key, ok := taskRunPermissionKey(request.Kind)
		if !ok {
			return fmt.Errorf("任务类型 %q 未登记运行权限：拒绝执行", request.Kind)
		}
		checker, err := r.taskPermissionChecker()
		if err != nil {
			return err
		}
		return checker.check(ctx, request.Actor.ID, key, "system")
	default:
		return fmt.Errorf("任务发起者类型 %q 不允许运行权限复验：拒绝执行",
			request.Actor.Type)
	}
}

// taskRunPermissionKey 把需要运行前复验的任务类型映射到真实权限键。
// 未登记类型返回 ok=false，由调用方按 fail-closed 拒绝。
func taskRunPermissionKey(kind string) (string, bool) {
	switch strings.TrimSpace(kind) {
	case auditops.TaskKindAuditExport:
		return auditops.PermissionExport, true
	case auditops.TaskKindAuditPurge:
		return auditops.PermissionPurge, true
	case backupadmin.KindBackupCreate:
		return backupadmin.PermissionCreate, true
	case backupadmin.KindBackupCleanup:
		return backupadmin.PermissionCleanup, true
	default:
		return "", false
	}
}

// taskPermissionChecker 惰性构造真实权限判定器：复用 bootstrap root 检查与真实
// authz 存储/引擎；构造失败保持 fail-closed，不降级为放行。
func (r *TaskRuntime) taskPermissionChecker() (*permissionChecker, error) {
	r.permissionOnce.Do(func() {
		if r.deps.Store == nil {
			r.permissionErr = fmt.Errorf("任务权限复验缺少存储依赖")
			return
		}
		bootstrapStore, err := bootstrapsqlite.New(r.deps.Store)
		if err != nil {
			r.permissionErr = fmt.Errorf("构造任务权限复验 root 存储失败: %w", err)
			return
		}
		roots, err := newHostRootChecker(bootstrapStore)
		if err != nil {
			r.permissionErr = fmt.Errorf("构造任务权限复验 root 检查失败: %w", err)
			return
		}
		authzStore, err := authzsqlite.New(r.deps.Store)
		if err != nil {
			r.permissionErr = fmt.Errorf("构造任务权限复验存储失败: %w", err)
			return
		}
		access, err := authz.New(authz.Options{Store: authzStore,
			Authorizer: selfQueryAuthorizer{}, Logger: r.logger})
		if err != nil {
			r.permissionErr = fmt.Errorf("构造任务权限复验引擎失败: %w", err)
			return
		}
		r.permissionChecker = newPermissionChecker(access, roots)
	})
	return r.permissionChecker, r.permissionErr
}

// Complete 注册本阶段真实存在的任务处理器并创建执行器与定时调度器。
//
// 必须的处理器：
//   - mailer.TaskKindMailDelivery：邮件投递；发送器显式为“未配置”实现，任何投递
//     以永久失败结束，不真实外发（本地捕获发送器只能由测试注入）；
//   - webhook.TaskKindWebhookDelivery：Webhook 投递；真实出站策略与签名密钥加密。
//
// extra 是已装配域服务提供的真实处理器（如 userbatch 导入/导出、报告计划生成、
// 备份计划/清理、审计保留清理）；未知/空类型直接拒绝构造，不伪造处理器。
func (r *TaskRuntime) Complete(extra map[string]task.Handler) error {
	if r == nil || r.store == nil || r.enqueuer == nil {
		return fmt.Errorf("任务运行时未完成第一阶段构造")
	}
	if r.executor != nil {
		return fmt.Errorf("任务运行时已注册处理器")
	}
	handlers := map[string]task.Handler{
		mailer.TaskKindMailDelivery:     r.mailer.Handler,
		webhook.TaskKindWebhookDelivery: r.webhook.Handler,
	}
	kinds := []string{mailer.TaskKindMailDelivery, webhook.TaskKindWebhookDelivery}
	for kind, handler := range extra {
		trimmed := strings.TrimSpace(kind)
		if trimmed == "" || handler == nil {
			return fmt.Errorf("任务处理器类型或处理函数为空")
		}
		if _, exists := handlers[trimmed]; exists {
			return fmt.Errorf("任务处理器类型重复: %s", trimmed)
		}
		handlers[trimmed] = handler
		kinds = append(kinds, trimmed)
	}
	now := r.now
	if now == nil {
		now = time.Now
	}
	executor, err := task.New(r.store, task.Options{
		Store: r.store, Handlers: handlers, ExecutorID: taskExecutorID,
		MaxConcurrent: taskMaxConcurrent, PollInterval: taskPollInterval,
		ShutdownTimeout: taskShutdownTimeout, Logger: r.logger, Now: now,
		// 运行前权限复验：审计导出/清理、备份创建/清理等任务标记
		// PermissionRequired；缺少可信回调时执行器会 fail-closed。回调按任务类型
		// 映射到真实权限键，受信宿主主体放行，其余一律经权限引擎判定。
		PermissionCheck: r.checkTaskPermission,
	})
	if err != nil {
		return fmt.Errorf("构造任务执行器失败: %w", err)
	}
	r.executor = executor
	r.handlerKinds = kinds
	r.enqueuer.Set(executor)
	return nil
}

// BuildTaskRuntimeLegacy 构造并完成默认处理器注册（邮件/Webhook 投递）的运行时，
// 不含域服务处理器；仅供只验证基础投递 worker 的定向测试使用。生产装配使用
// NewTaskRuntime + Complete，且 Webhook 敏感操作必须接真实 reauth 闸门。
func BuildTaskRuntimeLegacy(deps Deps) (*TaskRuntime, error) {
	runtime, err := NewTaskRuntime(deps, nil)
	if err != nil {
		return nil, err
	}
	if err := runtime.Complete(nil); err != nil {
		return nil, err
	}
	return runtime, nil
}

// Start 启动任务执行器与定时调度器；调度器启动失败时回滚已启动的执行器。
// 可重复调用安全，但只有首次真正启动。
func (r *TaskRuntime) Start(ctx context.Context) error {
	if r == nil {
		return fmt.Errorf("任务运行时未构造")
	}
	if r.executor == nil || r.scheduler == nil {
		return fmt.Errorf("任务运行时未完成处理器注册")
	}
	if err := r.executor.Start(ctx); err != nil {
		if errors.Is(err, task.ErrAlreadyStarted) {
			return nil
		}
		return fmt.Errorf("启动任务执行器失败: %w", err)
	}
	if err := r.scheduler.Start(ctx); err != nil {
		stopCtx, cancel := context.WithTimeout(context.Background(), taskShutdownTimeout)
		defer cancel()
		if stopErr := r.executor.Stop(stopCtx); stopErr != nil {
			return errors.Join(fmt.Errorf("启动任务调度器失败: %w", err),
				fmt.Errorf("回滚任务执行器失败: %w", stopErr))
		}
		return fmt.Errorf("启动任务调度器失败: %w", err)
	}
	r.logger.Info("后台任务运行时已启动",
		"executor_id", taskExecutorID, "scheduler_id", taskSchedulerID,
		"handlers", r.handlerKinds,
		"mail_delivery", "disabled（未配置真实发送器，投递会以明确错误失败）")
	return nil
}

// Close 有界停止调度器与执行器；错误聚合返回但继续释放。可重复调用。
func (r *TaskRuntime) Close(ctx context.Context) error {
	if r == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	shutdownCtx, cancel := context.WithTimeout(ctx, TaskRuntimeShutdownTimeout)
	defer cancel()
	var problems []error
	if r.scheduler != nil {
		if err := r.scheduler.Stop(shutdownCtx); err != nil {
			problems = append(problems, fmt.Errorf("停止任务调度器失败: %w", err))
		}
	}
	if r.executor != nil {
		if err := r.executor.Stop(shutdownCtx); err != nil {
			problems = append(problems, fmt.Errorf("停止任务执行器失败: %w", err))
		}
	}
	if len(problems) > 0 {
		return errors.Join(problems...)
	}
	r.logger.Info("后台任务运行时已停止")
	return nil
}

// 编译期确认后台组件契约。
var _ interface {
	Start(context.Context) error
	Close(context.Context) error
} = (*TaskRuntime)(nil)
