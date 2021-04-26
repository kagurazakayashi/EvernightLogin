package task

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"sync"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// Options 是构造 Executor 的依赖。
type Options struct {
	// Store 是任务状态持久化；必填。
	Store Store
	// Handlers 是按任务类型注册的处理器；每种任务类型必须有一个处理器。
	Handlers map[string]Handler
	// ExecutorID 是执行器稳定标识（宿主/进程级），用于 executed_by 与系统审计
	// 身份；必填。
	ExecutorID string
	// MaxConcurrent 是最大并发执行任务数；0 使用默认值，范围 1～6。
	MaxConcurrent int
	// PollInterval 是队列轮询间隔；0 使用默认值，范围 20ms～5s。本包不做定时
	// 调度，只轮询 queued 队列。
	PollInterval time.Duration
	// ShutdownTimeout 是 Stop 等待调度与处理器退出的期限；0 使用默认值，范围
	// 1～60 秒。
	ShutdownTimeout time.Duration
	// Logger 是运行日志器；nil 使用丢弃输出。运行日志与安全审计是两套数据。
	Logger *slog.Logger
	// Now 是可注入时钟；nil 使用 time.Now。任务时间统一截断到 UTC 毫秒。
	Now func() time.Time
	// RetryPolicy 是可重试失败后的有界指数退避；0 使用默认值（1s 起、5m 封顶）。
	// 只有任务行 MaxAttempts>1 且处理器返回可重试错误时才生效。
	RetryPolicy RetryPolicy
	// PermissionCheck 是运行前权限复验的可信回调。任务标记 PermissionRequired 时
	// 每次尝试前必须通过；未配置时这类任务失败而不是默认放行。
	PermissionCheck PermissionCheck
}

// executorState 是执行器内部生命周期状态。
type executorState int

const (
	executorStateNew executorState = iota
	executorStateRunning
	executorStateStopped
)

// Executor 是单实例后台任务执行器。构造后不启动任何 goroutine；Start 后由一个
// 调度 goroutine 领取 queued 任务并受并发上限约束，Stop 停止领取并以系统主体
// 取消运行中任务。
//
// 同一 Executor 的 Start/Stop 并发安全；Start 只能成功一次，Stop 可重复调用。
// 执行器不拥有数据库连接，也不关闭宿主资源。
type Executor struct {
	store           Store
	handlers        map[string]Handler
	executorID      string
	maxConcurrent   int
	pollInterval    time.Duration
	shutdownTimeout time.Duration
	logger          *slog.Logger
	now             func() time.Time
	retryPolicy     RetryPolicy
	permissionCheck PermissionCheck

	stopMu sync.Mutex
	mu     sync.Mutex

	state          executorState
	stopping       bool
	ctx            context.Context
	cancelFunc     context.CancelFunc
	wake           chan struct{}
	dispatcherDone chan struct{}
	running        map[string]context.CancelFunc
	wg             sync.WaitGroup
}

// New 构造执行器，不启动 goroutine、不访问数据库。store 为空、未注册处理器、
// 执行器标识非法或并发/轮询/关闭期限超界时返回 ErrOptionsInvalid。
func New(store Store, options Options) (*Executor, error) {
	if isNilStore(store) {
		return nil, fmt.Errorf("%w: 任务存储为空", ErrOptionsInvalid)
	}
	if err := validateToken("执行器标识", options.ExecutorID, audit.MaxActorIDBytes, true); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOptionsInvalid, err)
	}
	handlers := make(map[string]Handler, len(options.Handlers))
	for kind, handler := range options.Handlers {
		if err := validateToken("任务类型", kind, MaxKindBytes, true); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrOptionsInvalid, err)
		}
		if handler == nil {
			return nil, fmt.Errorf("%w: 任务类型 %q 的处理器为空", ErrOptionsInvalid, kind)
		}
		handlers[kind] = handler
	}
	maxConcurrent := options.MaxConcurrent
	if maxConcurrent == 0 {
		maxConcurrent = DefaultMaxConcurrent
	}
	if maxConcurrent < 1 || maxConcurrent > MaxAllowedConcurrent {
		return nil, fmt.Errorf("%w: 最大并发必须在 1～%d 之间", ErrOptionsInvalid, MaxAllowedConcurrent)
	}
	pollInterval := options.PollInterval
	if pollInterval == 0 {
		pollInterval = DefaultPollInterval
	}
	if pollInterval < MinPollInterval || pollInterval > MaxPollInterval {
		return nil, fmt.Errorf("%w: 轮询间隔必须在 %s～%s 之间", ErrOptionsInvalid, MinPollInterval, MaxPollInterval)
	}
	shutdownTimeout := options.ShutdownTimeout
	if shutdownTimeout == 0 {
		shutdownTimeout = DefaultShutdownTimeout
	}
	if shutdownTimeout < MinShutdownTimeout || shutdownTimeout > MaxShutdownTimeout {
		return nil, fmt.Errorf("%w: 关闭期限必须在 %s～%s 之间", ErrOptionsInvalid, MinShutdownTimeout, MaxShutdownTimeout)
	}
	logger := options.Logger
	if logger == nil {
		logger = discardLogger()
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	retryPolicy, err := options.RetryPolicy.normalize()
	if err != nil {
		return nil, err
	}
	return &Executor{
		store:           store,
		handlers:        handlers,
		executorID:      options.ExecutorID,
		maxConcurrent:   maxConcurrent,
		pollInterval:    pollInterval,
		shutdownTimeout: shutdownTimeout,
		logger:          logger,
		now:             now,
		retryPolicy:     retryPolicy,
		permissionCheck: options.PermissionCheck,
		wake:            make(chan struct{}, 1),
		running:         make(map[string]context.CancelFunc),
	}, nil
}

// isNilStore 检测 nil 接口与 typed nil 指针，避免调用时 panic。
func isNilStore(store Store) bool {
	if store == nil {
		return true
	}
	value := reflect.ValueOf(store)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

// Start 先识别并安全恢复重启前遗留的运行中任务（标记 failed/TASK_INTERRUPTED
// 并审计），然后启动调度 goroutine 领取 queued 任务。恢复失败时执行器拒绝开始，
// 返回 ErrRecoveryFailed，避免新任务与不确定的遗留状态混在一起。
func (e *Executor) Start(ctx context.Context) error {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	e.mu.Lock()
	if e.state == executorStateRunning {
		e.mu.Unlock()
		return ErrAlreadyStarted
	}
	if e.state == executorStateStopped {
		e.mu.Unlock()
		return ErrClosed
	}
	e.state = executorStateRunning
	lifetime, cancel := context.WithCancel(context.Background())
	e.ctx = lifetime
	e.cancelFunc = cancel
	e.dispatcherDone = make(chan struct{})
	dispatcherDone := e.dispatcherDone
	e.mu.Unlock()

	recovered, err := e.store.RecoverInterrupted(ctx, e.executorID, e.now())
	if err != nil {
		e.mu.Lock()
		e.state = executorStateNew
		e.ctx = nil
		e.cancelFunc = nil
		e.dispatcherDone = nil
		e.mu.Unlock()
		cancel()
		return fmt.Errorf("%w: %w", ErrRecoveryFailed, err)
	}
	go e.dispatch(lifetime, dispatcherDone)
	e.logger.Info("后台任务执行器已启动",
		"executor_id", e.executorID,
		"max_concurrent", e.maxConcurrent,
		"recovered_interrupted", recovered,
	)
	return nil
}

// Stop 停止领取新任务，对运行中任务以系统主体发起取消并记录审计，取消处理器
// 上下文，然后在调用方期限与 ShutdownTimeout 较早者内等待调度与处理器退出。
//
// queued 任务保留，下次启动继续执行。若期限内处理器仍未退出，返回
// ErrShutdownTimeout；此时不能声称已完全清理，遗留状态由下次启动的恢复策略处理。
func (e *Executor) Stop(ctx context.Context) error {
	ctx = normalizeContext(ctx)
	e.stopMu.Lock()
	defer e.stopMu.Unlock()

	e.mu.Lock()
	switch e.state {
	case executorStateNew:
		e.state = executorStateStopped
		e.mu.Unlock()
		return nil
	case executorStateStopped:
		e.mu.Unlock()
		return nil
	}
	e.stopping = true
	dispatcherDone := e.dispatcherDone
	e.mu.Unlock()

	// 唤醒调度 goroutine，使其观察到 stopping 并退出；不先取消 handler 上下文，
	// 以便先记录系统取消审计。
	select {
	case e.wake <- struct{}{}:
	default:
	}
	if err := waitFor(ctx, dispatcherDone, e.shutdownTimeout); err != nil {
		if e.cancelFunc != nil {
			e.cancelFunc()
		}
		e.markStopped()
		return fmt.Errorf("%w: 调度未在期限内退出", ErrShutdownTimeout)
	}

	e.mu.Lock()
	running := make(map[string]context.CancelFunc, len(e.running))
	for jobID, cancel := range e.running {
		running[jobID] = cancel
	}
	e.mu.Unlock()

	systemActor := audit.Actor{Type: audit.ActorSystem, ID: e.executorID}
	for jobID := range running {
		cancelCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), e.shutdownTimeout)
		_, err := e.store.RequestCancel(cancelCtx, CancelCommand{
			JobID:  jobID,
			Actor:  systemActor,
			Reason: "执行器停止，系统取消运行中任务",
			Now:    e.now(),
		})
		cancel()
		if err != nil && !errors.Is(err, ErrTaskTerminal) {
			e.logger.Warn("停机取消任务失败", "job_id", jobID, "error", err)
		}
	}
	for _, cancel := range running {
		cancel()
	}
	if e.cancelFunc != nil {
		e.cancelFunc()
	}

	workersDone := make(chan struct{})
	go func() {
		e.wg.Wait()
		close(workersDone)
	}()
	if err := waitFor(ctx, workersDone, e.shutdownTimeout); err != nil {
		e.markStopped()
		return fmt.Errorf("%w: 运行中处理器未在期限内退出", ErrShutdownTimeout)
	}
	e.markStopped()
	e.logger.Info("后台任务执行器已停止", "executor_id", e.executorID)
	return nil
}

// markStopped 把执行器标记为停止，避免再次启动。
func (e *Executor) markStopped() {
	e.mu.Lock()
	e.state = executorStateStopped
	e.mu.Unlock()
}

// Enqueue 创建并持久化一条 queued 任务，随后唤醒调度。Actor 必须来自可信调用
// 上下文，匿名身份返回 ErrUntrustedActor。
func (e *Executor) Enqueue(ctx context.Context, request EnqueueRequest) (Job, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return Job{}, err
	}
	normalized, err := normalizeEnqueueRequest(request)
	if err != nil {
		return Job{}, err
	}
	id, err := NewJobID()
	if err != nil {
		return Job{}, err
	}
	now := e.clockNow()
	job, err := e.store.Enqueue(ctx, NewJob{
		ID:                 id,
		Kind:               normalized.Kind,
		Initiator:          normalized.Actor,
		Payload:            normalized.Payload,
		MutexKey:           normalized.MutexKey,
		TimeoutSeconds:     normalized.TimeoutSeconds,
		MaxAttempts:        normalized.MaxAttempts,
		PermissionRequired: normalized.PermissionRequired,
		RequestID:          normalized.RequestID,
		CreatedAt:          now,
	})
	if err != nil {
		return Job{}, err
	}
	e.Wake()
	e.logger.Info("后台任务已入队",
		"job_id", job.ID,
		"kind", job.Kind,
		"initiated_by_type", string(job.Initiator.Type),
		"max_attempts", job.MaxAttempts,
	)
	return job, nil
}

// Wake 唤醒队列轮询，让在同一存储中由外部（例如定时计划触发）新增的 queued
// 任务尽快被领取。它不创建任务、不改变状态、不阻塞。
func (e *Executor) Wake() {
	if e.wake == nil {
		return
	}
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

// Attempts 返回任务的尝试历史（按尝试序号升序）；任务不存在或编号非法时返回
// 错误，空历史返回空切片。调用方必须是可信内部边界。
func (e *Executor) Attempts(ctx context.Context, id string) ([]Attempt, error) {
	ctx = normalizeContext(ctx)
	if err := validateJobID(id); err != nil {
		return nil, err
	}
	return e.store.Attempts(ctx, id)
}

// RequestCancel 接受可信取消请求。queued 任务会立即变为 cancelled；running 任务
// 进入 cancel_requested 并取消其上下文，真实终止结果稍后由执行器以终态写入。
// 终态任务返回 ErrTaskTerminal，不能把取消请求显示为已取消。
func (e *Executor) RequestCancel(ctx context.Context, request CancelRequest) (CancelResult, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return CancelResult{}, err
	}
	normalized, err := normalizeCancelRequest(request)
	if err != nil {
		return CancelResult{}, err
	}
	result, err := e.store.RequestCancel(ctx, CancelCommand{
		JobID:     normalized.JobID,
		Actor:     normalized.Actor,
		Reason:    normalized.Reason,
		RequestID: normalized.RequestID,
		Now:       e.clockNow(),
	})
	if err != nil {
		return result, err
	}
	if result.Accepted && result.State == StateCancelRequested {
		e.mu.Lock()
		cancel := e.running[normalized.JobID]
		e.mu.Unlock()
		if cancel != nil {
			cancel()
		}
	}
	e.logger.Info("后台任务取消请求已处理",
		"job_id", normalized.JobID,
		"accepted", result.Accepted,
		"state", string(result.State),
	)
	return result, nil
}

// Get 查询任务当前状态；不存在返回 ErrTaskNotFound。
func (e *Executor) Get(ctx context.Context, id string) (Job, error) {
	ctx = normalizeContext(ctx)
	if err := validateJobID(id); err != nil {
		return Job{}, err
	}
	job, found, err := e.store.Get(ctx, id)
	if err != nil {
		return Job{}, err
	}
	if !found {
		return Job{}, ErrTaskNotFound
	}
	return job, nil
}

// dispatch 是唯一的任务领取循环；它保证不会同时有多个 goroutine 领取任务，
// 从而简化互斥键检查与并发上限控制。
func (e *Executor) dispatch(lifetime context.Context, done chan struct{}) {
	defer close(done)
	timer := time.NewTimer(e.pollInterval)
	defer timer.Stop()
	for {
		if e.isStopping() {
			return
		}
		for {
			if e.isStopping() || lifetime.Err() != nil {
				return
			}
			if e.runningCount() >= e.maxConcurrent {
				break
			}
			job, found, err := e.store.Claim(lifetime, e.executorID, e.clockNow())
			if err != nil {
				if lifetime.Err() != nil {
					return
				}
				e.logger.Error("后台任务领取失败", "error", err)
				break
			}
			if !found {
				break
			}
			e.launch(lifetime, job)
		}
		resetTimer(timer, e.pollInterval)
		select {
		case <-lifetime.Done():
			return
		case <-e.wake:
		case <-timer.C:
		}
	}
}

// launch 为已领取任务创建带墙钟期限的执行上下文并启动处理器 goroutine。
//
// 期限长度用注入时钟计算（deadline - now），相对真实时间的计时由 context 负责；
// 这样确定性测试注入的假时钟不会因为绝对时间在过去而立即到期，同时生产环境
// 等价于 started_at + timeout_seconds 的绝对期限。
func (e *Executor) launch(lifetime context.Context, job Job) {
	deadline := job.StartedAt.Add(time.Duration(job.TimeoutSeconds) * time.Second)
	remaining := deadline.Sub(e.clockNow())
	if remaining <= 0 {
		remaining = time.Nanosecond
	}
	runCtx, cancel := context.WithTimeout(lifetime, remaining)
	e.mu.Lock()
	e.running[job.ID] = cancel
	e.mu.Unlock()
	e.wg.Add(1)
	go e.runJob(runCtx, cancel, job)
}

// errHandlerUnknown 表示任务类型没有注册处理器；属于配置错误，不重试。
var errHandlerUnknown = errors.New("任务类型没有注册处理器")

// runJob 执行任务处理器并把真实终止结果写入持久化终态；可重试失败按退避策略
// 重新排队，取消请求已接受的任务不会重试。
func (e *Executor) runJob(runCtx context.Context, cancel context.CancelFunc, job Job) {
	defer e.wg.Done()
	defer cancel()
	defer func() {
		e.mu.Lock()
		delete(e.running, job.ID)
		e.mu.Unlock()
	}()

	handlerErr := e.executeHandler(runCtx, job)
	now := e.clockNow()
	deadline := job.StartedAt.Add(time.Duration(job.TimeoutSeconds) * time.Second)
	completion := Completion{
		JobID:      job.ID,
		ExecutorID: e.executorID,
		Now:        now,
	}
	switch {
	case errors.Is(runCtx.Err(), context.DeadlineExceeded) || (!job.StartedAt.IsZero() && now.After(deadline)):
		completion.State = StateTimedOut
		completion.ErrorCode = "TASK_TIMEOUT"
		completion.FailureReason = "任务超过墙钟执行上限"
	case handlerErr == nil:
		// 即使取消请求已接受，处理器真实返回成功时记录真实最终状态 succeeded；
		// cancel_requested 的请求人、原因与时间已保存在任务行与审计中，不覆盖。
		completion.State = StateSucceeded
	case errors.Is(runCtx.Err(), context.Canceled):
		completion.State = StateCancelled
		completion.ErrorCode = "TASK_CANCELLED"
		completion.FailureReason = "任务在执行中被取消"
	default:
		if e.shouldRetry(job, handlerErr) {
			retryCtx, retryCancel := context.WithTimeout(context.WithoutCancel(runCtx), e.shutdownTimeout)
			_, retried, retryErr := e.store.Retry(retryCtx, RetryCommand{
				JobID:         job.ID,
				ExecutorID:    e.executorID,
				Attempt:       job.Attempt,
				ErrorCode:     classifyFailure(handlerErr),
				FailureReason: sanitizeFailureReason(handlerErr.Error()),
				NextAttemptAt: now.Add(e.retryPolicy.delayAfter(job.Attempt)),
				Now:           now,
			})
			retryCancel()
			if retryErr != nil && !errors.Is(retryErr, ErrTransitionRejected) {
				e.logger.Error("后台任务重试入队失败",
					"job_id", job.ID,
					"attempt", job.Attempt,
					"error", retryErr,
				)
				return
			}
			if retried {
				e.logger.Info("后台任务已安排重试",
					"job_id", job.ID,
					"attempt", job.Attempt,
					"max_attempts", job.MaxAttempts,
					"next_attempt_at", now.Add(e.retryPolicy.delayAfter(job.Attempt)).UTC(),
				)
				return
			}
			// 重试被状态竞争拒绝：读取真实状态，取消请求已接受时写取消终态，
			// 不能把已取消任务显示为失败或已安排重试。
			latest, found, getErr := e.store.Get(context.WithoutCancel(runCtx), job.ID)
			if getErr == nil && found && (latest.State == StateCancelRequested || latest.State == StateCancelled) {
				completion.State = StateCancelled
				completion.ErrorCode = "TASK_CANCELLED"
				completion.FailureReason = "任务在执行中被取消"
				break
			}
			completion.State = StateFailed
			completion.ErrorCode = classifyFailure(handlerErr)
			completion.FailureReason = sanitizeFailureReason(handlerErr.Error())
		} else {
			completion.State = StateFailed
			completion.ErrorCode = classifyFailure(handlerErr)
			completion.FailureReason = sanitizeFailureReason(handlerErr.Error())
		}
	}
	completeCtx, completeCancel := context.WithTimeout(context.WithoutCancel(runCtx), e.shutdownTimeout)
	updated, err := e.store.Complete(completeCtx, completion)
	completeCancel()
	if err != nil {
		e.logger.Error("后台任务终态写入失败",
			"job_id", job.ID,
			"state", string(completion.State),
			"error", err,
		)
		return
	}
	e.logger.Info("后台任务已结束",
		"job_id", updated.ID,
		"kind", updated.Kind,
		"state", string(updated.State),
		"attempt", updated.Attempt,
		"error_code", updated.ErrorCode,
	)
}

// executeHandler 在调用处理器前完成运行前权限复验：任务标记为需要权限时，
// 缺少可信回调或复验失败都按不可重试失败处理，绝不默认放行。
func (e *Executor) executeHandler(ctx context.Context, job Job) error {
	if job.PermissionRequired {
		if e.permissionCheck == nil {
			return NonRetryable(fmt.Errorf("%w: 任务要求运行前权限复验，但没有配置可信回调", ErrPermissionRevoked))
		}
		if err := e.permissionCheck(ctx, PermissionRequest{
			Kind:     job.Kind,
			Actor:    job.Initiator,
			Payload:  job.Payload,
			MutexKey: job.MutexKey,
			JobID:    job.ID,
		}); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			e.logger.Warn("后台任务运行前权限复验未通过",
				"job_id", job.ID,
				"kind", job.Kind,
				"error", err,
			)
			return NonRetryable(fmt.Errorf("%w: %s", ErrPermissionRevoked, sanitizeFailureReason(err.Error())))
		}
	}
	handler := e.handlers[job.Kind]
	if handler == nil {
		return NonRetryable(errHandlerUnknown)
	}
	return e.invokeHandler(ctx, job, handler)
}

// shouldRetry 判断处理器失败是否还能重试：受尝试上限、显式不可重试、权限撤销
// 与取消/期限约束，不自动重试整体墙钟超时（由 timed_out 终态处理）。
func (e *Executor) shouldRetry(job Job, err error) bool {
	if err == nil || job.MaxAttempts <= job.Attempt {
		return false
	}
	if IsNonRetryable(err) {
		return false
	}
	if errors.Is(err, ErrPermissionRevoked) {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	return true
}

// classifyFailure 把失败映射为内部错误码；对外错误码映射由服务层完成。
func classifyFailure(err error) string {
	switch {
	case errors.Is(err, errHandlerUnknown):
		return "TASK_HANDLER_UNKNOWN"
	case errors.Is(err, ErrPermissionRevoked):
		return "TASK_PERMISSION_REVOKED"
	default:
		return "TASK_FAILED"
	}
}

// invokeHandler 隔离处理器 panic，把 panic 当作不可重试失败而不是让执行器
// goroutine 崩溃。
func (e *Executor) invokeHandler(ctx context.Context, job Job, handler Handler) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			e.logger.Error("后台任务处理器 panic", "job_id", job.ID, "kind", job.Kind)
			err = NonRetryable(fmt.Errorf("任务处理器发生 panic"))
		}
	}()
	return handler(ctx, job)
}

// isStopping 报告执行器是否已进入停止流程。
func (e *Executor) isStopping() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stopping
}

// runningCount 返回当前运行中任务数量。
func (e *Executor) runningCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.running)
}

// clockNow 返回截断到 UTC 毫秒的当前时间。
func (e *Executor) clockNow() time.Time {
	return e.now().UTC().Truncate(time.Millisecond)
}

// resetTimer 安全地重置调度定时器。
func resetTimer(timer *time.Timer, duration time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(duration)
}

// waitFor 等待 done 关闭，同时受调用方 ctx 与内部期限约束。
func waitFor(ctx context.Context, done <-chan struct{}, timeout time.Duration) error {
	if done == nil {
		return nil
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return ErrShutdownTimeout
	}
}

// normalizeContext 把 nil ctx 当成 Background，避免调用方漏传时 panic。
func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
