package task

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

const (
	// DefaultSchedulerTickInterval 是调度器默认检查间隔。
	DefaultSchedulerTickInterval = 30 * time.Second
	// MinSchedulerTickInterval/MaxSchedulerTickInterval 是检查间隔范围。
	MinSchedulerTickInterval = 100 * time.Millisecond
	MaxSchedulerTickInterval = 5 * time.Minute
	// DefaultCatchUpGrace 是触发到期后仍视为“准点”的宽限窗口；超过该窗口的
	// 触发按错过策略处理，避免停机数小时后把旧的准点触发当成实时触发。
	DefaultCatchUpGrace = time.Minute
	// MaxCatchUpGrace 是宽限窗口上限。
	MaxCatchUpGrace = time.Hour
)

// SchedulerOptions 是构造定时调度器的依赖。
type SchedulerOptions struct {
	// Store 是任务与计划持久化；必填，且必须实现 ScheduleStore。
	Store ScheduleStore
	// SchedulerID 是调度器稳定标识（宿主/进程级），用于系统审计身份；必填。
	SchedulerID string
	// Executor 是可选的同进程任务执行器；触发入队后会被唤醒以尽快领取。
	Executor *Executor
	// PermissionCheck 是运行前权限复验的可信回调；计划要求权限时必填。
	PermissionCheck PermissionCheck
	// OnJobEnqueued 是可选的成功入队回调（best-effort）：在 FireSchedule 事务提交
	// 后调用，用于让管理域记录任务索引与阶段。回调失败不影响已入队任务；实现必须
	// 幂等、不得阻塞调度循环。
	OnJobEnqueued func(ctx context.Context, schedule Schedule, jobID string)
	// TickInterval 是周期检查间隔；0 使用默认值，范围 100ms～5m。
	TickInterval time.Duration
	// CatchUpGrace 是准点宽限窗口；0 使用默认值（1 分钟），上限 1 小时。
	CatchUpGrace time.Duration
	// Now 是可注入时钟；nil 使用 time.Now。测试必须注入确定性时钟。
	Now func() time.Time
	// Logger 是运行日志器；nil 使用丢弃输出。
	Logger *slog.Logger
}

// Scheduler 是单实例定时调度器：按计划表达式计算到期触发，原子去重后入队任务。
//
// 调度器只负责“何时创建任务”，复用 Executor/Store 的任务状态机与审计，不另造
// 一套任务状态。同一实例同一触发时刻最多入队一次：唯一键
// (schedule_id, scheduled_at_ms) 在数据库层阻止重复；多调度器同时运行也只有
// 一个能记录成功。
//
// 计划暂停/删除只停止后续触发，不取消已经入队或正在运行的任务。计划权限复验
// 在每次触发前执行；未配置回调而计划要求权限时拒绝触发并审计，默认拒绝。
type Scheduler struct {
	store           ScheduleStore
	executor        *Executor
	schedulerID     string
	permissionCheck PermissionCheck
	onJobEnqueued   func(ctx context.Context, schedule Schedule, jobID string)
	tickInterval    time.Duration
	catchUpGrace    time.Duration
	now             func() time.Time
	logger          *slog.Logger

	stopMu sync.Mutex
	mu     sync.Mutex

	state      executorState
	stopping   bool
	cancelFunc context.CancelFunc
	done       chan struct{}
}

// NewScheduler 构造调度器，不启动 goroutine、不访问数据库。存储为空、调度器
// 标识非法或间隔/宽限期超界时返回 ErrOptionsInvalid。
func NewScheduler(options SchedulerOptions) (*Scheduler, error) {
	if isNilScheduleStore(options.Store) {
		return nil, fmt.Errorf("%w: 计划存储为空", ErrOptionsInvalid)
	}
	if err := validateToken("调度器标识", options.SchedulerID, audit.MaxActorIDBytes, true); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOptionsInvalid, err)
	}
	tickInterval := options.TickInterval
	if tickInterval == 0 {
		tickInterval = DefaultSchedulerTickInterval
	}
	if tickInterval < MinSchedulerTickInterval || tickInterval > MaxSchedulerTickInterval {
		return nil, fmt.Errorf("%w: 调度检查间隔必须在 %s～%s 之间", ErrOptionsInvalid, MinSchedulerTickInterval, MaxSchedulerTickInterval)
	}
	catchUpGrace := options.CatchUpGrace
	if catchUpGrace == 0 {
		catchUpGrace = DefaultCatchUpGrace
	}
	if catchUpGrace < 0 || catchUpGrace > MaxCatchUpGrace {
		return nil, fmt.Errorf("%w: 准点宽限必须在 0～%s 之间", ErrOptionsInvalid, MaxCatchUpGrace)
	}
	logger := options.Logger
	if logger == nil {
		logger = discardLogger()
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	return &Scheduler{
		store:           options.Store,
		executor:        options.Executor,
		schedulerID:     options.SchedulerID,
		permissionCheck: options.PermissionCheck,
		onJobEnqueued:   options.OnJobEnqueued,
		tickInterval:    tickInterval,
		catchUpGrace:    catchUpGrace,
		now:             now,
		logger:          logger,
	}, nil
}

// isNilScheduleStore 检测 nil 接口与 typed nil 指针，避免调用时 panic。
func isNilScheduleStore(store ScheduleStore) bool {
	if store == nil {
		return true
	}
	// 复用任务存储的 nil 检测：ScheduleStore 内嵌 Store，typed nil 指针同样危险。
	return isNilStore(store)
}

// Start 先执行一次有界补跑 Tick（处理停机错过的触发），再启动周期检查
// goroutine。补跑失败时拒绝启动，避免把不确定的调度状态带入正常周期。
func (s *Scheduler) Start(ctx context.Context) error {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	if s.state == executorStateRunning {
		s.mu.Unlock()
		return ErrAlreadyStarted
	}
	if s.state == executorStateStopped {
		s.mu.Unlock()
		return ErrClosed
	}
	s.state = executorStateRunning
	lifetime, cancel := context.WithCancel(context.Background())
	s.cancelFunc = cancel
	s.done = make(chan struct{})
	done := s.done
	s.mu.Unlock()

	if err := s.Tick(ctx); err != nil {
		s.mu.Lock()
		s.state = executorStateNew
		s.cancelFunc = nil
		s.done = nil
		s.mu.Unlock()
		cancel()
		return fmt.Errorf("%w: 启动补跑失败: %w", ErrStoreUnavailable, err)
	}
	go s.loop(lifetime, done)
	s.logger.Info("定时计划调度器已启动",
		"schedule_id_scope", s.schedulerID,
		"tick_interval", s.tickInterval,
	)
	return nil
}

// Stop 停止周期检查并等待调度 goroutine 退出；可重复调用。调度器没有自己的
// 运行中任务，停止不会取消任务执行器里的任务。
func (s *Scheduler) Stop(ctx context.Context) error {
	ctx = normalizeContext(ctx)
	s.stopMu.Lock()
	defer s.stopMu.Unlock()

	s.mu.Lock()
	switch s.state {
	case executorStateNew:
		s.state = executorStateStopped
		s.mu.Unlock()
		return nil
	case executorStateStopped:
		s.mu.Unlock()
		return nil
	}
	s.stopping = true
	done := s.done
	cancel := s.cancelFunc
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if err := waitFor(ctx, done, DefaultShutdownTimeout); err != nil {
		s.markStopped()
		if errors.Is(err, ErrShutdownTimeout) {
			return fmt.Errorf("%w: 调度循环未在期限内退出", ErrShutdownTimeout)
		}
		return err
	}
	s.markStopped()
	s.logger.Info("定时计划调度器已停止", "scheduler_id", s.schedulerID)
	return nil
}

// markStopped 把调度器标记为停止，避免再次启动。
func (s *Scheduler) markStopped() {
	s.mu.Lock()
	s.state = executorStateStopped
	s.mu.Unlock()
}

// Tick 执行一次计划检查与触发（导出以便宿主手动触发和确定性测试）。它按注入
// 时钟计算到期触发，不等待真实时间；计划级错误会记录日志并继续处理其他计划。
func (s *Scheduler) Tick(ctx context.Context) error {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	schedules, err := s.store.ListSchedules(ctx, true)
	if err != nil {
		return fmt.Errorf("列出定时计划失败: %w", err)
	}
	var problems []error
	for _, schedule := range schedules {
		if err := s.processSchedule(ctx, schedule); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			s.logger.Error("处理定时计划失败", "schedule_id", schedule.ID, "error", err)
			problems = append(problems, err)
		}
	}
	return errors.Join(problems...)
}

// processSchedule 按错过策略处理单个计划的到期触发。
func (s *Scheduler) processSchedule(ctx context.Context, schedule Schedule) error {
	spec, err := ParseScheduleSpec(schedule.ScheduleType, schedule.Expression, schedule.TimeZone, schedule.CreatedAt)
	if err != nil {
		return fmt.Errorf("计划表达式无效: %w", err)
	}
	now := s.clockNow()
	cursor := schedule.LastScheduledAt
	switch schedule.MissedPolicy {
	case MissedSkip:
		latest, ok := spec.LatestAtOrBefore(now)
		if !ok || !latest.After(cursor) {
			return nil
		}
		if now.Sub(latest) > s.catchUpGrace {
			// 停机/长时间延迟后的旧触发不补跑，只推进游标并审计。
			_, err := s.recordSkipped(ctx, schedule, latest, "missed_policy_skip")
			return err
		}
		_, err := s.fire(ctx, schedule, latest, now)
		return err
	case MissedLatest:
		latest, ok := spec.LatestAtOrBefore(now)
		if !ok || !latest.After(cursor) {
			return nil
		}
		// 只补跑最近一次；更早的触发由游标一次性跳过，不产生无界补跑。
		_, err := s.fire(ctx, schedule, latest, now)
		return err
	case MissedAll:
		for index := 0; index < schedule.MaxCatchUp; index++ {
			next := spec.Next(cursor)
			if next.After(now) {
				return nil
			}
			result, err := s.fire(ctx, schedule, next, now)
			if err != nil {
				return err
			}
			cursor = next
			if !result.Fired {
				// 该触发时刻已由其他调度器或更早的 Tick 记录，继续推进游标。
				continue
			}
		}
		return nil
	default:
		return fmt.Errorf("未知错过策略 %q", schedule.MissedPolicy)
	}
}

// fire 在运行前权限复验通过后原子记录一次触发并入队任务。权限复验缺失或失败
// 时记录带拒绝原因的触发，不入队任务。
func (s *Scheduler) fire(ctx context.Context, schedule Schedule, scheduledAt, now time.Time) (FireResult, error) {
	if schedule.PermissionRequired {
		if s.permissionCheck == nil {
			s.logger.Warn("定时计划要求运行前权限复验但没有可信回调，拒绝触发",
				"schedule_id", schedule.ID,
				"job_kind", schedule.JobKind,
			)
			return s.recordDenied(ctx, schedule, scheduledAt, "permission_check_missing")
		}
		if err := s.permissionCheck(ctx, PermissionRequest{
			Kind:       schedule.JobKind,
			Actor:      schedule.ExecutionActor,
			Payload:    schedule.Payload,
			MutexKey:   schedule.MutexKey,
			ScheduleID: schedule.ID,
		}); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return FireResult{}, err
			}
			s.logger.Warn("定时计划运行前权限复验未通过",
				"schedule_id", schedule.ID,
				"job_kind", schedule.JobKind,
				"error", err,
			)
			return s.recordDenied(ctx, schedule, scheduledAt, "permission_check_failed")
		}
	}
	jobID, err := NewJobID()
	if err != nil {
		return FireResult{}, err
	}
	job := &NewJob{
		ID:                 jobID,
		Kind:               schedule.JobKind,
		Initiator:          schedule.ExecutionActor,
		Payload:            schedule.Payload,
		MutexKey:           schedule.MutexKey,
		TimeoutSeconds:     schedule.TimeoutSeconds,
		MaxAttempts:        schedule.MaxAttempts,
		PermissionRequired: schedule.PermissionRequired,
		CreatedAt:          now,
	}
	result, err := s.store.FireSchedule(ctx, FireCommand{
		ScheduleID:  schedule.ID,
		ScheduledAt: scheduledAt,
		Job:         job,
		Outcome:     FireEnqueued,
		Actor:       s.systemActor(),
		Now:         now,
	})
	if err != nil {
		return FireResult{}, err
	}
	if result.Fired {
		if s.onJobEnqueued != nil && result.JobID != "" {
			s.onJobEnqueued(ctx, schedule, result.JobID)
		}
		if s.executor != nil {
			s.executor.Wake()
		}
		s.logger.Info("定时计划已触发任务",
			"schedule_id", schedule.ID,
			"job_id", result.JobID,
			"scheduled_at", scheduledAt.UTC(),
		)
	}
	return result, nil
}

// recordSkipped 记录一次被错过策略跳过的触发（推进游标、不产生任务）。
func (s *Scheduler) recordSkipped(ctx context.Context, schedule Schedule, scheduledAt time.Time, reasonCode string) (FireResult, error) {
	return s.store.FireSchedule(ctx, FireCommand{
		ScheduleID:  schedule.ID,
		ScheduledAt: scheduledAt,
		Outcome:     FireSkipped,
		ReasonCode:  reasonCode,
		Actor:       s.systemActor(),
		Now:         s.clockNow(),
	})
}

// recordDenied 记录一次运行前权限复验拒绝（推进游标、不产生任务）。
func (s *Scheduler) recordDenied(ctx context.Context, schedule Schedule, scheduledAt time.Time, reasonCode string) (FireResult, error) {
	return s.store.FireSchedule(ctx, FireCommand{
		ScheduleID:  schedule.ID,
		ScheduledAt: scheduledAt,
		Outcome:     FireDenied,
		ErrorCode:   "ACCESS_DENIED",
		ReasonCode:  reasonCode,
		Actor:       s.systemActor(),
		Now:         s.clockNow(),
	})
}

// Create 创建计划。要求权限复验的计划在没有配置可信回调时直接拒绝，不创建
// “看起来已启用但无法安全运行”的计划。
func (s *Scheduler) Create(ctx context.Context, request NewScheduleRequest) (Schedule, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return Schedule{}, err
	}
	normalized, err := normalizeNewScheduleRequest(request)
	if err != nil {
		return Schedule{}, err
	}
	if !normalized.PermissionExempt && s.permissionCheck == nil {
		return Schedule{}, fmt.Errorf("%w: 计划要求运行前权限复验，但没有配置可信回调", ErrPermissionCheckRequired)
	}
	id, err := NewScheduleID()
	if err != nil {
		return Schedule{}, err
	}
	now := s.clockNow()
	return s.store.CreateSchedule(ctx, NewSchedule{
		ID:                 id,
		JobKind:            normalized.JobKind,
		ScheduleType:       normalized.ScheduleType,
		Expression:         normalized.Expression,
		TimeZone:           normalized.TimeZone,
		Owner:              normalized.Owner,
		ExecutionActor:     normalized.ExecutionActor,
		ScopeID:            normalized.ScopeID,
		Enabled:            normalized.Enabled,
		PermissionRequired: !normalized.PermissionExempt,
		MissedPolicy:       normalized.MissedPolicy,
		MaxCatchUp:         normalized.MaxCatchUp,
		Payload:            normalized.Payload,
		MutexKey:           normalized.MutexKey,
		TimeoutSeconds:     normalized.TimeoutSeconds,
		MaxAttempts:        normalized.MaxAttempts,
		RequestID:          normalized.RequestID,
		CreatedAt:          now,
	})
}

// Pause 暂停计划：只停止后续触发，不取消已入队或运行中的任务。
func (s *Scheduler) Pause(ctx context.Context, command ScheduleStateCommand) (Schedule, error) {
	ctx = normalizeContext(ctx)
	command.Enable = false
	command.Now = s.clockNow()
	return s.setState(ctx, command)
}

// Resume 恢复计划：以恢复时刻重新锚定游标，暂停期间的触发不补跑；之后按计划
// 表达式继续触发。恢复后的第一次触发不会早于恢复时刻的下一到期时刻。
func (s *Scheduler) Resume(ctx context.Context, command ScheduleStateCommand) (Schedule, error) {
	ctx = normalizeContext(ctx)
	command.Enable = true
	command.Now = s.clockNow()
	return s.setState(ctx, command)
}

// setState 校验公共命令字段并调用存储的状态变更。
func (s *Scheduler) setState(ctx context.Context, command ScheduleStateCommand) (Schedule, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return Schedule{}, err
	}
	if command.Now.IsZero() {
		command.Now = s.clockNow()
	}
	if err := ValidateScheduleCommand(command.ScheduleID, command.Actor, command.Reason, command.RequestID); err != nil {
		return Schedule{}, err
	}
	return s.store.SetScheduleEnabled(ctx, command)
}

// Delete 删除计划。已入队或运行中的任务作为独立任务继续执行；删除只停止后续
// 触发并清理计划记录。
func (s *Scheduler) Delete(ctx context.Context, command ScheduleDeleteCommand) error {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ValidateScheduleCommand(command.ScheduleID, command.Actor, command.Reason, command.RequestID); err != nil {
		return err
	}
	if command.Now.IsZero() {
		command.Now = s.clockNow()
	}
	return s.store.DeleteSchedule(ctx, command)
}

// Get 查询计划；不存在返回 ErrScheduleNotFound。
func (s *Scheduler) Get(ctx context.Context, id string) (Schedule, error) {
	ctx = normalizeContext(ctx)
	if err := ValidateScheduleID(id); err != nil {
		return Schedule{}, err
	}
	schedule, found, err := s.store.GetSchedule(ctx, id)
	if err != nil {
		return Schedule{}, err
	}
	if !found {
		return Schedule{}, ErrScheduleNotFound
	}
	return schedule, nil
}

// List 返回全部计划（含暂停的计划），按创建时间升序。
func (s *Scheduler) List(ctx context.Context) ([]Schedule, error) {
	ctx = normalizeContext(ctx)
	return s.store.ListSchedules(ctx, false)
}

// loop 是唯一的周期检查 goroutine。
func (s *Scheduler) loop(lifetime context.Context, done chan struct{}) {
	defer close(done)
	timer := time.NewTimer(s.tickInterval)
	defer timer.Stop()
	for {
		select {
		case <-lifetime.Done():
			return
		case <-timer.C:
			if s.isStopping() {
				return
			}
			if err := s.Tick(lifetime); err != nil && lifetime.Err() == nil {
				s.logger.Error("定时计划检查失败", "error", err)
			}
			resetTimer(timer, s.tickInterval)
		}
	}
}

// isStopping 报告调度器是否已进入停止流程。
func (s *Scheduler) isStopping() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopping
}

// systemActor 返回调度器记录触发与跳过的系统主体。
func (s *Scheduler) systemActor() audit.Actor {
	return audit.Actor{Type: audit.ActorSystem, ID: s.schedulerID}
}

// clockNow 返回截断到 UTC 毫秒的当前时间。
func (s *Scheduler) clockNow() time.Time {
	return s.now().UTC().Truncate(time.Millisecond)
}
