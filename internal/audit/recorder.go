package audit

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"time"
)

const (
	// DefaultFailureAuditTimeout 是业务失败后补写失败审计的独立事务期限。
	DefaultFailureAuditTimeout = 5 * time.Second
)

// AlarmKind 是运行告警类别。
type AlarmKind string

const (
	// AlarmAuditWriteFailed 表示安全审计写入失败；关键管理变更应被拒绝。
	AlarmAuditWriteFailed AlarmKind = "audit_write_failed"
)

// Alarm 是审计子系统触发的运行告警。它进入运行日志/监控，不替代安全审计。
type Alarm struct {
	Kind      AlarmKind
	Operation string
	Cause     error
}

// Alerter 接收审计故障告警。实现应把告警送到运维监控或被可靠记录；默认实现
// 使用结构化运行日志的 Error 级别。
type Alerter interface {
	Alarm(ctx context.Context, alarm Alarm)
}

// AlerterFunc 把函数适配为 Alerter。
type AlerterFunc func(ctx context.Context, alarm Alarm)

// Alarm 实现 Alerter。
func (f AlerterFunc) Alarm(ctx context.Context, alarm Alarm) {
	f(ctx, alarm)
}

// Options 是构造 Recorder 的依赖。
type Options struct {
	// Store 是审计持久化；必填。
	Store Store
	// Logger 是运行日志器；nil 使用丢弃输出。日志与安全审计是两套数据，不能
	// 把运行日志当作审计事件。
	Logger *slog.Logger
	// Alerter 接收审计写入故障告警；nil 时使用 Logger 的 Error 级别输出。
	Alerter Alerter
	// Now 是可注入时钟；nil 使用 time.Now。事件时间统一截断到 UTC 毫秒。
	Now func() time.Time
	// Random 是安全随机源，用于生成事件 ID；nil 使用 crypto/rand.Reader。
	Random io.Reader
	// FailureAuditTimeout 是业务失败后补写失败审计的时限；0 使用默认值。
	FailureAuditTimeout time.Duration
}

// Recorder 是安全审计写入器。构造后不可变，可被多个 goroutine 并发使用；它不
// 启动后台协程、不提供查询/导出接口，也不缓存待写事件。
type Recorder struct {
	store          Store
	logger         *slog.Logger
	alerter        Alerter
	now            func() time.Time
	random         io.Reader
	failureTimeout time.Duration
}

// New 创建审计写入器。store 为空、失败审计时限不合法时返回 ErrOptionsInvalid；
// 不会创建默认存储或静默丢弃审计。
func New(store Store, options Options) (*Recorder, error) {
	if isNilStore(store) {
		return nil, fmt.Errorf("%w: 审计存储为空", ErrOptionsInvalid)
	}
	logger := options.Logger
	if logger == nil {
		logger = discardLogger()
	}
	alerter := options.Alerter
	if alerter == nil {
		alerter = loggerAlerter{logger: logger}
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	random := options.Random
	if random == nil {
		random = rand.Reader
	}
	failureTimeout := options.FailureAuditTimeout
	if failureTimeout == 0 {
		failureTimeout = DefaultFailureAuditTimeout
	}
	if failureTimeout < 0 || failureTimeout > time.Minute {
		return nil, fmt.Errorf("%w: 失败审计期限必须在 0～60 秒之间", ErrOptionsInvalid)
	}
	return &Recorder{
		store:          store,
		logger:         logger,
		alerter:        alerter,
		now:            now,
		random:         random,
		failureTimeout: failureTimeout,
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

// discardLogger 返回写入丢弃输出的日志器。
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

// loggerAlerter 用运行日志 Error 级别发出审计故障告警。
type loggerAlerter struct {
	logger *slog.Logger
}

// Alarm 实现 Alerter。
func (a loggerAlerter) Alarm(_ context.Context, alarm Alarm) {
	a.logger.Error("安全审计写入失败告警",
		"alarm_kind", string(alarm.Kind),
		"operation", alarm.Operation,
		"error", alarm.Cause,
	)
}

// Record 在独立事务中追加一条审计事件。事件 ID 为空时自动生成，发生时间由
// 注入时钟覆盖。dedupe_key 已存在时返回 ErrDuplicateEvent（调用方可按幂等处理）；
// 存储失败返回 ErrAuditUnavailable 并触发告警。
func (r *Recorder) Record(ctx context.Context, event Event) error {
	return r.recordEvent(ctx, event, false)
}

// RecordFailure 可靠地记录失败尝试：使用不受调用方取消影响的独立事务与有限
// 期限，因此业务事务回滚或请求取消后失败审计仍会保存。失败时返回
// ErrAuditUnavailable 并触发告警；它绝不把失败包装成成功。
func (r *Recorder) RecordFailure(ctx context.Context, event Event) error {
	return r.recordEvent(ctx, event, true)
}

// recordEvent 实现 Record/RecordFailure 的共同流程。
func (r *Recorder) recordEvent(ctx context.Context, event Event, reliable bool) error {
	ctx = normalizeContext(ctx)
	if !reliable {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	prepared, err := r.prepareEvent(event, event.Outcome, r.clockNow())
	if err != nil {
		return err
	}
	return r.appendEvent(ctx, prepared, reliable)
}

// appendEvent 调用存储追加事件并统一处理重复、取消与告警。
func (r *Recorder) appendEvent(ctx context.Context, event Event, reliable bool) error {
	appendCtx := ctx
	if reliable {
		base := context.WithoutCancel(ctx)
		var cancel context.CancelFunc
		appendCtx, cancel = context.WithTimeout(base, r.failureTimeout)
		defer cancel()
	}
	err := r.store.Append(appendCtx, event)
	if err == nil {
		r.logger.Debug("安全审计事件已写入",
			"event_id", event.ID,
			"action", event.Action,
			"actor_type", string(event.Actor.Type),
			"outcome", string(event.Outcome),
		)
		return nil
	}
	if errors.Is(err, ErrDuplicateEvent) {
		r.logger.Info("安全审计事件重复，按幂等处理",
			"event_id", event.ID,
			"action", event.Action,
			"dedupe_key", event.DedupeKey,
		)
		return err
	}
	if !reliable {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
	}
	r.raiseAlarm(ctx, Alarm{Kind: AlarmAuditWriteFailed, Operation: "append", Cause: err})
	return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
}

// CriticalRequest 描述一次关键管理变更的审计事件模板。
//
// Event 中 Outcome 会被覆盖为 success/failure；Changes 在写入前脱敏；建议设置
// 稳定的 DedupeKey，使重复提交（例如网络重试）不会重复执行变更或重复记录。
type CriticalRequest struct {
	// Event 是审计事件模板（身份、应用快照、动作、目标、request/task、差异与
	// 幂等键）。
	Event Event
	// FailureErrorCode 是业务失败时记录的对外错误码（可选，大写错误码）。
	FailureErrorCode string
	// FailureReasonCode 是业务失败时记录的受限内部原因码（可选）。
	FailureReasonCode string
}

// Change 是关键变更回调。它在 Store 提供的事务中执行自己的参数化 SQL；返回
// 错误时整个事务回滚，由 Recorder 补写失败审计。
type Change func(ctx context.Context, tx Tx) error

// ExecuteCritical 在同一个数据库事务中执行关键变更并写入成功审计事件。
//
//   - 变更与成功审计一致提交；成功审计写入失败时业务变更回滚，返回
//     ErrAuditUnavailable（对外映射 AUDIT_WRITE_FAILED）并触发告警。
//   - 变更失败时业务回滚，随后用独立事务写入 failure 审计并返回原业务错误；
//     失败审计写入也失败时用 errors.Join 返回两个错误并告警。
//   - DedupeKey 已存在时不执行 change，返回 ErrDuplicateEvent，保证幂等重试。
//
// 注意：失败审计的独立写入使用 context.WithoutCancel + FailureAuditTimeout，
// 因此调用方取消不会丢失败证据；调用方不应在失败后自行重试 change，除非确认
// 使用新的幂等键。
func (r *Recorder) ExecuteCritical(ctx context.Context, request CriticalRequest, change Change) error {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	if change == nil {
		return fmt.Errorf("%w: 关键变更回调为空", ErrInvalidEvent)
	}
	currentTime := r.clockNow()
	successEvent, err := r.prepareEvent(request.Event, OutcomeSuccess, currentTime)
	if err != nil {
		return err
	}
	failureSpec := request.Event
	failureSpec.Outcome = OutcomeFailure
	failureSpec.ErrorCode = request.FailureErrorCode
	failureSpec.ReasonCode = request.FailureReasonCode
	failureSpec.DedupeKey = ""
	if _, err := r.prepareEvent(failureSpec, OutcomeFailure, currentTime); err != nil {
		return err
	}

	runErr := r.store.RunCritical(ctx, successEvent, change)
	if runErr == nil {
		r.logger.Info("关键管理变更与安全审计已一致提交",
			"event_id", successEvent.ID,
			"action", successEvent.Action,
			"actor_type", string(successEvent.Actor.Type),
		)
		return nil
	}
	if errors.Is(runErr, ErrDuplicateEvent) {
		r.logger.Info("关键管理变更幂等重放，未重复执行",
			"action", successEvent.Action,
			"dedupe_key", successEvent.DedupeKey,
		)
		return ErrDuplicateEvent
	}
	auditFailure := errors.Is(runErr, ErrAuditUnavailable)
	// 即使请求被取消，也要用独立事务补写失败审计：取消属于失败路径，不能因为
	// 调用方 context 结束而丢失“失败可追踪”的证据。
	failureEvent, err := r.prepareEvent(failureSpec, OutcomeFailure, r.clockNow())
	if err != nil {
		// 字段在进入事务前已校验；这里只有时钟/随机源异常等极端情况。
		r.raiseAlarm(ctx, Alarm{Kind: AlarmAuditWriteFailed, Operation: "critical_failure_event", Cause: err})
		return errors.Join(runErr, err)
	}
	failureErr := r.appendEvent(ctx, failureEvent, true)
	if auditFailure {
		r.raiseAlarm(ctx, Alarm{Kind: AlarmAuditWriteFailed, Operation: "critical_change", Cause: runErr})
	}
	if failureErr != nil {
		return errors.Join(runErr, failureErr)
	}
	return runErr
}

// prepareEvent 填充事件 ID 与发生时间并规范化事件。
func (r *Recorder) prepareEvent(event Event, outcome Outcome, occurredAt time.Time) (Event, error) {
	if event.ID == "" {
		id, err := newEventID(r.random)
		if err != nil {
			return Event{}, err
		}
		event.ID = id
	}
	event.OccurredAt = occurredAt
	event.Outcome = outcome
	return NormalizeEvent(event)
}

// clockNow 返回截断到 UTC 毫秒的当前时间。
func (r *Recorder) clockNow() time.Time {
	return r.now().UTC().Truncate(time.Millisecond)
}

// raiseAlarm 触发运行告警；告警实现自身的 panic 不应让审计调用崩溃。
func (r *Recorder) raiseAlarm(ctx context.Context, alarm Alarm) {
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				r.logger.Error("安全审计告警处理器 panic", "panic", recovered)
			}
		}()
		r.alerter.Alarm(ctx, alarm)
	}()
}

// defaultRandomReader 已由 crypto/rand.Reader 直接使用，避免额外间接层。
// normalizeContext 把 nil ctx 当成 Background，避免调用方漏传时 panic。
func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
