package sqlite_test

import (
	"context"
	"database/sql"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
	tasksqlite "github.com/kagurazakayashi/EvernightLogin/internal/task/sqlite"
)

// fakeClock 是并发安全的确定性时钟；调度器、执行器与存储共用同一时钟，测试
// 不等待真实时间。
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

// newFakeClock 构造从指定时刻开始的时钟。
func newFakeClock(start time.Time) *fakeClock {
	return &fakeClock{now: start.UTC()}
}

// Now 返回当前假时间（截断到毫秒，与生产时钟约定一致）。
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Set 设置当前假时间。
func (c *fakeClock) Set(moment time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = moment.UTC()
}

// Advance 前进指定时长。
func (c *fakeClock) Advance(delta time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(delta)
}

// openTestStoreWithClock 创建临时数据库，并用指定时钟构造任务/计划存储。
func openTestStoreWithClock(t *testing.T, clock *fakeClock) (*storagesqlite.Store, *tasksqlite.Store) {
	t.Helper()
	raw := openTestDatabase(t)
	store, err := tasksqlite.New(raw, tasksqlite.Options{Now: clock.Now})
	if err != nil {
		t.Fatalf("构造任务存储失败: %v", err)
	}
	return raw, store
}

// newClockExecutor 构造使用确定性时钟的执行器。
func newClockExecutor(t *testing.T, store task.Store, handlers map[string]task.Handler, maxConcurrent int, clock *fakeClock, mutate func(*task.Options)) *task.Executor {
	t.Helper()
	options := task.Options{
		Handlers:        handlers,
		ExecutorID:      "exec-test-1",
		MaxConcurrent:   maxConcurrent,
		PollInterval:    task.MinPollInterval,
		ShutdownTimeout: 3 * time.Second,
		Now:             clock.Now,
	}
	if mutate != nil {
		mutate(&options)
	}
	executor, err := task.New(store, options)
	if err != nil {
		t.Fatalf("构造执行器失败: %v", err)
	}
	return executor
}

// newTestScheduler 构造使用确定性时钟的调度器。
func newTestScheduler(t *testing.T, store task.ScheduleStore, executor *task.Executor, clock *fakeClock, check task.PermissionCheck) *task.Scheduler {
	t.Helper()
	scheduler, err := task.NewScheduler(task.SchedulerOptions{
		Store:           store,
		SchedulerID:     "sched-test-1",
		Executor:        executor,
		PermissionCheck: check,
		Now:             clock.Now,
	})
	if err != nil {
		t.Fatalf("构造调度器失败: %v", err)
	}
	return scheduler
}

// scheduleOwner 是测试计划的创建者。
func scheduleOwner() audit.Actor {
	return audit.Actor{Type: audit.ActorUser, ID: "user-owner-1"}
}

// scheduleExecutionActor 是测试计划的执行身份。
func scheduleExecutionActor() audit.Actor {
	return audit.Actor{Type: audit.ActorUser, ID: "user-exec-1"}
}

// schedulerSystemActor 是调度器记录触发时使用的系统身份。
func schedulerSystemActor() audit.Actor {
	return audit.Actor{Type: audit.ActorSystem, ID: "sched-test-1"}
}

// dailyRequest 构造每天固定时刻的计划创建请求。
func dailyRequest(kind, expression, timeZone string, policy task.MissedPolicy, permissionExempt bool) task.NewScheduleRequest {
	return task.NewScheduleRequest{
		JobKind:          kind,
		ScheduleType:     task.ScheduleTypeDaily,
		Expression:       expression,
		TimeZone:         timeZone,
		Owner:            scheduleOwner(),
		ExecutionActor:   scheduleExecutionActor(),
		Enabled:          true,
		PermissionExempt: permissionExempt,
		MissedPolicy:     policy,
		TimeoutSeconds:   30,
		MaxAttempts:      1,
	}
}

// mustCreateSchedule 创建计划，失败终止测试。
func mustCreateSchedule(t *testing.T, scheduler *task.Scheduler, request task.NewScheduleRequest) task.Schedule {
	t.Helper()
	schedule, err := scheduler.Create(context.Background(), request)
	if err != nil {
		t.Fatalf("创建计划失败: %v", err)
	}
	return schedule
}

// queryString 查询单行单列文本；无行返回空字符串。
func queryString(t *testing.T, raw *storagesqlite.Store, query string, args ...any) string {
	t.Helper()
	rows, err := raw.QueryContext(context.Background(), query, args...)
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			t.Fatalf("查询失败: %v", err)
		}
		return ""
	}
	var value string
	if err := rows.Scan(&value); err != nil {
		t.Fatalf("扫描失败: %v", err)
	}
	return value
}

// countJobsByKind 统计指定任务类型的任务数量。
func countJobsByKind(t *testing.T, raw *storagesqlite.Store, kind string) int {
	t.Helper()
	return queryInt(t, raw, `SELECT COUNT(*) FROM jobs WHERE kind=?`, kind)
}

// countAuditAction 统计指定动作的审计事件数量。
func countAuditAction(t *testing.T, raw *storagesqlite.Store, action string) int {
	t.Helper()
	return queryInt(t, raw, `SELECT COUNT(*) FROM audit_events WHERE action=?`, action)
}

// queryStates 返回指定任务类型的任务状态摘要，仅用于失败诊断。
func queryStates(t *testing.T, raw *storagesqlite.Store, kind string) string {
	t.Helper()
	rows, err := raw.QueryContext(context.Background(),
		`SELECT id,state,error_code FROM jobs WHERE kind=? ORDER BY created_at_ms`, kind)
	if err != nil {
		return err.Error()
	}
	defer rows.Close()
	summary := ""
	for rows.Next() {
		var id, state string
		var errorCode sql.NullString
		if err := rows.Scan(&id, &state, &errorCode); err != nil {
			return err.Error()
		}
		summary += id + "=" + state + "/" + errorCode.String + ";"
	}
	return summary
}

// waitJobsSettled 等待指定任务类型的任务全部离开 queued/running/cancel_requested。
func waitJobsSettled(t *testing.T, raw *storagesqlite.Store, kind string) {
	t.Helper()
	waitCondition(t, "任务全部执行完成", func() bool {
		return queryInt(t, raw,
			`SELECT COUNT(*) FROM jobs WHERE kind=? AND state IN('queued','running','cancel_requested')`, kind) == 0
	})
}

// TestSchedulerFiresDailyAndDeduplicates 验证日计划准点触发、同一触发时刻去重、
// 直接重复写入被唯一键拒绝，以及触发后任务真实执行。
func TestSchedulerFiresDailyAndDeduplicates(t *testing.T) {
	clock := newFakeClock(time.Date(2021, 4, 25, 4, 0, 0, 0, time.UTC)) // 上海 12:00
	raw, store := openTestStoreWithClock(t, clock)
	executor := newClockExecutor(t, store, map[string]task.Handler{
		"test.daily": func(context.Context, task.Job) error { return nil },
	}, 2, clock, nil)
	startExecutor(t, executor)
	scheduler := newTestScheduler(t, store, executor, clock, nil)
	schedule := mustCreateSchedule(t, scheduler, dailyRequest("test.daily", "02:30", "Asia/Shanghai", task.MissedSkip, true))

	ctx := context.Background()
	if err := scheduler.Tick(ctx); err != nil {
		t.Fatalf("首次 Tick 失败: %v", err)
	}
	if got := countJobsByKind(t, raw, "test.daily"); got != 0 {
		t.Fatalf("未到触发时刻不应入队，实际 %d", got)
	}

	due := time.Date(2021, 4, 25, 18, 30, 0, 0, time.UTC) // 上海次日 02:30
	clock.Set(due)
	if err := scheduler.Tick(ctx); err != nil {
		t.Fatalf("到期 Tick 失败: %v", err)
	}
	if got := countJobsByKind(t, raw, "test.daily"); got != 1 {
		t.Fatalf("到期应入队 1 个任务，实际 %d", got)
	}
	jobID := queryString(t, raw, `SELECT id FROM jobs WHERE kind=?`, "test.daily")
	waitForState(t, executor, jobID, task.StateSucceeded)
	attempts, err := executor.Attempts(ctx, jobID)
	if err != nil {
		t.Fatalf("读取尝试历史失败: %v", err)
	}
	if len(attempts) != 1 || attempts[0].Outcome != string(task.StateSucceeded) {
		t.Fatalf("尝试历史 = %+v，期望一次成功尝试", attempts)
	}

	// 同一触发时刻再次 Tick 不得重复入队。
	if err := scheduler.Tick(ctx); err != nil {
		t.Fatalf("重复 Tick 失败: %v", err)
	}
	if got := countJobsByKind(t, raw, "test.daily"); got != 1 {
		t.Fatalf("重复触发不应再入队，实际 %d", got)
	}
	if got := queryInt(t, raw, `SELECT COUNT(*) FROM schedule_firings WHERE schedule_id=?`, schedule.ID); got != 1 {
		t.Fatalf("触发记录 = %d，期望 1", got)
	}

	// 直接重复写入同一 (计划, 触发时刻) 必须被唯一键拒绝且不产生任务。
	duplicate := task.NewJob{
		ID:             mustJobID(t),
		Kind:           "test.daily",
		Initiator:      scheduleOwner(),
		Payload:        []byte(`{}`),
		TimeoutSeconds: 30,
		MaxAttempts:    1,
		CreatedAt:      clock.Now(),
	}
	result, err := store.FireSchedule(ctx, task.FireCommand{
		ScheduleID:  schedule.ID,
		ScheduledAt: due,
		Job:         &duplicate,
		Outcome:     task.FireEnqueued,
		Actor:       schedulerSystemActor(),
		Now:         clock.Now(),
	})
	if err != nil {
		t.Fatalf("重复触发写入返回错误: %v", err)
	}
	if result.Fired {
		t.Fatal("重复触发不应被接受")
	}
	if got := countJobsByKind(t, raw, "test.daily"); got != 1 {
		t.Fatalf("重复触发不应新增任务，实际 %d", got)
	}

	// 次日准点继续触发。
	clock.Set(due.Add(24 * time.Hour))
	if err := scheduler.Tick(ctx); err != nil {
		t.Fatalf("次日 Tick 失败: %v", err)
	}
	if got := countJobsByKind(t, raw, "test.daily"); got != 2 {
		t.Fatalf("次日应再入队 1 个任务，实际 %d", got)
	}
	if got := countAuditAction(t, raw, "schedules.fired"); got != 2 {
		t.Fatalf("schedules.fired 审计 = %d，期望 2", got)
	}
	waitJobsSettled(t, raw, "test.daily")
}

// TestSchedulerCatchUpPolicies 验证停机错过触发的 skip/latest/all 策略与单次补跑
// 上限：skip 不补跑、latest 只补最近一次、all 按上限有界补跑。
func TestSchedulerCatchUpPolicies(t *testing.T) {
	clock := newFakeClock(time.Date(2021, 4, 25, 4, 0, 0, 0, time.UTC)) // 上海 12:00
	raw, store := openTestStoreWithClock(t, clock)
	handlers := map[string]task.Handler{
		"test.skip":   func(context.Context, task.Job) error { return nil },
		"test.latest": func(context.Context, task.Job) error { return nil },
		"test.all":    func(context.Context, task.Job) error { return nil },
		"test.bound":  func(context.Context, task.Job) error { return nil },
	}
	executor := newClockExecutor(t, store, handlers, 2, clock, nil)
	startExecutor(t, executor)
	scheduler := newTestScheduler(t, store, executor, clock, nil)

	mustCreateSchedule(t, scheduler, dailyRequest("test.skip", "02:30", "Asia/Shanghai", task.MissedSkip, true))
	mustCreateSchedule(t, scheduler, dailyRequest("test.latest", "02:30", "Asia/Shanghai", task.MissedLatest, true))
	mustCreateSchedule(t, scheduler, dailyRequest("test.all", "02:30", "Asia/Shanghai", task.MissedAll, true))
	boundRequest := dailyRequest("test.bound", "02:30", "Asia/Shanghai", task.MissedAll, true)
	boundRequest.MaxCatchUp = 2
	mustCreateSchedule(t, scheduler, boundRequest)

	// 停机 3 天：错过 4 月 26/27/28 日 02:30 三次触发。
	clock.Set(time.Date(2021, 4, 28, 4, 0, 0, 0, time.UTC))
	if err := scheduler.Tick(context.Background()); err != nil {
		t.Fatalf("补跑 Tick 失败: %v", err)
	}
	if got := countJobsByKind(t, raw, "test.skip"); got != 0 {
		t.Fatalf("skip 策略不应补跑，实际 %d", got)
	}
	if got := countAuditAction(t, raw, "schedules.skipped"); got == 0 {
		t.Fatal("skip 策略应记录跳过审计")
	}
	if got := countJobsByKind(t, raw, "test.latest"); got != 1 {
		t.Fatalf("latest 策略应只补跑 1 次，实际 %d", got)
	}
	if got := countJobsByKind(t, raw, "test.all"); got != 3 {
		t.Fatalf("all 策略应补跑 3 次，实际 %d", got)
	}
	if got := countJobsByKind(t, raw, "test.bound"); got != 2 {
		t.Fatalf("单次补跑上限应限制为 2，实际 %d", got)
	}
	// 有界补跑在后续 Tick 继续追赶剩余触发。
	if err := scheduler.Tick(context.Background()); err != nil {
		t.Fatalf("第二次补跑 Tick 失败: %v", err)
	}
	if got := countJobsByKind(t, raw, "test.bound"); got != 3 {
		t.Fatalf("上限之后的剩余触发应继续补跑，实际 %d", got)
	}
	// 再次 Tick 不应重复补跑。
	if err := scheduler.Tick(context.Background()); err != nil {
		t.Fatalf("第三次 Tick 失败: %v", err)
	}
	if got := countJobsByKind(t, raw, "test.latest"); got != 1 {
		t.Fatalf("latest 策略不应重复补跑，实际 %d", got)
	}

	// 次日准点：skip 恢复正常触发，latest 继续追加一次。
	clock.Set(time.Date(2021, 4, 28, 18, 30, 0, 0, time.UTC))
	if err := scheduler.Tick(context.Background()); err != nil {
		t.Fatalf("次日准点 Tick 失败: %v", err)
	}
	if got := countJobsByKind(t, raw, "test.skip"); got != 1 {
		t.Fatalf("skip 策略次日准点应触发 1 次，实际 %d", got)
	}
	if got := countJobsByKind(t, raw, "test.latest"); got != 2 {
		t.Fatalf("latest 策略次日准点应追加 1 次，实际 %d", got)
	}
	for _, kind := range []string{"test.skip", "test.latest", "test.all", "test.bound"} {
		waitJobsSettled(t, raw, kind)
	}
}

// TestSchedulerRestartCatchUp 验证调度器重启后从持久化游标继续补跑，且不重复
// 触发已记录的时刻。
func TestSchedulerRestartCatchUp(t *testing.T) {
	clock := newFakeClock(time.Date(2021, 4, 25, 4, 0, 0, 0, time.UTC))
	raw, store := openTestStoreWithClock(t, clock)
	executor := newClockExecutor(t, store, map[string]task.Handler{
		"test.restart": func(context.Context, task.Job) error { return nil },
	}, 2, clock, nil)
	startExecutor(t, executor)
	scheduler := newTestScheduler(t, store, executor, clock, nil)
	mustCreateSchedule(t, scheduler, dailyRequest("test.restart", "02:30", "Asia/Shanghai", task.MissedAll, true))

	ctx := context.Background()
	clock.Set(time.Date(2021, 4, 25, 18, 30, 0, 0, time.UTC))
	if err := scheduler.Tick(ctx); err != nil {
		t.Fatalf("首次 Tick 失败: %v", err)
	}
	if got := countJobsByKind(t, raw, "test.restart"); got != 1 {
		t.Fatalf("首次触发应有 1 个任务，实际 %d", got)
	}

	// 模拟进程重启：新的调度器实例共享同一存储，从持久化游标继续。
	restarted, err := task.NewScheduler(task.SchedulerOptions{
		Store:       store,
		SchedulerID: "sched-test-2",
		Executor:    executor,
		Now:         clock.Now,
	})
	if err != nil {
		t.Fatalf("重启调度器失败: %v", err)
	}
	clock.Set(time.Date(2021, 4, 27, 18, 30, 0, 0, time.UTC)) // 错过 4 月 26、27 日两次
	if err := restarted.Tick(ctx); err != nil {
		t.Fatalf("重启补跑失败: %v", err)
	}
	if got := countJobsByKind(t, raw, "test.restart"); got != 3 {
		t.Fatalf("重启后应补跑 2 次，任务总数期望 3，实际 %d", got)
	}
	// 重复 Tick 与原调度器再 Tick 都不得重复触发。
	if err := restarted.Tick(ctx); err != nil {
		t.Fatalf("重启后重复 Tick 失败: %v", err)
	}
	if err := scheduler.Tick(ctx); err != nil {
		t.Fatalf("原调度器 Tick 失败: %v", err)
	}
	if got := countJobsByKind(t, raw, "test.restart"); got != 3 {
		t.Fatalf("重复 Tick 不应新增任务，实际 %d", got)
	}
	if got := queryInt(t, raw, `SELECT COUNT(*) FROM schedule_firings`); got != 3 {
		t.Fatalf("触发记录 = %d，期望 3", got)
	}
	waitJobsSettled(t, raw, "test.restart")
}

// TestSchedulerTimeZoneAndDST 验证跨时区准点触发与夏令时缺口通过调度器真实
// 入队（缺口日顺延到跳变后的首个有效瞬间）。
func TestSchedulerTimeZoneAndDST(t *testing.T) {
	clock := newFakeClock(time.Date(2021, 4, 24, 12, 0, 0, 0, time.UTC))
	raw, store := openTestStoreWithClock(t, clock)
	executor := newClockExecutor(t, store, map[string]task.Handler{
		"test.tokyo": func(context.Context, task.Job) error { return nil },
		"test.dst":   func(context.Context, task.Job) error { return nil },
	}, 2, clock, nil)
	startExecutor(t, executor)
	scheduler := newTestScheduler(t, store, executor, clock, nil)
	ctx := context.Background()

	// 东京 09:00 对应 UTC 00:00。
	mustCreateSchedule(t, scheduler, dailyRequest("test.tokyo", "09:00", "Asia/Tokyo", task.MissedSkip, true))
	clock.Set(time.Date(2021, 4, 25, 0, 0, 0, 0, time.UTC))
	if err := scheduler.Tick(ctx); err != nil {
		t.Fatalf("东京计划 Tick 失败: %v", err)
	}
	if got := countJobsByKind(t, raw, "test.tokyo"); got != 1 {
		t.Fatalf("跨时区准点应触发 1 次，实际 %d", got)
	}

	// 纽约 2021-03-14 02:30 不存在：应在 03:00 EDT（07:00 UTC）触发。
	clock.Set(time.Date(2021, 3, 13, 12, 0, 0, 0, time.UTC))
	mustCreateSchedule(t, scheduler, dailyRequest("test.dst", "02:30", "America/New_York", task.MissedSkip, true))
	clock.Set(time.Date(2021, 3, 14, 6, 30, 0, 0, time.UTC)) // 01:30 EST，尚未到顺延时刻
	if err := scheduler.Tick(ctx); err != nil {
		t.Fatalf("DST 未到点 Tick 失败: %v", err)
	}
	if got := countJobsByKind(t, raw, "test.dst"); got != 0 {
		t.Fatalf("DST 缺口未到跳变瞬间不应触发，实际 %d", got)
	}
	clock.Set(time.Date(2021, 3, 14, 7, 0, 0, 0, time.UTC)) // 03:00 EDT
	if err := scheduler.Tick(ctx); err != nil {
		t.Fatalf("DST 到点 Tick 失败: %v", err)
	}
	if got := countJobsByKind(t, raw, "test.dst"); got != 1 {
		t.Fatalf("DST 缺口应在 03:00 触发，实际 %d", got)
	}
	if err := scheduler.Tick(ctx); err != nil {
		t.Fatalf("DST 重复 Tick 失败: %v", err)
	}
	if got := countJobsByKind(t, raw, "test.dst"); got != 1 {
		t.Fatalf("DST 触发不得重复，实际 %d", got)
	}
	waitJobsSettled(t, raw, "test.tokyo")
	waitJobsSettled(t, raw, "test.dst")
}

// TestSchedulerPermissionRevalidation 验证运行前权限复验：拒绝时不入队并记录
// denied 审计，恢复权限后才触发；缺少回调时默认拒绝。
func TestSchedulerPermissionRevalidation(t *testing.T) {
	clock := newFakeClock(time.Date(2021, 4, 25, 4, 0, 0, 0, time.UTC))
	raw, store := openTestStoreWithClock(t, clock)
	var allow atomic.Bool
	check := func(context.Context, task.PermissionRequest) error {
		if allow.Load() {
			return nil
		}
		return errors.New("执行身份权限已撤销")
	}
	executor := newClockExecutor(t, store, map[string]task.Handler{
		"test.manage": func(context.Context, task.Job) error { return nil },
	}, 2, clock, func(options *task.Options) {
		options.PermissionCheck = check
	})
	startExecutor(t, executor)
	scheduler := newTestScheduler(t, store, executor, clock, check)
	schedule := mustCreateSchedule(t, scheduler, dailyRequest("test.manage", "02:30", "Asia/Shanghai", task.MissedSkip, false))

	ctx := context.Background()
	due := time.Date(2021, 4, 25, 18, 30, 0, 0, time.UTC)
	clock.Set(due)
	if err := scheduler.Tick(ctx); err != nil {
		t.Fatalf("权限拒绝 Tick 失败: %v", err)
	}
	if got := countJobsByKind(t, raw, "test.manage"); got != 0 {
		t.Fatalf("权限撤销时不应入队任务，实际 %d", got)
	}
	if got := countAuditAction(t, raw, "schedules.denied"); got != 1 {
		t.Fatalf("应记录 1 次 denied 审计，实际 %d", got)
	}
	if outcome := queryString(t, raw, `SELECT outcome FROM schedule_firings WHERE schedule_id=?`, schedule.ID); outcome != string(task.FireDenied) {
		t.Fatalf("触发结果 = %q，期望 denied", outcome)
	}

	// 恢复权限后下一次触发成功入队并由执行器复验通过后执行。
	allow.Store(true)
	clock.Set(due.Add(24 * time.Hour))
	if err := scheduler.Tick(ctx); err != nil {
		t.Fatalf("权限恢复 Tick 失败: %v", err)
	}
	waitJobsSettled(t, raw, "test.manage")
	jobID := queryString(t, raw, `SELECT id FROM jobs WHERE kind='test.manage'`)
	if jobID == "" {
		t.Fatal("权限恢复后应创建任务")
	}
	job, err := executor.Get(ctx, jobID)
	if err != nil {
		t.Fatalf("读取任务失败: %v", err)
	}
	if job.State != task.StateSucceeded {
		t.Fatalf("权限复验通过后任务状态 = %s，期望 succeeded", job.State)
	}

	// 计划要求权限但调度器没有可信回调时：创建被拒绝（默认拒绝）。
	noCheckScheduler := newTestScheduler(t, store, executor, clock, nil)
	if _, err := noCheckScheduler.Create(ctx, dailyRequest("test.manage", "02:30", "Asia/Shanghai", task.MissedSkip, false)); !errors.Is(err, task.ErrPermissionCheckRequired) {
		t.Fatalf("缺少权限回调创建错误 = %v，期望 ErrPermissionCheckRequired", err)
	}
	// 直接写入数据库的计划（例如旧数据/其他进程）在缺少回调时也必须拒绝触发。
	rawScheduleID, err := task.NewScheduleID()
	if err != nil {
		t.Fatalf("生成计划编号失败: %v", err)
	}
	rawSchedule := task.NewSchedule{
		ID:                 rawScheduleID,
		JobKind:            "test.manage",
		ScheduleType:       task.ScheduleTypeDaily,
		Expression:         "02:30",
		TimeZone:           "Asia/Shanghai",
		Owner:              scheduleOwner(),
		ExecutionActor:     scheduleExecutionActor(),
		ScopeID:            "system",
		Enabled:            true,
		PermissionRequired: true,
		MissedPolicy:       task.MissedSkip,
		MaxCatchUp:         task.DefaultScheduleMaxCatchUp,
		Payload:            []byte(`{}`),
		TimeoutSeconds:     30,
		MaxAttempts:        1,
		CreatedAt:          clock.Now(),
	}
	stored, err := store.CreateSchedule(ctx, rawSchedule)
	if err != nil {
		t.Fatalf("直接创建计划失败: %v", err)
	}
	clock.Set(clock.Now().Add(24 * time.Hour))
	if err := noCheckScheduler.Tick(ctx); err != nil {
		t.Fatalf("缺少回调 Tick 失败: %v", err)
	}
	if got := countJobsByKind(t, raw, "test.manage"); got != 1 {
		t.Fatalf("缺少回调时不得新增任务，实际 %d", got)
	}
	if outcome := queryString(t, raw, `SELECT outcome FROM schedule_firings WHERE schedule_id=?`, stored.ID); outcome != string(task.FireDenied) {
		t.Fatalf("缺少回调触发结果 = %q，期望 denied", outcome)
	}
}

// TestSchedulerPauseResumeDeleteSemantics 验证暂停/恢复/删除计划不取消已入队或
// 运行中的任务，恢复后不补跑暂停期间触发，删除只停止后续触发。
func TestSchedulerPauseResumeDeleteSemantics(t *testing.T) {
	clock := newFakeClock(time.Date(2021, 4, 25, 4, 0, 0, 0, time.UTC))
	raw, store := openTestStoreWithClock(t, clock)
	gateA := make(chan struct{})
	gateB := make(chan struct{})
	blockingHandler := func(gate <-chan struct{}) task.Handler {
		return func(ctx context.Context, _ task.Job) error {
			select {
			case <-gate:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	executor := newClockExecutor(t, store, map[string]task.Handler{
		"test.pause.a":  blockingHandler(gateA),
		"test.delete.b": blockingHandler(gateB),
	}, 2, clock, nil)
	startExecutor(t, executor)
	scheduler := newTestScheduler(t, store, executor, clock, nil)
	ctx := context.Background()

	// 阶段一：暂停不取消正在运行的任务，恢复后不补跑暂停期间触发。
	pauseRequest := dailyRequest("test.pause.a", "02:30", "Asia/Shanghai", task.MissedSkip, true)
	pauseRequest.TimeoutSeconds = task.MaxTimeoutSeconds // 假时钟前进时仍视为未超时
	scheduleA := mustCreateSchedule(t, scheduler, pauseRequest)
	due := time.Date(2021, 4, 25, 18, 30, 0, 0, time.UTC) // 上海次日 02:30
	clock.Set(due)
	if err := scheduler.Tick(ctx); err != nil {
		t.Fatalf("首次触发失败: %v", err)
	}
	jobA := queryString(t, raw, `SELECT id FROM jobs WHERE kind='test.pause.a'`)
	if jobA == "" {
		t.Fatal("首次触发应创建任务")
	}
	waitForState(t, executor, jobA, task.StateRunning)

	paused, err := scheduler.Pause(ctx, task.ScheduleStateCommand{
		ScheduleID: scheduleA.ID,
		Actor:      scheduleOwner(),
		Reason:     "维护窗口暂停",
	})
	if err != nil {
		t.Fatalf("暂停计划失败: %v", err)
	}
	if paused.Enabled {
		t.Fatal("暂停后 Enabled 应为 false")
	}
	if job, err := executor.Get(ctx, jobA); err != nil || job.State != task.StateRunning {
		t.Fatalf("暂停计划不应取消运行中任务: %v %v", job.State, err)
	}
	// 其他用户不能暂停/删除该计划。
	if _, err := scheduler.Pause(ctx, task.ScheduleStateCommand{
		ScheduleID: scheduleA.ID,
		Actor:      audit.Actor{Type: audit.ActorUser, ID: "user-other"},
		Reason:     "越权暂停",
	}); !errors.Is(err, task.ErrScheduleForbidden) {
		t.Fatalf("越权暂停错误 = %v，期望 ErrScheduleForbidden", err)
	}
	if err := scheduler.Delete(ctx, task.ScheduleDeleteCommand{
		ScheduleID: scheduleA.ID,
		Actor:      audit.Actor{Type: audit.ActorUser, ID: "user-other"},
		Reason:     "越权删除",
	}); !errors.Is(err, task.ErrScheduleForbidden) {
		t.Fatalf("越权删除错误 = %v，期望 ErrScheduleForbidden", err)
	}

	// 暂停期间即使到点也不触发。
	clock.Set(due.Add(time.Hour))
	if err := scheduler.Tick(ctx); err != nil {
		t.Fatalf("暂停期间 Tick 失败: %v", err)
	}
	if got := countJobsByKind(t, raw, "test.pause.a"); got != 1 {
		t.Fatalf("暂停期间不得新增任务，实际 %d", got)
	}
	// 恢复：以恢复时刻重新锚定，不补跑暂停期间触发。
	resumed, err := scheduler.Resume(ctx, task.ScheduleStateCommand{
		ScheduleID: scheduleA.ID,
		Actor:      scheduleOwner(),
		Reason:     "维护结束恢复",
	})
	if err != nil {
		t.Fatalf("恢复计划失败: %v", err)
	}
	if !resumed.Enabled {
		t.Fatal("恢复后 Enabled 应为 true")
	}
	close(gateA)
	waitForState(t, executor, jobA, task.StateSucceeded)
	// 恢复后的下一到期时刻正常触发。
	nextDue := time.Date(2021, 4, 26, 18, 30, 0, 0, time.UTC)
	clock.Set(nextDue)
	if err := scheduler.Tick(ctx); err != nil {
		t.Fatalf("恢复后 Tick 失败: %v", err)
	}
	if got := countJobsByKind(t, raw, "test.pause.a"); got != 2 {
		t.Fatalf("恢复后准点应新增 1 个任务，实际 %d", got)
	}
	waitJobsSettled(t, raw, "test.pause.a")
	if got := queryInt(t, raw, `SELECT COUNT(*) FROM jobs WHERE kind='test.pause.a' AND state='succeeded'`); got != 2 {
		t.Fatalf("暂停/恢复阶段任务应全部成功，实际 %d（状态：%s）", got, queryStates(t, raw, "test.pause.a"))
	}

	// 阶段二：删除计划不取消正在运行的任务，只停止后续触发。
	deleteRequest := dailyRequest("test.delete.b", "02:30", "Asia/Shanghai", task.MissedSkip, true)
	deleteRequest.TimeoutSeconds = task.MaxTimeoutSeconds
	scheduleB := mustCreateSchedule(t, scheduler, deleteRequest)
	// 创建时刻恰为 02:30；下一次严格晚于创建时刻的触发是次日同一时刻。
	clock.Set(time.Date(2021, 4, 27, 18, 30, 0, 0, time.UTC))
	if err := scheduler.Tick(ctx); err != nil {
		t.Fatalf("删除阶段触发失败: %v", err)
	}
	jobB := queryString(t, raw, `SELECT id FROM jobs WHERE kind='test.delete.b'`)
	if jobB == "" {
		t.Fatal("删除阶段应创建任务")
	}
	waitForState(t, executor, jobB, task.StateRunning)
	if err := scheduler.Delete(ctx, task.ScheduleDeleteCommand{
		ScheduleID: scheduleB.ID,
		Actor:      scheduleOwner(),
		Reason:     "计划下线",
	}); err != nil {
		t.Fatalf("删除计划失败: %v", err)
	}
	if _, err := scheduler.Get(ctx, scheduleB.ID); !errors.Is(err, task.ErrScheduleNotFound) {
		t.Fatalf("删除后查询错误 = %v，期望 ErrScheduleNotFound", err)
	}
	if job, err := executor.Get(ctx, jobB); err != nil || job.State != task.StateRunning {
		t.Fatalf("删除计划不应取消运行中任务: %v %v", job.State, err)
	}
	close(gateB)
	waitForState(t, executor, jobB, task.StateSucceeded)
	clock.Set(clock.Now().Add(7 * 24 * time.Hour))
	if err := scheduler.Tick(ctx); err != nil {
		t.Fatalf("删除后 Tick 失败: %v", err)
	}
	if got := countJobsByKind(t, raw, "test.delete.b"); got != 1 {
		t.Fatalf("删除计划后不得再触发，实际 %d", got)
	}
}

// TestSchedulerMutexKeySerializesExecution 验证同一互斥键的两个计划触发后，任务
// 不会并发执行。
func TestSchedulerMutexKeySerializesExecution(t *testing.T) {
	clock := newFakeClock(time.Date(2021, 4, 25, 4, 0, 0, 0, time.UTC))
	raw, store := openTestStoreWithClock(t, clock)
	var runningCount atomic.Int32
	var maxRunning atomic.Int32
	handler := func(context.Context, task.Job) error {
		current := runningCount.Add(1)
		for {
			observed := maxRunning.Load()
			if current <= observed || maxRunning.CompareAndSwap(observed, current) {
				break
			}
		}
		time.Sleep(30 * time.Millisecond)
		runningCount.Add(-1)
		return nil
	}
	executor := newClockExecutor(t, store, map[string]task.Handler{
		"test.lock": handler,
	}, 2, clock, nil)
	startExecutor(t, executor)
	scheduler := newTestScheduler(t, store, executor, clock, nil)

	first := dailyRequest("test.lock", "02:30", "Asia/Shanghai", task.MissedSkip, true)
	first.MutexKey = "shared-schedule-lock"
	mustCreateSchedule(t, scheduler, first)
	second := dailyRequest("test.lock", "02:30", "Asia/Shanghai", task.MissedSkip, true)
	second.MutexKey = "shared-schedule-lock"
	mustCreateSchedule(t, scheduler, second)

	clock.Set(time.Date(2021, 4, 25, 18, 30, 0, 0, time.UTC))
	if err := scheduler.Tick(context.Background()); err != nil {
		t.Fatalf("计划触发失败: %v", err)
	}
	if got := countJobsByKind(t, raw, "test.lock"); got != 2 {
		t.Fatalf("两个计划应各入队 1 个任务，实际 %d", got)
	}
	waitJobsSettled(t, raw, "test.lock")
	if got := queryInt(t, raw, `SELECT COUNT(*) FROM jobs WHERE kind='test.lock' AND state='succeeded'`); got != 2 {
		t.Fatalf("两个任务都应成功，实际 %d", got)
	}
	if got := maxRunning.Load(); got != 1 {
		t.Fatalf("相同互斥键的任务最大并发 = %d，期望 1", got)
	}
}

// TestSchedulerLifecycleNoLeakedGoroutines 验证调度器生命周期与后台 goroutine
// 在 Stop 后退出（测试结束不遗留后台任务）。
func TestSchedulerLifecycleNoLeakedGoroutines(t *testing.T) {
	clock := newFakeClock(time.Date(2021, 4, 25, 4, 0, 0, 0, time.UTC))
	_, store := openTestStoreWithClock(t, clock)
	scheduler, err := task.NewScheduler(task.SchedulerOptions{
		Store:        store,
		SchedulerID:  "sched-lifecycle",
		TickInterval: task.MinSchedulerTickInterval,
		Now:          clock.Now,
	})
	if err != nil {
		t.Fatalf("构造调度器失败: %v", err)
	}
	ctx := context.Background()
	// 先做一次查询让连接池 goroutine 进入稳定状态，再记录基线。
	if err := scheduler.Tick(ctx); err != nil {
		t.Fatalf("预热 Tick 失败: %v", err)
	}
	baseline := runtime.NumGoroutine()
	if err := scheduler.Start(ctx); err != nil {
		t.Fatalf("启动调度器失败: %v", err)
	}
	if err := scheduler.Start(ctx); !errors.Is(err, task.ErrAlreadyStarted) {
		t.Fatalf("重复启动错误 = %v，期望 ErrAlreadyStarted", err)
	}
	if err := scheduler.Stop(ctx); err != nil {
		t.Fatalf("停止调度器失败: %v", err)
	}
	if err := scheduler.Stop(ctx); err != nil {
		t.Fatalf("重复停止调度器失败: %v", err)
	}
	if err := scheduler.Start(ctx); !errors.Is(err, task.ErrClosed) {
		t.Fatalf("停止后启动错误 = %v，期望 ErrClosed", err)
	}
	waitCondition(t, "调度器 goroutine 退出", func() bool {
		return runtime.NumGoroutine() <= baseline
	})
}

// TestSchedulerMonthlyMonthEnd 验证月末语义经调度器真实生效：31 日在短月跳过，
// last 在 2 月最后一天（含闰年）触发。
func TestSchedulerMonthlyMonthEnd(t *testing.T) {
	clock := newFakeClock(time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC))
	raw, store := openTestStoreWithClock(t, clock)
	executor := newClockExecutor(t, store, map[string]task.Handler{
		"test.month31":   func(context.Context, task.Job) error { return nil },
		"test.monthlast": func(context.Context, task.Job) error { return nil },
	}, 2, clock, nil)
	startExecutor(t, executor)
	scheduler := newTestScheduler(t, store, executor, clock, nil)
	ctx := context.Background()

	day31 := dailyRequest("test.month31", "02:30", "UTC", task.MissedSkip, true)
	day31.ScheduleType = task.ScheduleTypeMonthly
	day31.Expression = "31 02:30"
	mustCreateSchedule(t, scheduler, day31)

	lastRequest := dailyRequest("test.monthlast", "09:00", "Asia/Shanghai", task.MissedSkip, true)
	lastRequest.ScheduleType = task.ScheduleTypeMonthly
	lastRequest.Expression = "last 09:00"
	mustCreateSchedule(t, scheduler, lastRequest)

	// 1 月 31 日触发一次（last 计划在 1 月末的触发因错过窗口被跳过）。
	clock.Set(time.Date(2021, 1, 31, 2, 30, 0, 0, time.UTC))
	if err := scheduler.Tick(ctx); err != nil {
		t.Fatalf("1 月末 Tick 失败: %v", err)
	}
	if got := countJobsByKind(t, raw, "test.month31"); got != 1 {
		t.Fatalf("1 月 31 日应触发一次，实际 %d", got)
	}
	// 2 月没有 31 日：跳过后不触发。
	clock.Set(time.Date(2021, 2, 15, 0, 0, 0, 0, time.UTC))
	if err := scheduler.Tick(ctx); err != nil {
		t.Fatalf("2 月 Tick 失败: %v", err)
	}
	if got := countJobsByKind(t, raw, "test.month31"); got != 1 {
		t.Fatalf("2 月不应触发 31 日计划，实际 %d", got)
	}
	// last：2021-02-28 09:00 +08 = 2021-02-28T01:00Z。
	clock.Set(time.Date(2021, 2, 28, 0, 30, 0, 0, time.UTC))
	if err := scheduler.Tick(ctx); err != nil {
		t.Fatalf("2 月末前 Tick 失败: %v", err)
	}
	if got := countJobsByKind(t, raw, "test.monthlast"); got != 0 {
		t.Fatalf("2 月末未到不应触发，实际 %d", got)
	}
	clock.Set(time.Date(2021, 2, 28, 1, 0, 0, 0, time.UTC))
	if err := scheduler.Tick(ctx); err != nil {
		t.Fatalf("2 月末 Tick 失败: %v", err)
	}
	if got := countJobsByKind(t, raw, "test.monthlast"); got != 1 {
		t.Fatalf("last 应在 2 月 28 日触发一次，实际 %d", got)
	}
	// 3 月 31 日再触发一次 31 日计划。
	clock.Set(time.Date(2021, 3, 31, 2, 30, 0, 0, time.UTC))
	if err := scheduler.Tick(ctx); err != nil {
		t.Fatalf("3 月末 Tick 失败: %v", err)
	}
	if got := countJobsByKind(t, raw, "test.month31"); got != 2 {
		t.Fatalf("31 日计划应在 1 月与 3 月各触发一次，实际 %d", got)
	}
	// 闰年 2024-02-29 09:00 +08 = 2024-02-29T01:00Z。
	clock.Set(time.Date(2024, 2, 29, 1, 0, 0, 0, time.UTC))
	if err := scheduler.Tick(ctx); err != nil {
		t.Fatalf("闰年 2 月末 Tick 失败: %v", err)
	}
	if got := countJobsByKind(t, raw, "test.monthlast"); got != 2 {
		t.Fatalf("last 应在闰年 2 月 29 日再触发一次，实际 %d", got)
	}
	waitJobsSettled(t, raw, "test.month31")
	waitJobsSettled(t, raw, "test.monthlast")
}
