package sqlite_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
	tasksqlite "github.com/kagurazakayashi/EvernightLogin/internal/task/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// openTestDatabase 在临时目录创建数据库并执行全部迁移。
func openTestDatabase(t *testing.T) *storagesqlite.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tasks.db")
	raw, err := storagesqlite.Open(context.Background(), storagesqlite.DefaultOptions(path))
	if err != nil {
		t.Fatalf("打开临时 SQLite 失败: %v", err)
	}
	t.Cleanup(func() {
		_ = raw.Close()
	})
	migrationSet, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移失败: %v", err)
	}
	if _, err := raw.Migrate(context.Background(), migrationSet); err != nil {
		t.Fatalf("执行迁移失败: %v", err)
	}
	return raw
}

// newTaskStore 构造 SQLite 任务存储。
func newTaskStore(t *testing.T, raw *storagesqlite.Store) *tasksqlite.Store {
	t.Helper()
	store, err := tasksqlite.New(raw, tasksqlite.Options{})
	if err != nil {
		t.Fatalf("构造任务存储失败: %v", err)
	}
	return store
}

// newExecutor 构造带默认执行器标识与较快轮询的任务执行器。
func newExecutor(t *testing.T, store task.Store, handlers map[string]task.Handler, maxConcurrent int) *task.Executor {
	t.Helper()
	if maxConcurrent == 0 {
		maxConcurrent = 2
	}
	executor, err := task.New(store, task.Options{
		Handlers:        handlers,
		ExecutorID:      "exec-test-1",
		MaxConcurrent:   maxConcurrent,
		PollInterval:    task.MinPollInterval,
		ShutdownTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("构造执行器失败: %v", err)
	}
	return executor
}

// startExecutor 启动执行器并注册测试结束清理。
func startExecutor(t *testing.T, executor *task.Executor) {
	t.Helper()
	if err := executor.Start(context.Background()); err != nil {
		t.Fatalf("启动执行器失败: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = executor.Stop(ctx)
	})
}

// waitForState 等待任务进入指定状态。
func waitForState(t *testing.T, executor *task.Executor, jobID string, want task.State) task.Job {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		job, err := executor.Get(context.Background(), jobID)
		if err == nil {
			if job.State == want {
				return job
			}
			if job.State.Terminal() && want != job.State {
				t.Fatalf("任务 %s 进入终态 %s（%s），期望 %s", jobID, job.State, job.ErrorCode, want)
			}
		}
		if time.Now().After(deadline) {
			latest, _ := executor.Get(context.Background(), jobID)
			t.Fatalf("等待任务 %s 状态 %s 超时，当前 = %+v", jobID, want, latest)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// waitCondition 等待条件成立，超时失败。
func waitCondition(t *testing.T, description string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("等待条件超时: %s", description)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// queryInt 执行单值整数查询。
func queryInt(t *testing.T, raw *storagesqlite.Store, query string, args ...any) int {
	t.Helper()
	rows, err := raw.QueryContext(context.Background(), query, args...)
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatalf("查询没有结果: %s", query)
	}
	var value int
	if err := rows.Scan(&value); err != nil {
		t.Fatalf("扫描查询结果失败: %v", err)
	}
	return value
}

// auditEntry 是审计事件摘要。
type auditEntry struct {
	Action     string
	ActorType  string
	ActorID    sql.NullString
	Outcome    string
	ErrorCode  sql.NullString
	ReasonCode sql.NullString
}

// loadAuditEntries 读取指定任务的安全审计事件。
func loadAuditEntries(t *testing.T, raw *storagesqlite.Store, jobID string) []auditEntry {
	t.Helper()
	rows, err := raw.QueryContext(context.Background(),
		`SELECT action,actor_type,actor_id,outcome,error_code,reason_code FROM audit_events WHERE task_id=? ORDER BY occurred_at_ms, rowid`, jobID)
	if err != nil {
		t.Fatalf("查询审计事件失败: %v", err)
	}
	defer rows.Close()
	var entries []auditEntry
	for rows.Next() {
		var entry auditEntry
		if err := rows.Scan(&entry.Action, &entry.ActorType, &entry.ActorID, &entry.Outcome, &entry.ErrorCode, &entry.ReasonCode); err != nil {
			t.Fatalf("扫描审计事件失败: %v", err)
		}
		entries = append(entries, entry)
	}
	return entries
}

// auditActionSet 返回审计动作集合。
func auditActionSet(entries []auditEntry) map[string]auditEntry {
	set := make(map[string]auditEntry, len(entries))
	for _, entry := range entries {
		set[entry.Action] = entry
	}
	return set
}

// mustEnqueue 入队任务并断言成功。
func mustEnqueue(t *testing.T, executor *task.Executor, request task.EnqueueRequest) task.Job {
	t.Helper()
	job, err := executor.Enqueue(context.Background(), request)
	if err != nil {
		t.Fatalf("入队失败: %v", err)
	}
	return job
}

// userActor 返回测试用户身份。
func userActor(id string) audit.Actor {
	return audit.Actor{Type: audit.ActorUser, ID: id}
}

// directEnqueue 直接用存储入队，供崩溃恢复类测试预置状态。
func directEnqueue(t *testing.T, store task.Store, kind string, timeoutSeconds int) task.Job {
	t.Helper()
	id, err := task.NewJobID()
	if err != nil {
		t.Fatalf("NewJobID 失败: %v", err)
	}
	job, err := store.Enqueue(context.Background(), task.NewJob{
		ID:             id,
		Kind:           kind,
		Initiator:      userActor("user-1"),
		Payload:        []byte(`{}`),
		TimeoutSeconds: timeoutSeconds,
		CreatedAt:      time.Now().UTC().Truncate(time.Millisecond),
	})
	if err != nil {
		t.Fatalf("直接入队失败: %v", err)
	}
	return job
}

// TestExecuteSuccessAndAuditAllTransitions 验证成功执行、载荷传递与全状态审计。
func TestExecuteSuccessAndAuditAllTransitions(t *testing.T) {
	raw := openTestDatabase(t)
	store := newTaskStore(t, raw)
	var handledPayload atomic.Value
	handler := func(_ context.Context, job task.Job) error {
		handledPayload.Store(string(job.Payload))
		return nil
	}
	executor := newExecutor(t, store, map[string]task.Handler{"test.success": handler}, 2)
	startExecutor(t, executor)
	job := mustEnqueue(t, executor, task.EnqueueRequest{
		Kind:      "test.success",
		Actor:     userActor("user-1"),
		Payload:   []byte(`{"value":1}`),
		RequestID: "req_1",
	})
	finished := waitForState(t, executor, job.ID, task.StateSucceeded)
	if finished.StartedAt.IsZero() || finished.FinishedAt.IsZero() || finished.ExecutorID != "exec-test-1" {
		t.Fatalf("任务时间/执行者字段错误: %+v", finished)
	}
	if handledPayload.Load() != `{"value":1}` {
		t.Fatalf("处理器载荷 = %v", handledPayload.Load())
	}
	entries := loadAuditEntries(t, raw, job.ID)
	actions := auditActionSet(entries)
	for _, want := range []string{"jobs.enqueued", "jobs.started", "jobs.succeeded"} {
		if _, ok := actions[want]; !ok {
			t.Fatalf("缺少审计动作 %s，实际 %+v", want, entries)
		}
	}
	if entry := actions["jobs.enqueued"]; entry.ActorType != "user" || !entry.ActorID.Valid || entry.ActorID.String != "user-1" {
		t.Fatalf("入队审计身份错误: %+v", entry)
	}
	if entry := actions["jobs.started"]; entry.ActorType != "system" || !entry.ActorID.Valid || entry.ActorID.String != "exec-test-1" {
		t.Fatalf("开始审计身份错误: %+v", entry)
	}
	if got := queryInt(t, raw, `SELECT COUNT(*) FROM audit_events WHERE task_id=?`, job.ID); got < 3 {
		t.Fatalf("审计事件数量 = %d", got)
	}
}

// TestExecuteFailureAndUnknownHandler 验证处理器失败与未知类型的安全终态。
func TestExecuteFailureAndUnknownHandler(t *testing.T) {
	raw := openTestDatabase(t)
	store := newTaskStore(t, raw)
	handler := func(context.Context, task.Job) error {
		return errors.New("下游失败\n含换行")
	}
	executor := newExecutor(t, store, map[string]task.Handler{"test.fail": handler}, 2)
	startExecutor(t, executor)
	job := mustEnqueue(t, executor, task.EnqueueRequest{Kind: "test.fail", Actor: userActor("user-1")})
	failed := waitForState(t, executor, job.ID, task.StateFailed)
	if failed.ErrorCode != "TASK_FAILED" {
		t.Fatalf("错误码 = %q", failed.ErrorCode)
	}
	if strings.Contains(failed.FailureReason, "\n") || !strings.Contains(failed.FailureReason, "下游失败") {
		t.Fatalf("失败说明未安全处理: %q", failed.FailureReason)
	}
	actions := auditActionSet(loadAuditEntries(t, raw, job.ID))
	if entry, ok := actions["jobs.failed"]; !ok || !entry.ErrorCode.Valid || entry.ErrorCode.String != "TASK_FAILED" {
		t.Fatalf("失败审计事件 = %+v", actions)
	}

	// 未注册处理器类型：executor 允许启动，但任务失败为 TASK_HANDLER_UNKNOWN。
	unknown := mustEnqueue(t, executor, task.EnqueueRequest{Kind: "test.unknown", Actor: userActor("user-1")})
	unknownJob := waitForState(t, executor, unknown.ID, task.StateFailed)
	if unknownJob.ErrorCode != "TASK_HANDLER_UNKNOWN" {
		t.Fatalf("未知处理器错误码 = %q", unknownJob.ErrorCode)
	}
}

// TestHandlerPanicContained 验证处理器 panic 被隔离为失败终态，不传播到执行器。
func TestHandlerPanicContained(t *testing.T) {
	raw := openTestDatabase(t)
	store := newTaskStore(t, raw)
	executor := newExecutor(t, store, map[string]task.Handler{
		"test.panic": func(context.Context, task.Job) error { panic("handler boom") },
	}, 2)
	startExecutor(t, executor)
	job := mustEnqueue(t, executor, task.EnqueueRequest{Kind: "test.panic", Actor: userActor("user-1")})
	failed := waitForState(t, executor, job.ID, task.StateFailed)
	if failed.ErrorCode != "TASK_FAILED" || !strings.Contains(failed.FailureReason, "panic") {
		t.Fatalf("panic 失败终态 = %+v", failed)
	}
}

// TestQueuedCancel 验证排队任务直接取消、审计记录请求人、终态拒绝晚到取消。
func TestQueuedCancel(t *testing.T) {
	raw := openTestDatabase(t)
	store := newTaskStore(t, raw)
	var invoked atomic.Int32
	executor := newExecutor(t, store, map[string]task.Handler{
		"test.success": func(context.Context, task.Job) error { invoked.Add(1); return nil },
	}, 2)
	job := mustEnqueue(t, executor, task.EnqueueRequest{Kind: "test.success", Actor: userActor("user-1")})
	result, err := executor.RequestCancel(context.Background(), task.CancelRequest{
		JobID: job.ID, Actor: userActor("user-1"), Reason: "用户不再需要该通知",
	})
	if err != nil {
		t.Fatalf("取消排队任务失败: %v", err)
	}
	if !result.Accepted || result.State != task.StateCancelled {
		t.Fatalf("取消结果 = %+v", result)
	}
	cancelled, err := executor.Get(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("查询取消任务失败: %v", err)
	}
	if cancelled.State != task.StateCancelled || cancelled.Canceller == nil || cancelled.Canceller.ID != "user-1" {
		t.Fatalf("取消后任务字段 = %+v", cancelled)
	}
	if _, err := executor.RequestCancel(context.Background(), task.CancelRequest{
		JobID: job.ID, Actor: userActor("user-1"), Reason: "再次取消",
	}); !errors.Is(err, task.ErrTaskTerminal) {
		t.Fatalf("终态重复取消错误 = %v", err)
	}
	startExecutor(t, executor)
	time.Sleep(100 * time.Millisecond)
	if invoked.Load() != 0 {
		t.Fatal("已取消的排队任务仍被执行")
	}
	actions := auditActionSet(loadAuditEntries(t, raw, job.ID))
	if entry, ok := actions["jobs.cancelled"]; !ok || entry.ActorType != "user" {
		t.Fatalf("取消审计事件 = %+v", actions)
	}
	if entry, ok := actions["jobs.cancel_rejected"]; !ok || entry.Outcome != "denied" {
		t.Fatalf("取消被拒绝审计事件 = %+v", actions)
	}
}

// TestRunningCancel 验证运行中取消：先进入 cancel_requested，处理器响应后真正
// 取消，记录取消请求人与真实终止结果。
func TestRunningCancel(t *testing.T) {
	raw := openTestDatabase(t)
	store := newTaskStore(t, raw)
	started := make(chan struct{})
	handler := func(ctx context.Context, _ task.Job) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}
	executor := newExecutor(t, store, map[string]task.Handler{"test.block": handler}, 2)
	startExecutor(t, executor)
	job := mustEnqueue(t, executor, task.EnqueueRequest{Kind: "test.block", Actor: userActor("user-1")})
	<-started
	result, err := executor.RequestCancel(context.Background(), task.CancelRequest{
		JobID: job.ID, Actor: userActor("user-1"), Reason: "用户取消运行中任务",
	})
	if err != nil || !result.Accepted || result.State != task.StateCancelRequested {
		t.Fatalf("运行中取消结果 = %+v, %v", result, err)
	}
	cancelled := waitForState(t, executor, job.ID, task.StateCancelled)
	if cancelled.Canceller == nil || cancelled.Canceller.Type != audit.ActorUser || cancelled.Canceller.ID != "user-1" {
		t.Fatalf("取消人字段 = %+v", cancelled.Canceller)
	}
	if cancelled.CancellationReason != "用户取消运行中任务" {
		t.Fatalf("取消原因 = %q", cancelled.CancellationReason)
	}
	if cancelled.ErrorCode != "TASK_CANCELLED" {
		t.Fatalf("取消错误码 = %q", cancelled.ErrorCode)
	}
	actions := auditActionSet(loadAuditEntries(t, raw, job.ID))
	if entry, ok := actions["jobs.cancel_requested"]; !ok || entry.ActorType != "user" {
		t.Fatalf("取消请求审计 = %+v", actions)
	}
	if _, ok := actions["jobs.cancelled"]; !ok {
		t.Fatalf("实际取消审计缺失: %+v", actions)
	}
	if _, err := executor.RequestCancel(context.Background(), task.CancelRequest{
		JobID: job.ID, Actor: userActor("user-1"), Reason: "晚到取消",
	}); !errors.Is(err, task.ErrTaskTerminal) {
		t.Fatalf("终态晚到取消错误 = %v", err)
	}
}

// TestCompletionCancelRaceKeepsRealResult 验证完成/取消竞争时记录真实最终状态，
// 终态不被晚到的取消覆盖。
func TestCompletionCancelRaceKeepsRealResult(t *testing.T) {
	raw := openTestDatabase(t)
	store := newTaskStore(t, raw)
	started := make(chan struct{})
	release := make(chan struct{})
	handler := func(context.Context, task.Job) error {
		close(started)
		<-release
		return nil
	}
	executor := newExecutor(t, store, map[string]task.Handler{"test.race": handler}, 2)
	startExecutor(t, executor)
	job := mustEnqueue(t, executor, task.EnqueueRequest{Kind: "test.race", Actor: userActor("user-1")})
	<-started
	if _, err := executor.RequestCancel(context.Background(), task.CancelRequest{
		JobID: job.ID, Actor: userActor("user-1"), Reason: "竞争取消",
	}); err != nil {
		t.Fatalf("取消请求失败: %v", err)
	}
	close(release)
	finished := waitForState(t, executor, job.ID, task.StateSucceeded)
	if finished.Canceller == nil || finished.Canceller.ID != "user-1" {
		t.Fatalf("真实完成时未保留取消请求人: %+v", finished.Canceller)
	}
	if _, err := executor.RequestCancel(context.Background(), task.CancelRequest{
		JobID: job.ID, Actor: userActor("user-1"), Reason: "完成后的晚到取消",
	}); !errors.Is(err, task.ErrTaskTerminal) {
		t.Fatalf("完成后取消错误 = %v", err)
	}
	latest, err := executor.Get(context.Background(), job.ID)
	if err != nil || latest.State != task.StateSucceeded {
		t.Fatalf("终态被覆盖: %+v, %v", latest, err)
	}
	actions := auditActionSet(loadAuditEntries(t, raw, job.ID))
	for _, want := range []string{"jobs.cancel_requested", "jobs.succeeded", "jobs.cancel_rejected"} {
		if _, ok := actions[want]; !ok {
			t.Fatalf("竞争场景缺少审计动作 %s: %+v", want, entriesActions(actions))
		}
	}
}

// entriesActions 返回动作键列表，便于失败信息。
func entriesActions(set map[string]auditEntry) []string {
	actions := make([]string, 0, len(set))
	for action := range set {
		actions = append(actions, action)
	}
	return actions
}

// TestTimeout 验证墙钟超时终态、错误码与审计。
func TestTimeout(t *testing.T) {
	raw := openTestDatabase(t)
	store := newTaskStore(t, raw)
	handler := func(ctx context.Context, _ task.Job) error {
		<-ctx.Done()
		return ctx.Err()
	}
	executor := newExecutor(t, store, map[string]task.Handler{"test.timeout": handler}, 2)
	startExecutor(t, executor)
	job := mustEnqueue(t, executor, task.EnqueueRequest{
		Kind: "test.timeout", Actor: userActor("user-1"), TimeoutSeconds: 1,
	})
	timedOut := waitForState(t, executor, job.ID, task.StateTimedOut)
	if timedOut.ErrorCode != "TASK_TIMEOUT" {
		t.Fatalf("超时错误码 = %q", timedOut.ErrorCode)
	}
	if timedOut.FinishedAt.Sub(timedOut.StartedAt) < 900*time.Millisecond {
		t.Fatalf("超时时间差 = %s", timedOut.FinishedAt.Sub(timedOut.StartedAt))
	}
	actions := auditActionSet(loadAuditEntries(t, raw, job.ID))
	if entry, ok := actions["jobs.timed_out"]; !ok || !entry.ErrorCode.Valid || entry.ErrorCode.String != "TASK_TIMEOUT" {
		t.Fatalf("超时审计事件 = %+v", actions)
	}
}

// TestShutdownCancelsRunningSystemSubject 验证停机取消记录具体系统主体、运行中
// 任务真实取消、排队任务保留。
func TestShutdownCancelsRunningSystemSubject(t *testing.T) {
	raw := openTestDatabase(t)
	store := newTaskStore(t, raw)
	started := make(chan struct{})
	handler := func(ctx context.Context, _ task.Job) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}
	executor := newExecutor(t, store, map[string]task.Handler{"test.block": handler}, 1)
	startExecutor(t, executor)
	running := mustEnqueue(t, executor, task.EnqueueRequest{Kind: "test.block", Actor: userActor("user-1")})
	queued := mustEnqueue(t, executor, task.EnqueueRequest{Kind: "test.block", Actor: userActor("user-2")})
	<-started
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := executor.Stop(stopCtx); err != nil {
		t.Fatalf("停机失败: %v", err)
	}
	cancelled, err := executor.Get(context.Background(), running.ID)
	if err != nil || cancelled.State != task.StateCancelled {
		t.Fatalf("运行中任务停机后状态 = %+v, %v", cancelled, err)
	}
	if cancelled.Canceller == nil || cancelled.Canceller.Type != audit.ActorSystem || cancelled.Canceller.ID != "exec-test-1" {
		t.Fatalf("停机取消主体 = %+v", cancelled.Canceller)
	}
	pending, err := executor.Get(context.Background(), queued.ID)
	if err != nil || pending.State != task.StateQueued {
		t.Fatalf("排队任务停机后状态 = %+v, %v", pending, err)
	}
	actions := auditActionSet(loadAuditEntries(t, raw, running.ID))
	if entry, ok := actions["jobs.cancel_requested"]; !ok || entry.ActorType != "system" {
		t.Fatalf("停机取消请求审计 = %+v", actions)
	}
	if entry, ok := actions["jobs.cancelled"]; !ok || entry.ActorType != "system" {
		t.Fatalf("停机实际取消审计 = %+v", actions)
	}
	// 排队任务在新执行器启动后可以继续执行。
	executor2 := newExecutor(t, store, map[string]task.Handler{
		"test.block": func(ctx context.Context, _ task.Job) error { return nil },
	}, 1)
	startExecutor(t, executor2)
	waitForState(t, executor2, queued.ID, task.StateSucceeded)
}

// TestRestartRecoveryMarksInterrupted 验证重启后遗留运行/取消请求任务被安全标记
// 为 failed/TASK_INTERRUPTED 并审计，排队任务继续执行。
func TestRestartRecoveryMarksInterrupted(t *testing.T) {
	raw := openTestDatabase(t)
	store := newTaskStore(t, raw)
	running := directEnqueue(t, store, "test.success", 300)
	cancelRequested := directEnqueue(t, store, "test.success", 300)
	queued := directEnqueue(t, store, "test.success", 300)
	nowMS := time.Now().UTC().UnixMilli()
	if _, err := raw.ExecContext(context.Background(),
		`UPDATE jobs SET state='running',executed_by='dead-exec',started_at_ms=?,updated_at_ms=? WHERE id=?`,
		nowMS, nowMS, running.ID); err != nil {
		t.Fatalf("模拟崩溃运行中状态失败: %v", err)
	}
	if _, err := raw.ExecContext(context.Background(),
		`UPDATE jobs SET state='cancel_requested',cancelled_by_type='user',cancelled_by_id='user-1',
		cancellation_reason='用户取消',cancel_requested_at_ms=?,updated_at_ms=? WHERE id=?`,
		nowMS, nowMS, cancelRequested.ID); err != nil {
		t.Fatalf("模拟崩溃取消请求状态失败: %v", err)
	}
	executor := newExecutor(t, store, map[string]task.Handler{
		"test.success": func(context.Context, task.Job) error { return nil },
	}, 2)
	startExecutor(t, executor)
	for _, id := range []string{running.ID, cancelRequested.ID} {
		recovered := waitForState(t, executor, id, task.StateFailed)
		if recovered.ErrorCode != "TASK_INTERRUPTED" {
			t.Fatalf("恢复任务 %s 错误码 = %q", id, recovered.ErrorCode)
		}
		actions := auditActionSet(loadAuditEntries(t, raw, id))
		if entry, ok := actions["jobs.recovered"]; !ok || entry.ActorType != "system" || !entry.ErrorCode.Valid || entry.ErrorCode.String != "TASK_INTERRUPTED" {
			t.Fatalf("恢复审计事件 = %+v", actions)
		}
	}
	waitForState(t, executor, queued.ID, task.StateSucceeded)
}

// TestConcurrencyLimitAndMutexKey 验证并发上限与互斥键不会同时运行。
func TestConcurrencyLimitAndMutexKey(t *testing.T) {
	raw := openTestDatabase(t)
	store := newTaskStore(t, raw)
	var active atomic.Int32
	var maxActive atomic.Int32
	mutexViolations := atomic.Int32{}
	var mutexActive sync.Map
	parallelHandler := func(context.Context, task.Job) error {
		current := active.Add(1)
		for {
			previous := maxActive.Load()
			if current <= previous || maxActive.CompareAndSwap(previous, current) {
				break
			}
		}
		time.Sleep(40 * time.Millisecond)
		active.Add(-1)
		return nil
	}
	mutexHandler := func(_ context.Context, job task.Job) error {
		key := job.MutexKey
		if _, loaded := mutexActive.LoadOrStore(key, struct{}{}); loaded {
			mutexViolations.Add(1)
		}
		time.Sleep(40 * time.Millisecond)
		mutexActive.Delete(key)
		return nil
	}
	executor := newExecutor(t, store, map[string]task.Handler{
		"test.parallel": parallelHandler,
		"test.mutex":    mutexHandler,
	}, 2)
	startExecutor(t, executor)
	var jobs []task.Job
	for i := 0; i < 6; i++ {
		jobs = append(jobs, mustEnqueue(t, executor, task.EnqueueRequest{
			Kind: "test.parallel", Actor: userActor("user-1"),
		}))
	}
	for _, job := range jobs {
		waitForState(t, executor, job.ID, task.StateSucceeded)
	}
	if maxActive.Load() > 2 {
		t.Fatalf("最大并发 = %d，超过上限 2", maxActive.Load())
	}
	mutexOne := mustEnqueue(t, executor, task.EnqueueRequest{Kind: "test.mutex", Actor: userActor("user-1"), MutexKey: "user-notification"})
	mutexTwo := mustEnqueue(t, executor, task.EnqueueRequest{Kind: "test.mutex", Actor: userActor("user-2"), MutexKey: "user-notification"})
	waitForState(t, executor, mutexOne.ID, task.StateSucceeded)
	waitForState(t, executor, mutexTwo.ID, task.StateSucceeded)
	if mutexViolations.Load() != 0 {
		t.Fatalf("互斥键任务发生 %d 次并发重叠", mutexViolations.Load())
	}
}

// TestChildProcessCleanupOnCancel 验证处理器使用 context 取消后子进程被清理。
func TestChildProcessCleanupOnCancel(t *testing.T) {
	raw := openTestDatabase(t)
	store := newTaskStore(t, raw)
	started := make(chan struct{})
	childDone := make(chan error, 1)
	handler := func(ctx context.Context, _ task.Job) error {
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestTaskChildHelperProcess$")
		command.Env = append(os.Environ(), "LOGIN_TASK_CHILD_HELPER=1")
		if err := command.Start(); err != nil {
			close(started)
			return err
		}
		close(started)
		err := command.Wait()
		childDone <- err
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	executor := newExecutor(t, store, map[string]task.Handler{"test.child": handler}, 1)
	startExecutor(t, executor)
	job := mustEnqueue(t, executor, task.EnqueueRequest{
		Kind: "test.child", Actor: userActor("user-1"), TimeoutSeconds: 60,
	})
	<-started
	if _, err := executor.RequestCancel(context.Background(), task.CancelRequest{
		JobID: job.ID, Actor: userActor("user-1"), Reason: "取消并清理子进程",
	}); err != nil {
		t.Fatalf("取消子进程任务失败: %v", err)
	}
	waitForState(t, executor, job.ID, task.StateCancelled)
	select {
	case <-childDone:
	case <-time.After(5 * time.Second):
		t.Fatal("子进程未在取消后退出")
	}
}

// TestTaskChildHelperProcess 是测试用子进程，被父测试通过 exec.CommandContext
// 启动；正常情况下应只由父测试显式运行。
func TestTaskChildHelperProcess(t *testing.T) {
	if os.Getenv("LOGIN_TASK_CHILD_HELPER") != "1" {
		return
	}
	time.Sleep(30 * time.Second)
}

// TestAuditFailureRejectsTaskChange 验证审计写入故障时任务状态变化回滚（fail-closed）。
func TestAuditFailureRejectsTaskChange(t *testing.T) {
	raw := openTestDatabase(t)
	store := newTaskStore(t, raw)
	executor := newExecutor(t, store, map[string]task.Handler{
		"test.success": func(context.Context, task.Job) error { return nil },
	}, 1)
	if _, err := raw.ExecContext(context.Background(),
		`CREATE TRIGGER audit_inject_job_failure BEFORE INSERT ON audit_events
		 WHEN NEW.action LIKE 'jobs.%' BEGIN SELECT RAISE(ABORT, 'injected'); END`); err != nil {
		t.Fatalf("创建审计故障触发器失败: %v", err)
	}
	_, err := executor.Enqueue(context.Background(), task.EnqueueRequest{
		Kind: "test.success", Actor: userActor("user-1"),
	})
	if !errors.Is(err, audit.ErrAuditUnavailable) {
		t.Fatalf("审计故障入队错误 = %v，期望 audit.ErrAuditUnavailable", err)
	}
	if got := queryInt(t, raw, `SELECT COUNT(*) FROM jobs`); got != 0 {
		t.Fatalf("审计故障后仍有 %d 条任务", got)
	}
	if _, err := raw.ExecContext(context.Background(), `DROP TRIGGER audit_inject_job_failure`); err != nil {
		t.Fatalf("删除审计故障触发器失败: %v", err)
	}
	job := mustEnqueue(t, executor, task.EnqueueRequest{Kind: "test.success", Actor: userActor("user-1")})
	startExecutor(t, executor)
	waitForState(t, executor, job.ID, task.StateSucceeded)
}

// TestStartRecoveryAuditFailureRejectsStart 验证恢复审计失败时执行器拒绝启动，
// 遗留任务状态不被错误改写。
func TestStartRecoveryAuditFailureRejectsStart(t *testing.T) {
	raw := openTestDatabase(t)
	store := newTaskStore(t, raw)
	stale := directEnqueue(t, store, "test.success", 300)
	nowMS := time.Now().UTC().UnixMilli()
	if _, err := raw.ExecContext(context.Background(),
		`UPDATE jobs SET state='running',executed_by='dead-exec',started_at_ms=?,updated_at_ms=? WHERE id=?`,
		nowMS, nowMS, stale.ID); err != nil {
		t.Fatalf("预置遗留运行任务失败: %v", err)
	}
	if _, err := raw.ExecContext(context.Background(),
		`CREATE TRIGGER audit_inject_recovery_failure BEFORE INSERT ON audit_events
		 WHEN NEW.action='jobs.recovered' BEGIN SELECT RAISE(ABORT, 'injected'); END`); err != nil {
		t.Fatalf("创建恢复审计故障触发器失败: %v", err)
	}
	executor := newExecutor(t, store, map[string]task.Handler{
		"test.success": func(context.Context, task.Job) error { return nil },
	}, 1)
	if err := executor.Start(context.Background()); !errors.Is(err, task.ErrRecoveryFailed) {
		t.Fatalf("恢复审计失败时 Start 错误 = %v", err)
	}
	current, err := executor.Get(context.Background(), stale.ID)
	if err != nil || current.State != task.StateRunning {
		t.Fatalf("审计失败时遗留任务状态被改写: %+v, %v", current, err)
	}
	if _, err := raw.ExecContext(context.Background(), `DROP TRIGGER audit_inject_recovery_failure`); err != nil {
		t.Fatalf("删除恢复审计故障触发器失败: %v", err)
	}
	if err := executor.Start(context.Background()); err != nil {
		t.Fatalf("修复后 Start 失败: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = executor.Stop(cleanupCtx)
	})
	waitForState(t, executor, stale.ID, task.StateFailed)
}

// TestUntrustedActorsRejected 验证匿名/无效身份不能入队或取消。
func TestUntrustedActorsRejected(t *testing.T) {
	raw := openTestDatabase(t)
	store := newTaskStore(t, raw)
	executor := newExecutor(t, store, map[string]task.Handler{
		"test.success": func(context.Context, task.Job) error { return nil },
	}, 1)
	if _, err := executor.Enqueue(context.Background(), task.EnqueueRequest{
		Kind: "test.success", Actor: audit.Actor{Type: audit.ActorAnonymous, ID: ""},
	}); !errors.Is(err, task.ErrUntrustedActor) {
		t.Fatalf("匿名入队错误 = %v", err)
	}
	if _, err := executor.RequestCancel(context.Background(), task.CancelRequest{
		JobID: mustJobID(t), Actor: audit.Actor{Type: audit.ActorAnonymous, ID: ""}, Reason: "匿名取消",
	}); !errors.Is(err, task.ErrUntrustedActor) {
		t.Fatalf("匿名取消错误 = %v", err)
	}
	if got := queryInt(t, raw, `SELECT COUNT(*) FROM jobs`); got != 0 {
		t.Fatalf("不可信身份仍写入了 %d 条任务", got)
	}
}

// mustJobID 生成任务编号。
func mustJobID(t *testing.T) string {
	t.Helper()
	id, err := task.NewJobID()
	if err != nil {
		t.Fatalf("NewJobID 失败: %v", err)
	}
	return id
}

// TestGetNotFound 验证查询不存在任务返回明确错误。
func TestGetNotFound(t *testing.T) {
	raw := openTestDatabase(t)
	store := newTaskStore(t, raw)
	executor := newExecutor(t, store, map[string]task.Handler{
		"test.success": func(context.Context, task.Job) error { return nil },
	}, 1)
	if _, err := executor.Get(context.Background(), mustJobID(t)); !errors.Is(err, task.ErrTaskNotFound) {
		t.Fatalf("不存在任务错误 = %v", err)
	}
	if _, err := executor.Get(context.Background(), "bad"); !errors.Is(err, task.ErrInvalidRequest) {
		t.Fatalf("非法任务编号错误 = %v", err)
	}
}

// TestStopReportsTimeoutWithoutClaimingCleanup 验证处理器不响应取消时 Stop 报告
// 超时，而不是假装已清理；随后处理器真实结束，状态由执行器真实写入。
func TestStopReportsTimeoutWithoutClaimingCleanup(t *testing.T) {
	raw := openTestDatabase(t)
	store := newTaskStore(t, raw)
	started := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan struct{})
	handler := func(context.Context, task.Job) error {
		close(started)
		<-release
		close(finished)
		return nil
	}
	executor, err := task.New(store, task.Options{
		Handlers:        map[string]task.Handler{"test.stubborn": handler},
		ExecutorID:      "exec-test-1",
		MaxConcurrent:   1,
		PollInterval:    task.MinPollInterval,
		ShutdownTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("构造执行器失败: %v", err)
	}
	if err := executor.Start(context.Background()); err != nil {
		t.Fatalf("启动执行器失败: %v", err)
	}
	job := mustEnqueue(t, executor, task.EnqueueRequest{
		Kind: "test.stubborn", Actor: userActor("user-1"), TimeoutSeconds: 60,
	})
	<-started
	stopCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	stopErr := executor.Stop(stopCtx)
	if !errors.Is(stopErr, task.ErrShutdownTimeout) {
		t.Fatalf("Stop 错误 = %v，期望 ErrShutdownTimeout", stopErr)
	}
	if elapsed := time.Since(start); elapsed < 900*time.Millisecond {
		t.Fatalf("Stop 提前返回，耗时 %s", elapsed)
	}
	close(release)
	<-finished
	waitCondition(t, "处理器结束后任务进入终态", func() bool {
		current, err := executor.Get(context.Background(), job.ID)
		return err == nil && current.State.Terminal()
	})
}

// TestEchoPayloadAndRequestIDPersisted 验证载荷与 request_id 持久化并可在查询中
// 读回。
func TestEchoPayloadAndRequestIDPersisted(t *testing.T) {
	raw := openTestDatabase(t)
	store := newTaskStore(t, raw)
	executor := newExecutor(t, store, map[string]task.Handler{
		"test.success": func(context.Context, task.Job) error { return nil },
	}, 1)
	startExecutor(t, executor)
	job := mustEnqueue(t, executor, task.EnqueueRequest{
		Kind: "test.success", Actor: userActor("user-1"), Payload: []byte(`{"key":"value"}`), RequestID: "req_abc",
	})
	loaded, err := executor.Get(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("查询任务失败: %v", err)
	}
	if string(loaded.Payload) != `{"key":"value"}` || loaded.RequestID != "req_abc" {
		t.Fatalf("任务载荷/请求编号 = %s / %q", loaded.Payload, loaded.RequestID)
	}
}

// TestStoreErrorAndValidationPaths 覆盖直接存储层的参数校验、终态保护、取消不存在
// 任务与数据库关闭错误映射。
func TestStoreErrorAndValidationPaths(t *testing.T) {
	raw := openTestDatabase(t)
	store := newTaskStore(t, raw)
	executor := newExecutor(t, store, map[string]task.Handler{
		"test.success": func(context.Context, task.Job) error { return nil },
	}, 1)

	// 非法任务编号与匿名发起者由存储层再次拒绝。
	if _, err := store.Enqueue(context.Background(), task.NewJob{
		ID: "bad", Kind: "test.success", Initiator: userActor("user-1"),
		Payload: []byte(`{}`), TimeoutSeconds: 30, CreatedAt: time.Now(),
	}); !errors.Is(err, task.ErrInvalidRequest) {
		t.Fatalf("非法编号入队错误 = %v", err)
	}
	if _, err := store.Enqueue(context.Background(), task.NewJob{
		ID: mustJobID(t), Kind: "test.success", Initiator: audit.Actor{Type: audit.ActorAnonymous, ID: ""},
		Payload: []byte(`{}`), TimeoutSeconds: 30, CreatedAt: time.Now(),
	}); !errors.Is(err, task.ErrUntrustedActor) {
		t.Fatalf("匿名发起者入队错误 = %v", err)
	}

	// 终态任务不能被再次 Complete 覆盖。
	startExecutor(t, executor)
	job := mustEnqueue(t, executor, task.EnqueueRequest{Kind: "test.success", Actor: userActor("user-1")})
	waitForState(t, executor, job.ID, task.StateSucceeded)
	if _, err := store.Complete(context.Background(), task.Completion{
		JobID: job.ID, State: task.StateFailed, ExecutorID: "other", Now: time.Now(),
	}); !errors.Is(err, task.ErrTransitionRejected) {
		t.Fatalf("终态覆盖错误 = %v", err)
	}

	// 取消不存在的任务。
	if _, err := store.RequestCancel(context.Background(), task.CancelCommand{
		JobID: mustJobID(t), Actor: userActor("user-1"), Reason: "不存在", Now: time.Now(),
	}); !errors.Is(err, task.ErrTaskNotFound) {
		t.Fatalf("取消不存在任务错误 = %v", err)
	}

	// 数据库关闭后入队明确失败，不返回成功。
	if err := raw.Close(); err != nil {
		t.Fatalf("关闭数据库失败: %v", err)
	}
	if _, err := executor.Enqueue(context.Background(), task.EnqueueRequest{
		Kind: "test.success", Actor: userActor("user-1"),
	}); !errors.Is(err, task.ErrStoreUnavailable) {
		t.Fatalf("关闭数据库后入队错误 = %v", err)
	}
}

// TestAuditFailureOnClaimKeepsQueued 验证领取阶段的审计故障使状态变化回滚，
// 任务保持 queued；修复后继续执行。
func TestAuditFailureOnClaimKeepsQueued(t *testing.T) {
	raw := openTestDatabase(t)
	store := newTaskStore(t, raw)
	executor := newExecutor(t, store, map[string]task.Handler{
		"test.success": func(context.Context, task.Job) error { return nil },
	}, 1)
	job := mustEnqueue(t, executor, task.EnqueueRequest{Kind: "test.success", Actor: userActor("user-1")})
	if _, err := raw.ExecContext(context.Background(),
		`CREATE TRIGGER audit_inject_start_failure BEFORE INSERT ON audit_events
		 WHEN NEW.action='jobs.started' BEGIN SELECT RAISE(ABORT, 'injected'); END`); err != nil {
		t.Fatalf("创建开始审计故障触发器失败: %v", err)
	}
	startExecutor(t, executor)
	time.Sleep(150 * time.Millisecond)
	queued, err := executor.Get(context.Background(), job.ID)
	if err != nil || queued.State != task.StateQueued {
		t.Fatalf("领取审计故障后任务状态 = %+v, %v", queued, err)
	}
	if got := queryInt(t, raw, `SELECT COUNT(*) FROM audit_events WHERE task_id=? AND action='jobs.started'`, job.ID); got != 0 {
		t.Fatalf("领取审计故障仍写入了 %d 条 started 事件", got)
	}
	if _, err := raw.ExecContext(context.Background(), `DROP TRIGGER audit_inject_start_failure`); err != nil {
		t.Fatalf("删除开始审计故障触发器失败: %v", err)
	}
	waitForState(t, executor, job.ID, task.StateSucceeded)
}

// TestAuditFailureOnCompletionLeavesForRecovery 验证终态审计失败时不提交终态，
// 任务留在 running，由下一次启动恢复为 TASK_INTERRUPTED。
func TestAuditFailureOnCompletionLeavesForRecovery(t *testing.T) {
	raw := openTestDatabase(t)
	store := newTaskStore(t, raw)
	executor := newExecutor(t, store, map[string]task.Handler{
		"test.success": func(context.Context, task.Job) error { return nil },
	}, 1)
	job := mustEnqueue(t, executor, task.EnqueueRequest{Kind: "test.success", Actor: userActor("user-1")})
	if _, err := raw.ExecContext(context.Background(),
		`CREATE TRIGGER audit_inject_success_failure BEFORE INSERT ON audit_events
		 WHEN NEW.action='jobs.succeeded' BEGIN SELECT RAISE(ABORT, 'injected'); END`); err != nil {
		t.Fatalf("创建成功审计故障触发器失败: %v", err)
	}
	startExecutor(t, executor)
	waitCondition(t, "任务进入 running 并因终态审计失败停留", func() bool {
		current, err := executor.Get(context.Background(), job.ID)
		return err == nil && current.State == task.StateRunning
	})
	time.Sleep(100 * time.Millisecond)
	current, err := executor.Get(context.Background(), job.ID)
	if err != nil || current.State != task.StateRunning {
		t.Fatalf("终态审计失败后任务状态 = %+v, %v", current, err)
	}
	if _, err := raw.ExecContext(context.Background(), `DROP TRIGGER audit_inject_success_failure`); err != nil {
		t.Fatalf("删除成功审计故障触发器失败: %v", err)
	}
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := executor.Stop(stopCtx); err != nil {
		cancel()
		t.Fatalf("停止执行器失败: %v", err)
	}
	cancel()

	recoveryExecutor := newExecutor(t, store, map[string]task.Handler{
		"test.success": func(context.Context, task.Job) error { return nil },
	}, 1)
	startExecutor(t, recoveryExecutor)
	recovered := waitForState(t, recoveryExecutor, job.ID, task.StateFailed)
	if recovered.ErrorCode != "TASK_INTERRUPTED" {
		t.Fatalf("遗留 running 任务恢复错误码 = %q", recovered.ErrorCode)
	}
}
