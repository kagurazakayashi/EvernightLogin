package sqlite_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// TestExecutorRetryBackoffAndExhaustion 验证可重试失败按有界指数退避重试、每次
// 尝试都写入历史、尝试次数耗尽后进入 failed 终态且不再重试。
func TestExecutorRetryBackoffAndExhaustion(t *testing.T) {
	clock := newFakeClock(time.Date(2021, 4, 25, 4, 0, 0, 0, time.UTC))
	_, store := openTestStoreWithClock(t, clock)
	var calls atomic.Int32
	executor := newClockExecutor(t, store, map[string]task.Handler{
		"test.retry": func(context.Context, task.Job) error {
			calls.Add(1)
			return errors.New("暂时性失败")
		},
	}, 2, clock, func(options *task.Options) {
		options.RetryPolicy = task.RetryPolicy{
			BaseDelay: 20 * time.Millisecond,
			MaxDelay:  60 * time.Millisecond,
		}
	})
	startExecutor(t, executor)
	ctx := context.Background()
	job := mustEnqueue(t, executor, task.EnqueueRequest{
		Kind:        "test.retry",
		Actor:       userActor("user-1"),
		MaxAttempts: 3,
	})

	wantDelays := []time.Duration{20 * time.Millisecond, 40 * time.Millisecond}
	for attempt := 1; attempt <= 2; attempt++ {
		var latest task.Job
		waitCondition(t, "等待失败后安排重试", func() bool {
			got, err := executor.Get(ctx, job.ID)
			if err != nil {
				return false
			}
			latest = got
			return got.State == task.StateQueued && !got.NextAttemptAt.IsZero() && got.Attempt == attempt
		})
		delay := latest.NextAttemptAt.Sub(clock.Now())
		if delay != wantDelays[attempt-1] {
			t.Fatalf("第 %d 次退避 = %s，期望 %s", attempt, delay, wantDelays[attempt-1])
		}
		attempts, err := executor.Attempts(ctx, job.ID)
		if err != nil {
			t.Fatalf("读取尝试历史失败: %v", err)
		}
		if len(attempts) != attempt {
			t.Fatalf("第 %d 次失败后尝试历史长度 = %d", attempt, len(attempts))
		}
		for _, record := range attempts {
			if record.JobID != job.ID || record.Attempt < 1 || record.FinishedAt.IsZero() || record.Outcome != string(task.StateFailed) {
				t.Fatalf("尝试历史记录异常: %+v", record)
			}
		}
		clock.Advance(delay)
	}

	final := waitForState(t, executor, job.ID, task.StateFailed)
	waitCondition(t, "第三次尝试历史写入", func() bool {
		attempts, err := executor.Attempts(ctx, job.ID)
		return err == nil && len(attempts) == 3
	})
	if final.Attempt != 3 || final.MaxAttempts != 3 || final.ErrorCode != "TASK_FAILED" {
		t.Fatalf("终态 = %+v，期望第 3 次尝试失败且 TASK_FAILED", final)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("处理器调用次数 = %d，期望 3", got)
	}
	// 耗尽后即便时间继续前进也不再尝试。
	clock.Advance(time.Hour)
	time.Sleep(3 * task.MinPollInterval)
	if got := calls.Load(); got != 3 {
		t.Fatalf("重试耗尽后处理器调用次数 = %d，期望保持 3", got)
	}
	attempts, err := executor.Attempts(ctx, job.ID)
	if err != nil || len(attempts) != 3 {
		t.Fatalf("最终尝试历史 = %d 条（错误 %v），期望 3 条", len(attempts), err)
	}
}

// TestExecutorNonRetryableAndPermanentFailures 验证显式不可重试错误、未知处理器
// 与处理器 panic 都不会重试。
func TestExecutorNonRetryableAndPermanentFailures(t *testing.T) {
	clock := newFakeClock(time.Date(2021, 4, 25, 4, 0, 0, 0, time.UTC))
	_, store := openTestStoreWithClock(t, clock)
	var permanentCalls atomic.Int32
	executor := newClockExecutor(t, store, map[string]task.Handler{
		"test.permanent": func(context.Context, task.Job) error {
			permanentCalls.Add(1)
			return task.NonRetryable(errors.New("配置错误，不可能成功"))
		},
		"test.panic": func(context.Context, task.Job) error {
			panic("测试 panic")
		},
	}, 2, clock, func(options *task.Options) {
		options.RetryPolicy = task.RetryPolicy{BaseDelay: 20 * time.Millisecond, MaxDelay: 40 * time.Millisecond}
	})
	startExecutor(t, executor)
	ctx := context.Background()

	permanent := mustEnqueue(t, executor, task.EnqueueRequest{
		Kind: "test.permanent", Actor: userActor("user-1"), MaxAttempts: 3,
	})
	waitForState(t, executor, permanent.ID, task.StateFailed)
	if got := permanentCalls.Load(); got != 1 {
		t.Fatalf("不可重试错误处理器调用次数 = %d，期望 1", got)
	}
	if attempts, err := executor.Attempts(ctx, permanent.ID); err != nil || len(attempts) != 1 {
		t.Fatalf("不可重试错误尝试历史 = %d 条（错误 %v），期望 1 条", len(attempts), err)
	}

	unknown := mustEnqueue(t, executor, task.EnqueueRequest{
		Kind: "test.unknown", Actor: userActor("user-1"), MaxAttempts: 3,
	})
	unknownFinal := waitForState(t, executor, unknown.ID, task.StateFailed)
	if unknownFinal.ErrorCode != "TASK_HANDLER_UNKNOWN" {
		t.Fatalf("未知处理器错误码 = %q，期望 TASK_HANDLER_UNKNOWN", unknownFinal.ErrorCode)
	}
	if attempts, err := executor.Attempts(ctx, unknown.ID); err != nil || len(attempts) != 1 {
		t.Fatalf("未知处理器尝试历史 = %d 条（错误 %v），期望 1 条", len(attempts), err)
	}

	panicJob := mustEnqueue(t, executor, task.EnqueueRequest{
		Kind: "test.panic", Actor: userActor("user-1"), MaxAttempts: 3,
	})
	panicFinal := waitForState(t, executor, panicJob.ID, task.StateFailed)
	if panicFinal.ErrorCode != "TASK_FAILED" {
		t.Fatalf("panic 错误码 = %q，期望 TASK_FAILED", panicFinal.ErrorCode)
	}
	// 时间前进后也不得出现额外尝试。
	clock.Advance(time.Hour)
	time.Sleep(3 * task.MinPollInterval)
	if attempts, err := executor.Attempts(ctx, panicJob.ID); err != nil || len(attempts) != 1 {
		t.Fatalf("panic 尝试历史 = %d 条（错误 %v），期望 1 条", len(attempts), err)
	}
}

// TestCancelPreventsRetry 验证已排队等待重试的任务被取消后不会重试。
func TestCancelPreventsRetry(t *testing.T) {
	clock := newFakeClock(time.Date(2021, 4, 25, 4, 0, 0, 0, time.UTC))
	_, store := openTestStoreWithClock(t, clock)
	var calls atomic.Int32
	executor := newClockExecutor(t, store, map[string]task.Handler{
		"test.cancelretry": func(context.Context, task.Job) error {
			calls.Add(1)
			return errors.New("暂时性失败")
		},
	}, 2, clock, func(options *task.Options) {
		options.RetryPolicy = task.RetryPolicy{BaseDelay: 20 * time.Millisecond, MaxDelay: 40 * time.Millisecond}
	})
	startExecutor(t, executor)
	ctx := context.Background()
	job := mustEnqueue(t, executor, task.EnqueueRequest{
		Kind: "test.cancelretry", Actor: userActor("user-1"), MaxAttempts: 3,
	})
	waitCondition(t, "等待任务安排重试", func() bool {
		latest, err := executor.Get(ctx, job.ID)
		return err == nil && latest.State == task.StateQueued && !latest.NextAttemptAt.IsZero()
	})
	result, err := executor.RequestCancel(ctx, task.CancelRequest{
		JobID:  job.ID,
		Actor:  userActor("user-cancel"),
		Reason: "用户取消等待重试的任务",
	})
	if err != nil {
		t.Fatalf("取消任务失败: %v", err)
	}
	if !result.Accepted || result.State != task.StateCancelled {
		t.Fatalf("取消结果 = %+v，期望接受并进入 cancelled", result)
	}
	clock.Advance(time.Hour)
	time.Sleep(3 * task.MinPollInterval)
	final, err := executor.Get(ctx, job.ID)
	if err != nil {
		t.Fatalf("读取任务失败: %v", err)
	}
	if final.State != task.StateCancelled || final.ErrorCode != "TASK_CANCELLED" {
		t.Fatalf("取消后任务 = %s/%s，期望 cancelled/TASK_CANCELLED", final.State, final.ErrorCode)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("取消后处理器调用次数 = %d，期望保持 1", got)
	}
	attempts, err := executor.Attempts(ctx, job.ID)
	if err != nil || len(attempts) != 1 || attempts[0].Outcome != string(task.StateFailed) {
		t.Fatalf("取消后尝试历史 = %+v（错误 %v），期望 1 次失败尝试", attempts, err)
	}
}

// TestRunningCancelBecomesCancelledNotFailed 验证运行中取消记录真实取消终态并且
// 不进入重试。
func TestRunningCancelBecomesCancelledNotFailed(t *testing.T) {
	clock := newFakeClock(time.Date(2021, 4, 25, 4, 0, 0, 0, time.UTC))
	_, store := openTestStoreWithClock(t, clock)
	var calls atomic.Int32
	executor := newClockExecutor(t, store, map[string]task.Handler{
		"test.runningcancel": func(ctx context.Context, _ task.Job) error {
			calls.Add(1)
			<-ctx.Done()
			return ctx.Err()
		},
	}, 2, clock, func(options *task.Options) {
		options.RetryPolicy = task.RetryPolicy{BaseDelay: 20 * time.Millisecond, MaxDelay: 40 * time.Millisecond}
	})
	startExecutor(t, executor)
	ctx := context.Background()
	job := mustEnqueue(t, executor, task.EnqueueRequest{
		Kind: "test.runningcancel", Actor: userActor("user-1"), MaxAttempts: 3,
	})
	waitForState(t, executor, job.ID, task.StateRunning)
	result, err := executor.RequestCancel(ctx, task.CancelRequest{
		JobID:  job.ID,
		Actor:  userActor("user-cancel"),
		Reason: "用户取消运行中任务",
	})
	if err != nil {
		t.Fatalf("取消运行中任务失败: %v", err)
	}
	if !result.Accepted {
		t.Fatalf("取消请求应被接受: %+v", result)
	}
	final := waitForState(t, executor, job.ID, task.StateCancelled)
	if final.ErrorCode != "TASK_CANCELLED" {
		t.Fatalf("取消终态错误码 = %q，期望 TASK_CANCELLED", final.ErrorCode)
	}
	clock.Advance(time.Hour)
	time.Sleep(3 * task.MinPollInterval)
	if got := calls.Load(); got != 1 {
		t.Fatalf("取消后处理器调用次数 = %d，期望保持 1", got)
	}
	if attempts, err := executor.Attempts(ctx, job.ID); err != nil || len(attempts) != 1 || attempts[0].Outcome != string(task.StateCancelled) {
		t.Fatalf("取消尝试历史 = %+v（错误 %v）", attempts, err)
	}
}

// TestExecutorPermissionRevalidation 验证执行前权限复验默认拒绝、权限恢复后正常
// 执行、重试期间权限被撤销则停止重试。
func TestExecutorPermissionRevalidation(t *testing.T) {
	clock := newFakeClock(time.Date(2021, 4, 25, 4, 0, 0, 0, time.UTC))
	_, store := openTestStoreWithClock(t, clock)
	var allow atomic.Bool
	var deniedCalls, allowCalls, retryCalls atomic.Int32
	check := func(context.Context, task.PermissionRequest) error {
		if allow.Load() {
			return nil
		}
		return errors.New("执行身份权限已撤销")
	}
	executor := newClockExecutor(t, store, map[string]task.Handler{
		"test.deny": func(context.Context, task.Job) error {
			deniedCalls.Add(1)
			return nil
		},
		"test.allow": func(context.Context, task.Job) error {
			allowCalls.Add(1)
			return nil
		},
		"test.retrydeny": func(context.Context, task.Job) error {
			if retryCalls.Add(1) == 1 {
				return errors.New("第一次暂时性失败")
			}
			return nil
		},
	}, 2, clock, func(options *task.Options) {
		options.PermissionCheck = check
		options.RetryPolicy = task.RetryPolicy{BaseDelay: 20 * time.Millisecond, MaxDelay: 40 * time.Millisecond}
	})
	startExecutor(t, executor)
	ctx := context.Background()

	denied := mustEnqueue(t, executor, task.EnqueueRequest{
		Kind: "test.deny", Actor: userActor("user-1"), PermissionRequired: true, MaxAttempts: 3,
	})
	deniedFinal := waitForState(t, executor, denied.ID, task.StateFailed)
	if deniedFinal.ErrorCode != "TASK_PERMISSION_REVOKED" {
		t.Fatalf("权限拒绝错误码 = %q，期望 TASK_PERMISSION_REVOKED", deniedFinal.ErrorCode)
	}
	if got := deniedCalls.Load(); got != 0 {
		t.Fatalf("权限拒绝时处理器不应执行，实际调用 %d 次", got)
	}
	if attempts, err := executor.Attempts(ctx, denied.ID); err != nil || len(attempts) != 1 {
		t.Fatalf("权限拒绝尝试历史 = %d 条（错误 %v），期望 1 条且不重试", len(attempts), err)
	}

	allow.Store(true)
	allowed := mustEnqueue(t, executor, task.EnqueueRequest{
		Kind: "test.allow", Actor: userActor("user-1"), PermissionRequired: true, MaxAttempts: 1,
	})
	waitForState(t, executor, allowed.ID, task.StateSucceeded)
	if got := allowCalls.Load(); got != 1 {
		t.Fatalf("权限允许后处理器调用次数 = %d，期望 1", got)
	}

	// 重试期间撤权：第 1 次失败后安排重试，第 2 次尝试前复验失败，不再重试。
	retryJob := mustEnqueue(t, executor, task.EnqueueRequest{
		Kind: "test.retrydeny", Actor: userActor("user-1"), PermissionRequired: true, MaxAttempts: 3,
	})
	waitCondition(t, "等待重试期间撤权任务安排重试", func() bool {
		latest, err := executor.Get(ctx, retryJob.ID)
		return err == nil && latest.State == task.StateQueued && !latest.NextAttemptAt.IsZero()
	})
	allow.Store(false)
	clock.Advance(20 * time.Millisecond)
	retryFinal := waitForState(t, executor, retryJob.ID, task.StateFailed)
	if retryFinal.ErrorCode != "TASK_PERMISSION_REVOKED" {
		t.Fatalf("重试撤权错误码 = %q，期望 TASK_PERMISSION_REVOKED", retryFinal.ErrorCode)
	}
	if got := retryCalls.Load(); got != 1 {
		t.Fatalf("撤权后处理器调用次数 = %d，期望保持 1（第 2 次尝试未执行）", got)
	}
	if attempts, err := executor.Attempts(ctx, retryJob.ID); err != nil || len(attempts) != 2 {
		t.Fatalf("撤权后尝试历史 = %d 条（错误 %v），期望 2 条且不再重试", len(attempts), err)
	}
	clock.Advance(time.Hour)
	time.Sleep(3 * task.MinPollInterval)
	if attempts, err := executor.Attempts(ctx, retryJob.ID); err != nil || len(attempts) != 2 {
		t.Fatalf("撤权后不应继续重试，尝试历史 = %d 条（错误 %v）", len(attempts), err)
	}
}

// TestExecutorPermissionRequiredWithoutCheckFailsClosed 验证要求权限复验但未配置
// 可信回调时任务直接失败，不默认放行。
func TestExecutorPermissionRequiredWithoutCheckFailsClosed(t *testing.T) {
	clock := newFakeClock(time.Date(2021, 4, 25, 4, 0, 0, 0, time.UTC))
	_, store := openTestStoreWithClock(t, clock)
	var calls atomic.Int32
	executor := newClockExecutor(t, store, map[string]task.Handler{
		"test.failclosed": func(context.Context, task.Job) error {
			calls.Add(1)
			return nil
		},
	}, 2, clock, nil)
	startExecutor(t, executor)
	ctx := context.Background()
	job := mustEnqueue(t, executor, task.EnqueueRequest{
		Kind: "test.failclosed", Actor: userActor("user-1"), PermissionRequired: true, MaxAttempts: 3,
	})
	final := waitForState(t, executor, job.ID, task.StateFailed)
	if final.ErrorCode != "TASK_PERMISSION_REVOKED" {
		t.Fatalf("缺少权限回调错误码 = %q，期望 TASK_PERMISSION_REVOKED", final.ErrorCode)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("缺少权限回调时处理器不应执行，实际调用 %d 次", got)
	}
	if attempts, err := executor.Attempts(ctx, job.ID); err != nil || len(attempts) != 1 {
		t.Fatalf("缺少权限回调尝试历史 = %d 条（错误 %v），期望 1 条", len(attempts), err)
	}
}

// TestAttemptHistoryInterruptedRecovery 验证崩溃重启恢复时把未关闭的尝试标记为
// interrupted 并结束任务。
func TestAttemptHistoryInterruptedRecovery(t *testing.T) {
	clock := newFakeClock(time.Date(2021, 4, 25, 4, 0, 0, 0, time.UTC))
	_, store := openTestStoreWithClock(t, clock)
	ctx := context.Background()
	jobID := mustJobID(t)
	if _, err := store.Enqueue(ctx, task.NewJob{
		ID:             jobID,
		Kind:           "test.recover",
		Initiator:      userActor("user-1"),
		Payload:        []byte(`{}`),
		TimeoutSeconds: 30,
		MaxAttempts:    1,
		CreatedAt:      clock.Now(),
	}); err != nil {
		t.Fatalf("入队失败: %v", err)
	}
	if _, found, err := store.Claim(ctx, "exec-crashed", clock.Now()); err != nil || !found {
		t.Fatalf("预置运行中任务失败: found=%v err=%v", found, err)
	}
	executor := newClockExecutor(t, store, map[string]task.Handler{
		"test.recover": func(context.Context, task.Job) error { return nil },
	}, 2, clock, nil)
	startExecutor(t, executor) // Start 时执行重启恢复

	final, err := executor.Get(ctx, jobID)
	if err != nil {
		t.Fatalf("读取恢复任务失败: %v", err)
	}
	if final.State != task.StateFailed || final.ErrorCode != "TASK_INTERRUPTED" {
		t.Fatalf("恢复任务 = %s/%s，期望 failed/TASK_INTERRUPTED", final.State, final.ErrorCode)
	}
	attempts, err := executor.Attempts(ctx, jobID)
	if err != nil {
		t.Fatalf("读取尝试历史失败: %v", err)
	}
	if len(attempts) != 1 {
		t.Fatalf("恢复后尝试历史 = %d 条，期望 1 条", len(attempts))
	}
	if attempts[0].Outcome != "interrupted" || attempts[0].ErrorCode != "TASK_INTERRUPTED" || attempts[0].FinishedAt.IsZero() {
		t.Fatalf("恢复尝试记录 = %+v，期望 interrupted/TASK_INTERRUPTED 且已结束", attempts[0])
	}
}

// TestEnqueueAttemptLimits 验证最大尝试次数范围与默认值。
func TestEnqueueAttemptLimits(t *testing.T) {
	clock := newFakeClock(time.Date(2021, 4, 25, 4, 0, 0, 0, time.UTC))
	_, store := openTestStoreWithClock(t, clock)
	executor := newClockExecutor(t, store, map[string]task.Handler{
		"test.limit": func(context.Context, task.Job) error { return nil },
	}, 1, clock, nil)
	ctx := context.Background()
	job, err := executor.Enqueue(ctx, task.EnqueueRequest{Kind: "test.limit", Actor: userActor("user-1")})
	if err != nil {
		t.Fatalf("入队失败: %v", err)
	}
	if job.MaxAttempts != 1 {
		t.Fatalf("默认最大尝试次数 = %d，期望 1", job.MaxAttempts)
	}
	if _, err := executor.Enqueue(ctx, task.EnqueueRequest{Kind: "test.limit", Actor: userActor("user-1"), MaxAttempts: task.MaxJobAttempts + 1}); !errors.Is(err, task.ErrInvalidRequest) {
		t.Fatalf("超上限最大尝试次数错误 = %v，期望 ErrInvalidRequest", err)
	}
}
