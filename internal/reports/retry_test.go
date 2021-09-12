package reports

// 本文件验证历史报告受控重试：仅失败/取消/超时可重试；当前权限/数据范围/敏感操作
// 重新校验；创建新记录并保留原记录（RetryOf 链式关联）；非法状态拒绝；审计失败
// fail-closed 不创建可执行任务；原记录状态不被改写。

import (
	"context"
	"errors"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
)

// newRetryEnv 构造带失败报告与完整授权的测试环境。
func newRetryEnv(t *testing.T) *testEnv {
	t.Helper()
	env := newTestEnv(t)
	env.grantAll(testUserID(1), ScopeSystem, stats.ScopeGrant{Allowed: true, AllData: true})
	return env
}

// generateFailedReport 生成一份失败报告并返回报告编号。
func generateFailedReport(t *testing.T, env *testEnv) string {
	t.Helper()
	ctx := context.Background()
	view, err := env.service.Start(ctx, env.startRequest(t))
	if err != nil {
		t.Fatalf("创建失败报告失败: %v", err)
	}
	env.source.err = errors.New("source unavailable")
	job := env.enqueuer.last()
	env.tasks.jobs[job.ID] = job
	if genErr := env.service.GenerateHandler(ctx, job); genErr == nil {
		t.Fatal("来源不可用时生成应失败")
	}
	env.source.err = nil
	failed, err := env.service.Get(ctx, testCaller(t, 1), view.ID)
	if err != nil || failed.State != StateFailed {
		t.Fatalf("失败报告状态 = %q err=%v", failed.State, err)
	}
	return view.ID
}

// TestRetryCreatesChainedRun 验证重试成功路径：新记录、RetryOf 关联、审计与真实
// 操作者、原记录保持失败、重新执行后成功。
func TestRetryCreatesChainedRun(t *testing.T) {
	env := newRetryEnv(t)
	ctx := context.Background()
	caller := testCaller(t, 1)
	originalID := generateFailedReport(t, env)
	beforeJobs := len(env.enqueuer.jobs)
	view, err := env.service.Retry(ctx, caller, originalID, "来源恢复后重试", "req-retry-1")
	if err != nil {
		t.Fatalf("重试失败: %v", err)
	}
	if view.ID == originalID || view.RetryOf != originalID || view.State != StateQueued {
		t.Fatalf("重试视图 = %+v，期望新编号且 RetryOf=%s", view, originalID)
	}
	if len(env.enqueuer.jobs) != beforeJobs+1 {
		t.Fatalf("重试未投递新任务: jobs=%d", len(env.enqueuer.jobs))
	}
	if !env.recorder.hasAction(ActionRetry) {
		t.Fatal("重试未写审计")
	}
	original, err := env.service.Get(ctx, caller, originalID)
	if err != nil || original.State != StateFailed {
		t.Fatalf("重试后原记录状态 = %q err=%v，期望保持 failed", original.State, err)
	}
	// 新任务真实执行后成功；历史中保留新旧两条记录。
	job := env.enqueuer.last()
	env.tasks.jobs[job.ID] = job
	if err := env.service.GenerateHandler(ctx, job); err != nil {
		t.Fatalf("重试任务执行失败: %v", err)
	}
	done, err := env.service.Get(ctx, caller, view.ID)
	if err != nil || done.State != StateSucceeded {
		t.Fatalf("重试任务状态 = %q err=%v", done.State, err)
	}
}

// TestRetryRejectsInvalidStateAndPermission 验证成功/进行中状态拒绝重试，失权后
// 拒绝重试且不创建新任务。
func TestRetryRejectsInvalidStateAndPermission(t *testing.T) {
	env := newRetryEnv(t)
	ctx := context.Background()
	caller := testCaller(t, 1)
	// 成功报告不能重试。
	reportID, _ := env.startAndGenerate(t, env.startRequest(t))
	if _, err := env.service.Retry(ctx, caller, reportID, "重试成功报告", "req-retry-2"); !errors.Is(err, ErrConflict) {
		t.Fatalf("成功报告重试错误 = %v，期望 ErrConflict", err)
	}
	// 失败报告，但撤销生成权限后拒绝且不投递任务。
	failedID := generateFailedReport(t, env)
	before := len(env.enqueuer.jobs)
	env.authorizer.deny(PermissionGenerate, ScopeSystem)
	if _, err := env.service.Retry(ctx, caller, failedID, "失权重试", "req-retry-3"); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("失权重试错误 = %v，期望 ErrAccessDenied", err)
	}
	if len(env.enqueuer.jobs) != before {
		t.Fatalf("失权重试投递了任务: before=%d after=%d", before, len(env.enqueuer.jobs))
	}
}

// TestRetryAuditFailureIsFailClosed 验证重试审计不可用时拒绝创建任务与记录。
func TestRetryAuditFailureIsFailClosed(t *testing.T) {
	env := newRetryEnv(t)
	ctx := context.Background()
	caller := testCaller(t, 1)
	failedID := generateFailedReport(t, env)
	env.recorder.setFailWrites(true)
	beforeJobs := len(env.enqueuer.jobs)
	beforeRecords := len(env.service.records)
	_, err := env.service.Retry(ctx, caller, failedID, "审计不可用重试", "req-retry-4")
	if !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("审计不可用重试错误 = %v，期望 ErrAuditUnavailable", err)
	}
	env.recorder.setFailWrites(false)
	if len(env.enqueuer.jobs) != beforeJobs {
		t.Fatal("审计失败后仍投递了重试任务")
	}
	if len(env.service.records) != beforeRecords {
		t.Fatal("审计失败后仍创建了重试记录")
	}
}

// TestRetryAuthorizationBeforeStateHidesExistence 验证无权限调用者对“不存在 ID”与
// “存在但终态不可重试”得到一致的隐藏结果（不泄露存在性与终态），且已授权调用者
// 仍能看到真实冲突。
func TestRetryAuthorizationBeforeStateHidesExistence(t *testing.T) {
	env := newRetryEnv(t)
	ctx := context.Background()
	// 用另一个无任何授权的调用者。
	outsider := testCaller(t, 9)
	// 存在但状态为失败（可重试）的报告：无权限时拒绝且隐藏存在性。
	failedID := generateFailedReport(t, env)
	_, existingErr := env.service.Retry(ctx, outsider, failedID, "越权重试", "req-retry-l2")
	// 不存在的 ID：同样不暴露存在性。
	missingID := "rpt_" + "33333333333333333333333333333333"
	_, missingErr := env.service.Retry(ctx, outsider, missingID, "越权重试", "req-retry-l2b")
	if !errors.Is(existingErr, ErrAccessDenied) || !errors.Is(existingErr, ErrNotFound) {
		t.Fatalf("存在报告无权重试错误 = %v，期望同时为 ACCESS_DENIED/NOT_FOUND", existingErr)
	}
	if !errors.Is(missingErr, ErrNotFound) {
		t.Fatalf("不存在报告重试错误 = %v，期望 NOT_FOUND", missingErr)
	}
	if errors.Is(existingErr, ErrConflict) {
		t.Fatal("无权限调用者可通过 CONFLICT 探测终态")
	}
	// 已授权调用者对成功报告仍得到真实 CONFLICT（终态不可重试）。
	successID, _ := env.startAndGenerate(t, env.startRequest(t))
	if _, err := env.service.Retry(ctx, testCaller(t, 1), successID,
		"重试成功报告", "req-retry-l2c"); !errors.Is(err, ErrConflict) {
		t.Fatalf("成功报告重试错误 = %v，期望 ErrConflict", err)
	}
}

// TestRetryFromPersistedHistoryAfterRestart 验证进程重启（内存记录丢失）后仍可对
// 持久历史中的失败报告发起受控重试，并链式关联原报告。
func TestRetryFromPersistedHistoryAfterRestart(t *testing.T) {
	now := baseTime
	env, history := newLifecycleEnv(t, &now)
	env.grantAll(testUserID(1), ScopeSystem, stats.ScopeGrant{Allowed: true, AllData: true})
	ctx := context.Background()
	env.source.err = errors.New("source unavailable")
	view, err := env.service.Start(ctx, env.startRequest(t))
	if err != nil {
		t.Fatalf("创建失败报告失败: %v", err)
	}
	job := env.enqueuer.last()
	env.tasks.jobs[job.ID] = job
	_ = env.service.GenerateHandler(ctx, job)
	env.source.err = nil
	// 重启：新 Service 只共享持久历史，没有内存记录。
	restarted := restartService(t, env, history)
	if _, err := restarted.Get(ctx, testCaller(t, 1), view.ID); err != nil {
		t.Fatalf("重启后历史回源失败: %v", err)
	}
	retried, err := restarted.Retry(ctx, testCaller(t, 1), view.ID,
		"重启后重试历史报告", "req-retry-history")
	if err != nil {
		t.Fatalf("历史回源重试失败: %v", err)
	}
	if retried.ID == view.ID || retried.RetryOf != view.ID {
		t.Fatalf("历史回源重试视图 = %+v，期望新编号且 RetryOf=%s", retried, view.ID)
	}
}
