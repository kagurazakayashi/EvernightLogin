package reports

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// newTestOptions 构造一份可覆盖可选依赖的完整 Options（测试辅助）。
func newTestOptions(env *testEnv) Options {
	return Options{Source: env.source, Authorizer: env.authorizer, Root: env.root,
		Sensitive: env.sensitive, Audit: env.recorder, Enqueuer: env.enqueuer,
		Canceller: env.canceller, Tasks: env.tasks, OutputDir: env.outputDir,
		MaxDetailRows: 50, Now: env.now}
}

// TestTimeoutIsFailureNotCancel 验证执行超时与主动取消的终态/错误码分开。
func TestTimeoutIsFailureNotCancel(t *testing.T) {
	env := newTestEnv(t)
	env.grantAll(testUserID(1), "system", stats.ScopeGrant{Allowed: true, AllData: true})
	ctx := context.Background()

	// 超时 → failed/TASK_TIMEOUT（不是 cancelled/TASK_CANCELLED），且无产物。
	env.source.err = context.DeadlineExceeded
	timeoutView, err := env.service.Start(ctx, env.startRequest(t))
	if err != nil {
		t.Fatalf("创建报告失败: %v", err)
	}
	timeoutJob := env.enqueuer.last()
	env.tasks.jobs[timeoutJob.ID] = timeoutJob
	if err := env.service.GenerateHandler(ctx, timeoutJob); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("超时生成错误 = %v，期望保留 DeadlineExceeded", err)
	}
	final, err := env.service.Get(ctx, testCaller(t, 1), timeoutView.ID)
	if err != nil {
		t.Fatalf("查询超时报告失败: %v", err)
	}
	if final.State != StateFailed || final.ErrorCode != string(CodeTaskTimeout) {
		t.Fatalf("超时终态不符: state=%s code=%s", final.State, final.ErrorCode)
	}
	if strings.Contains(final.FailureReason, "取消") {
		t.Fatalf("超时失败原因不应写成取消: %q", final.FailureReason)
	}
	if names := env.outputEntries(t); len(names) != 0 {
		t.Fatalf("超时后残留产物: %v", names)
	}
	// 超时审计使用 TASK_TIMEOUT。
	foundTimeoutAudit := false
	env.recorder.mu.Lock()
	for _, event := range env.recorder.events {
		if event.Action == ActionGenerateFinish && event.ErrorCode == string(CodeTaskTimeout) {
			foundTimeoutAudit = true
		}
	}
	env.recorder.mu.Unlock()
	if !foundTimeoutAudit {
		t.Error("超时未记录 TASK_TIMEOUT 失败审计")
	}

	// 主动取消（上下文取消）→ cancelled/TASK_CANCELLED。
	env.source.err = nil
	env.source.cancelled = true
	cancelView, err := env.service.Start(ctx, env.startRequest(t))
	if err != nil {
		t.Fatalf("创建报告失败: %v", err)
	}
	cancelJob := env.enqueuer.last()
	env.tasks.jobs[cancelJob.ID] = cancelJob
	if err := env.service.GenerateHandler(ctx, cancelJob); !errors.Is(err, context.Canceled) {
		t.Fatalf("取消生成错误 = %v，期望 context.Canceled", err)
	}
	cancelled, err := env.service.Get(ctx, testCaller(t, 1), cancelView.ID)
	if err != nil {
		t.Fatalf("查询取消报告失败: %v", err)
	}
	if cancelled.State != StateCancelled || cancelled.ErrorCode != string(CodeTaskCancelled) {
		t.Fatalf("取消终态不符: state=%s code=%s", cancelled.State, cancelled.ErrorCode)
	}
}

// TestAuditUnavailableFailsClosed 验证生成成功审计/下载审计不可用时拒绝导出。
func TestAuditUnavailableFailsClosed(t *testing.T) {
	env := newTestEnv(t)
	env.grantAll(testUserID(1), "system", stats.ScopeGrant{Allowed: true, AllData: true})
	ctx := context.Background()

	// 生成成功审计不可用 → 失败且删除产物，不出现“可下载但无审计”。
	view, err := env.service.Start(ctx, env.startRequest(t))
	if err != nil {
		t.Fatalf("创建报告失败: %v", err)
	}
	job := env.enqueuer.last()
	env.tasks.jobs[job.ID] = job
	env.recorder.setFailWrites(true)
	if err := env.service.GenerateHandler(ctx, job); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("审计不可用生成错误 = %v，期望 ErrAuditUnavailable", err)
	}
	final, err := env.service.Get(ctx, testCaller(t, 1), view.ID)
	if err != nil {
		t.Fatalf("查询失败报告失败: %v", err)
	}
	env.recorder.setFailWrites(false)
	if final.State != StateFailed || final.ErrorCode != string(CodeAuditWriteFailed) {
		t.Fatalf("审计不可用终态不符: %+v", final)
	}
	if names := env.outputEntries(t); len(names) != 0 {
		t.Fatalf("审计不可用后残留产物: %v", names)
	}

	// 下载审计不可用 → 不发放文件句柄（fail-closed），产物保留可重试。
	env.recorder.setFailWrites(false)
	reportID, _ := env.startAndGenerate(t, env.startRequest(t))
	artifactPath := filepath.Join(env.outputDir, artifactFileName(reportID, FormatHTML))
	if _, statErr := os.Lstat(artifactPath); statErr != nil {
		t.Fatalf("成功报告产物不存在: %v", statErr)
	}
	env.recorder.setFailWrites(true)
	if _, err := env.service.OpenFile(ctx, testCaller(t, 1), reportID, FormatHTML); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("审计不可用下载错误 = %v，期望 ErrAuditUnavailable", err)
	}
	env.recorder.setFailWrites(false)
	// 恢复审计后可下载，且记录了下载成功审计。
	if _, err := env.service.OpenFile(ctx, testCaller(t, 1), reportID, FormatHTML); err != nil {
		t.Fatalf("恢复审计后下载失败: %v", err)
	}
	foundDownload := false
	env.recorder.mu.Lock()
	for _, event := range env.recorder.events {
		if event.Action == ActionExportDownload && event.Outcome == audit.OutcomeSuccess {
			foundDownload = true
		}
	}
	env.recorder.mu.Unlock()
	if !foundDownload {
		t.Error("下载成功未写 reports.export.download 审计")
	}
}

// TestSnapshotRequiresReadAndExport 验证机器可读快照按导出面授权，撤销任一权限拒绝。
func TestSnapshotRequiresReadAndExport(t *testing.T) {
	env := newTestEnv(t)
	scopeID := "app_demo1"
	caller := testCaller(t, 1)
	env.grantAll(caller.Actor().ID, scopeID, stats.ScopeGrant{Allowed: true,
		ResourceIDs: []string{scopeID}})
	request := env.startRequest(t)
	request.ScopeID = scopeID
	reportID, _ := env.startAndGenerate(t, request)
	ctx := context.Background()

	// 仅 read（撤 export）：快照属于导出面 → 拒绝；元数据视图仍可用。
	env.authorizer.deny(PermissionExport, scopeID)
	if _, err := env.service.GetSnapshot(ctx, caller, reportID); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("缺导出权限取快照错误 = %v，期望 ErrAccessDenied", err)
	}
	if _, err := env.service.Get(ctx, caller, reportID); err != nil {
		t.Fatalf("缺导出但保留读权限时元数据视图失败: %v", err)
	}
	// 仅 export（撤 read）：快照与下载都拒绝。
	env.authorizer.allow(PermissionExport, scopeID, stats.ScopeGrant{Allowed: true,
		ResourceIDs: []string{scopeID}})
	env.authorizer.deny(PermissionRead, scopeID)
	if _, err := env.service.GetSnapshot(ctx, caller, reportID); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("缺读权限取快照错误 = %v，期望 ErrAccessDenied", err)
	}
	if _, err := env.service.OpenFile(ctx, caller, reportID, FormatJSON); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("缺读权限下载错误 = %v，期望 ErrAccessDenied", err)
	}
	env.grantAll(caller.Actor().ID, scopeID, stats.ScopeGrant{Allowed: true,
		ResourceIDs: []string{scopeID}})
	snapshot, err := env.service.GetSnapshot(ctx, caller, reportID)
	if err != nil || snapshot.Report.ID != reportID {
		t.Fatalf("双权限恢复后取快照失败: %v", err)
	}
}

// TestJSONZeroTimesAndUnknownTimeSchema 验证零值时间输出 null 而不是 0001-01-01。
func TestJSONZeroTimesAndUnknownTimeSchema(t *testing.T) {
	env := newTestEnv(t)
	env.grantAll(testUserID(1), "system", stats.ScopeGrant{Allowed: true, AllData: true})
	// 完整性未配置保留期 → retention_cutoff 为零值，应序列化为 null。
	env.source.completeness = stats.Completeness{WindowWithinRetention: true,
		RetentionDays: 30}
	reportID, _ := env.startAndGenerate(t, env.startRequest(t))
	data := env.artifactBytes(t, reportID, FormatJSON)
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("JSON 解析失败: %v", err)
	}
	schema := document["schema"].(map[string]any)
	if schema["unknown_time"] != "null" {
		t.Fatalf("schema.unknown_time = %v，期望 null 声明", schema["unknown_time"])
	}
	completeness := document["completeness"].(map[string]any)
	if value, exists := completeness["retention_cutoff"]; !exists || value != nil {
		t.Fatalf("零值 retention_cutoff = %v（存在=%v），期望 null", value, exists)
	}
	rows := document["errors"].(map[string]any)["rows"].([]any)
	foundUnavailable := false
	for _, rawRow := range rows {
		row := rawRow.(map[string]any)
		growth := row["growth"].(map[string]any)
		if growth["kind"] != "unavailable" {
			continue
		}
		foundUnavailable = true
		if growth["comparison_start"] != nil || growth["comparison_end"] != nil {
			t.Fatalf("不可用增幅比较时间 = %v/%v，期望 null 而不是零值时间",
				growth["comparison_start"], growth["comparison_end"])
		}
		if _, exists := growth["percent"]; exists {
			t.Fatal("不可用增幅不应输出 percent")
		}
	}
	if !foundUnavailable {
		t.Fatal("测试数据缺少不可用增幅行")
	}
}

// TestRequestIDNormalizedAndTypedNilTasks 验证非法请求编号归一为空（审计不丢）、
// 合法编号保留、可选 Tasks typed-nil 拒绝构造。
func TestRequestIDNormalizedAndTypedNilTasks(t *testing.T) {
	env := newTestEnv(t)
	env.grantAll(testUserID(1), "system", stats.ScopeGrant{Allowed: true, AllData: true})
	ctx := context.Background()

	request := env.startRequest(t)
	request.RequestID = "非法 编号!!"
	if _, err := env.service.Start(ctx, request); err != nil {
		t.Fatalf("非法请求编号不应改变业务结论（已归一为空）: %v", err)
	}
	job := env.enqueuer.last()
	if job.RequestID != "" {
		t.Fatalf("非法请求编号被写入任务: %q", job.RequestID)
	}
	// 合法编号保留。
	request = env.startRequest(t)
	request.RequestID = "req-77-fix"
	if _, err := env.service.Start(ctx, request); err != nil {
		t.Fatalf("合法请求编号创建失败: %v", err)
	}
	if got := env.enqueuer.last().RequestID; got != "req-77-fix" {
		t.Fatalf("合法请求编号丢失: %q", got)
	}

	// typed-nil 可选任务读取器必须拒绝构造（否则视图调用会 panic）。
	options := newTestOptions(env)
	var nilTasks *fakeTasks
	options.Tasks = nilTasks
	if _, err := New(options); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatalf("typed-nil Tasks 构造错误 = %v，期望 ErrOptionsInvalid", err)
	}
}

// TestViewTaskSummaryFromTaskReader 验证任务摘要读取失败不影响报告查询。
func TestViewTaskSummaryFromTaskReader(t *testing.T) {
	env := newTestEnv(t)
	env.grantAll(testUserID(1), "system", stats.ScopeGrant{Allowed: true, AllData: true})
	reportID, _ := env.startAndGenerate(t, env.startRequest(t))
	view, err := env.service.Get(context.Background(), testCaller(t, 1), reportID)
	if err != nil {
		t.Fatalf("查询报告失败: %v", err)
	}
	if view.Task == nil || view.Task.ID == "" || view.Task.State != string(task.StateQueued) {
		t.Fatalf("任务摘要未从真实 Get 签名读取: %+v", view.Task)
	}
	// 任务被移除后查询仍成功（可选摘要缺失不算报告失败）。
	delete(env.tasks.jobs, view.TaskID)
	view, err = env.service.Get(context.Background(), testCaller(t, 1), reportID)
	if err != nil || view.Task != nil {
		t.Fatalf("任务缺失时报告查询 = %v / summary=%+v，期望成功且无摘要", err, view.Task)
	}
}

// 确保 *task.Executor 可直接满足可选 TaskReader 契约（签名对齐的编译期断言）。
var _ TaskReader = (*task.Executor)(nil)
var _ Enqueuer = (*task.Executor)(nil)
var _ Canceller = (*task.Executor)(nil)

// countEvents 统计指定动作/结果/目标报告的事件数（测试辅助）。
func countEvents(recorder *fakeRecorder, action string, outcome audit.Outcome,
	reportID string) int {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	count := 0
	for _, event := range recorder.events {
		if event.Action != action || event.Outcome != outcome {
			continue
		}
		if reportID != "" && event.Target.ID != reportID {
			continue
		}
		count++
	}
	return count
}

// TestGetSnapshotAuditFailClosed 验证机器可读快照读取必须留审计，审计不可用即拒绝。
func TestGetSnapshotAuditFailClosed(t *testing.T) {
	env := newTestEnv(t)
	caller := testCaller(t, 1)
	env.grantAll(caller.Actor().ID, "system", stats.ScopeGrant{Allowed: true, AllData: true})
	reportID, _ := env.startAndGenerate(t, env.startRequest(t))
	ctx := context.Background()

	// 审计不可用：快照读取拒绝（不能绕过 OpenFile 的 fail-closed）。
	env.recorder.setFailWrites(true)
	if _, err := env.service.GetSnapshot(ctx, caller, reportID); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("审计不可用读快照错误 = %v，期望 ErrAuditUnavailable", err)
	}
	env.recorder.setFailWrites(false)
	snapshot, err := env.service.GetSnapshot(ctx, caller, reportID)
	if err != nil || snapshot.Report.ID != reportID {
		t.Fatalf("恢复审计后读快照失败: %v", err)
	}
	// 正常路径写入快照读取审计（动作/目标/结果/调用者）。
	recorder := env.recorder
	recorder.mu.Lock()
	found := false
	for _, event := range recorder.events {
		if event.Action == ActionExportSnapshot && event.Outcome == audit.OutcomeSuccess &&
			event.Target.ID == reportID && event.Actor == caller.Actor() {
			found = true
		}
	}
	recorder.mu.Unlock()
	if !found {
		t.Error("快照读取未写 reports.export.snapshot 审计（含目标与调用者）")
	}
}

// TestSuccessAuditOrderAndTerminalAudit 验证成功审计失败时回滚、失败/取消终态不记成功。
func TestSuccessAuditOrderAndTerminalAudit(t *testing.T) {
	env := newTestEnv(t)
	caller := testCaller(t, 1)
	env.grantAll(caller.Actor().ID, "system", stats.ScopeGrant{Allowed: true, AllData: true})
	ctx := context.Background()

	// 成功审计写入失败：报告回滚为失败、删除产物、失败/取消终态不会留下成功审计。
	view, err := env.service.Start(ctx, env.startRequest(t))
	if err != nil {
		t.Fatalf("创建报告失败: %v", err)
	}
	reportID := view.ID
	job := env.enqueuer.last()
	env.tasks.jobs[job.ID] = job
	env.recorder.setFailSuccess(true)
	if err := env.service.GenerateHandler(ctx, job); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("成功审计失败生成错误 = %v，期望 ErrAuditUnavailable", err)
	}
	env.recorder.setFailSuccess(false)
	final, err := env.service.Get(ctx, caller, reportID)
	if err != nil {
		t.Fatalf("查询回滚报告失败: %v", err)
	}
	if final.State != StateFailed || final.ErrorCode != string(CodeAuditWriteFailed) {
		t.Fatalf("成功审计失败后终态不符: state=%s code=%s", final.State, final.ErrorCode)
	}
	if names := env.outputEntries(t); len(names) != 0 {
		t.Fatalf("成功审计失败后残留产物: %v", names)
	}
	if count := countEvents(env.recorder, ActionGenerateFinish, audit.OutcomeSuccess, reportID); count != 0 {
		t.Fatalf("回滚报告仍记录了 %d 条成功审计", count)
	}

	// 正常成功：恰好一条成功审计。
	okView, err := env.service.Start(ctx, env.startRequest(t))
	if err != nil {
		t.Fatalf("创建报告失败: %v", err)
	}
	okID := okView.ID
	job3 := env.enqueuer.last()
	env.tasks.jobs[job3.ID] = job3
	if err := env.service.GenerateHandler(ctx, job3); err != nil {
		t.Fatalf("正常生成失败: %v", err)
	}
	if count := countEvents(env.recorder, ActionGenerateFinish, audit.OutcomeSuccess, okID); count != 1 {
		t.Fatalf("正常成功审计条数 = %d，期望 1", count)
	}

	// 超时/取消终态不得记成功审计。
	for _, mode := range []string{"timeout", "cancel"} {
		view, err := env.service.Start(ctx, env.startRequest(t))
		if err != nil {
			t.Fatalf("创建 %s 报告失败: %v", mode, err)
		}
		job := env.enqueuer.last()
		env.tasks.jobs[job.ID] = job
		if mode == "timeout" {
			env.source.err = context.DeadlineExceeded
		} else {
			env.source.cancelled = true
		}
		_ = env.service.GenerateHandler(ctx, job)
		env.source.err = nil
		env.source.cancelled = false
		if count := countEvents(env.recorder, ActionGenerateFinish,
			audit.OutcomeSuccess, view.ID); count != 0 {
			t.Fatalf("%s 终态记录了 %d 条成功审计", mode, count)
		}
	}
}
