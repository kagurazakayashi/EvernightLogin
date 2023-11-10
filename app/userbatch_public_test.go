package app

// 步骤 223：用户批量导入公开接口最小闭环测试。
//   - LocalAdmin：预检查、创建导入任务、真实任务执行到终态、逐行结果、任务列表、
//     幂等重复创建、终态取消/续跑拒绝；
//   - 普通用户：预检查/读取他人任务全部拒绝（owner 隔离）；
//   - 不存在任务：NOT_FOUND。
// 导出任务/失败续跑成功链依赖导出目录与失败注入，属未测范围（报告如实标注）。

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

// waitBatchTerminal 有界轮询任务直到终态。
func waitBatchTerminal(t *testing.T, ctx context.Context, runtime *Runtime,
	caller AdminCaller, jobID string) AdminUserBatchJob {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		job, err := runtime.UserBatch().GetJob(ctx, AdminUserBatchJobRequest{
			Caller: caller, JobID: jobID, RequestID: login.NewRequestID()})
		if err != nil {
			t.Fatalf("GetJob: %v", err)
		}
		switch job.State {
		case "succeeded", "partial", "failed", "cancelled":
			return job
		}
		if time.Now().After(deadline) {
			t.Fatalf("批量任务未在期限内到终态: %+v", job)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestUserBatchImportLifecycle 覆盖导入最小闭环与幂等/终态行为。
func TestUserBatchImportLifecycle(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 5, 0, 0, 0, time.UTC))
	runtime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	if err := runtime.Start(ctx); err != nil {
		t.Fatalf("启动运行时: %v", err)
	}
	local := runtime.LocalAdmin()
	batch := runtime.UserBatch()
	content := []byte("username,nickname\nbatch-alice,批量甲\nbatch-bob,批量乙\n")

	precheck, err := batch.PrecheckImport(ctx, AdminUserBatchPrecheckRequest{
		Caller: local, Content: content, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("PrecheckImport: %v", err)
	}
	if !precheck.CanImport || precheck.TotalRows != 2 || precheck.RejectedRows != 0 {
		t.Fatalf("预检查结果异常: %+v", precheck)
	}
	// 禁止列整文件拒绝（不静默忽略）。
	if _, err := batch.PrecheckImport(ctx, AdminUserBatchPrecheckRequest{
		Caller: local, Content: []byte("username,password\nbad,secret\n"),
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("禁止列表头错误 = %v，期望 REQ_INVALID", err)
	}

	const idempotencyKey = "step223-import-1"
	start, err := batch.StartImport(ctx, AdminUserBatchImportRequest{
		Caller: local, IdempotencyKey: idempotencyKey, Content: content,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("StartImport: %v", err)
	}
	if start.Duplicate || start.Job.ID == "" || start.Job.Kind != "import" {
		t.Fatalf("创建导入任务结果异常: %+v", start)
	}
	if start.Report == nil || start.Report.TotalRows != 2 {
		t.Fatalf("导入预检查报告异常: %+v", start.Report)
	}
	terminal := waitBatchTerminal(t, ctx, runtime, local, start.Job.ID)
	if terminal.State != "succeeded" || terminal.CreatedCount != 2 ||
		terminal.TotalRows != 2 {
		t.Fatalf("导入任务终态异常: %+v", terminal)
	}

	rows, err := batch.ListRows(ctx, AdminUserBatchRowsRequest{
		Caller: local, JobID: start.Job.ID, Limit: 10, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("ListRows: %v", err)
	}
	if len(rows.Rows) != 2 || rows.Truncated {
		t.Fatalf("逐行结果异常: %+v", rows)
	}
	if rows.Rows[0].UsernameNormalized == "" || rows.Rows[0].Action == "" {
		t.Fatalf("逐行字段异常: %+v", rows.Rows[0])
	}

	jobs, err := batch.ListJobs(ctx, AdminUserBatchListJobsRequest{
		Caller: local, Page: AdminPage{Limit: 10}, RequestID: login.NewRequestID()})
	if err != nil || len(jobs.Jobs) != 1 || jobs.HasMore {
		t.Fatalf("任务列表异常: %+v, %v", jobs, err)
	}

	// 幂等：同键同内容 → Duplicate=true 且复用同一任务；同键不同内容 → CONFLICT。
	duplicate, err := batch.StartImport(ctx, AdminUserBatchImportRequest{
		Caller: local, IdempotencyKey: idempotencyKey, Content: content,
		RequestID: login.NewRequestID()})
	if err != nil || !duplicate.Duplicate || duplicate.Job.ID != start.Job.ID {
		t.Fatalf("幂等重复创建异常: %+v, %v", duplicate, err)
	}
	if _, err := batch.StartImport(ctx, AdminUserBatchImportRequest{
		Caller: local, IdempotencyKey: idempotencyKey,
		Content:   []byte("username\nbatch-carol\n"),
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeConflict) {
		t.Fatalf("同键不同内容错误 = %v，期望 CONFLICT", err)
	}

	// 终态任务：取消与续跑均为稳定 CONFLICT。
	if _, err := batch.CancelJob(ctx, AdminUserBatchCancelRequest{
		Caller: local, JobID: start.Job.ID, Reason: "终态取消",
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeConflict) {
		t.Fatalf("终态取消错误 = %v，期望 CONFLICT", err)
	}
	if _, err := batch.RetryJob(ctx, AdminUserBatchJobRequest{
		Caller: local, JobID: start.Job.ID,
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeConflict) {
		t.Fatalf("成功任务续跑错误 = %v，期望 CONFLICT", err)
	}
}

// TestUserBatchOwnerIsolation 覆盖普通用户不能预检查/读取他人批量任务。
func TestUserBatchOwnerIsolation(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 5, 10, 0, 0, time.UTC))
	runtime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	const password = "K8$wR3!nB6@yF1#v"
	createLifecycleUser(t, ctx, runtime, "batch-normal", password)
	session := loginLifecycleUser(t, ctx, runtime, "batch-normal", password)
	normalCaller := runtime.AdminSession(session)

	if _, err := runtime.UserBatch().PrecheckImport(ctx,
		AdminUserBatchPrecheckRequest{Caller: normalCaller,
			Content: []byte("username\nbatch-x\n"), RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeAccessDenied) {
		t.Fatalf("普通用户预检查错误 = %v，期望 ACCESS_DENIED", err)
	}
	if _, err := runtime.UserBatch().GetJob(ctx, AdminUserBatchJobRequest{
		Caller: normalCaller, JobID: "ubj_00000000000000000000000000000000",
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err,
		login.CodeAccessDenied) {
		t.Fatalf("普通用户读取任务错误 = %v，期望 ACCESS_DENIED", err)
	}
	// 受信本地通道读取不存在任务 → NOT_FOUND。
	if _, err := runtime.UserBatch().GetJob(ctx, AdminUserBatchJobRequest{
		Caller:    runtime.LocalAdmin(),
		JobID:     "ubj_00000000000000000000000000000000",
		RequestID: login.NewRequestID()}); !IsNotFound(err) {
		t.Fatalf("不存在任务错误 = %v，期望 NOT_FOUND (%s)", err,
			fmt.Sprint(IsNotFound(err)))
	}
}
