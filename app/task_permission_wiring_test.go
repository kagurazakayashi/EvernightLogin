package app

// 步骤 230 随附修复：任务运行前权限复验接线验证。
//   - 未登记任务类型必须 fail-closed（TASK_PERMISSION_REVOKED）；
//   - 普通用户对 audit.export/audit.purge 无权限时，即使直接入队也被执行器拒绝；
//   - 本机受信操作者的同类型任务可执行（导出成功链已在 TestAuditExportPublicFacade）。

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

func TestTaskPermissionRecheckFailClosed(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 13, 0, 0, 0, time.UTC))
	runtime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	if err := runtime.Start(ctx); err != nil {
		t.Fatalf("启动运行时: %v", err)
	}
	user, err := runtime.Users().Create(ctx, CreateUserRequest{
		Username: "task-perm-user", Password: "T4!kR8#wQ2@mN6$z",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建任务权限用户: %v", err)
	}
	executor := runtime.base.Tasks.Executor()
	cases := []struct {
		name string
		kind string
	}{
		{name: "审计导出无权限", kind: "audit.export"},
		{name: "审计清理无权限", kind: "audit.purge"},
		{name: "未登记任务类型", kind: "test.unmapped.required"},
	}
	for _, testCase := range cases {
		job, err := executor.Enqueue(ctx, task.EnqueueRequest{Kind: testCase.kind,
			Actor:   audit.Actor{Type: audit.ActorUser, ID: user.ID},
			Payload: json.RawMessage(`{}`), TimeoutSeconds: 30, MaxAttempts: 1,
			PermissionRequired: true, RequestID: login.NewRequestID()})
		if err != nil {
			t.Fatalf("%s 入队: %v", testCase.name, err)
		}
		final := waitTaskPermissionTerminal(t, ctx, executor, job.ID)
		if final.State != task.StateFailed ||
			final.ErrorCode != "TASK_PERMISSION_REVOKED" {
			t.Fatalf("%s 终态 = %+v，期望 fail-closed TASK_PERMISSION_REVOKED",
				testCase.name, final)
		}
	}
	// 受信本机主体：运行前权限复验放行，任务能进入真实处理器（处理器再校验载荷/
	// 数据范围；这里只证明权限闸门不再误杀受信主体）。
	for _, kind := range []string{"audit.export", "audit.purge",
		"backup.create", "backup.cleanup"} {
		job, err := executor.Enqueue(ctx, task.EnqueueRequest{Kind: kind,
			Actor:   audit.Actor{Type: audit.ActorLocalAdmin, ID: "host-operator"},
			Payload: json.RawMessage(`{}`), TimeoutSeconds: 30, MaxAttempts: 1,
			PermissionRequired: true, RequestID: login.NewRequestID()})
		if err != nil {
			t.Fatalf("受信主体入队 %s: %v", kind, err)
		}
		final := waitTaskPermissionTerminal(t, ctx, executor, job.ID)
		if final.ErrorCode == "TASK_PERMISSION_REVOKED" {
			t.Fatalf("受信主体任务 %s 不应被权限闸门拒绝: %+v", kind, final)
		}
	}
}

// waitTaskPermissionTerminal 轮询任务终态，最多 10 秒。
func waitTaskPermissionTerminal(t *testing.T, ctx context.Context,
	executor *task.Executor, jobID string) task.Job {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		job, err := executor.Get(ctx, jobID)
		if err != nil {
			t.Fatalf("读取任务终态: %v", err)
		}
		switch job.State {
		case task.StateSucceeded, task.StateFailed, task.StateCancelled,
			task.StateTimedOut:
			return job
		}
		if time.Now().After(deadline) {
			t.Fatalf("任务未在期限内结束: state=%s", job.State)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
