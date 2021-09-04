package reports

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
	tasksqlite "github.com/kagurazakayashi/EvernightLogin/internal/task/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// TestGenerateViaRealTaskExecutor 验证真实 *task.Executor 可直接注入 Enqueuer/
// Canceller/Tasks（签名对齐）并完成一次报告生成；任务摘要来自真实任务读取。
func TestGenerateViaRealTaskExecutor(t *testing.T) {
	ctx := context.Background()
	now := func() time.Time { return baseTime }
	outputDir := t.TempDir()

	// 任务存储：临时 SQLite + 全部迁移。
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(
		filepath.Join(t.TempDir(), "reports-task.db")))
	if err != nil {
		t.Fatalf("打开临时 SQLite 失败: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	migrationSet, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移失败: %v", err)
	}
	if _, err := raw.Migrate(ctx, migrationSet); err != nil {
		t.Fatalf("执行迁移失败: %v", err)
	}
	taskStore, err := tasksqlite.New(raw, tasksqlite.Options{Now: now})
	if err != nil {
		t.Fatalf("构造任务存储失败: %v", err)
	}

	// 报告服务与真实执行器互相引用：先声明 handler 闭包变量，再构造执行器与服务。
	var service *Service
	executor, err := task.New(taskStore, task.Options{
		Handlers: map[string]task.Handler{
			TaskKindReportGenerate: func(handlerCtx context.Context, job task.Job) error {
				return service.GenerateHandler(handlerCtx, job)
			},
		},
		ExecutorID: "exec-reports-test", MaxConcurrent: 1,
		PollInterval: task.MinPollInterval, ShutdownTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("构造真实任务执行器失败: %v", err)
	}
	authorizer := &fakeAuthorizer{grants: map[string]stats.ScopeGrant{}}
	root := &fakeRoot{roots: map[string]bool{}}
	sensitive := &fakeSensitive{}
	recorder := &fakeRecorder{}
	source := &fakeSource{now: now, activity: 7,
		completeness: stats.Completeness{WindowWithinRetention: true,
			RetentionDays: 30, RetentionConfigured: true,
			RetentionCutoff: baseTime.AddDate(0, 0, -30)},
		rows: []stats.ErrorRow{{ErrorCode: "AUTH_FAILED",
			Category: stats.CategoryFailure, Severity: stats.SeverityError,
			AppID: "app_demo1", RawEvents: 2, FailedRequests: 1,
			FirstSeen: baseTime.Add(-time.Hour), LastSeen: baseTime.Add(-time.Minute),
			Growth:     stats.Growth{Kind: stats.GrowthNone},
			DataStatus: stats.DataComplete}}}
	service, err = New(Options{Source: source, Authorizer: authorizer, Root: root,
		Sensitive: sensitive, Audit: recorder, Enqueuer: executor,
		Canceller: executor, Tasks: executor, OutputDir: outputDir,
		MaxDetailRows: 20, Now: now})
	if err != nil {
		t.Fatalf("构造报告服务失败: %v", err)
	}
	if err := executor.Start(ctx); err != nil {
		t.Fatalf("启动任务执行器失败: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = executor.Stop(stopCtx)
	})

	caller := testCaller(t, 1)
	for _, permission := range []string{PermissionRead, PermissionGenerate, PermissionExport} {
		authorizer.allow(permission, "system", stats.ScopeGrant{Allowed: true, AllData: true})
	}
	view, err := service.Start(ctx, StartRequest{Caller: caller, ScopeID: "system",
		Window: stats.WindowRequest{TimeZone: "Asia/Shanghai",
			Start: baseTime.Add(-24 * time.Hour), End: baseTime,
			Granularity: stats.GranularityDay},
		Formats: []Format{FormatHTML, FormatJSON}})
	if err != nil {
		t.Fatalf("创建报告失败: %v", err)
	}
	if view.TaskID == "" {
		t.Fatal("真实执行器未返回任务编号")
	}
	deadline := time.Now().Add(10 * time.Second)
	var final ReportView
	for {
		final, err = service.Get(ctx, caller, view.ID)
		if err != nil {
			t.Fatalf("查询报告失败: %v", err)
		}
		if final.State == StateSucceeded || final.State == StateFailed ||
			final.State == StateCancelled {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("等待真实执行器完成超时，最后状态 %s", final.State)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if final.State != StateSucceeded {
		t.Fatalf("真实执行器生成失败: state=%s code=%s reason=%s",
			final.State, final.ErrorCode, final.FailureReason)
	}
	if final.Task == nil || final.Task.ID != view.TaskID {
		t.Fatalf("未从真实 *task.Executor 读取任务摘要: %+v (taskid=%s)", final.Task, view.TaskID)
	}
	if final.Task.State != string(task.StateSucceeded) {
		t.Fatalf("任务摘要状态 = %s，期望 succeeded", final.Task.State)
	}
	file, err := service.OpenFile(ctx, caller, view.ID, FormatJSON)
	if err != nil {
		t.Fatalf("下载真实执行器产物失败: %v", err)
	}
	if file.Bytes == 0 || file.SHA256 == "" {
		t.Fatalf("产物句柄不完整: %+v", file)
	}
}
