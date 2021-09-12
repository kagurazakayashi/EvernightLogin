package sqlite

// 本文件是步骤 79 的调度 Tick 端到端测试：真实 SQLite 迁移 + 真实 task.Scheduler /
// task.Executor + 真实报告计划/历史仓储适配器，验证
// 「到点触发 → 同计划触发去重 → 停机补跑 → 生成 → 历史落库 → 失权拒绝与自动停用」。
// 统计来源与授权/审计使用明确标注的测试替身，只验证报告生命周期语义，不进入生产装配。

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/reports"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
	tasksqlite "github.com/kagurazakayashi/EvernightLogin/internal/task/sqlite"
	appmigrations "github.com/kagurazakayashi/EvernightLogin/migrations"
)

// e2eNow 是端到端测试的初始时钟。
var e2eNow = time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)

// e2eAuthorizer 是按权限/范围键控的授权替身。
type e2eAuthorizer struct {
	mu     sync.Mutex
	grants map[string]stats.ScopeGrant
}

// AuthorizeScope 实现 stats.Authorizer。
func (a *e2eAuthorizer) AuthorizeScope(_ context.Context, _ account.Caller,
	permissionKey, scopeID string) (stats.ScopeGrant, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.grants[permissionKey+":"+scopeID], nil
}

// allow 设置授权结果。
func (a *e2eAuthorizer) allow(permission, scopeID string, grant stats.ScopeGrant) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.grants[permission+":"+scopeID] = grant
}

// deny 撤销授权。
func (a *e2eAuthorizer) deny(permission, scopeID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.grants, permission+":"+scopeID)
}

// e2eRoot 返回非 root 调用者。
type e2eRoot struct{}

// IsRoot 实现 stats.RootChecker。
func (e2eRoot) IsRoot(context.Context, account.Caller) (bool, error) { return false, nil }

// e2eSensitive 是敏感操作校验替身（本测试不使用清理流程）。
type e2eSensitive struct{}

// Authorize 实现 reauth.OperationRunner。
func (e2eSensitive) Authorize(_ context.Context, _ reauth.Caller,
	request reauth.Request) (reauth.Result, error) {
	return reauth.Result{OperationID: request.OperationID}, nil
}

// NotifyOutcome 实现 reauth.OperationRunner。
func (e2eSensitive) NotifyOutcome(context.Context, reauth.Result, reauth.Outcome) error {
	return nil
}

// e2eAudit 是审计写入替身。
type e2eAudit struct{}

// Record 实现审计记录。
func (e2eAudit) Record(context.Context, audit.Event) error { return nil }

// RecordFailure 实现失败审计记录。
func (e2eAudit) RecordFailure(context.Context, audit.Event) error { return nil }

// ExecuteCritical 实现关键变更事务契约。
func (e2eAudit) ExecuteCritical(context.Context, audit.CriticalRequest,
	audit.Change) error {
	return nil
}

// e2eSource 是统计来源替身：返回与请求窗口一致的完整数据，不访问网络。
type e2eSource struct {
	now func() time.Time
}

// window 返回请求规范化后的窗口。
func (s e2eSource) window(request stats.WindowRequest) stats.Window {
	window, err := stats.NormalizeWindow(request, s.now())
	if err != nil {
		panic(err)
	}
	return window
}

// Activity 实现来源契约。
func (s e2eSource) Activity(_ context.Context,
	request stats.ActivityRequest) (stats.ActivityResult, error) {
	window := s.window(request.Window)
	points := make([]stats.ActivityPoint, 0, len(window.Buckets))
	for _, bucket := range window.Buckets {
		points = append(points, stats.ActivityPoint{Bucket: bucket, ActiveUsers: 3,
			DataStatus: stats.DataComplete})
	}
	return stats.ActivityResult{Window: window, Metric: stats.MetricActiveUsers,
		DedupeScope: "system", Points: points, TotalActiveUsers: 3,
		Completeness: stats.Completeness{WindowWithinRetention: true,
			RetentionDays: 30, RetentionConfigured: true,
			RetentionCutoff: s.now().AddDate(0, 0, -30)},
		GeneratedAt: s.now()}, nil
}

// Errors 实现来源契约。
func (s e2eSource) Errors(_ context.Context,
	request stats.ErrorRequest) (stats.ErrorResult, error) {
	window := s.window(request.Window)
	return stats.ErrorResult{Window: window, Sort: stats.ErrorSortRaw,
		Order: stats.SortDesc, Limit: request.Limit,
		Completeness: stats.Completeness{WindowWithinRetention: true,
			RetentionDays: 30, RetentionConfigured: true,
			RetentionCutoff: s.now().AddDate(0, 0, -30)},
		GeneratedAt: s.now()}, nil
}

// ErrorTrend 实现来源契约。
func (s e2eSource) ErrorTrend(_ context.Context,
	request stats.ErrorTrendRequest) (stats.ErrorTrendResult, error) {
	window := s.window(request.Window)
	metric := request.Metric
	if metric == "" {
		metric = stats.MetricRawEvents
	}
	return stats.ErrorTrendResult{Window: window, Metric: metric,
		Completeness: stats.Completeness{WindowWithinRetention: true,
			RetentionDays: 30, RetentionConfigured: true,
			RetentionCutoff: s.now().AddDate(0, 0, -30)},
		GeneratedAt: s.now()}, nil
}

// e2eUserCaller 构造稳定测试调用者。
func e2eUserCaller(t *testing.T) account.Caller {
	t.Helper()
	caller, err := account.UserCaller("usr_00000000000000000000000000000001")
	if err != nil {
		t.Fatalf("构造调用者失败: %v", err)
	}
	return caller
}

// e2eHistoryIDs 返回历史中成功的报告编号集合。
func e2eHistoryIDs(t *testing.T, history *HistoryRecorder) map[string]reports.HistoryRecord {
	t.Helper()
	page, err := history.ListHistory(context.Background(), reports.HistoryQuery{
		Access: reports.AccessScope{AllData: true}, Limit: 100})
	if err != nil {
		t.Fatalf("读取历史失败: %v", err)
	}
	records := make(map[string]reports.HistoryRecord)
	for _, record := range page.Records {
		records[record.ReportID] = record
	}
	return records
}

// e2eSucceededCount 返回历史中成功报告数量。
func e2eSucceededCount(t *testing.T, history *HistoryRecorder) int {
	t.Helper()
	count := 0
	for _, record := range e2eHistoryIDs(t, history) {
		if record.State == reports.StateSucceeded {
			count++
		}
	}
	return count
}

// waitFor 轮询条件直到成立或超时；失败时报告当前历史状态便于排障。
func waitFor(t *testing.T, description string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("等待超时: %s", description)
}

// TestSchedulerTickReportLifecycle 验证计划到点触发、去重、停机补跑、生成落库、
// 失权拒绝与自动停用整链。
func TestSchedulerTickReportLifecycle(t *testing.T) {
	ctx := context.Background()
	var now = e2eNow
	nowFn := func() time.Time { return now }

	dbPath := filepath.Join(t.TempDir(), "reports-e2e.db")
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(dbPath))
	if err != nil {
		t.Fatalf("打开临时 SQLite 失败: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	migrationSet, err := migrate.LoadMigrations(appmigrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移失败: %v", err)
	}
	if _, err := raw.Migrate(ctx, migrationSet); err != nil {
		t.Fatalf("执行迁移失败: %v", err)
	}
	reportStore, err := New(raw)
	if err != nil {
		t.Fatalf("构造报告仓储失败: %v", err)
	}
	projectionStore, err := NewPlanProjectionStore(reportStore)
	if err != nil {
		t.Fatalf("构造计划投影仓储失败: %v", err)
	}
	history, err := NewHistoryRecorder(reportStore)
	if err != nil {
		t.Fatalf("构造历史仓储失败: %v", err)
	}
	taskStore, err := tasksqlite.New(raw, tasksqlite.Options{Now: nowFn})
	if err != nil {
		t.Fatalf("构造任务存储失败: %v", err)
	}
	authorizer := &e2eAuthorizer{grants: map[string]stats.ScopeGrant{}}
	caller := e2eUserCaller(t)
	for _, permission := range []string{reports.PermissionRead,
		reports.PermissionGenerate, reports.PermissionExport,
		reports.PermissionScheduleManage, reports.PermissionCleanup} {
		authorizer.allow(permission, reports.ScopeSystem,
			stats.ScopeGrant{Allowed: true, AllData: true})
	}
	var plans *reports.PlanService
	var service *reports.Service
	executor, err := task.New(taskStore, task.Options{
		Handlers: map[string]task.Handler{
			reports.TaskKindPlannedReportGenerate: func(handlerCtx context.Context,
				job task.Job) error {
				if service == nil {
					return errors.New("报告服务尚未装配")
				}
				return service.GenerateScheduledHandler(handlerCtx, job)
			},
		},
		ExecutorID: "e2e-executor", MaxConcurrent: 1,
		PollInterval: 50 * time.Millisecond, ShutdownTimeout: 3 * time.Second,
		Now: nowFn,
		PermissionCheck: func(checkCtx context.Context, request task.PermissionRequest) error {
			return plans.CheckExecutionPermission(checkCtx, request)
		},
	})
	if err != nil {
		t.Fatalf("构造执行器失败: %v", err)
	}
	scheduler, err := task.NewScheduler(task.SchedulerOptions{
		Store: taskStore, SchedulerID: "e2e-scheduler",
		PermissionCheck: func(checkCtx context.Context, request task.PermissionRequest) error {
			return plans.CheckExecutionPermission(checkCtx, request)
		},
		TickInterval: 100 * time.Millisecond, CatchUpGrace: time.Hour, Now: nowFn,
	})
	if err != nil {
		t.Fatalf("构造调度器失败: %v", err)
	}
	plans, err = reports.NewPlanService(reports.PlanOptions{
		Schedules: scheduler, Authorizer: authorizer, Root: e2eRoot{},
		Audit: e2eAudit{}, Now: nowFn, MaxDetailRows: 20,
		Projections: projectionStore,
	})
	if err != nil {
		t.Fatalf("构造计划服务失败: %v", err)
	}
	service, err = reports.New(reports.Options{
		Source: e2eSource{now: nowFn}, Authorizer: authorizer, Root: e2eRoot{},
		Sensitive: e2eSensitive{}, Audit: e2eAudit{}, Enqueuer: executor,
		Canceller: executor, Tasks: executor, History: history,
		OutputDir: t.TempDir(), MaxDetailRows: 20, Now: nowFn,
	})
	if err != nil {
		t.Fatalf("构造报告服务失败: %v", err)
	}
	if err := executor.Start(ctx); err != nil {
		t.Fatalf("启动执行器失败: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = executor.Stop(stopCtx)
	})
	view, err := plans.Create(ctx, reports.PlanCreateRequest{
		Caller: caller, Name: "端到端每日报告",
		ScheduleType: task.ScheduleTypeDaily, Expression: "09:00",
		TimeZone: "UTC", ScopeID: reports.ScopeSystem,
		Granularity: stats.GranularityDay, WindowDays: 1,
		Formats: []reports.Format{reports.FormatHTML}, Enabled: true,
		MissedPolicy: task.MissedAll, MaxCatchUp: 5,
		TimeoutSeconds: 60, MaxAttempts: 1, RequestID: "req-e2e-create",
	})
	if err != nil {
		t.Fatalf("创建计划失败: %v", err)
	}
	// 到点触发：下一次 09:00（UTC）后推进时钟并 Tick。
	now = time.Date(2026, 11, 20, 9, 1, 0, 0, time.UTC)
	if err := scheduler.Tick(ctx); err != nil {
		t.Fatalf("第一次 Tick 失败: %v", err)
	}
	firstDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(firstDeadline) && e2eSucceededCount(t, history) < 1 {
		time.Sleep(25 * time.Millisecond)
	}
	if e2eSucceededCount(t, history) < 1 {
		for id, record := range e2eHistoryIDs(t, history) {
			t.Logf("调试历史 %s state=%s code=%s reason=%s task=%s",
				id, record.State, record.ErrorCode, record.FailureReason, record.TaskID)
		}
		t.Fatalf("首份计划报告未生成")
	}
	records := e2eHistoryIDs(t, history)
	for _, record := range records {
		if record.State != reports.StateSucceeded {
			continue
		}
		if record.PlanID != view.ID {
			t.Fatalf("历史计划编号 = %q，期望 %q", record.PlanID, view.ID)
		}
		file, openErr := service.OpenFile(ctx, caller, record.ReportID,
			reports.FormatHTML)
		if openErr != nil || file.Bytes == 0 {
			t.Fatalf("计划报告下载失败: bytes=%d err=%v", file.Bytes, openErr)
		}
	}
	// 同计划去重：同一触发时刻重复 Tick 不新增历史。
	before := e2eSucceededCount(t, history)
	if err := scheduler.Tick(ctx); err != nil {
		t.Fatalf("重复 Tick 失败: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	if after := e2eSucceededCount(t, history); after != before {
		t.Fatalf("重复 Tick 后成功报告数 = %d，期望保持 %d", after, before)
	}
	// 停机补跑：时钟前进 3 天，按 MissedAll 补跑错过触发。
	now = time.Date(2026, 11, 23, 9, 1, 0, 0, time.UTC)
	if err := scheduler.Tick(ctx); err != nil {
		t.Fatalf("补跑 Tick 失败: %v", err)
	}
	waitFor(t, "停机补跑的报告生成并落库", func() bool {
		return e2eSucceededCount(t, history) >= before+3
	})
	catchUp := e2eSucceededCount(t, history)
	for _, record := range e2eHistoryIDs(t, history) {
		if record.State == reports.StateSucceeded && record.PlanID != view.ID {
			t.Fatalf("补跑历史计划编号异常: %q", record.PlanID)
		}
	}
	// 失权：撤销执行身份权限后，触发被拒绝且不产生假报告/历史。
	authorizer.deny(reports.PermissionGenerate, reports.ScopeSystem)
	now = time.Date(2026, 11, 24, 9, 1, 0, 0, time.UTC)
	if err := scheduler.Tick(ctx); err != nil {
		t.Fatalf("失权 Tick 失败: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	if after := e2eSucceededCount(t, history); after != catchUp {
		t.Fatalf("失权触发后成功报告数 = %d，期望保持 %d", after, catchUp)
	}
	disabled, err := plans.DisableRevokedPlans(ctx)
	if err != nil || disabled != 1 {
		t.Fatalf("自动停用失权计划 = %d, err=%v，期望 1", disabled, err)
	}
	paused, err := plans.Get(ctx, caller, view.ID)
	if err != nil || paused.Enabled || paused.PermissionState != reports.PlanPermissionRevoked {
		t.Fatalf("停用后计划 = %+v err=%v", paused, err)
	}
	// 重启恢复：关闭执行器与数据库后重新打开同一 SQLite 文件，计划、历史与
	// 计划管理读模型必须仍然存在且可读。
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := executor.Stop(stopCtx); err != nil {
		t.Fatalf("停止执行器失败: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("关闭数据库失败: %v", err)
	}
	reopened, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(dbPath))
	if err != nil {
		t.Fatalf("重启后打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	restartTaskStore, err := tasksqlite.New(reopened, tasksqlite.Options{Now: nowFn})
	if err != nil {
		t.Fatalf("重启后构造任务存储失败: %v", err)
	}
	restartScheduler, err := task.NewScheduler(task.SchedulerOptions{
		Store: restartTaskStore, SchedulerID: "e2e-restart-scheduler",
		TickInterval: 100 * time.Millisecond, Now: nowFn,
	})
	if err != nil {
		t.Fatalf("重启后构造调度器失败: %v", err)
	}
	schedules, err := restartScheduler.List(ctx)
	if err != nil {
		t.Fatalf("重启后读取计划失败: %v", err)
	}
	persisted := false
	for _, schedule := range schedules {
		if schedule.JobKind != reports.TaskKindPlannedReportGenerate {
			continue
		}
		var payload map[string]any
		if decodeErr := json.Unmarshal(schedule.Payload, &payload); decodeErr != nil {
			continue
		}
		if payload["plan_id"] == view.ID {
			persisted = true
		}
	}
	if !persisted {
		t.Fatalf("重启后执行计划载荷未保留计划编号 %s", view.ID)
	}
	restartReportStore, err := New(reopened)
	if err != nil {
		t.Fatalf("重启后构造报告仓储失败: %v", err)
	}
	restartHistory, err := NewHistoryRecorder(restartReportStore)
	if err != nil {
		t.Fatalf("重启后构造历史适配器失败: %v", err)
	}
	if count := e2eSucceededCount(t, restartHistory); count < catchUp {
		t.Fatalf("重启后成功历史数 = %d，期望至少 %d", count, catchUp)
	}
	restartProjections, err := NewPlanProjectionStore(restartReportStore)
	if err != nil {
		t.Fatalf("重启后构造计划投影适配器失败: %v", err)
	}
	projection, found, err := restartProjections.GetPlanProjection(ctx, view.ID)
	if err != nil || !found || projection.Version < 1 {
		t.Fatalf("重启后计划投影 = %+v found=%v err=%v", projection, found, err)
	}
}
