// Command report-schedule 演示定期报告生命周期的本地接线（步骤 79）。
//
// 它把真实组件接在一起：SQLite 迁移、报告历史/计划管理读模型仓储、internal/task
// 调度器与执行器、internal/reports 报告服务与计划服务，并使用确定性时钟手动推进
// 触发，不启动真实调度循环、不监听端口、不连接外部数据库。示例中的统计来源、
// 授权、root 判定与再次认证是明确标注的演示替身：生产宿主必须注入 internal/stats、
// internal/authz 适配器与真实敏感操作校验，不得把示例替身当作生产鉴权。
// 资源在函数返回前关闭，临时目录自动删除。
//
// 运行方式：go run ./examples/report-schedule
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/reports"
	reportsqlite "github.com/kagurazakayashi/EvernightLogin/internal/reports/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
	tasksqlite "github.com/kagurazakayashi/EvernightLogin/internal/task/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// demoClock 是确定性时钟；示例手动 Set 时间，不依赖真实等待。
type demoClock struct {
	mu  sync.Mutex
	now time.Time
}

// Now 返回当前示例时间。
func (c *demoClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Set 设置示例时间。
func (c *demoClock) Set(moment time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = moment.UTC()
}

// demoAuthorizer 是作用范围授权演示替身：只给固定演示用户全部数据范围权限。
// 生产必须注入 internal/authz 适配器（按当前账户/权限/数据范围重新判断）。
type demoAuthorizer struct{}

// AuthorizeScope 实现 reports/stats 的授权契约。
func (demoAuthorizer) AuthorizeScope(_ context.Context, _ account.Caller,
	_, _ string) (stats.ScopeGrant, error) {
	return stats.ScopeGrant{Allowed: true, AllData: true}, nil
}

// demoRoot 是 root 判定演示替身；生产必须读取受保护账户事实。
type demoRoot struct{}

// IsRoot 实现 stats.RootChecker。
func (demoRoot) IsRoot(context.Context, account.Caller) (bool, error) { return false, nil }

// demoSensitive 是敏感操作校验演示替身；生产必须注入 internal/reauth 服务，
// 验证近期强认证/一次性批准，不能默认放行。
type demoSensitive struct{}

// Authorize 实现 reauth.OperationRunner。
func (demoSensitive) Authorize(_ context.Context, _ reauth.Caller,
	request reauth.Request) (reauth.Result, error) {
	return reauth.Result{OperationID: request.OperationID}, nil
}

// NotifyOutcome 实现 reauth.OperationRunner。
func (demoSensitive) NotifyOutcome(context.Context, reauth.Result, reauth.Outcome) error {
	return nil
}

// demoSource 是统计来源演示替身：返回与请求窗口一致的固定数据；生产必须注入
// *stats.Service（其自身按调用者授权并裁剪数据范围）。
type demoSource struct{ now func() time.Time }

// window 返回请求规范化后的窗口。
func (s demoSource) window(request stats.WindowRequest) stats.Window {
	window, err := stats.NormalizeWindow(request, s.now())
	if err != nil {
		panic(err)
	}
	return window
}

// Activity 实现来源契约。
func (s demoSource) Activity(_ context.Context,
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
func (s demoSource) Errors(_ context.Context,
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
func (s demoSource) ErrorTrend(_ context.Context,
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

// demoNotifier 是报告结果通知演示替身：只打印受认证入口说明，不含令牌/链接。
type demoNotifier struct{}

// NotifyReport 实现 reports.Notifier。
func (demoNotifier) NotifyReport(_ context.Context,
	notification reports.ReportNotification) error {
	fmt.Printf("  通知（发送到报告所有者）：%s 报告 %s，状态 %s，入口 %s（需登录后重新鉴权）\n",
		notification.Kind, notification.ReportID, notification.State,
		notification.AuthenticatedEntry)
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "示例失败:", err)
		os.Exit(1)
	}
}

// run 执行完整示例；所有资源在函数返回前关闭。
func run() error {
	ctx := context.Background()
	dir, err := os.MkdirTemp("", "login-report-schedule-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	outputDir := filepath.Join(dir, "reports")
	if err := os.Mkdir(outputDir, 0o700); err != nil {
		return err
	}
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(
		filepath.Join(dir, "demo.db")))
	if err != nil {
		return err
	}
	defer raw.Close()
	migrationSet, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		return err
	}
	if _, err := raw.Migrate(ctx, migrationSet); err != nil {
		return err
	}
	// 真实安全审计存储：报告关键动作（生成/下载/计划变更）必须可追溯。
	auditStore, err := auditsqlite.New(raw)
	if err != nil {
		return err
	}
	clock := &demoClock{now: time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)}
	auditRecorder, err := audit.New(auditStore, audit.Options{Now: clock.Now})
	if err != nil {
		return err
	}
	reportStore, err := reportsqlite.New(raw)
	if err != nil {
		return err
	}
	projectionStore, err := reportsqlite.NewPlanProjectionStore(reportStore)
	if err != nil {
		return err
	}
	historyRecorder, err := reportsqlite.NewHistoryRecorder(reportStore)
	if err != nil {
		return err
	}
	taskStore, err := tasksqlite.New(raw, tasksqlite.Options{Now: clock.Now})
	if err != nil {
		return err
	}
	var plans *reports.PlanService
	var service *reports.Service
	executor, err := task.New(taskStore, task.Options{
		Handlers: map[string]task.Handler{
			reports.TaskKindPlannedReportGenerate: func(handlerCtx context.Context,
				job task.Job) error {
				return service.GenerateScheduledHandler(handlerCtx, job)
			},
			reports.TaskKindReportGenerate: func(handlerCtx context.Context,
				job task.Job) error {
				return service.GenerateHandler(handlerCtx, job)
			},
		},
		ExecutorID: "demo-report-executor", MaxConcurrent: 1,
		PollInterval: task.MinPollInterval, ShutdownTimeout: 3 * time.Second,
		Now: clock.Now,
		// 运行前权限复验：注册计划到执行器的任务默认要求复核，回调缺失时
		// 任务会失败而不是默认放行。
		PermissionCheck: func(checkCtx context.Context, request task.PermissionRequest) error {
			return plans.CheckExecutionPermission(checkCtx, request)
		},
	})
	if err != nil {
		return err
	}
	if err := executor.Start(ctx); err != nil {
		return err
	}
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = executor.Stop(stopCtx)
	}()
	scheduler, err := task.NewScheduler(task.SchedulerOptions{
		Store: taskStore, SchedulerID: "demo-report-scheduler", Executor: executor,
		PermissionCheck: func(checkCtx context.Context, request task.PermissionRequest) error {
			return plans.CheckExecutionPermission(checkCtx, request)
		},
		Now: clock.Now,
	})
	if err != nil {
		return err
	}
	plans, err = reports.NewPlanService(reports.PlanOptions{
		Schedules: scheduler, Authorizer: demoAuthorizer{}, Root: demoRoot{},
		Audit: auditRecorder, Now: clock.Now, MaxDetailRows: 20,
		Projections: projectionStore,
	})
	if err != nil {
		return err
	}
	service, err = reports.New(reports.Options{
		Source: demoSource{now: clock.Now}, Authorizer: demoAuthorizer{},
		Root: demoRoot{}, Sensitive: demoSensitive{}, Audit: auditRecorder,
		Enqueuer: executor, Canceller: executor, Tasks: executor,
		History: historyRecorder, Notifier: demoNotifier{},
		OutputDir: outputDir, MaxDetailRows: 20, Now: clock.Now})
	if err != nil {
		return err
	}
	// 宿主启动/周期任务应调用 ReconcilePlans 重建计划管理读模型（示例只演示一次）。
	if repaired, reconcileErr := plans.ReconcilePlans(ctx); reconcileErr != nil {
		return reconcileErr
	} else if repaired > 0 {
		fmt.Printf("启动对账修复了 %d 条计划投影\n", repaired)
	}
	caller, err := account.UserCaller("usr_00000000000000000000000000000001")
	if err != nil {
		return err
	}
	view, err := plans.Create(ctx, reports.PlanCreateRequest{
		Caller: caller, Name: "每日安全报告（演示）",
		ScheduleType: task.ScheduleTypeDaily, Expression: "09:00",
		TimeZone: "UTC", ScopeID: reports.ScopeSystem,
		Granularity: stats.GranularityDay, WindowDays: 1,
		Formats: []reports.Format{reports.FormatHTML}, Enabled: true,
		MissedPolicy: task.MissedLatest, MaxCatchUp: 1,
		TimeoutSeconds: 60, MaxAttempts: 1, RequestID: "req-demo-create",
	})
	if err != nil {
		return err
	}
	fmt.Printf("已创建计划 %s（稳定计划编号）\n", view.ID)
	// 到点触发：下次 09:00（UTC）后推进时钟并 Tick。
	clock.Set(time.Date(2026, 11, 20, 9, 1, 0, 0, time.UTC))
	if err := scheduler.Tick(ctx); err != nil {
		return err
	}
	reportID, err := waitSucceededReport(ctx, historyRecorder)
	if err != nil {
		return err
	}
	file, err := service.OpenFile(ctx, caller, reportID, reports.FormatHTML)
	if err != nil || file.Bytes == 0 {
		return fmt.Errorf("下载计划报告失败: bytes=%d err=%v", file.Bytes, err)
	}
	fmt.Printf("计划报告已生成并落库：%s（%d 字节），下载再次鉴权通过\n",
		reportID, file.Bytes)
	// 失权后触发被拒绝，不产生假报告；周期任务可进一步自动停用失权计划。
	view, err = plans.Get(ctx, caller, view.ID)
	if err != nil {
		return err
	}
	fmt.Printf("计划当前状态：已启用=%v，执行权限=%s，行版本=%d\n",
		view.Enabled, view.PermissionState, view.Version)
	fmt.Println("示例完成：计划触发、生成、历史落库与受控下载入口已接通。")
	return nil
}

// waitSucceededReport 等待历史中出现成功报告，返回其编号。
func waitSucceededReport(ctx context.Context,
	history *reportsqlite.HistoryRecorder) (string, error) {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		page, err := history.ListHistory(ctx, reports.HistoryQuery{
			Access: reports.AccessScope{AllData: true}, Limit: 20})
		if err != nil {
			return "", err
		}
		for _, record := range page.Records {
			if record.State == reports.StateSucceeded {
				return record.ReportID, nil
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	return "", errors.New("等待计划报告生成超时")
}
