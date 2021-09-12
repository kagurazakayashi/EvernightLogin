package uiadminadapter

// 步骤 79 修复轮 M5：报告页面适配器真实服务集成测试。
//
// 使用真实 SQLite（全部迁移）+ 真实 internal/reports.Service/PlanService +
// reports/sqlite 历史/计划投影仓储 + 真实 task.Scheduler + 真实 audit.Recorder，
// 只把统计来源/权限引擎/root 判定/再次认证/任务入队这些外部模块替换为明确标注的
// 替身。覆盖：能力位、历史列表/详情/预览、下载令牌签发+兑换、重试、清理预览+执行、
// 计划 CRUD/启停/编辑行版本冲突、越权 fail-closed。临时数据库与产物目录随测试清理。

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
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
	appmigrations "github.com/kagurazakayashi/EvernightLogin/migrations"
)

// m5Authorizer 是按权限键控的授权替身（真实权限引擎由宿主注入）。
type m5Authorizer struct {
	mu     sync.Mutex
	grants map[string]stats.ScopeGrant
}

func (a *m5Authorizer) AuthorizeScope(_ context.Context, _ account.Caller,
	permissionKey, _ string) (stats.ScopeGrant, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.grants[permissionKey], nil
}

func (a *m5Authorizer) allowAll(permissions ...string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, permission := range permissions {
		a.grants[permission] = stats.ScopeGrant{Allowed: true, AllData: true}
	}
}

func (a *m5Authorizer) denyAll() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.grants = map[string]stats.ScopeGrant{}
}

// m5Root 永远返回非 root。
type m5Root struct{}

func (m5Root) IsRoot(context.Context, account.Caller) (bool, error) { return false, nil }

// m5Sensitive 是再次认证替身（真实策略引擎由宿主注入）。
type m5Sensitive struct{}

func (m5Sensitive) Authorize(_ context.Context, _ reauth.Caller,
	request reauth.Request) (reauth.Result, error) {
	return reauth.Result{OperationID: request.OperationID}, nil
}

func (m5Sensitive) NotifyOutcome(context.Context, reauth.Result, reauth.Outcome) error {
	return nil
}

// m5Source 是统计来源替身：返回与请求窗口一致的固定数据。
type m5Source struct {
	now    func() time.Time
	failed bool
}

func (s *m5Source) window(request stats.WindowRequest) stats.Window {
	window, err := stats.NormalizeWindow(request, s.now())
	if err != nil {
		panic(err)
	}
	return window
}

func (s *m5Source) completeness() stats.Completeness {
	return stats.Completeness{WindowWithinRetention: true, RetentionDays: 30,
		RetentionConfigured: true, RetentionCutoff: s.now().AddDate(0, 0, -30)}
}

func (s *m5Source) Activity(_ context.Context,
	request stats.ActivityRequest) (stats.ActivityResult, error) {
	if s.failed {
		return stats.ActivityResult{}, errors.New("来源不可用")
	}
	window := s.window(request.Window)
	points := make([]stats.ActivityPoint, 0, len(window.Buckets))
	for _, bucket := range window.Buckets {
		points = append(points, stats.ActivityPoint{Bucket: bucket,
			ActiveUsers: 3, DataStatus: stats.DataComplete})
	}
	return stats.ActivityResult{Window: window, Metric: stats.MetricActiveUsers,
		DedupeScope: "system", Points: points, TotalActiveUsers: 3,
		Completeness: s.completeness(), GeneratedAt: s.now()}, nil
}

func (s *m5Source) Errors(_ context.Context,
	request stats.ErrorRequest) (stats.ErrorResult, error) {
	if s.failed {
		return stats.ErrorResult{}, errors.New("来源不可用")
	}
	window := s.window(request.Window)
	return stats.ErrorResult{Window: window, Sort: stats.ErrorSortRaw,
		Order: stats.SortDesc, Limit: request.Limit,
		Completeness: s.completeness(), GeneratedAt: s.now()}, nil
}

func (s *m5Source) ErrorTrend(_ context.Context,
	request stats.ErrorTrendRequest) (stats.ErrorTrendResult, error) {
	if s.failed {
		return stats.ErrorTrendResult{}, errors.New("来源不可用")
	}
	window := s.window(request.Window)
	metric := request.Metric
	if metric == "" {
		metric = stats.MetricRawEvents
	}
	return stats.ErrorTrendResult{Window: window, Metric: metric,
		Completeness: s.completeness(), GeneratedAt: s.now()}, nil
}

// m5Enqueuer 记录任务入队并返回稳定任务（真实执行器由宿主注入；本测试同步调用
// 生成处理器验证真实 Service 生成语义）。
type m5Enqueuer struct {
	mu   sync.Mutex
	jobs []task.Job
}

func (e *m5Enqueuer) Enqueue(_ context.Context,
	request task.EnqueueRequest) (task.Job, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	job := task.Job{ID: "job_m5_" + time.Now().Format("150405.000000"),
		Kind: request.Kind, Initiator: request.Actor, Payload: request.Payload,
		RequestID: request.RequestID}
	e.jobs = append(e.jobs, job)
	return job, nil
}

func (e *m5Enqueuer) last() task.Job {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.jobs[len(e.jobs)-1]
}

// m5Canceller 是取消契约替身（取消页面路径由根包页面测试覆盖）。
type m5Canceller struct{}

func (m5Canceller) RequestCancel(context.Context,
	task.CancelRequest) (task.CancelResult, error) {
	return task.CancelResult{Accepted: true, State: task.StateCancelled}, nil
}

// m5Env 是适配器真实服务集成测试环境。
type m5Env struct {
	t          *testing.T
	adapter    *ReportsAdapter
	service    *reports.Service
	plans      *reports.PlanService
	authorizer *m5Authorizer
	source     *m5Source
	enqueuer   *m5Enqueuer
	caller     account.Caller
	now        *time.Time
}

// newM5Env 构造真实 SQLite + 真实报告/计划服务 + 适配器。
func newM5Env(t *testing.T) *m5Env {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }
	dbPath := filepath.Join(t.TempDir(), "adapter-reports.db")
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
	auditStore, err := auditsqlite.New(raw)
	if err != nil {
		t.Fatalf("构造审计存储失败: %v", err)
	}
	auditRecorder, err := audit.New(auditStore, audit.Options{Now: nowFn})
	if err != nil {
		t.Fatalf("构造审计记录器失败: %v", err)
	}
	reportStore, err := reportsqlite.New(raw)
	if err != nil {
		t.Fatalf("构造报告仓储失败: %v", err)
	}
	history, err := reportsqlite.NewHistoryRecorder(reportStore)
	if err != nil {
		t.Fatalf("构造历史适配器失败: %v", err)
	}
	projections, err := reportsqlite.NewPlanProjectionStore(reportStore)
	if err != nil {
		t.Fatalf("构造计划投影适配器失败: %v", err)
	}
	taskStore, err := tasksqlite.New(raw, tasksqlite.Options{Now: nowFn})
	if err != nil {
		t.Fatalf("构造任务存储失败: %v", err)
	}
	authorizer := &m5Authorizer{grants: map[string]stats.ScopeGrant{}}
	authorizer.allowAll(reports.PermissionRead, reports.PermissionGenerate,
		reports.PermissionExport, reports.PermissionScheduleManage, reports.PermissionCleanup)
	source := &m5Source{now: nowFn}
	enqueuer := &m5Enqueuer{}
	var plans *reports.PlanService
	scheduler, err := task.NewScheduler(task.SchedulerOptions{
		Store: taskStore, SchedulerID: "adapter-m5-scheduler",
		PermissionCheck: func(checkCtx context.Context,
			request task.PermissionRequest) error {
			return plans.CheckExecutionPermission(checkCtx, request)
		},
		TickInterval: 100 * time.Millisecond, Now: nowFn,
	})
	if err != nil {
		t.Fatalf("构造调度器失败: %v", err)
	}
	plans, err = reports.NewPlanService(reports.PlanOptions{
		Schedules: scheduler, Authorizer: authorizer, Root: m5Root{},
		Audit: auditRecorder, Now: nowFn, MaxDetailRows: 20,
		Projections: projections,
	})
	if err != nil {
		t.Fatalf("构造计划服务失败: %v", err)
	}
	service, err := reports.New(reports.Options{
		Source: source, Authorizer: authorizer, Root: m5Root{},
		Sensitive: m5Sensitive{}, Audit: auditRecorder,
		Enqueuer: enqueuer, Canceller: m5Canceller{},
		History: history, OutputDir: t.TempDir(), MaxDetailRows: 20,
		Now: nowFn})
	if err != nil {
		t.Fatalf("构造报告服务失败: %v", err)
	}
	caller, err := account.UserCaller("usr_00000000000000000000000000000001")
	if err != nil {
		t.Fatalf("构造调用者失败: %v", err)
	}
	adapter, err := NewReports(ReportsOptions{Reports: service, Plans: plans,
		Authorizer: authorizer, Root: m5Root{}, Recorder: auditRecorder, Now: nowFn})
	if err != nil {
		t.Fatalf("构造报告页适配器失败: %v", err)
	}
	env := &m5Env{t: t, adapter: adapter, service: service, plans: plans,
		authorizer: authorizer, source: source, enqueuer: enqueuer,
		caller: caller, now: &now}
	return env
}

// generateReport 生成一份报告并返回其编号；failed=true 时生成失败报告。
func (e *m5Env) generateReport(failed bool) string {
	e.t.Helper()
	ctx := context.Background()
	e.source.failed = failed
	request := reports.StartRequest{Caller: e.caller, ScopeID: reports.ScopeSystem,
		Window: stats.WindowRequest{TimeZone: "Asia/Shanghai",
			Start: (*e.now).Add(-24 * time.Hour), End: *e.now,
			Granularity: stats.GranularityDay},
		Formats: []reports.Format{reports.FormatHTML}, RequestID: "req-m5" + failedState(failed)}
	view, err := e.service.Start(ctx, request)
	if err != nil {
		e.t.Fatalf("创建报告失败: %v", err)
	}
	job := e.enqueuer.last()
	_ = e.service.GenerateHandler(ctx, job)
	e.source.failed = false
	report, err := e.service.Get(ctx, e.caller, view.ID)
	if err != nil {
		e.t.Fatalf("查询报告失败: %v", err)
	}
	if failed && report.State != reports.StateFailed {
		e.t.Fatalf("失败报告状态 = %q", report.State)
	}
	if !failed && report.State != reports.StateSucceeded {
		e.t.Fatalf("成功报告状态 = %q", report.State)
	}
	return view.ID
}

func failedState(failed bool) string {
	if failed {
		return "fail"
	}
	return "ok"
}

// TestReportsAdapterRealServices 覆盖适配器真实服务主路径。
func TestReportsAdapterRealServices(t *testing.T) {
	env := newM5Env(t)
	ctx := context.Background()
	userID := env.caller.Actor().ID
	// 能力位来自真实授权替身。
	caps, err := env.adapter.Capabilities(ctx, userID)
	if err != nil || !caps.Read || !caps.ScheduleManage || !caps.Cleanup ||
		!caps.Generate || !caps.Export || caps.DownloadTTL <= 0 {
		t.Fatalf("能力位 = %+v err=%v", caps, err)
	}
	// 计划 CRUD/启停/编辑行版本冲突（真实 PlanService + 真实调度器）。
	plan, err := env.adapter.CreatePlan(ctx, userID, loginPlanRequest("每日报告"), "req-plan")
	if err != nil {
		t.Fatalf("创建计划失败: %v", err)
	}
	if plan.ID == "" || plan.Version != 1 {
		t.Fatalf("计划视图 = %+v", plan)
	}
	plans, err := env.adapter.ListPlans(ctx, userID)
	if err != nil || len(plans) != 1 {
		t.Fatalf("计划列表 = %d err=%v", len(plans), err)
	}
	update := loginPlanRequest("每日报告（改名）")
	updated, err := env.adapter.UpdatePlan(ctx, userID, plan.ID, plan.Version,
		update, "req-plan-update")
	if err != nil || updated.Version != 2 || updated.Name != "每日报告（改名）" {
		t.Fatalf("编辑计划 = %+v err=%v", updated, err)
	}
	if _, err := env.adapter.UpdatePlan(ctx, userID, plan.ID, plan.Version,
		update, "req-plan-stale"); err == nil {
		t.Fatal("过期行版本编辑未冲突")
	}
	if _, err := env.adapter.SetPlanEnabled(ctx, userID, plan.ID, false,
		"暂停", "req-plan-state"); err != nil {
		t.Fatalf("停用计划失败: %v", err)
	}
	preview, err := env.adapter.PlanDeletePreview(ctx, userID, plan.ID)
	if err != nil || !preview.Irreversible || preview.RawAuditNote == "" {
		t.Fatalf("删除预览 = %+v err=%v", preview, err)
	}
	if err := env.adapter.DeletePlan(ctx, userID, plan.ID, "不再需要", "req-plan-del"); err != nil {
		t.Fatalf("删除计划失败: %v", err)
	}
	if plans, err := env.adapter.ListPlans(ctx, userID); err != nil || len(plans) != 0 {
		t.Fatalf("删除后计划列表 = %d err=%v", len(plans), err)
	}
	// 历史列表/详情/预览/下载（下载走真实令牌签发+兑换+再次鉴权）。
	reportID := env.generateReport(false)
	page, err := env.adapter.ListHistory(ctx, userID, loginReportHistoryQuery())
	if err != nil || len(page.Records) == 0 || page.Records[0].ID != reportID {
		t.Fatalf("历史列表 = %+v err=%v", page, err)
	}
	detail, err := env.adapter.GetReport(ctx, userID, reportID)
	if err != nil || detail.State != "succeeded" || len(detail.Artifacts) == 0 {
		t.Fatalf("报告详情 = %+v err=%v", detail, err)
	}
	previewReport, err := env.adapter.Preview(ctx, userID, reportID)
	if err != nil || previewReport.ReportID != reportID ||
		previewReport.ActivityTotal != 3 || !previewReport.WindowWithinRetention {
		t.Fatalf("报告预览 = %+v err=%v", previewReport, err)
	}
	file, err := env.adapter.Download(ctx, userID, reportID, "html")
	if err != nil || len(file.Bytes) == 0 || file.ContentType == "" {
		t.Fatalf("下载 = size=%d err=%v", len(file.Bytes), err)
	}
	// 取消：复用既有取消能力（真实 Service + 真实审计），受理状态如实返回。
	queuedRequest := reports.StartRequest{Caller: env.caller, ScopeID: reports.ScopeSystem,
		Window: stats.WindowRequest{TimeZone: "Asia/Shanghai",
			Start: (*env.now).Add(-24 * time.Hour), End: *env.now,
			Granularity: stats.GranularityDay},
		Formats: []reports.Format{reports.FormatHTML}, RequestID: "req-m5-cancel"}
	queued, err := env.service.Start(ctx, queuedRequest)
	if err != nil {
		t.Fatalf("创建待取消报告失败: %v", err)
	}
	cancelResult, err := env.adapter.Cancel(ctx, userID, queued.ID, "测试取消", "req-cancel")
	if err != nil || !cancelResult.Accepted || cancelResult.ReportID != queued.ID {
		t.Fatalf("适配器取消 = %+v err=%v", cancelResult, err)
	}
	// 重试：失败报告创建新运行记录并保留原记录。
	failedID := env.generateReport(true)
	retried, err := env.adapter.Retry(ctx, userID, failedID, "来源恢复后重试", "req-retry")
	if err != nil || retried.ID == failedID || retried.RetryOf != failedID {
		t.Fatalf("重试 = %+v err=%v", retried, err)
	}
	// 清理预览+执行：推进到产物到期+宽限期后清理；原始审计不删除。
	*env.now = env.now.Add(24*time.Hour + 7*24*time.Hour + time.Minute)
	cleanupPreview, err := env.adapter.CleanupPreview(ctx, userID)
	if err != nil || cleanupPreview.TargetCount < 1 || cleanupPreview.Policy.RawAuditNote == "" {
		t.Fatalf("清理预览 = %+v err=%v", cleanupPreview, err)
	}
	result, err := env.adapter.RunCleanup(ctx, userID, "按保留策略清理", "req-cleanup")
	if err != nil || result.CleanedCount < 1 || result.RawAuditNote == "" {
		t.Fatalf("清理执行 = %+v err=%v", result, err)
	}
	if _, err := env.adapter.Download(ctx, userID, reportID, "html"); err == nil {
		t.Fatal("清理后仍可下载")
	}
	// 越权 fail-closed：撤销全部授权后读取/下载/预览必须拒绝。
	env.authorizer.denyAll()
	if _, err := env.adapter.GetReport(ctx, userID, reportID); err == nil {
		t.Fatal("无权限读取报告详情未被拒绝")
	}
	if _, err := env.adapter.Preview(ctx, userID, reportID); err == nil {
		t.Fatal("无权限预览未被拒绝")
	}
	if _, err := env.adapter.Download(ctx, userID, reportID, "html"); err == nil {
		t.Fatal("无权限下载未被拒绝")
	}
	if page, err := env.adapter.ListHistory(ctx, userID, loginReportHistoryQuery()); err != nil ||
		len(page.Records) != 0 {
		t.Fatalf("无权限历史列表 = %+v err=%v，期望空", page, err)
	}
	if _, err := env.adapter.GetPlan(ctx, userID, "sch_"+m5Repeat('a', 32)); err == nil {
		t.Fatal("无权限计划读取未被拒绝")
	}
	if _, err := env.adapter.Cancel(ctx, userID, queued.ID, "无权取消", "req-cancel-deny"); err == nil {
		t.Fatal("无权限取消未被拒绝")
	}
}

// loginPlanRequest 构造页面计划创建请求。
func loginPlanRequest(name string) login.UIReportPlanRequest {
	return login.UIReportPlanRequest{Name: name, ScopeID: "system",
		ScheduleType: "daily", Expression: "09:00", TimeZone: "Asia/Shanghai",
		Granularity: "day", WindowDays: 1, Formats: []string{"html"},
		DetailRows: 20, MissedPolicy: "latest", MaxCatchUp: 1,
		TimeoutSeconds: 600, MaxAttempts: 1, Enabled: true}
}

// loginReportHistoryQuery 构造历史列表查询。
func loginReportHistoryQuery() login.UIReportHistoryQuery {
	return login.UIReportHistoryQuery{Limit: 20}
}

// m5Repeat 生成重复字节字符串（测试数据）。
func m5Repeat(c byte, count int) string {
	buffer := make([]byte, count)
	for index := range buffer {
		buffer[index] = c
	}
	return string(buffer)
}
