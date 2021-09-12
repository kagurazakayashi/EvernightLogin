package reports

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
	tasksqlite "github.com/kagurazakayashi/EvernightLogin/internal/task/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// planTestEnv 是报告计划测试环境：真实临时 SQLite + 真实任务调度器/执行器 +
// 明确标注的授权/审计/统计替身。替身只用于测试授权与渲染语义，不进入生产装配。
type planTestEnv struct {
	scheduler  *task.Scheduler
	executor   *task.Executor
	plans      *PlanService
	service    *Service
	authorizer *fakeAuthorizer
	recorder   *fakeRecorder
	caller     account.Caller
	schedules  *tasksqlite.Store
	raw        *storagesqlite.Store
}

// newPlanTestEnv 构造隔离环境；now 是可变假时钟指针。
func newPlanTestEnv(t *testing.T, now *time.Time) *planTestEnv {
	t.Helper()
	ctx := context.Background()
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(
		filepath.Join(t.TempDir(), "reports-plan.db")))
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
	nowFunc := func() time.Time { return *now }
	store, err := tasksqlite.New(raw, tasksqlite.Options{Now: nowFunc})
	if err != nil {
		t.Fatalf("构造任务存储失败: %v", err)
	}
	authorizer := &fakeAuthorizer{grants: map[string]stats.ScopeGrant{}}
	recorder := &fakeRecorder{}
	var plans *PlanService
	scheduler, err := task.NewScheduler(task.SchedulerOptions{
		Store: store, SchedulerID: "sched-reports-plan-test",
		PermissionCheck: func(checkCtx context.Context, request task.PermissionRequest) error {
			return plans.CheckExecutionPermission(checkCtx, request)
		},
		Now: nowFunc, TickInterval: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("构造调度器失败: %v", err)
	}
	plans, err = NewPlanService(PlanOptions{
		Schedules: scheduler, Authorizer: authorizer, Root: &fakeRoot{},
		Audit: recorder, Now: nowFunc, MaxDetailRows: 20,
	})
	if err != nil {
		t.Fatalf("构造计划服务失败: %v", err)
	}
	var service *Service
	executor, err := task.New(store, task.Options{
		Handlers: map[string]task.Handler{
			TaskKindPlannedReportGenerate: func(handlerCtx context.Context, job task.Job) error {
				return service.GenerateScheduledHandler(handlerCtx, job)
			},
		},
		ExecutorID: "exec-reports-plan-test", MaxConcurrent: 1,
		PollInterval: task.MinPollInterval, ShutdownTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("构造执行器失败: %v", err)
	}
	source := &fakeSource{now: nowFunc, activity: 7,
		completeness: stats.Completeness{WindowWithinRetention: true,
			RetentionDays: 30, RetentionConfigured: true,
			RetentionCutoff: now.AddDate(0, 0, -30)},
		rows: []stats.ErrorRow{{ErrorCode: "AUTH_FAILED",
			Category: stats.CategoryFailure, Severity: stats.SeverityError,
			AppID: "app_demo1", RawEvents: 2, FailedRequests: 1,
			FirstSeen: now.Add(-time.Hour), LastSeen: now.Add(-time.Minute),
			Growth:     stats.Growth{Kind: stats.GrowthNone},
			DataStatus: stats.DataComplete}}}
	service, err = New(Options{Source: source, Authorizer: authorizer,
		Root: &fakeRoot{}, Sensitive: &fakeSensitive{}, Audit: recorder,
		Enqueuer: executor, Canceller: executor, Tasks: executor,
		OutputDir: t.TempDir(), MaxDetailRows: 20, Now: nowFunc})
	if err != nil {
		t.Fatalf("构造报告服务失败: %v", err)
	}
	caller := testCaller(t, 1)
	// 计划管理需要独立的 reports.schedule.manage 权限（步骤 79 收口）。
	for _, permission := range []string{PermissionRead, PermissionGenerate,
		PermissionExport, PermissionScheduleManage} {
		authorizer.allow(permission, ScopeSystem,
			stats.ScopeGrant{Allowed: true, AllData: true})
	}
	return &planTestEnv{scheduler: scheduler, executor: executor, plans: plans,
		service: service, authorizer: authorizer, recorder: recorder,
		caller: caller, schedules: store, raw: raw}
}

// newPlanRequest 返回一个合法的每日报告计划请求（系统范围）。
func newPlanRequest(caller account.Caller) PlanCreateRequest {
	return PlanCreateRequest{
		Caller: caller, Name: "每日安全报告",
		ScheduleType: task.ScheduleTypeDaily, Expression: "09:00",
		TimeZone: "Asia/Shanghai", ScopeID: ScopeSystem,
		Granularity: stats.GranularityDay, WindowDays: 1,
		Formats: []Format{FormatHTML, FormatJSON}, Enabled: true,
	}
}

// TestPlanCreateListGet 验证计划持久化、载荷还原、下次执行计算与可见性过滤。
func TestPlanCreateListGet(t *testing.T) {
	now := baseTime
	env := newPlanTestEnv(t, &now)
	view, err := env.plans.Create(context.Background(), newPlanRequest(env.caller))
	if err != nil {
		t.Fatalf("创建计划失败: %v", err)
	}
	if view.ID == "" || view.Name != "每日安全报告" || !view.Enabled {
		t.Fatalf("计划视图不完整: %+v", view)
	}
	if view.PermissionState != PlanPermissionOK {
		t.Fatalf("执行权限状态 = %q，期望 ok", view.PermissionState)
	}
	if view.NextRun.IsZero() || !view.NextRun.After(now) {
		t.Fatalf("下次执行时间 = %v，期望晚于 %v", view.NextRun, now)
	}
	list, err := env.plans.List(context.Background(), env.caller)
	if err != nil || len(list) != 1 {
		t.Fatalf("列表 = %d, err=%v，期望 1 条", len(list), err)
	}
	got, err := env.plans.Get(context.Background(), env.caller, view.ID)
	if err != nil || got.ScopeID != ScopeSystem || len(got.Formats) != 2 {
		t.Fatalf("查询计划失败: %+v err=%v", got, err)
	}
	// 无读取权限的调用者看不到任何计划，也不能用编号探测其存在。授权替身按
	// 权限/范围键控，因此撤销读取授权来模拟无权调用者。
	other := testCaller(t, 9)
	env.authorizer.deny(PermissionRead, ScopeSystem)
	if _, err := env.plans.Get(context.Background(), other, view.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("其他用户查询计划错误 = %v，期望 ErrNotFound", err)
	}
	if list, _ := env.plans.List(context.Background(), other); len(list) != 0 {
		t.Fatalf("其他用户可见计划数 = %d，期望 0", len(list))
	}
}

// TestPlanCreateRequiresAllPermissions 验证缺任一报告权限都拒绝创建计划且不落库。
func TestPlanCreateRequiresAllPermissions(t *testing.T) {
	now := baseTime
	env := newPlanTestEnv(t, &now)
	env.authorizer.deny(PermissionExport, ScopeSystem)
	if _, err := env.plans.Create(context.Background(),
		newPlanRequest(env.caller)); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("缺导出权限创建计划错误 = %v，期望 ErrAccessDenied", err)
	}
	if list, _ := env.plans.List(context.Background(), env.caller); len(list) != 0 {
		t.Fatalf("拒绝后仍落库 %d 条计划", len(list))
	}
	// 非法格式与非法名称也必须拒绝。
	env.authorizer.allow(PermissionExport, ScopeSystem,
		stats.ScopeGrant{Allowed: true, AllData: true})
	bad := newPlanRequest(env.caller)
	bad.Name = " "
	if _, err := env.plans.Create(context.Background(), bad); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("空名称错误 = %v，期望 ErrInvalidRequest", err)
	}
	bad = newPlanRequest(env.caller)
	bad.Formats = []Format{"docx"}
	if _, err := env.plans.Create(context.Background(), bad); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("非法格式错误 = %v，期望 ErrInvalidRequest", err)
	}
}

// TestPlanExecutionPermissionRecheck 验证计划触发前权限复验按执行身份当前权限判断，
// 并拒绝载荷所有者与执行身份不一致的篡改。
func TestPlanExecutionPermissionRecheck(t *testing.T) {
	now := baseTime
	env := newPlanTestEnv(t, &now)
	view, err := env.plans.Create(context.Background(), newPlanRequest(env.caller))
	if err != nil {
		t.Fatalf("创建计划失败: %v", err)
	}
	schedule, err := env.scheduler.Get(context.Background(), view.ScheduleID)
	if err != nil {
		t.Fatalf("读取计划失败: %v", err)
	}
	check := task.PermissionRequest{Kind: TaskKindPlannedReportGenerate,
		Actor: env.caller.Actor(), Payload: schedule.Payload, ScheduleID: schedule.ID}
	if err := env.plans.CheckExecutionPermission(context.Background(), check); err != nil {
		t.Fatalf("有权限时复验失败: %v", err)
	}
	// 权限收缩后复验必须拒绝。
	env.authorizer.deny(PermissionGenerate, ScopeSystem)
	if err := env.plans.CheckExecutionPermission(context.Background(), check); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("失权后复验错误 = %v，期望 ErrAccessDenied", err)
	}
	env.authorizer.allow(PermissionGenerate, ScopeSystem,
		stats.ScopeGrant{Allowed: true, AllData: true})
	// 载荷所有者与执行身份不一致（被篡改/装配错误）必须拒绝。
	tampered := check
	tampered.Actor = audit.Actor{Type: audit.ActorUser, ID: testUserID(8)}
	if err := env.plans.CheckExecutionPermission(context.Background(), tampered); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("执行身份不一致错误 = %v，期望 ErrAccessDenied", err)
	}
}

// TestPlanStateAndDelete 验证停用/启用/失权拒绝启用/删除预览与删除原因校验。
func TestPlanStateAndDelete(t *testing.T) {
	now := baseTime
	env := newPlanTestEnv(t, &now)
	view, err := env.plans.Create(context.Background(), newPlanRequest(env.caller))
	if err != nil {
		t.Fatalf("创建计划失败: %v", err)
	}
	paused, err := env.plans.SetEnabled(context.Background(), env.caller, view.ID,
		false, "例行维护", "req-pause")
	if err != nil || paused.Enabled {
		t.Fatalf("停用失败: enabled=%v err=%v", paused.Enabled, err)
	}
	if _, err := env.plans.SetEnabled(context.Background(), env.caller, view.ID,
		true, "恢复", "req-resume"); err != nil {
		t.Fatalf("恢复失败: %v", err)
	}
	// 执行身份失权时不能启用，避免用操作者权限掩盖执行身份失权。
	env.authorizer.deny(PermissionExport, ScopeSystem)
	if _, err := env.plans.SetEnabled(context.Background(), env.caller, view.ID,
		true, "恢复", "req-resume2"); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("失权启用错误 = %v，期望 ErrAccessDenied", err)
	}
	env.authorizer.allow(PermissionExport, ScopeSystem,
		stats.ScopeGrant{Allowed: true, AllData: true})
	preview, err := env.plans.DeletePreview(context.Background(), env.caller, view.ID)
	if err != nil {
		t.Fatalf("删除预览失败: %v", err)
	}
	if preview.RawAuditNote == "" || preview.HistoryNote == "" ||
		preview.ActiveTasksNote == "" {
		t.Fatalf("删除预览缺少后果说明: %+v", preview)
	}
	if err := env.plans.Delete(context.Background(), env.caller, view.ID, "", "req-del"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("空原因删除错误 = %v，期望 ErrInvalidRequest", err)
	}
	if err := env.plans.Delete(context.Background(), env.caller, view.ID, "不再需要", "req-del"); err != nil {
		t.Fatalf("删除计划失败: %v", err)
	}
	if _, err := env.plans.Get(context.Background(), env.caller, view.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("删除后查询错误 = %v，期望 ErrNotFound", err)
	}
}

// TestGenerateScheduledHandler 验证计划触发的处理器执行同一快照生成并在失权时
// 拒绝创建假报告。
func TestGenerateScheduledHandler(t *testing.T) {
	now := baseTime
	env := newPlanTestEnv(t, &now)
	view, err := env.plans.Create(context.Background(), newPlanRequest(env.caller))
	if err != nil {
		t.Fatalf("创建计划失败: %v", err)
	}
	schedule, err := env.scheduler.Get(context.Background(), view.ScheduleID)
	if err != nil {
		t.Fatalf("读取计划失败: %v", err)
	}
	job := task.Job{ID: "job-plan-test", Kind: TaskKindPlannedReportGenerate,
		Initiator: env.caller.Actor(), ExecutorID: "exec-plan-test",
		Payload: schedule.Payload, RequestID: ""}
	if err := env.service.GenerateScheduledHandler(context.Background(), job); err != nil {
		t.Fatalf("计划生成失败: %v", err)
	}
	var generated string
	env.service.mu.Lock()
	for id, record := range env.service.records {
		if record.RequestedBy == env.caller.Actor() && record.State == StateSucceeded {
			generated = id
		}
	}
	env.service.mu.Unlock()
	if generated == "" {
		t.Fatal("计划触发后没有成功的报告记录")
	}
	report, err := env.service.Get(context.Background(), env.caller, generated)
	if err != nil || report.State != StateSucceeded || len(report.Artifacts) != 2 {
		t.Fatalf("计划报告查询失败: state=%s artifacts=%d err=%v",
			report.State, len(report.Artifacts), err)
	}
	// 失权后再次执行同样的任务：必须返回拒绝且不产生新记录。
	env.authorizer.deny(PermissionRead, ScopeSystem)
	before := 0
	env.service.mu.Lock()
	before = len(env.service.records)
	env.service.mu.Unlock()
	job.ID = "job-plan-test-2"
	if err := env.service.GenerateScheduledHandler(context.Background(), job); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("失权计划生成错误 = %v，期望 ErrAccessDenied", err)
	}
	after := 0
	env.service.mu.Lock()
	after = len(env.service.records)
	env.service.mu.Unlock()
	if after != before {
		t.Fatalf("失权执行新增了 %d 条记录，期望 0", after-before)
	}
}

// TestDisableRevokedPlans 验证失权计划会被自动停用（明确状态，而非每次触发都报错）。
func TestDisableRevokedPlans(t *testing.T) {
	now := baseTime
	env := newPlanTestEnv(t, &now)
	view, err := env.plans.Create(context.Background(), newPlanRequest(env.caller))
	if err != nil {
		t.Fatalf("创建计划失败: %v", err)
	}
	env.authorizer.deny(PermissionGenerate, ScopeSystem)
	disabled, err := env.plans.DisableRevokedPlans(context.Background())
	if err != nil || disabled != 1 {
		t.Fatalf("自动停用 = %d, err=%v，期望 1", disabled, err)
	}
	got, err := env.plans.Get(context.Background(), env.caller, view.ID)
	if err != nil || got.Enabled {
		t.Fatalf("停用后计划 enabled=%v err=%v，期望已停用", got.Enabled, err)
	}
	if got.PermissionState != PlanPermissionRevoked {
		t.Fatalf("权限状态 = %q，期望 revoked", got.PermissionState)
	}
}
