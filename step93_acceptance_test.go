package login_test

// 步骤 93 验收探针：报告管理页（HTTP 页面）↔ 同一真实 internal/reports 服务 ↔ 页面
// 适配器（API 等价入口）的结果、授权、状态与诊断一致性；不因页面隐藏就认为安全，
// 直接调用适配器验证拒绝；异步取消区分“请求受理”与“实际取消”；撤销导出权限后
// 页面与直接下载同时拒绝。会话/CSRF/过期状态使用明确标注的页面会话替身；真实
// 用户中心页复用步骤 68 的真实会话环境（临时 SQLite）。
//
// 边界：测试进程内真实 Handler + 临时 SQLite；不是部署后独立服务，真实浏览器/
// 读屏/真机维度另列未测。

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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
	"github.com/kagurazakayashi/EvernightLogin/internal/uiadminadapter"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

const step93CSRF = "step93-csrf-token"

// step93Authorizer 是按“权限+范围”键控的授权替身（真实权限引擎由宿主注入）。
type step93Authorizer struct {
	mu     sync.Mutex
	grants map[string]stats.ScopeGrant
}

func (a *step93Authorizer) AuthorizeScope(_ context.Context, _ account.Caller,
	permissionKey, scopeID string) (stats.ScopeGrant, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	grant, ok := a.grants[permissionKey+"|"+scopeID]
	if !ok {
		return stats.ScopeGrant{Allowed: false}, nil
	}
	return grant, nil
}

func (a *step93Authorizer) grant(permission, scopeID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.grants[permission+"|"+scopeID] = stats.ScopeGrant{Allowed: true, AllData: true}
}

func (a *step93Authorizer) deny(permission, scopeID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.grants, permission+"|"+scopeID)
}

type step93Root struct{}

func (step93Root) IsRoot(context.Context, account.Caller) (bool, error) { return false, nil }

type step93Sensitive struct{}

func (step93Sensitive) Authorize(_ context.Context, _ reauth.Caller,
	request reauth.Request) (reauth.Result, error) {
	return reauth.Result{OperationID: request.OperationID}, nil
}

func (step93Sensitive) NotifyOutcome(context.Context, reauth.Result, reauth.Outcome) error {
	return nil
}

// step93Source 是统计来源替身：固定窗口内 3 名活跃用户、无错误明细。
type step93Source struct{ now func() time.Time }

func (s *step93Source) window(request stats.WindowRequest) stats.Window {
	window, err := stats.NormalizeWindow(request, s.now())
	if err != nil {
		panic(err)
	}
	return window
}

func (s *step93Source) completeness() stats.Completeness {
	return stats.Completeness{WindowWithinRetention: true, RetentionDays: 30,
		RetentionConfigured: true, RetentionCutoff: s.now().AddDate(0, 0, -30)}
}

func (s *step93Source) Activity(_ context.Context,
	request stats.ActivityRequest) (stats.ActivityResult, error) {
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

func (s *step93Source) Errors(_ context.Context,
	request stats.ErrorRequest) (stats.ErrorResult, error) {
	return stats.ErrorResult{Window: s.window(request.Window), Sort: stats.ErrorSortRaw,
		Order: stats.SortDesc, Limit: request.Limit,
		Completeness: s.completeness(), GeneratedAt: s.now()}, nil
}

func (s *step93Source) ErrorTrend(_ context.Context,
	request stats.ErrorTrendRequest) (stats.ErrorTrendResult, error) {
	metric := request.Metric
	if metric == "" {
		metric = stats.MetricRawEvents
	}
	return stats.ErrorTrendResult{Window: s.window(request.Window), Metric: metric,
		Completeness: s.completeness(), GeneratedAt: s.now()}, nil
}

// step93Enqueuer 记录任务入队（执行器由测试同步调用处理器模拟）。
type step93Enqueuer struct {
	mu   sync.Mutex
	jobs []task.Job
}

func (e *step93Enqueuer) Enqueue(_ context.Context,
	request task.EnqueueRequest) (task.Job, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	job := task.Job{ID: "job_step93_" + time.Now().Format("150405.000000"),
		Kind: request.Kind, Initiator: request.Actor, Payload: request.Payload,
		RequestID: request.RequestID}
	e.jobs = append(e.jobs, job)
	return job, nil
}

func (e *step93Enqueuer) last() task.Job {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.jobs[len(e.jobs)-1]
}

// step93Canceller 返回可配置的任务取消受理状态（默认实际取消）。
type step93Canceller struct{ state task.State }

func (c *step93Canceller) RequestCancel(context.Context,
	task.CancelRequest) (task.CancelResult, error) {
	state := c.state
	if state == "" {
		state = task.StateCancelled
	}
	return task.CancelResult{Accepted: true, State: state}, nil
}

// step93Sessions 是页面会话替身：可切换已认证/未认证与管理/普通级别。
type step93Sessions struct {
	userID        string
	kind          string
	authenticated bool
}

func (s step93Sessions) ResolvePageSession(context.Context,
	*http.Request) (login.UISession, error) {
	return login.UISession{Authenticated: s.authenticated, UserID: s.userID,
		Kind: s.kind, ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func (s step93Sessions) IssueCSRFToken(context.Context, *http.Request) (string, error) {
	return step93CSRF, nil
}

// step93ReportsEnv 是“真实报告服务 + 真实页面适配器 + 页面 Handler”的验收环境。
type step93ReportsEnv struct {
	t          *testing.T
	handler    http.Handler
	adapter    *uiadminadapter.ReportsAdapter
	service    *reports.Service
	authorizer *step93Authorizer
	source     *step93Source
	enqueuer   *step93Enqueuer
	canceller  *step93Canceller
	userID     string
	now        *time.Time
}

func newStep93ReportsEnv(t *testing.T, userID, kind string,
	authenticated bool) *step93ReportsEnv {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 11, 20, 3, 40, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(
		filepath.Join(t.TempDir(), "step93-reports.db")))
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
	auditStore, err := auditsqlite.New(raw)
	if err != nil {
		t.Fatalf("构造审计存储失败: %v", err)
	}
	recorder, err := audit.New(auditStore, audit.Options{Now: nowFn})
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
		t.Fatalf("构造计划投影失败: %v", err)
	}
	taskStore, err := tasksqlite.New(raw, tasksqlite.Options{Now: nowFn})
	if err != nil {
		t.Fatalf("构造任务存储失败: %v", err)
	}
	authorizer := &step93Authorizer{grants: map[string]stats.ScopeGrant{}}
	for _, permission := range []string{reports.PermissionRead, reports.PermissionGenerate,
		reports.PermissionExport, reports.PermissionScheduleManage,
		reports.PermissionCleanup} {
		authorizer.grant(permission, reports.ScopeSystem)
	}
	source := &step93Source{now: nowFn}
	enqueuer := &step93Enqueuer{}
	canceller := &step93Canceller{}
	var plans *reports.PlanService
	scheduler, err := task.NewScheduler(task.SchedulerOptions{
		Store: taskStore, SchedulerID: "step93-scheduler",
		PermissionCheck: func(checkCtx context.Context,
			request task.PermissionRequest) error {
			return plans.CheckExecutionPermission(checkCtx, request)
		},
		TickInterval: 100 * time.Millisecond, Now: nowFn})
	if err != nil {
		t.Fatalf("构造调度器失败: %v", err)
	}
	plans, err = reports.NewPlanService(reports.PlanOptions{
		Schedules: scheduler, Authorizer: authorizer, Root: step93Root{},
		Audit: recorder, Now: nowFn, MaxDetailRows: 20, Projections: projections})
	if err != nil {
		t.Fatalf("构造计划服务失败: %v", err)
	}
	service, err := reports.New(reports.Options{
		Source: source, Authorizer: authorizer, Root: step93Root{},
		Sensitive: step93Sensitive{}, Audit: recorder, Enqueuer: enqueuer,
		Canceller: canceller, History: history, OutputDir: t.TempDir(),
		FontPath: step93PDFFontPath(t), MaxDetailRows: 20, Now: nowFn})
	if err != nil {
		t.Fatalf("构造报告服务失败: %v", err)
	}
	adapter, err := uiadminadapter.NewReports(uiadminadapter.ReportsOptions{
		Reports: service, Plans: plans, Authorizer: authorizer, Root: step93Root{},
		Recorder: recorder, Now: nowFn})
	if err != nil {
		t.Fatalf("构造报告页适配器失败: %v", err)
	}
	ui, err := login.NewWebUI(login.WebUIOptions{
		Session: step93Sessions{userID: userID, kind: kind,
			authenticated: authenticated},
		PageReports: &login.UIPageReportsOptions{Backend: adapter,
			ValidateCSRF: func(context.Context, *http.Request, string) error { return nil }},
		Logger: testDiscardLogger()})
	if err != nil {
		t.Fatalf("构造页面框架失败: %v", err)
	}
	return &step93ReportsEnv{t: t, handler: ui, adapter: adapter, service: service,
		authorizer: authorizer, source: source, enqueuer: enqueuer,
		canceller: canceller, userID: userID, now: &now}
}

// generate 通过真实服务生成一份成功报告并返回编号。
func (e *step93ReportsEnv) generate() string {
	e.t.Helper()
	view, err := e.start(true)
	if err != nil {
		e.t.Fatalf("创建报告失败: %v", err)
	}
	return view.ID
}

// start 创建报告；generate=true 时同步执行生成处理器。
func (e *step93ReportsEnv) start(generate bool) (reports.ReportView, error) {
	caller, err := account.UserCaller(e.userID)
	if err != nil {
		e.t.Fatalf("构造调用者失败: %v", err)
	}
	view, err := e.service.Start(context.Background(), reports.StartRequest{
		Caller: caller, ScopeID: reports.ScopeSystem,
		Window: stats.WindowRequest{TimeZone: "Asia/Shanghai",
			Start: (*e.now).Add(-24 * time.Hour), End: *e.now,
			Granularity: stats.GranularityDay},
		Formats: []reports.Format{reports.FormatHTML, reports.FormatCSV,
			reports.FormatJSON, reports.FormatPDF, reports.FormatMarkdown},
		RequestID: "req-step93"})
	if err != nil {
		return reports.ReportView{}, err
	}
	if generate {
		job := e.enqueuer.last()
		if err := e.service.GenerateHandler(context.Background(), job); err != nil {
			return reports.ReportView{}, err
		}
	}
	return e.service.Get(context.Background(), caller, view.ID)
}

// get 发送页面 GET 请求。
func (e *step93ReportsEnv) get(target string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, "http://example.test"+target, nil)
	recorder := httptest.NewRecorder()
	e.handler.ServeHTTP(recorder, request)
	return recorder
}

// post 发送带 CSRF 的页面 POST 表单。
func (e *step93ReportsEnv) post(target string, values url.Values) *httptest.ResponseRecorder {
	values.Set("csrf_token", step93CSRF)
	request := httptest.NewRequest(http.MethodPost, "http://example.test"+target,
		strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	e.handler.ServeHTTP(recorder, request)
	return recorder
}

// TestStep93ReportsPageMatchesReportService 核对页面展示与真实服务结果、空状态与
// 同一动作的页面/API 等价入口一致。
func TestStep93ReportsPageMatchesReportService(t *testing.T) {
	userID := "usr_00000000000000000000000000000001"
	env := newStep93ReportsEnv(t, userID, "management", true)
	// 空状态：没有任何报告时页面显式呈现空列表，不显示伪造记录。
	empty := env.get("/admin/reports")
	if empty.Code != http.StatusOK ||
		!strings.Contains(empty.Body.String(), "当前筛选条件下没有历史报告") {
		t.Fatalf("空状态 = %d body 缺少空列表说明", empty.Code)
	}
	reportID := env.generate()
	// 页面历史列表与服务查询同一数据（编号/状态中文标签/生成时间）。
	list := env.get("/admin/reports")
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), reportID) ||
		!strings.Contains(list.Body.String(), "已完成") {
		t.Fatalf("历史列表 = %d 缺少 %s 或已完成标签", list.Code, reportID)
	}
	view, err := env.service.Get(context.Background(), mustStep93Caller(t, userID),
		reportID)
	if err != nil || view.State != reports.StateSucceeded {
		t.Fatalf("服务查询 = %+v err=%v", view, err)
	}
	// 页面详情与适配器（API 等价入口）返回同一报告状态与可下载格式。
	detail := env.get("/admin/reports/detail?report_id=" + reportID)
	if detail.Code != http.StatusOK ||
		!strings.Contains(detail.Body.String(), "报告详情") ||
		!strings.Contains(detail.Body.String(), reportID) {
		t.Fatalf("详情页 = %d 缺少报告编号/标题", detail.Code)
	}
	apiDetail, err := env.adapter.GetReport(context.Background(), userID, reportID)
	if err != nil || apiDetail.ID != reportID || apiDetail.State != "succeeded" {
		t.Fatalf("适配器详情 = %+v err=%v", apiDetail, err)
	}
	for _, format := range []string{"html", "csv", "json", "pdf", "markdown"} {
		found := false
		for _, artifact := range apiDetail.Artifacts {
			if artifact.Format == format && artifact.Available {
				found = true
			}
		}
		if !found {
			t.Fatalf("适配器缺少可用 %s 产物: %+v", format, apiDetail.Artifacts)
		}
		if !strings.Contains(strings.ToLower(detail.Body.String()), format) {
			t.Fatalf("详情页未展示 %s 格式下载入口", format)
		}
	}
	// 下载：页面走 POST+CSRF，响应不缓存；与适配器返回的产物一致（同一服务）。
	download := env.post("/admin/reports/download", url.Values{
		"report_id": {reportID}, "format": {"html"}})
	if download.Code != http.StatusOK || download.Body.Len() == 0 {
		t.Fatalf("页面下载 = %d body=%d", download.Code, download.Body.Len())
	}
	for header, want := range map[string]string{
		"Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
		"X-Content-Type-Options": "nosniff"} {
		if got := download.Header().Get(header); !strings.Contains(got, want) {
			t.Fatalf("下载响应头 %s=%q，期望包含 %q", header, got, want)
		}
	}
	apiFile, err := env.adapter.Download(context.Background(), userID, reportID, "html")
	if err != nil || len(apiFile.Bytes) == 0 {
		t.Fatalf("适配器下载 = %d bytes err=%v", len(apiFile.Bytes), err)
	}
	if download.Body.Len() != len(apiFile.Bytes) {
		t.Fatalf("页面下载 %d 字节，适配器 %d 字节，期望同一产物",
			download.Body.Len(), len(apiFile.Bytes))
	}
}

// TestStep93ReportsPageAuthorizationAndExpiry 核对会话过期、管理级别、能力位与
// CSRF 的拒绝路径：页面显示的“无权限”必须同时由直接调用适配器验证为拒绝。
func TestStep93ReportsPageAuthorizationAndExpiry(t *testing.T) {
	userID := "usr_00000000000000000000000000000002"
	// 未认证/会话过期：页面 401 且显示会话过期说明。
	expired := newStep93ReportsEnv(t, userID, "management", false)
	response := expired.get("/admin/reports")
	if response.Code != http.StatusUnauthorized ||
		!strings.Contains(response.Body.String(), "会话已过期") {
		t.Fatalf("会话过期 = %d body=%s", response.Code,
			firstRunes(response.Body.String(), 120))
	}
	// 普通用户会话访问管理页：403，不因路由存在而放行。
	normal := newStep93ReportsEnv(t, userID, "normal", true)
	response = normal.get("/admin/reports")
	if response.Code != http.StatusForbidden ||
		!strings.Contains(response.Body.String(), "请求未获准") {
		t.Fatalf("普通会话访问管理页 = %d body=%s", response.Code,
			firstRunes(response.Body.String(), 120))
	}
	// 管理会话但当前无报告权限：页面 403；直接调用适配器同样 ACCESS_DENIED。
	denied := newStep93ReportsEnv(t, userID, "management", true)
	reportID := denied.generate()
	for _, permission := range []string{reports.PermissionRead, reports.PermissionGenerate,
		reports.PermissionExport} {
		denied.authorizer.deny(permission, reports.ScopeSystem)
	}
	response = denied.get("/admin/reports")
	if response.Code != http.StatusForbidden ||
		!strings.Contains(response.Body.String(), "当前会话无权执行该报告操作") {
		t.Fatalf("无报告权限页面 = %d body=%s", response.Code,
			firstRunes(response.Body.String(), 120))
	}
	var publicErr *login.UIReportsError
	if _, err := denied.adapter.GetReport(context.Background(), userID,
		reportID); !errors.As(err, &publicErr) || publicErr.Code != "ACCESS_DENIED" {
		t.Fatalf("无报告权限直接查询 = %v，期望 ACCESS_DENIED", err)
	}
	// 缺 CSRF 的下载请求被拒绝，不因页面隐藏按钮而放行。
	withoutCSRF := httptest.NewRequest(http.MethodPost,
		"http://example.test/admin/reports/download",
		strings.NewReader(url.Values{"report_id": {"rpt_" + strings.Repeat("a", 32)},
			"format": {"html"}}.Encode()))
	withoutCSRF.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	denied.handler.ServeHTTP(recorder, withoutCSRF)
	if recorder.Code != http.StatusForbidden ||
		!strings.Contains(recorder.Body.String(), "表单安全令牌无效或已过期") {
		t.Fatalf("缺 CSRF 下载 = %d", recorder.Code)
	}
	// 已生成报告：撤销导出权限后页面下载与直接下载同时拒绝（隐藏不等于安全）。
	env := newStep93ReportsEnv(t, userID, "management", true)
	exportReportID := env.generate()
	env.authorizer.deny(reports.PermissionExport, reports.ScopeSystem)
	response = env.post("/admin/reports/download", url.Values{
		"report_id": {exportReportID}, "format": {"html"}})
	if response.Code != http.StatusForbidden ||
		!strings.Contains(response.Body.String(), "当前会话无权执行该报告操作") {
		t.Fatalf("撤销导出后页面下载 = %d body=%s", response.Code,
			firstRunes(response.Body.String(), 120))
	}
	if _, err := env.adapter.Download(context.Background(), userID, exportReportID,
		"html"); err == nil {
		t.Fatal("撤销导出后直接调用适配器下载仍成功")
	}
	if _, err := env.adapter.Download(context.Background(), userID, exportReportID,
		"html"); !errors.As(err, &publicErr) || publicErr.Code != "ACCESS_DENIED" {
		t.Fatalf("撤销导出后适配器错误 = %v，期望 ACCESS_DENIED", err)
	}
}

// TestStep93ReportsPageCancelRequestVersusActualCancel 核对异步取消状态一致性：
// “取消请求已受理”不等于“已取消”，只有任务实际收敛为 cancelled 后页面才显示已取消。
func TestStep93ReportsPageCancelRequestVersusActualCancel(t *testing.T) {
	userID := "usr_00000000000000000000000000000003"
	env := newStep93ReportsEnv(t, userID, "management", true)
	// 创建一个排队中的报告（不执行生成），页面应显示取消入口。
	view, err := env.start(false)
	if err != nil {
		t.Fatalf("创建排队报告失败: %v", err)
	}
	before := env.get("/admin/reports/detail?report_id=" + view.ID)
	if before.Code != http.StatusOK ||
		!strings.Contains(before.Body.String(), "提交取消请求") {
		t.Fatalf("排队报告详情 = %d 缺少取消入口", before.Code)
	}
	// 任务执行器仅受理取消请求（未收敛）：页面显示受理说明，报告状态仍为已排队。
	env.canceller.state = task.StateCancelRequested
	accepted := env.post("/admin/reports/cancel", url.Values{
		"report_id": {view.ID}, "reason": {"夜间维护窗口取消"}})
	if accepted.Code != http.StatusOK ||
		!strings.Contains(accepted.Body.String(),
			"取消请求已受理，等待任务状态收敛；受理不等于实际取消") {
		t.Fatalf("取消受理页面 = %d body=%s", accepted.Code,
			firstRunes(accepted.Body.String(), 200))
	}
	afterRequest, err := env.service.Get(context.Background(), mustStep93Caller(t, userID),
		view.ID)
	if err != nil {
		t.Fatalf("查询受理后报告失败: %v", err)
	}
	if afterRequest.State == reports.StateCancelled {
		t.Fatal("取消请求受理被页面/服务写成实际取消")
	}
	if afterRequest.State != reports.StateQueued {
		t.Fatalf("受理取消请求后状态 = %s，期望 queued", afterRequest.State)
	}
	// 任务真正收敛为 cancelled：页面刷新显示已取消，且报告不可再下载。
	env.canceller.state = task.StateCancelled
	final := env.post("/admin/reports/cancel", url.Values{
		"report_id": {view.ID}, "reason": {"确认停止生成"}})
	if final.Code != http.StatusOK {
		t.Fatalf("实际取消页面 = %d", final.Code)
	}
	afterCancel, err := env.service.Get(context.Background(), mustStep93Caller(t, userID),
		view.ID)
	if err != nil || afterCancel.State != reports.StateCancelled {
		t.Fatalf("实际取消后服务状态 = %+v err=%v", afterCancel, err)
	}
	detail := env.get("/admin/reports/detail?report_id=" + view.ID)
	if detail.Code != http.StatusOK || !strings.Contains(detail.Body.String(), "已取消") {
		t.Fatalf("实际取消后详情页 = %d 未显示已取消", detail.Code)
	}
	if _, err := env.adapter.Download(context.Background(), userID, view.ID,
		"html"); err == nil {
		t.Fatal("已实际取消的报告仍可下载")
	}
}

// TestStep93UserCenterSessionAndRoleGates 复用步骤 68 的真实会话环境核对普通用户
// 中心的可访问性，并用真实审计服务核对普通会话直达管理页被拒绝、管理会话正常。
func TestStep93UserCenterSessionAndRoleGates(t *testing.T) {
	env := newAccountIntegrationEnv(t)
	cookies, userID := env.loginCookie()
	profile := env.request(http.MethodGet, "/account/profile", nil, "", cookies)
	if profile.Code != http.StatusOK ||
		!strings.Contains(profile.Body.String(), userID) {
		t.Fatalf("普通用户中心 = %d", profile.Code)
	}
	// 过期/伪造会话 Cookie → 401，不进入业务页。
	forged := &http.Cookie{Name: "session", Value: "forged-session-token",
		Path: "/", HttpOnly: true}
	expired := env.request(http.MethodGet, "/account/profile", nil, "",
		[]*http.Cookie{forged})
	if expired.Code != http.StatusUnauthorized ||
		!strings.Contains(expired.Body.String(), "会话已过期") {
		t.Fatalf("伪造会话访问用户中心 = %d", expired.Code)
	}
	// 普通会话 URL 直达管理页（不依赖菜单隐藏）→ 403 且不泄露审计正文。
	auditUserID := "usr_0123456789abcdef0123456789abcdef"
	normalAudit, _ := newHTTPAuditHandlerKind(t, auditUserID, auditUserID, "normal")
	normal := httpAuditGet(normalAudit, "/admin/audit")
	if normal.Code != http.StatusForbidden ||
		strings.Contains(normal.Body.String(), "session.revoke") {
		t.Fatalf("普通会话直达审计管理页 = %d", normal.Code)
	}
	// 管理会话访问同一真实服务：200 且渲染真实事件（同一页面同级别对照）。
	managementAudit, _ := newHTTPAuditHandlerKind(t, auditUserID, auditUserID,
		"management")
	management := httpAuditGet(managementAudit, "/admin/audit")
	if management.Code != http.StatusOK ||
		!strings.Contains(management.Body.String(), "session.revoke") {
		t.Fatalf("管理会话访问审计管理页 = %d", management.Code)
	}
}

// step93PDFFontPath 返回预审通过的 Noto Sans SC 静态 TTF 路径；缺失时如实跳过
// PDF 相关页面用例（不把未跑当通过）。
func step93PDFFontPath(t *testing.T) string {
	t.Helper()
	candidates := make([]string, 0, 3)
	if custom := strings.TrimSpace(os.Getenv("REPORT_TEST_FONT_PATH")); custom != "" {
		candidates = append(candidates, custom)
	}
	if localTemp := os.Getenv("LOCALAPPDATA"); localTemp != "" {
		candidates = append(candidates, filepath.Join(localTemp, "Temp",
			"dep-review-step78", "font_gstatic", "NotoSansSC-Regular.ttf"))
	}
	if temp := os.Getenv("TEMP"); temp != "" {
		candidates = append(candidates, filepath.Join(temp, "dep-review-step78",
			"font_gstatic", "NotoSansSC-Regular.ttf"))
	}
	for _, candidate := range candidates {
		info, err := os.Lstat(candidate)
		if err != nil || !info.Mode().IsRegular() ||
			info.Size() != reports.RequiredPDFFontBytes {
			continue
		}
		return candidate
	}
	t.Skip("未提供预审通过的 Noto Sans SC 静态 TTF（设置 REPORT_TEST_FONT_PATH）：" +
		"跳过含 PDF 格式的报告页用例")
	return ""
}

// mustStep93Caller 构造测试用户调用者。
func mustStep93Caller(t *testing.T, userID string) account.Caller {
	t.Helper()
	caller, err := account.UserCaller(userID)
	if err != nil {
		t.Fatalf("构造用户调用者失败: %v", err)
	}
	return caller
}
