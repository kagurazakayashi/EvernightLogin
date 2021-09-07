package reports

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// baseTime 是测试固定时钟；窗口与产物有效期都以它为基准，不使用会随时间失效的
// 未来常量。
var baseTime = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

// testUserID 生成格式合法的稳定用户 ID。
func testUserID(index int) string { return fmt.Sprintf("usr_%032x", index) }

// testCaller 构造普通用户调用者。
func testCaller(t *testing.T, index int) account.Caller {
	t.Helper()
	caller, err := account.UserCaller(testUserID(index))
	if err != nil {
		t.Fatalf("构造用户调用者失败: %v", err)
	}
	return caller
}

// fakeAuthorizer 是明确标注的授权替身：按 "权限:作用范围" 返回配置结果。
// 只用于测试渲染/产物/取消等语义；不进入生产装配。
type fakeAuthorizer struct {
	mu     sync.Mutex
	grants map[string]stats.ScopeGrant
}

// AuthorizeScope 实现 stats.Authorizer。
func (f *fakeAuthorizer) AuthorizeScope(_ context.Context, _ account.Caller,
	permissionKey, scopeID string) (stats.ScopeGrant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.grants[permissionKey+":"+scopeID], nil
}

// allow 为指定权限/范围设置授权结果。
func (f *fakeAuthorizer) allow(permission, scopeID string, grant stats.ScopeGrant) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.grants[permission+":"+scopeID] = grant
}

// deny 撤销指定权限/范围的授权。
func (f *fakeAuthorizer) deny(permission, scopeID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.grants, permission+":"+scopeID)
}

// fakeRoot 是 root 判定替身。
type fakeRoot struct {
	roots map[string]bool
}

// IsRoot 实现 stats.RootChecker。
func (f *fakeRoot) IsRoot(_ context.Context, caller account.Caller) (bool, error) {
	return f.roots[caller.Actor().ID], nil
}

// fakeSensitive 是再次认证替身；denied 为 true 时拒绝。
type fakeSensitive struct {
	denied bool
}

// Authorize 实现 reauth.OperationRunner。
func (f *fakeSensitive) Authorize(_ context.Context, _ reauth.Caller,
	request reauth.Request) (reauth.Result, error) {
	if f.denied {
		return reauth.Result{}, errors.New("reauth required")
	}
	return reauth.Result{OperationID: request.OperationID}, nil
}

// NotifyOutcome 实现 reauth.OperationRunner。
func (f *fakeSensitive) NotifyOutcome(_ context.Context, _ reauth.Result,
	_ reauth.Outcome) error {
	return nil
}

// fakeRecorder 是审计写入替身，记录调用的事件用于断言；failWrites=true 模拟
// 审计存储不可用（用于验证 fail-closed）。
type fakeRecorder struct {
	mu          sync.Mutex
	events      []audit.Event
	failWrites  bool
	failSuccess bool
}

// setFailWrites 切换审计完全不可用状态。
func (f *fakeRecorder) setFailWrites(fail bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failWrites = fail
}

// setFailSuccess 只让成功结果的事件写入失败（用于验证成功审计失败后的回滚）。
func (f *fakeRecorder) setFailSuccess(fail bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failSuccess = fail
}

// Record 记录成功/取消事件。
func (f *fakeRecorder) Record(_ context.Context, event audit.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWrites || (f.failSuccess && event.Outcome == audit.OutcomeSuccess) {
		return errors.New("audit store unavailable")
	}
	f.events = append(f.events, event)
	return nil
}

// RecordFailure 记录失败/拒绝事件。
func (f *fakeRecorder) RecordFailure(ctx context.Context, event audit.Event) error {
	return f.Record(ctx, event)
}

// ExecuteCritical 在本测试中不使用关键事务路径。
func (f *fakeRecorder) ExecuteCritical(_ context.Context, _ audit.CriticalRequest,
	_ audit.Change) error {
	return nil
}

// hasAction 报告是否记录了指定动作。
func (f *fakeRecorder) hasAction(action string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, event := range f.events {
		if event.Action == action {
			return true
		}
	}
	return false
}

// fakeEnqueuer 记录入队请求并返回可复用的任务。
type fakeEnqueuer struct {
	mu   sync.Mutex
	jobs []task.Job
}

// Enqueue 实现 task 入队契约。
func (f *fakeEnqueuer) Enqueue(_ context.Context, request task.EnqueueRequest) (task.Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	job := task.Job{ID: fmt.Sprintf("job_%032x", len(f.jobs)+1),
		Kind: request.Kind, State: task.StateQueued, Initiator: request.Actor,
		Payload: request.Payload, TimeoutSeconds: request.TimeoutSeconds,
		MaxAttempts: 1, RequestID: request.RequestID, CreatedAt: baseTime}
	f.jobs = append(f.jobs, job)
	return job, nil
}

// last 返回最近一次入队任务。
func (f *fakeEnqueuer) last() task.Job {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.jobs[len(f.jobs)-1]
}

// fakeCanceller 模拟取消结果。
type fakeCanceller struct {
	state task.State
	err   error
}

// RequestCancel 实现取消契约。
func (f *fakeCanceller) RequestCancel(_ context.Context,
	_ task.CancelRequest) (task.CancelResult, error) {
	if f.err != nil {
		return task.CancelResult{}, f.err
	}
	return task.CancelResult{Accepted: true, State: f.state}, nil
}

// fakeTasks 是任务状态读取替身。
type fakeTasks struct {
	jobs map[string]task.Job
}

// Get 实现任务读取契约（签名与 *task.Executor.Get 一致）。
func (f *fakeTasks) Get(_ context.Context, id string) (task.Job, error) {
	job, found := f.jobs[id]
	if !found {
		return task.Job{}, task.ErrTaskNotFound
	}
	return job, nil
}

// fakeSource 是明确标注的统计来源替身：按请求窗口生成固定数据，供渲染与产物
// 语义测试。生产来源必须是 *stats.Service（本包测试单独验证真实统计服务由
// 步骤 75/76 覆盖，这里不伪造生产授权实现）。
type fakeSource struct {
	now          func() time.Time
	activity     int64
	rows         []stats.ErrorRow
	hasMore      bool
	completeness stats.Completeness
	err          error
	cancelled    bool
}

// window 按请求参数规范化窗口（与生产统计服务同一函数）。
func (f *fakeSource) window(request stats.WindowRequest) stats.Window {
	window, err := stats.NormalizeWindow(request, f.now())
	if err != nil {
		panic(err)
	}
	return window
}

// Activity 实现来源契约。
func (f *fakeSource) Activity(_ context.Context,
	request stats.ActivityRequest) (stats.ActivityResult, error) {
	if f.err != nil {
		return stats.ActivityResult{}, f.err
	}
	if f.cancelled {
		return stats.ActivityResult{}, context.Canceled
	}
	window := f.window(request.Window)
	points := make([]stats.ActivityPoint, 0, len(window.Buckets))
	for index, bucket := range window.Buckets {
		points = append(points, stats.ActivityPoint{Bucket: bucket,
			ActiveUsers: int64(index + 1), DataStatus: stats.DataComplete})
	}
	return stats.ActivityResult{Window: window, Metric: stats.MetricActiveUsers,
		DedupeScope: "system", Points: points, TotalActiveUsers: f.activity,
		Completeness: f.completeness, GeneratedAt: f.now()}, nil
}

// Errors 实现来源契约。
func (f *fakeSource) Errors(_ context.Context,
	request stats.ErrorRequest) (stats.ErrorResult, error) {
	if f.err != nil {
		return stats.ErrorResult{}, f.err
	}
	if f.cancelled {
		return stats.ErrorResult{}, context.Canceled
	}
	window := f.window(request.Window)
	result := stats.ErrorResult{Window: window, Sort: stats.ErrorSortRaw,
		Order: stats.SortDesc, Limit: request.Limit, HasMore: f.hasMore,
		Completeness: f.completeness, GeneratedAt: f.now()}
	for _, row := range f.rows {
		result.Rows = append(result.Rows, row)
		result.TotalRawEvents += row.RawEvents
		result.FailedRequests += row.FailedRequests
		result.FailedTasks += row.FailedTasks
	}
	result.ShareDenominator = result.TotalRawEvents
	result.Categories = fakeCategorySummary(result.Rows)
	return result, nil
}

// ErrorTrend 实现来源契约；趋势原始事件总数与 Errors 同源。
func (f *fakeSource) ErrorTrend(_ context.Context,
	request stats.ErrorTrendRequest) (stats.ErrorTrendResult, error) {
	if f.err != nil {
		return stats.ErrorTrendResult{}, f.err
	}
	if f.cancelled {
		return stats.ErrorTrendResult{}, context.Canceled
	}
	window := f.window(request.Window)
	metric := request.Metric
	if metric == "" {
		metric = stats.MetricRawEvents
	}
	result := stats.ErrorTrendResult{Window: window, Metric: metric,
		Completeness: f.completeness, GeneratedAt: f.now()}
	// 统计事实只落在一个时间桶：趋势桶合计必须等于窗口汇总，不能把同一批
	// 明细复制到每个桶使合计膨胀（图表与汇总同口径）。
	for index, bucket := range window.Buckets {
		for _, row := range f.rows {
			point := stats.ErrorTrendPoint{Bucket: bucket, Category: row.Category,
				Severity: row.Severity, DataStatus: row.DataStatus}
			if index == 0 {
				point.RawEvents = row.RawEvents
				point.FailedRequests = row.FailedRequests
				point.FailedTasks = row.FailedTasks
			}
			result.Points = append(result.Points, point)
		}
	}
	for _, row := range f.rows {
		result.TotalRawEvents += row.RawEvents
		result.FailedRequests += row.FailedRequests
		result.FailedTasks += row.FailedTasks
	}
	result.Categories = fakeCategorySummary(f.rows)
	return result, nil
}

// fakeCategorySummary 按固定顺序汇总替身数据。
func fakeCategorySummary(rows []stats.ErrorRow) []stats.CategorySummary {
	order := []stats.Category{stats.CategoryPending, stats.CategoryDenied,
		stats.CategoryCancelled, stats.CategoryWarning, stats.CategoryFailure,
		stats.CategoryUnknown}
	summary := make([]stats.CategorySummary, len(order))
	for index, category := range order {
		summary[index] = stats.CategorySummary{Category: category,
			Severity: stats.SeverityInfo}
	}
	for _, row := range rows {
		for index := range summary {
			if summary[index].Category == row.Category {
				summary[index].RawEvents += row.RawEvents
				summary[index].FailedRequests += row.FailedRequests
				summary[index].FailedTasks += row.FailedTasks
				summary[index].Severity = row.Severity
			}
		}
	}
	return summary
}

// testEnv 是隔离的完整测试环境。
type testEnv struct {
	t          *testing.T
	service    *Service
	source     *fakeSource
	authorizer *fakeAuthorizer
	root       *fakeRoot
	sensitive  *fakeSensitive
	recorder   *fakeRecorder
	enqueuer   *fakeEnqueuer
	canceller  *fakeCanceller
	tasks      *fakeTasks
	outputDir  string
	now        func() time.Time
}

// newTestEnv 构造临时输出目录与完整依赖。
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	now := func() time.Time { return baseTime }
	env := &testEnv{t: t, outputDir: t.TempDir(), now: now}
	env.authorizer = &fakeAuthorizer{grants: map[string]stats.ScopeGrant{}}
	env.root = &fakeRoot{roots: map[string]bool{}}
	env.sensitive = &fakeSensitive{}
	env.recorder = &fakeRecorder{}
	env.enqueuer = &fakeEnqueuer{}
	env.canceller = &fakeCanceller{state: task.StateCancelled}
	env.tasks = &fakeTasks{jobs: map[string]task.Job{}}
	env.source = &fakeSource{now: now, activity: 7,
		completeness: stats.Completeness{WindowWithinRetention: true,
			RetentionDays: 30, RetentionConfigured: true,
			RetentionCutoff: baseTime.AddDate(0, 0, -30)},
		rows: []stats.ErrorRow{
			{ErrorCode: "AUTH_FAILED", Category: stats.CategoryFailure,
				Severity: stats.SeverityError, AppID: "app_demo1", RawEvents: 5,
				FailedRequests: 3, FailedTasks: 0, Share: 0.5,
				FirstSeen: baseTime.Add(-time.Hour), LastSeen: baseTime.Add(-time.Minute),
				Growth: stats.Growth{Kind: stats.GrowthPercent, Percent: 12.5,
					ComparisonStart: baseTime.Add(-48 * time.Hour),
					ComparisonEnd:   baseTime.Add(-24 * time.Hour)},
				DataStatus: stats.DataComplete},
			{ErrorCode: `=cmd|' /C calc'!A0,"quoted"` + "\n下一行",
				Category: stats.CategoryUnknown, Severity: stats.SeverityUnknown,
				RawEvents: 2, FailedRequests: 1, FailedTasks: 1, Share: 0.2,
				FirstSeen: baseTime.Add(-2 * time.Hour), LastSeen: baseTime.Add(-time.Hour),
				Growth:     stats.Growth{Kind: stats.GrowthUnavailable},
				DataStatus: stats.DataUnknown},
			{ErrorCode: `测试<脚本>"引号"`, Category: stats.CategoryDenied,
				Severity: stats.SeverityInfo, AppID: "app_demo1", RawEvents: 3,
				FailedRequests: 2, FailedTasks: 0, Share: 0.3,
				FirstSeen: baseTime.Add(-3 * time.Hour), LastSeen: baseTime.Add(-2 * time.Hour),
				Growth: stats.Growth{Kind: stats.GrowthPercent, Percent: -12.5,
					ComparisonStart: baseTime.AddDate(0, 0, -3),
					ComparisonEnd:   baseTime.AddDate(0, 0, -2)},
				DataStatus: stats.DataComplete},
		}}
	service, err := New(Options{Source: env.source, Authorizer: env.authorizer,
		Root: env.root, Sensitive: env.sensitive, Audit: env.recorder,
		Enqueuer: env.enqueuer, Canceller: env.canceller, Tasks: env.tasks,
		OutputDir: env.outputDir, MaxDetailRows: 50, Now: now})
	if err != nil {
		t.Fatalf("构造报告服务失败: %v", err)
	}
	env.service = service
	return env
}

// grantAll 为指定用户在作用范围授予读/生成/导出权限与数据范围。
func (e *testEnv) grantAll(userID, scopeID string, grant stats.ScopeGrant) {
	e.authorizer.allow(PermissionRead, scopeID, grant)
	e.authorizer.allow(PermissionGenerate, scopeID, grant)
	e.authorizer.allow(PermissionExport, scopeID, grant)
	_ = userID
}

// startRequest 构造默认报告请求（系统范围、Asia/Shanghai 时区、最近一天）。
func (e *testEnv) startRequest(t *testing.T) StartRequest {
	t.Helper()
	return StartRequest{
		Caller: testCaller(t, 1), ScopeID: "system",
		Window: stats.WindowRequest{TimeZone: "Asia/Shanghai",
			Start: baseTime.Add(-24 * time.Hour), End: baseTime,
			Granularity: stats.GranularityDay},
		Formats: []Format{FormatHTML, FormatCSV, FormatJSON},
	}
}

// startAndGenerate 创建报告并同步执行处理器，返回报告编号与最终视图。
func (e *testEnv) startAndGenerate(t *testing.T, request StartRequest) (string, ReportView) {
	t.Helper()
	ctx := context.Background()
	view, err := e.service.Start(ctx, request)
	if err != nil {
		t.Fatalf("创建报告失败: %v", err)
	}
	job := e.enqueuer.last()
	e.tasks.jobs[job.ID] = job
	if err := e.service.GenerateHandler(ctx, job); err != nil {
		t.Fatalf("生成报告失败: %v", err)
	}
	final, err := e.service.Get(ctx, request.Caller, view.ID)
	if err != nil {
		t.Fatalf("查询报告失败: %v", err)
	}
	return view.ID, final
}

// artifactBytes 读取输出目录中的指定产物（测试用）。
func (e *testEnv) artifactBytes(t *testing.T, reportID string, format Format) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(e.outputDir, artifactFileName(reportID, format)))
	if err != nil {
		t.Fatalf("读取报告产物失败: %v", err)
	}
	return data
}

// outputEntries 返回受控目录中的文件名列表。
func (e *testEnv) outputEntries(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(e.outputDir)
	if err != nil {
		t.Fatalf("读取输出目录失败: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

// TestGenerateArtifactsAndFormats 验证生成、三种产物、HTML 离线/转义、CSV 引号
// 换行与公式注入防护、JSON 稳定结构、图表与明细同一快照。
func TestGenerateArtifactsAndFormats(t *testing.T) {
	env := newTestEnv(t)
	env.grantAll(testUserID(1), "system", stats.ScopeGrant{Allowed: true, AllData: true})
	reportID, view := env.startAndGenerate(t, env.startRequest(t))

	if view.State != StateSucceeded {
		t.Fatalf("报告状态 = %s，期望 succeeded", view.State)
	}
	if view.Summary.ActiveUsers != 7 || view.Summary.TotalRawEvents != 10 ||
		view.Summary.FailedRequests != 6 || view.Summary.FailedTasks != 1 {
		t.Fatalf("报告摘要不符: %+v", view.Summary)
	}
	if len(view.Artifacts) != 3 {
		t.Fatalf("产物数量 = %d，期望 3", len(view.Artifacts))
	}
	for _, artifact := range view.Artifacts {
		if len(artifact.SHA256) != 64 || artifact.Bytes == 0 || !artifact.Available {
			t.Fatalf("产物元数据不完整: %+v", artifact)
		}
	}
	if !env.recorder.hasAction(ActionGenerateFinish) {
		t.Error("缺少生成完成审计事件")
	}
	snapshot, err := env.service.GetSnapshot(context.Background(),
		env.startRequest(t).Caller, reportID)
	if err != nil {
		t.Fatalf("读取快照失败: %v", err)
	}
	if snapshot.Report.ID != reportID || snapshot.Schema.Version != SchemaVersion ||
		snapshot.Schema.TemplateVersion != TemplateVersion {
		t.Fatalf("快照元数据不符: %+v", snapshot.Report)
	}
	if len(snapshot.Activity.Points) != len(snapshot.Report.Window.Buckets) {
		t.Fatalf("活跃度点数 = %d，桶数 = %d，期望同一快照",
			len(snapshot.Activity.Points), len(snapshot.Report.Window.Buckets))
	}
	if len(snapshot.Trend.Points) != len(snapshot.Report.Window.Buckets)*len(snapshot.Errors.Rows) {
		t.Fatalf("趋势点数与明细行/桶不一致: %d", len(snapshot.Trend.Points))
	}
	var trendTotal int64
	for _, point := range snapshot.Trend.Points {
		trendTotal += point.RawEvents
	}
	if trendTotal != snapshot.Errors.TotalRawEvents {
		t.Fatalf("趋势原始事件合计 = %d，汇总 = %d，期望同一口径", trendTotal,
			snapshot.Errors.TotalRawEvents)
	}

	// HTML：自包含、无外部资源、中文保留、不可信文本被转义。
	htmlBytes := env.artifactBytes(t, reportID, FormatHTML)
	htmlText := string(htmlBytes)
	if !strings.HasPrefix(htmlText, "<!doctype html>") {
		t.Fatal("HTML 产物缺少 doctype")
	}
	if !strings.Contains(htmlText, "统计报告") || !strings.Contains(htmlText, "口径定义") {
		t.Fatal("HTML 缺少中文固定章节")
	}
	for _, forbidden := range []string{"http://", "https://", "<script", "<link ", "@import", "src="} {
		if strings.Contains(htmlText, forbidden) {
			t.Errorf("HTML 含外部资源或不安全内容 %q", forbidden)
		}
	}
	if strings.Contains(htmlText, "<script>alert") {
		t.Fatal("HTML 未转义不可信错误码")
	}
	if !strings.Contains(htmlText, "&lt;") {
		t.Fatal("HTML 未对特殊字符转义")
	}
	if !strings.Contains(htmlText, "未知（不可当作 0）") {
		t.Error("HTML 未把未知状态明确标为未知")
	}
	// 图表与表格同源：内联 SVG 柱状图与表格使用同一快照数值（峰值与类别次数）。
	if !strings.Contains(htmlText, "<svg") || !strings.Contains(htmlText, "峰值 2 人") {
		t.Error("HTML 缺少与数据表同源的活跃度内联 SVG 图")
	}
	if !strings.Contains(htmlText, "系统故障: 5 次") {
		t.Error("HTML 类别图未使用与明细同一快照的原始事件次数")
	}
	if strings.Count(htmlText, "<table") != strings.Count(htmlText, "</table>") {
		t.Error("HTML 表格标签不配对，离线打开可能结构异常")
	}
	if !strings.Contains(htmlText, "</html>") {
		t.Error("HTML 文档未闭合")
	}

	// CSV：稳定表头、公式注入防护、引号/逗号/换行正确往返。
	csvBytes := env.artifactBytes(t, reportID, FormatCSV)
	reader := csv.NewReader(strings.NewReader(string(csvBytes)))
	reader.FieldsPerRecord = len(csvColumns)
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("CSV 解析失败: %v", err)
	}
	if len(records) < 2 {
		t.Fatal("CSV 记录过少")
	}
	for index, column := range csvColumns {
		if records[0][index] != column {
			t.Fatalf("CSV 表头第 %d 列 = %q，期望 %q", index, records[0][index], column)
		}
	}
	formula := `'=cmd|' /C calc'!A0,"quoted"` + "\n下一行"
	foundFormula := false
	for _, record := range records[1:] {
		if record[7] == formula {
			foundFormula = true
			// 值行整体列语义必须正确：B1 回归断言（metric/value/unit/status）。
			if record[9] == "raw_events" && (record[10] != "2" || record[11] != "events") {
				t.Fatalf("CSV error_row 列错位: metric=%q value=%q unit=%q", record[9], record[10], record[11])
			}
		}
	}
	if !foundFormula {
		t.Fatal("CSV 公式载荷未按文本转义或引号/换行往返失败")
	}
	// 逐 section 精确断言 value/unit/status/first_seen/last_seen/note 列语义。
	reportIDCell, activityCells, totalCells := "", 0, 0
	authCells, growthCells, noteCells := 0, 0, 0
	for _, record := range records[1:] {
		switch record[0] {
		case "meta":
			if record[1] == "report_id" {
				reportIDCell = record[10]
				if record[15] != "" {
					t.Fatalf("meta 值错列到 note: %v", record)
				}
			}
		case "note":
			noteCells++
			if record[10] != "" || record[15] == "" {
				t.Fatalf("note 行值/说明列错位: %v", record)
			}
		case "activity":
			activityCells++
			if record[9] != "active_users" || record[11] != "users" || record[12] != "complete" {
				t.Fatalf("activity 列错位: %v", record)
			}
			value, err := strconv.ParseFloat(record[10], 64)
			if err != nil || value < 1 {
				t.Fatalf("activity value 不是数值: %q", record[10])
			}
			if _, err := time.Parse(reportTimeLayout, record[3]); err != nil {
				t.Fatalf("activity bucket_start 不是 RFC3339: %q", record[3])
			}
		case "activity_total":
			totalCells++
			if record[10] != "7" || record[11] != "users" || record[9] != "total_distinct_users" {
				t.Fatalf("activity_total 列错位: %v", record)
			}
		case "errors_total":
			if record[9] == "total_raw_events" && record[10] != "10" {
				t.Fatalf("errors_total 值不符: %q", record[10])
			}
			wantUnit := map[string]string{"total_raw_events": "events",
				"failed_requests": "requests", "failed_tasks": "tasks"}[record[9]]
			if record[11] != wantUnit {
				t.Fatalf("errors_total 单位错位: %v", record)
			}
			if record[12] != "partial" && record[12] != "complete" {
				t.Fatalf("errors_total 状态错位: %v", record)
			}
		case "error_row":
			switch record[9] {
			case "raw_events":
				if record[7] == "AUTH_FAILED" {
					authCells++
					if record[10] != "5" || record[11] != "events" {
						t.Fatalf("error_row raw_events 列错位: %v", record)
					}
					if _, err := time.Parse(reportTimeLayout, record[13]); err != nil {
						t.Fatalf("error_row first_seen 不是 RFC3339: %q", record[13])
					}
					if _, err := time.Parse(reportTimeLayout, record[14]); err != nil {
						t.Fatalf("error_row last_seen 不是 RFC3339: %q", record[14])
					}
				}
			case "growth_percent":
				if record[7] == `测试<脚本>"引号"` {
					growthCells++
					if record[10] != "-12.5" {
						t.Fatalf("负增幅应为不加前缀的数值 -12.5，实际 %q", record[10])
					}
					if record[11] != "percent" || record[12] != "percent" {
						t.Fatalf("growth 单位/kind 错位: %v", record)
					}
				}
			}
		}
	}
	if reportIDCell != reportID {
		t.Fatalf("CSV meta report_id 值 = %q，期望 %q", reportIDCell, reportID)
	}
	if activityCells == 0 || totalCells != 1 || authCells == 0 || growthCells == 0 {
		t.Fatalf("CSV 关键行缺失: activity=%d total=%d auth=%d growth=%d",
			activityCells, totalCells, authCells, growthCells)
	}
	if noteCells == 0 {
		t.Fatal("CSV 缺少完整性说明行")
	}
	// 数值列不得被公式注入防护加前缀（负数保持数字）。
	for _, record := range records[1:] {
		switch record[0] {
		case "activity", "activity_total", "category_summary", "errors_total", "trend", "error_row":
			if record[10] == "" {
				continue
			}
			if strings.HasPrefix(record[10], "'") {
				t.Fatalf("数值列被加上公式前缀: %v", record)
			}
			if _, err := strconv.ParseFloat(record[10], 64); err != nil {
				t.Fatalf("数值列不是数字: %q（%v）", record[10], record)
			}
		}
	}

	// JSON：稳定 schema、数值为数字、时间为 RFC3339 UTC。
	jsonBytes := env.artifactBytes(t, reportID, FormatJSON)
	var document map[string]any
	if err := json.Unmarshal(jsonBytes, &document); err != nil {
		t.Fatalf("JSON 解析失败: %v", err)
	}
	schema, ok := document["schema"].(map[string]any)
	if !ok || schema["version"] != SchemaVersion {
		t.Fatalf("JSON schema 不符: %v", document["schema"])
	}
	report, ok := document["report"].(map[string]any)
	if !ok || report["id"] != reportID {
		t.Fatalf("JSON report.id 不符: %v", document["report"])
	}
	generatedAt, ok := report["generated_at"].(string)
	if !ok {
		t.Fatal("JSON generated_at 不是字符串")
	}
	if _, err := time.Parse(reportTimeLayout, generatedAt); err != nil {
		t.Fatalf("JSON generated_at 不是 RFC3339: %v", err)
	}
	activity, ok := document["activity"].(map[string]any)
	if !ok {
		t.Fatal("JSON 缺少 activity")
	}
	if _, ok := activity["total_distinct_users"].(float64); !ok {
		t.Fatalf("JSON activity 数值不是 JSON 数字: %v", activity["total_distinct_users"])
	}
}

// TestPermissionRevokedAndDownloadAuthorization 验证权限撤销后不可查看/下载、产物
// 绑定发起者、root 可下载、产物篡改被拒绝。
func TestPermissionRevokedAndDownloadAuthorization(t *testing.T) {
	env := newTestEnv(t)
	caller := testCaller(t, 1)
	scopeID := "app_demo1"
	env.grantAll(caller.Actor().ID, scopeID, stats.ScopeGrant{Allowed: true,
		ResourceIDs: []string{scopeID}})
	request := env.startRequest(t)
	request.ScopeID = scopeID
	reportID, view := env.startAndGenerate(t, request)
	if view.State != StateSucceeded {
		t.Fatalf("报告状态 = %s", view.State)
	}
	ctx := context.Background()

	// 权限撤销：导出与查看都拒绝，产物文件仍在但不可下载。
	env.authorizer.deny(PermissionExport, scopeID)
	if _, err := env.service.OpenFile(ctx, caller, reportID, FormatHTML); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("撤销导出权限后下载错误 = %v，期望 ErrAccessDenied", err)
	}
	env.authorizer.deny(PermissionRead, scopeID)
	if _, err := env.service.Get(ctx, caller, reportID); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("撤销查看权限后查询错误 = %v，期望 ErrAccessDenied", err)
	}
	env.grantAll(caller.Actor().ID, scopeID, stats.ScopeGrant{Allowed: true,
		ResourceIDs: []string{scopeID}})

	// 同范围其他用户：可查看元数据（有读权限），但不可下载他人生成的产物。
	other := testCaller(t, 2)
	env.grantAll(other.Actor().ID, scopeID, stats.ScopeGrant{Allowed: true,
		ResourceIDs: []string{scopeID}})
	if _, err := env.service.Get(ctx, other, reportID); err != nil {
		t.Fatalf("同范围读权限用户查看元数据失败: %v", err)
	}
	if _, err := env.service.OpenFile(ctx, other, reportID, FormatHTML); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("他人下载错误 = %v，期望 ErrAccessDenied", err)
	}
	// root 可下载他人报告。
	env.root.roots[other.Actor().ID] = true
	file, err := env.service.OpenFile(ctx, other, reportID, FormatHTML)
	if err != nil {
		t.Fatalf("root 下载失败: %v", err)
	}
	if file.Bytes == 0 || len(file.SHA256) != 64 || filepath.Dir(file.HostPath) != env.outputDir {
		t.Fatalf("下载句柄不符: %+v", file)
	}
	env.root.roots[other.Actor().ID] = false

	// 产物篡改：摘要不符拒绝下发。
	path := filepath.Join(env.outputDir, artifactFileName(reportID, FormatHTML))
	if err := os.WriteFile(path, []byte("tampered"), 0o600); err != nil {
		t.Fatalf("篡改产物失败: %v", err)
	}
	if _, err := env.service.OpenFile(ctx, caller, reportID, FormatHTML); !errors.Is(err, ErrArtifactUnsafe) {
		t.Fatalf("篡改产物下载错误 = %v，期望 ErrArtifactUnsafe", err)
	}
}

// TestCancelledAndFailedLeaveNoArtifacts 验证取消/失败不留下可下载或临时产物。
func TestCancelledAndFailedLeaveNoArtifacts(t *testing.T) {
	env := newTestEnv(t)
	env.grantAll(testUserID(1), "system", stats.ScopeGrant{Allowed: true, AllData: true})
	ctx := context.Background()

	// queued 取消：记录收敛为 cancelled，输出目录为空。
	view, err := env.service.Start(ctx, env.startRequest(t))
	if err != nil {
		t.Fatalf("创建报告失败: %v", err)
	}
	job := env.enqueuer.last()
	env.tasks.jobs[job.ID] = job
	result, err := env.service.Cancel(ctx, testCaller(t, 1), view.ID, "用户取消", "")
	if err != nil {
		t.Fatalf("取消报告失败: %v", err)
	}
	if result.State != task.StateCancelled {
		t.Fatalf("取消结果状态 = %s", result.State)
	}
	final, err := env.service.Get(ctx, testCaller(t, 1), view.ID)
	if err != nil {
		t.Fatalf("查询取消报告失败: %v", err)
	}
	if final.State != StateCancelled || final.ErrorCode != string(CodeTaskCancelled) {
		t.Fatalf("取消终态不符: %+v", final)
	}
	if names := env.outputEntries(t); len(names) != 0 {
		t.Fatalf("取消后残留产物: %v", names)
	}
	if err := env.service.GenerateHandler(ctx, job); !errors.Is(err, ErrTaskTerminal) {
		t.Fatalf("取消后处理器错误 = %v，期望 ErrTaskTerminal", err)
	}
	if _, err := env.service.OpenFile(ctx, testCaller(t, 1), view.ID, FormatHTML); err == nil {
		t.Fatal("取消报告仍可下载")
	}

	// 统计读取失败：失败终态 + 无产物。
	env.source.err = errors.New("db down")
	failedView, err := env.service.Start(ctx, env.startRequest(t))
	if err != nil {
		t.Fatalf("创建报告失败: %v", err)
	}
	failedJob := env.enqueuer.last()
	env.tasks.jobs[failedJob.ID] = failedJob
	if err := env.service.GenerateHandler(ctx, failedJob); err == nil {
		t.Fatal("期望生成失败，实际成功")
	}
	failedFinal, err := env.service.Get(ctx, testCaller(t, 1), failedView.ID)
	if err != nil {
		t.Fatalf("查询失败报告失败: %v", err)
	}
	if failedFinal.State != StateFailed ||
		failedFinal.ErrorCode != string(CodeReportGeneration) {
		t.Fatalf("失败终态不符: %+v", failedFinal)
	}
	if names := env.outputEntries(t); len(names) != 0 {
		t.Fatalf("失败后残留产物: %v", names)
	}

	// 生成过程被取消（上下文取消）：真实取消终态 + 无产物。
	env.source.err = nil
	env.source.cancelled = true
	cancelledView, err := env.service.Start(ctx, env.startRequest(t))
	if err != nil {
		t.Fatalf("创建报告失败: %v", err)
	}
	cancelledJob := env.enqueuer.last()
	env.tasks.jobs[cancelledJob.ID] = cancelledJob
	if err := env.service.GenerateHandler(ctx, cancelledJob); err == nil {
		t.Fatal("期望生成被取消，实际成功")
	}
	cancelledFinal, err := env.service.Get(ctx, testCaller(t, 1), cancelledView.ID)
	if err != nil {
		t.Fatalf("查询取消报告失败: %v", err)
	}
	if cancelledFinal.State != StateCancelled {
		t.Fatalf("上下文取消后的状态 = %s，期望 cancelled", cancelledFinal.State)
	}
	if names := env.outputEntries(t); len(names) != 0 {
		t.Fatalf("上下文取消后残留产物: %v", names)
	}
}

// TestPartialCompletenessAndMissingData 验证数据缺失/截断/裁剪显式表达且不补零。
func TestPartialCompletenessAndMissingData(t *testing.T) {
	env := newTestEnv(t)
	env.grantAll(testUserID(1), "system", stats.ScopeGrant{Allowed: true, AllData: true})
	env.source.hasMore = true
	env.source.completeness = stats.Completeness{
		WindowWithinRetention: false, RetentionDays: 30, RetentionConfigured: false,
		RetentionCutoff: baseTime.AddDate(0, 0, -30),
		MissingIntervals: []stats.MissingInterval{{Start: baseTime.AddDate(0, 0, -2),
			End: baseTime.AddDate(0, 0, -30), Reason: "retention"}},
		ScopeTrimmed: true, SourceTruncated: true,
		ModulesNotEnabled: []stats.Module{stats.ModuleBackup},
	}
	reportID, view := env.startAndGenerate(t, env.startRequest(t))
	if view.OverallStatus != string(stats.DataPartial) {
		t.Fatalf("总体状态 = %s，期望 partial", view.OverallStatus)
	}
	if !view.Completeness.DetailRowsTruncated || !view.Completeness.ScopeTrimmed ||
		!view.Completeness.SourceTruncated {
		t.Fatalf("完整性标记丢失: %+v", view.Completeness)
	}
	joined := strings.Join(view.Notes, " ")
	for _, keyword := range []string{"未知", "不完整", "保留", "裁剪"} {
		if !strings.Contains(joined, keyword) {
			t.Errorf("完整性说明缺少 %q: %s", keyword, joined)
		}
	}
	jsonBytes := env.artifactBytes(t, reportID, FormatJSON)
	var document map[string]any
	if err := json.Unmarshal(jsonBytes, &document); err != nil {
		t.Fatalf("JSON 解析失败: %v", err)
	}
	completeness, ok := document["completeness"].(map[string]any)
	if !ok {
		t.Fatal("JSON 缺少 completeness")
	}
	if completeness["detail_rows_truncated"] != true ||
		completeness["scope_trimmed"] != true {
		t.Fatalf("JSON 完整性字段不符: %v", completeness)
	}
	rows := document["errors"].(map[string]any)["rows"].([]any)
	if len(rows) == 0 {
		t.Fatal("JSON 缺少错误明细")
	}
	foundUnknown := false
	for _, rawRow := range rows {
		if rawRow.(map[string]any)["status"] == "unknown" {
			foundUnknown = true
		}
	}
	if !foundUnknown {
		t.Fatal("未知状态行未保留 unknown（不能当作完整零值）")
	}
	htmlText := string(env.artifactBytes(t, reportID, FormatHTML))
	if !strings.Contains(htmlText, "部分（不完整）") || !strings.Contains(htmlText, "未知（不可当作 0）") {
		t.Error("HTML 未展示数据缺失/未知状态")
	}
}

// TestValidationAndDeniedPaths 验证构造与请求边界、敏感操作拒绝、缺权限拒绝。
func TestValidationAndDeniedPaths(t *testing.T) {
	// 缺依赖 → 拒绝构造（fail-closed）。
	if _, err := New(Options{}); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatalf("空配置构造错误 = %v", err)
	}
	env := newTestEnv(t)
	// 明细上限超出硬上限 → 拒绝构造。
	if _, err := New(Options{Source: env.source, Authorizer: env.authorizer,
		Root: env.root, Sensitive: env.sensitive, Audit: env.recorder,
		Enqueuer: env.enqueuer, Canceller: env.canceller,
		OutputDir: env.outputDir, MaxDetailRows: MaxDetailRows + 1,
		Now: env.now}); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatalf("超限明细构造错误 = %v", err)
	}
	ctx := context.Background()

	// 缺权限 → 拒绝且写拒绝审计。
	view, err := env.service.Start(ctx, env.startRequest(t))
	if !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("缺权限创建错误 = %v，期望 ErrAccessDenied", err)
	}
	if view.ID != "" || !env.recorder.hasAction(ActionAccessDenied) {
		t.Fatalf("拒绝路径未留痕: %+v", view)
	}

	env.grantAll(testUserID(1), "system", stats.ScopeGrant{Allowed: true, AllData: true})
	// 空作用范围。
	request := env.startRequest(t)
	request.ScopeID = ""
	if _, err := env.service.Start(ctx, request); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("空作用范围错误 = %v", err)
	}
	// 非法时区。
	request = env.startRequest(t)
	request.Window.TimeZone = "Mars/Olympus"
	if _, err := env.service.Start(ctx, request); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("非法时区错误 = %v", err)
	}
	// 非法格式。
	request = env.startRequest(t)
	request.Formats = []Format{"xml"}
	if _, err := env.service.Start(ctx, request); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("非法格式错误 = %v", err)
	}
	// 未配置 PDF 字体时请求 PDF → 明确拒绝（不生成假 PDF）。
	request = env.startRequest(t)
	request.Formats = []Format{FormatPDF}
	if _, err := env.service.Start(ctx, request); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("未配置字体请求 PDF 错误 = %v，期望 ErrInvalidRequest", err)
	}
	// 明细上限超出服务配置。
	request = env.startRequest(t)
	request.MaxDetailRows = 51
	if _, err := env.service.Start(ctx, request); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("超限明细错误 = %v", err)
	}
	// 趋势指标未登记。
	request = env.startRequest(t)
	request.TrendMetric = "unknown_metric"
	if _, err := env.service.Start(ctx, request); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("未登记趋势指标错误 = %v", err)
	}
	// 系统范围应用筛选越权。
	env.authorizer.allow(PermissionRead, "system",
		stats.ScopeGrant{Allowed: true, ResourceIDs: []string{"app_demo1"}})
	request = env.startRequest(t)
	request.AppID = "app_other"
	if _, err := env.service.Start(ctx, request); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("越权应用筛选错误 = %v，期望 ErrAccessDenied", err)
	}
	env.grantAll(testUserID(1), "system", stats.ScopeGrant{Allowed: true, AllData: true})
	// CSV/JSON 导出缺少 reports.export。
	env.authorizer.deny(PermissionExport, "system")
	request = env.startRequest(t)
	request.Formats = []Format{FormatCSV}
	if _, err := env.service.Start(ctx, request); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("缺导出权限错误 = %v，期望 ErrAccessDenied", err)
	}
	// HTML 产物同样属受控导出面：与 reports.export 敏感操作声明一致，缺导出权限拒绝。
	request = env.startRequest(t)
	request.Formats = []Format{FormatHTML}
	if _, err := env.service.Start(ctx, request); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("仅 HTML 缺导出权限错误 = %v，期望 ErrAccessDenied", err)
	}
	env.grantAll(testUserID(1), "system", stats.ScopeGrant{Allowed: true, AllData: true})
	request = env.startRequest(t)
	request.Formats = []Format{FormatHTML}
	if _, err := env.service.Start(ctx, request); err != nil {
		t.Fatalf("恢复导出权限后仅 HTML 生成失败: %v", err)
	}
	// 敏感操作拒绝。
	env.grantAll(testUserID(1), "system", stats.ScopeGrant{Allowed: true, AllData: true})
	env.sensitive.denied = true
	request = env.startRequest(t)
	request.Formats = []Format{FormatHTML}
	if _, err := env.service.Start(ctx, request); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("敏感操作拒绝错误 = %v，期望 ErrAccessDenied", err)
	}
	env.sensitive.denied = false

	// 非法/不存在报告编号查询。
	if _, err := env.service.Get(ctx, testCaller(t, 1), "not-a-report"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("非法报告编号错误 = %v", err)
	}
	missingID := reportIDPrefix + strings.Repeat("0", 32)
	if _, err := env.service.Get(ctx, testCaller(t, 1), missingID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("不存在报告错误 = %v，期望 ErrNotFound", err)
	}
}

// TestCancelValidation 验证取消原因与终态边界。
func TestCancelValidation(t *testing.T) {
	env := newTestEnv(t)
	env.grantAll(testUserID(1), "system", stats.ScopeGrant{Allowed: true, AllData: true})
	ctx := context.Background()
	view, err := env.service.Start(ctx, env.startRequest(t))
	if err != nil {
		t.Fatalf("创建报告失败: %v", err)
	}
	if _, err := env.service.Cancel(ctx, testCaller(t, 1), view.ID, "", ""); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("空取消原因错误 = %v", err)
	}
	// 非所有者不能取消。
	env.grantAll(testUserID(2), "system", stats.ScopeGrant{Allowed: true, AllData: true})
	if _, err := env.service.Cancel(ctx, testCaller(t, 2), view.ID, "尝试取消", ""); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("非所有者取消错误 = %v", err)
	}
	// 已完成任务不能再取消。
	env.canceller.state = task.StateCancelled
	if _, err := env.service.Cancel(ctx, testCaller(t, 1), view.ID, "取消", ""); err != nil {
		t.Fatalf("所有者取消失败: %v", err)
	}
	env.canceller.err = task.ErrTaskTerminal
	if _, err := env.service.Cancel(ctx, testCaller(t, 1), view.ID, "再取消", ""); !errors.Is(err, ErrTaskTerminal) {
		t.Fatalf("终态取消错误 = %v，期望 ErrTaskTerminal", err)
	}
}
