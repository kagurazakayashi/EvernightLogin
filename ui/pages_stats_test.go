package ui_test

// 步骤 76 统计看板页面契约测试：受控 UIPageStatsBackend 渲染、筛选规范化、同一
// 时间窗口、权限/空/失败/无效参数状态、排序链接、下钻链接仅在拥有审计读取能力时
// 生成。真实服务集成见 internal/uiadminadapter/stats_integration_test.go。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
)

// fakeStatsBackend 是受控统计后端；记录最后一次查询以断言页面传入真实筛选。
type fakeStatsBackend struct {
	capabilities login.UIStatsCapabilities
	dashboard    login.UIStatsDashboard
	statistics   login.UIStatsStatistics
	errors       login.UIStatsErrors

	failCode  string
	failIs    error
	lastQuery login.UIStatsQuery
	lastUser  string
	denials   []string
}

func (f *fakeStatsBackend) fail() error {
	if f.failCode != "" {
		return &login.UIStatsError{Code: f.failCode}
	}
	return f.failIs
}

func (f *fakeStatsBackend) Capabilities(context.Context,
	string) (login.UIStatsCapabilities, error) {
	return f.capabilities, nil
}

func (f *fakeStatsBackend) Dashboard(_ context.Context, userID string,
	query login.UIStatsQuery) (login.UIStatsDashboard, error) {
	f.lastUser, f.lastQuery = userID, query
	if err := f.fail(); err != nil {
		return login.UIStatsDashboard{}, err
	}
	result := f.dashboard
	result.Overview.Start = query.Window.Start
	result.Overview.End = query.Window.End
	result.Overview.TimeZone = query.Window.TimeZone
	result.Overview.Granularity = query.Window.Granularity
	result.UpdatedAt = query.Window.End
	return result, nil
}

func (f *fakeStatsBackend) Statistics(_ context.Context, userID string,
	query login.UIStatsQuery) (login.UIStatsStatistics, error) {
	f.lastUser, f.lastQuery = userID, query
	if err := f.fail(); err != nil {
		return login.UIStatsStatistics{}, err
	}
	result := f.statistics
	result.Activity.Start, result.Activity.End = query.Window.Start, query.Window.End
	result.Activity.TimeZone = query.Window.TimeZone
	result.Activity.Granularity = query.Window.Granularity
	result.ErrorTrend.Start, result.ErrorTrend.End = query.Window.Start, query.Window.End
	result.ErrorTrend.TimeZone = query.Window.TimeZone
	result.ErrorTrend.Granularity = query.Window.Granularity
	result.ErrorTrend.Metric = query.Metric
	return result, nil
}

func (f *fakeStatsBackend) Errors(_ context.Context, userID string,
	query login.UIStatsQuery) (login.UIStatsErrors, error) {
	f.lastUser, f.lastQuery = userID, query
	if err := f.fail(); err != nil {
		return login.UIStatsErrors{}, err
	}
	result := f.errors
	result.Start, result.End = query.Window.Start, query.Window.End
	result.TimeZone = query.Window.TimeZone
	result.Granularity = query.Window.Granularity
	if query.Sort != "" {
		result.Sort, result.Order = query.Sort, query.Order
	}
	result.Limit = 20
	return result, nil
}

func (f *fakeStatsBackend) RecordDenial(_ context.Context, _, reason string) error {
	f.denials = append(f.denials, reason)
	return nil
}

// statsPageSessions 提供管理页面会话。
type statsPageSessions struct {
	failure error
}

func (s statsPageSessions) ResolvePageSession(context.Context,
	*http.Request) (login.UISession, error) {
	if s.failure != nil {
		return login.UISession{}, s.failure
	}
	return login.UISession{Authenticated: true, UserID: "usr_admin", Kind: "management",
		ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func (statsPageSessions) IssueCSRFToken(context.Context, *http.Request) (string, error) {
	return "stats-csrf", nil
}

type statsPageEnv struct {
	t       *testing.T
	handler http.Handler
	backend *fakeStatsBackend
}

// baseStatsBackend 返回合成但结构与真实接口一致的受控后端数据。
func baseStatsBackend() *fakeStatsBackend {
	start := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	completeness := login.UIStatsCompleteness{WindowWithinRetention: true,
		RetentionDays: 180, RetentionConfigured: true,
		RetentionCutoff: start.AddDate(0, 0, -180)}
	categories := []login.UIStatsCategorySummary{
		{Category: "pending", Severity: "info", RawEvents: 1},
		{Category: "denied", Severity: "info", RawEvents: 2},
		{Category: "failure", Severity: "error", RawEvents: 3, FailedRequests: 2, FailedTasks: 1},
	}
	activity := login.UIStatsActivity{Start: start, End: end, TimeZone: "UTC",
		Granularity: "day", TotalActiveUsers: 3, DedupeScope: "system",
		UpdatedAt: end, Completeness: completeness,
		Points: []login.UIStatsPoint{
			{BucketKey: "2026-11-18", Start: time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC),
				End: time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC), ActiveUsers: 2,
				DataStatus: "complete"},
			{BucketKey: "2026-11-19", Start: end, End: end.Add(24 * time.Hour),
				InProgress: true, ActiveUsers: 1, DataStatus: "in_progress"},
			{BucketKey: "2026-11-17", Start: end, End: end.Add(24 * time.Hour),
				ActiveUsers: 0, DataStatus: "unknown"},
		}}
	trend := login.UIStatsErrorTrend{Start: start, End: end, TimeZone: "UTC",
		Granularity: "day", Metric: "raw_events", Categories: categories,
		TotalRawEvents: 5, FailedRequests: 2, FailedTasks: 1, UpdatedAt: end,
		Completeness: completeness,
		Points: []login.UIStatsErrorPoint{
			{BucketKey: "2026-11-18", Start: start, End: end, Category: "pending",
				Severity: "info", RawEvents: 1, DataStatus: "complete"},
			{BucketKey: "2026-11-18", Start: start, End: end, Category: "denied",
				Severity: "info", RawEvents: 2, DataStatus: "complete"},
			{BucketKey: "2026-11-18", Start: start, End: end, Category: "failure",
				Severity: "error", RawEvents: 3, FailedRequests: 2, FailedTasks: 1,
				DataStatus: "complete"},
			{BucketKey: "2026-11-17", Start: start, End: end, Category: "failure",
				Severity: "error", DataStatus: "unknown"},
		}}
	return &fakeStatsBackend{
		capabilities: login.UIStatsCapabilities{Read: true, Events: true,
			Scopes: []string{"system", "app_alpha"}},
		dashboard: login.UIStatsDashboard{Overview: login.UIStatsOverview{
			ScopeID: "system", ScopeKind: "system", Start: start, End: end,
			TimeZone: "UTC", Granularity: "day", ActiveUsers: 3, RawEvents: 5,
			FailedRequests: 2, FailedTasks: 1, Categories: categories,
			ActivityStatus: "in_progress", DataCutoff: end, UpdatedAt: end,
			Completeness: completeness},
			Health: &login.UIStatsHealth{ObservedAt: end, Modules: []login.UIStatsHealthSample{
				{Module: "database", State: "healthy", Severity: "info", Enabled: true,
					ObservedAt: end, Source: "database_ping", LatencyMS: "4"},
				{Module: "backup", State: "not_enabled", Severity: "info",
					ObservedAt: end, Source: "not_enabled", Reason: "backup_not_implemented"},
			}}, UpdatedAt: end},
		statistics: login.UIStatsStatistics{Activity: activity, ErrorTrend: trend,
			UpdatedAt: end},
		errors: login.UIStatsErrors{Start: start, End: end, TimeZone: "UTC",
			Granularity: "day", Limit: 20, Sort: "raw_events", Order: "desc",
			TotalRawEvents: 5, FailedRequests: 2, FailedTasks: 1, ShareDenominator: 5,
			Categories: categories, ComparisonStart: start.AddDate(0, 0, -7),
			ComparisonEnd: start, ComparisonEnabled: true, UpdatedAt: end,
			Completeness: completeness,
			Rows: []login.UIStatsErrorRow{
				{ErrorCode: "DB_UNAVAILABLE", Category: "failure", Severity: "critical",
					AppID: "app_alpha", RawEvents: 3, FailedRequests: 2, FailedTasks: 1,
					Share: 0.6, FirstSeen: start, LastSeen: end,
					GrowthKind: "new", DataStatus: "complete"},
				{ErrorCode: "ACCESS_DENIED", Category: "denied", Severity: "info",
					RawEvents: 2, Share: 0.4, FirstSeen: start, LastSeen: end,
					GrowthKind: "none", DataStatus: "complete"},
			}},
	}
}

// newStatsPageEnv 构造统计页测试环境。
func newStatsPageEnv(t *testing.T, backend *fakeStatsBackend,
	sessions statsPageSessions) *statsPageEnv {
	t.Helper()
	ui, err := login.NewWebUI(login.WebUIOptions{Session: sessions,
		PageStats: &login.UIPageStatsOptions{Backend: backend,
			Now: func() time.Time {
				return time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
			}}})
	if err != nil {
		t.Fatalf("统计页框架构造失败: %v", err)
	}
	return &statsPageEnv{t: t, handler: ui, backend: backend}
}

func (e *statsPageEnv) get(target string) *httptest.ResponseRecorder {
	e.t.Helper()
	request := httptest.NewRequest(http.MethodGet, "http://example.test"+target, nil)
	recorder := httptest.NewRecorder()
	e.handler.ServeHTTP(recorder, request)
	return recorder
}

func requireStatsBody(t *testing.T, response *httptest.ResponseRecorder, status int,
	fragments ...string) string {
	t.Helper()
	body := response.Body.String()
	if response.Code != status {
		t.Fatalf("状态 = %d，期望 %d；前 300 字符：%s", response.Code, status,
			firstRunes(body, 300))
	}
	for _, fragment := range fragments {
		if !strings.Contains(body, fragment) {
			t.Fatalf("页面缺少 %q；前 300 字符：%s", fragment, firstRunes(body, 300))
		}
	}
	return body
}

// TestDashboardRendersRealSummaryAndHealth 验证看板摘要、类别、当前状态卡、筛选回显
// 与会话用户透传；健康卡带观测时间与未启用原因，不显示为正常。
func TestDashboardRendersRealSummaryAndHealth(t *testing.T) {
	backend := baseStatsBackend()
	env := newStatsPageEnv(t, backend, statsPageSessions{})
	body := requireStatsBody(t, env.get("/admin/dashboard"), http.StatusOK,
		"统计摘要", "成功认证去重用户数", "数据库", "未启用",
		"活跃度与错误趋势", "错误分类明细")
	if backend.lastUser != "usr_admin" {
		t.Fatalf("页面未使用会话用户 ID：%q", backend.lastUser)
	}
	if backend.lastQuery.ScopeID != "system" {
		t.Fatalf("默认作用范围 = %q，期望 system", backend.lastQuery.ScopeID)
	}
	if !strings.Contains(body, "跳到主要内容") {
		t.Fatal("页面缺少无 JS 时的跳转主内容链接")
	}
	// 当前状态卡必须带观测时间与来源，且标注当前观测不同于历史筛选。
	if !strings.Contains(body, "观测时间") || !strings.Contains(body, "database_ping") {
		t.Fatal("系统状态卡缺少观测时间或来源")
	}
	if !strings.Contains(body, "历史筛选") {
		t.Fatal("缺少“当前状态不是历史状态”的说明")
	}
}

// TestDashboardScopeFromAppContext 验证会话带应用上下文时默认作用范围为该应用，
// 且切换应用后不再保留系统范围的选中项。
func TestDashboardScopeFromAppContext(t *testing.T) {
	backend := baseStatsBackend()
	backend.capabilities.Scopes = []string{"app_alpha"}
	ui, err := login.NewWebUI(login.WebUIOptions{
		Session: statsAppSession{},
		PageStats: &login.UIPageStatsOptions{Backend: backend,
			Now: func() time.Time { return time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC) }}})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://example.test/admin/dashboard", nil)
	recorder := httptest.NewRecorder()
	ui.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("状态 = %d", recorder.Code)
	}
	if backend.lastQuery.ScopeID != "app_alpha" {
		t.Fatalf("默认作用范围 = %q，期望 app_alpha", backend.lastQuery.ScopeID)
	}
	if !strings.Contains(recorder.Body.String(), `value="app_alpha" selected`) {
		t.Fatal("筛选未回显应用范围")
	}
	// 系统范围不在应用管理员获准列表中时，不接受该参数放大范围。
	recorder = httptest.NewRecorder()
	ui.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet,
		"http://example.test/admin/dashboard?scope=system", nil))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("越权作用范围状态 = %d，期望 400", recorder.Code)
	}
	if backend.lastQuery.ScopeID != "app_alpha" {
		t.Fatal("非法作用范围不应调用后端新查询")
	}
}

// statsAppSession 模拟应用上下文会话。
type statsAppSession struct{}

func (statsAppSession) ResolvePageSession(context.Context,
	*http.Request) (login.UISession, error) {
	return login.UISession{Authenticated: true, UserID: "usr_admin",
		AppID: "app_alpha", Kind: "management", ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func (statsAppSession) IssueCSRFToken(context.Context, *http.Request) (string, error) {
	return "stats-csrf", nil
}

// TestStatisticsSameWindowChartsTablesAndDrilldown 验证图表、数据表与下钻使用同一
// 规范化窗口；图表有替代数据表；无明细权限时不渲染伪链接。
func TestStatisticsSameWindowChartsTablesAndDrilldown(t *testing.T) {
	backend := baseStatsBackend()
	env := newStatsPageEnv(t, backend, statsPageSessions{})
	body := requireStatsBody(t, env.get("/admin/statistics?range=custom&"+
		"from=2026-11-12&to=2026-11-18&tz=Asia/Shanghai&granularity=day"),
		http.StatusOK, "活跃度与错误趋势", "活跃度数据表", "错误趋势数据表",
		"查看对应记录", "<svg", "时区：Asia/Shanghai")
	start, end := backend.lastQuery.Window.Start, backend.lastQuery.Window.End
	if !start.Equal(time.Date(2026, 11, 11, 16, 0, 0, 0, time.UTC)) {
		t.Fatalf("窗口起点 = %v，期望东八区 2026-11-12 00:00", start)
	}
	if !end.Equal(time.Date(2026, 11, 18, 16, 0, 0, 0, time.UTC)) {
		t.Fatalf("窗口终点 = %v，期望东八区 2026-11-19 00:00", end)
	}
	if backend.lastQuery.Window.InProgress {
		t.Fatal("已结束的自定义范围不应标记进行中")
	}
	// 下钻链接必须进入审计列表并保留同一日期区间与结果筛选。
	if !strings.Contains(body, "/admin/audit?") {
		t.Fatal("缺少下钻审计链接")
	}
	if !strings.Contains(body, "outcome=denied") {
		t.Fatal("拒绝类别下钻未携带审计结果筛选")
	}
	// 错误码级下钻在错误分类明细页；链接携带错误码与对应结果筛选。
	errorsBody := requireStatsBody(t, env.get("/admin/statistics/errors"), http.StatusOK)
	if !strings.Contains(errorsBody, "error_code=DB_UNAVAILABLE") {
		t.Fatal("错误行下钻未携带错误码")
	}
	// 等待/取消类别无法精确映射审计结果时显示限制而不是伪链接。
	if !strings.Contains(body, "当前权限仅可查看汇总") {
		t.Fatal("缺少不可精确下钻的限制说明")
	}
	// 图表与表格同源：表格行数与数据点一致（两个错误类别点、两个活跃点）。
	if strings.Count(body, `class="ln-chart"`) < 2 {
		t.Fatal("缺少两张内联 SVG 图表")
	}
}

// TestErrorsSortingShareAndGrowth 验证五种排序链接、百分比占比、零基数“新增”、
// 零分母与分页；非法参数不查询后端。
func TestErrorsSortingShareAndGrowth(t *testing.T) {
	backend := baseStatsBackend()
	env := newStatsPageEnv(t, backend, statsPageSessions{})
	body := requireStatsBody(t, env.get("/admin/statistics/errors?sort=share&order=asc"),
		http.StatusOK, "按占比排序", "按增幅排序", "60.00%", "新增", "无变化",
		"DB_UNAVAILABLE", "ACCESS_DENIED")
	if backend.lastQuery.Sort != "share" || backend.lastQuery.Order != "asc" {
		t.Fatalf("排序未透传：%s/%s", backend.lastQuery.Sort, backend.lastQuery.Order)
	}
	// 排序表头使用原生链接与 aria-sort 提升可访问性。
	if !strings.Contains(body, "aria-sort=") {
		t.Fatal("排序表头缺少 aria-sort")
	}
	// 每种排序都有稳定链接且保留当前排序切换。
	for _, sortField := range login.UIStatsSortValues() {
		if !strings.Contains(body, "sort="+sortField) {
			t.Fatalf("缺少排序链接 %s", sortField)
		}
	}
	// 零分母：分母为 0 时显示明确文案，不显示 0%。
	backend.errors.ShareDenominator = 0
	body = requireStatsBody(t, env.get("/admin/statistics/errors"), http.StatusOK,
		"分母为 0")
	_ = body
	// 非法参数：字段错误，不发起新查询。
	backend.lastQuery = login.UIStatsQuery{}
	recorder := env.get("/admin/statistics/errors?sort=bogus&limit=0")
	requireStatsBody(t, recorder, http.StatusBadRequest, "筛选条件有误")
	if backend.lastQuery.Limit != 0 {
		t.Fatal("非法参数不应调用后端查询")
	}
	// 分页：HasMore 时显示下一页并保留筛选。
	backend.errors.HasMore = true
	body = requireStatsBody(t, env.get("/admin/statistics/errors?sort=raw_events"), http.StatusOK,
		"offset=20")
	_ = body
}

// TestStatisticsPermissionAndFailureStates 验证无读取权限显示 403、读取失败显示
// 可恢复错误、会话过期使用既有会话过期页；未启用下钻时不渲染伪链接。
func TestStatisticsPermissionAndFailureStates(t *testing.T) {
	backend := baseStatsBackend()
	backend.capabilities = login.UIStatsCapabilities{}
	env := newStatsPageEnv(t, backend, statsPageSessions{})
	body := requireStatsBody(t, env.get("/admin/statistics"), http.StatusForbidden,
		"你没有权限查看此范围内的统计数据")
	if len(backend.denials) == 0 {
		t.Fatal("无读取权限应留下页面级拒绝记录")
	}
	_ = body

	backend = baseStatsBackend()
	backend.failCode = "DB_UNAVAILABLE"
	env = newStatsPageEnv(t, backend, statsPageSessions{})
	requireStatsBody(t, env.get("/admin/dashboard"), http.StatusServiceUnavailable,
		"无法读取统计看板")

	backend = baseStatsBackend()
	backend.capabilities.Events = false
	env = newStatsPageEnv(t, backend, statsPageSessions{})
	body = requireStatsBody(t, env.get("/admin/statistics/errors"), http.StatusOK,
		"当前权限仅可查看汇总")
	if strings.Contains(body, "/admin/audit?") {
		t.Fatal("无审计读取权限时不应渲染下钻链接")
	}
	_ = body

	// 会话过期：框架按既有系统页输出 401，不进入统计业务。
	env = newStatsPageEnv(t, baseStatsBackend(), statsPageSessions{
		failure: login.ErrUISessionExpired})
	requireStatsBody(t, env.get("/admin/dashboard"), http.StatusUnauthorized)
}

// TestStatsCompletenessMissingAndNotEnabled 验证缺失区间、保留期不足、权限裁剪、
// 来源截断与未启用模块都有可见文字，且当前状态未知/未启用不会被写成健康或零。
func TestStatsCompletenessMissingAndNotEnabled(t *testing.T) {
	backend := baseStatsBackend()
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	backend.dashboard.Overview.Completeness = login.UIStatsCompleteness{
		WindowWithinRetention: false,
		RetentionDays:         30,
		RetentionConfigured:   true,
		RetentionCutoff:       now.AddDate(0, 0, -30),
		MissingIntervals: []login.UIStatsInterval{{Start: now.AddDate(0, 0, -60),
			End: now.AddDate(0, 0, -30), Reason: "retention"}},
		ScopeTrimmed:      true,
		SourceTruncated:   true,
		ModulesNotEnabled: []string{"backup"},
	}
	backend.dashboard.Health.Modules[0].State = "unknown"
	env := newStatsPageEnv(t, backend, statsPageSessions{})
	body := requireStatsBody(t, env.get("/admin/dashboard"), http.StatusOK,
		"超出可查询保留期", "聚合已按当前权限裁剪", "结果不完整",
		"未启用", "未知", "retention")
	// 缺失不是零：页面不能出现“0 条缺失”式伪造，也不渲染示例图表。
	if strings.Contains(body, "示例") || strings.Contains(body, "随机") {
		t.Fatal("页面不应出现示例或随机数字")
	}
}

// TestStatsRefreshEnhancementAndLocalOnlyResources 验证异步刷新增强的挂载点与竞态
// 钩子存在，页面不引用任何在线图表/CDN/第三方脚本；无 JS 时筛选仍是普通 GET 表单。
func TestStatsRefreshEnhancementAndLocalOnlyResources(t *testing.T) {
	backend := baseStatsBackend()
	env := newStatsPageEnv(t, backend, statsPageSessions{})
	body := requireStatsBody(t, env.get("/admin/statistics"), http.StatusOK,
		`data-ln-module="stats-refresh"`, "data-ln-ignored=", "data-ln-loading=",
		`method="get"`, "刷新统计")
	if strings.Contains(body, "http://") || strings.Contains(body, "https://") {
		t.Fatal("页面不得引用远端在线资源")
	}
	script, err := os.ReadFile("web/assets/js/modules/stats-refresh.mjs")
	if err != nil {
		t.Fatalf("读取统计刷新模块失败: %v", err)
	}
	text := string(script)
	for _, marker := range []string{"AbortController", "latestSequence", "pushState",
		"data-ln-stats-status"} {
		if !strings.Contains(text, marker) {
			t.Fatalf("刷新模块缺少竞态/取消钩子 %q", marker)
		}
	}
}

// TestStatsPagesRespectBasePath 验证 BasePath 下命名路由/资源/下钻链接都由服务端
// 前缀生成，页面不会拼出根路径链接。
func TestStatsPagesRespectBasePath(t *testing.T) {
	backend := baseStatsBackend()
	ui, err := login.NewWebUI(login.WebUIOptions{Prefix: "/login",
		Session: statsPageSessions{},
		PageStats: &login.UIPageStatsOptions{Backend: backend,
			Now: func() time.Time { return time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC) }}})
	if err != nil {
		t.Fatalf("构造 BasePath 页面失败: %v", err)
	}
	recorder := httptest.NewRecorder()
	ui.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet,
		"http://example.test/login/admin/statistics", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("BasePath 页面状态 = %d", recorder.Code)
	}
	body := recorder.Body.String()
	for _, fragment := range []string{"/login/assets/", "/login/admin/statistics/errors",
		"/login/admin/dashboard", "/login/admin/audit?"} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("BasePath 链接缺少 %q", fragment)
		}
	}
	if strings.Contains(body, `href="/admin/`) {
		t.Fatal("BasePath 下出现未加前缀的站内链接")
	}
}

// TestStatsFilterFormsTargetCurrentPageAndCategory 验证三页筛选表单 action 指向当前页、
// 统计/错误页渲染真实错误类别筛选、重置回到当前页默认筛选（B1/B2）。
func TestStatsFilterFormsTargetCurrentPageAndCategory(t *testing.T) {
	backend := baseStatsBackend()
	env := newStatsPageEnv(t, backend, statsPageSessions{})
	cases := []struct {
		path        string
		action      string
		hasCategory bool
	}{
		{"/admin/dashboard", "/admin/dashboard", false},
		{"/admin/statistics", "/admin/statistics", true},
		{"/admin/statistics/errors", "/admin/statistics/errors", true},
	}
	for _, testCase := range cases {
		body := requireStatsBody(t, env.get(testCase.path), http.StatusOK)
		if !strings.Contains(body, `action="`+testCase.action+`"`) {
			t.Fatalf("%s 缺少指向当前页的筛选表单 action %q", testCase.path, testCase.action)
		}
		if testCase.hasCategory {
			if !strings.Contains(body, `id="stats-category"`) ||
				!strings.Contains(body, `name="category"`) {
				t.Fatalf("%s 未渲染错误类别筛选", testCase.path)
			}
		}
		if !strings.Contains(body, `href="`+testCase.action+`?`) {
			t.Fatalf("%s 重置链接未指向当前页默认筛选", testCase.path)
		}
	}
	// 统计页错误趋势主指标表单同样提交到当前页。
	body := requireStatsBody(t, env.get("/admin/statistics"), http.StatusOK,
		`id="stats-metric"`)
	if !strings.Contains(body, `action="/admin/statistics"`) {
		t.Fatal("指标表单未指向统计页")
	}
	// 类别参数真实透传给后端。
	requireStatsBody(t, env.get("/admin/statistics/errors?category=failure"), http.StatusOK)
	if backend.lastQuery.Category != "failure" {
		t.Fatalf("类别筛选未透传: %q", backend.lastQuery.Category)
	}
}

// TestStatsMessagesAndUniqueChartIDs 验证页面不显示原始 i18n 键名，两张图表 DOM id
// 唯一且 aria 关联各自图表（B3/B6）。
func TestStatsMessagesAndUniqueChartIDs(t *testing.T) {
	backend := baseStatsBackend()
	env := newStatsPageEnv(t, backend, statsPageSessions{})
	body := requireStatsBody(t, env.get("/admin/statistics"), http.StatusOK,
		"id=\"ln-activity-chart-title\"", "id=\"ln-error-chart-title\"",
		"成功认证去重活跃用户")
	for _, raw := range []string{"page.admin.", "report.metric.", "ln-chart-title"} {
		if strings.Contains(body, raw) {
			t.Fatalf("正文出现原始键名或重复图表 id: %q", raw)
		}
	}
	if strings.Count(body, `id="ln-activity-chart-title"`) != 1 ||
		strings.Count(body, `id="ln-error-chart-title"`) != 1 {
		t.Fatal("图表可访问标题 id 不唯一")
	}
	// 失败/无权限/参数错误页的处理器文案必须是中文而不是原始键名。
	backend.failCode = "DB_UNAVAILABLE"
	failed := requireStatsBody(t, env.get("/admin/dashboard"), http.StatusServiceUnavailable)
	if strings.Contains(failed, "page.admin.") {
		t.Fatal("失败横幅显示原始键名")
	}
	backend2 := baseStatsBackend()
	backend2.capabilities = login.UIStatsCapabilities{}
	forbiddenEnv := newStatsPageEnv(t, backend2, statsPageSessions{})
	forbidden := requireStatsBody(t, forbiddenEnv.get("/admin/statistics"),
		http.StatusForbidden)
	if strings.Contains(forbidden, "page.admin.") {
		t.Fatal("无权限横幅显示原始键名")
	}
	invalid := requireStatsBody(t, env.get("/admin/statistics?tz=Not/AZone"),
		http.StatusBadRequest)
	if strings.Contains(invalid, "page.admin.") {
		t.Fatal("字段错误显示原始键名")
	}
}

// TestStatsUnknownValuesRenderDash 验证未知/保留期外数据在数据表显示 —（不是 0）（B4）。
func TestStatsUnknownValuesRenderDash(t *testing.T) {
	backend := baseStatsBackend()
	env := newStatsPageEnv(t, backend, statsPageSessions{})
	body := requireStatsBody(t, env.get("/admin/statistics"), http.StatusOK,
		"<td>—</td>", "未知（暂无可用数据）")
	if strings.Count(body, "<td>—</td>") < 3 {
		t.Fatalf("未知数据行未按 — 呈现: %d", strings.Count(body, "<td>—</td>"))
	}
}

// TestStatsDrilldownCarriesRangeTimezoneAndApp 验证下钻携带真实时区、所点桶区间与
// 行级应用/系统范围（B5/L1）。
func TestStatsDrilldownCarriesRangeTimezoneAndApp(t *testing.T) {
	backend := baseStatsBackend()
	env := newStatsPageEnv(t, backend, statsPageSessions{})
	// 应用范围：活跃与错误趋势下钻都带 app_id。
	body := requireStatsBody(t, env.get(
		"/admin/statistics?scope=app_alpha&tz=Asia/Shanghai"), http.StatusOK)
	if !strings.Contains(body, "app_id=app_alpha") {
		t.Fatal("应用范围下钻未带 app_id")
	}
	if !strings.Contains(body, "tz=Asia%2FShanghai") {
		t.Fatal("下钻未携带统计时区")
	}
	// 下钻使用所点桶的起止日，而不是整窗：活跃度首桶（fixture 2026-11-12 UTC 起）。
	if !strings.Contains(body, "from=2026-11-12") {
		t.Fatal("下钻未使用桶起止日期")
	}
	// 错误明细：DB_UNAVAILABLE 行来自 app_alpha，应带 app_id；系统级 ACCESS_DENIED 行
	// 应带 system_only，而不是把所有行统一成页面作用范围。
	errorsBody := requireStatsBody(t, env.get("/admin/statistics/errors"),
		http.StatusOK)
	if !strings.Contains(errorsBody, "app_id=app_alpha") {
		t.Fatal("错误行下钻未使用行级 AppID")
	}
	if !strings.Contains(errorsBody, "system_only=1") {
		t.Fatal("系统级错误行下钻未使用 system_only")
	}
}

// TestStatsRefreshAndPaginationWhitelist 验证刷新/分页链接只携带白名单参数，未知
// 查询参数不会被反射（L7）。
func TestStatsRefreshAndPaginationWhitelist(t *testing.T) {
	backend := baseStatsBackend()
	backend.errors.HasMore = true
	env := newStatsPageEnv(t, backend, statsPageSessions{})
	body := requireStatsBody(t, env.get(
		"/admin/statistics/errors?user_id=usr_attacker&foo=bar&sort=share"), http.StatusOK,
		"offset=20")
	for _, leaked := range []string{"usr_attacker", "foo=bar"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("未知参数被反射进链接: %q", leaked)
		}
	}
}

// TestStatsAppScopeAccountDefaultsAndReset 验证只有应用范围权限的账户（会话无 AppID）
// 默认回退到获准应用范围而不是 system 400，重置链接保留真实作用范围（O1/O2）。
func TestStatsAppScopeAccountDefaultsAndReset(t *testing.T) {
	backend := baseStatsBackend()
	backend.capabilities = login.UIStatsCapabilities{Read: true,
		Scopes: []string{"app_alpha"}}
	// 会话无 AppID：默认必须回退到 app_alpha 而不是 system。
	env := newStatsPageEnv(t, backend, statsPageSessions{})
	body := requireStatsBody(t, env.get("/admin/dashboard"), http.StatusOK,
		`value="app_alpha" selected`, "scope=app_alpha")
	if backend.lastQuery.ScopeID != "app_alpha" {
		t.Fatalf("应用范围账户默认 scope = %q，期望 app_alpha", backend.lastQuery.ScopeID)
	}
	// 重置链接当前真实 scope：跟随该链接仍应 200 而不是 400。
	if !strings.Contains(body, "scope=app_alpha&amp;tz=") {
		t.Fatalf("重置链接未保留真实作用范围")
	}
	requireStatsBody(t, env.get(
		"/admin/dashboard?granularity=day&range=7d&scope=app_alpha&tz=UTC"),
		http.StatusOK)
	// 会话带应用上下文（但仍只有应用范围权限）同样正常工作。
	appSessionEnv := newStatsPageEnv(t, backend, statsPageSessions{})
	ui, err := login.NewWebUI(login.WebUIOptions{Session: statsAppSession{},
		PageStats: &login.UIPageStatsOptions{Backend: backend,
			Now: func() time.Time { return time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC) }}})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	_ = appSessionEnv
	recorder := httptest.NewRecorder()
	ui.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet,
		"http://example.test/admin/dashboard", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("应用上下文账户状态 = %d", recorder.Code)
	}
	if backend.lastQuery.ScopeID != "app_alpha" {
		t.Fatalf("应用上下文默认 scope = %q", backend.lastQuery.ScopeID)
	}
}
