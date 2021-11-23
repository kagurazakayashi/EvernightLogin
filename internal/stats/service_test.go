package stats_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
	statssqlite "github.com/kagurazakayashi/EvernightLogin/internal/stats/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// cst 是测试使用的固定东八区（与 Asia/Shanghai 永久偏移一致）。
var cst = time.FixedZone("CST", 8*60*60)

// baseNow 是测试固定时钟：事件与窗口都以它为基准相对生成，避免依赖真实时间。
var baseNow = time.Date(2026, 11, 19, 12, 0, 0, 0, cst)

// testUserID 生成格式合法的稳定用户 ID。
func testUserID(index int) string {
	return fmt.Sprintf("usr_%032x", index)
}

// fakeAuthorizer 是作用范围授权测试替身：按 scopeID 返回预设授权结果。
type fakeAuthorizer struct {
	grants map[string]stats.ScopeGrant
	err    error
}

// AuthorizeScope 实现 stats.Authorizer。
func (f *fakeAuthorizer) AuthorizeScope(_ context.Context, _ account.Caller,
	_, scopeID string) (stats.ScopeGrant, error) {
	if f.err != nil {
		return stats.ScopeGrant{}, f.err
	}
	grant, ok := f.grants[scopeID]
	if !ok {
		return stats.ScopeGrant{Allowed: false}, nil
	}
	return grant, nil
}

// fakeRoot 是 root 判定测试替身。
type fakeRoot struct {
	roots map[string]bool
	err   error
}

// IsRoot 实现 stats.RootChecker。
func (f *fakeRoot) IsRoot(_ context.Context, caller account.Caller) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	return f.roots[caller.Actor().ID], nil
}

// testEnv 是使用真实 SQLite + 真实审计写入 + 测试授权替身的隔离环境。
type testEnv struct {
	t             *testing.T
	ctx           context.Context
	raw           *storagesqlite.Store
	auditStore    *auditsqlite.Store
	store         *statssqlite.Store
	service       *stats.Service
	authorizer    *fakeAuthorizer
	root          *fakeRoot
	recorder      *audit.Recorder
	businessAuthz *fakeBusinessAuthorizer
	clock         time.Time
	nowFn         func() time.Time
}

// fakeBusinessAuthorizer 是业务活动来源校验测试替身：按 app|user 允许。
type fakeBusinessAuthorizer struct {
	allowed map[string]bool
	err     error
}

// AuthorizeBusinessActivity 实现 stats.BusinessActivityAuthorizer。
func (f *fakeBusinessAuthorizer) AuthorizeBusinessActivity(_ context.Context,
	_ audit.Actor, appID, userID string) error {
	if f.err != nil {
		return f.err
	}
	if f.allowed[appID+"|"+userID] {
		return nil
	}
	return errors.New("业务活动来源未获准")
}

// newTestEnv 构造临时数据库与统计服务。
func newTestEnv(t *testing.T, sources ...stats.HealthSource) *testEnv {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(testutil.TempDir(t), "stats.db")
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(path))
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
		t.Fatalf("构造审计仓储失败: %v", err)
	}
	store, err := statssqlite.New(raw)
	if err != nil {
		t.Fatalf("构造统计仓储失败: %v", err)
	}
	env := &testEnv{t: t, ctx: ctx, raw: raw, auditStore: auditStore, store: store,
		clock:         baseNow,
		authorizer:    &fakeAuthorizer{grants: map[string]stats.ScopeGrant{}},
		root:          &fakeRoot{roots: map[string]bool{}},
		businessAuthz: &fakeBusinessAuthorizer{allowed: map[string]bool{}}}
	env.nowFn = env.now
	recorder, err := audit.New(auditStore, audit.Options{Now: env.nowFn})
	if err != nil {
		t.Fatalf("构造审计 Recorder 失败: %v", err)
	}
	env.recorder = recorder
	service, err := stats.New(stats.Options{
		Store: store, Authorizer: env.authorizer, Root: env.root, Audit: recorder,
		HealthSources: sources, Now: env.nowFn, RetentionDays: 180,
		SampleInterval:        time.Minute,
		BusinessActivityApps:  []string{"app_alpha", "app_beta"},
		BusinessActivityAuthz: env.businessAuthz,
	})
	if err != nil {
		t.Fatalf("构造统计服务失败: %v", err)
	}
	env.service = service
	return env
}

// grant 设置作用范围授权。
func (e *testEnv) grant(scopeID string, grant stats.ScopeGrant) {
	e.authorizer.grants[scopeID] = grant
}

// now 返回当前注入时钟。
func (e *testEnv) now() time.Time { return e.clock }

// setNow 修改注入时钟（所有依赖持有同一函数值，修改立即生效）。
func (e *testEnv) setNow(now time.Time) { e.clock = now }

// userCaller 构造合法普通用户调用者。
func userCaller(t *testing.T, id string) account.Caller {
	t.Helper()
	caller, err := account.UserCaller(id)
	if err != nil {
		t.Fatalf("构造用户调用者失败: %v", err)
	}
	return caller
}

// eventSpec 描述一条待写入的审计事件。
type eventSpec struct {
	At        time.Time
	ActorType audit.ActorKind
	ActorID   string
	AppID     string
	Action    string
	Outcome   audit.Outcome
	ErrorCode string
	RequestID string
	TaskID    string
	Changes   []audit.FieldChange
}

// appendEvent 用真实 audit.Store 写入一条指定发生时刻的审计事件（绕过 Recorder
// 的当前时钟，便于构造确定性历史数据）。
func (e *testEnv) appendEvent(spec eventSpec) {
	e.t.Helper()
	event := audit.Event{
		Actor: audit.Actor{Type: spec.ActorType, ID: spec.ActorID},
		AppID: spec.AppID, Action: spec.Action,
		Target:    audit.Target{Type: "test", ID: spec.ActorID},
		Outcome:   spec.Outcome,
		ErrorCode: spec.ErrorCode, RequestID: spec.RequestID, TaskID: spec.TaskID,
		Changes: spec.Changes,
	}
	prepared, err := audit.PrepareEvent(event, spec.At)
	if err != nil {
		e.t.Fatalf("准备审计事件失败: %v", err)
	}
	if err := e.auditStore.Append(e.ctx, prepared); err != nil {
		e.t.Fatalf("写入审计事件失败: %v", err)
	}
}

// appendSessionIssue 写入一条会话签发审计（完整成功认证）。
func (e *testEnv) appendSessionIssue(at time.Time, userID, appID string, restricted bool) {
	e.t.Helper()
	kind := "normal"
	if restricted {
		kind = "restricted"
	}
	e.appendEvent(eventSpec{At: at, ActorType: audit.ActorUser, ActorID: userID,
		AppID: appID, Action: "session.issue", Outcome: audit.OutcomeSuccess,
		Changes: []audit.FieldChange{{Field: "session_kind", After: kind}}})
}

// appendLoginGrantIssued 写入一条可信登录批准后的会话签发审计。
func (e *testEnv) appendLoginGrantIssued(at time.Time, userID, appID string) {
	e.t.Helper()
	e.appendEvent(eventSpec{At: at, ActorType: audit.ActorUser, ActorID: userID,
		AppID: appID, Action: "session.login_grant_issued", Outcome: audit.OutcomeSuccess,
		Changes: []audit.FieldChange{{Field: "login_grant", After: "grant_1"}}})
}

// setRetention 写入审计保留策略（直接写库，模拟 root 已设置策略）。
func (e *testEnv) setRetention(days int) {
	e.t.Helper()
	_, err := e.raw.ExecContext(e.ctx,
		`INSERT INTO audit_retention_policy(
id,retention_days,version,updated_by_type,updated_by_id,updated_at_ms
) VALUES(1,?,1,'system','stats_test',?)
ON CONFLICT(id) DO UPDATE SET retention_days=excluded.retention_days,
version=audit_retention_policy.version+1, updated_at_ms=excluded.updated_at_ms`,
		days, e.nowFn().UTC().UnixMilli())
	if err != nil {
		e.t.Fatalf("写入保留策略失败: %v", err)
	}
}

// allDataGrant 是系统范围全数据授权。
var allDataGrant = stats.ScopeGrant{Allowed: true, AllData: true}

// nowWindow 返回以 baseNow 为结束、跨度 days 天的窗口请求。
func nowWindow(days int, granularity stats.Granularity) stats.WindowRequest {
	return stats.WindowRequest{
		TimeZone:    "Asia/Shanghai",
		Start:       baseNow.AddDate(0, 0, -days),
		End:         baseNow,
		Granularity: granularity,
	}
}

// findPoint 返回指定稳定桶标识的数据点。
func findPoint(t *testing.T, points []stats.ActivityPoint, key string) stats.ActivityPoint {
	t.Helper()
	for _, point := range points {
		if point.Bucket.Key == key {
			return point
		}
	}
	t.Fatalf("缺少时间桶 %s", key)
	return stats.ActivityPoint{}
}

// TestActivityCrossDayTimezoneAndDedup 用确定性数据验证跨天/时区分桶、跨应用同一
// 用户去重、受限会话排除与左闭右开边界。
func TestActivityCrossDayTimezoneAndDedup(t *testing.T) {
	env := newTestEnv(t)
	env.grant(stats.ScopeSystem, allDataGrant)
	userA, userB := testUserID(1), testUserID(2)
	userC, userD, userE, userF := testUserID(3), testUserID(4), testUserID(5), testUserID(6)
	env.appendSessionIssue(time.Date(2026, 11, 17, 23, 30, 0, 0, cst), userA, "app_alpha", false)
	env.appendSessionIssue(time.Date(2026, 11, 17, 23, 45, 0, 0, cst), userA, "app_beta", false)
	env.appendSessionIssue(time.Date(2026, 11, 18, 0, 10, 0, 0, cst), userA, "app_alpha", false)
	env.appendLoginGrantIssued(time.Date(2026, 11, 18, 10, 0, 0, 0, cst), userB, "app_alpha")
	// 受限会话（等待第二因素）不是完整成功认证，不计入活跃。
	env.appendSessionIssue(time.Date(2026, 11, 18, 11, 0, 0, 0, cst), userC, "app_alpha", true)
	// 起点事件属于窗口（左闭）。
	env.appendSessionIssue(time.Date(2026, 11, 17, 0, 0, 0, 0, cst), userD, "app_alpha", false)
	// 终点事件不属于窗口（右开）。
	env.appendSessionIssue(time.Date(2026, 11, 19, 0, 0, 0, 0, cst), userE, "app_alpha", false)
	env.appendLoginGrantIssued(time.Date(2026, 11, 18, 23, 59, 0, 0, cst), userF, "app_beta")
	caller := userCaller(t, testUserID(100))
	request := stats.ActivityRequest{
		Caller: caller, ScopeID: stats.ScopeSystem,
		Window: stats.WindowRequest{
			TimeZone:    "Asia/Shanghai",
			Start:       time.Date(2026, 11, 17, 0, 0, 0, 0, cst),
			End:         time.Date(2026, 11, 19, 0, 0, 0, 0, cst),
			Granularity: stats.GranularityDay,
		},
	}
	result, err := env.service.Activity(env.ctx, request)
	if err != nil {
		t.Fatalf("活跃度查询失败: %v", err)
	}
	if result.TotalActiveUsers != 4 {
		t.Errorf("窗口去重活跃用户 = %d，期望 4（A/B/D/F）", result.TotalActiveUsers)
	}
	if point := findPoint(t, result.Points, "2026-11-17"); point.ActiveUsers != 2 {
		t.Errorf("11-17 活跃 = %d，期望 2（A、D）", point.ActiveUsers)
	}
	if point := findPoint(t, result.Points, "2026-11-18"); point.ActiveUsers != 3 {
		t.Errorf("11-18 活跃 = %d，期望 3（A、B、F）", point.ActiveUsers)
	}
	if result.DedupeScope != "system" {
		t.Errorf("去重范围 = %q，期望 system", result.DedupeScope)
	}
	// 时区切换会重新分桶：同一批绝对时刻在 UTC 下日边界不同。
	utcRequest := request
	utcRequest.Window.TimeZone = "UTC"
	utcResult, err := env.service.Activity(env.ctx, utcRequest)
	if err != nil {
		t.Fatalf("UTC 活跃度查询失败: %v", err)
	}
	if utcResult.TotalActiveUsers != 4 {
		t.Errorf("UTC 窗口去重活跃用户 = %d，期望 4", utcResult.TotalActiveUsers)
	}
	// UTC 窗口从 11-16 16:00Z 到 11-18 16:00Z：16 日 D、17 日 A、18 日 B/F。
	if utcResult.Points[0].ActiveUsers != 1 || utcResult.Points[1].ActiveUsers != 1 ||
		utcResult.Points[2].ActiveUsers != 2 {
		t.Errorf("UTC 分桶 = %d/%d/%d，期望 1/1/2",
			utcResult.Points[0].ActiveUsers, utcResult.Points[1].ActiveUsers,
			utcResult.Points[2].ActiveUsers)
	}
	// 单应用视图只统计该应用：app_alpha 中去重 A、B、D = 3。
	appRequest := request
	appRequest.AppID = "app_alpha"
	appResult, err := env.service.Activity(env.ctx, appRequest)
	if err != nil {
		t.Fatalf("单应用活跃度查询失败: %v", err)
	}
	if appResult.TotalActiveUsers != 3 || appResult.DedupeScope != "app" {
		t.Errorf("单应用活跃 = %d scope=%q，期望 3/app",
			appResult.TotalActiveUsers, appResult.DedupeScope)
	}
	// 可重复聚合：相同窗口/数据/时钟重复查询结果完全一致。
	repeated, err := env.service.Activity(env.ctx, request)
	if err != nil {
		t.Fatalf("重复活跃度查询失败: %v", err)
	}
	if !reflect.DeepEqual(result, repeated) {
		t.Error("相同请求重复聚合结果不一致")
	}
}

// TestActivityWeeklyAndMonthly 验证周/月活跃按自然窗口去重。
func TestActivityWeeklyAndMonthly(t *testing.T) {
	env := newTestEnv(t)
	env.grant(stats.ScopeSystem, allDataGrant)
	userA, userB := testUserID(11), testUserID(12)
	env.appendSessionIssue(time.Date(2026, 11, 16, 9, 0, 0, 0, cst), userA, "app_alpha", false)
	env.appendSessionIssue(time.Date(2026, 11, 22, 23, 0, 0, 0, cst), userA, "app_alpha", false)
	env.appendSessionIssue(time.Date(2026, 11, 23, 1, 0, 0, 0, cst), userB, "app_alpha", false)
	caller := userCaller(t, testUserID(100))
	// 时钟推进到窗口结束后，避免窗口被裁剪到统计截止点。
	env.setNow(time.Date(2026, 12, 1, 0, 0, 0, 0, cst))
	window := stats.WindowRequest{
		TimeZone:    "Asia/Shanghai",
		Start:       time.Date(2026, 11, 2, 0, 0, 0, 0, cst),
		End:         time.Date(2026, 11, 30, 0, 0, 0, 0, cst),
		Granularity: stats.GranularityWeek,
	}
	result, err := env.service.Activity(env.ctx, stats.ActivityRequest{
		Caller: caller, ScopeID: stats.ScopeSystem, Window: window})
	if err != nil {
		t.Fatalf("周活跃查询失败: %v", err)
	}
	// 2026-11-16 周与 2026-11-23 周各 1 人；A 跨两周分别计数，窗口总去重为 2。
	if len(result.Points) != 4 {
		t.Fatalf("周桶数量 = %d，期望 4", len(result.Points))
	}
	if result.Points[2].ActiveUsers != 1 || result.Points[3].ActiveUsers != 1 {
		t.Errorf("周活跃 = %d/%d，期望 1/1", result.Points[2].ActiveUsers,
			result.Points[3].ActiveUsers)
	}
	if result.TotalActiveUsers != 2 {
		t.Errorf("窗口去重用户 = %d，期望 2", result.TotalActiveUsers)
	}
}

// TestErrorsAggregationDedupAndCategories 验证原始次数、去重失败请求/任务、类别
// 分开、重复日志不重复计数、增幅零基数“新增”与百分比。
func TestErrorsAggregationDedupAndCategories(t *testing.T) {
	env := newTestEnv(t)
	env.grant(stats.ScopeSystem, allDataGrant)
	userA := testUserID(21)
	target := time.Date(2026, 11, 18, 10, 0, 0, 0, cst)
	// 同一失败请求的多次日志：request_id 相同，只计一个失败请求。
	for index := 0; index < 3; index++ {
		env.appendEvent(eventSpec{At: target.Add(time.Duration(index) * time.Minute),
			ActorType: audit.ActorUser, ActorID: userA, AppID: "app_alpha",
			Action: "profile.update", Outcome: audit.OutcomeFailure,
			ErrorCode: "REQ_INVALID", RequestID: "req-1"})
	}
	// 同一任务重试两次：task_id 相同，只计一个失败任务。
	for index := 0; index < 2; index++ {
		env.appendEvent(eventSpec{At: target.Add(time.Duration(index) * time.Minute),
			ActorType: audit.ActorSystem, ActorID: "worker", AppID: "app_alpha",
			Action: "mail.send", Outcome: audit.OutcomeFailure,
			ErrorCode: "INTERNAL_ERROR", RequestID: "req-2", TaskID: "task-1"})
	}
	env.appendEvent(eventSpec{At: target, ActorType: audit.ActorUser, ActorID: userA,
		AppID: "app_beta", Action: "role.assign", Outcome: audit.OutcomeDenied,
		ErrorCode: "ACCESS_DENIED", RequestID: "req-3"})
	env.appendEvent(eventSpec{At: target, ActorType: audit.ActorSystem, ActorID: "worker",
		AppID: "app_alpha", Action: "mail.send", Outcome: audit.OutcomeFailure,
		ErrorCode: "TASK_CANCELLED"})
	env.appendEvent(eventSpec{At: target, ActorType: audit.ActorSystem, ActorID: "report",
		AppID: "app_alpha", Action: "report.generate", Outcome: audit.OutcomeFailure,
		ErrorCode: "REPORT_DATA_INCOMPLETE"})
	env.appendEvent(eventSpec{At: target, ActorType: audit.ActorSystem, ActorID: "backup",
		AppID: "app_alpha", Action: "backup.run", Outcome: audit.OutcomeFailure,
		ErrorCode: "BACKUP_FAILED", RequestID: "req-4", TaskID: "task-2"})
	// 等待授权不属于故障。
	env.appendEvent(eventSpec{At: target, ActorType: audit.ActorUser, ActorID: userA,
		AppID: "app_alpha", Action: "app_qr_login.request_created",
		Outcome: audit.OutcomeSuccess})
	// 普通成功动作不计入错误统计。
	env.appendSessionIssue(target, userA, "app_alpha", false)
	// 前一等长窗口存在一次 REQ_INVALID，用于计算百分比增幅。
	env.appendEvent(eventSpec{At: target.AddDate(0, 0, -1), ActorType: audit.ActorUser,
		ActorID: userA, AppID: "app_alpha", Action: "profile.update",
		Outcome: audit.OutcomeFailure, ErrorCode: "REQ_INVALID", RequestID: "req-0"})
	caller := userCaller(t, testUserID(101))
	window := stats.WindowRequest{
		TimeZone:    "Asia/Shanghai",
		Start:       time.Date(2026, 11, 18, 0, 0, 0, 0, cst),
		End:         time.Date(2026, 11, 19, 0, 0, 0, 0, cst),
		Granularity: stats.GranularityDay,
	}
	result, err := env.service.Errors(env.ctx, stats.ErrorRequest{
		Caller: caller, ScopeID: stats.ScopeSystem, Window: window})
	if err != nil {
		t.Fatalf("错误聚合失败: %v", err)
	}
	// 原始事件次数：3(REQ_INVALID)+2(INTERNAL_ERROR)+1(denied)+1(cancelled)
	// +1(warning)+1(BACKUP_FAILED)+1(pending)=10。普通成功不计入。
	if result.TotalRawEvents != 10 {
		t.Errorf("原始事件次数 = %d，期望 10（行：%+v）", result.TotalRawEvents, result.Rows)
	}
	// 全局去重失败请求只统计 failure 且排除取消/警告：req-1、req-2、req-4 = 3；
	// 正常拒绝（req-3）保留原始次数但不冒充失败。
	if result.FailedRequests != 3 {
		t.Errorf("去重失败请求数 = %d，期望 3", result.FailedRequests)
	}
	if result.FailedTasks != 2 {
		t.Errorf("去重失败任务数 = %d，期望 2（task-1、task-2）", result.FailedTasks)
	}
	rowsByKey := make(map[string]stats.ErrorRow)
	for _, row := range result.Rows {
		rowsByKey[row.ErrorCode+"|"+row.AppID] = row
	}
	if row := rowsByKey["REQ_INVALID|app_alpha"]; row.RawEvents != 3 || row.FailedRequests != 1 {
		t.Errorf("REQ_INVALID 行 = %d 次/%d 去重请求，期望 3/1", row.RawEvents, row.FailedRequests)
	}
	if row := rowsByKey["INTERNAL_ERROR|app_alpha"]; row.RawEvents != 2 || row.FailedTasks != 1 {
		t.Errorf("INTERNAL_ERROR 行 = %d 次/%d 去重任务，期望 2/1", row.RawEvents, row.FailedTasks)
	}
	if row, exists := rowsByKey["ACCESS_DENIED|app_beta"]; !exists || row.Category != stats.CategoryDenied {
		t.Errorf("ACCESS_DENIED 行缺失或类别错误: %+v", row)
	}
	if row, exists := rowsByKey["TASK_CANCELLED|app_alpha"]; !exists || row.Category != stats.CategoryCancelled {
		t.Errorf("TASK_CANCELLED 行缺失或未归入取消: %+v", row)
	}
	if row, exists := rowsByKey["REPORT_DATA_INCOMPLETE|app_alpha"]; !exists || row.Category != stats.CategoryWarning {
		t.Errorf("REPORT_DATA_INCOMPLETE 行缺失或未归入警告: %+v", row)
	}
	if row, exists := rowsByKey["|app_alpha"]; !exists || row.Category != stats.CategoryPending ||
		row.FailedRequests != 0 || row.FailedTasks != 0 {
		t.Errorf("等待授权行缺失/类别错误/不应计入失败请求: %+v", row)
	}
	// 取消与警告不是失败：原始次数保留，去重失败请求/任务数为 0。
	if row := rowsByKey["TASK_CANCELLED|app_alpha"]; row.FailedRequests != 0 || row.FailedTasks != 0 {
		t.Errorf("取消行不应计入失败请求/任务: %+v", row)
	}
	if row := rowsByKey["REPORT_DATA_INCOMPLETE|app_alpha"]; row.FailedRequests != 0 {
		t.Errorf("警告行不应计入失败请求: %+v", row)
	}
	if row := rowsByKey["ACCESS_DENIED|app_beta"]; row.FailedRequests != 0 {
		t.Errorf("正常拒绝行不应冒充失败请求: %+v", row)
	}
	// 类别汇总分开，不合并成“错误”。
	categoryByID := make(map[stats.Category]stats.CategorySummary)
	for _, summary := range result.Categories {
		categoryByID[summary.Category] = summary
	}
	if categoryByID[stats.CategoryDenied].RawEvents != 1 ||
		categoryByID[stats.CategoryCancelled].RawEvents != 1 ||
		categoryByID[stats.CategoryWarning].RawEvents != 1 ||
		categoryByID[stats.CategoryFailure].RawEvents != 6 ||
		categoryByID[stats.CategoryPending].RawEvents != 1 {
		t.Errorf("类别汇总错误: %+v", result.Categories)
	}
	// 增幅：REQ_INVALID 前值 1、本期 3 -> +200%；INTERNAL_ERROR 前值 0 -> 新增。
	if row := rowsByKey["REQ_INVALID|app_alpha"]; row.Growth.Kind != stats.GrowthPercent ||
		row.Growth.Percent != 200 {
		t.Errorf("REQ_INVALID 增幅 = %+v，期望 +200%%", row.Growth)
	}
	if row := rowsByKey["INTERNAL_ERROR|app_alpha"]; row.Growth.Kind != stats.GrowthNew {
		t.Errorf("INTERNAL_ERROR 增幅 = %+v，期望新增", row.Growth)
	}
	// 占比使用同一筛选与范围的全局分母；总分母为 0 时保持 0 并可由调用方判定。
	shareSum := 0.0
	for _, row := range result.Rows {
		shareSum += row.Share
	}
	if shareSum < 0.999 || shareSum > 1.001 {
		t.Errorf("占比之和 = %v，期望约 1", shareSum)
	}
	// 顺序不稳定字段不影响同一数据集重复聚合结果。
	repeated, err := env.service.Errors(env.ctx, stats.ErrorRequest{
		Caller: caller, ScopeID: stats.ScopeSystem, Window: window})
	if err != nil {
		t.Fatalf("重复错误聚合失败: %v", err)
	}
	if !reflect.DeepEqual(result, repeated) {
		t.Error("相同请求重复错误聚合结果不一致")
	}
}

// TestErrorsCategoryFilterAndSort 验证类别筛选、五种排序与稳定分页。
func TestErrorsCategoryFilterAndSort(t *testing.T) {
	env := newTestEnv(t)
	env.grant(stats.ScopeSystem, allDataGrant)
	userA := testUserID(22)
	target := baseNow.AddDate(0, 0, -1)
	env.appendEvent(eventSpec{At: target, ActorType: audit.ActorUser, ActorID: userA,
		AppID: "app_alpha", Action: "a", Outcome: audit.OutcomeFailure,
		ErrorCode: "INTERNAL_ERROR", RequestID: "req-a"})
	env.appendEvent(eventSpec{At: target, ActorType: audit.ActorUser, ActorID: userA,
		AppID: "app_alpha", Action: "b", Outcome: audit.OutcomeDenied,
		ErrorCode: "ACCESS_DENIED", RequestID: "req-b"})
	env.appendEvent(eventSpec{At: target, ActorType: audit.ActorUser, ActorID: userA,
		AppID: "app_alpha", Action: "c", Outcome: audit.OutcomeFailure,
		ErrorCode: "CONFLICT", RequestID: "req-c"})
	caller := userCaller(t, testUserID(102))
	window := stats.WindowRequest{TimeZone: "Asia/Shanghai",
		Start: target.Truncate(24 * time.Hour), End: target.Truncate(24*time.Hour).AddDate(0, 0, 1),
		Granularity: stats.GranularityDay}
	failureOnly, err := env.service.Errors(env.ctx, stats.ErrorRequest{
		Caller: caller, ScopeID: stats.ScopeSystem, Window: window,
		Categories: []stats.Category{stats.CategoryFailure}})
	if err != nil {
		t.Fatalf("类别筛选失败: %v", err)
	}
	if failureOnly.TotalRawEvents != 2 {
		t.Errorf("故障类原始次数 = %d，期望 2", failureOnly.TotalRawEvents)
	}
	for _, row := range failureOnly.Rows {
		if row.Category != stats.CategoryFailure {
			t.Errorf("类别筛选后出现非故障行: %+v", row)
		}
	}
	// 首次发生排序升序：三种类别各一行，按 first_seen 稳定排序。
	byFirst, err := env.service.Errors(env.ctx, stats.ErrorRequest{
		Caller: caller, ScopeID: stats.ScopeSystem, Window: window,
		Sort: stats.ErrorSortFirst, Order: stats.SortAsc, Limit: 2})
	if err != nil {
		t.Fatalf("首次发生排序失败: %v", err)
	}
	if len(byFirst.Rows) != 2 || !byFirst.HasMore {
		t.Errorf("分页结果 = %d 行 HasMore=%v，期望 2 行且还有更多", len(byFirst.Rows), byFirst.HasMore)
	}
	// 非法排序字段必须拒绝（白名单）。
	if _, err := env.service.Errors(env.ctx, stats.ErrorRequest{
		Caller: caller, ScopeID: stats.ScopeSystem, Window: window,
		Sort: stats.ErrorSort("error_code")}); !errors.Is(err, stats.ErrInvalidRequest) {
		t.Errorf("非法排序字段错误 = %v，期望 ErrInvalidRequest", err)
	}
}

// TestScopePermissionFilterAndDenial 验证聚合遵守调用者数据范围、拒绝无权限调用
// 并写入拒绝审计。
func TestScopePermissionFilterAndDenial(t *testing.T) {
	env := newTestEnv(t)
	env.grant(stats.ScopeSystem, stats.ScopeGrant{Allowed: true,
		ResourceIDs: []string{"app_beta"}})
	userA := testUserID(31)
	target := baseNow.AddDate(0, 0, -1)
	env.appendSessionIssue(target, userA, "app_alpha", false)
	env.appendSessionIssue(target, testUserID(32), "app_beta", false)
	env.appendEvent(eventSpec{At: target, ActorType: audit.ActorUser, ActorID: userA,
		AppID: "app_alpha", Action: "x", Outcome: audit.OutcomeFailure,
		ErrorCode: "INTERNAL_ERROR"})
	env.appendEvent(eventSpec{At: target, ActorType: audit.ActorUser, ActorID: userA,
		AppID: "app_beta", Action: "x", Outcome: audit.OutcomeFailure,
		ErrorCode: "INTERNAL_ERROR"})
	caller := userCaller(t, testUserID(103))
	result, err := env.service.Activity(env.ctx, stats.ActivityRequest{
		Caller: caller, ScopeID: stats.ScopeSystem, Window: nowWindow(3, stats.GranularityDay)})
	if err != nil {
		t.Fatalf("受权范围活跃度查询失败: %v", err)
	}
	// 只有 app_beta 的事件可见：1 个用户。
	if result.TotalActiveUsers != 1 {
		t.Errorf("裁剪后活跃用户 = %d，期望 1", result.TotalActiveUsers)
	}
	if !result.Completeness.ScopeTrimmed {
		t.Error("数据范围裁剪未在完整性信息中标注")
	}
	errorResult, err := env.service.Errors(env.ctx, stats.ErrorRequest{
		Caller: caller, ScopeID: stats.ScopeSystem, Window: nowWindow(3, stats.GranularityDay)})
	if err != nil {
		t.Fatalf("受权范围错误聚合失败: %v", err)
	}
	for _, row := range errorResult.Rows {
		if row.AppID == "app_alpha" {
			t.Errorf("越权应用出现在结果中: %+v", row)
		}
	}
	// 无授权作用范围直接拒绝，而不是返回空结果。
	if _, err := env.service.Errors(env.ctx, stats.ErrorRequest{
		Caller: caller, ScopeID: "app_alpha", Window: nowWindow(3, stats.GranularityDay)}); !errors.Is(err, stats.ErrAccessDenied) {
		t.Errorf("无权限错误 = %v，期望 ErrAccessDenied", err)
	}
	// 拒绝对应写失败审计（真实 audit 写入）。
	var deniedCount int
	if err := env.raw.DB().QueryRowContext(env.ctx,
		`SELECT COUNT(*) FROM audit_events WHERE action = 'stats.access.denied'
AND outcome = 'denied'`).Scan(&deniedCount); err != nil {
		t.Fatalf("查询拒绝审计失败: %v", err)
	}
	if deniedCount < 1 {
		t.Error("统计读取拒绝未写审计")
	}
	// root 不经过普通权限引擎：无需 grant 也能查看全量。
	rootID := testUserID(104)
	env.root.roots[rootID] = true
	rootResult, err := env.service.Errors(env.ctx, stats.ErrorRequest{
		Caller: userCaller(t, rootID), ScopeID: stats.ScopeSystem,
		Window: nowWindow(3, stats.GranularityDay)})
	if err != nil {
		t.Fatalf("root 查询失败: %v", err)
	}
	if len(rootResult.Rows) != 2 {
		t.Errorf("root 可见错误行 = %d，期望 2（跨应用）", len(rootResult.Rows))
	}
	// 依赖失败默认拒绝（fail-closed）。
	env.authorizer.err = errors.New("authz unavailable")
	if _, err := env.service.Activity(env.ctx, stats.ActivityRequest{
		Caller: caller, ScopeID: stats.ScopeSystem,
		Window: nowWindow(3, stats.GranularityDay)}); !errors.Is(err, stats.ErrAccessDenied) {
		t.Errorf("授权依赖失败错误 = %v，期望 ErrAccessDenied", err)
	}
}

// TestRetentionMissingIntervals 验证保留期不足时输出缺失区间与未知状态，不把未知
// 当零；比较窗口不完整时增幅不可用。
func TestRetentionMissingIntervals(t *testing.T) {
	env := newTestEnv(t)
	env.grant(stats.ScopeSystem, allDataGrant)
	env.setRetention(2)
	now := baseNow
	userBefore, userAfter := testUserID(41), testUserID(42)
	env.appendSessionIssue(now.AddDate(0, 0, -5), userBefore, "app_alpha", false)
	env.appendSessionIssue(now.AddDate(0, 0, -1), userAfter, "app_alpha", false)
	caller := userCaller(t, testUserID(105))
	window := stats.WindowRequest{TimeZone: "Asia/Shanghai",
		Start: now.AddDate(0, 0, -6), End: now, Granularity: stats.GranularityDay}
	result, err := env.service.Activity(env.ctx, stats.ActivityRequest{
		Caller: caller, ScopeID: stats.ScopeSystem, Window: window})
	if err != nil {
		t.Fatalf("保留期活跃度查询失败: %v", err)
	}
	if result.Completeness.WindowWithinRetention {
		t.Error("窗口整体早于保留边界时应标记不在保留期内")
	}
	if len(result.Completeness.MissingIntervals) != 1 {
		t.Fatalf("缺失区间数量 = %d，期望 1", len(result.Completeness.MissingIntervals))
	}
	missing := result.Completeness.MissingIntervals[0]
	if !missing.Start.Equal(result.Window.Start) || missing.Reason != "retention" {
		t.Errorf("缺失区间 = %+v，期望从窗口起点开始且原因为 retention", missing)
	}
	// 完全早于保留边界的桶必须是 unknown/partial，绝不能是“完整的 0”。
	for _, point := range result.Points {
		if point.Bucket.End.After(result.Completeness.RetentionCutoff) {
			continue
		}
		if point.DataStatus != stats.DataUnknown && point.DataStatus != stats.DataPartial {
			t.Errorf("早于保留边界的桶状态 = %q，期望 unknown/partial", point.DataStatus)
		}
	}
	// 错误聚合的比较窗口早于保留边界：增幅不可用。
	env.appendEvent(eventSpec{At: now.AddDate(0, 0, -1), ActorType: audit.ActorUser,
		ActorID: userAfter, AppID: "app_alpha", Action: "x",
		Outcome: audit.OutcomeFailure, ErrorCode: "INTERNAL_ERROR"})
	errorResult, err := env.service.Errors(env.ctx, stats.ErrorRequest{
		Caller: caller, ScopeID: stats.ScopeSystem, Window: window})
	if err != nil {
		t.Fatalf("保留期错误聚合失败: %v", err)
	}
	if len(errorResult.Rows) != 1 {
		t.Fatalf("错误行数量 = %d，期望 1", len(errorResult.Rows))
	}
	if errorResult.Rows[0].Growth.Kind != stats.GrowthUnavailable {
		t.Errorf("比较数据早于保留期时增幅 = %q，期望 unavailable",
			errorResult.Rows[0].Growth.Kind)
	}
	if errorResult.Rows[0].DataStatus == stats.DataComplete {
		t.Error("保留期不足时错误行不应标记 complete")
	}
}

// TestHealthModulesAndNotEnabled 验证当前健康快照：真实数据库探测、证书到期告警、
// 未来备份模块如实标“未启用”，缺少来源的模块为未知而不是健康。
func TestHealthModulesAndNotEnabled(t *testing.T) {
	notAfter := baseNow.AddDate(0, 0, 10)
	env := newTestEnv(t,
		stats.DatabaseSource{Ping: envPinger{}},
		stats.CertificateSource{StatusFn: func() (time.Time, bool) { return notAfter, true }},
		stats.NotEnabledSource{ModuleKey: stats.ModuleBackup, Reason: "backup_not_implemented"},
	)
	env.grant(stats.ScopeSystem, allDataGrant)
	caller := userCaller(t, testUserID(106))
	result, err := env.service.Health(env.ctx, stats.HealthRequest{
		Caller: caller, ScopeID: stats.ScopeSystem})
	if err != nil {
		t.Fatalf("健康查询失败: %v", err)
	}
	if len(result.Modules) != len(stats.RequiredModules()) {
		t.Fatalf("模块数量 = %d，期望 %d", len(result.Modules), len(stats.RequiredModules()))
	}
	byModule := make(map[stats.Module]stats.HealthSample)
	for _, module := range result.Modules {
		byModule[module.Module] = module
	}
	if sample := byModule[stats.ModuleDatabase]; sample.State != stats.StateHealthy {
		t.Errorf("数据库状态 = %q，期望 healthy", sample.State)
	}
	if sample := byModule[stats.ModuleCertificate]; sample.State != stats.StateDegraded {
		t.Errorf("证书状态 = %q，期望 degraded（10 天内到期）", sample.State)
	}
	if sample := byModule[stats.ModuleBackup]; sample.State != stats.StateNotEnabled || sample.Enabled {
		t.Errorf("备份模块 = %+v，期望未启用且 Enabled=false", sample)
	}
	if sample := byModule[stats.ModuleService]; sample.State != stats.StateUnknown {
		t.Errorf("缺少来源的服务模块状态 = %q，期望 unknown", sample.State)
	}
	// 正常系统范围读取不应产生拒绝审计（不多计正常请求）。
	deniedBefore := env.deniedAuditCount(t)
	if deniedBefore != 0 {
		t.Errorf("正常健康读取产生了拒绝审计 = %d，期望 0", deniedBefore)
	}
	// 已获应用授权、但健康模块属系统级数据：范围拒绝路径必须留痕（不是授权器拒绝）。
	env.grant("app_alpha", stats.ScopeGrant{Allowed: true, AllData: true})
	if _, err := env.service.Health(env.ctx, stats.HealthRequest{
		Caller: caller, ScopeID: "app_alpha"}); !errors.Is(err, stats.ErrAccessDenied) {
		t.Errorf("应用范围健康查询错误 = %v，期望 ErrAccessDenied", err)
	}
	if _, err := env.service.HealthHistory(env.ctx, stats.HealthHistoryRequest{
		Caller: caller, ScopeID: "app_alpha",
		Window: nowWindow(1, stats.GranularityDay)}); !errors.Is(err, stats.ErrAccessDenied) {
		t.Errorf("应用范围健康历史查询错误 = %v，期望 ErrAccessDenied", err)
	}
	deniedAfter := env.deniedAuditCount(t)
	if deniedAfter != deniedBefore+2 {
		t.Errorf("健康范围拒绝审计数量 = %d，期望 %d（两次拒绝各一条，正常请求不多计）",
			deniedAfter, deniedBefore+2)
	}
}

// deniedAuditCount 返回当前拒绝审计数量（统计读取/健康范围拒绝共用动作）。
func (e *testEnv) deniedAuditCount(t *testing.T) int {
	t.Helper()
	var count int
	if err := e.raw.DB().QueryRowContext(e.ctx,
		`SELECT COUNT(*) FROM audit_events WHERE action = 'stats.access.denied'
AND outcome = 'denied'`).Scan(&count); err != nil {
		t.Fatalf("查询拒绝审计失败: %v", err)
	}
	return count
}

// envPinger 是数据库探测替身，返回成功。
type envPinger struct{}

// Ping 实现 stats.Pinger。
func (envPinger) Ping(_ context.Context) error { return nil }

// TestSamplerBoundedAndStorageGrowth 验证采样任务：单次运行写入、缺少来源不写假
// 样本、保留期清理限制存储增长、采样空档判定与并发跳过。
func TestSamplerBoundedAndStorageGrowth(t *testing.T) {
	env := newTestEnv(t)
	sources := []stats.HealthSource{
		stats.FuncSource{ModuleKey: stats.ModuleService, CollectFn: func(_ context.Context,
			now time.Time) (stats.HealthSample, error) {
			return stats.HealthSample{Module: stats.ModuleService,
				State: stats.StateHealthy, Severity: stats.SeverityInfo, Enabled: true,
				ObservedAt: now, Source: "self_check"}, nil
		}},
	}
	sampler, err := stats.NewSampler(stats.SamplerOptions{Store: env.store,
		Sources: sources, Now: env.nowFn, RetentionDays: 30})
	if err != nil {
		t.Fatalf("构造采样任务失败: %v", err)
	}
	run, err := sampler.RunOnce(env.ctx)
	if err != nil {
		t.Fatalf("首次采样失败: %v", err)
	}
	if run.Modules != 1 {
		t.Errorf("写入模块数量 = %d，期望 1", run.Modules)
	}
	// 缺少来源的必需模块不写假样本。
	for _, module := range run.Missing {
		if module == stats.ModuleService {
			t.Error("已提供来源的模块不应出现在 Missing")
		}
	}
	if len(run.Missing) != len(stats.RequiredModules())-1 {
		t.Errorf("缺少来源模块数量 = %d，期望 %d", len(run.Missing),
			len(stats.RequiredModules())-1)
	}
	// 同一观测时刻重复运行按主键幂等。
	if _, err := sampler.RunOnce(env.ctx); err != nil {
		t.Fatalf("重复采样失败: %v", err)
	}
	var sampleCount int
	if err := env.raw.DB().QueryRowContext(env.ctx,
		`SELECT COUNT(*) FROM stats_health_samples`).Scan(&sampleCount); err != nil {
		t.Fatalf("查询采样行失败: %v", err)
	}
	if sampleCount != 1 {
		t.Errorf("采样行数 = %d，期望 1（同一时刻幂等）", sampleCount)
	}
	// 采样历史与空档：两次观测相隔 5 分钟 > 2 倍预期间隔 1 分钟。
	env.setNow(baseNow.Add(5 * time.Minute))
	if _, err := sampler.RunOnce(env.ctx); err != nil {
		t.Fatalf("第二次采样失败: %v", err)
	}
	// 历史查询时钟再往后，避免窗口结束时间被裁剪到最后一个样本的同一时刻。
	env.setNow(baseNow.Add(2 * time.Hour))
	env.grant(stats.ScopeSystem, allDataGrant)
	history, err := env.service.HealthHistory(env.ctx, stats.HealthHistoryRequest{
		Caller: userCaller(t, testUserID(107)), ScopeID: stats.ScopeSystem,
		Window: stats.WindowRequest{TimeZone: "UTC", Start: baseNow.Add(-time.Hour),
			End: baseNow.Add(time.Hour), Granularity: stats.GranularityDay}})
	if err != nil {
		t.Fatalf("采样历史查询失败: %v", err)
	}
	if len(history.Samples) != 2 {
		t.Errorf("历史样本数 = %d，期望 2", len(history.Samples))
	}
	if len(history.Completeness.SamplingGaps) == 0 {
		t.Error("两次观测间隔超过 2 倍预期间隔时应输出采样空档")
	}
	// 保留期清理：插入早于保留期的样本后运行，单次清理删除。
	old := baseNow.AddDate(0, 0, -40)
	if err := env.store.InsertHealthSamples(env.ctx, []stats.HealthSample{{
		Module: stats.ModuleService, State: stats.StateHealthy, Severity: stats.SeverityInfo,
		Enabled: true, ObservedAt: old, Source: "self_check"}}); err != nil {
		t.Fatalf("写入过期样本失败: %v", err)
	}
	pruneRun, err := sampler.RunOnce(env.ctx)
	if err != nil {
		t.Fatalf("保留期清理采样失败: %v", err)
	}
	if pruneRun.Pruned < 1 {
		t.Errorf("清理行数 = %d，期望至少 1", pruneRun.Pruned)
	}
}

// blockingSource 是阻塞状态来源，用于验证采样单实例互斥（不并发重活）。
type blockingSource struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

// Module 实现 stats.HealthSource。
func (s *blockingSource) Module() stats.Module { return stats.ModuleService }

// Collect 实现 stats.HealthSource：进入后阻塞直到 release。
func (s *blockingSource) Collect(_ context.Context, now time.Time) (stats.HealthSample, error) {
	s.once.Do(func() { close(s.entered) })
	<-s.release
	return stats.HealthSample{Module: stats.ModuleService, State: stats.StateHealthy,
		Severity: stats.SeverityInfo, Enabled: true, ObservedAt: now,
		Source: "blocking"}, nil
}

// TestSamplerRejectsConcurrentRun 验证重叠采样被跳过而不是排队堆积。
func TestSamplerRejectsConcurrentRun(t *testing.T) {
	env := newTestEnv(t)
	source := &blockingSource{entered: make(chan struct{}), release: make(chan struct{})}
	sampler, err := stats.NewSampler(stats.SamplerOptions{Store: env.store,
		Sources: []stats.HealthSource{source}, Now: env.nowFn})
	if err != nil {
		t.Fatalf("构造采样任务失败: %v", err)
	}
	firstDone := make(chan error, 1)
	go func() { firstDone <- runSampler(sampler, env.ctx) }()
	<-source.entered
	if _, err := sampler.RunOnce(env.ctx); !errors.Is(err, stats.ErrSamplingInProgress) {
		t.Errorf("重叠采样错误 = %v，期望 ErrSamplingInProgress", err)
	}
	close(source.release)
	if err := <-firstDone; err != nil {
		t.Fatalf("首次采样失败: %v", err)
	}
}

// runSampler 执行一次采样并返回错误，供 goroutine 使用。
func runSampler(sampler *stats.Sampler, ctx context.Context) error {
	_, err := sampler.RunOnce(ctx)
	return err
}

// TestBusinessActivityTrustedSource 验证业务活动组合可信校验：系统身份 + 应用白名单 +
// 用户格式/存在/成员关系 + 幂等键绑定应用；失败 fail-closed 并留痕。
func TestBusinessActivityTrustedSource(t *testing.T) {
	env := newTestEnv(t)
	env.grant(stats.ScopeSystem, allDataGrant)
	systemCaller, err := account.SystemCaller("app_server")
	if err != nil {
		t.Fatalf("构造系统调用者失败: %v", err)
	}
	userAlpha, userBeta := testUserID(51), testUserID(53)
	env.businessAuthz.allowed["app_alpha|"+userAlpha] = true
	env.businessAuthz.allowed["app_beta|"+userBeta] = true
	occurredAt := baseNow.Add(-time.Hour)
	request := stats.BusinessActivityRequest{Caller: systemCaller, AppID: "app_alpha",
		UserID: userAlpha, ActivityKey: "report.generated",
		OccurredAt: occurredAt, DedupeKey: "shared-dedupe-1"}
	if err := env.service.RecordBusinessActivity(env.ctx, request); err != nil {
		t.Fatalf("可信业务活动上报失败: %v", err)
	}
	// 重复上报（同应用同幂等键）按幂等成功，不重复计数。
	if err := env.service.RecordBusinessActivity(env.ctx, request); err != nil {
		t.Fatalf("重复业务活动上报失败: %v", err)
	}
	// 同一幂等键在另一个应用是独立事件，不能被全局唯一键静默吞掉。
	otherApp := request
	otherApp.AppID = "app_beta"
	otherApp.UserID = userBeta
	if err := env.service.RecordBusinessActivity(env.ctx, otherApp); err != nil {
		t.Fatalf("跨应用业务活动上报失败: %v", err)
	}
	// 普通用户会话不能自称可信来源。
	userRequest := request
	userRequest.Caller = userCaller(t, testUserID(52))
	userRequest.DedupeKey = "dedupe-business-2"
	if err := env.service.RecordBusinessActivity(env.ctx, userRequest); !errors.Is(err, stats.ErrAccessDenied) {
		t.Errorf("普通用户上报错误 = %v，期望 ErrAccessDenied", err)
	}
	// 用户 ID 格式非法直接拒绝（不进入存储/授权）。
	badUser := request
	badUser.UserID = "not-a-user-id"
	badUser.DedupeKey = "dedupe-business-3"
	if err := env.service.RecordBusinessActivity(env.ctx, badUser); !errors.Is(err, stats.ErrInvalidRequest) {
		t.Errorf("非法用户 ID 错误 = %v，期望 ErrInvalidRequest", err)
	}
	// 用户不存在/不属于该应用（授权器拒绝）fail-closed。
	crossApp := request
	crossApp.UserID = userBeta
	crossApp.DedupeKey = "dedupe-business-4"
	if err := env.service.RecordBusinessActivity(env.ctx, crossApp); !errors.Is(err, stats.ErrAccessDenied) {
		t.Errorf("跨应用用户上报错误 = %v，期望 ErrAccessDenied", err)
	}
	// 应用不在白名单：即使系统身份也拒绝。
	notAllowed := request
	notAllowed.AppID = "app_gamma"
	notAllowed.DedupeKey = "dedupe-business-5"
	if err := env.service.RecordBusinessActivity(env.ctx, notAllowed); !errors.Is(err, stats.ErrAccessDenied) {
		t.Errorf("未获准应用上报错误 = %v，期望 ErrAccessDenied", err)
	}
	// 拒绝必须写失败审计（不静默）。
	var deniedCount int
	if err := env.raw.DB().QueryRowContext(env.ctx,
		`SELECT COUNT(*) FROM audit_events WHERE action = 'stats.access.denied'
AND outcome = 'denied'`).Scan(&deniedCount); err != nil {
		t.Fatalf("查询拒绝审计失败: %v", err)
	}
	if deniedCount < 3 {
		t.Errorf("业务活动拒绝审计数量 = %d，期望至少 3", deniedCount)
	}
	result, err := env.service.BusinessActivity(env.ctx, stats.BusinessActivityQuery{
		Caller: userCaller(t, testUserID(108)), ScopeID: stats.ScopeSystem,
		Window: nowWindow(1, stats.GranularityDay)})
	if err != nil {
		t.Fatalf("业务活动查询失败: %v", err)
	}
	if result.TotalEvents != 2 || result.DistinctUsers != 2 {
		t.Errorf("业务活动 = %d 次/%d 用户，期望 2/2（跨应用同键不互相吞）",
			result.TotalEvents, result.DistinctUsers)
	}
	if result.Source != stats.SourceAppServer {
		t.Errorf("业务活动来源 = %q，期望 %q", result.Source, stats.SourceAppServer)
	}
	// 单应用筛选只返回该应用事件。
	appResult, err := env.service.BusinessActivity(env.ctx, stats.BusinessActivityQuery{
		Caller: userCaller(t, testUserID(108)), ScopeID: stats.ScopeSystem,
		Window: nowWindow(1, stats.GranularityDay), AppID: "app_alpha"})
	if err != nil {
		t.Fatalf("单应用业务活动查询失败: %v", err)
	}
	if appResult.TotalEvents != 1 {
		t.Errorf("单应用业务活动 = %d，期望 1", appResult.TotalEvents)
	}
}

// TestBusinessActivityRequiresAuthorizer 验证未装配来源授权器时默认拒绝（fail-closed）。
func TestBusinessActivityRequiresAuthorizer(t *testing.T) {
	env := newTestEnv(t)
	service, err := stats.New(stats.Options{Store: env.store,
		Authorizer: env.authorizer, Root: env.root, Now: env.nowFn,
		BusinessActivityApps: []string{"app_alpha"}})
	if err != nil {
		t.Fatalf("构造服务失败: %v", err)
	}
	systemCaller, err := account.SystemCaller("app_server")
	if err != nil {
		t.Fatalf("构造系统调用者失败: %v", err)
	}
	err = service.RecordBusinessActivity(env.ctx, stats.BusinessActivityRequest{
		Caller: systemCaller, AppID: "app_alpha", UserID: testUserID(54),
		ActivityKey: "k", OccurredAt: baseNow.Add(-time.Hour), DedupeKey: "d-no-authz"})
	if !errors.Is(err, stats.ErrAccessDenied) {
		t.Errorf("未装配来源授权器错误 = %v，期望 ErrAccessDenied", err)
	}
}

// TestCriticalFailureNotSwallowedByCancelledAction 验证取消类动作上的失败/不可用审计
// 仍计为失败或 critical，失败请求/任务去重计数不丢失。
func TestCriticalFailureNotSwallowedByCancelledAction(t *testing.T) {
	env := newTestEnv(t)
	env.grant(stats.ScopeSystem, allDataGrant)
	userA := testUserID(81)
	target := baseNow.Add(-time.Hour)
	// 取消类动作但以 DB_UNAVAILABLE 失败结束：必须计为 failure/critical 且计失败请求。
	env.appendEvent(eventSpec{At: target, ActorType: audit.ActorUser, ActorID: userA,
		AppID: "app_alpha", Action: "email.change.cancel", Outcome: audit.OutcomeFailure,
		ErrorCode: "DB_UNAVAILABLE", RequestID: "req-crit-1"})
	// 取消类动作但以 AUDIT_WRITE_FAILED 失败结束：critical 且计失败任务。
	env.appendEvent(eventSpec{At: target, ActorType: audit.ActorSystem, ActorID: "purger",
		AppID: "app_alpha", Action: "audit.purge.cancel", Outcome: audit.OutcomeFailure,
		ErrorCode: "AUDIT_WRITE_FAILED", RequestID: "req-crit-2", TaskID: "task-crit-1"})
	// 真正成功结束的取消动作仍归 cancelled/info。
	env.appendEvent(eventSpec{At: target, ActorType: audit.ActorUser, ActorID: userA,
		AppID: "app_alpha", Action: "audit.export.cancel", Outcome: audit.OutcomeSuccess})
	caller := userCaller(t, testUserID(110))
	result, err := env.service.Errors(env.ctx, stats.ErrorRequest{
		Caller: caller, ScopeID: stats.ScopeSystem,
		Window: nowWindow(1, stats.GranularityDay), DisableComparison: true})
	if err != nil {
		t.Fatalf("错误聚合失败: %v", err)
	}
	rowsByCode := make(map[string]stats.ErrorRow)
	for _, row := range result.Rows {
		rowsByCode[row.ErrorCode] = row
	}
	if row, exists := rowsByCode["DB_UNAVAILABLE"]; !exists ||
		row.Category != stats.CategoryFailure || row.Severity != stats.SeverityCritical ||
		row.FailedRequests != 1 {
		t.Errorf("DB_UNAVAILABLE 行 = %+v，期望 failure/critical 且去重请求 1", row)
	}
	if row, exists := rowsByCode["AUDIT_WRITE_FAILED"]; !exists ||
		row.Category != stats.CategoryFailure || row.Severity != stats.SeverityCritical ||
		row.FailedTasks != 1 {
		t.Errorf("AUDIT_WRITE_FAILED 行 = %+v，期望 failure/critical 且去重任务 1", row)
	}
	if row, exists := rowsByCode[""]; !exists || row.Category != stats.CategoryCancelled {
		t.Errorf("成功取消动作未归入 cancelled/info: %+v", row)
	}
	if result.FailedRequests != 2 || result.FailedTasks != 1 {
		t.Errorf("全局去重失败请求/任务 = %d/%d，期望 2/1（critical 不丢）",
			result.FailedRequests, result.FailedTasks)
	}
}

// TestNewValidatesHealthSources 验证构造期校验健康来源（模块登记/重复）。
func TestNewValidatesHealthSources(t *testing.T) {
	env := newTestEnv(t)
	if _, err := stats.New(stats.Options{Store: env.store, Authorizer: env.authorizer,
		Root: env.root, HealthSources: []stats.HealthSource{
			stats.FuncSource{ModuleKey: "unknown_module"}}}); !errors.Is(err, stats.ErrOptionsInvalid) {
		t.Errorf("未登记模块构造错误 = %v，期望 ErrOptionsInvalid", err)
	}
	if _, err := stats.New(stats.Options{Store: env.store, Authorizer: env.authorizer,
		Root: env.root, HealthSources: []stats.HealthSource{
			stats.FuncSource{ModuleKey: stats.ModuleService},
			stats.FuncSource{ModuleKey: stats.ModuleService}}}); !errors.Is(err, stats.ErrOptionsInvalid) {
		t.Errorf("重复模块构造错误 = %v，期望 ErrOptionsInvalid", err)
	}
}

// TestRootAppScopeStaysApp 验证 root 选择具体应用范围时仍只聚合法应用，不退化为全系统。
func TestRootAppScopeStaysApp(t *testing.T) {
	env := newTestEnv(t)
	userA, userB := testUserID(82), testUserID(83)
	target := baseNow.Add(-time.Hour)
	env.appendSessionIssue(target, userA, "app_alpha", false)
	env.appendSessionIssue(target, userB, "app_beta", false)
	rootID := testUserID(111)
	env.root.roots[rootID] = true
	caller := userCaller(t, rootID)
	appResult, err := env.service.Activity(env.ctx, stats.ActivityRequest{
		Caller: caller, ScopeID: "app_alpha",
		Window: nowWindow(1, stats.GranularityDay)})
	if err != nil {
		t.Fatalf("root 应用范围活跃度失败: %v", err)
	}
	if appResult.TotalActiveUsers != 1 {
		t.Errorf("root 应用范围活跃用户 = %d，期望 1（不退化为全系统）", appResult.TotalActiveUsers)
	}
	errorEnv := newTestEnv(t)
	errorEnv.root.roots[rootID] = true
	errorEnv.appendEvent(eventSpec{At: target, ActorType: audit.ActorUser, ActorID: userA,
		AppID: "app_alpha", Action: "x", Outcome: audit.OutcomeFailure,
		ErrorCode: "INTERNAL_ERROR"})
	errorEnv.appendEvent(eventSpec{At: target, ActorType: audit.ActorUser, ActorID: userA,
		AppID: "app_beta", Action: "x", Outcome: audit.OutcomeFailure,
		ErrorCode: "INTERNAL_ERROR"})
	errorResult, err := errorEnv.service.Errors(errorEnv.ctx, stats.ErrorRequest{
		Caller: userCaller(t, rootID), ScopeID: "app_alpha",
		Window: nowWindow(1, stats.GranularityDay), DisableComparison: true})
	if err != nil {
		t.Fatalf("root 应用范围错误聚合失败: %v", err)
	}
	if len(errorResult.Rows) != 1 || errorResult.Rows[0].AppID != "app_alpha" {
		t.Errorf("root 应用范围错误行 = %+v，期望仅 app_alpha", errorResult.Rows)
	}
}

// TestOverviewSameContext 验证看板摘要引用同一窗口与范围，并输出完整性。
func TestOverviewSameContext(t *testing.T) {
	env := newTestEnv(t)
	env.grant(stats.ScopeSystem, allDataGrant)
	userA := testUserID(61)
	target := baseNow.Add(-time.Hour)
	env.appendSessionIssue(target, userA, "app_alpha", false)
	env.appendEvent(eventSpec{At: target, ActorType: audit.ActorUser, ActorID: userA,
		AppID: "app_alpha", Action: "x", Outcome: audit.OutcomeFailure,
		ErrorCode: "INTERNAL_ERROR", RequestID: "req-ov"})
	result, err := env.service.Overview(env.ctx, stats.OverviewRequest{
		Caller: userCaller(t, testUserID(109)), ScopeID: stats.ScopeSystem,
		Window: nowWindow(1, stats.GranularityDay)})
	if err != nil {
		t.Fatalf("看板摘要查询失败: %v", err)
	}
	if result.ActiveUsers != 1 || result.TotalRawEvents != 1 || result.FailedRequests != 1 {
		t.Errorf("摘要 = %d 活跃/%d 原始/%d 去重请求，期望 1/1/1",
			result.ActiveUsers, result.TotalRawEvents, result.FailedRequests)
	}
	if result.Scope.ID != stats.ScopeSystem {
		t.Errorf("摘要范围 = %+v，期望 system", result.Scope)
	}
	if result.Window.TimeZone != "Asia/Shanghai" {
		t.Errorf("摘要时区 = %q", result.Window.TimeZone)
	}
	if result.Completeness.RetentionDays != 180 {
		t.Errorf("完整性保留天数 = %d，期望 180", result.Completeness.RetentionDays)
	}
}

// TestStatsStoreRejectsUnknownSource 验证仓储层也拒绝非可信业务活动来源。
func TestStatsStoreRejectsUnknownSource(t *testing.T) {
	env := newTestEnv(t)
	_, err := env.store.InsertBusinessActivity(env.ctx, stats.BusinessActivityRecord{
		AppID: "app_alpha", UserID: testUserID(71), ActivityKey: "k",
		OccurredAt: baseNow.Add(-time.Hour), RecordedAt: baseNow,
		Source: "browser", DedupeKey: "d1"})
	if !errors.Is(err, stats.ErrInvalidRequest) {
		t.Errorf("不可信来源错误 = %v，期望 ErrInvalidRequest", err)
	}
	// 保留策略缺省时不伪造配置时间：found=false。
	if _, found, err := env.store.GetRetention(env.ctx); err != nil || found {
		t.Errorf("缺省保留策略 found=%v err=%v，期望 false/nil", found, err)
	}
}
