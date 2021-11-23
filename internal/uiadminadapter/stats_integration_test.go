package uiadminadapter_test

// 步骤 76 统计页适配器真实服务集成测试：使用真实 SQLite + 真实 internal/audit 写入、
// internal/stats 统计服务与 internal/auditops 查询，验证统计值与审计明细计数一致、
// 分类/去重/排序/零基数增幅、跨应用可见性与无权限拒绝。权限引擎、root 判定与敏感
// 操作为边界测试替身（不作为生产鉴权）；浏览器视口另列未实测项。

import (
	"context"
	"fmt"
	"math"
	"path/filepath"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/auditops"
	auditopssqlite "github.com/kagurazakayashi/EvernightLogin/internal/auditops/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
	statssqlite "github.com/kagurazakayashi/EvernightLogin/internal/stats/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/internal/uiadminadapter"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// statsNow 是统计适配器集成测试的固定时钟。
var statsNow = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

// statsUserID 生成格式合法的稳定用户 ID。
func statsUserID(index int) string { return fmt.Sprintf("usr_%032x", index) }

// statsAuthorizer 是 stats 作用范围授权替身（按 用户|权限|范围 白名单）。
type statsAuthorizer struct {
	grants map[string]stats.ScopeGrant
}

func (f *statsAuthorizer) AuthorizeScope(_ context.Context, caller account.Caller,
	permissionKey, scopeID string) (stats.ScopeGrant, error) {
	key := caller.Actor().ID + "|" + permissionKey + "|" + scopeID
	if grant, ok := f.grants[key]; ok {
		return grant, nil
	}
	return stats.ScopeGrant{Allowed: false}, nil
}

// statsRoot 是 root 判定替身，同时满足 stats/auditops 的 RootChecker。
type statsRoot struct{ roots map[string]bool }

func (f *statsRoot) IsRoot(_ context.Context, caller account.Caller) (bool, error) {
	return f.roots[caller.Actor().ID], nil
}

// statsAuditAuthorizer 是 auditops 授权替身。
type statsAuditAuthorizer struct {
	grants map[string]auditops.ScopeGrant
}

func (f *statsAuditAuthorizer) AuthorizeScope(_ context.Context, caller account.Caller,
	permissionKey, scopeID string) (auditops.ScopeGrant, error) {
	key := caller.Actor().ID + "|" + permissionKey + "|" + scopeID
	if grant, ok := f.grants[key]; ok {
		return grant, nil
	}
	return auditops.ScopeGrant{Allowed: false}, nil
}

// statsSensitive 是敏感操作替身。
type statsSensitive struct{}

func (statsSensitive) Authorize(_ context.Context, _ reauth.Caller,
	request reauth.Request) (reauth.Result, error) {
	return reauth.Result{OperationID: request.OperationID}, nil
}

func (statsSensitive) NotifyOutcome(context.Context, reauth.Result, reauth.Outcome) error {
	return nil
}

// statsEnqueuer 是任务入队替身。
type statsEnqueuer struct{}

func (statsEnqueuer) Enqueue(context.Context, task.EnqueueRequest) (task.Job, error) {
	return task.Job{ID: "job_stats", State: task.StateQueued}, nil
}

// statsCanceller 是任务取消替身。
type statsCanceller struct{}

func (statsCanceller) RequestCancel(context.Context,
	task.CancelRequest) (task.CancelResult, error) {
	return task.CancelResult{Accepted: true, State: task.StateCancelRequested}, nil
}

// statsIntegrationEnv 是真实 SQLite + 真实 stats/auditops 的隔离环境。
type statsIntegrationEnv struct {
	t               *testing.T
	ctx             context.Context
	audit           *auditsqlite.Store
	recorder        *audit.Recorder
	statsAdpt       *uiadminadapter.StatsAdapter
	auditSvc        *auditops.Service
	authorizer      *statsAuthorizer
	auditAuthorizer *statsAuditAuthorizer
	root            *statsRoot
}

// newStatsIntegrationEnv 构造临时数据库、真实服务与适配器。
func newStatsIntegrationEnv(t *testing.T) *statsIntegrationEnv {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(testutil.TempDir(t), "stats_page.db")
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
		t.Fatalf("构造审计存储失败: %v", err)
	}
	recorder, err := audit.New(auditStore, audit.Options{Now: func() time.Time { return statsNow }})
	if err != nil {
		t.Fatalf("构造审计 Recorder 失败: %v", err)
	}
	statsStore, err := statssqlite.New(raw)
	if err != nil {
		t.Fatalf("构造统计存储失败: %v", err)
	}
	authorizer := &statsAuthorizer{grants: map[string]stats.ScopeGrant{}}
	root := &statsRoot{roots: map[string]bool{}}
	statsService, err := stats.New(stats.Options{Store: statsStore, Authorizer: authorizer,
		Root: root, Audit: recorder, Now: func() time.Time { return statsNow },
		RetentionDays: 180})
	if err != nil {
		t.Fatalf("构造统计服务失败: %v", err)
	}
	auditStoreOps, err := auditopssqlite.New(raw)
	if err != nil {
		t.Fatalf("构造审计查询存储失败: %v", err)
	}
	auditAuthorizer := &statsAuditAuthorizer{grants: map[string]auditops.ScopeGrant{}}
	auditSvc, err := auditops.New(auditops.Options{Store: auditStoreOps, Audit: recorder,
		Authorizer: auditAuthorizer,
		Root:       root, Sensitive: statsSensitive{}, Enqueuer: statsEnqueuer{},
		Canceller: statsCanceller{}, OutputDir: testutil.TempDir(t),
		Now: func() time.Time { return statsNow }})
	if err != nil {
		t.Fatalf("构造审计查询服务失败: %v", err)
	}
	adapter, err := uiadminadapter.NewStats(uiadminadapter.StatsOptions{
		Stats: statsService, Authorizer: authorizer, Recorder: recorder,
		IsRoot: func(_ context.Context, userID string) (bool, error) {
			return root.roots[userID], nil
		},
		AuditRead: func(_ context.Context, userID string) (bool, error) {
			return userID == statsUserID(1) || userID == statsUserID(2), nil
		},
	})
	if err != nil {
		t.Fatalf("构造统计页适配器失败: %v", err)
	}
	return &statsIntegrationEnv{t: t, ctx: ctx, audit: auditStore, recorder: recorder,
		statsAdpt: adapter, auditSvc: auditSvc, authorizer: authorizer,
		auditAuthorizer: auditAuthorizer, root: root}
}

// grant 登记统计读取授权。
func (e *statsIntegrationEnv) grant(userID, scopeID string, grant stats.ScopeGrant) {
	e.authorizer.grants[userID+"|"+stats.PermissionRead+"|"+scopeID] = grant
}

// seed 写入一条审计事件。
func (e *statsIntegrationEnv) seed(at time.Time, actorType audit.ActorKind, actorID,
	appID, action string, outcome audit.Outcome, errorCode, requestID, taskID string,
	changes ...audit.FieldChange) {
	e.t.Helper()
	prepared, err := audit.PrepareEvent(audit.Event{
		Actor: audit.Actor{Type: actorType, ID: actorID}, AppID: appID,
		Action: action, Target: audit.Target{Type: "test", ID: "target"},
		Outcome: outcome, ErrorCode: errorCode, RequestID: requestID, TaskID: taskID,
		Changes: changes,
	}, at)
	if err != nil {
		e.t.Fatalf("准备审计事件失败: %v", err)
	}
	if err := e.audit.Append(e.ctx, prepared); err != nil {
		e.t.Fatalf("写入审计事件失败: %v", err)
	}
}

// seedSessionIssue 写入一条完整成功认证。
func (e *statsIntegrationEnv) seedSessionIssue(at time.Time, userID, appID string) {
	e.seed(at, audit.ActorUser, userID, appID, "session.issue",
		audit.OutcomeSuccess, "", "", "",
		audit.FieldChange{Field: "session_kind", After: "normal"})
}

// closedWindow 返回已结束的固定窗口 [start,end)（UTC）。
func closedWindow() login.UIStatsWindow {
	return login.UIStatsWindow{TimeZone: "UTC",
		Start:       time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC),
		End:         time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC),
		Granularity: "day", Range: "custom"}
}

// seedStatsPageFixtures 写入确定性错误/成功认证数据。
func seedStatsPageFixtures(env *statsIntegrationEnv) {
	// 当前窗口：同一失败请求两条日志 + 正常拒绝 + 等待授权 + 警告码。
	env.seed(time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC), audit.ActorSystem,
		"svc_worker", "app_alpha", "backup.failed", audit.OutcomeFailure,
		"BACKUP_FAILED", "req_same", "")
	env.seed(time.Date(2026, 11, 12, 10, 1, 0, 0, time.UTC), audit.ActorSystem,
		"svc_worker", "app_alpha", "backup.failed", audit.OutcomeFailure,
		"BACKUP_FAILED", "req_same", "")
	env.seed(time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC), audit.ActorSystem,
		"svc_worker", "app_alpha", "webhook.delivery.failed", audit.OutcomeFailure,
		"WEBHOOK_DELIVERY_FAILED", "req_webhook", "task_webhook")
	env.seed(time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC), audit.ActorUser,
		statsUserID(9), "app_alpha", "role.assign", audit.OutcomeDenied,
		"ACCESS_DENIED", "", "")
	env.seed(time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC), audit.ActorUser,
		statsUserID(9), "app_alpha", "app_qr_login.request_created",
		audit.OutcomeSuccess, "", "", "")
	env.seed(time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC), audit.ActorSystem,
		"svc_worker", "app_alpha", "report.generate", audit.OutcomeSuccess,
		"REPORT_DATA_INCOMPLETE", "", "")
	// 成功认证：userA 两个应用各自一次（跨应用去重应计 1），userB 一次（app_beta）。
	env.seedSessionIssue(time.Date(2026, 11, 13, 8, 0, 0, 0, time.UTC), statsUserID(1), "app_alpha")
	env.seedSessionIssue(time.Date(2026, 11, 14, 8, 0, 0, 0, time.UTC), statsUserID(1), "app_beta")
	env.seedSessionIssue(time.Date(2026, 11, 15, 8, 0, 0, 0, time.UTC), statsUserID(2), "app_beta")
	// 前一等长窗口中的同一错误码（用于增幅比较），以及只在当前窗口出现的错误码（新增）。
	env.seed(time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC), audit.ActorSystem,
		"svc_worker", "app_alpha", "webhook.delivery.failed", audit.OutcomeFailure,
		"WEBHOOK_DELIVERY_FAILED", "req_old", "task_old")
	env.seed(time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC), audit.ActorSystem,
		"svc_worker", "app_alpha", "db.failed", audit.OutcomeFailure,
		"DB_UNAVAILABLE", "req_db_old", "")
}

// TestStatsDashboardCountsMatchAuditDetails 验证统计值与审计明细计数一致、类别分开、
// 跨应用去重与当前窗口健康快照。
func TestStatsDashboardCountsMatchAuditDetails(t *testing.T) {
	env := newStatsIntegrationEnv(t)
	seedStatsPageFixtures(env)
	env.grant(statsUserID(1), stats.ScopeSystem, stats.ScopeGrant{Allowed: true, AllData: true})
	caps, err := env.statsAdpt.Capabilities(env.ctx, statsUserID(1))
	if err != nil || !caps.Read {
		t.Fatalf("能力位读取失败: %v caps=%+v", err, caps)
	}
	dashboard, err := env.statsAdpt.Dashboard(env.ctx, statsUserID(1),
		login.UIStatsQuery{ScopeID: stats.ScopeSystem, Window: closedWindow()})
	if err != nil {
		t.Fatalf("看板读取失败: %v", err)
	}
	if dashboard.Overview.ActiveUsers != 2 {
		t.Fatalf("去重活跃用户 = %d，期望 2（跨应用按用户去重）", dashboard.Overview.ActiveUsers)
	}
	// 当前窗口原始错误事件：2 备份失败 + 1 Webhook 失败 + 1 拒绝 + 1 等待 + 1 警告 = 6。
	if dashboard.Overview.RawEvents != 6 {
		t.Fatalf("原始事件数 = %d，期望 6", dashboard.Overview.RawEvents)
	}
	if dashboard.Overview.FailedRequests != 2 {
		t.Fatalf("去重失败请求数 = %d，期望 2", dashboard.Overview.FailedRequests)
	}
	if dashboard.Overview.FailedTasks != 1 {
		t.Fatalf("去重失败任务数 = %d，期望 1", dashboard.Overview.FailedTasks)
	}
	// 类别分开：等待 1、拒绝 1、警告 1、故障 2。
	categories := map[string]int64{}
	for _, category := range dashboard.Overview.Categories {
		categories[category.Category] = category.RawEvents
	}
	if categories["pending"] != 1 || categories["denied"] != 1 ||
		categories["warning"] != 1 || categories["failure"] != 3 {
		t.Fatalf("类别汇总不符合口径: %+v", categories)
	}
	// 系统状态快照：没有配置健康来源时模块应为未知/未启用，不得显示为正常。
	if dashboard.Health == nil {
		t.Fatal("系统范围应返回当前状态快照")
	}
	for _, module := range dashboard.Health.Modules {
		if module.State == "healthy" {
			t.Fatalf("没有真实来源的模块不应显示为正常: %+v", module)
		}
	}
	// 统计值与审计明细一致：同一窗口、同一范围的失败+拒绝原始事件计数。
	env.auditAuthorizer.grants[statsUserID(1)+"|audit.read|system"] =
		auditops.ScopeGrant{Allowed: true, AllData: true}
	auditPage, err := env.auditSvc.Query(env.ctx, auditops.QueryRequest{
		Caller: mustUserCaller(t, statsUserID(1)), ScopeID: auditops.ScopeSystem,
		Limit: 100})
	if err != nil {
		t.Fatalf("审计明细查询失败: %v", err)
	}
	failureDetails, deniedDetails := 0, 0
	for _, event := range auditPage.Events {
		if event.OccurredAt.Before(closedWindow().Start) ||
			!event.OccurredAt.Before(closedWindow().End) {
			continue
		}
		switch event.Outcome {
		case audit.OutcomeFailure:
			failureDetails++
		case audit.OutcomeDenied:
			deniedDetails++
		}
	}
	if int64(failureDetails) != categories["failure"] {
		t.Fatalf("故障统计 %d 与明细 %d 不一致", categories["failure"], failureDetails)
	}
	if int64(deniedDetails) != categories["denied"] {
		t.Fatalf("拒绝统计 %d 与明细 %d 不一致", categories["denied"], deniedDetails)
	}
}

// mustUserCaller 构造合法用户调用者。
func mustUserCaller(t *testing.T, userID string) account.Caller {
	t.Helper()
	caller, err := account.UserCaller(userID)
	if err != nil {
		t.Fatalf("构造用户调用者失败: %v", err)
	}
	return caller
}

// TestStatsErrorSortingShareAndGrowth 验证排序、占比分母、零基数“新增”与比较窗口。
func TestStatsErrorSortingShareAndGrowth(t *testing.T) {
	env := newStatsIntegrationEnv(t)
	seedStatsPageFixtures(env)
	env.grant(statsUserID(1), stats.ScopeSystem, stats.ScopeGrant{Allowed: true, AllData: true})
	window := closedWindow()
	page, err := env.statsAdpt.Errors(env.ctx, statsUserID(1), login.UIStatsQuery{
		ScopeID: stats.ScopeSystem, Window: window, Sort: "raw_events", Order: "desc",
		Limit: 20})
	if err != nil {
		t.Fatalf("错误明细读取失败: %v", err)
	}
	if page.TotalRawEvents != 6 || page.ShareDenominator != 6 {
		t.Fatalf("总数/占比分母 = %d/%d，期望 6/6", page.TotalRawEvents, page.ShareDenominator)
	}
	var backupRow login.UIStatsErrorRow
	for _, row := range page.Rows {
		if row.ErrorCode == "BACKUP_FAILED" {
			backupRow = row
		}
	}
	if backupRow.RawEvents != 2 || backupRow.FailedRequests != 1 {
		t.Fatalf("备份失败行 = %+v，期望原始 2/去重请求 1", backupRow)
	}
	if math.Abs(backupRow.Share-2.0/6.0) > 0.0001 {
		t.Fatalf("备份失败占比 = %v，期望 %.4f", backupRow.Share, 2.0/6.0)
	}
	// 零基数：BACKUP_FAILED 在前一窗口为零 → 新增；WEBHOOK 在前一窗口存在 → 百分比。
	if backupRow.GrowthKind != "new" {
		t.Fatalf("零基数增幅 = %s，期望 new", backupRow.GrowthKind)
	}
	var webhookRow login.UIStatsErrorRow
	for _, row := range page.Rows {
		if row.ErrorCode == "WEBHOOK_DELIVERY_FAILED" {
			webhookRow = row
		}
	}
	if webhookRow.GrowthKind != "percent" {
		t.Fatalf("Webhook 增幅 = %s，期望 percent", webhookRow.GrowthKind)
	}
	// 五种排序均由服务端执行且返回稳定字段；占比升序首行应是最小占比。
	ascending, err := env.statsAdpt.Errors(env.ctx, statsUserID(1), login.UIStatsQuery{
		ScopeID: stats.ScopeSystem, Window: window, Sort: "share", Order: "asc",
		Limit: 20})
	if err != nil {
		t.Fatalf("占比排序失败: %v", err)
	}
	if len(ascending.Rows) > 1 && ascending.Rows[0].Share > ascending.Rows[1].Share {
		t.Fatalf("占比升序未生效: %v", ascending.Rows[0].Share)
	}
}

// TestStatsCrossAppVisibilityAndDenied 验证应用管理员只能看到获准应用，跨应用汇总
// 在聚合前按权限过滤；无授权与越权范围放回明确拒绝。
func TestStatsCrossAppVisibilityAndDenied(t *testing.T) {
	env := newStatsIntegrationEnv(t)
	seedStatsPageFixtures(env)
	appOnly := stats.ScopeGrant{Allowed: true, AllData: false, ResourceIDs: []string{"app_alpha"}}
	env.grant(statsUserID(2), stats.ScopeSystem, appOnly)
	caps, err := env.statsAdpt.Capabilities(env.ctx, statsUserID(2))
	if err != nil {
		t.Fatalf("能力位读取失败: %v", err)
	}
	if !caps.Read || len(caps.Scopes) != 1 || caps.Scopes[0] != "app_alpha" {
		t.Fatalf("应用管理员可见范围不符: %+v", caps.Scopes)
	}
	dashboard, err := env.statsAdpt.Dashboard(env.ctx, statsUserID(2),
		login.UIStatsQuery{ScopeID: stats.ScopeSystem, Window: closedWindow()})
	if err != nil {
		t.Fatalf("应用管理员看板读取失败: %v", err)
	}
	// app_alpha 范围内：活跃用户来自 session.issue（app_alpha 一次），userB 在 app_beta
	// 不应被计入；waiting/warning 等仍按 app_alpha 过滤。
	if dashboard.Overview.ActiveUsers != 1 {
		t.Fatalf("应用范围去重活跃 = %d，期望 1", dashboard.Overview.ActiveUsers)
	}
	// 未授权应用范围直接拒绝，且不泄露目标是否存在。
	if _, err := env.statsAdpt.Errors(env.ctx, statsUserID(2), login.UIStatsQuery{
		ScopeID: "app_beta", Window: closedWindow()}); err == nil {
		t.Fatal("未授权应用范围应被拒绝")
	}
	// 无授权用户能力位为 false 且读取拒绝。
	unpriv := statsUserID(3)
	caps, err = env.statsAdpt.Capabilities(env.ctx, unpriv)
	if err != nil {
		t.Fatalf("能力位读取失败: %v", err)
	}
	if caps.Read {
		t.Fatal("未授权用户不应具有统计读取能力")
	}
	if _, err := env.statsAdpt.Dashboard(env.ctx, unpriv, login.UIStatsQuery{
		ScopeID: stats.ScopeSystem, Window: closedWindow()}); err == nil {
		t.Fatal("未授权用户读取应被拒绝")
	}
}

// TestStatsStatisticsSameWindowAndTrend 验证活跃度与错误趋势使用同一窗口、趋势按桶
// 分类且状态完整。
func TestStatsStatisticsSameWindowAndTrend(t *testing.T) {
	env := newStatsIntegrationEnv(t)
	seedStatsPageFixtures(env)
	env.grant(statsUserID(1), stats.ScopeSystem, stats.ScopeGrant{Allowed: true, AllData: true})
	result, err := env.statsAdpt.Statistics(env.ctx, statsUserID(1), login.UIStatsQuery{
		ScopeID: stats.ScopeSystem, Window: closedWindow(), Metric: "dedup_failed_requests"})
	if err != nil {
		t.Fatalf("趋势读取失败: %v", err)
	}
	if !result.Activity.Start.Equal(result.ErrorTrend.Start) ||
		!result.Activity.End.Equal(result.ErrorTrend.End) {
		t.Fatalf("活跃度与错误趋势窗口不一致: %v/%v vs %v/%v",
			result.Activity.Start, result.Activity.End,
			result.ErrorTrend.Start, result.ErrorTrend.End)
	}
	if result.ErrorTrend.Metric != "dedup_failed_requests" {
		t.Fatalf("趋势主指标 = %q", result.ErrorTrend.Metric)
	}
	if len(result.Activity.Points) != 7 {
		t.Fatalf("活跃度桶数 = %d，期望 7", len(result.Activity.Points))
	}
	if result.Activity.TotalActiveUsers != 2 {
		t.Fatalf("活跃去重用户 = %d，期望 2", result.Activity.TotalActiveUsers)
	}
	// 趋势点按桶×类别给出完整序列：故障类别有实际事件的桶有 2 个，其余桶为真实零值。
	countedFailure := 0
	for _, point := range result.ErrorTrend.Points {
		if point.Category != "failure" {
			continue
		}
		if point.DataStatus != "complete" {
			t.Fatalf("完整桶状态 = %s", point.DataStatus)
		}
		if point.RawEvents > 0 {
			countedFailure++
		}
	}
	if countedFailure != 2 {
		t.Fatalf("有故障事件的桶数 = %d，期望 2", countedFailure)
	}
	// 当前窗口边界之外的事件不得计入（终点 11-18 00:00 的事件不存在；起点包含）。
	for _, point := range result.ErrorTrend.Points {
		if point.BucketKey >= "2026-11-18" {
			t.Fatalf("桶超出窗口: %s", point.BucketKey)
		}
	}
}
