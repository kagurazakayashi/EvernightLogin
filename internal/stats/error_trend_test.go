package stats_test

// 步骤 76 前置：错误趋势分桶聚合的定向测试。验证分类分离、桶边界、行级去重、
// 类别筛选、保留期未知标记与来源截断标记；全部使用隔离 SQLite 测试库。

import (
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
)

// trendWindow 返回以 baseNow 为结束、跨 days 天的日桶窗口。
func trendWindow(days int) stats.WindowRequest {
	return stats.WindowRequest{TimeZone: "Asia/Shanghai",
		Start:       baseNow.AddDate(0, 0, -days),
		End:         baseNow,
		Granularity: stats.GranularityDay}
}

// findTrendPoint 返回指定桶键与类别的趋势点。
func findTrendPoint(t *testing.T, points []stats.ErrorTrendPoint, key string,
	category stats.Category) stats.ErrorTrendPoint {
	t.Helper()
	for _, point := range points {
		if point.Bucket.Key == key && point.Category == category {
			return point
		}
	}
	t.Fatalf("缺少趋势点 %s/%s", key, category)
	return stats.ErrorTrendPoint{}
}

// errorEvent 用系统身份补齐 eventSpec（统计测试只关心结果/错误码/关联编号）。
func errorEvent(spec eventSpec) eventSpec {
	spec.ActorType = audit.ActorSystem
	spec.ActorID = "svc_stats_test"
	return spec
}

// TestErrorTrendBucketsCategoriesAndDedup 验证错误趋势按桶与类别分离、原始次数与
// 去重失败请求/任务数分别计算（重试不重复计数），且成功/等待/拒绝/取消/警告不混。
func TestErrorTrendBucketsCategoriesAndDedup(t *testing.T) {
	env := newTestEnv(t)
	env.grant(stats.ScopeSystem, allDataGrant)
	yesterday := time.Date(2026, 11, 18, 10, 0, 0, 0, cst)
	today := time.Date(2026, 11, 19, 9, 0, 0, 0, cst)
	// 同一失败请求的两条日志（采集/投递重试）：原始次数 2，去重失败请求 1。
	env.appendEvent(errorEvent(eventSpec{At: yesterday, AppID: "app_alpha",
		Action: "session.issue", Outcome: audit.OutcomeFailure, ErrorCode: "DB_UNAVAILABLE",
		RequestID: "req_1"}))
	env.appendEvent(errorEvent(eventSpec{At: yesterday.Add(time.Minute), AppID: "app_alpha",
		Action: "session.issue", Outcome: audit.OutcomeFailure, ErrorCode: "DB_UNAVAILABLE",
		RequestID: "req_1"}))
	// 同一任务重试：去重失败任务 1。
	env.appendEvent(errorEvent(eventSpec{At: today, AppID: "app_alpha",
		Action: "webhook.delivery.failed", Outcome: audit.OutcomeFailure,
		ErrorCode: "WEBHOOK_DELIVERY_FAILED", TaskID: "task_1"}))
	env.appendEvent(errorEvent(eventSpec{At: today.Add(2 * time.Minute), AppID: "app_alpha",
		Action: "webhook.delivery.failed", Outcome: audit.OutcomeFailure,
		ErrorCode: "WEBHOOK_DELIVERY_FAILED", TaskID: "task_1"}))
	// 正常拒绝是保护生效，不是故障。
	env.appendEvent(errorEvent(eventSpec{At: yesterday, AppID: "app_alpha",
		Action: "role.assign", Outcome: audit.OutcomeDenied, ErrorCode: "ACCESS_DENIED"}))
	// 等待授权单独计数。
	env.appendEvent(errorEvent(eventSpec{At: today, AppID: "app_alpha",
		Action: "app_qr_login.request_created", Outcome: audit.OutcomeSuccess}))
	// 数据质量警告不是故障。
	env.appendEvent(errorEvent(eventSpec{At: today, AppID: "app_alpha",
		Action: "report.generate", Outcome: audit.OutcomeSuccess,
		ErrorCode: "REPORT_DATA_INCOMPLETE"}))
	// 任务取消不是失败。
	env.appendEvent(errorEvent(eventSpec{At: today, AppID: "app_alpha",
		Action: "task.cancel", Outcome: audit.OutcomeFailure, ErrorCode: "TASK_CANCELLED"}))
	// 未登记错误码保留 unknown，不静默归入故障。
	env.appendEvent(errorEvent(eventSpec{At: today, AppID: "app_alpha",
		Action: "custom.action", Outcome: audit.OutcomeFailure, ErrorCode: "CUSTOM_FAIL"}))

	caller := userCaller(t, testUserID(100))
	result, err := env.service.ErrorTrend(env.ctx, stats.ErrorTrendRequest{
		Caller: caller, ScopeID: stats.ScopeSystem, Window: trendWindow(2),
	})
	if err != nil {
		t.Fatalf("错误趋势查询失败: %v", err)
	}
	if result.Window.TimeZone != "Asia/Shanghai" {
		t.Fatalf("时区丢失: %q", result.Window.TimeZone)
	}
	if result.TotalRawEvents != 9 {
		t.Fatalf("原始事件总数 = %d，期望 9", result.TotalRawEvents)
	}
	// 仅失败结果进入去重计数：DB_UNAVAILABLE 两条同号 → 1 个请求；
	// WEBHOOK_DELIVERY_FAILED 两条同任务 → 1 个任务、2 个逻辑请求（各事件无编号）。
	if result.FailedRequests != 4 {
		t.Fatalf("去重失败请求数 = %d，期望 4", result.FailedRequests)
	}
	if result.FailedTasks != 1 {
		t.Fatalf("去重失败任务数 = %d，期望 1", result.FailedTasks)
	}
	keyYesterday, keyToday := "2026-11-18", "2026-11-19"
	failureYesterday := findTrendPoint(t, result.Points, keyYesterday, stats.CategoryFailure)
	if failureYesterday.RawEvents != 2 || failureYesterday.FailedRequests != 1 {
		t.Fatalf("昨日故障点 = %+v，期望原始 2/去重请求 1", failureYesterday)
	}
	if failureYesterday.DataStatus != stats.DataComplete {
		t.Fatalf("完整桶状态 = %s，期望 complete", failureYesterday.DataStatus)
	}
	failureToday := findTrendPoint(t, result.Points, keyToday, stats.CategoryFailure)
	if failureToday.RawEvents != 2 {
		t.Fatalf("今日故障原始次数 = %d，期望 2", failureToday.RawEvents)
	}
	denied := findTrendPoint(t, result.Points, keyYesterday, stats.CategoryDenied)
	if denied.RawEvents != 1 || denied.Severity != stats.SeverityInfo {
		t.Fatalf("拒绝点 = %+v，期望 1/info", denied)
	}
	pending := findTrendPoint(t, result.Points, keyToday, stats.CategoryPending)
	if pending.RawEvents != 1 {
		t.Fatalf("等待点 = %d，期望 1", pending.RawEvents)
	}
	warning := findTrendPoint(t, result.Points, keyToday, stats.CategoryWarning)
	if warning.RawEvents != 1 {
		t.Fatalf("警告点 = %d，期望 1", warning.RawEvents)
	}
	cancelled := findTrendPoint(t, result.Points, keyToday, stats.CategoryCancelled)
	if cancelled.RawEvents != 1 {
		t.Fatalf("取消点 = %d，期望 1", cancelled.RawEvents)
	}
	unknown := findTrendPoint(t, result.Points, keyToday, stats.CategoryUnknown)
	if unknown.RawEvents != 1 || unknown.Severity != stats.SeverityUnknown {
		t.Fatalf("未知错误点 = %+v，期望 1/unknown", unknown)
	}
	// 类别摘要与点一致，不把等待/取消/警告合并成“错误”。
	if len(result.Categories) != 6 {
		t.Fatalf("类别摘要数 = %d，期望 6", len(result.Categories))
	}
}

// TestErrorTrendCategoryFilterAndInProgress 验证类别筛选只返回指定类别、末桶标
// 进行中、没有事件的类别在筛选下给出真实零值。
func TestErrorTrendCategoryFilterAndInProgress(t *testing.T) {
	env := newTestEnv(t)
	env.grant(stats.ScopeSystem, allDataGrant)
	at := time.Date(2026, 11, 19, 1, 0, 0, 0, cst)
	env.appendEvent(errorEvent(eventSpec{At: at, AppID: "app_alpha", Action: "backup.failed",
		Outcome: audit.OutcomeFailure, ErrorCode: "BACKUP_FAILED"}))
	caller := userCaller(t, testUserID(100))
	result, err := env.service.ErrorTrend(env.ctx, stats.ErrorTrendRequest{
		Caller: caller, ScopeID: stats.ScopeSystem, Window: trendWindow(1),
		Categories: []stats.Category{stats.CategoryFailure, stats.CategoryDenied},
	})
	if err != nil {
		t.Fatalf("错误趋势查询失败: %v", err)
	}
	if len(result.Categories) != 2 {
		t.Fatalf("类别摘要数 = %d，期望 2", len(result.Categories))
	}
	for _, point := range result.Points {
		if point.Category != stats.CategoryFailure && point.Category != stats.CategoryDenied {
			t.Fatalf("类别筛选泄漏了 %s", point.Category)
		}
	}
	last := findTrendPoint(t, result.Points, "2026-11-19", stats.CategoryFailure)
	if last.DataStatus != stats.DataInProgress {
		t.Fatalf("当前桶状态 = %s，期望 in_progress", last.DataStatus)
	}
	// 筛选下未出现的类别给出真实零值，而不是缺行。
	zero := findTrendPoint(t, result.Points, "2026-11-18", stats.CategoryDenied)
	if zero.RawEvents != 0 || zero.DataStatus != stats.DataComplete {
		t.Fatalf("零值点 = %+v，期望 0/complete", zero)
	}
}

// TestErrorTrendRetentionUnknown 验证完全早于保留边界的桶标未知（不是零）。
func TestErrorTrendRetentionUnknown(t *testing.T) {
	env := newTestEnv(t)
	env.grant(stats.ScopeSystem, allDataGrant)
	env.setRetention(1)
	caller := userCaller(t, testUserID(100))
	result, err := env.service.ErrorTrend(env.ctx, stats.ErrorTrendRequest{
		Caller: caller, ScopeID: stats.ScopeSystem, Window: trendWindow(3),
	})
	if err != nil {
		t.Fatalf("错误趋势查询失败: %v", err)
	}
	if result.Completeness.WindowWithinRetention {
		t.Fatalf("窗口不应完全落在保留期内")
	}
	if len(result.Points) != 0 {
		// 没有事件时不会为未出现的类别生成序列；此断言保证不伪造数据。
		t.Fatalf("没有事件时不应生成趋势点: %d", len(result.Points))
	}
	// 显式筛选某类别时必须给出真实零值或未知状态，而不是缺行。
	filtered, err := env.service.ErrorTrend(env.ctx, stats.ErrorTrendRequest{
		Caller: caller, ScopeID: stats.ScopeSystem, Window: trendWindow(3),
		Categories: []stats.Category{stats.CategoryFailure},
	})
	if err != nil {
		t.Fatalf("错误趋势查询失败: %v", err)
	}
	oldest := findTrendPoint(t, filtered.Points, "2026-11-16", stats.CategoryFailure)
	if oldest.DataStatus != stats.DataUnknown || oldest.RawEvents != 0 {
		t.Fatalf("保留期外桶 = %+v，期望 unknown/0", oldest)
	}
}

// TestErrorTrendTruncationStatus 验证来源行数达到上限时所有完整桶降级为 partial。
func TestErrorTrendTruncationStatus(t *testing.T) {
	env := newTestEnv(t)
	env.grant(stats.ScopeSystem, allDataGrant)
	env.appendEvent(errorEvent(eventSpec{At: time.Date(2026, 11, 19, 1, 0, 0, 0, cst),
		AppID: "app_alpha", Action: "backup.failed", Outcome: audit.OutcomeFailure,
		ErrorCode: "BACKUP_FAILED"}))
	env.appendEvent(errorEvent(eventSpec{At: time.Date(2026, 11, 19, 2, 0, 0, 0, cst),
		AppID: "app_alpha", Action: "backup.failed", Outcome: audit.OutcomeFailure,
		ErrorCode: "BACKUP_FAILED"}))
	limited, err := stats.New(stats.Options{
		Store: env.store, Authorizer: env.authorizer, Root: env.root,
		Now: env.nowFn, RetentionDays: 180, MaxFactRows: 1,
	})
	if err != nil {
		t.Fatalf("构造受限服务失败: %v", err)
	}
	caller := userCaller(t, testUserID(100))
	result, err := limited.ErrorTrend(env.ctx, stats.ErrorTrendRequest{
		Caller: caller, ScopeID: stats.ScopeSystem, Window: trendWindow(1),
		Categories: []stats.Category{stats.CategoryFailure},
	})
	if err != nil {
		t.Fatalf("错误趋势查询失败: %v", err)
	}
	if !result.Completeness.SourceTruncated {
		t.Fatalf("来源截断应显式标记")
	}
	for _, point := range result.Points {
		if point.DataStatus == stats.DataComplete {
			t.Fatalf("截断时不应有 complete 点: %+v", point)
		}
	}
}
