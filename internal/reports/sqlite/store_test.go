package sqlite

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/reports"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// baseTime 是测试固定时钟。
var baseTime = time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)

// newStore 构造隔离的临时 SQLite 仓储；数据库与迁移在测试结束自动清理。
func newStore(t *testing.T) *Store {
	t.Helper()
	ctx := context.Background()
	raw, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(
		filepath.Join(t.TempDir(), "report-lifecycle.db")))
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
	store, err := New(raw)
	if err != nil {
		t.Fatalf("构造报告仓储失败: %v", err)
	}
	return store
}

// testActor 构造用户审计身份。
func testActor(index int) audit.Actor {
	return audit.Actor{Type: audit.ActorUser,
		ID: "usr_0000000000000000000000000000000" + string(rune('0'+index))}
}

// testReportID 生成格式合法的报告编号。
func testReportID(seed byte) string {
	return "rpt_" + repeatByte("0123456789abcdef"[seed%16], 32)
}

// repeatByte 返回重复字符组成的字符串。
func repeatByte(value byte, count int) string {
	buffer := make([]byte, count)
	for index := range buffer {
		buffer[index] = value
	}
	return string(buffer)
}

// testPlan 构造合法的计划记录。
func testPlan() PlanRecord {
	return PlanRecord{
		ID: "sch_" + repeatByte('a', 32), Name: "每日安全报告",
		Owner: testActor(1), ExecutionActor: testActor(1),
		ScopeID: reports.ScopeSystem, ScopeKind: "system", Template: "standard",
		ScheduleType: "daily", Expression: "09:00", TimeZone: "Asia/Shanghai",
		Granularity: "day", WindowDays: 1, Categories: []string{"failure"},
		TrendMetric: "raw_events", Formats: []string{"html", "json"},
		DetailRows: 20, MissedPolicy: "skip", MaxCatchUp: 5,
		TimeoutSeconds: 600, MaxAttempts: 1, Enabled: true,
		CreatedAt: baseTime, UpdatedAt: baseTime,
	}
}

// TestPlanLifecycle 验证计划 CRUD、版本乐观并发、过滤与分页。
func TestPlanLifecycle(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	plan := testPlan()
	created, err := store.CreatePlan(ctx, plan)
	if err != nil {
		t.Fatalf("创建计划失败: %v", err)
	}
	if created.Version != 1 || !created.Enabled {
		t.Fatalf("创建后版本 = %d enabled=%v，期望 1/true", created.Version, created.Enabled)
	}
	// 重复编号返回冲突，不静默覆盖。
	if _, err := store.CreatePlan(ctx, plan); !errors.Is(err, reports.ErrConflict) {
		t.Fatalf("重复编号错误 = %v，期望 ErrConflict", err)
	}
	got, found, err := store.GetPlan(ctx, plan.ID, AccessScope{AllData: true})
	if err != nil || !found {
		t.Fatalf("读取计划失败: found=%v err=%v", found, err)
	}
	if got.Name != plan.Name || len(got.Formats) != 2 || got.Owner != plan.Owner {
		t.Fatalf("计划读取字段不一致: %+v", got)
	}
	// 版本更新：旧版本冲突，新版本成功并递增。
	updated := got
	updated.Name = "每周安全报告"
	updated.ScheduleType = "weekly"
	updated.Expression = "MON 09:00"
	if _, err := store.UpdatePlan(ctx, updated, 99); !errors.Is(err, reports.ErrConflict) {
		t.Fatalf("旧版本更新错误 = %v，期望 ErrConflict", err)
	}
	afterUpdate, err := store.UpdatePlan(ctx, updated, got.Version)
	if err != nil || afterUpdate.Version != 2 || afterUpdate.Name != "每周安全报告" {
		t.Fatalf("更新计划失败: %+v err=%v", afterUpdate, err)
	}
	// 启停切换：旧版本冲突，新版本成功。
	if _, err := store.SetPlanEnabled(ctx, plan.ID, false, 1, baseTime.Add(time.Hour)); !errors.Is(err, reports.ErrConflict) {
		t.Fatalf("旧版本启停错误 = %v，期望 ErrConflict", err)
	}
	paused, err := store.SetPlanEnabled(ctx, plan.ID, false, afterUpdate.Version, baseTime.Add(time.Hour))
	if err != nil || paused.Enabled || paused.Version != 3 {
		t.Fatalf("停用计划失败: %+v err=%v", paused, err)
	}
	// 列表过滤：启用状态、范围、所有者和分页上限。
	enabled := false
	list, err := store.ListPlans(ctx, PlanQuery{Access: AccessScope{AllData: true},
		Enabled: &enabled})
	if err != nil || len(list) != 1 || list[0].Enabled {
		t.Fatalf("按停用状态列表失败: len=%d err=%v", len(list), err)
	}
	list, err = store.ListPlans(ctx, PlanQuery{Access: AccessScope{AllData: true},
		OwnerType: "user", OwnerID: testActor(9).ID})
	if err != nil || len(list) != 0 {
		t.Fatalf("按其他所有者列表 len=%d err=%v，期望 0", len(list), err)
	}
	// 删除：旧版本冲突，正确版本成功；删除后不可读。
	if err := store.DeletePlan(ctx, plan.ID, 1); !errors.Is(err, reports.ErrConflict) {
		t.Fatalf("旧版本删除错误 = %v，期望 ErrConflict", err)
	}
	if err := store.DeletePlan(ctx, plan.ID, paused.Version); err != nil {
		t.Fatalf("删除计划失败: %v", err)
	}
	if _, found, err := store.GetPlan(ctx, plan.ID, AccessScope{AllData: true}); err != nil || found {
		t.Fatalf("删除后读取 found=%v err=%v，期望不存在", found, err)
	}
}

// TestHistoryLifecycle 验证历史写入/状态更新/快照保留/列表分页与筛选。
func TestHistoryLifecycle(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	window, _ := json.Marshal(map[string]string{"time_zone": "Asia/Shanghai"})
	snapshot, _ := json.Marshal(map[string]string{"schema_version": "report.v1"})
	artifacts, _ := json.Marshal([]map[string]any{{"format": "html",
		"sha256": repeatByte('f', 64), "bytes": 1024}})
	record := HistoryRecord{
		ID: testReportID(1), PlanID: "sch_" + repeatByte('a', 32),
		Name: "每日安全报告", Owner: testActor(1),
		ScopeID: reports.ScopeSystem, ScopeKind: "system", Template: "standard",
		State: "queued", Formats: []string{"html", "json"},
		Categories: []string{"failure"}, TrendMetric: "raw_events", DetailRows: 20,
		WindowJSON: window, SnapshotJSON: []byte("{}"), ArtifactsJSON: []byte("[]"),
		TaskID: "job_1", RequestID: "req_1", CreatedAt: baseTime,
		ExpiresAt: baseTime.Add(24 * time.Hour), RetentionUntil: baseTime.AddDate(0, 0, 30),
	}
	if err := store.UpsertHistory(ctx, record); err != nil {
		t.Fatalf("写入历史失败: %v", err)
	}
	// 状态推进：running → succeeded，快照与产物按终态写入。
	record.State = "running"
	record.StartedAt = baseTime.Add(time.Minute)
	if err := store.UpsertHistory(ctx, record); err != nil {
		t.Fatalf("更新运行状态失败: %v", err)
	}
	record.State = "succeeded"
	record.FinishedAt = baseTime.Add(2 * time.Minute)
	record.SnapshotJSON = snapshot
	record.ArtifactsJSON = artifacts
	if err := store.UpsertHistory(ctx, record); err != nil {
		t.Fatalf("更新完成状态失败: %v", err)
	}
	got, found, err := store.GetHistory(ctx, record.ID, AccessScope{AllData: true})
	if err != nil || !found {
		t.Fatalf("读取历史失败: found=%v err=%v", found, err)
	}
	if got.State != "succeeded" || got.PlanID != record.PlanID ||
		string(got.SnapshotJSON) != string(snapshot) ||
		string(got.ArtifactsJSON) != string(artifacts) {
		t.Fatalf("历史终态字段不一致: %+v", got)
	}
	if got.StartedAt.IsZero() || got.FinishedAt.IsZero() ||
		!got.ExpiresAt.Equal(record.ExpiresAt) || !got.RetentionUntil.Equal(record.RetentionUntil) {
		t.Fatalf("历史时间字段丢失: %+v", got)
	}
	// 乱序写入不得回退已完成终态：迟到的取消请求不能把 succeeded 改回进行中。
	record.State = "cancel_requested"
	if err := store.UpsertHistory(ctx, record); err != nil {
		t.Fatalf("写入迟到取消请求失败: %v", err)
	}
	if got, _, _ := store.GetHistory(ctx, record.ID, AccessScope{AllData: true}); got.State != "succeeded" {
		t.Fatalf("已完成终态被迟到状态覆盖: %q", got.State)
	}
	// 取消请求与实际取消是两个不同状态，正常的前进顺序必须保留。
	cancelRecord := record
	cancelRecord.ID = testReportID(3)
	cancelRecord.State = "running"
	cancelRecord.CreatedAt = baseTime
	cancelRecord.FinishedAt = time.Time{}
	if err := store.UpsertHistory(ctx, cancelRecord); err != nil {
		t.Fatalf("写入取消用例初始状态失败: %v", err)
	}
	cancelRecord.State = "cancel_requested"
	if err := store.UpsertHistory(ctx, cancelRecord); err != nil {
		t.Fatalf("更新取消请求状态失败: %v", err)
	}
	if got, _, _ := store.GetHistory(ctx, cancelRecord.ID, AccessScope{AllData: true}); got.State != "cancel_requested" {
		t.Fatalf("取消请求状态 = %q", got.State)
	}
	cancelRecord.State = "cancelled"
	cancelRecord.FinishedAt = baseTime.Add(5 * time.Minute)
	if err := store.UpsertHistory(ctx, cancelRecord); err != nil {
		t.Fatalf("更新取消终态失败: %v", err)
	}
	if got, _, _ := store.GetHistory(ctx, cancelRecord.ID, AccessScope{AllData: true}); got.State != "cancelled" {
		t.Fatalf("取消终态 = %q", got.State)
	}
	// 追加第二条历史，验证倒序与游标分页。
	second := record
	second.ID = testReportID(2)
	second.State = "failed"
	second.ErrorCode = "REPORT_GENERATION_FAILED"
	second.CreatedAt = baseTime.Add(3 * time.Minute)
	second.StartedAt = second.CreatedAt.Add(10 * time.Second)
	second.FinishedAt = second.CreatedAt.Add(30 * time.Second)
	if err := store.UpsertHistory(ctx, second); err != nil {
		t.Fatalf("写入第二条历史失败: %v", err)
	}
	page, err := store.ListHistory(ctx, HistoryQuery{Access: AccessScope{AllData: true},
		Limit: 1})
	if err != nil || len(page.Records) != 1 || !page.HasMore {
		t.Fatalf("分页第一页 = %d, hasMore=%v err=%v", len(page.Records), page.HasMore, err)
	}
	if page.Records[0].ID != second.ID {
		t.Fatalf("分页首条 = %s，期望最新记录 %s", page.Records[0].ID, second.ID)
	}
	next, err := store.ListHistory(ctx, HistoryQuery{Access: AccessScope{AllData: true},
		Limit: 10, BeforeCreatedAt: page.Records[0].CreatedAt,
		BeforeID: page.Records[0].ID})
	// 第二页包含同一创建时刻的两条（取消用例与首条），按编号倒序稳定排序。
	if err != nil || len(next.Records) != 2 || next.Records[0].ID != cancelRecord.ID ||
		next.Records[1].ID != record.ID {
		t.Fatalf("分页第二页 = %+v err=%v", next.Records, err)
	}
	// 按状态与计划筛选。
	page, err = store.ListHistory(ctx, HistoryQuery{Access: AccessScope{AllData: true},
		PlanID: record.PlanID, State: "failed"})
	if err != nil || len(page.Records) != 1 || page.Records[0].ID != second.ID {
		t.Fatalf("按状态/计划筛选 = %+v err=%v", page.Records, err)
	}
}

// TestAccessScopeDeniesOutOfScope 验证数据范围裁剪在 SQL 层生效：无权范围既不
// 返回列表也不返回按编号读取，不泄露对象存在性；合法性错误与不存在区分。
func TestAccessScopeDeniesOutOfScope(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	plan := testPlan()
	plan.ScopeID = "app_alpha"
	plan.ScopeKind = "app"
	if _, err := store.CreatePlan(ctx, plan); err != nil {
		t.Fatalf("创建应用范围计划失败: %v", err)
	}
	record := HistoryRecord{
		ID: testReportID(3), Name: "应用报告", Owner: testActor(1),
		ScopeID: "app_alpha", ScopeKind: "app", Template: "standard",
		State: "succeeded", Formats: []string{"html"}, DetailRows: 10,
		WindowJSON: []byte("{}"), ArtifactsJSON: []byte("[]"),
		CreatedAt: baseTime,
	}
	if err := store.UpsertHistory(ctx, record); err != nil {
		t.Fatalf("写入应用历史失败: %v", err)
	}
	// 空数据范围：列表为空、按编号不可读。
	if plans, err := store.ListPlans(ctx, PlanQuery{Access: AccessScope{}}); err != nil || len(plans) != 0 {
		t.Fatalf("空范围计划列表 = %d err=%v，期望 0", len(plans), err)
	}
	if _, found, err := store.GetPlan(ctx, plan.ID, AccessScope{}); err != nil || found {
		t.Fatalf("空范围读取计划 found=%v err=%v，期望不存在", found, err)
	}
	page, err := store.ListHistory(ctx, HistoryQuery{Access: AccessScope{}})
	if err != nil || len(page.Records) != 0 {
		t.Fatalf("空范围历史列表 = %d err=%v，期望 0", len(page.Records), err)
	}
	if _, found, err := store.GetHistory(ctx, record.ID, AccessScope{}); err != nil || found {
		t.Fatalf("空范围读取历史 found=%v err=%v，期望不存在", found, err)
	}
	// 范围不含目标应用：同样不可见，不能靠猜编号跨应用读取。
	other := AccessScope{ResourceIDs: []string{"app_beta"}}
	if _, found, _ := store.GetPlan(ctx, plan.ID, other); found {
		t.Fatal("跨应用读取计划未被拒绝")
	}
	if _, found, _ := store.GetHistory(ctx, record.ID, other); found {
		t.Fatal("跨应用读取历史未被拒绝")
	}
	// 范围内可读。
	within := AccessScope{ResourceIDs: []string{"app_alpha"}}
	if _, found, err := store.GetHistory(ctx, record.ID, within); err != nil || !found {
		t.Fatalf("范围内读取历史失败: found=%v err=%v", found, err)
	}
	// 编号格式非法与不存在区分：非法格式返回请求错误而不是 NotFound。
	if _, _, err := store.GetHistory(ctx, "../etc", AccessScope{AllData: true}); !errors.Is(err, reports.ErrInvalidRequest) {
		t.Fatalf("非法报告编号错误 = %v，期望 ErrInvalidRequest", err)
	}
	if _, found, err := store.GetHistory(ctx, testReportID(9), AccessScope{AllData: true}); err != nil || found {
		t.Fatalf("不存在报告 found=%v err=%v，期望不存在", found, err)
	}
}

// TestPlanDeletedHistoryKept 验证删除计划不级联删除历史记录。
func TestPlanDeletedHistoryKept(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	plan := testPlan()
	created, err := store.CreatePlan(ctx, plan)
	if err != nil {
		t.Fatalf("创建计划失败: %v", err)
	}
	record := HistoryRecord{
		ID: testReportID(4), PlanID: created.ID, Name: "计划报告",
		Owner: testActor(1), ScopeID: reports.ScopeSystem, ScopeKind: "system",
		Template: "standard", State: "succeeded", Formats: []string{"html"},
		DetailRows: 10, WindowJSON: []byte("{}"), ArtifactsJSON: []byte("[]"),
		CreatedAt: baseTime,
	}
	if err := store.UpsertHistory(ctx, record); err != nil {
		t.Fatalf("写入历史失败: %v", err)
	}
	if err := store.DeletePlan(ctx, created.ID, created.Version); err != nil {
		t.Fatalf("删除计划失败: %v", err)
	}
	if _, found, err := store.GetHistory(ctx, record.ID, AccessScope{AllData: true}); err != nil || !found {
		t.Fatalf("计划删除后历史丢失: found=%v err=%v", found, err)
	}
}
