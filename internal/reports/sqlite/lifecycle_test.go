package sqlite

// 本文件验证 0042 报告生命周期仓储的读取/清理/计划投影适配器（真实临时 SQLite）：
// 数据范围 SQL 过滤、历史数据范围引用往返、清理目标查询与清理状态前进、计划管理
// 读模型的行版本乐观并发。

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/reports"
)

// lifecycleHistoryRecord 构造测试历史记录。
func lifecycleHistoryRecord(id, scopeID string, ownerIndex int,
	state string) HistoryRecord {
	return HistoryRecord{
		ID: id, PlanID: "", Name: "生命周期测试报告",
		Owner: testActor(ownerIndex), ScopeID: scopeID,
		ScopeKind: func() string {
			if scopeID == "system" {
				return "system"
			}
			return "app"
		}(),
		Template: "standard", State: state, Formats: []string{"html"},
		DetailRows: 20, DataScopeJSON: []byte(`{"all":false,"resources":["app_demo1"]}`),
		WindowJSON: []byte(`{"time_zone":"Asia/Shanghai"}`),
		ArtifactsJSON: []byte(`[{"format":"html","name":"report_` + id +
			`.html","bytes":128,"sha256":"` + repeatByte('a', 64) + `"}]`),
		TaskID: "job_1", CreatedAt: baseTime,
		ExpiresAt: baseTime.Add(time.Hour),
	}
}

// TestHistoryReaderContracts 验证受控历史读取、范围过滤、数据范围引用往返与
// 清理目标查询/状态前进。
func TestHistoryReaderContracts(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	history, err := NewHistoryRecorder(store)
	if err != nil {
		t.Fatalf("构造历史适配器失败: %v", err)
	}
	systemRecord := lifecycleHistoryRecord(testReportID(1), "system", 1, "succeeded")
	appRecord := lifecycleHistoryRecord(testReportID(2), "app_demo1", 2, "failed")
	if err := store.UpsertHistory(ctx, systemRecord); err != nil {
		t.Fatalf("写入系统历史失败: %v", err)
	}
	appRecord.ExpiresAt = baseTime.Add(-24 * time.Hour)
	if err := store.UpsertHistory(ctx, appRecord); err != nil {
		t.Fatalf("写入应用历史失败: %v", err)
	}
	// 数据范围 SQL 过滤：只给应用范围时读不到系统记录，也不泄露存在性。
	hidden, hiddenFound, err := history.GetHistory(ctx, systemRecord.ID,
		reports.AccessScope{ResourceIDs: []string{"app_demo1"}})
	if err != nil || hiddenFound || hidden.ReportID != "" {
		t.Fatalf("越权范围读取 = %+v found=%v err=%v，期望不可见", hidden, hiddenFound, err)
	}
	visible, found, err := history.GetHistory(ctx, appRecord.ID,
		reports.AccessScope{ResourceIDs: []string{"app_demo1"}})
	if err != nil || !found || visible.ReportID != appRecord.ID {
		t.Fatalf("范围读取失败: %+v found=%v err=%v", visible, found, err)
	}
	// 生成时数据范围引用往返，供回源时重新判断范围是否被当前权限覆盖。
	if string(visible.DataScopeJSON) != string(appRecord.DataScopeJSON) {
		t.Fatalf("数据范围引用往返 = %s，期望 %s",
			visible.DataScopeJSON, appRecord.DataScopeJSON)
	}
	scopes, err := history.ListHistoryScopeIDs(ctx)
	if err != nil || len(scopes) != 2 || scopes[0] != "app_demo1" || scopes[1] != "system" {
		t.Fatalf("历史范围集合 = %v err=%v", scopes, err)
	}
	// 到期清理目标：只有已过期的应用记录。
	cutoff := baseTime.Add(-time.Hour)
	candidateScopes, err := history.ListCleanupCandidateScopes(ctx, cutoff)
	if err != nil || len(candidateScopes) != 1 || candidateScopes[0] != "app_demo1" {
		t.Fatalf("清理目标范围 = %v err=%v", candidateScopes, err)
	}
	candidates, err := history.ListCleanupCandidates(ctx,
		reports.AccessScope{ResourceIDs: []string{"app_demo1"}}, cutoff, 10)
	if err != nil || len(candidates) != 1 || candidates[0].ReportID != appRecord.ID {
		t.Fatalf("清理目标 = %+v err=%v", candidates, err)
	}
	noCandidates, err := history.ListCleanupCandidates(ctx,
		reports.AccessScope{ResourceIDs: []string{"app_other"}}, cutoff, 10)
	if err != nil || len(noCandidates) != 0 {
		t.Fatalf("无权清理目标 = %+v err=%v，期望空", noCandidates, err)
	}
	// 清理状态只前进：none→pending→cleaned，已清理后不再接受回退。
	if err := history.MarkHistoryCleanup(ctx, appRecord.ID, "pending"); err != nil {
		t.Fatalf("标记待清理失败: %v", err)
	}
	if err := history.MarkHistoryCleanup(ctx, appRecord.ID, "cleaned"); err != nil {
		t.Fatalf("标记已清理失败: %v", err)
	}
	if err := history.MarkHistoryCleanup(ctx, appRecord.ID, "pending"); !errors.Is(err, reports.ErrConflict) {
		t.Fatalf("清理状态回退错误 = %v，期望 ErrConflict", err)
	}
	cleaned, found, _ := history.GetHistory(ctx, appRecord.ID,
		reports.AccessScope{AllData: true})
	if !found || cleaned.CleanupState != "cleaned" {
		t.Fatalf("清理状态 = %q found=%v，期望 cleaned", cleaned.CleanupState, found)
	}
	// 列表筛选与游标分页沿用仓储契约（这里只验证状态筛选生效）。
	page, err := history.ListHistory(ctx, reports.HistoryQuery{
		Access: reports.AccessScope{AllData: true}, State: "succeeded", Limit: 10})
	if err != nil || len(page.Records) != 1 || page.Records[0].ReportID != systemRecord.ID {
		t.Fatalf("历史状态筛选 = %+v err=%v", page, err)
	}
}

// TestPlanProjectionAdapter 验证报告计划管理读模型的建立、行版本并发与启停/删除。
func TestPlanProjectionAdapter(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	projections, err := NewPlanProjectionStore(store)
	if err != nil {
		t.Fatalf("构造计划投影适配器失败: %v", err)
	}
	record := testPlan()
	plan := planProjectionFromRecord(record)
	created, err := projections.CreatePlanProjection(ctx, plan)
	if err != nil {
		t.Fatalf("创建计划投影失败: %v", err)
	}
	if created.Version != 1 || created.ID != plan.ID ||
		len(created.Formats) != len(plan.Formats) ||
		len(created.Categories) != len(plan.Categories) {
		t.Fatalf("创建结果 = %+v，期望版本 1 且配置完整", created)
	}
	if _, err := projections.CreatePlanProjection(ctx, plan); !errors.Is(err, reports.ErrConflict) {
		t.Fatalf("重复创建错误 = %v，期望 ErrConflict", err)
	}
	// 行版本 CAS：旧版本拒绝覆盖。
	stale := created
	stale.Name = "被覆盖的名称"
	if _, err := projections.UpdatePlanProjection(ctx, stale, 99); !errors.Is(err, reports.ErrConflict) {
		t.Fatalf("过期版本更新错误 = %v，期望 ErrConflict", err)
	}
	update := created
	update.Name = "更新后的计划"
	updated, err := projections.UpdatePlanProjection(ctx, update, created.Version)
	if err != nil || updated.Version != created.Version+1 || updated.Name != "更新后的计划" {
		t.Fatalf("更新计划投影 = %+v err=%v", updated, err)
	}
	// 启停同样推进行版本，编辑必须用重新读取后的版本。
	if err := projections.SetPlanProjectionEnabled(ctx, plan.ID, false); err != nil {
		t.Fatalf("停用计划投影失败: %v", err)
	}
	afterToggle, found, err := projections.GetPlanProjection(ctx, plan.ID)
	if err != nil || !found || afterToggle.Enabled ||
		afterToggle.Version != updated.Version+1 {
		t.Fatalf("启停后投影 = %+v found=%v err=%v", afterToggle, found, err)
	}
	ids, err := projections.ListPlanProjectionIDs(ctx)
	if err != nil || len(ids) != 1 || ids[0] != plan.ID {
		t.Fatalf("投影编号枚举 = %v err=%v", ids, err)
	}
	if err := projections.DeletePlanProjection(ctx, plan.ID); err != nil {
		t.Fatalf("删除计划投影失败: %v", err)
	}
	if _, found, _ := projections.GetPlanProjection(ctx, plan.ID); found {
		t.Fatal("删除后仍能读取计划投影")
	}
	if err := projections.DeletePlanProjection(ctx, plan.ID); !errors.Is(err, reports.ErrNotFound) {
		t.Fatalf("重复删除错误 = %v，期望 ErrNotFound", err)
	}
}
