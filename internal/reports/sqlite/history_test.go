package sqlite

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/reports"
)

// TestHistoryRecorderAdapter 验证 reports.HistoryRecorder 适配器把受控历史条目
// 真实写入 SQLite（含超时独立状态、产物引用、操作者），并能按范围读取。
func TestHistoryRecorderAdapter(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	adapter, err := NewHistoryRecorder(store)
	if err != nil {
		t.Fatalf("构造历史适配器失败: %v", err)
	}
	snapshot, _ := json.Marshal(map[string]string{"schema_version": "report.v1"})
	artifacts, _ := json.Marshal([]map[string]any{{"format": "html",
		"sha256": repeatByte('f', 64), "bytes": 1024}})
	record := reports.HistoryRecord{
		ReportID: testReportID(5), Name: "计划报告", Owner: testActor(1),
		ScopeID: reports.ScopeSystem, ScopeKind: "system", Template: "standard",
		State: "timed_out", Formats: []reports.Format{reports.FormatHTML},
		DetailRows: 20, WindowJSON: []byte(`{"time_zone":"Asia/Shanghai"}`),
		SnapshotJSON: snapshot, ArtifactsJSON: artifacts, TaskID: "job_timeout",
		ErrorCode: "TASK_TIMEOUT", FailureReason: "报告生成超时",
		CreatedAt: baseTime, StartedAt: baseTime.Add(time.Minute),
		FinishedAt: baseTime.Add(2 * time.Minute),
		ExpiresAt:  baseTime.Add(24 * time.Hour),
	}
	if err := adapter.RecordReportHistory(ctx, record); err != nil {
		t.Fatalf("写入历史适配器失败: %v", err)
	}
	got, found, err := store.GetHistory(ctx, record.ReportID, AccessScope{AllData: true})
	if err != nil || !found {
		t.Fatalf("读取适配器写入的历史失败: found=%v err=%v", found, err)
	}
	if got.State != "timed_out" || got.ErrorCode != "TASK_TIMEOUT" ||
		got.Owner != record.Owner || string(got.SnapshotJSON) != string(snapshot) ||
		string(got.ArtifactsJSON) != string(artifacts) {
		t.Fatalf("历史适配器字段不一致: %+v", got)
	}
	// 范围裁剪：无范围不可读取适配器写入的历史。
	if _, found, err := store.GetHistory(ctx, record.ReportID, AccessScope{}); err != nil || found {
		t.Fatalf("无范围读取历史 found=%v err=%v，期望不存在", found, err)
	}
	// 非法状态不得写入（避免把取消请求写成终态或写未知状态）。
	bad := record
	bad.ReportID = testReportID(6)
	bad.State = "cancel_requested_ok"
	if err := adapter.RecordReportHistory(ctx, bad); err == nil {
		t.Fatal("非法历史状态未被拒绝")
	}
}

// TestListHistoryScopedOwnerFilter 是回归测试：ListHistory 同时携带数据范围条件
// 与所有者/计划/状态筛选时，参数顺序必须与 WHERE 占位符一致。修复前数据范围参数
// 被放在 args 开头、筛选参数追加其后，而 SQL 把范围条件拼在末尾，导致“范围 +
// 所有者”组合参数错位并静默返回空页（非 root 普通所有者的历史列表受影响）。
func TestListHistoryScopedOwnerFilter(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	own := testActor(1)
	other := testActor(2)
	planID := "sch_" + repeatByte('a', 32)
	record := func(seed byte, owner audit.Actor, scopeID, state string,
		createdAt time.Time) HistoryRecord {
		scopeKind := "app"
		if scopeID == reports.ScopeSystem {
			scopeKind = "system"
		}
		return HistoryRecord{
			ID: testReportID(seed), PlanID: planID, Name: "范围与所有者筛选报告",
			Owner: owner, ScopeID: scopeID, ScopeKind: scopeKind,
			Template: "standard", State: state, Formats: []string{"html"},
			DetailRows: 10, WindowJSON: []byte(`{"time_zone":"UTC"}`),
			ArtifactsJSON: []byte("[]"), CreatedAt: createdAt,
			ExpiresAt: createdAt.Add(24 * time.Hour),
		}
	}
	systemRecord := record(1, own, reports.ScopeSystem, "succeeded", baseTime)
	if err := store.UpsertHistory(ctx, systemRecord); err != nil {
		t.Fatalf("写入系统范围历史失败: %v", err)
	}
	otherRecord := record(2, other, reports.ScopeSystem, "failed", baseTime.Add(time.Minute))
	if err := store.UpsertHistory(ctx, otherRecord); err != nil {
		t.Fatalf("写入其他所有者历史失败: %v", err)
	}
	appRecord := record(3, own, "app_alpha", "failed", baseTime.Add(2*time.Minute))
	if err := store.UpsertHistory(ctx, appRecord); err != nil {
		t.Fatalf("写入应用范围历史失败: %v", err)
	}

	systemScope := AccessScope{ResourceIDs: []string{reports.ScopeSystem}}
	// 核心回归：范围 + 所有者同时筛选必须命中自己的记录，不能静默空页。
	page, err := store.ListHistory(ctx, HistoryQuery{Access: systemScope,
		OwnerType: string(own.Type), OwnerID: own.ID, Limit: 10})
	if err != nil || len(page.Records) != 1 || page.Records[0].ID != systemRecord.ID {
		t.Fatalf("范围+所有者筛选 = %+v err=%v，期望仅命中 %s",
			page.Records, err, systemRecord.ID)
	}
	// 继续叠加计划与状态筛选，参数顺序仍需保持一致。
	page, err = store.ListHistory(ctx, HistoryQuery{Access: systemScope, PlanID: planID,
		State: "succeeded", OwnerType: string(own.Type), OwnerID: own.ID, Limit: 10})
	if err != nil || len(page.Records) != 1 || page.Records[0].ID != systemRecord.ID {
		t.Fatalf("范围+所有者+计划+状态筛选 = %+v err=%v", page.Records, err)
	}
	page, err = store.ListHistory(ctx, HistoryQuery{Access: systemScope, PlanID: planID,
		State: "failed", OwnerType: string(own.Type), OwnerID: own.ID, Limit: 10})
	if err != nil || len(page.Records) != 0 {
		t.Fatalf("错误状态组合应返回空页 = %+v err=%v", page.Records, err)
	}
	// 仅范围筛选：系统范围内两条（不同所有者）都可见。
	page, err = store.ListHistory(ctx, HistoryQuery{Access: systemScope, Limit: 10})
	if err != nil || len(page.Records) != 2 {
		t.Fatalf("仅范围筛选 = %d 条 err=%v，期望 2", len(page.Records), err)
	}
	// 范围不匹配时不得因参数错位误放行。
	otherScope := AccessScope{ResourceIDs: []string{"app_beta"}}
	page, err = store.ListHistory(ctx, HistoryQuery{Access: otherScope,
		OwnerType: string(own.Type), OwnerID: own.ID, Limit: 10})
	if err != nil || len(page.Records) != 0 {
		t.Fatalf("不匹配范围+所有者 = %+v err=%v，期望空页", page.Records, err)
	}
	// 应用范围 + 所有者：命中应用范围记录。
	page, err = store.ListHistory(ctx, HistoryQuery{
		Access:    AccessScope{ResourceIDs: []string{"app_alpha"}},
		OwnerType: string(own.Type), OwnerID: own.ID, Limit: 10})
	if err != nil || len(page.Records) != 1 || page.Records[0].ID != appRecord.ID {
		t.Fatalf("应用范围+所有者筛选 = %+v err=%v", page.Records, err)
	}
	// 全数据范围 + 所有者：两名下记录均可见。
	page, err = store.ListHistory(ctx, HistoryQuery{Access: AccessScope{AllData: true},
		OwnerType: string(own.Type), OwnerID: own.ID, Limit: 10})
	if err != nil || len(page.Records) != 2 {
		t.Fatalf("全范围+所有者筛选 = %d 条 err=%v，期望 2", len(page.Records), err)
	}
}
