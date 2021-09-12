package sqlite

import (
	"context"
	"encoding/json"
	"testing"
	"time"

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
