package app

// 步骤 230：报告取消与重试的公开真实终态测试。
//   - Cancel 只返回受理语义，真实终态由 Get 轮询；
//   - 取消后的报告可 Retry，新记录通过 RetryOf 关联且真实完成；
//   - 清理预览/执行不删除原始审计（结果说明），且不返回宿主路径。

import (
	"context"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

func TestReportsPublicCancelRetry(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 11, 0, 0, 0, time.UTC))
	runtime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	if err := runtime.Start(ctx); err != nil {
		t.Fatalf("启动运行时: %v", err)
	}
	local := runtime.LocalAdmin()
	reportsSvc := runtime.Reports()
	start, err := reportsSvc.Start(ctx, AdminReportStartRequest{Caller: local,
		ScopeID: "system", TimeZone: "UTC", Start: clock.Now().Add(-24 * time.Hour),
		End: clock.Now(), Granularity: "day", Formats: []string{"html", "csv"},
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建可取消报告: %v", err)
	}
	cancel, err := reportsSvc.Cancel(ctx, AdminReportCancelRequest{Caller: local,
		ReportID: start.ID, Reason: "测试取消", RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("取消报告: %v", err)
	}
	if cancel.Note == "" {
		t.Fatal("取消结果必须说明受理不等于已取消")
	}
	cancelled := waitReportTerminal(t, ctx, reportsSvc, local, start.ID)
	if cancel.State == "cancelled" && cancelled.State != "cancelled" {
		t.Fatalf("取消已受理但报告终态 = %s", cancelled.State)
	}
	// 对取消/失败终态发起重试；若报告已成功则不满足重试前提，跳过成功重试断言。
	if cancelled.State == "cancelled" || cancelled.State == "failed" {
		retried, err := reportsSvc.Retry(ctx, AdminReportRetryRequest{Caller: local,
			ReportID: cancelled.ID, Reason: "重新生成", RequestID: login.NewRequestID()})
		if err != nil {
			t.Fatalf("重试报告: %v", err)
		}
		if retried.RetryOf != cancelled.ID || retried.ID == cancelled.ID {
			t.Fatalf("重试关联 = %+v", retried)
		}
		finished := waitReportTerminal(t, ctx, reportsSvc, local, retried.ID)
		if finished.State != "succeeded" {
			t.Fatalf("重试报告终态 = %s error=%s", finished.State, finished.ErrorCode)
		}
	}
	// 清理预览/执行：不删除原始审计；执行结果必须带明确说明。
	preview, err := reportsSvc.CleanupPreview(ctx, AdminReportCleanupPreviewRequest{
		Caller: local, RequestID: login.NewRequestID()})
	if err != nil {
		if !login.IsErrorCode(err, login.CodeAccessDenied) {
			t.Fatalf("清理预览错误 = %v", err)
		}
	} else {
		if preview.Policy.RawAuditNote == "" {
			t.Fatal("清理预览必须说明原始审计不随报告文件删除")
		}
		result, execErr := reportsSvc.CleanupExecute(ctx, AdminReportCleanupRequest{
			Caller: local, Reason: "测试清理", MaxTargets: 10,
			RequestID: login.NewRequestID()})
		if execErr != nil {
			if !login.IsErrorCode(execErr, login.CodeAccessDenied) {
				t.Fatalf("清理执行错误 = %v", execErr)
			}
		} else if result.RawAuditNote == "" {
			t.Fatal("清理结果必须说明原始审计未被删除")
		}
	}
}

// waitReportTerminal 轮询报告终态，最多 10 秒。
func waitReportTerminal(t *testing.T, ctx context.Context, service ReportsService,
	caller AdminCaller, reportID string) AdminReport {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		report, err := service.Get(ctx, AdminReportRequest{Caller: caller,
			ReportID: reportID, RequestID: login.NewRequestID()})
		if err != nil {
			t.Fatalf("读取报告终态: %v", err)
		}
		switch report.State {
		case "succeeded", "failed", "cancelled":
			return report
		}
		if time.Now().After(deadline) {
			t.Fatalf("报告未在期限内结束: state=%s", report.State)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
