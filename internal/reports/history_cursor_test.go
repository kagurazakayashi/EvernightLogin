package reports

// 步骤 218：报告历史稳定游标测试。
//   - 相同 created_at 的多份历史按报告 ID 稳定分页，两页无重复/无遗漏；
//   - 服务端返回 NextCursor，且游标绑定 plan_id/state 筛选，换筛选复用拒绝；
//   - 游标与旧 before_* 参数互斥；非法游标 REQ_INVALID；
//   - HasMore=false 时不返回游标。

import (
	"context"
	"errors"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
)

func TestHistoryCursorPaginationStableAndBound(t *testing.T) {
	now := baseTime
	env, history := newLifecycleEnv(t, &now)
	ctx := context.Background()
	env.grantAll(testUserID(1), ScopeSystem, stats.ScopeGrant{Allowed: true, AllData: true})
	reportIDs := make([]string, 0, 3)
	for index := 0; index < 3; index++ {
		// 固定时钟使三份报告 CreatedAt 完全相同，验证 ID 决胜的游标稳定性。
		reportID, _ := env.startAndGenerate(t, env.startRequest(t))
		reportIDs = append(reportIDs, reportID)
	}
	if len(history.order) != 3 {
		t.Fatalf("历史记录数 = %d，期望 3", len(history.order))
	}
	first, err := env.service.HistoryList(ctx, HistoryListRequest{
		Caller: testCaller(t, 1), Limit: 2})
	if err != nil || len(first.Records) != 2 || !first.HasMore || first.NextCursor == "" {
		t.Fatalf("历史第一页 = %+v err=%v", first, err)
	}
	second, err := env.service.HistoryList(ctx, HistoryListRequest{
		Caller: testCaller(t, 1), Limit: 2, Cursor: first.NextCursor})
	if err != nil || len(second.Records) != 1 || second.HasMore || second.NextCursor != "" {
		t.Fatalf("历史第二页 = %+v err=%v", second, err)
	}
	seen := map[string]bool{}
	for _, record := range append(first.Records, second.Records...) {
		if seen[record.ID] {
			t.Fatalf("游标分页重复报告 %s", record.ID)
		}
		seen[record.ID] = true
	}
	for _, expected := range reportIDs {
		if !seen[expected] {
			t.Fatalf("游标分页遗漏报告 %s", expected)
		}
	}
	// 旧游标 + 不同筛选/排序复用拒绝。
	if _, err := env.service.HistoryList(ctx, HistoryListRequest{
		Caller: testCaller(t, 1), Limit: 2, Cursor: first.NextCursor,
		PlanID: "plan_other"}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("跨筛选游标错误 = %v，期望 ErrInvalidRequest", err)
	}
	if _, err := env.service.HistoryList(ctx, HistoryListRequest{
		Caller: testCaller(t, 1), Limit: 2, Cursor: first.NextCursor,
		State: StateFailed}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("跨状态游标错误 = %v，期望 ErrInvalidRequest", err)
	}
	// 非法游标与新旧参数混用。
	for _, request := range []HistoryListRequest{
		{Caller: testCaller(t, 1), Limit: 2, Cursor: "not-a-cursor"},
		{Caller: testCaller(t, 1), Limit: 2, Cursor: first.NextCursor,
			BeforeCreatedAt: baseTime, BeforeID: reportIDs[0]},
	} {
		if _, err := env.service.HistoryList(ctx, request); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("非法历史游标请求错误 = %v，期望 ErrInvalidRequest", err)
		}
	}
}
