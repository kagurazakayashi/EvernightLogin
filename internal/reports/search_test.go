package reports

// 步骤 263：报告历史与报告计划列表有界字面搜索。历史搜索在可见范围过滤后执行，
// 游标指纹绑定搜索条件；计划搜索先限定可见范围再过滤显示名。

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
)

// TestHistoryListSearchAndCursorBinding 验收历史报告名称搜索与游标绑定搜索条件。
func TestHistoryListSearchAndCursorBinding(t *testing.T) {
	now := baseTime
	env, _ := newLifecycleEnv(t, &now)
	ctx := context.Background()
	env.grantAll(testUserID(1), ScopeSystem, stats.ScopeGrant{Allowed: true, AllData: true})
	// 默认历史名称为“统计报告”；创建两份便于分页。
	for index := 0; index < 2; index++ {
		if _, _ = env.startAndGenerate(t, env.startRequest(t)); false {
			_ = index
		}
	}
	caller := testCaller(t, 1)
	page, err := env.service.HistoryList(ctx, HistoryListRequest{
		Caller: caller, Limit: 10, Search: "统计"})
	if err != nil {
		t.Fatalf("历史搜索失败: %v", err)
	}
	if len(page.Records) != 2 {
		t.Fatalf("历史搜索结果数 = %d，期望 2", len(page.Records))
	}
	// 无匹配与通配符按字面。
	if none, err := env.service.HistoryList(ctx, HistoryListRequest{
		Caller: caller, Limit: 10, Search: "%"}); err != nil || len(none.Records) != 0 {
		t.Fatalf("历史通配符/无匹配结果 = %+v err=%v", none, err)
	}
	// 空搜索保持原列表。
	if all, err := env.service.HistoryList(ctx, HistoryListRequest{
		Caller: caller, Limit: 10, Search: "  "}); err != nil || len(all.Records) != 2 {
		t.Fatalf("空搜索结果 = %+v err=%v", all, err)
	}
	// 非法字段/超长拒绝。
	if _, err := env.service.HistoryList(ctx, HistoryListRequest{
		Caller: caller, Limit: 10, Search: "x",
		SearchFields: []HistorySearchField{"failure_reason"},
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("非法搜索字段错误 = %v，期望 ErrInvalidRequest", err)
	}
	if _, err := env.service.HistoryList(ctx, HistoryListRequest{
		Caller: caller, Limit: 10, Search: strings.Repeat("a", 65),
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("超长搜索错误 = %v，期望 ErrInvalidRequest", err)
	}
	// 游标绑定搜索条件：不同搜索复用旧游标拒绝，同搜索可继续翻页。
	first, err := env.service.HistoryList(ctx, HistoryListRequest{
		Caller: caller, Limit: 1, Search: "统计"})
	if err != nil || len(first.Records) != 1 || first.NextCursor == "" {
		t.Fatalf("历史搜索第一页 = %+v err=%v", first, err)
	}
	if _, err := env.service.HistoryList(ctx, HistoryListRequest{
		Caller: caller, Limit: 1, Search: "另一个搜索", Cursor: first.NextCursor,
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("换搜索复用游标错误 = %v，期望 ErrInvalidRequest", err)
	}
	second, err := env.service.HistoryList(ctx, HistoryListRequest{
		Caller: caller, Limit: 1, Search: "统计", Cursor: first.NextCursor})
	if err != nil || len(second.Records) != 1 || second.Records[0].ID == first.Records[0].ID {
		t.Fatalf("同搜索游标第二页 = %+v err=%v", second, err)
	}
}

// TestPlanListPageSearch 验收报告计划列表按显示名搜索（可见范围过滤后）。
func TestPlanListPageSearch(t *testing.T) {
	now := baseTime
	env := newPlanTestEnv(t, &now)
	ctx := context.Background()
	if _, err := env.plans.Create(ctx, newPlanRequest(env.caller)); err != nil {
		t.Fatalf("创建计划失败: %v", err)
	}
	other := newPlanRequest(env.caller)
	other.Name = "每周安全摘要"
	if _, err := env.plans.Create(ctx, other); err != nil {
		t.Fatalf("创建第二个计划失败: %v", err)
	}
	list := func(request PlanListRequest) PlanListResult {
		t.Helper()
		request.Caller = env.caller
		result, err := env.plans.ListPage(ctx, request)
		if err != nil {
			t.Fatalf("ListPage(%+v): %v", request.Search, err)
		}
		return result
	}
	if result := list(PlanListRequest{Search: "安全"}); len(result.Plans) != 2 {
		t.Fatalf("计划名称搜索结果数 = %d，期望 2", len(result.Plans))
	}
	if result := list(PlanListRequest{Search: "每周"}); len(result.Plans) != 1 ||
		result.Plans[0].Name != "每周安全摘要" {
		t.Fatalf("计划精确子串结果 = %+v", result.Plans)
	}
	if result := list(PlanListRequest{Search: "不存在"}); len(result.Plans) != 0 {
		t.Fatalf("计划无匹配结果 = %+v", result.Plans)
	}
	// 空搜索保持原列表。
	if result := list(PlanListRequest{Search: "  "}); len(result.Plans) != 2 {
		t.Fatalf("计划空搜索结果数 = %d，期望 2", len(result.Plans))
	}
	// 非法字段/超长拒绝。
	if _, err := env.plans.ListPage(ctx, PlanListRequest{Caller: env.caller,
		Search: "x", SearchFields: []string{"payload"}}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("计划非法搜索字段错误 = %v，期望 ErrInvalidRequest", err)
	}
	if _, err := env.plans.ListPage(ctx, PlanListRequest{Caller: env.caller,
		Search: strings.Repeat("a", 65)}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("计划超长搜索错误 = %v，期望 ErrInvalidRequest", err)
	}
}
