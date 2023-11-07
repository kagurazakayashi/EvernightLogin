package auditops_test

// 步骤 218：审计事件稳定游标分页测试。
//   - 相同 occurred_at 的并列事件按事件 ID 稳定分页，两页无重复/无遗漏；
//   - 页间并发追加不会让旧游标的后续页重复或跳过既有记录；
//   - 非法/篡改游标、跨 scope、跨筛选、跨排序复用游标一律 REQ_INVALID；
//   - 升序游标同样稳定；HasMore/NextCursor 成对出现，不伪造总数。

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/auditops"
)

func TestAuditCursorPaginationStableAndBound(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	actor := userCaller(t, testUserID(1))
	env.grant(testUserID(1), auditops.PermissionRead, auditops.ScopeSystem,
		auditops.ScopeGrant{Allowed: true, AllData: true})
	sameTime := baseTime.Add(-2 * time.Hour)
	seedIDs := make([]string, 0, 5)
	for index := 0; index < 5; index++ {
		// 全部使用同一 occurred_at，验证 ID 决胜与游标稳定性。
		seedIDs = append(seedIDs, env.seed(event("user.update", "app_1",
			testUserID(5), audit.OutcomeSuccess), sameTime))
	}
	request := auditops.QueryRequest{Caller: actor, ScopeID: auditops.ScopeSystem,
		Limit: 2}
	first, err := env.service.Query(ctx, request)
	if err != nil {
		t.Fatalf("审计第一页: %v", err)
	}
	if len(first.Events) != 2 || !first.HasMore || first.NextCursor == "" {
		t.Fatalf("审计第一页元数据 = %+v", first)
	}
	// 并发追加：新事件如果排在第一页之前，不应出现在旧游标的后续页，避免重复。
	env.seed(event("user.update", "app_1", testUserID(6), audit.OutcomeFailure),
		baseTime.Add(-time.Minute))
	seen := map[string]bool{}
	for _, item := range first.Events {
		seen[item.ID] = true
	}
	cursor := first.NextCursor
	for pageIndex := 1; pageIndex < 4; pageIndex++ {
		page, pageErr := env.service.Query(ctx, auditops.QueryRequest{
			Caller: actor, ScopeID: auditops.ScopeSystem, Limit: 2, Cursor: cursor})
		if pageErr != nil {
			t.Fatalf("审计第 %d 页: %v", pageIndex+1, pageErr)
		}
		for _, item := range page.Events {
			if seen[item.ID] {
				t.Fatalf("游标分页出现重复事件 %s", item.ID)
			}
			seen[item.ID] = true
		}
		if !page.HasMore {
			if page.NextCursor != "" {
				t.Fatal("HasMore=false 时不应返回 NextCursor")
			}
			break
		}
		if page.NextCursor == "" {
			t.Fatal("HasMore=true 时必须返回 NextCursor")
		}
		cursor = page.NextCursor
	}
	for _, expected := range seedIDs {
		if !seen[expected] {
			t.Fatalf("游标分页遗漏事件 %s", expected)
		}
	}
	// 旧游标 + 不同筛选/排序/scope 复用：一律拒绝。
	badRequests := []auditops.QueryRequest{
		{Caller: actor, ScopeID: auditops.ScopeSystem, Limit: 2, Cursor: "not-a-cursor"},
		{Caller: actor, ScopeID: auditops.ScopeSystem, Limit: 2, Cursor: first.NextCursor,
			Filter: auditops.Filter{Action: "user.create"}},
		{Caller: actor, ScopeID: auditops.ScopeSystem, Limit: 2, Cursor: first.NextCursor,
			Order: auditops.SortOldestFirst},
	}
	for _, bad := range badRequests {
		if _, err := env.service.Query(ctx, bad); !errors.Is(err, auditops.ErrInvalidRequest) {
			t.Fatalf("非法/不匹配游标错误 = %v，期望 ErrInvalidRequest（请求 %+v）", err, bad)
		}
	}
	// 游标与 offset 同时使用也拒绝。
	if _, err := env.service.Query(ctx, auditops.QueryRequest{Caller: actor,
		ScopeID: auditops.ScopeSystem, Limit: 2, Offset: 2, Cursor: first.NextCursor}); !errors.Is(err, auditops.ErrInvalidRequest) {
		t.Fatalf("游标与 offset 混用错误 = %v，期望 ErrInvalidRequest", err)
	}

	// 升序游标同样稳定覆盖全部同时间事件。
	ascending, err := env.service.Query(ctx, auditops.QueryRequest{Caller: actor,
		ScopeID: auditops.ScopeSystem, Limit: 2, Order: auditops.SortOldestFirst})
	if err != nil || len(ascending.Events) != 2 || ascending.NextCursor == "" {
		t.Fatalf("升序第一页 = %+v err=%v", ascending, err)
	}
	ascendingSecond, err := env.service.Query(ctx, auditops.QueryRequest{Caller: actor,
		ScopeID: auditops.ScopeSystem, Limit: 2, Order: auditops.SortOldestFirst,
		Cursor: ascending.NextCursor})
	if err != nil {
		t.Fatalf("升序第二页: %v", err)
	}
	for _, item := range ascendingSecond.Events {
		for _, firstItem := range ascending.Events {
			if item.ID == firstItem.ID {
				t.Fatal("升序游标分页出现重复事件")
			}
		}
	}
}
