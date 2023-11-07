package sqlite_test

// 步骤 218：后台任务列表稳定游标与筛选测试。
//   - 相同 created_at 的任务按 ID 稳定分页，两页无重复/无遗漏；
//   - 游标绑定筛选（state/kind/request_id），换筛选复用拒绝；
//   - 非法游标与越界 limit 返回 ErrInvalidRequest；
//   - 过滤条件在存储层 WHERE 生效。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

func TestListJobsCursorStableAndFiltered(t *testing.T) {
	raw := openTestDatabase(t)
	store := newTaskStore(t, raw)
	ctx := context.Background()
	base := time.Date(2026, 11, 25, 6, 0, 0, 0, time.UTC)
	actor := audit.Actor{Type: audit.ActorUser, ID: "usr_000000000000000000000000000000a1"}
	ids := make([]string, 0, 5)
	for index := 0; index < 5; index++ {
		id := fmt.Sprintf("job_%032x", index+1)
		if _, err := store.Enqueue(ctx, task.NewJob{
			ID: id, Kind: "test.list", Initiator: actor, RequestID: "req_list_1",
			Payload:        json.RawMessage(`{}`),
			TimeoutSeconds: 30, MaxAttempts: 1, CreatedAt: base}); err != nil {
			t.Fatalf("入队任务 %d: %v", index, err)
		}
		ids = append(ids, id)
	}
	request := task.ListJobsRequest{State: task.StateQueued, Kind: "test.list", Limit: 2}
	page, err := store.ListJobs(ctx, task.JobPageQuery{State: request.State,
		Kind: request.Kind, Limit: request.Limit})
	if err != nil || len(page.Jobs) != 2 || !page.HasMore {
		t.Fatalf("任务列表第一页 = %+v err=%v", page, err)
	}
	cursor, err := task.EncodeJobListCursor(request, page.Jobs[len(page.Jobs)-1])
	if err != nil {
		t.Fatalf("生成任务游标: %v", err)
	}
	request.Cursor = cursor
	createdAt, jobID, err := task.DecodeJobListCursor(request)
	if err != nil {
		t.Fatalf("解析任务游标: %v", err)
	}
	second, err := store.ListJobs(ctx, task.JobPageQuery{State: request.State,
		Kind: request.Kind, Limit: 2, AfterCreatedAt: createdAt, AfterID: jobID})
	if err != nil {
		t.Fatalf("任务列表第二页: %v", err)
	}
	seen := map[string]bool{}
	for _, job := range page.Jobs {
		seen[job.ID] = true
	}
	for _, job := range second.Jobs {
		if seen[job.ID] {
			t.Fatalf("任务游标分页重复: %s", job.ID)
		}
		seen[job.ID] = true
	}
	if len(seen) != 4 {
		t.Fatalf("前两页任务数 = %d，期望 4", len(seen))
	}
	// 换筛选复用游标：拒绝。
	mismatched := request
	mismatched.State = task.StateFailed
	if _, _, err := task.DecodeJobListCursor(mismatched); !errors.Is(err,
		task.ErrInvalidRequest) {
		t.Fatalf("跨筛选游标错误 = %v，期望 ErrInvalidRequest", err)
	}
	// 非法游标 / 越界 limit。
	for _, bad := range []task.ListJobsRequest{
		{Cursor: "not-a-cursor", Limit: 2},
		{Limit: task.ListMaxLimit + 1},
	} {
		if _, _, err := task.DecodeJobListCursor(bad); !errors.Is(err,
			task.ErrInvalidRequest) {
			t.Fatalf("非法任务列表参数 %+v 错误 = %v，期望 ErrInvalidRequest", bad, err)
		}
	}
	// request_id 过滤在存储层生效。
	filtered, err := store.ListJobs(ctx, task.JobPageQuery{RequestID: "req_list_1", Limit: 10})
	if err != nil || len(filtered.Jobs) != 5 {
		t.Fatalf("request_id 过滤结果 = %+v err=%v", filtered, err)
	}
	none, err := store.ListJobs(ctx, task.JobPageQuery{RequestID: "req_other", Limit: 10})
	if err != nil || len(none.Jobs) != 0 {
		t.Fatalf("不匹配 request_id 结果 = %+v err=%v", none, err)
	}
}
