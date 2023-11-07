package userbatch_test

// 步骤 218：用户批量任务列表 offset 分页测试（页面“下一页”必须真实生效）。
//   - offset 在存储层分页，两页无重复并返回真实 HasMore；
//   - 越界 offset 返回空页且 HasMore=false；
//   - 非法 limit/offset 返回 ErrInvalidRequest（不静默钳制）。

import (
	"errors"
	"fmt"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/userbatch"
)

func TestListJobsOffsetPagination(t *testing.T) {
	env := newTestEnv(t)
	env.seedUser("usr_00000000000000000000000000000701", "batch-user", "批量用户", false)
	for index := 0; index < 3; index++ {
		env.startImport(env.csv("batch-user,批量用户,,zh-CN,Asia/Shanghai"),
			fmt.Sprintf("offset-key-%d", index), fmt.Sprintf("req-offset-%d", index))
	}
	first, hasMore, err := env.service.ListJobs(env.ctx, env.caller,
		userbatch.ListJobsQuery{Limit: 2, Offset: 0})
	if err != nil || len(first) != 2 || !hasMore {
		t.Fatalf("批量任务第一页 = %d hasMore=%v err=%v", len(first), hasMore, err)
	}
	second, hasMore, err := env.service.ListJobs(env.ctx, env.caller,
		userbatch.ListJobsQuery{Limit: 2, Offset: 2})
	if err != nil || len(second) != 1 || hasMore {
		t.Fatalf("批量任务第二页 = %d hasMore=%v err=%v", len(second), hasMore, err)
	}
	seen := map[string]bool{}
	for _, job := range append(first, second...) {
		if seen[job.ID] {
			t.Fatalf("offset 分页重复任务 %s", job.ID)
		}
		seen[job.ID] = true
	}
	if len(seen) != 3 {
		t.Fatalf("两页任务数 = %d，期望 3", len(seen))
	}
	empty, hasMore, err := env.service.ListJobs(env.ctx, env.caller,
		userbatch.ListJobsQuery{Limit: 2, Offset: 100})
	if err != nil || len(empty) != 0 || hasMore {
		t.Fatalf("越界 offset 结果 = %d hasMore=%v err=%v", len(empty), hasMore, err)
	}
	for _, query := range []userbatch.ListJobsQuery{
		{Limit: 2, Offset: -1},
		{Limit: 101},
	} {
		if _, _, err := env.service.ListJobs(env.ctx, env.caller,
			query); !errors.Is(err, userbatch.ErrInvalidRequest) {
			t.Fatalf("非法批量任务分页 %+v 错误 = %v，期望 ErrInvalidRequest", query, err)
		}
	}
}
