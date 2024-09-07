package uiadminadapter

// 步骤 266：通用后台任务页适配器。
//
// 权限与范围：页面动作经宿主 Authorize 复核 diagnostics.read；任务列表只返回当前
// 管理会话本人发起的任务（与 /admin/v1/tasks 非受信主体口径一致），不返回任务载荷，
// 也不因页面可见而放宽任务详情/取消的服务端授权。取消任务不在此处执行，避免把
// “请求已受理”误显示为“已取消”。

import (
	"context"
	"errors"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
	ui "github.com/kagurazakayashi/EvernightLogin/ui"
)

// TaskLister 是任务列表只读契约（生产实现为 *task.Executor.ListJobs）。
type TaskLister interface {
	ListJobs(ctx context.Context, request task.ListJobsRequest) (task.JobListPage, error)
}

// ListTasks 实现 ui.UIAdminTasksBackend：返回当前管理会话可见的有界任务页。
func (a *Adapter) ListTasks(ctx context.Context, adminUserID string,
	query ui.UIAdminTaskQuery) (ui.UIAdminTaskPage, error) {
	if err := a.check(ctx, adminUserID, "diagnostics.read"); err != nil {
		return ui.UIAdminTaskPage{}, err
	}
	if a.opts.Tasks == nil {
		return ui.UIAdminTaskPage{}, adminErr("INTERNAL_ERROR")
	}
	caller, err := account.UserCaller(adminUserID)
	if err != nil {
		return ui.UIAdminTaskPage{}, adminErr("ACCESS_DENIED")
	}
	actor := caller.Actor()
	state := task.State(strings.TrimSpace(query.State))
	if state != "" && !state.Valid() {
		return ui.UIAdminTaskPage{}, adminErr("REQ_INVALID")
	}
	limit := query.Limit
	if limit <= 0 {
		limit = task.ListDefaultLimit
	}
	if limit > task.ListMaxLimit {
		limit = task.ListMaxLimit
	}
	result, err := a.opts.Tasks.ListJobs(ctx, task.ListJobsRequest{
		State: state, Kind: strings.TrimSpace(query.Kind), Limit: limit,
		Cursor: query.Cursor, InitiatorType: actor.Type, InitiatorID: actor.ID,
	})
	if err != nil {
		if errors.Is(err, task.ErrInvalidRequest) {
			return ui.UIAdminTaskPage{}, adminErr("REQ_INVALID")
		}
		return ui.UIAdminTaskPage{}, adminErr("INTERNAL_ERROR")
	}
	page := ui.UIAdminTaskPage{HasMore: result.HasMore, Limit: result.Limit,
		NextCursor: result.NextCursor, Tasks: make([]ui.UIAdminTask, 0, len(result.Jobs))}
	for _, job := range result.Jobs {
		page.Tasks = append(page.Tasks, ui.UIAdminTask{
			ID: job.ID, Kind: job.Kind, State: string(job.State),
			InitiatorType: string(job.Initiator.Type), InitiatorID: job.Initiator.ID,
			Attempt: job.Attempt, MaxAttempts: job.MaxAttempts,
			ErrorCode: job.ErrorCode, RequestID: job.RequestID,
			CreatedAt: job.CreatedAt, UpdatedAt: job.UpdatedAt,
		})
	}
	return page, nil
}
