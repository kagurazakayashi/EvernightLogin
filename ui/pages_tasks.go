package ui

// 步骤 266：通用后台任务页（/admin/tasks）。
//
// 页面只做展示：后端适配器负责重新判定管理权限（diagnostics.read）并按可见范围
// 查询 internal/task 的真实任务状态；页面不拼接数据库、不返回任务载荷、不伪造
// 取消结果。R10-23 的“通用任务页”缺口在此闭环。
//
// 取消语义区分（页面固定文案说明）：
//   - 取消任务：对 internal/task 提交取消请求，仅“请求已受理”，终态以任务状态为准
//     （cancel_requested → cancelled/failed/...）；使用 `loginctl task cancel` 或任务 API。
//   - 取消邮件投递：终止某封邮件在可靠投递队列中的发送（投递状态转为 canceled），
//     它不是取消产生该邮件的后台任务，也不会回滚已完成的业务操作。

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// UIPageAdminTasksOptions 是通用任务页配置；Backend 为 nil 时不注册该页（404）。
type UIPageAdminTasksOptions struct {
	Backend UIAdminTasksBackend
}

// UIAdminTasksBackend 是通用任务列表的只读最小契约。实现必须重新判定管理权限；
// 返回字段只含任务元数据与状态，不含任务载荷、业务数据或秘密。
type UIAdminTasksBackend interface {
	ListTasks(ctx context.Context, adminID string, query UIAdminTaskQuery) (UIAdminTaskPage, error)
}

// UIAdminTaskQuery 是任务列表筛选/分页参数（游标为服务端不透明值）。
type UIAdminTaskQuery struct {
	Cursor string
	Limit  int
	State  string
	Kind   string
}

// UIAdminTask 是任务元数据白名单视图（不含 Payload）。
type UIAdminTask struct {
	ID            string
	Kind          string
	State         string
	InitiatorType string
	InitiatorID   string
	Attempt       int
	MaxAttempts   int
	ErrorCode     string
	RequestID     string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// UIAdminTaskPage 是一页任务结果；游标/是否还有下一页来自服务端真实查询。
type UIAdminTaskPage struct {
	Tasks      []UIAdminTask
	NextCursor string
	HasMore    bool
	Limit      int
}

// UIAdminTaskStates 是任务状态筛选的稳定枚举（与服务端 internal/task 一致）。
var UIAdminTaskStates = []string{"queued", "running", "succeeded", "failed",
	"cancel_requested", "cancelled", "timed_out"}

// tasks 渲染通用后台任务列表（只读、有界分页；取消入口不在本页伪造）。
func (h *adminPageHandlers) tasks(ctx context.Context, request *http.Request,
	page UIPageContext) (UIPageOutcome, error) {
	options := h.pages.options.Tasks
	if options == nil || isNilUIValue(options.Backend) {
		return UIPageOutcome{StatusCode: http.StatusNotFound,
			ErrorSummary: text("page.admin.tasks.unavailable")}, nil
	}
	values := request.URL.Query()
	state := strings.TrimSpace(values.Get("state"))
	if state != "" && !validTaskState(state) {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.tasks.filter.invalid_state")}, nil
	}
	kind, kindOK := normalizeListSearchInput(values.Get("kind"))
	if !kindOK {
		return UIPageOutcome{StatusCode: http.StatusBadRequest,
			ErrorSummary: text("page.admin.tasks.filter.invalid_kind")}, nil
	}
	limit := 20
	if raw := strings.TrimSpace(values.Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 100 {
			return UIPageOutcome{StatusCode: http.StatusBadRequest,
				ErrorSummary: text("page.admin.tasks.filter.invalid_limit")}, nil
		}
		limit = parsed
	}
	query := UIAdminTaskQuery{
		Cursor: strings.TrimSpace(values.Get("cursor")),
		Limit:  limit, State: state, Kind: kind,
	}
	result, err := options.Backend.ListTasks(ctx, page.Session.UserID, query)
	if err != nil {
		return adminErrorOutcome(err, nil, "page.admin.tasks.load_failed"), nil
	}
	return UIPageOutcome{Data: map[string]any{
		"tasks": result, "state": state, "kind": kind, "limit": limit,
	}}, nil
}

// validTaskState 报告状态筛选值是否属于稳定任务状态枚举。
func validTaskState(value string) bool {
	for _, state := range UIAdminTaskStates {
		if state == value {
			return true
		}
	}
	return false
}
