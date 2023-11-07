package adminapi

// 步骤 218：管理 HTTP 列表分页端点测试。
//   - 审计事件游标参数与 next_cursor 响应；非法/跨筛选游标 REQ_INVALID；
//   - 任务列表分页与列表级可见范围（未授权 403、非零 offset 拒绝）；
//   - 报告计划/备份计划分页元数据（has_more/next_offset）。

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/auditops"
	"github.com/kagurazakayashi/EvernightLogin/internal/backupadmin"
	"github.com/kagurazakayashi/EvernightLogin/internal/reports"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

var errTaskListDenied = errors.New("任务列表无权")

func TestAdminAuditEventsCursorHTTP(t *testing.T) {
	env := newAdminAuditEnv(t)
	env.setRoot(true)
	env.grant("audit.read", "system", auditops.ScopeGrant{Allowed: true, AllData: true})
	sameTime := adminBaseTime.Add(-2 * time.Hour)
	for index := 0; index < 5; index++ {
		env.seed("user.update", "app_1", adminTestUserID(5), sameTime)
	}
	firstReply := env.call(http.MethodGet, "/admin/v1/audit/events?limit=2", "")
	first := requireSuccess(t, firstReply)
	cursor, _ := first["next_cursor"].(string)
	if cursor == "" || first["has_more"] != true {
		t.Fatalf("审计第一页响应 = %+v", first)
	}
	second := requireSuccess(t, env.call(http.MethodGet,
		"/admin/v1/audit/events?limit=2&cursor="+cursor, ""))
	if second["has_more"] != true && second["has_more"] != false && second["has_more"] != nil {
		t.Fatalf("审计第二页响应 = %+v", second)
	}
	requireErrorCode(t, env.call(http.MethodGet,
		"/admin/v1/audit/events?limit=2&cursor=not-a-cursor", ""),
		http.StatusBadRequest, "REQ_INVALID")
	// 游标与筛选不匹配：服务端拒绝。
	requireErrorCode(t, env.call(http.MethodGet,
		"/admin/v1/audit/events?limit=2&action=user.create&cursor="+cursor, ""),
		http.StatusBadRequest, "REQ_INVALID")
}

func TestAdminTaskListHTTPAndScope(t *testing.T) {
	authz := "Bearer management-secret"
	tasks := &stubTaskReader{job: task.Job{ID: "job_000000000000000000000000000000a1",
		Kind: "report.generate", State: task.StateQueued,
		Initiator: audit.Actor{Type: audit.ActorUser, ID: adminTestUserID(4)},
		CreatedAt: adminBaseTime}}
	server := newDomainStubServer(t, nil, nil, nil, tasks, func(options *Options) {
		options.TaskLister = tasks
		options.TaskListAuthorizer = tasks
	})
	data := requireSuccess(t, callAPI(t, server, http.MethodGet,
		"/admin/v1/tasks?limit=5", "", authz, nil))
	items, _ := data["tasks"].([]any)
	if len(items) != 1 || data["has_more"] != false {
		t.Fatalf("任务列表响应 = %+v", data)
	}
	// 非零 offset 与游标列表冲突。
	requireErrorCode(t, callAPI(t, server, http.MethodGet,
		"/admin/v1/tasks?offset=1", "", authz, nil), http.StatusBadRequest, "REQ_INVALID")
	// 列表授权失败统一 403，不泄露是否存在任务。
	tasks.listAuthorize = func(context.Context, account.Caller) (TaskListScope, error) {
		return TaskListScope{}, errTaskListDenied
	}
	requireErrorCode(t, callAPI(t, server, http.MethodGet, "/admin/v1/tasks", "", authz, nil),
		http.StatusForbidden, "ACCESS_DENIED")
}

func TestAdminPlansAndBackupSchedulesPaginationHTTP(t *testing.T) {
	authz := "Bearer management-secret"
	plan := &stubPlanService{list: func(context.Context, account.Caller) ([]reports.PlanView, error) {
		return []reports.PlanView{{ID: "plan_1", Name: "计划1"},
			{ID: "plan_2", Name: "计划2"}, {ID: "plan_3", Name: "计划3"}}, nil
	}}
	backup := &stubBackupService{listSchedules: func(context.Context, account.Caller) ([]backupadmin.ScheduleView, error) {
		return []backupadmin.ScheduleView{{ID: "sch_1"}, {ID: "sch_2"}, {ID: "sch_3"}}, nil
	}}
	server := newDomainStubServer(t, nil, plan, backup, nil)
	data := requireSuccess(t, callAPI(t, server, http.MethodGet,
		"/admin/v1/report-plans?limit=2", "", authz, nil))
	plans, _ := data["plans"].([]any)
	if len(plans) != 2 || data["has_more"] != true || data["next_offset"].(float64) != 2 {
		t.Fatalf("报告计划分页响应 = %+v", data)
	}
	data = requireSuccess(t, callAPI(t, server, http.MethodGet,
		"/admin/v1/backups/schedules?limit=2", "", authz, nil))
	schedules, _ := data["schedules"].([]any)
	if len(schedules) != 2 || data["has_more"] != true || data["next_offset"].(float64) != 2 {
		t.Fatalf("备份计划分页响应 = %+v", data)
	}
}
