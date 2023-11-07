package app

// 步骤 218：公开管理门面新增可增长列表分页测试。
//   - ListTasks 使用稳定游标与筛选，本机受信操作者可见全部、管理会话只见本人任务；
//   - ListAuditEvents/ListReports/ListReportPlans/ListBackup* 返回统一分页元数据；
//   - 非法 limit/cursor/筛选返回 REQ_INVALID，且不查询领域（无副作用）。

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

func TestAdminObservabilityListsPagination(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock(time.Date(2026, 11, 25, 8, 0, 0, 0, time.UTC))
	runtime := adminTestRuntime(t, ctx, testConfig(), t.TempDir(), clock)
	local := runtime.LocalAdmin()
	adminAPI := runtime.Admin()
	if runtime.base == nil || runtime.base.Tasks == nil || runtime.base.Tasks.Executor() == nil {
		t.Fatal("后台任务运行时未装配")
	}
	executor := runtime.base.Tasks.Executor()
	hostActor := audit.Actor{Type: audit.ActorLocalAdmin, ID: "host-operator"}
	hostJob, err := executor.Enqueue(ctx, task.EnqueueRequest{
		Kind: "test.admin.list", Actor: hostActor, Payload: json.RawMessage(`{}`),
		TimeoutSeconds: 30, MaxAttempts: 1, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("入队测试任务: %v", err)
	}
	taskPage, err := adminAPI.ListTasks(ctx, AdminListTasksRequest{
		Caller: local, Limit: 10, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("ListTasks: %v", err)
	}
	if len(taskPage.Tasks) != 1 || taskPage.Tasks[0].ID != hostJob.ID ||
		taskPage.HasMore {
		t.Fatalf("任务列表 = %+v", taskPage)
	}
	if taskPage.Tasks[0].State != string(task.StateQueued) ||
		taskPage.Tasks[0].InitiatorID != "host-operator" {
		t.Fatalf("任务条目 = %+v", taskPage.Tasks[0])
	}
	for _, request := range []AdminListTasksRequest{
		{Caller: local, Limit: 101},
		{Caller: local, Cursor: "not-a-cursor"},
		{Caller: local, State: "bogus"},
	} {
		request.RequestID = login.NewRequestID()
		if _, err := adminAPI.ListTasks(ctx, request); !login.IsErrorCode(err,
			login.CodeReqInvalid) {
			t.Fatalf("非法任务列表请求 %+v 错误 = %v，期望 REQ_INVALID", request, err)
		}
	}
	// 管理会话只看到本人发起的任务；本机受信操作者可见全部。
	user, err := runtime.Users().Create(ctx, CreateUserRequest{
		Username: "task-list-user", Password: "T4!kR8#wQ2@mN6$z",
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("创建任务列表用户: %v", err)
	}
	userLogin, err := runtime.Auth().Login(ctx, LoginRequest{
		Username: "task-list-user", Password: "T4!kR8#wQ2@mN6$z",
		ClientIP: "127.0.0.1", RequestID: login.NewRequestID()})
	if err != nil || userLogin.Restricted {
		t.Fatalf("任务列表用户登录: %+v err=%v", userLogin, err)
	}
	userJob, err := executor.Enqueue(ctx, task.EnqueueRequest{
		Kind: "test.admin.list", Actor: audit.Actor{Type: audit.ActorUser, ID: user.ID},
		Payload: json.RawMessage(`{}`), TimeoutSeconds: 30, MaxAttempts: 1,
		RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("入队用户任务: %v", err)
	}
	userTasks, err := adminAPI.ListTasks(ctx, AdminListTasksRequest{
		Caller: runtime.AdminSession(userLogin.SessionSecret), Limit: 10,
		RequestID: login.NewRequestID()})
	if err != nil || len(userTasks.Tasks) != 1 || userTasks.Tasks[0].ID != userJob.ID {
		t.Fatalf("管理会话任务列表 = %+v err=%v", userTasks, err)
	}
	allTasks, err := adminAPI.ListTasks(ctx, AdminListTasksRequest{
		Caller: local, Limit: 10, RequestID: login.NewRequestID()})
	if err != nil || len(allTasks.Tasks) != 2 {
		t.Fatalf("本机受信任务列表 = %+v err=%v", allTasks, err)
	}

	// 审计事件：本机受信操作者读取，返回稳定分页元数据。
	auditPage, err := adminAPI.ListAuditEvents(ctx, AdminListAuditEventsRequest{
		Caller: local, ScopeID: "system", Limit: 5, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("ListAuditEvents: %v", err)
	}
	if auditPage.RetentionDays <= 0 || auditPage.ScopeID != "system" {
		t.Fatalf("审计分页 = %+v", auditPage)
	}
	if _, err := adminAPI.ListAuditEvents(ctx, AdminListAuditEventsRequest{
		Caller: local, Cursor: "bad-cursor",
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("非法审计游标错误 = %v，期望 REQ_INVALID", err)
	}

	// 报告与备份列表：真实服务装配时应返回分页元数据（空列表也合法）。
	reportPage, err := adminAPI.ListReports(ctx, AdminListReportsRequest{
		Caller: local, Limit: 5, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("ListReports: %v", err)
	}
	if reportPage.Limit != 5 {
		t.Fatalf("报告分页 = %+v", reportPage)
	}
	planPage, err := adminAPI.ListReportPlans(ctx, AdminListReportPlansRequest{
		Caller: local, Page: AdminPage{Limit: 5}, RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("ListReportPlans: %v", err)
	}
	if planPage.Page.Limit != 5 {
		t.Fatalf("报告计划分页 = %+v", planPage.Page)
	}
	backupSchedules, err := adminAPI.ListBackupSchedules(ctx,
		AdminListBackupSchedulesRequest{Caller: local, Page: AdminPage{Limit: 5},
			RequestID: login.NewRequestID()})
	if err != nil {
		t.Fatalf("ListBackupSchedules: %v", err)
	}
	if backupSchedules.Page.Limit != 5 {
		t.Fatalf("备份计划分页 = %+v", backupSchedules.Page)
	}
	if _, err := adminAPI.ListBackupJobs(ctx, AdminListBackupJobsRequest{
		Caller: local, Page: AdminPage{Limit: 101},
		RequestID: login.NewRequestID()}); !login.IsErrorCode(err, login.CodeReqInvalid) {
		t.Fatalf("非法备份分页错误 = %v，期望 REQ_INVALID", err)
	}
}
