package adminapi

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/reports"
	reportsqlite "github.com/kagurazakayashi/EvernightLogin/internal/reports/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/stats"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
	tasksqlite "github.com/kagurazakayashi/EvernightLogin/internal/task/sqlite"
)

// statsFakeAuthorizer 是 reports/stats 授权接缝的替身（生产为 *stats.Service /
// internal/authz 适配）；只替换授权判定，计划 CRUD/审计/版本并发仍是真实
// *reports.PlanService。
type statsFakeAuthorizer struct {
	grants map[string]stats.ScopeGrant
}

func (a *statsFakeAuthorizer) AuthorizeScope(_ context.Context, _ account.Caller,
	permissionKey, scopeID string) (stats.ScopeGrant, error) {
	return a.grants[permissionKey+"|"+scopeID], nil
}

// newRealPlanServer 用真实临时 SQLite + 真实 reports.PlanService 装配管理 API，
// 返回服务与授权替身（用于撤销权限验证拒绝）。
func newRealPlanServer(t *testing.T) (*Server, *statsFakeAuthorizer, *fakeSensitiveRunner) {
	t.Helper()
	env := newAdminAuditEnv(t)
	reportStore, err := reportsqlite.New(env.raw)
	if err != nil {
		t.Fatalf("构造报告仓储失败: %v", err)
	}
	projections, err := reportsqlite.NewPlanProjectionStore(reportStore)
	if err != nil {
		t.Fatalf("构造计划投影仓储失败: %v", err)
	}
	taskStore, err := tasksqlite.New(env.raw, tasksqlite.Options{Now: env.now})
	if err != nil {
		t.Fatalf("构造任务存储失败: %v", err)
	}
	authorizer := &statsFakeAuthorizer{grants: map[string]stats.ScopeGrant{}}
	for _, permission := range []string{reports.PermissionRead,
		reports.PermissionScheduleManage, reports.PermissionGenerate,
		reports.PermissionExport} {
		authorizer.grants[permission+"|"+reports.ScopeSystem] =
			stats.ScopeGrant{Allowed: true, AllData: true}
	}
	scheduler, err := task.NewScheduler(task.SchedulerOptions{
		Store: taskStore, SchedulerID: "adminapi-plan-scheduler",
		PermissionCheck: func(context.Context, task.PermissionRequest) error { return nil },
		TickInterval:    time.Minute, Now: env.now,
	})
	if err != nil {
		t.Fatalf("构造调度器失败: %v", err)
	}
	recorder, err := audit.New(env.audit, audit.Options{Now: env.now})
	if err != nil {
		t.Fatalf("构造审计写入器失败: %v", err)
	}
	plans, err := reports.NewPlanService(reports.PlanOptions{
		Schedules: scheduler, Authorizer: authorizer, Root: env.root,
		Audit: recorder, Projections: projections, MaxDetailRows: 20, Now: env.now})
	if err != nil {
		t.Fatalf("构造报告计划服务失败: %v", err)
	}
	sensitive := &fakeSensitiveRunner{denied: map[string]bool{}}
	server, err := New(Options{Session: env.session, ErrorCodes: testCodes(),
		Plans: plans, Sensitive: sensitive, Now: env.now})
	if err != nil {
		t.Fatalf("构造管理 API 失败: %v", err)
	}
	return server, authorizer, sensitive
}

// TestRealPlanServiceWriteFlow 用真实 *reports.PlanService 验证计划创建/编辑
// 行版本冲突/启停/删除与权限拒绝（权限、审计、投影写库均为真实路径）。
func TestRealPlanServiceWriteFlow(t *testing.T) {
	server, authorizer, sensitive := newRealPlanServer(t)
	authz := "Bearer management-secret"
	body := `{"confirm":true,"scope_id":"system","name":"真实每日报告",` +
		`"schedule_type":"daily","expression":"09:00","time_zone":"UTC",` +
		`"granularity":"day","window_days":1,"formats":["html"],` +
		`"missed_policy":"skip","enabled":true}`

	// 权限撤销：真实 PlanService 授权拒绝 → 403。
	for _, permission := range []string{reports.PermissionRead,
		reports.PermissionScheduleManage, reports.PermissionGenerate,
		reports.PermissionExport} {
		delete(authorizer.grants, permission+"|"+reports.ScopeSystem)
	}
	reply := callAPI(t, server, http.MethodPost, "/admin/v1/report-plans", body, authz, nil)
	requireErrorCode(t, reply, http.StatusForbidden, "ACCESS_DENIED")
	for _, permission := range []string{reports.PermissionRead,
		reports.PermissionScheduleManage, reports.PermissionGenerate,
		reports.PermissionExport} {
		authorizer.grants[permission+"|"+reports.ScopeSystem] =
			stats.ScopeGrant{Allowed: true, AllData: true}
	}

	// 敏感策略拒绝：403 REAUTH_REQUIRED（领域授权已通过也不放行）。
	sensitive.denied[OperationScheduleManage] = true
	reply = callAPI(t, server, http.MethodPost, "/admin/v1/report-plans", body, authz, nil)
	requireErrorCode(t, reply, http.StatusForbidden, "REAUTH_REQUIRED")
	delete(sensitive.denied, OperationScheduleManage)

	// 真实创建（写调度 + 管理投影 + 审计）。
	data := requireSuccess(t, callAPI(t, server, http.MethodPost,
		"/admin/v1/report-plans", body, authz, nil))
	plan, _ := data["plan"].(map[string]any)
	planID, _ := plan["id"].(string)
	version := int64(plan["version"].(float64))
	if planID == "" || version <= 0 {
		t.Fatalf("真实计划创建投影不符: %v", plan)
	}

	// 编辑：错误版本 → 409 CONFLICT（真实乐观并发）。
	updateBody := `{"confirm":true,"scope_id":"system","name":"真实每日报告（改）",` +
		`"schedule_type":"daily","expression":"10:00","time_zone":"UTC",` +
		`"granularity":"day","window_days":1,"formats":["html"],` +
		`"missed_policy":"skip","enabled":true,"version":999,"reason":"调整时间"}`
	reply = callAPI(t, server, http.MethodPut, "/admin/v1/report-plans/"+planID,
		updateBody, authz, nil)
	requireErrorCode(t, reply, http.StatusConflict, "CONFLICT")

	correctVersion := `{"confirm":true,"scope_id":"system","name":"真实每日报告（改）",` +
		`"schedule_type":"daily","expression":"10:00","time_zone":"UTC",` +
		`"granularity":"day","window_days":1,"formats":["html"],` +
		`"missed_policy":"skip","enabled":true,"version":` +
		formatInt(version) + `,"reason":"调整时间"}`
	data = requireSuccess(t, callAPI(t, server, http.MethodPut,
		"/admin/v1/report-plans/"+planID, correctVersion, authz, nil))
	updated, _ := data["plan"].(map[string]any)
	if updated["expression"] != "10:00" {
		t.Fatalf("真实计划编辑未生效: %v", updated)
	}

	// 启停与删除预览、删除均走真实服务。
	requireSuccess(t, callAPI(t, server, http.MethodPost,
		"/admin/v1/report-plans/"+planID+"/enabled",
		`{"confirm":true,"enabled":false,"reason":"维护窗口"}`, authz, nil))
	data = requireSuccess(t, callAPI(t, server, http.MethodGet,
		"/admin/v1/report-plans/"+planID+"/delete-preview", "", authz, nil))
	if data["delete_preview"].(map[string]any)["plan_id"] != planID {
		t.Fatalf("真实删除预览不符: %v", data)
	}
	requireSuccess(t, callAPI(t, server, http.MethodDelete,
		"/admin/v1/report-plans/"+planID,
		`{"confirm":true,"reason":"不再需要"}`, authz, nil))
	reply = callAPI(t, server, http.MethodGet,
		"/admin/v1/report-plans/"+planID, "", authz, nil)
	if reply.status < 400 || reply.status > 599 {
		t.Fatalf("删除后读取应失败，实际状态 %d", reply.status)
	}
}

// formatInt 把整数转成十进制字符串（避免在测试里引入额外格式化依赖）。
func formatInt(value int64) string {
	if value == 0 {
		return "0"
	}
	digits := make([]byte, 0, 20)
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}
