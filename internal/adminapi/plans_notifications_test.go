package adminapi

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/backupadmin"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/reports"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// fakeSensitiveRunner 是管理 API 敏感策略接缝的可控替身（生产为 *reauth.Service）。
type fakeSensitiveRunner struct {
	mu     sync.Mutex
	denied map[string]bool
	calls  []reauth.Request
}

func (f *fakeSensitiveRunner) Authorize(_ context.Context, caller reauth.Caller,
	request reauth.Request) (reauth.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, request)
	if f.denied[request.OperationID] {
		return reauth.Result{}, reauth.ErrReauthRequired
	}
	return reauth.Result{OperationID: request.OperationID,
		TargetType: request.TargetType, TargetID: request.TargetID,
		UserID: caller.Actor().ID, RequestID: request.RequestID}, nil
}

func (f *fakeSensitiveRunner) NotifyOutcome(context.Context, reauth.Result, reauth.Outcome) error {
	return nil
}

// fakeAuditRecorder 记录管理 API 自身动作的审计事件。
type fakeAuditRecorder struct {
	mu     sync.Mutex
	events []audit.Event
	fail   bool
}

func (f *fakeAuditRecorder) Record(_ context.Context, event audit.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return errors.New("审计不可用")
	}
	f.events = append(f.events, event)
	return nil
}

func (f *fakeAuditRecorder) RecordFailure(ctx context.Context, event audit.Event) error {
	return f.Record(ctx, event)
}

// fakeNotificationService 是本地捕获通知器的测试替身：不访问网络，只记录摘要。
type fakeNotificationService struct {
	mu        sync.Mutex
	calls     int
	testErr   error
	status    *NotificationStatus
	statusErr error
}

func (f *fakeNotificationService) NotificationStatus(context.Context, account.Caller) (NotificationStatus, error) {
	if f.statusErr != nil {
		return NotificationStatus{}, f.statusErr
	}
	if f.status != nil {
		return *f.status, nil
	}
	return NotificationStatus{Enabled: true, LocalCapture: true,
		Channels:     []string{DeliveryModeLocalCapture},
		DeliveryMode: DeliveryModeLocalCapture,
		Note:         "测试本地捕获器"}, nil
}

func (f *fakeNotificationService) TestNotification(_ context.Context,
	_ account.Caller, _ string) (NotificationTestResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.testErr != nil {
		return NotificationTestResult{}, f.testErr
	}
	return NotificationTestResult{CaptureID: "capture-1", Channel: "local_capture",
		RecipientMasked: "u***@example.invalid", CapturedAt: adminBaseTime,
		Note: "仅本地捕获，未真实外发"}, nil
}

// TestReportPlanWriteEndpoints 验证报告计划写：确认、强认证敏感策略、行版本冲突、
// 启停原因与删除语义。
func TestReportPlanWriteEndpoints(t *testing.T) {
	planView := reports.PlanView{ID: "plan_1", Name: "每日报告", Enabled: true,
		ScheduleType: task.ScheduleTypeDaily, Expression: "09:00", TimeZone: "UTC",
		ScopeID: reports.ScopeSystem, Version: 1,
		Owner: audit.Actor{Type: audit.ActorUser, ID: adminTestUserID(4)}}
	plan := &stubPlanService{
		create: func(_ context.Context, request reports.PlanCreateRequest) (reports.PlanView, error) {
			if request.ScopeID != reports.ScopeSystem || request.Name != "每日报告" {
				return reports.PlanView{}, reports.ErrInvalidRequest
			}
			return planView, nil
		},
		update: func(_ context.Context, request reports.PlanUpdateRequest) (reports.PlanView, error) {
			if request.Version != 1 {
				return reports.PlanView{}, reports.ErrConflict
			}
			return planView, nil
		},
		setEnabled: func(_ context.Context, _ account.Caller, _ string, enabled bool,
			reason, _ string) (reports.PlanView, error) {
			if reason != "维护窗口" {
				return reports.PlanView{}, reports.ErrInvalidRequest
			}
			planView.Enabled = enabled
			return planView, nil
		},
		deletePreview: func(context.Context, account.Caller, string) (reports.PlanDeletePreview, error) {
			return reports.PlanDeletePreview{PlanID: "plan_1", Name: "每日报告",
				Irreversible: true, RawAuditNote: "原始审计不删除"}, nil
		},
		deletePlan: func(_ context.Context, _ account.Caller, id, reason, _ string) error {
			if id != "plan_1" || reason != "不再需要" {
				return reports.ErrInvalidRequest
			}
			return nil
		},
	}
	sensitive := &fakeSensitiveRunner{denied: map[string]bool{}}
	server := newDomainStubServer(t, nil, plan, nil, nil,
		func(options *Options) { options.Sensitive = sensitive })
	authz := "Bearer management-secret"
	planBody := `{"scope_id":"system","name":"每日报告","schedule_type":"daily",` +
		`"expression":"09:00","time_zone":"UTC","granularity":"day","window_days":1,` +
		`"formats":["html"],"missed_policy":"skip","enabled":true}`

	// 缺确认：参数错误，不进入领域服务。
	reply := callAPI(t, server, http.MethodPost, "/admin/v1/report-plans",
		planBody, authz, nil)
	requireErrorCode(t, reply, http.StatusBadRequest, "REQ_INVALID")

	// 敏感策略拒绝：403 REAUTH_REQUIRED。
	sensitive.denied[OperationScheduleManage] = true
	reply = callAPI(t, server, http.MethodPost, "/admin/v1/report-plans",
		`{"confirm":true,`+planBody[1:], authz, nil)
	requireErrorCode(t, reply, http.StatusForbidden, "REAUTH_REQUIRED")
	delete(sensitive.denied, OperationScheduleManage)

	// 成功创建。
	body := `{"confirm":true,` + planBody[1:]
	data := requireSuccess(t, callAPI(t, server, http.MethodPost,
		"/admin/v1/report-plans", body, authz, nil))
	if data["plan"].(map[string]any)["id"] != "plan_1" {
		t.Fatalf("计划创建投影不符: %v", data)
	}

	// 编辑：缺行版本 400；版本不符映射 409 CONFLICT。
	reply = callAPI(t, server, http.MethodPut, "/admin/v1/report-plans/plan_1", body, authz, nil)
	requireErrorCode(t, reply, http.StatusBadRequest, "REQ_INVALID")
	conflictBody := `{"confirm":true,"version":99,` + planBody[1:]
	reply = callAPI(t, server, http.MethodPut, "/admin/v1/report-plans/plan_1",
		conflictBody, authz, nil)
	requireErrorCode(t, reply, http.StatusConflict, "CONFLICT")

	// 启停：缺原因 400；成功启停。
	reply = callAPI(t, server, http.MethodPost, "/admin/v1/report-plans/plan_1/enabled",
		`{"confirm":true,"enabled":false}`, authz, nil)
	requireErrorCode(t, reply, http.StatusBadRequest, "REQ_INVALID")
	data = requireSuccess(t, callAPI(t, server, http.MethodPost,
		"/admin/v1/report-plans/plan_1/enabled",
		`{"confirm":true,"enabled":false,"reason":"维护窗口"}`, authz, nil))
	if data["plan"].(map[string]any)["enabled"] != false {
		t.Fatalf("启停结果不符: %v", data)
	}

	// 删除预览与删除。
	data = requireSuccess(t, callAPI(t, server, http.MethodGet,
		"/admin/v1/report-plans/plan_1/delete-preview", "", authz, nil))
	preview, _ := data["delete_preview"].(map[string]any)
	if preview["irreversible"] != true || preview["raw_audit_note"] != "原始审计不删除" {
		t.Fatalf("删除预览投影不符: %v", preview)
	}
	reply = callAPI(t, server, http.MethodDelete, "/admin/v1/report-plans/plan_1",
		`{"confirm":true}`, authz, nil)
	requireErrorCode(t, reply, http.StatusBadRequest, "REQ_INVALID")
	requireSuccess(t, callAPI(t, server, http.MethodDelete,
		"/admin/v1/report-plans/plan_1",
		`{"confirm":true,"reason":"不再需要"}`, authz, nil))

	// 未装配敏感策略时计划写必须 fail-closed。
	unwired := newDomainStubServer(t, nil, plan, nil, nil)
	reply = callAPI(t, unwired, http.MethodPost, "/admin/v1/report-plans", body, authz, nil)
	requireErrorCode(t, reply, http.StatusForbidden, "REAUTH_REQUIRED")
}

// TestBackupScheduleWriteEndpoints 验证备份计划写：确认、敏感策略、冲突映射与
// 启停/删除语义。
func TestBackupScheduleWriteEndpoints(t *testing.T) {
	scheduleView := backupadmin.ScheduleView{ID: "sch_1", Name: "每日备份",
		Enabled: true, ScheduleType: string(task.ScheduleTypeDaily), Expression: "03:00",
		TimeZone: "UTC", ScopeID: reports.ScopeSystem,
		Owner: audit.Actor{Type: audit.ActorUser, ID: adminTestUserID(4)}}
	backup := &stubBackupService{
		createSchedule: func(_ context.Context, request backupadmin.ScheduleRequest) (backupadmin.ScheduleView, error) {
			if request.Name != "每日备份" || !request.Enabled {
				return backupadmin.ScheduleView{}, backupadmin.ErrInvalidRequest
			}
			return scheduleView, nil
		},
		updateSchedule: func(_ context.Context, id string, _ backupadmin.ScheduleRequest) (backupadmin.ScheduleView, error) {
			if id != "sch_1" {
				return backupadmin.ScheduleView{}, backupadmin.ErrConflict
			}
			return scheduleView, nil
		},
		setEnabled: func(_ context.Context, _ account.Caller, _ string, enabled bool,
			reason, _ string) (backupadmin.ScheduleView, error) {
			if reason != "维护窗口" {
				return backupadmin.ScheduleView{}, backupadmin.ErrInvalidRequest
			}
			scheduleView.Enabled = enabled
			return scheduleView, nil
		},
		deleteSchedule: func(_ context.Context, _ account.Caller, id, reason, _ string) error {
			if id != "sch_1" || reason != "不再需要" {
				return backupadmin.ErrInvalidRequest
			}
			return nil
		},
		getSchedule: func(context.Context, account.Caller, string) (backupadmin.ScheduleView, error) {
			return scheduleView, nil
		},
	}
	sensitive := &fakeSensitiveRunner{denied: map[string]bool{}}
	server := newDomainStubServer(t, nil, nil, backup, nil,
		func(options *Options) { options.Sensitive = sensitive })
	authz := "Bearer management-secret"
	scheduleBody := `{"name":"每日备份","schedule_type":"daily","expression":"03:00",` +
		`"time_zone":"UTC","missed_policy":"skip","enabled":true}`

	reply := callAPI(t, server, http.MethodPost, "/admin/v1/backups/schedules",
		scheduleBody, authz, nil)
	requireErrorCode(t, reply, http.StatusBadRequest, "REQ_INVALID")
	sensitive.denied[OperationBackupScheduleManage] = true
	reply = callAPI(t, server, http.MethodPost, "/admin/v1/backups/schedules",
		`{"confirm":true,`+scheduleBody[1:], authz, nil)
	requireErrorCode(t, reply, http.StatusForbidden, "REAUTH_REQUIRED")
	delete(sensitive.denied, OperationBackupScheduleManage)

	data := requireSuccess(t, callAPI(t, server, http.MethodPost,
		"/admin/v1/backups/schedules", `{"confirm":true,`+scheduleBody[1:], authz, nil))
	if data["schedule"].(map[string]any)["id"] != "sch_1" {
		t.Fatalf("备份计划创建投影不符: %v", data)
	}
	reply = callAPI(t, server, http.MethodPut, "/admin/v1/backups/schedules/unknown",
		`{"confirm":true,`+scheduleBody[1:], authz, nil)
	requireErrorCode(t, reply, http.StatusConflict, "CONFLICT")
	requireSuccess(t, callAPI(t, server, http.MethodPut,
		"/admin/v1/backups/schedules/sch_1",
		`{"confirm":true,`+scheduleBody[1:], authz, nil))

	reply = callAPI(t, server, http.MethodPost,
		"/admin/v1/backups/schedules/sch_1/enabled",
		`{"confirm":true,"enabled":false}`, authz, nil)
	requireErrorCode(t, reply, http.StatusBadRequest, "REQ_INVALID")
	requireSuccess(t, callAPI(t, server, http.MethodPost,
		"/admin/v1/backups/schedules/sch_1/enabled",
		`{"confirm":true,"enabled":false,"reason":"维护窗口"}`, authz, nil))

	reply = callAPI(t, server, http.MethodDelete, "/admin/v1/backups/schedules/sch_1",
		`{"confirm":true}`, authz, nil)
	requireErrorCode(t, reply, http.StatusBadRequest, "REQ_INVALID")
	requireSuccess(t, callAPI(t, server, http.MethodDelete,
		"/admin/v1/backups/schedules/sch_1",
		`{"confirm":true,"reason":"不再需要"}`, authz, nil))
	requireSuccess(t, callAPI(t, server, http.MethodGet,
		"/admin/v1/backups/schedules/sch_1", "", authz, nil))
}

// TestNotificationEndpoints 验证通知读取与本地捕获测试：
// 禁止真实外发、未装配时稳定能力码、reauth/审计缺失 fail-closed、成功摘要与审计。
func TestNotificationEndpoints(t *testing.T) {
	authz := "Bearer management-secret"

	// 未注入通知器：读取返回 MAIL_DIAGNOSTICS_UNAVAILABLE，测试返回
	// NOTIFICATION_TEST_DISABLED（稳定能力码，HTTP 503）。
	unwired := newDomainStubServer(t, nil, nil, nil, nil)
	reply := callAPI(t, unwired, http.MethodGet, "/admin/v1/notifications", "", authz, nil)
	requireErrorCode(t, reply, http.StatusServiceUnavailable, codeMailDiagnosticsUnavailable)
	reply = callAPI(t, unwired, http.MethodPost, "/admin/v1/notifications/test",
		`{"confirm":true}`, authz, nil)
	requireErrorCode(t, reply, http.StatusServiceUnavailable, codeNotificationTestDisabled)

	notifier := &fakeNotificationService{}
	auditRecorder := &fakeAuditRecorder{}
	sensitive := &fakeSensitiveRunner{denied: map[string]bool{}}

	// 有通知器但未装配敏感策略：fail-closed 403 REAUTH_REQUIRED。
	noSensitive := newDomainStubServer(t, nil, nil, nil, nil,
		func(options *Options) { options.Notifications = notifier })
	reply = callAPI(t, noSensitive, http.MethodPost, "/admin/v1/notifications/test",
		`{"confirm":true}`, authz, nil)
	requireErrorCode(t, reply, http.StatusForbidden, "REAUTH_REQUIRED")

	// 敏感策略可放行但审计不可用：拒绝测试（不留下虚假成功）。
	noAudit := newDomainStubServer(t, nil, nil, nil, nil, func(options *Options) {
		options.Notifications = notifier
		options.Sensitive = sensitive
	})
	reply = callAPI(t, noAudit, http.MethodPost, "/admin/v1/notifications/test",
		`{"confirm":true}`, authz, nil)
	requireErrorCode(t, reply, http.StatusServiceUnavailable, codeMailDiagnosticsUnavailable)

	// 全部装配：缺确认 400；成功只返回本地捕获摘要并写真实审计。
	server := newDomainStubServer(t, nil, nil, nil, nil, func(options *Options) {
		options.Notifications = notifier
		options.Sensitive = sensitive
		options.AuditRecorder = auditRecorder
	})
	reply = callAPI(t, server, http.MethodPost, "/admin/v1/notifications/test",
		`{}`, authz, nil)
	requireErrorCode(t, reply, http.StatusBadRequest, "REQ_INVALID")
	data := requireSuccess(t, callAPI(t, server, http.MethodPost,
		"/admin/v1/notifications/test", `{"confirm":true}`, authz, nil))
	capture, _ := data["capture"].(map[string]any)
	if capture["capture_id"] != "capture-1" || data["real_delivery"] != false {
		t.Fatalf("通知测试响应不符: %v", data)
	}
	if notifier.calls != 1 {
		t.Fatalf("本地捕获器调用次数 = %d，期望 1", notifier.calls)
	}
	auditRecorder.mu.Lock()
	if len(auditRecorder.events) != 1 ||
		auditRecorder.events[0].Outcome != audit.OutcomeSuccess {
		t.Fatalf("通知测试审计不符: %+v", auditRecorder.events)
	}
	auditRecorder.mu.Unlock()

	// 状态读取：返回脱敏配置。
	statusData := requireSuccess(t, callAPI(t, server, http.MethodGet,
		"/admin/v1/notifications", "", authz, nil))
	status, _ := statusData["notifications"].(map[string]any)
	if status["local_capture"] != true || status["delivery_mode"] != "local_capture" {
		t.Fatalf("通知状态投影不符: %v", status)
	}

	// 捕获器失败：映射稳定错误码并写失败审计，不伪成功。
	notifier.testErr = errors.New("本地捕获失败")
	reply = callAPI(t, server, http.MethodPost, "/admin/v1/notifications/test",
		`{"confirm":true}`, authz, nil)
	requireErrorCode(t, reply, http.StatusBadGateway, "MAIL_DELIVERY_FAILED")
	auditRecorder.mu.Lock()
	last := auditRecorder.events[len(auditRecorder.events)-1]
	auditRecorder.mu.Unlock()
	if last.Outcome != audit.OutcomeFailure {
		t.Fatalf("失败通知未写失败审计: %+v", last)
	}
}

// TestNotificationTestModeVerification 验证通知测试在执行前严格核验投递模式：
// 真实投递模式或状态读取失败都必须 fail-closed 并写拒绝审计，绝不执行测试器。
func TestNotificationTestModeVerification(t *testing.T) {
	authz := "Bearer management-secret"
	sensitive := &fakeSensitiveRunner{denied: map[string]bool{}}

	// 宿主声明非本地捕获（如 smtp）：拒绝执行、拒绝审计、测试器零调用。
	realDelivery := &fakeNotificationService{status: &NotificationStatus{
		Enabled: true, LocalCapture: false, DeliveryMode: "smtp",
		Channels: []string{"smtp"}}}
	auditRecorder := &fakeAuditRecorder{}
	server := newDomainStubServer(t, nil, nil, nil, nil, func(options *Options) {
		options.Notifications = realDelivery
		options.Sensitive = sensitive
		options.AuditRecorder = auditRecorder
	})
	reply := callAPI(t, server, http.MethodPost, "/admin/v1/notifications/test",
		`{"confirm":true}`, authz, nil)
	requireErrorCode(t, reply, http.StatusServiceUnavailable, codeNotificationTestDisabled)
	if realDelivery.calls != 0 {
		t.Fatalf("真实投递模式下仍调用了测试器：%d 次", realDelivery.calls)
	}
	auditRecorder.mu.Lock()
	if len(auditRecorder.events) != 1 ||
		auditRecorder.events[0].Outcome != audit.OutcomeFailure ||
		auditRecorder.events[0].ReasonCode != "notification_real_delivery_refused" {
		t.Fatalf("真实投递模式拒绝审计不符: %+v", auditRecorder.events)
	}
	auditRecorder.mu.Unlock()

	// 状态读取失败：fail-closed，测试器零调用，拒绝审计。
	statusFail := &fakeNotificationService{statusErr: errors.New("状态不可读")}
	failAudit := &fakeAuditRecorder{}
	failServer := newDomainStubServer(t, nil, nil, nil, nil, func(options *Options) {
		options.Notifications = statusFail
		options.Sensitive = sensitive
		options.AuditRecorder = failAudit
	})
	reply = callAPI(t, failServer, http.MethodPost, "/admin/v1/notifications/test",
		`{"confirm":true}`, authz, nil)
	requireErrorCode(t, reply, http.StatusServiceUnavailable, codeNotificationTestDisabled)
	if statusFail.calls != 0 {
		t.Fatalf("状态读取失败时仍调用了测试器：%d 次", statusFail.calls)
	}
	failAudit.mu.Lock()
	if len(failAudit.events) != 1 ||
		failAudit.events[0].ReasonCode != "notification_status_unavailable" {
		t.Fatalf("状态读取失败拒绝审计不符: %+v", failAudit.events)
	}
	failAudit.mu.Unlock()
}
