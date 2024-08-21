package ui_test

// 步骤 79 报告管理页面契约测试：路由注册/模板解析、历史与计划列表/详情、一次性短期
// 令牌下载响应头、计划创建/编辑/启停/删除预览、保留策略与清理确认、CSRF 与无权限
// 状态。使用受控页面后端替身，真实服务联调见 integration 用例（后续接入）。

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
)

const (
	reportsTestUserID = "usr_00000000000000000000000000000001"
	reportsTestCSRF   = "reports-csrf-token"
	reportsTestPlanID = "sch_11111111111111111111111111111111"
	reportsTestReport = "rpt_22222222222222222222222222222222"
)

// fakeReportsBackend 是报告页面后端替身（仅测试页面契约与响应）。
type fakeReportsBackend struct {
	caps        login.UIReportsCapabilities
	history     login.UIReportHistoryPage
	plan        login.UIReportPlan
	detail      login.UIReportDetail
	cleanup     login.UIReportCleanupPreview
	cleanupRun  login.UIReportCleanupResult
	file        login.UIReportFile
	failOn      string
	failCode    string
	lastReason  string
	lastFormat  string
	lastVersion int64
}

// fail 按方法名返回配置的稳定错误。
func (f *fakeReportsBackend) fail(method string) error {
	if f.failCode != "" && (f.failOn == "" || f.failOn == method) {
		return &login.UIReportsError{Code: f.failCode}
	}
	return nil
}

func (f *fakeReportsBackend) Capabilities(context.Context,
	string) (login.UIReportsCapabilities, error) {
	if err := f.fail("Capabilities"); err != nil {
		return login.UIReportsCapabilities{}, err
	}
	return f.caps, nil
}

func (f *fakeReportsBackend) RecordDenial(context.Context, string, string) error {
	return nil
}

func (f *fakeReportsBackend) ListPlans(context.Context,
	string) ([]login.UIReportPlan, error) {
	if err := f.fail("ListPlans"); err != nil {
		return nil, err
	}
	return []login.UIReportPlan{f.plan}, nil
}

func (f *fakeReportsBackend) GetPlan(context.Context, string,
	string) (login.UIReportPlan, error) {
	if err := f.fail("GetPlan"); err != nil {
		return login.UIReportPlan{}, err
	}
	return f.plan, nil
}

func (f *fakeReportsBackend) CreatePlan(_ context.Context, _ string,
	request login.UIReportPlanRequest, _ string) (login.UIReportPlan, error) {
	if err := f.fail("CreatePlan"); err != nil {
		return login.UIReportPlan{}, err
	}
	f.lastVersion = request.Version
	return f.plan, nil
}

func (f *fakeReportsBackend) UpdatePlan(_ context.Context, _, _ string,
	version int64, request login.UIReportPlanRequest,
	_ string) (login.UIReportPlan, error) {
	if err := f.fail("UpdatePlan"); err != nil {
		return login.UIReportPlan{}, err
	}
	f.lastVersion = version
	return f.plan, nil
}

func (f *fakeReportsBackend) SetPlanEnabled(_ context.Context, _, _ string,
	_ bool, reason, _ string) (login.UIReportPlan, error) {
	if err := f.fail("SetPlanEnabled"); err != nil {
		return login.UIReportPlan{}, err
	}
	f.lastReason = reason
	return f.plan, nil
}

func (f *fakeReportsBackend) PlanDeletePreview(context.Context, string,
	string) (login.UIReportPlanDeletePreview, error) {
	if err := f.fail("PlanDeletePreview"); err != nil {
		return login.UIReportPlanDeletePreview{}, err
	}
	return login.UIReportPlanDeletePreview{PlanID: reportsTestPlanID,
		Name: f.plan.Name, ScopeID: "system", Irreversible: true,
		ActiveTasksNote: "活动任务继续执行", HistoryNote: "历史按保留策略保留",
		RawAuditNote: "不删除原始审计"}, nil
}

func (f *fakeReportsBackend) DeletePlan(_ context.Context, _, _, reason,
	_ string) error {
	if err := f.fail("DeletePlan"); err != nil {
		return err
	}
	f.lastReason = reason
	return nil
}

func (f *fakeReportsBackend) ListHistory(context.Context, string,
	login.UIReportHistoryQuery) (login.UIReportHistoryPage, error) {
	if err := f.fail("ListHistory"); err != nil {
		return login.UIReportHistoryPage{}, err
	}
	return f.history, nil
}

func (f *fakeReportsBackend) GetReport(context.Context, string,
	string) (login.UIReportDetail, error) {
	if err := f.fail("GetReport"); err != nil {
		return login.UIReportDetail{}, err
	}
	return f.detail, nil
}

func (f *fakeReportsBackend) Download(_ context.Context, _, _ string,
	format string) (login.UIReportFile, error) {
	if err := f.fail("Download"); err != nil {
		return login.UIReportFile{}, err
	}
	f.lastFormat = format
	return f.file, nil
}

func (f *fakeReportsBackend) Cancel(_ context.Context, _, reportID, reason,
	_ string) (login.UIReportCancelResult, error) {
	if err := f.fail("Cancel"); err != nil {
		return login.UIReportCancelResult{}, err
	}
	f.lastReason = reason
	return login.UIReportCancelResult{ReportID: reportID, Accepted: true,
		State: "cancel_requested",
		Note:  "取消请求已受理，等待任务状态收敛；受理不等于实际取消。"}, nil
}

func (f *fakeReportsBackend) Preview(context.Context, string,
	string) (login.UIReportPreview, error) {
	if err := f.fail("Preview"); err != nil {
		return login.UIReportPreview{}, err
	}
	return login.UIReportPreview{ReportID: reportsTestReport,
		OverallStatus: "complete", ActivityTotal: 3, RawEvents: 5,
		FailedRequests: 2, DetailRowCount: 1,
		WindowWithinRetention: true, RetentionDays: 30}, nil
}

func (f *fakeReportsBackend) Retry(_ context.Context, _, reportID, reason,
	_ string) (login.UIReportDetail, error) {
	if err := f.fail("Retry"); err != nil {
		return login.UIReportDetail{}, err
	}
	f.lastReason = reason
	f.lastFormat = reportID
	return f.detail, nil
}

func (f *fakeReportsBackend) CleanupPreview(context.Context,
	string) (login.UIReportCleanupPreview, error) {
	if err := f.fail("CleanupPreview"); err != nil {
		return login.UIReportCleanupPreview{}, err
	}
	return f.cleanup, nil
}

func (f *fakeReportsBackend) RunCleanup(_ context.Context, _, reason,
	_ string) (login.UIReportCleanupResult, error) {
	if err := f.fail("RunCleanup"); err != nil {
		return login.UIReportCleanupResult{}, err
	}
	f.lastReason = reason
	return f.cleanupRun, nil
}

// reportsPageSessions 提供管理会话。
type reportsPageSessions struct{}

func (reportsPageSessions) ResolvePageSession(context.Context,
	*http.Request) (login.UISession, error) {
	return login.UISession{Authenticated: true, UserID: reportsTestUserID,
		Kind: "management", ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func (reportsPageSessions) IssueCSRFToken(context.Context, *http.Request) (string, error) {
	return reportsTestCSRF, nil
}

type reportsPageEnv struct {
	handler http.Handler
	backend *fakeReportsBackend
}

// newReportsPageEnv 构造报告页面测试环境。
func newReportsPageEnv(t *testing.T) *reportsPageEnv {
	t.Helper()
	now := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	backend := &fakeReportsBackend{
		caps: login.UIReportsCapabilities{Read: true, Generate: true, Export: true,
			ScheduleManage: true, Cleanup: true, DownloadTTL: 5 * time.Minute},
		history: login.UIReportHistoryPage{Records: []login.UIReportHistoryEntry{{
			ID: reportsTestReport, Name: "每日报告", ScopeID: "system",
			ScopeKind: "system", State: "succeeded", Formats: []string{"html"},
			Owner: "user · " + reportsTestUserID, CreatedAt: now,
			ExpiresAt: now.Add(24 * time.Hour)}}},
		plan: login.UIReportPlan{ID: reportsTestPlanID, Version: 1,
			Name: "每日安全报告", Enabled: true, PermissionState: "ok",
			ScheduleType: "daily", Expression: "09:00", TimeZone: "Asia/Shanghai",
			PeriodDescription: "每天 09:00", ScopeID: "system", ScopeKind: "system",
			Granularity: "day", WindowDays: 1, Formats: []string{"html"},
			MissedPolicy: "latest", MaxCatchUp: 1, Owner: "user · x",
			ExecutionActor: "user · x", NextRun: now.Add(23 * time.Hour),
			CreatedAt: now, UpdatedAt: now},
		detail: login.UIReportDetail{ID: reportsTestReport, ScopeID: "system",
			ScopeKind: "system", State: "succeeded", RequestedBy: "user · x",
			CreatedAt: now, GeneratedAt: now, Formats: []string{"html"},
			Artifacts: []login.UIReportArtifact{{Format: "html", Bytes: 4,
				Available: true, ExpiresAt: now.Add(24 * time.Hour)}}},
		cleanup: login.UIReportCleanupPreview{Policy: login.UIReportRetentionPolicy{
			ArtifactTTL: 24 * time.Hour, CleanupGrace: 7 * 24 * time.Hour,
			EligibleBefore: now, Source: "服务端配置",
			HistoryNote: "只删产物文件", RawAuditNote: "不删除原始审计"},
			Targets: []login.UIReportCleanupTarget{{ReportID: reportsTestReport,
				Name: "历史报告", ExpiresAt: now, ArtifactCount: 1, Bytes: 10}},
			TargetCount: 1, TotalBytes: 10, Note: "预览不是授权"},
		cleanupRun: login.UIReportCleanupResult{RequestedCount: 1, CleanedCount: 1,
			DeletedFiles: 1, FreedBytes: 10, RawAuditNote: "原始审计未删除"},
		file: login.UIReportFile{ReportID: reportsTestReport, Format: "html",
			FileName:    "report_" + reportsTestReport + ".html",
			ContentType: "text/html; charset=utf-8", Bytes: []byte("<html/>"),
			Size: 7},
	}
	ui, err := login.NewWebUI(login.WebUIOptions{
		Session: reportsPageSessions{},
		Logger:  slog.New(slog.NewTextHandler(os.Stderr, nil)),
		PageReports: &login.UIPageReportsOptions{
			Backend: backend,
			ValidateCSRF: func(context.Context, *http.Request, string) error {
				return nil
			},
		}})
	if err != nil {
		t.Fatalf("报告页面框架: %v", err)
	}
	return &reportsPageEnv{handler: ui, backend: backend}
}

// request 发送测试请求。
func (e *reportsPageEnv) request(method, target string, body []byte) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "http://example.test"+target,
		bytes.NewReader(body))
	if body != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	recorder := httptest.NewRecorder()
	e.handler.ServeHTTP(recorder, request)
	return recorder
}

// get 发送 GET 请求。
func (e *reportsPageEnv) get(target string) *httptest.ResponseRecorder {
	return e.request(http.MethodGet, target, nil)
}

// post 发送携带 CSRF 的 POST 表单。
func (e *reportsPageEnv) post(target string, values url.Values) *httptest.ResponseRecorder {
	values.Set("csrf_token", reportsTestCSRF)
	return e.request(http.MethodPost, target, []byte(values.Encode()))
}

// TestReportsPagesRenderAndStates 验证页面模板可解析、列表/详情渲染与无权限状态。
func TestReportsPagesRenderAndStates(t *testing.T) {
	env := newReportsPageEnv(t)
	history := env.get("/admin/reports")
	if history.Code != http.StatusOK || !strings.Contains(history.Body.String(), reportsTestReport) {
		t.Fatalf("历史列表状态=%d 缺少报告编号: %d", history.Code, len(history.Body.String()))
	}
	detail := env.get("/admin/reports/detail?report_id=" + reportsTestReport)
	if detail.Code != http.StatusOK || !strings.Contains(detail.Body.String(), "下载") {
		t.Fatalf("报告详情状态=%d", detail.Code)
	}
	routes := []string{"/admin/reports/schedules",
		"/admin/reports/schedules/detail?plan_id=" + reportsTestPlanID,
		"/admin/reports/schedules/new",
		"/admin/reports/schedules/edit?plan_id=" + reportsTestPlanID,
		"/admin/reports/schedules/delete?plan_id=" + reportsTestPlanID,
		"/admin/reports/retention"}
	for _, route := range routes {
		response := env.get(route)
		if response.Code != http.StatusOK {
			t.Fatalf("%s 状态=%d", route, response.Code)
		}
	}
	env.backend.caps.Read = false
	forbidden := env.get("/admin/reports")
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("无权限历史列表状态=%d，期望 403", forbidden.Code)
	}
}

// TestReportsDownloadHeaders 验证下载走 POST+CSRF、响应禁止缓存与 Referer 传递。
func TestReportsDownloadHeaders(t *testing.T) {
	env := newReportsPageEnv(t)
	response := env.post("/admin/reports/download", url.Values{
		"report_id": {reportsTestReport}, "format": {"html"}})
	if response.Code != http.StatusOK || response.Body.String() != "<html/>" {
		t.Fatalf("下载状态=%d body=%q", response.Code, response.Body.String())
	}
	for header, want := range map[string]string{
		"Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
		"X-Content-Type-Options": "nosniff",
		"Content-Type":           "text/html; charset=utf-8",
	} {
		if got := response.Header().Get(header); !strings.Contains(got, want) {
			t.Fatalf("%s=%q，期望包含 %q", header, got, want)
		}
	}
	if disposition := response.Header().Get("Content-Disposition"); !strings.Contains(
		disposition, "attachment") {
		t.Fatalf("Content-Disposition=%q", disposition)
	}
	// CSRF 缺失必须拒绝。
	request := httptest.NewRequest(http.MethodPost, "http://example.test/admin/reports/download",
		strings.NewReader(url.Values{"report_id": {reportsTestReport},
			"format": {"html"}}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	env.handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("缺 CSRF 下载状态=%d，期望 403", recorder.Code)
	}
}

// TestReportsPlanMutationsRequireCSRFAndVersion 验证计划创建/编辑/启停/删除与 CSRF。
func TestReportsPlanMutationsRequireCSRFAndVersion(t *testing.T) {
	env := newReportsPageEnv(t)
	values := url.Values{
		"name": {"每日报告"}, "schedule_type": {"daily"}, "expression": {"09:00"},
		"time_zone": {"Asia/Shanghai"}, "granularity": {"day"},
		"window_days": {"1"}, "formats": {"html"}, "detail_rows": {"20"},
		"missed_policy": {"latest"}, "max_catch_up": {"1"},
		"timeout_seconds": {"600"}, "max_attempts": {"1"}, "version": {"0"},
	}
	created := env.post("/admin/reports/schedules/create", values)
	if created.Code != http.StatusSeeOther && created.Code != http.StatusFound {
		t.Fatalf("创建计划状态=%d，期望重定向", created.Code)
	}
	update := url.Values{}
	for key, list := range values {
		update[key] = list
	}
	update.Set("plan_id", reportsTestPlanID)
	update.Set("version", "1")
	updated := env.post("/admin/reports/schedules/update", update)
	if updated.Code != http.StatusSeeOther && updated.Code != http.StatusFound {
		t.Fatalf("编辑计划状态=%d", updated.Code)
	}
	if env.backend.lastVersion != 1 {
		t.Fatalf("编辑行版本=%d，期望 1", env.backend.lastVersion)
	}
	missingCSRF := env.request(http.MethodPost, "/admin/reports/schedules/state",
		[]byte(url.Values{"plan_id": {reportsTestPlanID}, "enabled": {"0"}}.Encode()))
	if missingCSRF.Code != http.StatusForbidden {
		t.Fatalf("缺 CSRF 启停状态=%d", missingCSRF.Code)
	}
	state := env.post("/admin/reports/schedules/state", url.Values{
		"plan_id": {reportsTestPlanID}, "enabled": {"0"}, "reason": {"例行维护"}})
	if state.Code != http.StatusSeeOther && state.Code != http.StatusFound {
		t.Fatalf("启停计划状态=%d", state.Code)
	}
	deleted := env.post("/admin/reports/schedules/delete", url.Values{
		"plan_id": {reportsTestPlanID}, "reason": {"不再需要"}})
	if deleted.Code != http.StatusSeeOther && deleted.Code != http.StatusFound {
		t.Fatalf("删除计划状态=%d", deleted.Code)
	}
	missingReason := env.post("/admin/reports/schedules/delete", url.Values{
		"plan_id": {reportsTestPlanID}})
	if missingReason.Code != http.StatusBadRequest {
		t.Fatalf("缺删除原因状态=%d，期望 400", missingReason.Code)
	}
}

// TestReportsCancelEntry 验证取消请求页面入口：CSRF/原因/无权限/非法状态真实
// 呈现，且不把“请求已受理”写成“已取消”。
func TestReportsCancelEntry(t *testing.T) {
	env := newReportsPageEnv(t)
	missing := env.request(http.MethodPost, "/admin/reports/cancel",
		[]byte(url.Values{"report_id": {reportsTestReport}, "reason": {"取消"}}.Encode()))
	if missing.Code != http.StatusForbidden {
		t.Fatalf("缺 CSRF 取消状态=%d", missing.Code)
	}
	missingReason := env.post("/admin/reports/cancel", url.Values{
		"report_id": {reportsTestReport}})
	if missingReason.Code != http.StatusBadRequest {
		t.Fatalf("缺取消原因状态=%d", missingReason.Code)
	}
	accepted := env.post("/admin/reports/cancel", url.Values{
		"report_id": {reportsTestReport}, "reason": {"不再需要"}})
	if accepted.Code != http.StatusOK ||
		!strings.Contains(accepted.Body.String(), "取消请求已受理") {
		t.Fatalf("取消受理状态=%d body 缺少受理提示", accepted.Code)
	}
	env.backend.caps.Generate = false
	denied := env.post("/admin/reports/cancel", url.Values{
		"report_id": {reportsTestReport}, "reason": {"无权取消"}})
	if denied.Code != http.StatusForbidden {
		t.Fatalf("无权取消状态=%d", denied.Code)
	}
	env.backend.caps.Generate = true
	env.backend.failOn = "Cancel"
	env.backend.failCode = "CONFLICT"
	invalidState := env.post("/admin/reports/cancel", url.Values{
		"report_id": {reportsTestReport}, "reason": {"非法状态"}})
	if invalidState.Code != http.StatusConflict {
		t.Fatalf("非法状态取消状态=%d，期望 409", invalidState.Code)
	}
	env.backend.failOn = ""
	env.backend.failCode = ""
}

// TestReportsPreviewFailureVisible 验证预览读取失败时详情页显示失败横幅（而不是
// 静默无提示），且元数据仍可查看。
func TestReportsPreviewFailureVisible(t *testing.T) {
	env := newReportsPageEnv(t)
	env.backend.failOn = "Preview"
	env.backend.failCode = "UNAVAILABLE"
	response := env.get("/admin/reports/detail?report_id=" + reportsTestReport)
	if response.Code != http.StatusOK {
		t.Fatalf("预览失败时详情状态=%d，期望仍 200", response.Code)
	}
	if !strings.Contains(response.Body.String(), "预览暂时无法读取") {
		t.Fatalf("预览失败横幅缺失: body 长度=%d", len(response.Body.String()))
	}
	env.backend.failOn = ""
	env.backend.failCode = ""
}

// TestReportsCleanupRequiresCSRFAndShowsResult 验证清理确认与真实结果呈现。
func TestReportsCleanupRequiresCSRFAndShowsResult(t *testing.T) {
	env := newReportsPageEnv(t)
	missing := env.request(http.MethodPost, "/admin/reports/cleanup",
		[]byte(url.Values{"reason": {"清理过期报告"}}.Encode()))
	if missing.Code != http.StatusForbidden {
		t.Fatalf("缺 CSRF 清理状态=%d", missing.Code)
	}
	missingReason := env.post("/admin/reports/cleanup", url.Values{})
	if missingReason.Code != http.StatusBadRequest {
		t.Fatalf("缺清理原因状态=%d", missingReason.Code)
	}
	done := env.post("/admin/reports/cleanup", url.Values{"reason": {"清理过期报告"}})
	if done.Code != http.StatusOK {
		t.Fatalf("执行清理状态=%d", done.Code)
	}
	if env.backend.lastReason != "清理过期报告" {
		t.Fatalf("清理原因未传递: %q", env.backend.lastReason)
	}
}
