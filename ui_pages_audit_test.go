package login_test

// 步骤 74 审计与错误诊断页面契约测试：受控 UIPageAuditBackend 渲染、筛选/分页/
// 关联/披露状态/导出与清理状态机/越权与状态/不可信文本转义。真实服务集成见
// internal/uiadminadapter/audit_integration_test.go。

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
)

// fakeAuditBackend 是页面契约测试使用的受控后端；记录最后一次查询以便断言
// 页面确实传入了筛选/编号，而不是在前端伪造。
type fakeAuditBackend struct {
	capabilities login.UIAuditCapabilities

	page       login.UIAuditPage
	ownPage    login.UIAuditPage
	detail     login.UIAuditDetail
	ownDetail  login.UIAuditDetail
	search     login.UIErrorSearch
	exports    []login.UIAuditExport
	exportPage login.UIAuditExportPage
	exportView login.UIAuditExport
	exportFile login.UIAuditExportFile
	retention  login.UIPurgeRetention
	runs       []login.UIPurgeRun
	preview    login.UIPurgePreview
	run        login.UIPurgeRun

	failCode         string
	failIs           error
	lastQuery        login.UIAuditQuery
	lastOwn          bool
	started          bool
	cancelled        bool
	lastExport       string
	lastPurge        login.UIPurgeRequest
	lastDigest       string
	lastReason       string
	lastUserID       string
	lastRequestID    string
	downloadCount    int
	purgeContextFail bool
	denials          []string
}

func (f *fakeAuditBackend) fail() error {
	if f.failCode != "" {
		return &login.UIAuditError{Code: f.failCode}
	}
	return f.failIs
}

func (f *fakeAuditBackend) Capabilities(context.Context,
	string) (login.UIAuditCapabilities, error) {
	// 能力位读取失败不是本测试要模拟的场景；失败只注入具体业务方法。
	return f.capabilities, nil
}

func (f *fakeAuditBackend) ListAudit(_ context.Context, userID string,
	query login.UIAuditQuery) (login.UIAuditPage, error) {
	f.lastQuery, f.lastUserID = query, userID
	if err := f.fail(); err != nil {
		return login.UIAuditPage{}, err
	}
	return f.page, nil
}

func (f *fakeAuditBackend) GetAudit(_ context.Context, userID, eventID string,
	_ time.Time) (login.UIAuditDetail, error) {
	f.lastUserID = userID
	if eventID == "aud_missing" {
		return login.UIAuditDetail{}, &login.UIAuditError{Code: "NOT_FOUND", Disclosed: true}
	}
	if eventID == "aud_hidden" {
		return login.UIAuditDetail{}, &login.UIAuditError{Code: "NOT_FOUND"}
	}
	if eventID == "aud_expired" {
		return login.UIAuditDetail{}, &login.UIAuditError{Code: "RETENTION_EXPIRED", Disclosed: true}
	}
	if eventID == "aud_forbidden" {
		return login.UIAuditDetail{}, &login.UIAuditError{Code: "ACCESS_DENIED"}
	}
	if err := f.fail(); err != nil {
		return login.UIAuditDetail{}, err
	}
	return f.detail, nil
}

func (f *fakeAuditBackend) QueryOwnActivity(_ context.Context, userID string,
	query login.UIAuditQuery) (login.UIAuditPage, error) {
	f.lastOwn, f.lastQuery, f.lastUserID = true, query, userID
	if err := f.fail(); err != nil {
		return login.UIAuditPage{}, err
	}
	return f.ownPage, nil
}

func (f *fakeAuditBackend) GetOwnActivity(_ context.Context, userID, _ string,
	_ time.Time) (login.UIAuditDetail, error) {
	f.lastOwn, f.lastUserID = true, userID
	if err := f.fail(); err != nil {
		return login.UIAuditDetail{}, err
	}
	return f.ownDetail, nil
}

func (f *fakeAuditBackend) SearchErrors(context.Context, string,
	login.UIErrorQuery) (login.UIErrorSearch, error) {
	if err := f.fail(); err != nil {
		return login.UIErrorSearch{}, err
	}
	return f.search, nil
}

func (f *fakeAuditBackend) CreateExport(_ context.Context, userID string,
	request login.UIAuditExportRequest) (login.UIAuditExport, error) {
	f.lastUserID, f.lastQuery.Filter, f.lastRequestID, f.started = userID, request.Filter,
		request.RequestID, true
	if err := f.fail(); err != nil {
		return login.UIAuditExport{}, err
	}
	return f.exportView, nil
}

func (f *fakeAuditBackend) ListExports(context.Context, string, string, string, int,
	int) (login.UIAuditExportPage, error) {
	if err := f.fail(); err != nil {
		return login.UIAuditExportPage{}, err
	}
	return f.exportPage, nil
}

func (f *fakeAuditBackend) GetExport(_ context.Context, _, exportID string) (login.UIAuditExport, error) {
	f.lastExport = exportID
	if err := f.fail(); err != nil {
		return login.UIAuditExport{}, err
	}
	return f.exportView, nil
}

func (f *fakeAuditBackend) CancelExport(_ context.Context, _, exportID, reason,
	_ string) (login.UIAuditExport, error) {
	f.lastExport, f.lastReason = exportID, reason
	if err := f.fail(); err != nil {
		return login.UIAuditExport{}, err
	}
	view := f.exportView
	view.State = "cancel_requested"
	f.cancelled = true
	return view, nil
}

func (f *fakeAuditBackend) DownloadExport(context.Context, string,
	string) (login.UIAuditExportFile, error) {
	if err := f.fail(); err != nil {
		return login.UIAuditExportFile{}, err
	}
	f.downloadCount++
	return f.exportFile, nil
}

func (f *fakeAuditBackend) RecordDenial(_ context.Context, _, reason string) error {
	f.denials = append(f.denials, reason)
	return nil
}

func (f *fakeAuditBackend) PurgeContext(context.Context, string, string, int,
	int) (login.UIPurgeContext, error) {
	if f.purgeContextFail {
		return login.UIPurgeContext{}, &login.UIAuditError{Code: "DB_UNAVAILABLE"}
	}
	if err := f.fail(); err != nil {
		return login.UIPurgeContext{}, err
	}
	return login.UIPurgeContext{Retention: f.retention, Runs: f.runs}, nil
}

func (f *fakeAuditBackend) PreviewPurge(_ context.Context, _ string,
	request login.UIPurgeRequest) (login.UIPurgePreview, error) {
	f.lastPurge = request
	if err := f.fail(); err != nil {
		return login.UIPurgePreview{}, err
	}
	return f.preview, nil
}

func (f *fakeAuditBackend) StartPurge(_ context.Context, _ string,
	request login.UIPurgeRequest, digest, reason,
	_ string) (login.UIPurgeRun, error) {
	f.lastPurge, f.lastDigest, f.lastReason = request, digest, reason
	if err := f.fail(); err != nil {
		return login.UIPurgeRun{}, err
	}
	return f.run, nil
}

func (f *fakeAuditBackend) CancelPurge(_ context.Context, _, runID, reason,
	_ string) (login.UIPurgeRun, error) {
	f.lastReason = reason
	if err := f.fail(); err != nil {
		return login.UIPurgeRun{}, err
	}
	run := f.run
	run.State = "cancel_requested"
	return run, nil
}

// auditPageSessions 提供页面会话；failure 用于会话过期/无权限状态。
type auditPageSessions struct {
	kind    string
	userID  string
	failure error
}

func (s auditPageSessions) ResolvePageSession(context.Context,
	*http.Request) (login.UISession, error) {
	if s.failure != nil {
		return login.UISession{}, s.failure
	}
	kind, userID := s.kind, s.userID
	if kind == "" {
		kind = "management"
	}
	if userID == "" {
		userID = "usr_admin"
	}
	return login.UISession{Authenticated: true, UserID: userID, Kind: kind,
		ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func (auditPageSessions) IssueCSRFToken(context.Context, *http.Request) (string, error) {
	return "audit-csrf", nil
}

type auditPageEnv struct {
	t       *testing.T
	handler http.Handler
	backend *fakeAuditBackend
}

// baseAuditBackend 返回带合成事件/任务状态的受控后端。
func baseAuditBackend() *fakeAuditBackend {
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	event := login.UIAuditEventView{ID: "aud_0123456789abcdef0123456789abcdef",
		OccurredAt: now, ActorType: "user", ActorID: "usr_actor", AppID: "app_demo",
		Action: "session.revoke", TargetType: "user", TargetID: "usr_target",
		Outcome: "success", ErrorCode: "ACCESS_DENIED", RequestID: "req_abc123",
		TaskID: "job_task01"}
	backend := &fakeAuditBackend{
		capabilities: login.UIAuditCapabilities{Read: true, Export: true, Purge: true},
		page: login.UIAuditPage{Events: []login.UIAuditEventView{event}, HasMore: true,
			Limit: 20, Offset: 0, Order: "occurred_desc", ScopeID: "system",
			ScopeKind: "system", RetentionDays: 180, RetentionConfigured: true,
			RetentionCutoff: now.AddDate(0, 0, -180), DataScope: "全部数据范围"},
		ownPage: login.UIAuditPage{Events: []login.UIAuditEventView{event}, Limit: 20,
			RetentionDays: 180, DataScope: "仅限你本人的安全活动记录"},
		detail: login.UIAuditDetail{Event: event, ScopeID: "system", ScopeKind: "system",
			RetentionDays: 180, ErrorCode: "ACCESS_DENIED",
			Error: login.UIErrorEntry{Code: "ACCESS_DENIED", Category: "权限",
				Message: "请求未获准", Cause: "角色未包含该权限", Advice: "检查角色来源",
				Retry: "授权后", HasGuidance: true, HasHTTPStatus: true, HTTPStatus: 403},
			Changes: []login.UIAuditChange{{Field: "nickname", Before: "old",
				After: "[REDACTED]", Redacted: true}},
			RelatedTask: &login.UIExportTaskSummary{ID: "job_task01",
				State: "running", Attempt: 2, MaxAttempts: 3,
				FailureReason: "上次尝试超时"}},
		ownDetail: login.UIAuditDetail{Event: event, RetentionDays: 180,
			ErrorCode: "ACCESS_DENIED",
			Error: login.UIErrorEntry{Code: "ACCESS_DENIED", Message: "请求未获准",
				Cause: "角色未包含该权限", Advice: "检查角色来源", Retry: "授权后",
				HasGuidance: true}},
		search: login.UIErrorSearch{Searched: true, Entries: []login.UIErrorEntry{
			{Code: "ACCESS_DENIED", Category: "权限", Message: "请求未获准",
				Cause: "角色未包含该权限", Advice: "检查角色来源", Retry: "授权后",
				HasGuidance: true, HasHTTPStatus: true, HTTPStatus: 403}}},
		exportView: login.UIAuditExport{ID: "aex_0123", ScopeID: "system", Format: "csv",
			State: "queued", TaskID: "job_export01", MaxRows: 500, RequestID: "req_export",
			CreatedAt: now, Task: &login.UIExportTaskSummary{ID: "job_export01",
				State: "queued", Attempt: 1, MaxAttempts: 3}},
		exportPage: login.UIAuditExportPage{Exports: []login.UIAuditExport{
			{ID: "aex_0123", Format: "csv", State: "cancel_requested", TaskID: "job_export01"}}},
		exportFile: login.UIAuditExportFile{Name: "audit_export_aex_0123.csv",
			ContentType: "text/csv; charset=utf-8", Body: []byte("id,action\n")},
		retention: login.UIPurgeRetention{Days: 180, Configured: true, Version: 2,
			Cutoff: now.AddDate(0, 0, -180)},
		runs: []login.UIPurgeRun{{ID: "amr_0123", State: "running", TaskID: "job_purge01",
			ScopeID: "system", Cutoff: now.AddDate(0, 0, -200), BatchSize: 500,
			MaxRecords: 100000, Scanned: 10, Cleaned: 4, Failed: 1}},
		preview: login.UIPurgePreview{ScopeID: "system", ScopeKind: "system",
			Cutoff: now.AddDate(0, 0, -200), BatchSize: 500, MaxRecords: 100000,
			EstimatedCount: 42, AtLeast: true, WithinRetention: false,
			MaintenanceProtected: true, Digest: "digest_abc", GeneratedAt: now,
			Retention: login.UIPurgeRetention{Days: 180, Cutoff: now.AddDate(0, 0, -180)}},
		run: login.UIPurgeRun{ID: "amr_0456", State: "queued", TaskID: "job_purge02",
			ScopeID: "system", Cleaned: 0, Scanned: 0},
	}
	return backend
}

func newAuditPageEnv(t *testing.T, backend *fakeAuditBackend,
	sessions auditPageSessions) *auditPageEnv {
	t.Helper()
	ui, err := login.NewWebUI(login.WebUIOptions{Session: sessions,
		PageAudit: &login.UIPageAuditOptions{Backend: backend,
			Now: func() time.Time {
				return time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
			},
			ValidateCSRF: func(context.Context, *http.Request, string) error { return nil }}})
	if err != nil {
		t.Fatalf("审计页框架构造失败: %v", err)
	}
	return &auditPageEnv{t: t, handler: ui, backend: backend}
}

func (e *auditPageEnv) get(target string) *httptest.ResponseRecorder {
	return e.do(http.MethodGet, target, nil)
}

func (e *auditPageEnv) post(target string, values url.Values) *httptest.ResponseRecorder {
	if values == nil {
		values = url.Values{}
	}
	if values.Get("csrf_token") == "" {
		values.Set("csrf_token", "audit-csrf")
	}
	return e.do(http.MethodPost, target, values)
}

func (e *auditPageEnv) do(method, target string, values url.Values) *httptest.ResponseRecorder {
	e.t.Helper()
	var body *strings.Reader
	if values != nil {
		body = strings.NewReader(values.Encode())
	} else {
		body = strings.NewReader("")
	}
	request := httptest.NewRequest(method, "http://example.test"+target, body)
	if values != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	recorder := httptest.NewRecorder()
	e.handler.ServeHTTP(recorder, request)
	return recorder
}

func requireAuditBody(t *testing.T, response *httptest.ResponseRecorder, status int,
	fragments ...string) string {
	t.Helper()
	body := response.Body.String()
	if response.Code != status {
		t.Fatalf("状态 = %d，期望 %d；完整页面：%s", response.Code, status, body)
	}
	for _, fragment := range fragments {
		if !strings.Contains(body, fragment) {
			t.Fatalf("页面缺少 %q；前 200 字符：%s", fragment, firstRunes(body, 200))
		}
	}
	return body
}

func firstRunes(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit])
}

// TestAuditListFiltersPaginationAndCorrelation 验证列表筛选透传、分页保留筛选、
// request_id/task_id 精确关联与表格可访问性钩子。
func TestAuditListFiltersPaginationAndCorrelation(t *testing.T) {
	backend := baseAuditBackend()
	env := newAuditPageEnv(t, backend, auditPageSessions{})
	body := requireAuditBody(t, env.get("/admin/audit?from=2026-11-01&to=2026-11-18&"+
		"outcome=success&error_code=ACCESS_DENIED&request_id=req_abc123&task_id=job_task01&limit=20"),
		http.StatusOK, "session.revoke", "当前授权范围内的结果", "查看同一请求", "查看同一任务")
	if backend.lastQuery.Filter.RequestID != "req_abc123" ||
		backend.lastQuery.Filter.TaskID != "job_task01" ||
		backend.lastQuery.Filter.Outcome != "success" ||
		backend.lastQuery.Filter.ErrorCode != "ACCESS_DENIED" {
		t.Fatalf("筛选未透传：%+v", backend.lastQuery.Filter)
	}
	if backend.lastUserID != "usr_admin" {
		t.Fatalf("页面未使用会话用户 ID：%q", backend.lastUserID)
	}
	if !strings.Contains(body, "ln-table-scroll") || !strings.Contains(body, "<caption>") ||
		!strings.Contains(body, `scope="col"`) {
		t.Fatal("列表缺少表格可访问性/窄屏滚动钩子")
	}
	// 日期筛选必须回显，导出表单继承同一时间范围；列表有直白说明与可见数据范围。
	if !strings.Contains(body, `value="2026-11-01"`) ||
		!strings.Contains(body, `value="2026-11-18"`) {
		t.Fatal("日期筛选未回显")
	}
	if !strings.Contains(body, "结果：成功") || !strings.Contains(body, "全部数据范围") ||
		!strings.Contains(body, "直白说明") {
		t.Fatal("列表缺少直白说明或可见数据范围")
	}
	// 下一页链接保留筛选并递进 offset。
	if !strings.Contains(body, "offset=20") || !strings.Contains(body, "request_id=req_abc123") {
		t.Fatalf("分页链接未保留筛选：%s", firstRunes(body, 400))
	}
	// 非法筛选：字段错误、不得查询后端。
	backend.lastQuery = login.UIAuditQuery{}
	invalid := env.get("/admin/audit?outcome=bogus")
	requireAuditBody(t, invalid, http.StatusBadRequest, "筛选条件未通过校验")
	if backend.lastQuery.Limit != 0 {
		t.Fatal("非法筛选不应调用后端查询")
	}
	// 非法 request_id 格式同样拒绝。
	invalidID := env.get("/admin/audit?request_id=" + url.QueryEscape("../etc/passwd"))
	requireAuditBody(t, invalidID, http.StatusBadRequest, "筛选条件未通过校验")
}

// TestAuditListEmptyAndFailureStates 验证空列表与查询失败是不同状态。
func TestAuditListEmptyAndFailureStates(t *testing.T) {
	backend := baseAuditBackend()
	backend.page = login.UIAuditPage{ScopeID: "system", Limit: 20}
	env := newAuditPageEnv(t, backend, auditPageSessions{})
	emptyBody := requireAuditBody(t, env.get("/admin/audit"), http.StatusOK,
		"当前授权范围内尚无审计记录")
	if !strings.Contains(emptyBody, `<td colspan="10">`) {
		t.Fatal("列表空态 colspan 与列数不一致")
	}
	requireAuditBody(t, env.get("/admin/audit?outcome=success"), http.StatusOK,
		"没有符合这些条件的记录")
	backend.failCode = "DB_UNAVAILABLE"
	failed := env.get("/admin/audit")
	body := requireAuditBody(t, failed, http.StatusServiceUnavailable, "存储或审计服务暂时不可用")
	if strings.Contains(body, "尚无审计记录") {
		t.Fatal("失败不得伪装成空列表")
	}
}

// TestAuditDetailPublicAndRestrictedPartition 验证公开错误说明与受限诊断分区：
// 默认不显示受限原因码，获准后单独展示。
func TestAuditDetailPublicAndRestrictedPartition(t *testing.T) {
	backend := baseAuditBackend()
	env := newAuditPageEnv(t, backend, auditPageSessions{})
	body := requireAuditBody(t, env.get("/admin/audit/detail?event_id="+
		"aud_0123456789abcdef0123456789abcdef&occurred_at=2026-11-18T12%3A00%3A00Z"),
		http.StatusOK, "审计事件详情", "公开错误说明", "角色未包含该权限",
		"受限诊断（仅获准人员可见）", "已隐藏敏感值")
	if strings.Contains(body, "reason_unseen") {
		t.Fatal("无独立诊断权限时不得出现受限原因码")
	}
	// 获准后展示原因码，仍与公开区分离。
	backend.detail.Restricted = true
	backend.detail.RestrictedReasonCode = "reason_owner_mismatch"
	allowed := requireAuditBody(t, env.get("/admin/audit/detail?event_id="+
		"aud_0123456789abcdef0123456789abcdef"), http.StatusOK, "reason_owner_mismatch",
		"受限原因码")
	if strings.Index(allowed, "受限原因码") < strings.Index(allowed, "公开错误说明") {
		t.Fatal("受限诊断不得排在公开说明之前")
	}
}

// TestAuditDetailDisclosureStates 验证查无记录、无权限、保留期与不可披露互不伪装。
func TestAuditDetailDisclosureStates(t *testing.T) {
	env := newAuditPageEnv(t, baseAuditBackend(), auditPageSessions{})
	requireAuditBody(t, env.get("/admin/audit/detail?event_id=aud_missing"),
		http.StatusNotFound, "未找到该记录")
	requireAuditBody(t, env.get("/admin/audit/detail?event_id=aud_expired"),
		http.StatusGone, "该记录可能已超过保留期")
	requireAuditBody(t, env.get("/admin/audit/detail?event_id=aud_forbidden"),
		http.StatusForbidden, "服务端已拒绝访问")
	// 不允许披露时使用独立不可披露状态，不伪装成查无记录或保留期。
	backend := baseAuditBackend()
	backend.failIs = &login.UIAuditError{Code: "NOT_FOUND", Disclosed: false}
	hidden := newAuditPageEnv(t, backend, auditPageSessions{})
	requireAuditBody(t, hidden.get("/admin/audit/detail?event_id=aud_hidden"),
		http.StatusNotFound, "未获披露许可")
}

// TestAuditErrorCodesSearch 验证错误码检索显示同一注册表原因/建议/重试条件，
// 未知码不猜原因，受限诊断内容不进入公开区。
func TestAuditErrorCodesSearch(t *testing.T) {
	backend := baseAuditBackend()
	env := newAuditPageEnv(t, backend, auditPageSessions{})
	requireAuditBody(t, env.get("/admin/errors?code=ACCESS_DENIED"), http.StatusOK,
		"ACCESS_DENIED", "角色未包含该权限", "检查角色来源", "授权后")
	requireAuditBody(t, env.get("/admin/errors"), http.StatusOK, "错误码检索",
		"仅表示设计定义")
	backend.search = login.UIErrorSearch{Searched: true, UnknownCode: "NOT_REGISTERED"}
	requireAuditBody(t, env.get("/admin/errors?code=NOT_REGISTERED"), http.StatusOK,
		"NOT_REGISTERED 尚未登记")
	backend.search = login.UIErrorSearch{Searched: true}
	requireAuditBody(t, env.get("/admin/errors?keyword=x"), http.StatusOK,
		"注册表中没有符合当前条件的错误码")
}

// TestAuditExportsStatusMachineAndDownload 验证提交/取消/下载与“取消已请求≠已取消”。
func TestAuditExportsStatusMachineAndDownload(t *testing.T) {
	backend := baseAuditBackend()
	env := newAuditPageEnv(t, backend, auditPageSessions{})
	requireAuditBody(t, env.get("/admin/audit/exports"), http.StatusOK,
		"取消请求已接受（尚未实际取消）")
	created := env.post("/admin/audit/exports/create", url.Values{
		"format": {"csv"}, "outcome": {"success"}, "from": {"2026-11-01"},
		"to": {"2026-11-18"}, "filter_request_id": {"req_abc123"},
		"request_id": {"req_client_forged"}})
	requireAuditBody(t, created, http.StatusOK, "导出任务已提交，任务编号为 job_export01",
		"尚未执行完成")
	if !backend.started || backend.lastQuery.Filter.Outcome != "success" {
		t.Fatal("创建导出未透传筛选快照")
	}
	// 导出快照继承列表时间范围（含结束当天），且动作编号由服务端生成，不采用客户端值。
	if !backend.lastQuery.Filter.From.Equal(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)) ||
		!backend.lastQuery.Filter.To.Equal(time.Date(2026, 11, 18, 12, 1, 0, 0, time.UTC)) {
		t.Fatalf("导出时间范围 = %v ~ %v", backend.lastQuery.Filter.From,
			backend.lastQuery.Filter.To)
	}
	if backend.lastQuery.Filter.RequestID != "req_abc123" {
		t.Fatalf("筛选编号 = %q", backend.lastQuery.Filter.RequestID)
	}
	if backend.lastRequestID == "req_client_forged" || backend.lastRequestID == "" ||
		!strings.HasPrefix(backend.lastRequestID, "req_") {
		t.Fatalf("导出动作 request_id 未由服务端生成: %q", backend.lastRequestID)
	}
	// 详情 + 下载。
	requireAuditBody(t, env.get("/admin/audit/exports?export_id=aex_0123"),
		http.StatusOK, "导出任务详情")
	download := env.get("/admin/audit/exports/download?export_id=aex_0123")
	if download.Code != http.StatusOK || download.Body.String() != "id,action\n" {
		t.Fatalf("下载 = %d %q", download.Code, download.Body.String())
	}
	if !strings.Contains(download.Header().Get("Content-Disposition"),
		`filename="audit_export_aex_0123.csv"`) {
		t.Fatalf("下载文件名不安全：%q", download.Header().Get("Content-Disposition"))
	}
	// 取消：状态改为 cancel_requested，页面明确尚未实际取消。
	cancelled := env.post("/admin/audit/exports/cancel", url.Values{
		"export_id": {"aex_0123"}, "reason": {"owner request"}})
	requireAuditBody(t, cancelled, http.StatusOK, "尚未实际取消",
		"取消请求已接受")
	if !backend.cancelled {
		t.Fatal("取消请求未透传")
	}
	// 下载失败不把任务改成失败。
	backend.failCode = "CONFLICT"
	failed := env.get("/admin/audit/exports/download?export_id=aex_0123")
	if failed.Code != http.StatusConflict {
		t.Fatalf("下载失败状态 = %d", failed.Code)
	}
}

// TestAuditMaintenanceRootOnlyAndRealStateMachine 验证 root 门槛、预估确认页、
// 提交只表示已提交、取消请求与实际取消分开。
func TestAuditMaintenanceRootOnlyAndRealStateMachine(t *testing.T) {
	backend := baseAuditBackend()
	nonRoot := backend
	nonRoot.capabilities = login.UIAuditCapabilities{Read: true, Export: true}
	env := newAuditPageEnv(t, nonRoot, auditPageSessions{})
	requireAuditBody(t, env.get("/admin/audit/maintenance"), http.StatusForbidden,
		"只有 root 可以进入审计清理")
	requireAuditBody(t, env.post("/admin/audit/maintenance/preview", url.Values{
		"cutoff": {"2026-01-01"}, "reason": {"cleanup"}}), http.StatusForbidden)

	rootBackend := baseAuditBackend()
	rootEnv := newAuditPageEnv(t, rootBackend, auditPageSessions{})
	requireAuditBody(t, rootEnv.get("/admin/audit/maintenance"), http.StatusOK,
		"保留策略", "真实任务状态与计数")
	confirm := rootEnv.post("/admin/audit/maintenance/preview", url.Values{
		"cutoff": {"2026-01-01"}, "batch_size": {"500"}, "max_records": {"100000"},
		"reason": {"cleanup"}})
	requireAuditBody(t, confirm, http.StatusOK, "再次核对清理范围并确认",
		"至少 42", "不包含（本页不清理数据产物）", "不可通过本页面恢复")
	// 未携带预估摘要时拒绝提交，防止伪造/过期确认。
	requireAuditBody(t, rootEnv.post("/admin/audit/maintenance/start", url.Values{
		"cutoff": {"2026-01-01"}, "reason": {"cleanup"}}), http.StatusConflict,
		"确认摘要缺失或已过期")
	if rootBackend.lastDigest != "" {
		t.Fatal("缺少摘要时不得调用提交")
	}
	submitted := rootEnv.post("/admin/audit/maintenance/start", url.Values{
		"digest": {"digest_abc"}, "cutoff": {"2026-01-01"}, "batch_size": {"500"},
		"max_records": {"100000"}, "reason": {"cleanup"}})
	requireAuditBody(t, submitted, http.StatusOK, "清理任务已提交",
		"任务编号为 job_purge02")
	if rootBackend.lastDigest != "digest_abc" || rootBackend.lastPurge.Cutoff.IsZero() {
		t.Fatal("清理提交未绑定确认摘要与截止时间")
	}
	// 取消请求：只显示已接受，不显示已取消。
	rootBackend.run.State = "running"
	cancelled := rootEnv.post("/admin/audit/maintenance/cancel", url.Values{
		"digest": {"digest_abc"}, "cutoff": {"2026-01-01"}, "reason": {"cleanup"},
		"run_id": {"amr_0123"}})
	requireAuditBody(t, cancelled, http.StatusOK, "取消请求已接受")
}

// TestAuditExportFailureDoesNotFakeSuccess 验证导出创建/列表/下载失败不显示假成功、
// 不把旧数据冒充刚更新的结果。
func TestAuditExportFailureDoesNotFakeSuccess(t *testing.T) {
	backend := baseAuditBackend()
	env := newAuditPageEnv(t, backend, auditPageSessions{})
	backend.failCode = "DB_UNAVAILABLE"
	created := env.post("/admin/audit/exports/create", url.Values{"format": {"csv"}})
	body := requireAuditBody(t, created, http.StatusServiceUnavailable,
		"存储或审计服务暂时不可用")
	if strings.Contains(body, "导出任务已提交") {
		t.Fatal("创建失败不得显示已提交")
	}
	// 列表失败显示真实错误状态，不显示伪造的成功/上次成功徽标。
	failed := env.get("/admin/audit/exports")
	listBody := requireAuditBody(t, failed, http.StatusServiceUnavailable,
		"导出任务加载失败")
	if strings.Contains(listBody, "最后成功更新") {
		t.Fatal("加载失败不得显示最后成功更新时间")
	}
	// 下载失败不改写任务状态。
	backend.failCode = ""
	backend.downloadCount = 0
	backend.failIs = &login.UIAuditError{Code: "CONFLICT"}
	download := env.get("/admin/audit/exports/download?export_id=aex_0123")
	requireAuditBody(t, download, http.StatusConflict, "状态或版本已变化")
	if backend.downloadCount != 0 {
		t.Fatal("冲突时不得读取产物字节")
	}
}

// TestAuditDateBoundaryClamp 验证“结束日期含当天”在服务端时钟处钳制：to=今天 不再
// 被 auditops 判成未来而 400；to=未来日期同样钳制到今天末尾（语义明确）；列表、
// 本人活动与导出创建共用同一解析，范围一致。
func TestAuditDateBoundaryClamp(t *testing.T) {
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	clamped := now.Add(time.Minute)
	backend := baseAuditBackend()
	env := newAuditPageEnv(t, backend, auditPageSessions{})
	today := env.get("/admin/audit?to=2026-11-18")
	requireAuditBody(t, today, http.StatusOK, "审计记录")
	if !backend.lastQuery.Filter.To.Equal(clamped) {
		t.Fatalf("to=今天 上界 = %v，期望 %v", backend.lastQuery.Filter.To, clamped)
	}
	future := env.get("/admin/audit?to=2026-12-31")
	requireAuditBody(t, future, http.StatusOK, "审计记录")
	if !backend.lastQuery.Filter.To.Equal(clamped) {
		t.Fatalf("to=未来日期 上界 = %v，期望钳制 %v", backend.lastQuery.Filter.To, clamped)
	}
	// 本人活动同一钳制。
	ownEnv := newAuditPageEnv(t, backend, auditPageSessions{kind: "normal", userID: "usr_self"})
	requireAuditBody(t, ownEnv.get("/account/activity?to=2026-11-18"), http.StatusOK,
		"我的安全活动")
	if !backend.lastQuery.Filter.To.Equal(clamped) {
		t.Fatalf("本人活动上界 = %v", backend.lastQuery.Filter.To)
	}
	// 导出创建继承同一上界（与列表一致）。
	created := env.post("/admin/audit/exports/create", url.Values{
		"format": {"csv"}, "to": {"2026-11-18"}})
	requireAuditBody(t, created, http.StatusOK, "导出任务已提交")
	if !backend.lastQuery.Filter.To.Equal(clamped) {
		t.Fatalf("导出上界 = %v，期望与列表一致 %v", backend.lastQuery.Filter.To, clamped)
	}
}

// TestAuditPageStatesAndCSRF 验证会话过期、无权限与 CSRF 失败状态。
func TestAuditPageStatesAndCSRF(t *testing.T) {
	expired := newAuditPageEnv(t, baseAuditBackend(), auditPageSessions{
		failure: login.ErrUISessionExpired})
	requireAuditBody(t, expired.get("/admin/audit"), http.StatusUnauthorized,
		"会话已过期")
	forbidden := newAuditPageEnv(t, baseAuditBackend(), auditPageSessions{
		failure: login.ErrUIForbidden})
	requireAuditBody(t, forbidden.get("/admin/audit"), http.StatusForbidden, "当前账户没有查看该页面的权限")
	// 缺少 CSRF：拒绝，不调用后端。
	backend := baseAuditBackend()
	env := newAuditPageEnv(t, backend, auditPageSessions{})
	bad := env.do(http.MethodPost, "/admin/audit/exports/create",
		url.Values{"format": {"csv"}})
	requireAuditBody(t, bad, http.StatusForbidden, "表单安全令牌无效")
	if backend.started {
		t.Fatal("CSRF 失败不得创建导出任务")
	}
	// 无权限（能力位 false）不渲染管理内容。
	denied := baseAuditBackend()
	denied.capabilities = login.UIAuditCapabilities{}
	deniedEnv := newAuditPageEnv(t, denied, auditPageSessions{})
	body := requireAuditBody(t, deniedEnv.get("/admin/audit"), http.StatusForbidden,
		"服务端已拒绝访问")
	if strings.Contains(body, "session.revoke") {
		t.Fatal("无权限时不得显示记录正文")
	}
}

// TestAuditEscapesUntrustedText 验证昵称/目标/动作等不可信文本按输出格式转义。
func TestAuditEscapesUntrustedText(t *testing.T) {
	backend := baseAuditBackend()
	backend.page.Events[0].ActorID = `<script>alert(1)</script>`
	backend.page.Events[0].TargetID = `"><img src=x onerror=alert(1)>`
	backend.page.Events[0].Action = `<b>bold</b>`
	backend.detail = login.UIAuditDetail{Event: backend.page.Events[0],
		Changes: []login.UIAuditChange{{Field: "nickname", Before: `<script>x</script>`,
			After: `[REDACTED]`, Redacted: true}}}
	env := newAuditPageEnv(t, backend, auditPageSessions{})
	body := requireAuditBody(t, env.get("/admin/audit"), http.StatusOK, "&lt;script&gt;",
		"&lt;b&gt;")
	if strings.Contains(body, "<script>alert(1)</script>") ||
		strings.Contains(body, "<img src=x onerror=alert(1)>") {
		t.Fatal("不可信文本未转义")
	}
	detail := requireAuditBody(t, env.get("/admin/audit/detail?event_id="+
		"aud_0123456789abcdef0123456789abcdef"), http.StatusOK, "&lt;script&gt;")
	if strings.Contains(detail, "<script>x</script>") {
		t.Fatal("详情差异未转义")
	}
}

// TestAccountActivitySelfOnly 验证普通用户本人安全活动页使用本人查询接口、
// 不渲染管理导出/清理入口。
func TestAccountActivitySelfOnly(t *testing.T) {
	backend := baseAuditBackend()
	env := newAuditPageEnv(t, backend, auditPageSessions{kind: "normal", userID: "usr_self"})
	body := requireAuditBody(t, env.get("/account/activity?outcome=success"),
		http.StatusOK, "我的安全活动", "这里只显示与你本人相关", "session.revoke")
	if !backend.lastOwn || backend.lastUserID != "usr_self" {
		t.Fatal("本人安全活动未使用本人查询通道")
	}
	if strings.Contains(body, "创建导出任务") || strings.Contains(body, "清理审计记录") {
		t.Fatal("普通用户页面不得渲染管理导出/清理入口")
	}
	detail := requireAuditBody(t, env.get("/account/activity/detail?event_id="+
		"aud_0123456789abcdef0123456789abcdef"), http.StatusOK, "安全活动详情",
		"错误码", "角色未包含该权限")
	if strings.Contains(detail, "受限诊断") || strings.Contains(detail, "reason_") {
		t.Fatal("本人安全活动不得出现受限诊断内容")
	}
	if !backend.lastOwn {
		t.Fatal("本人详情未使用本人查询通道")
	}
}

// TestAuditResponsiveStaticContract 是窄屏可读性的静态契约检查：数据表位于可
// 聚焦局部滚动区，表格有 caption/scope，分页与清理确认摘要不省略范围/后果。
// 真实浏览器视口测试未在本环境执行。
func TestAuditResponsiveStaticContract(t *testing.T) {
	backend := baseAuditBackend()
	env := newAuditPageEnv(t, backend, auditPageSessions{})
	for _, target := range []string{"/admin/audit", "/admin/audit/exports",
		"/admin/audit/maintenance", "/admin/errors", "/account/activity"} {
		body := env.get(target).Body.String()
		if strings.Contains(body, "<table") {
			if !strings.Contains(body, `class="ln-table-scroll" tabindex="0" role="region"`) {
				t.Fatalf("%s 的表格缺少可聚焦局部滚动区", target)
			}
			if !strings.Contains(body, "<caption>") {
				t.Fatalf("%s 的表格缺少 caption", target)
			}
		}
		if strings.Contains(body, "style=\"width") {
			t.Fatalf("%s 使用固定宽度内联样式，窄屏可能溢出", target)
		}
	}
}

// TestExportStateMachineRendering 逐一验证真实任务状态在页面上的中文说明互不混写：
// 取消请求已接受不得显示为已取消，完成/失败/超时/运行分别呈现。
func TestExportStateMachineRendering(t *testing.T) {
	backend := baseAuditBackend()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	states := []string{"queued", "running", "succeeded", "failed", "cancelled"}
	exports := make([]login.UIAuditExport, 0, len(states))
	for _, state := range states {
		exports = append(exports, login.UIAuditExport{ID: "aex_" + state, Format: "json",
			State: state, TaskID: "job_" + state, CreatedAt: now})
	}
	backend.exportPage = login.UIAuditExportPage{Exports: exports}
	env := newAuditPageEnv(t, backend, auditPageSessions{})
	body := requireAuditBody(t, env.get("/admin/audit/exports"), http.StatusOK,
		"排队中", "运行中", "已完成", "失败", "已取消")
	if strings.Contains(body, "取消请求已接受（尚未实际取消）") {
		t.Fatal("没有取消请求的任务不得显示取消请求已接受")
	}
	// 取消请求已接受与已取消是不同行状态，不得互相混写。
	backend.exportPage = login.UIAuditExportPage{Exports: []login.UIAuditExport{
		{ID: "aex_cancel_req", Format: "csv", State: "cancel_requested"},
		{ID: "aex_cancelled", Format: "csv", State: "cancelled"},
		{ID: "aex_timeout", Format: "csv", State: "timed_out"}}}
	cancelBody := requireAuditBody(t, env.get("/admin/audit/exports"), http.StatusOK,
		"取消请求已接受（尚未实际取消）", "已取消", "任务执行超时")
	if strings.Count(cancelBody, "取消请求已接受（尚未实际取消）") != 1 {
		t.Fatal("取消请求状态重复或缺失")
	}
}

// TestAuditOwnActivityFilteredEmpty 验证本人页区分“无记录”和“筛选无结果”。
func TestAuditOwnActivityFilteredEmpty(t *testing.T) {
	backend := baseAuditBackend()
	backend.ownPage = login.UIAuditPage{RetentionDays: 180}
	env := newAuditPageEnv(t, backend, auditPageSessions{kind: "normal", userID: "usr_self"})
	ownEmpty := requireAuditBody(t, env.get("/account/activity"), http.StatusOK,
		"尚无你的安全活动记录", "仅限你本人的安全活动记录")
	if !strings.Contains(ownEmpty, `<td colspan="7">`) {
		t.Fatal("本人页空态 colspan 与列数不一致")
	}
	if strings.Contains(ownEmpty, "page.account.activity.scope_self") {
		t.Fatal("本人页显示未翻译的裸 i18n 键")
	}
	requireAuditBody(t, env.get("/account/activity?outcome=success"), http.StatusOK,
		"没有符合这些条件的记录")
}

// TestAuditDetailRelatedTaskRendered 验证关联任务摘要使用真实任务字段（不再恒不显示）。
func TestAuditDetailRelatedTaskRendered(t *testing.T) {
	env := newAuditPageEnv(t, baseAuditBackend(), auditPageSessions{})
	requireAuditBody(t, env.get("/admin/audit/detail?event_id="+
		"aud_0123456789abcdef0123456789abcdef"), http.StatusOK,
		"关联任务摘要", "job_task01", "运行中", "上次尝试超时")
}

// TestAuditMaintenanceRawNumberFieldsAndRetentionFailure 验证确认页回传原始整数
// （千分位会让服务端解析失败）与保留策略读取失败不伪装成 0 天。
func TestAuditMaintenanceRawNumberFieldsAndRetentionFailure(t *testing.T) {
	backend := baseAuditBackend()
	env := newAuditPageEnv(t, backend, auditPageSessions{})
	confirm := env.post("/admin/audit/maintenance/preview", url.Values{
		"cutoff": {"2026-01-01"}, "batch_size": {"500"}, "max_records": {"100000"},
		"reason": {"cleanup"}})
	body := requireAuditBody(t, confirm, http.StatusOK, "再次核对清理范围并确认")
	if !strings.Contains(body, `name="max_records" value="100000"`) ||
		strings.Contains(body, `name="max_records" value="100,000"`) {
		t.Fatal("确认页隐藏字段使用千分位，提交会 400")
	}
	backend.purgeContextFail = true
	failed := env.post("/admin/audit/maintenance/preview", url.Values{
		"cutoff": {"2027-01-01"}, "batch_size": {"500"}, "max_records": {"100000"},
		"reason": {"cleanup"}})
	requireAuditBody(t, failed, http.StatusOK, "保留策略读取失败")
}

// TestAuditPageDenialsAreRecorded 验证能力位拒绝与 CSRF 失败都写失败审计（拒绝留痕）。
func TestAuditPageDenialsAreRecorded(t *testing.T) {
	backend := baseAuditBackend()
	backend.capabilities = login.UIAuditCapabilities{}
	env := newAuditPageEnv(t, backend, auditPageSessions{})
	requireAuditBody(t, env.get("/admin/audit"), http.StatusForbidden, "服务端已拒绝访问")
	if len(backend.denials) == 0 || backend.denials[0] != "read_capability_denied" {
		t.Fatalf("读取能力位拒绝未留痕: %v", backend.denials)
	}
	// 非 root 清理页拒绝留痕。
	nonRoot := baseAuditBackend()
	nonRoot.capabilities = login.UIAuditCapabilities{Read: true, Export: true}
	nonRootEnv := newAuditPageEnv(t, nonRoot, auditPageSessions{})
	requireAuditBody(t, nonRootEnv.get("/admin/audit/maintenance"), http.StatusForbidden,
		"只有 root 可以进入审计清理")
	if len(nonRoot.denials) == 0 || nonRoot.denials[0] != "purge_capability_denied" {
		t.Fatalf("清理能力位拒绝未留痕: %v", nonRoot.denials)
	}
	// CSRF 失败留痕且不进入业务。
	csrfBackend := baseAuditBackend()
	csrfEnv := newAuditPageEnv(t, csrfBackend, auditPageSessions{})
	bad := csrfEnv.do(http.MethodPost, "/admin/audit/exports/create",
		url.Values{"format": {"csv"}})
	requireAuditBody(t, bad, http.StatusForbidden, "表单安全令牌无效")
	if len(csrfBackend.denials) == 0 || csrfBackend.denials[0] != "csrf_invalid" {
		t.Fatalf("CSRF 失败未留痕: %v", csrfBackend.denials)
	}
}

// 占位：确保 errors 包在测试文件内被使用（会话错误注入）。
var _ = errors.New

// TestAuditListHonorsControlledTimeZone 验证审计列表接受受控 tz 参数解释日期筛选，
// 使统计看板下钻的同一自然日区间在非账户时区下仍一致；非法 tz 回退会话时区。
func TestAuditListHonorsControlledTimeZone(t *testing.T) {
	backend := baseAuditBackend()
	env := newAuditPageEnv(t, backend, auditPageSessions{})
	requireAuditBody(t, env.get("/admin/audit?from=2026-11-18&to=2026-11-18&tz=Asia/Tokyo"),
		http.StatusOK, "Asia/Tokyo", `name="tz" value="Asia/Tokyo"`)
	// 东京 2026-11-18 00:00 = UTC 2026-11-17 15:00。
	if !backend.lastQuery.Filter.From.Equal(time.Date(2026, 11, 17, 15, 0, 0, 0, time.UTC)) {
		t.Fatalf("tz 未生效，From = %v", backend.lastQuery.Filter.From)
	}
	// 结束日上界被服务端当前时间钳制（now=2026-11-18 12:00 UTC → now+1m）。
	if !backend.lastQuery.Filter.To.Equal(time.Date(2026, 11, 18, 12, 1, 0, 0, time.UTC)) {
		t.Fatalf("To = %v，期望钳制到 now+1m", backend.lastQuery.Filter.To)
	}
	// 拒绝 Local，回退会话时区 UTC 后仍正常解析。
	backend.lastQuery = login.UIAuditQuery{}
	requireAuditBody(t, env.get("/admin/audit?from=2026-11-01&to=2026-11-02&tz=Local"),
		http.StatusOK)
	if !backend.lastQuery.Filter.From.Equal(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("非法 tz 未回退会话时区，From = %v", backend.lastQuery.Filter.From)
	}
}
