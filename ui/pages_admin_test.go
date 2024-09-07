package ui_test

// 步骤 68 管理页测试：受控 UIAdminBackend 渲染/表单/错误映射；真实服务集成见
// 报告“未验证项”与后续补充。

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
)

type fakeAdminBackend struct {
	users        []login.UIAdminUserView
	hasMore      bool
	review       login.UIAdminReview
	group        login.UIAdminGroup
	groups       []login.UIAdminGroup
	members      []login.UIAdminMember
	failCode     string
	deleted      bool
	memberResult login.UIAdminMemberResult
	// lastUserQuery 记录最近一次用户列表查询，供搜索参数透传测试断言。
	lastUserQuery login.UIAdminUserQuery
	// lastGroupQuery 记录最近一次用户组列表查询。
	lastGroupQuery login.UIAdminGroupQuery
}

func (f *fakeAdminBackend) fail() error {
	if f.failCode != "" {
		return &login.UIAdminError{Code: f.failCode}
	}
	return nil
}

func (f *fakeAdminBackend) ListUsers(_ context.Context, _ string,
	query login.UIAdminUserQuery) (login.UIAdminUserPage, error) {
	f.lastUserQuery = query
	if err := f.fail(); err != nil {
		return login.UIAdminUserPage{}, err
	}
	return login.UIAdminUserPage{Users: f.users, HasMore: f.hasMore}, nil
}

func (f *fakeAdminBackend) CreateUser(_ context.Context, _ string,
	create login.UIAdminCreateUser) (login.UIAdminUserView, error) {
	if err := f.fail(); err != nil {
		return login.UIAdminUserView{}, err
	}
	user := login.UIAdminUserView{UserID: "usr_created", Username: create.Username,
		Status: "active", RowVersion: 1}
	return user, nil
}

func (f *fakeAdminBackend) GetUser(context.Context, string,
	string) (login.UIAdminUserView, error) {
	if err := f.fail(); err != nil {
		return login.UIAdminUserView{}, err
	}
	return f.users[0], nil
}

func (f *fakeAdminBackend) UpdateUser(_ context.Context, _, userID string,
	change login.UIProfileChange, _ int64, _ string) (login.UIAdminUserView, error) {
	if err := f.fail(); err != nil {
		return login.UIAdminUserView{}, err
	}
	user := f.users[0]
	user.UserID = userID
	if change.Nickname != nil {
		user.Nickname = *change.Nickname
	}
	return user, nil
}

func (f *fakeAdminBackend) SetUserState(_ context.Context, _, userID, action string,
	_ int64, _ string) (login.UIAdminUserView, bool, error) {
	if err := f.fail(); err != nil {
		return login.UIAdminUserView{}, false, err
	}
	user := f.users[0]
	user.UserID = userID
	if action == "disable" {
		user.Status = "disabled"
	}
	return user, true, nil
}

func (f *fakeAdminBackend) PreviewDeletion(context.Context, string,
	string) (login.UIAdminDeletionPreview, error) {
	if err := f.fail(); err != nil {
		return login.UIAdminDeletionPreview{}, err
	}
	return login.UIAdminDeletionPreview{UserID: "usr_test", Username: "alice",
		Status: "pending_delete", RowVersion: 2, AppMemberships: 1, UserRoles: 2,
		GroupMemberships: 1}, nil
}

func (f *fakeAdminBackend) CompleteDeletion(context.Context, string, string, int64,
	string) (login.UIAdminDeletionPreview, error) {
	if err := f.fail(); err != nil {
		return login.UIAdminDeletionPreview{}, err
	}
	f.deleted = true
	return login.UIAdminDeletionPreview{UserID: "usr_test", DeletedAt: time.Now()}, nil
}

func (f *fakeAdminBackend) ListReviews(context.Context, string, int,
	int) (login.UIAdminReviewPage, error) {
	if err := f.fail(); err != nil {
		return login.UIAdminReviewPage{}, err
	}
	return login.UIAdminReviewPage{Reviews: []login.UIAdminReview{f.review}}, nil
}

func (f *fakeAdminBackend) GetReview(context.Context, string,
	string) (login.UIAdminReview, error) {
	if err := f.fail(); err != nil {
		return login.UIAdminReview{}, err
	}
	return f.review, nil
}

func (f *fakeAdminBackend) DecideReview(context.Context, string, string, bool,
	string, string, []string, string) (login.UIAdminReviewDecision, error) {
	if err := f.fail(); err != nil {
		return login.UIAdminReviewDecision{}, err
	}
	return login.UIAdminReviewDecision{Review: f.review, Notified: true}, nil
}

func (f *fakeAdminBackend) ListGroups(_ context.Context, _ string,
	query login.UIAdminGroupQuery) (login.UIAdminGroupPage, error) {
	f.lastGroupQuery = query
	if err := f.fail(); err != nil {
		return login.UIAdminGroupPage{}, err
	}
	return login.UIAdminGroupPage{Groups: f.groups}, nil
}

func (f *fakeAdminBackend) CreateGroup(_ context.Context, _ string, scopeID, groupKey, name,
	description, _ string) (login.UIAdminGroup, error) {
	if err := f.fail(); err != nil {
		return login.UIAdminGroup{}, err
	}
	return login.UIAdminGroup{ID: "grp_new", ScopeID: scopeID, GroupKey: groupKey,
		Name: name, Description: description}, nil
}

func (f *fakeAdminBackend) GetGroup(context.Context, string,
	string) (login.UIAdminGroup, error) {
	if err := f.fail(); err != nil {
		return login.UIAdminGroup{}, err
	}
	return f.group, nil
}

func (f *fakeAdminBackend) UpdateGroup(_ context.Context, _, groupID, name, description,
	_ string) (login.UIAdminGroup, error) {
	if err := f.fail(); err != nil {
		return login.UIAdminGroup{}, err
	}
	group := f.group
	group.ID = groupID
	group.Name = name
	group.Description = description
	return group, nil
}

func (f *fakeAdminBackend) DeleteGroup(context.Context, string, string, string) error {
	return f.fail()
}

func (f *fakeAdminBackend) ListMembers(context.Context, string, string, int,
	int) (login.UIAdminMemberPage, error) {
	if err := f.fail(); err != nil {
		return login.UIAdminMemberPage{}, err
	}
	return login.UIAdminMemberPage{Members: f.members}, nil
}

func (f *fakeAdminBackend) AddMembers(context.Context, string, string, []string,
	string) (login.UIAdminMemberResult, error) {
	if err := f.fail(); err != nil {
		return login.UIAdminMemberResult{}, err
	}
	return f.memberResult, nil
}

func (f *fakeAdminBackend) RemoveMembers(context.Context, string, string, []string,
	string) (login.UIAdminMemberResult, error) {
	if err := f.fail(); err != nil {
		return login.UIAdminMemberResult{}, err
	}
	return f.memberResult, nil
}

// adminPageSessions 提供管理会话（Kind=management）。
type adminPageSessions struct{}

func (adminPageSessions) ResolvePageSession(context.Context,
	*http.Request) (login.UISession, error) {
	return login.UISession{Authenticated: true, UserID: "usr_admin", Kind: "management",
		ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func (adminPageSessions) IssueCSRFToken(context.Context, *http.Request) (string, error) {
	return "admin-csrf-token", nil
}

type adminPageEnv struct {
	t       *testing.T
	handler http.Handler
	backend *fakeAdminBackend
}

func newAdminPageEnv(t *testing.T) *adminPageEnv {
	t.Helper()
	backend := &fakeAdminBackend{
		users: []login.UIAdminUserView{{UserID: "usr_test", Username: "alice",
			Nickname: "Alice", Status: "active", RowVersion: 1,
			CreatedAt: time.Now(), UpdatedAt: time.Now()}},
		hasMore: true,
		review: login.UIAdminReview{UserID: "usr_pending", Username: "pending",
			Status: "pending", ReviewStatus: "pending", CreatedAt: time.Now()},
		group: login.UIAdminGroup{ID: "grp_1", ScopeID: "system", GroupKey: "ops",
			Name: "Ops", Description: "运维组"},
		groups: []login.UIAdminGroup{{ID: "grp_1", ScopeID: "system", GroupKey: "ops",
			Name: "Ops"}},
		members:      []login.UIAdminMember{{GroupID: "grp_1", UserID: "usr_test"}},
		memberResult: login.UIAdminMemberResult{Added: 1, Skipped: 1},
	}
	ui, err := login.NewWebUI(login.WebUIOptions{
		Session: adminPageSessions{}, PageAdmin: &login.UIPageAdminOptions{Backend: backend}})
	if err != nil {
		t.Fatalf("管理页框架: %v", err)
	}
	return &adminPageEnv{t: t, handler: ui, backend: backend}
}

func (e *adminPageEnv) request(method, target string, body []byte,
	contentType string) *httptest.ResponseRecorder {
	e.t.Helper()
	request := httptest.NewRequest(method, "http://example.test"+target, bytes.NewReader(body))
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	recorder := httptest.NewRecorder()
	e.handler.ServeHTTP(recorder, request)
	return recorder
}

func (e *adminPageEnv) post(target string, values url.Values) *httptest.ResponseRecorder {
	return e.request(http.MethodPost, target, []byte(values.Encode()),
		"application/x-www-form-urlencoded")
}

func TestAdminUsersListAndCreate(t *testing.T) {
	env := newAdminPageEnv(t)
	page := env.request(http.MethodGet, "/admin/users?status=active&sort=username", nil, "")
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "alice") {
		t.Fatalf("用户列表 = %d", page.Code)
	}
	if !strings.Contains(page.Body.String(), "总数未知") ||
		!strings.Contains(page.Body.String(), "下一页") {
		t.Fatal("用户列表缺少分页/总数未知提示")
	}
	create := env.post("/admin/users/create", url.Values{"csrf_token": {"admin-csrf-token"},
		"username": {"bob"}, "nickname": {"Bob"}, "biography": {"x"},
		"language": {"zh-CN"}, "timezone": {"Asia/Shanghai"}})
	if create.Code != http.StatusSeeOther ||
		!strings.Contains(create.Header().Get("Location"), "user_id=usr_created") {
		t.Fatalf("创建用户 = %d %q", create.Code, create.Header().Get("Location"))
	}
}

func TestAdminUserDetailStateAndDelete(t *testing.T) {
	env := newAdminPageEnv(t)
	detail := env.request(http.MethodGet, "/admin/users/detail?user_id=usr_test", nil, "")
	if detail.Code != http.StatusOK || !strings.Contains(detail.Body.String(), "alice") {
		t.Fatalf("用户详情 = %d", detail.Code)
	}
	update := env.post("/admin/users/update?user_id=usr_test", url.Values{
		"csrf_token": {"admin-csrf-token"}, "user_id": {"usr_test"},
		"row_version": {"1"}, "nickname": {"Alice2"}})
	if update.Code != http.StatusSeeOther {
		t.Fatalf("用户编辑 = %d", update.Code)
	}
	state := env.post("/admin/users/state", url.Values{"csrf_token": {"admin-csrf-token"},
		"user_id": {"usr_test"}, "row_version": {"1"}, "action": {"disable"}})
	if state.Code != http.StatusSeeOther {
		t.Fatalf("状态操作 = %d", state.Code)
	}
	preview := env.request(http.MethodGet,
		"/admin/users/delete-preview?user_id=usr_test", nil, "")
	if preview.Code != http.StatusOK ||
		!strings.Contains(preview.Body.String(), "应用成员关系") {
		t.Fatalf("删除预览 = %d", preview.Code)
	}
	complete := env.post("/admin/users/delete", url.Values{
		"csrf_token": {"admin-csrf-token"}, "user_id": {"usr_test"},
		"row_version": {"2"}, "confirm_delete": {"yes"}})
	if complete.Code != http.StatusOK || !strings.Contains(complete.Body.String(), "账户已删除") ||
		!env.backend.deleted {
		t.Fatalf("完成删除 = %d", complete.Code)
	}
	missingConfirm := env.post("/admin/users/delete", url.Values{
		"csrf_token": {"admin-csrf-token"}, "user_id": {"usr_test"}})
	if missingConfirm.Code != http.StatusBadRequest {
		t.Fatalf("缺少确认的删除 = %d", missingConfirm.Code)
	}
}

func TestAdminReviewsAndDecide(t *testing.T) {
	env := newAdminPageEnv(t)
	list := env.request(http.MethodGet, "/admin/reviews", nil, "")
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), "pending") {
		t.Fatalf("审核列表 = %d", list.Code)
	}
	detail := env.request(http.MethodGet, "/admin/reviews/detail?user_id=usr_pending", nil, "")
	if detail.Code != http.StatusOK || !strings.Contains(detail.Body.String(), "审核理由") {
		t.Fatalf("审核详情 = %d", detail.Code)
	}
	missingReason := env.post("/admin/reviews/decide", url.Values{
		"csrf_token": {"admin-csrf-token"}, "user_id": {"usr_pending"},
		"decision": {"approve"}})
	if missingReason.Code != http.StatusBadRequest ||
		!strings.Contains(missingReason.Body.String(), "审核理由") {
		t.Fatalf("缺少理由 = %d", missingReason.Code)
	}
	approved := env.post("/admin/reviews/decide", url.Values{
		"csrf_token": {"admin-csrf-token"}, "user_id": {"usr_pending"},
		"reason": {"资料核验通过"}, "decision": {"approve"}})
	if approved.Code != http.StatusSeeOther {
		t.Fatalf("批准审核 = %d", approved.Code)
	}
}

func TestAdminGroupsAndMembers(t *testing.T) {
	env := newAdminPageEnv(t)
	list := env.request(http.MethodGet, "/admin/groups", nil, "")
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), "Ops") {
		t.Fatalf("组列表 = %d", list.Code)
	}
	created := env.post("/admin/groups/create", url.Values{"csrf_token": {"admin-csrf-token"},
		"scope_id": {"system"}, "group_key": {"dev"}, "name": {"Dev"}})
	if created.Code != http.StatusSeeOther ||
		!strings.Contains(created.Header().Get("Location"), "group_id=grp_new") {
		t.Fatalf("创建组 = %d", created.Code)
	}
	detail := env.request(http.MethodGet, "/admin/groups/detail?group_id=grp_1", nil, "")
	if detail.Code != http.StatusOK || !strings.Contains(detail.Body.String(), "ops") {
		t.Fatalf("组详情 = %d", detail.Code)
	}
	update := env.post("/admin/groups/update", url.Values{"csrf_token": {"admin-csrf-token"},
		"group_id": {"grp_1"}, "name": {"Ops2"}})
	if update.Code != http.StatusSeeOther {
		t.Fatalf("组更新 = %d", update.Code)
	}
	members := env.post("/admin/groups/members", url.Values{
		"csrf_token": {"admin-csrf-token"}, "group_id": {"grp_1"},
		"action": {"add"}, "user_ids": {"usr_a, usr_b"}})
	if members.Code != http.StatusSeeOther {
		t.Fatalf("成员变更 = %d", members.Code)
	}
	tooMany := env.post("/admin/groups/members", url.Values{
		"csrf_token": {"admin-csrf-token"}, "group_id": {"grp_1"}, "action": {"add"},
		"user_ids": {"usr_1 usr_2 usr_3 usr_4 usr_5 usr_6 usr_7 usr_8 usr_9 usr_10 usr_11 usr_12 usr_13"}})
	if tooMany.Code != http.StatusBadRequest {
		t.Fatalf("超过 12 名成员 = %d", tooMany.Code)
	}
	deleted := env.post("/admin/groups/delete", url.Values{
		"csrf_token": {"admin-csrf-token"}, "group_id": {"grp_1"}, "confirm_delete": {"yes"}})
	if deleted.Code != http.StatusSeeOther {
		t.Fatalf("删除组 = %d", deleted.Code)
	}
}

func TestAdminErrorsFailClosed(t *testing.T) {
	env := newAdminPageEnv(t)
	env.backend.failCode = "ACCESS_DENIED"
	page := env.request(http.MethodGet, "/admin/users", nil, "")
	if page.Code != http.StatusForbidden ||
		!strings.Contains(page.Body.String(), "没有执行该管理操作的权限") {
		t.Fatalf("越权页面 = %d", page.Code)
	}
	env.backend.failCode = "DB_UNAVAILABLE"
	page = env.request(http.MethodGet, "/admin/groups", nil, "")
	if page.Code != http.StatusServiceUnavailable ||
		!strings.Contains(page.Body.String(), "服务暂时不可用") {
		t.Fatalf("依赖故障页面 = %d", page.Code)
	}
	env.backend.failCode = "CONFLICT"
	page = env.post("/admin/users/update?user_id=usr_test", url.Values{
		"csrf_token": {"admin-csrf-token"}, "user_id": {"usr_test"},
		"row_version": {"1"}, "nickname": {"x"}})
	if page.Code != http.StatusBadRequest ||
		!strings.Contains(page.Body.String(), "重新读取") {
		t.Fatalf("冲突页面 = %d", page.Code)
	}
}

func (f *fakeAdminBackend) PrecheckImport(context.Context, string,
	[]byte) (login.UIAdminParseReport, error) {
	return login.UIAdminParseReport{Headers: []string{"username"}, TotalRows: 2,
		CanImport: true}, f.fail()
}

func (f *fakeAdminBackend) StartImport(context.Context, string, []byte, string,
	string) (login.UIAdminBatchStart, error) {
	if err := f.fail(); err != nil {
		return login.UIAdminBatchStart{}, err
	}
	return login.UIAdminBatchStart{JobID: "ubj_1", Kind: "import", State: "queued",
		TotalRows: 2}, nil
}

func (f *fakeAdminBackend) StartExport(context.Context, string, login.UIAdminExportOptions,
	string) (login.UIAdminBatchStart, error) {
	if err := f.fail(); err != nil {
		return login.UIAdminBatchStart{}, err
	}
	return login.UIAdminBatchStart{JobID: "ubj_2", Kind: "export", State: "queued"}, nil
}

func (f *fakeAdminBackend) ListJobs(context.Context, string, string, int,
	int) (login.UIAdminBatchPage, error) {
	if err := f.fail(); err != nil {
		return login.UIAdminBatchPage{}, err
	}
	return login.UIAdminBatchPage{Jobs: []login.UIAdminBatchJob{{JobID: "ubj_1",
		Kind: "import", State: "partial", TotalRows: 2, CreatedCount: 1, FailedCount: 1}}}, nil
}

func (f *fakeAdminBackend) GetJob(context.Context, string,
	string) (login.UIAdminBatchJob, error) {
	if err := f.fail(); err != nil {
		return login.UIAdminBatchJob{}, err
	}
	return login.UIAdminBatchJob{JobID: "ubj_1", Kind: "import", State: "partial",
		TotalRows: 2, CreatedCount: 1, FailedCount: 1, InputAvailable: true}, nil
}

func (f *fakeAdminBackend) ListRows(context.Context, string, string, int,
	int) ([]login.UIAdminBatchRow, bool, error) {
	if err := f.fail(); err != nil {
		return nil, false, err
	}
	return []login.UIAdminBatchRow{{RowNumber: 1, Action: "created"},
		{RowNumber: 2, Action: "failed", ErrorCode: "REQ_INVALID"}}, false, nil
}

func (f *fakeAdminBackend) ReportCSV(context.Context, string,
	string) ([]byte, bool, error) {
	if err := f.fail(); err != nil {
		return nil, false, err
	}
	return []byte("row_number,action,report_truncated\n1,created,false\n2,failed,false\n"),
		false, nil
}

func (f *fakeAdminBackend) CancelJob(context.Context, string, string, string, string) error {
	return f.fail()
}

func (f *fakeAdminBackend) RetryJob(context.Context, string, string,
	string) (login.UIAdminBatchJob, error) {
	if err := f.fail(); err != nil {
		return login.UIAdminBatchJob{}, err
	}
	return login.UIAdminBatchJob{JobID: "ubj_1", State: "queued"}, nil
}

func TestAdminBatchPages(t *testing.T) {
	env := newAdminPageEnv(t)
	// 预检查：multipart CSV，声明 action=precheck。
	var precheckBody bytes.Buffer
	precheckWriter := multipart.NewWriter(&precheckBody)
	_ = precheckWriter.WriteField("csrf_token", "admin-csrf-token")
	_ = precheckWriter.WriteField("action", "precheck")
	filePart, _ := precheckWriter.CreateFormFile("csv_file", "users.csv")
	_, _ = filePart.Write([]byte("username,nickname\nalice,A\n"))
	_ = precheckWriter.Close()
	precheck := env.request(http.MethodPost, "/admin/users/import", precheckBody.Bytes(),
		precheckWriter.FormDataContentType())
	if precheck.Code != http.StatusOK ||
		!strings.Contains(precheck.Body.String(), "预检查结果") {
		t.Fatalf("预检查 = %d", precheck.Code)
	}
	// 正式导入：幂等键缺失 → 400。
	var startBody bytes.Buffer
	startWriter := multipart.NewWriter(&startBody)
	_ = startWriter.WriteField("csrf_token", "admin-csrf-token")
	_ = startWriter.WriteField("action", "start")
	startFile, _ := startWriter.CreateFormFile("csv_file", "users.csv")
	_, _ = startFile.Write([]byte("username\nalice\n"))
	_ = startWriter.Close()
	missingKey := env.request(http.MethodPost, "/admin/users/import", startBody.Bytes(),
		startWriter.FormDataContentType())
	if missingKey.Code != http.StatusBadRequest {
		t.Fatalf("缺少幂等键 = %d", missingKey.Code)
	}
	// 导出任务 + 任务列表/详情/取消请求（不本地标已取消）+ 报告下载。
	export := env.post("/admin/users/export", url.Values{"csrf_token": {"admin-csrf-token"},
		"username": {"1"}, "idempotency_key": {"export-key-123"}})
	if export.Code != http.StatusSeeOther ||
		!strings.Contains(export.Header().Get("Location"), "job_id=ubj_2") {
		t.Fatalf("导出任务 = %d %q", export.Code, export.Header().Get("Location"))
	}
	list := env.request(http.MethodGet, "/admin/users/batch", nil, "")
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), "partial") {
		t.Fatalf("任务列表 = %d", list.Code)
	}
	detail := env.request(http.MethodGet, "/admin/users/batch/detail?job_id=ubj_1", nil, "")
	if detail.Code != http.StatusOK ||
		!strings.Contains(detail.Body.String(), "逐行结果") ||
		!strings.Contains(detail.Body.String(), "partial") {
		t.Fatalf("任务详情 = %d", detail.Code)
	}
	cancel := env.post("/admin/users/batch/action", url.Values{
		"csrf_token": {"admin-csrf-token"}, "job_id": {"ubj_1"}, "action": {"cancel"}})
	if cancel.Code != http.StatusSeeOther ||
		!strings.Contains(cancel.Header().Get("Location"), "status=cancel_requested") {
		t.Fatalf("取消请求 = %d %q", cancel.Code, cancel.Header().Get("Location"))
	}
	report := env.request(http.MethodGet, "/admin/users/batch/report?job_id=ubj_1", nil, "")
	if report.Code != http.StatusOK ||
		report.Header().Get("Content-Type") != "text/csv; charset=utf-8" ||
		!strings.Contains(report.Header().Get("Content-Disposition"), "attachment") ||
		!strings.Contains(report.Body.String(), "report_truncated") {
		t.Fatalf("报告下载 = %d %v", report.Code, report.Header())
	}
}
