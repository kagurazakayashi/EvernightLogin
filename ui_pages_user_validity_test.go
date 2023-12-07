package login_test

// 步骤 235：管理页账户有效期展示与设置测试。
//
// 覆盖列表到期/无限期显示、详情只读视图、root 隐藏表单、表单成功（UTC 半开区间/
// 理由/确认）、缺失确认/理由、非法时间/区间、conflict、权限拒绝与 CSRF 拒绝。
// 后端使用页面公开契约的测试替身；真实授权/领域规则由 234 服务与适配器测试覆盖。

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
)

// fakeValidityBackend 在 fakeAdminBackend 上实现有效期页面后端。
type fakeValidityBackend struct {
	*fakeAdminBackend
	view       login.UIAdminUserValidityView
	setErr     error
	setCalled  bool
	lastChange login.UIAdminUserValidityChange
}

func (f *fakeValidityBackend) GetUserValidity(context.Context, string,
	string) (login.UIAdminUserValidityView, error) {
	if f.view.UserID == "" {
		return login.UIAdminUserValidityView{}, &login.UIAdminError{Code: "ACCESS_DENIED"}
	}
	return f.view, nil
}

func (f *fakeValidityBackend) SetUserValidity(_ context.Context, _, _ string,
	change login.UIAdminUserValidityChange) (login.UIAdminUserValidityView, error) {
	f.setCalled = true
	f.lastChange = change
	if f.setErr != nil {
		return login.UIAdminUserValidityView{}, f.setErr
	}
	return f.view, nil
}

// validityPageEnv 是页面/假后端组合。
type validityPageEnv struct {
	t       *testing.T
	handler http.Handler
	backend *fakeValidityBackend
}

// newValidityPageEnv 构造带有有效期能力的用户管理页。
func newValidityPageEnv(t *testing.T, view login.UIAdminUserValidityView) *validityPageEnv {
	t.Helper()
	until := time.Date(2026, 11, 26, 0, 0, 0, 0, time.UTC)
	base := &fakeAdminBackend{users: []login.UIAdminUserView{
		{UserID: "usr_test", Username: "alice", Nickname: "Alice", Status: "active",
			RowVersion: 3, ValidUntil: &until, Availability: "expired",
			CreatedAt: time.Now(), UpdatedAt: time.Now()},
		{UserID: "usr_unlimited", Username: "bob", Nickname: "Bob", Status: "active",
			RowVersion: 1, Availability: "available",
			CreatedAt: time.Now(), UpdatedAt: time.Now()},
	}}
	backend := &fakeValidityBackend{fakeAdminBackend: base, view: view}
	ui, err := login.NewWebUI(login.WebUIOptions{Session: adminPageSessions{},
		PageAdmin: &login.UIPageAdminOptions{Backend: backend, Validity: backend}})
	if err != nil {
		t.Fatalf("管理页框架: %v", err)
	}
	return &validityPageEnv{t: t, handler: ui, backend: backend}
}

func (e *validityPageEnv) get(target string) *httptest.ResponseRecorder {
	e.t.Helper()
	request := httptest.NewRequest(http.MethodGet, target, nil)
	recorder := httptest.NewRecorder()
	e.handler.ServeHTTP(recorder, request)
	return recorder
}

func (e *validityPageEnv) post(target string, values url.Values) *httptest.ResponseRecorder {
	e.t.Helper()
	request := httptest.NewRequest(http.MethodPost, target,
		bytes.NewReader([]byte(values.Encode())))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	e.handler.ServeHTTP(recorder, request)
	return recorder
}

func validityForm(userID, from, until, reason string) url.Values {
	values := url.Values{"csrf_token": {"admin-csrf-token"}, "user_id": {userID},
		"expected_row_version": {"3"}, "reason": {reason}, "confirm": {"yes"}}
	if from != "" {
		values.Set("valid_from", from)
	}
	if until != "" {
		values.Set("valid_until", until)
	}
	return values
}

// TestAdminUsersListValidityDisplay 验证列表显示到期/无限期与可用性。
func TestAdminUsersListValidityDisplay(t *testing.T) {
	env := newValidityPageEnv(t, login.UIAdminUserValidityView{UserID: "usr_test"})
	page := env.get("/admin/users")
	if page.Code != http.StatusOK {
		t.Fatalf("用户列表 = %d", page.Code)
	}
	body := page.Body.String()
	for _, want := range []string{"已到期", "无限期", "2026-11-26",
		`class="ln-field__error"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("用户列表缺少 %q", want)
		}
	}
}

// TestAdminUserDetailValidityView 验证详情展示与 root 表单隐藏。
func TestAdminUserDetailValidityView(t *testing.T) {
	from := time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)
	until := time.Date(2026, 11, 26, 0, 0, 0, 0, time.UTC)
	view := login.UIAdminUserValidityView{UserID: "usr_test", Status: "active",
		ValidFrom: &from, ValidUntil: &until, RowVersion: 3, Available: true,
		Reason: "available", CheckedAt: from}
	env := newValidityPageEnv(t, view)
	detail := env.get("/admin/users/detail?user_id=usr_test")
	if detail.Code != http.StatusOK {
		t.Fatalf("用户详情 = %d", detail.Code)
	}
	body := detail.Body.String()
	for _, want := range []string{"账户有效期", "可用起点", "到期时间", "变更理由",
		"name=\"valid_from\"", "name=\"valid_until\"", "name=\"reason\"",
		"name=\"confirm\"", "/admin/users/validity"} {
		if !strings.Contains(body, want) {
			t.Fatalf("详情缺少 %q", want)
		}
	}
	// 已到期原因在授权详情中精确展示（不是防枚举的公开错误）。
	expiredView := view
	expiredView.Available = false
	expiredView.Reason = "expired"
	expiredEnv := newValidityPageEnv(t, expiredView)
	expiredDetail := expiredEnv.get("/admin/users/detail?user_id=usr_test")
	if expiredDetail.Code != http.StatusOK ||
		!strings.Contains(expiredDetail.Body.String(), "已到期") {
		t.Fatalf("到期详情 = %d body=%s", expiredDetail.Code,
			expiredDetail.Body.String())
	}
	// root：只显示说明，不渲染设置表单。
	rootView := view
	rootView.IsRoot = true
	rootEnv := newValidityPageEnv(t, rootView)
	rootDetail := rootEnv.get("/admin/users/detail?user_id=usr_test")
	if rootDetail.Code != http.StatusOK {
		t.Fatalf("root 详情 = %d", rootDetail.Code)
	}
	rootBody := rootDetail.Body.String()
	if !strings.Contains(rootBody, "root 账户不接受普通期限管理") {
		t.Fatalf("root 详情缺少保护说明")
	}
	if strings.Contains(rootBody, "name=\"valid_from\"") {
		t.Fatalf("root 详情不应渲染有效期设置表单")
	}
}

// TestAdminUserValiditySet 验证表单成功、UTC 解析、redirect 与清空。
func TestAdminUserValiditySet(t *testing.T) {
	view := login.UIAdminUserValidityView{UserID: "usr_test", Status: "active",
		RowVersion: 4, Available: true, Reason: "available", CheckedAt: time.Now()}
	env := newValidityPageEnv(t, view)
	form := validityForm("usr_test", "2026-11-26T01:02", "2026-11-27T03:04:05Z",
		"临时延长测试期")
	response := env.post("/admin/users/validity", form)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("设置有效期 = %d body=%s", response.Code, response.Body.String())
	}
	if !env.backend.setCalled {
		t.Fatal("未调用 SetUserValidity")
	}
	if env.backend.lastChange.ValidFrom == nil ||
		!env.backend.lastChange.ValidFrom.Equal(time.Date(2026, 11, 26, 1, 2, 0, 0, time.UTC)) ||
		env.backend.lastChange.ValidUntil == nil ||
		!env.backend.lastChange.ValidUntil.Equal(time.Date(2026, 11, 27, 3, 4, 5, 0, time.UTC)) {
		t.Fatalf("UTC 时间解析异常: %+v", env.backend.lastChange)
	}
	if env.backend.lastChange.Reason != "临时延长测试期" ||
		env.backend.lastChange.ExpectedRowVersion != 3 ||
		env.backend.lastChange.RequestID == "" {
		t.Fatalf("理由/版本传递异常: %+v", env.backend.lastChange)
	}
	// 两端留空：清除（nil,nil），后端 domain 清零。
	env.backend.view = login.UIAdminUserValidityView{UserID: "usr_test",
		Status: "active", RowVersion: 5, Available: true, Reason: "available"}
	cleared := env.post("/admin/users/validity",
		validityForm("usr_test", "", "", "恢复永久有效"))
	if cleared.Code != http.StatusSeeOther ||
		cleared.Header().Get("Location") == "" ||
		!strings.Contains(cleared.Header().Get("Location"), "validity_cleared") {
		t.Fatalf("清除有效期 = %d %q", cleared.Code, cleared.Header().Get("Location"))
	}
	if env.backend.lastChange.ValidFrom != nil || env.backend.lastChange.ValidUntil != nil {
		t.Fatalf("清除应传 nil 时间: %+v", env.backend.lastChange)
	}
}

// TestAdminUserValidityValidationRejections 验证确认/理由/时间/区间/CSRF 拒绝。
func TestAdminUserValidityValidationRejections(t *testing.T) {
	env := newValidityPageEnv(t, login.UIAdminUserValidityView{UserID: "usr_test"})
	// 缺少确认词。
	noConfirm := validityForm("usr_test", "", "", "理由")
	noConfirm.Del("confirm")
	if response := env.post("/admin/users/validity", noConfirm); response.Code !=
		http.StatusBadRequest {
		t.Fatalf("缺少确认 = %d", response.Code)
	}
	// 缺少理由。
	if response := env.post("/admin/users/validity",
		validityForm("usr_test", "", "", "")); response.Code != http.StatusBadRequest {
		t.Fatalf("缺少理由 = %d", response.Code)
	}
	// 非法时间。
	if response := env.post("/admin/users/validity",
		validityForm("usr_test", "not-a-time", "", "理由")); response.Code !=
		http.StatusBadRequest {
		t.Fatalf("非法时间 = %d", response.Code)
	}
	// 结束不晚于开始。
	if response := env.post("/admin/users/validity", validityForm("usr_test",
		"2026-11-27T00:00:00Z", "2026-11-27T00:00:00Z", "理由")); response.Code !=
		http.StatusBadRequest {
		t.Fatalf("空区间 = %d", response.Code)
	}
	if env.backend.setCalled {
		t.Fatal("非法表单不得调用后端")
	}
	// CSRF 缺失：页面框架拒绝，不调用后端。
	noCSRF := validityForm("usr_test", "", "", "理由")
	noCSRF.Del("csrf_token")
	if response := env.post("/admin/users/validity", noCSRF); response.Code !=
		http.StatusForbidden || env.backend.setCalled {
		t.Fatalf("缺少 CSRF 应 403 且不调用后端: %d", response.Code)
	}
}

// TestAdminUserValidityConflictAndDenied 验证版本冲突与权限拒绝的页面提示。
func TestAdminUserValidityConflictAndDenied(t *testing.T) {
	env := newValidityPageEnv(t, login.UIAdminUserValidityView{UserID: "usr_test"})
	env.backend.setErr = &login.UIAdminError{Code: "CONFLICT"}
	conflict := env.post("/admin/users/validity",
		validityForm("usr_test", "", "", "理由"))
	if conflict.Code != http.StatusBadRequest ||
		!strings.Contains(conflict.Body.String(), "数据已被其他操作修改") {
		t.Fatalf("冲突提示 = %d body=%s", conflict.Code, conflict.Body.String())
	}
	env.backend.setErr = &login.UIAdminError{Code: "ACCESS_DENIED"}
	denied := env.post("/admin/users/validity",
		validityForm("usr_test", "", "", "理由"))
	if denied.Code != http.StatusForbidden ||
		!strings.Contains(denied.Body.String(), "权限") {
		t.Fatalf("权限拒绝 = %d body=%s", denied.Code, denied.Body.String())
	}
	// root 拒绝（后端稳定码）显示权限拒绝，不伪装成功。
	env.backend.setErr = &login.UIAdminError{Code: "ACCESS_DENIED"}
	root := env.post("/admin/users/validity",
		validityForm("usr_root", "", "", "理由"))
	if root.Code != http.StatusForbidden {
		t.Fatalf("root 设置 = %d", root.Code)
	}
}
